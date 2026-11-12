//! Queued-submission smokes (`mq` / `req`): the per-command slot
//! lifecycle against the RAM-backed fake controller (every arch), and
//! real concurrency against QEMU's NVMe — many commands in flight at once,
//! N reads finishing in about the time of one, data intact under
//! interleaved writers.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_block::{BlockDevice, BlockDeviceSync, BlockOp, BlockRequest, QosHint};
use narf_io::{alloc_coherent, register_with_cap, DmaBuffer};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use super::mq::{Cmd, CmdOutcome, CmdResources, IoQueue};
use super::tests_cid::{fake_cid_controller_with, stage_cqe, FakeCidCtrl};
use super::{Controller, IoOpcode, Sqe};

/// A waker that counts its wakes (the tests poll by hand).
static WAKES: AtomicUsize = AtomicUsize::new(0);

fn counting_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    unsafe fn wake(_: *const ()) {
        WAKES.fetch_add(1, Ordering::AcqRel);
    }
    unsafe fn drop(_: *const ()) {}
    const VTAB: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);
    // SAFETY: the vtable's functions ignore the (null) data pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) }
}

fn read_sqe(prp1: u64) -> Sqe {
    let mut sqe = Sqe::zero();
    sqe.cdw0 = IoOpcode::Read as u32;
    sqe.nsid = 1;
    sqe.prp1 = prp1;
    sqe
}

fn fake() -> Option<FakeCidCtrl> {
    fake_cid_controller_with(None)
}

fn queue_of(ctrl: &Controller) -> Arc<IoQueue> {
    ctrl.io_queues()[0].clone()
}

fn smoke_nvme_mq_dropped_future_releases_only_on_completion() -> TestResult {
    // A command whose owner drops its future stays in flight at the queue:
    // its tag, its PRP page and its hold on the payload are released only
    // when the CQE lands (AGENTS.md invariant 7) — and never by the ISR,
    // which may not free; the next process-context visitor reclaims it.
    let Some(fx) = fake() else {
        return TestResult::Fail("fake controller setup failed");
    };
    let q = queue_of(&fx.ctrl);
    let tags = q.tag_count();
    let Ok(payload) = alloc_coherent(4096, DomainId::DRIVER_0) else {
        return TestResult::Fail("alloc_coherent failed");
    };
    let payload = Arc::new(payload);
    let Some(prp) = q.prp_page() else {
        return TestResult::Fail("no PRP page");
    };
    let Some(tag) = q.try_alloc_tag(None) else {
        return TestResult::Fail("no tag");
    };
    let res = CmdResources {
        prp_list: Some(prp),
        hold: Some(Arc::clone(&payload)),
    };
    let Ok(id) = q.post(tag, read_sqe(payload.dma_addr().raw()), res) else {
        return TestResult::Fail("post failed");
    };
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut cmd = Cmd::new(Arc::clone(&q), id);
    if cmd.poll_outcome(&mut cx).is_ready() {
        return TestResult::Fail("command resolved with nothing in the CQ");
    }
    // Owner gone, command still live in the "device".
    drop(cmd);
    if q.in_flight() != 1 || q.free_tags() != tags - 1 || Arc::strong_count(&payload) != 2 {
        return TestResult::Fail("dropping the future released the command's resources");
    }
    // The CQE lands and is reaped in interrupt context: published, nothing
    // freed.
    // SAFETY: the fake queue's live CQ page; slot 0.
    unsafe { stage_cqe(fx.cq_io, 0, tag, 1, 0) };
    if q.process_cq(true) != 1 {
        return TestResult::Fail("the ISR path did not consume the completion");
    }
    if q.in_flight() != 0 {
        return TestResult::Fail("a completed command still counts as in flight");
    }
    if q.free_tags() != tags - 1 || Arc::strong_count(&payload) != 2 {
        return TestResult::Fail("the ISR path freed an abandoned command's resources");
    }
    // Process context reclaims it.
    if q.sweep() != 1 || q.free_tags() != tags || Arc::strong_count(&payload) != 1 {
        return TestResult::Fail("the sweep did not reclaim the abandoned command");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/mq",
    smoke_nvme_mq_dropped_future_releases_only_on_completion
);

fn smoke_nvme_mq_teardown_resets_inflight_and_refuses_posts() -> TestResult {
    // Teardown under live commands: an owned command's future sees `Reset`
    // (it requeues); an abandoned one is reclaimed (the controller was
    // confirmed stopped); nothing can be posted afterwards.
    let Some(fx) = fake() else {
        return TestResult::Fail("fake controller setup failed");
    };
    let q = queue_of(&fx.ctrl);
    let tags = q.tag_count();
    let Ok(payload) = alloc_coherent(4096, DomainId::DRIVER_0) else {
        return TestResult::Fail("alloc_coherent failed");
    };
    let payload = Arc::new(payload);
    let post = |hold: bool| -> Option<Cmd> {
        let tag = q.try_alloc_tag(None)?;
        let res = CmdResources {
            prp_list: None,
            hold: hold.then(|| Arc::clone(&payload)),
        };
        let id = q.post(tag, read_sqe(payload.dma_addr().raw()), res).ok()?;
        Some(Cmd::new(Arc::clone(&q), id))
    };
    let Some(mut owned) = post(false) else {
        return TestResult::Fail("post 1 failed");
    };
    let Some(abandoned) = post(true) else {
        return TestResult::Fail("post 2 failed");
    };
    drop(abandoned);
    if q.in_flight() != 2 {
        return TestResult::Fail("two commands should be in flight");
    }
    q.teardown(true);
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    match owned.poll_outcome(&mut cx) {
        Poll::Ready(CmdOutcome::Reset) => {}
        _ => return TestResult::Fail("an owned command did not see the reset"),
    }
    if q.in_flight() != 0 || Arc::strong_count(&payload) != 1 || q.free_tags() != tags {
        return TestResult::Fail("teardown did not release the commands");
    }
    let Some(tag) = q.try_alloc_tag(None) else {
        return TestResult::Fail("no tag after teardown");
    };
    if q.post(
        tag,
        read_sqe(payload.dma_addr().raw()),
        CmdResources::default(),
    )
    .is_ok()
    {
        return TestResult::Fail("a torn-down queue accepted a command");
    }
    if q.free_tags() != tags {
        return TestResult::Fail("a refused post kept its tag");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/mq",
    smoke_nvme_mq_teardown_resets_inflight_and_refuses_posts
);

fn smoke_nvme_mq_tag_exhaustion_wakes_waiter() -> TestResult {
    // Every tag taken: a submitter registering a waker gets none and is
    // woken when one is returned (`blk_mq_get_tag`'s wait queue).
    let Some(fx) = fake() else {
        return TestResult::Fail("fake controller setup failed");
    };
    let q = queue_of(&fx.ctrl);
    let mut held = Vec::new();
    while let Some(t) = q.try_alloc_tag(None) {
        held.push(t);
    }
    if held.len() != q.tag_count() || held.len() != q.depth as usize - 1 {
        return TestResult::Fail("tag count is not depth - 1");
    }
    let waker = counting_waker();
    let before = WAKES.load(Ordering::Acquire);
    if q.try_alloc_tag(Some(&waker)).is_some() {
        return TestResult::Fail("a tag appeared out of nowhere");
    }
    let last = held.pop().expect("held tags");
    q.release_tag_unused(last);
    if WAKES.load(Ordering::Acquire) != before + 1 {
        return TestResult::Fail("returning a tag did not wake the waiter");
    }
    let Some(again) = q.try_alloc_tag(None) else {
        return TestResult::Fail("the returned tag is not allocatable");
    };
    if again != last {
        return TestResult::Fail("the returned tag was not the one handed out");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mq", smoke_nvme_mq_tag_exhaustion_wakes_waiter);

fn smoke_nvme_mq_timeout_timer_marks_expired_commands() -> TestResult {
    // The queue's timer (not a waiter's deadline check) marks an expired
    // command and wakes its owner, whose next poll reports the timeout
    // after a last look at the CQ.
    let Some(fx) = fake() else {
        return TestResult::Fail("fake controller setup failed");
    };
    let q = queue_of(&fx.ctrl);
    let Some(tag) = q.try_alloc_tag(None) else {
        return TestResult::Fail("no tag");
    };
    super::IO_TIMEOUT_MS_FOR_TEST.store(20, Ordering::Release);
    let posted = q.post(tag, read_sqe(fx.id_dma), CmdResources::default());
    super::IO_TIMEOUT_MS_FOR_TEST.store(0, Ordering::Release);
    let Ok(id) = posted else {
        return TestResult::Fail("post failed");
    };
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut cmd = Cmd::new(Arc::clone(&q), id);
    if cmd.poll_outcome(&mut cx).is_ready() {
        return TestResult::Fail("resolved at once");
    }
    if q.timed_out(id) != Some(false) {
        return TestResult::Fail("a fresh command reads as timed out");
    }
    let wakes0 = WAKES.load(Ordering::Acquire);
    // Run this CPU's timer wheel until the timer has fired (bounded).
    let give_up = narf_time::Deadline::after_ms(2_000);
    while q.timed_out(id) != Some(true) && !give_up.expired() {
        narf_time::timer::run_timer_softirq();
        core::hint::spin_loop();
    }
    if q.timed_out(id) != Some(true) {
        return TestResult::Fail("the queue timer never marked the command");
    }
    if WAKES.load(Ordering::Acquire) == wakes0 {
        return TestResult::Fail("the timer did not wake the owner");
    }
    match cmd.poll_outcome(&mut cx) {
        Poll::Ready(CmdOutcome::TimedOut) => {}
        _ => return TestResult::Fail("the owner did not see the timeout"),
    }
    // A completion arriving after the timeout is still taken (late).
    // SAFETY: the fake queue's live CQ page; slot 0.
    unsafe { stage_cqe(fx.cq_io, 0, tag, 1, 0) };
    match cmd.poll_outcome(&mut cx) {
        Poll::Ready(CmdOutcome::Completed { late: true, .. }) => {}
        _ => return TestResult::Fail("a late completion was not taken as such"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/mq",
    smoke_nvme_mq_timeout_timer_marks_expired_commands
);

// ── QEMU: real concurrency ─────────────────────────────────────────

/// Install a fresh controller for `nvme0` with the preferred (MSI-X,
/// per-CPU) queue set. `None` without a QEMU NVMe device.
fn install_qemu_controller() -> Option<Result<(), &'static str>> {
    use narf_bus::x86_64::ECAM_DEFAULT_BASE;
    use narf_bus::{bootstrap_registry_authority, claim_device_cap, devices, BusKind};
    // SAFETY: kernel-test runs at boot with the allocator online and the
    // memory map parsed; ECAM_DEFAULT_BASE is the standard x86_64 ECAM
    // window base, identity-mapped. `init` is idempotent (last call wins).
    let _ = unsafe { narf_bus::init(ECAM_DEFAULT_BASE) };
    let dev = devices()
        .iter()
        .find(|d| {
            matches!(d.kind, BusKind::Pcie { .. }) && d.id.vendor == 0x1B36 && d.id.device == 0x0010
        })
        .copied()?;
    let authority = bootstrap_registry_authority();
    let Ok((_h, cap)) = claim_device_cap(&authority, dev.addr) else {
        return Some(Err("claim_device_cap failed"));
    };
    let mut ctrl = Controller::from_device(dev);
    if ctrl.bring_up(&cap).is_err() {
        return Some(Err("bring_up failed"));
    }
    if ctrl.create_io_queues_preferred(&cap).is_err() {
        return Some(Err("create_io_queues_preferred failed"));
    }
    super::install_controller(ctrl);
    Some(Ok(()))
}

fn fill(buf: &DmaBuffer, seed: u8) {
    // SAFETY: a live coherent buffer, exclusively ours.
    unsafe {
        let p = buf.cpu_mut_ptr::<u8>();
        for i in 0..buf.len() {
            core::ptr::write_volatile(p.add(i), (i as u8).wrapping_mul(31).wrapping_add(seed));
        }
    }
}

fn check(buf: &DmaBuffer, seed: u8) -> bool {
    // SAFETY: as `fill`.
    unsafe {
        let p = buf.cpu_ptr::<u8>();
        (0..buf.len()).all(|i| {
            core::ptr::read_volatile(p.add(i)) == (i as u8).wrapping_mul(31).wrapping_add(seed)
        })
    }
}

/// Drive `futs` to completion by hand, round-robin, with a waker that does
/// nothing: every request future's poll looks at the CQ itself, so this
/// proves the queued data path without the executor — whose boot-time,
/// single-CPU test form may park an IRQ-woken task on an idle AP. Returns
/// `false` when `deadline` passed first.
fn drive_all(
    mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
    deadline: narf_time::Deadline,
) -> bool {
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    while !futs.is_empty() {
        if deadline.expired() {
            return false;
        }
        futs.retain_mut(|f| f.as_mut().poll(&mut cx).is_pending());
        narf_time::timer::run_timer_softirq();
        core::hint::spin_loop();
    }
    true
}

/// Peak commands in flight observed by any task of the concurrent smokes.
static PEAK_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static FAILURES: AtomicUsize = AtomicUsize::new(0);

fn note_in_flight() {
    let now = super::with_controller(|c| c.io_in_flight()).unwrap_or(0);
    PEAK_IN_FLIGHT.fetch_max(now, Ordering::AcqRel);
}

fn smoke_nvme_mq_concurrent_requests_overlap_qemu() -> TestResult {
    // N tasks each submit a read through `NvmeBlockDevice` (the queued
    // block path) and await it. More than one command must be at the
    // device at once, every read must succeed, and the batch must take
    // less than the serial sum of the same reads.
    const N: usize = 16;
    match install_qemu_controller() {
        None => return TestResult::Skip("no QEMU NVMe controller"),
        Some(Err(e)) => return TestResult::Fail(e),
        Some(Ok(())) => {}
    }
    let (lba_bytes, max_transfer) =
        super::with_controller(|c| (c.lba_bytes as usize, c.max_transfer_bytes() as usize))
            .unwrap_or((512, 4096));
    // The largest transfer one command carries, so device time per command
    // dwarfs the time to post the next: the batch overlaps at the device.
    let bytes = max_transfer.min(512 * 1024);
    #[allow(non_snake_case)]
    let BLOCKS = (bytes / lba_bytes) as u32;
    // SAFETY: APIC initialised; the queues' MSIs land in our IDT vectors.
    unsafe { narf_arch::enable_interrupts() };

    // Serial baseline: the same N reads one after another.
    let dev = Arc::new(super::NvmeBlockDevice);
    let serial_start = narf_time::now_cycles();
    for i in 0..N {
        let buf = alloc_coherent(bytes, DomainId::DRIVER_0).expect("alloc");
        let cap = register_with_cap(buf);
        let req = BlockRequest {
            op: BlockOp::Read,
            lba: 4096 + (i as u64) * BLOCKS as u64,
            blocks: BLOCKS,
            buffer: cap.derive().expect("derive"),
            qos: QosHint::Latency,
            user_tag: i as u64,
        };
        let c = narf_scheduler::block_on_spin(dev.submit(req));
        narf_io::unregister(cap);
        if c.result.is_err() {
            // SAFETY: counterpart to the enable above.
            unsafe { narf_arch::disable_interrupts() };
            return TestResult::Fail("serial read failed");
        }
    }
    let serial = narf_time::now_cycles() - serial_start;

    PEAK_IN_FLIGHT.store(0, Ordering::Release);
    FAILURES.store(0, Ordering::Release);
    // Buffers first: the timed batch is posting + waiting, nothing else.
    let mut caps = Vec::new();
    for _ in 0..N {
        let buf = alloc_coherent(bytes, DomainId::DRIVER_0).expect("alloc");
        caps.push(register_with_cap(buf));
    }
    let batch_start = narf_time::now_cycles();
    let mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
    for (i, cap) in caps.into_iter().enumerate() {
        let dev = Arc::clone(&dev);
        futs.push(Box::pin(async move {
            let req = BlockRequest {
                op: BlockOp::Read,
                lba: 4096 + (i as u64) * BLOCKS as u64,
                blocks: BLOCKS,
                buffer: cap.derive().expect("derive"),
                qos: QosHint::Latency,
                user_tag: i as u64,
            };
            let fut = dev.submit(req);
            let mut fut = core::pin::pin!(fut);
            // Post the command (first poll), then look at what the
            // controller has in flight, then await the rest.
            let c = core::future::poll_fn(|cx| {
                let r = fut.as_mut().poll(cx);
                note_in_flight();
                r
            })
            .await;
            narf_io::unregister(cap);
            if c.result.is_err() {
                FAILURES.fetch_add(1, Ordering::AcqRel);
            }
        }));
    }
    let drove = drive_all(futs, narf_time::Deadline::after_ms(20_000));
    let batch = narf_time::now_cycles() - batch_start;
    // SAFETY: counterpart to the enable above.
    unsafe { narf_arch::disable_interrupts() };

    // The driver's own high-water mark (kept at posting time) is the
    // authoritative figure; the task-side samples are a lower bound.
    let peak = super::with_controller(|c| c.io_peak_in_flight())
        .unwrap_or(0)
        .max(PEAK_IN_FLIGHT.load(Ordering::Acquire));
    let queues = super::with_controller(|c| c.io_queue_count()).unwrap_or(0);
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "nvme-mq: {N} x {bytes} B reads: serial {} us, concurrent {} us, peak in flight {peak}, \
             {queues} queue(s)",
            narf_time::cycles_to_ns(serial) / 1_000,
            narf_time::cycles_to_ns(batch) / 1_000,
        );
    }
    if !drove {
        return TestResult::Fail("concurrent reads did not all complete in 20 s");
    }
    if FAILURES.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("a concurrent read failed");
    }
    if peak < 2 {
        return TestResult::Fail("never more than one command in flight");
    }
    if batch >= serial {
        return TestResult::Fail("concurrent reads took as long as serial ones");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/mq",
    smoke_nvme_mq_concurrent_requests_overlap_qemu
);

fn smoke_nvme_mq_concurrent_integrity_qemu() -> TestResult {
    // Interleaved writers and readers through the registry device's queue
    // (`NvmeNamespaceBlock::queue()`, what `SyncBlock` submits through):
    // each task writes its own pattern to its own range, reads it back
    // through a second buffer and verifies it, while every other task does
    // the same. A flush is queued between the phases.
    const N: usize = 12;
    const BLOCKS: u32 = 16;
    match install_qemu_controller() {
        None => return TestResult::Skip("no QEMU NVMe controller"),
        Some(Err(e)) => return TestResult::Fail(e),
        Some(Ok(())) => {}
    }
    let (lba_bytes, nsid) =
        super::with_controller(|c| (c.lba_bytes, c.primary_nsid)).unwrap_or((512, 1));
    let bytes = BLOCKS as usize * lba_bytes as usize;
    let ns_dev: Arc<dyn BlockDeviceSync> = Arc::new(super::NvmeNamespaceBlock::new(0, nsid));
    let Some(queue) = ns_dev.queue() else {
        return TestResult::Fail("NvmeNamespaceBlock exposes no queue");
    };
    let sync = narf_block::SyncBlock::new(ns_dev);
    if sync.queue().is_none() {
        return TestResult::Fail("SyncBlock did not pick the queue up");
    }
    let limits = queue.limits();
    if limits.nr_queues == 0 || limits.queue_depth < limits.nr_queues {
        return TestResult::Fail("queue limits do not describe the queue set");
    }
    // SAFETY: APIC initialised; the queues' MSIs land in our IDT vectors.
    unsafe { narf_arch::enable_interrupts() };
    FAILURES.store(0, Ordering::Release);
    PEAK_IN_FLIGHT.store(0, Ordering::Release);
    let mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
    for i in 0..N {
        let sync = Arc::clone(&sync);
        futs.push(Box::pin(async move {
            let seed = (i as u8).wrapping_mul(7).wrapping_add(3);
            let lba = 8192 + (i as u64) * BLOCKS as u64;
            let wbuf = alloc_coherent(bytes, DomainId::DRIVER_0).expect("alloc");
            fill(&wbuf, seed);
            let wcap = register_with_cap(wbuf);
            let rbuf = alloc_coherent(bytes, DomainId::DRIVER_0).expect("alloc");
            let rcap = register_with_cap(rbuf);
            let mut ok = true;
            for round in 0..3u8 {
                let fua = round == 2;
                let w = sync
                    .submit(BlockRequest {
                        op: BlockOp::Write { fua },
                        lba,
                        blocks: BLOCKS,
                        buffer: wcap.derive().expect("derive"),
                        qos: QosHint::Throughput,
                        user_tag: i as u64,
                    })
                    .await;
                note_in_flight();
                ok &= w.result.is_ok();
                if round == 1 {
                    ok &= sync.flush_result().await.is_ok();
                }
                let r = sync
                    .submit(BlockRequest {
                        op: BlockOp::Read,
                        lba,
                        blocks: BLOCKS,
                        buffer: rcap.derive().expect("derive"),
                        qos: QosHint::Latency,
                        user_tag: i as u64,
                    })
                    .await;
                ok &= r.result.is_ok();
                if let Some(rb) = narf_io::resolve_cap(&rcap) {
                    ok &= check(&rb, seed);
                    // Scribble so the next round's read must bring it back.
                    fill(&rb, seed.wrapping_add(1));
                } else {
                    ok = false;
                }
            }
            narf_io::unregister(wcap);
            narf_io::unregister(rcap);
            if !ok {
                FAILURES.fetch_add(1, Ordering::AcqRel);
            }
        }));
    }
    let drove = drive_all(futs, narf_time::Deadline::after_ms(30_000));
    // SAFETY: counterpart to the enable above.
    unsafe { narf_arch::disable_interrupts() };
    if !drove {
        return TestResult::Fail("concurrent writers/readers did not all complete in 30 s");
    }
    if FAILURES.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("a task's data did not survive concurrent I/O");
    }
    if PEAK_IN_FLIGHT.load(Ordering::Acquire) < 2 {
        return TestResult::Fail(
            "never more than one request in flight through the registry queue",
        );
    }
    if super::with_controller(|c| c.io_in_flight()).unwrap_or(1) != 0 {
        return TestResult::Fail("commands left in flight after every task finished");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/nvme/mq", smoke_nvme_mq_concurrent_integrity_qemu);
