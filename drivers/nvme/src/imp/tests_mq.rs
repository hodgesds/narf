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

/// One pass of the bridge primitives' pump — sleep pumps and the timer
/// softirq — as any polled waiter gets between checks.
fn pump_once() {
    let mut first = true;
    narf_scheduler::responsive_spin_until(
        move || {
            let f = first;
            first = false;
            !f
        },
        narf_time::Deadline::after_ms(5),
    );
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
        pages: None,
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
            pages: None,
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
    // Wait as a polled driver path would (the bridge's pump expires the
    // timer wheel) until the queue timer has marked the command.
    let q2 = Arc::clone(&q);
    narf_scheduler::responsive_spin_until(
        move || q2.timed_out(id) == Some(true),
        narf_time::Deadline::after_ms(2_000),
    );
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
#[cfg(not(target_arch = "x86_64"))]
fn install_qemu_controller() -> Option<Result<(), &'static str>> {
    None
}

/// No QEMU NVMe controller off x86_64: nothing to install or tear down.
#[cfg(not(target_arch = "x86_64"))]
struct InstalledQemu;

#[cfg(not(target_arch = "x86_64"))]
impl InstalledQemu {
    fn tear_down(self) {}
}

#[cfg(not(target_arch = "x86_64"))]
fn install_qemu_controller_handle() -> Option<Result<InstalledQemu, &'static str>> {
    None
}

#[cfg(target_arch = "x86_64")]
fn install_qemu_controller() -> Option<Result<(), &'static str>> {
    install_qemu_controller_handle().map(|r| r.map(|_| ()))
}

/// The installed controller of [`install_qemu_controller_handle`]: its
/// instance and the device cap that lets a smoke stop it again.
#[cfg(target_arch = "x86_64")]
struct InstalledQemu {
    instance: u32,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
}

#[cfg(target_arch = "x86_64")]
impl InstalledQemu {
    /// Stop the controller (CC.EN=0) and release its I/O queues' IDT
    /// vectors. A smoke that installs a 16-queue controller and leaves it
    /// behind costs the suite 16 of the IDT's free vectors; enough such
    /// smokes and a later one that needs a vector (the fake IRQ-driven
    /// controllers) finds none. The next smoke's install brings the device
    /// up afresh, as every install here does.
    fn tear_down(self) {
        if let Some(slot) = super::slot_of(self.instance) {
            if let Ok(mut ctrl) = super::acquire(slot) {
                let _ = ctrl.disable_after_failure(&self.cap);
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn install_qemu_controller_handle() -> Option<Result<InstalledQemu, &'static str>> {
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
    let instance = super::install_controller(ctrl);
    Some(Ok(InstalledQemu { instance, cap }))
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
        // The bridge primitives' pump (timer wheel included), as any
        // polled waiter gets it.
        pump_once();
        core::hint::spin_loop();
    }
    true
}

/// The bytes of `nvme0n<nsid>` at `lba`, saved so a writing smoke can put
/// them back: the kernel-test disk is the btrfs image xtask verifies with
/// `btrfs check` after the run.
struct SavedRange {
    nsid: u32,
    lba: u64,
    blocks: u16,
    bytes: Vec<u8>,
}

impl SavedRange {
    fn save(nsid: u32, lba: u64, blocks: u16, lba_bytes: usize) -> Option<Self> {
        let dev = super::NvmeNamespaceBlock::new(0, nsid);
        let mut bytes = alloc::vec![0u8; blocks as usize * lba_bytes];
        dev.read(lba, blocks, &mut bytes).ok()?;
        Some(Self {
            nsid,
            lba,
            blocks,
            bytes,
        })
    }
    fn restore(&self) -> bool {
        super::NvmeNamespaceBlock::new(0, self.nsid)
            .write(self.lba, self.blocks, &self.bytes)
            .is_ok()
    }
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
    let Some(saved) = SavedRange::save(nsid, 8192, (N as u32 * BLOCKS) as u16, lba_bytes as usize)
    else {
        return TestResult::Fail("saving the scratch window failed");
    };
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
    if !saved.restore() {
        return TestResult::Fail("restoring the scratch window failed");
    }
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

// ── Scatter-gather over the queue ─────────────────────────────────

/// `n` separately allocated order-0 frames as a page list of `len` bytes.
fn sg_pages(n: usize, len: usize) -> Option<(Vec<DmaBuffer>, narf_io::sg::PageList)> {
    let mut keep = Vec::new();
    let mut frames = Vec::new();
    for _ in 0..n {
        let b = alloc_coherent(4096, DomainId::DRIVER_0).ok()?;
        frames.push(narf_memory::PhysAddr::new(b.dma_addr().raw()));
        keep.push(b);
    }
    let list = narf_io::sg::PageList::new(frames, len, DomainId::DRIVER_0).ok()?;
    Some((keep, list))
}

fn smoke_nvme_mq_scatter_gather_round_trip_qemu() -> TestResult {
    // A write over 5 non-contiguous pages (PRP1 + a PRP list built from the
    // segments) and a read back into 5 others through the registry
    // device's queue; then a request larger than the controller's maximum
    // transfer, which the block layer splits into children that complete
    // as one.
    use narf_block::{BlockOp, SgRequest};
    match install_qemu_controller() {
        None => return TestResult::Skip("no QEMU NVMe controller"),
        Some(Err(e)) => return TestResult::Fail(e),
        Some(Ok(())) => {}
    }
    let (lba_bytes, nsid) =
        super::with_controller(|c| (c.lba_bytes, c.primary_nsid)).unwrap_or((512, 1));
    let ns_dev: Arc<dyn BlockDeviceSync> = Arc::new(super::NvmeNamespaceBlock::new(0, nsid));
    let Some(queue) = ns_dev.queue() else {
        return TestResult::Fail("no queue");
    };
    let limits = queue.limits();
    // SAFETY: APIC initialised; MSIs land in our IDT vectors.
    unsafe { narf_arch::enable_interrupts() };
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut drive = |mut f: narf_block::BoxedCompletion| -> Option<narf_block::BlockCompletion> {
        let deadline = narf_time::Deadline::after_ms(10_000);
        loop {
            if let Poll::Ready(c) = f.as_mut().poll(&mut cx) {
                return Some(c);
            }
            if deadline.expired() {
                return None;
            }
            pump_once();
            core::hint::spin_loop();
        }
    };
    let pages = 5usize;
    let bytes = pages * 4096;
    let blocks = (bytes / lba_bytes as usize) as u32;
    let Some(saved_small) = SavedRange::save(nsid, 16384, blocks as u16, lba_bytes as usize) else {
        return TestResult::Fail("saving the scratch window failed");
    };
    let Some((wkeep, wlist)) = sg_pages(pages, bytes) else {
        return TestResult::Fail("page allocation failed");
    };
    let Some((rkeep, rlist)) = sg_pages(pages, bytes) else {
        return TestResult::Fail("page allocation failed");
    };
    for (i, b) in wkeep.iter().enumerate() {
        fill(b, 0x40 + i as u8);
    }
    let wcap = narf_io::register_pages_with_cap(wlist);
    let rcap = narf_io::register_pages_with_cap(rlist);
    let (Ok(wr), Ok(rr)) = (
        wcap.derive::<narf_capabilities::Read>(),
        rcap.derive::<narf_capabilities::Read>(),
    ) else {
        return TestResult::Fail("derive failed");
    };
    let w = narf_block::queue::submit_sg(
        &*queue,
        SgRequest::new(BlockOp::Write { fua: false }, 16384, blocks, wr, 7),
    );
    match drive(w) {
        Some(c) if c.result.is_ok() => {}
        _ => return TestResult::Fail("SG write failed or hung"),
    }
    let r =
        narf_block::queue::submit_sg(&*queue, SgRequest::new(BlockOp::Read, 16384, blocks, rr, 8));
    match drive(r) {
        Some(c) if c.result.is_ok() => {}
        _ => return TestResult::Fail("SG read failed or hung"),
    }
    for (i, b) in rkeep.iter().enumerate() {
        if !check(b, 0x40 + i as u8) {
            return TestResult::Fail("SG read-back mismatch: the device did not land each page");
        }
    }
    narf_io::unregister_pages(wcap);
    narf_io::unregister_pages(rcap);
    if !saved_small.restore() {
        return TestResult::Fail("restoring the scratch window failed");
    }

    // Over the maximum transfer: split into children, data intact.
    let big_pages = (limits.max_transfer_bytes as usize / 4096 + 2).min(600);
    let big_bytes = big_pages * 4096;
    let big_blocks = (big_bytes / lba_bytes as usize) as u32;
    let Some(saved_big) = SavedRange::save(nsid, 32768, big_blocks as u16, lba_bytes as usize)
    else {
        return TestResult::Fail("saving the scratch window failed");
    };
    let Some((wkeep, wlist)) = sg_pages(big_pages, big_bytes) else {
        return TestResult::Skip("not enough DMA memory for the split case");
    };
    let Some((rkeep, rlist)) = sg_pages(big_pages, big_bytes) else {
        return TestResult::Skip("not enough DMA memory for the split case");
    };
    for (i, b) in wkeep.iter().enumerate() {
        fill(b, i as u8);
    }
    let wcap = narf_io::register_pages_with_cap(wlist);
    let rcap = narf_io::register_pages_with_cap(rlist);
    let (Ok(wr), Ok(rr)) = (
        wcap.derive::<narf_capabilities::Read>(),
        rcap.derive::<narf_capabilities::Read>(),
    ) else {
        return TestResult::Fail("derive failed");
    };
    let w = narf_block::queue::submit_sg(
        &*queue,
        SgRequest::new(BlockOp::Write { fua: false }, 32768, big_blocks, wr, 9),
    );
    match drive(w) {
        Some(c) if c.result.is_ok() => {}
        _ => return TestResult::Fail("split SG write failed or hung"),
    }
    let r = narf_block::queue::submit_sg(
        &*queue,
        SgRequest::new(BlockOp::Read, 32768, big_blocks, rr, 10),
    );
    match drive(r) {
        Some(c) if c.result.is_ok() => {}
        _ => return TestResult::Fail("split SG read failed or hung"),
    }
    for (i, b) in rkeep.iter().enumerate() {
        if !check(b, i as u8) {
            return TestResult::Fail("split SG read-back mismatch");
        }
    }
    // SAFETY: counterpart to the enable above.
    unsafe { narf_arch::disable_interrupts() };
    narf_io::unregister_pages(wcap);
    narf_io::unregister_pages(rcap);
    if !saved_big.restore() {
        return TestResult::Fail("restoring the scratch window failed");
    }
    if queue.in_flight() != 0 {
        return TestResult::Fail("commands left in flight");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/mq",
    smoke_nvme_mq_scatter_gather_round_trip_qemu
);

// ── interrupt delivery to a waiter on another CPU (QEMU) ──────────

/// State shared with the pinned waiter task of
/// [`smoke_nvme_mq_irq_wakes_waiter_on_other_cpu_qemu`].
static XCPU_DONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static XCPU_FAILS: AtomicUsize = AtomicUsize::new(0);
static XCPU_MAX_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn smoke_nvme_mq_irq_wakes_waiter_on_other_cpu_qemu() -> TestResult {
    // Every I/O queue's MSI-X entry targets CPU 0's APIC; a request is
    // posted on the submitting CPU's queue. So a task on CPU k != 0 that
    // awaits a read is completed by an ISR on CPU 0, which must wake it
    // across CPUs — the shape of every userspace mount on the desktop,
    // where it took 250 ms per request. With no poll slice left on an
    // IRQ queue, the only ways a request ends are the interrupt's wake
    // (fast) or the 30 s timeout: the test demands the former, from the
    // queue's own counters (completions published by the ISR, none found
    // by the timeout's poll, no slow pickups) and from the latency.
    let qemu = match install_qemu_controller_handle() {
        None => return TestResult::Skip("no QEMU NVMe controller"),
        Some(Err(e)) => return TestResult::Fail(e),
        Some(Ok(q)) => q,
    };
    let result = xcpu_irq_wake_body();
    // Give the IDT its 16 vectors back (see `InstalledQemu::tear_down`).
    qemu.tear_down();
    result
}

fn xcpu_irq_wake_body() -> TestResult {
    const N: usize = 12;
    let (queues, any_polled) = super::with_controller(|c| {
        (
            c.io_queue_count(),
            c.io_queues().iter().any(|q| q.vector.is_none()),
        )
    })
    .unwrap_or((0, true));
    if queues == 0 || any_polled {
        return TestResult::Skip("I/O queues are polled (no MSI-X)");
    }
    let me = narf_lib::percpu::current_cpu();
    let Some(other) =
        (0..narf_lib::percpu::MAX_CPUS).find(|&c| c != me && narf_lib::smp::is_online(c as u32))
    else {
        return TestResult::Skip("no second online CPU");
    };
    let lba_bytes = super::with_controller(|c| c.lba_bytes as usize).unwrap_or(512);
    let bytes = 4096.max(lba_bytes);
    let blocks = (bytes / lba_bytes) as u32;
    XCPU_DONE.store(false, Ordering::Release);
    XCPU_FAILS.store(0, Ordering::Release);
    XCPU_MAX_NS.store(0, Ordering::Release);
    // The queue that CPU will use, with its counters before the run.
    let qix = other % queues;
    let before = super::with_controller(|c| c.io_queues()[qix].stats()).unwrap_or_default();
    // SAFETY: APIC initialised; the queues' MSIs land in our IDT vectors.
    unsafe { narf_arch::enable_interrupts() };
    narf_scheduler::spawn_stackful_pinned(
        async move {
            let dev = super::NvmeBlockDevice;
            for i in 0..N {
                let Ok(buf) = alloc_coherent(bytes, DomainId::DRIVER_0) else {
                    XCPU_FAILS.fetch_add(1, Ordering::AcqRel);
                    break;
                };
                let cap = register_with_cap(buf);
                let req = BlockRequest {
                    op: BlockOp::Read,
                    lba: 8192 + (i as u64) * blocks as u64,
                    blocks,
                    buffer: cap.derive().expect("derive"),
                    qos: QosHint::Latency,
                    user_tag: i as u64,
                };
                let t0 = narf_time::now_cycles();
                let c = dev.submit(req).await;
                let ns = narf_time::cycles_to_ns(narf_time::now_cycles().wrapping_sub(t0));
                XCPU_MAX_NS.fetch_max(ns, Ordering::AcqRel);
                narf_io::unregister(cap);
                if c.result.is_err() {
                    XCPU_FAILS.fetch_add(1, Ordering::AcqRel);
                }
            }
            XCPU_DONE.store(true, Ordering::Release);
        },
        other as u32,
    );
    let finished = narf_scheduler::responsive_spin_until(
        || XCPU_DONE.load(Ordering::Acquire),
        narf_time::Deadline::after_ms(20_000),
    );
    // SAFETY: counterpart to the enable above.
    unsafe { narf_arch::disable_interrupts() };
    let after = super::with_controller(|c| c.io_queues()[qix].stats()).unwrap_or_default();
    let max_us = XCPU_MAX_NS.load(Ordering::Acquire) / 1_000;
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "nvme-mq: {N} reads from CPU {other} on q{} (vec {:?} msix {:?} apic {:?}): \
             max {max_us} us; isr {} poll {} irq_missed {} slow_pickups {} pickup_max {} us",
            after.qid,
            after.vector,
            after.msix_entry,
            after.target_apic,
            after.reaped_isr.wrapping_sub(before.reaped_isr),
            after.reaped_poll.wrapping_sub(before.reaped_poll),
            after.irq_missed.wrapping_sub(before.irq_missed),
            after.slow_pickups.wrapping_sub(before.slow_pickups),
            after.pickup_max_ns / 1_000,
        );
    }
    if !finished {
        return TestResult::Fail("reads from another CPU did not finish in 20 s");
    }
    if XCPU_FAILS.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("a read from another CPU failed");
    }
    if after.reaped_isr.wrapping_sub(before.reaped_isr) < N as u64 {
        return TestResult::Fail("completions were not published by the queue's ISR");
    }
    if after.irq_missed != before.irq_missed {
        return TestResult::Fail("a completion was found only by the timeout's poll");
    }
    if after.slow_pickups != before.slow_pickups {
        return TestResult::Fail("an ISR-published completion took >10 ms to reach its waiter");
    }
    if max_us > 50_000 {
        return TestResult::Fail("a read awaited from another CPU took over 50 ms");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/mq",
    smoke_nvme_mq_irq_wakes_waiter_on_other_cpu_qemu
);
