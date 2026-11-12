//! Queued virtio-blk smokes against QEMU's `virtio-blk-pci` (`vblk0`):
//! several requests at the device at once through the registry device's
//! queue, data intact under interleaved writers, and a dropped request
//! future releasing its payload only on completion.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_block::{BlockDevice, BlockOp, BlockRequest, QosHint};
use narf_io::{alloc_coherent, register_with_cap, DmaBuffer};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use crate::blk_mq::{submit_async, BlkOp};

static PEAK: AtomicUsize = AtomicUsize::new(0);
static FAILURES: AtomicUsize = AtomicUsize::new(0);
/// First failing step of the integrity smoke: 1 write, 2 read, 3 data,
/// 4 cap resolve.
static FIRST_FAIL: AtomicUsize = AtomicUsize::new(0);

fn note_fail(step: usize) {
    let _ = FIRST_FAIL.compare_exchange(0, step, Ordering::AcqRel, Ordering::Acquire);
}

fn noop_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    unsafe fn no_op(_: *const ()) {}
    const VTAB: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    // SAFETY: the vtable's functions ignore the (null) data pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTAB)) }
}

fn fill(buf: &DmaBuffer, seed: u8) {
    // SAFETY: a live coherent buffer, exclusively ours.
    unsafe {
        let p = buf.cpu_mut_ptr::<u8>();
        for i in 0..buf.len() {
            core::ptr::write_volatile(p.add(i), (i as u8).wrapping_mul(13).wrapping_add(seed));
        }
    }
}

fn check(buf: &DmaBuffer, seed: u8) -> bool {
    // SAFETY: as `fill`.
    unsafe {
        let p = buf.cpu_ptr::<u8>();
        (0..buf.len()).all(|i| {
            core::ptr::read_volatile(p.add(i)) == (i as u8).wrapping_mul(13).wrapping_add(seed)
        })
    }
}

/// Drive `futs` round-robin by hand (see the NVMe `tests_mq` sibling).
fn drive_all(
    mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>>,
    deadline: narf_time::Deadline,
) -> bool {
    let waker = noop_waker();
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

fn vblk() -> Option<Arc<narf_block::SyncBlock>> {
    let dev = narf_block::find_block_device("vblk0")?;
    Some(narf_block::SyncBlock::new(dev))
}

fn smoke_vblk_mq_concurrent_integrity_qemu() -> TestResult {
    // N tasks each write their own pattern to their own range through the
    // registry device's queue, read it back and verify, interleaved with
    // every other task; more than one request must be at the device at
    // once; nothing is left in flight.
    // The kernel-test virtio disk is 64 KiB (128 sectors): ten tasks x 8
    // sectors (one page each, so the whole buffer is transferred and
    // checked) from sector 32.
    const N: usize = 10;
    const BLOCKS: u32 = 8;
    let Some(sync) = vblk() else {
        return TestResult::Skip("no virtio-blk device");
    };
    let Some(queue) = sync.queue().cloned() else {
        return TestResult::Fail("vblk0 exposes no queue");
    };
    if queue.limits().queue_depth < 2 {
        return TestResult::Fail("queue depth below two");
    }
    // SAFETY: APIC initialised; the queue's MSI lands in our IDT vector.
    unsafe { narf_arch::enable_interrupts() };
    PEAK.store(0, Ordering::Release);
    FAILURES.store(0, Ordering::Release);
    FIRST_FAIL.store(0, Ordering::Release);
    let mut futs: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = Vec::new();
    for i in 0..N {
        let sync = Arc::clone(&sync);
        let queue = Arc::clone(&queue);
        futs.push(Box::pin(async move {
            let seed = (i as u8).wrapping_mul(5).wrapping_add(1);
            let lba = 32 + (i as u64) * BLOCKS as u64;
            let bytes = BLOCKS as usize * 512;
            let wbuf = alloc_coherent(bytes, DomainId::DRIVER_0).expect("alloc");
            fill(&wbuf, seed);
            let wcap = register_with_cap(wbuf);
            let rbuf = alloc_coherent(bytes, DomainId::DRIVER_0).expect("alloc");
            let rcap = register_with_cap(rbuf);
            let mut ok = true;
            for round in 0..2u8 {
                let w = sync
                    .submit(BlockRequest {
                        op: BlockOp::Write { fua: round == 1 },
                        lba,
                        blocks: BLOCKS,
                        buffer: wcap.derive().expect("derive"),
                        qos: QosHint::Throughput,
                        user_tag: i as u64,
                    })
                    .await;
                if w.result.is_err() {
                    note_fail(1);
                }
                ok &= w.result.is_ok();
                let r = sync.submit(BlockRequest {
                    op: BlockOp::Read,
                    lba,
                    blocks: BLOCKS,
                    buffer: rcap.derive().expect("derive"),
                    qos: QosHint::Latency,
                    user_tag: i as u64,
                });
                let mut r = core::pin::pin!(r);
                let c = core::future::poll_fn(|cx| {
                    let p = r.as_mut().poll(cx);
                    PEAK.fetch_max(queue.in_flight(), Ordering::AcqRel);
                    p
                })
                .await;
                if c.result.is_err() {
                    note_fail(2);
                }
                ok &= c.result.is_ok();
                match narf_io::resolve_cap(&rcap) {
                    Some(rb) => {
                        if !check(&rb, seed) {
                            note_fail(3);
                        }
                        ok &= check(&rb, seed);
                        fill(&rb, seed.wrapping_add(1));
                    }
                    None => {
                        note_fail(4);
                        ok = false
                    }
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
        return TestResult::Fail("concurrent requests did not all complete in 30 s");
    }
    if FAILURES.load(Ordering::Acquire) != 0 {
        return TestResult::Fail(match FIRST_FAIL.load(Ordering::Acquire) {
            1 => "a concurrent write completed with an error",
            2 => "a concurrent read completed with an error",
            3 => "a task's data did not survive concurrent I/O",
            _ => "a task's read buffer cap did not resolve",
        });
    }
    if PEAK.load(Ordering::Acquire) < 2 {
        return TestResult::Fail("never more than one request in flight");
    }
    if queue.in_flight() != 0 {
        return TestResult::Fail("requests left in flight");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/blk-pci/mq",
    smoke_vblk_mq_concurrent_integrity_qemu
);

fn smoke_vblk_mq_dropped_request_releases_on_completion_qemu() -> TestResult {
    // A request future dropped after posting: its payload pin and slot are
    // released only once the device completes it (the next process-context
    // visitor reclaims), never by the drop.
    let Some(mq) = crate::blk_pci::with_controller(|c| Arc::clone(c.mq())) else {
        return TestResult::Skip("no virtio-blk device");
    };
    let slots = mq.slot_count();
    let payload = Arc::new(match alloc_coherent(512, DomainId::DRIVER_0) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("alloc_coherent failed"),
    });
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut fut = submit_async(
        Arc::clone(&mq),
        BlkOp::Read,
        0,
        Some(Arc::clone(&payload)),
        512,
    );
    let posted = matches!(Pin::new(&mut fut).poll(&mut cx), Poll::Pending);
    if !posted && Arc::strong_count(&payload) == 1 {
        // QEMU completed inline before the first poll returned: the slot
        // was reaped by the poll itself, which is also correct.
        return TestResult::Pass;
    }
    drop(fut);
    if Arc::strong_count(&payload) != 2 && mq.free_slots() == slots {
        return TestResult::Fail("the drop released the payload before completion");
    }
    // Let the device finish and a process-context visitor reclaim.
    let done = narf_scheduler::responsive_spin_until(
        || {
            if mq.used_pending() {
                mq.process_used(false);
            }
            mq.sweep();
            Arc::strong_count(&payload) == 1 && mq.free_slots() == slots
        },
        narf_time::Deadline::after_ms(5_000),
    );
    if !done {
        return TestResult::Fail("an abandoned request was never reclaimed after completion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/blk-pci/mq",
    smoke_vblk_mq_dropped_request_releases_on_completion_qemu
);
