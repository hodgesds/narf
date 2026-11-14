//! Blocking-I/O wake metadata. Placement and dispatch decisions remain policy
//! callbacks; this module only publishes the exact scheduler-owned wakee.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{RawWaker, RawWakerVTable, Waker};

// Conservative overhead gate only. Once a CPU has received this kind of wake,
// policies may inspect the per-task metadata. It never selects a task, and a
// stale true cannot change eligibility or scheduling authority.
static POSSIBLE: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

pub(crate) fn mark_possible(cpu: usize) {
    if let Some(possible) = POSSIBLE.get(cpu) {
        if !possible.load(Ordering::Acquire) {
            possible.store(true, Ordering::Release);
        }
    }
}

pub(crate) fn possible(cpu: usize) -> bool {
    POSSIBLE
        .get(cpu)
        .is_some_and(|state| state.load(Ordering::Acquire))
}

pub(crate) fn reset(cpu: usize) {
    if let Some(possible) = POSSIBLE.get(cpu) {
        possible.store(false, Ordering::Release);
    }
}

/// Clone a scheduler task waker for a blocking-I/O registration. The clone
/// retains the same WakeCell allocation and wake delivery, with blocking-I/O
/// metadata offered to Scheduler::pick_wakeup. Foreign/mismatched wakers
/// retain their original behavior. It neither migrates synchronously nor
/// requests a direct context transfer or immediate syscall-exit yield.
pub fn blocking_io_waker(waker: &Waker, expected_task: u64) -> Waker {
    if expected_task != 0 && core::ptr::eq(waker.vtable(), &crate::TASK_VTABLE) {
        let cell = waker.data().cast::<crate::WakeCell>();
        // SAFETY: vtable identity proves the borrowed waker owns a live
        // WakeCell Arc; its lifetime covers the id/eligibility checks and clone.
        let valid = unsafe {
            (*cell).task == expected_task && (*cell).direct_eligible.load(Ordering::Acquire)
        };
        if valid {
            // SAFETY: the original waker pins cell while we acquire the new
            // reference. VTABLE's clone/drop pair owns exactly that reference.
            unsafe { Arc::increment_strong_count(cell) };
            // SAFETY: cell is a WakeCell Arc reference owned by this RawWaker.
            return unsafe { Waker::from_raw(RawWaker::new(cell.cast(), &VTABLE)) };
        }
    }
    waker.clone()
}

unsafe fn wake_ref(data: *const ()) {
    // SAFETY: only our vtable calls this with its live WakeCell Arc reference.
    let fresh = unsafe { crate::wake_by_ref_impl(data, None) };
    if !fresh {
        return;
    }
    // SAFETY: the caller's reference remains live throughout wake publication.
    let cell = unsafe { &*data.cast::<crate::WakeCell>() };
    if !cell.direct_eligible.load(Ordering::Acquire) {
        return;
    }
    let home = cell.cpu.load(Ordering::Acquire);
    cell.blocking_wake.store(true, Ordering::Release);
    mark_possible(home as usize);
    // Placement may already have kicked home before this metadata was
    // published. Publish another normal kick so its request is visible.
    crate::notify_wake_cpu(home);
}

unsafe fn clone_raw(data: *const ()) -> RawWaker {
    // SAFETY: a live waker owns the reference being cloned; add one for output.
    unsafe { Arc::increment_strong_count(data.cast::<crate::WakeCell>()) };
    RawWaker::new(data, &VTABLE)
}

unsafe fn wake_raw(data: *const ()) {
    // SAFETY: this call consumes the RawWaker's one owned Arc reference.
    let cell = unsafe { Arc::from_raw(data.cast::<crate::WakeCell>()) };
    // SAFETY: cell pins the allocation until wake_ref returns.
    unsafe { wake_ref(data) };
    drop(cell);
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_raw, wake_raw, wake_ref, crate::drop_raw);

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_blocking_waker_alias_preserves_lifetime_and_identity() -> TestResult {
        crate::__reset_queues_for_test();
        let id = crate::alloc_task_id();
        let cpu = narf_lib::percpu::current_cpu();
        let cell = crate::new_wake_cell(id, cpu as u32, true);
        let ordinary = crate::make_waker(cell.clone());
        let mismatch = blocking_io_waker(&ordinary, id.raw() + 1);
        if !mismatch.will_wake(&ordinary) {
            return TestResult::Fail("mismatched task changed waker identity");
        }
        drop(mismatch);
        let foreign = Waker::noop();
        if !blocking_io_waker(foreign, id.raw()).will_wake(foreign) {
            return TestResult::Fail("foreign waker was upgraded");
        }
        let tagged = blocking_io_waker(&ordinary, id.raw());
        let cloned = tagged.clone();
        if Arc::strong_count(&cell) != 4 {
            return TestResult::Fail("blocking waker clone did not own one Arc each");
        }
        drop(tagged);
        cell.flag.store(false, Ordering::Release);
        cloned.wake();
        drop(ordinary);
        let ok = Arc::strong_count(&cell) == 1
            && cell.flag.load(Ordering::Acquire)
            && cell.blocking_wake.load(Ordering::Acquire)
            && possible(cpu);
        crate::__reset_queues_for_test();
        if !ok {
            return TestResult::Fail("blocking waker lost wake metadata or leaked its Arc");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler",
        smoke_blocking_waker_alias_preserves_lifetime_and_identity
    );
}
