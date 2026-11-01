//! Exercise the real controller gate with a descheduled holder and masked
//! waiter. No controller is registered and no device or DMA buffer is touched.

use alloc::sync::Arc;
use alloc::task::Wake;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use core::task::{Poll, Waker};

#[cfg(target_arch = "aarch64")]
use narf_arch::aarch64::kernel_ctx::KernelContext;
#[cfg(target_arch = "x86_64")]
use narf_arch::x86_64::kernel_ctx::KernelContext;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_scheduler::stackful::KernelTask;

use super::{acquire, leak_slot, Controller};

struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// A holder suspended on this CPU must get a chance to resume while another
/// task is acquiring its gate. Explicit switches make this independent of
/// timer timing and device latency, including on a single CPU.
fn smoke_nvme_gate_yields_to_descheduled_holder() -> TestResult {
    let slot = leak_slot(u32::MAX, None, Controller::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let waiter_done = done.clone();
    let mut holder = KernelTask::new(async move {
        let guard = acquire(slot);
        let _ = narf_scheduler::cooperative_yield();
        drop(guard);
    });
    let mut waiter = KernelTask::new(async move {
        let guard = acquire(slot);
        waiter_done.store(true, Ordering::Release);
        drop(guard);
    });
    // Only explicit cooperative switches may advance this test. A timer
    // preemption must not accidentally rescue a non-yielding gate waiter.
    holder.set_no_preempt(true);
    waiter.set_no_preempt(true);
    let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut exec = KernelContext::default();

    // SAFETY: these private tasks and executor context are polled serially
    // on this CPU; no executor or other CPU can poll either task.
    let held = unsafe { holder.poll_to_yield(&mut exec, &waker) };
    let gate_held = slot.req_gate.load(Ordering::Acquire);
    wakes.0.store(0, Ordering::Relaxed);
    // SAFETY: same exclusive, serial ownership as above.
    let waiting = unsafe { waiter.poll_to_yield(&mut exec, &waker) };
    let waiter_rearmed = wakes.0.load(Ordering::Relaxed) != 0;
    let still_exclusive = !done.load(Ordering::Acquire);
    // Resume the holder before the waiter: it owns the only release path.
    // SAFETY: same exclusive, serial ownership as above.
    let released = unsafe { holder.poll_to_yield(&mut exec, &waker) };
    // SAFETY: same exclusive, serial ownership as above.
    let completed = unsafe { waiter.poll_to_yield(&mut exec, &waker) };

    if held != Poll::Pending || !gate_held {
        return TestResult::Fail("holder did not suspend while retaining the NVMe gate");
    }
    if waiting != Poll::Pending || !waiter_rearmed || !still_exclusive {
        return TestResult::Fail("contended NVMe waiter did not re-arm and yield exclusively");
    }
    if released != Poll::Ready(()) || completed != Poll::Ready(()) {
        return TestResult::Fail("NVMe holder and waiter did not resume to completion");
    }
    if !done.load(Ordering::Acquire) || slot.req_gate.load(Ordering::Acquire) {
        return TestResult::Fail("NVMe waiter failed to acquire and release after the holder");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/req_gate/cooperative",
    smoke_nvme_gate_yields_to_descheduled_holder
);

static MASKED_GATE: AtomicPtr<AtomicBool> = AtomicPtr::new(core::ptr::null_mut());
static MASKED_CALLS: AtomicUsize = AtomicUsize::new(0);

fn release_masked_gate() {
    let flag = MASKED_GATE.load(Ordering::Acquire);
    if !flag.is_null() {
        MASKED_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the test publishes a leaked slot's request gate and keeps
        // it alive after restoring the prior spin hook.
        unsafe { &*flag }.store(false, Ordering::Release);
    }
}

/// Without a stackful task to yield, servicing pending TLB work is the only
/// way out of this wait. Model its acknowledgement by releasing the gate in
/// the real masked-spin hook, as the virtio request-gate regression does.
fn smoke_nvme_gate_services_masked_work() -> TestResult {
    let slot = leak_slot(u32::MAX, None, Controller::new(0));
    MASKED_CALLS.store(0, Ordering::Relaxed);
    MASKED_GATE.store(
        core::ptr::from_ref(&slot.req_gate).cast_mut(),
        Ordering::Release,
    );
    let previous = narf_lib::sync::__test_swap_lock_spin_hook(Some(release_masked_gate));
    slot.req_gate.store(true, Ordering::Release);
    narf_lib::sync::without_interrupts(|| drop(acquire(slot)));
    let fallback_serviced = MASKED_CALLS.load(Ordering::Relaxed) != 0;

    // A stackful task also must not switch away while its caller has IRQs
    // masked (for example, while holding an IRQ-safe lock).
    MASKED_CALLS.store(0, Ordering::Relaxed);
    slot.req_gate.store(true, Ordering::Release);
    let mut task = KernelTask::new(async move {
        narf_lib::sync::without_interrupts(|| drop(acquire(slot)));
    });
    task.set_no_preempt(true);
    let waker = Waker::from(Arc::new(WakeCount(AtomicUsize::new(0))));
    let mut exec = KernelContext::default();
    // SAFETY: this private task and executor context are polled serially
    // on this CPU, with no executor or other CPU able to poll the task.
    let masked_result = unsafe { task.poll_to_yield(&mut exec, &waker) };
    if masked_result == Poll::Pending {
        // Complete an incorrectly yielded task before reporting failure.
        slot.req_gate.store(false, Ordering::Release);
        // SAFETY: same exclusive, serial ownership as above.
        let _ = unsafe { task.poll_to_yield(&mut exec, &waker) };
    }
    let _ = narf_lib::sync::__test_swap_lock_spin_hook(previous);
    MASKED_GATE.store(core::ptr::null_mut(), Ordering::Release);
    if !fallback_serviced || MASKED_CALLS.load(Ordering::Relaxed) == 0 {
        return TestResult::Fail("masked NVMe gate waiter did not service pending TLB work");
    }
    if masked_result != Poll::Ready(()) {
        return TestResult::Fail("NVMe gate waiter yielded while its caller had IRQs masked");
    }
    if slot.req_gate.load(Ordering::Acquire) {
        return TestResult::Fail("NVMe gate remained held after the masked wait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/req_gate/masked",
    smoke_nvme_gate_services_masked_work
);
