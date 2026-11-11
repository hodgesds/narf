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
        // Only a waiter that really got the gate counts as done.
        if let Ok(guard) = acquire(slot) {
            waiter_done.store(true, Ordering::Release);
            drop(guard);
        }
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

/// Shortened stall bounds for the smoke below, restored on every exit.
struct StallBounds;

impl StallBounds {
    fn set(warn_ms: u64, fail_ms: u64) -> Self {
        super::GATE_STALL_WARN_MS_FOR_TEST.store(warn_ms, Ordering::Release);
        super::GATE_STALL_FAIL_MS_FOR_TEST.store(fail_ms, Ordering::Release);
        StallBounds
    }
}

impl Drop for StallBounds {
    fn drop(&mut self) {
        super::GATE_STALL_WARN_MS_FOR_TEST.store(0, Ordering::Release);
        super::GATE_STALL_FAIL_MS_FOR_TEST.store(0, Ordering::Release);
    }
}

/// A gate whose holder never releases it is neither silent nor forever:
/// the gate records who took it, a waiter reports the holder once it has
/// waited the warn bound, and once the holder has shown no progress for
/// the fail bound the waiter gets `GateTimeout` — without having taken,
/// released or otherwise disturbed the gate. A progress mark from the
/// holder restarts the fail bound. Short test-only bounds; the production
/// bounds are only compared against.
fn smoke_nvme_gate_stall_is_reported_and_bounded() -> TestResult {
    use super::NvmeError;
    if super::GATE_STALL_WARN_MS != 2_000 || super::GATE_STALL_FAIL_MS != 60_000 {
        return TestResult::Fail("gate stall bounds are not 2 s / 60 s");
    }
    let slot = leak_slot(u32::MAX, None, Controller::new(0));
    let Ok(held) = acquire(slot) else {
        return TestResult::Fail("an uncontended gate was not acquired");
    };
    // The holder is on record: this CPU, this task, a timestamp.
    let owner = slot.gate_owner.load(Ordering::Relaxed);
    if owner >> super::GATE_OWNER_TASK_BITS != narf_lib::percpu::current_cpu() as u64
        || owner & ((1 << super::GATE_OWNER_TASK_BITS) - 1)
            != narf_scheduler::current_task_id().raw() & ((1 << super::GATE_OWNER_TASK_BITS) - 1)
        || slot.gate_since.load(Ordering::Relaxed) == 0
    {
        return TestResult::Fail("the gate did not record its holder's CPU / task / time");
    }

    const WARN_MS: u64 = 20;
    const FAIL_MS: u64 = 120;
    let bounds = StallBounds::set(WARN_MS, FAIL_MS);
    let reports0 = super::gate_stall_reports();
    let timeouts0 = super::gate_timeouts();
    let t0 = narf_time::now_cycles();
    let outcome = acquire(slot);
    let waited_ms = narf_time::cycles_to_ns(narf_time::now_cycles().saturating_sub(t0)) / 1_000_000;
    match outcome {
        Err(NvmeError::GateTimeout) => {}
        Err(_) => return TestResult::Fail("a stalled gate failed with the wrong error"),
        Ok(_) => return TestResult::Fail("a second guard was handed out for a held gate"),
    }
    // At least the warn-bound report and the failing one.
    if super::gate_stall_reports() < reports0 + 2 {
        return TestResult::Fail("the waiter did not report the holder before failing");
    }
    if super::gate_timeouts() != timeouts0 + 1 {
        return TestResult::Fail("the gate timeout was not counted exactly once");
    }
    if !(FAIL_MS..30_000).contains(&waited_ms) {
        return TestResult::Fail("the waiter did not fail at its bound");
    }
    if !slot.req_gate.load(Ordering::Acquire) {
        return TestResult::Fail("a failed waiter released a gate it never held");
    }

    // A holder that marks progress is not stalled: with the mark placed
    // FAIL_MS/2 into the future the waiter must outlast one whole bound
    // from *that* point, not from its own arrival.
    let half = narf_time::wall::ns_to_cycles(FAIL_MS / 2 * 1_000_000);
    slot.gate_progress
        .store(narf_time::now_cycles() + half, Ordering::Relaxed);
    let t0 = narf_time::now_cycles();
    let outcome = acquire(slot);
    let waited_ms = narf_time::cycles_to_ns(narf_time::now_cycles().saturating_sub(t0)) / 1_000_000;
    drop(bounds);
    if !matches!(outcome, Err(NvmeError::GateTimeout)) {
        return TestResult::Fail("the waiter did not fail after the holder's progress mark aged");
    }
    if waited_ms < FAIL_MS + FAIL_MS / 4 {
        return TestResult::Fail("a holder's progress mark did not restart the fail bound");
    }

    // Released: the next acquisition is immediate and silent.
    drop(held);
    let reports1 = super::gate_stall_reports();
    match acquire(slot) {
        Ok(guard) => drop(guard),
        Err(_) => return TestResult::Fail("the gate was not acquirable after its release"),
    }
    if super::gate_stall_reports() != reports1 || slot.req_gate.load(Ordering::Acquire) {
        return TestResult::Fail("an uncontended acquisition reported a stall or leaked the gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/nvme/req_gate/stall",
    smoke_nvme_gate_stall_is_reported_and_bounded
);
