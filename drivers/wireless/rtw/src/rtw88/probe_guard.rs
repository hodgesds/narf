//! Serialize the complete synchronous admission/power/publication transaction.
use core::sync::atomic::{AtomicBool, Ordering};
struct Claim<'a>(&'a AtomicBool);
impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
/// An overlapping probe returns without entering configuration/MMIO or parking
/// another probe's initializing function. No spinlock spans power waits/spawn.
pub(super) fn run<T>(busy: &AtomicBool, operation: impl FnOnce() -> T) -> Option<T> {
    busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()?;
    let _claim = Claim(busy);
    Some(operation())
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_rtw88_overlapping_probes_have_one_retained_native_owner_and_task() -> TestResult {
        let busy = AtomicBool::new(false);
        let bound = Cell::new(false);
        let cold_power = Cell::new(0);
        let owners = Cell::new(0);
        let tasks = Cell::new(0);
        let extra_park = Cell::new(0);
        let outer = run(&busy, || {
            // Force both same-function and distinct-function overlap after
            // admission but before any owner has been retained/published.
            for same_function in [true, false] {
                if run(&busy, || {
                    if same_function {
                        cold_power.set(cold_power.get() + 1);
                        owners.set(owners.get() + 1);
                        tasks.set(tasks.get() + 1);
                    } else {
                        extra_park.set(extra_park.get() + 1);
                    }
                })
                .is_some()
                {
                    return false;
                }
            }
            cold_power.set(cold_power.get() + 1);
            owners.set(owners.get() + 1);
            bound.set(true); // controller and registry now retain same owner
            tasks.set(tasks.get() + 1);
            true
        });
        if outer != Some(true)
            || busy.load(Ordering::Acquire)
            || cold_power.get() != 1
            || owners.get() != 1
            || tasks.get() != 1
            || extra_park.get() != 0
        {
            return TestResult::Fail(
                "overlapping probe reset, parked or reconstructed native owner",
            );
        }
        // Once publication completes, normal admission sees the retained
        // function; the guard has released, but no native attempt is rebuilt.
        if run(&busy, || {
            if !bound.get() {
                owners.set(owners.get() + 1);
            }
        })
        .is_none()
            || owners.get() != 1
        {
            return TestResult::Fail("completed probe guard lost bound-owner admission");
        }
        // Ordinary early-return errors must release the reservation, too.
        if run(&busy, || Err::<(), _>(7)) != Some(Err(7))
            || run(&busy, || Ok::<(), u8>(())).is_none()
        {
            return TestResult::Fail("failed probe retained in-progress reservation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw88",
        smoke_rtw88_overlapping_probes_have_one_retained_native_owner_and_task
    );
}
