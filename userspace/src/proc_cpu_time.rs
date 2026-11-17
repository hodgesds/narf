//! Monotonic procfs views of independently folded CPU counters.
//!
//! Own-stack slices include syscall execution. Like Linux cputime_adjust,
//! retain the previous split so neither field regresses when syscall time
//! is folded before its enclosing scheduler slice. Readers serialize this
//! view; accounting writers continue using only their existing atomics.
#[derive(Default)]
pub(crate) struct AdjustedCpuTime {
    user: u64,
    kernel: u64,
}
impl AdjustedCpuTime {
    pub(crate) fn sample(&mut self, runtime: u64, kernel: u64) -> (u64, u64) {
        if runtime > self.user.saturating_add(self.kernel) {
            // Only charge completed runtime, without stealing previously
            // reported user time when a later kernel span is folded.
            self.kernel = kernel.min(runtime - self.user).max(self.kernel);
            self.user = runtime - self.kernel;
        }
        (self.user, self.kernel)
    }
}
#[cfg(any(test, feature = "kernel-test"))]
fn valid_adjustments() -> bool {
    let mut time = AdjustedCpuTime::default();
    for (runtime, kernel, expected) in [
        (100, 30, (70, 30)),
        (100, 80, (70, 30)), // kernel folds before the enclosing slice
        (150, 80, (70, 80)),
        (200, 60, (120, 80)),   // stale kernel observation
        (180, 90, (120, 80)),   // reordered total snapshot
        (250, 500, (120, 130)), // kernel outruns folded total
        (600, 500, (120, 480)),
        (650, 500, (150, 500)),
    ] {
        if time.sample(runtime, kernel) != expected {
            return false;
        }
    }
    for seed in 0..32 {
        let mut time = AdjustedCpuTime::default();
        let mut previous = (0, 0);
        for runtime in 0..256 {
            let kernel = (runtime * 17 + seed * 31) % 384;
            let next = time.sample(runtime, kernel);
            if next.0 < previous.0 || next.1 < previous.1 || next.0 + next.1 != runtime {
                return false;
            }
            previous = next;
        }
    }
    true
}
#[cfg(test)]
#[test]
fn cpu_times_preserve_runtime_and_monotonic_fields() {
    assert!(valid_adjustments());
}
#[cfg(feature = "kernel-test")]
fn smoke_proc_cpu_times_preserve_runtime_and_monotonic_fields() -> narf_kernel_test::TestResult {
    if valid_adjustments() {
        narf_kernel_test::TestResult::Pass
    } else {
        narf_kernel_test::TestResult::Fail("proc CPU split regressed or double-counted runtime")
    }
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "syscall_abi/proc_snapshot",
    smoke_proc_cpu_times_preserve_runtime_and_monotonic_fields
);
