use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn cs_kernel_dependency_wait_refuses_terminal_card() -> TestResult {
    struct Never;
    impl narf_filesystem::DrmFence for Never {
        fn is_signalled(&self) -> bool {
            false
        }
        fn wait(&self, _: u64) -> bool {
            false
        }
        fn driver_name(&self) -> &str {
            "test"
        }
    }
    const CARD: u32 = 0xfeed_0405;
    let guard = narf_scheduler::block_on_spin(crate::amdgpu_gem::lock_placement(CARD));
    crate::amdgpu_gem::mark_placement_lost(CARD);
    // Device loss refuses an unsignalled foreign dependency immediately;
    // it need not wait for a timeout or the quarantined admission mutex.
    let result = narf_scheduler::block_on_spin(wait_kernel(
        CARD,
        alloc::vec![Arc::new(Never) as Arc<dyn narf_filesystem::DrmFence>],
        narf_time::monotonic_ns(),
    ));
    assert_eq!(result, Err(FsError::NoDevice));
    drop(guard);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-transfer",
    cs_kernel_dependency_wait_refuses_terminal_card
);
