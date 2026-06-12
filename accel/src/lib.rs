#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;

pub mod device;

pub use device::{AccelDevice, AccelError, AccelInfo, ComputeJob, JobId};

/// Rights for accelerator capabilities.
pub enum AccelRight {
    /// Allows reading device status and job progress.
    Read,
    /// Allows submitting compute jobs.
    Compute,
    /// Allows direct memory-mapping of accelerator BARs.
    Map,
    /// Allows administrative operations (reset, firmware update).
    Admin,
}

#[async_trait]
pub trait AccelDeviceTrait: Send + Sync {
    /// Returns static information about the accelerator.
    fn get_info(&self) -> AccelInfo;

    /// Submits a job to the accelerator's compute queue.
    async fn submit(&self, job: ComputeJob) -> Result<JobId, AccelError>;

    /// Waits for a specific job to complete.
    async fn wait(&self, id: JobId) -> Result<(), AccelError>;

    /// Aborts a pending or running job.
    async fn abort(&self, id: JobId) -> Result<(), AccelError>;
}

pub mod registry {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_lib::sync::IrqSafeSpinLock;

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn AccelDeviceTrait>>> =
        IrqSafeSpinLock::new(Vec::new());

    pub fn register(device: Arc<dyn AccelDeviceTrait>) {
        REGISTRY.lock().push(device);
    }

    pub fn list() -> Vec<Arc<dyn AccelDeviceTrait>> {
        REGISTRY.lock().clone()
    }
}

/// Force-link hook.
pub fn register_initcalls() {}

// ── Smoke Tests ───────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    struct MockAccel {
        next_job_id: AtomicU64,
        completed_jobs: IrqSafeSpinLock<Vec<u64>>,
    }

    impl MockAccel {
        fn new() -> Self {
            Self {
                next_job_id: AtomicU64::new(1),
                completed_jobs: IrqSafeSpinLock::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AccelDeviceTrait for MockAccel {
        fn get_info(&self) -> AccelInfo {
            AccelInfo {
                id: device::AccelId(0),
                kind: device::AccelKind::Npu,
                memory_size: 1024 * 1024 * 1024,
                compute_units: 16,
                features: device::AccelFeatures::empty(),
            }
        }

        async fn submit(&self, _job: ComputeJob) -> Result<JobId, AccelError> {
            let id = self.next_job_id.fetch_add(1, Ordering::SeqCst);
            narf_scheduler::yield_now().await;
            self.completed_jobs.lock().push(id);
            Ok(JobId(id))
        }

        async fn wait(&self, id: JobId) -> Result<(), AccelError> {
            loop {
                if self.completed_jobs.lock().contains(&id.0) {
                    return Ok(());
                }
                narf_scheduler::yield_now().await;
            }
        }

        async fn abort(&self, _id: JobId) -> Result<(), AccelError> {
            Ok(())
        }
    }

    fn smoke_accel_submit_wait_cycle() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        let mock = Arc::new(MockAccel::new());
        let success = Arc::new(AtomicU64::new(0));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let job = ComputeJob {
                // SAFETY: Valid memory or trusted environment
                graph_blob: unsafe { core::mem::zeroed() }, // Mock cap
                inputs: alloc::vec![],
                outputs: alloc::vec![],
            };
            let job_id = m.submit(job).await.expect("submit failed");
            m.wait(job_id).await.expect("wait failed");
            s.store(1, Ordering::SeqCst);
        });

        narf_scheduler::run_until_empty();
        if success.load(Ordering::SeqCst) == 1 {
            TestResult::Pass
        } else {
            TestResult::Fail("submit-wait cycle failed")
        }
    }
    kernel_test_in!("accel", smoke_accel_submit_wait_cycle);

    fn smoke_accel_info_integrity() -> TestResult {
        let mock = MockAccel::new();
        let info = mock.get_info();
        if info.kind == device::AccelKind::Npu && info.memory_size > 0 {
            TestResult::Pass
        } else {
            TestResult::Fail("info integrity check failed")
        }
    }
    kernel_test_in!("accel", smoke_accel_info_integrity);

    fn smoke_accel_error_variants_distinct() -> TestResult {
        let all = [
            AccelError::NotSupported,
            AccelError::Busy,
            AccelError::Timeout,
            AccelError::InvalidArgs,
            AccelError::HardwareError,
            AccelError::Denied,
            AccelError::OutOfMemory,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("AccelError variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("accel", smoke_accel_error_variants_distinct);

    fn smoke_accel_kind_variants_distinct() -> TestResult {
        use crate::device::AccelKind;
        let all = [
            AccelKind::Npu,
            AccelKind::Tpu,
            AccelKind::Fpga,
            AccelKind::Dsp,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j && a == b {
                    return TestResult::Fail("AccelKind variants collapsed");
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("accel", smoke_accel_kind_variants_distinct);

    fn smoke_accel_features_bit_layout() -> TestResult {
        use crate::device::AccelFeatures;
        if AccelFeatures::BFLOAT16.bits() != 1 << 0 {
            return TestResult::Fail("BFLOAT16 bit drifted");
        }
        if AccelFeatures::INT8.bits() != 1 << 1 {
            return TestResult::Fail("INT8 bit drifted");
        }
        if AccelFeatures::ASYNC_QUEUE.bits() != 1 << 2 {
            return TestResult::Fail("ASYNC_QUEUE bit drifted");
        }
        if AccelFeatures::P2P_DMA.bits() != 1 << 3 {
            return TestResult::Fail("P2P_DMA bit drifted");
        }
        // Union/intersection round-trip.
        let combo = AccelFeatures::BFLOAT16 | AccelFeatures::INT8;
        if !combo.contains(AccelFeatures::BFLOAT16) || !combo.contains(AccelFeatures::INT8) {
            return TestResult::Fail("union doesn't contain its members");
        }
        if combo.contains(AccelFeatures::P2P_DMA) {
            return TestResult::Fail("union contains a bit it shouldn't");
        }
        TestResult::Pass
    }
    kernel_test_in!("accel", smoke_accel_features_bit_layout);

    fn smoke_accel_registry_register_and_list() -> TestResult {
        use crate::registry;
        let before = registry::list().len();
        let dev = Arc::new(MockAccel::new()) as Arc<dyn AccelDeviceTrait>;
        registry::register(dev);
        if registry::list().len() != before + 1 {
            return TestResult::Fail("register didn't bump list length");
        }
        TestResult::Pass
    }
    kernel_test_in!("accel", smoke_accel_registry_register_and_list);
}
