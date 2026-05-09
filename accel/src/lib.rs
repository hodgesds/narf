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
        narf_scheduler::init();
        let mock = Arc::new(MockAccel::new());
        let success = Arc::new(AtomicU64::new(0));

        let m = mock.clone();
        let s = success.clone();
        narf_scheduler::spawn(async move {
            let job = ComputeJob {
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
}
