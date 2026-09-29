#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use async_trait::async_trait;

pub mod device;
/// Intel NPU (VPU) — needs the PCIe bus, so x86_64 only.
#[cfg(target_arch = "x86_64")]
pub mod intel_npu;

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

/// Register this crate's Stage::Subsys initcalls. Also acts as the
/// force-link hook that keeps the crate in the final image.
pub fn register_initcalls() {
    #[cfg(target_arch = "x86_64")]
    {
        use narf_init::{InitResult, Stage};
        narf_init::register(Stage::Subsys, "intel-npu", || {
            intel_npu::register_pci_driver();
            InitResult::Ok
        });
    }
}

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

    // ── Intel NPU ───────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    fn smoke_intel_npu_pci_match_table() -> TestResult {
        use crate::intel_npu as npu;
        use narf_bus::driver_match::__reset_for_test;
        use narf_bus::{registered_pci_drivers, MatchKind};
        __reset_for_test();
        npu::register_pci_driver();
        let regs = registered_pci_drivers();
        for did in npu::SUPPORTED_DEVICE_IDS.iter().copied() {
            let found = regs.iter().any(|m| {
                matches!(m.kind, MatchKind::VendorDevice {
                    vendor: npu::NPU_VENDOR, device,
                } if device == did)
            });
            if !found {
                return TestResult::Fail("intel-npu match table missing a device id");
            }
        }
        // The MS-03's 00:0b.0.
        if !npu::is_supported_device(npu::NPU_DEV_PTL_P) || npu::NPU_DEV_PTL_P != 0xB03E {
            return TestResult::Fail("intel-npu does not claim the MS-03's NPU");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("accel/intel_npu", smoke_intel_npu_pci_match_table);

    #[cfg(target_arch = "x86_64")]
    fn smoke_intel_npu_generations_are_independent() -> TestResult {
        use crate::intel_npu::{btrs_gen_for, ip_gen_for, BtrsGen, IpGen};
        use crate::intel_npu::{NPU_DEV_LNL, NPU_DEV_MTL, NPU_DEV_PTL_P};
        // The IP generation and the buttress generation do not split
        // the same way: Lunar Lake is IP 40xx and Panther Lake is IP
        // 50xx, but both use the LNL buttress. Driving the register
        // map off IpGen would pick the wrong one for Panther Lake.
        if ip_gen_for(NPU_DEV_LNL) != IpGen::Ip40xx {
            return TestResult::Fail("Lunar Lake is IP 40xx");
        }
        if ip_gen_for(NPU_DEV_PTL_P) != IpGen::Ip50xx {
            return TestResult::Fail("Panther Lake is IP 50xx");
        }
        if btrs_gen_for(NPU_DEV_LNL) != BtrsGen::Lnl || btrs_gen_for(NPU_DEV_PTL_P) != BtrsGen::Lnl
        {
            return TestResult::Fail("Lunar and Panther Lake share the LNL buttress");
        }
        if btrs_gen_for(NPU_DEV_MTL) != BtrsGen::Mtl || ip_gen_for(NPU_DEV_MTL) != IpGen::Ip37xx {
            return TestResult::Fail("Meteor Lake generations wrong");
        }
        if ip_gen_for(0xFFFF) != IpGen::Unknown || btrs_gen_for(0xFFFF) != BtrsGen::Unknown {
            return TestResult::Fail("an unknown id must not map to a real generation");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "accel/intel_npu",
        smoke_intel_npu_generations_are_independent
    );

    #[cfg(target_arch = "x86_64")]
    fn smoke_intel_npu_pll_ratio_conversion() -> TestResult {
        use crate::intel_npu::{pll_ratio_to_mhz, BtrsGen, PLL_REF_CLK_FREQ_MHZ};
        if PLL_REF_CLK_FREQ_MHZ != 50 {
            return TestResult::Fail("PLL reference clock wrong");
        }
        // LNL: ratio * 50 / 2. MTL: ratio * 50 * 2 / 3. Using one
        // formula for both is off by a third.
        if pll_ratio_to_mhz(BtrsGen::Lnl, 40) != 1000 {
            return TestResult::Fail("LNL ratio conversion wrong");
        }
        if pll_ratio_to_mhz(BtrsGen::Mtl, 30) != 1000 {
            return TestResult::Fail("MTL ratio conversion wrong");
        }
        if pll_ratio_to_mhz(BtrsGen::Lnl, 30) == pll_ratio_to_mhz(BtrsGen::Mtl, 30) {
            return TestResult::Fail("the two generations must not share a formula");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("accel/intel_npu", smoke_intel_npu_pll_ratio_conversion);

    #[cfg(target_arch = "x86_64")]
    fn smoke_intel_npu_buttress_register_layout() -> TestResult {
        use crate::intel_npu as npu;
        if npu::BTRS_INTERRUPT_STAT != 0x0000
            || npu::BTRS_PLL_FREQ != 0x0148
            || npu::BTRS_TILE_FUSE != 0x0150
            || npu::BTRS_VPU_STATUS != 0x0154
        {
            return TestResult::Fail("buttress register offsets wrong");
        }
        // The two BARs are not interchangeable: RegV is BAR0 and RegB
        // (which is what this driver reads) is BAR4.
        if npu::NPU_BAR_REGV != 0 || npu::NPU_BAR_REGB != 4 {
            return TestResult::Fail("BAR indices wrong");
        }
        if npu::BTRS_STATUS_READY != 1 << 0 || npu::BTRS_STATUS_IDLE != 1 << 1 {
            return TestResult::Fail("VPU_STATUS ready/idle bits wrong");
        }
        if npu::BTRS_STATUS_PLATFORM_SHIFT != 29 || npu::BTRS_STATUS_PLATFORM_MASK != 0x7 {
            return TestResult::Fail("platform field is bits 31:29");
        }
        // TILE_FUSE: valid in bit 0, the disable mask in bits 6:1 —
        // so the config field is shifted, not the whole low byte.
        if npu::BTRS_TILE_FUSE_VALID != 1 << 0 {
            return TestResult::Fail("TILE_FUSE valid bit wrong");
        }
        if npu::BTRS_TILE_FUSE_CONFIG_SHIFT != 1 || npu::BTRS_TILE_FUSE_CONFIG_MASK != 0x3F {
            return TestResult::Fail("TILE_FUSE config field wrong");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("accel/intel_npu", smoke_intel_npu_buttress_register_layout);

    #[cfg(target_arch = "x86_64")]
    fn smoke_intel_npu_platform_decode() -> TestResult {
        use crate::intel_npu::Platform;
        if Platform::from_field(0) != Platform::Silicon {
            return TestResult::Fail("field 0 is silicon");
        }
        if Platform::from_field(3) != Platform::Fpga {
            return TestResult::Fail("field 3 is FPGA");
        }
        // Value 1 is not assigned; it must not silently read as
        // silicon.
        match Platform::from_field(1) {
            Platform::Invalid(1) => {}
            _ => return TestResult::Fail("an unassigned platform value was not preserved"),
        }
        if Platform::Silicon.label() != "silicon" {
            return TestResult::Fail("platform label wrong");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("accel/intel_npu", smoke_intel_npu_platform_decode);
}
