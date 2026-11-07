//! Tests for Graphics Main GT (GT0) telemetry and sysfs attributes.

use alloc::{format, sync::Arc};
use narf_filesystem::sysfs::{__reset_for_test, Kobject};
use narf_kernel_test::{TestResult, kernel_test_in};

use crate::drm_registry::{DrmCard, register_drm_card};
use crate::intel_gpu_engine::EngineSet;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_slpc::{FrequencyRange, Limits, PowerProfile, Status as SlpcStatus};
use crate::intel_gpu_user::{UserBackend, UserStatus};

use super::populate_card;

#[derive(Debug)]
struct MockBackend {
    epoch: u64,
    slpc: Option<SlpcStatus>,
    rc6_ms: Option<u64>,
}

impl UserBackend for MockBackend {
    fn submit<'a>(
        &'a self,
        _context: Arc<crate::intel_gpu_user::UserContext>,
        _batch: crate::intel_gpu_user::UserBatch,
    ) -> narf_filesystem::FsFuture<'a, Arc<crate::intel_gpu_fence::CompletionFence>> {
        alloc::boxed::Box::pin(async { Err(narf_filesystem::FsError::Unsupported) })
    }

    fn status(&self) -> Option<UserStatus> {
        (self.epoch != 0).then_some(UserStatus {
            epoch: self.epoch,
            platform: GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            submission_version: (1, 0, 0),
            engines: EngineSet::of(&[]),
        })
    }

    fn main_gt_slpc_status(&self) -> Option<SlpcStatus> {
        self.slpc
    }

    fn main_gt_rc6_residency_ms(&self) -> Option<u64> {
        self.rc6_ms
    }
}

#[derive(Debug)]
struct MockCard {
    backend: Option<Arc<dyn UserBackend>>,
}

impl DrmCard for MockCard {
    fn name(&self) -> &str {
        "intel-main-gt-card"
    }

    fn driver(&self) -> &str {
        "xe"
    }

    fn vendor_id(&self) -> u16 {
        0x8086
    }

    fn device_id(&self) -> u16 {
        0x7d55
    }

    fn subsystem_vendor(&self) -> u16 {
        0
    }

    fn subsystem_device(&self) -> u16 {
        0
    }

    fn vbios_version(&self) -> Option<&str> {
        None
    }

    fn gpu_busy_percent(&self) -> Option<u32> {
        None
    }

    fn power_state(&self) -> &str {
        "D0"
    }

    fn intel_user_backend(&self) -> Option<Arc<dyn UserBackend>> {
        self.backend.clone()
    }
}

fn sample_slpc_status() -> SlpcStatus {
    SlpcStatus {
        limits: Limits {
            rpn_mhz: 200,
            rpe_mhz: 800,
            rp0_mhz: 1400,
            min_mhz: 200,
            max_mhz: 1400,
        },
        range: FrequencyRange {
            min_mhz: 400,
            max_mhz: 1200,
        },
        profile: PowerProfile::Base,
    }
}

fn smoke_intel_main_gt_telemetry_live() -> TestResult {
    __reset_for_test();

    let backend = Arc::new(MockBackend {
        epoch: 1,
        slpc: Some(sample_slpc_status()),
        rc6_ms: Some(4500),
    });

    let card = Arc::new(MockCard {
        backend: Some(backend),
    });
    let card_idx = register_drm_card(card);

    let root = Kobject::new_root("sys");
    let card_node = Kobject::new_child(root.clone(), format!("card{card_idx}"));
    let dev_node = Kobject::new_child(card_node.clone(), "device");

    populate_card(card_idx, &card_node, Some(&dev_node));

    // Verify /sys/class/drm/card<N>/gt/ attributes
    let gt = card_node.get_child("gt").expect("gt child exists");
    assert_eq!(gt.attr_show("rps_cur_freq_mhz").as_deref(), Some("400\n"));
    assert_eq!(gt.attr_show("rps_act_freq_mhz").as_deref(), Some("400\n"));
    assert_eq!(gt.attr_show("rc6_residency_ms").as_deref(), Some("4500\n"));
    assert_eq!(gt.attr_show("rc6p_residency_ms").as_deref(), Some("0\n"));
    assert_eq!(gt.attr_show("rc6pp_residency_ms").as_deref(), Some("0\n"));
    assert_eq!(gt.attr_show("freq_factor_scale").as_deref(), Some("1.00\n"));
    assert_eq!(gt.attr_show("throttle_reasons").as_deref(), Some("0\n"));
    assert_eq!(gt.attr_show("gt_min_freq_mhz").as_deref(), Some("400\n"));
    assert_eq!(gt.attr_show("gt_max_freq_mhz").as_deref(), Some("1200\n"));
    assert_eq!(gt.attr_show("gt_RP0_freq_mhz").as_deref(), Some("1400\n"));
    assert_eq!(gt.attr_show("gt_RP1_freq_mhz").as_deref(), Some("800\n"));
    assert_eq!(gt.attr_show("gt_RPn_freq_mhz").as_deref(), Some("200\n"));
    assert_eq!(gt.attr_show("slpc_status").as_deref(), Some("running\n"));

    // Verify /sys/class/drm/card<N>/gt0/ mirror
    let gt0 = card_node.get_child("gt0").expect("gt0 child exists");
    assert_eq!(gt0.attr_show("rps_cur_freq_mhz").as_deref(), Some("400\n"));
    assert_eq!(gt0.attr_show("rc6_residency_ms").as_deref(), Some("4500\n"));

    // Verify Xe-style /device/tile0/gt0/
    let tile0 = dev_node.get_child("tile0").expect("tile0 child exists");
    let gt0_dev = tile0.get_child("gt0").expect("tile0/gt0 child exists");
    let freq0 = gt0_dev.get_child("freq0").expect("freq0 child exists");
    let gtidle = gt0_dev.get_child("gtidle").expect("gtidle child exists");

    assert_eq!(freq0.attr_show("cur_freq").as_deref(), Some("400\n"));
    assert_eq!(freq0.attr_show("act_freq").as_deref(), Some("400\n"));
    assert_eq!(freq0.attr_show("min_freq").as_deref(), Some("400\n"));
    assert_eq!(freq0.attr_show("max_freq").as_deref(), Some("1200\n"));
    assert_eq!(freq0.attr_show("rp0_freq").as_deref(), Some("1400\n"));
    assert_eq!(freq0.attr_show("rpe_freq").as_deref(), Some("800\n"));
    assert_eq!(freq0.attr_show("rpn_freq").as_deref(), Some("200\n"));
    assert_eq!(freq0.attr_show("power_profile").as_deref(), Some("base\n"));
    assert_eq!(
        gtidle.attr_show("idle_residency_ms").as_deref(),
        Some("4500\n")
    );
    assert_eq!(gtidle.attr_show("idle_status").as_deref(), Some("gt-c0\n"));
    assert_eq!(gtidle.attr_show("name").as_deref(), Some("gt0-rc6\n"));

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_sysfs",
    smoke_intel_main_gt_telemetry_live
);

fn smoke_intel_main_gt_telemetry_offline_fallback() -> TestResult {
    __reset_for_test();

    let backend = Arc::new(MockBackend {
        epoch: 0, // Uninitialized / offline
        slpc: None,
        rc6_ms: None,
    });

    let card = Arc::new(MockCard {
        backend: Some(backend),
    });
    let card_idx = register_drm_card(card);

    let root = Kobject::new_root("sys");
    let card_node = Kobject::new_child(root.clone(), format!("card{card_idx}"));
    populate_card(card_idx, &card_node, None);

    let gt = card_node.get_child("gt").expect("gt exists");
    assert_eq!(gt.attr_show("rps_cur_freq_mhz").as_deref(), Some(""));
    assert_eq!(gt.attr_show("rc6_residency_ms").as_deref(), Some(""));
    assert_eq!(
        gt.attr_show("slpc_status").as_deref(),
        Some("unavailable\n")
    );

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_gt_sysfs",
    smoke_intel_main_gt_telemetry_offline_fallback
);
