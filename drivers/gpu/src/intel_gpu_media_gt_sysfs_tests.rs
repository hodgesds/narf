//! Tests for Standalone Media GT (GT1) telemetry and sysfs attributes.

use alloc::sync::Arc;
use narf_filesystem::sysfs::{Kobject, __reset_for_test};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::drm_registry::{register_drm_card, DrmCard};
use crate::intel_gpu_engine::EngineSet;
use crate::intel_gpu_gt::media::MediaTopology;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_slpc::{FrequencyRange, Limits, PowerProfile, Status as SlpcStatus};
use crate::intel_gpu_user::{MediaGtStatus, UserBackend, UserStatus};

use super::{populate_card, MediaGtTelemetry};

#[derive(Debug)]
struct MockBackend {
    media_gt: Option<MediaGtStatus>,
    slpc: Option<SlpcStatus>,
    rc6_ms: Option<u64>,
    act_freq_mhz: Option<u32>,
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
        Some(UserStatus {
            epoch: 1,
            platform: GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            submission_version: (1, 0, 0),
            engines: EngineSet::of(&[]),
        })
    }

    fn media_gt(&self) -> Option<MediaGtStatus> {
        self.media_gt
    }

    fn media_gt_slpc_status(&self) -> Option<SlpcStatus> {
        self.slpc
    }

    fn media_gt_rc6_residency_ms(&self) -> Option<u64> {
        self.rc6_ms
    }

    fn media_gt_act_freq_mhz(&self) -> Option<u32> {
        self.act_freq_mhz
    }
}

#[derive(Debug)]
struct MockCard {
    backend: Option<Arc<dyn UserBackend>>,
}

impl DrmCard for MockCard {
    fn name(&self) -> &str {
        "intel-media-gt-card"
    }

    fn driver(&self) -> &str {
        "xe"
    }

    fn vendor_id(&self) -> u16 {
        0x8086
    }

    fn device_id(&self) -> u16 {
        0x7d55 // Meteor Lake PCI device
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

fn sample_media_gt_status() -> MediaGtStatus {
    MediaGtStatus {
        epoch: 42,
        engines: EngineSet::of(&[]),
        gmd: 0x1300,
        reference_clock: 19_200_000,
        topology: MediaTopology::default(),
    }
}

fn sample_slpc_status() -> SlpcStatus {
    SlpcStatus {
        limits: Limits {
            rpn_mhz: 100,
            rpe_mhz: 500,
            rp0_mhz: 1150,
            min_mhz: 100,
            max_mhz: 1150,
        },
        range: FrequencyRange {
            min_mhz: 900,
            max_mhz: 1150,
        },
        profile: PowerProfile::Base,
    }
}

fn smoke_intel_media_gt_telemetry_from_backend() -> TestResult {
    // 1. Without media_gt
    let backend_empty = MockBackend {
        media_gt: None,
        slpc: None,
        rc6_ms: None,
        act_freq_mhz: None,
    };
    assert_eq!(MediaGtTelemetry::from_backend(&backend_empty), None);

    // 2. With media_gt but without SLPC (fallback state)
    let backend_fallback = MockBackend {
        media_gt: Some(sample_media_gt_status()),
        slpc: None,
        rc6_ms: Some(1234),
        act_freq_mhz: None,
    };
    let telem_fallback = MediaGtTelemetry::from_backend(&backend_fallback).expect("fallback telem");
    assert!(!telem_fallback.is_running);
    assert_eq!(telem_fallback.rc6_residency_ms, 1234);
    assert_eq!(telem_fallback.min_freq_mhz, 100);
    assert_eq!(telem_fallback.max_freq_mhz, 1150);
    assert_eq!(telem_fallback.rp0_freq_mhz, 1150);
    assert_eq!(telem_fallback.rpe_freq_mhz, 500);
    assert_eq!(telem_fallback.rpn_freq_mhz, 100);
    assert_eq!(telem_fallback.power_profile, "base");
    assert_eq!(telem_fallback.idle_status, "gt-c0");

    // 3. With media_gt and active SLPC
    let backend_active = MockBackend {
        media_gt: Some(sample_media_gt_status()),
        slpc: Some(sample_slpc_status()),
        rc6_ms: Some(9999),
        act_freq_mhz: None,
    };
    let telem_active = MediaGtTelemetry::from_backend(&backend_active).expect("active telem");
    assert!(telem_active.is_running);
    assert_eq!(telem_active.cur_freq_mhz, 900);
    assert_eq!(telem_active.act_freq_mhz, 900);
    assert_eq!(telem_active.min_freq_mhz, 900);
    assert_eq!(telem_active.max_freq_mhz, 1150);
    assert_eq!(telem_active.rp0_freq_mhz, 1150);
    assert_eq!(telem_active.rpe_freq_mhz, 500);
    assert_eq!(telem_active.rpn_freq_mhz, 100);
    assert_eq!(telem_active.rc6_residency_ms, 9999);
    assert_eq!(telem_active.power_profile, "base");
    assert_eq!(telem_active.idle_status, "gt-c0");

    // 4. With hardware CAGF act_freq override and C6 idle state
    let mut ps_slpc = sample_slpc_status();
    ps_slpc.profile = PowerProfile::PowerSaving;
    let backend_c6 = MockBackend {
        media_gt: Some(sample_media_gt_status()),
        slpc: Some(ps_slpc),
        rc6_ms: Some(500),
        act_freq_mhz: Some(0),
    };
    let telem_c6 = MediaGtTelemetry::from_backend(&backend_c6).expect("c6 telem");
    assert_eq!(telem_c6.power_profile, "power_saving");
    assert_eq!(telem_c6.idle_status, "gt-c6");

    let backend_hw_act = MockBackend {
        media_gt: Some(sample_media_gt_status()),
        slpc: Some(sample_slpc_status()),
        rc6_ms: Some(500),
        act_freq_mhz: Some(1050),
    };
    let telem_hw_act = MediaGtTelemetry::from_backend(&backend_hw_act).expect("hw_act telem");
    assert_eq!(telem_hw_act.act_freq_mhz, 1050);
    assert_eq!(telem_hw_act.idle_status, "gt-c0");

    TestResult::Pass
}

fn smoke_intel_media_gt_sysfs_card_and_tile_attributes() -> TestResult {
    __reset_for_test();

    let backend = Arc::new(MockBackend {
        media_gt: Some(sample_media_gt_status()),
        slpc: Some(sample_slpc_status()),
        rc6_ms: Some(54321),
        act_freq_mhz: Some(1050),
    });
    let card_idx = register_drm_card(Arc::new(MockCard {
        backend: Some(backend),
    }));

    let card_kobj = Kobject::new_root("card_root");
    let dev_kobj = Kobject::new_root("dev_root");

    populate_card(card_idx, &card_kobj, Some(&dev_kobj));

    // Verify /sys/class/drm/card<N>/gt1/ attributes
    let gt1 = card_kobj.get_child("gt1").expect("gt1 child directory");
    assert_eq!(gt1.attr_show("rps_cur_freq_mhz").as_deref(), Some("900\n"));
    assert_eq!(gt1.attr_show("rps_act_freq_mhz").as_deref(), Some("1050\n"));
    assert_eq!(
        gt1.attr_show("rc6_residency_ms").as_deref(),
        Some("54321\n")
    );
    assert_eq!(gt1.attr_show("rc6p_residency_ms").as_deref(), Some("0\n"));
    assert_eq!(gt1.attr_show("rc6pp_residency_ms").as_deref(), Some("0\n"));
    assert_eq!(
        gt1.attr_show("freq_factor_scale").as_deref(),
        Some("1.00\n")
    );
    assert_eq!(gt1.attr_show("throttle_reasons").as_deref(), Some("0\n"));
    assert_eq!(gt1.attr_show("gt_min_freq_mhz").as_deref(), Some("900\n"));
    assert_eq!(gt1.attr_show("gt_max_freq_mhz").as_deref(), Some("1150\n"));
    assert_eq!(gt1.attr_show("gt_RP0_freq_mhz").as_deref(), Some("1150\n"));
    assert_eq!(gt1.attr_show("gt_RP1_freq_mhz").as_deref(), Some("500\n"));
    assert_eq!(gt1.attr_show("gt_RPn_freq_mhz").as_deref(), Some("100\n"));
    assert_eq!(gt1.attr_show("slpc_status").as_deref(), Some("running\n"));
    assert_eq!(
        gt1.attr_show("slpc_power_profile").as_deref(),
        Some("base\n")
    );

    // Verify /sys/class/drm/card<N>/device/tile0/gt1/ attributes
    let tile0 = dev_kobj.get_child("tile0").expect("tile0 child directory");
    let dev_gt1 = tile0.get_child("gt1").expect("dev gt1 directory");
    let freq0 = dev_gt1.get_child("freq0").expect("freq0 directory");
    let gtidle = dev_gt1.get_child("gtidle").expect("gtidle directory");

    assert_eq!(freq0.attr_show("cur_freq").as_deref(), Some("900\n"));
    assert_eq!(freq0.attr_show("act_freq").as_deref(), Some("1050\n"));
    assert_eq!(freq0.attr_show("min_freq").as_deref(), Some("900\n"));
    assert_eq!(freq0.attr_show("max_freq").as_deref(), Some("1150\n"));
    assert_eq!(freq0.attr_show("rp0_freq").as_deref(), Some("1150\n"));
    assert_eq!(freq0.attr_show("rpe_freq").as_deref(), Some("500\n"));
    assert_eq!(freq0.attr_show("rpn_freq").as_deref(), Some("100\n"));
    assert_eq!(freq0.attr_show("power_profile").as_deref(), Some("base\n"));
    assert_eq!(gtidle.attr_show("name").as_deref(), Some("gt1-mc\n"));
    assert_eq!(
        gtidle.attr_show("idle_residency_ms").as_deref(),
        Some("54321\n")
    );
    assert_eq!(gtidle.attr_show("idle_status").as_deref(), Some("gt-c0\n"));
    assert_eq!(gtidle.attr_show("gt1-mc").as_deref(), Some("54321\n"));

    __reset_for_test();
    TestResult::Pass
}

fn smoke_intel_media_gt_sysfs_without_backend_returns_unavailable() -> TestResult {
    __reset_for_test();

    let card_idx = register_drm_card(Arc::new(MockCard { backend: None }));

    let card_kobj = Kobject::new_root("card_root");
    let dev_kobj = Kobject::new_root("dev_root");

    populate_card(card_idx, &card_kobj, Some(&dev_kobj));

    let gt1 = card_kobj.get_child("gt1").expect("gt1 directory");
    assert_eq!(
        gt1.attr_show("slpc_status").as_deref(),
        Some("unavailable\n")
    );
    assert_eq!(gt1.attr_show("rps_cur_freq_mhz").as_deref(), Some(""));
    assert_eq!(gt1.attr_show("rc6_residency_ms").as_deref(), Some(""));

    let tile0 = dev_kobj.get_child("tile0").expect("tile0 directory");
    let dev_gt1 = tile0.get_child("gt1").expect("gt1 directory");
    let freq0 = dev_gt1.get_child("freq0").expect("freq0 directory");
    let gtidle = dev_gt1.get_child("gtidle").expect("gtidle directory");

    assert_eq!(freq0.attr_show("cur_freq").as_deref(), Some(""));
    assert_eq!(gtidle.attr_show("gt1-mc").as_deref(), Some(""));

    __reset_for_test();
    TestResult::Pass
}

kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt_sysfs",
    smoke_intel_media_gt_telemetry_from_backend
);
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt_sysfs",
    smoke_intel_media_gt_sysfs_card_and_tile_attributes
);
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt_sysfs",
    smoke_intel_media_gt_sysfs_without_backend_returns_unavailable
);
