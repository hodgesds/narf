use super::*;
#[path = "amdgpu_navi48_profile_tests.rs"]
mod profile_tests;
use crate::amdgpu_smu_navi48_telemetry::Metrics;
use alloc::format;
use narf_kernel_test::{kernel_test_in, TestResult};

fn limits(fan: bool) -> Limits {
    Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 108_000,
        mem_emergency_milli: 113_000,
        software_shutdown_c: 118,
        software_shutdown_offset_c: -10,
        fan_max_rpm: fan.then_some(3300),
        ppt_default_w: 304,
        ppt_min_w: 273,
        ppt_max_w: 340,
    }
}
fn navi48_power_cap_writes_follow_amdgpu_hwmon_units_and_range() -> TestResult {
    let l = Some(limits(true));
    // Microwatts truncate to watts, as amdgpu_hwmon_set_power_cap.
    assert_eq!(power_cap_request(l, b"300000000\n"), Ok(300));
    assert_eq!(power_cap_request(l, b"273999999"), Ok(273));
    assert_eq!(power_cap_request(l, b"340000000"), Ok(340));
    for bad in [
        &b"272999999"[..],
        b"341000000",
        b"0",
        b"",
        b"-5",
        b"3e8",
        b"300 W",
    ] {
        assert_eq!(
            power_cap_request(l, bad),
            Err(FsError::InvalidData),
            "{bad:?}"
        );
    }
    assert_eq!(
        power_cap_request(None, b"300000000"),
        Err(FsError::NoDevice)
    );
    let snapshot = Snapshot {
        telemetry: None,
        limits: l,
        protected: true,
        gfx_level: smu::GfxLevel::Auto,
        profile: smu::PowerProfile::BootupDefault,
        error: None,
        samples: 0,
    };
    assert_eq!(show(Some(&snapshot), "power1_cap_min"), "273000000\n");
    assert_eq!(show(Some(&snapshot), "power1_cap_max"), "340000000\n");
    assert!(attributes(false).contains(&"power1_cap_min"));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_power_cap_writes_follow_amdgpu_hwmon_units_and_range
);
fn telemetry(hotspot_c: i32, throttlers: u32) -> Telemetry {
    Telemetry {
        metrics: Metrics {
            counter: 7,
            edge_milli: 61_000,
            hotspot_milli: hotspot_c * 1000,
            mem_milli: 70_000,
            fan_rpm: 1620,
            fan_pwm: 127,
            socket_power_w: 287,
            vddgfx_mv: 1050,
            vddsoc_mv: Some(950),
            gfx_mhz: 2450,
            uclk_mhz: 1258,
            throttlers,
            ..Metrics::default()
        },
        enabled: 0x3e80_0000,
        ppt_limit_w: 304,
    }
}
fn sample(telemetry: Result<Telemetry, smu::Error>, protected: bool) -> Sample {
    Sample {
        telemetry,
        limits: Some(limits(true)),
        protected,
        gfx_level: smu::GfxLevel::Auto,
        profile: smu::PowerProfile::BootupDefault,
    }
}

fn navi48_power_snapshot_reports_transitions_once() -> TestResult {
    let seed = Snapshot {
        telemetry: None,
        limits: Some(limits(true)),
        protected: false,
        gfx_level: smu::GfxLevel::Auto,
        profile: smu::PowerProfile::BootupDefault,
        error: None,
        samples: 0,
    };
    let (s, e) = update(Some(seed), sample(Ok(telemetry(77, 1 << 14)), true));
    assert_eq!(e.started, 1 << 14);
    assert!(!e.protection_lost && !e.software_shutdown && e.failed.is_none());
    assert!(s.protected && s.samples == 1 && s.error.is_none());
    // Same throttler again: no event. A new one plus one ending.
    let (s, e) = update(Some(s), sample(Ok(telemetry(77, 1 << 14)), true));
    assert_eq!(e, Events::default());
    let (s, e) = update(Some(s), sample(Ok(telemetry(77, 1 << 1)), true));
    assert_eq!((e.started, e.stopped), (1 << 1, 1 << 14));
    // Software shutdown temperature reported on entry only.
    let (s, e) = update(Some(s), sample(Ok(telemetry(118, 0)), true));
    assert!(e.software_shutdown);
    let (s, e) = update(Some(s), sample(Ok(telemetry(119, 0)), true));
    assert!(!e.software_shutdown);
    // Lost protection reported once; a failed refresh keeps the last sample.
    let (s, e) = update(Some(s), sample(Ok(telemetry(60, 0)), false));
    assert!(e.protection_lost && !s.protected);
    let (s, e) = update(Some(s), sample(Ok(telemetry(60, 0)), false));
    assert!(!e.protection_lost);
    let (s, e) = update(Some(s), sample(Err(smu::Error::Rejected(0xfc)), false));
    assert_eq!(e.failed, Some(smu::Error::Rejected(0xfc)));
    assert_eq!(s.telemetry, Some(telemetry(60, 0)));
    assert_eq!((s.error, s.samples), (Some(smu::Error::Rejected(0xfc)), 7));
    let (s, e) = update(Some(s), sample(Err(smu::Error::Rejected(0xfc)), false));
    assert!(e.failed.is_none() && s.error.is_some());
    // Lost protection on the very first sample is reported too.
    let (_, e) = update(Some(seed), sample(Ok(telemetry(60, 0)), false));
    assert!(e.protection_lost);
    assert_eq!(throttler_names((1 << 1) | (1 << 14)), "temp-hotspot,ppt0");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_power_snapshot_reports_transitions_once
);

fn navi48_hwmon_follows_linux_amdgpu_units_and_visibility() -> TestResult {
    let names = attributes(true);
    assert_eq!(names.len(), 37); // includes SOC voltage/input power and cap bounds
    assert!(names.contains(&"pwm1") && names.contains(&"fan1_max"));
    let fanless = attributes(false);
    assert!(!fanless
        .iter()
        .any(|n| n.starts_with("pwm") || n.starts_with("fan")));
    let mut s = Snapshot {
        telemetry: None,
        limits: None,
        protected: false,
        gfx_level: smu::GfxLevel::Auto,
        profile: smu::PowerProfile::BootupDefault,
        error: None,
        samples: 0,
    };
    // No fake zeroes before data exists; labels and fixed ranges are static.
    for name in [
        "temp1_input",
        "temp1_crit",
        "power1_cap",
        "fan1_max",
        "freq1_input",
    ] {
        assert_eq!(show(Some(&s), name), "");
    }
    assert_eq!(show(None, "temp2_label"), "junction\n");
    assert_eq!(show(None, "pwm1_enable"), "2\n");
    assert_eq!(show(None, "pwm1_max"), "255\n");
    s.telemetry = Some(telemetry(77, 0));
    s.limits = Some(limits(true));
    for (name, value) in [
        ("temp1_input", "61000\n"),
        ("temp2_input", "77000\n"),
        ("temp3_input", "70000\n"),
        ("temp1_crit", "100000\n"),
        ("temp2_crit", "110000\n"),
        ("temp3_crit", "108000\n"),
        ("temp1_crit_hyst", "-273150\n"),
        ("temp2_emergency", "115000\n"),
        ("temp3_emergency", "113000\n"),
        ("temp1_label", "edge\n"),
        ("temp3_label", "mem\n"),
        ("pwm1", "127\n"),
        ("fan1_input", "1620\n"),
        ("fan1_min", "0\n"),
        ("fan1_max", "3300\n"),
        ("in0_input", "1050\n"),
        ("in0_label", "vddgfx\n"),
        ("in1_input", "950\n"),
        ("in1_label", "vddsoc\n"),
        ("power1_average", "287000000\n"),
        ("power1_input", "287000000\n"),
        ("power1_cap", "304000000\n"),
        ("power1_cap_default", "304000000\n"),
        ("power1_label", "PPT\n"),
        ("freq1_input", "2450000000\n"),
        ("freq1_label", "sclk\n"),
        ("freq2_input", "1258000000\n"),
        ("freq2_label", "mclk\n"),
        ("unknown", ""),
    ] {
        assert_eq!(show(Some(&s), name), value, "{name}");
    }
    for name in &names {
        assert!(!show(Some(&s), name).is_empty(), "{name}");
    }
    let t = s.telemetry.as_mut().unwrap();
    t.metrics.vddsoc_mv = None;
    t.metrics.socket_power_w = u16::MAX;
    assert_eq!(show(Some(&s), "in1_input"), "");
    assert_eq!(show(Some(&s), "power1_input"), "");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_hwmon_follows_linux_amdgpu_units_and_visibility
);

fn navi48_hwmon_publishes_next_free_class_node() -> TestResult {
    use narf_filesystem::sysfs::{class_device_register, class_register};
    let class = class_register("hwmon");
    let before = class.child_names();
    // Occupy the next index so publication must skip it.
    let next = (0..)
        .find(|i| !before.iter().any(|n| *n == format!("hwmon{i}")))
        .unwrap();
    class_device_register(class.clone(), &format!("hwmon{next}"));
    publish(Some(limits(false)));
    let node = class.get_child(&format!("hwmon{}", next + 1)).unwrap();
    assert_eq!(node.attr_show("name").as_deref(), Some("amdgpu\n"));
    assert_eq!(node.attr_show("temp1_label").as_deref(), Some("edge\n"));
    assert!(node.has_attr("power1_average") && !node.has_attr("pwm1"));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_hwmon_publishes_next_free_class_node
);

fn navi48_thermal_shutdown_uses_fresh_data_once_per_hot_episode() -> TestResult {
    use core::sync::atomic::AtomicBool;
    let hot = AtomicBool::new(false);
    let fresh = |c| sample(Ok(telemetry(c, 0)), true);
    assert!(!thermal_trip(&hot, None, None));
    assert!(!thermal_trip(
        &hot,
        Some(&sample(Err(smu::Error::Timeout), false)),
        None
    ));
    assert!(!thermal_trip(&hot, Some(&fresh(117)), None));
    assert!(thermal_trip(&hot, Some(&fresh(118)), None));
    assert!(!thermal_trip(&hot, Some(&fresh(119)), None));
    // Failed periodic telemetry neither fabricates a trip nor ends a hot episode.
    assert!(!thermal_trip(
        &hot,
        Some(&sample(Err(smu::Error::Rejected(0xfc)), false)),
        None
    ));
    assert!(!thermal_trip(&hot, Some(&fresh(119)), Some(118)));
    assert!(!thermal_trip(&hot, Some(&fresh(117)), Some(118)));
    assert!(thermal_trip(&hot, Some(&fresh(118)), Some(118)));
    assert!(!thermal_trip(&hot, Some(&fresh(100)), None));
    // A high IRQ cannot be dismissed without a fresh below-threshold reading.
    assert!(thermal_trip(&hot, None, Some(118)));
    assert!(!thermal_trip(&hot, None, Some(118)));
    assert!(!thermal_trip(&hot, Some(&fresh(40)), Some(118)));
    let mut no_limit = fresh(200);
    no_limit.limits = None;
    assert!(!thermal_trip(&hot, Some(&no_limit), None));
    no_limit.limits = Some(Limits {
        software_shutdown_c: 0,
        ..limits(true)
    });
    assert!(!thermal_trip(&hot, Some(&no_limit), None));
    // Delayed confirmed-IRQ fallback retains its known armed limit.
    assert!(thermal_trip(&hot, Some(&no_limit), Some(118)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_thermal_shutdown_uses_fresh_data_once_per_hot_episode
);

fn navi48_thermal_alert_cancellation_and_owner_change_cannot_notify_successor() -> TestResult {
    use core::future::{pending, Future};
    use core::sync::atomic::AtomicBool;
    use core::task::{Context, Waker};
    let slots = AlertSlots(AtomicU64::new(0));
    let owner = AtomicU64::new(4);
    let hot = AtomicBool::new(false);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let lease = slots.claim(4).unwrap();
        assert!(slots.claim(4).is_none());
        let mut task = alloc::boxed::Box::pin(alert_delay(lease, pending()));
        assert!(task.as_mut().poll(&mut cx).is_pending());
    }
    assert!(slots.claim(4).is_some());
    let old = slots.claim(4).unwrap();
    slots.cancel();
    owner.store(5, Ordering::Release);
    let new = slots.claim(5).unwrap();
    drop(old);
    assert!(slots.claim(5).is_none());
    assert!(!thermal_trip_if_current(
        &owner,
        4,
        &hot,
        Some(&sample(Ok(telemetry(200, 0)), true)),
        Some(118)
    ));
    assert!(!hot.load(Ordering::Acquire));
    assert!(thermal_trip_if_current(&owner, 5, &hot, None, Some(118)));
    drop(new);
    assert!(slots.claim(5).is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_thermal_alert_cancellation_and_owner_change_cannot_notify_successor
);

fn navi48_performance_controls_parse_and_read_native_levels() -> TestResult {
    for (text, wanted) in [
        ("auto\n", Ok(smu::GfxLevel::Auto)),
        (" low ", Ok(smu::GfxLevel::Low)),
        ("high", Ok(smu::GfxLevel::High)),
        ("manual", Err(FsError::Unsupported)),
        ("profile_standard", Err(FsError::Unsupported)),
        ("profile_min_sclk", Err(FsError::Unsupported)),
        ("profile_min_mclk", Err(FsError::Unsupported)),
        ("profile_peak", Err(FsError::Unsupported)),
        ("profile_exit", Err(FsError::Unsupported)),
        ("perf_determinism", Err(FsError::Unsupported)),
        ("turbo", Err(FsError::InvalidData)),
        ("HIGH", Err(FsError::InvalidData)),
        ("", Err(FsError::InvalidData)),
    ] {
        assert_eq!(parse_level(text), wanted);
    }
    let (mut applied, _) = update(None, sample(Ok(telemetry(60, 0)), true));
    assert_eq!(level_name(None), "auto");
    for (level, name) in [
        (smu::GfxLevel::Auto, "auto"),
        (smu::GfxLevel::Low, "low"),
        (smu::GfxLevel::High, "high"),
    ] {
        applied.gfx_level = level;
        assert_eq!(level_name(Some(applied)), name);
    }
    assert!(controls_live(Some(applied)));
    applied.error = Some(smu::Error::Rejected(0xfc));
    assert!(controls_live(Some(applied)));
    for error in [
        smu::Error::DeviceGone,
        smu::Error::Revoked,
        smu::Error::Timeout,
    ] {
        applied.error = Some(error);
        assert!(!controls_live(Some(applied)));
        assert_eq!(level_name(Some(applied)), "high");
    }
    assert!(!controls_live(None));
    // Exercise actual DrmCard dispatch for every listed family member:
    // malformed native input is validated before device readiness.
    use crate::drm_registry::DrmCard;
    for device in crate::amdgpu_rdna4::KNOWN_DEVICES {
        let card = crate::drm_devfs_bridge::AmdgpuCard::new(
            alloc::string::String::new(),
            crate::amdgpu::AMD_VENDOR,
            device.did,
            0,
            0,
            None,
        );
        assert_eq!(
            card.set_performance_level("turbo"),
            Err(FsError::InvalidData)
        );
        assert_eq!(
            card.set_performance_level("manual"),
            Err(FsError::Unsupported)
        );
    }
    let foreign = crate::drm_devfs_bridge::AmdgpuCard::new(
        alloc::string::String::new(),
        0x8086,
        0x7550,
        0,
        0,
        None,
    );
    assert_eq!(
        foreign.set_performance_level("turbo"),
        Err(FsError::Unsupported)
    );
    assert_eq!(foreign.performance_level(), "auto");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_performance_controls_parse_and_read_native_levels
);

fn navi48_performance_pending_writes_coalesce_and_cancel_without_applying() -> TestResult {
    use core::{
        cell::Cell,
        future::{pending, Future},
        task::{Context, Waker},
    };
    let serial = Mutex::new(());
    let latest = AtomicU64::new(2);
    let applied = Cell::new(smu::GfxLevel::Auto);
    let mut cx = Context::from_waker(Waker::noop());
    let held = serial.try_lock().unwrap();
    let mut old = alloc::boxed::Box::pin(run_level_request(&serial, &latest, 1, async {
        applied.set(smu::GfxLevel::Low);
        Ok::<(), smu::Error>(())
    }));
    let mut new = alloc::boxed::Box::pin(run_level_request(&serial, &latest, 2, async {
        applied.set(smu::GfxLevel::High);
        Ok::<(), smu::Error>(())
    }));
    assert!(old.as_mut().poll(&mut cx).is_pending());
    assert!(new.as_mut().poll(&mut cx).is_pending());
    assert_eq!(applied.get(), smu::GfxLevel::Auto);
    drop(held);
    assert_eq!(old.as_mut().poll(&mut cx), core::task::Poll::Ready(None));
    assert_eq!(
        new.as_mut().poll(&mut cx),
        core::task::Poll::Ready(Some(Ok(())))
    );
    assert_eq!(applied.get(), smu::GfxLevel::High);
    // A rejected request never reaches the publication path.
    latest.store(3, Ordering::Release);
    let mut rejected = alloc::boxed::Box::pin(run_level_request(&serial, &latest, 3, async {
        Err::<(), _>(smu::Error::Rejected(0xfc))?;
        applied.set(smu::GfxLevel::Low);
        Ok(())
    }));
    assert_eq!(
        rejected.as_mut().poll(&mut cx),
        core::task::Poll::Ready(Some(Err(smu::Error::Rejected(0xfc))))
    );
    assert_eq!(applied.get(), smu::GfxLevel::High);
    latest.store(4, Ordering::Release);
    let mut cancelled = alloc::boxed::Box::pin(run_level_request(&serial, &latest, 4, async {
        pending::<()>().await;
        applied.set(smu::GfxLevel::Low);
        Ok::<(), smu::Error>(())
    }));
    assert!(cancelled.as_mut().poll(&mut cx).is_pending());
    drop(cancelled);
    assert!(serial.try_lock().is_some());
    assert_eq!(applied.get(), smu::GfxLevel::High);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_performance_pending_writes_coalesce_and_cancel_without_applying
);
