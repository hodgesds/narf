use super::*;
use alloc::{boxed::Box, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_filesystem::{DirOps, FsError};
use narf_kernel_test::{kernel_test_in, TestResult};

fn dg2(register: u64) -> Option<u32> {
    Some(match register {
        0x145978 => 0x1020_3041, // low byte 65 Celsius
        0x1382c0 => 83,
        0x1381b4 => 0x8000_0141, // 321 * 2.5 mV, rounded to803
        0x145938 => 0xe00,
        0x14593c => 0x4000, // one joule at2^-14 J
        _ => panic!("non-whitelisted read {register:x}"),
    })
}
fn ready<T>(future: impl Future<Output = T>) -> T {
    match Box::pin(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("cached sysfs operation parked"),
    }
}

fn smoke_hwmon_dg2_native_sample_units_and_whitelist() -> TestResult {
    assert!(Monitor::new(
        GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
        0
    )
    .is_none());
    let monitor = Monitor::new(GtPlatform::Alchemist, 0).unwrap();
    let mut accesses = Vec::new();
    monitor.sample(7, 0, |_| panic!("unactivated sensor read hardware"));
    monitor.activate(7);
    monitor.sample(7, 0, |register| {
        accesses.push(register);
        dg2(register)
    });
    assert_eq!(accesses, [0x145978, 0x1382c0, 0x1381b4, 0x145938, 0x14593c]);
    assert_eq!(monitor.show("temp2_input", 0), "65000\n");
    assert_eq!(monitor.show("temp3_input", 0), "83000\n");
    assert_eq!(monitor.show("in1_input", 0), "803\n");
    assert_eq!(monitor.show("energy2_input", 0), "1000000\n");
    assert_eq!(monitor.show("in1_label", 0), "pkg\n");
    assert!(monitor.show("power2_cap", 0).is_empty());
    assert!(monitor.show("temp6_input", 0).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_native_sample_units_and_whitelist
);

fn smoke_hwmon_bmg_temperature_channels_and_signed_integer_source_format() -> TestResult {
    let monitor = Monitor::new(GtPlatform::Battlemage, 0).unwrap();
    monitor.activate(8);
    let mut accesses = Vec::new();
    monitor.sample(8, 0, |register| {
        accesses.push(register);
        Some(match register {
            0x138434 => 71,
            0x1382c0 => 94,
            0x138260 => 0,           // absent channel
            0x138264 => 0x8000_4b80, // source discards fraction: -75C
            0x138268 => 0x0000_44c0, // +68C
            0x13829c => u32::MAX,
            0x13826c..=0x138298 => 0,
            _ => panic!("unexpected BMG register {register:x}"),
        })
    });
    assert_eq!(
        accesses,
        [
            0x138434, 0x1382c0, 0x138260, 0x138264, 0x138268, 0x13826c, 0x138270, 0x138274,
            0x138278, 0x13827c, 0x138280, 0x138284, 0x138288, 0x13828c, 0x138290, 0x138294,
            0x138298, 0x13829c,
        ]
    );
    assert_eq!(monitor.show("temp2_input", 0), "71000\n");
    assert!(monitor.show("temp6_input", 0).is_empty());
    assert_eq!(monitor.show("temp7_input", 0), "-75000\n");
    assert_eq!(monitor.show("temp8_input", 0), "68000\n");
    assert_eq!(monitor.show("temp7_label", 0), "vram_ch_1\n");
    assert!(monitor.show("temp21_input", 0).is_empty());
    assert!(monitor.show("energy2_input", 0).is_empty());
    assert!(monitor.show("in1_label", 0).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_temperature_channels_and_signed_integer_source_format
);

fn smoke_hwmon_production_mmio_gate_distinguishes_optional_absence_from_loss() -> TestResult {
    struct Sensors(core::cell::RefCell<Vec<u64>>);
    impl MmioWindow for Sensors {
        fn read32(&self, offset: u64) -> u32 {
            self.0.borrow_mut().push(offset);
            match offset {
                0x138124 => u32::MAX, // unavailable optional discovery port
                0x138434 => 71,
                0x1382c0 => 94,
                0x138264 => u32::MAX,
                _ => 0,
            }
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("telemetry wrote hardware");
        }
    }
    let monitor = Monitor::new(GtPlatform::Battlemage, 0).unwrap();
    let io = Sensors(core::cell::RefCell::new(Vec::new()));
    monitor.activate(7);
    monitor.service_mmio(7, 0, &io, || true);
    assert_eq!(io.0.borrow().len(), 19);
    assert_eq!(monitor.show("temp2_input", 0), "71000\n");
    assert_eq!(monitor.show("temp3_input", 0), "94000\n");
    assert!(monitor.show("temp7_input", 0).is_empty());
    io.0.borrow_mut().clear();
    monitor.activate(8);
    monitor.service_mmio(8, 1_000_000_000, &io, || io.0.borrow().len() < 3);
    assert_eq!(*io.0.borrow(), [0x138124, 0x138434, 0x1382c0]);
    assert!(monitor.reading(1_000_000_000).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_production_mmio_gate_distinguishes_optional_absence_from_loss
);

fn smoke_hwmon_rate_freshness_epoch_and_close_during_capture() -> TestResult {
    let monitor = Monitor::new(GtPlatform::Alchemist, 0).unwrap();
    monitor.activate(7);
    monitor.sample(7, 0, dg2);
    monitor.sample(7, 999_999_999, |_| panic!("sample rate exceeded"));
    assert_eq!(monitor.show("temp2_input", 2_000_000_000), "65000\n");
    assert!(monitor.show("temp2_input", 2_000_000_001).is_empty());
    let mut accesses = 0;
    monitor.sample(7, 1_000_000_000, |register| {
        accesses += 1;
        monitor.close();
        dg2(register)
    });
    assert_eq!(accesses, 1, "closed epoch continued reading hardware");
    assert!(monitor.reading(1_000_000_000).is_none());
    monitor.sample(7, 2_000_000_000, |_| {
        panic!("stale worker reopened admission")
    });
    monitor.activate(8);
    monitor.sample(7, 2_000_000_000, |_| panic!("old epoch sampled new owner"));
    assert!(monitor.reading(2_000_000_000).is_none());
    monitor.sample(8, 2_000_000_000, dg2);
    assert_eq!(monitor.show("temp2_input", 2_000_000_000), "65000\n");
    assert!(
        monitor.reading(1_000_000_000).is_none(),
        "backwards clock looked fresh"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_rate_freshness_epoch_and_close_during_capture
);

fn smoke_hwmon_lost_authority_and_unavailable_registers_never_fabricate_zero() -> TestResult {
    let monitor = Monitor::new(GtPlatform::Alchemist, 0).unwrap();
    monitor.activate(7);
    monitor.sample(7, 0, dg2);
    let mut accesses = Vec::new();
    monitor.sample(7, 1_000_000_000, |register| {
        accesses.push(register);
        if register == 0x1381b4 {
            None
        } else {
            dg2(register)
        }
    });
    assert_eq!(accesses, [0x145978, 0x1382c0, 0x1381b4]);
    assert!(monitor.reading(1_000_000_000).is_none());
    monitor.sample(7, 2_000_000_000, dg2);
    assert_eq!(monitor.show("temp2_input", 2_000_000_000), "65000\n");
    assert!(monitor.show("energy2_input", 2_000_000_000).is_empty());
    monitor.activate(8);
    monitor.sample(8, 3_000_000_000, |_| Some(u32::MAX));
    for attribute in ["temp2_input", "temp3_input", "in1_input", "energy2_input"] {
        assert!(monitor.show(attribute, 3_000_000_000).is_empty());
    }
    monitor.activate(9);
    monitor.sample(9, 4_000_000_000, dg2);
    assert_eq!(monitor.show("energy2_input", 4_000_000_000), "1000000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_lost_authority_and_unavailable_registers_never_fabricate_zero
);

fn smoke_hwmon_energy_wrap_units_gap_and_overflow_ownership() -> TestResult {
    let monitor = Monitor::new(GtPlatform::Alchemist, 0).unwrap();
    monitor.activate(7);
    monitor.sample(7, 0, |register| {
        if register == 0x14593c {
            Some(0xfffffff0)
        } else {
            dg2(register)
        }
    });
    assert_eq!(monitor.show("energy2_input", 0), "262143999023\n");
    monitor.sample(7, 1_000_000_000, |register| {
        if register == 0x14593c {
            Some(0x10)
        } else {
            dg2(register)
        }
    });
    assert_eq!(
        monitor.show("energy2_input", 1_000_000_000),
        "262144000976\n"
    );
    monitor.sample(7, 2_000_000_000, |register| {
        if register == 0x145938 {
            Some(0xf00)
        } else {
            dg2(register)
        }
    });
    assert!(monitor.show("energy2_input", 2_000_000_000).is_empty());
    monitor.sample(7, 3_000_000_000, dg2);
    assert!(monitor.show("energy2_input", 3_000_000_000).is_empty());
    monitor.activate(8);
    monitor.sample(8, 4_000_000_000, dg2);
    monitor.sample(8, 6_000_000_001, dg2);
    assert!(monitor.show("energy2_input", 6_000_000_001).is_empty());
    monitor.activate(9);
    monitor.sample(9, 7_000_000_000, dg2);
    monitor.state.lock().energy.as_mut().unwrap().accumulated = u64::MAX;
    monitor.sample(9, 8_000_000_000, |register| {
        if register == 0x14593c {
            Some(0x4001)
        } else {
            dg2(register)
        }
    });
    assert!(monitor.show("energy2_input", 8_000_000_000).is_empty());
    assert!(monitor.state.lock().energy_lost);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_energy_wrap_units_gap_and_overflow_ownership
);

fn smoke_hwmon_real_sysfs_is_card_scoped_read_only_and_cached() -> TestResult {
    let dg2 = Monitor::register(987, GtPlatform::Alchemist, 0).unwrap();
    let bmg = Monitor::register(988, GtPlatform::Battlemage, 0).unwrap();
    let class = class_register("hwmon");
    let find = |card| {
        class
            .child_names()
            .iter()
            .filter_map(|name| class.get_child(name))
            .find(|node| {
                node.get_symlink("device") == Some(format!("/sys/class/drm/card{card}/device"))
            })
            .unwrap()
    };
    let node = find(987);
    let other = find(988);
    assert_eq!(node.attr_show("name").as_deref(), Some("xe\n"));
    assert!(node.has_attr("energy2_input"));
    assert!(!node.has_attr("temp6_input"));
    assert!(other.has_attr("temp21_input"));
    assert!(other.has_attr("energy2_input"));
    assert!(other.attr_show("energy2_input").unwrap().is_empty());
    let dir = narf_filesystem::sysfs::SysKobjDir { kobj: node.clone() };
    let file = dir.lookup("temp2_input").unwrap();
    assert_eq!(file.stat().mode.perms, 0o444);
    assert_eq!(ready(file.write(0, b"100")), Err(FsError::ReadOnly));
    assert!(!node.attr_is_writable("temp2_input"));
    assert!(node.attr_store("temp2_input", b"100").is_none());
    dg2.activate(7);
    let now = narf_time::monotonic_ns();
    dg2.sample(7, now, self::dg2);
    let mut bytes = [0; 32];
    let size = ready(file.read(0, &mut bytes)).unwrap();
    assert_eq!(&bytes[..size], b"65000\n");
    assert_eq!(ready(file.read(u64::MAX, &mut bytes)).unwrap(), 0);
    dg2.close();
    assert_eq!(ready(file.read(0, &mut bytes)).unwrap(), 0);
    // Independent per-card state: closing one never changes the other.
    bmg.activate(8);
    bmg.sample(8, now, |_| Some(42));
    assert_eq!(other.attr_show("temp2_input").as_deref(), Some("42000\n"));
    assert!(node.attr_show("temp2_input").unwrap().is_empty());
    assert!(class.remove_child(node.name()));
    assert!(class.remove_child(other.name()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_real_sysfs_is_card_scoped_read_only_and_cached
);
