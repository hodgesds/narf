//! BMG paired PL1/PL2 and interval ownership through real sysfs + MMIO.
//! Literal values: MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad
//! xe_hwmon.c PL1_HWMON_ATTR/PL2_HWMON_ATTR, TIME_UNIT/PWR_UNIT and
//! xe_pcode_api.h READ/WRITE_PACKAGE_POWER_LIMIT; xe_mchbar_regs.h masks.

use super::*;

fn prepare(card: u32, defaults: [u32; 2]) -> (Published, Firmware, u64) {
    let f = Published::new(card, GtPlatform::Battlemage);
    let fw = Firmware::new();
    fw.defaults.set(defaults);
    fw.i1.set(Some(0x8000_3200));
    let mut now = narf_time::monotonic_ns().saturating_sub(2_000_000);
    for _ in 0..8 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("i1_status"), "ready\n");
    (f, fw, now)
}

fn smoke_hwmon_bmg_pl2_real_sysfs_defaults_units_and_verified_pair() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = prepare(1120, FW);
    for name in ["power2_cap", "power2_max_interval", "power2_cap_interval"] {
        assert_eq!(
            f.show(name),
            "",
            "passive firmware source claimed a current value"
        );
        assert!(f.node.attr_is_writable(name));
    }
    for (name, value) in [
        ("power2_cap_default", "309375000\n"),
        ("power2_cap_max", "309375000\n"),
        ("power2_cap_min", "125000\n"),
        ("power2_cap_status", "default-only\n"),
        ("power2_max_interval_min", "1\n"),
        ("power2_cap_interval_min", "1\n"),
        ("power2_max_interval_max", "256000\n"),
        ("power2_cap_interval_max", "256000\n"),
    ] {
        assert_eq!(f.show(name), value);
        assert!(!f.node.attr_is_writable(name));
    }
    assert!(fw.writes().is_empty());
    f.store("power2_cap", b"250062500").unwrap();
    for _ in 0..4 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(fw.writes(), [[FW[0], 0x2468_87d1]]);
    assert_eq!(f.show("power2_cap_status"), "applying 1\n");
    assert_eq!(f.show("power2_cap"), "");
    for _ in 0..2 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("power2_cap_status"), "applied 1\n");
    assert_eq!(f.show("power2_cap"), "250125000\n");
    assert_eq!(f.show("power2_max"), "200000000\n");
    assert_eq!(f.show("power2_cap_default"), "309375000\n");
    assert_eq!(
        fw.commands.borrow()[4..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [READ_FW, WRITE, READ]
    );
    let reads = fw.hw.reads.borrow().len();
    assert_eq!(f.show("power2_cap_interval"), "1280000\n"); // Actual pre-existing window, not clamped.
    assert_eq!(fw.hw.reads.borrow().len(), reads, "sysfs read touched MMIO");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl2_real_sysfs_defaults_units_and_verified_pair
);

fn smoke_hwmon_bmg_pl2_admin_bounds_unavailable_fields_and_staleness() -> TestResult {
    let (f, fw, mut now) = prepare(1121, FW);
    {
        let _deny = Admin::deny();
        for name in ["power2_cap", "power2_max_interval", "power2_cap_interval"] {
            assert_eq!(f.store(name, b"1000"), Err(FsError::OperationNotPermitted));
        }
    }
    let _admin = Admin::allow();
    for bad in [
        &b"0"[..],
        b"124999",
        b"309375001",
        b"-1",
        b"+1",
        b"18446744073709551615",
        &[b'1'; 33],
        &[0xff],
    ] {
        assert_eq!(f.store("power2_cap", bad), Err(FsError::InvalidData));
    }
    assert_eq!(
        f.monitor
            .bmg_power
            .store_attribute("power2_cap", b"125000", now + MAX_AGE_NS + 1),
        Err(FsError::NoDevice)
    );
    apply(&f, &fw, &mut now, "power2_cap", b"125000");
    assert_eq!(fw.current.get()[1], 0x2468_8001);
    assert_eq!(f.show("power2_cap"), "125000\n");
    assert!(f
        .monitor
        .show("power2_cap", now + MAX_AGE_NS + 1)
        .is_empty());
    for word in [FW[1] & !(1 << 15), 0] {
        let (other, hardware, _) = prepare(1122, [FW[0], word]);
        for name in [
            "power2_cap",
            "power2_cap_default",
            "power2_cap_min",
            "power2_cap_max",
            "power2_cap_interval",
        ] {
            assert_eq!(other.show(name), "", "disabled PL2 invented a measurement");
        }
        assert_eq!(
            other.store("power2_cap", b"125000"),
            Err(FsError::Unsupported)
        );
        assert_eq!(
            other.store("power2_cap_interval", b"1000"),
            Err(FsError::Unsupported)
        );
        assert_eq!(other.show("power2_max_default"), "200000000\n");
        assert!(hardware.writes().is_empty());
    }
    let (only_pl2, hardware, mut t) = prepare(1122, [0, FW[1]]);
    assert_eq!(only_pl2.show("power2_max_default"), "");
    apply(&only_pl2, &hardware, &mut t, "power2_cap", b"250000000");
    assert_eq!(hardware.current.get(), [0, 0x2468_87d0]);
    assert_eq!(only_pl2.show("power2_max"), "");
    assert_eq!(only_pl2.show("power2_cap"), "250000000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl2_admin_bounds_unavailable_fields_and_staleness
);

fn smoke_hwmon_bmg_pl1_pl2_intervals_source_vectors_and_one_request_slot() -> TestResult {
    let _admin = Admin::allow();
    for (attribute, index) in [("power2_max_interval", 0), ("power2_cap_interval", 1)] {
        for (text, bits, value) in [
            (b"1000".as_slice(), 0x0014_0000, "1000\n"),
            (b"1250".as_slice(), 0x0054_0000, "1250\n"),
            (b"256000".as_slice(), 0x0024_0000, "256000\n"),
        ] {
            let (f, fw, mut now) = prepare(1123, FW);
            for bad in [
                &b"0"[..],
                b"256001",
                b"-1",
                b"18446744073709551615",
                &[b'1'; 33],
            ] {
                assert_eq!(f.store(attribute, bad), Err(FsError::InvalidData));
            }
            f.store(attribute, text).unwrap();
            for name in [
                "power2_max",
                "power2_cap",
                "power2_max_interval",
                "power2_cap_interval",
            ] {
                assert_eq!(f.store(name, b"1000"), Err(FsError::Busy));
            }
            assert!(fw.writes().is_empty());
            for _ in 0..6 {
                fw.step(&f.monitor, 7, &mut now);
            }
            let mut expected = FW;
            expected[index] = (expected[index] & !0x00fe_0000) | bits;
            assert_eq!(fw.writes(), [expected]);
            assert_eq!(f.show(attribute), value);
            assert_eq!(f.show("power2_max"), "200000000\n");
            assert_eq!(f.show("power2_cap"), "309375000\n");
            assert_eq!(f.show("power2_cap_status"), "applied 1\n");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl1_pl2_intervals_source_vectors_and_one_request_slot
);

fn smoke_hwmon_bmg_paired_fresh_rmw_refuses_disabled_and_raised_sibling() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = prepare(1124, FW);
    f.store("power2_cap", b"200000000").unwrap();
    let fresh = [FW[0] ^ (1 << 16), FW[1] ^ (1 << 24)];
    fw.defaults.set(fresh);
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(fw.writes(), [[fresh[0], 0x2568_8640]]);
    for case in 0..3 {
        let (other, hardware, mut t) = prepare(1125, FW);
        let (attribute, input, changed) = match case {
            0 => (
                "power2_cap",
                b"200000000".as_slice(),
                [FW[0], FW[1] & !(1 << 15)],
            ),
            1 => (
                "power2_cap",
                b"200000000".as_slice(),
                [(FW[0] & !0x7fff) | 0x641, FW[1]],
            ),
            _ => (
                "power2_cap_interval",
                b"1000".as_slice(),
                [FW[0], (FW[1] & !0x7fff) | 0x9ac],
            ),
        };
        other.store(attribute, input).unwrap();
        hardware.defaults.set(changed);
        for _ in 0..2 {
            hardware.step(&other.monitor, 7, &mut t);
        }
        assert_eq!(other.show("power2_cap_status"), "failed 1 Bounds\n");
        assert!(
            hardware.writes().is_empty(),
            "uncertain paired fields were switched into PCODE"
        );
        assert_eq!(other.show("power2_cap"), "");
        assert_eq!(other.show("power1_crit"), "200000000\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_paired_fresh_rmw_refuses_disabled_and_raised_sibling
);

fn smoke_hwmon_bmg_pl2_clamp_sibling_change_and_write_status_never_claim_applied() -> TestResult {
    let _admin = Admin::allow();
    for case in 0..3 {
        let (f, fw, mut now) = prepare(1126, FW);
        match case {
            0 => fw.change_pl2.set(true),
            1 => fw.clamp.set(true),
            _ => fw.error.set(Some((5, 6))),
        }
        apply(&f, &fw, &mut now, "power2_cap", b"250000000");
        let expected = if case == 2 {
            "failed 1 Status(6)\n"
        } else {
            "failed 1 Readback\n"
        };
        assert_eq!(f.show("power2_cap_status"), expected);
        assert_eq!(f.show("power2_max_status"), expected);
        assert_eq!(f.show("power2_cap"), "");
        assert_eq!(
            f.store("power2_max_interval", b"1000"),
            Err(FsError::Unsupported)
        );
        if case == 2 {
            assert_eq!(fw.commands.borrow().len(), 6, "error queued verification");
        }
        assert_eq!(
            f.show("i1_status"),
            "ready\n",
            "local power error quarantined independent I1"
        );
        apply(&f, &fw, &mut now, "power1_crit", b"100000000");
        assert_eq!(f.show("i1_status"), "applied 1\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl2_clamp_sibling_change_and_write_status_never_claim_applied
);

fn smoke_hwmon_bmg_pl2_interval_cancel_each_stage_retains_both_ceilings_without_replay(
) -> TestResult {
    let _admin = Admin::allow();
    for steps in 0..=5 {
        let (f, fw, mut now) = prepare(1127, FW);
        apply(&f, &fw, &mut now, "power2_max", b"100000000");
        apply(&f, &fw, &mut now, "power2_cap", b"200000000");
        f.store("power2_cap_interval", b"1250").unwrap();
        for _ in 0..steps {
            fw.step(&f.monitor, 7, &mut now);
        }
        f.monitor.close();
        fw.tick();
        assert_eq!(f.show("power2_cap_status"), "failed 3 Closed\n");
        let writes = fw.writes().len();
        f.monitor.activate(8);
        f.monitor
            .service_mmio(7, now, &fw, || panic!("old package epoch accessed PCI"));
        fw.defaults.set([0x5a2e_8320, 0x2468_8640]);
        for _ in 0..8 {
            fw.step(&f.monitor, 8, &mut now);
        }
        assert_eq!(
            fw.writes().len(),
            writes,
            "activation replayed paired policy"
        );
        assert_eq!(f.show("power2_max_default"), "200000000\n");
        assert_eq!(f.show("power2_cap_default"), "309375000\n");
        assert_eq!(f.show("power2_cap_max"), "309375000\n");
        assert_eq!(f.show("power2_cap"), "");
        f.store("power2_cap", b"309375000").unwrap();
        for _ in 0..6 {
            fw.step(&f.monitor, 8, &mut now);
        }
        assert_eq!(f.show("power2_cap"), "309375000\n");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl2_interval_cancel_each_stage_retains_both_ceilings_without_replay
);

fn smoke_hwmon_bmg_pl2_every_command_stage_checks_current_authority() -> TestResult {
    let _admin = Admin::allow();
    for (stage, operations) in [4, 4, 4, 1, 4, 4].into_iter().enumerate() {
        for denied in 1..=operations {
            let (f, fw, mut now) = prepare(1128, FW);
            f.store("power2_cap", b"250000000").unwrap();
            for _ in 0..stage {
                fw.step(&f.monitor, 7, &mut now);
            }
            fw.tick();
            fw.hw.reads.borrow_mut().clear();
            fw.hw.writes.borrow_mut().clear();
            let mut checks = 0;
            f.monitor.service_mmio(7, now, &fw, || {
                checks += 1;
                checks < denied
            });
            assert_eq!(
                fw.hw.reads.borrow().len() + fw.hw.writes.borrow().len(),
                denied - 1
            );
            assert_eq!(f.show("power2_cap_status"), "failed 1 Access\n");
            for name in [
                "power2_cap",
                "power2_cap_default",
                "power2_cap_interval",
                "power2_max_interval",
                "power2_max_default",
                "power1_crit",
                "temp2_input",
            ] {
                assert_eq!(
                    f.show(name),
                    "",
                    "{name} survived known loss at stage{stage}"
                );
            }
            let posted = fw.commands.borrow().len();
            f.monitor.service_mmio(7, now + 1, &fw, || true);
            assert_eq!(
                fw.commands.borrow().len(),
                posted,
                "ambiguous command was replayed"
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl2_every_command_stage_checks_current_authority
);

fn smoke_hwmon_bmg_pl2_and_interval_clients_yield_fairly_to_queued_i1() -> TestResult {
    let _admin = Admin::allow();
    let (f, fw, mut now) = prepare(1129, FW);
    f.store("power2_cap", b"250000000").unwrap();
    f.store("power1_crit", b"100000000").unwrap();
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("power2_cap_status"), "applied 1\n");
    f.store("power2_max_interval", b"1000").unwrap();
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("i1_status"), "applied 1\n");
    assert_eq!(f.show("power2_cap_status"), "queued 2\n");
    for _ in 0..6 {
        fw.step(&f.monitor, 7, &mut now);
    }
    assert_eq!(f.show("power2_cap_status"), "applied 2\n");
    assert_eq!(f.show("power2_max_interval"), "1000\n");
    assert_eq!(f.show("power2_cap"), "250000000\n");
    assert_eq!(
        fw.commands.borrow()[4..]
            .iter()
            .map(|c| c.0)
            .collect::<Vec<_>>(),
        [READ_FW, WRITE, READ, 0x047c, 0x057c, 0x047c, READ, WRITE, READ]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_pl2_and_interval_clients_yield_fairly_to_queued_i1
);
