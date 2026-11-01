//! Native production service models; literal vectors cite MIT Linux
//! b90c984d615e8ce2af96f5b1411a962d83fed2ad xe_hwmon.c, xe_pcode_api.h,
//! regs/{xe_mchbar_regs,xe_pcode_regs}.h. No host-extracted C or source slicing.

use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_filesystem::FsError;
use narf_kernel_test::{kernel_test_in, TestResult};

#[path = "intel_gpu_hwmon_bmg_power_tests.rs"]
mod bmg_power_tests;

const PL1: u64 = 0x1459a0;
const BOOT_PL1: u32 = 0x5a2e_8640; // enabled200 W, unrelated fields retained
const SECOND: u64 = 1_000_000_000;

struct Hardware {
    regs: RefCell<BTreeMap<u64, u32>>,
    reads: RefCell<Vec<u64>>,
    writes: RefCell<Vec<(u64, u32)>>,
    sticky_pl1: Cell<bool>,
}
impl Hardware {
    fn new() -> Self {
        Self {
            regs: RefCell::new(
                [
                    (0x145978, 65),
                    (0x138434, 71),
                    (0x1382c0, 83),
                    (0x1381b4, 0x141),
                    (0x145938, 0xe03),
                    (0x14593c, 0x4000),
                    (0x145930, 0x0258_0708), // SKU min75 W, rated225 W
                    (0x145934, 0x07d0),      // SKU max250 W
                    (PL1, BOOT_PL1),
                    (0x138140, 0),
                    (0x138170, 0),
                    (0x1381a0, 0),
                    (0x138124, 0),
                    (0x138128, 0),
                    (0x13812c, 0),
                ]
                .into_iter()
                .collect(),
            ),
            reads: RefCell::new(Vec::new()),
            writes: RefCell::new(Vec::new()),
            sticky_pl1: Cell::new(true),
        }
    }
    fn set(&self, register: u64, value: u32) {
        self.regs.borrow_mut().insert(register, value);
    }
    fn get(&self, register: u64) -> u32 {
        self.regs.borrow()[&register]
    }
    fn complete(&self, status: u8, data0: u32, data1: u32) {
        self.set(pcode::MAILBOX, u32::from(status)); // no command echo required
        self.set(pcode::DATA0, data0);
        self.set(pcode::DATA1, data1);
    }
    fn pl1_writes(&self) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter_map(|&(r, v)| (r == PL1).then_some(v))
            .collect()
    }
}
impl MmioWindow for Hardware {
    fn read32(&self, offset: u64) -> u32 {
        self.reads.borrow_mut().push(offset);
        self.regs.borrow().get(&offset).copied().unwrap_or_else(|| {
            assert!(
                (0x138260..=0x13829c).contains(&offset) && offset % 4 == 0,
                "non-whitelisted telemetry read {offset:x}"
            );
            0
        })
    }
    fn write32(&self, offset: u64, value: u32) {
        assert!([PL1, pcode::MAILBOX, pcode::DATA0, pcode::DATA1].contains(&offset));
        self.writes.borrow_mut().push((offset, value));
        if offset != PL1 || self.sticky_pl1.get() {
            self.set(offset, value);
        }
        // The legacy discovery model has no package-power firmware support.
        // Its first passive package read completes Illegal Command, rather
        // than pretending the new power client owns a working endpoint.
        if offset == pcode::MAILBOX && value == 0x8001_087c {
            self.set(offset, 1);
        }
    }
}
struct Admin(Option<fn(u32) -> bool>);
impl Admin {
    fn allow() -> Self {
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            |cap| cap == 21,
        )))
    }
    fn deny() -> Self {
        Self(narf_filesystem::__test_swap_caller_capable_hook(Some(
            |_| false,
        )))
    }
}
impl Drop for Admin {
    fn drop(&mut self) {
        narf_filesystem::__test_swap_caller_capable_hook(self.0);
    }
}
fn monitor(platform: GtPlatform) -> Monitor {
    // These control-only fixtures carry no PMT BAR-resource proof.
    let monitor = Monitor::new(platform, 0).unwrap();
    monitor.activate(7);
    monitor
}

fn smoke_hwmon_dg2_pl1_units_boot_bounds_queued_readback_and_preservation() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    for (name, expected) in [
        ("power2_max", "200000000\n"),
        ("power2_rated_max", "225000000\n"),
        ("power2_max_min", "75000000\n"),
        ("power2_max_max", "200000000\n"),
        ("power2_max_default", "200000000\n"),
    ] {
        assert_eq!(monitor.show(name, 0), expected);
    }
    assert!(
        hw.writes.borrow().is_empty(),
        "DG2 must never post a PCODE query"
    );
    assert_eq!(monitor.power.store(b"100000000\n", 0), Ok(()));
    assert_eq!(monitor.show("power2_max_status", 0), "queued 1\n");
    assert!(
        hw.writes.borrow().is_empty(),
        "store performed hardware I/O"
    );
    assert_eq!(monitor.power.store(b"125000000", 0), Err(FsError::Busy));
    monitor.service_mmio(7, 1, &hw, || true);
    assert_eq!(hw.pl1_writes(), [0x5a2e_8320]);
    assert_eq!(hw.get(PL1) & !0xffff, BOOT_PL1 & !0xffff);
    assert_eq!(monitor.show("power2_max", 1), "100000000\n");
    assert_eq!(monitor.show("power2_max_status", 1), "applied 1\n");
    assert_eq!(monitor.show("power2_max_default", 1), "200000000\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_pl1_units_boot_bounds_queued_readback_and_preservation
);

fn smoke_hwmon_dg2_pl1_admin_bounds_rounding_and_stale_refusal() -> TestResult {
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    {
        let _deny = Admin::deny();
        assert_eq!(
            monitor.power.store(b"100000000", 0),
            Err(FsError::OperationNotPermitted)
        );
    }
    let _admin = Admin::allow();
    for bad in [
        "0",
        "74999999",
        "200000001",
        "18446744073709551615",
        "-1",
        "+100000000",
        "1 2",
        "",
    ] {
        assert_eq!(
            monitor.power.store(bad.as_bytes(), 0),
            Err(FsError::InvalidData),
            "{bad}"
        );
    }
    assert_eq!(
        monitor.power.store(b"100000000", MAX_AGE_NS + 1),
        Err(FsError::NoDevice)
    );
    assert_eq!(monitor.power.store(b"100062500", 0), Ok(())); // .5 raw -> nearest up
    monitor.service_mmio(7, 1, &hw, || true);
    assert_eq!(hw.get(PL1), 0x5a2e_8321);
    assert_eq!(monitor.show("power2_max", 1), "100125000\n");
    assert!(monitor.show("power2_max", MAX_AGE_NS + 2).is_empty());
    assert_eq!(hw.pl1_writes().len(), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_pl1_admin_bounds_rounding_and_stale_refusal
);

fn smoke_hwmon_dg2_pl1_locked_disabled_and_units_loss_fail_closed() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    hw.sticky_pl1.set(false);
    monitor.power.store(b"100000000", 0).unwrap();
    monitor.service_mmio(7, 1, &hw, || true);
    assert_eq!(monitor.show("power2_max_status", 1), "failed 1 Readback\n");
    assert_eq!(monitor.show("power2_max", 1), "200000000\n");
    hw.set(PL1, BOOT_PL1 & !(1 << 15));
    monitor.service_mmio(7, SECOND + 1, &hw, || true);
    assert_eq!(monitor.show("power2_max", SECOND + 1), "0\n");
    assert_eq!(
        monitor.power.store(b"100000000", SECOND + 1),
        Err(FsError::Unsupported)
    );
    hw.set(PL1, BOOT_PL1);
    hw.set(0x145938, 0xe04); // changed power units: original ceiling cannot be reinterpreted
    monitor.service_mmio(7, 2 * SECOND + 1, &hw, || true);
    assert_eq!(
        monitor.power.store(b"100000000", 2 * SECOND + 1),
        Err(FsError::Unsupported)
    );
    assert!(monitor
        .show("power2_max_default", 2 * SECOND + 1)
        .is_empty());
    assert_eq!(hw.pl1_writes().len(), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_pl1_locked_disabled_and_units_loss_fail_closed
);

fn smoke_hwmon_dg2_pl1_close_revocation_reset_and_original_ceiling_retention() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    monitor.power.store(b"100000000", 0).unwrap();
    monitor.service_mmio(7, 1, &hw, || true);
    monitor.power.store(b"125000000", 1).unwrap();
    monitor.close();
    assert_eq!(monitor.show("power2_max_status", 2), "failed 2 Closed\n");
    monitor.service_mmio(7, SECOND, &hw, || panic!("old epoch touched PCI/MMIO"));
    monitor.activate(8);
    monitor.service_mmio(8, SECOND, &hw, || true);
    assert_eq!(hw.pl1_writes().len(), 1, "reset replayed an old policy");
    assert_eq!(monitor.show("power2_max_default", SECOND), "200000000\n");
    assert_eq!(monitor.show("power2_max_max", SECOND), "200000000\n");
    monitor.power.store(b"200000000", SECOND).unwrap();
    let mut checks = 0;
    monitor.service_mmio(8, SECOND + 1, &hw, || {
        checks += 1;
        if checks == 6 {
            monitor.close();
        }
        checks < 6
    });
    assert_eq!(
        hw.pl1_writes().len(),
        1,
        "revoked authority still wrote PL1"
    );
    assert!(monitor.show("power2_max", SECOND + 1).is_empty());
    assert_eq!(
        monitor.show("power2_max_status", SECOND + 1),
        "failed 3 Closed\n"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_pl1_close_revocation_reset_and_original_ceiling_retention
);

fn smoke_hwmon_dg2_power_loss_does_not_hide_sibling_sensors_and_no_wake() -> TestResult {
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    hw.set(0x145930, u32::MAX);
    monitor.service_mmio(7, 0, &hw, || true);
    assert!(monitor.show("power2_max", 0).is_empty());
    assert_eq!(monitor.show("temp2_input", 0), "65000\n");
    assert_eq!(monitor.show("energy2_input", 0), "1000000\n");
    hw.reads.borrow_mut().clear();
    monitor.service_mmio(7, SECOND, &hw, || false);
    assert!(hw.reads.borrow().is_empty(), "lost access read MMIO");
    assert!(monitor.show("power2_max", SECOND).is_empty());
    assert!(monitor.show("temp2_input", SECOND).is_empty());
    assert!(hw.writes.borrow().is_empty());
    let retry = self::monitor(GtPlatform::Alchemist);
    let flapping = Hardware::new();
    let mut calls = 0;
    retry.service_mmio(7, 0, &flapping, || {
        calls += 1;
        calls != 2 // a later true must not restart a partially lost service
    });
    assert_eq!(flapping.reads.borrow().len(), 1);
    assert_eq!(calls, 2);
    assert!(retry.show("temp2_input", 0).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_dg2_power_loss_does_not_hide_sibling_sensors_and_no_wake
);

fn smoke_hwmon_fans_native_pulses_wrap_rounding_gap_and_unavailable() -> TestResult {
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    hw.set(0x138140, 0xffff_fff0);
    hw.set(0x138170, 100);
    monitor.service_mmio(7, 0, &hw, || true);
    assert!(
        monitor.show("fan1_input", 0).is_empty(),
        "first sample invented RPM"
    );
    hw.set(0x138140, 0x10); // 32 pulses ->16 rotations ->960RPM
    hw.set(0x138170, 301); //201 pulses ->100 integer rotations ->6000RPM
    monitor.service_mmio(7, SECOND, &hw, || true);
    assert_eq!(monitor.show("fan1_input", SECOND), "960\n");
    assert_eq!(monitor.show("fan2_input", SECOND), "6000\n");
    assert!(monitor.show("fan3_input", SECOND).is_empty());
    hw.set(0x138140, 0x12);
    hw.set(0x138170, u32::MAX);
    monitor.service_mmio(7, 2 * SECOND + 1_000_000, &hw, || true);
    assert_eq!(monitor.show("fan1_input", 2 * SECOND + 1_000_000), "60\n");
    assert!(monitor
        .show("fan2_input", 2 * SECOND + 1_000_000)
        .is_empty());
    monitor.service_mmio(7, 5 * SECOND, &hw, || true);
    assert!(
        monitor.show("fan1_input", 5 * SECOND).is_empty(),
        "gap manufactured continuity"
    );
    monitor.close();
    assert!(monitor.show("fan1_input", 5 * SECOND).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_fans_native_pulses_wrap_rounding_gap_and_unavailable
);

fn smoke_hwmon_bmg_owned_mailbox_fans_and_thermal_limit_wire_cases() -> TestResult {
    let monitor = monitor(GtPlatform::Battlemage);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    assert_eq!(
        *hw.writes.borrow(),
        [(0x138128, 0), (0x13812c, 0), (0x138124, 0x8000_047d)]
    );
    assert!(!hw.reads.borrow().contains(&pcode::DATA0));
    hw.complete(0, 2, 0);
    monitor.service_mmio(7, 100_000, &hw, || true);
    monitor.service_mmio(7, 200_000, &hw, || true);
    assert_eq!(hw.get(pcode::MAILBOX), 0x8000_0025);
    hw.complete(0, 0x5f69_646e, 97); //110,100,105,95;97 Celsius
    monitor.service_mmio(7, 300_000, &hw, || true);
    assert_eq!(monitor.show("telemetry_status", 300_000), "ready\n");
    for (name, value) in [
        ("temp2_emergency", "110000\n"),
        ("temp2_crit", "100000\n"),
        ("temp3_emergency", "105000\n"),
        ("temp2_max", "95000\n"),
        ("temp3_crit", "97000\n"),
    ] {
        assert_eq!(monitor.show(name, 300_000), value);
    }
    monitor.service_mmio(7, SECOND, &hw, || true); // establish fan baseline
    hw.set(0x138140, 120);
    hw.set(0x138170, 160);
    monitor.service_mmio(7, 2 * SECOND, &hw, || true);
    assert_eq!(monitor.show("fan1_input", 2 * SECOND), "3600\n");
    assert_eq!(monitor.show("fan2_input", 2 * SECOND), "4800\n");
    assert!(!hw.reads.borrow().contains(&0x1381a0));
    assert_eq!(
        hw.writes.borrow().len(),
        9,
        "two discovery reads plus one refused package read expected"
    );
    assert!(monitor.show("temp2_crit", 4 * SECOND + 1).is_empty());
    hw.reads.borrow_mut().clear();
    let mut checks = 0;
    monitor.service_mmio(7, 3 * SECOND, &hw, || {
        checks += 1;
        checks <= 18 // sensors succeeded; the first fan read loses authority
    });
    assert_eq!(hw.reads.borrow().len(), 18);
    assert!(
        monitor.show("temp2_crit", 3 * SECOND).is_empty(),
        "lost access exposed old limits"
    );
    assert!(monitor.show("temp2_input", 3 * SECOND).is_empty());
    monitor.close();
    assert!(monitor.show("temp3_crit", 2 * SECOND).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_owned_mailbox_fans_and_thermal_limit_wire_cases
);

fn smoke_hwmon_bmg_foreign_busy_timeout_identity_and_reset_reply_refusal() -> TestResult {
    let hw = Hardware::new();
    let monitor = monitor(GtPlatform::Battlemage);
    hw.set(pcode::MAILBOX, 0x8000_9911);
    monitor.service_mmio(7, 0, &hw, || true);
    assert_eq!(monitor.show("telemetry_status", 0), "failed ForeignBusy\n");
    assert!(hw.writes.borrow().is_empty());
    monitor.activate(8);
    hw.set(pcode::MAILBOX, 0);
    monitor.service_mmio(8, SECOND, &hw, || true);
    monitor.service_mmio(8, SECOND + 1_000_000, &hw, || true);
    assert_eq!(monitor.show("telemetry_status", SECOND), "failed Timeout\n");
    hw.complete(0, 3, 0); // late reply may not be consumed after timeout
    hw.reads.borrow_mut().clear();
    monitor.service_mmio(8, SECOND + 1_000_001, &hw, || true);
    assert!(hw.reads.borrow().is_empty());
    monitor.activate(9);
    monitor.service_mmio(9, 2 * SECOND, &hw, || true); // fresh post overwrites stale DATA
    assert_eq!(hw.get(pcode::DATA0), 0);
    hw.set(pcode::MAILBOX, 0x8000_997d);
    monitor.service_mmio(9, 2 * SECOND + 1, &hw, || true);
    assert_eq!(
        monitor.show("telemetry_status", 2 * SECOND),
        "failed Identity\n"
    );
    monitor.close();
    hw.reads.borrow_mut().clear();
    monitor.service_mmio(9, 3 * SECOND, &hw, || {
        panic!("closed discovery touched PCI")
    });
    assert!(hw.reads.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_foreign_busy_timeout_identity_and_reset_reply_refusal
);

fn smoke_hwmon_bmg_status_errors_invalid_counts_zero_limits_and_partial_loss() -> TestResult {
    for status in [1, 2, 3, 4, 6, 0x10, 0x11, 0xff] {
        let monitor = monitor(GtPlatform::Battlemage);
        let hw = Hardware::new();
        monitor.service_mmio(7, 0, &hw, || true);
        hw.complete(status, 3, 0);
        hw.reads.borrow_mut().clear();
        monitor.service_mmio(7, 1, &hw, || true);
        assert!(
            !hw.reads.borrow().contains(&pcode::DATA0),
            "error reply data consumed"
        );
        assert!(monitor.show("fan1_input", 1).is_empty());
        assert!(monitor
            .show("telemetry_status", 1)
            .starts_with("failed Status("));
    }
    let monitor = monitor(GtPlatform::Battlemage);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    hw.complete(0, 4, 0); // out-of-range fan count cannot expand whitelist
    monitor.service_mmio(7, 1, &hw, || true);
    monitor.service_mmio(7, 2, &hw, || true);
    hw.complete(0, 0, 97);
    monitor.service_mmio(7, 3, &hw, || true);
    assert!(monitor.show("temp2_crit", 3).is_empty());
    assert_eq!(monitor.show("temp3_crit", 3), "97000\n");
    monitor.service_mmio(7, SECOND, &hw, || true);
    assert!(!hw.reads.borrow().iter().any(|r| FAN.contains(r)));
    monitor.activate(8);
    monitor.service_mmio(8, 2 * SECOND, &hw, || true);
    hw.complete(0, 2, 0);
    let mut checks = 0;
    monitor.service_mmio(8, 2 * SECOND + 1, &hw, || {
        checks += 1;
        checks < 2 // status readable; DATA authority lost
    });
    assert_eq!(
        monitor.show("telemetry_status", 2 * SECOND + 1),
        "failed Access\n"
    );
    assert!(monitor.show("temp2_input", 2 * SECOND + 1).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_bmg_status_errors_invalid_counts_zero_limits_and_partial_loss
);

fn smoke_hwmon_known_access_loss_invalidates_cached_dg2_data_between_ticks() -> TestResult {
    let _admin = Admin::allow();
    let monitor = monitor(GtPlatform::Alchemist);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    hw.set(0x138140, 120);
    monitor.service_mmio(7, SECOND, &hw, || true);
    assert_eq!(monitor.show("fan1_input", SECOND), "3600\n");
    assert_eq!(monitor.show("temp2_input", SECOND), "65000\n");
    assert_eq!(monitor.show("power2_max", SECOND), "200000000\n");
    assert_eq!(monitor.show("energy2_input", SECOND), "1000000\n");
    monitor.power.store(b"100000000", SECOND).unwrap();
    hw.reads.borrow_mut().clear();
    let mut checks = 0;
    monitor.service_mmio(7, SECOND + 1, &hw, || {
        checks += 1;
        checks < 2 // new PL1 request observes loss while sensors are rate-limited
    });
    assert_eq!(*hw.reads.borrow(), [0x145938]);
    assert!(hw.pl1_writes().is_empty());
    assert_eq!(
        monitor.show("power2_max_status", SECOND + 1),
        "failed 1 Access\n"
    );
    for name in [
        "temp2_input",
        "temp3_input",
        "in1_input",
        "energy2_input",
        "fan1_input",
        "fan2_input",
        "power2_max",
        "power2_rated_max",
        "power2_max_default",
        "power2_max_min",
        "power2_max_max",
    ] {
        assert!(
            monitor.show(name, SECOND + 1).is_empty(),
            "cached {name} survived denial"
        );
    }
    {
        let state = monitor.state.lock();
        assert_eq!(state.sampled, Some(SECOND));
        assert_eq!(state.fan_sampled, Some(SECOND));
        assert!(state.energy_lost);
    }
    hw.reads.borrow_mut().clear();
    monitor.service_mmio(7, SECOND + 2, &hw, || true);
    assert!(hw.reads.borrow().is_empty(), "denial bypassed the 1 Hz cap");
    assert!(monitor.show("temp2_input", SECOND + 2).is_empty());
    monitor.service_mmio(7, 2 * SECOND + 1, &hw, || true);
    assert_eq!(
        monitor.show("power2_max_default", 2 * SECOND + 1),
        "200000000\n"
    );
    assert_eq!(monitor.show("temp2_input", 2 * SECOND + 1), "65000\n");
    assert!(
        monitor.show("fan1_input", 2 * SECOND + 1).is_empty(),
        "lost fan baseline resumed"
    );
    assert!(
        monitor.show("energy2_input", 2 * SECOND + 1).is_empty(),
        "lost energy series resumed"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_known_access_loss_invalidates_cached_dg2_data_between_ticks
);

fn smoke_hwmon_known_access_loss_invalidates_cached_bmg_fans_between_ticks() -> TestResult {
    let monitor = monitor(GtPlatform::Battlemage);
    let hw = Hardware::new();
    monitor.service_mmio(7, 0, &hw, || true);
    hw.complete(0, 2, 0);
    monitor.service_mmio(7, SECOND, &hw, || true); // fan count confirmed; baseline established
    hw.set(0x138140, 120);
    hw.set(0x138170, 160);
    monitor.service_mmio(7, 2 * SECOND, &hw, || true); // post thermal query, cache fan RPM
    assert_eq!(monitor.show("fan1_input", 2 * SECOND), "3600\n");
    assert_eq!(monitor.show("fan2_input", 2 * SECOND), "4800\n");
    assert_eq!(monitor.show("temp2_input", 2 * SECOND), "71000\n");
    hw.complete(0, 0x5f69_646e, 97);
    hw.reads.borrow_mut().clear();
    let mut checks = 0;
    monitor.service_mmio(7, 2 * SECOND + 1, &hw, || {
        checks += 1;
        checks < 2 // status succeeds, but reply DATA loses authority
    });
    assert_eq!(*hw.reads.borrow(), [pcode::MAILBOX]);
    assert_eq!(
        monitor.show("telemetry_status", 2 * SECOND + 1),
        "failed Access\n"
    );
    for name in [
        "temp2_input",
        "temp3_input",
        "fan1_input",
        "fan2_input",
        "temp2_crit",
        "temp3_crit",
    ] {
        assert!(
            monitor.show(name, 2 * SECOND + 1).is_empty(),
            "cached {name} survived denial"
        );
    }
    {
        let state = monitor.state.lock();
        assert_eq!(state.sampled, Some(2 * SECOND));
        assert_eq!(state.fan_sampled, Some(2 * SECOND));
    }
    hw.reads.borrow_mut().clear();
    monitor.service_mmio(7, 2 * SECOND + 2, &hw, || true);
    assert!(
        hw.reads.borrow().is_empty(),
        "failed transaction consumed a late reply"
    );
    assert!(monitor.show("temp2_input", 2 * SECOND + 2).is_empty());
    monitor.service_mmio(7, 3 * SECOND, &hw, || true);
    assert_eq!(monitor.show("temp2_input", 3 * SECOND), "71000\n");
    assert!(monitor.show("fan1_input", 3 * SECOND).is_empty());
    assert_eq!(
        monitor.show("telemetry_status", 3 * SECOND),
        "failed Access\n"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_known_access_loss_invalidates_cached_bmg_fans_between_ticks
);

fn smoke_hwmon_live_adapter_current_epoch_and_close_during_mailbox_post() -> TestResult {
    let monitor = monitor(GtPlatform::Battlemage);
    let hw = Hardware::new();
    let mut checks = 0;
    monitor.service_mmio(7, 0, &hw, || {
        checks += 1;
        if checks == 3 {
            monitor.close();
        }
        checks < 3
    });
    assert_eq!(*hw.writes.borrow(), [(pcode::DATA0, 0)]);
    assert_eq!(hw.get(pcode::MAILBOX), 0);
    assert_eq!(monitor.show("telemetry_status", 0), "unavailable\n");
    assert!(monitor.show("temp2_input", 0).is_empty());
    monitor.activate(8);
    hw.reads.borrow_mut().clear();
    monitor.service_mmio(7, SECOND, &hw, || panic!("old worker checked PCI"));
    assert!(hw.reads.borrow().is_empty());
    monitor.service_mmio(8, SECOND, &hw, || false);
    assert!(hw.reads.borrow().is_empty());
    assert_eq!(monitor.show("telemetry_status", SECOND), "failed Access\n");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_live_adapter_current_epoch_and_close_during_mailbox_post
);

fn smoke_hwmon_sysfs_dg2_power_store_is_admin_gated_queued_and_card_scoped() -> TestResult {
    let monitor = Monitor::register(989, GtPlatform::Alchemist, 0).unwrap();
    let class = class_register("hwmon");
    let node = class
        .child_names()
        .iter()
        .filter_map(|name| class.get_child(name))
        .find(|n| n.get_symlink("device") == Some("/sys/class/drm/card989/device".into()))
        .unwrap();
    assert!(node.attr_is_writable("power2_max"));
    assert!(!node.attr_is_writable("power2_rated_max"));
    let hw = Hardware::new();
    monitor.activate(7);
    monitor.service_mmio(7, narf_time::monotonic_ns(), &hw, || true);
    {
        let _deny = Admin::deny();
        assert_eq!(
            node.attr_store("power2_max", b"100000000"),
            Some(Err(FsError::OperationNotPermitted))
        );
    }
    let _admin = Admin::allow();
    assert_eq!(node.attr_store("power2_max", b"100000000"), Some(Ok(())));
    assert!(hw.pl1_writes().is_empty());
    assert_eq!(
        node.attr_show("power2_max_status").as_deref(),
        Some("queued 1\n")
    );
    monitor.close();
    assert_eq!(
        node.attr_store("power2_max", b"100000000"),
        Some(Err(FsError::NoDevice))
    );
    assert_eq!(node.attr_show("power2_max").as_deref(), Some(""));
    assert!(class.remove_child(node.name()));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_hwmon",
    smoke_hwmon_sysfs_dg2_power_store_is_admin_gated_queued_and_card_scoped
);
