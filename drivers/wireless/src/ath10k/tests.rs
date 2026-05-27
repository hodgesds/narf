//! ath10k smoke tests — co-located per project convention.
//!
//! Stage-0 set: pure-data PCI match table presence, HwRev decode,
//! chip-id-rev mask + per-chip register-offset tables. The
//! "real silicon" smoke (probe-bound device + CHIP_ID readback)
//! Skips cleanly when no ath10k part is bound — useful on the
//! QCA-equipped real-HW bring-up boxes, no-op on QEMU.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::hw::*;
use super::pci::{name_for, register_pci_driver};

// ── PCI match table ────────────────────────────────────────────────

fn smoke_ath10k_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    for &(vendor, device) in ALL_PCI_MATCHES {
        let matched = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: v,
                    device: d,
                } if v == vendor && d == device
            )
        });
        if !matched {
            return TestResult::Fail("ath10k PCI match table missing a (vendor, device) pair");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_pci_match_table);

fn smoke_ath10k_name_for_known_ids() -> TestResult {
    if name_for(ATHEROS_VENDOR, QCA988X_DEVICE_ID) != "ath10k-qca988x" {
        return TestResult::Fail("qca988x name mismatch");
    }
    if name_for(ATHEROS_VENDOR, QCA6174_DEVICE_ID) != "ath10k-qca6174" {
        return TestResult::Fail("qca6174 name mismatch");
    }
    if name_for(ATHEROS_VENDOR, QCA9377_DEVICE_ID) != "ath10k-qca9377" {
        return TestResult::Fail("qca9377 name mismatch");
    }
    if name_for(UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID) != "ath10k-qca988x-ubnt" {
        return TestResult::Fail("qca988x-ubnt name mismatch");
    }
    if name_for(0xDEAD, 0xBEEF) != "ath10k" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_name_for_known_ids);

// ── HwRev / chip-id ────────────────────────────────────────────────

fn smoke_ath10k_hw_rev_from_pci_id_coverage() -> TestResult {
    let expected = [
        (ATHEROS_VENDOR, QCA988X_DEVICE_ID, HwRev::Qca988x),
        (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID, HwRev::Qca988x),
        (ATHEROS_VENDOR, QCA6174_DEVICE_ID, HwRev::Qca6174),
        (ATHEROS_VENDOR, QCA6164_DEVICE_ID, HwRev::Qca6174),
        (ATHEROS_VENDOR, QCA99X0_DEVICE_ID, HwRev::Qca99x0),
        (ATHEROS_VENDOR, QCA9888_DEVICE_ID, HwRev::Qca9888),
        (ATHEROS_VENDOR, QCA9984_DEVICE_ID, HwRev::Qca9984),
        (ATHEROS_VENDOR, QCA9377_DEVICE_ID, HwRev::Qca9377),
        (ATHEROS_VENDOR, AR9462_DEVICE_ID, HwRev::Ar9462Legacy),
    ];
    for (v, d, e) in expected {
        match HwRev::from_pci_id(v, d) {
            Some(r) if r == e => {}
            other => {
                let _ = other;
                return TestResult::Fail("HwRev::from_pci_id mismatch");
            }
        }
    }
    if HwRev::from_pci_id(0xDEAD, 0xBEEF).is_some() {
        return TestResult::Fail("unknown PCI ID should be None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_hw_rev_from_pci_id_coverage);

fn smoke_ath10k_chip_id_rev_extraction() -> TestResult {
    // `(rev << 8) | misc bits`. Linux docs: rev = (raw >> 8) & 0xF.
    // Mock a CHIP_ID = 0x000_0A37 -> rev = 0xA.
    if chip_id_rev(0x0000_0A37) != 0xA {
        return TestResult::Fail("chip_id_rev mis-shifts");
    }
    // Hi bits outside the mask are ignored.
    if chip_id_rev(0xFFFF_FFFF) != 0xF {
        return TestResult::Fail("chip_id_rev didn't mask high bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_chip_id_rev_extraction);

fn smoke_ath10k_per_chip_chip_id_addr_distinct() -> TestResult {
    // QCA6174 uses 0xF0; the rest use 0xEC.
    if soc_chip_id_address(HwRev::Qca6174) != 0x0000_00f0 {
        return TestResult::Fail("QCA6174 chip_id_address wrong");
    }
    if soc_chip_id_address(HwRev::Qca988x) != 0x0000_00ec {
        return TestResult::Fail("QCA988X chip_id_address wrong");
    }
    if soc_chip_id_address(HwRev::Qca9984) != 0x0000_00ec {
        return TestResult::Fail("QCA9984 chip_id_address wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_per_chip_chip_id_addr_distinct
);

fn smoke_ath10k_fw_indicator_address_per_chip() -> TestResult {
    // QCA988X / 6174 / 9377 — FW_INDICATOR at SOC_PCIE + 0x40.
    if fw_indicator_address(HwRev::Qca988x) != SOC_PCIE_BASE_ADDRESS + 0x40 {
        return TestResult::Fail("QCA988X FW_INDICATOR offset wrong");
    }
    // QCA99X0 / 9888 / 9984 — at +0x50.
    if fw_indicator_address(HwRev::Qca99x0) != SOC_PCIE_BASE_ADDRESS + 0x50 {
        return TestResult::Fail("QCA99X0 FW_INDICATOR offset wrong");
    }
    if fw_indicator_address(HwRev::Qca9984) != SOC_PCIE_BASE_ADDRESS + 0x50 {
        return TestResult::Fail("QCA9984 FW_INDICATOR offset wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_fw_indicator_address_per_chip
);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────

fn smoke_ath10k_probe_bound_or_skip() -> TestResult {
    if !super::pci::is_probed() {
        return TestResult::Skip("ath10k: no QCA part bound (expected on QEMU)");
    }
    // If we did probe, CHIP_ID must be sane (not all-0 / all-F).
    let raw = match super::pci::with_controller(|d| d.chip_id_raw) {
        Some(v) => v,
        None => return TestResult::Skip("ath10k: probed flag set but no controller borrowable"),
    };
    if raw == 0 || raw == 0xFFFF_FFFF {
        return TestResult::Fail("ath10k: bound device reports nonsense CHIP_ID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_probe_bound_or_skip
);
