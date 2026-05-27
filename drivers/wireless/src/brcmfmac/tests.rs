//! `brcmfmac` smoke tests — co-located per project convention.
//!
//! Stage-0 covers PCI match table + per-id name lookup + firmware
//! filename ladder presence + the live-silicon Skip path. Subsequent
//! stages append their own smokes here (common-ring SPSC cursor,
//! msgbuf encode/decode round-trips).
//!
//! All Stage-0 smokes are pure-data: they Pass on QEMU instead of
//! Skip. The probe-bound live-silicon smoke Skips cleanly when no
//! Broadcom PCIe Wi-Fi is on the bus.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::pcie::{
    firmware_filename, name_for, register_pci_driver, ALL_DEV_IDS, BRCM_PCIE_43602_DEVICE_ID,
    BRCM_PCIE_4365_DEVICE_ID, BRCM_PCIE_4366_DEVICE_ID, BRCM_PCIE_4371_DEVICE_ID,
    BRCM_PCIE_4378_DEVICE_ID, BROADCOM_VENDOR,
};

// ── PCI match table ────────────────────────────────────────────────

fn smoke_brcmfmac_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    for &did in ALL_DEV_IDS {
        let matched = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: BROADCOM_VENDOR,
                    device,
                } if device == did
            )
        });
        if !matched {
            return TestResult::Fail("brcmfmac PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_pci_match_table);

fn smoke_brcmfmac_name_for_known_ids() -> TestResult {
    if name_for(BRCM_PCIE_43602_DEVICE_ID) != "brcmfmac-43602" {
        return TestResult::Fail("43602 name mismatch");
    }
    if name_for(BRCM_PCIE_4366_DEVICE_ID) != "brcmfmac-4366" {
        return TestResult::Fail("4366 name mismatch");
    }
    if name_for(BRCM_PCIE_4371_DEVICE_ID) != "brcmfmac-4371" {
        return TestResult::Fail("4371 name mismatch");
    }
    if name_for(BRCM_PCIE_4378_DEVICE_ID) != "brcmfmac-4378" {
        return TestResult::Fail("4378 name mismatch");
    }
    if name_for(0xFFFF) != "brcmfmac" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/brcmfmac", smoke_brcmfmac_name_for_known_ids);

fn smoke_brcmfmac_firmware_filename_lookup() -> TestResult {
    // Every device id with a registered per-chip name also gets a
    // firmware blob name — paths follow the linux-firmware tree's
    // `/firmware/brcm/brcmfmacXXXX-pcie.bin` convention.
    if !firmware_filename(BRCM_PCIE_43602_DEVICE_ID)
        .unwrap_or("")
        .starts_with("/firmware/brcm/")
    {
        return TestResult::Fail("43602 firmware filename missing or wrong prefix");
    }
    if !firmware_filename(BRCM_PCIE_4365_DEVICE_ID)
        .unwrap_or("")
        .starts_with("/firmware/brcm/")
    {
        return TestResult::Fail("4365 firmware filename missing or wrong prefix");
    }
    if firmware_filename(0xFFFF).is_some() {
        return TestResult::Fail("unknown device id should have no firmware name");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_firmware_filename_lookup
);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────

fn smoke_brcmfmac_probe_bound_or_skip() -> TestResult {
    if !super::pcie::is_probed() {
        return TestResult::Skip("brcmfmac: no BCM43xxx PCIe bound (expected on QEMU)");
    }
    let did = match super::pcie::with_controller(|d| d.device_id) {
        Some(d) => d,
        None => return TestResult::Skip("brcmfmac: probed flag set but no controller borrowable"),
    };
    if !ALL_DEV_IDS.contains(&did) {
        return TestResult::Fail("brcmfmac: bound device id not in match table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac",
    smoke_brcmfmac_probe_bound_or_skip
);
