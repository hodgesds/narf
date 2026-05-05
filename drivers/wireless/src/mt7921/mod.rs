//! MediaTek MT7921 Wi-Fi 6 (802.11ax) PCIe — **PCI-ID match stub**.
//!
//! Spec: `drivers/wireless/specification/mt7921.md`.
//!
//! Scope: vendor/device match only. No bring-up logic. The full
//! MAC register map and MCU command-set ABI are not publicly
//! documented; the driver therefore stops at the PCI match table.

#![allow(dead_code)]

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

pub const MTK_VENDOR: u16 = 0x14C3;
pub const MTK_DEV_MT7921: u16 = 0x7961;

pub fn probe(
    device: BusDevice,
    _cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("mt7921"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });
    Ok(())
}

pub fn register() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "mt7921",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: MTK_VENDOR,
            device: MTK_DEV_MT7921,
        },
        probe,
    });
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_mt7921_pci_match_table() -> TestResult {
        register();
        let regs = narf_bus::driver_match::registered();
        for entry in regs.iter() {
            if let narf_bus::MatchKind::VendorDevice { vendor, device } = entry.kind {
                if vendor == MTK_VENDOR && device == MTK_DEV_MT7921 {
                    return TestResult::Pass;
                }
            }
        }
        TestResult::Fail("MT7921 not found in PCI match table")
    }
    kernel_test_in!("drivers/wireless/mt7921", smoke_mt7921_pci_match_table);
}
