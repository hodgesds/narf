// SPDX-License-Identifier: GPL-2.0-or-later
//! PCI probe for SDHCI controllers: class 0x080500, BAR0 MMIO map.
//!
//! Reference:
//! - PCI Local Bus Specification §6.2.1 — class code encoding.
//! - SD Host Controller Simplified Spec v4.20 §1.3 — PCI class assignment.
//! - Linux `drivers/mmc/host/sdhci-pci-core.c` (GPL-2.0-or-later, adapted).

#![allow(dead_code)]

use super::regs::{PCI_CLASS_SDHCI, PCI_SDHCI_BAR};

/// PCI base class for "generic system peripherals".
pub const PCI_BASE_CLASS_SYSTEM: u8 = 0x08;
/// PCI sub-class for SD host controllers.
pub const PCI_SUB_CLASS_SDHCI: u8   = 0x05;
/// Programming interface 0x00 (standard SDHCI; 0x01 is vendor-specific).
pub const PCI_PROG_IF_SDHCI: u8     = 0x00;

/// Build the 24-bit class code from base/sub/prog_if.
#[inline]
pub const fn pci_class(base: u8, sub: u8, prog_if: u8) -> u32 {
    ((base as u32) << 16) | ((sub as u32) << 8) | (prog_if as u32)
}

/// Test whether a raw 24-bit PCI class code identifies an SDHCI controller.
#[inline]
pub fn is_sdhci_class(class24: u32) -> bool {
    // Programming interface byte may be 0x00 (standard) or 0x01 (vendor);
    // match on base + sub only.
    (class24 >> 8) == (PCI_CLASS_SDHCI >> 8)
}

/// Return the BAR index that SDHCI controllers expose their MMIO registers on.
#[inline]
pub const fn sdhci_bar_index() -> u8 {
    PCI_SDHCI_BAR
}

/// Probe result from matching a PCI device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// Device is an SDHCI controller; contains the 64-bit BAR0 physical address.
    Match { bar0_phys: u64 },
    /// Device class does not match SDHCI.
    NoMatch,
    /// BAR0 is not memory-mapped (unusual; SDHCI requires MMIO).
    BadBar,
}

/// Given a PCI device's 24-bit class code and its BAR0 base address
/// (as decoded from BAR registers by the PCI bus driver), decide if
/// this is an SDHCI host and return the MMIO base.
///
/// The BAR0 value passed in must already be masked to a physical
/// address by the caller (low bits stripped, prefetchable/type bits
/// already decoded).
pub fn probe_device(class24: u32, bar0_phys: u64) -> ProbeResult {
    if !is_sdhci_class(class24) {
        return ProbeResult::NoMatch;
    }
    if bar0_phys == 0 {
        return ProbeResult::BadBar;
    }
    ProbeResult::Match { bar0_phys }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pci_class_sdhci_match() -> TestResult {
        let class = pci_class(PCI_BASE_CLASS_SYSTEM, PCI_SUB_CLASS_SDHCI, PCI_PROG_IF_SDHCI);
        if class != PCI_CLASS_SDHCI {
            return TestResult::Fail("pci_class helper mismatch against constant");
        }
        if !is_sdhci_class(class) {
            return TestResult::Fail("is_sdhci_class rejected known-good class");
        }
        // Vendor-specific prog-if (0x01) should also match.
        let vendor_if = pci_class(PCI_BASE_CLASS_SYSTEM, PCI_SUB_CLASS_SDHCI, 0x01);
        if !is_sdhci_class(vendor_if) {
            return TestResult::Fail("is_sdhci_class rejected prog_if=0x01");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/probe", smoke_pci_class_sdhci_match);

    fn smoke_pci_class_no_match() -> TestResult {
        // NVMe = 0x010802; USB = 0x0C0330 — neither is SDHCI.
        for class in [0x0108_02u32, 0x0C03_30u32, 0x0000_00u32] {
            if is_sdhci_class(class) {
                return TestResult::Fail("non-SDHCI class matched");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/probe", smoke_pci_class_no_match);

    fn smoke_probe_device_happy_path() -> TestResult {
        let class = PCI_CLASS_SDHCI;
        match probe_device(class, 0xFE00_0000) {
            ProbeResult::Match { bar0_phys: 0xFE00_0000 } => {},
            _ => return TestResult::Fail("expected Match with correct bar0"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/sdhci/probe", smoke_probe_device_happy_path);
}
