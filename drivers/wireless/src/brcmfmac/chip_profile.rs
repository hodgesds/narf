// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux brcmfmac PCIe chip profiles, transcribed from Linux 7.3-rc4 tables:
//! `chip.c::brcmf_chip_tcm_rambase` (RAM base per chip id/revision),
//! `chip.c::brcmf_chip_get_raminfo` (CR4 TCM banks vs CA7 SYS_MEM banks),
//! `pcie.c::brcmf_pcie_fwnames` (first chip id + `BIT(chiprev)` mask match,
//! as `firmware.c::brcmf_fw_alloc_request`), `pcie.c::brcmf_pcie_devid_table`
//! with its `drvdata` (firmware vendor + random-seed flag) and
//! `pcie.c::brcmf_pcie_read_otp` (the chips whose OTP Linux reads).
//!
//! These are chip facts only. They grant no board calibration, firmware
//! signature or radio authority: a board still needs an exact signed
//! selection (`provision`) or trusted platform registration.

/// `brcm_hw_ids.h` chip ids (the ChipCommon id, not the PCI device id).
pub const BRCM_CC_4350: u16 = 0x4350;
pub const BRCM_CC_4354: u16 = 0x4354;
pub const BRCM_CC_4355: u16 = 0x4355;
pub const BRCM_CC_4356: u16 = 0x4356;
pub const BRCM_CC_43567: u16 = 43567;
pub const BRCM_CC_43569: u16 = 43569;
pub const BRCM_CC_43570: u16 = 43570;
pub const BRCM_CC_4358: u16 = 0x4358;
pub const BRCM_CC_4359: u16 = 0x4359;
pub const BRCM_CC_43602: u16 = 43602;
pub const BRCM_CC_4364: u16 = 0x4364;
pub const BRCM_CC_4365: u16 = 0x4365;
pub const BRCM_CC_4366: u16 = 0x4366;
pub const BRCM_CC_43664: u16 = 43664;
pub const BRCM_CC_43666: u16 = 43666;
pub const BRCM_CC_43465: u16 = 43465;
pub const BRCM_CC_43525: u16 = 43525;
pub const BRCM_CC_4371: u16 = 0x4371;
pub const BRCM_CC_43752: u16 = 43752;
pub const BRCM_CC_4377: u16 = 0x4377;
pub const BRCM_CC_4378: u16 = 0x4378;
pub const BRCM_CC_4387: u16 = 0x4387;

/// `BCMA_CORE_INTERNAL_MEM` (SOCRAM) and `BCMA_CORE_SYS_MEM`.
pub const CORE_INTERNAL_MEM: u16 = 0x80e;
pub const CORE_SYS_MEM: u16 = 0x849;

/// `chip.c::BRCMF_CHIP_MAX_MEMSIZE`.
pub const MAX_MEMSIZE: u32 = 4 * 1024 * 1024;

/// `chip.c::brcmf_chip_tcm_rambase`, complete. `None` is Linux's
/// `INVALID_RAMBASE` ("unknown chip").
pub const fn tcm_rambase(chip: u16, chiprev: u8) -> Option<u32> {
    Some(match chip {
        0x4345 | 43454 => 0x198000,
        0x4335 | 0x4339 | BRCM_CC_4350 | BRCM_CC_4354 | BRCM_CC_4356 | BRCM_CC_43567
        | BRCM_CC_43569 | BRCM_CC_43570 | BRCM_CC_4358 | BRCM_CC_43602 | BRCM_CC_4371 => 0x180000,
        BRCM_CC_43465 | BRCM_CC_43525 | BRCM_CC_4365 | BRCM_CC_4366 | BRCM_CC_43664
        | BRCM_CC_43666 => 0x200000,
        BRCM_CC_4355 | BRCM_CC_4359 => {
            if chiprev < 9 {
                0x180000
            } else {
                0x160000
            }
        }
        BRCM_CC_4364 | 0x4373 => 0x160000,
        43751 | BRCM_CC_43752 | BRCM_CC_4377 => 0x170000,
        BRCM_CC_4378 => 0x352000,
        BRCM_CC_4387 => 0x740000,
        _ => return None,
    })
}

/// One `BRCMF_FW_ENTRY`: `brcm/<base>` plus Linux's `.bin`/`.txt` (and,
/// for `BRCMF_FW_CLM_DEF` bases, an optional `.clm_blob`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FwMapping {
    pub chip: u16,
    pub revmask: u32,
    pub base: &'static str,
    /// Declared with `BRCMF_FW_CLM_DEF` (optional external CLM blob).
    pub clm: bool,
}
const fn fw(chip: u16, revmask: u32, base: &'static str, clm: bool) -> FwMapping {
    FwMapping {
        chip,
        revmask,
        base,
        clm,
    }
}
/// `pcie.c::brcmf_pcie_fwnames`, in Linux order (first match wins).
pub const FIRMWARE: &[FwMapping] = &[
    fw(BRCM_CC_43602, 0xFFFFFFFF, "brcmfmac43602-pcie", false),
    fw(BRCM_CC_43465, 0xFFFFFFF0, "brcmfmac4366c-pcie", false),
    fw(BRCM_CC_4350, 0x000000FF, "brcmfmac4350c2-pcie", false),
    fw(BRCM_CC_4350, 0xFFFFFF00, "brcmfmac4350-pcie", false),
    fw(BRCM_CC_43525, 0xFFFFFFF0, "brcmfmac4365c-pcie", false),
    fw(BRCM_CC_4355, 0x000007FF, "brcmfmac4355-pcie", true),
    fw(BRCM_CC_4355, 0x00002000, "brcmfmac54591-pcie", true),
    fw(BRCM_CC_4355, 0xFFFFF800, "brcmfmac4355c1-pcie", true),
    fw(BRCM_CC_4356, 0xFFFFFFFF, "brcmfmac4356-pcie", true),
    fw(BRCM_CC_43567, 0xFFFFFFFF, "brcmfmac43570-pcie", true),
    fw(BRCM_CC_43569, 0xFFFFFFFF, "brcmfmac43570-pcie", true),
    fw(BRCM_CC_43570, 0xFFFFFFFF, "brcmfmac43570-pcie", true),
    fw(BRCM_CC_4358, 0xFFFFFFFF, "brcmfmac4358-pcie", false),
    fw(BRCM_CC_4359, 0x000001FF, "brcmfmac4359-pcie", false),
    fw(BRCM_CC_4359, 0xFFFFFE00, "brcmfmac4359c-pcie", false),
    fw(BRCM_CC_4364, 0x0000000F, "brcmfmac4364b2-pcie", true),
    fw(BRCM_CC_4364, 0xFFFFFFF0, "brcmfmac4364b3-pcie", true),
    fw(BRCM_CC_4365, 0x0000000F, "brcmfmac4365b-pcie", false),
    fw(BRCM_CC_4365, 0xFFFFFFF0, "brcmfmac4365c-pcie", false),
    fw(BRCM_CC_4366, 0x0000000F, "brcmfmac4366b-pcie", false),
    fw(BRCM_CC_4366, 0xFFFFFFF0, "brcmfmac4366c-pcie", false),
    fw(BRCM_CC_43664, 0xFFFFFFF0, "brcmfmac4366c-pcie", false),
    fw(BRCM_CC_43666, 0xFFFFFFF0, "brcmfmac4366c-pcie", false),
    fw(BRCM_CC_4371, 0xFFFFFFFF, "brcmfmac4371-pcie", false),
    fw(BRCM_CC_43752, 0xFFFFFFFF, "brcmfmac43752-pcie", true),
    fw(BRCM_CC_4377, 0xFFFFFFFF, "brcmfmac4377b3-pcie", true),
    fw(BRCM_CC_4378, 0x0000000F, "brcmfmac4378b1-pcie", true),
    fw(BRCM_CC_4378, 0xFFFFFFE0, "brcmfmac4378b3-pcie", true),
    fw(BRCM_CC_4387, 0xFFFFFFFF, "brcmfmac4387c2-pcie", true),
];

/// `firmware.c::brcmf_fw_alloc_request` table walk: a revision at or above
/// 32 is invalid; otherwise the first row with this chip id whose mask has
/// `BIT(chiprev)` names the firmware. `None` is Linux's "Unknown chip".
pub fn firmware(chip: u16, chiprev: u8) -> Option<&'static FwMapping> {
    if chiprev >= 32 {
        return None;
    }
    FIRMWARE
        .iter()
        .find(|row| row.chip == chip && row.revmask & (1 << chiprev) != 0)
}

/// `enum brcmf_fwvendor` as selected by the PCI table's `driver_data`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FwVendor {
    Cyw,
    Bca,
    Wcc,
}
/// One `brcmf_pcie_devid_table` row (all Broadcom vendor 0x14e4, class
/// `PCI_CLASS_NETWORK_OTHER << 8` under mask 0xffff00).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciMatch {
    pub device: u16,
    /// `BRCMF_PCIE_DEVICE_SUB` subsystem vendor/device, else any.
    pub subsystem: Option<(u16, u16)>,
    pub vendor: FwVendor,
    /// `BRCMF_DRVDATA_WCC_SEED`: a random-seed footer precedes NVRAM.
    pub seed: bool,
}
const fn dev(device: u16, vendor: FwVendor, seed: bool) -> PciMatch {
    PciMatch {
        device,
        subsystem: None,
        vendor,
        seed,
    }
}
const fn sub(device: u16, subsystem: (u16, u16), vendor: FwVendor) -> PciMatch {
    PciMatch {
        device,
        subsystem: Some(subsystem),
        vendor,
        seed: false,
    }
}
use FwVendor::{Bca, Cyw, Wcc};
/// `pcie.c::brcmf_pcie_devid_table`, in Linux order (first match wins).
pub const PCI_DEVICES: &[PciMatch] = &[
    dev(0x43a3, Wcc, false), // 4350
    sub(0x4355, (0x14e4, 0x4355), Wcc),
    dev(0x4354, Wcc, false), // 4354 raw
    dev(0x43dc, Wcc, true),  // 4355
    dev(0x43ec, Wcc, false), // 4356
    dev(0x43d3, Wcc, false), // 43567
    dev(0x43d9, Wcc, false), // 43570
    dev(0xaa31, Wcc, false), // 43570 raw
    dev(0x43e9, Wcc, false), // 4358
    dev(0x43ef, Wcc, false), // 4359
    dev(0x43ba, Wcc, false), // 43602
    dev(0x43bb, Wcc, false), // 43602 2G
    dev(0x43bc, Wcc, false), // 43602 5G
    dev(43602, Wcc, false),  // 43602 raw
    dev(0x4464, Wcc, true),  // 4364
    dev(0x43ca, Bca, false), // 4365
    dev(0x43cb, Bca, false), // 4365 2G
    dev(0x43cc, Bca, false), // 4365 5G
    sub(0x4365, (0x14e4, 0x4365), Bca),
    dev(0x43c3, Bca, false), // 4366
    dev(0x43c4, Bca, false), // 4366 2G
    dev(0x43c5, Bca, false), // 4366 5G
    dev(0x440d, Wcc, false), // 4371
    dev(0x4415, Cyw, false), // 43596
    dev(0x4488, Wcc, true),  // 4377
    dev(0x4425, Wcc, true),  // 4378
    dev(0x4433, Wcc, true),  // 4387
    dev(0x449d, Wcc, true),  // 43752
    dev(0x4417, Cyw, false), // CY 54591
];

/// `pci_match_id(brcmf_pcie_devid_table, pdev)` for a full PCI identity.
pub fn pci_match(id: &narf_bus::DeviceId) -> Option<PciMatch> {
    if id.class & 0xffff00 != 0x028000 {
        return None;
    }
    pci_row(id.vendor, id.device, (id.subsystem_vendor, id.subsystem_id))
}
/// The first table row for vendor/device/subsystem, without the class.
pub fn pci_row(vendor: u16, device: u16, subsystem: (u16, u16)) -> Option<PciMatch> {
    if vendor != 0x14e4 {
        return None;
    }
    PCI_DEVICES
        .iter()
        .copied()
        .find(|row| row.device == device && row.subsystem.is_none_or(|s| s == subsystem))
}
/// A PCI row whose vendor path NARF implements: WCC/BCA without the seed.
pub fn implemented(row: PciMatch) -> bool {
    !row.seed && row.vendor != FwVendor::Cyw
}

/// `pcie.c::brcmf_pcie_read_otp` reads OTP (Apple board/module selection)
/// for these chips only; every other chip returns "OTP not supported".
pub const fn linux_reads_otp(chip: u16) -> bool {
    matches!(
        chip,
        BRCM_CC_4355 | BRCM_CC_4364 | BRCM_CC_4377 | BRCM_CC_4378 | BRCM_CC_4387
    )
}

/// Firmware CPU, `chip.c::brcmf_chip_set_passive`/`_set_active` dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cpu {
    /// ARM CR4: RAM from the CR4 TCM bank registers.
    Cr4,
    /// ARM CA7: RAM from the SYS_MEM core's SOCRAM-layout banks.
    Ca7,
}

/// A chip NARF boots through the retained PCIe transport: one with a Linux
/// RAM base and firmware row, a CR4 or CA7 CPU, no Linux OTP read and no
/// random-seed footer for any of its PCI ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub chip: u16,
    pub cpu: Cpu,
    pub rambase: u32,
    pub firmware: &'static FwMapping,
}
/// Chips covered here. 43602 is the retained original profile. Left out:
/// 4354 (no Linux PCIe firmware row), 4355/4364/4377/4378/4387 (Linux OTP
/// board selection and, on their PCI ids, the random-seed footer), 43752
/// (random seed), CYW-vendor 43596/54591, and chips with no PCIe row.
const COVERED: &[(u16, Cpu)] = &[
    (BRCM_CC_43602, Cpu::Cr4),
    (BRCM_CC_4350, Cpu::Cr4),
    (BRCM_CC_4356, Cpu::Cr4),
    (BRCM_CC_43567, Cpu::Cr4),
    (BRCM_CC_43569, Cpu::Cr4),
    (BRCM_CC_43570, Cpu::Cr4),
    (BRCM_CC_4358, Cpu::Cr4),
    (BRCM_CC_4359, Cpu::Cr4),
    (BRCM_CC_4371, Cpu::Cr4),
    (BRCM_CC_4365, Cpu::Ca7),
    (BRCM_CC_4366, Cpu::Ca7),
    (BRCM_CC_43664, Cpu::Ca7),
    (BRCM_CC_43666, Cpu::Ca7),
    (BRCM_CC_43465, Cpu::Ca7),
    (BRCM_CC_43525, Cpu::Ca7),
];
/// The CPU of a covered chip, independent of its revision.
pub fn covered(chip: u16) -> Option<Cpu> {
    COVERED.iter().find(|row| row.0 == chip).map(|row| row.1)
}
pub fn profile(chip: u16, chiprev: u8) -> Option<Profile> {
    let cpu = covered(chip)?;
    if linux_reads_otp(chip) {
        return None;
    }
    Some(Profile {
        chip,
        cpu,
        rambase: tcm_rambase(chip, chiprev)?,
        firmware: firmware(chip, chiprev)?,
    })
}
/// The discovered chip/revision plus the actual PCI identity form one
/// admitted profile only when Linux would bind this PCI id with a vendor
/// whose path NARF implements (WCC/BCA, no random seed).
pub fn admit(chip: u16, chiprev: u8, pci: &narf_bus::DeviceId) -> Option<(Profile, FwVendor)> {
    let matched = pci_match(pci)?;
    if !implemented(matched) {
        return None;
    }
    Some((profile(chip, chiprev)?, matched.vendor))
}

/// Linux firmware/NVRAM registry names for a selected base: the plain
/// `brcm/<base>.<ext>` or the board-type `brcm/<base>.<board>.<ext>` that
/// `brcmf_fw_alloc_request` composes when a board type is known.
/// `extension` has no leading dot (`"bin"`, `"txt"`).
pub fn linux_asset_name(base: &str, key: &str, extension: &str) -> bool {
    let Some(rest) = key
        .strip_prefix("brcm/")
        .and_then(|k| k.strip_prefix(base))
        .and_then(|k| k.strip_suffix(extension))
    else {
        return false;
    };
    rest == "."
        || rest.len() > 2
            && rest.starts_with('.')
            && rest.ends_with('.')
            && !rest[1..rest.len() - 1].contains('/')
}

#[cfg(feature = "kernel-test")]
#[path = "chip_profile_tests.rs"]
mod tests;
