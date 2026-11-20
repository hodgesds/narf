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
/// A PCI row whose vendor path NARF implements: WCC/BCA, with or without
/// the random-seed footer (`pcie.c::brcmf_pcie_download_fw_nvram`).
pub fn implemented(row: PciMatch) -> bool {
    row.vendor != FwVendor::Cyw
}

/// `pcie.c::BRCMF_RANDOM_SEED_MAGIC` / `BRCMF_RANDOM_SEED_LENGTH`.
pub const RANDOM_SEED_MAGIC: u32 = 0xfeedc0de;
pub const RANDOM_SEED_LENGTH: usize = 0x100;
/// `struct brcmf_random_seed_footer` (`length`, `magic`, little endian).
pub const fn random_seed_footer() -> [u8; 8] {
    let length = (RANDOM_SEED_LENGTH as u32).to_le_bytes();
    let magic = RANDOM_SEED_MAGIC.to_le_bytes();
    [
        length[0], length[1], length[2], length[3], magic[0], magic[1], magic[2], magic[3],
    ]
}

/// `pcie.c::brcmf_pcie_read_otp` reads OTP (Apple board/module selection)
/// for these chips only; every other chip returns "OTP not supported".
pub const fn linux_reads_otp(chip: u16) -> bool {
    otp_source(chip).is_some()
}

/// `BCMA_CORE_GCI`.
pub const CORE_GCI: u16 = 0x840;
/// ChipCommon `sromcontrol` (`chipcregs` 0x190) and its OTP bits
/// (`BCMA_CC_SROM_CONTROL_OTPSEL` / `_OTP_PRESENT`).
pub const CC_SROM_CONTROL: u32 = 0x190;
pub const CC_SROM_CONTROL_OTPSEL: u32 = 0x10;
pub const CC_SROM_CONTROL_OTP_PRESENT: u32 = 0x20;

/// Where `brcmf_pcie_read_otp` reads a chip's OTP shadow: the core, the
/// byte offset from that core's base and the number of 16-bit words.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OtpSource {
    pub core: u16,
    pub offset: u32,
    pub words: u32,
}
/// `brcmf_pcie_read_otp`'s per-chip switch, complete.
pub const fn otp_source(chip: u16) -> Option<OtpSource> {
    let (core, offset, words) = match chip {
        BRCM_CC_4355 => (super::chip::CORE_CHIPCOMMON, 0x8c0, 0xb2),
        BRCM_CC_4364 => (super::chip::CORE_CHIPCOMMON, 0x8c0, 0x1a0),
        BRCM_CC_4377 | BRCM_CC_4378 => (CORE_GCI, 0x1120, 0x170),
        BRCM_CC_4387 => (CORE_GCI, 0x113c, 0x170),
        _ => return None,
    };
    Some(OtpSource {
        core,
        offset,
        words,
    })
}

/// `struct brcmf_otp_params` (`BRCMF_OTP_MAX_PARAM_LEN` 16 with the NUL).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OtpParams {
    pub module: alloc::string::String,
    pub vendor: alloc::string::String,
    pub version: alloc::string::String,
}
const OTP_MAX_PARAM_LEN: usize = 16;
const OTP_SYS_VENDOR: u8 = 0x15;
const OTP_VENDOR_HDR: u32 = 0x0000_0008;

/// `pcie.c::brcmf_pcie_parse_otp`: walk `type, length, data` records until
/// a zero type or a record past the end; the result is that of the last
/// `BRCMF_OTP_SYS_VENDOR` record (none at all is `-EINVAL`). Parameters
/// accumulate across records as Linux's `devinfo->otp` does. `None` is the
/// Linux error that fails `brcmf_pcie_probe`.
pub fn parse_otp(otp: &[u8]) -> Option<OtpParams> {
    let mut params = OtpParams::default();
    let mut ok = false;
    let mut p = 0usize;
    while p + 1 < otp.len() {
        let (kind, length) = (otp[p], usize::from(otp[p + 1]));
        if kind == 0 || p + 2 + length > otp.len() {
            break;
        }
        if kind == OTP_SYS_VENDOR {
            ok = parse_otp_sys_vendor(&mut params, &otp[p + 2..p + 2 + length]);
        }
        p += 2 + length;
    }
    ok.then_some(params)
}

/// `pcie.c::brcmf_pcie_parse_otp_sys_vendor`: a 4-byte header 0x8, the
/// chip-params string, then the board-params string of space-separated
/// `tag=value` pairs; `M` module, `V` vendor and `m` version (each at most
/// 15 bytes) are kept and must all be non-empty afterwards.
fn parse_otp_sys_vendor(params: &mut OtpParams, data: &[u8]) -> bool {
    let size = data.len();
    if size < 6 || u32::from_le_bytes(data[..4].try_into().unwrap()) != OTP_VENDOR_HDR {
        return false;
    }
    let strnlen = |from: usize| {
        data[from..]
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(size - from)
    };
    let mut idx = 4 + strnlen(4) + 1;
    if idx >= size {
        return false;
    }
    let board_start = idx;
    idx += strnlen(idx);
    if idx >= size {
        return false;
    }
    let board = &data[board_start..idx];
    // skip_spaces() skips isspace(); strchrnul() stops at ' ' only.
    let space = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    let skip = |mut at: usize| {
        while at < board.len() && space(board[at]) {
            at += 1;
        }
        at
    };
    let mut at = skip(0);
    while at < board.len() {
        let tag = board[at];
        if board.get(at + 1) != Some(&b'=') {
            return false;
        }
        let value = at + 2;
        let end = board[value..]
            .iter()
            .position(|b| *b == b' ')
            .map_or(board.len(), |n| value + n);
        if end - value > OTP_MAX_PARAM_LEN - 1 {
            return false;
        }
        let text = || alloc::string::String::from_utf8_lossy(&board[value..end]).into_owned();
        match tag {
            b'M' => params.module = text(),
            b'V' => params.vendor = text(),
            b'm' => params.version = text(),
            _ => {}
        }
        at = skip(end);
    }
    !params.module.is_empty() && !params.vendor.is_empty() && !params.version.is_empty()
}

/// `pcie.c::brcmf_pcie_prepare_fw_request`'s Apple selection (board type,
/// antenna SKU and valid OTP): `board_types[0..=5]` in Linux order.
pub fn apple_board_types(board: &str, otp: &OtpParams, sku: &str) -> [alloc::string::String; 6] {
    let (m, v, r) = (&otp.module, &otp.vendor, &otp.version);
    [
        alloc::format!("{board}-{m}-{v}-{r}-{sku}"),
        alloc::format!("{board}-{m}-{v}-{r}"),
        alloc::format!("{board}-{m}-{v}"),
        alloc::format!("{board}-{m}"),
        alloc::format!("{board}-{sku}"),
        alloc::string::String::from(board),
    ]
}
/// The board type inside a Linux registry key `brcm/<base>.<board>.<ext>`.
pub fn asset_board<'a>(base: &str, key: &'a str, extension: &str) -> Option<&'a str> {
    if !linux_asset_name(base, key, extension) {
        return None;
    }
    let rest = &key["brcm/".len() + base.len()..key.len() - extension.len()];
    (rest.len() > 2).then(|| &rest[1..rest.len() - 1])
}

/// Firmware CPU, `chip.c::brcmf_chip_set_passive`/`_set_active` dispatch.
/// A profile without a fixed CPU takes Linux's dispatch on the discovered
/// ARM core (CR4 first, then CA7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cpu {
    /// ARM CR4: RAM from the CR4 TCM bank registers.
    Cr4,
    /// ARM CA7: RAM from the SYS_MEM core's SOCRAM-layout banks.
    Ca7,
}

/// A chip NARF boots through the retained PCIe transport: one with a Linux
/// RAM base and firmware row and a CR4 or CA7 CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub chip: u16,
    /// `None`: no table fact; Linux's discovered-ARM dispatch decides.
    pub cpu: Option<Cpu>,
    pub rambase: u32,
    pub firmware: &'static FwMapping,
}
/// Chips covered here. 43602 is the retained original profile. Left out:
/// 4354 (no Linux PCIe firmware row), CYW-vendor 43596/54591, and chips
/// with no PCIe row. BCM43752 and the OTP chips 4355/4364/4377/4378/4387
/// have no CPU table fact: Linux discovers their ARM. The OTP chips need
/// an OTP-bound signed selection (`provision`) before they are admitted.
const COVERED: &[(u16, Option<Cpu>)] = &[
    (BRCM_CC_43602, Some(Cpu::Cr4)),
    (BRCM_CC_4350, Some(Cpu::Cr4)),
    (BRCM_CC_4356, Some(Cpu::Cr4)),
    (BRCM_CC_43567, Some(Cpu::Cr4)),
    (BRCM_CC_43569, Some(Cpu::Cr4)),
    (BRCM_CC_43570, Some(Cpu::Cr4)),
    (BRCM_CC_4358, Some(Cpu::Cr4)),
    (BRCM_CC_4359, Some(Cpu::Cr4)),
    (BRCM_CC_4371, Some(Cpu::Cr4)),
    (BRCM_CC_4365, Some(Cpu::Ca7)),
    (BRCM_CC_4366, Some(Cpu::Ca7)),
    (BRCM_CC_43664, Some(Cpu::Ca7)),
    (BRCM_CC_43666, Some(Cpu::Ca7)),
    (BRCM_CC_43465, Some(Cpu::Ca7)),
    (BRCM_CC_43525, Some(Cpu::Ca7)),
    (BRCM_CC_43752, None),
    (BRCM_CC_4355, None),
    (BRCM_CC_4364, None),
    (BRCM_CC_4377, None),
    (BRCM_CC_4378, None),
    (BRCM_CC_4387, None),
];
/// The CPU rule of a covered chip, independent of its revision.
pub fn covered(chip: u16) -> Option<Option<Cpu>> {
    COVERED.iter().find(|row| row.0 == chip).map(|row| row.1)
}
pub fn profile(chip: u16, chiprev: u8) -> Option<Profile> {
    let cpu = covered(chip)?;
    Some(Profile {
        chip,
        cpu,
        rambase: tcm_rambase(chip, chiprev)?,
        firmware: firmware(chip, chiprev)?,
    })
}
/// The discovered chip/revision plus the actual PCI identity form one
/// admitted profile only when Linux would bind this PCI id with a vendor
/// whose path NARF implements (WCC/BCA). The PCI row's `seed` is separate:
/// Linux keys the footer on the PCI id, not on the chip.
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
