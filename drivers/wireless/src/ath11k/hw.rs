//! Per-chip hardware-revision tables.
//!
//! Mirrors `enum ath11k_hw_rev` in Linux's `core.h` plus the
//! per-chip register-base tables. Each ath11k part exposes a TCSR
//! "SoC hardware version" register at `0x224` (relative to BAR0
//! base) whose major/minor fields name a specific stepping; the
//! `hw_rev` field downstream code consumes is derived from
//! `(device_id, major, minor)`.
//!
//! Linux references (BSD-3 / dual GPL — citation permitted):
//! - `drivers/net/wireless/ath/ath11k/pci.c::ath11k_pci_probe`
//!   (PCI ID → hw_rev decision tree, v6.6 ~L985..L1080).
//! - `drivers/net/wireless/ath/ath11k/core.h::enum ath11k_hw_rev`.
//! - `drivers/net/wireless/ath/ath11k/pci.h` (TCSR register
//!   address + version mask constants).

#![allow(dead_code)]

/// Qualcomm PCI vendor id used by all ath11k parts.
pub const QCOM_VENDOR: u16 = 0x17cb;

// ── PCI device IDs ────────────────────────────────────────────────
// QCA6390, QCN9074, WCN6855 are the canonical Linux entries; QCA2066
// shares the WCN6855 PCI ID with a different sub-version. WCN7850
// and QCN6122/QCN9224 are listed here because they appear in NARF's
// real-hardware target table even though Linux's main `pci.c` table
// is shorter.
pub const ATH11K_DEV_QCA6390: u16 = 0x1101;
pub const ATH11K_DEV_WCN6855: u16 = 0x1103;
pub const ATH11K_DEV_QCN9074: u16 = 0x1104;
pub const ATH11K_DEV_QCA2066: u16 = 0x1105;
pub const ATH11K_DEV_WCN7850: u16 = 0x1107;
pub const ATH11K_DEV_QCN6122: u16 = 0x1109;

/// Hardware revision tag — drives per-chip register/MHI/DP config.
/// Cribbed verbatim from Linux `enum ath11k_hw_rev`, plus a stable
/// `Unknown` so probe can report devices we haven't tabulated yet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwRev {
    Qca6390Hw20,
    Qcn9074Hw10,
    Wcn6855Hw20,
    Wcn6855Hw21,
    Qca2066Hw21,
    Wcn7850Hw20,
    Qcn6122Hw10,
    Unknown,
}

impl HwRev {
    pub fn name(self) -> &'static str {
        match self {
            HwRev::Qca6390Hw20 => "QCA6390 HW2.0",
            HwRev::Qcn9074Hw10 => "QCN9074 HW1.0",
            HwRev::Wcn6855Hw20 => "WCN6855 HW2.0",
            HwRev::Wcn6855Hw21 => "WCN6855 HW2.1",
            HwRev::Qca2066Hw21 => "QCA2066 HW2.1",
            HwRev::Wcn7850Hw20 => "WCN7850 HW2.0",
            HwRev::Qcn6122Hw10 => "QCN6122 HW1.0",
            HwRev::Unknown => "ath11k unknown",
        }
    }
}

/// Per-PCI-ID descriptor — display name + default `HwRev` (used
/// when the TCSR major/minor read isn't yet wired). Linux derives
/// the same defaults in its probe path.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub display_name: &'static str,
    pub default_hw_rev: HwRev,
}

/// Match a PCI vendor/device pair to a ChipInfo entry. Returns
/// `None` if not an ath11k part. The TCSR-derived HwRev refinement
/// (e.g. WCN6855 1.0 vs 2.0 vs QCA2066) lands with Stage-1.
pub fn chip_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != QCOM_VENDOR {
        return None;
    }
    Some(match did {
        ATH11K_DEV_QCA6390 => ChipInfo {
            vid,
            did,
            display_name: "QCA6390",
            default_hw_rev: HwRev::Qca6390Hw20,
        },
        ATH11K_DEV_WCN6855 => ChipInfo {
            vid,
            did,
            display_name: "WCN6855/QCA2066",
            default_hw_rev: HwRev::Wcn6855Hw20,
        },
        ATH11K_DEV_QCN9074 => ChipInfo {
            vid,
            did,
            display_name: "QCN9074",
            default_hw_rev: HwRev::Qcn9074Hw10,
        },
        ATH11K_DEV_QCA2066 => ChipInfo {
            vid,
            did,
            display_name: "QCA2066",
            default_hw_rev: HwRev::Qca2066Hw21,
        },
        ATH11K_DEV_WCN7850 => ChipInfo {
            vid,
            did,
            display_name: "WCN7850",
            default_hw_rev: HwRev::Wcn7850Hw20,
        },
        ATH11K_DEV_QCN6122 => ChipInfo {
            vid,
            did,
            display_name: "QCN6122/QCN9224",
            default_hw_rev: HwRev::Qcn6122Hw10,
        },
        _ => return None,
    })
}

/// Bare PCI ID table used to register matches.
pub const ALL_DEV_IDS: &[u16] = &[
    ATH11K_DEV_QCA6390,
    ATH11K_DEV_WCN6855,
    ATH11K_DEV_QCN9074,
    ATH11K_DEV_QCA2066,
    ATH11K_DEV_WCN7850,
    ATH11K_DEV_QCN6122,
];

/// Per-PCI-ID match name. The PCI driver-match registry is keyed
/// by `name`, so each entry needs its own — collapsing them all to
/// `"ath11k"` would silently de-dup down to one entry.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        ATH11K_DEV_QCA6390 => "ath11k-qca6390",
        ATH11K_DEV_WCN6855 => "ath11k-wcn6855",
        ATH11K_DEV_QCN9074 => "ath11k-qcn9074",
        ATH11K_DEV_QCA2066 => "ath11k-qca2066",
        ATH11K_DEV_WCN7850 => "ath11k-wcn7850",
        ATH11K_DEV_QCN6122 => "ath11k-qcn6122",
        _ => "ath11k",
    }
}

// ── BAR0 register-window constants ─────────────────────────────────
//
// ath11k uses a 128-byte sliding window at BAR0 + 0x80000 to address
// the 4 MiB chip register file. The window-select register at
// BAR0 + 0x310c selects which 512 KiB chunk of the chip's register
// file is visible. Constants below are copied verbatim from Linux
// `pcic.h`.

pub const ATH11K_PCI_WINDOW_ENABLE_BIT: u32 = 0x4000_0000;
pub const ATH11K_PCI_WINDOW_REG_ADDRESS: u32 = 0x310c;
/// Bits[24:19] in a chip-register offset select which 512 KiB chunk
/// of the chip's register file is exposed via the window.
pub const ATH11K_PCI_WINDOW_VALUE_MASK: u32 = (0x3F) << 19;
/// Window itself sits at BAR0+0x80000.
pub const ATH11K_PCI_WINDOW_START: u32 = 0x80000;
pub const ATH11K_PCI_WINDOW_RANGE_MASK: u32 = (1u32 << 19) - 1;

/// TCSR register — exposes SoC hardware version major/minor fields.
pub const TCSR_SOC_HW_VERSION: u32 = 0x0224;
pub const TCSR_SOC_HW_VERSION_MAJOR_MASK: u32 = 0x0000_0F00;
pub const TCSR_SOC_HW_VERSION_MAJOR_SHIFT: u32 = 8;
pub const TCSR_SOC_HW_VERSION_MINOR_MASK: u32 = 0x0000_00FF;
pub const TCSR_SOC_HW_SUB_VER: u32 = 0x1910010;

/// Decode the TCSR major-minor pair into a refined `HwRev`. Mirrors
/// the per-PCI-ID switch in `ath11k_pci_probe` — Linux infers
/// HW2.0 vs HW2.1 etc. from the major/minor pair.
pub fn refine_hw_rev(did: u16, major: u32, minor: u32) -> HwRev {
    match did {
        ATH11K_DEV_QCA6390 => HwRev::Qca6390Hw20,
        ATH11K_DEV_QCN9074 => HwRev::Qcn9074Hw10,
        ATH11K_DEV_WCN6855 => match (major, minor) {
            (2, 0) => HwRev::Wcn6855Hw20,
            (2, 1) => HwRev::Wcn6855Hw21,
            (2, m) if m >= 0x10 => HwRev::Qca2066Hw21,
            _ => HwRev::Wcn6855Hw20,
        },
        ATH11K_DEV_QCA2066 => HwRev::Qca2066Hw21,
        ATH11K_DEV_WCN7850 => HwRev::Wcn7850Hw20,
        ATH11K_DEV_QCN6122 => HwRev::Qcn6122Hw10,
        _ => HwRev::Unknown,
    }
}
