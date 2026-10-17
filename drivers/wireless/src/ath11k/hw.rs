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
// Exactly Linux's `ath11k_pci_id_table` (`pci.c`). QCA2066 and
// QCA6698AQ have no PCI id of their own: they enumerate as WCN6855
// (`17cb:1103`) and are told apart by `TCSR_SOC_HW_SUB_VER`.
// `17cb:1107` (WCN7850) and `17cb:1109` (QCN9274) belong to ath12k,
// which shares none of ath11k's HAL/DP layout.
pub const ATH11K_DEV_QCA6390: u16 = 0x1101;
pub const ATH11K_DEV_WCN6855: u16 = 0x1103;
pub const ATH11K_DEV_QCN9074: u16 = 0x1104;

/// Hardware revision tag — drives per-chip register/MHI/DP config.
/// The PCI-attached subset of Linux `enum ath11k_hw_rev`, plus
/// `Unknown` for a stepping `ath11k_pci_probe` rejects.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwRev {
    Qca6390Hw20,
    Qcn9074Hw10,
    Wcn6855Hw20,
    Wcn6855Hw21,
    Qca2066Hw21,
    Qca6698aqHw21,
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
            HwRev::Qca6698aqHw21 => "QCA6698AQ HW2.1",
            HwRev::Unknown => "ath11k unknown",
        }
    }

    /// Firmware directory under `ath11k/` — `hw_params.fw.dir` in
    /// Linux `core.c::ath11k_hw_params`. `None` for `Unknown`.
    pub fn fw_dir(self) -> Option<&'static str> {
        Some(match self {
            HwRev::Qca6390Hw20 => "QCA6390/hw2.0",
            HwRev::Qcn9074Hw10 => "QCN9074/hw1.0",
            HwRev::Wcn6855Hw20 => "WCN6855/hw2.0",
            HwRev::Wcn6855Hw21 => "WCN6855/hw2.1",
            HwRev::Qca2066Hw21 => "QCA2066/hw2.1",
            HwRev::Qca6698aqHw21 => "QCA6698AQ/hw2.1",
            HwRev::Unknown => return None,
        })
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
/// `None` if not an ath11k part.
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
            display_name: "WCN6855",
            default_hw_rev: HwRev::Wcn6855Hw20,
        },
        ATH11K_DEV_QCN9074 => ChipInfo {
            vid,
            did,
            display_name: "QCN9074",
            default_hw_rev: HwRev::Qcn9074Hw10,
        },
        _ => return None,
    })
}

/// Bare PCI ID table used to register matches.
pub const ALL_DEV_IDS: &[u16] = &[ATH11K_DEV_QCA6390, ATH11K_DEV_WCN6855, ATH11K_DEV_QCN9074];

/// Per-PCI-ID match name. The PCI driver-match registry is keyed
/// by `name`, so each entry needs its own — collapsing them all to
/// `"ath11k"` would silently de-dup down to one entry.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        ATH11K_DEV_QCA6390 => "ath11k-qca6390",
        ATH11K_DEV_WCN6855 => "ath11k-wcn6855",
        ATH11K_DEV_QCN9074 => "ath11k-qcn9074",
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

/// Decode the TCSR major/minor pair (plus, for WCN6855 HW2.1-class
/// parts, the `TCSR_SOC_HW_SUB_VER` word) into a `HwRev`. Mirrors
/// the per-PCI-ID switch in Linux `pci.c::ath11k_pci_probe`.
/// `sub_version` is consulted only for WCN6855 minor 0x10/0x11;
/// steppings Linux rejects (`unsupported_*_soc`) map to `Unknown`.
pub fn refine_hw_rev(did: u16, major: u32, minor: u32, sub_version: u32) -> HwRev {
    match did {
        ATH11K_DEV_QCA6390 => match major {
            2 => HwRev::Qca6390Hw20,
            _ => HwRev::Unknown,
        },
        ATH11K_DEV_QCN9074 => HwRev::Qcn9074Hw10,
        ATH11K_DEV_WCN6855 => match (major, minor) {
            (2, 0x00 | 0x01) => HwRev::Wcn6855Hw20,
            (2, 0x10 | 0x11) => match sub_version {
                0x1019_A0E1 | 0x1019_B0E1 | 0x1019_C0E1 | 0x1019_D0E1 => HwRev::Qca2066Hw21,
                0x001E_60E1 => HwRev::Qca6698aqHw21,
                _ => HwRev::Wcn6855Hw21,
            },
            _ => HwRev::Unknown,
        },
        _ => HwRev::Unknown,
    }
}

/// True when `refine_hw_rev` needs the `TCSR_SOC_HW_SUB_VER` word.
pub fn needs_sub_version(did: u16, major: u32, minor: u32) -> bool {
    did == ATH11K_DEV_WCN6855 && major == 2 && matches!(minor, 0x10 | 0x11)
}
