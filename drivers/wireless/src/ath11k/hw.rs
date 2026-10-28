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

use super::ce::{CeAttr, HOST_CE_CONFIG_QCA6390, HOST_CE_CONFIG_QCN9074};

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

    /// `hw_params.spectral` from Linux `core.c::ath11k_hw_params`. Every
    /// PCI WLAN profile NARF admits (QCA6390, WCN6855, QCA2066, QCA6698AQ)
    /// has an all-zero block; only QCN9074 among the PCI parts (and the
    /// IPQ8074/IPQ6018/IPQ5018 AHB SoCs NARF does not admit) defines an FFT
    /// report format.
    pub const fn spectral(self) -> SpectralParams {
        match self {
            HwRev::Qcn9074Hw10 => SpectralParams {
                fft_sz: 2,
                fft_pad_sz: 0,
                summary_pad_sz: 16,
                fft_hdr_len: 24,
                max_fft_bins: 1024,
                fragment_160mhz: false,
            },
            _ => SpectralParams {
                fft_sz: 0,
                fft_pad_sz: 0,
                summary_pad_sz: 0,
                fft_hdr_len: 0,
                max_fft_bins: 0,
                fragment_160mhz: false,
            },
        }
    }
}

/// `struct ath11k_hw_params::spectral`: the direct-buffer FFT report
/// geometry `spectral.c` parses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpectralParams {
    pub fft_sz: u32,
    pub fft_pad_sz: u32,
    pub summary_pad_sz: u32,
    pub fft_hdr_len: u32,
    pub max_fft_bins: u32,
    pub fragment_160mhz: bool,
}

/// The two gates at the top of Linux `ath11k_spectral_init`: the target
/// must advertise `WMI_TLV_SERVICE_FREQINFO_IN_METADATA` and the hardware
/// profile must define an FFT sample size. When either is absent Linux
/// returns 0 without allocating the spectral DBRing, registering the relay
/// channel or creating the debugfs controls, so no spectral WMI
/// (`WMI_VDEV_SPECTRAL_SCAN_{CONFIGURE,ENABLE}_CMDID`) is ever sent.
pub const fn spectral_supported(rev: HwRev, freqinfo_in_metadata: bool) -> bool {
    freqinfo_in_metadata && rev.spectral().fft_sz != 0
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

// ── Per-hw_rev parameters ─────────────────────────────────────────
//
// The subset of Linux `struct ath11k_hw_params` (`core.c`) and
// `ath11k_msi_config[]` (`pcic.c`) the driver consumes so far.
// Fields are added as later bring-up phases need them.

/// One MSI consumer — Linux `struct ath11k_msi_user`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsiUser {
    pub name: &'static str,
    pub num_vectors: u32,
    pub base_vector: u32,
}

/// Linux `struct ath11k_msi_config`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MsiConfig {
    pub total_vectors: u32,
    pub users: &'static [MsiUser],
}

impl MsiConfig {
    /// Linux `ath11k_pcic_get_user_msi_assignment`: `(num_vectors,
    /// user_base_data, base_vector)` for `name`, where
    /// `user_base_data = base_vector + ep_base_data`.
    pub fn user_assignment(&self, name: &str, ep_base_data: u32) -> Option<(u32, u32, u32)> {
        self.users
            .iter()
            .find(|u| u.name == name)
            .map(|u| (u.num_vectors, u.base_vector + ep_base_data, u.base_vector))
    }
}

/// 32 vectors: QCA6390 / WCN6855 / QCA2066 / QCA6698AQ.
pub const MSI_CONFIG_QCA6390: MsiConfig = MsiConfig {
    total_vectors: 32,
    users: &[
        MsiUser {
            name: "MHI",
            num_vectors: 3,
            base_vector: 0,
        },
        MsiUser {
            name: "CE",
            num_vectors: 10,
            base_vector: 3,
        },
        MsiUser {
            name: "WAKE",
            num_vectors: 1,
            base_vector: 13,
        },
        MsiUser {
            name: "DP",
            num_vectors: 18,
            base_vector: 14,
        },
    ],
};

/// 16 vectors: QCN9074.
pub const MSI_CONFIG_QCN9074: MsiConfig = MsiConfig {
    total_vectors: 16,
    users: &[
        MsiUser {
            name: "MHI",
            num_vectors: 3,
            base_vector: 0,
        },
        MsiUser {
            name: "CE",
            num_vectors: 5,
            base_vector: 3,
        },
        MsiUser {
            name: "DP",
            num_vectors: 8,
            base_vector: 8,
        },
    ],
};

/// Fallback when the multi-vector allocation fails — Linux
/// `msi_config_one_msi`: every user shares vector 0.
pub const MSI_CONFIG_ONE: MsiConfig = MsiConfig {
    total_vectors: 1,
    users: &[
        MsiUser {
            name: "MHI",
            num_vectors: 3,
            base_vector: 0,
        },
        MsiUser {
            name: "CE",
            num_vectors: 1,
            base_vector: 0,
        },
        MsiUser {
            name: "WAKE",
            num_vectors: 1,
            base_vector: 0,
        },
        MsiUser {
            name: "DP",
            num_vectors: 1,
            base_vector: 0,
        },
    ],
};

/// PCIe PHY registers `ath11k_pci_fix_l1ss` programs — Linux
/// `ath11k_hw_regs::pcie_qserdes_sysclk_en_sel` /
/// `pcie_pcs_osc_dtct_config_base`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct L1ssRegs {
    pub qserdes_sysclk_en_sel: u32,
    pub pcs_osc_dtct_config_base: u32,
}

/// Linux `struct ath11k_hw_params`, PCI-relevant subset.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HwParams {
    pub hw_rev: HwRev,
    pub fw_dir: &'static str,
    pub msi: &'static MsiConfig,
    /// `Some` iff Linux sets `fix_l1ss = true` for this part.
    pub fix_l1ss: Option<L1ssRegs>,
    pub static_window_map: bool,
    /// `hw_params.regs` — the HAL SRNG register map. `None` for parts
    /// whose map is not ported (QCN9074).
    pub regs: Option<&'static HalRegs>,
    /// `hw_params.host_ce_config`; its length is `hw_params.ce_count`.
    pub host_ce_config: &'static [CeAttr],
    /// `hw_params.supports_shadow_regs`.
    pub supports_shadow_regs: bool,
    /// `hw_params.credit_flow`: HTC credit flow, and CE TX completion
    /// frees the buffer instead of calling `send_cb`.
    pub credit_flow: bool,
    /// `hw_params.ring_mask` (DP interrupt groups).
    pub ring_mask: &'static RingMask,
}

impl HwParams {
    /// `hw_params.ce_count`.
    pub fn ce_count(&self) -> usize {
        self.host_ce_config.len()
    }
}

impl HwRev {
    /// Linux `ath11k_hw_params[]` entry for this revision.
    pub fn params(self) -> Option<HwParams> {
        let fw_dir = self.fw_dir()?;
        // (regs, host_ce_config, supports_shadow_regs, credit_flow)
        let (regs, host_ce_config, supports_shadow_regs, credit_flow): (
            Option<&'static HalRegs>,
            &'static [CeAttr],
            bool,
            bool,
        ) = match self {
            HwRev::Qca6390Hw20 => (Some(&QCA6390_REGS), &HOST_CE_CONFIG_QCA6390, true, true),
            HwRev::Qcn9074Hw10 => (None, &HOST_CE_CONFIG_QCN9074, false, false),
            HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
                (Some(&WCN6855_REGS), &HOST_CE_CONFIG_QCA6390, true, true)
            }
            HwRev::Unknown => return None,
        };
        let (msi, fix_l1ss, static_window_map) = match self {
            // qca6390_regs
            HwRev::Qca6390Hw20 => (
                &MSI_CONFIG_QCA6390,
                Some(L1ssRegs {
                    qserdes_sysclk_en_sel: 0x01e0_c0ac,
                    pcs_osc_dtct_config_base: 0x01e0_c628,
                }),
                false,
            ),
            // qcn9074_regs
            HwRev::Qcn9074Hw10 => (
                &MSI_CONFIG_QCN9074,
                Some(L1ssRegs {
                    qserdes_sysclk_en_sel: 0x01e0_e0a8,
                    pcs_osc_dtct_config_base: 0x01e0_f45c,
                }),
                true,
            ),
            HwRev::Wcn6855Hw20 | HwRev::Wcn6855Hw21 | HwRev::Qca2066Hw21 | HwRev::Qca6698aqHw21 => {
                (&MSI_CONFIG_QCA6390, None, false)
            }
            HwRev::Unknown => return None,
        };
        Some(HwParams {
            hw_rev: self,
            fw_dir,
            msi,
            fix_l1ss,
            static_window_map,
            regs,
            host_ce_config,
            supports_shadow_regs,
            credit_flow,
            ring_mask: &RING_MASK_QCA6390,
        })
    }
}

// ── HAL register map (`struct ath11k_hw_regs`, hw.h / hw.c) ────────
//
// The fields `hal.c` / `ce.c` read. Values verbatim from Linux
// `qca6390_regs` and `wcn6855_regs` (hw.c); the PCIe L1SS pair lives in
// [`L1ssRegs`].

/// Linux `struct ath11k_hw_regs` (HAL subset).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HalRegs {
    // SW2TCL(x) R0 ring configuration
    pub hal_tcl1_ring_base_lsb: u32,
    pub hal_tcl1_ring_base_msb: u32,
    pub hal_tcl1_ring_id: u32,
    pub hal_tcl1_ring_misc: u32,
    pub hal_tcl1_ring_tp_addr_lsb: u32,
    pub hal_tcl1_ring_tp_addr_msb: u32,
    pub hal_tcl1_ring_consumer_int_setup_ix0: u32,
    pub hal_tcl1_ring_consumer_int_setup_ix1: u32,
    pub hal_tcl1_ring_msi1_base_lsb: u32,
    pub hal_tcl1_ring_msi1_base_msb: u32,
    pub hal_tcl1_ring_msi1_data: u32,
    pub hal_tcl2_ring_base_lsb: u32,
    pub hal_tcl_ring_base_lsb: u32,
    // TCL STATUS ring
    pub hal_tcl_status_ring_base_lsb: u32,
    // REO2SW(x) R0 ring configuration
    pub hal_reo1_ring_base_lsb: u32,
    pub hal_reo1_ring_base_msb: u32,
    pub hal_reo1_ring_id: u32,
    pub hal_reo1_ring_misc: u32,
    pub hal_reo1_ring_hp_addr_lsb: u32,
    pub hal_reo1_ring_hp_addr_msb: u32,
    pub hal_reo1_ring_producer_int_setup: u32,
    pub hal_reo1_ring_msi1_base_lsb: u32,
    pub hal_reo1_ring_msi1_base_msb: u32,
    pub hal_reo1_ring_msi1_data: u32,
    pub hal_reo2_ring_base_lsb: u32,
    pub hal_reo1_aging_thresh_ix_0: u32,
    pub hal_reo1_aging_thresh_ix_1: u32,
    pub hal_reo1_aging_thresh_ix_2: u32,
    pub hal_reo1_aging_thresh_ix_3: u32,
    // REO2SW(x) R2 ring pointers
    pub hal_reo1_ring_hp: u32,
    pub hal_reo1_ring_tp: u32,
    pub hal_reo2_ring_hp: u32,
    // REO2TCL
    pub hal_reo_tcl_ring_base_lsb: u32,
    pub hal_reo_tcl_ring_hp: u32,
    // REO CMD
    pub hal_reo_cmd_ring_base_lsb: u32,
    pub hal_reo_cmd_ring_hp: u32,
    // REO status
    pub hal_reo_status_ring_base_lsb: u32,
    pub hal_reo_status_hp: u32,
    // SW2REO
    pub hal_sw2reo_ring_base_lsb: u32,
    pub hal_sw2reo_ring_hp: u32,
    // WCSS relative (CE register blocks)
    pub hal_seq_wcss_umac_ce0_src_reg: u32,
    pub hal_seq_wcss_umac_ce0_dst_reg: u32,
    pub hal_seq_wcss_umac_ce1_src_reg: u32,
    pub hal_seq_wcss_umac_ce1_dst_reg: u32,
    // WBM idle
    pub hal_wbm_idle_link_ring_base_lsb: u32,
    pub hal_wbm_idle_link_ring_misc: u32,
    // SW2WBM release
    pub hal_wbm_release_ring_base_lsb: u32,
    // WBM2SW release
    pub hal_wbm0_release_ring_base_lsb: u32,
    pub hal_wbm1_release_ring_base_lsb: u32,
    // Shadow register area
    pub hal_shadow_base_addr: u32,
    // REO misc control
    pub hal_reo1_misc_ctl: u32,
}

/// Linux `qca6390_regs`.
pub const QCA6390_REGS: HalRegs = HalRegs {
    hal_tcl1_ring_base_lsb: 0x0000_0684,
    hal_tcl1_ring_base_msb: 0x0000_0688,
    hal_tcl1_ring_id: 0x0000_068c,
    hal_tcl1_ring_misc: 0x0000_0694,
    hal_tcl1_ring_tp_addr_lsb: 0x0000_06a0,
    hal_tcl1_ring_tp_addr_msb: 0x0000_06a4,
    hal_tcl1_ring_consumer_int_setup_ix0: 0x0000_06b4,
    hal_tcl1_ring_consumer_int_setup_ix1: 0x0000_06b8,
    hal_tcl1_ring_msi1_base_lsb: 0x0000_06cc,
    hal_tcl1_ring_msi1_base_msb: 0x0000_06d0,
    hal_tcl1_ring_msi1_data: 0x0000_06d4,
    hal_tcl2_ring_base_lsb: 0x0000_06dc,
    hal_tcl_ring_base_lsb: 0x0000_078c,
    hal_tcl_status_ring_base_lsb: 0x0000_0894,
    hal_reo1_ring_base_lsb: 0x0000_0244,
    hal_reo1_ring_base_msb: 0x0000_0248,
    hal_reo1_ring_id: 0x0000_024c,
    hal_reo1_ring_misc: 0x0000_0254,
    hal_reo1_ring_hp_addr_lsb: 0x0000_0258,
    hal_reo1_ring_hp_addr_msb: 0x0000_025c,
    hal_reo1_ring_producer_int_setup: 0x0000_0268,
    hal_reo1_ring_msi1_base_lsb: 0x0000_028c,
    hal_reo1_ring_msi1_base_msb: 0x0000_0290,
    hal_reo1_ring_msi1_data: 0x0000_0294,
    hal_reo2_ring_base_lsb: 0x0000_029c,
    hal_reo1_aging_thresh_ix_0: 0x0000_050c,
    hal_reo1_aging_thresh_ix_1: 0x0000_0510,
    hal_reo1_aging_thresh_ix_2: 0x0000_0514,
    hal_reo1_aging_thresh_ix_3: 0x0000_0518,
    hal_reo1_ring_hp: 0x0000_3030,
    hal_reo1_ring_tp: 0x0000_3034,
    hal_reo2_ring_hp: 0x0000_3038,
    hal_reo_tcl_ring_base_lsb: 0x0000_03a4,
    hal_reo_tcl_ring_hp: 0x0000_3050,
    hal_reo_cmd_ring_base_lsb: 0x0000_0194,
    hal_reo_cmd_ring_hp: 0x0000_3020,
    hal_reo_status_ring_base_lsb: 0x0000_04ac,
    hal_reo_status_hp: 0x0000_3068,
    hal_sw2reo_ring_base_lsb: 0x0000_01ec,
    hal_sw2reo_ring_hp: 0x0000_3028,
    hal_seq_wcss_umac_ce0_src_reg: 0x00a0_0000,
    hal_seq_wcss_umac_ce0_dst_reg: 0x00a0_1000,
    hal_seq_wcss_umac_ce1_src_reg: 0x00a0_2000,
    hal_seq_wcss_umac_ce1_dst_reg: 0x00a0_3000,
    hal_wbm_idle_link_ring_base_lsb: 0x0000_0860,
    hal_wbm_idle_link_ring_misc: 0x0000_0870,
    hal_wbm_release_ring_base_lsb: 0x0000_01d8,
    hal_wbm0_release_ring_base_lsb: 0x0000_0910,
    hal_wbm1_release_ring_base_lsb: 0x0000_0968,
    hal_shadow_base_addr: 0x0000_08fc,
    hal_reo1_misc_ctl: 0x0,
};

/// Linux `wcn6855_regs` (WCN6855 HW2.0 / HW2.1, QCA2066, QCA6698AQ).
pub const WCN6855_REGS: HalRegs = HalRegs {
    hal_tcl1_ring_base_lsb: 0x0000_0690,
    hal_tcl1_ring_base_msb: 0x0000_0694,
    hal_tcl1_ring_id: 0x0000_0698,
    hal_tcl1_ring_misc: 0x0000_06a0,
    hal_tcl1_ring_tp_addr_lsb: 0x0000_06ac,
    hal_tcl1_ring_tp_addr_msb: 0x0000_06b0,
    hal_tcl1_ring_consumer_int_setup_ix0: 0x0000_06c0,
    hal_tcl1_ring_consumer_int_setup_ix1: 0x0000_06c4,
    hal_tcl1_ring_msi1_base_lsb: 0x0000_06d8,
    hal_tcl1_ring_msi1_base_msb: 0x0000_06dc,
    hal_tcl1_ring_msi1_data: 0x0000_06e0,
    hal_tcl2_ring_base_lsb: 0x0000_06e8,
    hal_tcl_ring_base_lsb: 0x0000_0798,
    hal_tcl_status_ring_base_lsb: 0x0000_08a0,
    hal_reo1_ring_base_lsb: 0x0000_0244,
    hal_reo1_ring_base_msb: 0x0000_0248,
    hal_reo1_ring_id: 0x0000_024c,
    hal_reo1_ring_misc: 0x0000_0254,
    hal_reo1_ring_hp_addr_lsb: 0x0000_0258,
    hal_reo1_ring_hp_addr_msb: 0x0000_025c,
    hal_reo1_ring_producer_int_setup: 0x0000_0268,
    hal_reo1_ring_msi1_base_lsb: 0x0000_028c,
    hal_reo1_ring_msi1_base_msb: 0x0000_0290,
    hal_reo1_ring_msi1_data: 0x0000_0294,
    hal_reo2_ring_base_lsb: 0x0000_029c,
    hal_reo1_aging_thresh_ix_0: 0x0000_05bc,
    hal_reo1_aging_thresh_ix_1: 0x0000_05c0,
    hal_reo1_aging_thresh_ix_2: 0x0000_05c4,
    hal_reo1_aging_thresh_ix_3: 0x0000_05c8,
    hal_reo1_ring_hp: 0x0000_3030,
    hal_reo1_ring_tp: 0x0000_3034,
    hal_reo2_ring_hp: 0x0000_3038,
    hal_reo_tcl_ring_base_lsb: 0x0000_0454,
    hal_reo_tcl_ring_hp: 0x0000_3060,
    hal_reo_cmd_ring_base_lsb: 0x0000_0194,
    hal_reo_cmd_ring_hp: 0x0000_3020,
    hal_reo_status_ring_base_lsb: 0x0000_055c,
    hal_reo_status_hp: 0x0000_3078,
    hal_sw2reo_ring_base_lsb: 0x0000_01ec,
    hal_sw2reo_ring_hp: 0x0000_3028,
    hal_seq_wcss_umac_ce0_src_reg: 0x01b8_0000,
    hal_seq_wcss_umac_ce0_dst_reg: 0x01b8_1000,
    hal_seq_wcss_umac_ce1_src_reg: 0x01b8_2000,
    hal_seq_wcss_umac_ce1_dst_reg: 0x01b8_3000,
    hal_wbm_idle_link_ring_base_lsb: 0x0000_0870,
    hal_wbm_idle_link_ring_misc: 0x0000_0880,
    hal_wbm_release_ring_base_lsb: 0x0000_01e8,
    hal_wbm0_release_ring_base_lsb: 0x0000_0920,
    hal_wbm1_release_ring_base_lsb: 0x0000_0978,
    hal_shadow_base_addr: 0x0000_08fc,
    hal_reo1_misc_ctl: 0x0000_0630,
};

// AHB SoC maps (`ipq8074_regs` also serves IPQ6018; `ipq5018_regs` CE
// offsets are relative to the remapped `HAL_IPQ5018_CE_WFSS_REG_BASE`
// window, as Linux computes them). Generated verbatim from Linux hw.c;
// fields Linux leaves unset are 0.
/// Linux `ipq8074_regs` (hw.c).
pub const IPQ8074_REGS: HalRegs = HalRegs {
    hal_tcl1_ring_base_lsb: 0x0000_0510,
    hal_tcl1_ring_base_msb: 0x0000_0514,
    hal_tcl1_ring_id: 0x0000_0518,
    hal_tcl1_ring_misc: 0x0000_0520,
    hal_tcl1_ring_tp_addr_lsb: 0x0000_052c,
    hal_tcl1_ring_tp_addr_msb: 0x0000_0530,
    hal_tcl1_ring_consumer_int_setup_ix0: 0x0000_0540,
    hal_tcl1_ring_consumer_int_setup_ix1: 0x0000_0544,
    hal_tcl1_ring_msi1_base_lsb: 0x0000_0558,
    hal_tcl1_ring_msi1_base_msb: 0x0000_055c,
    hal_tcl1_ring_msi1_data: 0x0000_0560,
    hal_tcl2_ring_base_lsb: 0x0000_0568,
    hal_tcl_ring_base_lsb: 0x0000_0618,
    hal_tcl_status_ring_base_lsb: 0x0000_0720,
    hal_reo1_ring_base_lsb: 0x0000_029c,
    hal_reo1_ring_base_msb: 0x0000_02a0,
    hal_reo1_ring_id: 0x0000_02a4,
    hal_reo1_ring_misc: 0x0000_02ac,
    hal_reo1_ring_hp_addr_lsb: 0x0000_02b0,
    hal_reo1_ring_hp_addr_msb: 0x0000_02b4,
    hal_reo1_ring_producer_int_setup: 0x0000_02c0,
    hal_reo1_ring_msi1_base_lsb: 0x0000_02e4,
    hal_reo1_ring_msi1_base_msb: 0x0000_02e8,
    hal_reo1_ring_msi1_data: 0x0000_02ec,
    hal_reo2_ring_base_lsb: 0x0000_02f4,
    hal_reo1_aging_thresh_ix_0: 0x0000_0564,
    hal_reo1_aging_thresh_ix_1: 0x0000_0568,
    hal_reo1_aging_thresh_ix_2: 0x0000_056c,
    hal_reo1_aging_thresh_ix_3: 0x0000_0570,
    hal_reo1_ring_hp: 0x0000_3038,
    hal_reo1_ring_tp: 0x0000_303c,
    hal_reo2_ring_hp: 0x0000_3040,
    hal_reo_tcl_ring_base_lsb: 0x0000_03fc,
    hal_reo_tcl_ring_hp: 0x0000_3058,
    hal_reo_cmd_ring_base_lsb: 0x0000_0194,
    hal_reo_cmd_ring_hp: 0x0000_3020,
    hal_reo_status_ring_base_lsb: 0x0000_0504,
    hal_reo_status_hp: 0x0000_3070,
    hal_sw2reo_ring_base_lsb: 0x0000_01ec,
    hal_sw2reo_ring_hp: 0x0000_3028,
    hal_seq_wcss_umac_ce0_src_reg: 0x00a0_0000,
    hal_seq_wcss_umac_ce0_dst_reg: 0x00a0_1000,
    hal_seq_wcss_umac_ce1_src_reg: 0x00a0_2000,
    hal_seq_wcss_umac_ce1_dst_reg: 0x00a0_3000,
    hal_wbm_idle_link_ring_base_lsb: 0x0000_0860,
    hal_wbm_idle_link_ring_misc: 0x0000_0870,
    hal_wbm_release_ring_base_lsb: 0x0000_01d8,
    hal_wbm0_release_ring_base_lsb: 0x0000_0910,
    hal_wbm1_release_ring_base_lsb: 0x0000_0968,
    hal_shadow_base_addr: 0x0000_0000,
    hal_reo1_misc_ctl: 0x0000_0000,
};
/// Linux `ipq5018_regs` (hw.c).
pub const IPQ5018_REGS: HalRegs = HalRegs {
    hal_tcl1_ring_base_lsb: 0x0000_0694,
    hal_tcl1_ring_base_msb: 0x0000_0698,
    hal_tcl1_ring_id: 0x0000_069c,
    hal_tcl1_ring_misc: 0x0000_06a4,
    hal_tcl1_ring_tp_addr_lsb: 0x0000_06b0,
    hal_tcl1_ring_tp_addr_msb: 0x0000_06b4,
    hal_tcl1_ring_consumer_int_setup_ix0: 0x0000_06c4,
    hal_tcl1_ring_consumer_int_setup_ix1: 0x0000_06c8,
    hal_tcl1_ring_msi1_base_lsb: 0x0000_06dc,
    hal_tcl1_ring_msi1_base_msb: 0x0000_06e0,
    hal_tcl1_ring_msi1_data: 0x0000_06e4,
    hal_tcl2_ring_base_lsb: 0x0000_06ec,
    hal_tcl_ring_base_lsb: 0x0000_079c,
    hal_tcl_status_ring_base_lsb: 0x0000_08a4,
    hal_reo1_ring_base_lsb: 0x0000_01ec,
    hal_reo1_ring_base_msb: 0x0000_01f0,
    hal_reo1_ring_id: 0x0000_01f4,
    hal_reo1_ring_misc: 0x0000_01fc,
    hal_reo1_ring_hp_addr_lsb: 0x0000_0200,
    hal_reo1_ring_hp_addr_msb: 0x0000_0204,
    hal_reo1_ring_producer_int_setup: 0x0000_0210,
    hal_reo1_ring_msi1_base_lsb: 0x0000_0234,
    hal_reo1_ring_msi1_base_msb: 0x0000_0238,
    hal_reo1_ring_msi1_data: 0x0000_023c,
    hal_reo2_ring_base_lsb: 0x0000_0244,
    hal_reo1_aging_thresh_ix_0: 0x0000_0564,
    hal_reo1_aging_thresh_ix_1: 0x0000_0568,
    hal_reo1_aging_thresh_ix_2: 0x0000_056c,
    hal_reo1_aging_thresh_ix_3: 0x0000_0570,
    hal_reo1_ring_hp: 0x0000_3028,
    hal_reo1_ring_tp: 0x0000_302c,
    hal_reo2_ring_hp: 0x0000_3030,
    hal_reo_tcl_ring_base_lsb: 0x0000_03fc,
    hal_reo_tcl_ring_hp: 0x0000_3058,
    hal_reo_cmd_ring_base_lsb: 0x0000_00e4,
    hal_reo_cmd_ring_hp: 0x0000_3010,
    hal_reo_status_ring_base_lsb: 0x0000_0504,
    hal_reo_status_hp: 0x0000_3070,
    hal_sw2reo_ring_base_lsb: 0x0000_013c,
    hal_sw2reo_ring_hp: 0x0000_3018,
    hal_seq_wcss_umac_ce0_src_reg: 0x0000_0000, // 0x08400000 - HAL_IPQ5018_CE_WFSS_REG_BASE
    hal_seq_wcss_umac_ce0_dst_reg: 0x0000_1000, // 0x08401000 - HAL_IPQ5018_CE_WFSS_REG_BASE
    hal_seq_wcss_umac_ce1_src_reg: 0x0000_2000, // 0x08402000 - HAL_IPQ5018_CE_WFSS_REG_BASE
    hal_seq_wcss_umac_ce1_dst_reg: 0x0000_3000, // 0x08403000 - HAL_IPQ5018_CE_WFSS_REG_BASE
    hal_wbm_idle_link_ring_base_lsb: 0x0000_0874,
    hal_wbm_idle_link_ring_misc: 0x0000_0884,
    hal_wbm_release_ring_base_lsb: 0x0000_01ec,
    hal_wbm0_release_ring_base_lsb: 0x0000_0924,
    hal_wbm1_release_ring_base_lsb: 0x0000_097c,
    hal_shadow_base_addr: 0x0000_0000,
    hal_reo1_misc_ctl: 0x0000_0000,
};
/// Linux `wcn6750_regs` (hw.c).
pub const WCN6750_REGS: HalRegs = HalRegs {
    hal_tcl1_ring_base_lsb: 0x0000_0694,
    hal_tcl1_ring_base_msb: 0x0000_0698,
    hal_tcl1_ring_id: 0x0000_069c,
    hal_tcl1_ring_misc: 0x0000_06a4,
    hal_tcl1_ring_tp_addr_lsb: 0x0000_06b0,
    hal_tcl1_ring_tp_addr_msb: 0x0000_06b4,
    hal_tcl1_ring_consumer_int_setup_ix0: 0x0000_06c4,
    hal_tcl1_ring_consumer_int_setup_ix1: 0x0000_06c8,
    hal_tcl1_ring_msi1_base_lsb: 0x0000_06dc,
    hal_tcl1_ring_msi1_base_msb: 0x0000_06e0,
    hal_tcl1_ring_msi1_data: 0x0000_06e4,
    hal_tcl2_ring_base_lsb: 0x0000_06ec,
    hal_tcl_ring_base_lsb: 0x0000_079c,
    hal_tcl_status_ring_base_lsb: 0x0000_08a4,
    hal_reo1_ring_base_lsb: 0x0000_01ec,
    hal_reo1_ring_base_msb: 0x0000_01f0,
    hal_reo1_ring_id: 0x0000_01f4,
    hal_reo1_ring_misc: 0x0000_01fc,
    hal_reo1_ring_hp_addr_lsb: 0x0000_0200,
    hal_reo1_ring_hp_addr_msb: 0x0000_0204,
    hal_reo1_ring_producer_int_setup: 0x0000_0210,
    hal_reo1_ring_msi1_base_lsb: 0x0000_0234,
    hal_reo1_ring_msi1_base_msb: 0x0000_0238,
    hal_reo1_ring_msi1_data: 0x0000_023c,
    hal_reo2_ring_base_lsb: 0x0000_0244,
    hal_reo1_aging_thresh_ix_0: 0x0000_0564,
    hal_reo1_aging_thresh_ix_1: 0x0000_0568,
    hal_reo1_aging_thresh_ix_2: 0x0000_056c,
    hal_reo1_aging_thresh_ix_3: 0x0000_0570,
    hal_reo1_ring_hp: 0x0000_3028,
    hal_reo1_ring_tp: 0x0000_302c,
    hal_reo2_ring_hp: 0x0000_3030,
    hal_reo_tcl_ring_base_lsb: 0x0000_03fc,
    hal_reo_tcl_ring_hp: 0x0000_3058,
    hal_reo_cmd_ring_base_lsb: 0x0000_00e4,
    hal_reo_cmd_ring_hp: 0x0000_3010,
    hal_reo_status_ring_base_lsb: 0x0000_0504,
    hal_reo_status_hp: 0x0000_3070,
    hal_sw2reo_ring_base_lsb: 0x0000_013c,
    hal_sw2reo_ring_hp: 0x0000_3018,
    hal_seq_wcss_umac_ce0_src_reg: 0x01b8_0000,
    hal_seq_wcss_umac_ce0_dst_reg: 0x01b8_1000,
    hal_seq_wcss_umac_ce1_src_reg: 0x01b8_2000,
    hal_seq_wcss_umac_ce1_dst_reg: 0x01b8_3000,
    hal_wbm_idle_link_ring_base_lsb: 0x0000_0874,
    hal_wbm_idle_link_ring_misc: 0x0000_0884,
    hal_wbm_release_ring_base_lsb: 0x0000_01ec,
    hal_wbm0_release_ring_base_lsb: 0x0000_0924,
    hal_wbm1_release_ring_base_lsb: 0x0000_097c,
    hal_shadow_base_addr: 0x0000_0504,
    hal_reo1_misc_ctl: 0x0000_05d8,
};

// ── DP interrupt groups (`struct ath11k_hw_ring_mask`) ─────────────

/// hw.h `ATH11K_EXT_IRQ_GRP_NUM_MAX`.
pub const ATH11K_EXT_IRQ_GRP_NUM_MAX: usize = 11;

/// Linux `struct ath11k_hw_ring_mask`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingMask {
    pub tx: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub rx_mon_status: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub rx: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub rx_err: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub rx_wbm_rel: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub reo_status: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub rxdma2host: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
    pub host2rxdma: [u8; ATH11K_EXT_IRQ_GRP_NUM_MAX],
}

/// Linux `ath11k_hw_ring_mask_qca6390` (QCA6390 + WCN6855 family):
/// the C designated initialisers place each mask at the index shown.
pub const RING_MASK_QCA6390: RingMask = RingMask {
    tx: [0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    rx_mon_status: [0, 0, 0, 0, 0x1, 0x2, 0x4, 0, 0, 0, 0],
    rx: [0, 0, 0, 0, 0, 0, 0, 0x1, 0x2, 0x4, 0x8],
    rx_err: [0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    rx_wbm_rel: [0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    reo_status: [0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    rxdma2host: [0x1, 0x2, 0x4, 0, 0, 0, 0, 0, 0, 0, 0],
    host2rxdma: [0; ATH11K_EXT_IRQ_GRP_NUM_MAX],
};

/// Linux `ath11k_hw_ring_mask_ipq8074` (IPQ8074, IPQ6018, IPQ5018).
pub const RING_MASK_IPQ8074: RingMask = RingMask {
    tx: [0x1, 0x2, 0x4, 0, 0, 0, 0, 0, 0, 0, 0],
    rx_mon_status: [0, 0, 0, 0, 0x1, 0x2, 0x4, 0, 0, 0, 0],
    rx: [0, 0, 0, 0, 0, 0, 0, 0x1, 0x2, 0x4, 0x8],
    rx_err: [0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    rx_wbm_rel: [0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    reo_status: [0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0, 0],
    rxdma2host: [0x1, 0x2, 0x4, 0, 0, 0, 0, 0, 0, 0, 0],
    host2rxdma: [0x1, 0x2, 0x4, 0, 0, 0, 0, 0, 0, 0, 0],
};

/// Linux `ath11k_hw_ring_mask_wcn6750`.
pub const RING_MASK_WCN6750: RingMask = RingMask {
    tx: [0x1, 0, 0x4, 0, 0x10, 0, 0, 0, 0, 0, 0],
    rx_mon_status: [0, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0],
    rx: [0, 0, 0, 0, 0, 0, 0, 0x1, 0x2, 0x4, 0x8],
    rx_err: [0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    rx_wbm_rel: [0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    reo_status: [0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    rxdma2host: [0x1, 0x2, 0x4, 0, 0, 0, 0, 0, 0, 0, 0],
    host2rxdma: [0; ATH11K_EXT_IRQ_GRP_NUM_MAX],
};

/// `enum hal_rx_buf_return_buf_manager` (hal.h).
pub mod rbm {
    pub const WBM_IDLE_BUF_LIST: u8 = 0;
    pub const WBM_IDLE_DESC_LIST: u8 = 1;
    pub const FW_BM: u8 = 2;
    pub const SW0_BM: u8 = 3;
    pub const SW1_BM: u8 = 4;
    pub const SW2_BM: u8 = 5;
    pub const SW3_BM: u8 = 6;
    pub const SW4_BM: u8 = 7;
}

/// Linux `struct ath11k_hw_tcl2wbm_rbm_map`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tcl2WbmRbmMap {
    pub tcl_ring_num: u8,
    pub wbm_ring_num: u8,
    pub rbm_id: u8,
}

/// Linux `struct ath11k_hw_hal_params`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HwHalParams {
    pub rx_buf_rbm: u8,
    pub tcl2wbm_rbm_map: &'static [Tcl2WbmRbmMap],
}

/// Linux `ath11k_hw_hal_params_qca6390` (uses
/// `ath11k_hw_tcl2wbm_rbm_map_ipq5018`: one TX ring, SW0_BM).
pub const HW_HAL_PARAMS_QCA6390: HwHalParams = HwHalParams {
    rx_buf_rbm: rbm::SW1_BM,
    tcl2wbm_rbm_map: &[Tcl2WbmRbmMap {
        tcl_ring_num: 0,
        wbm_ring_num: 0,
        rbm_id: rbm::SW0_BM,
    }],
};

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
