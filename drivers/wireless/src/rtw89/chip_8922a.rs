// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A (Wi-Fi 7, "BE" generation) chip container.
//!
//! Mirrors Linux `rtw89/rtw8922a.c` `rtw8922a_chip_info` (torvalds/linux
//! @ cbbddb6, `rtw8922a.c:3201..3362`). This is the chip's static
//! identity: FIFO/aggregation limits, band/bandwidth support, CAM sizes,
//! EFUSE geometry, PHY-cap window, power-state modes, and the H2C/C2H
//! register block. It does NOT include the firmware/RF/power/station
//! profile (BB/RF tables, TX-power program, calibration, station
//! composition) — that profile is the remainder of the `rtl8922a` TSV row.
//! What of it now exists: the firmware-parameter load path
//! (`radio_assets` admits Rtl8922A: BB/GAIN/RADIO_A idx0/RADIO_B idx1/
//! NCTL from the container, no static fallback), the BE TX-power
//! program (`radio_power_be::Plan`), and the power-trim parse
//! (`efuse_be::BeFactory::power_trim`). Still open: BE BB/RF/NCTL table
//! application, calibration `Board::new_be`, power-trim application,
//! periodic thermal/TSSI tracking, RFK execution, FW security
//! (follow-ups of #1878).
//!
//! Deliberate narrowings, all from the Linux struct itself:
//! - `support_bandwidths` is 20/40/80/160 MHz. 320 MHz EHT operation is
//!   NOT in this bitmask; claiming it here would be fabrication. The
//!   320 MHz width programming lives in `eht.rs` (the `eht` row, on
//!   top of this chip row); the mask itself is unchanged.
//! - `bb_table`, `bb_gain_table`, `rf_table`, `dflt_parms`,
//!   `rfe_parms_conf`, `dig_table`, `tssi_dbw_table` are NULL in Linux
//!   ("load parm from fw") — there is nothing to transcribe, so this
//!   container carries no such tables.
//! - `pwr_on_seq` / `pwr_off_seq` are NULL in Linux for this chip.

use super::mac::ChipId;

/// One EFUSE block window, mirroring Linux `struct rtw89_efuse_block_cfg`
/// (`efuse.h`: `offset` packs page in bits 31..16 and page offset in
/// bits 15..0; `size` is the logical window in bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EfuseBlock {
    /// Packed (page, page_offset) offset, as in Linux.
    pub(super) offset: u32,
    /// Logical window size in bytes.
    pub(super) size: u32,
}

/// EFUSE block kinds, in Linux `enum rtw89_efuse_block` order
/// (`rtw8922a.c:434..443` table order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EfuseBlockKind {
    Sys,
    Rf,
    HciDigPcieSdio,
    HciDigUsb,
    HciPhyPcie,
    HciPhyUsb3,
    HciPhyUsb2,
    Adie,
}

/// `rtw8922a_efuse_blocks` (`rtw8922a.c:434..443`).
pub(super) const EFUSE_BLOCKS: [EfuseBlock; 8] = [
    EfuseBlock {
        offset: 0x00000,
        size: 0x310,
    },
    EfuseBlock {
        offset: 0x10000,
        size: 0x240,
    },
    EfuseBlock {
        offset: 0x20000,
        size: 0x4800,
    },
    EfuseBlock {
        offset: 0x30000,
        size: 0x890,
    },
    EfuseBlock {
        offset: 0x40000,
        size: 0x200,
    },
    EfuseBlock {
        offset: 0x50000,
        size: 0x80,
    },
    EfuseBlock {
        offset: 0x60000,
        size: 0x0,
    },
    EfuseBlock {
        offset: 0x70000,
        size: 0x10,
    },
];

/// Block kind for a table index, mirroring the Linux table order.
pub(super) const fn efuse_block_kind(index: usize) -> Option<EfuseBlockKind> {
    match index {
        0 => Some(EfuseBlockKind::Sys),
        1 => Some(EfuseBlockKind::Rf),
        2 => Some(EfuseBlockKind::HciDigPcieSdio),
        3 => Some(EfuseBlockKind::HciDigUsb),
        4 => Some(EfuseBlockKind::HciPhyPcie),
        5 => Some(EfuseBlockKind::HciPhyUsb3),
        6 => Some(EfuseBlockKind::HciPhyUsb2),
        7 => Some(EfuseBlockKind::Adie),
        _ => None,
    }
}

/// `rtw8922a_chip_info.chip_id` / `chip_gen` (`rtw8922a.c:3202..3203`).
/// `ChipId::Rtl8922A` already exists in `mac.rs`; this asserts the
/// container is for that chip and the BE generation.
pub(super) const CHIP: ChipId = ChipId::Rtl8922A;

/// `fifo_size` (`rtw8922a.c:3217`).
pub(super) const FIFO_SIZE: usize = 589824;
/// `small_fifo_size` (`rtw8922a.c:3218`).
pub(super) const SMALL_FIFO_SIZE: bool = false;
/// `dle_scc_rsvd_size` (`rtw8922a.c:3219`).
pub(super) const DLE_SCC_RSVD_SIZE: u32 = 0;
/// `max_amsdu_limit` (`rtw8922a.c:3220`).
pub(super) const MAX_AMSDU_LIMIT: usize = 8000;
/// `max_vht_mpdu_cap` = 11454 (`rtw8922a.c:3221`).
pub(super) const MAX_VHT_MPDU_CAP: usize = 11454;
/// `max_eht_mpdu_cap` = 7991 (`rtw8922a.c:3222`).
pub(super) const MAX_EHT_MPDU_CAP: usize = 7991;
/// `max_tx_agg_num` (`rtw8922a.c:3223`).
pub(super) const MAX_TX_AGG_NUM: usize = 128;
/// `max_rx_agg_num` (`rtw8922a.c:3224`).
pub(super) const MAX_RX_AGG_NUM: usize = 64;
/// `rsvd_ple_ofst` (`rtw8922a.c:3226`).
pub(super) const RSVD_PLE_OFST: u32 = 0x8f800;
/// `wde_qempty_acq_grpnum` (`rtw8922a.c:3236`).
pub(super) const WDE_QEMPTY_ACQ_GRPNUM: u32 = 4;
/// `wde_qempty_mgq_grpsel` (`rtw8922a.c:3237`).
pub(super) const WDE_QEMPTY_MGQ_GRPSEL: u32 = 4;
/// `rf_base_addr` (`rtw8922a.c:3238`).
pub(super) const RF_BASE_ADDR: [u32; 2] = [0xe000, 0xf000];
/// `thermal_th` (`rtw8922a.c:3239`).
pub(super) const THERMAL_TH: [u8; 2] = [0xad, 0xb4];
/// `txpwr_factor_bb/rf/mac` (`rtw8922a.c:3250..3252`).
pub(super) const TXPWR_FACTOR_BB: u32 = 3;
/// `txpwr_factor_rf` (`rtw8922a.c:3251`).
pub(super) const TXPWR_FACTOR_RF: u32 = 2;
/// `txpwr_factor_mac` (`rtw8922a.c:3252`).
pub(super) const TXPWR_FACTOR_MAC: u32 = 1;
/// `support_macid_num` (`rtw8922a.c:3255`).
pub(super) const SUPPORT_MACID_NUM: usize = 32;
/// `support_link_num` (`rtw8922a.c:3256`).
pub(super) const SUPPORT_LINK_NUM: usize = 2;
/// `support_chanctx_num` (`rtw8922a.c:3257`).
pub(super) const SUPPORT_CHANCTX_NUM: usize = 2;
/// `support_rnr` (`rtw8922a.c:3258`).
pub(super) const SUPPORT_RNR: bool = true;
/// `support_bands`: 2.4 GHz, 5 GHz, 6 GHz (`rtw8922a.c:3260..3262`).
pub(super) const SUPPORT_BANDS_2GHZ: bool = true;
/// `support_bands`: 5 GHz (`rtw8922a.c:3261`).
pub(super) const SUPPORT_BANDS_5GHZ: bool = true;
/// `support_bands`: 6 GHz (`rtw8922a.c:3262`).
pub(super) const SUPPORT_BANDS_6GHZ: bool = true;
/// `support_bandwidths`: 20/40/80/160 MHz (`rtw8922a.c:3263..3266`).
/// 320 MHz is NOT in this mask; see the module docs.
pub(super) const SUPPORT_BANDWIDTHS_MHZ: [u32; 4] = [20, 40, 80, 160];
/// `support_unii4` (`rtw8922a.c:3267`).
pub(super) const SUPPORT_UNII4: bool = true;
/// `support_ant_gain` (`rtw8922a.c:3268`).
pub(super) const SUPPORT_ANT_GAIN: bool = true;
/// `support_tas` (`rtw8922a.c:3269`).
pub(super) const SUPPORT_TAS: bool = true;
/// `support_sar_by_ant` (`rtw8922a.c:3270`).
pub(super) const SUPPORT_SAR_BY_ANT: bool = true;
/// `support_noise` (`rtw8922a.c:3271`).
pub(super) const SUPPORT_NOISE: bool = false;
/// `support_fw_cmd_ofld` (`rtw8922a.c:3272`).
pub(super) const SUPPORT_FW_CMD_OFLD: bool = false;
/// `hw_sec_hdr` (`rtw8922a.c:3275`).
pub(super) const HW_SEC_HDR: bool = true;
/// `hw_mgmt_tx_encrypt` (`rtw8922a.c:3276`).
pub(super) const HW_MGMT_TX_ENCRYPT: bool = true;
/// `hw_tkip_crypto` (`rtw8922a.c:3277`).
pub(super) const HW_TKIP_CRYPTO: bool = true;
/// `hw_mlo_bmc_crypto` (`rtw8922a.c:3278`).
pub(super) const HW_MLO_BMC_CRYPTO: bool = false;
/// `rf_path_num` (`rtw8922a.c:3280`).
pub(super) const RF_PATH_NUM: usize = 2;
/// `tx_nss` (`rtw8922a.c:3281`).
pub(super) const TX_NSS: usize = 2;
/// `rx_nss` (`rtw8922a.c:3282`).
pub(super) const RX_NSS: usize = 2;
/// `acam_num` (`rtw8922a.c:3283`).
pub(super) const ACAM_NUM: usize = 128;
/// `bcam_num` (`rtw8922a.c:3284`).
pub(super) const BCAM_NUM: usize = 20;
/// `scam_num` (`rtw8922a.c:3285`).
pub(super) const SCAM_NUM: usize = 32;
/// `bacam_num` (`rtw8922a.c:3286`).
pub(super) const BACAM_NUM: usize = 24;
/// `bacam_dynamic_num` (`rtw8922a.c:3287`).
pub(super) const BACAM_DYNAMIC_NUM: usize = 8;
/// `bacam_ver` = `RTW89_BACAM_V1` = 1 (`rtw8922a.c:3288`,
/// `core.h` `enum rtw89_bacam_ver`: V0 = 0, V1 = 1, G7 = 2).
pub(super) const BACAM_VER: u32 = 1;
/// `addrcam_ver` (`rtw8922a.c:3289`).
pub(super) const ADDRCAM_VER: u32 = 0;
/// `ppdu_max_usr` (`rtw8922a.c:3290`).
pub(super) const PPDU_MAX_USR: usize = 16;
/// `sec_ctrl_efuse_size` (`rtw8922a.c:3291`).
pub(super) const SEC_CTRL_EFUSE_SIZE: usize = 4;
/// `physical_efuse_size` (`rtw8922a.c:3292`).
pub(super) const PHYSICAL_EFUSE_SIZE: usize = 0x1300;
/// `logical_efuse_size` (`rtw8922a.c:3293`).
pub(super) const LOGICAL_EFUSE_SIZE: usize = 0x70000;
/// `limit_efuse_size` (`rtw8922a.c:3294`).
pub(super) const LIMIT_EFUSE_SIZE: usize = 0x40000;
/// `dav_phy_efuse_size` (`rtw8922a.c:3295`).
pub(super) const DAV_PHY_EFUSE_SIZE: usize = 0;
/// `dav_log_efuse_size` (`rtw8922a.c:3296`).
pub(super) const DAV_LOG_EFUSE_SIZE: usize = 0;
/// `phycap_addr` (`rtw8922a.c:3298`).
pub(super) const PHYCAP_ADDR: u32 = 0x1700;
/// `phycap_size` (`rtw8922a.c:3299`).
pub(super) const PHYCAP_SIZE: usize = 0x38;
/// `para_ver` (`rtw8922a.c:3300`).
pub(super) const PARA_VER: u32 = 0xf;
/// `wlcx_desired` (`rtw8922a.c:3301`).
pub(super) const WLCX_DESIRED: u32 = 0x07110000;
/// `scbd` (`rtw8922a.c:3302`).
pub(super) const SCBD: u32 = 0x1;
/// `mailbox` (`rtw8922a.c:3303`).
pub(super) const MAILBOX: u32 = 0x1;
/// `ps_mode_supported`: RFOFF, CLK_GATED, PWR_GATED
/// (`rtw8922a.c:3320..3322`).
pub(super) const PS_MODE_RFOFF: bool = true;
/// `ps_mode_supported`: CLK_GATED (`rtw8922a.c:3321`).
pub(super) const PS_MODE_CLK_GATED: bool = true;
/// `ps_mode_supported`: PWR_GATED (`rtw8922a.c:3322`).
pub(super) const PS_MODE_PWR_GATED: bool = true;
/// `h2c_cctl_func_id` = `H2C_FUNC_MAC_CCTLINFO_UD_G7` = 0x11
/// (`rtw8922a.c:3324`, `fw.h:4828`).
pub(super) const H2C_CCTL_FUNC_ID: u8 = 0x11;
/// `hci_func_en_addr` = `R_BE_HCI_FUNC_EN` = 0x7880
/// (`rtw8922a.c:3325`, `reg.h:4880`).
pub(super) const HCI_FUNC_EN_ADDR: u32 = 0x7880;
/// `h2c_desc_size` = `sizeof(struct rtw89_rxdesc_short_v2)` = 6 dwords
/// (`rtw8922a.c:3326`, `core.h:1199`).
pub(super) const H2C_DESC_SIZE: usize = 24;
/// `txwd_body_size` = `sizeof(struct rtw89_txwd_body_v2)` = 8 dwords
/// (`rtw8922a.c:3327`, `core.h:1121`).
pub(super) const TXWD_BODY_SIZE: usize = 32;
/// `txwd_info_size` = `sizeof(struct rtw89_txwd_info_v2)` = 8 dwords
/// (`rtw8922a.c:3328`, `core.h:1141`).
pub(super) const TXWD_INFO_SIZE: usize = 32;
/// `h2c_ctrl_reg` = `R_BE_H2CREG_CTRL` = 0x7160
/// (`rtw8922a.c:3329`, `reg.h:4875`).
pub(super) const H2C_CTRL_REG: u32 = 0x7160;
/// `c2h_ctrl_reg` = `R_BE_C2HREG_CTRL` = 0x7164
/// (`rtw8922a.c:3333`, `reg.h:4877`).
pub(super) const C2H_CTRL_REG: u32 = 0x7164;
/// `h2c_counter_reg` / `c2h_counter_reg` base = `R_BE_UDM1` + 1 = 0x01F5
/// (`rtw8922a.c:3330`/`3334`, `reg.h:4568`).
pub(super) const UDM_COUNTER_REG: u32 = 0x01F5;
/// `dma_ch_mask` (`rtw8922a.c:3353`).
pub(super) const DMA_CH_MASK: u32 = 0;
/// `fw_basename` = `RTW8922A_FW_BASENAME` (`rtw8922a.c:3208`,
/// `rtw8922a.c:19`).
pub(super) const FW_BASENAME: &str = "rtw89/rtw8922a_fw";
/// `fw_format_max` = `RTW8922A_FW_FORMAT_MAX` (`rtw8922a.c:3209`,
/// `rtw8922a.c:18`).
pub(super) const FW_FORMAT_MAX: u32 = 4;
