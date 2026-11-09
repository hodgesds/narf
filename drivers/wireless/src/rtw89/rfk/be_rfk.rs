// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A firmware-offloaded RFK (torvalds/linux @ cbbddb6).
//!
//! Unlike the AX chips, whose IQK/DPK/TSSI run host-side register
//! programs, the BE chip calibrates in firmware: the host sends one H2C
//! offload per step and waits for the firmware C2H RFK report
//! (`rtw89_phy_rfk_*_and_wait`, phy.c:4175..4330). Each step is
//! `report_prep` (state = START, completion re-armed) -> one
//! `rtw89_fw_h2c_rf_*` (fw.c:8858..9380) -> `rtw89_phy_rfk_report_wait`
//! on the C2H report (`rtw89_phy_c2h_rfk_report_state`, phy.c:4085),
//! which completes only when the report state is `RTW89_RFK_STATE_OK`
//! (`-ETIMEDOUT` on no report, `-EFAULT` on a non-OK state).
//!
//! The H2C bodies here are byte-exact copies of the Linux structs
//! (fw.h:4976..5202); the header (category 2, class 0xB, function) is
//! added by the transport (`Interface::h2c`). The C2H report is
//! `struct rtw89_c2h_rfk_report` (fw.h:5410): the 8-byte C2H header
//! (`RTW89_C2H_HDR_W0_CATEGORY`/`CLASS`/`FUNC`, `W1_LEN` counting the
//! whole envelope) followed by `state` and `version`.
//!
//! Version selection is firmware-feature-gated in Linux
//! (`RTW89_CHK_FW_FEATURE(RFK_IQK_V0 / RFK_RXDCK_V0 / RFK_PRE_NOTIFY_V*)`).
//! NARF has no firmware-feature query for these, so this module builds
//! the default (newest) body in each case and keeps the older variant as
//! a documented builder for the day the query lands.

use super::super::h2c::{H2C_CAT_OUTSRC, H2C_CL_OUTSRC_RF_FW_RFK, H2C_FUNC_RFK_IQK_OFFLOAD};
use super::{Error, Interface};

/// `H2C_FUNC_RFK_TSSI_OFFLOAD` (0x0). fw.h:4976.
pub(in super::super) const FUNC_TSSI_OFFLOAD: u8 = 0x0;
/// `H2C_FUNC_RFK_IQK_OFFLOAD` (0x1). fw.h:4977; also `h2c.rs`.
pub(in super::super) const FUNC_IQK_OFFLOAD: u8 = H2C_FUNC_RFK_IQK_OFFLOAD;
/// `H2C_FUNC_RFK_DPK_OFFLOAD` (0x3). fw.h:4978.
pub(in super::super) const FUNC_DPK_OFFLOAD: u8 = 0x3;
/// `H2C_FUNC_RFK_TXGAPK_OFFLOAD` (0x4). fw.h:4979.
pub(in super::super) const FUNC_TXGAPK_OFFLOAD: u8 = 0x4;
/// `H2C_FUNC_RFK_DACK_OFFLOAD` (0x5). fw.h:4980.
pub(in super::super) const FUNC_DACK_OFFLOAD: u8 = 0x5;
/// `H2C_FUNC_RFK_RXDCK_OFFLOAD` (0x6). fw.h:4981.
pub(in super::super) const FUNC_RXDCK_OFFLOAD: u8 = 0x6;
/// `H2C_FUNC_RFK_PRE_NOTIFY` (0x8). fw.h:4982.
pub(in super::super) const FUNC_PRE_NOTIFY: u8 = 0x8;

/// `RTW89_C2H_CAT_OUTSRC` (2). fw.h:174.
pub(in super::super) const C2H_CAT_OUTSRC: u8 = 2;
/// `RTW89_PHY_C2H_RFK_REPORT` (0x9). phy.h:206.
pub(in super::super) const C2H_CLASS_RFK_REPORT: u8 = 0x9;
/// `RTW89_PHY_C2H_RFK_REPORT_FUNC_STATE` (0). phy.h:185.
pub(in super::super) const C2H_FUNC_RFK_REPORT_STATE: u8 = 0;

/// `RF_AB` (`BIT(RF_PATH_A) | BIT(RF_PATH_B)`): both RF paths on PHY_0
/// without DBCC (`rtw89_phy_get_kpath(PHY_0)`; the DPK/TXGAPK/RXDCK
/// bodies hardcode it in fw.c).
pub(in super::super) const RF_AB: u8 = 0x3;

/// `enum rtw89_rfk_report_types` (core.h:6689..6701). The index doubles
/// as the slot in the channel owner's per-kind record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum ReportKind {
    PreNtfy,
    Tssi,
    Iqk,
    Dpk,
    Txgapk,
    Dack,
    RxDck,
    TxIqk,
    Cim3k,
}

/// Number of [`ReportKind`] variants (Linux
/// `NUM_OF_RTW89_RFK_REPORT_TYPES`).
pub(in super::super) const REPORT_KINDS: usize = 9;

impl ReportKind {
    /// The H2C offload function for this kind (fw.h:4976..4985).
    pub(in super::super) const fn func(self) -> u8 {
        match self {
            Self::PreNtfy => FUNC_PRE_NOTIFY,
            Self::Tssi => FUNC_TSSI_OFFLOAD,
            Self::Iqk => FUNC_IQK_OFFLOAD,
            Self::Dpk => FUNC_DPK_OFFLOAD,
            Self::Txgapk => FUNC_TXGAPK_OFFLOAD,
            Self::Dack => FUNC_DACK_OFFLOAD,
            Self::RxDck => FUNC_RXDCK_OFFLOAD,
            // No Linux BE call site in this path; kept for the record.
            Self::TxIqk => 0xc,
            Self::Cim3k => 0xe,
        }
    }
    /// The Linux report name (phy.c `rtw89_rfk_report_names`).
    pub(in super::super) const fn name(self) -> &'static str {
        match self {
            Self::PreNtfy => "PRE_NTFY",
            Self::Tssi => "TSSI",
            Self::Iqk => "IQK",
            Self::Dpk => "DPK",
            Self::Txgapk => "TXGAPK",
            Self::Dack => "DACK",
            Self::RxDck => "RX_DCK",
            Self::TxIqk => "TX_IQK",
            Self::Cim3k => "CIM3k",
        }
    }
}

/// `enum rtw89_rfk_report_state` (core.h:6681..6687).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum ReportState {
    Start,
    Ok,
    Fail,
    Timeout,
    H2cCmdErr,
}

impl ReportState {
    /// Decode the report state byte; an unknown value fails the wait
    /// exactly like `RTW89_RFK_STATE_FAIL` (Linux only accepts OK).
    pub(in super::super) const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Start,
            1 => Self::Ok,
            2 => Self::Fail,
            3 => Self::Timeout,
            4 => Self::H2cCmdErr,
            _ => Self::Fail,
        }
    }
}

/// One parsed `struct rtw89_c2h_rfk_report`: the firmware's verdict on
/// the single outstanding offload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct Report {
    pub state: ReportState,
    pub version: u8,
}

/// Parse a C2H RFK report (`struct rtw89_c2h_rfk_report`, fw.h:5410):
/// the 8-byte C2H header must address OUTSRC / RFK_REPORT / STATE and
/// its `W1_LEN` must count the whole envelope (as `rx_packet::C2h`
/// checks); bytes 8 and 9 are `state` and `version`. Returns `None`
/// for any other message, so a stray C2H never completes an RFK wait.
pub(in super::super) fn parse_c2h_report(bytes: &[u8]) -> Option<Report> {
    if bytes.len() < 10 {
        return None;
    }
    let w0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let w1 = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    if w1 & 0x3fff != bytes.len() as u32 {
        return None;
    }
    if w0 & 3 != u32::from(C2H_CAT_OUTSRC) {
        return None;
    }
    if (w0 >> 2) & 0x3f != u32::from(C2H_CLASS_RFK_REPORT) {
        return None;
    }
    if (w0 >> 8) & 0xff != u32::from(C2H_FUNC_RFK_REPORT_STATE) {
        return None;
    }
    Some(Report {
        state: ReportState::from_u8(bytes[8]),
        version: bytes[9],
    })
}

/// `struct rtw89_fw_h2c_rfk_pre_info` (fw.h:5082), the default V3 body
/// `rtw89_fw_h2c_rf_pre_ntfy` sends when no `RFK_PRE_NOTIFY_V0/V1/V2`
/// firmware feature is set: `{mlo_mode, phy_idx, mlo_1_1}` as LE u32s.
/// The single-PHY non-MLO owner passes `MLO_DBCC_NOT_SUPPORT` (1,
/// core.h:5113) and `mlo_1_1 = false`.
pub(in super::super) fn pre_ntfy_body(phy_idx: u8, mlo_mode: u32, mlo_1_1: bool) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&mlo_mode.to_le_bytes());
    out[4..8].copy_from_slice(&u32::from(phy_idx).to_le_bytes());
    out[8..12].copy_from_slice(&u32::from(mlo_1_1).to_le_bytes());
    out
}

/// `struct rtw89_h2c_rf_iqk` (fw.h:5146), the default body
/// `rtw89_fw_h2c_rf_iqk` sends: `{len, ktype = 0, phy, kpath, band, bw,
/// ch, cv}`. `band`/`bw` are the Linux `RTW89_BAND_*` /
/// `RTW89_CHANNEL_WIDTH_*` values, `cv` is `hal->cv`.
pub(in super::super) fn iqk_body(phy: u8, kpath: u8, band: u8, bw: u8, ch: u8, cv: u8) -> [u8; 8] {
    [8, 0, phy, kpath, band, bw, ch, cv]
}

/// `struct rtw89_h2c_rf_iqk_v0` (fw.h:5141), the `RFK_IQK_V0` firmware
/// feature variant: `{phy_idx, dbcc}` as LE u32s. Kept for the day the
/// firmware-feature query lands; the channel uses the default body.
pub(in super::super) fn iqk_v0_body(phy_idx: u32, dbcc: bool) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&phy_idx.to_le_bytes());
    out[4..8].copy_from_slice(&u32::from(dbcc).to_le_bytes());
    out
}

/// `struct rtw89_h2c_rf_dpk` (fw.h:5157): `{len, phy, dpk_enable = 1,
/// kpath = RF_AB, cur_band, cur_bw, cur_ch, dpk_dbg_en}`.
/// `dpk_dbg_en` is Linux `rtw89_debug_is_enabled(RTW89_DBG_RFK)`.
pub(in super::super) fn dpk_body(phy: u8, band: u8, bw: u8, ch: u8, dbg: bool) -> [u8; 8] {
    [8, phy, 1, RF_AB, band, bw, ch, u8::from(dbg)]
}

/// `struct rtw89_h2c_rf_txgapk` (fw.h:5168): `{len, ktype = 2, phy,
/// kpath = RF_AB, band, bw, ch, cv}`.
pub(in super::super) fn txgapk_body(phy: u8, band: u8, bw: u8, ch: u8, cv: u8) -> [u8; 8] {
    [8, 2, phy, RF_AB, band, bw, ch, cv]
}

/// `struct rtw89_h2c_rf_dack` (fw.h:5179): `{len, phy, type = 0}`.
/// Used by `rtw8922a_rfk_init_late`, not by the channel run; the
/// runner is shared so the init-late lane needs no new transport.
pub(in super::super) fn dack_body(phy: u8) -> [u8; 3] {
    [3, phy, 0]
}

/// `struct rtw89_h2c_rf_rxdck` (fw.h:5200): the V0 body plus
/// `is_chl_k`. `{len, phy, is_afe = false, kpath = RF_AB, cur_band,
/// cur_bw, cur_ch, rxdck_dbg_en, is_chl_k}`.
pub(in super::super) fn rxdck_body(
    phy: u8,
    band: u8,
    bw: u8,
    ch: u8,
    dbg: bool,
    chl_k: bool,
) -> [u8; 9] {
    [
        9,
        phy,
        0,
        RF_AB,
        band,
        bw,
        ch,
        u8::from(dbg),
        u8::from(chl_k),
    ]
}

/// `struct rtw89_h2c_rf_rxdck_v0` (fw.h:5185) alone, the
/// `RFK_RXDCK_V0` firmware feature variant (8 bytes, no `is_chl_k`).
/// Kept for the day the firmware-feature query lands.
pub(in super::super) fn rxdck_v0_body(phy: u8, band: u8, bw: u8, ch: u8, dbg: bool) -> [u8; 8] {
    [8, phy, 0, RF_AB, band, bw, ch, u8::from(dbg)]
}

/// One `rtw89_phy_rfk_*_and_wait` transport: send the offload H2C,
/// then wait for the single C2H RFK report up to `timeout_ms` and
/// return it. A transport timeout surfaces as
/// `Error::Register(Timeout)`; a non-OK report state is returned
/// (not failed here) so the caller can record it first — Linux records
/// the state in `rfk_wait.record` before returning `-EFAULT`. Callers
/// must reject non-OK states via [`check`].
pub(in super::super) async fn run<I: Interface>(
    io: &mut I,
    func: u8,
    payload: &[u8],
    timeout_ms: u64,
) -> Result<Report, Error> {
    io.admit()?;
    io.h2c(H2C_CAT_OUTSRC, H2C_CL_OUTSRC_RF_FW_RFK, func, payload)
        .await?;
    io.await_rfk_report(timeout_ms).await
}

/// Accept only `RTW89_RFK_STATE_OK`, as `__rtw89_phy_rfk_report_wait`
/// does (`-EFAULT` otherwise). Linux ignores these returns in
/// `rtw8922a_rfk_channel` (void); NARF fails closed so a channel is
/// never declared calibrated on a failed offload.
pub(in super::super) fn check(report: Report) -> Result<Report, Error> {
    if report.state != ReportState::Ok {
        return Err(Error::Report);
    }
    Ok(report)
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_rfk_tests.rs"]
mod tests;
