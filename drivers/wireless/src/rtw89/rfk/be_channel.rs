// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A channel RFK and periodic track (torvalds/linux @ cbbddb6).
//!
//! `rtw8922a_rfk_channel` (rtw8922a.c:2388) on PHY_0 without DBCC:
//! BTC WL RFK START notify (`BTC_WRFKT_CHLK`), stop scheduler TX,
//! wait for both RF paths to reach RX mode, then the firmware-offloaded
//! steps with their Linux timeouts — PRE_NTFY (5 ms), TXGAPK (54 ms),
//! IQK (84 ms), TSSI NORMAL (20 ms), DPK (34 ms), RXDCK on PHY_0 with
//! `is_chl_k` (32 ms) — resume scheduler TX, BTC WL RFK STOP notify.
//! `rtw8922a_rfk_band_changed` (rtw8922a.c:2412) is a TSSI SCAN offload
//! (6 ms). There is no host-side register calibration in this path:
//! the B initial RCK/DACK/RXDCK core in `rfk.rs` stays the only
//! host-side RFK, and the one-shot `rtw8922a_tssi_reset` pulse belongs
//! to `set_channel_bb`, not to this owner.
//!
//! The periodic track step is `rtw89_core_rfk_track` (core.c:5335):
//! skip MCC mode, call the chip track hook, then
//! `rtw89_core_rfk_tssi_record` (core.c:5304). `rtw8922a_rfk_track`
//! (rtw8922a.c:2425) is EMPTY at this commit — Linux runs no periodic
//! IQK/DPK/TSSI rerun for 8922A — so the track step records the TSSI
//! codes only (8922A base 0x2ee10, mask 0x7fc00, 10-deep history) and
//! never invents a rerun.
//!
//! `rfk_channel` returns `Err` on a failed offload (Linux ignores the
//! returns and continues; NARF fails closed) and leaves the owner Busy
//! (terminal); the caller terminalizes the radio, as with the C/51
//! owners. The pre-notify MCC H2C (`rtw89_fw_h2c_rf_pre_ntfy_mcc`) is
//! NOT sent here: it is firmware-version-gated and needs the RFK MCC
//! channel-context table, neither of which this owner has.

use super::super::{
    operating_channel_c::{Band, Profile},
    power,
    rfk_regs::{RR_MOD, RR_MOD_MASK},
};
use super::{
    be_rfk::{
        self, check, dpk_body, iqk_body, pre_ntfy_body, rxdck_body, txgapk_body, Report,
        ReportKind, FUNC_DPK_OFFLOAD, FUNC_IQK_OFFLOAD, FUNC_PRE_NOTIFY, FUNC_RXDCK_OFFLOAD,
        FUNC_TSSI_OFFLOAD, FUNC_TXGAPK_OFFLOAD, REPORT_KINDS, RF_AB,
    },
    be_tssi::{self, Inputs, TssiMode},
    Access, Error, Interface,
};

/// `rtw89_phy_rfk_pre_ntfy_and_wait` timeout in `rtw8922a_rfk_channel`.
pub(in super::super) const PRE_NTFY_MS: u64 = 5;
/// `rtw89_phy_rfk_txgapk_and_wait` timeout in `rtw8922a_rfk_channel`.
pub(in super::super) const TXGAPK_MS: u64 = 54;
/// `rtw89_phy_rfk_iqk_and_wait` timeout in `rtw8922a_rfk_channel`.
pub(in super::super) const IQK_MS: u64 = 84;
/// `rtw89_phy_rfk_tssi_and_wait` (NORMAL) timeout in
/// `rtw8922a_rfk_channel`.
pub(in super::super) const TSSI_MS: u64 = 20;
/// `rtw89_phy_rfk_dpk_and_wait` timeout in `rtw8922a_rfk_channel`.
pub(in super::super) const DPK_MS: u64 = 34;
/// `rtw89_phy_rfk_rxdck_and_wait` timeout in `rtw8922a_rfk_channel`.
pub(in super::super) const RXDCK_MS: u64 = 32;
/// `rtw89_phy_rfk_tssi_and_wait` (SCAN) timeout in
/// `rtw8922a_rfk_band_changed`.
pub(in super::super) const TSSI_SCAN_MS: u64 = 6;
/// `rtw89_track_work` period (`RTW89_TRACK_WORK_PERIOD`, 2 s): the
/// caller schedules `track` on this cadence; the owner only counts.
pub(in super::super) const TRACK_PERIOD_MS: u64 = 2000;

/// `rtw89_core_rfk_tssi_record` 8922A TSSI code base (path A; path B
/// is +0x100) and mask (core.c:5316..5321).
const TSSI_CODE_BASE: u32 = 0x2ee10;
const TSSI_CODE_MASK: u32 = 0x7fc00;
/// `RTW89_RFK_RECORD_HISTORY_NR` (core.h:6702).
const TSSI_HISTORY: usize = 10;
/// `_wait_rx_mode` budget (rtw8922a.c:2368..2386): 2 us steps, 5000 us.
const RX_MODE_BUDGET_US: u64 = 5000;
/// `MLO_DBCC_NOT_SUPPORT` (core.h:5113): the single-PHY non-MLO mode
/// the pre-notify V3 body carries.
pub(in super::super) const MLO_NOT_SUPPORT: u32 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) enum State {
    #[default]
    New,
    Busy,
    /// `rtw8922a_rfk_channel` completed for the programmed channel.
    Calibrated,
}

/// One retained RTL8922A channel RFK owner: the calibrated channel and
/// the per-kind firmware report record (Linux `rtw89_rfk_record`
/// `states[]`), plus the periodic TSSI-code history.
#[derive(Default)]
pub(in super::super) struct Channel {
    state: State,
    channel: Option<Profile>,
    band: Option<Band>,
    /// `btc.cx.wl.rfk_info.con_rfk` (state only; no I/O).
    conn_rfk: bool,
    /// Last C2H report per [`ReportKind`] (Linux `rfk_wait.record`
    /// `states[]`).
    records: [Option<Report>; REPORT_KINDS],
    /// `rtw89_core_rfk_tssi_record` history (`tssi_code[10][2]`).
    tssi_codes: [[u32; 2]; TSSI_HISTORY],
    tssi_code_idx: usize,
    /// Periodic track ticks served.
    tracks: u64,
}

impl Channel {
    pub fn state(&self) -> State {
        self.state
    }
    /// The channel of the last completed channel RFK.
    pub fn calibrated(&self) -> Option<Profile> {
        (self.state == State::Calibrated)
            .then_some(self.channel)
            .flatten()
    }
    /// `rtw89_btc_ntfy_conn_rfk` state (true only inside `rfk_channel`).
    pub fn conn_rfk(&self) -> bool {
        self.conn_rfk
    }
    /// Last C2H report for `kind`, if that offload has run.
    pub fn record(&self, kind: ReportKind) -> Option<Report> {
        self.records[kind as usize]
    }
    /// TSSI-code history (oldest first from the current index).
    pub fn tssi_codes(&self) -> [[u32; 2]; TSSI_HISTORY] {
        self.tssi_codes
    }
    /// Periodic track ticks served.
    pub fn tracks(&self) -> u64 {
        self.tracks
    }
    fn begin(&mut self, from: &[State]) -> Result<(), Error> {
        if !from.contains(&self.state) {
            return Err(Error::Terminal);
        }
        self.state = State::Busy;
        Ok(())
    }
    fn set_record(&mut self, kind: ReportKind, report: Report) {
        self.records[kind as usize] = Some(report);
    }
    /// One offload step: send, wait, record the report (even on a
    /// non-OK state, as Linux records `states[]` before returning),
    /// then fail closed unless the state is OK.
    async fn step<I: Interface>(
        &mut self,
        io: &mut I,
        kind: ReportKind,
        func: u8,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Result<(), Error> {
        let report = be_rfk::run(io, func, payload, timeout_ms).await?;
        self.set_record(kind, report);
        check(report)?;
        Ok(())
    }

    /// rtw8922a.c `rtw8922a_rfk_channel` on the programmed `profile`:
    /// BTC WL RFK START, stop scheduler TX (`pause`), wait for RX mode
    /// on both RF paths, PRE_NTFY, TXGAPK, IQK, TSSI NORMAL, DPK, RXDCK
    /// (PHY_0, `is_chl_k`), resume scheduler TX, BTC WL RFK STOP.
    /// `tssi` carries the TSSI H2C inputs (efuse DE profile, trim,
    /// TXPWR_TRK rows, RFE type, cut); `mlo_mode` is the pre-notify
    /// MLO mode (`MLO_NOT_SUPPORT` for the single-PHY non-MLO owner).
    /// Re-runnable on a channel change (New or Calibrated).
    ///
    /// # Safety
    /// Actual RTL8922A after completed BE tables and `rfk_init`
    /// (`is_tssi_mode` false), with exclusive radio ownership and a
    /// current channel grant for `profile`; Interface enforces current
    /// admission at every access. On error the owner is terminal
    /// (Busy) and the caller terminalizes the radio.
    pub async unsafe fn rfk_channel(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        tssi: &Inputs<'_>,
        mlo_mode: u32,
    ) -> Result<(), Error> {
        self.begin(&[State::New, State::Calibrated])?;
        self.channel = None;
        io.admit()?;
        io.coex_rfk(true).await?;
        self.conn_rfk = true;
        let saved = io.pause().await?;
        let mut access = Access(io);
        for path in 0..2u8 {
            let start = access.0.now_us();
            loop {
                if access.rr(path, RR_MOD, RR_MOD_MASK).await? != 2 {
                    break;
                }
                if access.0.now_us().saturating_sub(start) >= RX_MODE_BUDGET_US {
                    return Err(power::Error::Timeout.into());
                }
                access.delay(2).await?;
            }
        }
        let band = profile.band() as u8;
        let bw = profile.width() as u8;
        let ch = profile.center();
        let cv = tssi.cv;
        self.step(
            access.0,
            ReportKind::PreNtfy,
            FUNC_PRE_NOTIFY,
            &pre_ntfy_body(0, mlo_mode, false),
            PRE_NTFY_MS,
        )
        .await?;
        self.step(
            access.0,
            ReportKind::Txgapk,
            FUNC_TXGAPK_OFFLOAD,
            &txgapk_body(0, band, bw, ch, cv),
            TXGAPK_MS,
        )
        .await?;
        self.step(
            access.0,
            ReportKind::Iqk,
            FUNC_IQK_OFFLOAD,
            &iqk_body(0, RF_AB, band, bw, ch, cv),
            IQK_MS,
        )
        .await?;
        self.step(
            access.0,
            ReportKind::Tssi,
            FUNC_TSSI_OFFLOAD,
            &be_tssi::build(profile, TssiMode::Normal, tssi),
            TSSI_MS,
        )
        .await?;
        self.step(
            access.0,
            ReportKind::Dpk,
            FUNC_DPK_OFFLOAD,
            &dpk_body(0, band, bw, ch, false),
            DPK_MS,
        )
        .await?;
        self.step(
            access.0,
            ReportKind::RxDck,
            FUNC_RXDCK_OFFLOAD,
            &rxdck_body(0, band, bw, ch, false, true),
            RXDCK_MS,
        )
        .await?;
        access.0.resume(saved).await?;
        access.0.coex_rfk(false).await?;
        self.conn_rfk = false;
        self.band = Some(profile.band());
        self.channel = Some(profile);
        self.state = State::Calibrated;
        Ok(())
    }

    /// rtw8922a.c `rtw8922a_rfk_band_changed` on the programmed
    /// `profile`: the TSSI SCAN offload (6 ms). Called by the
    /// set-channel owner on a band change (or the first programmed
    /// channel), before `rfk_channel`; it changes no owner state
    /// besides the TSSI record. Callable from New or Calibrated.
    ///
    /// # Safety
    /// Same owner as [`Self::rfk_channel`], directly after the channel
    /// program, with `tssi` as in [`Self::rfk_channel`]. There is no
    /// `mlo_mode` parameter: the TSSI body carries none (Linux
    /// `rtw8922a_rfk_band_changed` takes none either).
    pub async unsafe fn band_changed(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        tssi: &Inputs<'_>,
    ) -> Result<(), Error> {
        if self.state == State::Busy {
            return Err(Error::Terminal);
        }
        self.step(
            io,
            ReportKind::Tssi,
            FUNC_TSSI_OFFLOAD,
            &be_tssi::build(profile, TssiMode::Scan, tssi),
            TSSI_SCAN_MS,
        )
        .await?;
        Ok(())
    }

    /// One core.c `rtw89_track_work` RF step on the calibrated channel
    /// (`rtw89_core_rfk_track`): skip MCC mode, run the chip track
    /// hook (`rtw8922a_rfk_track`, empty at this commit — no periodic
    /// IQK/DPK/TSSI rerun exists for 8922A), then snapshot the TSSI
    /// codes (`rtw89_core_rfk_tssi_record`). `mcc_mode` returns
    /// `Ok(false)` with no access. Linux skips the whole track work
    /// while scanning; the caller applies that gate.
    ///
    /// # Safety
    /// Same retained owner after [`Self::rfk_channel`]; no concurrent
    /// RFK/PHY/reset/PM owner.
    pub async unsafe fn track(
        &mut self,
        io: &mut impl Interface,
        mcc_mode: bool,
    ) -> Result<bool, Error> {
        if mcc_mode {
            return Ok(false);
        }
        if self.state != State::Calibrated {
            return Err(Error::Terminal);
        }
        io.admit()?;
        let idx = self.tssi_code_idx;
        for path in 0..2u32 {
            let value = io.read32(TSSI_CODE_BASE + 0x100 * path)?;
            self.tssi_codes[idx][path as usize] =
                (value & TSSI_CODE_MASK) >> TSSI_CODE_MASK.trailing_zeros();
        }
        self.tssi_code_idx = (idx + 1) % TSSI_HISTORY;
        self.tracks += 1;
        Ok(true)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "be_channel_tests.rs"]
mod tests;
