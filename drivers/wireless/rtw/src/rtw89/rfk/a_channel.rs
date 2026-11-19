// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A MAC_0/PHY_0 (non-DBCC) channel RFK: rtw8852a.c
//! `rtw8852a_rfk_channel` (`btc_ntfy_conn_rfk`, RX DCK, IQK,
//! `btc_ntfy_preserve_bt_time(30)`, TSSI, 30ms, DPK, `conn_rfk =
//! false`), rtw8852a_rfk.c `rtw8852a_rfk_band_changed`
//! (`rtw8852a_tssi_scan`) and `rtw8852a_rfk_track` (`dpk_track` +
//! `tssi_track`).
//!
//! A has no MCC (`rtw8852a_rfk_channel` sends no H2C body). This generic
//! owner takes the profile directly; the separate `channel_a` owner
//! programs MAC/BB/RF. `tail:None` retains explicit `PartialTssi`;
//! `Some` composes actual firmware limits, high-power and pre-TX PMAC before
//! DPK, so only that path can return Calibrated. Native uses Some and
//! separately requires live nonzero thermal and positive PMAC/DPK receipts.
//! The source connection-RFK notification is software state only, so
//! `conn_rfk` is state only and both 30ms BT preserves always wait
//! the full 30ms. `scan` here is the band-change TSSI scan, gated on
//! the retained TSSI enable state.
use super::super::{factory_a::Calibration, operating_channel_c::Profile};
use super::a_tssi::{tail, Tracking};
use super::{a_dpk::Dpk, a_iqk::Iqk, a_tssi::Tssi, Access, Error, Interface};

/// Channel RFK lifecycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) enum State {
    #[default]
    New,
    Busy,
    /// IQK, partial TSSI and DPK effects ran; source high-power/pre-TX
    /// TSSI tails did not. No calibration or periodic-tracking receipt.
    PartialTssi,
    /// Complete source TSSI tail plus all channel RFK effects completed.
    Calibrated,
}

/// Returning success cannot be mistaken for complete channel RFK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Outcome {
    PartialTssi,
    Calibrated,
}

/// One retained RTL8852A channel owner: the channel, the retained
/// `is_tssi_mode` and the channel RFK results.
#[derive(Default)]
pub(in super::super) struct Channel {
    state: State,
    channel: Option<Profile>,
    /// `rtwdev->is_tssi_mode[A/B]` (false after `rtw8852a_rfk_init`).
    tssi_mode: [bool; 2],
    /// `rtwdev->btc.cx.wl.rfk_info.con_rfk` (state only; no I/O).
    conn_rfk: bool,
    iqk: Iqk,
    tssi: Tssi,
    dpk: Dpk,
}

/// Per-device inputs to one RTL8852A channel RFK, bundled so
/// [`Channel::rfk_channel`] stays under clippy's argument limit
/// (the BE channel takes the same shape as `&Inputs<'_>`).
#[derive(Clone, Copy, Debug)]
pub(in super::super) struct ChannelInputs<'a> {
    /// This device's A factory snapshot.
    pub calibration: &'a Calibration,
    /// This container's TXPWR_TRK.
    pub tracking: &'a Tracking,
    /// `hal.cv`.
    pub cut: u8,
    /// The current averaged thermal per path (for TSSI
    /// `base_thermal` and DPK `ther_dpk`).
    pub thermal: [u8; 2],
    /// EPA presence by band (2G, 5G), from `fem.epa_2g/epa_5g`,
    /// for the DPK bypass.
    pub epa: [bool; 2],
    /// Exact retained firmware power inputs; None keeps the historical
    /// explicitly partial generic prefix. Native always supplies Some.
    pub tail: Option<tail::Inputs>,
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
    pub fn partial_programmed(&self) -> Option<Profile> {
        (self.state == State::PartialTssi)
            .then_some(self.channel)
            .flatten()
    }
    pub fn tssi_mode(&self) -> [bool; 2] {
        self.tssi_mode
    }
    pub fn iqk(&self) -> &Iqk {
        &self.iqk
    }
    pub fn tssi(&self) -> &Tssi {
        &self.tssi
    }
    pub fn dpk(&self) -> &Dpk {
        &self.dpk
    }
    fn begin(&mut self, from: &[State]) -> Result<(), Error> {
        if !from.contains(&self.state) {
            return Err(Error::Terminal);
        }
        self.state = State::Busy;
        Ok(())
    }

    /// rtw8852a.c `rtw8852a_rfk_channel(PHY_0)` on `profile`:
    /// `conn_rfk = true`, `rtw8852a_rx_dck(PHY_0, true)` with the
    /// retained `is_tssi_mode`, `rtw8852a_iqk`,
    /// `btc_ntfy_preserve_bt_time(30)`, `rtw8852a_tssi`, 30ms,
    /// `rtw8852a_dpk`, `conn_rfk = false`. No MCC H2C body: Linux A
    /// sends none. A supplied exact tail composes `_tssi_high_power` and
    /// `_tssi_pre_tx`; without it success is `Outcome::PartialTssi` and
    /// `calibrated()` remains None.
    /// 8852A is Wi-Fi 6: a 6GHz channel is refused with
    /// `Error::Policy` by the IQK/DPK/TSSI owners.
    ///
    /// # Safety
    /// Actual RTL8852A PHY0 (non-DBCC) after completed A tables and
    /// `rfk::a::Init::prepare`, retuned to THIS `profile` by the
    /// caller, with exclusive radio ownership and a current channel
    /// grant; Interface enforces current admission at every RFK
    /// access. `inputs` carries the per-device RFK inputs (see
    /// [`ChannelInputs`]).
    pub async unsafe fn rfk_channel(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        inputs: &ChannelInputs<'_>,
    ) -> Result<Outcome, Error> {
        if inputs.tail.is_some_and(|tail| !tail.matches(profile)) {
            return Err(Error::Policy);
        }
        self.begin(&[State::New, State::PartialTssi, State::Calibrated])?;
        self.channel = Some(profile);
        self.conn_rfk = true;
        io.admit()?;
        Access(io).a_channel_rxdck(self.tssi_mode, true).await?;
        // SAFETY: same channel after its RX DCK.
        unsafe { self.iqk.run(io, profile) }.await?;
        Access(io).delay(30_000).await?;
        // A failed TSSI leaves the enable state unknown; the owner is
        // terminal (Busy) and the caller terminalizes the radio.
        // SAFETY: same channel after its IQK.
        unsafe {
            self.tssi.run(
                io,
                profile,
                inputs.calibration,
                inputs.tracking,
                inputs.thermal,
            )
        }
        .await?;
        if let Some(tail) = inputs.tail {
            // SAFETY: same actual channel, prefix and measured source limits;
            // native's outer attempt owns finite restrictive PMAC closure.
            unsafe { self.tssi.finish_tail(io, tail) }.await?;
        }
        self.tssi_mode = self.tssi.results().ok_or(Error::Terminal)?.tssi_mode;
        Access(io).delay(30_000).await?;
        // SAFETY: same channel after its TSSI.
        unsafe {
            self.dpk.run(
                io,
                profile,
                inputs.cut,
                self.tssi_mode,
                inputs.thermal,
                inputs.epa,
            )
        }
        .await?;
        self.conn_rfk = false;
        if self.tssi.complete().is_some() {
            self.state = State::Calibrated;
            Ok(Outcome::Calibrated)
        } else {
            self.state = State::PartialTssi;
            Ok(Outcome::PartialTssi)
        }
    }

    /// rtw8852a_rfk.c `rtw8852a_rfk_band_changed` (`rtw8852a_tssi_scan`
    /// with the retained `is_tssi_mode`): returns without I/O unless
    /// both paths are in TSSI mode. Returns whether it ran.
    ///
    /// # Safety
    /// Same owner as [`Self::rfk_channel`], on the channel just
    /// programmed by the channel owner.
    pub async unsafe fn scan(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        calibration: &Calibration,
        tracking: &Tracking,
        thermal: [u8; 2],
    ) -> Result<bool, Error> {
        if self.state == State::Busy {
            return Err(Error::Terminal);
        }
        // SAFETY: forwarded caller contract.
        let ran = unsafe {
            self.tssi
                .scan(io, profile, calibration, tracking, thermal, self.tssi_mode)
        }
        .await?;
        if ran {
            self.tssi_mode = self.tssi.results().ok_or(Error::Terminal)?.tssi_mode;
            self.state = State::PartialTssi;
        }
        Ok(ran)
    }

    /// rtw8852a_rfk.c `rtw8852a_rfk_track`: `_dpk_track` (with the
    /// retained TSSI `extra_ofst`) then `_tssi_track`.
    ///
    /// # Safety
    /// Same retained owner after actually complete source channel RFK;
    /// a `PartialTssi` outcome is refused before any effect. No concurrent
    /// RFK/PHY/reset/PM owner. `thermal` is the current averaged
    /// thermal per path, read back from `R_TSSI_THER` inside the
    /// owners.
    pub async unsafe fn track(
        &mut self,
        io: &mut impl Interface,
        thermal: [u8; 2],
    ) -> Result<(), Error> {
        if self.state != State::Calibrated {
            return Err(Error::Terminal);
        }
        let extra_ofst = self
            .tssi
            .results()
            .map(|results| results.extra_ofst)
            .unwrap_or_default();
        // SAFETY: caller contract; channel RFK completed.
        unsafe { self.dpk.track(io, thermal, extra_ofst, self.tssi_mode) }.await?;
        // SAFETY: same owner after DPK track.
        unsafe { self.tssi.track(io) }.await
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "a_channel_tests.rs"]
mod tests;
