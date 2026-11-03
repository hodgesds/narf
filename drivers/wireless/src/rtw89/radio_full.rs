// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained exact B radio composition: initial bring-up plus 2.4/5GHz
//! 20MHz retune of a Ready radio (band change runs the TSSI scan). The typed channel is always the one
//! bound into the selected power plan. The native caller binds every input to
//! actual factory/firmware and full measured current qualification.
use super::{
    channel_bb, channel_rf, channel_transition, dpk, factory_b, iqk, operating_channel::Profile,
    power, radio_gain, radio_power, radio_trim, rfk, tssi,
};
#[path = "radio_full/recipe.rs"]
mod recipe;
pub(super) const RECIPE: [u8; 32] = recipe::RECIPE;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Ready,
}
#[derive(Default)]
pub(super) struct Radio {
    state: State,
    /// Typed primary actually programmed by the last completed attempt.
    channel: Option<Profile>,
    /// Count of completed MAC/BB/RF/power/RFK programs (initial is 1). Any
    /// consumer of earlier channel results must compare this epoch.
    epoch: u32,
    transition: channel_transition::Transition,
    bb: channel_bb::Channel,
    rf: channel_rf::Channel,
    trim: radio_trim::Trim,
    power: radio_power::Power,
    rxdck: rfk::ChannelRxDck,
    iqk: iqk::Iqk,
    tssi: tssi::Tssi,
    dpk: dpk::Dpk,
}
pub(super) struct Inputs<'a> {
    pub gain: &'a radio_gain::Gain,
    pub calibration: &'a factory_b::Calibration,
    pub gain_bases: [i8; 2],
    pub cut: u8,
    pub dpd_gain: u8,
    pub power: &'a radio_power::Plan,
    pub tracking: &'a tssi::Tracking,
}
fn error(e: rfk::Error) -> power::Error {
    match e {
        rfk::Error::Register(e) => e,
        rfk::Error::Terminal => power::Error::Terminal,
        _ => power::Error::Unsupported,
    }
}
impl Radio {
    pub fn state(&self) -> State {
        self.state
    }
    /// The typed channel of the completed program, only while Ready.
    pub(super) fn channel(&self) -> Option<Profile> {
        (self.state == State::Ready)
            .then_some(self.channel)
            .flatten()
    }
    pub(super) fn epoch(&self) -> u32 {
        self.epoch
    }
    pub(super) fn tracking_inputs(&self) -> Option<super::rf_tracking::Inputs> {
        if self.state != State::Ready || self.tssi.results().is_none() {
            return None;
        }
        super::rf_tracking::Inputs::from_completed(*self.dpk.results()?)
    }
    /// # Safety
    /// Same actual initial B native factory/corrected-cut/BB/NCTL/basic RFK owner,
    /// full firmware capability permits TX-A/RX-AB, actual physical inputs and
    /// selected immutable source power/tracking configurations. Signed full v2
    /// measured calibration/packet/all-auto-response maxima and current host
    /// policy gate *every* transition, including independent PMAC/NCTL engines.
    /// Global CMAC TX/ordinary DMA remain closed. The enclosing retained Native
    /// attempt terminalizes and stops engines on failure or dropped future.
    pub async unsafe fn prepare<I: rfk::Interface + channel_bb::Interface>(
        &mut self,
        io: &mut I,
        input: Inputs<'_>,
    ) -> Result<(), power::Error> {
        if self.state != State::New {
            return Err(power::Error::Terminal);
        }
        self.state = State::Preparing;
        rfk::Interface::admit(io).map_err(error)?;
        // SAFETY: same current source-qualified initial power-control prefix.
        unsafe { radio_power::initial_reference(io) }.map_err(error)?;
        // SAFETY: all staged physical bytes belong to this retained actual factory.
        unsafe { self.trim.prepare(io, input.calibration).await }.map_err(error)?;
        // SAFETY: same exact initial RX-AB/NSS2 profile and actual gain bases.
        unsafe { tssi::configure_rx_ab(io, input.calibration, input.gain_bases) }.map_err(error)?;
        // SAFETY: caller contract; initial TSSI is still disabled.
        unsafe { self.program(io, &input, false, false).await }
    }
    /// Linux core.c `__rtw89_set_channel` (prepare, chip set_channel MAC/BB/RF,
    /// set_txpwr, done; a 2.4<->5GHz band change then runs the
    /// `rtw8852b_rfk_band_changed` TSSI scan) followed by
    /// rtw8852b.c `rtw8852b_rfk_channel` (RXDCK, IQK, 30ms, TSSI, 30ms, DPK).
    /// RTL8852B keeps DPK reload disabled and RFK MCC table index0, so every
    /// step is a fresh calibration on the new primary; earlier results retire.
    ///
    /// # Safety
    /// Same retained owner and authority as [`Self::prepare`] on a Ready radio.
    /// The caller has drained/closed ordinary TX, CMAC and autonomous responses,
    /// and the signed full envelope plus current host permission cover the
    /// typed channel bound in `input.power` (its whole occupied span), all its
    /// MAC/BB/RF/RFK emissions and calibration PMAC. Init-only power reference,
    /// trim and RX-AB steps are not repeated (Linux runs them once at init).
    /// Failure/cancellation leaves the radio non-Ready; the enclosing native
    /// owner terminalizes it.
    pub async unsafe fn retune<I: rfk::Interface + channel_bb::Interface>(
        &mut self,
        io: &mut I,
        input: Inputs<'_>,
    ) -> Result<(), power::Error> {
        if self.state != State::Ready {
            return Err(power::Error::Terminal);
        }
        self.state = State::Preparing;
        let previous = self.channel.take();
        self.transition = Default::default();
        self.bb = Default::default();
        self.rf = Default::default();
        self.power = Default::default();
        self.rxdck = Default::default();
        self.iqk = Default::default();
        self.tssi = Default::default();
        self.dpk = Default::default();
        rfk::Interface::admit(io).map_err(error)?;
        // core.c `__rtw89_set_channel`: `chan_rcd->band_changed` runs
        // `rtw89_chip_rfk_band_changed` (TSSI scan) after set_channel_done.
        let band_changed = previous.is_none_or(|old| old.band() != input.power.channel().band());
        // SAFETY: caller contract; the retired retained TSSI is still enabled.
        unsafe { self.program(io, &input, true, band_changed).await }
    }
    async unsafe fn program<I: rfk::Interface + channel_bb::Interface>(
        &mut self,
        io: &mut I,
        input: &Inputs<'_>,
        tssi_mode: bool,
        band_changed: bool,
    ) -> Result<(), power::Error> {
        let channel = input.power.channel();
        // SAFETY: no live retune; hold source scheduler/ADC/reset bracket exclusively.
        unsafe { self.transition.enter(io).await }.map_err(error)?;
        // SAFETY: actual source-selected gains and the plan's typed 2.4GHz/20 profile.
        unsafe {
            self.bb
                .prepare_for_channel(io, input.gain, input.calibration, input.gain_bases, channel)
                .await
        }
        .map_err(|e| match e {
            channel_bb::Error::Register(e) => e,
            channel_bb::Error::Terminal => power::Error::Terminal,
            channel_bb::Error::Policy => power::Error::Access,
        })?;
        // SAFETY: same bracket; signed full recipe includes all source LCK recovery.
        unsafe { self.rf.prepare_for_channel(io, channel).await }.map_err(|e| match e {
            channel_rf::Error::Register(e) => e,
            channel_rf::Error::Rfk(e) => error(e),
            channel_rf::Error::Terminal => power::Error::Terminal,
        })?;
        // SAFETY: concrete source configuration is bound by the full measured grant.
        unsafe { self.power.prepare(io, input.power) }.map_err(error)?;
        // SAFETY: MAC/BB/RF/channel power all completed on this same owner/backend.
        unsafe { self.transition.finish(io).await }.map_err(error)?;
        if band_changed {
            // core.c order: rtw89_btc_ntfy_switch_band, then
            // rtw89_chip_rfk_band_changed. WLAN-only coex re-executes its
            // fixed WONLY grant (no policy H2C; see `coex_switch_band`).
            io.coex_switch_band().await.map_err(error)?;
            // SAFETY: same owner after this channel's MAC/BB/RF/power; TSSI
            // configuration only.
            unsafe { tssi::band_scan(io, input.calibration, input.tracking, channel).await }
                .map_err(error)?;
        }
        // SAFETY: fresh channel RXDCK precedes this attempt's TSSI, matching source;
        // a retune pauses the previous channel's still-enabled TSSI tracking.
        unsafe { self.rxdck.prepare_with_tssi(io, tssi_mode).await }.map_err(error)?;
        // SAFETY: full source IQK stays under actual current measured engine authority.
        unsafe { self.iqk.prepare_for_channel(io, channel).await }.map_err(error)?;
        // Linux waits here for an existing A2DP peer. This WLAN-only initial profile
        // cannot assert BT absence, so conservatively preserve the complete30ms.
        rfk::Interface::admit(io).map_err(error)?;
        io.delay_us(30_000).await;
        rfk::Interface::admit(io).map_err(error)?;
        // SAFETY: actual factory/tracking/gain bases; measured full PMAC48/20 recipe.
        unsafe {
            self.tssi
                .prepare_for_channel(
                    io,
                    input.calibration,
                    input.tracking,
                    input.gain_bases,
                    channel,
                )
                .await
        }
        .map_err(error)?;
        rfk::Interface::admit(io).map_err(error)?;
        io.delay_us(30_000).await;
        rfk::Interface::admit(io).map_err(error)?;
        // SAFETY: actual corrected cut/basic backoff decision, completed retainedTSSI.
        unsafe {
            self.dpk
                .prepare_for_channel(io, input.cut, input.dpd_gain, &self.tssi, channel)
                .await
        }
        .map_err(error)?;
        rfk::Interface::admit(io).map_err(error)?;
        self.channel = Some(channel);
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_full/tests.rs"]
mod tests;
