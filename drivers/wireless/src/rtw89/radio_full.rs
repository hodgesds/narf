// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained exact initial B radio composition. The native caller binds every
//! input to actual factory/firmware and full measured current qualification.
use super::{
    channel_bb, channel_rf, channel_transition, dpk, factory_b, iqk, power, radio_gain,
    radio_power, radio_trim, rfk, tssi,
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
        // SAFETY: no live retune; hold source scheduler/ADC/reset bracket exclusively.
        unsafe { self.transition.enter(io).await }.map_err(error)?;
        // SAFETY: actual source-selected gains and fixed channel1/20MHz profile.
        unsafe {
            self.bb
                .prepare(io, input.gain, input.calibration, input.gain_bases)
                .await
        }
        .map_err(|e| match e {
            channel_bb::Error::Register(e) => e,
            channel_bb::Error::Terminal => power::Error::Terminal,
            channel_bb::Error::Policy => power::Error::Access,
        })?;
        // SAFETY: same bracket; signed full recipe includes all source LCK recovery.
        unsafe { self.rf.prepare(io).await }.map_err(|e| match e {
            channel_rf::Error::Register(e) => e,
            channel_rf::Error::Rfk(e) => error(e),
            channel_rf::Error::Terminal => power::Error::Terminal,
        })?;
        // SAFETY: concrete source configuration is bound by the full measured grant.
        unsafe { self.power.prepare(io, input.power) }.map_err(error)?;
        // SAFETY: MAC/BB/RF/channel power all completed on this same owner/backend.
        unsafe { self.transition.finish(io).await }.map_err(error)?;
        // SAFETY: fresh channel RXDCK occurs before TSSI is enabled, matching source.
        unsafe { self.rxdck.prepare(io).await }.map_err(error)?;
        // SAFETY: full source IQK stays under actual current measured engine authority.
        unsafe { self.iqk.prepare(io).await }.map_err(error)?;
        // Linux waits here for an existing A2DP peer. This WLAN-only initial profile
        // cannot assert BT absence, so conservatively preserve the complete30ms.
        rfk::Interface::admit(io).map_err(error)?;
        io.delay_us(30_000).await;
        rfk::Interface::admit(io).map_err(error)?;
        // SAFETY: actual factory/tracking/gain bases; measured full PMAC48/20 recipe.
        unsafe {
            self.tssi
                .prepare(io, input.calibration, input.tracking, input.gain_bases)
                .await
        }
        .map_err(error)?;
        rfk::Interface::admit(io).map_err(error)?;
        io.delay_us(30_000).await;
        rfk::Interface::admit(io).map_err(error)?;
        // SAFETY: actual corrected cut/basic backoff decision, completed retainedTSSI.
        unsafe {
            self.dpk
                .prepare(io, input.cut, input.dpd_gain, &self.tssi)
                .await
        }
        .map_err(error)?;
        rfk::Interface::admit(io).map_err(error)?;
        self.state = State::Ready;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_full/tests.rs"]
mod tests;
