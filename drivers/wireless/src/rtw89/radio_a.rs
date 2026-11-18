// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained RTL8852A (MAC_0/PHY_0, non-DBCC) radio composition after the
//! RTL8852A BB/RF tables: the RTL8852A part of phy.c `rtw89_phy_dm_init`,
//! mirroring the RTL8852C `radio_c` / RTL8851B `radio_51` owners.
//!
//! Order (Linux core.c `rtw89_core_start` -> phy.c `rtw89_phy_dm_init`):
//! `rtw8852a_bb_sethw` (`radio_init::controls_a`), the phy.c DM sub-inits
//! (PHYSTS/DIG/CFO/EDCCA through `phy_operating::Operating::prepare_a`),
//! `rtw89_phy_init_rf_nctl` (`radio_init::nctl_a`; `rfk_hw_init` and
//! `rfe_gpio` are NULL for A), `rtw8852a_rfk_init` (`rfk::a::Init`),
//! `rtw8852a_set_txpwr_ctrl` (`rtw8852a_set_txpwr_ref`, the same
//! `radio_power::initial_reference` words as B) and `rtw8852a_power_trim`
//! (thermal + PA bias trim). `rtw8852a.c` `.cfg_txrx_path` is NULL, so
//! there is no txrx-path step and no `RF_GET_MCCCH` body.
//!
//! After this init, [`Radio::program_channel`] composes A MAC/BB/RF
//! channel control and the qualified per-channel power plan. This yields
//! Programmed only, plus actual factory FEM and live non-TSSI thermal
//! observations. [`Radio::complete_channel`] then composes RXDCK/IQK,
//! complete TSSI/PMAC and DPK from those actual inputs. Only its positive
//! retained receipts permit channel publication; physical acceptance is separate.
use super::{
    channel_a, factory_a, radio_init,
    radio_power::initial_reference,
    radio_table::Pair,
    rfk::{self, a::Init, Error, Interface},
};
use alloc::vec::Vec;
#[path = "radio_a/observations.rs"]
pub(super) mod observations;
#[path = "radio_a/stop.rs"]
pub(super) mod stop;
pub(in crate::rtw89) const RETUNE_RECIPE: &[u8] = b"RTL8852A retained complete native retune v1; actual current original A grant, queues/backlog/core drained/awake, target exact N5AC selected and old ordinary epoch withheld; source get_thermal TSSI BB1c10/3c10 bits29:24 with retained EWMA; source A channel/help/power, band-change TSSI scan from existing state, full RXDCK IQK TSSI high/preTX DPK; retained FEM/trim/TSSI/DPK histories and current scheduler; strict fresh preTX receipts; source same-owner epoch publication, no B alias or reconstructed owner";

/// RR_TM2 / RR_TM2_OFF, RR_BIASA / RR_BIASA_TXG / RR_BIASA_TXA (reg.h).
const RR_TM2: (u32, u32) = (0x43, 0xf_0000);
const RR_BIASA: u32 = 0x60;
const RR_BIASA_TXG: u32 = 0xf000;
const RR_BIASA_TXA: u32 = 0xf_0000;

/// `rtw8852a_power_trim`: `rtw8852a_thermal_trim` (RR_TM2 OFF per path,
/// only with programmed PHY-cap thermal trim) then `rtw8852a_pa_bias_trim`
/// (RR_BIASA TXG/TXA per path, only with programmed PA bias trim), as
/// (path, RF address, mask, value).
pub(super) fn power_trim_writes(calibration: &factory_a::Calibration) -> Vec<(u8, u32, u32, u32)> {
    let mut out = Vec::new();
    for path in 0..2u8 {
        if let Some(value) = calibration.thermal_setting(usize::from(path)) {
            out.push((path, RR_TM2.0, RR_TM2.1, u32::from(value)));
        }
    }
    for path in 0..2u8 {
        if let Some((g, a)) = calibration.pa_bias_setting(usize::from(path)) {
            out.push((path, RR_BIASA, RR_BIASA_TXG, u32::from(g)));
            out.push((path, RR_BIASA, RR_BIASA_TXA, u32::from(a)));
        }
    }
    out
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Ready,
}

/// Actual A factory calibration for initial DM/RFK. Per-channel power
/// is supplied separately to `program_channel`; live channel-RFK inputs
/// remain separate from both initialization and channel programming.
pub(super) struct Inputs<'a> {
    pub calibration: &'a factory_a::Calibration,
}
pub(super) struct ChannelInputs<'a> {
    pub calibration: &'a factory_a::Calibration,
    pub tracking: &'a rfk::a_tssi::Tracking,
    pub tail: rfk::a_tssi::tail::Inputs,
}

#[derive(Default)]
pub(super) struct Radio {
    state: State,
    init: Init,
    channel: channel_a::Channel,
    rfk: rfk::a_channel::Channel,
    cut: Option<u8>,
    fem: Option<factory_a::Fem>,
    observations: observations::Observations,
    tracking: Option<alloc::boxed::Box<super::track::Tracker>>,
    epoch: u32,
}

fn radio_error(e: radio_init::Error) -> Error {
    match e {
        radio_init::Error::Register(e) => Error::Register(e),
        radio_init::Error::Terminal => Error::Terminal,
        _ => Error::Table,
    }
}

impl Radio {
    pub fn state(&self) -> State {
        self.state
    }
    /// Only the actual full RFK channel, while the source owner is Ready.
    pub fn channel(&self) -> Option<super::operating_channel::Profile> {
        if self.state != State::Ready {
            return None;
        }
        let actual = self.rfk.calibrated()?;
        let programmed = self.channel.programmed()?;
        (actual.primary() == programmed.primary()
            && actual.center() == programmed.center()
            && actual.width().mhz() == programmed.width().mhz()
            && (actual.band() == super::operating_channel_c::Band::Ghz5) == programmed.is_5ghz())
        .then_some(programmed)
    }
    pub fn programmed_channel(&self) -> Option<super::operating_channel::Profile> {
        if self.state == State::Ready {
            self.channel.programmed()
        } else {
            None
        }
    }
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    pub fn init(&self) -> &Init {
        &self.init
    }
    pub fn fem(&self) -> Option<factory_a::Fem> {
        self.fem
    }
    pub fn observations(&self) -> Option<observations::Snapshot> {
        (self.state == State::Ready)
            .then(|| self.observations.snapshot())
            .flatten()
    }

    /// `rtw8852a_bb_sethw` (`radio_init::controls_a`), the phy.c DM
    /// sub-inits (`phy_operating::Operating::prepare_a`) and
    /// `rtw89_phy_init_rf_nctl` (`radio_init::nctl_a` with the selected
    /// firmware NCTL table), before any RFK admission (as B's
    /// `prepare_basic_rfk` runs `controls` and `nctl` before the RFK owner).
    ///
    /// # Safety
    /// Actual RTL8852A PHY_0 after completed A `radio_init::Init` tables
    /// on the same retained owner, CMAC TX and ordinary DMA closed,
    /// exclusive radio/reset/PM ownership. Failure leaves the radio
    /// non-Ready and the enclosing native owner terminalizes it.
    pub async unsafe fn prepare_controls(
        &mut self,
        io: &mut impl super::phy_operating::Interface,
        operating: &mut super::phy_operating::Operating,
        identity: super::factory::Identity,
        nctl: &[Pair],
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        if identity.chip() != super::mac::ChipId::Rtl8852A {
            return Err(Error::Table);
        }
        self.state = State::Preparing;
        self.fem = Some(factory_a::Fem::from_identity(identity).ok_or(Error::Table)?);
        let cut = identity.cut();
        self.cut = Some(cut);
        radio_init::controls_a(io, cut).map_err(radio_error)?;
        // SAFETY: caller contract; directly after the A bb_sethw above.
        unsafe { operating.prepare_a(io, identity) }.await?;
        self.tracking = Some(operating.take_a_tracker().ok_or(Error::Terminal)?);
        radio_init::nctl_a(io, nctl).await.map_err(radio_error)?;
        self.state = State::New;
        Ok(())
    }

    /// The rest of dm_init (module docs), after [`Self::prepare_controls`]:
    /// `rtw8852a_rfk_init`, `rtw8852a_set_txpwr_ctrl` and
    /// `rtw8852a_power_trim`. No `bb_cfg_txrx_path`, no channel program,
    /// no `RF_GET_MCCCH`.
    ///
    /// # Safety
    /// Same owner directly after [`Self::prepare_controls`]; Interface
    /// admission is checked before every access. Failure or cancellation
    /// leaves the radio non-Ready and the enclosing native owner
    /// terminalizes it.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        input: Inputs<'_>,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        io.admit()?;
        // SAFETY: caller contract; A tables, bb_sethw and NCTL completed.
        unsafe { self.init.prepare(io) }.await?;
        if self.init.state() != rfk::State::BasicCalibrated {
            return Err(Error::Terminal);
        }
        // `rtw8852a_set_txpwr_ctrl` = `rtw8852a_set_txpwr_ref(PHY_0, 0)`:
        // the same R_AX_PWR_RATE_CTRL / 0x5804.. words as B.
        // SAFETY: same owner; reference control only.
        unsafe { initial_reference(io) }?;
        for (path, address, mask, value) in power_trim_writes(input.calibration) {
            io.admit()?;
            io.rf_write(path, address, mask, value).await?;
        }
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }

    /// Source A channel control and `set_txpwr` after the completed A
    /// init. The source help window is closed only after the exact power
    /// prefix succeeds. Then take the separately measured live non-TSSI
    /// observations; failed/cancelled attempts remain non-Ready. The
    /// observation is after the help exit, not the source's initial
    /// dm_init thermal sample, and supplies no TSSI-mode completion.
    ///
    /// # Safety
    /// Same retained A owner as `prepare`, with ordinary TX/autonomous
    /// responses closed. Actual A firmware power elements and current
    /// signed channel/calibration authority cover this typed profile.
    /// This does not execute or claim complete channel RFK.
    pub async unsafe fn program_channel(
        &mut self,
        io: &mut impl Interface,
        profile: super::operating_channel::Profile,
        power: &super::radio_power_c::Plan,
    ) -> Result<(), Error> {
        if self.state != State::Ready || self.rfk.tssi_mode() != [false, false] {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        // SAFETY: caller contract; retained A init completed above.
        unsafe { self.channel.set_channel(io, profile, power) }.await?;
        // SAFETY: same original A owner after rfk_init, with no TSSI
        // producer since; only channel control ran, and TX stays closed.
        unsafe { self.observations.non_tssi(io) }.await?;
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }
    pub fn channel_rfk(&self) -> &rfk::a_channel::Channel {
        &self.rfk
    }
    /// # Safety
    /// Same current original owner after program_channel, with exact source
    /// factory/tracking/power inputs and fresh measured PMAC/whole-RFK scope.
    /// The enclosing native Attempt closes A PMAC/BB on failure/drop; no
    /// station, packet, reset, IRQ or competing RF producer may run.
    pub async unsafe fn complete_channel(
        &mut self,
        io: &mut impl Interface,
        input: ChannelInputs<'_>,
    ) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let profile = self.channel.programmed().ok_or(Error::Terminal)?;
        let thermal = self.observations.snapshot().ok_or(Error::Terminal)?.average;
        if thermal.iter().any(|&v| v == 0 || v > 63) {
            return Err(Error::Policy);
        }
        let fem = self.fem.ok_or(Error::Terminal)?;
        let cut = self.cut.ok_or(Error::Terminal)?;
        let target = input.tail.profile();
        if target.primary() != profile.primary()
            || target.center() != profile.center()
            || target.width().mhz() != profile.width().mhz()
            || (target.band() == super::operating_channel_c::Band::Ghz5) != profile.is_5ghz()
        {
            return Err(Error::Policy);
        }
        // SAFETY: target geometry matches this owner's programmed channel;
        // cut, FEM and bounded nonzero thermal history were retained here.
        // The caller supplies the exact measured calibration/tracking/tail
        // inputs, and Interface rechecks original current authority per access.
        // The outer native Attempt owns terminal closure and DMA retention.
        let outcome = unsafe {
            self.rfk.rfk_channel(
                io,
                target,
                &rfk::a_channel::ChannelInputs {
                    calibration: input.calibration,
                    tracking: input.tracking,
                    cut,
                    thermal,
                    epa: fem.epa,
                    tail: Some(input.tail),
                },
            )
        }
        .await?;
        if outcome != rfk::a_channel::Outcome::Calibrated
            || self.rfk.calibrated().is_none()
            || (!self.rfk.dpk().bypassed()
                && self
                    .rfk
                    .dpk()
                    .results()
                    .ok_or(Error::Terminal)?
                    .iter()
                    .any(|p| !p.path_ok))
        {
            return Err(Error::Policy);
        }
        let pre_tx = self.rfk.tssi().complete().ok_or(Error::Terminal)?;
        // Linux logs unavailable pre-TX data and continues. Native ordinary
        // admission is stricter: require actual counter advance and both
        // measured nonzero default offsets, never implicit source zero state.
        if pre_tx.before == pre_tx.after
            || pre_tx
                .default_txagc
                .iter()
                .any(|value| !matches!(value, Some(v) if *v != 0))
        {
            return Err(Error::Policy);
        }
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }
    /// # Safety
    /// Same retained complete A radio with ordinary publication withdrawn,
    /// actual queues drained and awake, and exact new current signed A
    /// channel grant. No packet/reset/PM producer; outer Attempt closes on loss.
    pub async unsafe fn retune(
        &mut self,
        io: &mut impl Interface,
        profile: super::operating_channel::Profile,
        power: &super::radio_power_c::Plan,
        input: ChannelInputs<'_>,
    ) -> Result<(), Error> {
        if self.state != State::Ready
            || self.channel().is_none()
            || self.rfk.tssi_mode() != [true, true]
        {
            return Err(Error::Terminal);
        }
        let old = self.channel().ok_or(Error::Terminal)?;
        if power.channel() != input.tail.profile()
            || power.channel().primary() != profile.primary()
            || power.channel().center() != profile.center()
            || power.channel().width().mhz() != profile.width().mhz()
        {
            return Err(Error::Policy);
        }
        self.state = State::Preparing;
        // SAFETY: actual same-owner complete TSSI receipt/modes above.
        unsafe { self.observations.tssi(io) }.await?;
        let thermal = self.observations.snapshot().ok_or(Error::Terminal)?.average;
        // SAFETY: the full retained A channel and TSSI modes were verified;
        // target plan/tail geometry agrees. The sole original caller withdrew
        // ordinary publication and retains the help-window/scheduler owner
        // through failure or cancellation under current Interface admission.
        unsafe { self.channel.set_channel(io, profile, power) }.await?;
        if old.is_5ghz() != profile.is_5ghz() {
            // Source __set_channel help exit -> rfk_band_changed -> tssi_scan.
            // SAFETY: target channel/help programming just completed on this
            // owner, whose actual TSSI modes and thermal history are retained.
            // Calibration/tracking are the caller's same qualified sources;
            // no competing RF/reset/packet producer may run during this scan.
            unsafe {
                self.rfk.scan(
                    io,
                    power.channel(),
                    input.calibration,
                    input.tracking,
                    thermal,
                )
            }
            .await?;
        }
        self.state = State::Ready;
        // SAFETY: target channel/help and any band scan completed on this same
        // owner, using its actual thermal history and matched target inputs.
        // complete_channel synchronously enters Preparing before effects;
        // current source authority and original RFK/scheduler ownership remain
        // retained, with outer terminal closure on failure or cancellation.
        unsafe { self.complete_channel(io, input) }.await
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_a/tests.rs"]
mod tests;
