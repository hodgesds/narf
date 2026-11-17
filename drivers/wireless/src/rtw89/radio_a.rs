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
//! Programmed only: channel RFK still requires live thermal/TSSI inputs,
//! so [`Radio::channel`] and native ordinary readiness stay unset.
use super::{
    channel_a, factory_a, radio_init,
    radio_power::initial_reference,
    radio_table::Pair,
    rfk::{self, a::Init, Error, Interface},
};
use alloc::vec::Vec;

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

#[derive(Default)]
pub(super) struct Radio {
    state: State,
    init: Init,
    channel: channel_a::Channel,
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
    /// No channel-RFK completion yet. Programmed does not establish
    /// calibrated RF or ordinary station/AP readiness.
    pub fn channel(&self) -> Option<super::operating_channel::Profile> {
        None
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
        let cut = identity.cut();
        radio_init::controls_a(io, cut).map_err(radio_error)?;
        // SAFETY: caller contract; directly after the A bb_sethw above.
        unsafe { operating.prepare_a(io, identity) }.await?;
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
    /// prefix succeeds; failed/cancelled attempts remain non-Ready.
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
        if self.state != State::Ready {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        // SAFETY: caller contract; retained A init completed above.
        unsafe { self.channel.set_channel(io, profile, power) }.await?;
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_a/tests.rs"]
mod tests;
