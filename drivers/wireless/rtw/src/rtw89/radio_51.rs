// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained RTL8851B (MAC_0/PHY_0, one RF path) radio composition after the
//! RTL8851B BB/RF tables: the RTL8851B part of phy.c `rtw89_phy_dm_init`
//! and the first channel, mirroring the RTL8852C `radio_c` owner.
//!
//! Order (Linux core.c `rtw89_core_start` -> phy.c `rtw89_phy_dm_init`,
//! then core.c `__rtw89_set_channel` and `rtw89_chip_rfk_channel`):
//! `rtw8851b_bb_sethw` (`radio_init::controls_51`), the phy.c DM sub-inits
//! (PHYSTS/DIG/CFO/EDCCA through `phy_operating::Operating::prepare`, whose
//! RTL8852B sequence RTL8851B shares), `rtw8851b_rfe_gpio` +
//! `rtw89_phy_antdiv_*` (composed through `antdiv_51` for
//! `rfe_type % 3 == 2` boards; empty programs otherwise),
//! `rtw89_phy_init_rf_nctl`
//! (`radio_init::nctl_51`; `rfk_hw_init` is NULL), `rtw8851b_rfk_init`
//! (`rfk::n51::Init`), `rtw8851b_set_txpwr_ctrl`
//! (`radio_power_c::reference_51`), `rtw8851b_power_trim` (path-A thermal +
//! PA bias trim), `rtw8851b_bb_cfg_txrx_path`, then
//! `rfk::n51_channel::Channel::set_channel` (incl. `rtw8851b_set_txpwr`)
//! and `rtw8851b_rfk_channel`. RTL8851B sends no RF_GET_MCCCH.
use super::{
    antdiv_51, channel_51, factory_51,
    operating_channel::Profile,
    power,
    radio_gain::Gain,
    radio_init, radio_power_c,
    radio_table::Pair,
    rfk::{
        n51::Init,
        n51_channel::{Channel, State as ChannelState},
        n51_dpk::Track,
        n51_tssi::Tracking,
        Error, Interface,
    },
};
use alloc::vec::Vec;

const PHY: u32 = 0x10000;
/// RR_TM2 / RR_TM2_OFF, RR_BIASA / RR_BIASA_TXG / RR_BIASA_TXA (reg.h).
const RR_TM2: (u32, u32) = (0x43, 0xf_0000);
const RR_BIASA: u32 = 0x60;
const RR_BIASA_TXG: u32 = 0xf000;
const RR_BIASA_TXA: u32 = 0xf_0000;

type Field = (u32, u32, u32);

/// mac.c `rtw89_mac_setup_phycap` on a one-path chip:
/// `hal->ant_diversity = rfe_type % 3 == 2` (rtw8851b.c `rtw8851b_rfe_gpio`
/// additionally requires `rfe_type <= 50`).
pub(super) const fn antenna_diversity(rfe_type: u8) -> bool {
    rfe_type % 3 == 2
}

/// `rtw8851b_bb_cfg_txrx_path` for PHY_0: `rtw8851b_bb_ctrl_rx_path(RF_A)`
/// (R_CHBW_MOD_V1 ANT_RX_SEG0 1, R_FC0_BW_V1 1RCCA SEG0/SEG1 1, HT/VHT MCS
/// limit 0, `B_RXHE_USER_MAX` 4, HE/HE-TB NSS 0, `rtw8851b_set_gain_offset`
/// for the CHANCTX_0 subband, TXPW RSTB MANON|TSSI 1 then 3), the
/// `hal.rx_nss == 1` NSS limits and R_MAC_SEL MAC_SEL_MOD 0. mac.c
/// `rtw89_mac_setup_phycap` clamps `rx_nss` to `chip->rx_nss` = 1, so the
/// rx_nss rewrite always runs on RTL8851B. `default` is the dm_init chandef
/// (chan.c `rtw89_config_default_chandef`: 2.4GHz channel 1).
pub(super) fn txrx_path_fields(default: Profile, inputs: &channel_51::Inputs<'_>) -> Vec<Field> {
    let mut out = alloc::vec![
        (PHY + 0x49c4, 0xf, 1),
        (PHY + 0x49c0, 0x3_c000, 1),
        (PHY + 0x49c0, 0x3c_0000, 1),
        (PHY + 0x0d18, 0x300, 0),
        (PHY + 0x0d18, 0x60_0000, 0),
        (PHY + 0x0d80, 0x3fc0, 4),
        (PHY + 0x0d80, 0x1_c000, 0),
        (PHY + 0x0d80, 0x380_0000, 0),
    ];
    channel_51::gain_offset(default, inputs, &mut out);
    out.push((PHY + 0x58dc, 0xc000_0000, 1));
    out.push((PHY + 0x58dc, 0xc000_0000, 3));
    out.push((PHY + 0x0d18, 0x300, 0));
    out.push((PHY + 0x0d18, 0x60_0000, 0));
    out.push((PHY + 0x0d80, 0x1_c000, 0));
    out.push((PHY + 0x0d80, 0x380_0000, 0));
    out.push((PHY + 0x09a4, 0x1c, 0));
    out
}

/// `rtw8851b_power_trim`: `rtw8851b_thermal_trim` (RR_TM2 OFF on path A,
/// only with programmed PHY-cap thermal trim) then `rtw8851b_pa_bias_trim`
/// (RR_BIASA TXG/TXA, only with programmed PA bias trim), as
/// (path, RF address, mask, value). `RF_PATH_NUM_8851B` = 1.
pub(super) fn power_trim_writes(calibration: &factory_51::Calibration) -> Vec<(u8, u32, u32, u32)> {
    let mut out = Vec::new();
    if let Some(value) = calibration.thermal_setting() {
        out.push((0, RR_TM2.0, RR_TM2.1, u32::from(value)));
    }
    if let Some((g, a)) = calibration.pa_bias_setting() {
        out.push((0, RR_BIASA, RR_BIASA_TXG, u32::from(g)));
        out.push((0, RR_BIASA, RR_BIASA_TXA, u32::from(a)));
    }
    out
}

fn apply(io: &mut impl Interface, address: u32, mask: u32, value: u32) -> Result<(), Error> {
    io.admit()?;
    let new = if mask == u32::MAX {
        value
    } else {
        let old = io.read32(address)?;
        if old == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        (old & !mask) | ((value << mask.trailing_zeros()) & mask)
    };
    io.admit()?;
    io.write32(address, new)?;
    Ok(())
}

fn verify(io: &mut impl Interface, fields: &[Field]) -> Result<(), Error> {
    // Fold overlapping writes: the last write of each bit is the final value.
    let mut expected: Vec<(u32, u32, u32)> = Vec::new();
    for &(address, mask, value) in fields {
        let bits = (value << mask.trailing_zeros()) & mask;
        match expected.iter_mut().find(|e| e.0 == address) {
            Some(e) => {
                e.1 |= mask;
                e.2 = (e.2 & !mask) | bits;
            }
            None => expected.push((address, mask, bits)),
        }
    }
    for (address, mask, bits) in expected {
        io.admit()?;
        let actual = io.read32(address)?;
        if actual == u32::MAX || actual & mask != bits {
            return Err(power::Error::Access.into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Ready,
}

/// Inputs bound by the native caller to the actual RTL8851B factory,
/// firmware and container. `power` must be built for the target channel
/// by `radio_power_c::Plan::from_elements_51`.
pub(super) struct Inputs<'a> {
    pub gain: &'a Gain,
    pub calibration: &'a factory_51::Calibration,
    pub power: &'a radio_power_c::Plan,
    pub tracking: &'a Tracking,
    /// The typed channel `power` was built for.
    pub channel: Profile,
}

#[derive(Default)]
pub(super) struct Radio {
    state: State,
    /// `[efuse_gain.offset_base[PHY_0], efuse_gain.rssi_base[PHY_0]]`.
    bases: Option<[i8; 2]>,
    init: Init,
    channel: Channel,
    track: Option<Track>,
    /// Retained antenna-diversity runtime for `rfe_type % 3 == 2` boards
    /// (`antdiv_51::AntDiv`); `None` for non-diversity boards and before
    /// [`Self::prepare_controls`]. Driven by [`Self::parse_ppdu`] from
    /// the PHYSTS path and by [`Self::track`] on the periodic tick.
    antdiv: Option<antdiv_51::AntDiv>,
    /// An antenna-diversity training run is in progress: `track` /
    /// `step` run once per tick until a decision step ends it.
    antdiv_training: bool,
    /// Requested re-queue period (ms) of the last training step
    /// (`antdiv_51` `TRAINNING_INTVL_MS` 30 / `DELAY_MS` 110); 0 when
    /// no training step is pending. NARF has no sub-second
    /// delayed-work scheduler, so the actual cadence is the 2 s
    /// track tick; the period is recorded for the caller that does.
    antdiv_period_ms: u32,
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
    /// The calibrated channel, only while Ready.
    pub fn channel(&self) -> Option<Profile> {
        (self.state == State::Ready)
            .then(|| self.channel.calibrated())
            .flatten()
    }
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    /// Bases read by `controls_51`.
    pub fn bases(&self) -> Option<[i8; 2]> {
        self.bases
    }
    pub fn init(&self) -> &Init {
        &self.init
    }
    pub fn rfk(&self) -> &Channel {
        &self.channel
    }
    pub fn tracker(&self) -> Option<&Track> {
        self.track.as_ref()
    }
    pub fn antdiv(&self) -> Option<&antdiv_51::AntDiv> {
        self.antdiv.as_ref()
    }
    /// Whether an antenna-diversity training run is in progress.
    pub fn antdiv_training(&self) -> bool {
        self.antdiv_training
    }
    /// Requested re-queue period (ms) of the last training step; 0 when
    /// no training step is pending.
    pub fn antdiv_period_ms(&self) -> u32 {
        self.antdiv_period_ms
    }

    /// phy.c `rtw89_phy_antdiv_parse` hookup: feed one MACID-matched,
    /// to-self PPDU observation into the retained diversity owner.
    /// core.c `rtw89_core_rx_parse_phy_sts` calls it at the end of the
    /// IE walk + RPL-to-RSSI conversion, only on a fully-parsed PHYSTS.
    /// No-op on non-diversity boards and before `prepare_controls`:
    /// there is no retained owner. The caller classifies the PPDU and
    /// gates on MACID/to-self before this point.
    pub fn parse_ppdu(&mut self, observation: super::rx_packet::AntDivObservation) {
        if let Some(antdiv) = self.antdiv.as_mut() {
            antdiv.parse(observation.class, observation.rssi, observation.evm);
        }
    }

    /// One `rtw89_phy_antdiv_work` step on a copied-out owner: program
    /// ANTSEL when the step carries one, record the requested re-queue
    /// period, clear training on a decision.
    fn antdiv_step(
        &mut self,
        io: &mut impl Interface,
        antdiv: &mut antdiv_51::AntDiv,
    ) -> Result<(), Error> {
        match antdiv.step() {
            antdiv_51::Work::Training { period_ms, set_ant } => {
                self.antdiv_period_ms = period_ms;
                if let Some(fields) = set_ant {
                    for &(address, mask, value) in &fields {
                        apply(io, address, mask, value)?;
                    }
                }
            }
            antdiv_51::Work::Decision { set_ant } => {
                self.antdiv_training = false;
                self.antdiv_period_ms = 0;
                for &(address, mask, value) in &set_ant {
                    apply(io, address, mask, value)?;
                }
            }
        }
        Ok(())
    }

    /// One antenna-diversity periodic tick (core.c `rtw89_track_work` ->
    /// phy.c `rtw89_phy_antdiv_track` -> `antdiv_work`): while not
    /// training, a target-RSSI move of at least `RSSI_DIFF_TH` starts
    /// training and runs the first step immediately (Linux queues
    /// `antdiv_work` with period 0); while training, one step per
    /// tick. `track` is deliberately not re-run mid-training: with no
    /// traffic the empty target reads RSSI 0, which would restart
    /// training every tick and it would never complete. A failed
    /// ANTSEL program leaves the radio non-Ready, as a failed DPK
    /// step does.
    fn antdiv_tick(&mut self, io: &mut impl Interface) -> Result<(), Error> {
        let Some(mut antdiv) = self.antdiv else {
            return Ok(());
        };
        if !self.antdiv_training {
            if antdiv.track() == antdiv_51::TrackOutcome::StartTraining {
                self.antdiv_training = true;
                self.antdiv_step(io, &mut antdiv)?;
            }
        } else {
            self.antdiv_step(io, &mut antdiv)?;
        }
        self.antdiv = Some(antdiv);
        Ok(())
    }

    /// `rtw8851b_bb_sethw` (`radio_init::controls_51`), the phy.c DM
    /// sub-inits (`phy_operating::Operating::prepare`), the
    /// `rtw8851b_rfe_gpio`/antenna-diversity owner (`antdiv_51`, for
    /// `rfe_type % 3 == 2` boards) and
    /// `rtw89_phy_init_rf_nctl` (`radio_init::nctl_51` with the selected
    /// firmware NCTL table), before any RFK admission.
    ///
    /// # Safety
    /// Actual RTL8851B PHY_0 after completed RTL8851B `radio_init::Init`
    /// tables on the same retained owner, CMAC TX and ordinary DMA closed,
    /// exclusive radio/reset/PM ownership. Failure leaves the radio
    /// non-Ready and the enclosing native owner terminalizes it.
    pub async unsafe fn prepare_controls(
        &mut self,
        io: &mut impl super::phy_operating::Interface,
        operating: &mut super::phy_operating::Operating,
        identity: super::factory::Identity,
        nctl: &[Pair],
    ) -> Result<(), Error> {
        if self.state != State::New || self.bases.is_some() {
            return Err(Error::Terminal);
        }
        if identity.chip() != super::mac::ChipId::Rtl8851B {
            return Err(Error::Table);
        }
        // `identity` moves into `operating.prepare` below, so the RFE
        // type is captured first.
        let rfe_type = identity.calibration().rfe_type;
        let diversity = antenna_diversity(rfe_type);
        self.state = State::Preparing;
        let bases = radio_init::controls_51(io).map_err(radio_error)?;
        self.bases = Some(bases);
        // SAFETY: caller contract; directly after the RTL8851B bb_sethw.
        unsafe { operating.prepare(io, identity) }.await?;
        // Diversity boards program the antenna-diversity owner between
        // the DM sub-inits and NCTL, in Linux dm_init order: antdiv
        // init (reg_init writes), rfe_gpio, initial set_ant on RF_A.
        // Non-diversity boards skip all three (empty write lists and
        // no retained state).
        if diversity {
            let antdiv = antdiv_51::AntDiv::new(antdiv_51::RF_A, antdiv_51::RF_A);
            antdiv_51::apply_controls(io, &antdiv_51::reg_init_fields())?;
            antdiv_51::apply_controls(io, &antdiv_51::rfe_gpio_fields(rfe_type))?;
            antdiv_51::apply_mac8(io, &antdiv_51::rfe_gpio_mac_fields(rfe_type))?;
            antdiv_51::apply_controls(io, &antdiv.set_ant_fields())?;
            self.antdiv = Some(antdiv);
        }
        radio_init::nctl_51(io, nctl).await.map_err(radio_error)?;
        self.state = State::New;
        Ok(())
    }

    /// The rest of dm_init and the first channel (module docs), after
    /// [`Self::prepare_controls`].
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
        let bases = self.bases.ok_or(Error::Terminal)?;
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        let inputs = channel_51::Inputs {
            gain: input.gain,
            calibration: input.calibration,
            bases,
        };
        let txrx = txrx_path_fields(Profile::INITIAL, &inputs);
        self.state = State::Preparing;
        io.admit()?;
        // SAFETY: caller contract; RTL8851B tables, bb_sethw and NCTL done.
        unsafe { self.init.prepare(io) }.await?;
        let results = self.init.results().ok_or(Error::Terminal)?.clone();
        radio_power_c::reference_51(|a, m, v| apply(io, a, m, v))?;
        for (path, address, mask, value) in power_trim_writes(input.calibration) {
            io.admit()?;
            io.rf_write(path, address, mask, value).await?;
        }
        for &(address, mask, value) in &txrx {
            apply(io, address, mask, value)?;
        }
        verify(io, &txrx)?;
        // SAFETY: caller contract; dm_init completed on this owner.
        unsafe {
            self.channel
                .set_channel(io, input.channel, &inputs, input.power, input.tracking)
        }
        .await?;
        // SAFETY: directly after set_channel on the same owner.
        unsafe {
            self.channel
                .rfk_channel(io, input.calibration, input.tracking)
        }
        .await?;
        if self.channel.state() != ChannelState::Calibrated {
            return Err(Error::Terminal);
        }
        self.track = Some(Track::new(&results));
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }

    /// core.c `rtw89_set_channel` + `rtw89_chip_rfk_channel` on a Ready
    /// radio: `set_channel` (band change runs coex switch-band and the
    /// TSSI scan) then `rtw8851b_rfk_channel`. The init-only reference,
    /// trim and txrx-path steps are not repeated (Linux runs them once).
    ///
    /// # Safety
    /// Same owner as [`Self::prepare`] on a Ready radio; the caller has
    /// drained and closed ordinary TX and every autonomous response.
    pub async unsafe fn retune(
        &mut self,
        io: &mut impl Interface,
        input: Inputs<'_>,
    ) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Terminal);
        }
        let bases = self.bases.ok_or(Error::Terminal)?;
        self.state = State::Preparing;
        let inputs = channel_51::Inputs {
            gain: input.gain,
            calibration: input.calibration,
            bases,
        };
        // SAFETY: caller contract.
        unsafe {
            self.channel
                .set_channel(io, input.channel, &inputs, input.power, input.tracking)
        }
        .await?;
        // SAFETY: directly after set_channel.
        unsafe {
            self.channel
                .rfk_channel(io, input.calibration, input.tracking)
        }
        .await?;
        self.epoch = self.epoch.wrapping_add(1);
        self.state = State::Ready;
        Ok(())
    }

    /// One core.c `rtw89_track_work` RF step (thermal update +
    /// `rtw8851b_rfk_track`, then the antenna-diversity periodic tick
    /// when a diversity owner is retained) on a Ready radio. Linux
    /// skips the work while `rtwdev->scanning`; `scanning` returns
    /// `Ok(false)` with no access. A failed step leaves the tracker
    /// terminal and the radio non-Ready.
    ///
    /// # Safety
    /// Same retained owner on a Ready radio; no concurrent RFK/PHY/reset/
    /// PM owner.
    pub async unsafe fn track(
        &mut self,
        io: &mut impl Interface,
        scanning: bool,
    ) -> Result<bool, Error> {
        if scanning {
            return Ok(false);
        }
        if self.state != State::Ready {
            return Err(Error::Terminal);
        }
        let tracker = self.track.as_mut().ok_or(Error::Terminal)?;
        self.state = State::Preparing;
        // SAFETY: caller contract.
        let ran = unsafe { self.channel.track(io, tracker, false) }.await?;
        self.antdiv_tick(io)?;
        self.state = State::Ready;
        Ok(ran)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_51/tests.rs"]
mod tests;
