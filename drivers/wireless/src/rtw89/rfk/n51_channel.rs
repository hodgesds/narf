// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B MAC_0/PHY_0 channel switch and channel RFK, mirroring the
//! RTL8852C `c_channel` owner on RF path A only:
//! rtw8851b.c `rtw8851b_set_channel_help` (enter/exit), the composed
//! `rtw8851b_set_channel` (`channel_51::program` = MAC + BB, then
//! `channel_rf::Channel::prepare_for_channel_51` = `rtw8851b_set_channel_rf`),
//! `rtw8851b_set_txpwr` (`radio_power_c::Plan::visit_51`) and
//! `rtw8851b_rfk_channel` (`rtw89_btc_ntfy_conn_rfk`, RX DCK, IQK, 30ms BT
//! preserve, TSSI, 30ms, DPK).
//!
//! `Channel::set_channel` is core.c `__rtw89_set_channel` for this owner:
//! help enter, `rtw8851b_set_channel`, `rtw8851b_set_txpwr`, help exit,
//! then on a band change (or the first programmed channel, Linux
//! `!entity_active`) `rtw89_btc_ntfy_switch_band` and
//! `rtw8851b_rfk_band_changed` (`rtw8851b_tssi_scan`, no TSSI-mode gate).
//! Unlike RTL8852B/C, `rtw8851b_rfk_channel` issues no
//! `rtw89_fw_h2c_rf_ntfy_mcc` (rtw8851b.c has no `mcc_get_ch_info`), so this
//! owner returns no RF_GET_MCCCH body.
use super::super::{
    channel_51, channel_rf, factory_51::Calibration, operating_channel::Profile, power,
    radio_power_c,
};
use super::{
    n51::ChannelRxDck,
    n51_dpk::{Dpk, Track},
    n51_iqk::Iqk,
    n51_tssi::{Tracking, Tssi},
    Access, Error, Interface,
};

/// MAC R_AX_PPDU_STAT (MAC_0) and R_AX_HW_RPT_FWD.
const R_AX_PPDU_STAT: u32 = 0xce40;
const R_AX_HW_RPT_FWD: u32 = 0x9c18;
/// `rtw89_mac_cfg_ppdu_status_ax(enable)` full word.
const PPDU_STAT_ON: u32 = 0x2b;
/// R_P0_TXPW_RSTB B_P0_TXPW_RSTB_MANON and R_P0_TSSI_TRK B_P0_TSSI_TRK_EN.
const MANON: (u32, u32) = (0x1_58dc, 1 << 30);
const TSSI_TRK_EN: (u32, u32) = (0x1_5818, 1 << 30);
/// R_ADC_FIFO B_ADC_FIFO_RST.
const ADC_FIFO: (u32, u32) = (0x1_20fc, 0xff00_0000);
/// R_RXCCA B_RXCCA_DIS, R_PD_CTRL B_PD_HIT_DIS.
const RXCCA: (u32, u32) = (0x1_2344, 1 << 31);
const PD_HIT: (u32, u32) = (0x1_0c3c, 1 << 9);
/// R_S0_HW_SI_DIS B_S0_HW_SI_DIS_W_R_TRIG, R_RSTB_ASYNC B_RSTB_ASYNC_ALL.
const HW_SI: (u32, u32) = (0x1_1200, 0x7000_0000);
const RSTB: (u32, u32) = (0x1_0704, 1 << 1);

/// One help step: (absolute address, mask, value) or a delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Step {
    Write(u32, u32, u32),
    Delay(u32),
}

/// `rtw8851b_set_channel_help(enter = true)` after `rtw89_chip_stop_sch_tx`:
/// `rtw89_mac_cfg_ppdu_status(false)`, `rtw8851b_tssi_cont_en_phyidx(false)`
/// (path A: MANON 1, TSSI_TRK_EN 1), `rtw8851b_adc_en(false)`, 40us,
/// `rtw8851b_bb_reset_en(false)` (RXCCA/PD_HIT disable, S0 HW-SI 7, 1us,
/// RSTB_ASYNC 0). RTL8851B has no S1 HW-SI and no DFS step.
pub(in super::super) const HELP_ENTER: [Step; 10] = [
    Step::Write(R_AX_PPDU_STAT, 1, 0),
    Step::Write(MANON.0, MANON.1, 1),
    Step::Write(TSSI_TRK_EN.0, TSSI_TRK_EN.1, 1),
    Step::Write(ADC_FIFO.0, ADC_FIFO.1, 0xf),
    Step::Delay(40),
    Step::Write(RXCCA.0, RXCCA.1, 1),
    Step::Write(PD_HIT.0, PD_HIT.1, 1),
    Step::Write(HW_SI.0, HW_SI.1, 7),
    Step::Delay(1),
    Step::Write(RSTB.0, RSTB.1, 0),
];

/// `rtw8851b_set_channel_help(enter = false)` before `resume_sch_tx`:
/// PPDU status on, `adc_en(true)`, `tssi_cont_en(true)` (MANON 0,
/// TSSI_TRK_EN 0), then `rtw8851b_bb_reset_en(band, true)` (S0 HW-SI 0,
/// RSTB_ASYNC 1, RXCCA enable only on 2.4GHz, PD_HIT enable).
pub(in super::super) fn help_exit(two_ghz: bool) -> alloc::vec::Vec<Step> {
    let mut out = alloc::vec![
        Step::Write(R_AX_PPDU_STAT, u32::MAX, PPDU_STAT_ON),
        Step::Write(R_AX_HW_RPT_FWD, 0x3, 2),
        Step::Write(ADC_FIFO.0, ADC_FIFO.1, 0),
        Step::Write(MANON.0, MANON.1, 0),
        Step::Write(TSSI_TRK_EN.0, TSSI_TRK_EN.1, 0),
        Step::Write(HW_SI.0, HW_SI.1, 0),
        Step::Write(RSTB.0, RSTB.1, 1),
    ];
    if two_ghz {
        out.push(Step::Write(RXCCA.0, RXCCA.1, 0));
    }
    out.push(Step::Write(PD_HIT.0, PD_HIT.1, 0));
    out
}

impl<I: Interface> Access<'_, I> {
    /// Absolute-address masked write (MAC or PHY window) with readback.
    fn n51_step(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.0.admit()?;
        let v = if mask == u32::MAX {
            value
        } else {
            let old = self.0.read32(address)?;
            if old == u32::MAX {
                return Err(power::Error::Gone.into());
            }
            (old & !mask) | ((value << mask.trailing_zeros()) & mask)
        };
        self.0.admit()?;
        self.0.write32(address, v)?;
        self.0.admit()?;
        let actual = self.0.read32(address)?;
        if actual == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        if actual & mask != v & mask {
            return Err(power::Error::Access.into());
        }
        Ok(())
    }
    async fn n51_steps(&mut self, steps: &[Step]) -> Result<(), Error> {
        for &step in steps {
            match step {
                Step::Write(address, mask, value) => self.n51_step(address, mask, value)?,
                Step::Delay(us) => self.delay(u64::from(us)).await?,
            }
        }
        Ok(())
    }
}

fn rf_error(e: channel_rf::Error) -> Error {
    match e {
        channel_rf::Error::Rfk(e) => e,
        channel_rf::Error::Register(e) => e.into(),
        channel_rf::Error::Terminal => Error::Terminal,
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) enum State {
    #[default]
    New,
    Busy,
    /// Channel programmed; channel RFK not yet run.
    Programmed,
    /// `rtw8851b_rfk_channel` completed for the programmed channel.
    Calibrated,
}

/// One retained RTL8851B channel owner: the programmed channel, the
/// retained `is_tssi_mode[RF_PATH_A]` and the channel RFK results.
#[derive(Default)]
pub(in super::super) struct Channel {
    state: State,
    channel: Option<Profile>,
    /// `rtwdev->is_tssi_mode[RF_PATH_A]` (false after `rtw8851b_rfk_init`).
    tssi_mode: bool,
    /// `rtwdev->btc.cx.wl.rfk_info.con_rfk` (state only; no I/O).
    conn_rfk: bool,
    /// 5GHz flag of the last completed `set_channel` (`None` = Linux
    /// `!rtw89_get_entity_state(PHY_0)`).
    band_5ghz: Option<bool>,
    /// Whether the last `set_channel` ran `rtw8851b_tssi_scan`.
    scanned: bool,
    iqk: Iqk,
    tssi: Tssi,
    dpk: Dpk,
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
    pub fn tssi_mode(&self) -> bool {
        self.tssi_mode
    }
    /// Whether the last channel program ran the band-change TSSI scan.
    pub fn scanned(&self) -> bool {
        self.scanned
    }
    /// `rtw89_btc_ntfy_conn_rfk` state (true only inside `rfk_channel`).
    pub fn conn_rfk(&self) -> bool {
        self.conn_rfk
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

    /// core.c `__rtw89_set_channel(MAC_0, PHY_0)` without DBCC:
    /// `rtw8851b_set_channel_help(enter)`, `rtw8851b_set_channel`
    /// (`set_channel_mac`, `set_channel_bb`, `set_channel_rf`),
    /// `rtw8851b_set_txpwr` (`power`, which must be built for `profile` by
    /// `Plan::from_elements_51`), `rtw8851b_set_channel_help(exit)`; then,
    /// when no channel was programmed yet or the band changed,
    /// `rtw89_btc_ntfy_switch_band` (`Interface::coex_switch_band`) and
    /// `rtw8851b_tssi_scan`.
    ///
    /// # Safety
    /// Actual RTL8851B after completed RTL8851B tables, `controls_51`,
    /// `nctl_51` and `rfk::n51::Init::prepare`, with exclusive radio
    /// ownership and a current channel grant for `profile`; Interface
    /// enforces current admission at every RFK access. `tracking` is this
    /// container's TXPWR_TRK and `power` this container's TXPWR program.
    pub async unsafe fn set_channel(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        inputs: &channel_51::Inputs<'_>,
        power: &radio_power_c::Plan,
        tracking: &Tracking,
    ) -> Result<(), Error> {
        let planned = power.channel();
        if planned.center() != profile.center()
            || planned.primary() != profile.primary()
            || planned.width() as u8 != profile.width() as u8
        {
            return Err(Error::Policy);
        }
        self.begin(&[State::New, State::Programmed, State::Calibrated])?;
        self.channel = None;
        self.scanned = false;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        access.n51_steps(&HELP_ENTER).await?;
        access.0.admit()?;
        // SAFETY: caller contract; inside the channel-help window.
        unsafe { channel_51::program(access.0, profile, inputs) }.await?;
        let mut rf = channel_rf::Channel::default();
        // SAFETY: same window, directly after the MAC/BB program.
        unsafe { rf.prepare_for_channel_51(access.0, profile) }
            .await
            .map_err(rf_error)?;
        // `chip->ops->set_txpwr` = `rtw8851b_set_txpwr(chan, PHY_0)`.
        power.visit_51(|a, m, v| access.n51_step(a, m, v))?;
        access.n51_steps(&help_exit(!profile.is_5ghz())).await?;
        access.0.admit()?;
        access.0.resume(saved).await?;
        if self.band_5ghz != Some(profile.is_5ghz()) {
            io.admit()?;
            io.coex_switch_band().await?;
            // SAFETY: caller contract; the channel was just programmed.
            unsafe { self.tssi.scan(io, profile, inputs.calibration, tracking) }.await?;
            self.tssi_mode = self.tssi.results().ok_or(Error::Terminal)?.tssi_mode;
            self.scanned = true;
        }
        self.band_5ghz = Some(profile.is_5ghz());
        self.channel = Some(profile);
        self.state = State::Programmed;
        Ok(())
    }

    /// rtw8851b.c `rtw8851b_rfk_channel(PHY_0)` on the programmed channel:
    /// `conn_rfk = true`, `rtw8851b_rx_dck` with the retained
    /// `is_tssi_mode`, `rtw8851b_iqk`, `rtw89_btc_ntfy_preserve_bt_time(30)`,
    /// `rtw8851b_tssi`, 30ms, `rtw8851b_dpk`, `conn_rfk = false`. This owner
    /// cannot assert A2DP absence, so both BT preserves always wait the
    /// full 30ms (as B/C).
    ///
    /// # Safety
    /// Same owner as [`Self::set_channel`], directly after it.
    /// `calibration`/`tracking` are this device's RTL8851B factory snapshot
    /// and container TXPWR_TRK.
    pub async unsafe fn rfk_channel(
        &mut self,
        io: &mut impl Interface,
        calibration: &Calibration,
        tracking: &Tracking,
    ) -> Result<(), Error> {
        let profile = self.channel.ok_or(Error::Terminal)?;
        self.begin(&[State::Programmed])?;
        self.conn_rfk = true;
        io.admit()?;
        let mut rxdck = ChannelRxDck::default();
        // SAFETY: caller contract; the retained TSSI mode is current.
        unsafe { rxdck.prepare(io, self.tssi_mode) }.await?;
        // SAFETY: caller contract; RX DCK on this programmed channel done.
        unsafe { self.iqk.run(io, profile) }.await?;
        Access(io).delay(30_000).await?;
        // A failed TSSI leaves the enable state unknown; the owner is
        // terminal (Busy) and the caller terminalizes the radio.
        // SAFETY: same channel after its IQK.
        unsafe { self.tssi.run(io, profile, calibration, tracking) }.await?;
        self.tssi_mode = self.tssi.results().ok_or(Error::Terminal)?.tssi_mode;
        Access(io).delay(30_000).await?;
        // SAFETY: same channel after its TSSI.
        unsafe { self.dpk.run(io, profile, self.tssi_mode) }.await?;
        self.conn_rfk = false;
        self.state = State::Calibrated;
        Ok(())
    }

    /// One core.c `rtw89_track_work` RF step on the calibrated channel
    /// (`n51_dpk::Track::step` = thermal update + `rtw8851b_rfk_track`).
    /// Linux skips the whole track work while scanning
    /// (`rtwdev->scanning`); `scanning` returns `Ok(false)` with no access.
    ///
    /// # Safety
    /// Same retained owner after [`Self::rfk_channel`]; no concurrent
    /// RFK/PHY/reset/PM owner.
    pub async unsafe fn track(
        &mut self,
        io: &mut impl Interface,
        tracker: &mut Track,
        scanning: bool,
    ) -> Result<bool, Error> {
        if scanning {
            return Ok(false);
        }
        if self.state != State::Calibrated {
            return Err(Error::Terminal);
        }
        // SAFETY: caller contract; the DPK of this calibrated channel.
        unsafe { tracker.step(io, &self.dpk, self.tssi_mode) }.await?;
        Ok(true)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "n51_channel_tests.rs"]
mod tests;
