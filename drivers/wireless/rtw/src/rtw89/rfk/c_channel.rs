// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C MAC_0/PHY_0 (non-DBCC) channel switch around the C BB program:
//! rtw8852c.c `rtw8852c_set_channel_help` (enter/exit),
//! rtw8852c_rfk.c `rtw8852c_set_channel_rf` (`_ctrl_ch`, `_ctrl_bw`,
//! `_rxbb_bw`), the composed `rtw8852c_set_channel` (MAC, BB, RF) and
//! rtw8852c.c `rtw8852c_rfk_channel` (`rtw8852c_mcc_get_ch_info`,
//! `rtw89_btc_ntfy_conn_rfk`, RX DCK, IQK, 30ms BT preserve, TSSI, 30ms,
//! DPK, `rtw89_fw_h2c_rf_ntfy_mcc` V0 body).
//!
//! `Channel::set_channel` is core.c `__rtw89_set_channel` for this owner:
//! help enter, `rtw8852c_set_channel`, `rtw8852c_set_txpwr`
//! (`radio_power_c::Plan`), help exit, then on a band change (or the first
//! programmed channel, Linux `!entity_active`) `rtw89_btc_ntfy_switch_band`
//! and `rtw8852c_rfk_band_changed` (`rtw8852c_tssi_scan`).
use super::super::{
    channel_c,
    factory_c::Calibration,
    operating_channel_c::{Band, Profile, Width},
    power, radio_power_c,
};
use super::{
    c_dpk::Dpk,
    c_iqk::Iqk,
    c_tssi::{Tracking, Tssi},
    Access, Error, Interface,
};

const RFREG_MASK: u32 = 0xfffff;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_CFGCH: u32 = 0x18;
const RR_CFGCH_V1: u32 = 0x10018;
const RR_CFGCH_BW: u32 = 0xc00;
const RR_CFGCH_BAND1: u32 = 0x3_0000;
const RR_CFGCH_BAND0: u32 = 0x300;
const RR_CFGCH_CH: u32 = 0xff;
const RR_APK: u32 = 0x19;
const RR_APK_MOD: u32 = 0x30;
const RR_LUTWE2: u32 = 0xee;
const RR_LUTWE2_RTXBW: u32 = 1 << 2;
const RR_LUTWA: u32 = 0x33;
const RR_LUTWA_M2: u32 = 0x1f;
const RR_LUTWD0: u32 = 0x3f;
const RR_LUTWD0_LB: u32 = 0x3f;
const RR_RXBB2: u32 = 0x8f;
const RR_RXBB2_EBW: u32 = 0x60;
/// R_P0_CFCH_BW0 / B_P0_CFCH_BW0 and R_P0_CFCH_BW1 / B_P0_CFCH_BW1.
const CFCH_BW0: (u32, u32) = (0xc0d4, 0x0c00_0000);
const CFCH_BW1: (u32, u32) = (0xc0d8, 0x1e0);

/// MAC R_AX_PPDU_STAT (MAC_0) and R_AX_HW_RPT_FWD.
const R_AX_PPDU_STAT: u32 = 0xce40;
const R_AX_HW_RPT_FWD: u32 = 0x9c18;
/// `rtw89_mac_cfg_ppdu_status_ax(enable)` full word.
const PPDU_STAT_ON: u32 = 0x2b;

/// One help step: (absolute address, mask, value) or a delay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) enum Step {
    Write(u32, u32, u32),
    Delay(u32),
}

/// `rtw8852c_set_channel_help(enter = true)` after `rtw89_chip_stop_sch_tx`:
/// PPDU status off, `rtw8852c_dfs_en(false)`, `rtw8852c_tssi_cont_en_phyidx
/// (false)` (A, B), `rtw8852c_adc_en(false)`, 40us,
/// `rtw8852c_bb_reset_en(false)`.
pub(in super::super) const HELP_ENTER: [Step; 14] = [
    Step::Write(R_AX_PPDU_STAT, 1, 0),
    Step::Write(0x1_0000, 1 << 31, 0),
    Step::Write(0x1_5818, 1 << 30, 1),
    Step::Write(0x1_5820, 1 << 31, 1),
    Step::Write(0x1_7818, 1 << 30, 1),
    Step::Write(0x1_7820, 1 << 31, 1),
    Step::Write(0x1_20fc, 0xff00_0000, 0xf),
    Step::Delay(40),
    Step::Write(0x1_2320, 1, 1),
    Step::Write(0x1_0c3c, 1 << 9, 1),
    Step::Write(0x1_1200, 0x7000_0000, 7),
    Step::Write(0x1_3200, 0x7000_0000, 7),
    Step::Delay(1),
    Step::Write(0x1_0704, 1 << 1, 0),
];

/// `rtw8852c_set_channel_help(enter = false)` up to the TSSI continue
/// (PPDU status on, `adc_en(true)`, `dfs_en(true)`).
pub(in super::super) const HELP_EXIT_HEAD: [Step; 4] = [
    Step::Write(R_AX_PPDU_STAT, u32::MAX, PPDU_STAT_ON),
    Step::Write(R_AX_HW_RPT_FWD, 0x3, 2),
    Step::Write(0x1_20fc, 0xff00_0000, 0),
    Step::Write(0x1_0000, 1 << 31, 1),
];

/// `rtw8852c_bb_reset_en(band, true)`.
pub(in super::super) fn help_exit_reset(band: Band) -> alloc::vec::Vec<Step> {
    let mut out = alloc::vec![
        Step::Write(0x1_1200, 0x7000_0000, 0),
        Step::Write(0x1_3200, 0x7000_0000, 0),
        Step::Write(0x1_0704, 1 << 1, 1),
    ];
    if band == Band::Ghz2 {
        out.push(Step::Write(0x1_2320, 1, 0));
    }
    out.push(Step::Write(0x1_0c3c, 1 << 9, 0));
    out
}

/// `_ch_setting` RF18 word for `central_ch`/band over an old word.
pub(in super::super) fn rf18_channel(old: u32, profile: Profile) -> u32 {
    let (band1, band0) = match profile.band() {
        Band::Ghz2 => (0, 0),
        Band::Ghz5 => (1, 1),
        Band::Ghz6 => (3, 0),
    };
    (old & !(RR_CFGCH_BAND1 | RR_CFGCH_BAND0 | RR_CFGCH_CH))
        | u32::from(profile.center())
        | (band1 << 16)
        | (band0 << 8)
}

/// `_bw_setting`: (RF18 BW field, CFCH_BW0/CFCH_BW1 pair). Linux's
/// `default:` arm clears the RF18 BW bits (0) and performs no CFCH
/// write at all, so 320MHz carries no CFCH pair (`None`); the caller
/// still writes the RF18 word with the BW bits cleared.
pub(in super::super) fn bw_setting(width: Width) -> (u32, Option<(u32, u32)>) {
    match width {
        Width::Mhz20 => (3, Some((0x3, 0xf))),
        Width::Mhz40 => (2, Some((0x3, 0xf))),
        Width::Mhz80 => (1, Some((0x2, 0xd))),
        Width::Mhz160 => (0, Some((0x1, 0xb))),
        Width::Mhz320 => (0, None),
    }
}

/// `_set_rxbb_bw` LUT value and `_set_tia_bw` RR_RXBB2_EBW.
/// Linux `_set_rxbb_bw` falls to `default:` (0x3, the 160MHz LUT
/// value) for 320MHz, and `_set_tia_bw` writes EBW 2 for any width
/// other than 160MHz.
pub(in super::super) fn rxbb_bw(width: Width) -> (u32, u32) {
    match width {
        Width::Mhz20 => (0x1b, 2),
        Width::Mhz40 => (0x13, 2),
        Width::Mhz80 => (0xb, 2),
        Width::Mhz160 => (0x3, 0),
        Width::Mhz320 => (0x3, 2),
    }
}

/// `_ctrl_ch` range guard: true when Linux programs `central_ch`.
fn ctrl_ch_in_range(profile: Profile) -> bool {
    let ch = profile.center();
    if profile.band() != Band::Ghz6 {
        !((ch > 14 && ch < 36) || (ch > 64 && ch < 100) || (ch > 144 && ch < 149) || ch > 177)
    } else {
        !(ch > 253 || ch == 2)
    }
}

/// `rtw89_fw_h2c_rf_ntfy_mcc` body with `RFK_NTFY_MCC_V0` (fw.c
/// `__CFG_FW_FEAT(RTL8852C, ge, 0, 0, 0, 0, RFK_NTFY_MCC_V0)`):
/// `rtw89_fw_h2c_rf_get_mccch_v0` {ch_0, ch_1, band_0, band_1,
/// current_channel, current_band_type}. `rtw8852c_mcc_get_ch_info` for the
/// single channel context always selects table index 0 (slot 1 never
/// holds a live channel), so slot 1 stays zero.
pub(in super::super) fn mccch_v0(profile: Profile) -> [u8; 24] {
    let ch = u32::from(profile.center());
    let band = profile.band() as u32;
    let mut out = [0u8; 24];
    for (at, value) in [(0, ch), (8, band), (16, ch), (20, band)] {
        out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    out
}

impl<I: Interface> Access<'_, I> {
    /// Absolute-address masked write (MAC or PHY window) with readback.
    fn c_step(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
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
    async fn c_steps(&mut self, steps: &[Step]) -> Result<(), Error> {
        for &step in steps {
            match step {
                Step::Write(address, mask, value) => self.c_step(address, mask, value)?,
                Step::Delay(us) => self.delay(u64::from(us)).await?,
            }
        }
        Ok(())
    }
    /// rtw8852c_rfk.c `rtw8852c_ctrl_bw_ch(PHY_0)` (`_kpath` = RF_AB, no
    /// DBCC): `_ctrl_ch`, `_ctrl_bw` (incl. the CAV path-B RF18 copy),
    /// `_rxbb_bw`; the final RF18 words are read back.
    async fn c_set_channel_rf(&mut self, profile: Profile, cav: bool) -> Result<(), Error> {
        let mut last = [[None::<u32>; 2]; 2];
        if ctrl_ch_in_range(profile) {
            for path in 0..2u8 {
                for (slot, address) in [RR_CFGCH, RR_CFGCH_V1].into_iter().enumerate() {
                    let old = self.rr(path, address, RFREG_MASK).await?;
                    let new = rf18_channel(old, profile);
                    self.wr(path, address, RFREG_MASK, new).await?;
                    last[usize::from(path)][slot] = Some(new);
                    self.delay(100).await?;
                }
            }
        }
        let (bw, cfch) = bw_setting(profile.width());
        for path in 0..2u8 {
            let p = usize::from(path);
            for (slot, address) in [RR_CFGCH, RR_CFGCH_V1].into_iter().enumerate() {
                let old = self.rr(path, address, RFREG_MASK).await?;
                let new = (old & !RR_CFGCH_BW) | (bw << 10);
                let offset = u32::from(path) << 8;
                if let Some((bw0, bw1)) = cfch {
                    self.wm(CFCH_BW0.0 | offset, CFCH_BW0.1, bw0)?;
                    self.wm(CFCH_BW1.0 | offset, CFCH_BW1.1, bw1)?;
                }
                self.wr(path, address, RFREG_MASK, new).await?;
                last[p][slot] = Some(new);
            }
            if path == 1 && cav {
                self.wr(1, RR_RSV1, RR_RSV1_RST, 0).await?;
                let tmp = self.rr(0, RR_CFGCH, RFREG_MASK).await?;
                self.wr(1, RR_APK, RR_APK_MOD, 3).await?;
                self.wr(1, RR_CFGCH, RFREG_MASK, tmp).await?;
                last[1][0] = Some(tmp);
                self.delay(100).await?;
                self.wr(1, RR_RSV1, RR_RSV1_RST, 1).await?;
            }
        }
        let (lut, ebw) = rxbb_bw(profile.width());
        for path in 0..2u8 {
            self.wr(path, RR_LUTWE2, RR_LUTWE2_RTXBW, 1).await?;
            self.wr(path, RR_LUTWA, RR_LUTWA_M2, 0xa).await?;
            self.wr(path, RR_LUTWD0, RR_LUTWD0_LB, lut).await?;
            self.wr(path, RR_LUTWE2, RR_LUTWE2_RTXBW, 0).await?;
            self.wr(path, RR_RXBB2, RR_RXBB2_EBW, ebw).await?;
        }
        for path in 0..2u8 {
            for (slot, address) in [RR_CFGCH, RR_CFGCH_V1].into_iter().enumerate() {
                if let Some(expected) = last[usize::from(path)][slot] {
                    if self.rr(path, address, RFREG_MASK).await? != expected {
                        return Err(power::Error::Access.into());
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) enum State {
    #[default]
    New,
    Busy,
    /// Channel programmed; channel RFK not yet run.
    Programmed,
    /// `rtw8852c_rfk_channel` completed for the programmed channel.
    Calibrated,
}

/// One retained RTL8852C channel owner: the programmed channel, the
/// retained `is_tssi_mode` and the channel RFK results.
#[derive(Default)]
pub(in super::super) struct Channel {
    state: State,
    channel: Option<Profile>,
    /// `rtwdev->is_tssi_mode[A/B]` (false after `rtw8852c_rfk_init`).
    tssi_mode: [bool; 2],
    /// `rtwdev->btc.cx.wl.rfk_info.con_rfk` (state only; no I/O).
    conn_rfk: bool,
    /// Band of the last completed `set_channel` (`None` = Linux
    /// `!rtw89_get_entity_state(PHY_0)`).
    band: Option<Band>,
    /// Whether the last `set_channel` ran `rtw8852c_tssi_scan`.
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
    pub fn tssi_mode(&self) -> [bool; 2] {
        self.tssi_mode
    }
    /// Whether the last channel program ran the band-change TSSI scan.
    pub fn scanned(&self) -> bool {
        self.scanned
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
    /// rtw8852c.c `rtw8852c_set_channel_help(enter)`, `rtw8852c_set_channel`
    /// (`set_channel_mac`, `set_channel_bb`, `set_channel_rf`),
    /// `rtw8852c_set_txpwr` (`power`, which must be built for `profile`),
    /// `rtw8852c_set_channel_help(exit)`; then, when no channel was
    /// programmed yet or the band changed, `rtw89_btc_ntfy_switch_band`
    /// (`Interface::coex_switch_band`) and `rtw8852c_tssi_scan` with the
    /// retained `is_tssi_mode`. The exit's `rtw8852c_tssi_cont_en(true)`
    /// runs `_tssi_set_efuse_to_de(PHY_0)` (both paths) once per path, as
    /// Linux. `cut` is `hal.cv` (CHIP_CAV = 0).
    ///
    /// # Safety
    /// Actual RTL8852C after completed C tables, `controls_c` and
    /// `rfk::c::Init::prepare`, with exclusive radio ownership and a
    /// current channel grant for `profile`; Interface enforces current
    /// admission at every RFK access. `tracking` is this container's
    /// TXPWR_TRK and `power` this container's TXPWR program for `profile`.
    pub async unsafe fn set_channel(
        &mut self,
        io: &mut impl Interface,
        profile: Profile,
        inputs: &channel_c::Inputs<'_>,
        power: &radio_power_c::Plan,
        tracking: &Tracking,
        cut: u8,
    ) -> Result<(), Error> {
        if power.channel() != profile {
            return Err(Error::Policy);
        }
        self.begin(&[State::New, State::Programmed, State::Calibrated])?;
        self.channel = None;
        self.scanned = false;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        access.c_steps(&HELP_ENTER).await?;
        access.0.admit()?;
        // SAFETY: caller contract; inside the channel-help window.
        unsafe { channel_c::program(access.0, profile, inputs) }?;
        access.0.admit()?;
        // SAFETY: same window, immediately after `program`.
        unsafe { channel_c::program_tail(access.0, profile, cut == 0) }.await?;
        access.c_set_channel_rf(profile, cut == 0).await?;
        // `chip->ops->set_txpwr` = `rtw8852c_set_txpwr(chan, PHY_0)`.
        power.visit(|a, m, v| access.c_step(a, m, v))?;
        access.c_steps(&HELP_EXIT_HEAD).await?;
        for path in 0..2u32 {
            access.c_step(0x1_5818 + (path << 13), 1 << 30, 0)?;
            access.c_step(0x1_5820 + (path << 13), 1 << 31, 0)?;
            for de_path in 0..2u8 {
                access.c_tssi_de(de_path, profile, inputs.calibration)?;
            }
        }
        access.c_steps(&help_exit_reset(profile.band())).await?;
        access.0.admit()?;
        access.0.resume(saved).await?;
        if self.band != Some(profile.band()) {
            io.admit()?;
            io.coex_switch_band().await?;
            // SAFETY: caller contract; the channel was just programmed.
            self.scanned = unsafe {
                self.tssi
                    .scan(io, profile, inputs.calibration, tracking, self.tssi_mode)
            }
            .await?;
            if self.scanned {
                self.tssi_mode = self.tssi.results().ok_or(Error::Terminal)?.tssi_mode;
            }
        }
        self.band = Some(profile.band());
        self.channel = Some(profile);
        self.state = State::Programmed;
        Ok(())
    }

    /// rtw8852c.c `rtw8852c_rfk_channel(PHY_0)` on the programmed channel:
    /// `rtw8852c_mcc_get_ch_info` (table index 0), `conn_rfk = true`,
    /// `rtw8852c_rx_dck(PHY_0, false)` with the retained `is_tssi_mode`,
    /// `rtw8852c_iqk`, `rtw89_btc_ntfy_preserve_bt_time(30)`,
    /// `rtw8852c_tssi`, 30ms, `rtw8852c_dpk`, `conn_rfk = false`. Returns
    /// the `rtw89_fw_h2c_rf_ntfy_mcc` V0 body the caller sends as
    /// H2C_CAT_OUTSRC / H2C_CL_OUTSRC_RF_FW_NOTIFY /
    /// H2C_FUNC_OUTSRC_RF_GET_MCCCH. This owner cannot assert A2DP
    /// absence, so both BT preserves always wait the full 30ms (as B).
    ///
    /// # Safety
    /// Same owner as [`Self::set_channel`], directly after it. `calibration`/`tracking` are this device's C
    /// factory snapshot and container TXPWR_TRK; `cut` is `hal.cv`.
    pub async unsafe fn rfk_channel(
        &mut self,
        io: &mut impl Interface,
        calibration: &Calibration,
        tracking: &Tracking,
        cut: u8,
    ) -> Result<[u8; 24], Error> {
        let profile = self.channel.ok_or(Error::Terminal)?;
        self.begin(&[State::Programmed])?;
        let mcc = mccch_v0(profile);
        self.conn_rfk = true;
        io.admit()?;
        Access(io).c_rx_dck(self.tssi_mode).await?;
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
        unsafe { self.dpk.run(io, profile, cut, self.tssi_mode) }.await?;
        self.conn_rfk = false;
        self.state = State::Calibrated;
        Ok(mcc)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "c_channel_tests.rs"]
mod tests;
