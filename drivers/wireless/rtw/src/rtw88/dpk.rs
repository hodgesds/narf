// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822C digital pre-distortion calibration and thermal DPK tracking
//! (dm mechanism bit 7, [`super::dm::DPK`]).
//!
//! Faithful port of Linux rtw88 `rtw8822c.c::rtw8822c_do_dpk` (gain-loss
//! AGC state machine, coefficient readout,
//! `dpk_cal_gs`/`dpk_cal_coef1`, `dpk_enable_disable` and BB/RF backup and
//! restore), the surrounding `rtw8822c_phy_calibration` RFK power-save
//! bracket, and `rtw8822c_dpk_track`, using the `rtw8822c_table.c`
//! `rtw8822c_dpk_{mac_bb,afe_is_dpk,afe_no_dpk}` tables.
//!
//! `is_dpk_pwr_on` holds on every admitted C22 base: `phy.rs` loads the
//! RTL8822C `rfk_init_tbl` (`phy.c::rtw_load_rfk_table`). GAPK
//! (`rtw8822c_do_gapk`) is not part of this program: the retained base
//! already runs IQK without it, and DPK runs on that post-IQK state.
//!
//! Every register access runs inside [`Authority::run`]. The calibration
//! keeps its BB/RF backup until the source restore completes, so an
//! authority loss or hardware failure in the middle of the sequence still
//! restores the backed-up registers (including the `0x520..0x523` TX pause)
//! and turns DPD off through [`Dpk::restore`] under the base gate.
use super::dm::{Authority, Ewma};
use super::firmware_transport::{Error, Io};

const REG_NCTL0: u16 = 0x1b00;
const BIT_SUBPAGE: u32 = 0xf;
const BIT_SEL_PATH: u32 = 0x6;
const REG_DPD_CTL0_S0: u16 = 0x1b04;
const BIT_GS_PWSF: u32 = 0x0fff_ffff;
const REG_DPD_CTL1_S0: u16 = 0x1b08;
const BIT_DPD_EN: u32 = 1 << 31;
const BIT_PS_EN: u32 = 1 << 7;
const REG_IQK_CTL1: u16 = 0x1b20;
const BIT_TX_CFIR: u32 = 0xc000_0000;
const BIT_BYPASS_DPD: u32 = 1 << 25;
const REG_DPD_LUT0: u16 = 0x1b44;
const BIT_GLOSS_DB: u32 = 0x7000;
const REG_DPD_CTL0_S1: u16 = 0x1b5c;
const REG_DPD_CTL1_S1: u16 = 0x1b60;
const REG_DPD_AGC: u16 = 0x1b67;
const REG_DPD_CTL0: u16 = 0x1bb4;
const REG_R_CONFIG: u16 = 0x1bcc;
const BIT_INNER_LB: u32 = 1 << 21;
const BIT_IQ_SWITCH: u32 = 0x3f;
const REG_RXSRAM_CTL: u16 = 0x1bd4;
const BIT_RPT_SEL: u32 = 0x001f_0000;
const BIT_DPD_CLK: u32 = 0xf0;
const REG_DPD_CTL11: u16 = 0x1be4;
const REG_DPD_CTL12: u16 = 0x1be8;
const REG_DPD_CTL15: u16 = 0x1bf4;
const REG_DPD_CTL16: u16 = 0x1bf8;
const REG_STAT_RPT: u16 = 0x1bfc;
const BIT_RPT_DGAIN: u32 = 0x0fff_0000;
const MASKBYTE3: u32 = 0xff00_0000;
const MASKHWORD: u32 = 0xffff_0000;
const MASKLWORD: u32 = 0xffff;

const RFREG_MASK: u32 = 0xfffff;
const RF_MODE_TRXAGC: u8 = 0x00;
const BIT_RXAGC: u32 = 0x3e0;
const BIT_TXAGC: u32 = 0x1f;
const RF_RXAGC_OFFSET: u8 = 0x19;
const RF_BW_TRXBB: u8 = 0x1a;
const BIT_BW_TXBB: u32 = 0x7000;
const BIT_BW_RXBB: u32 = 0xc00;
const RF_T_METER: u8 = 0x42;
const RF_TX_GAIN_OFFSET: u8 = 0x55;
const BIT_BB_GAIN: u32 = 0x7_c000;
const BIT_RF_GAIN: u32 = 0x1c;
const RF_TX_GAIN: u8 = 0x56;
const BIT_GAIN_TXBB: u32 = 0x1f;
const RF_TXA_LB_SW: u8 = 0x63;
const BIT_TXA_LB_ATT: u32 = 0xc_0000;
const BIT_LB_ATT: u32 = 0x1c;
const BIT_LB_SW: u32 = 0x3;
const RF_RXG_GAIN: u8 = 0x87;
const BIT_RXG_GAIN: u32 = 1 << 18;
const RF_RXA_MIX_GAIN: u8 = 0x8a;
const BIT_RXA_MIX_GAIN: u32 = 0x18;
const RF_EXT_TIA_BW: u8 = 0x8f;
const RF_DEBUG: u8 = 0xde;
const BIT_DE_PWR_TRIM: u32 = 1 << 19;
const BIT_DE_TX_GAIN: u32 = 1 << 16;
const BIT_DE_TRXBW: u32 = 1 << 2;

/// `RTW_BAND_2G` / `DPK_CHANNEL_WIDTH_80`.
const BAND_2G: u8 = 1;
const WIDTH_80: u8 = 1;
/// `rtw8822c_do_dpk` `bb_reg[DPK_BB_REG_NUM]`.
const BB_REG: [u16; 18] = [
    0x520, 0x820, 0x824, 0x1c3c, 0x1d58, 0x1864, 0x4164, 0x180c, 0x410c, 0x186c, 0x416c, 0x1a14,
    0x1e70, 0x80c, 0x1d70, 0x1e7c, 0x18a4, 0x41a4,
];
/// `rtw8822c_do_dpk` `rf_reg[DPK_RF_REG_NUM]`.
const RF_REG: [u8; 7] = [0x0, 0x1a, 0x55, 0x63, 0x87, 0x8f, 0xde];
/// `rtw8822c_dpk_get_coef_tbl`.
const GET_COEF: [u32; 20] = [
    0x000400f0, 0x040400f0, 0x080400f0, 0x010400f0, 0x050400f0, 0x090400f0, 0x020400f0, 0x060400f0,
    0x0a0400f0, 0x030400f0, 0x070400f0, 0x0b0400f0, 0x0c0400f0, 0x100400f0, 0x0d0400f0, 0x110400f0,
    0x0e0400f0, 0x120400f0, 0x0f0400f0, 0x130400f0,
];
/// `rtw8822c_table.c::rtw8822c_dpk_mac_bb` (addr, mask, data).
const MAC_BB: [(u16, u32, u32); 14] = [
    (0x1e24, 1 << 17, 0x1),
    (0x1d58, 0xff8, 0x1ff),
    (0x1864, 1 << 31, 0x1),
    (0x4164, 1 << 31, 0x1),
    (0x180c, 1 << 27, 0x1),
    (0x410c, 1 << 27, 0x1),
    (0x186c, 1 << 7, 0x1),
    (0x416c, 1 << 7, 0x1),
    (0x180c, 0x3, 0x0),
    (0x410c, 0x3, 0x0),
    (0x1a14, 0x300, 0x3),
    (0x80c, 0xf, 0x8),
    (0x824, 0xf_0000, 0x3),
    (0x824, 0x0f00_0000, 0x3),
];
/// `rtw8822c_dpk_afe_is_dpk`: `0x1c38`, the `0x1830`/`0x4130` AFE sequences
/// (dword writes) and the trailing `0x18a4`/`0x41a4` bit7 sets.
const AFE_IS_DPK: [u32; 18] = [
    0x700f0001, 0x700f0001, 0x701f0001, 0x702f0001, 0x703f0001, 0x704f0001, 0x705f0001, 0x706f0001,
    0x707f0001, 0x708f0001, 0x709f0001, 0x70af0001, 0x70bf0001, 0x70cf0001, 0x70df0001, 0x70ef0001,
    0x70ff0001, 0x70ff0001,
];
/// `rtw8822c_dpk_afe_no_dpk` per-path sequences (first 7, then last 9).
const AFE_NO_DPK_A: [u32; 7] = [
    0x700b8041, 0x70144041, 0x70244041, 0x70344041, 0x70444041, 0x705b8041, 0x70644041,
];
const AFE_NO_DPK_B: [u32; 9] = [
    0x707b8041, 0x708b8041, 0x709b8041, 0x70ab8041, 0x70bb8041, 0x70cb8041, 0x70db8041, 0x70eb8041,
    0x70fb8041,
];

/// `rtw8822c.h` DPK one-shot actions.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    CalPwr,
    GainLoss,
    DoDpk,
    DpkOn,
    Dagc,
}
/// `rtw8822c.h` AGC state machine states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    GainCheck,
    GainLarge,
    GainLess,
    GlLarge,
    GlLess,
    LossCheck,
    AgcOut,
}

/// Saved `rtw8822c_do_dpk` backups, held until the source restore ran.
#[derive(Clone, Copy)]
struct Backup {
    bb: [u32; 18],
    rf: [[u32; 2]; 7],
}

/// Linux `struct rtw_dpk_info` subset for two paths.
pub(super) struct Dpk {
    window: u8,
    thermal: [u8; 2],
    path_ok: [bool; 2],
    thermal_dpk: [u8; 2],
    thermal_dpk_delta: [u8; 2],
    avg_thermal: [Ewma; 2],
    result: [bool; 2],
    coef: [[u32; 20]; 2],
    txagc: [u8; 2],
    gs: [u16; 2],
    pre_pwsf: [u8; 2],
    band: u8,
    ch: u8,
    bw: u8,
    backup: Option<Backup>,
    calibrations: u32,
    active: bool,
}

/// Register access through the current authority.
struct Hw<'a, I, A> {
    io: &'a mut I,
    auth: &'a A,
}
impl<I: Io, A: Authority> Hw<'_, I, A> {
    async fn r32(&mut self, reg: u16) -> Result<u32, Error> {
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(
            |op| self.auth.run(op),
            super::radio::read(io, reg),
        )
        .await
    }
    async fn get(&mut self, reg: u16, bits: u32) -> Result<u32, Error> {
        Ok((self.r32(reg).await? & bits) >> bits.trailing_zeros())
    }
    async fn r8(&mut self, reg: u16) -> Result<u8, Error> {
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), io.read8(reg)).await
    }
    async fn w32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), io.write32(reg, value))
            .await
    }
    async fn w8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), io.write8(reg, value))
            .await
    }
    /// `rtw_write32_mask`: the value is truncated to the mask like Linux.
    async fn mask(&mut self, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
        let shift = bits.trailing_zeros();
        let field = value.wrapping_shl(shift) & bits;
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), async {
            let old = super::radio::read(io, reg).await?;
            io.write32(reg, old & !bits | field).await
        })
        .await
    }
    async fn subpage(&mut self, value: u32) -> Result<(), Error> {
        self.mask(REG_NCTL0, BIT_SUBPAGE, value).await
    }
    async fn path_page(&mut self, path: u8) -> Result<(), Error> {
        self.subpage(0x8 | (u32::from(path) << 1)).await
    }
    async fn rf_get(&mut self, path: u8, address: u8, bits: u32) -> Result<u32, Error> {
        let io = &mut *self.io;
        let v = crate::rtw88::firmware_transport::enclosed(
            |op| self.auth.run(op),
            super::radio::rf_read(io, path, address),
        )
        .await?;
        Ok((v & bits) >> bits.trailing_zeros())
    }
    /// `rtw_phy_write_rf_reg_mix`: RF0 through SIPI, others direct.
    async fn rf(&mut self, path: u8, address: u8, bits: u32, value: u32) -> Result<(), Error> {
        if path > 1 {
            return Err(Error::Unsupported);
        }
        let shift = bits.trailing_zeros();
        let field = value.wrapping_shl(shift) & bits;
        let io = &mut *self.io;
        if address == 0 {
            crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), async {
                let data = if bits == RFREG_MASK {
                    value & RFREG_MASK
                } else {
                    super::radio::rf_read(io, path, 0).await? & !bits | field
                };
                io.write32(if path == 0 { 0x1808 } else { 0x4108 }, data)
                    .await
            })
            .await?;
            self.io.delay_us(13).await;
        } else {
            let reg = (if path == 0 { 0x3c00 } else { 0x4c00 }) + u16::from(address) * 4;
            crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), async {
                let old = super::radio::read(io, reg).await?;
                io.write32(reg, old & !bits | field).await
            })
            .await?;
            self.io.delay_us(1).await;
        }
        Ok(())
    }
    async fn delay(&mut self, us: u64) {
        self.io.delay_us(us).await;
    }
    /// `util.c::check_hw_ready`: 1000 reads, 10us apart.
    async fn ready(&mut self, reg: u16, bits: u32, target: u32) -> Result<bool, Error> {
        for _ in 0..1000 {
            if self.get(reg, bits).await? == target {
                return Ok(true);
            }
            self.delay(10).await;
        }
        Ok(false)
    }
    /// `util.c::ltecoex_read_reg` (ctrl 0x1700, rdata 0x1708).
    async fn lte_read(&mut self, offset: u16) -> Result<u32, Error> {
        if !self.ready(0x1700, 1 << 29, 1).await? {
            return Err(Error::Timeout);
        }
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), async {
            io.write32(0x1700, 0x800f_0000 | u32::from(offset)).await?;
            io.read32(0x1708).await
        })
        .await
    }
    /// `util.c::ltecoex_reg_write` (wdata 0x1704).
    async fn lte_write(&mut self, offset: u16, value: u32) -> Result<(), Error> {
        if !self.ready(0x1700, 1 << 29, 1).await? {
            return Err(Error::Timeout);
        }
        let io = &mut *self.io;
        crate::rtw88::firmware_transport::enclosed(|op| self.auth.run(op), async {
            io.write32(0x1704, value).await?;
            io.write32(0x1700, 0xc00f_0000 | u32::from(offset)).await
        })
        .await
    }
}

impl Dpk {
    /// `window` is the signed payload bound on |PWSF offset|; `thermal` the
    /// measured thermal-meter envelope shared with power tracking.
    pub(super) fn new(window: u8, thermal: [u8; 2]) -> Self {
        Self {
            window,
            thermal,
            path_ok: [false; 2],
            thermal_dpk: [0; 2],
            thermal_dpk_delta: [0; 2],
            avg_thermal: [Ewma::default(); 2],
            result: [false; 2],
            coef: [[0; 20]; 2],
            txagc: [0; 2],
            gs: [0x5b; 2],
            pre_pwsf: [0; 2],
            band: 0,
            ch: 0,
            bw: 0,
            backup: None,
            calibrations: 0,
            active: false,
        }
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn path_ok(&self) -> [bool; 2] {
        self.path_ok
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn channel(&self) -> u8 {
        self.ch
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn calibrations(&self) -> u32 {
        self.calibrations
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn pwsf(&self) -> [u8; 2] {
        self.pre_pwsf
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn gs(&self) -> [u16; 2] {
        self.gs
    }

    /// One watchdog period: calibrate when the operating
    /// channel differs from the calibrated one (Linux reruns
    /// `phy_calibration` from `rtw_chip_prepare_tx` after every channel
    /// change), otherwise `rtw8822c_dpk_track`.
    pub(super) async fn period(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        let mut hw = Hw { io, auth };
        let channel = (hw.rf_get(0, 0x18, RFREG_MASK).await? & 0xff) as u8;
        if !self.active || channel != self.ch {
            // rtw8822c_phy_calibration: rfk_power_save(false) .. (true).
            for path in 0..2 {
                hw.mask(REG_NCTL0, BIT_SEL_PATH, path).await?;
                hw.mask(REG_DPD_CTL1_S0, BIT_PS_EN, 1).await?;
            }
            self.do_dpk(&mut hw).await?;
            for path in 0..2 {
                hw.mask(REG_NCTL0, BIT_SEL_PATH, path).await?;
                hw.mask(REG_DPD_CTL1_S0, BIT_PS_EN, 0).await?;
            }
            self.active = true;
            return Ok(());
        }
        self.track(&mut hw).await
    }

    async fn thermal_read<I: Io, A: Authority>(
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<u8, Error> {
        for v in [1, 0, 1] {
            hw.rf(path, RF_T_METER, 1 << 19, v).await?;
        }
        hw.delay(15).await;
        Ok(hw.rf_get(path, RF_T_METER, 0x7e).await? as u8)
    }
    /// Thermal read bounded by the measured envelope.
    async fn thermal<I: Io, A: Authority>(
        &self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<u8, Error> {
        let t = Self::thermal_read(hw, path).await?;
        if !(self.thermal[0]..=self.thermal[1]).contains(&t) {
            return Err(Error::Prerequisite);
        }
        Ok(t)
    }

    /// `rtw8822c_dpk_track`, with the PWSF offset bounded by the payload.
    async fn track<I: Io, A: Authority>(&mut self, hw: &mut Hw<'_, I, A>) -> Result<(), Error> {
        if self.thermal_dpk == [0, 0] {
            return Ok(());
        }
        for path in 0..2u8 {
            let p = usize::from(path);
            let t = self.thermal(hw, path).await?;
            self.avg_thermal[p].add(t, 2);
            let avg = self.avg_thermal[p].read();
            let delta = i16::from(self.thermal_dpk[p] as i8) - i16::from(avg as i8);
            let offset = (delta - i16::from(self.thermal_dpk_delta[p] as i8))
                .clamp(-i16::from(self.window), i16::from(self.window));
            let offset = (offset as u8) & 0x7f;
            if offset != self.pre_pwsf[p] {
                hw.path_page(path).await?;
                hw.mask(0x1b58, 0x7f, u32::from(offset)).await?;
                self.pre_pwsf[p] = offset;
            }
        }
        Ok(())
    }

    fn set_gnt_wl_mask(value: u32) -> u32 {
        value & !0xff00 | 0x77 << 8
    }
    /// `rtw8822c_dpk_one_shot`. Returns true on a one-shot timeout.
    async fn one_shot<I: Io, A: Authority>(
        &self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
        action: Action,
    ) -> Result<bool, Error> {
        // rtw8822c_dpk_set_gnt_wl(true)
        let gnt_control = hw.r32(0x70).await?;
        let gnt_value = hw.lte_read(0x38).await?;
        hw.mask(0x70, 1 << 26, 1).await?;
        let cur = hw.lte_read(0x38).await?;
        hw.lte_write(0x38, Self::set_gnt_wl_mask(cur)).await?;
        let fail;
        if action == Action::CalPwr {
            hw.mask(REG_DPD_CTL0, 1 << 12, 1).await?;
            hw.mask(REG_DPD_CTL0, 1 << 12, 0).await?;
            hw.mask(REG_RXSRAM_CTL, BIT_RPT_SEL, 0).await?;
            hw.delay(10000).await;
            fail = !hw.ready(REG_STAT_RPT, 1 << 31, 1).await?;
        } else {
            hw.path_page(path).await?;
            hw.mask(REG_R_CONFIG, BIT_IQ_SWITCH, 0x9).await?;
            let cmd = self.cmd(action, path);
            hw.w32(REG_NCTL0, u32::from(cmd)).await?;
            hw.w32(REG_NCTL0, u32::from(cmd) + 1).await?;
            hw.delay(10000).await;
            fail = !hw.ready(0x2d9c, 0xff, 0x55).await?;
            hw.path_page(path).await?;
            hw.mask(REG_R_CONFIG, BIT_IQ_SWITCH, 0).await?;
        }
        // rtw8822c_dpk_set_gnt_wl(false)
        hw.lte_read(0x38).await?;
        hw.lte_write(0x38, gnt_value).await?;
        hw.w32(0x70, gnt_control).await?;
        hw.w8(0x1b10, 0).await?;
        Ok(fail)
    }
    /// `rtw8822c_dpk_get_cmd`.
    fn cmd(&self, action: Action, path: u8) -> u16 {
        let bw: u16 = if self.bw == WIDTH_80 { 2 } else { 0 };
        let path = u16::from(path);
        let cmd = match action {
            Action::GainLoss => 0x14 + path,
            Action::DoDpk => 0x16 + path + bw,
            Action::DpkOn => 0x1a + path,
            Action::Dagc => 0x1c + path + bw,
            Action::CalPwr => return 0,
        };
        (cmd << 8) | 0x48
    }

    async fn rxbb_dc_cal<I: Io, A: Authority>(
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<(), Error> {
        hw.rf(path, 0x92, RFREG_MASK, 0x84800).await?;
        hw.delay(5).await;
        hw.rf(path, 0x92, RFREG_MASK, 0x84801).await?;
        hw.delay(600).await;
        hw.rf(path, 0x92, RFREG_MASK, 0x84800).await
    }
    async fn dc_corr_check<I: Io, A: Authority>(hw: &mut Hw<'_, I, A>) -> Result<bool, Error> {
        hw.w32(REG_RXSRAM_CTL, 0x000900f0).await?;
        let mut dc_i = hw.get(REG_STAT_RPT, 0x0fff_0000).await? as u16;
        let mut dc_q = hw.get(REG_STAT_RPT, 0xfff).await? as u16;
        if dc_i & (1 << 11) != 0 {
            dc_i = 0x1000 - dc_i;
        }
        if dc_q & (1 << 11) != 0 {
            dc_q = 0x1000 - dc_q;
        }
        hw.w32(REG_RXSRAM_CTL, 0x000000f0).await?;
        let corr = hw.get(REG_STAT_RPT, 0xff).await? as u8;
        hw.get(REG_STAT_RPT, 0xff00).await?;
        Ok(dc_i > 200 || dc_q > 200 || !(40..=65).contains(&corr))
    }
    async fn dgain_read<I: Io, A: Authority>(hw: &mut Hw<'_, I, A>) -> Result<u16, Error> {
        hw.subpage(0xc).await?;
        hw.mask(REG_RXSRAM_CTL, 0x00ff_0000, 0).await?;
        Ok(hw.get(REG_STAT_RPT, 0x0fff_0000).await? as u16)
    }
    async fn pas_read<I: Io, A: Authority>(hw: &mut Hw<'_, I, A>, path: u8) -> Result<u32, Error> {
        hw.w32(REG_NCTL0, 0x8 | (u32::from(path) << 1)).await?;
        hw.mask(0x1b48, 1 << 14, 0).await?;
        hw.w32(REG_RXSRAM_CTL, 0x00060001).await?;
        hw.w32(0x1b4c, 0).await?;
        hw.w32(0x1b4c, 0x00080000).await?;
        let mut q = hw.get(REG_STAT_RPT, MASKHWORD).await?;
        let mut i = hw.get(REG_STAT_RPT, MASKLWORD).await?;
        if i & (1 << 15) != 0 {
            i = 0x10000 - i;
        }
        if q & (1 << 15) != 0 {
            q = 0x10000 - q;
        }
        hw.w32(0x1b4c, 0).await?;
        Ok(i.wrapping_mul(i).wrapping_add(q.wrapping_mul(q)))
    }
    /// `rtw8822c_psd_log2base`.
    pub(super) fn log2base(val: u32) -> u32 {
        const FRACTION: [u32; 21] = [
            0, 432, 332, 274, 232, 200, 174, 151, 132, 115, 100, 86, 74, 62, 51, 42, 32, 23, 15, 7,
            0,
        ];
        if val == 0 {
            return 0;
        }
        let integer = 32 - val.leading_zeros();
        let tmp = ((u64::from(val) * 100) >> integer) as u32;
        let index = ((tmp / 5) as usize).min(FRACTION.len() - 1);
        integer * 100 - FRACTION[index]
    }
    async fn gainloss_result<I: Io, A: Authority>(
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<u8, Error> {
        hw.path_page(path).await?;
        hw.mask(0x1b48, 1 << 14, 1).await?;
        hw.w32(REG_RXSRAM_CTL, 0x00060000).await?;
        let result = hw.get(REG_STAT_RPT, 0xf0).await? as u8;
        hw.mask(0x1b48, 1 << 14, 0).await?;
        Ok(result)
    }
    async fn agc_gain_chk<I: Io, A: Authority>(
        &self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
        limited_pga: bool,
    ) -> Result<State, Error> {
        self.one_shot(hw, path, Action::Dagc).await?;
        let dgain = Self::dgain_read(hw).await?;
        Ok(if dgain > 1535 && !limited_pga {
            State::GainLess
        } else if dgain < 768 && !limited_pga {
            State::GainLarge
        } else {
            State::GainCheck
        })
    }
    async fn agc_loss_chk<I: Io, A: Authority>(
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<State, Error> {
        let loss = Self::pas_read(hw, path).await?;
        if loss < 0x0400_0000 {
            return Ok(State::GlLess);
        }
        let db = (3 * Self::log2base(loss >> 13)).wrapping_sub(3870);
        Ok(if db > 1000 {
            State::GlLarge
        } else if db < 250 {
            State::GlLess
        } else {
            State::AgcOut
        })
    }
    /// `rtw8822c_dpk_pas_agc` state machine; returns the final TXBB.
    async fn pas_agc<I: Io, A: Authority>(
        &self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
        gain_only: bool,
        loss_only: bool,
    ) -> Result<u8, Error> {
        let mut txbb = 0u8;
        let mut pga = 0u8;
        let mut limited_pga = false;
        let mut agc_cnt = 0u8;
        let mut state = State::GainCheck;
        loop {
            state = match state {
                State::GainCheck => {
                    txbb = hw.rf_get(path, RF_TX_GAIN, BIT_GAIN_TXBB).await? as u8;
                    pga = hw.rf_get(path, RF_MODE_TRXAGC, BIT_RXAGC).await? as u8;
                    let mut next = if loss_only {
                        State::LossCheck
                    } else {
                        match self.agc_gain_chk(hw, path, limited_pga).await? {
                            State::GainCheck if gain_only => State::AgcOut,
                            State::GainCheck => State::LossCheck,
                            s => s,
                        }
                    };
                    agc_cnt += 1;
                    if agc_cnt >= 6 {
                        next = State::AgcOut;
                    }
                    next
                }
                State::GainLarge => {
                    if pga > 0xe {
                        hw.rf(path, RF_MODE_TRXAGC, BIT_RXAGC, 0xc).await?;
                    } else if pga > 0xb && pga < 0xf {
                        hw.rf(path, RF_MODE_TRXAGC, BIT_RXAGC, 0).await?;
                    } else if pga < 0xc {
                        limited_pga = true;
                    }
                    State::GainCheck
                }
                State::GainLess => {
                    if pga < 0xc {
                        hw.rf(path, RF_MODE_TRXAGC, BIT_RXAGC, 0xc).await?;
                    } else if pga > 0xb && pga < 0xf {
                        hw.rf(path, RF_MODE_TRXAGC, BIT_RXAGC, 0xf).await?;
                    } else if pga > 0xe {
                        limited_pga = true;
                    }
                    State::GainCheck
                }
                State::GlLarge | State::GlLess => {
                    let large = state == State::GlLarge;
                    if txbb == if large { 0 } else { 0x1f } {
                        State::AgcOut
                    } else {
                        txbb = if large {
                            txbb.wrapping_sub(2)
                        } else {
                            txbb.wrapping_add(3)
                        };
                        hw.rf(path, RF_TX_GAIN, BIT_GAIN_TXBB, u32::from(txbb))
                            .await?;
                        limited_pga = false;
                        State::GainCheck
                    }
                }
                State::LossCheck => {
                    self.one_shot(hw, path, Action::GainLoss).await?;
                    Self::agc_loss_chk(hw, path).await?
                }
                State::AgcOut => break,
            };
            if state == State::AgcOut {
                break;
            }
        }
        Ok(txbb)
    }

    /// `rtw8822c_dpk_rf_setting`; returns the original TXBB.
    async fn rf_setting<I: Io, A: Authority>(
        &self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<u8, Error> {
        hw.rf(path, RF_MODE_TRXAGC, RFREG_MASK, 0x50017).await?;
        let ori = hw.rf_get(path, RF_TX_GAIN, RFREG_MASK).await?;
        hw.rf(path, RF_DEBUG, BIT_DE_TX_GAIN, 1).await?;
        hw.rf(path, RF_DEBUG, BIT_DE_PWR_TRIM, 1).await?;
        hw.rf(path, RF_TX_GAIN_OFFSET, BIT_BB_GAIN, 0).await?;
        hw.rf(path, RF_TX_GAIN, RFREG_MASK, ori).await?;
        if self.band == BAND_2G {
            hw.rf(path, RF_TX_GAIN_OFFSET, BIT_RF_GAIN, 1).await?;
            hw.rf(path, RF_RXG_GAIN, BIT_RXG_GAIN, 0).await?;
        } else {
            hw.rf(path, RF_TXA_LB_SW, BIT_TXA_LB_ATT, 0).await?;
            hw.rf(path, RF_TXA_LB_SW, BIT_LB_ATT, 6).await?;
            hw.rf(path, RF_TXA_LB_SW, BIT_LB_SW, 1).await?;
            hw.rf(path, RF_RXA_MIX_GAIN, BIT_RXA_MIX_GAIN, 0).await?;
        }
        hw.rf(path, RF_MODE_TRXAGC, BIT_RXAGC, 0xf).await?;
        hw.rf(path, RF_DEBUG, BIT_DE_TRXBW, 1).await?;
        hw.rf(path, RF_BW_TRXBB, BIT_BW_RXBB, 0).await?;
        let txbb_bw = if self.bw == WIDTH_80 { 2 } else { 1 };
        hw.rf(path, RF_BW_TRXBB, BIT_BW_TXBB, txbb_bw).await?;
        hw.rf(path, RF_EXT_TIA_BW, 1 << 1, 1).await?;
        hw.delay(100).await;
        Ok((ori & 0x1f) as u8)
    }

    /// `rtw8822c_dpk_gainloss`; returns the DPK TXAGC.
    async fn gainloss<I: Io, A: Authority>(
        &mut self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<u8, Error> {
        let ori_txbb = self.rf_setting(hw, path).await?;
        let ori_txagc = hw.rf_get(path, RF_MODE_TRXAGC, BIT_TXAGC).await? as u8;
        Self::rxbb_dc_cal(hw, path).await?;
        self.one_shot(hw, path, Action::Dagc).await?;
        Self::dgain_read(hw).await?;
        if Self::dc_corr_check(hw).await? {
            Self::rxbb_dc_cal(hw, path).await?;
            self.one_shot(hw, path, Action::Dagc).await?;
            Self::dc_corr_check(hw).await?;
        }
        let t1 = self.thermal(hw, path).await?;
        let mut tx_bb = self.pas_agc(hw, path, false, true).await?;
        let search = Self::gainloss_result(hw, path).await?;
        tx_bb = tx_bb.saturating_sub(search);
        hw.rf(path, RF_TX_GAIN, BIT_GAIN_TXBB, u32::from(tx_bb))
            .await?;
        let tx_agc = ori_txagc.wrapping_sub(ori_txbb.wrapping_sub(tx_bb));
        let t2 = self.thermal(hw, path).await?;
        self.thermal_dpk_delta[usize::from(path)] = t2.abs_diff(t1);
        Ok(tx_agc)
    }

    /// `rtw8822c_dpk_coef_transfer`.
    async fn coef_transfer<I: Io, A: Authority>(hw: &mut Hw<'_, I, A>) -> Result<u32, Error> {
        hw.r32(REG_STAT_RPT).await?;
        let i = hw.get(REG_STAT_RPT, MASKHWORD).await? & 0x1fff;
        let q = hw.get(REG_STAT_RPT, MASKLWORD).await? & 0x1fff;
        let q = ((0x2000 - q) & 0x1fff).wrapping_sub(1) & 0xffff;
        Ok((i << 16) | q)
    }
    /// `rtw8822c_dpk_by_path` + `rtw8822c_dpk_get_coef`. True on failure.
    async fn by_path<I: Io, A: Authority>(
        &mut self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<bool, Error> {
        let mut fail = self.one_shot(hw, path, Action::DoDpk).await?;
        hw.path_page(path).await?;
        fail |= hw.get(REG_DPD_CTL1_S0, 1 << 26).await? != 0;
        hw.rf(path, RF_MODE_TRXAGC, RFREG_MASK, 0x33e14).await?;
        hw.w32(REG_NCTL0, 0xc).await?;
        if path == 0 {
            hw.mask(REG_DPD_CTL0, 1 << 24, 0).await?;
            hw.w32(REG_DPD_CTL0_S0, 0x30000080).await?;
        } else {
            hw.mask(REG_DPD_CTL0, 1 << 24, 1).await?;
            hw.w32(REG_DPD_CTL0_S1, 0x30000080).await?;
        }
        for (i, &sel) in GET_COEF.iter().enumerate() {
            hw.w32(REG_RXSRAM_CTL, sel).await?;
            self.coef[usize::from(path)][i] = Self::coef_transfer(hw).await?;
        }
        Ok(fail)
    }
    /// `rtw8822c_dpk_coef_read`: false when any coefficient saturates.
    fn coef_ok(&self, path: usize) -> bool {
        !self.coef[path].iter().any(|&c| {
            let i = (c >> 16) & 0x1fff;
            let q = c & 0x1fff;
            i == 0x1000 || i == 0x0fff || q == 0x1000 || q == 0x0fff
        })
    }
    /// `rtw8822c_dpk_coef_write`.
    async fn coef_write<I: Io, A: Authority>(
        &self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
        ok: bool,
    ) -> Result<(), Error> {
        let base: u16 = if path == 0 { 0x1b0c } else { 0x1b64 };
        hw.w32(REG_NCTL0, 0xc).await?;
        hw.w32(REG_RXSRAM_CTL, 0xf0).await?;
        for addr in 0..20u16 {
            let coef = if !ok {
                if addr == 3 {
                    0x04001fff
                } else {
                    0x00001fff
                }
            } else {
                self.coef[usize::from(path)][usize::from(addr)]
            };
            hw.w32(base + addr * 4, coef).await?;
        }
        Ok(())
    }
    /// `rtw8822c_dpk_check_pass` + `rtw8822c_dpk_fill_result`.
    async fn fill_result<I: Io, A: Authority>(
        &mut self,
        hw: &mut Hw<'_, I, A>,
        fail: bool,
        txagc: u8,
        path: u8,
    ) -> Result<bool, Error> {
        let p = usize::from(path);
        let ok = !fail && self.coef_ok(p);
        hw.path_page(path).await?;
        hw.w8(REG_DPD_AGC, if ok { txagc.wrapping_sub(6) } else { 0 })
            .await?;
        self.result[p] = ok;
        self.txagc[p] = hw.r8(REG_DPD_AGC).await?;
        self.coef_write(hw, path, ok).await?;
        Ok(ok)
    }
    /// `rtw8822c_dpk_cal_gs`.
    async fn cal_gs<I: Io, A: Authority>(
        &mut self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<(), Error> {
        let (ctl0, ctl1) = if path == 0 {
            (REG_DPD_CTL0_S0, REG_DPD_CTL1_S0)
        } else {
            (REG_DPD_CTL0_S1, REG_DPD_CTL1_S1)
        };
        hw.path_page(path).await?;
        hw.mask(REG_IQK_CTL1, BIT_BYPASS_DPD, 0).await?;
        hw.mask(REG_IQK_CTL1, BIT_TX_CFIR, 0).await?;
        hw.mask(REG_R_CONFIG, BIT_IQ_SWITCH, 0x9).await?;
        hw.mask(REG_R_CONFIG, BIT_INNER_LB, 1).await?;
        hw.subpage(0xc).await?;
        hw.mask(REG_RXSRAM_CTL, BIT_DPD_CLK, 0xf).await?;
        hw.mask(ctl0, BIT_GS_PWSF, 0x1066680).await?;
        hw.mask(ctl1, BIT_DPD_EN, 1).await?;
        let sel = 1u32 << path;
        if self.bw == WIDTH_80 {
            for v in [0x80001310, 0x00001310, 0x810000db, 0x010000db, 0x0000b428] {
                hw.w32(REG_DPD_CTL16, v).await?;
            }
            hw.w32(REG_DPD_CTL15, 0x05020000 | (sel << 28)).await?;
        } else {
            for v in [0x8200190c, 0x0200190c, 0x8301ee14, 0x0301ee14, 0x0000b428] {
                hw.w32(REG_DPD_CTL16, v).await?;
            }
            hw.w32(REG_DPD_CTL15, 0x05020008 | (sel << 28)).await?;
        }
        hw.mask(REG_DPD_CTL0, MASKBYTE3, 0x8 | u32::from(path))
            .await?;
        self.one_shot(hw, path, Action::CalPwr).await?;
        hw.mask(REG_DPD_CTL15, MASKBYTE3, 0).await?;
        hw.path_page(path).await?;
        hw.mask(REG_R_CONFIG, BIT_IQ_SWITCH, 0).await?;
        hw.mask(REG_R_CONFIG, BIT_INNER_LB, 0).await?;
        hw.subpage(0xc).await?;
        hw.mask(ctl0, BIT_GS_PWSF, 0x5b).await?;
        hw.mask(REG_RXSRAM_CTL, BIT_RPT_SEL, 0).await?;
        let mut gs = hw.get(REG_STAT_RPT, BIT_RPT_DGAIN).await? as u16 as u32;
        gs = (gs * 910) >> 10;
        // DIV_ROUND_CLOSEST(gs, 10)
        gs = (gs + 5) / 10;
        hw.mask(ctl0, BIT_GS_PWSF, gs).await?;
        self.gs[usize::from(path)] = gs as u16;
        Ok(())
    }
    /// `rtw8822c_dpk_cal_coef1`. A zero GS would divide by zero in Linux;
    /// this port refuses it instead.
    async fn cal_coef1<I: Io, A: Authority>(&self, hw: &mut Hw<'_, I, A>) -> Result<(), Error> {
        hw.subpage(0xc).await?;
        hw.w32(REG_RXSRAM_CTL, 0xf0).await?;
        hw.w32(REG_NCTL0, 0x1148).await?;
        hw.w32(REG_NCTL0, 0x1149).await?;
        // Linux only warns on a stuck DPK here ("performance may be suboptimal").
        let _ = hw.ready(0x2d9c, 0xff, 0x55).await?;
        hw.w8(0x1b10, 0).await?;
        hw.subpage(0xc).await?;
        for path in 0..2u16 {
            let gs = u32::from(self.gs[usize::from(path)]);
            if gs == 0 {
                return Err(Error::Prerequisite);
            }
            let offset = path * 0x58;
            hw.mask(0x1b18 + offset, MASKHWORD, 0x16c00 / gs).await?;
            for v in [0x9, 0x1, 0x0] {
                hw.mask(REG_DPD_CTL0_S0 + offset, 0xf000_0000, v).await?;
            }
            hw.mask(REG_DPD_CTL1_S0 + offset, 1 << 14, 0).await?;
        }
        Ok(())
    }
    /// `rtw8822c_dpk_on`.
    async fn on<I: Io, A: Authority>(
        &mut self,
        hw: &mut Hw<'_, I, A>,
        path: u8,
    ) -> Result<(), Error> {
        self.one_shot(hw, path, Action::DpkOn).await?;
        hw.path_page(path).await?;
        hw.mask(REG_IQK_CTL1, BIT_TX_CFIR, 0).await?;
        if self.path_ok[usize::from(path)] {
            self.cal_gs(hw, path).await?;
        }
        Ok(())
    }
    /// `rtw8822c_dpk_tx_pause` + `rtw8822c_dpk_mac_bb` table.
    async fn mac_bb<I: Io, A: Authority>(hw: &mut Hw<'_, I, A>) -> Result<(), Error> {
        hw.w8(0x522, 0xff).await?;
        hw.mask(0x1e70, 0xf, 2).await?;
        for _ in 0..2500 {
            let a = hw.rf_get(0, 0, 0xf0000).await?;
            let b = hw.rf_get(1, 0, 0xf0000).await?;
            hw.delay(2).await;
            if a != 2 && b != 2 {
                break;
            }
        }
        for (reg, bits, value) in MAC_BB {
            hw.mask(reg, bits, value).await?;
        }
        Ok(())
    }
    /// `rtw8822c_dpk_afe_setting`.
    async fn afe<I: Io, A: Authority>(hw: &mut Hw<'_, I, A>, is_dpk: bool) -> Result<(), Error> {
        if is_dpk {
            hw.w32(0x1c38, 0xffff_ffff).await?;
            for reg in [0x1830, 0x4130] {
                for v in AFE_IS_DPK {
                    hw.w32(reg, v).await?;
                }
            }
            hw.mask(0x18a4, 1 << 7, 1).await?;
            hw.mask(0x41a4, 1 << 7, 1).await?;
        } else {
            hw.mask(0x18a4, 1 << 7, 0).await?;
            hw.mask(0x41a4, 1 << 7, 0).await?;
            hw.w32(0x1c38, 0xffa1005e).await?;
            for reg in [0x1830, 0x4130] {
                for v in AFE_NO_DPK_A {
                    hw.w32(reg, v).await?;
                }
            }
            for reg in [0x1830, 0x4130] {
                for v in AFE_NO_DPK_B {
                    hw.w32(reg, v).await?;
                }
            }
        }
        Ok(())
    }
    /// `rtw8822c_dpk_pre_setting`.
    async fn pre_setting<I: Io, A: Authority>(&self, hw: &mut Hw<'_, I, A>) -> Result<(), Error> {
        for path in 0..2u8 {
            hw.rf(path, RF_RXAGC_OFFSET, RFREG_MASK, 0).await?;
            hw.w32(REG_NCTL0, 0x8 | (u32::from(path) << 1)).await?;
            hw.w32(
                REG_DPD_CTL1_S1,
                if self.band == BAND_2G {
                    0x1f100000
                } else {
                    0x1f0d0000
                },
            )
            .await?;
            hw.mask(REG_DPD_LUT0, BIT_GLOSS_DB, 0x4).await?;
            hw.mask(REG_IQK_CTL1, BIT_TX_CFIR, 0x3).await?;
        }
        hw.subpage(0xc).await?;
        hw.w32(REG_DPD_CTL11, 0x3b23170b).await?;
        hw.w32(REG_DPD_CTL12, 0x775f5347).await
    }
    /// `rtw8822c_dpk_result_reset`.
    async fn result_reset<I: Io, A: Authority>(
        &mut self,
        hw: &mut Hw<'_, I, A>,
    ) -> Result<(), Error> {
        for path in 0..2u8 {
            let p = usize::from(path);
            self.path_ok[p] = false;
            hw.path_page(path).await?;
            hw.mask(0x1b58, 0x7f, 0).await?;
            self.txagc[p] = 0;
            self.result[p] = false;
            self.gs[p] = 0x5b;
            self.pre_pwsf[p] = 0;
            self.thermal_dpk[p] = self.thermal(hw, path).await?;
        }
        Ok(())
    }
    /// `rtw8822c_dpk_enable_disable` (`is_dpk_pwr_on` holds).
    async fn enable<I: Io, A: Authority>(&self, hw: &mut Hw<'_, I, A>) -> Result<(), Error> {
        hw.subpage(0xc).await?;
        hw.mask(REG_DPD_CTL1_S0, BIT_DPD_EN, 1).await?;
        hw.mask(REG_DPD_CTL1_S1, BIT_DPD_EN, 1).await?;
        for (path, (ctl0, ctl1)) in [
            (REG_DPD_CTL0_S0, REG_DPD_CTL1_S0),
            (REG_DPD_CTL0_S1, REG_DPD_CTL1_S1),
        ]
        .into_iter()
        .enumerate()
        {
            if self.path_ok[path] {
                hw.mask(ctl1, 0xc000, 0).await?;
                hw.w8(ctl0, self.gs[path] as u8).await?;
            }
        }
        Ok(())
    }
    /// `rtw8822c_do_dpk`.
    async fn do_dpk<I: Io, A: Authority>(&mut self, hw: &mut Hw<'_, I, A>) -> Result<(), Error> {
        // rtw8822c_dpk_reload never matches here: `period` calibrates only
        // on a channel other than the calibrated one, and each association
        // starts a fresh tracker, so it always recalibrates.
        self.avg_thermal = [Ewma::default(); 2];
        // rtw8822c_dpk_information
        let reg = hw.rf_get(0, 0x18, RFREG_MASK).await?;
        self.band = 1 << ((reg >> 16) & 1);
        self.ch = (reg & 0xff) as u8;
        self.bw = ((reg & 0x3000) >> 12) as u8;
        // Backups (BB then RF), held until the source restore below.
        let mut backup = Backup {
            bb: [0; 18],
            rf: [[0; 2]; 7],
        };
        for (slot, &reg) in backup.bb.iter_mut().zip(BB_REG.iter()) {
            *slot = hw.r32(reg).await?;
        }
        for (slot, &reg) in backup.rf.iter_mut().zip(RF_REG.iter()) {
            *slot = [
                hw.rf_get(0, reg, RFREG_MASK).await?,
                hw.rf_get(1, reg, RFREG_MASK).await?,
            ];
        }
        self.backup = Some(backup);
        // Forget the channel until this calibration completes.
        let ch = self.ch;
        self.ch = 0;
        Self::mac_bb(hw).await?;
        Self::afe(hw, true).await?;
        self.pre_setting(hw).await?;
        self.result_reset(hw).await?;
        // rtw8822c_dpk_path_select
        for path in 0..2u8 {
            let txagc = self.gainloss(hw, path).await?;
            let fail = self.by_path(hw, path).await?;
            let ok = self.fill_result(hw, fail, txagc, path).await?;
            self.path_ok[usize::from(path)] = ok;
        }
        for path in 0..2u8 {
            self.on(hw, path).await?;
        }
        self.cal_coef1(hw).await?;
        Self::afe(hw, false).await?;
        self.enable(hw).await?;
        Self::restore_backup(hw, &backup).await?;
        self.backup = None;
        self.ch = ch;
        self.calibrations += 1;
        Ok(())
    }
    /// `rtw8822c_dpk_reload_rf_registers` + rxbb DC + `restore_registers`.
    async fn restore_backup<I: Io, A: Authority>(
        hw: &mut Hw<'_, I, A>,
        b: &Backup,
    ) -> Result<(), Error> {
        for (&reg, v) in RF_REG.iter().zip(b.rf.iter()) {
            hw.rf(0, reg, RFREG_MASK, v[0]).await?;
            hw.rf(1, reg, RFREG_MASK, v[1]).await?;
        }
        for path in 0..2 {
            Self::rxbb_dc_cal(hw, path).await?;
        }
        for (&reg, &v) in BB_REG.iter().zip(b.bb.iter()) {
            hw.w32(reg, v).await?;
        }
        hw.subpage(0xc).await?;
        hw.mask(REG_RXSRAM_CTL, BIT_DPD_CLK, 0x4).await
    }

    /// Return to the base no-DPD program under `base`: finish a pending
    /// calibration's source restore (TX unpause included), clear both PWSF
    /// offsets, re-enter RFK power save and disable DPD on both paths, as
    /// `radio.rs` leaves the base.
    pub(super) async fn restore(
        &mut self,
        io: &mut impl Io,
        base: &impl Authority,
    ) -> Result<(), Error> {
        let mut hw = Hw { io, auth: base };
        if let Some(b) = self.backup.take() {
            Self::restore_backup(&mut hw, &b).await?;
        }
        for path in 0..2u8 {
            hw.path_page(path).await?;
            hw.mask(0x1b58, 0x7f, 0).await?;
            hw.mask(REG_NCTL0, BIT_SEL_PATH, u32::from(path)).await?;
            hw.mask(REG_DPD_CTL1_S0, BIT_DPD_EN, 0).await?;
            hw.mask(REG_DPD_CTL1_S0, BIT_PS_EN, 0).await?;
        }
        hw.subpage(0xc).await?;
        hw.mask(REG_DPD_CTL1_S0, BIT_DPD_EN, 0).await?;
        hw.mask(REG_DPD_CTL1_S1, BIT_DPD_EN, 0).await?;
        self.pre_pwsf = [0; 2];
        self.path_ok = [false; 2];
        self.thermal_dpk = [0; 2];
        self.ch = 0;
        self.active = false;
        Ok(())
    }
}
