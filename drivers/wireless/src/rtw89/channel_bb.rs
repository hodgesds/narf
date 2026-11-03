// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Source B fixed MAC0/PHY0 channel1/20MHz BB/gain continuation. No native
//! caller until the complete radio recipe and current measured grant exist.
use super::{
    factory_b::Calibration,
    power::{self, Io},
    radio_gain::Gain,
};
#[path = "channel_bb/regs.rs"]
mod regs;
use super::operating_channel::{Profile, Width};
use regs::*;
#[path = "channel_bb/recipe.rs"]
mod recipe;
pub(super) const RECIPE: [u8; 32] = recipe::RECIPE;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    Policy,
    Terminal,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Register(e)
    }
}
pub(super) trait Interface: Io {
    fn admit(&mut self) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Preparing,
    Configured,
}
#[derive(Default)]
pub(super) struct Channel {
    state: State,
}
struct Access<'a, I>(&'a mut I);
fn bits(mask: u32, value: i32) -> u32 {
    (value as u32).wrapping_shl(mask.trailing_zeros()) & mask
}
impl<I: Interface> Access<'_, I> {
    fn read(&mut self, a: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let v = self.0.read32(a)?;
        if v == u32::MAX {
            return Err(power::Error::Gone.into());
        }
        Ok(v)
    }
    fn write(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.0.admit()?;
        Ok(self.0.write32(a, v)?)
    }
    fn masked(&mut self, a: u32, m: u32, v: i32) -> Result<(), Error> {
        let old = self.read(a)?;
        self.write(a, (old & !m) | bits(m, v))
    }
    fn phy(&mut self, a: u32, m: u32, v: i32) -> Result<(), Error> {
        self.masked(0x10000 + a, m, v)
    }
    fn byte(&mut self, a: u32, c: u8, s: u8) -> Result<(), Error> {
        self.0.admit()?;
        let old = self.0.read8(a)?;
        self.0.admit()?;
        Ok(self.0.write8(a, (old & !c) | s)?)
    }
    async fn delay(&mut self, u: u64) -> Result<(), Error> {
        self.0.admit()?;
        self.0.delay_us(u).await;
        self.0.admit()
    }
    /// Linux `rtw8852bx_set_gain_error`/`_set_gain_offset`/`_set_rxsc_rpl_comp`
    /// for the channel's subband (`gain_a` registers and BB gain band on 5GHz;
    /// the CCK RPL offset is 2.4GHz only).
    fn gain(
        &mut self,
        g: &Gain,
        c: &Calibration,
        bases: [i8; 2],
        channel: Profile,
    ) -> Result<(), Error> {
        let band = channel.gain_band();
        let subband = usize::from(channel.subband());
        let ofdm_band = channel.gain_offset_band();
        let a_band = [
            ([0x45dc, 0x4740], 0x00ff0000),
            ([0x45dc, 0x4740], 0xff000000),
            ([0x4660, 0x4744], 255),
            ([0x4660, 0x4744], 0xff00),
            ([0x4660, 0x4744], 0xff0000),
            ([0x4660, 0x4744], 0xff000000),
            ([0x4664, 0x4748], 255),
        ];
        let lna = [
            ([0x4678, 0x475c], 0x00ff0000),
            ([0x4678, 0x475c], 0xff000000),
            ([0x467c, 0x4760], 255),
            ([0x467c, 0x4760], 0xff00),
            ([0x467c, 0x4760], 0xff0000),
            ([0x467c, 0x4760], 0xff000000),
            ([0x4680, 0x4764], 255),
        ];
        let (lna, tia) = if channel.is_5ghz() {
            (a_band, [0x4664, 0x4748])
        } else {
            (lna, [0x4680, 0x4764])
        };
        for p in 0..2 {
            for (i, (address, mask)) in lna.iter().enumerate() {
                self.phy(address[p], *mask, i32::from(g.lna[band][p][i]))?;
            }
            for (i, mask) in [0xff0000, 0xff000000].into_iter().enumerate() {
                self.phy(tia[p], mask, i32::from(g.tia[band][p][i]))?;
            }
        }
        if c.comp_valid {
            for p in 0..2 {
                self.phy(
                    [R_P0_AGC_RSVD, R_P1_AGC_RSVD][p],
                    MASKBYTE0,
                    (i32::from(c.gain_comp[p][subband]) << 2).clamp(-128, 127),
                )?;
            }
        }
        if c.offset_valid {
            for p in 0..2 {
                let ofdm = -i32::from(c.gain_offset[p][ofdm_band]);
                let value = -((ofdm << 2) + (i32::from(bases[0]) >> 2));
                self.phy(
                    [R_PATH0_G_TIA1_LNA6_OP1DB_V1, R_PATH1_G_TIA1_LNA6_OP1DB_V1][p],
                    B_PATH0_R_G_OFST_MASK,
                    value.clamp(-128, 127),
                )?;
            }
            // Initial RX-AB uses the source default path-A offset selection.
            let ofdm = -i32::from(c.gain_offset[0][ofdm_band]);
            let cck = -i32::from(c.gain_offset[0][0]);
            self.phy(
                R_P0_RPL1,
                B_P0_RPL1_BIAS_MASK,
                ((ofdm << 4) + i32::from(bases[0])).clamp(-128, 127),
            )?;
            self.phy(
                R_P1_RPL1,
                B_P0_RPL1_BIAS_MASK,
                ((ofdm << 4) + i32::from(bases[1])).clamp(-128, 127),
            )?;
            if !channel.is_5ghz() {
                self.phy(
                    R_RX_RPL_OFST,
                    B_RX_RPL_OFST_CCK_MASK,
                    ((cck << 3) + (i32::from(bases[0]) >> 1)).clamp(-64, 63),
                )?;
            }
        }
        let avg = |a: i8, b: i8| (i32::from(a) + i32::from(b)) >> 1;
        let r20 = avg(g.rpl20[band][0], g.rpl20[band][1]);
        let r40 = |i| avg(g.rpl40[band][0][i], g.rpl40[band][1][i]);
        let r80 = |i| avg(g.rpl80[band][0][i], g.rpl80[band][1][i]);
        let v = (bits(B_P0_RPL1_20_MASK, r20)
            | bits(B_P0_RPL1_40_MASK, r40(0))
            | bits(B_P0_RPL1_41_MASK, r40(1)))
            >> B_P0_RPL1_SHIFT;
        for a in [R_P0_RPL1, R_P1_RPL1] {
            self.phy(a, B_P0_RPL1_MASK, v as i32)?;
        }
        let v = bits(B_P0_RTL2_42_MASK, r40(2))
            | bits(B_P0_RTL2_80_MASK, r80(0))
            | bits(B_P0_RTL2_81_MASK, r80(1))
            | bits(B_P0_RTL2_8A_MASK, r80(10));
        for a in [R_P0_RPL2, R_P1_RPL2] {
            self.write(0x10000 + a, v)?;
        }
        let v = bits(B_P0_RTL3_82_MASK, r80(2))
            | bits(B_P0_RTL3_83_MASK, r80(3))
            | bits(B_P0_RTL3_84_MASK, r80(4))
            | bits(B_P0_RTL3_89_MASK, r80(9));
        for a in [R_P0_RPL3, R_P1_RPL3] {
            self.write(0x10000 + a, v)?;
        }
        Ok(())
    }
}
impl Channel {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Exact initial B MAC0/PHY0 SCC, real retained gain/factory/RPL bases,
    /// current expanded measured channel envelope, exclusive stopped/awake radio
    /// with no live retune/monitor/packet or response transmitter. This is only
    /// MAC/BB programming; caller also retains RF synth/calibration ownership and
    /// terminalizes the actual backend if the future is dropped or fails.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        g: &Gain,
        c: &Calibration,
        bases: [i8; 2],
    ) -> Result<(), Error> {
        // SAFETY: exact existing initial preparation contract, fixed original
        // channel1 profile, same retained current interface/factory/calibration.
        unsafe {
            self.prepare_for_channel(io, g, c, bases, Profile::INITIAL)
                .await
        }
    }
    /// # Safety
    /// Same exclusive retained B/PHY0/SCC source owner, closed ordinary TX and
    /// autonomous responses, actual gain/factory bases. The current signed full
    /// envelope and host permission must cover THIS actual primary/channel
    /// MAC/BB/RF/RFK and its calibration emissions; no initial1 record alias.
    pub async unsafe fn prepare_for_channel(
        &mut self,
        io: &mut impl Interface,
        g: &Gain,
        c: &Calibration,
        bases: [i8; 2],
        channel: Profile,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Preparing;
        let mut a = Access(io);
        // `__rtw8852bx_set_channel_mac`: RFMOD 0/BIT(0)/BIT(1) and the
        // phy.c `rtw89_phy_get_txsc` TX sub-carrier word per width.
        let (rfmod, sub_carrier) = match channel.width() {
            Width::Mhz20 => (0, 0),
            Width::Mhz40 => (1, u32::from(channel.txsc(Width::Mhz20))),
            Width::Mhz80 => (
                2,
                u32::from(channel.txsc(Width::Mhz20))
                    | (u32::from(channel.txsc(Width::Mhz40)) << 4),
            ),
        };
        a.byte(R_AX_WMAC_RFMOD, B_AX_WMAC_RFMOD_MASK as u8, rfmod)?;
        a.write(R_AX_TX_SUB_CARRIER_VALUE, sub_carrier)?;
        // `__rtw8852bx_set_channel_mac`: 5GHz clears BAND_MODE and checks CCK.
        let cck = channel.cck_enabled();
        if cck {
            a.byte(R_AX_TXRATE_CHK, 0, B_AX_BAND_MODE as u8)?;
            a.byte(
                R_AX_TXRATE_CHK,
                (B_AX_CHECK_CCK_EN | B_AX_RTS_LIMIT_IN_OFDM6) as u8,
                0,
            )?;
            let sco = channel.sco();
            a.phy(R_RXSCOBC, B_RXSCOBC_TH, sco[0] as i32)?;
            a.phy(R_RXSCOCCK, B_RXSCOCCK_TH, sco[1] as i32)?;
        } else {
            a.byte(R_AX_TXRATE_CHK, B_AX_BAND_MODE as u8, 0)?;
            a.byte(
                R_AX_TXRATE_CHK,
                0,
                (B_AX_CHECK_CCK_EN | B_AX_RTS_LIMIT_IN_OFDM6) as u8,
            )?;
        }
        // `rtw8852bx_ctrl_ch`: BAND_SEL 1 on 2.4GHz, 0 on 5GHz.
        a.phy(R_PATH0_BAND_SEL_V1, B_PATH0_BAND_SEL_MSK_V1, i32::from(cck))?;
        a.phy(R_PATH1_BAND_SEL_V1, B_PATH1_BAND_SEL_MSK_V1, i32::from(cck))?;
        a.phy(R_FC0_BW_V1, B_FC0_BW_INV, channel.sco_compensation() as i32)?;
        for (address, value) in [
            R_TXFIR0, R_TXFIR2, R_TXFIR4, R_TXFIR6, R_TXFIR8, R_TXFIRA, R_TXFIRC, R_TXFIRE,
        ]
        .into_iter()
        .zip(channel.cck_fir(0))
        {
            a.phy(address, B_TXFIR_C01, value as i32)?;
        }
        a.gain(g, c, bases, channel)?;
        let rx =
            (a.read(0x10000 + R_CHBW_MOD_V1)? & B_ANT_RX_SEG0) >> B_ANT_RX_SEG0.trailing_zeros();
        // `rtw8852bx_ctrl_bw`: FC0 BW_SET = width, SBW 0, PRICH = pri_ch_idx.
        let pri = channel.pri_ch_idx();
        a.phy(R_FC0_BW_V1, B_FC0_BW_SET, channel.width() as i32)?;
        a.phy(R_CHBW_MOD_V1, B_CHBW_MOD_SBW, 0)?;
        a.phy(R_CHBW_MOD_V1, B_CHBW_MOD_PRICH, i32::from(pri))?;
        a.phy(R_P0_RFMODE_ORI_RX, B_P0_RFMODE_ORI_RX_ALL, 0x333)?;
        a.phy(R_P1_RFMODE_ORI_RX, B_P1_RFMODE_ORI_RX_ALL, 0x333)?;
        if channel.width() == Width::Mhz40 {
            // CCK primary channel (only the 40MHz branch writes R_RXSC).
            a.phy(R_RXSC, B_RXSC_EN, i32::from(pri == 1))?;
        }
        for (address, mask, value) in [
            (0xc0ec, 0x6000, 0),
            (0xc0e4, 0x30, 2),
            (0xc1ec, 0x6000, 0),
            (0xc1e4, 0x30, 2),
        ] {
            a.phy(address, mask, value)?;
        }
        if rx == 1 {
            a.phy(R_P1_RFMODE_ORI_RX, B_P1_RFMODE_ORI_RX_ALL, 0x111)?;
        } else if rx == 2 {
            a.phy(R_P0_RFMODE_ORI_RX, B_P0_RFMODE_ORI_RX_ALL, 0x111)?;
        }
        // `rtw8852bx_ctrl_cck_en`.
        a.phy(R_UPD_CLK_ADC, B_ENABLE_CCK, i32::from(cck))?;
        a.phy(R_RXCCA, B_RXCCA_DIS, i32::from(!cck))?;
        if !cck {
            // RTL8852B 5GHz: release the BT-shared 2.4GHz paths.
            for (address, mask) in [
                (R_PATH0_BT_SHARE_V1, B_PATH0_BT_SHARE_V1),
                (R_PATH0_BTG_PATH_V1, B_PATH0_BTG_PATH_V1),
                (R_PATH1_BT_SHARE_V1, B_PATH1_BT_SHARE_V1),
                (R_PATH1_BTG_PATH_V1, B_PATH1_BTG_PATH_V1),
                (R_CHBW_MOD_V1, B_BT_SHARE),
                (R_FC0_BW_V1, B_ANT_RX_BT_SEG0),
                (R_BT_DYN_DC_EST_EN_V1, B_BT_DYN_DC_EST_EN_MSK),
                (R_GNT_BT_WGT_EN, B_GNT_BT_WGT_EN),
            ] {
                a.phy(address, mask, 0)?;
            }
        }
        a.phy(R_MAC_PIN_SEL, B_CH_IDX_SEG0, i32::from(channel.chan_idx()))?;
        // `rtw8852bx_5m_mask`: 40MHz always, 80MHz only at UPMOST/LOWEST.
        let mask_5m = match channel.width() {
            Width::Mhz20 => None,
            Width::Mhz40 => Some(pri == 2),
            Width::Mhz80 => (pri == 3 || pri == 4).then_some(pri == 4),
        };
        match mask_5m {
            None => {
                a.phy(R_PATH0_5MDET_V1, B_PATH0_5MDET_EN, 0)?;
                a.phy(R_PATH1_5MDET_V1, B_PATH1_5MDET_EN, 0)?;
                a.phy(R_ASSIGN_SBD_OPT_V1, B_ASSIGN_SBD_OPT_EN_V1, 0)?;
            }
            Some(low) => {
                for (address, [th, en, sb2, sb0]) in [
                    (
                        R_PATH0_5MDET_V1,
                        [
                            B_PATH0_5MDET_TH,
                            B_PATH0_5MDET_EN,
                            B_PATH0_5MDET_SB2,
                            B_PATH0_5MDET_SB0,
                        ],
                    ),
                    (
                        R_PATH1_5MDET_V1,
                        [
                            B_PATH1_5MDET_TH,
                            B_PATH1_5MDET_EN,
                            B_PATH1_5MDET_SB2,
                            B_PATH1_5MDET_SB0,
                        ],
                    ),
                ] {
                    a.phy(address, th, 4)?;
                    a.phy(address, en, 1)?;
                    a.phy(address, sb2, i32::from(!low))?;
                    a.phy(address, sb0, i32::from(low))?;
                }
                a.phy(R_ASSIGN_SBD_OPT_V1, B_ASSIGN_SBD_OPT_EN_V1, 1)?;
            }
        }
        a.phy(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 7)?;
        a.phy(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 7)?;
        a.delay(1).await?;
        a.phy(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)?;
        a.phy(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 0)?;
        a.phy(R_S0_HW_SI_DIS, B_S0_HW_SI_DIS_W_R_TRIG, 0)?;
        a.phy(R_S1_HW_SI_DIS, B_S1_HW_SI_DIS_W_R_TRIG, 0)?;
        a.phy(R_RSTB_ASYNC, B_RSTB_ASYNC_ALL, 1)?;
        // Source stream plus mandatory actual critical width/channel/reset readback.
        for (address, mask, expected) in [
            (
                0x10000 + R_FC0_BW_V1,
                B_FC0_BW_SET,
                bits(B_FC0_BW_SET, channel.width() as i32),
            ),
            (
                0x10000 + R_CHBW_MOD_V1,
                B_CHBW_MOD_SBW | B_CHBW_MOD_PRICH,
                bits(B_CHBW_MOD_PRICH, i32::from(pri)),
            ),
            (
                0x10000 + R_MAC_PIN_SEL,
                B_CH_IDX_SEG0,
                bits(B_CH_IDX_SEG0, i32::from(channel.chan_idx())),
            ),
            (
                0x10000 + R_RSTB_ASYNC,
                B_RSTB_ASYNC_ALL,
                bits(B_RSTB_ASYNC_ALL, 1),
            ),
        ] {
            if a.read(address)? & mask != expected {
                return Err(power::Error::Access.into());
            }
        }
        self.state = State::Configured;
        Ok(())
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "channel_bb/tests.rs"]
mod tests;
