// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852A channel DPK: rtw8852a_rfk.c `rtw8852a_dpk` for the non-DBCC
//! PHY_0 (`_kpath` = RF_AB), both paths, on one typed [`Profile`].
//!
//! The public entry sets `is_dpk_enable = true` and
//! `is_dpk_reload_en = false`, so `cur_idx` is always 0 and no reload
//! path runs (`_dpk_reload_check` is never reached). The BTC ONESHOT
//! notifications inside `_dpk_one_shot` return without I/O; only the
//! outer START/STOP is emitted, as the `Kind::Dpk` bracket. Linux logs
//! a one-shot timeout and returns 1; NARF fails the attempt closed.
//!
//! `thermal` is the current averaged thermal per path
//! (`ewma_thermal_read`); the native A caller supplies its actual retained
//! non-TSSI observations. `epa` is the factory FEM external-PA presence
//! (`epa_2g`, `epa_5g`); a present external PA forces the bypass
//! (`_dpk_bypass_check` / `_dpk_force_bypass`).
//!
//! The `is_check = false` arm of `_dpk_pas_read` (32 debug reads, no
//! decision) is omitted, like the C port. `_dpk_set_mdpd_para` order
//! 0 is the only order the flow uses; orders 1/2 are transcribed and
//! any other order is a no-op, as in Linux (it only logs).
//!
//! DBCC tables (`DPK_BB_AFE_*_DEFS_A/B`, `DPK_BB_AFE_SF/SR_*`) are
//! landed as defs but unused by this flow: only the RF_AB
//! `DPK_BB_AFE_S/R_DEFS_AB` tables run on the non-DBCC path.
use super::super::operating_channel_c::{Band, Profile, Width};
use super::{power, Access, Entry, Error, Interface, Kind};

const B_COEF_SEL_MDPD: u32 = 0x100; // Linux reg.h: BIT(8)
const B_DPK_CFG2_ST: u32 = 0x4000; // Linux reg.h: BIT(14)
const B_DPK_CFG_IDX: u32 = 0x7000; // Linux reg.h: GENMASK(14, 12)
const B_DPK_CTL_EN: u32 = 0x10000000; // Linux reg.h: BIT(28)
const B_DPK_TRK_DIS: u32 = 0x80000000; // Linux reg.h: BIT(31)
const B_IQK_DIF4_RXT: u32 = 0xfff0000; // Linux reg.h: GENMASK(27, 16)
const B_KIP_RFGAIN: u32 = 0x100; // Linux reg.h: BIT(8)
const B_KIP_RPT1_SEL: u32 = 0x3f0000; // Linux reg.h: GENMASK(21, 16)
const B_LDL_NORM_OP: u32 = 0x3; // Linux reg.h: GENMASK(1, 0)
const B_LDL_NORM_PN: u32 = 0x1f00; // Linux reg.h: GENMASK(12, 8)
const B_LOAD_COEF_CFIR: u32 = 0x3; // Linux reg.h: GENMASK(1, 0)
const B_LOAD_COEF_MDPD: u32 = 0x10000; // Linux reg.h: BIT(16)
const B_MDPK_SYNC_MAN: u32 = 0xf0000000; // Linux reg.h: GENMASK(31, 28)
const B_MDPK_SYNC_SEL: u32 = 0x80000000; // Linux reg.h: BIT(31)
const B_NCTL_CFG_SPAGE: u32 = 0x6; // Linux reg.h: GENMASK(2, 1)
const B_P0_TSSI_TRK_EN: u32 = 0x40000000; // Linux reg.h: BIT(30)
const B_P0_TXDPD: u32 = 0xf0000000; // Linux reg.h: GENMASK(31, 28)
const B_PRT_COM_CORI: u32 = 0xff; // Linux reg.h: GENMASK(7, 0)
const B_PRT_COM_CORV: u32 = 0xff00; // Linux reg.h: GENMASK(15, 8)
const B_PRT_COM_DCI: u32 = 0xfff0000; // Linux reg.h: GENMASK(27, 16)
const B_PRT_COM_DCQ: u32 = 0xfff; // Linux reg.h: GENMASK(11, 0)
const B_PRT_COM_GL: u32 = 0xf0; // Linux reg.h: GENMASK(7, 4)
const B_PRT_COM_SYNERR: u32 = 0x40000000; // Linux reg.h: BIT(30)
const B_RFGAIN_PAD: u32 = 0x1f; // Linux reg.h: GENMASK(4, 0)
const B_RFGAIN_TXBB: u32 = 0x1f00; // Linux reg.h: GENMASK(12, 8)
const B_RXIQC_BYPASS: u32 = 0x1; // Linux reg.h: BIT(0)
const B_RXIQC_BYPASS2: u32 = 0x4; // Linux reg.h: BIT(2)
const B_TPG_MOD_F: u32 = 0x6; // Linux reg.h: GENMASK(2, 1)
const B_TXAGC_TP: u32 = 0x7; // Linux reg.h: GENMASK(2, 0)
const RR_BIASA2: u32 = 0x63; // Linux reg.h: 0x63
const RR_BIASA2_LB: u32 = 0x1c; // Linux reg.h: GENMASK(4, 2)
const RR_BTC: u32 = 0x1a; // Linux reg.h: 0x1a
const RR_BTC_RXBB: u32 = 0xc00; // Linux reg.h: GENMASK(11, 10)
const RR_BTC_TXBB: u32 = 0x7000; // Linux reg.h: GENMASK(14, 12)
const RR_CFGCH: u32 = 0x18; // Linux reg.h: 0x18
const RR_EN_TIA_IDA: u32 = 0xc00; // Linux reg.h: GENMASK(11, 10)
const RR_GAINTX: u32 = 0x56; // Linux reg.h: 0x56
const RR_GAINTX_BB: u32 = 0x1f; // Linux reg.h: GENMASK(4, 0)
const RR_GAINTX_PAD: u32 = 0x3e0; // Linux reg.h: GENMASK(9, 5)
const RR_MIXER: u32 = 0x9f; // Linux reg.h: 0x9f
const RR_MIXER_GN: u32 = 0x18; // Linux reg.h: GENMASK(4, 3)
const RR_MOD: u32 = 0x0; // Linux reg.h: 0x00
const RR_MODOPT: u32 = 0x1; // Linux reg.h: 0x01
const RR_MODOPT_M_TXPWR: u32 = 0x3f; // Linux reg.h: GENMASK(5, 0)
const RR_MOD_DPK: u32 = 0xfffe0; // Linux reg.h: GENMASK(19, 5)
const RR_MOD_MASK: u32 = 0xf0000; // Linux reg.h: GENMASK(19, 16)
const RR_MOD_M_RXBB: u32 = 0x3e0; // Linux reg.h: GENMASK(9, 5)
const RR_MOD_V_DPK: u32 = 0x5; // Linux reg.h: 0x5
const RR_MOD_V_RX: u32 = 0x3; // Linux reg.h: 0x3
const RR_RCKD: u32 = 0xde; // Linux reg.h: 0xde
const RR_RCKD_BW: u32 = 0x4; // Linux reg.h: BIT(2)
const RR_RSV1: u32 = 0x5; // Linux reg.h: 0x05
const RR_RSV1_RST: u32 = 0x1; // Linux reg.h: BIT(0)
const RR_RSV4: u32 = 0x1f; // Linux reg.h: 0x1f
const RR_RXA: u32 = 0x8a; // Linux reg.h: 0x8a
const RR_RXA_DPK: u32 = 0x300; // Linux reg.h: GENMASK(9, 8)
const RR_RXBB: u32 = 0x83; // Linux reg.h: 0x83
const RR_RXBB2: u32 = 0x8f; // Linux reg.h: 0x8f
const RR_RXBB_ATTC: u32 = 0x7; // Linux reg.h: GENMASK(2, 0)
const RR_RXBB_ATTR: u32 = 0xf0; // Linux reg.h: GENMASK(7, 4)
const RR_RXIQGEN: u32 = 0x8d; // Linux reg.h: 0x8d
const RR_RXIQGEN_ATTH: u32 = 0x6000; // Linux reg.h: GENMASK(14, 13)
const RR_RXIQGEN_ATTL: u32 = 0x1f00; // Linux reg.h: GENMASK(12, 8)
const RR_RXK: u32 = 0x20; // Linux reg.h: 0x20
const RR_RXKPLL: u32 = 0x1e; // Linux reg.h: 0x1e
const RR_RXKPLL_OFF: u32 = 0x3f; // Linux reg.h: GENMASK(5, 0)
const RR_RXKPLL_POW: u32 = 0x80000; // Linux reg.h: BIT(19)
const RR_RXK_PLLEN: u32 = 0x20; // Linux reg.h: BIT(5)
const RR_RXPOW: u32 = 0x80; // Linux reg.h: 0x80
const RR_RXPOW_IQK: u32 = 0x30000; // Linux reg.h: GENMASK(17, 16)
const RR_TXA: u32 = 0x5d; // Linux reg.h: 0x5d
const RR_TXATANK: u32 = 0x64; // Linux reg.h: 0x64
const RR_TXATANK_LBSW: u32 = 0x18000; // Linux reg.h: GENMASK(16, 15)
const RR_TXA_TRK: u32 = 0xfc000; // Linux reg.h: GENMASK(19, 14)
const R_CFIR_SYS: u32 = 0x8120; // Linux reg.h: 0x8120
const R_COEF_SEL: u32 = 0x8104; // Linux reg.h: 0x8104
const R_DPD_BND: u32 = 0x81b4; // Linux reg.h: 0x81B4
const R_DPD_CH0: u32 = 0x81ac; // Linux reg.h: 0x81AC
const R_DPD_CH0A: u32 = 0x81bc; // Linux reg.h: 0x81BC
const R_DPD_COM: u32 = 0x81c8; // Linux reg.h: 0x81C8
const R_DPD_V1: u32 = 0x81a0; // Linux reg.h: 0x81a0
const R_DPK_CFG: u32 = 0x80b8; // Linux reg.h: 0x80B8
const R_DPK_CFG2: u32 = 0x80bc; // Linux reg.h: 0x80BC
const R_DPK_CFG3: u32 = 0x80c0; // Linux reg.h: 0x80C0
const R_DPK_CTL: u32 = 0x80b0; // Linux reg.h: 0x80B0
const R_DPK_TRK: u32 = 0x80f0; // Linux reg.h: 0x80f0
const R_IQK_DIF4: u32 = 0x802c; // Linux reg.h: 0x802C
const R_IQK_RES: u32 = 0x8124; // Linux reg.h: 0x8124
const R_KIP: u32 = 0x8140; // Linux reg.h: 0x8140
const R_KIP_CLK: u32 = 0x808c; // Linux reg.h: 0x808C
const R_KIP_RPT1: u32 = 0x80d4; // Linux reg.h: 0x80D4
const R_KIP_SYSCFG: u32 = 0x8088; // Linux reg.h: 0x8088
const R_LDL_NORM: u32 = 0x80a0; // Linux reg.h: 0x80A0
const R_LOAD_COEF: u32 = 0x81dc; // Linux reg.h: 0x81DC
const R_MDPK_SYNC: u32 = 0x8070; // Linux reg.h: 0x8070
const R_NCTL_CFG: u32 = 0x8000; // Linux reg.h: 0x8000
const R_NCTL_N1: u32 = 0x8010; // Linux reg.h: 0x8010
const R_NCTL_RPT: u32 = 0x8008; // Linux reg.h: 0x8008
const R_P0_TSSI_TRK: u32 = 0x5818; // Linux reg.h: 0x5818
const R_P0_TXDPD: u32 = 0x58d4; // Linux reg.h: 0x58D4
const R_RFGAIN: u32 = 0x8144; // Linux reg.h: 0x8144
const R_RPT_COM: u32 = 0x80fc; // Linux reg.h: 0x80FC
const R_RXIQC: u32 = 0x813c; // Linux reg.h: 0x813c
const R_TPG_MOD: u32 = 0x806c; // Linux reg.h: 0x806C
const R_TXAGC_BB: u32 = 0x1c60; // Linux reg.h: 0x1C60
const R_TXAGC_RFK: u32 = 0x81c4; // Linux reg.h: 0x81C4
const R_TXAGC_TP: u32 = 0x1c04; // Linux reg.h: 0x1C04

/// Full-RF-register mask (Linux `RFREG_MASK`).
const RFREG_MASK: u32 = 0xfffff;
/// `DPK_TXAGC_LOWER` (rtw8852a_rfk.c).
const TXAGC_LOWER: u8 = 0x2e;
/// `DPK_TXAGC_UPPER` (rtw8852a_rfk.c).
const TXAGC_UPPER: u8 = 0x3f;
/// `DPK_TXAGC_INVAL` (rtw8852a_rfk.c): sync failure.
const TXAGC_INVAL: u8 = 0xff;
/// `DPK_AGC_ADJ_LMT` (rtw8852a_rfk.c).
const AGC_ADJ_LMT: u8 = 6;
/// `DPK_DGAIN_UPPER` / `DPK_DGAIN_LOWER` (rtw8852a_rfk.c).
const DGAIN_UPPER: u16 = 1922;
const DGAIN_LOWER: u16 = 342;
/// `DPK_GL_CRIT` (rtw8852a_rfk.c).
const GL_CRIT: u8 = 7;
/// DPK one-shot ids (`enum rtw8852a_dpk_id`) driven by this flow.
/// `MDPK_MPA` (0x12) and `GAIN_CAL` (0x14) are never driven here.
const ID_LBK_RXIQK: u32 = 0x06;
const ID_SYNC: u32 = 0x10;
const ID_MDPK_IDL: u32 = 0x11;
const ID_GAIN_LOSS: u32 = 0x13;
/// KIP backup registers (`_dpk_cal_select`: `kip_reg`).
const KIP_REG: [u32; 2] = [R_RXIQC, R_IQK_RES];

/// 12-bit sign extension + absolute value, as Linux
/// `abs(sign_extend32(v, 11))` in `_dpk_sync_check` / `_dpk_pas_read`.
fn sign12_abs(value: u32) -> u32 {
    (((value << 20) as i32) >> 20).unsigned_abs()
}

/// Per-path DPK results (`struct rtw89_dpk_info::bp[path][0]`).
///
/// No derived `Default`: `Band`/`Width` have none (shared
/// `operating_channel_c` types); the manual impl defaults to the
/// 2.4GHz / 20MHz geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct Path {
    pub path_ok: bool,
    pub txagc_dpk: u8,
    /// `ther_dpk`: averaged thermal sampled in `_dpk_main`.
    pub ther_dpk: u8,
    pub pwsf: u16,
    pub gs: u8,
    pub corr_idx: u8,
    pub corr_val: u8,
    pub dc_i: u16,
    pub dc_q: u16,
    /// `_dpk_information`: band/channel/width of the calibrated run.
    pub band: Band,
    pub ch: u8,
    pub bw: Width,
}
impl Default for Path {
    fn default() -> Self {
        Self {
            path_ok: false,
            txagc_dpk: 0,
            ther_dpk: 0,
            pwsf: 0,
            gs: 0,
            corr_idx: 0,
            corr_val: 0,
            dc_i: 0,
            dc_q: 0,
            band: Band::Ghz2,
            ch: 0,
            bw: Width::Mhz20,
        }
    }
}

/// Channel DPK owner (`struct rtw89_dpk_info`, non-DBCC slice).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Dpk {
    pub paths: [Path; 2],
    pub channel: Option<Profile>,
    /// True when an external PA forced the bypass.
    pub bypassed: bool,
    completed: bool,
}

/// `_dpk_agc` steps (`enum dpk_agc_step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgcStep {
    SyncDgain,
    GainAdj,
    GainLossIdx,
    GlGt,
    GlLt,
    SetTxGain,
}

impl<I: Interface> Access<'_, I> {
    /// `_dpk_one_shot`: command `(id << 8) | (0x19 + (path << 4))`,
    /// `R_NCTL_CFG` full word, `R_DPK_CTL_EN`, poll 0xbff8 byte0 ==
    /// 0x55 (10us step, 20ms budget), clear `R_NCTL_N1` byte0. The
    /// BTC ONESHOT notifications return without I/O. Linux returns 1
    /// on timeout; NARF fails closed.
    async fn a_dpk_one_shot(&mut self, path: u8, id: u32) -> Result<(), Error> {
        let command = (id << 8) | (0x19 + (u32::from(path) << 4));
        self.wm(R_NCTL_CFG, u32::MAX, command)?;
        self.wm(R_DPK_CTL, B_DPK_CTL_EN, 1)?;
        let start = self.0.now_us();
        while self.bb(0xbff8, 0xff)? != 0x55 {
            if self.0.now_us().saturating_sub(start) >= 20_000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(10).await?;
        }
        self.wm(R_NCTL_N1, 0xff, 0)
    }

    /// `_dpk_rx_dck`: `RR_RXBB2` TIA/IDA enable, then `_set_rx_dck`
    /// with `is_afe = false`.
    async fn a_dpk_rx_dck(&mut self, path: u8) -> Result<(), Error> {
        self.wr(path, RR_RXBB2, RR_EN_TIA_IDA, 0x3).await?;
        self.a_set_rx_dck(path, false).await
    }

    /// `_dpk_bb_afe_setting`: non-DBCC `_kpath` = RF_AB programs the
    /// `DPK_BB_AFE_S_DEFS_AB` table.
    async fn a_dpk_bb_afe_setting(&mut self) -> Result<(), Error> {
        self.table(DPK_BB_AFE_S_DEFS_AB).await
    }

    /// `_dpk_bb_afe_restore`: non-DBCC programs
    /// `DPK_BB_AFE_R_DEFS_AB`.
    async fn a_dpk_bb_afe_restore(&mut self) -> Result<(), Error> {
        self.table(DPK_BB_AFE_R_DEFS_AB).await
    }

    /// `_dpk_tssi_pause`.
    fn a_dpk_tssi_pause(&mut self, path: u8, pause: bool) -> Result<(), Error> {
        self.wm(
            R_P0_TSSI_TRK + (u32::from(path) << 13),
            B_P0_TSSI_TRK_EN,
            u32::from(pause),
        )
    }

    /// `_dpk_kip_setting` (`kidx` is always 0: reload is disabled).
    fn a_dpk_kip_setting(&mut self, path: u8) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        self.wm(R_NCTL_RPT, u32::MAX, 0x00000080)?;
        self.wm(R_KIP_CLK, u32::MAX, 0x00093f3f)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x807f030a)?;
        self.wm(R_CFIR_SYS + off, u32::MAX, 0xce000a08)?;
        self.wm(R_DPK_CFG, B_DPK_CFG_IDX, 0x2)?;
        self.wm(R_NCTL_CFG, B_NCTL_CFG_SPAGE, u32::from(path))?;
        self.wm(R_DPD_CH0 + off, u32::MAX, 0x003f2e2e)?;
        self.wm(R_DPD_CH0A + off, u32::MAX, 0x005b5b5b)
    }

    /// `_dpk_kip_restore`: `cut > CHIP_CBV` (cut > 1) sets
    /// `R_DPD_COM` BIT(15).
    fn a_dpk_kip_restore(&mut self, path: u8, cut: u8) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        self.wm(R_NCTL_RPT, u32::MAX, 0)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x80000000)?;
        self.wm(R_CFIR_SYS + off, u32::MAX, 0x10010000)?;
        self.wm(R_KIP_CLK, u32::MAX, 0)?;
        if cut > 1 {
            self.wm(R_DPD_COM + off, 1 << 15, 0x1)?;
        }
        Ok(())
    }

    /// `_dpk_lbk_rxiqk`.
    async fn a_dpk_lbk_rxiqk(&mut self, path: u8) -> Result<(), Error> {
        let cur_rxbb = self.rr(path, RR_MOD, RR_MOD_M_RXBB).await? as u8;
        self.table(DPK_LBK_RXIQK_DEFS_F).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, 0xc).await?;
        self.wr(path, RR_RXK, RR_RXK_PLLEN, 0x1).await?;
        self.wr(path, RR_RXPOW, RR_RXPOW_IQK, 0x2).await?;
        let cfgch = self.rr(path, RR_CFGCH, RFREG_MASK).await?;
        self.wr(path, RR_RSV4, RFREG_MASK, cfgch).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_OFF, 0x13).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x1).await?;
        self.delay(70).await?;
        self.wr(path, RR_RXIQGEN, RR_RXIQGEN_ATTL, 0x1f).await?;
        let atth = if cur_rxbb <= 0xa {
            0x3
        } else if cur_rxbb <= 0x10 {
            0x1
        } else {
            0x0
        };
        self.wr(path, RR_RXIQGEN, RR_RXIQGEN_ATTH, atth).await?;
        self.wm(R_IQK_DIF4, B_IQK_DIF4_RXT, 0x11)?;
        self.a_dpk_one_shot(path, ID_LBK_RXIQK).await?;
        // Linux reads `R_RXIQC` (no path offset) for a debug print only.
        let _ = self.bb(R_RXIQC, u32::MAX)?;
        self.wr(path, RR_RXK, RR_RXK_PLLEN, 0x0).await?;
        self.wr(path, RR_RXPOW, RR_RXPOW_IQK, 0x0).await?;
        self.wr(path, RR_RXKPLL, RR_RXKPLL_POW, 0x0).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_DPK).await?;
        self.table(DPK_LBK_RXIQK_DEFS_R).await
    }

    /// `_dpk_set_tx_pwr`: writes 0x38 to `RR_MODOPT`, returns 0x38
    /// (the `gain` parameter is unused in Linux).
    async fn a_dpk_set_tx_pwr(&mut self, path: u8) -> Result<u8, Error> {
        self.wr(path, RR_MODOPT, RFREG_MASK, 0x38).await?;
        Ok(0x38)
    }

    /// `_dpk_rf_setting`.
    async fn a_dpk_rf_setting(&mut self, path: u8, channel: Profile) -> Result<(), Error> {
        match channel.band() {
            Band::Ghz2 => {
                self.wr(path, RR_MOD, RR_MOD_DPK, 0x280b).await?;
                self.wr(path, RR_RXBB, RR_RXBB_ATTC, 0x0).await?;
                self.wr(path, RR_RXBB, RR_RXBB_ATTR, 0x4).await?;
                self.wr(path, RR_MIXER, RR_MIXER_GN, 0x0).await?;
            }
            Band::Ghz5 => {
                self.wr(path, RR_MOD, RR_MOD_DPK, 0x282e).await?;
                self.wr(path, RR_BIASA2, RR_BIASA2_LB, 0x7).await?;
                self.wr(path, RR_TXATANK, RR_TXATANK_LBSW, 0x3).await?;
                self.wr(path, RR_RXA, RR_RXA_DPK, 0x3).await?;
            }
            Band::Ghz6 => return Err(Error::Policy),
        }
        self.wr(path, RR_RCKD, RR_RCKD_BW, 0x1).await?;
        self.wr(path, RR_BTC, RR_BTC_TXBB, channel.width() as u32 + 1)
            .await?;
        self.wr(path, RR_BTC, RR_BTC_RXBB, 0x0).await
    }

    /// `_dpk_manual_txcfir`.
    async fn a_dpk_manual_txcfir(&mut self, path: u8, manual: bool) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        if manual {
            self.wm(R_KIP + off, B_KIP_RFGAIN, 0x1)?;
            let tmp_pad = self.rr(path, RR_GAINTX, RR_GAINTX_PAD).await?;
            self.wm(R_RFGAIN + off, B_RFGAIN_PAD, tmp_pad)?;
            let tmp_txbb = self.rr(path, RR_GAINTX, RR_GAINTX_BB).await?;
            self.wm(R_RFGAIN + off, B_RFGAIN_TXBB, tmp_txbb)?;
            self.wm(R_LOAD_COEF + off, B_LOAD_COEF_CFIR, 0x1)?;
            self.wm(R_LOAD_COEF + off, B_LOAD_COEF_CFIR, 0)?;
            self.wm(R_LOAD_COEF + off, 1 << 1, 0x1)
        } else {
            self.wm(R_KIP + off, B_KIP_RFGAIN, 0)
        }
    }

    /// `_dpk_bypass_rxcfir`.
    fn a_dpk_bypass_rxcfir(&mut self, path: u8, bypass: bool) -> Result<(), Error> {
        let address = R_RXIQC + (u32::from(path) << 8);
        if bypass {
            self.wm(address, B_RXIQC_BYPASS2, 0x1)?;
            self.wm(address, B_RXIQC_BYPASS, 0x1)
        } else {
            self.wm(address, B_RXIQC_BYPASS2, 0)?;
            self.wm(address, B_RXIQC_BYPASS, 0)
        }
    }

    /// `_dpk_tpg_sel`.
    fn a_dpk_tpg_sel(&mut self, channel: Profile) -> Result<(), Error> {
        match channel.width() {
            Width::Mhz80 => self.wm(R_TPG_MOD, B_TPG_MOD_F, 0),
            Width::Mhz40 => self.wm(R_TPG_MOD, B_TPG_MOD_F, 0x2),
            _ => self.wm(R_TPG_MOD, B_TPG_MOD_F, 0x1),
        }
    }

    /// `_dpk_table_select` (`kidx` is always 0: reload is disabled).
    fn a_dpk_table_select(&mut self, path: u8, gain: u8) -> Result<(), Error> {
        let val = 0x80 + u32::from(gain) * 0x10;
        self.wm(R_DPD_CH0 + (u32::from(path) << 8), 0xff000000, val)
    }

    /// `_dpk_sync_check`: thresholds DC_I/Q 200, CORR 170; true = fail.
    /// (`path` is unused: the RPT reads are global, as in Linux.)
    fn a_dpk_sync_check(&mut self, _path: u8, state: &mut Path) -> Result<bool, Error> {
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        state.corr_idx = self.bb(R_RPT_COM, B_PRT_COM_CORI)? as u8;
        state.corr_val = self.bb(R_RPT_COM, B_PRT_COM_CORV)? as u8;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x9)?;
        state.dc_i = sign12_abs(self.bb(R_RPT_COM, B_PRT_COM_DCI)?) as u16;
        state.dc_q = sign12_abs(self.bb(R_RPT_COM, B_PRT_COM_DCQ)?) as u16;
        Ok(state.dc_i > 200 || state.dc_q > 200 || state.corr_val < 170)
    }

    /// `_dpk_sync`.
    async fn a_dpk_sync(
        &mut self,
        path: u8,
        channel: Profile,
        state: &mut Path,
    ) -> Result<bool, Error> {
        self.a_dpk_tpg_sel(channel)?;
        self.a_dpk_one_shot(path, ID_SYNC).await?;
        self.a_dpk_sync_check(path, state)
    }

    /// `_dpk_dgain_read`.
    fn a_dpk_dgain_read(&mut self) -> Result<u16, Error> {
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        let _ = self.bb(R_RPT_COM, B_PRT_COM_SYNERR)?;
        Ok(self.bb(R_RPT_COM, B_PRT_COM_DCI)? as u16)
    }

    /// `_dpk_dgain_mapping`, as an if-chain (equivalent to Linux's
    /// overlapping ranges for every `u16`).
    fn a_dpk_dgain_mapping(dgain: u16) -> i8 {
        if dgain >= 0x783 {
            0x6
        } else if dgain >= 0x551 {
            0x3
        } else if dgain >= 0x3c4 {
            0x0
        } else if dgain >= 0x2aa {
            -3
        } else if dgain >= 0x1e3 {
            -6
        } else if dgain >= 0x156 {
            -9
        } else {
            -12
        }
    }

    /// `_dpk_gainloss_read`.
    fn a_dpk_gainloss_read(&mut self) -> Result<u8, Error> {
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x6)?;
        self.wm(R_DPK_CFG2, B_DPK_CFG2_ST, 0x1)?;
        Ok(self.bb(R_RPT_COM, B_PRT_COM_GL)? as u8)
    }

    /// `_dpk_gainloss`.
    async fn a_dpk_gainloss(&mut self, path: u8) -> Result<(), Error> {
        self.a_dpk_table_select(path, 1)?;
        self.a_dpk_one_shot(path, ID_GAIN_LOSS).await
    }

    /// `_dpk_set_offset`: read the current `RR_MODOPT`, subtract the
    /// offset, clamp to [`TXAGC_LOWER`, `TXAGC_UPPER`], write back.
    async fn a_dpk_set_offset(&mut self, path: u8, gain_offset: i8) -> Result<u8, Error> {
        let txagc = self.rr(path, RR_MODOPT, RFREG_MASK).await? as i32;
        let value =
            (txagc - i32::from(gain_offset)).clamp(i32::from(TXAGC_LOWER), i32::from(TXAGC_UPPER));
        self.wr(path, RR_MODOPT, RFREG_MASK, value as u32).await?;
        Ok(value as u8)
    }

    /// `_dpk_pas_read(is_check = true)`: the `is_check = false` arm
    /// (32 debug reads, no decision) is omitted.
    async fn a_dpk_pas_read(&mut self) -> Result<u8, Error> {
        self.table(DPK_PAS_READ_DEFS).await?;
        self.wm(R_DPK_CFG3, 0xff000000, 0x00)?;
        let val1_i = sign12_abs(self.bb(R_RPT_COM, 0xffff0000)?);
        let val1_q = sign12_abs(self.bb(R_RPT_COM, 0xffff)?);
        self.wm(R_DPK_CFG3, 0xff000000, 0x1f)?;
        let val2_i = sign12_abs(self.bb(R_RPT_COM, 0xffff0000)?);
        let val2_q = sign12_abs(self.bb(R_RPT_COM, 0xffff)?);
        if val1_i * val1_i + val1_q * val1_q >= (val2_i * val2_i + val2_q * val2_q) * 8 / 5 {
            Ok(1)
        } else {
            Ok(0)
        }
    }

    /// `_dpk_agc` (`loss_only` is always false in `_dpk_main`, so there
    /// is no such parameter here). Returns the settled TXAGC, or
    /// [`TXAGC_INVAL`] on a sync failure. Bounded by `agc_cnt < 6`;
    /// the 200-iteration guard is belt-and-braces, as in the C port.
    async fn a_dpk_agc(
        &mut self,
        path: u8,
        channel: Profile,
        state: &mut Path,
        init_txagc: u8,
    ) -> Result<u8, Error> {
        let mut tmp_txagc = init_txagc;
        let mut tmp_gl_idx = 0u8;
        let mut dgain = 0u16;
        let mut limited_rxbb = false;
        let mut agc_cnt = 0u8;
        let mut step = AgcStep::SyncDgain;
        let mut goout = false;
        let mut iter = 0u32;
        while !goout && agc_cnt < AGC_ADJ_LMT {
            iter += 1;
            if iter > 200 {
                return Err(Error::Terminal);
            }
            match step {
                AgcStep::SyncDgain => {
                    if self.a_dpk_sync(path, channel, state).await? {
                        tmp_txagc = TXAGC_INVAL;
                        goout = true;
                    } else {
                        dgain = self.a_dpk_dgain_read()?;
                        step = if limited_rxbb {
                            AgcStep::GainLossIdx
                        } else {
                            AgcStep::GainAdj
                        };
                    }
                }
                AgcStep::GainAdj => {
                    let tmp_rxbb = self.rr(path, RR_MOD, RR_MOD_M_RXBB).await? as u8;
                    let offset = Self::a_dpk_dgain_mapping(dgain);
                    let adjusted = i32::from(tmp_rxbb) + i32::from(offset);
                    let (rxbb, limited) = if adjusted > 0x1f {
                        (0x1f, true)
                    } else if adjusted < 0 {
                        (0, true)
                    } else {
                        (adjusted as u8, false)
                    };
                    limited_rxbb = limited;
                    self.wr(path, RR_MOD, RR_MOD_M_RXBB, u32::from(rxbb))
                        .await?;
                    if offset != 0 || agc_cnt == 0 {
                        if channel.width() < Width::Mhz80 {
                            self.a_dpk_bypass_rxcfir(path, true)?;
                        } else {
                            self.a_dpk_lbk_rxiqk(path).await?;
                        }
                    }
                    step = if !(DGAIN_LOWER..=DGAIN_UPPER).contains(&dgain) {
                        AgcStep::SyncDgain
                    } else {
                        AgcStep::GainLossIdx
                    };
                    agc_cnt += 1;
                }
                AgcStep::GainLossIdx => {
                    self.a_dpk_gainloss(path).await?;
                    tmp_gl_idx = self.a_dpk_gainloss_read()?;
                    step = if (tmp_gl_idx == 0 && self.a_dpk_pas_read().await? == 1)
                        || tmp_gl_idx > GL_CRIT
                    {
                        AgcStep::GlGt
                    } else if tmp_gl_idx == 0 {
                        AgcStep::GlLt
                    } else {
                        AgcStep::SetTxGain
                    };
                }
                AgcStep::GlGt => {
                    if tmp_txagc == TXAGC_LOWER {
                        goout = true;
                    } else {
                        tmp_txagc = self.a_dpk_set_offset(path, 3).await?;
                    }
                    step = AgcStep::GainLossIdx;
                    agc_cnt += 1;
                }
                AgcStep::GlLt => {
                    if tmp_txagc == TXAGC_UPPER {
                        goout = true;
                    } else {
                        tmp_txagc = self.a_dpk_set_offset(path, -2).await?;
                    }
                    step = AgcStep::GainLossIdx;
                    agc_cnt += 1;
                }
                AgcStep::SetTxGain => {
                    tmp_txagc = self.a_dpk_set_offset(path, tmp_gl_idx as i8).await?;
                    goout = true;
                    agc_cnt += 1;
                }
            }
        }
        Ok(tmp_txagc)
    }

    /// `_dpk_set_mdpd_para`. Order 0 is the only order the flow uses;
    /// orders 1/2 are transcribed; any other order is a no-op, as in
    /// Linux (it only logs).
    fn a_dpk_set_mdpd_para(&mut self, order: u8) -> Result<(), Error> {
        match order {
            0 => {
                self.wm(R_LDL_NORM, B_LDL_NORM_OP, 0)?;
                self.wm(R_LDL_NORM, B_LDL_NORM_PN, 0x3)?;
                self.wm(R_MDPK_SYNC, B_MDPK_SYNC_MAN, 0x1)
            }
            1 | 2 => {
                self.wm(R_LDL_NORM, B_LDL_NORM_OP, u32::from(order))?;
                self.wm(R_LDL_NORM, B_LDL_NORM_PN, 0)?;
                self.wm(R_MDPK_SYNC, B_MDPK_SYNC_MAN, 0)
            }
            _ => Ok(()),
        }
    }

    /// `_dpk_idl_mpa`.
    async fn a_dpk_idl_mpa(&mut self, path: u8) -> Result<(), Error> {
        self.a_dpk_set_mdpd_para(0)?;
        self.a_dpk_table_select(path, 1)?;
        self.a_dpk_one_shot(path, ID_MDPK_IDL).await
    }

    /// `_dpk_fill_result` (`kidx` is always 0: reload is disabled;
    /// `gain` is always 1 from `_dpk_cal_select`).
    fn a_dpk_fill_result(
        &mut self,
        path: u8,
        gain: u8,
        txagc: u8,
        state: &mut Path,
    ) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        let pwsf: u16 = 0x78;
        let gs: u8 = 0x5b;
        self.wm(R_COEF_SEL + off, B_COEF_SEL_MDPD, 0)?;
        state.txagc_dpk = txagc;
        self.wm(
            R_TXAGC_RFK + off,
            0x3f << (u32::from(gain) << 3),
            u32::from(txagc),
        )?;
        state.pwsf = pwsf;
        self.wm(
            R_DPD_BND + off,
            0x1ff << (u32::from(gain) << 4),
            u32::from(pwsf),
        )?;
        self.wm(R_LOAD_COEF + off, B_LOAD_COEF_MDPD, 0x1)?;
        self.wm(R_LOAD_COEF + off, B_LOAD_COEF_MDPD, 0)?;
        state.gs = gs;
        self.wm(R_DPD_CH0A + off, u32::MAX, 0x065b5b5b)?;
        self.wm(R_DPD_V1 + off, u32::MAX, 0)?;
        self.wm(R_MDPK_SYNC, B_MDPK_SYNC_SEL, 0)
    }

    /// `_dpk_main` (`gain` is always 1). Returns true on failure
    /// (sync/AGC failure: a completed bypassed path, not an error).
    /// `thermal` is the current averaged thermal for this path.
    async fn a_dpk_main(
        &mut self,
        path: u8,
        channel: Profile,
        thermal: u8,
        state: &mut Path,
    ) -> Result<bool, Error> {
        // `_rf_direct_cntrl(path, is_bybb = false)`.
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0x0).await?;
        let mut txagc = self.a_dpk_set_tx_pwr(path).await?;
        self.a_dpk_rf_setting(path, channel).await?;
        self.a_dpk_rx_dck(path).await?;
        self.a_dpk_kip_setting(path)?;
        self.a_dpk_manual_txcfir(path, true).await?;
        txagc = self.a_dpk_agc(path, channel, state, txagc).await?;
        let is_fail = txagc == TXAGC_INVAL;
        // `_dpk_get_thermal`.
        state.ther_dpk = thermal;
        self.a_dpk_idl_mpa(path).await?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RR_MOD_V_RX).await?;
        self.a_dpk_fill_result(path, 1, txagc, state)?;
        self.a_dpk_manual_txcfir(path, false).await?;
        state.path_ok = !is_fail;
        Ok(is_fail)
    }

    /// `_dpk_onoff`: `is_dpk_enable` is true at entry; `val` is the
    /// enable bit written into `R_DPD_CH0A` byte 3.
    fn a_dpk_onoff(&mut self, path: u8, off: bool, state: &Path) -> Result<(), Error> {
        let val = u32::from(!off && state.path_ok);
        self.wm(R_DPD_CH0A + (u32::from(path) << 8), 0xff000000, 0x6 | val)
    }
}

impl Dpk {
    /// Latest per-path results, only after a completed DPK run.
    pub fn results(&self) -> Option<&[Path; 2]> {
        self.completed.then_some(&self.paths)
    }
    /// Whether the last run force-bypassed DPK (`_dpk_bypass_check`).
    pub fn bypassed(&self) -> bool {
        self.bypassed
    }
    /// rtw8852a_rfk.c `rtw8852a_dpk(PHY_0)`: `BTC_WRFKT_DPK` START,
    /// `rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_AB)` (2us step,
    /// 5000us), then `_dpk`: the FEM bypass check, or `_dpk_cal_select`
    /// (BB backup, per-path TSSI pause + KIP/RF backup + information,
    /// BB/AFE set, per-path `_dpk_main` + on/off, BB/AFE restore, BB
    /// restore, per-path KIP restore + reload + RF restore + TSSI
    /// resume), then resume and STOP. 8852A is Wi-Fi 6: a 6GHz channel
    /// is refused with `Error::Policy`.
    ///
    /// # Safety
    /// Actual RTL8852A PHY0 (non-DBCC) after `rfk::a::Init::prepare`,
    /// the BB/RF retune to THIS `channel` and its RX DCK + IQK;
    /// `thermal` is the current averaged thermal per path,
    /// `tssi_mode` the retained TSSI enable state, `epa` the FEM
    /// external-PA presence `(epa_2g, epa_5g)`, `cut` the chip cut
    /// version. Current admission is enforced by Interface at every
    /// access. No concurrent PHY/packet/reset/PM owner; the outer
    /// attempt closes and retains DMA on failure/cancellation.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        cut: u8,
        tssi_mode: [bool; 2],
        thermal: [u8; 2],
        epa: [bool; 2],
    ) -> Result<(), Error> {
        if channel.band() == Band::Ghz6 {
            return Err(Error::Policy);
        }
        self.completed = false;
        self.channel = Some(channel);
        self.paths = [Path::default(); 2];
        io.admit()?;
        io.begin(Kind::Dpk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        access.a_wait_rx_mode().await?;
        // `_dpk_bypass_check`.
        self.bypassed =
            (epa[0] && channel.band() == Band::Ghz2) || (epa[1] && channel.band() == Band::Ghz5);
        if self.bypassed {
            // `_dpk_force_bypass`.
            for path in 0..2u8 {
                access.a_dpk_onoff(path, true, &self.paths[usize::from(path)])?;
            }
        } else {
            // `_dpk_cal_select` (reload disabled: `cur_idx` is 0).
            let bb = access.a_backup_bb()?;
            let mut kip = [[0u32; 2]; 2];
            let mut rf = [[0u32; 8]; 2];
            for path in 0..2u8 {
                let p = usize::from(path);
                if tssi_mode[p] {
                    access.a_dpk_tssi_pause(path, true)?;
                }
                for (slot, register) in kip[p].iter_mut().zip(KIP_REG) {
                    *slot = access.bb(register + (u32::from(path) << 8), u32::MAX)?;
                }
                rf[p] = access.a_backup_rf(path).await?;
                // `_dpk_information`.
                self.paths[p].band = channel.band();
                self.paths[p].ch = channel.center();
                self.paths[p].bw = channel.width();
            }
            access.a_dpk_bb_afe_setting().await?;
            for path in 0..2u8 {
                let p = usize::from(path);
                let failed = access
                    .a_dpk_main(path, channel, thermal[p], &mut self.paths[p])
                    .await?;
                access.a_dpk_onoff(path, failed, &self.paths[p])?;
            }
            access.a_dpk_bb_afe_restore().await?;
            access.a_restore_bb(&bb)?;
            for path in 0..2u8 {
                let p = usize::from(path);
                access.a_dpk_kip_restore(path, cut)?;
                for (register, value) in KIP_REG.into_iter().zip(kip[p]) {
                    access.wm(register + (u32::from(path) << 8), u32::MAX, value)?;
                }
                access.a_restore_rf(path, &rf[p]).await?;
                if tssi_mode[p] {
                    access.a_dpk_tssi_pause(path, false)?;
                }
            }
        }
        access.0.admit()?;
        access.0.resume(saved).await?;
        access.0.admit()?;
        access.0.end(Kind::Dpk).await?;
        self.completed = true;
        Ok(())
    }

    /// rtw8852a_rfk.c `_dpk_track`: recompute `R_DPD_BND` from the
    /// thermal delta against the DPK-time thermal, the TSSI offset
    /// state and `extra_ofst` (from `_tssi_track`). No BTC bracket:
    /// Linux calls this from `rtw8852a_rfk_track` without one.
    ///
    /// # Safety
    /// Same retained owner after [`Self::run`]; no concurrent
    /// RFK/PHY/reset/PM owner. `thermal` is the current averaged
    /// thermal per path; `extra_ofst` is the TSSI track offset per
    /// path; `tssi_mode` the retained TSSI enable state.
    pub async unsafe fn track(
        &mut self,
        io: &mut impl Interface,
        thermal: [u8; 2],
        extra_ofst: [i8; 2],
        tssi_mode: [bool; 2],
    ) -> Result<(), Error> {
        let mut access = Access(io);
        for path in 0..2u8 {
            let p = usize::from(path);
            let state = &self.paths[p];
            let cur_ther = thermal[p];
            let mut delta = 0i8;
            if state.ch != 0 && cur_ther != 0 {
                delta = (state.ther_dpk as i8).wrapping_sub(cur_ther as i8);
            }
            delta = if state.band == Band::Ghz2 {
                (i32::from(delta) * 3 / 2) as i8
            } else {
                (i32::from(delta) * 5 / 2) as i8
            };
            let txagc_rf =
                access.bb(R_TXAGC_BB + (u32::from(path) << 13), RR_MODOPT_M_TXPWR)? as u8;
            let (pwsf0, pwsf1) = if tssi_mode[p] {
                // `trk_idx` is read for a debug print only in Linux.
                let _ = access.rr(path, RR_TXA, RR_TXA_TRK).await?;
                let txagc_bb = access.bb(R_TXAGC_BB + (u32::from(path) << 13), 0x00ff0000)? as i8;
                let txagc_bb_tp =
                    access.bb(R_TXAGC_TP + (u32::from(path) << 13), B_TXAGC_TP)? as u8;
                let mut txagc_ofst =
                    access.bb(R_TXAGC_BB + (u32::from(path) << 13), 0xff000000)? as i8;
                if access.bb(R_DPD_COM + (u32::from(path) << 8), 1 << 15)? == 0x1 {
                    txagc_ofst = 0;
                }
                let mut ini_diff = 0i8;
                if txagc_rf != 0 && cur_ther != 0 {
                    ini_diff = txagc_ofst.wrapping_add(delta);
                }
                let base = i32::from(state.pwsf) + i32::from(ini_diff) + i32::from(extra_ofst[p]);
                if access.bb(R_P0_TXDPD + (u32::from(path) << 13), B_P0_TXDPD)? == 0x0 {
                    let v = base + i32::from(txagc_bb_tp) - i32::from(txagc_bb);
                    (v as u16, v as u16)
                } else {
                    (base as u16, base as u16)
                }
            } else {
                let v = (i32::from(state.pwsf) + i32::from(delta)) & 0x1ff;
                (v as u16, v as u16)
            };
            if access.bb(R_DPK_TRK, B_DPK_TRK_DIS)? == 0x0 && txagc_rf != 0 {
                access.wm(
                    R_DPD_BND + (u32::from(path) << 8),
                    0x000001ff,
                    u32::from(pwsf0),
                )?;
                access.wm(
                    R_DPD_BND + (u32::from(path) << 8),
                    0x01ff0000,
                    u32::from(pwsf1),
                )?;
            }
        }
        Ok(())
    }
}

#[rustfmt::skip]
pub(super) const DPK_BB_AFE_R_DEFS_A: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x101),Entry(3,0,0x12b8,0x40000000,0x0),
Entry(3,0,0x5864,0xc0000000,0x0),Entry(3,0,0x2008,0x1ffffff,0x0),
Entry(3,0,0xc1c,0x4,0x0),Entry(3,0,0x700,0x8000000,0x0),
Entry(1,0,0xc70,0x1f,0x3),Entry(1,0,0xc70,0x3e0,0x3),
Entry(3,0,0x12a0,0xff000,0x0),Entry(3,0,0x700,0x7000000,0x0),
Entry(3,0,0x5864,0x20000000,0x0),Entry(3,0,0xc3c,0x200,0x0),
Entry(3,0,0x20fc,0xffff0000,0x0),Entry(3,0,0x58c8,0x1000000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_R_DEFS_AB: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x303),Entry(3,0,0x12b8,0x40000000,0x0),
Entry(3,0,0x32b8,0x40000000,0x0),Entry(3,0,0x5864,0xc0000000,0x0),
Entry(3,0,0x7864,0xc0000000,0x0),Entry(3,0,0x2008,0x1ffffff,0x0),
Entry(3,0,0xc1c,0x4,0x0),Entry(3,0,0x700,0x8000000,0x0),
Entry(1,0,0xc70,0x1f,0x3),Entry(1,0,0xc70,0x3e0,0x3),
Entry(3,0,0x12a0,0xff000,0x0),Entry(3,0,0x32a0,0xff000,0x0),
Entry(3,0,0x700,0x7000000,0x0),Entry(3,0,0x5864,0x20000000,0x0),
Entry(3,0,0x7864,0x20000000,0x0),Entry(3,0,0xc3c,0x200,0x0),
Entry(3,0,0x20fc,0xffff0000,0x0),Entry(3,0,0x58c8,0x1000000,0x0),
Entry(3,0,0x78c8,0x1000000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_R_DEFS_B: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x202),Entry(3,0,0x32b8,0x40000000,0x0),
Entry(3,0,0x7864,0xc0000000,0x0),Entry(3,0,0x2008,0x1ffffff,0x0),
Entry(3,0,0x2c1c,0x4,0x0),Entry(3,0,0x2700,0x8000000,0x0),
Entry(1,0,0xc70,0x1f,0x3),Entry(1,0,0xc70,0x3e0,0x3),
Entry(3,0,0x32a0,0xff000,0x0),Entry(3,0,0x2700,0x7000000,0x0),
Entry(3,0,0x7864,0x20000000,0x0),Entry(3,0,0x2c3c,0x200,0x0),
Entry(3,0,0x20fc,0xffff0000,0x0),Entry(3,0,0x78c8,0x1000000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_S_DEFS_AB: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x303),Entry(2,0,0x12b8,0x40000000,0x0),
Entry(2,0,0x32b8,0x40000000,0x0),Entry(1,0,0x30c,0xff000000,0x13),
Entry(1,0,0x32c,0xffff0000,0x41),Entry(2,0,0x12b8,0x10000000,0x0),
Entry(2,0,0x58c8,0x1000000,0x0),Entry(2,0,0x78c8,0x1000000,0x0),
Entry(2,0,0x5864,0xc0000000,0x0),Entry(2,0,0x7864,0xc0000000,0x0),
Entry(2,0,0x2008,0x1ffffff,0x0),Entry(2,0,0xc1c,0x4,0x0),
Entry(2,0,0x700,0x8000000,0x0),Entry(2,0,0xc70,0x3ff,0x0),
Entry(2,0,0xc60,0x3,0x0),Entry(2,0,0xc6c,0x1,0x0),
Entry(2,0,0x58ac,0x8000000,0x0),Entry(2,0,0x78ac,0x8000000,0x0),
Entry(2,0,0xc3c,0x200,0x0),Entry(2,0,0x2344,0x80000000,0x0),
Entry(2,0,0x4490,0x80000000,0x0),Entry(2,0,0x12a0,0x7000,0x0),
Entry(2,0,0x12a0,0x8000,0x0),Entry(1,0,0x12a0,0x70000,0x3),
Entry(2,0,0x12a0,0x80000,0x0),Entry(1,0,0x32a0,0x70000,0x3),
Entry(2,0,0x32a0,0x80000,0x0),Entry(2,0,0x700,0x1000000,0x0),
Entry(1,0,0x700,0x6000000,0x2),Entry(1,0,0x20fc,0xffff0000,0x3333),
Entry(1,0,0x58f0,0x80000,0x0),Entry(1,0,0x78f0,0x80000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_SF_DEFS_A: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x101),Entry(2,0,0x12b8,0x40000000,0x0),
Entry(1,0,0x30c,0xff000000,0x13),Entry(1,0,0x32c,0xffff0000,0x41),
Entry(2,0,0x12b8,0x10000000,0x0),Entry(2,0,0x58c8,0x1000000,0x0),
Entry(2,0,0x5864,0xc0000000,0x0),Entry(2,0,0x2008,0x1ffffff,0x0),
Entry(2,0,0xc1c,0x4,0x0),Entry(2,0,0x700,0x8000000,0x0),
Entry(2,0,0xc70,0x3ff,0x0),Entry(2,0,0xc60,0x3,0x0),
Entry(2,0,0xc6c,0x1,0x0),Entry(2,0,0x58ac,0x8000000,0x0),
Entry(2,0,0xc3c,0x200,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_SF_DEFS_B: &[Entry] = &[
Entry(1,0,0x20fc,0xffff0000,0x202),Entry(2,0,0x32b8,0x40000000,0x0),
Entry(1,0,0x30c,0xff000000,0x13),Entry(1,0,0x32c,0xffff0000,0x41),
Entry(2,0,0x32b8,0x10000000,0x0),Entry(2,0,0x78c8,0x1000000,0x0),
Entry(2,0,0x7864,0xc0000000,0x0),Entry(2,0,0x2008,0x1ffffff,0x0),
Entry(2,0,0x2c1c,0x4,0x0),Entry(2,0,0x2700,0x8000000,0x0),
Entry(2,0,0xc70,0x3ff,0x0),Entry(2,0,0xc60,0x3,0x0),
Entry(2,0,0xc6c,0x1,0x0),Entry(2,0,0x78ac,0x8000000,0x0),
Entry(2,0,0x2c3c,0x200,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_SR_DEFS_A: &[Entry] = &[
Entry(2,0,0x4490,0x80000000,0x0),Entry(2,0,0x12a0,0x7000,0x0),
Entry(2,0,0x12a0,0x8000,0x0),Entry(1,0,0x12a0,0x70000,0x3),
Entry(2,0,0x12a0,0x80000,0x0),Entry(2,0,0x700,0x1000000,0x0),
Entry(1,0,0x700,0x6000000,0x2),Entry(1,0,0x20fc,0xffff0000,0x1111),
Entry(1,0,0x58f0,0x80000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_BB_AFE_SR_DEFS_B: &[Entry] = &[
Entry(2,0,0x6490,0x80000000,0x0),Entry(2,0,0x32a0,0x7000,0x0),
Entry(2,0,0x32a0,0x8000,0x0),Entry(1,0,0x32a0,0x70000,0x3),
Entry(2,0,0x32a0,0x80000,0x0),Entry(2,0,0x2700,0x1000000,0x0),
Entry(1,0,0x2700,0x6000000,0x2),Entry(1,0,0x20fc,0xffff0000,0x2222),
Entry(1,0,0x78f0,0x80000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_LBK_RXIQK_DEFS_F: &[Entry] = &[
Entry(1,0,0x30c,0xff000000,0xf),Entry(4,0,0x0,0x0,0x1),
Entry(1,0,0x30c,0xff000000,0x3),Entry(1,0,0x32c,0xffff0000,0xa001),
Entry(4,0,0x0,0x0,0x1),Entry(1,0,0x32c,0xffff0000,0xa041),
Entry(2,0,0x8074,0x80000000,0x0),
];
#[rustfmt::skip]
pub(super) const DPK_LBK_RXIQK_DEFS_R: &[Entry] = &[
Entry(3,0,0x8074,0x80000000,0x0),Entry(1,0,0x30c,0xff000000,0x1f),
Entry(4,0,0x0,0x0,0x1),Entry(1,0,0x30c,0xff000000,0x13),
Entry(1,0,0x32c,0xffff0000,0x1),Entry(4,0,0x0,0x0,0x1),
Entry(1,0,0x32c,0xffff0000,0x41),Entry(1,0,0x20fc,0xffff0000,0x303),
Entry(1,0,0x20fc,0xffff0000,0x3333),
];
#[rustfmt::skip]
pub(super) const DPK_PAS_READ_DEFS: &[Entry] = &[
Entry(1,0,0x80d4,0xff0000,0x6),Entry(3,0,0x80bc,0x4000,0x0),
Entry(1,0,0x80c0,0xff0000,0x8),
];
