// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8851B channel DPK and periodic RF tracking from rtw8851b_rfk.c on RF
//! path A (`_kpath` = RF_A, `RF_PATH_NUM_8851B` 1, `cur_idx` 0):
//! `rtw8851b_dpk(PHY_0)` (`_dpk_cal_select` without reload, `_dpk_main`,
//! `_dpk_onoff`, KIP restore and backup reload) and `rtw8851b_rfk_track`
//! (`rtw8851b_dpk_track` + `rtw8851b_lck_track`) behind phy.c
//! `rtw89_phy_stat_thermal_update` with rtw8851b.c `rtw8851b_get_thermal`.
//!
//! `_dpk_information` stores `chan->band_width` in `bp.ch` and
//! `chan->channel` in `bp.bw` (swapped in Linux 7.3-rc4). `_dpk_tpg_sel`
//! and `_dpk_rf_setting` (`RR_BTC_TXBB = bw + 1`) consume `bp.bw`, so the
//! TPG row and TXBB field follow the center channel number exactly as Linux
//! programs them; NARF mirrors that rather than inventing the intended row.
//!
//! Linux only logs the two one-shot poll timeouts and substitutes `cur_k_set`
//! 2 (with `rtw89_warn`) for a K-set index outside `dpk_par_regs`; NARF
//! fails a timeout closed and follows the substitution, except a raw KSET of
//! 0 (`cur_k_set` 0xff, `BIT(0xff)` undefined in `_dpk_on`) which is
//! refused. A "need Check" (sync failure) path leaves MDPD off exactly as
//! `_dpk_onoff(path, true)`; it is a completed, bypassed path, not an error.
use super::super::{
    channel_rf,
    operating_channel::{Profile, Width},
    rf_tracking::Thermal,
};
use super::n51::Results as InitResults;
use super::{power, Access, Error, Interface, Kind};

const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf_0000;
const RR_MOD_RXB: u32 = 0x3e0;
const RR_MOD_V1: u32 = 0x10000;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_TXIG: u32 = 0x11;
const RR_TXIG_GR0: u32 = 0x3;
const RR_TXIG_GR1: u32 = 0x70;
const RR_TXIG_TG: u32 = 0x1_f000;
const RR_CFGCH: u32 = 0x18;
const RR_BTC: u32 = 0x1a;
const RR_BTC_TXBB: u32 = 0x7000;
const RR_BTC_RXBB: u32 = 0xc00;
const RR_TM: u32 = 0x42;
const RR_TM_TRI: u32 = 1 << 19;
const RR_TM_VAL: u32 = 0x7e;
const RR_RXBB: u32 = 0x83;
const RR_RXBB_ATTC: u32 = 0x7;
const RR_RXBB_ATTR: u32 = 0xf0;
const RR_RXA2: u32 = 0x8c;
const RR_RAA2_SATT: u32 = 0xe000;
const RR_RXBB2: u32 = 0x8f;
const RR_RXBB2_EBW: u32 = 0x60;
const RR_LCK_TRG: u32 = 0xd3;
const RR_LCK_TRGSEL: u32 = 1 << 8;
const RR_RCKD: u32 = 0xde;
const RR_RCKD_BW: u32 = 1 << 2;
const RR_BBDC: u32 = 0x10005;
const RR_BBDC_SEL: u32 = 1;
/// rtw8851b_rfk.c `enum rf_mode` RF_RX / RF_DPK.
const RF_RX: u32 = 0x3;
const RF_DPK: u32 = 0x5;

const R_ANAPAR_PW15: u32 = 0x030c;
const B_ANAPAR_PW15: u32 = 0xff00_0000;
const R_ANAPAR: u32 = 0x032c;
const B_ANAPAR_15: u32 = 0xffff_0000;
const R_P0_RXCK: u32 = 0x12a0;
const B_P0_TXCK_ALL: u32 = 0x000f_f000;
const R_P0_NRBW: u32 = 0x12b8;
const B_P0_NRBW_DBG: u32 = 1 << 30;
const R_TSSI_THER: u32 = 0x1c10;
const B_TSSI_THER: u32 = 0x3f00_0000;
const R_TXAGC_BB: u32 = 0x1c60;
const B_TXAGC_RF: u32 = 0x3f;
const R_TXAGC_BTP: u32 = 0x1ca0;
const B_TXAGC_BTP: u32 = 0xff00_0000;
const R_ADC_FIFO: u32 = 0x20fc;
const R_P0_AGC_CTL: u32 = 0x4730;
const B_P0_AGC_EN: u32 = 1 << 31;
const R_UPD_CLK: u32 = 0x5670;
const B_IQK_RFC_ON: u32 = 1 << 1;
const R_TXPWRB: u32 = 0x56cc;
const B_TXPWRB_ON: u32 = 1 << 28;
const B_TXPWRB_VAL: u32 = 0x0ff8_0000;
const R_TXPWRB_H: u32 = 0x580c;
const B_TXPWRB_RDY: u32 = 1 << 15;
const R_P0_TSSI_TRK: u32 = 0x5818;
const B_P0_TSSI_TRK_EN: u32 = 1 << 30;
const R_P0_TSSI_SLOPE_CAL: u32 = 0x581c;
const B_P0_TSSI_SLOPE_CAL_EN: u32 = 1 << 20;
const R_NCTL_CFG: u32 = 0x8000;
const R_NCTL_RPT: u32 = 0x8008;
const R_NCTL_N1: u32 = 0x8010;
const R_IQK_DIF4: u32 = 0x802c;
const R_TPG_SEL: u32 = 0x8068;
const R_TPG_MOD: u32 = 0x806c;
const B_TPG_MOD_F: u32 = 0x6;
const R_MDPK_SYNC: u32 = 0x8070;
const B_MDPK_SYNC_DMAN: u32 = 0x7000_0000;
const R_MDPK_RX_DCK: u32 = 0x8074;
const B_MDPK_RX_DCK_EN: u32 = 1 << 31;
const R_KIP_MOD: u32 = 0x8078;
const B_KIP_MOD: u32 = 0xf_ffff;
const R_KIP_SYSCFG: u32 = 0x8088;
const R_DPK_IDL: u32 = 0x809c;
const B_DPK_IDL_SEL: u32 = 0x600;
const B_DPK_IDL: u32 = 1 << 8;
const R_LDL_NORM: u32 = 0x80a0;
const B_LDL_NORM_PN: u32 = 0x1f00;
const B_LDL_NORM_OP: u32 = 0x3;
const R_DPK_CFG2: u32 = 0x80bc;
const B_DPK_CFG2_ST: u32 = 1 << 14;
const R_DPK_CFG3: u32 = 0x80c0;
const R_KPATH_CFG: u32 = 0x80d0;
const B_KPATH_CFG_ED: u32 = 0x30_0000;
const R_KIP_RPT1: u32 = 0x80d4;
const B_KIP_RPT1_SEL: u32 = 0x3f_0000;
const R_IDL_MPA: u32 = 0x80dc;
const B_IDL_DN: u32 = 1 << 31;
const B_IDL_MD530: u32 = 1 << 1;
const B_IDL_MD500: u32 = 1;
const R_DPK_WR: u32 = 0x80f4;
const R_RPT_COM: u32 = 0x80fc;
const B_RPT_COM_RDY: u32 = 0xffff;
const B_PRT_COM_CORI: u32 = 0xff;
const B_PRT_COM_CORV: u32 = 0xff00;
const B_PRT_COM_DCI: u32 = 0x0fff_0000;
const B_PRT_COM_DCQ: u32 = 0xfff;
const B_PRT_COM_GL: u32 = 0xf0;
const B_PRT_COM_RXBB: u32 = 0x3f;
const B_PRT_COM_RXOV: u32 = 1 << 8;
const R_RXIQC: u32 = 0x813c;
const R_DPD_BND: u32 = 0x81b4;
const R_DPD_V1: u32 = 0x81a0;
const B_DPD_LBK: u32 = 1 << 7;
const R_DPD_CH0A: u32 = 0x81bc;
const B_DPD_SEL: u32 = 0x3f00;
const B_DPD_ORDER: u32 = 0x0700_0000;
const B_DPD_MEN: u32 = 0xf000_0000;
const R_KIP_IQP: u32 = 0x81cc;
const B_KIP_IQP_IQSW: u32 = 0x3f;
const B_KIP_IQP_SW: u32 = 0x3000;
const R_KIP_RPT: u32 = 0x81d4;
const B_KIP_RPT_SEL: u32 = 0x3f_0000;
const R_LOAD_COEF: u32 = 0x81dc;
const B_LOAD_COEF_MDPD: u32 = 1 << 16;
const B_LOAD_COEF_DI: u32 = 1 << 1;
const R_DPK_GL: u32 = 0x81f0;
const B_DPK_GL_A1: u32 = 0x3_ffff;
const B_DPK_GL_A0: u32 = 0xf000_0000;
const R_RPT_PER: u32 = 0x81fc;
const B_RPT_PER_KSET: u32 = 0xe000_0000;
const B_RPT_PER_TSSI: u32 = 0x1fff_0000;
const B_RPT_PER_OF: u32 = 0xff00;
const B_RPT_PER_TH: u32 = 0x3f;
const R_DCIM: u32 = 0xc0ec;
const B_DCIM_FR: u32 = 0x6000;
const R_ADCMOD: u32 = 0xc0e8;
const B_ADCMOD_AUTO_RST: u32 = 1 << 6;

/// `enum dpk_id` one-shots used by the flow.
const D_KIP_PRESET: u32 = 0x28;
const D_TXAGC: u32 = 0x29;
const D_RXAGC: u32 = 0x2a;
const D_SYNC: u32 = 0x2b;
const D_GAIN_LOSS: u32 = 0x2c;
const D_MDPK_IDL: u32 = 0x2d;
const D_KIP_RESTORE: u32 = 0x31;
const LBK_RXIQK: u32 = 0x06;
/// `enum adc_ck` ADC_1920M / `enum dac_ck` DAC_960M.
const ADC_1920M: u32 = 3;
const DAC_960M: u32 = 7;
/// `DPK_VER_8851B`.
pub(in super::super) const DPK_VER_8851B: u8 = 0x11;
/// `dpk_kip_reg[DPK_KIP_REG_NUM_8851B]`.
const KIP_REG: [u32; 8] = [
    0x813c, 0x8124, 0xc0ec, 0xc0e8, 0xc0c4, 0xc0d4, 0xc0d8, 0x12a0,
];
/// `dpk_rf_reg[DPK_RF_REG_NUM_8851B]`.
const RF_REG: [u32; 4] = [0xde, 0x8f, 0x5, 0x10005];
/// `_dpk_para_query` / `_dpk_gain_normalize` `reg[kidx][cur_k_set]`.
const PAR_REGS: [[u32; 4]; 2] = [
    [0x8190, 0x8194, 0x8198, 0x81a4],
    [0x81a8, 0x81c4, 0x81c8, 0x81e8],
];
/// `RTW8851B_LCK_TH`.
const LCK_TH: u8 = 8;

/// `rtw89_dpk_bkup_para` and the per-path `rtw89_dpk_info` fields for the
/// single (`cur_idx` 0) entry of RF path A.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Path {
    /// `bp.band` (`chan->band_type`: 0 2GHz, 1 5GHz).
    pub band: u8,
    /// `bp.ch` as Linux fills it: `chan->band_width`.
    pub ch: u8,
    /// `bp.bw` as Linux fills it: `chan->channel` (the center channel).
    pub bw: u8,
    /// `bp.path_ok` bitmap (`BIT(cur_k_set)` after `_dpk_on`).
    pub path_ok: u8,
    pub txagc_dpk: u8,
    pub ther_dpk: u8,
    pub gs: u8,
    pub corr_idx: u8,
    pub corr_val: u8,
    pub dc_i: u16,
    pub dc_q: u16,
    /// `dpk->cur_k_set` after the last `_dpk_kset_query`.
    pub cur_k_set: u8,
    /// `_dpk_main` returned "need Check".
    pub failed: bool,
}

/// `rtw89_dpk_info` for RTL8851B.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Dpk {
    /// `DPK_VER_8851B` of the last attempt.
    pub version: u8,
    pub path: Path,
    pub channel: Option<Profile>,
    completed: bool,
}

/// `rtw8851b_rfk_track` state: phy.c `phystat.avg_thermal[RF_PATH_A]`
/// (DECLARE_EWMA(thermal, 4, 4)), `lck->thermal[RF_PATH_A]` and the last
/// tracking AACK values.
#[derive(Debug)]
pub(in super::super) struct Track {
    average: Thermal,
    lck_thermal: u8,
    /// Last `rtw8851b_aack` IB values and retry count from a tracking LCK.
    pub aack: Option<([u32; 4], u8)>,
    /// Number of `rtw8851b_lck` reissues (`delta >= RTW8851B_LCK_TH`).
    pub lck_count: u32,
    /// Last `_dpk_track` PWSF write (`0x78 - delta_ther`), if any.
    pub last_pwsf: Option<u32>,
    terminal: bool,
}

/// `_dpk_kset_query`'s `cur_k_set` mapped through Linux's
/// `cur_k_set >= DPK_KSET_NUM` substitution of 2 for the `reg[]` index.
fn par_index(cur_k_set: u8) -> usize {
    if cur_k_set >= 4 {
        2
    } else {
        usize::from(cur_k_set)
    }
}

impl<I: Interface> Access<'_, I> {
    /// `_dpk_one_shot`: 0xbff8 byte0 == 0x55 (10us/20ms), 1us,
    /// `R_RPT_COM` [15:0] == 0x8000 (1us/2ms), clear N1 byte0.
    async fn n51d_one_shot(&mut self, id: u32) -> Result<(), Error> {
        self.wm(R_NCTL_CFG, u32::MAX, (id << 8) | 0x19)?;
        self.n51_poll_eq(0xbff8, 0xff, 0x55, 10, 20_000).await?;
        self.delay(1).await?;
        self.n51_poll_eq(R_RPT_COM, B_RPT_COM_RDY, 0x8000, 1, 2000)
            .await?;
        self.wm(R_NCTL_N1, 0xff, 0)
    }
    /// `_dpk_kip_control_rfc(A, ctrl_by_kip)`.
    fn n51d_rfc(&mut self, by_kip: bool) -> Result<(), Error> {
        self.wm(R_UPD_CLK, B_IQK_RFC_ON, u32::from(by_kip))
    }
    /// `_dpk_txpwr_bb_force(A, force)`.
    fn n51d_txpwr_force(&mut self, force: bool) -> Result<(), Error> {
        self.wm(R_TXPWRB, B_TXPWRB_ON, u32::from(force))?;
        self.wm(R_TXPWRB_H, B_TXPWRB_RDY, u32::from(force))
    }
    /// `_dpk_kset_query(A)`.
    fn n51d_kset(&mut self, state: &mut Path) -> Result<(), Error> {
        self.wm(R_KIP_RPT, B_KIP_RPT_SEL, 0x10)?;
        let set = (self.bb(R_RPT_PER, B_RPT_PER_KSET)? as u8).wrapping_sub(1);
        // `BIT(0xff)` in `_dpk_on` is undefined: refuse a raw KSET of 0.
        if set == u8::MAX {
            return Err(Error::Terminal);
        }
        state.cur_k_set = set;
        Ok(())
    }
    /// `_dpk_kip_set_txagc(A, dbm, set_from_bb)`.
    async fn n51d_txagc(&mut self, dbm: Option<u8>, state: &mut Path) -> Result<(), Error> {
        if let Some(dbm) = dbm {
            let dbm = dbm.clamp(7, 24);
            self.wm(R_TXPWRB, B_TXPWRB_VAL, u32::from(dbm) << 2)?;
        }
        self.n51d_one_shot(D_TXAGC).await?;
        self.n51d_kset(state)
    }
    /// `_dpk_sync_check(A, 0)`: true = failed.
    fn n51d_sync_check(&mut self, state: &mut Path) -> Result<bool, Error> {
        let sign12 = |v: u32| (((v << 20) as i32) >> 20).unsigned_abs() as u16;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        state.corr_idx = self.bb(R_RPT_COM, B_PRT_COM_CORI)? as u8;
        state.corr_val = self.bb(R_RPT_COM, B_PRT_COM_CORV)? as u8;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x9)?;
        state.dc_i = sign12(self.bb(R_RPT_COM, B_PRT_COM_DCI)?);
        state.dc_q = sign12(self.bb(R_RPT_COM, B_PRT_COM_DCQ)?);
        // RXBB / RXBB-overlimit selections (values feed only diagnostics;
        // the selector writes and the two plain reads are Linux's).
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x8)?;
        self.bb(R_RPT_COM, B_PRT_COM_RXBB)?;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x31)?;
        self.bb(R_RPT_COM, B_PRT_COM_RXOV)?;
        Ok(state.dc_i > 200 || state.dc_q > 200 || state.corr_val < 170)
    }
    /// `_dpk_dgain_read`.
    fn n51d_dgain(&mut self) -> Result<u32, Error> {
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        self.bb(R_RPT_COM, B_PRT_COM_DCI)
    }
    /// `_dpk_kip_set_rxagc(A)`.
    async fn n51d_rxagc(&mut self, state: &mut Path) -> Result<bool, Error> {
        self.n51d_rfc(false)?;
        let mode = self.rr(0, RR_MOD, RFREG_MASK).await?;
        self.wm(R_KIP_MOD, B_KIP_MOD, mode)?;
        self.n51d_rfc(true)?;
        self.n51d_one_shot(D_RXAGC).await?;
        self.n51d_sync_check(state)
    }
    /// `_dpk_lbk_rxiqk(A)`.
    async fn n51d_lbk_rxiqk(&mut self) -> Result<(), Error> {
        self.wm(R_DPD_V1, B_DPD_LBK, 1)?;
        self.wm(R_MDPK_RX_DCK, B_MDPK_RX_DCK_EN, 1)?;
        self.n51d_rfc(false)?;
        let rxbb = self.rr(0, RR_MOD, RR_MOD_RXB).await?;
        let rf_11 = self.rr(0, RR_TXIG, RFREG_MASK).await?;
        let sw = self.bb(R_KIP_IQP, B_KIP_IQP_SW)?;
        self.wr(0, RR_TXIG, RR_TXIG_GR0, 0).await?;
        self.wr(0, RR_TXIG, RR_TXIG_GR1, 0x3).await?;
        self.wr(0, RR_TXIG, RR_TXIG_TG, 0xd).await?;
        self.wr(0, RR_MOD, RR_MOD_RXB, 0x1f).await?;
        self.wm(R_KIP_IQP, B_KIP_IQP_IQSW, 0x12)?;
        self.wm(R_KIP_IQP, B_KIP_IQP_SW, 0x3)?;
        self.n51d_rfc(true)?;
        self.wm(R_IQK_DIF4, u32::MAX, 0x0025_0025)?;
        self.n51d_one_shot(LBK_RXIQK).await?;
        self.n51d_rfc(false)?;
        self.wr(0, RR_TXIG, RFREG_MASK, rf_11).await?;
        self.wr(0, RR_MOD, RR_MOD_RXB, rxbb).await?;
        self.wm(R_KIP_IQP, B_KIP_IQP_SW, sw)?;
        self.wm(R_MDPK_RX_DCK, B_MDPK_RX_DCK_EN, 0)?;
        self.wm(R_KPATH_CFG, B_KPATH_CFG_ED, 0)?;
        self.wm(R_LOAD_COEF, B_LOAD_COEF_DI, 1)?;
        self.n51d_rfc(true)
    }
    /// `_dpk_gainloss(A)` + `_dpk_gainloss_read`.
    async fn n51d_gainloss(&mut self, state: &mut Path) -> Result<u32, Error> {
        self.n51d_one_shot(D_GAIN_LOSS).await?;
        self.n51d_txagc(None, state).await?;
        self.wm(R_DPK_GL, B_DPK_GL_A1, 0xf078)?;
        self.wm(R_DPK_GL, B_DPK_GL_A0, 0)?;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x6)?;
        self.wm(R_DPK_CFG2, B_DPK_CFG2_ST, 1)?;
        self.bb(R_RPT_COM, B_PRT_COM_GL)
    }
    /// `_dpk_pas_read(is_check = true)`: 0 NOR, 1 GT, 2 LT.
    fn n51d_pas(&mut self) -> Result<u8, Error> {
        let sign12 = |v: u32| (((v << 20) as i32) >> 20).unsigned_abs();
        self.wm(R_KIP_RPT1, 0xff_0000, 0x06)?;
        self.wm(R_DPK_CFG2, B_DPK_CFG2_ST, 0)?;
        self.wm(R_DPK_CFG3, 0xff_0000, 0x08)?;
        let mut sums = [0u32; 2];
        for (sum, select) in sums.iter_mut().zip([0x00, 0x1f]) {
            self.wm(R_DPK_CFG3, 0xff00_0000, select)?;
            let i = sign12(self.bb(R_RPT_COM, 0xffff_0000)?);
            let q = sign12(self.bb(R_RPT_COM, 0xffff)?);
            *sum = i * i + q * q;
        }
        Ok(if sums[0] < sums[1] {
            2
        } else if sums[0] >= sums[1] * 8 / 5 {
            1
        } else {
            0
        })
    }
    /// `_dpk_agc(A, 0, init_xdbm = 17)`: true = failed (sync check).
    async fn n51d_agc(&mut self, a_band: bool, state: &mut Path) -> Result<bool, Error> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Step {
            SyncDgain,
            GainLossIdx,
            GlGt,
            GlLt,
            SetTxGain,
        }
        let mut step = Step::SyncDgain;
        let (mut dbm, mut gl_idx, mut agc_count) = (17u8, 0u32, 0u8);
        let mut is_fail = false;
        let mut limit = 200i32;
        loop {
            let mut goout = false;
            match step {
                Step::SyncDgain => {
                    is_fail = self.n51d_rxagc(state).await?;
                    if is_fail {
                        goout = true;
                    } else {
                        let dgain = self.n51d_dgain()?;
                        if !(0x556..=0x5fc).contains(&dgain) {
                            self.n51d_one_shot(D_SYNC).await?;
                            self.n51d_dgain()?;
                        }
                        if agc_count == 0 {
                            if a_band {
                                self.n51d_lbk_rxiqk().await?;
                            } else {
                                // `_dpk_bypass_rxiqc(A)`.
                                self.wm(R_DPD_V1, B_DPD_LBK, 1)?;
                                self.wm(R_RXIQC, u32::MAX, 0x4000_0002)?;
                            }
                        }
                        step = Step::GainLossIdx;
                    }
                }
                Step::GainLossIdx => {
                    gl_idx = self.n51d_gainloss(state).await?;
                    // Linux evaluates `_dpk_pas_read` once, and a second
                    // time only on the `tmp_gl_idx == 0` arm.
                    let first = self.n51d_pas()?;
                    step = if first == 2 && gl_idx > 0 {
                        Step::GlLt
                    } else if (gl_idx == 0 && self.n51d_pas()? == 1) || gl_idx >= 7 {
                        Step::GlGt
                    } else if gl_idx == 0 {
                        Step::GlLt
                    } else {
                        Step::SetTxGain
                    };
                }
                Step::GlGt => {
                    if dbm <= 7 {
                        goout = true;
                    } else {
                        dbm = (dbm - 3).max(7);
                        self.n51d_txagc(Some(dbm), state).await?;
                    }
                    step = Step::SyncDgain;
                    agc_count += 1;
                }
                Step::GlLt => {
                    if dbm >= 24 {
                        goout = true;
                    } else {
                        dbm = (dbm + 2).min(24);
                        self.n51d_txagc(Some(dbm), state).await?;
                    }
                    step = Step::SyncDgain;
                    agc_count += 1;
                }
                Step::SetTxGain => {
                    self.n51d_rfc(false)?;
                    let rxbb = self.rr(0, RR_MOD, RR_MOD_RXB).await?;
                    self.wr(0, RR_MOD, RR_MOD_RXB, (rxbb + gl_idx).min(0x1f))
                        .await?;
                    self.n51d_rfc(true)?;
                    goout = true;
                }
            }
            // `while (!goout && agc_cnt < 6 && limit-- > 0)`.
            if goout || agc_count >= 6 {
                break;
            }
            limit -= 1;
            if limit < 0 {
                break;
            }
        }
        Ok(is_fail)
    }
    /// `_dpk_set_mdpd_para(order)` for the orders `_dpk_idl_mpa` selects.
    fn n51d_mdpd(&mut self, order: u8) -> Result<(), Error> {
        let (op, sel, pn, dman) = match order {
            0 => (0x0, 0x2, 0x3, 0x1),
            1 => (0x1, 0x1, 0x0, 0x0),
            _ => (0x2, 0x0, 0x0, 0x0),
        };
        self.wm(R_LDL_NORM, B_LDL_NORM_OP, op)?;
        self.wm(R_DPK_IDL, B_DPK_IDL_SEL, sel)?;
        self.wm(R_LDL_NORM, B_LDL_NORM_PN, pn)?;
        self.wm(R_MDPK_SYNC, B_MDPK_SYNC_DMAN, dman)
    }
    /// `_dpk_idl_mpa(A)`.
    async fn n51d_idl_mpa(&mut self) -> Result<(), Error> {
        let order = if self.bb(R_IDL_MPA, B_IDL_MD500)? == 1 {
            2
        } else if self.bb(R_IDL_MPA, B_IDL_MD530)? == 1 {
            1
        } else {
            0
        };
        self.n51d_mdpd(order)?;
        self.wm(R_DPK_IDL, B_DPK_IDL, 0)?;
        self.delay(1000).await?;
        self.n51d_one_shot(D_MDPK_IDL).await
    }
    /// `_dpk_rf_setting(A, 0)` (`dbcc_en` = 0); `bw` is Linux's `bp.bw`
    /// (the center channel).
    async fn n51d_rf_setting(&mut self, state: &Path) -> Result<(), Error> {
        if state.band == 0 {
            self.wr(0, RR_MOD, RFREG_MASK, 0x50521).await?;
            self.wr(0, RR_MOD_V1, RR_MOD_MASK, RF_DPK).await?;
            self.wr(0, RR_RXBB, RR_RXBB_ATTC, 0x0).await?;
            self.wr(0, RR_RXBB, RR_RXBB_ATTR, 0x7).await?;
        } else {
            self.wr(0, RR_MOD, RFREG_MASK, 0x50521 | 1).await?;
            self.wr(0, RR_MOD_V1, RR_MOD_MASK, RF_DPK).await?;
            self.wr(0, RR_RXA2, RR_RAA2_SATT, 0x3).await?;
        }
        self.wr(0, RR_RCKD, RR_RCKD_BW, 0x1).await?;
        // `rtw89_write_rf` keeps only the RR_BTC_TXBB field bits.
        let txbb = (u32::from(state.bw) + 1) & (RR_BTC_TXBB >> RR_BTC_TXBB.trailing_zeros());
        self.wr(0, RR_BTC, RR_BTC_TXBB, txbb).await?;
        self.wr(0, RR_BTC, RR_BTC_RXBB, 0x0).await?;
        self.wr(0, RR_RXBB2, RR_RXBB2_EBW, 0x0).await
    }
    /// `_dpk_bb_afe_setting(A)`.
    async fn n51d_afe(&mut self) -> Result<(), Error> {
        self.wm(R_ADC_FIFO, 1 << 16, 1)?;
        self.wm(R_ADC_FIFO, 1 << 20, 0)?;
        self.wm(R_ADC_FIFO, 1 << 24, 1)?;
        self.wm(R_ADC_FIFO, 1 << 28, 0)?;
        self.wm(R_UPD_CLK, u32::MAX, 0xd801_dffd)?;
        self.n51_txck_force(DAC_960M)?;
        self.n51_rxck_force(ADC_1920M)?;
        self.wm(R_DCIM, B_DCIM_FR, 0)?;
        self.wm(R_ADCMOD, B_ADCMOD_AUTO_RST, 1)?;
        self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 1)?;
        self.delay(1).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x1f)?;
        self.delay(10).await?;
        self.wm(R_ANAPAR_PW15, B_ANAPAR_PW15, 0x13)?;
        self.delay(2).await?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x0001)?;
        self.delay(2).await?;
        self.wm(R_ANAPAR, B_ANAPAR_15, 0x0041)?;
        self.delay(10).await?;
        self.wm(R_ADC_FIFO, 1 << 20, 1)?;
        self.wm(R_ADC_FIFO, 1 << 28, 1)
    }
    /// `_dpk_bb_afe_restore(A)`.
    fn n51d_afe_restore(&mut self) -> Result<(), Error> {
        self.wm(R_P0_NRBW, B_P0_NRBW_DBG, 0)?;
        self.wm(R_ADC_FIFO, 1 << 16, 1)?;
        self.wm(R_ADC_FIFO, 1 << 20, 0)?;
        self.wm(R_ADC_FIFO, 1 << 24, 1)?;
        self.wm(R_ADC_FIFO, 1 << 28, 0)?;
        self.wm(R_UPD_CLK, u32::MAX, 0)?;
        self.wm(R_P0_RXCK, B_P0_TXCK_ALL, 0)?;
        self.wm(R_ADC_FIFO, 1 << 16, 0)?;
        self.wm(R_ADC_FIFO, 1 << 24, 0)
    }
    /// `_dpk_main(A)`: true = "need Check".
    async fn n51d_main(&mut self, state: &mut Path) -> Result<bool, Error> {
        self.n51d_rfc(false)?;
        // `_rfk_rf_direct_cntrl(A, false)`.
        self.wr(0, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(0, RR_BBDC, RFREG_MASK, 0x03ffd).await?;
        self.n51d_rf_setting(state).await?;
        self.n51_set_rx_dck(RF_DPK).await?;
        // `_dpk_kip_pwr_clk_onoff(true)`.
        self.wm(R_NCTL_RPT, u32::MAX, 0x0000_0080)?;
        self.wm(R_KIP_SYSCFG, u32::MAX, 0x807f_030a)?;
        // `_dpk_kip_preset(A, 0)`.
        let mode = self.rr(0, RR_MOD, RFREG_MASK).await?;
        self.wm(R_KIP_MOD, B_KIP_MOD, mode)?;
        self.wm(R_DPD_CH0A, B_DPD_SEL, 0x01)?;
        self.n51d_rfc(true)?;
        self.n51d_one_shot(D_KIP_PRESET).await?;
        self.n51d_txpwr_force(true)?;
        self.n51d_txagc(Some(17), state).await?;
        // `_dpk_tpg_sel(A, 0)` on Linux's `bp.bw` (the center channel)
        // against RTW89_CHANNEL_WIDTH_80 (2) / _40 (1).
        let (mode, select) = match state.bw {
            2 => (0x0, 0xffe0_fa00),
            1 => (0x2, 0xff40_09e0),
            _ => (0x1, 0xf9f0_07d0),
        };
        self.wm(R_TPG_MOD, B_TPG_MOD_F, mode)?;
        self.wm(R_TPG_SEL, u32::MAX, select)?;
        let failed = self.n51d_agc(state.band != 0, state).await?;
        if !failed {
            self.n51d_idl_mpa().await?;
            // `_dpk_para_query(A, 0)`.
            let par = PAR_REGS[0][par_index(state.cur_k_set)];
            let para = self.bb(par, u32::MAX)?;
            state.txagc_dpk = ((para >> 10) & 0x3f) as u8;
            state.ther_dpk = ((para >> 26) & 0x3f) as u8;
            // `_dpk_on(A, 0)`.
            self.wm(R_LOAD_COEF, B_LOAD_COEF_MDPD, 1)?;
            self.wm(R_LOAD_COEF, B_LOAD_COEF_MDPD, 0)?;
            // `_dpk_order_convert`: 0xff for (7,3,1) lands as 0x7 in the
            // 3-bit B_DPD_ORDER field.
            let order = match self.bb(R_LDL_NORM, B_LDL_NORM_OP)? {
                0 => 0x6,
                1 => 0x2,
                2 => 0x0,
                _ => 0xff,
            };
            self.wm(R_DPD_CH0A, B_DPD_ORDER, order)?;
            state.path_ok |= 1u8 << state.cur_k_set;
            self.wm(R_DPD_CH0A, B_DPD_MEN, u32::from(state.path_ok))?;
            // `_dpk_gain_normalize(A, 0, is_execute = false)`.
            let par = PAR_REGS[0][par_index(state.cur_k_set)];
            self.wm(par, 0x7f, 0x5b)?;
            state.gs = self.bb(par, 0x7f)? as u8;
        }
        self.n51d_rfc(false)?;
        self.wr(0, RR_MOD, RR_MOD_MASK, RF_RX).await?;
        Ok(failed)
    }
    /// `_dpk_onoff(A, off)` with `is_dpk_enable` = true, `kidx` 0.
    fn n51d_onoff(&mut self, off: bool, state: &Path) -> Result<(), Error> {
        let value = if off { 0 } else { state.path_ok };
        self.wm(R_DPD_CH0A, B_DPD_MEN, u32::from(value))
    }
    /// rtw8851b.c `rtw8851b_get_thermal(RF_PATH_A)`.
    async fn n51d_thermal(&mut self, tssi_mode: bool) -> Result<u8, Error> {
        if tssi_mode {
            return Ok(self.bb(R_TSSI_THER, B_TSSI_THER)? as u8);
        }
        self.wr(0, RR_TM, RR_TM_TRI, 1).await?;
        self.wr(0, RR_TM, RR_TM_TRI, 0).await?;
        self.wr(0, RR_TM, RR_TM_TRI, 1).await?;
        self.delay(200).await?;
        Ok(self.rr(0, RR_TM, RR_TM_VAL).await? as u8)
    }
    /// `_dpk_track` for RF path A, `kidx` 0. Returns the PWSF written.
    fn n51d_track(&mut self, state: &Path) -> Result<Option<u32>, Error> {
        let txagc_rf = self.bb(R_TXAGC_BB, B_TXAGC_RF)?;
        // `txagc_bb` / `txagc_bb_tp` are read by Linux outside the debug
        // arguments and feed only diagnostics.
        self.bb(R_TXAGC_BB, 0xff_0000)?;
        self.bb(R_TXAGC_BTP, B_TXAGC_BTP)?;
        self.wm(R_KIP_RPT, B_KIP_RPT_SEL, 0xf)?;
        let cur_ther = self.bb(R_RPT_PER, B_RPT_PER_TH)? as u8;
        self.bb(R_RPT_PER, B_RPT_PER_OF)?;
        self.bb(R_RPT_PER, B_RPT_PER_TSSI)?;
        // s8 delta_ther = cur_ther - ther_dpk; delta_ther = delta_ther * 2 / 3.
        let delta = (i16::from(cur_ther) - i16::from(state.ther_dpk)) as i8;
        let delta = (i16::from(delta) * 2 / 3) as i8;
        if self.bb(R_IDL_MPA, B_IDL_DN)? == 0 && txagc_rf != 0 {
            let pwsf = (0x78 - i32::from(delta)) as u32;
            self.wm(R_DPD_BND, 0x07fc_0000, pwsf)?;
            return Ok(Some(pwsf));
        }
        Ok(None)
    }
    /// `rtw8851b_lck` (`_set_ch` through channel_rf, `_lck_keep_thermal`
    /// by the caller).
    async fn n51d_lck(&mut self) -> Result<(), Error> {
        let tmp05 = self.rr(0, RR_RSV1, RFREG_MASK).await?;
        let tmp18 = self.rr(0, RR_CFGCH, RFREG_MASK).await?;
        let tmpd3 = self.rr(0, RR_LCK_TRG, RFREG_MASK).await?;
        self.wr(0, RR_MOD, RR_MOD_MASK, 0x3).await?;
        self.wr(0, RR_RSV1, RFREG_MASK, 0x0).await?;
        self.wr(0, RR_LCK_TRG, RR_LCK_TRGSEL, 0x1).await?;
        self.0.admit()?;
        // SAFETY: same retained RTL8851B PHY_0 owner; `tmp18` is the
        // read-back path-A RR_CFGCH word.
        unsafe { channel_rf::set_ch_51(self.0, tmp18) }
            .await
            .map_err(|e| match e {
                channel_rf::Error::Rfk(e) => e,
                channel_rf::Error::Register(e) => e.into(),
                channel_rf::Error::Terminal => Error::Terminal,
            })?;
        self.wr(0, RR_LCK_TRG, RFREG_MASK, tmpd3).await?;
        self.wr(0, RR_RSV1, RFREG_MASK, tmp05).await
    }
}

impl Dpk {
    /// Path-A result after a completed DPK (a "need Check" path has
    /// `failed` set and MDPD off).
    pub fn results(&self) -> Option<&Path> {
        self.completed.then_some(&self.path)
    }
    /// rtw8851b_rfk.c `rtw8851b_dpk(PHY_0)`: `BTC_WRFKT_DPK` START,
    /// `rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_A)` (2us/5000us),
    /// `is_dpk_enable` true / reload off, `_dpk_cal_select` (KIP/RF backup,
    /// `_dpk_information`, `_dpk_init`, TSSI pause, slope-K/RXAGC/DRF off,
    /// `_dpk_bb_afe_setting`, `_dpk_main`, `_dpk_onoff`, `_dpk_kip_restore`,
    /// backup reload, AFE restore, RXAGC/slope-K on, TSSI resume, KIP clock
    /// off), resume and STOP. 160MHz (unsupported by RTL8851B) is refused
    /// before any access.
    ///
    /// `tssi_mode` is the retained `is_tssi_mode[RF_PATH_A]` after this
    /// channel's TSSI.
    ///
    /// # Safety
    /// Actual RTL8851B PHY_0 after `n51::Init::prepare` and THIS channel's
    /// BB/RF program, RX DCK, IQK and TSSI; Interface enforces current
    /// admission at every access; no concurrent PHY/packet/reset/PM owner.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        tssi_mode: bool,
    ) -> Result<(), Error> {
        self.completed = false;
        if channel.width() == Width::Mhz160 {
            return Err(Error::Policy);
        }
        self.channel = Some(channel);
        self.version = DPK_VER_8851B;
        io.admit()?;
        io.begin(Kind::Dpk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        let start = access.0.now_us();
        while access.rr(0, RR_MOD, RR_MOD_MASK).await? == 2 {
            if access.0.now_us().saturating_sub(start) >= 5000 {
                return Err(power::Error::Timeout.into());
            }
            access.delay(2).await?;
        }
        let mut kip = [0u32; KIP_REG.len()];
        for (slot, &register) in kip.iter_mut().zip(KIP_REG.iter()) {
            *slot = access.bb(register, u32::MAX)?;
        }
        let mut rf = [0u32; RF_REG.len()];
        for (slot, &register) in rf.iter_mut().zip(RF_REG.iter()) {
            *slot = access.rr(0, register, RFREG_MASK).await?;
        }
        // `_dpk_information` (Linux's swapped ch/bw) and `_dpk_init`.
        let mut state = Path {
            band: u8::from(channel.is_5ghz()),
            ch: channel.width() as u8,
            bw: channel.center(),
            ..Path::default()
        };
        if tssi_mode {
            access.wm(R_P0_TSSI_TRK, B_P0_TSSI_TRK_EN, 1)?;
        }
        access.wm(R_P0_TSSI_SLOPE_CAL, B_P0_TSSI_SLOPE_CAL_EN, 0)?;
        access.wm(R_P0_AGC_CTL, B_P0_AGC_EN, 0)?;
        access.wr(0, RR_BBDC, RR_BBDC_SEL, 0).await?;
        access.n51d_afe().await?;
        let failed = access.n51d_main(&mut state).await?;
        state.failed = failed;
        access.n51d_onoff(failed, &state)?;
        self.path = state;
        // `_dpk_kip_restore(A)`.
        access.n51d_one_shot(D_KIP_RESTORE).await?;
        access.n51d_rfc(false)?;
        access.n51d_txpwr_force(false)?;
        for (&value, &register) in kip.iter().zip(KIP_REG.iter()) {
            access.wm(register, u32::MAX, value)?;
        }
        for (&value, &register) in rf.iter().zip(RF_REG.iter()) {
            access.wr(0, register, RFREG_MASK, value).await?;
        }
        access.n51d_afe_restore()?;
        access.wm(R_P0_AGC_CTL, B_P0_AGC_EN, 1)?;
        access.wm(R_P0_TSSI_SLOPE_CAL, B_P0_TSSI_SLOPE_CAL_EN, 1)?;
        if tssi_mode {
            access.wm(R_P0_TSSI_TRK, B_P0_TSSI_TRK_EN, 0)?;
        }
        // `_dpk_kip_pwr_clk_onoff(false)`.
        access.wm(R_NCTL_RPT, u32::MAX, 0)?;
        access.wm(R_KIP_SYSCFG, u32::MAX, 0x8000_0000)?;
        access.wm(R_DPK_WR, 1 << 18, 1)?;
        access.0.admit()?;
        access.0.resume(saved).await?;
        access.0.admit()?;
        access.0.end(Kind::Dpk).await?;
        self.completed = true;
        Ok(())
    }
}

impl Track {
    /// Tracking state after `rtw8851b_rfk_init` (`rtw8851b_lck_init` kept
    /// `lck->thermal[A]` from the then-fresh EWMA).
    pub fn new(init: &InitResults) -> Self {
        Self {
            average: Thermal::default(),
            lck_thermal: init.lck_thermal,
            aack: None,
            lck_count: 0,
            last_pwsf: None,
            terminal: false,
        }
    }
    /// Current `ewma_thermal_read(&phystat.avg_thermal[RF_PATH_A])`.
    pub fn average(&self) -> u8 {
        self.average.read()
    }
    /// core.c `rtw89_track_work` -> phy.c `rtw89_phy_stat_track`'s
    /// `rtw89_phy_stat_thermal_update` (path A; a zero sample is not
    /// added) then `rtw89_core_rfk_track` -> `rtw8851b_rfk_track`:
    /// `_dpk_track`, then `rtw8851b_lck_track` (`rtw8851b_aack` +
    /// `rtw8851b_lck` when `|avg - lck.thermal| >= RTW8851B_LCK_TH`).
    /// Linux skips the work while scanning and in MCC; the caller is the
    /// single-channel retained owner and must not call it during a scan.
    /// Any error leaves this tracker terminal.
    ///
    /// # Safety
    /// Same retained RTL8851B PHY_0 owner after a completed channel
    /// `rfk_channel` whose DPK is `dpk`; `tssi_mode` is the retained
    /// `is_tssi_mode[RF_PATH_A]`; no concurrent RFK/PHY/reset/PM owner.
    pub async unsafe fn step(
        &mut self,
        io: &mut impl Interface,
        dpk: &Dpk,
        tssi_mode: bool,
    ) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::Terminal);
        }
        let Some(path) = dpk.results().copied() else {
            return Err(Error::Policy);
        };
        self.terminal = true;
        let mut access = Access(io);
        let sample = access.n51d_thermal(tssi_mode).await?;
        self.average.add(sample);
        self.last_pwsf = access.n51d_track(&path)?;
        let current = self.average.read();
        if current.abs_diff(self.lck_thermal) >= LCK_TH {
            let mut scratch = InitResults::default();
            access.n51_aack(&mut scratch).await?;
            self.aack = Some((scratch.aack_ib, scratch.aack_rek));
            access.n51d_lck().await?;
            // `_lck_keep_thermal`.
            self.lck_thermal = self.average.read();
            self.lck_count += 1;
        }
        self.terminal = false;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "n51_dpk_tests.rs"]
mod tests;
