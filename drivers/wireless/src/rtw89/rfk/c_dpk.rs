// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C channel DPK: rtw8852c_rfk.c `rtw8852c_dpk(PHY_0)` for the
//! non-DBCC RF_AB pair on one typed [`Profile`], with `rtw8852c_dpk_init`
//! state (`is_dpk_enable`, reload disabled, so `cur_idx` is always 0).
//!
//! Linux only logs a 20ms one-shot timeout and indexes `dpk_par_regs` with
//! an unchecked `cur_k_set`; NARF fails such an attempt closed. A DPK that
//! Linux reports as "need Check" (sync/AGC failure) leaves that path's MDPD
//! off exactly as `_dpk_onoff(path, true)`; it is a completed, bypassed
//! path, not an error.
use super::super::operating_channel_c::{Band, Profile, Width};
use super::{power, Access, Error, Interface, Kind};
#[path = "c_dpk_tables.rs"]
mod tables;
use tables::*;

const RFREG_MASK: u32 = 0xfffff;
const RR_MOD: u32 = 0x00;
const RR_MOD_MASK: u32 = 0xf_0000;
const RR_MOD_M_RXBB: u32 = 0x3e0;
const RR_MOD_V1: u32 = 0x10000;
const RR_RSV1: u32 = 0x05;
const RR_RSV1_RST: u32 = 1;
const RR_TXIG: u32 = 0x11;
const RR_TXIG_GR0: u32 = 0x3;
const RR_TXIG_GR1: u32 = 0x70;
const RR_TXIG_TG: u32 = 0x1_f000;
const RR_TXAC: u32 = 0x5f;
const RR_TXAC_IQG: u32 = 0xf;
const RR_RXBB: u32 = 0x83;
const RR_RXBB_ATTC: u32 = 0x7;
const RR_RXBB_ATTR: u32 = 0xf0;
const RR_RXA2: u32 = 0x8c;
const RR_RXA2_ATT: u32 = 0xf;
const RR_RXBB2: u32 = 0x8f;
const RR_RXBB2_EBW: u32 = 0x60;
const RR_DCKC: u32 = 0x95;
const RR_DCKC_CHK: u32 = 1 << 3;
const RR_IQGEN: u32 = 0x97;
const RR_IQGEN_BIAS: u32 = 0xf00;
const RR_TXIQK: u32 = 0x98;
const RR_TXIQK_ATT2: u32 = 0xf000;
const RR_TIA: u32 = 0x9e;
const RR_TIA_N6: u32 = 1 << 8;
const RR_LOGEN: u32 = 0xa3;
const RR_LOGEN_RPT: u32 = 0xf_0000;
const RR_LUTDBG: u32 = 0xdf;
const RR_LUTDBG_TIA: u32 = 1 << 12;
const RR_BBDC: u32 = 0x10005;
const RR_BBDC_SEL: u32 = 1;
/// `enum rf_mode` RF_RX / RF_DPK.
const RF_RX: u32 = 0x3;
const RF_DPK: u32 = 0x5;

const R_ANAPAR_PW15: u32 = 0x030c;
const R_ANAPAR: u32 = 0x032c;
const R_P0_RXCK: u32 = 0x12a0;
const B_P0_TXCK_ALL: u32 = 0x000f_f000;
const R_P0_NRBW: u32 = 0x12b8;
const B_P0_NRBW_DBG: u32 = 1 << 30;
const R_ADC_FIFO: u32 = 0x20fc;
const B_ADC_FIFO_A0: u32 = 1 << 16;
const B_ADC_FIFO_A1: u32 = 1 << 20;
const B_ADC_FIFO_A2: u32 = 1 << 24;
const B_ADC_FIFO_A3: u32 = 1 << 28;
const R_UPD_CLK: u32 = 0x5670;
const B_IQK_RFC_ON: u32 = 1 << 1;
const R_TXPWRB: u32 = 0x56cc;
const B_TXPWRB_ON: u32 = 1 << 28;
const B_TXPWRB_VAL: u32 = 0x0ff8_0000;
const R_TXPWRB_H: u32 = 0x580c;
const B_TXPWRB_RDY: u32 = 1 << 15;
const R_P0_TSSI_TRK: u32 = 0x5818;
const B_P0_TSSI_TRK_EN: u32 = 1 << 30;
const R_NCTL_CFG: u32 = 0x8000;
const R_NCTL_N1: u32 = 0x8010;
const R_IQK_DIF4: u32 = 0x802c;
const R_TPG_SEL: u32 = 0x8068;
const R_TPG_MOD: u32 = 0x806c;
const B_TPG_MOD_F: u32 = 0x6;
const R_MDPK_RX_DCK: u32 = 0x8074;
const B_MDPK_RX_DCK_EN: u32 = 1 << 31;
const R_KIP_MOD: u32 = 0x8078;
const B_KIP_MOD: u32 = 0xf_ffff;
const R_DPK_IDL: u32 = 0x809c;
const B_DPK_IDL: u32 = 1 << 8;
const R_LDL_NORM: u32 = 0x80a0;
const B_LDL_NORM_MA: u32 = 1 << 16;
const B_LDL_NORM_OP: u32 = 0x3;
const R_DPK_CFG2: u32 = 0x80bc;
const B_DPK_CFG2_ST: u32 = 1 << 14;
const R_DPK_CFG3: u32 = 0x80c0;
const R_KPATH_CFG: u32 = 0x80d0;
const B_KPATH_CFG_ED: u32 = 0x30_0000;
const R_KIP_RPT1: u32 = 0x80d4;
const B_KIP_RPT1_SEL: u32 = 0x3f_0000;
const R_DPK_MPA: u32 = 0x80ec;
const B_DPK_MPA_T0: u32 = 1 << 10;
const B_DPK_MPA_T1: u32 = 1 << 9;
const B_DPK_MPA_T2: u32 = 1 << 8;
const R_RPT_COM: u32 = 0x80fc;
const B_PRT_COM_CORI: u32 = 0xff;
const B_PRT_COM_CORV: u32 = 0xff00;
const B_PRT_COM_DCI: u32 = 0x0fff_0000;
const B_PRT_COM_DCQ: u32 = 0xfff;
const B_PRT_COM_GL: u32 = 0xf0;
const B_PRT_COM_SYNERR: u32 = 1 << 30;
const R_COEF_SEL: u32 = 0x8104;
const B_COEF_SEL_MDPD: u32 = 1 << 8;
const R_RXIQC: u32 = 0x813c;
const R_DPK_GN: u32 = 0x819c;
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

/// `enum rtw8852c_dpk_id` one-shots used by the flow.
const D_KIP_PRESET: u32 = 0x28;
const D_TXAGC: u32 = 0x29;
const D_RXAGC: u32 = 0x2a;
const D_SYNC: u32 = 0x2b;
const D_GAIN_LOSS: u32 = 0x2c;
const D_MDPK_IDL: u32 = 0x2d;
const LBK_RXIQK: u32 = 0x06;
const D_KIP_RESTORE: u32 = 0x31;
/// `enum adc_ck` ADC_1920M / `enum dac_ck` DAC_960M.
const ADC_1920M: u32 = 3;
const DAC_960M: u32 = 7;
/// `_dpk_cal_select` `kip_reg[]`.
const KIP_REG: [u32; 7] = [0x813c, 0x8124, 0x8120, 0xc0c4, 0xc0e8, 0xc0d4, 0xc0d8];
/// `rtw8852c_backup_rf_regs`.
const BACKUP_RF: [u32; 7] = [0xdf, 0x5f, 0x8f, 0x97, 0xa3, 0x5, 0x10005];
/// `dpk_par_regs[kidx][k_set]`.
const PAR_REGS: [[u32; 4]; 2] = [
    [0x8190, 0x8194, 0x8198, 0x81a4],
    [0x81a8, 0x81c4, 0x81c8, 0x81e8],
];

/// `rtw89_dpk_bkup_para` for the single (index 0) entry of one path.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Path {
    pub path_ok: bool,
    pub mdpd_en: u8,
    pub k_set: u8,
    pub txagc_dpk: u8,
    pub ther_dpk: u8,
    pub gs: u8,
    pub corr_idx: u8,
    pub corr_val: u8,
    pub dc_i: u16,
    pub dc_q: u16,
}

/// `rtw89_dpk_info` for RTL8852C.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) struct Dpk {
    pub paths: [Path; 2],
    pub channel: Option<Profile>,
    /// `_dpk_bypass_check`: CAV cut outside 2.4GHz forced bypass.
    pub bypassed: bool,
    completed: bool,
}

impl<I: Interface> Access<'_, I> {
    /// `_dpk_one_shot` (10us step, 20ms budget, then 10us and the
    /// R_NCTL_N1 byte0 clear).
    async fn d_one_shot(&mut self, path: u8, id: u32) -> Result<(), Error> {
        let command = (id << 8) | (0x19 + u32::from(path) * 0x12);
        self.wm(R_NCTL_CFG, u32::MAX, command)?;
        let start = self.0.now_us();
        while self.bb(0xbff8, 0xff)? != 0x55 {
            if self.0.now_us().saturating_sub(start) >= 20_000 {
                return Err(power::Error::Timeout.into());
            }
            self.delay(10).await?;
        }
        self.delay(10).await?;
        self.wm(R_NCTL_N1, 0xff, 0)
    }
    /// `_dpk_kip_control_rfc`.
    fn d_rfc(&mut self, path: u8, by_kip: bool) -> Result<(), Error> {
        self.wm(
            R_UPD_CLK + (u32::from(path) << 13),
            B_IQK_RFC_ON,
            u32::from(by_kip),
        )
    }
    /// `_dpk_txpwr_bb_force`.
    fn d_txpwr_force(&mut self, path: u8, force: bool) -> Result<(), Error> {
        let off = u32::from(path) << 13;
        self.wm(R_TXPWRB + off, B_TXPWRB_ON, u32::from(force))?;
        self.wm(R_TXPWRB_H + off, B_TXPWRB_RDY, u32::from(force))
    }
    /// `_dpk_kset_query`; refuses a `cur_k_set` outside `dpk_par_regs`.
    fn d_kset(&mut self, path: u8, state: &mut Path) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        self.wm(R_KIP_RPT + off, B_KIP_RPT_SEL, 0x10)?;
        let set = (self.bb(R_RPT_PER + off, 0xe000_0000)? as u8).wrapping_sub(1);
        if usize::from(set) >= PAR_REGS[0].len() {
            return Err(Error::Terminal);
        }
        state.k_set = set;
        Ok(())
    }
    /// `_dpk_kip_set_txagc`.
    async fn d_txagc(&mut self, path: u8, dbm: Option<u8>, state: &mut Path) -> Result<(), Error> {
        if let Some(dbm) = dbm {
            let dbm = dbm.clamp(7, 24);
            self.wm(
                R_TXPWRB + (u32::from(path) << 13),
                B_TXPWRB_VAL,
                u32::from(dbm) << 2,
            )?;
        }
        self.d_one_shot(path, D_TXAGC).await?;
        self.d_kset(path, state)
    }
    /// `_dpk_sync_check`: true = failed.
    fn d_sync_check(&mut self, state: &mut Path) -> Result<bool, Error> {
        let sign12 = |v: u32| (((v << 20) as i32) >> 20).unsigned_abs() as u16;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        state.corr_idx = self.bb(R_RPT_COM, B_PRT_COM_CORI)? as u8;
        state.corr_val = self.bb(R_RPT_COM, B_PRT_COM_CORV)? as u8;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x9)?;
        state.dc_i = sign12(self.bb(R_RPT_COM, B_PRT_COM_DCI)?);
        state.dc_q = sign12(self.bb(R_RPT_COM, B_PRT_COM_DCQ)?);
        // RXBB / RXBB-overlimit diagnostics (no decision).
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x8)?;
        self.bb(R_RPT_COM, 0x3f)?;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x31)?;
        self.bb(R_RPT_COM, 1 << 8)?;
        self.bb(R_RPT_COM, 1)?;
        Ok(state.dc_i > 200 || state.dc_q > 200 || state.corr_val < 170)
    }
    /// `_dpk_dgain_read`.
    fn d_dgain(&mut self) -> Result<u32, Error> {
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        self.bb(R_RPT_COM, B_PRT_COM_DCI)
    }
    /// `_dpk_kip_set_rxagc`.
    async fn d_rxagc(&mut self, path: u8, state: &mut Path) -> Result<bool, Error> {
        self.d_rfc(path, false)?;
        let mode = self.rr(path, RR_MOD, RFREG_MASK).await?;
        self.wm(R_KIP_MOD, B_KIP_MOD, mode)?;
        self.d_rfc(path, true)?;
        self.d_one_shot(path, D_RXAGC).await?;
        self.d_sync_check(state)
    }
    /// `_dpk_lbk_rxiqk`.
    async fn d_lbk_rxiqk(&mut self, path: u8) -> Result<(), Error> {
        let off = u32::from(path) << 8;
        self.wm(R_DPD_V1 + off, B_DPD_LBK, 1)?;
        self.wm(R_MDPK_RX_DCK, B_MDPK_RX_DCK_EN, 1)?;
        self.d_rfc(path, false)?;
        let rxbb = self.rr(path, RR_MOD, RR_MOD_M_RXBB).await?;
        let rf_11 = self.rr(path, RR_TXIG, RFREG_MASK).await?;
        let sw = self.bb(R_KIP_IQP + off, B_KIP_IQP_SW)?;
        self.wr(path, RR_TXIG, RR_TXIG_GR0, 0).await?;
        self.wr(path, RR_TXIG, RR_TXIG_GR1, 0x3).await?;
        self.wr(path, RR_TXIG, RR_TXIG_TG, 0xd).await?;
        self.wr(path, RR_MOD, RR_MOD_M_RXBB, 0x1f).await?;
        self.wm(R_KIP_IQP + off, B_KIP_IQP_IQSW, 0x12)?;
        self.wm(R_KIP_IQP + off, B_KIP_IQP_SW, 0x3)?;
        self.d_rfc(path, true)?;
        // RX_TONE_IDX, Q.2 9.25MHz.
        self.wm(R_IQK_DIF4, u32::MAX, 0x0025_0025)?;
        self.d_one_shot(path, LBK_RXIQK).await?;
        self.bb(R_RXIQC + off, u32::MAX)?;
        self.d_rfc(path, false)?;
        self.wr(path, RR_TXIG, RFREG_MASK, rf_11).await?;
        self.wr(path, RR_MOD, RR_MOD_M_RXBB, rxbb).await?;
        self.wm(R_KIP_IQP + off, B_KIP_IQP_SW, sw)?;
        self.wm(R_MDPK_RX_DCK, B_MDPK_RX_DCK_EN, 0)?;
        self.wm(R_KPATH_CFG, B_KPATH_CFG_ED, 0)?;
        self.wm(R_LOAD_COEF + off, B_LOAD_COEF_DI, 1)?;
        self.d_rfc(path, true)
    }
    /// `_dpk_gainloss` (+ `_dpk_gainloss_read`).
    async fn d_gainloss(&mut self, path: u8, state: &mut Path) -> Result<u32, Error> {
        self.d_one_shot(path, D_GAIN_LOSS).await?;
        self.d_txagc(path, None, state).await?;
        let off = u32::from(path) << 8;
        self.wm(R_DPK_GL + off, B_DPK_GL_A1, 0)?;
        self.wm(R_DPK_GL + off, B_DPK_GL_A0, 0)?;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0x6)?;
        self.wm(R_DPK_CFG2, B_DPK_CFG2_ST, 1)?;
        self.bb(R_RPT_COM, B_PRT_COM_GL)
    }
    /// `_dpk_pas_read(is_check = true)`: 0 NOR, 1 GT, 2 LT.
    fn d_pas(&mut self) -> Result<u8, Error> {
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
    /// `_dpk_agc`: true = failed (sync check).
    async fn d_agc(&mut self, path: u8, band: Band, state: &mut Path) -> Result<bool, Error> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Step {
            SyncDgain,
            GainLossIdx,
            GlGt,
            GlLt,
            SetTxGain,
        }
        let mut step = Step::SyncDgain;
        let (mut dbm, mut gl_idx, mut agc_count) = (15u8, 0u32, 0u8);
        let mut is_fail = false;
        let mut limit = 200;
        loop {
            let mut goout = false;
            match step {
                Step::SyncDgain => {
                    is_fail = self.d_rxagc(path, state).await?;
                    if is_fail {
                        goout = true;
                    } else {
                        let dgain = self.d_dgain()?;
                        if !(0x556..=0x5fc).contains(&dgain) {
                            self.d_one_shot(path, D_SYNC).await?;
                            self.d_dgain()?;
                        }
                        if agc_count == 0 {
                            if band == Band::Ghz2 {
                                // `_dpk_bypass_rxiqc`.
                                let off = u32::from(path) << 8;
                                self.wm(R_DPD_V1 + off, B_DPD_LBK, 1)?;
                                self.wm(R_RXIQC + off, u32::MAX, 0x4000_0002)?;
                            } else {
                                self.d_lbk_rxiqk(path).await?;
                            }
                        }
                        step = Step::GainLossIdx;
                    }
                }
                Step::GainLossIdx => {
                    gl_idx = self.d_gainloss(path, state).await?;
                    let pas = self.d_pas()?;
                    step = if pas == 2 && gl_idx > 0 {
                        Step::GlLt
                    } else if (pas == 1 && gl_idx == 0) || gl_idx >= 7 {
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
                        self.d_txagc(path, Some(dbm), state).await?;
                    }
                    step = Step::SyncDgain;
                    agc_count += 1;
                }
                Step::GlLt => {
                    if dbm >= 24 {
                        goout = true;
                    } else {
                        dbm = (dbm + 2).min(24);
                        self.d_txagc(path, Some(dbm), state).await?;
                    }
                    step = Step::SyncDgain;
                    agc_count += 1;
                }
                Step::SetTxGain => {
                    self.d_rfc(path, false)?;
                    let rxbb = self.rr(path, RR_MOD, RR_MOD_M_RXBB).await?;
                    self.wr(path, RR_MOD, RR_MOD_M_RXBB, (rxbb + gl_idx).min(0x1f))
                        .await?;
                    self.d_rfc(path, true)?;
                    goout = true;
                }
            }
            limit -= 1;
            if goout || agc_count >= 6 || limit <= 0 {
                break;
            }
        }
        Ok(is_fail)
    }
    /// `_dpk_set_mdpd_para`.
    async fn d_mdpd(&mut self, order: u8) -> Result<(), Error> {
        self.table(match order {
            0 => &DPK_MDPD_ORDER0_DEFS,
            1 => &DPK_MDPD_ORDER1_DEFS,
            2 => &DPK_MDPD_ORDER2_DEFS,
            _ => &DPK_MDPD_ORDER3_DEFS,
        })
        .await
    }
    /// `_dpk_idl_mpa`.
    async fn d_idl_mpa(&mut self, path: u8, width: Width) -> Result<(), Error> {
        self.wm(R_LDL_NORM, B_LDL_NORM_MA, 1)?;
        let order = if self.bb(R_DPK_MPA, B_DPK_MPA_T2)? == 1 {
            2
        } else if self.bb(R_DPK_MPA, B_DPK_MPA_T1)? == 1 {
            1
        } else if self.bb(R_DPK_MPA, B_DPK_MPA_T0)? == 1 {
            0
        } else {
            match width {
                Width::Mhz20 => 2,
                Width::Mhz40 | Width::Mhz80 => 1,
                // Linux `_dpk_idl_mpa` falls to `else` (0x0) for any
                // bandwidth other than 5/10/20/40/80, including 160
                // and 320MHz.
                Width::Mhz160 | Width::Mhz320 => 0,
            }
        };
        self.d_mdpd(order).await?;
        self.wm(R_DPK_IDL, B_DPK_IDL, 0)?;
        self.delay(1000).await?;
        self.d_one_shot(path, D_MDPK_IDL).await?;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0)?;
        self.bb(R_RPT_COM, u32::MAX)?;
        self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0xf)?;
        let mut overflow = self.bb(R_RPT_COM, B_PRT_COM_SYNERR)?;
        let mut count = 0;
        while count < 5 && overflow == 1 {
            self.d_one_shot(path, D_MDPK_IDL).await?;
            self.wm(R_KIP_RPT1, B_KIP_RPT1_SEL, 0xf)?;
            overflow = self.bb(R_RPT_COM, B_PRT_COM_SYNERR)?;
            count += 1;
        }
        if overflow != 0 {
            self.d_mdpd(2).await?;
            self.d_one_shot(path, D_MDPK_IDL).await?;
        }
        Ok(())
    }
    /// `_dpk_rf_setting` (`dbcc_en` = 0).
    async fn d_rf_setting(&mut self, path: u8, channel: Profile) -> Result<(), Error> {
        if channel.band() == Band::Ghz2 {
            self.wr(path, RR_MOD, RFREG_MASK, 0x50121 | 1).await?;
            self.wr(path, RR_MOD_V1, RR_MOD_MASK, RF_DPK).await?;
            self.wr(path, RR_RXBB, RR_RXBB_ATTC, 0x2).await?;
            self.wr(path, RR_RXBB, RR_RXBB_ATTR, 0x4).await?;
            self.wr(path, RR_LUTDBG, RR_LUTDBG_TIA, 1).await?;
            self.wr(path, RR_TIA, RR_TIA_N6, 1).await?;
            // The diagnostic RF dump reads (no decision).
            for address in [RR_MOD, RR_RXBB, RR_TIA, 0x1a, RR_LUTDBG, 0x1001a] {
                self.rr(path, address, RFREG_MASK).await?;
            }
            return Ok(());
        }
        self.wr(path, RR_MOD, RFREG_MASK, 0x50101 | 1).await?;
        self.wr(path, RR_MOD_V1, RR_MOD_MASK, RF_DPK).await?;
        if channel.band() == Band::Ghz6 && channel.center() >= 161 {
            self.wr(path, RR_IQGEN, RR_IQGEN_BIAS, 0x8).await?;
        }
        self.wr(path, RR_LOGEN, RR_LOGEN_RPT, 0xd).await?;
        self.wr(path, RR_TXAC, RR_TXAC_IQG, 0x8).await?;
        self.wr(path, RR_RXA2, RR_RXA2_ATT, 0).await?;
        self.wr(path, RR_TXIQK, RR_TXIQK_ATT2, 0x3).await?;
        self.wr(path, RR_LUTDBG, RR_LUTDBG_TIA, 1).await?;
        self.wr(path, RR_TIA, RR_TIA_N6, 1).await?;
        if channel.width() == Width::Mhz160 {
            self.wr(path, RR_RXBB2, RR_RXBB2_EBW, 0).await?;
        }
        Ok(())
    }
    /// `_dpk_bb_afe_setting`.
    fn d_afe(&mut self, path: u8) -> Result<(), Error> {
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A0 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A1 << path, 0)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A2 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A3 << path, 0)?;
        self.wm(R_UPD_CLK + (u32::from(path) << 13), u32::MAX, 0xd801_dffd)?;
        self.c_txck_force(path, DAC_960M)?;
        self.c_rxck(path, true, ADC_1920M)?;
        self.wm(R_P0_NRBW + (u32::from(path) << 13), B_P0_NRBW_DBG, 1)?;
        self.wm(R_ANAPAR_PW15, 0xff00_0000, 0x1f)?;
        self.wm(R_ANAPAR_PW15, 0xff00_0000, 0x13)?;
        self.wm(R_ANAPAR, 0xffff_0000, 0x0001)?;
        self.wm(R_ANAPAR, 0xffff_0000, 0x0041)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A1 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A3 << path, 1)
    }
    /// `_dpk_bb_afe_restore`.
    fn d_afe_restore(&mut self, path: u8) -> Result<(), Error> {
        let off = u32::from(path) << 13;
        self.wm(R_P0_NRBW + off, B_P0_NRBW_DBG, 0)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A0 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A1 << path, 0)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A2 << path, 1)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A3 << path, 0)?;
        self.wm(R_UPD_CLK + off, u32::MAX, 0)?;
        self.wm(R_P0_RXCK + off, B_P0_TXCK_ALL, 0)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A0 << path, 0)?;
        self.wm(R_ADC_FIFO, B_ADC_FIFO_A2 << path, 0)
    }
    /// `_dpk_main(path, gain = 1)` for `kidx` 0; true = "need Check".
    async fn d_main(
        &mut self,
        path: u8,
        channel: Profile,
        cut: u8,
        state: &mut Path,
    ) -> Result<bool, Error> {
        let off = u32::from(path) << 8;
        self.d_rfc(path, false)?;
        self.wr(path, RR_RSV1, RR_RSV1_RST, 0).await?;
        self.wr(path, RR_BBDC, RFREG_MASK, 0x03ffd).await?;
        self.d_rf_setting(path, channel).await?;
        self.c_set_rx_dck(path).await?;
        self.table(&DPK_KIP_PWR_CLK_ON_DEFS).await?;
        // `_dpk_kip_preset_8852c`.
        let mode = self.rr(path, RR_MOD, RFREG_MASK).await?;
        self.wm(R_KIP_MOD, B_KIP_MOD, mode)?;
        self.wm(
            R_DPD_CH0A + off,
            B_DPD_SEL,
            if cut == 0 { 0x01 } else { 0x0c },
        )?;
        self.d_rfc(path, true)?;
        self.wm(R_COEF_SEL + off, B_COEF_SEL_MDPD, 0)?;
        self.d_one_shot(path, D_KIP_PRESET).await?;
        self.d_txpwr_force(path, true)?;
        self.d_txagc(path, Some(15), state).await?;
        // `_dpk_tpg_sel`: Linux falls to the `else` arm (the 20MHz
        // pair) for any bandwidth other than 160/80/40, including 320MHz.
        let (mode, select) = match channel.width() {
            Width::Mhz160 => (0x3, 0x0180_ff30),
            Width::Mhz80 => (0x0, 0xffe0_fa00),
            Width::Mhz40 => (0x2, 0xff40_09e0),
            Width::Mhz20 | Width::Mhz320 => (0x1, 0xf9f0_07d0),
        };
        self.wm(R_TPG_MOD, B_TPG_MOD_F, mode)?;
        self.wm(R_TPG_SEL, u32::MAX, select)?;
        let failed = self.d_agc(path, channel.band(), state).await?;
        if !failed {
            self.d_idl_mpa(path, channel.width()).await?;
            // `_dpk_para_query`.
            let par = PAR_REGS[0][usize::from(state.k_set)] + off;
            let para = self.bb(par, u32::MAX)?;
            state.txagc_dpk = ((para >> 10) & 0x3f) as u8;
            state.ther_dpk = (para >> 26) as u8;
            // `_dpk_on`.
            self.wm(R_LOAD_COEF + off, B_LOAD_COEF_MDPD, 1)?;
            self.wm(R_LOAD_COEF + off, B_LOAD_COEF_MDPD, 0)?;
            let order = match self.bb(R_LDL_NORM, B_LDL_NORM_OP)? {
                0 => 0x6,
                1 => 0x2,
                2 => 0x0,
                _ => 0x7,
            };
            self.wm(R_DPD_CH0A + off, B_DPD_ORDER, order)?;
            state.mdpd_en = 1 << state.k_set;
            state.path_ok = true;
            self.wm(R_DPD_CH0A + off, B_DPD_MEN, u32::from(state.mdpd_en))?;
            // `_dpk_gain_normalize_8852c(is_execute = false)`.
            self.wm(par, 0x7f, 0x5b)?;
            state.gs = self.bb(par, 0x7f)? as u8;
        }
        self.d_rfc(path, false)?;
        self.wr(path, RR_MOD, RR_MOD_MASK, RF_RX).await?;
        Ok(failed)
    }
    /// `_dpk_onoff(path, off)` with `is_dpk_enable` = true, `kidx` 0.
    fn d_onoff(&mut self, path: u8, off: bool, state: &Path) -> Result<(), Error> {
        let value = if !off && state.path_ok {
            state.mdpd_en
        } else {
            0
        };
        self.wm(
            R_DPD_CH0A + (u32::from(path) << 8),
            B_DPD_MEN,
            u32::from(value),
        )
    }
}

impl Dpk {
    /// Per-path results after a completed DPK (bypassed paths have
    /// `path_ok = false` and MDPD off).
    pub fn results(&self) -> Option<&[Path; 2]> {
        self.completed.then_some(&self.paths)
    }
    /// rtw8852c_rfk.c `rtw8852c_dpk(PHY_0)`: `BTC_WRFKT_DPK` START,
    /// `rtw89_chip_stop_sch_tx`, `_wait_rx_mode(RF_AB)`, `_dpk`
    /// (`_dpk_bypass_check` with no external PA on RTL8852C, else
    /// `_dpk_cal_select` without reload: backup, `_dpk_information`,
    /// `_dpk_init`, TSSI pause, per-path `_dpk_main` + `_dpk_onoff`,
    /// KIP restore, backup reload, AFE restore, TSSI resume, KIP clock
    /// off), then RX DCK when path A RR_DCKC_CHK is set, resume and STOP.
    ///
    /// `cut` is the actual chip cut (`hal.cv`, CHIP_CAV = 0);
    /// `tssi_mode` the retained `is_tssi_mode` after this channel's TSSI.
    ///
    /// # Safety
    /// Actual RTL8852C PHY0 (non-DBCC) after `rfk::c::Init::prepare` and
    /// THIS channel's BB/RF retune, RX DCK, IQK and TSSI; Interface
    /// enforces current admission at every access; no concurrent
    /// PHY/packet/reset/PM owner.
    pub async unsafe fn run(
        &mut self,
        io: &mut impl Interface,
        channel: Profile,
        cut: u8,
        tssi_mode: [bool; 2],
    ) -> Result<(), Error> {
        self.completed = false;
        self.channel = Some(channel);
        self.paths = [Path::default(); 2];
        io.admit()?;
        io.begin(Kind::Dpk).await?;
        io.admit()?;
        let saved = io.pause().await?;
        let mut access = Access(io);
        for path in 0..2 {
            let start = access.0.now_us();
            while access.rr(path, RR_MOD, RR_MOD_MASK).await? == 2 {
                if access.0.now_us().saturating_sub(start) >= 5000 {
                    return Err(power::Error::Timeout.into());
                }
                access.delay(2).await?;
            }
        }
        self.bypassed = cut == 0 && channel.band() != Band::Ghz2;
        if self.bypassed {
            for path in 0..2u8 {
                access.d_onoff(path, true, &self.paths[usize::from(path)])?;
            }
        } else {
            let mut kip = [[0u32; 7]; 2];
            let mut rf = [[0u32; 7]; 2];
            for path in 0..2u8 {
                let p = usize::from(path);
                for (slot, &register) in kip[p].iter_mut().zip(KIP_REG.iter()) {
                    *slot = access.bb(register + (u32::from(path) << 8), u32::MAX)?;
                }
                for (slot, &register) in rf[p].iter_mut().zip(BACKUP_RF.iter()) {
                    *slot = access.rr(path, register, RFREG_MASK).await?;
                }
                if tssi_mode[p] {
                    access.wm(R_P0_TSSI_TRK + (u32::from(path) << 13), B_P0_TSSI_TRK_EN, 1)?;
                }
            }
            for path in 0..2u8 {
                let p = usize::from(path);
                access.c_rxagc(path, 0)?;
                access.wr(path, RR_BBDC, RR_BBDC_SEL, 0).await?;
                access.d_afe(path)?;
                let mut state = Path::default();
                let failed = access.d_main(path, channel, cut, &mut state).await?;
                self.paths[p] = state;
                access.d_onoff(path, failed, &state)?;
            }
            for path in 0..2u8 {
                let p = usize::from(path);
                // `_dpk_kip_restore`.
                access.d_one_shot(path, D_KIP_RESTORE).await?;
                access.d_rfc(path, false)?;
                access.d_txpwr_force(path, false)?;
                for (&value, &register) in kip[p].iter().zip(KIP_REG.iter()) {
                    access.wm(register + (u32::from(path) << 8), u32::MAX, value)?;
                }
                for (&value, &register) in rf[p].iter().zip(BACKUP_RF.iter()) {
                    access.wr(path, register, RFREG_MASK, value).await?;
                }
                access.d_afe_restore(path)?;
                access.c_rxagc(path, 1)?;
                if tssi_mode[p] {
                    access.wm(R_P0_TSSI_TRK + (u32::from(path) << 13), B_P0_TSSI_TRK_EN, 0)?;
                }
            }
            access.table(&DPK_KIP_PWR_CLK_OFF_DEFS).await?;
        }
        if access.rr(0, RR_DCKC, RR_DCKC_CHK).await? == 1 {
            access.c_rx_dck(tssi_mode).await?;
        }
        access.0.admit()?;
        access.0.resume(saved).await?;
        access.0.admit()?;
        access.0.end(Kind::Dpk).await?;
        self.completed = true;
        Ok(())
    }
}
