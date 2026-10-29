// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B `rtw89_track_work` subset for the live PHY0 station: per-peer
//! RSSI statistics (`rtw89_phy_stat_rssi_update`), the IFS-CLM environment
//! monitor (`rtw89_phy_env_monitor_track`), DIG's dynamic packet-detection
//! threshold (`rtw89_phy_dig`; B has `support_igi = false`, so no gain-code
//! writes) and dynamic EDCCA (`rtw89_phy_edcca_track`), in Linux's order.
//! The scope is the native 2.4 GHz, 20 MHz, single-link profile.
use super::power;

/// `RTW89_TRACK_WORK_PERIOD` (2 s).
pub(super) const PERIOD_MS: u64 = 2000;
/// `EDCCA_MAX`: the unlinked level.
pub(super) const EDCCA_MAX: u8 = 249;
const EDCCA_TH_L2H_LB: i32 = 66;
const EDCCA_TH_REF: i32 = 3;
const RSSI_UNIT_CONVER: i32 = 110;
const EDCCA_UNIT_CONVER: i32 = 128;

/// `rtw89_phy_gen_ax.cr_base`.
const BB: u32 = 0x10000;
// rtw89_ccx_regs_ax
const R_CCX: u32 = BB + 0x0c00;
const B_CCX_EDCCA_OPT_MSK: u32 = 0x70;
const B_MEASUREMENT_TRIG_MSK: u32 = 1 << 2;
const B_CCX_TRIG_OPT_MSK: u32 = 1 << 1;
const B_CCX_EN_MSK: u32 = 1 << 0;
const R_IFS_COUNTER: u32 = BB + 0x0c28;
const B_IFS_CLM_PERIOD_MSK: u32 = 0xffff_0000;
const B_IFS_CLM_COUNTER_UNIT_MSK: u32 = 0xc000;
const B_IFS_COUNTER_CLR_MSK: u32 = 1 << 13;
const B_IFS_COLLECT_EN: u32 = 1 << 12;
/// `R_IFS_T1..T4`: TH_HIGH [31:16], EN bit 15, TH_LOW [14:0].
const R_IFS_T: [u32; 4] = [BB + 0x0c2c, BB + 0x0c30, BB + 0x0c34, BB + 0x0c38];
const B_IFS_TH_HIGH_MSK: u32 = 0xffff_0000;
const B_IFS_EN_MSK: u32 = 1 << 15;
const B_IFS_TH_LOW_MSK: u32 = 0x7fff;
const R_IFS_CLM_FA: u32 = BB + 0x1ad4;
const B_IFS_CLM_OFDM_FA_MSK: u32 = 0xffff_0000;
const B_IFS_CLM_CCK_FA_MSK: u32 = 0xffff;
const R_IFSCNT: u32 = BB + 0x1aec;
const B_IFSCNT_DONE_MSK: u32 = 1 << 16;
// rtw8852b_dig_regs
const R_SEG0R_PD_V1: u32 = BB + 0x4860;
const B_SEG0R_PD_LOWER_BOUND_MSK: u32 = 0x7c0;
const B_SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1: u32 = 0x4000_0000;
const R_BMODE_PDTH_EN_V1: u32 = BB + 0x4b74;
const B_BMODE_PDTH_LIMIT_EN_MSK_V1: u32 = 0x4000_0000;
const R_BMODE_PDTH_V1: u32 = BB + 0x4b64;
const B_BMODE_PDTH_LOWER_BOUND_MSK_V1: u32 = 0xff00_0000;
const R_PAGCUGC: [u32; 4] = [BB + 0x46e8, BB + 0x46ec, BB + 0x47a8, BB + 0x47ac];
const B_PAGCUGC_EN_MSK: u32 = 0x20;
// rtw8852b_edcca_regs
const R_SEG0R_EDCCA_LVL_V1: u32 = BB + 0x4884;
const B_EDCCA_LVL_MSK: [u32; 3] = [0x0000_00ff, 0x0000_ff00, 0xff00_0000];
// rtw89_mac_cfg_ppdu_status_ax
const R_AX_PPDU_STAT: u32 = 0xce40;
const PPDU_STAT_ENABLE: u32 = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5);
const R_AX_HW_RPT_FWD: u32 = 0x9c18;
const B_AX_FWD_PPDU_STAT_MASK: u32 = 0x3;
const RTW89_PRPT_DEST_HOST: u32 = 1;

/// Every register track work may touch; the native owner refuses others.
pub(super) const REGISTERS: [u32; 18] = [
    R_CCX,
    R_IFS_COUNTER,
    R_IFS_T[0],
    R_IFS_T[1],
    R_IFS_T[2],
    R_IFS_T[3],
    R_IFS_CLM_FA,
    R_IFSCNT,
    R_SEG0R_PD_V1,
    R_BMODE_PDTH_EN_V1,
    R_BMODE_PDTH_V1,
    R_PAGCUGC[0],
    R_PAGCUGC[1],
    R_PAGCUGC[2],
    R_PAGCUGC[3],
    R_SEG0R_EDCCA_LVL_V1,
    R_AX_PPDU_STAT,
    R_AX_HW_RPT_FWD,
];

/// Register access for track work, enclosed by the owner's current authority.
pub(super) trait Hw {
    fn read(&mut self, address: u32) -> Result<u32, power::Error>;
    fn write(&mut self, address: u32, value: u32) -> Result<(), power::Error>;
    /// `hal.support_cckpd` for the prepared operating PHY.
    fn cck_pd(&mut self) -> Result<bool, power::Error>;
}
fn field(value: u32, mask: u32) -> u32 {
    (value & mask) >> mask.trailing_zeros()
}
fn read(hw: &mut impl Hw, address: u32, mask: u32) -> Result<u32, power::Error> {
    let value = hw.read(address)?;
    if value == u32::MAX {
        return Err(power::Error::Gone);
    }
    Ok(field(value, mask))
}
/// `rtw89_phy_write32_idx`: read-modify-write of one field.
fn write(hw: &mut impl Hw, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    let old = hw.read(address)?;
    if old == u32::MAX {
        return Err(power::Error::Gone);
    }
    hw.write(
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}
/// A configuration write that must read back (not trigger/clear pulses).
fn set(hw: &mut impl Hw, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
    write(hw, address, mask, value)?;
    if read(hw, address, mask)? != value & (mask >> mask.trailing_zeros()) {
        return Err(power::Error::Terminal);
    }
    Ok(())
}

/// `DECLARE_EWMA(rssi, 10, 16)` over PPDU status `RSSI_AVG` samples.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Rssi(u32);
impl Rssi {
    pub(super) fn add(&mut self, sample: u8) {
        let sample = u32::from(sample) << 10;
        self.0 = if self.0 == 0 {
            sample
        } else {
            ((self.0 << 4) - self.0 + sample) >> 4
        };
    }
    pub(super) fn read(&self) -> u8 {
        (self.0 >> 10) as u8
    }
}

/// `rtw89_phy_edcca_get_thre_by_rssi`: `rssi_min` is the weakest linked
/// peer's average (`ch_info->rssi_min`), `None` with no associated station.
pub(super) fn edcca_threshold(rssi_min: Option<u8>) -> u8 {
    match rssi_min {
        None => EDCCA_MAX,
        Some(rssi) => (i32::from(rssi >> 1) - RSSI_UNIT_CONVER + EDCCA_UNIT_CONVER - EDCCA_TH_REF)
            .max(EDCCA_TH_L2H_LB) as u8,
    }
}

// IFS-CLM environment monitor constants (phy.h).
const CCX_MAX_PERIOD: u32 = 2097;
const CCX_MAX_PERIOD_UNIT: u32 = 32;
const MS_TO_4US_RATIO: u32 = 250;
/// `ilog2(CCX_US_BASE_RATIO)`.
const CCX_US_BASE_SHIFT: u32 = 2;
const IFS_CLM_TH0_UPPER: u32 = 64;
const IFS_CLM_TH_MUL: u32 = 4;
const RTW89_CCX_32_US: u32 = 3;
/// `__rtw89_phy_env_monitor_track` background monitor time.
const MNTR_TIME_MS: u32 = 1900;
const PERMIL: u32 = 1000;

/// `rtw89_phy_ccx_ms_to_period_unit`: (period, unit index).
pub(super) fn ccx_period_unit(time_ms: u32) -> (u32, u32) {
    let time_ms = time_ms.min(CCX_MAX_PERIOD);
    let quotient = (CCX_MAX_PERIOD_UNIT * time_ms / CCX_MAX_PERIOD) as u8;
    let unit = match quotient {
        0..=3 => 0,
        4..=7 => 1,
        8..=15 => 2,
        _ => RTW89_CCX_32_US,
    };
    ((time_ms * MS_TO_4US_RATIO) >> unit, unit)
}
/// `rtw89_phy_ifs_clm_th_update_check` thresholds (low, high) in counter units.
pub(super) fn ifs_thresholds(unit: u32) -> [(u16, u16); 4] {
    let to_index = |us: u32| (us >> (CCX_US_BASE_SHIFT + unit)) as u16;
    let mut result = [(0, 0); 4];
    let mut high_us = IFS_CLM_TH0_UPPER;
    result[0] = (0, to_index(high_us));
    for i in 1..4 {
        high_us *= IFS_CLM_TH_MUL;
        result[i] = (result[i - 1].1 + 1, to_index(high_us));
    }
    result
}
/// `rtw89_phy_ccx_get_report`.
pub(super) fn ccx_report(report: u32, score: u32, period: u32) -> u32 {
    if period == 0 {
        return 0;
    }
    let ratio = (report * score + (period >> 1)) / period;
    if ratio >= score {
        score - 1
    } else {
        ratio
    }
}

/// `struct rtw89_env_monitor_info` subset for the background IFS-CLM.
#[derive(Debug, Default)]
struct Env {
    period: u32,
    mntr_time: u32,
    cck_fa_permil: u32,
    ofdm_fa_permil: u32,
}
impl Env {
    /// `rtw89_phy_ccx_top_setting_init` + `rtw89_phy_ifs_clm_setting_init`.
    fn init(&mut self, hw: &mut impl Hw) -> Result<(), power::Error> {
        *self = Self::default();
        set(hw, R_CCX, B_CCX_EN_MSK, 1)?;
        set(hw, R_CCX, B_CCX_TRIG_OPT_MSK, 1)?;
        write(hw, R_CCX, B_MEASUREMENT_TRIG_MSK, 1)?;
        set(hw, R_CCX, B_CCX_EDCCA_OPT_MSK, 0)?;
        Self::thresholds(hw, RTW89_CCX_32_US)?;
        set(hw, R_IFS_COUNTER, B_IFS_COLLECT_EN, 1)?;
        for address in R_IFS_T {
            set(hw, address, B_IFS_EN_MSK, 1)?;
        }
        Ok(())
    }
    fn thresholds(hw: &mut impl Hw, unit: u32) -> Result<(), power::Error> {
        let thresholds = ifs_thresholds(unit);
        for (address, (low, _)) in R_IFS_T.into_iter().zip(thresholds) {
            set(hw, address, B_IFS_TH_LOW_MSK, low.into())?;
        }
        for (address, (_, high)) in R_IFS_T.into_iter().zip(thresholds) {
            set(hw, address, B_IFS_TH_HIGH_MSK, high.into())?;
        }
        Ok(())
    }
    /// `__rtw89_phy_env_monitor_track`: collect a finished IFS-CLM period,
    /// then program (first time) and trigger the next 1900 ms period. The
    /// application never changes from background, so the thresholds written
    /// at init (32 us unit) stay, as in Linux.
    fn track(&mut self, hw: &mut impl Hw) -> Result<(), power::Error> {
        if read(hw, R_IFSCNT, B_IFSCNT_DONE_MSK)? != 0 {
            let fa = hw.read(R_IFS_CLM_FA)?;
            if fa == u32::MAX {
                return Err(power::Error::Gone);
            }
            self.cck_fa_permil = ccx_report(field(fa, B_IFS_CLM_CCK_FA_MSK), PERMIL, self.period);
            self.ofdm_fa_permil = ccx_report(field(fa, B_IFS_CLM_OFDM_FA_MSK), PERMIL, self.period);
        }
        if self.mntr_time != MNTR_TIME_MS {
            let (period, unit) = ccx_period_unit(MNTR_TIME_MS);
            set(hw, R_IFS_COUNTER, B_IFS_CLM_PERIOD_MSK, period)?;
            set(hw, R_IFS_COUNTER, B_IFS_CLM_COUNTER_UNIT_MSK, unit)?;
            self.mntr_time = MNTR_TIME_MS;
            self.period = period;
        }
        // rtw89_phy_ccx_trigger: clear and measurement-trigger pulses.
        write(hw, R_IFS_COUNTER, B_IFS_COUNTER_CLR_MSK, 0)?;
        write(hw, R_CCX, B_MEASUREMENT_TRIG_MSK, 0)?;
        write(hw, R_IFS_COUNTER, B_IFS_COUNTER_CLR_MSK, 1)?;
        write(hw, R_CCX, B_MEASUREMENT_TRIG_MSK, 1)
    }
    fn fa_permil(&self) -> u32 {
        self.cck_fa_permil + self.ofdm_fa_permil
    }
}

// DIG constants (phy.c / phy.h).
const RSSI_NOLINK: u8 = 22;
const FA_TH_2G: [u32; 4] = [22, 44, 66, 88];
const FA_TH_NOLINK: [u32; 4] = [196, 352, 440, 528];
const IGI_OFFSET_MAX: u8 = 25;
const IGI_OFFSET_MUL: u8 = 2;
const IGI_RSSI_MIN: i32 = 10;
const ABS_IGI_MIN: u8 = 0xc;
const IGI_MAX_PERFORMANCE_MODE: u8 = 0x5a;
const PD_LOW_TH_OFFSET: u8 = 16;
const PD_TH_SB_FLTR_CMP_VAL: u8 = 7;
const PD_TH_BW20_CMP_VAL: u8 = 0;
const PD_TH_MIN_RSSI: u8 = 8;
const PD_TH_MAX_RSSI: u8 = 70;
const CCKPD_TH_MIN_RSSI: i8 = -18;
const IGI_RSSI_MAX: i32 = 110;

/// Register values one DIG pass programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DigOutput {
    pub pd: u32,
    pub cck_pd: u32,
    pub sdagc_follow_pagc: bool,
}
/// `struct rtw89_dig_info` subset after `rtw89_phy_dig_reset` on 2.4 GHz
/// (`dyn_pd_th_en`, no forced gain code; `rtw89_phy_dig_update_para`).
#[derive(Debug)]
pub(super) struct Dig {
    linked_pre: bool,
    fa_th: [u32; 4],
    igi_fa_rssi: u8,
    fa_rssi_ofst: u8,
}
impl Default for Dig {
    fn default() -> Self {
        Self {
            linked_pre: false,
            fa_th: FA_TH_NOLINK,
            igi_fa_rssi: 0,
            fa_rssi_ofst: 0,
        }
    }
}
impl Dig {
    /// `__rtw89_phy_dig` decisions for one period (pure).
    pub(super) fn step(&mut self, rssi_min: Option<u8>, fa_permil: u32) -> DigOutput {
        let linked = rssi_min.is_some();
        // rtw89_phy_dig_update_rssi_info
        let igi_rssi = rssi_min.map_or(RSSI_NOLINK, |rssi| rssi >> 1);
        if linked != self.linked_pre {
            self.fa_th = if linked { FA_TH_2G } else { FA_TH_NOLINK };
            self.igi_fa_rssi = igi_rssi;
        }
        self.linked_pre = linked;
        // rtw89_phy_dig_igi_offset_by_env
        let level = self.fa_th.iter().take_while(|&&th| fa_permil >= th).count() as u8;
        let mut offset = self.fa_rssi_ofst;
        if level == 0 {
            offset = if offset < 2 {
                0
            } else {
                offset - IGI_OFFSET_MUL
            };
        } else {
            offset += (level - 1) * IGI_OFFSET_MUL;
        }
        self.fa_rssi_ofst = offset.min(IGI_OFFSET_MAX);
        // rtw89_phy_cal_igi_fa_rssi
        let igi_min = (i32::from(igi_rssi) - IGI_RSSI_MIN).max(0) as u8;
        let dyn_max = (igi_min + IGI_OFFSET_MAX).min(IGI_MAX_PERFORMANCE_MODE);
        let dyn_min = igi_min.max(ABS_IGI_MIN);
        self.igi_fa_rssi = if dyn_max >= dyn_min {
            self.igi_fa_rssi
                .wrapping_add(self.fa_rssi_ofst)
                .clamp(dyn_min, dyn_max)
        } else {
            dyn_max
        };
        // rtw89_phy_dig_dyn_pd_th (enable) with dyn_pd_th_max = igi_rssi
        let under = PD_LOW_TH_OFFSET + PD_TH_SB_FLTR_CMP_VAL + PD_TH_BW20_CMP_VAL;
        let final_rssi = self.igi_fa_rssi.min(igi_rssi);
        let ofdm = final_rssi.clamp(PD_TH_MIN_RSSI + under, PD_TH_MAX_RSSI + under);
        let cck = (final_rssi.wrapping_sub(under) as i8).max(CCKPD_TH_MIN_RSSI);
        DigOutput {
            pd: u32::from((ofdm - under - PD_TH_MIN_RSSI) >> 1),
            cck_pd: (i32::from(cck) - IGI_RSSI_MAX) as u32,
            sdagc_follow_pagc: self.igi_fa_rssi > igi_rssi,
        }
    }
    fn program(hw: &mut impl Hw, output: DigOutput, cck_pd: bool) -> Result<(), power::Error> {
        set(hw, R_SEG0R_PD_V1, B_SEG0R_PD_LOWER_BOUND_MSK, output.pd)?;
        set(hw, R_SEG0R_PD_V1, B_SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1, 1)?;
        if cck_pd {
            set(hw, R_BMODE_PDTH_EN_V1, B_BMODE_PDTH_LIMIT_EN_MSK_V1, 1)?;
            set(
                hw,
                R_BMODE_PDTH_V1,
                B_BMODE_PDTH_LOWER_BOUND_MSK_V1,
                output.cck_pd,
            )?;
        }
        for address in R_PAGCUGC {
            set(
                hw,
                address,
                B_PAGCUGC_EN_MSK,
                output.sdagc_follow_pagc.into(),
            )?;
        }
        Ok(())
    }
}

/// Track-work state for the single station link.
#[derive(Debug, Default)]
pub(super) struct Tracker {
    next_ms: u64,
    initialized: bool,
    env: Env,
    dig: Dig,
    /// `edcca_bak.th_old`: the level last written to hardware.
    threshold: Option<u8>,
    rssi: Rssi,
    peer: Option<[u8; 6]>,
    /// Owner disabled tracking (`disabled_dm_bitmap`).
    disabled: bool,
}
impl Tracker {
    /// `ewma_rssi_init` at station add: a new (or no) peer restarts the average.
    fn observe(&mut self, peer: Option<[u8; 6]>) {
        if self.peer != peer {
            self.peer = peer;
            self.rssi = Rssi::default();
        }
    }
    /// `rtw89_core_rx_process_phy_ppdu_iter`: samples only count for a linked peer.
    pub(super) fn sample(&mut self, peer: Option<[u8; 6]>, rssi: u8) {
        self.observe(peer);
        if peer.is_some() {
            self.rssi.add(rssi);
        }
    }
    pub(super) fn rssi(&self) -> u8 {
        self.rssi.read()
    }
    pub(super) fn disable(&mut self) {
        self.disabled = true;
    }
    /// One `rtw89_track_work` period when due. Linux skips the whole work
    /// item while scanning. The first period performs the `rtw89_core_start`
    /// half: PPDU status reports and `rtw89_phy_env_monitor_init`.
    pub(super) fn run(
        &mut self,
        hw: &mut impl Hw,
        now_ms: u64,
        peer: Option<[u8; 6]>,
        scanning: bool,
    ) -> Result<(), power::Error> {
        if self.disabled || scanning || now_ms < self.next_ms {
            return Ok(());
        }
        self.next_ms = now_ms.saturating_add(PERIOD_MS);
        self.observe(peer);
        let cck_pd = hw.cck_pd()?;
        if !self.initialized {
            set(hw, R_AX_PPDU_STAT, u32::MAX, PPDU_STAT_ENABLE)?;
            set(
                hw,
                R_AX_HW_RPT_FWD,
                B_AX_FWD_PPDU_STAT_MASK,
                RTW89_PRPT_DEST_HOST,
            )?;
            self.env.init(hw)?;
            self.initialized = true;
        }
        let rssi_min = peer.map(|_| self.rssi.read());
        self.env.track(hw)?;
        let output = self.dig.step(rssi_min, self.env.fa_permil());
        Dig::program(hw, output, cck_pd)?;
        let threshold = edcca_threshold(rssi_min);
        if self.threshold != Some(threshold) {
            for mask in B_EDCCA_LVL_MSK {
                set(hw, R_SEG0R_EDCCA_LVL_V1, mask, threshold.into())?;
            }
            self.threshold = Some(threshold);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "track/tests.rs"]
mod tests;
