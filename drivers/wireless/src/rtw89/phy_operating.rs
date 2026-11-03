// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B static awake receive/carrier-sense initialization after BB tables.
//! Source phy_dm_init's PHYSTS/DIG/CFO/EDCCA; periodic DIG/EDCCA track work is
//! `track.rs`; CFO/antenna tracking stay open.
use super::{
    factory::Identity,
    mac::ChipId,
    power::{self, Io},
    rfk::Error,
};
#[path = "phy_operating/recipe.rs"]
mod recipe;
#[path = "phy_operating/registers.rs"]
mod registers;
use registers::*;
pub(super) const RECIPE: [u8; 32] = recipe::RECIPE;
pub(super) trait Interface: Io {
    fn admit(&mut self) -> Result<(), Error>;
    async fn xtal_write(&mut self, address: u8, value: u8, mask: u8) -> Result<(), Error>;
    async fn xtal_read(&mut self, address: u8) -> Result<u8, Error>;
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Failed,
    Prepared,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WorkingState {
    pub cut: u8,
    pub rfe: u8,
    pub crystal_cap: u8,
    pub crystal_lower: u8,
    pub crystal_upper: u8,
    pub cck_pd: bool,
}
#[derive(Default)]
pub(super) struct Operating {
    state: State,
    working: Option<WorkingState>,
}
struct Access<'a, I>(&'a mut I);
impl<I: Interface> Access<'_, I> {
    fn read(&mut self, address: u32) -> Result<u32, Error> {
        self.0.admit()?;
        let value = self.0.read32(address)?;
        if value == u32::MAX {
            Err(power::Error::Gone.into())
        } else {
            Ok(value)
        }
    }
    fn modify(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(address)?;
        self.0.admit()?;
        self.0.write32(
            address,
            (old & !mask) | ((value << mask.trailing_zeros()) & mask),
        )?;
        if (self.read(address)? & mask) >> mask.trailing_zeros()
            != value & (mask >> mask.trailing_zeros())
        {
            return Err(Error::Terminal);
        }
        Ok(())
    }
    fn bb(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.modify(0x10000 + address, mask, value)
    }
}
impl Operating {
    pub(super) fn state(&self) -> State {
        self.state
    }
    pub(super) fn working(&self) -> Option<WorkingState> {
        (self.state == State::Prepared)
            .then_some(self.working)
            .flatten()
    }
    /// # Safety
    /// Actual retained B BB tables/MAC/firmware PHY-capability owner, PHY0/SCC
    /// channel1/20MHz nonDBCC with no monitor/antdiv. Identity is the completed
    /// factory's corrected snapshot. Interface admits current device, immutable
    /// firmware topology and measured board/policy before every MMIO/analog op.
    /// No concurrent reset/PHY/PM/packet producer; outer Native fails closed.
    pub(super) async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        identity: Identity,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Failed;
        // RTL8851B shares this exact sequence: `rtw8851b_dig_regs` and
        // `rtw8851b_edcca_regs` are byte-identical to RTL8852B's, both set
        // `cfo_hw_comp`, and `rtw89_phy_dig_sdagc_follow_pagc_config` writes
        // the p1 PAGCUGC fields on every AX chip. Only core.c
        // `rtw89_core_setup_phycap` differs: `support_cckpd` is false solely
        // for RTL8852B CAV, so every RTL8851B cut takes the CCK PD reset.
        let n51 = identity.chip() == ChipId::Rtl8851B;
        if !(identity.chip() == ChipId::Rtl8852B || n51)
            || identity.cut() > 15
            || !identity.calibration().valid
            || identity.calibration().rfe_type == 255
        {
            return Err(Error::Table);
        }
        let mut a = Access(io);
        physts(&mut a)?;
        // B support_igi=false in core_setup_phycap; there are no B gain-table
        // reads/forced IGI writes. Initial disabled DIG PD is still real HW.
        a.bb(R_SEG0R_PD_V1, B_SEG0R_PD_LOWER_BOUND_MSK, 0)?;
        a.bb(R_SEG0R_PD_V1, B_SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1, 0)?;
        let cck_pd = n51 || identity.cut() > 0;
        if cck_pd {
            a.bb(R_BMODE_PDTH_EN_V1, B_BMODE_PDTH_LIMIT_EN_MSK_V1, 0)?;
            // Exact first no-link DIG reset: igi_rssi initially0, under-region
            //16+AX filter7, clamp(-23,-18) then subtract IGI_RSSI_MAX110.
            a.bb(
                R_BMODE_PDTH_V1,
                B_BMODE_PDTH_LOWER_BOUND_MSK_V1,
                (-128i32) as u32,
            )?;
        }
        for (address, mask) in [
            (
                R_PATH0_P20_FOLLOW_BY_PAGCUGC_V2,
                B_PATH0_P20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
            (
                R_PATH0_S20_FOLLOW_BY_PAGCUGC_V2,
                B_PATH0_S20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
            (
                R_PATH1_P20_FOLLOW_BY_PAGCUGC_V2,
                B_PATH1_P20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
            (
                R_PATH1_S20_FOLLOW_BY_PAGCUGC_V2,
                B_PATH1_S20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
        ] {
            a.bb(address, mask, 0)?;
        }
        let cap = identity.xtal() & 0x7f;
        for address in [5, 4] {
            a.0.admit()?;
            a.0.xtal_write(address, cap, 255).await?;
        }
        for address in [5, 4] {
            a.0.admit()?;
            if a.0.xtal_read(address).await? != cap {
                return Err(Error::Terminal);
            }
        }
        a.bb(R_DCFO_OPT, B_DCFO_OPT_EN, 1)?;
        a.bb(R_DCFO_WEIGHT, B_DCFO_WEIGHT_MSK, 8)?;
        // B.cfo_hw_comp=true; this register belongs to MAC, not BB aperture.
        a.modify(R_AX_PWR_UL_CTRL2, B_AX_PWR_UL_CFO_MASK, 6)?;
        // AX bb_wrap/ch_info callbacks and B.rfe_gpio are NULL. Firmware's
        // qualified RFAB profile has no antdiv; those source paths are no-ops.
        a.bb(R_TX_COLLISION_T2R_ST, B_TX_COLLISION_T2R_ST_M, 0x29)?;
        a.0.admit()?;
        self.working = Some(WorkingState {
            cut: identity.cut(),
            rfe: identity.calibration().rfe_type,
            crystal_cap: cap,
            crystal_lower: cap.saturating_sub(64).max(1),
            crystal_upper: cap.saturating_add(64).min(127),
            cck_pd,
        });
        self.state = State::Prepared;
        Ok(())
    }
}
/// RTL8852C `rtw8852c_dig_regs` addresses that differ from B's (reg.h).
mod c_regs {
    pub(super) const R_SEG0R_PD: u32 = 0x481c;
    pub(super) const B_SEG0R_PD_SPATIAL_REUSE_EN_MSK: u32 = 1 << 29;
    pub(super) const R_PATH0_P20_FOLLOW_BY_PAGCUGC_V1: u32 = 0x4c24;
    pub(super) const R_PATH0_S20_FOLLOW_BY_PAGCUGC_V1: u32 = 0x4c28;
    pub(super) const R_PATH1_P20_FOLLOW_BY_PAGCUGC_V1: u32 = 0x4ce8;
    pub(super) const R_PATH1_S20_FOLLOW_BY_PAGCUGC_V1: u32 = 0x4cec;
    pub(super) const R_DCFO: u32 = 0x4264;
    pub(super) const B_DCFO: u32 = 0xff;
}
impl Operating {
    /// RTL8852C phy.c `rtw89_phy_dm_init` sub-inits between
    /// `rtw8852c_bb_sethw` and `rtw89_phy_init_rf_nctl`, PHY_0 non-DBCC,
    /// default (2.4GHz channel 1 / 20MHz, unlinked) chandef:
    /// `rtw89_physts_parsing_init` (AX PHYSTS, identical to B),
    /// `rtw89_phy_dig_init` with `rtw8852c_dig_regs` (core.c: `support_igi`
    /// false, `support_cckpd` true for every C cut; `R_SEG0R_PD` and the
    /// `_V1` PAGCUGC registers), `rtw89_phy_cfo_init` (XTAL SI SC_XO/SC_XI
    /// as B; `rtw89_dcfo_comp_init` with `cfo_hw_comp = false`: `R_DCFO` = 1
    /// and `R_AX_PWR_UL_CTRL2` CFO cleared) and `rtw89_phy_edcca_init`.
    /// `bb_wrap`/`ch_info` are BE-only, `ul_tb_waveform_ctrl` is false and
    /// RTL8852C has no antenna diversity or `rfe_gpio`; those are no-ops.
    ///
    /// # Safety
    /// As [`Self::prepare`], for the actual retained C BB tables/MAC/
    /// firmware PHY-capability owner directly after `bb_sethw`.
    pub(super) async unsafe fn prepare_c(
        &mut self,
        io: &mut impl Interface,
        identity: Identity,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Failed;
        if identity.chip() != ChipId::Rtl8852C
            || identity.cut() > 15
            || !identity.calibration().valid
            || identity.calibration().rfe_type == 255
        {
            return Err(Error::Table);
        }
        let mut a = Access(io);
        physts(&mut a)?;
        // `rtw89_phy_dig_dyn_pd_th(rssi_nolink, false)`.
        a.bb(c_regs::R_SEG0R_PD, B_SEG0R_PD_LOWER_BOUND_MSK, 0)?;
        a.bb(
            c_regs::R_SEG0R_PD,
            c_regs::B_SEG0R_PD_SPATIAL_REUSE_EN_MSK,
            0,
        )?;
        a.bb(R_BMODE_PDTH_EN_V1, B_BMODE_PDTH_LIMIT_EN_MSK_V1, 0)?;
        // Same first unlinked 20MHz reset as B: igi_rssi 0, AX under-region,
        // clamp to CCKPD_TH_MIN_RSSI (-18), minus IGI_RSSI_MAX (110).
        a.bb(
            R_BMODE_PDTH_V1,
            B_BMODE_PDTH_LOWER_BOUND_MSK_V1,
            (-128i32) as u32,
        )?;
        for (address, mask) in [
            (
                c_regs::R_PATH0_P20_FOLLOW_BY_PAGCUGC_V1,
                B_PATH0_P20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
            (
                c_regs::R_PATH0_S20_FOLLOW_BY_PAGCUGC_V1,
                B_PATH0_S20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
            (
                c_regs::R_PATH1_P20_FOLLOW_BY_PAGCUGC_V1,
                B_PATH1_P20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
            (
                c_regs::R_PATH1_S20_FOLLOW_BY_PAGCUGC_V1,
                B_PATH1_S20_FOLLOW_BY_PAGCUGC_EN_MSK,
            ),
        ] {
            a.bb(address, mask, 0)?;
        }
        let cap = identity.xtal() & 0x7f;
        for address in [5, 4] {
            a.0.admit()?;
            a.0.xtal_write(address, cap, 255).await?;
        }
        for address in [5, 4] {
            a.0.admit()?;
            if a.0.xtal_read(address).await? != cap {
                return Err(Error::Terminal);
            }
        }
        a.bb(R_DCFO_OPT, B_DCFO_OPT_EN, 1)?;
        a.bb(R_DCFO_WEIGHT, B_DCFO_WEIGHT_MSK, 8)?;
        a.bb(c_regs::R_DCFO, c_regs::B_DCFO, 1)?;
        a.modify(R_AX_PWR_UL_CTRL2, B_AX_PWR_UL_CFO_MASK, 0)?;
        a.bb(R_TX_COLLISION_T2R_ST, B_TX_COLLISION_T2R_ST_M, 0x29)?;
        a.0.admit()?;
        self.working = Some(WorkingState {
            cut: identity.cut(),
            rfe: identity.calibration().rfe_type,
            crystal_cap: cap,
            crystal_lower: cap.saturating_sub(64).max(1),
            crystal_upper: cap.saturating_add(64).min(127),
            cck_pd: true,
        });
        self.state = State::Prepared;
        Ok(())
    }
}
/// AX `__rtw89_physts_parsing_init(PHY_0)` without monitor mode.
fn physts<I: Interface>(a: &mut Access<'_, I>) -> Result<(), Error> {
    a.bb(R_PLCP_HISTOGRAM, B_STS_DIS_TRIG_BY_FAIL, 1)?;
    a.bb(R_PLCP_HISTOGRAM, B_STS_DIS_TRIG_BY_BRK, 1)?;
    for page in 0..16 {
        if page == 9 {
            continue;
        }
        let address = R_PHY_STS_BITMAP_ADDR_START + (if page > 9 { page - 1 } else { page }) * 4;
        let mut value = a.read(0x10000 + address)?;
        match page {
            6 | 7 => value |= 1 << 13,
            10 => value |= 1 << 13 | 1 << 1,
            11..=15 => {
                value &= !0xf0;
                if page == 11 {
                    value |= 1 << 1;
                } else if page >= 13 {
                    value |= 1 << 20;
                }
            }
            _ => {}
        }
        a.bb(address, u32::MAX, value)?;
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_operating/tests.rs"]
mod tests;

/// Source phy_dm_reinit PHYSTS half, after actual CPWM Active and before
/// ordinary publication. Native encloses this whole bounded transaction in
/// original current device and full joint LPS program scopes.
pub(super) fn restore_physts(io: &mut impl Io) -> Result<(), power::Error> {
    fn modify(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), power::Error> {
        let old = io.read32(address)?;
        if old == u32::MAX {
            return Err(power::Error::Gone);
        }
        io.write32(address, old & !mask | value & mask)?;
        if io.read32(address)? & mask != value & mask {
            return Err(power::Error::Access);
        }
        Ok(())
    }
    modify(
        io,
        0x10000 + R_PLCP_HISTOGRAM,
        B_STS_DIS_TRIG_BY_FAIL | B_STS_DIS_TRIG_BY_BRK,
        B_STS_DIS_TRIG_BY_FAIL | B_STS_DIS_TRIG_BY_BRK,
    )?;
    for page in 0..16 {
        if page == 9 {
            continue;
        }
        let address =
            0x10000 + R_PHY_STS_BITMAP_ADDR_START + (if page > 9 { page - 1 } else { page }) * 4;
        let mut value = io.read32(address)?;
        if value == u32::MAX {
            return Err(power::Error::Gone);
        }
        match page {
            6 | 7 => value |= 1 << 13,
            10 => value |= 1 << 13 | 1 << 1,
            11..=15 => {
                value &= !0xf0;
                if page == 11 {
                    value |= 1 << 1;
                } else if page >= 13 {
                    value |= 1 << 20;
                }
            }
            _ => {}
        }
        modify(io, address, u32::MAX, value)?;
    }
    Ok(())
}
