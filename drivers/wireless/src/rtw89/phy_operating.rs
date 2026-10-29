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
        if identity.chip() != ChipId::Rtl8852B
            || identity.cut() > 15
            || !identity.calibration().valid
            || identity.calibration().rfe_type == 255
        {
            return Err(Error::Table);
        }
        let mut a = Access(io);
        a.bb(R_PLCP_HISTOGRAM, B_STS_DIS_TRIG_BY_FAIL, 1)?;
        a.bb(R_PLCP_HISTOGRAM, B_STS_DIS_TRIG_BY_BRK, 1)?;
        for page in 0..16 {
            if page == 9 {
                continue;
            }
            let address =
                R_PHY_STS_BITMAP_ADDR_START + (if page > 9 { page - 1 } else { page }) * 4;
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
        // B support_igi=false in core_setup_phycap; there are no B gain-table
        // reads/forced IGI writes. Initial disabled DIG PD is still real HW.
        a.bb(R_SEG0R_PD_V1, B_SEG0R_PD_LOWER_BOUND_MSK, 0)?;
        a.bb(R_SEG0R_PD_V1, B_SEG0R_PD_SPATIAL_REUSE_EN_MSK_V1, 0)?;
        let cck_pd = identity.cut() > 0;
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
#[cfg(any(test, feature = "kernel-test"))]
#[path = "phy_operating/tests.rs"]
mod tests;
