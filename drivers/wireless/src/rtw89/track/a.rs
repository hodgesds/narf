// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Actual retained A DIG/NHM state. Early-cut gains come from BB reads.
use super::*;
use crate::rtw89::{dig_a::Gains, factory::Identity, mac::ChipId, nhm, phy_operating, rfk};
pub(in crate::rtw89) const RECIPE:&[u8]=b"RTL8852A retained DM initialization v1; exact source CCX/IFS init then NHM enable/pwdb before PHYSTS/DIG, early-cut retained IB/gain arrays/reset, direct A XTAL; original per-radio DM history retained across retunes; source projection helper width20/40/80 cut-dependent IGI/CCKPD A nonV1 PAGC/DIG481c EDCCA4840 DCFO448c shift10; native periodic adapter, NHM scan trigger/result and measured RF-tracking window remain closed; fresh full A source scope before every initial effect";
pub(super) const LAYOUT: Layout = Layout {
    pd: R_SEG0R_PD,
    pd_spatial_reuse: B_SEG0R_PD_SPATIAL_REUSE_EN_MSK,
    pagcugc: [BB + 0x46a0, BB + 0x46a4, BB + 0x4774, BB + 0x4778],
    edcca: R_SEG0R_EDCCA_LVL,
    dcfo_comp: R_DCFO_COMP_S0,
    dcfo_comp_mask: B_DCFO_COMP_S0_MSK,
    dcfo_comp_sft: 10,
};
pub(super) const REGISTERS: &[u32] = &[
    R_CCX,
    R_IFS_COUNTER,
    R_IFS_T[0],
    R_IFS_T[1],
    R_IFS_T[2],
    R_IFS_T[3],
    R_IFS_CLM_FA,
    R_IFSCNT,
    R_SEG0R_PD,
    R_BMODE_PDTH_EN_V1,
    R_BMODE_PDTH_V1,
    BB + 0x46a0,
    BB + 0x46a4,
    BB + 0x4774,
    BB + 0x4778,
    R_SEG0R_EDCCA_LVL,
    R_AX_PPDU_STAT,
    R_AX_HW_RPT_FWD,
    R_DCFO,
    R_DCFO_COMP_S0,
    BB + 0x4668,
    BB + 0x473c,
    BB + 0x4674,
    BB + 0x4748,
    BB + 0x4658,
    BB + 0x472c,
    BB + 0x0c08,
    BB + 0x0c0c,
    BB + 0x0c10,
    BB + 0x0c14,
    BB + 0x1aa4,
    BB + 0x1a88,
    BB + 0x1a8c,
    BB + 0x1a90,
    BB + 0x1a94,
    BB + 0x1a98,
    BB + 0x1a9c,
];
struct Initial<'a, I> {
    io: &'a mut I,
    profile: Profile,
}
impl<I: phy_operating::Interface> Hw for Initial<'_, I> {
    fn read(&mut self, a: u32) -> Result<u32, power::Error> {
        self.io.admit().map_err(crate::rtw89::radio_c::error)?;
        self.io.read32(a)
    }
    fn write(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.io.admit().map_err(crate::rtw89::radio_c::error)?;
        self.io.write32(a, v)
    }
    fn profile(&mut self) -> Result<Profile, power::Error> {
        Ok(self.profile)
    }
    fn layout(&mut self) -> Result<(Layout, bool), power::Error> {
        Ok((LAYOUT, false))
    }
    async fn crystal(&mut self, _: u8) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
}
pub(super) struct NhmRegs<'a, H>(pub &'a mut H);
impl<H: Hw> crate::rtw89::irq::Regs for NhmRegs<'_, H> {
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        let value = self.0.read(BB + a)?;
        if value == u32::MAX {
            Err(power::Error::Gone)
        } else {
            Ok(value)
        }
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.0.write(BB + a, v)
    }
}
fn nhm_error(error: nhm::Error) -> power::Error {
    match error {
        nhm::Error::Io(e) => e,
        _ => power::Error::Access,
    }
}
impl Tracker {
    /// Source DM-init environment, before PHYSTS/DIG. Retained before any
    /// operation by its original Operating owner; no packet proof is produced.
    pub(in crate::rtw89) fn prepare_a(
        &mut self,
        io: &mut impl phy_operating::Interface,
        id: Identity,
    ) -> Result<(), rfk::Error> {
        if id.chip() != ChipId::Rtl8852A || self.a_cut.is_some() {
            return Err(rfk::Error::Terminal);
        }
        io.admit()?;
        self.a_cut = Some(id.cut());
        let cap = id.xtal() & 0x7f;
        let profile = Profile {
            cck_pd: id.cut() > 1,
            crystal_cap: cap,
            crystal_lower: cap.saturating_sub(64).max(1),
            crystal_upper: cap.saturating_add(64).min(127),
        };
        let mut hw = Initial { io, profile };
        self.env.init(&mut hw)?;
        let state = self.a_nhm.get_or_insert(nhm::NhmState::new());
        nhm::setting_init(&mut NhmRegs(&mut hw), state).map_err(nhm_error)?;
        self.cfo.init(profile);
        Ok(())
    }
    pub(in crate::rtw89) fn a_gains(&mut self, gains: Option<Gains>) -> Result<(), rfk::Error> {
        let cut = self.a_cut.ok_or(rfk::Error::Terminal)?;
        if (cut <= 1) != gains.is_some() {
            return Err(rfk::Error::Table);
        }
        self.a_gain = gains;
        Ok(())
    }
}
pub(super) fn program_gain(
    hw: &mut impl Hw,
    cut: u8,
    gains: Option<Gains>,
    rssi: u8,
    ghz5: bool,
) -> Result<(), power::Error> {
    if cut > 1 {
        return Ok(());
    }
    let g = gains.ok_or(power::Error::Terminal)?;
    let (lna, tia, rxb) = if ghz5 {
        (6, 1, 31)
    } else {
        let lna = if rssi < 68 {
            6
        } else if rssi < 84 {
            5
        } else if rssi < 90 {
            4
        } else if rssi < 98 {
            3
        } else if rssi < 104 {
            2
        } else {
            1
        };
        let tia = usize::from(rssi < 68);
        let wb = i32::from(rssi) + i32::from(g.lna_g[lna]) + i32::from(g.tia_g[tia]);
        let rxb = (120 + i32::from(g.ib_pkpwr) - i32::from(g.ib_pbk) - wb).clamp(0, 31) as usize;
        (lna, tia, rxb)
    };
    for &(a, m, _) in crate::rtw89::dig_a::MAX_GAIN_WRITES {
        let value = if m == 0x0700_0000 {
            lna
        } else if m == 0x0002_0000 {
            tia
        } else {
            rxb
        };
        set(hw, BB + a, m, value as u32)?;
    }
    Ok(())
}
