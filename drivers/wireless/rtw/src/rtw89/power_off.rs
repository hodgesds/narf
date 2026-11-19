// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AX parked-device power-off callbacks and inherited-state normalization.
use super::*;

impl<I: Io> Power<I> {
    /// # Safety
    /// All device producers and IRQ handlers are serialized, hardware DMA has
    /// been independently stopped/fenced and PCI bus mastering is verified off.
    /// This callback is not itself a DMA quiescence or resource reclamation proof.
    pub async unsafe fn power_off(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Powered {
            return Err(Error::Terminal);
        }
        let (chip, cut, cal) = self.profile.ok_or(Error::Terminal)?;
        self.phase = Phase::Stopping;
        self.off_sequence(chip, cut, cal).await?;
        self.phase = Phase::Off;
        Ok(())
    }
    /// Normalize an inherited ON MAC before the first cold-power operation.
    /// Access failure/cancellation leaves the owner Stopping and refuses replay.
    /// # Safety
    /// Same serialized, stopped/fenced DMA and verified PCI parking contract as
    /// power_off; no active firmware/control/EFUSE operation may coexist.
    pub async unsafe fn normalize_inherited(
        &mut self,
        chip: ChipId,
        cut: u8,
        cal: Calibration,
    ) -> Result<u8, Error> {
        if self.phase != Phase::Cold {
            return Err(Error::Terminal);
        }
        if chip == ChipId::Rtl8922A || cut > 15 {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Stopping;
        self.profile = Some((chip, cut, cal));
        let state = self.io.read32(R_AX_IC_PWR_STATE)?;
        if state == u32::MAX {
            return Err(Error::Gone);
        }
        if (state & B_AX_WLMAC_PWR_STE_MASK) >> B_AX_WLMAC_PWR_STE_MASK.trailing_zeros()
            == MAC_AX_MAC_ON
        {
            self.off_sequence(chip, cut, cal).await?;
        } else if state & B_AX_WLMAC_PWR_STE_MASK != 0 {
            return Err(Error::AlreadyOn);
        }
        self.phase = Phase::Off;
        self.power_on(chip, cut, cal).await
    }
    async fn off_sequence(&mut self, chip: ChipId, cut: u8, cal: Calibration) -> Result<(), Error> {
        if chip == ChipId::Rtl8852A {
            self.table_steps(cut, super::super::power_tables::A_OFF)
                .await?;
        } else {
            if chip == ChipId::Rtl8852B && cal.rfe_type == 5 {
                self.io
                    .write16(R_AX_SPS_ANA_ON_CTRL2, RTL8852B_RFE_05_SPS_ANA as u16)?;
            }
            for (address, value, mask) in [
                (XTAL_SI_ANAPAR_WL, XTAL_SI_RFC2RF, XTAL_SI_RFC2RF),
                (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_OFF_EI),
                (XTAL_SI_ANAPAR_WL, 0, XTAL_SI_OFF_WEI),
                (XTAL_SI_WL_RFC_S0, 0, XTAL_SI_RF00),
            ] {
                self.xtal(address, value, mask).await?;
            }
            if chip != ChipId::Rtl8851B {
                self.xtal(XTAL_SI_WL_RFC_S1, 0, XTAL_SI_RF10).await?;
            }
            for (value, mask) in [
                (XTAL_SI_SRAM2RFC, XTAL_SI_SRAM2RFC),
                (0, XTAL_SI_PON_EI),
                (0, XTAL_SI_PON_WEI),
            ] {
                self.xtal(XTAL_SI_ANAPAR_WL, value, mask).await?;
            }
            if chip == ChipId::Rtl8851B {
                self.set(R_AX_WLAN_XTAL_SI_CONFIG, B_AX_XTAL_SI_ADDR_NOT_CHK)?;
            }
            self.set(R_AX_SYS_PW_CTRL, B_AX_EN_WLON)?;
            self.clear(R_AX_WLRF_CTRL, B_AX_AFC_AFEDIG)?;
            self.modify8(
                R_AX_SYS_FUNC_EN,
                (B_AX_FEN_BB_GLB_RSTN | B_AX_FEN_BBRSTB) as u8,
                0,
            )?;
            if chip == ChipId::Rtl8852C {
                self.clear(
                    R_AX_SYS_ISO_CTRL_EXTEND,
                    B_AX_R_SYM_FEN_WLBBGLB_1 | B_AX_R_SYM_FEN_WLBBFUN_1,
                )?;
            }
            if chip != ChipId::Rtl8851B {
                self.clear(R_AX_SYS_ADIE_PAD_PWR_CTRL, B_AX_SYM_PADPDN_WL_RFC_1P3)?;
                self.xtal(XTAL_SI_ANAPAR_WL, 0, XTAL_SI_SHDN_WL).await?;
                self.clear(R_AX_SYS_ADIE_PAD_PWR_CTRL, B_AX_SYM_PADPDN_WL_PTA_1P3)?;
                self.xtal(XTAL_SI_ANAPAR_WL, 0, XTAL_SI_GND_SHDN_WL).await?;
            }
            self.set(R_AX_SYS_PW_CTRL, B_AX_APFM_OFFMAC)?;
            self.poll32(R_AX_SYS_PW_CTRL, B_AX_APFM_OFFMAC, 0, 1000, 20_000)
                .await?;
            self.io.write32(R_AX_WLLPS_CTRL, SW_LPS_OPTION)?;
            if chip == ChipId::Rtl8852C {
                self.clear(R_AX_SYS_PW_CTRL, B_AX_XTAL_OFF_A_DIE)?;
            }
            if chip == ChipId::Rtl8851B {
                if cut == 0 {
                    self.set(R_AX_SYS_PW_CTRL, B_AX_SOP_PWMM_DSWR)?;
                    self.set(R_AX_SYS_PW_CTRL, B_AX_SOP_ASWRM)?;
                    self.set(R_AX_WLLPS_CTRL, B_AX_LPSOP_DSWRM)?;
                    self.set(R_AX_WLLPS_CTRL, B_AX_LPSOP_ASWRM)?;
                } else {
                    self.set(R_AX_SPSLDO_ON_CTRL1, B_AX_FPWMDELAY)?;
                    self.set(R_AX_SPSANA_ON_CTRL1, B_AX_FPWMDELAY)?;
                }
            } else {
                self.set(R_AX_SYS_SWR_CTRL1, B_AX_SYM_CTRL_SPS_PWMFREQ)?;
                self.field(R_AX_SPS_DIG_ON_CTRL0, B_AX_REG_ZCDC_H_MASK, 3)?;
            }
            self.set(R_AX_SYS_PW_CTRL, B_AX_APFM_SWLPS)?;
        }
        self.io
            .write8(R_AX_SCOREBOARD + 3, MAC_AX_NOTIFY_PWR_MAJOR as u8)?;
        self.poll32(R_AX_IC_PWR_STATE, B_AX_WLMAC_PWR_STE_MASK, 0, 1000, 20_000)
            .await
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "power_off_tests.rs"]
mod tests;
