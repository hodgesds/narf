// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One-shot PCI AX cold-power sequences; no DMA or station admission.
//! Linux rtw8852a.c tables, rtw8852{b,c}.c and rtw8851b.c pwr_on_func,
//! mac.c reset_pwr_state_ax and write_xtal_si_ax.
use super::{mac::ChipId, power_regs::*, power_tables::A_ON};
use core::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Access,
    Gone,
    Timeout,
    AlreadyOn,
    Unsupported,
    Terminal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Cold,
    Starting,
    Powered,
    Stopping,
    Off,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Calibration {
    pub rfe_type: u8,
    pub valid: bool,
    pub power_k_valid: bool,
}

pub trait Io {
    fn read8(&mut self, address: u32) -> Result<u8, Error>;
    fn read16(&mut self, address: u32) -> Result<u16, Error>;
    fn read32(&mut self, address: u32) -> Result<u32, Error>;
    fn write8(&mut self, address: u32, value: u8) -> Result<(), Error>;
    fn write16(&mut self, address: u32, value: u16) -> Result<(), Error>;
    fn write32(&mut self, address: u32, value: u32) -> Result<(), Error>;
    fn now_us(&self) -> u64;
    fn delay_us(&mut self, us: u64) -> impl Future<Output = ()>;
    fn read_ecv(&mut self) -> impl Future<Output = Result<Option<u8>, Error>>;
}
#[derive(Clone, Copy, Debug)]
pub struct Step {
    pub address: u16,
    pub cut: u8,
    pub interface: u8,
    pub base: u8,
    pub command: u8,
    pub mask: u8,
    pub value: u8,
}
#[derive(Debug)]
pub struct Power<I> {
    io: I,
    phase: Phase,
    profile: Option<(ChipId, u8, Calibration)>,
}
impl<I: Io> Power<I> {
    pub fn new(io: I) -> Self {
        Self {
            io,
            phase: Phase::Cold,
            profile: None,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn io(&mut self) -> &mut I {
        &mut self.io
    }
    fn modify8(&mut self, address: u32, mask: u8, value: u8) -> Result<(), Error> {
        let old = self.io.read8(address)?;
        self.io.write8(address, (old & !mask) | (value & mask))
    }
    fn modify16(&mut self, address: u32, mask: u16, value: u16) -> Result<(), Error> {
        let old = self.io.read16(address)?;
        self.io.write16(address, (old & !mask) | (value & mask))
    }
    fn modify32(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.io.read32(address)?;
        self.io.write32(address, (old & !mask) | (value & mask))
    }
    fn set(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        self.modify32(address, mask, mask)
    }
    fn clear(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        self.modify32(address, mask, 0)
    }
    fn field(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.modify32(address, mask, value << mask.trailing_zeros())
    }
    async fn poll32(
        &mut self,
        address: u32,
        mask: u32,
        value: u32,
        interval: u64,
        budget: u64,
    ) -> Result<(), Error> {
        let start = self.io.now_us();
        loop {
            let current = self.io.read32(address)?;
            if current == u32::MAX {
                return Err(Error::Gone);
            }
            if current & mask == value {
                return Ok(());
            }
            if self.io.now_us().saturating_sub(start) >= budget {
                return Err(Error::Timeout);
            }
            self.io.delay_us(interval).await;
        }
    }
    async fn xtal(&mut self, address: u32, value: u32, mask: u32) -> Result<(), Error> {
        // AX normal write mode is zero, one command for the selected bitmask.
        let command = (1 << 31) | ((mask & 255) << 16) | ((value & 255) << 8) | address;
        self.io.write32(R_AX_WLAN_XTAL_SI_CTRL, command)?;
        self.poll32(R_AX_WLAN_XTAL_SI_CTRL, 1 << 31, 0, 50, 50_000)
            .await
    }
    async fn table_steps(&mut self, cut: u8, steps: &[Step]) -> Result<(), Error> {
        if cut >= 8 {
            return Err(Error::Unsupported);
        }
        for step in steps {
            if step.command == 3 {
                break;
            }
            if step.interface & 4 == 0 || step.cut & (1 << cut) == 0 {
                continue;
            }
            if step.base != 0 {
                return Err(Error::Unsupported);
            }
            let address = u32::from(step.address);
            match step.command {
                0 => self.modify8(address, step.mask, step.value)?,
                1 => {
                    let start = self.io.now_us();
                    loop {
                        if self.io.read8(address)? & step.mask == step.value & step.mask {
                            break;
                        }
                        if self.io.now_us().saturating_sub(start) >= 2_000_000 {
                            return Err(Error::Timeout);
                        }
                        self.io.delay_us(1000).await;
                    }
                }
                2 => {
                    self.io
                        .delay_us(u64::from(step.address) * if step.value == 0 { 1 } else { 1000 })
                        .await
                }
                _ => return Err(Error::Unsupported),
            }
        }
        Ok(())
    }
    /// Failed or dropped attempts stay Starting and cannot be replayed. A
    /// separate verified power-off/reset owner is required before another try.
    /// The returned cut includes RTL8851B's real EFUSE ECV correction.
    pub async fn power_on(
        &mut self,
        chip: ChipId,
        mut cut: u8,
        calibration: Calibration,
    ) -> Result<u8, Error> {
        if !matches!(self.phase, Phase::Cold | Phase::Off) {
            return Err(Error::Terminal);
        }
        if self
            .profile
            .is_some_and(|profile| profile != (chip, cut, calibration))
        {
            return Err(Error::Unsupported);
        }
        if chip == ChipId::Rtl8922A || cut > 15 {
            return Err(Error::Unsupported);
        }
        self.phase = Phase::Starting;
        self.profile = Some((chip, cut, calibration));
        if self.io.read16(R_AX_SYS_FUNC_EN)? == u16::MAX {
            return Err(Error::Gone);
        }
        let state = self.io.read32(R_AX_IC_PWR_STATE)?;
        if state == u32::MAX {
            return Err(Error::Gone);
        }
        if (state & B_AX_WLMAC_PWR_STE_MASK) >> B_AX_WLMAC_PWR_STE_MASK.trailing_zeros()
            == MAC_AX_MAC_ON
        {
            return Err(Error::AlreadyOn);
        }
        if chip == ChipId::Rtl8852A {
            self.table_steps(cut, A_ON).await?;
        } else {
            self.callback(chip, &mut cut, calibration).await?;
        }
        self.io
            .write8(R_AX_SCOREBOARD + 3, MAC_AX_NOTIFY_TP_MAJOR as u8)?;
        self.profile = Some((chip, cut, calibration));
        self.phase = Phase::Powered;
        Ok(cut)
    }
    async fn callback(
        &mut self,
        chip: ChipId,
        cut: &mut u8,
        cal: Calibration,
    ) -> Result<(), Error> {
        if chip == ChipId::Rtl8852B && cal.rfe_type == 5 {
            self.io
                .write16(R_AX_SPS_ANA_ON_CTRL2, RTL8852B_RFE_05_SPS_ANA as u16)?;
        }
        if chip == ChipId::Rtl8852C {
            let selector = self.io.read32(R_AX_SYS_STATUS1)?;
            if (selector & B_AX_PAD_HCI_SEL_V2_MASK) >> B_AX_PAD_HCI_SEL_V2_MASK.trailing_zeros()
                == MAC_AX_HCI_SEL_PCIE_USB
            {
                self.set(R_AX_LDO_AON_CTRL0, B_AX_PD_REGU_L)?;
            }
        }
        self.clear(R_AX_SYS_PW_CTRL, B_AX_AFSM_WLSUS_EN | B_AX_AFSM_PCIE_SUS_EN)?;
        self.set(R_AX_SYS_PW_CTRL, B_AX_DIS_WLBT_PDNSUSEN_SOPC)?;
        self.set(R_AX_WLLPS_CTRL, B_AX_DIS_WLBT_LPSEN_LOPC)?;
        self.clear(R_AX_SYS_PW_CTRL, B_AX_APDM_HPDN)?;
        self.clear(R_AX_SYS_PW_CTRL, B_AX_APFM_SWLPS)?;
        if chip == ChipId::Rtl8852C {
            self.field(R_AX_SPS_DIG_ON_CTRL0, B_AX_OCP_L1_MASK, 7)?;
        }
        self.poll32(
            R_AX_SYS_PW_CTRL,
            B_AX_RDY_SYSPWR,
            B_AX_RDY_SYSPWR,
            1000,
            20_000,
        )
        .await?;
        if chip == ChipId::Rtl8852B {
            self.set(R_AX_AFE_LDO_CTRL, B_AX_AON_OFF_PC_EN)?;
            self.poll32(
                R_AX_AFE_LDO_CTRL,
                B_AX_AON_OFF_PC_EN,
                B_AX_AON_OFF_PC_EN,
                1000,
                20_000,
            )
            .await?;
            self.field(R_AX_SPS_DIG_OFF_CTRL0, B_AX_C1_L1_MASK, 1)?;
            if cal.rfe_type == 5 {
                self.field(R_AX_SPS_DIG_OFF_CTRL0, B_AX_C2_L1_MASK, 1)?;
                self.field(R_AX_SPS_DIG_OFF_CTRL0, B_AX_C3_L1_MASK, 2)?;
                self.field(R_AX_SPS_DIG_OFF_CTRL0, B_AX_R1_L1_MASK, 1)?;
            } else {
                self.field(R_AX_SPS_DIG_OFF_CTRL0, B_AX_C3_L1_MASK, 3)?;
            }
        }
        self.set(R_AX_SYS_PW_CTRL, B_AX_EN_WLON)?;
        self.set(R_AX_SYS_PW_CTRL, B_AX_APFN_ONMAC)?;
        self.poll32(R_AX_SYS_PW_CTRL, B_AX_APFN_ONMAC, 0, 1000, 20_000)
            .await?;
        for value in [true, false, true, false, true] {
            self.modify8(
                R_AX_PLATFORM_ENABLE,
                B_AX_PLATFORM_EN as u8,
                if value { B_AX_PLATFORM_EN as u8 } else { 0 },
            )?;
        }
        self.clear(R_AX_SYS_SDIO_CTRL, B_AX_PCIE_CALIB_EN_V1)?;
        if chip == ChipId::Rtl8852C {
            self.clear(R_AX_SYS_ISO_CTRL_EXTEND, B_AX_CMAC1_FEN)?;
            self.set(R_AX_SYS_ISO_CTRL_EXTEND, B_AX_R_SYM_ISO_CMAC12PP)?;
            self.clear(
                R_AX_AFE_CTRL1,
                B_AX_R_SYM_WLCMAC1_P4_PC_EN
                    | B_AX_R_SYM_WLCMAC1_P3_PC_EN
                    | B_AX_R_SYM_WLCMAC1_P2_PC_EN
                    | B_AX_R_SYM_WLCMAC1_P1_PC_EN
                    | B_AX_R_SYM_WLCMAC1_PC_EN,
            )?;
        }
        if chip != ChipId::Rtl8851B {
            self.set(R_AX_SYS_ADIE_PAD_PWR_CTRL, B_AX_SYM_PADPDN_WL_PTA_1P3)?;
            self.xtal(XTAL_SI_ANAPAR_WL, XTAL_SI_GND_SHDN_WL, XTAL_SI_GND_SHDN_WL)
                .await?;
            self.set(R_AX_SYS_ADIE_PAD_PWR_CTRL, B_AX_SYM_PADPDN_WL_RFC_1P3)?;
            self.xtal(XTAL_SI_ANAPAR_WL, XTAL_SI_SHDN_WL, XTAL_SI_SHDN_WL)
                .await?;
        }
        for (value, mask) in [
            (XTAL_SI_OFF_WEI, XTAL_SI_OFF_WEI),
            (XTAL_SI_OFF_EI, XTAL_SI_OFF_EI),
            (0, XTAL_SI_RFC2RF),
            (XTAL_SI_PON_WEI, XTAL_SI_PON_WEI),
            (XTAL_SI_PON_EI, XTAL_SI_PON_EI),
            (0, XTAL_SI_SRAM2RFC),
        ] {
            self.xtal(XTAL_SI_ANAPAR_WL, value, mask).await?;
        }
        if chip != ChipId::Rtl8852C {
            self.xtal(XTAL_SI_SRAM_CTRL, 0, XTAL_SI_SRAM_DIS).await?;
        }
        self.xtal(
            XTAL_SI_XTAL_XMD_2,
            if chip == ChipId::Rtl8852C { 0x10 } else { 0 },
            XTAL_SI_LDO_LPS,
        )
        .await?;
        self.xtal(XTAL_SI_XTAL_XMD_4, 0, XTAL_SI_LPS_CAP).await?;
        if chip == ChipId::Rtl8851B {
            self.xtal(XTAL_SI_XTAL_DRV, 0, XTAL_SI_DRV_LATCH).await?;
        }
        self.set(R_AX_PMC_DBG_CTRL2, B_AX_SYSON_DIS_PMCR_AX_WRMSK)?;
        self.set(R_AX_SYS_ISO_CTRL, B_AX_ISO_EB2CORE)?;
        self.clear(R_AX_SYS_ISO_CTRL, B_AX_PWC_EV2EF_B15)?;
        self.io.delay_us(1000).await;
        self.clear(R_AX_SYS_ISO_CTRL, B_AX_PWC_EV2EF_B14)?;
        self.clear(R_AX_PMC_DBG_CTRL2, B_AX_SYSON_DIS_PMCR_AX_WRMSK)?;
        if chip == ChipId::Rtl8852B && cal.valid && !cal.power_k_valid {
            self.field(R_AX_SPS_DIG_ON_CTRL0, B_AX_VOL_L1_MASK, 9)?;
            self.field(R_AX_SPS_DIG_ON_CTRL0, B_AX_VREFPFM_L_MASK, 10)?;
            if *cut == 1 {
                self.set(R_AX_PMC_DBG_CTRL2, B_AX_SYSON_DIS_PMCR_AX_WRMSK)?;
                self.modify16(
                    R_AX_HCI_LDO_CTRL,
                    B_AX_R_AX_VADJ_MASK as u16,
                    (10 << B_AX_R_AX_VADJ_MASK.trailing_zeros()) as u16,
                )?;
                self.clear(R_AX_PMC_DBG_CTRL2, B_AX_SYSON_DIS_PMCR_AX_WRMSK)?;
            }
        }
        if chip == ChipId::Rtl8852C {
            self.set(
                R_AX_GPIO0_15_EECS_EESK_LED1_PULL_LOW_EN,
                B_AX_EECS_PULL_LOW_EN | B_AX_EESK_PULL_LOW_EN | B_AX_LED1_PULL_LOW_EN,
            )?;
        }
        if chip == ChipId::Rtl8851B {
            self.set(
                R_AX_GPIO0_16_EECS_EESK_LED1_PULL_LOW_EN,
                B_AX_GPIO10_PULL_LOW_EN | B_AX_GPIO16_PULL_LOW_EN_V1,
            )?;
            if *cut == 0 {
                if let Some(ecv) = self.io.read_ecv().await? {
                    *cut = ecv;
                }
            }
            self.clear(R_AX_WLAN_XTAL_SI_CONFIG, B_AX_XTAL_SI_ADDR_NOT_CHK)?;
            if *cut != 0 {
                self.set(R_AX_SPSLDO_ON_CTRL1, B_AX_FPWMDELAY)?;
                self.set(R_AX_SPSANA_ON_CTRL1, B_AX_FPWMDELAY)?;
            }
        }
        let common_dmac = B_AX_MAC_FUNC_EN
            | B_AX_DMAC_FUNC_EN
            | B_AX_MPDU_PROC_EN
            | B_AX_WD_RLS_EN
            | B_AX_DLE_WDE_EN
            | B_AX_TXPKT_CTRL_EN
            | B_AX_STA_SCH_EN
            | B_AX_DLE_PLE_EN
            | B_AX_PKT_BUF_EN
            | B_AX_DMAC_TBL_EN
            | B_AX_PKT_IN_EN
            | B_AX_DLE_CPUIO_EN
            | B_AX_DISPATCHER_EN
            | B_AX_BBRPT_EN
            | B_AX_MAC_SEC_EN;
        self.set(
            R_AX_DMAC_FUNC_EN,
            common_dmac
                | if chip == ChipId::Rtl8852C {
                    B_AX_MAC_UN_EN | B_AX_H_AXIDMA_EN
                } else {
                    B_AX_DMACREG_GCKEN
                },
        )?;
        self.set(
            R_AX_CMAC_FUNC_EN,
            B_AX_CMAC_EN
                | B_AX_CMAC_TXEN
                | B_AX_CMAC_RXEN
                | B_AX_FORCE_CMACREG_GCKEN
                | B_AX_PHYINTF_EN
                | B_AX_CMAC_DMA_EN
                | B_AX_PTCLTOP_EN
                | B_AX_SCHEDULER_EN
                | B_AX_TMAC_EN
                | B_AX_RMAC_EN,
        )?;
        if chip == ChipId::Rtl8852C {
            self.field(
                R_AX_LED1_FUNC_SEL,
                B_AX_PINMUX_EESK_FUNC_SEL_V1_MASK,
                PINMUX_EESK_FUNC_SEL_BT_LOG,
            )?;
        } else {
            self.field(
                R_AX_EECS_EESK_FUNC_SEL,
                B_AX_PINMUX_EESK_FUNC_SEL_MASK,
                PINMUX_EESK_FUNC_SEL_BT_LOG,
            )?;
        }
        Ok(())
    }
}

#[path = "power_off.rs"]
mod off;
