// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Exact Linux AX PCIe MAC-pre-init policy. No system-memory DMA publication.
use super::pcie_regs::*;
use super::{
    mac::ChipId,
    phy_access::Generation,
    power::{Error, Io},
};

/// Serialized config/PHY transactions. Native methods invoke current authority;
/// a failed primary config access may use Linux's explicit AX DBI fallback.
pub trait Interface: Io {
    async fn config_read8(&mut self, address: u16) -> Result<u8, Error>;
    async fn config_write8(&mut self, address: u16, value: u8) -> Result<(), Error>;
    async fn phy_read(&mut self, generation: Generation, address: u8) -> Result<u16, Error>;
    async fn phy_write(
        &mut self,
        generation: Generation,
        address: u8,
        value: u16,
    ) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Preparing,
    Ready,
}
#[derive(Debug)]
pub struct Pcie {
    state: State,
}
impl Default for Pcie {
    fn default() -> Self {
        Self { state: State::New }
    }
}
impl Pcie {
    pub fn state(&self) -> State {
        self.state
    }
    pub fn terminal() -> Self {
        Self {
            state: State::Preparing,
        }
    }
    /// # Safety
    /// Exclusively owned powered AX function, old DMA independently fenced,
    /// PCI BME verified off, and no concurrent reset/power/ring/IRQ operation.
    /// `ber` is the qualified platform's Linux PCI_BER quirk, never guessed.
    /// A failed/dropped preparation requires an independently verified reset.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        chip: ChipId,
        cut: u8,
        ber: bool,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        if chip == ChipId::Rtl8922A || cut > 15 || (ber && chip != ChipId::Rtl8852C) {
            return Err(Error::Unsupported);
        }
        self.state = State::Preparing;
        if ber {
            for (generation, value) in [
                (Generation::One, RAC_ANA1E_G1_VAL),
                (Generation::Two, RAC_ANA1E_G2_VAL),
            ] {
                io.phy_write(generation, RAC_ANA1E as u8, value as u16)
                    .await?;
                io.phy_write(generation, RAC_ANA2E as u8, RAC_ANA2E_VAL as u16)
                    .await?;
            }
        }
        let xb = matches!(chip, ChipId::Rtl8852B | ChipId::Rtl8851B);
        if chip == ChipId::Rtl8852A {
            set(io, R_AX_PCIE_INIT_CFG1, B_AX_DIS_RXDMA_PRE)?;
        }
        if chip == ChipId::Rtl8852A || xb {
            clear(io, R_AX_PCIE_PS_CTRL, B_AX_L1OFF_PWR_OFF_EN)?;
        }
        if matches!(chip, ChipId::Rtl8852A | ChipId::Rtl8852C) {
            for generation in [Generation::One, Generation::Two] {
                phy_modify(io, generation, RAC_ANA24 as u8, B_AX_DEGLITCH as u16, 0).await?;
            }
        }
        if chip == ChipId::Rtl8852A {
            for generation in [Generation::One, Generation::Two] {
                phy_modify(io, generation, RAC_ANA26 as u8, B_AX_RXEN as u16, 0).await?;
            }
        }
        if chip == ChipId::Rtl8852A || xb {
            clear(io, R_AX_SYS_PW_CTRL, B_AX_PSUS_OFF_CAPC_EN)?;
            set(io, R_AX_SYS_SDIO_CTRL, B_AX_PCIE_DIS_L2_CTRL_LDO_HCI)?;
            clear(io, R_AX_SYS_SDIO_CTRL, B_AX_PCIE_DIS_WLSUS_AFT_PDN)?;
        } else {
            clear(io, R_AX_SYS_SDIO_CTRL, B_AX_PCIE_DIS_L2_CTRL_LDO_HCI)?;
        }
        if xb {
            phy_modify(
                io,
                Generation::One,
                RAC_REG_REV2 as u8,
                BAC_CMU_EN_DLY_MASK as u16,
                PCIE_DPHY_DLY_25US as u16,
            )
            .await?;
            phy_modify(
                io,
                Generation::One,
                RAC_REG_FLD_0 as u8,
                BAC_AUTOK_N_MASK as u16,
                PCIE_AUTOK_4 as u16,
            )
            .await?;
            // Every retained Linux AX profile disables autok. Do not invent
            // target/divider calibration or a safe default for invalid rate.
            let rate =
                io.config_read8(RTW89_PCIE_PHY_RATE as u16).await? & RTW89_PCIE_PHY_RATE_MASK as u8;
            let generation = match rate {
                1 => Generation::One,
                2 => Generation::Two,
                _ => return Err(Error::Unsupported),
            };
            let l1 = io.config_read8(RTW89_PCIE_L1_CTRL as u16).await?;
            if l1 & RTW89_PCIE_BIT_L1 as u8 != 0 {
                io.config_write8(RTW89_PCIE_L1_CTRL as u16, l1 & !(RTW89_PCIE_BIT_L1 as u8))
                    .await?;
            }
            let calibration = async {
                let value = io.phy_read(generation, RAC_CTRL_PPR_V1 as u8).await?;
                if value & B_AX_CALIB_EN as u16 != 0 {
                    io.phy_write(
                        generation,
                        RAC_CTRL_PPR_V1 as u8,
                        value & !(B_AX_CALIB_EN as u16),
                    )
                    .await?;
                }
                Ok::<(), Error>(())
            }
            .await;
            // Linux restores the temporary L1 byte even after a PHY error.
            // Preserve the original failure; cancellation keeps this owner
            // terminal and requires a reset instead of replaying restoration.
            if l1 & RTW89_PCIE_BIT_L1 as u8 != 0 {
                let restoration = io.config_write8(RTW89_PCIE_L1_CTRL as u16, l1).await;
                calibration?;
                restoration?;
            } else {
                calibration?;
            }
        }
        set(io, R_AX_HCI_OPT_CTRL, BIT_WAKE_CTRL)?;
        if chip == ChipId::Rtl8852C {
            set(io, R_AX_PCIE_BG_CLR, B_AX_BG_CLR_ASYNC_M3)?;
            clear(io, R_AX_PCIE_BG_CLR, B_AX_BG_CLR_ASYNC_M3)?;
            if cut == 0 {
                set(io, R_AX_SYS_SDIO_CTRL, B_AX_PCIE_FORCE_PWR_NGAT)?;
                set(io, R_AX_PMC_DBG_CTRL2, B_AX_SYSON_DIS_PMCR_AX_WRMSK)?;
                set(io, R_AX_HCI_BG_CTRL, B_AX_BG_CLR_ASYNC_M3)?;
                clear(io, R_AX_PMC_DBG_CTRL2, B_AX_SYSON_DIS_PMCR_AX_WRMSK)?;
            }
            clear(io, R_AX_PCIE_PS_CTRL_V1, B_AX_SEL_REQ_ENTR_L1)?;
            set(io, R_AX_PCIE_PS_CTRL_V1, B_AX_DMAC0_EXIT_L1_EN)?;
            let timer = (72000 << B_AX_PCIE_WDT_TIMER_M1_MASK.trailing_zeros())
                & B_AX_PCIE_WDT_TIMER_M1_MASK;
            for address in [
                R_AX_PCIE_WDT_TIMER_M1,
                R_AX_PCIE_WDT_TIMER_M2,
                R_AX_PCIE_WDT_TIMER_E0,
            ] {
                io.write32(address, timer)?;
            }
            set(io, R_AX_PCIE_IO_RCY_M1, B_AX_PCIE_IO_RCY_WDT_MODE_M1)?;
            set(io, R_AX_PCIE_IO_RCY_M2, B_AX_PCIE_IO_RCY_WDT_MODE_M2)?;
            set(io, R_AX_PCIE_IO_RCY_E0, B_AX_PCIE_IO_RCY_WDT_MODE_E0)?;
            clear(io, R_AX_PCIE_IO_RCY_S1, B_AX_PCIE_IO_RCY_WDT_MODE_S1)?;
        } else {
            clear(io, R_AX_PCIE_EXP_CTRL, B_AX_SIC_EN_FORCE_CLKREQ)?;
            let old = read(io, R_AX_LBC_WATCHDOG)?;
            let value = (old & !B_AX_LBC_TIMER)
                | ((8 << B_AX_LBC_TIMER.trailing_zeros()) & B_AX_LBC_TIMER)
                | B_AX_LBC_FLAG
                | B_AX_LBC_EN;
            io.write32(R_AX_LBC_WATCHDOG, value)?;
            // Linux follows the initial write with write32_set(value).
            set(io, R_AX_LBC_WATCHDOG, value)?;
            set(
                io,
                R_AX_PCIE_DBG_CTRL,
                B_AX_ASFF_FULL_NO_STK | B_AX_EN_STUCK_DBG,
            )?;
            field(
                io,
                R_AX_PCIE_EXP_CTRL,
                B_AX_EN_STUCK_DBG | B_AX_ASFF_FULL_NO_STK,
                B_AX_EN_STUCK_DBG,
            )?;
            if chip == ChipId::Rtl8852A {
                set(io, R_AX_PCIE_EXP_CTRL, B_AX_EN_CHKDSC_NO_RX_STUCK)?;
            }
            set(
                io,
                R_AX_PCIE_INIT_CFG1,
                B_AX_PCIE_TXRST_KEEP_REG | B_AX_PCIE_RXRST_KEEP_REG,
            )?;
        }
        self.state = State::Ready;
        Ok(())
    }
}
async fn phy_modify(
    io: &mut impl Interface,
    generation: Generation,
    address: u8,
    mask: u16,
    value: u16,
) -> Result<(), Error> {
    let old = io.phy_read(generation, address).await?;
    if old == u16::MAX {
        return Err(Error::Gone);
    }
    io.phy_write(
        generation,
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
    .await
}
fn read(io: &mut impl Io, address: u32) -> Result<u32, Error> {
    let value = io.read32(address)?;
    if value == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(value)
    }
}
fn field(io: &mut impl Io, address: u32, mask: u32, value: u32) -> Result<(), Error> {
    let old = read(io, address)?;
    io.write32(
        address,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}
fn set(io: &mut impl Io, address: u32, mask: u32) -> Result<(), Error> {
    let old = read(io, address)?;
    io.write32(address, old | mask)
}
fn clear(io: &mut impl Io, address: u32, mask: u32) -> Result<(), Error> {
    let old = read(io, address)?;
    io.write32(address, old & !mask)
}
/// Linux mode_op at the stopped/zero-index point, before BDRAM reset.
/// The retained exact profiles all choose truncated BD, packet RX, 8 tags.
pub(super) fn mode(io: &mut impl Io, chip: ChipId, cut: u8) -> Result<(), Error> {
    if chip == ChipId::Rtl8922A {
        return Err(Error::Unsupported);
    }
    let c = chip == ChipId::Rtl8852C;
    if chip == ChipId::Rtl8852A && cut == 1 {
        set(io, R_AX_PCIE_INIT_CFG1, B_AX_TX_TRUNC_MODE)?;
        set(io, R_AX_PCIE_INIT_CFG1, B_AX_RX_TRUNC_MODE)?;
    }
    clear(
        io,
        if c {
            R_AX_HAXI_INIT_CFG1
        } else {
            R_AX_PCIE_INIT_CFG1
        },
        if c { B_AX_RXBD_MODE_V1 } else { B_AX_RXBD_MODE },
    )?;
    if c {
        field(io, R_AX_HAXI_INIT_CFG1, B_AX_HAXI_MAX_TXDMA_MASK, 2)?;
        field(io, R_AX_HAXI_INIT_CFG1, B_AX_HAXI_MAX_RXDMA_MASK, 1)?;
        field(io, R_AX_HAXI_EXP_CTRL, B_AX_MAX_TAG_NUM_V1_MASK, 7)?;
        field(io, R_AX_HAXI_INIT_CFG1, B_AX_WD_ITVL_IDLE_V1_MASK, 1)?;
        field(io, R_AX_HAXI_INIT_CFG1, B_AX_WD_ITVL_ACT_V1_MASK, 1)?;
    } else {
        field(io, R_AX_PCIE_INIT_CFG1, B_AX_PCIE_MAX_TXDMA_MASK, 7)?;
        field(io, R_AX_PCIE_INIT_CFG1, B_AX_PCIE_MAX_RXDMA_MASK, 3)?;
        set(io, R_AX_PCIE_INIT_CFG1, B_AX_LATENCY_CONTROL)?;
        field(io, R_AX_PCIE_EXP_CTRL, B_AX_MAX_TAG_NUM, 7)?;
        field(io, R_AX_PCIE_INIT_CFG2, B_AX_WD_ITVL_IDLE, 1)?;
        field(io, R_AX_PCIE_INIT_CFG2, B_AX_WD_ITVL_ACT, 1)?;
    }
    set(
        io,
        R_AX_TX_ADDRESS_INFO_MODE_SETTING,
        B_AX_HOST_ADDR_INFO_8B_SEL,
    )?;
    clear(io, R_AX_PKTIN_SETTING, B_AX_WD_ADDR_INFO_LENGTH)?;
    verify_mode(io, chip, cut)
}
fn verify_mode(io: &mut impl Io, chip: ChipId, cut: u8) -> Result<(), Error> {
    let c = chip == ChipId::Rtl8852C;
    let init = if c {
        R_AX_HAXI_INIT_CFG1
    } else {
        R_AX_PCIE_INIT_CFG1
    };
    let fields = if c {
        [
            (init, B_AX_RXBD_MODE_V1, 0),
            (init, B_AX_HAXI_MAX_TXDMA_MASK, 2),
            (init, B_AX_HAXI_MAX_RXDMA_MASK, 1),
            (R_AX_HAXI_EXP_CTRL, B_AX_MAX_TAG_NUM_V1_MASK, 7),
            (init, B_AX_WD_ITVL_IDLE_V1_MASK, 1),
            (init, B_AX_WD_ITVL_ACT_V1_MASK, 1),
        ]
    } else {
        [
            (init, B_AX_RXBD_MODE, 0),
            (init, B_AX_PCIE_MAX_TXDMA_MASK, 7),
            (init, B_AX_PCIE_MAX_RXDMA_MASK, 3),
            (R_AX_PCIE_EXP_CTRL, B_AX_MAX_TAG_NUM, 7),
            (R_AX_PCIE_INIT_CFG2, B_AX_WD_ITVL_IDLE, 1),
            (R_AX_PCIE_INIT_CFG2, B_AX_WD_ITVL_ACT, 1),
        ]
    };
    for (address, mask, value) in fields {
        if (read(io, address)? & mask) >> mask.trailing_zeros() != value {
            return Err(Error::Access);
        }
    }
    for (address, mask, value) in [
        (
            R_AX_TX_ADDRESS_INFO_MODE_SETTING,
            B_AX_HOST_ADDR_INFO_8B_SEL,
            B_AX_HOST_ADDR_INFO_8B_SEL,
        ),
        (R_AX_PKTIN_SETTING, B_AX_WD_ADDR_INFO_LENGTH, 0),
    ] {
        if read(io, address)? & mask != value {
            return Err(Error::Access);
        }
    }
    let trunc = B_AX_TX_TRUNC_MODE | B_AX_RX_TRUNC_MODE;
    if !c && read(io, init)? & B_AX_LATENCY_CONTROL == 0
        || chip == ChipId::Rtl8852A && cut == 1 && read(io, init)? & trunc != trunc
    {
        return Err(Error::Access);
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "pcie/tests.rs"]
mod tests;
