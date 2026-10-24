// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained AX PCI basic_cfg, including C PHY calibration and host PM policy.
//! No ring, DMA, interrupt, firmware or radio publication occurs here.
use super::pci_basic_regs::*;
use super::{
    mac::ChipId,
    pcie::Interface,
    power::{Error, Io},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Preparing,
    Ready,
}
#[derive(Debug)]
pub struct Basic {
    state: State,
}
impl Default for Basic {
    fn default() -> Self {
        Self { state: State::New }
    }
}
impl Basic {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Exact, exclusively owned AX function with independently fenced old DMA,
    /// BME off and a powered-accessible PCIe PHY. No concurrent reset, config,
    /// PHY, PM or firmware operation. Failure/cancellation requires reset.
    pub async unsafe fn prepare(
        &mut self,
        io: &mut impl Interface,
        chip: ChipId,
    ) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        if chip == ChipId::Rtl8922A {
            return Err(Error::Unsupported);
        }
        self.state = State::Preparing;
        if chip == ChipId::Rtl8852C {
            disable_eq(io).await?;
            filter_out(io).await?;
        }
        let capability = pcie_capability(io).await?;
        // AX needs PCIe v2 Device Control2. Refuse an unimplemented register
        // instead of writing beyond a v1 capability's defined control words.
        if io.config_read16(capability + 2).await? & 15 < 2 {
            return Err(Error::Unsupported);
        }
        let control = io.config_read16(capability + 0x28).await?;
        if control == u16::MAX {
            return Err(Error::Gone);
        }
        io.config_write16(capability + 0x28, control | 0x10).await?;
        if io.config_read16(capability + 0x28).await? & 0x10 == 0 {
            return Err(Error::Access);
        }
        let link = io.config_read16(capability + 0x10).await?;
        if link == u16::MAX {
            return Err(Error::Gone);
        }
        // Realtek's internal PM modules may follow only host-advertised PCIe
        // enables. No unconditional CLKREQ/ASPM/L1SS capability is invented.
        if link & 0x100 != 0 {
            clkreq(io, chip).await?;
        }
        if link & 2 != 0 {
            aspm(io, chip).await?;
        }
        if let Some(l1ss) = l1ss_capability(io).await? {
            let control = io.config_read32(l1ss + 8).await?;
            if control == u32::MAX {
                return Err(Error::Gone);
            }
            if control & 15 != 0 {
                l1ss_enable(io, chip).await?;
            }
        }
        self.state = State::Ready;
        Ok(())
    }
}
pub(super) async fn pcie_capability(io: &mut impl Interface) -> Result<u16, Error> {
    let mut pointer = u16::from(io.config_read8(0x34).await?);
    let mut visited = 0u64;
    for _ in 0..48 {
        if pointer == 0 {
            return Err(Error::Unsupported);
        }
        if !(0x40..=0xfc).contains(&pointer) || pointer & 3 != 0 {
            return Err(Error::Access);
        }
        let bit = 1u64 << (pointer / 4);
        if visited & bit != 0 {
            return Err(Error::Access);
        }
        visited |= bit;
        let id = io.config_read8(pointer).await?;
        if id == 255 {
            return Err(Error::Gone);
        }
        if id == 0x10 {
            if pointer + 0x2a > 0x100 {
                return Err(Error::Unsupported);
            }
            return Ok(pointer);
        }
        pointer = u16::from(io.config_read8(pointer + 1).await?);
    }
    Err(Error::Access)
}
async fn l1ss_capability(io: &mut impl Interface) -> Result<Option<u16>, Error> {
    let mut pointer = 0x100u16;
    let mut visited = [0u64; 16];
    for _ in 0..960 {
        if !(0x100..=0xffc).contains(&pointer) || pointer & 3 != 0 {
            return Err(Error::Access);
        }
        let slot = usize::from((pointer - 0x100) / 4);
        let bit = 1u64 << (slot % 64);
        if visited[slot / 64] & bit != 0 {
            return Err(Error::Access);
        }
        visited[slot / 64] |= bit;
        let header = io.config_read32(pointer).await?;
        if header == u32::MAX {
            return Err(Error::Gone);
        }
        if header == 0 {
            return Ok(None);
        }
        if header & 0xffff == 0x1e {
            if pointer + 12 > 4096 || header >> 16 & 15 == 0 {
                return Err(Error::Unsupported);
            }
            return Ok(Some(pointer));
        }
        let next = (header >> 20) as u16;
        if next == 0 {
            return Ok(None);
        }
        pointer = next;
    }
    Err(Error::Access)
}
fn read(io: &mut impl Io, a: u32) -> Result<u32, Error> {
    let v = io.read32(a)?;
    if v == u32::MAX {
        Err(Error::Gone)
    } else {
        Ok(v)
    }
}
fn read16(io: &mut impl Io, a: u32) -> Result<u16, Error> {
    let v = io.read16(a)?;
    if v == u16::MAX {
        Err(Error::Gone)
    } else {
        Ok(v)
    }
}
fn modify(io: &mut impl Io, a: u32, clear: u32, set: u32) -> Result<(), Error> {
    let v = read(io, a)?;
    io.write32(a, (v & !clear) | set)
}
fn modify16(io: &mut impl Io, a: u32, clear: u16, set: u16) -> Result<(), Error> {
    let v = read16(io, a)?;
    io.write16(a, (v & !clear) | set)
}
fn field16(io: &mut impl Io, a: u32, mask: u32, value: u16) -> Result<(), Error> {
    modify16(
        io,
        a,
        mask as u16,
        ((u32::from(value) << mask.trailing_zeros()) & mask) as u16,
    )
}
async fn config_modify(io: &mut impl Interface, a: u16, clear: u8, set: u8) -> Result<(), Error> {
    let v = io.config_read8(a).await?;
    if v == 255 {
        return Err(Error::Gone);
    }
    io.config_write8(a, (v & !clear) | set).await
}
async fn link_offset(io: &mut impl Interface) -> Result<u32, Error> {
    let v = io.config_read32(RTW89_PCIE_L1_STS_V1 as u16).await?;
    if v == u32::MAX {
        return Err(Error::Gone);
    }
    match (v & RTW89_BCFG_LINK_SPEED_MASK) >> RTW89_BCFG_LINK_SPEED_MASK.trailing_zeros() {
        1 => Ok(R_RAC_DIRECT_OFFSET_G1),
        2 => Ok(R_RAC_DIRECT_OFFSET_G2),
        _ => Err(Error::Unsupported),
    }
}
async fn disable_eq(io: &mut impl Interface) -> Result<(), Error> {
    let g1 = read16(io, R_RAC_DIRECT_OFFSET_G1 + RAC_ANA09 * 2)? & BAC_OOBS_SEL as u16;
    let g2 = read16(io, R_RAC_DIRECT_OFFSET_G2 + RAC_ANA09 * 2)? & BAC_OOBS_SEL as u16;
    if g1 != 0 && g2 != 0 {
        return Ok(());
    }
    let backup = read(io, R_AX_PCIE_MIX_CFG_V1)?;
    modify(io, R_AX_PCIE_MIX_CFG_V1, B_AX_ASPM_CTRL_MASK, 0)?;
    let calibration = async {
        let offset = link_offset(io).await?;
        modify16(io, offset + RAC_ANA0D * 2, 0, BAC_RX_TEST_EN as u16)?;
        io.write16(offset + RAC_ANA10 * 2, ADDR_SEL_PINOUT_DIS_VAL as u16)?;
        modify16(io, offset + RAC_ANA19 * 2, 0, B_PCIE_BIT_RD_SEL as u16)?;
        let oobs = (read16(io, offset + RAC_ANA1F * 2)? & OOBS_LEVEL_MASK as u16)
            >> OOBS_LEVEL_MASK.trailing_zeros();
        for base in [R_RAC_DIRECT_OFFSET_G1, R_RAC_DIRECT_OFFSET_G2] {
            field16(io, base + RAC_ANA03 * 2, OOBS_SEN_MASK, oobs)?;
            modify16(io, base + RAC_ANA09 * 2, 0, BAC_OOBS_SEL as u16)?;
        }
        for base in [R_RAC_DIRECT_OFFSET_G1, R_RAC_DIRECT_OFFSET_G2] {
            modify16(io, base + RAC_ANA19 * 2, B_PCIE_BIT_RD_SEL as u16, 0)?;
        }
        let offset = (read16(io, R_RAC_DIRECT_OFFSET_G1 + RAC_ANA1F * 2)? & OFFSET_CAL_MASK as u16)
            >> OFFSET_CAL_MASK.trailing_zeros();
        for base in [R_RAC_DIRECT_OFFSET_G1, R_RAC_DIRECT_OFFSET_G2] {
            field16(io, base + RAC_ANA0B * 2, MANUAL_LVL_MASK, offset)?;
            modify16(io, base + RAC_ANA0D * 2, OFFSET_CAL_MODE as u16, 0)?;
        }
        Ok::<(), Error>(())
    }
    .await;
    // Restore the temporary ASPM control on returned errors. A dropped future
    // remains Preparing and cannot replay this partly calibrated PHY.
    let restored = io.write32(R_AX_PCIE_MIX_CFG_V1, backup);
    calibration?;
    restored
}
async fn filter_out(io: &mut impl Interface) -> Result<(), Error> {
    let value = (read(io, R_AX_PCIE_MIX_CFG_V1)? & B_AX_ASPM_CTRL_MASK)
        >> B_AX_ASPM_CTRL_MASK.trailing_zeros();
    // Preserve the original Linux helper's comparison and field semantics.
    if value == B_AX_ASPM_CTRL_L1 {
        return Ok(());
    }
    let offset = link_offset(io).await?;
    if offset == R_RAC_DIRECT_OFFSET_G2 {
        let value = read16(io, offset + RAC_ANA10 * 2)?;
        modify16(
            io,
            offset + RAC_ANA10 * 2,
            0,
            value | B_PCIE_BIT_PINOUT_DIS as u16,
        )?;
        modify16(
            io,
            offset + RAC_ANA19 * 2,
            0,
            value & !(B_PCIE_BIT_RD_SEL as u16),
        )?;
        let gray = (read16(io, offset + RAC_ANA1F * 2)? & FILTER_OUT_EQ_MASK as u16)
            >> FILTER_OUT_EQ_MASK.trailing_zeros();
        let mut binary = gray;
        let mut shifted = gray >> 1;
        while shifted != 0 {
            binary ^= shifted;
            shifted >>= 1;
        }
        field16(io, offset + RAC_ANA24 * 2, REG_FILTER_OUT_MASK, binary)?;
        modify16(io, offset + RAC_ANA0A * 2, 0, B_BAC_EQ_SEL as u16)?;
        modify16(
            io,
            R_RAC_DIRECT_OFFSET_G1 + RAC_ANA0C * 2,
            0,
            B_PCIE_BIT_PSAVE as u16,
        )?;
    }
    modify16(io, offset + RAC_ANA0C * 2, 0, B_PCIE_BIT_PSAVE as u16)
}
async fn clkreq(io: &mut impl Interface, chip: ChipId) -> Result<(), Error> {
    io.config_write8(RTW89_PCIE_CLK_CTRL as u16, PCIE_CLKDLY_HW_30US as u8)
        .await?;
    if chip == ChipId::Rtl8852C {
        modify(
            io,
            R_AX_PCIE_LAT_CTRL,
            0,
            B_AX_CLK_REQ_SEL_OPT | B_AX_CLK_REQ_SEL,
        )?;
        modify(io, R_AX_L1_CLK_CTRL, 0, B_AX_CLK_REQ_N)
    } else {
        config_modify(io, RTW89_PCIE_L1_CTRL as u16, 0, RTW89_PCIE_BIT_CLK as u8).await
    }
}
async fn aspm(io: &mut impl Interface, chip: ChipId) -> Result<(), Error> {
    let value = io.config_read8(RTW89_PCIE_ASPM_CTRL as u16).await?;
    if value == 255 {
        return Err(Error::Gone);
    }
    let value = (u32::from(value) & !(RTW89_L1DLY_MASK | RTW89_L0DLY_MASK))
        | ((PCIE_L1DLY_16US << RTW89_L1DLY_MASK.trailing_zeros()) & RTW89_L1DLY_MASK)
        | ((PCIE_L0SDLY_4US << RTW89_L0DLY_MASK.trailing_zeros()) & RTW89_L0DLY_MASK);
    io.config_write8(RTW89_PCIE_ASPM_CTRL as u16, value as u8)
        .await?;
    if chip == ChipId::Rtl8852C {
        modify(io, R_AX_PCIE_MIX_CFG_V1, 0, B_AX_ASPM_CTRL_L1)
    } else {
        config_modify(io, RTW89_PCIE_L1_CTRL as u16, 0, RTW89_PCIE_BIT_L1 as u8).await
    }
}
async fn l1ss_enable(io: &mut impl Interface, chip: ChipId) -> Result<(), Error> {
    if chip == ChipId::Rtl8852C {
        config_modify(
            io,
            RTW89_PCIE_L1SS_STS_V1 as u16,
            (RTW89_PCIE_BIT_ASPM_L11 | RTW89_PCIE_BIT_PCI_L11) as u8,
            0,
        )
        .await?;
        modify(io, R_AX_PCIE_MIX_CFG_V1, B_AX_L1SUB_DISABLE, 0)
    } else {
        config_modify(
            io,
            RTW89_PCIE_TIMER_CTRL as u16,
            0,
            RTW89_PCIE_BIT_L1SUB as u8,
        )
        .await
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "pci_basic/tests.rs"]
mod tests;
