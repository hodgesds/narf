// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE `_rtl8712e_init_mac` power segment.
//!
//! Linux `rtl8723ae/hw.c::_rtl8712e_init_mac` begins `REG_RSV_CTRL = 0`,
//! records `mac_func_enable` (`REG_CR == 0xff`) and parses
//! `RTL8723_NIC_ENABLE_FLOW` (`rtl8723A_card_enable_flow`) with
//! `PWR_CUT_ALL_MSK` / `PWR_FAB_ALL_MSK` / `PWR_INTF_PCI_MSK`; probe runs that
//! prefix (`power::power_on_with`). [`post_flow`] is the segment Linux runs
//! next, before `REG_CR = 0x2ff`: `REG_PCIE_CTRL_REG + 2` BIT4, the eMAC
//! timeout enable (`0x369` BIT7) and the ePHY `0x1e[4]` MDIO write loop.
//! The firmware owner issues it before the download, as Linux does.
//!
//! The ePHY loop is Linux's: up to 100 rounds of the `0x358`/`0x356`/`0x354`
//! word writes with 100 us settles, ending when `0x356` reads back `0xc290`.
//! Linux fails `_rtl8712e_init_mac` (and so `hw_init`) after 100 rounds; so
//! does [`post_flow`].

use crate::rtlwifi::firmware_transport::{Error, Io};

/// `REG_RSV_CTRL`, `REG_CR`, `REG_PCIE_CTRL_REG` (`reg.h`).
pub const REG_RSV_CTRL: u16 = 0x001c;
pub const REG_CR: u16 = 0x0100;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
/// ePHY MDIO registers `_rtl8712e_init_mac` uses.
pub const REG_MDIO_WDATA: u16 = 0x0354;
pub const REG_MDIO_RDATA: u16 = 0x0356;
pub const REG_MDIO_CTL: u16 = 0x0358;
/// eMAC time-out function enable byte.
pub const REG_EMAC_TIMEOUT: u16 = 0x0369;
/// `retry < 100`.
pub const EPHY_RETRIES: u16 = 100;

/// `_rtl8712e_init_mac` after `RTL8723_NIC_ENABLE_FLOW`, up to but not
/// including `REG_CR = 0x2ff`.
pub async fn post_flow<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    let value = io.read8(REG_PCIE_CTRL_REG + 2)?;
    io.write8(REG_PCIE_CTRL_REG + 2, value | (1 << 4))?;
    let value = io.read8(REG_EMAC_TIMEOUT)?;
    io.write8(REG_EMAC_TIMEOUT, value | (1 << 7))?;
    let mut retry = 0;
    loop {
        io.write16(REG_MDIO_CTL, 0x5e)?;
        io.delay_us(100).await;
        io.write16(REG_MDIO_RDATA, 0xc280)?;
        io.write16(REG_MDIO_WDATA, 0xc290)?;
        io.write16(REG_MDIO_CTL, 0x3e)?;
        io.delay_us(100).await;
        io.write16(REG_MDIO_CTL, 0x5e)?;
        io.delay_us(100).await;
        let value = u16::from_le_bytes([io.read8(REG_MDIO_RDATA)?, io.read8(REG_MDIO_RDATA + 1)?]);
        retry += 1;
        if value == 0xc290 || retry >= EPHY_RETRIES {
            break;
        }
    }
    if retry >= EPHY_RETRIES {
        // Linux: "InitMAC(): ePHY configure fail!!!", return false.
        return Err(Error::Gate);
    }
    Ok(())
}
