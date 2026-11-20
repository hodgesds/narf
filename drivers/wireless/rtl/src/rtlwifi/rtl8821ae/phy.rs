// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE BB/RF enable and table configuration.
//!
//! Exact `rtl8821ae/phy.c::rtl8821ae_phy_bb_config` (BB enable, PHY_REG and
//! AGC walks, crystal cap) and `rtl8821ae_phy_rf_config` /
//! `rf.c::_rtl8821ae_phy_rf6052_config_parafile` (RF path A only; RTL8821AE
//! is `RF_1T1R`). RF writes use `_rtl8821ae_phy_rf_serial_write` through
//! `RA_LSSIWRITE_8821A`; reads use `_rtl8821ae_phy_rf_serial_read` (no CCA
//! toggle for 8821AE, 20 us HSSI settle). Power-by-rate (`PHY_REG_PG`) and
//! limit tables are software-only in Linux and are owned by `power_limit`.

use super::headerfile::{bb_action, rf_action, walk, BbAction, Condition, RfAction};
use super::tables;
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;
use alloc::vec::Vec;

pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_RF_CTRL: u16 = 0x001f;
pub const REG_MAC_PHY_CTRL: u16 = 0x002c;
pub const REG_OPT_CTRL: u16 = 0x0074;
pub const FEN_BBRSTB: u8 = 1 << 0;
pub const FEN_BB_GLB_RSTN: u8 = 1 << 1;
pub const FEN_PCIEA: u8 = 1 << 6;
/// `RFPGA0_XA_HSSIPARAMETER2`; bit 9 is `cck_high_power`.
pub const RFPGA0_XA_HSSIPARAMETER2: u16 = 0x0824;
/// `RHSSIREAD_8821AE`.
pub const RHSSIREAD: u16 = 0x08b0;
/// `RA_LSSIWRITE_8821A` (`phyreg_def[A].rf3wire_offset`).
pub const RA_LSSIWRITE: u16 = 0x0c90;
/// `RA_PIREAD_8821A` / `RA_SIREAD_8821A`.
pub const RA_PIREAD: u16 = 0x0d04;
pub const RA_SIREAD: u16 = 0x0d08;
/// `EEPROM_XTAL_8821AE` / `EEPROM_RFE_OPTION` (`reg.h`).
pub const EEPROM_XTAL: usize = 0xb9;
pub const EEPROM_RFE_OPTION: usize = 0xca;

/// Facts produced by BB/RF configuration of one provisioned board.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub crystal_cap: u8,
    pub rfe_type: u8,
    /// `rtlphy->cck_high_power` read back after the AGC table.
    pub cck_high_power: bool,
    /// `rtlphy->reg_837` saved after the crystal-cap write.
    pub reg_837: u8,
}

fn reg(addr: u32) -> Result<u16, Error> {
    u16::try_from(addr)
        .ok()
        .filter(|r| r & 3 == 0)
        .ok_or(Error::Descriptor)
}

/// Rows the walker selects for this board, in source order.
pub fn selected(table: &[[u32; 2]], condition: &Condition) -> Vec<(u32, u32)> {
    let mut rows = Vec::new();
    let _ = walk::<()>(table, condition, |a, d| {
        rows.push((a, d));
        Ok(())
    });
    rows
}

/// `rtl8821ae_phy_set_bb_reg` (read-modify-write unless `MASKDWORD`).
pub fn set_bb(io: &impl Io, at: u16, mask: u32, value: u32) -> Result<(), Error> {
    let data = if mask == u32::MAX {
        value
    } else {
        let shift = mask.trailing_zeros();
        (io.read32(at)? & !mask) | ((value << shift) & mask)
    };
    io.write32(at, data)?;
    Ok(())
}

/// `rtl8821ae_phy_query_bb_reg`.
pub fn get_bb(io: &impl Io, at: u16, mask: u32) -> Result<u32, Error> {
    Ok((io.read32(at)? & mask) >> mask.trailing_zeros())
}

/// `_rtl8821ae_phy_rf_serial_write` on path A.
pub fn rf_write(io: &impl Io, offset: u32, data: u32) -> Result<(), Error> {
    let word = (((offset & 0xff) << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    set_bb(io, RA_LSSIWRITE, u32::MAX, word)
}

/// `_rtl8821ae_phy_rf_serial_read` on path A (8821AE: no CCA toggle).
pub async fn rf_read(io: &impl Io, offset: u32) -> Result<u32, Error> {
    let pi = get_bb(io, 0x0c00, 0x4)? != 0;
    set_bb(io, RHSSIREAD, 0xff, offset & 0xff)?;
    io.delay_us(20).await;
    get_bb(io, if pi { RA_PIREAD } else { RA_SIREAD }, 0x000f_ffff)
}

/// `rtl8821ae_phy_set_rf_reg` on path A.
pub async fn set_rf(io: &impl Io, offset: u32, mask: u32, value: u32) -> Result<(), Error> {
    let data = if mask == 0x000f_ffff {
        value
    } else {
        // Linux does not re-mask the shifted value here.
        (rf_read(io, offset).await? & !mask) | (value << mask.trailing_zeros())
    };
    rf_write(io, offset, data)
}

/// `_rtl8821ae_read_rfe_type` for a provisioned (autoloaded) map.
pub fn rfe_type(logical: &[u8], condition: &Condition) -> Result<u8, Error> {
    let option = *logical.get(EEPROM_RFE_OPTION).ok_or(Error::State)?;
    Ok(if option & 0x80 != 0 {
        if condition.external_lna_5g {
            if condition.external_pa_5g {
                if condition.external_lna_2g && condition.external_pa_2g {
                    3
                } else {
                    0
                }
            } else {
                2
            }
        } else {
            4
        }
    } else {
        // The rfe_type 4 -> 2 override applies only to RTL8812AE.
        option & 0x3f
    })
}

/// `rtlefuse->crystalcap` (`0xff` ⇒ Linux default `0x20`).
pub fn crystal_cap(logical: &[u8]) -> Result<u8, Error> {
    let cap = *logical.get(EEPROM_XTAL).ok_or(Error::State)?;
    Ok(if cap == 0xff { 0x20 } else { cap })
}

/// `rtl8821ae_phy_bb_config` register effects in Linux order.
pub async fn bb_config(
    io: &impl Io,
    condition: &Condition,
    crystal: u8,
) -> Result<(bool, u8), Error> {
    let value = io.read8(REG_SYS_FUNC_EN)? | FEN_PCIEA;
    io.write8(REG_SYS_FUNC_EN, value)?;
    io.write8(REG_SYS_FUNC_EN, value | FEN_BB_GLB_RSTN | FEN_BBRSTB)?;
    io.write8(REG_RF_CTRL, 0x7)?;
    io.write8(REG_OPT_CTRL + 2, 0x7)?;
    // _rtl8821ae_config_bb_reg: delay rows, else dword write; 1 us per row.
    for (addr, data) in selected(tables::PHY_REG, condition) {
        match bb_action(addr, data) {
            BbAction::DelayUs(us) => io.delay_us(u64::from(us)).await,
            BbAction::Write(addr, data) => set_bb(io, reg(addr)?, u32::MAX, data)?,
        }
        io.delay_us(1).await;
    }
    // rtl_set_bbreg_with_dwmask: every AGC row is a plain dword write.
    for (addr, data) in selected(tables::AGC_TAB, condition) {
        set_bb(io, reg(addr)?, u32::MAX, data)?;
    }
    let cck_high_power = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, 0x200)? != 0;
    let cap = u32::from(crystal & 0x3f);
    set_bb(io, REG_MAC_PHY_CTRL, 0x00ff_f000, cap | (cap << 6))?;
    let reg_837 = io.read8(0x837)?;
    Ok((cck_high_power, reg_837))
}

/// `rtl8821ae_phy_config_rf_with_headerfile(RF90_PATH_A)`.
pub async fn rf_config(io: &impl Io, condition: &Condition) -> Result<(), Error> {
    for (addr, data) in selected(tables::RADIOA, condition) {
        match rf_action(addr, data) {
            RfAction::DelayUs(us) => io.delay_us(u64::from(us)).await,
            RfAction::Write(addr, data) => {
                rf_write(io, addr, data)?;
                io.delay_us(1).await;
            }
        }
    }
    Ok(())
}

/// MAC table (`_rtl8821ae_phy_config_mac_with_headerfile`), byte writes.
pub fn mac_config(io: &impl Io, condition: &Condition) -> Result<(), Error> {
    for (addr, data) in selected(tables::MAC, condition) {
        let at = u16::try_from(addr).map_err(|_| Error::Descriptor)?;
        io.write8(at, data as u8)?;
    }
    Ok(())
}

/// MAC table, BB and RF configuration of `rtl8821ae_hw_init`.
pub async fn configure(
    io: &impl Io,
    condition: &Condition,
    logical: &[u8],
) -> Result<Report, Error> {
    let crystal = crystal_cap(logical)?;
    let rfe_type = rfe_type(logical, condition)?;
    mac_config(io, condition)?;
    let (cck_high_power, reg_837) = bb_config(io, condition, crystal).await?;
    rf_config(io, condition).await?;
    Ok(Report {
        crystal_cap: crystal,
        rfe_type,
        cck_high_power,
        reg_837,
    })
}
