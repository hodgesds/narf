// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE chip identity qualification from live registers and EFUSE.
//!
//! Mirrors Linux `rtl8192de/hw.c`:
//! - `_rtl92de_read_chip_version`: `REG_SYS_CFG` bits 19:16 clear ⇒ test
//!   chip, refused here (the normal chip is the only qualified part).
//! - `rtl92de_read_eeprom_info`: `REG_9346CR` BIT(5) set ⇒ "Autoload
//!   OK" (`autoload_failflag = false`); clear ⇒ "Autoload ERR!!" and the
//!   EFUSE contents are untrusted, so the TX-power defaults branch runs.
//! - `_rtl92de_efuse_update_chip_version`: the cut is the EFUSE word at
//!   physical bytes `0x3FE` (high) / `0x3FF` (low): `0xAA55` ⇒ C cut,
//!   `0x9966` ⇒ D cut, `0xCC33` ⇒ E cut, anything else ⇒ D cut (Linux
//!   logs "Unknown CUT!" and falls through to D). Only D/E cuts read
//!   `internal_pa_5g` from the TSSI 5G bytes' BIT(6), so the TX-power
//!   reader takes `d_or_e_cut`.
//!
//! The cut bytes are read through the `REG_EFUSE_CTRL` byte protocol
//! (`rtlwifi/efuse.rs::read_factory_with`): the address goes to
//! `CTRL+1` (low byte) and `CTRL+2` bits 1:0 (high bits), `CTRL+3` bit 7
//! is cleared to start the read, the `VALID` bit (dword bit 31) is
//! polled, and the data byte is the low byte of the `REG_EFUSE_CTRL`
//! dword. The EFUSE clocks (`SYS_ISO_CTRL` BIT(15), `SYS_FUNC_EN`
//! BIT(12), `SYS_CLKR` BIT(5) for 92D) are set first, exactly as the
//! factory read does; the writes are idempotent ORs.
//!
//! The retained `Io` has no 16-bit read, so the 16-bit setup registers
//! are read as the low (or high) half of their aligned dword.

use crate::rtlwifi::firmware_transport::{Error as AccessError, Io};
use crate::rtlwifi::prepare::Error;

/// `REG_SYS_CFG` (`rtl8192de/reg.h`).
pub const REG_SYS_CFG: u16 = 0x00f0;
/// `REG_SYS_CFG` bits 19:16: zero on a test chip
/// (`_rtl92de_read_chip_version`).
pub const SYS_CFG_VERSION_MASK: u32 = 0x000f_0000;
/// `REG_9346CR` (`rtl8192de/reg.h`).
pub const REG_9346CR: u16 = 0x000a;
/// `REG_9346CR` BIT(5): set ⇒ autoload OK.
pub const CR9346_AUTOLOAD_OK: u8 = 1 << 5;
/// `REG_SYS_ISO_CTRL` (`rtlwifi/reg.h`).
pub const REG_SYS_ISO_CTRL: u16 = 0x0000;
/// `REG_SYS_FUNC_EN` (`rtlwifi/reg.h`).
pub const REG_SYS_FUNC_EN: u16 = 0x0002;
/// `REG_SYS_CLKR` (`rtlwifi/reg.h`).
pub const REG_SYS_CLKR: u16 = 0x0008;
/// `REG_EFUSE_CTRL` (`rtlwifi/reg.h`).
pub const REG_EFUSE_CTRL: u16 = 0x0030;
/// `REG_EFUSE_CTRL` dword bit 31: the byte read completed.
pub const EFUSE_CTRL_VALID: u32 = 1 << 31;
/// EFUSE physical byte holding the chip-version word's high byte
/// (`EEPROME_CHIP_VERSION_H`, `rtl8192de/reg.h`).
pub const EEPROME_CHIP_VERSION_H: u16 = 0x03fe;
/// EFUSE physical byte holding the chip-version word's low byte
/// (`EEPROME_CHIP_VERSION_L`, `rtl8192de/reg.h`).
pub const EEPROME_CHIP_VERSION_L: u16 = 0x03ff;
/// Chip-version word ⇒ C cut.
pub const CHIP_VERSION_C_CUT: u16 = 0xaa55;
/// Chip-version word ⇒ D cut.
pub const CHIP_VERSION_D_CUT: u16 = 0x9966;
/// Chip-version word ⇒ E cut.
pub const CHIP_VERSION_E_CUT: u16 = 0xcc33;

/// EFUSE chip-version cut (`version_8192d`, `rtl8192de/def.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    /// `0xAA55`: the only cut that does not read `internal_pa_5g`.
    C,
    /// `0x9966`, and any unrecognised word (Linux's default).
    D,
    /// `0xCC33`.
    E,
}

impl Cut {
    /// Whether this cut reads `internal_pa_5g` from the TSSI 5G bytes
    /// (`IS_92D_D_CUT` / `IS_92D_E_CUT`, `rtl8192de/def.h`).
    pub const fn d_or_e_cut(self) -> bool {
        !matches!(self, Self::C)
    }
}

/// Whether the part is a test chip (`_rtl92de_read_chip_version`).
pub fn is_test_chip(io: &impl Io) -> Result<bool, Error> {
    Ok(io.read32(REG_SYS_CFG)? & SYS_CFG_VERSION_MASK == 0)
}

/// Whether EFUSE autoload failed (`REG_9346CR` BIT(5) clear).
pub fn autoload_failed(io: &impl Io) -> Result<bool, Error> {
    Ok(io.read8(REG_9346CR)? & CR9346_AUTOLOAD_OK == 0)
}

/// The EFUSE chip-version cut, read through `REG_EFUSE_CTRL`.
pub async fn read_cut(io: &impl Io) -> Result<Cut, Error> {
    efuse_setup(io).await?;
    let high = read_efuse_byte(io, EEPROME_CHIP_VERSION_H).await?;
    let low = read_efuse_byte(io, EEPROME_CHIP_VERSION_L).await?;
    let word = (u16::from(high) << 8) | u16::from(low);
    Ok(match word {
        CHIP_VERSION_C_CUT => Cut::C,
        CHIP_VERSION_D_CUT => Cut::D,
        CHIP_VERSION_E_CUT => Cut::E,
        // Linux logs "Unknown CUT!" and falls through to D.
        _ => Cut::D,
    })
}

/// Enable the EFUSE clocks, as the factory read does
/// (`read_factory_with`, 92D branch: `SYS_CLKR` BIT(5)).
async fn efuse_setup(io: &impl Io) -> Result<(), Error> {
    let iso = read16_via32(io, REG_SYS_ISO_CTRL).await?;
    io.write16(REG_SYS_ISO_CTRL, iso | (1 << 15))?;
    let func_en = read16_via32(io, REG_SYS_FUNC_EN).await?;
    io.write16(REG_SYS_FUNC_EN, func_en | (1 << 12))?;
    let clkr = read16_via32(io, REG_SYS_CLKR).await?;
    io.write16(REG_SYS_CLKR, clkr | (1 << 5))?;
    Ok(())
}

/// One physical EFUSE byte through `REG_EFUSE_CTRL`
/// (`read_factory_with`): address to `CTRL+1`/`CTRL+2`, start the read
/// by clearing `CTRL+3` bit 7, poll `VALID` (5 ms budget, the factory
/// read's `Deadline::after_ms(5)`), then take the data byte.
async fn read_efuse_byte(io: &impl Io, address: u16) -> Result<u8, Error> {
    io.write8(REG_EFUSE_CTRL + 1, address as u8)?;
    let value = io.read8(REG_EFUSE_CTRL + 2)?;
    io.write8(
        REG_EFUSE_CTRL + 2,
        (value & 0xfc) | ((address >> 8) as u8 & 3),
    )?;
    let value = io.read8(REG_EFUSE_CTRL + 3)?;
    io.write8(REG_EFUSE_CTRL + 3, value & 0x7f)?;
    let mut ready = false;
    for _ in 0..1000 {
        let value = io.read32(REG_EFUSE_CTRL)?;
        if value == u32::MAX {
            return Err(Error::Access(AccessError::Gone));
        }
        if value & EFUSE_CTRL_VALID != 0 {
            ready = true;
            break;
        }
        io.delay_us(5).await;
    }
    if !ready {
        return Err(Error::Access(AccessError::Deadline));
    }
    // Linux allows the data output to settle after the ready flag.
    io.delay_us(50).await;
    Ok(io.read32(REG_EFUSE_CTRL)? as u8)
}

/// A 16-bit register read as half of its aligned dword (the retained
/// `Io` has no 16-bit read). `REG_SYS_FUNC_EN` (0x0002) is the high half
/// of the dword at 0x0000.
async fn read16_via32(io: &impl Io, reg: u16) -> Result<u16, Error> {
    let aligned = reg & !3;
    let value = io.read32(aligned)?;
    Ok(if reg & 2 == 0 {
        value as u16
    } else {
        (value >> 16) as u16
    })
}
