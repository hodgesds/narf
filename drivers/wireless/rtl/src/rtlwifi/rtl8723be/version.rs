// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE chip identity.
//!
//! Mirrors Linux `rtl8723be/hw.c::_rtl8723be_read_chip_version` over the
//! measured `REG_SYS_CFG1` (`0xfc`) and `REG_SYS_CFG` (`0xf0`), with the
//! `def.h` / `rtl8723com/fw_common.h` version bits, and the
//! `rtl8723be/sw.c` firmware names.
//!
//! Linux treats every RTL8723BE as an MP (`NORMAL_CHIP`) 1T1R part and
//! only logs when `REG_SYS_CFG1` lacks `CHIP_8723B`, continuing with
//! `VERSION_UNKNOWN | NORMAL_CHIP | cut` (`0xff` already carries every low
//! bit). Such a version selects nothing meaningful (the table conditions use
//! the cut nibble), so it is refused here. Every cut and both vendors
//! (`EXT_VENDOR_ID == 1` ⇒ `CHIP_VENDOR_SMIC`) are carried exactly.

/// `REG_SYS_CFG` (`reg.h`).
pub const REG_SYS_CFG: u16 = 0x00f0;
/// `REG_SYS_CFG1` (`reg.h`).
pub const REG_SYS_CFG1: u16 = 0x00fc;

/// `CHIP_8723B` (`def.h`).
pub const CHIP_8723B: u32 = (1 << 1) | (1 << 2);
/// `NORMAL_CHIP` (`def.h`).
pub const NORMAL_CHIP: u16 = 1 << 3;
/// `CHIP_VENDOR_SMIC` (`def.h`).
pub const CHIP_VENDOR_SMIC: u16 = 1 << 8;
/// `EXT_VENDOR_ID` (`def.h`), `REG_SYS_CFG[19:18]`.
pub const EXT_VENDOR_ID: u32 = (1 << 18) | (1 << 19);
/// `CHIP_VER_RTL_MASK` / `CHIP_VER_RTL_SHIFT` (`reg.h`).
pub const CHIP_VER_RTL_MASK: u32 = 0xf000;
pub const CHIP_VER_RTL_SHIFT: u32 = 12;

/// `rtl8723be/sw.c` `fw_name`, and `alt_fw_name` which
/// `core.c::rtl_fw_do_work` requests only when the primary is absent.
pub const FW_NORMAL: &str = "rtlwifi/rtl8723befw_36.bin";
pub const FW_NORMAL_ALT: &str = "rtlwifi/rtl8723befw.bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `REG_SYS_CFG1` does not identify an RTL8723B (`CHIP_8723B`).
    Unknown,
}

/// `rtlhal->version` of an identified RTL8723BE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version(u16);

impl Version {
    /// `_rtl8723be_read_chip_version`.
    pub fn from_registers(sys_cfg1: u32, sys_cfg: u32) -> Result<Self, Error> {
        if sys_cfg1 & CHIP_8723B != CHIP_8723B {
            return Err(Error::Unknown);
        }
        let mut version = CHIP_8723B as u16 | NORMAL_CHIP;
        version |= (sys_cfg & CHIP_VER_RTL_MASK) as u16;
        if (sys_cfg & EXT_VENDOR_ID) >> 18 == 0x01 {
            version |= CHIP_VENDOR_SMIC;
        }
        Ok(Self(version))
    }

    pub const fn raw(self) -> u16 {
        self.0
    }

    /// `(version & CHIP_VER_RTL_MASK) >> CHIP_VER_RTL_SHIFT`, the cut used
    /// by `_rtl8723be_check_condition`.
    pub const fn cut(self) -> u8 {
        ((self.0 as u32 & CHIP_VER_RTL_MASK) >> CHIP_VER_RTL_SHIFT) as u8
    }

    pub const fn is_smic(self) -> bool {
        self.0 & CHIP_VENDOR_SMIC != 0
    }

    /// Firmware names in `rtl_fw_do_work` order.
    pub const fn firmware_names() -> [&'static str; 2] {
        [FW_NORMAL, FW_NORMAL_ALT]
    }
}
