// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE chip identity.
//!
//! Mirrors Linux `rtl8723ae/hw.c::_rtl8723e_read_chip_version` over the
//! measured `REG_SYS_CFG` (`0xf0`), `REG_GPIO_OUTSTS` (`0xf4`) and
//! `REG_MULTI_FUNC_CTRL` (`0x68`), the `rtl8723ae/def.h` version predicates
//! and the `rtl8723ae/sw.c::rtl8723e_init_sw_vars` firmware selection.
//!
//! Qualified: a normal (mass-production) chip carrying `BT_FUNC`, i.e.
//! `IS_8723_SERIES`, for which Linux sets `rf_type = RF_1T1R`. Refused:
//! `TRP_VAUX_EN` test chips (`VERSION_TEST_UMC_CHIP_8723`) and parts without
//! `BT_FUNC` (Linux leaves `rf_type` and the polarity at their defaults and
//! logs "Unknown. Bug?"). The vendor bit, the UMC cut nibble and the ROM
//! version (`REG_GPIO_OUTSTS[31:28] >> 20`) are carried exactly.

/// `REG_MULTI_FUNC_CTRL` (`reg.h`).
pub const REG_MULTI_FUNC_CTRL: u16 = 0x0068;
/// `REG_SYS_CFG` (`reg.h`).
pub const REG_SYS_CFG: u16 = 0x00f0;
/// `REG_GPIO_OUTSTS` (`reg.h`).
pub const REG_GPIO_OUTSTS: u16 = 0x00f4;

/// `REG_SYS_CFG` fields (`reg.h`).
pub const BT_FUNC: u32 = 1 << 16;
pub const VENDOR_ID: u32 = 1 << 19;
pub const TRP_VAUX_EN: u32 = 1 << 23;
pub const CHIP_VER_RTL_MASK: u32 = 0xf000;
/// `RF_RL_ID` (`def.h`), `REG_GPIO_OUTSTS[31:28]`.
pub const RF_RL_ID: u32 = 0xf000_0000;
/// `WL_HWPDN_SL` (`reg.h`), `REG_MULTI_FUNC_CTRL` BIT1.
pub const WL_HWPDN_SL: u32 = 1 << 1;

/// `enum version_8723e` bits (`def.h`).
pub const CHIP_8723: u16 = 1 << 0;
pub const NORMAL_CHIP: u16 = 1 << 3;
pub const CHIP_VENDOR_UMC: u16 = 1 << 7;
pub const B_CUT_VERSION: u16 = 1 << 12;
pub const IC_TYPE_MASK: u16 = 0x0007;
pub const ROM_VERSION_MASK: u16 = 0x0f00;
pub const CUT_VERSION_MASK: u16 = 0xf000;

/// `rtl8723ae/sw.c` firmware names: `rtl8723fw.bin`, or `rtl8723fw_B.bin`
/// when `IS_81XXC_VENDOR_UMC_B_CUT(rtlhal->version)`. No `alt_fw_name`.
pub const FW_NORMAL: &str = "rtlwifi/rtl8723fw.bin";
pub const FW_UMC_B: &str = "rtlwifi/rtl8723fw_B.bin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `TRP_VAUX_EN`: a test chip.
    TestChip,
    /// `BT_FUNC` clear: not `IS_8723_SERIES`, no Linux RF type.
    NotSeries,
}

/// `rtlphy->polarity_ctl` from `REG_MULTI_FUNC_CTRL[1]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    /// `RT_POLARITY_LOW_ACT`.
    LowActive,
    /// `RT_POLARITY_HIGH_ACT`.
    HighActive,
}

/// A qualified `rtlhal->version` (`enum version_8723e` value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    raw: u16,
    polarity: Polarity,
}

impl Version {
    /// `_rtl8723e_read_chip_version`. `gpio_outsts` and `multi_func_ctrl`
    /// are read only on the paths Linux reads them (normal 8723 series).
    pub fn from_registers(
        sys_cfg: u32,
        gpio_outsts: impl FnOnce() -> u32,
        multi_func_ctrl: impl FnOnce() -> u32,
    ) -> Result<Self, Error> {
        if sys_cfg & TRP_VAUX_EN != 0 {
            return Err(Error::TestChip);
        }
        if sys_cfg & BT_FUNC == 0 {
            return Err(Error::NotSeries);
        }
        let mut raw = NORMAL_CHIP | CHIP_8723;
        if sys_cfg & VENDOR_ID != 0 {
            raw |= CHIP_VENDOR_UMC;
            raw |= (sys_cfg & CHIP_VER_RTL_MASK) as u16;
        }
        raw |= ((gpio_outsts() & RF_RL_ID) >> 20) as u16;
        let polarity = if multi_func_ctrl() & WL_HWPDN_SL != 0 {
            Polarity::HighActive
        } else {
            Polarity::LowActive
        };
        Ok(Self { raw, polarity })
    }

    pub const fn raw(self) -> u16 {
        self.raw
    }

    pub const fn polarity(self) -> Polarity {
        self.polarity
    }

    /// `IS_CHIP_VENDOR_UMC`.
    pub const fn is_umc(self) -> bool {
        self.raw & CHIP_VENDOR_UMC != 0
    }

    /// `GET_CVID_CUT_VERSION`.
    pub const fn cut(self) -> u16 {
        self.raw & CUT_VERSION_MASK
    }

    /// `IS_VENDOR_UMC_A_CUT`.
    pub const fn is_umc_a_cut(self) -> bool {
        self.is_umc() && self.cut() == 0
    }

    /// `IS_81XXC_VENDOR_UMC_B_CUT`.
    pub const fn is_umc_b_cut(self) -> bool {
        self.is_umc() && self.cut() == B_CUT_VERSION
    }

    /// `IS_VENDOR_8723_A_CUT` (every qualified version is 8723 series).
    pub const fn is_8723_a_cut(self) -> bool {
        self.cut() == 0
    }

    /// `rtl8723e_init_sw_vars` `fw_name`.
    pub const fn firmware(self) -> &'static str {
        if self.is_umc_b_cut() {
            FW_UMC_B
        } else {
            FW_NORMAL
        }
    }
}
