// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE chip identity and RF-type qualification.
//!
//! Mirrors Linux `rtl8192ce/hw.c::_rtl92ce_read_chip_version` (from the
//! measured `REG_SYS_CFG` and, for 92C-serial parts, `REG_HPON_FSM`), the
//! `rtl8192c/fw_common.h` version predicates and the
//! `rtl8192ce/sw.c::rtl92c_init_sw_vars` firmware-name selection.
//!
//! Only the two RF types Linux actually assigns are qualified:
//! `version & 3 == CHIP_88C` ⇒ `RF_1T1R` (RTL8188CE) and `CHIP_92C` ⇒
//! `RF_2T2R` (RTL8192CE). A 92C-serial part whose bonding reads
//! `CHIP_BONDING_92C_1T2R` gets `version & 3 == CHIP_92C_1T2R`, for which
//! Linux's `switch (version & 0x3)` leaves `rtlphy->rf_type` at its default;
//! that combination (and therefore any 1T2R table/calibration choice) is
//! refused here. `TRP_VAUX_EN` test chips (`VERSION_A_CHIP_*`, written by
//! `rtl_fw_block_write` instead of the paged download) and versions carrying
//! `CHIP_UNKNOWN` (a non-UMC `CHIP_VER_RTL_MASK` other than `BIT(12)`) are
//! refused as well.

/// `REG_HPON_FSM` (`reg.h`).
pub const REG_HPON_FSM: u16 = 0x00ec;
/// `REG_SYS_CFG` (`reg.h`).
pub const REG_SYS_CFG: u16 = 0x00f0;

/// `REG_SYS_CFG` fields (`reg.h`).
pub const VENDOR_ID: u32 = 1 << 19;
pub const TRP_VAUX_EN: u32 = 1 << 23;
pub const TYPE_ID: u32 = 1 << 27;
pub const CHIP_VER_RTL_MASK: u32 = 0xf000;

/// `version_8192c` bits (`def.h`, `fw_common.h`).
pub const CHIP_92C_BITMASK: u8 = 1 << 0;
pub const RF_TYPE_1T2R: u8 = 1 << 1;
pub const CHIP_VER_B: u8 = 1 << 4;
pub const CHIP_VENDOR_UMC: u8 = 1 << 5;
pub const CHIP_VENDOR_UMC_B_CUT: u8 = 1 << 6;
pub const CHIP_UNKNOWN: u8 = 1 << 7;
pub const RF_TYPE_MASK: u8 = 0x03;
pub const CUT_VERSION_MASK: u8 = 0xc0;
/// `CHIP_BONDING_IDENTIFIER(value) == CHIP_BONDING_92C_1T2R`.
pub const CHIP_BONDING_92C_1T2R: u32 = 0x1;

/// `rtl8192ce/sw.c` firmware names.
pub const FW_NORMAL: &str = "rtlwifi/rtl8192cfw.bin";
pub const FW_UMC_A: &str = "rtlwifi/rtl8192cfwU.bin";
pub const FW_UMC_B: &str = "rtlwifi/rtl8192cfwU_B.bin";

/// `rtlphy->rf_type` values Linux assigns for this family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfType {
    /// `RF_1T1R`: RTL8188CE (`CHIP_88C`).
    T1R1,
    /// `RF_2T2R`: RTL8192CE (`CHIP_92C`).
    T2R2,
}

impl RfType {
    /// Number of RF paths the table walker and calibration program.
    pub const fn paths(self) -> usize {
        match self {
            Self::T1R1 => 1,
            Self::T2R2 => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `TRP_VAUX_EN`: an A-cut test chip.
    TestChip,
    /// `CHIP_UNKNOWN`: a non-UMC chip with an unrecognised RTL version.
    UnknownCut,
    /// `CHIP_92C_1T2R`: Linux assigns no RF type for this bonding.
    UnqualifiedRfType,
}

/// A qualified `rtlhal->version` (`enum version_8192c` value).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version(u8);

impl Version {
    /// `_rtl92ce_read_chip_version` over the measured `REG_SYS_CFG` and
    /// `REG_HPON_FSM` (the latter is only consulted for 92C-serial parts,
    /// exactly as Linux reads it).
    pub fn from_registers(sys_cfg: u32, hpon_fsm: impl FnOnce() -> u32) -> Result<Self, Error> {
        if sys_cfg & TRP_VAUX_EN != 0 {
            return Err(Error::TestChip);
        }
        let mut version = CHIP_VER_B
            | if sys_cfg & TYPE_ID != 0 {
                CHIP_92C_BITMASK
            } else {
                0
            }
            | if sys_cfg & VENDOR_ID != 0 {
                CHIP_VENDOR_UMC
            } else {
                0
            };
        if version & CHIP_VENDOR_UMC == 0 && sys_cfg & CHIP_VER_RTL_MASK != 0 {
            version |= if sys_cfg & CHIP_VER_RTL_MASK == 1 << 12 {
                CHIP_VENDOR_UMC_B_CUT
            } else {
                CHIP_UNKNOWN
            } | CHIP_VENDOR_UMC;
        }
        if version & RF_TYPE_MASK == CHIP_92C_BITMASK
            && (hpon_fsm() >> 22) & 0x3 == CHIP_BONDING_92C_1T2R
        {
            version |= RF_TYPE_1T2R;
        }
        Self::qualify(version)
    }

    /// Admit an already-derived `version_8192c` value.
    pub fn qualify(version: u8) -> Result<Self, Error> {
        if version & CHIP_VER_B == 0 {
            return Err(Error::TestChip);
        }
        if version & CHIP_UNKNOWN != 0 {
            return Err(Error::UnknownCut);
        }
        if version & RF_TYPE_MASK > CHIP_92C_BITMASK {
            return Err(Error::UnqualifiedRfType);
        }
        Ok(Self(version))
    }

    pub const fn raw(self) -> u8 {
        self.0
    }

    /// `IS_92C_SERIAL` / `IS_2T2R`.
    pub const fn is_92c_serial(self) -> bool {
        self.0 & RF_TYPE_MASK == CHIP_92C_BITMASK
    }

    /// The RF type `_rtl92ce_read_chip_version` assigns.
    pub const fn rf_type(self) -> RfType {
        if self.is_92c_serial() {
            RfType::T2R2
        } else {
            RfType::T1R1
        }
    }

    /// `IS_CHIP_VENDOR_UMC`.
    pub const fn is_umc(self) -> bool {
        self.0 & CHIP_VENDOR_UMC != 0
    }

    /// `IS_VENDOR_UMC_A_CUT`.
    pub const fn is_umc_a_cut(self) -> bool {
        self.is_umc() && self.0 & CUT_VERSION_MASK == 0
    }

    /// `IS_81XXC_VENDOR_UMC_B_CUT`.
    pub const fn is_umc_b_cut(self) -> bool {
        self.is_umc() && self.0 & CUT_VERSION_MASK == CHIP_VENDOR_UMC_B_CUT
    }

    /// `rtl92c_init_sw_vars` firmware selection.
    pub const fn firmware(self) -> &'static str {
        if self.is_umc_a_cut() && !self.is_92c_serial() {
            FW_UMC_A
        } else if self.is_umc_b_cut() {
            FW_UMC_B
        } else {
            FW_NORMAL
        }
    }
}
