// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE conditional register-table walker.
//!
//! Mirrors Linux `rtl8821ae/phy.c::__rtl8821ae_phy_config_with_headerfile`
//! and `_rtl8821ae_check_positive`. The selector inputs are never assumed:
//! the cut comes from `REG_SYS_CFG` (`_rtl8821ae_read_chip_version`), the
//! board type from the factory EFUSE PA/LNA bytes (`_rtl8821ae_read_pa_type`)
//! plus the BT-coexist strap in `REG_MULTI_FUNC_CTRL[18]`
//! (`_rtl8821ae_read_bt_coexist_info_from_hwpg`). An EFUSE map without the
//! `0x8129` autoload ID is unprovisioned and yields no condition at all, so
//! no table row can be selected for it.

/// `REG_SYS_CFG` (`reg.h`).
pub const REG_SYS_CFG: u16 = 0x00f0;
/// `REG_MULTI_FUNC_CTRL` (`reg.h`).
pub const REG_MULTI_FUNC_CTRL: u16 = 0x0068;
/// `TRP_VAUX_EN` — test-chip strap in `REG_SYS_CFG`.
pub const TRP_VAUX_EN: u32 = 1 << 23;
/// `CHIP_VER_RTL_MASK` / `CHIP_VER_RTL_SHIFT`.
pub const CHIP_VER_RTL_MASK: u32 = 0xf000;

/// `ODM_BOARD_*` (`def.h`).
pub const ODM_BOARD_BT: u8 = 1 << 2;
pub const ODM_BOARD_EXT_PA: u8 = 1 << 3;
pub const ODM_BOARD_EXT_LNA: u8 = 1 << 4;
pub const ODM_BOARD_EXT_PA_5G: u8 = 1 << 6;
pub const ODM_BOARD_EXT_LNA_5G: u8 = 1 << 7;

/// EFUSE logical offsets read by `_rtl8821ae_read_pa_type`.
const EEPROM_PA_TYPE: usize = 0xbc;
const EEPROM_LNA_TYPE_2G: usize = 0xbd;
const EEPROM_LNA_TYPE_5G: usize = 0xbf;
/// `RTL8190_EEPROM_ID`, checked by `rtl_get_hwinfo`.
const EEPROM_ID: u16 = 0x8129;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `TRP_VAUX_EN` test chip; Linux `VERSION_TEST_CHIP_8821`.
    TestChip,
    /// EFUSE autoload failed (`autoload_failflag`): no factory board facts.
    Unprovisioned,
    /// Table length is not a whole number of (v1, v2) pairs.
    Table,
}

/// Selector inputs for `_rtl8821ae_check_positive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Condition {
    /// `GET_CVID_CUT_VERSION(version) >> 12` for a normal 8821A chip.
    pub cut: u8,
    /// `rtlhal->board_type` as composed in `_rtl8821ae_read_adapter_info`.
    pub board_type: u8,
    pub external_pa_2g: bool,
    pub external_lna_2g: bool,
    pub external_pa_5g: bool,
    pub external_lna_5g: bool,
}

impl Condition {
    /// Build from measured `REG_SYS_CFG`, `REG_MULTI_FUNC_CTRL` and the
    /// retained factory logical EFUSE map (512 bytes for RTL8821AE).
    pub fn from_hardware(
        sys_cfg: u32,
        multi_func_ctrl: u32,
        logical: &[u8],
    ) -> Result<Self, Error> {
        if sys_cfg & TRP_VAUX_EN != 0 {
            return Err(Error::TestChip);
        }
        if logical.len() < 0x100 || u16::from_le_bytes([logical[0], logical[1]]) != EEPROM_ID {
            return Err(Error::Unprovisioned);
        }
        let (mut pa_2g, mut lna_2g) = (logical[EEPROM_PA_TYPE], logical[EEPROM_LNA_TYPE_2G]);
        if pa_2g == 0xff && lna_2g == 0xff {
            pa_2g = 0;
            lna_2g = 0;
        }
        let (mut pa_5g, mut lna_5g) = (logical[EEPROM_PA_TYPE], logical[EEPROM_LNA_TYPE_5G]);
        if pa_5g == 0xff && lna_5g == 0xff {
            pa_5g = 0;
            lna_5g = 0;
        }
        let external_pa_2g = pa_2g & (1 << 5) != 0;
        let external_lna_2g = lna_2g & (1 << 7) != 0;
        let external_pa_5g = pa_5g & (1 << 1) != 0;
        let external_lna_5g = lna_5g & (1 << 7) != 0;
        let mut board_type = 0;
        if external_lna_2g {
            board_type |= ODM_BOARD_EXT_LNA;
        }
        if external_lna_5g {
            board_type |= ODM_BOARD_EXT_LNA_5G;
        }
        if external_pa_2g {
            board_type |= ODM_BOARD_EXT_PA;
        }
        if external_pa_5g {
            board_type |= ODM_BOARD_EXT_PA_5G;
        }
        if multi_func_ctrl & (1 << 18) != 0 {
            board_type |= ODM_BOARD_BT;
        }
        Ok(Self {
            cut: ((sys_cfg & CHIP_VER_RTL_MASK) >> 12) as u8,
            board_type,
            external_pa_2g,
            external_lna_2g,
            external_pa_5g,
            external_lna_5g,
        })
    }

    /// `_rtl8821ae_check_positive`. RTL8821AE never sets `package_type` or
    /// the per-path `type_{glna,gpa,alna,apa}` (only the 8812AE amplifier
    /// reader does), so both are zero exactly as in Linux.
    pub fn positive(&self, cond1: u32, cond2: u32) -> bool {
        let b = u32::from(self.board_type);
        let board = ((b >> 4) & 1)        // _GLNA
            | ((b >> 3) & 1) << 1         // _GPA
            | ((b >> 7) & 1) << 2         // _ALNA
            | ((b >> 6) & 1) << 3         // _APA
            | ((b >> 2) & 1) << 4; // _BT
        let package_type = 0u32;
        let intf = 1u32; // PCIe: BIT(0)
        let driver1 =
            u32::from(self.cut) << 24 | 0x04 << 16 | package_type << 12 | intf << 8 | board;
        let driver2 = 0u32;
        if cond1 & 0x0000_f000 != 0 && cond1 & 0x0000_f000 != driver1 & 0x0000_f000 {
            return false;
        }
        if cond1 & 0x0f00_0000 != 0 && cond1 & 0x0f00_0000 != driver1 & 0x0f00_0000 {
            return false;
        }
        let c1 = cond1 & 0x00ff_0fff;
        let d1 = driver1 & 0x00ff_0fff;
        if c1 & d1 != c1 {
            return false;
        }
        if c1 & 0x0f == 0 {
            return true;
        }
        let mut mask = 0u32;
        if c1 & 1 != 0 {
            mask |= 0x0000_00ff;
        }
        if c1 & 2 != 0 {
            mask |= 0x0000_ff00;
        }
        if c1 & 4 != 0 {
            mask |= 0x00ff_0000;
        }
        if c1 & 8 != 0 {
            mask |= 0xff00_0000;
        }
        cond2 & mask == driver2 & mask
    }
}

/// Walk an (address, value) table, calling `set` for every selected row in
/// source order. Condition rows (`BIT31`) select IF/ELSE-IF/ELSE/ENDIF
/// blocks; `BIT30` negative rows are ignored as in Linux. A set failure
/// stops the walk at that exact row.
pub fn walk<E>(
    table: &[[u32; 2]],
    condition: &Condition,
    mut set: impl FnMut(u32, u32) -> Result<(), E>,
) -> Result<(), E> {
    const COND_ELSE: u32 = 2;
    const COND_ENDIF: u32 = 3;
    let (mut matched, mut skipped) = (true, false);
    for &[v1, v2] in table {
        if v1 & 0xc000_0000 != 0 {
            if v1 & 0x8000_0000 != 0 {
                match (v1 >> 28) & 3 {
                    COND_ENDIF => {
                        matched = true;
                        skipped = false;
                    }
                    COND_ELSE => matched = !skipped,
                    _ if skipped => matched = false,
                    _ if condition.positive(v1, v2) => {
                        matched = true;
                        skipped = true;
                    }
                    _ => {
                        matched = false;
                        skipped = false;
                    }
                }
            }
        } else if matched {
            set(v1, v2)?;
        }
    }
    Ok(())
}

/// Register-table action for BB/AGC rows (`_rtl8821ae_config_bb_reg`):
/// addresses `0xf9..=0xfe` are delays, everything else a dword write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbAction {
    DelayUs(u32),
    Write(u32, u32),
}

/// Decode one selected PHY_REG/AGC row. Linux additionally delays 1 us after
/// every row, which the caller applies.
pub fn bb_action(addr: u32, data: u32) -> BbAction {
    match addr {
        0xfe => BbAction::DelayUs(50_000),
        0xfd => BbAction::DelayUs(5_000),
        0xfc => BbAction::DelayUs(1_000),
        0xfb => BbAction::DelayUs(50),
        0xfa => BbAction::DelayUs(5),
        0xf9 => BbAction::DelayUs(1),
        _ => BbAction::Write(addr, data),
    }
}

/// RF-A row action (`_rtl8821ae_config_rf_reg`): `0xfe`/`0xffe` are 50 ms
/// delays, otherwise a 20-bit RF register write on path A followed by 1 us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfAction {
    DelayUs(u32),
    Write(u32, u32),
}

pub fn rf_action(addr: u32, data: u32) -> RfAction {
    match addr {
        0xfe | 0xffe => RfAction::DelayUs(50_000),
        // maskforphyset = 0x1000 & 0xe000 = 0, so regaddr == addr.
        _ => RfAction::Write(addr, data & 0x000f_ffff),
    }
}
