// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE factory adapter facts.
//!
//! Mirrors Linux `rtl8192ee/hw.c::rtl92ee_read_eeprom_info`,
//! `_rtl92ee_read_chip_version`, `_rtl92ee_read_adapter_info` (through
//! `efuse.c::rtl_get_hwinfo`) and `rtl92ee_read_bt_coexist_info_from_hwpg`.
//! Inputs are the measured `REG_SYS_CFG1` / `REG_9346CR` values and the
//! retained 512-byte logical EFUSE map read at probe. Nothing is assumed:
//!
//! - `TRP_VAUX_EN` (a test chip, `VERSION_TEST_CHIP_2T2R_8192E`) is refused —
//!   no table condition or calibration is qualified for one.
//! - An EEPROM boot (`REG_9346CR` BIT4), a failed autoload (BIT5 clear) or a
//!   map without the `RTL8192E_EEPROM_ID` (`0x8129`) is unprovisioned. Linux
//!   then runs with `autoload_failflag` defaults (and `btcoexist = 1`); here
//!   no adapter facts exist, so nothing downstream can be selected for it.
//! - Every value Linux takes from the map is copied with its Linux default
//!   rule (`0xff` crystal cap ⇒ `0x20`, `0xff` board option ⇒ board type 0,
//!   `0xff` customer id ⇒ 0).

/// `REG_9346CR` (`reg.h`).
pub const REG_9346CR: u16 = 0x000a;
/// `REG_SYS_CFG1` (`reg.h`).
pub const REG_SYS_CFG1: u16 = 0x00f0;
/// `TRP_VAUX_EN` — test-chip strap in `REG_SYS_CFG1`.
pub const TRP_VAUX_EN: u32 = 1 << 23;
/// `REG_9346CR` BIT4: boot from 93C46 EEPROM instead of EFUSE.
pub const CR9346_EEPROM: u8 = 1 << 4;
/// `REG_9346CR` BIT5: autoload OK.
pub const CR9346_AUTOLOAD_OK: u8 = 1 << 5;

/// `VERSION_NORMAL_CHIP_2T2R_8192E` (`def.h`).
pub const VERSION_NORMAL_CHIP_2T2R: u16 = 0x102c;

/// `RTL8192E_EEPROM_ID`.
const EEPROM_ID: u16 = 0x8129;
const EEPROM_VID: usize = 0xd6;
const EEPROM_DID: usize = 0xd8;
const EEPROM_SVID: usize = 0xda;
const EEPROM_SMID: usize = 0xdc;
const EEPROM_MAC_ADDR: usize = 0xd0;
const EEPROM_CHANNELPLAN: usize = 0xb8;
const EEPROM_VERSION: usize = 0xc4;
const EEPROM_CUSTOMER_ID: usize = 0xc5;
pub const EEPROM_XTAL: usize = 0xb9;
pub const EEPROM_THERMAL_METER: usize = 0xba;
pub const EEPROM_IQK_LCK: usize = 0xbb;
pub const EEPROM_RF_BOARD_OPTION: usize = 0xc1;
/// `HWSET_MAX_SIZE` for 8192EE.
pub const HWSET_MAX_SIZE: usize = 512;

/// `ODM_BOARD_BT` (`rtlwifi/wifi.h`).
pub const ODM_BOARD_BT: u8 = 1 << 2;

/// `COUNTRY_CODE_WORLD_WIDE_13`, which `rtl_get_hwinfo` installs as the
/// channel plan whatever the map says.
pub const COUNTRY_CODE_WORLD_WIDE_13: u8 = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// `TRP_VAUX_EN` test chip.
    TestChip,
    /// EEPROM boot, autoload failure or missing EEPROM ID.
    Unprovisioned,
}

/// `rtlhal->oem_id` as `_rtl92ee_read_adapter_info` derives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oem {
    Default,
    /// `RT_CID_819X_LENOVO`: customer id 0, DID `0x818b`, SVID `0x10ec`,
    /// SMID `0x001b`.
    Lenovo,
}

/// Factory facts of a provisioned, normal-cut RTL8192EE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adapter {
    /// `rtlhal->version` (always `VERSION_NORMAL_CHIP_2T2R_8192E` here).
    pub version: u16,
    pub mac: [u8; 6],
    pub vid: u16,
    pub did: u16,
    pub svid: u16,
    pub smid: u16,
    /// `eeprom_channelplan` (informational: Linux overrides the plan with
    /// `COUNTRY_CODE_WORLD_WIDE_13`).
    pub eeprom_channel_plan: u8,
    pub eeprom_version: u16,
    /// `eeprom_oemid` after the `0xff` ⇒ 0 rule.
    pub customer_id: u8,
    /// `btcoexist.btc_info.btcoexist`: board option `[7:5] == 1`.
    pub bt_coexist: bool,
    /// `rtlhal->board_type` including `ODM_BOARD_BT`.
    pub board_type: u8,
    /// `rtlefuse->crystalcap` (`0xff` ⇒ `0x20`).
    pub crystal_cap: u8,
    pub oem: Oem,
}

fn le16(map: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([map[at], map[at + 1]])
}

impl Adapter {
    /// Build from measured `REG_SYS_CFG1`, `REG_9346CR` and the retained
    /// logical EFUSE map (`HWSET_MAX_SIZE` bytes).
    pub fn from_hardware(sys_cfg1: u32, cr9346: u8, logical: &[u8]) -> Result<Self, Error> {
        if sys_cfg1 & TRP_VAUX_EN != 0 {
            return Err(Error::TestChip);
        }
        if cr9346 & CR9346_EEPROM != 0
            || cr9346 & CR9346_AUTOLOAD_OK == 0
            || logical.len() < HWSET_MAX_SIZE
            || le16(logical, 0) != EEPROM_ID
        {
            return Err(Error::Unprovisioned);
        }
        let mut mac = [0; 6];
        mac.copy_from_slice(&logical[EEPROM_MAC_ADDR..EEPROM_MAC_ADDR + 6]);
        let customer_id = match logical[EEPROM_CUSTOMER_ID] {
            0xff => 0,
            v => v,
        };
        let option = logical[EEPROM_RF_BOARD_OPTION];
        // rtl92ee_read_bt_coexist_info_from_hwpg (autoload OK branch).
        let bt_coexist = (option & 0xe0) >> 5 == 1;
        let mut board_type = if option == 0xff {
            0
        } else {
            (option & 0xe0) >> 5
        };
        if bt_coexist {
            board_type |= ODM_BOARD_BT;
        }
        let crystal_cap = match logical[EEPROM_XTAL] {
            0xff => 0x20,
            v => v,
        };
        let (did, svid, smid) = (
            le16(logical, EEPROM_DID),
            le16(logical, EEPROM_SVID),
            le16(logical, EEPROM_SMID),
        );
        let oem = if customer_id == 0 && did == 0x818b && svid == 0x10ec && smid == 0x001b {
            Oem::Lenovo
        } else {
            Oem::Default
        };
        Ok(Self {
            version: VERSION_NORMAL_CHIP_2T2R,
            mac,
            vid: le16(logical, EEPROM_VID),
            did,
            svid,
            smid,
            eeprom_channel_plan: logical[EEPROM_CHANNELPLAN],
            eeprom_version: le16(logical, EEPROM_VERSION),
            customer_id,
            bt_coexist,
            board_type,
            crystal_cap,
            oem,
        })
    }
}
