// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE factory adapter facts.
//!
//! Mirrors Linux `rtl8192ce/hw.c::rtl92ce_read_eeprom_info`,
//! `_rtl92ce_read_adapter_info` (through `efuse.c::rtl_get_hwinfo` with the
//! 92CE `params[]`), `rtl8192ce_read_bt_coexist_info_from_hwpg` and the OEM
//! rule. Inputs are the qualified chip [`Version`], the measured
//! `REG_9346CR` and the retained logical EFUSE map (`HWSET_MAX_SIZE` = 128
//! bytes for this family). Nothing is assumed:
//!
//! - An EEPROM boot (`REG_9346CR` BIT4), a failed autoload (BIT5 clear) or a
//!   map without `RTL8190_EEPROM_ID` (`0x8129`) is unprovisioned. Linux then
//!   runs with `autoload_failflag` defaults; here no adapter facts exist, so
//!   nothing downstream (TX power, tables, RF) can be selected for it.
//! - The retained map is kept verbatim for the TX-power decode
//!   (`_rtl92ce_read_txpower_info_from_hwpg`), which applies its own `0xff`
//!   default rules per field.

use super::version::Version;

/// `REG_9346CR` (`reg.h`).
pub const REG_9346CR: u16 = 0x000a;
/// `REG_9346CR` BIT4: boot from 93C46 EEPROM instead of EFUSE.
pub const CR9346_EEPROM: u8 = 1 << 4;
/// `REG_9346CR` BIT5: autoload OK.
pub const CR9346_AUTOLOAD_OK: u8 = 1 << 5;

/// `HWSET_MAX_SIZE` (`rtl8192ce/reg.h`).
pub const HWSET_MAX_SIZE: usize = 128;
/// `RTL8190_EEPROM_ID`.
const EEPROM_ID: u16 = 0x8129;
const EEPROM_VID: usize = 0x0a;
const EEPROM_DID: usize = 0x0c;
const EEPROM_SVID: usize = 0x0e;
const EEPROM_SMID: usize = 0x10;
const EEPROM_MAC_ADDR: usize = 0x16;
/// `EEPROM_CHANNELPLAN` (the `params[]` entry; not `EEPROM_CHANNEL_PLAN`).
const EEPROM_CHANNELPLAN: usize = 0x75;
const EEPROM_VERSION: usize = 0x7e;
const EEPROM_CUSTOMER_ID: usize = 0x7f;
/// `RF_OPTION1` / `RF_OPTION4`.
pub const RF_OPTION1: usize = 0x79;
pub const RF_OPTION4: usize = 0x7c;

/// `COUNTRY_CODE_WORLD_WIDE_13`, which `rtl_get_hwinfo` installs as the
/// channel plan whatever the map says.
pub const COUNTRY_CODE_WORLD_WIDE_13: u8 = 11;

/// `EEPROM_CID_*` (`reg.h`).
const EEPROM_CID_DEFAULT: u8 = 0x00;
const EEPROM_CID_TOSHIBA: u8 = 0x04;
const EEPROM_CID_QMI: u8 = 0x0d;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// EEPROM boot, autoload failure or missing EEPROM ID.
    Unprovisioned,
}

/// `rtlhal->oem_id` as `_rtl92ce_read_adapter_info` derives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oem {
    Default,
    /// `RT_CID_819X_HP`: customer id default, DID `0x8176`, SVID `0x103c`,
    /// SMID `0x1629` (`_rtl92ce_hal_customized_behavior` sets LED open-drain).
    Hp,
    /// `RT_CID_TOSHIBA`.
    Toshiba,
    /// `RT_CID_819X_QMI`.
    Qmi,
}

/// `rtl8192ce_read_bt_coexist_info_from_hwpg` (autoload-OK branch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtInfo {
    /// `eeprom_bt_coexist` = `RF_OPTION1[7:5]`; Linux uses it as the
    /// `bt_coexistence` boolean (non-zero ⇒ coexistence code paths).
    pub coexist: u8,
    /// `eeprom_bt_type` = `RF_OPTION4[3:1]`.
    pub kind: u8,
    /// `eeprom_bt_ant_num` = `RF_OPTION4[0]`.
    pub ant_num: u8,
    /// `eeprom_bt_ant_isol` = `RF_OPTION4[4]`.
    pub ant_isolation: u8,
    /// `eeprom_bt_radio_shared` = `RF_OPTION4[5]`.
    pub radio_shared: u8,
}

/// Factory facts of a provisioned, qualified RTL8192CE-family adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adapter {
    pub version: Version,
    pub mac: [u8; 6],
    pub vid: u16,
    pub did: u16,
    pub svid: u16,
    pub smid: u16,
    /// `eeprom_channelplan` (informational: Linux overrides the plan with
    /// `COUNTRY_CODE_WORLD_WIDE_13`).
    pub eeprom_channel_plan: u8,
    pub eeprom_version: u16,
    /// `eeprom_oemid` (no `0xff` rule in this driver).
    pub customer_id: u8,
    pub bt: BtInfo,
    pub oem: Oem,
    /// The verbatim `hwinfo` map for the TX-power decode.
    pub hwinfo: [u8; HWSET_MAX_SIZE],
}

fn le16(map: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([map[at], map[at + 1]])
}

impl Adapter {
    /// Build from the qualified version, measured `REG_9346CR` and the
    /// retained logical EFUSE map (at least `HWSET_MAX_SIZE` bytes).
    pub fn from_hardware(version: Version, cr9346: u8, logical: &[u8]) -> Result<Self, Error> {
        if cr9346 & CR9346_EEPROM != 0
            || cr9346 & CR9346_AUTOLOAD_OK == 0
            || logical.len() < HWSET_MAX_SIZE
            || le16(logical, 0) != EEPROM_ID
        {
            return Err(Error::Unprovisioned);
        }
        let mut hwinfo = [0; HWSET_MAX_SIZE];
        hwinfo.copy_from_slice(&logical[..HWSET_MAX_SIZE]);
        let mut mac = [0; 6];
        mac.copy_from_slice(&hwinfo[EEPROM_MAC_ADDR..EEPROM_MAC_ADDR + 6]);
        let option4 = hwinfo[RF_OPTION4];
        let bt = BtInfo {
            coexist: (hwinfo[RF_OPTION1] & 0xe0) >> 5,
            kind: (option4 & 0x0e) >> 1,
            ant_num: option4 & 0x01,
            ant_isolation: (option4 & 0x10) >> 4,
            radio_shared: (option4 & 0x20) >> 5,
        };
        let (did, svid, smid) = (
            le16(&hwinfo, EEPROM_DID),
            le16(&hwinfo, EEPROM_SVID),
            le16(&hwinfo, EEPROM_SMID),
        );
        let customer_id = hwinfo[EEPROM_CUSTOMER_ID];
        let oem = match customer_id {
            EEPROM_CID_DEFAULT if did == 0x8176 && svid == 0x103c && smid == 0x1629 => Oem::Hp,
            EEPROM_CID_TOSHIBA => Oem::Toshiba,
            EEPROM_CID_QMI => Oem::Qmi,
            _ => Oem::Default,
        };
        Ok(Self {
            version,
            mac,
            vid: le16(&hwinfo, EEPROM_VID),
            did,
            svid,
            smid,
            eeprom_channel_plan: hwinfo[EEPROM_CHANNELPLAN],
            eeprom_version: le16(&hwinfo, EEPROM_VERSION),
            customer_id,
            bt,
            oem,
            hwinfo,
        })
    }

    /// `rtlpriv->btcoexist.bt_coexistence` after `rtl8192ce_bt_var_init`.
    pub const fn bt_coexistence(&self) -> bool {
        self.bt.coexist != 0
    }
}
