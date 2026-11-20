// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE factory adapter facts.
//!
//! Mirrors Linux `rtl8723ae/hw.c::rtl8723e_read_eeprom_info`,
//! `_rtl8723e_read_adapter_info` (through `efuse.c::rtl_get_hwinfo` with the
//! 8723AE `params[]`), `rtl8723e_read_bt_coexist_info_from_hwpg` /
//! `rtl8723e_bt_var_init` and the OEM rule. Inputs are the qualified
//! [`Version`], the measured `REG_9346CR` and `REG_MULTI_FUNC_CTRL` and the
//! retained logical EFUSE map (`HWSET_MAX_SIZE` = 256). Nothing is assumed:
//!
//! - An EEPROM boot (`REG_9346CR` BIT4), a failed autoload (BIT5 clear) or a
//!   map without `RTL8190_EEPROM_ID` (`0x8129`) is unprovisioned. For the
//!   last case `rtl_get_hwinfo` returns 1 and Linux skips the TX-power and BT
//!   reads entirely; here no adapter facts exist.
//! - The retained map is kept verbatim for the TX-power decode
//!   (`_rtl8723e_read_txpower_info_from_hwpg`, [`super::txpower`]).
//! - `rtl8723e_read_eeprom_info` first selects the Wi-Fi EFUSE bank
//!   (`REG_EFUSE_TEST[9:8] = EFUSE_WIFI_SEL_0`); [`efuse_test_wifi_sel`] is
//!   that value, written by probe before the map read.

use super::version::Version;

/// `REG_9346CR` (`reg.h`).
pub const REG_9346CR: u16 = 0x000a;
/// `REG_EFUSE_TEST` (`reg.h`).
pub const REG_EFUSE_TEST: u16 = 0x0034;
/// `EFUSE_SEL_MASK` (`efuse.h`, bits 9:8).
pub const EFUSE_SEL_MASK: u32 = 0x0300;
/// `(value & ~EFUSE_SEL_MASK) | EFUSE_SEL(EFUSE_WIFI_SEL_0)`.
pub const fn efuse_test_wifi_sel(value: u32) -> u32 {
    value & !EFUSE_SEL_MASK
}
/// `REG_MULTI_FUNC_CTRL` BIT18: BT function present.
pub const MULTI_BT_FUNC_EN: u32 = 1 << 18;
/// `REG_9346CR` BIT4: boot from 93C46 EEPROM instead of EFUSE.
pub const CR9346_EEPROM: u8 = 1 << 4;
/// `REG_9346CR` BIT5: autoload OK.
pub const CR9346_AUTOLOAD_OK: u8 = 1 << 5;

/// `HWSET_MAX_SIZE` (`rtl8723ae/reg.h`).
pub const HWSET_MAX_SIZE: usize = 256;
/// `RTL8190_EEPROM_ID`.
const EEPROM_ID: u16 = 0x8129;
const EEPROM_VID: usize = 0x49;
const EEPROM_DID: usize = 0x4b;
const EEPROM_SVID: usize = 0x4d;
const EEPROM_SMID: usize = 0x4f;
pub const EEPROM_MAC_ADDR: usize = 0x67;
const EEPROM_CHANNELPLAN: usize = 0x28;
const EEPROM_VERSION: usize = 0x30;
const EEPROM_CUSTOMER_ID: usize = 0x31;
/// `RF_OPTION1` / `RF_OPTION4` (`reg.h`).
pub const RF_OPTION1: usize = 0x2b;
pub const RF_OPTION4: usize = 0x2e;

/// `EEPROM_CID_*` (`reg.h`).
const CID_DEFAULT: u8 = 0x00;
const CID_TOSHIBA: u8 = 0x04;
const CID_CCX: u8 = 0x10;
const CID_QMI: u8 = 0x0d;

/// `BT_RTL8723A` (`wifi.h` `enum bt_co_type`), `eeprom_bt_type`.
pub const BT_RTL8723A: u8 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// EEPROM boot, autoload failure or missing EEPROM ID.
    Unprovisioned,
}

/// `btcoexist.bt_ant_num` (`ANT_X2 = 0`, `ANT_X1 = 1`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntNum {
    X2,
    X1,
}

/// `rtl8723e_read_bt_coexist_info_from_hwpg` (autoload-OK branch) after
/// `rtl8723e_bt_var_init` copies the `eeprom_bt_*` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BtInfo {
    /// `bt_coexistence` = `REG_MULTI_FUNC_CTRL[18]`.
    pub coexistence: bool,
    /// `bt_coexist_type` = `BT_RTL8723A`.
    pub kind: u8,
    /// `bt_ant_num` = `RF_OPTION4[0]`.
    pub ant_num: AntNum,
    /// `bt_ant_isolation` = `RF_OPTION4[4]`.
    pub ant_isolation: u8,
    /// `bt_radio_shared_type` = `RF_OPTION4[5]`.
    pub radio_shared: u8,
}

/// `rtlhal->oem_id` as `_rtl8723e_read_adapter_info` derives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oem {
    Default,
    Toshiba,
    Samsung,
    Clevo,
    Pronets,
    Lenovo,
    Acer,
    Dell,
    Hp,
    Qmi,
    EdimaxAsus,
    Ccx,
}

/// Factory facts of a provisioned, qualified RTL8723AE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adapter {
    pub version: Version,
    pub mac: [u8; 6],
    pub vid: u16,
    pub did: u16,
    pub svid: u16,
    pub smid: u16,
    /// `eeprom_channelplan` (informational: `rtl_get_hwinfo` installs
    /// `COUNTRY_CODE_WORLD_WIDE_13`).
    pub eeprom_channel_plan: u8,
    pub eeprom_version: u16,
    /// `eeprom_oemid`.
    pub customer_id: u8,
    pub bt: BtInfo,
    pub oem: Oem,
    /// The verbatim `hwinfo` map for the TX-power decode.
    pub hwinfo: [u8; HWSET_MAX_SIZE],
}

fn le16(map: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([map[at], map[at + 1]])
}

const fn in_ranges(value: u16, ranges: &[(u16, u16)]) -> bool {
    let mut i = 0;
    while i < ranges.len() {
        if value >= ranges[i].0 && value <= ranges[i].1 {
            return true;
        }
        i += 1;
    }
    false
}

/// `_rtl8723e_read_adapter_info` `switch (rtlefuse->eeprom_oemid)`.
pub fn oem(customer_id: u8, did: u16, svid: u16, smid: u16) -> Oem {
    const TOSHIBA_8176: &[(u16, u16)] = &[
        (0x6151, 0x6152),
        (0x6154, 0x6155),
        (0x6177, 0x6180),
        (0x7151, 0x7152),
        (0x7154, 0x7155),
        (0x7177, 0x7180),
        (0x8151, 0x8152),
        (0x8154, 0x8155),
        (0x8181, 0x8182),
        (0x8184, 0x8185),
        (0x9151, 0x9152),
        (0x9154, 0x9155),
        (0x9181, 0x9182),
        (0x9184, 0x9185),
    ];
    const SAMSUNG_8176: &[(u16, u16)] = &[
        (0x6191, 0x6193),
        (0x7191, 0x7193),
        (0x8191, 0x8193),
        (0x9191, 0x9193),
    ];
    const LENOVO_8176: &[(u16, u16)] = &[
        (0x8195, 0x8195),
        (0x9195, 0x9195),
        (0x7194, 0x7194),
        (0x8200, 0x8202),
        (0x9200, 0x9200),
    ];
    const TOSHIBA_8178: &[(u16, u16)] = &[
        (0x6181, 0x6182),
        (0x6184, 0x6185),
        (0x7181, 0x7182),
        (0x7184, 0x7185),
        (0x8181, 0x8182),
        (0x8184, 0x8185),
        (0x9181, 0x9182),
        (0x9184, 0x9185),
    ];
    match customer_id {
        CID_DEFAULT => match (did, svid) {
            (0x8176, 0x10ec) if in_ranges(smid, TOSHIBA_8176) => Oem::Toshiba,
            (0x8176, 0x10ec) if in_ranges(smid, SAMSUNG_8176) => Oem::Samsung,
            (0x8176, 0x10ec) if matches!(smid, 0x8197 | 0x9196) => Oem::Clevo,
            (0x8176, 0x10ec) if smid == 0x8203 => Oem::Pronets,
            (0x8176, 0x10ec) if in_ranges(smid, LENOVO_8176) => Oem::Lenovo,
            (0x8176, 0x1025) => Oem::Acer,
            (0x8176, 0x1028) if matches!(smid, 0x8194 | 0x8198 | 0x9197 | 0x9198) => Oem::Dell,
            (0x8176, 0x103c) if smid == 0x1629 => Oem::Hp,
            (0x8176, 0x1a32) if smid == 0x2315 => Oem::Qmi,
            (0x8176, 0x1043) if smid == 0x84b5 => Oem::EdimaxAsus,
            (0x8178, 0x10ec) if in_ranges(smid, TOSHIBA_8178) => Oem::Toshiba,
            (0x8178, 0x10ec) if smid == 0x8186 => Oem::Pronets,
            (0x8178, 0x1025) => Oem::Acer,
            (0x8178, 0x1043) if smid == 0x8486 => Oem::EdimaxAsus,
            _ => Oem::Default,
        },
        CID_TOSHIBA => Oem::Toshiba,
        CID_CCX => Oem::Ccx,
        CID_QMI => Oem::Qmi,
        // EEPROM_CID_WHQL leaves the default; every other id is default.
        _ => Oem::Default,
    }
}

impl Adapter {
    /// Build from the qualified version, measured `REG_9346CR` /
    /// `REG_MULTI_FUNC_CTRL` and the retained logical EFUSE map (at least
    /// `HWSET_MAX_SIZE` bytes).
    pub fn from_hardware(
        version: Version,
        cr9346: u8,
        multi_func_ctrl: u32,
        logical: &[u8],
    ) -> Result<Self, Error> {
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
            coexistence: multi_func_ctrl & MULTI_BT_FUNC_EN != 0,
            kind: BT_RTL8723A,
            ant_num: if option4 & 1 != 0 {
                AntNum::X1
            } else {
                AntNum::X2
            },
            ant_isolation: (option4 & 0x10) >> 4,
            radio_shared: (option4 & 0x20) >> 5,
        };
        let (did, svid, smid) = (
            le16(&hwinfo, EEPROM_DID),
            le16(&hwinfo, EEPROM_SVID),
            le16(&hwinfo, EEPROM_SMID),
        );
        let customer_id = hwinfo[EEPROM_CUSTOMER_ID];
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
            oem: oem(customer_id, did, svid, smid),
            hwinfo,
        })
    }
}
