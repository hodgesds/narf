// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE factory adapter facts.
//!
//! Mirrors Linux `rtl8723be/hw.c::rtl8723be_read_eeprom_info`,
//! `_rtl8723be_read_adapter_info` (through `efuse.c::rtl_get_hwinfo`),
//! `rtl8723be_read_bt_coexist_info_from_hwpg`, the non-power parts of
//! `_rtl8723be_read_txpower_info_from_hwpg` (thermal meter, regulatory) and
//! `_rtl8723be_read_package_type`. Inputs are the measured `REG_9346CR`,
//! `REG_MULTI_FUNC_CTRL`, the retained 512-byte logical EFUSE map and the
//! physical EFUSE byte `0x1fb`. Nothing is assumed:
//!
//! - An EEPROM boot (`REG_9346CR` BIT4), a failed autoload (BIT5 clear) or a
//!   map without `RTL8723BE_EEPROM_ID` (`0x8129`) is unprovisioned. Linux
//!   then skips `_rtl8723be_read_adapter_info` entirely; here no facts exist.
//! - The BT facts are exactly the autoload-OK branch:
//!   `btcoexist = REG_MULTI_FUNC_CTRL[18]`, `ant_num = map[0xc3] & 1`
//!   (`ANT_X2 = 0`, `ANT_X1 = 1`), `single_ant_path = map[0xc3][6]`
//!   (`ANT_MAIN` / `ANT_AUX`). The `ant_sel` module parameter defaults to
//!   0 (no override) and has no equivalent here.
//! - `board_type` is only `ODM_BOARD_BT` (Linux never reads an RF board
//!   option into it for this chip).

use super::version::Version;

/// `REG_9346CR` (`reg.h`).
pub const REG_9346CR: u16 = 0x000a;
/// `REG_MULTI_FUNC_CTRL` (`reg.h`).
pub const REG_MULTI_FUNC_CTRL: u16 = 0x0068;
/// `REG_MULTI_FUNC_CTRL` BIT18: BT function present.
pub const MULTI_BT_FUNC_EN: u32 = 1 << 18;
/// `REG_9346CR` BIT4: boot from 93C46 EEPROM instead of EFUSE.
pub const CR9346_EEPROM: u8 = 1 << 4;
/// `REG_9346CR` BIT5: autoload OK.
pub const CR9346_AUTOLOAD_OK: u8 = 1 << 5;
/// Physical EFUSE address `_rtl8723be_read_package_type` reads.
pub const EFUSE_PACKAGE_ADDR: u16 = 0x1fb;

/// `RTL8723BE_EEPROM_ID`.
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
pub const EEPROM_RF_BOARD_OPTION: usize = 0xc1;
pub const EEPROM_RF_BT_SETTING: usize = 0xc3;
/// `HWSET_MAX_SIZE` for 8723BE.
pub const HWSET_MAX_SIZE: usize = 512;
/// `EEPROM_DEFAULT_THERMALMETER`.
pub const DEFAULT_THERMAL_METER: u8 = 0x18;

/// `ODM_BOARD_BT` (`rtlwifi/wifi.h`).
pub const ODM_BOARD_BT: u8 = 1 << 2;

/// `EEPROM_CID_*` (`reg.h`).
const CID_DEFAULT: u8 = 0x00;
const CID_TOSHIBA: u8 = 0x04;
const CID_CCX: u8 = 0x10;
const CID_QMI: u8 = 0x0d;
const CID_WHQL: u8 = 0xfe;

const TOSHIBA_SMID1: [u16; 32] = [
    0x6151, 0x6152, 0x6154, 0x6155, 0x6177, 0x6178, 0x6179, 0x6180, 0x7151, 0x7152, 0x7154, 0x7155,
    0x7177, 0x7178, 0x7179, 0x7180, 0x8151, 0x8152, 0x8154, 0x8155, 0x8181, 0x8182, 0x8184, 0x8185,
    0x9151, 0x9152, 0x9154, 0x9155, 0x9181, 0x9182, 0x9184, 0x9185,
];
const TOSHIBA_SMID2: [u16; 15] = [
    0x6181, 0x6184, 0x6185, 0x7181, 0x7182, 0x7184, 0x7185, 0x8181, 0x8182, 0x8184, 0x8185, 0x9181,
    0x9182, 0x9184, 0x9185,
];
const SAMSUNG_SMID: [u16; 12] = [
    0x6191, 0x6192, 0x6193, 0x7191, 0x7192, 0x7193, 0x8191, 0x8192, 0x8193, 0x9191, 0x9192, 0x9193,
];
const LENOVO_SMID: [u16; 8] = [
    0x8195, 0x9195, 0x7194, 0x8200, 0x8201, 0x8202, 0x9199, 0x9200,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// EEPROM boot, autoload failure or missing EEPROM ID.
    Unprovisioned,
}

/// `btc_info.ant_num`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntNum {
    /// `ANT_X2` (0): two antennas, `halbtc8723b2ant`.
    X2,
    /// `ANT_X1` (1): one shared antenna, `halbtc8723b1ant`.
    X1,
}

/// `btc_info.single_ant_path`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntPath {
    /// `ANT_MAIN` (0).
    Main,
    /// `ANT_AUX` (1).
    Aux,
}

/// `rtlhal->oem_id` as `_rtl8723be_read_adapter_info` derives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Oem {
    Default,
    Toshiba,
    Acer,
    Samsung,
    Lenovo,
    Clevo,
    Dell,
    Hp,
    Qmi,
    Pronets,
    EdimaxAsus,
    Ccx,
}

/// `enum package_type` value `_rtl8723be_read_package_type` returns.
pub const fn package_type(efuse_0x1fb: u8) -> u8 {
    match efuse_0x1fb & 7 {
        // PACKAGE_TFBGA79, PACKAGE_TFBGA90, PACKAGE_QFN68, PACKAGE_TFBGA80.
        4 => 4,
        5 => 2,
        6 => 1,
        7 => 3,
        // PACKAGE_DEFAULT.
        _ => 0,
    }
}

/// Factory facts of a provisioned RTL8723BE.
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
    /// `rtlefuse->crystalcap` (`0xff` ⇒ `0x20`).
    pub crystal_cap: u8,
    /// `eeprom_thermalmeter` (`0xff` ⇒ `EEPROM_DEFAULT_THERMALMETER`).
    pub thermal_meter: u8,
    /// `apk_thermalmeterignore` (the `0xff` thermal case).
    pub thermal_ignore: bool,
    /// `eeprom_regulatory`: board option `[2:0]`, `0xff` ⇒ 0.
    pub regulatory: u8,
    /// `btc_info.btcoexist`.
    pub bt_coexist: bool,
    pub ant_num: AntNum,
    pub single_ant_path: AntPath,
    /// `rtlhal->board_type` (`ODM_BOARD_BT` when BT-coexist).
    pub board_type: u8,
    /// `rtlhal->package_type`.
    pub package_type: u8,
    pub oem: Oem,
}

fn le16(map: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([map[at], map[at + 1]])
}

fn oem(customer_id: u8, did: u16, svid: u16, smid: u16) -> Oem {
    match customer_id {
        CID_DEFAULT if did == 0x8176 => match (svid, smid) {
            (0x10ec, s) if TOSHIBA_SMID1.contains(&s) => Oem::Toshiba,
            (0x1025, _) => Oem::Acer,
            (0x10ec, s) if SAMSUNG_SMID.contains(&s) => Oem::Samsung,
            (0x10ec, s) if LENOVO_SMID.contains(&s) => Oem::Lenovo,
            (0x10ec, 0x8197 | 0x9196) => Oem::Clevo,
            (0x1028, 0x8194 | 0x8198 | 0x9197 | 0x9198) => Oem::Dell,
            (0x103c, 0x1629) => Oem::Hp,
            (0x1a32, 0x2315) => Oem::Qmi,
            (0x10ec, 0x8203) => Oem::Pronets,
            (0x1043, 0x84b5) => Oem::EdimaxAsus,
            _ => Oem::Default,
        },
        CID_DEFAULT if did == 0x8178 => match (svid, smid) {
            (0x10ec, s) if TOSHIBA_SMID2.contains(&s) => Oem::Toshiba,
            (0x1025, _) => Oem::Acer,
            (0x10ec, 0x8186) => Oem::Pronets,
            (0x1043, 0x84b6) => Oem::EdimaxAsus,
            _ => Oem::Default,
        },
        CID_TOSHIBA => Oem::Toshiba,
        CID_CCX => Oem::Ccx,
        CID_QMI => Oem::Qmi,
        // EEPROM_CID_WHQL leaves the default; every other id is default.
        CID_WHQL => Oem::Default,
        _ => Oem::Default,
    }
}

impl Adapter {
    /// Build from the identified version, measured `REG_9346CR` /
    /// `REG_MULTI_FUNC_CTRL`, the retained logical EFUSE map and the
    /// physical byte `0x1fb` (0 when `efuse_one_byte_read` timed out).
    pub fn from_hardware(
        version: Version,
        cr9346: u8,
        multi_func_ctrl: u32,
        logical: &[u8],
        efuse_0x1fb: u8,
    ) -> Result<Self, Error> {
        if cr9346 & CR9346_EEPROM != 0
            || cr9346 & CR9346_AUTOLOAD_OK == 0
            || logical.len() < HWSET_MAX_SIZE
            || le16(logical, 0) != EEPROM_ID
        {
            return Err(Error::Unprovisioned);
        }
        let mut mac = [0; 6];
        mac.copy_from_slice(&logical[EEPROM_MAC_ADDR..EEPROM_MAC_ADDR + 6]);
        let crystal_cap = match logical[EEPROM_XTAL] {
            0xff => 0x20,
            v => v,
        };
        let (thermal_meter, thermal_ignore) = match logical[EEPROM_THERMAL_METER] {
            0xff => (DEFAULT_THERMAL_METER, true),
            v => (v, false),
        };
        let regulatory = match logical[EEPROM_RF_BOARD_OPTION] {
            0xff => 0,
            v => v & 0x07,
        };
        // rtl8723be_read_bt_coexist_info_from_hwpg (autoload OK branch).
        let bt_coexist = multi_func_ctrl & MULTI_BT_FUNC_EN != 0;
        let setting = logical[EEPROM_RF_BT_SETTING];
        let ant_num = if setting & 1 != 0 {
            AntNum::X1
        } else {
            AntNum::X2
        };
        let single_ant_path = if setting & 0x40 != 0 {
            AntPath::Aux
        } else {
            AntPath::Main
        };
        let board_type = if bt_coexist { ODM_BOARD_BT } else { 0 };
        let customer_id = logical[EEPROM_CUSTOMER_ID];
        let (did, svid, smid) = (
            le16(logical, EEPROM_DID),
            le16(logical, EEPROM_SVID),
            le16(logical, EEPROM_SMID),
        );
        Ok(Self {
            version,
            mac,
            vid: le16(logical, EEPROM_VID),
            did,
            svid,
            smid,
            eeprom_channel_plan: logical[EEPROM_CHANNELPLAN],
            eeprom_version: le16(logical, EEPROM_VERSION),
            customer_id,
            crystal_cap,
            thermal_meter,
            thermal_ignore,
            regulatory,
            bt_coexist,
            ant_num,
            single_ant_path,
            board_type,
            package_type: package_type(efuse_0x1fb),
            oem: oem(customer_id, did, svid, smid),
        })
    }
}
