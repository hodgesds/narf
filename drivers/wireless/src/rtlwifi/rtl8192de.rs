// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE (`rtl8192de` + `rtl8192d` common) retained runtime, in progress.
//!
//! RTL8192DE (PCI `0x8193`) is the dual-band dual-MAC 802.11n part: one chip
//! exposing two PCI functions (MAC0 / MAC1) that share one PHY/RF block.
//! This module is step 1 of the `rtl8192de` TSV row: the per-function
//! ownership model — how Linux selects the MAC/PHY mode from EFUSE, what
//! each mode programs, which band each function runs, and which register
//! tables each function/band/PA combination loads. Step 2 adds the
//! firmware image + paged download ([`fw`]), the signed per-board
//! power envelope ([`envelope`], 2.4 GHz only), the chip's own TX/RX
//! descriptors ([`trx`]) and the packet owner ([`packet`]). Step 3 adds
//! the power-on sequence ([`power`]), the LLT ([`llt`]) and MAC init
//! ([`mac`]). Step 4 adds the station chains ([`station`], the rate
//! table [`rate`], the H2C mailbox [`h2c`], the reserved-page packet
//! [`rsvd_page`]), bands/HT/QoS/lifecycle
//! ([`channel`], [`lifecycle`]), the TX-power levels ([`txpower`]) and
//! the DE factory table ([`phy::PgStore`]) plus the BB/RF access they
//! need ([`phy`]). Step 5 adds the 5 GHz envelope rows (NAPC v3) and
//! the 2SS HT rates ([`ht`]). Step 6 adds the DM init ([`dm`]), the
//! `rtl92de_hw_init` early-mode / ASPM back-door / hardware-security
//! steps ([`mac`]), the IQK reload ([`calib`], wired into the
//! channel switch), and the 5 GHz native-admission gate
//! ([`native_channel`]). It is not admitted yet (probe keeps it diagnostic); the
//! `Prepared` integration and the production `rtl92de_hw_init`
//! orchestrator are remainders.
//!
//! Per-function EFUSE identity already lives in-tree: `efuse.rs` maps
//! function 0 / 1 to MAC offsets `0x55` / `0x5b` (497 physical bytes, 256
//! logical); this module does not duplicate that mapping.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8192d/{def,reg,hw_common,phy_common}.{c,h}`
//! - `rtlwifi/rtl8192de/{sw,phy,table}.{c,h}`
//! - Linux `wifi.h` `macphy_mode` / `band_type` enums
//!
//! ## Modules
//!
//! - [`tables`] — the 10 Linux `table.c` arrays, generated verbatim
//!   (`gen_tables.py` + independent `check_tables.py`, 0 failures).
//! - [`fw`] — the firmware image, header parse and paged download.
//! - [`envelope`] — the signed per-board power envelope (NAPC).
//! - [`trx`] — the chip's own TX/RX descriptors.
//! - [`packet`] — the packet owner (TX fill + RX decode).
//! - [`power`] — power-on: `rtl92d_phy_set_poweron` + the
//!   `_rtl92de_init_mac` power prefix through `REG_CR = 0x2ff`.
//! - [`llt`] — the LLT table init (`_rtl92de_llt_table_init`).
//! - [`mac`] — MAC init (`_rtl92de_init_mac` after the LLT),
//!   `_rtl92de_hw_configure`, interrupt control, CAM reset and the
//!   station identity.
//! - [`station`] — station chains: network type / media status,
//!   check-BSSID, BSSID, basic rate, AID, beacon registers, interrupt
//!   mask, suspend/resume, and the `set_hw_reg` / `get_hw_reg` cases.
//! - [`rate`] — the station rate table (`REG_ARFR0`).
//! - [`ht`] — the HT station profile: MCS8-15 two-stream admission
//!   (`two_stream`), gated on the envelope permission and `RF_2T2R`.
//! - [`h2c`] — the host-to-firmware mailbox + join-bss report.
//! - [`channel`] — bands, channel switching, bandwidth mode, the
//!   BB/RF band-switch configuration.
//! - [`phy`] — BB/RF register access, the RF 3-wire serial path, the
//!   DBI cross-function path, and the factory power-group table.
//! - [`txpower`] — TX-power levels from the EFUSE factory map.
//! - [`lifecycle`] — `init_sw_vars` / `deinit_sw_vars` / ASPM state.
//! - [`dm`] — DM init (`rtl92d_dm_init`): DIG table, dynamic TX
//!   power, EDCA turbo, rate-adaptive mask, TX-power tracking.
//! - [`calib`] — IQK calibration reload
//!   (`rtl92d_phy_reload_iqk_setting`) with the stored per-channel
//!   matrix.

#![allow(dead_code)]

pub mod calib;
pub mod channel;
pub mod dm;
pub mod envelope;
pub mod fw;
pub mod h2c;
pub mod ht;
pub mod init;
pub mod lifecycle;
pub mod llt;
pub mod mac;
pub mod packet;
pub mod phy;
pub mod power;
pub mod rate;
pub mod rsvd_page;
pub mod station;
pub mod tables;
pub mod trx;
pub mod txpower;
pub mod version;

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests;

/// PCI device ID (Linux `pci.h` `RTL_PCI_8192DE_DID`).
pub const DEV_ID: u16 = super::regs::RTL_DEV_8192DE;

/// Firmware image name (Linux `rtl8192de/sw.c` `rtl92d_init_sw_vars`).
pub const FW_NAME: &str = "rtlwifi/rtl8192defw.bin";

/// EFUSE offset selecting single- vs dual-MAC on PCI
/// (Linux `rtl8192d/reg.h` `EEPROM_MAC_FUNCTION`).
pub const EEPROM_MAC_FUNCTION: usize = 0x08;

/// EFUSE offset selecting single- vs dual-MAC on USB
/// (Linux `rtl8192d/reg.h` `EEPROM_ENDPOINT_SETTING`).
pub const EEPROM_ENDPOINT_SETTING: usize = 0x10;

/// MAC/PHY control register
/// (Linux `rtl8192d/reg.h` `REG_MAC_PHY_CTRL_NORMAL`).
pub const REG_MAC_PHY_CTRL_NORMAL: u16 = 0x00f8;

/// Base PHY-control value on PCI
/// (Linux `rtl8192d/phy_common.c` `rtl92d_phy_config_macphymode`).
pub const PHY_CTRL_BASE: u8 = 0xf0;

/// MAC/PHY mode (Linux `wifi.h` `macphy_mode`, values in order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacPhyMode {
    /// One MAC, one PHY.
    SingleMacSinglePhy = 0,
    /// Two MACs, two PHYs (the dual-MAC case).
    DualMacDualPhy = 1,
    /// Two MACs, one PHY (enumerated but never selected by the PROM read).
    DualMacSinglePhy = 2,
}

/// Bus interface, selecting which PROM byte decides the mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    Pci,
    Usb,
}

/// MAC/PHY mode from the EFUSE/PROM image, exactly Linux's
/// `_rtl92d_read_macphymode_from_prom` (`rtl8192d/hw_common.c`):
/// PCI reads `EEPROM_MAC_FUNCTION` bit 3 (set = single MAC); USB reads
/// `EEPROM_ENDPOINT_SETTING` bit 0 (clear = single MAC). `None` when the
/// image is too short to hold the deciding byte.
pub fn mode_from_prom(interface: Interface, prom: &[u8]) -> Option<MacPhyMode> {
    let (offset, invert) = match interface {
        Interface::Pci => (EEPROM_MAC_FUNCTION, false),
        Interface::Usb => (EEPROM_ENDPOINT_SETTING, true),
    };
    let byte = *prom.get(offset)?;
    let is_single = if invert {
        byte & 0x01 == 0
    } else {
        byte & 0x08 != 0
    };
    Some(if is_single {
        MacPhyMode::SingleMacSinglePhy
    } else {
        MacPhyMode::DualMacDualPhy
    })
}

/// PHY-control register word for a mode on PCI: base `0xf0` plus the
/// mode bits (Linux `rtl92d_phy_config_macphymode`).
pub fn phy_ctrl_word_pci(mode: MacPhyMode) -> u8 {
    PHY_CTRL_BASE | phy_ctrl_mode_bits(mode)
}

/// PHY-control register word for a mode on USB: the current register
/// value with bits 0–2 cleared, plus the mode bits (Linux reads the
/// register first on USB; on PCI it starts from the `0xf0` base).
pub fn phy_ctrl_word_usb(mode: MacPhyMode, current: u8) -> u8 {
    (current & !0x07) | phy_ctrl_mode_bits(mode)
}

fn phy_ctrl_mode_bits(mode: MacPhyMode) -> u8 {
    match mode {
        MacPhyMode::DualMacDualPhy => 0x03,
        MacPhyMode::SingleMacSinglePhy => 0x04,
        MacPhyMode::DualMacSinglePhy => 0x01,
    }
}

/// RF chain width selected by a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfType {
    OneT1R,
    TwoT2R,
}

/// A single operating band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    On2Ghz,
    On5Ghz,
}

/// The band set a function may use (Linux `band_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandSet {
    On2Ghz,
    On5Ghz,
    OnBoth,
}

/// What a mode implies for a function (Linux
/// `rtl92d_phy_config_macphymode_info`): single and dual-single modes
/// are 2T2R on both bands starting at 2.4 GHz; dual-dual is 1T1R with
/// MAC0 (interface index 0) on 5 GHz and every other function on 2.4 GHz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeInfo {
    pub rf_type: RfType,
    pub bandset: BandSet,
    pub current_band: Band,
}

pub fn mode_info(mode: MacPhyMode, interface_index: u8) -> ModeInfo {
    match mode {
        MacPhyMode::SingleMacSinglePhy | MacPhyMode::DualMacSinglePhy => ModeInfo {
            rf_type: RfType::TwoT2R,
            bandset: BandSet::OnBoth,
            current_band: Band::On2Ghz,
        },
        MacPhyMode::DualMacDualPhy => {
            if interface_index == 0 {
                ModeInfo {
                    rf_type: RfType::OneT1R,
                    bandset: BandSet::On5Ghz,
                    current_band: Band::On5Ghz,
                }
            } else {
                ModeInfo {
                    rf_type: RfType::OneT1R,
                    bandset: BandSet::On2Ghz,
                    current_band: Band::On2Ghz,
                }
            }
        }
    }
}

/// AMPDU-factor base word per mode (Linux `rtl8192d/hw_common.c`
/// `HW_VAR_AMPDU_FACTOR`).
pub fn ampdu_factor_base(mode: MacPhyMode) -> u32 {
    match mode {
        MacPhyMode::DualMacDualPhy => 0xb9726641,
        MacPhyMode::DualMacSinglePhy => 0x66626641,
        MacPhyMode::SingleMacSinglePhy => 0xb972a841,
    }
}

/// `rtl92d_init_sw_vars` consequences of the mode plus the current band:
/// non-single modes disable 8K A-MSDU (`disable_amsdu_8k`, the spec's
/// "MAX_AMSDU cleared only for RTL8192DE dual-MAC") and cap the RX
/// buffer at 4096 bytes; single mode leaves both untouched (`None`).
/// The default channel is 36 on 5 GHz, 1 otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwConsequences {
    pub disable_amsdu_8k: bool,
    pub rxbuffersize: Option<u32>,
    pub default_channel: u8,
}

pub fn sw_consequences(mode: MacPhyMode, current_band: Band) -> SwConsequences {
    let default_channel = match current_band {
        Band::On5Ghz => 36,
        Band::On2Ghz => 1,
    };
    match mode {
        MacPhyMode::SingleMacSinglePhy => SwConsequences {
            disable_amsdu_8k: false,
            rxbuffersize: None,
            default_channel,
        },
        _ => SwConsequences {
            disable_amsdu_8k: true,
            rxbuffersize: Some(4096),
            default_channel,
        },
    }
}

/// Whether `channel` is natively admittable for one function: the
/// channel must be a station channel
/// ([`envelope::station_channel`]) and inside the function's bandset
/// ([`mode_info`]). A dual-dual MAC0 function (5 GHz bandset) admits
/// the 5 GHz plan and no 2.4 GHz channel; a dual-dual MAC1 function
/// admits 2.4 GHz channels 1–11 and no 5 GHz channel; single and
/// dual-single functions admit both bands. This is the gate the
/// future `prepare_rtl8192de` native entry calls, mirroring
/// `prepare_rtl8821ae`'s `station_channel` check; the entry itself
/// (and the `Prepared::Chip::Rtl8192de` integration it needs) is a
/// later step.
pub fn native_channel(channel: u8, mode: MacPhyMode, interface_index: u8) -> bool {
    if !envelope::station_channel(channel) {
        return false;
    }
    match mode_info(mode, interface_index).bandset {
        BandSet::On2Ghz => channel <= 14,
        BandSet::On5Ghz => channel >= 36,
        BandSet::OnBoth => true,
    }
}

/// `REG_MAX_AGGR_NUM` per mode (Linux `_rtl92d_phy_config_mac`):
/// single MAC writes `0x0B`, any dual mode writes `0x07`.
pub fn max_aggr_num(mode: MacPhyMode) -> u8 {
    match mode {
        MacPhyMode::SingleMacSinglePhy => 0x0b,
        _ => 0x07,
    }
}

/// AGC table for a function (Linux `_rtl92d_phy_config_bb_with_headerfile`):
/// MAC0 (interface index 0) always uses the combined table for both bands;
/// MAC1 uses the 2G table on 2.4 GHz and the 5G table otherwise.
pub fn agc_table(interface_index: u8, current_band: Band) -> &'static [u32] {
    if interface_index == 0 {
        &tables::AGCTAB
    } else {
        match current_band {
            Band::On2Ghz => &tables::AGCTAB_2G,
            Band::On5Ghz => &tables::AGCTAB_5G,
        }
    }
}

/// RF tables for a function (Linux `_rtl92d_phy_config_rf_with_headerfile`):
/// the plain 2T tables by default; per-path internal-PA tables when
/// `internal_pa_5g[path]` is set from EFUSE.
pub fn radio_tables(internal_pa_5g: [bool; 2]) -> (&'static [u32], &'static [u32]) {
    let a = if internal_pa_5g[0] {
        &tables::RADIOA_2T_INT_PA[..]
    } else {
        &tables::RADIOA_2T[..]
    };
    let b = if internal_pa_5g[1] {
        &tables::RADIOB_2T_INT_PA[..]
    } else {
        &tables::RADIOB_2T[..]
    };
    (a, b)
}

/// Which RF content a table load carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfContent {
    RadioATxt,
    RadioBTxt,
}

/// Which RF path a table load targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RfPath {
    A,
    B,
}

/// The DMDP swap (Linux `_rtl92d_phy_config_rf_with_headerfile`): when a
/// radio-B text load targets path A — the case where MAC0 starts on
/// 2.4 GHz and MAC1 on 5 GHz — path A loads the radio-B table instead.
pub fn dmdp_swapped(content: RfContent, path: RfPath) -> bool {
    content == RfContent::RadioBTxt && path == RfPath::A
}

/// The MAC table, applied unconditionally (Linux `_rtl92d_phy_config_mac`).
pub fn mac_table() -> &'static [u32] {
    &tables::MAC_2T
}

/// The PHY register table, applied unconditionally
/// (Linux `_rtl92d_phy_config_bb_with_headerfile`).
pub fn phy_reg_table() -> &'static [u32] {
    &tables::PHY_REG_2T
}

/// The PHY register power-group table, applied unconditionally.
pub fn phy_reg_pg_table() -> &'static [u32] {
    &tables::PHY_REG_PG
}
