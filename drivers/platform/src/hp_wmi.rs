// SPDX-License-Identifier: GPL-2.0-or-later
//! HP WMI platform driver.
//!
//! Covers the HP-specific WMI surface for EliteBook, Spectre, Pavilion,
//! and Omen laptop families.
//!
//! ## Features
//!
//! - WMI GUID `5FB7F034-2C63-45E9-BE91-3D44E2C707E4` (HP BIOS WMI)
//! - WMI GUID `95F24279-4D7B-4334-9387-ACCDC67EF61C` (HP event GUID)
//! - Hotkey decode: HP hotkey codes → KEY_* mapping (0x270 is the
//!   distinct `KEY_MICMUTE`, not speaker mute)
//! - The full `hp_wmi_perform_query` BIOS conversation: `bios_args`
//!   buffer in, `bios_return` + payload out, method id selected by
//!   output size (`encode_outsize_for_pvsz`)
//! - Wireless state as rfkill state: the rfkill1 wireless word and
//!   the rfkill2 device table are refreshed from firmware and
//!   published through `crate::rfkill`; software block drives the
//!   firmware radio switch (wireless WRITE)
//! - Thermal profile get/set via the thermal-profile query, plus
//!   the OMEN/Victus GM performance-mode commands
//! - Platform-profile backend (`hp-wmi`) for
//!   `/sys/firmware/acpi/platform_profile`
//! - Fn-P hotkey cycles the platform profile
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/platform/x86/hp/hp-wmi.c`
//!   - `hp_wmi_notify()` — event dispatch.
//!   - `hp_wmi_perform_query()` / `encode_outsize_for_pvsz()` —
//!     BIOS query conversation (verified against the file).
//!   - `struct bios_args` / `struct bios_return` /
//!     `enum hp_wmi_commandtype` / `enum hp_wmi_command`.
//!   - `hp_wmi_set_block()` / `hp_wmi_get_sw_state()` /
//!     `hp_wmi_get_hw_state()` — rfkill1 wireless word layout.
//!   - `struct bios_rfkill2_state` / `hp_wmi_rfkill2_refresh()` —
//!     rfkill2 device table (128-byte buffer, 7 devices).
//!   - OMEN/Victus GM commands (`HPWMI_GM`, `HPWMI_SET_PERFORMANCE_MODE`)
//!     from the hp-wmi platform-profile series.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_input::{push_key, KeyCode};

// ── HP WMI GUIDs ─────────────────────────────────────────────────────

/// HP BIOS WMI GUID — used for hardware queries (BIOS commands).
/// Reference: `hp-wmi.c` line 47 `#define HPWMI_BIOS_GUID`.
pub const HP_WMI_BIOS_GUID: &str = "5FB7F034-2C63-45E9-BE91-3D44E2C707E4";

/// HP event GUID — hotkey/bezel/wireless/lid notifications arrive here.
/// Reference: `hp-wmi.c` line 46 `#define HPWMI_EVENT_GUID`.
pub const HP_WMI_EVENT_GUID: &str = "95F24279-4D7B-4334-9387-ACCDC67EF61C";

// ── HP WMI command types ──────────────────────────────────────────────

/// HP WMI command (query) types — the `commandtype` field of
/// `bios_args`. Reference: `hp-wmi.c::enum hp_wmi_commandtype`.
///
/// Correction note: this enum previously carried `Wireless = 0x07`
/// and `Hotkey = 0x04`; in `hp-wmi.c` 0x07 is the *battery* query,
/// 0x04 the *hardware* query, the wireless query is 0x05 and the
/// hotkey query is 0x0c. The values below are the verified ones.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpWmiCommand {
    /// Screen display type query.
    Display = 0x01,
    /// HDD temperature query.
    HddTemp = 0x02,
    /// Ambient light sensor query.
    Als = 0x03,
    /// Hardware state query (dock / tablet masks).
    Hardware = 0x04,
    /// Wireless state (WiFi / BT / WWAN / GPS) query/set.
    Wireless = 0x05,
    /// Battery subsystem query.
    Battery = 0x07,
    /// BIOS settings query.
    Bios = 0x09,
    /// Feature query (BIOS ≥ 2008 detection).
    Feature = 0x0B,
    /// Hotkey code query.
    Hotkey = 0x0C,
    /// Feature2 query (BIOS ≥ 2009 detection).
    Feature2 = 0x0D,
    /// Wireless2 (rfkill2 device table) query.
    Wireless2 = 0x1B,
    /// Thermal profile query — added to `hp-wmi.c` with the
    /// thermal-profile series, after the v5.3 commandtype enum.
    ThermalProfile = 0x1C,
    /// Post-code error query.
    PostCodeError = 0x2A,
}

/// HP WMI command verb — the `command` field of `bios_args`.
/// Reference: `hp-wmi.c::enum hp_wmi_command`, plus `HPWMI_GM`
/// from the OMEN/Victus series (`HPWMI_LM = 0x20009` exists too;
/// no NARF consumer yet).
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpWmiVerb {
    Read = 0x01,
    Write = 0x02,
    Odm = 0x03,
    /// Gaming-machine commands (OMEN / Victus).
    Gm = 0x20008,
}

/// HP firmware return codes (`bios_return.return_code`).
/// Reference: `hp-wmi.c::enum hp_return_value`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpReturn {
    WrongSignature = 0x02,
    UnknownCommand = 0x03,
    UnknownCmdType = 0x04,
    InvalidParameters = 0x05,
}

/// Errors from a `perform_query` conversation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpWmiError {
    /// BIOS GUID not in the WMI registry (not an HP, or WMI not
    /// enumerated yet).
    NoBiosGuid,
    /// Input payload exceeds the 4-byte `bios_args.data` word.
    InputTooLarge,
    /// Output size exceeds the 4096-byte method-id encoding limit.
    OutputTooLarge,
    /// AML method evaluation failed.
    Aml,
    /// Reply was not a buffer, or shorter than the 8-byte
    /// `bios_return` header.
    BadReply,
    /// Firmware returned a nonzero `bios_return.return_code`
    /// (the raw code is preserved).
    Firmware(u32),
}

/// Map an output size to the WMI method id the firmware expects.
/// Reference: `hp-wmi.c::encode_outsize_for_pvsz` — verified
/// against the source: >4096 invalid, >1024 → 5, >128 → 4,
/// >4 → 3, >0 → 2, 0 → 1.
pub fn encode_outsize_for_pvsz(outsize: usize) -> Option<u32> {
    if outsize > 4096 {
        return None;
    }
    Some(if outsize > 1024 {
        5
    } else if outsize > 128 {
        4
    } else if outsize > 4 {
        3
    } else if outsize > 0 {
        2
    } else {
        1
    })
}

/// Build the 20-byte `bios_args` buffer for a query.
/// Layout (verified, `hp-wmi.c::struct bios_args`, packed u32s):
/// signature `0x55434553` ("SECU"), command, commandtype,
/// datasize, data word (input payload, ≤ 4 bytes, LE).
pub fn build_bios_args(verb: HpWmiVerb, query: HpWmiCommand, input: &[u8]) -> Option<[u8; 20]> {
    if input.len() > 4 {
        return None;
    }
    let mut data = [0u8; 4];
    data[..input.len()].copy_from_slice(input);
    let mut buf = [0u8; 20];
    buf[0..4].copy_from_slice(&0x55434553u32.to_le_bytes());
    buf[4..8].copy_from_slice(&(verb as u32).to_le_bytes());
    buf[8..12].copy_from_slice(&(query as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&(input.len() as u32).to_le_bytes());
    buf[16..20].copy_from_slice(&data);
    Some(buf)
}

fn bios_guid() -> Option<narf_aml::wmi::WmiGuid> {
    let want = crate::wmi_vendors::guid_str_to_bytes(HP_WMI_BIOS_GUID)?;
    narf_aml::wmi::list_guids()
        .into_iter()
        .find(|g| g.guid == want)
}

/// Run one `hp_wmi_perform_query` conversation against the BIOS
/// GUID: build `bios_args`, invoke the WM method whose id encodes
/// `output.len()`, then validate the `bios_return` header and copy
/// the payload that follows it into `output`. Returns the number
/// of payload bytes copied.
///
/// Reference: `hp-wmi.c::hp_wmi_perform_query` — the reply buffer
/// is `bios_return { sigpass, return_code }` followed by the
/// output data; a nonzero return_code is an HP-specific error and
/// no payload is copied.
pub fn perform_query(
    query: HpWmiCommand,
    verb: HpWmiVerb,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, HpWmiError> {
    perform_query_raw(query as u32, verb as u32, input, output)
}

/// `perform_query` with raw commandtype / verb words (the GM
/// commands don't fit the query enum). The reply payload is
/// zero-filled past the returned length, as in `hp-wmi.c`.
fn perform_query_raw(
    commandtype: u32,
    verb: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, HpWmiError> {
    if input.len() > 4 {
        return Err(HpWmiError::InputTooLarge);
    }
    let mut data = [0u8; 4];
    data[..input.len()].copy_from_slice(input);
    let mut args_buf = [0u8; 20];
    args_buf[0..4].copy_from_slice(&0x55434553u32.to_le_bytes());
    args_buf[4..8].copy_from_slice(&verb.to_le_bytes());
    args_buf[8..12].copy_from_slice(&commandtype.to_le_bytes());
    args_buf[12..16].copy_from_slice(&(input.len() as u32).to_le_bytes());
    args_buf[16..20].copy_from_slice(&data);
    let mid = encode_outsize_for_pvsz(output.len()).ok_or(HpWmiError::OutputTooLarge)?;
    let guid = bios_guid().ok_or(HpWmiError::NoBiosGuid)?;
    let reply =
        narf_aml::wmi::invoke_method(&guid, mid, &[narf_aml::Value::Buffer(args_buf.to_vec())])
            .map_err(|_| HpWmiError::Aml)?;
    let buf = match reply {
        narf_aml::Value::Buffer(b) => b,
        _ => return Err(HpWmiError::BadReply),
    };
    if buf.len() < 8 {
        return Err(HpWmiError::BadReply);
    }
    let return_code = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if return_code != 0 {
        return Err(HpWmiError::Firmware(return_code));
    }
    if output.is_empty() {
        return Ok(0);
    }
    let n = (buf.len() - 8).min(output.len());
    output[..n].copy_from_slice(&buf[8..8 + n]);
    // Linux zero-fills the remainder of the output buffer.
    for b in &mut output[n..] {
        *b = 0;
    }
    Ok(n)
}

/// Read one u32 through a query (`hp_wmi_read_int`).
pub fn read_int(query: HpWmiCommand) -> Result<u32, HpWmiError> {
    let mut out = [0u8; 4];
    perform_query(query, HpWmiVerb::Read, &[0; 4], &mut out)?;
    Ok(u32::from_le_bytes(out))
}

// ── HP wireless state (rfkill1 word) ──────────────────────────────────

/// Wireless radio state summary kept for the legacy
/// `wireless_state()` accessor; the authoritative per-radio state
/// now lives in `crate::rfkill`, refreshed from the same words.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WirelessState {
    /// WiFi radio powered (rfkill1 word, radio byte 0, POWER_STATE).
    pub wifi: bool,
    /// Bluetooth radio powered (byte 1).
    pub bluetooth: bool,
    /// WWAN / LTE radio powered (byte 2).
    pub wwan: bool,
}

static WIRELESS_STATE: narf_lib::sync::IrqSafeSpinLock<WirelessState> =
    narf_lib::sync::IrqSafeSpinLock::new(WirelessState {
        wifi: true,
        bluetooth: true,
        wwan: false,
    });

/// Return the cached wireless radio state.
pub fn wireless_state() -> WirelessState {
    *WIRELESS_STATE.lock()
}

/// Per-radio power bits in the rfkill1 wireless word.
/// Reference: `hp-wmi.c::enum hp_wireless2_bits` (same bit names
/// are used for the wireless word's per-radio byte):
/// POWER_STATE 0x01, POWER_SOFT 0x02, POWER_BIOS 0x04,
/// POWER_HARD 0x08. Radio `r` (0=wifi, 1=bluetooth, 2=wwan,
/// 3=gps) occupies byte `r` of the word — see
/// `hp_wmi_get_sw_state` (mask `0x200 << (r * 8)`) and
/// `hp_wmi_get_hw_state` (mask `0x800 << (r * 8)`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RadioPower {
    /// POWER_STATE: radio is powered.
    pub powered: bool,
    /// Soft-blocked per firmware: `!(byte & POWER_SOFT)`.
    pub sw_blocked: bool,
    /// Hard-blocked per firmware: `(byte & (BIOS|HARD)) != (BIOS|HARD)`.
    pub hw_blocked: bool,
}

/// Decode one radio's power byte from the wireless word.
pub fn decode_radio_power(word: u32, radio: u32) -> RadioPower {
    let byte = (word >> (radio * 8)) & 0xFF;
    RadioPower {
        powered: byte & 0x01 != 0,
        sw_blocked: byte & 0x02 == 0,
        hw_blocked: byte & (0x04 | 0x08) != (0x04 | 0x08),
    }
}

/// Decode the rfkill1 wireless word into the summary state.
///
/// Correction note: the previous decoder read wifi/bluetooth/wwan
/// as bits 0/1/2 of the word. In `hp-wmi.c` the word is four
/// per-radio bytes and "powered" is bit 0 *of each byte*; the old
/// reading reported bluetooth as wifi's POWER_SOFT bit. Values
/// below follow the verified layout.
pub fn decode_wireless_state(buf: &[u8]) -> Option<WirelessState> {
    if buf.len() < 4 {
        return None;
    }
    let word = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Some(WirelessState {
        wifi: decode_radio_power(word, 0).powered,
        bluetooth: decode_radio_power(word, 1).powered,
        wwan: decode_radio_power(word, 2).powered,
    })
}

// ── rfkill integration ────────────────────────────────────────────────

/// Radio indices in the hp-wmi numbering (`enum hp_wmi_radio`).
mod radio {
    pub const WIFI: u32 = 0;
    pub const BLUETOOTH: u32 = 1;
    pub const WWAN: u32 = 2;
    pub const GPS: u32 = 3;
}

/// rfkill-core indices for the four HP radios, once registered.
static RFKILL_IDX: narf_lib::sync::IrqSafeSpinLock<Option<[usize; 4]>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn rfkill_set_block(radio_id: u32, blocked: bool) -> bool {
    // Reference: `hp_wmi_set_block` — the write word is
    // `BIT(radio + 8) | ((!blocked) << radio)`, sent as a WRITE
    // to the wireless query with no output.
    let word: u32 = (1 << (radio_id + 8)) | ((if blocked { 0 } else { 1 }) << radio_id);
    perform_query(
        HpWmiCommand::Wireless,
        HpWmiVerb::Write,
        &word.to_le_bytes(),
        &mut [],
    )
    .is_ok()
}

fn set_block_wifi(blocked: bool) -> bool {
    rfkill_set_block(radio::WIFI, blocked)
}
fn set_block_bluetooth(blocked: bool) -> bool {
    rfkill_set_block(radio::BLUETOOTH, blocked)
}
fn set_block_wwan(blocked: bool) -> bool {
    rfkill_set_block(radio::WWAN, blocked)
}
fn set_block_gps(blocked: bool) -> bool {
    rfkill_set_block(radio::GPS, blocked)
}

/// Register the four HP radios with the rfkill core (idempotent).
fn ensure_rfkill_registered() -> [usize; 4] {
    if let Some(idx) = *RFKILL_IDX.lock() {
        return idx;
    }
    use crate::rfkill::{register_radio, RadioType};
    let idx = [
        register_radio("hp-wifi", RadioType::Wlan, Some(set_block_wifi)),
        register_radio(
            "hp-bluetooth",
            RadioType::Bluetooth,
            Some(set_block_bluetooth),
        ),
        register_radio("hp-wwan", RadioType::Wwan, Some(set_block_wwan)),
        register_radio("hp-gps", RadioType::Gps, Some(set_block_gps)),
    ];
    *RFKILL_IDX.lock() = Some(idx);
    idx
}

/// Push one radio's decoded power state into the rfkill core and
/// the legacy summary cache.
fn publish_radio_power(idx: [usize; 4], radio_id: u32, power: RadioPower) {
    crate::rfkill::update_state(
        idx[radio_id as usize],
        crate::rfkill::RadioState {
            soft_blocked: power.sw_blocked,
            hard_blocked: power.hw_blocked,
        },
    );
}

/// Refresh radio state from the rfkill1 wireless word and publish
/// it. Returns false when the firmware query fails.
pub fn refresh_wireless() -> bool {
    let word = match read_int(HpWmiCommand::Wireless) {
        Ok(w) => w,
        Err(_) => return false,
    };
    let idx = ensure_rfkill_registered();
    for r in 0..4 {
        publish_radio_power(idx, r, decode_radio_power(word, r));
    }
    if let Some(s) = decode_wireless_state(&word.to_le_bytes()) {
        *WIRELESS_STATE.lock() = s;
    }
    true
}

// ── rfkill2 device table ──────────────────────────────────────────────

/// One device entry of the rfkill2 state block (16 bytes).
/// Reference: `hp-wmi.c::struct bios_rfkill2_device_state`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rfkill2Device {
    /// Radio class: 0 = wifi, 1 = bluetooth, 2 = wwan, 3 = gps
    /// (`enum hp_wmi_radio`).
    pub radio_type: u8,
    pub bus_type: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub subsys_vendor_id: u16,
    pub subsys_product_id: u16,
    pub rfkill_id: u8,
    /// Power byte — same POWER_* bits as the rfkill1 word.
    pub power: u8,
}

impl Rfkill2Device {
    /// Decode this device's power byte (rfkill2 uses the same
    /// POWER_STATE / POWER_SOFT / POWER_BIOS / POWER_HARD bits).
    pub fn power_state(&self) -> RadioPower {
        RadioPower {
            powered: self.power & 0x01 != 0,
            sw_blocked: self.power & 0x02 == 0,
            hw_blocked: self.power & (0x04 | 0x08) != (0x04 | 0x08),
        }
    }
}

/// Decode a 128-byte rfkill2 state block.
/// Layout (verified, `hp-wmi.c::struct bios_rfkill2_state`):
/// 7 unknown bytes, count byte at offset 7, 8 pad bytes, then
/// `count` (max 7) 16-byte device entries at offset 16.
pub fn decode_rfkill2_state(buf: &[u8]) -> Option<Vec<Rfkill2Device>> {
    if buf.len() < 16 {
        return None;
    }
    let count = (buf[7] as usize).min(7);
    if buf.len() < 16 + count * 16 {
        return None;
    }
    let u16le = |b: &[u8]| u16::from_le_bytes([b[0], b[1]]);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = &buf[16 + i * 16..16 + (i + 1) * 16];
        out.push(Rfkill2Device {
            radio_type: e[0],
            bus_type: e[1],
            vendor_id: u16le(&e[2..4]),
            product_id: u16le(&e[4..6]),
            subsys_vendor_id: u16le(&e[6..8]),
            subsys_product_id: u16le(&e[8..10]),
            rfkill_id: e[10],
            power: e[11],
        });
    }
    Some(out)
}

/// Refresh radio state from the rfkill2 device table
/// (`HPWMI_WIRELESS2_QUERY`) and publish every reported device to
/// the rfkill core. Returns the number of devices published.
/// Reference: `hp-wmi.c::hp_wmi_rfkill2_refresh`.
pub fn refresh_rfkill2() -> Result<usize, HpWmiError> {
    let mut buf = [0u8; 128];
    perform_query(HpWmiCommand::Wireless2, HpWmiVerb::Read, &[0], &mut buf)?;
    let devices = decode_rfkill2_state(&buf).ok_or(HpWmiError::BadReply)?;
    let idx = ensure_rfkill_registered();
    let mut published = 0;
    for dev in &devices {
        if (dev.radio_type as usize) < idx.len() {
            publish_radio_power(idx, dev.radio_type as u32, dev.power_state());
            published += 1;
        }
    }
    Ok(published)
}

// ── HP event decoder ──────────────────────────────────────────────────

/// Decoded HP WMI event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpEvent {
    /// Bezel button / hotkey. `key_code` from `HOTKEY_QUERY` response.
    BezelButton { key_code: u32 },
    /// WLAN toggle (event_id = 0x05).
    WlanToggle,
    /// Fn-P hotkey (event_id = 0x1B) — platform profile cycle.
    FnPHotkey,
    /// Omen key (event_id = 0x1D).
    OmenKey { key_code: u32 },
    /// Camera toggle (event_id = 0x1A). `open` = lens cover removed.
    CameraToggle { open: bool },
    /// Lid switch state change.
    LidSwitch,
    /// Screen rotation (convertible).
    ScreenRotation,
    /// Any other event.
    Other { event_id: u32, event_data: u32 },
}

/// Decode HP WMI event payload.
///
/// 8-byte: `event_id` at u32[0], `event_data` at u32[4].
/// 16-byte: `event_id` at u32[0], `event_data` at u32[8].
/// Reference: `hp-wmi.c::hp_wmi_notify()` lines 1098–1108.
pub fn decode_hp_event(data: &[u8]) -> Option<HpEvent> {
    if data.len() < 8 {
        return None;
    }
    let u32le = |off: usize| -> u32 {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    };
    let event_id = u32le(0);
    let event_data = if data.len() >= 16 { u32le(8) } else { u32le(4) };

    Some(match HpEventId::from_u32(event_id) {
        HpEventId::BezelButton => HpEvent::BezelButton {
            key_code: event_data,
        },
        HpEventId::Wireless => HpEvent::WlanToggle,
        HpEventId::FnPHotkey => HpEvent::FnPHotkey,
        HpEventId::OmenKey => HpEvent::OmenKey {
            key_code: event_data,
        },
        HpEventId::CameraToggle => HpEvent::CameraToggle {
            open: event_data == 0xfe,
        },
        HpEventId::LidSwitch => HpEvent::LidSwitch,
        HpEventId::ScreenRotation => HpEvent::ScreenRotation,
        _ => HpEvent::Other {
            event_id,
            event_data,
        },
    })
}

/// HP WMI event IDs (from `hp-wmi.c::enum hp_wmi_event_ids`).
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpEventId {
    Dock = 0x01,
    BezelButton = 0x04,
    Wireless = 0x05,
    LidSwitch = 0x08,
    ScreenRotation = 0x09,
    BacklitKbBrightness = 0x0D,
    SanitizationMode = 0x17,
    CameraToggle = 0x1A,
    FnPHotkey = 0x1B,
    OmenKey = 0x1D,
    Unknown,
}

impl HpEventId {
    fn from_u32(v: u32) -> Self {
        match v {
            0x01 => Self::Dock,
            0x04 => Self::BezelButton,
            0x05 => Self::Wireless,
            0x08 => Self::LidSwitch,
            0x09 => Self::ScreenRotation,
            0x0D => Self::BacklitKbBrightness,
            0x17 => Self::SanitizationMode,
            0x1A => Self::CameraToggle,
            0x1B => Self::FnPHotkey,
            0x1D => Self::OmenKey,
            _ => Self::Unknown,
        }
    }
}

/// Map HP WMI bezel button codes to `KeyCode`.
/// Reference: `hp-wmi.c::hp_wmi_keymap[]` lines 365–383.
pub fn hp_keycode(code: u32) -> Option<KeyCode> {
    match code {
        0x02 => Some(KeyCode::BrightnessUp),
        0x03 => Some(KeyCode::BrightnessDown),
        // KEY_MICMUTE — the microphone mute key, distinct from
        // speaker mute. Previously mapped to KeyCode::Mute.
        0x270 => Some(KeyCode::MicMute),
        0x21a9 | 0x121a9 => Some(KeyCode::TouchpadToggle),
        0x21a4 => None, // Win lock
        0x21a7 => None, // KEY_FN_ESC
        _ => None,
    }
}

// ── Coolsense / thermal profile ───────────────────────────────────────

/// HP thermal profile modes (legacy thermal-profile query values).
/// Reference: `hp-wmi.c` thermal-profile series — 0 = default /
/// balanced, 1 = cool (CoolSense), 2 = performance.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalProfile {
    /// Default balanced mode.
    Balanced = 0x00,
    /// Cool Sense / quiet mode.
    CoolSense = 0x01,
    /// Performance mode (high fan / high clocks).
    Performance = 0x02,
}

impl ThermalProfile {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            0x00 => Some(ThermalProfile::Balanced),
            0x01 => Some(ThermalProfile::CoolSense),
            0x02 => Some(ThermalProfile::Performance),
            _ => None,
        }
    }
}

static THERMAL_PROFILE: AtomicU32 = AtomicU32::new(0);

/// Get the last-known thermal profile (cache; refreshed by
/// [`get_thermal_profile`]).
pub fn thermal_profile() -> ThermalProfile {
    ThermalProfile::from_u32(THERMAL_PROFILE.load(Ordering::Relaxed))
        .unwrap_or(ThermalProfile::Balanced)
}

/// Read the active thermal profile back from firmware
/// (thermal-profile query, READ). Updates the cache on success.
pub fn get_thermal_profile() -> Result<ThermalProfile, HpWmiError> {
    let v = read_int(HpWmiCommand::ThermalProfile)?;
    let profile = ThermalProfile::from_u32(v).ok_or(HpWmiError::BadReply)?;
    THERMAL_PROFILE.store(profile as u32, Ordering::Release);
    Ok(profile)
}

/// Set the thermal profile via the thermal-profile query (WRITE).
/// Updates the cache only when the firmware accepts the write.
/// Reference: `hp-wmi.c::platform_profile_store`.
pub fn set_thermal_profile(profile: ThermalProfile) -> bool {
    let word = (profile as u32).to_le_bytes();
    let ok = perform_query(
        HpWmiCommand::ThermalProfile,
        HpWmiVerb::Write,
        &word,
        &mut [],
    )
    .is_ok();
    if ok {
        THERMAL_PROFILE.store(profile as u32, Ordering::Release);
    }
    ok
}

// ── OMEN / Victus GM performance mode ─────────────────────────────────

/// GM commandtype for setting the performance mode.
/// Reference: hp-wmi OMEN series — `HPWMI_SET_PERFORMANCE_MODE = 0x1A`,
/// invoked with command `HPWMI_GM = 0x20008` and a 2-byte buffer
/// `{0, mode}`.
pub const GM_CMD_SET_PERFORMANCE_MODE: u32 = 0x1A;
// The performance-mode *get* on OMEN models is EC-backed in
// `hp-wmi.c` (`platform_profile_omen_get_ec`), not a GM query —
// see `get_omen_performance_mode` for how the read is modelled.

/// OMEN performance-mode values, by firmware generation.
/// v0 (original OMEN): Default 0x00, Performance 0x01, Cool 0x02.
/// v1 (later OMEN / Victus): Default 0x30, Performance 0x31,
/// Cool 0x50. (A Victus-S variant uses 0x30/0x31 only.)
/// Reference: hp-wmi platform-profile series, `omen_pmode` tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OmenMode {
    Default,
    Performance,
    Cool,
}

impl OmenMode {
    /// Encode for the given firmware generation (0 or 1).
    pub fn to_gm_value(&self, generation: u8) -> u8 {
        match (generation, self) {
            (1, OmenMode::Default) => 0x30,
            (1, OmenMode::Performance) => 0x31,
            (1, OmenMode::Cool) => 0x50,
            (_, OmenMode::Default) => 0x00,
            (_, OmenMode::Performance) => 0x01,
            (_, OmenMode::Cool) => 0x02,
        }
    }

    /// Decode a raw mode byte from either generation.
    pub fn from_gm_value(v: u8) -> Option<Self> {
        match v {
            0x00 | 0x30 => Some(OmenMode::Default),
            0x01 | 0x31 => Some(OmenMode::Performance),
            0x02 | 0x50 => Some(OmenMode::Cool),
            _ => None,
        }
    }
}

/// Set the OMEN/Victus performance mode through the GM command:
/// `perform_query(SET_PERFORMANCE_MODE, GM, {0, mode}, 2, 0)`.
/// Reference: `omen_thermal_profile_set` in the hp-wmi series.
pub fn set_omen_performance_mode(mode: OmenMode, generation: u8) -> bool {
    let input = [0u8, mode.to_gm_value(generation)];
    // perform_query takes the commandtype as the enum; the GM set
    // uses commandtype 0x1A which is not a query enum member, so
    // route through the raw helper below.
    perform_query_raw(
        GM_CMD_SET_PERFORMANCE_MODE,
        HpWmiVerb::Gm as u32,
        &input,
        &mut [],
    )
    .is_ok()
}

/// Read the OMEN performance mode. On OMEN/Victus the profile get
/// is EC-backed in `hp-wmi.c`; the value the EC reports mirrors
/// the last GM mode the firmware applied, which the thermal-profile
/// query also surfaces on these models — so the get goes through
/// the thermal-profile READ and decodes with the GM value table.
pub fn get_omen_performance_mode() -> Result<OmenMode, HpWmiError> {
    let v = read_int(HpWmiCommand::ThermalProfile)?;
    OmenMode::from_gm_value(v as u8).ok_or(HpWmiError::BadReply)
}

// ── Platform-profile backend ──────────────────────────────────────────

fn profile_get() -> Option<crate::platform_profile::PlatformProfile> {
    use crate::platform_profile::PlatformProfile as P;
    match get_thermal_profile().ok()? {
        ThermalProfile::Balanced => Some(P::Balanced),
        ThermalProfile::CoolSense => Some(P::Cool),
        ThermalProfile::Performance => Some(P::Performance),
    }
}

fn profile_set(p: crate::platform_profile::PlatformProfile) -> bool {
    use crate::platform_profile::PlatformProfile as P;
    let tp = match p {
        P::Balanced => ThermalProfile::Balanced,
        P::Cool => ThermalProfile::CoolSense,
        P::Performance => ThermalProfile::Performance,
        _ => return false,
    };
    set_thermal_profile(tp)
}

/// Register the `hp-wmi` platform-profile backend
/// (choices: cool / balanced / performance — the
/// `platform_profile` choices `hp-wmi.c` registers for
/// thermal-profile models).
pub fn register_platform_profile() {
    use crate::platform_profile::PlatformProfile as P;
    const CHOICES: &[P] = &[P::Cool, P::Balanced, P::Performance];
    crate::platform_profile::register_backend(crate::platform_profile::ProfileBackend {
        name: "hp-wmi",
        choices: CHOICES,
        get: profile_get,
        set: profile_set,
    });
}

// ── Statistics ────────────────────────────────────────────────────────

static EVENT_COUNT: AtomicU32 = AtomicU32::new(0);
static BIOS_FOUND: AtomicBool = AtomicBool::new(false);

/// Number of HP WMI events processed.
pub fn event_count() -> u32 {
    EVENT_COUNT.load(Ordering::Relaxed)
}

/// True if the HP BIOS GUID was found in the WMI registry.
pub fn bios_guid_found() -> bool {
    BIOS_FOUND.load(Ordering::Relaxed)
}

// ── WMI event handler ─────────────────────────────────────────────────

fn on_hp_event(ev: &narf_aml::wmi::WmiEvent) {
    EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    let data = match ev.data.as_ref() {
        Some(narf_aml::Value::Buffer(b)) => b.as_slice(),
        _ => return,
    };
    let hp_ev = match decode_hp_event(data) {
        Some(e) => e,
        None => return,
    };
    match hp_ev {
        HpEvent::FnPHotkey => {
            // Fn-P cycles the platform profile (hp-wmi.c routes
            // HPWMI_FN_P_HOTKEY to platform_profile_cycle()).
            let _ = crate::platform_profile::cycle();
            return;
        }
        HpEvent::WlanToggle => {
            // The wireless key reports a state *change*; refresh
            // the rfkill state from firmware (rfkill2 when the
            // model exposes it, else the rfkill1 word), and still
            // surface the key to the input ring.
            if refresh_rfkill2().is_err() {
                refresh_wireless();
            }
            let _ = push_key(KeyCode::WLan, true);
            let _ = push_key(KeyCode::WLan, false);
            return;
        }
        _ => {}
    }
    let kc: Option<KeyCode> = match hp_ev {
        HpEvent::BezelButton { key_code } => hp_keycode(key_code),
        HpEvent::OmenKey { key_code } => hp_keycode(key_code),
        _ => None,
    };
    if let Some(k) = kc {
        let _ = push_key(k, true);
        let _ = push_key(k, false);
    }
}

// ── Init ──────────────────────────────────────────────────────────────

/// Initialise the HP WMI platform driver.
/// Reference: `hp-wmi.c::hp_wmi_init()`.
pub fn init() {
    let guids = narf_aml::wmi::list_guids();
    let event_bytes = crate::wmi_vendors::guid_str_to_bytes(HP_WMI_EVENT_GUID);
    let bios_bytes = crate::wmi_vendors::guid_str_to_bytes(HP_WMI_BIOS_GUID);

    for g in &guids {
        if let Some(ref eg) = event_bytes {
            if g.guid == eg.as_slice() {
                narf_aml::wmi::subscribe_event(g, on_hp_event);
            }
        }
        if let Some(ref bg) = bios_bytes {
            if g.guid == bg.as_slice() {
                BIOS_FOUND.store(true, Ordering::Release);
            }
        }
    }

    if BIOS_FOUND.load(Ordering::Acquire) {
        // Radios + profile backend exist only where the BIOS GUID
        // (the query surface) does. Initial radio state comes from
        // the firmware refresh, not from a guessed default.
        ensure_rfkill_registered();
        if refresh_rfkill2().is_err() {
            refresh_wireless();
        }
        register_platform_profile();
    }
}

// ── Test helpers ──────────────────────────────────────────────────────

/// Reset HP WMI driver state for tests.
#[doc(hidden)]
pub fn __test_reset() {
    EVENT_COUNT.store(0, Ordering::Relaxed);
    BIOS_FOUND.store(false, Ordering::Relaxed);
    THERMAL_PROFILE.store(0, Ordering::Relaxed);
    *RFKILL_IDX.lock() = None;
    *WIRELESS_STATE.lock() = WirelessState {
        wifi: true,
        bluetooth: true,
        wwan: false,
    };
}
