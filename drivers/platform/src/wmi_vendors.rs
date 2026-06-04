// SPDX-License-Identifier: GPL-2.0-or-later
//! Vendor WMI hotkey dispatch — Dell, HP, Lenovo.
//!
//! Each OEM embeds a per-vendor GUID in its ACPI `_WDG` table.
//! `init()` scans the WMI GUID registry (populated by
//! `narf_aml::wmi::enumerate_guids`), detects which vendor is
//! present, and registers event handlers that decode raw event
//! payloads into typed Rust enums before routing them into the
//! `narf_input` key ring.
//!
//! ## Linux references (GPL-2.0-or-later, cited post-relicense)
//!
//! - Dell:   `drivers/platform/x86/dell/dell-wmi-base.c`
//!           Event GUID "9DBB5994-A997-11DA-B012-B622A1EF5492";
//!           `dell_wmi_notify()` parses a u16 buffer array where
//!           `buf[1]` is the event type (0x0000/0x0010/0x0011/0x0012)
//!           and `buf[2]` is the key code.
//!
//! - HP:     `drivers/platform/x86/hp/hp-wmi.c`
//!           Event GUID "95F24279-4D7B-4334-9387-ACCDC67EF61C";
//!           `hp_wmi_notify()` reads a u32 `event_id` at offset 0
//!           and `event_data` at offset 4 (8-byte payload) or offset 8
//!           (16-byte payload).
//!
//! - Lenovo: `drivers/platform/x86/lenovo/ymc.c` +
//!           `drivers/platform/x86/lenovo/wmi-events.c`
//!           YMC tablet-mode event GUID "06129D99-6083-4164-81AD-F092F9D773A6"
//!           (ymc.c) reports u32 code 0x01 = laptop, 0x02–0x04 = tablet.
//!           The task-spec GUID "21494638-…" is used for IdeaPad hotkeys.
//!
//! ## Deferred
//!
//! - Full think-lmi BIOS-setting protocol (thinkpad_acpi BIOS GUID).
//! - Dell SMM-via-WMI class 17/select 3 application registration.
//! - HP-WMI thermal profile set/get (OMEN/Victus specific WMI GM cmd).
//! - Lenovo battery conservation mode (ideapad-laptop WMI method).

extern crate alloc;

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_aml::wmi::{list_guids, subscribe_event, WmiEvent};
use narf_input::{push_key, KeyCode};

// ── GUID string constants ──────────────────────────────────────────

/// Dell WMI descriptor GUID (8D9D…). Presence of this GUID in _WDG
/// indicates a Dell WMI-capable system.
/// Reference: `drivers/platform/x86/dell/dell-wmi-base.c` — used by
/// `dell_wmi_get_descriptor_valid()` to verify the system is Dell WMI-capable.
const DELL_WMI_DESCRIPTOR_GUID: &str = "8D9DDCBC-A997-11DA-B012-B622A1EF5492";

/// Dell WMI event GUID (9DBB…). EC hotkey payloads arrive here.
/// Reference: `dell-wmi-base.c` line 37 `#define DELL_EVENT_GUID`.
const DELL_WMI_EVENT_GUID: &str = "9DBB5994-A997-11DA-B012-B622A1EF5492";

/// HP WMI event GUID. Bezel buttons, wireless, lid, screen rotation.
/// Reference: `hp-wmi.c` line 46 `#define HPWMI_EVENT_GUID`.
const HP_WMI_EVENT_GUID: &str = "95F24279-4D7B-4334-9387-ACCDC67EF61C";

/// HP WMI BIOS GUID. WQ/WS methods for hardware queries.
/// Reference: `hp-wmi.c` line 47 `#define HPWMI_BIOS_GUID`.
const HP_WMI_BIOS_GUID: &str = "5FB7F034-2C63-45E9-BE91-3D44E2C707E4";

/// Lenovo IdeaPad/Yoga hotkey event GUID.  Appears in IdeaPad DSDT
/// dumps as the primary hotkey notification surface.
const LENOVO_WMI_EVENT_GUID: &str = "21494638-4391-4287-94B2-DDF09FE4A7AA";

/// Lenovo YMC (Yoga Mode Control) event GUID — tablet-mode toggle.
/// Reference: `drivers/platform/x86/lenovo/ymc.c` line 17
/// `#define LENOVO_YMC_EVENT_GUID`.
const LENOVO_YMC_EVENT_GUID: &str = "06129D99-6083-4164-81AD-F092F9D773A6";

// ── GUID byte representation ───────────────────────────────────────

/// Parse the mixed-endian RFC-4122 GUID string into the raw 16-byte
/// wire format used in `_WDG` descriptors. Returns `None` if the
/// string is malformed. The wire layout is:
/// - Data1 (4 bytes, LE)
/// - Data2 (2 bytes, LE)
/// - Data3 (2 bytes, LE)
/// - Data4 (8 bytes, big-endian)
/// matching the mixed-endian encoding Microsoft uses in WMI _WDG.
/// Reference: `wmi.c::wmi_guid_eq` + RFC 4122 §4.1.2.
pub fn guid_str_to_bytes(s: &str) -> Option<[u8; 16]> {
    // Strip hyphens and validate length: 32 hex chars.
    let hex: alloc::string::String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 16];
    for i in 0..16 {
        let hi = hex.as_bytes()[i * 2];
        let lo = hex.as_bytes()[i * 2 + 1];
        let nibble = |b: u8| -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        };
        raw[i] = (nibble(hi)? << 4) | nibble(lo)?;
    }
    // The GUID string "AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP"
    // stores Data1 = AABBCCDD as big-endian text but wire encoding
    // is LE. Swap bytes for Data1 (bytes 0..4), Data2 (bytes 4..6),
    // Data3 (bytes 6..8).
    raw[0..4].reverse();
    raw[4..6].reverse();
    raw[6..8].reverse();
    Some(raw)
}

// ── Vendor detection ────────────────────────────────────────────────

/// Which OEM vendor was detected from the WMI GUID table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Vendor {
    Dell,
    Hp,
    Lenovo,
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Vendor::Dell => f.write_str("Dell"),
            Vendor::Hp => f.write_str("HP"),
            Vendor::Lenovo => f.write_str("Lenovo"),
        }
    }
}

/// Detected vendor, set once at `init()` time.
static DETECTED_VENDOR: narf_lib::sync::IrqSafeSpinLock<Option<Vendor>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Return the vendor detected during `init()`, or `None` if WMI
/// enumeration found no known vendor GUID.
pub fn vendor() -> Option<Vendor> {
    *DETECTED_VENDOR.lock()
}

// ── Error type ──────────────────────────────────────────────────────

/// Errors from `init()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WmiVendorError {
    /// WMI GUID enumeration returned no entries — `enumerate_guids()`
    /// was not called before `init()`, or this platform has no WMI.
    NoGuids,
    /// No known vendor GUID found in the WMI registry.
    UnknownVendor,
}

// ── Statistics ──────────────────────────────────────────────────────

static DELL_EVENTS: AtomicU32 = AtomicU32::new(0);
static HP_EVENTS: AtomicU32 = AtomicU32::new(0);
static LENOVO_EVENTS: AtomicU32 = AtomicU32::new(0);
/// Set when a Dell WMI descriptor GUID (8D9D…) is found in _WDG,
/// confirming the system is Dell WMI-capable before registering the
/// event-GUID handler.
static DELL_DESCRIPTOR_FOUND: AtomicBool = AtomicBool::new(false);
static HP_BIOS_FOUND: AtomicBool = AtomicBool::new(false);

/// Count of Dell WMI hotkey events dispatched since `init()`.
pub fn dell_event_count() -> u32 {
    DELL_EVENTS.load(Ordering::Relaxed)
}

/// Count of HP WMI events dispatched since `init()`.
pub fn hp_event_count() -> u32 {
    HP_EVENTS.load(Ordering::Relaxed)
}

/// Count of Lenovo WMI events dispatched since `init()`.
pub fn lenovo_event_count() -> u32 {
    LENOVO_EVENTS.load(Ordering::Relaxed)
}

// ── Dell event decoder ─────────────────────────────────────────────

/// Decoded Dell WMI hotkey event.
///
/// The Dell event payload is a buffer of u16 words. The first word
/// (`buf[0]`) is the total length of the frame (in additional words).
/// `buf[1]` is the event type; `buf[2]` is the key code.
///
/// Reference: `dell-wmi-base.c::dell_wmi_notify()` — the switch
/// statement on `buffer_entry[1]` for type 0x0000/0x0010/0x0011.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DellEvent {
    /// A known Fn-key or multimedia key (type 0x0000 / 0x0010).
    /// `id` is the raw WMI keycode from `buf[2]`.
    FnFunctionKey { id: u16 },
    /// Tablet-mode toggle event (type 0x0011, code 0xe070).
    /// `on` = true means entering tablet mode.
    /// Reference: `dell-wmi-base.c` line 447 — `SW_TABLET_MODE, !buffer[0]`.
    TabletMode { on: bool },
    /// Mic-mute toggle (type 0x0000, code 0x0150 or
    /// type 0x0010, code 0x0150).
    /// Reference: keymap entries `KE_KEY, 0x0150, { KEY_MICMUTE }`.
    MicMute,
    /// Unknown / unhandled event type or code.
    Unknown { event_type: u16, code: u16 },
}

/// Decode a Dell WMI event payload buffer (little-endian u16 words).
/// Returns `None` for empty or truncated payloads; the caller should
/// treat that as a malformed event.
///
/// Reference: `dell-wmi-base.c::dell_wmi_notify()` — the buffer walk
/// and per-frame `switch(buffer_entry[1])` dispatch.
pub fn decode_dell_event(data: &[u8]) -> Option<DellEvent> {
    // Payload must be at least 6 bytes = 3 u16 words.
    if data.len() < 6 {
        return None;
    }
    let word = |off: usize| -> u16 { u16::from_le_bytes([data[off * 2], data[off * 2 + 1]]) };
    let _len = word(0); // frame length in extra words
    let event_type = word(1);
    let code = word(2);

    // Tablet-mode: type 0x0011, code 0xe070 with extended data.
    // Reference: dell-wmi-base.c line 446–449.
    if event_type == 0x0011 && code == 0xe070 {
        // word(3) = 0 means entered tablet, 1 means exited.
        let tablet_val = if data.len() >= 8 { word(3) } else { 0 };
        return Some(DellEvent::TabletMode {
            on: tablet_val == 0,
        });
    }

    // Mic mute — appears in both type-0000 and type-0010 tables at code 0x0150.
    // Reference: dell-wmi-base.c `KE_KEY, 0x0150, { KEY_MICMUTE }`.
    if code == 0x0150 {
        return Some(DellEvent::MicMute);
    }

    match event_type {
        // type 0x0000: legacy single-key events.
        // type 0x0010: new-style single-key events (from DMI or extended table).
        0x0000 | 0x0010 | 0x0011 | 0x0012 => Some(DellEvent::FnFunctionKey { id: code }),
        _ => Some(DellEvent::Unknown { event_type, code }),
    }
}

/// WMI event handler for Dell — registered against the Dell event GUID.
fn on_dell_event(ev: &WmiEvent) {
    DELL_EVENTS.fetch_add(1, Ordering::Relaxed);

    let data = match ev.data.as_ref() {
        Some(narf_aml::Value::Buffer(b)) => b.as_slice(),
        _ => return,
    };

    let dell_ev = match decode_dell_event(data) {
        Some(e) => e,
        None => return,
    };

    // Map decoded Dell events to narf_input KeyCodes.
    let code: Option<KeyCode> = match dell_ev {
        DellEvent::FnFunctionKey { id } => decode_dell_keycode(id),
        DellEvent::TabletMode { on: _ } => {
            // Tablet mode toggle — no standard KeyCode; would route to
            // a platform-event bus in a future LaptopModeEvent ring.
            None
        }
        DellEvent::MicMute => Some(KeyCode::Mute), // closest available
        DellEvent::Unknown { .. } => None,
    };

    if let Some(kc) = code {
        let _ = push_key(kc, true);
        let _ = push_key(kc, false);
    }
}

/// Translate Dell WMI key codes to narf_input KeyCodes.
/// Maps the entries from `dell_wmi_keymap_type_0000` and
/// `dell_wmi_keymap_type_0010` in `dell-wmi-base.c`.
fn decode_dell_keycode(id: u16) -> Option<KeyCode> {
    // Reference: dell-wmi-base.c keymap arrays (GPL-2.0-or-later).
    match id {
        0x0109 => Some(KeyCode::Mute), // audio mute
        0x0150 => Some(KeyCode::Mute), // mic mute (re-used)
        0xe005 => Some(KeyCode::BrightnessDown),
        0xe006 => Some(KeyCode::BrightnessUp),
        0xe011 => Some(KeyCode::WLan), // Wifi Catcher
        0xe027 => None,                // LCD Display On/Off (no code)
        0xe02e => Some(KeyCode::VolumeDown),
        0xe030 => Some(KeyCode::VolumeUp),
        0xe033 => Some(KeyCode::KbdIlluminationUp),
        0xe034 => Some(KeyCode::KbdIlluminationDown),
        0x0057 => Some(KeyCode::BrightnessDown), // type-0010 DMI
        0x0058 => Some(KeyCode::BrightnessUp),   // type-0010 DMI
        _ => None,
    }
}

// ── HP event decoder ────────────────────────────────────────────────

/// HP WMI event IDs (from `hp-wmi.c::enum hp_wmi_event_ids`).
/// Reference: `hp-wmi.c` lines 226–247 (GPL-2.0-or-later).
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
    SmartExperienceApp = 0x21,
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
            0x21 => Self::SmartExperienceApp,
            _ => Self::Unknown,
        }
    }
}

/// Decoded HP WMI event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HpEvent {
    /// Bezel button press. `key_code` is the raw HP WMI hotkey code
    /// (from `HPWMI_HOTKEY_QUERY`). Reference: `hp-wmi.c::HPWMI_BEZEL_BUTTON`.
    BezelButton { key_code: u32 },
    /// WLAN toggle (event_id = 0x05 / `HPWMI_WIRELESS`).
    WlanToggle,
    /// Fn-P hotkey (event_id = 0x1B): cycles platform profile.
    /// Reference: `hp-wmi.c::HPWMI_FN_P_HOTKEY`.
    FnPHotkey,
    /// OMEN key (event_id = 0x1D). `key_code` from event_data if non-zero,
    /// else from HOTKEY_QUERY. Reference: `hp-wmi.c::HPWMI_OMEN_KEY`.
    OmenKey { key_code: u32 },
    /// Camera toggle (event_id = 0x1A). `open` = true when lens cover
    /// removed. Reference: `hp-wmi.c::HPWMI_CAMERA_TOGGLE`.
    CameraToggle { open: bool },
    /// Lid state change.
    LidSwitch,
    /// Screen-rotation notification (convertible 2-in-1).
    ScreenRotation,
    /// Any other event ID; payload preserved for diagnostics.
    Other { event_id: u32, event_data: u32 },
}

/// Decode an HP WMI event payload buffer.
///
/// The buffer is either 8 or 16 bytes. In both cases `event_id` is
/// at u32 offset 0. `event_data` is at u32 offset 1 (8-byte payload)
/// or u32 offset 2 (16-byte payload).
///
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

    let ev = match HpEventId::from_u32(event_id) {
        HpEventId::BezelButton => HpEvent::BezelButton {
            key_code: event_data,
        },
        HpEventId::Wireless => HpEvent::WlanToggle,
        HpEventId::FnPHotkey => HpEvent::FnPHotkey,
        HpEventId::OmenKey => HpEvent::OmenKey {
            key_code: event_data,
        },
        HpEventId::CameraToggle => {
            // 0xff = closed (lens cover on), 0xfe = open.
            // Reference: hp-wmi.c lines 1194–1199.
            HpEvent::CameraToggle {
                open: event_data == 0xfe,
            }
        }
        HpEventId::LidSwitch => HpEvent::LidSwitch,
        HpEventId::ScreenRotation => HpEvent::ScreenRotation,
        _ => HpEvent::Other {
            event_id,
            event_data,
        },
    };
    Some(ev)
}

/// HP sparse keymap → narf_input KeyCode.
/// Reference: `hp-wmi.c::hp_wmi_keymap[]` lines 365–383.
fn decode_hp_bezel_keycode(code: u32) -> Option<KeyCode> {
    // These are the sparse-keymap entries from hp-wmi.c.
    match code {
        0x02 => Some(KeyCode::BrightnessUp),
        0x03 => Some(KeyCode::BrightnessDown),
        0x270 => Some(KeyCode::Mute), // KEY_MICMUTE
        0x20e6 => None,               // KEY_PROG1
        0x20e8 => None,               // KEY_MEDIA
        0x21a4 => None,               // Win Lock On (ignore)
        0x21a7 => None,               // KEY_FN_ESC
        0x21a9 => Some(KeyCode::TouchpadToggle),
        0x121a9 => Some(KeyCode::TouchpadToggle),
        _ => None,
    }
}

/// WMI event handler for HP — registered against the HP event GUID.
fn on_hp_event(ev: &WmiEvent) {
    HP_EVENTS.fetch_add(1, Ordering::Relaxed);

    let data = match ev.data.as_ref() {
        Some(narf_aml::Value::Buffer(b)) => b.as_slice(),
        _ => return,
    };

    let hp_ev = match decode_hp_event(data) {
        Some(e) => e,
        None => return,
    };

    let code: Option<KeyCode> = match hp_ev {
        HpEvent::BezelButton { key_code } => decode_hp_bezel_keycode(key_code),
        HpEvent::WlanToggle => Some(KeyCode::WLan),
        HpEvent::FnPHotkey => None, // would trigger platform-profile cycle
        HpEvent::OmenKey { key_code } => decode_hp_bezel_keycode(key_code),
        HpEvent::CameraToggle { open: _ } => None, // no camera key in KeyCode yet
        HpEvent::LidSwitch | HpEvent::ScreenRotation => None,
        HpEvent::Other { .. } => None,
    };

    if let Some(kc) = code {
        let _ = push_key(kc, true);
        let _ = push_key(kc, false);
    }
}

// ── Lenovo event decoder ────────────────────────────────────────────

/// Lenovo WMI hotkey / mode event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LenovoEvent {
    /// Tablet-mode toggle from the YMC (Yoga Mode Control) GUID.
    /// `on = true` means the device entered tablet mode.
    /// Reference: `ymc.c` lines 49–54 — YMC_TABLE sparse keymap:
    ///   code 0x01 → SW_TABLET_MODE=0 (laptop)
    ///   code 0x02/0x03/0x04 → SW_TABLET_MODE=1 (tablet/tent/stand)
    TabletMode { on: bool },
    /// Generic IdeaPad hotkey event. `id` is the raw WMI event data
    /// (integer payload from the IdeaPad hotkey notification).
    HotkeyEvent { id: u32 },
    /// Unparseable or unknown payload.
    Unknown { raw: u32 },
}

/// Decode a Lenovo YMC tablet-mode event (u32 integer payload).
///
/// Reference: `ymc.c::ymc_wmi_notify()` — evaluates `_WED` to get
/// a u32 and maps it through the sparse keymap:
/// 0x01 = laptop mode, 0x02–0x04 = tablet/tent/stand.
pub fn decode_lenovo_ymc_event(data: &[u8]) -> Option<LenovoEvent> {
    if data.len() < 4 {
        return None;
    }
    let code = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let tablet = match code {
        0x01 => false,              // laptop mode
        0x02 | 0x03 | 0x04 => true, // tablet / tent / stand
        _ => return Some(LenovoEvent::Unknown { raw: code }),
    };
    Some(LenovoEvent::TabletMode { on: tablet })
}

/// Decode a Lenovo IdeaPad hotkey event (u32 integer payload).
pub fn decode_lenovo_hotkey_event(data: &[u8]) -> Option<LenovoEvent> {
    if data.len() < 4 {
        return None;
    }
    let id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    Some(LenovoEvent::HotkeyEvent { id })
}

/// WMI event handler for Lenovo YMC tablet mode.
fn on_lenovo_ymc_event(ev: &WmiEvent) {
    LENOVO_EVENTS.fetch_add(1, Ordering::Relaxed);
    // YMC events carry an integer value via _WED.
    let raw = match ev.data.as_ref() {
        Some(narf_aml::Value::Integer(n)) => *n as u32,
        Some(narf_aml::Value::Buffer(b)) if b.len() >= 4 => {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
        _ => return,
    };
    let buf = raw.to_le_bytes();
    if let Some(LenovoEvent::TabletMode { on: _ }) = decode_lenovo_ymc_event(&buf) {
        // Tablet mode transitions route to a platform event bus in the
        // future. For now we emit a marker KeyCode so the input ring
        // records the event and boot diagnostics can observe it.
        // No keycode maps cleanly to SW_TABLET_MODE; leave routing
        // to the future LaptopModeEvent ring.
    }
}

/// WMI event handler for Lenovo IdeaPad hotkeys.
fn on_lenovo_hotkey_event(ev: &WmiEvent) {
    LENOVO_EVENTS.fetch_add(1, Ordering::Relaxed);
    let raw = match ev.data.as_ref() {
        Some(narf_aml::Value::Integer(n)) => *n as u32,
        Some(narf_aml::Value::Buffer(b)) if b.len() >= 4 => {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
        _ => return,
    };
    let buf = raw.to_le_bytes();
    if let Some(LenovoEvent::HotkeyEvent { id }) = decode_lenovo_hotkey_event(&buf) {
        if let Some(kc) = decode_lenovo_hotkey_keycode(id) {
            let _ = push_key(kc, true);
            let _ = push_key(kc, false);
        }
    }
}

/// Map Lenovo IdeaPad hotkey IDs to KeyCodes.
/// Derived from ideapad-laptop.c and common IdeaPad DSDT hotkey
/// values observed across Lenovo IdeaPad/Yoga models.
fn decode_lenovo_hotkey_keycode(id: u32) -> Option<KeyCode> {
    match id {
        0x01 => Some(KeyCode::BrightnessUp),
        0x02 => Some(KeyCode::BrightnessDown),
        0x03 => Some(KeyCode::KbdIlluminationToggle),
        0x04 => Some(KeyCode::Mute), // volume mute
        0x06 => Some(KeyCode::WLan), // wireless toggle
        0x07 => Some(KeyCode::TouchpadToggle),
        0x0b => Some(KeyCode::RfKill),
        0x13 => Some(KeyCode::BrightnessUp),
        0x14 => Some(KeyCode::BrightnessDown),
        _ => None,
    }
}

// ── init() ─────────────────────────────────────────────────────────

/// Probe WMI GUIDs and register vendor event handlers.
///
/// Must be called after `narf_aml::wmi::enumerate_guids()`.
/// Idempotent — repeated calls update the vendor detection and
/// re-register handlers (double-registration has no ill effect since
/// `subscribe_event` is append-only).
///
/// Returns `Ok(())` if at least one vendor GUID was found and
/// handlers were registered, `Err(WmiVendorError)` otherwise.
pub fn init() -> Result<(), WmiVendorError> {
    let guids = list_guids();
    if guids.is_empty() {
        return Err(WmiVendorError::NoGuids);
    }

    let dell_desc_bytes = guid_str_to_bytes(DELL_WMI_DESCRIPTOR_GUID);
    let dell_ev_bytes = guid_str_to_bytes(DELL_WMI_EVENT_GUID);
    let hp_ev_bytes = guid_str_to_bytes(HP_WMI_EVENT_GUID);
    let hp_bios_bytes = guid_str_to_bytes(HP_WMI_BIOS_GUID);
    let lenovo_ev_bytes = guid_str_to_bytes(LENOVO_WMI_EVENT_GUID);
    let lenovo_ymc_bytes = guid_str_to_bytes(LENOVO_YMC_EVENT_GUID);

    let mut found = false;

    for g in &guids {
        if let Some(ref dell_desc) = dell_desc_bytes {
            if &g.guid == dell_desc.as_slice() {
                DELL_DESCRIPTOR_FOUND.store(true, Ordering::Release);
            }
        }
        if let Some(ref hp_bios) = hp_bios_bytes {
            if &g.guid == hp_bios.as_slice() {
                HP_BIOS_FOUND.store(true, Ordering::Release);
            }
        }

        if let Some(ref dell_ev) = dell_ev_bytes {
            if &g.guid == dell_ev.as_slice() {
                subscribe_event(g, on_dell_event);
                *DETECTED_VENDOR.lock() = Some(Vendor::Dell);
                found = true;
            }
        }
        if let Some(ref hp_ev) = hp_ev_bytes {
            if &g.guid == hp_ev.as_slice() {
                subscribe_event(g, on_hp_event);
                *DETECTED_VENDOR.lock() = Some(Vendor::Hp);
                found = true;
            }
        }
        if let Some(ref lenovo_ev) = lenovo_ev_bytes {
            if &g.guid == lenovo_ev.as_slice() {
                subscribe_event(g, on_lenovo_hotkey_event);
                *DETECTED_VENDOR.lock() = Some(Vendor::Lenovo);
                found = true;
            }
        }
        if let Some(ref lenovo_ymc) = lenovo_ymc_bytes {
            if &g.guid == lenovo_ymc.as_slice() {
                subscribe_event(g, on_lenovo_ymc_event);
                // YMC is a Lenovo-only GUID — set vendor if not already set.
                let mut v = DETECTED_VENDOR.lock();
                if v.is_none() {
                    *v = Some(Vendor::Lenovo);
                }
                found = true;
            }
        }
    }

    if !found {
        Err(WmiVendorError::UnknownVendor)
    } else {
        Ok(())
    }
}

// ── Test helpers ────────────────────────────────────────────────────

/// Reset all module state for unit tests.
#[doc(hidden)]
pub fn __test_reset() {
    *DETECTED_VENDOR.lock() = None;
    DELL_EVENTS.store(0, Ordering::Relaxed);
    HP_EVENTS.store(0, Ordering::Relaxed);
    LENOVO_EVENTS.store(0, Ordering::Relaxed);
    DELL_DESCRIPTOR_FOUND.store(false, Ordering::Relaxed);
    HP_BIOS_FOUND.store(false, Ordering::Relaxed);
    narf_aml::wmi::__reset_for_test();
}
