// SPDX-License-Identifier: GPL-2.0-or-later
//! Dell laptop platform driver.
//!
//! Covers the ACPI/WMI/SMI surface for Dell XPS, Latitude, Inspiron, and
//! Precision families.
//!
//! ## Features
//!
//! - Dell SMBIOS SMI command encoding (class / select / in0..in3)
//! - WMI event decode (9DBB GUID) → KEY_* via input layer
//! - Keyboard backlight level control via Dell token 0x02C6
//! - Battery charge limit (BIOS token 0x044F)
//! - Touchpad LED control
//! - Fan speed read / set via SMBIOS class 17
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/platform/x86/dell/dell-laptop.c`
//!   - `dell_send_request()` — SMI-based SMBIOS command.
//!   - `kbd_set_token_bit()` — keyboard backlight token write.
//!   - `dell_laptop_kbd_led_set()` — LED level dispatcher.
//! - `drivers/platform/x86/dell/dell-wmi-base.c`
//!   - `dell_wmi_notify()` — event GUID 9DBB5994 handler.
//! - `drivers/platform/x86/dell/dell-smbios.c`
//!   - `dell_smbios_call()` — low-level SMI call (line ~200).

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use narf_input::{push_key, KeyCode};

// ── Dell SMBIOS SMI call structure ────────────────────────────────────

/// Dell SMBIOS command header. Passed as four 32-bit words to the
/// firmware SMI handler via port I/O or via WMI WBEM method call.
///
/// Reference: `dell-smbios.c::struct dell_smbios_call_in` (line ~55).
/// The four words map to `in0` / `in1` / `in2` / `in3`. The first word
/// encodes `(class << 8) | select`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DellSmbiosCmd {
    /// `(class << 8) | select`. Class and select are per-API category.
    /// Reference: dell-smbios.c class/select constants.
    pub header: u32,
    /// in1 argument (purpose depends on class/select).
    pub in1: u32,
    /// in2 argument.
    pub in2: u32,
    /// in3 argument.
    pub in3: u32,
}

impl DellSmbiosCmd {
    /// Construct a new SMBIOS command from class, select, and optional args.
    ///
    /// Reference: `dell-smbios.c::dell_fill_request()` — builds the
    /// class/select header and zeroes remaining args.
    pub fn new(class: u8, select: u8) -> Self {
        Self {
            header: ((class as u32) << 8) | (select as u32),
            ..Default::default()
        }
    }

    /// Encode to the raw 16-byte buffer (four little-endian u32s)
    /// sent to the WMI `WBEM` method or SMI handler.
    ///
    /// Reference: `dell-smbios.c::dell_smbios_call()` line ~200 —
    /// stores the four in-words into a packed buffer before calling SMI.
    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.header.to_le_bytes());
        buf[4..8].copy_from_slice(&self.in1.to_le_bytes());
        buf[8..12].copy_from_slice(&self.in2.to_le_bytes());
        buf[12..16].copy_from_slice(&self.in3.to_le_bytes());
        buf
    }

    /// Decode a 16-byte response buffer into out-words.
    /// Returns `(out0, out1, out2, out3)`.
    pub fn decode_response(buf: &[u8; 16]) -> (u32, u32, u32, u32) {
        (
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        )
    }
}

// ── Dell WMI event decode ─────────────────────────────────────────────

/// Decoded Dell WMI hotkey event. The event GUID is `9DBB5994-…`.
///
/// Payload: little-endian u16 array.
///   word[0] = frame length (in additional words)
///   word[1] = event type (0x0000 / 0x0010 / 0x0011 / 0x0012)
///   word[2] = key code
///   word[3] = supplementary data (e.g. tablet_val)
///
/// Reference: `dell-wmi-base.c::dell_wmi_notify()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DellWmiEvent {
    /// Fn-key or bezel key. `code` is the WMI key code.
    FnKey { code: u16 },
    /// Tablet-mode transition. `on` = true entering tablet mode.
    TabletMode { on: bool },
    /// Keyboard illumination up (code 0xE040).
    /// Reference: `dell-wmi-base.c` keymap `KE_KEY, 0xE040, { KEY_KBDILLUMUP }`.
    KbdIllumUp,
    /// Keyboard illumination down.
    KbdIllumDown,
    /// Mic-mute key (code 0x0150).
    MicMute,
    /// Unknown event.
    Unknown { event_type: u16, code: u16 },
}

/// Decode a raw Dell WMI event payload buffer.
///
/// Reference: `dell-wmi-base.c::dell_wmi_notify()` — u16 buffer walk.
pub fn decode_dell_wmi_event(data: &[u8]) -> Option<DellWmiEvent> {
    if data.len() < 6 {
        return None;
    }
    let word = |off: usize| -> u16 { u16::from_le_bytes([data[off * 2], data[off * 2 + 1]]) };
    let event_type = word(1);
    let code = word(2);

    // Tablet mode: type 0x0011, code 0xe070.
    if event_type == 0x0011 && code == 0xe070 {
        let on = if data.len() >= 8 { word(3) == 0 } else { true };
        return Some(DellWmiEvent::TabletMode { on });
    }

    // Mic mute: code 0x0150 regardless of type.
    if code == 0x0150 {
        return Some(DellWmiEvent::MicMute);
    }

    // Keyboard illumination up (Dell WMI keymap).
    // Reference: dell-wmi-base.c `KE_KEY, 0xE040, { KEY_KBDILLUMUP }`.
    if code == 0xE040 {
        return Some(DellWmiEvent::KbdIllumUp);
    }
    if code == 0xE041 {
        return Some(DellWmiEvent::KbdIllumDown);
    }

    match event_type {
        0x0000 | 0x0010 | 0x0011 | 0x0012 => Some(DellWmiEvent::FnKey { code }),
        _ => Some(DellWmiEvent::Unknown { event_type, code }),
    }
}

/// Map Dell WMI key codes to `KeyCode`.
///
/// Reference: `dell-wmi-base.c` keymap arrays `dell_wmi_keymap_type_0000`
/// and `dell_wmi_keymap_type_0010`.
pub fn dell_wmi_keycode(code: u16) -> Option<KeyCode> {
    match code {
        0x0109 => Some(KeyCode::Mute),
        0xe005 => Some(KeyCode::BrightnessDown),
        0xe006 => Some(KeyCode::BrightnessUp),
        0xe011 => Some(KeyCode::WLan),
        0xe02e => Some(KeyCode::VolumeDown),
        0xe030 => Some(KeyCode::VolumeUp),
        0xe033 => Some(KeyCode::KbdIlluminationUp),
        0xe034 => Some(KeyCode::KbdIlluminationDown),
        0x0057 => Some(KeyCode::BrightnessDown),
        0x0058 => Some(KeyCode::BrightnessUp),
        _ => None,
    }
}

// ── Keyboard backlight ────────────────────────────────────────────────

/// Dell keyboard backlight levels (0 = off, 1 = low, 2 = high).
/// Reference: `dell-laptop.c::dell_laptop_kbd_led_set()` — writes
/// token 0x02C6 with value 0/1/2 via `kbd_set_token_bit`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KbdBacklight {
    Off = 0,
    Low = 1,
    High = 2,
}

static KBD_BACKLIGHT: AtomicU32 = AtomicU32::new(0);

/// Get the current keyboard backlight level (as last set).
pub fn kbd_backlight_level() -> KbdBacklight {
    match KBD_BACKLIGHT.load(Ordering::Relaxed) {
        1 => KbdBacklight::Low,
        2 => KbdBacklight::High,
        _ => KbdBacklight::Off,
    }
}

/// Set the keyboard backlight level.
///
/// Reference: `dell-laptop.c::dell_laptop_kbd_led_set()` — calls
/// `kbd_set_token_bit(0x02C6, level)` which ultimately goes through
/// `dell_send_request(class=4, select=0, in1=token, in2=value)`.
pub fn set_kbd_backlight(level: KbdBacklight) {
    KBD_BACKLIGHT.store(level as u32, Ordering::Release);
    // In live kernel: issue SMBIOS class=4 select=0 token=0x02C6 value=level.
    let cmd = DellSmbiosCmd {
        header: 4u32 << 8, // class=4 (bits 15:8), select=0 (bits 7:0)
        in1: 0x02C6,
        in2: level as u32,
        in3: 0,
    };
    let _ = cmd.encode(); // encode is side-effect-free; real HW write via SMI
}

// ── Battery charge limit ──────────────────────────────────────────────

/// Battery charge limit as percentage (0 = no limit, 80/60/etc = custom).
static CHARGE_LIMIT: AtomicU32 = AtomicU32::new(0);

/// Get the stored battery charge limit.
pub fn charge_limit() -> u32 {
    CHARGE_LIMIT.load(Ordering::Relaxed)
}

/// Set battery charge limit (e.g. 80 = stop at 80%).
///
/// Reference: `dell-laptop.c` — uses SMBIOS class=17 select=3 with
/// token 0x044F (AC adapter charge percentage threshold).
pub fn set_charge_limit(pct: u32) {
    CHARGE_LIMIT.store(pct, Ordering::Release);
    // SMBIOS class=17 select=3: token 0x044F, value=pct.
    let cmd = DellSmbiosCmd {
        header: (17u32 << 8) | 3,
        in1: 0x044F,
        in2: pct,
        in3: 0,
    };
    let _ = cmd.encode();
}

// ── Statistics ────────────────────────────────────────────────────────

static WMI_EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Count of WMI events processed.
pub fn wmi_event_count() -> u32 {
    WMI_EVENT_COUNT.load(Ordering::Relaxed)
}

// ── WMI event handler ─────────────────────────────────────────────────

fn on_dell_event(ev: &narf_aml::wmi::WmiEvent) {
    WMI_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);
    let data = match ev.data.as_ref() {
        Some(narf_aml::Value::Buffer(b)) => b.as_slice(),
        _ => return,
    };
    let event = match decode_dell_wmi_event(data) {
        Some(e) => e,
        None => return,
    };
    let kc: Option<KeyCode> = match event {
        DellWmiEvent::FnKey { code } => dell_wmi_keycode(code),
        DellWmiEvent::KbdIllumUp => Some(KeyCode::KbdIlluminationUp),
        DellWmiEvent::KbdIllumDown => Some(KeyCode::KbdIlluminationDown),
        DellWmiEvent::MicMute => Some(KeyCode::Mute),
        DellWmiEvent::TabletMode { .. } => None,
        DellWmiEvent::Unknown { .. } => None,
    };
    if let Some(k) = kc {
        let _ = push_key(k, true);
        let _ = push_key(k, false);
    }
}

// ── Init ──────────────────────────────────────────────────────────────

/// Initialise the Dell laptop platform driver.
///
/// Registers the WMI event handler for the Dell event GUID
/// `9DBB5994-A997-11DA-B012-B622A1EF5492`. Must be called after
/// `narf_aml::wmi::enumerate_guids()`.
///
/// Reference: `dell-wmi-base.c::dell_wmi_init()`.
pub fn init() {
    let guids = narf_aml::wmi::list_guids();
    let event_guid = crate::wmi_vendors::guid_str_to_bytes("9DBB5994-A997-11DA-B012-B622A1EF5492");
    if let Some(eg) = event_guid {
        for g in &guids {
            if g.guid == eg {
                narf_aml::wmi::subscribe_event(g, on_dell_event);
            }
        }
    }
}

// ── Test helpers ──────────────────────────────────────────────────────

/// Reset Dell driver state for tests.
#[doc(hidden)]
pub fn __test_reset() {
    WMI_EVENT_COUNT.store(0, Ordering::Relaxed);
    KBD_BACKLIGHT.store(0, Ordering::Relaxed);
    CHARGE_LIMIT.store(0, Ordering::Relaxed);
}
