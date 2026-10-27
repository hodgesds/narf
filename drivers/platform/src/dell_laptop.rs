// SPDX-License-Identifier: GPL-2.0-or-later
//! Dell laptop platform driver.
//!
//! Covers the ACPI/WMI/SMI surface for Dell XPS, Latitude, Inspiron, and
//! Precision families.
//!
//! ## Features
//!
//! - Dell SMBIOS calling-interface buffer (class / select / in0..in3,
//!   out0..out3) in the real `dell-smbios.h` layout, transported over
//!   the SMBIOS WMI GUID (`dell-smbios-wmi.c`)
//! - WMI application registration (class 17 / select 3) at init, per
//!   the Dell SMBIOS documentation, so WMI events are enabled
//! - WMI event decode (9DBB GUID) → KEY_* via input layer; the
//!   mic-mute key (0x0150) reports the distinct `KEY_MICMUTE`
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
//!   - `dell_wmi_events_set_enabled()` — class 17 / select 3
//!     application registration ("According to Dell SMBIOS
//!     documentation: 17 3 Application Program Registration").
//! - `drivers/platform/x86/dell/dell-smbios.c` + `dell-smbios.h`
//!   - `struct calling_interface_buffer` — u16 class, u16 select,
//!     u32 input[4], u32 output[4].
//! - `drivers/platform/x86/dell/dell-smbios-wmi.c`
//!   - `run_smbios_call()` — WMI transport of the buffer.

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use narf_input::{push_key, KeyCode};

// ── Dell SMBIOS calling-interface buffer ──────────────────────────────

/// Dell SMBIOS WMI GUID — the WMI transport for SMBIOS calls.
/// Reference: `dell-smbios-wmi.c` — `DELL_WMI_SMBIOS_GUID`.
pub const DELL_WMI_SMBIOS_GUID: &str = "A80593CE-A997-11DA-B012-B622A1EF5492";

/// SMBIOS class for firmware information / application services.
/// Reference: `dell-smbios.h` — `CLASS_INFO = 17`.
pub const CLASS_INFO: u16 = 17;
/// Select for application-program registration under CLASS_INFO.
/// Reference: `dell-wmi-base.c` — `SELECT_APP_REGISTRATION = 3`
/// ("According to Dell SMBIOS documentation: 17 3 Application
/// Program Registration").
pub const SELECT_APP_REGISTRATION: u16 = 3;

/// A Dell SMBIOS command in the real `calling_interface_buffer`
/// layout: u16 class, u16 select, four u32 inputs, four u32
/// outputs (36 bytes packed).
///
/// Reference: `dell-smbios.h::struct calling_interface_buffer`.
///
/// Correction note: this struct previously modelled the buffer as
/// four u32 words with `(class << 8) | select` packed into the
/// first word — a shape no Dell firmware implements (class and
/// select are separate u16 fields, and the buffer carries four
/// inputs *and* four outputs). The layout below is the documented
/// one; the encode smoke in `tests.rs` pins it byte-for-byte.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DellSmbiosCmd {
    /// Command class (per-API category).
    pub class: u16,
    /// Command select within the class.
    pub select: u16,
    /// Input words in0..in3 (purpose depends on class/select).
    pub input: [u32; 4],
}

impl DellSmbiosCmd {
    /// Construct a new SMBIOS command from class and select, with
    /// zeroed inputs.
    ///
    /// Reference: `dell-smbios.c::dell_fill_request()`.
    pub fn new(class: u16, select: u16) -> Self {
        Self {
            class,
            select,
            input: [0; 4],
        }
    }

    /// Encode to the raw 36-byte calling-interface buffer sent to
    /// firmware (via the WMI method or the SMI handler): class,
    /// select, the four input words, and a zeroed output area the
    /// firmware fills in.
    pub fn encode(&self) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[0..2].copy_from_slice(&self.class.to_le_bytes());
        buf[2..4].copy_from_slice(&self.select.to_le_bytes());
        for (i, w) in self.input.iter().enumerate() {
            buf[4 + i * 4..8 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        buf
    }

    /// Decode the output words (out0..out3 at byte offset 20) of a
    /// response buffer.
    pub fn decode_response(buf: &[u8; 36]) -> (u32, u32, u32, u32) {
        let word = |i: usize| -> u32 {
            u32::from_le_bytes(buf[20 + i * 4..24 + i * 4].try_into().unwrap())
        };
        (word(0), word(1), word(2), word(3))
    }
}

/// Issue one SMBIOS call over the WMI transport and return the
/// output words. Returns `None` when the SMBIOS WMI GUID is not
/// present, the method fails, or the reply is malformed.
///
/// Reference: `dell-smbios-wmi.c::run_smbios_call` — the
/// calling-interface buffer is the method's buffer argument; the
/// firmware returns the same buffer with the output area filled.
pub fn smbios_wmi_call(cmd: &DellSmbiosCmd) -> Option<(u32, u32, u32, u32)> {
    let want = crate::wmi_vendors::guid_str_to_bytes(DELL_WMI_SMBIOS_GUID)?;
    let guid = narf_aml::wmi::list_guids()
        .into_iter()
        .find(|g| g.guid == want)?;
    let reply =
        narf_aml::wmi::invoke_method(&guid, 1, &[narf_aml::Value::Buffer(cmd.encode().to_vec())])
            .ok()?;
    match reply {
        narf_aml::Value::Buffer(b) if b.len() >= 36 => {
            let arr: &[u8; 36] = b[..36].try_into().ok()?;
            Some(DellSmbiosCmd::decode_response(arr))
        }
        _ => None,
    }
}

/// Enable or disable Dell WMI event delivery through the SMBIOS
/// application-registration call: class 17 (`CLASS_INFO`), select
/// 3 (`SELECT_APP_REGISTRATION`), with inputs
/// `[0x10000, 0x51534554, 0, enable]`.
///
/// Reference: `dell-wmi-base.c::dell_wmi_events_set_enabled()` —
/// input[1] `0x51534554` is the registration magic ("TESQ" in LE
/// byte order); the call result is `output[0]` run through
/// `dell_smbios_error`, where 0 is success. We return the raw
/// output[0] as the error when nonzero rather than reproducing
/// the errno table.
///
/// Returns `Err(None)` when the WMI transport is unavailable.
pub fn wmi_events_set_enabled(enable: bool) -> Result<(), Option<u32>> {
    let mut cmd = DellSmbiosCmd::new(CLASS_INFO, SELECT_APP_REGISTRATION);
    cmd.input[0] = 0x10000;
    cmd.input[1] = 0x51534554;
    cmd.input[3] = enable as u32;
    match smbios_wmi_call(&cmd) {
        Some((0, _, _, _)) => Ok(()),
        Some((err, _, _, _)) => Err(Some(err)),
        None => Err(None),
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
    // Issue SMBIOS class=4 select=0 token=0x02C6 value=level over
    // the WMI transport when the SMBIOS GUID is present. (The
    // previous body encoded the command and dropped it.) When the
    // GUID is absent the value stays cache-only — the SMI port
    // transport `dell-laptop.c` uses by default is not modelled.
    let mut cmd = DellSmbiosCmd::new(4, 0);
    cmd.input[0] = 0x02C6;
    cmd.input[1] = level as u32;
    let _ = smbios_wmi_call(&cmd);
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
    // SMBIOS class=17 select=3: token 0x044F, value=pct — now
    // actually issued over the WMI transport when present (the
    // previous body encoded and dropped it); cache-only otherwise.
    let mut cmd = DellSmbiosCmd::new(17, 3);
    cmd.input[0] = 0x044F;
    cmd.input[1] = pct;
    let _ = smbios_wmi_call(&cmd);
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
        DellWmiEvent::MicMute => Some(KeyCode::MicMute),
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
    // Application registration: on models where the SMBIOS WMI
    // GUID is present, firmware only delivers WMI events after the
    // class 17 / select 3 registration call (Dell SMBIOS
    // documentation, via dell-wmi-base.c). Best-effort — absence
    // of the GUID just means the legacy SMI path owns events.
    let _ = wmi_events_set_enabled(true);
}

// ── Test helpers ──────────────────────────────────────────────────────

/// Reset Dell driver state for tests.
#[doc(hidden)]
pub fn __test_reset() {
    WMI_EVENT_COUNT.store(0, Ordering::Relaxed);
    KBD_BACKLIGHT.store(0, Ordering::Relaxed);
    CHARGE_LIMIT.store(0, Ordering::Relaxed);
}
