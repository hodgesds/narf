//! HID Keyboard / Keypad profile decoder — clean-room.
//!
//! ## Sources (public only)
//!
//! - **HID 1.11 §B.1** — "Keyboard" boot-interface Report Descriptor
//!   (the 8-bit modifier byte + 1 reserved byte + 6-byte key array
//!   shape every keyboard advertises). Also §6.2.2 for descriptor
//!   parsing (already in [`crate::descriptor`]).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - **HID Usage Tables 1.4 §10** — Keyboard/Keypad page (0x07). The
//!   [`hid_usage_to_keycode`] table maps every usage id we handle to
//!   its Linux `KEY_*` code.
//! - **HID Usage Tables 1.4 §15** — Consumer page (0x0C). Laptop
//!   keyboards route Fn/media keys (volume, brightness, transport
//!   controls) through a separate Consumer Control collection;
//!   [`consumer_usage_to_keycode`] maps those.
//!   <https://usb.org/document-library/hid-usage-tables-14>
//!
//! Linux source not consulted; the `KEY_*` code *values* are the
//! architecture-neutral UAPI numbers from
//! `include/uapi/linux/input-event-codes.h`, which are ABI-stable and
//! carry the Linux-syscall-note license exception.
//!
//! ## What this module is
//!
//! A *profile probe* + *report decoder* on top of a parsed
//! [`ReportDescriptor`]:
//!
//! - [`detect`] returns `Some(KeyboardProfile)` iff the descriptor
//!   declares a Keyboard Application Collection (Generic Desktop page,
//!   usage 0x06 Keyboard) with a key-array Input field on the Keyboard
//!   usage page. The optional modifier bitmap field is captured too.
//! - [`decode_input`] applies the profile to one Input report and
//!   produces a [`DecodedKeyboardReport`]: the set of currently-pressed
//!   HID keyboard usages (from the array field) plus the modifier
//!   bitmap. Report diffing (press / release / autorepeat) is the
//!   transport layer's job — this module only decodes one frame.
//!
//! - [`detect_consumer`] / [`decode_consumer`] handle the separate
//!   Consumer Control collection a laptop uses for Fn/media keys.

extern crate alloc;
use alloc::vec::Vec;

use crate::descriptor::{Field, FieldFlags, FieldKind, ReportDescriptor};
use crate::report::{array_active_usages, extract, ReportError};
use crate::usage::{consumer, generic_desktop, keyboard};

/// Standard boot-keyboard modifier bit positions (HID Usage Tables
/// 1.4 §10, usages 0xE0..=0xE7). Bit N in the modifier byte
/// corresponds to `0xE0 + N`. Exposed so the transport layer can
/// diff modifier state without re-deriving the bit order.
pub mod modbit {
    pub const LEFT_CTRL: u8 = 1 << 0; // usage 0xE0
    pub const LEFT_SHIFT: u8 = 1 << 1; // usage 0xE1
    pub const LEFT_ALT: u8 = 1 << 2; // usage 0xE2
    pub const LEFT_GUI: u8 = 1 << 3; // usage 0xE3 (Meta / Super / Win)
    pub const RIGHT_CTRL: u8 = 1 << 4; // usage 0xE4
    pub const RIGHT_SHIFT: u8 = 1 << 5; // usage 0xE5
    pub const RIGHT_ALT: u8 = 1 << 6; // usage 0xE6
    pub const RIGHT_GUI: u8 = 1 << 7; // usage 0xE7
}

/// Result of [`detect`]. Points at the parsed [`Field`]s a runtime
/// decoder extracts values from; the descriptor is parsed once and
/// never re-walked per report.
#[derive(Clone, Debug)]
pub struct KeyboardProfile {
    /// Report ID of the Input report carrying key data. `0` when the
    /// descriptor declares no Report IDs (the classic boot keyboard
    /// shape — HID §B.1 uses no report id).
    pub input_report_id: u8,
    /// The 8-bit (or wider) modifier bitmap field (Keyboard usages
    /// 0xE0..=0xE7 declared as a Variable Input). `None` for the rare
    /// keyboard that omits a discrete modifier field and folds the
    /// modifiers into the key array.
    pub modifiers: Option<Field>,
    /// The key-array Input field (Array flag clear/Variable clear):
    /// `report_count` slots, each an 8-bit index into the Keyboard
    /// usage page. This is the load-bearing field — a keyboard with
    /// no array field isn't decodable as a boot-style keyboard.
    pub keys: Field,
}

/// Probe a parsed descriptor for a Keyboard Application Collection.
/// Returns `Some` iff the descriptor declares a top-level Generic
/// Desktop / Keyboard (0x01/0x06) application collection AND carries
/// a key-array Input field on the Keyboard usage page (0x07).
///
/// A device may present *both* a keyboard and a touch collection
/// (2-in-1 keyboards with an integrated touchpad); this probe only
/// claims the keyboard collection and leaves the digitizer collections
/// for `touchscreen::detect` / `ptp::detect`.
pub fn detect(d: &ReportDescriptor) -> Option<KeyboardProfile> {
    let has_keyboard_root = d
        .top_level_apps
        .iter()
        .any(|&(p, u)| p == generic_desktop::PAGE && u == generic_desktop::KEYBOARD);
    if !has_keyboard_root {
        return None;
    }

    // The key array is an Input field on the Keyboard page whose
    // Variable flag is clear (an Array). HID §B.1's key array declares
    // `Usage Min 0 / Usage Max 101` on page 0x07 with `Input(Array)`.
    // We accept any Array Input field on page 0x07 with report_size 8.
    let keys = d
        .fields
        .iter()
        .find(|f| {
            f.kind == FieldKind::Input
                && f.usage_page == keyboard::PAGE
                && !f.flags.contains(FieldFlags::VARIABLE)
                && !f.flags.contains(FieldFlags::CONSTANT)
                && f.report_size == 8
        })?
        .clone();
    let input_report_id = keys.report_id;

    // The modifier field is a Variable Input on the Keyboard page whose
    // usages span 0xE0..=0xE7 (declared via Usage Min/Max). Bind to the
    // first such field in the same report; absence is tolerated.
    let modifiers = d
        .fields
        .iter()
        .find(|f| {
            f.kind == FieldKind::Input
                && f.report_id == input_report_id
                && f.usage_page == keyboard::PAGE
                && f.flags.contains(FieldFlags::VARIABLE)
                && field_covers_modifier_range(f)
        })
        .cloned();

    Some(KeyboardProfile {
        input_report_id,
        modifiers,
        keys,
    })
}

/// `true` when `f`'s local usage range (or explicit usage list)
/// includes the modifier usages 0xE0..=0xE7 on the Keyboard page.
fn field_covers_modifier_range(f: &Field) -> bool {
    if let (Some((_, lo)), Some((_, hi))) = (f.usage_min, f.usage_max) {
        return lo <= 0xE0 && hi >= 0xE0;
    }
    f.usages.iter().any(|&(_, id)| (0xE0..=0xE7).contains(&id))
}

/// Decoded view of one keyboard Input report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedKeyboardReport {
    /// Raw modifier bitmap (bits per [`modbit`]). `0` when the
    /// descriptor had no modifier field.
    pub modifiers: u8,
    /// HID Keyboard-page usage ids currently held down, from the key
    /// array (zeros / rollover-error codes dropped). Order follows the
    /// device's array slots.
    pub keys: Vec<u16>,
}

impl DecodedKeyboardReport {
    /// `true` if HID keyboard usage `usage` is held in this report.
    pub fn holds(&self, usage: u16) -> bool {
        self.keys.contains(&usage)
    }
}

/// Decode one Input report. `report` is the wire bytes including the
/// leading 1-byte Report ID when the descriptor uses report ids; this
/// function strips the prefix itself. Reports whose leading id doesn't
/// match the profile are rejected as `Short` so the bind layer treats
/// them as "not for me".
pub fn decode_input(
    p: &KeyboardProfile,
    report: &[u8],
) -> Result<DecodedKeyboardReport, ReportError> {
    if report.is_empty() {
        return Err(ReportError::Short);
    }
    if p.input_report_id != 0 && report[0] != p.input_report_id {
        return Err(ReportError::Short);
    }
    let body = if p.input_report_id != 0 {
        &report[1..]
    } else {
        report
    };

    let modifiers = match &p.modifiers {
        Some(f) => {
            // Variable bitmap: one value (0/1) per bit slot; fold back
            // into a byte using the field's usage order (bit N = the
            // Nth extracted value = usage_min + N).
            let bits = extract(f, body)?;
            let mut acc = 0u8;
            for (i, v) in bits.iter().enumerate().take(8) {
                if *v != 0 {
                    acc |= 1u8 << i;
                }
            }
            acc
        }
        None => 0,
    };

    // The key array reports the active usage *ids* directly (Usage Min
    // is 0 in the boot descriptor, so `array_active_usages` returns the
    // value itself as the usage id). Rollover-error codes (0x01..=0x03)
    // are the standard "too many keys" sentinels — drop them.
    let mut keys = Vec::new();
    for (_pg, id) in array_active_usages(&p.keys, body)? {
        if id >= 0x04 {
            keys.push(id);
        }
    }

    Ok(DecodedKeyboardReport { modifiers, keys })
}

// ── Consumer Control (Fn / media keys) ────────────────────────────

/// Result of [`detect_consumer`]. A laptop's Fn row (volume,
/// brightness, transport) usually lives in a separate Consumer Control
/// Application Collection (Consumer page 0x0C) that reports one or more
/// active consumer usages per frame.
#[derive(Clone, Debug)]
pub struct ConsumerProfile {
    pub input_report_id: u8,
    /// The consumer usage field. Modern laptops declare this either as
    /// an Array (index → consumer usage) or as a bank of Variable bits;
    /// we capture the field and let the decoder handle both shapes.
    pub field: Field,
}

/// Probe for a Consumer Control Application Collection (Consumer page,
/// usage 0x01 Consumer Control). Returns `Some` iff such a top-level
/// collection exists with at least one Consumer-page Input field.
pub fn detect_consumer(d: &ReportDescriptor) -> Option<ConsumerProfile> {
    let has_consumer_root = d
        .top_level_apps
        .iter()
        .any(|&(p, u)| p == consumer::PAGE && u == consumer::CONSUMER_CONTROL);
    if !has_consumer_root {
        return None;
    }
    let field = d
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Input && f.usage_page == consumer::PAGE)?
        .clone();
    Some(ConsumerProfile {
        input_report_id: field.report_id,
        field,
    })
}

/// Decode one Consumer Control Input report into the list of active
/// consumer usage ids. Handles both the Array shape (usage indices)
/// and the Variable bitmap shape (one bit per declared usage).
pub fn decode_consumer(p: &ConsumerProfile, report: &[u8]) -> Result<Vec<u16>, ReportError> {
    if report.is_empty() {
        return Err(ReportError::Short);
    }
    if p.input_report_id != 0 && report[0] != p.input_report_id {
        return Err(ReportError::Short);
    }
    let body = if p.input_report_id != 0 {
        &report[1..]
    } else {
        report
    };

    let mut out = Vec::new();
    if p.field.flags.contains(FieldFlags::VARIABLE) {
        // Variable bank: bit N set → the Nth declared usage is active.
        let bits = extract(&p.field, body)?;
        for (i, v) in bits.iter().enumerate() {
            if *v != 0 {
                if let Some(&(_, id)) = p.field.usages.get(i) {
                    out.push(id);
                }
            }
        }
    } else {
        // Array: each slot holds a consumer usage id (or index).
        for (_pg, id) in array_active_usages(&p.field, body)? {
            if id != 0 {
                out.push(id);
            }
        }
    }
    Ok(out)
}

// ── HID usage → Linux KEY_* translation ───────────────────────────

/// Linux `KEY_*` codes (subset used by the keyboard translation
/// tables). Values are the ABI-stable numbers from
/// `include/uapi/linux/input-event-codes.h`. Duplicated here at the
/// *value* level so the `narf-hid` crate stays transport- and
/// input-core-neutral (no dependency on `narf-input`); the driver
/// layer's `narf_input::evdev::key` module carries the same constants
/// for evdev emission. Keep the two in sync.
mod key {
    pub const RESERVED: u16 = 0;
    pub const ESC: u16 = 1;
    pub const K1: u16 = 2;
    pub const K0: u16 = 11;
    pub const MINUS: u16 = 12;
    pub const EQUAL: u16 = 13;
    pub const BACKSPACE: u16 = 14;
    pub const TAB: u16 = 15;
    pub const Q: u16 = 16;
    pub const ENTER: u16 = 28;
    pub const LEFTCTRL: u16 = 29;
    pub const A: u16 = 30;
    pub const LEFTBRACE: u16 = 26;
    pub const RIGHTBRACE: u16 = 27;
    pub const SEMICOLON: u16 = 39;
    pub const APOSTROPHE: u16 = 40;
    pub const GRAVE: u16 = 41;
    pub const LEFTSHIFT: u16 = 42;
    pub const BACKSLASH: u16 = 43;
    pub const Z: u16 = 44;
    pub const COMMA: u16 = 51;
    pub const DOT: u16 = 52;
    pub const SLASH: u16 = 53;
    pub const RIGHTSHIFT: u16 = 54;
    pub const KPASTERISK: u16 = 55;
    pub const LEFTALT: u16 = 56;
    pub const SPACE: u16 = 57;
    pub const CAPSLOCK: u16 = 58;
    pub const F1: u16 = 59;
    pub const NUMLOCK: u16 = 69;
    pub const SCROLLLOCK: u16 = 70;
    pub const KP7: u16 = 71;
    pub const KP8: u16 = 72;
    pub const KP9: u16 = 73;
    pub const KPMINUS: u16 = 74;
    pub const KP4: u16 = 75;
    pub const KP5: u16 = 76;
    pub const KP6: u16 = 77;
    pub const KPPLUS: u16 = 78;
    pub const KP1: u16 = 79;
    pub const KP2: u16 = 80;
    pub const KP3: u16 = 81;
    pub const KP0: u16 = 82;
    pub const KPDOT: u16 = 83;
    pub const K102ND: u16 = 86;
    pub const F11: u16 = 87;
    pub const F12: u16 = 88;
    pub const KPENTER: u16 = 96;
    pub const RIGHTCTRL: u16 = 97;
    pub const KPSLASH: u16 = 98;
    pub const SYSRQ: u16 = 99;
    pub const RIGHTALT: u16 = 100;
    pub const HOME: u16 = 102;
    pub const UP: u16 = 103;
    pub const PAGEUP: u16 = 104;
    pub const LEFT: u16 = 105;
    pub const RIGHT: u16 = 106;
    pub const END: u16 = 107;
    pub const DOWN: u16 = 108;
    pub const PAGEDOWN: u16 = 109;
    pub const INSERT: u16 = 110;
    pub const DELETE: u16 = 111;
    pub const MUTE: u16 = 113;
    pub const VOLUMEDOWN: u16 = 114;
    pub const VOLUMEUP: u16 = 115;
    pub const POWER: u16 = 116;
    pub const KPEQUAL: u16 = 117;
    pub const PAUSE: u16 = 119;
    pub const KPCOMMA: u16 = 121;
    pub const LEFTMETA: u16 = 125;
    pub const RIGHTMETA: u16 = 126;
    pub const COMPOSE: u16 = 127;
    pub const MENU: u16 = 139;
    pub const NEXTSONG: u16 = 163;
    pub const PLAYPAUSE: u16 = 164;
    pub const PREVIOUSSONG: u16 = 165;
    pub const STOPCD: u16 = 166;
    pub const SEARCH: u16 = 217;
    pub const BRIGHTNESSDOWN: u16 = 224;
    pub const BRIGHTNESSUP: u16 = 225;
}

/// Map a HID Keyboard/Keypad-page (0x07) usage id to its Linux
/// `KEY_*` code. Returns `None` for usages with no evdev mapping
/// (reserved / rollover-error codes / unassigned).
///
/// Coverage: letters (a..z), digit row, F1..F12, the modifier keys
/// (left/right ctrl/shift/alt/gui), enter/esc/backspace/tab/space,
/// the punctuation cluster, arrows + navigation cluster (Home/End/
/// PageUp/PageDown/Insert/Delete), the keypad, and the lock keys.
/// Reference: HID Usage Tables 1.4 §10 alongside
/// `include/uapi/linux/input-event-codes.h`.
pub fn hid_usage_to_keycode(usage: u16) -> Option<u16> {
    // Letters: HID a=0x04..z=0x1D → KEY_A(30)-anchored via the Linux
    // scancode order (which is *not* alphabetical), so table it.
    let code = match usage {
        0x04 => key::A, // a
        0x05 => 48,     // b
        0x06 => 46,     // c
        0x07 => 32,     // d
        0x08 => 18,     // e
        0x09 => 33,     // f
        0x0A => 34,     // g
        0x0B => 35,     // h
        0x0C => 23,     // i
        0x0D => 36,     // j
        0x0E => 37,     // k
        0x0F => 38,     // l
        0x10 => 50,     // m
        0x11 => 49,     // n
        0x12 => 24,     // o
        0x13 => 25,     // p
        0x14 => key::Q, // q
        0x15 => 19,     // r
        0x16 => 31,     // s
        0x17 => 20,     // t
        0x18 => 22,     // u
        0x19 => 47,     // v
        0x1A => 17,     // w
        0x1B => 45,     // x
        0x1C => 21,     // y
        0x1D => key::Z, // z
        // Digit row 1..0 (HID 0x1E..0x27).
        0x1E => key::K1, // 1
        0x1F => 3,       // 2
        0x20 => 4,       // 3
        0x21 => 5,       // 4
        0x22 => 6,       // 5
        0x23 => 7,       // 6
        0x24 => 8,       // 7
        0x25 => 9,       // 8
        0x26 => 10,      // 9
        0x27 => key::K0, // 0
        // Control cluster.
        0x28 => key::ENTER,
        0x29 => key::ESC,
        0x2A => key::BACKSPACE,
        0x2B => key::TAB,
        0x2C => key::SPACE,
        0x2D => key::MINUS,
        0x2E => key::EQUAL,
        0x2F => key::LEFTBRACE,
        0x30 => key::RIGHTBRACE,
        0x31 => key::BACKSLASH,
        0x32 => key::BACKSLASH, // Non-US # and ~ → maps to backslash on ISO
        0x33 => key::SEMICOLON,
        0x34 => key::APOSTROPHE,
        0x35 => key::GRAVE,
        0x36 => key::COMMA,
        0x37 => key::DOT,
        0x38 => key::SLASH,
        0x39 => key::CAPSLOCK,
        // Function row F1..F12 (HID 0x3A..0x45).
        0x3A => key::F1,
        0x3B => key::F1 + 1,
        0x3C => key::F1 + 2,
        0x3D => key::F1 + 3,
        0x3E => key::F1 + 4,
        0x3F => key::F1 + 5,
        0x40 => key::F1 + 6,
        0x41 => key::F1 + 7,
        0x42 => key::F1 + 8,
        0x43 => key::F1 + 9, // F10 = 68
        0x44 => key::F11,
        0x45 => key::F12,
        // System keys.
        0x46 => key::SYSRQ, // PrintScreen
        0x47 => key::SCROLLLOCK,
        0x48 => key::PAUSE,
        // Nav cluster.
        0x49 => key::INSERT,
        0x4A => key::HOME,
        0x4B => key::PAGEUP,
        0x4C => key::DELETE,
        0x4D => key::END,
        0x4E => key::PAGEDOWN,
        0x4F => key::RIGHT,
        0x50 => key::LEFT,
        0x51 => key::DOWN,
        0x52 => key::UP,
        // Keypad.
        0x53 => key::NUMLOCK,
        0x54 => key::KPSLASH,
        0x55 => key::KPASTERISK,
        0x56 => key::KPMINUS,
        0x57 => key::KPPLUS,
        0x58 => key::KPENTER,
        0x59 => key::KP1,
        0x5A => key::KP2,
        0x5B => key::KP3,
        0x5C => key::KP4,
        0x5D => key::KP5,
        0x5E => key::KP6,
        0x5F => key::KP7,
        0x60 => key::KP8,
        0x61 => key::KP9,
        0x62 => key::KP0,
        0x63 => key::KPDOT,
        0x64 => key::K102ND,  // Non-US \ and |
        0x65 => key::COMPOSE, // Application / Menu
        0x66 => key::POWER,
        0x67 => key::KPEQUAL,
        0x85 => key::KPCOMMA,
        0x87 => key::RIGHTSHIFT, // International1 (Ro) — rare; approx
        // Modifiers (HID 0xE0..0xE7).
        0xE0 => key::LEFTCTRL,
        0xE1 => key::LEFTSHIFT,
        0xE2 => key::LEFTALT,
        0xE3 => key::LEFTMETA,
        0xE4 => key::RIGHTCTRL,
        0xE5 => key::RIGHTSHIFT,
        0xE6 => key::RIGHTALT,
        0xE7 => key::RIGHTMETA,
        _ => return None,
    };
    let _ = (key::RESERVED, key::MENU, key::SEARCH, key::MUTE);
    Some(code)
}

/// Map one of the 8 modifier *bits* (0..=7, matching [`modbit`] shift
/// positions and HID usages 0xE0 + bit) to its Linux `KEY_*` code.
/// Used by the transport layer's report-diff to emit modifier
/// press/release as ordinary EV_KEY events.
pub fn modifier_bit_to_keycode(bit: u8) -> Option<u16> {
    hid_usage_to_keycode(0xE0u16.wrapping_add(bit as u16))
}

/// Map a Consumer-page (0x0C) usage id to a Linux `KEY_*` code, for
/// the Fn/media row. Covers volume, mute, transport controls,
/// brightness, and a couple of navigation keys laptops surface here.
/// Returns `None` for consumer usages with no evdev keycode.
pub fn consumer_usage_to_keycode(usage: u16) -> Option<u16> {
    Some(match usage {
        consumer::VOLUME_UP => key::VOLUMEUP,
        consumer::VOLUME_DOWN => key::VOLUMEDOWN,
        consumer::MUTE => key::MUTE,
        consumer::PLAY_PAUSE => key::PLAYPAUSE,
        0xB5 => key::NEXTSONG,     // Scan Next Track
        0xB6 => key::PREVIOUSSONG, // Scan Previous Track
        0xB7 => key::STOPCD,       // Stop
        consumer::BRIGHTNESS_UP => key::BRIGHTNESSUP,
        consumer::BRIGHTNESS_DOWN => key::BRIGHTNESSDOWN,
        0x221 => key::SEARCH, // AC Search
        _ => return None,
    })
}

// ── Test-only descriptor blobs ────────────────────────────────────

/// Boot-keyboard Report Descriptor (HID 1.11 §B.1) — modifier byte +
/// reserved byte + LED output + 6-byte key array. No report ids.
/// Shared with the sibling driver crate's smokes.
#[doc(hidden)]
pub fn __boot_keyboard_descriptor_blob() -> &'static [u8] {
    BOOT_KEYBOARD_DESCRIPTOR_BLOB
}

static BOOT_KEYBOARD_DESCRIPTOR_BLOB: &[u8] = &[
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Keyboard)
    0x19, 0xE0, //   Usage Minimum (LeftControl)
    0x29, 0xE7, //   Usage Maximum (RightGUI)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Var, Abs)  — modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Const) — reserved byte
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1)
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Min (NumLock)
    0x29, 0x05, //   Usage Max (Kana)
    0x91, 0x02, //   Output (Data, Var, Abs)  — LEDs
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x01, //   Output (Const) — LED padding
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Min (0)
    0x25, 0x65, //   Logical Max (101)
    0x05, 0x07, //   Usage Page (Keyboard)
    0x19, 0x00, //   Usage Min (0)
    0x29, 0x65, //   Usage Max (Keyboard Application)
    0x81, 0x00, //   Input (Data, Array, Abs) — key array
    0xC0, // End Collection
];

/// Consumer-control Report Descriptor: a single Report ID(3) input
/// with a 2-slot 16-bit Array over the Consumer usage range — the
/// shape a laptop's media/Fn row typically ships.
#[doc(hidden)]
pub fn __consumer_descriptor_blob() -> &'static [u8] {
    CONSUMER_DESCRIPTOR_BLOB
}

static CONSUMER_DESCRIPTOR_BLOB: &[u8] = &[
    0x05, 0x0C, // Usage Page (Consumer)
    0x09, 0x01, // Usage (Consumer Control)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x03, //   Report ID (3)
    0x15, 0x00, //   Logical Min (0)
    0x26, 0xFF, 0x03, //   Logical Max (0x3FF)
    0x19, 0x00, //   Usage Min (0)
    0x2A, 0xFF, 0x03, //   Usage Max (0x3FF)
    0x75, 0x10, //   Report Size (16)
    0x95, 0x02, //   Report Count (2)
    0x81, 0x00, //   Input (Array) — two active consumer usages
    0xC0, // End Collection
];

// Host unit tests (run under `cargo test -p narf-hid`) — exercise the
// real decode + translation logic end-to-end. The kernel-test-runner
// smokes in `crate::tests` cover the same paths inside the kernel; these
// give a fast host signal that doesn't depend on the kernel link.
#[cfg(test)]
mod host_tests {
    use super::*;
    use crate::descriptor::parse;

    #[test]
    fn detect_and_decode_boot_keyboard() {
        let d = parse(__boot_keyboard_descriptor_blob()).unwrap();
        let p = detect(&d).expect("keyboard collection");
        assert_eq!(p.input_report_id, 0);
        assert_eq!(p.keys.report_count, 6);
        assert!(p.modifiers.is_some());

        // LeftShift + 'a'(0x04) + 'b'(0x05).
        let report = [modbit::LEFT_SHIFT, 0, 0x04, 0x05, 0, 0, 0, 0];
        let dec = decode_input(&p, &report).unwrap();
        assert_eq!(dec.modifiers, modbit::LEFT_SHIFT);
        assert_eq!(dec.keys, alloc::vec![0x04u16, 0x05]);
        assert!(dec.holds(0x04));
        assert!(!dec.holds(0x99));
    }

    #[test]
    fn usage_to_keycode_spot_checks() {
        let cases: &[(u16, u16)] = &[
            (0x04, 30),
            (0x05, 48),
            (0x1D, 44),
            (0x1E, 2),
            (0x27, 11),
            (0x28, 28),
            (0x29, 1),
            (0x2A, 14),
            (0x2C, 57),
            (0x3A, 59),
            (0x45, 88),
            (0x4F, 106),
            (0x52, 103),
            (0x53, 69),
            (0xE0, 29),
            (0xE1, 42),
            (0xE3, 125),
            (0xE7, 126),
        ];
        for &(u, w) in cases {
            assert_eq!(hid_usage_to_keycode(u), Some(w), "usage {u:#x}");
        }
        assert_eq!(hid_usage_to_keycode(0x00), None);
        assert_eq!(hid_usage_to_keycode(0x01), None);
        assert_eq!(modifier_bit_to_keycode(0), Some(29));
        assert_eq!(modifier_bit_to_keycode(1), Some(42));
    }

    #[test]
    fn consumer_detect_decode_and_map() {
        let d = parse(__consumer_descriptor_blob()).unwrap();
        let p = detect_consumer(&d).expect("consumer collection");
        assert_eq!(p.input_report_id, 3);
        let report = [3u8, 0xE9, 0x00, 0x00, 0x00];
        let active = decode_consumer(&p, &report).unwrap();
        assert_eq!(active, alloc::vec![consumer::VOLUME_UP]);
        assert_eq!(consumer_usage_to_keycode(consumer::VOLUME_UP), Some(115));
        assert_eq!(
            consumer_usage_to_keycode(consumer::BRIGHTNESS_UP),
            Some(225)
        );
    }

    #[test]
    fn touchscreen_not_claimed_as_keyboard() {
        let d = parse(crate::touchscreen::__touchscreen_descriptor_blob()).unwrap();
        assert!(detect(&d).is_none());
    }
}
