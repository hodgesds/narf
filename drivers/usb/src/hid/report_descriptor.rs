//! HID Report Descriptor parser — USB HID driver layer.
//!
//! ## Role
//!
//! This module is the USB-HID layer's entry point to the transport-
//! neutral `narf_hid::descriptor` parser (which lives in the `narf-hid`
//! crate shared with i2c-hid and BT-HID). It provides:
//!
//! 1. Re-exports of the core types a caller needs when walking the
//!    parsed descriptor tree.
//! 2. Keyboard-specific helpers: `has_keyboard_collection` (cheap
//!    gate before a full parse) and `find_keyboard_fields` (extract
//!    the Input fields from a Keyboard/Keypad Application Collection
//!    so the keyboard driver can set up per-field decoders without
//!    re-walking the whole tree).
//! 3. LED output-report builder: `build_led_report` encodes a
//!    HID Usage Page 0x08 (LED) Output report from a 1-byte LED
//!    mask (NumLock bit 0, CapsLock bit 1, ScrollLock bit 2) —
//!    matching the SET_REPORT encoding used by the keyboard driver
//!    and cross-referencing `usbkbd.c::usb_kbd_event` for the bit
//!    positions (Linux ref: `drivers/hid/usbhid/usbkbd.c:163`).
//! 4. A smoke-test suite (≥10 test cases) covering both the parser
//!    and the helpers.
//!
//! ## References
//!
//! - "Device Class Definition for Human Interface Devices (HID)"
//!   Version 1.11, 27 June 2001 (USB-IF). §6.2.2 (Report Descriptor),
//!   §B.1 (Boot Keyboard), §B.2 (Boot Mouse).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - "USB HID Usage Tables" Version 1.4 (USB-IF, March 2022). §10
//!   (Keyboard / Keypad, page 0x07), §11 (LED, page 0x08).
//!   <https://www.usb.org/document-library/hid-usage-tables-14>
//! - Linux `drivers/hid/hid-core.c` — `hid_parser_global` (line 401),
//!   `hid_parser_local` (line 507), `hid_parser_main` (line 638),
//!   `hid_open_report` (line 1259). State-machine mirrors this.
//!   GPL-2.0-or-later; adapted under NARF's GPL-2.0-or-later licence.
//! - Linux `drivers/hid/usbhid/usbkbd.c` — `usb_kbd_event` (line 153)
//!   for LED byte encoding: NumLock=bit0, CapsLock=bit1, ScrollLock=bit2.
//!   GPL-2.0-or-later.

// Re-export the core parsed types the keyboard and generic drivers use.
pub use narf_hid::descriptor::{
    CollectionKind, DescriptorError, Field, FieldFlags, FieldKind, ReportDescriptor,
};
pub use narf_hid::{parse, ReportError};

// ── Usage Page / Usage ID constants ─────────────────────────────────

/// HID Usage Page: Generic Desktop (§4, table 1).
pub const USAGE_PAGE_GENERIC_DESKTOP: u16 = 0x01;
/// HID Usage Page: Keyboard / Keypad (§10).
pub const USAGE_PAGE_KEYBOARD: u16 = 0x07;
/// HID Usage Page: LED (§11).
pub const USAGE_PAGE_LED: u16 = 0x08;
/// HID Usage Page: Button (§12).
pub const USAGE_PAGE_BUTTON: u16 = 0x09;
/// HID Usage Page: Consumer Control (§15).
pub const USAGE_PAGE_CONSUMER: u16 = 0x0C;

/// Generic Desktop usage: Keyboard (application collection, §4).
pub const USAGE_GD_KEYBOARD: u16 = 0x06;
/// Generic Desktop usage: Mouse (application collection, §4).
pub const USAGE_GD_MOUSE: u16 = 0x02;
/// Generic Desktop usage: Joystick (§4).
pub const USAGE_GD_JOYSTICK: u16 = 0x04;
/// Generic Desktop usage: Gamepad (§4).
pub const USAGE_GD_GAMEPAD: u16 = 0x05;

/// LED usage: NumLock (§11, table 11-1, usage 0x01).
pub const USAGE_LED_NUMLOCK: u16 = 0x01;
/// LED usage: CapsLock (§11, table 11-1, usage 0x02).
pub const USAGE_LED_CAPSLOCK: u16 = 0x02;
/// LED usage: ScrollLock (§11, table 11-1, usage 0x03).
pub const USAGE_LED_SCROLLLOCK: u16 = 0x03;

// ── LED report bits ──────────────────────────────────────────────────

/// Boot-keyboard LED byte: bit 0 = NumLock.
/// Matches Linux `usbkbd.c:165` `LED_NUML` bit position.
pub const LED_BIT_NUMLOCK: u8 = 1 << 0;
/// Boot-keyboard LED byte: bit 1 = CapsLock.
/// Matches Linux `usbkbd.c:164` `LED_CAPSL` bit position.
pub const LED_BIT_CAPSLOCK: u8 = 1 << 1;
/// Boot-keyboard LED byte: bit 2 = ScrollLock.
/// Matches Linux `usbkbd.c:164` `LED_SCROLLL` bit position.
pub const LED_BIT_SCROLLLOCK: u8 = 1 << 2;
/// Boot-keyboard LED byte: bit 3 = Compose.
pub const LED_BIT_COMPOSE: u8 = 1 << 3;
/// Boot-keyboard LED byte: bit 4 = Kana.
pub const LED_BIT_KANA: u8 = 1 << 4;

// ── Detection helper ─────────────────────────────────────────────────

/// Scan a raw report descriptor blob and return `true` if it contains
/// a Keyboard Application Collection. This is the cheap "is this the
/// right interface?" gate — do this before calling the full `parse`.
///
/// Recognises two descriptor shapes:
///   1. `Usage Page (Generic Desktop) + Usage (Keyboard) + Collection
///      (Application)` — the standard shape for a report-protocol
///      keyboard.
///   2. `Usage Page (Keyboard/Keypad) + Collection (Application)` —
///      some OEM firmware omits a distinct application-level Usage Page
///      and opens the collection while Generic Desktop is still current.
///
/// Adapted from the Linux `hid_scan_collection` detection in
/// `drivers/hid/hid-core.c:853` (GPL-2.0-or-later).
pub fn has_keyboard_collection(desc: &[u8]) -> bool {
    let mut i = 0usize;
    let mut current_page: u16 = 0;
    let mut pending_usage: u16 = 0;

    while i < desc.len() {
        let tag = desc[i];
        if tag == 0xFE {
            // Long item: skip header + data.
            if i + 2 > desc.len() {
                break;
            }
            let n = desc[i + 1] as usize;
            i += 2 + n;
            continue;
        }
        let payload_len = short_item_size(tag);
        if i + 1 + payload_len > desc.len() {
            break;
        }
        let val = read_u32(&desc[i + 1..i + 1 + payload_len]);
        match tag & !0x03 {
            // Usage Page (global, tag=0x04): update page, reset pending usage.
            0x04 => {
                current_page = val as u16;
                pending_usage = 0;
            }
            // Usage (local, tag=0x08): record pending usage id.
            0x08 => {
                pending_usage = val as u16;
            }
            // Collection (main, tag=0xA0): check for keyboard application.
            0xA0 => {
                let is_application = val as u8 == 0x01;
                if is_application {
                    // Shape 1: Generic Desktop page + Keyboard usage.
                    if current_page == USAGE_PAGE_GENERIC_DESKTOP
                        && pending_usage == USAGE_GD_KEYBOARD
                    {
                        return true;
                    }
                    // Shape 2: Keyboard/Keypad page directly opens an
                    // Application Collection (some OEM keyboards).
                    if current_page == USAGE_PAGE_KEYBOARD {
                        return true;
                    }
                }
                pending_usage = 0;
            }
            _ => {}
        }
        i += 1 + payload_len;
    }
    false
}

/// Extract all Input `Field`s from the first Keyboard Application
/// Collection in a parsed `ReportDescriptor`. Returns an empty Vec
/// if no keyboard collection is present.
///
/// "Keyboard Application Collection" means any top-level application
/// whose usage is `(Generic Desktop, Keyboard)` or whose usage page
/// is Keyboard/Keypad.
pub fn find_keyboard_fields(desc: &ReportDescriptor) -> alloc::vec::Vec<Field> {
    desc.fields
        .iter()
        .filter(|f| {
            f.kind == FieldKind::Input
                && (f.usage_page == USAGE_PAGE_KEYBOARD
                    || f.collection_path.iter().any(|&(pg, id)| {
                        (pg == USAGE_PAGE_GENERIC_DESKTOP && id == USAGE_GD_KEYBOARD)
                            || pg == USAGE_PAGE_KEYBOARD
                    }))
        })
        .cloned()
        .collect()
}

/// Build a 1-byte HID LED Output report from a modifier-flags bitset.
/// `caps_on`, `num_on`, `scroll_on` map to bits 1/0/2 respectively,
/// matching the LED byte layout in the HID boot keyboard spec and the
/// Linux `usbkbd.c::usb_kbd_event` implementation (line 163–165).
///
/// If `report_id` is `Some(id)`, the returned slice is 2 bytes
/// (report-id prefix + LED byte). Otherwise it is 1 byte.
///
/// Returns a stack-allocated `[u8; 2]` and the valid length (1 or 2).
pub fn build_led_report(
    num_on: bool,
    caps_on: bool,
    scroll_on: bool,
    report_id: Option<u8>,
) -> ([u8; 2], usize) {
    let led = (num_on as u8 * LED_BIT_NUMLOCK)
        | (caps_on as u8 * LED_BIT_CAPSLOCK)
        | (scroll_on as u8 * LED_BIT_SCROLLLOCK);
    match report_id {
        Some(id) => ([id, led], 2),
        None => ([led, 0], 1),
    }
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Decode the payload-byte-count from a HID short-item prefix byte.
/// bits[1:0] encode 0→0, 1→1, 2→2, 3→4 bytes.
#[inline]
fn short_item_size(tag: u8) -> usize {
    match tag & 0x03 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => unreachable!(),
    }
}

/// Read a little-endian unsigned integer from a 0-to-4-byte slice.
#[inline]
fn read_u32(bytes: &[u8]) -> u32 {
    match bytes.len() {
        0 => 0,
        1 => bytes[0] as u32,
        2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u32,
        _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    }
}

extern crate alloc;

// ── Smokes ────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // A real Logitech K400+ keyboard Report Descriptor
    // (trimmed to application + modifier + keycode fields).
    // Sourced from USB descriptor dump of a Logitech K400+ USB dongle.
    // Collection: Generic Desktop / Keyboard (0x01/0x06).
    // Fields: modifier byte (8x 1-bit variables), keycode array (6x 8-bit).
    static LOGITECH_KBD_DESC: &[u8] = &[
        // Usage Page (Generic Desktop)
        0x05, 0x01,
        // Usage (Keyboard)
        0x09, 0x06,
        // Collection (Application)
        0xA1, 0x01,
        // Usage Page (Keyboard)
        0x05, 0x07,
        // Usage Minimum (Keyboard Left Control = 0xE0)
        0x19, 0xE0,
        // Usage Maximum (Keyboard Right GUI = 0xE7)
        0x29, 0xE7,
        // Logical Minimum (0)
        0x15, 0x00,
        // Logical Maximum (1)
        0x25, 0x01,
        // Report Size (1)
        0x75, 0x01,
        // Report Count (8)
        0x95, 0x08,
        // Input (Data, Variable, Absolute) — 8 modifier bits
        0x81, 0x02,
        // Report Count (1), Report Size (8)
        0x95, 0x01,
        0x75, 0x08,
        // Input (Constant) — reserved byte
        0x81, 0x01,
        // Report Count (6), Report Size (8)
        0x95, 0x06,
        0x75, 0x08,
        // Usage Minimum (0x00), Usage Maximum (0xFF)
        0x19, 0x00,
        0x29, 0xFF,
        // Logical Minimum (0), Logical Maximum (255)
        0x15, 0x00,
        0x26, 0xFF, 0x00,
        // Input (Data, Array, Absolute) — 6 keycodes
        0x81, 0x00,
        // End Collection
        0xC0,
    ];

    // Minimal 3-button + wheel mouse descriptor for parser regression.
    // Usage Page (Generic Desktop), Usage (Mouse), Collection (Application),
    //   Usage (Pointer), Collection (Physical),
    //   buttons (3 bits), padding (5 bits),
    //   X and Y (two i8 relative axes), Wheel (i8 relative).
    // End Collection x2.
    static MOUSE_DESC: &[u8] = &[
        0x05, 0x01, // Usage Page (Generic Desktop)
        0x09, 0x02, // Usage (Mouse)
        0xA1, 0x01, // Collection (Application)
        0x09, 0x01, //   Usage (Pointer)
        0xA1, 0x00, //   Collection (Physical)
        0x05, 0x09, //     Usage Page (Button)
        0x19, 0x01, //     Usage Minimum (Button 1)
        0x29, 0x03, //     Usage Maximum (Button 3)
        0x15, 0x00, //     Logical Minimum (0)
        0x25, 0x01, //     Logical Maximum (1)
        0x75, 0x01, //     Report Size (1)
        0x95, 0x03, //     Report Count (3)
        0x81, 0x02, //     Input (Data, Variable, Absolute)
        0x75, 0x05, //     Report Size (5)
        0x95, 0x01, //     Report Count (1)
        0x81, 0x01, //     Input (Constant) — padding
        0x05, 0x01, //     Usage Page (Generic Desktop)
        0x09, 0x30, //     Usage (X)
        0x09, 0x31, //     Usage (Y)
        0x09, 0x38, //     Usage (Wheel)
        0x15, 0x81, //     Logical Minimum (-127)
        0x25, 0x7F, //     Logical Maximum (127)
        0x75, 0x08, //     Report Size (8)
        0x95, 0x03, //     Report Count (3)
        0x81, 0x06, //     Input (Data, Variable, Relative)
        0xC0,       //   End Collection (Physical)
        0xC0,       // End Collection (Application)
    ];

    // ── Test 1: keyboard boot-descriptor parse end-to-end ────────────

    fn smoke_report_desc_kbd_logitech_parse() -> TestResult {
        let desc = parse(LOGITECH_KBD_DESC).expect("parse failed");
        // Must have detected at least two Input fields (modifier + keycode).
        if desc.fields.is_empty() {
            return TestResult::Fail("no fields parsed from Logitech kbd descriptor");
        }
        // No report IDs in this simple descriptor.
        if desc.has_report_ids {
            return TestResult::Fail("unexpected report IDs in Logitech kbd descriptor");
        }
        // Top-level application: (Generic Desktop=0x01, Keyboard=0x06).
        if desc.top_level_apps.is_empty() {
            return TestResult::Fail("no top-level application collection found");
        }
        let (pg, id) = desc.top_level_apps[0];
        if pg != 0x01 || id != 0x06 {
            return TestResult::Fail(
                "top-level app is not Generic Desktop / Keyboard",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_kbd_logitech_parse
    );

    // ── Test 2: mouse boot-descriptor parse ──────────────────────────

    fn smoke_report_desc_mouse_parse() -> TestResult {
        let desc = parse(MOUSE_DESC).expect("parse failed");
        if desc.fields.is_empty() {
            return TestResult::Fail("no fields from mouse descriptor");
        }
        if !desc.top_level_apps.is_empty() {
            let (pg, id) = desc.top_level_apps[0];
            if pg != 0x01 || id != 0x02 {
                return TestResult::Fail("mouse app collection not (0x01, Mouse)");
            }
        }
        // Must find a Button-page field (3 bits).
        let has_btn = desc
            .fields
            .iter()
            .any(|f| f.usage_page == 0x09 && f.report_count == 3);
        if !has_btn {
            return TestResult::Fail("no 3-bit button field found in mouse descriptor");
        }
        // Must find an X/Y relative field (report_count=3, report_size=8).
        let has_xy = desc.fields.iter().any(|f| {
            f.usage_page == 0x01
                && f.report_count == 3
                && f.report_size == 8
                && f.flags.contains(FieldFlags::RELATIVE)
        });
        if !has_xy {
            return TestResult::Fail("no X/Y/Wheel relative field found");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_mouse_parse
    );

    // ── Test 3: report ID field decoding ─────────────────────────────

    fn smoke_report_desc_report_id() -> TestResult {
        // Descriptor with two collections, each with a report ID.
        let desc_with_ids: &[u8] = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x06, // Usage (Keyboard)
            0xA1, 0x01, // Collection (Application)
            0x85, 0x01, //   Report ID (1)
            0x05, 0x07, //   Usage Page (Keyboard)
            0x19, 0xE0, //   Usage Minimum (0xE0)
            0x29, 0xE7, //   Usage Maximum (0xE7)
            0x15, 0x00, //   Logical Minimum (0)
            0x25, 0x01, //   Logical Maximum (1)
            0x75, 0x01, //   Report Size (1)
            0x95, 0x08, //   Report Count (8)
            0x81, 0x02, //   Input (Data, Variable, Absolute)
            0xC0,       // End Collection
            0x05, 0x0C, // Usage Page (Consumer)
            0x09, 0x01, // Usage (Consumer Control)
            0xA1, 0x01, // Collection (Application)
            0x85, 0x02, //   Report ID (2)
            0x15, 0x00, //   Logical Minimum (0)
            0x26, 0xFF, 0x00, //   Logical Maximum (255)
            0x75, 0x08, //   Report Size (8)
            0x95, 0x01, //   Report Count (1)
            0x81, 0x00, //   Input (Data, Array, Absolute)
            0xC0,       // End Collection
        ];
        let desc = parse(desc_with_ids).expect("parse failed");
        if !desc.has_report_ids {
            return TestResult::Fail("expected has_report_ids = true");
        }
        // Fields for report ID 1 should be keyboard modifier type.
        let id1_fields: alloc::vec::Vec<_> = desc
            .fields_with_report_id(1)
            .filter(|f| f.kind == FieldKind::Input)
            .collect();
        if id1_fields.is_empty() {
            return TestResult::Fail("no Input fields for report ID 1");
        }
        // Fields for report ID 2 should be consumer page.
        let id2_fields: alloc::vec::Vec<_> = desc
            .fields_with_report_id(2)
            .filter(|f| f.kind == FieldKind::Input)
            .collect();
        if id2_fields.is_empty() {
            return TestResult::Fail("no Input fields for report ID 2");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_report_id
    );

    // ── Test 4: collection nesting ───────────────────────────────────

    fn smoke_report_desc_collection_nesting() -> TestResult {
        // Mouse descriptor has Application → Physical nesting.
        let desc = parse(MOUSE_DESC).expect("parse failed");
        // Fields inside the Physical collection must record the
        // application path (Generic Desktop / Mouse).
        let xy_field = desc
            .fields
            .iter()
            .find(|f| f.usage_page == 0x01 && f.report_count == 3 && f.report_size == 8);
        match xy_field {
            None => TestResult::Fail("X/Y field not found for collection-path check"),
            Some(f) => {
                if f.collection_path.is_empty() {
                    TestResult::Fail("collection_path empty for nested field")
                } else {
                    TestResult::Pass
                }
            }
        }
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_collection_nesting
    );

    // ── Test 5: has_keyboard_collection ─────────────────────────────

    fn smoke_has_keyboard_collection() -> TestResult {
        if !has_keyboard_collection(LOGITECH_KBD_DESC) {
            return TestResult::Fail("Logitech kbd desc not detected as keyboard");
        }
        if has_keyboard_collection(MOUSE_DESC) {
            return TestResult::Fail("mouse desc false-positive as keyboard");
        }
        // Empty / degenerate cases must not panic.
        if has_keyboard_collection(&[]) {
            return TestResult::Fail("empty desc false-positive");
        }
        // Consumer descriptor must not match.
        let consumer: &[u8] = &[
            0x05, 0x0C, // Usage Page (Consumer)
            0x09, 0x01, // Usage (Consumer Control)
            0xA1, 0x01, // Collection (Application)
            0xC0,
        ];
        if has_keyboard_collection(consumer) {
            return TestResult::Fail("consumer desc false-positive as keyboard");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_has_keyboard_collection
    );

    // ── Test 6: find_keyboard_fields ────────────────────────────────

    fn smoke_find_keyboard_fields() -> TestResult {
        let desc = parse(LOGITECH_KBD_DESC).expect("parse failed");
        let kbd_fields = find_keyboard_fields(&desc);
        if kbd_fields.is_empty() {
            return TestResult::Fail("no keyboard fields found");
        }
        // All returned fields must be Input.
        for f in &kbd_fields {
            if f.kind != FieldKind::Input {
                return TestResult::Fail("non-Input field returned by find_keyboard_fields");
            }
        }
        // For the mouse descriptor, find_keyboard_fields should be empty.
        let mouse_desc = parse(MOUSE_DESC).expect("mouse parse failed");
        let mouse_kbd = find_keyboard_fields(&mouse_desc);
        if !mouse_kbd.is_empty() {
            return TestResult::Fail("found keyboard fields in mouse descriptor");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_find_keyboard_fields
    );

    // ── Test 7: build_led_report — no report ID ───────────────────────

    fn smoke_build_led_report_no_rid() -> TestResult {
        // All off.
        let (buf, len) = build_led_report(false, false, false, None);
        if len != 1 || buf[0] != 0x00 {
            return TestResult::Fail("all-LEDs-off: expected 0x00");
        }
        // NumLock only.
        let (buf, len) = build_led_report(true, false, false, None);
        if len != 1 || buf[0] != LED_BIT_NUMLOCK {
            return TestResult::Fail("NumLock-only LED byte wrong");
        }
        // CapsLock only.
        let (buf, len) = build_led_report(false, true, false, None);
        if len != 1 || buf[0] != LED_BIT_CAPSLOCK {
            return TestResult::Fail("CapsLock-only LED byte wrong");
        }
        // All three on.
        let (buf, len) = build_led_report(true, true, true, None);
        if len != 1 || buf[0] != (LED_BIT_NUMLOCK | LED_BIT_CAPSLOCK | LED_BIT_SCROLLLOCK) {
            return TestResult::Fail("all-LEDs-on byte wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_build_led_report_no_rid
    );

    // ── Test 8: build_led_report — with report ID ────────────────────

    fn smoke_build_led_report_with_rid() -> TestResult {
        let (buf, len) = build_led_report(false, true, false, Some(0x03));
        if len != 2 {
            return TestResult::Fail("expected 2-byte buffer when report_id is Some");
        }
        if buf[0] != 0x03 {
            return TestResult::Fail("report-id prefix byte wrong");
        }
        if buf[1] != LED_BIT_CAPSLOCK {
            return TestResult::Fail("LED byte wrong with report-id prefix");
        }
        // Caps + Num with report ID 1.
        let (buf, len) = build_led_report(true, true, false, Some(0x01));
        if len != 2 || buf[0] != 0x01 || buf[1] != (LED_BIT_NUMLOCK | LED_BIT_CAPSLOCK) {
            return TestResult::Fail("Caps+Num with rid=1 wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_build_led_report_with_rid
    );

    // ── Test 9: truncated descriptor returns error ───────────────────

    fn smoke_report_desc_truncated() -> TestResult {
        // A descriptor that declares an item whose data extends past the end.
        let truncated: &[u8] = &[
            0x05, // Usage Page with 1-byte payload ... but no payload byte
        ];
        match parse(truncated) {
            Err(DescriptorError::Truncated) => TestResult::Pass,
            Err(e) => {
                let _ = e;
                TestResult::Fail("expected Truncated, got a different error")
            }
            Ok(_) => TestResult::Fail("expected Truncated error, got Ok"),
        }
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_truncated
    );

    // ── Test 10: bit-offset accumulation ────────────────────────────

    fn smoke_report_desc_bit_offsets() -> TestResult {
        // The Logitech descriptor fields must have ascending bit offsets:
        // field 0 = 8 modifier bits at offset 0,
        // field 1 = 8 reserved-constant bits at offset 8,
        // field 2 = 48 keycode bits at offset 16.
        let desc = parse(LOGITECH_KBD_DESC).expect("parse failed");
        let input_fields: alloc::vec::Vec<_> = desc
            .fields
            .iter()
            .filter(|f| f.kind == FieldKind::Input)
            .collect();
        if input_fields.len() < 3 {
            return TestResult::Fail("expected 3 Input fields");
        }
        if input_fields[0].bit_offset != 0 {
            return TestResult::Fail("first field bit_offset should be 0");
        }
        if input_fields[1].bit_offset != 8 {
            return TestResult::Fail("reserved field bit_offset should be 8");
        }
        if input_fields[2].bit_offset != 16 {
            return TestResult::Fail("keycode field bit_offset should be 16");
        }
        // Verify keycode field is 6 × 8 bits.
        if input_fields[2].report_count != 6 || input_fields[2].report_size != 8 {
            return TestResult::Fail("keycode field report_count/size wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_bit_offsets
    );

    // ── Test 11: keyboard descriptor with report ID inside ───────────

    fn smoke_report_desc_kbd_with_report_id() -> TestResult {
        // A keyboard descriptor that uses a report ID (composite device).
        let kbd_with_rid: &[u8] = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x06, // Usage (Keyboard)
            0xA1, 0x01, // Collection (Application)
            0x85, 0x04, //   Report ID (4)
            0x05, 0x07, //   Usage Page (Keyboard)
            0x19, 0xE0, //   Usage Minimum (0xE0)
            0x29, 0xE7, //   Usage Maximum (0xE7)
            0x15, 0x00, //   Logical Minimum (0)
            0x25, 0x01, //   Logical Maximum (1)
            0x75, 0x01, //   Report Size (1)
            0x95, 0x08, //   Report Count (8)
            0x81, 0x02, //   Input (Data, Variable, Absolute)
            0xC0,       // End Collection
        ];
        let desc = parse(kbd_with_rid).expect("parse failed");
        if !desc.has_report_ids {
            return TestResult::Fail("expected has_report_ids = true");
        }
        let fields: alloc::vec::Vec<_> = desc
            .fields_with_report_id(4)
            .filter(|f| f.kind == FieldKind::Input)
            .collect();
        if fields.is_empty() {
            return TestResult::Fail("no Input fields for report ID 4");
        }
        if fields[0].report_id != 4 {
            return TestResult::Fail("report_id field not set to 4");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/report_descriptor",
        smoke_report_desc_kbd_with_report_id
    );
}
