//! Smoke tests for narf-hid.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::descriptor::{parse, FieldFlags, FieldKind};
use crate::report::{array_active_usages, extract, pack};
use crate::usage::{digitizer, generic_desktop, keyboard};

// ── Item-format walker basics ─────────────────────────────────────

fn smoke_hid_descriptor_truncated_blob_rejected() -> TestResult {
    // Prefix says size=2 (bSize=2 → 2 data bytes) but only 1 byte
    // follows.
    let blob = [0x06, 0x01];
    match parse(&blob) {
        Err(crate::DescriptorError::Truncated) => TestResult::Pass,
        _ => TestResult::Fail("truncated short item must be rejected"),
    }
}
kernel_test_in!("hid", smoke_hid_descriptor_truncated_blob_rejected);

fn smoke_hid_descriptor_unbalanced_end_collection_rejected() -> TestResult {
    // Single End-Collection (0xC0) with no preceding Collection.
    let blob = [0xC0];
    match parse(&blob) {
        Err(crate::DescriptorError::UnbalancedEndCollection) => TestResult::Pass,
        _ => TestResult::Fail("orphan End-Collection must be rejected"),
    }
}
kernel_test_in!("hid", smoke_hid_descriptor_unbalanced_end_collection_rejected);

fn smoke_hid_descriptor_long_item_skipped() -> TestResult {
    // Long item: 0xFE, dataSize=2, longTag=0x55, two data bytes.
    // Followed by a valid Usage Page (Generic Desktop) item.
    let blob = [0xFE, 0x02, 0x55, 0x11, 0x22, 0x05, 0x01];
    let d = parse(&blob).expect("parse");
    if !d.fields.is_empty() {
        return TestResult::Fail("usage-page on its own should not emit a Field");
    }
    if !d.top_level_apps.is_empty() {
        return TestResult::Fail("no Collection — top_level_apps should be empty");
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_descriptor_long_item_skipped);

// ── Boot keyboard descriptor ──────────────────────────────────────
//
// Verbatim from HID 1.11 Appendix B.1. The descriptor declares:
//   - 8 modifier bits   (Usage Min LCtrl..RGui, 1 bit × 8)
//   - 1 reserved byte
//   - 5 LED bits + 3 padding (output)
//   - 6-byte key array (8-bit indices into the keyboard usage page)

fn smoke_hid_descriptor_parses_boot_keyboard() -> TestResult {
    // HID 1.11 §B.1.
    let blob: [u8; 63] = [
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
        0xC0,       // End Collection
    ];
    let d = parse(&blob).expect("parse");
    if d.has_report_ids {
        return TestResult::Fail("boot keyboard does not use report IDs");
    }
    if d.top_level_apps.len() != 1
        || d.top_level_apps[0] != (generic_desktop::PAGE, generic_desktop::KEYBOARD)
    {
        return TestResult::Fail("expected 1 top-level Keyboard application collection");
    }
    let inputs: alloc::vec::Vec<_> = d.fields.iter().filter(|f| f.kind == FieldKind::Input).collect();
    if inputs.len() != 3 {
        return TestResult::Fail("expected 3 Input fields");
    }
    // Modifier: 8 bits × 1
    let mods = inputs[0];
    if !(mods.report_size == 1 && mods.report_count == 8 && mods.bit_offset == 0) {
        return TestResult::Fail("modifier field shape wrong");
    }
    if !mods.flags.contains(FieldFlags::VARIABLE) {
        return TestResult::Fail("modifier byte must be Variable");
    }
    // Reserved: 1 × 8 bits, Constant.
    let reserved = inputs[1];
    if !(reserved.flags.contains(FieldFlags::CONSTANT)
        && reserved.report_size == 8
        && reserved.report_count == 1
        && reserved.bit_offset == 8)
    {
        return TestResult::Fail("reserved byte shape wrong");
    }
    // Key array: 6 × 8 bits, Array (VARIABLE clear).
    let keys = inputs[2];
    if keys.flags.contains(FieldFlags::VARIABLE) {
        return TestResult::Fail("key array must be Array, not Variable");
    }
    if !(keys.report_size == 8 && keys.report_count == 6 && keys.bit_offset == 16) {
        return TestResult::Fail("key array shape wrong");
    }
    if keys.usage_page != keyboard::PAGE {
        return TestResult::Fail("key array usage page must be Keyboard");
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_descriptor_parses_boot_keyboard);

// ── Bit extraction ───────────────────────────────────────────────

fn smoke_hid_report_extract_bits_unsigned() -> TestResult {
    // Construct a synthetic field: 8 modifier bits at offset 0, then
    // an 8-bit reserved byte, then 6 × 8-bit keys (matches the boot
    // kbd modifier field with 8 elements of 1 bit).
    let blob: [u8; 17] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01,   //
        0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7,   //
        0x15, 0x00, 0x25, 0x01,               //
        0xC0,                                  //
    ];
    // Hand-built, simpler: just use parse and ask for an artificial
    // modifier-only descriptor.
    let _ = blob;
    let blob: [u8; 21] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, //
        0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, //
        0x15, 0x00, 0x25, 0x01, //
        0x75, 0x01, 0x95, 0x08, 0x81, //
    ];
    // Above doesn't have terminating data byte for Input; trim back
    // and add it.
    let _ = blob;
    let blob: [u8; 23] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00,
        0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
    ];
    let d = parse(&blob).expect("parse");
    let f = &d.fields[0];
    // Wire byte 0 = 0b1010_0101 → bit 0=1, bit 1=0, bit 2=1, bit 3=0,
    // bit 4=0, bit 5=1, bit 6=0, bit 7=1.
    let body = [0xA5u8];
    let v = extract(f, &body).expect("extract");
    let expected = [1, 0, 1, 0, 0, 1, 0, 1];
    if v != expected {
        return TestResult::Fail("extracted bits don't match LSB-first wire");
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_report_extract_bits_unsigned);

fn smoke_hid_report_extract_signed_8bit() -> TestResult {
    // Build a descriptor whose single Input field is one 8-bit
    // signed value (Logical -127..127), like the dx of a boot mouse.
    let blob: [u8; 21] = [
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, // GD/Mouse Application
        0x09, 0x30, // Usage X
        0x15, 0x81, // Logical Min (-127)
        0x25, 0x7F, // Logical Max (127)
        0x75, 0x08, // Report Size 8
        0x95, 0x01, // Report Count 1
        0x81, 0x06, // Input(Data,Var,Rel)
        0xC0,       // End Collection
        0x00, 0x00, // padding so length is right
    ];
    // Trim trailing padding — we don't actually need it, but the
    // descriptor was sized to a multiple of 7. The parser must
    // tolerate trailing zero items (size 0 / type 0 / tag 0 = main
    // Input with no data; harmless because no report_size set yet).
    // Just parse the meaningful prefix:
    let d = parse(&blob[..19]).expect("parse");
    let f = &d.fields[0];
    if f.logical_min != -127 || f.logical_max != 127 || f.report_size != 8 {
        return TestResult::Fail("X field shape wrong");
    }
    // dx = -2 → 0xFE.
    let body = [0xFEu8];
    let v = extract(f, &body).expect("extract");
    if v != [-2] {
        return TestResult::Fail("signed extract wrong");
    }
    // dx = +5.
    let v = extract(f, &[0x05]).expect("extract");
    if v != [5] {
        return TestResult::Fail("signed positive extract wrong");
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_report_extract_signed_8bit);

fn smoke_hid_report_extract_short_buffer_errors() -> TestResult {
    // Same 8-bit signed field; pass an empty body.
    let blob: [u8; 19] = [
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x30, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08,
        0x95, 0x01, 0x81, 0x06, 0xC0,
    ];
    let d = parse(&blob).expect("parse");
    let f = &d.fields[0];
    match extract(f, &[]) {
        Err(crate::ReportError::Short) => TestResult::Pass,
        _ => TestResult::Fail("empty body must error"),
    }
}
kernel_test_in!("hid", smoke_hid_report_extract_short_buffer_errors);

// ── Pack / unpack round-trip ─────────────────────────────────────

fn smoke_hid_report_pack_unpack_roundtrip() -> TestResult {
    // 4-bit field count=2 starting at offset 0.
    let blob: [u8; 18] = [
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, // GD / Mouse
        0x15, 0x00, 0x25, 0x0F, // Logical 0..15
        0x75, 0x04, 0x95, 0x02, // size 4, count 2
        0x09, 0x30, // Usage X
        0x81, 0x02, // Input (Data,Var,Abs)
    ];
    let d = parse(&blob).expect("parse");
    let f = &d.fields[0];
    let mut body = [0u8; 1];
    pack(f, &mut body, &[0x0A, 0x05]).expect("pack");
    if body[0] != 0x5A {
        return TestResult::Fail("packed bytes wrong (LSB-first packing)");
    }
    let v = extract(f, &body).expect("extract");
    if v != [0x0A, 0x05] {
        return TestResult::Fail("round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_report_pack_unpack_roundtrip);

// ── Array-active-usages helper ────────────────────────────────────

fn smoke_hid_array_active_usages_dedup_zeros() -> TestResult {
    // Build the boot-kbd key array: 6 × 8-bit values, logical 0..101,
    // usage min 0 / max 101 on Usage Page Keyboard.
    let blob: [u8; 28] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, // GD/Keyboard application
        0x05, 0x07, // Usage Page (Keyboard)
        0x19, 0x00, 0x29, 0x65, // Usage Min..Max (0..101)
        0x15, 0x00, 0x25, 0x65, // Logical Min..Max (0..101)
        0x75, 0x08, 0x95, 0x06, // size 8, count 6
        0x81, 0x00, // Input (Data, Array, Abs)
        0xC0, // End Collection
        0, 0, 0, 0, 0, // padding (ignored)
    ];
    let d = parse(&blob[..23]).expect("parse");
    let f = &d.fields[0];
    if f.flags.contains(FieldFlags::VARIABLE) {
        return TestResult::Fail("array field must be Array, not Variable");
    }
    let body = [0x04, 0x00, 0x05, 0x00, 0x00, 0x00];
    let active = array_active_usages(f, &body).expect("active");
    // Two non-zero entries: 0x04 (A) and 0x05 (B).
    if active.len() != 2 {
        return TestResult::Fail("expected 2 active usages");
    }
    if active[0] != (keyboard::PAGE, 0x04) || active[1] != (keyboard::PAGE, 0x05) {
        return TestResult::Fail("active usage decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_array_active_usages_dedup_zeros);

// ── Digitizer / PTP shape ─────────────────────────────────────────
//
// Minimal slice of a Microsoft Precision Touchpad: one TouchPad
// Application Collection containing a single contact (Finger) with
// Tip Switch (1 bit), Contact ID (3 bits), padding (4 bits), X+Y
// (16 bits each), all behind Report ID 1.

fn smoke_hid_descriptor_parses_ptp_finger() -> TestResult {
    let blob: [u8; 49] = [
        0x05, 0x0D, // Usage Page (Digitizer)
        0x09, 0x05, // Usage (Touch Pad)
        0xA1, 0x01, // Collection (Application)
        0x85, 0x01, //   Report ID (1)
        0x09, 0x22, //   Usage (Finger)
        0xA1, 0x02, //   Collection (Logical)
        0x09, 0x42, //     Usage (Tip Switch)
        0x15, 0x00, //     Logical Min 0
        0x25, 0x01, //     Logical Max 1
        0x75, 0x01, //     Size 1
        0x95, 0x01, //     Count 1
        0x81, 0x02, //     Input (Data,Var,Abs)
        0x09, 0x51, //     Usage (Contact ID)
        0x25, 0x07, //     Logical Max 7
        0x75, 0x03, //     Size 3
        0x81, 0x02, //     Input
        0x75, 0x04, //     Size 4 (padding)
        0x81, 0x03, //     Input (Const,Var)
        0x05, 0x01, //     Usage Page (Generic Desktop)
        0x09, 0x30, //     Usage (X)
        0x26, 0xFF, 0x7F, // Logical Max 0x7FFF (16-bit data)
        0x75, 0x10, //     Size 16
        0x81, 0x02, //     Input
        0xC0,       //   End Collection
        0xC0,       // End Collection
    ];
    let d = parse(&blob).expect("parse");
    if !d.has_report_ids {
        return TestResult::Fail("PTP descriptor must use report IDs");
    }
    if d.top_level_apps.len() != 1
        || d.top_level_apps[0] != (digitizer::PAGE, digitizer::TOUCH_PAD)
    {
        return TestResult::Fail("expected Touch Pad top-level application");
    }
    // Locate the Tip Switch field — Page Digitizer, Usage 0x42.
    let tip = d
        .fields
        .iter()
        .find(|f| {
            f.usages.iter().any(|u| u.0 == digitizer::PAGE && u.1 == digitizer::TIP_SWITCH)
        })
        .ok_or(())
        .map_err(|_| ());
    let tip = match tip {
        Ok(f) => f,
        Err(()) => return TestResult::Fail("Tip Switch field missing"),
    };
    if tip.report_id != 1 || tip.report_size != 1 || tip.report_count != 1 || tip.bit_offset != 0 {
        return TestResult::Fail("Tip Switch shape wrong");
    }
    // Contact ID: 3 bits at bit_offset 1, on Digitizer page.
    let cid = d.fields.iter().find(|f| {
        f.usages
            .iter()
            .any(|u| u.0 == digitizer::PAGE && u.1 == digitizer::CONTACT_ID)
    });
    match cid {
        Some(f) if f.report_size == 3 && f.bit_offset == 1 => {}
        _ => return TestResult::Fail("Contact ID shape wrong"),
    }
    // X: 16 bits at bit_offset 8.
    let x = d.fields.iter().find(|f| {
        f.usages
            .iter()
            .any(|u| u.0 == generic_desktop::PAGE && u.1 == generic_desktop::X)
    });
    match x {
        Some(f) if f.report_size == 16 && f.bit_offset == 8 => {}
        Some(f) => {
            // The padding before X is 4 bits, so X starts at bit 8
            // (1 + 3 + 4). Tolerate either if the parser hadn't
            // accounted for the padding field — but the strict
            // expectation is 8.
            let _ = f;
            return TestResult::Fail("X bit offset wrong");
        }
        _ => return TestResult::Fail("X field missing"),
    }
    TestResult::Pass
}
kernel_test_in!("hid", smoke_hid_descriptor_parses_ptp_finger);
