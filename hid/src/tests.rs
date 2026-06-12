//! Smoke tests for narf-hid.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::descriptor::{parse, FieldFlags, FieldKind};
use crate::ptp::{build_mode_feature_report, decode_input, detect, mode};
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
kernel_test_in!(
    "hid",
    smoke_hid_descriptor_unbalanced_end_collection_rejected
);

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
        0xC0, // End Collection
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
    let inputs: alloc::vec::Vec<_> = d
        .fields
        .iter()
        .filter(|f| f.kind == FieldKind::Input)
        .collect();
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
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, //
        0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, //
        0x15, 0x00, 0x25, 0x01, //
        0xC0, //
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
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xC0,
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
        0xC0, // End Collection
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
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x30, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95,
        0x01, 0x81, 0x06, 0xC0,
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
        0xC0, //   End Collection
        0xC0, // End Collection
    ];
    let d = parse(&blob).expect("parse");
    if !d.has_report_ids {
        return TestResult::Fail("PTP descriptor must use report IDs");
    }
    if d.top_level_apps.len() != 1 || d.top_level_apps[0] != (digitizer::PAGE, digitizer::TOUCH_PAD)
    {
        return TestResult::Fail("expected Touch Pad top-level application");
    }
    // Locate the Tip Switch field — Page Digitizer, Usage 0x42.
    let tip = d
        .fields
        .iter()
        .find(|f| {
            f.usages
                .iter()
                .any(|u| u.0 == digitizer::PAGE && u.1 == digitizer::TIP_SWITCH)
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

// ── PTP profile detection + report decode ─────────────────────────

/// Synthetic but spec-shaped PTP descriptor: 2 fingers + Contact
/// Count + Scan Time + Button 1, with a Configuration TLC carrying
/// a Device Mode Feature item.
const PTP_DESCRIPTOR: &[u8] = &[
    // ── Touch Pad Application Collection (Input report ID 1) ────
    0x05, 0x0D, // Usage Page (Digitizer)
    0x09, 0x05, // Usage (Touch Pad)
    0xA1, 0x01, //   Collection (Application)
    0x85, 0x01, //     Report ID (1)
    // Finger 0
    0x09, 0x22, //     Usage (Finger)
    0xA1, 0x02, //     Collection (Logical)
    0x05, 0x0D, //       Usage Page (Digitizer)
    0x09, 0x42, //       Usage (Tip Switch)
    0x15, 0x00, 0x25, 0x01, //       Logical 0..1
    0x75, 0x01, 0x95, 0x01, //       Size 1, Count 1
    0x81, 0x02, //       Input (Data,Var,Abs)
    0x09, 0x51, //       Usage (Contact ID)
    0x25, 0x07, //       Logical Max 7
    0x75, 0x03, 0x95, 0x01, //       Size 3, Count 1
    0x81, 0x02, //       Input
    0x75, 0x04, 0x95, 0x01, //       Size 4, Count 1 (padding)
    0x81, 0x03, //       Input (Const)
    0x05, 0x01, //       Usage Page (Generic Desktop)
    0x09, 0x30, //       Usage (X)
    0x26, 0xFF, 0x7F, //       Logical Max 0x7FFF
    0x75, 0x10, 0x95, 0x01, //       Size 16, Count 1
    0x81, 0x02, //       Input
    0x09, 0x31, //       Usage (Y)
    0x81, 0x02, //       Input
    0xC0, //     End Collection (Finger 0)
    // Finger 1
    0x05, 0x0D, //     Usage Page (Digitizer)
    0x09, 0x22, //     Usage (Finger)
    0xA1, 0x02, //     Collection (Logical)
    0x09, 0x42, //       Usage (Tip Switch)
    0x15, 0x00, 0x25, 0x01, //       Logical 0..1
    0x75, 0x01, 0x95, 0x01, //       Size 1, Count 1
    0x81, 0x02, //       Input
    0x09, 0x51, //       Usage (Contact ID)
    0x25, 0x07, //       Logical Max 7
    0x75, 0x03, 0x95, 0x01, //       Size 3, Count 1
    0x81, 0x02, //       Input
    0x75, 0x04, 0x95, 0x01, //       Size 4 padding
    0x81, 0x03, //       Input (Const)
    0x05, 0x01, //       Usage Page (Generic Desktop)
    0x09, 0x30, //       Usage (X)
    0x26, 0xFF, 0x7F, //       Logical Max 0x7FFF
    0x75, 0x10, 0x95, 0x01, //       Size 16, Count 1
    0x81, 0x02, //       Input
    0x09, 0x31, //       Usage (Y)
    0x81, 0x02, //       Input
    0xC0, //     End Collection (Finger 1)
    // Contact Count + Scan Time + Button 1 + padding
    0x05, 0x0D, //     Usage Page (Digitizer)
    0x09, 0x54, //     Usage (Contact Count)
    0x25, 0x05, //     Logical Max 5
    0x75, 0x08, 0x95, 0x01, //     Size 8, Count 1
    0x81, 0x02, //     Input
    0x09, 0x56, //     Usage (Scan Time)
    0x27, 0xFF, 0xFF, 0x00, 0x00, // Logical Max 0xFFFF (4-byte form)
    0x75, 0x10, 0x95, 0x01, //     Size 16, Count 1
    0x81, 0x02, //     Input
    0x05, 0x09, //     Usage Page (Button)
    0x09, 0x01, //     Usage (Button 1)
    0x15, 0x00, 0x25, 0x01, //     Logical 0..1
    0x75, 0x01, 0x95, 0x01, //     Size 1, Count 1
    0x81, 0x02, //     Input
    0x75, 0x07, 0x95, 0x01, //     Size 7 padding
    0x81, 0x03, //     Input (Const)
    0xC0, //   End Collection (Touch Pad)
    // ── Configuration TLC (Feature report ID 3) ─────────────────
    0x05, 0x0D, // Usage Page (Digitizer)
    0x09, 0x0E, // Usage (Configuration)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x03, //   Report ID (3)
    0x09, 0x22, //   Usage (Finger)
    0xA1, 0x02, //   Collection (Logical)
    0x09, 0x60, //     Usage (Device Mode)
    0x15, 0x00, 0x25, 0x0A, //     Logical 0..10
    0x75, 0x08, 0x95, 0x01, //     Size 8, Count 1
    0xB1, 0x02, //     Feature (Data,Var,Abs)
    0xC0, //   End Collection
    0xC0, // End Collection
];

fn smoke_ptp_detect_basic_shape() -> TestResult {
    let d = parse(PTP_DESCRIPTOR).expect("parse");
    let p = match detect(&d) {
        Some(p) => p,
        None => return TestResult::Fail("PTP detect rejected a valid descriptor"),
    };
    if p.input_report_id != 1 {
        return TestResult::Fail("input report id should be 1");
    }
    if p.contacts.len() != 2 {
        return TestResult::Fail("expected 2 contacts (Finger collections)");
    }
    if p.contact_count.is_none() {
        return TestResult::Fail("Contact Count must be detected");
    }
    if p.scan_time.is_none() {
        return TestResult::Fail("Scan Time must be detected");
    }
    if p.button1.is_none() {
        return TestResult::Fail("Button 1 must be detected");
    }
    if p.config_report_id != Some(3) {
        return TestResult::Fail("Configuration TLC report id should be 3");
    }
    if p.device_mode_feature.is_none() {
        return TestResult::Fail("Device Mode feature must be detected");
    }
    if p.contacts_max != 2 {
        return TestResult::Fail("contacts_max wrong");
    }
    TestResult::Pass
}
kernel_test_in!("hid/ptp", smoke_ptp_detect_basic_shape);

fn smoke_ptp_decode_one_active_contact() -> TestResult {
    let d = parse(PTP_DESCRIPTOR).expect("parse");
    let p = detect(&d).expect("detect");

    // Finger 0: tip=1, cid=3, X=0x1234, Y=0x5678
    // Finger 1: tip=0, cid=0, X=0, Y=0
    // Contact Count=1, Scan Time=0xABCD, Button 1 = pressed.
    let report = [
        0x01,        // Report ID 1
        0b0000_0111, // tip=1, cid=011, pad=0000
        0x34,
        0x12, // X = 0x1234
        0x78,
        0x56, // Y = 0x5678
        0x00, // Finger 1: tip=0, cid=0, pad=0
        0x00,
        0x00, // Finger 1 X
        0x00,
        0x00, // Finger 1 Y
        0x01, // Contact Count = 1
        0xCD,
        0xAB, // Scan Time = 0xABCD
        0x01, // Button 1 = 1, pad 7 bits = 0
    ];
    let r = match decode_input(&p, &report) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("decode_input failed"),
    };
    if r.contact_count != 1 {
        return TestResult::Fail("contact_count != 1");
    }
    if r.scan_time != 0xABCD {
        return TestResult::Fail("scan_time != 0xABCD");
    }
    if !r.button1 {
        return TestResult::Fail("button1 should be pressed");
    }
    if r.contacts.len() != 2 {
        return TestResult::Fail("contacts vec length wrong");
    }
    let c0 = &r.contacts[0];
    if !(c0.tip_switch && c0.contact_id == 3 && c0.x == 0x1234 && c0.y == 0x5678) {
        return TestResult::Fail("contact 0 wrong");
    }
    let c1 = &r.contacts[1];
    if c1.tip_switch || c1.contact_id != 0 || c1.x != 0 || c1.y != 0 {
        return TestResult::Fail("contact 1 should be all zero");
    }
    TestResult::Pass
}
kernel_test_in!("hid/ptp", smoke_ptp_decode_one_active_contact);

fn smoke_ptp_build_mode_feature_multi_touch() -> TestResult {
    let d = parse(PTP_DESCRIPTOR).expect("parse");
    let p = detect(&d).expect("detect");
    let buf = match build_mode_feature_report(&p, mode::MULTI_TOUCH) {
        Some(b) => b,
        None => return TestResult::Fail("build_mode_feature_report returned None"),
    };
    if buf.len() != 2 {
        return TestResult::Fail("Feature report should be report-id + 1 byte");
    }
    if buf[0] != 3 {
        return TestResult::Fail("Feature report id wrong");
    }
    if buf[1] != mode::MULTI_TOUCH {
        return TestResult::Fail("Mode byte wrong");
    }
    TestResult::Pass
}
kernel_test_in!("hid/ptp", smoke_ptp_build_mode_feature_multi_touch);

fn smoke_ptp_detect_rejects_non_touchpad() -> TestResult {
    // A boot-keyboard descriptor must not be detected as PTP.
    let blob: [u8; 63] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
        0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
        0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
        0x81, 0x00, 0xC0,
    ];
    let d = parse(&blob).expect("parse");
    if detect(&d).is_some() {
        return TestResult::Fail("boot keyboard must not be detected as PTP");
    }
    TestResult::Pass
}
kernel_test_in!("hid/ptp", smoke_ptp_detect_rejects_non_touchpad);

// ── HID Pen profile ───────────────────────────────────────────────

/// Synthetic Pen descriptor. One Pen Application Collection, Report
/// ID 5: tip / barrel / invert / eraser / in-range (5 bits + 3 pad)
/// + X/Y (16-bit each) + Pressure (16) + X-Tilt/Y-Tilt (8-bit signed)
/// + Twist (16).
const PEN_DESCRIPTOR: &[u8] = &[
    0x05, 0x0D, // Digitizer page
    0x09, 0x02, // Usage (Pen)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x05, //   Report ID (5)
    0x09, 0x20, //   Usage (Stylus)
    0xA1, 0x00, //   Collection (Physical)
    0x09, 0x42, //     Tip Switch
    0x09, 0x44, //     Barrel Switch
    0x09, 0x3C, //     Invert
    0x09, 0x45, //     Eraser
    0x09, 0x32, //     In Range
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x05, 0x81, 0x02, //     Input (Data,Var,Abs)
    0x75, 0x03, 0x95, 0x01, 0x81, 0x03, //     Input (Const,Var) — padding
    0x05, 0x01, //     Generic Desktop
    0x09, 0x30, //     Usage (X)
    0x26, 0xFF, 0x7F, // Logical Max 0x7FFF
    0x75, 0x10, 0x95, 0x01, 0x81, 0x02, 0x09, 0x31, //     Usage (Y)
    0x81, 0x02, 0x05, 0x0D, //     Digitizer
    0x09, 0x30, //     Tip Pressure
    0x26, 0xFF, 0x0F, // Logical Max 4095
    0x75, 0x10, 0x95, 0x01, 0x81, 0x02, 0x09, 0x3D, //     X-Tilt
    0x15, 0x80, 0x25, 0x7F, // signed -128..127
    0x75, 0x08, 0x95, 0x01, 0x81, 0x02, 0x09, 0x3E, //     Y-Tilt
    0x81, 0x02, 0x09, 0x41, //     Twist
    0x15, 0x00, 0x26, 0x67, 0x01, // 0..359
    0x75, 0x10, 0x95, 0x01, 0x81, 0x02, 0xC0, //   End Collection
    0xC0, // End Collection
];

fn smoke_pen_detect_finds_minimum_field_set() -> TestResult {
    use crate::pen::detect;

    let d = parse(PEN_DESCRIPTOR).expect("parse");

    let p = match detect(&d) {
        Some(p) => p,

        None => return TestResult::Fail("pen detect rejected valid descriptor"),
    };

    if p.input_report_id != 5 {
        return TestResult::Fail("report id");
    }

    if p.fields.tip_pressure.is_none()
        || p.fields.x_tilt.is_none()
        || p.fields.twist.is_none()
        || p.fields.barrel_switch.is_none()
    {
        return TestResult::Fail("missing optional field");
    }

    TestResult::Pass
}

kernel_test_in!("hid/pen", smoke_pen_detect_finds_minimum_field_set);

fn smoke_pen_decode_input_round_trip() -> TestResult {
    use crate::pen::{decode_input, detect};

    let d = parse(PEN_DESCRIPTOR).expect("parse");

    let p = detect(&d).expect("detect");

    // Construct a report:

    //   tip=1, barrel=0, invert=0, eraser=0, in-range=1, pad=000

    //   X=0x1234, Y=0x5678, Pressure=0x0F00, X-Tilt=-30, Y-Tilt=+45, Twist=180

    let report = [
        5,           // Report ID
        0b0001_0001, // tip + in-range, others clear
        0x34,
        0x12, // X
        0x78,
        0x56, // Y
        0x00,
        0x0F,          // Pressure
        (-30i8) as u8, // X-Tilt
        45,            // Y-Tilt
        180,
        0, // Twist (LE)
    ];

    let pen = match decode_input(&p, &report) {
        Ok(d) => d,

        Err(_) => return TestResult::Fail("decode_input failed"),
    };

    if !(pen.tip && pen.in_range && !pen.eraser && !pen.invert && !pen.barrel_button) {
        return TestResult::Fail("button state wrong");
    }

    if pen.x != 0x1234 || pen.y != 0x5678 {
        return TestResult::Fail("X/Y wrong");
    }

    if pen.pressure != Some(0x0F00) {
        return TestResult::Fail("pressure wrong");
    }

    if pen.x_tilt_deg != Some(-30) || pen.y_tilt_deg != Some(45) {
        return TestResult::Fail("tilt wrong");
    }

    if pen.twist != Some(180) {
        return TestResult::Fail("twist wrong");
    }

    TestResult::Pass
}

kernel_test_in!("hid/pen", smoke_pen_decode_input_round_trip);

fn smoke_pen_detect_rejects_non_pen_descriptor() -> TestResult {
    use crate::pen::detect;

    let d = parse(PTP_DESCRIPTOR).expect("parse");

    if detect(&d).is_some() {
        return TestResult::Fail("PTP must not be detected as Pen");
    }

    TestResult::Pass
}

kernel_test_in!("hid/pen", smoke_pen_detect_rejects_non_pen_descriptor);

// ── HID Sensor Collections ────────────────────────────────────────

/// Synthetic accelerometer descriptor: page 0x20 / usage 0x73, with
/// 16-bit X/Y/Z fields under report ID 1.
const ACCEL_DESCRIPTOR: &[u8] = &[
    0x05, 0x20, // Usage Page (Sensors)
    0x09, 0x73, // Usage (Motion: Accelerometer 3D)
    0xA1, 0x01, // Collection (Application)
    0x85, 0x01, //   Report ID (1)
    0x05, 0x20, //   Usage Page (Sensors) - same
    0x0A, 0x53, 0x04, // Usage (Acceleration X) — 2-byte form
    0x16, 0x00, 0x80, // Logical Min -32768
    0x26, 0xFF, 0x7F, // Logical Max 32767
    0x75, 0x10, 0x95, 0x01, //   Size 16, Count 1
    0x81, 0x02, //   Input (Data,Var,Abs)
    0x0A, 0x54, 0x04, // Usage (Acceleration Y)
    0x81, 0x02, 0x0A, 0x55, 0x04, // Usage (Acceleration Z)
    0x81, 0x02, 0xC0, // End Collection
];

fn smoke_sensor_detects_accelerometer() -> TestResult {
    use crate::sensor::{detect, SensorKind};

    let d = parse(ACCEL_DESCRIPTOR).expect("parse");

    let p = detect(&d).expect("detect");

    if p.kind != SensorKind::Accelerometer3D {
        return TestResult::Fail("sensor kind");
    }

    if p.axes.len() != 3 || p.input_report_id != 1 {
        return TestResult::Fail("axes / report id");
    }

    TestResult::Pass
}

kernel_test_in!("hid/sensor", smoke_sensor_detects_accelerometer);

fn smoke_sensor_decode_xyz_signed() -> TestResult {
    use crate::sensor::{decode_input, detect};

    let d = parse(ACCEL_DESCRIPTOR).expect("parse");

    let p = detect(&d).expect("detect");

    // X = +1000, Y = -500, Z = +9806 (1g).

    let report = [
        1, 0xE8, 0x03, // X = 1000
        0x0C, 0xFE, // Y = -500
        0x4E, 0x26, // Z = 9806
    ];

    let s = decode_input(&p, &report).expect("decode");

    if s.values != [1000, -500, 9806] {
        return TestResult::Fail("axis values wrong");
    }

    TestResult::Pass
}

kernel_test_in!("hid/sensor", smoke_sensor_decode_xyz_signed);

/// Ambient-light descriptor: single 32-bit Illuminance field.
const ALS_DESCRIPTOR: &[u8] = &[
    0x05, 0x20, // Sensors
    0x09, 0x41, // Light: Ambient Light
    0xA1, 0x01, 0x85, 0x02, //   Report ID 2
    0x0A, 0xD1, 0x04, // Illuminance (lux)
    0x17, 0x00, 0x00, 0x00, 0x00, // Logical Min 0 (4-byte form)
    0x27, 0xFF, 0xFF, 0xFF, 0x7F, // Logical Max 0x7FFFFFFF
    0x75, 0x20, 0x95, 0x01, //   Size 32, Count 1
    0x81, 0x02, 0xC0,
];

fn smoke_sensor_detects_ambient_light() -> TestResult {
    use crate::sensor::{decode_input, detect, SensorKind};

    let d = parse(ALS_DESCRIPTOR).expect("parse");

    let p = detect(&d).expect("detect");

    if p.kind != SensorKind::AmbientLight {
        return TestResult::Fail("sensor kind");
    }

    if p.axes.len() != 1 || p.input_report_id != 2 {
        return TestResult::Fail("axes");
    }

    let report = [2u8, 0xE8, 0x03, 0x00, 0x00]; // 1000 lux

    let s = decode_input(&p, &report).expect("decode");

    if s.values != [1000] {
        return TestResult::Fail("value");
    }

    TestResult::Pass
}

kernel_test_in!("hid/sensor", smoke_sensor_detects_ambient_light);

// ── Touchscreen descriptor + report decoder ──────────────────────

fn smoke_touchscreen_detects_two_finger_descriptor() -> TestResult {
    use crate::touchscreen;
    let blob = touchscreen::__touchscreen_descriptor_blob();
    let parsed = match parse(blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("parse(touchscreen descriptor) failed"),
    };
    let profile = match touchscreen::detect(&parsed) {
        Some(p) => p,
        None => return TestResult::Fail("touchscreen detect should have matched"),
    };
    if profile.contacts_max != 2 {
        return TestResult::Fail("expected 2 contacts max");
    }
    if profile.input_report_id != 1 {
        return TestResult::Fail("expected report id 1");
    }
    if profile.contact_count.is_none() {
        return TestResult::Fail("Contact Count field should have been captured");
    }
    if profile.x_range != (0, 0x7FFF) {
        return TestResult::Fail("X range should mirror Logical Min/Max");
    }
    if profile.y_range != (0, 0x7FFF) {
        return TestResult::Fail("Y range should mirror Logical Min/Max");
    }
    for c in &profile.contacts {
        if c.contact_id.is_none() || c.x.is_none() || c.y.is_none() {
            return TestResult::Fail("per-contact field set incomplete");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "hid/touchscreen",
    smoke_touchscreen_detects_two_finger_descriptor
);

fn smoke_touchscreen_rejects_touchpad_descriptor() -> TestResult {
    // The PTP blob's top-level usage is Touch Pad (0x05) — the
    // touchscreen probe should refuse it.
    let blob = crate::ptp::__ptp_descriptor_blob();
    let parsed = match parse(blob) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("parse failed"),
    };
    if crate::touchscreen::detect(&parsed).is_some() {
        return TestResult::Fail("touchscreen::detect should not match a Touch Pad descriptor");
    }
    TestResult::Pass
}
kernel_test_in!(
    "hid/touchscreen",
    smoke_touchscreen_rejects_touchpad_descriptor
);

fn smoke_touchscreen_decodes_report_payload() -> TestResult {
    use crate::touchscreen;
    let blob = touchscreen::__touchscreen_descriptor_blob();
    let parsed = parse(blob).expect("parse");
    let profile = touchscreen::detect(&parsed).expect("detect");

    // Hand-built wire report for the descriptor: 1-byte report id +
    // 2 fingers × (1-byte tip+in_range+pad + 1-byte contact_id +
    // 2-byte X + 2-byte Y) + 1-byte contact count = 1 + 12 + 1 = 14
    // bytes.
    let mut report = alloc::vec![0u8; 1 + 2 * (1 + 1 + 2 + 2) + 1];
    report[0] = 1; // report id
                   // Finger 0
    report[1] = 0b0000_0011; // tip + in_range
    report[2] = 0x05;
    report[3..5].copy_from_slice(&0x1234u16.to_le_bytes());
    report[5..7].copy_from_slice(&0x5678u16.to_le_bytes());
    // Finger 1
    report[7] = 0b0000_0001; // tip only
    report[8] = 0x07;
    report[9..11].copy_from_slice(&0x0F0Fu16.to_le_bytes());
    report[11..13].copy_from_slice(&0x00AAu16.to_le_bytes());
    // Contact Count
    report[13] = 2;

    let decoded = match touchscreen::decode_input(&profile, &report) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("decode_input failed"),
    };
    if decoded.contact_count != 2 {
        return TestResult::Fail("contact count should be 2");
    }
    if decoded.contacts.len() != 2 {
        return TestResult::Fail("two contacts expected");
    }
    let c0 = &decoded.contacts[0];
    if !c0.tip_switch || c0.contact_id != 0x05 || c0.x != 0x1234 || c0.y != 0x5678 {
        return TestResult::Fail("contact 0 decode wrong");
    }
    if !c0.in_range {
        return TestResult::Fail("contact 0 in_range should be true");
    }
    let c1 = &decoded.contacts[1];
    if !c1.tip_switch || c1.contact_id != 0x07 || c1.x != 0x0F0F || c1.y != 0x00AA {
        return TestResult::Fail("contact 1 decode wrong");
    }
    if c1.in_range {
        return TestResult::Fail("contact 1 in_range should be false");
    }
    TestResult::Pass
}
kernel_test_in!("hid/touchscreen", smoke_touchscreen_decodes_report_payload);

fn smoke_touchscreen_rejects_wrong_report_id() -> TestResult {
    use crate::touchscreen;
    let blob = touchscreen::__touchscreen_descriptor_blob();
    let parsed = parse(blob).expect("parse");
    let profile = touchscreen::detect(&parsed).expect("detect");
    let mut report = alloc::vec![0u8; 32];
    report[0] = 2; // wrong report id
    match touchscreen::decode_input(&profile, &report) {
        Err(_) => TestResult::Pass,
        Ok(_) => TestResult::Fail("mismatched report id should have been rejected"),
    }
}
kernel_test_in!("hid/touchscreen", smoke_touchscreen_rejects_wrong_report_id);
