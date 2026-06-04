//! USB HID Generic catch-all driver.
//!
//! ## Role
//!
//! When no specific HID class driver (keyboard, mouse, touchpad,
//! consumer, sensor) claims a HID interface, `hid-generic` binds it
//! as the last-resort fallback. It:
//!
//! 1. Parses the Report Descriptor.
//! 2. Walks each Input field in every incoming report and dispatches
//!    events according to the field's Usage Page:
//!    - **Keyboard / Keypad (0x07)**: via `usage_to_keycode` → `push_key`.
//!    - **Generic Desktop (0x01)**: X/Y absolute/relative axes →
//!      `push_global(Absolute/Pointer)`, Wheel → `push_global(Scroll)`.
//!    - **Button (0x09)**: → `push_global(Button)`.
//!    - **Consumer (0x0C)**: via `consumer::usage_to_keycode` → `push_key`.
//!    - **Unknown pages**: "raw report" delivery — pushes
//!      `InputEvent::Button` with usage code as `code` so consumers can
//!      observe the raw input without the kernel dropping it.
//! 3. Tracks the previous report to synthesise press/release events for
//!    Array-encoded fields (same diff approach as boot-keyboard and
//!    consumer drivers).
//!
//! ## Linux reference
//!
//! Linux's `hid-generic.c` is 98 lines (GPL-2.0-or-later). It calls
//! `hid_parse` + `hid_hw_start(HID_CONNECT_DEFAULT)`, delegating all
//! dispatch to `hid-core.c::hid_input_report` and `hid-input.c`.
//! NARF lacks those shared layers; this module inlines the equivalent
//! dispatch directly.
//!
//! The field-walking logic mirrors `hid-input.c::hidinput_hid_event`
//! (GPL-2.0-or-later), specifically the per-usage-page dispatch at
//! line 745 et seq.
//!
//! ## References
//!
//! - Linux `drivers/hid/hid-generic.c` (line 65: `hid_generic_probe`).
//!   GPL-2.0-or-later.
//! - Linux `drivers/hid/hid-input.c` `hidinput_hid_event` (line 1545).
//!   GPL-2.0-or-later. NARF adaptation under NARF's GPL-2.0-or-later.
//! - HID 1.11 §6.2.2.5, §6.2.2.7 (field flags, global state).

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_input::{
    evdev::{
        dispatch_key_to_node, dispatch_rel_to_node, key, rel, DeviceCaps, DeviceId, DeviceNode,
        ROUTER,
    },
    push_global, push_key, AbsoluteEvent, ButtonEvent, InputEvent, PointerEvent, ScrollEvent,
};
use narf_lib::sync::IrqSafeSpinLock;

use super::consumer::usage_to_keycode as consumer_usage_to_keycode;
use super::report_descriptor::{
    parse, Field, FieldFlags, FieldKind, ReportDescriptor, USAGE_PAGE_BUTTON, USAGE_PAGE_CONSUMER,
    USAGE_PAGE_GENERIC_DESKTOP, USAGE_PAGE_KEYBOARD,
};
use crate::hid::{usage_to_keycode, HidError};
use crate::xhci::Xhci;

// Generic Desktop usage IDs (§4, table 4-1 / 4-3) used for axis dispatch.
const GD_X: u16 = 0x30;
const GD_Y: u16 = 0x31;
const GD_Z: u16 = 0x32;
const GD_WHEEL: u16 = 0x38;
const GD_H_WHEEL: u16 = 0x37;

/// Maximum report size we'll allocate for a generic device's buffer.
const MAX_GENERIC_REPORT: usize = 64;

// ── Bound device record ───────────────────────────────────────────────

/// One bound HID Generic interface.
#[derive(Debug)]
pub struct GenericDevice {
    pub slot_id: u8,
    pub interrupt_in_dci: u8,
    pub interface_num: u8,
    /// Parsed descriptor — needed to walk fields at runtime.
    pub descriptor: ReportDescriptor,
    /// Previous raw report (up to `MAX_GENERIC_REPORT` bytes).
    /// Used for Array-field diff to generate press/release events.
    prev_report: IrqSafeSpinLock<[u8; MAX_GENERIC_REPORT]>,
    /// evdev ROUTER device id — for unregister on detach.
    pub(crate) evdev_id: DeviceId,
    /// evdev DeviceNode — keyboard/mouse events dispatched here.
    pub(crate) evdev_node: Arc<DeviceNode>,
}

/// Global registry of bound Generic HID interfaces.
static GENERIC_DEVICES: IrqSafeSpinLock<Vec<GenericDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Lock-free count.
pub static ATTACHED_GENERIC_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Build a `DeviceCaps` set for a generic HID device by inspecting the
/// parsed descriptor. We declare EV_KEY for any Keyboard/Consumer/Button
/// field, and EV_REL for any relative Generic-Desktop axis field.
/// This gives the ROUTER enough information to filter events and expose
/// a correctly-typed device node.
fn generic_evdev_caps(descriptor: &ReportDescriptor) -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    for field in descriptor
        .fields
        .iter()
        .filter(|f| f.kind == FieldKind::Input)
    {
        match field.usage_page {
            USAGE_PAGE_KEYBOARD => {
                // Full boot-range keyboard usages.
                for c in 1u16..=127 {
                    caps.add_key(c);
                }
            }
            USAGE_PAGE_CONSUMER => {
                // Expose standard consumer codes.
                for c in [
                    key::BTN_LEFT,
                    key::BTN_RIGHT,
                    key::BTN_MIDDLE,
                    // Media key placeholder range 0x70..=0x77 (volume etc.).
                    0x71u16,
                    0x72,
                    0x73,
                ] {
                    caps.add_key(c);
                }
            }
            USAGE_PAGE_BUTTON => {
                // Up to 8 generic buttons.
                for c in [
                    key::BTN_LEFT,
                    key::BTN_RIGHT,
                    key::BTN_MIDDLE,
                    key::BTN_SIDE,
                    key::BTN_EXTRA,
                ] {
                    caps.add_key(c);
                }
            }
            USAGE_PAGE_GENERIC_DESKTOP => {
                let is_relative = field.flags.contains(FieldFlags::RELATIVE);
                if is_relative {
                    caps.add_rel(rel::REL_X);
                    caps.add_rel(rel::REL_Y);
                }
            }
            _ => {}
        }
    }
    caps
}

// ── Bind entry point ──────────────────────────────────────────────────

/// Bind a HID interface as a Generic device. `descriptor_blob` is the
/// raw Report Descriptor fetched by the attach dispatcher. Returns
/// `Err(NotBootKeyboard)` if the descriptor fails to parse (so the
/// dispatcher can skip silently). Registers a DeviceNode with the
/// evdev ROUTER so keyboard/mouse events reach `/dev/input/event<N>`.
pub async fn try_bind_generic(
    xhci_dev: &Xhci,
    slot_id: u8,
    interface_num: u8,
    interrupt_in_dci: u8,
    descriptor_blob: &[u8],
) -> Result<(), HidError> {
    let descriptor = parse(descriptor_blob).map_err(|_| HidError::NotBootKeyboard)?;

    // Arm one interrupt-IN TRB.
    xhci_dev
        .arm_interrupt_in(slot_id, interrupt_in_dci, MAX_GENERIC_REPORT as u32)
        .map_err(HidError::Xhci)?;

    // Register with the evdev ROUTER.
    let caps = generic_evdev_caps(&descriptor);
    let (evdev_id, evdev_node) = ROUTER.register_device(caps);

    let dev = GenericDevice {
        slot_id,
        interrupt_in_dci,
        interface_num,
        descriptor,
        prev_report: IrqSafeSpinLock::new([0u8; MAX_GENERIC_REPORT]),
        evdev_id,
        evdev_node,
    };
    {
        let mut g = GENERIC_DEVICES.lock();
        g.push(dev);
        ATTACHED_GENERIC_COUNT.store(g.len() as u32, core::sync::atomic::Ordering::Release);
    }
    {
        use core::fmt::Write as _;
        let _ = core::write!(
            narf_console::Writer,
            "  usb-hid: generic slot={} iface={} dci={}\n",
            slot_id,
            interface_num,
            interrupt_in_dci,
        );
    }
    Ok(())
}

/// Unregister a generic device's evdev DeviceNode from the ROUTER.
/// Call when the device is detached / unplugged.
pub fn unregister_generic_evdev(slot_id: u8) {
    let mut g = GENERIC_DEVICES.lock();
    if let Some(pos) = g.iter().position(|d| d.slot_id == slot_id) {
        let dev = g.remove(pos);
        ROUTER.unregister_device(dev.evdev_id);
        ATTACHED_GENERIC_COUNT.store(g.len() as u32, core::sync::atomic::Ordering::Release);
    }
}

// ── Pump ─────────────────────────────────────────────────────────────

/// Drain reports from all Generic devices, dispatch events. Returns
/// total events across all devices.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let len = GENERIC_DEVICES.lock().len();
    let mut total = 0;
    for idx in 0..len {
        total += pump_one(xhci_dev, idx);
    }
    total
}

fn pump_one(xhci_dev: &Xhci, idx: usize) -> usize {
    let (slot_id, dci) = {
        let g = GENERIC_DEVICES.lock();
        match g.get(idx) {
            Some(d) => (d.slot_id, d.interrupt_in_dci),
            None => return 0,
        }
    };
    let mut total = 0;
    let mut buf = [0u8; MAX_GENERIC_REPORT];
    loop {
        match xhci_dev.poll_interrupt_in(slot_id, dci, &mut buf) {
            Ok(Some(n)) => {
                let report = &buf[..n.min(MAX_GENERIC_REPORT)];
                // Snapshot descriptor + prev_report + evdev_node under lock.
                let (desc, prev, node) = {
                    let g = GENERIC_DEVICES.lock();
                    match g.get(idx) {
                        Some(d) => {
                            let pr = *d.prev_report.lock();
                            (d.descriptor.clone(), pr, Arc::clone(&d.evdev_node))
                        }
                        None => break,
                    }
                };
                total += dispatch_report(&desc, report, &prev[..n.min(MAX_GENERIC_REPORT)], &node);
                // Update prev_report.
                {
                    let g = GENERIC_DEVICES.lock();
                    if let Some(d) = g.get(idx) {
                        let mut pr = d.prev_report.lock();
                        let copy_len = n.min(MAX_GENERIC_REPORT);
                        pr[..copy_len].copy_from_slice(&buf[..copy_len]);
                        // Zero out any trailing bytes from the previous report.
                        pr[copy_len..].fill(0);
                    }
                }
                buf = [0u8; MAX_GENERIC_REPORT];
            }
            _ => break,
        }
    }
    total
}

// ── Report dispatch ───────────────────────────────────────────────────

/// Extract a bit-field value from a raw report byte slice.
/// `bit_offset` is 0-based from the start of the post-report-id payload.
/// `size_bits` is the field width. Returns the value sign-extended
/// when `logical_min < 0`.
fn extract_field_value(report: &[u8], bit_offset: u32, size_bits: u32, logical_min: i32) -> i32 {
    if size_bits == 0 {
        return 0;
    }
    let byte_offset = (bit_offset / 8) as usize;
    let bit_shift = bit_offset % 8;
    let bytes_needed = ((bit_shift + size_bits + 7) / 8) as usize;
    if byte_offset + bytes_needed > report.len() {
        return 0;
    }
    // Accumulate up to 4 bytes.
    let mut raw: u32 = 0;
    for b in (0..bytes_needed.min(4)).rev() {
        raw = (raw << 8) | report[byte_offset + b] as u32;
    }
    // This is wrong for big byte orders but HID is little-endian.
    // Reread in little-endian.
    raw = 0;
    for b in 0..bytes_needed.min(4) {
        raw |= (report[byte_offset + b] as u32) << (b * 8);
    }
    raw >>= bit_shift;
    let mask = if size_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << size_bits) - 1
    };
    raw &= mask;

    // Sign-extend if this is a signed field (logical_min < 0).
    if logical_min < 0 && size_bits < 32 {
        let sign_bit = 1u32 << (size_bits - 1);
        if raw & sign_bit != 0 {
            return (raw | !mask) as i32;
        }
    }
    raw as i32
}

/// Dispatch one incoming report against the parsed descriptor, emitting
/// input events for each non-padding field to both the legacy global
/// ring and the evdev ROUTER DeviceNode. Returns event count.
///
/// Mirrors `hid-input.c::hidinput_hid_event` per-page dispatch.
/// `node` receives keyboard/pointer events for ROUTER delivery.
pub fn dispatch_report(
    desc: &ReportDescriptor,
    report: &[u8],
    prev: &[u8],
    node: &DeviceNode,
) -> usize {
    let mut emitted = 0usize;

    // If the descriptor uses report IDs, the first byte is the report ID.
    // Strip it before feeding bits to extract_field_value.
    let (report_id, payload): (u8, &[u8]) = if desc.has_report_ids {
        if report.is_empty() {
            return 0;
        }
        (report[0], &report[1..])
    } else {
        (0, report)
    };
    let prev_payload: &[u8] = if desc.has_report_ids {
        if prev.len() > 1 {
            &prev[1..]
        } else {
            &[]
        }
    } else {
        prev
    };

    for field in desc.fields.iter().filter(|f| {
        f.kind == FieldKind::Input
            && f.report_id == report_id
            && !f.flags.contains(FieldFlags::CONSTANT)
    }) {
        emitted += dispatch_field(field, payload, prev_payload, node);
    }
    emitted
}

/// Dispatch one field's events. Returns count.
fn dispatch_field(field: &Field, payload: &[u8], prev_payload: &[u8], node: &DeviceNode) -> usize {
    let mut emitted = 0;
    let is_variable = field.flags.contains(FieldFlags::VARIABLE);
    let is_relative = field.flags.contains(FieldFlags::RELATIVE);

    if is_variable {
        // Variable fields: one value per element, addressed by usage index.
        for elem in 0..field.report_count {
            let bit_off = field.bit_offset + elem * field.report_size;
            let val = extract_field_value(payload, bit_off, field.report_size, field.logical_min);
            let prev_val =
                extract_field_value(prev_payload, bit_off, field.report_size, field.logical_min);
            if val == prev_val && !is_relative {
                continue; // Absolute: no change.
            }
            // Pick the usage for this element.
            let usage_id: u16 = if (elem as usize) < field.usages.len() {
                field.usages[elem as usize].1
            } else if let (Some(min), Some(max)) = (field.usage_min, field.usage_max) {
                let id = min.1 + elem as u16;
                if id <= max.1 {
                    id
                } else {
                    continue;
                }
            } else {
                continue;
            };

            emitted += dispatch_usage_value(field.usage_page, usage_id, val, is_relative, node);
        }
    } else {
        // Array fields: each non-zero element is a currently-pressed usage id.
        // Diff old vs new array.
        let count = field.report_count as usize;
        // Collect current elements.
        let mut cur_usages: Vec<u32> = Vec::new();
        let mut prev_usages: Vec<u32> = Vec::new();
        for elem in 0..(count.min(16)) {
            let bit_off = field.bit_offset + elem as u32 * field.report_size;
            let v = extract_field_value(payload, bit_off, field.report_size, field.logical_min);
            let p =
                extract_field_value(prev_payload, bit_off, field.report_size, field.logical_min);
            if v > 0 {
                cur_usages.push(v as u32);
            }
            if p > 0 {
                prev_usages.push(p as u32);
            }
        }
        // Releases: in prev but not in cur.
        for &pu in &prev_usages {
            if !cur_usages.iter().any(|&c| c == pu) {
                emitted += dispatch_array_usage(field.usage_page, pu, false, node);
            }
        }
        // Presses: in cur but not in prev.
        for &cu in &cur_usages {
            if !prev_usages.iter().any(|&p| p == cu) {
                emitted += dispatch_array_usage(field.usage_page, cu, true, node);
            }
        }
    }
    emitted
}

/// Dispatch a variable-field value to both the legacy global ring and
/// the evdev ROUTER DeviceNode.
fn dispatch_usage_value(
    page: u16,
    usage: u16,
    val: i32,
    relative: bool,
    node: &DeviceNode,
) -> usize {
    match page {
        USAGE_PAGE_KEYBOARD => {
            // Keyboard page: bit-per-key (modifier byte style).
            // Val=1 → press, val=0 → release.
            let code = usage_to_keycode(usage as u8);
            // Legacy ring.
            push_key(code, val != 0);
            // evdev ROUTER.
            dispatch_key_to_node(node, code as u16, val != 0);
            1
        }
        USAGE_PAGE_GENERIC_DESKTOP => {
            match usage {
                GD_X | GD_Y | GD_Z | GD_H_WHEEL if relative => {
                    let (dx, dy) = if usage == GD_X {
                        (val, 0)
                    } else if usage == GD_Y {
                        (0, val)
                    } else {
                        (0, 0)
                    };
                    if usage == GD_X || usage == GD_Y {
                        use narf_input::PointerButtons;
                        // Legacy ring.
                        push_global(InputEvent::Pointer(PointerEvent {
                            dx,
                            dy,
                            buttons: PointerButtons::EMPTY,
                        }));
                        // evdev ROUTER.
                        dispatch_rel_to_node(node, dx, dy);
                    } else {
                        push_global(InputEvent::Scroll(ScrollEvent { dx: val, dy: 0 }));
                    }
                    1
                }
                GD_WHEEL if relative => {
                    push_global(InputEvent::Scroll(ScrollEvent { dx: 0, dy: val }));
                    1
                }
                _ => {
                    // Unknown GD usage: emit as Absolute axis (legacy only).
                    push_global(InputEvent::Absolute(AbsoluteEvent {
                        axis: usage,
                        value: val,
                    }));
                    1
                }
            }
        }
        USAGE_PAGE_BUTTON => {
            // Button page: usage ID is button number, val = pressed.
            push_global(InputEvent::Button(ButtonEvent {
                code: usage,
                pressed: val != 0,
            }));
            1
        }
        USAGE_PAGE_CONSUMER => {
            let kc = consumer_usage_to_keycode(usage as u16);
            use narf_input::KeyCode;
            if kc != KeyCode::Unknown {
                // Legacy ring.
                push_key(kc, val != 0);
                // evdev ROUTER.
                dispatch_key_to_node(node, kc as u16, val != 0);
                1
            } else {
                // Raw fallback for unknown consumer codes.
                push_global(InputEvent::Button(ButtonEvent {
                    code: usage,
                    pressed: val != 0,
                }));
                1
            }
        }
        _ => {
            // Unknown usage page: raw delivery via ButtonEvent (legacy only).
            push_global(InputEvent::Button(ButtonEvent {
                code: usage,
                pressed: val != 0,
            }));
            1
        }
    }
}

/// Dispatch an Array-field usage (press or release) to both legacy ring
/// and evdev ROUTER DeviceNode.
fn dispatch_array_usage(page: u16, usage: u32, pressed: bool, node: &DeviceNode) -> usize {
    match page {
        USAGE_PAGE_KEYBOARD if usage <= 0xFF => {
            let kc = usage_to_keycode(usage as u8);
            // Legacy ring.
            push_key(kc, pressed);
            // evdev ROUTER.
            dispatch_key_to_node(node, kc as u16, pressed);
            1
        }
        USAGE_PAGE_CONSUMER => {
            let kc = consumer_usage_to_keycode(usage as u16);
            use narf_input::KeyCode;
            if kc != KeyCode::Unknown {
                // Legacy ring.
                push_key(kc, pressed);
                // evdev ROUTER.
                dispatch_key_to_node(node, kc as u16, pressed);
                1
            } else {
                push_global(InputEvent::Button(ButtonEvent {
                    code: usage as u16,
                    pressed,
                }));
                1
            }
        }
        _ => {
            // Unknown usage: raw fallback (legacy only).
            push_global(InputEvent::Button(ButtonEvent {
                code: usage as u16,
                pressed,
            }));
            1
        }
    }
}

#[doc(hidden)]
pub fn __reset_generic_devices_for_test() {
    GENERIC_DEVICES.lock().clear();
    ATTACHED_GENERIC_COUNT.store(0, core::sync::atomic::Ordering::Release);
}

// ── Smokes ─────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub(crate) mod tests {
    use super::super::report_descriptor::parse;
    use super::*;
    use narf_input::{
        __reset_global_ring_for_test, evdev::ROUTER, init_global_ring, pop_button, pop_key,
        pop_pointer, pop_scroll, KeyCode,
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    // Minimal Generic Desktop mouse descriptor (same as report_descriptor
    // tests) — used for the generic dispatch tests below.
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
        0x81, 0x02, //     Input (Data, Variable, Absolute) — button bits
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
        0xC0, //   End Collection (Physical)
        0xC0, // End Collection (Application)
    ];

    /// Allocate a throw-away DeviceNode for unit tests that call
    /// `dispatch_report` directly (no real device registration needed).
    fn make_test_node() -> Arc<DeviceNode> {
        let (_id, node) = ROUTER.register_device(DeviceCaps::new());
        node
    }

    // ── Test 1: Generic Desktop dispatch table ────────────────────────

    fn smoke_generic_gd_dispatch() -> TestResult {
        init_global_ring(128);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let desc = parse(MOUSE_DESC).expect("mouse parse failed");
        // Synthesise a mouse report: buttons=none (0b000), padding (0b00000),
        // X=+10, Y=-5, Wheel=+1.
        // Byte 0: buttons (3 bits) + padding (5 bits) = 0x00.
        // Byte 1: X = 10 = 0x0A.
        // Byte 2: Y = -5 = 0xFB (i8).
        // Byte 3: Wheel = 1 = 0x01.
        let node = make_test_node();
        let report: &[u8] = &[0x00, 0x0A, 0xFB, 0x01];
        let prev: &[u8] = &[0x00, 0x00, 0x00, 0x00];
        let n = dispatch_report(&desc, report, prev, &node);
        if n == 0 {
            return TestResult::Fail("expected at least 1 event from mouse report");
        }
        // Expect at least one Pointer and/or Scroll event.
        let mut saw_pointer = false;
        let mut saw_scroll = false;
        for _ in 0..16 {
            match narf_input::pop_pointer() {
                Some(p) if p.dx != 0 || p.dy != 0 => {
                    saw_pointer = true;
                }
                _ => {}
            }
            match narf_input::pop_scroll() {
                Some(_) => {
                    saw_scroll = true;
                }
                None => {}
            }
        }
        if !saw_pointer && !saw_scroll {
            return TestResult::Fail("no Pointer or Scroll event from mouse report");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/generic", smoke_generic_gd_dispatch);

    // ── Test 2: unknown-usage fallback path ──────────────────────────

    fn smoke_generic_unknown_usage_fallback() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        // A descriptor with a vendor-specific usage page (0xFF00).
        let vendor_desc: &[u8] = &[
            0x06, 0x00, 0xFF, // Usage Page (Vendor 0xFF00) — 2-byte
            0x09, 0x01, // Usage (Vendor Usage 1)
            0xA1, 0x01, // Collection (Application)
            0x09, 0x01, //   Usage (Vendor Usage 1)
            0x15, 0x00, //   Logical Minimum (0)
            0x25, 0x01, //   Logical Maximum (1)
            0x75, 0x01, //   Report Size (1)
            0x95, 0x01, //   Report Count (1)
            0x81, 0x02, //   Input (Data, Variable, Absolute)
            0x75, 0x07, //   Report Size (7) — padding
            0x95, 0x01, //   Report Count (1)
            0x81, 0x01, //   Input (Constant)
            0xC0, // End Collection
        ];
        let desc = parse(vendor_desc).expect("vendor parse failed");
        // Report: byte 0 = 0x01 (bit 0 set = vendor usage pressed).
        let node = make_test_node();
        let report: &[u8] = &[0x01];
        let prev: &[u8] = &[0x00];
        let n = dispatch_report(&desc, report, prev, &node);
        // Should emit at least 1 raw ButtonEvent.
        if n == 0 {
            return TestResult::Fail("expected fallback event for vendor usage");
        }
        // The ButtonEvent should be in the ring.
        match pop_button() {
            Some(b) if b.pressed => {}
            _ => return TestResult::Fail("expected pressed ButtonEvent in ring"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/generic",
        smoke_generic_unknown_usage_fallback
    );

    // ── Test 3: consumer-page dispatch ───────────────────────────────

    fn smoke_generic_consumer_dispatch() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        // A minimal consumer descriptor with a single volume-up button.
        let consumer_desc: &[u8] = &[
            0x05, 0x0C, // Usage Page (Consumer Control)
            0x09, 0x01, // Usage (Consumer Control)
            0xA1, 0x01, // Collection (Application)
            0x09, 0xE9, // Usage (Volume Up = 0xE9)
            0x15, 0x00, // Logical Minimum (0)
            0x25, 0x01, // Logical Maximum (1)
            0x75, 0x01, // Report Size (1)
            0x95, 0x01, // Report Count (1)
            0x81, 0x02, // Input (Data, Variable, Absolute)
            0x75, 0x07, // Padding
            0x95, 0x01, 0x81, 0x01, 0xC0, // End Collection
        ];
        let desc = parse(consumer_desc).expect("consumer parse failed");
        let node = make_test_node();
        let report: &[u8] = &[0x01]; // Volume Up pressed
        let prev: &[u8] = &[0x00];
        let n = dispatch_report(&desc, report, prev, &node);
        if n == 0 {
            return TestResult::Fail("expected event from consumer volume-up");
        }
        match pop_key() {
            Some(k) if k.code == KeyCode::VolumeUp && k.pressed => {}
            _ => return TestResult::Fail("VolumeUp key event not in ring"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/generic", smoke_generic_consumer_dispatch);

    // ── Test 4: keyboard-page Array dispatch (generic) ───────────────

    fn smoke_generic_keyboard_array_dispatch() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        // Minimal keyboard array descriptor (6-keycode boot format).
        let kbd_desc: &[u8] = &[
            0x05, 0x01, // Usage Page (Generic Desktop)
            0x09, 0x06, // Usage (Keyboard)
            0xA1, 0x01, // Collection (Application)
            0x05, 0x07, // Usage Page (Keyboard/Keypad)
            0x19, 0x00, // Usage Minimum (0)
            0x29, 0xFF, // Usage Maximum (255)
            0x15, 0x00, // Logical Minimum (0)
            0x26, 0xFF, 0x00, // Logical Maximum (255)
            0x75, 0x08, // Report Size (8)
            0x95, 0x06, // Report Count (6)
            0x81, 0x00, // Input (Data, Array, Absolute)
            0xC0, // End Collection
        ];
        let desc = parse(kbd_desc).expect("kbd parse failed");
        let node = make_test_node();
        // Report with Enter pressed (usage 0x28).
        let cur: &[u8] = &[0x28, 0x00, 0x00, 0x00, 0x00, 0x00];
        let prev: &[u8] = &[0x00; 6];
        let n = dispatch_report(&desc, cur, prev, &node);
        if n == 0 {
            return TestResult::Fail("expected key event from keyboard array report");
        }
        match pop_key() {
            Some(k) if k.code == KeyCode::Enter && k.pressed => {}
            _ => return TestResult::Fail("Enter key event not in ring"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/generic",
        smoke_generic_keyboard_array_dispatch
    );

    // ── Test 5: button-page dispatch ─────────────────────────────────

    fn smoke_generic_button_page_dispatch() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let desc = parse(MOUSE_DESC).expect("mouse parse failed");
        let node = make_test_node();
        // Left button (bit 0) pressed: byte 0 = 0x01.
        let report: &[u8] = &[0x01, 0x00, 0x00, 0x00];
        let prev: &[u8] = &[0x00, 0x00, 0x00, 0x00];
        let n = dispatch_report(&desc, report, prev, &node);
        if n == 0 {
            return TestResult::Fail("expected button event");
        }
        // Button 1 (left) should appear as ButtonEvent code=1.
        match pop_button() {
            Some(b) if b.code == 1 && b.pressed => {}
            _ => return TestResult::Fail("Button-1 event not in ring"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/generic",
        smoke_generic_button_page_dispatch
    );

    // ── Test 6: extract_field_value basic coverage ───────────────────

    fn smoke_extract_field_value_basic() -> TestResult {
        // Byte at offset 0, full byte.
        let data: &[u8] = &[0xAB, 0xCD];
        let v = extract_field_value(data, 0, 8, 0);
        if v != 0xAB {
            return TestResult::Fail("extract byte 0 failed");
        }
        // Second byte.
        let v2 = extract_field_value(data, 8, 8, 0);
        if v2 != 0xCD {
            return TestResult::Fail("extract byte 1 failed");
        }
        // 3 bits at offset 0: 0xAB = 0b10101011 → bits[0..2] = 0b011 = 3.
        let v3 = extract_field_value(data, 0, 3, 0);
        if v3 != 3 {
            return TestResult::Fail("extract 3 bits at offset 0 failed");
        }
        // Signed extraction: -1 in a 4-bit field = 0xF.
        let neg: &[u8] = &[0x0F];
        let v4 = extract_field_value(neg, 0, 4, -1);
        if v4 != -1 {
            return TestResult::Fail("signed 4-bit extraction failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/generic", smoke_extract_field_value_basic);
}
