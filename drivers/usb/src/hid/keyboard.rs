//! USB HID Keyboard driver — full 6KRO + report-protocol + LED.
//!
//! ## Boot vs Report Protocol
//!
//! HID boot keyboards (HID 1.11 §B.1) use a fixed 8-byte report:
//!   byte 0 = modifier mask, byte 1 = reserved, bytes 2–7 = keycodes.
//!
//! This driver defaults to Boot Protocol for safety (works out-of-the-
//! box with any USB keyboard, no descriptor parsing required). When the
//! report descriptor is available and `attach_with_descriptor` is called,
//! it switches to Report Protocol so the full keymap is available.
//!
//! Protocol switching is done with SET_PROTOCOL (HID §7.2.6, bRequest
//! 0x0B): wValue=0 → Boot, wValue=1 → Report.
//!
//! ## LED Output Reports
//!
//! HID keyboards expose Num/Caps/ScrollLock LEDs via an Output report.
//! In Boot Protocol the host sends a 1-byte report: bit 0 = NumLock,
//! bit 1 = CapsLock, bit 2 = ScrollLock (matching Linux usbkbd.c:163–165,
//! GPL-2.0-or-later). In Report Protocol the report structure is taken
//! from the descriptor via `find_led_output_report_id`. The report is
//! sent with SET_REPORT (HID §7.2.2, bRequest 0x09).
//!
//! ## References
//!
//! - HID 1.11 §7.2.6 SET_PROTOCOL, §7.2.2 SET_REPORT, §B.1 Boot Keyboard.
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - Linux `drivers/hid/usbhid/usbkbd.c` — `usb_kbd_irq` (report diff,
//!   line 100), `usb_kbd_event` (LED encoding, line 153). GPL-2.0-or-later;
//!   adapted under NARF's GPL-2.0-or-later licence.
//! - Linux `drivers/hid/hid-core.c` — `hid_open_report` (line 1259),
//!   `hid_parser_global` (line 401). State machine reference.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_input::{
    evdev::{dispatch_key_to_node, key, DeviceCaps, DeviceId, DeviceNode, ROUTER},
    push_key, update_modifiers, KeyCode, Modifiers,
};
use narf_lib::sync::IrqSafeSpinLock;

use crate::hid::{
    usage_to_keycode, HidError, HID_BOOT_PROTOCOL, HID_REPORT_PROTOCOL, HID_REQ_SET_IDLE,
    HID_REQ_SET_PROTOCOL,
};
use crate::xhci::Xhci;

use super::report_descriptor::{
    build_led_report, find_keyboard_fields, has_keyboard_collection, parse, FieldKind,
    ReportDescriptor, USAGE_PAGE_LED,
};

// HID class request codes.
/// SET_REPORT class request (HID §7.2.2). Sends Output/Feature report.
pub(crate) const HID_REQ_SET_REPORT: u8 = 0x09;
/// bmRequestType for Host→Device, Class, Interface.
const RT_HOST_TO_DEV_CLASS_IFACE: u8 = 0x21;

/// Boot-keyboard LED report type: Output report (HID §7.2.2, table 7-2).
/// wValue for SET_REPORT = (report_type<<8 | report_id).
const HID_REPORT_TYPE_OUTPUT: u16 = 0x02;

/// Rollover indicator: all 6 keycode slots contain 0x01 when the
/// keyboard cannot decode the current key combination (ghosting).
pub const ROLLOVER_USAGE: u8 = 0x01;

// ── LED state ────────────────────────────────────────────────────────

/// Current LED state for one keyboard. Updated by `set_leds` and
/// tracked so callers can diff against modifier state without an
/// extra async SET_REPORT on every idle poll.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LedState {
    pub num_lock: bool,
    pub caps_lock: bool,
    pub scroll_lock: bool,
}

impl LedState {
    /// Encode the LED state as the 1-byte boot-keyboard Output report.
    /// Bit layout (Linux usbkbd.c:163–165):
    ///   bit 0 = NumLock, bit 1 = CapsLock, bit 2 = ScrollLock.
    pub fn as_byte(self) -> u8 {
        use super::report_descriptor::{LED_BIT_CAPSLOCK, LED_BIT_NUMLOCK, LED_BIT_SCROLLLOCK};
        (self.num_lock as u8 * LED_BIT_NUMLOCK)
            | (self.caps_lock as u8 * LED_BIT_CAPSLOCK)
            | (self.scroll_lock as u8 * LED_BIT_SCROLLLOCK)
    }
}

// ── Keyboard protocol ─────────────────────────────────────────────────

/// Which protocol the keyboard is currently using (HID §7.2.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KbdProtocol {
    Boot,
    Report,
}

// ── Full keyboard device record ───────────────────────────────────────

/// A bound full-keyboard HID interface. Extends `BootKeyboard` with:
/// - Report Protocol capability.
/// - LED SET_REPORT support.
/// - Per-field keycode decoding via the parsed Report Descriptor.
/// - evdev ROUTER integration: events are dispatched to a `DeviceNode`
///   so `/dev/input/event<N>` is populated for userspace.
///   Ref: `linux/drivers/hid/usbhid/usbkbd.c::usb_kbd_irq` (GPL-2.0-or-later).
#[derive(Debug)]
pub struct UsbKeyboard {
    pub slot_id: u8,
    pub interrupt_in_dci: u8,
    pub interface_num: u8,
    pub protocol: KbdProtocol,
    /// LED report-id when using Report Protocol (None → boot LED byte).
    pub led_report_id: Option<u8>,
    /// Snapshot of last 8-byte report for boot-protocol diff.
    pub(crate) last_keys: [u8; 6],
    pub(crate) last_mods: u8,
    /// Parsed descriptor (Some only when using Report Protocol).
    #[allow(dead_code)]
    pub(crate) descriptor: Option<ReportDescriptor>,
    /// Current LED state.
    pub(crate) leds: LedState,
    /// evdev ROUTER device id — used to unregister on detach.
    pub(crate) evdev_id: DeviceId,
    /// evdev DeviceNode — used to dispatch events to ROUTER.
    pub(crate) evdev_node: Arc<DeviceNode>,
}

/// Global registry of bound USB keyboards.
static USB_KEYBOARDS: IrqSafeSpinLock<Vec<UsbKeyboard>> = IrqSafeSpinLock::new(Vec::new());

/// Lock-free count of bound keyboards.
pub static ATTACHED_USB_KBD_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// ── Modifier-byte bit positions ───────────────────────────────────────

// Defined here so tests in this module can reference them without the
// parent mod re-export.
use crate::hid::kbd_mod;

/// Decode the HID modifier byte into a Modifiers bitset and push
/// individual modifier KeyEvents for any bit transitions. Also dispatches
/// each modifier to the evdev DeviceNode for ROUTER delivery.
/// Returns (events_emitted, current_modifiers).
fn diff_modifiers(prev_byte: u8, cur_byte: u8, node: &DeviceNode) -> (usize, Modifiers) {
    use narf_input::push_global;
    use narf_input::InputEvent;
    use narf_input::KeyEvent;

    let cur_mods_raw = narf_input::Modifiers::from_bits_truncate(
        crate::hid::modifier_byte_to_modifiers(cur_byte).bits(),
    );

    // HID modifier bit → (KeyCode for legacy ring, evdev code for ROUTER).
    // Evdev codes from linux/include/uapi/linux/input-event-codes.h.
    let mod_pairs: &[(u8, KeyCode, u16)] = &[
        (kbd_mod::LCTRL, KeyCode::LeftCtrl, 29),
        (kbd_mod::LSHIFT, KeyCode::LeftShift, 42),
        (kbd_mod::LALT, KeyCode::LeftAlt, 56),
        (kbd_mod::LGUI, KeyCode::LeftMeta, 125),
        (kbd_mod::RCTRL, KeyCode::RightCtrl, 97),
        (kbd_mod::RSHIFT, KeyCode::RightShift, 54),
        (kbd_mod::RALT, KeyCode::RightAlt, 100),
        (kbd_mod::RGUI, KeyCode::RightMeta, 126),
    ];
    let mut emitted = 0usize;
    for &(bit, code, evdev_code) in mod_pairs {
        let was = prev_byte & bit != 0;
        let now = cur_byte & bit != 0;
        if was != now {
            // Legacy global ring.
            let mods = update_modifiers(code, now);
            push_global(InputEvent::Key(KeyEvent {
                code,
                pressed: now,
                modifiers: mods,
            }));
            // evdev ROUTER.
            dispatch_key_to_node(node, evdev_code, now);
            emitted += 1;
        }
    }
    (emitted, cur_mods_raw)
}

/// Diff two 6-byte keycode arrays and push press/release events to both
/// the legacy global ring and the evdev DeviceNode (ROUTER).
/// Returns the number of events pushed. Rollover (all slots = 0x01)
/// is suppressed — no events for phantom key combinations.
///
/// Ref: `linux/drivers/hid/usbhid/usbkbd.c::usb_kbd_irq` key-array diff
/// (line 100). GPL-2.0-or-later.
pub fn diff_keycodes(
    prev: &[u8; 6],
    cur: &[u8; 6],
    _cur_mods: Modifiers,
    node: &DeviceNode,
) -> usize {
    let is_rollover = cur.iter().all(|&k| k == ROLLOVER_USAGE);
    if is_rollover {
        return 0;
    }
    let mut emitted = 0;
    // Releases: keys in prev absent from cur.
    for &k in prev.iter() {
        if k == 0 || k == ROLLOVER_USAGE {
            continue;
        }
        if !cur.iter().any(|&c| c == k) {
            let kc = usage_to_keycode(k);
            // Legacy ring.
            push_key(kc, false);
            // evdev ROUTER — use KeyCode as u16 (matches set-1/evdev code).
            dispatch_key_to_node(node, kc as u16, false);
            emitted += 1;
        }
    }
    // Presses: keys in cur absent from prev.
    for &k in cur.iter() {
        if k == 0 || k == ROLLOVER_USAGE {
            continue;
        }
        if !prev.iter().any(|&p| p == k) {
            let kc = usage_to_keycode(k);
            // Legacy ring.
            push_key(kc, true);
            // evdev ROUTER.
            dispatch_key_to_node(node, kc as u16, true);
            emitted += 1;
        }
    }
    emitted
}

// ── Boot-protocol report decoder ─────────────────────────────────────

/// Decode a raw 8-byte boot-keyboard report and diff it against the
/// stored `last_mods`/`last_keys` on a `UsbKeyboard`, pushing events to
/// both the legacy global ring and the evdev ROUTER DeviceNode.
/// Returns the count of events emitted.
///
/// Ref: `linux/drivers/hid/usbhid/usbkbd.c::usb_kbd_irq` (GPL-2.0-or-later).
pub fn process_boot_report(kbd: &mut UsbKeyboard, raw: &[u8; 8]) -> usize {
    let new_mods = raw[0];
    let new_keys: [u8; 6] = [raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]];

    // Clone the Arc to get a reference without holding the global lock.
    let node = Arc::clone(&kbd.evdev_node);
    let (mod_events, cur_mods) = diff_modifiers(kbd.last_mods, new_mods, &node);
    let key_events = diff_keycodes(&kbd.last_keys, &new_keys, cur_mods, &node);

    kbd.last_mods = new_mods;
    kbd.last_keys = new_keys;
    mod_events + key_events
}

// ── LED SET_REPORT ────────────────────────────────────────────────────

/// Send a LED SET_REPORT to the keyboard. Uses the 1-byte boot-
/// protocol encoding (NumLock=bit0, CapsLock=bit1, ScrollLock=bit2).
///
/// Ref: Linux `usbkbd.c::usb_kbd_event` (line 153) for bit layout;
/// HID §7.2.2 for the SET_REPORT encoding.
pub async fn set_leds(
    xhci_dev: &Xhci,
    kbd: &mut UsbKeyboard,
    num: bool,
    caps: bool,
    scroll: bool,
) -> Result<(), HidError> {
    let new_leds = LedState {
        num_lock: num,
        caps_lock: caps,
        scroll_lock: scroll,
    };
    if new_leds == kbd.leds {
        return Ok(());
    }
    kbd.leds = new_leds;

    let (buf, len) = build_led_report(num, caps, scroll, kbd.led_report_id);
    let report_id = kbd.led_report_id.unwrap_or(0) as u16;
    let w_value = (HID_REPORT_TYPE_OUTPUT << 8) | report_id;
    // SET_REPORT: bmRequestType=0x21, bRequest=0x09, wValue=(type<<8|id),
    // wIndex=interface, wLength=len, data=[led_byte].
    xhci_dev
        .control_in(
            kbd.slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_REPORT,
            w_value,
            kbd.interface_num as u16,
            &mut {
                let mut d = [0u8; 2];
                d[..len].copy_from_slice(&buf[..len]);
                d
            }[..len],
        )
        .await
        .map_err(HidError::Xhci)
        .map(|_| ())
}

// ── Find LED output report ID in a parsed descriptor ─────────────────

/// Scan a parsed Report Descriptor for an Output field whose usage page
/// is LED (0x08). Returns the report_id of that field (0 if no report
/// IDs are used). Used when switching to Report Protocol.
pub fn find_led_output_report_id(desc: &ReportDescriptor) -> Option<u8> {
    desc.fields
        .iter()
        .find(|f| f.kind == FieldKind::Output && f.usage_page == USAGE_PAGE_LED)
        .map(|f| f.report_id)
}

// ── Switch to Report Protocol ─────────────────────────────────────────

/// Attempt to switch a keyboard to Report Protocol and parse its
/// descriptor. If successful, updates `kbd.protocol`, `kbd.descriptor`,
/// and `kbd.led_report_id`. On failure the keyboard stays in Boot
/// Protocol (safe fallback).
pub async fn try_switch_to_report_protocol(
    xhci_dev: &Xhci,
    kbd: &mut UsbKeyboard,
    descriptor_blob: &[u8],
) -> Result<(), HidError> {
    // Only attempt if the descriptor contains a keyboard collection.
    if !has_keyboard_collection(descriptor_blob) {
        return Err(HidError::NotBootKeyboard);
    }
    let desc = parse(descriptor_blob).map_err(|_| HidError::NotBootKeyboard)?;

    // Must have keyboard Input fields.
    let kbd_fields = find_keyboard_fields(&desc);
    if kbd_fields.is_empty() {
        return Err(HidError::NotBootKeyboard);
    }

    let led_rid = find_led_output_report_id(&desc);

    // Issue SET_PROTOCOL(Report).
    let mut nothing = [0u8; 0];
    xhci_dev
        .control_in(
            kbd.slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_PROTOCOL,
            HID_REPORT_PROTOCOL,
            kbd.interface_num as u16,
            &mut nothing,
        )
        .await
        .map_err(|_| HidError::SetProtocolFailed)?;

    kbd.protocol = KbdProtocol::Report;
    kbd.led_report_id = led_rid;
    kbd.descriptor = Some(desc);
    Ok(())
}

// ── evdev capability set for a USB boot keyboard ─────────────────────

/// Build the `DeviceCaps` for a USB boot-protocol keyboard.
/// Registers the full boot-keycode range (Linux evdev codes 1..=127)
/// plus the standard modifier keys.
///
/// Mirrors the i8042 keyboard capability setup in
/// `drivers/input/src/i8042.rs::init`.
pub fn keyboard_evdev_caps() -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    // Boot-protocol keycode range (set-1 / evdev 1..=127).
    for c in 1u16..=127 {
        caps.add_key(c);
    }
    // Standard modifier + extended key evdev codes.
    for c in [
        key::BTN_LEFT,
        key::BTN_RIGHT,
        key::BTN_MIDDLE,
        // Right-side modifier codes beyond 127.
        97u16,  // KEY_RIGHTCTRL
        100u16, // KEY_RIGHTALT
        125u16, // KEY_LEFTMETA
        126u16, // KEY_RIGHTMETA
    ] {
        caps.add_key(c);
    }
    caps
}

// ── Bind entry point (for the attach dispatcher) ──────────────────────

/// Bind an already-addressed xHCI slot as a USB keyboard.
/// Does NOT issue SET_CONFIGURATION (the attach dispatcher owns that).
/// Does issue SET_PROTOCOL(Boot) + SET_IDLE.
/// On success the keyboard is added to `USB_KEYBOARDS` and a
/// DeviceNode is registered with the evdev ROUTER so the keyboard
/// appears as `/dev/input/event<N>` for userspace.
///
/// Ref: `linux/drivers/hid/usbhid/usbkbd.c::usb_kbd_probe` pattern.
/// GPL-2.0-or-later.
pub async fn try_bind_keyboard_already_addressed(
    xhci_dev: &Xhci,
    slot_id: u8,
    interface_num: u8,
    interrupt_in_dci: u8,
) -> Result<(), HidError> {
    let mut nothing = [0u8; 0];
    // SET_PROTOCOL(Boot): wValue=0.
    xhci_dev
        .control_in(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_PROTOCOL,
            HID_BOOT_PROTOCOL,
            interface_num as u16,
            &mut nothing,
        )
        .await
        .map_err(|_| HidError::SetProtocolFailed)?;

    // SET_IDLE(0, 0) — non-fatal.
    let _ = xhci_dev
        .control_in(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            HID_REQ_SET_IDLE,
            0,
            interface_num as u16,
            &mut nothing,
        )
        .await;

    // Arm the interrupt-IN endpoint.
    xhci_dev
        .arm_interrupt_in(slot_id, interrupt_in_dci, 8)
        .map_err(HidError::Xhci)?;

    // Register with the evdev ROUTER. Mirrors i8042.rs::init().
    let (evdev_id, evdev_node) = ROUTER.register_device(keyboard_evdev_caps());

    let kbd = UsbKeyboard {
        slot_id,
        interrupt_in_dci,
        interface_num,
        protocol: KbdProtocol::Boot,
        led_report_id: None,
        last_keys: [0u8; 6],
        last_mods: 0,
        descriptor: None,
        leds: LedState::default(),
        evdev_id,
        evdev_node,
    };
    {
        let mut g = USB_KEYBOARDS.lock();
        g.push(kbd);
        ATTACHED_USB_KBD_COUNT.store(g.len() as u32, core::sync::atomic::Ordering::Release);
    }
    Ok(())
}

/// Unregister a USB keyboard's evdev DeviceNode from the ROUTER.
/// Call when the device is detached/unplugged so `/dev/input/event<N>`
/// disappears. Mirrors `input_unregister_device` in Linux.
pub fn unregister_keyboard_evdev(slot_id: u8) {
    let mut g = USB_KEYBOARDS.lock();
    if let Some(pos) = g.iter().position(|k| k.slot_id == slot_id) {
        let kbd = g.remove(pos);
        ROUTER.unregister_device(kbd.evdev_id);
        ATTACHED_USB_KBD_COUNT.store(g.len() as u32, core::sync::atomic::Ordering::Release);
    }
}

/// Drain reports from all bound USB keyboards, push events. Returns
/// total events across all keyboards.
pub fn pump_all(xhci_dev: &Xhci) -> usize {
    let len = USB_KEYBOARDS.lock().len();
    let mut total = 0;
    for idx in 0..len {
        total += pump_one(xhci_dev, idx);
    }
    total
}

fn pump_one(xhci_dev: &Xhci, idx: usize) -> usize {
    let (slot_id, dci) = {
        let g = USB_KEYBOARDS.lock();
        match g.get(idx) {
            Some(k) => (k.slot_id, k.interrupt_in_dci),
            None => return 0,
        }
    };
    let mut total = 0;
    let mut buf = [0u8; 8];
    loop {
        match xhci_dev.poll_interrupt_in(slot_id, dci, &mut buf) {
            Ok(Some(_)) => {
                let mut g = USB_KEYBOARDS.lock();
                if let Some(kbd) = g.get_mut(idx) {
                    total += process_boot_report(kbd, &buf);
                }
                buf = [0u8; 8];
            }
            _ => break,
        }
    }
    total
}

#[doc(hidden)]
pub fn __reset_usb_keyboards_for_test() {
    USB_KEYBOARDS.lock().clear();
    ATTACHED_USB_KBD_COUNT.store(0, core::sync::atomic::Ordering::Release);
}

// ── Smokes ────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub(crate) mod tests {
    use super::*;
    use narf_input::{__reset_global_ring_for_test, init_global_ring, pop_key, KeyCode};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Build a test `UsbKeyboard` already wired to a fresh evdev DeviceNode.
    /// Each test that calls `process_boot_report` or `diff_keycodes` should
    /// use this so it gets a valid `evdev_node`.
    fn make_test_kbd() -> UsbKeyboard {
        let (evdev_id, evdev_node) = ROUTER.register_device(keyboard_evdev_caps());
        UsbKeyboard {
            slot_id: 0,
            interrupt_in_dci: 0,
            interface_num: 0,
            protocol: KbdProtocol::Boot,
            led_report_id: None,
            last_keys: [0u8; 6],
            last_mods: 0,
            descriptor: None,
            leds: LedState::default(),
            evdev_id,
            evdev_node,
        }
    }

    // ── Test 1: boot-protocol parse — no keys ────────────────────────

    fn smoke_kbd_boot_no_keys() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let mut kbd = make_test_kbd();
        let raw = [0u8; 8];
        let n = process_boot_report(&mut kbd, &raw);
        if n != 0 {
            return TestResult::Fail("expected 0 events for empty report");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_boot_no_keys);

    // ── Test 2: boot-protocol — 3 keys + LSHIFT ──────────────────────

    fn smoke_kbd_boot_3keys_lshift() -> TestResult {
        init_global_ring(128);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let mut kbd = make_test_kbd();
        // LSHIFT (0x02) held, keys A(0x04), B(0x05), C(0x06).
        let raw: [u8; 8] = [0x02, 0x00, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00];
        let n = process_boot_report(&mut kbd, &raw);
        // 1 modifier event (LSHIFT) + 3 key presses = 4.
        if n != 4 {
            return TestResult::Fail("expected 4 events (1 mod + 3 keys)");
        }
        // Pop events — should contain LeftShift, A, B, C all pressed.
        let mut saw_lshift = false;
        let mut saw_a = false;
        let mut saw_b = false;
        let mut saw_c = false;
        for _ in 0..8 {
            match pop_key() {
                Some(k) if k.code == KeyCode::LeftShift && k.pressed => {
                    saw_lshift = true;
                }
                Some(k) if k.code == KeyCode::A && k.pressed => {
                    saw_a = true;
                }
                Some(k) if k.code == KeyCode::B && k.pressed => {
                    saw_b = true;
                }
                Some(k) if k.code == KeyCode::C && k.pressed => {
                    saw_c = true;
                }
                None => break,
                _ => {}
            }
        }
        if !saw_lshift {
            return TestResult::Fail("LeftShift press not in ring");
        }
        if !saw_a || !saw_b || !saw_c {
            return TestResult::Fail("A/B/C presses not all in ring");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_boot_3keys_lshift);

    // ── Test 3: 6KRO rollover ghosting detection ──────────────────────

    fn smoke_kbd_6kro_rollover() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let mut kbd = make_test_kbd();
        // Rollover: all keycode slots = 0x01.
        let raw: [u8; 8] = [0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
        let n = process_boot_report(&mut kbd, &raw);
        if n != 0 {
            return TestResult::Fail("rollover should emit 0 events");
        }
        if pop_key().is_some() {
            return TestResult::Fail("rollover leaked key event into ring");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_6kro_rollover);

    // ── Test 4: LED report encode (Caps + Num) ────────────────────────

    fn smoke_kbd_led_encode_caps_num() -> TestResult {
        use super::super::report_descriptor::{LED_BIT_CAPSLOCK, LED_BIT_NUMLOCK};
        let (buf, len) = super::super::report_descriptor::build_led_report(
            true,  // num_on
            true,  // caps_on
            false, // scroll_on
            None,
        );
        if len != 1 {
            return TestResult::Fail("expected 1-byte report for no-rid LED");
        }
        let expected = LED_BIT_NUMLOCK | LED_BIT_CAPSLOCK;
        if buf[0] != expected {
            return TestResult::Fail("Caps+Num LED byte wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_led_encode_caps_num);

    // ── Test 5: press → release round-trip ───────────────────────────

    fn smoke_kbd_press_release_roundtrip() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let mut kbd = make_test_kbd();
        // Press Enter.
        let press: [u8; 8] = [0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00];
        process_boot_report(&mut kbd, &press);
        match pop_key() {
            Some(k) if k.code == KeyCode::Enter && k.pressed => {}
            _ => return TestResult::Fail("Enter press not in ring"),
        }
        // Release Enter.
        let release = [0u8; 8];
        process_boot_report(&mut kbd, &release);
        match pop_key() {
            Some(k) if k.code == KeyCode::Enter && !k.pressed => {}
            _ => return TestResult::Fail("Enter release not in ring"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/hid/keyboard",
        smoke_kbd_press_release_roundtrip
    );

    // ── Test 6: diff_keycodes — no rollover, 2 simultaneous keys ─────

    fn smoke_kbd_diff_keycodes_two_keys() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let (_id, node) = ROUTER.register_device(keyboard_evdev_caps());
        let prev = [0u8; 6];
        let cur: [u8; 6] = [0x04, 0x05, 0, 0, 0, 0]; // A, B
        let mods = Modifiers::EMPTY;
        let n = diff_keycodes(&prev, &cur, mods, &node);
        if n != 2 {
            return TestResult::Fail("expected 2 press events");
        }
        let mut saw_a = false;
        let mut saw_b = false;
        for _ in 0..4 {
            match pop_key() {
                Some(k) if k.code == KeyCode::A && k.pressed => {
                    saw_a = true;
                }
                Some(k) if k.code == KeyCode::B && k.pressed => {
                    saw_b = true;
                }
                None => break,
                _ => {}
            }
        }
        if !saw_a || !saw_b {
            return TestResult::Fail("A or B press missing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_diff_keycodes_two_keys);

    // ── Test 7: modifier-only report ─────────────────────────────────

    fn smoke_kbd_modifier_only() -> TestResult {
        init_global_ring(64);
        __reset_global_ring_for_test();
        narf_input::__reset_modifiers_for_test();

        let mut kbd = make_test_kbd();
        // RightAlt pressed (bit 6 of modifier byte).
        let raw: [u8; 8] = [kbd_mod::RALT, 0, 0, 0, 0, 0, 0, 0];
        let n = process_boot_report(&mut kbd, &raw);
        if n != 1 {
            return TestResult::Fail("expected 1 modifier event");
        }
        match pop_key() {
            Some(k) if k.code == KeyCode::RightAlt && k.pressed => {}
            _ => return TestResult::Fail("RightAlt press not in ring"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_modifier_only);

    // ── Test 8: LedState::as_byte encoding ───────────────────────────

    fn smoke_kbd_led_state_as_byte() -> TestResult {
        use super::super::report_descriptor::{
            LED_BIT_CAPSLOCK, LED_BIT_NUMLOCK, LED_BIT_SCROLLLOCK,
        };
        let all_off = LedState {
            num_lock: false,
            caps_lock: false,
            scroll_lock: false,
        };
        if all_off.as_byte() != 0x00 {
            return TestResult::Fail("all-off LED byte should be 0x00");
        }
        let caps_only = LedState {
            num_lock: false,
            caps_lock: true,
            scroll_lock: false,
        };
        if caps_only.as_byte() != LED_BIT_CAPSLOCK {
            return TestResult::Fail("caps-only LED byte wrong");
        }
        let all_on = LedState {
            num_lock: true,
            caps_lock: true,
            scroll_lock: true,
        };
        if all_on.as_byte() != (LED_BIT_NUMLOCK | LED_BIT_CAPSLOCK | LED_BIT_SCROLLLOCK) {
            return TestResult::Fail("all-on LED byte wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/hid/keyboard", smoke_kbd_led_state_as_byte);
}
