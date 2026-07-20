//! HID-over-I2C keyboard pump glue.
//!
//! What this module does
//! ---------------------
//! Turns the per-report state produced by
//! [`narf_hid::keyboard::decode_input`] into evdev `EV_KEY` events on
//! a per-device [`DeviceNode`], with press (1) / release (0) /
//! autorepeat (2) derived by diffing against the previous report —
//! exactly the model the i8042 PS/2 driver uses, but sourced from a
//! HID Keyboard collection over I2C instead of scancode-set-1 bytes.
//!
//! This is the transport for the built-in keyboard on modern laptops
//! (ultrabooks / 2-in-1s / Surface / many Dell/HP/Lenovo), whose
//! keyboard attaches over I2C-HID (PNP0C50) rather than USB or a
//! legacy i8042 controller.
//!
//! Report diffing
//! --------------
//! HID keyboard input reports are *level* state, not events: each
//! report lists every key currently held (an 8-bit modifier bitmap +
//! up to N array slots of held usage ids). We keep the previous
//! decoded report and emit:
//!   - press   (value 1) for a usage/modifier newly held,
//!   - release (value 0) for one no longer held,
//!   - repeat  (value 2) for a usage still held across reports (Linux
//!     input-core auto-repeats at the driver level for keyboards),
//!
//! then one `EV_SYN SYN_REPORT` to close the frame.
//!
//! Consumer (Fn / media) row
//! -------------------------
//! Laptop Fn keys (volume, brightness, transport) come through a
//! separate Consumer Control collection; [`pump_consumer_report`]
//! diffs that report the same way and emits the corresponding
//! `KEY_VOLUMEUP` / `KEY_BRIGHTNESSUP` / … codes.
//!
//! Reference: `drivers/input/src/i8042.rs` for the keycode-emission
//! shape, and Linux `drivers/hid/hid-input.c` for the HID-usage →
//! evdev mapping model.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_hid::keyboard::{
    consumer_usage_to_keycode, hid_usage_to_keycode, modifier_bit_to_keycode, DecodedKeyboardReport,
};
use narf_input::evdev::{DeviceNode, EvdevEvent, EventType};

/// Per-device keyboard state carried between reports. Owns the
/// previous decoded report so the pump can diff press/release/repeat.
#[derive(Clone, Debug, Default)]
pub struct KeyboardPumpState {
    /// Modifier bitmap from the previous report.
    prev_modifiers: u8,
    /// HID keyboard usages held in the previous report.
    prev_keys: Vec<u16>,
}

impl KeyboardPumpState {
    pub const fn new() -> Self {
        Self {
            prev_modifiers: 0,
            prev_keys: Vec::new(),
        }
    }
}

/// One emitted evdev key transition — `(KEY_* code, value)` where
/// value is 1=press, 0=release, 2=autorepeat. Returned by the
/// test-only diff helper; the live pump feeds these straight into a
/// `DeviceNode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyEmit {
    pub code: u16,
    pub value: i32,
}

/// Diff `decoded` against `state`'s previous report and produce the
/// ordered list of `(KEY_* code, value)` transitions. Updates `state`
/// to hold `decoded` as the new baseline.
///
/// Emission order matches Linux's evdev convention and keeps the frame
/// self-consistent: releases first (so a key can be released and its
/// slot reused in the same frame without a spurious double-press),
/// then modifiers, then key presses/repeats. Autorepeat (value 2) is
/// emitted for any key still held across the two reports.
pub fn diff_report(state: &mut KeyboardPumpState, decoded: &DecodedKeyboardReport) -> Vec<KeyEmit> {
    let mut out = Vec::new();

    // ── Key array releases: previously held, now absent ──
    for &usage in &state.prev_keys {
        if !decoded.keys.contains(&usage) {
            if let Some(code) = hid_usage_to_keycode(usage) {
                out.push(KeyEmit { code, value: 0 });
            }
        }
    }

    // ── Modifier transitions (per bit) ──
    let changed = state.prev_modifiers ^ decoded.modifiers;
    for bit in 0u8..8 {
        let mask = 1u8 << bit;
        if changed & mask == 0 {
            continue;
        }
        if let Some(code) = modifier_bit_to_keycode(bit) {
            let pressed = decoded.modifiers & mask != 0;
            out.push(KeyEmit {
                code,
                value: if pressed { 1 } else { 0 },
            });
        }
    }

    // ── Key array presses / repeats ──
    for &usage in &decoded.keys {
        if let Some(code) = hid_usage_to_keycode(usage) {
            let value = if state.prev_keys.contains(&usage) {
                2 // still held → autorepeat
            } else {
                1 // newly pressed
            };
            out.push(KeyEmit { code, value });
        }
    }

    // Latch the new baseline.
    state.prev_modifiers = decoded.modifiers;
    state.prev_keys.clear();
    state.prev_keys.extend_from_slice(&decoded.keys);

    out
}

/// Diff a decoded keyboard report against the previous one and
/// dispatch the resulting `EV_KEY` transitions (+ a closing
/// `EV_SYN SYN_REPORT`) to `node`. Returns the number of key events
/// emitted (excluding the SYN). A frame that changed nothing emits no
/// SYN — keeping idle polls off the evdev ring.
pub fn pump_report(
    node: &DeviceNode,
    state: &mut KeyboardPumpState,
    decoded: &DecodedKeyboardReport,
) -> usize {
    let emits = diff_report(state, decoded);
    dispatch_emits(node, &emits)
}

/// Per-device consumer (Fn/media) state — the set of consumer usages
/// held in the previous report, so we can diff press/release.
#[derive(Clone, Debug, Default)]
pub struct ConsumerPumpState {
    prev: Vec<u16>,
}

impl ConsumerPumpState {
    pub const fn new() -> Self {
        Self { prev: Vec::new() }
    }
}

/// Diff a decoded consumer report (list of active consumer usage ids)
/// against the previous one, producing `(KEY_* code, value)` press/
/// release transitions. Consumer keys are momentary and don't
/// autorepeat, so only 1/0 are emitted.
pub fn diff_consumer(state: &mut ConsumerPumpState, active: &[u16]) -> Vec<KeyEmit> {
    let mut out = Vec::new();
    // Releases.
    for &usage in &state.prev {
        if !active.contains(&usage) {
            if let Some(code) = consumer_usage_to_keycode(usage) {
                out.push(KeyEmit { code, value: 0 });
            }
        }
    }
    // Presses (newly active only).
    for &usage in active {
        if !state.prev.contains(&usage) {
            if let Some(code) = consumer_usage_to_keycode(usage) {
                out.push(KeyEmit { code, value: 1 });
            }
        }
    }
    state.prev.clear();
    state.prev.extend_from_slice(active);
    out
}

/// Diff + dispatch a consumer report to `node`. Returns the number of
/// key events emitted (excluding the closing SYN).
pub fn pump_consumer_report(
    node: &DeviceNode,
    state: &mut ConsumerPumpState,
    active: &[u16],
) -> usize {
    let emits = diff_consumer(state, active);
    dispatch_emits(node, &emits)
}

/// Dispatch a slice of key transitions to `node` as one evdev frame,
/// appending a single `SYN_REPORT` iff at least one key event was
/// emitted. Shared by the keyboard + consumer pumps.
fn dispatch_emits(node: &DeviceNode, emits: &[KeyEmit]) -> usize {
    if emits.is_empty() {
        return 0;
    }
    let now = narf_time::now_cycles();
    for e in emits {
        node.dispatch(EvdevEvent {
            time: now,
            type_: EventType::Key,
            code: e.code,
            value: e.value,
        });
    }
    node.dispatch(EvdevEvent::syn_report(now));
    emits.len()
}

/// Build the evdev capability set for a HID keyboard: declare every
/// `KEY_*` code the HID-usage table can produce so `libevdev` /
/// `libinput` accept the device as a keyboard. Walks the whole
/// Keyboard usage page (0x00..=0xE7) + the modifier range and adds
/// each mapped code.
pub fn build_keyboard_caps() -> narf_input::evdev::DeviceCaps {
    let mut caps = narf_input::evdev::DeviceCaps::new();
    for usage in 0u16..=0xE7 {
        if let Some(code) = hid_usage_to_keycode(usage) {
            caps.add_key(code);
        }
    }
    caps
}

/// Add the consumer (Fn/media) `KEY_*` codes to an existing caps set —
/// called when a device also presents a Consumer Control collection.
pub fn add_consumer_caps(caps: &mut narf_input::evdev::DeviceCaps) {
    // The consumer usages we map are sparse; probe the ones the table
    // knows about. 0x000..=0x2FF covers the volume/transport/brightness
    // cluster plus AC Search.
    for usage in 0u16..=0x2FF {
        if let Some(code) = consumer_usage_to_keycode(usage) {
            caps.add_key(code);
        }
    }
}

/// Log a one-line boot summary describing the keyboard collection we
/// bound, matching the format the touch pump uses. `keys` is the
/// key-array slot count, `has_mods` whether a modifier field was
/// found, `consumer` whether a Fn/media collection is present.
pub fn log_boot_summary(path: &str, keys: u32, has_mods: bool, consumer: bool) {
    let _ = writeln!(
        narf_console::Writer,
        "  keyboard: {} HID keyboard, {} key slots, modifiers={}, consumer={}",
        path,
        keys,
        has_mods,
        consumer,
    );
}

// ── Test-only hooks ───────────────────────────────────────────────

#[doc(hidden)]
pub fn __new_state_for_test() -> KeyboardPumpState {
    KeyboardPumpState::new()
}

#[doc(hidden)]
pub fn __new_consumer_state_for_test() -> ConsumerPumpState {
    ConsumerPumpState::new()
}

/// Build a synthetic boot-style keyboard report: `modifiers` byte
/// followed by up to 6 usage ids (zero-padded). Matches the wire shape
/// of HID §B.1 (no report id). Keeps the smokes readable.
#[doc(hidden)]
pub fn __build_boot_report(modifiers: u8, keys: &[u16]) -> Vec<u8> {
    let mut report = alloc::vec![0u8; 8];
    report[0] = modifiers;
    // report[1] is the reserved byte (0). Six key slots follow.
    for (i, &k) in keys.iter().take(6).enumerate() {
        report[2 + i] = k as u8;
    }
    report
}
