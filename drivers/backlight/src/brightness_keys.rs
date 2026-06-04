//! Brightness key handling — ACPI Notify 0x86/0x87 dispatch.
//!
//! Firmware delivers brightness-key presses as ACPI Notify events on
//! the video output device:
//!   - **0x86** — Brightness Increment (Fn+F6 / XF86BrightnessUp).
//!   - **0x87** — Brightness Decrement (Fn+F5 / XF86BrightnessDown).
//!
//! This module subscribes to these notify codes and, on each event:
//!   1. Looks up the first [`crate::acpi_video::AcpiVideoDevice`] in
//!      the ACPI video registry.
//!   2. Calls `step_up` / `step_down` on that device to adjust the
//!      panel brightness by one ladder step.
//!   3. Emits an [`narf_input::KeyCode::BrightnessUp`] /
//!      [`narf_input::KeyCode::BrightnessDown`] key-press + key-release
//!      event pair to the global input ring so userspace can handle it.
//!
//! ## Why both hardware and input events?
//!
//! Some desktop environments handle brightness in userspace via the
//! input ring (GNOME, KDE, sway). Others read `/sys/class/backlight`
//! directly. We do both: the hardware brightness change happens
//! immediately (frame N is already at the new level), and the input
//! event lets userspace know the user's intent in case it wants to
//! apply policy (minimum floor, ambient-light compensation, …).
//!
//! ## Notify registration
//!
//! The AML namespace handler for video-output Notify events calls
//! [`handle_notify`] directly. In a future wave this will be wired
//! through the ACPI event bus (`acpi.notify` topic); for now it is a
//! direct function call from the ACPI Notify dispatcher in
//! `drivers/platform/src/backlight.rs` / `bus/src/acpi_notify.rs`.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/acpi/acpi_video.c` — `acpi_video_device_notify`, code
//!   0x86 / 0x87 brightness up/down dispatch.
//! - `include/linux/input.h` — `KEY_BRIGHTNESSDOWN` / `KEY_BRIGHTNESSUP`.

use core::fmt::Write as FmtWrite;

use narf_input::{push_key, KeyCode};

use crate::BacklightDevice;

// ── Notify code constants ──────────────────────────────────────────

/// ACPI Notify value: Brightness Increment (Fn+F6 / XF86BrightnessUp).
/// Reference: ACPI 6.5 §B.7 Video Device Notifications, table B-6.
pub const NOTIFY_BRIGHTNESS_UP: u8 = 0x86;

/// ACPI Notify value: Brightness Decrement (Fn+F5 / XF86BrightnessDown).
/// Reference: ACPI 6.5 §B.7.
pub const NOTIFY_BRIGHTNESS_DOWN: u8 = 0x87;

// ── Public handler ─────────────────────────────────────────────────

/// Handle an ACPI Notify event delivered to a video output device.
///
/// `code` is the raw byte from the ACPI Notify instruction. Only
/// 0x86 and 0x87 are handled; all other codes are silently ignored.
///
/// Returns `true` if the event was consumed (0x86/0x87); `false`
/// otherwise.
///
/// ## Behaviour
///
/// 1. Find the first ACPI video backlight device (if any).
/// 2. Step its brightness up or down by one ladder step.
/// 3. Emit a key-press + key-release input event pair.
///
/// Steps 1–2 are no-ops if no ACPI video device is registered;
/// step 3 always fires so userspace sees the key regardless of
/// whether hardware backlight is under kernel control.
pub fn handle_notify(code: u8) -> bool {
    match code {
        NOTIFY_BRIGHTNESS_UP => {
            step_brightness_up();
            emit_key(KeyCode::BrightnessUp);
            true
        }
        NOTIFY_BRIGHTNESS_DOWN => {
            step_brightness_down();
            emit_key(KeyCode::BrightnessDown);
            true
        }
        _ => false,
    }
}

// ── Private helpers ────────────────────────────────────────────────

fn step_brightness_up() {
    let devs = crate::acpi_video::acpi_video_devices();
    if let Some(dev) = devs.first() {
        dev.step_up();
    } else {
        // Fall back to amdgpu backlight if present.
        if let Some(amd) = crate::amdgpu_bl::amdgpu_bl_device() {
            let cur = amd.current_brightness();
            let max = amd.max_brightness();
            // Step by ~10% of max_brightness.
            let step = (max / 10).max(1);
            amd.set_brightness(cur.saturating_add(step).min(max));
        }
    }
}

fn step_brightness_down() {
    let devs = crate::acpi_video::acpi_video_devices();
    if let Some(dev) = devs.first() {
        dev.step_down();
    } else if let Some(amd) = crate::amdgpu_bl::amdgpu_bl_device() {
        let cur = amd.current_brightness();
        let max = amd.max_brightness();
        let step = (max / 10).max(1);
        amd.set_brightness(cur.saturating_sub(step));
    }
}

/// Emit a key-press + key-release pair into the global input ring.
///
/// We fire both press and release in the same dispatch call because
/// brightness keys are momentary (no repeat, no held state): the
/// system makes one step per key event.
fn emit_key(code: KeyCode) {
    push_key(code, true);
    push_key(code, false);
}

// ── initcall ──────────────────────────────────────────────────────

/// Register the brightness-key handler. Currently a no-op because
/// the handler is called directly by the ACPI Notify dispatcher via
/// [`handle_notify`]; future waves will subscribe to the `acpi.notify`
/// event-bus topic here.
pub fn init() {
    // Nothing to register at this stage; handle_notify() is called
    // directly by the ACPI Notify dispatcher.
    let _ = writeln!(
        narf_console::Writer,
        "  brightness-keys: 0x86/0x87 handler active"
    );
}
