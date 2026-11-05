//! Brightness key handling — ACPI Notify 0x86/0x87 dispatch.
//!
//! Firmware delivers brightness-key presses as ACPI Notify events on
//! the video output device:
//!   - **0x86** — Brightness Increment (Fn+F6 / XF86BrightnessUp).
//!   - **0x87** — Brightness Decrement (Fn+F5 / XF86BrightnessDown).
//!
//! ## Producer: the AML Notify dispatch (#954)
//!
//! The producer is the AML interpreter's `Notify` opcode
//! (`narf_aml::eval`, `NotifyOp 0x86`), which calls
//! `narf_aml::sync::dispatch_notify`. [`register_video_notify`]
//! installs the handler on a video-output device's AML path; it is
//! called by [`crate::acpi_video::init`] for every discovered `_BCL`
//! device, so the handler is registered on exactly the paths
//! firmware notifies. This is the same producer every other Notify
//! consumer in the tree uses (lid/power/sleep buttons in
//! `narf_aml::buttons`, ThinkPad HKEY, Intel HID) — and the only
//! live one: the `acpi.notify` event-bus topic has no production
//! producer (nothing initialises the topic or publishes to it
//! outside tests), so subscribing to it would wire this handler to
//! a dead bus.
//!
//! ## Step policy (explicit)
//!
//! Kernel-steps + input event, mirroring Linux `acpi_video`
//! (`acpi_video_device_notify`):
//!   1. Step the panel owner elected by the subsystem's
//!      single-owner arbitration ([`crate::panel_owner`]) — one
//!      ladder rung for ACPI video, a tenth of the range
//!      otherwise. Deferred candidates are never stepped: the ACPI
//!      `_BCM` path and the native GPU path usually drive the same
//!      panel PWM, so stepping a deferred candidate here would
//!      fight the owner (audit #936 §2).
//!   2. Emit a [`narf_input::KeyCode::BrightnessUp`] /
//!      [`narf_input::KeyCode::BrightnessDown`] key-press +
//!      key-release event pair to the global input ring, so
//!      userspace sees the key even though the hardware change
//!      already happened.
//!
//! The Notify handler is the **sole in-kernel stepper**. The
//! ThinkPad HKEY (0x1004/0x1005) and Intel HID (19/20) decoders emit
//! input events only and never step: firmware may deliver both a
//! video Notify and an HKEY/HID event for a single press, and two
//! steppers would move the panel twice. Userspace may additionally
//! step the published panel via `/sys/class/backlight`; it must not
//! assume one input event per step.
//!
//! Step 2 always fires, even when no panel owner is registered, so
//! userspace sees the key on panel-less machines too. Step 1 is a
//! no-op in that case.
//!
//! ## Limitation
//!
//! Registration is per discovered `_BCL` device path. If a machine
//! has no `_BCL`-bearing video device, no handler is registered and
//! brightness keys reach the panel only via userspace sysfs stepping
//! (the HKEY/HID input events still flow). Likewise, a DSDT that
//! notifies the GPU device itself rather than the `_BCL` output
//! device misses the handler; that DSDT shape is a remainder.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/acpi/acpi_video.c` — `acpi_video_device_notify`, code
//!   0x86 / 0x87 brightness up/down dispatch.
//! - `include/linux/input.h` — `KEY_BRIGHTNESSDOWN` / `KEY_BRIGHTNESSUP`.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;

use narf_aml::sync::register_notify_handler;
use narf_input::{push_key, KeyCode};
use narf_lib::sync::IrqSafeSpinLock;

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
/// 1. Find the panel owner under single-owner arbitration (if any).
/// 2. Step its brightness up or down by one step.
/// 3. Emit a key-press + key-release input event pair.
///
/// Steps 1–2 are no-ops if no backlight candidate is registered;
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
    if let Some(owner) = crate::panel_owner() {
        owner.step_up();
    }
}

fn step_brightness_down() {
    if let Some(owner) = crate::panel_owner() {
        owner.step_down();
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

// ── Notify registration ────────────────────────────────────────────

/// AML paths already registered for brightness Notify dispatch.
/// Guards the re-entrant-init hazard: `sync::register_notify_handler`
/// appends, so registering the same path twice would step the panel
/// twice per key press (cf. `narf_aml::buttons::INIT_DONE`).
static REGISTERED_PATHS: IrqSafeSpinLock<Vec<String>> = IrqSafeSpinLock::new(Vec::new());

/// Register the brightness-key Notify handler on one AML
/// video-output device path (e.g. `\_SB.PCI0.GFX0.DD1F`).
///
/// Called by [`crate::acpi_video::init`] for every discovered `_BCL`
/// device: the path is known there, so no initcall-ordering
/// assumption is needed. Idempotent per path — a second registration
/// for the same path is a no-op, so a re-run of the discovery init
/// cannot double-step the panel.
///
/// The registered handler forwards the Notify value to
/// [`handle_notify`].
pub fn register_video_notify(device_path: &str) {
    {
        let mut g = REGISTERED_PATHS.lock();
        if g.iter().any(|p| p.as_str() == device_path) {
            return;
        }
        g.push(String::from(device_path));
    }
    register_notify_handler(device_path, video_notify_handler);
}

/// `NotifyHandler` adapter for `narf_aml::sync::dispatch_notify`:
/// forwards the Notify value to [`handle_notify`]. Notify values are
/// bytes per ACPI 6.5 §B.7, so the AML integer is truncated;
/// `handle_notify` ignores anything but 0x86/0x87.
fn video_notify_handler(_target: &str, value: u64) {
    let _ = handle_notify(value as u8);
}

/// Test helper: forget registered paths (the AML handler table itself
/// is reset via `narf_aml::sync::__reset_for_test`).
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTERED_PATHS.lock().clear();
}

// ── initcall ──────────────────────────────────────────────────────

/// Register the brightness-key handler. The handler itself is
/// registered per video device by [`register_video_notify`], called
/// from `acpi_video::init()` for every discovered `_BCL` device.
/// This initcall only marks the subsystem active in the composed
/// boot.
pub fn init() {
    let _ = writeln!(
        narf_console::Writer,
        "  brightness-keys: 0x86/0x87 handler active"
    );
}
