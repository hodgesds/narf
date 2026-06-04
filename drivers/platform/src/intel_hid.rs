//! Intel HID Event Filter (`INT33D5`) driver.
//!
//! This driver claims the `INT33D5` and `INT3400` ACPI devices found on
//! most modern Intel laptops. It handles the "HID Event Filter" surface
//! which delivers hotkey events (Volume, Mute, Brightness, etc.) as
//! ACPI Notify codes.
//!
//! # References (GPL-2.0-or-later)
//! - Linux `drivers/platform/x86/intel-hid.c` — `intel_hid_notify`.
//! - Intel "HID Event Filter" specification.
//!
//! # Keycodes
//! - 0xCC: Volume Up
//! - 0xCD: Volume Down
//! - 0xCE: Mute
//! - 0x64: Brightness Up
//! - 0x65: Brightness Down
//! - 0xD0: Wireless Toggle

use core::fmt::Write as _;

use narf_aml::find_all_devices_by_hid;
use narf_aml::sync::register_notify_handler;
use narf_input::{push_global, InputEvent, KeyCode, KeyEvent, Modifiers};

const INTEL_HID_HID: &str = "INT33D5";

// ── Intel HID codes ───────────────────────────────────────────────

const NOTIFY_BRIGHTNESS_UP: u64 = 0x64;
const NOTIFY_BRIGHTNESS_DOWN: u64 = 0x65;
const NOTIFY_VOLUME_UP: u64 = 0xCC;
const NOTIFY_VOLUME_DOWN: u64 = 0xCD;
const NOTIFY_VOLUME_MUTE: u64 = 0xCE;
const NOTIFY_WIRELESS_TOGGLE: u64 = 0xD0;

/// Initialize the Intel HID Event Filter driver.
pub fn init() {
    let mut found = 0;
    for node in find_all_devices_by_hid(INTEL_HID_HID) {
        if bind_one(&node.path) {
            found += 1;
        }
    }
    if found > 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  intel-hid: registered {} filter(s)",
            found
        );
    }
}

fn bind_one(path: &str) -> bool {
    register_notify_handler(path, intel_hid_notify);
    true
}

fn intel_hid_notify(path: &str, value: u64) {
    let key = match value {
        NOTIFY_VOLUME_UP => Some(KeyCode::VolumeUp),
        NOTIFY_VOLUME_DOWN => Some(KeyCode::VolumeDown),
        NOTIFY_VOLUME_MUTE => Some(KeyCode::Mute),
        NOTIFY_BRIGHTNESS_UP => Some(KeyCode::BrightnessUp),
        NOTIFY_BRIGHTNESS_DOWN => Some(KeyCode::BrightnessDown),
        NOTIFY_WIRELESS_TOGGLE => Some(KeyCode::WLan),
        _ => {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-hid: {}: unknown notify code {:#x}",
                path,
                value
            );
            None
        }
    };

    if let Some(k) = key {
        // HID events are typically single-pulse (Press).
        // Emit Press followed immediately by Release to simulate a click.
        let _ = push_global(InputEvent::Key(KeyEvent {
            code: k,
            pressed: true,
            modifiers: Modifiers::EMPTY,
        }));
        let _ = push_global(InputEvent::Key(KeyEvent {
            code: k,
            pressed: false,
            modifiers: Modifiers::EMPTY,
        }));
    }
}
