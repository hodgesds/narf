// SPDX-License-Identifier: GPL-2.0-or-later
//! Acer WMI platform driver.
//!
//! Covers Acer notebooks using the WMI interface.
//!
//! ## Features
//!
//! - WMI GUIDs for Acer (AMW0, WMID)
//! - Hotkey decode (Acer-specific codes → KEY_*)
//!
//! ## Linux references (GPL-2.0-or-later)
//!
//! - `drivers/platform/x86/acer-wmi.c`

extern crate alloc;

use core::sync::atomic::{AtomicU32, Ordering};
use narf_input::{push_key, KeyCode};

// ── Acer WMI GUIDs ─────────────────────────────────────────────────────

pub const ACER_AMW0_GUID1: &str = "67C3371D-95A3-4C37-BB61-DD47B491DAAB";
pub const ACER_AMW0_GUID2: &str = "431F16ED-0C2B-444C-B267-27DEB140CF9C";
pub const ACER_WMID_GUID1: &str = "6AF4F258-B401-42FD-BE91-3D4AC2D7C0D3";
pub const ACER_WMID_GUID2: &str = "95764E09-FB56-4E83-B31A-37761F60994A";
pub const ACER_WMID_EVENT_GUID: &str = "676AA15E-6A47-4D9F-A2CC-1E6D18D14026";

// ── Acer hotkey decoder ───────────────────────────────────────────────

/// Decode an Acer WMI hotkey event value to a `KeyCode`.
///
/// Reference: `acer-wmi.c::acer_wmi_keymap[]` sparse keymap.
pub fn acer_keycode(code: u32) -> Option<KeyCode> {
    match code {
        0x01 | 0x03 | 0x04 => Some(KeyCode::WLan), // WiFi
        0x12 => Some(KeyCode::Unknown),            // BT
        0x21 => Some(KeyCode::Unknown),            // Backup
        0x22 => Some(KeyCode::Unknown),            // Arcade
        0x23 | 0x29 => Some(KeyCode::Unknown),     // P_Key
        0x24 => Some(KeyCode::Unknown),            // Social networking
        0x27 => Some(KeyCode::Unknown),
        0x41 => Some(KeyCode::Mute),
        0x42 | 0x4d => Some(KeyCode::PreviousSong),
        0x43 | 0x4e => Some(KeyCode::NextSong),
        0x44 | 0x4f => Some(KeyCode::PlayPause),
        0x45 | 0x50 => Some(KeyCode::Stop),
        0x48 => Some(KeyCode::VolumeUp),
        0x49 | 0x4a => Some(KeyCode::VolumeDown),
        0x61 => Some(KeyCode::Unknown),
        0x62 => Some(KeyCode::BrightnessUp),
        0x63 => Some(KeyCode::BrightnessDown),
        0x64 => Some(KeyCode::Unknown), // Display Switch
        0x81 => Some(KeyCode::Sleep),
        0x82 | 0x83 | 0x85 => Some(KeyCode::TouchpadToggle), // Touch Pad Toggle
        0x84 => Some(KeyCode::KbdIlluminationToggle),
        0x86 => Some(KeyCode::WLan),
        0x87 => Some(KeyCode::Power),
        _ => None,
    }
}

// ── Statistics ────────────────────────────────────────────────────────

static EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of Acer WMI events processed.
pub fn event_count() -> u32 {
    EVENT_COUNT.load(Ordering::Relaxed)
}

// ── WMI event handler ─────────────────────────────────────────────────

fn on_acer_event(ev: &narf_aml::wmi::WmiEvent) {
    EVENT_COUNT.fetch_add(1, Ordering::Relaxed);

    // Acer events usually carry a u32 key code via the event data.
    // The event payload is 1 byte, 4 bytes, or struct event_return_value.
    // We try to extract the first u32.
    let code: u32 = match ev.data.as_ref() {
        Some(narf_aml::Value::Integer(n)) => *n as u32,
        Some(narf_aml::Value::Buffer(b)) => {
            if b.len() >= 4 {
                // For WMID_HOTKEY_EVENT, it might be in the first field of event_return_value
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else if b.len() == 1 || b.len() == 2 {
                b[0] as u32
            } else {
                return;
            }
        }
        _ => return,
    };

    // The keycode may be embedded in the return struct differently, but for simplicity
    // we use the directly decoded integer or first byte if it's small.
    // In actual acer_wmi, the WMID_HOTKEY_EVENT structure has:
    // u8 function; u8 key_num; u16 device_state; ...
    // So key_num is at offset 1.
    let actual_code = match ev.data.as_ref() {
        Some(narf_aml::Value::Buffer(b)) if b.len() >= 2 => b[1] as u32,
        _ => code,
    };

    if let Some(kc) = acer_keycode(actual_code) {
        let _ = push_key(kc, true);
        let _ = push_key(kc, false);
    }
}

// ── Init ──────────────────────────────────────────────────────────────

/// Initialise the Acer WMI platform driver.
pub fn init() {
    let guids = narf_aml::wmi::list_guids();
    let has_wmid = guids.iter().any(|g| {
        if let Some(gb) = crate::wmi_vendors::guid_str_to_bytes(ACER_WMID_GUID1) {
            g.guid == gb
        } else {
            false
        }
    });
    let has_amw0 = guids.iter().any(|g| {
        if let Some(gb) = crate::wmi_vendors::guid_str_to_bytes(ACER_AMW0_GUID1) {
            g.guid == gb
        } else {
            false
        }
    });

    if has_wmid || has_amw0 {
        if let Some(egb) = crate::wmi_vendors::guid_str_to_bytes(ACER_WMID_EVENT_GUID) {
            for g in &guids {
                if g.guid == egb {
                    narf_aml::wmi::subscribe_event(g, on_acer_event);
                }
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "  acer-wmi: registered event handler for Acer hotkeys"
            );
        }
    }
}
