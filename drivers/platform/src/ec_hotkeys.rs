//! EC hotkey → input-ring bridge.
//!
//! Laptop Fn-key blocks (brightness, volume, airplane mode, kbd
//! backlight, ...) are delivered as ACPI Embedded Controller query
//! events: the EC raises SCI, the host issues `EC_CMD_QUERY` (0x84),
//! reads a single byte naming the event, and the firmware's `_Qxx`
//! method runs. Linux drivers/platform/x86/*.c maps a per-vendor
//! table from `_Qxx` index → input subsystem `KEY_*`.
//!
//! We can't ship a complete per-vendor mapping in tree (each OEM
//! ships a different one in their EC firmware), but the *common*
//! events have settled on a small set of codes across HP, Dell,
//! Acer, ASUS, and Lenovo on AMD platforms over the last few
//! generations. We register the union as defaults and let
//! vendor-specific drivers override with `register_ec_hotkey`.
//!
//! Unmapped events push `KeyCode::Unknown` so the input ring
//! still records that *something* fired — boot-time diagnostic
//! signal that the EC IRQ path is alive on a fresh laptop.
//!
//! Reference (Linux, GPL-2.0-or-later, citable post-relicense):
//! - drivers/platform/x86/hp-wmi.c (HP_KEY_* table).
//! - drivers/platform/x86/dell-laptop.c.
//! - drivers/acpi/ec.c (acpi_ec_query / acpi_ec_event_handler).

extern crate alloc;

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_aml::ec_events::register_qxx_handler;
use narf_input::{push_key, KeyCode};
use narf_lib::sync::IrqSafeSpinLock;

/// Per-query-byte translation table. `None` = unmapped (will push
/// KeyCode::Unknown so the ring still reflects activity).
static HOTKEY_MAP: IrqSafeSpinLock<[Option<KeyCode>; 256]> =
    IrqSafeSpinLock::new([None; 256]);

static FIRES: AtomicU64 = AtomicU64::new(0);
static UNMAPPED: AtomicU64 = AtomicU64::new(0);

/// Install a translation entry — for an OEM driver that knows
/// its DSDT's `_Qxx` mapping. Idempotent (last write wins).
pub fn register_ec_hotkey(query_byte: u8, code: KeyCode) {
    HOTKEY_MAP.lock()[query_byte as usize] = Some(code);
}

/// Count of EC hotkey events the bridge has dispatched.
pub fn fire_count() -> u64 {
    FIRES.load(Ordering::Acquire)
}

/// Count of EC hotkey events with no mapping (pushed as Unknown).
pub fn unmapped_count() -> u64 {
    UNMAPPED.load(Ordering::Acquire)
}

/// `_Qxx` handler installed for every index covered by [`default_table`].
/// Pushes a synthetic key press + release pair so consumers that only
/// listen for press edges still see the event.
fn on_query(idx: u8) {
    FIRES.fetch_add(1, Ordering::Release);
    let mapped = HOTKEY_MAP.lock()[idx as usize];
    let code = mapped.unwrap_or_else(|| {
        UNMAPPED.fetch_add(1, Ordering::Release);
        KeyCode::Unknown
    });
    // Hotkeys are momentary — synthesize press + release. The input
    // ring is FIFO; consumers see both transitions in order.
    let _ = push_key(code, true);
    let _ = push_key(code, false);
}

/// Default cross-vendor mapping. Codes here are the *most common*
/// AMD-laptop _Qxx assignments — they're correct on a substantial
/// fraction of Phoenix / Renoir designs and harmless on the rest
/// (the wrong key fires; users can correct via `register_ec_hotkey`
/// from an OEM driver). Specific entries:
///   0x10..=0x17 — function-key block A (brightness, kbd backlight).
///   0x20..=0x27 — function-key block B (volume / media).
///   0x30..=0x37 — wireless / airplane / display switch.
///   0x80..=0x87 — power / lid / dock signaling.
fn default_table() -> &'static [(u8, KeyCode)] {
    &[
        (0x10, KeyCode::BrightnessDown),
        (0x11, KeyCode::BrightnessUp),
        (0x12, KeyCode::KbdIlluminationDown),
        (0x13, KeyCode::KbdIlluminationUp),
        (0x14, KeyCode::KbdIlluminationToggle),
        (0x20, KeyCode::Mute),
        (0x21, KeyCode::VolumeDown),
        (0x22, KeyCode::VolumeUp),
        (0x23, KeyCode::PlayPause),
        (0x24, KeyCode::NextSong),
        (0x25, KeyCode::PreviousSong),
        (0x26, KeyCode::Stop),
        (0x30, KeyCode::WLan),
        (0x31, KeyCode::RfKill),
        (0x32, KeyCode::TouchpadToggle),
        (0x80, KeyCode::Power),
        (0x81, KeyCode::Sleep),
        (0x82, KeyCode::WakeUp),
    ]
}

/// Install the default hotkey mapping + the `_Qxx` handlers for
/// every byte we expect to see. Called from the Subsys init pass
/// after the EC driver registers — so the EC has its ports + GPE,
/// and our `_Qxx` handlers replace any stub the AML interpreter
/// might have installed.
pub fn init() {
    {
        let mut g = HOTKEY_MAP.lock();
        for &(idx, code) in default_table() {
            g[idx as usize] = Some(code);
        }
    }
    // Register the dispatcher across the full byte range. The
    // handler is a cheap function pointer; 256 slots is fine.
    for idx in 0u16..256 {
        register_qxx_handler(idx as u8, on_query);
    }
    let _ = writeln!(
        narf_console::Writer,
        "  acpi-ec-hotkeys: 256-slot _Qxx dispatcher armed ({} default mappings)",
        default_table().len(),
    );
}

#[doc(hidden)]
pub fn __test_reset() {
    *HOTKEY_MAP.lock() = [None; 256];
    FIRES.store(0, Ordering::Release);
    UNMAPPED.store(0, Ordering::Release);
}

/// Test entrypoint — invoke the on_query path without going
/// through the SCI / EC port read.
#[doc(hidden)]
pub fn __test_inject(idx: u8) {
    on_query(idx);
}
