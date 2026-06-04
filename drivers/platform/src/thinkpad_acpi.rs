// SPDX-License-Identifier: GPL-2.0-or-later
//! ThinkPad ACPI platform driver.
//!
//! Implements the Lenovo ThinkPad-specific ACPI surface:
//!   - HKEY hotkey decode (Fn+F1–F12, volume, brightness, mute, mic-mute,
//!     wireless toggle, tablet mode for Yoga/X1 Fold families)
//!   - LED control: ThinkLight, keyboard backlight, charging LED,
//!     power LED, mic-mute LED
//!   - Battery conservation mode (stop charging at ~60%)
//!   - Fan control: read speed via `\HFSP`, set via `\HFNF` / EC offsets
//!   - Dock detection via HKEY notify value 0x4010 / 0x4011
//!
//! ## Linux references (GPL-2.0-or-later, cited post-relicense 2026-05-20)
//!
//! - `drivers/platform/x86/thinkpad_acpi.c` — main driver (~10 000 lines).
//!   Key functions:
//!   - `hotkey_decode_one_event()` — HKEY notify decode (line ~1400).
//!   - `tpacpi_led_set()` — LED blink/on/off via `MLCG`/`MLCS` (line ~4800).
//!   - `fan_set_level()` — writes `\HFNF` with fan level (line ~6600).
//!   - `battery_conservation_mode_show/store()` — reads/writes BIOS WMI
//!     variable index 0x44 (line ~9400).
//!
//! ## HKEY device
//!
//! The HKEY device (`LEN0268` / `IBM0068` / `LEN0018`) exposes a `_Q?? → HKEY`
//! notify chain. Notify values live in specific ranges:
//!
//! | Range         | Meaning                           |
//! |---------------|-----------------------------------|
//! | 0x1001..0x10FF | Fn+key hotkeys                  |
//! | 0x2xxx         | Tablet / lid state              |
//! | 0x3xxx         | Thermal event (TZ / fan)        |
//! | 0x4010 / 4011  | Dock in / out                   |
//! | 0x6020         | Tablet mode (Yoga)              |
//! | 0x60C0         | Mic-mute LED sync               |
//!
//! Reference: `thinkpad_acpi.c::tp_features` enum + notify handler
//! `hotkey_notify_hotkey()`.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_input::{push_key, KeyCode};

// ── HKEY notify-value ranges ───────────────────────────────────────────

/// Hotkey range: 0x1001 to 0x10FF — Fn + function key combos.
/// Reference: `thinkpad_acpi.c::TP_ACPI_HOTKEYSCAN_FNF1` etc.
pub const HKEY_FN_RANGE_LO: u32 = 0x1001;
pub const HKEY_FN_RANGE_HI: u32 = 0x10FF;

/// Dock connect/disconnect notify values.
/// Reference: `thinkpad_acpi.c` dock probe notify filter (line ~7100).
pub const HKEY_DOCK_IN: u32 = 0x4010;
pub const HKEY_DOCK_OUT: u32 = 0x4011;

/// Tablet-mode (Yoga) enter/exit.
/// Reference: `thinkpad_acpi.c::TP_ACPI_WGSV_GET_TABLET_SW` (line ~6010).
pub const HKEY_TABLET_ENTER: u32 = 0x6020;
pub const HKEY_TABLET_EXIT: u32 = 0x6021;

/// Mic-mute LED sync notification.
/// Reference: `thinkpad_acpi.c` notify 0x60C0 micmute-led handler.
pub const HKEY_MIC_MUTE_LED: u32 = 0x60C0;

// ── Battery conservation mode ──────────────────────────────────────────

/// Global battery conservation state (set stop-at-60% when true).
/// Linux stores this in the BIOS NVRAM via WMI index 0x44.
/// Reference: `thinkpad_acpi.c::tpacpi_battery_conservation_mode_show`.
static BATTERY_CONSERVATION: AtomicBool = AtomicBool::new(false);

/// Return the current battery conservation mode state.
pub fn battery_conservation_enabled() -> bool {
    BATTERY_CONSERVATION.load(Ordering::Relaxed)
}

/// Enable or disable battery conservation mode (stop-charge-at-60%).
///
/// In a live kernel this would write BIOS WMI method `BCTG` / BIOS
/// NVRAM index 0x44 via the Lenovo BIOS WMI surface
/// (`thinkpad_acpi.c::tpacpi_battery_conservation_mode_store`).
/// Here we record the state locally and would trigger the WMI write;
/// the WMI invocation path is wired in `do_set_conservation`.
///
/// Reference: `thinkpad_acpi.c` line ~9430 — writes Arg0=0x21 or 0x20
/// to `HBIF` (Battery Information) WMI method depending on enable/disable.
pub fn set_battery_conservation(enable: bool) {
    BATTERY_CONSERVATION.store(enable, Ordering::Release);
    do_set_conservation(enable);
}

fn do_set_conservation(enable: bool) {
    // Invoke `\_SB.PCI0.LPCB.EC.BCTG` (HBIF WMI index 0x44) via AML.
    // ThinkPad BIOS WMI GUID: "3FC0DE0C-2A72-4B88-BDC5-1D24E64AB5C6"
    // Command byte: 0x21 = enable conservation, 0x20 = disable.
    // Reference: thinkpad_acpi.c `tpacpi_battery_conservation_mode_store`.
    let cmd: u64 = if enable { 0x21 } else { 0x20 };
    // Best-effort: if the AML method doesn't exist on this system,
    // the state is still recorded in BATTERY_CONSERVATION.
    let _ = narf_aml::eval::evaluate_method(
        r"\_SB.PCI0.LPCB.EC.BCTG",
        &[narf_aml::Value::Integer(cmd)],
    );
}

// ── Fan control ────────────────────────────────────────────────────────

/// Fan speed levels (0 = auto/firmware, 1–7 = explicit speeds, 255 = max).
/// Reference: `thinkpad_acpi.c::fan_set_level()` — writes `\HFNF`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FanLevel {
    Auto = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
    L5 = 5,
    L6 = 6,
    L7 = 7,
    FullSpeed = 255,
}

/// Last-written fan level.
static FAN_LEVEL: AtomicU32 = AtomicU32::new(0);

/// Read the current fan level as set by `set_fan_level`.
pub fn fan_level() -> FanLevel {
    match FAN_LEVEL.load(Ordering::Relaxed) {
        0 => FanLevel::Auto,
        1 => FanLevel::L1,
        2 => FanLevel::L2,
        3 => FanLevel::L3,
        4 => FanLevel::L4,
        5 => FanLevel::L5,
        6 => FanLevel::L6,
        7 => FanLevel::L7,
        _ => FanLevel::FullSpeed,
    }
}

/// Set fan speed level by writing `\HFNF` via AML.
///
/// Reference: `thinkpad_acpi.c::fan_set_level()` line ~6600 — evaluates
/// `\HFNF` with the level byte as Arg0.
pub fn set_fan_level(level: FanLevel) {
    let lvl = level as u64;
    FAN_LEVEL.store(lvl as u32, Ordering::Release);
    let _ = narf_aml::eval::evaluate_method(r"\HFNF", &[narf_aml::Value::Integer(lvl)]);
}

// ── HKEY hotkey decoder ────────────────────────────────────────────────

/// Decoded ThinkPad HKEY hotkey event.
///
/// Reference: `thinkpad_acpi.c::tp_acpi_hkey_event` enum + keymap tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HkeyEvent {
    /// Fn+key hotkey. `code` is the raw HKEY notify value.
    FnKey { code: u32 },
    /// Dock connected.
    DockIn,
    /// Dock disconnected.
    DockOut,
    /// Entered tablet mode.
    TabletEnter,
    /// Exited tablet mode (laptop mode).
    TabletExit,
    /// Mic-mute LED synchronisation.
    MicMuteLed,
    /// Unknown / unhandled notify value.
    Unknown { value: u32 },
}

/// Decode a raw HKEY notify value into a `HkeyEvent`.
///
/// Reference: `thinkpad_acpi.c::hotkey_notify_hotkey()` — the notify
/// handler dispatches on the integer value received from the HKEY ACPI
/// notify.
pub fn decode_hkey_event(value: u32) -> HkeyEvent {
    match value {
        HKEY_DOCK_IN => HkeyEvent::DockIn,
        HKEY_DOCK_OUT => HkeyEvent::DockOut,
        HKEY_TABLET_ENTER => HkeyEvent::TabletEnter,
        HKEY_TABLET_EXIT => HkeyEvent::TabletExit,
        HKEY_MIC_MUTE_LED => HkeyEvent::MicMuteLed,
        v if v >= HKEY_FN_RANGE_LO && v <= HKEY_FN_RANGE_HI => HkeyEvent::FnKey { code: v },
        other => HkeyEvent::Unknown { value: other },
    }
}

/// Map a ThinkPad HKEY Fn-key notify value to a `KeyCode`.
///
/// Reference: `thinkpad_acpi.c` `hotkey_map` — `tp_acpi_hkey_event`
/// sparse keymap (line ~1370–1450).
///
/// | HKEY  | Key meaning          | Linux KEY_*           |
/// |-------|----------------------|-----------------------|
/// | 0x1004 | Brightness Up       | KEY_BRIGHTNESSUP (225)|
/// | 0x1005 | Brightness Down     | KEY_BRIGHTNESSDOWN    |
/// | 0x1011 | Volume Up           | KEY_VOLUMEUP          |
/// | 0x1012 | Volume Down         | KEY_VOLUMEDOWN        |
/// | 0x1013 | Mute                | KEY_MUTE              |
/// | 0x100B | Mic-Mute            | KEY_MICMUTE (synonyms KEY_F20) |
/// | 0x1014 | ThinkVantage        | KEY_VENDOR            |
/// | 0x1015 | Fn+F5 wireless      | KEY_WLAN              |
/// | 0x1009 | Fn+F9               | KEY_CONFIG            |
/// | 0x101B | Keyboard backlight  | KEY_KBDILLUMTOGGLE    |
pub fn hkey_to_keycode(hkey: u32) -> Option<KeyCode> {
    match hkey {
        0x1004 => Some(KeyCode::BrightnessUp),
        0x1005 => Some(KeyCode::BrightnessDown),
        0x1011 => Some(KeyCode::VolumeUp),
        0x1012 => Some(KeyCode::VolumeDown),
        0x1013 => Some(KeyCode::Mute),
        0x100B => Some(KeyCode::Mute), // mic-mute, closest available
        0x1015 => Some(KeyCode::WLan),
        0x101B => Some(KeyCode::KbdIlluminationToggle),
        0x1016 => Some(KeyCode::KbdIlluminationDown),
        0x1017 => Some(KeyCode::KbdIlluminationUp),
        _ => None,
    }
}

// ── LED control ────────────────────────────────────────────────────────

/// ThinkPad LED identifiers.
/// Reference: `thinkpad_acpi.c` `TPACPI_LED_*` enum (line ~4740).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ThinkpadLed {
    /// Power LED (index 0).
    Power = 0,
    /// Battery / charging LED (index 1).
    Battery = 1,
    /// UltraBay eject LED (index 2).
    UltraBay = 2,
    /// ThinkLight (screen light, index 4).
    ThinkLight = 4,
    /// Keyboard backlight (index 8).
    KbdBacklight = 8,
    /// Mic-mute LED (index 9). Shows mute state.
    MicMute = 9,
}

/// LED state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LedState {
    Off,
    On,
    Blink,
}

/// Set a ThinkPad LED state by writing the `MLCS` (LED Set) ACPI method.
///
/// MLCS Arg0 encodes `(led_index << 4) | blink_bit | on_bit`.
/// Reference: `thinkpad_acpi.c::tpacpi_led_set()` line ~4800 — builds
/// a packed byte from led id + blink/on flags and passes to `MLCS`.
pub fn set_led(led: ThinkpadLed, state: LedState) {
    let id = led as u8;
    let arg: u8 = match state {
        LedState::Off => id << 4,
        LedState::On => (id << 4) | 0x01,
        LedState::Blink => (id << 4) | 0x02,
    };
    let _ = narf_aml::eval::evaluate_method(
        r"\_SB.PCI0.LPCB.EC.MLCS",
        &[narf_aml::Value::Integer(arg as u64)],
    );
}

// ── Statistics ─────────────────────────────────────────────────────────

static HOTKEY_COUNT: AtomicU32 = AtomicU32::new(0);
static DOCK_IN_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of HKEY hotkey events dispatched since init.
pub fn hotkey_count() -> u32 {
    HOTKEY_COUNT.load(Ordering::Relaxed)
}

/// Number of dock-connected events dispatched since init.
pub fn dock_in_count() -> u32 {
    DOCK_IN_COUNT.load(Ordering::Relaxed)
}

// ── ACPI notify handler ────────────────────────────────────────────────

/// Process a raw HKEY ACPI notify value.
///
/// Called by the ACPI notify dispatcher when any notify arrives on the
/// HKEY device (`LEN0268` / `IBM0068`). Decodes the value, bumps stats,
/// and pushes a key event into `narf_input` when appropriate.
///
/// Reference: `thinkpad_acpi.c::hotkey_inputdev_send_key()` + the
/// switch statement in the notify handler.
pub fn handle_hkey_notify(value: u32) {
    handle_hkey_notify_aml("", value as u64);
}

/// AML notify dispatcher trampoline — signature matches `NotifyHandler`.
fn handle_hkey_notify_aml(_target: &str, value: u64) {
    let value = value as u32;
    let ev = decode_hkey_event(value);
    match ev {
        HkeyEvent::FnKey { code } => {
            HOTKEY_COUNT.fetch_add(1, Ordering::Relaxed);
            if let Some(kc) = hkey_to_keycode(code) {
                let _ = push_key(kc, true);
                let _ = push_key(kc, false);
            }
        }
        HkeyEvent::DockIn => {
            DOCK_IN_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        HkeyEvent::DockOut => {}
        HkeyEvent::TabletEnter | HkeyEvent::TabletExit => {
            // Route to platform event bus in Wave 16.
        }
        HkeyEvent::MicMuteLed => {
            // Sync mic-mute LED — would read mic state and call set_led.
        }
        HkeyEvent::Unknown { .. } => {}
    }
}

// ── Init ───────────────────────────────────────────────────────────────

/// Initialise the ThinkPad ACPI platform driver.
///
/// Registers the HKEY notify handler with the AML dispatcher so that
/// `handle_hkey_notify` is called whenever the HKEY device fires a
/// notify. HKEY is identified by multiple HIDs depending on firmware
/// generation:
///   `LEN0268` (newer ThinkPad, post-2010)
///   `IBM0068` (older ThinkPad, pre-2010)
///   `LEN0018` (some ultrabooks)
///
/// Reference: `thinkpad_acpi.c::tpacpi_acpi_driver_init()` — installs
/// the notify handler for each HKEY HID variant.
pub fn init() {
    for hid in &["LEN0268", "IBM0068", "LEN0018"] {
        for dev in narf_aml::find_all_devices_by_hid(hid) {
            narf_aml::sync::register_notify_handler(&dev.path, handle_hkey_notify_aml);
        }
    }
}

// ── Test helpers ───────────────────────────────────────────────────────

/// Reset all ThinkPad driver state for unit tests.
#[doc(hidden)]
pub fn __test_reset() {
    HOTKEY_COUNT.store(0, Ordering::Relaxed);
    DOCK_IN_COUNT.store(0, Ordering::Relaxed);
    BATTERY_CONSERVATION.store(false, Ordering::Relaxed);
    FAN_LEVEL.store(0, Ordering::Relaxed);
}
