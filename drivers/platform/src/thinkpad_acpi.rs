// SPDX-License-Identifier: GPL-2.0-or-later
//! ThinkPad ACPI platform driver.
//!
//! Implements the Lenovo ThinkPad-specific ACPI surface:
//!   - HKEY hotkey decode (Fn+F1–F12, volume, brightness, mute, mic-mute,
//!     wireless toggle, tablet mode for Yoga/X1 Fold families)
//!   - LED control: keyboard backlight, mute/micmute LEDs, and the
//!     Linux-safe generic LEDs (power, standby, lid-logo dot,
//!     ThinkVantage) — three separate mechanisms, never one setter
//!     (see the LED section below)
//!   - Battery conservation mode (stop charging at ~60%)
//!   - Fan control: read speed via `\HFSP`, set via `\HFNF` / EC offsets
//!   - Dock detection via HKEY notify value 0x4010 / 0x4011
//!
//! ## Linux references (GPL-2.0-or-later, cited post-relicense 2026-05-20)
//!
//! - `drivers/platform/x86/thinkpad_acpi.c` — main driver (~10 000 lines).
//!   Key functions:
//!   - `hotkey_decode_one_event()` — HKEY notify decode (line ~1400).
//!   - `led_set_status()` — generic LEDs via the EC `LED` object,
//!     NEW mode (Linux 7.4-rc2 `thinkpad_acpi.c:5646`).
//!   - `kbdlight_set_level()` — keyboard-backlight level via HKEY
//!     `MLCS` / `MLCG` (`thinkpad_acpi.c:5108`).
//!   - `tpacpi_led_set()` — mute/micmute LEDs ONLY, via HKEY `SSMS` /
//!     `MMTS` (`thinkpad_acpi.c:9409`); it is not a generic LED
//!     setter and builds no packed byte.
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
        v if (HKEY_FN_RANGE_LO..=HKEY_FN_RANGE_HI).contains(&v) => HkeyEvent::FnKey { code: v },
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
        0x100B => Some(KeyCode::MicMute), // KEY_MICMUTE — distinct
        // from speaker mute (was conflated with KeyCode::Mute).
        0x1015 => Some(KeyCode::WLan),
        0x101B => Some(KeyCode::KbdIlluminationToggle),
        0x1016 => Some(KeyCode::KbdIlluminationDown),
        0x1017 => Some(KeyCode::KbdIlluminationUp),
        _ => None,
    }
}

// ── LED control ────────────────────────────────────────────────────────
//
// Linux drives ThinkPad LEDs through THREE distinct mechanisms
// (mechanism record `~/workspace/queue/thinkpad-led-mechanism-2026-11-23.md`,
// Linux 7.4-rc2 `thinkpad_acpi.c`). There is no single "LED setter":
//   - generic LEDs: the `LED` method under the EC handle, NEW mode
//     (`led_set_status`, :5646) — 2 args: index 0-15, 0x00/0x80/0xC0;
//   - keyboard backlight: HKEY `MLCS` set / `MLCG` get, the argument
//     is the LEVEL (`kbdlight_set_level`, :5108). `MLCS` is called
//     from exactly one place in all of Linux — nowhere else;
//   - mute/micmute: HKEY `SSMS`/`MMTS`, one int arg each
//     (`tpacpi_led_set`, :9409, mute-only dispatcher).
// The old `set_led()` wrote a packed byte `(id << 4) | flags` to
// `MLCS` for every LED — a scheme with no Linux counterpart at all
// (`set_led(Power, On)` would have set kbdlight level 1). It is
// deleted here, not repaired.
//
// DSDT-UNVERIFIED PATHS. Linux resolves `MLCS`/`MLCG`/`SSMS`/`MMTS`
// relative to the HKEY device handle and the `LED` object relative
// to the EC handle; NARF's `evaluate_method` is path-based only,
// so the absolute paths are spelled out below. NEITHER has been
// verified against the P14s DSDT yet: the HKEY device may sit
// elsewhere than under the EC, and the EC path itself varies by
// machine (`LPCB` vs `LPC`, `EC` vs `EC0`). Do not submit a PR with
// these literals until the DSDT confirms them (tracker #2448,
// mechanism record §5).

/// HKEY device path — DSDT-UNVERIFIED (see above).
pub const HKEY_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY";

/// EC device path — DSDT-UNVERIFIED (see above).
pub const EC_PATH: &str = r"\_SB.PCI0.LPCB.EC";

/// HKEY `MLCS` (kbdlight set) — DSDT-UNVERIFIED.
pub const HKEY_MLCS_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.MLCS";

/// HKEY `MLCG` (kbdlight get / support probe) — DSDT-UNVERIFIED.
pub const HKEY_MLCG_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.MLCG";

/// HKEY `SSMS` (speaker-mute LED) — DSDT-UNVERIFIED.
pub const HKEY_SSMS_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.SSMS";

/// HKEY `MMTS` (mic-mute LED) — DSDT-UNVERIFIED.
pub const HKEY_MMTS_PATH: &str = r"\_SB.PCI0.LPCB.EC.HKEY.MMTS";

/// EC `LED` object (generic LEDs) — DSDT-UNVERIFIED.
pub const EC_LED_PATH: &str = r"\_SB.PCI0.LPCB.EC.LED";

/// Linux `TPACPI_SAFE_LEDS` (`thinkpad_acpi.c:5611`, 0x1481) —
/// bits {0, 7, 10, 12}. Every other generic-LED index is
/// restricted by default and needs the unsafe-LEDs policy decision
/// (audit Q6) before it is exposed.
const SAFE_GENERIC_LEDS: u16 = 0x1481;

/// Keyboard-backlight classdev max (`tpacpi_led_kbdlight`,
/// `thinkpad_acpi.c:5200`): levels 0-2. Whether the P14s 8840
/// uses 0-1 or 0-2 is DSDT-dependent (mechanism record §5.7).
pub const KBDLIGHT_MAX_LEVEL: u8 = 2;

/// A Linux-safe generic LED under the EC `LED` object.
/// Reference: `tpacpi_led_names[16]` (`thinkpad_acpi.c:5595-5608`);
/// only the four `TPACPI_SAFE_LEDS` indices are constructible.
/// The old `ThinkpadLed` mixed three mechanisms into one index
/// space (battery 1, UltraBay 2, ThinkLight 4, kbdlight 8,
/// micmute 9 — 5 of 6 wrong); it is deleted, not repaired.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GenericLed {
    /// `tpacpi::power` — index 0.
    Power = 0,
    /// `tpacpi::standby` — index 7.
    Standby = 7,
    /// `tpacpi::lid_logo_dot` — index 10.
    LidLogoDot = 10,
    /// `tpacpi::thinkvantage` — index 12.
    ThinkVantage = 12,
}

impl GenericLed {
    /// The generic-LED index this LED is addressed by.
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// The Linux sysfs name (`tpacpi_led_names[16]`).
    pub const fn linux_name(self) -> &'static str {
        match self {
            GenericLed::Power => "tpacpi::power",
            GenericLed::Standby => "tpacpi::standby",
            GenericLed::LidLogoDot => "tpacpi::lid_logo_dot",
            GenericLed::ThinkVantage => "tpacpi::thinkvantage",
        }
    }

    /// Map a raw generic-LED index to the safe LED, if it is one of
    /// the four `TPACPI_SAFE_LEDS` indices. Restricted indices
    /// (battery 1/2, dock/bay 3/4/5/8/9, unknown 6/11/13-15)
    /// return `None`.
    pub const fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(GenericLed::Power),
            7 => Some(GenericLed::Standby),
            10 => Some(GenericLed::LidLogoDot),
            12 => Some(GenericLed::ThinkVantage),
            _ => None,
        }
    }
}

/// LED state — for the GENERIC LEDs only. Kbdlight is a `u8` level,
/// mute/micmute are `bool`; they do not share this type.
/// Reference: `TPACPI_LED_OFF/ON/BLINK` (`thinkpad_acpi.c:423-425`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LedState {
    Off,
    On,
    Blink,
}

/// Errors from the ThinkPad LED setters.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LedError {
    /// Generic-LED index outside 0..=15.
    InvalidIndex(u8),
    /// Generic-LED index restricted by default (Linux
    /// `tpacpi_is_led_restricted`, `TPACPI_SAFE_LEDS` 0x1481).
    RestrictedIndex(u8),
    /// Keyboard-backlight level outside 0..=`KBDLIGHT_MAX_LEVEL`.
    InvalidLevel(u8),
    /// The AML method does not exist on this machine (Linux's
    /// `mute_led_init` pattern: absent means unavailable, not an
    /// error in the other LED).
    MethodUnavailable(&'static str),
    /// The AML evaluation itself failed.
    Aml(narf_aml::AmlError),
}

impl From<narf_aml::AmlError> for LedError {
    fn from(e: narf_aml::AmlError) -> Self {
        LedError::Aml(e)
    }
}

/// Generic-LED state cache, packed 2 bits per LED (Off=0, On=1,
/// Blink=2) in one atomic so the cache stays consistent from
/// notify context without a lock. NEW-mode generic LEDs have no
/// hardware read-back in Linux (`led_get_status` returns `-ENXIO`,
/// `thinkpad_acpi.c:5640-5641`); the cache
/// (`tpacpi_led_state_cache[16]`, :5594, updated on every
/// successful set at :5696-5697) is the only record of state.
static GENERIC_LED_CACHE: AtomicU32 = AtomicU32::new(0);

/// Last mic-mute LED state written by `set_micmute`. The 0x60C0
/// notify re-asserts it (see `handle_hkey_notify_aml`); the audio
/// mic-mute feed (lane 4) replaces this cache read when it lands.
static MICMUTE_STATE: AtomicBool = AtomicBool::new(false);

/// Read back the cached state of a generic LED, if the index is in
/// range. The cache is updated on every successful `set_generic_led`.
pub fn generic_led_state(index: u8) -> Option<LedState> {
    if index >= 16 {
        return None;
    }
    match (GENERIC_LED_CACHE.load(Ordering::Relaxed) >> (u32::from(index) * 2)) & 0x3 {
        0 => Some(LedState::Off),
        1 => Some(LedState::On),
        2 => Some(LedState::Blink),
        _ => None,
    }
}

/// Last mic-mute LED state written by `set_micmute`.
pub fn micmute_state() -> bool {
    MICMUTE_STATE.load(Ordering::Relaxed)
}

fn cache_generic_led(index: u8, state: LedState) {
    let bits: u32 = match state {
        LedState::Off => 0,
        LedState::On => 1,
        LedState::Blink => 2,
    };
    let shift = u32::from(index) * 2;
    let _ = GENERIC_LED_CACHE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some((v & !(0x3u32 << shift)) | (bits << shift))
    });
}

/// Does an AML method exist at this absolute path (Linux's
/// `acpi_has_method` / `acpi_get_handle` probe, `mute_led_init`
/// pattern)? Absent means unavailable, never an error.
fn method_available(path: &str) -> bool {
    narf_aml::find_node(path).is_some()
}

/// Set a generic LED (NEW mode only — HawkPoint is NEW-mode if the
/// `LED` object exists under the EC handle).
///
/// Reference: `led_set_status` (`thinkpad_acpi.c:5646-5699`, NEW
/// case :5680-5689): `LED(index, 0x00 | 0x80 | 0xC0)` for
/// OFF / ON / BLINK. Rejects indices >= 16 and restricted indices
/// per `TPACPI_SAFE_LEDS`; updates the state cache on success.
/// OLD/570 modes are out of scope.
pub fn set_generic_led(index: u8, state: LedState) -> Result<(), LedError> {
    if index >= 16 {
        return Err(LedError::InvalidIndex(index));
    }
    if SAFE_GENERIC_LEDS & (1u16 << index) == 0 {
        return Err(LedError::RestrictedIndex(index));
    }
    let arg1: u64 = match state {
        LedState::Off => 0x00,
        LedState::On => 0x80,
        LedState::Blink => 0xC0,
    };
    narf_aml::eval::evaluate_method(
        EC_LED_PATH,
        &[
            narf_aml::Value::Integer(u64::from(index)),
            narf_aml::Value::Integer(arg1),
        ],
    )?;
    cache_generic_led(index, state);
    Ok(())
}

/// Set the keyboard-backlight level (0..=`KBDLIGHT_MAX_LEVEL`).
///
/// Reference: `kbdlight_set_level` (`thinkpad_acpi.c:5108-5119`):
/// `MLCS(level)` — the single argument is the level, no LED
/// index, no packed byte. This is the ONLY caller of `MLCS` in
/// Linux.
pub fn set_kbdlight_level(level: u8) -> Result<(), LedError> {
    if level > KBDLIGHT_MAX_LEVEL {
        return Err(LedError::InvalidLevel(level));
    }
    narf_aml::eval::evaluate_method(
        HKEY_MLCS_PATH,
        &[narf_aml::Value::Integer(u64::from(level))],
    )?;
    Ok(())
}

/// Read the keyboard-backlight level (0-2).
///
/// Reference: `kbdlight_get_level` (`thinkpad_acpi.c:5122-5135`):
/// `MLCG(0)`, return `status & 0x3`.
pub fn get_kbdlight_level() -> Result<u8, LedError> {
    let v = narf_aml::eval::evaluate_method(HKEY_MLCG_PATH, &[narf_aml::Value::Integer(0)])?;
    Ok((v.as_integer() & 0x3) as u8)
}

/// Full Linux `kbdlight_is_supported` probe
/// (`thinkpad_acpi.c:5138-5181`): `MLCG` exists AND evaluates
/// successfully AND has bit 9 set (`return status & BIT(9)`).
/// (A successful NARF evaluation returns `u64`, so the ">= 0" leg
/// is the `Err` arm below; the bit-9 test is the discriminator.)
pub fn kbdlight_supported() -> bool {
    if !method_available(HKEY_MLCG_PATH) {
        return false;
    }
    match narf_aml::eval::evaluate_method(HKEY_MLCG_PATH, &[narf_aml::Value::Integer(0)]) {
        Ok(v) => v.as_integer() & (1u64 << 9) != 0,
        Err(_) => false,
    }
}

/// Is the speaker-mute LED method present? (`mute_led_init`
/// probes each method independently; absent marks it unavailable
/// and does not fail the other LED.)
pub fn mute_available() -> bool {
    method_available(HKEY_SSMS_PATH)
}

/// Is the mic-mute LED method present?
pub fn micmute_available() -> bool {
    method_available(HKEY_MMTS_PATH)
}

/// Set the speaker-mute LED.
///
/// Reference: `mute_led_on_off` (`thinkpad_acpi.c:9391-9406`) via
/// `led_tables` (:9378-9388): `SSMS(1)` on, `SSMS(0)` off.
/// Returns `MethodUnavailable` if `SSMS` is absent.
pub fn set_mute(on: bool) -> Result<(), LedError> {
    if !mute_available() {
        return Err(LedError::MethodUnavailable("SSMS"));
    }
    narf_aml::eval::evaluate_method(
        HKEY_SSMS_PATH,
        &[narf_aml::Value::Integer(if on { 1 } else { 0 })],
    )?;
    Ok(())
}

/// Set the mic-mute LED.
///
/// Reference: `mute_led_on_off` (`thinkpad_acpi.c:9391-9406`) via
/// `led_tables` (:9378-9388): `MMTS(2)` on, `MMTS(0)` off.
/// Returns `MethodUnavailable` if `MMTS` is absent. Updates the
/// mic-mute state cache on success (the 0x60C0 notify arm reads
/// it back).
pub fn set_micmute(on: bool) -> Result<(), LedError> {
    if !micmute_available() {
        return Err(LedError::MethodUnavailable("MMTS"));
    }
    narf_aml::eval::evaluate_method(
        HKEY_MMTS_PATH,
        &[narf_aml::Value::Integer(if on { 2 } else { 0 })],
    )?;
    MICMUTE_STATE.store(on, Ordering::Relaxed);
    Ok(())
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
            // 0x60C0: firmware says the mic-mute LED may be out of
            // sync — re-assert the last state `set_micmute` wrote.
            // The audio mic-mute feed (lane 4) replaces this cache
            // read when it lands; do not invent a feed here.
            let _ = set_micmute(micmute_state());
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
    let mut found = false;
    for hid in &["LEN0268", "IBM0068", "LEN0018"] {
        for dev in narf_aml::find_all_devices_by_hid(hid) {
            narf_aml::sync::register_notify_handler(&dev.path, handle_hkey_notify_aml);
            found = true;
        }
    }
    if found {
        // An HKEY device is present, so the EC fan behind `\HFNF`
        // is too: expose it as a CoolingDevice so the thermal
        // governor can drive it (#911).
        crate::fan::register_thinkpad_fan();
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
    GENERIC_LED_CACHE.store(0, Ordering::Relaxed);
    MICMUTE_STATE.store(false, Ordering::Relaxed);
}
