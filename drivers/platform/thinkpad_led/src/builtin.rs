//! Builtin backend: the ThinkPad LED setters, called directly.
//!
//! Moved verbatim from lane 2's `drivers/platform/src/thinkpad_acpi.rs`
//! (the three per-mechanism setters, `GenericLed` + `u8` level +
//! `bool`, packed-`AtomicU32` state cache, wired 0x60C0 arm) so the
//! driver body lives in this crate and the platform facade can depend
//! on it without a cycle. `thinkpad_acpi.rs` keeps the HKEY hotkey
//! dispatch; its 0x60C0 arm calls [`set_micmute`]/[`micmute_state`]
//! here. The module backend (`module_probe.rs`) implements the same
//! operations through the KABI exports.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_drivers_leds::{set_led_default_trigger, LedDevice, Trigger};
use narf_lib::sync::IrqSafeSpinLock;

use crate::defs::{
    EC_LED_PATH, HKEY_MLCG_PATH, HKEY_MLCS_PATH, HKEY_MMTS_PATH, HKEY_SSMS_PATH,
    KBDLIGHT_MAX_LEVEL, LED_DEFS, SAFE_GENERIC_LEDS,
};
use crate::driver::{self, Backend};

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
/// notify re-asserts it (see `handle_hkey_notify_aml` in
/// `thinkpad_acpi.rs`); the audio mic-mute feed (lane 4) replaces
/// this cache read when it lands.
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
/// (A successful NARF evaluation returns `u64`, so the `>= 0` leg
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

// ── Backend ──────────────────────────────────────────────────────────

/// The builtin backend: the moved setters above, behind the shared
/// [`Backend`] trait.
#[derive(Debug)]
pub struct BuiltinBackend;

impl Backend for BuiltinBackend {
    fn kbdlight_supported(&self) -> bool {
        kbdlight_supported()
    }
    fn set_kbdlight(&self, level: u8) -> Result<(), ()> {
        set_kbdlight_level(level).map_err(|_| ())
    }
    fn get_kbdlight(&self) -> Result<u8, ()> {
        get_kbdlight_level().map_err(|_| ())
    }
    fn generic_available(&self) -> bool {
        method_available(EC_LED_PATH)
    }
    fn set_generic(&self, index: u8, on: bool) -> Result<(), ()> {
        set_generic_led(index, if on { LedState::On } else { LedState::Off }).map_err(|_| ())
    }
    fn mute_available(&self) -> bool {
        mute_available()
    }
    fn set_mute(&self, on: bool) -> Result<(), ()> {
        set_mute(on).map_err(|_| ())
    }
    fn micmute_available(&self) -> bool {
        micmute_available()
    }
    fn set_micmute(&self, on: bool) -> Result<(), ()> {
        set_micmute(on).map_err(|_| ())
    }
}

/// The single builtin backend instance.
static BACKEND: BuiltinBackend = BuiltinBackend;

/// One LED device, backed by a def in [`LED_DEFS`]. `set_brightness`
/// goes through the shared [`driver::set_led`] (clamp + dispatch +
/// last-written cache); the trigger cell is engine-owned state, as
/// in `SimpleLed`.
#[derive(Debug)]
struct DriverLed {
    def_idx: usize,
    trigger: IrqSafeSpinLock<Trigger>,
}

impl DriverLed {
    fn new(def_idx: usize) -> Self {
        Self {
            def_idx,
            trigger: IrqSafeSpinLock::new(Trigger::None),
        }
    }
}

impl LedDevice for DriverLed {
    fn name(&self) -> &str {
        LED_DEFS[self.def_idx].name
    }

    fn max_brightness(&self) -> u32 {
        LED_DEFS[self.def_idx].max_brightness
    }

    fn brightness(&self) -> u32 {
        driver::get_led(self.def_idx)
    }

    fn set_brightness(&self, level: u32) {
        driver::set_led(&BACKEND, self.def_idx, level);
    }

    fn current_trigger(&self) -> Trigger {
        self.trigger.lock().clone()
    }

    fn set_trigger(&self, trigger: Trigger) {
        *self.trigger.lock() = trigger;
    }
}

/// Register the available LEDs with the LED class (builtin build).
/// Called from the platform facade's `Stage::Device` initcall;
/// registration is dynamic (#956), so the stage only orders boot
/// logging. Unavailable LEDs are skipped (absent method, never an
/// error in the other LED). The kbdlight level is re-seeded from
/// hardware first, so a reload picks up the level left behind.
pub fn register() {
    driver::seed_kbdlight(&BACKEND);
    for (idx, def) in LED_DEFS.iter().enumerate() {
        if !driver::def_available(&BACKEND, def) {
            continue;
        }
        narf_drivers_leds::register_led(alloc::sync::Arc::new(DriverLed::new(idx)));
        if let Some(trigger) = def.default_trigger {
            set_led_default_trigger(def.name, trigger);
        }
    }
}

/// Reset the builtin backend's caches for tests.
#[doc(hidden)]
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    GENERIC_LED_CACHE.store(0, Ordering::Relaxed);
    MICMUTE_STATE.store(false, Ordering::Relaxed);
}
