//! Shared probe/register/set logic for the ThinkPad LED driver
//! (both builds).
//!
//! The two backends — builtin (AML direct, `builtin.rs`) and module
//! (AML through the KABI quad stream, `module_probe.rs`) — implement
//! the `Backend` trait; everything else is shared: the last-written
//! brightness cache, the clamp-and-dispatch set path, the kbdlight
//! re-seed from hardware, and the 0x60C0 mic-mute re-assert.
//!
//! Readback: generic/mute/micmute LEDs have no hardware readback
//! (Linux's NEW-mode `led_get_status` returns `-ENXIO`,
//! `thinkpad_acpi.c:5640-5641`), so `get_led` returns the last
//! brightness the driver wrote. The kbdlight level *is* readable
//! (`MLCG`), so it is re-seeded from hardware at probe — a reload
//! picks up the level the previous load (or the firmware) left.
//! A reload seeds generic/mute/micmute to off: the first set after
//! reload writes the new level, so the hardware converges on first
//! use.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::defs::{LedDef, LedKind, KBD_IDX, LED_DEFS, MICMUTE_IDX, MICMUTE_NOTIFY};

/// Number of LEDs in [`LED_DEFS`]; the cache below is sized to it.
const LED_COUNT: usize = LED_DEFS.len();
const _: () = assert!(LED_COUNT == 7);

/// Last brightness written per LED def (index = def index in
/// [`LED_DEFS`]). The readback for every LED (see the module doc).
static LAST_BRIGHTNESS: [AtomicU32; 7] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];

/// The hardware behind one LED mechanism. Implemented twice: the
/// builtin backend calls the moved setters (AML direct), the module
/// backend calls the same methods through the KABI exports.
pub trait Backend {
    /// Full Linux `kbdlight_is_supported` probe: `MLCG` exists AND
    /// evaluates AND has bit 9 set.
    fn kbdlight_supported(&self) -> bool;
    /// `MLCS(level)` — level already clamped to
    /// `0..=KBDLIGHT_MAX_LEVEL` by [`set_led`].
    fn set_kbdlight(&self, level: u8) -> Result<(), ()>;
    /// `MLCG(0) & 0x3` — the current kbdlight level, for the
    /// reload re-seed.
    fn get_kbdlight(&self) -> Result<u8, ()>;
    /// The EC `LED` object exists (generic LEDs are addressable).
    fn generic_available(&self) -> bool;
    /// `LED(index, 0x00 | 0x80)` for off / on.
    fn set_generic(&self, index: u8, on: bool) -> Result<(), ()>;
    /// The `SSMS` method exists.
    fn mute_available(&self) -> bool;
    /// `SSMS(1)` / `SSMS(0)`.
    fn set_mute(&self, on: bool) -> Result<(), ()>;
    /// The `MMTS` method exists.
    fn micmute_available(&self) -> bool;
    /// `MMTS(2)` / `MMTS(0)`.
    fn set_micmute(&self, on: bool) -> Result<(), ()>;
}

/// Is this LED available on this machine, via the backend's probe?
pub fn def_available<B: Backend>(backend: &B, def: &LedDef) -> bool {
    match def.kind {
        LedKind::Kbdlight => backend.kbdlight_supported(),
        LedKind::Mute => backend.mute_available(),
        LedKind::MicMute => backend.micmute_available(),
        LedKind::Generic(_) => backend.generic_available(),
    }
}

/// Drive one LED to `level` (the LED core clamps to
/// `[0, max_brightness()]` first; this clamps again defensively).
/// The last-written cache updates only on a successful backend
/// set, so `get_led` never claims a level the hardware refused.
pub fn set_led<B: Backend>(backend: &B, def_idx: usize, level: u32) {
    let Some(def) = LED_DEFS.get(def_idx) else {
        return;
    };
    let level = core::cmp::min(level, def.max_brightness);
    let ok = match def.kind {
        LedKind::Kbdlight => backend.set_kbdlight(level as u8).is_ok(),
        LedKind::Mute => backend.set_mute(level != 0).is_ok(),
        LedKind::MicMute => backend.set_micmute(level != 0).is_ok(),
        LedKind::Generic(index) => backend.set_generic(index, level != 0).is_ok(),
    };
    if ok {
        LAST_BRIGHTNESS[def_idx].store(level, Ordering::Release);
    }
}

/// Last brightness written to this LED (0 before any successful
/// set, or after a reset).
pub fn get_led(def_idx: usize) -> u32 {
    LAST_BRIGHTNESS
        .get(def_idx)
        .map(|a| a.load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Re-seed the kbdlight level from hardware (reload path). Other
/// LEDs have no readback and seed to off (see the module doc).
pub fn seed_kbdlight<B: Backend>(backend: &B) {
    if let Ok(level) = backend.get_kbdlight() {
        LAST_BRIGHTNESS[KBD_IDX].store(u32::from(level), Ordering::Release);
    }
}

/// HKEY notify handler (shared): `0x60C0` means the firmware says
/// the mic-mute LED may be out of sync — re-assert the last state
/// this driver wrote. Every other notify value is ignored here
/// (hotkeys are the HKEY driver's job, not this driver's).
pub fn on_notify<B: Backend>(backend: &B, value: u64) {
    if value != MICMUTE_NOTIFY {
        return;
    }
    let on = get_led(MICMUTE_IDX) != 0;
    let _ = backend.set_micmute(on);
}

/// Reset the last-written cache for tests.
#[doc(hidden)]
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    for slot in &LAST_BRIGHTNESS {
        slot.store(0, Ordering::Release);
    }
}
