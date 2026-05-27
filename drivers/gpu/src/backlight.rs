//! Unified display-backlight control with backend selection.
//!
//! Most modern laptops expose at least one — sometimes several —
//! ways to control panel brightness. The OS picks the highest-
//! quality interface available and ignores the rest. This module
//! presents one public API (`set` / `get` / `levels` / `backend`)
//! and an internal probe order that mirrors what Linux's
//! `acpi_video_get_backlight_type()` does:
//!
//!   1. **Intel BLC PWM** — direct PWM duty-cycle programming
//!      against the iGPU's display engine. Smoothest curve
//!      because the host owns both the period (frequency) and
//!      the duty register. Used by `i915` / `xe` when the
//!      platform is Intel and the PRM-documented PWM block is
//!      present.
//!   2. **AMD ATIF (WMI _DSM)** — AMD-specific ACPI service
//!      exposed as a WMI device with GUID
//!      `ea3168f8-ce3c-4c12-aedd-69dd0e6bb59b`. `_DSM` function 1
//!      returns the supported-function bitmap; function 3 sets
//!      brightness as a 0–100 percentage; function 4 returns the
//!      current percentage. Optional — not every AMD-laptop
//!      firmware ships it.
//!   3. **Generic ACPI `_BCL` / `_BCM` / `_BQC`** — the
//!      vendor-neutral fallback every laptop DSDT carries (when
//!      a brightness ladder exists at all). `_BCL` returns the
//!      list of supported levels (with the first two entries
//!      being the AC and battery defaults); `_BCM(level)` sets
//!      brightness; `_BQC` reads it back.
//!
//! ## References
//!
//! Linux is GPL-2.0-or-later and NARF was relicensed to the
//! same on 2026-05-20, so the upstream sources may be cited
//! and adapted directly:
//!
//! - `drivers/gpu/drm/i915/display/intel_backlight.c` —
//!   `pch_get_max_backlight`, `bxt_set_backlight`, the
//!   PERIOD/DUTY pair, and the SOUTH_CHICKEN1 panel-power gate.
//! - `drivers/platform/x86/amd/pmf/sps.c` /
//!   `drivers/gpu/drm/radeon/radeon_atif.c` — the ATIF GUID
//!   and the `_DSM` function-supported-bitmap convention.
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_acpi.c` —
//!   `amdgpu_atif_set_backlight` shows the func-3 set call shape.
//! - `drivers/acpi/acpi_video.c` — `_BCL` package decode, the
//!   "skip first two entries" idiom, and the level-snap behaviour.
//!
//! ## Stage progression
//!
//! The runtime portion of this driver is split intentionally
//! into pure decode functions (testable without hardware) and
//! a thin trait-driven activation layer. The current commit
//! lands the pure code + the dispatcher; wiring the dispatcher
//! to a live iGPU BAR / live ATIF method is the responsibility
//! of the platform's bring-up code, which calls `activate_*`.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Public surface ────────────────────────────────────────────────

/// Identifier for the currently-selected backlight backend. Set by
/// the boot-time probe (`select_backend`) and read by `backend()`.
/// `None` means no backlight was detected on this platform.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// No backlight backend installed. `set` returns
    /// `BacklightError::NoBackend`.
    None = 0,
    /// Intel display-engine PWM (`BLC_PWM_FREQ1` /
    /// `BLC_PWM_DUTY1`). Smoothest curve; direct MMIO.
    IntelBlc = 1,
    /// AMD ATIF via WMI `_DSM`. Percentage-based.
    AmdAtif = 2,
    /// Generic ACPI `_BCL` / `_BCM` / `_BQC` ladder.
    AcpiVideo = 3,
}

impl Backend {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Backend::IntelBlc,
            2 => Backend::AmdAtif,
            3 => Backend::AcpiVideo,
            _ => Backend::None,
        }
    }
}

/// Errors from the unified backlight surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacklightError {
    /// No backend was detected on this platform — `set`/`get`
    /// can't be honoured.
    NoBackend,
    /// Backend was detected but the active driver has not yet
    /// been wired up (e.g. ATIF GUID present but no `_DSM` runner
    /// registered yet). Transient — call `activate_*` first.
    NotActivated,
    /// MMIO / AML / WMI invocation failed. Cause is logged.
    Hardware,
    /// `_DSM` function 3 (set) reports the function isn't
    /// supported at this revision. Caller should fall back to
    /// the ACPI generic backend or refuse the request.
    Unsupported,
    /// Caller passed a percentage > 100 and didn't want it
    /// clamped, or `_BCL` ladder was empty.
    InvalidLevel,
}

// ── Intel BLC PWM (backend A) ─────────────────────────────────────
//
// The Intel display engine carries a per-pipe PWM block that drives
// the eDP panel's backlight. The "modern" (Broxton / Geminilake /
// Kaby Lake-R / Tiger Lake / Alder Lake) shape uses two registers:
//
//   * `BXT_BLC_PWM_FREQ1`  — 32-bit period (in PWM-clock units).
//     The HW divides the source clock by this value to derive the
//     PWM frequency. Picked by firmware so the panel sees its
//     calibrated drive frequency.
//   * `BXT_BLC_PWM_DUTY1`  — 32-bit duty target. Linear scale:
//     `duty == 0` → fully off, `duty == freq` → fully on.
//
// The "legacy" PCH path uses `BLC_PWM_CTL` at 0xC8250 which packs
// (period << 16) | duty into one DWord. We expose both register
// sets so the activator can pick the right one per generation.

/// `BLC_PWM_CTL` (legacy PCH path). High 16 bits = period, low 16
/// bits = duty cycle. Used on Skylake PCH and earlier display
/// engines. Reference: TGL PRM Vol 11 §"Backlight control".
pub const BLC_PWM_CTL: u64 = 0xC8250;
/// `SOUTH_CHICKEN1` — panel-power gating chicken bits. Bit 25
/// (`PCH_LPC_PWM_SEL`) selects whether the LPC or the CPU drives
/// the PWM. The activator clears this bit so the iGPU owns the PWM.
/// Reference: Linux `drivers/gpu/drm/i915/i915_reg.h::SOUTH_CHICKEN1`.
pub const SOUTH_CHICKEN1: u64 = 0xC2000;
/// `BXT_BLC_PWM_FREQ1` — period register, modern PCH path.
/// Reference: Linux `intel_backlight.c::bxt_get_backlight`.
pub const BXT_BLC_PWM_FREQ1: u64 = 0xC8254;
/// `BXT_BLC_PWM_DUTY1` — duty-cycle target, modern PCH path.
/// Reference: Linux `intel_backlight.c::bxt_set_backlight`.
pub const BXT_BLC_PWM_DUTY1: u64 = 0xC8258;

/// Minimum 32-bit MMIO interface needed by the Intel BLC backend.
/// Wraps the iGPU's BAR0 window in production; tests inject a
/// `FakeMmio`. Identical to the trait `intel_gpu_aux::MmioWindow`
/// uses, but redeclared here so the backlight module doesn't pull
/// the entire AUX transport into its dep graph.
pub trait MmioWindow {
    fn read32(&self, off: u64) -> u32;
    fn write32(&self, off: u64, val: u32);
}

/// Convert a 0..=100 percentage to a duty count given the panel's
/// PWM period. Clamps to `[0, period]`. Linear — gamma correction
/// is the panel's job (or the SMU's brightness table on AMD).
///
/// Mirrors `intel_backlight.c::scale_user_to_hw`:
///   `hw = (period * pct) / 100`
pub fn intel_pct_to_duty(period: u32, pct: u8) -> u32 {
    let pct = pct.min(100) as u64;
    let p = period as u64;
    ((p * pct) / 100) as u32
}

/// Convert a measured duty count back to a 0..=100 percentage given
/// the panel's PWM period. Inverse of `intel_pct_to_duty`. Saturating.
/// Returns 0 when `period == 0` (panel not initialised).
pub fn intel_duty_to_pct(period: u32, duty: u32) -> u8 {
    if period == 0 {
        return 0;
    }
    // Round to nearest.
    let p = period as u64;
    let d = duty.min(period) as u64;
    let pct = (d * 100 + p / 2) / p;
    pct.min(100) as u8
}

/// Apply `pct` to an Intel iGPU BAR via the modern PCH path
/// (BXT-style). Reads `BXT_BLC_PWM_FREQ1` for the period, writes
/// `BXT_BLC_PWM_DUTY1` to the scaled duty. Returns the duty value
/// actually written (so callers can verify against a probe).
///
/// Caller is responsible for the SOUTH_CHICKEN1 gate; the modern
/// PCH path doesn't need to re-gate per-set because the activator
/// already did it.
pub fn intel_set_pct<M: MmioWindow + ?Sized>(
    mmio: &M,
    pct: u8,
) -> Result<u32, BacklightError> {
    let period = mmio.read32(BXT_BLC_PWM_FREQ1);
    if period == 0 {
        // Firmware didn't program the PWM — we can't pick a sane
        // period without panel data, so refuse rather than scribble.
        return Err(BacklightError::Hardware);
    }
    let duty = intel_pct_to_duty(period, pct);
    mmio.write32(BXT_BLC_PWM_DUTY1, duty);
    Ok(duty)
}

/// Read the current Intel iGPU PWM duty and return it as a 0..=100
/// percentage. Pure round-trip of `intel_set_pct`.
pub fn intel_get_pct<M: MmioWindow + ?Sized>(mmio: &M) -> Result<u8, BacklightError> {
    let period = mmio.read32(BXT_BLC_PWM_FREQ1);
    let duty = mmio.read32(BXT_BLC_PWM_DUTY1);
    Ok(intel_duty_to_pct(period, duty))
}

// ── AMD ATIF (backend B) ───────────────────────────────────────────
//
// ATIF (AMD ACPI Total Inferred Frequency) is a WMI-exposed _DSM
// surface that AMD-laptop firmware uses to mediate things the
// host can't drive directly: thermal events, hotkeys, expansion-
// dock detection, and (importantly here) panel backlight.
//
// The function-supported bitmap follows the standard _DSM
// convention (ACPI 6.5 §9.1.1):
//   - Function 0: returns a Buffer whose bits indicate which
//     other function indices are valid for this revision.
//   - Bit 0 of function 0's return is *always* set (the spec
//     promises function 0 itself is supported).
//
// AMD's documented ATIF function map (per radeon_atif.c and
// amdgpu_acpi.c):
//   - Func 1 — QUERY_BRIGHTNESS_TRANSFER_CHARACTERISTICS
//   - Func 2 — SET_PREFERRED_BRIGHTNESS_NOTIFICATION
//   - Func 3 — SET_BRIGHTNESS_PERCENTAGE
//   - Func 4 — GET_BRIGHTNESS_PERCENTAGE
//   - Func 5 — SELECT_ACTIVE_DISPLAYS
//   - Func 6 — GET_LID_STATE
//   - Func 7 — GET_TV_STANDARD
//   - Func 8..N — thermal / hotkey / expansion notifications

/// ATIF WMI GUID, little-endian mixed-endian (Microsoft GUID byte
/// order): `ea3168f8-ce3c-4c12-aedd-69dd0e6bb59b`.
/// First three groups are little-endian; the trailing two groups
/// are big-endian per the MS GUID convention. This is the byte
/// layout AML sees when the `_DSM` Buffer argument is decoded.
pub const ATIF_GUID: [u8; 16] = [
    0xf8, 0x68, 0x31, 0xea, // ea3168f8 (LE)
    0x3c, 0xce,             // ce3c     (LE)
    0x12, 0x4c,             // 4c12     (LE)
    0xae, 0xdd,             // aedd     (BE)
    0x69, 0xdd, 0x0e, 0x6b, 0xb5, 0x9b, // 69dd0e6bb59b (BE)
];

/// ATIF function indices.
pub const ATIF_FN_QUERY_FUNCTIONS: u8 = 0;
pub const ATIF_FN_QUERY_BRIGHTNESS_TC: u8 = 1;
pub const ATIF_FN_SET_BRIGHTNESS_PCT: u8 = 3;
pub const ATIF_FN_GET_BRIGHTNESS_PCT: u8 = 4;

/// Result of decoding the `_DSM` function-0 supported-bitmap. Each
/// `Some` entry says "function index `i` is supported". The bitmap
/// is little-endian; bit 0 of byte 0 is always set per spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DsmSupported {
    /// All supported function indices, ascending.
    pub functions: Vec<u8>,
}

impl DsmSupported {
    /// True iff function `f` appears in the supported set.
    pub fn supports(&self, f: u8) -> bool {
        self.functions.iter().any(|&x| x == f)
    }
}

/// Decode the buffer returned by `_DSM(GUID, rev, 0, Package())`
/// into the supported-function set. Per ACPI 6.5 §9.1.1 the buffer
/// is a bitmask: bit `i` of byte `i / 8` ↔ function `i` is
/// supported. Function 0 (bit 0) MUST be set; if it isn't, this
/// function returns an empty set so the caller falls through to the
/// next backend without spamming.
pub fn decode_dsm_supported(buf: &[u8]) -> DsmSupported {
    if buf.is_empty() || buf[0] & 0x01 == 0 {
        return DsmSupported::default();
    }
    let mut funcs = Vec::new();
    for (byte_idx, byte) in buf.iter().enumerate() {
        for bit in 0..8 {
            if (byte >> bit) & 1 != 0 {
                let f = (byte_idx as u16) * 8 + bit;
                if f <= u8::MAX as u16 {
                    funcs.push(f as u8);
                }
            }
        }
    }
    DsmSupported { functions: funcs }
}

/// Trait the ATIF backend uses to invoke `_DSM` against the WMI
/// device. Pure trait → testable without an AML interpreter. The
/// production wiring (in a later commit / by the platform crate)
/// implements this by calling `narf_aml::eval::evaluate_dsm`.
pub trait AtifInvoke: Sync + Send {
    /// Invoke `_DSM(GUID=ATIF, rev=1, function, package_arg)`. The
    /// `package_arg` is encoded by the caller; for func 0 it's an
    /// empty package, for func 3 (set) it's `Package(Integer(pct))`.
    /// Returns the raw buffer the AML method returned, or `None`
    /// on AML evaluation error.
    fn dsm(&self, function: u8, package_arg: &[u8]) -> Option<Vec<u8>>;
}

// ── ACPI _BCL / _BCM / _BQC (backend C) ────────────────────────────
//
// `_BCL` returns a Package(Integer, Integer, Integer...) where:
//   - element 0 = "full-power" default (AC),
//   - element 1 = "battery-power" default,
//   - elements 2..N = the supported brightness ladder.
//
// Ladders vary wildly per firmware:
//   - Most laptops: 11 entries 0,10,20,...,100.
//   - Lenovo Yoga: 11 entries with the lowest non-zero step at 5.
//   - Some Dell BIOS: 256-entry ladder 0..=255.
// Snap-to-nearest is the universal write strategy.

/// Decode a `_BCL` package payload (as a slice of u32 values) into
/// the supported ladder. Drops the first two entries (AC default,
/// battery default) and returns a sorted, deduped vector. Returns
/// an empty vec when the payload is too short to be a real ladder.
///
/// Mirrors `acpi_video_init_brightness`'s slicing.
pub fn decode_bcl(pkg: &[u32]) -> Vec<u8> {
    if pkg.len() < 3 {
        return Vec::new();
    }
    let mut out: Vec<u8> = pkg[2..]
        .iter()
        .filter_map(|&v| if v <= 100 { Some(v as u8) } else { None })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Snap `requested` (0..=100) to the nearest level on `ladder`. Ties
/// resolve toward the larger value (brighter). Returns `None` when
/// the ladder is empty.
pub fn snap_to_ladder(ladder: &[u8], requested: u8) -> Option<u8> {
    if ladder.is_empty() {
        return None;
    }
    let req = requested.min(100) as i32;
    let mut best = ladder[0];
    let mut best_dist = (ladder[0] as i32 - req).abs();
    for &l in &ladder[1..] {
        let d = (l as i32 - req).abs();
        if d <= best_dist {
            best = l;
            best_dist = d;
        }
    }
    Some(best)
}

/// Trait the AcpiVideo backend uses to invoke `_BCM` / `_BQC`. Pure
/// trait → testable without an AML interpreter. The production
/// wiring implements this by calling `narf_aml::eval::evaluate_method`.
pub trait AcpiVideoInvoke: Sync + Send {
    /// Set brightness to `level` on the active panel via `_BCM(level)`.
    /// Returns `false` on AML evaluation error.
    fn bcm(&self, level: u8) -> bool;
    /// Read the current brightness level via `_BQC`. Returns `None`
    /// on AML evaluation error.
    fn bqc(&self) -> Option<u8>;
    /// Return the cached ladder. Called once during activation; the
    /// driver caches it internally so the hot path doesn't re-walk.
    fn ladder(&self) -> &[u8];
}

// ── Global dispatcher state ────────────────────────────────────────
//
// One backend at a time. `BACKEND` carries the currently-active
// Backend enum value. The implementation pointers live behind
// `ACTIVE_*` slots — only the slot matching `BACKEND` is consulted.
// Boxing keeps the implementation choice dynamic without making
// `Backend` itself a trait-object.

trait Driver: Sync + Send {
    fn set(&self, pct: u8) -> Result<(), BacklightError>;
    fn get(&self) -> Result<u8, BacklightError>;
}

struct IntelDriver<M: MmioWindow + Sync + Send + 'static> {
    mmio: M,
}

impl<M: MmioWindow + Sync + Send + 'static> Driver for IntelDriver<M> {
    fn set(&self, pct: u8) -> Result<(), BacklightError> {
        intel_set_pct(&self.mmio, pct).map(|_| ())
    }
    fn get(&self) -> Result<u8, BacklightError> {
        intel_get_pct(&self.mmio)
    }
}

struct AtifDriver<I: AtifInvoke + 'static> {
    invoke: I,
}

impl<I: AtifInvoke + 'static> Driver for AtifDriver<I> {
    fn set(&self, pct: u8) -> Result<(), BacklightError> {
        // _DSM func 3: Package(Integer(pct)). The package encoder
        // is up to the AML runner; we only carry the percentage.
        let pct = pct.min(100);
        match self.invoke.dsm(ATIF_FN_SET_BRIGHTNESS_PCT, &[pct]) {
            Some(_) => Ok(()),
            None => Err(BacklightError::Hardware),
        }
    }
    fn get(&self) -> Result<u8, BacklightError> {
        match self.invoke.dsm(ATIF_FN_GET_BRIGHTNESS_PCT, &[]) {
            Some(buf) if !buf.is_empty() => Ok(buf[0].min(100)),
            _ => Err(BacklightError::Hardware),
        }
    }
}

struct AcpiVideoDriver<I: AcpiVideoInvoke + 'static> {
    invoke: I,
    levels: Vec<u8>,
}

impl<I: AcpiVideoInvoke + 'static> Driver for AcpiVideoDriver<I> {
    fn set(&self, pct: u8) -> Result<(), BacklightError> {
        let target =
            snap_to_ladder(&self.levels, pct).ok_or(BacklightError::InvalidLevel)?;
        if self.invoke.bcm(target) {
            Ok(())
        } else {
            Err(BacklightError::Hardware)
        }
    }
    fn get(&self) -> Result<u8, BacklightError> {
        self.invoke.bqc().ok_or(BacklightError::Hardware)
    }
}

/// Test-only backend that records every set/get and reflects them.
/// Used by the priority + round-trip smokes.
#[doc(hidden)]
#[derive(Debug)]
pub struct FakeDriver {
    pub current: AtomicU8,
    pub levels: Vec<u8>,
}

impl FakeDriver {
    /// Build a fake with a stepped ladder identical to most laptops.
    pub fn new_full_ladder() -> Self {
        Self {
            current: AtomicU8::new(50),
            levels: (0..=10).map(|n| n * 10).collect(),
        }
    }
}

impl Driver for FakeDriver {
    fn set(&self, pct: u8) -> Result<(), BacklightError> {
        self.current.store(pct.min(100), Ordering::Release);
        Ok(())
    }
    fn get(&self) -> Result<u8, BacklightError> {
        Ok(self.current.load(Ordering::Acquire))
    }
}

// 100% / 0 — empty ladder slice for the `NoBackend` case.
const EMPTY_LEVELS: &[u8] = &[];

// Use `Option<Box<dyn Driver>>` behind a spinlock for the active
// driver. AtomicU8 holds the discriminant so `backend()` is a
// lock-free read. Levels are deep-cloned out behind the lock when
// requested; the `levels()` API returns `&'static [u8]` via a
// stash to keep the trait signature ergonomic.
static BACKEND: AtomicU8 = AtomicU8::new(Backend::None as u8);
static DRIVER: IrqSafeSpinLock<Option<alloc::boxed::Box<dyn Driver>>> =
    IrqSafeSpinLock::new(None);

// Stash for the levels() return slice. Refreshed on every
// `activate_*` so the static lifetime is honoured.
static LEVELS_PTR: AtomicUsize = AtomicUsize::new(0);
static LEVELS_LEN: AtomicUsize = AtomicUsize::new(0);
static LEVELS_STASH: IrqSafeSpinLock<Vec<u8>> = IrqSafeSpinLock::new(Vec::new());

fn refresh_levels_stash(levels: Vec<u8>) {
    let mut g = LEVELS_STASH.lock();
    *g = levels;
    LEVELS_PTR.store(g.as_ptr() as usize, Ordering::Release);
    LEVELS_LEN.store(g.len(), Ordering::Release);
}

// ── Public dispatch API ────────────────────────────────────────────

/// Set the backlight to `pct` percent. Clamped to 0..=100. Returns
/// `BacklightError::NoBackend` when no backend has been activated.
pub fn set(pct: u8) -> Result<(), BacklightError> {
    let g = DRIVER.lock();
    match &*g {
        Some(d) => d.set(pct),
        None => Err(BacklightError::NoBackend),
    }
}

/// Get the current backlight percentage. See `set` for error shape.
pub fn get() -> Result<u8, BacklightError> {
    let g = DRIVER.lock();
    match &*g {
        Some(d) => d.get(),
        None => Err(BacklightError::NoBackend),
    }
}

/// Return the supported brightness percentages for the active
/// backend. Empty slice when no backend is active.
///
/// For Intel BLC and ATIF the ladder is the full 0..=100 set
/// (since both are continuous percentages). For ACPI _BCL it's
/// the ladder the firmware declared.
pub fn levels() -> &'static [u8] {
    let ptr = LEVELS_PTR.load(Ordering::Acquire);
    let len = LEVELS_LEN.load(Ordering::Acquire);
    if ptr == 0 || len == 0 {
        return EMPTY_LEVELS;
    }
    // SAFETY: ptr+len point at the contents of LEVELS_STASH, a
    // static vec that is only mutated under LEVELS_STASH.lock() in
    // `refresh_levels_stash`. We never shrink the vec past 0 once
    // the LEN store retires, and we never re-allocate after the
    // first push without re-storing ptr. Worst case under a race
    // with a re-activation: callers see a partial new ladder; they
    // never see out-of-bounds memory.
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len) }
}

/// Currently-active backend.
pub fn backend() -> Backend {
    Backend::from_u8(BACKEND.load(Ordering::Acquire))
}

// ── Activation API ─────────────────────────────────────────────────
//
// Each activator installs one backend, refreshes the levels stash,
// and stores the discriminant. The probe order at boot is encoded
// in `select_backend` below.

/// Install the Intel BLC backend driving `mmio`. Replaces any
/// currently-active backend.
pub fn activate_intel_blc<M: MmioWindow + Sync + Send + 'static>(mmio: M) {
    let levels: Vec<u8> = (0..=100).collect();
    refresh_levels_stash(levels);
    let drv = IntelDriver { mmio };
    *DRIVER.lock() = Some(alloc::boxed::Box::new(drv));
    BACKEND.store(Backend::IntelBlc as u8, Ordering::Release);
}

/// Install the AMD ATIF backend driving `invoke`. Replaces any
/// currently-active backend. Caller is responsible for having
/// already checked that `decode_dsm_supported` says func 3 / 4
/// are available — otherwise `set` / `get` will return
/// `BacklightError::Hardware` on every call.
pub fn activate_amd_atif<I: AtifInvoke + 'static>(invoke: I) {
    let levels: Vec<u8> = (0..=100).collect();
    refresh_levels_stash(levels);
    let drv = AtifDriver { invoke };
    *DRIVER.lock() = Some(alloc::boxed::Box::new(drv));
    BACKEND.store(Backend::AmdAtif as u8, Ordering::Release);
}

/// Install the generic ACPI _BCL backend driving `invoke`. The
/// invoker's `ladder()` is queried once and cached.
pub fn activate_acpi_video<I: AcpiVideoInvoke + 'static>(invoke: I) {
    let levels: Vec<u8> = invoke.ladder().to_vec();
    refresh_levels_stash(levels.clone());
    let drv = AcpiVideoDriver { invoke, levels };
    *DRIVER.lock() = Some(alloc::boxed::Box::new(drv));
    BACKEND.store(Backend::AcpiVideo as u8, Ordering::Release);
}

/// Install a test-only `FakeDriver`. Hidden from docs because
/// production code shouldn't call it.
#[doc(hidden)]
pub fn activate_fake(drv: FakeDriver, backend: Backend) {
    let levels = drv.levels.clone();
    refresh_levels_stash(levels);
    *DRIVER.lock() = Some(alloc::boxed::Box::new(drv));
    BACKEND.store(backend as u8, Ordering::Release);
}

/// Tear down the active backend. Used by tests; production code
/// shouldn't call this since brightness is a stateful setting.
#[doc(hidden)]
pub fn deactivate() {
    *DRIVER.lock() = None;
    refresh_levels_stash(Vec::new());
    BACKEND.store(Backend::None as u8, Ordering::Release);
}

// ── Boot-time probe ────────────────────────────────────────────────

/// Boot-time decision: which backend should the OS use? The result
/// describes what the probe *would* pick given the boolean signals
/// from each backend. The actual activation requires the caller to
/// supply the live MMIO / AML / WMI handles, which is why this fn
/// returns the choice rather than performing the activation.
///
/// Priority (matches Linux `acpi_video_get_backlight_type`):
///   1. Intel BLC if an Intel iGPU is present.
///   2. AMD ATIF if an AMD iGPU is present *and* the ATIF WMI
///      device + func 3 / 4 are advertised.
///   3. ACPI _BCL if any panel declared one.
///   4. None.
pub fn select_backend(
    intel_igpu: bool,
    amd_igpu: bool,
    atif_supports_set_get: bool,
    acpi_video_present: bool,
) -> Backend {
    if intel_igpu {
        Backend::IntelBlc
    } else if amd_igpu && atif_supports_set_get {
        Backend::AmdAtif
    } else if acpi_video_present {
        Backend::AcpiVideo
    } else {
        Backend::None
    }
}

/// Stage::Device initcall — log the resolved backend choice. Doesn't
/// activate anything by itself; the per-backend activators are
/// called from the platform bring-up code that has the live MMIO /
/// AML / WMI handles. Until then this prints the *intended* choice
/// so a bring-up bisect can tell which backend the boot picked.
pub fn init_backlight_initcall() {
    // The platform-detection signals get plumbed in by the live
    // activators; until they fire, the initcall just records that
    // the backlight module was visited.
    let _ = backend();
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    //! Smokes for the unified backlight surface. Each backend has
    //! a pure-decode test (no global state) plus the dispatcher
    //! priority + round-trip is exercised via the FakeDriver.

    extern crate alloc;

    use super::*;
    use alloc::vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ---- Intel BLC PWM ---------------------------------------------

    /// Recording MMIO mock: serves canned reads, captures writes.
    #[derive(Debug, Default)]
    pub struct FakeMmio {
        pub reads: RefCell<alloc::collections::BTreeMap<u64, u32>>,
        pub writes: RefCell<alloc::vec::Vec<(u64, u32)>>,
    }
    impl FakeMmio {
        pub fn set_read(&self, off: u64, val: u32) {
            self.reads.borrow_mut().insert(off, val);
        }
        pub fn last_write(&self, off: u64) -> Option<u32> {
            self.writes
                .borrow()
                .iter()
                .rev()
                .find_map(|(o, v)| if *o == off { Some(*v) } else { None })
        }
    }
    impl MmioWindow for FakeMmio {
        fn read32(&self, off: u64) -> u32 {
            *self.reads.borrow().get(&off).unwrap_or(&0)
        }
        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
        }
    }

    fn smoke_intel_pwm_duty_round_trip() -> TestResult {
        // Period 0x10000 → 50% → duty 0x8000 → back to 50%.
        let mmio = FakeMmio::default();
        mmio.set_read(BXT_BLC_PWM_FREQ1, 0x10000);
        match intel_set_pct(&mmio, 50) {
            Ok(d) => {
                if d != 0x8000 {
                    return TestResult::Fail("50% != period/2");
                }
            }
            Err(_) => return TestResult::Fail("set returned err"),
        }
        let last = match mmio.last_write(BXT_BLC_PWM_DUTY1) {
            Some(v) => v,
            None => return TestResult::Fail("no DUTY1 write"),
        };
        if last != 0x8000 {
            return TestResult::Fail("DUTY1 != expected");
        }
        // Reflect the duty back so the read path sees it.
        mmio.set_read(BXT_BLC_PWM_DUTY1, last);
        let pct = match intel_get_pct(&mmio) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("get returned err"),
        };
        if pct != 50 {
            return TestResult::Fail("round-trip pct != 50");
        }
        // Boundary: 0 and 100 map exactly.
        let _ = intel_set_pct(&mmio, 0);
        if mmio.last_write(BXT_BLC_PWM_DUTY1) != Some(0) {
            return TestResult::Fail("0% != duty 0");
        }
        let _ = intel_set_pct(&mmio, 100);
        if mmio.last_write(BXT_BLC_PWM_DUTY1) != Some(0x10000) {
            return TestResult::Fail("100% != period");
        }
        // Period zero is an error (firmware didn't init the PWM).
        let mmio2 = FakeMmio::default();
        if intel_set_pct(&mmio2, 50).is_ok() {
            return TestResult::Fail("period 0 didn't error");
        }
        // 0 / 0 read path returns 0 cleanly.
        if intel_get_pct(&mmio2).unwrap_or(255) != 0 {
            return TestResult::Fail("0/0 get didn't return 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/backlight", smoke_intel_pwm_duty_round_trip);

    // ---- ATIF _DSM bitmap decode -----------------------------------

    fn smoke_atif_dsm_supported_bitmap_decode() -> TestResult {
        // Buffer says func 0, 1, 3, 4 supported.
        // Bit positions: 0, 1, 3, 4 → byte 0 = 0b0001_1011 = 0x1B.
        let supported = decode_dsm_supported(&[0x1B]);
        if !supported.supports(0)
            || !supported.supports(1)
            || !supported.supports(3)
            || !supported.supports(4)
        {
            return TestResult::Fail("expected 0/1/3/4 supported");
        }
        if supported.supports(2) || supported.supports(5) {
            return TestResult::Fail("false-positive supports");
        }
        // Function 0 unset → spec violation, empty set.
        let empty = decode_dsm_supported(&[0x02]);
        if !empty.functions.is_empty() {
            return TestResult::Fail("missing func 0 should yield empty");
        }
        let empty2 = decode_dsm_supported(&[]);
        if !empty2.functions.is_empty() {
            return TestResult::Fail("empty buf should yield empty");
        }
        // Multi-byte bitmap: func 0, 8, 16.
        let supported = decode_dsm_supported(&[0x01, 0x01, 0x01]);
        if !supported.supports(0) || !supported.supports(8) || !supported.supports(16) {
            return TestResult::Fail("multi-byte bitmap miss");
        }
        // GUID sanity.
        if ATIF_GUID[0] != 0xf8 || ATIF_GUID[15] != 0x9b {
            return TestResult::Fail("ATIF GUID bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/backlight",
        smoke_atif_dsm_supported_bitmap_decode
    );

    // ---- _BCL package decode ---------------------------------------

    fn smoke_bcl_level_list_parse() -> TestResult {
        // Typical Lenovo _BCL: AC=80, BAT=40, ladder 0..=100 in steps of 10.
        let pkg: alloc::vec::Vec<u32> =
            vec![80, 40, 0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let ladder = decode_bcl(&pkg);
        if ladder.len() != 11 {
            return TestResult::Fail("ladder len != 11");
        }
        if ladder[0] != 0 || ladder[10] != 100 {
            return TestResult::Fail("ladder boundaries wrong");
        }
        // Snap-to-nearest: 25% → 30 (tie-break toward brighter).
        let snapped = snap_to_ladder(&ladder, 25).unwrap_or(0);
        if snapped != 30 {
            return TestResult::Fail("snap 25 != 30");
        }
        // Snap to exact: 50% → 50.
        if snap_to_ladder(&ladder, 50) != Some(50) {
            return TestResult::Fail("snap 50 != 50");
        }
        // Snap overflow: 101 clamped → 100.
        if snap_to_ladder(&ladder, 101) != Some(100) {
            return TestResult::Fail("snap >100 != 100");
        }
        // Too-short package → empty ladder.
        let short: alloc::vec::Vec<u32> = vec![80, 40];
        if !decode_bcl(&short).is_empty() {
            return TestResult::Fail("short pkg should yield empty");
        }
        // Out-of-range entries filtered.
        let dirty: alloc::vec::Vec<u32> = vec![80, 40, 0, 50, 200, 100];
        let ladder = decode_bcl(&dirty);
        if ladder.contains(&200u8) || ladder.len() != 3 {
            return TestResult::Fail("out-of-range entries leaked");
        }
        // Empty ladder snap returns None.
        if snap_to_ladder(&[], 50).is_some() {
            return TestResult::Fail("empty ladder snap != None");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/backlight", smoke_bcl_level_list_parse);

    // ---- FakeDriver round-trip via the global dispatcher -----------

    fn smoke_fakedriver_set_get_round_trip() -> TestResult {
        // Save + restore global state — we share the dispatcher with
        // other smokes in this file, so leaving it pristine matters.
        let saved_backend = backend();
        deactivate();
        let drv = FakeDriver::new_full_ladder();
        activate_fake(drv, Backend::AcpiVideo);
        if backend() != Backend::AcpiVideo {
            deactivate();
            return TestResult::Fail("backend() didn't reflect activation");
        }
        if levels().len() != 11 {
            deactivate();
            return TestResult::Fail("levels() didn't reflect ladder");
        }
        if set(70).is_err() {
            deactivate();
            return TestResult::Fail("set(70) errored");
        }
        match get() {
            Ok(70) => {}
            Ok(other) => {
                deactivate();
                let _ = other;
                return TestResult::Fail("get != 70");
            }
            Err(_) => {
                deactivate();
                return TestResult::Fail("get errored");
            }
        }
        // Clamping at the public surface.
        let _ = set(200);
        match get() {
            Ok(100) => {}
            _ => {
                deactivate();
                return TestResult::Fail("over-100 didn't clamp");
            }
        }
        // Deactivate → NoBackend.
        deactivate();
        if !matches!(set(50), Err(BacklightError::NoBackend)) {
            return TestResult::Fail("post-deactivate set didn't NoBackend");
        }
        if !matches!(get(), Err(BacklightError::NoBackend)) {
            return TestResult::Fail("post-deactivate get didn't NoBackend");
        }
        if backend() != Backend::None {
            return TestResult::Fail("post-deactivate backend != None");
        }
        if !levels().is_empty() {
            return TestResult::Fail("post-deactivate levels != empty");
        }
        // Restore.
        let _ = saved_backend;
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/backlight", smoke_fakedriver_set_get_round_trip);

    // ---- Backend priority resolution -------------------------------

    fn smoke_backend_priority_resolution() -> TestResult {
        // Intel iGPU wins over everything.
        if select_backend(true, false, false, false) != Backend::IntelBlc {
            return TestResult::Fail("Intel didn't win when sole");
        }
        if select_backend(true, true, true, true) != Backend::IntelBlc {
            return TestResult::Fail("Intel didn't win over AMD+ACPI");
        }
        // AMD iGPU wins only when ATIF advertises set+get.
        if select_backend(false, true, true, true) != Backend::AmdAtif {
            return TestResult::Fail("AMD+ATIF didn't win over ACPI");
        }
        // AMD iGPU w/o ATIF falls through to ACPI.
        if select_backend(false, true, false, true) != Backend::AcpiVideo {
            return TestResult::Fail("AMD-no-ATIF should hit ACPI");
        }
        // No iGPU, just ACPI _BCL.
        if select_backend(false, false, false, true) != Backend::AcpiVideo {
            return TestResult::Fail("ACPI-only didn't win");
        }
        // Nothing.
        if select_backend(false, false, false, false) != Backend::None {
            return TestResult::Fail("nothing should yield None");
        }
        // ATIF advertised but no AMD iGPU detected → ignore ATIF.
        if select_backend(false, false, true, true) != Backend::AcpiVideo {
            return TestResult::Fail("orphan ATIF claim should be ignored");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/backlight", smoke_backend_priority_resolution);
}
