//! ACPI fan control.
//!
//! Two parallel surfaces exist:
//!
//! - **`_FST` / `_FSL`** (ACPI 6.5 §11.3) — control-method fans
//!   on D-states *and* with explicit speed control. `_FST`
//!   returns a Package `(revision, control, speed)` where
//!   `control` is the current set-point in tenths of a percent
//!   and `speed` is the observed RPM. `_FSL(level)` sets a new
//!   level. Standardised; the host doesn't need vendor quirks.
//!
//! - **Legacy `_PSx` D-state fans** (ACPI 6.5 §11.4) — older
//!   thermal-zone fans that only support on/off via D0/D3
//!   transitions. Speed levels come from `_PSL` (Passive Speed
//!   List) and `_TSP` (Thermal Sample Period). These are common
//!   on pre-2015 laptops.
//!
//! This module ships pure decoders + a `Fan` trait the host
//! implements per chip. Vendor-specific EC fan offsets (Dell,
//! ThinkPad, Asus, etc.) are handled by laptop-specific drivers
//! that consume this trait.
//!
//! Reference: ACPI 6.5 §11 (Thermal Management).

extern crate alloc;

use alloc::vec::Vec;

// ── _FST decoder ──────────────────────────────────────────────────

/// Decoded `_FST` Package contents (control-method fan info).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FanStatus {
    /// Revision — currently always 0 per ACPI 6.5.
    pub revision: u32,
    /// Current control set-point in *tenths of a percent*
    /// (0..=1000). E.g. 500 = 50.0 % of the fan's max output.
    pub control: u32,
    /// Observed fan speed in RPM. 0xFFFFFFFF = "not measured".
    pub speed_rpm: u32,
}

impl FanStatus {
    /// Convert the control field to whole percent (rounding down).
    pub fn control_percent(&self) -> u32 {
        self.control / 10
    }
    /// True iff the fan reports an RPM reading (vs 0xFFFFFFFF unknown).
    pub fn has_tachometer(&self) -> bool {
        self.speed_rpm != 0xFFFF_FFFF
    }
}

/// Errors decoding `_FST` packages.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FanDecodeError {
    /// `_FST` returned fewer than 3 elements.
    WrongElementCount,
    /// `control` field exceeds 1000 (>100.0 %).
    ControlOutOfRange(u32),
}

/// Decode a `_FST` Package — `values[0]` = revision,
/// `[1]` = control, `[2]` = speed_rpm.
pub fn decode_fst(values: &[u32]) -> Result<FanStatus, FanDecodeError> {
    if values.len() < 3 {
        return Err(FanDecodeError::WrongElementCount);
    }
    if values[1] > 1000 {
        return Err(FanDecodeError::ControlOutOfRange(values[1]));
    }
    Ok(FanStatus {
        revision: values[0],
        control: values[1],
        speed_rpm: values[2],
    })
}

// ── _FIF decoder ──────────────────────────────────────────────────

/// Decoded `_FIF` Package contents (fine-grained fan info).
///
/// `_FIF` is an ACPI 6.5 §11.3 extension that advertises whether
/// a fan supports fine-grained speed control and how many discrete
/// levels it offers. Not all firmware exposes `_FIF`; its absence
/// means the fan only supports on/off via D-state transitions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FanInfo {
    /// Revision — 0 per ACPI 6.5.
    pub revision: u32,
    /// True when the fan supports fine-grained speed control
    /// (i.e. `_FSL` takes any value in 0..=1000). False when
    /// only coarse-level (`speed_levels` discrete steps) is available.
    pub fine_grained_control: bool,
    /// Step size in tenths of a percent. Meaningful only when
    /// `fine_grained_control == false`. E.g. step_size=100 means
    /// the fan has 10 speed levels in 10% increments.
    pub step_size: u32,
    /// Number of discrete speed levels. If `fine_grained_control` is
    /// true the firmware may report 0 here.
    pub speed_levels: u32,
}

/// Errors decoding `_FIF` packages.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FifDecodeError {
    /// `_FIF` returned fewer than 4 elements.
    WrongElementCount,
}

/// Decode a `_FIF` Package — `values[0]` = revision,
/// `[1]` = fine_grained_control (0 or 1),
/// `[2]` = step_size (tenths of %), `[3]` = speed_levels.
pub fn decode_fif(values: &[u32]) -> Result<FanInfo, FifDecodeError> {
    if values.len() < 4 {
        return Err(FifDecodeError::WrongElementCount);
    }
    Ok(FanInfo {
        revision: values[0],
        fine_grained_control: values[1] != 0,
        step_size: values[2],
        speed_levels: values[3],
    })
}

// ── _FSL encoder ──────────────────────────────────────────────────

/// Encode a fan control level for `_FSL(level)`. The ACPI spec
/// defines the argument in tenths of a percent (0..=1000). Values
/// above 1000 are clamped to 1000 (100 %).
///
/// `_FSL` never fails — it either writes the level or the EC ignores
/// the over-range value. Clamping here matches Linux `acpi_fan_set_level`.
#[inline]
pub fn encode_fsl(control: u32) -> u32 {
    control.min(1000)
}

/// Validate the control argument before encoding. Returns the
/// (possibly clamped) value and an optional error indicating clamping
/// occurred. Useful for drivers that want to surface the warning
/// without refusing the call.
pub fn encode_fsl_validated(control: u32) -> (u32, Option<FslError>) {
    if control > 1000 {
        (1000, Some(FslError::Clamped(control)))
    } else {
        (control, None)
    }
}

/// Soft error from [`encode_fsl_validated`] — not fatal, just
/// diagnostic.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FslError {
    /// The requested level was above 1000 and has been clamped to 1000.
    Clamped(u32),
}

// ── Fan trait ──────────────────────────────────────────────────────

/// One physical fan on the platform. Implementations live in
/// chip-specific driver crates (k10temp's amd_fch, ThinkPad ec,
/// Dell SMBIOS, etc.) and register against [`register_fan`].
pub trait Fan: Send + Sync {
    /// Human-readable name for logs / status bar (e.g. "cpu_fan",
    /// "gpu_fan"). Caller's responsibility to keep stable across
    /// suspend/resume.
    fn name(&self) -> &'static str;

    /// Read the current status (set-point + RPM if measured).
    fn status(&self) -> Result<FanStatus, FanRuntimeError>;

    /// Set the fan to `control` (in tenths of a percent, 0-1000).
    /// Some fans only accept discrete levels (`_PSL` list); the
    /// implementation rounds to the nearest supported level.
    /// Returns the actual level programmed.
    fn set_control(&self, control: u32) -> Result<u32, FanRuntimeError>;
}

/// Errors from a `Fan` implementation at runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FanRuntimeError {
    /// Underlying EC / MMIO / AML call failed.
    AccessFailed,
    /// Hardware reported an inconsistent state (e.g. control set
    /// but tachometer reads 0 RPM for several seconds — fan
    /// stalled or wire disconnected).
    Stalled,
    /// `set_control` got an out-of-range argument.
    OutOfRange,
}

// ── Registry ───────────────────────────────────────────────────────

use alloc::sync::Arc;
use narf_lib::sync::IrqSafeSpinLock;

/// Globally-registered fans. Power / thermal subsystems iterate
/// this list to find every fan on the system.
static FANS: IrqSafeSpinLock<Vec<Arc<dyn Fan>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a `Fan` implementation against the global registry.
/// Idempotent on `name` — re-registering replaces the prior entry.
pub fn register_fan(fan: Arc<dyn Fan>) {
    let mut g = FANS.lock();
    let name = fan.name();
    if let Some(slot) = g.iter_mut().find(|f| f.name() == name) {
        *slot = fan;
    } else {
        g.push(fan);
    }
}

/// Iterate all registered fans (snapshot — safe to call status
/// on each without holding the registry lock).
pub fn registered_fans() -> Vec<Arc<dyn Fan>> {
    FANS.lock().clone()
}

/// Number of registered fans (debug / status helper).
pub fn fan_count() -> usize {
    FANS.lock().len()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FANS.lock().clear();
}
