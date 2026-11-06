//! Cooling-device drivers — ACPI Fan + PWM Fan.
//!
//! Spec: ACPI 6.5 §11.3 (Fan Device, _HID `PNP0C0B`).
//!   <https://uefi.org/specs/ACPI/>
//!
//! Two driver shapes live here:
//!
//! - [`AcpiFan`] — discovered by walking the AML namespace for devices
//!   whose `_HID` is `PNP0C0B`, in either the string or the EISAID
//!   integer form. Driven through `_ON` / `_OFF` for binary fans and
//!   `_FSL(level)` for speed control, with the level ladder taken
//!   from the decoded `_FPS` state table and `_FIF` decoded for
//!   real (FineGrainControl / StepSize), per ACPI 6.5 §11.3.1.
//! - [`PwmFan`] — board-described fan wired to a generic PWM controller.
//!   Used when the platform exposes the fan via DT/PWM rather than
//!   ACPI (e.g. embedded SBC laptops).
//!
//! Both implement [`narf_power::thermal::CoolingDevice`] so the active-
//! cooling governor in `power/` can drive them uniformly.
//!
//! The vendor laptop fan controls are wrapped the same way
//! (#911): [`ThinkpadFan`] drives `thinkpad_acpi::set_fan_level`
//! (`\HFNF`) and [`AsusFan`] drives `asus_wmi::set_fan_boost_mode`
//! (`DEVID_FAN_BOOST`). Each wrapper maps the governor's 0..=255
//! level onto the vendor driver's own discrete ladder.
//!
//! `PwmFan` is constructed from its board description: a DT
//! `pwm-fan` node (`compatible = "pwm-fan"`, `pwms = <&pwm
//! channel period_ns [flags]>`, optional `cooling-levels` ladder;
//! Linux `Documentation/devicetree/bindings/hwmon/pwm-fan.yaml`)
//! is claimed through the bus DT-match registry
//! ([`register_dt_driver`]) and its `pwms` phandle resolves to a
//! `PwmDevice` through the `narf_pwm` controller registry, which
//! PWM controller drivers populate as they land. No production
//! PWM controller driver exists yet, so on real hardware the probe
//! defers until one registers — the fan construction itself is
//! wired and fixture-validated end to end.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::eval::{evaluate_method, evaluate_object};
use narf_aml::{device_hid, for_each_node_of_kind, NodeKind, Value};
use narf_bus::ProbeError;
use narf_power::bootstrap_thermal_authority;
use narf_power::thermal::{register_cooling_device, CoolingDevice, ThermalError};
use narf_pwm::{Polarity, PwmConfig, PwmDevice};

// ── ACPI Fan (_HID = PNP0C0B) ───────────────────────────────────────

/// The `_HID` every ACPI fan device carries (ACPI 6.5 §11.3).
const FAN_HID: &str = "PNP0C0B";

/// Decoded `_FIF` fan information (ACPI 6.5 §11.3.1.1, Table 11.2:
/// `Package { Revision, FineGrainControl, StepSize,
/// LowSpeedNotificationSupport }`, all Integers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FanInfo {
    /// Structure revision (the spec's current revision is 0; the
    /// fields below are decoded positionally regardless, so a future
    /// revision with appended fields still parses).
    // Decoded for the record; no consumer yet.
    #[allow(dead_code)]
    revision: u64,
    /// `FineGrainControl != 0`: `_FSL` may be evaluated with any
    /// Level in 0..=100, a percentage of maximum speed. When zero,
    /// `_FSL` may only be evaluated with a Control field value from
    /// a `_FPS` state package.
    fine_grained: bool,
    /// Recommended minimum step size, in percentage points, for
    /// fine-grained control (spec: between 1 and 9 when
    /// `fine_grained`). Zero when the platform declares none.
    step_size: u64,
    /// `LowSpeedNotificationSupport != 0`: the platform issues
    /// Notify(0x80) to the fan device when it detects a low
    /// (errant) fan speed.
    // Decoded for the record; the Notify handler is future work.
    #[allow(dead_code)]
    low_speed_notify: bool,
}

/// Decode an evaluated `_FIF` value. `None` when the value is not a
/// Package holding at least the four spec fields.
fn decode_fif(value: &Value) -> Option<FanInfo> {
    let pkg = match value {
        Value::Package(p) => p,
        _ => return None,
    };
    if pkg.len() < 4 {
        return None;
    }
    Some(FanInfo {
        revision: pkg[0].as_integer(),
        fine_grained: pkg[1].as_integer() != 0,
        step_size: pkg[2].as_integer(),
        low_speed_notify: pkg[3].as_integer() != 0,
    })
}

/// One decoded `_FPS` performance state (ACPI 6.5 §11.3.1.2,
/// Table 11.3: `Package { Control, TripPoint, Speed, NoiseLevel,
/// Power }`, all Integer DWORDs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FanPState {
    /// The value `_FSL` takes to select this state: a percentage
    /// (0..=100) of maximum speed when the fan supports fine-grained
    /// control, an opaque token otherwise. Passed through verbatim
    /// either way (§11.3.1.3).
    control: u64,
    /// The active cooling trip point this state corresponds to
    /// (0..=9), or 0xFFFFFFFF when it corresponds to none. The four
    /// fields below are the spec record for the state; `control`
    /// drives `_FSL` today, the rest are decoded for the thermal
    /// layer's future policy use.
    #[allow(dead_code)]
    trip_point: u64,
    /// Fan speed in RPM in this state.
    #[allow(dead_code)]
    speed_rpm: u64,
    /// Audible noise in tenths of a decibel, or 0xFFFFFFFF when the
    /// field is not populated.
    #[allow(dead_code)]
    noise_deci_db: u64,
    /// Power consumption in milliwatts, or 0xFFFFFFFF when the
    /// field is not populated.
    #[allow(dead_code)]
    power_mw: u64,
}

/// Decode an evaluated `_FPS` value into the state table. The
/// package is `{ Revision, FanPState[0], ... }` (§11.3.1.2) —
/// element 0 is the revision, every following element one state.
/// Entries that are not Packages of at least the five spec fields
/// are skipped rather than failing the whole table: a partially
/// malformed table still yields its well-formed states.
fn decode_fps(value: &Value) -> Option<Vec<FanPState>> {
    let pkg = match value {
        Value::Package(p) => p,
        _ => return None,
    };
    let mut states = Vec::new();
    for entry in pkg.iter().skip(1) {
        let fields = match entry {
            Value::Package(f) => f,
            _ => continue,
        };
        if fields.len() < 5 {
            continue;
        }
        states.push(FanPState {
            control: fields[0].as_integer(),
            trip_point: fields[1].as_integer(),
            speed_rpm: fields[2].as_integer(),
            noise_deci_db: fields[3].as_integer(),
            power_mw: fields[4].as_integer(),
        });
    }
    Some(states)
}

/// Whether the AML device at `path` is an ACPI fan: its `_HID`
/// normalises to `PNP0C0B`. `device_hid` decodes both shapes
/// firmware emits — the string form and the EISAID integer form
/// (`EisaId("PNP0C0B")` compiles to the DWORD 0x0B0CD041; ACPI 6.5
/// §5.6.7 encoding). The previous string-only match silently
/// skipped every fan whose firmware used the integer form.
fn is_fan_device(path: &str) -> bool {
    device_hid(path).as_deref() == Some(FAN_HID)
}

/// ACPI Fan device. Drives `_ON` / `_OFF` for binary fans; when the
/// firmware declares `_FSL` control — a `_FPS` state table and/or
/// `_FIF` fine-grained percentages — also calls `_FSL(level)` to
/// pick a speed.
#[derive(Debug)]
pub struct AcpiFan {
    path: String,
    /// Decoded `_FIF`, when the firmware provides a well-formed one.
    info: Option<FanInfo>,
    /// Decoded `_FPS` state table — the fan's level ladder, exactly
    /// as the firmware declared it. Empty when the firmware declares
    /// no performance states.
    states: Vec<FanPState>,
    /// Cached on/off state so we don't issue redundant `_ON`/`_OFF`
    /// transitions every poll cycle.
    on: AtomicBool,
    /// Last applied level (0..=255) — used by `level()` for telemetry.
    last_level: AtomicU8,
}

impl AcpiFan {
    fn probe(path: &str) -> Self {
        // _FIF / _FPS are data objects: most DSDTs declare them as
        // `Name(Package(...))`, some as zero-argument Methods
        // returning a Package. `evaluate_object` covers both shapes;
        // `evaluate_method` alone rejects the Name shape — which is
        // why the previous probe could only treat `_FIF` as a
        // boolean and had to invent a 10-step ladder for `_FPS`.
        let info = evaluate_object(&format!("{}._FIF", path), &[])
            .ok()
            .and_then(|v| decode_fif(&v));
        let states = evaluate_object(&format!("{}._FPS", path), &[])
            .ok()
            .and_then(|v| decode_fps(&v))
            .unwrap_or_default();
        Self {
            path: String::from(path),
            info,
            states,
            on: AtomicBool::new(false),
            last_level: AtomicU8::new(0),
        }
    }

    /// Whether `_FIF` declares fine-grained (percentage) control.
    fn fine_grained(&self) -> bool {
        self.info.map(|i| i.fine_grained).unwrap_or(false)
    }

    fn call(&self, method: &str) {
        let _ = evaluate_method(&format!("{}.{}", self.path, method), &[]);
    }

    fn call_with(&self, method: &str, arg: u64) {
        let _ = evaluate_method(&format!("{}.{}", self.path, method), &[Value::Integer(arg)]);
    }
}

impl CoolingDevice for AcpiFan {
    fn name(&self) -> &'static str {
        // `CoolingDevice::name` is &'static for cheap identification;
        // ACPI paths are dynamic, so report a stable role-name and let
        // the dynamic path land in `Debug`.
        "acpi-fan"
    }

    fn set_level(&self, level: u8) {
        self.last_level.store(level, Ordering::Relaxed);
        let want_on = level > 0;
        let was_on = self.on.swap(want_on, Ordering::AcqRel);
        if want_on != was_on {
            self.call(if want_on { "_ON" } else { "_OFF" });
        }
        if !want_on {
            return;
        }
        if !self.states.is_empty() {
            // The ladder is the firmware's own state table: map
            // 0..=255 onto 1..=states.len() and pass the selected
            // state's Control value to `_FSL` verbatim (ACPI 6.5
            // §11.3.1.3 — a percentage when fine-grained, an opaque
            // token the OSPM passes through when not).
            let span = self.states.len() as u64;
            let idx = (level as u64 * span).div_ceil(255).clamp(1, span);
            self.call_with("_FSL", self.states[(idx - 1) as usize].control);
        } else if self.fine_grained() {
            // No `_FPS` table: fine-grained control takes a raw
            // percentage (0..=100). Round up to the platform's
            // recommended step size (§11.3.1.1) when it declares a
            // valid one, so quantisation never rounds a cooling
            // request down; the final step may land short of the
            // multiple to reach exactly 100.
            let mut pct = (level as u64 * 100).div_ceil(255).clamp(1, 100);
            let step = self.info.map(|i| i.step_size).unwrap_or(0);
            if (1..=9).contains(&step) {
                pct = pct.div_ceil(step) * step;
                if pct > 100 {
                    pct = 100;
                }
            }
            self.call_with("_FSL", pct);
        }
        // Otherwise the fan is binary: `_ON` above is the whole
        // control surface the firmware declared.
    }

    fn reset_cached_power(&self) {
        // Firmware may have powered the fan off across S3 while
        // this cache still says on (#1223). Drop the cache so
        // the next `set_level > 0` re-issues `_ON`; worst case
        // on firmware that kept the fan on is one redundant `_ON`.
        self.on.store(false, Ordering::Release);
    }
}

/// Walk the AML namespace, find devices with `_HID == "PNP0C0B"`, and
/// register each as a cooling device.
///
/// The boot log must report the REAL state (#907): "no fans
/// discovered" is printed only when discovery genuinely found none.
/// A discovered fan whose registration fails is logged per-device
/// with its error — previously every failure was swallowed and the
/// log claimed the machine had no fans.
pub fn init() {
    let cap = bootstrap_thermal_authority();
    let mut discovered: u32 = 0;
    let mut registered: u32 = 0;

    for_each_node_of_kind(NodeKind::Device, |node| {
        if !is_fan_device(&node.path) {
            return;
        }
        discovered += 1;

        let fan = Arc::new(AcpiFan::probe(&node.path));
        let label = fan.path.clone();
        let fine = fan.fine_grained();
        let n_states = fan.states.len();
        match register_cooling_device(&cap, fan) {
            Ok(()) => {
                registered += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "  acpi-fan: registered {} (fine-grained={}, fps-states={})",
                    label,
                    fine,
                    n_states
                );
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  acpi-fan: {} discovered but cooling-device registration failed: {:?}",
                    label,
                    e
                );
            }
        }
    });

    if discovered == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-fan: no PNP0C0B fans discovered"
        );
    } else if registered == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-fan: {} PNP0C0B fan(s) discovered, none registered (see failures above)",
            discovered
        );
    }
}

// ── ThinkPad vendor fan ───────────────────────────────────────────

/// Map a governor cooling level (0..=255) onto the ThinkPad fan
/// ladder — the vendor driver's own levels
/// (`thinkpad_acpi::FanLevel`).
///
/// Level 0 is "no active-cooling demand": `\HFNF` has no fan-off
/// setting — its 0 is firmware auto control — so 0 hands the fan
/// back to the firmware. Non-zero levels scale onto the eight
/// explicit states L1..=L7 + FullSpeed.
#[cfg(target_arch = "x86_64")]
pub fn thinkpad_level_for(level: u8) -> crate::thinkpad_acpi::FanLevel {
    use crate::thinkpad_acpi::FanLevel;
    if level == 0 {
        return FanLevel::Auto;
    }
    match (level as u64 * 8).div_ceil(255) {
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

/// ThinkPad EC fan as a [`CoolingDevice`], driving
/// `thinkpad_acpi::set_fan_level` (the `\HFNF` AML write).
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
pub struct ThinkpadFan {
    /// Last applied vendor level (`FanLevel as u32`); `u32::MAX`
    /// until the first `set_level`, so the first call always writes.
    last: AtomicU32,
}

#[cfg(target_arch = "x86_64")]
impl ThinkpadFan {
    pub fn new() -> Self {
        Self {
            last: AtomicU32::new(u32::MAX),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Default for ThinkpadFan {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86_64")]
impl CoolingDevice for ThinkpadFan {
    fn name(&self) -> &'static str {
        "thinkpad-fan"
    }

    fn set_level(&self, level: u8) {
        let want = thinkpad_level_for(level);
        // Coalesce: the governor re-asserts levels on every thermal
        // crossing, and each change is an AML evaluation — only
        // write when the vendor level actually changes.
        if self.last.swap(want as u32, Ordering::AcqRel) != want as u32 {
            crate::thinkpad_acpi::set_fan_level(want);
        }
    }
}

/// Register the ThinkPad fan as a cooling device. Called from
/// `thinkpad_acpi::init()` once an HKEY device has been found —
/// the fan lives behind the same EC surface. Registration failure
/// is logged, never swallowed silently (the #907 rule fan::init
/// follows for ACPI fans).
#[cfg(target_arch = "x86_64")]
pub fn register_thinkpad_fan() {
    let cap = bootstrap_thermal_authority();
    match register_cooling_device(&cap, Arc::new(ThinkpadFan::new())) {
        Ok(()) => {
            let _ = writeln!(
                narf_console::Writer,
                "  thinkpad-fan: registered as cooling device"
            );
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  thinkpad-fan: cooling-device registration failed: {:?}",
                e
            );
        }
    }
}

// ── ASUS vendor fan ───────────────────────────────────────────────

/// Map a governor cooling level (0..=255) onto the ASUS fan boost
/// ladder — the vendor driver's own modes
/// (`asus_wmi::FanBoostMode`).
///
/// Level 0 is "no active-cooling demand" → Silent. The remaining
/// range splits between Normal and Overboost at 2/3, so the
/// governor's three StepPolicy outputs (0 / 128 / 255) land on
/// Silent / Normal / Overboost respectively.
#[cfg(target_arch = "x86_64")]
pub fn asus_mode_for(level: u8) -> crate::asus_wmi::FanBoostMode {
    use crate::asus_wmi::FanBoostMode;
    match level {
        0 => FanBoostMode::Silent,
        1..=170 => FanBoostMode::Normal,
        _ => FanBoostMode::Overboost,
    }
}

/// ASUS fan boost mode as a [`CoolingDevice`], driving
/// `asus_wmi::set_fan_boost_mode` (the `DEVID_FAN_BOOST` WMI
/// devstate write).
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
pub struct AsusFan {
    /// Last applied vendor mode (`FanBoostMode as u32`); `u32::MAX`
    /// until the first `set_level`, so the first call always writes.
    last: AtomicU32,
}

#[cfg(target_arch = "x86_64")]
impl AsusFan {
    pub fn new() -> Self {
        Self {
            last: AtomicU32::new(u32::MAX),
        }
    }
}

#[cfg(target_arch = "x86_64")]
impl Default for AsusFan {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86_64")]
impl CoolingDevice for AsusFan {
    fn name(&self) -> &'static str {
        "asus-fan"
    }

    fn set_level(&self, level: u8) {
        let want = asus_mode_for(level);
        // Coalesce, as in ThinkpadFan::set_level — each change is a
        // WMI method invocation.
        if self.last.swap(want as u32, Ordering::AcqRel) != want as u32 {
            crate::asus_wmi::set_fan_boost_mode(want);
        }
    }
}

/// Register the ASUS fan as a cooling device. Called from
/// `asus_wmi::init()` when the ASUS WMI GUID is present (the
/// driver's probe). Registration failure is logged, never
/// swallowed silently.
#[cfg(target_arch = "x86_64")]
pub fn register_asus_fan() {
    let cap = bootstrap_thermal_authority();
    match register_cooling_device(&cap, Arc::new(AsusFan::new())) {
        Ok(()) => {
            let _ = writeln!(
                narf_console::Writer,
                "  asus-fan: registered as cooling device"
            );
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  asus-fan: cooling-device registration failed: {:?}",
                e
            );
        }
    }
}

// ── PWM Fan ─────────────────────────────────────────────────────────

/// Board description of a PWM fan, decoded from its Devicetree
/// `pwm-fan` node (Linux
/// `Documentation/devicetree/bindings/hwmon/pwm-fan.yaml`:
/// `compatible = "pwm-fan"`, `pwms` required, `cooling-levels`
/// optional with each entry ≤ 255, `#cooling-cells = <2>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwmFanDesc {
    /// Phandle of the PWM controller node the fan's `pwms`
    /// specifier points at. Used to resolve the `PwmDevice` from
    /// the controller registry; not a fan property itself.
    pub controller: u32,
    /// Channel index within the controller (`pwms` cell 1).
    pub channel: u32,
    /// PWM period in nanoseconds (`pwms` cell 2). The worker
    /// derives the frequency from this, so a board that declares
    /// a non-25 kHz period gets its own period.
    pub period_ns: u64,
    /// Output polarity (`pwms` flags cell bit 0, when the
    /// controller declares `#pwm-cells = <3>`: 0 normal, 1
    /// inverted — `PWM_POLARITY_INVERTED` in
    /// `include/dt-bindings/pwm/pwm.h`).
    pub polarity: Polarity,
    /// `cooling-levels` ladder: PWM duty values (0..=255) per
    /// thermal cooling state, most to least heat dissipation.
    /// Empty = no ladder declared: the governor level maps
    /// linearly onto duty.
    pub cooling_levels: Vec<u8>,
}

impl PwmFanDesc {
    /// Description with no board data: the pre-DT default — the
    /// standard PC / Intel 4-wire fan 25 kHz period (40_000 ns),
    /// normal polarity, linear level→duty.
    pub fn linear(channel: u32) -> Self {
        Self {
            controller: 0,
            channel,
            period_ns: 40_000,
            polarity: Polarity::Normal,
            cooling_levels: Vec::new(),
        }
    }
}

/// Generic PWM-controlled fan. Used on platforms that expose the fan
/// via a PWM controller (DT-described boards, embedded SBC laptops).
pub struct PwmFan {
    name: &'static str,
    pwm: Arc<dyn PwmDevice>,
    channel: u32,
    /// PWM period in nanoseconds, from the board description
    /// (`PwmFanDesc::linear` supplies the 25 kHz default).
    period_ns: u64,
    /// Output polarity from the board description.
    polarity: Polarity,
    /// `cooling-levels` ladder, if the board declared one.
    /// Immutable after construction, so the worker takes a clone
    /// of this `Arc` instead of another raw pointer.
    cooling_levels: Arc<[u8]>,
    /// Coalesce target. set_level stores the latest requested
    /// level here; the worker reads + applies it. Pre-fix every
    /// set_level spawned a fresh task — a thermal loop oscillating
    /// at a few Hz could pile dozens of pending tasks into the
    /// scheduler queue (audit #5).
    target_level: core::sync::atomic::AtomicU8,
    /// `true` while a worker task is in flight. set_level only
    /// spawns a new worker when this is false; the running worker
    /// loops while target_level changes during its iteration so
    /// every level update gets applied without per-call spawn
    /// churn.
    worker_inflight: core::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for PwmFan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PwmFan")
            .field("name", &self.name)
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl PwmFan {
    pub fn new(name: &'static str, pwm: Arc<dyn PwmDevice>, channel: u32) -> Self {
        Self::from_description(name, pwm, PwmFanDesc::linear(channel))
    }

    /// Construct from a board description: the DT probe's path.
    /// A zero period is normalised to the 25 kHz default — a
    /// `PwmFan` must never divide by its own period.
    pub fn from_description(name: &'static str, pwm: Arc<dyn PwmDevice>, desc: PwmFanDesc) -> Self {
        Self {
            name,
            pwm,
            channel: desc.channel,
            period_ns: if desc.period_ns == 0 {
                40_000
            } else {
                desc.period_ns
            },
            polarity: desc.polarity,
            cooling_levels: Arc::from(desc.cooling_levels),
            target_level: core::sync::atomic::AtomicU8::new(0),
            worker_inflight: core::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl CoolingDevice for PwmFan {
    fn name(&self) -> &'static str {
        self.name
    }

    fn set_level(&self, level: u8) {
        use core::sync::atomic::Ordering;
        // Update the coalesced target. The in-flight worker (if
        // any) re-reads on each iteration so this update will be
        // applied without spawning a new task.
        self.target_level.store(level, Ordering::Release);
        // Try to claim the worker slot. If a worker is already
        // running, this returns Err and we just leave the target
        // for it to pick up.
        if self
            .worker_inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Spawn the single worker. It loops as long as the target
        // changes during one apply — flushes the latest value
        // before clearing the in-flight flag.
        let p = self.pwm.clone();
        let ch = self.channel;
        // Board timing is immutable after construction, so the
        // worker takes copies instead of more raw pointers.
        let period_ns = self.period_ns;
        let polarity = self.polarity;
        let levels = self.cooling_levels.clone();
        // SAFETY: target_level + worker_inflight are read by the
        // worker via raw pointer below. They live in `self` which
        // is held by an Arc kept alive by the fan registry; the
        // pointer outlives the worker as long as the registry
        // doesn't drop the fan, which only happens at shutdown.
        let target_ptr = (&self.target_level as *const core::sync::atomic::AtomicU8) as usize;
        let inflight_ptr =
            (&self.worker_inflight as *const core::sync::atomic::AtomicBool) as usize;
        narf_scheduler::spawn(async move {
            // SAFETY: pointers are to fields of an Arc-kept-alive
            // PwmFan; safe to dereference for the duration of
            // this task.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let target = unsafe { &*(target_ptr as *const core::sync::atomic::AtomicU8) };
            // SAFETY: inflight_ptr was formed from &self.worker_inflight above;
            // self is a PwmFan kept alive by an Arc in the fan registry for the
            // lifetime of this task, so the AtomicBool it points at is live and
            // properly aligned for the whole loop below.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let inflight = unsafe { &*(inflight_ptr as *const core::sync::atomic::AtomicBool) };
            loop {
                let lvl = target.load(Ordering::Acquire);
                // Board ladder first: `cooling-levels[i]` is the
                // PWM duty for cooling state `i`, so the governor
                // level picks its state by index; without a ladder
                // the level IS the duty (linear, as before).
                let duty_value: u64 = if levels.is_empty() {
                    lvl as u64
                } else {
                    let idx = (lvl as usize * (levels.len() - 1)) / 255;
                    levels[idx] as u64
                };
                let duty_ns = (period_ns * duty_value) / 255;
                let cfg = PwmConfig {
                    frequency_hz: (1_000_000_000u64 / period_ns) as u32,
                    duty_cycle_ns: duty_ns,
                    polarity,
                };
                let _ = p.set_config(ch, &cfg).await;
                if lvl > 0 {
                    let _ = p.enable(ch).await;
                } else {
                    let _ = p.disable(ch).await;
                }
                // If the target hasn't changed since we started
                // this iteration, release the slot. Re-checking
                // after the release would race with another
                // set_level — order is: drop slot, then re-check.
                // If the racer set the target between our load and
                // our store(false), they'll see worker_inflight =
                // true and skip; we re-acquire below and apply.
                inflight.store(false, Ordering::Release);
                let cur = target.load(Ordering::Acquire);
                if cur == lvl {
                    return;
                }
                // Target changed under us. Try to re-claim the
                // slot; if someone else got here first, they'll
                // apply the change.
                if inflight
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return;
                }
            }
        });
    }
}

/// Construct a [`PwmFan`] from its board description and register
/// it as a cooling device. Called by the DT probe
/// ([`dt_pwm_fan_probe`]) once the `pwms` phandle resolves to a
/// registered controller; direct callers pass
/// [`PwmFanDesc::linear`] for the pre-DT default. Returns the
/// registration outcome so the probe can leave the node unbound
/// (deferred probe) when registration fails. Registration failure
/// is logged, never swallowed silently.
pub fn register_pwm_fan(pwm: Arc<dyn PwmDevice>, desc: PwmFanDesc) -> Result<(), ThermalError> {
    let cap = bootstrap_thermal_authority();
    let channel = desc.channel;
    let period_ns = desc.period_ns;
    let n_levels = desc.cooling_levels.len();
    match register_cooling_device(
        &cap,
        Arc::new(PwmFan::from_description("pwm-fan", pwm, desc)),
    ) {
        Ok(()) => {
            let _ = writeln!(
                narf_console::Writer,
                "  pwm-fan: registered (channel={}, period_ns={}, cooling-levels={})",
                channel,
                period_ns,
                n_levels
            );
            Ok(())
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  pwm-fan: cooling-device registration failed: {:?}",
                e
            );
            Err(e)
        }
    }
}

// ── Devicetree `pwm-fan` probe ────────────────────────────────────────

/// The bus DT driver-match name.
pub const PWM_FAN_DT_DRIVER: &str = "pwm-fan";

/// `module_platform_driver` analogue: register the `pwm-fan`
/// compatible with the bus DT match table
/// (`narf_bus::register_dt_driver`). The Stage::Device
/// `probe_all_dt` walk then binds every enabled `pwm-fan` node;
/// the probe resolves its PWM controller and registers the fan.
/// Called from the platform `Stage::Subsys` initcall.
pub fn register_dt_driver() {
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: PWM_FAN_DT_DRIVER,
        compatible: &["pwm-fan"],
        probe: dt_pwm_fan_probe,
    });
}

/// Render an FDT walk [`narf_firmware_fdt::Path`] as the `/a/b`
/// string the bus DT walk hands probes.
fn node_path_string(path: &narf_firmware_fdt::Path<'_>) -> String {
    let mut p = String::new();
    for i in 0..path.depth() as usize {
        p.push('/');
        p.push_str(path.segment(i).unwrap_or(""));
    }
    if p.is_empty() {
        p.push('/');
    }
    p
}

/// Decode the `pwm-fan` node at `path` in `blob` into its board
/// description. `None` when the node is absent, its `compatible`
/// does not carry `pwm-fan`, or any part of the description is
/// malformed — the probe maps that to `BadDevice` and the node
/// stays unbound.
///
/// Decoding follows the two bindings, not the code's convenience:
/// - `pwms` is one specifier, `<phandle channel period_ns
///   [flags]>`. How many cells follow the phandle comes from the
///   controller node's `#pwm-cells` (generic PWM binding: 2 =
///   channel + period, 3 = + flags; absent defaults to 2 — a
///   controller node that declares anything else is malformed).
/// - `cooling-levels` is the optional PWM-duty ladder, one u32
///   per thermal cooling state (`pwm-fan.yaml`: each ≤ 255).
/// - `status` is already enforced by the bus walk, which only
///   probes enabled nodes; `#cooling-cells` belongs to the
///   thermal-zone `cooling-maps` reference, not to this driver,
///   so it is neither read nor required here.
pub fn decode_dt_pwm_fan(blob: &[u8], path: &str) -> Option<PwmFanDesc> {
    // 1) Find the node at `path` and collect its properties.
    // Property payloads borrow from the walker's per-call iterator,
    // so they are copied into owned buffers here — the decoded
    // description must outlive the walk.
    let mut pwms: Option<Vec<u8>> = None;
    let mut cooling_levels: Option<Vec<u8>> = None;
    let mut compatible_ok = false;
    let mut found = false;
    narf_firmware_fdt::walk_nodes(blob, |node_path, props| {
        if found {
            return;
        }
        if node_path_string(&node_path) != path {
            return;
        }
        found = true;
        for (name, value) in props {
            match name {
                "compatible" => {
                    compatible_ok = narf_firmware_fdt::compatible_matches(value, "pwm-fan");
                }
                "pwms" => pwms = Some(value.to_vec()),
                "cooling-levels" => cooling_levels = Some(value.to_vec()),
                _ => {}
            }
        }
    });
    if !found || !compatible_ok {
        return None;
    }
    let pwms = pwms?;
    if pwms.len() < 12 || pwms.len() % 4 != 0 {
        return None;
    }
    let be = |i: usize| {
        u32::from_be_bytes([
            pwms[4 * i],
            pwms[4 * i + 1],
            pwms[4 * i + 2],
            pwms[4 * i + 3],
        ])
    };
    let controller = be(0);
    // 2) The controller node's `#pwm-cells` says how many cells
    // follow the phandle. The `pwms` property must carry exactly
    // one specifier (the binding caps it at `maxItems: 1`).
    let mut cells = 2u32;
    narf_firmware_fdt::for_phandle(blob, controller, |_, props, _| {
        if let Some(c) = narf_firmware_fdt::prop_u32(props, "#pwm-cells") {
            cells = c;
        }
    });
    if !(2..=3).contains(&cells) {
        return None;
    }
    if pwms.len() != 4 * (1 + cells as usize) {
        return None;
    }
    let channel = be(1);
    let period_ns = be(2) as u64;
    if period_ns == 0 {
        return None;
    }
    let polarity = if cells == 3 && be(3) & 1 != 0 {
        Polarity::Inversed
    } else {
        Polarity::Normal
    };
    // 3) `cooling-levels`: optional PWM-duty ladder, one u32 per
    // thermal cooling state. A present-but-empty or ragged array
    // is malformed; absent means linear.
    let mut levels = Vec::new();
    if let Some(raw) = cooling_levels {
        if raw.is_empty() || raw.len() % 4 != 0 {
            return None;
        }
        for chunk in raw.chunks_exact(4) {
            let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            if v > 255 {
                return None;
            }
            levels.push(v as u8);
        }
    }
    Some(PwmFanDesc {
        controller,
        channel,
        period_ns,
        polarity,
        cooling_levels: levels,
    })
}

/// The DT probe: decode the node, resolve its PWM controller from
/// the registry, and register the fan. An unresolvable controller
/// is a deferred probe — the error leaves the node unbound so a
/// later `probe_all_dt` walk retries it once the controller driver
/// has registered (Linux deferred probe; a controller must register
/// by Stage::Device for the fan to bind at boot).
pub fn dt_pwm_fan_probe(blob: &'static [u8], path: &str) -> Result<(), ProbeError> {
    let desc = decode_dt_pwm_fan(blob, path).ok_or(ProbeError::BadDevice)?;
    let pwm = narf_pwm::lookup_controller(desc.controller)
        .ok_or(ProbeError::Other("pwm-fan: PWM controller not registered"))?;
    register_pwm_fan(pwm, desc)
        .map_err(|_| ProbeError::Other("pwm-fan: cooling-device registration failed"))
}

// ── Smoke tests ─────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use async_trait::async_trait;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;
    use narf_pwm::PwmError;

    /// Fake cooling device that records the last-set level. Mirrors
    /// the shape of `PwmFan`/`AcpiFan` without touching real hardware.
    #[derive(Debug)]
    struct RecordingFan {
        last: AtomicU8,
    }

    impl CoolingDevice for RecordingFan {
        fn name(&self) -> &'static str {
            "recording-fan"
        }
        fn set_level(&self, level: u8) {
            self.last.store(level, Ordering::SeqCst);
        }
    }

    fn smoke_pwm_fan_set_level_dispatches() -> TestResult {
        // We only verify the `CoolingDevice` plumbing here — the PWM
        // path is exercised in `narf-pwm`'s own smoke test. Building a
        // PwmFan would require spinning up the scheduler; this test
        // covers the trait surface that the cooling registry uses.
        let fan = RecordingFan {
            last: AtomicU8::new(0),
        };
        fan.set_level(200);
        if fan.last.load(Ordering::SeqCst) == 200 {
            TestResult::Pass
        } else {
            TestResult::Fail("RecordingFan did not record set_level")
        }
    }
    kernel_test_in!("drivers-platform-fan", smoke_pwm_fan_set_level_dispatches);

    #[cfg(target_arch = "x86_64")]
    fn smoke_thinkpad_level_mapping() -> TestResult {
        use crate::thinkpad_acpi::FanLevel;
        // Boundary table for thinkpad_level_for: 0 hands the fan
        // back to firmware auto; non-zero levels scale onto the
        // eight explicit states L1..=L7 + FullSpeed by
        // ceil(level * 8 / 255). The StepPolicy outputs must land
        // mid-ladder and at the top: 128 → L5, 255 → FullSpeed.
        let table: [(u8, FanLevel); 8] = [
            (0, FanLevel::Auto),
            (1, FanLevel::L1),
            (31, FanLevel::L1),
            (32, FanLevel::L2),
            (128, FanLevel::L5),
            (223, FanLevel::L7),
            (224, FanLevel::FullSpeed),
            (255, FanLevel::FullSpeed),
        ];
        for (level, want) in table {
            if thinkpad_level_for(level) != want {
                return TestResult::Fail("thinkpad_level_for boundary mismatch");
            }
        }
        // The mapping must be monotonic non-decreasing across the
        // whole range (rank: Auto < L1 < .. < L7 < FullSpeed) — a
        // hotter demand must never slow the fan down.
        let rank = |l: FanLevel| match l {
            FanLevel::FullSpeed => 8,
            other => other as u32,
        };
        for level in 0..255u8 {
            if rank(thinkpad_level_for(level + 1)) < rank(thinkpad_level_for(level)) {
                return TestResult::Fail("thinkpad_level_for is not monotonic");
            }
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("drivers-platform-fan", smoke_thinkpad_level_mapping);

    #[cfg(target_arch = "x86_64")]
    fn smoke_asus_mode_mapping() -> TestResult {
        use crate::asus_wmi::FanBoostMode;
        // Boundary table for asus_mode_for: 0 → Silent (no demand),
        // 1..=170 → Normal, 171..=255 → Overboost. The StepPolicy
        // outputs land one per mode: 0 / 128 / 255.
        let table: [(u8, FanBoostMode); 6] = [
            (0, FanBoostMode::Silent),
            (1, FanBoostMode::Normal),
            (128, FanBoostMode::Normal),
            (170, FanBoostMode::Normal),
            (171, FanBoostMode::Overboost),
            (255, FanBoostMode::Overboost),
        ];
        for (level, want) in table {
            if asus_mode_for(level) != want {
                return TestResult::Fail("asus_mode_for boundary mismatch");
            }
        }
        let rank = |m: FanBoostMode| match m {
            FanBoostMode::Silent => 0,
            FanBoostMode::Normal => 1,
            FanBoostMode::Overboost => 2,
        };
        for level in 0..255u8 {
            if rank(asus_mode_for(level + 1)) < rank(asus_mode_for(level)) {
                return TestResult::Fail("asus_mode_for is not monotonic");
            }
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("drivers-platform-fan", smoke_asus_mode_mapping);

    #[cfg(target_arch = "x86_64")]
    fn smoke_vendor_fan_wrappers_drive_vendor_state() -> TestResult {
        use crate::asus_wmi::FanBoostMode;
        use crate::thinkpad_acpi::FanLevel;
        // The wrappers must reach the vendor drivers' own state:
        // ThinkpadFan → thinkpad_acpi::set_fan_level (records into
        // fan_level()), AsusFan → asus_wmi::set_fan_boost_mode
        // (records into fan_boost_mode()). The AML/WMI transports
        // are best-effort in these drivers, so the recorded state
        // is the observable seam below the governor fixtures in
        // the crate test suite, which assert the wire writes.
        crate::thinkpad_acpi::__test_reset();
        crate::asus_wmi::__test_reset();

        let tp = ThinkpadFan::new();
        tp.set_level(128);
        if crate::thinkpad_acpi::fan_level() != FanLevel::L5 {
            return TestResult::Fail("ThinkpadFan(128) did not set fan level L5");
        }
        tp.set_level(255);
        if crate::thinkpad_acpi::fan_level() != FanLevel::FullSpeed {
            return TestResult::Fail("ThinkpadFan(255) did not set FullSpeed");
        }
        tp.set_level(0);
        if crate::thinkpad_acpi::fan_level() != FanLevel::Auto {
            return TestResult::Fail("ThinkpadFan(0) did not return fan to Auto");
        }

        let asus = AsusFan::new();
        asus.set_level(0);
        if crate::asus_wmi::fan_boost_mode() != FanBoostMode::Silent {
            return TestResult::Fail("AsusFan(0) did not set Silent");
        }
        asus.set_level(128);
        if crate::asus_wmi::fan_boost_mode() != FanBoostMode::Normal {
            return TestResult::Fail("AsusFan(128) did not set Normal");
        }
        asus.set_level(255);
        if crate::asus_wmi::fan_boost_mode() != FanBoostMode::Overboost {
            return TestResult::Fail("AsusFan(255) did not set Overboost");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_vendor_fan_wrappers_drive_vendor_state
    );
    // ── Hand-encoded AML fan fixtures ─────────────────────────────
    //
    // The fixtures below are hand-encoded AML byte streams in the
    // shape a real DSDT carries (Device / Name / Method / Package
    // terms, PkgLength framing). They are parsed by the real
    // namespace builder (`__parse_body_for_test`), evaluated by the
    // real evaluator, and driven through the production `AcpiFan` —
    // the fake is the firmware, not a mock of the driver. Device
    // names FAN4..FAN9 are unique so the additive parses never
    // collide with the boot namespace or each other.

    /// PkgLength field for a package whose total length (the field
    /// itself included) is `total`: single-byte form below 64, the
    /// two-byte follow form (`0x40 | low nibble`, high byte) above.
    fn pkg_len(total: usize) -> Vec<u8> {
        if total < 64 {
            alloc::vec![total as u8]
        } else {
            alloc::vec![0x40 | (total & 0x0F) as u8, (total >> 4) as u8]
        }
    }

    /// Frame `payload` (everything after the PkgLength field) behind
    /// a package-bearing opcode.
    fn framed(op: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut total = 1 + payload.len();
        if total >= 64 {
            total += 1; // the length field itself grows to 2 bytes
        }
        let mut v = Vec::new();
        v.extend_from_slice(op);
        v.extend_from_slice(&pkg_len(total));
        v.extend_from_slice(payload);
        v
    }

    /// An integer constant term with the minimal prefix encoding
    /// (ZeroOp / OneOp / BytePrefix / WordPrefix / DWordPrefix).
    fn int_term(v: u64) -> Vec<u8> {
        match v {
            0 => alloc::vec![0x00],
            1 => alloc::vec![0x01],
            0x02..=0xFF => alloc::vec![0x0A, v as u8],
            0x100..=0xFFFF => {
                let mut b = alloc::vec![0x0B];
                b.extend_from_slice(&(v as u16).to_le_bytes());
                b
            }
            _ => {
                let mut b = alloc::vec![0x0C];
                b.extend_from_slice(&(v as u32).to_le_bytes());
                b
            }
        }
    }

    /// A string constant term (StringPrefix + NUL-terminated ASCII).
    fn string_term(s: &str) -> Vec<u8> {
        let mut v = alloc::vec![0x0D];
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        v
    }

    fn name_term(seg: &[u8; 4], value: Vec<u8>) -> Vec<u8> {
        let mut v = alloc::vec![0x08]; // NameOp
        v.extend_from_slice(seg);
        v.extend_from_slice(&value);
        v
    }

    fn package_term(elements: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = alloc::vec![elements.len() as u8]; // NumElements
        for e in elements {
            payload.extend_from_slice(e);
        }
        framed(&[0x12], &payload) // PackageOp
    }

    fn method_term(seg: &[u8; 4], flags: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(seg);
        payload.push(flags);
        payload.extend_from_slice(body);
        framed(&[0x14], &payload) // MethodOp
    }

    fn device_term(seg: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(seg);
        payload.extend_from_slice(body);
        framed(&[0x5B, 0x82], &payload) // ExtOpPrefix + DeviceOp
    }

    /// `Store(src, seg)` — how the fixture methods record what the
    /// driver evaluated them with.
    fn store_term(src: Vec<u8>, seg: &[u8; 4]) -> Vec<u8> {
        let mut v = alloc::vec![0x70]; // StoreOp
        v.extend_from_slice(&src);
        v.extend_from_slice(seg);
        v
    }

    /// One `_FPS` FanPState package built from its five spec fields
    /// (ACPI 6.5 §11.3.1.2, Table 11.3).
    fn fps_state(control: u64, trip: u64, speed: u64, noise: u64, power: u64) -> Vec<u8> {
        package_term(&[
            int_term(control),
            int_term(trip),
            int_term(speed),
            int_term(noise),
            int_term(power),
        ])
    }

    /// The recorder tail every controllable fixture fan carries:
    /// `LAST` (the most recent `_FSL` argument) and `POWR` (1 after
    /// `_ON`, 0 after `_OFF`) Names, plus the three methods that
    /// write them.
    fn recorder_tail() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&name_term(b"LAST", int_term(0)));
        v.extend_from_slice(&name_term(b"POWR", int_term(0)));
        // Method(_FSL, 1) { Store(Arg0, LAST) }
        v.extend_from_slice(&method_term(
            b"_FSL",
            0x01,
            &store_term(alloc::vec![0x68], b"LAST"),
        ));
        // Method(_ON, 0) { Store(One, POWR) }
        v.extend_from_slice(&method_term(
            b"_ON_",
            0x00,
            &store_term(int_term(1), b"POWR"),
        ));
        // Method(_OFF, 0) { Store(Zero, POWR) }
        v.extend_from_slice(&method_term(
            b"_OFF",
            0x00,
            &store_term(int_term(0), b"POWR"),
        ));
        v
    }

    /// FAN9: EISAID-integer `_HID`, fine-grained `_FIF`, and a
    /// four-state `_FPS`, all declared as Names — the dominant
    /// real-DSDT shape.
    fn fan9_blob() -> Vec<u8> {
        let mut body = Vec::new();
        // Name(_HID, EisaId("PNP0C0B")) compiles to DWord 0x0B0CD041.
        body.extend_from_slice(&name_term(b"_HID", int_term(0x0B0CD041)));
        // Name(_FIF, Package { 0, 1, 5, 1 }): revision 0,
        // FineGrainControl on, StepSize 5, LowSpeedNotify on.
        body.extend_from_slice(&name_term(
            b"_FIF",
            package_term(&[int_term(0), int_term(1), int_term(5), int_term(1)]),
        ));
        // Name(_FPS, Package { 0, S0, S1, S2, S3 }).
        body.extend_from_slice(&name_term(
            b"_FPS",
            package_term(&[
                int_term(0),
                fps_state(30, 0xFFFF_FFFF, 1200, 0xFFFF_FFFF, 0xFFFF_FFFF),
                fps_state(55, 1, 4660, 283, 500),
                fps_state(80, 0, 3600, 350, 900),
                fps_state(100, 0xFFFF_FFFF, 4800, 420, 1500),
            ]),
        ));
        body.extend_from_slice(&recorder_tail());
        device_term(b"FAN9", &body)
    }

    /// FAN8: string `_HID`, coarse `_FIF` (FineGrainControl = 0), and
    /// a `_FPS` whose Control values are opaque tokens (33/66/99) —
    /// neither percentages nor 1..=3 indices.
    fn fan8_blob() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&name_term(b"_HID", string_term("PNP0C0B")));
        body.extend_from_slice(&name_term(
            b"_FIF",
            package_term(&[int_term(0), int_term(0), int_term(0), int_term(0)]),
        ));
        body.extend_from_slice(&name_term(
            b"_FPS",
            package_term(&[
                int_term(0),
                fps_state(33, 0xFFFF_FFFF, 900, 0xFFFF_FFFF, 0xFFFF_FFFF),
                fps_state(66, 1, 1800, 250, 300),
                fps_state(99, 0, 2700, 310, 700),
            ]),
        ));
        body.extend_from_slice(&recorder_tail());
        device_term(b"FAN8", &body)
    }

    /// FAN7: `_FIF` / `_FPS` as zero-argument Methods returning
    /// Packages — the other shape firmware uses.
    fn fan7_blob() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&name_term(b"_HID", int_term(0x0B0CD041)));
        // Method(_FIF, 0) { Return(Package { 0, 1, 0, 0 }) }
        let mut fif_body = alloc::vec![0xA4]; // ReturnOp
        fif_body.extend_from_slice(&package_term(&[
            int_term(0),
            int_term(1),
            int_term(0),
            int_term(0),
        ]));
        body.extend_from_slice(&method_term(b"_FIF", 0x00, &fif_body));
        // Method(_FPS, 0) { Return(Package { 0, S0, S1 }) }
        let mut fps_body = alloc::vec![0xA4];
        fps_body.extend_from_slice(&package_term(&[
            int_term(0),
            fps_state(40, 0xFFFF_FFFF, 1500, 0xFFFF_FFFF, 0xFFFF_FFFF),
            fps_state(90, 0, 3900, 380, 1200),
        ]));
        body.extend_from_slice(&method_term(b"_FPS", 0x00, &fps_body));
        body.extend_from_slice(&recorder_tail());
        device_term(b"FAN7", &body)
    }

    /// FAN6: a non-fan device (`_HID` PNP0C0C) — discovery must pass
    /// it by.
    fn fan6_blob() -> Vec<u8> {
        device_term(b"FAN6", &name_term(b"_HID", string_term("PNP0C0C")))
    }

    /// FAN5: a binary fan — string `_HID`, `_ON`/`_OFF` only, no
    /// `_FIF` / `_FPS` / `_FSL` at all.
    fn fan5_blob() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&name_term(b"_HID", string_term("PNP0C0B")));
        body.extend_from_slice(&name_term(b"POWR", int_term(0)));
        body.extend_from_slice(&method_term(
            b"_ON_",
            0x00,
            &store_term(int_term(1), b"POWR"),
        ));
        body.extend_from_slice(&method_term(
            b"_OFF",
            0x00,
            &store_term(int_term(0), b"POWR"),
        ));
        device_term(b"FAN5", &body)
    }

    /// FAN4: fine-grained `_FIF` with a StepSize but no `_FPS` —
    /// `_FSL` takes raw percentages, quantised to the step.
    fn fan4_blob() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&name_term(b"_HID", string_term("PNP0C0B")));
        body.extend_from_slice(&name_term(
            b"_FIF",
            package_term(&[int_term(0), int_term(1), int_term(5), int_term(0)]),
        ));
        body.extend_from_slice(&recorder_tail());
        device_term(b"FAN4", &body)
    }

    /// Read an Integer Name the fixture methods recorded into.
    fn recorded(path: &str) -> Option<u64> {
        use narf_aml::{find_node, NameValue};
        match find_node(path).and_then(|n| n.value) {
            Some(NameValue::Integer(v)) => Some(v),
            _ => None,
        }
    }

    fn smoke_acpi_fan_fps_state_package_byte_layout() -> TestResult {
        // Byte-for-byte pin against the spec-shaped frame
        // (§11.3.1.2, Table 11.3): PackageOp, PkgLength(18),
        // NumElements(5), then Control / TripPoint / Speed /
        // NoiseLevel / Power with minimal integer prefixes:
        //   Control    55          -> BytePrefix  0x0A 0x37
        //   TripPoint  0xFFFFFFFF  -> DWordPrefix 0x0C FF FF FF FF
        //   Speed      4660        -> WordPrefix  0x0B 0x34 0x12
        //   NoiseLevel 283         -> WordPrefix  0x0B 0x1B 0x01
        //   Power      500         -> WordPrefix  0x0B 0xF4 0x01
        let expected: &[u8] = &[
            0x12, 18, 5, 0x0A, 0x37, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0x0B, 0x34, 0x12, 0x0B, 0x1B,
            0x01, 0x0B, 0xF4, 0x01,
        ];
        if fps_state(55, 0xFFFF_FFFF, 4660, 283, 500).as_slice() != expected {
            return TestResult::Fail("_FPS state package does not match the spec byte layout");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_acpi_fan_fps_state_package_byte_layout
    );

    fn smoke_acpi_fan_eisaid_hid_discovery() -> TestResult {
        if narf_aml::__parse_body_for_test(&fan9_blob(), "\\").is_err() {
            return TestResult::Fail("FAN9 fixture parse failed");
        }
        if narf_aml::__parse_body_for_test(&fan6_blob(), "\\").is_err() {
            return TestResult::Fail("FAN6 fixture parse failed");
        }
        // The fixture really carries the integer form — this guards
        // the test against silently exercising the string path.
        if recorded("\\FAN9._HID") != Some(0x0B0CD041) {
            return TestResult::Fail("FAN9 _HID is not the EisaId DWORD 0x0B0CD041");
        }
        if !is_fan_device("\\FAN9") {
            return TestResult::Fail("EisaId-form PNP0C0B fan must be discovered");
        }
        if is_fan_device("\\FAN6") {
            return TestResult::Fail("PNP0C0C device must not be discovered as a fan");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-fan", smoke_acpi_fan_eisaid_hid_discovery);

    fn smoke_acpi_fan_fps_ladder_drives_fsl() -> TestResult {
        if narf_aml::__parse_body_for_test(&fan9_blob(), "\\").is_err() {
            return TestResult::Fail("FAN9 fixture parse failed");
        }
        let fan = AcpiFan::probe("\\FAN9");
        // _FIF decoded field-by-field, not treated as a boolean.
        match fan.info {
            Some(info) => {
                if info.revision != 0
                    || !info.fine_grained
                    || info.step_size != 5
                    || !info.low_speed_notify
                {
                    return TestResult::Fail("_FIF fields decoded wrong");
                }
            }
            None => return TestResult::Fail("_FIF must decode"),
        }
        // _FPS decoded: the ladder is the declared table, not the
        // invented 10-step one.
        if fan.states.len() != 4 {
            return TestResult::Fail("_FPS must yield 4 states");
        }
        let s1 = fan.states[1];
        if s1.control != 55
            || s1.trip_point != 1
            || s1.speed_rpm != 4660
            || s1.noise_deci_db != 283
            || s1.power_mw != 500
        {
            return TestResult::Fail("_FPS state 1 fields decoded wrong");
        }
        if fan.states[0].trip_point != 0xFFFF_FFFF {
            return TestResult::Fail("trip-point sentinel must survive decode");
        }
        // Full level -> top state's Control, and the fan turned on.
        fan.set_level(255);
        if recorded("\\FAN9.LAST") != Some(100) {
            return TestResult::Fail("set_level(255) must evaluate _FSL(100)");
        }
        if recorded("\\FAN9.POWR") != Some(1) {
            return TestResult::Fail("set_level(255) must evaluate _ON");
        }
        // 64/255 -> second of the four states -> Control 55, a value
        // no round-number ladder would produce.
        fan.set_level(64);
        if recorded("\\FAN9.LAST") != Some(55) {
            return TestResult::Fail("set_level(64) must evaluate _FSL(55)");
        }
        // Off -> _OFF.
        fan.set_level(0);
        if recorded("\\FAN9.POWR") != Some(0) {
            return TestResult::Fail("set_level(0) must evaluate _OFF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-fan", smoke_acpi_fan_fps_ladder_drives_fsl);

    fn smoke_acpi_fan_coarse_controls_passed_verbatim() -> TestResult {
        if narf_aml::__parse_body_for_test(&fan8_blob(), "\\").is_err() {
            return TestResult::Fail("FAN8 fixture parse failed");
        }
        if !is_fan_device("\\FAN8") {
            return TestResult::Fail("string-HID fan must be discovered");
        }
        let fan = AcpiFan::probe("\\FAN8");
        if fan.fine_grained() {
            return TestResult::Fail("FAN8 must probe as coarse (FineGrainControl = 0)");
        }
        if fan.states.len() != 3 {
            return TestResult::Fail("FAN8 _FPS must yield 3 states");
        }
        // Coarse mode: _FSL must receive the state's Control token
        // verbatim — not a 1..=3 index and not a percentage.
        fan.set_level(255);
        if recorded("\\FAN8.LAST") != Some(99) {
            return TestResult::Fail("set_level(255) must evaluate _FSL(99)");
        }
        fan.set_level(128);
        if recorded("\\FAN8.LAST") != Some(66) {
            return TestResult::Fail("set_level(128) must evaluate _FSL(66)");
        }
        fan.set_level(10);
        if recorded("\\FAN8.LAST") != Some(33) {
            return TestResult::Fail("set_level(10) must evaluate _FSL(33)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_acpi_fan_coarse_controls_passed_verbatim
    );

    fn smoke_acpi_fan_method_form_packages() -> TestResult {
        if narf_aml::__parse_body_for_test(&fan7_blob(), "\\").is_err() {
            return TestResult::Fail("FAN7 fixture parse failed");
        }
        let fan = AcpiFan::probe("\\FAN7");
        if !fan.fine_grained() {
            return TestResult::Fail("Method-form _FIF must decode as fine-grained");
        }
        if fan.states.len() != 2 || fan.states[1].control != 90 {
            return TestResult::Fail("Method-form _FPS must yield its 2 states");
        }
        fan.set_level(255);
        if recorded("\\FAN7.LAST") != Some(90) {
            return TestResult::Fail("set_level(255) must evaluate _FSL(90)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-fan", smoke_acpi_fan_method_form_packages);

    fn smoke_acpi_fan_fine_percentage_step_rounding() -> TestResult {
        if narf_aml::__parse_body_for_test(&fan4_blob(), "\\").is_err() {
            return TestResult::Fail("FAN4 fixture parse failed");
        }
        let fan = AcpiFan::probe("\\FAN4");
        if !fan.fine_grained() || !fan.states.is_empty() {
            return TestResult::Fail("FAN4 must probe as fine-grained with no _FPS table");
        }
        // 255 -> 100%.
        fan.set_level(255);
        if recorded("\\FAN4.LAST") != Some(100) {
            return TestResult::Fail("set_level(255) must evaluate _FSL(100)");
        }
        // 128 -> ceil(128*100/255) = 51%, rounded up to the declared
        // StepSize of 5 -> 55%.
        fan.set_level(128);
        if recorded("\\FAN4.LAST") != Some(55) {
            return TestResult::Fail("set_level(128) must evaluate _FSL(55) after step rounding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_acpi_fan_fine_percentage_step_rounding
    );

    fn smoke_acpi_fan_binary_only() -> TestResult {
        if narf_aml::__parse_body_for_test(&fan5_blob(), "\\").is_err() {
            return TestResult::Fail("FAN5 fixture parse failed");
        }
        let fan = AcpiFan::probe("\\FAN5");
        if fan.info.is_some() || !fan.states.is_empty() || fan.fine_grained() {
            return TestResult::Fail("fan without _FIF/_FPS must probe as binary");
        }
        fan.set_level(200);
        if recorded("\\FAN5.POWR") != Some(1) {
            return TestResult::Fail("binary fan set_level(200) must evaluate _ON");
        }
        fan.set_level(0);
        if recorded("\\FAN5.POWR") != Some(0) {
            return TestResult::Fail("binary fan set_level(0) must evaluate _OFF");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-fan", smoke_acpi_fan_binary_only);

    // ── PWM fan fixtures ────────────────────────────────────────
    //
    // The fixtures below are hand-encoded FDT blobs in the shape a
    // real DTB carries (header + struct block + strings block,
    // big-endian cells). They are parsed by the real FDT walker
    // and driven through the production `decode_dt_pwm_fan` /
    // `dt_pwm_fan_probe` — the fake is the firmware, not a mock of
    // the driver. The node contents follow the Linux pwm-fan
    // binding (`Documentation/devicetree/bindings/hwmon/pwm-fan.yaml`:
    // `compatible = "pwm-fan"`, `pwms = <&pwm channel period>`,
    // `cooling-levels` entries ≤ 255) and the generic PWM binding
    // (`pwms` cells after the phandle: channel, period in ns,
    // optional flags with bit 0 = inverted polarity).

    /// Test-only `PwmDevice` recording every config/enable call,
    /// so the `PwmFan` worker's output is observable without
    /// hardware. Mirrors `narf_pwm`'s `MockPwm` (which is
    /// test-gated inside its own crate and not reachable here).
    struct FakePwm {
        state: IrqSafeSpinLock<Vec<(u32, PwmConfig, bool)>>,
        channels: u32,
    }

    impl FakePwm {
        fn new(channels: u32) -> Self {
            Self {
                state: IrqSafeSpinLock::new(Vec::new()),
                channels,
            }
        }

        /// The last `(config, enabled)` recorded for `channel`.
        fn last(&self, channel: u32) -> Option<(PwmConfig, bool)> {
            self.state
                .lock()
                .iter()
                .rev()
                .find(|(ch, _, _)| *ch == channel)
                .map(|(_, cfg, en)| (*cfg, *en))
        }
    }

    #[async_trait]
    impl PwmDevice for FakePwm {
        async fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            let mut state = self.state.lock();
            if let Some(c) = state.iter_mut().find(|(ch, _, _)| *ch == channel) {
                c.1 = *config;
            } else {
                state.push((channel, *config, false));
            }
            Ok(())
        }

        async fn enable(&self, channel: u32) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            let mut state = self.state.lock();
            if let Some(c) = state.iter_mut().find(|(ch, _, _)| *ch == channel) {
                c.2 = true;
            } else {
                state.push((
                    channel,
                    PwmConfig {
                        frequency_hz: 0,
                        duty_cycle_ns: 0,
                        polarity: Polarity::Normal,
                    },
                    true,
                ));
            }
            Ok(())
        }

        async fn disable(&self, channel: u32) -> Result<(), PwmError> {
            if channel >= self.channels {
                return Err(PwmError::InvalidChannel);
            }
            let mut state = self.state.lock();
            if let Some(c) = state.iter_mut().find(|(ch, _, _)| *ch == channel) {
                c.2 = false;
            } else {
                state.push((
                    channel,
                    PwmConfig {
                        frequency_hz: 0,
                        duty_cycle_ns: 0,
                        polarity: Polarity::Normal,
                    },
                    false,
                ));
            }
            Ok(())
        }

        fn channel_count(&self) -> u32 {
            self.channels
        }
    }

    /// One big-endian u32 cell.
    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Minimal FDT (DTB v17) builder: header + struct block +
    /// strings block, one reservation-map terminator. Same layout
    /// as `narf-firmware-fdt`'s own test builder
    /// (`firmware/fdt/src/tests.rs`); the blob is parsed by the
    /// real FDT walker, so the decode under test reads real wire
    /// bytes, not a hand-rolled node struct.
    fn fdt_blob(nodes: &[(&str, &[(&str, &[u8])])]) -> Vec<u8> {
        use narf_firmware_fdt as fdt;
        let mut strings: Vec<u8> = Vec::new();
        let intern = |strings: &mut Vec<u8>, name: &str| -> u32 {
            // Search for an existing identical run.
            let target = name.as_bytes();
            let mut i = 0;
            while i + target.len() < strings.len() {
                if &strings[i..i + target.len()] == target && strings[i + target.len()] == 0 {
                    return i as u32;
                }
                i += 1;
            }
            let off = strings.len() as u32;
            strings.extend_from_slice(target);
            strings.push(0);
            off
        };

        let mut s: Vec<u8> = Vec::new();
        // Root open: BEGIN_NODE + empty name + 4-byte alignment.
        s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]);

        for (node_path, props) in nodes {
            let mut opened = 0;
            for node_name in node_path.split('/') {
                s.extend_from_slice(&fdt::FDT_BEGIN_NODE.to_be_bytes());
                s.extend_from_slice(node_name.as_bytes());
                s.push(0);
                while s.len() % 4 != 0 {
                    s.push(0);
                }
                opened += 1;
            }
            for (pname, pval) in *props {
                let off = intern(&mut strings, pname);
                s.extend_from_slice(&fdt::FDT_PROP.to_be_bytes());
                s.extend_from_slice(&(pval.len() as u32).to_be_bytes());
                s.extend_from_slice(&off.to_be_bytes());
                s.extend_from_slice(pval);
                while s.len() % 4 != 0 {
                    s.push(0);
                }
            }
            for _ in 0..opened {
                s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes());
            }
        }

        s.extend_from_slice(&fdt::FDT_END_NODE.to_be_bytes()); // close root
        s.extend_from_slice(&fdt::FDT_END.to_be_bytes());

        let struct_size = s.len() as u32;
        let strings_size = strings.len() as u32;

        let mut rsv: Vec<u8> = Vec::new();
        rsv.extend_from_slice(&0u64.to_be_bytes());
        rsv.extend_from_slice(&0u64.to_be_bytes());

        let off_rsvmap = 40u32;
        let off_struct = off_rsvmap + rsv.len() as u32;
        let off_strings = off_struct + struct_size;
        let totalsize = off_strings + strings_size;

        let mut out: Vec<u8> = Vec::with_capacity(totalsize as usize);
        out.extend_from_slice(&fdt::FDT_MAGIC.to_be_bytes());
        out.extend_from_slice(&totalsize.to_be_bytes());
        out.extend_from_slice(&off_struct.to_be_bytes());
        out.extend_from_slice(&off_strings.to_be_bytes());
        out.extend_from_slice(&off_rsvmap.to_be_bytes());
        out.extend_from_slice(&17u32.to_be_bytes()); // version
        out.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
        out.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid
        out.extend_from_slice(&strings_size.to_be_bytes());
        out.extend_from_slice(&struct_size.to_be_bytes());
        out.extend_from_slice(&rsv);
        out.extend_from_slice(&s);
        out.extend_from_slice(&strings);
        out
    }

    /// Two-node fixture blob: a PWM controller node (phandle
    /// `0x2a`, `#pwm-cells` = `pwm_cells`) and a `pwm-fan` node
    /// whose `pwms` carries `pwms_cells` (first cell the phandle)
    /// and whose `cooling-levels` is `levels` when `Some`
    /// (absent when `None`). The fan lives at `/fan`, the
    /// controller at `/pwm@1000`.
    fn pwm_fan_fixture(pwm_cells: u32, pwms_cells: &[u32], levels: Option<&[u32]>) -> Vec<u8> {
        let phandle = be32(0x2a);
        let cells = be32(pwm_cells);
        let compatible = b"pwm-fan\0";
        let mut pwms = Vec::new();
        for c in pwms_cells {
            pwms.extend_from_slice(&be32(*c));
        }
        let mut level_bytes = Vec::new();
        for l in levels.unwrap_or(&[]) {
            level_bytes.extend_from_slice(&be32(*l));
        }
        let mut fan_props: Vec<(&str, &[u8])> = alloc::vec![
            ("compatible", compatible.as_slice()),
            ("pwms", pwms.as_slice()),
        ];
        if levels.is_some() {
            fan_props.push(("cooling-levels", level_bytes.as_slice()));
        }
        fdt_blob(&[
            (
                "pwm@1000",
                &[
                    ("phandle", phandle.as_slice()),
                    ("#pwm-cells", cells.as_slice()),
                ],
            ),
            ("fan", &fan_props),
        ])
    }

    fn smoke_dt_pwm_fan_decode() -> TestResult {
        // The binding's own example shape: `pwms = <&pwm 0
        // 10000 0>` with `cooling-levels = <0 102 170 230>` —
        // here channel 3 at the 25 kHz period (40_000 ns).
        let blob = pwm_fan_fixture(2, &[0x2a, 3, 40_000], Some(&[0, 102, 170, 230]));
        let desc = match decode_dt_pwm_fan(&blob, "/fan") {
            Some(d) => d,
            None => return TestResult::Fail("pwm-fan node must decode"),
        };
        if desc.controller != 0x2a || desc.channel != 3 || desc.period_ns != 40_000 {
            return TestResult::Fail("pwms specifier decoded wrong");
        }
        if desc.polarity != Polarity::Normal {
            return TestResult::Fail("2-cell pwms must decode as normal polarity");
        }
        if desc.cooling_levels != alloc::vec![0, 102, 170, 230] {
            return TestResult::Fail("cooling-levels ladder decoded wrong");
        }
        // Unknown path / missing node must not decode.
        if decode_dt_pwm_fan(&blob, "/nope").is_some() {
            return TestResult::Fail("unknown path must not decode");
        }
        // No ladder declared: linear, not an error.
        let blob = pwm_fan_fixture(2, &[0x2a, 0, 40_000], None);
        match decode_dt_pwm_fan(&blob, "/fan") {
            Some(d) if d.cooling_levels.is_empty() => {}
            _ => return TestResult::Fail("absent cooling-levels must decode as linear"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-fan", smoke_dt_pwm_fan_decode);

    fn smoke_dt_pwm_fan_decode_polarity_flag() -> TestResult {
        // 3-cell specifier: flags bit 0 set inverts the output.
        let blob = pwm_fan_fixture(3, &[0x2a, 1, 40_000, 1], None);
        match decode_dt_pwm_fan(&blob, "/fan") {
            Some(d) if d.polarity == Polarity::Inversed => {}
            _ => return TestResult::Fail("flags bit 0 must decode as inverted polarity"),
        }
        let blob = pwm_fan_fixture(3, &[0x2a, 1, 40_000, 0], None);
        match decode_dt_pwm_fan(&blob, "/fan") {
            Some(d) if d.polarity == Polarity::Normal => {}
            _ => return TestResult::Fail("flags 0 must decode as normal polarity"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_dt_pwm_fan_decode_polarity_flag
    );

    fn smoke_dt_pwm_fan_decode_rejects_malformed() -> TestResult {
        // Missing `pwms` (required by the binding).
        let blob = fdt_blob(&[("fan", &[("compatible", b"pwm-fan\0".as_slice())])]);
        if decode_dt_pwm_fan(&blob, "/fan").is_some() {
            return TestResult::Fail("node without pwms must not decode");
        }
        // Zero period: the worker divides by it.
        let blob = pwm_fan_fixture(2, &[0x2a, 0, 0], None);
        if decode_dt_pwm_fan(&blob, "/fan").is_some() {
            return TestResult::Fail("zero period must not decode");
        }
        // Cooling level above the binding's 255 maximum.
        let blob = pwm_fan_fixture(2, &[0x2a, 0, 40_000], Some(&[0, 256]));
        if decode_dt_pwm_fan(&blob, "/fan").is_some() {
            return TestResult::Fail("cooling level > 255 must not decode");
        }
        // `#pwm-cells` disagrees with the specifier length.
        let blob = pwm_fan_fixture(3, &[0x2a, 0, 40_000], None);
        if decode_dt_pwm_fan(&blob, "/fan").is_some() {
            return TestResult::Fail("3-cell controller with 2-cell pwms must not decode");
        }
        let blob = pwm_fan_fixture(1, &[0x2a, 0, 40_000], None);
        if decode_dt_pwm_fan(&blob, "/fan").is_some() {
            return TestResult::Fail("#pwm-cells = 1 must not decode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_dt_pwm_fan_decode_rejects_malformed
    );

    fn smoke_pwm_fan_linear_default_drives_25khz() -> TestResult {
        // The first test that actually constructs a `PwmFan`: the
        // pre-DT default keeps the old behaviour — 25 kHz, duty
        // is the level itself.
        narf_scheduler::__reset_queues_for_test();
        let pwm = Arc::new(FakePwm::new(2));
        let fan = PwmFan::new("pwm-fan", pwm.clone(), 1);
        fan.set_level(200);
        narf_scheduler::run_until_empty();
        match pwm.last(1) {
            Some((cfg, true)) => {
                // 40_000 * 200 / 255 = 31_372 ns at 25 kHz.
                if cfg.frequency_hz != 25_000 || cfg.duty_cycle_ns != 31_372 {
                    return TestResult::Fail("linear PwmFan drove the wrong duty");
                }
            }
            _ => return TestResult::Fail("PwmFan set_level(200) did not enable its channel"),
        }
        fan.set_level(0);
        narf_scheduler::run_until_empty();
        match pwm.last(1) {
            Some((_, false)) => TestResult::Pass,
            _ => TestResult::Fail("PwmFan set_level(0) did not disable its channel"),
        }
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_pwm_fan_linear_default_drives_25khz
    );

    fn smoke_dt_pwm_fan_probe_registers_and_drives() -> TestResult {
        narf_scheduler::__reset_queues_for_test();
        narf_power::thermal::init();
        let blob = pwm_fan_fixture(2, &[0x2a, 3, 40_000], Some(&[0, 102, 170, 230]));
        let blob: &'static [u8] = alloc::boxed::Box::leak(blob.into_boxed_slice());
        let pwm = Arc::new(FakePwm::new(4));
        narf_pwm::unregister_controller(0x2a);
        narf_pwm::register_controller(0x2a, pwm.clone());
        // No controller registered yet for a different phandle:
        // the probe defers instead of binding.
        let blob_noctl = pwm_fan_fixture(2, &[0x2b, 3, 40_000], None);
        let blob_noctl: &'static [u8] = alloc::boxed::Box::leak(blob_noctl.into_boxed_slice());
        if dt_pwm_fan_probe(blob_noctl, "/fan").is_ok() {
            narf_pwm::unregister_controller(0x2a);
            return TestResult::Fail("probe with no controller must defer, not bind");
        }
        if dt_pwm_fan_probe(blob, "/fan").is_err() {
            narf_pwm::unregister_controller(0x2a);
            return TestResult::Fail("pwm-fan probe must succeed with a registered controller");
        }
        // Governor drive, end to end through the thermal
        // registry: level 128 lands on cooling state 1
        // (128 * 3 / 255 = 1) -> duty value 102 -> duty_ns
        // 40_000 * 102 / 255 = 16_000 at 25 kHz, channel enabled.
        if narf_power::thermal::set_cooling_level(128).is_err() {
            narf_pwm::unregister_controller(0x2a);
            return TestResult::Fail("set_cooling_level rejected");
        }
        narf_scheduler::run_until_empty();
        match pwm.last(3) {
            Some((cfg, true)) => {
                if cfg.frequency_hz != 25_000
                    || cfg.duty_cycle_ns != 16_000
                    || cfg.polarity != Polarity::Normal
                {
                    narf_pwm::unregister_controller(0x2a);
                    return TestResult::Fail("governor level 128 drove the wrong PWM config");
                }
            }
            _ => {
                narf_pwm::unregister_controller(0x2a);
                return TestResult::Fail("fan channel 3 was not enabled by the governor drive");
            }
        }
        // Level 0 disables the channel.
        if narf_power::thermal::set_cooling_level(0).is_err() {
            narf_pwm::unregister_controller(0x2a);
            return TestResult::Fail("set_cooling_level(0) rejected");
        }
        narf_scheduler::run_until_empty();
        match pwm.last(3) {
            Some((_, false)) => {}
            _ => {
                narf_pwm::unregister_controller(0x2a);
                return TestResult::Fail("level 0 must disable the fan channel");
            }
        }
        narf_pwm::unregister_controller(0x2a);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-fan",
        smoke_dt_pwm_fan_probe_registers_and_drives
    );

    fn smoke_pwm_fan_dt_driver_registers() -> TestResult {
        // The Subsys initcall's claim: the `pwm-fan` compatible
        // is registered with the bus DT-match table, so the
        // Stage::Device walk binds it. Unregister afterwards so
        // the global table is left as found.
        narf_bus::unregister_dt_driver(PWM_FAN_DT_DRIVER);
        register_dt_driver();
        let found = narf_bus::registered_dt_drivers()
            .iter()
            .any(|d| d.name == PWM_FAN_DT_DRIVER && d.compatible.contains(&"pwm-fan"));
        narf_bus::unregister_dt_driver(PWM_FAN_DT_DRIVER);
        if !found {
            return TestResult::Fail("pwm-fan DT driver was not registered");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-fan", smoke_pwm_fan_dt_driver_registers);
}
