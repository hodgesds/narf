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

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::eval::{evaluate_method, evaluate_object};
use narf_aml::{device_hid, for_each_node_of_kind, NodeKind, Value};
use narf_power::bootstrap_thermal_authority;
use narf_power::thermal::{register_cooling_device, CoolingDevice};
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

// ── PWM Fan ─────────────────────────────────────────────────────────

/// Generic PWM-controlled fan. Used on platforms that expose the fan
/// via a PWM controller (DT-described boards, embedded SBC laptops).
pub struct PwmFan {
    name: &'static str,
    pwm: Arc<dyn PwmDevice>,
    channel: u32,
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
        Self {
            name,
            pwm,
            channel,
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
            // Standard PC / Intel 4-wire fan: 25 kHz PWM.
            const FREQ: u32 = 25_000;
            const PERIOD_NS: u64 = 1_000_000_000u64 / FREQ as u64;
            loop {
                let lvl = target.load(Ordering::Acquire);
                let duty_ns = (PERIOD_NS * lvl as u64) / 255;
                let cfg = PwmConfig {
                    frequency_hz: FREQ,
                    duty_cycle_ns: duty_ns,
                    polarity: Polarity::Normal,
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

// ── Smoke tests ─────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU8, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

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
            b"_ON",
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
            b"_ON",
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
}
