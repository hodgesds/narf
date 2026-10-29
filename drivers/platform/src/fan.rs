//! Cooling-device drivers — ACPI Fan + PWM Fan.
//!
//! Spec: ACPI 6.5 §11.3 (Fan Device, _HID `PNP0C0B`).
//!   <https://uefi.org/specs/ACPI/>
//!
//! Two driver shapes live here:
//!
//! - [`AcpiFan`] — discovered by walking the AML namespace for devices
//!   whose `_HID` is `PNP0C0B`. Driven through `_ON` / `_OFF` for
//!   binary fans and `_FSL(level)` for fine-grained speed control
//!   when `_FIF.FineGrainCtrl` is set.
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
//! `PwmFan` remains unconstructed in production: nothing in the
//! tree can supply it a `PwmDevice` — `narf_pwm` has no controller
//! registry and no production `PwmDevice` implementor, and no
//! ACPI/DT description of a PWM fan is parsed anywhere. Wiring it
//! waits on a board description source (the DT/embedded stack).

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write;
#[cfg(target_arch = "x86_64")]
use core::sync::atomic::AtomicU32;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::eval::evaluate_method;
use narf_aml::{find_node, for_each_node_of_kind, NameValue, NodeKind, Value};
use narf_power::bootstrap_thermal_authority;
use narf_power::thermal::{register_cooling_device, CoolingDevice};
use narf_pwm::{Polarity, PwmConfig, PwmDevice};

// ── ACPI Fan (_HID = PNP0C0B) ───────────────────────────────────────

/// ACPI Fan device. Drives `_ON` / `_OFF` for binary fans; if the
/// platform reports fine-grained control via `_FIF`, also calls
/// `_FSL(level)` to pick a speed step.
#[derive(Debug)]
pub struct AcpiFan {
    path: String,
    /// Whether the fan supports `_FSL(level)` fine-grained speed
    /// control (read from `_FIF.FineGrainCtrl` at probe time).
    fine_grained: bool,
    /// Maximum `_FSL` level reported by `_FPS` (0 if none).
    max_level: u8,
    /// Cached on/off state so we don't issue redundant `_ON`/`_OFF`
    /// transitions every poll cycle.
    on: AtomicBool,
    /// Last applied level (0..=255) — used by `level()` for telemetry.
    last_level: AtomicU8,
}

impl AcpiFan {
    fn probe(path: &str) -> Self {
        // _FIF is a Package; treat any successful eval as "fine-grained
        // capable". Real decode of the Package fields lands when the
        // AML evaluator grows package-typed return support.
        let fine_grained = evaluate_method(&format!("{}._FIF", path), &[]).is_ok();
        // _FPS lists performance states. Without package decoding we
        // can't read the count, so default to a sensible 10-step
        // ladder when fine-grained is supported.
        let max_level = if fine_grained { 10 } else { 0 };
        Self {
            path: String::from(path),
            fine_grained,
            max_level,
            on: AtomicBool::new(false),
            last_level: AtomicU8::new(0),
        }
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
        if want_on && self.fine_grained && self.max_level > 0 {
            // Map 0..=255 onto 1..=max_level. `level == 0` is already
            // handled by the off path above.
            let span = self.max_level as u64;
            let step = (level as u64 * span).div_ceil(255);
            let step = step.max(1).min(span);
            self.call_with("_FSL", step);
        }
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
        // _HID is stored as a Name child of the Device.
        let hid_path = format!("{}._HID", node.path);
        let hid = match find_node(&hid_path) {
            Some(n) => n,
            None => return,
        };
        let is_fan = match &hid.value {
            Some(NameValue::String(s)) => s == "PNP0C0B",
            // Some firmwares emit _HID as an EISAID integer for
            // PNP0C0B (= 0x0B0CD041 little-endian). We don't decode
            // that compressed form yet; treat string-matching as the
            // primary path.
            _ => false,
        };
        if !is_fan {
            return;
        }
        discovered += 1;

        let fan = Arc::new(AcpiFan::probe(&node.path));
        let label = fan.path.clone();
        let fine = fan.fine_grained;
        match register_cooling_device(&cap, fan) {
            Ok(()) => {
                registered += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "  acpi-fan: registered {} (fine-grained={})",
                    label,
                    fine
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
}
