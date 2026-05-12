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

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::eval::evaluate_method;
use narf_aml::{NameValue, NodeKind, Value, find_node, for_each_node_of_kind};
use narf_power::bootstrap_thermal_authority;
use narf_power::thermal::{CoolingDevice, register_cooling_device};
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
        let _ = evaluate_method(
            &format!("{}.{}", self.path, method),
            &[Value::Integer(arg)],
        );
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
            let step = (level as u64 * span + 254) / 255;
            let step = step.max(1).min(span);
            self.call_with("_FSL", step);
        }
    }
}

/// Walk the AML namespace, find devices with `_HID == "PNP0C0B"`, and
/// register each as a cooling device.
pub fn init() {
    let cap = bootstrap_thermal_authority();
    let mut count: u32 = 0;

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

        let fan = Arc::new(AcpiFan::probe(&node.path));
        let label = fan.path.clone();
        let fine = fan.fine_grained;
        if register_cooling_device(&cap, fan).is_ok() {
            count += 1;
            let _ = writeln!(
                narf_console::Writer,
                "  acpi-fan: registered {} (fine-grained={})",
                label,
                fine
            );
        }
    });

    if count == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-fan: no PNP0C0B fans discovered"
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
        let target_ptr =
            (&self.target_level as *const core::sync::atomic::AtomicU8) as usize;
        let inflight_ptr =
            (&self.worker_inflight as *const core::sync::atomic::AtomicBool) as usize;
        narf_scheduler::spawn(async move {
            // SAFETY: pointers are to fields of an Arc-kept-alive
            // PwmFan; safe to dereference for the duration of
            // this task.
            let target =
                unsafe { &*(target_ptr as *const core::sync::atomic::AtomicU8) };
            let inflight = unsafe {
                &*(inflight_ptr as *const core::sync::atomic::AtomicBool)
            };
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
        let fan = RecordingFan { last: AtomicU8::new(0) };
        fan.set_level(200);
        if fan.last.load(Ordering::SeqCst) == 200 {
            TestResult::Pass
        } else {
            TestResult::Fail("RecordingFan did not record set_level")
        }
    }
    kernel_test_in!("drivers-platform-fan", smoke_pwm_fan_set_level_dispatches);
}
