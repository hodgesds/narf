//! LED trigger types and the 100 ms trigger engine.
//!
//! A trigger is an automatic blink/ramp pattern that drives an LED
//! without userspace polling. The engine wakes every 100 ms, iterates
//! all registered LEDs that have a non-None trigger, and updates
//! brightness accordingly.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/leds/trigger/ledtrig-heartbeat.c` — heartbeat ramp calc.
//! - `drivers/leds/trigger/ledtrig-timer.c` — square-wave on/off.
//! - `drivers/leds/trigger/ledtrig-disk.c` — disk-activity blink.
//! - `drivers/leds/trigger/ledtrig-netdev.c` — network-activity blink.
//! - `drivers/leds/trigger/ledtrig-oneshot.c` — one-shot pulse.

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

use crate::class::led_devices;

// ── Trigger enum ───────────────────────────────────────────────────

/// LED trigger — automatic blink/ramp pattern.
///
/// Mirrors Linux's `struct led_trigger` / named trigger strings
/// (`include/linux/leds.h`, `drivers/leds/led-core.c:__led_set_trigger`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// No trigger — brightness is under direct userspace/driver control.
    None,

    /// LED stays fully on at boot. Mirrors Linux `default-on` trigger
    /// (`drivers/leds/trigger/ledtrig-default-on.c`).
    DefaultOn,

    /// Ramp pattern that mimics a heartbeat over a 1 s cycle.
    /// Matches Linux's `heartbeat` trigger brightness curve
    /// (`drivers/leds/trigger/ledtrig-heartbeat.c`).
    Heartbeat,

    /// Square-wave blink: on for `on_ms`, off for `off_ms`.
    /// Mirrors Linux's `timer` trigger
    /// (`drivers/leds/trigger/ledtrig-timer.c`).
    Timer { on_ms: u32, off_ms: u32 },

    /// Single pulse after `delay_ms`, staying on for `on_ms` then
    /// off for `off_ms`. Mirrors Linux's `oneshot` trigger
    /// (`drivers/leds/trigger/ledtrig-oneshot.c`).
    OneShot {
        delay_ms: u32,
        on_ms: u32,
        off_ms: u32,
    },

    /// Blink on block I/O completion. Mirrors Linux's `disk-activity`
    /// trigger (`drivers/leds/trigger/ledtrig-disk.c`). Stubbed —
    /// wires to block registry when available.
    DiskActivity,

    /// Blink on NIC frame events. Mirrors Linux's `netdev` trigger
    /// (`drivers/leds/trigger/ledtrig-netdev.c`). `iface` = interface
    /// name, e.g. `"eth0"`.
    NetworkActivity { iface: &'static str },

    /// Reflect keyboard Caps Lock state. Set via HID SET_REPORT bridge
    /// (`drivers/leds/leds-input.c` analogue).
    KeyboardCapsLock,

    /// Reflect keyboard Num Lock state.
    KeyboardNumLock,

    /// Reflect keyboard Scroll Lock state.
    KeyboardScrollLock,

    /// Mirrors AC-adapter connected / disconnected state.
    /// Matches Linux's `ac-online` trigger.
    AcOnline,

    /// Mirrors battery charging state.
    /// Matches Linux's `charging` trigger.
    BatteryCharging,
}

// ── Trigger engine ─────────────────────────────────────────────────

/// Per-LED engine state — tracks phase within the current trigger
/// cycle. Keyed on the LED name; the engine keeps a parallel list
/// so state survives across registry lookups.
#[derive(Debug)]
struct EngineState {
    /// LED name — owned copy so no lifetime coupling to the Arc.
    name: alloc::string::String,
    /// Elapsed time in units of 100 ms ticks since trigger installed.
    ticks: u32,
}

static ENGINE: IrqSafeSpinLock<alloc::vec::Vec<EngineState>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Drive one tick of the trigger engine (called every 100 ms).
///
/// For each registered LED whose trigger is not `None`:
/// - Compute the desired brightness for this tick.
/// - Call `set_brightness`.
/// - Advance the per-LED tick counter.
///
/// Allocates a snapshot of `led_devices()` so it can release the
/// registry lock before calling `set_brightness` (which may itself
/// take per-device locks).
pub fn tick() {
    let devs = led_devices();
    let mut eng = ENGINE.lock();

    for dev in &devs {
        let trigger = dev.current_trigger();
        if matches!(trigger, Trigger::None) {
            continue;
        }

        // Find or create the per-LED tick counter.
        let dev_name = dev.name();
        let state = if let Some(s) = eng.iter_mut().find(|s| s.name == dev_name) {
            s
        } else {
            eng.push(EngineState {
                name: alloc::string::String::from(dev_name),
                ticks: 0,
            });
            eng.last_mut().unwrap()
        };

        let max = dev.max_brightness();
        // Release ENGINE lock transiently? No — we hold it for the
        // whole snapshot pass; set_brightness must not re-enter here.
        // This is safe because set_brightness never calls tick().
        let b = compute_brightness(&trigger, state.ticks, max);
        dev.set_brightness(b);
        state.ticks = state.ticks.wrapping_add(1);
    }
}

/// Compute the brightness for a given trigger at `ticks` (100 ms units).
///
/// All trigger curves normalised to `[0, max]`.
pub(crate) fn compute_brightness(trigger: &Trigger, ticks: u32, max: u32) -> u32 {
    match trigger {
        Trigger::None
        | Trigger::DiskActivity
        | Trigger::NetworkActivity { .. }
        | Trigger::KeyboardCapsLock
        | Trigger::KeyboardNumLock
        | Trigger::KeyboardScrollLock
        | Trigger::AcOnline
        | Trigger::BatteryCharging => 0,

        Trigger::DefaultOn => max,

        // Heartbeat: two quick pulses at t=0 and t=200ms within a 1 s
        // cycle, then off for the remainder.
        // Matches Linux's heartbeat_trig.c brightness table shape:
        // pulse at 0–100 ms, off 100–200 ms, pulse at 200–300 ms, off rest.
        Trigger::Heartbeat => {
            let phase = ticks % 10; // 10 ticks = 1 s
            match phase {
                0 => max,     // first pulse on
                1 => max / 2, // first pulse decay
                2 => max,     // second pulse on
                3 => max / 2, // second pulse decay
                _ => 0,       // off for 600 ms
            }
        }

        // Timer: square wave.  on_ms and off_ms are in milliseconds;
        // ticks are 100 ms units.
        Trigger::Timer { on_ms, off_ms } => {
            let period_ticks = (on_ms + off_ms) / 100;
            if period_ticks == 0 {
                return max;
            }
            let phase = ticks % period_ticks;
            let on_ticks = on_ms / 100;
            if phase < on_ticks {
                max
            } else {
                0
            }
        }

        // OneShot: delay, then one pulse.
        Trigger::OneShot {
            delay_ms,
            on_ms,
            off_ms,
        } => {
            let delay_ticks = delay_ms / 100;
            let on_ticks = on_ms / 100;
            let _off_ticks = off_ms / 100;
            if ticks < delay_ticks {
                0
            } else if ticks < delay_ticks + on_ticks {
                max
            } else {
                0
            }
        }
    }
}

/// Reset engine state for tests.
#[doc(hidden)]
pub fn __reset_for_test() {
    ENGINE.lock().clear();
}

/// Test helper: expose `compute_brightness` for smoke tests.
#[doc(hidden)]
#[cfg(any(test, feature = "kernel-test"))]
pub fn __compute_brightness_for_test(trigger: &Trigger, ticks: u32, max: u32) -> u32 {
    compute_brightness(trigger, ticks, max)
}
