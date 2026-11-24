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
//! - `drivers/leds/trigger/ledtrig-audio.c` — audio-mute level.

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

    /// LED on while the audio mixer is muted, off otherwise.
    /// Mirrors Linux's `audio-mute` trigger
    /// (`drivers/leds/trigger/ledtrig-audio.c`: `ledtrig_audio_mute`
    /// drives the LED to `LED_FULL` on mute, `LED_OFF` on unmute).
    /// The mute state is fed by the sound subsystem — see
    /// [`set_audio_muted`]; the engine samples it on every tick,
    /// so the LED follows the mixer within one 100 ms tick.
    AudioMute,

    /// A trigger implemented by a loadable module (Linux
    /// `led_trigger_register`; triggers are `tristate` modules).
    /// The payload is the module-trigger registry handle
    /// (allocated by [`register_module_trigger`]); the core never
    /// calls into module text directly — the engine calls the
    /// registered closure, which the modules crate built around
    /// the module call gate, and clamps the result to
    /// `[0, max_brightness]`. The first trigger module is
    /// `audio-micmute` (tracker #2448).
    Module(u64),
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

/// Current audio-mute state, as reported by the sound subsystem.
///
/// Linux's `ledtrig-audio` keeps the mute state in the trigger's
/// private data, updated by `ledtrig_audio_mute()` from
/// `sound/core/control_led.c` whenever the Master Playback Switch
/// changes. NARF keeps the same single bit here: the mixer feed
/// (`drivers/sound/src/mixer.rs::set`) writes it, and the engine
/// reads it. Default `false` (unmuted) matches the mixer's initial
/// Master Playback Switch value (`ControlValue::boolean(true)` =
/// unmute) at `register_standard_realtek` time.
///
/// (An earlier revision of this comment also named the USB UAC card
/// and virtio-snd as feeders; a tree-wide search at tip `61b7a28a`
/// finds no `set_audio_muted` call site in either — the mixer is
/// the only feeder. Tracker #2448.)
static AUDIO_MUTED: AtomicBool = AtomicBool::new(false);

/// Report a mixer mute change into the audio-mute trigger.
///
/// Called by the sound subsystem when the Master Playback Switch
/// changes (`true` = muted). The trigger engine picks the new state
/// up on its next 100 ms tick; no LED is driven synchronously here.
pub fn set_audio_muted(muted: bool) {
    AUDIO_MUTED.store(muted, Ordering::Release);
}

/// Current audio-mute state as last reported by the sound
/// subsystem (`false` before any mixer mute change).
pub fn audio_muted() -> bool {
    AUDIO_MUTED.load(Ordering::Acquire)
}

/// Current audio *mic*-mute state, as reported by the sound
/// subsystem. The mic-mute counterpart of [`AUDIO_MUTED`]: Linux's
/// `ledtrig-audio` covers both mute and mic-mute in one trigger
/// (`LEDS_TRIGGER_AUDIO`); NARF splits them because `AudioMute`
/// already exists builtin and the mic-mute trigger is born as a
/// module (tracker #2448, KABI design §1.5/§4.8).
///
/// The feed is audit lane 4's builtin sound work — a mic-mute
/// control in the sound subsystem calling [`set_audio_micmuted`].
/// Until it lands the bit stays `false` and the `audio-micmute`
/// trigger module reads "unmuted". Do not invent a feed here.
static AUDIO_MICMUTED: AtomicBool = AtomicBool::new(false);

/// Report a mic-mute change into the audio-micmute trigger module.
///
/// Called by the sound subsystem when the mic-mute state changes
/// (`true` = mic muted). The `audio-micmute` trigger module reads
/// the bit through the KABI (`narf_led_audio_mic_muted`) on its
/// next tick; no LED is driven synchronously here.
pub fn set_audio_micmuted(muted: bool) {
    AUDIO_MICMUTED.store(muted, Ordering::Release);
}

/// Current audio mic-mute state as last reported by the sound
/// subsystem (`false` before any mic-mute change — and until the
/// lane-4 sound feed lands).
pub fn audio_mic_muted() -> bool {
    AUDIO_MICMUTED.load(Ordering::Acquire)
}

// ── Module triggers ────────────────────────────────────────────────

/// A trigger implemented by a loadable module.
///
/// The closure is built by the modules crate around the module
/// call gate: `compute(max_brightness, ticks)` returns the desired
/// brightness for this 100 ms tick; the engine clamps the result
/// to `[0, max_brightness]`. The core never calls into module text
/// directly, and never holds the registry lock while calling the
/// closure (the engine snapshots the `Arc` first).
struct ModuleTrigger {
    /// Sysfs name, e.g. `"audio-micmute"`.
    name: alloc::string::String,
    /// `compute(max_brightness, ticks) -> brightness`.
    compute: alloc::sync::Arc<dyn Fn(u32, u32) -> u32 + Send + Sync>,
}

/// Module-trigger registry: handle → trigger. Handles start at 1
/// (`0` is never a valid handle); the counter never wraps in
/// practice. The registry is keyed by handle because the LED's
/// `Trigger::Module(handle)` must survive a trigger-name lookup
/// without holding the lock.
static MODULE_TRIGGERS: IrqSafeSpinLock<alloc::vec::Vec<(u64, ModuleTrigger)>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

static NEXT_MODULE_TRIGGER_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Look up a module trigger's compute closure by handle. Snapshots
/// the `Arc` under the registry lock and releases it before the
/// caller invokes the closure.
fn lookup_module_trigger(
    handle: u64,
) -> Option<alloc::sync::Arc<dyn Fn(u32, u32) -> u32 + Send + Sync>> {
    MODULE_TRIGGERS
        .lock()
        .iter()
        .find(|(h, _)| *h == handle)
        .map(|(_, t)| t.compute.clone())
}

/// Register a module trigger. Returns the registry handle the
/// LED's `Trigger::Module(handle)` carries, or `-EINVAL` for an
/// empty name, `-EEXIST` when a builtin trigger or an already
/// registered module trigger has this name. Builtin names win on
/// collision (the module trigger is rejected, not shadowed).
/// Registers a pending default trigger for any LED whose default
/// is this name (see [`set_led_default_trigger`]).
///
/// Ownership (which module registered which trigger) is tracked
/// by the modules crate's `TRIGGER_OWNERS` table, not here — the
/// core registry is name → closure only, so it carries no
/// never-read owner field.
pub fn register_module_trigger(
    name: &str,
    compute: alloc::sync::Arc<dyn Fn(u32, u32) -> u32 + Send + Sync>,
) -> Result<u64, i32> {
    if name.is_empty() || is_builtin_trigger_name(name) {
        return Err(if name.is_empty() { -22 } else { -17 });
    }
    let mut reg = MODULE_TRIGGERS.lock();
    if reg.iter().any(|(_, t)| t.name == name) {
        return Err(-17); // -EEXIST
    }
    let handle = NEXT_MODULE_TRIGGER_HANDLE.fetch_add(1, Ordering::Relaxed);
    reg.push((
        handle,
        ModuleTrigger {
            name: alloc::string::String::from(name),
            compute,
        },
    ));
    drop(reg);
    resolve_pending_defaults_for(name);
    Ok(handle)
}

/// Unregister a module trigger by name. Returns `-ENODEV` when no
/// module trigger has this name, `-EBUSY` while any LED's current
/// trigger is this trigger (move those LEDs first — the loader
/// backstop force-reverts them instead, see
/// [`force_unregister_module_trigger`]).
///
/// A sysfs write installing this trigger on a LED between the
/// in-use check and the removal is a pathological userspace race;
/// the consequence is bounded: the LED keeps
/// `Trigger::Module(handle)` with no registry entry, and the
/// engine computes `0` (dark) for it until its trigger changes.
pub fn unregister_module_trigger(name: &str) -> Result<(), i32> {
    let handle = {
        let reg = MODULE_TRIGGERS.lock();
        match reg.iter().find(|(_, t)| t.name == name) {
            Some((h, _)) => *h,
            None => return Err(-19), // -ENODEV
        }
    };
    for dev in led_devices() {
        if dev.current_trigger() == Trigger::Module(handle) {
            return Err(-16); // -EBUSY
        }
    }
    MODULE_TRIGGERS.lock().retain(|(_, t)| t.name != name);
    Ok(())
}

/// Force-unregister a module trigger by name (loader backstop):
/// revert every LED using it to `Trigger::None` first, then remove
/// the registry entry. Returns whether an entry existed.
pub fn force_unregister_module_trigger(name: &str) -> bool {
    let handle = {
        let reg = MODULE_TRIGGERS.lock();
        match reg.iter().find(|(_, t)| t.name == name) {
            Some((h, _)) => *h,
            None => return false,
        }
    };
    for dev in led_devices() {
        if dev.current_trigger() == Trigger::Module(handle) {
            dev.set_trigger(Trigger::None);
        }
    }
    MODULE_TRIGGERS.lock().retain(|(_, t)| t.name != name);
    true
}

// ── Trigger ↔ name conversion ──────────────────────────────────────

/// Whether `name` is one of the builtin trigger names (the closed
/// match in [`trigger_from_name`]).
fn is_builtin_trigger_name(name: &str) -> bool {
    matches!(
        name,
        "none"
            | "default-on"
            | "heartbeat"
            | "timer"
            | "oneshot"
            | "disk-activity"
            | "netdev"
            | "network-activity"
            | "ac-online"
            | "charging"
            | "audio-mute"
    )
}

/// Convert a `Trigger` to its Linux sysfs name string. Returns
/// `None` for a `Module` trigger whose registry entry is gone
/// (unregistered between snapshot and display — the caller shows
/// `"none"` for that transient state).
/// Linux ref: `drivers/leds/led-triggers.c` trigger list.
pub fn name_of_trigger(trigger: &Trigger) -> Option<alloc::string::String> {
    use alloc::string::ToString;
    let name = match trigger {
        Trigger::None => "none",
        Trigger::DefaultOn => "default-on",
        Trigger::Heartbeat => "heartbeat",
        Trigger::Timer { .. } => "timer",
        Trigger::OneShot { .. } => "oneshot",
        Trigger::DiskActivity => "disk-activity",
        Trigger::NetworkActivity { .. } => "netdev",
        Trigger::KeyboardCapsLock => "capslock",
        Trigger::KeyboardNumLock => "numlock",
        Trigger::KeyboardScrollLock => "scrolllock",
        Trigger::AcOnline => "ac-online",
        Trigger::BatteryCharging => "charging",
        Trigger::AudioMute => "audio-mute",
        Trigger::Module(handle) => {
            return MODULE_TRIGGERS
                .lock()
                .iter()
                .find(|(h, _)| h == handle)
                .map(|(_, t)| t.name.clone());
        }
    };
    Some(name.to_string())
}

/// Parse a trigger name into a `Trigger` value. Builtin names win
/// on collision; module-trigger names resolve through the registry.
/// Returns `None` for unrecognised names.
/// Linux ref: `led_trigger_write` (led-triggers.c:52) string
/// comparison.
pub fn trigger_from_name(name: &str) -> Option<Trigger> {
    match name {
        "none" => Some(Trigger::None),
        "default-on" => Some(Trigger::DefaultOn),
        "heartbeat" => Some(Trigger::Heartbeat),
        "timer" => Some(Trigger::Timer {
            on_ms: 500,
            off_ms: 500,
        }),
        "oneshot" => Some(Trigger::OneShot {
            delay_ms: 0,
            on_ms: 100,
            off_ms: 100,
        }),
        "disk-activity" => Some(Trigger::DiskActivity),
        "netdev" | "network-activity" => Some(Trigger::NetworkActivity { iface: "eth0" }),
        "ac-online" => Some(Trigger::AcOnline),
        "charging" => Some(Trigger::BatteryCharging),
        "audio-mute" => Some(Trigger::AudioMute),
        _ => MODULE_TRIGGERS
            .lock()
            .iter()
            .find(|(_, t)| t.name == name)
            .map(|(h, _)| Trigger::Module(*h)),
    }
}

// ── Default triggers ───────────────────────────────────────────────

/// LED name → default trigger name (Linux
/// `led_trigger_set_default`, `leds.h` `default_trigger` field).
/// Recorded at LED registration; applied immediately when the
/// trigger resolves (builtin or already-loaded module), else kept
/// pending and re-resolved when a trigger with that name registers
/// — which is what lets the micmute LED get `audio-micmute` even
/// if the trigger module loads after the LED driver.
static DEFAULT_TRIGGERS: IrqSafeSpinLock<
    alloc::vec::Vec<(alloc::string::String, alloc::string::String)>,
> = IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Record a LED's default trigger and apply it now if it resolves.
/// Called by the KABI LED registration (and the builtin driver)
/// right after the LED is registered.
pub fn set_led_default_trigger(led_name: &str, trigger_name: &str) {
    let mut map = DEFAULT_TRIGGERS.lock();
    if let Some(entry) = map.iter_mut().find(|(led, _)| led == led_name) {
        entry.1 = alloc::string::String::from(trigger_name);
    } else {
        map.push((
            alloc::string::String::from(led_name),
            alloc::string::String::from(trigger_name),
        ));
    }
    drop(map);
    apply_pending_default(led_name);
}

/// Apply a LED's recorded default trigger if it resolves now.
/// Called after LED registration (the default may have been
/// recorded before the LED existed) and after trigger
/// registration (the trigger may have been missing when the LED
/// was registered).
pub fn apply_pending_default(led_name: &str) {
    let trigger_name = {
        let map = DEFAULT_TRIGGERS.lock();
        map.iter()
            .find(|(led, _)| led == led_name)
            .map(|(_, t)| t.clone())
    };
    let Some(trigger_name) = trigger_name else {
        return;
    };
    let Some(trigger) = trigger_from_name(&trigger_name) else {
        return;
    };
    if let Some(dev) = led_devices().into_iter().find(|d| d.name() == led_name) {
        dev.set_trigger(trigger);
    }
}

/// Re-resolve every pending default naming `trigger_name` — called
/// after a module trigger with that name registers.
fn resolve_pending_defaults_for(trigger_name: &str) {
    let leds: alloc::vec::Vec<alloc::string::String> = {
        let map = DEFAULT_TRIGGERS.lock();
        map.iter()
            .filter(|(_, t)| t == trigger_name)
            .map(|(led, _)| led.clone())
            .collect()
    };
    for led in leds {
        apply_pending_default(&led);
    }
}

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

        // Audio-mute: level, not a pattern — on while muted, off
        // while unmuted. Matches Linux `ledtrig_audio_mute()`
        // (`drivers/leds/trigger/ledtrig-audio.c`).
        Trigger::AudioMute => {
            if audio_muted() {
                max
            } else {
                0
            }
        }

        Trigger::DefaultOn => max,

        // Module trigger: call the registered compute closure
        // (snapshotted out of the registry first — the lock is
        // never held across module text) and clamp to [0, max].
        // A handle with no registry entry (unregistered between
        // the LED snapshot and this compute — the backstop reverts
        // LEDs first, so this is a transient race) computes dark.
        Trigger::Module(handle) => match lookup_module_trigger(*handle) {
            Some(compute) => core::cmp::min(compute(max, ticks), max),
            None => 0,
        },

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
    AUDIO_MUTED.store(false, Ordering::Release);
    AUDIO_MICMUTED.store(false, Ordering::Release);
    MODULE_TRIGGERS.lock().clear();
    NEXT_MODULE_TRIGGER_HANDLE.store(1, Ordering::Release);
    DEFAULT_TRIGGERS.lock().clear();
}

/// Test helper: expose `compute_brightness` for smoke tests.
#[doc(hidden)]
#[cfg(any(test, feature = "kernel-test"))]
pub fn __compute_brightness_for_test(trigger: &Trigger, ticks: u32, max: u32) -> u32 {
    compute_brightness(trigger, ticks, max)
}
