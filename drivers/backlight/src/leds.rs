//! LED class abstraction — `/sys/class/leds/*`.
//!
//! Mirrors Linux's `include/linux/leds.h` (`led_classdev`) and
//! `drivers/leds/leds-class.c`.
//!
//! Each device exposes:
//!   - `name()` → the sysfs directory name.
//!   - `max_brightness()` / `current_brightness()` → step values.
//!   - `set_brightness(level)` → direct control.
//!   - `set_trigger(trigger)` → attach a software trigger
//!     (heartbeat blink, disk-activity, etc.).
//!
//! Standard LED names follow the Linux `leds-naming.rst` convention:
//!   `<device>:<color>:<function>` e.g. `"input3::capslock"`,
//!   `"platform::kbd_backlight"`, `"platform::power"`.
//!
//! ## Standard LED set registered at boot
//!
//! - `platform::power` — chassis power LED.
//! - `input3::capslock` — CapsLock indicator (fed by HID layer).
//! - `input3::scrolllock` — ScrollLock indicator.
//! - `input3::numlock` — NumLock indicator.
//!
//! WiFi and battery indicator LEDs are registered by their respective
//! subsystems (wireless, power) once those devices are probed.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `include/linux/leds.h` — `led_classdev`, `led_trigger`.
//! - `drivers/leds/leds-class.c` — `led_classdev_register_ext`,
//!   `led_trigger_register`.
//! - `drivers/leds/trigger/ledtrig-heartbeat.c` — heartbeat trigger.
//! - `drivers/leds/trigger/ledtrig-disk.c` — disk-activity trigger.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Trigger ────────────────────────────────────────────────────────

/// Software trigger for a LED device. When a trigger is active the
/// kernel drives the LED brightness autonomously; direct writes via
/// `set_brightness` are ignored until the trigger is cleared with
/// `Trigger::None`.
///
/// Reference: Linux `drivers/leds/led-triggers.c`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// No trigger; brightness is directly controlled.
    None,
    /// 1 Hz heartbeat blink (LED_TRIGGER_ONESHOT style): on 100 ms,
    /// off 900 ms. Indicates the system is alive.
    Heartbeat,
    /// Blinks on storage-device activity (read or write).
    DiskActivity,
    /// Mirrors the AC-adapter connected / disconnected state.
    AcOnline,
    /// Mirrors battery charging state.
    BatteryCharging,
    /// Blinks on network TX/RX.
    NetActivity,
}

// ── LedDevice trait ────────────────────────────────────────────────

/// Trait implemented by every LED device registered with the
/// subsystem. Mirrors Linux's `led_classdev` ops.
pub trait LedDevice: Send + Sync + core::fmt::Debug {
    /// sysfs name, e.g. `"input3::capslock"`.
    fn name(&self) -> &str;
    /// Maximum brightness level (typically 255 for brightness LEDs;
    /// 1 for simple on/off indicators).
    fn max_brightness(&self) -> u32;
    /// Current brightness (hardware-read or cached).
    fn current_brightness(&self) -> u32;
    /// Set brightness to `level`. Clamped to `max_brightness()`.
    fn set_brightness(&self, level: u32);
    /// Attach or clear a software trigger. When set, the LED is
    /// driven by the trigger source; direct `set_brightness` calls
    /// are suppressed.
    fn set_trigger(&self, trigger: Trigger);
    /// Currently-attached trigger.
    fn trigger(&self) -> Trigger;
}

// ── SimpleLed — generic no-HW LED ─────────────────────────────────

/// A simple LED device that holds state in atomics without touching
/// hardware. Used for standard indicators (CapsLock, NumLock,
/// ScrollLock) that are driven by the HID / input layer, not by a
/// physical GPIO driver.
///
/// Hardware-backed LEDs (e.g. a GPIO LED) implement `LedDevice`
/// directly.
#[derive(Debug)]
pub struct SimpleLed {
    pub name: String,
    max: u32,
    brightness: AtomicU32,
    trigger: core::sync::atomic::AtomicU8,
}

impl SimpleLed {
    /// Build a simple on/off LED (max = 1).
    pub fn onoff(name: &str) -> Self {
        Self {
            name: name.to_string(),
            max: 1,
            brightness: AtomicU32::new(0),
            trigger: core::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Build a brightness-capable LED (max = 255).
    pub fn brightness_led(name: &str) -> Self {
        Self {
            name: name.to_string(),
            max: 255,
            brightness: AtomicU32::new(0),
            trigger: core::sync::atomic::AtomicU8::new(0),
        }
    }
}

fn trigger_to_u8(t: Trigger) -> u8 {
    match t {
        Trigger::None => 0,
        Trigger::Heartbeat => 1,
        Trigger::DiskActivity => 2,
        Trigger::AcOnline => 3,
        Trigger::BatteryCharging => 4,
        Trigger::NetActivity => 5,
    }
}

fn u8_to_trigger(v: u8) -> Trigger {
    match v {
        1 => Trigger::Heartbeat,
        2 => Trigger::DiskActivity,
        3 => Trigger::AcOnline,
        4 => Trigger::BatteryCharging,
        5 => Trigger::NetActivity,
        _ => Trigger::None,
    }
}

impl LedDevice for SimpleLed {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max
    }

    fn current_brightness(&self) -> u32 {
        self.brightness.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        // Suppressed when a trigger is active (matches Linux behaviour).
        if self.trigger() == Trigger::None {
            self.brightness.store(level.min(self.max), Ordering::Release);
        }
    }

    fn set_trigger(&self, trigger: Trigger) {
        self.trigger
            .store(trigger_to_u8(trigger), Ordering::Release);
        // When clearing the trigger, preserve last brightness.
    }

    fn trigger(&self) -> Trigger {
        u8_to_trigger(self.trigger.load(Ordering::Acquire))
    }
}

// ── Global LED registry ────────────────────────────────────────────

static LED_DEVS: IrqSafeSpinLock<Vec<Arc<dyn LedDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// Register a LED device. Duplicate names replace the existing entry.
pub fn register_led(dev: Arc<dyn LedDevice>) {
    let name = dev.name().to_string();
    let mut g = LED_DEVS.lock();
    if let Some(slot) = g.iter_mut().find(|d| d.name() == name) {
        *slot = dev;
    } else {
        g.push(dev);
    }
}

/// Unregister a LED device by name.
pub fn unregister_led(name: &str) {
    LED_DEVS.lock().retain(|d| d.name() != name);
}

/// Return a snapshot of all registered LED devices.
pub fn led_devices() -> Vec<Arc<dyn LedDevice>> {
    LED_DEVS.lock().clone()
}

/// Find a LED device by name.
pub fn led_device(name: &str) -> Option<Arc<dyn LedDevice>> {
    LED_DEVS.lock().iter().find(|d| d.name() == name).cloned()
}

/// Test helper: drain the LED registry.
#[doc(hidden)]
pub fn __reset_for_test() {
    LED_DEVS.lock().clear();
}

// ── Standard boot LEDs ─────────────────────────────────────────────

/// Register the standard set of laptop-indicator LEDs. Called from
/// [`crate::register_initcalls`] at Stage::Device.
///
/// Follows the Linux LED naming convention (`leds-naming.rst`):
/// `<device>:<color>:<function>` — where known; bare function name
/// for platform indicators.
///
/// Reference: `Documentation/leds/leds-class.rst`.
pub fn init() {
    // Power LED.
    register_led(Arc::new(SimpleLed::onoff("platform::power")));
    // Keyboard indicator LEDs — driven by the HID layer.
    register_led(Arc::new(SimpleLed::onoff("input3::capslock")));
    register_led(Arc::new(SimpleLed::onoff("input3::scrolllock")));
    register_led(Arc::new(SimpleLed::onoff("input3::numlock")));

    let _ = writeln!(
        narf_console::Writer,
        "  leds: registered power, capslock, scrolllock, numlock"
    );
}
