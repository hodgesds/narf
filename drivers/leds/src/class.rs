//! LED class registry — `LedDevice` trait + global name-keyed registry.
//!
//! Every LED that the kernel manages registers here. Consumers (sysfs
//! adapters, power-management code, trigger engine) look up devices by
//! name or iterate the full list.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/leds/led-class.c` — `led_classdev_register`,
//!   `led_classdev_unregister`, `led_update_brightness`.
//! - `include/linux/leds.h` — `struct led_classdev` field layout.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::triggers::Trigger;

// ── LedDevice trait ────────────────────────────────────────────────

/// Single LED managed by the LED class.
///
/// Implementations are `Send + Sync` so the global registry can hold
/// them behind `Arc<dyn LedDevice>` from any context.
///
/// Design matches Linux's `led_classdev` ops surface
/// (`include/linux/leds.h:led_classdev`):
/// - `brightness_set` → `set_brightness`
/// - `brightness_get` → `brightness`
/// - `max_brightness` → `max_brightness`
pub trait LedDevice: Send + Sync + core::fmt::Debug {
    /// Short name used as the sysfs directory entry under
    /// `/sys/class/leds/<name>/`, e.g. `"input0::capslock"`,
    /// `"platform::power"`.
    fn name(&self) -> &str;

    /// Maximum brightness level. Hardware-specific; 1 for simple
    /// on/off GPIO LEDs, 255 for typical PWM LEDs.
    fn max_brightness(&self) -> u32;

    /// Current brightness. Returns 0 on any hardware-read failure.
    fn brightness(&self) -> u32;

    /// Drive the LED to `level`. Implementations clamp to
    /// `[0, max_brightness()]` before touching hardware.
    fn set_brightness(&self, level: u32);

    /// Active trigger that drives this LED. `Trigger::None` means
    /// userspace / driver controls brightness directly.
    fn current_trigger(&self) -> Trigger;

    /// Install a new trigger. The trigger engine picks this up on
    /// its next 100 ms tick.
    fn set_trigger(&self, trigger: Trigger);
}

// ── Global registry ────────────────────────────────────────────────

static LEDS: IrqSafeSpinLock<Vec<Arc<dyn LedDevice>>> = IrqSafeSpinLock::new(Vec::new());

/// Count of currently registered LED devices. Useful for diagnostics
/// that must not contend with the LEDS lock.
pub static REGISTERED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Register an LED device.
///
/// If a device with the same `name()` already exists it is replaced,
/// matching Linux's `led_classdev_register` idempotency convention
/// (`drivers/leds/led-class.c:led_classdev_register`).
pub fn register_led(dev: Arc<dyn LedDevice>) {
    let mut g = LEDS.lock();
    let name = dev.name();
    if let Some(slot) = g.iter_mut().find(|d| d.name() == name) {
        *slot = dev;
    } else {
        g.push(dev);
    }
    REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
}

/// Unregister a device by name. No-op if not present.
pub fn unregister_led(name: &str) {
    let mut g = LEDS.lock();
    g.retain(|d| d.name() != name);
    REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
}

/// Return a snapshot of all registered devices. Allocates.
pub fn led_devices() -> Vec<Arc<dyn LedDevice>> {
    LEDS.lock().clone()
}

/// Lookup a device by name.
pub fn lookup_led_by_name(name: &str) -> Option<Arc<dyn LedDevice>> {
    LEDS.lock().iter().find(|d| d.name() == name).cloned()
}

/// Test-only: drain the registry.
#[doc(hidden)]
pub fn __reset_for_test() {
    LEDS.lock().clear();
    REGISTERED_COUNT.store(0, Ordering::Release);
}

// ── SimpleLed — software-only LED ─────────────────────────────────

use alloc::string::String;

/// Simple LED device backed by an atomic brightness value and IRQ-safe trigger state
/// (no hardware GPIO/PWM).
///
/// Used for standard laptop indicator LEDs (CapsLock, NumLock,
/// ScrollLock, power) that are driven by the HID / input layer.
/// Hardware-backed LEDs use [`crate::leds_gpio::LedGpio`] or
/// [`crate::leds_pwm::LedPwm`] instead.
///
/// This matches the `SimpleLed` provided in Linux's generic LED
/// helpers — an in-kernel software LED class object.
#[derive(Debug)]
pub struct SimpleLed {
    /// sysfs name.
    pub name: String,
    max: u32,
    brightness: AtomicU32,
    trigger: IrqSafeSpinLock<Trigger>,
}

impl SimpleLed {
    /// Create a simple on/off LED (max_brightness = 1).
    pub fn onoff(name: &str) -> Self {
        Self {
            name: alloc::string::String::from(name),
            max: 1,
            brightness: AtomicU32::new(0),
            trigger: IrqSafeSpinLock::new(Trigger::None),
        }
    }

    /// Create a brightness-capable LED (max_brightness = 255).
    pub fn brightness_led(name: &str) -> Self {
        Self {
            name: alloc::string::String::from(name),
            max: 255,
            brightness: AtomicU32::new(0),
            trigger: IrqSafeSpinLock::new(Trigger::None),
        }
    }
}

impl LedDevice for SimpleLed {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max
    }

    fn brightness(&self) -> u32 {
        self.brightness.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        self.brightness
            .store(level.min(self.max), Ordering::Release);
    }

    fn current_trigger(&self) -> crate::triggers::Trigger {
        self.trigger.lock().clone()
    }

    fn set_trigger(&self, trigger: crate::triggers::Trigger) {
        *self.trigger.lock() = trigger;
    }
}
