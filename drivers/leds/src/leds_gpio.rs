//! GPIO-backed LED driver.
//!
//! Wraps a `GpioController` pin. Setting brightness to 0 clears the
//! pin; any non-zero brightness sets it. Active-low LEDs invert the
//! polarity.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/leds/leds-gpio.c` — `gpio_led_set`, `create_gpio_led`,
//!   `gpio_leds_create`. Active-low inversion at line 44–48.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_drivers_gpio::GpioController;
use narf_lib::sync::IrqSafeSpinLock;

use crate::class::LedDevice;
use crate::triggers::Trigger;

// ── Default state for GPIO LEDs ────────────────────────────────────

/// Initial LED state at registration time.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DefaultState {
    /// LED is off at boot (pin driven to inactive level).
    Off,
    /// LED is on at boot (pin driven to active level).
    On,
    /// LED keeps whatever state firmware left it in.
    KeepState,
}

// ── LedGpio ────────────────────────────────────────────────────────

/// GPIO-backed LED device.
///
/// Created via [`LedGpio::new`] and registered with
/// [`crate::register_led`].
#[derive(Debug)]
pub struct LedGpio {
    /// `/sys/class/leds/<name>` path component.
    name: String,
    /// GPIO controller that owns the pin.
    ctrl: Arc<dyn GpioController>,
    /// Pin index within `ctrl`.
    pin: u16,
    /// If true the pin logic is inverted: brightness > 0 → pin low,
    /// brightness 0 → pin high. Matches Linux's `gpiod_is_active_low`
    /// in `leds-gpio.c:gpio_led_set` (line 44).
    active_low: bool,
    /// Always 1 for a simple on/off GPIO LED.
    max_brightness: u32,
    /// Last written brightness — atomic so `brightness()` doesn't
    /// need to round-trip to hardware.
    cur_brightness: AtomicU32,
    /// Active trigger (locked).
    trigger: IrqSafeSpinLock<Trigger>,
}

impl LedGpio {
    /// Create a new GPIO LED.
    ///
    /// # Arguments
    ///
    /// - `name` — sysfs name, e.g. `"platform::power"`.
    /// - `ctrl` — GPIO controller that owns the pin.
    /// - `pin` — pin index within `ctrl`.
    /// - `active_low` — `true` if the LED anode is pulled to VCC and
    ///   the GPIO sinks current (active-low wiring).
    /// - `default_state` — initial brightness to apply at construction.
    pub fn new(
        name: impl Into<String>,
        ctrl: Arc<dyn GpioController>,
        pin: u16,
        active_low: bool,
        default_state: DefaultState,
    ) -> Self {
        let initial = match default_state {
            DefaultState::On => 1,
            DefaultState::Off | DefaultState::KeepState => 0,
        };
        let led = Self {
            name: name.into(),
            ctrl,
            pin,
            active_low,
            max_brightness: 1,
            cur_brightness: AtomicU32::new(initial),
            trigger: IrqSafeSpinLock::new(Trigger::None),
        };
        // Drive the pin to match the default state.
        if default_state != DefaultState::KeepState {
            led.apply_brightness(initial);
        }
        led
    }

    fn apply_brightness(&self, level: u32) {
        // active_low inverts: level > 0 → drive low (false), 0 → drive high (true).
        let pin_high = if self.active_low { level == 0 } else { level > 0 };
        // Ignore errors — hardware might not be present on QEMU.
        let _ = self.ctrl.set_pin(self.pin, pin_high);
    }
}

impl LedDevice for LedGpio {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max_brightness
    }

    fn brightness(&self) -> u32 {
        self.cur_brightness.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        let clamped = level.min(self.max_brightness);
        self.cur_brightness.store(clamped, Ordering::Release);
        self.apply_brightness(clamped);
    }

    fn current_trigger(&self) -> Trigger {
        self.trigger.lock().clone()
    }

    fn set_trigger(&self, trigger: Trigger) {
        *self.trigger.lock() = trigger;
    }
}
