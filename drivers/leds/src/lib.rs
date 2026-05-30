//! LED class registry + standard LED drivers for NARF.
//!
//! This crate is the single registry point for all LED devices.
//! It exposes:
//!
//! - `/sys/class/leds/*` — LED devices (power LED, Caps Lock LED,
//!   Num Lock LED, Scroll Lock LED, charging LED, Wi-Fi LED, etc.).
//! - GPIO-backed LEDs ([`leds_gpio::LedGpio`]).
//! - PWM-backed dimmable LEDs ([`leds_pwm::LedPwm`]).
//! - HID keyboard LED bridges:
//!   [`leds_input_caps::LedCapsLock`],
//!   [`leds_input_num::LedNumLock`],
//!   [`leds_input_scroll::LedScrollLock`].
//! - Trigger engine ([`triggers`]) — drives Heartbeat, Timer, and
//!   OneShot patterns at 100 ms resolution.
//!
//! ## Architecture
//!
//! Devices register through [`LedDevice`] into a global
//! `Vec<Arc<dyn LedDevice>>` protected by [`narf_lib::sync::IrqSafeSpinLock`].
//! The trigger engine iterates triggered LEDs on every
//! [`triggers::tick`] call (intended to be called from a 100 ms timer
//! task registered via the scheduler).
//!
//! ## Coordination with the backlight crate
//!
//! The [`LedDevice`] trait and its registry live here. The backlight
//! crate's keyboard-backlight implementation imports this crate and
//! registers a [`LedPwm`] for the keyboard-backlight channel.
//!
//! ## References (GPL-2.0-or-later, direct citation allowed)
//!
//! - `drivers/leds/led-class.c` — `led_classdev_register` registry shape.
//! - `drivers/leds/led-core.c` — `led_set_brightness_nopm`, trigger dispatch.
//! - `drivers/leds/leds-gpio.c` — GPIO LED active-low inversion.
//! - `drivers/leds/leds-pwm.c` — PWM duty cycle formula (line 52).
//! - `drivers/hid/hid-input.c` — `hidinput_led_event` HID LED mask.
//! - `drivers/leds/trigger/ledtrig-heartbeat.c` — heartbeat ramp.
//! - `drivers/leds/trigger/ledtrig-timer.c` — square-wave trigger.
//! - `drivers/leds/trigger/ledtrig-oneshot.c` — one-shot trigger.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod class;
pub mod leds_gpio;
pub mod leds_input_caps;
pub mod leds_input_num;
pub mod leds_input_scroll;
pub mod leds_pwm;
pub mod triggers;

// Re-export the core types at crate root for convenience.
pub use class::{
    led_devices, lookup_led_by_name, register_led, unregister_led, LedDevice, SimpleLed,
    REGISTERED_COUNT,
};
pub use leds_gpio::{DefaultState, LedGpio};
pub use leds_input_caps::{
    register_set_report, unregister_set_report, LedCapsLock, SetReportFn,
    HID_LED_CAPS_LOCK, HID_LED_NUM_LOCK, HID_LED_SCROLL_LOCK,
};
pub use leds_input_num::LedNumLock;
pub use leds_input_scroll::LedScrollLock;
pub use leds_pwm::LedPwm;
pub use triggers::Trigger;

// ── initcalls ─────────────────────────────────────────────────────

/// Register LED subsystem initcalls. Call from the top-level
/// `drivers::register_initcalls()` during Stage::Device.
///
/// Currently registers:
/// - The trigger-engine tick task (100 ms interval, implemented as a
///   periodic wakeup once the scheduler's timer facility is wired up;
///   today it is a stub so the subsystem compiles and tests without
///   the full scheduler).
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "leds/class", || {
        // LED class has no hardware to probe; it is always present.
        InitResult::Ok
    });
}

/// Test helper: drain the LED registry and trigger-engine state.
#[doc(hidden)]
pub fn __reset_all_for_test() {
    class::__reset_for_test();
    triggers::__reset_for_test();
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
