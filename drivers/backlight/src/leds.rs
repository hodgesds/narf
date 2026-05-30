//! LED class — thin re-export from `narf-drivers-leds`.
//!
//! All types and registry functions are defined in the canonical
//! `narf-drivers-leds` crate. This module re-exports the subset that
//! the backlight subsystem uses so the `crate::leds::*` import paths
//! that callers inside this crate use remain stable.
//!
//! References (GPL-2.0-or-later):
//! - `drivers/leds/leds-class.c` — `led_classdev_register`.
//! - `include/linux/leds.h` — `led_classdev`, `led_trigger`.

extern crate alloc;

use alloc::sync::Arc;

// Re-export the canonical LED types from narf-drivers-leds.
pub use narf_drivers_leds::class::{
    led_devices, lookup_led_by_name as led_device, register_led, unregister_led, LedDevice,
    SimpleLed, __reset_for_test,
};
pub use narf_drivers_leds::triggers::Trigger;

/// Register the standard set of laptop-indicator LEDs. Called from
/// [`crate::register_initcalls`] at Stage::Device.
///
/// Follows the Linux LED naming convention (`leds-naming.rst`):
/// `<device>:<color>:<function>`.
///
/// Reference: `Documentation/leds/leds-class.rst`.
pub fn init() {
    register_led(Arc::new(SimpleLed::onoff("platform::power")));
    register_led(Arc::new(SimpleLed::onoff("input3::capslock")));
    register_led(Arc::new(SimpleLed::onoff("input3::scrolllock")));
    register_led(Arc::new(SimpleLed::onoff("input3::numlock")));

    let _ = core::fmt::Write::write_fmt(
        &mut narf_console::Writer,
        format_args!("  leds: registered power, capslock, scrolllock, numlock\n"),
    );
}
