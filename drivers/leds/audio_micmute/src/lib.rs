//! `audio-micmute` LED trigger — loadable module only.
//!
//! The first trigger module (tracker #2448, KABI design §1.5/§4.8).
//! It registers the `audio-micmute` trigger through
//! `narf_led_register_trigger` and computes the LED level from the
//! core mic-mute bit (`narf_led_audio_mic_muted`, which defaults
//! `false` until the lane-4 sound feed lands).
//!
//! There is NO builtin duplicate by design: the trigger exists only
//! as a `.ko`, so the `builtin` build registers nothing. The micmute
//! LED (`platform::micmute`) names `audio-micmute` as its default
//! trigger through the LED core's default-trigger map, which
//! resolves it when this module loads — even if the LED driver
//! loaded first.

#![no_std]

use narf_driver_macros::narf_driver;

pub mod trigger;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "audio-micmute",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "audio-micmute LED trigger (loadable module only)",
        target_domain: "leds",
        required_caps: "PlatformDriver:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    // No builtin duplicate by design (KABI design §6.8): the
    // trigger exists only as a loadable module.
}

#[cfg(feature = "module")]
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    module_probe::exit();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
