//! ThinkPad LED driver — dual-build (built-in or loadable `.ko`).
//!
//! The LED half of `drivers/platform/thinkpad_acpi` (lane 2's corrected
//! surface: three per-mechanism setters, `GenericLed` + `u8` level +
//! `bool`, packed-`AtomicU32` state cache, wired 0x60C0 arm),
//! promoted into its own crate so it builds two ways from one source,
//! exactly like `drivers/wireless/mt76/` (the locked dual-build
//! template). Tracker #2448, KABI design §4-§6.
//!
//! Seven LEDs (`defs::LED_DEFS`): `tpacpi::kbd_backlight` (max 2),
//! `platform::mute` (max 1, default trigger `audio-mute`),
//! `platform::micmute` (max 1, default trigger `audio-micmute`),
//! and the four safe generic LEDs (`tpacpi::power`, `tpacpi::standby`,
//! `tpacpi::lid_logo_dot`, `tpacpi::thinkvantage`).
//!
//! The builtin backend (`builtin.rs`) calls the moved setters (AML
//! evaluation + state cache) directly; the module backend
//! (`module_probe.rs`) calls the same methods through the KABI
//! exports. Both share the probe/register/set logic (`driver.rs`)
//! behind the `Backend` trait, so the two builds cannot drift apart
//! in behavior — only in how they reach the hardware.
//!
//! DSDT-VERIFIED (2026-11-26, P14s `dsdt.aml`): every AML path
//! literal in `defs.rs` is the DSDT's real path
//! (`\_SB.PCI0.LPC0.EC0`, HKEY `LEN0268` under it).

#![no_std]

#[cfg(feature = "builtin")]
extern crate alloc;

use narf_driver_macros::narf_driver;

pub mod defs;
pub mod driver;
pub mod quad;

#[cfg(feature = "builtin")]
pub mod builtin;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "thinkpad-led",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "ThinkPad LED driver (kbdlight, mute/micmute, safe generic LEDs)",
        target_domain: "platform",
        required_caps: "PlatformDriver:Write",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    builtin::register();
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
