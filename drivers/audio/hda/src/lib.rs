//! HD Audio controller + codec driver — dual-build (built-in or loadable `.ko`).
//!
//! The driver body lives in [`hda`] (controller, CORB/RIRB, streams, HDMI)
//! and [`hda_codec`] (widget walk, verbs, pin config) and compiles only for
//! the built-in build; `narf-audio` re-exports both modules. [`ids`] holds
//! the PCI match table and is compiled in both builds.
//!
//! The `module` build registers the same ids through the
//! `narf_register_pci_driver` KSYMTAB export (registration-only until the
//! device datapath ABI covers a PCM device). See `narf-drivers-net-tg3` for
//! the registration-only shape.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

#[cfg(feature = "builtin")]
#[allow(unused_imports)]
use narf_drivers_audio_core::{native_firmware, native_irq, native_pci, native_pcm};

pub mod ids;

#[cfg(feature = "builtin")]
pub mod hda;
#[cfg(feature = "builtin")]
pub mod hda_codec;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "hda",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "HD Audio controller",
        target_domain: "scratch",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    hda::register_pci_driver();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}
