//! Shared helpers for the native audio controller drivers.
//!
//! PCI power-on, IRQ routing, the PCM DMA ring and the ACPI/AML firmware
//! queries used by both `narf-drivers-audio-hda` and `narf-drivers-audio-acp`.
//! Split out of `narf-audio` so each controller driver can be its own
//! dual-build crate without a dependency on the PCM subsystem facade.
//! Always built-in.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod native_firmware;
pub mod native_irq;
pub mod native_pci;
pub mod native_pcm;
