//! Display drivers.
//!
//! M0 surface: bochs-display (`-device bochs-display`) on x86_64 q35.
//! Future modules: virtio-gpu (cross-arch), ramfb (paravirt minimal).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod bochs;
