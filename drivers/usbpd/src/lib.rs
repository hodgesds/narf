//! TCPC drivers — implementations of `narf_usbpd::tcpc::Tcpc`.
//!
//! Each chip is its own module. Driver code is clean-room from the
//! vendor's public silicon datasheet; no GPL Linux source consulted.
//! See `specification/spec.md` for the per-chip reference list.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod fusb302;
pub mod tps65987;

mod tests;
