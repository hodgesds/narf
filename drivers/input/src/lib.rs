//! Input drivers (Stage-3 onwards).
//!
//! M0 surface: i8042 PS/2 keyboard on x86_64. Future modules:
//! virtio-input (cross-arch, lives under drivers/virtio/), USB HID
//! (depends on the xHCI stack maturing past structural-probe).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
pub mod i8042;
