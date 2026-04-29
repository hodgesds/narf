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
#[cfg(target_arch = "x86_64")]
pub mod i8042_mouse;

/// Stage::Device initcalls for this driver crate. i8042 init is
/// best-effort — a missing PS/2 controller (USB-only systems,
/// virtio-input-only) returns NotPresent rather than failing.
#[cfg(target_arch = "x86_64")]
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "i8042-kbd", || {
        // SAFETY: BSP boot context, no other agent driving 0x60/0x64.
        match unsafe { i8042::init() } {
            Ok(())  => InitResult::Ok,
            Err(_)  => InitResult::NotPresent,
        }
    });
    narf_init::register(Stage::Device, "i8042-mouse", || {
        // SAFETY: BSP, post-keyboard-init.
        match unsafe { i8042_mouse::init() } {
            Ok(())  => InitResult::Ok,
            Err(_)  => InitResult::NotPresent,
        }
    });
}

#[cfg(not(target_arch = "x86_64"))]
pub fn register_initcalls() {}
