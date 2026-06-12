//! Media subsystem drivers.
//!
//! Includes Software Defined Radio (SDR), Digital Video Broadcasting (DVB),
//! Consumer Electronics Control (CEC), and TV Tuners.
//!
//! Reference: `linux/drivers/media`

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod cec_gpio;
pub mod rtl2832;
pub mod tc358743;
pub mod uvcvideo;
pub mod vivid;

pub fn register_initcalls() {
    cec_gpio::register_initcalls();
    rtl2832::register_initcalls();
    tc358743::register_initcalls();
    uvcvideo::register_initcalls();
    vivid::register_initcalls();
}
