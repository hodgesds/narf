#![no_std]

extern crate alloc;

pub mod nxp;

pub fn register_initcalls() {
    nxp::register();
}
