#![no_std]

extern crate alloc;

pub mod mipi_hci;
pub mod nxp;

pub fn register_initcalls() {
    nxp::register();
}
