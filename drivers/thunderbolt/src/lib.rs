//! USB4 native host interface and connection manager.
//!
//! PCI discovery includes AMD Pink Sardine and Intel USB4 class controllers.
//! Firmware `_OSC` must grant USB3/DisplayPort ownership before ring zero is
//! started. One actor owns each NHI's DMA rings, config transactions, topology,
//! and tunnels. PCIe/XDomain tunneling and legacy ICM are not implemented.
//!
//! Reference: `/usr/src/linux/drivers/thunderbolt/{pci,nhi,ctl,usb4,path,tunnel}.c`.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod adapter;
pub mod cm;
mod control;
mod firmware;
pub mod nhi;
mod ring;
mod runtime;
pub mod switch;
pub mod topology;
pub mod tunnel;

#[cfg(target_arch = "x86_64")]
mod tests;

/// Discover controllers during Device init and start native CMs during Late init.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "usb4-nhi", || {
        nhi::register_pci_driver_thunderbolt();
        InitResult::Ok
    });
    narf_init::register(Stage::Late, "usb4-native-cm", runtime::start);
}
