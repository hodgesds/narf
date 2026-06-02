//! Non-NVMe storage drivers (AHCI today).
//!
//! Spec: AHCI base 1.3.1.
//!
//! Stage-4 cut: AHCI structural bring-up — map ABAR, reset the
//! HBA, enumerate ports via PI (Ports Implemented), and read each
//! port's signature so the driver can later route IDENTIFY DEVICE
//! / IDENTIFY PACKET DEVICE per port. Per-port command-list +
//! IDENTIFY-DEVICE issuance is a follow-up that lands once a smoke
//! has a guaranteed disk to talk to.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod ahci;
pub mod emmc;
pub mod rtsx;
pub mod sd_proto;
pub mod sdhci;
pub mod ufs;
pub mod vmd;

mod tests;
mod e2e_tests;

/// Stage::Subsys + Stage::Device initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // SD/MMC block device bridge: register_card() is called at probe
    // time by the RTSX driver; no additional initcall needed here.
    // Linux ref: `drivers/mmc/core/block.c:mmc_blk_alloc_req`.
    narf_init::register(Stage::Subsys, "ahci", || {
        ahci::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "sdhci", || {
        sdhci::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "rtsx", || {
        rtsx::register_pci_driver();
        InitResult::Ok
    });
    // Intel VMD must register at Stage::Device because its probe
    // appends children into the bus registry that the *same* PCI
    // walk's later probes would not otherwise see. Stage::Subsys
    // registers the match; the actual `probe_all_pci` call that
    // binds it runs at Stage::Device per `frame::bare_main`. Putting
    // VMD's register at Stage::Device keeps the children visible
    // to any Stage::Late re-walk while leaving the Stage::Subsys
    // ordering unchanged for the existing storage drivers.
    narf_init::register(Stage::Device, "intel-vmd", || {
        vmd::register_pci_driver_vmd();
        InitResult::Ok
    });
}
