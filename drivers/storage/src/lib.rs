//! Non-NVMe storage driver facade.
//!
//! Each controller driver is its own dual-build crate (built-in rlib or
//! loadable `.ko`) over `narf-drivers-storage-core`, following the
//! `narf-drivers-net-e1000` pattern. This facade aggregates them behind
//! per-driver features (all enabled by `default`, so the built kernel is
//! unchanged), re-exports each driver module so `crate::<driver>::…` keeps
//! resolving for the smokes, and wires the boot initcalls.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

// The smokes use `alloc`.
extern crate alloc;

// Per-driver module re-exports (optional deps selected by same-named features).
#[cfg(feature = "ahci")]
pub use narf_drivers_storage_ahci::ahci;
#[cfg(feature = "megaraid")]
pub use narf_drivers_storage_megaraid::megaraid;
#[cfg(feature = "mpt3sas")]
pub use narf_drivers_storage_mpt3sas::mpt3sas;
#[cfg(feature = "rtsx")]
pub use narf_drivers_storage_rtsx::rtsx;
#[cfg(feature = "sdhci")]
pub use narf_drivers_storage_sdhci::sdhci;
#[cfg(feature = "smartpqi")]
pub use narf_drivers_storage_smartpqi::smartpqi;
#[cfg(feature = "vmd")]
pub use narf_drivers_storage_vmd::vmd;

// Shared SD/MMC/UFS helpers (emmc, sd_proto, ufs, req_gate) live in core.
pub use narf_drivers_storage_core::*;

// Smokes reach into driver + helper internals via the re-exports above, so
// gate on all driver features. `default` enables them all.
#[cfg(all(
    feature = "ahci",
    feature = "megaraid",
    feature = "mpt3sas",
    feature = "rtsx",
    feature = "sdhci",
    feature = "smartpqi",
    feature = "vmd"
))]
mod e2e_tests;
#[cfg(all(
    feature = "ahci",
    feature = "megaraid",
    feature = "mpt3sas",
    feature = "rtsx",
    feature = "sdhci",
    feature = "smartpqi",
    feature = "vmd"
))]
mod tests;

/// Stage::Subsys + Stage::Device initcalls for this driver crate.
pub fn register_initcalls() {
    #[cfg(any(
        feature = "ahci",
        feature = "megaraid",
        feature = "mpt3sas",
        feature = "rtsx",
        feature = "sdhci",
        feature = "smartpqi",
        feature = "vmd"
    ))]
    use narf_init::{InitResult, Stage};

    // SD/MMC block device bridge: register_card() is called at probe time by
    // the RTSX driver; no additional initcall needed here.
    // Linux ref: `drivers/mmc/core/block.c:mmc_blk_alloc_req`.
    #[cfg(feature = "ahci")]
    narf_init::register(Stage::Subsys, "ahci", || {
        narf_drivers_storage_ahci::register();
        InitResult::Ok
    });
    #[cfg(feature = "megaraid")]
    narf_init::register(Stage::Subsys, "megaraid", || {
        narf_drivers_storage_megaraid::register();
        InitResult::Ok
    });
    #[cfg(feature = "smartpqi")]
    narf_init::register(Stage::Subsys, "smartpqi", || {
        narf_drivers_storage_smartpqi::register();
        InitResult::Ok
    });
    #[cfg(feature = "mpt3sas")]
    narf_init::register(Stage::Subsys, "mpt3sas", || {
        narf_drivers_storage_mpt3sas::register();
        InitResult::Ok
    });
    #[cfg(feature = "sdhci")]
    narf_init::register(Stage::Subsys, "sdhci", || {
        narf_drivers_storage_sdhci::register();
        InitResult::Ok
    });
    #[cfg(feature = "rtsx")]
    narf_init::register(Stage::Subsys, "rtsx", || {
        narf_drivers_storage_rtsx::register();
        InitResult::Ok
    });
    // Intel VMD must register at Stage::Device because its probe appends
    // children into the bus registry that the *same* PCI walk's later probes
    // would not otherwise see. Keeping VMD at Stage::Device leaves the
    // Stage::Subsys ordering unchanged for the existing storage drivers.
    #[cfg(feature = "vmd")]
    narf_init::register(Stage::Device, "intel-vmd", || {
        narf_drivers_storage_vmd::register();
        InitResult::Ok
    });
}
