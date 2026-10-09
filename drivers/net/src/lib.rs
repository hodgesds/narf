//! narf-drivers-net — hardware NIC driver facade.
//!
//! Each NIC driver is its own crate (see `narf-drivers-net-e1000` for the
//! dual-build pattern): buildable as a built-in (linked into the kernel) or a
//! loadable `.ko` from one source. This facade aggregates them behind
//! per-driver cargo features — all enabled by `default`, so the built kernel is
//! unchanged — re-exports each driver module so `narf_drivers_net::<driver>`
//! and `crate::<driver>::…` keep resolving for the smokes and external callers,
//! and wires every enabled driver's registration into the boot initcalls.
//!
//! The driver-agnostic surface (`HwNic`, `NicModel`, `NicCaps`,
//! `NicDescriptor`, `NicError`) and the Realtek PHY helpers live in
//! `narf-drivers-net-core`, re-exported here.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

// The smokes in `tests` use `alloc`.
extern crate alloc;

// Per-driver module re-exports. Each is an optional dependency selected by a
// same-named feature; `default` enables them all.
#[cfg(feature = "atheros")]
pub use narf_drivers_net_atheros::atheros;
#[cfg(feature = "bnxt")]
pub use narf_drivers_net_bnxt::bnxt;
#[cfg(feature = "cxgb4")]
pub use narf_drivers_net_cxgb4::cxgb4;
#[cfg(feature = "e1000")]
pub use narf_drivers_net_e1000::e1000;
#[cfg(feature = "enic")]
pub use narf_drivers_net_enic::enic;
#[cfg(feature = "forcedeth")]
pub use narf_drivers_net_forcedeth::forcedeth;
#[cfg(feature = "i40e")]
pub use narf_drivers_net_i40e::i40e;
#[cfg(feature = "igc")]
pub use narf_drivers_net_igc::igc;
#[cfg(feature = "ixgbe")]
pub use narf_drivers_net_ixgbe::ixgbe;
#[cfg(feature = "mlx5")]
pub use narf_drivers_net_mlx5::mlx5;
// The Realtek family ships as one crate (dependency chain + shared rtl_phy).
#[cfg(feature = "realtek")]
pub use narf_drivers_net_realtek::{r8169, rtl8125, rtl8126, rtl8127};
#[cfg(feature = "rtl8139")]
pub use narf_drivers_net_rtl8139::rtl8139;
#[cfg(feature = "tg3")]
pub use narf_drivers_net_tg3::tg3;
#[cfg(feature = "vmxnet3")]
pub use narf_drivers_net_vmxnet3::vmxnet3;

pub use narf_drivers_net_core::*;

// Per-driver smoke tests register against `narf-kernel-test` and land in the
// same `narf.tests` ELF section. They reach into the driver modules via the
// re-exports above, so the suite compiles only when every driver crate is
// present — gate on all driver features. `default` enables them all, so
// standard builds compile the full suite.
#[cfg(all(
    feature = "atheros",
    feature = "bnxt",
    feature = "cxgb4",
    feature = "e1000",
    feature = "enic",
    feature = "forcedeth",
    feature = "i40e",
    feature = "igc",
    feature = "ixgbe",
    feature = "mlx5",
    feature = "realtek",
    feature = "rtl8139",
    feature = "tg3",
    feature = "vmxnet3"
))]
mod tests;

/// Register the late PHY-firmware pass.
///
/// Kept out of [`register_initcalls`] because it must run after the firmware
/// registry has been populated, and `Stage::Late` initcalls run in
/// registration order — this crate registers before `narf-firmware` does.
/// `bare_main` calls this after `narf_firmware::register_initcalls()`, which is
/// what puts it after the initramfs and rootfs firmware scans.
pub fn register_late_firmware_initcalls() {
    #[cfg(feature = "realtek")]
    {
        use narf_init::{InitResult, Stage};
        narf_init::register(Stage::Late, "rtl8127-phy-firmware", || {
            narf_drivers_net_realtek::configure_rtl8127_phy_late();
            InitResult::Ok
        });
    }
}

/// Stage::Subsys initcalls for this driver crate. Each enabled driver crate's
/// `register()` registers its PCI match(es); the Realtek family registers all
/// four of its drivers from one entry.
pub fn register_initcalls() {
    #[cfg(any(
        feature = "atheros",
        feature = "bnxt",
        feature = "cxgb4",
        feature = "e1000",
        feature = "enic",
        feature = "forcedeth",
        feature = "i40e",
        feature = "igc",
        feature = "ixgbe",
        feature = "mlx5",
        feature = "realtek",
        feature = "rtl8139",
        feature = "tg3",
        feature = "vmxnet3"
    ))]
    use narf_init::{InitResult, Stage};

    #[cfg(feature = "cxgb4")]
    narf_init::register(Stage::Subsys, "cxgb4", || {
        narf_drivers_net_cxgb4::register();
        InitResult::Ok
    });
    #[cfg(feature = "e1000")]
    narf_init::register(Stage::Subsys, "e1000", || {
        narf_drivers_net_e1000::register();
        InitResult::Ok
    });
    #[cfg(feature = "i40e")]
    narf_init::register(Stage::Subsys, "i40e", || {
        narf_drivers_net_i40e::register();
        InitResult::Ok
    });
    #[cfg(feature = "realtek")]
    narf_init::register(Stage::Subsys, "realtek", || {
        narf_drivers_net_realtek::register();
        InitResult::Ok
    });
    #[cfg(feature = "mlx5")]
    narf_init::register(Stage::Subsys, "mlx5", || {
        narf_drivers_net_mlx5::register();
        InitResult::Ok
    });
    #[cfg(feature = "ixgbe")]
    narf_init::register(Stage::Subsys, "ixgbe", || {
        narf_drivers_net_ixgbe::register();
        InitResult::Ok
    });
    #[cfg(feature = "igc")]
    narf_init::register(Stage::Subsys, "igc", || {
        narf_drivers_net_igc::register();
        InitResult::Ok
    });
    #[cfg(feature = "rtl8139")]
    narf_init::register(Stage::Subsys, "rtl8139", || {
        narf_drivers_net_rtl8139::register();
        InitResult::Ok
    });
    #[cfg(feature = "atheros")]
    narf_init::register(Stage::Subsys, "atheros", || {
        narf_drivers_net_atheros::register();
        InitResult::Ok
    });
    #[cfg(feature = "tg3")]
    narf_init::register(Stage::Subsys, "tg3", || {
        narf_drivers_net_tg3::register();
        InitResult::Ok
    });
    #[cfg(feature = "vmxnet3")]
    narf_init::register(Stage::Subsys, "vmxnet3", || {
        narf_drivers_net_vmxnet3::register();
        InitResult::Ok
    });
    #[cfg(feature = "forcedeth")]
    narf_init::register(Stage::Subsys, "forcedeth", || {
        narf_drivers_net_forcedeth::register();
        InitResult::Ok
    });
    #[cfg(feature = "bnxt")]
    narf_init::register(Stage::Subsys, "bnxt", || {
        narf_drivers_net_bnxt::register();
        InitResult::Ok
    });
    #[cfg(feature = "enic")]
    narf_init::register(Stage::Subsys, "enic", || {
        narf_drivers_net_enic::register();
        InitResult::Ok
    });
}
