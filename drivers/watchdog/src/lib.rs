//! Watchdog device class + Intel TCO (iTCO) driver.
//!
//! This crate is the single registry point for watchdog devices on
//! NARF. It owns:
//!
//! - The [`WatchdogDevice`] trait + global registry ([`register_watchdog`],
//!   [`watchdog_devices`]) — the watchdog class surface. Linux
//!   reference: `drivers/watchdog/watchdog_dev.c` (the class
//!   registry shape only; NARF has no `/dev/watchdog` yet — see the
//!   spec's open questions).
//! - The Intel TCO driver ([`itco`]): WDDT-driven probe, timer
//!   programming, pet, halt, and status over the TCO register block.
//!
//! ## References
//!
//! - Intel Core Ultra 200S/200HX SoC I/O Registers (EDC ID 834819,
//!   2025-01-29), SMBus TCO block: TCO_RLD (TRLD, offset 0), TCO1_STS
//!   (TSTS1, offset 4), TCO2_CNT (TCTL2, offset 0x0a), TCO_TMR (TTMR,
//!   offset 0x12). TCOBASE PCI register (offset 0x50) in the same
//!   document.
//! - Linux `drivers/watchdog/iTCO_wdt.c` + `iTCO_vendor_support.c`
//!   (reference implementation): TCOBASE = ACPIBASE + 0x60,
//!   TCO1_STS = TCOBASE + 0x04, TCO1_CNT bit 11 = TCO_TMR_HLT,
//!   NO_REBOOT generation split (GCS MMIO bit 5 on v2, TCO1_CNT
//!   member on v6).
//! - ACPI WDDT 1.0 (in-tree `narf_acpi::WddtInfo`): the probe's
//!   register-block base + count bounds.
//!
//! ## What is deliberately NOT here
//!
//! - NO_REBOOT control: the v6 TCO1_CNT bit position is not pinned
//!   to a citable source (the LKML Cannon Lake note says only
//!   "part of the TCO1_CNT register"), so the driver never touches
//!   it and reports `no_reboot_control: false`. See the spec §8.
//! - PCI TCOBASE probe route (SMBus device config offset 0x50):
//!   the probe is WDDT-driven only in this lane. See the spec §8.
//! - SBSA / SP805 watchdogs: embedded-programme scope, not this
//!   lane (issue #1057's census scope).
//! - SMI_EN / TCO_EN manipulation: BIOS/vendor territory, out of
//!   scope (Linux keeps it behind vendor support, same here).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod class;
pub mod itco;

#[cfg(any(test, feature = "kernel-test"))]
mod tests;

pub use class::{
    register_watchdog, unregister_watchdog, watchdog_device, watchdog_devices, WatchdogDevice,
    WatchdogError, WatchdogStatus,
};

/// Register all Stage::Device initcalls for the watchdog subsystem.
///
/// On x86_64 this registers the iTCO probe, which consumes the
/// WDDT parsed at boot (see `frame`'s boot-time `parse_wddt` call)
/// and registers the device when a usable table is present. On
/// other architectures there is no iTCO block, so nothing registers.
pub fn register_initcalls() {
    #[cfg(target_arch = "x86_64")]
    {
        use narf_init::{InitResult, Stage};
        narf_init::register(
            Stage::Device,
            "watchdog/itco",
            || match itco::probe_from_wddt() {
                Some(dev) => {
                    register_watchdog(dev);
                    InitResult::Ok
                }
                None => InitResult::NotPresent,
            },
        );
    }
}
