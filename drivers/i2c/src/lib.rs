//! I2C bus trait + AMD FCH and Intel LPSS controller drivers.
//!
//! Three layers:
//! - `I2cBus` trait + `I2cOp` + a process-global registry of buses,
//!   so HID-over-I2C and other client drivers can locate a bus by
//!   name (typically the ACPI path of the controller) without
//!   plumbing an Arc through every initcall.
//! - `amd_fch` — an AMD FCH I2C controller driver. The FCH I2C IP is
//!   the Synopsys DesignWare core lightly relabelled, so the register
//!   map below is the standard DW-i2c map. Discovery walks the AML
//!   namespace for `AMDI0010 / AMDI0019 / AMDI0510 / AMDI0011`,
//!   decodes `_CRS` for MMIO base + IRQ, and hands the resulting
//!   driver instance to the registry.
//! - `lpss` — Intel PCH LPSS I2C controllers (Tiger Lake / Alder Lake
//!   / Raptor Lake and earlier). Same DW core, different ACPI HIDs
//!   (`INT3xxx` / `80860Fxx` / `808622xx`). Stage-0 skeleton:
//!   discovery + MMIO mapping + IC_COMP_TYPE probe + bus
//!   registration + transfer state machine.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod amd_fch;
pub mod gsb;
pub mod i801;
pub mod lpss;
pub mod piix4;
pub mod registry;

use alloc::boxed::Box;
use alloc::vec::Vec;
use async_trait::async_trait;

/// One operation in an I2C transfer. The bus issues a single
/// (repeated-)START between ops and a STOP after the last op. Repeated
/// reads/writes against the same target inside one `transfer()` call
/// are atomic with respect to other tasks holding the bus mutex.
#[derive(Debug)]
pub enum I2cOp<'a> {
    Write(&'a [u8]),
    Read(&'a mut [u8]),
}

/// Surface for I2C errors. Stays narrow on purpose: drivers turn
/// hardware-specific failure registers into one of these so callers
/// can decide policy (retry / abandon / log) without learning every
/// controller's quirks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum I2cError {
    /// Target NACK'd its address phase — the device is not present
    /// at this slave address.
    Nack,
    /// Bus arbitration loss (multi-master). Rare on AMD FCH (no
    /// other master in PC layouts) but the controller still flags it.
    ArbLost,
    /// Generic transfer abort raised by the controller (TX_ABRT).
    /// `code` carries the controller-specific abort reason for logs.
    Abort(u32),
    /// Transfer didn't complete within the bus mutex's timeout.
    Timeout,
    /// Hardware register read returned an impossible value (read 0
    /// from the DW component-type register, etc.). Usually means the
    /// MMIO mapping points at the wrong place.
    BadHardware,
}

/// Async I2C bus interface. The implementor owns the controller's
/// MMIO + any IRQ vector and serialises concurrent transfers via its
/// own internal mutex — callers just `.transfer().await`.
#[async_trait]
pub trait I2cBus: Send + Sync + core::fmt::Debug {
    /// Issue a sequence of ops against the 7-bit target address
    /// `addr`. Single (repeated-)START between ops, STOP after last.
    async fn transfer(&self, addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError>;

    /// Identifier for the registry — typically the ACPI path of the
    /// controller (e.g. `\_SB.I2CA`). Unique within a single boot.
    fn name(&self) -> &str;
}

/// Discover, instantiate, and register every supported I2C controller.
/// Stage::Device entry — called once during boot. Idempotent only in
/// the sense that re-running it on hardware that's already been
/// programmed will reprogram the registers; the registry's
/// `register_unique` collapses duplicate controller paths.
///
/// The AMD FCH and Intel LPSS probes run as separate initcalls so a
/// failure / no-match in one doesn't gate the other — the Stage-1
/// bring-up target group has both Zen2 / Zen4 laptops (FCH path) and
/// Intel laptops (LPSS path). Either initcall successfully registering
/// at least one bus is enough to install the GenericSerialBus
/// dispatcher.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "amd-fch-i2c", || {
        let n = amd_fch::probe_all();
        if n == 0 {
            // No AMD FCH I2C controllers in the namespace — quiet
            // success on non-AMD platforms (e.g. QEMU virt, Intel
            // laptops) is the right behaviour, the i2c-hid initcall
            // logs the absence when it can't find a controller for
            // its children.
            InitResult::NotPresent
        } else {
            // Install the GenericSerialBus dispatcher so AML
            // OperationRegion(..., GenericSerialBus, ...) field
            // accesses route through the I2C registry. Audit #5
            // real impl. Idempotent — set_gsb_dispatcher just
            // overwrites the fn pointer.
            narf_aml::oregion::set_gsb_dispatcher(gsb::dispatch);
            InitResult::Ok
        }
    });
    narf_init::register(Stage::Device, "lpss-i2c", || {
        let n = lpss::probe_all();
        if n == 0 {
            // No Intel LPSS I2C controllers in the namespace — quiet
            // success on non-Intel platforms.
            InitResult::NotPresent
        } else {
            // Install the GenericSerialBus dispatcher in case the
            // AMD initcall didn't (Intel-only platform). The
            // dispatcher itself routes through `registry::find`
            // regardless of which driver populated the entry, so
            // it works for either backend.
            narf_aml::oregion::set_gsb_dispatcher(gsb::dispatch);
            InitResult::Ok
        }
    });
    narf_init::register(Stage::Subsys, "i801-smbus", || {
        i801::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "piix4-smbus", || {
        piix4::register_pci_driver();
        InitResult::Ok
    });
}

/// Snapshot of every registered I2C bus. Cheap clone — Arcs only.
pub fn registered_buses() -> Vec<alloc::sync::Arc<dyn I2cBus>> {
    registry::list()
}

/// Lock-free count of registered buses. Diagnostics (e.g.
/// fb::status::paint) read this instead of `registered_buses().len()`
/// so they never block on the registry's IrqSafeSpinLock while a
/// driver is mid-probe.
pub fn registered_bus_count() -> u32 {
    registry::REGISTERED_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
