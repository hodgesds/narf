//! TCPC drivers — implementations of `narf_usbpd::tcpc::Tcpc`.
//!
//! Each chip is its own module. Driver code is clean-room from the
//! vendor's public silicon datasheet; no GPL/BSD source consulted.
//! See `specification/spec.md` for the per-chip reference list.
//!
//! ## Surface
//!
//! - [`fusb302`] — ON Semiconductor FUSB302B (low-level BMC PHY).
//! - [`tps65987`] — TI TPS65987DDH (firmware-driven PD controller).
//! - [`i2c_bridge`] — sync façade that wraps `narf_drivers_i2c::I2cBus`
//!   so the chip drivers' sync `I2cBus` trait can ride the kernel's
//!   async I²C controllers.
//! - [`register_initcalls`] — Stage::Late initcall: walks every
//!   registered I²C bus, probes each for a TCPC chip, and parks any
//!   detected chip in [`PORTS`] for the (future) TCPM step task.
//!
//! References (public, non-GPL only):
//! - **USB Power Delivery 3.1 v1.8** (USB-IF).
//!     <https://www.usb.org/document-library/usb-power-delivery>
//! - **USB Type-C Cable and Connector Specification 2.2** (USB-IF).
//!     <https://www.usb.org/document-library/usb-type-c-cable-and-connector-specification-revision-22>
//! - **USB Type-C Port Controller Interface Specification 2.0**
//!   (USB-IF, TCPCI 2.0).
//!     <https://www.usb.org/document-library/usb-type-c-port-controller-interface-specification-revision-20>

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod fusb302;
pub mod i2c_bridge;
pub mod tps65987;

mod tests;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;
use narf_usbpd::tcpc::Tcpc;

/// One bound TCPC port — the chip handle plus identifying metadata
/// for diagnostics. Stored in the global [`PORTS`] registry.
#[derive(Debug)]
pub struct PortBinding {
    /// Stable name from the host I²C controller (typically the ACPI
    /// path of the controller, e.g. `\_SB.I2CA`).
    pub bus_name: alloc::string::String,
    /// 7-bit I²C target address the chip responds at.
    pub i2c_addr: u8,
    /// Chip-side TCPC handle. The TCPM step task drives this once
    /// it lands.
    pub tcpc: Arc<dyn Tcpc>,
}

/// Global registry of detected TCPC ports. Populated by
/// [`register_initcalls`]; consumed by the (future) TCPM step task.
pub static PORTS: IrqSafeSpinLock<Vec<PortBinding>> =
    IrqSafeSpinLock::new(Vec::new());

/// Stage::Late initcall: walk every registered I²C bus, probe known
/// TCPC chips at their datasheet I²C addresses, and park any
/// successful detection in [`PORTS`]. Quiet on systems with no
/// matching chip (typical for QEMU without TCPC emulation).
///
/// Probe order:
/// 1. **FUSB302B** at the default 7-bit address `0x22` (datasheet
///    "Pin Description / I²C Address"). DEVICE_ID high-nibble must
///    be ≥ 0x8 to match a real FUSB302 silicon revision.
/// 2. **TPS65987DDH** at `0x38` (TPS65987 TRM §"Host Interface").
///    Vendor-ID register must read `0x0451` (TI's USB-IF VID).
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "usbpd-tcpc-probe", || {
        let buses = narf_drivers_i2c::registered_buses();
        if buses.is_empty() {
            return InitResult::NotPresent;
        }
        let mut detected = 0usize;
        for bus in &buses {
            detected += probe_bus(bus);
        }
        if detected == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
}

/// Probe one I²C bus for every supported TCPC chip. Returns the
/// number of chips registered.
fn probe_bus(bus: &Arc<dyn narf_drivers_i2c::I2cBus>) -> usize {
    use core::fmt::Write as _;
    let mut n = 0usize;
    let bus_name = bus.name();
    let bridge = Arc::new(i2c_bridge::KernelBusBridge::new(bus.clone()));

    // FUSB302B at 0x22.
    let fusb = fusb302::Fusb302::new(bridge.clone(), fusb302::FUSB302_DEFAULT_I2C_ADDR);
    if let Ok(id) = fusb.probe_device_id() {
        // Init brings up the BMC PHY; failure here means the chip is
        // present but reset cleared something the datasheet says we
        // need to re-program. Surface as "detected" anyway so a
        // future debug pass can pick it up.
        let _ = fusb.init();
        let _ = writeln!(
            narf_console::Writer,
            "  usbpd: FUSB302 detected on bus '{}' addr 0x22 device_id=0x{:02x}",
            bus_name, id
        );
        let chip: Arc<dyn Tcpc> = Arc::new(fusb);
        PORTS.lock().push(PortBinding {
            bus_name: bus_name.into(),
            i2c_addr: fusb302::FUSB302_DEFAULT_I2C_ADDR,
            tcpc: chip,
        });
        n += 1;
    }

    // TPS65987DDH at 0x38.
    let tps = tps65987::Tps65987::new(bridge, tps65987::TPS65987_DEFAULT_I2C_ADDR);
    if let Ok((vendor, device)) = tps.probe() {
        let _ = writeln!(
            narf_console::Writer,
            "  usbpd: TPS65987 detected on bus '{}' addr 0x38 vid=0x{:04x} did=0x{:04x}",
            bus_name, vendor, device
        );
        let chip: Arc<dyn Tcpc> = Arc::new(tps);
        PORTS.lock().push(PortBinding {
            bus_name: bus_name.into(),
            i2c_addr: tps65987::TPS65987_DEFAULT_I2C_ADDR,
            tcpc: chip,
        });
        n += 1;
    }

    n
}

/// Number of TCPC ports currently bound. Useful for tests +
/// diagnostics.
pub fn bound_port_count() -> usize {
    PORTS.lock().len()
}
