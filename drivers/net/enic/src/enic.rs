//! Cisco VIC (enic) Ethernet driver — explicit refusal marker.
//!
//! The real datapath is NOT implemented and is deferred out of the
//! desktop scope (issue #798): there is no TX/RX path and no `HwNic`
//! implementation. Probe declines every device with
//! `ProbeError::NotForThisDriver` *before touching the hardware*, so
//! the device is never presented as bound and stays available to the
//! next claimant in the bus arbitration walk (bus spec §9.3).
//!
//! References: `linux/drivers/net/ethernet/cisco/enic/`

use narf_bus::{BusDevice, BusDeviceCap, ProbeError};
use narf_capabilities::{Cap, Write};

const ENIC_PCI_VENDOR: u16 = 0x1137; // Cisco Systems
const ENIC_PCI_DEVICE_VIC: u16 = 0x0043;

/// Probe entry — installed via `bus::register_pci_driver`.
///
/// Explicit refusal, not a driver: the enic datapath is deferred out
/// of desktop scope (#798), so this always declines with
/// `NotForThisDriver`. The dispatcher returns the device to the
/// candidate list and attempts the next-most-specific match. No BAR
/// is mapped and no reset is issued — declining must not disturb
/// hardware another driver may later claim.
pub fn probe(_device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    Err(ProbeError::NotForThisDriver)
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "enic",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: ENIC_PCI_VENDOR,
            device: ENIC_PCI_DEVICE_VIC,
        },
        probe,
    });
}
