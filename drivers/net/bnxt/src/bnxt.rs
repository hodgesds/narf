//! Broadcom NetXtreme-C/E (bnxt) Ethernet driver — explicit refusal marker.
//!
//! The real datapath is NOT implemented and is deferred out of the
//! desktop scope (issue #798): there is no TX/RX path and no `HwNic`
//! implementation. Probe declines every device with
//! `ProbeError::NotForThisDriver` *before touching the hardware*, so
//! the device is never presented as bound and stays available to the
//! next claimant in the bus arbitration walk (bus spec §9.3).
//!
//! References: `linux/drivers/net/ethernet/broadcom/bnxt/`

use narf_bus::{BusDevice, BusDeviceCap, ProbeError};
use narf_capabilities::{Cap, Write};

const BNXT_PCI_VENDOR: u16 = 0x14E4;
const BNXT_PCI_DEVICE_BCM57414: u16 = 0x16D7;

/// Probe entry — installed via `bus::register_pci_driver`.
///
/// Explicit refusal, not a driver: the bnxt datapath is deferred out
/// of desktop scope (#798), so this always declines with
/// `NotForThisDriver`. The dispatcher returns the device to the
/// candidate list and attempts the next-most-specific match. No BAR
/// is mapped and no reset is pulsed — declining must not disturb
/// hardware another driver may later claim.
pub fn probe(_device: BusDevice, _cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    Err(ProbeError::NotForThisDriver)
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "bnxt",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: BNXT_PCI_VENDOR,
            device: BNXT_PCI_DEVICE_BCM57414,
        },
        probe,
    });
}
