//! HPE Smart Array PQI Storage Driver.
//!
//! Provides support for the PCIe Queued Interface (PQI) used by
//! modern HP Smart Array RAID controllers.
//!
//! References: `linux/drivers/scsi/smartpqi/`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the smartpqi PCI driver.
pub fn register_pci_driver() {
    let _ = writeln!(Writer, "  storage: HPE Smart Array PQI driver registered");
    // Placeholder for actual PCI vendor=0x9005 match and PQI queue setup.
}
