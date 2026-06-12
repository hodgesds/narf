//! QXL Virtual GPU Driver.
//!
//! Provides a basic driver for the QXL paravirtualized graphics card
//! commonly used in KVM / QEMU / SPICE environments.
//!
//! References: `linux/drivers/gpu/drm/qxl/`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the QXL PCI driver.
pub fn register_pci_driver() {
    let _ = writeln!(Writer, "  gpu: QXL Virtual GPU driver registered");
    // Placeholder for PCI vendor=0x1b36, device=0x0100 match
}
