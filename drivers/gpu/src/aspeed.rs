//! ASPEED AST2400/AST2500/AST2600 BMC Display Driver.
//!
//! Exposes a basic framebuffer for the VGA display controller
//! integrated into ASPEED BMCs, standard in most enterprise servers.
//!
//! References: `linux/drivers/gpu/drm/aspeed/`

extern crate alloc;

use core::fmt::Write;
use narf_console::Writer;

/// Register the ASPEED PCI driver.
pub fn register_pci_driver() {
    let _ = writeln!(Writer, "  gpu: ASPEED BMC Display driver registered");
    // Placeholder for actual PCI vendor=0x1A03 match.
}
