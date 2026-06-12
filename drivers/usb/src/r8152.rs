//! Realtek RTL8152/RTL8153 USB Ethernet driver.
//!
//! Basic skeleton for detecting and binding RTL8152/RTL8153 family
//! USB NICs.
//!
//! ## References
//! - Linux `drivers/net/usb/r8152.c`

extern crate alloc;

use crate::class_registry::{register_class_driver, UsbClassMatch, UsbProbeError};
use crate::device::USBDevice;
use alloc::sync::Arc;

const MATCHES: &[UsbClassMatch] = &[
    // Realtek
    UsbClassMatch::vid_pid(0x0BDA, 0x8050),
    UsbClassMatch::vid_pid(0x0BDA, 0x8053),
    UsbClassMatch::vid_pid(0x0BDA, 0x8152),
    UsbClassMatch::vid_pid(0x0BDA, 0x8153),
    UsbClassMatch::vid_pid(0x0BDA, 0x8155),
    UsbClassMatch::vid_pid(0x0BDA, 0x8156),
    // Microsoft
    UsbClassMatch::vid_pid(0x045E, 0x07ab),
    UsbClassMatch::vid_pid(0x045E, 0x07c6),
    UsbClassMatch::vid_pid(0x045E, 0x0927),
    UsbClassMatch::vid_pid(0x045E, 0x0c5e),
    // Samsung
    UsbClassMatch::vid_pid(0x04E8, 0xa101),
    // Lenovo
    UsbClassMatch::vid_pid(0x17EF, 0x304f),
    UsbClassMatch::vid_pid(0x17EF, 0x3054),
    UsbClassMatch::vid_pid(0x17EF, 0x3062),
    UsbClassMatch::vid_pid(0x17EF, 0x3069),
];

fn probe(device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "  net: Realtek RTL8152/8153 USB Ethernet device bound! (vendor={:04x}, product={:04x})",
        device.vendor_id(),
        device.product_id()
    );
    Ok(())
}

/// Register the r8152 USB class driver.
pub fn register() {
    let _ = register_class_driver("r8152", MATCHES, probe);
}
