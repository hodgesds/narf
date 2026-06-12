//! Realtek RTL2832U DVB-T / SDR USB receiver driver.
//!
//! Extremely popular for Software Defined Radio (RTL-SDR).
//!
//! Reference: `linux/drivers/media/usb/dvb-usb-v2/rtl28xxu.c`

extern crate alloc;

use alloc::sync::Arc;
use core::fmt::Write;
use narf_console::Writer;
use narf_drivers_usb::class_registry::{register_class_driver, UsbClassMatch, UsbProbeError};
use narf_drivers_usb::device::USBDevice;

pub const RTL2832U_VID: u16 = 0x0bda;
pub const RTL2832U_PID: u16 = 0x2832;

pub static RTL2832U_MATCH: [UsbClassMatch; 1] = [
    UsbClassMatch::vid_pid(RTL2832U_VID, RTL2832U_PID),
];

pub fn probe(_device: Arc<USBDevice>) -> Result<(), UsbProbeError> {
    let _ = writeln!(Writer, "  media: RTL2832U SDR / DVB-T USB device driver bound!");
    Ok(())
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "media-rtl2832", || {
        let _ = writeln!(Writer, "  media: Registering rtl2832u USB class driver");
        let _ = register_class_driver("rtl2832u", &RTL2832U_MATCH, probe);
        InitResult::Ok
    });
}
