//! The module build's USB binding (`rtl.ko`, rtl8xxxu).
//!
//! The built-in `rtl8xxxu_probe` over the USB KABI:
//!
//! 1. classify the dongle by VID/PID with the driver's own table
//!    ([`super::regs::ChipFamily::from_usb_id`]) and refuse an unknown one;
//! 2. retain it: the 1 ms device poller (`narf_usb_spawn_poller`) drives the
//!    module's executor, and the factory/power/firmware owner runs over the
//!    KABI transport (`platform::rtl_usb`: EP0 vendor requests and bulk
//!    transfers);
//! 3. configure the configuration's bulk/interrupt endpoints
//!    (`narf_usb_configure`; the built-in USB stack does this at
//!    enumeration), then start the family's chain exactly as built in
//!    ([`super::start`]): RTL8188EU, RTL8192EU and RTL8723BU go on to
//!    firmware, calibration, admission and the station, which publishes
//!    through `module_netdev::attach_usb`. Other families stay
//!    detection-only.
//!
//! One device binds per module (PCI or USB): every device export takes the
//! single bound token.

use core::fmt::Write as _;

use alloc::sync::Arc;

use super::regs::ChipFamily;
use crate::platform::{self, Console};

/// KABI exports the USB binding calls.
mod ffi {
    unsafe extern "C" {
        #[allow(clippy::too_many_arguments)]
        pub fn narf_register_usb_driver(
            name: *const u8,
            name_len: usize,
            match_flags: u16,
            vendor: u16,
            product: u16,
            class: u8,
            subclass: u8,
            protocol: u8,
            probe: usize,
        ) -> i32;
        pub fn narf_usb_spawn_poller(dev: u64, callback: usize, cookie: u64) -> i32;
    }
}

/// `usb_device_id` VID/PID match (`narf_bus::module_usb::MATCH_VENDOR_PRODUCT`).
const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;
const ENODEV: i32 = -19;
const EBUSY: i32 = -16;
/// The name the USB registry records for the module's matches.
const NAME: &[u8] = b"rtl8xxxu-module";

/// A `ModuleProbeFn`.
type ProbeFn = extern "C" fn(u64, u64) -> i32;

/// One probe per matched row: the kernel names the dongle to the probe only
/// by an opaque token, so each row gets its own thunk that knows its ids.
macro_rules! probe_thunks {
    ($($i:literal)*) => {
        [$({
            extern "C" fn thunk(dev: u64, _reserved: u64) -> i32 {
                let (vid, pid) = crate::module_ids::USB_IDS[$i];
                probe(dev, vid, pid)
            }
            thunk as ProbeFn
        }),*]
    };
}

/// One thunk per `module_ids::USB_IDS` row (the length is checked below).
const THUNKS: [ProbeFn; 23] =
    probe_thunks!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22);
const _: () = assert!(THUNKS.len() == crate::module_ids::USB_IDS.len());

/// The device poller: the executor's heartbeat (every 1 ms).
extern "C" fn poll(_cookie: u64) -> i32 {
    platform::run_executor();
    0
}

/// `rtl8xxxu_probe` for the matched `(vid, pid)`.
fn probe(dev: u64, vid: u16, pid: u16) -> i32 {
    let family = ChipFamily::from_usb_id(vid, pid);
    if family == ChipFamily::Unknown {
        // UsbProbeError::UnsupportedVariant: an RTL8XXXU_USB_IDS row with
        // no owning chip family (RTL8710BU / RTL8188GU, the Rosewill alias).
        let _ = writeln!(
            Console,
            "  rtl.ko: {vid:04x}:{pid:04x} has no rtl8xxxu chip family; not claimed"
        );
        return ENODEV;
    }
    if platform::device() != 0 {
        return EBUSY;
    }
    // SAFETY: `poll` is a valid extern "C" fn in this image; the kernel
    // retires the poller with the USB context before unmapping it.
    if unsafe { ffi::narf_usb_spawn_poller(dev, poll as usize, 0) } != 0 {
        return ENODEV;
    }
    platform::set_device(dev);
    let device = Arc::new(platform::usb::USBDevice::new(dev, vid, pid));
    let firmware = Arc::new(super::firmware_transport::Owner::new(
        super::firmware_transport::UsbControl::new(device.clone()),
        family,
    ));
    super::DEVICES.lock().push(super::Rtl8xxxuDevice {
        device: device.clone(),
        family,
        firmware: firmware.clone(),
    });
    let _ = writeln!(
        Console,
        "  rtl.ko: {vid:04x}:{pid:04x} {} claimed",
        family.name()
    );
    platform::scheduler::spawn(async move {
        match platform::rtl_usb::configure_endpoints(&device).await {
            Ok(count) => {
                let _ = writeln!(Console, "  rtl.ko: {} endpoints configured", count);
                super::start(family, firmware);
            }
            Err(error) => {
                let _ = writeln!(
                    Console,
                    "  rtl.ko: endpoint configuration failed: {error:?}"
                );
            }
        }
    });
    0
}

/// Register every rtl8xxxu VID/PID. A kernel without a USB stack refuses
/// each row (`-ENODEV`); the PCI side is registered regardless.
pub fn register() {
    let mut registered = 0usize;
    for (&(vendor, product), &thunk) in crate::module_ids::USB_IDS.iter().zip(THUNKS.iter()) {
        // SAFETY: `NAME` is 'static; `thunk` is a valid extern "C" fn in
        // this image; the loader unregisters every match before unmapping it.
        let rc = unsafe {
            ffi::narf_register_usb_driver(
                NAME.as_ptr(),
                NAME.len(),
                MATCH_VENDOR_PRODUCT,
                vendor,
                product,
                0,
                0,
                0,
                thunk as usize,
            )
        };
        if rc == 0 {
            registered += 1;
        }
    }
    let _ = writeln!(
        Console,
        "  rtl.ko: {registered}/{} rtl8xxxu USB ids registered",
        crate::module_ids::USB_IDS.len()
    );
}
