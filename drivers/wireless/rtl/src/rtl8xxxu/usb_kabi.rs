//! The module build's USB binding (`rtl.ko`, rtl8xxxu).
//!
//! Built in, `rtl8xxxu_probe` classifies the dongle by VID/PID
//! ([`super::regs::ChipFamily::from_usb_id`]), refuses an unknown one, then
//! retains it; RTL8188EU, RTL8192EU and RTL8723BU go on to the async
//! factory/power/firmware owner and, once separately admitted, the station.
//! The module registers every `RTL8XXXU_USB_IDS` row and runs the same
//! classification. The firmware owner and station are not carried by the
//! module build yet, so a claimed dongle stays idle, as the built-in's
//! detection-only families do.

use core::fmt::Write as _;

use super::regs::ChipFamily;
use crate::platform::Console;

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
        pub fn narf_usb_config_descriptor(
            dev: u64,
            buf: *mut u8,
            len: usize,
            out_len: *mut usize,
        ) -> i32;
    }
}

/// `usb_device_id` VID/PID match (`narf_bus::module_usb::MATCH_VENDOR_PRODUCT`).
const MATCH_VENDOR_PRODUCT: u16 = 1 << 0;
const ENODEV: i32 = -19;
const ENOBUFS: i32 = -105;
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

/// `rtl8xxxu_probe`'s classification for the matched `(vid, pid)`.
fn probe(dev: u64, vid: u16, pid: u16) -> i32 {
    let family = ChipFamily::from_usb_id(vid, pid);
    if family == ChipFamily::Unknown {
        // UsbProbeError::UnsupportedVariant: an RTL8XXXU_USB_IDS row with
        // no owning chip family (e.g. RTL8710BU / RTL8188GU).
        let _ = writeln!(
            Console,
            "  rtl.ko: {vid:04x}:{pid:04x} has no rtl8xxxu chip family; not claimed"
        );
        return ENODEV;
    }
    // The token must name a live USB context of this module: size its
    // configuration descriptor (`-ENOBUFS` with the length) before claiming.
    let mut len = 0usize;
    // SAFETY: sizing call — null buffer, zero length, `len` a live local.
    let rc = unsafe { ffi::narf_usb_config_descriptor(dev, core::ptr::null_mut(), 0, &mut len) };
    if !matches!(rc, 0 | ENOBUFS) || len == 0 {
        return ENODEV;
    }
    let _ = writeln!(
        Console,
        "  rtl.ko: {vid:04x}:{pid:04x} {} claimed (config {len} bytes); firmware and \
         station are not carried by the module build",
        family.name()
    );
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
