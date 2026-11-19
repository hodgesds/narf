//! USB CDC-MBIM modem binding — dual-build (built-in or loadable `.ko`).
//!
//! The binding lives in [`usb_mbim`] (class-registry claim, descriptor and
//! class-request bring-up, control port, RX/notification pumps, raw-IP
//! bearer handoff) and compiles only for the built-in build, on top of the
//! WWAN core (`narf-drivers-wwan-core`); `narf-drivers-wwan` re-exports it.
//!
//! The `module` build registers the same CDC-MBIM interface match
//! (class 0x02 Communications, subclass 0x0E MBIM, any protocol) through the
//! `narf_register_usb_driver` KSYMTAB export. Registration-only: the probe
//! returns `-ENOSYS` until a USB transfer datapath is exported to modules.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use narf_driver_macros::narf_driver;

#[cfg(feature = "builtin")]
extern crate alloc;

// `usb_mbim` reaches the core through `crate::…` paths.
#[cfg(feature = "builtin")]
#[allow(unused_imports)]
use narf_drivers_wwan_core::{
    bearer, mbim, register_port, session, WwanError, WwanPort, WwanPortKind,
};

#[cfg(feature = "builtin")]
pub mod usb_mbim;

narf_driver! {
    name: "cdc_mbim",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "USB CDC-MBIM cellular modem",
        target_domain: "net",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    usb_mbim::register();
}

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
}

/// Loadable-module registration path (registration-only; `-ENOSYS` probe).
/// Links only the `narf_register_usb_driver` KSYMTAB import.
#[cfg(feature = "module")]
mod module_probe {
    /// `usb_device_id` match flags (`narf_bus::module_usb`).
    const MATCH_INT_CLASS: u16 = 1 << 1;
    const MATCH_INT_SUBCLASS: u16 = 1 << 2;
    /// `usb_mbim::MBIM_USB_MATCH`: CDC Communications class, MBIM subclass.
    const USB_CLASS_CDC_COMM: u8 = 0x02;
    const CDC_SUBCLASS_MBIM: u8 = 0x0E;
    const NAME: &[u8] = b"cdc_mbim-module";

    unsafe extern "C" {
        #[allow(clippy::too_many_arguments)]
        fn narf_register_usb_driver(
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
    }

    extern "C" fn probe_c(_dev_token: u64, _reserved: u64) -> i32 {
        // -ENOSYS: no USB transfer datapath is exported to modules yet.
        -38
    }

    pub fn register() {
        // SAFETY: `NAME` is 'static; `probe_c` is a valid extern "C" fn.
        // The loader unregisters the match before unmapping this image.
        unsafe {
            narf_register_usb_driver(
                NAME.as_ptr(),
                NAME.len(),
                MATCH_INT_CLASS | MATCH_INT_SUBCLASS,
                0,
                0,
                USB_CLASS_CDC_COMM,
                CDC_SUBCLASS_MBIM,
                0,
                probe_c as usize,
            );
        }
    }
}
