//! Realtek RTW88/RTW89 PCIe Wi-Fi family — dual-build (built-in or loadable
//! `.ko`).
//!
//! Promoted from the former `drivers/wireless/src/{rtw88,rtw89}/` modules into
//! one family crate: rtw89 reuses rtw88's `pci_park` helper, so they share a
//! crate (inner module paths `rtw88`/`rtw89` preserved). rtw88's USB datapath
//! reuses the shared transport in `narf-drivers-wireless-rtl-usb`.
//!
//! Built in, [`rtw88`] and [`rtw89`] are the whole drivers. The `module`
//! build is the same rtw88 source running inside the `.ko` for its USB
//! parts (RTL8821CU / RTL8822BU): it registers their USB ids through
//! `narf_register_usb_driver` and drives the function through the USB KABI
//! (`narf_usb_*`), with the kernel services the driver names supplied by
//! `rtw88::platform` over `narf-module-rt` and the KABI. The rtw88 and
//! rtw89 PCIe ids stay registration-only in the module (`module_probe`,
//! probe `-ENOSYS`); rtw89 does not build into the `.ko` at all.
//!
//! ## Hardware validation is gated
//!
//! QEMU emulates no Realtek Wi-Fi device (PCIe or USB), so chip bring-up and
//! association cannot run here. Validation is dual builds, fixtures and the
//! gated station/AP tests on both architectures; these do not establish RF
//! acceptance.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

use narf_driver_macros::narf_driver;

// Shared, driver-agnostic helpers live in `narf-drivers-wireless-core`.
// Re-exported at the crate root so the inner drivers' `crate::future_heap` and
// `crate::watchdog_work` references resolve unchanged after promotion. The
// module build supplies the same names over its own executor.
#[cfg(feature = "builtin")]
pub(crate) use narf_drivers_wireless_core::{future_heap, watchdog_work};
#[cfg(feature = "module")]
pub(crate) use rtw88::platform::watchdog_work;

/// The rtw88 driver. One source tree in both builds: kernel services come
/// from the kernel's crates built in and from `rtw88::platform` in the
/// `.ko`.
pub mod rtw88;

#[cfg(feature = "builtin")]
pub mod rtw89;

#[cfg(feature = "module")]
mod module_probe;

narf_driver! {
    name: "rtw",
    module: {
        version: "0.1.0",
        license: "GPL-2.0-or-later",
        author: "narf",
        description: "Realtek RTW88/RTW89 PCIe Wi-Fi + RTL8821CU/8822BU USB",
        target_domain: "net",
        required_caps: "BusDevice:Write,NetIface:Write,Firmware:Read",
    },
    register: do_register,
}

#[cfg(feature = "builtin")]
fn do_register() {
    rtw88::register();
    rtw89::register();
}

/// The station bring-up parameters (`rtw88::iface_module::autoconnect`):
/// `rtw.ssid=` / `rtw.psk=` / `rtw.passphrase=` / `rtw.scan=`, declared so
/// the loader applies them from the kernel command line (and the load's
/// own arguments) before init. Empty = not given.
#[cfg(feature = "module")]
#[used]
#[link_section = ".narf_kparams"]
static KPARAMS: [u8; 29] = *b"ssid=\npsk=\npassphrase=\nscan=\n";

#[cfg(feature = "module")]
fn do_register() {
    module_probe::register();
    rtw88::register_module();
}
