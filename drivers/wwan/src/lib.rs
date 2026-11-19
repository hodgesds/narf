// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/lib.rs — WWAN subsystem facade
//
// Re-exports the subsystem core (`narf-drivers-wwan-core`: WwanPort +
// registry, MBIM/QMI codecs, MBIM session, raw-IP bearer, IOSM id table)
// and the USB CDC-MBIM binding (`narf-drivers-wwan-cdc-mbim`, dual-build:
// built-in here, or a loadable `.ko`), so every `narf_drivers_wwan::…` path
// is unchanged, and registers the built-in initcalls.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub use narf_drivers_wwan_cdc_mbim::usb_mbim;
pub use narf_drivers_wwan_core::*;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests;

// ─── initcall registration ───────────────────────────────────────────────────
//
// One Stage::Subsys registration, "wwan-usb-mbim", which registers the
// CDC-MBIM class driver with the USB class registry. The IOSM initcall the
// Stage-0/1 scaffold once sketched ("wwan-iosm") is NOT registered: there
// is still no IOSM transport to probe with, and an initcall that cannot
// bind anything would be census noise. It lands with the PCIe follow-on.

/// Register the crate's initcalls. Called by frame at boot.
pub fn register_initcalls() {
    narf_init::register(narf_init::Stage::Subsys, "wwan-usb-mbim", || {
        narf_drivers_wwan_cdc_mbim::register();
        narf_init::InitResult::Ok
    });
}
