//! narf-usbpd — USB Power Delivery + Type-C Port Manager (clean-room).
//!
//! Spec sources (public only):
//! - USB Power Delivery Specification 3.1 v1.8 (USB-IF).
//! - USB Type-C Cable and Connector Specification 2.2 (USB-IF).
//! - USB Type-C Port Controller Interface Specification 2.0 (USB-IF).
//!
//! No GPL / Linux source consulted.
//!
//! ## Surface
//!
//! - [`message`] — PD message header + Power/Request Data Object
//!   encode/decode.
//! - [`tcpc`] — `Tcpc` trait: register-level Type-C Port Controller
//!   interface (CC pin status, transmit/receive PD frames, role
//!   switch). Vendor TCPC drivers (FUSB302, TPS6598x) implement it.
//! - [`tcpm`] — sink-role state machine that drives a `Tcpc` to a
//!   negotiated power contract.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod message;
pub mod sop_prime;
pub mod tcpc;
pub mod tcpm;
pub mod vdm;

mod tests;

use narf_capabilities::{Cap, CapKind, CapType, Grant};

/// Cap-type marker for the USB-PD control surface.
#[derive(Copy, Clone, Debug)]
pub struct UsbPd;

impl CapType for UsbPd {
    const KIND: CapKind = CapKind::UsbPd;
}

/// Mint a USB-PD authority cap. TCB-only entry.
pub fn bootstrap_usbpd_authority() -> Cap<UsbPd, Grant> {
    Cap::<UsbPd, Grant>::bootstrap()
}
