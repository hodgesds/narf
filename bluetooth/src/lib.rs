//! narf-bluetooth — Bluetooth HCI core (clean-room).
//!
//! Spec sources (public only):
//! - Bluetooth Core Specification 5.3, Vol 4 Part E (HCI Functional
//!   Specification) — Bluetooth SIG.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//! - Bluetooth Core Specification 5.3, Vol 4 Part B (USB Transport
//!   Layer) — Bluetooth SIG.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//! - USB Class Definitions for Wireless Controllers v1.0, USB-IF
//!   (class 0xE0, subclass 0x01, protocol 0x01).
//!
//! No GPL / Linux Bluetooth source consulted.
//!
//! ## Surface
//!
//! - [`hci`] — packet codec for Command, ACL, Synchronous Data, Event.
//! - [`opcode`] — Mandatory + commonly-used HCI opcode constants.
//! - [`event`] — Event-code enum + event packet builders/parsers.
//! - [`transport`] — `HciTransport` trait. USB / UART concrete
//!   bindings register against the global registry.
//! - [`controller`] — bring-up state machine (Reset → Read Local
//!   Version → Read BD_ADDR → Set Event Mask). Drives a transport
//!   through the mandatory init dance described in Vol 4 Part E §3.
//!
//! No data-plane work yet (L2CAP/ATT/GATT/SMP); those land as
//! separate crates so per-protocol cap-typing stays tight.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod att;
pub mod avdtp;
pub mod controller;
pub mod event;
pub mod gap;
pub mod gatt;
pub mod gatt_server;
pub mod h4;
pub mod h5;
pub mod hci;
pub mod hfp;
pub mod hid_profile;
pub mod hogp;
pub mod usb_transport;
pub mod rfcomm;
pub mod sdp;
pub mod l2cap;
pub mod mesh;
pub mod opcode;
pub mod smp;
pub mod transport;

mod tests;

use narf_capabilities::{Cap, CapKind, CapType, Grant};

/// Cap-type marker for the Bluetooth control surface.
#[derive(Copy, Clone, Debug)]
pub struct Bluetooth;

impl CapType for Bluetooth {
    const KIND: CapKind = CapKind::Bluetooth;
}

/// Mint a Bluetooth authority cap. TCB-only entry.
pub fn bootstrap_bluetooth_authority() -> Cap<Bluetooth, Grant> {
    Cap::<Bluetooth, Grant>::bootstrap()
}

/// Stage::Late initcall registration. Stage 0 just registers a
/// per-stage placeholder so the boot summary records that the
/// Bluetooth subsystem is wired in; the actual USB transport bind
/// runs out of the USB host supervisor's per-port attach pass
/// (`narf_drivers_usb::btusb::try_bind_btusb_already_addressed`).
///
/// Future stages will hook here to spawn an HCI event-pump task and
/// register Bluetooth-specific syscalls.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Late, "bluetooth-stage0", || {
        // Stage 0: no work beyond registering the subsystem. A real
        // controller probed by the USB supervisor will print its own
        // `bluetooth: ... adapter` line at attach time.
        let _ = transport::transport_count();
        InitResult::Ok
    });
}
