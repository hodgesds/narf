//! Root-hub port reset → Enable Slot → Address Device → Get Device
//! Descriptor → Get Configuration Descriptor → Configure Endpoint
//! flow. Re-exports the async helpers on [`Xhci`] for callers that
//! want a focused enumeration surface.

#![allow(dead_code)]

pub use super::{
    Device, EndpointConfig, EndpointKind, EndpointState, PortSpeed, Topology, Xhci, XhciError,
};

/// Standard USB request constants (§9.4 USB 2.0). Re-exported for the
/// control-transfer builder.
pub use super::USB_REQ_GET_DESCRIPTOR;
pub const USB_DESC_TYPE_DEVICE: u8 = 1;
pub const USB_DESC_TYPE_CONFIGURATION: u8 = 2;
pub const USB_DESC_TYPE_STRING: u8 = 3;
pub const USB_DESC_TYPE_INTERFACE: u8 = 4;
pub const USB_DESC_TYPE_ENDPOINT: u8 = 5;

/// USB standard device request `bmRequestType` values (USB 2.0 §9.3).
pub const USB_RT_DEV_TO_HOST_STD: u8 = 0x80;
pub const USB_RT_HOST_TO_DEV_STD: u8 = 0x00;
pub const USB_RT_DEV_TO_HOST_CLASS: u8 = 0xA0;
pub const USB_RT_HOST_TO_DEV_CLASS: u8 = 0x20;
pub const USB_RT_DEV_TO_HOST_VENDOR: u8 = 0xC0;
pub const USB_RT_HOST_TO_DEV_VENDOR: u8 = 0x40;
