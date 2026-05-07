//! USB transport binding for HCI — clean-room.
//!
//! ## Sources (public only)
//!
//! - **Bluetooth Core Specification 5.4, Vol 4 Part B** —
//!   "USB Transport Layer". Defines the endpoint roles, Setup-packet
//!   shape for HCI Commands, and the four-channel split (control /
//!   interrupt-IN / bulk-IN / bulk-OUT, plus optional isoch).
//!   <https://www.bluetooth.com/specifications/specs/core-specification-5-4/>
//! - **USB Class Definitions for Wireless Controllers v1.0**,
//!   USB-IF, 2007. Class triple `0xE0 / 0x01 / 0x01` ("Wireless /
//!   RF / Bluetooth Programming Interface") identifies a HCI
//!   transport device on the USB bus.
//!   <https://www.usb.org/document-library/usb-class-definitions-wireless-controllers-10>
//! - **USB 2.0 §9.6.5** — Interface Descriptor layout used by the
//!   class-triple recogniser.
//!   <https://www.usb.org/document-library/usb-20-specification>
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Two pieces:
//!
//! 1. **Recogniser** — given a USB Configuration Descriptor blob,
//!    [`is_bluetooth_hci`] returns `true` iff the descriptor
//!    declares a HCI transport interface (class 0xE0 / sub 0x01 /
//!    proto 0x01). [`find_endpoints`] returns the descriptor offsets
//!    + endpoint addresses for the four required endpoints.
//! 2. **HCI Setup-packet builder** — [`hci_command_setup`] builds
//!    the 8-byte Setup packet that wraps a HCI Command on the
//!    control endpoint. The actual command payload follows the
//!    Setup packet on the same control transfer (USB 2.0 §9.4).
//!
//! Live attach + the `HciTransport`-trait implementor that stitches
//! these two together with xHCI / EHCI transfers lands when the
//! controller-pump scaffold gets a "register class-driver by
//! interface triple" hook. The codecs here are the bring-up half.

extern crate alloc;
use alloc::vec::Vec;

/// USB Class — Wireless Controller.
pub const USB_CLASS_WIRELESS: u8 = 0xE0;
/// USB Subclass — RF Controller.
pub const USB_SUBCLASS_RF: u8 = 0x01;
/// USB Protocol — Bluetooth Programming Interface.
pub const USB_PROTOCOL_BLUETOOTH: u8 = 0x01;

/// USB transfer-type values from §9.6.6 (bmAttributes bits[1:0]).
const XFER_CONTROL: u8 = 0;
const XFER_ISOCH: u8 = 1;
const XFER_BULK: u8 = 2;
const XFER_INTERRUPT: u8 = 3;

/// Scan a Configuration Descriptor and report whether any
/// interface declares the Bluetooth HCI class triple.
pub fn is_bluetooth_hci(cfg: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 4 && len >= 9 {
            // Interface Descriptor (§9.6.5).
            if cfg[i + 5] == USB_CLASS_WIRELESS
                && cfg[i + 6] == USB_SUBCLASS_RF
                && cfg[i + 7] == USB_PROTOCOL_BLUETOOTH
            {
                return true;
            }
        }
        i += len;
    }
    false
}

/// Endpoint addresses for a Bluetooth HCI USB transport, as parsed
/// from the Configuration Descriptor.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HciEndpoints {
    /// Interface number (`bInterfaceNumber`).
    pub interface: u8,
    /// Interrupt-IN endpoint (HCI Events). `None` = not present.
    pub event_ep: Option<u8>,
    /// Bulk-IN endpoint (ACL Data, device → host).
    pub acl_in_ep: Option<u8>,
    /// Bulk-OUT endpoint (ACL Data, host → device).
    pub acl_out_ep: Option<u8>,
    /// Optional Isoch-IN endpoint (Synchronous Data — eSCO/SCO).
    pub sco_in_ep: Option<u8>,
    /// Optional Isoch-OUT endpoint.
    pub sco_out_ep: Option<u8>,
}

/// Walk a Configuration Descriptor and locate the endpoint
/// addresses for the first HCI interface. Returns `None` if no
/// HCI interface is present.
pub fn find_endpoints(cfg: &[u8]) -> Option<HciEndpoints> {
    let mut i = 0;
    let mut in_match = false;
    let mut eps = HciEndpoints::default();
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        match cfg[i + 1] {
            4 if len >= 9 => {
                let class = cfg[i + 5];
                let sub = cfg[i + 6];
                let proto = cfg[i + 7];
                in_match = class == USB_CLASS_WIRELESS
                    && sub == USB_SUBCLASS_RF
                    && proto == USB_PROTOCOL_BLUETOOTH;
                if in_match {
                    eps.interface = cfg[i + 2];
                }
            }
            5 if len >= 7 && in_match => {
                let addr = cfg[i + 2];
                let attr = cfg[i + 3];
                let xfer = attr & 0x03;
                let is_in = addr & 0x80 != 0;
                match (xfer, is_in) {
                    (XFER_INTERRUPT, true) if eps.event_ep.is_none() => eps.event_ep = Some(addr),
                    (XFER_BULK, true) if eps.acl_in_ep.is_none() => eps.acl_in_ep = Some(addr),
                    (XFER_BULK, false) if eps.acl_out_ep.is_none() => eps.acl_out_ep = Some(addr),
                    (XFER_ISOCH, true) if eps.sco_in_ep.is_none() => eps.sco_in_ep = Some(addr),
                    (XFER_ISOCH, false) if eps.sco_out_ep.is_none() => eps.sco_out_ep = Some(addr),
                    _ => {
                        let _ = (XFER_CONTROL,); // silence "unused const" if we shrink further
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    if eps.event_ep.is_none() || eps.acl_in_ep.is_none() || eps.acl_out_ep.is_none() {
        return None;
    }
    Some(eps)
}

/// Build the 8-byte SETUP packet for a HCI Command transfer (Vol 4
/// Part B §2.2.1). HCI Commands always go on the default-control
/// endpoint (EP0) with this fixed bmRequestType=0x20 (Class |
/// Interface | Host-to-Device) and bRequest=0x00.
pub fn hci_command_setup(interface: u8, command_len: u16) -> [u8; 8] {
    [
        0x20,                  // bmRequestType
        0x00,                  // bRequest
        0x00, 0x00,            // wValue
        interface, 0x00,        // wIndex (low byte = interface)
        (command_len & 0xFF) as u8,
        ((command_len >> 8) & 0xFF) as u8, // wLength
    ]
}

/// Build the 8-byte SETUP packet for a HCI Reset shortcut. Equivalent
/// to `hci_command_setup(interface, 3)` since the HCI_Reset command
/// is a 3-byte payload (opcode 0x0C03 + zero parameter-length byte).
pub fn hci_reset_setup(interface: u8) -> [u8; 8] {
    hci_command_setup(interface, 3)
}

/// Decode a SETUP packet and report whether it's a HCI Command
/// (used by parsing logic on the device side / fuzzers / tests).
pub fn is_hci_command_setup(setup: &[u8; 8]) -> bool {
    setup[0] == 0x20 && setup[1] == 0x00
}

/// Wrap a HCI Command opcode into the wire form: 2-byte LE opcode +
/// 1-byte parameter length + N parameter bytes. Same shape as the
/// HCI command-payload that travels in the Data stage of the
/// control transfer (Bluetooth Core 5.x Vol 4 Part E §5.4.1).
pub fn build_hci_command(opcode: u16, params: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(3 + params.len());
    buf.extend_from_slice(&opcode.to_le_bytes());
    buf.push(params.len() as u8);
    buf.extend_from_slice(params);
    buf
}
