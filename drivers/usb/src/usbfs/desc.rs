//! Configuration-descriptor walks usbfs needs: every alternate setting
//! with its endpoints (Linux keeps these parsed in `usb_host_config`;
//! NARF keeps the raw blobs in [`crate::usbdev::UsbDev::configs`]).

use alloc::vec::Vec;

use crate::xhci::{EndpointConfig, EndpointKind};

/// USB 2.0 Table 9-13 `bmAttributes` transfer types.
pub const XFER_CONTROL: u8 = 0;
pub const XFER_ISOC: u8 = 1;
pub const XFER_BULK: u8 = 2;
pub const XFER_INT: u8 = 3;

/// USB class code of a printer interface (`USB_CLASS_PRINTER`).
pub const CLASS_PRINTER: u8 = 7;

/// One endpoint descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EpDesc {
    pub addr: u8,
    pub attributes: u8,
    /// Raw `wMaxPacketSize`, multiplier bits included.
    pub max_packet: u16,
    pub interval: u8,
}

impl EpDesc {
    /// `usb_endpoint_type`.
    pub fn xfer(&self) -> u8 {
        self.attributes & 0x03
    }

    /// `usb_endpoint_maxp`: the packet size without multiplier bits.
    pub fn maxp(&self) -> usize {
        usize::from(self.max_packet & 0x07ff)
    }

    /// The controller endpoint this descriptor programs. Control
    /// endpoints beyond EP0 have no xHCI configuration here.
    pub fn config(&self) -> Option<EndpointConfig> {
        let is_in = self.addr & 0x80 != 0;
        let kind = match (self.xfer(), is_in) {
            (XFER_BULK, true) => EndpointKind::BulkIn,
            (XFER_BULK, false) => EndpointKind::BulkOut,
            (XFER_INT, true) => EndpointKind::InterruptIn,
            (XFER_INT, false) => EndpointKind::InterruptOut,
            (XFER_ISOC, true) => EndpointKind::IsochIn,
            (XFER_ISOC, false) => EndpointKind::IsochOut,
            _ => return None,
        };
        Some(EndpointConfig {
            ep_addr: self.addr,
            max_packet: self.max_packet,
            kind,
            interval: self.interval,
        })
    }
}

/// One alternate setting of one interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AltDesc {
    pub number: u8,
    pub alt: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<EpDesc>,
}

/// Every alternate setting in `config`, in descriptor order. Endpoint
/// descriptors belong to the interface descriptor before them.
pub fn alt_settings(config: &[u8]) -> Vec<AltDesc> {
    let mut out: Vec<AltDesc> = Vec::new();
    let mut at = 0usize;
    while at + 2 <= config.len() {
        let len = usize::from(config[at]);
        if len < 2 || at + len > config.len() {
            break;
        }
        match config[at + 1] {
            0x04 if len >= 9 => out.push(AltDesc {
                number: config[at + 2],
                alt: config[at + 3],
                class: config[at + 5],
                subclass: config[at + 6],
                protocol: config[at + 7],
                endpoints: Vec::new(),
            }),
            0x05 if len >= 7 => {
                if let Some(current) = out.last_mut() {
                    current.endpoints.push(EpDesc {
                        addr: config[at + 2],
                        attributes: config[at + 3],
                        max_packet: u16::from_le_bytes([config[at + 4], config[at + 5]]),
                        interval: config[at + 6],
                    });
                }
            }
            _ => {}
        }
        at += len;
    }
    out
}

/// `usb_altnum_to_altsetting` over the configuration.
pub fn find_alt(config: &[u8], iface: u8, alt: u8) -> Option<AltDesc> {
    alt_settings(config)
        .into_iter()
        .find(|a| a.number == iface && a.alt == alt)
}

/// `usb_ifnum_to_if`: whether `iface` is an interface of `config`.
pub fn has_interface(config: &[u8], iface: u8) -> bool {
    alt_settings(config).iter().any(|a| a.number == iface)
}

/// How many alternate settings `iface` has (`num_altsetting`).
pub fn num_altsettings(config: &[u8], iface: u8) -> usize {
    alt_settings(config)
        .iter()
        .filter(|a| a.number == iface)
        .count()
}

/// The interface number owning endpoint `ep` in any alternate setting
/// (the search of Linux `findintfep`, which the caller guards).
pub fn interface_for_endpoint(config: &[u8], ep: u8) -> Option<u8> {
    alt_settings(config)
        .iter()
        .find(|a| a.endpoints.iter().any(|e| e.addr == ep))
        .map(|a| a.number)
}
