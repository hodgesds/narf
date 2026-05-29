//! USB control-transfer builder consumed by class drivers.
//!
//! Class drivers like rtl8xxxu, hub, msc, cdc-acm need to send the
//! standard 8-byte SETUP packet (USB 2.0 §9.3) over a control pipe.
//! This module exposes a typed builder that produces a [`Setup`]
//! struct + dispatches the transfer through a [`USBDevice`] so the
//! class driver doesn't carry any xHCI-specific encoding.

#![allow(dead_code)]

use crate::device::{USBDevice, UsbError};

/// Standard SETUP packet (USB 2.0 §9.3 Table 9-2).
///
/// `bmRequestType` encodes Direction (bit 7), Type (bits[6:5]),
/// Recipient (bits[4:0]). `wValue` / `wIndex` are request-specific;
/// `wLength` is the number of bytes the host expects the device to
/// transfer in the Data Stage (0 for no Data Stage).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Setup {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl Setup {
    /// Construct a SETUP packet from raw fields.
    pub const fn new(
        bm_request_type: u8,
        b_request: u8,
        w_value: u16,
        w_index: u16,
        w_length: u16,
    ) -> Self {
        Self {
            bm_request_type,
            b_request,
            w_value,
            w_index,
            w_length,
        }
    }

    /// Encode the 8-byte little-endian SETUP packet.
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.bm_request_type;
        b[1] = self.b_request;
        b[2..4].copy_from_slice(&self.w_value.to_le_bytes());
        b[4..6].copy_from_slice(&self.w_index.to_le_bytes());
        b[6..8].copy_from_slice(&self.w_length.to_le_bytes());
        b
    }

    /// Decode a SETUP packet from 8 bytes.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            bm_request_type: b[0],
            b_request: b[1],
            w_value: u16::from_le_bytes([b[2], b[3]]),
            w_index: u16::from_le_bytes([b[4], b[5]]),
            w_length: u16::from_le_bytes([b[6], b[7]]),
        }
    }

    /// Direction bit of `bmRequestType`. true = IN (device → host).
    pub fn is_in(&self) -> bool {
        (self.bm_request_type & 0x80) != 0
    }
}

// Standard SETUP packet helpers — vendor / class / standard.

pub const RT_DIR_OUT: u8 = 0x00;
pub const RT_DIR_IN: u8 = 0x80;
pub const RT_TYPE_STANDARD: u8 = 0x00;
pub const RT_TYPE_CLASS: u8 = 0x20;
pub const RT_TYPE_VENDOR: u8 = 0x40;
pub const RT_RECIP_DEVICE: u8 = 0x00;
pub const RT_RECIP_INTERFACE: u8 = 0x01;
pub const RT_RECIP_ENDPOINT: u8 = 0x02;
pub const RT_RECIP_OTHER: u8 = 0x03;

// Standard bRequest codes (USB 2.0 §9.4).
pub const REQ_GET_STATUS: u8 = 0;
pub const REQ_CLEAR_FEATURE: u8 = 1;
pub const REQ_SET_FEATURE: u8 = 3;
pub const REQ_SET_ADDRESS: u8 = 5;
pub const REQ_GET_DESCRIPTOR: u8 = 6;
pub const REQ_SET_DESCRIPTOR: u8 = 7;
pub const REQ_GET_CONFIGURATION: u8 = 8;
pub const REQ_SET_CONFIGURATION: u8 = 9;
pub const REQ_GET_INTERFACE: u8 = 10;
pub const REQ_SET_INTERFACE: u8 = 11;

/// Build a standard GET_DESCRIPTOR setup packet.
pub const fn get_descriptor(desc_type: u8, desc_index: u8, lang_id: u16, len: u16) -> Setup {
    Setup {
        bm_request_type: RT_DIR_IN | RT_TYPE_STANDARD | RT_RECIP_DEVICE,
        b_request: REQ_GET_DESCRIPTOR,
        w_value: ((desc_type as u16) << 8) | (desc_index as u16),
        w_index: lang_id,
        w_length: len,
    }
}

/// Build a standard SET_CONFIGURATION setup packet.
pub const fn set_configuration(config: u8) -> Setup {
    Setup {
        bm_request_type: RT_DIR_OUT | RT_TYPE_STANDARD | RT_RECIP_DEVICE,
        b_request: REQ_SET_CONFIGURATION,
        w_value: config as u16,
        w_index: 0,
        w_length: 0,
    }
}

/// Build a standard SET_INTERFACE setup packet.
pub const fn set_interface(interface: u8, alt_setting: u8) -> Setup {
    Setup {
        bm_request_type: RT_DIR_OUT | RT_TYPE_STANDARD | RT_RECIP_INTERFACE,
        b_request: REQ_SET_INTERFACE,
        w_value: alt_setting as u16,
        w_index: interface as u16,
        w_length: 0,
    }
}

/// Build a vendor-specific control read.
pub const fn vendor_read(b_request: u8, w_value: u16, w_index: u16, len: u16) -> Setup {
    Setup {
        bm_request_type: RT_DIR_IN | RT_TYPE_VENDOR | RT_RECIP_DEVICE,
        b_request,
        w_value,
        w_index,
        w_length: len,
    }
}

/// Build a vendor-specific control write.
pub const fn vendor_write(b_request: u8, w_value: u16, w_index: u16, len: u16) -> Setup {
    Setup {
        bm_request_type: RT_DIR_OUT | RT_TYPE_VENDOR | RT_RECIP_DEVICE,
        b_request,
        w_value,
        w_index,
        w_length: len,
    }
}

/// Issue a control transfer described by `setup` against `dev`. If
/// the SETUP packet is IN, fill `out`; if OUT, write `out`. The
/// direction is taken from `bmRequestType` bit 7.
pub async fn submit(dev: &USBDevice, setup: Setup, data: &mut [u8]) -> Result<usize, UsbError> {
    if setup.is_in() {
        dev.control_in(
            setup.bm_request_type,
            setup.b_request,
            setup.w_value,
            setup.w_index,
            data,
        )
        .await
    } else {
        // For OUT we already have the buffer to send. Length is the
        // smaller of w_length and data slice length.
        let len = (setup.w_length as usize).min(data.len());
        dev.control_out(
            setup.bm_request_type,
            setup.b_request,
            setup.w_value,
            setup.w_index,
            &data[..len],
        )
        .await
        .map(|_| len)
    }
}
