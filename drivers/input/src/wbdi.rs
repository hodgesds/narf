//! Windows Biometric Device Interface (WBDI) descriptor recogniser
//! + Microsoft OS Descriptor 2.0 codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **Microsoft, "Microsoft OS 2.0 Descriptors Specification"**,
//!   Version 1.0, July 13, 2018.
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/microsoft-os-2-0-descriptors-specification>
//! - **Microsoft, "Biometric devices design guide"** — public
//!   reference for the WBDI sensor adapter interface that every
//!   WHCK-certified fingerprint reader must implement to advertise
//!   itself to the Windows Biometric Framework.
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/biometric/>
//! - **USB 2.0 Specification §9.6.5** — Interface Descriptor that
//!   carries the vendor class (0xFF) most fingerprint readers
//!   declare before identifying as WBDI via OS descriptors.
//!   <https://www.usb.org/document-library/usb-20-specification>
//!
//! No GPL / Linux source consulted. Vendor-specific command codecs
//! (Goodix, Synaptics/Validity, ELAN) are explicitly *not* covered
//! here — those formats are public only via reverse-engineered
//! work (libfprint, etc.) that this project doesn't accept as a
//! clean-room source.
//!
//! ## What this is
//!
//! Every Windows-compatible fingerprint reader since Windows 10
//! advertises itself the same way:
//!
//! 1. USB Vendor class (`bInterfaceClass = 0xFF`) interface.
//! 2. Microsoft OS 2.0 Compatible-ID descriptor naming the WBDI
//!    sensor (compatible ID = `WINUSB`, sub-compatible ID =
//!    `WBDI` for the actual biometric service).
//! 3. WBDI Vendor-Defined feature reports for image streaming and
//!    enrollment commands (vendor-specific bytes — NOT covered).
//!
//! This module implements the recogniser end (parts 1 + 2). Once a
//! transport / driver knows it's talking to a WBDI sensor, the
//! per-vendor command codec is the missing piece — but it cannot
//! be implemented clean-room from public sources today.

extern crate alloc;
use alloc::vec::Vec;

/// Microsoft OS 2.0 Descriptor wDescriptorType values
/// (MS OS 2.0 §3 Table 9).
pub mod desc_type {
    pub const SET_HEADER_DESCRIPTOR: u16 = 0x00;
    pub const SUBSET_HEADER_CONFIGURATION: u16 = 0x01;
    pub const SUBSET_HEADER_FUNCTION: u16 = 0x02;
    pub const FEATURE_COMPATIBLE_ID: u16 = 0x03;
    pub const FEATURE_REG_PROPERTY: u16 = 0x04;
    pub const FEATURE_MIN_RESUME_TIME: u16 = 0x05;
    pub const FEATURE_MODEL_ID: u16 = 0x06;
    pub const FEATURE_CCGP_DEVICE: u16 = 0x07;
    pub const FEATURE_VENDOR_REVISION: u16 = 0x08;
}

/// MS OS 2.0 Set Header (10 bytes) — top of the descriptor set.
///
/// ```text
///   0..2:   wLength               (descriptor length, =10)
///   2..4:   wDescriptorType       (=0x00 SET_HEADER_DESCRIPTOR)
///   4..8:   dwWindowsVersion      (NTDDI_WIN8_1 = 0x06030000)
///   8..10:  wTotalLength          (whole descriptor set)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SetHeader {
    pub windows_version: u32,
    pub total_length: u16,
}

/// MS OS 2.0 Compatible-ID Feature (20 bytes) — the descriptor that
/// pairs a USB function with a Windows driver. For a WBDI sensor:
///
/// - `compatible_id    = b"WINUSB\0\0"`
/// - `sub_compatible_id = b"WBDI\0\0\0\0"`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CompatibleId {
    pub compatible_id: [u8; 8],
    pub sub_compatible_id: [u8; 8],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WbdiError {
    Short,
    BadDescriptorType,
    BadHeaderLength,
    /// Descriptor `wTotalLength` is smaller than the bytes we
    /// already parsed (corrupt set).
    InvalidTotalLength,
}

impl SetHeader {
    pub fn decode(buf: &[u8]) -> Result<Self, WbdiError> {
        if buf.len() < 10 {
            return Err(WbdiError::Short);
        }
        let length = u16::from_le_bytes([buf[0], buf[1]]);
        if length != 10 {
            return Err(WbdiError::BadHeaderLength);
        }
        let dt = u16::from_le_bytes([buf[2], buf[3]]);
        if dt != desc_type::SET_HEADER_DESCRIPTOR {
            return Err(WbdiError::BadDescriptorType);
        }
        let windows_version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let total_length = u16::from_le_bytes([buf[8], buf[9]]);
        if (total_length as usize) < 10 {
            return Err(WbdiError::InvalidTotalLength);
        }
        Ok(Self {
            windows_version,
            total_length,
        })
    }
}

impl CompatibleId {
    pub fn decode(buf: &[u8]) -> Result<Self, WbdiError> {
        if buf.len() < 20 {
            return Err(WbdiError::Short);
        }
        let length = u16::from_le_bytes([buf[0], buf[1]]);
        let dt = u16::from_le_bytes([buf[2], buf[3]]);
        if length != 20 {
            return Err(WbdiError::BadHeaderLength);
        }
        if dt != desc_type::FEATURE_COMPATIBLE_ID {
            return Err(WbdiError::BadDescriptorType);
        }
        let mut cid = [0u8; 8];
        cid.copy_from_slice(&buf[4..12]);
        let mut sub = [0u8; 8];
        sub.copy_from_slice(&buf[12..20]);
        Ok(Self {
            compatible_id: cid,
            sub_compatible_id: sub,
        })
    }
}

/// Walk a complete MS OS 2.0 Descriptor Set blob and collect every
/// Compatible-ID feature found. Returns `(set_header, ids)`.
pub fn parse_descriptor_set(blob: &[u8]) -> Result<(SetHeader, Vec<CompatibleId>), WbdiError> {
    let header = SetHeader::decode(blob)?;
    let total = header.total_length as usize;
    if total > blob.len() {
        return Err(WbdiError::Short);
    }
    let mut ids = Vec::new();
    let mut off = 10usize;
    while off + 4 <= total {
        let length = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
        let dt = u16::from_le_bytes([blob[off + 2], blob[off + 3]]);
        if length < 4 || off + length > total {
            return Err(WbdiError::InvalidTotalLength);
        }
        if dt == desc_type::FEATURE_COMPATIBLE_ID {
            let cid = CompatibleId::decode(&blob[off..off + length])?;
            ids.push(cid);
        }
        off += length;
    }
    Ok((header, ids))
}

/// Compatible-ID strings the WBDI sensor adapter advertises.
pub const COMPATIBLE_ID_WINUSB: &[u8; 8] = b"WINUSB\0\0";
pub const SUB_COMPATIBLE_ID_WBDI: &[u8; 8] = b"WBDI\0\0\0\0";

/// `true` iff the descriptor set names the device a WBDI sensor.
pub fn is_wbdi(blob: &[u8]) -> bool {
    match parse_descriptor_set(blob) {
        Err(_) => false,
        Ok((_, ids)) => ids.iter().any(|c| {
            &c.compatible_id == COMPATIBLE_ID_WINUSB
                && &c.sub_compatible_id == SUB_COMPATIBLE_ID_WBDI
        }),
    }
}

/// Recognise a fingerprint-reader-shaped USB Configuration: vendor
/// class (0xFF) interface that *also* advertises a WBDI Compatible
/// ID via MS OS 2.0. Returns the interface number on hit.
pub fn find_wbdi_interface(cfg: &[u8], ms_os_blob: &[u8]) -> Option<u8> {
    if !is_wbdi(ms_os_blob) {
        return None;
    }
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 4 && len >= 9 {
            if cfg[i + 5] == 0xFF {
                return Some(cfg[i + 2]);
            }
        }
        i += len;
    }
    None
}
