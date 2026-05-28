// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/qmi.rs — QMI (Qualcomm Modem Interface) framing
//
// QMI is used by Qualcomm-based WWAN modems (Snapdragon X55, Sierra Wireless
// EM7565, etc.).  The host communicates over a USB bulk endpoint or PCIe MHI
// channel framed as QMUX packets.
//
// QMUX packet layout (little-endian):
//
//   Offset  Size  Field
//   ------  ----  -----
//     0       1   I/F type   (0x01 = link-layer, always 0x01 for USB)
//     1       2   Length     (total packet length minus the I/F byte)
//     3       1   Flags      (0x00 = client → service; 0x80 = service → client)
//     4       1   ServiceId  (CTL=0x00, WDS=0x01, DMS=0x02, NAS=0x03, …)
//     5       1   ClientId   (0x00 for CTL; host-allocated for all others)
//     6       2   TxId       (transaction ID, little-endian u16)
//     8       2   MsgId      (message ID within the service)
//    10       2   TlvLength  (total length of TLV section that follows)
//    12+      n   TLVs       (type[1] | length[2] | value[length])
//
// Total fixed-header size: 12 bytes.
//
// Each service defines its own set of message IDs and TLV structures.  Only
// the CTL service (ServiceId 0x00) is relevant for initial bring-up (used to
// allocate ClientIds for other services).
//
// Linux cross-reference:
//   drivers/net/usb/qmi_wwan.c  — USB endpoint wiring
//   net/qrtr/qrtr.c             — Qualcomm IPC Router (higher layer)

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ─── QMUX constants ──────────────────────────────────────────────────────────

/// Fixed I/F type byte that opens every QMUX packet.
pub const QMUX_IF_TYPE: u8 = 0x01;

/// Flags value for a host→modem message (control link layer).
pub const QMUX_FLAGS_SENDER_HOST: u8 = 0x00;
/// Flags value for a modem→host message.
pub const QMUX_FLAGS_SENDER_MODEM: u8 = 0x80;

/// Service IDs — one per QMI service family.
pub const QMI_SVC_CTL: u8 = 0x00; // Control — client allocation
pub const QMI_SVC_WDS: u8 = 0x01; // Wireless Data Service
pub const QMI_SVC_DMS: u8 = 0x02; // Device Management Service
pub const QMI_SVC_NAS: u8 = 0x03; // Network Access Service
pub const QMI_SVC_WMS: u8 = 0x05; // Wireless Messaging Service
pub const QMI_SVC_PDS: u8 = 0x06; // Position Determination Service
pub const QMI_SVC_UIM: u8 = 0x0B; // User Identity Module

/// Minimum QMUX header size in bytes.
pub const QMUX_HEADER_SIZE: usize = 12;

// ─── QmiError ────────────────────────────────────────────────────────────────

/// Errors returned by QMI codec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QmiError {
    /// Buffer too short to contain a complete QMUX header.
    TooShort,
    /// The I/F type byte is not 0x01.
    BadIfType,
    /// The Length field indicates fewer bytes than the minimum header.
    InvalidLength,
}

// ─── QmiHeader ───────────────────────────────────────────────────────────────

/// Decoded 12-byte QMUX fixed header.
///
/// Wire layout (all multi-byte fields little-endian):
///
/// ```text
/// byte  0     if_type     always 0x01
/// byte  1..2  length      total - 1 (excludes the if_type byte)
/// byte  3     flags       0x00 host→modem | 0x80 modem→host
/// byte  4     service_id  QMI_SVC_*
/// byte  5     client_id   0x00 for CTL; host-allocated otherwise
/// byte  6..7  tx_id       transaction ID (u16 LE)
/// byte  8..9  msg_id      message ID within service (u16 LE)
/// byte 10..11 tlv_length  byte count of trailing TLV section
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmiHeader {
    /// I/F type — always `QMUX_IF_TYPE` (0x01) on USB QMUX.
    pub if_type:    u8,
    /// Total packet length minus the leading `if_type` byte.
    pub length:     u16,
    /// Direction flags: `QMUX_FLAGS_SENDER_HOST` or `QMUX_FLAGS_SENDER_MODEM`.
    pub flags:      u8,
    /// Service identifier (QMI_SVC_*).
    pub service_id: u8,
    /// Client identifier allocated by CTL service.  0x00 for CTL itself.
    pub client_id:  u8,
    /// Host-allocated transaction ID.  Echoed in responses.
    pub tx_id:      u16,
    /// Message ID within the service.
    pub msg_id:     u16,
    /// Byte length of the TLV section that follows this header.
    pub tlv_length: u16,
}

impl QmiHeader {
    /// Encode into the 12-byte little-endian wire format.
    #[inline]
    pub fn encode(&self) -> [u8; QMUX_HEADER_SIZE] {
        let mut out = [0u8; QMUX_HEADER_SIZE];
        out[0]      = self.if_type;
        out[1..3].copy_from_slice(&self.length.to_le_bytes());
        out[3]      = self.flags;
        out[4]      = self.service_id;
        out[5]      = self.client_id;
        out[6..8].copy_from_slice(&self.tx_id.to_le_bytes());
        out[8..10].copy_from_slice(&self.msg_id.to_le_bytes());
        out[10..12].copy_from_slice(&self.tlv_length.to_le_bytes());
        out
    }

    /// Decode a QMUX header from a byte slice.
    ///
    /// Returns `Err(QmiError::TooShort)` if `buf.len() < 12`.
    /// Returns `Err(QmiError::BadIfType)` if byte 0 is not `0x01`.
    /// Returns `Err(QmiError::InvalidLength)` if the length field is
    /// smaller than the remaining fixed-header bytes (11).
    pub fn decode(buf: &[u8]) -> Result<Self, QmiError> {
        if buf.len() < QMUX_HEADER_SIZE {
            return Err(QmiError::TooShort);
        }
        if buf[0] != QMUX_IF_TYPE {
            return Err(QmiError::BadIfType);
        }
        let length     = u16::from_le_bytes([buf[1], buf[2]]);
        // Length covers bytes [1..] so minimum meaningful value is 11
        // (the rest of the fixed header after the if_type byte).
        if (length as usize) < (QMUX_HEADER_SIZE - 1) {
            return Err(QmiError::InvalidLength);
        }
        let flags      = buf[3];
        let service_id = buf[4];
        let client_id  = buf[5];
        let tx_id      = u16::from_le_bytes([buf[6], buf[7]]);
        let msg_id     = u16::from_le_bytes([buf[8], buf[9]]);
        let tlv_length = u16::from_le_bytes([buf[10], buf[11]]);

        Ok(Self {
            if_type: QMUX_IF_TYPE,
            length,
            flags,
            service_id,
            client_id,
            tx_id,
            msg_id,
            tlv_length,
        })
    }
}

// ─── CTL helpers ─────────────────────────────────────────────────────────────

/// QMI CTL message IDs used during initial bring-up.
///
/// Linux ref: `drivers/net/usb/qmi_wwan.c` and Qualcomm QMI docs.
pub const QMI_CTL_GET_VERSION_INFO: u16 = 0x0021;
pub const QMI_CTL_ALLOCATE_CLIENT_ID: u16 = 0x0022;
pub const QMI_CTL_RELEASE_CLIENT_ID: u16  = 0x0023;
pub const QMI_CTL_SYNC: u16               = 0x0027;

/// Build a bare QMI CTL GET_VERSION_INFO request (no TLVs).
///
/// `tx_id` starts at 1 and should be incremented per request.
pub fn ctl_get_version_info(tx_id: u16) -> Vec<u8> {
    let hdr = QmiHeader {
        if_type:    QMUX_IF_TYPE,
        // length = QMUX_HEADER_SIZE - 1 (everything after if_type) + 0 TLVs
        length:     (QMUX_HEADER_SIZE - 1) as u16,
        flags:      QMUX_FLAGS_SENDER_HOST,
        service_id: QMI_SVC_CTL,
        client_id:  0x00,
        tx_id,
        msg_id:     QMI_CTL_GET_VERSION_INFO,
        tlv_length: 0,
    };
    hdr.encode().to_vec()
}
