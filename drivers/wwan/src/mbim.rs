// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/mbim.rs — MBIM 1.0 message header codec
//
// Mobile Broadband Interface Model (MBIM) is a USB CDC subclass (0x0E) defined
// by the MBIM 1.0 specification (Microsoft, 2011).  The host and function
// exchange fixed-size message headers followed by variable-length payloads.
//
// This module implements encode/decode for the 12-byte MBIM message header
// and the set of well-known message type codes.  It does not yet implement
// fragmentation reassembly, service UUIDs, CID dispatch, or the USB
// control-plane (those are Stage-2+).
//
// Wire format (MBIM 1.0 §10.3.1):
//
//   Offset  Size  Field
//   ------  ----  -----
//     0       4   MessageType    (little-endian u32)
//     4       4   MessageLength  (total packet bytes, including header)
//     8       4   TransactionId  (little-endian u32; host-allocated)
//
// Fragmented messages (FragmentHeader) insert two additional u32 fields
// (TotalFragments, CurrentFragment) after TransactionId; that extension is
// handled by the FragmentHeader type but is otherwise not exercised here.
//
// Linux cross-reference: drivers/net/wwan/mhi_wwan_mbim.c,
//                        drivers/usb/class/cdc-wdm.c

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ─── Message type codes ──────────────────────────────────────────────────────
//
// MBIM 1.0 §10.3 Table 10-2.

/// MBIM_OPEN_MSG: host requests the function to open the MBIM interface.
pub const MBIM_OPEN: u32 = 0x0000_0001;
/// MBIM_CLOSE_MSG: host requests the function to close the interface.
pub const MBIM_CLOSE: u32 = 0x0000_0002;
/// MBIM_COMMAND_MSG: host sends a CID command to the function.
pub const MBIM_COMMAND_MSG: u32 = 0x0000_0003;
/// MBIM_HOST_ERROR_MSG: host reports an error to the function.
pub const MBIM_HOST_ERROR: u32 = 0x0000_0004;
/// MBIM_OPEN_DONE: function ACKs the MBIM_OPEN from the host.
pub const MBIM_OPEN_DONE: u32 = 0x8000_0001;
/// MBIM_CLOSE_DONE: function ACKs the MBIM_CLOSE from the host.
pub const MBIM_CLOSE_DONE: u32 = 0x8000_0002;
/// MBIM_COMMAND_DONE: function returns the result of a CID command.
pub const MBIM_COMMAND_DONE: u32 = 0x8000_0003;
/// MBIM_FUNCTION_ERROR_MSG: function reports an error to the host.
pub const MBIM_FUNCTION_ERROR: u32 = 0x8000_0004;
/// MBIM_INDICATE_STATUS_MSG: function sends an unsolicited status notification.
pub const MBIM_INDICATE_STATUS: u32 = 0x8000_0007;

/// Minimum on-wire size of an MBIM header (MessageType + MessageLength + TransactionId).
pub const MBIM_HEADER_SIZE: usize = 12;

// ─── MbimMessageType enum ────────────────────────────────────────────────────

/// Typed wrapper around the raw MBIM message-type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbimMessageType {
    Open,
    Close,
    CommandMsg,
    HostError,
    OpenDone,
    CloseDone,
    CommandDone,
    FunctionError,
    IndicateStatus,
    /// Unrecognised type code; carries the raw value.
    Unknown(u32),
}

impl MbimMessageType {
    /// Decode from the raw little-endian u32 on-wire value.
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            MBIM_OPEN => Self::Open,
            MBIM_CLOSE => Self::Close,
            MBIM_COMMAND_MSG => Self::CommandMsg,
            MBIM_HOST_ERROR => Self::HostError,
            MBIM_OPEN_DONE => Self::OpenDone,
            MBIM_CLOSE_DONE => Self::CloseDone,
            MBIM_COMMAND_DONE => Self::CommandDone,
            MBIM_FUNCTION_ERROR => Self::FunctionError,
            MBIM_INDICATE_STATUS => Self::IndicateStatus,
            other => Self::Unknown(other),
        }
    }

    /// Encode to the raw little-endian u32 wire value.
    pub fn to_raw(self) -> u32 {
        match self {
            Self::Open => MBIM_OPEN,
            Self::Close => MBIM_CLOSE,
            Self::CommandMsg => MBIM_COMMAND_MSG,
            Self::HostError => MBIM_HOST_ERROR,
            Self::OpenDone => MBIM_OPEN_DONE,
            Self::CloseDone => MBIM_CLOSE_DONE,
            Self::CommandDone => MBIM_COMMAND_DONE,
            Self::FunctionError => MBIM_FUNCTION_ERROR,
            Self::IndicateStatus => MBIM_INDICATE_STATUS,
            Self::Unknown(raw) => raw,
        }
    }
}

// ─── MbimError ───────────────────────────────────────────────────────────────

/// Errors returned by MBIM codec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MbimError {
    /// Buffer too short to contain a complete header.
    TooShort,
    /// MessageLength field is smaller than the minimum header size.
    InvalidLength,
}

// ─── MbimHeader ──────────────────────────────────────────────────────────────

/// Decoded 12-byte MBIM message header.
///
/// Wire layout (MBIM 1.0 §10.3.1, all fields little-endian):
///
/// ```text
/// byte  0..3  MessageType
/// byte  4..7  MessageLength   (total, including this header)
/// byte  8..11 TransactionId
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbimHeader {
    /// Message type tag.
    pub message_type: MbimMessageType,
    /// Total on-wire length of the message in bytes (header + payload).
    pub message_length: u32,
    /// Host-allocated transaction identifier; echoed by function in responses.
    pub transaction_id: u32,
}

impl MbimHeader {
    /// Encode the header into a 12-byte little-endian array.
    #[inline]
    pub fn encode(&self) -> [u8; MBIM_HEADER_SIZE] {
        let mut out = [0u8; MBIM_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.message_type.to_raw().to_le_bytes());
        out[4..8].copy_from_slice(&self.message_length.to_le_bytes());
        out[8..12].copy_from_slice(&self.transaction_id.to_le_bytes());
        out
    }

    /// Decode a header from a byte slice.
    ///
    /// Returns `Err(MbimError::TooShort)` if `buf.len() < 12`.
    /// Returns `Err(MbimError::InvalidLength)` if the MessageLength field
    /// is smaller than the 12-byte minimum header size.
    pub fn decode(buf: &[u8]) -> Result<Self, MbimError> {
        if buf.len() < MBIM_HEADER_SIZE {
            return Err(MbimError::TooShort);
        }
        let raw_type = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let msg_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let tx_id = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

        if (msg_len as usize) < MBIM_HEADER_SIZE {
            return Err(MbimError::InvalidLength);
        }

        Ok(Self {
            message_type: MbimMessageType::from_raw(raw_type),
            message_length: msg_len,
            transaction_id: tx_id,
        })
    }
}

// ─── MBIM_OPEN builder ───────────────────────────────────────────────────────

/// MBIM_OPEN_MSG payload: a single u32 `MaxControlTransfer`.
///
/// MBIM 1.0 §10.3.2.
/// The total message length is 16 bytes (12-byte header + 4-byte payload).
pub const MBIM_OPEN_MSG_LEN: u32 = 16;

/// Build a complete MBIM_OPEN_MSG packet.
///
/// `transaction_id` is the host-allocated sequence number (start at 1).
/// `max_control_transfer` is the maximum USB control-transfer size the host
/// supports; the spec recommends 4096.
pub fn build_open(transaction_id: u32, max_control_transfer: u32) -> Vec<u8> {
    let hdr = MbimHeader {
        message_type: MbimMessageType::Open,
        message_length: MBIM_OPEN_MSG_LEN,
        transaction_id,
    };
    let mut buf = Vec::with_capacity(MBIM_OPEN_MSG_LEN as usize);
    buf.extend_from_slice(&hdr.encode());
    buf.extend_from_slice(&max_control_transfer.to_le_bytes());
    buf
}
