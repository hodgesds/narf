// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/mbim.rs — MBIM 1.0 message codec
//
// Mobile Broadband Interface Model (MBIM) is a USB CDC subclass (0x0E) defined
// by the USB-IF "Communications Class Subclass Specification for Mobile
// Broadband Interface Model", Revision 1.0 (Errata 1), May 1, 2013 ("MBIM
// 1.0" below).  The host and function exchange fixed-size message headers
// followed by variable-length payloads.
//
// This module implements the full control-message codec the session layer
// (crate::session) drives: the 12-byte message header, the fragment header,
// MBIM_COMMAND_MSG / MBIM_COMMAND_DONE framing, the Basic Connect service
// UUID and CID set, and the information-buffer structures for the CIDs the
// bearer bring-up needs (DEVICE_CAPS, SUBSCRIBER_READY_STATUS, RADIO_STATE,
// PACKET_SERVICE, CONNECT, IP_CONFIGURATION_INFO).  Fragment reassembly and
// transaction matching live in crate::session; the USB transport lives in
// crate::usb_mbim; the NTB datapath lives in crate::bearer.
//
// Wire format (MBIM 1.0 §10.3.1):
//
//   Offset  Size  Field
//   ------  ----  -----
//     0       4   MessageType    (little-endian u32)
//     4       4   MessageLength  (total packet bytes, including header)
//     8       4   TransactionId  (little-endian u32; host-allocated)
//
// Fragmented messages (COMMAND_MSG / COMMAND_DONE / INDICATE_STATUS) insert
// a FragmentHeader (TotalFragments, CurrentFragment) after TransactionId.
//
// Authoritative sources for every constant and layout in this module:
//   - USB-IF MBIM 1.0 (Errata 1) — message types (§10.3), Basic Connect
//     service UUID + CID table (§10.1 / Table 10-6 in some printings),
//     information-buffer structures (§10.5.x per-CID sections).
//   - libmbim (freedesktop) `mbim-uuid.h`, `mbim-cid.h`,
//     `mbim-message-basic-connect.h` — the same tables as implemented by
//     the reference userspace stack.
//   - Linux `drivers/net/usb/cdc_mbim.c` + `include/uapi/linux/usb/cdc.h`
//     for the datapath (NTB/NDP) conventions, in crate::bearer.

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
    /// An offset/size pair (or a fixed structure) reaches outside the
    /// information buffer it indexes.
    OutOfBounds,
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

/// Parse the Status field of an MBIM_OPEN_DONE / MBIM_CLOSE_DONE message
/// (header + one u32). Returns the raw MBIM_STATUS code.
pub fn parse_done_status(buf: &[u8]) -> Result<u32, MbimError> {
    if buf.len() < MBIM_HEADER_SIZE + 4 {
        return Err(MbimError::TooShort);
    }
    Ok(rd_u32(buf, MBIM_HEADER_SIZE))
}

// ─── Service UUIDs ───────────────────────────────────────────────────────────
//
// MBIM identifies services by 128-bit UUIDs carried in GUID wire order:
// the first three fields are little-endian, the last eight bytes are raw
// (the standard GUID encoding, MBIM 1.0 §10.1).

/// A 16-byte MBIM service UUID in wire order.
pub type MbimUuid = [u8; 16];

/// UUID_BASIC_CONNECT — a289cc33-bcbb-4518-bbdb-34ec7edfb873.
///
/// Source: MBIM 1.0 §10.1; libmbim `MBIM_UUID_BASIC_CONNECT`.
pub const MBIM_UUID_BASIC_CONNECT: MbimUuid = [
    0x33, 0xCC, 0x89, 0xA2, 0xBC, 0xBB, 0x45, 0x18, 0xBB, 0xDB, 0x34, 0xEC, 0x7E, 0xDF, 0xB8, 0x73,
];

// ─── MBIM_STATUS codes ───────────────────────────────────────────────────────
//
// MBIM 1.0 Table 10-4 (MBIM_STATUS); libmbim `MbimStatusError`.

/// The operation succeeded.
pub const MBIM_STATUS_SUCCESS: u32 = 0;
/// The function is busy; the host may retry.
pub const MBIM_STATUS_BUSY: u32 = 1;
/// Generic failure.
pub const MBIM_STATUS_FAILURE: u32 = 2;
/// No SIM is inserted.
pub const MBIM_STATUS_SIM_NOT_INSERTED: u32 = 3;
/// The inserted SIM is bad.
pub const MBIM_STATUS_BAD_SIM: u32 = 4;
/// A PIN is required before the operation can proceed.
pub const MBIM_STATUS_PIN_REQUIRED: u32 = 5;
/// The device was not found (e.g. removed mid-operation).
pub const MBIM_STATUS_DEVICE_NOT_FOUND: u32 = 7;
/// No packet service is available.
pub const MBIM_STATUS_NO_PACKET_SERVICE: u32 = 8;
/// The referenced context is not activated.
pub const MBIM_STATUS_CONTEXT_NOT_ACTIVATED: u32 = 20;

// ─── Basic Connect CIDs ──────────────────────────────────────────────────────
//
// MBIM 1.0 Basic Connect command set; libmbim `MbimCidBasicConnect`.

/// MBIM_CID_DEVICE_CAPS (query).
pub const CID_DEVICE_CAPS: u32 = 1;
/// MBIM_CID_SUBSCRIBER_READY_STATUS (query / event).
pub const CID_SUBSCRIBER_READY_STATUS: u32 = 2;
/// MBIM_CID_RADIO_STATE (query / set / event).
pub const CID_RADIO_STATE: u32 = 3;
/// MBIM_CID_PACKET_SERVICE (query / set / event).
pub const CID_PACKET_SERVICE: u32 = 10;
/// MBIM_CID_CONNECT (query / set / event).
pub const CID_CONNECT: u32 = 12;
/// MBIM_CID_IP_CONFIGURATION_INFO (query).
pub const CID_IP_CONFIGURATION_INFO: u32 = 16;
/// MBIM_CID_DEVICE_SERVICES (query).
pub const CID_DEVICE_SERVICES: u32 = 17;

/// MBIM_COMMAND_TYPE_QUERY.
pub const COMMAND_TYPE_QUERY: u32 = 0;
/// MBIM_COMMAND_TYPE_SET.
pub const COMMAND_TYPE_SET: u32 = 1;

// ─── Fragment header ─────────────────────────────────────────────────────────

/// The 8-byte fragment header that follows the message header in
/// COMMAND_MSG / COMMAND_DONE / INDICATE_STATUS_MSG (MBIM 1.0 §10.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Total number of fragments the message is split into (>= 1).
    pub total_fragments: u32,
    /// Zero-based index of this fragment.
    pub current_fragment: u32,
}

impl FragmentHeader {
    /// Wire size of the fragment header.
    pub const SIZE: usize = 8;

    /// Encode into an 8-byte little-endian array.
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[0..4].copy_from_slice(&self.total_fragments.to_le_bytes());
        out[4..8].copy_from_slice(&self.current_fragment.to_le_bytes());
        out
    }

    /// Decode from `buf` (must hold at least 8 bytes).
    pub fn decode(buf: &[u8]) -> Result<Self, MbimError> {
        if buf.len() < Self::SIZE {
            return Err(MbimError::TooShort);
        }
        Ok(Self {
            total_fragments: rd_u32(buf, 0),
            current_fragment: rd_u32(buf, 4),
        })
    }
}

// ─── Small read helpers ──────────────────────────────────────────────────────

/// Read a little-endian u32 at `off`; caller guarantees `off + 4 <= buf.len()`.
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Read a little-endian u64 at `off`; caller guarantees `off + 8 <= buf.len()`.
fn rd_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Write a little-endian u32 into `buf` at `off`.
fn wr_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Resolve an MBIM offset/length pair (OL_PAIR) against the information
/// buffer it indexes. Offsets are relative to the start of the containing
/// structure (the information buffer itself, for the structures here).
/// A (0, 0) pair resolves to an empty slice.
fn ol_slice(info: &[u8], pair_at: usize) -> Result<&[u8], MbimError> {
    if pair_at + 8 > info.len() {
        return Err(MbimError::OutOfBounds);
    }
    let offset = rd_u32(info, pair_at) as usize;
    let size = rd_u32(info, pair_at + 4) as usize;
    if size == 0 {
        return Ok(&[]);
    }
    if offset > info.len() || size > info.len() - offset {
        return Err(MbimError::OutOfBounds);
    }
    Ok(&info[offset..offset + size])
}

/// Decode an MBIM string: UTF-16LE, length from the OL pair, NOT
/// NUL-terminated (MBIM 1.0 §10.1 "DataBuffer strings").
fn ol_string(info: &[u8], pair_at: usize) -> Result<alloc::string::String, MbimError> {
    let raw = ol_slice(info, pair_at)?;
    if raw.len() % 2 != 0 {
        return Err(MbimError::OutOfBounds);
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(alloc::string::String::from_utf16_lossy(&units))
}

/// Append a UTF-16LE string to `data` (the variable-length tail of an
/// information buffer under construction) and return its OL pair,
/// expressed against the final buffer whose fixed part occupies
/// `fixed_len` bytes. The caller patches the pair into the fixed part
/// once `data` is complete; offsets recorded here already account for
/// `fixed_len`.
fn push_ol_string(data: &mut Vec<u8>, fixed_len: usize, s: &str) -> (u32, u32) {
    let offset = (fixed_len + data.len()) as u32;
    let mut size = 0u32;
    for unit in s.encode_utf16() {
        data.extend_from_slice(&unit.to_le_bytes());
        size += 2;
    }
    (offset, size)
}

// ─── COMMAND_MSG / COMMAND_DONE framing ──────────────────────────────────────

/// Fixed bytes before the information buffer in a COMMAND_MSG or in the
/// first fragment of a COMMAND_DONE: header (12) + fragment header (8) +
/// DeviceServiceId (16) + CID (4) + CommandType-or-Status (4) +
/// InformationBufferLength (4).
pub const COMMAND_FIXED_LEN: usize = 48;

/// Build a complete single-fragment MBIM_COMMAND_MSG.
///
/// The commands this crate issues are small (worst case a CONNECT set
/// with credentials, far below any MaxControlTransfer), so requests are
/// never fragmented; responses may be, and the session layer reassembles
/// them (see [`parse_command_head`]).
pub fn build_command(
    transaction_id: u32,
    service: &MbimUuid,
    cid: u32,
    command_type: u32,
    info: &[u8],
) -> Vec<u8> {
    let total = COMMAND_FIXED_LEN + info.len();
    let hdr = MbimHeader {
        message_type: MbimMessageType::CommandMsg,
        message_length: total as u32,
        transaction_id,
    };
    let frag = FragmentHeader {
        total_fragments: 1,
        current_fragment: 0,
    };
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&hdr.encode());
    buf.extend_from_slice(&frag.encode());
    buf.extend_from_slice(service);
    buf.extend_from_slice(&cid.to_le_bytes());
    buf.extend_from_slice(&command_type.to_le_bytes());
    buf.extend_from_slice(&(info.len() as u32).to_le_bytes());
    buf.extend_from_slice(info);
    buf
}

/// The parsed head of a COMMAND_DONE or INDICATE_STATUS message:
/// everything except the information buffer itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandHead {
    /// Service UUID the command belongs to.
    pub service: MbimUuid,
    /// Command identifier within the service.
    pub cid: u32,
    /// MBIM_STATUS for a COMMAND_DONE; `None` for INDICATE_STATUS
    /// (which carries no status field).
    pub status: Option<u32>,
    /// Byte offset of the information-buffer chunk inside the message:
    /// COMMAND_FIXED_LEN for fragment 0 of a COMMAND_DONE /
    /// INDICATE_STATUS, MBIM_HEADER_SIZE + 8 (header + fragment header)
    /// for continuation fragments.
    pub info_offset: usize,
}

/// Parse the fixed head of a COMMAND_DONE / INDICATE_STATUS message.
///
/// For fragment 0 this yields the service, CID and (for COMMAND_DONE)
/// status; the information-buffer chunk is `msg[head.info_offset ..
/// header.message_length]`. For continuation fragments (CurrentFragment
/// `> 0`) the message carries only header + fragment header + the next
/// information chunk: `service`/`cid` are zeroed, `status` is `None`,
/// and callers must already know them from fragment 0 (MBIM 1.0
/// §10.3.1 fragmentation rules; libmbim reassembles the same way).
pub fn parse_command_head(
    msg: &[u8],
) -> Result<(MbimHeader, FragmentHeader, CommandHead), MbimError> {
    let header = MbimHeader::decode(msg)?;
    if msg.len() < MBIM_HEADER_SIZE + FragmentHeader::SIZE {
        return Err(MbimError::TooShort);
    }
    let frag = FragmentHeader::decode(&msg[MBIM_HEADER_SIZE..])?;
    if frag.total_fragments == 0 || frag.current_fragment >= frag.total_fragments {
        return Err(MbimError::InvalidLength);
    }
    if frag.current_fragment > 0 {
        return Ok((
            header,
            frag,
            CommandHead {
                service: [0u8; 16],
                cid: 0,
                status: None,
                info_offset: MBIM_HEADER_SIZE + FragmentHeader::SIZE,
            },
        ));
    }
    // INDICATE_STATUS carries no Status field: its fixed head is 44
    // bytes (COMMAND_FIXED_LEN - 4). COMMAND_DONE's is the full 48.
    let min_len = match header.message_type {
        MbimMessageType::CommandDone => COMMAND_FIXED_LEN,
        MbimMessageType::IndicateStatus => COMMAND_FIXED_LEN - 4,
        _ => return Err(MbimError::InvalidLength),
    };
    if msg.len() < min_len {
        return Err(MbimError::TooShort);
    }
    let mut service = [0u8; 16];
    service.copy_from_slice(&msg[20..36]);
    let cid = rd_u32(msg, 36);
    let (status, info_offset) = match header.message_type {
        MbimMessageType::CommandDone => (Some(rd_u32(msg, 40)), COMMAND_FIXED_LEN),
        MbimMessageType::IndicateStatus => (None, COMMAND_FIXED_LEN - 4),
        _ => return Err(MbimError::InvalidLength),
    };
    Ok((
        header,
        frag,
        CommandHead {
            service,
            cid,
            status,
            info_offset,
        },
    ))
}

/// If `msg` is an unsolicited Basic Connect CID_CONNECT indication,
/// decode its MBIM_CONNECT_INFO. Returns `None` for any other message
/// (including malformed ones — event parsing never fails the caller).
pub fn parse_indicate_connect_event(msg: &[u8]) -> Option<ConnectInfo> {
    let (header, frag, head) = parse_command_head(msg).ok()?;
    if header.message_type != MbimMessageType::IndicateStatus
        || frag.current_fragment != 0
        || head.service != MBIM_UUID_BASIC_CONNECT
        || head.cid != CID_CONNECT
    {
        return None;
    }
    ConnectInfo::parse(&msg[head.info_offset..]).ok()
}

// ─── MBIM_DEVICE_CAPS_INFO (MBIM 1.0 §10.5.1) ────────────────────────────────

/// Decoded MBIM_DEVICE_CAPS_INFO — the response information buffer of
/// MBIM_CID_DEVICE_CAPS. Fixed part is 64 bytes: eight u32 fields
/// followed by four OL pairs (CustomDataClass, DeviceId, FirmwareInfo,
/// HardwareInfo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapsInfo {
    /// MBIM_DEVICE_TYPE (0 = unknown, 1 = embedded, 2 = removable, 3 = remote).
    pub device_type: u32,
    /// MBIM_CELLULAR_CLASS bitmask.
    pub cellular_class: u32,
    /// MBIM_VOICE_CLASS.
    pub voice_class: u32,
    /// MBIM_SIM_CLASS bitmask.
    pub sim_class: u32,
    /// MBIM_DATA_CLASS bitmask (GSM/UMTS/LTE technology bits).
    pub data_class: u32,
    /// MBIM_SMS_CAPS bitmask.
    pub sms_caps: u32,
    /// MBIM_CTRL_CAPS bitmask.
    pub control_caps: u32,
    /// Maximum number of IP/DSS sessions the function supports.
    pub max_sessions: u32,
    /// Custom data class string (may be empty).
    pub custom_data_class: alloc::string::String,
    /// Device identifier string (IMEI for GSM, ESN/MEID for CDMA).
    pub device_id: alloc::string::String,
    /// Firmware version string.
    pub firmware_info: alloc::string::String,
    /// Hardware model string.
    pub hardware_info: alloc::string::String,
}

impl DeviceCapsInfo {
    /// Size of the fixed part of MBIM_DEVICE_CAPS_INFO.
    pub const FIXED_LEN: usize = 64;

    /// Parse from a CID_DEVICE_CAPS response information buffer.
    pub fn parse(info: &[u8]) -> Result<Self, MbimError> {
        if info.len() < Self::FIXED_LEN {
            return Err(MbimError::TooShort);
        }
        Ok(Self {
            device_type: rd_u32(info, 0),
            cellular_class: rd_u32(info, 4),
            voice_class: rd_u32(info, 8),
            sim_class: rd_u32(info, 12),
            data_class: rd_u32(info, 16),
            sms_caps: rd_u32(info, 20),
            control_caps: rd_u32(info, 24),
            max_sessions: rd_u32(info, 28),
            custom_data_class: ol_string(info, 32)?,
            device_id: ol_string(info, 40)?,
            firmware_info: ol_string(info, 48)?,
            hardware_info: ol_string(info, 56)?,
        })
    }
}

// ─── MBIM_SUBSCRIBER_READY_INFO (MBIM 1.0 §10.5.2) ───────────────────────────

/// MBIM_SUBSCRIBER_READY_STATE_INITIALIZED — the SIM is ready.
pub const SUBSCRIBER_READY_INITIALIZED: u32 = 1;

/// Decoded subset of MBIM_SUBSCRIBER_READY_INFO (28-byte fixed header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberReadyInfo {
    /// MBIM_SUBSCRIBER_READY_STATE.
    pub ready_state: u32,
    /// MBIM_SUBSCRIBER_READY_INFO.ReadyInfo.
    pub ready_info: u32,
    /// Subscriber identifier string (may be empty).
    pub subscriber_id: alloc::string::String,
    /// SIM ICC identifier string (may be empty).
    pub sim_iccid: alloc::string::String,
}

impl SubscriberReadyInfo {
    /// Size of the fixed header before the variable telephone-number array.
    pub const FIXED_LEN: usize = 28;

    /// Parse from a CID_SUBSCRIBER_READY_STATUS response buffer.
    pub fn parse(info: &[u8]) -> Result<Self, MbimError> {
        if info.len() < Self::FIXED_LEN {
            return Err(MbimError::TooShort);
        }
        Ok(Self {
            ready_state: rd_u32(info, 0),
            subscriber_id: ol_string(info, 4)?,
            sim_iccid: ol_string(info, 12)?,
            ready_info: rd_u32(info, 20),
        })
    }
}

// ─── MBIM_RADIO_STATE (MBIM 1.0 §10.5.3) ─────────────────────────────────────

/// MBIM_RADIO_STATE_OFF.
pub const RADIO_STATE_OFF: u32 = 0;
/// MBIM_RADIO_STATE_ON.
pub const RADIO_STATE_ON: u32 = 1;

/// Decoded MBIM_RADIO_STATE_INFO (8 bytes: HardwareRadioState then
/// SoftwareRadioState).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadioStateInfo {
    /// Radio state enforced by the hardware switch.
    pub hardware_state: u32,
    /// Radio state requested by software.
    pub software_state: u32,
}

impl RadioStateInfo {
    /// Size of MBIM_RADIO_STATE_INFO.
    pub const LEN: usize = 8;

    /// Parse from a CID_RADIO_STATE response buffer.
    pub fn parse(info: &[u8]) -> Result<Self, MbimError> {
        if info.len() < Self::LEN {
            return Err(MbimError::TooShort);
        }
        Ok(Self {
            hardware_state: rd_u32(info, 0),
            software_state: rd_u32(info, 4),
        })
    }
}

/// Build the MBIM_SET_RADIO_STATE payload (one u32: SoftwareRadioState).
pub fn build_radio_state_set(on: bool) -> [u8; 4] {
    (if on { RADIO_STATE_ON } else { RADIO_STATE_OFF }).to_le_bytes()
}

// ─── MBIM_PACKET_SERVICE (MBIM 1.0 §10.5.10) ─────────────────────────────────

/// MBIM_PACKET_SERVICE_ACTION_ATTACH.
pub const PACKET_SERVICE_ATTACH: u32 = 0;
/// MBIM_PACKET_SERVICE_ACTION_DETACH.
pub const PACKET_SERVICE_DETACH: u32 = 1;

/// MBIM_PACKET_SERVICE_STATE_DETACHED.
pub const PACKET_SERVICE_DETACHED: u32 = 0;
/// MBIM_PACKET_SERVICE_STATE_ATTACHED.
pub const PACKET_SERVICE_ATTACHED: u32 = 2;

/// Decoded MBIM_PACKET_SERVICE_INFO (28 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketServiceInfo {
    /// Network error code (0 = none).
    pub nw_error: u32,
    /// MBIM_PACKET_SERVICE_STATE.
    pub packet_service_state: u32,
    /// MBIM_DATA_CLASS bitmask of the best available data class.
    pub highest_available_data_class: u32,
    /// Uplink speed in bits per second.
    pub uplink_speed: u64,
    /// Downlink speed in bits per second.
    pub downlink_speed: u64,
}

impl PacketServiceInfo {
    /// Size of MBIM_PACKET_SERVICE_INFO.
    pub const LEN: usize = 28;

    /// Parse from a CID_PACKET_SERVICE response buffer.
    pub fn parse(info: &[u8]) -> Result<Self, MbimError> {
        if info.len() < Self::LEN {
            return Err(MbimError::TooShort);
        }
        Ok(Self {
            nw_error: rd_u32(info, 0),
            packet_service_state: rd_u32(info, 4),
            highest_available_data_class: rd_u32(info, 8),
            uplink_speed: rd_u64(info, 12),
            downlink_speed: rd_u64(info, 20),
        })
    }
}

/// Build the MBIM_PACKET_SERVICE_SET payload (one u32 action).
pub fn build_packet_service_set(attach: bool) -> [u8; 4] {
    (if attach {
        PACKET_SERVICE_ATTACH
    } else {
        PACKET_SERVICE_DETACH
    })
    .to_le_bytes()
}

// ─── MBIM_CONNECT (MBIM 1.0 §10.5.11) ────────────────────────────────────────

/// MBIM_ACTIVATION_COMMAND_DEACTIVATE.
pub const ACTIVATION_DEACTIVATE: u32 = 0;
/// MBIM_ACTIVATION_COMMAND_ACTIVATE.
pub const ACTIVATION_ACTIVATE: u32 = 1;

/// MBIM_ACTIVATION_STATE_DEACTIVATED.
pub const ACTIVATION_STATE_DEACTIVATED: u32 = 0;
/// MBIM_ACTIVATION_STATE_ACTIVATING.
pub const ACTIVATION_STATE_ACTIVATING: u32 = 1;
/// MBIM_ACTIVATION_STATE_ACTIVATED.
pub const ACTIVATION_STATE_ACTIVATED: u32 = 2;
/// MBIM_ACTIVATION_STATE_DEACTIVATING.
pub const ACTIVATION_STATE_DEACTIVATING: u32 = 3;

/// MBIM_CONTEXT_IP_TYPE_DEFAULT.
pub const IP_TYPE_DEFAULT: u32 = 0;
/// MBIM_CONTEXT_IP_TYPE_IPV4.
pub const IP_TYPE_IPV4: u32 = 1;
/// MBIM_CONTEXT_IP_TYPE_IPV6.
pub const IP_TYPE_IPV6: u32 = 2;
/// MBIM_CONTEXT_IP_TYPE_IPV4V6.
pub const IP_TYPE_IPV4V6: u32 = 3;

/// MBIM_CONTEXT_AUTH_PROTOCOL_NONE.
pub const AUTH_PROTOCOL_NONE: u32 = 0;
/// MBIM_CONTEXT_AUTH_PROTOCOL_PAP.
pub const AUTH_PROTOCOL_PAP: u32 = 1;
/// MBIM_CONTEXT_AUTH_PROTOCOL_CHAP.
pub const AUTH_PROTOCOL_CHAP: u32 = 2;
/// MBIM_CONTEXT_AUTH_PROTOCOL_MSCHAPV2.
pub const AUTH_PROTOCOL_MSCHAPV2: u32 = 3;

/// Parameters for a CID_CONNECT set (activation) request —
/// MBIM_SET_CONNECT. Strings are encoded into the buffer tail as
/// UTF-16LE OL pairs by [`build_connect_set`]; absent strings encode
/// as (0, 0) pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectSetParams {
    /// Session to activate (0-based; must be < DeviceCapsInfo::max_sessions).
    pub session_id: u32,
    /// Access string (APN), e.g. "internet".
    pub access_string: Option<alloc::string::String>,
    /// User name for the context (usually absent).
    pub user_name: Option<alloc::string::String>,
    /// Password for the context (usually absent).
    pub password: Option<alloc::string::String>,
    /// MBIM_COMPRESSION (0 = none).
    pub compression_type: u32,
    /// MBIM_CONTEXT_AUTH_PROTOCOL.
    pub auth_protocol_type: u32,
    /// MBIM_CONTEXT_IP_TYPE requested for the session.
    pub ip_type: u32,
    /// Context type GUID in wire order. All-zero
    /// (MBIM_CONTEXT_TYPE_NONE-shaped) means "the function's default
    /// provisioned context"; callers with a provisioned-context policy
    /// pass the context GUID explicitly — this codec deliberately does
    /// not hardcode one.
    pub context_type: MbimUuid,
}

impl ConnectSetParams {
    /// A plain internet activation: no credentials, no compression,
    /// no auth, IPv4, default context.
    pub fn activate(session_id: u32, access_string: Option<alloc::string::String>) -> Self {
        Self {
            session_id,
            access_string,
            user_name: None,
            password: None,
            compression_type: 0,
            auth_protocol_type: AUTH_PROTOCOL_NONE,
            ip_type: IP_TYPE_IPV4,
            context_type: [0u8; 16],
        }
    }
}

/// Size of the fixed part of MBIM_SET_CONNECT.
pub const CONNECT_SET_FIXED_LEN: usize = 60;

/// Build the MBIM_SET_CONNECT information buffer for `params`
/// (activation when used with COMMAND_TYPE_SET; the same structure
/// with only SessionId + ActivationCommand meaningful is used for
/// deactivation by [`build_disconnect_set`]).
pub fn build_connect_set(params: &ConnectSetParams) -> Vec<u8> {
    let mut fixed = [0u8; CONNECT_SET_FIXED_LEN];
    let mut tail: Vec<u8> = Vec::new();
    wr_u32(&mut fixed, 0, params.session_id);
    wr_u32(&mut fixed, 4, ACTIVATION_ACTIVATE);
    let (off, size) = match &params.access_string {
        Some(s) => push_ol_string(&mut tail, CONNECT_SET_FIXED_LEN, s),
        None => (0, 0),
    };
    wr_u32(&mut fixed, 8, off);
    wr_u32(&mut fixed, 12, size);
    let (off, size) = match &params.user_name {
        Some(s) => push_ol_string(&mut tail, CONNECT_SET_FIXED_LEN, s),
        None => (0, 0),
    };
    wr_u32(&mut fixed, 16, off);
    wr_u32(&mut fixed, 20, size);
    let (off, size) = match &params.password {
        Some(s) => push_ol_string(&mut tail, CONNECT_SET_FIXED_LEN, s),
        None => (0, 0),
    };
    wr_u32(&mut fixed, 24, off);
    wr_u32(&mut fixed, 28, size);
    wr_u32(&mut fixed, 32, params.compression_type);
    wr_u32(&mut fixed, 36, params.auth_protocol_type);
    wr_u32(&mut fixed, 40, params.ip_type);
    fixed[44..60].copy_from_slice(&params.context_type);
    let mut buf = Vec::with_capacity(CONNECT_SET_FIXED_LEN + tail.len());
    buf.extend_from_slice(&fixed);
    buf.extend_from_slice(&tail);
    buf
}

/// Build the MBIM_SET_CONNECT buffer for deactivation: SessionId +
/// ActivationCommand = DEACTIVATE, everything else zero (functions
/// ignore the remaining fields on deactivate).
pub fn build_disconnect_set(session_id: u32) -> Vec<u8> {
    let mut fixed = [0u8; CONNECT_SET_FIXED_LEN];
    wr_u32(&mut fixed, 0, session_id);
    wr_u32(&mut fixed, 4, ACTIVATION_DEACTIVATE);
    fixed.to_vec()
}

/// Decoded MBIM_CONNECT_INFO (36 bytes) — the response/event buffer of
/// MBIM_CID_CONNECT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectInfo {
    /// Session this state describes.
    pub session_id: u32,
    /// MBIM_ACTIVATION_STATE.
    pub activation_state: u32,
    /// MBIM_VOICE_CALL_STATE.
    pub voice_call_state: u32,
    /// MBIM_CONTEXT_IP_TYPE in effect for the session.
    pub ip_type: u32,
    /// Context type GUID in wire order.
    pub context_type: MbimUuid,
    /// Network error code (0 = none).
    pub nw_error: u32,
}

impl ConnectInfo {
    /// Size of MBIM_CONNECT_INFO.
    pub const LEN: usize = 36;

    /// Parse from a CID_CONNECT response or event buffer.
    pub fn parse(info: &[u8]) -> Result<Self, MbimError> {
        if info.len() < Self::LEN {
            return Err(MbimError::TooShort);
        }
        let mut context_type = [0u8; 16];
        context_type.copy_from_slice(&info[16..32]);
        Ok(Self {
            session_id: rd_u32(info, 0),
            activation_state: rd_u32(info, 4),
            voice_call_state: rd_u32(info, 8),
            ip_type: rd_u32(info, 12),
            context_type,
            nw_error: rd_u32(info, 32),
        })
    }
}

/// Build the CID_CONNECT query payload (MBIM_CONNECT_INFO-shaped with
/// only SessionId meaningful — the query form carries the session id
/// in a MBIM_CONNECT_INFO whose remaining fields are zero).
pub fn build_connect_query(session_id: u32) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; ConnectInfo::LEN];
    wr_u32(&mut buf, 0, session_id);
    buf
}

// ─── MBIM_IP_CONFIGURATION_INFO (MBIM 1.0 §10.5.12) ───────────────────────────

/// IPv4ConfigurationAvailable bit: an address is present.
pub const IP_AVAIL_ADDRESS: u32 = 0x01;
/// IPv4ConfigurationAvailable bit: a gateway is present.
pub const IP_AVAIL_GATEWAY: u32 = 0x02;
/// IPv4ConfigurationAvailable bit: DNS servers are present.
pub const IP_AVAIL_DNS: u32 = 0x04;
/// IPv4ConfigurationAvailable bit: an MTU is present.
pub const IP_AVAIL_MTU: u32 = 0x08;

/// One IPv4 address assignment from MBIM_IP_CONFIGURATION_INFO:
/// an MBIM_IPV4_ADDRESS_ELEMENT plus the gateway/DNS/MTU companions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Configuration {
    /// Assigned IPv4 address.
    pub address: [u8; 4],
    /// On-link prefix length for the address.
    pub prefix_length: u32,
    /// Default gateway, when the GATEWAY availability bit was set.
    pub gateway: Option<[u8; 4]>,
    /// DNS server addresses (may be empty).
    pub dns_servers: Vec<[u8; 4]>,
    /// Interface MTU, when the MTU availability bit was set.
    pub mtu: Option<u32>,
}

/// Decoded MBIM_IP_CONFIGURATION_INFO (fixed part 68 bytes: seventeen
/// u32 fields, then the variable arrays the offsets point at).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpConfigurationInfo {
    /// Session the configuration belongs to.
    pub session_id: u32,
    /// Raw IPv4ConfigurationAvailable bitmask.
    pub ipv4_available: u32,
    /// Raw IPv6ConfigurationAvailable bitmask.
    pub ipv6_available: u32,
    /// IPv4 configuration, when an address is available.
    pub ipv4: Option<Ipv4Configuration>,
    /// IPv6 MTU, when reported (this crate's netdev handoff is
    /// IPv4-first; IPv6 addresses are counted by the availability
    /// bitmask but not decoded into the bearer in this lane).
    pub ipv6_mtu: Option<u32>,
}

impl IpConfigurationInfo {
    /// Size of the fixed part of MBIM_IP_CONFIGURATION_INFO.
    pub const FIXED_LEN: usize = 68;

    /// Parse from a CID_IP_CONFIGURATION_INFO response buffer. The
    /// query payload for this CID is the session id as a single u32
    /// (see [`build_ip_configuration_query`]).
    pub fn parse(info: &[u8]) -> Result<Self, MbimError> {
        if info.len() < Self::FIXED_LEN {
            return Err(MbimError::TooShort);
        }
        let ipv4_available = rd_u32(info, 4);
        let ipv6_available = rd_u32(info, 8);
        let ipv4 = if ipv4_available & IP_AVAIL_ADDRESS != 0 {
            let count = rd_u32(info, 12) as usize;
            let offset = rd_u32(info, 16) as usize;
            if count == 0 {
                None
            } else {
                // Only the first address element drives the netdev;
                // MBIM sessions in practice carry exactly one.
                if offset + 8 > info.len() {
                    return Err(MbimError::OutOfBounds);
                }
                let prefix_length = rd_u32(info, offset);
                let mut address = [0u8; 4];
                address.copy_from_slice(&info[offset + 4..offset + 8]);
                let gateway = if ipv4_available & IP_AVAIL_GATEWAY != 0 {
                    let gw_off = rd_u32(info, 28) as usize;
                    if gw_off + 4 > info.len() {
                        return Err(MbimError::OutOfBounds);
                    }
                    let mut gw = [0u8; 4];
                    gw.copy_from_slice(&info[gw_off..gw_off + 4]);
                    Some(gw)
                } else {
                    None
                };
                let mut dns_servers = Vec::new();
                if ipv4_available & IP_AVAIL_DNS != 0 {
                    let dns_count = rd_u32(info, 36) as usize;
                    let dns_off = rd_u32(info, 40) as usize;
                    if dns_off + dns_count.saturating_mul(4) > info.len() {
                        return Err(MbimError::OutOfBounds);
                    }
                    for i in 0..dns_count {
                        let mut srv = [0u8; 4];
                        srv.copy_from_slice(&info[dns_off + i * 4..dns_off + i * 4 + 4]);
                        dns_servers.push(srv);
                    }
                }
                let mtu = if ipv4_available & IP_AVAIL_MTU != 0 {
                    let m = rd_u32(info, 52);
                    if m > 0 {
                        Some(m)
                    } else {
                        None
                    }
                } else {
                    None
                };
                Some(Ipv4Configuration {
                    address,
                    prefix_length,
                    gateway,
                    dns_servers,
                    mtu,
                })
            }
        } else {
            None
        };
        let ipv6_mtu = if ipv6_available & IP_AVAIL_MTU != 0 {
            let m = rd_u32(info, 56);
            if m > 0 {
                Some(m)
            } else {
                None
            }
        } else {
            None
        };
        Ok(Self {
            session_id: rd_u32(info, 0),
            ipv4_available,
            ipv6_available,
            ipv4,
            ipv6_mtu,
        })
    }
}

/// Build the CID_IP_CONFIGURATION_INFO query payload: the session id
/// as a single u32 (MBIM 1.0 §10.5.12 — the query form of this CID
/// takes the SessionId directly, unlike CONNECT's query).
pub fn build_ip_configuration_query(session_id: u32) -> [u8; 4] {
    session_id.to_le_bytes()
}
