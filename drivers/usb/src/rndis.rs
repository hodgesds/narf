//! USB Remote NDIS (RNDIS) class driver — clean-room.
//!
//! References (public-only):
//! - **Remote NDIS Specification, Version 1.0** (Microsoft,
//!   January 2001) and **Version 1.1** (November 2001). Public,
//!   via Microsoft Learn ("Remote NDIS Concepts and
//!   Definitions", "Multipacket Messages", "Remote NDIS Message
//!   Formats").
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/remote-ndis-concepts-and-definitions>
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/multipacket-messages>
//! - **USB Class Definitions for Communications Devices,
//!   Revision 1.2** (USB-IF). Public. §6.2 (encapsulated
//!   commands: `SEND_ENCAPSULATED_COMMAND` /
//!   `GET_ENCAPSULATED_RESPONSE`), §6.3 (notifications).
//!   <https://www.usb.org/document-library/class-definitions-communication-devices-12>
//!
//! Every protocol constant and message layout below is taken
//! from those documents (cross-checked against the public
//! spec-restatement header `drivers/usb/gadget/rndis.h` and the
//! NDIS OID table in `ntddndis.h`); no GPL Linux source was
//! copied. Linux `drivers/net/usb/rndis_host.c` was consulted
//! for structure only — the interface signature it matches
//! (class `0x02` / subclass `0x02` / protocol `0xFF`) and the
//! bring-up exchange order (initialize → query MAC / max frame
//! → set packet filter).
//!
//! ## Why RNDIS, and how it differs from ECM/NCM
//!
//! RNDIS is the protocol Windows hosts speak to USB network
//! adapters (and what Android USB tethering and many LTE
//! dongles expose): the host and device exchange NDIS control
//! messages over the CDC encapsulated-command channel on EP0,
//! and Ethernet frames over bulk endpoints wrapped in a
//! 44-byte `REMOTE_NDIS_PACKET_MSG` header. Unlike ECM (one
//! raw frame per bulk transfer) and NCM (NTB batching with
//! NTH/NDP headers), RNDIS frames carry their own header per
//! frame, and several `PACKET_MSG`s may be concatenated in one
//! bulk transfer ("multipacket messages", aligned to the
//! device's `PacketAlignmentFactor`).
//!
//! ## Transport
//!
//! - Control channel: CDC `SEND_ENCAPSULATED_COMMAND`
//!   (`0x00`, bmRequestType `0x21`) carries one RNDIS message;
//!   `GET_ENCAPSULATED_RESPONSE` (`0x01`, bmRequestType `0xA1`)
//!   retrieves the response. Every message starts with
//!   `MessageType`, `MessageLength`, `RequestId` (all
//!   little-endian); responses are matched by `RequestId`.
//! - Data channel: bulk IN/OUT on the CDC-Data interface
//!   (`0x0A`), grouped with the Comm interface by the Union
//!   functional descriptor — the same config-walking idiom as
//!   `cdc_ecm` / `cdc_ncm`.
//! - Notification channel (optional): the Comm interface's
//!   interrupt-IN endpoint delivers CDC §6.3 notifications:
//!   `NETWORK_CONNECTION` (`0x00`, link up/down) and
//!   `RESPONSE_AVAILABLE` (`0x01`, an encapsulated response is
//!   waiting).
//!
//! ## Bring-up exchange (RNDIS spec §"Device State Definitions")
//!
//! ```text
//!   host ── INITIALIZE (v1.0, MaxTransferSize) ──► device
//!   host ◄── INITIALIZE_CMPLT (medium, flags, ───── device
//!          MaxPacketsPerTransfer, MaxTransferSize,
//!          PacketAlignmentFactor)
//!   host ── QUERY OID_802_3_CURRENT_ADDRESS ──────► device
//!   host ◄── QUERY_CMPLT (6-byte station address) ─ device
//!   host ── QUERY OID_GEN_MAXIMUM_FRAME_SIZE ─────► device
//!   host ◄── QUERY_CMPLT (u32) ─────────────────── device
//!   host ── QUERY OID_GEN_MEDIA_CONNECT_STATUS ────► device
//!   host ◄── QUERY_CMPLT (u32, 1 = connected) ──── device
//!   host ── SET OID_GEN_CURRENT_PACKET_FILTER ─────► device
//!          (DIRECTED | MULTICAST | BROADCAST)
//!   host ◄── SET_CMPLT (SUCCESS) ───────────────── device
//! ```
//!
//! State machine (spec): RNDIS-uninitialized → (INITIALIZE
//! ok) → RNDIS-initialized → (SET nonzero packet filter) →
//! RNDIS-data-initialized; a zero filter returns the device to
//! RNDIS-initialized; HALT or bus disconnect returns it to
//! RNDIS-uninitialized. The machine lives in [`RndisBringup`]:
//! a pure, hardware-free driver of the exchange — the async
//! bind loop feeds it through the xHCI control channel, and
//! the fixtures feed it through a scripted fake device, so the
//! exchange is validated end to end without silicon.
//!
//! ## Offsets — the one rule that bites
//!
//! Every variable-length buffer offset in an RNDIS message is
//! measured **from the start of the field that holds the
//! offset**, not from the start of the message. E.g. in a
//! `PACKET_MSG`, `DataOffset` is at byte 8 and the payload
//! sits at `8 + DataOffset` (the spec's canonical value is
//! `36`, putting the payload at byte `44`, right after the
//! header). A decoder that treats the offset as
//! message-relative reads 8 bytes into the header and hands
//! the stack garbage. The multipacket fixture pins this.
//!
//! ## Claimant check (narf_spec_fixture_discipline)
//!
//! An RNDIS function presents as CDC-Comm subclass ACM
//! (`0x02`) with protocol `0xFF`. NARF's CDC-ACM finder
//! (`cdc_acm::find_acm_interfaces`) matched class/subclass
//! only — protocol-blind — and its bind treats
//! `SET_LINE_CODING` / `SET_CONTROL_LINE_STATE` failures as
//! non-fatal, so an RNDIS device would have been claimed as a
//! `/dev/ttyACM` serial port before any RNDIS binder ran
//! (ACM sits earlier in the attach cascade). Two fixes in
//! this lane: the RNDIS bind attempt runs **before** the ACM
//! attempt in the cascade (its finder requires protocol
//! `0xFF`, so it can only claim RNDIS devices), and the ACM
//! finder now skips Comm interfaces whose protocol is `0xFF`
//! (`0xFF` is not a valid ACM protocol per CDC PSTN 1.2 §6.3;
//! ACM protocols are `0x00`–`0x06`). The wireless RNDIS
//! variant (class `0xE0` / subclass `1` / protocol `3`,
//! some ZTE WWAN modules) is NOT matched: no NARF WLAN
//! stack consumes it yet; filed as a remainder, not silently
//! claimed.
//!
//! ## Remainders (stated, not hidden)
//!
//! - `RESET` is implemented at the message layer only; no
//!   recovery path re-runs bring-up after a reset yet — the RX
//!   pump exits after a bounded run of transfer errors and
//!   detach/re-enumeration recovers the device (the NCM/ECM
//!   pattern).
//! - No periodic KEEPALIVE task is spawned; the message layer
//!   and a `send_keepalive` trampoline exist, and link state
//!   is tracked via `MEDIA_CONNECT_STATUS` + the notification
//!   pump. A supervisor-driven keepalive policy is future
//!   work.
//! - TX sends one frame per bulk transfer. Multipacket TX
//!   batching (concatenating `PACKET_MSG`s to the negotiated
//!   `PacketAlignmentFactor`) is a throughput optimisation,
//!   not a correctness requirement — the device accepts
//!   single-packet transfers. RX walks multipacket buffers.

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use super::cdc::{USB_CLASS_CDC_COMM, USB_CLASS_CDC_DATA};
use super::cdc_acm::{
    REQ_GET_ENCAPSULATED_RESPONSE, REQ_SEND_ENCAPSULATED_COMMAND, RT_HOST_TO_DEV_CLASS_IFACE,
};
use super::cdc_ncm::is_valid_station_address;
use super::xhci::{EndpointConfig, EndpointKind};

// ── CDC encapsulated-command channel (CDC 1.2 §6.2) ───────────────

/// bmRequestType for a class-specific IN request to an
/// interface (device → host, class, interface recipient).
pub const RT_DEV_TO_HOST_CLASS_IFACE: u8 = 0xA1;

// ── RNDIS versions (RNDIS spec §2, "Remote NDIS Versions") ───────

/// Major version the host offers.
pub const RNDIS_MAJOR_VERSION: u32 = 1;
/// Minor version the host offers (spec 1.0).
pub const RNDIS_MINOR_VERSION: u32 = 0;

// ── Message types (RNDIS spec §"Message Set") ─────────────────────

pub const MSG_PACKET: u32 = 0x0000_0001;
pub const MSG_INITIALIZE: u32 = 0x0000_0002;
pub const MSG_HALT: u32 = 0x0000_0003;
pub const MSG_QUERY: u32 = 0x0000_0004;
pub const MSG_SET: u32 = 0x0000_0005;
pub const MSG_RESET: u32 = 0x0000_0006;
pub const MSG_INDICATE_STATUS: u32 = 0x0000_0007;
pub const MSG_KEEPALIVE: u32 = 0x0000_0008;

// ── Message completions (RNDIS spec §"Message completion") ────────

pub const CMPLT_INITIALIZE: u32 = 0x8000_0002;
pub const CMPLT_QUERY: u32 = 0x8000_0004;
pub const CMPLT_SET: u32 = 0x8000_0005;
pub const CMPLT_RESET: u32 = 0x8000_0006;
pub const CMPLT_KEEPALIVE: u32 = 0x8000_0008;

// ── Status values (RNDIS spec §"Status Values") ───────────────────

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_FAILURE: u32 = 0xC000_0001;
pub const STATUS_INVALID_DATA: u32 = 0xC001_0015;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_MEDIA_CONNECT: u32 = 0x4001_000B;
pub const STATUS_MEDIA_DISCONNECT: u32 = 0x4001_000C;

// ── Device flags / medium (RNDIS spec) ────────────────────────────

/// Connectionless (802.3) device.
pub const DF_CONNECTIONLESS: u32 = 0x0000_0001;
/// Connection-oriented device (not supported by this driver).
pub const DF_CONNECTION_ORIENTED: u32 = 0x0000_0002;
/// `NDIS_MEDIUM` 802.3 — the only medium this driver binds.
pub const MEDIUM_802_3: u32 = 0x0000_0000;

// ── OIDs (NDIS OID table, `ntddndis.h`) ───────────────────────────

pub const OID_GEN_SUPPORTED_LIST: u32 = 0x0001_0101;
pub const OID_GEN_MAXIMUM_FRAME_SIZE: u32 = 0x0001_0106;
pub const OID_GEN_LINK_SPEED: u32 = 0x0001_0107;
pub const OID_GEN_CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
pub const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x0001_0114;
pub const OID_GEN_VENDOR_DRIVER_VERSION: u32 = 0x0001_0116;
pub const OID_802_3_PERMANENT_ADDRESS: u32 = 0x0101_0101;
pub const OID_802_3_CURRENT_ADDRESS: u32 = 0x0101_0102;
pub const OID_802_3_MULTICAST_LIST: u32 = 0x0101_0103;
pub const OID_802_3_MAXIMUM_LIST_SIZE: u32 = 0x0101_0104;

// ── Packet-filter bits (NDIS_PACKET_TYPE_*, `ntddndis.h`) ─────────

pub const FILTER_DIRECTED: u32 = 0x0000_0001;
pub const FILTER_MULTICAST: u32 = 0x0000_0002;
pub const FILTER_ALL_MULTICAST: u32 = 0x0000_0004;
pub const FILTER_BROADCAST: u32 = 0x0000_0008;
pub const FILTER_SOURCE_ROUTING: u32 = 0x0000_0010;
pub const FILTER_PROMISCUOUS: u32 = 0x0000_0020;
pub const FILTER_SMT: u32 = 0x0000_0040;
pub const FILTER_ALL_LOCAL: u32 = 0x0000_0080;

// ── Size constants ─────────────────────────────────────────────────

/// Spec constant: maximum Ethernet frame size (RNDIS spec).
pub const RNDIS_MAXIMUM_FRAME_SIZE: u32 = 1518;
/// Spec constant: maximum total transfer size (RNDIS spec).
pub const RNDIS_MAX_TOTAL_SIZE: u32 = 1558;
/// Largest bulk transfer the host offers in INITIALIZE, and
/// the RX buffer size. 16 KiB matches the NCM default.
pub const HOST_MAX_TRANSFER_SIZE: u32 = 16 * 1024;
/// Clamp on a device-reported MaxTransferSize for RX sizing:
/// never allocate more than 64 KiB per pump buffer.
pub const RX_BUFFER_MAX: u32 = 64 * 1024;
/// Minimum usable device MaxTransferSize (one max frame + header).
pub const RX_BUFFER_MIN: u32 = 2048;

// ── RNDIS USB interface signature ─────────────────────────────────

/// CDC-Comm subclass RNDIS devices present under: ACM (`0x02`).
pub const RNDIS_SUBCLASS_ACM: u8 = 0x02;
/// CDC-Comm protocol for RNDIS (vendor-specific, "MSFT RNDIS").
pub const RNDIS_PROTOCOL: u8 = 0xFF;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RndisError {
    /// Buffer too short for the structure being decoded.
    Truncated,
    /// A length field disagrees with the buffer (or the header).
    BadLength,
    /// Unexpected MessageType for this exchange step.
    BadMessageType,
    /// Response RequestId does not match the request.
    BadRequestId,
    /// Device completed the request with a non-success status.
    DeviceStatus(u32),
    /// Device is not RNDIS (no Comm/ACM/0xFF interface).
    NotRndis,
    /// SET_CONFIGURATION control transfer failed during bind.
    SetConfigFailed,
    /// No usable station address: both the current- and
    /// permanent-address OID queries failed or returned an
    /// invalid address. The bind fails; one is never invented.
    NoMacAddress,
    /// No CDC-Data interface with a bulk IN/OUT pair was found.
    NoBulkEndpoints,
    /// Device is not an 802.3 medium.
    BadMedium,
    /// Device is connection-oriented, not connectionless.
    BadDeviceFlags,
    /// A TX frame exceeds the negotiated maximum frame size.
    FrameTooLarge,
    /// Control or bulk transfer failed / timed out waiting for
    /// the matching encapsulated response.
    Transfer,
    /// No xHCI controller is available for a transfer.
    NoController,
    /// The device record is detached (or missing) — no transfer.
    NotBound,
}

// ── Little-endian field helpers ────────────────────────────────────

fn u32le(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn put_u32le(out: &mut [u8], off: usize, v: u32) {
    if let Some(b) = out.get_mut(off..off + 4) {
        b.copy_from_slice(&v.to_le_bytes());
    }
}

/// Read the `MessageType` + `MessageLength` prefix shared by
/// every RNDIS message. Returns `(message_type, length)`.
fn message_prefix(buf: &[u8]) -> Result<(u32, usize), RndisError> {
    if buf.len() < 8 {
        return Err(RndisError::Truncated);
    }
    let msg_type = u32le(buf, 0).ok_or(RndisError::Truncated)?;
    let len = u32le(buf, 4).ok_or(RndisError::Truncated)? as usize;
    if len < 8 {
        return Err(RndisError::BadLength);
    }
    Ok((msg_type, len))
}

/// Read the `RequestId` at byte 8 of a request/response message.
fn request_id(buf: &[u8]) -> Result<u32, RndisError> {
    if buf.len() < 12 {
        return Err(RndisError::Truncated);
    }
    u32le(buf, 8).ok_or(RndisError::Truncated)
}

// ── INITIALIZE (spec §"REMOTE_NDIS_INITIALIZE_MSG") ───────────────

/// Encode `REMOTE_NDIS_INITIALIZE_MSG` — 24 bytes:
///
/// ```text
///   u32 MessageType       (0x00000002)
///   u32 MessageLength     (24)
///   u32 RequestId
///   u32 MajorVersion      (1)
///   u32 MinorVersion      (0)
///   u32 MaxTransferSize   (host RX buffer offer)
/// ```
pub fn encode_initialize_msg(request_id: u32, max_transfer_size: u32) -> [u8; 24] {
    let mut out = [0u8; 24];
    put_u32le(&mut out, 0, MSG_INITIALIZE);
    put_u32le(&mut out, 4, 24);
    put_u32le(&mut out, 8, request_id);
    put_u32le(&mut out, 12, RNDIS_MAJOR_VERSION);
    put_u32le(&mut out, 16, RNDIS_MINOR_VERSION);
    put_u32le(&mut out, 20, max_transfer_size);
    out
}

/// Decoded `REMOTE_NDIS_INITIALIZE_CMPLT` — 52 bytes:
///
/// ```text
///   u32 MessageType, MessageLength, RequestId, Status,
///   u32 MajorVersion, MinorVersion, DeviceFlags, Medium,
///   u32 MaxPacketsPerTransfer, MaxTransferSize,
///   u32 PacketAlignmentFactor, AfListOffset, AfListSize
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InitializeComplete {
    pub request_id: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub device_flags: u32,
    pub medium: u32,
    pub max_packets_per_transfer: u32,
    pub max_transfer_size: u32,
    pub packet_alignment_factor: u32,
}

impl InitializeComplete {
    /// Minimum wire length per spec (52 bytes).
    pub const WIRE_LEN: usize = 52;

    /// Decode from the response buffer. `expected_request_id`
    /// must match; a non-success `Status` is reported as
    /// [`RndisError::DeviceStatus`] — the caller never mistakes
    /// a failed initialization for a negotiated one.
    pub fn decode(buf: &[u8], expected_request_id: u32) -> Result<Self, RndisError> {
        let (msg_type, len) = message_prefix(buf)?;
        if msg_type != CMPLT_INITIALIZE {
            return Err(RndisError::BadMessageType);
        }
        if len < Self::WIRE_LEN || buf.len() < Self::WIRE_LEN {
            return Err(RndisError::Truncated);
        }
        let request_id = request_id(buf)?;
        if request_id != expected_request_id {
            return Err(RndisError::BadRequestId);
        }
        let status = u32le(buf, 12).ok_or(RndisError::Truncated)?;
        if status != STATUS_SUCCESS {
            return Err(RndisError::DeviceStatus(status));
        }
        Ok(Self {
            request_id,
            major_version: u32le(buf, 16).ok_or(RndisError::Truncated)?,
            minor_version: u32le(buf, 20).ok_or(RndisError::Truncated)?,
            device_flags: u32le(buf, 24).ok_or(RndisError::Truncated)?,
            medium: u32le(buf, 28).ok_or(RndisError::Truncated)?,
            max_packets_per_transfer: u32le(buf, 32).ok_or(RndisError::Truncated)?,
            max_transfer_size: u32le(buf, 36).ok_or(RndisError::Truncated)?,
            packet_alignment_factor: u32le(buf, 40).ok_or(RndisError::Truncated)?,
        })
    }
}

// ── QUERY / SET (spec §"REMOTE_NDIS_QUERY_MSG" / "SET_MSG") ───────

/// Encode `REMOTE_NDIS_QUERY_MSG` — 28 bytes + `input`:
///
/// ```text
///   u32 MessageType, MessageLength, RequestId, Oid,
///   u32 InformationBufferLength, InformationBufferOffset,
///   u32 DeviceVcHandle (0), then `input` bytes.
/// ```
/// `InformationBufferOffset` is measured from the start of its
/// own field (byte 16): `28 - 16 = 12` when input follows the
/// header; `0` when there is no input buffer.
pub fn encode_query_msg(request_id: u32, oid: u32, input: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 28 + input.len()];
    let total_len = out.len() as u32;
    put_u32le(&mut out, 0, MSG_QUERY);
    put_u32le(&mut out, 4, total_len);
    put_u32le(&mut out, 8, request_id);
    put_u32le(&mut out, 12, oid);
    put_u32le(&mut out, 16, input.len() as u32);
    put_u32le(&mut out, 20, if input.is_empty() { 0 } else { 12 });
    put_u32le(&mut out, 24, 0);
    out[28..].copy_from_slice(input);
    out
}

/// Encode `REMOTE_NDIS_SET_MSG` — 28 bytes + `value`:
///
/// ```text
///   u32 MessageType, MessageLength, RequestId, Oid,
///   u32 InformationBufferLength, InformationBufferOffset,
///   u32 DeviceVcHandle (0), then `value` bytes.
/// ```
/// `InformationBufferOffset` is measured from the start of its
/// own field (byte 20): `28 - 20 = 8`.
pub fn encode_set_msg(request_id: u32, oid: u32, value: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 28 + value.len()];
    let total_len = out.len() as u32;
    put_u32le(&mut out, 0, MSG_SET);
    put_u32le(&mut out, 4, total_len);
    put_u32le(&mut out, 8, request_id);
    put_u32le(&mut out, 12, oid);
    put_u32le(&mut out, 16, value.len() as u32);
    put_u32le(&mut out, 20, if value.is_empty() { 0 } else { 8 });
    put_u32le(&mut out, 24, 0);
    out[28..].copy_from_slice(value);
    out
}

/// Decoded `REMOTE_NDIS_QUERY_CMPLT` — 24 bytes + info buffer:
///
/// ```text
///   u32 MessageType, MessageLength, RequestId, Status,
///   u32 InformationBufferLength, InformationBufferOffset
/// ```
/// The info buffer starts at `20 + InformationBufferOffset`
/// (offset measured from its own field at byte 20).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QueryComplete<'a> {
    pub request_id: u32,
    pub info: &'a [u8],
}

impl<'a> QueryComplete<'a> {
    /// Minimum wire length per spec (24 bytes).
    pub const WIRE_LEN: usize = 24;

    /// Decode from the response buffer. The returned `info`
    /// borrows `buf`; its bounds are validated against
    /// `MessageLength`, so a device-supplied offset/length pair
    /// can never alias outside the message.
    pub fn decode(buf: &'a [u8], expected_request_id: u32) -> Result<Self, RndisError> {
        let (msg_type, len) = message_prefix(buf)?;
        if msg_type != CMPLT_QUERY {
            return Err(RndisError::BadMessageType);
        }
        if len < Self::WIRE_LEN || buf.len() < Self::WIRE_LEN {
            return Err(RndisError::Truncated);
        }
        let request_id = request_id(buf)?;
        if request_id != expected_request_id {
            return Err(RndisError::BadRequestId);
        }
        let status = u32le(buf, 12).ok_or(RndisError::Truncated)?;
        if status != STATUS_SUCCESS {
            return Err(RndisError::DeviceStatus(status));
        }
        let info_len = u32le(buf, 16).ok_or(RndisError::Truncated)? as usize;
        let info_off = u32le(buf, 20).ok_or(RndisError::Truncated)? as usize;
        let info_start = 20usize.checked_add(info_off).ok_or(RndisError::BadLength)?;
        let info_end = info_start
            .checked_add(info_len)
            .ok_or(RndisError::BadLength)?;
        if info_end > len || info_end > buf.len() {
            return Err(RndisError::BadLength);
        }
        Ok(Self {
            request_id,
            info: &buf[info_start..info_end],
        })
    }
}

/// Decode `REMOTE_NDIS_SET_CMPLT` — 16 bytes:
///
/// ```text
///   u32 MessageType, MessageLength, RequestId, Status
/// ```
pub fn decode_set_complete(buf: &[u8], expected_request_id: u32) -> Result<u32, RndisError> {
    let (msg_type, len) = message_prefix(buf)?;
    if msg_type != CMPLT_SET {
        return Err(RndisError::BadMessageType);
    }
    if len < 16 || buf.len() < 16 {
        return Err(RndisError::Truncated);
    }
    let rid = request_id(buf)?;
    if rid != expected_request_id {
        return Err(RndisError::BadRequestId);
    }
    let status = u32le(buf, 12).ok_or(RndisError::Truncated)?;
    if status != STATUS_SUCCESS {
        return Err(RndisError::DeviceStatus(status));
    }
    Ok(rid)
}

// ── RESET / KEEPALIVE / HALT ────────────────────────────────────────

/// Encode `REMOTE_NDIS_RESET_MSG` — 12 bytes:
///
/// ```text
///   u32 MessageType (0x00000006), MessageLength (12),
///   u32 Reserved (0)
/// ```
pub fn encode_reset_msg() -> [u8; 12] {
    let mut out = [0u8; 12];
    put_u32le(&mut out, 0, MSG_RESET);
    put_u32le(&mut out, 4, 12);
    out
}

/// Decode `REMOTE_NDIS_RESET_CMPLT` — 16 bytes:
///
/// ```text
///   u32 MessageType, MessageLength, Status, AddressingReset
/// ```
/// Returns `AddressingReset` (nonzero ↔ the device reset its
/// addressing state). A non-success status is an error.
pub fn decode_reset_complete(buf: &[u8]) -> Result<bool, RndisError> {
    let (msg_type, len) = message_prefix(buf)?;
    if msg_type != CMPLT_RESET {
        return Err(RndisError::BadMessageType);
    }
    if len < 16 || buf.len() < 16 {
        return Err(RndisError::Truncated);
    }
    let status = u32le(buf, 8).ok_or(RndisError::Truncated)?;
    if status != STATUS_SUCCESS {
        return Err(RndisError::DeviceStatus(status));
    }
    Ok(u32le(buf, 12).ok_or(RndisError::Truncated)? != 0)
}

/// Encode `REMOTE_NDIS_KEEPALIVE_MSG` — 12 bytes:
///
/// ```text
///   u32 MessageType (0x00000008), MessageLength (12),
///   u32 RequestId
/// ```
pub fn encode_keepalive_msg(request_id: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    put_u32le(&mut out, 0, MSG_KEEPALIVE);
    put_u32le(&mut out, 4, 12);
    put_u32le(&mut out, 8, request_id);
    out
}

/// Decode `REMOTE_NDIS_KEEPALIVE_CMPLT` — 16 bytes:
///
/// ```text
///   u32 MessageType, MessageLength, RequestId, Status
/// ```
pub fn decode_keepalive_complete(buf: &[u8], expected_request_id: u32) -> Result<u32, RndisError> {
    let (msg_type, len) = message_prefix(buf)?;
    if msg_type != CMPLT_KEEPALIVE {
        return Err(RndisError::BadMessageType);
    }
    if len < 16 || buf.len() < 16 {
        return Err(RndisError::Truncated);
    }
    let rid = request_id(buf)?;
    if rid != expected_request_id {
        return Err(RndisError::BadRequestId);
    }
    let status = u32le(buf, 12).ok_or(RndisError::Truncated)?;
    if status != STATUS_SUCCESS {
        return Err(RndisError::DeviceStatus(status));
    }
    Ok(rid)
}

/// Encode `REMOTE_NDIS_HALT_MSG` — 12 bytes:
///
/// ```text
///   u32 MessageType (0x00000003), MessageLength (12),
///   u32 RequestId
/// ```
pub fn encode_halt_msg(request_id: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    put_u32le(&mut out, 0, MSG_HALT);
    put_u32le(&mut out, 4, 12);
    put_u32le(&mut out, 8, request_id);
    out
}

// ── INDICATE_STATUS (spec §"REMOTE_NDIS_INDICATE_STATUS_MSG") ──────

/// Decoded `REMOTE_NDIS_INDICATE_STATUS_MSG`:
///
/// ```text
///   u32 MessageType, MessageLength, Status,
///   u32 StatusBufferLength, StatusBufferOffset,
///   u32 DiagStatus, DiagBufferLength, DiagBufferOffset
/// ```
/// (32 bytes; the diagnostic fields are present in the spec
/// form. The status buffer starts at `12 +
/// StatusBufferOffset` — offset measured from its own field.)
/// Only `Status` drives the link state; the buffer is carried
/// for diagnostics. Decoders require at least the 20 bytes
/// through `StatusBufferOffset` so a truncated indication is
/// rejected rather than misread.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IndicateStatus<'a> {
    pub status: u32,
    pub status_buffer: &'a [u8],
    pub diag_status: u32,
}

impl<'a> IndicateStatus<'a> {
    pub fn decode(buf: &'a [u8]) -> Result<Self, RndisError> {
        let (msg_type, len) = message_prefix(buf)?;
        if msg_type != MSG_INDICATE_STATUS {
            return Err(RndisError::BadMessageType);
        }
        if len < 20 || buf.len() < 20 {
            return Err(RndisError::Truncated);
        }
        let status = u32le(buf, 8).ok_or(RndisError::Truncated)?;
        let sb_len = u32le(buf, 12).ok_or(RndisError::Truncated)? as usize;
        let sb_off = u32le(buf, 16).ok_or(RndisError::Truncated)? as usize;
        let sb_start = 12usize.checked_add(sb_off).ok_or(RndisError::BadLength)?;
        let sb_end = sb_start.checked_add(sb_len).ok_or(RndisError::BadLength)?;
        if sb_end > len || sb_end > buf.len() {
            return Err(RndisError::BadLength);
        }
        let diag_status = if buf.len() >= 24 {
            u32le(buf, 20).unwrap_or(0)
        } else {
            0
        };
        Ok(Self {
            status,
            status_buffer: &buf[sb_start..sb_end],
            diag_status,
        })
    }

    /// True for `RNDIS_STATUS_MEDIA_CONNECT`.
    pub fn is_connect(&self) -> bool {
        self.status == STATUS_MEDIA_CONNECT
    }

    /// True for `RNDIS_STATUS_MEDIA_DISCONNECT`.
    pub fn is_disconnect(&self) -> bool {
        self.status == STATUS_MEDIA_DISCONNECT
    }
}

// ── PACKET_MSG (spec §"REMOTE_NDIS_PACKET_MSG") ─────────────────────

/// Encode one `REMOTE_NDIS_PACKET_MSG` wrapping `frame` — 44
/// bytes of header + the frame, no OOB data, no per-packet
/// info:
///
/// ```text
///   u32 MessageType (0x00000001), MessageLength (44 + len),
///   u32 DataOffset (36), DataLength (len),
///   u32 OOBDataOffset (0), OOBDataLength (0),
///   u32 NumOOBDataElements (0),
///   u32 PerPacketInfoOffset (0), PerPacketInfoLength (0),
///   u32 VcHandle (0), Reserved (0)
/// ```
/// `DataOffset = 36` because it is measured from the start of
/// its own field (byte 8): `8 + 36 = 44`, the first payload
/// byte. Single-packet TX needs no alignment padding (the
/// alignment factor governs boundaries *between* elements of a
/// multipacket message).
pub fn encode_packet_msg(frame: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 44 + frame.len()];
    let total_len = out.len() as u32;
    put_u32le(&mut out, 0, MSG_PACKET);
    put_u32le(&mut out, 4, total_len);
    put_u32le(&mut out, 8, 36);
    put_u32le(&mut out, 12, frame.len() as u32);
    // OOB / per-packet-info / VcHandle / Reserved stay zero.
    out[44..].copy_from_slice(frame);
    out
}

/// Decode one `REMOTE_NDIS_PACKET_MSG` at the start of `buf`,
/// returning the Ethernet frame slice. Bounds are validated
/// against `MessageLength`, so a device-supplied
/// offset/length pair can never alias outside the message.
///
/// Returns `(frame, message_length)` — the caller advances by
/// `message_length` when walking a multipacket buffer.
pub fn decode_packet_msg(buf: &[u8]) -> Result<(&[u8], usize), RndisError> {
    let (msg_type, len) = message_prefix(buf)?;
    if msg_type != MSG_PACKET {
        return Err(RndisError::BadMessageType);
    }
    if len < 44 || buf.len() < 44 {
        return Err(RndisError::Truncated);
    }
    let data_off = u32le(buf, 8).ok_or(RndisError::Truncated)? as usize;
    let data_len = u32le(buf, 12).ok_or(RndisError::Truncated)? as usize;
    let data_start = 8usize.checked_add(data_off).ok_or(RndisError::BadLength)?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(RndisError::BadLength)?;
    if data_end > len || data_end > buf.len() {
        return Err(RndisError::BadLength);
    }
    Ok((&buf[data_start..data_end], len))
}

/// Walk a bulk-IN buffer holding one or more concatenated
/// `REMOTE_NDIS_PACKET_MSG`s (a multipacket message) and
/// collect each Ethernet frame. Stops at the first malformed
/// element and returns the frames collected so far together
/// with `false`; returns `true` when the whole buffer walked
/// cleanly. An empty buffer yields zero frames and `true`.
/// Single-packet fixtures pass a tail-walk bug; the
/// multipacket fixture below is what catches it.
pub fn parse_multipacket<'a>(buf: &'a [u8], frames: &mut Vec<&'a [u8]>) -> bool {
    let mut off = 0usize;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < 8 {
            return false;
        }
        match decode_packet_msg(rest) {
            Ok((frame, msg_len)) => {
                if msg_len == 0 || msg_len > rest.len() {
                    return false;
                }
                frames.push(frame);
                off += msg_len;
            }
            Err(_) => return false,
        }
    }
    true
}

// ── Packet filter (NDIS_PACKET_TYPE_* bitmap) ───────────────────────

/// Packet-filter bitmap for `OID_GEN_CURRENT_PACKET_FILTER`.
///
/// A nonzero value moves the device to RNDIS-data-initialized
/// (spec §"Device State Definitions"); zero disables receive
/// indications.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketFilter {
    pub directed: bool,
    pub multicast: bool,
    pub all_multicast: bool,
    pub broadcast: bool,
    pub promiscuous: bool,
}

impl PacketFilter {
    /// Typical "normal" filter: directed + broadcast + multicast.
    pub const NORMAL: Self = Self {
        directed: true,
        multicast: true,
        all_multicast: false,
        broadcast: true,
        promiscuous: false,
    };

    /// Encode as the `u32` value for the SET.
    pub fn encode(&self) -> u32 {
        let mut v: u32 = 0;
        if self.directed {
            v |= FILTER_DIRECTED;
        }
        if self.multicast {
            v |= FILTER_MULTICAST;
        }
        if self.all_multicast {
            v |= FILTER_ALL_MULTICAST;
        }
        if self.broadcast {
            v |= FILTER_BROADCAST;
        }
        if self.promiscuous {
            v |= FILTER_PROMISCUOUS;
        }
        v
    }

    /// Decode a filter bitmap (round-trip testing).
    pub fn decode(v: u32) -> Self {
        Self {
            directed: v & FILTER_DIRECTED != 0,
            multicast: v & FILTER_MULTICAST != 0,
            all_multicast: v & FILTER_ALL_MULTICAST != 0,
            broadcast: v & FILTER_BROADCAST != 0,
            promiscuous: v & FILTER_PROMISCUOUS != 0,
        }
    }
}

// ── Device state ───────────────────────────────────────────────────

/// RNDIS device state (spec §"Device State Definitions").
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RndisState {
    /// After bus-level init, before a successful INITIALIZE.
    Uninitialized,
    /// After INITIALIZE_CMPLT with SUCCESS.
    Initialized,
    /// After a nonzero packet-filter SET.
    DataInitialized,
}

/// Negotiated parameters from `INITIALIZE_CMPLT`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RndisNegotiated {
    /// Device flags (`DF_CONNECTIONLESS` expected).
    pub device_flags: u32,
    /// Medium (`MEDIUM_802_3` expected).
    pub medium: u32,
    /// Max `PACKET_MSG`s per multipacket transfer (0 = the
    /// device imposes no count cap — host applies its own).
    pub max_packets_per_transfer: u32,
    /// Max bytes per bulk transfer (device side).
    pub max_transfer_size: u32,
    /// Alignment exponent: multipacket elements after the
    /// first start at multiples of `1 << factor` bytes.
    pub packet_alignment_factor: u32,
    /// Maximum Ethernet frame size from
    /// `OID_GEN_MAXIMUM_FRAME_SIZE` (spec default 1518 when
    /// the query fails).
    pub max_frame_size: u32,
    /// Media-connect status from
    /// `OID_GEN_MEDIA_CONNECT_STATUS` (`Some(true)` =
    /// connected, `Some(false)` = disconnected, `None` = the
    /// query failed and link state is unknown).
    pub media_connected: Option<bool>,
}

// ── Bring-up state machine (pure — no hardware) ────────────────────
//
// Drives the control-channel exchange as a request/response
// loop: `next_request()` yields the bytes to send, and
// `handle_response()` consumes the device's reply and advances
// the step. The async bind loop feeds it through xHCI; the
// fixtures feed it through a scripted fake device, so the
// exchange is validated end to end without silicon.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BringupStep {
    SendInitialize,
    AwaitInitialize,
    SendQueryCurrentAddress,
    AwaitQueryCurrentAddress,
    SendQueryPermanentAddress,
    AwaitQueryPermanentAddress,
    SendQueryMaxFrame,
    AwaitQueryMaxFrame,
    SendQueryMediaConnect,
    AwaitQueryMediaConnect,
    SendSetFilter,
    AwaitSetFilter,
    Done,
}

/// Pure driver of the RNDIS bring-up exchange.
#[derive(Debug)]
pub struct RndisBringup {
    step: BringupStep,
    request_id: u32,
    max_transfer_size: u32,
    negotiated: Option<RndisNegotiated>,
    mac: Option<[u8; 6]>,
    max_frame_size: u32,
    media_connected: Option<bool>,
}

impl RndisBringup {
    /// Start a bring-up offering `max_transfer_size` (the
    /// host's RX buffer size) in INITIALIZE.
    pub fn new(max_transfer_size: u32) -> Self {
        Self {
            step: BringupStep::SendInitialize,
            request_id: 0,
            max_transfer_size,
            negotiated: None,
            mac: None,
            max_frame_size: RNDIS_MAXIMUM_FRAME_SIZE,
            media_connected: None,
        }
    }

    /// True once the filter SET completed — the device is in
    /// RNDIS-data-initialized and the datapath may start.
    pub fn is_done(&self) -> bool {
        self.step == BringupStep::Done
    }

    /// Current device state implied by the exchange progress.
    pub fn state(&self) -> RndisState {
        match self.step {
            BringupStep::SendInitialize | BringupStep::AwaitInitialize => RndisState::Uninitialized,
            BringupStep::Done => RndisState::DataInitialized,
            _ => RndisState::Initialized,
        }
    }

    /// Negotiated parameters once INITIALIZE completed.
    pub fn negotiated(&self) -> Option<RndisNegotiated> {
        self.negotiated
    }

    /// Station address once an address query completed.
    pub fn mac(&self) -> Option<[u8; 6]> {
        self.mac
    }

    /// Next control message to send, or `None` when done.
    /// Advances the step to the matching await state.
    pub fn next_request(&mut self) -> Option<Vec<u8>> {
        let rid = self.request_id.wrapping_add(1);
        self.request_id = rid;
        match self.step {
            BringupStep::SendInitialize => {
                self.step = BringupStep::AwaitInitialize;
                Some(encode_initialize_msg(rid, self.max_transfer_size).to_vec())
            }
            BringupStep::SendQueryCurrentAddress => {
                self.step = BringupStep::AwaitQueryCurrentAddress;
                Some(encode_query_msg(rid, OID_802_3_CURRENT_ADDRESS, &[]))
            }
            BringupStep::SendQueryPermanentAddress => {
                self.step = BringupStep::AwaitQueryPermanentAddress;
                Some(encode_query_msg(rid, OID_802_3_PERMANENT_ADDRESS, &[]))
            }
            BringupStep::SendQueryMaxFrame => {
                self.step = BringupStep::AwaitQueryMaxFrame;
                Some(encode_query_msg(rid, OID_GEN_MAXIMUM_FRAME_SIZE, &[]))
            }
            BringupStep::SendQueryMediaConnect => {
                self.step = BringupStep::AwaitQueryMediaConnect;
                Some(encode_query_msg(rid, OID_GEN_MEDIA_CONNECT_STATUS, &[]))
            }
            BringupStep::SendSetFilter => {
                self.step = BringupStep::AwaitSetFilter;
                let filter = PacketFilter::NORMAL.encode().to_le_bytes();
                Some(encode_set_msg(rid, OID_GEN_CURRENT_PACKET_FILTER, &filter))
            }
            _ => None,
        }
    }

    /// Feed one device response. Validates type, RequestId and
    /// status for the pending step, records the negotiated
    /// values, and advances. Returns the step's outcome as an
    /// error when the device refuses or mis-frames a reply.
    ///
    /// Fallback rules (fail-soft where the spec allows it):
    /// a failed/invalid current-address query falls back to
    /// the permanent address; a failed max-frame or
    /// media-connect query keeps the spec default / unknown
    /// and the exchange continues — only a failed
    /// INITIALIZE, a failed address lookup on both OIDs, or
    /// a failed filter SET aborts bring-up.
    pub fn handle_response(&mut self, resp: &[u8]) -> Result<(), RndisError> {
        match self.step {
            BringupStep::AwaitInitialize => {
                let init = InitializeComplete::decode(resp, self.request_id)?;
                if init.medium != MEDIUM_802_3 {
                    return Err(RndisError::BadMedium);
                }
                if init.device_flags & DF_CONNECTIONLESS == 0 {
                    return Err(RndisError::BadDeviceFlags);
                }
                self.negotiated = Some(RndisNegotiated {
                    device_flags: init.device_flags,
                    medium: init.medium,
                    max_packets_per_transfer: init.max_packets_per_transfer,
                    max_transfer_size: init.max_transfer_size,
                    packet_alignment_factor: init.packet_alignment_factor,
                    max_frame_size: self.max_frame_size,
                    media_connected: None,
                });
                self.step = BringupStep::SendQueryCurrentAddress;
                Ok(())
            }
            BringupStep::AwaitQueryCurrentAddress => {
                match self.decode_mac_query(resp) {
                    Ok(mac) => {
                        self.mac = Some(mac);
                        self.step = BringupStep::SendQueryMaxFrame;
                        Ok(())
                    }
                    Err(_) => {
                        // Fall back to the permanent address.
                        self.step = BringupStep::SendQueryPermanentAddress;
                        Ok(())
                    }
                }
            }
            BringupStep::AwaitQueryPermanentAddress => {
                let mac = self.decode_mac_query(resp)?;
                if !is_valid_station_address(&mac) {
                    return Err(RndisError::NoMacAddress);
                }
                self.mac = Some(mac);
                self.step = BringupStep::SendQueryMaxFrame;
                Ok(())
            }
            BringupStep::AwaitQueryMaxFrame => {
                match QueryComplete::decode(resp, self.request_id) {
                    Ok(q) if q.info.len() >= 4 => {
                        let size = u32::from_le_bytes([q.info[0], q.info[1], q.info[2], q.info[3]]);
                        if size > 0 {
                            self.max_frame_size = size;
                        }
                    }
                    _ => {}
                }
                if let Some(n) = self.negotiated.as_mut() {
                    n.max_frame_size = self.max_frame_size;
                }
                self.step = BringupStep::SendQueryMediaConnect;
                Ok(())
            }
            BringupStep::AwaitQueryMediaConnect => {
                match QueryComplete::decode(resp, self.request_id) {
                    Ok(q) if q.info.len() >= 4 => {
                        let v = u32::from_le_bytes([q.info[0], q.info[1], q.info[2], q.info[3]]);
                        self.media_connected = Some(v != 0);
                    }
                    _ => {}
                }
                if let Some(n) = self.negotiated.as_mut() {
                    n.media_connected = self.media_connected;
                }
                self.step = BringupStep::SendSetFilter;
                Ok(())
            }
            BringupStep::AwaitSetFilter => {
                decode_set_complete(resp, self.request_id)?;
                self.step = BringupStep::Done;
                Ok(())
            }
            _ => Err(RndisError::BadMessageType),
        }
    }

    /// Decode an address query response and validate the MAC.
    /// A device error status or a malformed reply is an error
    /// here (the caller decides whether to fall back); an
    /// invalid station address is also an error, never a
    /// silently accepted address.
    fn decode_mac_query(&self, resp: &[u8]) -> Result<[u8; 6], RndisError> {
        let q = QueryComplete::decode(resp, self.request_id)?;
        if q.info.len() < 6 {
            return Err(RndisError::Truncated);
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&q.info[..6]);
        if !is_valid_station_address(&mac) {
            return Err(RndisError::NoMacAddress);
        }
        Ok(mac)
    }
}

// ── CDC notification decoder (CDC 1.2 §6.3) ────────────────────────

/// `NETWORK_CONNECTION` notification code.
pub const NOTIFICATION_NETWORK_CONNECTION: u8 = 0x00;
/// `RESPONSE_AVAILABLE` notification code.
pub const NOTIFICATION_RESPONSE_AVAILABLE: u8 = 0x01;
/// `CONNECTION_SPEED_CHANGE` notification code.
pub const NOTIFICATION_CONNECTION_SPEED_CHANGE: u8 = 0x0A;

/// Decoded notification packet from the Comm interface's
/// interrupt-IN endpoint: 8-byte header (`bmRequestType`,
/// code, `wValue`, `wIndex`, `wLength`, little-endian)
/// followed by `wLength` payload bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RndisNotification {
    /// `NETWORK_CONNECTION` — `wValue` bit 0 set ↔ link up.
    NetworkConnection { up: bool },
    /// `RESPONSE_AVAILABLE` — an encapsulated response is
    /// waiting; the control exchange polls for it.
    ResponseAvailable,
    /// `CONNECTION_SPEED_CHANGE` — 8-byte payload: downlink
    /// bitrate `u32` LE, then uplink bitrate `u32` LE.
    ConnectionSpeedChange { downlink_bps: u32, uplink_bps: u32 },
    /// Notification code the parser doesn't decode further.
    Unknown { code: u8, value: u16, index: u16 },
}

impl RndisNotification {
    pub fn decode(packet: &[u8]) -> Result<Self, RndisError> {
        if packet.len() < 8 {
            return Err(RndisError::Truncated);
        }
        let code = packet[1];
        let value = u16::from_le_bytes([packet[2], packet[3]]);
        let index = u16::from_le_bytes([packet[4], packet[5]]);
        let length = u16::from_le_bytes([packet[6], packet[7]]) as usize;
        if packet.len() < 8 + length {
            return Err(RndisError::Truncated);
        }
        Ok(match code {
            NOTIFICATION_NETWORK_CONNECTION => {
                RndisNotification::NetworkConnection { up: value & 1 != 0 }
            }
            NOTIFICATION_RESPONSE_AVAILABLE => RndisNotification::ResponseAvailable,
            NOTIFICATION_CONNECTION_SPEED_CHANGE => {
                if length < 8 {
                    return Err(RndisError::Truncated);
                }
                RndisNotification::ConnectionSpeedChange {
                    downlink_bps: u32::from_le_bytes([
                        packet[8], packet[9], packet[10], packet[11],
                    ]),
                    uplink_bps: u32::from_le_bytes([
                        packet[12], packet[13], packet[14], packet[15],
                    ]),
                }
            }
            other => RndisNotification::Unknown {
                code: other,
                value,
                index,
            },
        })
    }
}

// ── Config-blob walkers ──────────────────────────────────────────────
//
// All walkers take a raw configuration descriptor blob and never
// touch hardware, so they are directly unit-testable against
// modelled descriptors. Descriptor walking idiom mirrors
// `cdc_ecm` / `cdc_ncm`: `len` guards every step; a malformed
// block ends the walk instead of panicking.

/// Find the first CDC-Comm interface with subclass ACM (`0x02`)
/// **and protocol `0xFF`** (RNDIS) in `cfg`. Returns its
/// `bInterfaceNumber`. A real modem (protocol `0x00`–`0x06`)
/// does not match — this is what keeps the RNDIS binder from
/// claiming ACM devices — and neither do NCM (`0x0D`) or ECM
/// (`0x06`) Comm interfaces.
pub fn find_rndis_comm_interface(cfg: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        if cfg[i + 1] == 0x04 && len >= 9 {
            let cls = cfg[i + 5];
            let sub = cfg[i + 6];
            let proto = cfg[i + 7];
            if cls == USB_CLASS_CDC_COMM && sub == RNDIS_SUBCLASS_ACM && proto == RNDIS_PROTOCOL {
                return Some(cfg[i + 2]);
            }
        }
        i += len;
    }
    None
}

/// One CDC-Data interface's bulk pair as seen while walking.
struct DataPair {
    num: u8,
    bulk_in: Option<EndpointConfig>,
    bulk_out: Option<EndpointConfig>,
}

/// Walk the config blob for the CDC-Data interface that belongs
/// to the RNDIS function on Comm interface `comm_iface`, and
/// return its (interface_number, bulk_in_ep, bulk_out_ep).
///
/// Selection rule (mirrors `cdc_ecm`): the Union descriptor is
/// authoritative (CDC 1.2 §5.2.3.2 groups one control interface
/// with its subordinate data interfaces). If the Union names a
/// subordinate Data interface that carries a complete bulk
/// pair, that interface wins — even when another Data interface
/// appears earlier or later in the blob (composite trap). With
/// no usable Union, the first Data interface *after* the Comm
/// interface with a complete pair wins. Data interfaces before
/// the Comm interface belong to another function and never win.
///
/// Alt-setting rule: within one interface number, the *last*
/// alt setting seen wins its pair (the standard RNDIS layout
/// is alt 0 with no endpoints, then alt 1 with the bulk pair).
pub fn find_rndis_bulk_endpoints(
    cfg: &[u8],
    comm_iface: u8,
) -> Option<(u8, EndpointConfig, EndpointConfig)> {
    let union = find_rndis_union(cfg, comm_iface);
    let union_subs: Vec<u8> = union.map(|u| u.subordinate_interfaces).unwrap_or_default();

    let mut seen_comm = false;
    let mut current_data: Option<usize> = None;
    let mut datas: Vec<DataPair> = Vec::new();
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            let num = cfg[i + 2];
            let cls = cfg[i + 5];
            if num == comm_iface {
                seen_comm = true;
                current_data = None;
            } else if seen_comm && cls == USB_CLASS_CDC_DATA {
                match datas.iter_mut().find(|d| d.num == num) {
                    Some(d) => {
                        d.bulk_in = None;
                        d.bulk_out = None;
                        current_data = datas.iter().position(|d| d.num == num);
                    }
                    None => {
                        datas.push(DataPair {
                            num,
                            bulk_in: None,
                            bulk_out: None,
                        });
                        current_data = Some(datas.len() - 1);
                    }
                }
            } else {
                current_data = None;
            }
        } else if desc_type == 0x05 && len >= 7 {
            if let Some(di) = current_data {
                let ep_addr = cfg[i + 2];
                let attrs = cfg[i + 3];
                let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                if attrs & 0x03 == 2 {
                    let is_in = ep_addr & 0x80 != 0;
                    let ep_cfg = EndpointConfig {
                        ep_addr,
                        max_packet,
                        kind: if is_in {
                            EndpointKind::BulkIn
                        } else {
                            EndpointKind::BulkOut
                        },
                        interval: 0,
                    };
                    if is_in && datas[di].bulk_in.is_none() {
                        datas[di].bulk_in = Some(ep_cfg);
                    } else if !is_in && datas[di].bulk_out.is_none() {
                        datas[di].bulk_out = Some(ep_cfg);
                    }
                }
            }
        }
        i += len;
    }
    // Union-authoritative selection, then first complete pair.
    for sub in &union_subs {
        if let Some(d) = datas.iter().find(|d| d.num == *sub) {
            if let (Some(bi), Some(bo)) = (d.bulk_in, d.bulk_out) {
                return Some((d.num, bi, bo));
            }
        }
    }
    for d in &datas {
        if let (Some(bi), Some(bo)) = (d.bulk_in, d.bulk_out) {
            return Some((d.num, bi, bo));
        }
    }
    None
}

/// Locate the Union functional descriptor in the descriptor set
/// that follows the Comm interface `comm_iface` within `cfg`.
/// The Union names the subordinate Data interface(s); absent on
/// malformed firmware, in which case the bulk walker falls back
/// to first-Data-after-Comm.
fn find_rndis_union(cfg: &[u8], comm_iface: u8) -> Option<super::cdc::UnionDescriptor> {
    use super::cdc::{FunctionalSubtype, CS_INTERFACE};
    let mut in_comm = false;
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            in_comm = cfg[i + 2] == comm_iface;
        } else if desc_type == CS_INTERFACE && in_comm {
            let chunk = &cfg[i..i + len];
            if len >= 3 && FunctionalSubtype::decode(chunk[2]) == FunctionalSubtype::Union {
                if let Ok(u) = super::cdc::UnionDescriptor::parse(chunk) {
                    return Some(u);
                }
            }
        }
        i += len;
    }
    None
}

/// Find the endpoint-bearing alt setting of a CDC-Data
/// interface: the first Data interface whose alt setting
/// carries a bulk endpoint. Returns `(iface, alt)`; `None`
/// when every Data interface is alt 0 with no endpoints.
/// (Same walk as `cdc_ncm::find_ncm_data_alt_setting`.)
pub fn find_rndis_data_alt_setting(cfg: &[u8]) -> Option<(u8, u8)> {
    let mut current: Option<(u8, u8, bool)> = None;
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            current = Some((cfg[i + 2], cfg[i + 3], cfg[i + 5] == USB_CLASS_CDC_DATA));
        } else if desc_type == 0x05 && len >= 7 {
            if let Some((num, alt, true)) = current {
                if cfg[i + 3] & 0x03 == 2 {
                    return Some((num, alt));
                }
            }
        }
        i += len;
    }
    None
}

/// Find the Comm interface's interrupt-IN notification endpoint
/// in `cfg`, if the device carries one. `None` is not fatal:
/// the control exchange polls `GET_ENCAPSULATED_RESPONSE`
/// directly, and link-state updates just stop arriving.
pub fn find_rndis_notif_endpoint(cfg: &[u8], comm_iface: u8) -> Option<EndpointConfig> {
    let mut current_iface: Option<u8> = None;
    let mut current_class: u8 = 0;
    let mut i = 0usize;
    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let desc_type = cfg[i + 1];
        if desc_type == 0x04 && len >= 9 {
            current_iface = Some(cfg[i + 2]);
            current_class = cfg[i + 5];
        } else if desc_type == 0x05 && len >= 7 {
            let ep_addr = cfg[i + 2];
            let attrs = cfg[i + 3];
            let max_packet = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
            if current_iface == Some(comm_iface)
                && current_class == USB_CLASS_CDC_COMM
                && attrs & 0x03 == 3
                && ep_addr & 0x80 != 0
            {
                return Some(EndpointConfig {
                    ep_addr,
                    max_packet,
                    kind: EndpointKind::InterruptIn,
                    interval: cfg[i + 6],
                });
            }
        }
        i += len;
    }
    None
}

// ── Device record ──────────────────────────────────────────────────

/// One bound RNDIS device.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RndisDevice {
    slot_id: u8,
    comm_iface: u8,
    data_iface: u8,
    bulk_in_dci: u8,
    bulk_out_dci: u8,
    notif_dci: u8,
    mac: [u8; 6],
    max_transfer_size: u32,
    max_packets_per_transfer: u32,
    packet_alignment_factor: u32,
    max_frame_size: u32,
    media_connected: Option<bool>,
    link_up: bool,
    next_request_id: u32,
    iface_name: String,
    pump_running: bool,
    notif_running: bool,
    detached: bool,
    controller: u8,
}

/// Bound RNDIS devices, indexed by registration order.
/// Records are never removed (tombstoned on detach) so a TX
/// cookie for an index can never retarget a later device —
/// the `cdc_ecm` / `cdc_ncm` pattern.
pub static RNDIS_DEVICES: IrqSafeSpinLock<Vec<RndisDevice>> = IrqSafeSpinLock::new(Vec::new());

fn controller_of(idx: usize) -> Option<alloc::sync::Arc<crate::xhci::Xhci>> {
    let g = RNDIS_DEVICES.lock();
    let dev = g.get(idx)?;
    crate::xhci::controller_by_id(dev.controller)
}

/// RX buffer length for a device: its negotiated
/// MaxTransferSize, clamped to `[RX_BUFFER_MIN, RX_BUFFER_MAX]`.
/// A zero/undersized device value falls back to the host offer.
fn rndis_rx_buf_len(max_transfer_size: u32) -> usize {
    let size = if max_transfer_size == 0 {
        HOST_MAX_TRANSFER_SIZE
    } else {
        max_transfer_size
    };
    size.clamp(RX_BUFFER_MIN, RX_BUFFER_MAX) as usize
}

// ── Control-channel exchange ───────────────────────────────────────

/// Maximum `GET_ENCAPSULATED_RESPONSE` polls per request
/// before the exchange gives up. The device answers most
/// requests immediately; the bound keeps a wedged device from
/// stalling bind forever.
const MAX_RESPONSE_POLLS: usize = 16;

/// Send one RNDIS control message and wait for its matching
/// response.
///
/// The message goes out as `SEND_ENCAPSULATED_COMMAND` on EP0.
/// The response is then polled with
/// `GET_ENCAPSULATED_RESPONSE` until a message arrives whose
/// `MessageType` is the expected completion and whose
/// `RequestId` matches (stale/unsolicited responses — e.g. an
/// `INDICATE_STATUS` queued ahead of the reply — are skipped
/// within the poll bound). Yields between polls so the
/// controller can make progress.
///
/// Returns the response bytes. The caller decodes them with
/// the matching `decode_*` function.
async fn rndis_command(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    comm_iface: u8,
    request: &[u8],
    expected_complete: u32,
) -> Result<Vec<u8>, RndisError> {
    xhci_dev
        .control_out(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            REQ_SEND_ENCAPSULATED_COMMAND,
            0,
            comm_iface as u16,
            request,
        )
        .await
        .map_err(|_| RndisError::Transfer)?;
    let expected_rid = request_id(request).map_err(|_| RndisError::Transfer)?;
    let mut buf = alloc::vec![0u8; 4096];
    for _ in 0..MAX_RESPONSE_POLLS {
        match xhci_dev
            .control_in(
                slot_id,
                RT_DEV_TO_HOST_CLASS_IFACE,
                REQ_GET_ENCAPSULATED_RESPONSE,
                0,
                comm_iface as u16,
                &mut buf,
            )
            .await
        {
            Ok(n) if n >= 12 => {
                let got = &buf[..n];
                let (msg_type, _) = match message_prefix(got) {
                    Ok(p) => p,
                    Err(_) => {
                        narf_scheduler::yield_now().await;
                        continue;
                    }
                };
                if msg_type == expected_complete {
                    if request_id(got).ok() == Some(expected_rid) {
                        return Ok(got.to_vec());
                    }
                    // Right type, wrong request — a stale reply
                    // for an earlier request; keep polling.
                }
                // Wrong type (e.g. an unsolicited INDICATE_STATUS
                // queued ahead of the reply) — keep polling.
                narf_scheduler::yield_now().await;
            }
            Ok(_) => narf_scheduler::yield_now().await,
            Err(_) => narf_scheduler::yield_now().await,
        }
    }
    Err(RndisError::Transfer)
}

/// Run the [`RndisBringup`] exchange over the control channel.
/// Returns the negotiated parameters + station address.
async fn run_bringup(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    comm_iface: u8,
) -> Result<(RndisNegotiated, [u8; 6]), RndisError> {
    let mut bringup = RndisBringup::new(HOST_MAX_TRANSFER_SIZE);
    while !bringup.is_done() {
        let request = match bringup.next_request() {
            Some(r) => r,
            None => break,
        };
        let expected = match message_prefix(&request) {
            Ok((MSG_INITIALIZE, _)) => CMPLT_INITIALIZE,
            Ok((MSG_QUERY, _)) => CMPLT_QUERY,
            Ok((MSG_SET, _)) => CMPLT_SET,
            _ => return Err(RndisError::BadMessageType),
        };
        let resp = rndis_command(xhci_dev, slot_id, comm_iface, &request, expected).await?;
        bringup.handle_response(&resp)?;
    }
    match (bringup.negotiated(), bringup.mac()) {
        (Some(n), Some(mac)) => Ok((n, mac)),
        _ => Err(RndisError::NoMacAddress),
    }
}

// ── Bind ───────────────────────────────────────────────────────────

/// Post-address RNDIS bind: caller has already issued
/// port_reset + enable_slot + address_device. We pull the
/// config descriptor, match the Comm (0x02/0x02/0xFF) +
/// Data interface pair, configure the bulk endpoints, then run
/// the bring-up exchange (INITIALIZE → QUERY MAC / max frame /
/// media-connect → SET packet filter) and register the device
/// with the net-iface registry under `usb-rndisN`.
///
/// Returns the index into [`RNDIS_DEVICES`] on success, or
/// [`RndisError`] if the device is not RNDIS or bring-up fails.
pub async fn try_bind_rndis_already_addressed(
    xhci_dev: &crate::xhci::Xhci,
    slot_id: u8,
    cfg: &[u8],
) -> Result<usize, RndisError> {
    let comm_iface = find_rndis_comm_interface(cfg).ok_or(RndisError::NotRndis)?;
    let cfg_value = if cfg.len() >= 9 { cfg[5] } else { 1 };
    if xhci_dev
        .control_out(
            slot_id,
            0x00,
            crate::hid::STD_REQ_SET_CONFIGURATION,
            cfg_value as u16,
            0,
            &[],
        )
        .await
        .is_err()
    {
        return Err(RndisError::SetConfigFailed);
    }
    let (data_iface, bulk_in_ep, bulk_out_ep) =
        find_rndis_bulk_endpoints(cfg, comm_iface).ok_or(RndisError::NoBulkEndpoints)?;
    // Activate the data interface's endpoint-bearing alt setting
    // (commonly alt 1; alt 0 carries no endpoints and leaves the
    // data pipe inert on real firmware).
    if let Some((alt_iface, alt)) = find_rndis_data_alt_setting(cfg) {
        if alt > 0 {
            let _ = xhci_dev
                .control_out(slot_id, 0x01, 0x0B, alt as u16, alt_iface as u16, &[])
                .await;
        }
    }
    let notif_ep = find_rndis_notif_endpoint(cfg, comm_iface);
    let mut ep_list = alloc::vec![bulk_in_ep, bulk_out_ep];
    if let Some(notif) = notif_ep {
        ep_list.push(notif);
    }
    if xhci_dev
        .configure_endpoints(slot_id, &ep_list)
        .await
        .is_err()
    {
        return Err(RndisError::SetConfigFailed);
    }
    let bulk_in_dci = ((bulk_in_ep.ep_addr & 0x0F) * 2) + 1;
    let bulk_out_dci = (bulk_out_ep.ep_addr & 0x0F) * 2;
    let notif_dci = notif_ep
        .map(|ep| ((ep.ep_addr & 0x0F) * 2) + 1)
        .unwrap_or(0);

    // The bring-up exchange negotiates the device and yields the
    // station address; no address is ever invented.
    let (negotiated, mac) = run_bringup(xhci_dev, slot_id, comm_iface).await?;

    let idx = {
        let mut g = RNDIS_DEVICES.lock();
        let idx = g.len();
        g.push(RndisDevice {
            slot_id,
            comm_iface,
            data_iface,
            bulk_in_dci,
            bulk_out_dci,
            notif_dci,
            mac,
            max_transfer_size: negotiated.max_transfer_size,
            max_packets_per_transfer: negotiated.max_packets_per_transfer,
            packet_alignment_factor: negotiated.packet_alignment_factor,
            max_frame_size: negotiated.max_frame_size,
            media_connected: negotiated.media_connected,
            link_up: negotiated.media_connected.unwrap_or(false),
            next_request_id: 0,
            iface_name: alloc::format!("usb-rndis{}", idx),
            pump_running: false,
            notif_running: false,
            detached: false,
            controller: xhci_dev.id(),
        });
        idx
    };
    let assigned = register_rndis_iface(idx, mac);
    {
        let mut g = RNDIS_DEVICES.lock();
        g[idx].iface_name = assigned;
        g[idx].pump_running = true;
        g[idx].notif_running = notif_dci != 0;
    }
    // Pre-arm the notification endpoint so the controller starts
    // polling the device for link events. Failure only disables
    // link-state updates; the datapath is unaffected.
    if notif_dci != 0 {
        let max_packet = notif_ep.map(|ep| ep.max_packet).unwrap_or(16);
        if xhci_dev
            .arm_interrupt_in(slot_id, notif_dci, max_packet.min(64) as u32)
            .is_err()
        {
            let mut g = RNDIS_DEVICES.lock();
            if let Some(dev) = g.get_mut(idx) {
                dev.notif_running = false;
            }
        }
    }
    narf_scheduler::spawn(async move {
        rndis_rx_pump(idx).await;
    });
    if notif_dci != 0 {
        narf_scheduler::spawn(async move {
            rndis_notif_pump(idx).await;
        });
    }
    Ok(idx)
}

/// Supervised RX pump for one bound RNDIS device: post bulk-IN
/// reads sized by the negotiated MaxTransferSize, walk each
/// transfer as a (possibly multipacket) run of `PACKET_MSG`s,
/// and hand each Ethernet frame to the network stack. Stops
/// after a bounded run of consecutive transfer errors (a
/// removed device surfaces as persistent errors) or when the
/// record vanishes or is detached.
async fn rndis_rx_pump(idx: usize) {
    let (slot_id, bulk_in_dci, name, buf_len) = {
        let g = RNDIS_DEVICES.lock();
        let Some(dev) = g.get(idx).filter(|d| !d.detached) else {
            return;
        };
        (
            dev.slot_id,
            dev.bulk_in_dci,
            dev.iface_name.clone(),
            rndis_rx_buf_len(dev.max_transfer_size),
        )
    };
    let Some(c) = controller_of(idx) else {
        let mut g = RNDIS_DEVICES.lock();
        if let Some(dev) = g.get_mut(idx) {
            dev.pump_running = false;
        }
        return;
    };
    let mut buf = alloc::vec![0u8; buf_len];
    let mut errors = 0u32;
    loop {
        {
            let g = RNDIS_DEVICES.lock();
            if g.get(idx).map(|d| d.detached).unwrap_or(true) {
                break;
            }
        }
        match c.bulk_in(slot_id, bulk_in_dci, &mut buf).await {
            Ok(n) => {
                errors = 0;
                let mut frames: Vec<&[u8]> = Vec::new();
                if parse_multipacket(&buf[..n], &mut frames) {
                    for frame in frames {
                        let mut owned = frame.to_vec();
                        narf_net::iface::on_rx_frame_from(&name, &mut owned);
                    }
                } else {
                    narf_scheduler::yield_now().await;
                }
            }
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
    let mut g = RNDIS_DEVICES.lock();
    if let Some(dev) = g.get_mut(idx) {
        dev.pump_running = false;
    }
}

/// Notification pump for one bound RNDIS device: poll the
/// interrupt-IN endpoint and apply `NETWORK_CONNECTION` to the
/// record; `RESPONSE_AVAILABLE` needs no action here (the
/// control exchange polls for its response directly), and
/// unknown codes are decoded and ignored. Exits when the
/// record vanishes, is detached, or after a bounded run of
/// errors.
async fn rndis_notif_pump(idx: usize) {
    let (slot_id, notif_dci) = {
        let g = RNDIS_DEVICES.lock();
        let Some(dev) = g.get(idx).filter(|d| !d.detached) else {
            return;
        };
        (dev.slot_id, dev.notif_dci)
    };
    if notif_dci == 0 {
        return;
    }
    let Some(c) = controller_of(idx) else {
        let mut g = RNDIS_DEVICES.lock();
        if let Some(dev) = g.get_mut(idx) {
            dev.notif_running = false;
        }
        return;
    };
    let mut buf = [0u8; 64];
    let mut errors = 0u32;
    loop {
        {
            let g = RNDIS_DEVICES.lock();
            if g.get(idx).map(|d| d.detached).unwrap_or(true) {
                break;
            }
        }
        match c.poll_interrupt_in(slot_id, notif_dci, &mut buf) {
            Ok(Some(n)) => {
                errors = 0;
                if let Ok(notif) = RndisNotification::decode(&buf[..n.min(buf.len())]) {
                    let mut g = RNDIS_DEVICES.lock();
                    if let Some(dev) = g.get_mut(idx) {
                        match notif {
                            RndisNotification::NetworkConnection { up } => {
                                dev.link_up = up;
                                dev.media_connected = Some(up);
                            }
                            RndisNotification::ConnectionSpeedChange { .. }
                            | RndisNotification::ResponseAvailable
                            | RndisNotification::Unknown { .. } => {}
                        }
                    }
                }
            }
            Ok(None) => narf_scheduler::yield_now().await,
            Err(_) => {
                errors += 1;
                if errors >= 16 {
                    break;
                }
                narf_scheduler::yield_now().await;
            }
        }
    }
    let mut g = RNDIS_DEVICES.lock();
    if let Some(dev) = g.get_mut(idx) {
        dev.notif_running = false;
    }
}

// ── TX / RX trampolines + detach ─────────────────────────────────────

/// Resolve a device-record index to its TX target
/// `(slot_id, bulk_out_dci)`. Detached or missing records
/// resolve to `None` — the net stack must never send to a
/// detached device, and a tombstoned index must never retarget
/// another device.
pub fn tx_target(idx: usize) -> Option<(u8, u8)> {
    let g = RNDIS_DEVICES.lock();
    let dev = g.get(idx).filter(|d| !d.detached)?;
    Some((dev.slot_id, dev.bulk_out_dci))
}

/// Build the TX transfer for `eth_frame`: one `PACKET_MSG`
/// wrapping the frame, after the negotiated maximum-frame-size
/// cap check. A frame larger than the device's max frame size
/// is refused rather than truncated.
pub fn rndis_tx_frame(eth_frame: &[u8], max_frame_size: u32) -> Result<Vec<u8>, RndisError> {
    if eth_frame.len() as u32 > max_frame_size {
        return Err(RndisError::FrameTooLarge);
    }
    Ok(encode_packet_msg(eth_frame))
}

/// Send `eth_frame` via the bound RNDIS device. The frame goes
/// on bulk-OUT wrapped in a single `PACKET_MSG`.
pub fn send_frame(idx: usize, eth_frame: &[u8]) -> Result<usize, RndisError> {
    let (slot_id, bulk_out_dci, max_frame_size) = {
        let g = RNDIS_DEVICES.lock();
        let dev = g
            .get(idx)
            .filter(|d| !d.detached)
            .ok_or(RndisError::NotBound)?;
        (dev.slot_id, dev.bulk_out_dci, dev.max_frame_size)
    };
    let frame = rndis_tx_frame(eth_frame, max_frame_size)?;
    // The net stack's `SendFn` is sync — bridge to the now-async
    // bulk_out via block_on. Safe here because the trampoline is
    // called from netstack TX paths that are not themselves inside
    // an executor poll.
    let c = controller_of(idx).ok_or(RndisError::NoController)?;
    let outcome =
        narf_scheduler::block_on(async move { c.bulk_out(slot_id, bulk_out_dci, &frame).await });
    match outcome {
        Ok(n) => Ok(n),
        Err(_) => Err(RndisError::Transfer),
    }
}

/// Pull Ethernet frames off the bound RNDIS device's bulk-IN
/// endpoint into `scratch`, returning the frames as slices of
/// `scratch`. One transfer may hold several frames
/// (multipacket). Caller polls this periodically; on real
/// silicon the RX pump (not this call) is what streams frames
/// in.
pub fn recv_frames<'a>(idx: usize, scratch: &'a mut [u8]) -> Result<Vec<&'a [u8]>, RndisError> {
    let (slot_id, bulk_in_dci) = {
        let g = RNDIS_DEVICES.lock();
        let dev = g
            .get(idx)
            .filter(|d| !d.detached)
            .ok_or(RndisError::NotBound)?;
        (dev.slot_id, dev.bulk_in_dci)
    };
    let c = controller_of(idx).ok_or(RndisError::NoController)?;
    let outcome =
        narf_scheduler::block_on(async { c.bulk_in(slot_id, bulk_in_dci, scratch).await });
    match outcome {
        Ok(n) => {
            let mut frames: Vec<&[u8]> = Vec::new();
            if parse_multipacket(&scratch[..n], &mut frames) {
                Ok(frames)
            } else {
                Err(RndisError::BadMessageType)
            }
        }
        Err(_) => Err(RndisError::Transfer),
    }
}

/// Issue a `KEEPALIVE` on the control channel and wait for its
/// completion. The request id is allocated from the device
/// record so concurrent callers cannot reuse an id. Called
/// from non-executor contexts (same `block_on` contract as
/// [`send_frame`]).
pub fn send_keepalive(idx: usize) -> Result<(), RndisError> {
    let (slot_id, comm_iface, req_id) = {
        let mut g = RNDIS_DEVICES.lock();
        let dev = g
            .get_mut(idx)
            .filter(|d| !d.detached)
            .ok_or(RndisError::NotBound)?;
        dev.next_request_id = dev.next_request_id.wrapping_add(1);
        (dev.slot_id, dev.comm_iface, dev.next_request_id)
    };
    let c = controller_of(idx).ok_or(RndisError::NoController)?;
    let msg = encode_keepalive_msg(req_id);
    let outcome = narf_scheduler::block_on(async {
        if c.control_out(
            slot_id,
            RT_HOST_TO_DEV_CLASS_IFACE,
            REQ_SEND_ENCAPSULATED_COMMAND,
            0,
            comm_iface as u16,
            &msg,
        )
        .await
        .is_err()
        {
            return Err(RndisError::Transfer);
        }
        let mut buf = [0u8; 64];
        for _ in 0..MAX_RESPONSE_POLLS {
            match c
                .control_in(
                    slot_id,
                    RT_DEV_TO_HOST_CLASS_IFACE,
                    REQ_GET_ENCAPSULATED_RESPONSE,
                    0,
                    comm_iface as u16,
                    &mut buf,
                )
                .await
            {
                Ok(n) if n >= 16 => {
                    let got = &buf[..n];
                    if let Ok((CMPLT_KEEPALIVE, _)) = message_prefix(got) {
                        if request_id(got).ok() == Some(req_id) {
                            return decode_keepalive_complete(got, req_id).map(|_| ());
                        }
                    }
                }
                Ok(_) => {}
                Err(_) => {}
            }
            narf_scheduler::yield_now().await;
        }
        Err(RndisError::Transfer)
    });
    outcome
}

/// Detach hook for a slot: tombstone every RNDIS record bound
/// to it and unregister its net iface. Pumps exit on the
/// tombstone; TX cookies for the index keep resolving to
/// `NotBound` instead of retargeting a later device (records
/// are never removed). Unknown slots no-op.
///
/// Tombstones are set under the registry lock and iface names
/// collected there, but the net unregister runs after the lock
/// is released — the net registry lock must never be taken
/// while the RNDIS registry lock is held (the NCM/ECM
/// collect-then-unregister pattern).
///
/// RX-mirror obligation (#789): RESOLVED as not owed here. The
/// mirror registry in `narf_drivers_net_core::publish` is noted
/// only by dual-published families' `rx_ring()` takes; this
/// family's pumps deliver via
/// `narf_net::iface::on_rx_frame_from` directly and never note,
/// and its `usb-rndis{N}` names live in a disjoint namespace
/// from the `eth%d` keys that can ever be noted — so no detach
/// path here can inherit a stale attach note, and no clear call
/// is owed. If this family ever dual-publishes, its detach
/// paths must call `publish::clear_rx_mirror_attached` for the
/// iface name alongside unregister.
///
/// Infallible bookkeeping, adapted to the [`UsbUnbindFn`]
/// contract with an unconditional `Ok(())` (#893: a hook
/// reports failure with `Err(())`, never by panicking).
pub fn detach_rndis_slot(controller: u8, slot_id: u8) -> Result<(), ()> {
    let ifaces: Vec<String> = {
        let mut g = RNDIS_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g
            .iter_mut()
            .filter(|d| d.controller == controller && d.slot_id == slot_id && !d.detached)
        {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
    Ok(())
}

/// Wholesale variant of [`detach_rndis_slot`] for controller
/// recovery (`attach::detach_all_bindings`): tombstone every
/// RNDIS binding on `controller` and unregister its net iface,
/// regardless of slot. Infallible and idempotent, same
/// pump-exit and never-remove reasoning as
/// [`detach_rndis_slot`], and the same #789 mirror verdict (no
/// clear call owed).
pub fn detach_all_rndis(controller: u8) {
    let ifaces: Vec<String> = {
        let mut g = RNDIS_DEVICES.lock();
        let mut names = Vec::new();
        for dev in g
            .iter_mut()
            .filter(|d| d.controller == controller && !d.detached)
        {
            dev.detached = true;
            dev.pump_running = false;
            names.push(dev.iface_name.clone());
        }
        names
    };
    for name in ifaces {
        let _ = narf_net::iface::unregister(&name);
    }
}

fn rndis_send_ctx(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    match send_frame(cookie as usize, frame) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

/// Register the RNDIS device at `idx` as a network interface
/// under `usb-rndis{idx}`, publishing the device-supplied
/// station address `mac`. Returns the assigned interface name.
fn register_rndis_iface(idx: usize, mac: [u8; 6]) -> String {
    let name = alloc::format!("usb-rndis{}", idx);
    narf_net::iface::register_with_context(&name, mac, idx as u64, rndis_send_ctx)
}

// ── RndisIface — logical per-device interface handle ───────────────

/// Logical handle to a bound RNDIS device exposed to the rest
/// of the kernel as a narf-net `NetIfaceEntry`-compatible face.
///
/// After [`try_bind_rndis_already_addressed`] succeeds, callers
/// can borrow a `RndisIface` via [`RndisIface::from_idx`] to
/// send or receive Ethernet frames without going through the
/// static trampoline used during bring-up.
#[derive(Copy, Clone, Debug)]
pub struct RndisIface {
    /// Index into [`RNDIS_DEVICES`].
    pub idx: usize,
    /// Station address read from the device at bind.
    pub mac: [u8; 6],
}

impl RndisIface {
    /// Construct from a bound-device index. Returns `None` if
    /// `idx` is out of range or the record is detached.
    pub fn from_idx(idx: usize) -> Option<Self> {
        let g = RNDIS_DEVICES.lock();
        let dev = g.get(idx).filter(|d| !d.detached)?;
        Some(Self { idx, mac: dev.mac })
    }

    /// Send `eth_frame` via the bound RNDIS device, wrapped in
    /// a single `PACKET_MSG` (see [`send_frame`]).
    pub fn send(&self, eth_frame: &[u8]) -> Result<usize, RndisError> {
        send_frame(self.idx, eth_frame)
    }

    /// Receive the next frames off the bulk-IN endpoint.
    /// `scratch` must be at least as large as the device's RX
    /// buffer (see [`rndis_rx_buf_len`]).
    pub fn recv<'a>(&self, scratch: &'a mut [u8]) -> Result<Vec<&'a [u8]>, RndisError> {
        recv_frames(self.idx, scratch)
    }

    /// Issue a KEEPALIVE on the control channel.
    pub fn keepalive(&self) -> Result<(), RndisError> {
        send_keepalive(self.idx)
    }
}

// ── Class-registry wiring ────────────────────────────────────────────

pub static RNDIS_MATCH: [crate::class_registry::UsbClassMatch; 1] = [
    // Class 2 (Comm), Subclass 2 (ACM), Protocol 0xFF (RNDIS).
    crate::class_registry::UsbClassMatch {
        vendor_id: 0,
        product_id: 0,
        class: Some(2),
        subclass: Some(2),
        protocol: Some(0xFF),
    },
];

pub fn probe(
    _device: alloc::sync::Arc<crate::device::USBDevice>,
    _match_interface: Option<(u8, u8)>,
) -> Result<(), crate::class_registry::UsbProbeError> {
    use core::fmt::Write;
    let _ = writeln!(narf_console::Writer, "  usb: RNDIS device bound!");
    Ok(())
}

pub fn register_initcalls() {
    // Mirror NCM/ECM: the probe is a claim marker (real binding
    // stays in the attach cascade), and the unbind hook adapts
    // infallible `detach_rndis_slot` to the fallible
    // `UsbUnbindFn` contract with an unconditional `Ok(())`
    // (#893: a hook reports failure with `Err(())`, never by
    // panicking).
    let _ = crate::class_registry::register_class_driver_with_unbind(
        "rndis",
        &RNDIS_MATCH,
        probe,
        detach_rndis_slot,
    );
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Modelled descriptors ─────────────────────────────────────────

    fn modelled_rndis_cfg() -> Vec<u8> {
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 0, 0, 2, 1, 0, 0x80, 0x32, // config (len patched below)
            // Comm interface 0, class 2 / subclass ACM / protocol RNDIS, 1 endpoint
            9, 4, 0, 0, 1, 0x02, 0x02, 0xFF, 0,
            // Header functional descriptor, CDC 1.2
            5, 0x24, 0x00, 0x20, 0x01,
            // Union { ctrl=0, sub=1 }
            5, 0x24, 0x06, 0, 1,
            // interrupt endpoint of the Comm interface
            7, 5, 0x83, 3, 8, 0, 8,
            // Data interface 1, alt 0, no endpoints
            9, 4, 1, 0, 0, 0x0A, 0, 0, 0,
            // Data interface 1, alt 1, bulk pair
            9, 4, 1, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        let mut v = cfg.to_vec();
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    /// Composite trap: Union names Data 1, but Data 2 appears
    /// first in the blob. Union-authoritative selection must
    /// pick Data 1's pair; a "last Data wins" walker picks 2.
    fn modelled_rndis_composite_cfg() -> Vec<u8> {
        #[rustfmt::skip]
        let cfg: &[u8] = &[
            9, 2, 0, 0, 3, 1, 0, 0x80, 0x32,
            9, 4, 0, 0, 1, 0x02, 0x02, 0xFF, 0,
            5, 0x24, 0x06, 0, 1, // Union { ctrl=0, sub=1 }
            // Data interface 2 first — must NOT win.
            9, 4, 2, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x82, 2, 64, 0, 0,
            7, 5, 0x03, 2, 64, 0, 0,
            // Data interface 1 second — Union-named, must win.
            9, 4, 1, 1, 2, 0x0A, 0, 0, 0,
            7, 5, 0x81, 2, 64, 0, 0,
            7, 5, 0x02, 2, 64, 0, 0,
        ];
        let mut v = cfg.to_vec();
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    // ── Scripted fake RNDIS device (spec-side model) ────────────────
    //
    // Answers the control exchange the way the RNDIS spec says a
    // device must: INITIALIZE_CMPLT, QUERY_CMPLT per OID, SET_CMPLT.
    // The fake is written from the spec message layouts
    // independently of the host-side encoders (it builds its
    // replies byte by byte), so a shared wrong assumption cannot
    // make host and fake agree while silicon disagrees.

    #[derive(Debug)]
    struct FakeRndisDevice {
        mac: [u8; 6],
        permanent_mac: [u8; 6],
        max_transfer_size: u32,
        max_packets_per_transfer: u32,
        packet_alignment_factor: u32,
        max_frame_size: u32,
        media_connected: bool,
        fail_initialize: bool,
        fail_current_address: bool,
        current_address_invalid: bool,
    }

    impl FakeRndisDevice {
        fn new() -> Self {
            Self {
                mac: [0x02, 0x00, 0x5E, 0x10, 0x20, 0x30],
                permanent_mac: [0x02, 0x00, 0x5E, 0x10, 0x20, 0x31],
                max_transfer_size: 16384,
                max_packets_per_transfer: 8,
                packet_alignment_factor: 3,
                max_frame_size: 1518,
                media_connected: true,
                fail_initialize: false,
                fail_current_address: false,
                current_address_invalid: false,
            }
        }

        fn handle(&self, req: &[u8]) -> Vec<u8> {
            let (msg_type, _) = match message_prefix(req) {
                Ok(p) => p,
                Err(_) => return Vec::new(),
            };
            let rid = request_id(req).unwrap_or(0);
            match msg_type {
                MSG_INITIALIZE => {
                    let mut out = alloc::vec![0u8; 52];
                    put_u32le(&mut out, 0, CMPLT_INITIALIZE);
                    put_u32le(&mut out, 4, 52);
                    put_u32le(&mut out, 8, rid);
                    put_u32le(
                        &mut out,
                        12,
                        if self.fail_initialize {
                            STATUS_FAILURE
                        } else {
                            STATUS_SUCCESS
                        },
                    );
                    put_u32le(&mut out, 16, 1); // major
                    put_u32le(&mut out, 20, 1); // minor (1.1 device, 1.0 host: compatible)
                    put_u32le(&mut out, 24, DF_CONNECTIONLESS);
                    put_u32le(&mut out, 28, MEDIUM_802_3);
                    put_u32le(&mut out, 32, self.max_packets_per_transfer);
                    put_u32le(&mut out, 36, self.max_transfer_size);
                    put_u32le(&mut out, 40, self.packet_alignment_factor);
                    out
                }
                MSG_QUERY => {
                    let oid = u32le(req, 12).unwrap_or(0);
                    match oid {
                        OID_802_3_CURRENT_ADDRESS => {
                            if self.fail_current_address {
                                return Self::query_failure(rid);
                            }
                            let mac = if self.current_address_invalid {
                                [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]
                            } else {
                                self.mac
                            };
                            Self::query_ok(rid, &mac)
                        }
                        OID_802_3_PERMANENT_ADDRESS => Self::query_ok(rid, &self.permanent_mac),
                        OID_GEN_MAXIMUM_FRAME_SIZE => {
                            Self::query_ok(rid, &self.max_frame_size.to_le_bytes())
                        }
                        OID_GEN_MEDIA_CONNECT_STATUS => {
                            let v: u32 = if self.media_connected { 1 } else { 0 };
                            Self::query_ok(rid, &v.to_le_bytes())
                        }
                        _ => Self::query_failure(rid),
                    }
                }
                MSG_SET => {
                    let mut out = alloc::vec![0u8; 16];
                    put_u32le(&mut out, 0, CMPLT_SET);
                    put_u32le(&mut out, 4, 16);
                    put_u32le(&mut out, 8, rid);
                    put_u32le(&mut out, 12, STATUS_SUCCESS);
                    out
                }
                MSG_KEEPALIVE => {
                    let mut out = alloc::vec![0u8; 16];
                    put_u32le(&mut out, 0, CMPLT_KEEPALIVE);
                    put_u32le(&mut out, 4, 16);
                    put_u32le(&mut out, 8, rid);
                    put_u32le(&mut out, 12, STATUS_SUCCESS);
                    out
                }
                MSG_RESET => {
                    let mut out = alloc::vec![0u8; 16];
                    put_u32le(&mut out, 0, CMPLT_RESET);
                    put_u32le(&mut out, 4, 16);
                    put_u32le(&mut out, 8, STATUS_SUCCESS);
                    put_u32le(&mut out, 12, 0);
                    out
                }
                _ => Vec::new(),
            }
        }

        fn query_ok(rid: u32, info: &[u8]) -> Vec<u8> {
            let mut out = alloc::vec![0u8; 24 + info.len()];
            put_u32le(&mut out, 0, CMPLT_QUERY);
            put_u32le(&mut out, 4, out.len() as u32);
            put_u32le(&mut out, 8, rid);
            put_u32le(&mut out, 12, STATUS_SUCCESS);
            put_u32le(&mut out, 16, info.len() as u32);
            put_u32le(&mut out, 20, 4);
            out[24..].copy_from_slice(info);
            out
        }

        fn query_failure(rid: u32) -> Vec<u8> {
            let mut out = alloc::vec![0u8; 24];
            put_u32le(&mut out, 0, CMPLT_QUERY);
            put_u32le(&mut out, 4, 24);
            put_u32le(&mut out, 8, rid);
            put_u32le(&mut out, 12, STATUS_NOT_SUPPORTED);
            put_u32le(&mut out, 16, 0);
            put_u32le(&mut out, 20, 0);
            out
        }
    }

    /// Drive a bring-up against the fake device, request by
    /// request, exactly as the async bind loop does over xHCI.
    fn drive_bringup(fake: &FakeRndisDevice) -> Result<RndisBringup, RndisError> {
        let mut bringup = RndisBringup::new(HOST_MAX_TRANSFER_SIZE);
        while !bringup.is_done() {
            let req = bringup.next_request().ok_or(RndisError::BadMessageType)?;
            let resp = fake.handle(&req);
            if resp.is_empty() {
                return Err(RndisError::Transfer);
            }
            bringup.handle_response(&resp)?;
        }
        Ok(bringup)
    }

    // ── Message-layer fixtures ─────────────────────────────────────

    fn smoke_rndis_initialize_msg_byte_exact() -> TestResult {
        let msg = encode_initialize_msg(7, 16384);
        let expected: [u8; 24] = [
            0x02, 0x00, 0x00, 0x00, // INITIALIZE
            0x18, 0x00, 0x00, 0x00, // length 24
            0x07, 0x00, 0x00, 0x00, // request id 7
            0x01, 0x00, 0x00, 0x00, // major 1
            0x00, 0x00, 0x00, 0x00, // minor 0
            0x00, 0x40, 0x00, 0x00, // max transfer 16384
        ];
        if msg != expected {
            return TestResult::Fail("INITIALIZE_MSG bytes differ from spec layout");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_initialize_msg_byte_exact);

    fn smoke_rndis_initialize_complete_decode() -> TestResult {
        // Spec-shaped 52-byte INITIALIZE_CMPLT, built byte by byte.
        let mut buf = [0u8; 52];
        put_u32le(&mut buf, 0, CMPLT_INITIALIZE);
        put_u32le(&mut buf, 4, 52);
        put_u32le(&mut buf, 8, 7);
        put_u32le(&mut buf, 12, STATUS_SUCCESS);
        put_u32le(&mut buf, 16, 1);
        put_u32le(&mut buf, 20, 0);
        put_u32le(&mut buf, 24, DF_CONNECTIONLESS);
        put_u32le(&mut buf, 28, MEDIUM_802_3);
        put_u32le(&mut buf, 32, 8);
        put_u32le(&mut buf, 36, 16384);
        put_u32le(&mut buf, 40, 3);
        let init = match InitializeComplete::decode(&buf, 7) {
            Ok(i) => i,
            Err(_) => return TestResult::Fail("valid INITIALIZE_CMPLT rejected"),
        };
        if init.device_flags != DF_CONNECTIONLESS
            || init.medium != MEDIUM_802_3
            || init.max_packets_per_transfer != 8
            || init.max_transfer_size != 16384
            || init.packet_alignment_factor != 3
        {
            return TestResult::Fail("INITIALIZE_CMPLT fields decoded wrong");
        }
        // Wrong request id must not match.
        if InitializeComplete::decode(&buf, 8).is_ok() {
            return TestResult::Fail("INITIALIZE_CMPLT with wrong request id accepted");
        }
        // Failure status must surface as an error, never as a
        // negotiated device.
        put_u32le(&mut buf, 12, STATUS_FAILURE);
        if !matches!(
            InitializeComplete::decode(&buf, 7),
            Err(RndisError::DeviceStatus(STATUS_FAILURE))
        ) {
            return TestResult::Fail("failed INITIALIZE_CMPLT not reported as DeviceStatus");
        }
        // Truncated buffer rejected.
        if InitializeComplete::decode(&buf[..40], 7).is_ok() {
            return TestResult::Fail("truncated INITIALIZE_CMPLT accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_initialize_complete_decode);

    fn smoke_rndis_query_set_encode_decode() -> TestResult {
        // QUERY with a 4-byte input: InformationBufferOffset must
        // be 12 (measured from its own field at byte 16).
        let q = encode_query_msg(3, OID_GEN_CURRENT_PACKET_FILTER, &[0x0F, 0, 0, 0]);
        if q.len() != 32
            || u32le(&q, 0) != Some(MSG_QUERY)
            || u32le(&q, 12) != Some(OID_GEN_CURRENT_PACKET_FILTER)
            || u32le(&q, 16) != Some(4)
            || u32le(&q, 20) != Some(12)
        {
            return TestResult::Fail("QUERY_MSG offset/length fields wrong");
        }
        // QUERY with no input: offset 0.
        let q0 = encode_query_msg(3, OID_802_3_CURRENT_ADDRESS, &[]);
        if u32le(&q0, 20) != Some(0) || q0.len() != 28 {
            return TestResult::Fail("QUERY_MSG without input must carry offset 0");
        }
        // SET with a 4-byte value: InformationBufferOffset must
        // be 8 (measured from its own field at byte 20).
        let s = encode_set_msg(4, OID_GEN_CURRENT_PACKET_FILTER, &[0x0F, 0, 0, 0]);
        if s.len() != 32 || u32le(&s, 20) != Some(8) || u32le(&s, 16) != Some(4) {
            return TestResult::Fail("SET_MSG offset fields wrong");
        }
        // QUERY_CMPLT carrying a 6-byte MAC at offset 4
        // (info starts at 20 + 4 = 24).
        let mac: [u8; 6] = [0x02, 0x00, 0x5E, 0x10, 0x20, 0x30];
        let resp = FakeRndisDevice::query_ok(3, &mac);
        let qc = match QueryComplete::decode(&resp, 3) {
            Ok(q) => q,
            Err(_) => return TestResult::Fail("valid QUERY_CMPLT rejected"),
        };
        if qc.info != mac {
            return TestResult::Fail("QUERY_CMPLT info buffer mislocated");
        }
        // Tampered info length (claims more than the message
        // holds) must fail, not alias past the message.
        let mut bad = resp.clone();
        put_u32le(&mut bad, 16, 600);
        if QueryComplete::decode(&bad, 3).is_ok() {
            return TestResult::Fail("QUERY_CMPLT with overrunning info length accepted");
        }
        // SET_CMPLT decode + wrong-request rejection.
        let mut set_ok = [0u8; 16];
        put_u32le(&mut set_ok, 0, CMPLT_SET);
        put_u32le(&mut set_ok, 4, 16);
        put_u32le(&mut set_ok, 8, 4);
        put_u32le(&mut set_ok, 12, STATUS_SUCCESS);
        if decode_set_complete(&set_ok, 4) != Ok(4) {
            return TestResult::Fail("valid SET_CMPLT rejected");
        }
        if decode_set_complete(&set_ok, 5).is_ok() {
            return TestResult::Fail("SET_CMPLT with wrong request id accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_query_set_encode_decode);

    fn smoke_rndis_packet_msg_byte_exact() -> TestResult {
        let frame: [u8; 14] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst
            0x02, 0x00, 0x5E, 0x10, 0x20, 0x30, // src
            0x08, 0x00, // EtherType IPv4
        ];
        let pkt = encode_packet_msg(&frame);
        if pkt.len() != 58
            || u32le(&pkt, 0) != Some(MSG_PACKET)
            || u32le(&pkt, 4) != Some(58)
            || u32le(&pkt, 8) != Some(36)
            || u32le(&pkt, 12) != Some(14)
        {
            return TestResult::Fail("PACKET_MSG header fields wrong");
        }
        // DataOffset 36 is message-relative-8: payload at 44.
        if pkt[44..] != frame {
            return TestResult::Fail("PACKET_MSG payload not at 8 + DataOffset");
        }
        let (decoded, msg_len) = match decode_packet_msg(&pkt) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("own PACKET_MSG rejected on decode"),
        };
        if decoded != frame || msg_len != 58 {
            return TestResult::Fail("PACKET_MSG round-trip wrong");
        }
        // A DataOffset that runs the payload past the message
        // must fail, not alias outside it.
        let mut bad = pkt.clone();
        put_u32le(&mut bad, 8, 100);
        if decode_packet_msg(&bad).is_ok() {
            return TestResult::Fail("PACKET_MSG with overrunning DataOffset accepted");
        }
        // Wrong message type rejected.
        put_u32le(&mut bad, 0, MSG_INITIALIZE);
        if decode_packet_msg(&bad).is_ok() {
            return TestResult::Fail("non-PACKET message accepted as PACKET_MSG");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_packet_msg_byte_exact);

    fn smoke_rndis_multipacket_walk() -> TestResult {
        // Two PACKET_MSGs in one transfer, the second starting
        // on an 8-byte boundary (first message padded from 58
        // to 64 bytes: MessageLength includes the padding).
        // A walker that returns only the first element, or that
        // advances by header+payload instead of MessageLength,
        // fails this fixture — a single-packet fixture would not
        // catch it.
        let frame_a = [0xAAu8; 14];
        let frame_b = [0xBBu8; 20];
        let mut pkt_a = encode_packet_msg(&frame_a);
        let pad = (8 - (pkt_a.len() % 8)) % 8;
        let msg_len_a = pkt_a.len() + pad;
        put_u32le(&mut pkt_a, 4, msg_len_a as u32);
        pkt_a.resize(msg_len_a, 0);
        let pkt_b = encode_packet_msg(&frame_b);
        let mut buf = pkt_a.clone();
        buf.extend_from_slice(&pkt_b);
        let mut frames: Vec<&[u8]> = Vec::new();
        if !parse_multipacket(&buf, &mut frames) {
            return TestResult::Fail("multipacket walk failed on valid buffer");
        }
        if frames.len() != 2 || frames[0] != frame_a || frames[1] != frame_b {
            return TestResult::Fail("multipacket walk returned wrong frames");
        }
        // A buffer truncated mid-second-message must fail the
        // walk (not silently return the first frame as clean).
        let mut short = buf.clone();
        short.truncate(buf.len() - 4);
        let mut frames2: Vec<&[u8]> = Vec::new();
        if parse_multipacket(&short, &mut frames2) {
            return TestResult::Fail("truncated multipacket buffer walked clean");
        }
        if frames2.len() != 1 {
            return TestResult::Fail("truncated walk must keep the first good frame");
        }
        // Empty buffer: zero frames, clean.
        let mut frames3: Vec<&[u8]> = Vec::new();
        if !parse_multipacket(&[], &mut frames3) || !frames3.is_empty() {
            return TestResult::Fail("empty multipacket buffer mishandled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_multipacket_walk);

    fn smoke_rndis_reset_keepalive_halt_indicate() -> TestResult {
        let rst = encode_reset_msg();
        if rst.len() != 12 || u32le(&rst, 0) != Some(MSG_RESET) {
            return TestResult::Fail("RESET_MSG wrong");
        }
        let mut rst_cplt = [0u8; 16];
        put_u32le(&mut rst_cplt, 0, CMPLT_RESET);
        put_u32le(&mut rst_cplt, 4, 16);
        put_u32le(&mut rst_cplt, 8, STATUS_SUCCESS);
        put_u32le(&mut rst_cplt, 12, 1);
        if decode_reset_complete(&rst_cplt) != Ok(true) {
            return TestResult::Fail("RESET_CMPLT with AddressingReset=1 rejected");
        }
        put_u32le(&mut rst_cplt, 8, STATUS_FAILURE);
        if !matches!(
            decode_reset_complete(&rst_cplt),
            Err(RndisError::DeviceStatus(STATUS_FAILURE))
        ) {
            return TestResult::Fail("failed RESET_CMPLT not reported");
        }
        let ka = encode_keepalive_msg(9);
        if ka.len() != 12 || u32le(&ka, 8) != Some(9) {
            return TestResult::Fail("KEEPALIVE_MSG wrong");
        }
        let mut ka_cplt = [0u8; 16];
        put_u32le(&mut ka_cplt, 0, CMPLT_KEEPALIVE);
        put_u32le(&mut ka_cplt, 4, 16);
        put_u32le(&mut ka_cplt, 8, 9);
        put_u32le(&mut ka_cplt, 12, STATUS_SUCCESS);
        if decode_keepalive_complete(&ka_cplt, 9) != Ok(9) {
            return TestResult::Fail("valid KEEPALIVE_CMPLT rejected");
        }
        let halt = encode_halt_msg(11);
        if halt.len() != 12 || u32le(&halt, 0) != Some(MSG_HALT) || u32le(&halt, 8) != Some(11) {
            return TestResult::Fail("HALT_MSG wrong");
        }
        // INDICATE_STATUS: MEDIA_CONNECT with an empty status buffer.
        let mut ind = [0u8; 32];
        put_u32le(&mut ind, 0, MSG_INDICATE_STATUS);
        put_u32le(&mut ind, 4, 32);
        put_u32le(&mut ind, 8, STATUS_MEDIA_CONNECT);
        put_u32le(&mut ind, 12, 0);
        put_u32le(&mut ind, 16, 0);
        let decoded = match IndicateStatus::decode(&ind) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("valid INDICATE_STATUS rejected"),
        };
        if !decoded.is_connect() || decoded.is_disconnect() {
            return TestResult::Fail("MEDIA_CONNECT indication misdecoded");
        }
        put_u32le(&mut ind, 8, STATUS_MEDIA_DISCONNECT);
        let decoded = match IndicateStatus::decode(&ind) {
            Ok(d) => d,
            Err(_) => return TestResult::Fail("disconnect INDICATE_STATUS rejected"),
        };
        if !decoded.is_disconnect() {
            return TestResult::Fail("MEDIA_DISCONNECT indication misdecoded");
        }
        // Truncated indication rejected.
        if IndicateStatus::decode(&ind[..16]).is_ok() {
            return TestResult::Fail("truncated INDICATE_STATUS accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/rndis",
        smoke_rndis_reset_keepalive_halt_indicate
    );

    fn smoke_rndis_packet_filter() -> TestResult {
        let f = PacketFilter::NORMAL;
        let v = f.encode();
        if v != (FILTER_DIRECTED | FILTER_MULTICAST | FILTER_BROADCAST) {
            return TestResult::Fail("NORMAL filter bitmap wrong");
        }
        if PacketFilter::decode(v) != f {
            return TestResult::Fail("filter round-trip wrong");
        }
        if PacketFilter::decode(0) != PacketFilter::default() {
            return TestResult::Fail("zero filter must decode to all-false");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_packet_filter);

    fn smoke_rndis_notification_decode() -> TestResult {
        // NETWORK_CONNECTION up.
        let pkt: [u8; 8] = [0xA1, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        if RndisNotification::decode(&pkt) != Ok(RndisNotification::NetworkConnection { up: true })
        {
            return TestResult::Fail("NETWORK_CONNECTION up misdecoded");
        }
        // RESPONSE_AVAILABLE.
        let pkt: [u8; 8] = [0xA1, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        if RndisNotification::decode(&pkt) != Ok(RndisNotification::ResponseAvailable) {
            return TestResult::Fail("RESPONSE_AVAILABLE misdecoded");
        }
        // CONNECTION_SPEED_CHANGE, 8-byte payload.
        let mut pkt = [0u8; 16];
        pkt[0] = 0xA1;
        pkt[1] = 0x0A;
        pkt[6] = 8;
        put_u32le(&mut pkt, 8, 100_000_000);
        put_u32le(&mut pkt, 12, 50_000_000);
        if RndisNotification::decode(&pkt)
            != Ok(RndisNotification::ConnectionSpeedChange {
                downlink_bps: 100_000_000,
                uplink_bps: 50_000_000,
            })
        {
            return TestResult::Fail("CONNECTION_SPEED_CHANGE misdecoded");
        }
        // Short packet rejected.
        if RndisNotification::decode(&pkt[..4]).is_ok() {
            return TestResult::Fail("short notification accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_notification_decode);

    // ── Finder fixtures ────────────────────────────────────────────

    fn smoke_rndis_comm_interface_finder() -> TestResult {
        let cfg = modelled_rndis_cfg();
        if find_rndis_comm_interface(&cfg) != Some(0) {
            return TestResult::Fail("RNDIS comm interface not found");
        }
        // A real modem (protocol 0x01) must NOT match the RNDIS finder.
        let mut acm_cfg = cfg.clone();
        acm_cfg[9 + 7] = 0x01;
        if find_rndis_comm_interface(&acm_cfg).is_some() {
            return TestResult::Fail("ACM modem must not match RNDIS finder");
        }
        // NCM comm (subclass 0x0D) must NOT match either.
        let mut ncm_cfg = cfg.clone();
        ncm_cfg[9 + 6] = 0x0D;
        ncm_cfg[9 + 7] = 0x00;
        if find_rndis_comm_interface(&ncm_cfg).is_some() {
            return TestResult::Fail("NCM comm must not match RNDIS finder");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_comm_interface_finder);

    fn smoke_rndis_bulk_endpoints_finder() -> TestResult {
        let cfg = modelled_rndis_cfg();
        let found = match find_rndis_bulk_endpoints(&cfg, 0) {
            Some(f) => f,
            None => return TestResult::Fail("RNDIS bulk pair not found"),
        };
        if found.0 != 1 || found.1.ep_addr != 0x81 || found.2.ep_addr != 0x02 {
            return TestResult::Fail("RNDIS bulk pair endpoints wrong");
        }
        // Composite trap: Union names Data 1; Data 2 first must not win.
        let composite = modelled_rndis_composite_cfg();
        let found = match find_rndis_bulk_endpoints(&composite, 0) {
            Some(f) => f,
            None => return TestResult::Fail("composite RNDIS bulk pair not found"),
        };
        if found.0 != 1 || found.1.ep_addr != 0x81 || found.2.ep_addr != 0x02 {
            return TestResult::Fail("Union-named Data interface must win the composite trap");
        }
        // Alt setting: Data 1 alt 1 carries the bulk pair.
        if find_rndis_data_alt_setting(&cfg) != Some((1, 1)) {
            return TestResult::Fail("RNDIS data alt setting not found");
        }
        // Notification endpoint on the Comm interface.
        let notif = match find_rndis_notif_endpoint(&cfg, 0) {
            Some(n) => n,
            None => return TestResult::Fail("RNDIS notification endpoint not found"),
        };
        if notif.ep_addr != 0x83 {
            return TestResult::Fail("RNDIS notification endpoint address wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_bulk_endpoints_finder);

    // ── End-to-end bring-up against the scripted fake ──────────────

    fn smoke_rndis_bringup_end_to_end() -> TestResult {
        let fake = FakeRndisDevice::new();
        let bringup = match drive_bringup(&fake) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("bring-up against spec fake failed"),
        };
        if !bringup.is_done() || bringup.state() != RndisState::DataInitialized {
            return TestResult::Fail("bring-up did not reach data-initialized");
        }
        if bringup.mac() != Some(fake.mac) {
            return TestResult::Fail("bring-up MAC differs from fake device MAC");
        }
        let n = match bringup.negotiated() {
            Some(n) => n,
            None => return TestResult::Fail("bring-up has no negotiated parameters"),
        };
        if n.medium != MEDIUM_802_3
            || n.device_flags != DF_CONNECTIONLESS
            || n.max_packets_per_transfer != fake.max_packets_per_transfer
            || n.max_transfer_size != fake.max_transfer_size
            || n.packet_alignment_factor != fake.packet_alignment_factor
            || n.max_frame_size != fake.max_frame_size
            || n.media_connected != Some(true)
        {
            return TestResult::Fail("negotiated parameters differ from fake device");
        }
        // The first request the machine emits must be the
        // byte-exact INITIALIZE_MSG offering the host buffer.
        let mut first = RndisBringup::new(HOST_MAX_TRANSFER_SIZE);
        let req = match first.next_request() {
            Some(r) => r,
            None => return TestResult::Fail("bring-up emitted no first request"),
        };
        if req != encode_initialize_msg(1, HOST_MAX_TRANSFER_SIZE).to_vec() {
            return TestResult::Fail("first bring-up request is not INITIALIZE_MSG");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_bringup_end_to_end);

    fn smoke_rndis_bringup_failed_initialize() -> TestResult {
        let mut fake = FakeRndisDevice::new();
        fake.fail_initialize = true;
        if drive_bringup(&fake).is_ok() {
            return TestResult::Fail("bring-up accepted a failed INITIALIZE");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_bringup_failed_initialize);

    fn smoke_rndis_bringup_address_fallback() -> TestResult {
        // Current-address query fails: the machine must fall back
        // to the permanent address and still complete.
        let mut fake = FakeRndisDevice::new();
        fake.fail_current_address = true;
        let bringup = match drive_bringup(&fake) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("bring-up failed instead of falling back"),
        };
        if bringup.mac() != Some(fake.permanent_mac) {
            return TestResult::Fail("bring-up did not fall back to permanent address");
        }
        // Current address returns a multicast address (invalid):
        // same fallback must happen.
        let mut fake = FakeRndisDevice::new();
        fake.current_address_invalid = true;
        let bringup = match drive_bringup(&fake) {
            Ok(b) => b,
            Err(_) => {
                return TestResult::Fail("bring-up failed on invalid current address");
            }
        };
        if bringup.mac() != Some(fake.permanent_mac) {
            return TestResult::Fail("invalid current address did not fall back");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_bringup_address_fallback);

    fn smoke_rndis_bringup_truncated_response() -> TestResult {
        // A device that answers INITIALIZE with a truncated
        // completion must fail bring-up, not negotiate garbage.
        #[derive(Debug)]
        struct TruncatingFake;
        impl TruncatingFake {
            fn handle(&self, req: &[u8]) -> Vec<u8> {
                let (msg_type, _) = match message_prefix(req) {
                    Ok(p) => p,
                    Err(_) => return Vec::new(),
                };
                if msg_type == MSG_INITIALIZE {
                    alloc::vec![0x02, 0x00, 0x00, 0x80, 0x34, 0x00, 0x00, 0x00]
                } else {
                    Vec::new()
                }
            }
        }
        let fake = TruncatingFake;
        let mut bringup = RndisBringup::new(HOST_MAX_TRANSFER_SIZE);
        let mut failed = false;
        while !bringup.is_done() {
            let req = match bringup.next_request() {
                Some(r) => r,
                None => break,
            };
            let resp = fake.handle(&req);
            if resp.is_empty() || bringup.handle_response(&resp).is_err() {
                failed = true;
                break;
            }
        }
        if !failed {
            return TestResult::Fail("truncated INITIALIZE_CMPLT accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_bringup_truncated_response);

    fn smoke_rndis_tx_frame_cap() -> TestResult {
        let frame = [0u8; 1518];
        if rndis_tx_frame(&frame, 1518).is_err() {
            return TestResult::Fail("max-size frame refused");
        }
        let oversize = [0u8; 1519];
        if rndis_tx_frame(&oversize, 1518).is_ok() {
            return TestResult::Fail("oversize frame accepted instead of refused");
        }
        let pkt = match rndis_tx_frame(&frame, 1518) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("TX frame build failed"),
        };
        if pkt.len() != 44 + 1518 {
            return TestResult::Fail("TX PACKET_MSG length wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/rndis", smoke_rndis_tx_frame_cap);
}
