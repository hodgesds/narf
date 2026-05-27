//! HTC (Host Target Communication) — ath10k's framing layer.
//!
//! HTC sits between the Copy Engines and WMI/HTT. Every message the
//! host sends to / receives from the firmware is wrapped in an 8-byte
//! HTC header that identifies the *endpoint* (service-id-bound CE
//! pair) and the payload length. The handshake at boot:
//!
//!   1. Host sets `FW_INDICATOR = HOST_READY` so the firmware knows
//!      it can use CE0/CE1.
//!   2. Host polls CE1 (RX) for an `HTC_READY` message — the
//!      firmware sends it once it's done with self-init.
//!   3. Host sends `CONNECT_SERVICE` messages over CE0 (TX) for each
//!      service it wants (WMI_CONTROL, HTT_DATA_MSG, ...). Each one
//!      returns a `CONNECT_SERVICE_RESPONSE` over CE1.
//!   4. Host sends `SETUP_COMPLETE`. From here on out CE2..CE5 carry
//!      WMI events / WMI cmds / HTT TX / HTT RX.
//!
//! ## Stage 2 scope (this commit)
//!
//! - `HtcHdr` 8-byte header with packed accessors.
//! - `MessageId` enum mirroring `enum ath10k_ath10k_htc_msg_id`.
//! - `ServiceId` constants mirroring `enum ath10k_htc_svc_id`.
//! - `encode_htc_hdr` / `decode_htc_hdr` round-trip helpers.
//! - `build_connect_service` / `parse_connect_service_response`.
//! - `build_setup_complete`.
//! - `HandshakeError` enum surfacing the "firmware required" boundary.
//!
//! Out of scope (Stage 3 — needs firmware blob + live CE rings):
//!   - The actual ALIVE-style poll for HTC_READY.
//!   - Driving the CE pipes.
//!   - Lookahead processing on bundled RX.
//!
//! ## References
//!
//! - `drivers/net/wireless/ath/ath10k/htc.h` — header layout, enums.
//! - `drivers/net/wireless/ath/ath10k/htc.c::ath10k_htc_wait_target`,
//!   `ath10k_htc_connect_service`, `ath10k_htc_send_complete_check`.

#![allow(dead_code)]

use core::convert::TryInto;

// ── Header layout ──────────────────────────────────────────────────
//
// `htc.h::struct ath10k_htc_hdr` — 8 bytes, packed, 4-byte aligned:
//
//   u8 eid;              // endpoint id (which CE channel)
//   u8 flags;            // tx/rx flags + bundle count
//   __le16 len;          // payload length (excl. header)
//   union {
//       u8 trailer_len;  // RX
//       u8 control_byte0;
//   };
//   union {
//       u8 seq_no;       // TX
//       u8 control_byte1;
//   };
//   __le16 pad_len;      // 4-byte alignment padding count

/// HTC header — packed exactly as the firmware expects.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct HtcHdr {
    /// Endpoint id (which service-bound CE channel).
    pub eid: u8,
    /// `ATH10K_HTC_FLAG_*`.
    pub flags: u8,
    /// Payload length, excluding header.
    pub len: u16,
    /// Control byte 0 (TX: trailer-len in some sub-types).
    pub control_byte0: u8,
    /// Control byte 1 (TX: seq_no).
    pub control_byte1: u8,
    /// Padding count to 4-byte alignment.
    pub pad_len: u16,
}

/// Wire-size of the HTC header — checked at compile time.
pub const HTC_HDR_LEN: usize = 8;
const _: () = assert!(core::mem::size_of::<HtcHdr>() == HTC_HDR_LEN);

impl HtcHdr {
    /// Build a TX header. `eid` identifies the target endpoint;
    /// `len` is the payload length; `seq_no` is the sequence
    /// number Linux tracks per-endpoint.
    pub const fn tx(eid: u8, len: u16, seq_no: u8) -> Self {
        Self {
            eid,
            flags: 0,
            len,
            control_byte0: 0,
            control_byte1: seq_no,
            pad_len: 0,
        }
    }
}

/// Encode an HTC header into the first 8 bytes of `out`. Returns
/// `Err(())` if `out.len() < HTC_HDR_LEN`. Layout matches
/// `htc.h::struct ath10k_htc_hdr` byte-for-byte: little-endian
/// `len` + `pad_len`, single-byte `eid`/`flags`/control bytes.
pub fn encode_htc_hdr(hdr: &HtcHdr, out: &mut [u8]) -> Result<(), ()> {
    if out.len() < HTC_HDR_LEN {
        return Err(());
    }
    out[0] = hdr.eid;
    out[1] = hdr.flags;
    out[2..4].copy_from_slice(&hdr.len.to_le_bytes());
    out[4] = hdr.control_byte0;
    out[5] = hdr.control_byte1;
    out[6..8].copy_from_slice(&hdr.pad_len.to_le_bytes());
    Ok(())
}

/// Decode an HTC header from the first 8 bytes of `bytes`.
pub fn decode_htc_hdr(bytes: &[u8]) -> Result<HtcHdr, ()> {
    if bytes.len() < HTC_HDR_LEN {
        return Err(());
    }
    Ok(HtcHdr {
        eid: bytes[0],
        flags: bytes[1],
        len: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        control_byte0: bytes[4],
        control_byte1: bytes[5],
        pad_len: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
    })
}

// ── Message IDs (the 2-byte body header following the HTC hdr) ─────
//
// `htc.h::enum ath10k_ath10k_htc_msg_id`.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MessageId {
    Ready = 1,
    ConnectService = 2,
    ConnectServiceResponse = 3,
    SetupComplete = 4,
    SetupCompleteEx = 5,
    SendSuspendComplete = 6,
}

impl MessageId {
    pub fn from_raw(v: u16) -> Option<Self> {
        Some(match v {
            1 => MessageId::Ready,
            2 => MessageId::ConnectService,
            3 => MessageId::ConnectServiceResponse,
            4 => MessageId::SetupComplete,
            5 => MessageId::SetupCompleteEx,
            6 => MessageId::SendSuspendComplete,
            _ => return None,
        })
    }
}

// ── Service IDs ────────────────────────────────────────────────────
//
// `htc.h::enum ath10k_htc_svc_id` packs `(group, index)` into 16 bits:
//   svc_id = (group << 8) | index
//
// Linux's macro: `#define SVC(grp, idx) (((grp) << 8) | (idx))`.

/// Build a service id from `(group, index)`.
pub const fn svc(group: u8, index: u8) -> u16 {
    ((group as u16) << 8) | (index as u16)
}

/// Service groups.
pub mod svc_group {
    pub const RSVD: u8 = 0;
    pub const WMI: u8 = 1;
    pub const NMI: u8 = 2;
    pub const HTT: u8 = 3;
    pub const TEST: u8 = 254;
}

pub const SVC_ID_RSVD_CTRL: u16 = svc(svc_group::RSVD, 1);
pub const SVC_ID_WMI_CONTROL: u16 = svc(svc_group::WMI, 0);
pub const SVC_ID_WMI_DATA_BE: u16 = svc(svc_group::WMI, 1);
pub const SVC_ID_WMI_DATA_BK: u16 = svc(svc_group::WMI, 2);
pub const SVC_ID_WMI_DATA_VI: u16 = svc(svc_group::WMI, 3);
pub const SVC_ID_WMI_DATA_VO: u16 = svc(svc_group::WMI, 4);
pub const SVC_ID_HTT_DATA_MSG: u16 = svc(svc_group::HTT, 0);
pub const SVC_ID_HTT_DATA2_MSG: u16 = svc(svc_group::HTT, 1);
pub const SVC_ID_HTT_DATA3_MSG: u16 = svc(svc_group::HTT, 2);

// ── ConnectService / SetupComplete builders ────────────────────────

/// Build a `CONNECT_SERVICE` message body (excluding HTC header).
/// `htc.h::struct ath10k_htc_conn_svc`:
///   __le16 service_id; __le16 flags; u8 pad0; u8 pad1;
///
/// Plus the 2-byte message-id prefix.  Total body = 8 bytes.
pub const CONNECT_SERVICE_BODY_LEN: usize = 8;

pub fn build_connect_service(service_id: u16, flags: u16) -> [u8; CONNECT_SERVICE_BODY_LEN] {
    let mut buf = [0u8; CONNECT_SERVICE_BODY_LEN];
    buf[0..2].copy_from_slice(&(MessageId::ConnectService as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&service_id.to_le_bytes());
    buf[4..6].copy_from_slice(&flags.to_le_bytes());
    buf
}

/// Parsed response from a `CONNECT_SERVICE` exchange.
/// `htc.h::struct ath10k_htc_conn_svc_response`:
///   __le16 service_id; u8 status; u8 eid; __le16 max_msg_size;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ConnectServiceResponse {
    pub service_id: u16,
    pub status: ConnectStatus,
    pub endpoint_id: u8,
    pub max_msg_size: u16,
}

/// `htc.h::enum ath10k_htc_conn_svc_status`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectStatus {
    Success = 0,
    NotFound = 1,
    Failed = 2,
    NoResources = 3,
    NoMoreEp = 4,
    Unknown,
}

impl ConnectStatus {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => ConnectStatus::Success,
            1 => ConnectStatus::NotFound,
            2 => ConnectStatus::Failed,
            3 => ConnectStatus::NoResources,
            4 => ConnectStatus::NoMoreEp,
            _ => ConnectStatus::Unknown,
        }
    }
}

/// Parse a `CONNECT_SERVICE_RESPONSE` body. The 2-byte message-id
/// prefix is expected to be at `bytes[0..2]` and equal to
/// `ConnectServiceResponse`.
pub fn parse_connect_service_response(bytes: &[u8]) -> Result<ConnectServiceResponse, ()> {
    if bytes.len() < 8 {
        return Err(());
    }
    let msg_id = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    if MessageId::from_raw(msg_id) != Some(MessageId::ConnectServiceResponse) {
        return Err(());
    }
    Ok(ConnectServiceResponse {
        service_id: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        status: ConnectStatus::from_raw(bytes[4]),
        endpoint_id: bytes[5],
        max_msg_size: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
    })
}

/// Build the trailing `SETUP_COMPLETE` body. Linux uses the
/// "extended" variant (`ath10k_htc_setup_complete_extended`,
/// 8 bytes) on every modern part — encode that.
pub const SETUP_COMPLETE_BODY_LEN: usize = 8;

pub fn build_setup_complete(rx_bundle_en: bool) -> [u8; SETUP_COMPLETE_BODY_LEN] {
    let mut buf = [0u8; SETUP_COMPLETE_BODY_LEN];
    buf[0..2].copy_from_slice(&(MessageId::SetupCompleteEx as u16).to_le_bytes());
    // bytes[2..4] = pad0, pad1
    let flags: u32 = if rx_bundle_en { 1 } else { 0 };
    buf[4..8].copy_from_slice(&flags.to_le_bytes());
    buf
}

// ── Handshake error type ───────────────────────────────────────────

/// What can go wrong driving the HTC handshake. Stage 2 only
/// surfaces the structural errors; the production path uses the
/// same enum with a real `FirmwareUnavailable` variant returned
/// at the firmware-load boundary.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// HTC_READY didn't arrive within the deadline.
    Timeout,
    /// Received message wasn't HTC_READY when it was expected.
    UnexpectedMessage(u16),
    /// CONNECT_SERVICE returned a non-`Success` status.
    ConnectFailed(ConnectStatus),
    /// Firmware blob not registered with `narf_firmware`.
    /// Returned by the Stage-2 driver — Stage 3 will replace this
    /// with the real load path.
    NotImplemented,
}

/// Stage 2 handshake entry. There is no firmware blob shipped with
/// NARF yet, so this returns `NotImplemented` immediately. The
/// driver wiring is here so the Stage-2 unit tests can verify the
/// frame-builder/parser code links cleanly.
pub fn run_handshake() -> Result<(), HandshakeError> {
    Err(HandshakeError::NotImplemented)
}
