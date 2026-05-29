//! WMI (Wireless Management Interface) — ath10k's firmware command set.
//!
//! After HTC connects the `WMI_CONTROL` service, the host talks to
//! firmware over CE3 (TX commands) / CE2 (RX events) using WMI
//! messages. Each message starts with a 4-byte header:
//!
//!   ┌─────────────────┬────────────────────┐
//!   │ cmd_id (24 bit) │ plt_priv (8 bit)   │
//!   └─────────────────┴────────────────────┘
//!
//! (`wmi.h::struct wmi_cmd_hdr`; the platform-private byte is
//! firmware-internal and the host writes 0.)
//!
//! ## Stage 2 scope (this commit)
//!
//! - `WmiCmdHdr` packed header + encode/decode helpers.
//! - Command-id enum for the bring-up commands every firmware
//!   accepts (`INIT`, `PDEV_SET_PARAM`, `START_SCAN`, etc.).
//! - `Encoder`/`Decoder` shape so Stage-3 callers can build WMI
//!   command bodies without reaching for raw bytes.
//! - `wmi_send` stub returning `Err(NotImplemented)` — there's no
//!   firmware blob shipped yet, so we don't have a real ALIVE-style
//!   handshake to dispatch through.
//!
//! ## References
//!
//! - `drivers/net/wireless/ath/ath10k/wmi.h` — `wmi_cmd_hdr`, the
//!   per-cmd-id enum, payload structs.
//! - `drivers/net/wireless/ath/ath10k/wmi-tlv.h` — TLV-encoded WMI
//!   for the QCA6174 / QCA9377 family (newer firmware).
//! - `drivers/net/wireless/ath/ath10k/wmi.c::ath10k_wmi_cmd_send`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;

// ── Command header layout ──────────────────────────────────────────

/// 4-byte WMI command header.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct WmiCmdHdr {
    /// Encoded as `(plt_priv << 24) | (cmd_id & 0x00FF_FFFF)`.
    pub cmd_id_and_priv: u32,
}

pub const WMI_HDR_LEN: usize = 4;
const _: () = assert!(core::mem::size_of::<WmiCmdHdr>() == WMI_HDR_LEN);

/// `wmi.h::WMI_CMD_HDR_CMD_ID_MASK`.
pub const WMI_CMD_HDR_CMD_ID_MASK: u32 = 0x00FF_FFFF;
/// `wmi.h::WMI_CMD_HDR_CMD_ID_LSB`.
pub const WMI_CMD_HDR_CMD_ID_LSB: u32 = 0;
/// `wmi.h::WMI_CMD_HDR_PLT_PRIV_MASK`.
pub const WMI_CMD_HDR_PLT_PRIV_MASK: u32 = 0xFF00_0000;
/// `wmi.h::WMI_CMD_HDR_PLT_PRIV_LSB`.
pub const WMI_CMD_HDR_PLT_PRIV_LSB: u32 = 24;

impl WmiCmdHdr {
    /// Build a header from a 24-bit command id. Host always writes
    /// `plt_priv = 0`; firmware sets it on responses.
    pub const fn new(cmd_id: u32) -> Self {
        Self {
            cmd_id_and_priv: cmd_id & WMI_CMD_HDR_CMD_ID_MASK,
        }
    }

    /// Extract the 24-bit command id.
    pub const fn cmd_id(self) -> u32 {
        (self.cmd_id_and_priv & WMI_CMD_HDR_CMD_ID_MASK) >> WMI_CMD_HDR_CMD_ID_LSB
    }

    /// Extract the 8-bit platform-private byte.
    pub const fn plt_priv(self) -> u8 {
        ((self.cmd_id_and_priv & WMI_CMD_HDR_PLT_PRIV_MASK) >> WMI_CMD_HDR_PLT_PRIV_LSB) as u8
    }
}

/// Encode a WMI header into the first 4 bytes of `out`.
pub fn encode_wmi_hdr(hdr: &WmiCmdHdr, out: &mut [u8]) -> Result<(), ()> {
    if out.len() < WMI_HDR_LEN {
        return Err(());
    }
    out[0..4].copy_from_slice(&hdr.cmd_id_and_priv.to_le_bytes());
    Ok(())
}

/// Decode a WMI header from the first 4 bytes of `bytes`.
pub fn decode_wmi_hdr(bytes: &[u8]) -> Result<WmiCmdHdr, ()> {
    if bytes.len() < WMI_HDR_LEN {
        return Err(());
    }
    Ok(WmiCmdHdr {
        cmd_id_and_priv: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
    })
}

// ── Command-id enumeration ─────────────────────────────────────────
//
// `wmi.h::enum wmi_cmd_id` is enormous. Stage 2 enumerates only the
// commands the bring-up path issues + a handful of common runtime
// commands that demonstrate the encoder shape. Group IDs from the
// `WMI_GRP_*` enum (`wmi.h` ~L1050..L1100):
//
//   WMI_GRP_START = 0x3   — base group offset
//   WMI_GRP_SCAN  = WMI_GRP_START
//   WMI_GRP_PDEV  = 0x4
//   WMI_GRP_VDEV  = 0x5
//   WMI_GRP_PEER  = 0x6
//
// Command id = (group << 12) | local_index. We use the *legacy* WMI
// numbering (the TLV variant used by 6174 has a parallel enum;
// Stage 2 covers main-WMI which is the wire format for 988X / 9888 /
// 9984 / 99X0).

/// A handful of legacy-WMI command IDs, mirroring `wmi.h::enum wmi_cmd_id`.
/// The 24-bit values here are the actual on-wire encoding.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WmiCmdId {
    /// `WMI_INIT_CMDID` — `0x1`. Host's first command after the HTC
    /// handshake.
    Init = 0x0001,
    /// `WMI_START_SCAN_CMDID` — `WMI_GRP_SCAN << 12 | 0`.
    StartScan = 0x3000,
    /// `WMI_STOP_SCAN_CMDID` — `WMI_GRP_SCAN << 12 | 1`.
    StopScan = 0x3001,
    /// `WMI_PDEV_SET_PARAM_CMDID` — `WMI_GRP_PDEV << 12 | 0`.
    PdevSetParam = 0x4000,
    /// `WMI_PDEV_SET_CHANNEL_CMDID` — `WMI_GRP_PDEV << 12 | 1`.
    PdevSetChannel = 0x4001,
    /// `WMI_VDEV_CREATE_CMDID` — `WMI_GRP_VDEV << 12 | 0`.
    VdevCreate = 0x5000,
    /// `WMI_VDEV_DELETE_CMDID` — `WMI_GRP_VDEV << 12 | 1`.
    VdevDelete = 0x5001,
    /// `WMI_VDEV_START_REQUEST_CMDID` — `WMI_GRP_VDEV << 12 | 2`.
    VdevStart = 0x5002,
    /// `WMI_PEER_CREATE_CMDID` — `WMI_GRP_PEER << 12 | 0`.
    PeerCreate = 0x6000,
}

impl WmiCmdId {
    pub fn from_raw(v: u32) -> Option<Self> {
        Some(match v {
            0x0001 => WmiCmdId::Init,
            0x3000 => WmiCmdId::StartScan,
            0x3001 => WmiCmdId::StopScan,
            0x4000 => WmiCmdId::PdevSetParam,
            0x4001 => WmiCmdId::PdevSetChannel,
            0x5000 => WmiCmdId::VdevCreate,
            0x5001 => WmiCmdId::VdevDelete,
            0x5002 => WmiCmdId::VdevStart,
            0x6000 => WmiCmdId::PeerCreate,
            _ => return None,
        })
    }
}

// ── Event-id enumeration ───────────────────────────────────────────
//
// Events flow firmware→host on CE2. The first 4 bytes of each event
// are the event id (`wmi.h::enum wmi_event_id`). Stage 2 enumerates
// the "service ready" + "ready" events the handshake-completion path
// needs to see.

/// A handful of legacy-WMI event IDs (`wmi.h::enum wmi_event_id`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WmiEventId {
    /// `WMI_SERVICE_READY_EVENTID` — `0x1`. Firmware sends this once
    /// it's done with WMI-side init; payload includes the
    /// service-id-bitmask the firmware exposes.
    ServiceReady = 0x0001,
    /// `WMI_READY_EVENTID` — `0x2`. Firmware sends this after the
    /// host has acknowledged `SERVICE_READY` and is ready to run.
    Ready = 0x0002,
    /// `WMI_SCAN_EVENTID` — `WMI_GRP_SCAN << 12 | 0`.
    Scan = 0x3000,
    /// `WMI_DEBUG_MESG_EVENTID`.
    DebugMessage = 0x3001,
}

impl WmiEventId {
    pub fn from_raw(v: u32) -> Option<Self> {
        Some(match v {
            0x0001 => WmiEventId::ServiceReady,
            0x0002 => WmiEventId::Ready,
            0x3000 => WmiEventId::Scan,
            0x3001 => WmiEventId::DebugMessage,
            _ => return None,
        })
    }
}

// ── Encoder ────────────────────────────────────────────────────────

/// Builds a WMI command frame: 4-byte header + arbitrary payload.
/// Caller is responsible for the payload layout (which is per-cmd-id
/// — see `wmi.h::struct wmi_*_cmd`).
#[derive(Debug)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Allocate a new encoder for command `cmd`. The header is
    /// pre-populated; calls to `push_*` append payload bytes.
    pub fn new(cmd: WmiCmdId) -> Self {
        let mut buf = Vec::with_capacity(WMI_HDR_LEN + 32);
        let hdr = WmiCmdHdr::new(cmd as u32);
        buf.extend_from_slice(&hdr.cmd_id_and_priv.to_le_bytes());
        Self { buf }
    }

    pub fn push_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn push_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn push_u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn push_slice(&mut self, s: &[u8]) {
        self.buf.extend_from_slice(s);
    }

    /// Finalize. Returns the assembled `[hdr | payload]` frame
    /// ready to hand to HTC.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

// ── Decoder ────────────────────────────────────────────────────────

/// View of an inbound WMI event frame. Borrows the underlying bytes
/// so it's zero-copy.
#[derive(Copy, Clone, Debug)]
pub struct EventFrame<'a> {
    pub event_id: WmiEventId,
    pub raw_event_id: u32,
    pub payload: &'a [u8],
}

/// Parse a WMI event frame: 4-byte event-id + payload. Recognized
/// event ids land in `event_id`; unknown ids surface via
/// `raw_event_id` and an event_id of `WmiEventId::DebugMessage` as
/// a soft fallback (see `wmi.c::ath10k_wmi_event_debug_mesg`).
pub fn decode_event(bytes: &[u8]) -> Result<EventFrame<'_>, ()> {
    if bytes.len() < WMI_HDR_LEN {
        return Err(());
    }
    let raw_event_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap())
        & WMI_CMD_HDR_CMD_ID_MASK;
    Ok(EventFrame {
        event_id: WmiEventId::from_raw(raw_event_id).unwrap_or(WmiEventId::DebugMessage),
        raw_event_id,
        payload: &bytes[WMI_HDR_LEN..],
    })
}

// ── Dispatch boundary (the firmware-load barrier) ──────────────────

/// What can go wrong when trying to send a WMI command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WmiError {
    /// Firmware not loaded. Stage 2 returns this for every send —
    /// Stage 3 will replace the body with a real CE3-dispatch.
    NotImplemented,
    /// Command frame too small / malformed.
    BadFrame,
}

/// Send a WMI command. Stage 2 stub — no firmware loaded.
///
/// Production shape (Stage 3): build the HTC header around `frame`,
/// post it to the CE3 source ring, kick the doorbell.
pub fn wmi_send(_frame: &[u8]) -> Result<(), WmiError> {
    Err(WmiError::NotImplemented)
}

// ── Common bring-up command builders ───────────────────────────────
//
// Stage 2 only ships the two simplest payloads (`PDEV_SET_PARAM`
// + `INIT`) so the encoder shape is exercised by the smokes. The
// rest of the WMI command set is structurally the same — caller
// adds fields per the `wmi.h::struct wmi_*_cmd` definition.

/// Build a `PDEV_SET_PARAM` command. Payload from
/// `wmi.h::struct wmi_pdev_set_param_cmd`:
///   __le32 param_id;
///   __le32 param_value;
pub fn build_pdev_set_param(param_id: u32, param_value: u32) -> Vec<u8> {
    let mut e = Encoder::new(WmiCmdId::PdevSetParam);
    e.push_u32(param_id);
    e.push_u32(param_value);
    e.finish()
}

/// Build a minimal `INIT` command. The full
/// `wmi.h::struct wmi_init_cmd` is large — bring-up sends a stub
/// with zero peers / vdevs to confirm the firmware is responsive,
/// then re-issues with real config. Stage 2 emits just the header
/// so the encoder shape is testable; Stage 3 will widen the
/// payload to match the firmware's expected resource config.
pub fn build_init_stub() -> Vec<u8> {
    Encoder::new(WmiCmdId::Init).finish()
}

// ── MAC vif (VDEV) commands ────────────────────────────────────────
//
// After HTC + WMI INIT, the host creates a virtual interface ("vdev")
// with `WMI_VDEV_CREATE_CMDID`. Payload layout from
// `wmi.h::struct wmi_vdev_create_cmd` (line 4871):
//
//   __le32 vdev_id;
//   __le32 vdev_type;
//   __le32 vdev_subtype;
//   struct wmi_mac_addr vdev_macaddr;  // 6 bytes addr + 2 pad
//
// Total payload = 3 × 4 + 8 = 20 bytes.
//
// Reference: `wmi.c::ath10k_wmi_vdev_create_send` (line 7146).

/// vdev type from `wmi.h::enum wmi_vdev_type`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VdevType {
    Ap = 1,
    Sta = 2,
    Ibss = 3,
    Monitor = 4,
}

/// vdev subtype from `wmi.h::enum wmi_vdev_subtype`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VdevSubtype {
    None = 0,
    P2pDevice = 1,
    P2pClient = 2,
    P2pGo = 3,
}

/// Build a `WMI_VDEV_CREATE_CMDID` command frame.
///
/// Reference: `wmi.c::ath10k_wmi_vdev_create_send` (line 7146).
pub fn build_vdev_create(
    vdev_id: u32,
    vdev_type: VdevType,
    vdev_subtype: VdevSubtype,
    mac_addr: [u8; 6],
) -> Vec<u8> {
    let mut e = Encoder::new(WmiCmdId::VdevCreate);
    e.push_u32(vdev_id);
    e.push_u32(vdev_type as u32);
    e.push_u32(vdev_subtype as u32);
    // wmi_mac_addr: 6 bytes + 2 bytes pad.
    e.push_slice(&mac_addr);
    e.push_u16(0u16);
    e.finish()
}

/// WMI_VDEV_PARAM_* constants from `wmi.h::enum wmi_vdev_param`.
pub mod vdev_param {
    pub const MAC_ADDR: u32 = 0x1;
    pub const RTS_THRESHOLD: u32 = 0x2;
    pub const FRAGMENTATION_THRESHOLD: u32 = 0x3;
    pub const DTIM_PERIOD: u32 = 0x5;
    pub const BEACON_INTERVAL: u32 = 0x6;
}

/// Build a `WMI_VDEV_SET_PARAM_CMDID` command frame.
///
/// Payload from `wmi.h::struct wmi_vdev_set_param_cmd`:
///   __le32 vdev_id; __le32 param_id; __le32 param_value;
pub fn build_vdev_set_param(vdev_id: u32, param_id: u32, param_value: u32) -> Vec<u8> {
    // WMI_VDEV_SET_PARAM_CMDID = WMI_GRP_VDEV << 12 | 0x3 = 0x5003.
    const VDEV_SET_PARAM_ID: u32 = 0x5003;
    let mut buf = Vec::with_capacity(4 + 12);
    let hdr = WmiCmdHdr::new(VDEV_SET_PARAM_ID);
    buf.extend_from_slice(&hdr.cmd_id_and_priv.to_le_bytes());
    buf.extend_from_slice(&vdev_id.to_le_bytes());
    buf.extend_from_slice(&param_id.to_le_bytes());
    buf.extend_from_slice(&param_value.to_le_bytes());
    buf
}
