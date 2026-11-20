//! Host Target Communications — the framing between Copy Engine pipes
//! and the WMI / HTT services.
//!
//! Byte-exact port of Linux `drivers/net/wireless/ath/ath11k/htc.{c,h}`
//! as a pure state machine: frames come in through [`Htc::rx`], frames
//! to transmit come out as [`HtcTx`] (pipe + bytes) for the CE layer to
//! post. No MMIO, no rings, no waits — where Linux blocks on
//! `ctl_resp`, the caller feeds the next received frame and then calls
//! the matching "complete" step ([`Htc::wait_target`],
//! [`Htc::connect_service_complete`]); [`HtcHandshake`] sequences the
//! whole bring-up the way `ath11k_core_start` does.
//!
//! Every HTC frame starts with `struct ath11k_htc_hdr` (8 bytes):
//!
//! | word | bits | field |
//! |---|---|---|
//! | `htc_info` | 7:0 | endpoint id |
//! | | 15:8 | flags (TX: `NEED_CREDIT_UPDATE`; RX: `TRAILER_PRESENT`) |
//! | | 31:16 | payload length (excludes this header) |
//! | `ctrl_info` | 7:0 | control byte 0 (RX: trailer length) |
//! | | 15:8 | control byte 1 (TX: per-endpoint sequence number) |
//!
//! Endpoint 0 carries the control messages (READY, CONNECT_SERVICE,
//! CONNECT_SERVICE_RESP, SETUP_COMPLETE_EX); its "connection" to the
//! pseudo service `RSVD_CTRL` is made locally by [`Htc::init`].
//!
//! Endpoint → CE pipe mapping comes from
//! [`TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390`], the table QCA6390 and all
//! WCN6855 variants use (Linux hw.c). The QMI WLAN-config request
//! (`ath11k_qmi_wlanfw_wlan_cfg_send`) sends the same 14 entries to the
//! firmware, so that layer should use this table too
//! ([`ServiceToPipe::to_le_bytes`] gives the wire form).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Header (htc.h) ──────────────────────────────────────────────────

/// `sizeof(struct ath11k_htc_hdr)`.
pub const HTC_HDR_SIZE: usize = 8;
/// `ATH11K_HTC_MAX_LEN` — largest RX frame (header included).
pub const ATH11K_HTC_MAX_LEN: usize = 4096;
/// `ATH11K_HTC_MAX_CTRL_MSG_LEN` — `control_resp_buffer` size.
pub const ATH11K_HTC_MAX_CTRL_MSG_LEN: usize = 256;
/// `ATH11K_NUM_CONTROL_TX_BUFFERS`.
pub const ATH11K_NUM_CONTROL_TX_BUFFERS: i32 = 2;
/// `ATH11K_HTC_MAX_SERVICE_ALLOC_ENTRIES`.
pub const ATH11K_HTC_MAX_SERVICE_ALLOC_ENTRIES: usize = 8;
/// `ATH11K_GLOBAL_DISABLE_CREDIT_FLOW` (SETUP_COMPLETE_EX flags).
pub const ATH11K_GLOBAL_DISABLE_CREDIT_FLOW: u32 = 1 << 1;

/// `enum ath11k_htc_tx_flags`.
pub const ATH11K_HTC_FLAG_NEED_CREDIT_UPDATE: u8 = 0x01;
/// See [`ATH11K_HTC_FLAG_NEED_CREDIT_UPDATE`].
pub const ATH11K_HTC_FLAG_SEND_BUNDLE: u8 = 0x02;
/// `enum ath11k_htc_rx_flags`.
pub const ATH11K_HTC_FLAG_TRAILER_PRESENT: u8 = 0x02;
/// See [`ATH11K_HTC_FLAG_TRAILER_PRESENT`].
pub const ATH11K_HTC_FLAG_BUNDLE_MASK: u8 = 0xF0;

/// `enum ath11k_htc_msg_id`.
pub mod msg_id {
    pub const READY: u16 = 1;
    pub const CONNECT_SERVICE: u16 = 2;
    pub const CONNECT_SERVICE_RESP: u16 = 3;
    pub const SETUP_COMPLETE: u16 = 4;
    pub const SETUP_COMPLETE_EX: u16 = 5;
    pub const SEND_SUSPEND_COMPLETE: u16 = 6;
    pub const NACK_SUSPEND: u16 = 7;
    pub const WAKEUP_FROM_SUSPEND: u16 = 8;
}

/// `enum ath11k_htc_version`.
pub const ATH11K_HTC_VERSION_2P0: u8 = 0x00;
/// See [`ATH11K_HTC_VERSION_2P0`].
pub const ATH11K_HTC_VERSION_2P1: u8 = 0x01;

/// `enum ath11k_htc_conn_flags` + the two field masks.
pub mod conn_flags {
    /// `ATH11K_HTC_CONN_FLAGS_THRESHOLD_LEVEL_MASK` — `GENMASK(1, 0)`.
    pub const THRESHOLD_LEVEL_MASK: u16 = 0x0003;
    pub const THRESHOLD_LEVEL_ONE_FOURTH: u16 = 0x0;
    pub const THRESHOLD_LEVEL_ONE_HALF: u16 = 0x1;
    pub const THRESHOLD_LEVEL_THREE_FOURTHS: u16 = 0x2;
    pub const THRESHOLD_LEVEL_UNITY: u16 = 0x3;
    pub const REDUCE_CREDIT_DRIBBLE: u16 = 0x4;
    pub const DISABLE_CREDIT_FLOW_CTRL: u16 = 0x8;
    /// `ATH11K_HTC_CONN_FLAGS_RECV_ALLOC` — `GENMASK(15, 8)`.
    pub const RECV_ALLOC_SHIFT: u16 = 8;
}

/// `enum ath11k_htc_conn_svc_status`.
pub mod conn_status {
    pub const SUCCESS: u8 = 0;
    pub const NOT_FOUND: u8 = 1;
    pub const FAILED: u8 = 2;
    pub const NO_RESOURCES: u8 = 3;
    pub const NO_MORE_EP: u8 = 4;
}

/// `enum ath11k_htc_record_id`.
pub const ATH11K_HTC_RECORD_NULL: u8 = 0;
/// See [`ATH11K_HTC_RECORD_NULL`].
pub const ATH11K_HTC_RECORD_CREDITS: u8 = 1;

/// `enum ath11k_htc_svc_gid`.
pub mod svc_group {
    pub const RSVD: u16 = 0;
    pub const WMI: u16 = 1;
    pub const NMI: u16 = 2;
    pub const HTT: u16 = 3;
    pub const CFG: u16 = 4;
    pub const IPA: u16 = 5;
    pub const PKTLOG: u16 = 6;
    pub const TEST: u16 = 254;
    pub const LAST: u16 = 255;
}

/// `SVC(group, idx)` = `(group << 8) | idx`.
pub const fn svc(group: u16, idx: u16) -> u16 {
    (group << 8) | idx
}

/// `enum ath11k_htc_svc_id`.
pub mod svc_id {
    use super::{svc, svc_group as g};
    pub const RESERVED: u16 = 0x0000;
    pub const UNUSED: u16 = RESERVED;
    pub const RSVD_CTRL: u16 = svc(g::RSVD, 1);
    pub const WMI_CONTROL: u16 = svc(g::WMI, 0);
    pub const WMI_DATA_BE: u16 = svc(g::WMI, 1);
    pub const WMI_DATA_BK: u16 = svc(g::WMI, 2);
    pub const WMI_DATA_VI: u16 = svc(g::WMI, 3);
    pub const WMI_DATA_VO: u16 = svc(g::WMI, 4);
    pub const WMI_CONTROL_MAC1: u16 = svc(g::WMI, 5);
    pub const WMI_CONTROL_MAC2: u16 = svc(g::WMI, 6);
    pub const NMI_CONTROL: u16 = svc(g::NMI, 0);
    pub const NMI_DATA: u16 = svc(g::NMI, 1);
    pub const HTT_DATA_MSG: u16 = svc(g::HTT, 0);
    pub const TEST_RAW_STREAMS: u16 = svc(g::TEST, 0);
    pub const IPA_TX: u16 = svc(g::IPA, 0);
    pub const PKT_LOG: u16 = svc(g::PKTLOG, 0);
}

/// `enum ath11k_htc_ep_id` — `ATH11K_HTC_EP_0`.
pub const ATH11K_HTC_EP_0: u8 = 0;
/// `ATH11K_HTC_EP_COUNT`.
pub const ATH11K_HTC_EP_COUNT: usize = 9;

/// `struct ath11k_htc_hdr`, unpacked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtcHdr {
    pub eid: u8,
    pub flags: u8,
    pub payload_len: u16,
    /// `HTC_HDR_CONTROLBYTES0` — trailer length on RX.
    pub ctrl0: u8,
    /// `HTC_HDR_CONTROLBYTES1` — sequence number on TX.
    pub ctrl1: u8,
}

impl HtcHdr {
    /// Pack into the two little-endian words.
    pub fn to_bytes(&self) -> [u8; HTC_HDR_SIZE] {
        let info = self.eid as u32 | (self.flags as u32) << 8 | (self.payload_len as u32) << 16;
        let ctrl = self.ctrl0 as u32 | (self.ctrl1 as u32) << 8;
        let mut b = [0u8; HTC_HDR_SIZE];
        b[0..4].copy_from_slice(&info.to_le_bytes());
        b[4..8].copy_from_slice(&ctrl.to_le_bytes());
        b
    }

    /// Unpack; `None` if fewer than 8 bytes. `HTC_HDR_RESERVED`
    /// (`ctrl_info` 31:16) is ignored as in Linux.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < HTC_HDR_SIZE {
            return None;
        }
        let info = rd32(b, 0);
        let ctrl = rd32(b, 4);
        Some(HtcHdr {
            eid: info as u8,
            flags: (info >> 8) as u8,
            payload_len: (info >> 16) as u16,
            ctrl0: ctrl as u8,
            ctrl1: (ctrl >> 8) as u8,
        })
    }
}

fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn words<const N: usize>(w: [u32; N]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 * N);
    for x in w {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v
}

// ── Control messages ────────────────────────────────────────────────

/// `struct ath11k_htc_ready` (8 bytes): `id_credit_count` =
/// message id (15:0) | credit count (31:16); `size_ep` = credit size
/// (15:0) | max endpoints (23:16). The firmware builds this; the
/// encoder exists for tests and simulators.
pub fn ready_msg(credit_count: u16, credit_size: u16, max_endpoints: u8) -> Vec<u8> {
    words([
        msg_id::READY as u32 | (credit_count as u32) << 16,
        credit_size as u32 | (max_endpoints as u32) << 16,
    ])
}

/// `struct ath11k_htc_ready_extended` (12 bytes): READY + `ver_bundle`
/// (HTC version 7:0, max msgs per bundle 15:8).
pub fn ready_ext_msg(
    credit_count: u16,
    credit_size: u16,
    max_endpoints: u8,
    version: u8,
    max_msgs_per_bundle: u8,
) -> Vec<u8> {
    let mut v = ready_msg(credit_count, credit_size, max_endpoints);
    v.extend_from_slice(&(version as u32 | (max_msgs_per_bundle as u32) << 8).to_le_bytes());
    v
}

/// Decoded READY (`ath11k_htc_wait_target`'s view).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtcReady {
    pub message_id: u16,
    pub credit_count: u16,
    pub credit_size: u16,
    pub max_endpoints: u8,
}

impl HtcReady {
    /// Parse the first 8 bytes; `None` if shorter.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        let a = rd32(b, 0);
        let s = rd32(b, 4);
        Some(HtcReady {
            message_id: a as u16,
            credit_count: (a >> 16) as u16,
            credit_size: s as u16,
            max_endpoints: (s >> 16) as u8,
        })
    }
}

/// `struct ath11k_htc_conn_svc` (8 bytes): `msg_svc_id` = message id
/// (15:0) | service id (31:16); `flags_len` = connection flags (15:0)
/// | service meta length (23:16, always 0 from Linux).
pub fn connect_service_msg(service_id: u16, flags: u16) -> Vec<u8> {
    words([
        msg_id::CONNECT_SERVICE as u32 | (service_id as u32) << 16,
        flags as u32,
    ])
}

/// `struct ath11k_htc_conn_svc_resp` (12 bytes): `msg_svc_id` =
/// message id | service id (31:16); `flags_len` = status (7:0) |
/// endpoint (15:8) | max message size (31:16); `svc_meta_pad` = meta
/// length (7:0). Firmware-built; encoder for tests and simulators.
pub fn connect_service_resp_msg(
    service_id: u16,
    status: u8,
    eid: u8,
    max_msg_size: u16,
    meta_len: u8,
) -> Vec<u8> {
    words([
        msg_id::CONNECT_SERVICE_RESP as u32 | (service_id as u32) << 16,
        status as u32 | (eid as u32) << 8 | (max_msg_size as u32) << 16,
        meta_len as u32,
    ])
}

/// Decoded CONNECT_SERVICE_RESP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtcConnSvcResp {
    pub message_id: u16,
    pub service_id: u16,
    pub status: u8,
    pub eid: u8,
    pub max_msg_size: u16,
    pub meta_len: u8,
}

impl HtcConnSvcResp {
    /// Parse 12 bytes; `None` if shorter.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 12 {
            return None;
        }
        let a = rd32(b, 0);
        let f = rd32(b, 4);
        Some(HtcConnSvcResp {
            message_id: a as u16,
            service_id: (a >> 16) as u16,
            status: f as u8,
            eid: (f >> 8) as u8,
            max_msg_size: (f >> 16) as u16,
            meta_len: rd32(b, 8) as u8,
        })
    }
}

/// `struct ath11k_htc_setup_complete_extended` (12 bytes): `msg_id`,
/// `flags`, `max_msgs_per_bundled_recv` (7:0). Linux sets only the
/// first two.
pub fn setup_complete_ex_msg(flags: u32, max_msgs_per_bundled_recv: u8) -> Vec<u8> {
    words([
        msg_id::SETUP_COMPLETE_EX as u32,
        flags,
        max_msgs_per_bundled_recv as u32,
    ])
}

/// A trailer of `ATH11K_HTC_RECORD_CREDITS` records: one record
/// (`ath11k_htc_record_hdr` {id, len, pad, pad} + `len / 4`
/// `ath11k_htc_credit_report` {eid, credits, pad, pad}) holding every
/// `(eid, credits)` pair. Firmware-built; for tests and simulators.
pub fn credit_report_trailer(reports: &[(u8, u8)]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 4 * reports.len());
    v.extend_from_slice(&[ATH11K_HTC_RECORD_CREDITS, (4 * reports.len()) as u8, 0, 0]);
    for &(eid, credits) in reports {
        v.extend_from_slice(&[eid, credits, 0, 0]);
    }
    v
}

/// Wrap `payload` (+ optional `trailer`) in an RX-direction HTC header
/// with `TRAILER_PRESENT` and `ctrl0 = trailer.len()` when a trailer is
/// given — what the target sends. For tests and simulators.
pub fn target_frame(eid: u8, payload: &[u8], trailer: &[u8]) -> Vec<u8> {
    let hdr = HtcHdr {
        eid,
        flags: if trailer.is_empty() {
            0
        } else {
            ATH11K_HTC_FLAG_TRAILER_PRESENT
        },
        payload_len: (payload.len() + trailer.len()) as u16,
        ctrl0: trailer.len() as u8,
        ctrl1: 0,
    };
    let mut v = Vec::with_capacity(HTC_HDR_SIZE + payload.len() + trailer.len());
    v.extend_from_slice(&hdr.to_bytes());
    v.extend_from_slice(payload);
    v.extend_from_slice(trailer);
    v
}

// ── Service → CE pipe map (hw.c) ────────────────────────────────────

/// `PIPEDIR_NONE` (ce.h).
pub const PIPEDIR_NONE: u32 = 0;
/// `PIPEDIR_IN` — target → host.
pub const PIPEDIR_IN: u32 = 1;
/// `PIPEDIR_OUT` — host → target.
pub const PIPEDIR_OUT: u32 = 2;
/// `PIPEDIR_INOUT`.
pub const PIPEDIR_INOUT: u32 = 3;
/// `PIPEDIR_INOUT_H2H`.
pub const PIPEDIR_INOUT_H2H: u32 = 4;

/// `struct service_to_pipe` (ce.h): three `__le32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceToPipe {
    pub service_id: u32,
    pub pipedir: u32,
    pub pipenum: u32,
}

impl ServiceToPipe {
    /// Wire form (12 bytes, little-endian) — as QMI's `svc_cfg`
    /// carries it.
    pub fn to_le_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&self.service_id.to_le_bytes());
        b[4..8].copy_from_slice(&self.pipedir.to_le_bytes());
        b[8..12].copy_from_slice(&self.pipenum.to_le_bytes());
        b
    }
}

const fn s2p(service_id: u16, pipedir: u32, pipenum: u32) -> ServiceToPipe {
    ServiceToPipe {
        service_id: service_id as u32,
        pipedir,
        pipenum,
    }
}

/// `ath11k_target_service_to_ce_map_wlan_qca6390` (hw.c) — used by
/// QCA6390 and every WCN6855 variant (`hw_params.svc_to_ce_map`,
/// `svc_to_ce_map_len = 14`; the Linux array's zero terminator is not
/// counted and not included here). Shared with the QMI layer.
pub const TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390: [ServiceToPipe; 14] = [
    s2p(svc_id::WMI_DATA_VO, PIPEDIR_OUT, 3),
    s2p(svc_id::WMI_DATA_VO, PIPEDIR_IN, 2),
    s2p(svc_id::WMI_DATA_BK, PIPEDIR_OUT, 3),
    s2p(svc_id::WMI_DATA_BK, PIPEDIR_IN, 2),
    s2p(svc_id::WMI_DATA_BE, PIPEDIR_OUT, 3),
    s2p(svc_id::WMI_DATA_BE, PIPEDIR_IN, 2),
    s2p(svc_id::WMI_DATA_VI, PIPEDIR_OUT, 3),
    s2p(svc_id::WMI_DATA_VI, PIPEDIR_IN, 2),
    s2p(svc_id::WMI_CONTROL, PIPEDIR_OUT, 3),
    s2p(svc_id::WMI_CONTROL, PIPEDIR_IN, 2),
    s2p(svc_id::RSVD_CTRL, PIPEDIR_OUT, 0),
    s2p(svc_id::RSVD_CTRL, PIPEDIR_IN, 2),
    s2p(svc_id::HTT_DATA_MSG, PIPEDIR_OUT, 4),
    s2p(svc_id::HTT_DATA_MSG, PIPEDIR_IN, 1),
];

/// `ath11k_pcic_map_service_to_pipe` → `(ul_pipe, dl_pipe)`. Linux
/// `WARN_ON`s a duplicate direction and keeps the last; both
/// directions must be found or it is `-ENOENT`.
pub fn map_service_to_pipe(map: &[ServiceToPipe], service_id: u16) -> Result<(u8, u8), HtcError> {
    let mut ul = None;
    let mut dl = None;
    for e in map.iter().filter(|e| e.service_id == service_id as u32) {
        match e.pipedir {
            PIPEDIR_IN => dl = Some(e.pipenum as u8),
            PIPEDIR_OUT => ul = Some(e.pipenum as u8),
            PIPEDIR_INOUT => {
                dl = Some(e.pipenum as u8);
                ul = Some(e.pipenum as u8);
            }
            _ => {}
        }
    }
    match (ul, dl) {
        (Some(u), Some(d)) => Ok((u, d)),
        _ => Err(HtcError::NoPipe(service_id)),
    }
}

// ── State ───────────────────────────────────────────────────────────

/// HTC failures with the Linux errno they correspond to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HtcError {
    /// Endpoint id ≥ `ATH11K_HTC_EP_COUNT` (`-ENOENT` on TX; RX drop).
    InvalidEndpoint(u8),
    /// Not enough TX credits (`-EAGAIN`; WMI retries on credit report).
    NoCredits { eid: u8, needed: i32, have: i32 },
    /// Payload too large for the 16-bit length field.
    PayloadTooLarge(usize),
    /// RX frame shorter than its header.
    ShortFrame,
    /// RX `payload_len + 8 > ATH11K_HTC_MAX_LEN`.
    FrameTooLong(usize),
    /// RX buffer shorter than `payload_len`.
    InsufficientLength { got: usize, expected: usize },
    /// Trailer length < 4 or > payload length.
    InvalidTrailerLen(u8),
    /// Malformed trailer record (`-EINVAL`).
    InvalidRecord,
    /// RX on a non-zero endpoint nobody connected.
    NotConnected(u8),
    /// No control response has arrived (Linux `-ETIMEDOUT`).
    NoControlResponse,
    /// READY malformed / zero credits (`-ECOMM`).
    BadReady,
    /// Wrong message id or short CONNECT_SERVICE_RESP (`-EPROTO`).
    BadConnectResp,
    /// Target refused the service (`-EPROTO`).
    ConnectRefused(u8),
    /// Assigned endpoint out of range, zero max message size, or
    /// already in use (`-EPROTO`).
    BadAssignment,
    /// Service missing from the CE map (`-ENOENT`).
    NoPipe(u16),
    /// Step called out of order (no Linux equivalent).
    OutOfOrder,
}

impl HtcError {
    /// Linux errno (positive).
    pub fn errno(&self) -> i32 {
        match self {
            HtcError::InvalidEndpoint(_) | HtcError::NoPipe(_) => 2, // ENOENT
            HtcError::NoCredits { .. } => 11,                        // EAGAIN
            HtcError::NoControlResponse => 110,                      // ETIMEDOUT
            HtcError::BadReady => 70,                                // ECOMM
            HtcError::BadConnectResp | HtcError::ConnectRefused(_) | HtcError::BadAssignment => 71, // EPROTO
            _ => 22, // EINVAL
        }
    }
}

/// Per-chip knobs `htc.c` reads from `hw_params` / `wmi_ab`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtcConfig {
    /// `hw_params.credit_flow`.
    pub credit_flow: bool,
    /// `hw_params.supports_shadow_regs` — forces 1 total TX credit.
    pub supports_shadow_regs: bool,
    /// `htc->wmi_ep_count` (see [`wmi_ep_count`]).
    pub wmi_ep_count: u8,
    /// `hw_params.svc_to_ce_map`.
    pub svc_to_ce_map: &'static [ServiceToPipe],
}

impl HtcConfig {
    /// WCN6855 (all variants): `credit_flow = true`,
    /// `supports_shadow_regs = true`, `max_radios = 3`, and
    /// `preferred_hw_mode = SINGLE` at HTC init (set by
    /// `ath11k_wmi_attach` since it is `single_pdev_only` with
    /// `num_rxdma_per_pdev = 2`), hence one WMI endpoint.
    pub fn wcn6855() -> Self {
        HtcConfig {
            credit_flow: true,
            supports_shadow_regs: true,
            wmi_ep_count: wmi_ep_count(super::wmi::hw_mode::SINGLE, 3),
            svc_to_ce_map: &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
        }
    }
}

/// `ath11k_htc_init`'s `wmi_ep_count` switch on
/// `wmi_ab.preferred_hw_mode`.
pub fn wmi_ep_count(preferred_hw_mode: u32, max_radios: u8) -> u8 {
    use super::wmi::hw_mode;
    match preferred_hw_mode {
        hw_mode::SINGLE => 1,
        hw_mode::DBS | hw_mode::DBS_OR_SBS => 2,
        hw_mode::DBS_SBS => 3,
        _ => max_radios,
    }
}

/// `struct ath11k_htc_ep` (state only; callbacks are the caller's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtcEp {
    pub eid: u8,
    pub service_id: u16,
    pub max_tx_queue_depth: i32,
    pub max_ep_message_len: u32,
    pub ul_pipe_id: u8,
    pub dl_pipe_id: u8,
    pub seq_no: u8,
    pub tx_credits: i32,
    pub tx_credit_flow_enabled: bool,
}

impl HtcEp {
    /// Connected ⇔ `service_id != ATH11K_HTC_SVC_ID_UNUSED`.
    pub fn connected(&self) -> bool {
        self.service_id != svc_id::UNUSED
    }
}

/// One frame to post on a CE pipe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtcTx {
    /// `ep->ul_pipe_id`.
    pub pipe: u8,
    pub eid: u8,
    /// Credits deducted (0 without credit flow); give them back with
    /// [`Htc::revert_credits`] if the CE send fails.
    pub credits: i32,
    /// Header + payload.
    pub frame: Vec<u8>,
}

/// What an RX frame turned into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HtcRxKind {
    /// EP0 READY / CONNECT_SERVICE_RESP stored as the control response.
    Control(u16),
    /// EP0 control message while one was still pending — Linux warns
    /// and drops it.
    UnsolicitedControl(u16),
    /// `SEND_SUSPEND_COMPLETE` (`true`) / `NACK_SUSPEND` (`false`).
    SuspendComplete(bool),
    /// `WAKEUP_FROM_SUSPEND`.
    WakeupFromSuspend,
    /// Other EP0 message id — ignored.
    IgnoredControl(u16),
    /// Trailer-only frame (`trailer_len >= payload_len`) — dropped
    /// after the credits were applied.
    TrailerOnly,
    /// Data for a connected endpoint: `frame[range]` is what Linux hands
    /// `ep_rx_complete` (everything after the header minus the trailer).
    Deliver {
        eid: u8,
        range: core::ops::Range<usize>,
    },
}

/// Result of [`Htc::rx`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtcRx {
    /// Endpoints credited by the trailer, in report order (Linux calls
    /// `ep_tx_credits` for each).
    pub credited: Vec<u8>,
    pub kind: HtcRxKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingConnect {
    service_id: u16,
    tx_alloc: u8,
    disable_credit_flow: bool,
    max_send_queue_depth: i32,
}

/// Outcome of a service connection (`struct ath11k_htc_svc_conn_resp`
/// + pipes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HtcConnected {
    pub service_id: u16,
    pub eid: u8,
    pub max_msg_len: u32,
    pub ul_pipe: u8,
    pub dl_pipe: u8,
    pub tx_credits: i32,
    pub credit_flow: bool,
}

/// `struct ath11k_htc`.
#[derive(Clone, Debug)]
pub struct Htc {
    pub cfg: HtcConfig,
    pub endpoints: [HtcEp; ATH11K_HTC_EP_COUNT],
    /// `control_resp_buffer[..control_resp_len]` while the
    /// `ctl_resp` completion is done-but-unconsumed.
    control_resp: Option<Vec<u8>>,
    pub total_transmit_credits: i32,
    pub target_credit_size: i32,
    /// `service_alloc_table[]` as `(service_id, credit_allocation)`.
    pub service_alloc_table: [(u16, u8); ATH11K_HTC_MAX_SERVICE_ALLOC_ENTRIES],
    pending: Option<PendingConnect>,
}

/// `ath11k_htc_setup_target_buffer_assignments`'s service list.
const WMI_SVC_IDS: [u16; 3] = [
    svc_id::WMI_CONTROL,
    svc_id::WMI_CONTROL_MAC1,
    svc_id::WMI_CONTROL_MAC2,
];

impl Htc {
    /// `ath11k_htc_init`: reset every endpoint
    /// (`ath11k_htc_reset_endpoint_states`) and connect the pseudo
    /// `RSVD_CTRL` service to EP0 locally (no message): credit flow off,
    /// `max_tx_queue_depth = 2`, and — because Linux reads the size
    /// back from a zeroed dummy response — `max_ep_message_len = 0`.
    pub fn init(cfg: HtcConfig) -> Result<Self, HtcError> {
        let mut endpoints = [HtcEp {
            eid: 0,
            service_id: svc_id::UNUSED,
            max_tx_queue_depth: 0,
            max_ep_message_len: 0,
            ul_pipe_id: 0,
            dl_pipe_id: 0,
            seq_no: 0,
            tx_credits: 0,
            tx_credit_flow_enabled: true,
        }; ATH11K_HTC_EP_COUNT];
        for (i, ep) in endpoints.iter_mut().enumerate() {
            ep.eid = i as u8;
        }
        let mut htc = Htc {
            cfg,
            endpoints,
            control_resp: None,
            total_transmit_credits: 0,
            target_credit_size: 0,
            service_alloc_table: [(0, 0); ATH11K_HTC_MAX_SERVICE_ALLOC_ENTRIES],
            pending: None,
        };
        // connect_service special case: RSVD_CTRL → EP0.
        let (ul, dl) = map_service_to_pipe(cfg.svc_to_ce_map, svc_id::RSVD_CTRL)?;
        let ep = &mut htc.endpoints[ATH11K_HTC_EP_0 as usize];
        ep.service_id = svc_id::RSVD_CTRL;
        ep.max_tx_queue_depth = ATH11K_NUM_CONTROL_TX_BUFFERS;
        ep.max_ep_message_len = 0;
        ep.tx_credits = 0;
        ep.ul_pipe_id = ul;
        ep.dl_pipe_id = dl;
        ep.tx_credit_flow_enabled = false;
        Ok(htc)
    }

    /// Whether a control response is waiting (`completion_done`).
    pub fn control_pending(&self) -> bool {
        self.control_resp.is_some()
    }

    /// `ath11k_htc_send`: prepend the header, charge
    /// `DIV_ROUND_UP(len_with_header, target_credit_size)` credits when
    /// both `hw_params.credit_flow` and the endpoint's flow control are
    /// on, set `NEED_CREDIT_UPDATE` whenever the endpoint's flow control
    /// is on, and stamp the post-incremented sequence number.
    pub fn send(&mut self, eid: u8, payload: &[u8]) -> Result<HtcTx, HtcError> {
        if eid as usize >= ATH11K_HTC_EP_COUNT {
            return Err(HtcError::InvalidEndpoint(eid));
        }
        if payload.len() > u16::MAX as usize {
            return Err(HtcError::PayloadTooLarge(payload.len()));
        }
        let credit_size = self.target_credit_size;
        let ep = &mut self.endpoints[eid as usize];
        let credit_flow = self.cfg.credit_flow && ep.tx_credit_flow_enabled;
        let len = payload.len() + HTC_HDR_SIZE;
        let mut credits = 0;
        if credit_flow {
            if credit_size <= 0 {
                // Linux would divide by zero; no READY processed yet.
                return Err(HtcError::OutOfOrder);
            }
            credits = len.div_ceil(credit_size as usize) as i32;
            if ep.tx_credits < credits {
                return Err(HtcError::NoCredits {
                    eid,
                    needed: credits,
                    have: ep.tx_credits,
                });
            }
            ep.tx_credits -= credits;
        }
        let hdr = HtcHdr {
            eid,
            flags: if ep.tx_credit_flow_enabled {
                ATH11K_HTC_FLAG_NEED_CREDIT_UPDATE
            } else {
                0
            },
            payload_len: payload.len() as u16,
            ctrl0: 0,
            ctrl1: ep.seq_no,
        };
        ep.seq_no = ep.seq_no.wrapping_add(1);
        let mut frame = Vec::with_capacity(len);
        frame.extend_from_slice(&hdr.to_bytes());
        frame.extend_from_slice(payload);
        Ok(HtcTx {
            pipe: ep.ul_pipe_id,
            eid,
            credits,
            frame,
        })
    }

    /// `ath11k_htc_send`'s `err_credits` path: the CE refused the frame,
    /// return its credits (Linux then calls `ep_tx_credits`).
    pub fn revert_credits(&mut self, tx: &HtcTx) {
        if let Some(ep) = self.endpoints.get_mut(tx.eid as usize) {
            ep.tx_credits += tx.credits;
        }
    }

    /// `ath11k_htc_process_trailer` (+ `_process_credit_report`).
    /// Credits are applied as records are read, so a later malformed
    /// record leaves earlier credits applied, as in Linux.
    fn process_trailer(&mut self, mut buf: &[u8], credited: &mut Vec<u8>) -> Result<(), HtcError> {
        while !buf.is_empty() {
            if buf.len() < 4 {
                return Err(HtcError::InvalidRecord);
            }
            let id = buf[0];
            let rlen = buf[1] as usize;
            // Linux compares the record length to the bytes left
            // *including* the 4-byte record header.
            if rlen > buf.len() {
                return Err(HtcError::InvalidRecord);
            }
            if self.cfg.credit_flow && id == ATH11K_HTC_RECORD_CREDITS {
                if rlen < 4 {
                    return Err(HtcError::InvalidRecord);
                }
                // NARF-stricter: only reports inside the trailer (Linux
                // may read up to 4 bytes past it when rlen == left).
                let body = &buf[4..(4 + rlen).min(buf.len())];
                for r in body.chunks_exact(4).take(rlen / 4) {
                    let eid = r[0] as usize;
                    if eid >= ATH11K_HTC_EP_COUNT {
                        break;
                    }
                    self.endpoints[eid].tx_credits += r[1] as i32;
                    credited.push(eid as u8);
                }
            }
            let adv = 4 + rlen;
            if adv >= buf.len() {
                break;
            }
            buf = &buf[adv..];
        }
        Ok(())
    }

    /// `ath11k_htc_rx_completion_handler` for one received buffer
    /// (header included).
    pub fn rx(&mut self, frame: &[u8]) -> Result<HtcRx, HtcError> {
        let hdr = HtcHdr::parse(frame).ok_or(HtcError::ShortFrame)?;
        let eid = hdr.eid;
        if eid as usize >= ATH11K_HTC_EP_COUNT {
            return Err(HtcError::InvalidEndpoint(eid));
        }
        let payload_len = hdr.payload_len as usize;
        if payload_len + HTC_HDR_SIZE > ATH11K_HTC_MAX_LEN {
            return Err(HtcError::FrameTooLong(payload_len + HTC_HDR_SIZE));
        }
        let body_len = frame.len() - HTC_HDR_SIZE;
        if body_len < payload_len {
            return Err(HtcError::InsufficientLength {
                got: body_len,
                expected: payload_len,
            });
        }
        let mut credited = Vec::new();
        let mut trailer_len = 0usize;
        if hdr.flags & ATH11K_HTC_FLAG_TRAILER_PRESENT != 0 {
            trailer_len = hdr.ctrl0 as usize;
            if trailer_len < 4 || trailer_len > payload_len {
                return Err(HtcError::InvalidTrailerLen(hdr.ctrl0));
            }
            let start = HTC_HDR_SIZE + payload_len - trailer_len;
            let trailer = &frame[start..HTC_HDR_SIZE + payload_len];
            self.process_trailer(trailer, &mut credited)?;
        }
        if trailer_len >= payload_len {
            return Ok(HtcRx {
                credited,
                kind: HtcRxKind::TrailerOnly,
            });
        }
        // skb_trim(skb, skb->len - trailer_len): the whole received
        // buffer after the header, less the trailer.
        let range = HTC_HDR_SIZE..frame.len() - trailer_len;
        if eid == ATH11K_HTC_EP_0 {
            let msg = &frame[range];
            // NARF-stricter: Linux reads msg_svc_id without a length check.
            if msg.len() < 4 {
                return Err(HtcError::ShortFrame);
            }
            let id = rd32(msg, 0) as u16;
            let kind = match id {
                msg_id::READY | msg_id::CONNECT_SERVICE_RESP => {
                    if self.control_resp.is_some() {
                        HtcRxKind::UnsolicitedControl(id)
                    } else {
                        let n = msg.len().min(ATH11K_HTC_MAX_CTRL_MSG_LEN);
                        self.control_resp = Some(msg[..n].to_vec());
                        HtcRxKind::Control(id)
                    }
                }
                msg_id::SEND_SUSPEND_COMPLETE => HtcRxKind::SuspendComplete(true),
                msg_id::NACK_SUSPEND => HtcRxKind::SuspendComplete(false),
                msg_id::WAKEUP_FROM_SUSPEND => HtcRxKind::WakeupFromSuspend,
                other => HtcRxKind::IgnoredControl(other),
            };
            return Ok(HtcRx { credited, kind });
        }
        // NARF-stricter: Linux calls a NULL ep_rx_complete here.
        if !self.endpoints[eid as usize].connected() {
            return Err(HtcError::NotConnected(eid));
        }
        Ok(HtcRx {
            credited,
            kind: HtcRxKind::Deliver { eid, range },
        })
    }

    /// `ath11k_htc_wait_target` after the READY arrived: record the
    /// credit pool, clamp it to 1 on shadow-register chips (WCN6855:
    /// "wmi endpoint uses 1 credit to avoid back-to-back write"), and
    /// divide it among the WMI services
    /// (`ath11k_htc_setup_target_buffer_assignments`; its `-EINVAL` for
    /// a bad `wmi_ep_count` is ignored by Linux, leaving the table
    /// untouched).
    pub fn wait_target(&mut self) -> Result<HtcReady, HtcError> {
        let resp = self
            .control_resp
            .take()
            .ok_or(HtcError::NoControlResponse)?;
        let ready = HtcReady::parse(&resp).ok_or(HtcError::BadReady)?;
        if ready.message_id != msg_id::READY {
            return Err(HtcError::BadReady);
        }
        self.total_transmit_credits = ready.credit_count as i32;
        self.target_credit_size = ready.credit_size as i32;
        if self.total_transmit_credits == 0 || self.target_credit_size == 0 {
            return Err(HtcError::BadReady);
        }
        if self.cfg.supports_shadow_regs {
            self.total_transmit_credits = 1;
        }
        let n = self.cfg.wmi_ep_count as usize;
        if n != 0 && n <= WMI_SVC_IDS.len() {
            let credits = self.total_transmit_credits / n as i32;
            for (i, &s) in WMI_SVC_IDS.iter().take(n).enumerate() {
                self.service_alloc_table[i] = (s, credits as u8);
            }
        }
        Ok(ready)
    }

    /// `ath11k_htc_get_credit_allocation` — the *last* matching entry
    /// wins (the loop has no break).
    pub fn credit_allocation(&self, service_id: u16) -> u8 {
        let mut a = 0;
        for &(s, c) in &self.service_alloc_table {
            if s == service_id {
                a = c;
            }
        }
        a
    }

    /// First half of `ath11k_htc_connect_service` for a real service:
    /// build CONNECT_SERVICE (`RECV_ALLOC = tx_alloc`;
    /// `DISABLE_CREDIT_FLOW_CTRL` unless the service is one of the three
    /// WMI control services and `hw_params.credit_flow` is set),
    /// `reinit_completion`, and send it on EP0.
    pub fn connect_service_request(
        &mut self,
        service_id: u16,
        max_send_queue_depth: i32,
    ) -> Result<HtcTx, HtcError> {
        if service_id == svc_id::RSVD_CTRL || self.pending.is_some() {
            return Err(HtcError::OutOfOrder);
        }
        let tx_alloc = self.credit_allocation(service_id);
        let mut flags = (tx_alloc as u16) << conn_flags::RECV_ALLOC_SHIFT;
        let mut disable = false;
        if !WMI_SVC_IDS.contains(&service_id) {
            flags |= conn_flags::DISABLE_CREDIT_FLOW_CTRL;
            disable = true;
        }
        if !self.cfg.credit_flow {
            flags |= conn_flags::DISABLE_CREDIT_FLOW_CTRL;
            disable = true;
        }
        self.control_resp = None;
        let tx = self.send(ATH11K_HTC_EP_0, &connect_service_msg(service_id, flags))?;
        self.pending = Some(PendingConnect {
            service_id,
            tx_alloc,
            disable_credit_flow: disable,
            max_send_queue_depth,
        });
        Ok(tx)
    }

    /// Second half of `ath11k_htc_connect_service`, after the response
    /// arrived: validate it, set up the assigned endpoint and map its
    /// pipes.
    pub fn connect_service_complete(&mut self) -> Result<HtcConnected, HtcError> {
        let p = self.pending.take().ok_or(HtcError::OutOfOrder)?;
        let resp = self
            .control_resp
            .take()
            .ok_or(HtcError::NoControlResponse)?;
        let r = match HtcConnSvcResp::parse(&resp) {
            Some(r) if r.message_id == msg_id::CONNECT_SERVICE_RESP => r,
            _ => return Err(HtcError::BadConnectResp),
        };
        if r.status != conn_status::SUCCESS {
            return Err(HtcError::ConnectRefused(r.status));
        }
        let eid = r.eid;
        if eid as usize >= ATH11K_HTC_EP_COUNT || r.max_msg_size == 0 {
            return Err(HtcError::BadAssignment);
        }
        if self.endpoints[eid as usize].connected() {
            return Err(HtcError::BadAssignment);
        }
        let (ul, dl) = map_service_to_pipe(self.cfg.svc_to_ce_map, p.service_id)?;
        let ep = &mut self.endpoints[eid as usize];
        ep.eid = eid;
        ep.service_id = p.service_id;
        ep.max_tx_queue_depth = p.max_send_queue_depth;
        ep.max_ep_message_len = r.max_msg_size as u32;
        ep.tx_credits = p.tx_alloc as i32;
        ep.ul_pipe_id = ul;
        ep.dl_pipe_id = dl;
        if p.disable_credit_flow && ep.tx_credit_flow_enabled {
            ep.tx_credit_flow_enabled = false;
        }
        Ok(HtcConnected {
            service_id: p.service_id,
            eid,
            max_msg_len: r.max_msg_size as u32,
            ul_pipe: ul,
            dl_pipe: dl,
            tx_credits: ep.tx_credits,
            credit_flow: ep.tx_credit_flow_enabled,
        })
    }

    /// `ath11k_htc_start`: SETUP_COMPLETE_EX on EP0 (flags 0 with credit
    /// flow, else `ATH11K_GLOBAL_DISABLE_CREDIT_FLOW`).
    pub fn start(&mut self) -> Result<HtcTx, HtcError> {
        let flags = if self.cfg.credit_flow {
            0
        } else {
            ATH11K_GLOBAL_DISABLE_CREDIT_FLOW
        };
        self.send(ATH11K_HTC_EP_0, &setup_complete_ex_msg(flags, 0))
    }

    /// Endpoint currently bound to `service_id`.
    pub fn endpoint_for(&self, service_id: u16) -> Option<&HtcEp> {
        self.endpoints.iter().find(|e| e.service_id == service_id)
    }
}

// ── Bring-up sequencer ──────────────────────────────────────────────

/// Where [`HtcHandshake`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for the target's READY.
    AwaitReady,
    /// CONNECT_SERVICE for this service is in flight.
    AwaitConnectResp(u16),
    /// SETUP_COMPLETE_EX sent; endpoints usable.
    Done,
}

/// Something for the caller to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HtcAction {
    /// Post this frame on `tx.pipe`.
    Send(HtcTx),
    /// READY processed (credits as reported, before the shadow clamp).
    Ready(HtcReady),
    /// A service got its endpoint.
    Connected(HtcConnected),
    /// Handshake finished (SETUP_COMPLETE_EX is the preceding `Send`).
    SetupComplete,
    /// TX credits arrived for this endpoint (`ep_tx_credits`).
    TxCredits(u8),
    /// Payload for a connected endpoint.
    Deliver {
        eid: u8,
        range: core::ops::Range<usize>,
    },
    /// Suspend ack/nack or wakeup on EP0.
    Suspend(bool),
    Wakeup,
}

/// The HTC part of `ath11k_core_start`: `ath11k_htc_init` →
/// `ath11k_htc_wait_target` → `ath11k_dp_htt_connect` (HTT_DATA_MSG) →
/// `ath11k_wmi_connect` (WMI_CONTROL[, _MAC1, _MAC2] per
/// `wmi_ep_count`) → `ath11k_htc_start`, driven by received frames.
#[derive(Clone, Debug)]
pub struct HtcHandshake {
    pub htc: Htc,
    pub state: HandshakeState,
    services: Vec<u16>,
    next: usize,
}

impl HtcHandshake {
    /// `ath11k_htc_init` + the service plan.
    pub fn new(cfg: HtcConfig) -> Result<Self, HtcError> {
        let htc = Htc::init(cfg)?;
        let mut services = alloc::vec![svc_id::HTT_DATA_MSG];
        // ath11k_wmi_connect: -1 if wmi_ep_count > max_radios; the svc
        // table has 3 entries.
        let n = (cfg.wmi_ep_count as usize).min(WMI_SVC_IDS.len());
        services.extend_from_slice(&WMI_SVC_IDS[..n]);
        Ok(HtcHandshake {
            htc,
            state: HandshakeState::AwaitReady,
            services,
            next: 0,
        })
    }

    /// Services connected in order (HTT first, then WMI).
    pub fn services(&self) -> &[u16] {
        &self.services
    }

    fn advance(&mut self, out: &mut Vec<HtcAction>) -> Result<(), HtcError> {
        if let Some(&s) = self.services.get(self.next) {
            self.next += 1;
            out.push(HtcAction::Send(self.htc.connect_service_request(s, 0)?));
            self.state = HandshakeState::AwaitConnectResp(s);
        } else {
            out.push(HtcAction::Send(self.htc.start()?));
            out.push(HtcAction::SetupComplete);
            self.state = HandshakeState::Done;
        }
        Ok(())
    }

    /// Feed one received HTC frame.
    pub fn on_rx(&mut self, frame: &[u8]) -> Result<Vec<HtcAction>, HtcError> {
        let rx = self.htc.rx(frame)?;
        let mut out: Vec<HtcAction> = rx
            .credited
            .iter()
            .map(|&e| HtcAction::TxCredits(e))
            .collect();
        match rx.kind {
            HtcRxKind::Control(_) => match self.state {
                HandshakeState::AwaitReady => {
                    let r = self.htc.wait_target()?;
                    out.push(HtcAction::Ready(r));
                    self.advance(&mut out)?;
                }
                HandshakeState::AwaitConnectResp(_) => {
                    let c = self.htc.connect_service_complete()?;
                    out.push(HtcAction::Connected(c));
                    self.advance(&mut out)?;
                }
                // Linux stores it; nobody waits. Clear it so the next
                // wait does not see a stale response.
                HandshakeState::Done => {
                    self.htc.control_resp = None;
                }
            },
            HtcRxKind::Deliver { eid, range } => out.push(HtcAction::Deliver { eid, range }),
            HtcRxKind::SuspendComplete(ack) => out.push(HtcAction::Suspend(ack)),
            HtcRxKind::WakeupFromSuspend => out.push(HtcAction::Wakeup),
            HtcRxKind::UnsolicitedControl(_)
            | HtcRxKind::IgnoredControl(_)
            | HtcRxKind::TrailerOnly => {}
        }
        Ok(out)
    }
}
