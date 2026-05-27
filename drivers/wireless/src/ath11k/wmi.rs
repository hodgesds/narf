//! Wireless Management Interface — TLV command/response framing.
//!
//! WMI is ath11k's host↔firmware control plane. Commands are
//! variable-length TLV records prefixed by a 4-byte
//! `wmi_cmd_hdr` carrying a 24-bit command id. Responses arrive
//! as events with a parallel TLV-wrapped payload. The cmd-id
//! encoding `((group << 12) | 0x1)` matches Linux's
//! `WMI_TLV_CMD(grp_id)` macro.
//!
//! This file provides the byte-level frame builder + a small
//! decode helper. The MHI dispatch wiring (which writes the bytes
//! into an MHI control-channel TRE and rings the doorbell) lands
//! with Stage-2; commands built here can be unit-tested offline.
//!
//! Linux references (BSD-3 / dual GPL):
//! - `drivers/net/wireless/ath/ath11k/wmi.h` — TLV layout +
//!   command group enum.
//! - `drivers/net/wireless/ath/ath11k/wmi.c::ath11k_wmi_init`,
//!   `ath11k_wmi_send_init_country_cmd`,
//!   `ath11k_wmi_cmd_send_nowait` — encoder pattern.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Header field accessors ─────────────────────────────────────────
//
// Every WMI command starts with a 4-byte `wmi_cmd_hdr` carrying
// the 24-bit command id in bits[23:0]. The TLV stream follows
// immediately.

pub const WMI_CMD_HDR_CMD_ID_MASK: u32 = 0x00FF_FFFF;

/// Encode a command id into the 24-bit header field.
pub fn cmd_hdr(cmd_id: u32) -> u32 {
    cmd_id & WMI_CMD_HDR_CMD_ID_MASK
}

/// Build a WMI command id from `(group, sub_id)` per the
/// `WMI_TLV_CMD` macro: `((group << 12) | 0x1) + sub_id`.
/// `sub_id == 0` yields the group's first command id; subsequent
/// ids increment from there.
pub fn build_cmd_id(group: u16, sub_id: u16) -> u32 {
    let base = ((group as u32) << 12) | 0x1;
    base + sub_id as u32
}

// ── TLV header arithmetic ─────────────────────────────────────────
//
// Each TLV is `[ header(4) ][ payload(len) ]`. The 32-bit header
// carries the 16-bit tag in bits[31:16] and the 16-bit length in
// bits[15:0]. TLV payloads are 4-byte aligned in the stream —
// padding bytes after a short payload are zero.

pub const WMI_TLV_HDR_SIZE: usize = 4;
pub const WMI_TLV_LEN_MASK: u32 = 0x0000_FFFF;
pub const WMI_TLV_TAG_MASK: u32 = 0xFFFF_0000;
pub const WMI_TLV_TAG_SHIFT: u32 = 16;

/// Pack a TLV header.
pub fn pack_tlv_header(tag: u16, len: u16) -> u32 {
    ((tag as u32) << WMI_TLV_TAG_SHIFT) | (len as u32)
}

/// Unpack a TLV header into `(tag, len)`.
pub fn unpack_tlv_header(hdr: u32) -> (u16, u16) {
    let tag = ((hdr & WMI_TLV_TAG_MASK) >> WMI_TLV_TAG_SHIFT) as u16;
    let len = (hdr & WMI_TLV_LEN_MASK) as u16;
    (tag, len)
}

// ── Command groups + selected cmd-ids ──────────────────────────────
//
// Subset enumerated here — the rest live in Linux's wmi.h and are
// added as they get used. These five suffice for an INIT handshake
// (the gateway every other command goes through).

pub const WMI_GRP_START: u16 = 0x3;
pub const WMI_GRP_SCAN: u16 = 0x4;
pub const WMI_GRP_PDEV: u16 = 0x5;
pub const WMI_GRP_VDEV: u16 = 0x6;
pub const WMI_GRP_PEER: u16 = 0x7;

/// Subset of `enum wmi_tlv_cmd_id` we'll need for init + scan.
pub const WMI_INIT_CMDID: u32 = build_cmd_id_const(WMI_GRP_START, 0);
pub const WMI_START_SCAN_CMDID: u32 = build_cmd_id_const(WMI_GRP_SCAN, 0);
pub const WMI_STOP_SCAN_CMDID: u32 = build_cmd_id_const(WMI_GRP_SCAN, 1);
pub const WMI_PDEV_SET_REGDOMAIN_CMDID: u32 = build_cmd_id_const(WMI_GRP_PDEV, 0);
pub const WMI_VDEV_CREATE_CMDID: u32 = build_cmd_id_const(WMI_GRP_VDEV, 0);
pub const WMI_PEER_CREATE_CMDID: u32 = build_cmd_id_const(WMI_GRP_PEER, 0);

/// const-fn variant for use in `const` initialisers.
const fn build_cmd_id_const(group: u16, sub_id: u16) -> u32 {
    let base = ((group as u32) << 12) | 0x1;
    base + sub_id as u32
}

// ── TLV tag IDs ────────────────────────────────────────────────────
//
// Subset of `enum wmi_tlv_tag` from Linux's `wmi.h`. Only the
// tags we actually emit / consume in the bring-up path are
// enumerated; unknown tags are surfaced as `Other(u16)` so the
// decoder is forward-compatible.

pub const WMI_TAG_LAST_RESERVED: u16 = 15;

pub const WMI_TAG_INIT_CMD: u16 = 0x2c;
pub const WMI_TAG_RESOURCE_CONFIG: u16 = 0x2d;
pub const WMI_TAG_HOST_MEM_CHUNK: u16 = 0x2e;
pub const WMI_TAG_START_SCAN_CMD: u16 = 0x3b;
pub const WMI_TAG_STOP_SCAN_CMD: u16 = 0x3c;
pub const WMI_TAG_PDEV_SET_REGDOMAIN_CMD: u16 = 0x9b;
pub const WMI_TAG_VDEV_CREATE_CMD: u16 = 0x67;
pub const WMI_TAG_SERVICE_READY_EVENT: u16 = 0x53;
pub const WMI_TAG_READY_EVENT: u16 = 0x54;

// ── Encoder ───────────────────────────────────────────────────────

/// Builder for a WMI command frame. Layout:
///   `[ cmd_hdr(4) ][ tlv0_hdr(4) ][ tlv0_payload ][ pad ]...`
/// All TLV payloads are 4-byte aligned in the stream.
pub struct WmiCmdBuilder {
    bytes: Vec<u8>,
}

impl WmiCmdBuilder {
    /// Start a new command frame with the given 24-bit cmd id.
    pub fn new(cmd_id: u32) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&cmd_hdr(cmd_id).to_le_bytes());
        WmiCmdBuilder { bytes }
    }

    /// Append a TLV with `tag` and the given payload (length is
    /// the payload's `len()`; payload is auto-padded to 4 bytes).
    pub fn push_tlv(&mut self, tag: u16, payload: &[u8]) -> &mut Self {
        let len = payload.len() as u16;
        self.bytes
            .extend_from_slice(&pack_tlv_header(tag, len).to_le_bytes());
        self.bytes.extend_from_slice(payload);
        let pad = (4 - (payload.len() & 3)) & 3;
        for _ in 0..pad {
            self.bytes.push(0);
        }
        self
    }

    /// Convenience: append a u32 inside a TLV. Useful for the
    /// many single-u32 commands (e.g. WMI_PDEV_*_PARAM).
    pub fn push_u32_tlv(&mut self, tag: u16, value: u32) -> &mut Self {
        self.push_tlv(tag, &value.to_le_bytes())
    }

    /// Finalise + return the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// Borrow the in-progress frame.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ── Decoder ───────────────────────────────────────────────────────

/// One decoded TLV from a WMI event frame. Borrows into the
/// underlying frame bytes.
#[derive(Clone, Debug)]
pub struct WmiTlv<'a> {
    pub tag: u16,
    pub payload: &'a [u8],
}

/// Errors produced by the TLV walker.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WmiDecodeError {
    /// Frame too short for the 4-byte cmd_hdr.
    TooShortForHeader,
    /// A TLV's declared length runs past the end of the frame.
    Truncated { offset: usize },
}

/// Iterate the TLVs inside a WMI event frame. The first 4 bytes
/// are the `wmi_cmd_hdr` (event id); the rest is the TLV stream.
pub fn walk_event<'a>(frame: &'a [u8]) -> Result<(u32, Vec<WmiTlv<'a>>), WmiDecodeError> {
    if frame.len() < 4 {
        return Err(WmiDecodeError::TooShortForHeader);
    }
    let evt_id = u32::from_le_bytes(frame[0..4].try_into().unwrap()) & WMI_CMD_HDR_CMD_ID_MASK;
    let mut tlvs: Vec<WmiTlv<'a>> = Vec::new();
    let mut pos = 4;
    while pos + WMI_TLV_HDR_SIZE <= frame.len() {
        let hdr = u32::from_le_bytes(frame[pos..pos + 4].try_into().unwrap());
        let (tag, len) = unpack_tlv_header(hdr);
        let len = len as usize;
        pos += WMI_TLV_HDR_SIZE;
        if pos + len > frame.len() {
            return Err(WmiDecodeError::Truncated { offset: pos - 4 });
        }
        tlvs.push(WmiTlv {
            tag,
            payload: &frame[pos..pos + len],
        });
        let advance = (len + 3) & !3;
        pos += advance;
    }
    Ok((evt_id, tlvs))
}

// ── Init-command convenience builder ───────────────────────────────
//
// The first command the host issues to ath11k firmware is
// WMI_INIT_CMDID, which carries a `resource_config` TLV + zero
// or more `host_mem_chunk` TLVs. We expose a minimal builder
// here so unit tests can validate frame layout.

/// Subset of `struct wmi_resource_config` we set in INIT. The
/// full struct is ~80 u32 fields; this is just enough for a
/// stable smoke test. Add fields as actual init goes live.
#[derive(Copy, Clone, Debug, Default)]
pub struct ResourceConfig {
    pub num_vdevs: u32,
    pub num_peers: u32,
    pub num_offload_peers: u32,
    pub num_offload_reorder_buffs: u32,
    pub num_peer_keys: u32,
    pub num_tids: u32,
    pub ast_skid_limit: u32,
    pub tx_chain_mask: u32,
    pub rx_chain_mask: u32,
    pub rx_decap_mode: u32,
}

impl ResourceConfig {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[0..4].copy_from_slice(&self.num_vdevs.to_le_bytes());
        out[4..8].copy_from_slice(&self.num_peers.to_le_bytes());
        out[8..12].copy_from_slice(&self.num_offload_peers.to_le_bytes());
        out[12..16].copy_from_slice(&self.num_offload_reorder_buffs.to_le_bytes());
        out[16..20].copy_from_slice(&self.num_peer_keys.to_le_bytes());
        out[20..24].copy_from_slice(&self.num_tids.to_le_bytes());
        out[24..28].copy_from_slice(&self.ast_skid_limit.to_le_bytes());
        out[28..32].copy_from_slice(&self.tx_chain_mask.to_le_bytes());
        out[32..36].copy_from_slice(&self.rx_chain_mask.to_le_bytes());
        out[36..40].copy_from_slice(&self.rx_decap_mode.to_le_bytes());
        out
    }
}

/// Build a minimal WMI_INIT command — `cmd_hdr` + INIT_CMD tag
/// (empty payload) + RESOURCE_CONFIG. Real firmware-load tests
/// will need to add HOST_MEM_CHUNK entries; the builder above
/// supports those via `push_tlv`.
pub fn build_init_cmd(rc: &ResourceConfig) -> Vec<u8> {
    let mut b = WmiCmdBuilder::new(WMI_INIT_CMDID);
    b.push_tlv(WMI_TAG_INIT_CMD, &[]);
    b.push_tlv(WMI_TAG_RESOURCE_CONFIG, &rc.to_bytes());
    b.finish()
}
