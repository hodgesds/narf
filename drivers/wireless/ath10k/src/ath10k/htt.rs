//! HTT (Host-Target Transport) — ath10k RX ring setup and
//! RX-indication frame decoder.
//!
//! HTT is the data-plane channel layered over Copy Engines 4/5.
//! CE4 carries HTT H2T commands (TX, RX-ring config) from host to
//! firmware; CE5 carries HTT T2H messages (RX indications, TX
//! completions) from firmware to host.
//!
//! ## RX ring layout
//!
//! The host allocates a flat ring of 2048-byte buffers and communicates
//! the ring to firmware via an `HTT_H2T_MSG_TYPE_RX_RING_CFG` command.
//! Firmware then DMA-writes received 802.11 MSDUs into those buffers
//! and notifies the host with `HTT_T2H_MSG_TYPE_RX_IND` indications.
//!
//! This module implements:
//!   1. `HttRxRingSetup` — the `RX_RING_CFG` command payload.
//!   2. `HttRxIndHdr` + `HttRxIndMpduRange` — parsing the T2H
//!      `RX_IND` indication.
//!   3. Completion drain: iterate pending indications and post
//!      decoded frames to the upper layer.
//!
//! ## References (Linux `drivers/net/wireless/ath/ath10k/`)
//!
//! - `htt.h` lines 238-242 — HTT_RX_RING_SIZE / FILL_LEVEL constants.
//! - `htt.h` lines 258-292 — `htt_rx_ring_setup_ring32` layout.
//! - `htt.h` lines 591-730 — RX indication header + PPDU + mpdu_ranges.
//! - `htt_rx.c` lines 136-214 — `__ath10k_htt_rx_ring_fill_n`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::convert::TryInto;

// ── RX ring constants ──────────────────────────────────────────────

/// Number of RX buffer slots in the ring.
/// Mirrors `HTT_RX_RING_SIZE = HTT_RX_RING_SIZE_MAX = 2048` in
/// `htt.h` line 240.
pub const HTT_RX_RING_SIZE: u16 = 2048;

/// Initial fill level: half of the ring.
/// `HTT_RX_RING_FILL_LEVEL = (HTT_RX_RING_SIZE / 2) - 1`.
/// `htt.h` line 241.
pub const HTT_RX_RING_FILL_LEVEL: u16 = (HTT_RX_RING_SIZE / 2) - 1;

/// Per-slot buffer size in bytes. Firmware writes one MSDU per slot.
/// Linux uses 2048 for most chips (`htt_rx.c` line ~154).
pub const HTT_RX_BUF_SIZE: u16 = 2048;

// ── HTT H2T message type ───────────────────────────────────────────

/// `htt.h::enum htt_h2t_msg_type`.
pub mod h2t_msg_type {
    /// Version-string request. Host sends this first.
    pub const VERSION_REQ: u8 = 0;
    /// TX descriptor push.
    pub const TX_FRM: u8 = 1;
    /// RX ring configuration. Tells firmware where to put RX frames.
    pub const RX_RING_CFG: u8 = 2;
    /// Add/remove RX REORDER (A-MPDU) entry.
    pub const RX_ADDBA: u8 = 5;
    pub const RX_DELBA: u8 = 6;
    /// HTT flush request.
    pub const FLUSH: u8 = 9;
}

/// `htt.h::enum htt_t2h_msg_type` — firmware→host.
pub mod t2h_msg_type {
    pub const VERSION_CONF: u8 = 0;
    /// RX data indication — the main path.
    pub const RX_IND: u8 = 1;
    pub const RX_FLUSH: u8 = 2;
    pub const PEER_MAP: u8 = 3;
    pub const TX_COMPL_IND: u8 = 8;
}

// ── RX ring setup command ──────────────────────────────────────────
//
// Layout from `htt.h::struct htt_rx_ring_setup_ring32` +
// `htt_rx_ring_rx_desc_offsets`. The host sends this once at boot
// to tell firmware the physical address, depth, and slot layout of
// the RX buffer ring.

/// Receive descriptor field offsets. Values are in 4-byte units
/// relative to the start of each RX buffer.
///
/// Source: `htt.h::struct htt_rx_ring_rx_desc_offsets`
/// (Linux line ~244-256).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RxDescOffsets {
    pub mac80211_hdr_offset: u16,
    pub msdu_payload_offset: u16,
    pub ppdu_start_offset: u16,
    pub ppdu_end_offset: u16,
    pub mpdu_start_offset: u16,
    pub mpdu_end_offset: u16,
    pub msdu_start_offset: u16,
    pub msdu_end_offset: u16,
    pub rx_attention_offset: u16,
    pub frag_info_offset: u16,
}

/// `HTT_H2T_MSG_TYPE_RX_RING_CFG` command payload.
///
/// The msg_type prefix and a 1-byte num_rings are not included here —
/// they are prepended by the caller when handing to the CE4 ring.
///
/// Source: `htt.h::struct htt_rx_ring_setup_ring32` (line 258-268).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct HttRxRingSetup32 {
    /// Firmware write-index shadow register paddr (little-endian).
    /// Firmware bumps this as it consumes buffers; host polls it to
    /// know how many slots are free.
    pub fw_idx_shadow_reg_paddr: u32,
    /// Physical address of the ring base (slot-0 buffer paddr).
    pub rx_ring_base_paddr: u32,
    /// Ring depth in 4-byte words (so 2048-byte buffers → 512 words).
    /// `rx_ring_len = HTT_RX_RING_SIZE * HTT_RX_BUF_SIZE / 4`.
    pub rx_ring_len: u16,
    /// Per-slot buffer size in bytes.
    pub rx_ring_bufsize: u16,
    /// `HTT_RX_RING_FLAGS_*` bitmask. Unicast + multicast data.
    pub flags: u16,
    /// Initial write-index (= fill-level we pre-post on boot).
    pub fw_idx_init_val: u16,
    /// Descriptor field offsets. In practice Linux sets these to
    /// chip-specific values; for the smoke we set all to 0.
    pub offsets: RxDescOffsets,
}

/// RX ring flags (from `htt.h::enum htt_rx_ring_flags`).
pub mod rx_ring_flags {
    pub const UNICAST_RX: u16 = 1 << 10;
    pub const MULTICAST_RX: u16 = 1 << 11;
    pub const CTRL_RX: u16 = 1 << 12;
    pub const MGMT_RX: u16 = 1 << 13;
    pub const NULL_RX: u16 = 1 << 14;
    pub const PHY_DATA_RX: u16 = 1 << 15;
}

/// Build the `HttRxRingSetup32` payload for the standard bring-up
/// configuration (unicast + multicast, ring size 2048, buf size 2048).
///
/// `ring_base_paddr` — host physical address of the ring base.
/// `fw_idx_shadow_paddr` — host physical address of the firmware
///   shadow write-index DWORD (must be 4-byte aligned, zeroed at boot).
pub fn build_rx_ring_setup(ring_base_paddr: u32, fw_idx_shadow_paddr: u32) -> HttRxRingSetup32 {
    HttRxRingSetup32 {
        fw_idx_shadow_reg_paddr: fw_idx_shadow_paddr,
        rx_ring_base_paddr: ring_base_paddr,
        // Ring depth in 4-byte words: 2048 slots × 2048 bytes / 4 = 1 048 576 words.
        // Linux stores the slot count here, not the word count, in the v2 variant.
        // For 32-bit ring the field is slot count (`rx_ring_len = num_slots`).
        rx_ring_len: HTT_RX_RING_SIZE,
        rx_ring_bufsize: HTT_RX_BUF_SIZE,
        flags: rx_ring_flags::UNICAST_RX | rx_ring_flags::MULTICAST_RX | rx_ring_flags::MGMT_RX,
        fw_idx_init_val: HTT_RX_RING_FILL_LEVEL,
        offsets: RxDescOffsets::default(),
    }
}

/// Encode `HttRxRingSetup32` into a flat byte vec, prepended by the
/// HTT H2T header: `[msg_type=2][num_rings=1][pad=0]`.
/// Total = 4 bytes header + size_of(HttRxRingSetup32).
pub fn encode_rx_ring_cfg(setup: &HttRxRingSetup32) -> Vec<u8> {
    let body_size = core::mem::size_of::<HttRxRingSetup32>();
    let mut out = Vec::with_capacity(4 + body_size);
    // HTT H2T header: msg_type | (num_rings << 16) packed LE.
    //   byte 0: msg_type = HTT_H2T_MSG_TYPE_RX_RING_CFG = 2
    //   byte 1: num_rings = 1
    //   bytes 2-3: reserved / pad
    out.push(h2t_msg_type::RX_RING_CFG);
    out.push(1u8); // num_rings
    out.push(0u8);
    out.push(0u8);
    // Serialize HttRxRingSetup32 field by field (avoids packed-ref UB).
    out.extend_from_slice(&setup.fw_idx_shadow_reg_paddr.to_le_bytes());
    out.extend_from_slice(&setup.rx_ring_base_paddr.to_le_bytes());
    out.extend_from_slice(&setup.rx_ring_len.to_le_bytes());
    out.extend_from_slice(&setup.rx_ring_bufsize.to_le_bytes());
    out.extend_from_slice(&setup.flags.to_le_bytes());
    out.extend_from_slice(&setup.fw_idx_init_val.to_le_bytes());
    // RxDescOffsets (10 × u16 = 20 bytes).
    let o = &setup.offsets;
    out.extend_from_slice(&o.mac80211_hdr_offset.to_le_bytes());
    out.extend_from_slice(&o.msdu_payload_offset.to_le_bytes());
    out.extend_from_slice(&o.ppdu_start_offset.to_le_bytes());
    out.extend_from_slice(&o.ppdu_end_offset.to_le_bytes());
    out.extend_from_slice(&o.mpdu_start_offset.to_le_bytes());
    out.extend_from_slice(&o.mpdu_end_offset.to_le_bytes());
    out.extend_from_slice(&o.msdu_start_offset.to_le_bytes());
    out.extend_from_slice(&o.msdu_end_offset.to_le_bytes());
    out.extend_from_slice(&o.rx_attention_offset.to_le_bytes());
    out.extend_from_slice(&o.frag_info_offset.to_le_bytes());
    out
}

// ── HTT T2H RX indication decoder ──────────────────────────────────
//
// When the device finishes receiving one or more MPDUs, it posts an
// `RX_IND` T2H message on CE5. We decode just enough of it to learn
// how many MPDUs arrived and their status.
//
// Source: `htt.h::struct htt_rx_indication` (line 713-730) and
// `htt_rx_indication_hdr` (line 591).

/// Decoded `htt_rx_indication_hdr` — first 8 bytes of an RX_IND.
///
/// Sourced from `htt.h::struct htt_rx_indication_hdr` (line 591).
#[derive(Copy, Clone, Debug, Default)]
pub struct HttRxIndHdr {
    /// `info0` bits[7:0]. Bit 7 = START_VALID, bit 6 = END_VALID.
    pub info0: u8,
    /// Peer ID (which station sent the frames).
    pub peer_id: u16,
    /// `info1` encodes VHT SIG and preamble type.
    pub info1: u32,
}

/// One MPDU range entry from the tail of an RX_IND.
///
/// Source: `htt.h::struct htt_rx_indication_mpdu_range` (line 700).
#[derive(Copy, Clone, Debug, Default)]
pub struct HttRxIndMpduRange {
    /// Number of MPDUs in this range.
    pub mpdu_count: u8,
    /// Status code (`htt_rx_mpdu_status`).
    pub mpdu_range_status: u8,
}

/// MPDU status codes from `htt.h::enum htt_rx_mpdu_status`.
pub mod mpdu_status {
    pub const UNKNOWN: u8 = 0x00;
    pub const OK: u8 = 0x01;
    pub const ERR_FCS: u8 = 0x02;
    pub const ERR_DUP: u8 = 0x03;
    pub const ERR_REPLAY: u8 = 0x04;
    pub const ERR_INV_PEER: u8 = 0x05;
    pub const MISC_ERR: u8 = 0xFF;
}

/// Minimal decoded RX indication.
#[derive(Debug, Default)]
pub struct RxIndication {
    pub hdr: HttRxIndHdr,
    /// MPDU count extracted from the first mpdu_range entry.
    pub mpdu_count: u8,
    /// Status from the first mpdu_range entry.
    pub mpdu_status: u8,
    /// Total number of mpdu_range entries.
    pub num_mpdu_ranges: usize,
}

/// T2H message type byte offset in an HTT message.
const T2H_MSG_TYPE_OFFSET: usize = 0;
/// RX_IND header starts at byte 1 (after msg_type byte).
const RX_IND_HDR_OFFSET: usize = 1;
/// Size of the RX_IND hdr fields we parse (msg_type + info0 + peer_id + info1).
const RX_IND_FIXED_HDR_SIZE: usize = 8;
/// PPDU info block size (Linux `struct htt_rx_indication_ppdu` = 44 bytes).
const RX_IND_PPDU_SIZE: usize = 44;
/// prefix (fw_rx_desc_bytes u16 + 2 pad) = 4 bytes.
const RX_IND_PREFIX_SIZE: usize = 4;

/// Decode a T2H RX indication message. Returns `None` if the message
/// is too short or is not an RX_IND type.
///
/// The PPDU block and fw_rx_desc bytes are skipped — we only care
/// about the num_mpdu_ranges and the first mpdu_range entry for the
/// bring-up path.
pub fn decode_rx_indication(msg: &[u8]) -> Option<RxIndication> {
    // Minimum length: msg_type(1) + hdr(7) + ppdu(44) + prefix(4).
    const MIN_LEN: usize = 1 + 7 + RX_IND_PPDU_SIZE + RX_IND_PREFIX_SIZE;
    if msg.len() < MIN_LEN {
        return None;
    }
    if msg[T2H_MSG_TYPE_OFFSET] != t2h_msg_type::RX_IND {
        return None;
    }
    // Parse htt_rx_indication_hdr: starts at byte 1.
    //   byte 1: info0
    //   bytes 2-3: peer_id (LE)
    //   bytes 4-7: info1 (LE)
    let info0 = msg[1];
    let peer_id = u16::from_le_bytes(msg[2..4].try_into().ok()?);
    let info1 = u32::from_le_bytes(msg[4..8].try_into().ok()?);
    let hdr = HttRxIndHdr {
        info0,
        peer_id,
        info1,
    };

    // Skip: PPDU (44 bytes starting at offset 8).
    // prefix: bytes at offset 8+44 = 52.
    let prefix_start = 1 + 7 + RX_IND_PPDU_SIZE;
    let fw_rx_desc_bytes =
        u16::from_le_bytes(msg[prefix_start..prefix_start + 2].try_into().ok()?) as usize;

    // fw_rx_desc follows prefix (4 bytes), rounded up to 4-byte alignment.
    let fw_desc_end = prefix_start + RX_IND_PREFIX_SIZE + ((fw_rx_desc_bytes + 3) & !3);

    // mpdu_ranges follow fw_desc.
    let mpdu_ranges_start = fw_desc_end;
    const MPDU_RANGE_SIZE: usize = 4; // mpdu_count(1) + status(1) + 2 pad
    let remaining = msg.len().saturating_sub(mpdu_ranges_start);
    let num_mpdu_ranges = remaining / MPDU_RANGE_SIZE;

    let (mpdu_count, mpdu_status) =
        if num_mpdu_ranges > 0 && mpdu_ranges_start + MPDU_RANGE_SIZE <= msg.len() {
            (msg[mpdu_ranges_start], msg[mpdu_ranges_start + 1])
        } else {
            (0, 0)
        };

    Some(RxIndication {
        hdr,
        mpdu_count,
        mpdu_status,
        num_mpdu_ranges,
    })
}

// ── RX completion drain ─────────────────────────────────────────────

/// A minimal RX slot: the physical address and a consumed flag.
/// In the real path each slot maps to a DMA-coherent 2 KiB buffer.
#[derive(Clone, Debug, Default)]
pub struct RxSlot {
    /// Physical address of the buffer (host DMA address).
    pub paddr: u64,
    /// Set to `true` once firmware has consumed this slot.
    pub consumed: bool,
}

/// Drain up to `max_frames` completed RX indications. For each
/// completed indication the caller-supplied callback `on_frame` is
/// invoked with `(peer_id, mpdu_count, mpdu_status)`.
///
/// In the production path `pending_indications` is the list of
/// decoded T2H messages staged by the CE5 completion ISR; `slots`
/// is the RX buffer ring.
pub fn drain_rx_completions<F>(
    pending_indications: &[RxIndication],
    max_frames: usize,
    mut on_frame: F,
) -> usize
where
    F: FnMut(u16, u8, u8), // peer_id, mpdu_count, status
{
    let mut processed = 0;
    for ind in pending_indications.iter().take(max_frames) {
        on_frame(ind.hdr.peer_id, ind.mpdu_count, ind.mpdu_status);
        processed += 1;
    }
    processed
}
