//! MT7921 / MT7922 MAC TX descriptor (TXD) and RX descriptor (RXD)
//! encoders — Stage-3.
//!
//! ## TX descriptor (TXD)
//!
//! The CONNAC2 TXD is an 8-dword (32-byte) descriptor prepended to
//! every frame the host submits on a WFDMA TX ring. The bit-field
//! layout comes from Linux's
//! `drivers/net/wireless/mediatek/mt76/mt76_connac2_mac.h` (v6.6,
//! ~L50..L128) and the fill logic from
//! `drivers/net/wireless/mediatek/mt76/mt76_connac2_mac.c::
//! mt76_connac2_mac_write_txwi` (~L1..L90).
//!
//! This file provides a pure-data encoder that takes the key per-frame
//! fields and marshals them into the 32-byte wire layout. The DMA
//! submission path (WFDMA0 ring pointer writes) sits in the `mac.rs`
//! hardware layer and is not represented here.
//!
//! ## RX descriptor (RXD)
//!
//! The CONNAC2 RXD is a 16-byte prefix on every inbound frame. The
//! host reads these from `MT7921_RXQ_DATA` after the WFDMA RX interrupt
//! fires and uses them to determine the payload length and any error
//! conditions.
//!
//! Bit-field source: `mt76_connac2_mac.h` (~L185..L232).
//!
//! ## MCU init / STA-record commands
//!
//! `MCU_EXT_CMD_STA_REC_UPDATE` (opcode 0x25, from
//! `mt76_connac_mcu.h:1226`) registers a station entry with the
//! firmware's MAC layer. This is the minimum MCU command needed after
//! `take_driver_own` before data-path traffic can flow.
//!
//! Reference:
//!   `drivers/net/wireless/mediatek/mt76/mt76_connac_mcu.c::
//!    mt76_connac_mcu_sta_cmd` (~L1..L50)

#![allow(dead_code)]

// ── TXD bit-field constants ─────────────────────────────────────────
//
// Per Linux `mt76_connac2_mac.h` (~L50..L128). Each TXD dword index
// is prefixed with the dword number (TXD0..TXD7).

/// TXD dword 0 — queue index + packet format + byte count.
///
/// `MT_TXD0_Q_IDX`  = GENMASK(31, 25).  Queue/ring index.
/// `MT_TXD0_PKT_FMT`= GENMASK(24, 23).  Packet format:
///     0 = 802.11 (L-SIG), 1 = CT (control token), 2 = 802.3.
/// `MT_TXD0_TX_BYTES`= GENMASK(15, 0).  Total bytes (TXD + frame).
pub const TXD0_Q_IDX_SHIFT: u32 = 25;
pub const TXD0_Q_IDX_MASK: u32 = 0x7F << TXD0_Q_IDX_SHIFT;
pub const TXD0_PKT_FMT_SHIFT: u32 = 23;
pub const TXD0_PKT_FMT_MASK: u32 = 0x3 << TXD0_PKT_FMT_SHIFT;
/// Packet format: 802.3 Ethernet (the default for data frames the MCU
/// re-encaps to 802.11).
pub const TXD0_PKT_FMT_802_3: u32 = 2 << TXD0_PKT_FMT_SHIFT;
pub const TXD0_TX_BYTES_MASK: u32 = 0xFFFF;

/// TXD dword 1 — long-format flag + own-MAC + WLAN-IDX.
///
/// `MT_TXD1_LONG_FORMAT` = BIT(31).   Set for the 8-dword (long) form.
/// `MT_TXD1_OWN_MAC`     = GENMASK(29, 24). BSS / own-MAC index.
/// `MT_TXD1_WLAN_IDX`    = GENMASK(9, 0).  Per-station WLAN index.
pub const TXD1_LONG_FORMAT: u32 = 1 << 31;
pub const TXD1_OWN_MAC_SHIFT: u32 = 24;
pub const TXD1_OWN_MAC_MASK: u32 = 0x3F << TXD1_OWN_MAC_SHIFT;
pub const TXD1_WLAN_IDX_MASK: u32 = 0x3FF;

/// TXD dword 2 — fixed-rate + fragment + misc flags.
///
/// `MT_TXD2_MULTICAST` = BIT(10). Frame is multicast/broadcast.
/// `MT_TXD2_NO_NAT`    = BIT(6).  Disable NAT translation.
pub const TXD2_MULTICAST: u32 = 1 << 10;

/// TXD dword 3 — sequence + retry.
///
/// `MT_TXD3_NO_ACK`    = BIT(0).  No ACK requested (broadcast).
pub const TXD3_NO_ACK: u32 = 1 << 0;

/// TXD dword 5 — TX status reporting.
///
/// `MT_TXD5_TX_STATUS_HOST` = BIT(10). Report TX status to host.
/// `MT_TXD5_PID`            = GENMASK(7, 0). Packet-ID echo.
pub const TXD5_TX_STATUS_HOST: u32 = 1 << 10;
pub const TXD5_PID_MASK: u32 = 0xFF;

/// Wire size of the short (4-dword) TXD.
pub const TXD_SHORT_SIZE: usize = 16;
/// Wire size of the long (8-dword) TXD used for data frames.
/// `MT_TXD_SIZE`. Linux `mt76_connac.h:34`.
pub const TXD_SIZE: usize = 32;

// ── RXD bit-field constants ─────────────────────────────────────────
//
// Per Linux `mt76_connac2_mac.h` (~L185..L232).

/// RXD dword 0 — packet length + type.
///
/// `MT_RXD0_LENGTH`   = GENMASK(15, 0). Total frame length.
/// `MT_RXD0_PKT_TYPE` = GENMASK(31, 27). Type: 0=normal, 1=event.
pub const RXD0_LENGTH_MASK: u32 = 0xFFFF;
pub const RXD0_PKT_TYPE_SHIFT: u32 = 27;
pub const RXD0_PKT_TYPE_MASK: u32 = 0x1F << RXD0_PKT_TYPE_SHIFT;
/// Packet type: normal data frame.
pub const RXD0_PKT_TYPE_NORMAL: u32 = 0;
/// Packet type: MCU event frame (delivered to `RXQ_MCU_EVENT`).
pub const RXD0_PKT_TYPE_EVENT: u32 = 1 << RXD0_PKT_TYPE_SHIFT;

/// RXD dword 1 — WLAN index + security + error flags.
///
/// `MT_RXD1_NORMAL_WLAN_IDX` = GENMASK(9, 0).
/// `MT_RXD1_NORMAL_FCS_ERR`  = BIT(27). FCS error.
/// `MT_RXD1_NORMAL_ICV_ERR`  = BIT(25). ICV error.
pub const RXD1_WLAN_IDX_MASK: u32 = 0x3FF;
pub const RXD1_FCS_ERR: u32 = 1 << 27;
pub const RXD1_ICV_ERR: u32 = 1 << 25;

/// RXD dword 2 — BSSID + header offset.
///
/// `MT_RXD2_NORMAL_HDR_OFFSET` = GENMASK(15, 14).
///     0 = 0 extra bytes, 1 = 2 bytes, 2 = 6 bytes (802.3 Eth header).
pub const RXD2_HDR_OFFSET_SHIFT: u32 = 14;
pub const RXD2_HDR_OFFSET_MASK: u32 = 0x3 << RXD2_HDR_OFFSET_SHIFT;

/// Wire size of the base RXD (4 dwords = 16 bytes).
/// Per Linux `mt76_connac2_mac.h` the normal RXD is 4 dwords; extended
/// group descriptors (groups 1-5) follow but are optional.
pub const RXD_BASE_SIZE: usize = 16;

// ── MCU command opcodes ─────────────────────────────────────────────
//
// Per `mt76_connac_mcu.h`.

/// `MCU_EXT_CMD_STA_REC_UPDATE` — register / update a station record.
/// Opcode 0x25. Linux `mt76_connac_mcu.h:1226`.
pub const MCU_EXT_CMD_STA_REC_UPDATE: u8 = 0x25;

/// `MCU_CMD_PATCH_SEM_CONTROL` — patch semaphore acquire/release.
/// Opcode 0x10. Linux `mt76_connac_mcu.h:1322`.
pub const MCU_CMD_PATCH_SEM_CONTROL: u8 = 0x10;

/// `MCU_CMD_PATCH_FINISH_REQ` — signal patch download is complete.
/// Opcode 0x07. Linux `mt76_connac_mcu.h:1321`.
pub const MCU_CMD_PATCH_FINISH_REQ: u8 = 0x07;

// ── TXD encoder ─────────────────────────────────────────────────────

/// Inputs for building one MT7921 TXD.
///
/// Derived from the fields `mt76_connac2_mac_write_txwi` sets in
/// `mt76_connac2_mac.c` (~L1..L90, v6.6).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TxdInfo {
    /// WFDMA TX queue index. Typically one of `MT7921_TXQ_AC_*`.
    pub q_idx: u8,
    /// Per-station WLAN index (firmware-assigned). 0 for broadcast.
    pub wlan_idx: u16,
    /// BSS / own-MAC index (0 for the default STA interface).
    pub own_mac_idx: u8,
    /// Total frame byte count (includes TXD itself).
    pub tx_bytes: u16,
    /// Frame is multicast / broadcast (disables ACK).
    pub is_mcast: bool,
    /// Packet-ID for TX-status correlation.
    pub pid: u8,
}

/// Encode a TXD into `out` (must be `≥ TXD_SIZE` = 32 bytes).
///
/// The 8-dword long form (`MT_TXD1_LONG_FORMAT`) is always used for
/// data frames. Dwords 4-7 are reserved/zeroed at this stage — the
/// rate-selection and security fields are filled by the firmware or
/// set by the TX-info follow-up.
///
/// Reference: Linux `mt76_connac2_mac.c::mt76_connac2_mac_write_txwi`
/// (~L1..L90).
pub fn encode_txd(info: &TxdInfo, out: &mut [u8]) -> Option<()> {
    if out.len() < TXD_SIZE {
        return None;
    }
    // Dword 0: queue index + 802.3 packet format + byte count.
    let dw0: u32 = ((info.q_idx as u32) << TXD0_Q_IDX_SHIFT) & TXD0_Q_IDX_MASK
        | TXD0_PKT_FMT_802_3
        | ((info.tx_bytes as u32) & TXD0_TX_BYTES_MASK);
    out[0..4].copy_from_slice(&dw0.to_le_bytes());

    // Dword 1: long-format flag + own-MAC + wlan-idx.
    let dw1: u32 = TXD1_LONG_FORMAT
        | (((info.own_mac_idx as u32) << TXD1_OWN_MAC_SHIFT) & TXD1_OWN_MAC_MASK)
        | ((info.wlan_idx as u32) & TXD1_WLAN_IDX_MASK);
    out[4..8].copy_from_slice(&dw1.to_le_bytes());

    // Dword 2: multicast flag if applicable.
    let dw2: u32 = if info.is_mcast { TXD2_MULTICAST } else { 0 };
    out[8..12].copy_from_slice(&dw2.to_le_bytes());

    // Dword 3: NO_ACK for multicast frames (no ACK expected).
    let dw3: u32 = if info.is_mcast { TXD3_NO_ACK } else { 0 };
    out[12..16].copy_from_slice(&dw3.to_le_bytes());

    // Dword 4-4: reserved (PN low — only used for encrypted frames).
    out[16..20].fill(0);

    // Dword 5: TX status reporting + PID.
    let dw5: u32 = TXD5_TX_STATUS_HOST | ((info.pid as u32) & TXD5_PID_MASK);
    out[20..24].copy_from_slice(&dw5.to_le_bytes());

    // Dwords 6-7: rate / BW overrides. Leave at 0 so firmware chooses.
    out[24..TXD_SIZE].fill(0);

    Some(())
}

// ── RXD decoder ─────────────────────────────────────────────────────

/// Decoded fields from the 16-byte base RXD.
///
/// The host reads this from `MT7921_RXQ_DATA` after the DMA interrupt,
/// uses `frame_len` to locate the payload in the DMA buffer, and checks
/// the error bits before handing the frame upward.
///
/// Reference: Linux `mt76_connac2_mac.c::mt7921_mac_decode_rx_desc`
/// and the RXD field layout in `mt76_connac2_mac.h` (~L185..L232).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RxdInfo {
    /// Total length of the received frame payload in bytes.
    pub frame_len: u16,
    /// Packet type: 0 = normal data, 1 = MCU event.
    pub pkt_type: u8,
    /// WLAN index (station that sent the frame).
    pub wlan_idx: u16,
    /// FCS error — frame should be dropped.
    pub fcs_err: bool,
    /// ICV (MIC/CCMP) error — encrypted frame failed integrity check.
    pub icv_err: bool,
}

/// Decode the base RXD from `bytes` (must be `≥ RXD_BASE_SIZE` = 16
/// bytes).
///
/// Returns `None` if the slice is too short.
pub fn decode_rxd(bytes: &[u8]) -> Option<RxdInfo> {
    if bytes.len() < RXD_BASE_SIZE {
        return None;
    }
    let dw0 = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let dw1 = u32::from_le_bytes(bytes[4..8].try_into().ok()?);

    let frame_len = (dw0 & RXD0_LENGTH_MASK) as u16;
    let pkt_type = ((dw0 & RXD0_PKT_TYPE_MASK) >> RXD0_PKT_TYPE_SHIFT) as u8;
    let wlan_idx = (dw1 & RXD1_WLAN_IDX_MASK) as u16;
    let fcs_err = (dw1 & RXD1_FCS_ERR) != 0;
    let icv_err = (dw1 & RXD1_ICV_ERR) != 0;

    Some(RxdInfo {
        frame_len,
        pkt_type,
        wlan_idx,
        fcs_err,
        icv_err,
    })
}

/// Build the minimal 16-byte RXD byte pattern for a clean data frame
/// of the given length and wlan index. Used in round-trip tests to
/// exercise the decoder without live silicon.
pub fn encode_rxd_for_test(info: &RxdInfo) -> [u8; RXD_BASE_SIZE] {
    let mut buf = [0u8; RXD_BASE_SIZE];
    let dw0: u32 = ((info.pkt_type as u32) << RXD0_PKT_TYPE_SHIFT)
        | (info.frame_len as u32 & RXD0_LENGTH_MASK);
    let dw1: u32 = (info.wlan_idx as u32 & RXD1_WLAN_IDX_MASK)
        | if info.fcs_err { RXD1_FCS_ERR } else { 0 }
        | if info.icv_err { RXD1_ICV_ERR } else { 0 };
    buf[0..4].copy_from_slice(&dw0.to_le_bytes());
    buf[4..8].copy_from_slice(&dw1.to_le_bytes());
    // dwords 2-3 stay zeroed (BSSID / HDR_OFFSET / etc.).
    buf
}

// ── MCU STA-record command encoder ──────────────────────────────────

/// Wire size of the minimal `STA_REC_UPDATE` MCU command payload.
/// The actual command carries a much larger structure on Linux; the
/// NARF baseline ships only the 8-byte opcode header + 4-byte tag/len.
/// Full station-record payloads land with the association path.
pub const STA_REC_CMD_SIZE: usize = 12;

/// Build the minimal `MCU_EXT_CMD_STA_REC_UPDATE` command payload.
///
/// Layout (12 bytes, all LE):
///
/// ```text
///   byte 0:    opcode = MCU_EXT_CMD_STA_REC_UPDATE (0x25)
///   bytes 1-3: reserved (must be zero)
///   bytes 4-7: WLAN index (u32 LE)
///   bytes 8-11: tag bitmap (u32 LE) — 0 = minimal (no cipher / BA setup)
/// ```
///
/// Reference: Linux `mt76_connac_mcu.c::mt76_connac_mcu_sta_cmd`
/// (~L1..L50). The full command is up to 256 bytes; this 12-byte form
/// is the baseline "register station exists, no crypto" entry.
pub fn encode_sta_rec_update(wlan_idx: u16, out: &mut [u8]) -> Option<()> {
    if out.len() < STA_REC_CMD_SIZE {
        return None;
    }
    out[0] = MCU_EXT_CMD_STA_REC_UPDATE;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..8].copy_from_slice(&(wlan_idx as u32).to_le_bytes());
    out[8..STA_REC_CMD_SIZE].fill(0); // tag bitmap = 0
    Some(())
}

use core::convert::TryInto;

// ── Stage-13/14: live TX submit + RX drain (uses dma::Ring) ──────

use super::dma::{
    ring_dma_index, ring_doorbell, Ring, RingRegs, MT_DMA_CTL_BURST, MT_DMA_CTL_DMA_DONE,
    MT_DMA_CTL_LAST_SEC0, MT_DMA_CTL_SD_LEN0_MASK, MT_DMA_CTL_SD_LEN0_SHIFT,
};
use narf_bus::MmioRegion;

/// Errors raised by the live TX/RX submit + drain paths.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxRxError {
    /// TX ring is full — caller should retry after the next drain.
    RingFull,
    /// Frame is too large for one descriptor (> SD_LEN0 max =
    /// `MT_DMA_CTL_SD_LEN0_MASK`).
    FrameTooBig,
    /// Encoded TXD was too short to be valid (programmer bug).
    BadTxd,
    /// The frame's DMA buffer alloc failed.
    BufferAllocFailed,
}

/// Submit one frame to the given TX ring. Builds a TXD prefix into a
/// per-frame DmaBuffer, copies the payload behind it, points the
/// next free descriptor at the buffer, and bumps the host pointer
/// + doorbell.
///
/// The caller has already called `program_ring` for this ring's
/// MMIO offsets, so the engine knows where the descriptor table
/// lives.
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device.
pub unsafe fn submit_tx_frame(
    mmio: &MmioRegion,
    ring: &mut Ring,
    regs: RingRegs,
    info: &TxdInfo,
    payload: &[u8],
) -> Result<(), TxRxError> {
    let total_len = TXD_SIZE + payload.len();
    let max_sd_len = (MT_DMA_CTL_SD_LEN0_MASK >> MT_DMA_CTL_SD_LEN0_SHIFT) as usize;
    if total_len > max_sd_len {
        return Err(TxRxError::FrameTooBig);
    }

    // Detect full ring before we mutate anything: (cpu_idx + 1) %
    // depth would catch up to hw_idx.
    let depth = ring.depth();
    let next_cpu = (ring.cpu_idx() + 1) % depth;
    if next_cpu == ring.hw_idx() {
        return Err(TxRxError::RingFull);
    }

    // Allocate a coherent buffer for this frame. The descriptor's
    // buf0 will point at it, so it stays live until the next time
    // this slot is reused (reap_tx).
    let mut buf = narf_io::alloc_coherent(total_len.max(64), narf_lib::id::DomainId::DRIVER_0)
        .map_err(|_| TxRxError::BufferAllocFailed)?;
    let phys = buf.phys_addr().as_u64();
    {
        let bytes = buf.as_mut_slice();
        // Encode the TXD at the head of the buffer.
        if encode_txd(info, &mut bytes[..TXD_SIZE]).is_none() {
            return Err(TxRxError::BadTxd);
        }
        bytes[TXD_SIZE..TXD_SIZE + payload.len()].copy_from_slice(payload);
    }

    // Find the next free descriptor.
    let slot = ring.cpu_idx();
    {
        let descs = ring.descriptors_mut();
        let d = &mut descs[slot];
        d.buf0 = phys as u32;
        d.buf1 = ((phys >> 32) as u32) & 0x0F;
        d.ctrl = ((total_len as u32) << MT_DMA_CTL_SD_LEN0_SHIFT) & MT_DMA_CTL_SD_LEN0_MASK
            | MT_DMA_CTL_LAST_SEC0
            | MT_DMA_CTL_BURST;
        d.info = 0;
    }
    // Stash the buffer in the ring so it lives until reaped.
    // We grow the pool to match the ring depth lazily.
    // The caller's `Ring` keeps the buffers in `ring.buffers`.
    // Use a Vec push — slot index == buffers.len() for the first
    // pass, and subsequent submits reuse the same DmaBuffer slot
    // by replacing it. For the baseline we just append; Stage-14's
    // reap-tx swaps in place.
    //
    // Since we can't directly index into `ring.buffers` mutably
    // (the API only returns &[DmaBuffer]), we expose a setter.
    ring.set_tx_buffer(slot, buf);

    // Advance CPU pointer and ring the doorbell.
    ring.set_cpu_idx(next_cpu);
    // SAFETY: BAR0 mapped + owned per `# Safety`.
    unsafe { ring_doorbell(mmio, regs, ring.cpu_idx() as u32) };
    Ok(())
}

/// Drain the RX ring: walk descriptors from `hw_idx` forward, decode
/// each completed frame (DMA_DONE bit set), invoke `f` with the
/// payload bytes, then re-arm the descriptor and bump the host
/// pointer + doorbell.
///
/// Returns the number of frames drained.
///
/// # Safety
/// BAR0 mapped + owned.
pub unsafe fn drain_rx(
    mmio: &MmioRegion,
    ring: &mut Ring,
    regs: RingRegs,
    mut f: impl FnMut(&[u8], RxdInfo),
) -> usize {
    // SAFETY: BAR0 mapped + owned.
    let new_hw = unsafe { ring_dma_index(mmio, regs) } as usize;
    let depth = ring.depth();
    if depth == 0 {
        return 0;
    }
    let new_hw = new_hw % depth;

    let mut drained = 0usize;
    let mut idx = ring.hw_idx();
    while idx != new_hw {
        // Read the descriptor and the per-entry buffer.
        let (ctrl, _buf0, _buf1) = {
            let descs = ring.descriptors();
            let d = descs[idx];
            (d.ctrl, d.buf0, d.buf1)
        };
        // Skip descriptors the HW didn't mark done (shouldn't happen
        // if `new_hw` is fresh).
        if (ctrl & MT_DMA_CTL_DMA_DONE) == 0 {
            break;
        }
        // The per-entry buffer carries the RXD prefix + payload.
        let bufs = ring.buffers();
        let buf = &bufs[idx];
        let bytes = buf.as_slice();
        // Decode the RXD.
        let decoded = match decode_rxd(bytes) {
            Some(r) => r,
            None => {
                // Move on; drop the malformed frame.
                idx = (idx + 1) % depth;
                continue;
            }
        };
        let len = decoded.frame_len as usize;
        let frame_end = (RXD_BASE_SIZE + len).min(bytes.len());
        let payload = &bytes[RXD_BASE_SIZE..frame_end];
        f(payload, decoded);

        // Re-arm: clear DMA_DONE so the engine knows the descriptor
        // is available again.
        {
            let descs = ring.descriptors_mut();
            descs[idx].ctrl &= !MT_DMA_CTL_DMA_DONE;
        }
        drained += 1;
        idx = (idx + 1) % depth;
    }
    ring.set_hw_idx(new_hw);
    // Re-arm the doorbell: CPU pointer moves to wherever HW just was
    // (one full lap behind, modulo depth).
    let new_cpu = if new_hw == 0 { depth - 1 } else { new_hw - 1 };
    ring.set_cpu_idx(new_cpu);
    // SAFETY: BAR0 mapped + owned.
    unsafe { ring_doorbell(mmio, regs, new_cpu as u32) };
    drained
}

/// Reap completed TX descriptors: walk from `hw_idx` forward, free
/// each `DmaBuffer` whose descriptor's `DMA_DONE` bit is set, and
/// move the cached HW pointer.
///
/// # Safety
/// BAR0 mapped + owned.
pub unsafe fn reap_tx(mmio: &MmioRegion, ring: &mut Ring, regs: RingRegs) -> usize {
    // SAFETY: BAR0 mapped + owned.
    let new_hw = unsafe { ring_dma_index(mmio, regs) } as usize;
    let depth = ring.depth();
    if depth == 0 {
        return 0;
    }
    let new_hw = new_hw % depth;

    let mut reaped = 0usize;
    let mut idx = ring.hw_idx();
    while idx != new_hw {
        let done = {
            let descs = ring.descriptors();
            descs[idx].ctrl & MT_DMA_CTL_DMA_DONE != 0
        };
        if !done {
            break;
        }
        // Drop the per-slot buffer. `take_tx_buffer` removes the
        // DmaBuffer from the ring and frees it via Drop.
        let _ = ring.take_tx_buffer(idx);
        {
            let descs = ring.descriptors_mut();
            descs[idx].ctrl &= !MT_DMA_CTL_DMA_DONE;
        }
        reaped += 1;
        idx = (idx + 1) % depth;
    }
    ring.set_hw_idx(new_hw);
    reaped
}
