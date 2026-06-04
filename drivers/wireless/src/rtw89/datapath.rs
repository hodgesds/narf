//! RTW89 TX/RX datapath glue — Stage-11.
//!
//! Wires the existing pieces together so a queued frame on a TX
//! channel walks through:
//!
//! ```text
//! ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
//! │ 802.11   │ → │ TXWD     │ → │ BD slot  │ → │ doorbell │
//! │ frame    │   │ prefix   │   │ write    │   │ MMIO     │
//! └──────────┘   └──────────┘   └──────────┘   └──────────┘
//! ```
//!
//! The TX side composes a TXWD body (`txrx::encode_txwd`), writes it
//! into a host-DMA buffer in front of the 802.11 payload, advances the
//! ring's wp, then bangs the `*_TXBD_IDX` doorbell with the new wp.
//!
//! The RX side, on interrupt, reads `*_RXBD_IDX` to learn how many
//! BDs the hardware filled, walks them, decodes the RXD prefix
//! (`txrx::decode_rxd`), and surfaces each 802.11 payload.
//!
//! ## References (all GPL-2.0)
//!
//! - Linux `rtw89/pci.c::rtw89_pci_ops_tx_write` (~L1370) — TX submit.
//! - Linux `rtw89/pci.c::rtw89_pci_ops_tx_kick_off` (~L1430) — doorbell.
//! - Linux `rtw89/pci.c::rtw89_pci_rxq_napi_poll` (~L1180) — RX consumer.

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::dma::{addr_set_for_chip, RingState, RxRingRegs, TxRingRegs, RING_IDX_HOST_SHIFT};
use super::mac::ChipId;
use super::txrx::{decode_rxd, encode_txwd, RxdInfo, TxwdInfo, RXD_SHORT_SIZE, TXWD_BODY_SIZE};

// ── TX submit ───────────────────────────────────────────────────────

/// Result of preparing a frame for TX. Caller is expected to copy
/// `wire` into a DMA-coherent buffer and write the buffer's physical
/// address into the BD descriptor.
#[derive(Debug)]
pub struct TxSubmission<'a> {
    /// TXWD body (24 bytes) prepended to the 802.11 payload.
    pub txwd: [u8; TXWD_BODY_SIZE],
    /// 802.11 frame body.
    pub frame: &'a [u8],
    /// Total wire bytes (`TXWD_BODY_SIZE + frame.len()`).
    pub total: usize,
}

/// Stage a frame for transmission on `channel`. Builds the TXWD body;
/// caller does the DMA copy + BD setup.
pub fn stage_tx<'a>(
    channel: u8,
    qsel: u8,
    mac_id: u8,
    frame: &'a [u8],
) -> Option<TxSubmission<'a>> {
    let info = TxwdInfo {
        channel,
        qsel,
        mac_id,
        pkt_size: frame.len() as u16,
    };
    let mut txwd = [0u8; TXWD_BODY_SIZE];
    encode_txwd(&info, &mut txwd)?;
    Some(TxSubmission {
        txwd,
        frame,
        total: TXWD_BODY_SIZE + frame.len(),
    })
}

/// Bang the TX ring's doorbell. The 32-bit `*_TXBD_IDX` register holds
/// the HW read pointer in bits[11:0] and the host write pointer in
/// bits[31:16]; we write the new host_wp into the upper half.
///
/// Mirrors the WP update in `rtw89_pci_tx_kick_off` (`pci.c:1430`).
///
/// # Safety
/// Caller owns the BAR2 MMIO.
pub unsafe fn ring_doorbell_tx(mmio: &MmioRegion, regs: &TxRingRegs, new_wp: u16) {
    // SAFETY: identity-mapped MMIO.
    let cur = unsafe { mmio.read32(regs.idx) };
    // Preserve the HW read pointer in bits[11:0]; overwrite host_wp
    // in bits[31:16].
    let new = (cur & 0x0000_FFFF) | ((new_wp as u32) << RING_IDX_HOST_SHIFT);
    // SAFETY: same.
    unsafe {
        mmio.write32(regs.idx, new);
    }
}

/// Read the current ring index back to update the host's `RingState`.
///
/// # Safety
/// Caller owns the BAR2 MMIO.
pub unsafe fn read_tx_ring_idx(mmio: &MmioRegion, regs: &TxRingRegs) -> u32 {
    // SAFETY: identity-mapped MMIO.
    unsafe { mmio.read32(regs.idx) }
}

// ── RX consume ──────────────────────────────────────────────────────

/// Bang the RX ring's doorbell to acknowledge `consumed` BDs.
///
/// # Safety
/// Caller owns the BAR2 MMIO.
pub unsafe fn ring_doorbell_rx(mmio: &MmioRegion, regs: &RxRingRegs, new_wp: u16) {
    // SAFETY: identity-mapped MMIO.
    let cur = unsafe { mmio.read32(regs.idx) };
    let new = (cur & 0x0000_FFFF) | ((new_wp as u32) << RING_IDX_HOST_SHIFT);
    // SAFETY: same.
    unsafe {
        mmio.write32(regs.idx, new);
    }
}

/// Read the RX ring index.
///
/// # Safety
/// Caller owns the BAR2 MMIO.
pub unsafe fn read_rx_ring_idx(mmio: &MmioRegion, regs: &RxRingRegs) -> u32 {
    // SAFETY: identity-mapped MMIO.
    unsafe { mmio.read32(regs.idx) }
}

/// One RX BD's payload — the RXD prefix decoded + the byte slice
/// pointing at the 802.11 frame.
#[derive(Debug)]
pub struct RxDelivery<'a> {
    /// Decoded RXD fields.
    pub rxd: RxdInfo,
    /// The 802.11 frame body (after the 16-byte RXD prefix).
    pub frame: &'a [u8],
}

/// Pull one RX BD's payload. `bd_payload` is the full DMA buffer (RXD
/// + frame); we return the frame slice and the decoded RXD. Returns
/// `None` if the buffer is too short or the RXD says CRC/ICV error
/// (caller should still ACK the BD; this is just a filter).
pub fn consume_rx_bd(bd_payload: &[u8]) -> Option<RxDelivery<'_>> {
    let rxd = decode_rxd(bd_payload)?;
    if rxd.crc32_err || rxd.icv_err {
        return None;
    }
    let frame_start = RXD_SHORT_SIZE;
    let frame_end = frame_start.checked_add(rxd.pkt_len as usize)?;
    if frame_end > bd_payload.len() {
        return None;
    }
    Some(RxDelivery {
        rxd,
        frame: &bd_payload[frame_start..frame_end],
    })
}

// ── Per-channel state ───────────────────────────────────────────────

/// Per-TX-channel runtime state: the address-set regs and the ring
/// bookkeeping. A live driver holds one of these per TXCH (×13) plus
/// two RX rings.
#[derive(Debug)]
pub struct TxChannelState {
    /// Channel index (0..12).
    pub channel: u8,
    /// Per-ring register addresses.
    pub regs: TxRingRegs,
    /// Host-side bookkeeping.
    pub state: RingState,
}

impl TxChannelState {
    /// Build a fresh per-channel state for the given chip + channel.
    pub fn new(chip: ChipId, channel: u8, depth: u16) -> Self {
        let set = addr_set_for_chip(chip);
        let regs = set.tx[channel as usize];
        Self {
            channel,
            regs,
            state: RingState::new(depth),
        }
    }
}

/// Per-RX-ring runtime state.
#[derive(Debug)]
pub struct RxChannelState {
    /// Channel index (0..1).
    pub channel: u8,
    pub regs: RxRingRegs,
    pub state: RingState,
}

impl RxChannelState {
    pub fn new(chip: ChipId, channel: u8, depth: u16) -> Self {
        let set = addr_set_for_chip(chip);
        let regs = set.rx[channel as usize];
        Self {
            channel,
            regs,
            state: RingState::new(depth),
        }
    }
}
