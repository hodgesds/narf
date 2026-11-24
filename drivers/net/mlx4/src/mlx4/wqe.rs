//! Work-queue entry (WQE) builders + doorbell encoders for the Ethernet
//! datapath.
//!
//! A ConnectX-3 Ethernet send WQE is a 16-byte control segment followed
//! by data segments; the simplest form the driver uses is one control
//! segment plus one data segment pointing at a copied staging buffer
//! (ctrl + data = 32 bytes, occupying one 64-byte TXBB). A receive WQE
//! is a bare scatter (data) segment. The control segment also carries
//! the TX checksum-offload request bits. Clean-room from the ConnectX-3
//! PRM §14 ("Work Queues") + the public register-offset documentation.

use super::wire;

/// Smallest send-queue allocation unit (a "transmit basic block").
pub const TXBB_SIZE: usize = 64;
/// Control-segment length.
pub const CTRL_SEG_LEN: usize = 16;
/// Data (scatter/gather) segment length.
pub const DATA_SEG_LEN: usize = 16;
/// One ctrl + one data segment.
pub const TX_WQE_LEN: usize = CTRL_SEG_LEN + DATA_SEG_LEN;

/// Send opcode (normal, non-LSO Ethernet frame).
pub const OPCODE_SEND: u32 = 0x0a;
/// Owner bit in `owner_opcode` — set to hand the WQE to hardware when
/// the producer index's phase bit is set.
pub const DESC_OWN: u32 = 0x8000_0000;

/// `srcrb_flags` bit: generate a completion-queue entry for this WQE.
pub const CTRL_CQ_UPDATE: u32 = 3 << 2;
/// `srcrb_flags` bit: offload the IP header checksum on TX.
pub const CTRL_IP_CSUM: u32 = 1 << 4;
/// `srcrb_flags` bit: offload the L4 (TCP/UDP) checksum on TX.
pub const CTRL_TCP_UDP_CSUM: u32 = 1 << 5;

/// Byte offset of the send doorbell within a UAR page.
pub const SEND_DOORBELL_UAR_OFFSET: u64 = 0x14;

/// Build a send WQE: control segment + one data segment.
///
/// `own` sets the ownership bit (the producer-index phase). `csum`
/// requests IP + L4 checksum offload. A completion is always requested
/// (`CQ_UPDATE`) so the datapath can recycle the staging slot. The
/// data segment points at `data_va` (device address), tagged with
/// `data_lkey` and `data_len` bytes.
pub fn build_tx_wqe(
    own: bool,
    csum: bool,
    data_va: u64,
    data_lkey: u32,
    data_len: u32,
) -> [u8; TX_WQE_LEN] {
    let mut w = [0u8; TX_WQE_LEN];
    // Control segment.
    let opcode = OPCODE_SEND | if own { DESC_OWN } else { 0 };
    wire::put_be32(&mut w, 0x00, opcode);
    // qpn_vlan: the fence/size byte (0x07) holds the WQE size in 16-byte
    // descriptor units; no VLAN insertion.
    wire::put_u8(&mut w, 0x07, (TX_WQE_LEN / 16) as u8);
    let mut flags = CTRL_CQ_UPDATE;
    if csum {
        flags |= CTRL_IP_CSUM | CTRL_TCP_UDP_CSUM;
    }
    wire::put_be32(&mut w, 0x08, flags);
    // imm (0x0c) left zero.
    // Data segment at 0x10.
    wire::put_be32(&mut w, 0x10, data_len);
    wire::put_be32(&mut w, 0x14, data_lkey);
    wire::put_be64(&mut w, 0x18, data_va);
    w
}

/// The host value written (big-endian) to the send doorbell at
/// `UAR + SEND_DOORBELL_UAR_OFFSET` to advance the send queue: the
/// QP number left-shifted by 8.
#[inline]
pub fn tx_doorbell_word(qpn: u32) -> u32 {
    qpn << 8
}

/// Build a receive WQE — a single scatter (data) segment naming the
/// `data_len`-byte buffer at device address `data_va`, tagged with
/// `data_lkey`.
pub fn build_rx_wqe(data_va: u64, data_lkey: u32, data_len: u32) -> [u8; DATA_SEG_LEN] {
    let mut w = [0u8; DATA_SEG_LEN];
    wire::put_be32(&mut w, 0x00, data_len);
    wire::put_be32(&mut w, 0x04, data_lkey);
    wire::put_be64(&mut w, 0x08, data_va);
    w
}

/// The host value written (big-endian) to the receive-queue doorbell
/// record (host memory) to advance the RX producer index: the low 16
/// bits of the running producer index.
#[inline]
pub fn rx_prod_doorbell_word(prod: u32) -> u32 {
    prod & 0xffff
}

/// Decode the opcode + owner bit from a built send WQE (for tests).
#[inline]
pub fn wqe_owner_opcode(w: &[u8]) -> u32 {
    wire::get_be32(w, 0x00)
}

/// Decode the `srcrb_flags` of a built send WQE (for tests).
#[inline]
pub fn wqe_srcrb_flags(w: &[u8]) -> u32 {
    wire::get_be32(w, 0x08)
}
