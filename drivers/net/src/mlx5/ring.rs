//! Stage 11: SQ / RQ / CQ ring helpers — pure-data operations
//! over the QP buffer + CQ buffer.
//!
//! The live `Mlx5Hca::post_send` / `post_recv` / `poll_cq` paths
//! wrap these helpers around the DMA buffers + UAR doorbells. The
//! split keeps the wire-layout work testable without DMA.
//!
//! ## QP-buffer layout (Stage 11)
//!
//! Stage 11 commits to: SQ first, RQ following. WQE stride is 64
//! bytes (16-byte control + up to 3 data segments). This matches
//! the canonical small-WQE configuration; larger strides will
//! land alongside the `cqe_sz` / `wq_sz` qpc bits in a later
//! stage.
//!
//! ```text
//! 0                                   sq_size_bytes        end
//! ├────────── SQ (1<<log_sq_size) ──────┤── RQ (1<<log_rq_size) ─┤
//! ```
//!
//! ## CQ ring
//!
//! Contiguous CQEs of `CQE_STRIDE` bytes, polled by walking
//! `consumer mod capacity` and toggling the expected phase on each
//! wraparound. Stage 11 uses the documented owner-bit convention
//! (bit 0 of byte 0x3F) — phase tracking lands when we add CQ
//! resize support.

use super::cqe::{decode_cqe, is_hw_owned, CqeView, CQE_LEN};
use super::wqe::{
    build_ctrl_segment, build_data_seg_ptr, CqeRequest, SendOpcode,
    CTRL_SEG_LEN, DATA_SEG_LEN,
};

/// Stride of one SQ / RQ WQE in bytes.
pub const WQE_STRIDE: usize = 64;
/// Stride of one CQE in bytes.
pub const CQE_STRIDE: usize = CQE_LEN;
/// Maximum data segments after the control segment fitting in one
/// `WQE_STRIDE`. (64 - 16) / 16 = 3.
pub const MAX_DATA_SEGS_PER_WQE: usize = (WQE_STRIDE - CTRL_SEG_LEN) / DATA_SEG_LEN;

/// One scatter/gather buffer descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IoVec {
    /// Virtual address of the buffer (must be in a memory region
    /// covered by `l_key`).
    pub va:    u64,
    /// L_KEY of the memory region this buffer lives in.
    pub l_key: u32,
    /// Buffer length in bytes.
    pub len:   u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    /// More IoVecs than fit in a single WQE (Stage 11 caps at
    /// `MAX_DATA_SEGS_PER_WQE` data segments).
    TooManySegments,
    /// At least one IoVec is required.
    NoSegments,
}

/// SQ-byte-offset for the `wqe_idx`th WQE.
pub fn sq_offset_of(wqe_idx: u32) -> usize {
    (wqe_idx as usize) * WQE_STRIDE
}

/// RQ byte offset for the `wqe_idx`th WQE — measured from the start
/// of the RQ region (which itself sits at `sq_size_bytes` of the QP
/// buffer).
pub fn rq_offset_of(wqe_idx: u32) -> usize {
    (wqe_idx as usize) * WQE_STRIDE
}

/// Total SQ region size in bytes.
pub fn sq_size_bytes(log_sq_size: u8) -> usize {
    (1usize << log_sq_size) * WQE_STRIDE
}

/// Total RQ region size in bytes.
pub fn rq_size_bytes(log_rq_size: u8) -> usize {
    (1usize << log_rq_size) * WQE_STRIDE
}

/// CQE byte offset within the CQ buffer.
pub fn cq_offset_of(consumer: u32, capacity: u32) -> usize {
    ((consumer % capacity) as usize) * CQE_STRIDE
}

/// Build a complete WQE (control + data segments) ready to copy
/// into an SQ slot. Returns the bytes; caller writes them at
/// `sq_offset_of(wqe_idx)`.
pub fn build_send_wqe(
    qp_num:    u32,
    wqe_idx:   u16,
    opcode:    SendOpcode,
    cqe_req:   CqeRequest,
    iovecs:    &[IoVec],
) -> Result<[u8; WQE_STRIDE], RingError> {
    if iovecs.is_empty()
        { return Err(RingError::NoSegments); }
    if iovecs.len() > MAX_DATA_SEGS_PER_WQE
        { return Err(RingError::TooManySegments); }
    // ds = total 16-byte chunks in the WQE = 1 (ctrl) + iovec count.
    let ds = (1 + iovecs.len()) as u8;
    let ctrl = build_ctrl_segment(opcode, qp_num, wqe_idx, ds, cqe_req, /* sig */ 0);
    let mut wqe = [0u8; WQE_STRIDE];
    wqe[..CTRL_SEG_LEN].copy_from_slice(&ctrl);
    for (i, iov) in iovecs.iter().enumerate() {
        let off = CTRL_SEG_LEN + i * DATA_SEG_LEN;
        let seg = build_data_seg_ptr(iov.len, iov.l_key, iov.va);
        wqe[off..off + DATA_SEG_LEN].copy_from_slice(&seg);
    }
    Ok(wqe)
}

/// Build a receive-WQE — RQ WQEs are simpler: just N data segments
/// in a 64-byte stride, no control segment. Stage 11 commits to
/// the inline-segment-count layout where byte 0x00..0x02 holds the
/// number of segments (BE u16) and the data segments follow.
pub fn build_recv_wqe(iovecs: &[IoVec]) -> Result<[u8; WQE_STRIDE], RingError> {
    if iovecs.is_empty()
        { return Err(RingError::NoSegments); }
    if iovecs.len() > MAX_DATA_SEGS_PER_WQE
        { return Err(RingError::TooManySegments); }
    let mut wqe = [0u8; WQE_STRIDE];
    wqe[0x00..0x02].copy_from_slice(&(iovecs.len() as u16).to_be_bytes());
    for (i, iov) in iovecs.iter().enumerate() {
        // RQ data segments live at the same 16-byte stride as SQ.
        let off = CTRL_SEG_LEN + i * DATA_SEG_LEN;
        let seg = build_data_seg_ptr(iov.len, iov.l_key, iov.va);
        wqe[off..off + DATA_SEG_LEN].copy_from_slice(&seg);
    }
    Ok(wqe)
}

/// Walk the CQ ring starting at `consumer` and return the first
/// SW-owned CQE if any. Returns `(view, new_consumer)` so callers
/// can advance their cursor; `None` means no completion ready.
pub fn pop_completion(
    cq_bytes: &[u8],
    capacity: u32,
    consumer: u32,
) -> Option<(CqeView, u32)> {
    let off = cq_offset_of(consumer, capacity);
    if off + CQE_STRIDE > cq_bytes.len() {
        return None;
    }
    let mut cqe = [0u8; CQE_LEN];
    cqe.copy_from_slice(&cq_bytes[off..off + CQE_STRIDE]);
    if is_hw_owned(&cqe) { return None; }
    Some((decode_cqe(&cqe), consumer.wrapping_add(1)))
}
