//! Flow-steering primitives — TIR / TIS / RQT — Stage 14.
//!
//! Reference: public Mellanox PRM §16.7 ("Transport Interface
//! Receive / Send") + §16.6 ("Receive Queue Table").
//!
//! `TIR` (Transport Interface Receive) is the per-flow RX endpoint:
//! a TIR points at either a single RQ (`inline_rqn`) or an RQT
//! (Receive Queue Table) for RSS spreading. `TIS` is the analogous
//! TX endpoint. `RQT` is a power-of-two-sized table of RQ numbers
//! the HCA hashes packets across.
//!
//! Stage 14 commits to the byte-aligned subset enough to plug a
//! single-RQ raw-Ethernet TIR + TIS pair + a single-entry RQT. The
//! full RSS-key + hash-function layout lands when we need multi-
//! queue steering.

extern crate alloc;
use alloc::vec::Vec;

// ── TIR ────────────────────────────────────────────────────────────

pub const TIRC_LEN: usize = 256;
pub const TIRC_OFF_DISP_TYPE: usize = 0x04;
pub const TIRC_OFF_INLINE_RQN: usize = 0x1C;
pub const TIRC_OFF_TRANSPORT_DOMAIN: usize = 0x24;

/// TIR dispatch types.
pub const TIR_DISP_DIRECT: u8 = 0x0;
pub const TIR_DISP_INDIRECT_RQT: u8 = 0x1;

#[derive(Copy, Clone, Debug)]
pub struct TirParams {
    /// `0x0` = direct (use `inline_rqn`); `0x1` = indirect (RQT).
    pub disp_type:         u8,
    /// RQ number (or RQT number when `disp_type` = indirect).
    pub inline_rqn:        u32,
    pub transport_domain:  u32,
}

pub fn build_create_tir_input(p: TirParams) -> Vec<u8> {
    let mut out = alloc::vec![0u8; TIRC_LEN];
    out[TIRC_OFF_DISP_TYPE] = p.disp_type & 0x0F;
    out[TIRC_OFF_INLINE_RQN..TIRC_OFF_INLINE_RQN + 4]
        .copy_from_slice(&p.inline_rqn.to_be_bytes());
    out[TIRC_OFF_TRANSPORT_DOMAIN..TIRC_OFF_TRANSPORT_DOMAIN + 4]
        .copy_from_slice(&p.transport_domain.to_be_bytes());
    out
}

// ── TIS ────────────────────────────────────────────────────────────

pub const TISC_LEN: usize = 256;
pub const TISC_OFF_PRIO:    usize = 0x00;
pub const TISC_OFF_TRANSPORT_DOMAIN: usize = 0x24;

#[derive(Copy, Clone, Debug)]
pub struct TisParams {
    pub priority:         u8,
    pub transport_domain: u32,
}

pub fn build_create_tis_input(p: TisParams) -> Vec<u8> {
    let mut out = alloc::vec![0u8; TISC_LEN];
    out[TISC_OFF_PRIO] = p.priority & 0x0F;
    out[TISC_OFF_TRANSPORT_DOMAIN..TISC_OFF_TRANSPORT_DOMAIN + 4]
        .copy_from_slice(&p.transport_domain.to_be_bytes());
    out
}

// ── RQT ────────────────────────────────────────────────────────────

pub const RQTC_OFF_RQT_MAX_SIZE: usize = 0x10;
pub const RQTC_OFF_RQT_ACTUAL_SIZE: usize = 0x14;
pub const RQTC_OFF_RQ_LIST: usize = 0x20;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RqtError { TooLarge }

#[derive(Clone, Debug)]
pub struct RqtParams {
    /// log2 of the RQT capacity (HW supports up to 128).
    pub max_size:    u32,
    /// Actual-size <= max_size. Per PRM bits[12:0].
    pub actual_size: u32,
}

/// Build the CREATE_RQT input mailbox: 32-byte rqt context plus a
/// 4-byte BE rqn entry per RQ in `rqs`.
pub fn build_create_rqt_input(p: RqtParams, rqs: &[u32]) -> Result<Vec<u8>, RqtError> {
    if rqs.len() > 128 { return Err(RqtError::TooLarge); }
    let total = RQTC_OFF_RQ_LIST + rqs.len() * 4;
    let mut out = alloc::vec![0u8; total];
    out[RQTC_OFF_RQT_MAX_SIZE..RQTC_OFF_RQT_MAX_SIZE + 4]
        .copy_from_slice(&p.max_size.to_be_bytes());
    out[RQTC_OFF_RQT_ACTUAL_SIZE..RQTC_OFF_RQT_ACTUAL_SIZE + 4]
        .copy_from_slice(&p.actual_size.to_be_bytes());
    for (i, &rqn) in rqs.iter().enumerate() {
        let off = RQTC_OFF_RQ_LIST + i * 4;
        out[off..off + 4].copy_from_slice(&rqn.to_be_bytes());
    }
    Ok(out)
}
