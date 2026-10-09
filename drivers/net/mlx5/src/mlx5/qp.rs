//! Queue Pair (QP) context + `CREATE_QP` / `MODIFY_QP` state
//! machine.
//!
//! Reference: public Mellanox PRM §16.5 ("Queue Pair Context") +
//! §15.7.7 ("CREATE_QP" / "MODIFY_QP" command family).
//!
//! A QP is the workhorse of the HCA: a paired Send Queue (SQ) +
//! Receive Queue (RQ) with associated CQs and protection domain.
//! Stage 9 establishes the transport surface — the qpc layout +
//! the four MODIFY_QP transitions that walk the QP through:
//!
//! ```text
//! RST  ──RST2INIT──►  INIT  ──INIT2RTR──►  RTR  ──RTR2RTS──►  RTS
//! ```
//!
//! Per PRM the reverse-direction `2RST_QP` returns any state to RST.
//!
//! ## qpc layout (Stage 9 committed subset)
//!
//! The qpc is 512 bytes. Stage 9 commits to:
//!
//! | bits / bytes  | field         | width / notes                |
//! |---------------|---------------|------------------------------|
//! | 0x00 byte     | state (hi 4) | high nibble of byte 0         |
//! | 0x00 lo nib   | qp_type       | service type, low 4 bits      |
//! | 0x10..0x12    | pd            | 24 bits BE                    |
//! | 0x18..0x1A    | cqn_snd       | 24 bits BE                    |
//! | 0x20..0x22    | cqn_rcv       | 24 bits BE                    |
//! | 0x29 low 5    | log_sq_size   | bit-packed                    |
//! | 0x2B low 5    | log_rq_size   | bit-packed                    |
//! | 0x2C          | log_page_size | byte                          |
//!
//! Phys-addr list starts at offset 0x200 (512 bytes in) with 8-byte
//! BE entries.

extern crate alloc;
use alloc::vec::Vec;

use super::bit_field::{read_bits_be, write_bits_be};

pub const QPC_LEN: usize = 512;
pub const QPC_PA_LIST_OFF: usize = 512;
pub const QPC_PA_ENTRY_LEN: usize = 8;

pub const QPC_OFF_STATE_TYPE: usize = 0x00;
pub const QPC_OFF_LOG_PAGE_SIZE: usize = 0x2C;

pub const QPC_BIT_PD: usize = 0x10 * 8;
pub const QPC_BIT_PD_W: usize = 24;
pub const QPC_BIT_CQN_SND: usize = 0x18 * 8;
pub const QPC_BIT_CQN_SND_W: usize = 24;
pub const QPC_BIT_CQN_RCV: usize = 0x20 * 8;
pub const QPC_BIT_CQN_RCV_W: usize = 24;
pub const QPC_BIT_LOG_SQ_SIZE: usize = 0x29 * 8 + 3;
pub const QPC_BIT_LOG_SQ_SIZE_W: usize = 5;
pub const QPC_BIT_LOG_RQ_SIZE: usize = 0x2B * 8 + 3;
pub const QPC_BIT_LOG_RQ_SIZE_W: usize = 5;

/// QP service types (qpc state-byte low nibble).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QpType {
    /// Reliable Connection.
    Rc = 0x0,
    /// Unreliable Connection.
    Uc = 0x1,
    /// Unreliable Datagram.
    Ud = 0x2,
    /// XRC (eXtended Reliable Connection).
    Xrc = 0x3,
    /// Dynamically Connected Transport.
    Dct = 0x6,
    /// Raw Ethernet — used by NIC fast-path TX/RX.
    RawEthernet = 0x9,
}

/// QP state, encoded in the high nibble of qpc byte 0x00.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum QpState {
    Rst = 0x0,
    Init = 0x1,
    Rtr = 0x2,
    Rts = 0x3,
    Sqer = 0x4,
    Sqd = 0x5,
    Err = 0x6,
    Sqdrng = 0x7,
}

/// MODIFY_QP transitions Stage 9 surfaces. Each maps to one of the
/// PRM-documented opcodes; the qpc fields the transition expects to
/// be set are listed in the PRM §15.7.7 modifier mask tables.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QpTransition {
    /// Any state → RST. Opcode `2RST_QP` (0x50A).
    ToRst,
    /// RST → INIT. Opcode `RST2INIT_QP` (0x502). Caller programs
    /// pkey_index, port, qkey on the qpc input.
    RstToInit,
    /// INIT → RTR. Opcode `INIT2RTR_QP` (0x503). Caller programs
    /// path / mtu / dest_qp.
    InitToRtr,
    /// RTR → RTS. Opcode `RTR2RTS_QP` (0x504). Caller programs
    /// timeout / retry_count / sq_psn.
    RtrToRts,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QpError {
    BadLogSqSize,
    BadLogRqSize,
    BadPd,
    BadCqn,
    NoPages,
}

#[derive(Copy, Clone, Debug)]
pub struct QpParams {
    pub qp_type: QpType,
    /// Protection-domain number.
    pub pd: u32,
    /// Send CQ number.
    pub cqn_snd: u32,
    /// Receive CQ number.
    pub cqn_rcv: u32,
    /// log2 of the SQ depth (in WQEs).
    pub log_sq_size: u8,
    /// log2 of the RQ depth.
    pub log_rq_size: u8,
    pub log_page_size: u8,
    /// UAR page bound to this QP for SQ/RQ doorbells. Stage 11
    /// uses this directly when posting work; the qpc encoding for
    /// uar_page lands in a later stage.
    pub uar_page: u32,
}

/// Build the CREATE_QP input mailbox payload — 512-byte qpc + an
/// 8-byte BE phys-addr list. Stage-7-style transport feeds this
/// through `issue_command_with_input_mailbox`.
pub fn build_create_qp_input(params: QpParams, pages: &[u64]) -> Result<Vec<u8>, QpError> {
    if pages.is_empty() {
        return Err(QpError::NoPages);
    }
    if params.log_sq_size >= (1 << 5) {
        return Err(QpError::BadLogSqSize);
    }
    if params.log_rq_size >= (1 << 5) {
        return Err(QpError::BadLogRqSize);
    }
    if params.pd >= (1 << 24) {
        return Err(QpError::BadPd);
    }
    if params.cqn_snd >= (1 << 24) {
        return Err(QpError::BadCqn);
    }
    if params.cqn_rcv >= (1 << 24) {
        return Err(QpError::BadCqn);
    }

    let total = QPC_PA_LIST_OFF + pages.len() * QPC_PA_ENTRY_LEN;
    let mut out = alloc::vec![0u8; total];

    // state | qp_type — both in byte 0x00. State starts at RST (0x0)
    // so we just write the qp_type into the low nibble.
    out[QPC_OFF_STATE_TYPE] = (QpState::Rst as u8) << 4 | (params.qp_type as u8 & 0x0F);

    write_bits_be(&mut out, QPC_BIT_PD, QPC_BIT_PD_W, params.pd as u64);
    write_bits_be(
        &mut out,
        QPC_BIT_CQN_SND,
        QPC_BIT_CQN_SND_W,
        params.cqn_snd as u64,
    );
    write_bits_be(
        &mut out,
        QPC_BIT_CQN_RCV,
        QPC_BIT_CQN_RCV_W,
        params.cqn_rcv as u64,
    );
    write_bits_be(
        &mut out,
        QPC_BIT_LOG_SQ_SIZE,
        QPC_BIT_LOG_SQ_SIZE_W,
        params.log_sq_size as u64,
    );
    write_bits_be(
        &mut out,
        QPC_BIT_LOG_RQ_SIZE,
        QPC_BIT_LOG_RQ_SIZE_W,
        params.log_rq_size as u64,
    );
    out[QPC_OFF_LOG_PAGE_SIZE] = params.log_page_size;

    for (i, &pa) in pages.iter().enumerate() {
        let off = QPC_PA_LIST_OFF + i * QPC_PA_ENTRY_LEN;
        out[off..off + 8].copy_from_slice(&pa.to_be_bytes());
    }
    Ok(out)
}

/// Decode the QP state out of a qpc snapshot — used by smokes + the
/// Stage-9 state-machine driver to confirm a MODIFY_QP completed.
pub fn decode_qp_state(qpc: &[u8]) -> QpState {
    match qpc[QPC_OFF_STATE_TYPE] >> 4 {
        0x0 => QpState::Rst,
        0x1 => QpState::Init,
        0x2 => QpState::Rtr,
        0x3 => QpState::Rts,
        0x4 => QpState::Sqer,
        0x5 => QpState::Sqd,
        0x6 => QpState::Err,
        0x7 => QpState::Sqdrng,
        _ => QpState::Err,
    }
}

/// Decode the QP type back from a qpc snapshot.
pub fn decode_qp_type(qpc: &[u8]) -> Option<QpType> {
    match qpc[QPC_OFF_STATE_TYPE] & 0x0F {
        0x0 => Some(QpType::Rc),
        0x1 => Some(QpType::Uc),
        0x2 => Some(QpType::Ud),
        0x3 => Some(QpType::Xrc),
        0x6 => Some(QpType::Dct),
        0x9 => Some(QpType::RawEthernet),
        _ => None,
    }
}

/// Round-trip the bit-packed params subset from a qpc — used by the
/// Stage-9 round-trip smoke.
pub fn decode_create_qp_input(bytes: &[u8]) -> QpParams {
    QpParams {
        qp_type: decode_qp_type(bytes).unwrap_or(QpType::Rc),
        pd: read_bits_be(bytes, QPC_BIT_PD, QPC_BIT_PD_W) as u32,
        cqn_snd: read_bits_be(bytes, QPC_BIT_CQN_SND, QPC_BIT_CQN_SND_W) as u32,
        cqn_rcv: read_bits_be(bytes, QPC_BIT_CQN_RCV, QPC_BIT_CQN_RCV_W) as u32,
        log_sq_size: read_bits_be(bytes, QPC_BIT_LOG_SQ_SIZE, QPC_BIT_LOG_SQ_SIZE_W) as u8,
        log_rq_size: read_bits_be(bytes, QPC_BIT_LOG_RQ_SIZE, QPC_BIT_LOG_RQ_SIZE_W) as u8,
        log_page_size: bytes[QPC_OFF_LOG_PAGE_SIZE],
        uar_page: 0,
    }
}
