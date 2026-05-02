//! Completion Queue Entry (CQE) layout — Stage 10.
//!
//! Reference: public Mellanox PRM §16.3.3 ("Completion Queue Entry").
//!
//! A CQE is 64 bytes (some HCAs support a 128-byte CQE; Stage 10
//! commits to 64-byte CQEs first). Firmware writes one CQE per
//! retired WQE into the CQ ring. Software polls the ring's tail
//! and walks ownership-bit-marked entries.
//!
//! ## Layout (Stage-10 committed subset)
//!
//! ```text
//! +0x14..0x18  byte_count   (BE u32)        — bytes RX'd / TX'd
//! +0x37        status       (u8)            — completion status
//! +0x38..0x3A  wqe_counter  (BE u16)        — SQ/RQ index of WQE
//! +0x3B        signature    (u8)
//! +0x3C..0x3F  qp_op_own    (BE u32):
//!                bits[31:8] = qp_num (24)
//!                bits[7:4]  = opcode (4)
//!                bit[0]     = owner (1 = HW, 0 = SW)
//! ```

pub const CQE_LEN: usize = 64;

pub const CQE_OFF_BYTE_COUNT:  usize = 0x14;
pub const CQE_OFF_STATUS:      usize = 0x37;
pub const CQE_OFF_WQE_COUNTER: usize = 0x38;
pub const CQE_OFF_SIGNATURE:   usize = 0x3B;
pub const CQE_OFF_QP_OP_OWN:   usize = 0x3C;

pub const CQE_OWNER_BIT:  u8 = 1 << 0;
pub const CQE_OPCODE_MASK: u8 = 0xF0;

/// CQE opcodes as published in PRM §16.3.3 Table 102.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CqeOpcode {
    Requester        = 0x0,
    ResponderRdmaWrite = 0x1,
    ResponderSend    = 0x2,
    Resize           = 0x5,
    NoOp             = 0xE,
    Error            = 0xF,
}

impl CqeOpcode {
    pub fn from_raw(b: u8) -> Self {
        match b & 0x0F {
            0x0 => CqeOpcode::Requester,
            0x1 => CqeOpcode::ResponderRdmaWrite,
            0x2 => CqeOpcode::ResponderSend,
            0x5 => CqeOpcode::Resize,
            0xE => CqeOpcode::NoOp,
            _   => CqeOpcode::Error,
        }
    }
}

/// Completion-status codes (PRM §16.3.3 Table 103).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CqeStatus {
    Success,
    LocalLengthError,
    LocalQpOpError,
    LocalProtectionError,
    WrFlushedError,
    MwBindError,
    BadResponseError,
    LocalAccessError,
    RemoteInvalidRequest,
    RemoteAccessError,
    RemoteOpError,
    Unknown(u8),
}

impl CqeStatus {
    pub fn from_raw(b: u8) -> Self {
        match b {
            0x00 => CqeStatus::Success,
            0x01 => CqeStatus::LocalLengthError,
            0x02 => CqeStatus::LocalQpOpError,
            0x04 => CqeStatus::LocalProtectionError,
            0x05 => CqeStatus::WrFlushedError,
            0x06 => CqeStatus::MwBindError,
            0x10 => CqeStatus::BadResponseError,
            0x11 => CqeStatus::LocalAccessError,
            0x12 => CqeStatus::RemoteInvalidRequest,
            0x13 => CqeStatus::RemoteAccessError,
            0x14 => CqeStatus::RemoteOpError,
            other => CqeStatus::Unknown(other),
        }
    }
}

/// Decoded view over a CQE.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CqeView {
    pub byte_count:  u32,
    pub status:      CqeStatus,
    pub wqe_counter: u16,
    pub qp_num:      u32,
    pub opcode:      CqeOpcode,
    pub owner:       bool,
}

/// True if HW still owns the CQE (firmware has not posted a
/// completion to this slot yet).
pub fn is_hw_owned(cqe: &[u8; CQE_LEN]) -> bool {
    cqe[CQE_OFF_QP_OP_OWN + 3] & CQE_OWNER_BIT != 0
}

/// Decode the Stage-10 committed subset of a CQE.
pub fn decode_cqe(cqe: &[u8; CQE_LEN]) -> CqeView {
    let byte_count = u32::from_be_bytes([
        cqe[CQE_OFF_BYTE_COUNT],
        cqe[CQE_OFF_BYTE_COUNT + 1],
        cqe[CQE_OFF_BYTE_COUNT + 2],
        cqe[CQE_OFF_BYTE_COUNT + 3],
    ]);
    let status = CqeStatus::from_raw(cqe[CQE_OFF_STATUS]);
    let wqe_counter = u16::from_be_bytes([
        cqe[CQE_OFF_WQE_COUNTER],
        cqe[CQE_OFF_WQE_COUNTER + 1],
    ]);
    let qp_op_own = u32::from_be_bytes([
        cqe[CQE_OFF_QP_OP_OWN],
        cqe[CQE_OFF_QP_OP_OWN + 1],
        cqe[CQE_OFF_QP_OP_OWN + 2],
        cqe[CQE_OFF_QP_OP_OWN + 3],
    ]);
    let qp_num = (qp_op_own >> 8) & 0x00FF_FFFF;
    let opcode = CqeOpcode::from_raw(((qp_op_own >> 4) as u8) & 0x0F);
    let owner  = (qp_op_own as u8 & CQE_OWNER_BIT) != 0;
    CqeView { byte_count, status, wqe_counter, qp_num, opcode, owner }
}

/// Test-harness helper: write a synthetic completed CQE in place.
pub fn simulate_completion(
    cqe:         &mut [u8; CQE_LEN],
    byte_count:  u32,
    raw_status:  u8,
    wqe_counter: u16,
    qp_num:      u32,
    opcode:      CqeOpcode,
) {
    cqe[CQE_OFF_BYTE_COUNT..CQE_OFF_BYTE_COUNT + 4]
        .copy_from_slice(&byte_count.to_be_bytes());
    cqe[CQE_OFF_STATUS] = raw_status;
    cqe[CQE_OFF_WQE_COUNTER..CQE_OFF_WQE_COUNTER + 2]
        .copy_from_slice(&wqe_counter.to_be_bytes());
    let qp_op_own =
        ((qp_num & 0x00FF_FFFF) << 8)
        | ((opcode as u32) << 4);  // owner bit is 0 (SW-owned / completed)
    cqe[CQE_OFF_QP_OP_OWN..CQE_OFF_QP_OP_OWN + 4]
        .copy_from_slice(&qp_op_own.to_be_bytes());
}
