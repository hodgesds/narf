//! Work Queue Entry (WQE) layout for Send / Receive queues.
//!
//! Reference: public Mellanox PRM §11.4 ("WQE Format") + §11.5
//! ("Send / Receive Operation Codes").
//!
//! A WQE is composed of a 16-byte control segment followed by N
//! 16-byte data segments. The control segment carries the opcode,
//! QP number, intra-SQ wqe_idx, the data-segment count `ds`, and a
//! 4-bit flags field controlling completion / solicited-event
//! semantics.
//!
//! Stage 10 focuses on the *layout* + builder/decoder pairs. Live
//! WQE posting happens through `Mlx5Hca::post_wqe_raw`, which writes
//! the bytes into the QP buffer and rings the SQ doorbell via the
//! UAR.
//!
//! ## Control segment (16 bytes, dword-BE)
//!
//! ```text
//! dword 0 (0x00..0x04):
//!   bits[31:24] = opmod
//!   bits[23:8]  = wqe_idx (16-bit)
//!   bits[7:0]   = opcode
//! dword 1 (0x04..0x08):
//!   bits[31:8]  = qp_num (24-bit)
//!   bits[7:0]   = ds (data-segment count, in 16-byte units, INCLUDING
//!                     the control segment itself)
//! dword 2 (0x08..0x0C):
//!   bits[31:24] = signature
//!   bits[7:2]   = ce (completion enable)
//!   bits[1:0]   = se (solicited event)
//! dword 3 (0x0C..0x10):
//!   immediate / invalidation key — opcode-dependent
//! ```
//!
//! ## Pointer data segment (16 bytes, dword-BE)
//!
//! ```text
//! dword 0 (0x00..0x04): byte_count (u32 BE)
//! dword 1 (0x04..0x08): l_key      (u32 BE)
//! dword 2 (0x08..0x0C): va_high    (u32 BE)
//! dword 3 (0x0C..0x10): va_low     (u32 BE)
//! ```

use super::bit_field::{read_bits_be, write_bits_be};

pub const CTRL_SEG_LEN: usize = 16;
pub const DATA_SEG_LEN: usize = 16;

// Control-segment bit positions (within the 16-byte segment).
pub const CTRL_BIT_OPMOD: usize = 0;
pub const CTRL_BIT_OPMOD_W: usize = 8;
pub const CTRL_BIT_WQE_IDX: usize = 8;
pub const CTRL_BIT_WQE_IDX_W: usize = 16;
pub const CTRL_BIT_OPCODE: usize = 24;
pub const CTRL_BIT_OPCODE_W: usize = 8;
pub const CTRL_BIT_QPN: usize = 32;
pub const CTRL_BIT_QPN_W: usize = 24;
pub const CTRL_BIT_DS: usize = 56;
pub const CTRL_BIT_DS_W: usize = 8;
pub const CTRL_BIT_SIG: usize = 64;
pub const CTRL_BIT_SIG_W: usize = 8;

/// WQE send opcodes. See PRM §11.5.1.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SendOpcode {
    Nop = 0x00,
    SndInv = 0x01,
    RdmaWrite = 0x08,
    RdmaWriteImmediate = 0x09,
    Send = 0x0A,
    SendImmediate = 0x0B,
    LoSend = 0x0C,
    LoSendImmediate = 0x0D,
    RdmaRead = 0x10,
    AtomicCs = 0x11,
    AtomicFa = 0x12,
}

/// Completion-enable bits (control-segment fm_ce_se field).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CqeRequest {
    /// No completion is generated for this WQE.
    NoCqe = 0b00,
    /// Always generate a CQE.
    AlwaysCqe = 0b10,
    /// Generate a CQE on first error or solicited completion.
    SolicitedOnly = 0b01,
}

/// Build a 16-byte send-WQE control segment.
pub fn build_ctrl_segment(
    opcode: SendOpcode,
    qp_num: u32,
    wqe_idx: u16,
    ds: u8,
    cqe_req: CqeRequest,
    signature: u8,
) -> [u8; CTRL_SEG_LEN] {
    let mut seg = [0u8; CTRL_SEG_LEN];
    write_bits_be(&mut seg, CTRL_BIT_OPCODE, CTRL_BIT_OPCODE_W, opcode as u64);
    write_bits_be(
        &mut seg,
        CTRL_BIT_WQE_IDX,
        CTRL_BIT_WQE_IDX_W,
        wqe_idx as u64,
    );
    write_bits_be(
        &mut seg,
        CTRL_BIT_QPN,
        CTRL_BIT_QPN_W,
        (qp_num & 0x00FF_FFFF) as u64,
    );
    write_bits_be(&mut seg, CTRL_BIT_DS, CTRL_BIT_DS_W, ds as u64);
    write_bits_be(&mut seg, CTRL_BIT_SIG, CTRL_BIT_SIG_W, signature as u64);
    // ce|se flags — bits[7:2]=ce, bits[1:0]=se. We pack the 2-bit
    // CqeRequest variant into bits[7:6] of byte 0x0B (the low byte
    // of dword 2 after signature).
    let flags = (cqe_req as u8) << 6;
    seg[0x0B] = flags;
    seg
}

/// Decode the opcode out of a control segment.
pub fn ctrl_opcode(seg: &[u8; CTRL_SEG_LEN]) -> u8 {
    read_bits_be(seg, CTRL_BIT_OPCODE, CTRL_BIT_OPCODE_W) as u8
}

/// Decode the qp_num.
pub fn ctrl_qp_num(seg: &[u8; CTRL_SEG_LEN]) -> u32 {
    read_bits_be(seg, CTRL_BIT_QPN, CTRL_BIT_QPN_W) as u32
}

/// Decode the wqe_idx.
pub fn ctrl_wqe_idx(seg: &[u8; CTRL_SEG_LEN]) -> u16 {
    read_bits_be(seg, CTRL_BIT_WQE_IDX, CTRL_BIT_WQE_IDX_W) as u16
}

/// Decode the data-segment count.
pub fn ctrl_ds(seg: &[u8; CTRL_SEG_LEN]) -> u8 {
    read_bits_be(seg, CTRL_BIT_DS, CTRL_BIT_DS_W) as u8
}

/// Build a pointer data segment.
pub fn build_data_seg_ptr(byte_count: u32, l_key: u32, va: u64) -> [u8; DATA_SEG_LEN] {
    let mut seg = [0u8; DATA_SEG_LEN];
    seg[0x00..0x04].copy_from_slice(&byte_count.to_be_bytes());
    seg[0x04..0x08].copy_from_slice(&l_key.to_be_bytes());
    seg[0x08..0x0C].copy_from_slice(&((va >> 32) as u32).to_be_bytes());
    seg[0x0C..0x10].copy_from_slice(&(va as u32).to_be_bytes());
    seg
}

/// Decode a pointer data segment back into (byte_count, l_key, va).
pub fn decode_data_seg_ptr(seg: &[u8; DATA_SEG_LEN]) -> (u32, u32, u64) {
    let bc = u32::from_be_bytes([seg[0], seg[1], seg[2], seg[3]]);
    let lk = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
    let vh = u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]]);
    let vl = u32::from_be_bytes([seg[12], seg[13], seg[14], seg[15]]);
    let va = ((vh as u64) << 32) | vl as u64;
    (bc, lk, va)
}
