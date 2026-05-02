//! Completion Queue (CQ) context + `CREATE_CQ` input layout.
//!
//! Reference: public Mellanox PRM §16.3 ("Completion Queue Context")
//! + §15.7.4 ("CREATE_CQ command").
//!
//! The CQ context (cqc) is structurally a sibling of the EQ context
//! — 256 bytes followed by an 8-byte BE phys-addr list — with the
//! key difference that a CQ is bound to an **event queue** via the
//! `c_eqn` field. Asynchronous events on this CQ (overrun, errors)
//! get reported through that EQ.
//!
//! ## Layout
//!
//! | bits / bytes  | field         | notes                       |
//! |---------------|---------------|-----------------------------|
//! | 0x07 low 5    | log_cq_size   | bit-packed                  |
//! | 0x08..0x0A    | uar_page      | 24 bits                     |
//! | 0x0C          | log_page_size | byte                        |
//! | 0x0F          | c_eqn         | byte — bound EQ number      |
//!
//! Phys-addr list starts at offset 0x100 with 8-byte BE entries.

extern crate alloc;
use alloc::vec::Vec;

use super::bit_field::{read_bits_be, write_bits_be};

pub const CQC_LEN:           usize = 256;
pub const CQC_PA_LIST_OFF:   usize = 256;
pub const CQC_PA_ENTRY_LEN:  usize = 8;

pub const CQC_OFF_LOG_PAGE_SIZE: usize = 0x0C;
pub const CQC_OFF_C_EQN:         usize = 0x0F;

pub const CQC_BIT_LOG_CQ_SIZE:   usize = 0x07 * 8 + 3; // low 5 bits of byte 0x07
pub const CQC_BIT_LOG_CQ_SIZE_W: usize = 5;
pub const CQC_BIT_UAR_PAGE:      usize = 0x08 * 8;
pub const CQC_BIT_UAR_PAGE_W:    usize = 24;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CqError {
    BadLogCqSize,
    BadUarPage,
    NoPages,
}

#[derive(Copy, Clone, Debug)]
pub struct CqParams {
    /// log2 of the CQ depth (in CQEs).
    pub log_cq_size:    u8,
    /// UAR page index for the CQ doorbell.
    pub uar_page:       u32,
    /// log2 of the CQ buffer-page size (e.g. 12 for 4-KiB pages).
    pub log_page_size:  u8,
    /// EQ number this CQ is bound to for async events.
    pub c_eqn:          u8,
}

/// Build a CREATE_CQ input mailbox: 256-byte cqc followed by the
/// 8-byte BE phys-addr list. Stage-7-style transport feeds this
/// through `issue_command_with_input_mailbox`.
pub fn build_create_cq_input(
    params: CqParams,
    pages:  &[u64],
) -> Result<Vec<u8>, CqError> {
    if pages.is_empty()                 { return Err(CqError::NoPages); }
    if params.log_cq_size >= (1 << 5)   { return Err(CqError::BadLogCqSize); }
    if params.uar_page    >= (1 << 24)  { return Err(CqError::BadUarPage); }

    let total = CQC_PA_LIST_OFF + pages.len() * CQC_PA_ENTRY_LEN;
    let mut out = alloc::vec![0u8; total];

    write_bits_be(&mut out,
        CQC_BIT_LOG_CQ_SIZE, CQC_BIT_LOG_CQ_SIZE_W,
        params.log_cq_size as u64);
    write_bits_be(&mut out,
        CQC_BIT_UAR_PAGE, CQC_BIT_UAR_PAGE_W,
        params.uar_page as u64);

    out[CQC_OFF_LOG_PAGE_SIZE] = params.log_page_size;
    out[CQC_OFF_C_EQN]         = params.c_eqn;

    for (i, &pa) in pages.iter().enumerate() {
        let off = CQC_PA_LIST_OFF + i * CQC_PA_ENTRY_LEN;
        out[off..off + 8].copy_from_slice(&pa.to_be_bytes());
    }
    Ok(out)
}

/// Round-trip the CREATE_CQ input back to params — for smoke tests
/// + diagnostics.
pub fn decode_create_cq_input(bytes: &[u8]) -> CqParams {
    CqParams {
        log_cq_size: read_bits_be(bytes,
            CQC_BIT_LOG_CQ_SIZE, CQC_BIT_LOG_CQ_SIZE_W) as u8,
        uar_page: read_bits_be(bytes,
            CQC_BIT_UAR_PAGE, CQC_BIT_UAR_PAGE_W) as u32,
        log_page_size: bytes[CQC_OFF_LOG_PAGE_SIZE],
        c_eqn:         bytes[CQC_OFF_C_EQN],
    }
}
