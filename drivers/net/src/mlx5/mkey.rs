//! Memory key (mkey) — Stage 13.
//!
//! Reference: public Mellanox PRM §8.4 ("Memory Translation +
//! Protection") + §15.7.10 ("CREATE_MKEY").
//!
//! An mkey covers a virtual-address range against a protection
//! domain — every WQE pointer-data segment carries the `l_key`
//! produced here. Stage 13 exposes a minimal "physical-address
//! mkey" form that maps a single contiguous DMA region; the
//! more general indirect mkey + UMR (User-Mode Registration)
//! flows land in a later stage.
//!
//! ## CREATE_MKEY input layout
//!
//! 64-byte mkey context followed by an 8-byte BE phys-addr list.
//!
//! | bits / bytes | field                | width                  |
//! |--------------|----------------------|------------------------|
//! | 0x00 hi nib  | access_flags         | local-write / -read    |
//! | 0x04..0x07   | qpn_mkey             | 24-bit pd low + variant |
//! | 0x18..0x20   | start_addr           | u64 BE                 |
//! | 0x20..0x28   | length               | u64 BE                 |
//! | 0x2C..0x30   | log_page_size        | u32 BE                 |

extern crate alloc;
use alloc::vec::Vec;

pub const MKC_LEN:           usize = 64;
pub const MKC_PA_LIST_OFF:   usize = 64;
pub const MKC_PA_ENTRY_LEN:  usize = 8;

pub const MKC_OFF_ACCESS:        usize = 0x00;
pub const MKC_OFF_QPN_PD:        usize = 0x04;
pub const MKC_OFF_START_ADDR:    usize = 0x18;
pub const MKC_OFF_LENGTH:        usize = 0x20;
pub const MKC_OFF_LOG_PAGE_SIZE: usize = 0x2C;

/// Access-rights bits (high nibble of byte 0x00).
pub const MKC_ACCESS_LOCAL_WRITE: u8 = 1 << 7;
pub const MKC_ACCESS_LOCAL_READ:  u8 = 1 << 6;
pub const MKC_ACCESS_REMOTE_READ: u8 = 1 << 5;
pub const MKC_ACCESS_REMOTE_WRITE: u8 = 1 << 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MkeyError { NoPages, BadPd }

#[derive(Copy, Clone, Debug)]
pub struct MkeyParams {
    /// Protection domain.
    pub pd:             u32,
    /// Combined access bits (`MKC_ACCESS_*`).
    pub access:         u8,
    /// Virtual base address.
    pub start_addr:     u64,
    /// Region length in bytes.
    pub length:         u64,
    /// log2 of the per-page size used by the phys-addr list.
    pub log_page_size:  u32,
}

/// Build the CREATE_MKEY input mailbox.
pub fn build_create_mkey_input(
    params: MkeyParams,
    pages:  &[u64],
) -> Result<Vec<u8>, MkeyError> {
    if pages.is_empty()         { return Err(MkeyError::NoPages); }
    if params.pd >= (1 << 24)   { return Err(MkeyError::BadPd); }
    let total = MKC_PA_LIST_OFF + pages.len() * MKC_PA_ENTRY_LEN;
    let mut out = alloc::vec![0u8; total];
    out[MKC_OFF_ACCESS] = params.access;
    // qpn_pd at byte 4..7: low 24 bits = pd, high byte = variant 0.
    out[MKC_OFF_QPN_PD..MKC_OFF_QPN_PD + 4]
        .copy_from_slice(&params.pd.to_be_bytes());
    out[MKC_OFF_START_ADDR..MKC_OFF_START_ADDR + 8]
        .copy_from_slice(&params.start_addr.to_be_bytes());
    out[MKC_OFF_LENGTH..MKC_OFF_LENGTH + 8]
        .copy_from_slice(&params.length.to_be_bytes());
    out[MKC_OFF_LOG_PAGE_SIZE..MKC_OFF_LOG_PAGE_SIZE + 4]
        .copy_from_slice(&params.log_page_size.to_be_bytes());
    for (i, &pa) in pages.iter().enumerate() {
        let off = MKC_PA_LIST_OFF + i * MKC_PA_ENTRY_LEN;
        out[off..off + 8].copy_from_slice(&pa.to_be_bytes());
    }
    Ok(out)
}

/// L_KEY / R_KEY are derived from `mkey_index` plus an 8-bit variant
/// the driver chooses. PRM convention: key = (mkey_index << 8) |
/// variant. Stage 13 always uses variant 0.
pub fn lkey_for(mkey_index: u32) -> u32 {
    (mkey_index & 0x00FF_FFFF) << 8
}
