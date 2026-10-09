//! Event Queue (EQ) context + `CREATE_EQ` input layout.
//!
//! Reference: public Mellanox PRM §16.4 ("Event Queue Context") +
//! §15.7.1 ("CREATE_EQ command").
//!
//! ## What this stage commits to (Stage 6)
//!
//! Pure data layout — the `EqContext` byte array + builder. The live
//! cmdq transport for posting `CREATE_EQ` lives in Stage 7, where we
//! hook in DMA backing for the EQ buffer pages and wire the address
//! list into the input mailbox tail.
//!
//! ## EQ Context (eqc) layout
//!
//! The EQ context is 256 bytes per PRM §16.4. Stage 6 surfaces the
//! byte-aligned + bit-packed fields modesetters and IRQ binders use:
//!
//! | bits         | field            | notes                       |
//! |--------------|------------------|-----------------------------|
//! | 0x00 byte    | status (high 4)  | initialised to 0            |
//! | 0x01 byte    | ec / oi flags    | bit 7 = ec, bit 6 = oi      |
//! | 0x18..1F     | log_eq_size      | 5 bits at byte 0x07 low     |
//! | 0x40..57     | uar_page         | 24 bits at bytes 0x08..0x0A |
//! | 0x58..5F     | intr (vec idx)   | byte 0x0B                   |
//! | 0x60..67     | log_page_size    | byte 0x0C                   |
//!
//! Followed by an N-entry phys-addr list of 8-byte BE entries
//! starting at offset 0x100 (256 bytes in).

extern crate alloc;
use alloc::vec::Vec;

use super::bit_field::{read_bits_be, write_bits_be};

/// Length of the eqc structure proper.
pub const EQC_LEN: usize = 256;
/// Offset (within the CREATE_EQ input mailbox) of the phys-addr list
/// that follows the eqc.
pub const EQC_PA_LIST_OFF: usize = 256;
/// Each phys-addr-list entry is a BE u64.
pub const EQC_PA_ENTRY_LEN: usize = 8;

// Byte offsets we expose as named accessors.
pub const EQC_OFF_STATUS: usize = 0x00;
pub const EQC_OFF_FLAGS: usize = 0x01;
pub const EQC_OFF_LOG_EQ_SIZE: usize = 0x07;
pub const EQC_OFF_UAR_PAGE_HIGH: usize = 0x08;
pub const EQC_OFF_INTR_VECTOR: usize = 0x0B;
pub const EQC_OFF_LOG_PAGE_SIZE: usize = 0x0C;

// Bit positions within the eqc — used by the bit_field helpers.
pub const EQC_BIT_LOG_EQ_SIZE: usize = 0x07 * 8 + 3; // low 5 bits of byte 0x07
pub const EQC_BIT_LOG_EQ_SIZE_W: usize = 5;
pub const EQC_BIT_UAR_PAGE: usize = 0x08 * 8; // 24 bits across 0x08..0x0B
pub const EQC_BIT_UAR_PAGE_W: usize = 24;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EqError {
    /// Caller asked for a log_eq_size that doesn't fit in 5 bits.
    BadLogEqSize,
    /// `uar_page` doesn't fit in 24 bits.
    BadUarPage,
    /// Empty phys-addr list — EQ needs at least one backing page.
    NoPages,
}

/// Parameters for an EQ being created. Stage 6 keeps the surface
/// minimal — Stage 7 will add async-event mask + irq binding.
#[derive(Copy, Clone, Debug)]
pub struct EqParams {
    /// log2 of the EQ depth (in EQEs). PRM allows 1..16 in practice.
    pub log_eq_size: u8,
    /// UAR page index for the doorbell that arms the EQ.
    pub uar_page: u32,
    /// MSI-X interrupt vector to route this EQ's events to.
    pub intr_vector: u8,
    /// log2 of the EQ-buffer page size, e.g. 12 for 4-KiB pages.
    pub log_page_size: u8,
}

/// Build the CREATE_EQ input mailbox payload — the 256-byte eqc
/// followed by an 8-byte BE phys-addr per backing page. The total
/// length is `EQC_PA_LIST_OFF + pages.len() * 8` bytes; callers feed
/// this through Stage-4's chained-mailbox path.
pub fn build_create_eq_input(params: EqParams, pages: &[u64]) -> Result<Vec<u8>, EqError> {
    if pages.is_empty() {
        return Err(EqError::NoPages);
    }
    if params.log_eq_size >= (1 << 5) {
        return Err(EqError::BadLogEqSize);
    }
    if params.uar_page >= (1 << 24) {
        return Err(EqError::BadUarPage);
    }

    let total = EQC_PA_LIST_OFF + pages.len() * EQC_PA_ENTRY_LEN;
    let mut out = alloc::vec![0u8; total];

    // Bit-packed fields.
    write_bits_be(
        &mut out,
        EQC_BIT_LOG_EQ_SIZE,
        EQC_BIT_LOG_EQ_SIZE_W,
        params.log_eq_size as u64,
    );
    write_bits_be(
        &mut out,
        EQC_BIT_UAR_PAGE,
        EQC_BIT_UAR_PAGE_W,
        params.uar_page as u64,
    );

    // Byte-aligned fields.
    out[EQC_OFF_INTR_VECTOR] = params.intr_vector;
    out[EQC_OFF_LOG_PAGE_SIZE] = params.log_page_size;

    // Phys-addr list — each entry is a BE u64 at EQC_PA_LIST_OFF +
    // i*8.
    for (i, &pa) in pages.iter().enumerate() {
        let off = EQC_PA_LIST_OFF + i * EQC_PA_ENTRY_LEN;
        out[off..off + 8].copy_from_slice(&pa.to_be_bytes());
    }
    Ok(out)
}

/// Decode the parameters back from a CREATE_EQ input payload — used
/// by smokes to round-trip the builder, and by diagnostics.
pub fn decode_create_eq_input(bytes: &[u8]) -> EqParams {
    EqParams {
        log_eq_size: read_bits_be(bytes, EQC_BIT_LOG_EQ_SIZE, EQC_BIT_LOG_EQ_SIZE_W) as u8,
        uar_page: read_bits_be(bytes, EQC_BIT_UAR_PAGE, EQC_BIT_UAR_PAGE_W) as u32,
        intr_vector: bytes[EQC_OFF_INTR_VECTOR],
        log_page_size: bytes[EQC_OFF_LOG_PAGE_SIZE],
    }
}
