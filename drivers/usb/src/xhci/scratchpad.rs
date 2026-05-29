//! Scratchpad Buffer Array (xHCI 1.2 §4.20).
//!
//! When `HCSPARAMS2.MAXSCRATCHPAD_BUFS > 0` the controller wants the
//! OS to allocate N 4-KiB pages, write each page's physical address
//! into a contiguous 64-bit array, and store the array base into
//! DCBAA entry 0.
//!
//! The pages back the controller's internal state save / restore
//! across run/halt cycles and across the SET_ADDRESS phase. Linux,
//! BSD, NetBSD all do the same dance.

#![allow(dead_code)]

/// Page size as required by xHCI (§4.20.5): the controller chooses
/// from PAGESIZE (always a power of 2 ≥ 4 KiB). Default 4 KiB matches
/// every commercial xHCI shipped.
pub const SCRATCH_PAGE_SIZE: usize = 4096;
/// Scratchpad Buffer Array must be 64-byte aligned (§4.20.5).
pub const SCRATCH_ARRAY_ALIGN: usize = 64;

/// Compute the scratchpad-array byte size for `n` buffers.
pub const fn scratchpad_array_bytes(n: usize) -> usize {
    n * 8
}

/// Encode one entry into the scratchpad buffer array.
///
/// xHCI 1.2 §4.20.5 requires each entry to point at a buffer whose
/// physical base is aligned to PAGESIZE. We hard-code PAGESIZE = 4 KiB
/// (the canonical xHCI default; QEMU + AMD Renoir + Phoenix all
/// report PAGESIZE = 1 = 4 KiB).
pub const fn encode_entry(page_phys: u64) -> u64 {
    page_phys & !((SCRATCH_PAGE_SIZE as u64) - 1)
}

/// Sanity-check that a phys address is page-aligned for use as a
/// scratchpad buffer.
pub const fn is_page_aligned(phys: u64) -> bool {
    (phys & ((SCRATCH_PAGE_SIZE as u64) - 1)) == 0
}

/// Sanity-check the scratchpad-array base alignment.
pub const fn is_array_aligned(phys: u64) -> bool {
    (phys & ((SCRATCH_ARRAY_ALIGN as u64) - 1)) == 0
}
