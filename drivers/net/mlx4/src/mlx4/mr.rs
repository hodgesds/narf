//! Memory region and translation-table support — MTT entries, MPT contexts,
//! lkey/rkey swizzle.
//!
//! ConnectX-3 implements the `mlx4` ICM-based memory model: the host carves
//! out an *ICM* (InfiniCon Context Memory) region that the firmware uses as
//! backing for all hardware context blocks, including the Memory Protection
//! Table (MPT). Each MPT entry describes one memory region: its virtual-
//! address window, protection domain, access rights and — for non-physical
//! mappings — a chain of 8-byte MTT (Memory Translation Table) entries
//! carrying the scatter-gather physical addresses.
//!
//! The two functions [`hw_index_to_key`] / [`key_to_hw_index`] perform the
//! byte-rotation between the driver's flat MPT index and the 32-bit lkey/rkey
//! value placed in WQEs. [`build_mpt`] serialises an [`MptParams`] descriptor
//! into the 64-byte big-endian context block written to the firmware via
//! `SW2HW_MPT`.
//!
//! Reference: ConnectX-3 PRM §8 ("Memory Management") and §9.4 (SW2HW_MPT
//! command and MPT context layout).
//!
//! ## MPT context layout (64 bytes, big-endian)
//!
//! | offset | field            | width |
//! |--------|------------------|-------|
//! | 0x00   | flags            | u32   |
//! | 0x04   | qpn / reserved   | u32   |
//! | 0x08   | key (hw-index)   | u32   |
//! | 0x0c   | pd \| pd_flags   | u32   |
//! | 0x10   | start_addr       | u64   |
//! | 0x18   | length           | u64   |
//! | 0x20   | lkey / reserved  | u32   |
//! | 0x24   | win_cnt          | u32   |
//! | 0x2c   | mtt_addr         | u64   |
//! | 0x34   | mtt_sz           | u32   |
//! | 0x38   | entity_size      | u32   |
//! | 0x3c   | first_byte_off   | u32   |

use super::wire::{put_be32, put_be64};

// ── MPT flag bits ─────────────────────────────────────────────────────────────

/// Software-owns flag: firmware treats this MPT entry as not yet activated
/// when these four bits (28..31) are all set.
pub const MLX4_MPT_FLAG_SW_OWNS: u32 = 0xf << 28;

/// Memory I/O flag: marks the region as an MMIO bar mapping.
pub const MLX4_MPT_FLAG_MIO: u32 = 1 << 17;

/// Physical flag: the MPT describes a contiguous physical region; the MTT
/// chain is bypassed and `mtt_addr` is ignored.
pub const MLX4_MPT_FLAG_PHYSICAL: u32 = 1 << 9;

/// Region flag: distinguishes a memory region from a memory window.
pub const MLX4_MPT_FLAG_REGION: u32 = 1 << 8;

/// PD flags: enable invalidation. These two bits are ORed into the `pd_flags`
/// dword at offset 0x0c alongside the protection-domain ID.
pub const MLX4_MPT_PD_FLAG_EN_INV: u32 = 3 << 24;

// ── Access-permission bits ────────────────────────────────────────────────────

/// Local-read access right bit.
pub const MLX4_PERM_LOCAL_READ: u32 = 1 << 10;

/// Local-write access right bit.
pub const MLX4_PERM_LOCAL_WRITE: u32 = 1 << 11;

// ── MTT entries ───────────────────────────────────────────────────────────────

/// Present bit for an 8-byte MTT entry. The firmware treats an entry without
/// this bit as a hole in the scatter-gather list.
pub const MLX4_MTT_FLAG_PRESENT: u64 = 1;

/// Construct the host-endian value for one MTT entry.
///
/// The caller is responsible for writing the returned `u64` to the mailbox
/// in big-endian byte order before submitting `WRITE_MTT`.
#[inline]
pub fn mtt_entry(phys_addr: u64) -> u64 {
    phys_addr | MLX4_MTT_FLAG_PRESENT
}

// ── lkey / rkey byte-rotation ─────────────────────────────────────────────────

/// Rotate a flat MPT hardware index into the lkey/rkey placed in WQEs.
///
/// The PRM defines the key as a byte-rotation of the index: the low byte of
/// the index becomes the high byte of the key, and the upper 24 bits shift
/// down by one byte.
#[inline]
pub fn hw_index_to_key(ind: u32) -> u32 {
    ind.rotate_left(8)
}

/// Reverse the byte-rotation: recover the MPT hardware index from an lkey
/// or rkey value.
#[inline]
pub fn key_to_hw_index(key: u32) -> u32 {
    key.rotate_left(24)
}

// ── MPT context builder ───────────────────────────────────────────────────────

/// Length of a serialised MPT context block.
pub const MPT_ENTRY_LEN: usize = 64;

/// Input parameters for [`build_mpt`].
#[derive(Copy, Clone, Debug)]
pub struct MptParams {
    /// Protection domain ID.
    pub pd: u32,
    /// Access-rights bits (`MLX4_PERM_LOCAL_{READ,WRITE}` and remote
    /// equivalents OR-ed together).
    pub access: u32,
    /// Driver-assigned key (the `hw_index` before byte-rotation; [`build_mpt`]
    /// calls [`key_to_hw_index`] internally).
    pub key: u32,
    /// Virtual base address of the region.
    pub start: u64,
    /// Region length in bytes.
    pub length: u64,
    /// Physical address of the first MTT entry for scatter-gather mappings.
    /// Ignored when `physical` is `true`.
    pub mtt_addr: u64,
    /// Log₂ of the page size used by the MTT scatter-gather list, stored in
    /// the `entity_size` field.
    pub page_shift: u32,
    /// When `true` the region is a contiguous physical mapping; `mtt_addr` is
    /// zeroed in the context and `MLX4_MPT_FLAG_PHYSICAL` is set in flags.
    pub physical: bool,
}

/// Serialise an [`MptParams`] descriptor into a 64-byte big-endian MPT
/// context block suitable for submission via `SW2HW_MPT`.
///
/// The returned array is zeroed first; only fields defined by the PRM are
/// written — reserved bytes remain zero.
pub fn build_mpt(p: &MptParams) -> [u8; MPT_ENTRY_LEN] {
    let mut b = [0u8; MPT_ENTRY_LEN];

    // flags @0x00
    let flags = MLX4_MPT_FLAG_MIO
        | MLX4_MPT_FLAG_REGION
        | p.access
        | if p.physical {
            MLX4_MPT_FLAG_PHYSICAL
        } else {
            MLX4_MPT_FLAG_SW_OWNS
        };
    put_be32(&mut b, 0x00, flags);

    // qpn @0x04 — zero (not a window)
    // key @0x08
    put_be32(&mut b, 0x08, key_to_hw_index(p.key));

    // pd_flags @0x0c
    put_be32(&mut b, 0x0c, p.pd | MLX4_MPT_PD_FLAG_EN_INV);

    // start @0x10
    put_be64(&mut b, 0x10, p.start);

    // length @0x18
    put_be64(&mut b, 0x18, p.length);

    // lkey @0x20 — zero; win_cnt @0x24 — zero

    // mtt_addr @0x2c — zero for physical regions, scatter-gather address otherwise
    let mtt = if p.physical { 0 } else { p.mtt_addr };
    put_be64(&mut b, 0x2c, mtt);

    // mtt_sz @0x34 — zero (filled by caller once MTT chain length is known)

    // entity_size @0x38
    put_be32(&mut b, 0x38, p.page_shift);

    // first_byte_offset @0x3c — zero

    b
}
