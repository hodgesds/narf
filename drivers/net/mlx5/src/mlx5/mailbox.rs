//! mlx5 multi-block mailbox chain — Stage 4.
//!
//! Long command payloads (more than 480 bytes of input or output)
//! span multiple `MailboxBlock`s linked through the `next_block_h/l`
//! pointer at offset `0x1F0` of each block. This module separates the
//! pure-data layout work (testable without DMA) from the live
//! `LiveChain` that wraps it around `DmaBuffer` allocations (in
//! `mlx5.rs`).
//!
//! Reference: PRM §3.5.3.
//!
//! ## Layout
//!
//! - Block 0 holds payload bytes `[0..480]`.
//! - Block 1 holds `[480..960]`, …
//! - Block N holds `[N*480 .. (N+1)*480]` (clamped to payload len).
//! - Each block's chain pointer is the phys addr of the next block;
//!   the last block stores `0`.
//! - Each block carries its own `block_number` (sequential, BE u16
//!   at offset `0x1FC`), `token` (byte at `0x1FE`, identical across
//!   the chain so FW can correlate), and XOR-checksum signature
//!   (byte at `0x1FF`).

extern crate alloc;
use alloc::vec::Vec;

use super::cmd::{build_mailbox_block, MAILBOX_BLOCK_LEN, MAILBOX_PAYLOAD_LEN};

/// Number of 512-byte blocks needed to carry `byte_len` bytes of
/// payload. A zero-length payload still costs one block (CQEs that
/// declare a non-inline mailbox always need at least the head).
pub fn block_count_for(byte_len: usize) -> usize {
    if byte_len == 0 {
        1
    } else {
        byte_len.div_ceil(MAILBOX_PAYLOAD_LEN)
    }
}

/// Build a chain of populated mailbox blocks for an *input* payload.
/// Caller supplies the per-block phys addresses (one per block) so
/// each block's `next_block_h/l` pointer is correct.
///
/// The number of phys addrs MUST equal `block_count_for(payload.len())`.
pub fn write_input_chain(
    payload: &[u8],
    block_phys: &[u64],
    token: u8,
) -> Vec<[u8; MAILBOX_BLOCK_LEN]> {
    let n = block_phys.len();
    debug_assert!(n >= 1);
    let mut out: Vec<[u8; MAILBOX_BLOCK_LEN]> = Vec::with_capacity(n);
    for i in 0..n {
        let start = i * MAILBOX_PAYLOAD_LEN;
        let end = (start + MAILBOX_PAYLOAD_LEN).min(payload.len());
        let chunk: &[u8] = if start < payload.len() {
            &payload[start..end]
        } else {
            &[]
        };
        let next = if i + 1 < n { block_phys[i + 1] } else { 0 };
        let block = build_mailbox_block(chunk, i as u16, token, next);
        out.push(block);
    }
    out
}

/// Reassemble a contiguous output payload from a chain of blocks. The
/// caller supplies `byte_len` (the firmware-declared output length)
/// so we know exactly how many bytes are valid.
pub fn read_output_chain(blocks: &[[u8; MAILBOX_BLOCK_LEN]], byte_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(byte_len);
    for block in blocks {
        if out.len() >= byte_len {
            break;
        }
        let take = (byte_len - out.len()).min(MAILBOX_PAYLOAD_LEN);
        out.extend_from_slice(&block[..take]);
    }
    out
}
