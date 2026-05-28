//! JBD2 journal — re-exports the shared replay decoder from
//! `drivers/fs/ext2/journal.rs` and adds **write-side** helpers:
//! encode a journal superblock, a descriptor block carrying N tags,
//! and a commit-record marker. The replay path reads a transaction
//! as a (descriptor → data blocks → commit) sequence; the encode
//! path here produces the same shape so a test image can be
//! synthesised and round-tripped through the replay walker.
//!
//! Sources (post-relicense — NARF is GPL-2.0+ as of 2026-05-20):
//! - Linux `include/linux/jbd2.h` — on-disk layout.
//! - Linux `fs/jbd2/journal.c::jbd2_journal_get_log_tail`,
//!   `jbd2_journal_create_marker` — superblock + commit marker
//!   building.
//! - Linux `fs/jbd2/commit.c::jbd2_journal_commit_transaction` —
//!   the descriptor + data + commit sequence we mirror.
//! - Linux `fs/jbd2/recovery.c::do_one_pass` — the replay walker.

extern crate alloc;

pub use narf_drivers_fs_ext2::journal::{
    JBD2_MAGIC_NUMBER, block_type, tag_flag,
    JournalHeader, JournalSuperblock, DescriptorTag, DescriptorBlock,
    CommitBlock, RevokeBlock, ReplayReport, JournalError,
    replay_journal, replay_journal_flat,
};

use alloc::vec::Vec;

/// Encode a JBD2 superblock V2 — the only flavour ext4 produces in
/// 2026.  `buf` MUST be sized exactly to `block_size` (the journal
/// block size in bytes); on return it carries the on-disk v2
/// superblock layout from `journal_superblock_s`.
///
/// Linux `include/linux/jbd2.h::journal_superblock_s` v2 layout
/// (big-endian on disk):
///   off 0   : s_header        12 bytes
///   off 12  : s_blocksize     u32
///   off 16  : s_maxlen        u32
///   off 20  : s_first         u32
///   off 24  : s_sequence      u32
///   off 28  : s_start         u32 (0 = clean)
///   off 32  : s_errno         i32
///   off 36  : s_feature_compat       u32
///   off 40  : s_feature_incompat     u32
///   off 44  : s_feature_ro_compat    u32
///   off 48  : s_uuid          16 bytes
pub fn encode_superblock(
    buf: &mut [u8],
    block_size: u32,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
) {
    if buf.len() < 48 {
        return;
    }
    // s_header: magic + blocktype + sequence (sequence is the FIRST
    // commit ID expected, NOT the superblock's own sequence).
    buf[0..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
    buf[4..8].copy_from_slice(&block_type::SUPERBLOCK_V2.to_be_bytes());
    buf[8..12].copy_from_slice(&0u32.to_be_bytes());
    buf[12..16].copy_from_slice(&block_size.to_be_bytes());
    buf[16..20].copy_from_slice(&maxlen.to_be_bytes());
    buf[20..24].copy_from_slice(&first.to_be_bytes());
    buf[24..28].copy_from_slice(&sequence.to_be_bytes());
    buf[28..32].copy_from_slice(&start.to_be_bytes());
    buf[32..36].copy_from_slice(&0i32.to_be_bytes());
    // feature flag triplet — all zero is the legitimate "no
    // optional features" reply for our minimal write path.
    if buf.len() >= 48 {
        buf[36..40].copy_from_slice(&0u32.to_be_bytes());
        buf[40..44].copy_from_slice(&0u32.to_be_bytes());
        buf[44..48].copy_from_slice(&0u32.to_be_bytes());
    }
    // UUID at offset 48: leave zero (the read path doesn't enforce
    // it).
}

/// Encode a descriptor block listing `tags` — one tag per FS-side
/// target block whose data follows in the next `tags.len()` journal
/// blocks.
///
/// Tag stride: 8 bytes per tag (target_blocknr:u32 + flags:u32),
/// followed by a 16-byte UUID unless the tag's `SAME_UUID` flag is
/// set. We always set `SAME_UUID` after the first tag because all
/// the tags in one transaction share the volume UUID — this is
/// what Linux does too (`do_one_pass`'s tag walk).
///
/// The last tag in the list gets the `LAST_TAG` flag so the read
/// path stops scanning.
///
/// Linux `fs/jbd2/commit.c::write_journal_block_descriptor`.
pub fn encode_descriptor(
    buf: &mut [u8],
    sequence: u32,
    tags: &[(u64, u32)], // (target_block, flags)
) {
    if buf.len() < 12 + tags.len() * 8 {
        return;
    }
    buf[0..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
    buf[4..8].copy_from_slice(&block_type::DESCRIPTOR.to_be_bytes());
    buf[8..12].copy_from_slice(&sequence.to_be_bytes());
    let mut cursor = 12usize;
    let last_i = tags.len().saturating_sub(1);
    for (i, (target, flags)) in tags.iter().enumerate() {
        let mut t_flags = *flags | tag_flag::SAME_UUID; // dedup
        if i == 0 {
            // First tag should NOT have SAME_UUID — caller's UUID
            // is the canonical one. Per Linux convention this also
            // means a 16-byte UUID would follow on the FIRST tag.
            t_flags &= !tag_flag::SAME_UUID;
        }
        if i == last_i {
            t_flags |= tag_flag::LAST_TAG;
        }
        if cursor + 8 > buf.len() {
            return;
        }
        buf[cursor..cursor + 4].copy_from_slice(&(*target as u32).to_be_bytes());
        buf[cursor + 4..cursor + 8].copy_from_slice(&t_flags.to_be_bytes());
        cursor += 8;
        if i == 0 {
            // 16-byte UUID slot for the first tag. We leave it zero
            // — replay treats it as the volume UUID and our test
            // image has no UUID enforcement.
            if cursor + 16 > buf.len() {
                return;
            }
            cursor += 16;
        }
    }
}

/// Encode a commit-record block. This is the transaction-close
/// marker that the replay path looks for to install pending data.
///
/// Linux `fs/jbd2/commit.c::jbd2_journal_commit_transaction` writes
/// `struct commit_header` at the end of the transaction with a
/// timestamp (`h_commit_sec` / `h_commit_nsec`) and an optional
/// checksum. Our minimal encoder writes only the common 12-byte
/// header.
pub fn encode_commit(buf: &mut [u8], sequence: u32) {
    if buf.len() < 12 {
        return;
    }
    buf[0..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
    buf[4..8].copy_from_slice(&block_type::COMMIT.to_be_bytes());
    buf[8..12].copy_from_slice(&sequence.to_be_bytes());
}

/// Encode a revoke block listing FS-side block numbers that
/// subsequent transactions should NOT replay because a newer
/// version exists outside the journal. Linux
/// `struct jbd2_journal_revoke_header_s` + the trailing array.
///
///   off 0  : header        12 bytes
///   off 12 : r_count       u32 (BE) — total bytes including header
///   off 16 : blocks[]      u32 BE each
pub fn encode_revoke(buf: &mut [u8], sequence: u32, revoked: &[u64]) {
    if buf.len() < 16 + revoked.len() * 4 {
        return;
    }
    buf[0..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
    buf[4..8].copy_from_slice(&block_type::REVOKE.to_be_bytes());
    buf[8..12].copy_from_slice(&sequence.to_be_bytes());
    let total = (16 + revoked.len() * 4) as u32;
    buf[12..16].copy_from_slice(&total.to_be_bytes());
    let mut cursor = 16usize;
    for &b in revoked {
        if cursor + 4 > buf.len() {
            return;
        }
        buf[cursor..cursor + 4].copy_from_slice(&(b as u32).to_be_bytes());
        cursor += 4;
    }
}

/// Build a complete one-transaction journal image: superblock
/// (block 0), descriptor + N data blocks + commit (starting at
/// block `first`). Returns the assembled image as a `Vec<u8>`
/// sized to `block_size * total_blocks`. Used by smokes to verify
/// the descriptor/commit encoders round-trip through the replay
/// walker.
///
/// `tags` carries `(target_fs_block, data_bytes)` pairs. Caller
/// chooses `block_size`; each data slice must be exactly
/// `block_size` bytes.
pub fn build_one_txn_image(
    block_size: usize,
    tags: &[(u64, Vec<u8>)],
    sequence: u32,
) -> Vec<u8> {
    let first = 1u32;
    let n_tags = tags.len() as u32;
    // Layout: [sb][descriptor][data*N][commit]
    let total = 1 + 1 + n_tags + 1;
    let mut image = alloc::vec![0u8; (total as usize) * block_size];

    // Superblock.
    encode_superblock(
        &mut image[..block_size],
        block_size as u32,
        total,
        first,
        sequence,
        first, // start = first (we have one txn pending replay)
    );

    // Descriptor.
    let desc_off = block_size;
    let mut tag_list: Vec<(u64, u32)> = Vec::with_capacity(tags.len());
    for (t, _) in tags {
        tag_list.push((*t, 0));
    }
    encode_descriptor(&mut image[desc_off..desc_off + block_size], sequence, &tag_list);

    // Data blocks.
    for (i, (_, data)) in tags.iter().enumerate() {
        let off = block_size + block_size + i * block_size;
        let len = data.len().min(block_size);
        image[off..off + len].copy_from_slice(&data[..len]);
    }

    // Commit.
    let commit_off = block_size + block_size + (tags.len() * block_size);
    encode_commit(&mut image[commit_off..commit_off + block_size], sequence);

    image
}
