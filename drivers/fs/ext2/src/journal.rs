//! JBD2 (ext3/4 journal) on-disk format + read-side replay.
//!
//! Pure-logic parsers + a replay driver that walks transactions from
//! the journal-superblock's `s_start` for `s_sequence` and builds a
//! map of `target_fs_block → replayed_data`. The caller (typically
//! `Ext2Volume`) uses that override map to serve reads after an
//! unclean shutdown without ever touching the disk — RO replay only.
//!
//! NARF is GPL-2.0-or-later (relicensed 2026-05-20), so the Linux
//! `fs/jbd2/` sources are directly cited where the on-disk layout or
//! recovery algorithm comes from them.
//!
//! References (all big-endian on disk — JBD2 is a network-byte-order
//! format):
//!
//! - Linux `include/linux/jbd2.h` — `struct journal_header_s`,
//!   `struct journal_block_tag_s`, `struct journal_superblock_s`,
//!   `struct commit_header`, block-type constants, tag-flag constants.
//! - Linux `fs/jbd2/journal.c` — `journal_get_superblock` (magic +
//!   superblock_v1/v2 dispatch).
//! - Linux `fs/jbd2/recovery.c` — `do_one_pass` (the descriptor /
//!   commit / revoke walker this module reimplements), `count_tags`
//!   (tag stride math), `jbd2_journal_revoke` (revoke-table semantics).
//!
//! Deferred for follow-up commits:
//!   * Journal checksum feature (`JBD2_FEATURE_INCOMPAT_CSUM_V2/V3`)
//!     — we read past csum tags but don't verify them.
//!   * 64-bit block tags (`JBD2_FEATURE_INCOMPAT_64BIT`) — only the
//!     32-bit tag stride is implemented.
//!   * Async commit + fast commits — handled as plain commits if seen.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// JBD2 magic. ASCII "JBD\x99" big-endian. Linux
/// `include/linux/jbd2.h::JBD2_MAGIC_NUMBER`.
pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B_3998;

/// Block-type discriminator values. Linux
/// `include/linux/jbd2.h::JBD2_*_BLOCK`.
pub mod block_type {
    pub const DESCRIPTOR: u32 = 1;
    pub const COMMIT: u32 = 2;
    pub const SUPERBLOCK_V1: u32 = 3;
    pub const SUPERBLOCK_V2: u32 = 4;
    pub const REVOKE: u32 = 5;
}

/// Tag-flag bits (per-block flags within a descriptor entry). Linux
/// `include/linux/jbd2.h::JBD2_FLAG_*`.
pub mod tag_flag {
    /// First word of the data block matched JBD2_MAGIC_NUMBER and was
    /// escaped (XOR'd with zero in the journaled copy).
    pub const ESCAPE: u32 = 1;
    /// The UUID field is absent — reuse the previous tag's UUID.
    pub const SAME_UUID: u32 = 2;
    /// Block was deleted by this transaction (don't replay).
    pub const DELETED: u32 = 4;
    /// Last tag in this descriptor block.
    pub const LAST_TAG: u32 = 8;
}

/// Header common to every journal block — descriptor, commit,
/// superblock, revoke. Linux `journal_header_s`.
///
/// On disk (big-endian):
///   off 0  : h_magic     u32 — JBD2_MAGIC_NUMBER
///   off 4  : h_blocktype u32 — one of `block_type::*`
///   off 8  : h_sequence  u32 — transaction sequence number
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct JournalHeader {
    pub magic: u32,
    pub block_type: u32,
    pub sequence: u32,
}

impl JournalHeader {
    /// Decode the 12-byte common header. Returns `None` if the magic
    /// is wrong.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != JBD2_MAGIC_NUMBER {
            return None;
        }
        Some(Self {
            magic,
            block_type: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            sequence: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

/// Decoded journal superblock — subset of `journal_superblock_s` the
/// replay path actually needs. Linux
/// `include/linux/jbd2.h::journal_superblock_s`, v1 + v2 layouts.
///
/// On disk (big-endian, offsets from start of journal block 0):
///   off 0   : s_header        12 bytes (JournalHeader)
///   off 12  : s_blocksize     u32 — journal block size
///   off 16  : s_maxlen        u32 — total journal blocks
///   off 20  : s_first         u32 — first log block (after the SB)
///   off 24  : s_sequence      u32 — first commit ID expected at s_start
///   off 28  : s_start         u32 — first block of the log; 0 = clean
///   off 32  : s_errno         s32
///   v2 only:
///   off 36  : s_feature_compat       u32
///   off 40  : s_feature_incompat     u32
///   off 44  : s_feature_ro_compat    u32
///   off 48  : s_uuid          16 bytes
///   off 64  : s_nr_users      u32
///   off 68  : s_dynsuper      u32
///   off 72  : s_max_transaction u32
///   off 76  : s_max_trans_data u32
#[derive(Copy, Clone, Debug)]
pub struct JournalSuperblock {
    pub header: JournalHeader,
    pub block_size: u32,
    pub maxlen: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub errno: i32,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
}

impl JournalSuperblock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let header = JournalHeader::parse(buf)?;
        // Both v1 and v2 superblocks have the first 36 bytes laid
        // out the same way; v2 extends with feature flags. Reject
        // anything that isn't one of the two superblock blocktypes.
        if header.block_type != block_type::SUPERBLOCK_V1
            && header.block_type != block_type::SUPERBLOCK_V2
        {
            return None;
        }
        if buf.len() < 36 {
            return None;
        }
        let g32 = |o: usize| {
            u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
        };
        let block_size = g32(12);
        let maxlen = g32(16);
        let first = g32(20);
        let sequence = g32(24);
        let start = g32(28);
        let errno = g32(32) as i32;
        let (feature_compat, feature_incompat, feature_ro_compat) =
            if header.block_type == block_type::SUPERBLOCK_V2 && buf.len() >= 48 {
                (g32(36), g32(40), g32(44))
            } else {
                (0, 0, 0)
            };
        Some(Self {
            header,
            block_size,
            maxlen,
            first,
            sequence,
            start,
            errno,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
        })
    }

    /// `s_start == 0` means the journal was committed clean — no
    /// replay needed. Linux `recovery.c::do_one_pass` PASS_SCAN.
    pub fn is_clean(&self) -> bool {
        self.start == 0
    }
}

/// One entry inside a descriptor block. Linux `journal_block_tag_s`
/// (non-64BIT, non-csum_v3 stride = 8 bytes; UUID optional).
///
///   off 0 : t_blocknr u32 (target FS block, big-endian)
///   off 4 : t_flags   u32 (`tag_flag::*` bits)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DescriptorTag {
    /// FS-side target block this descriptor entry redirects to.
    pub target_block: u64,
    pub flags: u32,
}

impl DescriptorTag {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }
        let blocknr = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let flags = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Some(Self {
            target_block: blocknr as u64,
            flags,
        })
    }

    pub fn is_last(&self) -> bool {
        self.flags & tag_flag::LAST_TAG != 0
    }
    pub fn has_uuid(&self) -> bool {
        self.flags & tag_flag::SAME_UUID == 0
    }
    pub fn is_deleted(&self) -> bool {
        self.flags & tag_flag::DELETED != 0
    }
    pub fn is_escaped(&self) -> bool {
        self.flags & tag_flag::ESCAPE != 0
    }
}

/// One descriptor block fully decoded — header + tag list. Each tag
/// corresponds to a journal block following the descriptor (in
/// log-block order) that should be replayed into `tag.target_block`.
#[derive(Debug, Clone)]
pub struct DescriptorBlock {
    pub header: JournalHeader,
    pub tags: Vec<DescriptorTag>,
}

impl DescriptorBlock {
    /// Decode a descriptor block. `buf` is the full journal-block-
    /// sized buffer. Tags follow the 12-byte header; each tag is 8
    /// bytes, plus an optional 16-byte UUID unless `SAME_UUID` is
    /// set on the tag. Iteration stops at the first tag with the
    /// `LAST_TAG` flag (inclusive) or when the buffer is exhausted.
    ///
    /// Linux `fs/jbd2/recovery.c::do_one_pass`, the
    /// `JBD2_DESCRIPTOR_BLOCK` arm.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let header = JournalHeader::parse(buf)?;
        if header.block_type != block_type::DESCRIPTOR {
            return None;
        }
        let mut tags = Vec::new();
        let mut cursor = 12usize;
        loop {
            if cursor + 8 > buf.len() {
                break;
            }
            let tag = DescriptorTag::parse(&buf[cursor..cursor + 8])?;
            cursor += 8;
            let last = tag.is_last();
            let need_uuid = tag.has_uuid();
            tags.push(tag);
            if need_uuid {
                // Skip the 16-byte UUID.
                if cursor + 16 > buf.len() {
                    break;
                }
                cursor += 16;
            }
            if last {
                break;
            }
        }
        Some(Self { header, tags })
    }
}

/// Commit block — the marker that closes a transaction. Linux
/// `struct commit_header` (we only consult the common header; the
/// commit-time + checksum tail is ignored on the read-side replay).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommitBlock {
    pub header: JournalHeader,
}

impl CommitBlock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let header = JournalHeader::parse(buf)?;
        if header.block_type != block_type::COMMIT {
            return None;
        }
        Some(Self { header })
    }
}

/// Revoke block — list of FS blocks that should be skipped during
/// replay because a newer copy exists outside the journal. Linux
/// `struct jbd2_journal_revoke_header_s` + the trailing block-number
/// array.
///
///   off 0  : header        12 bytes
///   off 12 : r_count       u32 (BE) — total bytes including header
///   off 16 : blocks[]      u32 BE each (32-bit revoke records)
#[derive(Debug, Clone)]
pub struct RevokeBlock {
    pub header: JournalHeader,
    /// FS-side block numbers that this revoke record marks as
    /// "newer-version-exists-outside-journal — do not replay".
    pub revoked: Vec<u64>,
}

impl RevokeBlock {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        let header = JournalHeader::parse(buf)?;
        if header.block_type != block_type::REVOKE {
            return None;
        }
        if buf.len() < 16 {
            return None;
        }
        let count = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
        // r_count is total byte size of the revoke record including
        // the 12-byte header + the 4-byte count itself.
        if count < 16 || count > buf.len() {
            return None;
        }
        let payload = &buf[16..count];
        let mut revoked = Vec::with_capacity(payload.len() / 4);
        let mut i = 0;
        while i + 4 <= payload.len() {
            let b = u32::from_be_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]);
            revoked.push(b as u64);
            i += 4;
        }
        Some(Self { header, revoked })
    }
}

/// Outcome of a `replay_journal` run.
#[derive(Debug, Default, Clone)]
pub struct ReplayReport {
    /// Number of complete transactions (descriptor … commit pairs)
    /// that were replayed into `blocks_to_write`.
    pub transactions_replayed: u32,
    /// FS-block-number → journaled-data-bytes. Each value is exactly
    /// one filesystem block in length (matches the journal superblock's
    /// `s_blocksize`). The caller serves reads of these blocks from
    /// this map instead of from disk.
    pub blocks_to_write: BTreeMap<u64, Vec<u8>>,
}

/// Errors returned by `replay_journal`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// Block 0 didn't decode as a journal superblock (bad magic /
    /// blocktype).
    BadSuperblock,
    /// A descriptor or revoke block was corrupt (header magic ok,
    /// payload not parseable).
    CorruptBlock,
    /// The replay walk would have run off the end of the journal
    /// without seeing a commit.
    UnterminatedTransaction,
}

/// Replay the journal, returning a map of FS-block → post-replay
/// bytes.
///
/// `journal_blocks(i)` returns a slice covering journal block `i`
/// (size == `s_blocksize`). The function is pure — it never writes
/// to disk; the caller installs the resulting overrides into a
/// volume-level cache and serves reads from there for RO mounts.
///
/// Algorithm (Linux `fs/jbd2/recovery.c::do_one_pass`):
///   1. Read journal superblock from block 0.
///   2. If `s_start == 0` the journal is clean — no work.
///   3. Walk log blocks starting at `s_start`, wrapping at `maxlen`
///      back to `first`:
///        * Descriptor: each tag is paired with the next log block;
///          buffer the (target, data) pairs until a Commit closes
///          the transaction.
///        * Revoke: mark the listed FS blocks; any descriptor entry
///          for one of these blocks that was buffered AFTER the
///          revoke is replayed normally, but anything BEFORE the
///          revoke at the same sequence is dropped. (Spec-accurate
///          behavior: revokes apply to records with sequence numbers
///          ≤ the revoke's sequence. We track this per-transaction.)
///        * Commit: flush buffered (target, data) pairs into the
///          output map (skipping revoked blocks) and increment the
///          transaction counter.
///   4. Stop when a transaction's expected sequence doesn't match
///      the journal's `s_sequence`-monotonic walk.
pub fn replay_journal<F>(
    block_count: u32,
    mut journal_block: F,
) -> Result<ReplayReport, JournalError>
where
    F: FnMut(u32) -> Option<Vec<u8>>,
{
    let sb_bytes = journal_block(0).ok_or(JournalError::BadSuperblock)?;
    let sb = JournalSuperblock::parse(&sb_bytes).ok_or(JournalError::BadSuperblock)?;
    let mut report = ReplayReport::default();
    if sb.is_clean() {
        return Ok(report);
    }
    // Revoke table — FS-block → highest sequence at which the block
    // was revoked. Records with sequence ≤ that value are not
    // replayed; records strictly above ARE replayed. Linux
    // `recovery.c::jbd2_journal_test_revoke`.
    let mut revoke_at: BTreeMap<u64, u32> = BTreeMap::new();

    let first = sb.first.max(1);
    let maxlen = sb.maxlen.max(first + 1).min(block_count);
    let mut cursor = sb.start;
    let mut expected_seq = sb.sequence;

    // Bounded walk — at most `maxlen` iterations through the log
    // ring before we must have hit either a sequence mismatch or
    // exhausted the journal.
    let mut steps_remaining = maxlen as u64 * 2 + 16;

    'outer: loop {
        if steps_remaining == 0 {
            return Err(JournalError::UnterminatedTransaction);
        }
        steps_remaining -= 1;

        if cursor >= maxlen {
            cursor = first;
        }
        let buf = match journal_block(cursor) {
            Some(b) => b,
            None => break,
        };
        let header = match JournalHeader::parse(&buf) {
            Some(h) => h,
            None => break,
        };
        // A sequence mismatch — common-case termination per
        // recovery.c PASS_SCAN: "transaction we expected got
        // overwritten with garbage / a future-transaction's data".
        if header.sequence != expected_seq {
            break;
        }

        match header.block_type {
            block_type::DESCRIPTOR => {
                let desc = DescriptorBlock::parse(&buf).ok_or(JournalError::CorruptBlock)?;
                // Each tag consumes the next log block as its data.
                let mut pending: Vec<(u64, Vec<u8>, bool)> = Vec::new();
                for tag in &desc.tags {
                    cursor = if cursor + 1 >= maxlen { first } else { cursor + 1 };
                    if steps_remaining == 0 {
                        return Err(JournalError::UnterminatedTransaction);
                    }
                    steps_remaining -= 1;
                    let data = journal_block(cursor)
                        .ok_or(JournalError::UnterminatedTransaction)?;
                    pending.push((tag.target_block, data, tag.is_escaped()));
                }
                // Advance past the last data block; the next block
                // in the log should be a commit / revoke / next
                // descriptor for the same sequence.
                cursor = if cursor + 1 >= maxlen { first } else { cursor + 1 };

                // Buffer transactionally — only commit installs.
                // Walk forward from here looking for commit, applying
                // any revoke we see along the way.
                let mut commit_seen = false;
                let mut local_steps = maxlen as u64 + 8;
                let mut walk = cursor;
                while local_steps > 0 {
                    local_steps -= 1;
                    if walk >= maxlen {
                        walk = first;
                    }
                    let nxt = match journal_block(walk) {
                        Some(b) => b,
                        None => break,
                    };
                    let nh = match JournalHeader::parse(&nxt) {
                        Some(h) => h,
                        None => break,
                    };
                    if nh.sequence != expected_seq {
                        break;
                    }
                    match nh.block_type {
                        block_type::COMMIT => {
                            commit_seen = true;
                            walk = if walk + 1 >= maxlen { first } else { walk + 1 };
                            break;
                        }
                        block_type::REVOKE => {
                            let rev = RevokeBlock::parse(&nxt)
                                .ok_or(JournalError::CorruptBlock)?;
                            for b in &rev.revoked {
                                let entry = revoke_at.entry(*b).or_insert(0);
                                if expected_seq > *entry {
                                    *entry = expected_seq;
                                }
                            }
                            walk = if walk + 1 >= maxlen { first } else { walk + 1 };
                        }
                        block_type::DESCRIPTOR => {
                            // A second descriptor inside the same
                            // sequence — buffer its tags too.
                            let dd = DescriptorBlock::parse(&nxt)
                                .ok_or(JournalError::CorruptBlock)?;
                            for tag in &dd.tags {
                                walk = if walk + 1 >= maxlen { first } else { walk + 1 };
                                let data = journal_block(walk)
                                    .ok_or(JournalError::UnterminatedTransaction)?;
                                pending.push((tag.target_block, data, tag.is_escaped()));
                            }
                            walk = if walk + 1 >= maxlen { first } else { walk + 1 };
                        }
                        _ => {
                            walk = if walk + 1 >= maxlen { first } else { walk + 1 };
                        }
                    }
                }
                if !commit_seen {
                    // Incomplete transaction — Linux drops it
                    // silently (PASS_SCAN exits the loop).
                    break 'outer;
                }
                // Install pending into the output, honoring revokes
                // (revokes seen at this sequence apply to tags with
                // sequence ≤ revoke sequence — which is all our
                // pending tags since they all carry expected_seq).
                for (target, mut data, escape) in pending.drain(..) {
                    if let Some(&rev_seq) = revoke_at.get(&target) {
                        if rev_seq >= expected_seq {
                            continue;
                        }
                    }
                    if escape {
                        // The journaled copy had its first 4 bytes
                        // zeroed so the data block wouldn't be
                        // mistaken for a descriptor — restore the
                        // magic. Linux `recovery.c` calls the
                        // restored word JBD2_MAGIC_NUMBER.
                        if data.len() >= 4 {
                            data[0..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
                        }
                    }
                    report.blocks_to_write.insert(target, data);
                }
                report.transactions_replayed = report.transactions_replayed.saturating_add(1);
                cursor = walk;
                expected_seq = expected_seq.wrapping_add(1);
            }
            block_type::COMMIT => {
                // Standalone commit (e.g. an empty transaction) —
                // skip + advance.
                cursor = if cursor + 1 >= maxlen { first } else { cursor + 1 };
                expected_seq = expected_seq.wrapping_add(1);
            }
            block_type::REVOKE => {
                let rev = RevokeBlock::parse(&buf).ok_or(JournalError::CorruptBlock)?;
                for b in &rev.revoked {
                    let entry = revoke_at.entry(*b).or_insert(0);
                    if expected_seq > *entry {
                        *entry = expected_seq;
                    }
                }
                cursor = if cursor + 1 >= maxlen { first } else { cursor + 1 };
            }
            _ => break,
        }
    }
    Ok(report)
}

/// Convenience wrapper: pure in-memory replay over a flat journal
/// image (no wrap-around bookkeeping by the caller). Each block is
/// exactly `block_size` bytes; index `i` is at offset `i * block_size`.
///
/// Used by the smokes in `tests.rs`; also handy for any caller that
/// has already read the entire journal into a contiguous buffer.
pub fn replay_journal_flat(
    image: &[u8],
    block_size: usize,
) -> Result<ReplayReport, JournalError> {
    let count = (image.len() / block_size) as u32;
    replay_journal(count, |i| {
        let off = (i as usize).checked_mul(block_size)?;
        if off + block_size > image.len() {
            return None;
        }
        Some(image[off..off + block_size].to_vec())
    })
}
