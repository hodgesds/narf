//! JBD2, the ext3/ext4 journal: the on-disk format, superblock validation,
//! and recovery, as Linux does them.
//!
//! - `include/linux/jbd2.h`: the block layouts and feature bits.
//! - `fs/jbd2/journal.c`: `journal_check_superblock`,
//!   `journal_load_superblock`, `jbd2_journal_load`, `journal_reset`,
//!   `jbd2_journal_wipe`, `jbd2_mark_journal_empty`,
//!   `jbd2_journal_update_sb_log_tail`, `jbd2_journal_update_sb_errno`.
//! - `fs/jbd2/recovery.c`: `jbd2_journal_recover`, `do_one_pass` (the three
//!   passes SCAN, REVOKE, REPLAY), `jbd2_do_replay`, `count_tags`,
//!   `calc_chksums`, the checksum checks, `scan_revoke_records`.
//! - `fs/jbd2/revoke.c`: `jbd2_journal_set_revoke`,
//!   `jbd2_journal_test_revoke`.
//!
//! [`Journal`] is the `journal_t` subset recovery needs. The ext4 side
//! (`ext4_load_journal`, in `volume.rs`) decides when to wipe, load or
//! refuse; this module does the jbd2 part. All I/O goes through
//! [`JournalIo`], so the same code runs against a device at mount and
//! against memory in the tests.
//!
//! Everything on disk is big-endian. Block numbers inside the log are
//! journal-relative (the journal inode's logical blocks); tags name
//! filesystem blocks.
//!
//! Fast commits are not replayed yet. A dirty journal with the FAST_COMMIT
//! feature fails with [`JournalError::FastCommit`] before anything is
//! written (`fc_do_one_pass` and ext4's replay callback come later).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

use crate::metadata_csum::crc32c;

/// `JBD2_MAGIC_NUMBER`.
pub const JBD2_MAGIC_NUMBER: u32 = 0xC03B_3998;
/// `JBD2_MIN_JOURNAL_BLOCKS`.
pub const JBD2_MIN_JOURNAL_BLOCKS: u32 = 1024;
/// `JBD2_DEFAULT_FAST_COMMIT_BLOCKS`.
pub const JBD2_DEFAULT_FAST_COMMIT_BLOCKS: u32 = 256;
/// Size of `journal_superblock_t`.
pub const SUPERBLOCK_BYTES: usize = 1024;

/// `JBD2_*_BLOCK`.
pub mod block_type {
    pub const DESCRIPTOR: u32 = 1;
    pub const COMMIT: u32 = 2;
    pub const SUPERBLOCK_V1: u32 = 3;
    pub const SUPERBLOCK_V2: u32 = 4;
    pub const REVOKE: u32 = 5;
}

/// `JBD2_FLAG_*`: the 16-bit tag flags.
pub mod tag_flag {
    /// The block began with the magic number; the log copy's first four
    /// bytes are zero and replay puts the magic back.
    pub const ESCAPE: u16 = 1;
    /// No UUID follows this tag.
    pub const SAME_UUID: u16 = 2;
    /// Never written by Linux; ignored.
    pub const DELETED: u16 = 4;
    /// The last tag of the descriptor.
    pub const LAST_TAG: u16 = 8;
}

/// `JBD2_FEATURE_*`.
pub mod feature {
    pub const COMPAT_CHECKSUM: u32 = 0x1;
    pub const INCOMPAT_REVOKE: u32 = 0x1;
    pub const INCOMPAT_64BIT: u32 = 0x2;
    pub const INCOMPAT_ASYNC_COMMIT: u32 = 0x4;
    pub const INCOMPAT_CSUM_V2: u32 = 0x8;
    pub const INCOMPAT_CSUM_V3: u32 = 0x10;
    pub const INCOMPAT_FAST_COMMIT: u32 = 0x20;
    /// `JBD2_KNOWN_ROCOMPAT_FEATURES`.
    pub const KNOWN_ROCOMPAT: u32 = 0;
    /// `JBD2_KNOWN_INCOMPAT_FEATURES`.
    pub const KNOWN_INCOMPAT: u32 = INCOMPAT_REVOKE
        | INCOMPAT_64BIT
        | INCOMPAT_ASYNC_COMMIT
        | INCOMPAT_CSUM_V2
        | INCOMPAT_CSUM_V3
        | INCOMPAT_FAST_COMMIT;
}

/// `JBD2_CRC32_CHKSUM`.
pub const JBD2_CRC32_CHKSUM: u8 = 1;
/// `JBD2_CRC32C_CHKSUM`.
pub const JBD2_CRC32C_CHKSUM: u8 = 4;
/// `JBD2_CRC32_CHKSUM_SIZE`.
pub const JBD2_CRC32_CHKSUM_SIZE: u8 = 4;

/// `journal_header_t`.
const HEADER_BYTES: usize = 12;
/// `struct jbd2_journal_block_tail`.
const TAIL_BYTES: usize = 4;
/// `jbd2_journal_revoke_header_t`.
const REVOKE_HEADER_BYTES: usize = 16;
/// `struct commit_header` through `h_commit_nsec`.
const COMMIT_HEADER_BYTES: usize = 60;
/// Revoke records held during recovery before it fails with
/// [`JournalError::NoMemory`]. Linux allocates one record per revoked block
/// with no limit and fails with `-ENOMEM` when an allocation does.
const MAX_REVOKE_RECORDS: usize = 1 << 20;

/// Where Linux would fail, and with what.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    /// `-EINVAL`: a malformed journal superblock or revoke block.
    Invalid,
    /// `-EFSBADCRC` (`EBADMSG`): a checksum that does not match.
    BadChecksum,
    /// `-EFSCORRUPTED` (`EUCLEAN`): a corrupt transaction, or a journal
    /// block that does not map.
    Corrupted,
    /// `-EIO`: a read or write failed, or the passes disagreed.
    Io,
    /// `-ENOMEM`.
    NoMemory,
    /// The journal needs a fast-commit replay, which NARF does not do yet.
    FastCommit,
}

/// A boxed I/O future, so [`JournalIo`] stays object-safe and `Send`.
pub type IoFuture<'a> = Pin<Box<dyn Future<Output = Result<(), JournalError>> + Send + 'a>>;

/// The journal's view of the device.
pub trait JournalIo: Send {
    /// Read journal block `block` (journal-relative) into `buf`, one
    /// filesystem block. A block that does not map is
    /// [`JournalError::Corrupted`] (`ext4_journal_bmap`).
    fn read_log<'a>(&'a mut self, block: u32, buf: &'a mut [u8]) -> IoFuture<'a>;
    /// Write filesystem block `block` (replay).
    fn write_home<'a>(&'a mut self, block: u64, data: &'a [u8]) -> IoFuture<'a>;
    /// Write journal block `block` with FUA (the journal superblock).
    fn write_log_fua<'a>(&'a mut self, block: u32, data: &'a [u8]) -> IoFuture<'a>;
    /// `sync_blockdev` + `blkdev_issue_flush`.
    fn flush(&mut self) -> IoFuture<'_>;
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn be64(b: &[u8], off: usize) -> u64 {
    (be32(b, off) as u64) << 32 | be32(b, off + 4) as u64
}
fn put_be32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// `tid_gt`.
fn tid_gt(x: u32, y: u32) -> bool {
    (x.wrapping_sub(y) as i32) > 0
}
/// `tid_geq`.
fn tid_geq(x: u32, y: u32) -> bool {
    (x.wrapping_sub(y) as i32) >= 0
}

/// `crc32_be`: the big-endian CRC-32 (polynomial 0x04C11DB7) with no pre- or
/// post-inversion, as `lib/crc32.c` computes it. Only COMPAT_CHECKSUM (v1)
/// journals use it.
pub fn crc32_be(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04C1_1DB7
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// `journal_superblock_t`, kept as the bytes it was read as so a rewrite
/// preserves every field this code does not own.
#[derive(Clone)]
pub struct JournalSuperblock {
    raw: Vec<u8>,
}

impl core::fmt::Debug for JournalSuperblock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("JournalSuperblock")
            .field("blocktype", &self.blocktype())
            .field("maxlen", &self.maxlen())
            .field("first", &self.first())
            .field("sequence", &self.sequence())
            .field("start", &self.start())
            .field("incompat", &self.feature_incompat())
            .finish_non_exhaustive()
    }
}

impl JournalSuperblock {
    /// The first [`SUPERBLOCK_BYTES`] of `block`; `None` if shorter.
    pub fn from_bytes(block: &[u8]) -> Option<Self> {
        (block.len() >= SUPERBLOCK_BYTES).then(|| Self {
            raw: block[..SUPERBLOCK_BYTES].to_vec(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn magic(&self) -> u32 {
        be32(&self.raw, 0)
    }
    pub fn blocktype(&self) -> u32 {
        be32(&self.raw, 4)
    }
    pub fn blocksize(&self) -> u32 {
        be32(&self.raw, 0x0C)
    }
    pub fn maxlen(&self) -> u32 {
        be32(&self.raw, 0x10)
    }
    pub fn first(&self) -> u32 {
        be32(&self.raw, 0x14)
    }
    pub fn sequence(&self) -> u32 {
        be32(&self.raw, 0x18)
    }
    pub fn start(&self) -> u32 {
        be32(&self.raw, 0x1C)
    }
    pub fn errno(&self) -> i32 {
        be32(&self.raw, 0x20) as i32
    }
    pub fn feature_compat(&self) -> u32 {
        be32(&self.raw, 0x24)
    }
    pub fn feature_incompat(&self) -> u32 {
        be32(&self.raw, 0x28)
    }
    pub fn feature_ro_compat(&self) -> u32 {
        be32(&self.raw, 0x2C)
    }
    pub fn uuid(&self) -> &[u8] {
        &self.raw[0x30..0x40]
    }
    pub fn checksum_type(&self) -> u8 {
        self.raw[0x50]
    }
    /// `jbd2_journal_get_num_fc_blks`.
    pub fn num_fc_blocks(&self) -> u32 {
        match be32(&self.raw, 0x54) {
            0 => JBD2_DEFAULT_FAST_COMMIT_BLOCKS,
            n => n,
        }
    }
    pub fn head(&self) -> u32 {
        be32(&self.raw, 0x58)
    }
    pub fn checksum(&self) -> u32 {
        be32(&self.raw, 0xFC)
    }

    /// `jbd2_format_support_feature`: only a v2 superblock has features.
    fn v2(&self) -> bool {
        self.blocktype() == block_type::SUPERBLOCK_V2
    }
    fn incompat(&self, bit: u32) -> bool {
        self.v2() && self.feature_incompat() & bit != 0
    }
    pub fn has_checksum_v1(&self) -> bool {
        self.v2() && self.feature_compat() & feature::COMPAT_CHECKSUM != 0
    }
    pub fn has_csum2(&self) -> bool {
        self.incompat(feature::INCOMPAT_CSUM_V2)
    }
    pub fn has_csum3(&self) -> bool {
        self.incompat(feature::INCOMPAT_CSUM_V3)
    }
    /// `jbd2_journal_has_csum_v2or3`.
    pub fn has_csum_v2or3(&self) -> bool {
        self.has_csum2() || self.has_csum3()
    }
    pub fn has_64bit(&self) -> bool {
        self.incompat(feature::INCOMPAT_64BIT)
    }
    pub fn has_async_commit(&self) -> bool {
        self.incompat(feature::INCOMPAT_ASYNC_COMMIT)
    }
    pub fn has_fast_commit(&self) -> bool {
        self.incompat(feature::INCOMPAT_FAST_COMMIT)
    }

    /// `journal_tag_bytes`.
    pub fn tag_bytes(&self) -> usize {
        if self.has_csum3() {
            return 16;
        }
        let size = 12 + if self.has_csum2() { 2 } else { 0 };
        if self.has_64bit() {
            size
        } else {
            size - 4
        }
    }

    /// `jbd2_superblock_csum`: crc32c over the superblock with `s_checksum`
    /// zeroed, seeded with ~0.
    pub fn compute_checksum(&self) -> u32 {
        let mut copy = self.raw.clone();
        copy[0xFC..0x100].fill(0);
        crc32c(!0, &copy)
    }

    fn set(&mut self, off: usize, value: u32) {
        put_be32(&mut self.raw, off, value);
    }
}

/// The journal: `journal_t`'s recovery-time state.
pub struct Journal {
    sb: JournalSuperblock,
    /// The whole first journal block, written back around the superblock.
    sb_block: Vec<u8>,
    block_size: usize,
    /// `j_total_len`.
    pub total_len: u32,
    /// `j_first`; the log is `[first, last)`.
    pub first: u32,
    /// `j_last`.
    pub last: u32,
    /// `j_tail`.
    pub tail: u32,
    /// `j_tail_sequence`.
    pub tail_sequence: u32,
    /// `j_transaction_sequence`: the next transaction id.
    pub transaction_sequence: u32,
    /// `j_head`.
    pub head: u32,
    /// `j_errno`, from `s_errno`.
    pub errno: i32,
    /// `j_failed_commit`.
    pub failed_commit: u32,
    /// `JBD2_FLUSHED`: the on-disk superblock says the log is empty.
    pub flushed: bool,
    csum_seed: u32,
    revoke: BTreeMap<u64, u32>,
}

impl core::fmt::Debug for Journal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Journal")
            .field("sb", &self.sb)
            .field("first", &self.first)
            .field("last", &self.last)
            .field("tail", &self.tail)
            .field("tail_sequence", &self.tail_sequence)
            .field("transaction_sequence", &self.transaction_sequence)
            .field("head", &self.head)
            .field("errno", &self.errno)
            .field("failed_commit", &self.failed_commit)
            .finish_non_exhaustive()
    }
}

/// What a recovery found and did (`struct recovery_info`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryInfo {
    pub start_transaction: u32,
    pub end_transaction: u32,
    pub head_block: u32,
    pub nr_replays: u32,
    pub nr_revokes: u32,
    pub nr_revoke_hits: u32,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Pass {
    Scan,
    Revoke,
    Replay,
}

impl Journal {
    /// `journal_load_superblock`. `first_block` is journal block 0,
    /// `block_size` the filesystem block size (`j_blocksize`) and
    /// `total_len` the journal inode's size in blocks (`j_total_len`).
    /// The superblock is checked as `journal_check_superblock` does.
    pub fn load_superblock(
        first_block: &[u8],
        block_size: usize,
        total_len: u32,
    ) -> Result<Self, JournalError> {
        let sb = JournalSuperblock::from_bytes(first_block).ok_or(JournalError::Io)?;
        check_superblock(&sb, block_size, total_len)?;
        let csum_seed = if sb.has_csum_v2or3() {
            crc32c(!0, sb.uuid())
        } else {
            0
        };
        let mut journal = Self {
            tail_sequence: sb.sequence(),
            tail: sb.start(),
            first: sb.first(),
            errno: sb.errno(),
            last: sb.maxlen(),
            total_len: total_len.min(sb.maxlen()),
            transaction_sequence: 0,
            head: 0,
            failed_commit: 0,
            flushed: false,
            csum_seed,
            revoke: BTreeMap::new(),
            block_size,
            sb_block: first_block.to_vec(),
            sb,
        };
        if journal.sb.has_fast_commit() {
            journal.last = journal.sb.maxlen() - journal.sb.num_fc_blocks();
        }
        Ok(journal)
    }

    pub fn superblock(&self) -> &JournalSuperblock {
        &self.sb
    }

    /// `wrap`.
    fn wrap(&self, block: u32) -> u32 {
        if block >= self.last {
            block - (self.last - self.first)
        } else {
            block
        }
    }

    /// `jbd2_journal_recover`. Replays every complete, un-revoked
    /// transaction through `io.write_home`, then flushes. On success
    /// `transaction_sequence` and `head` say where the log restarts.
    pub async fn recover(&mut self, io: &mut dyn JournalIo) -> Result<RecoveryInfo, JournalError> {
        let mut info = RecoveryInfo::default();
        if self.tail == 0 {
            self.transaction_sequence = self.sb.sequence().wrapping_add(1);
            self.head = self.sb.head();
            return Ok(info);
        }
        if self.sb.has_fast_commit() {
            return Err(JournalError::FastCommit);
        }
        let mut err = self.do_one_pass(io, &mut info, Pass::Scan).await;
        if err.is_ok() {
            err = self.do_one_pass(io, &mut info, Pass::Revoke).await;
        }
        if err.is_ok() {
            err = self.do_one_pass(io, &mut info, Pass::Replay).await;
        }
        // Restart the log at the next transaction id, invalidating every
        // commit record still in it.
        info.end_transaction = info.end_transaction.wrapping_add(1);
        self.transaction_sequence = info.end_transaction;
        self.head = info.head_block;
        self.revoke.clear();
        let flushed = io.flush().await;
        err?;
        flushed?;
        Ok(info)
    }

    /// `jbd2_journal_skip_recovery`: one SCAN pass to find the next unused
    /// transaction id, then forget the log.
    async fn skip_recovery(&mut self, io: &mut dyn JournalIo) -> Result<(), JournalError> {
        let mut info = RecoveryInfo::default();
        let err = self.do_one_pass(io, &mut info, Pass::Scan).await;
        match err {
            Err(_) => {
                self.transaction_sequence = self.transaction_sequence.wrapping_add(1);
                self.head = self.first;
            }
            Ok(()) => {
                self.transaction_sequence = info.end_transaction.wrapping_add(1);
                self.head = info.head_block;
            }
        }
        self.tail = 0;
        err
    }

    /// `jbd2_journal_wipe`: ignore the log's contents; with `write`, mark it
    /// empty on disk too.
    pub async fn wipe(&mut self, io: &mut dyn JournalIo, write: bool) -> Result<(), JournalError> {
        if self.tail == 0 {
            return Ok(());
        }
        let err = self.skip_recovery(io).await;
        if write {
            self.mark_empty(io).await;
        }
        err
    }

    /// `jbd2_journal_load`: recover, refuse a corrupt transaction, and
    /// reset the log. `writable` is false on a read-only device, where
    /// `journal_reset`'s log-tail update cannot be written.
    pub async fn load(
        &mut self,
        io: &mut dyn JournalIo,
        writable: bool,
    ) -> Result<RecoveryInfo, JournalError> {
        let info = self.recover(io).await?;
        if self.failed_commit != 0 {
            return Err(JournalError::Corrupted);
        }
        self.reset(io, writable).await?;
        Ok(info)
    }

    /// `journal_reset`, with ext4's `JBD2_CYCLE_RECORD`.
    async fn reset(&mut self, io: &mut dyn JournalIo, writable: bool) -> Result<(), JournalError> {
        let first = self.sb.first();
        let last = self.sb.maxlen();
        if u64::from(first) + u64::from(JBD2_MIN_JOURNAL_BLOCKS) > u64::from(last) + 1 {
            return Err(JournalError::Invalid);
        }
        self.first = first;
        self.last = last;
        if self.head != 0 {
            if self.head < first || self.head >= last {
                self.head = first;
            }
        } else {
            self.head = first;
        }
        self.tail = self.head;
        self.tail_sequence = self.transaction_sequence;
        // Recovery is done: fast commits stay off until the filesystem asks
        // for them again.
        let incompat = self.sb.feature_incompat() & !feature::INCOMPAT_FAST_COMMIT;
        self.sb.set(0x28, incompat);
        if self.sb.start() == 0 {
            self.flushed = true;
        } else if writable {
            // Linux ignores a failure here (the journal is aborted instead).
            let _ = self
                .update_sb_log_tail(io, self.tail_sequence, self.tail)
                .await;
        }
        Ok(())
    }

    /// `jbd2_journal_update_sb_log_tail` with `REQ_FUA`.
    pub async fn update_sb_log_tail(
        &mut self,
        io: &mut dyn JournalIo,
        tail_tid: u32,
        tail_block: u32,
    ) -> Result<(), JournalError> {
        self.sb.set(0x18, tail_tid);
        self.sb.set(0x1C, tail_block);
        self.write_superblock(io).await?;
        self.flushed = false;
        Ok(())
    }

    /// `jbd2_mark_journal_empty` with `REQ_FUA`. A write error is not
    /// returned, as in Linux (which aborts the journal on one).
    pub async fn mark_empty(&mut self, io: &mut dyn JournalIo) {
        if self.sb.start() == 0 {
            return;
        }
        self.sb.set(0x18, self.tail_sequence);
        self.sb.set(0x1C, 0);
        self.sb.set(0x58, self.head);
        let incompat = self.sb.feature_incompat();
        let had_fast_commit = incompat & feature::INCOMPAT_FAST_COMMIT != 0;
        self.sb.set(0x28, incompat & !feature::INCOMPAT_FAST_COMMIT);
        let _ = self.write_superblock(io).await;
        if had_fast_commit {
            self.sb.set(0x28, incompat);
        }
        self.flushed = true;
    }

    /// `jbd2_journal_clear_err`, then `jbd2_journal_update_sb_errno`, whose
    /// write errors are not returned.
    pub async fn clear_err(&mut self, io: &mut dyn JournalIo) {
        self.errno = 0;
        self.sb.set(0x20, 0);
        let _ = self.write_superblock(io).await;
    }

    /// `jbd2_write_superblock`: the checksum, then the whole first block,
    /// with FUA.
    async fn write_superblock(&mut self, io: &mut dyn JournalIo) -> Result<(), JournalError> {
        if self.sb.has_csum_v2or3() {
            let csum = self.sb.compute_checksum();
            self.sb.set(0xFC, csum);
        }
        self.sb_block[..SUPERBLOCK_BYTES].copy_from_slice(&self.sb.raw);
        let block = self.sb_block.clone();
        io.write_log_fua(0, &block).await
    }

    /// `jbd2_descriptor_block_csum_verify`, also used for revoke blocks.
    fn descriptor_csum_ok(&self, block: &[u8]) -> bool {
        if !self.sb.has_csum_v2or3() {
            return true;
        }
        let tail = self.block_size - TAIL_BYTES;
        let provided = be32(block, tail);
        let mut copy = block.to_vec();
        copy[tail..].fill(0);
        crc32c(self.csum_seed, &copy) == provided
    }

    /// `jbd2_commit_block_csum_verify`.
    fn commit_csum_ok(&self, block: &[u8]) -> bool {
        if !self.sb.has_csum_v2or3() {
            return true;
        }
        let provided = be32(block, 16);
        let mut copy = block.to_vec();
        copy[16..20].fill(0);
        crc32c(self.csum_seed, &copy) == provided
    }

    /// `jbd2_commit_block_csum_verify_partial`: the commit header made it to
    /// disk and the rest of the block did not.
    fn commit_csum_partial_ok(&self, block: &[u8]) -> bool {
        let provided = be32(block, 16);
        let mut copy = vec![0u8; self.block_size];
        copy[..COMMIT_HEADER_BYTES].copy_from_slice(&block[..COMMIT_HEADER_BYTES]);
        copy[16..20].fill(0);
        crc32c(self.csum_seed, &copy) == provided
    }

    /// `jbd2_block_tag_csum_verify`.
    fn tag_csum_ok(&self, tag: &[u8], data: &[u8], sequence: u32) -> bool {
        if !self.sb.has_csum_v2or3() {
            return true;
        }
        let csum = crc32c(crc32c(self.csum_seed, &sequence.to_be_bytes()), data);
        if self.sb.has_csum3() {
            be32(tag, 12) == csum
        } else {
            be16(tag, 4) == csum as u16
        }
    }

    /// `read_tag_block`.
    fn tag_block(&self, tag: &[u8]) -> u64 {
        let low = be32(tag, 0) as u64;
        if self.sb.has_64bit() {
            low | (be32(tag, 8) as u64) << 32
        } else {
            low
        }
    }

    /// The tags of a descriptor block, in order, as offsets into it:
    /// `count_tags` and `jbd2_do_replay` walk them the same way.
    fn tags(&self, block: &[u8]) -> Vec<usize> {
        let tag_bytes = self.sb.tag_bytes();
        let size = if self.sb.has_csum_v2or3() {
            self.block_size - TAIL_BYTES
        } else {
            self.block_size
        };
        let mut offsets = Vec::new();
        let mut at = HEADER_BYTES;
        while at + tag_bytes <= size {
            offsets.push(at);
            let flags = be16(block, at + 6);
            at += tag_bytes;
            if flags & tag_flag::SAME_UUID == 0 {
                at += 16;
            }
            if flags & tag_flag::LAST_TAG != 0 {
                break;
            }
        }
        offsets
    }

    /// `jbd2_journal_set_revoke`: keep the latest transaction that revoked
    /// the block.
    fn set_revoke(&mut self, block: u64, sequence: u32) -> Result<(), JournalError> {
        if let Some(seen) = self.revoke.get_mut(&block) {
            if tid_gt(sequence, *seen) {
                *seen = sequence;
            }
            return Ok(());
        }
        if self.revoke.len() >= MAX_REVOKE_RECORDS {
            return Err(JournalError::NoMemory);
        }
        self.revoke.insert(block, sequence);
        Ok(())
    }

    /// `jbd2_journal_test_revoke`: revoked by this transaction or a later
    /// one.
    fn test_revoke(&self, block: u64, sequence: u32) -> bool {
        match self.revoke.get(&block) {
            Some(&seen) => !tid_gt(sequence, seen),
            None => false,
        }
    }

    /// `scan_revoke_records`.
    fn scan_revoke_records(
        &mut self,
        pass: Pass,
        block: &[u8],
        sequence: u32,
        info: &mut RecoveryInfo,
    ) -> Result<(), JournalError> {
        let rcount = be32(block, HEADER_BYTES) as usize;
        let csum_size = if self.sb.has_csum_v2or3() {
            TAIL_BYTES
        } else {
            0
        };
        if rcount > self.block_size - csum_size {
            return Err(JournalError::Invalid);
        }
        let record_len = if self.sb.has_64bit() { 8 } else { 4 };
        if pass == Pass::Scan {
            let records = rcount.saturating_sub(REVOKE_HEADER_BYTES) / record_len;
            info.nr_revokes = info.nr_revokes.wrapping_add(records as u32);
            return Ok(());
        }
        let mut offset = REVOKE_HEADER_BYTES;
        while offset + record_len <= rcount {
            let target = if record_len == 4 {
                be32(block, offset) as u64
            } else {
                be64(block, offset)
            };
            offset += record_len;
            self.set_revoke(target, sequence)?;
        }
        Ok(())
    }

    /// `calc_chksums`: fold a descriptor and the blocks it describes into
    /// the v1 transaction checksum. False on a read error, which ends the
    /// scan.
    async fn calc_chksums(
        &self,
        io: &mut dyn JournalIo,
        descriptor: &[u8],
        next_log_block: &mut u32,
        crc32_sum: &mut u32,
    ) -> bool {
        let count = self.tags(descriptor).len();
        *crc32_sum = crc32_be(*crc32_sum, descriptor);
        let mut buf = vec![0u8; self.block_size];
        for _ in 0..count {
            let io_block = *next_log_block;
            *next_log_block = self.wrap(*next_log_block + 1);
            if io.read_log(io_block, &mut buf).await.is_err() {
                return false;
            }
            *crc32_sum = crc32_be(*crc32_sum, &buf);
        }
        true
    }

    /// `jbd2_do_replay`: write every un-revoked block of one descriptor home.
    /// Returns the last error a block hit, having replayed the others.
    async fn do_replay(
        &mut self,
        io: &mut dyn JournalIo,
        info: &mut RecoveryInfo,
        descriptor: &[u8],
        next_log_block: &mut u32,
        next_commit_id: u32,
    ) -> Result<(), JournalError> {
        let mut ret = Ok(());
        let tag_bytes = self.sb.tag_bytes();
        let mut data = vec![0u8; self.block_size];
        for tag_at in self.tags(descriptor) {
            let tag = &descriptor[tag_at..tag_at + tag_bytes];
            let flags = be16(tag, 6);
            let io_block = *next_log_block;
            *next_log_block = self.wrap(*next_log_block + 1);
            if let Err(e) = io.read_log(io_block, &mut data).await {
                // Recover what we can, report the failure at the end.
                ret = Err(e);
                continue;
            }
            let block = self.tag_block(tag);
            if self.test_revoke(block, next_commit_id) {
                info.nr_revoke_hits = info.nr_revoke_hits.wrapping_add(1);
                continue;
            }
            if !self.tag_csum_ok(tag, &data, next_commit_id) {
                ret = Err(JournalError::BadChecksum);
                continue;
            }
            if flags & tag_flag::ESCAPE != 0 {
                put_be32(&mut data, 0, JBD2_MAGIC_NUMBER);
            }
            io.write_home(block, &data).await?;
            info.nr_replays = info.nr_replays.wrapping_add(1);
        }
        ret
    }

    /// `do_one_pass`.
    ///
    /// Linux bounds the walk only by the log's contents. This also ends a
    /// pass with [`JournalError::Corrupted`] once it has read more block
    /// headers than one lap of the log holds, so a log that never ends (one
    /// sequence's descriptors all the way round, no commit) cannot spin.
    async fn do_one_pass(
        &mut self,
        io: &mut dyn JournalIo,
        info: &mut RecoveryInfo,
        pass: Pass,
    ) -> Result<(), JournalError> {
        let mut next_commit_id = self.sb.sequence();
        let mut next_log_block = self.sb.start();
        let mut head_block = next_log_block;
        let mut success: Result<(), JournalError> = Ok(());
        let mut crc32_sum: u32 = !0;
        let mut need_check_commit_time = false;
        let mut last_trans_commit_time: u64 = 0;
        if pass == Pass::Scan {
            info.start_transaction = next_commit_id;
        }
        let lap = u64::from(self.last.saturating_sub(self.first));
        let mut walked: u64 = 0;
        let mut block = vec![0u8; self.block_size];

        loop {
            if pass != Pass::Scan && tid_geq(next_commit_id, info.end_transaction) {
                break;
            }
            walked += 1;
            if walked > lap + 1 {
                return Err(JournalError::Corrupted);
            }
            io.read_log(next_log_block, &mut block).await?;
            next_log_block = self.wrap(next_log_block + 1);

            if be32(&block, 0) != JBD2_MAGIC_NUMBER {
                break;
            }
            let blocktype = be32(&block, 4);
            let sequence = be32(&block, 8);
            if sequence != next_commit_id {
                break;
            }

            match blocktype {
                block_type::DESCRIPTOR => {
                    if !self.descriptor_csum_ok(&block) {
                        // SCAN can see stale blocks left by lazy journal
                        // init; the commit time decides later.
                        if pass != Pass::Scan {
                            return Err(JournalError::BadChecksum);
                        }
                        need_check_commit_time = true;
                    }
                    if pass != Pass::Replay {
                        if pass == Pass::Scan
                            && self.sb.has_checksum_v1()
                            && info.end_transaction == 0
                        {
                            let descriptor = block.clone();
                            if !self
                                .calc_chksums(io, &descriptor, &mut next_log_block, &mut crc32_sum)
                                .await
                            {
                                break;
                            }
                            continue;
                        }
                        let count = self.tags(&block).len() as u32;
                        next_log_block = self.wrap(next_log_block + count);
                        continue;
                    }
                    let descriptor = block.clone();
                    if let Err(e) = self
                        .do_replay(io, info, &descriptor, &mut next_log_block, next_commit_id)
                        .await
                    {
                        if e == JournalError::NoMemory {
                            return Err(e);
                        }
                        success = Err(e);
                    }
                    continue;
                }
                block_type::COMMIT => {
                    if pass != Pass::Scan {
                        next_commit_id = next_commit_id.wrapping_add(1);
                        continue;
                    }
                    let commit_time = be64(&block, 48);
                    if need_check_commit_time {
                        if commit_time >= last_trans_commit_time {
                            return Err(JournalError::BadChecksum);
                        }
                        // Likely a stale block of an older journal: end here.
                        break;
                    }
                    let ok = if self.sb.has_checksum_v1() {
                        let found = be32(&block, 16);
                        if info.end_transaction != 0 {
                            self.failed_commit = info.end_transaction;
                            break;
                        }
                        let kind = block[12];
                        let size = block[13];
                        let good = (crc32_sum == found
                            && kind == JBD2_CRC32_CHKSUM
                            && size == JBD2_CRC32_CHKSUM_SIZE)
                            || (kind == 0 && size == 0 && found == 0);
                        if good {
                            crc32_sum = !0;
                        }
                        good
                    } else {
                        self.commit_csum_ok(&block) || self.commit_csum_partial_ok(&block)
                    };
                    if !ok {
                        if commit_time < last_trans_commit_time {
                            break;
                        }
                        info.end_transaction = next_commit_id;
                        info.head_block = head_block;
                        if !self.sb.has_async_commit() {
                            self.failed_commit = next_commit_id;
                            break;
                        }
                    }
                    last_trans_commit_time = commit_time;
                    head_block = next_log_block;
                    next_commit_id = next_commit_id.wrapping_add(1);
                    continue;
                }
                block_type::REVOKE => {
                    if pass != Pass::Revoke && pass != Pass::Scan {
                        continue;
                    }
                    if pass == Pass::Scan && !self.descriptor_csum_ok(&block) {
                        need_check_commit_time = true;
                    }
                    let revoke = block.clone();
                    self.scan_revoke_records(pass, &revoke, next_commit_id, info)?;
                    continue;
                }
                _ => break,
            }
        }

        if pass == Pass::Scan {
            if info.end_transaction == 0 {
                info.end_transaction = next_commit_id;
            }
            if info.head_block == 0 {
                info.head_block = head_block;
            }
        } else if info.end_transaction != next_commit_id && success.is_ok() {
            // The passes ended in different places (an I/O error).
            success = Err(JournalError::Io);
        }
        success
    }
}

impl Journal {
    /// The journal features ext4 writes with (`ext4_set_journal_csum_feature_set`
    /// with ext4's default `journal_checksum` under `metadata_csum`, and the
    /// 64-bit tag format on a 64-bit filesystem), applied as
    /// `jbd2_journal_set_features` and `jbd2_journal_clear_features` do: v3
    /// checksums with crc32c and the seed from the journal UUID, or no
    /// checksums at all; `async_commit` off. A v1 superblock carries no
    /// features (EINVAL, as `jbd2_journal_check_available_features` refuses).
    pub fn set_write_features(
        &mut self,
        metadata_csum: bool,
        wide: bool,
    ) -> Result<(), JournalError> {
        let mut compat = self.sb.feature_compat() & !feature::COMPAT_CHECKSUM;
        let mut incompat = self.sb.feature_incompat()
            & !(feature::INCOMPAT_CSUM_V2
                | feature::INCOMPAT_CSUM_V3
                | feature::INCOMPAT_ASYNC_COMMIT);
        if metadata_csum {
            incompat |= feature::INCOMPAT_CSUM_V3;
        }
        if wide {
            incompat |= feature::INCOMPAT_64BIT;
        }
        let needs_features = incompat != 0 || compat != 0;
        if !self.sb.v2() {
            if needs_features {
                return Err(JournalError::Invalid);
            }
            return Ok(());
        }
        if incompat & feature::INCOMPAT_CSUM_V3 != 0 {
            self.sb.raw[0x50] = JBD2_CRC32C_CHKSUM;
            self.csum_seed = crc32c(!0, self.sb.uuid());
            compat &= !feature::COMPAT_CHECKSUM;
        }
        self.sb.set(0x24, compat);
        self.sb.set(0x28, incompat);
        Ok(())
    }
}

/// One journal block a commit writes: where in the log, and its bytes.
#[derive(Debug)]
pub struct LogWrite {
    pub block: u32,
    pub data: Vec<u8>,
}

/// A transaction's log blocks, in the order they are written, and where the
/// log continues after it.
#[derive(Debug)]
pub struct EncodedTransaction {
    /// Revoke, descriptor and data blocks: written first, plain.
    pub body: Vec<LogWrite>,
    /// The commit block: written after a flush, with FUA.
    pub commit: LogWrite,
    /// The block after the commit (`j_head` once it is written).
    pub next_head: u32,
}

impl Journal {
    /// Log blocks free from `head` to the tail, the way `jbd2_log_space_left`
    /// counts them; with every commit checkpointed at once the whole log is
    /// free between transactions.
    pub fn log_len(&self) -> u32 {
        self.last - self.first
    }

    /// The blocks one transaction of `blocks` filesystem blocks and
    /// `revokes` revoked blocks needs in the log: descriptors (each holding
    /// as many tags as fit, `commit.c` line ~695), the data copies, revoke
    /// blocks, and the commit block.
    pub fn transaction_blocks(&self, blocks: usize, revokes: usize) -> usize {
        let per_descriptor = self.tags_per_descriptor().max(1);
        let per_revoke = self.revokes_per_block().max(1);
        blocks.div_ceil(per_descriptor) + blocks + revokes.div_ceil(per_revoke) + 1
    }

    fn csum_size(&self) -> usize {
        if self.sb.has_csum_v2or3() {
            TAIL_BYTES
        } else {
            0
        }
    }

    /// Tags a descriptor holds: the first carries a 16-byte UUID after it,
    /// the rest share it (`SAME_UUID`); the block keeps room for the tail.
    fn tags_per_descriptor(&self) -> usize {
        let space = self.block_size - HEADER_BYTES - self.csum_size();
        let tag = self.sb.tag_bytes();
        if space < tag + 16 {
            return 0;
        }
        1 + (space - tag - 16) / tag
    }

    /// `journal_revoke_records_per_block`.
    fn revokes_per_block(&self) -> usize {
        let record = if self.sb.has_64bit() { 8 } else { 4 };
        (self.block_size - REVOKE_HEADER_BYTES - self.csum_size()) / record
    }

    /// Lay out transaction `tid` from `head`: revoke blocks, then for each
    /// run of tags a descriptor followed by its data copies (escaped when a
    /// block begins with the magic, `jbd2_journal_write_metadata_buffer`),
    /// then the commit block stamped `commit_sec`/`commit_nsec`. Checksums
    /// as the superblock's features say: v3/v2 tag, descriptor-tail and
    /// commit checksums; v1 a running crc32_be over descriptors and data.
    pub fn encode_transaction(
        &self,
        tid: u32,
        head: u32,
        blocks: &[(u64, &[u8])],
        revokes: &[u64],
        commit_sec: u64,
        commit_nsec: u32,
    ) -> EncodedTransaction {
        let bs = self.block_size;
        let mut at = head;
        let mut body = Vec::new();
        let mut crc32_sum: u32 = !0;
        let take = |at: &mut u32| {
            let block = *at;
            *at = self.wrap(*at + 1);
            block
        };

        // Revoke blocks (`jbd2_journal_write_revoke_records`).
        let record = if self.sb.has_64bit() { 8 } else { 4 };
        for chunk in revokes.chunks(self.revokes_per_block().max(1)) {
            let mut r = vec![0u8; bs];
            put_be32(&mut r, 0, JBD2_MAGIC_NUMBER);
            put_be32(&mut r, 4, block_type::REVOKE);
            put_be32(&mut r, 8, tid);
            let mut off = REVOKE_HEADER_BYTES;
            for &target in chunk {
                if record == 8 {
                    r[off..off + 8].copy_from_slice(&target.to_be_bytes());
                } else {
                    put_be32(&mut r, off, target as u32);
                }
                off += record;
            }
            put_be32(&mut r, HEADER_BYTES, off as u32);
            self.seal_tail(&mut r);
            body.push(LogWrite {
                block: take(&mut at),
                data: r,
            });
        }

        // Descriptors and data.
        let tag_bytes = self.sb.tag_bytes();
        for run in blocks.chunks(self.tags_per_descriptor().max(1)) {
            let mut d = vec![0u8; bs];
            put_be32(&mut d, 0, JBD2_MAGIC_NUMBER);
            put_be32(&mut d, 4, block_type::DESCRIPTOR);
            put_be32(&mut d, 8, tid);
            let descriptor_at = take(&mut at);
            let mut data_writes = Vec::with_capacity(run.len());
            let mut off = HEADER_BYTES;
            for (i, &(target, content)) in run.iter().enumerate() {
                let mut logged = content.to_vec();
                let mut flags = 0u16;
                if be32(&logged, 0) == JBD2_MAGIC_NUMBER {
                    flags |= tag_flag::ESCAPE;
                    logged[..4].fill(0);
                }
                if i > 0 {
                    flags |= tag_flag::SAME_UUID;
                }
                if i + 1 == run.len() {
                    flags |= tag_flag::LAST_TAG;
                }
                put_be32(&mut d, off, target as u32);
                d[off + 6..off + 8].copy_from_slice(&flags.to_be_bytes());
                if self.sb.has_64bit() {
                    put_be32(&mut d, off + 8, (target >> 32) as u32);
                }
                if self.sb.has_csum_v2or3() {
                    let csum = crc32c(crc32c(self.csum_seed, &tid.to_be_bytes()), &logged);
                    if self.sb.has_csum3() {
                        put_be32(&mut d, off + 12, csum);
                    } else {
                        d[off + 4..off + 6].copy_from_slice(&(csum as u16).to_be_bytes());
                    }
                }
                off += tag_bytes;
                if i == 0 {
                    // `j_uuid`, which Linux never sets: sixteen zero bytes.
                    off += 16;
                }
                data_writes.push(LogWrite {
                    block: take(&mut at),
                    data: logged,
                });
            }
            self.seal_tail(&mut d);
            if self.sb.has_checksum_v1() {
                crc32_sum = crc32_be(crc32_sum, &d);
                for w in &data_writes {
                    crc32_sum = crc32_be(crc32_sum, &w.data);
                }
            }
            body.push(LogWrite {
                block: descriptor_at,
                data: d,
            });
            body.extend(data_writes);
        }

        // The commit block (`journal_submit_commit_record`).
        let mut c = vec![0u8; bs];
        put_be32(&mut c, 0, JBD2_MAGIC_NUMBER);
        put_be32(&mut c, 4, block_type::COMMIT);
        put_be32(&mut c, 8, tid);
        c[48..56].copy_from_slice(&commit_sec.to_be_bytes());
        put_be32(&mut c, 56, commit_nsec);
        if self.sb.has_checksum_v1() {
            c[12] = JBD2_CRC32_CHKSUM;
            c[13] = JBD2_CRC32_CHKSUM_SIZE;
            put_be32(&mut c, 16, crc32_sum);
        } else if self.sb.has_csum_v2or3() {
            let csum = crc32c(self.csum_seed, &c);
            put_be32(&mut c, 16, csum);
        }
        let commit = LogWrite {
            block: take(&mut at),
            data: c,
        };
        EncodedTransaction {
            body,
            commit,
            next_head: at,
        }
    }

    /// `jbd2_descriptor_block_csum_set`.
    fn seal_tail(&self, block: &mut [u8]) {
        if self.sb.has_csum_v2or3() {
            let tail = self.block_size - TAIL_BYTES;
            block[tail..].fill(0);
            let csum = crc32c(self.csum_seed, block);
            put_be32(block, tail, csum);
        }
    }
}

/// `journal_check_superblock`, in its order.
fn check_superblock(
    sb: &JournalSuperblock,
    block_size: usize,
    total_len: u32,
) -> Result<(), JournalError> {
    if sb.magic() != JBD2_MAGIC_NUMBER || sb.blocksize() as usize != block_size {
        return Err(JournalError::Invalid);
    }
    if sb.blocktype() != block_type::SUPERBLOCK_V1 && sb.blocktype() != block_type::SUPERBLOCK_V2 {
        return Err(JournalError::Invalid);
    }
    if sb.maxlen() > total_len {
        return Err(JournalError::Invalid);
    }
    if sb.first() == 0 || sb.first() >= total_len {
        return Err(JournalError::Invalid);
    }
    if !sb.v2() {
        return Ok(());
    }
    if sb.feature_ro_compat() & !feature::KNOWN_ROCOMPAT != 0
        || sb.feature_incompat() & !feature::KNOWN_INCOMPAT != 0
    {
        return Err(JournalError::Invalid);
    }
    let num_fc = if sb.has_fast_commit() {
        sb.num_fc_blocks()
    } else {
        0
    };
    if sb.maxlen() < JBD2_MIN_JOURNAL_BLOCKS || sb.maxlen() - JBD2_MIN_JOURNAL_BLOCKS < num_fc {
        return Err(JournalError::Invalid);
    }
    if sb.has_csum2() && sb.has_csum3() {
        return Err(JournalError::Invalid);
    }
    if sb.has_csum_v2or3() && sb.has_checksum_v1() {
        return Err(JournalError::Invalid);
    }
    if sb.has_csum_v2or3() {
        if sb.checksum_type() != JBD2_CRC32C_CHKSUM {
            return Err(JournalError::Invalid);
        }
        if sb.checksum() != sb.compute_checksum() {
            return Err(JournalError::BadChecksum);
        }
    }
    Ok(())
}
