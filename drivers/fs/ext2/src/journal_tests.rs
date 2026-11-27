//! Kernel tests for the JBD2 recovery in `journal.rs` and for the journal
//! load at mount (`Ext2Volume::load_journal_at_mount`), each against the
//! Linux behaviour it reproduces (`fs/jbd2/recovery.c`, `fs/jbd2/journal.c`,
//! `fs/ext4/super.c`).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::journal::{
    block_type, feature, tag_flag, IoFuture, Journal, JournalError, JournalIo, JBD2_MAGIC_NUMBER,
};
use crate::metadata_csum::crc32c;

fn run<F: core::future::Future>(fut: F) -> F::Output {
    let mut fut = core::pin::pin!(fut);
    let waker = core::task::Waker::noop();
    let mut cx = core::task::Context::from_waker(waker);
    loop {
        if let core::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

const UUID: [u8; 16] = [
    0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f,
];

/// A journal image built the way Linux's commit code lays one out
/// (`fs/jbd2/commit.c`).
struct Log {
    bs: usize,
    blocks: Vec<Vec<u8>>,
    compat: u32,
    incompat: u32,
}

impl Log {
    fn new(bs: usize, maxlen: u32, compat: u32, incompat: u32) -> Self {
        Self {
            bs,
            blocks: vec![vec![0u8; bs]; maxlen as usize],
            compat,
            incompat,
        }
    }
    fn csum3(&self) -> bool {
        self.incompat & feature::INCOMPAT_CSUM_V3 != 0
    }
    fn csum2(&self) -> bool {
        self.incompat & feature::INCOMPAT_CSUM_V2 != 0
    }
    fn csum(&self) -> bool {
        self.csum2() || self.csum3()
    }
    fn wide(&self) -> bool {
        self.incompat & feature::INCOMPAT_64BIT != 0
    }
    fn seed(&self) -> u32 {
        crc32c(!0, &UUID)
    }
    fn tag_bytes(&self) -> usize {
        if self.csum3() {
            16
        } else {
            let s = 12 + if self.csum2() { 2 } else { 0 };
            if self.wide() {
                s
            } else {
                s - 4
            }
        }
    }
    fn maxlen(&self) -> u32 {
        self.blocks.len() as u32
    }

    /// The journal superblock (`journal_superblock_t`), checksummed.
    fn superblock(&mut self, sequence: u32, start: u32, head: u32) {
        let (bs, maxlen, compat, incompat, csum) = (
            self.bs,
            self.maxlen(),
            self.compat,
            self.incompat,
            self.csum(),
        );
        let b = &mut self.blocks[0];
        b.fill(0);
        put32(b, 0, JBD2_MAGIC_NUMBER);
        put32(b, 4, block_type::SUPERBLOCK_V2);
        put32(b, 0x0C, bs as u32);
        put32(b, 0x10, maxlen);
        put32(b, 0x14, 1);
        put32(b, 0x18, sequence);
        put32(b, 0x1C, start);
        put32(b, 0x24, compat);
        put32(b, 0x28, incompat);
        b[0x30..0x40].copy_from_slice(&UUID);
        put32(b, 0x58, head);
        if csum {
            b[0x50] = 4;
        }
        Self::seal_superblock(b, csum);
    }

    fn seal_superblock(b: &mut [u8], csum: bool) {
        if csum {
            b[0xFC..0x100].fill(0);
            let c = crc32c(!0, &b[..1024]);
            put32(b, 0xFC, c);
        }
    }

    fn wrap(&self, block: u32) -> u32 {
        if block >= self.maxlen() {
            block - (self.maxlen() - 1)
        } else {
            block
        }
    }

    fn header(b: &mut [u8], kind: u32, sequence: u32) {
        b.fill(0);
        put32(b, 0, JBD2_MAGIC_NUMBER);
        put32(b, 4, kind);
        put32(b, 8, sequence);
    }

    fn seal_tail(&self, b: &mut [u8]) {
        if self.csum() {
            let tail = self.bs - 4;
            b[tail..].fill(0);
            let c = crc32c(self.seed(), b);
            put32(b, tail, c);
        }
    }

    /// A descriptor at `at` naming `entries`, the data blocks after it.
    /// Returns the block after the last data block.
    fn descriptor(&mut self, at: u32, sequence: u32, entries: &[(u64, Vec<u8>)]) -> u32 {
        let mut d = vec![0u8; self.bs];
        Self::header(&mut d, block_type::DESCRIPTOR, sequence);
        let mut off = 12;
        let mut next = self.wrap(at + 1);
        for (i, (target, data)) in entries.iter().enumerate() {
            let mut logged = data.clone();
            let mut flags = 0u16;
            if get32(&logged, 0) == JBD2_MAGIC_NUMBER {
                flags |= tag_flag::ESCAPE;
                logged[..4].fill(0);
            }
            if i > 0 {
                flags |= tag_flag::SAME_UUID;
            }
            if i + 1 == entries.len() {
                flags |= tag_flag::LAST_TAG;
            }
            put32(&mut d, off, *target as u32);
            d[off + 6..off + 8].copy_from_slice(&flags.to_be_bytes());
            if self.wide() {
                put32(&mut d, off + 8, (*target >> 32) as u32);
            }
            let c = crc32c(crc32c(self.seed(), &sequence.to_be_bytes()), &logged);
            if self.csum3() {
                put32(&mut d, off + 12, c);
            } else if self.csum2() {
                d[off + 4..off + 6].copy_from_slice(&(c as u16).to_be_bytes());
            }
            off += self.tag_bytes();
            if i == 0 {
                off += 16;
            }
            self.blocks[next as usize] = logged;
            next = self.wrap(next + 1);
        }
        self.seal_tail(&mut d);
        self.blocks[at as usize] = d;
        next
    }

    /// A commit block (`struct commit_header`) at `at`.
    fn commit(&mut self, at: u32, sequence: u32, sec: u64) {
        let mut c = vec![0u8; self.bs];
        Self::header(&mut c, block_type::COMMIT, sequence);
        c[48..56].copy_from_slice(&sec.to_be_bytes());
        if self.csum() {
            let sum = crc32c(self.seed(), &c);
            put32(&mut c, 16, sum);
        }
        self.blocks[at as usize] = c;
    }

    /// A revoke block at `at`.
    fn revoke(&mut self, at: u32, sequence: u32, targets: &[u64]) {
        let mut r = vec![0u8; self.bs];
        Self::header(&mut r, block_type::REVOKE, sequence);
        let mut off = 16;
        for t in targets {
            if self.wide() {
                r[off..off + 8].copy_from_slice(&t.to_be_bytes());
                off += 8;
            } else {
                put32(&mut r, off, *t as u32);
                off += 4;
            }
        }
        put32(&mut r, 12, off as u32);
        self.seal_tail(&mut r);
        self.blocks[at as usize] = r;
    }
}

/// [`JournalIo`] over a [`Log`] and an in-memory filesystem.
struct Mem {
    log: Vec<Vec<u8>>,
    home: BTreeMap<u64, Vec<u8>>,
    writes: Vec<u64>,
    flushes: u32,
    fail_read: Option<u32>,
}

impl Mem {
    fn new(log: Log) -> Self {
        Self {
            log: log.blocks,
            home: BTreeMap::new(),
            writes: Vec::new(),
            flushes: 0,
            fail_read: None,
        }
    }
}

impl JournalIo for Mem {
    fn read_log<'a>(&'a mut self, block: u32, buf: &'a mut [u8]) -> IoFuture<'a> {
        alloc::boxed::Box::pin(async move {
            if self.fail_read == Some(block) {
                return Err(JournalError::Io);
            }
            let b = self
                .log
                .get(block as usize)
                .ok_or(JournalError::Corrupted)?;
            buf.copy_from_slice(b);
            Ok(())
        })
    }
    fn write_home<'a>(&'a mut self, block: u64, data: &'a [u8]) -> IoFuture<'a> {
        alloc::boxed::Box::pin(async move {
            self.writes.push(block);
            self.home.insert(block, data.to_vec());
            Ok(())
        })
    }
    fn write_log_fua<'a>(&'a mut self, block: u32, data: &'a [u8]) -> IoFuture<'a> {
        alloc::boxed::Box::pin(async move {
            self.log[block as usize] = data.to_vec();
            Ok(())
        })
    }
    fn flush(&mut self) -> IoFuture<'_> {
        alloc::boxed::Box::pin(async move {
            self.flushes += 1;
            Ok(())
        })
    }
}

const BS: usize = 1024;
const MAXLEN: u32 = 1024;
const V3: u32 = feature::INCOMPAT_CSUM_V3 | feature::INCOMPAT_64BIT | feature::INCOMPAT_REVOKE;

fn block_of(byte: u8) -> Vec<u8> {
    vec![byte; BS]
}

fn load(mem: &mut Mem) -> Result<(Journal, crate::journal::RecoveryInfo), JournalError> {
    let first = mem.log[0].clone();
    let mut j = Journal::load_superblock(&first, BS, MAXLEN)?;
    let info = run(j.load(mem, true))?;
    Ok((j, info))
}

// ── journal_check_superblock ────────────────────────────────────────

fn smoke_jbd2_superblock_checks_in_linux_order() -> TestResult {
    let check = |edit: &dyn Fn(&mut Vec<u8>), total: u32| -> Result<(), JournalError> {
        let mut log = Log::new(BS, MAXLEN, 0, V3);
        log.superblock(1, 0, 0);
        let mut b = log.blocks[0].clone();
        edit(&mut b);
        Journal::load_superblock(&b, BS, total).map(|_| ())
    };
    let reseal = |b: &mut Vec<u8>| Log::seal_superblock(b, true);
    type Case = (
        &'static str,
        Result<(), JournalError>,
        Result<(), JournalError>,
    );
    let cases: [Case; 12] = [
        ("valid", check(&|_| {}, MAXLEN), Ok(())),
        (
            "bad magic",
            check(&|b| put32(b, 0, 0), MAXLEN),
            Err(JournalError::Invalid),
        ),
        (
            "blocksize differs from the filesystem's",
            check(
                &|b| {
                    put32(b, 0x0C, 2048);
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "unknown superblock type",
            check(&|b| put32(b, 4, block_type::DESCRIPTOR), MAXLEN),
            Err(JournalError::Invalid),
        ),
        (
            "journal file too short",
            check(&|_| {}, MAXLEN - 1),
            Err(JournalError::Invalid),
        ),
        (
            "s_first 0",
            check(
                &|b| {
                    put32(b, 0x14, 0);
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "unknown incompat feature",
            check(
                &|b| {
                    put32(b, 0x28, V3 | 0x8000);
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "fewer than JBD2_MIN_JOURNAL_BLOCKS",
            check(
                &|b| {
                    put32(b, 0x10, 1023);
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "csum v2 and v3",
            check(
                &|b| {
                    put32(b, 0x28, V3 | feature::INCOMPAT_CSUM_V2);
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "csum v1 and v3",
            check(
                &|b| {
                    put32(b, 0x24, feature::COMPAT_CHECKSUM);
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "checksum type not crc32c",
            check(
                &|b| {
                    b[0x50] = 1;
                    reseal(b)
                },
                MAXLEN,
            ),
            Err(JournalError::Invalid),
        ),
        (
            "superblock checksum",
            check(&|b| b[0x100] ^= 1, MAXLEN),
            Err(JournalError::BadChecksum),
        ),
    ];
    for (_, got, want) in cases {
        if got != want {
            return TestResult::Fail("journal_check_superblock outcome differs from Linux");
        }
    }
    // A v1 superblock carries no features: none of the v2 checks apply.
    let mut log = Log::new(BS, MAXLEN, 0, 0);
    log.superblock(1, 0, 0);
    let mut b = log.blocks[0].clone();
    put32(&mut b, 4, block_type::SUPERBLOCK_V1);
    put32(&mut b, 0x28, 0xffff_0000);
    if Journal::load_superblock(&b, BS, MAXLEN).is_err() {
        return TestResult::Fail("a v1 superblock's feature words must be ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_superblock_checks_in_linux_order
);

fn smoke_jbd2_tag_bytes_match_journal_tag_bytes() -> TestResult {
    let cases = [
        (0, 8),
        (feature::INCOMPAT_64BIT, 12),
        (feature::INCOMPAT_CSUM_V2, 10),
        (feature::INCOMPAT_CSUM_V2 | feature::INCOMPAT_64BIT, 14),
        (feature::INCOMPAT_CSUM_V3, 16),
        (feature::INCOMPAT_CSUM_V3 | feature::INCOMPAT_64BIT, 16),
    ];
    for (incompat, want) in cases {
        let mut log = Log::new(BS, MAXLEN, 0, incompat);
        log.superblock(1, 0, 0);
        let Ok(j) = Journal::load_superblock(&log.blocks[0], BS, MAXLEN) else {
            return TestResult::Fail("superblock rejected");
        };
        if j.superblock().tag_bytes() != want {
            return TestResult::Fail("tag size differs from journal_tag_bytes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_tag_bytes_match_journal_tag_bytes
);

// ── Recovery ────────────────────────────────────────────────────────

/// An empty log (`s_start == 0`) replays nothing and resumes after
/// `s_sequence` at `s_head`.
fn smoke_jbd2_clean_log_replays_nothing() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    log.superblock(41, 0, 17);
    let mut mem = Mem::new(log);
    let Ok((j, info)) = load(&mut mem) else {
        return TestResult::Fail("clean journal failed to load");
    };
    if info.nr_replays != 0 || !mem.writes.is_empty() {
        return TestResult::Fail("a clean journal replayed blocks");
    }
    if j.transaction_sequence != 42 || j.head != 17 || !j.flushed {
        return TestResult::Fail("clean journal must resume at s_sequence + 1, s_head");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_clean_log_replays_nothing
);

/// Two transactions, csum v3 and 64-bit: every block lands home (the last
/// copy wins), an escaped block gets its magic back, a 64-bit target keeps
/// its high word, and the log restarts two ids later.
fn smoke_jbd2_replays_committed_transactions() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let mut escaped = block_of(0x77);
    escaped[..4].copy_from_slice(&JBD2_MAGIC_NUMBER.to_be_bytes());
    let high = 0x1_0000_0005u64;
    let next = log.descriptor(1, 100, &[(9, block_of(0xa1)), (high, escaped.clone())]);
    log.commit(next, 100, 1000);
    let next = log.descriptor(next + 1, 101, &[(9, block_of(0xb2))]);
    log.commit(next, 101, 1001);
    log.superblock(100, 1, 0);
    let mut mem = Mem::new(log);
    let Ok((j, info)) = load(&mut mem) else {
        return TestResult::Fail("recovery failed");
    };
    if info.nr_replays != 3 || mem.home.get(&9) != Some(&block_of(0xb2)) {
        return TestResult::Fail("later transaction's copy of block 9 must win");
    }
    if mem.home.get(&high) != Some(&escaped) {
        return TestResult::Fail("64-bit target or unescape wrong");
    }
    if mem.flushes == 0 {
        return TestResult::Fail("recovery must flush the replayed blocks");
    }
    // end_transaction is 102; the log restarts at 103 (++end_transaction).
    if j.transaction_sequence != 103 {
        return TestResult::Fail("log must restart after end_transaction");
    }
    // journal_reset rewrote the tail: s_sequence 103, s_start = head.
    let sb = &mem.log[0];
    if get32(sb, 0x18) != 103 || get32(sb, 0x1C) != j.head || j.head != 8 {
        return TestResult::Fail("journal_reset's log tail update is wrong");
    }
    if Journal::load_superblock(sb, BS, MAXLEN).is_err() {
        return TestResult::Fail("rewritten journal superblock fails its checksum");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_replays_committed_transactions
);

/// A revoke in a later transaction suppresses the block in earlier ones, and
/// a copy logged after the revoke still replays (`jbd2_journal_test_revoke`).
fn smoke_jbd2_revoke_applies_to_its_transaction_and_earlier() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let next = log.descriptor(1, 7, &[(20, block_of(1)), (21, block_of(2))]);
    log.commit(next, 7, 10);
    log.revoke(next + 1, 8, &[20, 21]);
    let next = log.descriptor(next + 2, 8, &[(30, block_of(3))]);
    log.commit(next, 8, 11);
    let next = log.descriptor(next + 1, 9, &[(21, block_of(4))]);
    log.commit(next, 9, 12);
    log.superblock(7, 1, 0);
    let mut mem = Mem::new(log);
    let Ok((_, info)) = load(&mut mem) else {
        return TestResult::Fail("recovery failed");
    };
    if mem.home.contains_key(&20) {
        return TestResult::Fail("block revoked by a later transaction was replayed");
    }
    if mem.home.get(&21) != Some(&block_of(4)) || mem.home.get(&30) != Some(&block_of(3)) {
        return TestResult::Fail("blocks logged after the revoke must replay");
    }
    if info.nr_revoke_hits != 2 || info.nr_revokes != 2 {
        return TestResult::Fail("revoke accounting differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_revoke_applies_to_its_transaction_and_earlier
);

/// A data block whose tag checksum is wrong is skipped, the others replay,
/// and recovery reports EFSBADCRC.
fn smoke_jbd2_bad_tag_checksum_skips_block_and_fails() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let next = log.descriptor(1, 3, &[(40, block_of(5)), (41, block_of(6))]);
    log.commit(next, 3, 5);
    log.blocks[2][100] ^= 0xff;
    log.superblock(3, 1, 0);
    let mut mem = Mem::new(log);
    match load(&mut mem) {
        Err(JournalError::BadChecksum) => {}
        _ => return TestResult::Fail("bad tag checksum must fail recovery with EFSBADCRC"),
    }
    if mem.home.contains_key(&40) || mem.home.get(&41) != Some(&block_of(6)) {
        return TestResult::Fail("only the corrupt block may be skipped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_bad_tag_checksum_skips_block_and_fails
);

/// A commit block with a bad checksum, newer than the last good one, is a
/// corrupt transaction: the earlier transaction replays, the load fails
/// with EFSCORRUPTED. Under async_commit it is an interrupted commit and
/// ends the log cleanly.
fn smoke_jbd2_bad_commit_checksum() -> TestResult {
    for async_commit in [false, true] {
        let incompat = V3
            | if async_commit {
                feature::INCOMPAT_ASYNC_COMMIT
            } else {
                0
            };
        let mut log = Log::new(BS, MAXLEN, 0, incompat);
        let next = log.descriptor(1, 50, &[(60, block_of(1))]);
        log.commit(next, 50, 100);
        let next2 = log.descriptor(next + 1, 51, &[(61, block_of(2))]);
        log.commit(next2, 51, 101);
        log.blocks[next2 as usize][16] ^= 1;
        log.superblock(50, 1, 0);
        let mut mem = Mem::new(log);
        let result = load(&mut mem);
        if mem.home.get(&60) != Some(&block_of(1)) || mem.home.contains_key(&61) {
            return TestResult::Fail("only the transaction before the bad commit replays");
        }
        match (async_commit, result) {
            (false, Err(JournalError::Corrupted)) => {}
            (true, Ok(_)) => {}
            _ => return TestResult::Fail("bad commit checksum outcome differs from Linux"),
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2/journal", smoke_jbd2_bad_commit_checksum);

/// A commit whose header reached the disk and whose remainder did not
/// (`jbd2_commit_block_csum_verify_partial`) still commits.
fn smoke_jbd2_torn_commit_block_counts() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let next = log.descriptor(1, 9, &[(70, block_of(9))]);
    log.commit(next, 9, 77);
    // Only the header's sector reached the disk: a later sector of the block
    // still holds old bytes, so the full checksum fails.
    log.blocks[next as usize][600] = 0xee;
    log.superblock(9, 1, 0);
    let mut mem = Mem::new(log);
    if load(&mut mem).is_err() || mem.home.get(&70) != Some(&block_of(9)) {
        return TestResult::Fail("a torn commit block with an intact header must commit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_torn_commit_block_counts
);

/// A descriptor that fails its checksum in SCAN is lazily-initialised stale
/// data when the commit after it is older than the last good commit (the
/// log just ends), and EFSBADCRC when it is not.
fn smoke_jbd2_stale_descriptor_uses_commit_time() -> TestResult {
    for (stale_time, want_ok) in [(50u64, true), (500u64, false)] {
        let mut log = Log::new(BS, MAXLEN, 0, V3);
        let next = log.descriptor(1, 20, &[(80, block_of(1))]);
        log.commit(next, 20, 100);
        let next2 = log.descriptor(next + 1, 21, &[(81, block_of(2))]);
        log.blocks[(next + 1) as usize][300] ^= 0xff;
        log.commit(next2, 21, stale_time);
        log.superblock(20, 1, 0);
        let mut mem = Mem::new(log);
        let result = load(&mut mem);
        match (want_ok, result) {
            (true, Ok(_)) => {
                if mem.home.get(&80) != Some(&block_of(1)) || mem.home.contains_key(&81) {
                    return TestResult::Fail("stale transaction must not replay");
                }
            }
            (false, Err(JournalError::BadChecksum)) => {}
            _ => return TestResult::Fail("stale-descriptor outcome differs from Linux"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_stale_descriptor_uses_commit_time
);

/// A transaction that runs past `s_maxlen` continues at `s_first`.
fn smoke_jbd2_log_wraps_at_maxlen() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let at = MAXLEN - 2;
    let next = log.descriptor(
        at,
        12,
        &[(90, block_of(1)), (91, block_of(2)), (92, block_of(3))],
    );
    if next != 3 {
        return TestResult::Fail("fixture: descriptor should wrap to block 3");
    }
    log.commit(next, 12, 9);
    log.superblock(12, at, 0);
    let mut mem = Mem::new(log);
    if load(&mut mem).is_err() || mem.home.len() != 3 || mem.home.get(&92) != Some(&block_of(3)) {
        return TestResult::Fail("wrapped transaction did not replay");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2/journal", smoke_jbd2_log_wraps_at_maxlen);

/// Tids wrap at 2^32 (`tid_gt`, `tid_geq`).
fn smoke_jbd2_transaction_ids_wrap() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let next = log.descriptor(1, u32::MAX, &[(100, block_of(1))]);
    log.commit(next, u32::MAX, 1);
    let next = log.descriptor(next + 1, 0, &[(101, block_of(2))]);
    log.commit(next, 0, 2);
    log.superblock(u32::MAX, 1, 0);
    let mut mem = Mem::new(log);
    let Ok((j, _)) = load(&mut mem) else {
        return TestResult::Fail("recovery across the tid wrap failed");
    };
    if mem.home.len() != 2 || j.transaction_sequence != 2 {
        return TestResult::Fail("transaction ids must wrap");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2/journal", smoke_jbd2_transaction_ids_wrap);

/// `jbd2_journal_wipe`: the log is scanned, nothing replays, and with
/// `write` the superblock says empty, keeping `s_sequence`.
fn smoke_jbd2_wipe_ignores_log() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let next = log.descriptor(1, 30, &[(110, block_of(1))]);
    log.commit(next, 30, 5);
    log.superblock(30, 1, 0);
    let mut mem = Mem::new(log);
    let first = mem.log[0].clone();
    let Ok(mut j) = Journal::load_superblock(&first, BS, MAXLEN) else {
        return TestResult::Fail("superblock rejected");
    };
    if run(j.wipe(&mut mem, true)).is_err() || run(j.load(&mut mem, true)).is_err() {
        return TestResult::Fail("wipe + load failed");
    }
    if !mem.home.is_empty() {
        return TestResult::Fail("a wiped journal must not replay");
    }
    let sb = &mem.log[0];
    if get32(sb, 0x1C) != 0 || get32(sb, 0x18) != 30 || get32(sb, 0x58) != 4 {
        return TestResult::Fail("wipe must mark the log empty at s_sequence, head after it");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/ext2/journal", smoke_jbd2_wipe_ignores_log);

/// A log of one sequence's descriptors all the way round, with no commit,
/// ends the pass with EFSCORRUPTED instead of spinning.
fn smoke_jbd2_endless_log_is_bounded() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, 0);
    for at in 1..MAXLEN {
        let mut d = vec![0u8; BS];
        Log::header(&mut d, block_type::DESCRIPTOR, 5);
        // One tag, flags LAST_TAG|SAME_UUID: it describes no block here
        // because the next block is a descriptor too; count_tags still
        // skips one block, so make every block a descriptor.
        put32(&mut d, 12, 1);
        d[18..20].copy_from_slice(&(tag_flag::LAST_TAG | tag_flag::SAME_UUID).to_be_bytes());
        log.blocks[at as usize] = d;
    }
    log.superblock(5, 1, 0);
    let mut mem = Mem::new(log);
    match load(&mut mem) {
        Err(JournalError::Corrupted) => TestResult::Pass,
        _ => TestResult::Fail("an endless log must fail, not spin"),
    }
}
kernel_test_in!("drivers/fs/ext2/journal", smoke_jbd2_endless_log_is_bounded);

/// A revoke block whose `r_count` is larger than the block is EINVAL.
fn smoke_jbd2_oversized_revoke_is_einval() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    log.revoke(1, 4, &[5]);
    put32(&mut log.blocks[1], 12, BS as u32);
    let mut b = log.blocks[1].clone();
    log.seal_tail(&mut b);
    log.blocks[1] = b;
    log.commit(2, 4, 1);
    log.superblock(4, 1, 0);
    let mut mem = Mem::new(log);
    match load(&mut mem) {
        Err(JournalError::Invalid) => TestResult::Pass,
        _ => TestResult::Fail("r_count past the block must be EINVAL"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_oversized_revoke_is_einval
);

/// COMPAT_CHECKSUM (v1): the commit carries crc32_be over the descriptor
/// and its data blocks; a wrong sum is a corrupt transaction.
fn smoke_jbd2_v1_transaction_checksum() -> TestResult {
    for corrupt in [false, true] {
        let mut log = Log::new(BS, MAXLEN, feature::COMPAT_CHECKSUM, 0);
        let next = log.descriptor(1, 60, &[(120, block_of(4))]);
        let mut sum = !0u32;
        for b in 1..next {
            sum = crate::journal::crc32_be(sum, &log.blocks[b as usize]);
        }
        log.commit(next, 60, 3);
        let c = &mut log.blocks[next as usize];
        c[12] = 1;
        c[13] = 4;
        put32(c, 16, if corrupt { sum ^ 1 } else { sum });
        log.superblock(60, 1, 0);
        let mut mem = Mem::new(log);
        let result = load(&mut mem);
        match (corrupt, result) {
            (false, Ok(_)) if mem.home.get(&120) == Some(&block_of(4)) => {}
            (true, Err(JournalError::Corrupted)) if mem.home.is_empty() => {}
            _ => return TestResult::Fail("v1 transaction checksum outcome differs from Linux"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_v1_transaction_checksum
);

/// A dirty journal with fast commits is refused before anything is written.
fn smoke_jbd2_fast_commit_replay_refused() -> TestResult {
    let mut log = Log::new(BS, 2048, 0, V3 | feature::INCOMPAT_FAST_COMMIT);
    let next = log.descriptor(1, 2, &[(130, block_of(1))]);
    log.commit(next, 2, 1);
    log.superblock(2, 1, 0);
    let mut mem = Mem::new(log);
    let first = mem.log[0].clone();
    let Ok(mut j) = Journal::load_superblock(&first, BS, 2048) else {
        return TestResult::Fail("superblock rejected");
    };
    match run(j.load(&mut mem, true)) {
        Err(JournalError::FastCommit) if mem.home.is_empty() => TestResult::Pass,
        _ => TestResult::Fail("fast-commit recovery must be refused, unwritten"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_fast_commit_replay_refused
);

/// A read error in the middle of SCAN fails recovery with EIO.
fn smoke_jbd2_read_error_fails_recovery() -> TestResult {
    let mut log = Log::new(BS, MAXLEN, 0, V3);
    let next = log.descriptor(1, 6, &[(140, block_of(1))]);
    log.commit(next, 6, 1);
    log.superblock(6, 1, 0);
    let mut mem = Mem::new(log);
    mem.fail_read = Some(next);
    match load(&mut mem) {
        Err(JournalError::Io) => TestResult::Pass,
        _ => TestResult::Fail("a log read error must fail recovery with EIO"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_jbd2_read_error_fails_recovery
);

// ── The journal at mount (ext4_load_journal) ────────────────────────

use narf_block::ram::RamBlockDevice;
use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest, CancelResult,
    LbaRange,
};
use narf_filesystem::{FsError, FsInstance};
use narf_lib::id::DomainId;

use crate::volume::Ext2Volume;

/// A RAM disk that refuses writes and says so (`bdev_read_only`).
struct ReadOnlyRam(Arc<RamBlockDevice>);

impl BlockDevice for ReadOnlyRam {
    fn logical_block_size(&self) -> u32 {
        self.0.logical_block_size()
    }
    fn physical_block_size(&self) -> u32 {
        self.0.physical_block_size()
    }
    fn capacity_blocks(&self) -> u64 {
        self.0.capacity_blocks()
    }
    fn supports(&self, f: BlockFeature) -> bool {
        self.0.supports(f)
    }
    fn is_read_only(&self) -> bool {
        true
    }
    async fn submit(&self, req: BlockRequest) -> BlockCompletion {
        if matches!(req.op, BlockOp::Read) {
            return self.0.submit(req).await;
        }
        BlockCompletion {
            tag: 0,
            user_tag: req.user_tag,
            result: Err(BlockError::PermissionDenied),
        }
    }
    async fn flush(&self) {}
    async fn discard(&self, _r: LbaRange) {}
    async fn cancel(&self, _tag: u64) -> CancelResult {
        CancelResult::NotFound
    }
}

fn put_le32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_le16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

const FS_BS: usize = 1024;
/// The journal inode's blocks on disk.
const JOURNAL_AT: usize = 16;
/// The root directory's block, which the journal rewrites.
const ROOT_DIR_BLOCK: usize = 9;

fn dir_block(name: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; FS_BS];
    put_le32(&mut b, 0, 12);
    put_le16(&mut b, 4, FS_BS as u16);
    b[6] = name.len() as u8;
    b[7] = 1; // EXT2_FT_REG_FILE
    b[8..8 + name.len()].copy_from_slice(name);
    b
}

/// An ext3 image (has_journal, no metadata_csum) whose 1024-block journal
/// (inode 8, its first 12 blocks mapped) holds one committed transaction
/// that rewrites the root directory: on disk the root lists "ondisk", the
/// journal's copy lists "REPLAYED". `recover` sets the superblock's
/// RECOVER; `links` is the journal inode's link count and `mode` its type.
pub(crate) fn ext3_image(recover: bool, links: u16, mode: u16) -> Vec<u8> {
    const TOTAL_BLOCKS: u32 = 128;
    const INODES_PER_GROUP: u32 = 32;
    const INODE_SIZE: usize = 128;
    let mut img = vec![0u8; FS_BS * TOTAL_BLOCKS as usize];
    let sb = &mut img[1024..2048];
    put_le32(sb, 0, INODES_PER_GROUP);
    put_le32(sb, 4, TOTAL_BLOCKS);
    put_le32(sb, 20, 1);
    put_le32(sb, 24, 0);
    put_le32(sb, 32, 128);
    put_le32(sb, 40, INODES_PER_GROUP);
    put_le16(sb, 56, 0xEF53);
    put_le16(sb, 58, 1); // EXT2_VALID_FS: Linux journals keep it set
    put_le32(sb, 76, 1);
    put_le16(sb, 88, INODE_SIZE as u16);
    put_le32(sb, 92, 0x4); // has_journal
    put_le32(sb, 96, 0x2 | if recover { 0x4 } else { 0 }); // filetype, RECOVER
    put_le32(sb, 224, 8);
    // Group descriptor: bitmaps at 3 and 4, inode table at 5..=8.
    let gdt = 2 * FS_BS;
    put_le32(&mut img, gdt, 3);
    put_le32(&mut img, gdt + 4, 4);
    put_le32(&mut img, gdt + 8, 5);
    put_le16(&mut img, gdt + 16, 1);
    let itab = 5 * FS_BS;
    // Root directory, inode 2.
    let root = itab + INODE_SIZE;
    put_le16(&mut img, root, 0x4000 | 0o755);
    put_le32(&mut img, root + 4, FS_BS as u32);
    put_le16(&mut img, root + 26, 2);
    put_le32(&mut img, root + 28, (FS_BS / 512) as u32);
    put_le32(&mut img, root + 40, ROOT_DIR_BLOCK as u32);
    // Journal, inode 8: 1024 blocks, the first 12 mapped at JOURNAL_AT.
    let jino = itab + 7 * INODE_SIZE;
    put_le16(&mut img, jino, mode);
    put_le32(&mut img, jino + 4, (MAXLEN as usize * FS_BS) as u32);
    put_le16(&mut img, jino + 26, links);
    put_le32(&mut img, jino + 28, 24);
    for i in 0..12 {
        put_le32(&mut img, jino + 40 + i * 4, (JOURNAL_AT + i) as u32);
    }
    img[ROOT_DIR_BLOCK * FS_BS..(ROOT_DIR_BLOCK + 1) * FS_BS]
        .copy_from_slice(&dir_block(b"ondisk"));
    // The journal: no checksum features, one transaction (tid 5).
    let mut log = Log::new(FS_BS, 12, 0, feature::INCOMPAT_REVOKE);
    let next = log.descriptor(1, 5, &[(ROOT_DIR_BLOCK as u64, dir_block(b"REPLAYED"))]);
    log.commit(next, 5, 1);
    log.blocks.resize(MAXLEN as usize, vec![0u8; FS_BS]);
    log.superblock(5, 1, 0);
    log.blocks.truncate(12);
    for (i, b) in log.blocks.iter().enumerate() {
        img[(JOURNAL_AT + i) * FS_BS..(JOURNAL_AT + i + 1) * FS_BS].copy_from_slice(b);
    }
    img
}

/// Empty [`ext3_image`]'s log (`s_start = 0`), leaving the superblock as it
/// is.
pub(crate) fn empty_log(img: &mut [u8]) {
    put32(
        &mut img[JOURNAL_AT * FS_BS..(JOURNAL_AT + 1) * FS_BS],
        0x1C,
        0,
    );
}

fn names(
    volume: &Arc<Ext2Volume<impl BlockDevice + 'static>>,
) -> Option<Vec<alloc::string::String>> {
    let entries = run(volume.root().enumerate_async(0, 16)).ok()?;
    Some(entries.into_iter().map(|(n, _)| n).collect())
}

fn jsb(img: &[u8]) -> &[u8] {
    &img[JOURNAL_AT * FS_BS..JOURNAL_AT * FS_BS + 1024]
}

fn incompat(img: &[u8]) -> u32 {
    u32::from_le_bytes(img[1024 + 96..1024 + 100].try_into().unwrap())
}

/// RECOVER set, read-write mount: the transaction is written home, the log
/// marked empty (s_start 0, restarting two ids on), and the root lists the
/// journal's copy.
fn smoke_ext4_rw_mount_replays_journal_to_disk() -> TestResult {
    let device = RamBlockDevice::from_image(512, ext3_image(true, 1, 0x8000 | 0o600));
    let Ok(volume) = run(Ext2Volume::mount(device.clone(), DomainId::DRIVER_0)) else {
        return TestResult::Fail("mount of a journal needing recovery failed");
    };
    if names(&volume).as_deref() != Some(&["REPLAYED".into()][..]) {
        return TestResult::Fail("root must list the replayed entry");
    }
    let img = device.snapshot();
    if img[ROOT_DIR_BLOCK * FS_BS..(ROOT_DIR_BLOCK + 1) * FS_BS] != dir_block(b"REPLAYED")[..] {
        return TestResult::Fail("the replay must reach the disk");
    }
    if get32(jsb(&img), 0x1C) != 0 || get32(jsb(&img), 0x18) != 7 {
        return TestResult::Fail("after recovery the log must be empty at tid 7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_ext4_rw_mount_replays_journal_to_disk
);

/// RECOVER set, read-only mount of a writable device: Linux replays to disk
/// anyway ("write access will be enabled during recovery") and clears
/// RECOVER (`ext4_mark_recovery_complete`).
fn smoke_ext4_ro_mount_replays_and_clears_recover() -> TestResult {
    let device = RamBlockDevice::from_image(512, ext3_image(true, 1, 0x8000 | 0o600));
    let Ok(volume) = run(Ext2Volume::mount_read_only(
        device.clone(),
        DomainId::DRIVER_0,
    )) else {
        return TestResult::Fail("read-only mount needing recovery failed");
    };
    if !volume.is_read_only() || names(&volume).as_deref() != Some(&["REPLAYED".into()][..]) {
        return TestResult::Fail("read-only mount must show the replayed root");
    }
    let img = device.snapshot();
    if img[ROOT_DIR_BLOCK * FS_BS..(ROOT_DIR_BLOCK + 1) * FS_BS] != dir_block(b"REPLAYED")[..] {
        return TestResult::Fail("read-only mount must still replay to the device");
    }
    if incompat(&img) & 0x4 != 0 || get32(jsb(&img), 0x1C) != 0 {
        return TestResult::Fail("RECOVER must be cleared and the log empty");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_ext4_ro_mount_replays_and_clears_recover
);

/// RECOVER set on a device that cannot be written: EROFS ("write access
/// unavailable, cannot proceed"), and not one byte written. `noload`
/// mounts it read-only as it is on disk.
fn smoke_ext4_recovery_on_read_only_device_is_erofs() -> TestResult {
    let image = ext3_image(true, 1, 0x8000 | 0o600);
    let ram = RamBlockDevice::from_image(512, image.clone());
    let device = Arc::new(ReadOnlyRam(ram.clone()));
    match run(Ext2Volume::mount_read_only(
        device.clone(),
        DomainId::DRIVER_0,
    )) {
        Err(FsError::ReadOnly) => {}
        _ => return TestResult::Fail("recovery on a read-only device must be EROFS"),
    }
    if ram.snapshot() != image {
        return TestResult::Fail("a refused mount must not write");
    }
    let Ok(volume) = run(Ext2Volume::mount_with_options(
        device,
        DomainId::DRIVER_0,
        true,
        true,
    )) else {
        return TestResult::Fail("noload read-only mount failed");
    };
    if names(&volume).as_deref() != Some(&["ondisk".into()][..]) || ram.snapshot() != image {
        return TestResult::Fail("noload must show the on-disk state and write nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_ext4_recovery_on_read_only_device_is_erofs
);

/// `noload` on a read-write mount of a filesystem that needs recovery:
/// "required journal recovery suppressed and not mounted read-only", EINVAL.
fn smoke_ext4_noload_rw_needing_recovery_is_einval() -> TestResult {
    let image = ext3_image(true, 1, 0x8000 | 0o600);
    let device = RamBlockDevice::from_image(512, image.clone());
    match run(Ext2Volume::mount_with_options(
        device.clone(),
        DomainId::DRIVER_0,
        false,
        true,
    )) {
        Err(FsError::InvalidData) if device.snapshot() == image => TestResult::Pass,
        _ => TestResult::Fail("noload read-write mount needing recovery must be EINVAL"),
    }
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_ext4_noload_rw_needing_recovery_is_einval
);

/// RECOVER clear with a non-empty log: the log is wiped, not replayed
/// (`jbd2_journal_wipe`), and marked empty at its old sequence.
fn smoke_ext4_journal_without_recover_is_wiped() -> TestResult {
    let device = RamBlockDevice::from_image(512, ext3_image(false, 1, 0x8000 | 0o600));
    let Ok(volume) = run(Ext2Volume::mount_read_only(
        device.clone(),
        DomainId::DRIVER_0,
    )) else {
        return TestResult::Fail("mount failed");
    };
    if names(&volume).as_deref() != Some(&["ondisk".into()][..]) {
        return TestResult::Fail("a journal without RECOVER must not replay");
    }
    let img = device.snapshot();
    if get32(jsb(&img), 0x1C) != 0 || get32(jsb(&img), 0x18) != 5 {
        return TestResult::Fail("wipe must mark the log empty at its sequence");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_ext4_journal_without_recover_is_wiped
);

/// The journal inode must be live and a regular file
/// (`ext4_get_journal_inode`: EFSCORRUPTED).
fn smoke_ext4_bad_journal_inode_is_efscorrupted() -> TestResult {
    for (links, mode) in [(0u16, 0x8000 | 0o600), (1, 0x4000 | 0o700)] {
        let device = RamBlockDevice::from_image(512, ext3_image(true, links, mode));
        match run(Ext2Volume::mount(device, DomainId::DRIVER_0)) {
            Err(FsError::Corrupted) => {}
            _ => return TestResult::Fail("a deleted or non-regular journal inode is EFSCORRUPTED"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/ext2/journal",
    smoke_ext4_bad_journal_inode_is_efscorrupted
);
