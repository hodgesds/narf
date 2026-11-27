//! Journaled metadata writes: ext4 on jbd2 in `data=ordered` mode
//! (`fs/jbd2/transaction.c`, `commit.c`, `checkpoint.c`;
//! `fs/ext4/ext4_jbd2.c`).
//!
//! While a journaled filesystem is mounted read-write, every metadata write
//! ([`Ext2Volume::write_byte_range`]) goes into the running transaction
//! instead of the device: whole filesystem blocks, the latest copy of each,
//! which every read consults first. File data is written to the device
//! directly, inside the operation that writes it, so it is on the device
//! before the commit that references it (`data=ordered`). A freshly
//! allocated block is zero-filled the same way: nothing references it in
//! the committed state, and its frees are held (below).
//!
//! An operation is a jbd2 handle: every mutation holds the volume's
//! `inode_update_lock`, and a commit runs only between operations, so one
//! operation's writes never straddle two transactions.
//!
//! A commit (`jbd2_journal_commit_transaction`), with every step's
//! durability before the next:
//! 1. After the log was marked empty, the journal superblock's tail is set
//!    to this transaction (FUA).
//! 2. The descriptors and copies are written to the log, then flushed.
//! 3. The commit block goes out with FUA.
//! 4. Checkpoint (`jbd2_log_do_checkpoint`): every block is written home,
//!    then flushed.
//! 5. The log tail moves past the transaction (FUA), so the log is empty
//!    again.
//!
//! A crash before step 3 loses the transaction and leaves the old metadata
//! intact; after it, recovery replays it. Every commit is checkpointed at
//! once, so the log never holds a block older than the running transaction
//! and no revoke record is ever needed.
//!
//! Blocks freed in the running transaction stay allocated to the allocator
//! until it commits (`ext4_free_blocks` with `EXT4_FREE_BLOCKS_METADATA`,
//! released by `ext4_journal_commit_callback`): reused as file data before
//! the commit, a crash would hand the old file the new file's bytes.
//!
//! Commits happen when an operation starts and the transaction has reached
//! its limit, on `fsync`/`syncfs`, on a timer (Linux's default 5 s commit
//! interval), and at remount read-only and unmount.
//!
//! LINUX-GAPs: one transaction at a time, committed and checkpointed in one
//! go (no overlap of a committing and a running transaction, no lazy
//! checkpointing); `commit=` is accepted but the interval stays 5 s; fast
//! commits are not written; an operation larger than the log fails (Linux
//! splits a large truncate across transactions with the orphan list).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_block::BlockDevice;
use narf_filesystem::FsError;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use super::super::inode::Inode;
use super::super::journal::{IoFuture, Journal, JournalError, JournalIo};
use super::Ext2Volume;

/// Linux's default commit interval (`JBD2_DEFAULT_MAX_COMMIT_AGE`).
pub(crate) const COMMIT_INTERVAL_SECS: u64 = 5;
/// The most memory a running transaction may hold before the next
/// operation commits it first.
const MAX_TRANSACTION_BYTES: usize = 4 << 20;

/// The journal of a mounted volume.
pub(crate) struct Jbd {
    /// The journal inode, to map log blocks.
    inode: Inode,
    /// The jbd2 state: head, tail, sequence, the superblock.
    journal: Mutex<Journal>,
    /// Metadata writes go through the journal (a read-write mount).
    active: AtomicBool,
    /// A commit failed: nothing more is written (`jbd2_journal_abort`).
    aborted: AtomicBool,
    /// The running transaction: filesystem block → its latest contents.
    running: IrqSafeSpinLock<BTreeMap<u64, Arc<[u8]>>>,
    /// Blocks freed in the running transaction: start → end (exclusive).
    held: IrqSafeSpinLock<BTreeMap<u64, u64>>,
    /// Blocks the running transaction may hold before a commit is due.
    limit: usize,
    /// When the running transaction got its first block (ns), or 0.
    started_ns: AtomicU64,
    /// The last commit's time, so commit times never go backwards (recovery
    /// tells a stale log by an older commit time).
    last_commit_sec: AtomicU64,
}

impl core::fmt::Debug for Jbd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Jbd")
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("aborted", &self.aborted.load(Ordering::Relaxed))
            .field("running_blocks", &self.running.lock().len())
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl Jbd {
    /// `journal`, loaded and recovered at mount, for the journal `inode`.
    /// `block_size` sizes the transaction limit: a quarter of the log
    /// (`jbd2_journal_get_max_txn_bufs`), at most [`MAX_TRANSACTION_BYTES`].
    pub(crate) fn new(journal: Journal, inode: Inode, block_size: usize) -> Self {
        let quarter = (journal.log_len() / 4) as usize;
        let cap = MAX_TRANSACTION_BYTES / block_size.max(1);
        let limit = quarter.min(cap).max(1);
        Self {
            inode,
            journal: Mutex::new(journal),
            active: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            running: IrqSafeSpinLock::new(BTreeMap::new()),
            held: IrqSafeSpinLock::new(BTreeMap::new()),
            limit,
            started_ns: AtomicU64::new(0),
            last_commit_sec: AtomicU64::new(0),
        }
    }

    pub(crate) fn set_active(&self, on: bool) {
        self.active.store(on, Ordering::Release);
    }
}

/// [`JournalIo`] over the mounted volume.
struct LiveIo<'a, B: BlockDevice + 'static> {
    vol: &'a Ext2Volume<B>,
    inode: &'a Inode,
}

impl<B: BlockDevice + 'static> LiveIo<'_, B> {
    /// `jbd2_journal_bmap`: a log block that does not map is EFSCORRUPTED.
    async fn map(&self, block: u32) -> Result<u64, JournalError> {
        match self.vol.map_block(self.inode, u64::from(block)).await {
            Ok(0) | Err(_) => Err(JournalError::Corrupted),
            Ok(physical) => Ok(physical),
        }
    }

    /// One log block, plain (descriptors, copies, revokes).
    async fn write_log(&self, block: u32, data: &[u8]) -> Result<(), JournalError> {
        let physical = self.map(block).await?;
        let bs = self.vol.block_size() as u64;
        self.vol
            .write_direct(physical * bs, data, false)
            .await
            .map_err(|_| JournalError::Io)
    }
}

impl<B: BlockDevice + 'static> JournalIo for LiveIo<'_, B> {
    fn read_log<'b>(&'b mut self, block: u32, buf: &'b mut [u8]) -> IoFuture<'b> {
        alloc::boxed::Box::pin(async move {
            let physical = self.map(block).await?;
            let bs = self.vol.block_size() as u64;
            self.vol
                .read_device(physical * bs, buf)
                .await
                .map_err(|_| JournalError::Io)
        })
    }

    fn write_home<'b>(&'b mut self, block: u64, data: &'b [u8]) -> IoFuture<'b> {
        alloc::boxed::Box::pin(async move {
            let bs = self.vol.block_size() as u64;
            self.vol
                .write_direct(block * bs, data, false)
                .await
                .map_err(|_| JournalError::Io)
        })
    }

    fn write_log_fua<'b>(&'b mut self, block: u32, data: &'b [u8]) -> IoFuture<'b> {
        alloc::boxed::Box::pin(async move {
            let physical = self.map(block).await?;
            let bs = self.vol.block_size() as u64;
            self.vol
                .write_direct(physical * bs, data, true)
                .await
                .map_err(|_| JournalError::Io)
        })
    }

    fn flush(&mut self) -> IoFuture<'_> {
        alloc::boxed::Box::pin(async move {
            self.vol
                .device
                .flush_result()
                .await
                .map_err(|_| JournalError::Io)
        })
    }
}

fn now_ns() -> u64 {
    narf_time::cycles_to_ns(narf_time::now_cycles())
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Metadata writes go through the journal.
    pub(crate) fn journaling(&self) -> bool {
        self.jbd
            .as_ref()
            .is_some_and(|j| j.active.load(Ordering::Acquire) && !j.aborted.load(Ordering::Acquire))
    }

    /// The running transaction's copy of `block`, if it has one.
    pub(crate) fn running_block(&self, block: u64) -> Option<Arc<[u8]>> {
        let jbd = self.jbd.as_ref()?;
        jbd.running.lock().get(&block).cloned()
    }

    /// Whether the running transaction holds any block.
    pub(crate) fn has_running_blocks(&self) -> bool {
        self.jbd
            .as_ref()
            .is_some_and(|j| !j.running.lock().is_empty())
    }

    /// A metadata write into the running transaction: each filesystem block
    /// the range touches is read whole (the running copy first), patched and
    /// kept there. The device is untouched until the commit.
    pub(crate) async fn journal_write(&self, byte_off: u64, src: &[u8]) -> Result<(), FsError> {
        let Some(jbd) = self.jbd.as_ref() else {
            return Err(FsError::Io(narf_block::BlockError::IOError));
        };
        let bs = self.block_size() as u64;
        let mut cursor = 0usize;
        while cursor < src.len() {
            let abs = byte_off + cursor as u64;
            let block = abs / bs;
            let in_block = (abs % bs) as usize;
            let take = (src.len() - cursor).min(bs as usize - in_block);
            let mut bytes = match self.running_block(block) {
                Some(copy) => copy.to_vec(),
                None if in_block == 0 && take == bs as usize => alloc::vec![0u8; bs as usize],
                None => {
                    let mut whole = alloc::vec![0u8; bs as usize];
                    self.read_byte_range(block * bs, &mut whole).await?;
                    whole
                }
            };
            bytes[in_block..in_block + take].copy_from_slice(&src[cursor..cursor + take]);
            {
                let mut running = jbd.running.lock();
                if running.is_empty() {
                    jbd.started_ns.store(now_ns().max(1), Ordering::Relaxed);
                }
                running.insert(block, Arc::from(bytes));
            }
            cursor += take;
        }
        self.invalidate_bytes(byte_off, src.len());
        Ok(())
    }

    /// A write that goes to the device directly (a superblock state change
    /// with FUA) also lands in the running copy of the blocks it covers, so
    /// the checkpoint cannot put back the bytes it replaced.
    pub(crate) fn patch_running(&self, byte_off: u64, src: &[u8]) {
        let Some(jbd) = self.jbd.as_ref() else {
            return;
        };
        let bs = self.block_size() as u64;
        let mut running = jbd.running.lock();
        if running.is_empty() {
            return;
        }
        let mut cursor = 0usize;
        while cursor < src.len() {
            let abs = byte_off + cursor as u64;
            let block = abs / bs;
            let in_block = (abs % bs) as usize;
            let take = (src.len() - cursor).min(bs as usize - in_block);
            if let Some(copy) = running.get_mut(&block) {
                let mut bytes = copy.to_vec();
                bytes[in_block..in_block + take].copy_from_slice(&src[cursor..cursor + take]);
                *copy = Arc::from(bytes);
            }
            cursor += take;
        }
    }

    /// Blocks `start..start + len` were freed in the running transaction:
    /// the allocator leaves them alone until it commits.
    pub(crate) fn hold_blocks(&self, start: u64, len: u64) {
        if len == 0 || !self.journaling() {
            return;
        }
        if let Some(jbd) = self.jbd.as_ref() {
            jbd.held.lock().insert(start, start + len);
        }
    }

    /// Whether `block` was freed in the running transaction.
    pub(crate) fn block_held(&self, block: u64) -> bool {
        let Some(jbd) = self.jbd.as_ref() else {
            return false;
        };
        let held = jbd.held.lock();
        held.range(..=block)
            .next_back()
            .is_some_and(|(_, &end)| block < end)
    }

    /// The running transaction has reached its limit.
    pub(crate) fn journal_due(&self) -> bool {
        self.jbd
            .as_ref()
            .is_some_and(|j| j.running.lock().len() >= j.limit)
    }

    /// The running transaction is older than the commit interval.
    pub(crate) fn journal_aged(&self) -> bool {
        let Some(jbd) = self.jbd.as_ref() else {
            return false;
        };
        let started = jbd.started_ns.load(Ordering::Relaxed);
        started != 0 && now_ns().saturating_sub(started) >= COMMIT_INTERVAL_SECS * 1_000_000_000
    }

    /// Commit and checkpoint the running transaction. The caller holds
    /// `inode_update_lock` (or is the last user, at unmount). On failure the
    /// journal is aborted and the volume goes read-only; the running copies
    /// stay readable and are never written.
    pub(crate) async fn journal_commit(&self) -> Result<(), FsError> {
        let Some(jbd) = self.jbd.as_ref() else {
            return Ok(());
        };
        if !jbd.active.load(Ordering::Acquire) {
            return Ok(());
        }
        if jbd.aborted.load(Ordering::Acquire) {
            return Err(FsError::Io(narf_block::BlockError::IOError));
        }
        let mut journal = jbd.journal.lock().await;
        let blocks: Vec<(u64, Arc<[u8]>)> = jbd
            .running
            .lock()
            .iter()
            .map(|(&b, d)| (b, d.clone()))
            .collect();
        if blocks.is_empty() {
            jbd.held.lock().clear();
            return Ok(());
        }
        let result = self.commit_blocks(jbd, &mut journal, &blocks).await;
        match result {
            Ok(()) => {
                jbd.running.lock().clear();
                jbd.held.lock().clear();
                jbd.started_ns.store(0, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                use core::fmt::Write as _;
                jbd.aborted.store(true, Ordering::Release);
                self.read_only.store(true, Ordering::Release);
                let _ = writeln!(
                    narf_console::Writer,
                    "ext4 {}: journal commit failed ({error:?}); journal aborted, filesystem READ-ONLY",
                    super::sb_state::uuid_string(&self.superblock)
                );
                Err(error)
            }
        }
    }

    async fn commit_blocks(
        &self,
        jbd: &Jbd,
        journal: &mut Journal,
        blocks: &[(u64, Arc<[u8]>)],
    ) -> Result<(), FsError> {
        let jerr = |e: JournalError| match e {
            JournalError::NoMemory => FsError::OutOfMemory,
            JournalError::Corrupted => FsError::Corrupted,
            _ => FsError::Io(narf_block::BlockError::IOError),
        };
        let bs = self.block_size() as u64;
        let mut io = LiveIo {
            vol: self,
            inode: &jbd.inode,
        };
        // An operation larger than the whole log cannot commit atomically.
        if journal.transaction_blocks(blocks.len(), 0) as u64 > u64::from(journal.log_len()) {
            return Err(FsError::NoSpace);
        }
        let tid = journal.transaction_sequence;
        let head = journal.head;
        if journal.flushed {
            journal
                .update_sb_log_tail(&mut io, tid, head)
                .await
                .map_err(jerr)?;
        }
        let wall = narf_time::now_wall();
        let sec = (wall.secs.max(0) as u64).max(jbd.last_commit_sec.load(Ordering::Relaxed));
        jbd.last_commit_sec.store(sec, Ordering::Relaxed);
        let refs: Vec<(u64, &[u8])> = blocks.iter().map(|(b, d)| (*b, &d[..])).collect();
        let encoded = journal.encode_transaction(tid, head, &refs, &[], sec, wall.nanos);
        for w in &encoded.body {
            io.write_log(w.block, &w.data).await.map_err(jerr)?;
        }
        io.flush().await.map_err(jerr)?;
        io.write_log_fua(encoded.commit.block, &encoded.commit.data)
            .await
            .map_err(jerr)?;
        // Checkpoint.
        for (block, data) in blocks {
            self.write_direct(block * bs, data, false).await?;
        }
        io.flush().await.map_err(jerr)?;
        journal.head = encoded.next_head;
        journal.transaction_sequence = tid.wrapping_add(1);
        journal.tail = encoded.next_head;
        journal.tail_sequence = journal.transaction_sequence;
        let (tail_tid, tail) = (journal.tail_sequence, journal.tail);
        journal
            .update_sb_log_tail(&mut io, tail_tid, tail)
            .await
            .map_err(jerr)
    }

    /// `jbd2_journal_flush` at remount read-only and unmount: commit, then
    /// mark the log empty (`s_start = 0`).
    pub(crate) async fn journal_flush(&self) -> Result<(), FsError> {
        self.journal_commit().await?;
        let Some(jbd) = self.jbd.as_ref() else {
            return Ok(());
        };
        let mut journal = jbd.journal.lock().await;
        let mut io = LiveIo {
            vol: self,
            inode: &jbd.inode,
        };
        journal.mark_empty(&mut io).await;
        Ok(())
    }

    /// Start journaled writes on a read-write mount: ext4's journal features
    /// (`ext4_set_journal_csum_feature_set`, the 64-bit format), written with
    /// the first commit.
    pub(crate) async fn journal_start(&self) -> Result<(), FsError> {
        let Some(jbd) = self.jbd.as_ref() else {
            return Ok(());
        };
        {
            let mut journal = jbd.journal.lock().await;
            journal
                .set_write_features(
                    self.superblock.has_metadata_csum(),
                    self.superblock.feature_incompat
                        & super::super::superblock::incompat::SIXTYFOURBIT
                        != 0,
                )
                .map_err(|_| FsError::InvalidData)?;
        }
        jbd.set_active(true);
        self.spawn_commit_timer();
        Ok(())
    }

    /// `jbd2_journal_abort`: nothing more is committed. The running
    /// transaction, with whatever a failed operation left half done in it,
    /// is never written; `RECOVER` stays set, so the next mount recovers the
    /// last commit.
    pub(crate) fn journal_abort(&self) {
        use core::fmt::Write as _;
        let Some(jbd) = self.jbd.as_ref() else {
            return;
        };
        if jbd.active.load(Ordering::Acquire) && !jbd.aborted.swap(true, Ordering::AcqRel) {
            let _ = writeln!(
                narf_console::Writer,
                "Aborting journal on device {}.",
                super::sb_state::uuid_string(&self.superblock)
            );
        }
    }

    /// kjournald2's periodic commit: every [`COMMIT_INTERVAL_SECS`], a
    /// transaction at least that old is committed.
    fn spawn_commit_timer(&self) {
        if !cfg!(target_os = "none") {
            // Host builds have no executor to run it; they commit on sync.
            return;
        }
        let weak = self.self_weak.clone();
        let tick = narf_time::wall::ns_to_cycles(COMMIT_INTERVAL_SECS * 1_000_000_000);
        let _ = narf_scheduler::spawn_with_spec(
            alloc::boxed::Box::pin(async move {
                loop {
                    narf_time::sleep_cycles(tick).await;
                    let Some(vol) = weak.upgrade() else {
                        return;
                    };
                    if !vol.journaling() {
                        return;
                    }
                    if vol.journal_aged() {
                        let _update = vol.lock_inode_updates().await;
                        let _ = vol.journal_commit().await;
                    }
                }
            }),
            narf_scheduler::TaskSpec::kernel_any(),
        );
    }
}
