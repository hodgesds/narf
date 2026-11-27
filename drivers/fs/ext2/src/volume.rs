//! ext2 volume management.
//!
//! Clean-room implementation. Volume mount, superblock + BGDT
//! decoding, inode-number-to-block-group math, and the indirect-block
//! pointer walk all derived strictly from the public references
//! below — no GPL Linux `fs/ext2/*`, GRUB, e2fsprogs, or BSD ext2
//! sources were consulted while writing this file.
//!
//! References:
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, §"Physical Layout", §"Block Groups",
//!   §"Inodes". <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_.
//! - OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::task::{Context, Poll, Waker};

use narf_block::{BlockDevice, BlockFeature, BlockOp, BlockRequest, LbaRange, QosHint};
use narf_capabilities::{Cap, Read, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{
    BlockMapping, DirOps, FolioSlice, FsError, FsInstance, PageCache, PAGE_SIZE,
};
use narf_io::{alloc_coherent, register_with_cap, resolve_cap, unregister, DmaBuffer};
use narf_lib::mutex::Mutex;

use narf_lib::sync::IrqSafeSpinLock;
use narf_time::now_wall;

use super::group_desc::GroupDesc;
use super::inode::Inode;
use super::journal;
use super::metadata_csum;
use super::superblock::{ExtFlavour, Superblock};

mod extent_write;
mod file_data;
mod free_list;
pub(crate) mod jbd;
pub(crate) mod orphan;
pub mod sb_state;
pub(crate) mod uninit;
pub(crate) mod xattr;

/// Cap → DmaBuffer pair owned by an Ext2Volume. The cap is minted
/// once at `mount()` via `narf_io::register_with_cap` and is the
/// load-bearing identifier in every `BlockRequest::buffer`. Drop
/// calls `unregister`, which bumps the epoch + frees the registry
/// slot + releases the underlying frame.
/// Number of scratch DMA buffers in the per-volume pool. A device op
/// borrows one for its whole submit→await→copy span, so this bounds how
/// many reads/writes can be in flight concurrently before one has to wait
/// for a buffer. Sized to comfortably cover a multi-stage pipeline's worth
/// of simultaneous execve loads (each stage streams a binary block-by-block).
const SCRATCH_POOL_LEN: usize = 16;

/// Size of each scratch DMA buffer. A multi-block `BlockRequest` reads up to
/// this many contiguous device bytes per submit, so a sequential file read
/// pays one submit→await round-trip per buffer instead of one per logical
/// block — with a 512-byte LBS that's 128 LBAs per request, so mmap'ing a big
/// DSO (Mesa/Qt6, MBs) does ~128× fewer device round-trips than a per-block
/// read (16× fewer than the previous 4 KiB buffer). `narf_io::alloc_coherent`
/// now backs this with a single physically-contiguous 64 KiB (order-4) region,
/// which the virtio-blk driver DMAs through one data descriptor.
const SCRATCH_BUF_BYTES: usize = 65536;

#[derive(Debug)]
struct VolumeIo {
    /// Free list of registered DMA scratch buffers. A device op pops one
    /// (exclusive ownership for its DMA), returns it on completion. A SINGLE
    /// shared buffer would let two concurrent reads DMA into it and clobber
    /// each other (the old serialize-via-mutex scheme busy-spun under
    /// poll_blocking and starved one read under 3-way contention). With a
    /// pool, concurrent ops use distinct buffers — the block device, not a
    /// lock, serialises the actual requests.
    pool: Vec<Cap<DmaBuffer, Write>>,
    /// Futures sleeping until a scratch buffer is returned. IDs make waiter
    /// registration cancellation-safe: dropping an FS future removes only its
    /// own entry instead of leaving a stale waker in the volume indefinitely.
    scratch_waiters: BTreeMap<u64, Waker>,
    next_scratch_waiter: u64,
    /// Logical block size of the underlying device.
    lbs: usize,
    /// Byte size of each pooled scratch buffer (a multiple of `lbs`, >= `lbs`).
    /// Bounds how many blocks one multi-block `BlockRequest` can read at once.
    scratch_bytes: usize,
}

impl Drop for VolumeIo {
    fn drop(&mut self) {
        // Every buffer is back in the pool by the time the volume drops (an
        // in-flight op holds an Arc<Ext2Volume>, so the volume outlives it).
        for &cap in &self.pool {
            unregister(cap);
        }
    }
}

/// RAII handle to a borrowed scratch buffer: returns it to the pool on drop,
/// including when a `poll_blocking` timeout drops the owning future mid-op.
struct ScratchGuard<'a> {
    io: &'a IrqSafeSpinLock<VolumeIo>,
    cap: Cap<DmaBuffer, Write>,
}

fn return_scratch(io_lock: &IrqSafeSpinLock<VolumeIo>, cap: Cap<DmaBuffer, Write>) {
    let wake = {
        let mut io = io_lock.lock();
        io.pool.push(cap);
        io.scratch_waiters
            .keys()
            .next()
            .copied()
            .and_then(|id| io.scratch_waiters.remove(&id))
    };
    if let Some(waker) = wake {
        waker.wake();
    }
}

impl Drop for ScratchGuard<'_> {
    fn drop(&mut self) {
        return_scratch(self.io, self.cap);
    }
}

/// Future for one slot in the per-volume scratch-buffer waitqueue.
struct AcquireScratch<'a> {
    io: &'a IrqSafeSpinLock<VolumeIo>,
    waiter_id: Option<u64>,
}

impl Drop for AcquireScratch<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.waiter_id.take() {
            let wake = {
                let mut io = self.io.lock();
                let still_registered = io.scratch_waiters.remove(&id).is_some();
                // If the entry was already taken, buffer return selected and
                // woke us. Cancellation before our next poll must hand that
                // now-free capacity to another waiter or it could sleep
                // forever while a buffer sits idle.
                if !still_registered && !io.pool.is_empty() {
                    io.scratch_waiters
                        .keys()
                        .next()
                        .copied()
                        .and_then(|next| io.scratch_waiters.remove(&next))
                } else {
                    None
                }
            };
            if let Some(waker) = wake {
                waker.wake();
            }
        }
    }
}

impl<'a> core::future::Future for AcquireScratch<'a> {
    type Output = ScratchGuard<'a>;

    fn poll(mut self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut io = self.io.lock();
        if let Some(cap) = io.pool.pop() {
            if let Some(id) = self.waiter_id.take() {
                io.scratch_waiters.remove(&id);
            }
            drop(io);
            return Poll::Ready(ScratchGuard { io: self.io, cap });
        }

        if let Some(id) = self.waiter_id {
            if let Some(waker) = io.scratch_waiters.get_mut(&id) {
                if !waker.will_wake(cx.waker()) {
                    *waker = cx.waker().clone();
                }
            } else {
                io.scratch_waiters.insert(id, cx.waker().clone());
            }
        } else {
            let id = loop {
                let candidate = io.next_scratch_waiter.max(1);
                io.next_scratch_waiter = candidate.wrapping_add(1).max(1);
                if !io.scratch_waiters.contains_key(&candidate) {
                    break candidate;
                }
            };
            io.scratch_waiters.insert(id, cx.waker().clone());
            self.waiter_id = Some(id);
        }
        Poll::Pending
    }
}

/// Borrow a scratch buffer from the pool, sleeping until one is free.
async fn acquire_scratch(io: &IrqSafeSpinLock<VolumeIo>) -> ScratchGuard<'_> {
    AcquireScratch {
        io,
        waiter_id: None,
    }
    .await
}

#[doc(hidden)]
pub(super) fn __test_scratch_waitqueue_wakes_and_handoffs() -> bool {
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{RawWaker, RawWakerVTable};

    static FIRST_WAKES: AtomicUsize = AtomicUsize::new(0);
    static SECOND_WAKES: AtomicUsize = AtomicUsize::new(0);

    unsafe fn clone(data: *const ()) -> RawWaker {
        RawWaker::new(data, &VTABLE)
    }
    unsafe fn wake(data: *const ()) {
        // SAFETY: test wakers store a pointer to one of the two static counters.
        let counter = unsafe { &*(data.cast::<AtomicUsize>()) };
        counter.fetch_add(1, Ordering::Relaxed);
    }
    unsafe fn wake_by_ref(data: *const ()) {
        // SAFETY: same representation and lifetime as `wake`.
        unsafe { wake(data) };
    }
    unsafe fn drop_waker(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);

    FIRST_WAKES.store(0, Ordering::Relaxed);
    SECOND_WAKES.store(0, Ordering::Relaxed);
    let io = core::mem::ManuallyDrop::new(IrqSafeSpinLock::new(VolumeIo {
        pool: Vec::new(),
        scratch_waiters: BTreeMap::new(),
        next_scratch_waiter: 1,
        lbs: 512,
        scratch_bytes: 512,
    }));
    let mut first = AcquireScratch {
        io: &io,
        waiter_id: None,
    };
    let mut second = AcquireScratch {
        io: &io,
        waiter_id: None,
    };
    // SAFETY: the data pointers name static AtomicUsize values and the vtable
    // preserves those pointers without ownership or lifetime obligations.
    let first_waker = unsafe {
        Waker::from_raw(RawWaker::new(
            (&FIRST_WAKES as *const AtomicUsize).cast(),
            &VTABLE,
        ))
    };
    // SAFETY: same as above.
    let second_waker = unsafe {
        Waker::from_raw(RawWaker::new(
            (&SECOND_WAKES as *const AtomicUsize).cast(),
            &VTABLE,
        ))
    };
    let mut first_cx = Context::from_waker(&first_waker);
    let mut second_cx = Context::from_waker(&second_waker);
    if !matches!(Pin::new(&mut first).poll(&mut first_cx), Poll::Pending)
        || !matches!(Pin::new(&mut second).poll(&mut second_cx), Poll::Pending)
    {
        return false;
    }

    // A returned buffer selects the oldest waiter. Cancelling that selected
    // future before it polls again must hand the free capacity to the next.
    return_scratch(&io, Cap::<DmaBuffer, Write>::bootstrap());
    if FIRST_WAKES.load(Ordering::Relaxed) != 1 || SECOND_WAKES.load(Ordering::Relaxed) != 0 {
        return false;
    }
    drop(first);
    if SECOND_WAKES.load(Ordering::Relaxed) != 1 {
        return false;
    }
    let guard = match Pin::new(&mut second).poll(&mut second_cx) {
        Poll::Ready(guard) => guard,
        Poll::Pending => return false,
    };
    drop(guard);
    drop(second);
    // The bootstrap cap is a test stand-in, not a registered I/O object. Skip
    // VolumeIo::drop so it is not passed to unregister().
    true
}

/// One mounted ext2 volume.
#[derive(Debug)]
pub struct Ext2Volume<B: BlockDevice + 'static> {
    pub device: Arc<B>,
    pub superblock: Superblock,
    pub group_descs: Vec<GroupDesc>,
    pub domain: DomainId,
    pub self_weak: Weak<Ext2Volume<B>>,
    /// Per-volume scratch buffer pool + free list. Wrapped in a spinlock
    /// guarding only the pop/push of the free list and the synchronous
    /// byte-copy — never held across an `await` (the lock would otherwise
    /// deadlock under cooperative async). A device op pops its own buffer
    /// from the pool, so concurrent reads/writes never share scratch.
    io: IrqSafeSpinLock<VolumeIo>,
    /// The volume's page cache: one tree for the block-device mapping
    /// (`bdev_mapping`, inode 0 — metadata keyed by device page). An `Arc`
    /// so it can also be registered with the central memory reclaimer as a
    /// shrinker. The fill protocol (miss coalescing, per-page invalidation of
    /// in-flight fills) lives in the cache itself; see
    /// `narf_filesystem::page_cache`.
    page_cache: Arc<PageCache>,
    /// Linux's `bdev` inode mapping over `page_cache`. Device writes
    /// (`write_byte_range`) invalidate exactly the device pages they cover.
    bdev_mapping: BlockMapping,
    /// The inode cache (Linux `fs/inode.c` icache): at most one live
    /// `Ext2Node` per on-disk inode, so every lookup, open, hard link and
    /// `FsInstance::root` of one inode shares one in-memory inode — and,
    /// through it, one page-cache mapping. Weak, so an unreferenced node is
    /// evicted when its last `Arc` drops (`Ext2Node::drop` removes its own
    /// entry). Never held while a node is dropped or across an `.await`.
    icache: IrqSafeSpinLock<BTreeMap<u32, Weak<super::node::Ext2Node<B>>>>,
    /// Unlinked inodes whose last node has dropped and which are not yet
    /// released (Linux's deferred `iput_final`). Drained by
    /// [`Self::lock_inode_updates`].
    orphans: IrqSafeSpinLock<Vec<u32>>,
    /// The on-disk orphan record: the orphan file and the `s_last_orphan`
    /// list (`orphan.rs`).
    pub(crate) orphans_state: IrqSafeSpinLock<orphan::Orphans>,
    /// `s_feature_ro_compat & RO_COMPAT_LARGE_FILE`, as on disk now. Set
    /// once, when the first inode past 2 GiB is written.
    large_file: core::sync::atomic::AtomicBool,
    /// Source of node incarnations; see [`Self::new_file_mapping`].
    incarnations: core::sync::atomic::AtomicU32,
    /// Serializes whole-inode read/modify/write sequences. Directory
    /// mutations rewrite inodes (parent, target) that have no node in hand,
    /// so this stays volume-wide rather than per node.
    pub(crate) inode_update_lock: Mutex<()>,
    /// Serializes bitmap + group-descriptor + superblock counter updates.
    /// These three writes form one allocation transaction; allowing two
    /// allocators to interleave can leave a bitmap whose checksum no longer
    /// matches the descriptor that names it.
    allocation_lock: Mutex<()>,
    /// Mount-root metadata must be available to the synchronous `root()`
    /// interface. It is loaded during mount and refreshed by `write_inode`.
    root_inode: IrqSafeSpinLock<Option<Inode>>,
    /// Set when this mount writes nothing: requested read-only, refused by
    /// the write gate ([`sb_state::rw_refusal`]), a dirty journal replayed
    /// into memory only, an error under a read-only error policy, or a
    /// remount read-only. Cleared only by a remount read-write that passes
    /// the gate again.
    read_only: core::sync::atomic::AtomicBool,
    /// The gate rules this mount was made under.
    profile: sb_state::GateProfile,
    /// Why the gate refused a read-write mount, if it did.
    refusal: Option<sb_state::Refusal>,
    /// `s_state` as the mount found it (Linux `s_mount_state`), restored
    /// when the filesystem is marked clean again.
    mount_state: u16,
    /// An error was recorded during this mount (`EXT4_ERROR_FS` then
    /// survives the clean unmount).
    errors_seen: core::sync::atomic::AtomicBool,
    /// The superblock says "not clean" because this mount wrote it so.
    dirty_marked: core::sync::atomic::AtomicBool,
    /// The journal, when the filesystem has one and it was loaded
    /// (`noload` leaves it `None`). Journaled writes run through it on a
    /// read-write mount (`jbd.rs`).
    pub(crate) jbd: Option<jbd::Jbd>,
    /// The superblock's `st_dev`, allocated at mount.
    pub dev: u64,
}

/// One filesystem block retained either directly from the unified folio cache
/// or, only when folio allocation is unavailable, in a bounded owned buffer.
/// Consumers parse through the same slice interface and never need to flatten
/// an inode-sized range.
pub(crate) enum BlockView {
    Folio(FolioSlice),
    Owned(Vec<u8>),
}

impl core::ops::Deref for BlockView {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Folio(view) => view,
            Self::Owned(bytes) => bytes,
        }
    }
}

#[derive(Copy, Clone)]
enum BitmapKind {
    Block,
    Inode,
}

/// Free-function indirect-pointer read used by the pre-construction
/// journal-replay path. Mirrors `Ext2Volume::read_indirect` but
/// borrows everything directly so the async future has no implicit
/// 'static bound from `Ext2Volume::<B>::...` qualification.
async fn read_indirect_static<B: BlockDevice>(
    device: &B,
    io: &VolumeIo,
    bs: usize,
    block_no: u32,
    index: u64,
) -> Result<u32, FsError> {
    if block_no == 0 {
        return Ok(0);
    }
    if index >= (bs / 4) as u64 {
        return Err(FsError::Io(narf_block::BlockError::InvalidRange));
    }
    let mut buf = vec![0u8; bs];
    read_byte_range_into_static(device, io, block_no as u64 * bs as u64, &mut buf).await?;
    let off = (index as usize) * 4;
    Ok(u32::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
    ]))
}

/// Read `dst.len()` device bytes starting at `byte_off` into `dst`, using one
/// exclusively-owned scratch buffer `scratch` of `scratch_bytes` (a multiple of
/// `lbs`). The whole range is contiguous on the device, so each submit reads as
/// many LBAs as fit in the scratch buffer (`blocks: n`) in a single round-trip
/// — the old code read one LBA per submit, so a large sequential read paid one
/// park→IRQ→wake per logical block (the dominant cost of mmap'ing big DSOs).
async fn device_read_into<B: BlockDevice>(
    device: &B,
    lbs: usize,
    scratch_bytes: usize,
    scratch: &Cap<DmaBuffer, Write>,
    byte_off: u64,
    dst: &mut [u8],
) -> Result<(), FsError> {
    let buf_blocks = (scratch_bytes / lbs).max(1);
    let mut cursor = 0usize;
    while cursor < dst.len() {
        let abs = byte_off + cursor as u64;
        let lba = abs / lbs as u64;
        let in_lba = (abs % lbs as u64) as usize;
        let remaining = dst.len() - cursor;
        // Blocks that cover [in_lba, in_lba+remaining), capped to the buffer.
        let need_blocks = (in_lba + remaining).div_ceil(lbs);
        let n_blocks = need_blocks.min(buf_blocks).max(1);
        let span = n_blocks * lbs; // bytes the device writes into the buffer
        let take = remaining.min(span - in_lba); // bytes to copy out this round

        let req = BlockRequest {
            op: BlockOp::Read,
            lba,
            blocks: n_blocks as u32,
            buffer: scratch
                .derive::<Read>()
                .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        let completion = device.submit(req).await;
        completion.result.map_err(FsError::Io)?;

        let buf =
            resolve_cap(scratch).ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
        // SAFETY: `scratch` is exclusively owned for this op; the device wrote
        // `span` (<= scratch_bytes) bytes from its start, so the slice is valid.
        let src = unsafe { core::slice::from_raw_parts(buf.as_ptr(), span) };
        dst[cursor..cursor + take].copy_from_slice(&src[in_lba..in_lba + take]);
        cursor += take;
    }
    Ok(())
}

/// Free-function variant of `Ext2Volume::read_byte_range_into`
/// usable from other free helpers.
async fn read_byte_range_into_static<B: BlockDevice>(
    device: &B,
    io: &VolumeIo,
    byte_off: u64,
    dst: &mut [u8],
) -> Result<(), FsError> {
    device_read_into(device, io.lbs, io.scratch_bytes, &io.pool[0], byte_off, dst).await
}

/// `EXT4_S_ERR_START` .. `EXT4_S_ERR_END`: `s_error_count` up to
/// `s_mount_opts`.
const ERR_START: usize = 0x194;
const ERR_END: usize = 0x200;

/// How the journal is loaded at mount.
#[derive(Copy, Clone)]
struct JournalMount {
    /// `sb_rdonly`: a read-only mount.
    read_only: bool,
    /// `bdev_read_only`: the device cannot be written.
    really_read_only: bool,
    /// `needs_recovery` as `ext4_fill_super` computed it before the load,
    /// cleared on a read-only device.
    needs_recovery: bool,
}

/// The JBD2 error as `ext4_fill_super` reports it.
fn journal_error(error: journal::JournalError) -> FsError {
    use journal::JournalError as J;
    match error {
        J::Invalid => FsError::InvalidData,
        J::BadChecksum => FsError::BadChecksum,
        J::Corrupted => FsError::Corrupted,
        J::Io => FsError::Io(narf_block::BlockError::IOError),
        J::NoMemory => FsError::OutOfMemory,
        J::FastCommit => FsError::Unsupported,
    }
}

/// Write `src` at device byte `byte_off` before the volume exists (mount
/// time, when `io.pool[0]` is the only buffer in use). Whole logical blocks
/// go out several per request; a partial one is read, merged and written.
async fn write_byte_range_static<B: BlockDevice>(
    device: &B,
    io: &VolumeIo,
    byte_off: u64,
    src: &[u8],
    fua: bool,
) -> Result<(), FsError> {
    let lbs = io.lbs;
    let per_request = (io.scratch_bytes / lbs).max(1);
    let scratch = &io.pool[0];
    let mut cursor = 0usize;
    while cursor < src.len() {
        let abs = byte_off + cursor as u64;
        let lba = abs / lbs as u64;
        let in_lba = (abs % lbs as u64) as usize;
        let (blocks, take) = if in_lba == 0 && src.len() - cursor >= lbs {
            let n = ((src.len() - cursor) / lbs).min(per_request);
            (n, n * lbs)
        } else {
            (1, (src.len() - cursor).min(lbs - in_lba))
        };
        let mut staged = vec![0u8; blocks * lbs];
        if take != blocks * lbs {
            device_read_into(
                device,
                lbs,
                io.scratch_bytes,
                scratch,
                lba * lbs as u64,
                &mut staged,
            )
            .await?;
        }
        staged[in_lba..in_lba + take].copy_from_slice(&src[cursor..cursor + take]);
        {
            let buf = resolve_cap(scratch)
                .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
            // SAFETY: mount time: nothing else uses `pool[0]`, and the
            // buffer holds `scratch_bytes >= blocks * lbs` bytes.
            let dst = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), staged.len()) };
            dst.copy_from_slice(&staged);
        }
        let req = BlockRequest {
            op: BlockOp::Write { fua },
            lba,
            blocks: blocks as u32,
            buffer: scratch
                .derive::<Read>()
                .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
            qos: QosHint::Latency,
            user_tag: 0,
        };
        device.submit(req).await.result.map_err(FsError::Io)?;
        cursor += take;
    }
    Ok(())
}

/// `ext4_commit_super` at mount time: the checksum, then the primary
/// superblock with FUA.
async fn commit_super_static<B: BlockDevice>(
    device: &B,
    io: &VolumeIo,
    sb: &Superblock,
    sb_bytes: &mut [u8],
) -> Result<(), FsError> {
    metadata_csum::write_superblock_checksum(sb, sb_bytes).ok_or(FsError::InvalidData)?;
    write_byte_range_static(device, io, 1024, sb_bytes, true).await
}

/// The journal inode's blocks, through the mount-time helpers.
struct MountJournalIo<'a, B: BlockDevice> {
    device: &'a B,
    io: &'a VolumeIo,
    sb: &'a Superblock,
    group_descs: &'a [GroupDesc],
    inode: Inode,
    bs: usize,
    total_len: u32,
    /// Whether a replayed block went to the filesystem.
    wrote_home: bool,
}

impl<B: BlockDevice + 'static> MountJournalIo<'_, B> {
    /// `ext4_journal_bmap`: a journal block that does not map is
    /// EFSCORRUPTED.
    async fn map(&self, block: u32) -> Result<u64, journal::JournalError> {
        if block >= self.total_len {
            return Err(journal::JournalError::Corrupted);
        }
        let physical = Ext2Volume::<B>::map_block_static(
            self.device,
            self.io,
            self.sb,
            self.group_descs,
            &self.inode,
            u64::from(block),
        )
        .await
        .map_err(|_| journal::JournalError::Corrupted)?;
        if physical == 0 {
            return Err(journal::JournalError::Corrupted);
        }
        Ok(physical)
    }
}

impl<B: BlockDevice + 'static> journal::JournalIo for MountJournalIo<'_, B> {
    fn read_log<'b>(&'b mut self, block: u32, buf: &'b mut [u8]) -> journal::IoFuture<'b> {
        alloc::boxed::Box::pin(async move {
            let physical = self.map(block).await?;
            read_byte_range_into_static(self.device, self.io, physical * self.bs as u64, buf)
                .await
                .map_err(|_| journal::JournalError::Io)
        })
    }

    fn write_home<'b>(&'b mut self, block: u64, data: &'b [u8]) -> journal::IoFuture<'b> {
        alloc::boxed::Box::pin(async move {
            self.wrote_home = true;
            write_byte_range_static(self.device, self.io, block * self.bs as u64, data, false)
                .await
                .map_err(|_| journal::JournalError::Io)
        })
    }

    fn write_log_fua<'b>(&'b mut self, block: u32, data: &'b [u8]) -> journal::IoFuture<'b> {
        alloc::boxed::Box::pin(async move {
            let physical = self.map(block).await?;
            write_byte_range_static(self.device, self.io, physical * self.bs as u64, data, true)
                .await
                .map_err(|_| journal::JournalError::Io)
        })
    }

    fn flush(&mut self) -> journal::IoFuture<'_> {
        alloc::boxed::Box::pin(async move {
            self.device
                .flush_result()
                .await
                .map_err(|_| journal::JournalError::Io)
        })
    }
}

/// A boxed future for the recursive block-tree walks (an `async fn` cannot
/// recurse directly).
pub(crate) type TreeFuture<'a, T> = core::pin::Pin<
    alloc::boxed::Box<dyn core::future::Future<Output = Result<T, FsError>> + Send + 'a>,
>;

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Mount an ext2 volume. Reads the superblock at byte offset
    /// 1024 (in 512-byte sectors that's LBA 2), validates the
    /// `0xEF53` magic, then loads the block group descriptor table.
    ///
    /// A device that reports [`BlockDevice::is_read_only`] is mounted as by
    /// [`Self::mount_read_only`].
    pub async fn mount(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        Self::mount_with(device, domain, false, false).await
    }

    /// Mount read-only (`MS_RDONLY`). Every later write is refused with
    /// [`FsError::ReadOnly`]. What the mount itself writes is what Linux
    /// writes on a read-only mount (`ext4_load_journal`,
    /// `ext4_mark_recovery_complete`): a journal that needs recovery is
    /// replayed to the device and marked empty, and the superblock's
    /// `RECOVER` cleared. On a device that cannot be written that recovery
    /// fails the mount with EROFS instead, and nothing is written at all.
    pub async fn mount_read_only(device: Arc<B>, domain: DomainId) -> Result<Arc<Self>, FsError> {
        Self::mount_with(device, domain, true, false).await
    }

    /// Mount with ext4's `ro` and `noload` (`norecovery`) options. With
    /// `noload` the journal is not loaded: a read-only mount then sees the
    /// filesystem as it is on disk, without the transactions still in the
    /// log, and a read-write mount of a filesystem that needs recovery is
    /// refused (`ext4_fill_super`, EINVAL).
    pub async fn mount_with_options(
        device: Arc<B>,
        domain: DomainId,
        read_only: bool,
        noload: bool,
    ) -> Result<Arc<Self>, FsError> {
        Self::mount_with(device, domain, read_only, noload).await
    }

    /// The superblock (its bytes and parse) and the group descriptors, each
    /// checked as `ext4_fill_super` checks them.
    async fn read_geometry(
        device: &B,
        io: &VolumeIo,
    ) -> Result<(Vec<u8>, Superblock, Vec<GroupDesc>), FsError> {
        // Read 1024 bytes starting at byte 1024 — the superblock.
        // For a 512-byte LBS this is two LBA reads (LBA 2 and LBA
        // 3); for a 1024-byte LBS it's one (LBA 1); for a 4096-byte
        // LBS the superblock sits inside LBA 0 at byte 1024.
        let mut sb_bytes = vec![0u8; 1024];
        Self::read_byte_range_into(device, io, 1024, &mut sb_bytes).await?;
        let superblock = Superblock::parse(&sb_bytes).ok_or(FsError::Unsupported)?;
        // Reject any volume that uses incompat features we don't
        // implement — refusing is safer than mis-decoding. Encrypted
        // and inline-data volumes hit this; ext2/3/4 with EXTENTS +
        // 64BIT + FLEX_BG + FILETYPE + RECOVER pass.
        if superblock.check_incompat_features().is_err() {
            return Err(FsError::Unsupported);
        }
        if !metadata_csum::verify_superblock(&superblock, &sb_bytes) {
            return Err(FsError::InvalidData);
        }
        // Block group descriptor table starts at the block after
        // the superblock. With a 1-KiB block volume that's block 2;
        // with a 2-KiB or 4-KiB block volume it's block 1. The
        // canonical formula:
        //
        //     bgdt_block = s_first_data_block + 1
        //
        // ext2 design paper, §"Block Groups". ext4 with 64BIT uses
        // 64-byte descriptors instead of 32 — see effective_desc_size.
        let bs = superblock.block_size() as u64;
        let group_count = superblock.block_group_count() as usize;
        let desc_size = superblock.effective_desc_size();
        let bgdt_size_bytes = (group_count * desc_size) as u64;
        let bgdt_block_offset = (superblock.first_data_block + 1) as u64 * bs;

        let mut bgdt_bytes = vec![0u8; bgdt_size_bytes as usize];
        Self::read_byte_range_into(device, io, bgdt_block_offset, &mut bgdt_bytes).await?;

        let mut group_descs = Vec::with_capacity(group_count);
        for i in 0..group_count {
            let off = i * desc_size;
            if !metadata_csum::verify_group_desc_checksum(
                &superblock,
                i as u32,
                &bgdt_bytes[off..off + desc_size],
            ) {
                return Err(FsError::InvalidData);
            }
            let gd = GroupDesc::parse_sized(&bgdt_bytes[off..off + desc_size], desc_size)
                .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
            group_descs.push(gd);
        }
        Ok((sb_bytes, superblock, group_descs))
    }

    async fn mount_with(
        device: Arc<B>,
        domain: DomainId,
        read_only_requested: bool,
        noload: bool,
    ) -> Result<Arc<Self>, FsError> {
        let read_only_requested = read_only_requested || device.is_read_only();
        let lbs = device.logical_block_size() as usize;
        if lbs == 0 || 1024 % lbs != 0 && lbs % 1024 != 0 {
            // The driver assumes the device's logical block size is
            // a power-of-two factor of 1024 (or vice-versa). 512,
            // 1024, 2048, 4096 all qualify.
            return Err(FsError::Unsupported);
        }
        // Scratch buffers hold one multi-block read each. Round the target up
        // to an `lbs` multiple and never smaller than one block.
        let scratch_bytes = {
            let n = SCRATCH_BUF_BYTES.div_ceil(lbs).max(1);
            n * lbs
        };
        let mut pool = Vec::with_capacity(SCRATCH_POOL_LEN);
        for _ in 0..SCRATCH_POOL_LEN {
            let buffer = alloc_coherent(scratch_bytes, domain)
                .map_err(|_| FsError::Io(narf_block::BlockError::IOError))?;
            pool.push(register_with_cap(buffer));
        }
        let io = VolumeIo {
            pool,
            scratch_waiters: BTreeMap::new(),
            next_scratch_waiter: 1,
            lbs,
            scratch_bytes,
        };

        // `io` drops on an error return, unregistering every pooled buffer.
        let (mut sb_bytes, mut superblock, mut group_descs) =
            Self::read_geometry(&*device, &io).await?;

        // ── ext4_load_journal ───────────────────────────────────
        //
        // `ext4_fill_super` loads the journal before it reads any inode but
        // the journal's own: recovery may rewrite any metadata block. A
        // journal that needs recovery is replayed to the device on a
        // read-only mount too; only a device that cannot be written refuses
        // it (EROFS), unless `noload` asks for the filesystem as it is on
        // disk.
        let really_read_only = device.is_read_only();
        let recover_bit = super::superblock::incompat::RECOVER;
        let needs_recovery = superblock.last_orphan != 0
            || superblock.feature_ro_compat & super::superblock::ro_compat::ORPHAN_PRESENT != 0
            || superblock.feature_incompat & recover_bit != 0;
        // Whether the JBD2 log has nothing to replay: then a stale RECOVER
        // bit is repaired by the read-write mount's superblock update below.
        let journal_clean;
        let mut jbd_state = None;
        if superblock.flavour() != ExtFlavour::Ext2 && superblock.has_journal() && !noload {
            let (rewrote, loaded) = Self::load_journal_at_mount(
                &*device,
                &io,
                &superblock,
                &group_descs,
                &mut sb_bytes,
                JournalMount {
                    read_only: read_only_requested,
                    really_read_only,
                    needs_recovery: needs_recovery && !really_read_only,
                },
            )
            .await?;
            if rewrote {
                // The replay may have rewritten the superblock and the
                // group descriptors.
                (_, superblock, group_descs) = Self::read_geometry(&*device, &io).await?;
            }
            jbd_state = Some(loaded);
            journal_clean = true;
        } else if noload && !read_only_requested && superblock.feature_incompat & recover_bit != 0 {
            // "required journal recovery suppressed and not mounted
            // read-only".
            return Err(FsError::InvalidData);
        } else {
            journal_clean = superblock.feature_incompat & recover_bit == 0;
        }
        // `ext4_fill_super`: no recovery to complete without a journal, or
        // on a device that cannot be written.
        let needs_recovery = needs_recovery && jbd_state.is_some() && !really_read_only;
        // The write gate. Nothing has been written yet, whatever it says.
        let profile = sb_state::GateProfile::current();
        let refusal = if read_only_requested {
            None
        } else {
            sb_state::rw_refusal(&superblock, journal_clean, profile)
        };
        if let Some(refusal) = refusal {
            sb_state::report_refusal(&superblock, refusal);
        }
        let read_only = read_only_requested || refusal.is_some();

        let block_size = superblock.block_size() as usize;
        let page_cache = Arc::new(PageCache::new());
        let volume = Arc::new_cyclic(|self_weak| Ext2Volume {
            device,
            superblock,
            group_descs,
            domain,
            self_weak: self_weak.clone(),
            io: IrqSafeSpinLock::new(io),
            page_cache: page_cache.clone(),
            bdev_mapping: BlockMapping::new(page_cache, 0),
            icache: IrqSafeSpinLock::new(BTreeMap::new()),
            orphans: IrqSafeSpinLock::new(Vec::new()),
            orphans_state: IrqSafeSpinLock::new(orphan::Orphans::default()),
            large_file: core::sync::atomic::AtomicBool::new(
                superblock.feature_ro_compat & super::superblock::ro_compat::LARGE_FILE != 0,
            ),
            incarnations: core::sync::atomic::AtomicU32::new(1),
            inode_update_lock: Mutex::new(()),
            allocation_lock: Mutex::new(()),
            root_inode: IrqSafeSpinLock::new(None),
            read_only: core::sync::atomic::AtomicBool::new(read_only),
            profile,
            refusal,
            mount_state: superblock.state,
            errors_seen: core::sync::atomic::AtomicBool::new(false),
            dirty_marked: core::sync::atomic::AtomicBool::new(false),
            jbd: jbd_state.map(|(journal, inode)| jbd::Jbd::new(journal, inode, block_size)),
            dev: narf_filesystem::inode_id::alloc_anon_dev(),
        });
        let root_inode = volume.read_inode(super::EXT2_ROOT_INO).await?;
        *volume.root_inode.lock() = Some(root_inode);
        // `ext4_init_orphan_info`: a bad orphan block fails the mount (EIO).
        // Before anything is written.
        volume.init_orphan_info().await?;
        // `ext4_setup_super`: mark the filesystem dirty (and repair a stale
        // RECOVER / ORPHAN_PRESENT the gate found clean) before anything
        // else is written. If that cannot be written, `ext4_fill_super`
        // falls back to read-only, and so does this.
        if !volume.is_read_only() {
            // `ext4_set_journal_csum_feature_set` fails the mount (a v1
            // journal superblock cannot carry the features).
            volume.journal_start().await?;
            if let Err(error) = volume.setup_super().await {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "ext4 {}: superblock update failed ({error:?}); mounting READ-ONLY",
                    sb_state::uuid_string(&volume.superblock)
                );
                volume
                    .read_only
                    .store(true, core::sync::atomic::Ordering::Release);
                if let Some(jbd) = volume.jbd.as_ref() {
                    jbd.set_active(false);
                }
            }
        }
        // `ext4_orphan_cleanup`: what a crash left on the orphan file or list
        // is finished now, on a read-only mount too when the device can be
        // written; then `ext4_mark_recovery_complete`.
        volume
            .finish_orphans_at_mount(needs_recovery, journal_clean)
            .await?;
        // Register the page cache with the central memory reclaimer so its
        // clean pages can be shed under pressure (shrinker). Done after the
        // owning Arc exists so a Weak can be held without keeping it alive.
        narf_filesystem::page_cache::register_for_reclaim(&volume.page_cache);
        Ok(volume)
    }

    /// `ext4_load_journal`, then the journal half of
    /// `ext4_mark_recovery_complete`, before anything else on the volume is
    /// read. Returns whether anything outside the journal was written (the
    /// caller then re-reads the superblock and descriptors).
    ///
    /// - The journal inode must be live and regular (`ext4_get_journal_inode`,
    ///   EFSCORRUPTED), and its superblock valid
    ///   (`journal_check_superblock`: EINVAL, EFSBADCRC).
    /// - `RECOVER` on a read-only mount of a device that cannot be written:
    ///   EROFS.
    /// - `RECOVER` clear: the log is wiped (`jbd2_journal_wipe`), and on a
    ///   writable device marked empty. `RECOVER` set: it is replayed
    ///   (`jbd2_journal_load`); any recovery error fails the mount.
    /// - The superblock's error fields are put back if the replay
    ///   overwrote them, and an error recorded in the journal
    ///   (`s_errno`) moves into the superblock's ERROR_FS
    ///   (`ext4_clear_journal_err`).
    /// - With `needs_recovery`, the replayed log is marked empty. Clearing
    ///   `RECOVER` and `ORPHAN_PRESENT` on a read-only mount waits for the
    ///   orphan cleanup (`orphan.rs`), as `ext4_mark_recovery_complete`
    ///   follows `ext4_orphan_cleanup`.
    async fn load_journal_at_mount(
        device: &B,
        io: &VolumeIo,
        sb: &Superblock,
        group_descs: &[GroupDesc],
        sb_bytes: &mut [u8],
        how: JournalMount,
    ) -> Result<(bool, (journal::Journal, Inode)), FsError> {
        use core::fmt::Write as _;
        let bs = sb.block_size() as usize;
        let inode_no = sb.journal_inum;
        if inode_no == 0 {
            // An external journal device (`ext4_open_dev_journal`).
            return Err(FsError::Unsupported);
        }
        // `ext4_get_journal_inode`.
        let zero = inode_no.checked_sub(1).ok_or(FsError::Corrupted)?;
        let gd = group_descs
            .get((zero / sb.inodes_per_group) as usize)
            .ok_or(FsError::Corrupted)?;
        let inode_size = sb.inode_size_bytes();
        let inode_off =
            gd.inode_table * bs as u64 + (zero % sb.inodes_per_group) as u64 * inode_size as u64;
        let mut inode_bytes = vec![0u8; inode_size];
        read_byte_range_into_static::<B>(device, io, inode_off, &mut inode_bytes).await?;
        if !metadata_csum::verify_inode_checksum(sb, inode_no, &inode_bytes) {
            return Err(FsError::BadChecksum);
        }
        let inode = Inode::parse(&inode_bytes).ok_or(FsError::Corrupted)?;
        if inode.links_count == 0 || inode.mode & 0xF000 != 0x8000 {
            return Err(FsError::Corrupted);
        }
        let total_len = u32::try_from(inode.size / bs as u64).unwrap_or(u32::MAX);
        let mut jio = MountJournalIo {
            device,
            io,
            sb,
            group_descs,
            inode,
            bs,
            total_len,
            wrote_home: false,
        };
        let mut first = vec![0u8; bs];
        journal::JournalIo::read_log(&mut jio, 0, &mut first)
            .await
            .map_err(journal_error)?;
        let mut journal =
            journal::Journal::load_superblock(&first, bs, total_len).map_err(journal_error)?;

        let recover = sb.feature_incompat & super::superblock::incompat::RECOVER != 0;
        if recover && how.read_only && how.really_read_only {
            let _ = writeln!(
                narf_console::Writer,
                "ext4 {}: write access unavailable, cannot proceed (try mounting with noload)",
                sb_state::uuid_string(sb)
            );
            return Err(FsError::ReadOnly);
        }
        let writable = !how.really_read_only;
        if !recover {
            journal
                .wipe(&mut jio, writable)
                .await
                .map_err(journal_error)?;
        }
        let saved_errors = sb_bytes[ERR_START..ERR_END].to_vec();
        let loaded = journal.load(&mut jio, writable).await;
        let mut wrote = jio.wrote_home;
        if wrote {
            Self::read_byte_range_into(device, io, 1024, sb_bytes).await?;
        }
        // `ext4_load_journal`: the replay must not lose errors recorded since
        // the transaction that last wrote the superblock.
        let mut changed = sb_bytes[ERR_START..ERR_END] != saved_errors[..];
        if changed {
            sb_bytes[ERR_START..ERR_END].copy_from_slice(&saved_errors);
        }
        let state = u16::from_le_bytes([sb_bytes[0x3a], sb_bytes[0x3b]]);
        let merged = state | (sb.state & super::superblock::EXT2_ERROR_FS);
        if merged != state {
            sb_bytes[0x3a..0x3c].copy_from_slice(&merged.to_le_bytes());
            changed = true;
        }
        let mut result = loaded.map(|_| ()).map_err(journal_error);
        if changed && writable {
            let committed = commit_super_static(device, io, sb, sb_bytes).await;
            wrote = true;
            if result.is_ok() {
                result = committed;
            }
        }
        if let Err(error) = result {
            let _ = writeln!(
                narf_console::Writer,
                "ext4 {}: error loading journal ({error:?})",
                sb_state::uuid_string(sb)
            );
            return Err(error);
        }

        // `ext4_clear_journal_err`.
        if journal.errno != 0 {
            let _ = writeln!(
                narf_console::Writer,
                "ext4 {}: Filesystem error recorded from previous mount: errno {}",
                sb_state::uuid_string(sb),
                -journal.errno
            );
            let state = u16::from_le_bytes([sb_bytes[0x3a], sb_bytes[0x3b]]);
            sb_bytes[0x3a..0x3c]
                .copy_from_slice(&(state | super::superblock::EXT2_ERROR_FS).to_le_bytes());
            if writable {
                commit_super_static(device, io, sb, sb_bytes).await?;
                wrote = true;
                let _ = writeln!(
                    narf_console::Writer,
                    "ext4 {}: Marked fs in need of filesystem check.",
                    sb_state::uuid_string(sb)
                );
                journal.clear_err(&mut jio).await;
            }
        }

        // The replayed log is empty (`jbd2_journal_flush`).
        if how.needs_recovery {
            journal.mark_empty(&mut jio).await;
        }
        Ok((wrote, (journal, jio.inode)))
    }

    /// Static block-map walk usable before the `Arc<Ext2Volume>`
    /// exists. Mirrors `map_block` but takes all state by reference.
    /// Only used during the journal-replay path at mount.
    async fn map_block_static(
        device: &B,
        io: &VolumeIo,
        sb: &Superblock,
        _group_descs: &[GroupDesc],
        inode: &Inode,
        logical: u64,
    ) -> Result<u64, FsError> {
        if sb.uses_extents() && inode.uses_extents() {
            // Mirror map_block_extents but read child blocks via
            // the static helper.
            use super::extent::{lookup_in_node, LookupOutcome};
            let mut node_buf = vec![0u8; 60];
            for (i, &b) in inode.block.iter().enumerate() {
                node_buf[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
            }
            let logical32 = if logical > u32::MAX as u64 {
                return Err(FsError::Io(narf_block::BlockError::InvalidRange));
            } else {
                logical as u32
            };
            let mut depth = 8u32;
            loop {
                match lookup_in_node(&node_buf, logical32) {
                    LookupOutcome::Mapped {
                        physical,
                        is_uninitialized,
                    } => {
                        if is_uninitialized {
                            return Ok(0);
                        }
                        return Ok(physical);
                    }
                    LookupOutcome::Hole => return Ok(0),
                    LookupOutcome::Corrupt => {
                        return Err(FsError::Io(narf_block::BlockError::IOError));
                    }
                    LookupOutcome::DeeperLookupRequired { child_block } => {
                        depth = depth
                            .checked_sub(1)
                            .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
                        let bs = sb.block_size() as usize;
                        let mut child = vec![0u8; bs];
                        read_byte_range_into_static::<B>(
                            device,
                            io,
                            child_block * bs as u64,
                            &mut child,
                        )
                        .await?;
                        node_buf = child;
                    }
                }
            }
        }
        // Legacy indirect-block walk.
        let bs = sb.block_size() as usize;
        let p = (bs / 4) as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;

        if logical < direct_max {
            return Ok(inode.block[logical as usize] as u64);
        }
        if logical < single_max {
            let idx = logical - direct_max;
            let l1 = inode.block[super::inode::SINGLE_IND_IDX];
            return Ok(read_indirect_static::<B>(device, io, bs, l1, idx).await? as u64);
        }
        if logical < double_max {
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let l2_block = inode.block[super::inode::DOUBLE_IND_IDX];
            let middle = read_indirect_static::<B>(device, io, bs, l2_block, l1).await?;
            return Ok(read_indirect_static::<B>(device, io, bs, middle, l0).await? as u64);
        }
        if logical < triple_max {
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let l3_block = inode.block[super::inode::TRIPLE_IND_IDX];
            let middle = read_indirect_static::<B>(device, io, bs, l3_block, l2).await?;
            let leaf = read_indirect_static::<B>(device, io, bs, middle, l1).await?;
            return Ok(read_indirect_static::<B>(device, io, bs, leaf, l0).await? as u64);
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// Filesystem block size in bytes.
    pub fn block_size(&self) -> usize {
        self.superblock.block_size() as usize
    }

    /// Number of 32-bit pointers per indirect block.
    pub fn pointers_per_block(&self) -> usize {
        self.block_size() / 4
    }

    /// Return a retained, zero-copy view of one filesystem block when it can
    /// be represented by the unified folio cache. The common ext-family
    /// block sizes (1/2/4 KiB) share an order-zero 4 KiB folio; callers can
    /// walk many blocks while keeping only the current folio alive.
    pub(crate) async fn read_block_folio(
        &self,
        block_no: u64,
    ) -> Result<Option<FolioSlice>, FsError> {
        let bs = self.block_size();
        if bs > PAGE_SIZE || PAGE_SIZE % bs != 0 {
            return Ok(None);
        }

        let blocks_per_page = PAGE_SIZE / bs;
        let page = block_no / blocks_per_page as u64;
        let in_page = (block_no % blocks_per_page as u64) as usize * bs;
        // Lookup, miss coalescing, and publish-unless-invalidated are the
        // cache's protocol; this only says how to read one device page.
        let filled = self
            .bdev_mapping
            .get_or_fill(page, |mut folio| async move {
                self.read_byte_range(page * PAGE_SIZE as u64, &mut folio[..])
                    .await?;
                Ok(folio)
            })
            .await;
        match filled {
            // A fill that raced a write of this page returns its private
            // pre-write bytes, a read that linearises before that write; the
            // cache never kept them.
            Ok(filled) => Ok(filled.folio().page_slice(in_page, bs)),
            // No frame for a folio: degrade to a bounded uncached read.
            Err(FsError::OutOfMemory) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Read one block as a retained view. This is the preferred metadata and
    /// directory iteration API: the normal path is zero-copy from the folio
    /// cache, while allocation pressure uses at most one filesystem block of
    /// fallible heap storage rather than allocating the whole inode.
    pub(crate) async fn read_block_view(&self, block_no: u64) -> Result<BlockView, FsError> {
        if let Some(view) = self.read_block_folio(block_no).await? {
            return Ok(BlockView::Folio(view));
        }

        let bs = self.block_size();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(bs)
            .map_err(|_| FsError::OutOfMemory)?;
        bytes.resize(bs, 0);
        self.read_byte_range(block_no * bs as u64, &mut bytes)
            .await?;
        Ok(BlockView::Owned(bytes))
    }

    /// Read one filesystem block (`block_size()` bytes) into `dst`.
    /// Normal reads copy from a retained folio; allocation pressure degrades
    /// to a direct bounded read rather than failing or allocating on the slab.
    pub async fn read_block(&self, block_no: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let bs = self.block_size();
        if dst.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        if let Some(view) = self.read_block_folio(block_no).await? {
            dst.copy_from_slice(&view);
            return Ok(());
        }
        self.read_byte_range(block_no * bs as u64, dst).await
    }

    /// Read `dst.len()` bytes starting at the device byte offset
    /// `byte_off`. Internally serialises on the volume's scratch
    /// buffer + cap.
    ///
    /// A filesystem block the running journal transaction holds is read from
    /// its copy there (`jbd.rs`): the device has the committed state.
    pub async fn read_byte_range(&self, byte_off: u64, dst: &mut [u8]) -> Result<(), FsError> {
        if !self.has_running_blocks() {
            return self.read_device(byte_off, dst).await;
        }
        let bs = self.block_size() as u64;
        let mut cursor = 0usize;
        while cursor < dst.len() {
            let abs = byte_off + cursor as u64;
            let block = abs / bs;
            let in_block = (abs % bs) as usize;
            let take = (dst.len() - cursor).min(bs as usize - in_block);
            match self.running_block(block) {
                Some(copy) => {
                    dst[cursor..cursor + take].copy_from_slice(&copy[in_block..in_block + take])
                }
                None => {
                    self.read_device(abs, &mut dst[cursor..cursor + take])
                        .await?
                }
            }
            cursor += take;
        }
        Ok(())
    }

    /// Read device bytes, past the running journal transaction.
    pub(crate) async fn read_device(&self, byte_off: u64, dst: &mut [u8]) -> Result<(), FsError> {
        let lbs = self.io.lock().lbs;
        Self::read_byte_range_with(&*self.device, lbs, &self.io, byte_off, dst).await
    }

    /// Write `src.len()` bytes starting at device byte offset
    /// `byte_off`. Inverse of `read_byte_range`. Note: this is a
    /// byte-granularity write — for sub-LBA spans we read-modify-
    /// write the enclosing sector.
    ///
    /// This is the metadata write: on a journaled read-write mount it goes
    /// into the running transaction (`jbd.rs`). File data goes through
    /// [`Self::write_data_range`].
    pub async fn write_byte_range(&self, byte_off: u64, src: &[u8]) -> Result<(), FsError> {
        if self.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        if self.journaling() {
            return self.journal_write(byte_off, src).await;
        }
        self.write_direct(byte_off, src, false).await
    }

    /// File data, and the zero-fill of a freshly allocated block: straight
    /// to the device, never through the journal (`data=ordered`). The block
    /// is unreferenced in the committed state, so the write is safe before
    /// the commit that references it.
    pub(crate) async fn write_data_range(&self, byte_off: u64, src: &[u8]) -> Result<(), FsError> {
        if self.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        self.write_direct(byte_off, src, false).await
    }

    /// Zero a block just allocated ([`Self::write_data_range`]).
    pub(crate) async fn zero_fresh_block(&self, block: u64) -> Result<(), FsError> {
        let bs = self.block_size();
        let zeros = vec![0u8; bs];
        self.write_data_range(block * bs as u64, &zeros).await
    }

    /// Drop the cached device pages `[byte_off, byte_off + len)` overlaps.
    pub(crate) fn invalidate_bytes(&self, byte_off: u64, len: usize) {
        let first_page = byte_off / PAGE_SIZE as u64;
        let end_page = (byte_off + len as u64).div_ceil(PAGE_SIZE as u64);
        self.bdev_mapping.invalidate(first_page, end_page);
    }

    /// Write device bytes, past the journal.
    pub(crate) async fn write_direct(
        &self,
        byte_off: u64,
        src: &[u8],
        fua: bool,
    ) -> Result<(), FsError> {
        let result = self.write_byte_range_device(byte_off, src, fua).await;
        // Direct block writes bypass the page cache, so once the device has
        // changed — even partially, on an error — drop the cached device
        // pages they overwrote, and void any fill of exactly those pages that
        // may have read the old bytes (Linux `invalidate_mapping_pages` on
        // the bdev mapping). Only those: a fill of any other page publishes
        // normally.
        let first_page = byte_off / PAGE_SIZE as u64;
        let end_page = (byte_off + src.len() as u64).div_ceil(PAGE_SIZE as u64);
        self.bdev_mapping.invalidate(first_page, end_page);
        result
    }

    /// [`Self::write_byte_range`] with Force Unit Access on every sector:
    /// for the superblock state changes that must be on media before any
    /// write that depends on them ([`sb_state`]).
    pub(crate) async fn write_byte_range_fua(
        &self,
        byte_off: u64,
        src: &[u8],
    ) -> Result<(), FsError> {
        if self.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        // The running transaction's copy of these blocks gets the same
        // bytes, so its checkpoint does not put the old ones back.
        self.patch_running(byte_off, src);
        let result = self.write_byte_range_device(byte_off, src, true).await;
        let first_page = byte_off / PAGE_SIZE as u64;
        let end_page = (byte_off + src.len() as u64).div_ceil(PAGE_SIZE as u64);
        self.bdev_mapping.invalidate(first_page, end_page);
        result
    }

    async fn write_byte_range_device(
        &self,
        byte_off: u64,
        src: &[u8],
        fua: bool,
    ) -> Result<(), FsError> {
        let (lbs, scratch_bytes) = {
            let io = self.io.lock();
            (io.lbs, io.scratch_bytes)
        };
        let mut cursor = 0usize;
        while cursor < src.len() {
            let abs = byte_off + cursor as u64;
            let lba = abs / lbs as u64;
            let in_lba = (abs % lbs as u64) as usize;
            // Whole sectors go out several per request: a filesystem block
            // (a journal commit block above all) is one write, as Linux
            // submits it, not one per sector a power cut could tear apart.
            let whole = if in_lba == 0 {
                ((src.len() - cursor) / lbs).min(scratch_bytes / lbs)
            } else {
                0
            };
            if whole > 0 {
                let span = whole * lbs;
                let guard = acquire_scratch(&self.io).await;
                {
                    let buf = resolve_cap(&guard.cap)
                        .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
                    // SAFETY: the guard owns this buffer until it drops, and it
                    // holds `scratch_bytes >= span` bytes.
                    let dst = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), span) };
                    dst.copy_from_slice(&src[cursor..cursor + span]);
                }
                let req = BlockRequest {
                    op: BlockOp::Write { fua },
                    lba,
                    blocks: whole as u32,
                    buffer: guard
                        .cap
                        .derive::<Read>()
                        .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                    qos: QosHint::Latency,
                    user_tag: 0,
                };
                self.device.submit(req).await.result.map_err(FsError::Io)?;
                cursor += span;
                continue;
            }
            let want = core::cmp::min(src.len() - cursor, lbs - in_lba);

            // If we're not writing a full sector, do a RMW. The read borrows
            // its own pool buffer and returns it before the write below.
            let mut sector = alloc::vec![0u8; lbs];
            if !(in_lba == 0 && want == lbs) {
                Self::read_byte_range_with(
                    &*self.device,
                    lbs,
                    &self.io,
                    lba * lbs as u64,
                    &mut sector,
                )
                .await?;
            }
            sector[in_lba..in_lba + want].copy_from_slice(&src[cursor..cursor + want]);

            // Borrow a private scratch buffer for the whole stage→submit→await
            // span: no other concurrent device op can touch it (it is ours
            // until the guard drops), so the staged bytes can't be clobbered.
            {
                let guard = acquire_scratch(&self.io).await;
                {
                    let buf = resolve_cap(&guard.cap)
                        .ok_or(FsError::Io(narf_block::BlockError::PermissionDenied))?;
                    // SAFETY: the guard gives us sole ownership of this buffer
                    // for the duration of the copy. Valid DMA-mapped bounds.
                    let dst = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr(), lbs) };
                    dst.copy_from_slice(&sector);
                }
                let req = BlockRequest {
                    op: BlockOp::Write { fua },
                    lba,
                    blocks: 1,
                    buffer: guard
                        .cap
                        .derive::<Read>()
                        .map_err(|_| FsError::Io(narf_block::BlockError::PermissionDenied))?,
                    qos: QosHint::Latency,
                    user_tag: 0,
                };
                let completion = self.device.submit(req).await;
                completion.result.map_err(FsError::Io)?;
            }

            cursor += want;
        }
        Ok(())
    }

    /// Write one filesystem block from `src`. Inverse of
    /// `read_block`. NOTE: this writes to the device only; it does
    /// not touch the journal-replay overrides cache (which is the
    /// read-side replay path; writes invalidate it).
    pub async fn write_block(&self, block_no: u64, src: &[u8]) -> Result<(), FsError> {
        let bs = self.block_size();
        if src.len() != bs {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        self.write_byte_range(block_no * bs as u64, src).await
    }

    /// Variant of `read_byte_range` usable before the `Ext2Volume`
    /// `Arc` exists — `mount()` calls this through a `&VolumeIo`
    /// directly.
    async fn read_byte_range_into(
        device: &B,
        io: &VolumeIo,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        device_read_into(device, io.lbs, io.scratch_bytes, &io.pool[0], byte_off, dst).await
    }

    /// Internal helper used by `read_byte_range`. Borrows ONE scratch
    /// buffer from the pool for the whole call (private to this op — no
    /// other concurrent device op can use it), then streams the range
    /// sector-by-sector into it. Holding a pool buffer across `await`s is
    /// fine: it is not a lock, masks no IRQs, and the block device — not a
    /// lock — serialises the actual requests, so concurrent reads on other
    /// CPUs simply use other pool buffers instead of clobbering this one.
    async fn read_byte_range_with(
        device: &B,
        lbs: usize,
        io_lock: &IrqSafeSpinLock<VolumeIo>,
        byte_off: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        let scratch_bytes = io_lock.lock().scratch_bytes;
        let guard = acquire_scratch(io_lock).await;
        device_read_into(device, lbs, scratch_bytes, &guard.cap, byte_off, dst).await
    }

    /// `(group, index)` for an inode number. Inode numbers are
    /// 1-based on disk; the math (per the design paper §"Inodes"):
    ///
    /// ```text
    /// group = (inode - 1) / s_inodes_per_group
    /// index = (inode - 1) % s_inodes_per_group
    /// ```
    pub fn inode_group_and_index(&self, inode_no: u32) -> Option<(u32, u32)> {
        if inode_no == 0 {
            return None;
        }
        let zero = inode_no - 1;
        let group = zero / self.superblock.inodes_per_group;
        let index = zero % self.superblock.inodes_per_group;
        if (group as usize) >= self.group_descs.len() {
            return None;
        }
        Some((group, index))
    }

    /// Write inode `inode_no` back to the inode table. Preserves
    /// the rev-1+ extra-fields tail by read-modify-writing the full
    /// `inode_size_bytes()` slot.
    pub async fn write_inode(&self, inode_no: u32, inode: &Inode) -> Result<(), FsError> {
        self.write_inode_slot(inode_no, inode, false).await
    }

    /// Initialize a newly allocated inode slot without inheriting stale ACL,
    /// xattr, deletion-time, or project-id fields from its former owner.
    pub async fn write_new_inode(&self, inode_no: u32, inode: &Inode) -> Result<(), FsError> {
        self.write_inode_slot(inode_no, inode, true).await
    }

    async fn write_inode_slot(
        &self,
        inode_no: u32,
        inode: &Inode,
        fresh: bool,
    ) -> Result<(), FsError> {
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let gd = &self.group_descs[group as usize];
        let inode_size = self.superblock.inode_size_bytes();
        let bs = self.block_size() as u64;
        let table_byte_off = gd.inode_table * bs;
        let inode_byte_off = table_byte_off + (index as u64) * inode_size as u64;
        let mut buf = vec![0u8; inode_size];
        if fresh {
            if inode_size >= 130 {
                let extra = self
                    .superblock
                    .want_extra_isize
                    .min((inode_size - 128) as u16);
                buf[128..130].copy_from_slice(&extra.to_le_bytes());
            }
        } else {
            self.read_byte_range(inode_byte_off, &mut buf).await?;
            // `ext4_inode_blocks`: with huge_file, `i_blocks` is 48 bits
            // (`l_i_blocks_high` at 116), and counts filesystem blocks under
            // `HUGE_FILE_FL`. NARF keeps 32 bits of sectors; rewriting such
            // an inode would leave the high half and the flag over a low
            // half counted another way.
            // LINUX-GAP: a file holding 2 TiB or more cannot be changed.
            let flags = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
            if self.superblock.feature_ro_compat & super::superblock::ro_compat::HUGE_FILE != 0
                && (u16::from_le_bytes([buf[116], buf[117]]) != 0
                    || flags & super::inode::I_FLAGS_HUGE_FILE != 0)
            {
                return Err(FsError::FileTooLarge);
            }
        }
        // `ext4_inode_blocks_set`: a count past 32 bits is EFBIG unless the
        // high half is used, which NARF does not do. Every real count is a
        // multiple of the sectors per block, so `u32::MAX` is only ever a
        // saturated sum.
        if inode.blocks == u32::MAX {
            return Err(FsError::FileTooLarge);
        }
        // `ext4_update_inode`: the first file past 2 GiB turns the volume's
        // RO_COMPAT_LARGE_FILE on, or an older kernel / e2fsck would take
        // `i_size_high` for ext2's `i_dir_acl`.
        if inode.size > 0x7fff_ffff && !self.large_file.load(core::sync::atomic::Ordering::Acquire)
        {
            self.set_large_file_feature().await?;
        }
        inode.encode_into(&mut buf);
        // A count that fits 32 bits is stored as Linux stores it: high half
        // zero, `HUGE_FILE_FL` clear (without huge_file Linux never reads
        // either).
        buf[116..118].fill(0);
        let flags = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]])
            & !super::inode::I_FLAGS_HUGE_FILE;
        buf[32..36].copy_from_slice(&flags.to_le_bytes());
        // Keep this self-contained so every inode metadata writer
        // (chmod/chown, truncate, directory links, and data writes) inherits
        // the correct checksum.
        let _ = metadata_csum::write_inode_checksum(&self.superblock, inode_no, &mut buf);
        self.write_byte_range(inode_byte_off, &buf).await?;
        if inode_no == super::EXT2_ROOT_INO {
            *self.root_inode.lock() = Some(*inode);
        }
        // The cached in-memory inode is the one every holder of this inode
        // reads; keep it identical to what was just written. The upgrade's
        // icache guard is released before the node is touched or dropped.
        let live = self.icache_get(inode_no);
        if let Some(node) = live {
            node.set_cached_inode(*inode);
        }
        Ok(())
    }

    /// The live node of `inode_no`, if any (no I/O).
    pub(crate) fn icache_get(&self, inode_no: u32) -> Option<Arc<super::node::Ext2Node<B>>> {
        self.icache.lock().get(&inode_no).and_then(Weak::upgrade)
    }

    /// Linux `iget_locked`: the one in-memory inode for `inode_no`, reading
    /// it from disk only when no node is live.
    pub async fn iget(&self, inode_no: u32) -> Result<Arc<super::node::Ext2Node<B>>, FsError> {
        if let Some(node) = self.icache_get(inode_no) {
            return Ok(node);
        }
        let inode = self.read_inode(inode_no).await?;
        Ok(self.iget_with(inode_no, inode))
    }

    /// [`Self::iget`] when the caller has just read or written `inode`. A
    /// node that became live meanwhile wins (its cached inode was refreshed
    /// by the write funnel), so two racing lookups still share one node.
    pub(crate) fn iget_with(&self, inode_no: u32, inode: Inode) -> Arc<super::node::Ext2Node<B>> {
        let volume = self
            .self_weak
            .upgrade()
            .expect("ext2 iget on a volume being dropped");
        let mut icache = self.icache.lock();
        if let Some(node) = icache.get(&inode_no).and_then(Weak::upgrade) {
            return node;
        }
        let node = super::node::Ext2Node::new_cached(volume, inode_no, inode);
        icache.insert(inode_no, Arc::downgrade(&node));
        node
    }

    /// A fresh page-cache mapping for a new in-memory inode of `inode_no`.
    /// The key carries a per-node incarnation in its high half, so the pages
    /// of a node that outlived its on-disk inode (freed while still open)
    /// can never be found through the node of a NEW inode that reuses the
    /// number, and vice versa.
    pub(crate) fn new_file_mapping(&self, inode_no: u32) -> narf_filesystem::FileMapping {
        let incarnation = self
            .incarnations
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        narf_filesystem::FileMapping::new(
            self.page_cache.clone(),
            0,
            (u64::from(incarnation) << 32) | u64::from(inode_no),
        )
    }

    /// Whether a live node holds an inode whose last link is gone (Linux's
    /// `s_remove_count`).
    pub(crate) fn has_open_unlinked(&self) -> bool {
        let nodes: Vec<_> = self
            .icache
            .lock()
            .values()
            .filter_map(|w| w.upgrade())
            .collect();
        nodes.iter().any(|node| node.is_orphaned())
    }

    /// Queue an orphaned inode whose last node just dropped.
    pub(crate) fn queue_orphan(&self, inode_no: u32) {
        self.orphans.lock().push(inode_no);
    }

    /// Pop one queued orphan. A function of its own so the queue's guard is
    /// gone before the caller's `.await` (a `while let` scrutinee would hold
    /// it through the loop body).
    fn pop_orphan(&self) -> Option<u32> {
        self.orphans.lock().pop()
    }

    /// Caller holds `inode_update_lock`. Failed releases stay queued so
    /// a later sync can retry rather than silently leaking their allocation.
    async fn drain_orphans_locked(&self) -> Result<(), FsError> {
        while let Some(inode_no) = self.pop_orphan() {
            if let Err(error) = self.release_orphan(inode_no).await {
                self.queue_orphan(inode_no);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Directory metadata is write-through. Complete deferred inode teardown
    /// before flushing the device, and preserve a failed flush as an error.
    pub(crate) async fn sync_metadata(&self) -> Result<(), FsError> {
        if self.is_read_only() {
            return Ok(());
        }
        let _update = self.inode_update_lock.lock().await;
        self.drain_orphans_locked().await?;
        // `ext4_sync_file` / `ext4_sync_fs` on a journaled filesystem:
        // commit the running transaction (its commit flushes everything
        // before it), then flush the device.
        self.journal_commit().await?;
        self.device.flush_result().await.map_err(FsError::Io)
    }

    /// `sync_filesystem`: dirty mmap pages belong to every live inode, not
    /// just the inode used to obtain the syncfs descriptor. Never keep the
    /// icache spinlock across I/O or nest the inode-update mutex.
    pub(crate) async fn sync_filesystem(&self) -> Result<(), FsError> {
        if self.is_read_only() {
            return Ok(());
        }
        let nodes: Vec<_> = self
            .icache
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for node in nodes {
            node.write_back_dirty(0, u64::MAX).await?;
        }
        self.sync_metadata().await
    }

    /// Take `inode_update_lock`, releasing any orphaned inodes first. Every
    /// whole-inode update goes through here, so an inode unlinked while open
    /// is released at the first update after its last reference drops.
    ///
    /// This is a jbd2 handle: an operation's metadata writes all land in one
    /// journal transaction. A transaction at its limit is committed here,
    /// before the operation starts (`add_transaction_credits`).
    pub(crate) async fn lock_inode_updates(&self) -> narf_lib::mutex::MutexGuard<'_, ()> {
        let guard = self.inode_update_lock.lock().await;
        // An unrelated mutation can proceed if orphan cleanup fails. Sync
        // instead calls the fallible drain directly and reports the failure.
        let _ = self.drain_orphans_locked().await;
        if self.journal_due() {
            // A failed commit aborts the journal and makes the volume
            // read-only; the operation then fails with EROFS.
            let _ = self.journal_commit().await;
        }
        guard
    }

    async fn release_orphan(&self, inode_no: u32) -> Result<(), FsError> {
        // A node made live again since (by inode number) carries the release
        // to its own drop.
        if let Some(node) = self.icache_get(inode_no) {
            node.mark_orphaned();
            return Ok(());
        }
        let mut inode = self.read_inode(inode_no).await?;
        // Linked again while open (`linkat` of an `O_TMPFILE`): it lives on,
        // off the orphan record.
        if inode.links_count != 0 {
            self.orphan_del(inode_no, &mut inode).await?;
            return self.write_inode(inode_no, &inode).await;
        }
        self.evict_inode(inode_no, &mut inode).await
    }

    /// `ext4_evict_inode` for an inode with no link and no reference left:
    /// its blocks, its orphan record, then the inode, with a directory's
    /// `bg_used_dirs_count` (`ext4_free_inode`). Caller holds
    /// `inode_update_lock`.
    pub(crate) async fn evict_inode(
        &self,
        inode_no: u32,
        inode: &mut Inode,
    ) -> Result<(), FsError> {
        self.truncate_inode(inode_no, inode).await?;
        self.orphan_del(inode_no, inode).await?;
        self.write_inode(inode_no, inode).await?;
        if inode.is_dir() {
            self.note_dir_count_delta(inode_no, -1).await?;
        }
        self.free_inode(inode_no).await
    }

    /// The inode's last link is gone (`links_count == 0`, not yet written).
    /// Free it now when nothing holds it; otherwise persist the link count
    /// and leave the inode, its size and its blocks to the last reference,
    /// as Linux's `iput_final` does. Caller holds `inode_update_lock`.
    ///
    /// A deferred release is recorded on disk first (`ext4_orphan_add`, in
    /// `ext4_unlink`), in the same journal transaction, so a crash before
    /// it is finished at the next mount (`orphan.rs`).
    pub(crate) async fn release_unlinked(
        &self,
        inode_no: u32,
        inode: &mut Inode,
    ) -> Result<(), FsError> {
        debug_assert_eq!(inode.links_count, 0);
        if let Some(node) = self.icache_get(inode_no) {
            self.orphan_add(inode_no, inode).await?;
            self.write_inode(inode_no, inode).await?;
            node.mark_orphaned();
            // Ours may have been the last reference; release it now if so.
            drop(node);
            while let Some(queued) = self.pop_orphan() {
                if let Err(error) = self.release_orphan(queued).await {
                    self.queue_orphan(queued);
                    return Err(error);
                }
            }
            return Ok(());
        }
        self.evict_inode(inode_no, inode).await
    }

    /// `evict`: forget the icache entry of `inode_no` if it still names the
    /// node at `node` (a racing `iget` may already have replaced it).
    pub(crate) fn icache_evict(&self, inode_no: u32, node: *const super::node::Ext2Node<B>) {
        let mut icache = self.icache.lock();
        if icache
            .get(&inode_no)
            .is_some_and(|weak| core::ptr::eq(weak.as_ptr(), node))
        {
            icache.remove(&inode_no);
        }
    }

    // ── Bitmap allocator (Linux fs/ext2/balloc.c + ialloc.c) ─────

    /// Scan a bitmap block for the first zero bit and set it. The
    /// `start_block` lives in `bm_block` (FS block number); on
    /// success returns the (zero-based) bit position. Bits 0..k are
    /// skipped if `skip_first` is set (used to reserve bit 0 of the
    /// inode bitmap on the first scanned block — Linux does this
    /// implicitly because inode 0 is unused and inode 1 may be
    /// reserved).
    async fn group_desc_bytes(&self, group: usize) -> Result<(u64, Vec<u8>), FsError> {
        if group >= self.group_descs.len() {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let desc_size = self.superblock.effective_desc_size();
        let table = (self.superblock.first_data_block + 1) as u64 * self.block_size() as u64;
        let offset = table + (group * desc_size) as u64;
        let mut bytes = vec![0u8; desc_size];
        self.read_byte_range(offset, &mut bytes).await?;
        if !metadata_csum::verify_group_desc_checksum(&self.superblock, group as u32, &bytes) {
            return Err(FsError::InvalidData);
        }
        Ok((offset, bytes))
    }

    fn bitmap_bytes(&self, kind: BitmapKind) -> usize {
        let bits = match kind {
            BitmapKind::Block => self.superblock.blocks_per_group,
            BitmapKind::Inode => self.superblock.inodes_per_group,
        };
        (bits as usize).div_ceil(8)
    }

    async fn verify_bitmap(
        &self,
        group: usize,
        kind: BitmapKind,
        bitmap: &[u8],
    ) -> Result<(), FsError> {
        let (_, desc) = self.group_desc_bytes(group).await?;
        let meaningful = self.bitmap_bytes(kind).min(bitmap.len());
        if !metadata_csum::verify_bitmap_checksum(
            &self.superblock,
            &desc,
            &bitmap[..meaningful],
            matches!(kind, BitmapKind::Inode),
        ) {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn update_group_desc(
        &self,
        group: usize,
        blocks: i64,
        inodes: i64,
        dirs: i64,
        bitmap: Option<(BitmapKind, &[u8])>,
        allocated_inode_index: Option<u32>,
        clear_flags: u16,
    ) -> Result<(), FsError> {
        let (offset, mut desc) = self.group_desc_bytes(group).await?;
        if clear_flags != 0 {
            use super::group_desc::BG_FLAGS_OFFSET as F;
            let flags = u16::from_le_bytes([desc[F], desc[F + 1]]) & !clear_flags;
            desc[F..F + 2].copy_from_slice(&flags.to_le_bytes());
        }
        for (lo_off, hi_off, delta) in
            [(12usize, 44usize, blocks), (14, 46, inodes), (16, 48, dirs)]
        {
            if delta == 0 {
                continue;
            }
            let lo = u16::from_le_bytes([desc[lo_off], desc[lo_off + 1]]) as i64;
            let has_hi = desc.len() >= hi_off + 2;
            let hi = if has_hi {
                u16::from_le_bytes([desc[hi_off], desc[hi_off + 1]]) as i64
            } else {
                0
            };
            let current = (hi << 16) | lo;
            // Historic ext2 fixtures and damaged-but-mountable volumes can
            // carry stale zero counters even when the bitmap is authoritative.
            // Preserve the existing scan-the-bitmap recovery policy and clamp
            // the accounting field instead of rejecting a valid allocation.
            let updated = current.saturating_add(delta).max(0) as u64;
            desc[lo_off..lo_off + 2].copy_from_slice(&(updated as u16).to_le_bytes());
            if has_hi {
                desc[hi_off..hi_off + 2].copy_from_slice(&((updated >> 16) as u16).to_le_bytes());
            }
        }
        if let Some(index) = allocated_inode_index {
            // ext4 uses bg_itable_unused to delimit the uninitialized tail of
            // each inode table.  Leaving this at its mkfs value after writing
            // a new inode makes Linux treat the allocated slot as deleted,
            // even when its bitmap bit and inode checksum are both valid.
            // Allocation may fill a hole below the current boundary, so this
            // field only ever shrinks; freeing an inode must not expand it.
            const ITABLE_UNUSED_LO: usize = 0x1c;
            const ITABLE_UNUSED_HI: usize = 0x32;
            let lo =
                u16::from_le_bytes([desc[ITABLE_UNUSED_LO], desc[ITABLE_UNUSED_LO + 1]]) as u32;
            let has_hi = desc.len() >= ITABLE_UNUSED_HI + 2;
            let hi = if has_hi {
                u16::from_le_bytes([desc[ITABLE_UNUSED_HI], desc[ITABLE_UNUSED_HI + 1]]) as u32
            } else {
                0
            };
            let current = (hi << 16) | lo;
            let remaining = self
                .superblock
                .inodes_per_group
                .saturating_sub(index.saturating_add(1));
            let updated = current.min(remaining);
            desc[ITABLE_UNUSED_LO..ITABLE_UNUSED_LO + 2]
                .copy_from_slice(&(updated as u16).to_le_bytes());
            if has_hi {
                desc[ITABLE_UNUSED_HI..ITABLE_UNUSED_HI + 2]
                    .copy_from_slice(&((updated >> 16) as u16).to_le_bytes());
            }
        }
        if let Some((kind, bytes)) = bitmap {
            let meaningful = self.bitmap_bytes(kind).min(bytes.len());
            if metadata_csum::write_bitmap_checksum(
                &self.superblock,
                &mut desc,
                &bytes[..meaningful],
                matches!(kind, BitmapKind::Inode),
            )
            .is_none()
                && self.superblock.has_metadata_csum()
            {
                return Err(FsError::InvalidData);
            }
        }
        if metadata_csum::write_group_desc_checksum(&self.superblock, group as u32, &mut desc)
            .is_none()
            && self.superblock.has_metadata_csum()
        {
            return Err(FsError::InvalidData);
        }
        self.write_byte_range(offset, &desc).await
    }

    /// Turn on RO_COMPAT_LARGE_FILE in the on-disk superblock (byte 100 of
    /// it), keeping its checksum valid. Under the allocation lock, the one
    /// the counter updates take for the same read-modify-write.
    async fn set_large_file_feature(&self) -> Result<(), FsError> {
        use core::sync::atomic::Ordering;
        let _allocation = self.allocation_lock.lock().await;
        if self.large_file.load(Ordering::Acquire) {
            return Ok(());
        }
        // The primary superblock is exactly 1024 bytes. Keep this fixed-size
        // read/modify/write scratch on the kernel-task stack: large-file
        // promotion can run while the machine is under writeback pressure,
        // and failing an otherwise unrelated heap allocation here must not
        // turn a recoverable filesystem error into a kernel OOM panic.
        let mut bytes = [0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        let ro_compat = u32::from_le_bytes(bytes[100..104].try_into().expect("four bytes"))
            | super::superblock::ro_compat::LARGE_FILE;
        bytes[100..104].copy_from_slice(&ro_compat.to_le_bytes());
        if metadata_csum::write_superblock_checksum(&self.superblock, &mut bytes).is_none() {
            return Err(FsError::InvalidData);
        }
        self.write_byte_range(1024, &bytes).await?;
        self.large_file.store(true, Ordering::Release);
        Ok(())
    }

    async fn update_superblock_counters(&self, blocks: i64, inodes: i64) -> Result<(), FsError> {
        if blocks == 0 && inodes == 0 {
            return Ok(());
        }
        // Allocation/free updates are themselves reached while process and
        // inode teardown is trying to relieve memory pressure. The on-disk
        // primary superblock has a fixed 1024-byte size, so a stack buffer
        // avoids depending on slab growth in the emergency reserve window.
        let mut bytes = [0u8; 1024];
        self.read_byte_range(1024, &mut bytes).await?;
        for (lo_off, hi_off, delta) in [(12usize, Some(344usize), blocks), (16, None, inodes)] {
            if delta == 0 {
                continue;
            }
            let lo = u32::from_le_bytes(
                bytes[lo_off..lo_off + 4]
                    .try_into()
                    .expect("superblock counter is four bytes"),
            ) as i64;
            let hi = hi_off.map_or(0, |off| {
                u32::from_le_bytes(
                    bytes[off..off + 4]
                        .try_into()
                        .expect("superblock high counter is four bytes"),
                ) as i64
            });
            let current = (hi << 32) | lo;
            let updated = current.saturating_add(delta).max(0) as u64;
            bytes[lo_off..lo_off + 4].copy_from_slice(&(updated as u32).to_le_bytes());
            if let Some(off) = hi_off {
                bytes[off..off + 4].copy_from_slice(&((updated >> 32) as u32).to_le_bytes());
            }
        }
        if metadata_csum::write_superblock_checksum(&self.superblock, &mut bytes).is_none() {
            return Err(FsError::InvalidData);
        }
        self.write_byte_range(1024, &bytes).await
    }

    /// The group's descriptor as it is on the device now (the mount-time
    /// `group_descs` snapshot does not follow free counts or flags).
    async fn current_group_desc(&self, group: usize) -> Result<GroupDesc, FsError> {
        let (_, bytes) = self.group_desc_bytes(group).await?;
        GroupDesc::parse_sized(&bytes, bytes.len()).ok_or(FsError::Corrupted)
    }

    /// `ext4_read_block_bitmap` of a `BLOCK_UNINIT` group: compute the
    /// bitmap (`ext4_init_block_bitmap`), check it against the free count
    /// the descriptor promises, write it, and clear the flag.
    async fn init_block_bitmap_on_disk(&self, group: usize, gd: &GroupDesc) -> Result<(), FsError> {
        let bitmap = uninit::init_block_bitmap(&self.superblock, group as u32, gd)
            .ok_or(FsError::Corrupted)?;
        let bits = uninit::blocks_in_group(&self.superblock, group as u32);
        if uninit::free_bits(&bitmap, bits) != gd.free_blocks_count {
            return Err(FsError::Corrupted);
        }
        self.write_block(gd.block_bitmap, &bitmap).await?;
        self.update_group_desc(
            group,
            0,
            0,
            0,
            Some((BitmapKind::Block, &bitmap)),
            None,
            super::group_desc::BG_BLOCK_UNINIT,
        )
        .await
    }

    /// Allocate one bit of `kind` in `group`, scanning from `start` and
    /// wrapping. The caller holds `allocation_lock`.
    ///
    /// - A group whose descriptor counts nothing free is skipped without
    ///   reading its bitmap (`ext4_mb_good_group`).
    /// - A lazily initialized group (`BLOCK_UNINIT` / `INODE_UNINIT`) is
    ///   used only when `allow_uninit`, the allocator's last pass: its
    ///   bitmap is computed ([`uninit`]), and the allocation writes it out
    ///   with the flag cleared. An inode allocated in a group whose block
    ///   bitmap is still uninitialized initializes that first, as
    ///   `__ext4_new_inode` does.
    /// - A bitmap whose checksum fails, or a computed one that disagrees
    ///   with the descriptor, quarantines the group: it is skipped.
    ///
    /// Writes go bitmap, then descriptor (with the bitmap's checksum), then
    /// superblock counters.
    async fn alloc_in_group(
        &self,
        group: usize,
        kind: BitmapKind,
        start: u32,
        allow_uninit: bool,
    ) -> Result<Option<u32>, FsError> {
        use super::group_desc::{BG_BLOCK_UNINIT, BG_INODE_UNINIT};
        let gd = self.current_group_desc(group).await?;
        let flags_valid = uninit::has_group_desc_csum(&self.superblock);
        let (uninit_flag, free, bits, bm_block) = match kind {
            BitmapKind::Block => (
                BG_BLOCK_UNINIT,
                gd.free_blocks_count,
                uninit::blocks_in_group(&self.superblock, group as u32),
                gd.block_bitmap,
            ),
            BitmapKind::Inode => (
                BG_INODE_UNINIT,
                gd.free_inodes_count,
                self.superblock.inodes_per_group,
                gd.inode_bitmap,
            ),
        };
        if free == 0 {
            return Ok(None);
        }
        let lazy = flags_valid && gd.flags & uninit_flag != 0;
        if lazy && !allow_uninit {
            return Ok(None);
        }
        let mut buf = if lazy {
            match kind {
                BitmapKind::Block => {
                    let Some(bitmap) =
                        uninit::init_block_bitmap(&self.superblock, group as u32, &gd)
                    else {
                        return Ok(None);
                    };
                    if uninit::free_bits(&bitmap, bits) != free {
                        return Ok(None);
                    }
                    bitmap
                }
                BitmapKind::Inode => uninit::init_inode_bitmap(&self.superblock),
            }
        } else {
            let mut buf = vec![0u8; self.block_size()];
            self.read_block(bm_block, &mut buf).await?;
            match self.verify_bitmap(group, kind, &buf).await {
                Ok(()) => {}
                // A large ext4 volume can still allocate safely from its other
                // groups. Quarantine this group rather than mutating metadata
                // whose checksum does not validate or failing the whole volume.
                Err(FsError::InvalidData) => return Ok(None),
                Err(error) => return Err(error),
            }
            buf
        };
        let max = bits.min(buf.len() as u32 * 8);
        let start = start.min(max);
        // A block freed in the running journal transaction is not reused
        // until that transaction commits (`jbd.rs`).
        let group_first = u64::from(self.superblock.first_data_block)
            + group as u64 * u64::from(self.superblock.blocks_per_group);
        let Some(bit) = (start..max).chain(0..start).find(|&bit| {
            buf[bit as usize / 8] & (1 << (bit % 8)) == 0
                && !(matches!(kind, BitmapKind::Block)
                    && self.block_held(group_first + u64::from(bit)))
        }) else {
            return Ok(None);
        };
        if matches!(kind, BitmapKind::Inode) && flags_valid && gd.flags & BG_BLOCK_UNINIT != 0 {
            self.init_block_bitmap_on_disk(group, &gd).await?;
        }
        buf[bit as usize / 8] |= 1 << (bit % 8);
        self.write_block(bm_block, &buf).await?;
        let (blocks, inodes) = match kind {
            BitmapKind::Block => (-1, 0),
            BitmapKind::Inode => (0, -1),
        };
        self.update_group_desc(
            group,
            blocks,
            inodes,
            0,
            Some((kind, &buf)),
            matches!(kind, BitmapKind::Inode).then_some(bit),
            if lazy { uninit_flag } else { 0 },
        )
        .await?;
        self.update_superblock_counters(blocks, inodes).await?;
        Ok(Some(bit))
    }

    /// Allocate one block, starting at `goal`'s group (`ext4_mb_new_blocks`
    /// with a goal): the goal group from the goal block, then every later
    /// group wrapping around; groups still lazily initialized only in a
    /// second pass, so initialized space is used first. The caller holds
    /// `allocation_lock`.
    async fn alloc_block_locked(&self, goal: Option<u64>) -> Result<u64, FsError> {
        if self.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        let groups = self.group_descs.len();
        let first = u64::from(self.superblock.first_data_block);
        let bpg = u64::from(self.superblock.blocks_per_group);
        let (goal_group, goal_bit) = match goal {
            Some(goal) if goal >= first && goal < self.superblock.total_blocks() => (
                ((goal - first) / bpg) as usize,
                ((goal - first) % bpg) as u32,
            ),
            _ => (0, 0),
        };
        for allow_uninit in [false, true] {
            for step in 0..groups {
                let group = (goal_group + step) % groups;
                let start = if step == 0 { goal_bit } else { 0 };
                if let Some(bit) = self
                    .alloc_in_group(group, BitmapKind::Block, start, allow_uninit)
                    .await?
                {
                    return Ok(
                        uninit::group_first_block(&self.superblock, group as u32) + u64::from(bit)
                    );
                }
            }
        }
        Err(FsError::NoSpace)
    }

    /// Clear bit `bit_index` in bitmap block `bm_block`.
    async fn free_in_bitmap_block(
        &self,
        group: usize,
        kind: BitmapKind,
        bm_block: u64,
        bit_index: u32,
    ) -> Result<(), FsError> {
        // Nothing was ever allocated in a lazily initialized group: freeing
        // there is Linux's "bit already cleared" (EFSCORRUPTED), and its
        // on-disk bitmap is not to be read.
        if uninit::has_group_desc_csum(&self.superblock) {
            let flag = match kind {
                BitmapKind::Block => super::group_desc::BG_BLOCK_UNINIT,
                BitmapKind::Inode => super::group_desc::BG_INODE_UNINIT,
            };
            if self.current_group_desc(group).await?.flags & flag != 0 {
                return Err(FsError::Corrupted);
            }
        }
        let bs = self.block_size();
        let mut buf = vec![0u8; bs];
        self.read_block(bm_block, &mut buf).await?;
        self.verify_bitmap(group, kind, &buf).await?;
        let byte = (bit_index / 8) as usize;
        let bit_in_byte = (bit_index % 8) as u8;
        if byte < buf.len() && buf[byte] & (1u8 << bit_in_byte) != 0 {
            buf[byte] &= !(1u8 << bit_in_byte);
            self.write_block(bm_block, &buf).await?;
            if matches!(kind, BitmapKind::Block) {
                let block = u64::from(self.superblock.first_data_block)
                    + group as u64 * u64::from(self.superblock.blocks_per_group)
                    + u64::from(bit_index);
                self.hold_blocks(block, 1);
            }
            let (blocks, inodes) = match kind {
                BitmapKind::Block => (1, 0),
                BitmapKind::Inode => (0, 1),
            };
            self.update_group_desc(group, blocks, inodes, 0, Some((kind, &buf)), None, 0)
                .await?;
            self.update_superblock_counters(blocks, inodes).await?;
        }
        Ok(())
    }

    /// Allocate a free block anywhere ([`Self::alloc_block_locked`] with no
    /// goal). Returns the absolute block number.
    pub async fn alloc_block(&self) -> Result<u64, FsError> {
        let _allocation = self.allocation_lock.lock().await;
        self.alloc_block_locked(None).await
    }

    /// Free block `block_no` (absolute 1-based).
    pub async fn free_block(&self, block_no: u64) -> Result<(), FsError> {
        let _allocation = self.allocation_lock.lock().await;
        let bpg = self.superblock.blocks_per_group as u64;
        let first_block = self.superblock.first_data_block as u64;
        if block_no < first_block {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let group = ((block_no - first_block) / bpg) as usize;
        let bit = ((block_no - first_block) % bpg) as u32;
        if group >= self.group_descs.len() {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let bm_block = self.group_descs[group].block_bitmap;
        self.free_in_bitmap_block(group, BitmapKind::Block, bm_block, bit)
            .await
    }

    /// FITRIM (`fstrim`) — the first discard caller (#1166).
    ///
    /// Scans the block bitmaps for free blocks inside the byte
    /// range `[start, start + len)`, coalesces each maximal
    /// contiguous free run, and issues one
    /// [`BlockDevice::discard`] per run that is at least `minlen`
    /// bytes long. Returns the bytes actually trimmed. Only whole
    /// filesystem blocks fully inside the range are candidates, so
    /// a partially-covered edge block is never trimmed.
    ///
    /// Linux refs: `include/uapi/linux/fs.h::FITRIM` /
    /// `struct fstrim_range` for the wire format (see
    /// [`super::fitrim`]); `ext4_trim_fs` for the scan-and-discard
    /// shape. Two deliberate divergences, both documented:
    /// - A device without [`BlockFeature::Discard`] fails with
    ///   [`FsError::Unsupported`] (Linux `EOPNOTSUPP` from
    ///   `blkdev_issue_discard`) instead of silently reporting
    ///   success — a no-op "trim" would tell callers blocks were
    ///   freed when they were not (#841).
    /// - The whole scan+discard holds `allocation_lock`, the same
    ///   lock that serializes `alloc_block`/`free_block` bitmap
    ///   updates. Without it a block freed by the scan could be
    ///   reallocated before its discard lands, and a live block
    ///   would be trimmed. A bitmap whose checksum does not verify
    ///   aborts the ioctl rather than trimming on untrusted bits.
    ///
    /// FITRIM writes no filesystem metadata, so it is allowed on a
    /// read-only volume. No `CAP_SYS_ADMIN` gate is enforced here:
    /// the ioctl seam carries no credential (see the PR body).
    pub async fn fitrim(&self, start: u64, len: u64, minlen: u64) -> Result<u64, FsError> {
        if !self.device.supports(BlockFeature::Discard) {
            return Err(FsError::Unsupported);
        }
        if self.journaling() {
            // A block freed in the running transaction is still the old
            // file's until the commit: discarding it first would lose it.
            let _update = self.inode_update_lock.lock().await;
            self.journal_commit().await?;
        }
        if len == 0 {
            return Err(FsError::InvalidData);
        }
        let bs = self.block_size() as u64;
        let fs_bytes = self.superblock.total_blocks() * bs;
        if start >= fs_bytes {
            return Err(FsError::InvalidData);
        }
        let end = start.saturating_add(len).min(fs_bytes);
        // Whole blocks fully inside [start, end) only.
        let first = start.div_ceil(bs);
        let last_excl = end / bs;
        if last_excl <= first {
            return Ok(0);
        }
        let min_run = minlen.div_ceil(bs).max(1);
        let lbs = u64::from(self.device.logical_block_size());
        let mut trimmed: u64 = 0;
        let _allocation = self.allocation_lock.lock().await;
        let bpg = self.superblock.blocks_per_group as u64;
        let first_block = self.superblock.first_data_block as u64;
        for (gi, gd) in self.group_descs.iter().enumerate() {
            let group_first = first_block + gi as u64 * bpg;
            let group_last = (group_first + bpg).min(self.superblock.total_blocks());
            let bits_in_group = group_last.saturating_sub(group_first);
            let scan_first = first.max(group_first);
            let scan_last = last_excl.min(group_last);
            if scan_last <= scan_first {
                continue;
            }
            let mut bitmap = vec![0u8; bs as usize];
            self.read_block(gd.block_bitmap, &mut bitmap).await?;
            self.verify_bitmap(gi, BitmapKind::Block, &bitmap).await?;
            let bit_is_free = |block: u64| -> bool {
                let bit = (block - group_first) as usize;
                bit < bits_in_group as usize
                    && bit / 8 < bitmap.len()
                    && (bitmap[bit / 8] >> (bit % 8)) & 1 == 0
            };
            let mut run_start: Option<u64> = None;
            // One past the scan end acts as a sentinel that flushes
            // a run ending exactly at the range edge.
            for block in scan_first..=scan_last {
                let free = block < scan_last && bit_is_free(block) && !self.block_held(block);
                match (run_start, free) {
                    (None, true) => run_start = Some(block),
                    (Some(run), false) => {
                        let run_len = block - run;
                        run_start = None;
                        if run_len >= min_run {
                            trimmed += self.discard_run(run, run_len, bs, lbs).await;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(trimmed)
    }

    /// Discard one free run of `run_len` filesystem blocks starting
    /// at `run_start`. Returns the trimmed bytes (0 when the run
    /// cannot be expressed in whole device blocks — a filesystem
    /// block smaller than one device block — which is skipped
    /// rather than trimmed partially).
    async fn discard_run(&self, run_start: u64, run_len: u64, bs: u64, lbs: u64) -> u64 {
        if bs < lbs {
            return 0;
        }
        let lba_start = run_start * (bs / lbs);
        let lba_blocks = run_len * (bs / lbs);
        self.device
            .discard(LbaRange {
                start: lba_start,
                blocks: lba_blocks,
            })
            .await;
        run_len * bs
    }

    /// Allocate a free inode. Returns the 1-based inode number. Groups in
    /// order, skipping the reserved inodes of group 0 (`EXT4_FIRST_INO`);
    /// lazily initialized groups only in a second pass.
    ///
    /// LINUX-GAP: no Orlov spreading of new directories across groups
    /// (`find_group_orlov`).
    pub async fn alloc_inode(&self) -> Result<u32, FsError> {
        // EROFS before ENOSPC, as the VFS refuses a read-only mount before
        // the filesystem looks for space.
        if self.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        let _allocation = self.allocation_lock.lock().await;
        let ipg = self.superblock.inodes_per_group;
        let first_reserved = self.superblock.first_ino();
        for allow_uninit in [false, true] {
            for group in 0..self.group_descs.len() {
                let skip = if group == 0 {
                    first_reserved.saturating_sub(1)
                } else {
                    0
                };
                if let Some(bit) = self
                    .alloc_in_group(group, BitmapKind::Inode, skip, allow_uninit)
                    .await?
                {
                    // The wrap-around scan must not hand out a reserved inode.
                    if group == 0 && bit < skip {
                        return Err(FsError::Corrupted);
                    }
                    return Ok((group as u32) * ipg + bit + 1);
                }
            }
        }
        Err(FsError::NoSpace)
    }

    /// Free inode `inode_no` (1-based).
    pub async fn free_inode(&self, inode_no: u32) -> Result<(), FsError> {
        if inode_no == 0 {
            return Ok(());
        }
        // `ext4_evict_inode` -> `ext4_xattr_delete_inode`: the attribute
        // block goes with the inode (freed, or unshared by one reference).
        // Before the allocation lock — releasing frees a block, which takes
        // it too.
        self.xattr_release_on_free(inode_no).await?;
        self.clear_inode_for_free(inode_no).await?;
        self.release_inode_allocation(inode_no).await
    }

    /// Roll back an inode-bit allocation that failed before a valid inode was
    /// published.  Such a slot can carry arbitrary old bytes and therefore
    /// cannot be fed through xattr teardown or checksum validation first.
    pub(crate) async fn abort_inode_allocation(&self, inode_no: u32) -> Result<(), FsError> {
        if inode_no == 0 {
            return Ok(());
        }
        self.clear_inode_for_free(inode_no).await?;
        self.release_inode_allocation(inode_no).await
    }

    /// Replace an inode slot with a checksummed deleted record before making
    /// its bitmap bit reusable.  Clearing the bit alone leaves a live-looking
    /// inode with zero `i_dtime`, which e2fsck reports as filesystem damage.
    async fn clear_inode_for_free(&self, inode_no: u32) -> Result<(), FsError> {
        let deleted = Inode::deleted(Self::now_secs());
        self.write_new_inode(inode_no, &deleted).await
    }

    async fn release_inode_allocation(&self, inode_no: u32) -> Result<(), FsError> {
        // The number is about to become reusable: a node still held for the
        // freed inode must not be what a later `iget` of a NEW inode with the
        // same number returns. Unhash it (Linux `remove_inode_hash`).
        let unhashed = self.icache.lock().remove(&inode_no);
        drop(unhashed);
        let _allocation = self.allocation_lock.lock().await;
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let bm_block = self.group_descs[group as usize].inode_bitmap;
        self.free_in_bitmap_block(group as usize, BitmapKind::Inode, bm_block, index)
            .await
    }

    /// Keep `bg_used_dirs_count` synchronized with directory inode creation
    /// and removal, including its group-descriptor checksum.
    pub async fn note_dir_count_delta(&self, inode_no: u32, delta: i64) -> Result<(), FsError> {
        let _allocation = self.allocation_lock.lock().await;
        let (group, _) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        self.update_group_desc(group as usize, 0, 0, delta, None, None, 0)
            .await
    }

    /// Map a logical block index to a physical block, allocating
    /// a fresh block (and intermediate indirect blocks) when the
    /// slot is currently a hole. The inode is mutated in place;
    /// caller persists via `write_inode`.
    ///
    /// Only the legacy (non-extents) path is supported on the write
    /// side — ext4 extents trees stay read-only for now.
    pub async fn map_block_alloc(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        logical: u64,
    ) -> Result<u64, FsError> {
        if self.superblock.uses_extents() && inode.uses_extents() {
            // `ext4_ext_map_blocks(EXT4_GET_BLOCKS_CREATE)` — see
            // `extent_write`. This used to answer `Unsupported` (-EINVAL at
            // the syscall) for any block not already mapped, so no
            // Linux-created ext4 file could grow.
            return self.extent_map_alloc(inode_no, inode, logical).await;
        }
        let p = self.pointers_per_block() as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;
        let bs = self.block_size();
        let sectors_per_block = (bs / 512) as u32;
        if logical < direct_max {
            let slot = &mut inode.block[logical as usize];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                inode.blocks = inode.blocks.saturating_add(sectors_per_block);
                self.zero_fresh_block(b as u64).await?;
            }
            return Ok(*slot as u64);
        }
        if logical < single_max {
            let mut allocated = 0u32;
            let slot = &mut inode.block[super::inode::SINGLE_IND_IDX];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                allocated += 1;
                self.zero_fresh_block(b as u64).await?;
            }
            let ind = *slot;
            let idx = logical - direct_max;
            let (block, made) = self.alloc_indirect_slot(ind as u64, idx).await?;
            allocated += made as u32;
            inode.blocks = inode
                .blocks
                .saturating_add(allocated.saturating_mul(sectors_per_block));
            return Ok(block);
        }
        if logical < double_max {
            let mut allocated = 0u32;
            let slot = &mut inode.block[super::inode::DOUBLE_IND_IDX];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                allocated += 1;
                self.zero_fresh_block(b as u64).await?;
            }
            let dbl = *slot;
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let (mid, made_mid) = self.alloc_indirect_slot(dbl as u64, l1).await?;
            let (block, made_block) = self.alloc_indirect_slot(mid, l0).await?;
            allocated += made_mid as u32 + made_block as u32;
            inode.blocks = inode
                .blocks
                .saturating_add(allocated.saturating_mul(sectors_per_block));
            return Ok(block);
        }
        if logical < triple_max {
            let mut allocated = 0u32;
            let slot = &mut inode.block[super::inode::TRIPLE_IND_IDX];
            if *slot == 0 {
                let b = self.alloc_block().await? as u32;
                *slot = b;
                allocated += 1;
                self.zero_fresh_block(b as u64).await?;
            }
            let tri = *slot;
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let (mid, made_mid) = self.alloc_indirect_slot(tri as u64, l2).await?;
            let (leaf, made_leaf) = self.alloc_indirect_slot(mid, l1).await?;
            let (block, made_block) = self.alloc_indirect_slot(leaf, l0).await?;
            allocated += made_mid as u32 + made_leaf as u32 + made_block as u32;
            inode.blocks = inode
                .blocks
                .saturating_add(allocated.saturating_mul(sectors_per_block));
            return Ok(block);
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// Read pointer `idx` from indirect block `ind_block`. If zero,
    /// allocate a fresh data block, write the pointer back, and
    /// return the new block number.
    async fn alloc_indirect_slot(&self, ind_block: u64, idx: u64) -> Result<(u64, bool), FsError> {
        let bs = self.block_size();
        let p = self.pointers_per_block() as u64;
        if idx >= p {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let mut buf = vec![0u8; bs];
        self.read_block(ind_block, &mut buf).await?;
        let off = (idx as usize) * 4;
        let cur = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
        if cur != 0 {
            return Ok((cur as u64, false));
        }
        let new = self.alloc_block().await? as u32;
        buf[off..off + 4].copy_from_slice(&new.to_le_bytes());
        // Zero the new block before the pointer to it can commit.
        self.zero_fresh_block(new as u64).await?;
        self.write_block(ind_block, &buf).await?;
        Ok((new as u64, true))
    }

    /// Free every block an inode's map owns (an extent tree, or direct and
    /// indirect blocks) and leave an empty map, `i_size` 0. The inode is
    /// written with the empty map before any block is freed
    /// ([`free_list`]); the caller writes it again with its other changes.
    pub async fn truncate_inode(&self, inode_no: u32, inode: &mut Inode) -> Result<(), FsError> {
        // A fast symlink's `i_block` is the link text, not block pointers:
        // walking it frees whatever blocks the text bytes happen to name
        // (or fails with EIO when they are out of range, which made
        // `unlink` of Firefox's `lock -> IP:+PID` profile symlink fail).
        // Linux never truncates one (`ext4_can_truncate`).
        if inode.is_fast_symlink(self.block_size() as u32) {
            return Ok(());
        }
        let mut deferred = free_list::FreeList::default();
        let freed = if self.superblock.uses_extents() && inode.uses_extents() {
            // `ext4_ext_remove_space` over the whole file.
            self.extent_free_all(inode, &mut deferred).await?
        } else {
            self.blockmap_free_range(inode, 0, u64::MAX, &mut deferred)
                .await?
        };
        inode.size = 0;
        // What the file still owns outside its map (an external xattr
        // block) stays counted.
        inode.blocks = inode.blocks.saturating_sub(freed);
        self.release_deferred(inode_no, inode, deferred).await
    }

    /// `ext4_truncate` for a shrink to a nonzero size: free every block
    /// mapped at logical block `first` or beyond (`first` is the first block
    /// wholly past the new EOF), with any tree block left mapping nothing.
    /// `i_blocks` drops by what was released; `i_size` and the inode write
    /// are the caller's.
    pub(crate) async fn truncate_inode_from(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u64,
    ) -> Result<(), FsError> {
        self.free_block_range(inode_no, inode, first, u64::MAX)
            .await
    }

    /// Release every block mapped at logical `first..end` and any tree block
    /// left mapping nothing (`ext4_ext_remove_space` / `ext4_ind_remove_space`):
    /// the block-freeing half of truncate and of `FALLOC_FL_PUNCH_HOLE`.
    /// `i_blocks` drops by what was released. The trimmed nodes, then the
    /// inode, are written before any block is freed ([`free_list`]); the
    /// caller writes the inode again with its other changes.
    pub(crate) async fn free_block_range(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u64,
        end: u64,
    ) -> Result<(), FsError> {
        if inode.is_fast_symlink(self.block_size() as u32) || end <= first {
            return Ok(());
        }
        let mut deferred = free_list::FreeList::default();
        let freed = if self.superblock.uses_extents() && inode.uses_extents() {
            // Logical block numbers are 32-bit in an extent tree; nothing is
            // mapped at or past 2^32.
            match u32::try_from(first) {
                Ok(first) => {
                    self.extent_free_range(inode_no, inode, first, end, &mut deferred)
                        .await?
                }
                Err(_) => 0,
            }
        } else {
            self.blockmap_free_range(inode, first, end, &mut deferred)
                .await?
        };
        inode.blocks = inode.blocks.saturating_sub(freed);
        self.release_deferred(inode_no, inode, deferred).await
    }

    /// `ext4_alloc_file_blocks` over logical blocks `first..end`: every hole
    /// becomes an unwritten extent. Extent-mapped inodes only — Linux's
    /// `ext4_do_fallocate` refuses a block-mapped inode with -EOPNOTSUPP,
    /// and so does this (`Unsupported`). A failure part-way (ENOSPC) leaves
    /// what was already allocated in place, as Linux does; `inode` reflects
    /// it either way, and the caller writes it.
    pub(crate) async fn preallocate(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u64,
        end: u64,
    ) -> Result<(), FsError> {
        if !(self.superblock.uses_extents() && inode.uses_extents()) {
            return Err(FsError::Unsupported);
        }
        for logical in first..end {
            self.extent_prealloc(inode_no, inode, logical).await?;
        }
        Ok(())
    }

    /// `s_maxbytes` (`ext4_max_size` without HUGE_FILE): `i_blocks` counts
    /// 512-byte sectors in 32 bits, which bounds a file at 2^32 - 1 sectors,
    /// rounded down to whole blocks — 2 TiB. Extent and block-map
    /// addressing both reach further, so this is the limit.
    ///
    /// LINUX-GAP: with HUGE_FILE Linux widens `i_blocks` with
    /// `l_i_blocks_hi` (and `EXT4_HUGE_FILE_FL` units) and allows 16 TiB at
    /// 4 KiB blocks; this driver keeps the 32-bit `i_blocks`.
    pub(crate) fn max_file_size(&self) -> u64 {
        let blkbits = self.block_size().trailing_zeros();
        ((u64::from(u32::MAX)) >> (blkbits - 9)) << blkbits
    }

    /// Whether `inode` maps its data through an extent tree — the inodes
    /// Linux's `ext4_fallocate` modes other than punch hole require.
    pub(crate) fn extent_mapped(&self, inode: &Inode) -> bool {
        self.superblock.uses_extents() && inode.uses_extents()
    }

    /// Turn every written extent at logical `first..end` unwritten
    /// (`EXT4_GET_BLOCKS_CONVERT_UNWRITTEN`): the blocks stay allocated and
    /// read back as zeros. Extent-mapped inodes only.
    pub(crate) async fn convert_to_unwritten(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u64,
        end: u64,
    ) -> Result<(), FsError> {
        if !self.extent_mapped(inode) {
            return Err(FsError::Unsupported);
        }
        match u32::try_from(first) {
            Ok(first) => {
                self.extent_convert_to_unwritten(inode_no, inode, first, end)
                    .await
            }
            Err(_) => Ok(()),
        }
    }

    /// Split the extent mapping both `at - 1` and `at` so `at` starts one
    /// (`ext4_split_extent_at`). Extent-mapped inodes only.
    pub(crate) async fn split_extent_at(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        at: u64,
    ) -> Result<(), FsError> {
        if !self.extent_mapped(inode) {
            return Err(FsError::Unsupported);
        }
        let at = u32::try_from(at).map_err(|_| FsError::InvalidData)?;
        self.extent_split_at(inode_no, inode, at).await
    }

    /// Move every extent at logical `from` or beyond by `delta` blocks
    /// (`ext4_ext_shift_extents`). Extent-mapped inodes only.
    pub(crate) async fn shift_extents(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        from: u64,
        delta: i64,
    ) -> Result<(), FsError> {
        if !self.extent_mapped(inode) {
            return Err(FsError::Unsupported);
        }
        let from = u32::try_from(from).map_err(|_| FsError::InvalidData)?;
        self.extent_shift(inode_no, inode, from, delta).await
    }

    /// The block-map half of [`Self::free_block_range`]
    /// (`ext4_ind_remove_space`). Returns the 512-byte sectors released.
    async fn blockmap_free_range(
        &self,
        inode: &mut Inode,
        first: u64,
        end: u64,
        deferred: &mut free_list::FreeList,
    ) -> Result<u32, FsError> {
        use super::inode::{DOUBLE_IND_IDX, N_DIRECT, SINGLE_IND_IDX, TRIPLE_IND_IDX};
        let spb = (self.block_size() / 512) as u32;
        let p = self.pointers_per_block() as u64;
        let mut freed = 0u32;
        let direct_end = end.min(N_DIRECT as u64);
        for slot in first.min(N_DIRECT as u64)..direct_end {
            let slot = slot as usize;
            if inode.block[slot] != 0 {
                deferred.push(u64::from(inode.block[slot]));
                inode.block[slot] = 0;
                freed = freed.saturating_add(spb);
            }
        }
        // Each indirect tree maps `span` logical blocks starting at `base`.
        let mut base = N_DIRECT as u64;
        let mut span = p;
        for (slot, level) in [
            (SINGLE_IND_IDX, 1u32),
            (DOUBLE_IND_IDX, 2),
            (TRIPLE_IND_IDX, 3),
        ] {
            let root = u64::from(inode.block[slot]);
            let tree_end = base.saturating_add(span);
            if root != 0 && first < tree_end && end > base {
                let (empty, sub) = self
                    .blockmap_free_branch(
                        root,
                        level,
                        first.saturating_sub(base),
                        end.saturating_sub(base),
                        deferred,
                    )
                    .await?;
                freed = freed.saturating_add(sub);
                if empty {
                    deferred.push(root);
                    inode.block[slot] = 0;
                    freed = freed.saturating_add(spb);
                }
            }
            base = tree_end;
            span = span.saturating_mul(p);
        }
        Ok(freed)
    }

    /// Free the entries of the `level`-deep indirect block `block` that map
    /// relative logical blocks `start..end`. Returns whether the block now
    /// maps nothing (the caller frees it) and the sectors released below it;
    /// a block that keeps entries is written back.
    fn blockmap_free_branch<'a>(
        &'a self,
        block: u64,
        level: u32,
        start: u64,
        end: u64,
        deferred: &'a mut free_list::FreeList,
    ) -> TreeFuture<'a, (bool, u32)> {
        alloc::boxed::Box::pin(async move {
            let spb = (self.block_size() / 512) as u32;
            let p = self.pointers_per_block() as u64;
            let child_span = p.saturating_pow(level - 1);
            let mut buf = vec![0u8; self.block_size()];
            self.read_block(block, &mut buf).await?;
            let mut freed = 0u32;
            let mut changed = false;
            let mut live = false;
            for j in 0..p {
                let off = j as usize * 4;
                let ptr = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                if ptr == 0 {
                    continue;
                }
                let child_first = j.saturating_mul(child_span);
                let child_end = child_first.saturating_add(child_span);
                if child_end <= start || child_first >= end {
                    // Wholly outside the range.
                    live = true;
                    continue;
                }
                let child = u64::from(ptr);
                let empty = if level == 1 {
                    true
                } else {
                    let (empty, sub) = self
                        .blockmap_free_branch(
                            child,
                            level - 1,
                            start.saturating_sub(child_first),
                            end.saturating_sub(child_first).min(child_span),
                            &mut *deferred,
                        )
                        .await?;
                    freed = freed.saturating_add(sub);
                    empty
                };
                if empty {
                    deferred.push(child);
                    freed = freed.saturating_add(spb);
                    buf[off..off + 4].fill(0);
                    changed = true;
                } else {
                    live = true;
                }
            }
            if live && changed {
                self.write_block(block, &buf).await?;
            }
            Ok((!live, freed))
        })
    }

    /// Read the on-disk inode `inode_no`.
    pub async fn read_inode(&self, inode_no: u32) -> Result<Inode, FsError> {
        let (group, index) = self
            .inode_group_and_index(inode_no)
            .ok_or(FsError::NotFound)?;
        let gd = &self.group_descs[group as usize];
        let inode_size = self.superblock.inode_size_bytes();
        let bs = self.block_size() as u64;

        let table_byte_off = gd.inode_table * bs;
        let inode_byte_off = table_byte_off + (index as u64) * inode_size as u64;

        // Read the full inode slot: ext4's checksum covers the extended
        // fields even though the common inode decoder only consumes its
        // original 128-byte prefix.
        let mut buf = vec![0u8; inode_size];
        self.read_byte_range(inode_byte_off, &mut buf).await?;
        if !metadata_csum::verify_inode_checksum(&self.superblock, inode_no, &buf) {
            return Err(FsError::InvalidData);
        }
        Inode::parse(&buf).ok_or(FsError::Io(narf_block::BlockError::IOError))
    }

    /// Resolve the `i`th logical block of `inode` to its physical
    /// block number. Returns `Ok(0)` for a hole (sparse file).
    ///
    /// Dispatches on the superblock's `uses_extents()` flag:
    /// ext4-with-EXTENTS reads the i_block[60] region as an extent
    /// tree root; ext2/3 walks the legacy 12-direct + 3-indirect
    /// pointer chain.
    pub async fn map_block(&self, inode: &Inode, logical: u64) -> Result<u64, FsError> {
        if self.superblock.uses_extents() && inode.uses_extents() {
            return self.map_block_extents(inode, logical).await;
        }
        // Legacy ext2/3 indirect-block walk.
        let p = self.pointers_per_block() as u64;
        let direct_max = super::inode::N_DIRECT as u64;
        let single_max = direct_max + p;
        let double_max = single_max + p * p;
        let triple_max = double_max + p * p * p;

        if logical < direct_max {
            return Ok(inode.block[logical as usize] as u64);
        }
        if logical < single_max {
            let idx = logical - direct_max;
            let l1 = inode.block[super::inode::SINGLE_IND_IDX];
            return Ok(self.read_indirect(l1, idx).await? as u64);
        }
        if logical < double_max {
            let l = logical - single_max;
            let l1 = l / p;
            let l0 = l % p;
            let l2_block = inode.block[super::inode::DOUBLE_IND_IDX];
            let middle = self.read_indirect(l2_block, l1).await?;
            return Ok(self.read_indirect(middle, l0).await? as u64);
        }
        if logical < triple_max {
            let l = logical - double_max;
            let l2 = l / (p * p);
            let l1 = (l / p) % p;
            let l0 = l % p;
            let l3_block = inode.block[super::inode::TRIPLE_IND_IDX];
            let middle = self.read_indirect(l3_block, l2).await?;
            let leaf = self.read_indirect(middle, l1).await?;
            return Ok(self.read_indirect(leaf, l0).await? as u64);
        }
        Err(FsError::Io(narf_block::BlockError::InvalidRange))
    }

    /// ext4 extent-tree dispatch for `map_block`. Serialises the
    /// inode's 60-byte i_block region as the extent root and walks
    /// the tree, fetching index-child blocks via `read_block` as
    /// the walker descends.
    async fn map_block_extents(&self, inode: &Inode, logical: u64) -> Result<u64, FsError> {
        self.map_block_extents_as(inode, logical, false).await
    }

    /// [`Self::map_block`], but an uninitialized (preallocated, unwritten)
    /// extent answers with its physical block rather than as a hole: where
    /// the block *is*, not what a read returns. `bmap` answers through this,
    /// as Linux's swap-file setup (`iomap_swapfile_activate`) accepts
    /// unwritten extents.
    pub async fn map_block_allocated(&self, inode: &Inode, logical: u64) -> Result<u64, FsError> {
        if self.superblock.uses_extents() && inode.uses_extents() {
            return self.map_block_extents_as(inode, logical, true).await;
        }
        self.map_block(inode, logical).await
    }

    async fn map_block_extents_as(
        &self,
        inode: &Inode,
        logical: u64,
        unwritten_is_mapped: bool,
    ) -> Result<u64, FsError> {
        use super::extent::{lookup_in_node, LookupOutcome};
        // Serialise inode.block[15] as 60 bytes (15 × u32 LE).
        let mut node_buf = alloc::vec![0u8; 60];
        for (i, &b) in inode.block.iter().enumerate() {
            node_buf[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
        }
        // Cap on extent-tree depth to defend against malformed
        // volumes pointing children back at themselves. ext4 spec
        // limits depth to 5 (root + 4 index levels); 8 is paranoid.
        let mut depth_budget = 8u32;
        let logical32 = if logical > u32::MAX as u64 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        } else {
            logical as u32
        };
        loop {
            match lookup_in_node(&node_buf, logical32) {
                LookupOutcome::Mapped {
                    physical,
                    is_uninitialized,
                } => {
                    // Uninitialized extents read as zeros — surface
                    // them as a hole to the caller, who already
                    // zero-fills on physical == 0.
                    if is_uninitialized && !unwritten_is_mapped {
                        return Ok(0);
                    }
                    return Ok(physical);
                }
                LookupOutcome::Hole => return Ok(0),
                LookupOutcome::Corrupt => {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
                LookupOutcome::DeeperLookupRequired { child_block } => {
                    depth_budget = depth_budget
                        .checked_sub(1)
                        .ok_or(FsError::Io(narf_block::BlockError::IOError))?;
                    // Fetch the child extent-block + retry.
                    let bs = self.block_size();
                    let mut child = alloc::vec![0u8; bs];
                    self.read_block(child_block, &mut child).await?;
                    node_buf = child;
                }
            }
        }
    }

    /// Read pointer `index` from the indirect block `block_no`.
    /// `block_no == 0` is a hole — returns 0.
    async fn read_indirect(&self, block_no: u32, index: u64) -> Result<u32, FsError> {
        if block_no == 0 {
            return Ok(0);
        }
        if index >= self.pointers_per_block() as u64 {
            return Err(FsError::Io(narf_block::BlockError::InvalidRange));
        }
        let off = (index as usize) * 4;
        // Indirect blocks are ordinary bdev-mapping pages: a sequential walk
        // of a large file hits the same cached page for every data block.
        let block = self.read_block_view(u64::from(block_no)).await?;
        Ok(u32::from_le_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
        ]))
    }
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Return the current wall-clock time as a `u32` seconds-since-epoch
    /// value suitable for ext2's 32-bit timestamp fields. Returns `0`
    /// when the clock has not been calibrated (pre-epoch or uninitialised).
    ///
    /// Ref: Linux `fs/ext4/inode.c::ext4_current_time` pattern —
    /// read `ktime_get_real_seconds()`, clamp to `u32`, store in
    /// `i_mtime` / `i_ctime`.
    pub(crate) fn now_secs() -> u32 {
        let w = now_wall();
        if w.secs <= 0 {
            return 0;
        }
        w.secs.min(u32::MAX as i64) as u32
    }
}

impl<B: BlockDevice + 'static> FsInstance for Ext2Volume<B> {
    fn root(&self) -> Arc<dyn DirOps> {
        let inode =
            (*self.root_inode.lock()).expect("mounted ext2 volume lost root inode metadata");
        self.iget_with(super::EXT2_ROOT_INO, inode)
    }

    fn name(&self) -> &str {
        "ext2"
    }

    /// `ext2_statfs`: `buf->f_fsid = uuid_to_fsid(es->s_uuid)`, the two
    /// little-endian halves of the UUID XORed.
    fn statfs_fsid(&self) -> Option<u64> {
        let uuid = self.superblock.uuid;
        let lo = u64::from_le_bytes(uuid[..8].try_into().ok()?);
        let hi = u64::from_le_bytes(uuid[8..].try_into().ok()?);
        Some(lo ^ hi)
    }

    /// `ext4_reconfigure`, after the VFS took its own keys out. See
    /// [`super::mount_opts::validate_remount`].
    fn reconfigure(&self, options: &str) -> Result<(), FsError> {
        super::mount_opts::validate_remount(options)
    }

    /// Writes are refused at the mount (`mnt_want_write` → EROFS) while
    /// this mount writes nothing.
    fn always_read_only(&self) -> bool {
        self.is_read_only()
    }

    /// `__ext4_remount`: `SB_RDONLY` turning on writes everything back and
    /// marks the filesystem clean; turning off runs the write gate again.
    fn reconfigure_sb_async<'a>(
        &'a self,
        sb_flags: u64,
        sb_mask: u64,
        options: &'a str,
    ) -> narf_filesystem::FsFuture<'a, ()> {
        alloc::boxed::Box::pin(async move {
            use narf_filesystem::sb_flags::RDONLY;
            super::mount_opts::validate_remount(options)?;
            let mut want_ro = (sb_mask & RDONLY != 0).then_some(sb_flags & RDONLY != 0);
            for option in options.split(',') {
                match option {
                    "ro" => want_ro = Some(true),
                    "rw" => want_ro = Some(false),
                    _ => {}
                }
            }
            match want_ro {
                Some(true) => self.remount_read_only().await,
                Some(false) => self.remount_read_write().await,
                None => Ok(()),
            }
        })
    }
}

impl<B: BlockDevice + 'static> Drop for Ext2Volume<B> {
    /// The last reference went away (umount, which never syncs, or a
    /// dropped internal mount): `ext4_put_super` marks the filesystem clean
    /// after everything is on the device. Drop cannot block, so the flush
    /// and superblock write are polled once in place, which completes on
    /// NARF's synchronous block devices. If they cannot finish, the
    /// superblock keeps saying "not clean", and e2fsck checks it, which is
    /// safe.
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;
        if self.read_only.load(Ordering::Acquire) || !self.dirty_marked.load(Ordering::Acquire) {
            return;
        }
        use core::future::Future as _;
        let this: &Self = self;
        let mut finish = core::pin::pin!(async move {
            let _ = this.device.flush_result().await;
            this.mark_clean().await
        });
        let waker = core::task::Waker::noop();
        let mut cx = core::task::Context::from_waker(waker);
        if finish.as_mut().poll(&mut cx).is_pending() {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "ext4 {}: last unmount could not mark the filesystem clean; e2fsck will check it",
                sb_state::uuid_string(&self.superblock)
            );
        }
    }
}
