//! Lifetime and fault-source tracking for file/device mappings.
//!
//! Address-space regions store physical frames but intentionally do not depend
//! on filesystem objects. Keep the backing open-file description alive here
//! until the last process mapping disappears, matching Linux's VMA-held file
//! reference without adding a filesystem dependency to the memory TCB.
//!
//! That reference is **load-bearing for memory safety**, not only for
//! writeback. A file whose frames are aliased into userspace `MAP_SHARED` —
//! `mmap_frames` or `mmap_fault` — must outlive every mapping of them, or
//! teardown returns user-mapped frames to the buddy and userspace keeps a
//! writable window onto whatever is allocated next. `/dev/fb0` and perf's ring
//! are accidentally safe (device memory that is never in the buddy; a ring
//! that lives as long as the task); a BPF arena is not, which is what turned
//! this table from bookkeeping into the thing that makes `Arena::drop` sound.
//! `memory/src/bpf_arena.rs`'s `Arena::drop` names the test that pins it.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::{FileOps, FsError, FsFuture, MmapLifetime, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{
    AddressSpace, AddressSpaceError, FileFaultError, MappingReceipt, PhysAddr, RegionPerms,
    VirtAddr, ZapOutcome,
};

const ANON_SHARED_INLINE_PAGES: usize = 4;

/// The unnamed shmem inode behind one `MAP_SHARED | MAP_ANONYMOUS` mapping.
///
/// This deliberately is not a full MemFs inode. Linux uses an unlinked shmem
/// file here, but the hot stress-ng shape creates tens of thousands of
/// three-page objects: giving every one its own superblock, quota tables,
/// xattrs, timestamps and B-tree node makes kernel metadata rival the resident
/// pages. Four atomic slots cover that common shape without another allocation;
/// larger objects spill into the same fallible sparse backing used by VMAs.
struct AnonymousSharedFile {
    len: u64,
    inline: [AtomicU64; ANON_SHARED_INLINE_PAGES],
    overflow: IrqSafeSpinLock<narf_memory::region_backing::RegionBacking>,
}

impl AnonymousSharedFile {
    fn new(len: u64) -> Self {
        Self {
            len,
            inline: [const { AtomicU64::new(0) }; ANON_SHARED_INLINE_PAGES],
            overflow: IrqSafeSpinLock::new(narf_memory::region_backing::RegionBacking::new()),
        }
    }

    fn allocate_zeroed() -> Result<narf_memory::PhysFrame, FsError> {
        let frame = narf_memory::frame::alloc_frame().map_err(|_| FsError::OutOfMemory)?;
        // SAFETY: this fresh allocator frame is exclusively owned here and is
        // reachable through the kernel direct map.
        unsafe {
            core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, 4096);
        }
        Ok(frame)
    }

    fn inline_fault(&self, index: usize) -> Result<u64, FsError> {
        let slot = &self.inline[index];
        let existing = slot.load(Ordering::Acquire);
        if existing != 0 {
            return Ok(existing);
        }
        let frame = Self::allocate_zeroed()?;
        let candidate = frame.start_address().raw();
        match slot.compare_exchange(0, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(candidate),
            Err(winner) => {
                narf_memory::free_frame(frame);
                Ok(winner)
            }
        }
    }

    fn overflow_fault(&self, index: usize) -> Result<u64, FsError> {
        let mut backing = self.overflow.lock();
        if let Some(existing) = backing.get(index).filter(|phys| phys.raw() != 0) {
            return Ok(existing.raw());
        }
        backing
            .reserve_slot(index)
            .map_err(|_| FsError::OutOfMemory)?;
        let frame = Self::allocate_zeroed()?;
        let phys = frame.start_address();
        *backing
            .get_mut(index)
            .expect("reserved anonymous-shmem slot disappeared") = phys;
        Ok(phys.raw())
    }
}

impl Drop for AnonymousSharedFile {
    fn drop(&mut self) {
        for slot in &self.inline {
            let phys = slot.load(Ordering::Relaxed);
            if phys != 0 {
                narf_memory::free_frame(narf_memory::PhysFrame::new(PhysAddr::new(phys)));
            }
        }
        for (_, phys) in self.overflow.lock().indexed() {
            if phys.raw() != 0 {
                narf_memory::free_frame(narf_memory::PhysFrame::new(*phys));
            }
        }
    }
}

impl FileOps for AnonymousSharedFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::Unsupported) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.len,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn mmap_is_ram(&self) -> bool {
        true
    }

    fn supports_mmap_fault(&self) -> bool {
        true
    }

    fn mmap_fault(&self, offset: u64) -> Result<u64, FsError> {
        if offset & 0xfff != 0 || offset >= self.len {
            return Err(FsError::BadAddress);
        }
        let index = usize::try_from(offset >> 12).map_err(|_| FsError::BadAddress)?;
        if index < ANON_SHARED_INLINE_PAGES {
            self.inline_fault(index)
        } else {
            self.overflow_fault(index)
        }
    }
}

pub(crate) fn new_anonymous_shared_file(len: u64) -> Result<Arc<dyn FileOps>, FsError> {
    Arc::try_new(AnonymousSharedFile::new(len))
        .map(|file| file as Arc<dyn FileOps>)
        .map_err(|_| FsError::OutOfMemory)
}

/// Snapshot process roots; the memory transaction's metadata census refuses
/// roots still being built by fork or retiring outside this snapshot.
pub(crate) fn relocate_device_frames(
    old: &[u64],
    new: &[u64],
    aliases: fn(u64) -> usize,
    commit: &mut dyn FnMut() -> Result<(), FsError>,
) -> Result<(), FsError> {
    let mut spaces = crate::handlers::all_address_spaces();
    if let Some(current) = crate::handlers::active_user_as() {
        if !spaces.iter().any(|space| Arc::ptr_eq(space, &current)) {
            spaces.push(current);
        }
    }
    let old: Vec<_> = old.iter().copied().map(PhysAddr::new).collect();
    let new: Vec<_> = new.iter().copied().map(PhysAddr::new).collect();
    let mut failure = None;
    // SAFETY: the driver retains both allocations and card admission through
    // this synchronous call. Process Arc snapshots retain live roots; the
    // external-frame census covers unpublished fork metadata too.
    let result = unsafe {
        narf_memory::address_space::with_revoked_shared_frames(&spaces, &old, &new, aliases, || {
            match commit() {
                Ok(()) => Ok(()),
                Err(error) => {
                    failure = Some(error);
                    Err(AddressSpaceError::NotImplemented)
                }
            }
        })
    };
    if let Some(error) = failure {
        return Err(error);
    }
    result.map_err(|error| match error {
        AddressSpaceError::AllocationFailed => FsError::OutOfMemory,
        _ => FsError::Busy,
    })
}

#[derive(Clone)]
struct FileWriteback {
    offset: u64,
    /// Materialized prefix of this VMA. Missing tail entries are unfaulted,
    /// exactly like the corresponding FILE_DEMAND Region backing.
    phys: Vec<PhysAddr>,
}

fn clone_writeback_window(
    source: &[PhysAddr],
    first: usize,
    pages: usize,
) -> Result<Vec<PhysAddr>, AddressSpaceError> {
    let requested_end = first
        .checked_add(pages)
        .ok_or(AddressSpaceError::AllocationFailed)?;
    let materialized_end = requested_end.min(source.len());
    let slice = source
        .get(first.min(materialized_end)..materialized_end)
        .ok_or(AddressSpaceError::Unmapped)?;
    let mut phys = Vec::new();
    phys.try_reserve_exact(slice.len())
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    phys.extend_from_slice(slice);
    Ok(phys)
}

struct MappingOwner {
    base: u64,
    len: u64,
    /// File offset of `base`. Needed by [`demand_frame`] to turn a faulting
    /// address back into the file offset `FileOps::mmap_fault` expects, and
    /// therefore adjusted wherever `base` moves (`punch`).
    file_offset: u64,
    ops: Arc<dyn FileOps>,
    /// Optional per-object backing owner. The open file alone is insufficient
    /// for multiplexed devices such as DRM, where GEM_CLOSE removes one buffer
    /// while the fd and other resources remain live.
    lifetime: Option<Arc<dyn MmapLifetime>>,
    /// Generic `MAP_PRIVATE` file mapping. Its demand hook returns a freshly
    /// allocated frame owned by the VMA instead of a page-cache/device frame
    /// carrying an external mapping hold.
    private_copy: bool,
    /// Ordinary file MAP_SHARED mappings use private physical frames as a
    /// fallback when the filesystem cannot expose cache pages directly. Keep
    /// their frame list so fsync/msync can copy dirty bytes back to FileOps.
    /// Device mappings leave this `None`: they already alias device memory.
    writeback: Option<FileWriteback>,
    /// File offset at and beyond which this mapping must read as zero, even
    /// though the file has bytes there — `binfmt_elf`'s `padzero()` window.
    ///
    /// An ELF segment whose `p_memsz` exceeds its `p_filesz` ends its file
    /// image mid-page, and the rest of that page is `.bss`: it must read as
    /// zero, while the file almost always continues with the next segment or
    /// the section headers. Linux zeroes it with `clear_user` right after
    /// `elf_map`, which faults the page in and clears the tail of the private
    /// copy; doing it here instead keeps the page lazy and reaches the same
    /// bytes. Honoured only for `private_copy` mappings — zeroing a shared
    /// page-cache page would corrupt the file for everyone.
    ///
    /// Absolute in the FILE, not relative to `base`, so `punch` moving `base`
    /// and `file_offset` cannot invalidate it.
    zero_from: Option<u64>,
    /// `/proc/<pid>/maps` identity of the mapped file, captured at `mmap`.
    /// `None` when the creator recorded none (the exec loader's segments,
    /// whose identity lives in the exec image table). Shared by `Arc` so
    /// splits, moves and fork copy it without allocating.
    provenance: Option<Arc<MappingProvenance>>,
}

/// The file identity Linux's `show_map_vma` prints for a VMA with a
/// `vm_file`: `inode->i_sb->s_dev` (Linux `st_dev` encoding), `i_ino`, and
/// the open path. Captured once at `mmap` — a file's identity never changes
/// and its pathname is the one the mapping's open used.
pub(crate) struct MappingProvenance {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    /// Host-absolute path the mapped fd was opened on; `None` when the fd
    /// has no recorded path (memfd, anonymous inodes).
    pub(crate) pathname: Option<alloc::string::String>,
}

/// One file-owner row's provenance, as `/proc/<pid>/maps` needs it.
pub(crate) struct FileMappingProvenance {
    pub(crate) base: u64,
    pub(crate) len: u64,
    /// File offset of `base`.
    pub(crate) file_offset: u64,
    pub(crate) provenance: Arc<MappingProvenance>,
}

/// Snapshot the provenance-carrying file owners of an address space. The
/// table lock is held only while the rows are copied (Arc clones, no
/// FileOps calls). Fallible: procfs also runs on the fatal-fault diagnostic
/// path, so an allocation failure yields an empty snapshot (the VMAs then
/// render as unknown backing) instead of aborting the kernel.
pub(crate) fn file_provenance_snapshot(address_space_id: u64) -> Vec<FileMappingProvenance> {
    let Some(bucket) = existing_mapping_owners(address_space_id) else {
        return Vec::new();
    };
    let owners = bucket.lock();
    let mut snapshot = Vec::new();
    if snapshot.try_reserve_exact(owners.len()).is_err() {
        return Vec::new();
    }
    snapshot.extend(owners.iter().filter_map(|mapping| {
        Some(FileMappingProvenance {
            base: mapping.base,
            len: mapping.len,
            file_offset: mapping.file_offset,
            provenance: Arc::clone(mapping.provenance.as_ref()?),
        })
    }));
    snapshot
}

type MappingOwners = Arc<IrqSafeSpinLock<Vec<MappingOwner>>>;

/// The top-level index is sharded by address-space incarnation. Publication
/// and faults then serialize only on that address space's payload lock; an
/// unrelated process normally neither shares the index lock nor its cache
/// line. Fork snapshots and drops one source bucket before resolving the
/// destination, so no operation holds two shards at once.
const MAPPING_OWNER_SHARDS: usize = 64;

#[repr(align(64))]
struct MappingOwnerShard {
    buckets: IrqSafeSpinLock<BTreeMap<u64, MappingOwners>>,
}

impl MappingOwnerShard {
    const fn new() -> Self {
        Self {
            buckets: IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }
}

static MAPPING_OWNER_BUCKETS: [MappingOwnerShard; MAPPING_OWNER_SHARDS] =
    [const { MappingOwnerShard::new() }; MAPPING_OWNER_SHARDS];

#[inline]
fn mapping_owner_shard(address_space_id: u64) -> &'static MappingOwnerShard {
    &MAPPING_OWNER_BUCKETS[address_space_id as usize & (MAPPING_OWNER_SHARDS - 1)]
}

fn mapping_owners(address_space_id: u64) -> MappingOwners {
    if let Some(existing) = existing_mapping_owners(address_space_id) {
        return existing;
    }
    let candidate = Arc::new(IrqSafeSpinLock::new(Vec::new()));
    let mut buckets = mapping_owner_shard(address_space_id).buckets.lock();
    Arc::clone(buckets.entry(address_space_id).or_insert_with(|| candidate))
}

fn existing_mapping_owners(address_space_id: u64) -> Option<MappingOwners> {
    mapping_owner_shard(address_space_id)
        .buckets
        .lock()
        .get(&address_space_id)
        .map(Arc::clone)
}

/// The file object a `MAP_SHARED` mapping at `va` exposes, and the absolute
/// file offset of `va` in it — the `(inode, pgoff)` half of a shared
/// `get_futex_key`. `None` for an address no file owner covers, and for a
/// `MAP_PRIVATE` file mapping (whose pages belong to the mm, not the file).
pub(crate) fn shared_file_at(address_space_id: u64, va: u64) -> Option<(Arc<dyn FileOps>, u64)> {
    let bucket = existing_mapping_owners(address_space_id)?;
    let owners = bucket.lock();
    owners
        .iter()
        .find(|m| m.base <= va && va - m.base < m.len && !m.private_copy)
        .map(|m| (Arc::clone(&m.ops), m.file_offset + (va - m.base)))
}

pub(crate) fn drop_address_space(address_space_id: u64) {
    // Address-space teardown is the last writeback chance for this
    // process's dirty fallback pages: a mapper that exits without
    // munmap/fsync must still commit them, or its MAP_SHARED writes are
    // silently lost. Flush first, while the bucket still names the files;
    // the sweep itself is cache-driven and runs with no bucket lock held.
    if let Some(bucket) = existing_mapping_owners(address_space_id) {
        let files: Vec<Arc<dyn FileOps>> = {
            let owners = bucket.lock();
            let mut files: Vec<Arc<dyn FileOps>> = Vec::new();
            for mapping in owners.iter().filter(|mapping| !mapping.private_copy) {
                if !files.iter().any(|file| Arc::ptr_eq(file, &mapping.ops)) {
                    files.push(Arc::clone(&mapping.ops));
                }
            }
            files
        };
        for ops in files {
            let _ = flush_shared_pages_for_ops(&ops);
        }
    }
    // Drop the bucket (and therefore FileOps/MmapLifetime references) after
    // releasing the global index: destructors may allocate or take arbitrary
    // filesystem locks.
    let retired = mapping_owner_shard(address_space_id)
        .buckets
        .lock()
        .remove(&address_space_id);
    drop(retired);
}

/// Distinct files with a non-private mapping of `address_space_id`
/// overlapping `[base, base + len)`. `munmap` snapshots this before the
/// punch so it can commit the range's dirty pages afterwards, when the
/// owner rows are already gone.
pub(crate) fn file_ops_in_range(
    address_space_id: u64,
    base: u64,
    len: u64,
) -> Vec<Arc<dyn FileOps>> {
    let mut files: Vec<Arc<dyn FileOps>> = Vec::new();
    if let Some(bucket) = existing_mapping_owners(address_space_id) {
        let end = base.saturating_add(len);
        let owners = bucket.lock();
        for mapping in owners.iter().filter(|mapping| {
            !mapping.private_copy
                && mapping.base < end
                && base < mapping.base.saturating_add(mapping.len)
        }) {
            if !files.iter().any(|file| Arc::ptr_eq(file, &mapping.ops)) {
                files.push(Arc::clone(&mapping.ops));
            }
        }
    }
    files
}

/// Device page restrictions survive fd close and VMA splitting. Resolve the
/// file offsets under the table lock, then call FileOps after releasing it.
pub(crate) fn protection_allowed(address_space_id: u64, base: u64, len: u64, prot: u32) -> bool {
    let Some(bucket) = existing_mapping_owners(address_space_id) else {
        return true;
    };
    let end = base.saturating_add(len);
    let files: Vec<_> = bucket
        .lock()
        .iter()
        .filter(|m| m.base < end && base < m.base.saturating_add(m.len))
        .map(|m| (m.ops.clone(), m.file_offset + base.saturating_sub(m.base)))
        .collect();
    files
        .into_iter()
        .all(|(ops, offset)| prot & 7 & !ops.mmap_max_prot(offset) == 0)
}

/// Publish a memory VMA and its external file owner as one transaction.
///
/// The caller holds the address space's VMA transaction (and, for SHARED
/// mappings, memory's shared-mapping transaction). Keeping this address
/// space's owner bucket locked across `publish` means a peer fault may observe the new VMA but
/// cannot conclude that it has no file owner before registration completes.
/// `finish` may materialize the receipt; on failure it must roll the memory
/// mapping back before returning, after which this helper removes the owner.
pub(crate) struct MappingOwnerRegistration {
    pub(crate) base: u64,
    pub(crate) len: u64,
    pub(crate) file_offset: u64,
    pub(crate) ops: Arc<dyn FileOps>,
    pub(crate) lifetime: Option<Arc<dyn MmapLifetime>>,
    pub(crate) writeback_phys: Option<Vec<PhysAddr>>,
    pub(crate) private_copy: bool,
    pub(crate) replace: bool,
    /// See [`MappingOwner::zero_from`]. Only the ELF loader sets it.
    pub(crate) zero_from: Option<u64>,
    /// See [`MappingOwner::provenance`]. Set by `mmap(2)`.
    pub(crate) provenance: Option<Arc<MappingProvenance>>,
}

pub(crate) fn publish_current_mapping(
    address_space_id: u64,
    registration: MappingOwnerRegistration,
    publish: impl FnOnce() -> Result<MappingReceipt, AddressSpaceError>,
    finish: impl FnOnce(MappingReceipt) -> Result<(), AddressSpaceError>,
) -> Result<MappingReceipt, AddressSpaceError> {
    let MappingOwnerRegistration {
        base,
        len,
        file_offset,
        ops,
        lifetime,
        writeback_phys,
        private_copy,
        replace,
        zero_from,
        provenance,
    } = registration;
    let owner_bucket = mapping_owners(address_space_id);
    let mut owners = owner_bucket.lock();
    let receipt = publish()?;
    if replace {
        punch_locked(&mut owners, base, len);
    }
    owners.push(MappingOwner {
        base,
        len,
        file_offset,
        ops,
        lifetime,
        private_copy,
        writeback: writeback_phys.map(|phys| FileWriteback {
            offset: file_offset,
            phys,
        }),
        zero_from,
        provenance,
    });
    // Publication and owner registration are now atomic with respect to
    // faults. Release the IRQ-safe global table before PTE materialization,
    // which may walk many pages and must not serialize unrelated processes.
    drop(owners);
    if let Err(error) = finish(receipt) {
        let mut owners = owner_bucket.lock();
        punch_locked(&mut owners, base, len);
        return Err(error);
    }
    Ok(receipt)
}

/// Publish a VMA which has no new file owner while atomically retiring any
/// file owners covered by a successful `MAP_FIXED` replacement.
pub(crate) fn publish_current_unowned_mapping<T: Copy>(
    address_space_id: u64,
    base: u64,
    len: u64,
    replace: bool,
    publish: impl FnOnce() -> Result<T, AddressSpaceError>,
    finish: impl FnOnce(T) -> Result<(), AddressSpaceError>,
) -> Result<T, AddressSpaceError> {
    // Anonymous address spaces normally have no file mappings. The caller's
    // VMA transaction prevents a file-backed mapping from being published
    // while we classify this operation, so an absent bucket is a stable fact
    // for the duration of `publish`.
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        let receipt = publish()?;
        finish(receipt)?;
        return Ok(receipt);
    };
    let mut owners = owner_bucket.lock();
    if !replace {
        // A non-replacing unowned mapping cannot retire a file owner. Do not
        // hold an unrelated per-AS IRQ-safe lock across page-table work.
        drop(owners);
        let receipt = publish()?;
        finish(receipt)?;
        return Ok(receipt);
    }
    let end = base.checked_add(len).ok_or(AddressSpaceError::OutOfRange)?;
    if !owners.iter().any(|mapping| {
        mapping
            .base
            .checked_add(mapping.len)
            .is_some_and(|mapping_end| mapping_end > base && mapping.base < end)
    }) {
        // The existing bucket belongs to disjoint mappings. The VMA
        // transaction keeps that classification stable until publication.
        drop(owners);
        let receipt = publish()?;
        finish(receipt)?;
        return Ok(receipt);
    }
    let receipt = publish()?;
    punch_locked(&mut owners, base, len);
    drop(owners);
    finish(receipt)?;
    Ok(receipt)
}

/// Run a transaction-held fixed mremap while blocking file-demand faults on
/// this address space's owner bucket. Memory reports whether Linux-style
/// target retirement occurred before a later failure; mirror the owner punch
/// on both success and that post-punch error path.
///
/// The caller must hold `AddressSpace::with_vma_transaction`, establishing the
/// same VMA -> owner order used by mmap publication.
pub(crate) fn publish_current_fixed_remap<T>(
    base: u64,
    len: u64,
    publish: impl FnOnce() -> Result<T, narf_memory::FixedRelocationError>,
) -> Result<T, narf_memory::FixedRelocationError> {
    let Some(address_space_id) = current_address_space_id() else {
        // Pure AddressSpace tests have no scheduler-owned current mm and
        // therefore cannot have file-owner rows to retire. The syscall path
        // always has an identity by construction.
        return publish();
    };
    publish_fixed_remap(address_space_id, base, len, publish)
}

fn publish_fixed_remap<T>(
    address_space_id: u64,
    base: u64,
    len: u64,
    publish: impl FnOnce() -> Result<T, narf_memory::FixedRelocationError>,
) -> Result<T, narf_memory::FixedRelocationError> {
    // Anonymous address spaces normally have no file mappings. Do not create
    // an empty global-registry bucket or hold an empty per-AS IRQ lock across
    // a potentially large relocation.
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return publish();
    };
    let mut owners = owner_bucket.lock();
    let Some(end) = base.checked_add(len) else {
        return publish();
    };
    if !owners.iter().any(|mapping| {
        mapping
            .base
            .checked_add(mapping.len)
            .is_some_and(|mapping_end| mapping_end > base && mapping.base < end)
    }) {
        // VMA serialization prevents a new owner for this window from being
        // published after this check. Avoid holding an unrelated owner bucket
        // across page-table work.
        drop(owners);
        return publish();
    }
    let suffixes = prepare_punch_locked(&mut owners, base, len, 0).map_err(|error| {
        narf_memory::FixedRelocationError {
            error,
            target_punched: false,
            source_shrunk: false,
        }
    })?;
    let result = publish();
    if result.is_ok() || result.as_ref().is_err_and(|failure| failure.target_punched) {
        commit_prepared_punch_locked(&mut owners, base, len, suffixes);
    }
    result
}

/// Publish a shared/file-backed mremap alias while keeping file-demand faults
/// serialized with destination-owner registration. `old_addr` names the first
/// byte of backing to clone; this works for both equal-length DONTUNMAP and the
/// legacy zero-old-length shared duplication (whose alias length is `len`).
///
/// A fixed operation prepares its target-owner punch in the same transaction.
/// Memory's typed outcome decides the commit: success publishes the alias and
/// retires the target; a post-punch failure retires only the target; an early
/// failure changes neither. The caller must hold the address-space VMA
/// transaction and, for SHARED mappings, the shared-mapping transaction.
#[allow(dead_code)] // Wired by the shared-mremap syscall change landing alongside this helper.
pub(crate) fn publish_current_owner_alias<T>(
    old_addr: u64,
    new_addr: u64,
    len: u64,
    fixed: bool,
    publish: impl FnOnce() -> Result<T, narf_memory::FixedRelocationError>,
) -> Result<T, narf_memory::FixedRelocationError> {
    let Some(address_space_id) = current_address_space_id() else {
        // Pure AddressSpace tests have no scheduler-owned current mm and hence
        // no file-owner rows. Keep that path identical to anonymous aliases.
        return publish();
    };
    publish_owner_alias(address_space_id, old_addr, new_addr, len, fixed, publish)
}

/// Publish an ordinary shared/file-backed mremap move. Unlike alias
/// publication, this retires the selected source owner interval and transfers
/// its file offset/lifetime to a possibly resized destination. A fixed move
/// can additionally commit target-only and target-plus-source-shrink states
/// when memory reports a late Linux-style failure.
///
/// The caller holds the address-space VMA and shared-mapping transactions.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_current_owner_relocation<T>(
    old_addr: u64,
    old_len: u64,
    new_addr: u64,
    new_len: u64,
    fixed: bool,
    publish: impl FnOnce() -> Result<T, narf_memory::FixedRelocationError>,
) -> Result<T, narf_memory::FixedRelocationError> {
    let Some(address_space_id) = current_address_space_id() else {
        return publish();
    };
    publish_owner_relocation(
        address_space_id,
        old_addr,
        old_len,
        new_addr,
        new_len,
        fixed,
        publish,
    )
}

#[allow(clippy::too_many_arguments)]
fn publish_owner_relocation<T>(
    address_space_id: u64,
    old_addr: u64,
    old_len: u64,
    new_addr: u64,
    new_len: u64,
    fixed: bool,
    publish: impl FnOnce() -> Result<T, narf_memory::FixedRelocationError>,
) -> Result<T, narf_memory::FixedRelocationError> {
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return publish();
    };
    let mut owners = owner_bucket.lock();
    let fail = |error| narf_memory::FixedRelocationError {
        error,
        target_punched: false,
        source_shrunk: false,
    };
    let destination =
        prepare_relocated_owners_locked(&owners, old_addr, old_len, new_addr, new_len)
            .map_err(fail)?;
    let source_owned = !destination.is_empty();
    let target_owned = fixed && owner_range_intersects(&owners, new_addr, new_len);
    if !source_owned && !target_owned {
        drop(owners);
        return publish();
    }

    let target_suffixes = if fixed {
        prepare_punch_suffixes_locked(&owners, new_addr, new_len).map_err(fail)?
    } else {
        Vec::new()
    };
    let source_suffixes = if source_owned {
        prepare_punch_suffixes_locked(&owners, old_addr, old_len).map_err(fail)?
    } else {
        Vec::new()
    };
    let shrink_suffixes = if source_owned && old_len > new_len {
        prepare_punch_suffixes_locked(
            &owners,
            old_addr
                .checked_add(new_len)
                .ok_or_else(|| fail(AddressSpaceError::OutOfRange))?,
            old_len - new_len,
        )
        .map_err(fail)?
    } else {
        Vec::new()
    };
    let success_growth = target_suffixes
        .len()
        .checked_add(source_suffixes.len())
        .and_then(|count| count.checked_add(destination.len()))
        .ok_or_else(|| fail(AddressSpaceError::AllocationFailed))?;
    let failed_growth = target_suffixes
        .len()
        .checked_add(shrink_suffixes.len())
        .ok_or_else(|| fail(AddressSpaceError::AllocationFailed))?;
    owners
        .try_reserve_exact(core::cmp::max(success_growth, failed_growth))
        .map_err(|_| fail(AddressSpaceError::AllocationFailed))?;

    let result = publish();
    match &result {
        Ok(_) => {
            if fixed {
                commit_prepared_punch_locked(&mut owners, new_addr, new_len, target_suffixes);
            }
            if source_owned {
                commit_prepared_punch_locked(&mut owners, old_addr, old_len, source_suffixes);
                owners.extend(destination);
            }
        }
        Err(failure) if failure.target_punched => {
            commit_prepared_punch_locked(&mut owners, new_addr, new_len, target_suffixes);
            if failure.source_shrunk && old_len > new_len && source_owned {
                commit_prepared_punch_locked(
                    &mut owners,
                    old_addr + new_len,
                    old_len - new_len,
                    shrink_suffixes,
                );
            }
        }
        Err(_) => {}
    }
    result
}

/// Resize an ordinary shared file owner in place. The replacement owner rows
/// are fully cloned/reserved before memory grows; publication is therefore
/// failure-atomic and a FILE_DEMAND fault cannot observe the new tail before
/// its backing file row exists.
pub(crate) fn publish_current_owner_resize<T>(
    base: u64,
    old_len: u64,
    new_len: u64,
    publish: impl FnOnce() -> Result<T, AddressSpaceError>,
) -> Result<T, AddressSpaceError> {
    let Some(address_space_id) = current_address_space_id() else {
        return publish();
    };
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return publish();
    };
    let mut owners = owner_bucket.lock();
    let replacement = prepare_relocated_owners_locked(&owners, base, old_len, base, new_len)?;
    if replacement.is_empty() {
        drop(owners);
        return publish();
    }
    let suffixes = prepare_punch_suffixes_locked(&owners, base, old_len)?;
    owners
        .try_reserve_exact(
            suffixes
                .len()
                .checked_add(replacement.len())
                .ok_or(AddressSpaceError::AllocationFailed)?,
        )
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    let result = publish();
    if result.is_ok() {
        commit_prepared_punch_locked(&mut owners, base, old_len, suffixes);
        owners.extend(replacement);
    }
    result
}

fn publish_owner_alias<T>(
    address_space_id: u64,
    old_addr: u64,
    new_addr: u64,
    len: u64,
    fixed: bool,
    publish: impl FnOnce() -> Result<T, narf_memory::FixedRelocationError>,
) -> Result<T, narf_memory::FixedRelocationError> {
    // An address space without file owners needs neither a new global bucket
    // nor an IRQ-disabled per-AS transaction for an anonymous shared alias.
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return publish();
    };
    let mut owners = owner_bucket.lock();
    let fail = |error| narf_memory::FixedRelocationError {
        error,
        target_punched: false,
        source_shrunk: false,
    };
    let old_end = old_addr
        .checked_add(len)
        .ok_or_else(|| fail(AddressSpaceError::OutOfRange))?;
    let new_end = new_addr
        .checked_add(len)
        .ok_or_else(|| fail(AddressSpaceError::OutOfRange))?;
    let source_owned = owners.iter().any(|mapping| {
        mapping
            .base
            .checked_add(mapping.len)
            .is_some_and(|end| mapping.base < old_end && old_addr < end)
    });
    let target_owned = fixed
        && owners.iter().any(|mapping| {
            mapping
                .base
                .checked_add(mapping.len)
                .is_some_and(|end| mapping.base < new_end && new_addr < end)
        });
    if !source_owned && !target_owned {
        // The bucket belongs to unrelated mappings. The VMA transaction keeps
        // that classification stable while memory publishes the alias.
        drop(owners);
        return publish();
    }

    let aliases = prepare_aliases_locked(&owners, old_addr, new_addr, len).map_err(fail)?;
    let suffixes = if fixed {
        Some(prepare_punch_locked(&mut owners, new_addr, len, aliases.len()).map_err(fail)?)
    } else {
        owners
            .try_reserve_exact(aliases.len())
            .map_err(|_| fail(AddressSpaceError::AllocationFailed))?;
        None
    };

    let result = publish();
    match &result {
        Ok(_) => {
            if let Some(suffixes) = suffixes {
                commit_prepared_punch_locked(&mut owners, new_addr, len, suffixes);
            }
            owners.extend(aliases);
        }
        Err(failure) if failure.target_punched => {
            if let Some(suffixes) = suffixes {
                commit_prepared_punch_locked(&mut owners, new_addr, len, suffixes);
            }
            // `aliases` drops without publication: memory did not establish a
            // destination VMA even though it destructively retired the target.
        }
        Err(_) => {
            // Every allocation was only a prepared clone; preserve source and
            // target owner rows when memory failed before target retirement.
        }
    }
    result
}

/// Publish a transaction-held unmap and retire overlapping file-owner rows
/// before the caller releases the VMA transaction.
pub(crate) fn publish_current_punch(
    address_space_id: u64,
    base: u64,
    len: u64,
    publish: impl FnOnce() -> Result<(), AddressSpaceError>,
) -> Result<(), AddressSpaceError> {
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return publish();
    };
    let mut owners = owner_bucket.lock();
    let suffixes = prepare_punch_locked(&mut owners, base, len, 0)?;
    let result = publish();
    if result.is_ok() {
        commit_prepared_punch_locked(&mut owners, base, len, suffixes);
    }
    result
}

/// Drop only the window's recorded writeback frames from every overlapping
/// owner row, keeping each row's base, length and file offset — the owner
/// mirror of a memory-side zap that retained the VMA. Zeroing is the
/// "no fallback frame here" state every writeback consumer already
/// honours (flush skips zero entries; a later fault re-publishes the slot
/// through the ordinary demand path), so the row stays truthful about the
/// surviving mapping while forgetting the frames the zap just released.
/// Without this, msync would write back through a retired folio's frame
/// and a re-fault could adopt it as the mapping's backing again.
fn zap_owner_rows_locked(owners: &mut [MappingOwner], base: u64, len: u64) {
    let Some(end) = base.checked_add(len) else {
        return;
    };
    for mapping in owners.iter_mut() {
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        if mapping_end <= base || mapping.base >= end {
            continue;
        }
        let Some(writeback) = mapping.writeback.as_mut() else {
            continue;
        };
        let first = ((base.max(mapping.base) - mapping.base) / 4096) as usize;
        let last =
            (((end.min(mapping_end) - mapping.base) / 4096) as usize).min(writeback.phys.len());
        for slot in writeback.phys.iter_mut().take(last).skip(first) {
            *slot = PhysAddr::new(0);
        }
    }
}

/// Publish a transaction-held truncate zap and mirror its outcome in the
/// file-owner rows before the caller releases the VMA transaction.
///
/// The memory zap reports which of its two shapes ran, because the owner
/// mirror differs: [`ZapOutcome::Retained`] keeps every row and drops only
/// the window's writeback entries ([`zap_owner_rows_locked`]);
/// [`ZapOutcome::RangeRemoved`] (the swap/huge fallback to the full punch)
/// retires rows exactly like [`publish_current_punch`]. The removal shape
/// needs its split suffixes prepared before memory becomes destructive —
/// the retention shape needs no allocation at all — so, like the punch,
/// preparation happens up front and the commit follows the outcome.
pub(crate) fn publish_current_zap(
    address_space_id: u64,
    base: u64,
    len: u64,
    publish: impl FnOnce() -> Result<ZapOutcome, AddressSpaceError>,
) -> Result<ZapOutcome, AddressSpaceError> {
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return publish();
    };
    let mut owners = owner_bucket.lock();
    let suffixes = prepare_punch_locked(&mut owners, base, len, 0)?;
    let result = publish();
    match &result {
        Ok(ZapOutcome::Retained) => zap_owner_rows_locked(&mut owners, base, len),
        Ok(ZapOutcome::RangeRemoved) => {
            commit_prepared_punch_locked(&mut owners, base, len, suffixes)
        }
        Err(_) => {}
    }
    result
}

/// Physical file-cache pages for generic `MAP_SHARED` fallbacks. A filesystem
/// which cannot directly expose its own page-cache frames still needs one
/// backing page per `(file, file offset)`: otherwise two overlapping mappings
/// diverge and the last writeback can overwrite a newer change through the
/// other mapping. The file is `FileOps::mmap_backing_identity`, so a
/// filesystem whose opens are separate `FileOps` objects (btrfs) shares the
/// pages of one inode across every open and process.
struct SharedFilePage {
    /// Weak to avoid making the global cache keep an unlinked inode alive.
    /// Every active mapping independently owns a strong FileOps reference.
    ops: Weak<dyn FileOps>,
    /// `mmap_backing_identity` of the file this page caches.
    identity: SharedFileIdentity,
    offset: u64,
    phys: PhysAddr,
    mappings: usize,
    /// Mappers which selected this canonical page but have not yet either
    /// committed a VMA reference or aborted. Reclaim requires both counters
    /// to reach zero.
    pending: usize,
    /// `Some` opts this page into bounded retention after its final unmap.
    /// It must still match `FileOps::mmap_cache_generation` before reuse.
    cache_generation: Option<u64>,
    /// Exact bytes last read from, or successfully written to, the backing
    /// file. Generic mappings cannot rely on hardware dirty bits here, so an
    /// exact snapshot lets fsync skip clean pages without risking a hash
    /// collision that could lose a write.
    clean: Vec<u8>,
}

// Pointer anchors and generation counters are only unique within a mounted
// filesystem. A different filesystem can reuse both after the old one drops.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct SharedFileIdentity {
    device: u64,
    anchor: usize,
}
fn shared_file_identity(ops: &dyn FileOps) -> SharedFileIdentity {
    SharedFileIdentity {
        device: ops.inode_attrs().dev,
        anchor: ops.mmap_backing_identity(),
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct SharedFileKey {
    file: SharedFileIdentity,
    offset: u64,
}

struct SharedFilePages {
    by_phys: BTreeMap<u64, SharedFilePage>,
    by_file: BTreeMap<SharedFileKey, u64>,
}

impl SharedFilePages {
    const fn new() -> Self {
        Self {
            by_phys: BTreeMap::new(),
            by_file: BTreeMap::new(),
        }
    }

    fn key(identity: SharedFileIdentity, offset: u64) -> SharedFileKey {
        Self::key_from_ptr(identity, offset)
    }

    fn key_from_ptr(file: SharedFileIdentity, offset: u64) -> SharedFileKey {
        SharedFileKey { file, offset }
    }

    fn remove_phys(&mut self, phys: u64) -> Option<SharedFilePage> {
        let page = self.by_phys.remove(&phys)?;
        let key = Self::key_from_ptr(page.identity, page.offset);
        assert_eq!(
            self.by_file.remove(&key),
            Some(phys),
            "shared-file indexes diverged"
        );
        Some(page)
    }
}

static SHARED_FILE_PAGES: IrqSafeSpinLock<SharedFilePages> =
    IrqSafeSpinLock::new(SharedFilePages::new());

/// Clean idle pages retained between mappings. Dirty pages remain cached
/// until an explicit writeback makes them reclaimable; dropping them would
/// lose MAP_SHARED writes. Linux makes the same distinction in its page cache.
const MAX_RETAINED_SHARED_FILE_PAGES: usize = 1024;

/// `page` caches `ops`'s file. A page with live mappings or pending holds is
/// pinned by those mappers' strong `FileOps` references, so its identity
/// cannot have been reused. An idle page falls into one of two regimes:
///
/// - No cache generation: the filesystem never vouched for the page, and its
///   identity may be a recycled object address, so the recording open must
///   still be alive — otherwise a recycled identity could adopt another
///   file's stale page.
/// - A cache generation is recorded: the filesystem opted into the
///   generation discipline, which is only sound with a stable per-file
///   `mmap_backing_identity` (a volume-anchored token, never a per-open
///   address). Identity plus the generation checks at the call sites are
///   the guard then, and the recording open need not outlive the page —
///   that is what lets a later open of the same file reuse it.
///
/// `identity` contains the filesystem device and anchor, computed before
/// taking the cache lock (a filesystem may lock or allocate to answer it).
fn shared_page_matches_ops(page: &SharedFilePage, identity: SharedFileIdentity) -> bool {
    page.identity == identity
        && (page.mappings != 0
            || page.pending != 0
            || page.ops.upgrade().is_some()
            || page.cache_generation.is_some())
}

fn retain_pending_shared_page(page: &mut SharedFilePage) {
    page.pending = page
        .pending
        .checked_add(1)
        .expect("shared-file pending hold overflow");
}

fn shared_page_is_clean(page: &SharedFilePage) -> bool {
    // SAFETY: the cache entry owns `phys` while this function is called under
    // SHARED_FILE_PAGES. No final mapping release can free it concurrently.
    let current = unsafe { core::slice::from_raw_parts(page.phys.kernel_ptr::<u8>(), 4096) };
    page.clean.as_slice() == current
}

fn should_retire_idle_shared_page(page: &SharedFilePage, cache_len: usize) -> bool {
    if page.cache_generation.is_none() && page.ops.upgrade().is_none() {
        // The file object is gone and no generation discipline vouches for
        // the page, so no writeback can ever reach it again and its
        // identity cannot be trusted across opens; retaining the frame
        // only leaks it. A generation-carrying page is the opposite case:
        // its file is identified by (identity, generation), a later open
        // can still flush or reuse it, and the cap below bounds retention.
        return true;
    }
    if !shared_page_is_clean(page) {
        // A dirty page is the only copy of a MAP_SHARED write that no
        // fsync/msync has committed yet. Retiring it would silently lose
        // the write; the flush lifecycle (munmap / address-space teardown /
        // sync / fsync) must get its chance to commit the page first, after
        // which it is clean and this check lets it go.
        return false;
    }
    page.cache_generation.is_none() || cache_len > MAX_RETAINED_SHARED_FILE_PAGES
}

/// Consumable reservation for the canonical pages selected by one mmap
/// attempt. Drop is abort. A successful VMA publication calls [`Self::commit`]
/// after memory's SHARED retain hooks have recorded committed mappings.
pub(crate) struct SharedFilePublication {
    phys: Vec<PhysAddr>,
    active: bool,
}

/// Reuse a complete generation-valid run of generic shared-file pages.
/// Pending holds close the gap between this lookup and VMA publication.
pub(crate) fn reserve_cached_shared_file_pages(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    count: usize,
) -> Option<(Vec<PhysAddr>, SharedFilePublication)> {
    let generation = ops.mmap_cache_generation()?;
    let identity = shared_file_identity(ops.as_ref());
    let mut canonical = Vec::new();
    canonical.try_reserve_exact(count).ok()?;
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        for index in 0..count {
            let page_offset = offset.checked_add(index as u64 * 4096)?;
            let key = SharedFilePages::key(identity, page_offset);
            let phys = *pages.by_file.get(&key)?;
            let page = pages.by_phys.get(&phys)?;
            if !shared_page_matches_ops(page, identity)
                || (page.mappings == 0
                    && page.pending == 0
                    && page.cache_generation != Some(generation))
            {
                return None;
            }
            canonical.push(PhysAddr::new(phys));
        }
        for phys in &canonical {
            let page = pages
                .by_phys
                .get_mut(&phys.raw())
                .expect("validated shared-file page disappeared under cache lock");
            retain_pending_shared_page(page);
        }
    }
    let publication = SharedFilePublication {
        phys: canonical.clone(),
        active: true,
    };
    if ops.mmap_cache_generation() != Some(generation) {
        let mut pages = SHARED_FILE_PAGES.lock();
        for phys in &canonical {
            if let Some(page) = pages.by_phys.get_mut(&phys.raw()) {
                page.cache_generation = None;
            }
        }
        drop(pages);
        drop(publication);
        return None;
    }
    Some((canonical, publication))
}

impl SharedFilePublication {
    pub(crate) fn commit(mut self) {
        self.release_pending();
    }

    fn release_pending(&mut self) {
        if !self.active {
            return;
        }
        // Capacity is reserved before IRQs are masked. At most one page can
        // become free for each reservation held by this publication.
        let mut free = Vec::with_capacity(self.phys.len());
        {
            let mut pages = SHARED_FILE_PAGES.lock();
            for phys in &self.phys {
                let cache_len = pages.by_phys.len();
                let retire = {
                    let page = pages
                        .by_phys
                        .get_mut(&phys.raw())
                        .expect("pending shared-file publication lost its canonical page");
                    assert!(page.pending != 0, "shared-file pending hold underflow");
                    page.pending -= 1;
                    page.mappings == 0
                        && page.pending == 0
                        && should_retire_idle_shared_page(page, cache_len)
                };
                if retire {
                    let retired = pages
                        .remove_phys(phys.raw())
                        .expect("unreferenced shared-file page disappeared");
                    free.push(retired.phys);
                }
            }
        }
        self.active = false;
        for phys in free {
            narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
        }
    }
}

impl Drop for SharedFilePublication {
    fn drop(&mut self) {
        self.release_pending();
    }
}

fn current_address_space_id() -> Option<u64> {
    crate::handlers::active_user_as().map(|address_space| address_space.identity())
}

/// Resolve a fault on a demand-paged file mapping. Shared mappings return a
/// retained file/cache frame; private mappings read into a newly allocated
/// frame whose ownership transfers to the faulting address space.
///
/// Installed into `narf-memory` as the `RegionPerms::FILE_DEMAND` hook (see
/// `sys_mmap`), which is why this lives with the mapping owners rather than
/// with the syscall: the owner table is already the thing that knows which
/// file a user address belongs to, and it is the reference that keeps that
/// file alive while the mapping exists.
///
/// The lock is dropped before entering the file. `FileOps::mmap_fault` may
/// allocate and take its own locks — a BPF arena installs a kernel page-table
/// entry inside it — and holding an owner bucket across that would put this
/// lock beneath every lock any demand-pageable file might take, on a path
/// entered from the page-fault handler. `address_space_id` comes from the
/// owning `AddressSpace`, not the CPU's currently active user root: ptrace may
/// fault a stopped tracee's file-backed page while the tracer's root is live.
/// What a resolved generic shared fault can tell the fault-around
/// expansion: the owner row that served it. Only the generic path
/// produces one — a private copy and a direct-provider page have no
/// cache window to widen into.
struct FaultExpansion {
    owner_base: u64,
    owner_len: u64,
    ops: Arc<dyn FileOps>,
    offset: u64,
}

/// The single-page fault hook installed in `narf-memory`: resolve one
/// page through [`demand_frame_inner`], then — for a generic shared
/// fault only — widen it through [`fault_around`]. The expansion lives
/// here, in the single-page entry, and never in the fill core: that is
/// what makes bulk faulting acyclic (see `demand_alloc_range` in
/// `narf-memory` and [`demand_frames_batch`] below).
pub(crate) fn demand_frame(address_space_id: u64, vaddr: u64) -> Result<u64, FileFaultError> {
    let (phys, expansion) = demand_frame_inner(address_space_id, vaddr)?;
    if let Some(expansion) = expansion {
        fault_around(
            address_space_id,
            vaddr & !0xFFF,
            expansion.owner_base,
            expansion.owner_len,
            &expansion.ops,
            expansion.offset,
        );
    }
    Ok(phys)
}

/// The batch fill hook installed in `narf-memory` beside
/// [`demand_frame`]: supply frames for a run of pages a bulk fault
/// claimed, through the same fill core, one page at a time. A page
/// that cannot be supplied keeps its zero slot — a per-page refusal
/// the batch skips. Fill-only by construction: this path never calls
/// [`demand_frame`] (so it never expands a window) and never installs
/// a leaf, so a batch fill cannot re-enter the fault machinery.
pub(crate) fn demand_frames_batch(address_space_id: u64, first_vaddr: u64, out: &mut [u64]) {
    for (index, slot) in out.iter_mut().enumerate() {
        let vaddr = first_vaddr.saturating_add((index as u64).saturating_mul(4096));
        if let Ok((phys, _)) = demand_frame_inner(address_space_id, vaddr) {
            *slot = phys;
        }
    }
}

/// Resolve one page for a demand fault, returning the frame and, for a
/// generic shared fault, the [`FaultExpansion`] the caller may widen.
/// Fill-only: this function never expands a window and never installs
/// a leaf — it is the whole of what `demand_frame` did before
/// fault-around existed, shared by the single-page hook and the batch
/// fill hook.
fn demand_frame_inner(
    address_space_id: u64,
    vaddr: u64,
) -> Result<(u64, Option<FaultExpansion>), FileFaultError> {
    let page = vaddr & !0xFFFu64;
    let owner_bucket = existing_mapping_owners(address_space_id).ok_or(FileFaultError::NoOwner)?;
    let (offset, ops, generic_fallback, private_copy, zero_from, owner_base, owner_len) = {
        let owners = owner_bucket.lock();
        let owner = owners
            .iter()
            .find(|mapping| page >= mapping.base && page < mapping.base.saturating_add(mapping.len))
            .ok_or(FileFaultError::NoOwner)?;
        (
            owner
                .file_offset
                .checked_add(page - owner.base)
                .ok_or(FileFaultError::Bus)?,
            Arc::clone(&owner.ops),
            owner.writeback.is_some(),
            owner.private_copy,
            owner.zero_from,
            owner.base,
            owner.len,
        )
    };
    if private_copy {
        let phys = crate::handlers::load_file_demand_page(&ops, offset).map_err(fault_error)?;
        // `padzero()`: the bytes from an ELF segment's `p_filesz` to the end of
        // that page are `.bss` and must read as zero, not as whatever the file
        // holds there. Only this private copy is touched.
        if let Some(zero_from) = zero_from {
            // `saturating_sub`, not `checked_sub`: a page that begins at or
            // after the zero point is zero in its entirety, not left alone.
            let in_page = zero_from.saturating_sub(offset);
            if in_page < 4096 {
                // SAFETY: `phys` is the frame just allocated for this mapping
                // and is reachable through the kernel direct map; nothing else
                // can observe it until this returns.
                unsafe {
                    core::ptr::write_bytes(
                        phys.kernel_mut_ptr::<u8>().add(in_page as usize),
                        0,
                        4096 - in_page as usize,
                    );
                }
            }
        }
        return Ok((phys.raw(), None));
    }
    if !generic_fallback {
        // `filemap_fault`: an I/O-backed direct provider returns Pending with
        // this task's executor waker registered on its cache fill. The common
        // synchronous bridge parks the faulting own-stack task until that
        // waker fires; it does not spin on a folio owned by another task.
        return crate::handlers::poll_io_to_completion(ops.mmap_fault_async(offset))
            .ok_or(FileFaultError::Bus)?
            .map_err(fault_error)
            .map(|phys| (phys, None));
    }

    // Linux filemap_fault first looks in the inode page cache, then reads a
    // missing folio. The pending publication pins this canonical fallback
    // page while the mapping owner is revalidated after filesystem I/O.
    // `filemap_fault`: a page at or past i_size is SIGBUS, not unmapped.
    if offset >= ops.stat().size {
        return Err(FileFaultError::Bus);
    }
    let expected_generation = ops.mmap_cache_generation();
    let (phys, publication) =
        if let Some((phys, publication)) = reserve_cached_shared_file_pages(&ops, offset, 1) {
            (*phys.first().ok_or(FileFaultError::NoMemory)?, publication)
        } else {
            let candidate =
                crate::handlers::load_file_demand_page(&ops, offset).map_err(fault_error)?;
            let mut candidates = Vec::new();
            if candidates.try_reserve_exact(1).is_err() {
                narf_memory::free_frame(narf_memory::PhysFrame::new(candidate));
                return Err(FileFaultError::NoMemory);
            }
            candidates.push(candidate);
            let (phys, publication) =
                publish_shared_file_pages(&ops, offset, candidates, expected_generation);
            (*phys.first().ok_or(FileFaultError::NoMemory)?, publication)
        };
    if !retain_shared_file_page(phys.raw()) {
        drop(publication);
        return Err(FileFaultError::NoOwner);
    }
    publication.commit();

    // Recording the fetched frame as the owner row's writeback fallback
    // has three outcomes, because this fill ran lock-free and the world
    // may have moved since its entry checks:
    //
    // - `Recorded`: the slot now names the frame. It is written only for
    //   a fill publication can still adopt — see `Revoked`.
    // - `Revoked`: the file changed under the fill — its size shrank
    //   past this page, or its cache generation moved (any content
    //   mutation bumps it). The filesystems publish the new EOF and bump
    //   the generation BEFORE revoking mappings (the #690 truncate
    //   ordering), and this check runs under the same owner-bucket lock
    //   as the zap's owner mirror (`zap_owner_rows_locked`), so a
    //   shrink that crossed this page is always visible here by the
    //   time registration could land after the mirror pass. In that
    //   interleave the truncate zap has cancelled this fault's demand
    //   claim, `finish_demand_page` will refuse publication, and the
    //   fault path will release the frame's mapping hold through its
    //   false path; writing the slot anyway would leave the RETAINED
    //   row naming a frame no mapping holds, and a later msync would
    //   write back through it. So the slot is left empty — the "no
    //   fallback frame" state every consumer already honours — and the
    //   frame is still returned, with its hold, for memory's finish to
    //   dispose of. A generation move without a shrink (a racing write)
    //   takes the same branch: the page may well publish, just without
    //   a fallback record; the frame remains the canonical cache page,
    //   reachable by the cache-side flush (`flush_shared_pages_for_ops`),
    //   which is the same reach the flush lifecycle gives any fallback
    //   page whose owner has unmapped it.
    // - `Failed`: the row (or its writeback table, or the capacity to
    //   extend it) is gone, so no publication may proceed — the
    //   historical outcome: release the hold here and fail the fault.
    enum Registration {
        Recorded,
        Revoked,
        Failed,
    }
    let registration = {
        let mut owners = owner_bucket.lock();
        let found = owners.iter_mut().find(|mapping| {
            page >= mapping.base
                && page < mapping.base.saturating_add(mapping.len)
                && Arc::ptr_eq(&mapping.ops, &ops)
                && mapping.file_offset.checked_add(page - mapping.base) == Some(offset)
        });
        match found {
            None => Registration::Failed,
            Some(mapping) => match mapping.writeback.as_mut() {
                None => Registration::Failed,
                Some(writeback) => {
                    let index = ((page - mapping.base) >> 12) as usize;
                    if index >= writeback.phys.len()
                        && writeback
                            .phys
                            .try_reserve_exact(index + 1 - writeback.phys.len())
                            .is_err()
                    {
                        Registration::Failed
                    } else {
                        if index >= writeback.phys.len() {
                            writeback.phys.resize(index + 1, PhysAddr::new(0));
                        }
                        if offset >= ops.stat().size
                            || ops.mmap_cache_generation() != expected_generation
                        {
                            Registration::Revoked
                        } else {
                            let slot = &mut writeback.phys[index];
                            // A prior leaf-install failure can leave a safe,
                            // unretained cache identity in this writeback
                            // slot. The memory fault path balanced that
                            // page's mapping reference; overwrite the stale
                            // identity on retry before publication.
                            *slot = phys;
                            Registration::Recorded
                        }
                    }
                }
            },
        }
    };
    if matches!(registration, Registration::Failed) {
        let released = release_shared_file_page(phys.raw());
        debug_assert!(released);
        return Err(FileFaultError::NoOwner);
    }
    // The faulting page is fully published and no lock is held. Report
    // the owner row so the caller (`demand_frame`) can widen the win
    // for a sequential reader before the fault returns
    // (`do_fault_around`, #734) — the expansion itself lives there,
    // never in this fill core.
    Ok((
        phys.raw(),
        Some(FaultExpansion {
            owner_base,
            owner_len,
            ops,
            offset,
        }),
    ))
}

/// Linux's `fault_around_bytes` (64 KiB): the window one fault tries to
/// make resident around itself, the faulting page included.
const FAULT_AROUND_PAGES: u64 = 16;

/// `mm/filemap.c::do_fault_around`: after a generic shared fault has
/// resolved its page, install a bounded window of neighbours so a
/// sequential scan stops trapping once per page (#734).
///
/// The window is [`FAULT_AROUND_PAGES`] pages, aligned in the mapping's
/// own page space (first index `fault_index & !(FAULT_AROUND_PAGES - 1)`,
/// the alignment Linux applies in file-offset space), clamped to the
/// owner row that served the fault and to the file's current `i_size`:
/// a page at or past EOF can only SIGBUS, so there is nothing to install
/// for it, and a mapping may legitimately extend past EOF.
///
/// The window is installed by ONE `AddressSpace::demand_alloc_range`
/// call (#737): the batch claims the whole window atomically, fills it
/// through the batch hook ([`demand_frames_batch`] — this fault path's
/// own fill core, so an installed neighbour carries the same cache
/// fill, generation stamp, and writeback registration as a faulted
/// page), and publishes each page through the single fault's own
/// transaction. The batch skips the faulting page itself — its ticket
/// is held by the fault that triggered this — and any page a peer is
/// mid-fault on. As landed in #736 this loop instead drove
/// `demand_alloc_page` once per neighbour behind a recursion guard
/// (`FAULT_AROUND_ACTIVE`), because every call re-entered
/// [`demand_frame`] and would expand in turn; the batch's fill cannot
/// re-enter the fault path at all, so the guard's reason for existing
/// is gone and the guard is deleted, not bypassed. The result is
/// deliberately discarded: a neighbour that cannot be installed
/// (racing unmap, reclaim pressure, a fill error) fails silently and
/// its next real touch faults it in the ordinary way. Only the
/// faulting page's own outcome, already decided by the caller, is ever
/// reported, so a fill error here can never fail the original fault.
///
/// Installation needs the faulting space's page-table root live on
/// this CPU — the batch's safety contract, as it was for the per-page
/// path. When the space active here is a different one (a ptrace
/// remote access faulting a stopped tracee's page through this hook),
/// expansion is skipped and the fault keeps its single-page service.
fn fault_around(
    address_space_id: u64,
    fault_page: u64,
    owner_base: u64,
    owner_len: u64,
    ops: &Arc<dyn FileOps>,
    fault_offset: u64,
) {
    let Some(aspace) = crate::handlers::active_user_as() else {
        return;
    };
    if aspace.identity() != address_space_id {
        return;
    }
    let owner_pages = owner_len.div_ceil(4096);
    if owner_pages <= 1 {
        return;
    }
    let fault_index = (fault_page - owner_base) / 4096;
    let window_first = fault_index & !(FAULT_AROUND_PAGES - 1);
    let mut window_last = (window_first + FAULT_AROUND_PAGES).min(owner_pages);
    // Nothing at or past i_size is installable; clamp the window to
    // the pages that begin below EOF, exactly the set the per-page
    // loop's `>= size` skip admitted.
    let owner_file_offset = fault_offset - fault_index * 4096;
    let size = ops.stat().size;
    if size <= owner_file_offset {
        return;
    }
    window_last = window_last.min((size - owner_file_offset).div_ceil(4096));
    if window_last <= window_first {
        return;
    }
    let first_va = owner_base + window_first * 4096;
    let pages = window_last - window_first;
    // SAFETY: `aspace` is the space active on this CPU (identity
    // checked above) inside its own page fault, so its root is the
    // live one and paging is enabled — the batch's contract, and the
    // same one the trap path's `demand_page` call on this fault
    // satisfies. The result is advisory and discarded by design (see
    // above).
    let _ = unsafe { aspace.demand_alloc_range(narf_memory::VirtAddr::new(first_va), pages) };
}

/// `vmf_error`: `-ENOMEM` waits for reclaim and retries (`VM_FAULT_OOM`);
/// every other filesystem error is `VM_FAULT_SIGBUS`.
fn fault_error(error: FsError) -> FileFaultError {
    match error {
        FsError::OutOfMemory => FileFaultError::NoMemory,
        _ => FileFaultError::Bus,
    }
}

/// Whether the canonical cache already holds a page a fault for
/// `(identity, offset)` would reuse: the same validity rule
/// [`reserve_cached_shared_file_pages`] applies (a mapped or pending page
/// counts regardless of generation; an idle one must still carry the
/// file's current generation), but without taking a pending hold, so a
/// population scan does not perturb the retention state it is only
/// observing.
fn shared_file_page_present(identity: SharedFileIdentity, offset: u64, generation: u64) -> bool {
    let pages = SHARED_FILE_PAGES.lock();
    let key = SharedFilePages::key(identity, offset);
    let Some(&phys) = pages.by_file.get(&key) else {
        return false;
    };
    let Some(page) = pages.by_phys.get(&phys) else {
        return false;
    };
    shared_page_matches_ops(page, identity)
        && (page.mappings != 0 || page.pending != 0 || page.cache_generation == Some(generation))
}

/// Populate the shared page cache for `[offset, offset + len)` of a
/// generic-fallback file without mapping anything: the `readahead(2)` /
/// `MADV_WILLNEED` primitive (#731). Each missing page is filled by the
/// fault path's own machinery — [`load_file_demand_page`] then
/// [`publish_shared_file_pages`] — so a populated page is
/// indistinguishable from a fault-filled one: same EOF clamping (the
/// final partial page is filled exactly as a fault fills it, nothing is
/// loaded at or past `i_size`), same generation stamp, same
/// `note_file_written` fold and invalidation afterwards. A page already
/// present is never reloaded or overwritten, and population never
/// dirties anything.
///
/// Retention is inherited from the cache discipline, not reinvented:
/// only a filesystem that opted into a cache generation can keep an
/// idle populated page (see [`should_retire_idle_shared_page`]), so
/// files without one — and direct `mmap_fault` providers, whose pages
/// are provider-owned and never consult this cache — are deliberate
/// no-ops. Advisory throughout: the first fill error stops the scan
/// and is not reported, mirroring Linux `page_cache_ra`, which treats
/// readahead I/O failure as "the fault will surface it later". Returns
/// the number of pages newly populated.
///
/// Locking mirrors [`demand_frame`]: no cache or owner lock is held
/// across the fill I/O (`load_file_demand_page` may park in
/// `poll_io_to_completion`); the cache lock is taken only inside the
/// presence check and the publication, in the fault path's order.
pub(crate) fn populate_file_cache(ops: &Arc<dyn FileOps>, offset: u64, len: u64) -> u64 {
    if len == 0 || ops.supports_mmap_fault() {
        return 0;
    }
    let Some(generation) = ops.mmap_cache_generation() else {
        return 0;
    };
    let size = ops.stat().size;
    let first = offset & !0xFFF;
    let end = offset.saturating_add(len).min(size);
    if end <= first {
        return 0;
    }
    let identity = shared_file_identity(ops.as_ref());
    let mut populated = 0u64;
    let mut page = first;
    while page < end {
        if !shared_file_page_present(identity, page, generation) {
            let mut candidates = Vec::new();
            if candidates.try_reserve_exact(1).is_err() {
                break;
            }
            let candidate = match crate::handlers::load_file_demand_page(ops, page) {
                Ok(frame) => frame,
                Err(_) => break,
            };
            candidates.push(candidate);
            let (_phys, publication) =
                publish_shared_file_pages(ops, page, candidates, Some(generation));
            publication.commit();
            populated += 1;
        }
        page += 4096;
    }
    populated
}

/// Populate the cache behind the generic-fallback shared owners that
/// cover `[base, base + len)` of an address space — the `MADV_WILLNEED`
/// walk. The owner bucket lock is dropped after snapshotting the
/// covering owners (Arc clones only, no FileOps calls under the lock),
/// and each owner's intersection is populated through
/// [`populate_file_cache`], clamped per owner to its mapping and, inside
/// the primitive, to the file's current `i_size`. Private mappings are
/// skipped (their faults copy through `load_file_demand_page` directly
/// and never consult this cache) and so are direct-provider owners
/// (no writeback state); anonymous ranges have no owner and are a no-op.
pub(crate) fn populate_mapped_range(address_space_id: u64, base: u64, len: u64) {
    let Some(bucket) = existing_mapping_owners(address_space_id) else {
        return;
    };
    let owners: Vec<(u64, u64, u64, Arc<dyn FileOps>)> = {
        let owners = bucket.lock();
        owners
            .iter()
            .filter(|mapping| mapping.writeback.is_some() && !mapping.private_copy)
            .map(|mapping| {
                (
                    mapping.base,
                    mapping.len,
                    mapping.file_offset,
                    Arc::clone(&mapping.ops),
                )
            })
            .collect()
    };
    let end = base.saturating_add(len);
    for (owner_base, owner_len, file_offset, ops) in owners {
        let start = base.max(owner_base);
        let stop = end.min(owner_base.saturating_add(owner_len));
        if start < stop {
            populate_file_cache(&ops, file_offset + (start - owner_base), stop - start);
        }
    }
}

/// Why a strict population — `MADV_POPULATE_READ` /
/// `MADV_POPULATE_WRITE` — did not complete. The variants carry the
/// syscall's errno mapping: `Invalid` is Linux's `EINVAL`,
/// `NoMemory` its `ENOMEM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PopulateError {
    Invalid,
    NoMemory,
}

fn note_populate_error(slot: &mut Option<PopulateError>, error: PopulateError) {
    if slot.is_none() {
        *slot = Some(error);
    }
}

/// The owner-table class of one page, for the strict populate walk.
/// Only three shapes can appear behind a `FILE_DEMAND` region: a
/// generic-fallback or private-copy file (a fault fills it from the
/// file), a direct provider whose backing is RAM (a fault fills it
/// through the provider), and a direct provider aliasing device
/// memory — the `VM_IO` / `VM_PFNMAP` analogue, which Linux refuses
/// to populate with `EINVAL`.
enum OwnerClass {
    /// No file owner covers the page (anonymous, or an ownerless
    /// region whose pages the batch claim will simply refuse).
    None,
    File,
    Provider,
    Device,
}

fn classify_owner(address_space_id: u64, page: u64) -> OwnerClass {
    let Some(bucket) = existing_mapping_owners(address_space_id) else {
        return OwnerClass::None;
    };
    // Snapshot under the lock; the one trait call happens after it
    // drops, as everywhere else in this file (`mmap_is_ram` is a
    // constant leaf getter, but the discipline costs nothing).
    let snapshot = {
        let owners = bucket.lock();
        owners
            .iter()
            .find(|mapping| page >= mapping.base && page < mapping.base.saturating_add(mapping.len))
            .map(|owner| {
                (
                    owner.private_copy,
                    owner.writeback.is_some(),
                    Arc::clone(&owner.ops),
                )
            })
    };
    let Some((private_copy, has_writeback, ops)) = snapshot else {
        return OwnerClass::None;
    };
    if private_copy || has_writeback {
        return OwnerClass::File;
    }
    // A direct provider: its fault path serves pages itself. RAM
    // backing (memfs-class) is populatable exactly like a file;
    // device backing is not page-table populatable at all.
    if ops.mmap_is_ram() {
        OwnerClass::Provider
    } else {
        OwnerClass::Device
    }
}

/// The man page's permission rule for one segment: `POPULATE_READ`
/// cannot be applied to a mapping without read permission,
/// `POPULATE_WRITE` not to one without write permission, and a
/// `PROT_NONE` segment has neither.
fn populate_perm_error(perms: RegionPerms, write: bool) -> Option<PopulateError> {
    if perms.prot_only().0 == 0 {
        return Some(PopulateError::Invalid);
    }
    if write {
        if !perms.contains(RegionPerms::WRITE) {
            return Some(PopulateError::Invalid);
        }
    } else if !perms.contains(RegionPerms::READ) {
        return Some(PopulateError::Invalid);
    }
    None
}

/// Resolve one backed COW page to its private writable copy — the
/// populate-write half of the COW contract. The batch claim skips
/// backed pages by design (a peer's leaf is that peer fault's
/// business), so a page left COW-shared by fork is *present* after
/// the batch yet not *writable*, and Linux's guarantee for
/// `MADV_POPULATE_WRITE` — if it succeeds, the pages were populated
/// writable once — is only met once the split has happened. This is
/// the same resolve the supervisor-write path uses
/// (`AddressSpace::user_page_writable_or_resolve`): split in place,
/// rewrite the leaf, report `false` only for a genuinely read-only
/// mapping, which a `WRITE` region never is.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn resolve_cow_page(aspace: &AddressSpace, va: u64) -> bool {
    // SAFETY: `aspace` is the caller's own space, live on this CPU in
    // syscall context (the `populate_range` contract); `va` is a
    // backed page of a COW region in it.
    unsafe { aspace.user_page_writable_or_resolve(VirtAddr::new(va)) }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn resolve_cow_page(_aspace: &AddressSpace, _va: u64) -> bool {
    // No kernel target outside x86_64/aarch64 exists today; report
    // the page unresolved (the caller fails the range with ENOMEM)
    // rather than claim a writability this build cannot establish.
    false
}

/// Populate `[base, base + len)` of the caller's own address space —
/// the strict walk behind `MADV_POPULATE_READ` (`write == false`) and
/// `MADV_POPULATE_WRITE` (`write == true`), #741.
///
/// Where `MADV_WILLNEED` populates the *cache* and stops, POPULATE
/// must leave the pages *installed*: the successful return is the
/// caller's guarantee that the whole range can be touched without a
/// major fault. The walk is Linux-shaped (`mm/madvise.c::
/// madvise_populate` over `madvise_walk_vmas`): segments are
/// processed per VMA in address order, the first error in that order
/// is the one returned, and processing continues past a failed
/// segment — pages populated before (or after) a failure stay
/// populated, which the man page states outright ("if population
/// fails, some page tables might have been populated").
///
/// Per segment, in order:
///
/// 1. **Validate** — the permission rule ([`populate_perm_error`])
///    and, for a `FILE_DEMAND` segment, the device refusal
///    ([`classify_owner`]).
/// 2. **Install** — one [`AddressSpace::demand_alloc_range`] batch
///    for the segment's missing pages. The batch is advisory (it
///    reports a count, never an error, and skips backed / in-flight /
///    guarded / swap-owned pages), so its count is *not* the
///    success criterion — step 4 is.
/// 3. **Resolve** (`write` only) — every backed page of a `COW`
///    segment is split to its private writable copy
///    ([`resolve_cow_page`]); `POPULATE_READ` deliberately leaves
///    COW sharing intact, as a read fault would.
/// 4. **Verify** — every page of the segment must report resident
///    backing through `AddressSpace::page_backing`. This single
///    check is what turns the advisory batch into the all-or-nothing
///    return: a hole in coverage, a fill the hook refused (a page at
///    or past `i_size` — the batch hook answers it exactly as a
///    fault does, with `Bus`, so a range extending past EOF fails
///    here with `ENOMEM`; `madvise` itself never raises the
///    `SIGBUS` a touch would), a swap-owned page, and a guard page
///    all leave the slot empty and fail the range the same way.
///
/// Known limits, all deliberate: swap-owned pages are *not* swapped
/// in by the walk (the single-fault path owns that transaction; a
/// later touch faults them in), so a range containing one reports
/// `ENOMEM` where Linux — which swaps in on populate — would
/// succeed. Guard markers are checked separately from backing: a shared
/// page can retain its frame while its leaf is deliberately inaccessible.
///
/// # Safety contract
/// `aspace` must be the caller's own address space with its root live
/// on this CPU — the ordinary syscall context, the same contract
/// `sys_mmap`'s eager population and `mlock`'s population already
/// rely on when they drive the demand paths. It must never be a
/// ptrace tracee's space (that path keeps single-page service).
pub(crate) fn populate_range(
    aspace: &AddressSpace,
    base: u64,
    len: u64,
    write: bool,
) -> Result<(), PopulateError> {
    let address_space_id = aspace.identity();
    // Pre-warm the shared cache for the generic owners in the range,
    // exactly as MADV_WILLNEED does, so the batch fills below find
    // their pages already canonical instead of re-reading them
    // through the hook one by one. Advisory only — installation,
    // not the cache, is this walk's guarantee.
    populate_mapped_range(address_space_id, base, len);
    let end = base.saturating_add(len);
    let mut first_error: Option<PopulateError> = None;
    let mut cur = base;
    while cur < end {
        let Some(region) = aspace.lookup(VirtAddr::new(cur)) else {
            // No ordinary region covers this page. A hardware-huge
            // region is installed whole at mmap time, so a page it
            // backs is populated by construction (its perms still
            // take the permission rule); anything else is a hole.
            match aspace.page_backing(VirtAddr::new(cur)) {
                Some((perms, phys)) if phys.raw() != 0 => {
                    if let Some(error) = populate_perm_error(perms, write) {
                        note_populate_error(&mut first_error, error);
                    }
                }
                _ => note_populate_error(&mut first_error, PopulateError::NoMemory),
            }
            cur = cur.saturating_add(4096);
            continue;
        };
        let seg_end = end.min(region.base.as_u64().saturating_add(region.len));
        let perms = region.perms;
        if let Some(error) = populate_perm_error(perms, write) {
            note_populate_error(&mut first_error, error);
            cur = seg_end;
            continue;
        }
        if perms.contains(RegionPerms::FILE_DEMAND)
            && matches!(classify_owner(address_space_id, cur), OwnerClass::Device)
        {
            note_populate_error(&mut first_error, PopulateError::Invalid);
            cur = seg_end;
            continue;
        }
        // Install the segment's missing pages as one batch (#737):
        // claim set taken atomically, fills outside the lock, each
        // page published through the single fault's own transaction,
        // so an installed page is indistinguishable from a faulted
        // one. The count is deliberately discarded — step 4 decides.
        // SAFETY: the caller's own space, live on this CPU in
        // syscall context (see the contract above); the batch never
        // serves a faulting page and cannot fail the caller.
        let _ = unsafe { aspace.demand_alloc_range(VirtAddr::new(cur), (seg_end - cur) / 4096) };
        if write && perms.contains(RegionPerms::COW) {
            let mut va = cur;
            while va < seg_end {
                if !aspace.is_guard_page(VirtAddr::new(va))
                    && aspace
                        .page_backing(VirtAddr::new(va))
                        .is_some_and(|(_, phys)| phys.raw() != 0)
                    && !resolve_cow_page(aspace, va)
                {
                    note_populate_error(&mut first_error, PopulateError::NoMemory);
                }
                va = va.saturating_add(4096);
            }
        }
        let mut va = cur;
        while va < seg_end {
            if aspace.is_guard_page(VirtAddr::new(va)) {
                note_populate_error(&mut first_error, PopulateError::NoMemory);
                va = va.saturating_add(4096);
                continue;
            }
            match aspace.page_backing(VirtAddr::new(va)) {
                Some((_, phys)) if phys.raw() != 0 => {}
                _ => note_populate_error(&mut first_error, PopulateError::NoMemory),
            }
            va = va.saturating_add(4096);
        }
        cur = seg_end;
    }
    match first_error {
        None => Ok(()),
        Some(error) => Err(error),
    }
}

/// Publish freshly loaded fallback pages into the process-independent file
/// page cache. A concurrent/overlapping mapper may already have published a
/// page; in that case use its physical page and return the unused allocation
/// to the frame allocator.
pub(crate) fn publish_shared_file_pages(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    candidates: Vec<PhysAddr>,
    expected_generation: Option<u64>,
) -> (Vec<PhysAddr>, SharedFilePublication) {
    // Snapshot candidate contents before entering the IRQ-safe cache lock.
    // A candidate selected as canonical consumes its image; a losing
    // candidate drops the unused Vec outside the critical section.
    let mut prepared = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        // SAFETY: every candidate is a freshly allocated, identity-mapped
        // fallback page owned by this publication attempt.
        let clean =
            unsafe { core::slice::from_raw_parts(candidate.kernel_ptr::<u8>(), 4096).to_vec() };
        prepared.push((candidate, clean));
    }
    let mut rejected = Vec::with_capacity(prepared.len());
    let mut retired = Vec::new();
    let mut canonical = Vec::with_capacity(prepared.len());
    let cache_generation =
        expected_generation.filter(|generation| ops.mmap_cache_generation() == Some(*generation));
    let identity = shared_file_identity(ops.as_ref());
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        for (index, (candidate, clean)) in prepared.into_iter().enumerate() {
            let page_offset = offset
                .checked_add(index as u64 * 4096)
                .expect("validated mmap file offset overflowed");
            let key = SharedFilePages::key(identity, page_offset);
            let mut existing = pages.by_file.get(&key).copied().filter(|phys| {
                pages.by_phys.get(phys).is_some_and(|page| {
                    shared_page_matches_ops(page, identity)
                        && (page.mappings != 0
                            || page.pending != 0
                            || (cache_generation.is_some()
                                && page.cache_generation == cache_generation))
                })
            });
            if existing.is_none() && pages.by_file.contains_key(&key) {
                let stale_phys = pages.by_file[&key];
                // A dirty idle page holds MAP_SHARED writes no flush has
                // committed yet. Adopt it as canonical — refreshing its
                // generation — rather than freeing the only copy of those
                // writes to make room for a stale device read.
                let adopt = pages.by_phys.get(&stale_phys).is_some_and(|page| {
                    shared_page_matches_ops(page, identity) && !shared_page_is_clean(page)
                });
                if adopt {
                    let page = pages
                        .by_phys
                        .get_mut(&stale_phys)
                        .expect("shared-file key points to no physical page");
                    page.cache_generation = cache_generation;
                    existing = Some(stale_phys);
                } else {
                    let stale = pages
                        .remove_phys(stale_phys)
                        .expect("shared-file key points to no physical page");
                    debug_assert_eq!(stale.mappings, 0);
                    debug_assert_eq!(stale.pending, 0);
                    retired.push(stale.phys);
                }
            }
            let phys = if let Some(phys) = existing {
                let phys = PhysAddr::new(phys);
                canonical.push(phys);
                if candidate.raw() != phys.raw() {
                    rejected.push(candidate);
                }
                phys
            } else {
                let phys = candidate.raw();
                assert!(
                    pages
                        .by_phys
                        .insert(
                            phys,
                            SharedFilePage {
                                ops: Arc::downgrade(ops),
                                identity,
                                offset: page_offset,
                                phys: candidate,
                                mappings: 0,
                                pending: 0,
                                cache_generation,
                                clean,
                            },
                        )
                        .is_none(),
                    "shared-file physical page was already indexed"
                );
                assert!(
                    pages.by_file.insert(key, phys).is_none(),
                    "shared-file key was already indexed"
                );
                canonical.push(candidate);
                candidate
            };
            let page = pages
                .by_phys
                .get_mut(&phys.raw())
                .expect("shared-file key points to no physical page");
            retain_pending_shared_page(page);
        }
        // Bound the retained set while this publication already holds the
        // cache lock: past the cap, clean idle pages are evicted. Dirty
        // pages are never eviction candidates — they leave only through
        // the flush lifecycle, after which they are clean and evictable.
        if pages.by_phys.len() > MAX_RETAINED_SHARED_FILE_PAGES {
            let excess = pages.by_phys.len() - MAX_RETAINED_SHARED_FILE_PAGES;
            let victims: Vec<u64> = pages
                .by_phys
                .values()
                .filter(|page| {
                    page.mappings == 0 && page.pending == 0 && shared_page_is_clean(page)
                })
                .map(|page| page.phys.raw())
                .take(excess)
                .collect();
            for phys in victims {
                let evicted = pages
                    .remove_phys(phys)
                    .expect("evicted shared-file page disappeared");
                retired.push(evicted.phys);
            }
        }
    }
    for phys in rejected.into_iter().chain(retired) {
        if phys.raw() != 0 {
            narf_memory::free_frame(narf_memory::PhysFrame::new(phys));
        }
    }
    let receipt = SharedFilePublication {
        phys: canonical.clone(),
        active: true,
    };
    (canonical, receipt)
}

/// Memory's `RegionPerms::SHARED` hooks call these to tie each mapped alias to
/// the fallback page cache's lifetime. Return false for non-file-cache pages
/// so the System V shared-memory registry can handle them instead.
pub(crate) fn retain_shared_file_page(phys: u64) -> bool {
    let mut pages = SHARED_FILE_PAGES.lock();
    let Some(page) = pages.by_phys.get_mut(&phys) else {
        return false;
    };
    page.mappings = page
        .mappings
        .checked_add(1)
        .expect("shared-file mapping hold overflow");
    true
}

pub(crate) fn release_shared_file_page(phys: u64) -> bool {
    let retired = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let cache_len = pages.by_phys.len();
        let Some(page) = pages.by_phys.get_mut(&phys) else {
            return false;
        };
        assert!(page.mappings != 0, "shared-file mapping hold underflow");
        page.mappings -= 1;
        if page.mappings != 0 || page.pending != 0 {
            return true;
        }
        if should_retire_idle_shared_page(page, cache_len) {
            Some(
                pages
                    .remove_phys(phys)
                    .expect("unreferenced shared-file page disappeared"),
            )
        } else {
            None
        }
    };
    if let Some(page) = retired {
        narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
    }
    true
}

fn register(
    address_space_id: u64,
    base: u64,
    len: u64,
    file_offset: u64,
    ops: Arc<dyn FileOps>,
    lifetime: Option<Arc<dyn MmapLifetime>>,
    writeback: Option<FileWriteback>,
) {
    mapping_owners(address_space_id).lock().push(MappingOwner {
        base,
        len,
        file_offset,
        ops,
        lifetime,
        private_copy: false,
        writeback,
        // Not an ELF segment: no `padzero` window.
        zero_from: None,
        provenance: None,
    });
}

pub(crate) fn unmap_current(base: u64) {
    if let Some(owners) = current_address_space_id().and_then(existing_mapping_owners) {
        owners.lock().retain(|mapping| mapping.base != base);
    }
}

/// Mirror `AddressSpace::punch_fixed` splitting for an explicit address-space
/// identity. Syscall paths use `publish_current_punch` so VMA and owner
/// publication remain one transaction; this form supports lifecycle tests.
fn punch(address_space_id: u64, base: u64, len: u64) {
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return;
    };
    let mut owners = owner_bucket.lock();
    punch_locked(&mut owners, base, len);
}

/// Fallibly clone every file-owner slice intersecting the remap source. The
/// returned rows are rebased at `new_addr` but remain unpublished until memory
/// reports success. Holes are intentional: anonymous shared portions have no
/// file-owner row and are owned entirely by the memory/shared-frame layer.
fn prepare_aliases_locked(
    owners: &[MappingOwner],
    old_addr: u64,
    new_addr: u64,
    len: u64,
) -> Result<Vec<MappingOwner>, AddressSpaceError> {
    let old_end = old_addr
        .checked_add(len)
        .ok_or(AddressSpaceError::OutOfRange)?;
    let new_end = new_addr
        .checked_add(len)
        .ok_or(AddressSpaceError::OutOfRange)?;
    let count = owners
        .iter()
        .filter(|mapping| {
            mapping
                .base
                .checked_add(mapping.len)
                .is_some_and(|end| mapping.base < old_end && old_addr < end)
        })
        .count();
    let mut aliases = Vec::new();
    aliases
        .try_reserve_exact(count)
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    for mapping in owners {
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        let source_base = mapping.base.max(old_addr);
        let source_end = mapping_end.min(old_end);
        if source_base >= source_end {
            continue;
        }
        let source_offset = source_base - mapping.base;
        let alias_offset = source_base - old_addr;
        let alias_base = new_addr
            .checked_add(alias_offset)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let alias_len = source_end - source_base;
        let file_offset = mapping
            .file_offset
            .checked_add(source_offset)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let writeback = if let Some(original) = mapping.writeback.as_ref() {
            if source_offset & 0xfff != 0 || alias_len & 0xfff != 0 {
                return Err(AddressSpaceError::AlignmentMismatch);
            }
            let first = usize::try_from(source_offset >> 12)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            let pages = usize::try_from(alias_len >> 12)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            let phys = clone_writeback_window(&original.phys, first, pages)?;
            Some(FileWriteback {
                offset: original
                    .offset
                    .checked_add(source_offset)
                    .ok_or(AddressSpaceError::OutOfRange)?,
                phys,
            })
        } else {
            None
        };
        aliases.push(MappingOwner {
            base: alias_base,
            len: alias_len,
            file_offset,
            ops: Arc::clone(&mapping.ops),
            lifetime: mapping.lifetime.clone(),
            private_copy: mapping.private_copy,
            zero_from: mapping.zero_from,
            provenance: mapping.provenance.clone(),
            writeback,
        });
    }
    // A Region has exactly one backing kind. Once any file owner intersects
    // the source, owner rows must form one exact, non-overlapping partition of
    // the whole source range. Treating a hole as anonymous would publish a
    // FILE_DEMAND VMA whose fault hook has no owner; accepting overlap would
    // make fault lookup depend on Vec order and could select the wrong file.
    if !aliases.is_empty() {
        aliases.sort_unstable_by_key(|mapping| mapping.base);
        let mut cursor = new_addr;
        for alias in &aliases {
            if alias.base < cursor {
                return Err(AddressSpaceError::Overlap);
            }
            if alias.base > cursor {
                return Err(AddressSpaceError::Unmapped);
            }
            cursor = cursor
                .checked_add(alias.len)
                .ok_or(AddressSpaceError::OutOfRange)?;
        }
        if cursor != new_end {
            return Err(AddressSpaceError::Unmapped);
        }
    }
    Ok(aliases)
}

fn owner_range_intersects(owners: &[MappingOwner], base: u64, len: u64) -> bool {
    let Some(end) = base.checked_add(len) else {
        return false;
    };
    owners.iter().any(|mapping| {
        mapping
            .base
            .checked_add(mapping.len)
            .is_some_and(|mapping_end| mapping.base < end && base < mapping_end)
    })
}

/// Fallibly prepare the destination file-owner partition for an ordinary
/// move. If any file owner intersects the source, owner rows must cover the
/// entire old interval exactly. This is the file-owner equivalent of memory's
/// one-Region rule: accepting a hole would leave FILE_DEMAND faults without a
/// backing object after the move.
fn prepare_relocated_owners_locked(
    owners: &[MappingOwner],
    old_addr: u64,
    old_len: u64,
    new_addr: u64,
    new_len: u64,
) -> Result<Vec<MappingOwner>, AddressSpaceError> {
    let old_end = old_addr
        .checked_add(old_len)
        .ok_or(AddressSpaceError::OutOfRange)?;
    let kept_len = core::cmp::min(old_len, new_len);
    let kept_end = old_addr
        .checked_add(kept_len)
        .ok_or(AddressSpaceError::OutOfRange)?;
    let new_end = new_addr
        .checked_add(new_len)
        .ok_or(AddressSpaceError::OutOfRange)?;
    let count = owners
        .iter()
        .filter(|mapping| {
            mapping
                .base
                .checked_add(mapping.len)
                .is_some_and(|end| mapping.base < old_end && old_addr < end)
        })
        .count();
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut source_ranges = Vec::new();
    source_ranges
        .try_reserve_exact(count)
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    let mut destination = Vec::new();
    destination
        .try_reserve_exact(count)
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    for mapping in owners {
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        let source_base = mapping.base.max(old_addr);
        let source_end = mapping_end.min(old_end);
        if source_base >= source_end {
            continue;
        }
        source_ranges.push((source_base, source_end));

        let kept_base = source_base;
        let kept_mapping_end = source_end.min(kept_end);
        if kept_base >= kept_mapping_end {
            continue;
        }
        let source_offset = kept_base - mapping.base;
        let destination_base = new_addr
            .checked_add(kept_base - old_addr)
            .ok_or(AddressSpaceError::OutOfRange)?;
        let destination_len = kept_mapping_end - kept_base;
        let writeback = if let Some(original) = mapping.writeback.as_ref() {
            let first = usize::try_from(source_offset >> 12)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            let pages = usize::try_from(destination_len >> 12)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            let phys = clone_writeback_window(&original.phys, first, pages)?;
            Some(FileWriteback {
                offset: original
                    .offset
                    .checked_add(source_offset)
                    .ok_or(AddressSpaceError::OutOfRange)?,
                phys,
            })
        } else {
            None
        };
        destination.push(MappingOwner {
            base: destination_base,
            len: destination_len,
            file_offset: mapping
                .file_offset
                .checked_add(source_offset)
                .ok_or(AddressSpaceError::OutOfRange)?,
            ops: Arc::clone(&mapping.ops),
            lifetime: mapping.lifetime.clone(),
            private_copy: mapping.private_copy,
            zero_from: mapping.zero_from,
            provenance: mapping.provenance.clone(),
            writeback,
        });
    }

    source_ranges.sort_unstable_by_key(|range| range.0);
    let mut cursor = old_addr;
    for &(base, end) in &source_ranges {
        if base != cursor || end <= base {
            return Err(if base < cursor {
                AddressSpaceError::Overlap
            } else {
                AddressSpaceError::Unmapped
            });
        }
        cursor = end;
    }
    if cursor != old_end {
        return Err(AddressSpaceError::Unmapped);
    }

    destination.sort_unstable_by_key(|mapping| mapping.base);
    if new_len > old_len {
        let tail = destination.last_mut().ok_or(AddressSpaceError::Unmapped)?;
        let delta = new_len - old_len;
        if tail.base.saturating_add(tail.len) != new_addr + old_len {
            return Err(AddressSpaceError::Unmapped);
        }
        tail.len = tail
            .len
            .checked_add(delta)
            .ok_or(AddressSpaceError::OutOfRange)?;
    }
    let mut cursor = new_addr;
    for mapping in &destination {
        if mapping.base != cursor || mapping.len == 0 {
            return Err(AddressSpaceError::Unmapped);
        }
        cursor = cursor
            .checked_add(mapping.len)
            .ok_or(AddressSpaceError::OutOfRange)?;
    }
    if cursor != new_end {
        return Err(AddressSpaceError::Unmapped);
    }
    Ok(destination)
}

fn prepare_punch_suffixes_locked(
    owners: &[MappingOwner],
    base: u64,
    len: u64,
) -> Result<Vec<MappingOwner>, AddressSpaceError> {
    let end = base.checked_add(len).ok_or(AddressSpaceError::OutOfRange)?;
    let split_count = owners
        .iter()
        .filter(|mapping| {
            mapping
                .base
                .checked_add(mapping.len)
                .is_some_and(|mapping_end| mapping.base < base && mapping_end > end)
        })
        .count();
    let mut suffixes = Vec::new();
    suffixes
        .try_reserve_exact(split_count)
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    for mapping in owners.iter() {
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        if mapping.base >= base || mapping_end <= end {
            continue;
        }
        let mut writeback = None;
        if let Some(original) = mapping.writeback.as_ref() {
            let skip = ((end - mapping.base) / 4096) as usize;
            let tail = original.phys.get(skip..).unwrap_or_default();
            let mut phys = Vec::new();
            phys.try_reserve_exact(tail.len())
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            phys.extend_from_slice(tail);
            writeback = Some(FileWriteback {
                offset: original.offset.saturating_add(end - mapping.base),
                phys,
            });
        }
        suffixes.push(MappingOwner {
            base: end,
            len: mapping_end - end,
            file_offset: mapping.file_offset.saturating_add(end - mapping.base),
            ops: Arc::clone(&mapping.ops),
            lifetime: mapping.lifetime.clone(),
            private_copy: mapping.private_copy,
            zero_from: mapping.zero_from,
            provenance: mapping.provenance.clone(),
            writeback,
        });
    }
    Ok(suffixes)
}

/// Reserve every allocation required to split owner metadata before the
/// corresponding memory punch can become destructive. Only a mapping which
/// survives on both sides needs a new owner row and a copied writeback tail.
fn prepare_punch_locked(
    owners: &mut Vec<MappingOwner>,
    base: u64,
    len: u64,
    additional_rows: usize,
) -> Result<Vec<MappingOwner>, AddressSpaceError> {
    let suffixes = prepare_punch_suffixes_locked(owners, base, len)?;
    owners
        .try_reserve_exact(
            suffixes
                .len()
                .checked_add(additional_rows)
                .ok_or(AddressSpaceError::AllocationFailed)?,
        )
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    Ok(suffixes)
}

/// Apply a punch after [`prepare_punch_locked`] has made every split
/// allocation infallible. Order is not semantically significant; fault lookup
/// selects by range.
fn commit_prepared_punch_locked(
    owners: &mut Vec<MappingOwner>,
    base: u64,
    len: u64,
    suffixes: Vec<MappingOwner>,
) {
    let end = base
        .checked_add(len)
        .expect("prepared owner punch range changed");
    let original_count = owners.len();
    let mut index = 0usize;
    let mut suffixes = suffixes.into_iter();
    let mut visited = 0usize;
    while visited < original_count {
        visited += 1;
        let mapping_end = owners[index].base.saturating_add(owners[index].len);
        if mapping_end <= base || owners[index].base >= end {
            index += 1;
            continue;
        }
        if owners[index].base < base {
            let split = mapping_end > end;
            owners[index].len = base - owners[index].base;
            let prefix_pages = (owners[index].len / 4096) as usize;
            if let Some(writeback) = owners[index].writeback.as_mut() {
                writeback.phys.truncate(prefix_pages);
            }
            index += 1;
            if split {
                owners.push(suffixes.next().expect("prepared owner suffix disappeared"));
            }
        } else if mapping_end > end {
            let skipped = end - owners[index].base;
            owners[index].base = end;
            owners[index].len = mapping_end - end;
            owners[index].file_offset = owners[index].file_offset.saturating_add(skipped);
            if let Some(writeback) = owners[index].writeback.as_mut() {
                let pages = (skipped / 4096) as usize;
                writeback.offset = writeback.offset.saturating_add(skipped);
                writeback.phys.drain(..pages.min(writeback.phys.len()));
            }
            index += 1;
        } else {
            owners.swap_remove(index);
        }
    }
    assert!(suffixes.next().is_none(), "unused prepared owner suffix");
}

fn punch_locked(owners: &mut Vec<MappingOwner>, base: u64, len: u64) {
    let Some(end) = base.checked_add(len) else {
        return;
    };
    let old = core::mem::take(&mut *owners);
    for mut mapping in old {
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        if mapping_end <= base || mapping.base >= end {
            owners.push(mapping);
            continue;
        }
        if mapping.base < base {
            let original_base = mapping.base;
            let suffix = if mapping_end > end {
                let mut suffix = MappingOwner {
                    base: end,
                    len: mapping_end - end,
                    // The suffix starts `end - original_base` further into the
                    // file, exactly as its writeback offset below does. A
                    // stale offset here would fault the wrong page of the file
                    // into the surviving half of a punched mapping.
                    file_offset: mapping.file_offset.saturating_add(end - original_base),
                    ops: Arc::clone(&mapping.ops),
                    lifetime: mapping.lifetime.clone(),
                    private_copy: mapping.private_copy,
                    zero_from: mapping.zero_from,
                    provenance: mapping.provenance.clone(),
                    writeback: mapping.writeback.clone(),
                };
                if let Some(wb) = suffix.writeback.as_mut() {
                    let skip = ((end - original_base) / 4096) as usize;
                    wb.offset = wb.offset.saturating_add(end - original_base);
                    wb.phys = wb.phys.get(skip..).unwrap_or_default().to_vec();
                }
                Some(suffix)
            } else {
                None
            };
            mapping.len = base - mapping.base;
            if let Some(wb) = mapping.writeback.as_mut() {
                wb.phys.truncate((mapping.len / 4096) as usize);
            }
            owners.push(mapping);
            if let Some(suffix) = suffix {
                owners.push(suffix);
            }
        } else if mapping_end > end {
            let skipped = end - mapping.base;
            mapping.base = end;
            mapping.len = mapping_end - end;
            mapping.file_offset = mapping.file_offset.saturating_add(skipped);
            if let Some(wb) = mapping.writeback.as_mut() {
                let pages = (skipped / 4096) as usize;
                wb.offset = wb.offset.saturating_add(skipped);
                wb.phys = wb.phys.get(pages..).unwrap_or_default().to_vec();
            }
            owners.push(mapping);
        }
    }
}

pub(crate) fn fork_address_space(parent_id: u64, child_id: u64) {
    if parent_id == child_id {
        return;
    }
    let Some(parent_bucket) = existing_mapping_owners(parent_id) else {
        return;
    };
    let inherited: Vec<_> = parent_bucket
        .lock()
        .iter()
        .map(|mapping| MappingOwner {
            base: mapping.base,
            len: mapping.len,
            file_offset: mapping.file_offset,
            ops: Arc::clone(&mapping.ops),
            lifetime: mapping.lifetime.clone(),
            private_copy: mapping.private_copy,
            zero_from: mapping.zero_from,
            provenance: mapping.provenance.clone(),
            writeback: mapping.writeback.clone(),
        })
        .collect();
    mapping_owners(child_id).lock().extend(inherited);
}

fn owner_count(address_space_id: u64) -> usize {
    existing_mapping_owners(address_space_id)
        .map(|owners| owners.lock().len())
        .unwrap_or(0)
}

/// Commit all fallback `MAP_SHARED` pages of `ops` in the current process.
/// The kernel copies one page at a time before awaiting FileOps::write, so no
/// IRQ-safe mapping lock spans filesystem I/O and an unmap racing this flush
/// cannot free a page before its bytes have been snapshotted.
pub(crate) fn flush_current_file(ops: &Arc<dyn FileOps>) -> Result<(), ()> {
    // A task without an installed userspace address space cannot own any
    // mapped-file fallback pages. `fsync` is still valid for its open file;
    // treat the absent bucket as the same clean no-op as an empty bucket.
    if let Some(address_space_id) = current_address_space_id() {
        if let Some(owner_bucket) = existing_mapping_owners(address_space_id) {
            let mappings: Vec<FileWriteback> = owner_bucket
                .lock()
                .iter()
                .filter(|mapping| Arc::ptr_eq(&mapping.ops, ops))
                .filter_map(|mapping| mapping.writeback.clone())
                .collect();
            flush_mappings(ops, mappings)?;
        }
    }
    // fsync's contract covers the file, not the caller: pages of this file
    // retained under another address space's mappings (or under none, after
    // their owner unmapped) are just as much its responsibility.
    flush_shared_pages_for_ops(ops)
}

/// Commit the current process's fallback shared mappings overlapping
/// `[base, base + len)`. `msync` uses this range form; a zero length follows
/// Linux's no-op convention.
pub(crate) fn flush_current_range(base: u64, len: u64) -> Result<(), ()> {
    if len == 0 {
        return Ok(());
    }
    let Some(end) = base.checked_add(len) else {
        return Err(());
    };
    let address_space_id = current_address_space_id().ok_or(())?;
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return Ok(());
    };
    let (mappings, files) = {
        let owners = owner_bucket.lock();
        let mut mappings = Vec::new();
        let mut files: Vec<Arc<dyn FileOps>> = Vec::new();
        for mapping in owners
            .iter()
            .filter(|mapping| mapping.base < end && base < mapping.base.saturating_add(mapping.len))
        {
            if let Some(writeback) = mapping.writeback.clone() {
                mappings.push((Arc::clone(&mapping.ops), writeback));
            }
            if !mapping.private_copy && !files.iter().any(|file| Arc::ptr_eq(file, &mapping.ops)) {
                files.push(Arc::clone(&mapping.ops));
            }
        }
        (mappings, files)
    };
    for (ops, mapping) in mappings {
        flush_mappings(&ops, alloc::vec![mapping])?;
    }
    // Direct page-cache mappings have no fallback frames to copy. Their
    // filesystem marks faulted folios dirty, so msync completes by driving
    // that inode's ordinary writeback path after all fallback copies.
    for ops in files {
        match crate::handlers::poll_blocking(ops.fsync(false)) {
            Some(Ok(())) => {}
            _ => return Err(()),
        }
    }
    Ok(())
}

/// Linux `unmap_mapping_range` for a shrinking direct-mapped file. Zap the
/// page-aligned suffix of every VMA whose file offsets are wholly beyond
/// the new EOF — frames retired, VMAs kept, so a later grow lets the same
/// mapping fault the range back in (#691). Windows the memory zap cannot
/// retain (swap-backed, huge) fall back to full removal inside the zap
/// itself and are mirrored as punches in the owner rows. This runs before
/// the filesystem removes cache folios, balancing their external mapping
/// holds while the frames are still owned.
pub fn truncate_file_mappings(
    file: &dyn FileOps,
    new_len: u64,
) -> Result<(), narf_filesystem::FsError> {
    let first_invalid = new_len
        .checked_add(4095)
        .ok_or(narf_filesystem::FsError::InvalidData)?
        & !4095;
    let mut spaces = crate::handlers::all_address_spaces();
    if let Some(current) = crate::handlers::active_user_as() {
        if !spaces.iter().any(|space| Arc::ptr_eq(space, &current)) {
            spaces.push(current);
        }
    }

    for address_space in spaces {
        let id = address_space.identity();
        let Some(owner_bucket) = existing_mapping_owners(id) else {
            continue;
        };
        let result = address_space.with_vma_transaction(|| {
            narf_memory::with_address_space_shared_mapping_transaction(id, || {
                // Snapshot only after both transactions are held. Otherwise a
                // concurrent unmap/remap could replace one of these virtual
                // ranges between the identity check and the zap, and a file
                // truncation would tear down the unrelated replacement VMA.
                let ranges: Vec<(u64, u64)> = owner_bucket
                    .lock()
                    .iter()
                    .filter(|mapping| {
                        mapping.ops.mmap_backing_identity() == file.mmap_backing_identity()
                    })
                    .filter_map(|mapping| {
                        let file_end = mapping.file_offset.checked_add(mapping.len)?;
                        let invalid_offset = first_invalid.max(mapping.file_offset);
                        (invalid_offset < file_end).then(|| {
                            let base = mapping.base + (invalid_offset - mapping.file_offset);
                            (base, file_end - invalid_offset)
                        })
                    })
                    .collect();
                for (base, len) in ranges {
                    // The outcome is consumed by the owner mirror inside
                    // `publish_current_zap`; the truncate itself succeeds
                    // either way (retained-and-zapped, or removed by the
                    // zap's fallback punch).
                    let _ = publish_current_zap(id, base, len, || {
                        // SAFETY: the enclosing closures hold this address
                        // space's VMA and shared-owner transactions in order.
                        unsafe {
                            address_space.zap_mapping_range_locked_for_syscall_with_shared(
                                narf_memory::VirtAddr::new(base),
                                len,
                                true,
                            )
                        }
                    })?;
                }
                Ok::<(), AddressSpaceError>(())
            })
        });
        result.map_err(|_| narf_filesystem::FsError::OutOfMemory)?;
    }
    Ok(())
}

fn flush_mappings(ops: &Arc<dyn FileOps>, mappings: Vec<FileWriteback>) -> Result<(), ()> {
    for mapping in mappings {
        for (index, phys) in mapping.phys.iter().enumerate() {
            if phys.raw() == 0 {
                continue;
            }
            let offset = mapping.offset + (index as u64) * 4096;
            flush_shared_page(ops, offset, *phys)?;
        }
    }
    Ok(())
}

/// Commit one cached fallback page if its bytes differ from the file's.
/// The snapshot is taken under the cache lock; the write itself runs with
/// every lock released, exactly as in [`flush_mappings`].
fn flush_shared_page(ops: &Arc<dyn FileOps>, offset: u64, phys: PhysAddr) -> Result<(), ()> {
    let file_len = ops.stat().size;
    if offset >= file_len {
        return Ok(());
    }
    let len = ((file_len - offset) as usize).min(4096);
    let Some(bytes) = snapshot_dirty_page(ops, offset, phys, len) else {
        return Ok(());
    };
    let mut done = 0;
    while done < bytes.len() {
        match crate::handlers::poll_io_to_completion(
            ops.write(offset + done as u64, &bytes[done..]),
        ) {
            Some(Ok(0)) | Some(Err(_)) | None => return Err(()),
            Some(Ok(n)) => done += n,
        }
    }
    mark_page_clean(ops, offset, phys, &bytes);
    Ok(())
}

/// Commit every cached fallback page of `ops`'s file, whichever address
/// space — if any — currently maps it. The owner-bucket flushes only see
/// the calling process's own mappings; the cache is the one place that can
/// still reach a dirty page whose owner unmapped it, lives in another
/// process, or has already exited. Page selection follows the cache's own
/// `shared_page_matches_ops` identity rule.
pub(crate) fn flush_shared_pages_for_ops(ops: &Arc<dyn FileOps>) -> Result<(), ()> {
    let identity = shared_file_identity(ops.as_ref());
    let targets: Vec<(u64, PhysAddr)> = {
        let pages = SHARED_FILE_PAGES.lock();
        pages
            .by_phys
            .values()
            .filter(|page| shared_page_matches_ops(page, identity))
            .map(|page| (page.offset, page.phys))
            .collect()
    };
    for (offset, phys) in targets {
        flush_shared_page(ops, offset, phys)?;
    }
    Ok(())
}

/// Commit every dirty fallback page in the cache, across all files. This
/// is what gives `sync(2)` its global reach: dirty pages whose owning
/// process never calls fsync are still the kernel's responsibility.
pub(crate) fn flush_all_shared_file_pages() {
    let files: Vec<Arc<dyn FileOps>> = {
        let pages = SHARED_FILE_PAGES.lock();
        let mut files: Vec<Arc<dyn FileOps>> = Vec::new();
        let mut seen: Vec<SharedFileIdentity> = Vec::new();
        for page in pages.by_phys.values() {
            // Dedup on the page's recorded identity: asking a filesystem
            // for its identity may lock or allocate, which the cache lock
            // must never span.
            if seen.contains(&page.identity) {
                continue;
            }
            if let Some(ops) = page.ops.upgrade() {
                seen.push(page.identity);
                files.push(ops);
            }
        }
        files
    };
    for ops in files {
        // sync(2) has no per-file error channel; one failing file must not
        // stop the others from being committed.
        let _ = flush_shared_pages_for_ops(&ops);
    }
}

/// Fold a completed `write(2)`-family write into every cached fallback
/// page it overlaps, so live `MAP_SHARED` mappings observe the new bytes
/// and a later whole-page writeback cannot resurrect the pre-write image.
/// The written bytes become part of the page's clean snapshot — they are
/// already on the file — while bytes the write did not touch keep their
/// previous clean/dirty state. The cache generation is deliberately left
/// alone: an idle page whose generation a filesystem can no longer vouch
/// for must still fail reuse validation, exactly as before.
pub(crate) fn note_file_written(ops: &Arc<dyn FileOps>, offset: u64, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let identity = shared_file_identity(ops.as_ref());
    let mut done = 0usize;
    while done < bytes.len() {
        let cur = offset + done as u64;
        let page_offset = cur & !4095;
        let in_page = (cur - page_offset) as usize;
        let n = core::cmp::min(4096 - in_page, bytes.len() - done);
        {
            let mut pages = SHARED_FILE_PAGES.lock();
            if let Some(&phys) = pages
                .by_file
                .get(&SharedFilePages::key(identity, page_offset))
            {
                if let Some(page) = pages.by_phys.get_mut(&phys).filter(|page| {
                    page.offset == page_offset && shared_page_matches_ops(page, identity)
                }) {
                    // SAFETY: the cache entry owns `phys` while the cache
                    // lock is held, so no final release can free the frame
                    // during this copy; the frame is identity-mapped.
                    let frame = unsafe {
                        core::slice::from_raw_parts_mut(page.phys.kernel_mut_ptr::<u8>(), 4096)
                    };
                    frame[in_page..in_page + n].copy_from_slice(&bytes[done..done + n]);
                    let clean_n = n.min(page.clean.len().saturating_sub(in_page));
                    if clean_n != 0 {
                        page.clean[in_page..in_page + clean_n]
                            .copy_from_slice(&bytes[done..done + clean_n]);
                    }
                }
            }
        }
        done += n;
    }
}

/// Snapshot a fallback page only when it differs from the last file image.
/// Holding the cache lock pins the page against final-unmap reclamation while
/// its bytes are copied; filesystem I/O starts only after the lock is dropped.
fn snapshot_dirty_page(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    phys: PhysAddr,
    len: usize,
) -> Option<Vec<u8>> {
    let identity = shared_file_identity(ops.as_ref());
    let pages = SHARED_FILE_PAGES.lock();
    let page = pages.by_phys.get(&phys.raw())?;
    if page.offset != offset || !shared_page_matches_ops(page, identity) {
        return None;
    }
    // SAFETY: the cache entry owns `phys`; the cache lock prevents its last
    // mapping release from removing and freeing the entry during this copy.
    let current = unsafe { core::slice::from_raw_parts(phys.kernel_ptr::<u8>(), len) };
    if page.clean.get(..len) == Some(current) {
        None
    } else {
        Some(current.to_vec())
    }
}

/// Advance the exact clean image only after the whole page write succeeds.
/// If userspace changes the mapped page during I/O, the stored snapshot still
/// describes what reached the file, so the next fsync observes it as dirty.
fn mark_page_clean(ops: &Arc<dyn FileOps>, offset: u64, phys: PhysAddr, bytes: &[u8]) {
    let cache_generation = ops.mmap_cache_generation();
    let identity = shared_file_identity(ops.as_ref());
    let mut pages = SHARED_FILE_PAGES.lock();
    if let Some(page) = pages
        .by_phys
        .get_mut(&phys.raw())
        .filter(|page| page.offset == offset && shared_page_matches_ops(page, identity))
    {
        page.clean[..bytes.len()].copy_from_slice(bytes);
        page.cache_generation = cache_generation;
    }
}

mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use narf_filesystem::{FsFuture, Mode, Stat};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    static LIFETIME_DROPS: AtomicUsize = AtomicUsize::new(0);

    struct TestOwner;

    struct FixedRemapOwner;

    struct CacheableOwner {
        generation: AtomicU64,
    }

    struct TestLifetime;

    impl Drop for TestLifetime {
        fn drop(&mut self) {
            LIFETIME_DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Drop for TestOwner {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl FileOps for TestOwner {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }

        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    impl FileOps for FixedRemapOwner {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }

        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    impl FileOps for CacheableOwner {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }

        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }

        fn mmap_cache_generation(&self) -> Option<u64> {
            Some(self.generation.load(Ordering::Acquire))
        }
    }

    fn smoke_mapped_file_owner_lifecycle() -> TestResult {
        const PARENT: u64 = u64::MAX - 20;
        const CHILD: u64 = u64::MAX - 19;
        drop_address_space(PARENT);
        drop_address_space(CHILD);
        DROPS.store(0, Ordering::Relaxed);
        LIFETIME_DROPS.store(0, Ordering::Relaxed);

        let owner: Arc<dyn FileOps> = Arc::new(TestOwner);
        let lifetime: Arc<dyn MmapLifetime> = Arc::new(TestLifetime);
        register(
            PARENT,
            0x1000,
            0x3000,
            0,
            Arc::clone(&owner),
            Some(Arc::clone(&lifetime)),
            None,
        );
        drop(owner);
        drop(lifetime);
        if DROPS.load(Ordering::Relaxed) != 0
            || LIFETIME_DROPS.load(Ordering::Relaxed) != 0
            || owner_count(PARENT) != 1
        {
            return TestResult::Fail("mapping did not retain its file owner");
        }

        // CLONE_VM creates another process identity but not another mm/VMA.
        // Treating that as fork used to duplicate PID-keyed rows and let one
        // sibling's MAP_FIXED/unmap leave the other's stale row behind.
        fork_address_space(PARENT, PARENT);
        if owner_count(PARENT) != 1 {
            return TestResult::Fail("CLONE_VM duplicated an address-space owner");
        }

        fork_address_space(PARENT, CHILD);
        if owner_count(CHILD) != 1 {
            return TestResult::Fail("fork did not inherit the mapping owner");
        }

        // Punch the middle page: parent retains prefix + suffix references.
        punch(PARENT, 0x2000, 0x1000);
        if owner_count(PARENT) != 2 {
            return TestResult::Fail("MAP_FIXED punch did not split the mapping owner");
        }
        drop_address_space(PARENT);
        if DROPS.load(Ordering::Relaxed) != 0
            || LIFETIME_DROPS.load(Ordering::Relaxed) != 0
            || owner_count(CHILD) != 1
        {
            return TestResult::Fail("parent exit released an inherited mapping owner");
        }
        drop_address_space(CHILD);
        if DROPS.load(Ordering::Relaxed) != 1 || LIFETIME_DROPS.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("last mapping did not release all backing owners");
        }
        TestResult::Pass
    }

    kernel_test_in!("userspace/perf", smoke_mapped_file_owner_lifecycle);

    fn smoke_mapped_file_fixed_remap_mirrors_target_outcome() -> TestResult {
        const ADDRESS_SPACE: u64 = u64::MAX - 18;
        const POST_PUNCH: u64 = 0x4000;
        const EARLY_FAILURE: u64 = 0x8000;
        const SPLIT: u64 = 0xc000;
        drop_address_space(ADDRESS_SPACE);
        let owner: Arc<dyn FileOps> = Arc::new(FixedRemapOwner);
        register(
            ADDRESS_SPACE,
            POST_PUNCH,
            0x1000,
            0,
            Arc::clone(&owner),
            None,
            None,
        );
        register(
            ADDRESS_SPACE,
            EARLY_FAILURE,
            0x1000,
            0x1000,
            Arc::clone(&owner),
            None,
            None,
        );
        register(
            ADDRESS_SPACE,
            SPLIT,
            0x3000,
            0x2000,
            Arc::clone(&owner),
            None,
            None,
        );

        let post_punch = publish_fixed_remap(ADDRESS_SPACE, POST_PUNCH, 0x1000, || {
            Err::<(), _>(narf_memory::FixedRelocationError {
                error: AddressSpaceError::AllocationFailed,
                target_punched: true,
                source_shrunk: false,
            })
        });
        let early = publish_fixed_remap(ADDRESS_SPACE, EARLY_FAILURE, 0x1000, || {
            Err::<(), _>(narf_memory::FixedRelocationError {
                error: AddressSpaceError::LockLimit,
                target_punched: false,
                source_shrunk: false,
            })
        });
        let split = publish_fixed_remap(ADDRESS_SPACE, SPLIT + 0x1000, 0x1000, || Ok(()));
        let mut owners = existing_mapping_owners(ADDRESS_SPACE)
            .map(|bucket| {
                bucket
                    .lock()
                    .iter()
                    .map(|mapping| mapping.base)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        owners.sort_unstable();
        drop_address_space(ADDRESS_SPACE);
        if post_punch
            != Err(narf_memory::FixedRelocationError {
                error: AddressSpaceError::AllocationFailed,
                target_punched: true,
                source_shrunk: false,
            })
            || early
                != Err(narf_memory::FixedRelocationError {
                    error: AddressSpaceError::LockLimit,
                    target_punched: false,
                    source_shrunk: false,
                })
            || split != Ok(())
            || owners != alloc::vec![EARLY_FAILURE, SPLIT, SPLIT + 0x2000]
        {
            return TestResult::Fail("fixed-remap owner punch did not mirror memory outcome");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace",
        smoke_mapped_file_fixed_remap_mirrors_target_outcome
    );

    fn smoke_mapped_file_zap_mirrors_all_outcomes() -> TestResult {
        const ADDRESS_SPACE: u64 = u64::MAX - 21;
        const BASE: u64 = 0x1_0000;
        drop_address_space(ADDRESS_SPACE);
        let owner: Arc<dyn FileOps> = Arc::new(FixedRemapOwner);
        register(
            ADDRESS_SPACE,
            BASE,
            0x3000,
            0,
            Arc::clone(&owner),
            None,
            Some(FileWriteback {
                offset: 0,
                phys: alloc::vec![
                    PhysAddr::new(0x11_000),
                    PhysAddr::new(0x12_000),
                    PhysAddr::new(0x13_000),
                ],
            }),
        );
        let snapshot = || {
            existing_mapping_owners(ADDRESS_SPACE).map(|bucket| {
                bucket
                    .lock()
                    .iter()
                    .map(|mapping| {
                        (
                            mapping.base,
                            mapping.len,
                            mapping
                                .writeback
                                .as_ref()
                                .map(|writeback| writeback.phys.clone()),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        };

        // Retained: the row survives whole; only the window's recorded
        // writeback frame is forgotten.
        let retained = publish_current_zap(ADDRESS_SPACE, BASE + 0x1000, 0x1000, || {
            Ok(ZapOutcome::Retained)
        });
        // Failure: owner rows must not move at all.
        let failed = publish_current_zap(ADDRESS_SPACE, BASE, 0x1000, || {
            Err(AddressSpaceError::AllocationFailed)
        });
        let after_retained = snapshot();
        // RangeRemoved (the memory fallback to a full punch): rows retire
        // exactly like a punch — the window tail goes away and the
        // surviving prefix keeps its (already zapped) frame list.
        let removed = publish_current_zap(ADDRESS_SPACE, BASE + 0x2000, 0x1000, || {
            Ok(ZapOutcome::RangeRemoved)
        });
        let after_removed = snapshot();
        drop_address_space(ADDRESS_SPACE);
        if retained != Ok(ZapOutcome::Retained)
            || failed != Err(AddressSpaceError::AllocationFailed)
            || removed != Ok(ZapOutcome::RangeRemoved)
            || after_retained
                != Some(alloc::vec![(
                    BASE,
                    0x3000,
                    Some(alloc::vec![
                        PhysAddr::new(0x11_000),
                        PhysAddr::new(0),
                        PhysAddr::new(0x13_000),
                    ]),
                )])
            || after_removed
                != Some(alloc::vec![(
                    BASE,
                    0x2000,
                    Some(alloc::vec![PhysAddr::new(0x11_000), PhysAddr::new(0)]),
                )])
        {
            return TestResult::Fail("truncate zap owner mirror diverged from the memory outcome");
        }
        TestResult::Pass
    }

    kernel_test_in!("userspace", smoke_mapped_file_zap_mirrors_all_outcomes);

    /// A generation-disciplined generic-fallback file whose `read` can
    /// be armed to land a shrink-truncate in the middle of a demand
    /// fill: the fill's entry checks pass against the old size, then
    /// the read publishes the new EOF and bumps the generation (the
    /// #690 filesystem ordering) and runs the real truncate revoke
    /// composition — VMA transaction → shared-owner transaction →
    /// `publish_current_zap` over the zap primitive — before returning
    /// the pre-shrink bytes. That is the parked-fill interleave of
    /// #691's second review, modelled on one stack: claim and finish
    /// are memory's real code, the fill is the real hook, and only the
    /// scheduling of the truncate is modelled.
    struct ZapRaceOwner {
        size: AtomicU64,
        generation: AtomicU64,
        store: IrqSafeSpinLock<alloc::vec::Vec<u8>>,
        identity: usize,
        zap_as: IrqSafeSpinLock<Option<Arc<narf_memory::AddressSpace>>>,
        zap_base: AtomicU64,
        zap_armed: core::sync::atomic::AtomicBool,
        zap_outcome: AtomicU64,
    }

    impl FileOps for ZapRaceOwner {
        fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            if offset == 4096 && self.zap_armed.swap(false, Ordering::AcqRel) {
                // The shrink lands mid-fill. Generation bump and EOF
                // publication first, then the revoke — a filesystem
                // that revoked first would let this fill's registration
                // check (below) observe a state no real truncate
                // produces.
                self.generation.fetch_add(1, Ordering::Release);
                self.size.store(4096, Ordering::Release);
                if let Some(aspace) = self.zap_as.lock().clone() {
                    let id = aspace.identity();
                    let base = self.zap_base.load(Ordering::Acquire);
                    let outcome = aspace.with_vma_transaction(|| {
                        narf_memory::with_address_space_shared_mapping_transaction(id, || {
                            publish_current_zap(id, base, 4096, || {
                                // SAFETY: this closure runs under the
                                // VMA -> shared-owner transaction order
                                // `truncate_file_mappings` itself uses.
                                unsafe {
                                    aspace.zap_mapping_range_locked_for_syscall_with_shared(
                                        narf_memory::VirtAddr::new(base),
                                        4096,
                                        true,
                                    )
                                }
                            })
                        })
                    });
                    self.zap_outcome.store(
                        match outcome {
                            Ok(ZapOutcome::Retained) => 1,
                            Ok(ZapOutcome::RangeRemoved) => 2,
                            Err(_) => 3,
                        },
                        Ordering::Release,
                    );
                }
            }
            let n = {
                let store = self.store.lock();
                let start = (offset as usize).min(store.len());
                let n = buf.len().min(store.len() - start);
                buf[..n].copy_from_slice(&store[start..start + n]);
                n
            };
            Box::pin(async move { Ok(n) })
        }

        fn write<'a>(&'a self, offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            let mut store = self.store.lock();
            let start = offset as usize;
            if store.len() < start + buf.len() {
                store.resize(start + buf.len(), 0);
            }
            store[start..start + buf.len()].copy_from_slice(buf);
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: self.size.load(Ordering::Acquire),
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }

        fn mmap_cache_generation(&self) -> Option<u64> {
            Some(self.generation.load(Ordering::Acquire))
        }

        fn mmap_backing_identity(&self) -> usize {
            self.identity
        }
    }

    /// The userspace half of the zap straddle: a fault parked in its
    /// fill while a shrink crosses its page must not end up resident,
    /// must refuse at EOF while the file stays shrunk, must serve the
    /// file's CURRENT bytes after a regrow (never the pre-shrink
    /// folio), and must leave the retained owner row's writeback slot
    /// EMPTY — the cancelled fill's frame had its mapping hold released
    /// by the fault path's false path, so a slot naming it would let a
    /// later msync write back through an unheld frame.
    fn smoke_mapped_file_zap_cancels_straddling_fill() -> TestResult {
        // The base must sit in the AS-private part of the PML4[1]
        // subtree: PDPT[0] (virt 0x80_0000_0000..0x80_4000_0000).
        // PDPT[1..512] of every user root is a verbatim copy of the
        // kernel's high-MMIO identity map — 1 GiB huge leaves — so a
        // base under PDPT[1] (the old 0x80_6000_0000) can never take
        // a 4 KiB demand leaf: `map_4kb_demand` refuses with
        // EncounteredHugePage and the fault fails NotImplemented
        // before any zap behaviour is exercised.
        const VB: u64 = 0x0000_0080_2000_0000;
        // SAFETY: kernel tests run with paging enabled; the new root is
        // owned by this fixture, as in the syscall-ABI fixtures.
        let aspace = match unsafe { narf_memory::AddressSpace::new_for_user() } {
            Ok(a) => Arc::new(a),
            Err(_) => return TestResult::Skip("new_for_user failed"),
        };
        let id = aspace.identity();
        drop_address_space(id);
        // The anchor stand-in, as in the cache tests: a dedicated
        // static whose address is this file's volume-anchored identity.
        static ANCHOR: AtomicU64 = AtomicU64::new(0);
        let identity = &ANCHOR as *const AtomicU64 as usize;
        let owner = Arc::new(ZapRaceOwner {
            size: AtomicU64::new(8192),
            generation: AtomicU64::new(11),
            store: IrqSafeSpinLock::new(alloc::vec![0xA1u8; 8192]),
            identity,
            zap_as: IrqSafeSpinLock::new(Some(Arc::clone(&aspace))),
            zap_base: AtomicU64::new(VB + 4096),
            zap_armed: core::sync::atomic::AtomicBool::new(true),
            zap_outcome: AtomicU64::new(0),
        });
        let ops: Arc<dyn FileOps> = owner.clone();
        register(
            id,
            VB,
            8192,
            0,
            Arc::clone(&ops),
            None,
            Some(FileWriteback {
                offset: 0,
                phys: alloc::vec![],
            }),
        );
        if aspace
            .map_region(narf_memory::Region {
                base: narf_memory::VirtAddr::new(VB),
                len: 8192,
                perms: narf_memory::RegionPerms::READ
                    | narf_memory::RegionPerms::WRITE
                    | narf_memory::RegionPerms::SHARED
                    | narf_memory::RegionPerms::FILE_DEMAND,
                phys: alloc::vec![].into(),
            })
            .is_err()
        {
            drop_address_space(id);
            return TestResult::Fail("map_region rejected the fixture region");
        }
        // The real hook (the same function the syscall layer installs).
        let _ = narf_memory::install_file_fault_hook(demand_frame);

        let slot_of = |index: usize| {
            aspace
                .lookup(narf_memory::VirtAddr::new(VB))
                .and_then(|r| r.phys.get(index).copied())
        };
        let writeback_slot_of = |index: usize| {
            existing_mapping_owners(id).and_then(|bucket| {
                bucket
                    .lock()
                    .iter()
                    .find(|mapping| mapping.base == VB)
                    .and_then(|mapping| mapping.writeback.as_ref()?.phys.get(index).copied())
            })
        };

        // The straddling fault. It returns Ok — finish refusal is the
        // fault path's silent drop, with SIGBUS deferred to the retry —
        // but nothing may be left published behind it.
        // SAFETY: live user root, paging enabled.
        let first = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(VB + 4096)) };
        let zap_outcome = owner.zap_outcome.load(Ordering::Relaxed);
        let slot_after = slot_of(1);
        let writeback_after = writeback_slot_of(1);
        // The fetched frame's cache hold must be balanced: either the
        // idle page was retired outright, or it sits with zero mappings.
        let hold_balanced = {
            let pages = SHARED_FILE_PAGES.lock();
            match pages.by_file.get(&SharedFileKey {
                file: SharedFileIdentity {
                    device: 0,
                    anchor: identity,
                },
                offset: 4096,
            }) {
                None => true,
                Some(phys) => pages
                    .by_phys
                    .get(phys)
                    .is_some_and(|page| page.mappings == 0),
            }
        };
        // While the file stays shrunk, the same fault refuses at EOF:
        // the SIGBUS shape, and still nothing published.
        // SAFETY: as above.
        let refault = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(VB + 4096)) };
        let slot_refault = slot_of(1);

        // Regrow with current content (the write a user would land
        // before touching the range again).
        {
            let mut store = owner.store.lock();
            store[4096..].fill(0xB2);
        }
        owner.generation.fetch_add(1, Ordering::Release);
        owner.size.store(8192, Ordering::Release);
        // SAFETY: as above.
        let regrown = unsafe { aspace.demand_alloc_page(narf_memory::VirtAddr::new(VB + 4096)) };
        let slot_regrown = slot_of(1);
        let regrown_bytes_ok = slot_regrown.is_some_and(|phys| {
            phys.raw() != 0 && {
                // SAFETY: `phys` is the frame the mapping now holds.
                let bytes = unsafe { core::slice::from_raw_parts(phys.kernel_ptr::<u8>(), 4096) };
                bytes.iter().all(|&b| b == 0xB2)
            }
        });
        let writeback_regrown = writeback_slot_of(1);
        // A flush over the row must not push anything stale over the
        // current content.
        let flush_ok = existing_mapping_owners(id)
            .and_then(|bucket| {
                bucket
                    .lock()
                    .iter()
                    .find(|mapping| mapping.base == VB)
                    .and_then(|mapping| mapping.writeback.clone())
            })
            .is_some_and(|writeback| flush_mappings(&ops, alloc::vec![writeback]).is_ok());
        let store_intact = {
            let store = owner.store.lock();
            store[4096..].iter().all(|&b| b == 0xB2)
        };

        drop_address_space(id);
        drop(aspace);

        if first != Ok(()) {
            return TestResult::Fail("the straddled fault did not take the silent-drop outcome");
        }
        if zap_outcome != 1 {
            return TestResult::Fail("the mid-fill zap did not run and retain the region");
        }
        if slot_after.is_some_and(|phys| phys.raw() != 0) {
            return TestResult::Fail("the straddled fault left its pre-shrink frame resident");
        }
        if writeback_after.is_some_and(|phys| phys.raw() != 0) {
            return TestResult::Fail("the cancelled fill left a dangling writeback slot");
        }
        if !hold_balanced {
            return TestResult::Fail("the cancelled fill's cache hold was not balanced");
        }
        if refault != Err(AddressSpaceError::Bus) {
            return TestResult::Fail("a fault past the shrunk EOF was not refused as SIGBUS");
        }
        if slot_refault.is_some_and(|phys| phys.raw() != 0) {
            return TestResult::Fail("the refused fault left a frame behind");
        }
        if regrown != Ok(()) || !regrown_bytes_ok {
            return TestResult::Fail("the regrown range does not serve the file's current bytes");
        }
        if writeback_regrown != slot_regrown || slot_regrown.is_none_or(|phys| phys.raw() == 0) {
            return TestResult::Fail("the healthy fault did not record its writeback frame");
        }
        if !flush_ok || !store_intact {
            return TestResult::Fail("a flush after the interleave disturbed current content");
        }
        TestResult::Pass
    }

    kernel_test_in!("userspace", smoke_mapped_file_zap_cancels_straddling_fill);

    fn smoke_mapped_file_shared_relocation_mirrors_all_outcomes() -> TestResult {
        const ADDRESS_SPACE: u64 = u64::MAX - 16;
        const SOURCE: u64 = 0x20_000;
        const TARGET: u64 = 0x40_000;
        const DESTINATION: u64 = 0x60_000;
        drop_address_space(ADDRESS_SPACE);
        let owner: Arc<dyn FileOps> = Arc::new(FixedRemapOwner);
        register(
            ADDRESS_SPACE,
            SOURCE,
            0x4000,
            0x80_000,
            Arc::clone(&owner),
            None,
            Some(FileWriteback {
                offset: 0x80_000,
                phys: alloc::vec![PhysAddr::new(0x11_000), PhysAddr::new(0x12_000),],
            }),
        );
        register(
            ADDRESS_SPACE,
            TARGET,
            0x3000,
            0,
            Arc::clone(&owner),
            None,
            None,
        );

        let late =
            publish_owner_relocation(ADDRESS_SPACE, SOURCE, 0x4000, TARGET, 0x2000, true, || {
                Err::<(), _>(narf_memory::FixedRelocationError {
                    error: AddressSpaceError::AllocationFailed,
                    target_punched: true,
                    source_shrunk: true,
                })
            });
        let after_failure = existing_mapping_owners(ADDRESS_SPACE)
            .map(|bucket| {
                let mut rows = bucket
                    .lock()
                    .iter()
                    .map(|mapping| (mapping.base, mapping.len))
                    .collect::<Vec<_>>();
                rows.sort_unstable();
                rows
            })
            .unwrap_or_default();
        let moved = publish_owner_relocation(
            ADDRESS_SPACE,
            SOURCE,
            0x2000,
            DESTINATION,
            0x3000,
            false,
            || Ok(()),
        );
        let destination = existing_mapping_owners(ADDRESS_SPACE).and_then(|bucket| {
            bucket
                .lock()
                .iter()
                .find(|mapping| mapping.base == DESTINATION)
                .map(|mapping| {
                    (
                        mapping.len,
                        mapping.file_offset,
                        mapping
                            .writeback
                            .as_ref()
                            .map(|writeback| (writeback.offset, writeback.phys.clone())),
                    )
                })
        });
        drop_address_space(ADDRESS_SPACE);
        if late
            != Err(narf_memory::FixedRelocationError {
                error: AddressSpaceError::AllocationFailed,
                target_punched: true,
                source_shrunk: true,
            })
            || after_failure != alloc::vec![(SOURCE, 0x2000), (TARGET + 0x2000, 0x1000)]
            || moved != Ok(())
            || destination
                != Some((
                    0x3000,
                    0x80_000,
                    Some((
                        0x80_000,
                        alloc::vec![PhysAddr::new(0x11_000), PhysAddr::new(0x12_000),],
                    )),
                ))
        {
            return TestResult::Fail("shared relocation owner state diverged from memory");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "userspace",
        smoke_mapped_file_shared_relocation_mirrors_all_outcomes
    );

    fn smoke_mapped_file_alias_slices_owner_and_is_failure_atomic() -> TestResult {
        const ADDRESS_SPACE: u64 = u64::MAX - 17;
        const SOURCE: u64 = 0x10_000;
        const ALIAS: u64 = 0x40_000;
        const FIXED: u64 = 0x80_000;
        const EARLY_TARGET: u64 = 0xc0_000;
        const POST_TARGET: u64 = 0x100_000;
        drop_address_space(ADDRESS_SPACE);
        let owner: Arc<dyn FileOps> = Arc::new(FixedRemapOwner);
        register(
            ADDRESS_SPACE,
            SOURCE,
            0x4000,
            0x20_000,
            Arc::clone(&owner),
            None,
            Some(FileWriteback {
                offset: 0x20_000,
                phys: alloc::vec![
                    PhysAddr::new(0x11_000),
                    PhysAddr::new(0x12_000),
                    PhysAddr::new(0x13_000),
                    PhysAddr::new(0x14_000),
                ],
            }),
        );

        // This is the owner operation needed by legacy old_len==0 shared
        // duplication: `len` is the new alias length and old_addr may start
        // inside the source VMA.
        let alias =
            publish_owner_alias(ADDRESS_SPACE, SOURCE + 0x1000, ALIAS, 0x2000, false, || {
                Ok(7u64)
            });
        let alias_ok = existing_mapping_owners(ADDRESS_SPACE).is_some_and(|bucket| {
            let owners = bucket.lock();
            owners.iter().any(|mapping| {
                mapping.base == ALIAS
                    && mapping.len == 0x2000
                    && mapping.file_offset == 0x21_000
                    && mapping.writeback.as_ref().is_some_and(|writeback| {
                        writeback.offset == 0x21_000
                            && writeback.phys
                                == alloc::vec![PhysAddr::new(0x12_000), PhysAddr::new(0x13_000),]
                    })
            })
        });
        if alias != Ok(7) || !alias_ok {
            drop_address_space(ADDRESS_SPACE);
            return TestResult::Fail("shared remap owner alias used the wrong file slice");
        }

        // A successful fixed alias must split the replaced owner and insert
        // the destination row without any allocation after memory succeeds.
        register(
            ADDRESS_SPACE,
            FIXED - 0x1000,
            0x3000,
            0x30_000,
            Arc::clone(&owner),
            None,
            None,
        );
        let fixed = publish_owner_alias(ADDRESS_SPACE, SOURCE, FIXED, 0x1000, true, || Ok(()));

        register(
            ADDRESS_SPACE,
            EARLY_TARGET,
            0x1000,
            0x40_000,
            Arc::clone(&owner),
            None,
            None,
        );
        let early = publish_owner_alias(ADDRESS_SPACE, SOURCE, EARLY_TARGET, 0x1000, true, || {
            Err::<(), _>(narf_memory::FixedRelocationError {
                error: AddressSpaceError::LockLimit,
                target_punched: false,
                source_shrunk: false,
            })
        });

        register(
            ADDRESS_SPACE,
            POST_TARGET,
            0x1000,
            0x50_000,
            Arc::clone(&owner),
            None,
            None,
        );
        let post = publish_owner_alias(ADDRESS_SPACE, SOURCE, POST_TARGET, 0x1000, true, || {
            Err::<(), _>(narf_memory::FixedRelocationError {
                error: AddressSpaceError::AllocationFailed,
                target_punched: true,
                source_shrunk: false,
            })
        });
        let (fixed_prefix, fixed_alias, fixed_suffix, early_preserved, post_removed) =
            existing_mapping_owners(ADDRESS_SPACE)
                .map(|bucket| {
                    let owners = bucket.lock();
                    (
                        owners.iter().any(|mapping| mapping.base == FIXED - 0x1000),
                        owners.iter().any(|mapping| mapping.base == FIXED),
                        owners.iter().any(|mapping| mapping.base == FIXED + 0x1000),
                        owners.iter().any(|mapping| mapping.base == EARLY_TARGET),
                        !owners.iter().any(|mapping| mapping.base == POST_TARGET),
                    )
                })
                .unwrap_or_default();
        drop_address_space(ADDRESS_SPACE);
        if fixed != Ok(())
            || early
                != Err(narf_memory::FixedRelocationError {
                    error: AddressSpaceError::LockLimit,
                    target_punched: false,
                    source_shrunk: false,
                })
            || post
                != Err(narf_memory::FixedRelocationError {
                    error: AddressSpaceError::AllocationFailed,
                    target_punched: true,
                    source_shrunk: false,
                })
            || !fixed_prefix
            || !fixed_alias
            || !fixed_suffix
            || !early_preserved
            || !post_removed
        {
            return TestResult::Fail("owner alias did not mirror the typed memory outcome");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace/mapped_file",
        smoke_mapped_file_alias_slices_owner_and_is_failure_atomic
    );

    fn smoke_mapped_file_alias_rejects_owner_gaps_and_ambiguity() -> TestResult {
        const GAP_AS: u64 = u64::MAX - 16;
        const OVERLAP_AS: u64 = u64::MAX - 15;
        const SOURCE: u64 = 0x20_000;
        const DESTINATION: u64 = 0x60_000;
        drop_address_space(GAP_AS);
        drop_address_space(OVERLAP_AS);
        let owner: Arc<dyn FileOps> = Arc::new(FixedRemapOwner);

        register(GAP_AS, SOURCE, 0x1000, 0, Arc::clone(&owner), None, None);
        register(
            GAP_AS,
            SOURCE + 0x2000,
            0x1000,
            0x2000,
            Arc::clone(&owner),
            None,
            None,
        );
        let gap_publish_calls = AtomicUsize::new(0);
        let gap = publish_owner_alias(GAP_AS, SOURCE, DESTINATION, 0x3000, false, || {
            gap_publish_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });

        register(
            OVERLAP_AS,
            SOURCE,
            0x2000,
            0,
            Arc::clone(&owner),
            None,
            None,
        );
        register(
            OVERLAP_AS,
            SOURCE + 0x1000,
            0x1000,
            0x1000,
            Arc::clone(&owner),
            None,
            None,
        );
        let overlap_publish_calls = AtomicUsize::new(0);
        let overlap = publish_owner_alias(OVERLAP_AS, SOURCE, DESTINATION, 0x2000, false, || {
            overlap_publish_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let owners_preserved = owner_count(GAP_AS) == 2 && owner_count(OVERLAP_AS) == 2;
        drop_address_space(GAP_AS);
        drop_address_space(OVERLAP_AS);
        if gap
            != Err(narf_memory::FixedRelocationError {
                error: AddressSpaceError::Unmapped,
                target_punched: false,
                source_shrunk: false,
            })
            || overlap
                != Err(narf_memory::FixedRelocationError {
                    error: AddressSpaceError::Overlap,
                    target_punched: false,
                    source_shrunk: false,
                })
            || gap_publish_calls.load(Ordering::Relaxed) != 0
            || overlap_publish_calls.load(Ordering::Relaxed) != 0
            || !owners_preserved
        {
            return TestResult::Fail(
                "owner alias accepted incomplete or ambiguous source coverage",
            );
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace/mapped_file",
        smoke_mapped_file_alias_rejects_owner_gaps_and_ambiguity
    );

    fn smoke_shared_file_pending_publications_do_not_free_peer_page() -> TestResult {
        let ops: Arc<dyn FileOps> = Arc::new(TestOwner);
        let first_candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let second_candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => {
                narf_memory::free_frame(narf_memory::PhysFrame::new(first_candidate));
                return TestResult::Skip("frame allocator drained");
            }
        };
        let (first_phys, first) =
            publish_shared_file_pages(&ops, 0x7fff_0000, alloc::vec![first_candidate], None);
        let (second_phys, second) =
            publish_shared_file_pages(&ops, 0x7fff_0000, alloc::vec![second_candidate], None);
        if first_phys != second_phys || first_phys != alloc::vec![first_candidate] {
            return TestResult::Fail("overlapping mapper did not select canonical page");
        }

        drop(first);
        let still_pending =
            SHARED_FILE_PAGES.lock().by_phys.values().any(|page| {
                page.phys == first_candidate && page.pending == 1 && page.mappings == 0
            });
        if !still_pending {
            return TestResult::Fail("first abort freed a peer's pending canonical page");
        }

        if !retain_shared_file_page(first_candidate.raw()) {
            return TestResult::Fail("pending canonical page could not become mapped");
        }
        second.commit();
        let committed =
            SHARED_FILE_PAGES.lock().by_phys.values().any(|page| {
                page.phys == first_candidate && page.pending == 0 && page.mappings == 1
            });
        if !committed {
            return TestResult::Fail("publication commit did not transfer pending hold");
        }
        if !release_shared_file_page(first_candidate.raw())
            || SHARED_FILE_PAGES
                .lock()
                .by_phys
                .values()
                .any(|page| page.phys == first_candidate)
        {
            return TestResult::Fail("last mapping did not reclaim canonical page once");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace/perf",
        smoke_shared_file_pending_publications_do_not_free_peer_page
    );

    fn smoke_shared_file_idle_cache_requires_current_generation() -> TestResult {
        const OFFSET: u64 = 0x7ffe_0000;
        let owner = Arc::new(CacheableOwner {
            generation: AtomicU64::new(1),
        });
        let ops: Arc<dyn FileOps> = owner.clone();
        let first_candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let (first_phys, first) =
            publish_shared_file_pages(&ops, OFFSET, alloc::vec![first_candidate], Some(1));
        let first_canonical = first_phys == alloc::vec![first_candidate];
        let first_retained = retain_shared_file_page(first_candidate.raw());
        first.commit();
        let first_released = release_shared_file_page(first_candidate.raw());

        let hit = reserve_cached_shared_file_pages(&ops, OFFSET, 1);
        let hit_same = hit
            .as_ref()
            .is_some_and(|(phys, _)| phys == &alloc::vec![first_candidate]);
        if let Some((phys, publication)) = hit {
            let _ = retain_shared_file_page(phys[0].raw());
            publication.commit();
            let _ = release_shared_file_page(phys[0].raw());
        }

        owner.generation.store(2, Ordering::Release);
        let stale_rejected = reserve_cached_shared_file_pages(&ops, OFFSET, 1).is_none();
        let second_candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => {
                let retired = SHARED_FILE_PAGES.lock().remove_phys(first_candidate.raw());
                if let Some(page) = retired {
                    narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
                }
                return TestResult::Skip("frame allocator drained");
            }
        };
        let (second_phys, second) =
            publish_shared_file_pages(&ops, OFFSET, alloc::vec![second_candidate], Some(2));
        let generation_replaced = second_phys == alloc::vec![second_candidate];
        let second_retained = retain_shared_file_page(second_candidate.raw());
        second.commit();
        let second_released = release_shared_file_page(second_candidate.raw());
        let retired = SHARED_FILE_PAGES.lock().remove_phys(second_candidate.raw());
        let retired_final = retired.is_some();
        if let Some(page) = retired {
            narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
        }

        if !first_canonical
            || !first_retained
            || !first_released
            || !hit_same
            || !stale_rejected
            || !generation_replaced
            || !second_retained
            || !second_released
            || !retired_final
        {
            return TestResult::Fail("idle cache reused a stale shared-file generation");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace/perf",
        smoke_shared_file_idle_cache_requires_current_generation
    );

    /// Two opens of one generation-disciplined file, modelled the way
    /// the FAT/minix drivers behave: distinct owner objects reporting
    /// one volume-anchored identity and one shared generation counter.
    struct AnchoredOwner {
        device: u64,
        identity: usize,
        generation: Arc<AtomicU64>,
    }

    fn smoke_shared_file_cache_separates_recycled_filesystem_identity() -> TestResult {
        static ANCHOR: AtomicU64 = AtomicU64::new(0);
        let identity = &ANCHOR as *const _ as usize;
        let generation = Arc::new(AtomicU64::new(7));
        let open1: Arc<dyn FileOps> = Arc::new(AnchoredOwner {
            device: 0x12340001,
            identity,
            generation: generation.clone(),
        });
        let candidate = match narf_memory::alloc_frame() {
            Ok(f) => f.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        // SAFETY: newly allocated frame is exclusively owned by this fixture.
        unsafe {
            core::ptr::write_bytes(candidate.kernel_mut_ptr::<u8>(), 0x51, 4096);
        }
        let (_, publication) =
            publish_shared_file_pages(&open1, 0, alloc::vec![candidate], Some(7));
        publication.commit();
        drop(open1);
        let other: Arc<dyn FileOps> = Arc::new(AnchoredOwner {
            device: 0x12340002,
            identity,
            generation,
        });
        // Same recycled anchor, offset and generation; different superblock.
        let collision = reserve_cached_shared_file_pages(&other, 0, 1).is_some();
        let retired = SHARED_FILE_PAGES.lock().remove_phys(candidate.raw());
        if let Some(page) = retired {
            narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
        }
        if collision {
            TestResult::Fail("different filesystem reused stale mapped data")
        } else {
            TestResult::Pass
        }
    }
    kernel_test_in!(
        "syscall_abi/filemap",
        smoke_shared_file_cache_separates_recycled_filesystem_identity
    );

    impl FileOps for AnchoredOwner {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }

        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }

        fn inode_attrs(&self) -> narf_filesystem::InodeAttrs {
            narf_filesystem::InodeAttrs {
                dev: self.device,
                ..Default::default()
            }
        }

        fn mmap_cache_generation(&self) -> Option<u64> {
            Some(self.generation.load(Ordering::Acquire))
        }

        fn mmap_backing_identity(&self) -> usize {
            self.identity
        }
    }

    /// Cross-open retention (issue #679): a generation-carrying page
    /// is retained for its *file*, so a second open reuses it after
    /// the publishing open — the only holder of the recording
    /// `FileOps` object — is gone. A generation-less page keeps the
    /// old rule and retires with its owner.
    fn smoke_shared_file_cache_survives_publisher_close() -> TestResult {
        const OFFSET: u64 = 0x7ffd_0000;
        // The anchor stand-in: a dedicated static whose address plays
        // the volume anchor's role (stable, unique, never a node).
        static ANCHOR: AtomicU64 = AtomicU64::new(0);
        let identity = &ANCHOR as *const AtomicU64 as usize;
        let generation = Arc::new(AtomicU64::new(7));

        let first_candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let open1: Arc<dyn FileOps> = Arc::new(AnchoredOwner {
            device: 0,
            identity,
            generation: Arc::clone(&generation),
        });
        let (first_phys, first) =
            publish_shared_file_pages(&open1, OFFSET, alloc::vec![first_candidate], Some(7));
        let first_canonical = first_phys == alloc::vec![first_candidate];
        let first_retained = retain_shared_file_page(first_candidate.raw());
        first.commit();
        // Close the publishing open before the mapping is released:
        // the recording file object is gone entirely.
        drop(open1);
        let first_released = release_shared_file_page(first_candidate.raw());
        let retained_after_close = SHARED_FILE_PAGES
            .lock()
            .by_phys
            .values()
            .any(|page| page.phys == first_candidate);

        // A fresh open of the same file (a new object, same anchored
        // identity and generation) must reuse the retained page.
        let open2: Arc<dyn FileOps> = Arc::new(AnchoredOwner {
            device: 0,
            identity,
            generation: Arc::clone(&generation),
        });
        let hit = reserve_cached_shared_file_pages(&open2, OFFSET, 1);
        let hit_same = hit
            .as_ref()
            .is_some_and(|(phys, _)| phys == &alloc::vec![first_candidate]);
        if let Some((phys, publication)) = hit {
            let _ = retain_shared_file_page(phys[0].raw());
            publication.commit();
            let _ = release_shared_file_page(phys[0].raw());
        }
        // A mutation through the file (a generation move) ends reuse.
        generation.store(8, Ordering::Release);
        let stale_rejected = reserve_cached_shared_file_pages(&open2, OFFSET, 1).is_none();
        let retired = SHARED_FILE_PAGES.lock().remove_phys(first_candidate.raw());
        let retired_final = retired.is_some();
        if let Some(page) = retired {
            narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
        }
        if !first_canonical
            || !first_retained
            || !first_released
            || !retained_after_close
            || !hit_same
            || !stale_rejected
            || !retired_final
        {
            return TestResult::Fail(
                "retained page did not survive its publishing open for the next open",
            );
        }

        // The generation-less regime is unchanged: a page whose owner
        // is gone retires at release, because its identity is only an
        // object address.
        let plain_candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let plain: Arc<dyn FileOps> = Arc::new(TestOwner);
        let (plain_phys, plain_pub) =
            publish_shared_file_pages(&plain, OFFSET, alloc::vec![plain_candidate], None);
        let plain_canonical = plain_phys == alloc::vec![plain_candidate];
        let plain_retained = retain_shared_file_page(plain_candidate.raw());
        plain_pub.commit();
        drop(plain);
        let plain_released = release_shared_file_page(plain_candidate.raw());
        let plain_gone = !SHARED_FILE_PAGES
            .lock()
            .by_phys
            .values()
            .any(|page| page.phys == plain_candidate);
        if !plain_canonical || !plain_retained || !plain_released || !plain_gone {
            return TestResult::Fail("generation-less page survived the death of its only owner");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace/perf",
        smoke_shared_file_cache_survives_publisher_close
    );

    /// Build the minimal ISO 9660 image the driver crate's own
    /// tests use (PVD at sector 16, terminator at 17, root
    /// directory at 18, `TEST.TXT;1` contents at 20), so the test
    /// below can mount a real immutable filesystem in userspace.
    fn iso681_image() -> alloc::vec::Vec<u8> {
        const SECTOR: usize = 2048;
        fn be_le32(buf: &mut [u8], off: usize, v: u32) {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
            buf[off + 4..off + 8].copy_from_slice(&v.to_be_bytes());
        }
        fn be_le16(buf: &mut [u8], off: usize, v: u16) {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
            buf[off + 2..off + 4].copy_from_slice(&v.to_be_bytes());
        }
        fn record(
            dst: &mut [u8],
            off: usize,
            extent: u32,
            len: u32,
            flags: u8,
            id: &[u8],
        ) -> usize {
            let mut total = 33 + id.len();
            if total % 2 != 0 {
                total += 1;
            }
            dst[off] = total as u8;
            be_le32(dst, off + 2, extent);
            be_le32(dst, off + 10, len);
            dst[off + 25] = flags;
            be_le16(dst, off + 28, 1);
            dst[off + 32] = id.len() as u8;
            dst[off + 33..off + 33 + id.len()].copy_from_slice(id);
            total
        }
        let payload: &[u8] = b"narf-iso\n";
        let mut img = alloc::vec![0u8; SECTOR * 24];
        let root_off = 18 * SECTOR;
        let mut cursor = 0usize;
        cursor += record(&mut img[root_off..], cursor, 18, SECTOR as u32, 2, &[0x00]);
        cursor += record(&mut img[root_off..], cursor, 18, SECTOR as u32, 2, &[0x01]);
        let _ = record(
            &mut img[root_off..],
            cursor,
            20,
            payload.len() as u32,
            0,
            b"TEST.TXT;1",
        );
        let pvd = 16 * SECTOR;
        img[pvd] = 1;
        img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        img[pvd + 6] = 1;
        be_le32(&mut img, pvd + 80, 24);
        be_le16(&mut img, pvd + 120, 1);
        be_le16(&mut img, pvd + 124, 1);
        be_le16(&mut img, pvd + 128, SECTOR as u16);
        let _ = record(&mut img, pvd + 156, 18, SECTOR as u32, 2, &[0x00]);
        img[pvd + 881] = 1;
        let term = 17 * SECTOR;
        img[term] = 0xFF;
        img[term + 1..term + 6].copy_from_slice(b"CD001");
        img[term + 6] = 1;
        let data_off = 20 * SECTOR;
        img[data_off..data_off + payload.len()].copy_from_slice(payload);
        img
    }

    /// End-to-end cross-open retention with a REAL driver (#681):
    /// two lookups of one ISO 9660 file are two node objects; a page
    /// published under the first open must be reservable through the
    /// second — the property the constant generation + stable
    /// backing identity exist to provide, and the one that silently
    /// never engaged while these filesystems reported no generation
    /// and per-open identities.
    fn smoke_shared_file_iso9660_cross_open_retention() -> TestResult {
        use narf_filesystem::FsInstance as _;

        const OFFSET: u64 = 0x7ffd_0000;
        let device = narf_block::ram::RamBlockDevice::from_image(2048, iso681_image());
        let volume = match crate::handlers::poll_io_to_completion(
            narf_drivers_fs_iso9660::volume::Iso9660Volume::mount(
                device,
                narf_lib::id::DomainId::DRIVER_0,
            ),
        ) {
            Some(Ok(v)) => v,
            _ => return TestResult::Fail("mounting the test ISO image failed"),
        };
        let root = volume.root();
        let open1 = match crate::handlers::poll_io_to_completion(root.lookup_async("TEST.TXT")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("first lookup of TEST.TXT failed"),
        };
        let open2 = match crate::handlers::poll_io_to_completion(root.lookup_async("TEST.TXT")) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("second lookup of TEST.TXT failed"),
        };
        // The #681 contract, on real driver nodes.
        let generation = match open1.mmap_cache_generation() {
            Some(g) => g,
            None => return TestResult::Fail("ISO file reports no cache generation"),
        };
        if open2.mmap_cache_generation() != Some(generation) {
            return TestResult::Fail("two opens disagree on the generation");
        }
        if open1.mmap_backing_identity() != open2.mmap_backing_identity() {
            return TestResult::Fail("two opens disagree on the backing identity");
        }

        let candidate = match narf_memory::alloc_frame() {
            Ok(frame) => frame.start_address(),
            Err(_) => return TestResult::Skip("frame allocator drained"),
        };
        let (published, publication) =
            publish_shared_file_pages(&open1, OFFSET, alloc::vec![candidate], Some(generation));
        let canonical = published == alloc::vec![candidate];
        let retained = retain_shared_file_page(candidate.raw());
        publication.commit();
        let released = release_shared_file_page(candidate.raw());

        // The second open must find the page the first published.
        let hit = reserve_cached_shared_file_pages(&open2, OFFSET, 1);
        let hit_same = hit
            .as_ref()
            .is_some_and(|(phys, _)| phys == &alloc::vec![candidate]);
        if let Some((phys, publication)) = hit {
            let _ = retain_shared_file_page(phys[0].raw());
            publication.commit();
            let _ = release_shared_file_page(phys[0].raw());
        }
        let retired = SHARED_FILE_PAGES.lock().remove_phys(candidate.raw());
        let retired_final = retired.is_some();
        if let Some(page) = retired {
            narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
        }

        if !canonical || !retained || !released || !hit_same || !retired_final {
            return TestResult::Fail(
                "ISO 9660 page published under one open was not reservable under another",
            );
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "userspace/perf",
        smoke_shared_file_iso9660_cross_open_retention
    );
}
