//! Lifetime tracking for `MAP_SHARED` file/device mappings.
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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_filesystem::{FileOps, MmapLifetime};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpaceError, MappingReceipt, PhysAddr};

#[derive(Clone)]
struct FileWriteback {
    offset: u64,
    phys: Vec<PhysAddr>,
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
    /// Ordinary file MAP_SHARED mappings use private physical frames as a
    /// fallback when the filesystem cannot expose cache pages directly. Keep
    /// their frame list so fsync/msync can copy dirty bytes back to FileOps.
    /// Device mappings leave this `None`: they already alias device memory.
    writeback: Option<FileWriteback>,
}

type MappingOwners = Arc<IrqSafeSpinLock<Vec<MappingOwner>>>;

/// The global index is held only long enough to resolve one address-space
/// bucket. Publication and faults serialize on that address space's lock, so
/// a slow MAP_FIXED teardown cannot block unrelated processes system-wide.
static MAPPING_OWNER_BUCKETS: IrqSafeSpinLock<BTreeMap<u64, MappingOwners>> =
    IrqSafeSpinLock::new(BTreeMap::new());

fn mapping_owners(address_space_id: u64) -> MappingOwners {
    if let Some(existing) = existing_mapping_owners(address_space_id) {
        return existing;
    }
    let candidate = Arc::new(IrqSafeSpinLock::new(Vec::new()));
    let mut buckets = MAPPING_OWNER_BUCKETS.lock();
    Arc::clone(buckets.entry(address_space_id).or_insert_with(|| candidate))
}

fn existing_mapping_owners(address_space_id: u64) -> Option<MappingOwners> {
    MAPPING_OWNER_BUCKETS
        .lock()
        .get(&address_space_id)
        .map(Arc::clone)
}

pub(crate) fn drop_address_space(address_space_id: u64) {
    // Drop the bucket (and therefore FileOps/MmapLifetime references) after
    // releasing the global index: destructors may allocate or take arbitrary
    // filesystem locks.
    let retired = MAPPING_OWNER_BUCKETS.lock().remove(&address_space_id);
    drop(retired);
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
    pub(crate) replace: bool,
}

pub(crate) fn publish_current_mapping(
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
        replace,
    } = registration;
    let address_space_id = current_address_space_id().ok_or(AddressSpaceError::Unmapped)?;
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
        writeback: writeback_phys.map(|phys| FileWriteback {
            offset: file_offset,
            phys,
        }),
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
    base: u64,
    len: u64,
    replace: bool,
    publish: impl FnOnce() -> Result<T, AddressSpaceError>,
    finish: impl FnOnce(T) -> Result<(), AddressSpaceError>,
) -> Result<T, AddressSpaceError> {
    let address_space_id = current_address_space_id().ok_or(AddressSpaceError::Unmapped)?;
    let owner_bucket = mapping_owners(address_space_id);
    let mut owners = owner_bucket.lock();
    let receipt = publish()?;
    if replace {
        punch_locked(&mut owners, base, len);
    }
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
    base: u64,
    len: u64,
    publish: impl FnOnce() -> Result<(), AddressSpaceError>,
) -> Result<(), AddressSpaceError> {
    let Some(address_space_id) = current_address_space_id() else {
        return publish();
    };
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

/// Physical file-cache pages for generic `MAP_SHARED` fallbacks. A filesystem
/// which cannot directly expose its own page-cache frames still needs one
/// backing page per `(open file description, file offset)`: otherwise two
/// overlapping mappings diverge and the last writeback can overwrite a newer
/// change through the other mapping.
struct SharedFilePage {
    ops: Arc<dyn FileOps>,
    offset: u64,
    phys: PhysAddr,
    mappings: usize,
    /// Mappers which selected this canonical page but have not yet either
    /// committed a VMA reference or aborted. Reclaim requires both counters
    /// to reach zero.
    pending: usize,
    /// Exact bytes last read from, or successfully written to, the backing
    /// file. Generic mappings cannot rely on hardware dirty bits here, so an
    /// exact snapshot lets fsync skip clean pages without risking a hash
    /// collision that could lose a write.
    clean: Vec<u8>,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct SharedFileKey {
    file: usize,
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

    fn key(ops: &Arc<dyn FileOps>, offset: u64) -> SharedFileKey {
        SharedFileKey {
            file: Arc::as_ptr(ops) as *const () as usize,
            offset,
        }
    }

    fn remove_phys(&mut self, phys: u64) -> Option<SharedFilePage> {
        let page = self.by_phys.remove(&phys)?;
        let key = Self::key(&page.ops, page.offset);
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

/// Consumable reservation for the canonical pages selected by one mmap
/// attempt. Drop is abort. A successful VMA publication calls [`Self::commit`]
/// after memory's SHARED retain hooks have recorded committed mappings.
pub(crate) struct SharedFilePublication {
    phys: Vec<PhysAddr>,
    active: bool,
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
                let page = pages
                    .by_phys
                    .get_mut(&phys.raw())
                    .expect("pending shared-file publication lost its canonical page");
                assert!(page.pending != 0, "shared-file pending hold underflow");
                page.pending -= 1;
                if page.mappings == 0 && page.pending == 0 {
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

/// Resolve a fault on a demand-paged `MAP_SHARED` mapping to the frame its
/// backing file wants at `vaddr`.
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
/// entered from the page-fault handler.
pub(crate) fn demand_frame(vaddr: u64) -> Option<u64> {
    let page = vaddr & !0xFFFu64;
    let address_space_id = current_address_space_id()?;
    let owner_bucket = existing_mapping_owners(address_space_id)?;
    let (offset, ops) = {
        let owners = owner_bucket.lock();
        let owner = owners.iter().find(|mapping| {
            page >= mapping.base && page < mapping.base.saturating_add(mapping.len)
        })?;
        (
            owner.file_offset.checked_add(page - owner.base)?,
            Arc::clone(&owner.ops),
        )
    };
    ops.mmap_fault(offset).ok()
}

/// Publish freshly loaded fallback pages into the process-independent file
/// page cache. A concurrent/overlapping mapper may already have published a
/// page; in that case use its physical page and return the unused allocation
/// to the frame allocator.
pub(crate) fn publish_shared_file_pages(
    ops: &Arc<dyn FileOps>,
    offset: u64,
    candidates: Vec<PhysAddr>,
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
    let mut canonical = Vec::with_capacity(prepared.len());
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        for (index, (candidate, clean)) in prepared.into_iter().enumerate() {
            let page_offset = offset
                .checked_add(index as u64 * 4096)
                .expect("validated mmap file offset overflowed");
            let key = SharedFilePages::key(ops, page_offset);
            let phys = if let Some(phys) = pages.by_file.get(&key).copied() {
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
                                ops: Arc::clone(ops),
                                offset: page_offset,
                                phys: candidate,
                                mappings: 0,
                                pending: 0,
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
            page.pending = page
                .pending
                .checked_add(1)
                .expect("shared-file pending hold overflow");
        }
    }
    for phys in rejected {
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
    let page = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let Some(page) = pages.by_phys.get_mut(&phys) else {
            return false;
        };
        assert!(page.mappings != 0, "shared-file mapping hold underflow");
        page.mappings -= 1;
        if page.mappings != 0 || page.pending != 0 {
            return true;
        }
        pages
            .remove_phys(phys)
            .expect("unreferenced shared-file page disappeared")
    };
    narf_memory::free_frame(narf_memory::PhysFrame::new(page.phys));
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
        writeback,
    });
}

pub(crate) fn unmap_current(base: u64) {
    if let Some(owners) = current_address_space_id().and_then(existing_mapping_owners) {
        owners.lock().retain(|mapping| mapping.base != base);
    }
}

/// Mirror `AddressSpace::punch_fixed` splitting for owner references.
pub(crate) fn punch_current(base: u64, len: u64) {
    if let Some(address_space_id) = current_address_space_id() {
        punch(address_space_id, base, len);
    }
}

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
            let last = first
                .checked_add(pages)
                .ok_or(AddressSpaceError::AllocationFailed)?;
            let slice = original
                .phys
                .get(first..last)
                .ok_or(AddressSpaceError::Unmapped)?;
            let mut phys = Vec::new();
            phys.try_reserve_exact(slice.len())
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            phys.extend_from_slice(slice);
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
            let last = first
                .checked_add(pages)
                .ok_or(AddressSpaceError::AllocationFailed)?;
            let source = original
                .phys
                .get(first..last)
                .ok_or(AddressSpaceError::Unmapped)?;
            let mut phys = Vec::new();
            phys.try_reserve_exact(source.len())
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            phys.extend_from_slice(source);
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
        if let Some(writeback) = tail.writeback.as_mut() {
            let pages =
                usize::try_from(delta >> 12).map_err(|_| AddressSpaceError::AllocationFailed)?;
            writeback
                .phys
                .try_reserve_exact(pages)
                .map_err(|_| AddressSpaceError::AllocationFailed)?;
            writeback
                .phys
                .resize(writeback.phys.len() + pages, PhysAddr::new(0));
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
    let Some(address_space_id) = current_address_space_id() else {
        return Ok(());
    };
    let Some(owner_bucket) = existing_mapping_owners(address_space_id) else {
        return Ok(());
    };
    let mappings: Vec<FileWriteback> = owner_bucket
        .lock()
        .iter()
        .filter(|mapping| Arc::ptr_eq(&mapping.ops, ops))
        .filter_map(|mapping| mapping.writeback.clone())
        .collect();
    flush_mappings(ops, mappings)
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
    let mappings: Vec<(Arc<dyn FileOps>, FileWriteback)> = owner_bucket
        .lock()
        .iter()
        .filter(|mapping| mapping.base < end && base < mapping.base.saturating_add(mapping.len))
        .filter_map(|mapping| {
            mapping
                .writeback
                .clone()
                .map(|wb| (Arc::clone(&mapping.ops), wb))
        })
        .collect();
    for (ops, mapping) in mappings {
        flush_mappings(&ops, alloc::vec![mapping])?;
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
            let file_len = ops.stat().size;
            if offset >= file_len {
                continue;
            }
            let len = ((file_len - offset) as usize).min(4096);
            let Some(bytes) = snapshot_dirty_page(ops, offset, *phys, len) else {
                continue;
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
            mark_page_clean(ops, offset, *phys, &bytes);
        }
    }
    Ok(())
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
    let pages = SHARED_FILE_PAGES.lock();
    let page = pages.by_phys.get(&phys.raw())?;
    if page.offset != offset || !Arc::ptr_eq(&page.ops, ops) {
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
    let mut pages = SHARED_FILE_PAGES.lock();
    if let Some(page) = pages
        .by_phys
        .get_mut(&phys.raw())
        .filter(|page| page.offset == offset && Arc::ptr_eq(&page.ops, ops))
    {
        page.clean[..bytes.len()].copy_from_slice(bytes);
    }
}

mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_filesystem::{FsFuture, Mode, Stat};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static DROPS: AtomicUsize = AtomicUsize::new(0);
    static LIFETIME_DROPS: AtomicUsize = AtomicUsize::new(0);

    struct TestOwner;

    struct FixedRemapOwner;

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
                phys: alloc::vec![
                    PhysAddr::new(0x11_000),
                    PhysAddr::new(0x12_000),
                    PhysAddr::new(0x13_000),
                    PhysAddr::new(0x14_000),
                ],
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
                        alloc::vec![
                            PhysAddr::new(0x11_000),
                            PhysAddr::new(0x12_000),
                            PhysAddr::new(0),
                        ],
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
            publish_shared_file_pages(&ops, 0x7fff_0000, alloc::vec![first_candidate]);
        let (second_phys, second) =
            publish_shared_file_pages(&ops, 0x7fff_0000, alloc::vec![second_candidate]);
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
}
