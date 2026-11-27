//! Retained Intel CPU-frame census for atomic GEM and PRIME mmap backing.
//!
//! Tokens retain the same immutable BO/reservation object. Physical rows keep
//! it alive independently while fork metadata exists before child file-owner
//! publication. Storage migration of a mapped object ([`relocate`]) runs
//! through the synchronous CPU revocation transaction, which cannot await a
//! GPU copy: its commit copies with the CPU.
//!
//! Lock order: BACKINGS -> backing frames -> FRAMES. Frame alias callbacks
//! use only FRAMES (and a retire, backing frames -> FRAMES). No registry lock
//! spans a VM call, user callback, GPU operation or await.
use super::*;
use alloc::sync::Weak;
use core::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Debug)]
struct CpuBacking {
    object: Arc<GemObject>,
    /// The CPU frames of the object's current placement; [`relocate`]
    /// replaces them.
    frames: IrqSafeSpinLock<Vec<u64>>,
    owners: AtomicUsize,
    pending: AtomicUsize,
    /// A [`relocate`] is moving the aliases: no retire until it settles.
    moving: AtomicBool,
    retired: AtomicBool,
}
#[derive(Debug)]
struct CpuMap {
    backing: Arc<CpuBacking>,
    published: AtomicBool,
}
type FrameOwners = BTreeMap<u64, (Arc<CpuBacking>, usize)>;
static FRAMES: IrqSafeSpinLock<FrameOwners> = IrqSafeSpinLock::new(BTreeMap::new());
static BACKINGS: IrqSafeSpinLock<Vec<Weak<CpuBacking>>> = IrqSafeSpinLock::new(Vec::new());

fn retire(backing: &Arc<CpuBacking>) {
    if backing.owners.load(Ordering::Acquire) != 0 || backing.moving.load(Ordering::Acquire) {
        return;
    }
    let keys = backing.frames.lock();
    let mut frames = FRAMES.lock();
    if backing.retired.load(Ordering::Acquire)
        || backing.owners.load(Ordering::Acquire) != 0
        || backing.moving.load(Ordering::Acquire)
        || keys.iter().any(|phys| {
            frames
                .get(phys)
                .is_some_and(|(owner, count)| Arc::ptr_eq(owner, backing) && *count != 0)
        })
    {
        return;
    }
    backing.retired.store(true, Ordering::Release);
    for phys in keys.iter() {
        let (owner, count) = frames.remove(phys).expect("registered Intel CPU frame");
        assert!(Arc::ptr_eq(&owner, backing) && count == 0);
        // The argument's Arc retains this backing/object while row Arcs are
        // removed. Final BO/backing destruction occurs outside FRAMES.
        drop(owner);
    }
}
impl Drop for CpuMap {
    fn drop(&mut self) {
        if !self.published.load(Ordering::Acquire) {
            self.backing.pending.fetch_sub(1, Ordering::AcqRel);
        }
        self.backing.owners.fetch_sub(1, Ordering::AcqRel);
        retire(&self.backing);
    }
}

/// Called by the shared-frame metadata hooks, including unpublished forks.
fn retain_cpu_frame(phys: u64) -> bool {
    let mut frames = FRAMES.lock();
    let Some((_, count)) = frames.get_mut(&phys) else {
        return false;
    };
    *count = count
        .checked_add(1)
        .expect("Intel CPU alias count overflow");
    true
}
fn release_cpu_frame(phys: u64) -> bool {
    let backing = {
        let mut frames = FRAMES.lock();
        let Some((backing, count)) = frames.get_mut(&phys) else {
            return false;
        };
        assert!(*count != 0, "unbalanced Intel CPU alias release");
        *count -= 1;
        backing.clone()
    };
    retire(&backing);
    true
}

/// The metadata-alias census of `[start, end)` (address-space slots,
/// including fork children not yet scheduler-visible): every frame with a
/// nonzero count. Takes only `FRAMES` and never allocates.
fn vram_alias_census(start: u64, end: u64, report: &mut dyn FnMut(u64, usize)) {
    for (&phys, (_, count)) in FRAMES.lock().range(start..end) {
        if *count != 0 {
            report(phys, *count);
        }
    }
}

/// Linux `xe_bo_runtime_pm_release_mmap_offset` over every VRAM CPU mapping
/// of one card at once: revoke every user translation of the card's LMEM
/// BAR window `[start, start + len)` until the returned handle drops. New
/// mappings made meanwhile stay unmapped too, and a CPU access calls
/// `refault`, which resumes the device. `Busy` means an alias the snapshot
/// could not see (a fork in flight); the caller retries later.
pub(crate) fn revoke_window(
    start: u64,
    len: u64,
    refault: Arc<dyn narf_filesystem::mmap_relocation::DeviceFrameRefault>,
) -> Result<narf_filesystem::mmap_relocation::DeviceFrameRevocation, FsError> {
    narf_filesystem::mmap_relocation::revoke(start, len, vram_alias_census, refault)
}

/// True if `object` currently has any live CPU mmap or unretired shared-frame
/// fork alias, precluding storage relocation.
pub(crate) fn has_active_aliases(object: &GemObject) -> bool {
    let index = BACKINGS.lock();
    let Some(backing) = index.iter().filter_map(Weak::upgrade).find(|b| {
        core::ptr::eq(Arc::as_ptr(&b.object), object) && !b.retired.load(Ordering::Acquire)
    }) else {
        return false;
    };
    if backing.owners.load(Ordering::Acquire) != 0 {
        return true;
    }
    let keys = backing.frames.lock();
    let frames = FRAMES.lock();
    keys.iter().any(|phys| {
        frames
            .get(phys)
            .is_some_and(|(owner, count)| Arc::ptr_eq(owner, &backing) && *count != 0)
    })
}

/// Retire an inactive `CpuBacking` before migrating `object`'s storage to new
/// physical frames so subsequent mappings re-register cleanly. Returns `Busy`
/// if any CPU mmap or shared-frame alias is still active.
pub(crate) fn retire_object(object: &Arc<GemObject>) -> Result<(), FsError> {
    let mut index = BACKINGS.lock();
    index.retain(|weak| weak.strong_count() != 0);
    let Some(backing) = index
        .iter()
        .filter_map(Weak::upgrade)
        .find(|b| Arc::ptr_eq(&b.object, object) && !b.retired.load(Ordering::Acquire))
    else {
        return Ok(());
    };
    let keys = backing.frames.lock();
    let mut frames = FRAMES.lock();
    if backing.retired.load(Ordering::Acquire) {
        return Ok(());
    }
    if backing.owners.load(Ordering::Acquire) != 0
        || backing.moving.load(Ordering::Acquire)
        || keys.iter().any(|phys| {
            frames
                .get(phys)
                .is_some_and(|(owner, count)| Arc::ptr_eq(owner, &backing) && *count != 0)
        })
    {
        return Err(FsError::Busy);
    }
    backing.retired.store(true, Ordering::Release);
    for phys in keys.iter() {
        let (owner, count) = frames.remove(phys).expect("registered Intel CPU frame");
        assert!(Arc::ptr_eq(&owner, &backing) && count == 0);
        drop(owner);
    }
    Ok(())
}

pub(super) fn backing(
    object: Arc<GemObject>,
    offset: u64,
    len: usize,
) -> Result<MmapBacking, FsError> {
    // Validate before registering any ownership or advertising a provider.
    let frames = object.cpu_frames(offset, len)?;
    let whole = object.cpu_frames(0, object.size as usize)?;
    narf_filesystem::mmap_relocation::register_alias_hooks(retain_cpu_frame, release_cpu_frame)?;
    let mut index = BACKINGS.lock();
    index.retain(|weak| weak.strong_count() != 0);
    let backing = loop {
        let existing = index
            .iter()
            .filter_map(Weak::upgrade)
            .find(|b| Arc::ptr_eq(&b.object, &object) && !b.retired.load(Ordering::Acquire));
        let backing = match existing {
            Some(backing) => backing,
            None => {
                let mut keys = Vec::new();
                keys.try_reserve_exact(whole.len())
                    .map_err(|_| FsError::OutOfMemory)?;
                keys.extend_from_slice(&whole);
                index.try_reserve(1).map_err(|_| FsError::OutOfMemory)?;
                let backing = Arc::new(CpuBacking {
                    object: object.clone(),
                    frames: IrqSafeSpinLock::new(keys),
                    owners: AtomicUsize::new(0),
                    pending: AtomicUsize::new(0),
                    moving: AtomicBool::new(false),
                    retired: AtomicBool::new(false),
                });
                index.push(Arc::downgrade(&backing));
                backing
            }
        };
        let keys = backing.frames.lock();
        let mut registry = FRAMES.lock();
        if backing.retired.load(Ordering::Acquire) {
            continue;
        }
        // A relocation in flight would publish the old frames.
        if backing.moving.load(Ordering::Acquire)
            || *keys != whole
            || whole.iter().any(|phys| {
                registry
                    .get(phys)
                    .is_some_and(|(owner, _)| !Arc::ptr_eq(owner, &backing))
            })
        {
            return Err(FsError::Busy);
        }
        for &phys in &whole {
            registry.entry(phys).or_insert_with(|| (backing.clone(), 0));
        }
        backing.owners.fetch_add(1, Ordering::AcqRel);
        backing.pending.fetch_add(1, Ordering::AcqRel);
        drop(registry);
        drop(keys);
        break backing;
    };
    drop(index);
    let memory_type = if object.is_vram() || object.is_wc() {
        narf_memory::MemoryType::WriteCombining
    } else {
        narf_memory::MemoryType::WriteBack
    };
    Ok(MmapBacking {
        frames,
        lifetime: Some(Arc::new(CpuMap {
            backing,
            published: AtomicBool::new(false),
        })),
        memory_type,
    })
}

/// `FRAMES`' metadata-alias count of `phys`, the census the CPU revocation
/// transaction checks every alias it finds against. A leaf lock.
fn alias_count(phys: u64) -> usize {
    FRAMES.lock().get(&phys).map_or(0, |(_, count)| *count)
}

/// Linux `ttm_bo_handle_move_mem` for an object a process has mmapped:
/// `ttm_bo_unmap_virtual` takes every CPU translation away before the move,
/// and the next fault maps the new placement (`xe_bo_cpu_fault`). Here
/// [`narf_filesystem::mmap_relocation::relocate`] freezes every CPU alias of
/// the object's current frames, runs `commit` (which moves the storage to
/// the system frames `new`, without allocating or awaiting) and rebinds the
/// aliases to `new`. `Ok(false)`: no CPU mapping is registered any more (the
/// caller moves the object as an unmapped one). `Busy`: a mapping not yet
/// published, an alias the snapshot cannot see, a relocation in flight, a
/// registered generation that is not the object's current one, or a refused
/// commit; nothing changed.
pub(crate) fn relocate(
    object: &Arc<GemObject>,
    new: &[u64],
    commit: &mut dyn FnMut() -> Result<(), FsError>,
) -> Result<bool, FsError> {
    let backing = {
        let mut index = BACKINGS.lock();
        index.retain(|weak| weak.strong_count() != 0);
        let found = index
            .iter()
            .filter_map(Weak::upgrade)
            .find(|b| Arc::ptr_eq(&b.object, object) && !b.retired.load(Ordering::Acquire));
        found
    };
    let Some(backing) = backing else {
        return Ok(false);
    };
    if backing.moving.swap(true, Ordering::AcqRel) {
        return Err(FsError::Busy);
    }
    struct Moving(Arc<CpuBacking>);
    impl Drop for Moving {
        fn drop(&mut self) {
            self.0.moving.store(false, Ordering::Release);
            retire(&self.0);
        }
    }
    let moving = Moving(backing.clone());
    let current = object.cpu_frames(0, object.size as usize)?;
    if current.len() != new.len() {
        return Err(FsError::InvalidData);
    }
    // Everything the settle step stores is allocated here.
    let mut next = Vec::new();
    next.try_reserve_exact(new.len())
        .map_err(|_| FsError::OutOfMemory)?;
    next.extend_from_slice(new);
    let mut retired = Vec::new();
    retired
        .try_reserve_exact(new.len())
        .map_err(|_| FsError::OutOfMemory)?;
    let old = {
        let keys = backing.frames.lock();
        let mut frames = FRAMES.lock();
        if backing.retired.load(Ordering::Acquire) {
            // The last alias went before `moving` was published.
            drop((frames, keys, moving));
            return Ok(false);
        }
        // An mmap handed out but not yet installed would map the old frames.
        if backing.pending.load(Ordering::Acquire) != 0
            || *keys != current
            || keys.iter().any(|key| {
                !frames
                    .get(key)
                    .is_some_and(|(owner, _)| Arc::ptr_eq(owner, &backing))
            })
            || new.iter().any(|key| frames.contains_key(key))
        {
            return Err(FsError::Busy);
        }
        for &key in new {
            frames.insert(key, (backing.clone(), 0));
        }
        keys.to_vec()
    };
    let result = narf_filesystem::mmap_relocation::relocate(&old, new, alias_count, commit);
    let stale = {
        let mut keys = backing.frames.lock();
        let mut frames = FRAMES.lock();
        for key in if result.is_ok() { &old[..] } else { new } {
            let (owner, count) = frames.remove(key).expect("registered Intel CPU frame");
            assert_eq!(count, 0, "CPU alias census did not move every alias");
            retired.push(owner);
        }
        result.is_ok().then(|| core::mem::replace(&mut *keys, next))
    };
    // Row and key releases run outside the registry locks.
    drop(stale);
    drop(retired);
    drop(moving);
    result.map(|()| true)
}

/// The existing VM mmap path calls this only after leaves and their owner
/// exist. Duplicate forwarding is harmless; failed mmap drops a pending token.
pub(crate) fn published(lifetime: Option<&Arc<dyn narf_filesystem::MmapLifetime>>) {
    let Some(lifetime) = lifetime else {
        return;
    };
    let any: &dyn core::any::Any = lifetime.as_ref();
    if let Some(map) = any.downcast_ref::<CpuMap>() {
        if !map.published.swap(true, Ordering::AcqRel) {
            map.backing.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_cpu_mapping_tests.rs"]
mod tests;
