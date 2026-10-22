//! Revocable CPU mappings. Physical alias counts also retain backing during
//! fork's interval between copying VMA metadata and publishing file owners.
//!
//! One live `CpuBacking` exists per GEM object with CPU mappings. Its
//! placement lease pins the current generation; `FRAMES` rows, keyed by every
//! frame of that generation, count external metadata aliases (address-space
//! slots, including fork children not yet scheduler-visible) and hold the
//! backing alive. Once no `CpuMap` owner and no alias remains, `retire` drops
//! the rows and lease and marks the backing retired; a retired backing is
//! never reused, so a stale `Weak` upgrade cannot resurrect old frames.
//!
//! This registry is the only device-alias provider: the filesystem's alias
//! hooks are a singleton that refuses replacement by another provider.
//!
//! Lock order: object placement -> `BACKINGS` -> backing frames -> `FRAMES`;
//! a backing's own placement slot is a leaf lock.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Debug)]
struct CpuBacking {
    object: Arc<GemObject>,
    placement: IrqSafeSpinLock<Option<Arc<GemPlacement>>>,
    frames: IrqSafeSpinLock<Vec<u64>>,
    owners: AtomicUsize,
    pending: AtomicUsize,
    moving: AtomicBool,
    /// Set under `FRAMES` once the rows are gone; terminal.
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

/// Retire a backing with no mapping owner and no metadata alias. `moving`,
/// `owners` and `retired` are all decided under `FRAMES`, which `relocate` and
/// `backing` also take before relying on them.
fn retire(backing: &Arc<CpuBacking>) {
    if backing.moving.load(Ordering::Acquire) || backing.owners.load(Ordering::Acquire) != 0 {
        return;
    }
    let removed = {
        let keys = backing.frames.lock();
        let mut frames = FRAMES.lock();
        if backing.retired.load(Ordering::Acquire)
            || backing.moving.load(Ordering::Acquire)
            || backing.owners.load(Ordering::Acquire) != 0
            || keys.iter().any(|p| {
                frames
                    .get(p)
                    .is_some_and(|(owner, n)| Arc::ptr_eq(owner, backing) && *n != 0)
            })
        {
            return;
        }
        let mut removed = Vec::new();
        for key in keys.iter() {
            if frames
                .get(key)
                .is_some_and(|(owner, _)| Arc::ptr_eq(owner, backing))
            {
                removed.extend(frames.remove(key).map(|(owner, _)| owner));
            }
        }
        backing.retired.store(true, Ordering::Release);
        removed
    };
    // Row Arcs and the lease may be the last references; release them with
    // the registry locks dropped.
    drop(removed);
    drop(backing.placement.lock().take());
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

/// Called by the external shared-frame owner hook, including fork metadata.
pub fn retain_cpu_frame(phys: u64) -> bool {
    let mut frames = FRAMES.lock();
    let Some((_, count)) = frames.get_mut(&phys) else {
        return false;
    };
    *count = count
        .checked_add(1)
        .expect("CPU device alias count overflow");
    true
}
/// Balance an external metadata alias after its leaf has been retired.
pub fn release_cpu_frame(phys: u64) -> bool {
    let backing = {
        let mut frames = FRAMES.lock();
        let Some((backing, count)) = frames.get_mut(&phys) else {
            return false;
        };
        assert!(*count != 0, "unbalanced CPU device alias release");
        *count -= 1;
        backing.clone()
    };
    retire(&backing);
    true
}
fn alias_count(phys: u64) -> usize {
    FRAMES.lock().get(&phys).map_or(0, |(_, count)| *count)
}

pub(crate) fn backing(
    object: Arc<GemObject>,
    offset: u64,
    len: usize,
) -> Result<narf_filesystem::MmapBacking, FsError> {
    if object.flags & u64::from(uapi::AMDGPU_GEM_CREATE_NO_CPU_ACCESS) != 0 {
        return Err(FsError::OperationNotPermitted);
    }
    narf_filesystem::mmap_relocation::install_alias_hooks(retain_cpu_frame, release_cpu_frame);
    // The placement lock excludes relocation commits, so this generation and
    // its frame snapshots stay current until the owner is registered.
    let placement = object.placement.lock();
    let whole = placement.frames(0, object.byte_len as usize)?;
    let frames = placement.frames(offset, len)?;
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
                let backing = Arc::new(CpuBacking {
                    object: object.clone(),
                    placement: IrqSafeSpinLock::new(Some(placement.clone())),
                    frames: IrqSafeSpinLock::new(whole.clone()),
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
            // Retired after the lookup; the next pass creates a fresh one.
            continue;
        }
        let current = backing
            .placement
            .lock()
            .as_ref()
            .is_some_and(|lease| Arc::ptr_eq(lease, &placement));
        if backing.moving.load(Ordering::Acquire) || !current || *keys != whole {
            return Err(FsError::Busy);
        }
        if keys.iter().any(|key| {
            registry
                .get(key)
                .is_some_and(|(owner, _)| !Arc::ptr_eq(owner, &backing))
        }) {
            return Err(FsError::Busy);
        }
        for &key in keys.iter() {
            registry.entry(key).or_insert_with(|| (backing.clone(), 0));
        }
        backing.owners.fetch_add(1, Ordering::AcqRel);
        backing.pending.fetch_add(1, Ordering::AcqRel);
        drop(registry);
        drop(keys);
        break backing;
    };
    drop(index);
    drop(placement);
    Ok(narf_filesystem::MmapBacking {
        frames,
        lifetime: Some(Arc::new(CpuMap {
            backing,
            published: AtomicBool::new(false),
        })),
        // Linux TTM's WC request persists across relocation: VRAM BAR leaves use
        // WC, while memory/ keeps each System RAM leaf write-back to match
        // its direct-map alias. A later promotion recomputes WC again.
        memory_type: narf_memory::MemoryType::WriteCombining,
    })
}

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

/// Prepare allocations before entering the CPU VM freeze. Registered GPU
/// leases have already been released by Rebind, and the card gate is held.
pub(crate) fn relocate(object: &Arc<GemObject>, to_vram: bool) -> Result<(), FsError> {
    // The frozen commit is a CPU copy, which cannot move a GFX12 DCC
    // buffer's compressed bytes (amdgpu_vm::relocate moves an unmapped one
    // through its engine; a CPU-mapped one stays put).
    if moves_by_engine(object) {
        return Err(FsError::Busy);
    }
    let backing = BACKINGS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .find(|b| Arc::ptr_eq(&b.object, object) && !b.retired.load(Ordering::Acquire));
    let Some(backing) = backing else {
        return object.relocate(to_vram);
    };
    let source = {
        let placement = object.placement.lock();
        if backing.moving.swap(true, Ordering::AcqRel) {
            return Err(FsError::Busy);
        }
        placement.clone()
    };
    struct Moving(Arc<CpuBacking>);
    impl Drop for Moving {
        fn drop(&mut self) {
            self.0.moving.store(false, Ordering::Release);
            retire(&self.0);
        }
    }
    let moving = Moving(backing.clone());
    let old = source.frames(0, object.byte_len as usize)?;
    {
        let keys = backing.frames.lock();
        let frames = FRAMES.lock();
        if backing.retired.load(Ordering::Acquire) {
            // The last alias disappeared before `moving` was published: no
            // CPU mapping remains, so move as an unmapped object.
            drop((frames, keys, moving, source));
            return object.relocate(to_vram);
        }
        // The registered generation must be exactly the current one.
        if *keys != old
            || keys.iter().any(|key| {
                !frames
                    .get(key)
                    .is_some_and(|(owner, _)| Arc::ptr_eq(owner, &backing))
            })
        {
            return Err(FsError::Busy);
        }
    }
    let domain = if to_vram {
        uapi::AMDGPU_GEM_DOMAIN_VRAM
    } else {
        uapi::AMDGPU_GEM_DOMAIN_CPU | uapi::AMDGPU_GEM_DOMAIN_GTT
    };
    let leased = backing
        .placement
        .lock()
        .as_ref()
        .is_some_and(|lease| Arc::ptr_eq(lease, &source));
    // Expected leases: object storage, `source`, and the backing's own. Any
    // other (deferred user fence, legacy raw mapping) pins this generation.
    if backing.pending.load(Ordering::Acquire) != 0
        || source.hidden_address().is_some()
        || !leased
        || object.allowed_domains.load(Ordering::Acquire) & u64::from(domain) == 0
    {
        return Err(FsError::Busy);
    }
    object.check_transfer_source(&source, 1)?;
    let resv = &object.dma_buf.resv;
    let generation = resv.generation();
    if !resv
        .fences(narf_filesystem::dma_buf::DmaResvUsage::Bookkeep)
        .is_empty()
    {
        return Err(FsError::Busy);
    }
    let destination = Arc::new(destination(object, to_vram)?);
    let new = destination.frames(0, object.byte_len as usize)?;
    {
        let mut frames = FRAMES.lock();
        if new.iter().any(|key| frames.contains_key(key)) {
            return Err(FsError::Busy);
        }
        for &key in &new {
            frames.insert(key, (backing.clone(), 0));
        }
    }
    // Runs with every alias revoked and every affected region table locked:
    // no allocation, no fence sampling, no lock above the placement locks.
    let result = narf_filesystem::mmap_relocation::relocate(&old, &new, alias_count, &mut || {
        let lease = backing.placement.lock().take().ok_or(FsError::Busy)?;
        if !Arc::ptr_eq(&lease, &source) {
            *backing.placement.lock() = Some(lease);
            return Err(FsError::Busy);
        }
        drop(lease);
        let result = commit(object, &source, &destination, generation);
        *backing.placement.lock() = Some(if result.is_ok() {
            destination.clone()
        } else {
            source.clone()
        });
        result
    });
    let retired = {
        let mut keys = backing.frames.lock();
        let mut frames = FRAMES.lock();
        let mut retired = Vec::new();
        for key in if result.is_ok() { &old } else { &new } {
            let (owner, count) = frames.remove(key).expect("registered CPU backing frame");
            assert_eq!(
                count, 0,
                "CPU alias census did not retire the old generation"
            );
            retired.push(owner);
        }
        if result.is_ok() {
            *keys = new;
        }
        retired
    };
    drop(retired);
    // `moving` clears first, then `source` (possibly the old generation's
    // last lease) is released after every alias and row is retired.
    drop(moving);
    drop(source);
    result
}

pub(crate) fn destination(object: &GemObject, to_vram: bool) -> Result<GemPlacement, FsError> {
    if !to_vram {
        return GemPlacement::new_system(object.byte_len);
    }
    let heap = object.card.and_then(vram_heap).ok_or(FsError::NoDevice)?;
    let align = object
        .alignment
        .max(PAGE_SIZE)
        .checked_next_power_of_two()
        .ok_or(FsError::InvalidData)?;
    let held = reserve_visible(&heap, object.card, object.flags, object.byte_len, align)
        .map_err(|_| FsError::NoSpace)?;
    let gpu = held
        .address()
        .checked_sub(heap.fb_base)
        .and_then(|a| a.checked_add(heap.fb_offset))
        .ok_or(FsError::InvalidData)?;
    crate::amdgpu_vm::make_pte(gpu, 0)?;
    crate::amdgpu_vm::make_pte(gpu + object.byte_len - PAGE_SIZE, 0)?;
    Ok(GemPlacement {
        phys: held.mapping().phys.raw(),
        gpu,
        system: false,
        byte_len: object.byte_len,
        backing: Backing::Vram { _held: held },
    })
}

/// Frozen commit: allocation-free and callback-free. `generation` was sampled
/// before the freeze together with an empty unsignalled-fence set.
fn commit(
    object: &GemObject,
    source: &Arc<GemPlacement>,
    destination: &Arc<GemPlacement>,
    generation: u64,
) -> Result<(), FsError> {
    let mut placement = object.placement.lock();
    let domain = if destination.system {
        uapi::AMDGPU_GEM_DOMAIN_CPU | uapi::AMDGPU_GEM_DOMAIN_GTT
    } else {
        uapi::AMDGPU_GEM_DOMAIN_VRAM
    };
    if !Arc::ptr_eq(&placement, source)
        || Arc::strong_count(source) != 2
        || Arc::weak_count(source) != 0
        || destination.byte_len != object.byte_len
        || object.allowed_domains.load(Ordering::Acquire) & u64::from(domain) == 0
        || object.dma_buf.resv.generation() != generation
    {
        return Err(FsError::Busy);
    }
    let mut offset = 0;
    while offset < object.byte_len {
        let (src, src_len) = cpu_run(source, offset)?;
        let (dst, dst_len) = cpu_run(destination, offset)?;
        let bytes = src_len.min(dst_len);
        // SAFETY: the VM hook revoked and globally invalidated every CPU alias;
        // card admission excludes GPU jobs and the exact lease census excludes
        // deferred CPU writers. Destination refs are private to this move.
        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, bytes as usize);
        }
        offset += bytes;
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    *placement = destination.clone();
    Ok(())
}
fn cpu_run(placement: &GemPlacement, offset: u64) -> Result<(u64, u64), FsError> {
    match &placement.backing {
        Backing::System(_) => {
            let (phys, run) = placement.locate(offset).ok_or(FsError::InvalidData)?;
            Ok((
                narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u8>() as u64,
                run,
            ))
        }
        Backing::Vram { _held } => Ok((_held.mapping().virt + offset, placement.byte_len - offset)),
        _ => Err(FsError::Unsupported),
    }
}

/// Test view: whether `object` has a live, unretired CPU backing.
#[cfg(feature = "kernel-test")]
fn live_backing(object: &Arc<GemObject>) -> bool {
    BACKINGS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .any(|b| Arc::ptr_eq(&b.object, object) && !b.retired.load(Ordering::Acquire))
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_cpu_mapping_tests.rs"]
mod tests;
