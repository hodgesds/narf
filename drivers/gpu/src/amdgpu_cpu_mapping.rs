//! Revocable CPU mappings. Physical alias counts also retain backing during
//! fork's interval between copying VMA metadata and publishing file owners.
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
    if backing.moving.load(Ordering::Acquire) || backing.owners.load(Ordering::Acquire) != 0 {
        return;
    }
    let keys = backing.frames.lock().clone();
    let mut frames = FRAMES.lock();
    if backing.moving.load(Ordering::Acquire)
        || backing.owners.load(Ordering::Acquire) != 0
        || keys
            .iter()
            .any(|p| frames.get(p).is_some_and(|(_, n)| *n != 0))
    {
        return;
    }
    for key in keys {
        frames.remove(&key);
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
    let placement = object.placement.lock();
    let mut index = BACKINGS.lock();
    index.retain(|weak| weak.strong_count() != 0);
    let existing = index
        .iter()
        .filter_map(Weak::upgrade)
        .find(|backing| Arc::ptr_eq(&backing.object, &object));
    let backing = if let Some(backing) = existing {
        if backing.moving.load(Ordering::Acquire) {
            return Err(FsError::Busy);
        }
        backing
    } else {
        let frames = placement.frames(0, object.byte_len as usize)?;
        let backing = Arc::new(CpuBacking {
            object: object.clone(),
            placement: IrqSafeSpinLock::new(Some(placement.clone())),
            frames: IrqSafeSpinLock::new(frames),
            owners: AtomicUsize::new(0),
            pending: AtomicUsize::new(0),
            moving: AtomicBool::new(false),
        });
        index.push(Arc::downgrade(&backing));
        backing
    };
    let frames = placement.frames(offset, len)?;
    {
        let keys = backing.frames.lock();
        let mut registry = FRAMES.lock();
        for &key in keys.iter() {
            if registry
                .get(&key)
                .is_some_and(|(owner, _)| !Arc::ptr_eq(owner, &backing))
            {
                return Err(FsError::Busy);
            }
        }
        for &key in keys.iter() {
            registry.entry(key).or_insert_with(|| (backing.clone(), 0));
        }
        backing.owners.fetch_add(1, Ordering::AcqRel);
        backing.pending.fetch_add(1, Ordering::AcqRel);
    }
    Ok(narf_filesystem::MmapBacking {
        frames,
        lifetime: Some(Arc::new(CpuMap {
            backing,
            published: AtomicBool::new(false),
        })),
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
    let backing = BACKINGS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .find(|backing| Arc::ptr_eq(&backing.object, object));
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
    let _moving = Moving(backing.clone());
    if backing.pending.load(Ordering::Acquire) != 0 || source.hidden_address().is_some() {
        return Err(FsError::Busy);
    }
    let destination = Arc::new(destination(object, to_vram)?);
    let old = source.frames(0, object.byte_len as usize)?;
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
    let result = narf_filesystem::mmap_relocation::relocate(&old, &new, alias_count, &mut || {
        let lease = backing.placement.lock().take().ok_or(FsError::Busy)?;
        if !Arc::ptr_eq(&lease, &source) {
            *backing.placement.lock() = Some(lease);
            return Err(FsError::Busy);
        }
        drop(lease);
        let result = commit(object, &source, &destination);
        *backing.placement.lock() = Some(if result.is_ok() {
            destination.clone()
        } else {
            source.clone()
        });
        result
    });
    {
        let mut frames = FRAMES.lock();
        for key in if result.is_ok() { &old } else { &new } {
            let (_, count) = frames.remove(key).expect("registered CPU backing frame");
            assert_eq!(
                count, 0,
                "CPU alias census did not retire the old generation"
            );
        }
    }
    if result.is_ok() {
        *backing.frames.lock() = new;
    }
    result
}

fn destination(object: &GemObject, to_vram: bool) -> Result<GemPlacement, FsError> {
    if !to_vram {
        return GemPlacement::new_system(object.byte_len);
    }
    let heap = object.card.and_then(vram_heap).ok_or(FsError::NoDevice)?;
    let align = object
        .alignment
        .max(PAGE_SIZE)
        .checked_next_power_of_two()
        .ok_or(FsError::InvalidData)?;
    let held = heap
        .pool
        .reserve_aligned(object.byte_len, align)
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

fn commit(
    object: &GemObject,
    source: &Arc<GemPlacement>,
    destination: &Arc<GemPlacement>,
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
        || object.allowed_domains.load(Ordering::Acquire) & u64::from(domain) == 0
        || !object
            .dma_buf
            .resv
            .fences(narf_filesystem::dma_buf::DmaResvUsage::Bookkeep)
            .is_empty()
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
