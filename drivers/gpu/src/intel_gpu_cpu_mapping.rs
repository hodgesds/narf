//! Retained Intel CPU-frame census for atomic GEM and PRIME mmap backing.
//!
//! Tokens retain the same immutable BO/reservation object. Physical rows keep
//! it alive independently while fork metadata exists before child file-owner
//! publication. This supplies alias ownership, not storage migration: the
//! existing CPU revocation transaction cannot await a retained GPU copy.
//!
//! Lock order: BACKINGS -> FRAMES. Frame alias callbacks use only FRAMES.
//! No registry lock spans a VM call, user callback, GPU operation or await.
use super::*;
use alloc::sync::Weak;
use core::sync::atomic::{AtomicBool, AtomicUsize};

#[derive(Debug)]
struct CpuBacking {
    object: Arc<GemObject>,
    frames: Vec<u64>,
    owners: AtomicUsize,
    pending: AtomicUsize,
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
    if backing.owners.load(Ordering::Acquire) != 0 {
        return;
    }
    let mut frames = FRAMES.lock();
    if backing.retired.load(Ordering::Acquire)
        || backing.owners.load(Ordering::Acquire) != 0
        || backing.frames.iter().any(|phys| {
            frames
                .get(phys)
                .is_some_and(|(owner, count)| Arc::ptr_eq(owner, backing) && *count != 0)
        })
    {
        return;
    }
    backing.retired.store(true, Ordering::Release);
    for phys in &backing.frames {
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
                    frames: keys,
                    owners: AtomicUsize::new(0),
                    pending: AtomicUsize::new(0),
                    retired: AtomicBool::new(false),
                });
                index.push(Arc::downgrade(&backing));
                backing
            }
        };
        let mut registry = FRAMES.lock();
        if backing.retired.load(Ordering::Acquire) {
            continue;
        }
        if backing.frames != whole
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
