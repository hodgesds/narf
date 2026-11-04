//! Revocation of user CPU mappings of a device aperture, and their refault.
//!
//! Linux revokes a buffer object's CPU mappings with `ttm_bo_unmap_virtual`
//! (`drm_vma_node_unmap` -> `unmap_mapping_range`): every PTE goes, every VMA
//! stays, and the next CPU access faults into the driver (`xe_bo_cpu_fault`
//! -> `__xe_bo_cpu_fault`), which takes a runtime-PM reference, resuming the
//! device, before it inserts the same PFN again. Xe runs this over every VRAM
//! object on its `vram_userfault` list when it runtime-suspends
//! (`xe_pm_runtime_suspend` -> `xe_bo_runtime_pm_release_mmap_offset`),
//! because the LMEM BAR does not decode while the function is in D3.
//!
//! A NARF VMA keeps its backing frames in `Region::phys`, and several paths
//! build leaves from that backing (materialize for mmap and fork, mprotect).
//! A revocation therefore names a physical range, and while it is live:
//!
//! - no leaf for a frame in the range is installed in a `SHARED` region by
//!   any of those paths (they leave the slot unmapped, as for a guard page);
//! - a fault on such a page calls the revocation's [`DeviceFrameRefault`]
//!   hook with no address-space lock held and waits for its future through
//!   the waiter the syscall layer installs ([`install_refault_wait`]), which
//!   parks the faulting task. When the future completes the access retries;
//!   once the driver has dropped the revocation, the ordinary fault repair
//!   installs the same frame again.
//!
//! [`revoke_device_frames`] removes every present leaf of the range in every
//! address space the caller names, under the global shared-mapping
//! transaction and every one of those region tables, and completes the TLB
//! invalidation before it returns. Mirroring [`super::with_revoked_shared_frames`],
//! it refuses when the provider's metadata-alias census finds an alias the
//! snapshot does not (a fork child still being built), so no translation
//! outside the snapshot survives. Region slots, VMAs and alias references
//! are left alone: revocation only takes translations away.
//!
//! Lock order: shared-mapping transaction -> region tables (ascending
//! identity) -> revocation registry. Faults, materialize and mprotect take
//! the registry under one region lock. The registry lock is a leaf.

use super::*;
use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Why a refault could not make its page accessible: the fault is delivered
/// as `SIGBUS` (Linux `VM_FAULT_SIGBUS` from `xe_err_to_fault_t`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceRefaultError {
    /// The device could not be resumed, or was lost.
    Bus,
}

/// Completes once the revoked frame may be accessed again.
pub type DeviceRefaultFuture =
    Pin<Box<dyn Future<Output = Result<(), DeviceRefaultError>> + Send + 'static>>;

/// A driver's refault hook for one revocation (Linux `vm_ops->fault` of the
/// revoked mappings).
pub trait DeviceFrameRefault: Send + Sync {
    /// Called with no address-space lock held when a task touches a page
    /// whose frame `phys` is revoked. The future must complete only after the
    /// device is accessible again and the driver has dropped its
    /// [`DeviceFrameRevocation`], or with an error.
    fn refault(&self, phys: PhysAddr) -> DeviceRefaultFuture;
}

/// Drives a refault future to completion, parking the faulting task while it
/// is pending; `None` when the task cannot wait (a fatal signal, or no task
/// context). Installed by the layer that owns task parking.
pub type DeviceRefaultWait = fn(DeviceRefaultFuture) -> Option<Result<(), DeviceRefaultError>>;

static WAIT: IrqSafeSpinLock<Option<DeviceRefaultWait>> = IrqSafeSpinLock::new(None);

/// Install the refault waiter, returning the one it replaced.
pub fn install_refault_wait(wait: Option<DeviceRefaultWait>) -> Option<DeviceRefaultWait> {
    core::mem::replace(&mut *WAIT.lock(), wait)
}

/// Bound on simultaneously live revocations (one per suspended device).
pub const MAX_DEVICE_REVOCATIONS: usize = 16;

/// The device provider's alias census over `[start, end)`: report
/// `(frame, metadata aliases)` once for every frame with a nonzero count.
/// See [`revoke_device_frames`] for when it runs and what it may do.
pub type DeviceAliasCensus = fn(u64, u64, &mut dyn FnMut(u64, usize));

struct Entry {
    id: u64,
    start: u64,
    end: u64,
    refault: Arc<dyn DeviceFrameRefault>,
}

type Registry = [Option<Entry>; MAX_DEVICE_REVOCATIONS];

static REVOKED: IrqSafeSpinLock<Registry> =
    IrqSafeSpinLock::new([const { None }; MAX_DEVICE_REVOCATIONS]);
/// Live revocations. Zero lets every leaf installer and fault skip the
/// registry after one load.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[inline]
fn active() -> bool {
    ACTIVE.load(Ordering::Acquire) != 0
}

fn entry_for(registry: &Registry, phys: u64) -> Option<&Entry> {
    registry
        .iter()
        .flatten()
        .find(|entry| entry.start <= phys && phys < entry.end)
}

/// Whether `phys` lies in a live revocation.
pub fn is_revoked(phys: PhysAddr) -> bool {
    active() && entry_for(&REVOKED.lock(), phys.raw()).is_some()
}

/// `slots` with every frame of a live revocation zeroed. Leaf installers
/// leave a zero slot unmapped, so a revoked frame is never mapped by them.
/// The registry is consulted in windows of 64 slots, and any copy is made
/// with only the caller's locks held.
pub(super) fn masked(mut slots: Cow<'_, [PhysAddr]>) -> Cow<'_, [PhysAddr]> {
    if !active() {
        return slots;
    }
    let mut start = 0;
    while start < slots.len() {
        let end = (start + 64).min(slots.len());
        let mask = {
            let registry = REVOKED.lock();
            slots[start..end]
                .iter()
                .enumerate()
                .filter(|(_, phys)| phys.raw() != 0 && entry_for(&registry, phys.raw()).is_some())
                .fold(0u64, |mask, (index, _)| mask | 1 << index)
        };
        if mask != 0 {
            let owned = slots.to_mut();
            for (index, slot) in owned[start..end].iter_mut().enumerate() {
                if mask & 1 << index != 0 {
                    *slot = PhysAddr::new(0);
                }
            }
        }
        start = end;
    }
    slots
}

/// Wait for the device behind a revoked frame, as a fault on it must.
/// `Ok` means the access should retry (the revocation may also have ended
/// meanwhile); a failure is `Bus`. Called with no address-space lock held.
pub(super) fn await_refault(phys: PhysAddr) -> Result<(), AddressSpaceError> {
    let refault = {
        let registry = REVOKED.lock();
        entry_for(&registry, phys.raw()).map(|entry| entry.refault.clone())
    };
    let Some(refault) = refault else {
        return Ok(());
    };
    let wait = *WAIT.lock();
    let wait = wait.ok_or(AddressSpaceError::Bus)?;
    match wait(refault.refault(phys)) {
        Some(Ok(())) => Ok(()),
        Some(Err(DeviceRefaultError::Bus)) | None => Err(AddressSpaceError::Bus),
    }
}

/// A live revocation (Linux: the window between `unmap_mapping_range` and the
/// next fault). Dropping it ends the revocation: leaf installers and faults
/// map the range's frames again. The driver drops it once the device is
/// accessible, before completing the refault futures it handed out.
#[derive(Debug)]
pub struct DeviceFrameRevocation {
    id: u64,
    start: u64,
    end: u64,
}

impl DeviceFrameRevocation {
    /// The revoked physical range `[start, start + len)`.
    pub fn range(&self) -> (PhysAddr, u64) {
        (PhysAddr::new(self.start), self.end - self.start)
    }
}

impl Drop for DeviceFrameRevocation {
    fn drop(&mut self) {
        let removed = {
            let mut registry = REVOKED.lock();
            let slot = registry
                .iter_mut()
                .find(|slot| slot.as_ref().is_some_and(|entry| entry.id == self.id));
            slot.and_then(Option::take)
        };
        if removed.is_some() {
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
        }
        // The hook's last reference, if this was it, drops unlocked.
        drop(removed);
    }
}

/// One present or metadata-only alias of a revoked frame.
#[derive(Clone, Copy)]
struct Alias {
    space: usize,
    va: VirtAddr,
    phys: PhysAddr,
    present: bool,
    tracked: bool,
}

/// Revoke every user CPU translation of the device frames in
/// `[start, start + len)` and keep them revoked until the returned handle is
/// dropped (Linux `ttm_bo_unmap_virtual`).
///
/// Every present leaf of the range in `spaces` is removed together with its
/// reverse-map owner, interval notifiers fire `Clear` over each space's
/// revoked span, and the TLB invalidation of every space completes before
/// this returns. VMAs, backing slots and alias references are untouched, and
/// no frame is released. Leaves of the range are installed again only by a
/// fault after the handle is dropped; a fault before then calls `refault`.
///
/// Refused, with nothing changed: a misaligned or empty range, or one
/// overlapping a live revocation (`AlignmentMismatch`, `Overlap`); a frame of
/// the range in a private region or mapped by a leaf that does not translate
/// to exactly it (`Overlap`); a pinned frame, a present leaf without its
/// reverse-map owner, or a census mismatch, meaning an alias outside
/// `spaces` or one the provider does not count (`Pinned`); no free registry
/// slot or no memory (`AllocationFailed`).
///
/// # Safety
/// The range must be device memory the caller owns for as long as the handle
/// lives, and every space must own a live root or a zero metadata-only root.
/// `census(start, end, report)` must call `report(frame, aliases)` once for
/// every frame in `[start, end)` with a nonzero external metadata-alias
/// count, including aliases not yet scheduler-visible. It runs inside the
/// global shared-mapping transaction (which excludes every alias change)
/// with every region table of `spaces` locked: it may take only leaf locks
/// and must not allocate.
pub unsafe fn revoke_device_frames(
    spaces: &[Arc<AddressSpace>],
    start: PhysAddr,
    len: u64,
    census: DeviceAliasCensus,
    refault: Arc<dyn DeviceFrameRefault>,
) -> Result<DeviceFrameRevocation, AddressSpaceError> {
    let lo = start.raw();
    let hi = lo
        .checked_add(len)
        .filter(|_| lo != 0 && lo & 4095 == 0 && len != 0 && len & 4095 == 0)
        .ok_or(AddressSpaceError::AlignmentMismatch)?;
    let mut spaces: Vec<_> = spaces.iter().collect();
    spaces.sort_unstable_by_key(|space| space.identity());
    spaces.dedup_by_key(|space| space.identity());
    let mut spans = Vec::new();
    spans
        .try_reserve_exact(spaces.len())
        .map_err(|_| AddressSpaceError::AllocationFailed)?;
    spans.resize(spaces.len(), (u64::MAX, 0u64));
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut entry = Some(Entry {
        id,
        start: lo,
        end: hi,
        refault,
    });
    with_shared_mapping_transaction(|| {
        for space in &spaces {
            space.flush_deferred();
        }
        // Canonical order: shared transaction -> region tables, ascending by
        // identity, as in `with_revoked_shared_frames`.
        let tables: Vec<_> = spaces.iter().map(|space| space.regions.lock()).collect();
        let mut found: Vec<Alias> = Vec::new();
        for (s, table) in tables.iter().enumerate() {
            let root = spaces[s].root;
            for region in table.iter() {
                for (slot, &phys) in region.phys.indexed() {
                    if !(lo..hi).contains(&phys.raw()) {
                        continue;
                    }
                    if !region.perms.contains(RegionPerms::SHARED) {
                        return Err(AddressSpaceError::Overlap);
                    }
                    let va = VirtAddr::new(region.base.raw() + slot as u64 * 4096);
                    let mapped_at = if root.raw() == 0 {
                        None
                    } else {
                        // SAFETY: the live root and its leaf are protected by
                        // the region lock and the global shared transaction.
                        unsafe {
                            #[cfg(target_arch = "x86_64")]
                            {
                                crate::x86_64::paging::translate(root, va)
                            }
                            #[cfg(target_arch = "aarch64")]
                            {
                                crate::aarch64::paging::translate(root, va)
                            }
                        }
                    };
                    let present = match mapped_at {
                        None => false,
                        Some(at) if at == phys => true,
                        // Only an exact base leaf can be revoked.
                        Some(_) => return Err(AddressSpaceError::Overlap),
                    };
                    found
                        .try_reserve(1)
                        .map_err(|_| AddressSpaceError::AllocationFailed)?;
                    found.push(Alias {
                        space: s,
                        va,
                        phys,
                        present,
                        tracked: crate::rmap::contains_owner(phys, root, va),
                    });
                }
            }
        }
        // Census: every present leaf is reverse-mapped and its frame unpinned;
        // per frame, the reverse-map owners are exactly the tracked aliases
        // found. The provider then reports every aliased frame of the range,
        // under this transaction, which excludes every alias change: each
        // report must equal the aliases found for it (a frame no snapshot
        // space holds is an alias outside `spaces`), and every frame found
        // must be reported (an alias the provider does not own).
        found.sort_unstable_by_key(|alias| alias.phys.raw());
        if found.iter().any(|alias| alias.present && !alias.tracked) {
            return Err(AddressSpaceError::Pinned);
        }
        let mut distinct = 0usize;
        for run in found.chunk_by(|a, b| a.phys == b.phys) {
            let phys = run[0].phys;
            let tracked = run.iter().filter(|alias| alias.tracked).count();
            if crate::frame::cow::is_pinned(phys) || crate::rmap::owner_count(phys) != tracked {
                return Err(AddressSpaceError::Pinned);
            }
            distinct += 1;
        }
        let mut reported = 0usize;
        let mut consistent = true;
        census(lo, hi, &mut |frame, count| {
            let first = found.partition_point(|alias| alias.phys.raw() < frame);
            let held = found[first..]
                .iter()
                .take_while(|alias| alias.phys.raw() == frame)
                .count();
            if !(lo..hi).contains(&frame) || held != count || count == 0 {
                consistent = false;
            } else {
                reported += 1;
            }
        });
        if !consistent || reported != distinct {
            return Err(AddressSpaceError::Pinned);
        }
        // Publish before removing any leaf: from here every installer masks
        // the range and every fault on it refaults.
        {
            let mut registry = REVOKED.lock();
            if registry
                .iter()
                .flatten()
                .any(|other| other.start < hi && lo < other.end)
            {
                return Err(AddressSpaceError::Overlap);
            }
            let slot = registry
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or(AddressSpaceError::AllocationFailed)?;
            *slot = entry.take();
            ACTIVE.fetch_add(1, Ordering::AcqRel);
        }
        for alias in found.iter().filter(|alias| alias.present) {
            let root = spaces[alias.space].root;
            // SAFETY: an exact validated base leaf of this live root; the
            // unmap keeps its table path and releases no backing.
            let removed = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::x86_64::paging::unmap_4kb_local(root, alias.va).ok()
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::aarch64::paging::unmap_4kb(root, alias.va).ok()
                }
            };
            assert_eq!(removed, Some(alias.phys), "validated device leaf changed");
            // The owner follows the leaf: the refault's repair adds it back.
            crate::rmap::remove_without_shrink(alias.phys, root, alias.va);
            let span = &mut spans[alias.space];
            span.0 = span.0.min(alias.va.raw());
            span.1 = span.1.max(alias.va.raw() + 4096);
        }
        for (s, &(span_lo, span_hi)) in spans.iter().enumerate() {
            if span_lo < span_hi {
                // Under this space's region lock, before the call returns.
                spaces[s].notify_invalidate(
                    span_lo,
                    span_hi,
                    crate::mmu_notifier::MmuNotifierEvent::Clear,
                );
            }
        }
        // Every CPU stops translating the range under each space's own tag
        // before the device may leave D0. aarch64's unmap_4kb already
        // broadcast an inner-shareable invalidation per leaf.
        #[cfg(target_arch = "x86_64")]
        for (space, &(span_lo, span_hi)) in spaces.iter().zip(&spans) {
            if span_lo < span_hi {
                space.flush_range_all_cpus(VirtAddr::new(span_lo), (span_hi - span_lo) / 4096);
            }
        }
        drop(tables);
        Ok(())
    })?;
    // `found` and the tables were released inside the transaction; a refused
    // call drops the unpublished entry (and its hook reference) here.
    drop(entry);
    Ok(DeviceFrameRevocation {
        id,
        start: lo,
        end: hi,
    })
}
