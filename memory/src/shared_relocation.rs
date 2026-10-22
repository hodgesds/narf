//! Failure-atomic synchronous revocation of externally owned CPU aliases.
use super::*;
use alloc::sync::Arc;

#[cfg(target_arch = "x86_64")]
type LeafFlags = crate::x86_64::paging::PtFlags;
#[cfg(target_arch = "aarch64")]
type LeafFlags = crate::aarch64::paging::PtFlags;

#[derive(Clone, Copy)]
struct Alias {
    space: usize,
    region: u64,
    /// The region's permissions, for recomputing the leaf memory type of
    /// whichever frame the alias is rebound to.
    perms: RegionPerms,
    slot: usize,
    va: VirtAddr,
    frame: usize,
    /// The exact original 4 KiB leaf attributes; `None` for a metadata-only
    /// alias (lazy, PROT_NONE, guard page, or a root still being built).
    leaf: Option<LeafFlags>,
    /// The reverse map names this `(root, va)`. Every present leaf is
    /// tracked; a PROT_NONE leaf keeps its owner for the later re-protect.
    tracked: bool,
}

/// Per-space bounds of revoked leaves, for one tagged invalidation each.
#[derive(Clone, Copy)]
struct Span {
    lo: u64,
    hi: u64,
}

/// Revoke every alias before `commit`, then rebind to `new` on success or
/// restore `old` on error. Faults and permission rewrites remain excluded by
/// the region locks. An external metadata-alias census refuses missing spaces
/// (notably a child still being constructed by fork). Long-term pins refuse
/// the operation.
///
/// Every allocation (alias list, destination reverse-map rows and owner
/// capacity) and every validation precedes leaf revocation, so neither the
/// commit nor the rebind can fail for lack of memory. Rebinding reinstalls the
/// original leaf attributes on the retained leaf-table paths, with the memory
/// type recomputed for the target frame (`memtype::rebind_leaf_flags`); absent
/// metadata aliases stay absent, and reverse-map owners move with exactly the
/// aliases that had them.
///
/// # Safety
/// Both frame lists must remain externally owned until return, and each space
/// must own a live root or a zero metadata-only root. `commit` may neither
/// await nor enter VMA/shared transactions, acquire a region lock, or release
/// either frame list. It must preserve old backing on error and must not
/// allocate. The alias counter must count all externally retained metadata
/// aliases, including aliases not yet scheduler-visible; it runs with every
/// selected region table locked and may take only leaf locks.
pub unsafe fn with_revoked_shared_frames(
    spaces: &[Arc<AddressSpace>],
    old: &[PhysAddr],
    new: &[PhysAddr],
    aliases: fn(u64) -> usize,
    commit: impl FnOnce() -> Result<(), AddressSpaceError>,
) -> Result<(), AddressSpaceError> {
    if old.is_empty()
        || old.len() != new.len()
        || old
            .iter()
            .chain(new)
            .any(|p| p.raw() == 0 || p.raw() & 4095 != 0)
    {
        return Err(AddressSpaceError::AlignmentMismatch);
    }
    let mut index = alloc::collections::BTreeMap::new();
    let mut destinations = alloc::collections::BTreeSet::new();
    for (i, (&source, &target)) in old.iter().zip(new).enumerate() {
        if index.insert(source.raw(), i).is_some() || !destinations.insert(target.raw()) {
            return Err(AddressSpaceError::Overlap);
        }
    }
    if index.keys().any(|p| destinations.contains(p)) {
        return Err(AddressSpaceError::Overlap);
    }
    let mut spaces: Vec<_> = spaces.iter().collect();
    spaces.sort_unstable_by_key(|space| space.identity());
    spaces.dedup_by_key(|space| space.identity());
    let mut counts = alloc::vec![0usize; old.len()];
    let mut tracked = alloc::vec![0usize; old.len()];
    let mut spans = alloc::vec![Span { lo: u64::MAX, hi: 0 }; spaces.len()];
    with_shared_mapping_transaction(|| {
        for space in &spaces {
            space.flush_deferred();
        }
        // Canonical order: shared transaction -> region tables, ascending by
        // identity. No other path holds two region tables without holding a
        // shared transaction shard, which this transaction excludes.
        let mut tables: Vec<_> = spaces.iter().map(|space| space.regions.lock()).collect();
        let mut found = Vec::new();
        for (s, table) in tables.iter().enumerate() {
            let root = spaces[s].root;
            for region in table.iter() {
                for (slot, phys) in region.phys.indexed() {
                    let Some(&frame) = index.get(&phys.raw()) else {
                        continue;
                    };
                    if !region.perms.contains(RegionPerms::SHARED)
                        || region.perms.contains(RegionPerms::LOCKED)
                    {
                        return Err(AddressSpaceError::Pinned);
                    }
                    let va = VirtAddr::new(region.base.raw() + slot as u64 * 4096);
                    let leaf = if root.raw() == 0 {
                        None
                    } else {
                        // SAFETY: the live root and leaf are protected by the
                        // region lock and the global shared transaction.
                        let (mapped, flags) = unsafe {
                            #[cfg(target_arch = "x86_64")]
                            {
                                (
                                    crate::x86_64::paging::translate(root, va),
                                    crate::x86_64::paging::flags_at(root, va),
                                )
                            }
                            #[cfg(target_arch = "aarch64")]
                            {
                                (
                                    crate::aarch64::paging::translate(root, va),
                                    crate::aarch64::paging::flags_at(root, va),
                                )
                            }
                        };
                        match (mapped, flags) {
                            (None, _) => None,
                            // Only an exact base leaf can be revoked and later
                            // restored on its retained table path.
                            (Some(at), Some(flags)) if at == *phys => Some(flags),
                            _ => return Err(AddressSpaceError::Overlap),
                        }
                    };
                    found
                        .try_reserve(1)
                        .map_err(|_| AddressSpaceError::AllocationFailed)?;
                    found.push(Alias {
                        space: s,
                        region: region.base.raw(),
                        perms: region.perms,
                        slot,
                        va,
                        frame,
                        leaf,
                        tracked: false,
                    });
                    counts[frame] += 1;
                    if leaf.is_some() {
                        let span = &mut spans[s];
                        span.lo = span.lo.min(va.raw());
                        span.hi = span.hi.max(va.raw() + 4096);
                    }
                }
            }
        }
        // Census: metadata aliases must match every externally retained
        // alias (a missing or retiring root shows up as a shortfall). Every
        // present leaf must be reverse-mapped, and every reverse-map owner
        // must be one of the distinct aliases found above, so no translation
        // outside the snapshot can survive revocation.
        for alias in &mut found {
            let root = spaces[alias.space].root;
            alias.tracked = crate::rmap::contains_owner(old[alias.frame], root, alias.va);
            if alias.leaf.is_some() && !alias.tracked {
                return Err(AddressSpaceError::Pinned);
            }
            tracked[alias.frame] += usize::from(alias.tracked);
        }
        for (i, &phys) in old.iter().enumerate() {
            if crate::frame::cow::is_pinned(phys)
                || counts[i] != aliases(phys.raw())
                || crate::rmap::owner_count(phys) != tracked[i]
            {
                return Err(AddressSpaceError::Pinned);
            }
        }
        // Prepare destination rows and owner capacity while failure is still
        // free of side effects.
        for i in 0..new.len() {
            #[cfg(feature = "kernel-test")]
            let injected = FAIL_PREPARE_AT
                .compare_exchange(
                    i + 1,
                    0,
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                )
                .is_ok();
            #[cfg(not(feature = "kernel-test"))]
            let injected = false;
            if injected || crate::rmap::try_prepare_owner_slots(new[i], tracked[i]).is_err() {
                for j in 0..i {
                    crate::rmap::release_reserved_owner_slots(new[j], tracked[j]);
                }
                return Err(AddressSpaceError::AllocationFailed);
            }
        }
        for alias in found.iter().filter(|alias| alias.leaf.is_some()) {
            // SAFETY: an exact validated existing base leaf; unmap retains its
            // page-table path. No backing is released by this operation.
            let result = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::x86_64::paging::unmap_4kb_local(spaces[alias.space].root, alias.va)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::aarch64::paging::unmap_4kb(spaces[alias.space].root, alias.va)
                }
            };
            assert_eq!(
                result.ok(),
                Some(old[alias.frame]),
                "validated shared leaf changed"
            );
        }
        // All leaves are gone from every CPU, under each space's own
        // translation tag, before any source byte may be read or changed.
        invalidate(&spaces, &spans);
        let result = commit();
        let target = if result.is_ok() { new } else { old };
        let hooks = *SHARED_FRAME_HOOKS.lock();
        for alias in &found {
            let space = spaces[alias.space];
            let phys = target[alias.frame];
            if result.is_ok() {
                tables[alias.space]
                    .get_mut(alias.region)
                    .expect("locked shared region")
                    .store_backing(alias.slot, phys);
                if let Some((retain, release)) = hooks {
                    retain(phys.raw());
                    release(old[alias.frame].raw());
                }
            }
            if result.is_ok() && alias.tracked {
                crate::rmap::remove_without_shrink(old[alias.frame], space.root, alias.va);
                crate::rmap::add_reserved(phys, space.root, alias.va);
            }
            let Some(flags) = alias.leaf else {
                continue;
            };
            // The original attributes, except the memory type: that belongs
            // to the frame, so a write-combining device leaf rebound onto
            // System RAM becomes write-back (`memtype` alias rule). Restoring
            // the old frame on error recomputes its original type.
            let flags = crate::memtype::rebind_leaf_flags(flags, alias.perms, phys);
            // SAFETY: exact same retained leaf-table path, live target and the
            // original leaf attributes. No page-table allocation is needed;
            // an error here is an internal invariant violation.
            let mapped = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::x86_64::paging::map_4kb(space.root, alias.va, phys, flags)
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::aarch64::paging::map_4kb(space.root, alias.va, phys, flags)
                }
            };
            assert!(mapped.is_ok(), "revoked shared leaf could not be restored");
        }
        if result.is_err() {
            for (i, &phys) in new.iter().enumerate() {
                crate::rmap::release_reserved_owner_slots(phys, tracked[i]);
            }
        }
        // Not-present to present needs no shootdown: no CPU can cache the
        // revoked leaves after the invalidation above.
        drop(tables);
        result
    })
}

/// Invalidate each space's revoked span on every CPU under that space's own
/// tag. x86 needs the foreign-mutation flush: the local INVLPG in
/// `unmap_4kb_local` only covers the current hardware context. aarch64's
/// `unmap_4kb` already issued an inner-shareable all-ASID TLBI per leaf.
fn invalidate(spaces: &[&Arc<AddressSpace>], spans: &[Span]) {
    for (space, span) in spaces.iter().zip(spans) {
        if span.lo >= span.hi {
            continue;
        }
        #[cfg(target_arch = "x86_64")]
        space.flush_range_all_cpus(VirtAddr::new(span.lo), (span.hi - span.lo) / 4096);
        #[cfg(not(target_arch = "x86_64"))]
        let _ = space;
    }
}

/// One-shot injected destination-row preparation failure at frame `index`.
#[cfg(feature = "kernel-test")]
static FAIL_PREPARE_AT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(feature = "kernel-test")]
pub(crate) fn __test_fail_shared_revocation_prepare_at(index: usize) {
    FAIL_PREPARE_AT.store(index + 1, core::sync::atomic::Ordering::Release);
}

/// Test-only view of [`with_revoked_shared_frames`]'s census and rebind
/// effects: `(metadata aliases, present leaves)` of `phys` in `space`.
#[cfg(feature = "kernel-test")]
pub(crate) fn __shared_alias_census(space: &AddressSpace, phys: PhysAddr) -> (usize, usize) {
    let table = space.regions.lock();
    let mut metadata = 0;
    let mut leaves = 0;
    for region in table.iter() {
        for (slot, slot_phys) in region.phys.indexed() {
            if *slot_phys != phys {
                continue;
            }
            metadata += 1;
            let va = VirtAddr::new(region.base.raw() + slot as u64 * 4096);
            if space.root.raw() != 0 {
                // SAFETY: test caller owns the live root; region lock held.
                let mapped = unsafe {
                    #[cfg(target_arch = "x86_64")]
                    {
                        crate::x86_64::paging::translate(space.root, va)
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        crate::aarch64::paging::translate(space.root, va)
                    }
                };
                leaves += usize::from(mapped == Some(phys));
            }
        }
    }
    (metadata, leaves)
}
