//! Failure-atomic synchronous revocation of externally owned CPU aliases.
use super::*;
use alloc::sync::Arc;

#[derive(Clone, Copy)]
struct Alias {
    space: usize,
    region: u64,
    slot: usize,
    va: VirtAddr,
    perms: RegionPerms,
    frame: usize,
    present: bool,
}

/// Revoke every alias before `commit`, then rebind to `new` on success or
/// restore `old` on error. Faults and permission rewrites remain excluded by
/// the region locks. An external metadata-alias census refuses missing spaces
/// (notably a child still being constructed by fork). Long-term pins refuse
/// the operation. All allocation and validation precedes leaf revocation.
///
/// # Safety
/// Both frame lists must remain externally owned until return, and each space
/// must own a live root or a zero metadata-only root. `commit` may neither
/// await nor enter VMA/shared transactions, acquire a region lock, or release
/// either frame list. It must preserve old backing on error and must not
/// allocate. The alias counter must count all externally retained metadata
/// aliases, including aliases not yet scheduler-visible.
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
    with_shared_mapping_transaction(|| {
        for space in &spaces {
            space.flush_deferred();
        }
        let mut tables: Vec<_> = spaces.iter().map(|space| space.regions.lock()).collect();
        let mut found = Vec::new();
        let mut counts = alloc::vec![0usize; old.len()];
        for (s, table) in tables.iter().enumerate() {
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
                    // SAFETY: caller owns the root; region locks exclude base
                    // leaf changes and the global transaction excludes teardown.
                    let mapped = if spaces[s].root.raw() == 0 {
                        None
                    } else {
                        // SAFETY: the live root and leaf are protected by the
                        // region lock and the global shared transaction.
                        unsafe {
                            #[cfg(target_arch = "x86_64")]
                            {
                                crate::x86_64::paging::translate(spaces[s].root, va)
                            }
                            #[cfg(target_arch = "aarch64")]
                            {
                                crate::aarch64::paging::translate(spaces[s].root, va)
                            }
                        }
                    };
                    if mapped.is_some_and(|at| at != *phys) {
                        return Err(AddressSpaceError::Overlap);
                    }
                    found
                        .try_reserve(1)
                        .map_err(|_| AddressSpaceError::AllocationFailed)?;
                    found.push(Alias {
                        space: s,
                        region: region.base.raw(),
                        slot,
                        va,
                        perms: region.perms,
                        frame,
                        present: mapped.is_some(),
                    });
                    counts[frame] += 1;
                }
            }
        }
        for (i, &phys) in old.iter().enumerate() {
            if crate::frame::cow::is_pinned(phys)
                || counts[i] != aliases(phys.raw())
                || crate::rmap::owner_count(phys) > counts[i]
            {
                return Err(AddressSpaceError::Pinned);
            }
        }
        for alias in &found {
            if !alias.present {
                continue;
            }
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
        // All leaves are gone before any source byte may be read or changed.
        for space in &spaces {
            space.flush_region_broadcast(VirtAddr::new(0), AddressSpace::USER_HALF_END / 4096);
        }
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
                crate::rmap::remove(old[alias.frame], space.root, alias.va);
                crate::rmap::add(phys, space.root, alias.va);
                if let Some((retain, release)) = hooks {
                    retain(phys.raw());
                    release(old[alias.frame].raw());
                }
            }
            if !alias.present {
                continue;
            }
            // SAFETY: exact same retained leaf-table path, live destination,
            // authoritative original permissions. No page-table allocation is
            // needed; an error here is an internal invariant violation.
            let mapped = unsafe {
                #[cfg(target_arch = "x86_64")]
                {
                    crate::x86_64::paging::map_4kb(
                        space.root,
                        alias.va,
                        phys,
                        user_leaf_flags(alias.perms, alias.perms.contains(RegionPerms::WRITE)),
                    )
                }
                #[cfg(target_arch = "aarch64")]
                {
                    crate::aarch64::paging::map_4kb(
                        space.root,
                        alias.va,
                        phys,
                        user_leaf_flags(alias.perms, alias.perms.contains(RegionPerms::WRITE)),
                    )
                }
            };
            assert!(mapped.is_ok(), "revoked shared leaf could not be restored");
        }
        for space in &spaces {
            space.flush_region_broadcast(VirtAddr::new(0), AddressSpace::USER_HALF_END / 4096);
        }
        result
    })
}
