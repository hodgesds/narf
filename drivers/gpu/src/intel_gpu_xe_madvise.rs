//! `DRM_IOCTL_XE_MADVISE` behind `narf.intel.svm=1`. MIT Linux 7.4-rc4
//! `xe_vm_madvise.c` (`xe_vm_madvise_ioctl`, `madvise_args_are_sane`,
//! `madvise_preferred_mem_loc`, `madvise_atomic`, `madvise_pat_index`,
//! `check_bo_args_are_sane`, `xe_vm_invalidate_madvise_range`), `xe_vm.c`
//! (`xe_vm_alloc_madvise_vma`, `xe_vma_has_default_mem_attrs`) and
//! `include/uapi/drm/xe_drm.h` (`struct drm_xe_madvise`).
//!
//! The advice splits the VMAs at the range's edges and sets one attribute
//! on the parts inside it. A mirror VMA keeps all three (`MemAttr` and its
//! PAT index); a buffer, USERPTR or NULL VMA takes a new PAT index, and its
//! atomic advice is checked against the object's placements. Changed parts
//! are zapped: their SVM ranges drop their pages and mappings take the new
//! PAT, so the next job builds its tables, and refaults its ranges, under the
//! new attributes. NARF's GPU never takes the advice another way: without
//! `CONFIG_DRM_XE_PAGEMAP` a preferred location never migrates, and its PTEs
//! carry no `XE_USM_PPGTT_PTE_AE`, so atomic advice changes only the fault
//! service's `-EACCES` for `DRM_XE_ATOMIC_CPU` on a discrete device.
//!
//! Where NARF departs from Linux:
//! - `DRM_XE_VMA_ATTR_PURGEABLE_STATE` is refused with EOPNOTSUPP: Xe objects
//!   have no purgeable state or shrinker here (`xe_bo_madv_is_dontneed`), so
//!   the DONTNEED/WILLNEED transitions and their `retained_ptr` report have
//!   nothing to act on.
//! - A compressed PAT index is refused, as for a mirror bind: no flat-CCS
//!   state follows the advice. (`xe_device_is_l2_flush_optimized` needs
//!   graphics 35; no NARF platform reaches it.)
//! - Atomic advice on a buffer VMA is checked and not stored: no NARF path
//!   reads `bo->attr.atomic_access` (the BO migration on an atomic fault and
//!   the CPU-mapping zap of `madvise_atomic` have no counterpart).
//! - A running job keeps the tables it was built with, as for every other
//!   invalidation (see `intel_gpu_xe_svm`): Linux's TLB invalidation of the
//!   zapped range has no running table to apply to.
use super::{pat_entry, svm::MirrorVma, State, Vm, MAX_MAPPINGS, MAX_VA};
use crate::{intel_gpu_exec::VmMapping, intel_gpu_gt::GtPlatform, intel_gpu_uapi::u32_at};
use alloc::vec::Vec;
use narf_filesystem::FsError;

/// `DRM_XE_MEM_RANGE_ATTR_PREFERRED_LOC`.
pub(crate) const ATTR_PREFERRED_LOC: u32 = 0;
/// `DRM_XE_MEM_RANGE_ATTR_ATOMIC`.
pub(crate) const ATTR_ATOMIC: u32 = 1;
/// `DRM_XE_MEM_RANGE_ATTR_PAT`.
pub(crate) const ATTR_PAT: u32 = 2;
/// `DRM_XE_VMA_ATTR_PURGEABLE_STATE`.
pub(crate) const ATTR_PURGEABLE_STATE: u32 = 3;
/// `DRM_XE_ATOMIC_UNDEFINED` .. `DRM_XE_ATOMIC_CPU`.
#[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
pub(crate) const ATOMIC_UNDEFINED: u32 = 0;
pub(crate) const ATOMIC_DEVICE: u32 = 1;
pub(crate) const ATOMIC_GLOBAL: u32 = 2;
pub(crate) const ATOMIC_CPU: u32 = 3;
/// `DRM_XE_PREFERRED_LOC_DEFAULT_DEVICE`, `DRM_XE_PREFERRED_LOC_DEFAULT_SYSTEM`
/// (devmem_fd as an `int`).
pub(crate) const PREFERRED_LOC_DEFAULT_DEVICE: i32 = 0;
pub(crate) const PREFERRED_LOC_DEFAULT_SYSTEM: i32 = -1;
/// `DRM_XE_MIGRATE_ONLY_SYSTEM_PAGES`, the largest migration policy.
pub(crate) const MIGRATE_ONLY_SYSTEM_PAGES: u16 = 1;
/// `DRM_XE_VMA_PURGEABLE_STATE_DONTNEED`, the largest purgeable state.
const PURGEABLE_STATE_DONTNEED: u32 = 1;

/// One attribute to set (`args->type` and its union member).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Advice {
    PreferredLoc {
        devmem_fd: u32,
        migration_policy: u16,
    },
    Atomic(u32),
    Pat(u8),
}

/// A parsed `struct drm_xe_madvise`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Madvise {
    pub vm_id: u32,
    pub start: u64,
    pub end: u64,
    pub advice: Advice,
}

fn u16_at(wire: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([wire[offset], wire[offset + 1]])
}

fn u64_at(wire: &[u8], offset: usize) -> u64 {
    crate::intel_gpu_uapi::u64_at(wire, offset)
}

impl Madvise {
    /// `madvise_args_are_sane` over the 64-byte `struct drm_xe_madvise`
    /// (extensions 0, start 8, range 16, vm_id 24, type 28, the union at 32,
    /// reserved 48): start and range 4 KiB aligned and at least 4 KiB, then
    /// each type's fields, then `reserved` zero; EINVAL otherwise. The start
    /// is uncanonicalized (`xe_device_uncanonicalize_addr`). A sane
    /// PURGEABLE_STATE is EOPNOTSUPP (module notes).
    pub(crate) fn parse(wire: &[u8], platform: GtPlatform) -> Result<Self, FsError> {
        if wire.len() != 64 {
            return Err(FsError::InvalidData);
        }
        let start = u64_at(wire, 8);
        let range = u64_at(wire, 16);
        if start % 4096 != 0 || range % 4096 != 0 || range < 4096 {
            return Err(FsError::InvalidData);
        }
        let (value, pad, reserved) = (u32_at(wire, 32), u32_at(wire, 36), u64_at(wire, 40));
        let advice = match u32_at(wire, 28) {
            ATTR_PREFERRED_LOC => {
                let fd = value as i32;
                let migration_policy = u16_at(wire, 36);
                if fd < PREFERRED_LOC_DEFAULT_SYSTEM
                    || (fd <= PREFERRED_LOC_DEFAULT_DEVICE && u16_at(wire, 38) != 0)
                    || migration_policy > MIGRATE_ONLY_SYSTEM_PAGES
                    || reserved != 0
                {
                    return Err(FsError::InvalidData);
                }
                Ok(Advice::PreferredLoc {
                    devmem_fd: value,
                    migration_policy,
                })
            }
            ATTR_ATOMIC => {
                if value > ATOMIC_CPU || pad != 0 || reserved != 0 {
                    return Err(FsError::InvalidData);
                }
                Ok(Advice::Atomic(value))
            }
            ATTR_PAT => {
                // xe_pat_index_get_coh_mode: a valid index with a coherency
                // mode; NARF also refuses a compressed one.
                let entry = u16::try_from(value)
                    .ok()
                    .and_then(|pat| pat_entry(platform, pat))
                    .ok_or(FsError::InvalidData)?;
                if !entry.coherent || entry.compressed || pad != 0 || reserved != 0 {
                    return Err(FsError::InvalidData);
                }
                Ok(Advice::Pat(value as u8))
            }
            ATTR_PURGEABLE_STATE => {
                if value > PURGEABLE_STATE_DONTNEED || pad != 0 {
                    return Err(FsError::InvalidData);
                }
                Err(FsError::Unsupported)
            }
            _ => return Err(FsError::InvalidData),
        };
        if u64_at(wire, 48) != 0 || u64_at(wire, 56) != 0 {
            return Err(FsError::InvalidData);
        }
        let advice = advice?;
        let start = start & (MAX_VA - 1);
        Ok(Self {
            vm_id: u32_at(wire, 24),
            start,
            end: start.checked_add(range).ok_or(FsError::InvalidData)?,
            advice,
        })
    }
}

/// `check_bo_args_are_sane` for one buffer VMA's object: CPU atomics need a
/// system placement, device atomics a VRAM placement or a system one (every
/// NARF platform has `has_device_atomics_on_smem`), and global atomics both.
fn bo_admits_atomic(object: &crate::intel_gpu_gem::GemObject, atomic: u32) -> bool {
    let system = object.can_migrate_to_system() || object.is_imported();
    let vram = object.is_vram() || object.preferred_vram();
    match atomic {
        ATOMIC_CPU => system,
        ATOMIC_DEVICE => vram || system,
        ATOMIC_GLOBAL => system && vram,
        _ => true,
    }
}

/// Split `mappings` at `start` and `end` (`xe_vm_alloc_madvise_vma`) and
/// give the parts inside a PAT index of `pat`. Returns whether any part
/// changed (`skip_invalidation` false).
fn advise_mappings(
    mappings: &mut Vec<VmMapping>,
    start: u64,
    end: u64,
    pat: u8,
) -> Result<bool, FsError> {
    let mut changed = false;
    let mut next = Vec::new();
    next.try_reserve(mappings.len() + 2)
        .map_err(|_| FsError::OutOfMemory)?;
    for mapping in mappings.drain(..) {
        let limit = mapping.va + mapping.length;
        if limit <= start || mapping.va >= end || mapping.pat == pat {
            next.push(mapping);
            continue;
        }
        changed = true;
        if mapping.va < start {
            let mut left = mapping.clone();
            left.length = start - mapping.va;
            next.push(left);
        }
        let mut inside = mapping.clone();
        let from = mapping.va.max(start);
        inside.offset += from - mapping.va;
        inside.va = from;
        inside.length = limit.min(end) - from;
        inside.pat = pat;
        next.push(inside);
        if limit > end {
            let mut right = mapping;
            right.offset += end - right.va;
            right.va = end;
            right.length = limit - end;
            next.push(right);
        }
    }
    *mappings = next;
    Ok(changed)
}

/// Split the mirror VMAs at `start` and `end` and apply `advice` to the parts
/// inside (`madvise_preferred_mem_loc`, `madvise_atomic`,
/// `madvise_pat_index`). Returns the changed parts.
fn advise_mirrors(
    vmas: &mut Vec<MirrorVma>,
    start: u64,
    end: u64,
    advice: Advice,
) -> Result<Vec<(u64, u64)>, FsError> {
    let mut changed = Vec::new();
    let mut next = Vec::new();
    next.try_reserve(vmas.len() + 2)
        .map_err(|_| FsError::OutOfMemory)?;
    for vma in vmas.drain(..) {
        if !vma.overlaps(start, end) {
            next.push(vma);
            continue;
        }
        let mut advised = vma;
        match advice {
            Advice::PreferredLoc {
                devmem_fd,
                migration_policy,
            } => {
                advised.attr.devmem_fd = devmem_fd;
                advised.attr.migration_policy = migration_policy;
            }
            Advice::Atomic(atomic) => advised.attr.atomic = atomic,
            Advice::Pat(pat) => advised.pat = pat,
        }
        // skip_invalidation: the attribute already holds.
        if advised == vma {
            next.push(vma);
            continue;
        }
        let inside = MirrorVma {
            start: vma.start.max(start),
            end: vma.end.min(end),
            ..advised
        };
        if vma.start < start {
            next.push(MirrorVma { end: start, ..vma });
        }
        changed.try_reserve(1).map_err(|_| FsError::OutOfMemory)?;
        changed.push((inside.start, inside.end));
        next.push(inside);
        if vma.end > end {
            next.push(MirrorVma { start: end, ..vma });
        }
    }
    *vmas = next;
    Ok(changed)
}

/// `xe_vm_madvise_ioctl` once the VM is found, with its state held: a closed
/// VM is ENOENT; a preferred device other than the defaults is ENOENT
/// (`xe_drm_pagemap_from_fd` without `CONFIG_DRM_XE_PAGEMAP`); garbage is
/// collected first (`xe_svm_flush`); a range with no VMA does nothing; atomic
/// advice over a buffer VMA its placements refuse is EINVAL. Then the VMAs
/// split, the advice applies and changed parts are zapped.
pub(crate) fn apply(vm: &Vm, state: &mut State, advice: &Madvise) -> Result<(), FsError> {
    vm.check()?;
    if let Advice::PreferredLoc { devmem_fd, .. } = advice.advice {
        if devmem_fd as i32 > PREFERRED_LOC_DEFAULT_DEVICE {
            return Err(FsError::NotFound);
        }
    }
    vm.svm_collect_garbage(state);
    let (start, end) = (advice.start, advice.end);
    let mut mirrors = vm.svm_vmas(state);
    let has_mapping = state
        .mappings
        .iter()
        .any(|m| m.va < end && start < m.va + m.length);
    if !has_mapping && !mirrors.iter().any(|vma| vma.overlaps(start, end)) {
        return Ok(());
    }
    if let Advice::Atomic(atomic) = advice.advice {
        let refused = state
            .mappings
            .iter()
            .filter(|m| m.va < end && start < m.va + m.length)
            .filter_map(|m| m.object.as_ref())
            .filter(|object| !object.is_userptr())
            .any(|object| !bo_admits_atomic(object, atomic));
        if refused {
            return Err(FsError::InvalidData);
        }
    }
    let mut mappings = state.mappings.clone();
    let mappings_changed = match advice.advice {
        // madvise_preferred_mem_loc: "TODO: Extend attributes to bo based
        // vmas"; madvise_atomic: nothing NARF stores for a buffer VMA.
        Advice::PreferredLoc { .. } | Advice::Atomic(_) => false,
        Advice::Pat(pat) => advise_mappings(&mut mappings, start, end, pat)?,
    };
    let changed = advise_mirrors(&mut mirrors, start, end, advice.advice)?;
    if mappings.len() + mirrors.len() > MAX_MAPPINGS {
        return Err(FsError::OutOfMemory);
    }
    if mappings_changed {
        mappings.sort_unstable_by_key(|m| m.va);
        state.publish(mappings);
    }
    if let Some(svm) = &vm.svm {
        if !changed.is_empty() {
            svm.set_vmas(state, mirrors);
        }
        // xe_vm_invalidate_madvise_range: zap the changed mirror parts.
        for (start, end) in changed {
            svm.zap(state, start, end);
        }
    }
    Ok(())
}
