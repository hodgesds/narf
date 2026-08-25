//! Reverse mapping: physical frame → the `(address space, virtual address)`
//! mappings that reference it.
//!
//! NARF's frame allocator has no per-frame descriptor (frame state is the buddy
//! free-list + the [`cow`](crate::frame::cow) refcount shards), so there was no
//! way to answer "who maps this frame?". That question is the prerequisite for
//! page MIGRATION (compaction relocates a frame and must rewrite every
//! referencing PTE), a per-cgroup reclaim LRU (frame → owning address space →
//! cgroup), and swap-based anonymous reclaim beyond the CLOCK aging.
//!
//! Storage mirrors the COW refcount shards: a phys-frame-keyed map, sharded
//! 64-way by frame number so unrelated frames on other CPUs don't contend.
//! Most anonymous frames have exactly ONE owner (COW refcount 1) — only
//! fork-shared frames have several — so the per-frame owner list is almost
//! always length 1. `cow::count(phys)` already reports HOW MANY owners a frame
//! has; this records WHO. (A future anon_vma-style representation could drop the
//! per-frame `Vec`; noted as a follow-up.)
//!
//! This is standalone storage + API. The map / unmap / fork / COW-split paths
//! are wired to it in separate changes, and the consumers (migration,
//! per-cgroup LRU, swap) come after.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{PhysAddr, VirtAddr};

/// One mapping of a physical frame: the address space (page-table root) and the
/// virtual address at which the frame is mapped there.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Owner {
    /// Architecture page-table root (`pml4` phys) naming the address space.
    pub root: PhysAddr,
    /// Page-aligned virtual address the frame is mapped at in `root`.
    pub va: VirtAddr,
}

// Same 64-way sharding transform as the COW refcount table: a frame always maps
// to one shard, but unrelated frames on other CPUs no longer contend on a
// single lock.
const RMAP_SHARDS: usize = 64;

#[repr(align(64))]
struct RmapShard {
    map: IrqSafeSpinLock<Option<BTreeMap<u64, Vec<Owner>>>>,
}

impl RmapShard {
    const fn new() -> Self {
        Self {
            map: IrqSafeSpinLock::new(None),
        }
    }
}

static RMAP: [RmapShard; RMAP_SHARDS] = [const { RmapShard::new() }; RMAP_SHARDS];

#[inline]
fn shard(frame_key: u64) -> usize {
    // Frames are page-aligned; the low 12 bits are always zero.
    ((frame_key >> 12) as usize) & (RMAP_SHARDS - 1)
}

/// Record that `(root, va)` maps `phys`. Idempotent — a duplicate mapping for
/// the same frame is not added twice. No-op for the null frame. Allocates
/// (map/`Vec` growth), so it must run on a normal map path, never the
/// allocation-failure path.
pub fn add(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let owner = Owner { root, va };
    let mut g = RMAP[shard(key)].map.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    let owners = map.entry(key).or_default();
    if !owners.contains(&owner) {
        owners.push(owner);
    }
}

/// Drop the `(root, va)` mapping of `phys`. Frees the frame's entry once its
/// last owner is removed. No-op for the null frame or an unknown mapping.
pub fn remove(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let owner = Owner { root, va };
    let mut g = RMAP[shard(key)].map.lock();
    if let Some(map) = g.as_mut() {
        if let Some(owners) = map.get_mut(&key) {
            owners.retain(|o| *o != owner);
            if owners.is_empty() {
                map.remove(&key);
            }
        }
    }
}

/// Allocation-free exact-owner membership check.
pub fn contains_owner(phys: PhysAddr, root: PhysAddr, va: VirtAddr) -> bool {
    let key = phys.raw();
    if key == 0 {
        return false;
    }
    let owner = Owner { root, va };
    RMAP[shard(key)]
        .map
        .lock()
        .as_ref()
        .and_then(|map| map.get(&key))
        .is_some_and(|owners| owners.contains(&owner))
}

/// Change one recorded virtual coordinate without allocating.
///
/// Address-space relocation uses this while holding its topology lock, after
/// the destination leaf is installed and the source leaf is retired. Keeping
/// the existing owner slot avoids entering the allocator (and therefore
/// reclaim) while VMA/page ownership is mid-transaction.
pub fn move_owner(phys: PhysAddr, root: PhysAddr, old_va: VirtAddr, new_va: VirtAddr) -> bool {
    let key = phys.raw();
    if key == 0 {
        return false;
    }
    let old = Owner { root, va: old_va };
    let new = Owner { root, va: new_va };
    let mut g = RMAP[shard(key)].map.lock();
    let Some(owners) = g.as_mut().and_then(|map| map.get_mut(&key)) else {
        return false;
    };
    let Some(old_index) = owners.iter().position(|owner| *owner == old) else {
        return false;
    };
    if owners.contains(&new) {
        owners.swap_remove(old_index);
    } else {
        owners[old_index] = new;
    }
    true
}

/// Number of distinct mappings recorded for `phys` (`0` if untracked). Should
/// track `cow::count(phys)` once every map path is wired.
pub fn owner_count(phys: PhysAddr) -> usize {
    let key = phys.raw();
    if key == 0 {
        return 0;
    }
    RMAP[shard(key)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&key))
        .map_or(0, Vec::len)
}

/// Visit every recorded owner of `phys`. Snapshots the owner list under the
/// shard lock, then invokes `f` with the lock RELEASED, so the callback may take
/// page-table locks (e.g. to rewrite a PTE during migration) without a
/// lock-order hazard against the shard lock.
pub fn for_each_owner(phys: PhysAddr, mut f: impl FnMut(Owner)) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let owners: Vec<Owner> = RMAP[shard(key)]
        .map
        .lock()
        .as_ref()
        .and_then(|m| m.get(&key))
        .cloned()
        .unwrap_or_default();
    for o in owners {
        f(o);
    }
}

/// Visit every physical frame currently tracked (i.e. mapped by at least one
/// owner). Snapshots each shard's keys under its lock, then invokes `f` with the
/// lock RELEASED, so the callback may migrate frames / take page-table locks.
/// Used by the compaction driver to find movable (user-mapped) frames.
pub fn for_each_tracked_frame(mut f: impl FnMut(PhysAddr)) {
    for shard in RMAP.iter() {
        let frames: Vec<u64> = shard
            .map
            .lock()
            .as_ref()
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for key in frames {
            f(PhysAddr::new(key));
        }
    }
}

/// Test-only: clear all rmap shards so a test's entries never leak into another
/// test or the live kernel.
#[doc(hidden)]
pub fn __reset_for_test() {
    for s in RMAP.iter() {
        *s.map.lock() = None;
    }
}

// ── Tests ────────────────────────────────────────────────────────
// Always compiled (not `#[cfg(test)]`) so they register into the in-kernel
// `narf.tests` section and actually run under `cargo xtask test`.
mod tests {
    use super::{__reset_for_test, add, for_each_owner, move_owner, owner_count, remove, Owner};
    use crate::{PhysAddr, VirtAddr};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_rmap_add_count_remove() -> TestResult {
        __reset_for_test();
        let phys = PhysAddr::new(0x20_0000);
        let (r0, r1) = (PhysAddr::new(0x1000), PhysAddr::new(0x2000));
        let (v0, v1) = (VirtAddr::new(0x4000_0000), VirtAddr::new(0x5000_0000));

        // Two distinct owners of one frame (as a COW-shared page would have).
        add(phys, r0, v0);
        add(phys, r1, v1);
        // Idempotent: re-adding the same mapping does not double-count.
        add(phys, r0, v0);
        let result = (|| {
            if owner_count(phys) != 2 {
                return TestResult::Fail("expected exactly 2 distinct owners");
            }
            // for_each visits both, with the lock released.
            let mut seen = 0usize;
            let mut saw_r0 = false;
            for_each_owner(phys, |o: Owner| {
                seen += 1;
                if o.root == r0 && o.va == v0 {
                    saw_r0 = true;
                }
            });
            if seen != 2 || !saw_r0 {
                return TestResult::Fail("for_each_owner did not visit both owners");
            }
            // Remove one → 1 left; remove the last → entry gone.
            remove(phys, r0, v0);
            if owner_count(phys) != 1 {
                return TestResult::Fail("remove of one owner should leave 1");
            }
            remove(phys, r1, v1);
            if owner_count(phys) != 0 {
                return TestResult::Fail("removing the last owner should free the entry");
            }
            // Null frame + unknown mapping are no-ops.
            add(PhysAddr::new(0), r0, v0);
            remove(phys, r0, v0);
            if owner_count(PhysAddr::new(0)) != 0 {
                return TestResult::Fail("null frame must never be tracked");
            }
            TestResult::Pass
        })();
        __reset_for_test();
        result
    }
    kernel_test_in!("memory/rmap", smoke_rmap_add_count_remove);

    fn smoke_rmap_move_owner_updates_coordinate() -> TestResult {
        __reset_for_test();
        let phys = PhysAddr::new(0x28_0000);
        let root = PhysAddr::new(0x1000);
        let old = VirtAddr::new(0x4000_0000);
        let new = VirtAddr::new(0x5000_0000);
        add(phys, root, old);
        let moved = move_owner(phys, root, old, new);
        let mut saw_old = false;
        let mut saw_new = false;
        for_each_owner(phys, |owner| {
            saw_old |= owner.root == root && owner.va == old;
            saw_new |= owner.root == root && owner.va == new;
        });
        let result = moved && !saw_old && saw_new && owner_count(phys) == 1;
        __reset_for_test();
        if result {
            TestResult::Pass
        } else {
            TestResult::Fail("move_owner did not replace the old coordinate")
        }
    }
    kernel_test_in!("memory/rmap", smoke_rmap_move_owner_updates_coordinate);

    fn smoke_rmap_frames_independent() -> TestResult {
        __reset_for_test();
        let (a, b) = (PhysAddr::new(0x30_0000), PhysAddr::new(0x30_1000));
        let root = PhysAddr::new(0x1000);
        add(a, root, VirtAddr::new(0x1_0000));
        add(b, root, VirtAddr::new(0x2_0000));
        let ok = owner_count(a) == 1 && owner_count(b) == 1;
        remove(a, root, VirtAddr::new(0x1_0000));
        let independent = ok && owner_count(a) == 0 && owner_count(b) == 1;
        __reset_for_test();
        if independent {
            TestResult::Pass
        } else {
            TestResult::Fail("distinct frames must track owners independently")
        }
    }
    kernel_test_in!("memory/rmap", smoke_rmap_frames_independent);
}
