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
//! fork-shared frames have several — so that owner is stored inline. A `Vec`
//! is allocated only when a second alias appears or failure-atomic alias
//! publication reserves capacity. `cow::count(phys)` already reports HOW MANY
//! owners a frame has; this records WHO.
//!
//! This is standalone storage + API. The map / unmap / fork / COW-split paths
//! are wired to it in separate changes, and the consumers (migration,
//! per-cgroup LRU, swap) come after.

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
/// Retain a bounded high-water set of empty keys in each shard. Anonymous
/// teardown commonly returns the same physical frames that the next mapping
/// consumes; keeping their occupied hash slots avoids reinsertion work without
/// letting reusable empty metadata grow with total machine RAM.
const RETAINED_EMPTY_KEYS_PER_SHARD: usize = 1024;

#[repr(align(64))]
struct RmapShard {
    map: IrqSafeSpinLock<Option<RmapTable>>,
}

enum Owners {
    Empty,
    One(Owner),
    Many(Vec<Owner>),
}

/// Per-frame owners plus capacity promised to an in-flight failure-atomic
/// publisher. The overwhelmingly common unique owner stays inline; ordinary
/// map paths must leave `reserved` vector slots unused after promotion.
struct OwnerList {
    owners: Owners,
    reserved: usize,
}

impl OwnerList {
    const fn new(owner: Owner) -> Self {
        Self {
            owners: Owners::One(owner),
            reserved: 0,
        }
    }

    fn len(&self) -> usize {
        match &self.owners {
            Owners::Empty => 0,
            Owners::One(_) => 1,
            Owners::Many(owners) => owners.len(),
        }
    }

    fn contains(&self, owner: Owner) -> bool {
        match &self.owners {
            Owners::Empty => false,
            Owners::One(existing) => *existing == owner,
            Owners::Many(owners) => owners.contains(&owner),
        }
    }

    fn add(&mut self, owner: Owner) {
        if self.contains(owner) {
            return;
        }
        match &mut self.owners {
            Owners::Empty => self.owners = Owners::One(owner),
            Owners::One(existing) => {
                let first = *existing;
                let mut owners = Vec::with_capacity(self.reserved.saturating_add(2));
                // Capacity promised to a failure-atomic alias is not available
                // to this ordinary add.
                owners.push(first);
                owners.push(owner);
                self.owners = Owners::Many(owners);
            }
            Owners::Many(owners) => {
                owners.reserve(self.reserved.saturating_add(1));
                owners.push(owner);
            }
        }
    }

    fn try_reserve(&mut self, additional: usize) -> Result<(), ()> {
        let promised = self.reserved.checked_add(additional).ok_or(())?;
        match &mut self.owners {
            Owners::Empty => return Err(()),
            Owners::One(owner) => {
                let first = *owner;
                let mut owners = Vec::new();
                owners
                    .try_reserve_exact(promised.saturating_add(1))
                    .map_err(|_| ())?;
                owners.push(first);
                self.owners = Owners::Many(owners);
            }
            Owners::Many(owners) => {
                owners.try_reserve_exact(promised).map_err(|_| ())?;
            }
        }
        self.reserved = promised;
        Ok(())
    }

    fn add_reserved(&mut self, owner: Owner) {
        assert!(
            !self.contains(owner),
            "reserved rmap owner already existed before commit"
        );
        let Owners::Many(owners) = &mut self.owners else {
            panic!("reserved rmap owner list lost its prepared storage");
        };
        assert!(
            self.reserved != 0 && owners.len() < owners.capacity(),
            "reserved rmap owner capacity was consumed before commit"
        );
        self.reserved -= 1;
        owners.push(owner);
    }

    fn remove(&mut self, owner: Owner) {
        match &mut self.owners {
            Owners::Empty => {}
            Owners::One(existing) => {
                if *existing == owner {
                    self.owners = Owners::Empty;
                }
            }
            Owners::Many(owners) => owners.retain(|existing| *existing != owner),
        }
    }

    fn move_owner(&mut self, old: Owner, new: Owner) -> bool {
        match &mut self.owners {
            Owners::Empty => false,
            Owners::One(existing) => {
                if *existing != old {
                    return false;
                }
                *existing = new;
                true
            }
            Owners::Many(owners) => {
                let Some(old_index) = owners.iter().position(|owner| *owner == old) else {
                    return false;
                };
                if old != new && owners.contains(&new) {
                    owners.swap_remove(old_index);
                } else {
                    owners[old_index] = new;
                }
                true
            }
        }
    }

    fn snapshot(&self) -> Vec<Owner> {
        match &self.owners {
            Owners::Empty => Vec::new(),
            Owners::One(owner) => Vec::from([*owner]),
            Owners::Many(owners) => owners.clone(),
        }
    }
}

enum RmapSlot {
    Vacant,
    Tombstone,
    Occupied { key: u64, owners: OwnerList },
}

/// Open-addressed physical-frame index. Reverse-map operations are on fault,
/// unmap, COW, and migration hot paths; a B-tree made the common unique-owner
/// lookup logarithmic and allocated one node per newly-seen frame. This table
/// grows in amortized chunks and keeps lookup O(1) on average.
struct RmapTable {
    slots: Vec<RmapSlot>,
    len: usize,
    tombstones: usize,
    retained_empty: usize,
}

impl RmapTable {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
            tombstones: 0,
            retained_empty: 0,
        }
    }

    #[inline]
    fn hash(key: u64) -> usize {
        // SplitMix64 finalizer over the page number. The shard already used
        // its low six bits, so mixing is important for sequential frames.
        let mut value = key >> 12;
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        (value ^ (value >> 31)) as usize
    }

    fn find(&self, key: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut index = Self::hash(key) & mask;
        for _ in 0..self.slots.len() {
            match &self.slots[index] {
                RmapSlot::Vacant => return None,
                RmapSlot::Occupied { key: existing, .. } if *existing == key => {
                    return Some(index);
                }
                RmapSlot::Tombstone | RmapSlot::Occupied { .. } => {}
            }
            index = (index + 1) & mask;
        }
        None
    }

    fn insertion_slot(&self, key: u64) -> usize {
        let mask = self.slots.len() - 1;
        let mut index = Self::hash(key) & mask;
        let mut first_tombstone = None;
        for _ in 0..self.slots.len() {
            match &self.slots[index] {
                RmapSlot::Vacant => return first_tombstone.unwrap_or(index),
                RmapSlot::Tombstone => {
                    first_tombstone.get_or_insert(index);
                }
                RmapSlot::Occupied { key: existing, .. } => {
                    assert_ne!(*existing, key, "duplicate rmap table insertion");
                }
            }
            index = (index + 1) & mask;
        }
        first_tombstone.expect("rmap table has no insertion slot")
    }

    fn rehash(&mut self, capacity: usize) {
        debug_assert!(capacity.is_power_of_two());
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || RmapSlot::Vacant);
        let old = core::mem::replace(&mut self.slots, slots);
        self.len = 0;
        self.tombstones = 0;
        for slot in old {
            if let RmapSlot::Occupied { key, owners } = slot {
                self.insert_rehashed(key, owners);
            }
        }
    }

    fn insert_rehashed(&mut self, key: u64, owners: OwnerList) {
        let index = self.insertion_slot(key);
        self.slots[index] = RmapSlot::Occupied { key, owners };
        self.len += 1;
    }

    fn prepare_insert(&mut self) {
        const INITIAL_CAPACITY: usize = 16;
        if self.slots.is_empty() {
            self.rehash(INITIAL_CAPACITY);
            return;
        }
        // Keep at least 25% truly-vacant slots so a missing-key probe stays
        // bounded. Rebuild in place when tombstones, rather than live keys,
        // are what crossed the threshold.
        let occupied_after_insert = self.len + self.tombstones + 1;
        let load_ceiling = self.slots.len() - self.slots.len() / 4;
        if occupied_after_insert >= load_ceiling {
            let capacity = if self.len + 1 < self.slots.len() / 2 {
                self.slots.len()
            } else {
                self.slots
                    .len()
                    .checked_mul(2)
                    .expect("rmap table capacity overflow")
            };
            self.rehash(capacity);
        }
    }

    fn get(&self, key: u64) -> Option<&OwnerList> {
        let index = self.find(key)?;
        match &self.slots[index] {
            RmapSlot::Occupied { owners, .. } => Some(owners),
            _ => unreachable!(),
        }
    }

    fn get_mut(&mut self, key: u64) -> Option<&mut OwnerList> {
        let index = self.find(key)?;
        match &mut self.slots[index] {
            RmapSlot::Occupied { owners, .. } => Some(owners),
            _ => unreachable!(),
        }
    }

    fn insert(&mut self, key: u64, owners: OwnerList) {
        self.prepare_insert();
        let index = self.insertion_slot(key);
        if matches!(self.slots[index], RmapSlot::Tombstone) {
            self.tombstones -= 1;
        }
        self.slots[index] = RmapSlot::Occupied { key, owners };
        self.len += 1;
    }

    fn remove(&mut self, key: u64) {
        let Some(index) = self.find(key) else {
            return;
        };
        self.slots[index] = RmapSlot::Tombstone;
        self.len -= 1;
        self.tombstones += 1;
    }

    fn iter(&self) -> impl Iterator<Item = (u64, &OwnerList)> {
        self.slots.iter().filter_map(|slot| match slot {
            RmapSlot::Occupied { key, owners } => Some((*key, owners)),
            RmapSlot::Vacant | RmapSlot::Tombstone => None,
        })
    }
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
/// the same frame is not added twice. No-op for the null frame. The first owner
/// stays inline, but map insertion or later alias growth may allocate, so this
/// must run on a normal map path, never the allocation-failure path.
pub fn add(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let owner = Owner { root, va };
    let mut g = RMAP[shard(key)].map.lock();
    let map = g.get_or_insert_with(RmapTable::new);
    if let Some(list) = map.get_mut(key) {
        let was_empty = list.len() == 0;
        list.add(owner);
        if was_empty {
            debug_assert!(map.retained_empty != 0);
            map.retained_empty -= 1;
        }
    } else {
        map.insert(key, OwnerList::new(owner));
    }
}

/// Fallibly reserve `additional` owner slots for an already-tracked frame.
///
/// Shared-alias publication uses this before touching a destination PTE. Its
/// source PTE proves the frame already has a map entry, so only the per-frame
/// owner Vec can need capacity. The reservation is explicit in the frame's
/// owner list: concurrent ordinary additions allocate beyond promised slots,
/// and removal cannot retire the entry until commit or rollback consumes them.
pub(crate) fn try_reserve_owner_slots(phys: PhysAddr, additional: usize) -> Result<(), ()> {
    if phys.raw() == 0 || additional == 0 {
        return Ok(());
    }
    let key = phys.raw();
    let mut g = RMAP[shard(key)].map.lock();
    let list = g.as_mut().and_then(|map| map.get_mut(key)).ok_or(())?;
    list.try_reserve(additional)
}

/// Allocation-free counterpart to [`try_reserve_owner_slots`].
///
/// Panics if the caller did not reserve capacity or if the frame's existing
/// rmap authority disappeared between reservation and commit.
pub(crate) fn add_reserved(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let owner = Owner { root, va };
    let mut g = RMAP[shard(key)].map.lock();
    let list = g
        .as_mut()
        .and_then(|map| map.get_mut(key))
        .expect("reserved rmap frame disappeared before commit");
    list.add_reserved(owner);
}

/// Release owner slots reserved by [`try_reserve_owner_slots`] when the
/// page-table publication rolls back before [`add_reserved`].
pub(crate) fn release_reserved_owner_slots(phys: PhysAddr, count: usize) {
    if phys.raw() == 0 || count == 0 {
        return;
    }
    let key = phys.raw();
    let mut g = RMAP[shard(key)].map.lock();
    let list = g
        .as_mut()
        .and_then(|map| map.get_mut(key))
        .expect("reserved rmap frame disappeared before rollback");
    assert!(
        list.reserved >= count,
        "rmap rollback released more slots than it reserved"
    );
    list.reserved -= count;
}

/// Drop the `(root, va)` mapping of `phys`. The last-owner key is either kept
/// as a bounded reuse shell or changed to a probe-preserving tombstone. No-op
/// for the null frame or an unknown mapping.
pub fn remove(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let owner = Owner { root, va };
    let mut g = RMAP[shard(key)].map.lock();
    if let Some(map) = g.as_mut() {
        let became_empty = if let Some(list) = map.get_mut(key) {
            let was_nonempty = list.len() != 0;
            list.remove(owner);
            was_nonempty && list.len() == 0 && list.reserved == 0
        } else {
            false
        };
        if became_empty {
            if map.retained_empty < RETAINED_EMPTY_KEYS_PER_SHARD {
                map.retained_empty += 1;
            } else {
                map.remove(key);
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
        .and_then(|map| map.get(key))
        .is_some_and(|list| list.contains(owner))
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
    let Some(list) = g.as_mut().and_then(|map| map.get_mut(key)) else {
        return false;
    };
    list.move_owner(old, new)
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
        .and_then(|m| m.get(key))
        .map_or(0, OwnerList::len)
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
        .and_then(|m| m.get(key))
        .map(OwnerList::snapshot)
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
            .map(|m| {
                m.iter()
                    .filter_map(|(key, owners)| (owners.len() != 0).then_some(key))
                    .collect()
            })
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
    use super::{
        __reset_for_test, add, add_reserved, for_each_owner, for_each_tracked_frame, move_owner,
        owner_count, remove, shard, try_reserve_owner_slots, Owner, OwnerList, Owners, RmapTable,
        RETAINED_EMPTY_KEYS_PER_SHARD, RMAP,
    };
    use crate::{PhysAddr, VirtAddr};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_rmap_add_count_remove() -> TestResult {
        __reset_for_test();
        let phys = PhysAddr::new(0x20_0000);
        let (r0, r1) = (PhysAddr::new(0x1000), PhysAddr::new(0x2000));
        let (v0, v1) = (VirtAddr::new(0x4000_0000), VirtAddr::new(0x5000_0000));

        // Two distinct owners of one frame (as a COW-shared page would have).
        add(phys, r0, v0);
        let first_is_inline = RMAP[shard(phys.raw())]
            .map
            .lock()
            .as_ref()
            .and_then(|map| map.get(phys.raw()))
            .is_some_and(|list| matches!(list.owners, Owners::One(owner) if owner == Owner { root: r0, va: v0 }));
        if !first_is_inline {
            __reset_for_test();
            return TestResult::Fail("first rmap owner was not stored inline");
        }
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
            let mut still_tracked = false;
            for_each_tracked_frame(|candidate| still_tracked |= candidate == phys);
            if still_tracked {
                return TestResult::Fail("retained empty rmap key was reported as an owner");
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

    fn smoke_rmap_hash_index_grows_through_tombstones() -> TestResult {
        let root = PhysAddr::new(0x1000);
        let mut table = RmapTable::new();
        for page in 1..=192u64 {
            table.insert(
                page << 12,
                OwnerList::new(Owner {
                    root,
                    va: VirtAddr::new(page << 20),
                }),
            );
        }
        for page in (2..=192u64).step_by(2) {
            table.remove(page << 12);
        }
        for page in 193..=320u64 {
            table.insert(
                page << 12,
                OwnerList::new(Owner {
                    root,
                    va: VirtAddr::new(page << 20),
                }),
            );
        }
        let old_survived =
            (1..=192u64).all(|page| table.get(page << 12).is_some() == (page & 1 != 0));
        let new_visible = (193..=320u64).all(|page| table.get(page << 12).is_some());
        if old_survived && new_visible && table.len == 224 {
            TestResult::Pass
        } else {
            TestResult::Fail("rmap hash growth lost a live key across tombstones")
        }
    }
    kernel_test_in!(
        "memory/rmap",
        smoke_rmap_hash_index_grows_through_tombstones
    );

    fn smoke_rmap_retained_empty_keys_are_bounded() -> TestResult {
        __reset_for_test();
        let root = PhysAddr::new(0x1000);
        let va = VirtAddr::new(0x4000_0000);
        let count = RETAINED_EMPTY_KEYS_PER_SHARD + 2;
        // Keep every key in shard 7 while forcing two last-owner removals past
        // the retention ceiling. Those become tombstones, not probe-chain
        // terminators.
        for index in 0..count {
            let pfn = 7 + index as u64 * super::RMAP_SHARDS as u64;
            add(PhysAddr::new(pfn << 12), root, va);
        }
        for index in 0..count {
            let pfn = 7 + index as u64 * super::RMAP_SHARDS as u64;
            remove(PhysAddr::new(pfn << 12), root, va);
        }
        let shard = shard(7 << 12);
        let bounded = RMAP[shard].map.lock().as_ref().is_some_and(|table| {
            table.retained_empty == RETAINED_EMPTY_KEYS_PER_SHARD
                && table.len == RETAINED_EMPTY_KEYS_PER_SHARD
                && table.tombstones >= 2
        });
        let mut reported = false;
        for_each_tracked_frame(|_| reported = true);
        __reset_for_test();
        if bounded && !reported {
            TestResult::Pass
        } else {
            TestResult::Fail("rmap empty-key retention exceeded its bound")
        }
    }
    kernel_test_in!("memory/rmap", smoke_rmap_retained_empty_keys_are_bounded);

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

    fn smoke_rmap_reservation_survives_racing_add() -> TestResult {
        __reset_for_test();
        let phys = PhysAddr::new(0x2c_0000);
        let root = PhysAddr::new(0x1000);
        let source = VirtAddr::new(0x4000_0000);
        let racing = VirtAddr::new(0x5000_0000);
        let reserved = VirtAddr::new(0x6000_0000);
        add(phys, root, source);
        if try_reserve_owner_slots(phys, 1).is_err() {
            __reset_for_test();
            return TestResult::Fail("failed to reserve rmap owner slot");
        }
        // A concurrent demand completion must allocate beyond the promised
        // slot rather than consuming it.
        add(phys, root, racing);
        add_reserved(phys, root, reserved);
        let ok = owner_count(phys) == 3;
        __reset_for_test();
        if ok {
            TestResult::Pass
        } else {
            TestResult::Fail("ordinary rmap add consumed reserved alias capacity")
        }
    }
    kernel_test_in!("memory/rmap", smoke_rmap_reservation_survives_racing_add);

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
