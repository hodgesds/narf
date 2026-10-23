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
/// Retain a bounded hot set of empty keys in each shard. Anonymous
/// teardown commonly returns the same physical frames that the next mapping
/// consumes; keeping their occupied hash slots avoids reinsertion work without
/// letting reusable empty metadata grow with total machine RAM.
const RETAINED_EMPTY_KEYS_PER_SHARD: usize = 64;
const RMAP_INITIAL_CAPACITY: usize = 16;

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
            Owners::Empty if self.reserved == 0 => self.owners = Owners::One(owner),
            Owners::Empty => {
                // A normal publisher raced a promised first owner. Preserve
                // the reservation by promoting with capacity for both; normal
                // `add` is explicitly allowed to allocate.
                let mut owners = Vec::with_capacity(self.reserved.saturating_add(1));
                owners.push(owner);
                self.owners = Owners::Many(owners);
            }
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
        match &mut self.owners {
            // A fresh frame's first owner needs no separate allocation. The
            // table row itself is the fallible reservation; commit it into the
            // inline representation used by ordinary unique mappings.
            Owners::Empty => {
                assert!(
                    self.reserved == 1,
                    "inline rmap reservation has an invalid owner count"
                );
                self.reserved = 0;
                self.owners = Owners::One(owner);
            }
            Owners::Many(owners) => {
                assert!(
                    self.reserved != 0 && owners.len() < owners.capacity(),
                    "reserved rmap owner capacity was consumed before commit"
                );
                self.reserved -= 1;
                owners.push(owner);
            }
            Owners::One(_) => panic!("reserved rmap owner list lost its prepared storage"),
        }
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

    fn replace_slots(&mut self, slots: Vec<RmapSlot>) -> Vec<RmapSlot> {
        debug_assert!(slots.len().is_power_of_two());
        let mut old = core::mem::replace(&mut self.slots, slots);
        self.len = 0;
        self.tombstones = 0;
        for slot in &mut old {
            if let RmapSlot::Occupied { key, owners } = core::mem::replace(slot, RmapSlot::Vacant) {
                self.insert_rehashed(key, owners);
            }
        }
        old
    }

    fn rehash(&mut self, capacity: usize) {
        debug_assert!(capacity.is_power_of_two());
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || RmapSlot::Vacant);
        drop(self.replace_slots(slots));
    }

    fn try_empty_slots(capacity: usize) -> Option<Vec<RmapSlot>> {
        debug_assert!(capacity.is_power_of_two());
        let mut slots = Vec::new();
        if slots.try_reserve_exact(capacity).is_err() {
            return None;
        }
        slots.resize_with(capacity, || RmapSlot::Vacant);
        Some(slots)
    }

    fn insert_rehashed(&mut self, key: u64, owners: OwnerList) {
        let index = self.insertion_slot(key);
        self.slots[index] = RmapSlot::Occupied { key, owners };
        self.len += 1;
    }

    fn prepare_insert(&mut self) {
        if self.slots.is_empty() {
            self.rehash(RMAP_INITIAL_CAPACITY);
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

    /// Fallible [`Self::prepare_insert`]: grow or rebuild before an insert
    /// whose caller must not later enter the allocator.
    fn try_prepare_insert(&mut self) -> Result<(), ()> {
        let capacity = if self.slots.is_empty() {
            RMAP_INITIAL_CAPACITY
        } else {
            let occupied_after_insert = self.len + self.tombstones + 1;
            let load_ceiling = self.slots.len() - self.slots.len() / 4;
            if occupied_after_insert < load_ceiling {
                return Ok(());
            }
            if self.len + 1 < self.slots.len() / 2 {
                self.slots.len()
            } else {
                self.slots.len().checked_mul(2).ok_or(())?
            }
        };
        let slots = Self::try_empty_slots(capacity).ok_or(())?;
        drop(self.replace_slots(slots));
        Ok(())
    }

    /// Insert after a successful [`Self::try_prepare_insert`]; never grows.
    fn insert_prepared(&mut self, key: u64, owners: OwnerList) {
        let index = self.insertion_slot(key);
        if matches!(self.slots[index], RmapSlot::Tombstone) {
            self.tombstones -= 1;
        }
        self.slots[index] = RmapSlot::Occupied { key, owners };
        self.len += 1;
    }

    fn minimum_capacity(len: usize) -> usize {
        let mut capacity = RMAP_INITIAL_CAPACITY;
        while len.saturating_add(1) >= capacity - capacity / 4 {
            capacity = capacity
                .checked_mul(2)
                .expect("rmap table capacity overflow");
        }
        capacity
    }

    fn shrink_target(&self) -> Option<usize> {
        let capacity = self.slots.len();
        if capacity <= RMAP_INITIAL_CAPACITY {
            return None;
        }
        let all_empty = self.len == self.retained_empty;
        if !all_empty && self.len > capacity / 8 {
            return None;
        }
        let target = Self::minimum_capacity(self.len);
        (target < capacity).then_some(target)
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
        self.insert_prepared(key, owners);
    }

    fn remove(&mut self, key: u64) {
        let Some(index) = self.find(key) else {
            return;
        };
        self.slots[index] = RmapSlot::Tombstone;
        self.len -= 1;
        self.tombstones += 1;
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
        // Only an unreserved empty row is a counted reuse shell; a prepared
        // empty row belongs to its in-flight publisher instead.
        let was_shell = list.len() == 0 && list.reserved == 0;
        list.add(owner);
        if was_shell {
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

/// Fallibly prepare `additional` owner slots for any frame, including one with
/// no row yet or only a retained empty shell.
///
/// Relocation into a fresh destination uses this before revoking a source
/// leaf: neither the table nor the owner `Vec` may grow afterwards. A
/// prepared empty row is not a reuse shell (it is excluded from
/// `retained_empty`) and survives ordinary removal until the matching
/// [`add_reserved`] or [`release_reserved_owner_slots`].
pub(crate) fn try_prepare_owner_slots(phys: PhysAddr, additional: usize) -> Result<(), ()> {
    let key = phys.raw();
    if key == 0 || additional == 0 {
        return Ok(());
    }
    let mut g = RMAP[shard(key)].map.lock();
    let map = g.get_or_insert_with(RmapTable::new);
    if let Some(list) = map.get_mut(key) {
        if list.len() != 0 {
            return list.try_reserve(additional);
        }
        let was_shell = list.reserved == 0;
        if additional == 1 && was_shell {
            // The first owner is stored inline. Mark the existing hash row as
            // promised without allocating a one-element Vec merely to reserve
            // an operation that cannot grow `Owners::One`.
            list.reserved = 1;
            debug_assert!(map.retained_empty != 0);
            map.retained_empty -= 1;
            return Ok(());
        }
        let mut owners = match core::mem::replace(&mut list.owners, Owners::Empty) {
            Owners::Many(owners) => owners,
            _ => Vec::new(),
        };
        let promised = list.reserved.checked_add(additional).ok_or(())?;
        if owners.try_reserve_exact(promised).is_err() {
            list.owners = Owners::Many(owners);
            return Err(());
        }
        list.owners = Owners::Many(owners);
        list.reserved = promised;
        if was_shell {
            debug_assert!(map.retained_empty != 0);
            map.retained_empty -= 1;
        }
        return Ok(());
    }
    if additional == 1 {
        // Reserve the hash-table insertion fallibly, but keep the promised
        // first owner inline. `add_reserved` turns this Empty row into One
        // without touching the allocator after the PTE is published.
        map.try_prepare_insert()?;
        map.insert_prepared(
            key,
            OwnerList {
                owners: Owners::Empty,
                reserved: 1,
            },
        );
        return Ok(());
    }
    let mut owners = Vec::new();
    owners.try_reserve_exact(additional).map_err(|_| ())?;
    map.try_prepare_insert()?;
    map.insert_prepared(
        key,
        OwnerList {
            owners: Owners::Many(owners),
            reserved: additional,
        },
    );
    Ok(())
}

/// Allocation-free counterpart to [`try_reserve_owner_slots`] and
/// [`try_prepare_owner_slots`].
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
    if list.len() == 0 && list.reserved == 0 {
        // The prepared row became an ordinary empty key: count it as a
        // bounded reuse shell, or retire it like a last-owner removal.
        let map = g.as_mut().expect("reserved rmap table disappeared");
        if map.retained_empty < RETAINED_EMPTY_KEYS_PER_SHARD {
            map.retained_empty += 1;
        } else {
            map.remove(key);
        }
    }
}

/// Drop the `(root, va)` mapping of `phys`. The last-owner key is either kept
/// as a bounded reuse shell or changed to a probe-preserving tombstone. No-op
/// for the null frame or an unknown mapping.
pub fn remove(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key == 0 {
        return;
    }
    let shard_index = shard(key);
    let shrink_target = remove_owner(key, Owner { root, va });

    // Allocate with the IRQ-safe shard lock released. If allocation fails,
    // leave the valid high-water table alone; a later removal can retry.
    let Some(target) = shrink_target else {
        return;
    };
    let Some(slots) = RmapTable::try_empty_slots(target) else {
        return;
    };

    let mut slots = Some(slots);
    let old = {
        let mut g = RMAP[shard_index].map.lock();
        g.as_mut().and_then(|map| {
            // A racing add may have made the prepared table too small, while a
            // racing removal may already have contracted past this target.
            let current_target = map.shrink_target()?;
            if current_target <= target && map.slots.len() > target {
                Some(map.replace_slots(slots.take().expect("prepared rmap slots missing")))
            } else {
                None
            }
        })
    };
    // Deallocation may re-enter the heap, so release it outside the IRQ-safe
    // shard lock just like the allocation above.
    drop(slots);
    drop(old);
}

/// Retire one owner without the opportunistic table shrink, so it never
/// allocates. Shared-alias relocation calls this while every affected region
/// table is locked; a later ordinary [`remove`] may contract the table.
pub(crate) fn remove_without_shrink(phys: PhysAddr, root: PhysAddr, va: VirtAddr) {
    let key = phys.raw();
    if key != 0 {
        let _ = remove_owner(key, Owner { root, va });
    }
}

/// Remove `owner` under the shard lock, returning the contraction target the
/// removal made available.
fn remove_owner(key: u64, owner: Owner) -> Option<usize> {
    let mut g = RMAP[shard(key)].map.lock();
    g.as_mut().and_then(|map| {
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
            map.shrink_target()
        } else {
            None
        }
    })
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

/// The single recorded owner of `phys`, or `None` when it has zero or several.
///
/// Allocation-free (unlike [`for_each_owner`], which snapshots into a `Vec`):
/// single-owner migration runs inside direct compaction, i.e. on the failure
/// path of an allocation, where entering the heap could recurse into the
/// allocator that just failed.
pub fn sole_owner(phys: PhysAddr) -> Option<Owner> {
    let key = phys.raw();
    if key == 0 {
        return None;
    }
    let guard = RMAP[shard(key)].map.lock();
    match guard.as_ref().and_then(|m| m.get(key)).map(|l| &l.owners) {
        Some(Owners::One(owner)) => Some(*owner),
        Some(Owners::Many(owners)) if owners.len() == 1 => Some(owners[0]),
        _ => None,
    }
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
/// owner), invoking `f` with every shard lock RELEASED so the callback may
/// migrate frames / take page-table locks. Used by the compaction driver to find
/// movable (user-mapped) frames. See [`try_for_each_tracked_frame`].
pub fn for_each_tracked_frame(mut f: impl FnMut(PhysAddr)) {
    try_for_each_tracked_frame(|phys| {
        f(phys);
        core::ops::ControlFlow::Continue(())
    });
}

/// Keys copied out of a shard per lock hold by [`try_for_each_tracked_frame`].
const TRACKED_SCAN_CHUNK: usize = 128;

/// Like [`for_each_tracked_frame`], but `f` may stop the walk early by
/// returning `ControlFlow::Break`.
///
/// ALLOCATION-FREE. Direct compaction calls this from the failure path of a
/// higher-order allocation, with IRQs masked under the node cache drain, so
/// it must not enter the heap: the previous implementation collected each
/// whole shard's keys into a `Vec` (tens of KiB on a loaded desktop), and when
/// that `Vec` could not grow the kernel panicked in `handle_alloc_error`
/// instead of the original allocation failing cleanly. Keys are instead
/// copied in bounded stack chunks, resuming at a slot cursor after each lock
/// drop. A concurrent table resize between chunks can make the walk skip or
/// repeat a key; callers treat the walk as a candidate hint and re-validate
/// every frame (compaction re-checks ownership under the region lock).
pub fn try_for_each_tracked_frame(mut f: impl FnMut(PhysAddr) -> core::ops::ControlFlow<()>) {
    for shard in RMAP.iter() {
        let mut cursor = 0usize;
        loop {
            let mut keys = [0u64; TRACKED_SCAN_CHUNK];
            let mut n = 0usize;
            let exhausted = {
                let guard = shard.map.lock();
                let Some(table) = guard.as_ref() else {
                    break;
                };
                while cursor < table.slots.len() && n < TRACKED_SCAN_CHUNK {
                    if let RmapSlot::Occupied { key, owners } = &table.slots[cursor] {
                        if owners.len() != 0 {
                            keys[n] = *key;
                            n += 1;
                        }
                    }
                    cursor += 1;
                }
                cursor >= table.slots.len()
            };
            for &key in &keys[..n] {
                if f(PhysAddr::new(key)).is_break() {
                    return;
                }
            }
            if exhausted {
                break;
            }
        }
    }
}

/// Test-only: owner slots currently promised to in-flight publishers.
#[cfg(feature = "kernel-test")]
pub(crate) fn __reserved_for_test(phys: PhysAddr) -> usize {
    RMAP[shard(phys.raw())]
        .map
        .lock()
        .as_ref()
        .and_then(|map| map.get(phys.raw()))
        .map_or(0, |list| list.reserved)
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
        owner_count, release_reserved_owner_slots, remove, remove_without_shrink, shard,
        try_prepare_owner_slots, try_reserve_owner_slots, Owner, OwnerList, Owners, RmapTable,
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
        const HIGH_WATER_KEYS: usize = 512;
        let count = HIGH_WATER_KEYS.max(RETAINED_EMPTY_KEYS_PER_SHARD + 2);
        // Keep every key in shard 7 and grow its table to the 1024-slot
        // high-water observed after a populated 128 MiB process exited.
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
                && table.slots.len() == 128
        });
        let mut reported = false;
        for_each_tracked_frame(|_| reported = true);
        __reset_for_test();
        if bounded && !reported {
            TestResult::Pass
        } else {
            TestResult::Fail("rmap empty-key table did not shrink after teardown")
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

    fn retained_empty(phys: PhysAddr) -> usize {
        RMAP[shard(phys.raw())]
            .map
            .lock()
            .as_ref()
            .map_or(0, |table| table.retained_empty)
    }

    /// Relocation destinations may have no row or only a reuse shell. Both
    /// are prepared fallibly, consumed without allocation, and a released
    /// preparation returns to exact shell accounting.
    fn smoke_rmap_prepare_fresh_and_shell_destinations() -> TestResult {
        __reset_for_test();
        let fresh = PhysAddr::new(0x34_0000);
        let shell = PhysAddr::new(0x34_0000 + (64 << 12));
        let inline = PhysAddr::new(0x34_0000 + (128 << 12));
        let root = PhysAddr::new(0x1000);
        let (v0, v1) = (VirtAddr::new(0x4000_0000), VirtAddr::new(0x5000_0000));
        let result = (|| {
            if try_prepare_owner_slots(fresh, 2).is_err() || owner_count(fresh) != 0 {
                return TestResult::Fail("fresh rmap destination was not prepared");
            }
            // A prepared empty row is neither a shell nor removable.
            remove(fresh, root, v0);
            add_reserved(fresh, root, v0);
            add_reserved(fresh, root, v1);
            if owner_count(fresh) != 2 || retained_empty(fresh) != 0 {
                return TestResult::Fail("prepared rmap row lost capacity or miscounted");
            }
            if try_prepare_owner_slots(inline, 1).is_err() {
                return TestResult::Fail("fresh inline rmap destination was not prepared");
            }
            let inline_reserved = RMAP[shard(inline.raw())]
                .map
                .lock()
                .as_ref()
                .and_then(|table| table.get(inline.raw()))
                .is_some_and(|list| matches!(list.owners, Owners::Empty) && list.reserved == 1);
            if !inline_reserved {
                return TestResult::Fail("one-owner rmap reservation allocated alias storage");
            }
            add_reserved(inline, root, v0);
            let inline_committed = RMAP[shard(inline.raw())]
                .map
                .lock()
                .as_ref()
                .and_then(|table| table.get(inline.raw()))
                .is_some_and(|list| {
                    matches!(list.owners, Owners::One(owner) if owner == Owner { root, va: v0 })
                        && list.reserved == 0
                });
            if !inline_committed {
                return TestResult::Fail("one-owner rmap reservation did not commit inline");
            }
            // Same shard: turn `shell` into a counted reuse shell.
            add(shell, root, v0);
            remove(shell, root, v0);
            if retained_empty(shell) != 1 {
                return TestResult::Fail("emptied rmap row was not a counted shell");
            }
            if try_prepare_owner_slots(shell, 1).is_err() || retained_empty(shell) != 0 {
                return TestResult::Fail("preparing a shell did not uncount it");
            }
            // An ordinary add on a prepared row must not uncount again.
            add(shell, root, v1);
            remove_without_shrink(shell, root, v1);
            release_reserved_owner_slots(shell, 1);
            if retained_empty(shell) != 1 || owner_count(shell) != 0 {
                return TestResult::Fail("released preparation did not restore its shell");
            }
            add(shell, root, v0);
            if retained_empty(shell) != 0 || owner_count(shell) != 1 {
                return TestResult::Fail("restored shell was not reusable");
            }
            TestResult::Pass
        })();
        __reset_for_test();
        result
    }
    kernel_test_in!(
        "memory/rmap",
        smoke_rmap_prepare_fresh_and_shell_destinations
    );

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
