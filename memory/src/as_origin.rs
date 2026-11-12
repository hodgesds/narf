//! Where each live user address space was created, and who still holds it.
//!
//! A soak can end with thousands of user page-table roots that no scheduled
//! task owns (`/proc/narf/pgtables`: `user_roots_live` far above
//! `sched_address_spaces`). Each such root keeps its page tables and mapped
//! pages. This table records, per live root, the source location of the
//! call that built its address space (`AddressSpace::new_for_user`'s or
//! `clone_for_fork`'s caller), so the orphans can be grouped by what made
//! them — fork, exec, spawn — and the owner that never let go found.
//!
//! Once a space is shared through an `Arc` ([`note_arc`], [`note_owner`]
//! when the scheduler first attaches a task) the table keeps a `Weak`
//! reference and indexes the `Arc`'s address: a weak registry by identity,
//! so a dump can read an orphan's strong count without keeping it alive. A
//! task exit or exec abandons the kernel stack it ran on without running the
//! destructors of the locals still live there; the scheduler scans that
//! stack for registered `Arc`s and records the frame that held one
//! ([`note_held`]) and, at exit, the strong count it saw ([`note_exit`]).
//!
//! Lock-free open addressing over a fixed `.bss` table: allocation-free, so
//! it is safe on every path that creates or tears down a root. A full table
//! drops the record (counted). The weak pointers alone are guarded by one
//! spinlock, so a reader never upgrades a reference [`forget`] is releasing.

use alloc::sync::{Arc, Weak};
use core::panic::Location;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::AddressSpace;

const SLOTS: usize = 1 << 16;
/// Slot key states besides a root's physical address.
const EMPTY: u64 = 0;
const TOMBSTONE: u64 = 1;

static ROOTS: [AtomicU64; SLOTS] = [const { AtomicU64::new(EMPTY) }; SLOTS];
static ORIGINS: [AtomicPtr<Location<'static>>; SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; SLOTS];
/// First task attached to the space (0: none yet).
static OWNER_TID: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// `Weak::into_raw` of the space (null: none yet). Guarded by [`WEAK_LOCK`].
static WEAK: [AtomicPtr<AddressSpace>; SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; SLOTS];
/// Strong count seen when the last attached task exited, plus one (0: no
/// exit seen).
static EXIT_STRONG: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// `.text` offset of the return address above the first strong reference to
/// the space found on an abandoned kernel stack (0: none found), and the
/// task whose stack it was.
static HELD_SITE: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static HELD_TID: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// `ArcInner` address -> root-table slot, so a scan of a stack can ask of
/// any word whether it is a registered space's `Arc`. Guarded by
/// [`WEAK_LOCK`], with backward-shift deletion: no tombstones, so a lookup
/// of an absent word stays short however long the kernel runs.
struct PtrIndex {
    keys: [u64; SLOTS],
    slots: [u32; SLOTS],
}
static WEAK_LOCK: IrqSafeSpinLock<PtrIndex> = IrqSafeSpinLock::new(PtrIndex {
    keys: [EMPTY; SLOTS],
    slots: [0; SLOTS],
});
static DROPPED: AtomicUsize = AtomicUsize::new(0);
/// Task exits seen by [`note_exit`], and those whose abandoned stack still
/// held a strong reference to the space.
static EXITS: AtomicU64 = AtomicU64::new(0);
static EXITS_HELD: AtomicU64 = AtomicU64::new(0);

#[inline]
fn home(root: u64) -> usize {
    ((root >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 48) as usize & (SLOTS - 1)
}

fn find(root: u64) -> Option<usize> {
    let mut i = home(root);
    for _ in 0..SLOTS {
        let key = ROOTS[i].load(Ordering::Acquire);
        if key == EMPTY {
            return None;
        }
        if key == root {
            return Some(i);
        }
        i = (i + 1) & (SLOTS - 1);
    }
    None
}

/// Record that the user root `root` was built at `origin`.
pub fn record(root: u64, origin: &'static Location<'static>) {
    let mut i = home(root);
    for _ in 0..SLOTS {
        let key = ROOTS[i].load(Ordering::Acquire);
        if (key == EMPTY || key == TOMBSTONE)
            && ROOTS[i]
                .compare_exchange(key, root, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            ORIGINS[i].store(origin as *const _ as *mut _, Ordering::Release);
            OWNER_TID[i].store(0, Ordering::Relaxed);
            EXIT_STRONG[i].store(0, Ordering::Relaxed);
            HELD_SITE[i].store(0, Ordering::Relaxed);
            HELD_TID[i].store(0, Ordering::Relaxed);
            return;
        }
        i = (i + 1) & (SLOTS - 1);
    }
    DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// The address an `Arc<AddressSpace>` stores: its `ArcInner`, two counters
/// before the value.
#[inline]
pub fn arc_inner_addr(space: *const AddressSpace) -> u64 {
    let offset = (2 * core::mem::size_of::<usize>())
        .next_multiple_of(core::mem::align_of::<AddressSpace>()) as u64;
    (space as u64).wrapping_sub(offset)
}

#[inline]
fn ptr_home(ptr: u64) -> usize {
    ((ptr >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 48) as usize & (SLOTS - 1)
}

impl PtrIndex {
    fn get(&self, ptr: u64) -> Option<usize> {
        if ptr == EMPTY {
            return None;
        }
        let mut i = ptr_home(ptr);
        loop {
            match self.keys[i] {
                EMPTY => return None,
                key if key == ptr => return Some(self.slots[i] as usize),
                _ => i = (i + 1) & (SLOTS - 1),
            }
        }
    }

    fn insert(&mut self, ptr: u64, slot: usize) {
        let mut i = ptr_home(ptr);
        for _ in 0..SLOTS {
            if self.keys[i] == EMPTY || self.keys[i] == ptr {
                self.keys[i] = ptr;
                self.slots[i] = slot as u32;
                return;
            }
            i = (i + 1) & (SLOTS - 1);
        }
    }

    fn remove(&mut self, ptr: u64) {
        let mut i = ptr_home(ptr);
        loop {
            match self.keys[i] {
                EMPTY => return,
                key if key == ptr => break,
                _ => i = (i + 1) & (SLOTS - 1),
            }
        }
        let mut hole = i;
        let mut j = (i + 1) & (SLOTS - 1);
        while self.keys[j] != EMPTY {
            let home = ptr_home(self.keys[j]);
            // Move `j` into the hole unless its home lies cyclically in
            // (hole, j].
            let stays = if hole <= j {
                home > hole && home <= j
            } else {
                home > hole || home <= j
            };
            if !stays {
                self.keys[hole] = self.keys[j];
                self.slots[hole] = self.slots[j];
                hole = j;
            }
            j = (j + 1) & (SLOTS - 1);
        }
        self.keys[hole] = EMPTY;
    }
}

/// Keep a weak reference to `space` (once) and index its `Arc` address, as
/// soon as it is shared: an `Arc` lost before any task was attached is then
/// still found.
pub fn note_arc(space: &Arc<AddressSpace>) {
    note(space, 0);
}

/// Record the first task attached to `space` (and register it as
/// [`note_arc`] does if that has not happened). Later attachments — threads,
/// a replaced slot — leave the record as it is.
pub fn note_owner(space: &Arc<AddressSpace>, tid: u64) {
    note(space, tid);
}

fn note(space: &Arc<AddressSpace>, tid: u64) {
    let Some(i) = find(space.root.raw()) else {
        return;
    };
    let mut index = WEAK_LOCK.lock();
    if ROOTS[i].load(Ordering::Acquire) != space.root.raw() {
        return;
    }
    if tid != 0 && OWNER_TID[i].load(Ordering::Relaxed) == 0 {
        OWNER_TID[i].store(tid, Ordering::Relaxed);
    }
    if WEAK[i].load(Ordering::Acquire).is_null() {
        // `downgrade` only bumps the weak count: allocation-free.
        let raw = Weak::into_raw(Arc::downgrade(space)) as *mut AddressSpace;
        WEAK[i].store(raw, Ordering::Release);
        index.insert(arc_inner_addr(raw), i);
    }
}

/// Scan `[lo, hi)`, the live part of a kernel stack that is about to be
/// abandoned (task exit, or exec entering the new image at the stack top),
/// for registered spaces' `Arc`s. No destructor of a local on it will run,
/// so each one found is a strong reference never released (or the stale
/// bits of a moved-from slot: a lead, checked against whether the space
/// then outlives its tasks). For each, the first word above it inside
/// `[tstart, tend)` — the return address of the frame owning the slot — is
/// recorded with `tid` against the space, once. Returns whether any was
/// found.
///
/// # Safety
/// `[lo, hi)` must be mapped and readable, 8-byte aligned.
pub unsafe fn scan_abandoned_stack(lo: u64, hi: u64, tid: u64, tstart: u64, tend: u64) -> bool {
    let index = WEAK_LOCK.lock();
    let mut found = false;
    let mut at = lo;
    while at + 8 <= hi {
        // SAFETY: caller contract.
        let word = unsafe { (at as *const u64).read_volatile() };
        if let Some(slot) = index.get(word) {
            found = true;
            let mut site = u64::MAX;
            let mut above = at + 8;
            while above + 8 <= hi && above < at + 8 * 512 {
                // SAFETY: caller contract.
                let w = unsafe { (above as *const u64).read_volatile() };
                if w > tstart && w < tend {
                    site = w - tstart;
                    break;
                }
                above += 8;
            }
            if HELD_SITE[slot].load(Ordering::Relaxed) == 0 {
                HELD_SITE[slot].store(site, Ordering::Relaxed);
                HELD_TID[slot].store(tid, Ordering::Relaxed);
            }
        }
        at += 8;
    }
    found
}

/// Note the exit of the task whose space has root `root`, with the strong
/// count seen; `held` says whether its abandoned stack held any registered
/// space's `Arc`.
pub fn note_exit(root: u64, strong: usize, held: bool) {
    EXITS.fetch_add(1, Ordering::Relaxed);
    if held {
        EXITS_HELD.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(i) = find(root) {
        EXIT_STRONG[i].store(strong as u64 + 1, Ordering::Relaxed);
    }
}

/// Forget `root` (its tree is being freed).
pub fn forget(root: u64) {
    let Some(i) = find(root) else {
        return;
    };
    let weak = {
        let mut index = WEAK_LOCK.lock();
        let weak = WEAK[i].swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !weak.is_null() {
            index.remove(arc_inner_addr(weak));
        }
        weak
    };
    ORIGINS[i].store(core::ptr::null_mut(), Ordering::Release);
    ROOTS[i].store(TOMBSTONE, Ordering::Release);
    if !weak.is_null() {
        // SAFETY: stored by `note_owner` from `Weak::into_raw`, swapped out
        // exactly once under the lock. Called from the space's own `Drop`
        // this only lowers the weak count: the `Arc`'s implicit weak
        // reference keeps the allocation until `Drop` returns.
        drop(unsafe { Weak::from_raw(weak) });
    }
}

/// Visit every recorded live root with its origin (racy snapshot).
pub fn for_each(mut visit: impl FnMut(u64, Option<&'static Location<'static>>)) {
    for i in 0..SLOTS {
        let key = ROOTS[i].load(Ordering::Acquire);
        if key == EMPTY || key == TOMBSTONE {
            continue;
        }
        let origin = ORIGINS[i].load(Ordering::Acquire);
        // SAFETY: only `&'static Location` pointers are stored.
        visit(key, unsafe { origin.as_ref() });
    }
}

/// What the registry knows about one live root.
#[derive(Clone, Copy, Debug)]
pub struct RootInfo {
    pub root: u64,
    pub origin: Option<&'static Location<'static>>,
    /// First task attached (0: never attached).
    pub owner_tid: u64,
    /// Strong references now (`None`: no weak reference was registered).
    pub strong: Option<usize>,
    /// Strong references when the last task exited (`None`: no exit seen).
    pub exit_strong: Option<usize>,
    /// `.text` offset of the frame that held a reference on an abandoned
    /// kernel stack (0: none), and that stack's task.
    pub held_site: u64,
    pub held_tid: u64,
    /// Scheduler tasks that may still execute through it (Linux
    /// `mm_users`), when it could be read.
    pub user_tasks: Option<u32>,
    /// The address its `Arc`s store (0: no weak reference registered).
    pub arc: u64,
}

/// Look up `root` (racy snapshot). Reads the strong count through the weak
/// reference without upgrading it.
pub fn info(root: u64) -> Option<RootInfo> {
    let i = find(root)?;
    let origin = ORIGINS[i].load(Ordering::Acquire);
    let (strong, user_tasks, arc) = {
        let _g = WEAK_LOCK.lock();
        let raw = WEAK[i].load(Ordering::Acquire);
        if raw.is_null() {
            (None, None, 0)
        } else {
            // SAFETY: `raw` is a live `Weak::into_raw` pointer: `forget`
            // swaps it out under this lock before releasing it. Wrapped in
            // ManuallyDrop so the registry keeps its reference.
            let weak = core::mem::ManuallyDrop::new(unsafe { Weak::from_raw(raw) });
            let strong = weak.strong_count();
            let user_tasks = if strong != 0 {
                // SAFETY: the weak reference keeps the allocation, and the
                // space's fields are dropped only after `Drop::drop` returns,
                // which first needs this lock (in `forget`). The counter is
                // an atomic, so a concurrent `Drop` body is no data race.
                Some(unsafe { (*raw).scheduler_user_tasks() })
            } else {
                None
            };
            (Some(strong), user_tasks, arc_inner_addr(raw))
        }
    };
    let exit_strong = EXIT_STRONG[i].load(Ordering::Relaxed);
    Some(RootInfo {
        root,
        // SAFETY: only `&'static Location` pointers are stored.
        origin: unsafe { origin.as_ref() },
        owner_tid: OWNER_TID[i].load(Ordering::Relaxed),
        strong,
        exit_strong: exit_strong.checked_sub(1).map(|s| s as usize),
        held_site: HELD_SITE[i].load(Ordering::Relaxed),
        held_tid: HELD_TID[i].load(Ordering::Relaxed),
        user_tasks,
        arc,
    })
}

/// Words on each side of a hit that [`scan_ram_for_arcs`] hands its visitor.
pub const HIT_CONTEXT: usize = 8;

/// Diagnostic sweep for the owner of an `Arc` nobody released: read every
/// managed RAM frame but page tables through the direct map and call
/// `visit(phys, words, at)` for each 8-byte word equal to one of `targets`
/// (sorted `ArcInner` addresses), with the `2 * HIT_CONTEXT` words around it
/// (`words[at]` is the hit; words outside the frame read as 0). Freed memory
/// keeps stale copies, so a single hit proves nothing; an owner shows up as
/// the same surrounding layout — usually a vtable or `.rodata` word at a fixed
/// distance — repeated once per leaked space. Racy, read-only, and slow
/// (every word of RAM): for `/proc` diagnostics only.
pub fn scan_ram_for_arcs(
    targets: &[u64],
    mut visit: impl FnMut(u64, &[u64; 2 * HIT_CONTEXT], usize),
) {
    let (Some(&lo), Some(&hi)) = (targets.first(), targets.last()) else {
        return;
    };
    for (start, len) in crate::frame::managed_ram_ranges() {
        let mut page = (start + 4095) & !4095;
        while page + 4096 <= start + len {
            if crate::frame::cow::page_table_mark(page) != Some(true) {
                let base = crate::PhysAddr::new(page).kernel_ptr::<u64>();
                for i in 0..512usize {
                    // SAFETY: managed RAM is mapped in the kernel's direct map;
                    // a racy volatile read of a live frame is all this does.
                    let w = unsafe { base.add(i).read_volatile() };
                    if w < lo || w > hi || targets.binary_search(&w).is_err() {
                        continue;
                    }
                    let mut words = [0u64; 2 * HIT_CONTEXT];
                    for (k, slot) in words.iter_mut().enumerate() {
                        let j = i as isize + k as isize - HIT_CONTEXT as isize;
                        if (0..512).contains(&j) {
                            // SAFETY: as above, inside the same frame.
                            *slot = unsafe { base.add(j as usize).read_volatile() };
                        }
                    }
                    visit(page + i as u64 * 8, &words, HIT_CONTEXT);
                }
            }
            page += 4096;
        }
    }
}

/// `(exits seen, exits whose abandoned stack held the space)`.
pub fn exit_counts() -> (u64, u64) {
    (
        EXITS.load(Ordering::Relaxed),
        EXITS_HELD.load(Ordering::Relaxed),
    )
}

/// Records dropped because the table was full.
pub fn dropped() -> usize {
    DROPPED.load(Ordering::Relaxed)
}
