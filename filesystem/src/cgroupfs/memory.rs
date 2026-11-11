//! `memory` controller — memory accounting + limits.
//!
//! Real charge/uncharge accounting wired to the page/frame allocator
//! (`narf-memory`) through hooks this module installs the first time a
//! `memory` cgroup state is created. User pages — anonymous memory, page
//! cache a task brings in, tmpfs/shmem — are charged to the allocating task's
//! cgroup chain; the allocator records the cgroup's `MemcgId` on the frame and
//! the frame's final free uncharges that cgroup, whoever frees it. Kernel
//! memory is never charged (Linux charges it only with `__GFP_ACCOUNT`).
//! A pid-keyed charge hook remains for BPF maps and zswap payloads.
//!
//! # What is enforced vs accounting-only
//!
//! * **`memory.max` — ENFORCED for user memory.** A charge that would push
//!   any level over its `memory.max` publishes a capped background-reclaim
//!   request, bumps that level's `max` event and is refused. A refused user
//!   page queues a memory-cgroup OOM, run by the OOM reaper with no lock
//!   held, which kills a process of the cgroup's subtree (or the task whose
//!   charge was refused) and bumps `oom`/`oom_kill`; the faulting task waits
//!   on a reclaim cycle and retries. A copy-on-write break is force-charged.
//! * **`memory.high` — deferred reclaim trigger.** v2 `memory.high` is a
//!   throttle/reclaim trigger, never a hard wall. A positive charge that
//!   would push a level over `high` publishes the same kind of background
//!   request, commits the charge, and bumps the `high` event counter.
//!
//! ## Reclaim scope + limitations
//!
//! Background work enters the global kswapd reclaim engines rather than a
//! per-cgroup LRU, so a cgroup at `memory.max` is relieved by its OOM kill,
//! not by reclaiming its own pages.
//! * **`memory.current` / `memory.peak` — REAL.** Live charged-byte
//!   totals, summed from actual frame allocations attributed to the
//!   cgroup's tasks (no fabricated numbers).
//! * **`memory.min` / `memory.low` — STORED, NOT ACTED ON.** These are
//!   reclaim-protection knobs; with no reclaim path they are accepted
//!   and echoed back but have no runtime effect.
//! * **`memory.stat` — single honest bucket.** We can attribute charged
//!   bytes to the cgroup but cannot (yet) distinguish anon vs file vs
//!   kernel at the frame allocator, so the total lands in `anon` and
//!   the categories we can't back are reported as `0` rather than
//!   invented.
//! * **swap / zswap — accounting-only zero.** No swap/zswap accounting
//!   seam exists in the allocator; `memory.swap.current` /
//!   `memory.zswap.current` stay `0` and `memory.swap.max` /
//!   `memory.zswap.max` store their limits without effect. (`zswap.*` is
//!   present so systemd can read the knobs back rather than seeing
//!   ENOENT.)
//!
//! Linux ref: `mm/memcontrol.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"Memory".

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "memory.current",
    "memory.peak",
    "memory.min",
    "memory.low",
    "memory.high",
    "memory.max",
    "memory.events",
    "memory.events.local",
    "memory.stat",
    "memory.oom.group",
    "memory.reclaim",
    "memory.swap.current",
    "memory.swap.max",
    "memory.zswap.current",
    "memory.zswap.max",
    "memory.zswap.writeback",
];

/// Guards the one-time install of the allocator charge hook. Set the
/// first time any `memory` cgroup state is created (`new_state`), so no
/// external boot wiring is required.
static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

// Charge-hook recursion is local to the CPU executing the allocator. A
// process on another CPU must still be accounted while this CPU is walking
// its cgroup chain. The old single AtomicBool made every concurrent charge a
// false "recursive" entry and silently let it through unaccounted.
static IN_CHARGE: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

// Cgroup membership bookkeeping is kernel metadata, and mutating its
// BTreeMap can itself allocate or free a slab page. The allocator charge hook
// resolves membership through that same map, so charging while its lock is
// held would recursively acquire the lock with IRQs disabled. This per-CPU
// nesting count lets the narrow mutation helper in the parent module suppress
// only those metadata charges. Its guard is entered after the IRQ-safe map
// lock is acquired, so the CPU cannot migrate before it is dropped.
static BYPASS_CHARGE: [AtomicUsize; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; narf_lib::percpu::MAX_CPUS];

/// Bound one memcg pressure publication to 16 MiB of base pages. Requests
/// coalesce by maximum in `narf-memory`, so a burst cannot accumulate an
/// unbounded kswapd debt.
const BACKGROUND_RECLAIM_MAX_PAGES: usize = 4096;

pub(super) struct ChargeBypassGuard {
    cpu: usize,
}

impl Drop for ChargeBypassGuard {
    fn drop(&mut self) {
        let previous = BYPASS_CHARGE[self.cpu].fetch_sub(1, Ordering::Release);
        debug_assert!(previous != 0, "unbalanced cgroup charge bypass");
    }
}

pub(super) fn bypass_charge() -> ChargeBypassGuard {
    let cpu = narf_lib::percpu::current_cpu();
    BYPASS_CHARGE[cpu].fetch_add(1, Ordering::AcqRel);
    ChargeBypassGuard { cpu }
}

fn charge_hook(pid: u64, delta_bytes: i64) -> bool {
    let cpu = narf_lib::percpu::current_cpu();
    if BYPASS_CHARGE[cpu].load(Ordering::Acquire) != 0 {
        return true;
    }
    if IN_CHARGE[cpu].swap(true, Ordering::AcqRel) {
        return true;
    }
    struct Guard(usize);
    impl Drop for Guard {
        fn drop(&mut self) {
            IN_CHARGE[self.0].store(false, Ordering::Release);
        }
    }
    let _guard = Guard(cpu);

    if delta_bytes < 0 {
        let amount = delta_bytes.unsigned_abs();
        // Final-owner frame return can run from allocator teardown, so this
        // branch must not allocate or it recursively re-enters GlobalAlloc.
        // Walk only an existing membership chain (no
        // allocating root fallback), clone one already-owned Arc at a time,
        // and perform the atomic uncharge inline. An exited/unplaced pid is a
        // documented best-effort miss, not a reason to construct cgroup state.
        super::with_existing_chain_states(pid, "memory", |s| {
            if let Some(m) = s.as_any().downcast_ref::<MemoryState>() {
                m.uncharge(amount);
            }
        });
        return true;
    }

    if delta_bytes == 0 {
        return true;
    }

    struct ChargeLevel {
        state: Arc<dyn ControllerState>,
        reserved_current: u64,
    }

    // Collect the hierarchy once, then reserve each level with a CAS. If an
    // ancestor rejects the charge, roll back every descendant already
    // reserved. This is the page_counter_try_charge shape: concurrent callers
    // cannot both pass a detached load/check and overrun memory.max.
    let mut states: Vec<ChargeLevel> = Vec::new();
    super::with_chain_states(pid, "memory", |state| {
        states.push(ChargeLevel {
            state: state.clone(),
            reserved_current: 0,
        });
    });

    let amount = delta_bytes as u64;

    for index in 0..states.len() {
        let Some(m) = states[index].state.as_any().downcast_ref::<MemoryState>() else {
            continue;
        };
        match m.try_reserve_charge(amount) {
            Ok(now) => states[index].reserved_current = now,
            Err(deficit) => {
                for reserved in &states[..index] {
                    if reserved.reserved_current == 0 {
                        continue;
                    }
                    if let Some(previous) = reserved.state.as_any().downcast_ref::<MemoryState>() {
                        previous.uncharge(amount);
                    }
                }
                queue_background_reclaim(deficit);
                m.note_max_event();
                return false;
            }
        }
    }

    // All levels are committed now. Only a successful charge may generate
    // memory.high pressure; publishing it before max validation would reclaim
    // unrelated caches for a hypothetical charge that never landed.
    let mut high_deficit = 0u64;
    for level in &states {
        if let Some(m) = level.state.as_any().downcast_ref::<MemoryState>() {
            high_deficit = high_deficit.max(m.finish_reserved_charge(level.reserved_current));
        }
    }
    queue_background_reclaim(high_deficit);
    true
}

/// Publish a capped page target to the local node's kswapd. This is bounded,
/// allocation-free, and does not authorize the global OOM killer.
fn queue_background_reclaim(deficit: u64) {
    if deficit == 0 {
        return;
    }
    let pages = deficit
        .div_ceil(narf_memory::PAGE_SIZE)
        .min(BACKGROUND_RECLAIM_MAX_PAGES as u64) as usize;
    narf_memory::reclaim::request_reclaim(narf_memory::frame::local_node(), pages);
}

/// Test-only seam: drive the chain-walking [`charge_hook`] directly
/// (the allocator normally invokes it via the installed fn-pointer).
/// Lets the cgroupfs tests exercise the re-entrancy guard and the
/// hierarchical `memory.max` reservation over a real cgroup chain without a
/// live frame allocation.
#[doc(hidden)]
pub fn charge_hook_for_test(pid: u64, delta_bytes: i64) -> bool {
    charge_hook(pid, delta_bytes)
}

/// Test-only seam: is a charge currently in progress on this path? Lets
/// a test observe the re-entrancy guard's state to synthesise a nested
/// entry deterministically.
#[doc(hidden)]
pub fn in_charge_for_test() -> bool {
    IN_CHARGE[narf_lib::percpu::current_cpu()].load(Ordering::Acquire)
}

/// Test-only seam: raise/lower the re-entrancy guard so a test can
/// simulate a nested `charge_hook` entry (the real nesting arises when
/// the charge path itself allocates). Returns the previous value.
#[doc(hidden)]
pub fn set_in_charge_for_test(v: bool) -> bool {
    IN_CHARGE[narf_lib::percpu::current_cpu()].swap(v, Ordering::AcqRel)
}

/// Install the allocator charge plumbing exactly once.
///
/// DOCUMENTED LAZY INSTALL: called from `MemoryController::new_state`
/// the first time any `memory` cgroup acquires state, so cgroup memory
/// accounting comes online with no external boot wiring. Two halves:
///
///   * the **charge hook** (this module's [`charge_hook`]) — the
///     allocator calls it on every user-facing frame alloc/free;
///   * the **charge-PID provider** — installed via
///     [`narf_scheduler::install_memory_pid_provider`], which answers
///     "which task is allocating now" from the scheduler's current-task
///     register (the allocator has no per-task context of its own).
///
/// With both installed, `memory.max` enforcement is live end-to-end: a
/// frame allocation by a task whose cgroup chain is at its limit is
/// charged, rejected, and failed back to the caller as ENOMEM.
fn ensure_hook_installed() {
    if HOOK_INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        init_memcg_ids();
        narf_memory::install_cgroup_charge_hook(charge_hook);
        narf_memory::install_page_charge_hooks(
            charge_page_hook,
            uncharge_page_hook,
            memcg_oom_hook,
        );
        narf_scheduler::install_memory_pid_provider();
    }
}

// ── Memory-cgroup ids and per-page charging ──────────────────────────────
//
// Every memory cgroup state gets a `MemcgId` (Linux `mem_cgroup_id`,
// 1..=MEMCG_ID_MAX). The frame allocator records that id on each user page it
// charges, and the page's final free uncharges the id's cgroup and its
// ancestors — never whichever task happens to be running then.
//
// A cgroup that is removed (rmdir, or `memory` disabled in its parent's
// `cgroup.subtree_control`) while pages are still charged to it goes
// offline but keeps its id and counters until its `memory.current` reaches
// 0, so late uncharges land on it and on its ancestors exactly as the charges
// did. Linux reparents the dying cgroup's objcg to the parent; the
// ancestors' counters come out the same either way, because a charge is
// accounted at every level of the chain.

/// Linux `MEM_CGROUP_ID_MAX`.
const MEMCG_ID_MAX: usize = 65535;

#[derive(Debug)]
struct MemcgEntry {
    state: Arc<dyn ControllerState>,
    /// Id of the nearest ancestor with a memory state; 0 for the top.
    parent: narf_memory::MemcgId,
    /// The cgroup is gone; release the id once nothing is charged to it.
    offline: bool,
}

#[derive(Debug)]
struct MemcgSlot {
    entry: IrqSafeSpinLock<Option<MemcgEntry>>,
}

/// Slot `id - 1` describes memory cgroup `id`. Allocated with the first
/// memory cgroup; per-slot locks, so uncharges of different cgroups never
/// meet on one lock.
static MEMCG_SLOTS: narf_lib::sync::OnceLock<alloc::boxed::Box<[MemcgSlot]>> =
    narf_lib::sync::OnceLock::new();
/// Ids returned by released cgroups. Capacity for every id is reserved up
/// front, so a release (which runs on the frame-free path) never allocates.
static MEMCG_FREE_IDS: IrqSafeSpinLock<Vec<narf_memory::MemcgId>> =
    IrqSafeSpinLock::new(Vec::new());
/// Next never-used id.
static MEMCG_NEXT_ID: AtomicU32 = AtomicU32::new(1);

fn memcg_slots() -> Option<&'static [MemcgSlot]> {
    MEMCG_SLOTS.get().map(|slots| &slots[..])
}

/// Allocate the id table. Runs once, from `ensure_hook_installed`, in the
/// context of creating a cgroup, where allocation is fine.
fn init_memcg_ids() {
    let mut slots = Vec::with_capacity(MEMCG_ID_MAX);
    slots.resize_with(MEMCG_ID_MAX, || MemcgSlot {
        entry: IrqSafeSpinLock::new(None),
    });
    let _ = MEMCG_SLOTS.set(slots.into_boxed_slice());
    let mut free = Vec::with_capacity(MEMCG_ID_MAX);
    core::mem::swap(&mut *MEMCG_FREE_IDS.lock(), &mut free);
}

/// Give `state` an id. `parent` is the nearest ancestor's memory state. A
/// full table leaves the state with id 0: its pages are then charged to the
/// nearest ancestor that has an id (see `charge_page_hook`).
fn register_memcg(state: &Arc<dyn ControllerState>, parent: Option<&Arc<dyn ControllerState>>) {
    let Some(slots) = memcg_slots() else {
        return;
    };
    let Some(memory) = state.as_any().downcast_ref::<MemoryState>() else {
        return;
    };
    let parent_id = parent
        .and_then(|p| p.as_any().downcast_ref::<MemoryState>())
        .map_or(0, MemoryState::memcg_id);
    let id = {
        let reused = MEMCG_FREE_IDS.lock().pop();
        match reused {
            Some(id) => id,
            None => {
                let id = MEMCG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
                if id as usize > MEMCG_ID_MAX {
                    MEMCG_NEXT_ID.store(MEMCG_ID_MAX as u32 + 1, Ordering::Relaxed);
                    return;
                }
                id
            }
        }
    };
    *slots[id as usize - 1].entry.lock() = Some(MemcgEntry {
        state: state.clone(),
        parent: parent_id,
        offline: false,
    });
    memory.id.store(id, Ordering::Release);
}

/// Take `state`'s cgroup offline: it has been removed from the hierarchy.
/// Its id is released now if nothing is charged to it, else by the uncharge
/// that brings it to zero.
pub(super) fn offline_memcg(state: &Arc<dyn ControllerState>) {
    let Some(memory) = state.as_any().downcast_ref::<MemoryState>() else {
        return;
    };
    let id = memory.memcg_id();
    let Some(slots) = memcg_slots() else {
        return;
    };
    if id == 0 {
        return;
    }
    if let Some(entry) = slots[id as usize - 1].entry.lock().as_mut() {
        entry.offline = true;
    }
    release_if_drained(id);
}

/// Release `id` if its cgroup is offline and nothing is charged to it any
/// more. Allocation-free: the free-id list has room for every id, and the
/// final `Arc` of the state, if this is it, is dropped after every lock is
/// released.
fn release_if_drained(id: narf_memory::MemcgId) {
    let Some(slots) = memcg_slots() else {
        return;
    };
    let released = {
        let mut entry = slots[id as usize - 1].entry.lock();
        let drained = entry.as_ref().is_some_and(|e| {
            e.offline
                && e.state
                    .as_any()
                    .downcast_ref::<MemoryState>()
                    .is_some_and(|m| m.current.load(Ordering::Acquire) == 0)
        });
        if drained {
            entry.take()
        } else {
            None
        }
    };
    if let Some(entry) = released {
        if let Some(memory) = entry.state.as_any().downcast_ref::<MemoryState>() {
            memory.id.store(0, Ordering::Release);
        }
        let mut free = MEMCG_FREE_IDS.lock();
        if free.len() < free.capacity() {
            free.push(id);
        }
        drop(free);
        drop(entry);
    }
}

/// `narf_memory` page-charge hook: charge `bytes` to `pid`'s memory cgroup
/// chain and return the id the frame records. `Ok(0)` when nothing was
/// charged; `Err(id)` names the cgroup whose `memory.max` refused it.
fn charge_page_hook(
    pid: u64,
    bytes: u64,
    force: bool,
) -> Result<narf_memory::MemcgId, narf_memory::MemcgId> {
    if bytes == 0 {
        return Ok(0);
    }
    let cpu = narf_lib::percpu::current_cpu();
    if BYPASS_CHARGE[cpu].load(Ordering::Acquire) != 0 {
        return Ok(0);
    }
    if IN_CHARGE[cpu].swap(true, Ordering::AcqRel) {
        return Ok(0);
    }
    struct Guard(usize);
    impl Drop for Guard {
        fn drop(&mut self) {
            IN_CHARGE[self.0].store(false, Ordering::Release);
        }
    }
    let _guard = Guard(cpu);

    let mut levels: Vec<Arc<dyn ControllerState>> = Vec::new();
    super::with_chain_states(pid, "memory", |state| levels.push(state.clone()));
    // The id the page records: the nearest level that has one. Every level
    // from it up is charged, and its uncharge walks the same levels.
    let Some(first) = levels.iter().position(|state| {
        state
            .as_any()
            .downcast_ref::<MemoryState>()
            .is_some_and(|m| m.memcg_id() != 0)
    }) else {
        return Ok(0);
    };
    let levels = &levels[first..];
    let leaf = levels[0]
        .as_any()
        .downcast_ref::<MemoryState>()
        .map_or(0, MemoryState::memcg_id);

    let mut reserved = 0usize;
    let mut breach = None;
    for (index, state) in levels.iter().enumerate() {
        let Some(m) = state.as_any().downcast_ref::<MemoryState>() else {
            reserved = index + 1;
            continue;
        };
        match m.try_reserve_charge(bytes) {
            Ok(now) => {
                m.finish_reserved_charge(now);
            }
            Err(deficit) if force => {
                let now = m.current.fetch_add(bytes, Ordering::AcqRel) + bytes;
                m.peak.fetch_max(now, Ordering::AcqRel);
                m.note_max_event();
                queue_background_reclaim(deficit);
            }
            Err(deficit) => {
                m.note_max_event();
                queue_background_reclaim(deficit);
                breach = Some(m.memcg_id());
                break;
            }
        }
        reserved = index + 1;
    }
    if let Some(breach) = breach {
        for state in &levels[..reserved] {
            if let Some(m) = state.as_any().downcast_ref::<MemoryState>() {
                m.uncharge(bytes);
            }
        }
        // A breach at a level with no id (table full) is scoped to the leaf.
        return Err(if breach == 0 { leaf } else { breach });
    }
    Ok(leaf)
}

/// `narf_memory` page-uncharge hook: return `bytes` to memory cgroup `id` and
/// each ancestor it was charged through. Runs on frame-free paths with any
/// lock held: allocation-free, per-slot locks only, no lock held across the
/// counter updates.
fn uncharge_page_hook(id: narf_memory::MemcgId, bytes: u64) {
    let Some(slots) = memcg_slots() else {
        return;
    };
    let mut next = id;
    // Bounded by the hierarchy depth; the extra bound only guards a corrupted
    // parent link from looping.
    for _ in 0..MEMCG_ID_MAX {
        if next == 0 || next as usize > MEMCG_ID_MAX {
            break;
        }
        let current = next;
        let (state, parent, offline) = {
            let entry = slots[current as usize - 1].entry.lock();
            match entry.as_ref() {
                Some(e) => (e.state.clone(), e.parent, e.offline),
                None => break,
            }
        };
        if let Some(m) = state.as_any().downcast_ref::<MemoryState>() {
            m.uncharge(bytes);
        }
        drop(state);
        if offline {
            release_if_drained(current);
        }
        next = parent;
    }
}

/// `narf_memory` memcg-OOM hook, run by the OOM reaper with no allocator or
/// address-space lock held (Linux `mem_cgroup_out_of_memory`): kill one
/// process inside memory cgroup `id`'s subtree, chosen by the OOM policy; if
/// none is eligible, the task whose charge was refused. Returns whether a
/// victim was queued.
fn memcg_oom_hook(id: narf_memory::MemcgId, pid: u64) -> bool {
    let state = memcg_slots().and_then(|slots| {
        if id == 0 || id as usize > MEMCG_ID_MAX {
            return None;
        }
        slots[id as usize - 1]
            .entry
            .lock()
            .as_ref()
            .map(|e| e.state.clone())
    });
    let members = state.as_ref().and_then(super::memcg_member_pids);
    if let Some(m) = state
        .as_ref()
        .and_then(|s| s.as_any().downcast_ref::<MemoryState>())
    {
        m.events_oom.fetch_add(1, Ordering::Relaxed);
    }
    let killed = members
        .as_deref()
        .filter(|pids| !pids.is_empty())
        .and_then(narf_memory::oom::request_oom_relief_in)
        .or_else(|| {
            (pid != 0)
                .then(|| narf_memory::oom::request_oom_relief_in(&[pid]))
                .flatten()
        });
    if killed.is_some() {
        if let Some(m) = state
            .as_ref()
            .and_then(|s| s.as_any().downcast_ref::<MemoryState>())
        {
            m.events_oom_kill.fetch_add(1, Ordering::Relaxed);
        }
    }
    killed.is_some()
}

/// Test seams for the per-page charge hooks.
#[doc(hidden)]
pub fn charge_page_for_test(pid: u64, bytes: u64) -> Result<u32, u32> {
    charge_page_hook(pid, bytes, false)
}

#[doc(hidden)]
pub fn uncharge_page_for_test(id: u32, bytes: u64) {
    uncharge_page_hook(id, bytes);
}

#[derive(Debug)]
pub struct MemoryController;

impl Controller for MemoryController {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn new_state(&self, parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        ensure_hook_installed();
        let state: Arc<dyn ControllerState> = Arc::new(MemoryState {
            id: AtomicU32::new(0),
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            swap_current: AtomicU64::new(0),
            zswap_current: AtomicU64::new(0),
            min: IrqSafeSpinLock::new(0),
            low: IrqSafeSpinLock::new(0),
            high: IrqSafeSpinLock::new(None),
            max: IrqSafeSpinLock::new(None),
            swap_max: IrqSafeSpinLock::new(None),
            zswap_max: IrqSafeSpinLock::new(None),
            events_low: AtomicU64::new(0),
            events_high: AtomicU64::new(0),
            events_max: AtomicU64::new(0),
            events_oom: AtomicU64::new(0),
            events_oom_kill: AtomicU64::new(0),
            oom_group: AtomicBool::new(false),
            zswap_writeback: AtomicBool::new(true),
        });
        register_memcg(&state, parent.as_ref());
        state
    }
}

#[derive(Debug)]
pub struct MemoryState {
    /// This cgroup's `MemcgId` (0 = none: id table full, or released).
    id: AtomicU32,
    /// `memory.current` — live charged bytes for this level.
    current: AtomicU64,
    /// `memory.peak` — high-water mark of `current`.
    peak: AtomicU64,
    swap_current: AtomicU64,
    /// `memory.zswap.current` — accounting-only (no zswap seam in the
    /// allocator), so this stays 0 like `swap_current`.
    zswap_current: AtomicU64,
    min: IrqSafeSpinLock<u64>,
    low: IrqSafeSpinLock<u64>,
    /// `None` = "max".
    high: IrqSafeSpinLock<Option<u64>>,
    max: IrqSafeSpinLock<Option<u64>>,
    swap_max: IrqSafeSpinLock<Option<u64>>,
    /// `memory.zswap.max` — stored limit, accounting-only (no effect),
    /// mirroring `swap_max`. Present so systemd can read it back rather
    /// than seeing ENOENT and logging a spurious debug error.
    zswap_max: IrqSafeSpinLock<Option<u64>>,
    zswap_writeback: AtomicBool,
    /// `memory.events` counters (this cgroup's own — i.e. `.local`).
    events_low: AtomicU64,
    events_high: AtomicU64,
    events_max: AtomicU64,
    events_oom: AtomicU64,
    events_oom_kill: AtomicU64,
    /// `memory.oom.group` — kill the cgroup as a unit on OOM. systemd
    /// writes this for units with `OOMPolicy=kill`; NARF has no OOM
    /// killer, so the bit is stored + reported, never acted on.
    oom_group: AtomicBool,
}

fn max_line(v: &Option<u64>) -> String {
    match v {
        None => "max\n".into(),
        Some(n) => format!("{n}\n"),
    }
}

/// Snapshot a limit while its IRQ-safe lock is held, then run all callbacks
/// and formatting after releasing the guard. Allocator charging re-enters the
/// memory controller's `high`/`max` locks, so even a tiny `format!` under one
/// of these guards can self-deadlock on a slab refill.
fn locked_max_line_with(
    limit: &IrqSafeSpinLock<Option<u64>>,
    after_snapshot: impl FnOnce(),
) -> String {
    let value = *limit.lock();
    after_snapshot();
    max_line(&value)
}

fn locked_max_line(limit: &IrqSafeSpinLock<Option<u64>>) -> String {
    locked_max_line_with(limit, || {})
}

fn locked_u64_line(value: &IrqSafeSpinLock<u64>) -> String {
    let value = *value.lock();
    format!("{value}\n")
}

fn parse_limit(buf: &[u8]) -> Result<Option<u64>, FsError> {
    let t = core::str::from_utf8(buf)
        .map_err(|_| FsError::InvalidData)?
        .trim();
    if t == "max" {
        Ok(None)
    } else {
        t.parse::<u64>().map(Some).map_err(|_| FsError::InvalidData)
    }
}

fn parse_u64(buf: &[u8]) -> Result<u64, FsError> {
    core::str::from_utf8(buf)
        .map_err(|_| FsError::InvalidData)?
        .trim()
        .parse::<u64>()
        .map_err(|_| FsError::InvalidData)
}

impl MemoryState {
    /// The id user pages charged to this cgroup record; 0 if it has none.
    pub fn memcg_id(&self) -> narf_memory::MemcgId {
        self.id.load(Ordering::Acquire)
    }

    /// `memory.current`, in bytes.
    pub fn current_bytes(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// Deterministically inject allocator charging between taking a locked
    /// limit snapshot and formatting it. This shares the production helper,
    /// so regressing the guard lifetime makes the test self-deadlock.
    #[doc(hidden)]
    pub fn limit_read_charge_reentry_for_test(
        &self,
        file: &str,
        pid: u64,
        delta_bytes: i64,
    ) -> bool {
        let mut allowed = false;
        let inject = || {
            allowed = charge_hook_for_test(pid, delta_bytes);
        };
        match file {
            "memory.high" => {
                let _ = locked_max_line_with(&self.high, inject);
            }
            "memory.max" => {
                let _ = locked_max_line_with(&self.max, inject);
            }
            _ => return false,
        }
        allowed
    }

    /// Atomically reserve `amount` against this level's current max. The limit
    /// lock serializes a concurrent limit write with the CAS, while the CAS
    /// serializes concurrent charges without holding a hierarchy-wide lock.
    fn try_reserve_charge(&self, amount: u64) -> Result<u64, u64> {
        self.try_reserve_charge_with(amount, || {})
    }

    fn try_reserve_charge_with(
        &self,
        amount: u64,
        after_initial_load: impl FnOnce(),
    ) -> Result<u64, u64> {
        let limit = self.max.lock();
        let mut current = self.current.load(Ordering::Acquire);
        after_initial_load();
        loop {
            let Some(next) = current.checked_add(amount) else {
                return Err(u64::MAX);
            };
            if let Some(max) = *limit {
                if next > max {
                    return Err(next - max);
                }
            }
            match self.current.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(next),
                Err(actual) => current = actual,
            }
        }
    }

    /// Complete telemetry for an already-reserved hierarchy charge and return
    /// its high-pressure deficit from the same limit snapshot used for the
    /// event decision.
    fn finish_reserved_charge(&self, now: u64) -> u64 {
        self.peak.fetch_max(now, Ordering::AcqRel);
        if let Some(high) = *self.high.lock() {
            if now > high {
                // high is a throttle, not a wall: record only.
                self.events_high.fetch_add(1, Ordering::Relaxed);
                return now - high;
            }
        }
        0
    }

    /// Deterministically place a competing current update after this caller's
    /// initial load. The CAS must observe it and refuse a stale max decision.
    #[doc(hidden)]
    pub fn reservation_interleaving_for_test(&self, amount: u64) -> bool {
        let result = self.try_reserve_charge_with(amount, || {
            self.current.fetch_add(amount, Ordering::AcqRel);
        });
        let current = self.current.load(Ordering::Acquire);
        self.uncharge(amount);
        result.is_err() && current == amount
    }

    /// Uncharge `amount` bytes, saturating at 0 so a free that races a
    /// fresh/zeroed state can never underflow.
    fn uncharge(&self, amount: u64) {
        let mut cur = self.current.load(Ordering::Acquire);
        loop {
            let next = cur.saturating_sub(amount);
            match self
                .current
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Record that a charge was ultimately rejected for exceeding
    /// `memory.max`. Only `max` advances: Linux's `oom` counter means OOM
    /// policy was considered, which this arbitrary-context hook forbids.
    fn note_max_event(&self) {
        self.events_max.fetch_add(1, Ordering::Relaxed);
    }

    /// Charge (`delta > 0`) or uncharge (`delta < 0`) this single level,
    /// enforcing `memory.max` on a positive delta. Returns `false` iff a
    /// positive delta is rejected for exceeding `max`. Exposed for tests
    /// and direct accounting; the allocator hook drives the chain-wide
    /// hierarchy-reservation path in `charge_hook`.
    pub fn charge(&self, delta: i64) -> bool {
        if delta < 0 {
            self.uncharge(delta.unsigned_abs());
            return true;
        }
        if delta == 0 {
            return true;
        }
        let amount = delta as u64;
        match self.try_reserve_charge(amount) {
            Ok(now) => {
                self.finish_reserved_charge(now);
                true
            }
            Err(_) => {
                self.note_max_event();
                false
            }
        }
    }

    fn events_block(&self) -> String {
        format!(
            "low {}\nhigh {}\nmax {}\noom {}\noom_kill {}\noom_group_kill 0\n",
            self.events_low.load(Ordering::Acquire),
            self.events_high.load(Ordering::Acquire),
            self.events_max.load(Ordering::Acquire),
            self.events_oom.load(Ordering::Acquire),
            self.events_oom_kill.load(Ordering::Acquire),
        )
    }
}

impl ControllerState for MemoryState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "memory.current" => format!("{}\n", self.current.load(Ordering::Acquire)),
            "memory.peak" => format!("{}\n", self.peak.load(Ordering::Acquire)),
            "memory.min" => locked_u64_line(&self.min),
            "memory.low" => locked_u64_line(&self.low),
            "memory.high" => locked_max_line(&self.high),
            "memory.max" => locked_max_line(&self.max),
            "memory.swap.current" => format!("{}\n", self.swap_current.load(Ordering::Acquire)),
            "memory.swap.max" => locked_max_line(&self.swap_max),
            "memory.oom.group" => format!("{}\n", u8::from(self.oom_group.load(Ordering::Acquire))),
            // memory.reclaim is write-only on Linux (0200); render
            // empty for a read that slips through.
            "memory.reclaim" => String::new(),
            "memory.zswap.current" => format!("{}\n", self.zswap_current.load(Ordering::Acquire)),
            "memory.zswap.max" => locked_max_line(&self.zswap_max),
            "memory.zswap.writeback" => {
                format!(
                    "{}\n",
                    u8::from(self.zswap_writeback.load(Ordering::Acquire))
                )
            }
            // We charge each level directly, so this cgroup's own
            // counters ARE its local counters: events == events.local.
            "memory.events" | "memory.events.local" => self.events_block(),
            // Single honest bucket: charged bytes land in `anon`; the
            // categories the frame allocator can't distinguish are 0.
            "memory.stat" => format!(
                "anon {}\nfile 0\nkernel 0\nslab 0\nsock 0\n",
                self.current.load(Ordering::Acquire)
            ),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        match file {
            "memory.min" => {
                *self.min.lock() = parse_u64(buf)?;
                Ok(())
            }
            "memory.low" => {
                *self.low.lock() = parse_u64(buf)?;
                Ok(())
            }
            "memory.high" => {
                *self.high.lock() = parse_limit(buf)?;
                Ok(())
            }
            "memory.max" => {
                *self.max.lock() = parse_limit(buf)?;
                Ok(())
            }
            "memory.swap.max" => {
                *self.swap_max.lock() = parse_limit(buf)?;
                Ok(())
            }
            "memory.oom.group" => {
                match core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim()
                {
                    "0" => self.oom_group.store(false, Ordering::Release),
                    "1" => self.oom_group.store(true, Ordering::Release),
                    _ => return Err(FsError::InvalidData),
                }
                Ok(())
            }
            "memory.reclaim" => {
                // "<bytes>[ swappiness=<n>]". Parsed for validity;
                // NARF has no reclaim path, so accepting the request
                // is a no-op (the charged pages stay). Linux returns
                // success for whatever it managed to reclaim.
                let text = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
                let mut it = text.split_whitespace();
                let amount = it.next().ok_or(FsError::InvalidData)?;
                amount.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                for tok in it {
                    let (key, val) = tok.split_once('=').ok_or(FsError::InvalidData)?;
                    if key != "swappiness" {
                        return Err(FsError::InvalidData);
                    }
                    val.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                }
                Ok(())
            }
            "memory.zswap.max" => {
                *self.zswap_max.lock() = parse_limit(buf)?;
                Ok(())
            }
            "memory.zswap.writeback" => {
                match core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim()
                {
                    "0" => self.zswap_writeback.store(false, Ordering::Release),
                    "1" => self.zswap_writeback.store(true, Ordering::Release),
                    _ => return Err(FsError::InvalidData),
                }
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(
            file,
            "memory.min"
                | "memory.low"
                | "memory.high"
                | "memory.max"
                | "memory.swap.max"
                | "memory.oom.group"
                | "memory.reclaim"
                | "memory.zswap.max"
                | "memory.zswap.writeback"
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
