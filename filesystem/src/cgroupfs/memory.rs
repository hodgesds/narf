//! `memory` controller — memory accounting + limits.
//!
//! Real charge/uncharge accounting wired to the page/frame allocator
//! (`narf-memory`) via the fn-pointer charge hook this module installs
//! the first time a `memory` cgroup state is created. The allocator
//! calls the hook on every user-facing frame allocation (positive byte
//! delta) and free (negative delta); the hook walks the allocating
//! task's cgroup chain and charges/uncharges every level.
//!
//! # What is enforced vs accounting-only
//!
//! * **`memory.max` — ENFORCED with reclaim + OOM.** A positive charge
//!   that would push any level over its `memory.max` first drives a
//!   best-effort **direct reclaim** pass (`narf_memory::reclaim::
//!   try_to_free`, the allocation-free frame-LRU + shrinker path) sized
//!   to the breach, then re-checks. If a level is still over after
//!   reclaim, the hook asks the OOM policy to kill a task
//!   (`narf_memory::oom::request_oom_relief`) and re-checks once more.
//!   Only if the breach still stands does the hook return `false`, so
//!   `narf-memory`'s `alloc_frame*` / `alloc_pages_on` fail the
//!   allocation (`FrameAllocError::Exhausted` ⇒ ENOMEM to the caller).
//!   The breaching level's `memory.events` `max` counter is bumped, and
//!   `oom` / `oom_kill` are bumped when the OOM path is taken.
//! * **`memory.high` — ENFORCED as a reclaim throttle.** v2 `memory.high`
//!   is a throttle/reclaim trigger, never a hard wall. A positive charge
//!   that would push a level over `high` drives the same best-effort
//!   direct-reclaim pass (`try_to_free`) sized to the over-`high` deficit
//!   before committing, applying back-pressure. Crossing `high` still
//!   bumps the `high` event counter and never denies the charge.
//!
//! ## Reclaim/OOM scope + limitations (first enforcement pass)
//!
//! Both the `high` reclaim throttle and the `max` reclaim step invoke
//! **global** reclaim, not per-cgroup LRU: `try_to_free` reclaims the
//! kernel-wide frame LRU + shrinkers, and it runs in the allocator charge
//! path, so it can only drive the *allocation-free* reclaim arms — it
//! must NOT call `reclaim_anon_pages` (that may allocate; it is kswapd's
//! job). The `max`-breach OOM is **cgroup-scoped**: it collects the member
//! pids of the charging task's cgroup subtree ([`super::oom_candidate_pids`])
//! and calls `request_oom_relief_in`, so `OomKiller::select_victim_in` kills
//! the highest-badness task INSIDE the offending hierarchy (an empty/unkillable
//! subtree fails the charge as ENOMEM rather than reaching outside the cgroup).
//! Follow-ups: (1) a per-cgroup reclaim LRU keyed on the cgroup's resident
//! frames; (2) exact scoping when an ANCESTOR's limit breached (map the
//! breaching MemoryState back to its cgroup) + `memory.oom.group` kill-all.
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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

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
        // Final-owner frame return is reachable from GlobalAlloc's direct-
        // reclaim retry, so this branch must not allocate or it recursively
        // re-enters GlobalAlloc. Walk only an existing membership chain (no
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

    // Positive charging needs a two-phase precheck/commit transaction. Collect
    // the chain's `MemoryState`s once (clone the `Arc`s so we can iterate them
    // twice without holding the chain lock across the closure body). This arm
    // may allocate; it is never entered by final-owner direct reclaim.
    let mut states: Vec<Arc<dyn ControllerState>> = Vec::new();
    super::with_chain_states(pid, "memory", |s| states.push(s.clone()));

    let amount = delta_bytes as u64;

    // High throttle: before committing, drive best-effort direct reclaim
    // sized to the largest over-`memory.high` deficit on the chain. `high`
    // never denies (it is a throttle, not a wall), so we reclaim and then
    // fall through to commit regardless of the result.
    let mut high_deficit = 0u64;
    for s in &states {
        if let Some(m) = s.as_any().downcast_ref::<MemoryState>() {
            high_deficit = high_deficit.max(m.over_high_by(amount));
        }
    }
    if high_deficit != 0 {
        drive_direct_reclaim(high_deficit);
    }

    // Phase 1: pre-check every level against memory.max, driving reclaim
    // (and then a scoped OOM kill) against any breach before denying.
    for s in &states {
        if let Some(m) = s.as_any().downcast_ref::<MemoryState>() {
            if m.can_charge(amount) {
                continue;
            }
            // Best-effort direct reclaim sized to the breach, then re-check.
            drive_direct_reclaim(m.over_max_by(amount));
            if m.can_charge(amount) {
                continue;
            }
            // Still over: ask the OOM policy to kill a task WITHIN this cgroup's
            // subtree — cgroup v2 kills inside the offending hierarchy, not
            // machine-wide — then give the freed frames one more re-check. An
            // empty/unkillable subtree yields `None`, so the charge is failed as
            // ENOMEM rather than reaching outside the cgroup.
            let candidates = super::oom_candidate_pids(pid);
            let killed = narf_memory::oom::request_oom_relief_in(&candidates).is_some();
            if killed {
                m.note_oom_kill_event();
            }
            if m.can_charge(amount) {
                continue;
            }
            // The breach still stands: record it and deny, so the allocator
            // fails the allocation back to the caller as ENOMEM.
            m.note_max_event();
            return false;
        }
    }

    // Phase 2: commit on every level (also notes `high` crossings).
    for s in &states {
        if let Some(m) = s.as_any().downcast_ref::<MemoryState>() {
            m.commit_charge(amount);
        }
    }
    true
}

/// Drive best-effort direct reclaim for a byte `deficit`, from the
/// allocator charge path. Converts the byte deficit to a page target
/// (round up) and calls `narf_memory::reclaim::try_to_free`, the
/// **allocation-free** frame-LRU + shrinker reclaim path. It deliberately
/// does NOT call `reclaim_anon_pages`: that arm may allocate and is
/// reserved for kswapd (kthread) context, whereas this runs inside the
/// re-entrancy-guarded charge hook where allocating could self-deadlock.
/// Reclaim here is global, not per-cgroup (see the module-level scope
/// note). Returns the number of pages freed.
fn drive_direct_reclaim(deficit: u64) -> usize {
    if deficit == 0 {
        return 0;
    }
    let pages = deficit
        .div_ceil(narf_memory::PAGE_SIZE)
        .min(usize::MAX as u64) as usize;
    narf_memory::reclaim::try_to_free(pages)
}

/// Test-only seam: drive the chain-walking [`charge_hook`] directly
/// (the allocator normally invokes it via the installed fn-pointer).
/// Lets the cgroupfs tests exercise the re-entrancy guard and the
/// two-phase `memory.max` enforcement over a real cgroup chain without a
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
        narf_memory::install_cgroup_charge_hook(charge_hook);
        narf_scheduler::install_memory_pid_provider();
    }
}

#[derive(Debug)]
pub struct MemoryController;

impl Controller for MemoryController {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        ensure_hook_installed();
        Arc::new(MemoryState {
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
        })
    }
}

#[derive(Debug)]
pub struct MemoryState {
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

    /// Would charging `amount` more bytes keep this level at or below
    /// `memory.max`? `None` max ⇒ unlimited ⇒ always true.
    fn can_charge(&self, amount: u64) -> bool {
        match *self.max.lock() {
            None => true,
            Some(limit) => {
                let cur = self.current.load(Ordering::Acquire);
                cur.saturating_add(amount) <= limit
            }
        }
    }

    /// Bytes by which charging `amount` more would exceed this level's
    /// `memory.max`, or `0` if it stays at/under `max` (`None` ⇒
    /// unlimited ⇒ `0`). Drives the reclaim target on the enforcement
    /// path.
    fn over_max_by(&self, amount: u64) -> u64 {
        match *self.max.lock() {
            None => 0,
            Some(limit) => self
                .current
                .load(Ordering::Acquire)
                .saturating_add(amount)
                .saturating_sub(limit),
        }
    }

    /// Bytes by which charging `amount` more would exceed this level's
    /// `memory.high`, or `0` if it stays at/under `high` (`None` ⇒
    /// unlimited ⇒ `0`). Drives the reclaim throttle target.
    fn over_high_by(&self, amount: u64) -> u64 {
        match *self.high.lock() {
            None => 0,
            Some(high) => self
                .current
                .load(Ordering::Acquire)
                .saturating_add(amount)
                .saturating_sub(high),
        }
    }

    /// Commit a charge of `amount` bytes: bump `current`, advance
    /// `peak`, and note a `memory.high` crossing if one occurs.
    fn commit_charge(&self, amount: u64) {
        let now = self.current.fetch_add(amount, Ordering::AcqRel) + amount;
        self.peak.fetch_max(now, Ordering::AcqRel);
        if let Some(high) = *self.high.lock() {
            if now > high {
                // high is a throttle, not a wall: record only.
                self.events_high.fetch_add(1, Ordering::Relaxed);
            }
        }
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
    /// `memory.max` — i.e. reclaim (and any OOM kill) could not make room.
    /// Bumps `max` (limit hit) and `oom` (the allocation is failed back to
    /// the caller as an OOM). `oom_kill` is bumped separately, only when a
    /// task was actually killed (see [`note_oom_kill_event`]).
    fn note_max_event(&self) {
        self.events_max.fetch_add(1, Ordering::Relaxed);
        self.events_oom.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that the `memory.max` enforcement path killed a task to try
    /// to relieve the breach. Bumps `oom_kill`, matching v2 where the
    /// counter tracks kills attributed to the cgroup's pressure.
    fn note_oom_kill_event(&self) {
        self.events_oom_kill.fetch_add(1, Ordering::Relaxed);
    }

    /// Charge (`delta > 0`) or uncharge (`delta < 0`) this single level,
    /// enforcing `memory.max` on a positive delta. Returns `false` iff a
    /// positive delta is rejected for exceeding `max`. Exposed for tests
    /// and direct accounting; the allocator hook drives the chain-wide
    /// two-phase path in `charge_hook`.
    pub fn charge(&self, delta: i64) -> bool {
        if delta < 0 {
            self.uncharge(delta.unsigned_abs());
            return true;
        }
        let amount = delta as u64;
        if !self.can_charge(amount) {
            self.note_max_event();
            return false;
        }
        self.commit_charge(amount);
        true
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
