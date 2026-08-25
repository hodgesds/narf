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
//! * **`memory.max` — ENFORCED without inline reclaim.** A positive charge
//!   that would push any level over its `memory.max` publishes a capped,
//!   coalesced background-reclaim request and returns `false`, so
//!   `narf-memory`'s `alloc_frame*` / `alloc_pages_on` fail the
//!   allocation with `FrameAllocError::Exhausted`. Fallible callers such as
//!   BPF map creation preserve that as ENOMEM.
//!   The breaching level's `memory.events` `max` counter is bumped. `oom` and
//!   `oom_kill` remain unchanged because OOM selection is deliberately not run
//!   from this arbitrary allocator/lock context.
//! * **`memory.high` — deferred reclaim trigger.** v2 `memory.high` is a
//!   throttle/reclaim trigger, never a hard wall. A positive charge that
//!   would push a level over `high` publishes the same kind of background
//!   request, commits the charge, and bumps the `high` event counter.
//!
//! ## Reclaim/OOM scope + limitations (first enforcement pass)
//!
//! Background work currently enters the global kswapd reclaim engines rather
//! than a per-cgroup LRU. It is never OOM-authorized: a memcg breach must not
//! select a machine-wide victim. Full deferred `memory.high` throttling and
//! scoped `memory.max` reclaim/OOM require stable per-allocation cgroup
//! ownership plus a cgroup-keyed worker; current uncharge attribution is only
//! best-effort when a page is freed by a different task.
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
