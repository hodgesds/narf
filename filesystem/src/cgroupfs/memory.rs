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
//! * **`memory.max` — ENFORCED.** A positive charge that would push any
//!   level over its `memory.max` is rejected: the hook returns `false`,
//!   and `narf-memory`'s `alloc_frame*` / `alloc_pages_on` fail the
//!   allocation (returning `FrameAllocError::Exhausted`). The breaching
//!   level's `memory.events` `max` counter is bumped, and `oom` /
//!   `oom_kill` are bumped to record that the allocation was refused.
//!   (NARF has no OOM-killer task-reaper yet; we record the OOM event
//!   but do not actually kill a task — the allocation simply fails,
//!   which the caller surfaces as ENOMEM. This is honest v2 semantics
//!   for `memory.oom.group` unset.)
//! * **`memory.high` — ACCOUNTING-ONLY.** v2 `memory.high` is a
//!   throttle/reclaim trigger, never a hard wall. We have no reclaim
//!   path here, so crossing `high` bumps the `high` event counter for
//!   visibility but never denies the charge.
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
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

/// The charge hook `narf-memory` calls on every user-facing frame
/// allocation (`delta_bytes > 0`) and free (`delta_bytes < 0`).
///
/// Returns `true` if the (positive) charge is allowed, `false` if it
/// would push some level over its `memory.max` — in which case the
/// allocation is denied. Negative deltas always return `true`.
///
/// Two-phase for positive deltas: pre-check every level against its
/// `max` (charging nothing), and only commit if all levels pass, so a
/// rejected allocation leaves accounting untouched.
fn charge_hook(pid: u64, delta_bytes: i64) -> bool {
    // Collect the chain's `MemoryState`s once (clone the `Arc`s so we
    // can iterate them twice without holding the chain lock across the
    // closure body).
    let mut states: Vec<Arc<dyn ControllerState>> = Vec::new();
    super::with_chain_states(pid, "memory", |s| states.push(s.clone()));

    if delta_bytes < 0 {
        let amount = delta_bytes.unsigned_abs();
        for s in &states {
            if let Some(m) = s.as_any().downcast_ref::<MemoryState>() {
                m.uncharge(amount);
            }
        }
        return true;
    }

    let amount = delta_bytes as u64;

    // Phase 1: pre-check every level against memory.max.
    for s in &states {
        if let Some(m) = s.as_any().downcast_ref::<MemoryState>() {
            if !m.can_charge(amount) {
                // Record the breach on the level that rejected it. No
                // level has been charged yet, so this is consistent.
                m.note_max_event();
                return false;
            }
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

    /// Record that a charge was rejected for exceeding `memory.max`.
    /// Bumps `max`, and — since the allocation is failed outright (no
    /// reclaim, no task-reaper) — `oom` and `oom_kill` too, mirroring
    /// the v2 path where an unrecoverable `max` breach is an OOM.
    fn note_max_event(&self) {
        self.events_max.fetch_add(1, Ordering::Relaxed);
        self.events_oom.fetch_add(1, Ordering::Relaxed);
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
            "memory.min" => format!("{}\n", *self.min.lock()),
            "memory.low" => format!("{}\n", *self.low.lock()),
            "memory.high" => max_line(&self.high.lock()),
            "memory.max" => max_line(&self.max.lock()),
            "memory.swap.current" => format!("{}\n", self.swap_current.load(Ordering::Acquire)),
            "memory.swap.max" => max_line(&self.swap_max.lock()),
            "memory.oom.group" => format!("{}\n", u8::from(self.oom_group.load(Ordering::Acquire))),
            // memory.reclaim is write-only on Linux (0200); render
            // empty for a read that slips through.
            "memory.reclaim" => String::new(),
            "memory.zswap.current" => format!("{}\n", self.zswap_current.load(Ordering::Acquire)),
            "memory.zswap.max" => max_line(&self.zswap_max.lock()),
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
