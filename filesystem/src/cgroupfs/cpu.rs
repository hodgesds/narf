//! `cpu` controller — CPU weight + bandwidth.
//!
//! Presents the v2 cpu interface and pushes `cpu.weight` /
//! `cpu.weight.nice` onto member tasks as a scheduler `Priority`
//! through the `narf-scheduler` cgroup hook. Tracks the pids attached
//! at this cgroup level so a tunable write re-applies to every current
//! member.
//!
//! ## REAL vs accepted-but-not-enforced
//!
//! - **`cpu.weight` / `cpu.weight.nice`**: mapped weight→nice→
//!   `Priority` and pushed to member tasks via
//!   `narf_scheduler::cgroup_set_priority`. Whether priority reorders
//!   dispatch is scheduler-policy-dependent (REAL under
//!   `PriorityScheduler`, carried-but-inert under the default FIFO
//!   policy) — see `scheduler/src/cgroup.rs` module docs.
//! - **`cpu.max` (quota/period)**: ACCEPTED AND REPORTED BUT NOT
//!   ENFORCED. The NARF executor is cooperative and exposes no
//!   preemptive bandwidth-throttle seam, so there is nothing to push a
//!   quota onto. The value round-trips through read/write so userspace
//!   tooling that sets and reads it back sees consistent state; no
//!   task is actually throttled. `cpu.stat`'s `nr_throttled` /
//!   `throttled_usec` are therefore always zero.
//! - **`cpu.stat` `usage_usec`**: REAL (best-effort) — summed from the
//!   scheduler's per-task measured cycles for current members. See
//!   `cgroup_cycles_for`. `user_usec` / `system_usec` are not split
//!   out (the executor does not track the user/kernel boundary per
//!   task) and report zero with this comment.
//!
//! Linux ref: `kernel/sched/core.c` (cgroup hooks),
//! `Documentation/admin-guide/cgroup-v2.rst` §"CPU".

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "cpu.stat",
    "cpu.weight",
    "cpu.weight.nice",
    "cpu.max",
    "cpu.max.burst",
    "cpu.idle",
];

/// Cycles → microseconds. The scheduler measures poll time in
/// `narf_time` cycles; convert at read time for `cpu.stat`. Until a
/// calibrated cycles-per-µs is plumbed through, treat 1 cycle ≈ 1 ns
/// (TSC-like) and divide by 1000. This is an ACCOUNTING APPROXIMATION,
/// not a calibrated figure — see the note on `cpu.stat` REAL-ness.
#[cfg(feature = "cgroup")]
const CYCLES_PER_USEC: u64 = 1000;

/// Ensure the scheduler-side apply hooks are installed exactly once.
/// Lazy install from `new_state` avoids any external boot wiring.
#[cfg(feature = "cgroup")]
fn ensure_hooks() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        narf_scheduler::install_cgroup_cpu_hook(narf_scheduler::apply_priority);
    }
}

#[cfg(not(feature = "cgroup"))]
fn ensure_hooks() {}

#[derive(Debug)]
pub struct CpuController;

impl Controller for CpuController {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        ensure_hooks();
        Arc::new(CpuState {
            weight: IrqSafeSpinLock::new(100),
            // `cpu.max`: (quota, period); None quota = "max".
            quota: IrqSafeSpinLock::new(None),
            period: IrqSafeSpinLock::new(100_000),
            burst: IrqSafeSpinLock::new(0),
            idle: IrqSafeSpinLock::new(0),
            members: IrqSafeSpinLock::new(BTreeSet::new()),
        })
    }
}

#[derive(Debug)]
pub struct CpuState {
    weight: IrqSafeSpinLock<u64>,
    quota: IrqSafeSpinLock<Option<u64>>,
    period: IrqSafeSpinLock<u64>,
    burst: IrqSafeSpinLock<u64>,
    idle: IrqSafeSpinLock<u64>,
    /// Pids attached at this cgroup level. A `cpu.weight` write
    /// re-applies the derived priority to each of these.
    members: IrqSafeSpinLock<BTreeSet<u64>>,
}

/// `cpu.weight` (1..=10000) → nice (-20..=19). Default weight 100 ↔
/// nice 0. Coarse inverse of the kernel's `sched_prio_to_weight`
/// table, monotonic across the full range.
fn weight_to_nice(weight: u64) -> i64 {
    let w = weight.clamp(1, 10000) as i64;
    (((10000 - w) * 39) / 9999) - 20
}

/// nice (-20..=19) → `cpu.weight` (1..=10000). Inverse of
/// [`weight_to_nice`] for the `cpu.weight.nice` write path. Nice 0 ↔
/// weight 100 is preserved as the anchor (Linux's default).
fn nice_to_weight(nice: i64) -> u64 {
    let n = nice.clamp(-20, 19);
    // Anchor the default: nice 0 must map back to weight 100.
    if n == 0 {
        return 100;
    }
    // Linear inverse over the same span used by `weight_to_nice`.
    let w = 10000 - ((n + 20) * 9999) / 39;
    w.clamp(1, 10000) as u64
}

impl CpuState {
    /// Push the current weight's derived priority to every member.
    /// No-op (and cheap) when the cgroup has no members.
    fn reapply_priority(&self) {
        let nice = weight_to_nice(*self.weight.lock());
        // `Priority` is an `i8`; the v2 nice range (-20..=19) fits.
        let nice_i8 = nice.clamp(i8::MIN as i64, i8::MAX as i64) as i8;
        let members: Vec<u64> = self.members.lock().iter().copied().collect();
        for pid in members {
            push_priority(pid, nice_i8);
        }
    }
}

#[cfg(feature = "cgroup")]
fn push_priority(pid: u64, nice: i8) {
    let _ = narf_scheduler::cgroup_set_priority(pid, nice);
}

#[cfg(not(feature = "cgroup"))]
fn push_priority(_pid: u64, _nice: i8) {}

#[cfg(feature = "cgroup")]
fn usage_usec(members: &[u64]) -> u64 {
    narf_scheduler::cgroup_cycles_for(members) / CYCLES_PER_USEC
}

#[cfg(not(feature = "cgroup"))]
fn usage_usec(_members: &[u64]) -> u64 {
    0
}

/// Aggregate scheduler usage for an arbitrary pid set — the data
/// source for the core base `cpu.stat` (present on cgroups where the
/// cpu controller is not enabled; see `render_cpu_stat_base`).
pub(super) fn members_usage_usec(pids: &[u64]) -> u64 {
    usage_usec(pids)
}

impl ControllerState for CpuState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "cpu.stat" => {
                let members: Vec<u64> = self.members.lock().iter().copied().collect();
                let usage = usage_usec(&members);
                // user_usec/system_usec: the cooperative executor does
                // not split per-task user vs kernel cycles, so report
                // the total under usage_usec and leave the split at 0.
                // nr_throttled/throttled_usec: cpu.max is not enforced
                // (no preemptive throttle seam), so always 0.
                format!(
                    "usage_usec {usage}\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n"
                )
            }
            "cpu.weight" => format!("{}\n", *self.weight.lock()),
            "cpu.weight.nice" => format!("{}\n", weight_to_nice(*self.weight.lock())),
            "cpu.max" => {
                let q = self.quota.lock();
                let p = *self.period.lock();
                match *q {
                    None => format!("max {p}\n"),
                    Some(quota) => format!("{quota} {p}\n"),
                }
            }
            "cpu.max.burst" => format!("{}\n", *self.burst.lock()),
            "cpu.idle" => format!("{}\n", *self.idle.lock()),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        match file {
            "cpu.weight" => {
                let w = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                if !(1..=10000).contains(&w) {
                    return Err(FsError::InvalidData);
                }
                *self.weight.lock() = w;
                self.reapply_priority();
                Ok(())
            }
            "cpu.weight.nice" => {
                let n = text.parse::<i64>().map_err(|_| FsError::InvalidData)?;
                if !(-20..=19).contains(&n) {
                    return Err(FsError::InvalidData);
                }
                *self.weight.lock() = nice_to_weight(n);
                self.reapply_priority();
                Ok(())
            }
            "cpu.max" => {
                // "<quota|max> [period]"
                let mut parts = text.split_whitespace();
                let quota = parts.next().ok_or(FsError::InvalidData)?;
                if let Some(p) = parts.next() {
                    *self.period.lock() = p.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                }
                *self.quota.lock() = if quota == "max" {
                    None
                } else {
                    Some(quota.parse::<u64>().map_err(|_| FsError::InvalidData)?)
                };
                // NOTE: cpu.max is accepted and round-trips through
                // read, but the cooperative executor has no throttle
                // seam, so no member task is actually bandwidth-capped.
                Ok(())
            }
            "cpu.max.burst" => {
                *self.burst.lock() = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                Ok(())
            }
            "cpu.idle" => {
                *self.idle.lock() = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(
            file,
            "cpu.weight" | "cpu.weight.nice" | "cpu.max" | "cpu.max.burst" | "cpu.idle"
        )
    }

    fn on_attach(&self, pid: u64) {
        self.members.lock().insert(pid);
        // Apply this cgroup's current weight to the joining task.
        let nice = weight_to_nice(*self.weight.lock());
        let nice_i8 = nice.clamp(i8::MIN as i64, i8::MAX as i64) as i8;
        push_priority(pid, nice_i8);
    }

    fn on_detach(&self, pid: u64) {
        self.members.lock().remove(&pid);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
