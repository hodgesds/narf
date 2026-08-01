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

/// Linux's `sched_prio_to_weight` load-weight table, indexed by
/// `nice + 20` (nice -20..=19). `cpu.weight` is derived from this via
/// the same scaling the kernel uses, so nice 0 (index 20, weight 1024)
/// maps to the default `cpu.weight` 100. Ref: `kernel/sched/core.c`.
const SCHED_PRIO_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, // -20..-16
    29154, 23254, 18705, 14949, 11916, // -15..-11
    9548, 7620, 6100, 4904, 3906, // -10..-6
    3121, 2501, 1991, 1586, 1277, // -5..-1
    1024, 820, 655, 526, 423, // 0..4
    335, 272, 215, 172, 137, // 5..9
    110, 87, 70, 56, 45, // 10..14
    36, 29, 23, 18, 15, // 15..19
];

/// `cpu.weight` (1..=10000) → nice (-20..=19). Finds the nice level
/// whose derived `cpu.weight` is closest to the requested value. Nice 0
/// ↔ weight 100 is the anchor; the mapping is a true inverse of
/// [`nice_to_weight`] at every table point.
fn weight_to_nice(weight: u64) -> i64 {
    let w = weight.clamp(1, 10000);
    let mut best = 0i64;
    let mut best_diff = u64::MAX;
    for (i, _) in SCHED_PRIO_TO_WEIGHT.iter().enumerate() {
        let cw = nice_to_weight(i as i64 - 20);
        let diff = cw.abs_diff(w);
        if diff < best_diff {
            best_diff = diff;
            best = i as i64 - 20;
        }
    }
    best
}

/// nice (-20..=19) → `cpu.weight` (1..=10000). Scales the scheduler
/// load-weight so nice 0 ↔ weight 100 (Linux's default), matching the
/// kernel's `cpu.weight` presentation.
fn nice_to_weight(nice: i64) -> u64 {
    let n = nice.clamp(-20, 19);
    let load = SCHED_PRIO_TO_WEIGHT[(n + 20) as usize];
    // Scale so the nice-0 load (1024) presents as cpu.weight 100, with
    // round-to-nearest; clamp into the valid 1..=10000 range.
    ((load * 100 + 512) / 1024).clamp(1, 10000)
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
                let quota_text = parts.next().ok_or(FsError::InvalidData)?;
                let period = match parts.next() {
                    Some(period) => period.parse::<u64>().map_err(|_| FsError::InvalidData)?,
                    None => *self.period.lock(),
                };
                if parts.next().is_some() || !(1_000..=1_000_000).contains(&period) {
                    return Err(FsError::InvalidData);
                }
                let quota = if quota_text == "max" {
                    None
                } else {
                    let quota = quota_text
                        .parse::<u64>()
                        .map_err(|_| FsError::InvalidData)?;
                    if quota < 1_000 || *self.burst.lock() > quota {
                        return Err(FsError::InvalidData);
                    }
                    Some(quota)
                };
                // Commit only after the complete line validates.
                *self.period.lock() = period;
                *self.quota.lock() = quota;
                // NOTE: cpu.max is accepted and round-trips through
                // read, but the cooperative executor has no throttle
                // seam, so no member task is actually bandwidth-capped.
                Ok(())
            }
            "cpu.max.burst" => {
                let burst = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                if self.quota.lock().is_some_and(|quota| burst > quota) {
                    return Err(FsError::InvalidData);
                }
                *self.burst.lock() = burst;
                Ok(())
            }
            "cpu.idle" => {
                let idle = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                if idle > 1 {
                    return Err(FsError::InvalidData);
                }
                *self.idle.lock() = idle;
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
