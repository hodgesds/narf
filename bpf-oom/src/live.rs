//! The live candidate source: real tasks, real signals.
//!
//! This is the half of the policy a BPF program cannot express — walking the
//! task list, resolving each task's address space, reading its `oom_score_adj`,
//! and queuing the SIGKILL. It is a near-transcription of
//! `narf_userspace::oom::ProcessOomKiller::select_victim`'s *enumeration*, with
//! the ranking lifted out into [`crate::policy`] where a program can supply it.
//! Keeping the eligibility filter here (rather than exposing every task and
//! trusting the program to skip `init`) means no program set — buggy, hostile,
//! or merely empty — can select a candidate the in-tree policy would have
//! refused to consider.

use alloc::vec::Vec;

use narf_scheduler::TaskId;

use crate::policy::{register_candidate_source, CandidateSource, OomCandidate};

/// Uncatchable kill signal.
const SIGKILL: u32 = 9;

/// Bytes per base page, for the `mapped_bytes` → resident-pages conversion.
const PAGE_SIZE: u64 = 4096;

/// The live system as a candidate source.
#[derive(Debug)]
pub struct LiveTasks;

static LIVE_TASKS: LiveTasks = LiveTasks;

impl CandidateSource for LiveTasks {
    fn candidates(&self) -> Vec<OomCandidate> {
        let mut out = Vec::new();
        for (tid, pid) in narf_userspace::task::snapshot_identities() {
            // Never target init (pid 1) or kernel identities (pid 0).
            if pid <= 1 {
                continue;
            }
            // Only user processes have an address space to reclaim; a kernel
            // task (or an already-reaped zombie off the ready queue) resolves
            // to None and is skipped.
            let Some(address_space) = narf_scheduler::address_space_of(TaskId(tid)) else {
                continue;
            };
            // One walk of the region tables, not three: `mapped_bytes()` is
            // `memory_stats().mapped_bytes`, so taking the whole stat block
            // costs nothing extra and fills the rest of the candidate.
            let stats = address_space.memory_stats();
            let rss_pages = stats.mapped_bytes / PAGE_SIZE;
            if rss_pages == 0 {
                continue;
            }
            out.push(OomCandidate {
                pid,
                tid,
                rss_pages,
                oom_score_adj: i64::from(narf_userspace::handlers::proc_oom_adj_of(pid)),
                mapped_bytes: stats.mapped_bytes,
                resident_pages: stats.resident_pages,
                writable_nonexec_bytes: stats.writable_nonexec_bytes,
                address_space,
            });
        }
        out
    }

    fn total_pages(&self) -> u64 {
        // Clamped so a program may divide by it, per the trait contract.
        (narf_memory::frame::stats().total as u64).max(1)
    }

    fn kill(&self, tid: u64) {
        // Uncatchable: the victim exits at its next return-to-user, and the
        // async reaper reclaims its anonymous frames without waiting for that.
        narf_userspace::handlers::raise_signal_pending(tid, SIGKILL);
    }
}

/// Install the live source. Called from [`crate::register_initcalls`].
pub fn install() {
    register_candidate_source(&LIVE_TASKS);
}
