//! Process OOM-kill policy — the userspace half of `narf_memory::oom`.
//!
//! `memory` defines the [`OomKiller`](narf_memory::oom::OomKiller) trait but
//! cannot enumerate tasks or deliver signals. This module supplies a
//! Linux-shaped policy (highest badness = resident pages plus an
//! `oom_score_adj` bias) and installs it at boot with
//! [`install`]. An out-of-tree crate could register a different policy the same
//! way.

use alloc::sync::Arc;

use narf_memory::address_space::AddressSpace;
use narf_memory::oom::{OomKiller, OomVictim};
use narf_scheduler::TaskId;

/// `oom_score_adj` sentinel meaning "never OOM-kill this task" (Linux
/// `OOM_SCORE_ADJ_MIN`).
const OOM_SCORE_ADJ_MIN: i16 = -1000;

/// Uncatchable kill signal.
const SIGKILL: u32 = 9;

/// The default NARF OOM policy: pick the resident user process with the
/// greatest badness and SIGKILL it.
struct ProcessOomKiller;

static PROCESS_OOM_KILLER: ProcessOomKiller = ProcessOomKiller;

impl OomKiller for ProcessOomKiller {
    fn select_victim(&self) -> Option<OomVictim> {
        let total_pages = narf_memory::frame::stats().total.max(1) as i64;
        let mut best: Option<(u64, u64, usize, i64, Arc<AddressSpace>)> = None;

        for (tid, pid) in crate::task::snapshot_identities() {
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
            let rss_pages = (address_space.mapped_bytes() / 4096) as usize;
            if rss_pages == 0 {
                continue;
            }
            let adj = crate::handlers::proc_oom_adj_of(pid);
            if adj <= OOM_SCORE_ADJ_MIN {
                continue; // opted out of the OOM killer
            }
            // Linux-shaped badness: resident pages, biased by oom_score_adj
            // scaled against total RAM. Higher wins.
            let badness = rss_pages as i64 + total_pages * adj as i64 / 1000;
            if best.as_ref().is_none_or(|b| badness > b.3) {
                best = Some((tid, pid, rss_pages, badness, address_space));
            }
        }

        let (tid, pid, rss_pages, _badness, address_space) = best?;
        // Deliver an uncatchable SIGKILL; the victim exits at its next
        // return-to-user, and the async reaper reclaims its anonymous frames
        // now rather than waiting for that exit.
        crate::handlers::raise_signal_pending(tid, SIGKILL);
        Some(OomVictim {
            pid,
            tid,
            rss_pages,
            address_space,
        })
    }
}

/// Install the default process OOM policy into the memory crate. Call once at
/// boot, before user tasks run.
pub fn install() {
    narf_memory::oom::register_oom_killer(&PROCESS_OOM_KILLER);
}
