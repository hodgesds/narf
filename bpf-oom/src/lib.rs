//! `narf-bpf-oom` — BPF-supplied OOM victim selection.
//!
//! A `struct_ops` consumer in the shape `narf-bpf-idle` established: the macro
//! emits the [`BpfOomPolicy`] trait, the [`BpfOomPolicyOps`] adapter that runs
//! the bound programs, and the cap-gated [`install_bpf_oom_policy`] entry; a
//! `#[commit(...)]` committer moves the verified adapter into this crate's live
//! slot and hands `narf-memory` an [`OomKiller`](narf_memory::oom::OomKiller)
//! that dispatches through it. `memory` learns nothing about BPF; BPF learns
//! nothing about the task list. This crate is the only place the two meet.
//!
//! # What is programmable, and what is not
//!
//! Only the **ranking**. `narf_memory::oom::OomKiller::select_victim` has to
//! enumerate tasks, resolve address spaces, and deliver a signal — all of which
//! need allocation, locks, and pointers no verified program may hold. So this
//! crate enumerates candidates natively (`live`), asks the program set to score
//! each one over scalars, and does the killing itself. The blast radius of a
//! hostile or broken program is therefore bounded to *which* eligible task
//! dies, never *whether* the kill is legal: `init`, kernel tasks, and tasks
//! with no resident memory are filtered out before a program sees them, and a
//! program that traps, declines every candidate, or is never bound falls back
//! to the same Linux-shaped badness `narf_userspace::oom` computes — so no
//! program can turn the OOM killer *off*. See
//! [`policy::native_fallback_count`].
//!
//! # Loading a policy
//!
//! ```ignore
//! let cap = narf_bpf_oom::bootstrap_oom_policy_authority();
//! let set = ProgSet::new()
//!     .with("badness", biggest_rss_prog)      // required
//!     .with("veto", spare_the_database_prog); // optional
//! narf_bpf_oom::install_bpf_oom_policy(&cap, set)?;
//! ```
//!
//! Any number of program sets can be swapped in over a boot; the last install
//! wins, and [`clear_policy`](policy::clear_policy) drops back to native
//! badness.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::sync::Arc;

use narf_capabilities::{Cap, CapKind, CapType, Grant};

pub mod live;
pub mod policy;

pub use policy::{
    clear_policy, has_candidate_source, native_fallback_count, policy_installed,
    register_candidate_source, CandidateSource, OomCandidate, OOM_SCORE_ADJ_MIN,
};

/// Authority to install an OOM victim-selection policy.
///
/// The marker for `CapKind::OomPolicy` (0x020A), reserved per
/// `docs/PLUGGABILITY.md`. It lives here rather than in `memory` because
/// `memory`'s own `register_oom_killer` seam is deliberately uncapped — it is
/// called once at boot by the in-tree policy, from inside the kernel, before
/// user tasks run. This crate is what makes the slot reachable at *runtime*,
/// by a program, and that is the authority worth naming.
#[derive(Copy, Clone, Debug)]
pub struct OomPolicy;

impl CapType for OomPolicy {
    const KIND: CapKind = CapKind::OomPolicy;
}

/// Mint the root OOM-policy authority.
///
/// Mirrors `narf_power::bootstrap_idle_governor_authority`: boot-time plumbing
/// derives grants from this rather than re-bootstrapping, since each call
/// allocates an object-table slot.
#[must_use]
pub fn bootstrap_oom_policy_authority() -> Cap<OomPolicy, Grant> {
    Cap::<OomPolicy, Grant>::bootstrap()
}

narf_bpf_structops::struct_ops! {
    /// A BPF-supplied OOM victim-selection policy.
    ///
    /// Called from `memory`'s pressure path in atomic context: `badness` and
    /// `veto` once per *candidate*, `notify_kill` once per *selection*. The
    /// context tuple is scalars only — there is no task pointer to chase and
    /// nothing to `probe_read`, which is what lets the whole policy run under
    /// `run_atomic` with no mediation.
    #[cap(OomPolicy)]
    #[install(install_bpf_oom_policy)]
    #[desc(BPF_OOM_POLICY_OPS)]
    #[adapter(BpfOomPolicyOps)]
    #[commit(commit_bpf_oom_policy)]
    #[optional(veto, notify_kill)]
    pub trait BpfOomPolicy {
        /// Score a candidate. **Higher is killed first; `0` declines to rank
        /// it.** `total_pages` is the machine's frame count, so a program can
        /// scale `oom_score_adj` against RAM the way Linux's `oom_badness()`
        /// does.
        ///
        /// `0` is a *soft* exclusion. If a program declines every candidate —
        /// which is also what a program that traps looks like, since both
        /// produce `DEFAULT_RET` — selection falls back to native badness over
        /// the candidates this policy did not veto, rather than killing
        /// nothing. Otherwise one buggy program would silently disable the OOM
        /// killer and wedge the machine under pressure. Use [`veto`](Self::veto)
        /// for an exclusion that must hold unconditionally.
        ///
        /// Required: a set without it is rejected at install, because a policy
        /// that cannot rank is not a policy.
        fn badness(&self, pid: u64, rss_pages: u64, oom_score_adj: i64, total_pages: u64) -> u64;

        /// Exclude a candidate from consideration: **nonzero vetoes.**
        ///
        /// A *hard* exclusion — unlike a `badness` of 0, a veto survives the
        /// native fallback, so a policy protecting a particular process keeps
        /// protecting it even when the rest of its ranking misfires.
        ///
        /// Phrased as a veto, not an eligibility test, because an unbound
        /// optional method returns `BpfRet::DEFAULT_RET` — `0`. As a veto that
        /// reads "nothing excluded", which is the safe default; as an
        /// eligibility test it would read "nothing eligible" and exclude every
        /// candidate the moment a program set omitted the method.
        fn veto(&self, pid: u64, rss_pages: u64, oom_score_adj: i64) -> u32;

        /// Told which candidate the policy cost, after the kill is initiated.
        ///
        /// For a program keeping its own accounting in a map. The return value
        /// is ignored — by the time this runs the victim is already terminal,
        /// so a program that traps here cannot un-kill anything.
        fn notify_kill(&self, pid: u64, rss_pages: u64) -> i32;
    }
}

/// The committer named by `#[commit(...)]`: bind the verified adapter as the
/// live ranking and take over `memory`'s OOM slot.
///
/// Generic over the cap marker because the generated install fn is; the
/// struct_ops layer has already proved the cap's kind is `OomPolicy` and the
/// set well-formed before this runs, so the only checks left are the
/// last-moment liveness re-check every native install point performs, and the
/// one precondition struct_ops cannot know about: a candidate source must be
/// registered. Committing without one would install a killer that can never
/// find a victim — the OOM killer would look armed and do nothing — so that is
/// refused here rather than discovered under pressure.
fn commit_bpf_oom_policy<M: CapType>(
    cap: &Cap<M, Grant>,
    adapter: BpfOomPolicyOps,
) -> Result<(), narf_bpf_structops::StructOpsError> {
    cap.check_live()?;
    if !policy::has_candidate_source() {
        return Err(narf_bpf_structops::StructOpsError::CommitFailed(
            "no OOM candidate source registered",
        ));
    }
    policy::install_policy(Arc::new(adapter));
    Ok(())
}

/// Force-link anchor + live-source install.
///
/// No policy is installed at boot — a BPF program installs one at runtime via
/// [`install_bpf_oom_policy`], and until then `narf_userspace::oom`'s in-tree
/// policy stays in `memory`'s slot untouched. This entry registers the live
/// candidate source so an install *can* succeed later, and touches the
/// descriptor so `frame` (under the `bpf-oom` feature) and `verification` keep
/// this crate's `narf.structops` entry and its smokes from being dropped at
/// link (`codegen-units > 1`).
pub fn register_initcalls() {
    live::install();
    let _ = &BPF_OOM_POLICY_OPS;
}

#[cfg(feature = "kernel-test")]
mod tests;
