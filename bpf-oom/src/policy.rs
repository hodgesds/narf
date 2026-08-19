//! Candidate enumeration, scoring, and the [`OomKiller`] the BPF policy drives.
//!
//! The split this module draws is the one that makes a BPF OOM policy possible
//! at all: **enumeration and killing stay in Rust; only the ranking is
//! programmable.** A BPF program cannot walk the task list, resolve an address
//! space, or queue a signal — those need allocation, locks, and pointers no
//! verified program may hold. What it *can* do is answer "how bad is this
//! candidate?" over a handful of scalars, in atomic context, in bounded time.
//! So the scoring loop below enumerates candidates natively, asks the installed
//! program set for a score per candidate, and does the killing itself.
//!
//! # Why a [`CandidateSource`] indirection
//!
//! The live source is backed by `narf-userspace` + `narf-scheduler` (see
//! [`live`](crate::live)). It is a trait rather than a direct call for two
//! reasons: the smokes must be able to score synthetic candidates without
//! SIGKILLing a real task (an in-kernel test suite that can kill the shell it
//! runs under is not a test suite), and an out-of-tree crate with a different
//! notion of "candidate" — a container runtime scoring cgroups, say — can
//! supply its own without patching this one.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::address_space::AddressSpace;
use narf_memory::oom::{OomKiller, OomVictim};

use crate::BpfOomPolicy;

/// `oom_score_adj` sentinel meaning "never OOM-kill this task" (Linux
/// `OOM_SCORE_ADJ_MIN`), honoured by the native fallback exactly as
/// `narf_userspace::oom` honours it.
pub const OOM_SCORE_ADJ_MIN: i64 = -1000;

/// One task the policy may rank, as the scoring loop sees it.
///
/// A source only ever yields *killable* candidates — a kernel task, `init`, or
/// a task with no resident anonymous memory is filtered out before it gets
/// here, so neither the native fallback nor a BPF program can select one by
/// accident.
pub struct OomCandidate {
    /// Process id.
    pub pid: u64,
    /// Thread id the kill is delivered to.
    pub tid: u64,
    /// Resident pages, the dominant term in Linux-shaped badness.
    pub rss_pages: u64,
    /// The task's `oom_score_adj` bias, `-1000..=1000`.
    pub oom_score_adj: i64,
    /// The address space the reaper reclaims. Held as an `Arc` so pinning the
    /// victim for [`OomVictim`] is a refcount bump, not a lookup that could
    /// race the task's exit.
    pub address_space: Arc<AddressSpace>,
}

impl core::fmt::Debug for OomCandidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `AddressSpace` is not `Debug`; report identity + size instead, as
        // `OomVictim` does.
        f.debug_struct("OomCandidate")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("rss_pages", &self.rss_pages)
            .field("oom_score_adj", &self.oom_score_adj)
            .finish_non_exhaustive()
    }
}

/// Where candidates come from and how a chosen one is killed.
///
/// Implemented once for the live system (`crate::live`) and once per test that
/// needs synthetic candidates.
pub trait CandidateSource: Send + Sync {
    /// Snapshot the killable tasks. Returning an empty `Vec` means "nothing is
    /// eligible", which the killer reports as `None` — the same answer the
    /// in-tree policy gives when only kernel tasks remain.
    fn candidates(&self) -> Vec<OomCandidate>;

    /// Total frames in the machine, so a program can scale `oom_score_adj`
    /// against RAM the way Linux's `oom_badness()` does. Never 0 (the live
    /// source clamps), so a program may divide by it.
    fn total_pages(&self) -> u64;

    /// Initiate the chosen victim's death. The reaper reclaims its frames
    /// asynchronously; this call only has to make the task terminal.
    fn kill(&self, tid: u64);
}

static SOURCE: IrqSafeSpinLock<Option<&'static dyn CandidateSource>> = IrqSafeSpinLock::new(None);

/// The live policy: `None` means no program set is bound and the native
/// fallback ranks candidates.
///
/// `Arc` rather than `Box` so the scoring loop can clone the handle out and
/// drop this lock *before* running any BPF program. A program that re-entered
/// this module while the lock was held — a kfunc that allocates and trips
/// pressure, say — would deadlock against itself; cloning first makes that
/// unrepresentable rather than merely unlikely.
static LIVE: IrqSafeSpinLock<Option<Arc<dyn BpfOomPolicy>>> = IrqSafeSpinLock::new(None);

/// Install the source of killable candidates. Last registration wins;
/// [`crate::register_initcalls`] installs the live one at boot.
pub fn register_candidate_source(source: &'static dyn CandidateSource) {
    *SOURCE.lock() = Some(source);
}

/// Whether a candidate source is installed.
///
/// The committer checks this: installing a program set with no source would
/// register a killer that can never find a victim, silently *disabling* the
/// OOM killer for the rest of the boot. That failure mode is worse than the
/// policy not installing at all, so it is refused rather than reported later.
#[must_use]
pub fn has_candidate_source() -> bool {
    SOURCE.lock().is_some()
}

/// The BPF-driven OOM policy, as `memory` sees it.
///
/// One static instance, registered with `memory` the first time a program set
/// commits. With no set bound it ranks candidates by the same Linux-shaped
/// badness the in-tree policy uses, so [`clear_policy`] leaves a working OOM
/// killer behind rather than a hole.
#[derive(Debug)]
struct BpfOomKiller;

static BPF_OOM_KILLER: BpfOomKiller = BpfOomKiller;

impl OomKiller for BpfOomKiller {
    fn select_victim(&self) -> Option<OomVictim> {
        select_victim()
    }
}

/// Bind `policy` as the live ranking and take over `memory`'s OOM slot.
///
/// Registering with `memory` here rather than at boot is deliberate: until a
/// program set commits there is nothing this crate does that
/// `narf_userspace::oom` does not already do, so it leaves the in-tree policy
/// installed and untouched.
pub(crate) fn install_policy(policy: Arc<dyn BpfOomPolicy>) {
    *LIVE.lock() = Some(policy);
    // Idempotent: `register_oom_killer` is last-wins and this is the same
    // `&'static` every time.
    narf_memory::oom::register_oom_killer(&BPF_OOM_KILLER);
}

/// Drop the bound program set, falling back to native badness.
///
/// This crate's killer stays registered with `memory` — deliberately, because
/// `memory` has no unregister and a half-torn-down policy would be worse than
/// a native one. Callers wanting the in-tree policy back call
/// `narf_userspace::oom::install()`, which wins by last registration.
pub fn clear_policy() {
    *LIVE.lock() = None;
}

/// Whether a BPF program set is currently ranking candidates.
#[must_use]
pub fn policy_installed() -> bool {
    LIVE.lock().is_some()
}

/// A candidate's rank, or its exclusion.
///
/// Kept as a distinct type rather than "0 means skip" so the native ranking can
/// score a candidate *negatively* — every task carrying a negative
/// `oom_score_adj` still has to produce a victim — without colliding with a
/// program's `0`, which means something else entirely.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Rank {
    /// Excluded: opted out with `oom_score_adj == -1000`.
    Skip,
    /// Eligible, ranked. Higher wins; ties go to the first candidate seen.
    Score(i64),
}

/// Linux-shaped badness: resident pages biased by `oom_score_adj` scaled
/// against total RAM. Mirrors
/// `narf_userspace::oom::ProcessOomKiller::select_victim`, so swapping this
/// crate in with no program bound is a behavioural no-op — and it is what the
/// fallback below falls back *to*.
fn native_rank(c: &OomCandidate, total_pages: u64) -> Rank {
    if c.oom_score_adj <= OOM_SCORE_ADJ_MIN {
        return Rank::Skip;
    }
    let rss = i64::try_from(c.rss_pages).unwrap_or(i64::MAX);
    let total = i64::try_from(total_pages).unwrap_or(i64::MAX);
    Rank::Score(rss.saturating_add(total.saturating_mul(c.oom_score_adj) / 1000))
}

/// How many selections fell back to native ranking because the bound program
/// set ranked nothing. Diagnostic: a climbing count means the installed policy
/// is declining (or trapping on) every candidate and is not actually in charge.
static NATIVE_FALLBACKS: AtomicUsize = AtomicUsize::new(0);

/// Selections that fell back to native ranking with a policy installed.
#[must_use]
pub fn native_fallback_count() -> usize {
    NATIVE_FALLBACKS.load(Ordering::Acquire)
}

/// Rank every candidate and kill the worst.
///
/// Called from `memory`'s pressure path. It allocates (the candidate snapshot
/// is a `Vec`) exactly as the in-tree policy it replaces does — the OOM path
/// reaches here only after reclaim has failed, not from the allocator's own
/// failure path.
///
/// # Two rankings, and why the fallback exists
///
/// A program that traps is indistinguishable from one that returns 0: the
/// adapter maps both to `BpfRet::DEFAULT_RET`, deliberately, because
/// fabricating a score for a trapped run would be worse. That indistinguishability
/// is the whole problem — without a fallback, one buggy `badness` program
/// silently turns the OOM killer off, and the machine wedges under pressure
/// instead of losing a process. So when the program set ranks *nothing*, this
/// falls back to native badness over the candidates it did not veto, which is
/// the same call Linux's `bpf_handle_out_of_memory` makes (an unhandled OOM
/// runs the in-kernel killer).
///
/// The two exclusions are therefore not equally strong, and the trait docs say
/// so:
///
///   * `veto` is **hard**. A vetoed candidate is out, fallback or not — a
///     policy that protects a database cannot have that protection evaporate
///     because the rest of its ranking misfired.
///   * `badness == 0` is **soft**: "this policy declines to rank you". If every
///     candidate is declined, native ranking decides among the non-vetoed ones
///     rather than nothing dying.
fn select_victim() -> Option<OomVictim> {
    let source = (*SOURCE.lock())?;
    // Clone the policy handle out and release the lock before any program runs.
    let policy = LIVE.lock().clone();
    let policy = policy.as_deref();

    let total_pages = source.total_pages().max(1);
    // Best by the program's ranking, and best by native ranking over the same
    // non-vetoed candidates. Computed in one pass; the native one is consulted
    // only if the program ranked nothing.
    let mut best: Option<(i64, OomCandidate)> = None;
    let mut fallback: Option<(i64, OomCandidate)> = None;
    for c in source.candidates() {
        // Hard exclusion first, so a vetoed candidate is not even eligible for
        // the fallback ranking.
        if let Some(p) = policy {
            if p.veto(c.pid, c.rss_pages, c.oom_score_adj) != 0 {
                continue;
            }
        }
        // A program's score is unsigned; clamping at `i64::MAX` keeps it
        // orderable without a wrapping cast turning a huge score negative.
        let ranked = policy.and_then(|p| {
            match p.badness(c.pid, c.rss_pages, c.oom_score_adj, total_pages) {
                0 => None,
                n => Some(i64::try_from(n).unwrap_or(i64::MAX)),
            }
        });
        match ranked {
            Some(score) => {
                if best.as_ref().is_none_or(|(bs, _)| score > *bs) {
                    best = Some((score, c));
                }
            }
            // Declined by the program, or no program bound at all: this is the
            // pool the fallback ranks. With no policy installed every candidate
            // lands here, which is how a bare install stays a behavioural no-op.
            None => {
                if let Rank::Score(score) = native_rank(&c, total_pages) {
                    if fallback.as_ref().is_none_or(|(bs, _)| score > *bs) {
                        fallback = Some((score, c));
                    }
                }
            }
        }
    }

    if best.is_none() && policy.is_some() && fallback.is_some() {
        NATIVE_FALLBACKS.fetch_add(1, Ordering::AcqRel);
    }
    let (_score, victim) = best.or(fallback)?;
    source.kill(victim.tid);
    // Tell the program which candidate it cost, after the kill is initiated so
    // a trapping or declining program cannot stop one. Unbound ⇒ no call.
    if let Some(p) = policy {
        let _ = p.notify_kill(victim.pid, victim.rss_pages);
    }
    Some(OomVictim {
        pid: victim.pid,
        tid: victim.tid,
        rss_pages: usize::try_from(victim.rss_pages).unwrap_or(usize::MAX),
        address_space: victim.address_space,
        // The reap queue seeds the retry budget on enqueue
        // (`request_oom_relief`); a policy leaves it at 0.
        retries_left: 0,
    })
}

/// Test hook: run the whole selection path (enumerate → rank → kill → victim)
/// without going through `memory`'s registry.
///
/// The smokes need to prove a program's score decided the victim, but
/// registering into `memory` and calling `request_oom_relief` would push a
/// synthetic victim onto the *real* reap queue for the reaper to walk. This
/// runs the identical code path and hands the victim straight back instead.
#[cfg(feature = "kernel-test")]
pub(crate) fn select_victim_for_test() -> Option<OomVictim> {
    select_victim()
}

/// Test hook: unregister the candidate source, so the "commit refuses without
/// one" smoke can observe the refusal. Restored by the same smoke immediately;
/// while cleared, this crate's killer would find no victim — which is exactly
/// the state the refusal exists to prevent becoming permanent.
#[cfg(feature = "kernel-test")]
pub(crate) fn __clear_candidate_source_for_test() {
    *SOURCE.lock() = None;
}
