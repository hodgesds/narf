//! Cross-CPU TLB shootdown — PCID/ASID-filtered fan-out.
//!
//! Spec: `memory/specification/asid-pcid-isolation.md` §4.
//!
//! ## Why this exists
//!
//! Every TLB-invalidating mapping change (munmap, RW->RO, free, copy-on-
//! write resolve, ...) must flush stale entries from every CPU that
//! *might* be caching the affected translation. A naive broadcast IPI to
//! all-but-self adds 1-5 us of cross-core latency on N-core systems even
//! when only one peer actually holds the affected mapping. The EuroSys
//! 2020 paper "Don't Shoot Down TLB Shootdowns!" (Amit, Wei, Tsafrir,
//! <https://dl.acm.org/doi/10.1145/3342195.3387516>) showed that the
//! majority of broadcast IPIs are spurious -- the receiver has no TLB
//! entry for the affected tag -- and proposed filtering on a per-CPU
//! "active address space" bitmap before IPI'ing.
//!
//! This module wires that filter into NARF's fan-out path:
//!
//! * **Per-CPU active-AS bitmap (`ACTIVE_AS`)** -- each CPU advertises
//!   which PCIDs / ASIDs it currently has resident in its TLB. The
//!   scheduler publishes `set_active_as(pcid)` before it loads a task's
//!   CR3 (Intel SDM Vol 3 §4.10.4.3, "Software may assume that a TLB
//!   entry's tag matches the current PCID"). Lifetime process tags retain
//!   this conservative history across context-out; their teardown invalidates
//!   every published CPU before allocator reuse.
//! * **IPI mask construction** -- `shootdown(req)` builds the IPI target
//!   set by intersecting the online-CPU bitmap with the set of CPUs that
//!   have the affected PCID resident. CPUs that have never loaded the
//!   affected PCID are skipped.
//! * **Local-only fast path** -- if no peer CPU has the PCID resident,
//!   the call reduces to a local `INVPCID` and the IPI is skipped
//!   entirely. Single-task / per-CPU-pinned-domain workloads pay zero
//!   cross-core cost (Intel SDM Vol 2, INVPCID instruction reference).
//! * **Batched range shootdown** -- `shootdown_range(tag, va, pages)`
//!   coalesces an N-page invalidation into one IPI; the existing
//!   `narf-interrupts` bridge already loops `INVPCID(tag, va + k*4K)`
//!   on the receiver side. Saves N-1 IPI round-trips per `munmap`.
//!
//! ## Bitmap encoding
//!
//! `MAX_CPUS = 64` (see `narf_lib::percpu`). PCIDs are 12-bit per
//! Intel SDM Vol 3 §4.10.1, so a per-CPU bitmap of *which PCIDs are
//! resident* would be 4096 bits per CPU. We use a coarser hash-bucket
//! encoding: each CPU has a 64-bit bitmap, and bit `pcid & 63` is set
//! when *any* PCID hashing to that bucket has been loaded. This gives a
//! 64-way filter -- false positives are possible (two PCIDs colliding
//! on the same bucket force an IPI to a CPU that doesn't hold the
//! exact tag) but no false negatives. Today's NARF allocates <= 16
//! PCIDs (one per domain, see `arch/x86_64/pcid.rs`) so collisions are
//! expected for process PCIDs; the resulting false positives remain safe.
//!
//! ## Hard cutover (no fallback flag)
//!
//! Per project policy the broadcast path is *replaced*, not gated. The
//! one exception is **bootstrap correctness**: until a particular hash
//! bucket participates in the publication protocol, a zero bitmap cannot
//! prove that no CPU retains that tag. Each bucket therefore broadcasts
//! until its first `set_active_as`; an empty mask becomes authoritative only
//! for that tracked bucket. See `shootdown_target_mask` for the precise rule.
//!
//! ## References
//!
//! * Intel(R) 64 and IA-32 Architectures Software Developer's Manual,
//!   Vol 3A §4.10, "Caching Translation Information" -- INVLPG,
//!   INVPCID, CR3 reloads, global vs non-global page handling.
//! * Intel SDM Vol 2B, INVPCID instruction reference -- type-field
//!   encoding (0 = address, 1 = single-context, 2/3 = all).
//! * AMD64 Architecture Programmer's Manual Vol 2 §5.5, "Translation-
//!   Lookaside Buffer" -- ASID-tagged TLB invalidation semantics on AMD.
//! * Amit, Wei, Tsafrir, "Don't Shoot Down TLB Shootdowns!", EuroSys
//!   2020 -- independent academic spec for filtered cross-CPU TLB
//!   invalidation.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_lib::percpu::MAX_CPUS;

// ── Request shape ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShootdownRequest {
    /// Tag (PCID / ASID). `None` = flush across all tags.
    pub tag: Option<u16>,
    /// Single VA to invalidate. `None` = full per-tag flush.
    pub addr: Option<u64>,
    /// Range size in bytes (used when `addr` is set + range
    /// invalidation is needed). `None` = single page.
    pub size: Option<u64>,
}

impl ShootdownRequest {
    pub const fn full() -> Self {
        Self {
            tag: None,
            addr: None,
            size: None,
        }
    }
    pub const fn for_tag(tag: u16) -> Self {
        Self {
            tag: Some(tag),
            addr: None,
            size: None,
        }
    }
    pub const fn for_va(tag: u16, va: u64) -> Self {
        Self {
            tag: Some(tag),
            addr: Some(va),
            size: None,
        }
    }
    /// Range invalidation: `pages` 4 KiB pages starting at `va`.
    /// Encoded as `size = pages * 4096` so the existing IPI bridge
    /// can decode it without API churn.
    pub const fn for_range(tag: u16, va: u64, pages: u64) -> Self {
        Self {
            tag: Some(tag),
            addr: Some(va),
            size: Some(pages * 4096),
        }
    }
}

// ── Kernel-test counters ─────────────────────────────────────────

/// Cache-line-isolated counters written only by the executing CPU. Readers
/// aggregate the array on demand, keeping observability off shared hot lines.
#[repr(C, align(64))]
struct ShootdownStats {
    shootdown_count: AtomicU64,
    local_only_count: AtomicU64,
    ipi_fanout_count: AtomicU64,
    broadcast_budget: AtomicU64,
    filtered_targets: AtomicU64,
    lazy_flush_count: AtomicU64,
    stale_deferred: AtomicU64,
    _pad: [u8; 8],
}

impl ShootdownStats {
    const fn new() -> Self {
        Self {
            shootdown_count: AtomicU64::new(0),
            local_only_count: AtomicU64::new(0),
            ipi_fanout_count: AtomicU64::new(0),
            broadcast_budget: AtomicU64::new(0),
            filtered_targets: AtomicU64::new(0),
            lazy_flush_count: AtomicU64::new(0),
            stale_deferred: AtomicU64::new(0),
            _pad: [0; 8],
        }
    }
}

const _: () = assert!(core::mem::size_of::<ShootdownStats>() == 64);

static SHOOTDOWN_STATS: [ShootdownStats; MAX_CPUS] = [const { ShootdownStats::new() }; MAX_CPUS];

#[inline]
fn local_stats() -> &'static ShootdownStats {
    &SHOOTDOWN_STATS[narf_lib::percpu::current_cpu().min(MAX_CPUS - 1)]
}

fn sum_stat(select: fn(&ShootdownStats) -> &AtomicU64) -> u64 {
    SHOOTDOWN_STATS.iter().fold(0u64, |total, stats| {
        total.wrapping_add(select(stats).load(Ordering::Relaxed))
    })
}

/// Total count of shootdowns observed (incremented by every invocation).
/// Useful for liveness assertions in smokes.
pub fn shootdown_count() -> u64 {
    sum_stat(|stats| &stats.shootdown_count)
}

/// Number of `shootdown` calls that elided the IPI entirely.
pub fn local_only_count() -> u64 {
    sum_stat(|stats| &stats.local_only_count)
}

/// Number of `shootdown` calls that fanned out via IPI.
pub fn ipi_fanout_count() -> u64 {
    sum_stat(|stats| &stats.ipi_fanout_count)
}

/// Total peer-CPU IPI budget had every call done an all-but-self
/// broadcast. Diagnostic.
pub fn broadcast_budget() -> u64 {
    sum_stat(|stats| &stats.broadcast_budget)
}

/// Total peer-CPU IPIs actually delivered after PCID filtering.
/// Difference from `broadcast_budget` is the saving.
pub fn filtered_targets() -> u64 {
    sum_stat(|stats| &stats.filtered_targets)
}

// ── Active-AS bitmap ─────────────────────────────────────────────
//
// Per-CPU 64-bit bitmap. Bit `pcid & 63` indicates "this CPU has
// (or recently had) a TLB entry tagged with some PCID that hashes
// to bucket `pcid & 63`. A tracked load publishes the bit before the
// architecture context switch. Clearing is permitted only after a local
// invalidation proves the CPU retains no entry in that bucket. Stale set bits
// cost only a spurious IPI; a missing live bit would violate frame-reuse
// ordering.

static ACTIVE_AS: [AtomicU64; MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_CPUS]
};

/// Buckets whose loads are covered by the residency publication protocol.
/// An untracked bucket retains the bootstrap-safe broadcast behaviour even
/// when some unrelated bucket has already been published.
static TRACKED_BUCKETS: AtomicU64 = AtomicU64::new(0);

#[inline]
fn pcid_bucket(pcid: u16) -> u32 {
    (pcid as u32) & 63
}

/// Announce that `cpu` is about to load `pcid` and may then cache
/// translations under that tag.
///
/// This must precede the context-register write. A concurrent invalidation
/// then either targets this CPU or completes its page-table edit before the
/// subsequent load can populate a translation. Idempotent and lock-free.
pub fn set_active_as(cpu: u32, pcid: u16) {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    let bit = 1u64 << pcid_bucket(pcid);
    // Publish residency before enabling the filter for this bucket. A racing
    // shootdown either still broadcasts or observes this CPU in the mask.
    ACTIVE_AS[i].fetch_or(bit, Ordering::SeqCst);
    TRACKED_BUCKETS.fetch_or(bit, Ordering::Release);
}

/// Announce that `cpu` can no longer retain anything tagged with `pcid`.
/// The caller must first complete a local invalidation for the bucket. For
/// Tags sharing a hash bucket must not use this operation until
/// every colliding resident has also been invalidated.
pub fn clear_active_as(cpu: u32, pcid: u16) {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    let bit = !(1u64 << pcid_bucket(pcid));
    ACTIVE_AS[i].fetch_and(bit, Ordering::Release);
}

/// Read this CPU's active-AS bitmap. Bit `i` set => this CPU may
/// hold a TLB entry tagged with some PCID hashing to bucket `i`.
pub fn active_as_bitmap(cpu: u32) -> u64 {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    ACTIVE_AS[i].load(Ordering::Acquire)
}

/// Idle-CPU mask: bit `i` = 1 => CPU `i` is between task polls and may
/// defer an x86 software invalidation to `mark_busy` before its next dispatch.
static IDLE_MASK: AtomicU64 = AtomicU64::new(0);

/// CPUs that elided an IPI while idle and therefore owe a complete local
/// non-global flush before loading another task address-space context.
static DEFERRED_FULL_FLUSH: AtomicU64 = AtomicU64::new(0);

/// Scheduler hook: announce `cpu` has parked (idle thread / `hlt`).
/// Calls from `shootdown` to a CPU in this mask will be elided --
/// the next dispatch on that CPU performs a full INVPCID anyway,
/// so the cross-IPI is redundant.
pub fn mark_idle(cpu: u32) {
    if (cpu as usize) < MAX_CPUS {
        IDLE_MASK.fetch_or(1u64 << cpu, Ordering::SeqCst);
    }
}

/// Scheduler hook: announce `cpu` has woken from idle. Must be
/// called *before* the new task's CR3 is loaded so the shootdown
/// path doesn't elide an IPI to a CPU that's just become reachable.
pub fn mark_busy(cpu: u32) {
    if (cpu as usize) < MAX_CPUS && take_deferred_on_busy(cpu, &IDLE_MASK, &DEFERRED_FULL_FLUSH) {
        apply_lazy_local_full();
        SHOOTDOWN_STATS[cpu as usize]
            .lazy_flush_count
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Clear one CPU's idle publication and atomically claim any deferred debt.
/// Keeping the ordering in a state-parameterized helper lets kernel tests
/// exercise the race protocol without rewriting live scheduler state.
fn take_deferred_on_busy(cpu: u32, idle: &AtomicU64, deferred: &AtomicU64) -> bool {
    let bit = 1u64 << cpu;
    // Clear IDLE before claiming the deferred bit. The sender publishes a
    // deferred bit and then rechecks IDLE; therefore a race is covered by
    // either this local flush or a normal IPI rendezvous.
    idle.fetch_and(!bit, Ordering::SeqCst);
    deferred.fetch_and(!bit, Ordering::SeqCst) & bit != 0
}

/// Snapshot of the idle-mask.
pub fn idle_mask() -> u64 {
    IDLE_MASK.load(Ordering::Acquire)
}

/// CPUs that owe a local flush before their next task dispatch.
pub fn deferred_flush_mask() -> u64 {
    DEFERRED_FULL_FLUSH.load(Ordering::Acquire)
}

/// Number of lazy idle invalidations completed on wake.
pub fn lazy_flush_count() -> u64 {
    sum_stat(|stats| &stats.lazy_flush_count)
}

/// Number of remote targets whose invalidation was deferred to their next
/// load of the affected tag bucket instead of being IPI'd.
pub fn stale_deferred_count() -> u64 {
    sum_stat(|stats| &stats.stale_deferred)
}

// ── Lazy residency: the bucket a CPU runs, and the debt it owes ─────────
//
// `ACTIVE_AS` is a residency *history*: a lifetime PCID keeps its entries
// across CR3 switches (NOFLUSH), so a bucket bit can only be dropped after a
// local flush, and in practice it never is. Interrupting every CPU in that
// history on each invalidation is what made a forked systemd's COW faults
// wait on CPUs that had not run it for seconds.
//
// Linux avoids that with `mm_cpumask` plus `tlb_gen`: only CPUs currently
// running the mm are interrupted; a CPU that merely cached its ASID earlier
// compares generations when it switches back and flushes then
// (`switch_mm_irqs_off`, `flush_tlb_func`). NARF does the same per bucket:
//
// * `CURRENT_BUCKETS[cpu]` holds the bucket(s) of the process tag this CPU
//   has loaded, or is about to load. It is widened *before* the CR3 write
//   and narrowed only *after* it, so it always covers the live CR3.
// * A sender that finds a resident CPU not running the bucket publishes
//   `STALE_BUCKETS[cpu] |= bucket` instead of interrupting it, then
//   re-reads `CURRENT_BUCKETS`. The loader widens `CURRENT_BUCKETS` and
//   then reads `STALE_BUCKETS`. With both pairs SeqCst (Dekker), either the
//   sender sees the load and sends the IPI, or the loader sees the debt and
//   flushes every non-global entry before its CR3 write. Possibly both;
//   never neither.
//
// A stale entry tagged with a PCID can only be used while CR3 carries that
// PCID (Intel SDM Vol 3 §4.10.1), and every load of a process tag goes
// through `AddressSpace::activate`, so a deferred CPU cannot consume a stale
// translation before it pays the debt. Domain tags (1..=N_DOMAINS) are also
// loaded by the trap/syscall entry assembly, which does not take part in
// this protocol, so they are never deferred.

static CURRENT_BUCKETS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static STALE_BUCKETS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

// Tag 0 (the flushing fallback: no PCIDE, or tag exhaustion) is different.
// Every CR3 load of a tag-0 root drops that context's entries, so a CPU can
// hold a tag-0 address space's translations only while that root is its
// live CR3, exactly Linux's `mm_cpumask`. But all tag-0 address spaces share
// bucket 0, so the bucket history above cannot tell them apart. For tag 0
// the sender instead matches the owning root against each CPU's
// `CURRENT_ROOT` (the root its CR3 holds) and `LOADING_ROOT` (a root it has
// announced but may not have written yet). The loader stores `LOADING_ROOT`
// (SeqCst) before its serialising CR3 write; the sender reads both after
// its page-table writes and SeqCst fence. A sender that misses the
// announcement is ordered before it, so the loader's fresh page walk sees
// the new PTEs.
static CURRENT_ROOT: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static LOADING_ROOT: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Whether invalidations of `tag` may be deferred to the next context load.
#[inline]
fn deferrable_tag(tag: u16) -> bool {
    tag >= crate::asid_alloc::PROCESS_CONTEXT_FIRST
}

/// Begin loading process tag `tag` on `cpu`: publish residency, mark the
/// bucket current, and claim any deferred debt. Returns `true` when the
/// caller must flush every non-global local entry before writing CR3.
///
/// Must run on `cpu` with interrupts disabled until the matching
/// [`finish_context_load`].
pub fn begin_context_load(cpu: u32, tag: u16, root: u64) -> bool {
    set_active_as(cpu, tag);
    let i = (cpu as usize).min(MAX_CPUS - 1);
    LOADING_ROOT[i].store(root, Ordering::SeqCst);
    claim_stale_on_load(
        1u64 << pcid_bucket(tag),
        &CURRENT_BUCKETS[i],
        &STALE_BUCKETS[i],
    )
}

/// Finish loading `tag` on `cpu`: the CR3 write is done, so buckets of the
/// previous context stop being current.
pub fn finish_context_load(cpu: u32, tag: u16, root: u64) {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    CURRENT_ROOT[i].store(root, Ordering::SeqCst);
    LOADING_ROOT[i].store(0, Ordering::SeqCst);
    CURRENT_BUCKETS[i].store(1u64 << pcid_bucket(tag), Ordering::SeqCst);
}

/// Whether every load of a tag-0 user root goes through
/// [`begin_context_load`]. The trap/syscall entry and `kernel_switch`
/// assembly displace a CR3 whose PCID is at most 16, which includes a tag-0
/// user root, and later write it back without this protocol, but only when
/// the entry-visible CR4 cache has PCIDE set. With that gate clear the only
/// writer of a user root is `AddressSpace::activate`.
#[cfg(target_arch = "x86_64")]
#[inline]
fn tag0_roots_tracked() -> bool {
    narf_arch::x86_64::cr::NARF_X86_CACHED_CR4.load(Ordering::Acquire)
        & narf_arch::x86_64::cr::CR4_PCIDE
        == 0
}

/// CPUs among `candidates` whose live or announced CR3 root is `root`.
fn running_root_mask(
    candidates: u64,
    root: u64,
    current: &[AtomicU64],
    loading: &[AtomicU64],
) -> u64 {
    let mut out = 0u64;
    let mut scan = candidates;
    while scan != 0 {
        let cpu = scan.trailing_zeros() as usize;
        scan &= scan - 1;
        let running = match (current.get(cpu), loading.get(cpu)) {
            (Some(c), Some(l)) => {
                c.load(Ordering::SeqCst) == root || l.load(Ordering::SeqCst) == root
            }
            // Outside the tracked range: stay conservative.
            _ => true,
        };
        if running {
            out |= 1u64 << cpu;
        }
    }
    out
}

/// Loader half of the protocol over explicit state (tests drive it).
fn claim_stale_on_load(bit: u64, current: &AtomicU64, stale: &AtomicU64) -> bool {
    current.fetch_or(bit, Ordering::SeqCst);
    if stale.load(Ordering::SeqCst) & bit == 0 {
        return false;
    }
    // The caller's full non-global flush runs after this swap, so it also
    // discharges any other bucket whose debt the swap consumes.
    stale.swap(0, Ordering::SeqCst);
    true
}

/// Sender half: split resident `candidates` into CPUs to interrupt now and
/// CPUs that now owe a flush on their next load of `bit`'s bucket.
fn split_current_targets(
    candidates: u64,
    bit: u64,
    current: &[AtomicU64],
    stale: &[AtomicU64],
) -> (u64, u64) {
    let mut ipi = 0u64;
    let mut deferred = 0u64;
    let mut scan = candidates;
    while scan != 0 {
        let cpu = scan.trailing_zeros() as usize;
        scan &= scan - 1;
        if cpu >= current.len() || cpu >= stale.len() {
            ipi |= 1u64 << cpu;
            continue;
        }
        if current[cpu].load(Ordering::SeqCst) & bit != 0 {
            ipi |= 1u64 << cpu;
            continue;
        }
        stale[cpu].fetch_or(bit, Ordering::SeqCst);
        if current[cpu].load(Ordering::SeqCst) & bit != 0 {
            ipi |= 1u64 << cpu;
        } else {
            deferred |= 1u64 << cpu;
        }
    }
    (ipi, deferred)
}

fn residency_target_mask(req: ShootdownRequest) -> u64 {
    let online = narf_lib::smp::online_bitmap();
    let self_cpu = narf_lib::percpu::current_cpu();
    let self_bit = 1u64 << (self_cpu & 63);
    let mut targets = online & !self_bit;

    if let Some(tag) = req.tag {
        let bucket_bit = 1u64 << pcid_bucket(tag);
        let tracked = TRACKED_BUCKETS.load(Ordering::Acquire);
        if tracked & bucket_bit != 0 {
            let mut residency = 0u64;
            for (cpu, slot) in ACTIVE_AS.iter().enumerate().take(MAX_CPUS) {
                if slot.load(Ordering::Acquire) & bucket_bit != 0 {
                    residency |= 1u64 << (cpu & 63);
                }
            }
            targets = filter_residency_targets(req, targets, tracked, residency);
        }
    }
    targets
}

/// Apply the tracked-bucket residency filter to an already-bounded CPU mask.
/// `residency` is the CPU mask for `req`'s bucket. This pure seam is also used
/// by tests so they never need to clear live per-CPU residency publication.
fn filter_residency_targets(
    req: ShootdownRequest,
    candidates: u64,
    tracked: u64,
    residency: u64,
) -> u64 {
    match req.tag {
        Some(tag) if tracked & (1u64 << pcid_bucket(tag)) != 0 => candidates & residency,
        _ => candidates,
    }
}

/// Compute the peer-CPU IPI target mask for `req`. Algorithm:
///
/// 1. Start from `online_bitmap & !self_bit`. This is the legacy
///    all-but-self broadcast set.
/// 2. **If a tag is specified**, AND-in the set of CPUs whose
///    `ACTIVE_AS` bitmap has the corresponding bucket bit set.
///    Receivers without that bucket cannot hold an entry for the
///    PCID (bitmap is conservative -- bits stay set until cleared,
///    so no false negatives).
/// 3. If this exact bucket has never participated in the publication
///    protocol, preserve the step-1 broadcast set. Activity in an unrelated
///    bucket may never enable filtering for an untracked tag.
/// 4. Drop idle CPUs (their TLB invalidation is lazy -- handled on
///    next dispatch).
///
/// Returns the bitmap of CPU IDs that appear immediately IPI-eligible. This
/// is a diagnostic snapshot only: callers must use `shootdown*`, whose idle
/// debt handshake closes races between this observation and dispatch.
pub fn shootdown_target_mask(req: ShootdownRequest) -> u64 {
    residency_target_mask(req) & !IDLE_MASK.load(Ordering::Acquire)
}

// ── IPI fan-out hook ─────────────────────────────────────────────
//
// `narf-memory` can't depend on `narf-interrupts` (the dependency
// runs the other way), so the cross-CPU IPI shoot path is wired by
// the interrupts crate via `set_ipi_fanout` at boot. UP boots leave
// the hook unset and `shootdown` reduces to local invalidation.
//
// The fan-out hook is called only when the filtered target mask is
// non-empty. The interrupts crate translates the request into the
// concrete IPI primitive and sends only to `targets` (Intel SDM Vol
// 3 §11.6.1, physical destination mode in the ICR). Passing the mask
// is load-bearing: recomputing or broadcasting in the bridge would
// defeat both the active-AS filter and idle-CPU elision.

type IpiFanoutFn = fn(req: ShootdownRequest, targets: u64);

static IPI_FANOUT: AtomicUsize = AtomicUsize::new(0);

/// Wire the IPI fan-out function. Called once by the interrupts
/// crate after the IPI vector + per-CPU pending state are ready.
pub fn set_ipi_fanout(f: IpiFanoutFn) {
    IPI_FANOUT.store(f as usize, Ordering::Release);
}

fn ipi_fanout(req: ShootdownRequest, targets: u64) {
    let f = IPI_FANOUT.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: stored as `IpiFanoutFn as usize`; round-trip back
        // is sound when non-null.
        // SAFETY: Valid memory or trusted environment
        let func: IpiFanoutFn = unsafe { core::mem::transmute(f) };
        func(req, targets);
    }
}

/// Apply `req` locally, then -- *only if the active-AS bitmap says a
/// peer CPU may hold the affected mapping* -- fan out via IPI. On UP
/// boots / when the filter culls every peer, the call reduces to a
/// local INVPCID.
pub fn shootdown(req: ShootdownRequest) {
    apply_local(req);
    local_stats()
        .shootdown_count
        .fetch_add(1, Ordering::Relaxed);

    dispatch_remote(req, req, None);
    #[cfg(any(test, feature = "kernel-test"))]
    notify_completion_for_test(req);
}

/// [`shootdown`] for an invalidation of the address space whose page-table
/// root is `owner_root`. A tag-0 request then targets only CPUs running that
/// root (see the tag-0 notes above); other tags behave as `shootdown`.
pub fn shootdown_owned(owner_root: u64, req: ShootdownRequest) {
    apply_local(req);
    local_stats()
        .shootdown_count
        .fetch_add(1, Ordering::Relaxed);

    dispatch_remote(req, req, Some(owner_root));
    #[cfg(any(test, feature = "kernel-test"))]
    notify_completion_for_test(req);
}

/// Test-only observer invoked after both halves of a synchronous shootdown.
/// It lets ordering tests model the last store completed by a remote CPU at
/// the rendezvous boundary without routing through the obsolete PCID-0 paging
/// hook.
#[cfg(any(test, feature = "kernel-test"))]
pub type ShootdownCompletionHook = fn(ShootdownRequest);

#[cfg(any(test, feature = "kernel-test"))]
static COMPLETION_HOOK_FOR_TEST: AtomicUsize = AtomicUsize::new(0);

/// Replace the test-only completion observer and return the prior value.
#[doc(hidden)]
#[cfg(any(test, feature = "kernel-test"))]
pub fn replace_completion_hook_for_test(
    hook: Option<ShootdownCompletionHook>,
) -> Option<ShootdownCompletionHook> {
    let previous = COMPLETION_HOOK_FOR_TEST.swap(hook.map_or(0, |f| f as usize), Ordering::AcqRel);
    if previous == 0 {
        None
    } else {
        // SAFETY: only `ShootdownCompletionHook` values are stored above.
        Some(unsafe { core::mem::transmute::<usize, ShootdownCompletionHook>(previous) })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
fn notify_completion_for_test(req: ShootdownRequest) {
    let hook = COMPLETION_HOOK_FOR_TEST.load(Ordering::Acquire);
    if hook != 0 {
        // SAFETY: only `ShootdownCompletionHook` values are stored above.
        let hook: ShootdownCompletionHook = unsafe { core::mem::transmute(hook) };
        hook(req);
    }
}

/// Complete only the remote half of an invalidation whose caller already
/// performed the matching local operation after its final page-table write.
pub fn shootdown_remote(req: ShootdownRequest) {
    local_stats()
        .shootdown_count
        .fetch_add(1, Ordering::Relaxed);
    dispatch_remote(req, req, None);
}

/// Remotely flush every non-global entry, but target only CPUs that may hold
/// `residency_tag`. Retained for callers whose local phase deliberately uses a
/// broader non-global flush while remote selection still knows one logical tag.
pub fn shootdown_remote_full_for_tag(residency_tag: u16) {
    local_stats()
        .shootdown_count
        .fetch_add(1, Ordering::Relaxed);
    dispatch_remote(
        ShootdownRequest::full(),
        ShootdownRequest::for_tag(residency_tag),
        None,
    );
}

fn dispatch_remote(
    payload: ShootdownRequest,
    residency: ShootdownRequest,
    owner_root: Option<u64>,
) {
    // Pair the page-table writer's stores with a CPU's pre-context-load
    // residency publication. Without this StoreLoad barrier, both sides
    // could transiently miss one another on weakly ordered hardware (and on
    // x86 via the local store buffer) even though compiler ordering holds.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Tagged aarch64 TLBI operations already carry the Inner Shareable suffix;
    // issuing an SGI would perform the same invalidation a second time.
    #[cfg(target_arch = "aarch64")]
    if payload.tag.is_some() {
        local_stats()
            .local_only_count
            .fetch_add(1, Ordering::Relaxed);
        return;
    }

    {
        // Accounting: BROADCAST_BUDGET is what an unfiltered fan-out
        // would have cost. FILTERED_TARGETS is what we actually IPI'd.
        let online = narf_lib::smp::online_bitmap();
        let self_cpu = narf_lib::percpu::current_cpu();
        let self_bit = 1u64 << (self_cpu & 63);
        let budget = (online & !self_bit).count_ones() as u64;
        local_stats()
            .broadcast_budget
            .fetch_add(budget, Ordering::Relaxed);
    }

    let candidates = residency_target_mask(residency);
    // Owner-root targeting is an x86 tag-0 refinement; aarch64 tagged TLBI
    // returned above and its untagged requests stay broadcast.
    #[cfg(not(target_arch = "x86_64"))]
    let _ = owner_root;
    #[cfg(target_arch = "x86_64")]
    let candidates = match (residency.tag, owner_root) {
        (Some(crate::asid_alloc::TAG_RESERVED), Some(root))
            if root != 0 && tag0_roots_tracked() =>
        {
            running_root_mask(candidates, root, &CURRENT_ROOT, &LOADING_ROOT)
        }
        (Some(tag), _) if deferrable_tag(tag) => {
            let (ipi, deferred) = split_current_targets(
                candidates,
                1u64 << pcid_bucket(tag),
                &CURRENT_BUCKETS,
                &STALE_BUCKETS,
            );
            if deferred != 0 {
                local_stats()
                    .stale_deferred
                    .fetch_add(deferred.count_ones() as u64, Ordering::Relaxed);
            }
            ipi
        }
        _ => candidates,
    };
    #[cfg(target_arch = "x86_64")]
    let targets = defer_idle_targets(candidates, &IDLE_MASK, &DEFERRED_FULL_FLUSH);
    #[cfg(not(target_arch = "x86_64"))]
    let targets = candidates;
    if targets == 0 {
        local_stats()
            .local_only_count
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    let stats = local_stats();
    stats
        .filtered_targets
        .fetch_add(targets.count_ones() as u64, Ordering::Relaxed);
    stats.ipi_fanout_count.fetch_add(1, Ordering::Relaxed);
    ipi_fanout(payload, targets);
}

/// Publish full-flush debt for currently idle candidates, then recheck the
/// idle mask. A CPU racing busy either claims the debt or remains in the
/// returned IPI mask.
#[cfg(target_arch = "x86_64")]
fn defer_idle_targets(candidates: u64, idle: &AtomicU64, deferred: &AtomicU64) -> u64 {
    let idle_snapshot = idle.load(Ordering::SeqCst);
    let debt = candidates & idle_snapshot;
    if debt != 0 {
        deferred.fetch_or(debt, Ordering::SeqCst);
    }
    candidates & !idle.load(Ordering::SeqCst)
}

#[inline]
fn apply_lazy_local_full() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: mark_busy runs in scheduler context at CPL=0. User PTEs are
        // non-global, so retaining global kernel entries is both sufficient
        // for correctness and materially cheaper than INVPCID type 2.
        unsafe { crate::x86_64::paging::flush_user_tlb_local() };
    }
    #[cfg(not(target_arch = "x86_64"))]
    apply_local(ShootdownRequest::full());
}

/// Batched range shootdown. Issues one IPI for `pages` contiguous
/// 4 KiB pages starting at `va` tagged with `pcid`. The receiver
/// loops `INVPCID(pcid, va + k*4K)` (Intel SDM Vol 2 INVPCID type 0).
///
/// Equivalent to calling `shootdown` once per page but with one IPI
/// round-trip instead of N. Used by munmap of a range, mprotect of
/// a region, etc.
pub fn shootdown_range(pcid: u16, va: u64, pages: u64) {
    if pages == 0 {
        return;
    }
    shootdown(ShootdownRequest::for_range(pcid, va, pages));
}

#[cfg(target_arch = "x86_64")]
fn apply_local(req: ShootdownRequest) {
    use narf_arch::x86_64::pcid;
    // INVPCID with a non-zero PCID #GPs unless CR4.PCIDE=1, AND a hypervisor can
    // expose the INVPCID instruction on a vCPU while NOT advertising PCID
    // (CPUID(1).ECX[17]) — seen under QEMU `-cpu max`+KVM, where `enable_pcide`
    // no-op'd so CR4.PCIDE stayed 0. Require BOTH the instruction and PCIDE; on a
    // PCIDE-off CPU there are no PCID-tagged entries, so the MOV-CR3 self-flush
    // below (drops all non-global entries) is a correct, if coarser, substitute.
    if !pcid::invpcid_supported() || !pcid::pcide_enabled() {
        // Fall back to MOV-CR3 self-flush -- global pages stay.
        // SAFETY: CR4.PCIDE may or may not be on; this is a
        // best-effort cleanup and CR3 read/write is always legal
        // at CPL=0.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let cr3 = narf_arch::x86_64::cr::read_cr3();
            narf_arch::x86_64::cr::write_cr3(cr3);
        }
        return;
    }
    match (req.tag, req.addr, req.size) {
        (Some(t), Some(va), Some(size)) => {
            // Range: INVPCID(addr) per page. Intel SDM Vol 2
            // INVPCID type 0.
            let pages = size.div_ceil(4096);
            for k in 0..pages.max(1) {
                // SAFETY: caller-asserted CPL=0; INVPCID supported.
                unsafe {
                    pcid::invpcid_addr(t, va + k * 4096);
                }
            }
        }
        (Some(t), Some(va), None) => {
            // SAFETY: caller-asserted CPL=0.
            unsafe {
                pcid::invpcid_addr(t, va);
            }
        }
        (Some(t), None, _) => {
            // SAFETY: same.
            unsafe {
                pcid::invpcid_single(t);
            }
        }
        (None, _, _) => {
            // SAFETY: same.
            unsafe {
                pcid::invpcid_all_with_globals();
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
fn apply_local(req: ShootdownRequest) {
    use narf_arch::aarch64::sysreg;
    match (req.tag, req.addr, req.size) {
        (Some(t), Some(va), Some(size)) => {
            // Range invalidation: ARM ARM v8 D4.7 -- TLBI VAEn,IS
            // per page covers the ASID-tagged entries.
            let pages = size.div_ceil(4096);
            for k in 0..pages.max(1) {
                // SAFETY: kernel-test runs at EL1.
                unsafe {
                    sysreg::tlbi_va_asid_inner_shareable(t, va + k * 4096);
                }
            }
        }
        (Some(t), Some(va), None) => {
            // SAFETY: kernel-test runs at EL1.
            unsafe {
                sysreg::tlbi_va_asid_inner_shareable(t, va);
            }
        }
        (Some(t), None, _) => {
            // SAFETY: same.
            unsafe {
                sysreg::tlbi_asid_inner_shareable(t);
            }
        }
        (None, _, _) => {
            // SAFETY: same.
            unsafe {
                sysreg::tlb_flush_all();
            }
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn apply_local(_req: ShootdownRequest) {}

// ── Tests ────────────────────────────────────────────────────────
//
// Kernel-runner-visible tests (registered via `kernel_test_in!`).
// These run inside the live SMP kernel. They must never reset ACTIVE_AS,
// TRACKED_BUCKETS, IDLE_MASK, or deferred debt: doing so can erase a live
// scheduler publication and turn a test fixture into a missed shootdown.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_tlb_shootdown_empty_bitmap_broadcasts() -> TestResult {
    // Model pre-scheduler boot without clearing the live kernel's publication
    // state. An untracked bucket must retain every candidate even when its
    // residency mask is empty.
    let req = ShootdownRequest::for_va(7, 0x1000);
    let candidates = 0xA5A5_5A5A_F0F0_0F0Fu64;
    if filter_residency_targets(req, candidates, 0, 0) != candidates {
        return TestResult::Fail("untracked empty bucket did not broadcast");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_empty_bitmap_broadcasts
);

fn smoke_tlb_shootdown_active_as_filter_skips_unaffected() -> TestResult {
    const CPU_A: u32 = 62;
    const CPU_B: u32 = 63;
    let candidates = (1u64 << CPU_A) | (1u64 << CPU_B);
    let tracked = (1u64 << 5) | (1u64 << 7);
    let residency = 1u64 << CPU_B;
    let mask = filter_residency_targets(
        ShootdownRequest::for_va(5, 0x4000),
        candidates,
        tracked,
        residency,
    );
    if mask & (1u64 << CPU_A) != 0 || mask & (1u64 << CPU_B) == 0 {
        return TestResult::Fail("tracked bucket did not select exact resident peer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_active_as_filter_skips_unaffected
);

#[cfg(target_arch = "x86_64")]
fn smoke_tlb_shootdown_tracked_empty_and_idle_defer() -> TestResult {
    const PEER_CPU: u32 = 63;
    let peer = 1u64 << PEER_CPU;
    // An unrelated tracked bucket must not disable bootstrap broadcast for a
    // bucket whose loads have never been published.
    let tracked = 1u64;
    if filter_residency_targets(ShootdownRequest::for_va(7, 0x4000), peer, tracked, 0) & peer == 0 {
        return TestResult::Fail("unrelated tracking suppressed bootstrap broadcast");
    }

    // Once tag 0 is tracked, clearing its only resident makes an empty mask
    // authoritative rather than falling back to all peers.
    if filter_residency_targets(ShootdownRequest::for_va(0, 0x4000), peer, tracked, 0) & peer != 0 {
        return TestResult::Fail("tracked empty bucket fell back to broadcast");
    }

    // Exercise the sender/waker handshake on local atomics. Tests must not
    // forge a live CPU id then call mark_busy for it from the BSP: the flush
    // is CPU-local, so that old fixture proved the wrong processor flushed.
    let idle = AtomicU64::new(peer);
    let deferred = AtomicU64::new(0);
    if defer_idle_targets(peer, &idle, &deferred) != 0
        || deferred.load(Ordering::Acquire) & peer == 0
    {
        return TestResult::Fail("idle target did not acquire deferred flush debt");
    }
    if !take_deferred_on_busy(PEER_CPU, &idle, &deferred)
        || idle.load(Ordering::Acquire) & peer != 0
        || deferred.load(Ordering::Acquire) & peer != 0
    {
        return TestResult::Fail("mark_busy did not discharge deferred flush debt");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_tracked_empty_and_idle_defer
);

fn smoke_tlb_shootdown_invpcid_encoding_round_trip() -> TestResult {
    // The ShootdownRequest carries the data the bridge uses to
    // build the INVPCID descriptor. Verify the encoding for each
    // INVPCID type (Intel SDM Vol 2 INVPCID type field):
    //   - for_va(tag, va)             -> type 0 (individual-address)
    //   - for_tag(tag)                -> type 1 (single-context)
    //   - for_range(tag, va, pages)   -> type 0 looped per page
    //   - full()                      -> no tag -> CR3 reload / type 2
    let r0 = ShootdownRequest::for_va(0x123, 0xFFFF_8000_DEAD_0000);
    if r0.tag != Some(0x123) || r0.addr != Some(0xFFFF_8000_DEAD_0000) || r0.size.is_some() {
        return TestResult::Fail("for_va encoding drift (type 0)");
    }
    let r1 = ShootdownRequest::for_tag(0xABC);
    if r1.tag != Some(0xABC) || r1.addr.is_some() || r1.size.is_some() {
        return TestResult::Fail("for_tag encoding drift (type 1)");
    }
    let rr = ShootdownRequest::for_range(0x42, 0x4000, 8);
    if rr.tag != Some(0x42) || rr.addr != Some(0x4000) || rr.size != Some(8 * 4096) {
        return TestResult::Fail("for_range encoding drift");
    }
    let rf = ShootdownRequest::full();
    if rf.tag.is_some() || rf.addr.is_some() || rf.size.is_some() {
        return TestResult::Fail("full() encoding drift (type 2)");
    }
    // PCID 12-bit limit per SDM Vol 3 §4.10.1: the bridge masks the
    // descriptor to 12 bits -- verify the bucket hash is stable
    // under that mask (low 6 bits == low 6 bits of pcid).
    if pcid_bucket(0xABC) != (0xABC & 63) {
        return TestResult::Fail("pcid_bucket hash drifted from low 6 bits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_invpcid_encoding_round_trip
);

fn smoke_tlb_shootdown_batched_range_encodes_one_request() -> TestResult {
    // The whole point of batching: N-page invalidation produces a
    // *single* ShootdownRequest (and therefore a single IPI fan-out
    // call), not N requests.
    let before = shootdown_count();
    shootdown_range(
        /* pcid */ 9, /* va */ 0x10_0000, /* pages */ 16,
    );
    let after = shootdown_count();
    if after - before != 1 {
        return TestResult::Fail("range shootdown made multiple requests");
    }
    // Zero-page range is a no-op (don't poke INVPCID / don't bump
    // the counter -- there's nothing to flush).
    let before2 = shootdown_count();
    shootdown_range(9, 0x10_0000, 0);
    if shootdown_count() != before2 {
        return TestResult::Fail("zero-page range bumped the counter");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_batched_range_encodes_one_request
);

fn smoke_tlb_shootdown_idle_mask_round_trip() -> TestResult {
    // Exercise the calling CPU: mark_busy's deferred flush is local and must
    // never be invoked for a made-up peer from this CPU. Evaluate both states
    // before returning so even a failed assertion leaves this CPU busy.
    let cpu = narf_lib::percpu::current_cpu() as u32;
    let bit = 1u64 << cpu;
    mark_busy(cpu);
    let initially_busy = idle_mask() & bit == 0;
    mark_idle(cpu);
    let became_idle = idle_mask() & bit != 0;
    mark_busy(cpu);
    let became_busy = idle_mask() & bit == 0;
    if !initially_busy {
        return TestResult::Fail("mark_busy did not establish the initial busy state");
    }
    if !became_idle {
        return TestResult::Fail("mark_idle didn't set bit");
    }
    if !became_busy {
        return TestResult::Fail("mark_busy didn't clear bit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_idle_mask_round_trip
);

fn smoke_tlb_shootdown_local_only_count_advances() -> TestResult {
    // The IPI-reduction headline: when no peer CPU holds an
    // affected mapping, every shootdown collapses to a local INVPCID and
    // shows up as a +1 in local_only_count. Bucket 63 is unused by production
    // Marking it tracked is monotonic and safe because any future load must
    // publish residency before its context load. A production PCID may share
    // the bucket, in which case this diagnostic correctly skips.
    const TEST_TAG: u16 = 63;
    let bucket = 1u64 << pcid_bucket(TEST_TAG);
    TRACKED_BUCKETS.fetch_or(bucket, Ordering::Release);
    if ACTIVE_AS
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) & bucket != 0)
    {
        return TestResult::Skip("test PCID bucket is live");
    }
    let before_local = local_only_count();
    let before_targets = filtered_targets();
    shootdown(ShootdownRequest::for_va(TEST_TAG, 0x4000));
    shootdown(ShootdownRequest::for_tag(TEST_TAG));
    shootdown_range(TEST_TAG, 0x8000, 4);
    let after_local = local_only_count();
    let after_targets = filtered_targets();
    if after_local - before_local != 3 {
        return TestResult::Fail("local_only_count didn't advance by 3");
    }
    if after_targets - before_targets != 0 {
        return TestResult::Fail("filtered_targets advanced on UP boot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_local_only_count_advances
);

fn smoke_tlb_lazy_residency_defers_and_claims() -> TestResult {
    // Drive the protocol over local state; live per-CPU slots must never be
    // forged (see the module's test notes).
    let bit = 1u64 << pcid_bucket(0x125);
    let other = 1u64 << pcid_bucket(0x126);
    let current = [AtomicU64::new(bit), AtomicU64::new(other)];
    let stale = [AtomicU64::new(0), AtomicU64::new(0)];

    // CPU 0 runs the bucket: interrupt it. CPU 1 only cached it: defer.
    let (ipi, deferred) = split_current_targets(0b11, bit, &current, &stale);
    if ipi != 0b01 || deferred != 0b10 {
        return TestResult::Fail("running CPU not interrupted or resident CPU not deferred");
    }
    if stale[0].load(Ordering::Acquire) != 0 || stale[1].load(Ordering::Acquire) != bit {
        return TestResult::Fail("deferred CPU did not receive the bucket's flush debt");
    }

    // Loading an unrelated bucket neither flushes nor drops the debt.
    if claim_stale_on_load(other, &current[1], &stale[1]) {
        return TestResult::Fail("load of an unrelated bucket claimed foreign debt");
    }
    if stale[1].load(Ordering::Acquire) != bit {
        return TestResult::Fail("unrelated load discarded pending debt");
    }

    // Loading the stale bucket must flush before CR3, exactly once.
    if !claim_stale_on_load(bit, &current[1], &stale[1]) {
        return TestResult::Fail("load of a stale bucket skipped its flush");
    }
    if stale[1].load(Ordering::Acquire) != 0 || current[1].load(Ordering::Acquire) & bit == 0 {
        return TestResult::Fail("claim left debt behind or did not mark the bucket current");
    }
    if claim_stale_on_load(bit, &current[1], &stale[1]) {
        return TestResult::Fail("discharged debt flushed twice");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_lazy_residency_defers_and_claims
);

fn smoke_tlb_lazy_residency_racing_load_is_interrupted() -> TestResult {
    // A loader that widened CURRENT before the sender's scan is a live
    // resident: the sender must interrupt it rather than defer. A loader that
    // widens after the sender published debt must observe that debt. Either
    // side of the Dekker pair suffices; this checks both orders.
    let bit = 1u64 << pcid_bucket(0x231);
    let current = [AtomicU64::new(0)];
    let stale = [AtomicU64::new(0)];

    current[0].fetch_or(bit, Ordering::SeqCst);
    let (ipi, deferred) = split_current_targets(0b1, bit, &current, &stale);
    if ipi != 0b1 || deferred != 0 {
        return TestResult::Fail("sender deferred a CPU that had announced the load");
    }

    let current = [AtomicU64::new(0)];
    let stale = [AtomicU64::new(0)];
    let (ipi, deferred) = split_current_targets(0b1, bit, &current, &stale);
    if ipi != 0 || deferred != 0b1 {
        return TestResult::Fail("idle-history CPU was not deferred");
    }
    if !claim_stale_on_load(bit, &current[0], &stale[0]) {
        return TestResult::Fail("load after deferral missed the published debt");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_lazy_residency_racing_load_is_interrupted
);

fn smoke_tlb_tag0_targets_cpus_running_the_root() -> TestResult {
    const ROOT: u64 = 0x1234_5000;
    const OTHER: u64 = 0x6789_a000;
    let current = [
        AtomicU64::new(ROOT),
        AtomicU64::new(OTHER),
        AtomicU64::new(OTHER),
        AtomicU64::new(0),
    ];
    // CPU 2 has announced ROOT but not yet written CR3.
    let loading = [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(ROOT),
        AtomicU64::new(0),
    ];
    if running_root_mask(0b1111, ROOT, &current, &loading) != 0b0101 {
        return TestResult::Fail(
            "tag-0 targets are not exactly the CPUs running or loading the root",
        );
    }
    // A CPU outside the tracked arrays stays a target.
    if running_root_mask(1u64 << 9, ROOT, &current, &loading) != 1u64 << 9 {
        return TestResult::Fail("untracked CPU was dropped from tag-0 targets");
    }
    // Domain tags are loaded by entry assembly outside the protocol.
    if deferrable_tag(0)
        || deferrable_tag(crate::asid_alloc::N_DOMAINS as u16)
        || !deferrable_tag(crate::asid_alloc::PROCESS_CONTEXT_FIRST)
    {
        return TestResult::Fail("deferral eligibility drifted from the process-tag range");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_tag0_targets_cpus_running_the_root
);
