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
//!   entry's tag matches the current PCID"). On context-out, it first
//!   invalidates that tag locally and only then calls `clear_active_as`.
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
//! impossible in practice; the encoding scales cleanly when the PCID
//! allocator grows.
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

// ── Counters (test + diagnostics) ────────────────────────────────

static SHOOTDOWN_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of `shootdown` calls that were satisfied locally without
/// firing an IPI (the active-AS bitmap reported no peer CPU could
/// possibly hold the affected PCID). Reduction in this counter
/// directly equals saved IPI round-trips.
static LOCAL_ONLY_COUNT: AtomicU64 = AtomicU64::new(0);
/// Number of `shootdown` calls that fanned out via IPI.
static IPI_FANOUT_COUNT: AtomicU64 = AtomicU64::new(0);
/// Total number of peer-CPU bits that *would* have been IPI'd under a
/// pure all-but-self broadcast, summed across all `shootdown` calls.
/// Subtracting `FILTERED_TARGETS` gives the saved IPIs.
static BROADCAST_BUDGET: AtomicU64 = AtomicU64::new(0);
/// Total number of peer-CPU bits actually IPI'd (post-filter), summed
/// across all calls. Always <= `BROADCAST_BUDGET`.
static FILTERED_TARGETS: AtomicU64 = AtomicU64::new(0);

/// Per-CPU count of shootdowns observed (incremented by every
/// invocation). Useful for liveness assertions in smokes.
pub fn shootdown_count() -> u64 {
    SHOOTDOWN_COUNT.load(Ordering::Acquire)
}

/// Number of `shootdown` calls that elided the IPI entirely.
pub fn local_only_count() -> u64 {
    LOCAL_ONLY_COUNT.load(Ordering::Acquire)
}

/// Number of `shootdown` calls that fanned out via IPI.
pub fn ipi_fanout_count() -> u64 {
    IPI_FANOUT_COUNT.load(Ordering::Acquire)
}

/// Total peer-CPU IPI budget had every call done an all-but-self
/// broadcast. Diagnostic.
pub fn broadcast_budget() -> u64 {
    BROADCAST_BUDGET.load(Ordering::Acquire)
}

/// Total peer-CPU IPIs actually delivered after PCID filtering.
/// Difference from `broadcast_budget` is the saving.
pub fn filtered_targets() -> u64 {
    FILTERED_TARGETS.load(Ordering::Acquire)
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
/// x86 process PCID 0, the scheduler's plain kernel-CR3 restore supplies that
/// invalidation. Tags sharing a hash bucket must not use this operation until
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

/// Number of deferred invalidations discharged by [`mark_busy`].
static LAZY_FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);

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
    if (cpu as usize) < MAX_CPUS {
        let bit = 1u64 << cpu;
        // Clear IDLE before claiming the deferred bit. The sender publishes a
        // deferred bit and then rechecks IDLE; therefore a race is covered by
        // either this local flush or a normal IPI rendezvous.
        IDLE_MASK.fetch_and(!bit, Ordering::SeqCst);
        if DEFERRED_FULL_FLUSH.fetch_and(!bit, Ordering::SeqCst) & bit != 0 {
            apply_lazy_local_full();
            LAZY_FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }
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
    LAZY_FLUSH_COUNT.load(Ordering::Acquire)
}

fn residency_target_mask(req: ShootdownRequest) -> u64 {
    let online = narf_lib::smp::online_bitmap();
    let self_cpu = narf_lib::percpu::current_cpu();
    let self_bit = 1u64 << (self_cpu & 63);
    let mut targets = online & !self_bit;

    if let Some(tag) = req.tag {
        let bucket_bit = 1u64 << pcid_bucket(tag);
        if TRACKED_BUCKETS.load(Ordering::Acquire) & bucket_bit != 0 {
            let mut residency = 0u64;
            for (cpu, slot) in ACTIVE_AS.iter().enumerate().take(MAX_CPUS) {
                if slot.load(Ordering::Acquire) & bucket_bit != 0 {
                    residency |= 1u64 << (cpu & 63);
                }
            }
            targets &= residency;
        }
    }
    targets
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
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::AcqRel);

    dispatch_remote(req, req);
}

/// Complete only the remote half of an invalidation whose caller already
/// performed the matching local operation after its final page-table write.
pub fn shootdown_remote(req: ShootdownRequest) {
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::AcqRel);
    dispatch_remote(req, req);
}

/// Remotely flush every non-global entry, but target only CPUs that may hold
/// `residency_tag`. Used by x86 process roots, which all run under flushing
/// PCID 0 and publish exact active residency around scheduler polls.
pub fn shootdown_remote_full_for_tag(residency_tag: u16) {
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::AcqRel);
    dispatch_remote(
        ShootdownRequest::full(),
        ShootdownRequest::for_tag(residency_tag),
    );
}

fn dispatch_remote(payload: ShootdownRequest, residency: ShootdownRequest) {
    // Pair the page-table writer's stores with a CPU's pre-context-load
    // residency publication. Without this StoreLoad barrier, both sides
    // could transiently miss one another on weakly ordered hardware (and on
    // x86 via the local store buffer) even though compiler ordering holds.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Tagged aarch64 TLBI operations already carry the Inner Shareable suffix;
    // issuing an SGI would perform the same invalidation a second time.
    #[cfg(target_arch = "aarch64")]
    if payload.tag.is_some() {
        LOCAL_ONLY_COUNT.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Accounting: BROADCAST_BUDGET is what an unfiltered fan-out
    // would have cost. FILTERED_TARGETS is what we actually IPI'd.
    let online = narf_lib::smp::online_bitmap();
    let self_cpu = narf_lib::percpu::current_cpu();
    let self_bit = 1u64 << (self_cpu & 63);
    let budget = (online & !self_bit).count_ones() as u64;
    BROADCAST_BUDGET.fetch_add(budget, Ordering::Relaxed);

    let candidates = residency_target_mask(residency);
    #[cfg(target_arch = "x86_64")]
    let targets = {
        let idle = IDLE_MASK.load(Ordering::SeqCst);
        let deferred = candidates & idle;
        if deferred != 0 {
            DEFERRED_FULL_FLUSH.fetch_or(deferred, Ordering::SeqCst);
        }
        // Recheck after publishing deferred work. If a CPU raced busy before
        // observing its bit, it appears here and receives the ordinary IPI.
        candidates & !IDLE_MASK.load(Ordering::SeqCst)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let targets = candidates;
    if targets == 0 {
        LOCAL_ONLY_COUNT.fetch_add(1, Ordering::Relaxed);
        return;
    }
    FILTERED_TARGETS.fetch_add(targets.count_ones() as u64, Ordering::Relaxed);
    IPI_FANOUT_COUNT.fetch_add(1, Ordering::Relaxed);
    ipi_fanout(payload, targets);
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

#[doc(hidden)]
pub fn __reset_for_test() {
    SHOOTDOWN_COUNT.store(0, Ordering::Release);
    LOCAL_ONLY_COUNT.store(0, Ordering::Release);
    IPI_FANOUT_COUNT.store(0, Ordering::Release);
    BROADCAST_BUDGET.store(0, Ordering::Release);
    FILTERED_TARGETS.store(0, Ordering::Release);
    for cell in ACTIVE_AS.iter() {
        cell.store(0, Ordering::Release);
    }
    TRACKED_BUCKETS.store(0, Ordering::Release);
    IDLE_MASK.store(0, Ordering::Release);
    DEFERRED_FULL_FLUSH.store(0, Ordering::Release);
    LAZY_FLUSH_COUNT.store(0, Ordering::Release);
}

// ── Tests ────────────────────────────────────────────────────────
//
// Kernel-runner-visible tests (registered via `kernel_test_in!`).
// These run inside the live kernel binary, so they share global
// state with whatever else has touched the bitmap -- every test
// calls `__reset_for_test` first.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_tlb_shootdown_empty_bitmap_broadcasts() -> TestResult {
    // Pre-scheduler boot: no CPU has populated its ACTIVE_AS bitmap.
    // A tag-scoped shootdown's target mask must be exactly the
    // "all online minus self" set -- the filter does NOT activate
    // until at least one CPU has reported residency.
    __reset_for_test();
    let req = ShootdownRequest::for_va(7, 0x1000);
    let mask = shootdown_target_mask(req);
    // In the test environment we're single-CPU (BSP), so the mask
    // collapses to zero by virtue of `online & !self`. The shape
    // we check is that an empty active-AS bitmap doesn't *increase*
    // the broadcast scope, i.e. mask is a subset of online & !self,
    // and that shootdown counts the request as "no peers" rather
    // than panicking.
    let online = narf_lib::smp::online_bitmap();
    let self_cpu = narf_lib::percpu::current_cpu();
    let self_bit = 1u64 << (self_cpu & 63);
    if mask & !(online & !self_bit) != 0 {
        return TestResult::Fail("empty bitmap broadened the target mask");
    }
    // Confirm shootdown itself works end-to-end without crashing
    // and bumps the counter exactly once.
    let before = shootdown_count();
    shootdown(req);
    let after = shootdown_count();
    if after - before != 1 {
        return TestResult::Fail("shootdown_count did not advance");
    }
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_empty_bitmap_broadcasts
);

fn smoke_tlb_shootdown_active_as_filter_skips_unaffected() -> TestResult {
    let _topology = narf_lib::smp::__reset_for_test_scoped();
    // Use IDs outside the live 16-CPU QEMU topology so scheduler idle-state
    // publication by a genuine AP cannot perturb this structural mask test.
    const CPU_A: u32 = 62;
    const CPU_B: u32 = 63;
    narf_lib::smp::__test_fake_online(CPU_A);
    narf_lib::smp::__test_fake_online(CPU_B);
    __reset_for_test();
    // CPU A advertises PCID 7 (bucket 7).
    set_active_as(CPU_A, 7);
    // CPU B advertises PCID 5 (bucket 5).
    set_active_as(CPU_B, 5);
    // Sanity: bitmap accessors reflect what we just published.
    if active_as_bitmap(CPU_A) & (1u64 << 7) == 0 {
        return TestResult::Fail("CPU A didn't latch PCID 7 bucket");
    }
    if active_as_bitmap(CPU_B) & (1u64 << 5) == 0 {
        return TestResult::Fail("CPU B didn't latch PCID 5 bucket");
    }
    // CPU A's PCID-7 residency must not leak into bucket 5.
    if active_as_bitmap(CPU_A) & (1u64 << 5) != 0 {
        return TestResult::Fail("CPU A falsely advertises bucket 5");
    }
    let mask = residency_target_mask(ShootdownRequest::for_va(5, 0x4000));
    if mask & (1u64 << CPU_A) != 0 || mask & (1u64 << CPU_B) == 0 {
        return TestResult::Fail("tracked bucket did not select exact resident peer");
    }
    // Filter consistency: clearing CPU B must drop its bucket-5
    // residency.
    clear_active_as(CPU_B, 5);
    if active_as_bitmap(CPU_B) & (1u64 << 5) != 0 {
        return TestResult::Fail("clear_active_as didn't take effect");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_active_as_filter_skips_unaffected
);

#[cfg(target_arch = "x86_64")]
fn smoke_tlb_shootdown_tracked_empty_and_idle_defer() -> TestResult {
    let _topology = narf_lib::smp::__reset_for_test_scoped();
    const PEER_CPU: u32 = 63;
    narf_lib::smp::__test_fake_online(PEER_CPU);
    __reset_for_test();

    let peer = 1u64 << PEER_CPU;
    // An unrelated tracked bucket must not disable bootstrap broadcast for a
    // bucket whose loads have never been published.
    set_active_as(PEER_CPU, 0);
    if residency_target_mask(ShootdownRequest::for_va(7, 0x4000)) & peer == 0 {
        return TestResult::Fail("unrelated tracking suppressed bootstrap broadcast");
    }

    // Once PCID 0 is tracked, clearing its only resident makes an empty mask
    // authoritative rather than falling back to all peers.
    clear_active_as(PEER_CPU, 0);
    if residency_target_mask(ShootdownRequest::for_va(0, 0x4000)) & peer != 0 {
        return TestResult::Fail("tracked empty bucket fell back to broadcast");
    }

    // An idle resident does not receive an IPI; it owes one full local flush
    // that mark_busy must discharge before its next context load.
    set_active_as(PEER_CPU, 0);
    mark_idle(PEER_CPU);
    let before = lazy_flush_count();
    shootdown_remote(ShootdownRequest::for_range(0, 0x8000, 4));
    if deferred_flush_mask() & peer == 0 {
        return TestResult::Fail("idle target did not acquire deferred flush debt");
    }
    mark_busy(PEER_CPU);
    if deferred_flush_mask() & peer != 0 || lazy_flush_count() != before + 1 {
        return TestResult::Fail("mark_busy did not discharge deferred flush debt");
    }
    __reset_for_test();
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
    __reset_for_test();
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
    __reset_for_test();
    if idle_mask() != 0 {
        return TestResult::Fail("idle_mask not zero after reset");
    }
    mark_idle(2);
    if idle_mask() & (1u64 << 2) == 0 {
        return TestResult::Fail("mark_idle didn't set bit");
    }
    mark_busy(2);
    if idle_mask() & (1u64 << 2) != 0 {
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
    // affected mapping, every shootdown collapses to a local
    // INVPCID and shows up as a +1 in local_only_count with a
    // 0-bit in FILTERED_TARGETS. Force the online-CPU bitmap to
    // a single CPU for the test so the filter has a non-trivial
    // input to work with — the test runs after AP bring-up, where
    // online_bitmap() returns multiple bits and an empty ACTIVE_AS
    // would otherwise leave peers in the target set.
    let online_before = narf_lib::smp::online_bitmap();
    let count_before = narf_lib::smp::cpu_count();
    narf_lib::smp::__reset_for_test();
    __reset_for_test();
    let before_local = local_only_count();
    let before_targets = filtered_targets();
    shootdown(ShootdownRequest::for_va(7, 0x4000));
    shootdown(ShootdownRequest::for_tag(11));
    shootdown_range(3, 0x8000, 4);
    let after_local = local_only_count();
    let after_targets = filtered_targets();
    // Restore the real SMP topology so downstream tests see the
    // live CPU set.
    narf_lib::smp::set_cpu_count(count_before);
    for bit in 0..64u32 {
        if (online_before >> bit) & 1 != 0 {
            // SAFETY: restoring the topology snapshot captured at
            // the top of the test; identity remains the same CPU
            // we observed online a few instructions ago.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_lib::smp::mark_online(bit);
            }
        }
    }
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
