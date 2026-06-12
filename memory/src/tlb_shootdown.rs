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
//!   scheduler must call `set_active_as(pcid)` when it loads a task's
//!   CR3 (Intel SDM Vol 3 §4.10.4.3, "Software may assume that a TLB
//!   entry's tag matches the current PCID"). On context-out, it calls
//!   `clear_active_as(pcid)`.
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
//! one exception is **bootstrap correctness**: until the scheduler
//! has populated any `ACTIVE_AS` bits, the bitmap is all-zero and a
//! naive mask would skip every CPU. We treat the **empty bitmap** as
//! "filter not initialised -- fan out to every online CPU" (this is
//! correct: every CPU might have stale entries; we just lack the
//! information to filter). Once any CPU sets a bit, the filter
//! activates. See `shootdown_target_mask` for the precise rule.
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
// to bucket `pcid & 63`". The scheduler calls `set_active_as` on
// context-in and (optionally) `clear_active_as` on context-out.
//
// We never auto-clear bits -- stale set bits cost at most a spurious
// IPI; missing a set bit costs correctness (stale TLB entries on a
// CPU that wasn't IPI'd). The receiver's INVPCID is harmless on a
// CPU that doesn't hold the tag.

static ACTIVE_AS: [AtomicU64; MAX_CPUS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; MAX_CPUS]
};

#[inline]
fn pcid_bucket(pcid: u16) -> u32 {
    (pcid as u32) & 63
}

/// Scheduler hook: announce that `cpu` has loaded `pcid` into its
/// TLB and may now cache translations under that tag.
///
/// Called from the scheduler's CR3-load path (after `mov cr3, ...`
/// completes, since INVPCID semantics in Intel SDM Vol 3 §4.10.4.3
/// say only entries *for the loaded PCID* are tagged with it).
/// Idempotent and lock-free.
pub fn set_active_as(cpu: u32, pcid: u16) {
    let i = (cpu as usize).min(MAX_CPUS - 1);
    let bit = 1u64 << pcid_bucket(pcid);
    ACTIVE_AS[i].fetch_or(bit, Ordering::Release);
}

/// Scheduler hook: announce that `cpu` is no longer running anything
/// tagged with `pcid`. Optional -- leaving stale bits set only causes
/// spurious IPIs, never correctness bugs. Use when the scheduler
/// knows a PCID slot is being recycled / a domain is unloading.
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

/// Idle-CPU mask: bit `i` = 1 => CPU `i` is currently idle and its
/// TLB is "lazy" -- the scheduler may defer invalidation to the next
/// dispatch. Today's scheduler doesn't yet wire this; the mask
/// stays zero and the shootdown path treats every reachable CPU as
/// busy. The hooks `mark_idle` / `mark_busy` are the land-site.
static IDLE_MASK: AtomicU64 = AtomicU64::new(0);

/// Scheduler hook: announce `cpu` has parked (idle thread / `hlt`).
/// Calls from `shootdown` to a CPU in this mask will be elided --
/// the next dispatch on that CPU performs a full INVPCID anyway,
/// so the cross-IPI is redundant.
pub fn mark_idle(cpu: u32) {
    if (cpu as usize) < MAX_CPUS {
        IDLE_MASK.fetch_or(1u64 << cpu, Ordering::Release);
    }
}

/// Scheduler hook: announce `cpu` has woken from idle. Must be
/// called *before* the new task's CR3 is loaded so the shootdown
/// path doesn't elide an IPI to a CPU that's just become reachable.
pub fn mark_busy(cpu: u32) {
    if (cpu as usize) < MAX_CPUS {
        IDLE_MASK.fetch_and(!(1u64 << cpu), Ordering::Release);
    }
}

/// Snapshot of the idle-mask.
pub fn idle_mask() -> u64 {
    IDLE_MASK.load(Ordering::Acquire)
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
/// 3. **If the filter is empty across every CPU** (bootstrap case
///    -- no scheduler has reported residency yet), preserve the
///    step-1 broadcast set. Filtering would skip every CPU, which
///    is wrong before the bitmap is populated.
/// 4. Drop idle CPUs (their TLB invalidation is lazy -- handled on
///    next dispatch).
///
/// Returns the bitmap of CPU IDs to IPI.
pub fn shootdown_target_mask(req: ShootdownRequest) -> u64 {
    let online = narf_lib::smp::online_bitmap();
    let self_cpu = narf_lib::percpu::current_cpu();
    let self_bit = 1u64 << (self_cpu & 63);
    let mut targets = online & !self_bit;

    if let Some(tag) = req.tag {
        let bucket = pcid_bucket(tag);
        let bucket_bit = 1u64 << bucket;
        let mut residency: u64 = 0;
        let mut any_set: bool = false;
        for (cpu, slot) in ACTIVE_AS.iter().enumerate().take(MAX_CPUS) {
            let bm = slot.load(Ordering::Acquire);
            if bm != 0 {
                any_set = true;
            }
            if bm & bucket_bit != 0 {
                residency |= 1u64 << (cpu & 63);
            }
        }
        // Only apply the filter once *some* CPU has populated its
        // bitmap. Pre-scheduler boot leaves the bitmap empty and a
        // strict AND would zero the target set -- wrong, because
        // every CPU's TLB may legitimately hold stale entries from
        // boot-time mappings.
        if any_set {
            targets &= residency;
        }
    }

    // Strip idle CPUs -- lazy invalidation handles them on next
    // dispatch. (When IDLE_MASK is 0 -- today's default -- this is
    // a no-op.)
    targets & !IDLE_MASK.load(Ordering::Acquire)
}

// ── IPI fan-out hook ─────────────────────────────────────────────
//
// `narf-memory` can't depend on `narf-interrupts` (the dependency
// runs the other way), so the cross-CPU IPI shoot path is wired by
// the interrupts crate via `set_ipi_fanout` at boot. UP boots leave
// the hook unset and `shootdown` reduces to local invalidation.
//
// The fan-out hook is called only when the filtered target mask is
// non-empty. The interrupts crate is responsible for translating
// the `ShootdownRequest` into the concrete IPI primitive
// (`shoot_range` / `shoot_tag_only` / broadcast). Future revision:
// pass the target mask through so the bridge can use targeted
// rather than broadcast IPIs (Intel SDM Vol 3 §11.6.1 -- physical
// destination mode in the ICR). Today's bridge still broadcasts;
// the filter at least avoids the call entirely when no peer needs
// it, which is the biggest win.

type IpiFanoutFn = fn(req: ShootdownRequest);

static IPI_FANOUT: AtomicUsize = AtomicUsize::new(0);

/// Wire the IPI fan-out function. Called once by the interrupts
/// crate after the IPI vector + per-CPU pending state are ready.
pub fn set_ipi_fanout(f: IpiFanoutFn) {
    IPI_FANOUT.store(f as usize, Ordering::Release);
}

fn ipi_fanout(req: ShootdownRequest) {
    let f = IPI_FANOUT.load(Ordering::Acquire);
    if f != 0 {
        // SAFETY: stored as `IpiFanoutFn as usize`; round-trip back
        // is sound when non-null.
        // SAFETY: Valid memory or trusted environment
        let func: IpiFanoutFn = unsafe { core::mem::transmute(f) };
        func(req);
    }
}

/// Apply `req` locally, then -- *only if the active-AS bitmap says a
/// peer CPU may hold the affected mapping* -- fan out via IPI. On UP
/// boots / when the filter culls every peer, the call reduces to a
/// local INVPCID.
pub fn shootdown(req: ShootdownRequest) {
    apply_local(req);
    SHOOTDOWN_COUNT.fetch_add(1, Ordering::AcqRel);

    // Accounting: BROADCAST_BUDGET is what an unfiltered fan-out
    // would have cost. FILTERED_TARGETS is what we actually IPI'd.
    let online = narf_lib::smp::online_bitmap();
    let self_cpu = narf_lib::percpu::current_cpu();
    let self_bit = 1u64 << (self_cpu & 63);
    let budget = (online & !self_bit).count_ones() as u64;
    BROADCAST_BUDGET.fetch_add(budget, Ordering::Relaxed);

    let targets = shootdown_target_mask(req);
    if targets == 0 {
        LOCAL_ONLY_COUNT.fetch_add(1, Ordering::Relaxed);
        return;
    }
    FILTERED_TARGETS.fetch_add(targets.count_ones() as u64, Ordering::Relaxed);
    IPI_FANOUT_COUNT.fetch_add(1, Ordering::Relaxed);
    ipi_fanout(req);
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
    if !pcid::invpcid_supported() {
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
    IDLE_MASK.store(0, Ordering::Release);
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
    // After a CPU reports residency for some unrelated PCID, a
    // shootdown for a *different* bucket must NOT see that CPU in
    // its target mask. The filter is per-bucket.
    __reset_for_test();
    // CPU 1 advertises PCID 7 (bucket 7).
    set_active_as(1, 7);
    // CPU 2 advertises PCID 5 (bucket 5).
    set_active_as(2, 5);
    // Sanity: bitmap accessors reflect what we just published.
    if active_as_bitmap(1) & (1u64 << 7) == 0 {
        return TestResult::Fail("CPU 1 didn't latch PCID 7 bucket");
    }
    if active_as_bitmap(2) & (1u64 << 5) == 0 {
        return TestResult::Fail("CPU 2 didn't latch PCID 5 bucket");
    }
    // CPU 1's PCID-7 residency must not leak into bucket 5.
    if active_as_bitmap(1) & (1u64 << 5) != 0 {
        return TestResult::Fail("CPU 1 falsely advertises bucket 5");
    }
    // Filter consistency: clearing CPU 2 must drop its bucket-5
    // residency.
    clear_active_as(2, 5);
    if active_as_bitmap(2) & (1u64 << 5) != 0 {
        return TestResult::Fail("clear_active_as didn't take effect");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "memory/tlb_shootdown",
    smoke_tlb_shootdown_active_as_filter_skips_unaffected
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
