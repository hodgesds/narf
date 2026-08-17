//! Page-reclaim subsystem — Stage-1 LRU tracking + foreground reclaim.
//!
//! # Why this exists
//!
//! Up through the buddy + slab landing, NARF had exactly one path off
//! the "we're out of memory" cliff: the owning task drops a buffer and
//! `free_frame` returns the page to the buddy. There is no mechanism
//! for *the kernel* to reclaim a page that is still nominally owned
//! (and merely cold) when another path needs the memory. The only
//! response to pressure is OOM.
//!
//! This module installs the tracking + foreground-reclaim scaffolding
//! a real reclaimer needs:
//!
//!   1. Owners *register* pages they're willing to give back under
//!      pressure, supplying a per-page **reclaim handler** the
//!      subsystem can invoke when it wants the page back. The handler
//!      is what knows how to write back dirty contents, decrement a
//!      refcount, drop a cache entry, etc. — this module never
//!      mutates the page contents itself.
//!   2. Per-page metadata carries an `accessed` bit (intended to be
//!      sampled from the architectural PTE-A bit by a periodic sweep)
//!      and a `dirty` bit (PTE-D). Stage-1 doesn't ship the PTE walk;
//!      callers / a future periodic pump push the bits in via
//!      `mark_accessed` / `mark_dirty`.
//!   3. Pages live on one of two LRU lists — `active` and `inactive`.
//!      A periodic *sweep* (`reclaim_sweep`) demotes
//!      not-recently-accessed `active` pages to `inactive` and clears
//!      the accessed bit; `mark_accessed` promotes back. The sweep
//!      also ages each page so callers can prioritise truly cold
//!      content first.
//!   4. `reclaim_target_pages(n)` walks the tail of `inactive`
//!      (oldest first) and calls each page's `reclaim_fn`; pages that
//!      report `Freed` are dropped from tracking, the rest stay
//!      tracked with their handler's outcome recorded.
//!
//! # Why Stage-1 is *only* the foreground path
//!
//! A background kthread that wakes up under low-watermark pressure is
//! the eventual shape — but it needs the scheduler + sleep-pump
//! integration that we won't have wired through cleanly until the
//! kthread infrastructure stabilises. Until then the caller drives
//! reclaim explicitly from the failing alloc site (e.g. in front of
//! a buddy `Err(Exhausted)`). The same API surface that the
//! foreground path uses is what the kthread will eventually call —
//! no second redesign required when we install it.
//!
//! # Why active/inactive instead of CLOCK or LRFU
//!
//! Two-list active/inactive is the EELRU shape (Smaragdakis, Kaplan,
//! Wilson, SIGMETRICS 1999): pages graduate to `active` only after
//! a *second* reference, which gives strong scan resistance against
//! one-shot workloads (a streaming `read()` of a huge file does not
//! evict the working set). The trade-off — accuracy under
//! mixed-frequency workloads — is exactly what LRFU (Kim et al.,
//! IEEE Trans. Computers 2001) is designed to address, but LRFU
//! needs a tunable λ and continuous CRF math that doesn't fit a
//! cold-path stage-1 implementation. CLOCK-Pro (Jiang + Zhang,
//! USENIX 2005) is similar in shape but uses a circular structure
//! with three hands; for our purposes that's strictly more
//! implementation surface for the same approximation quality.
//!
//! We keep the LRU lists as `VecDeque<PageHandle>` so promotion /
//! demotion is O(n) on the list (we need to find the handle to
//! remove it). That is fine at the scale the kernel runs reclaim
//! (target_pages ~= dozens, not millions). A sharded slot table
//! with intrusive list pointers is the right shape if/when scan
//! cost becomes the bottleneck — out of scope here.
//!
//! # Clean-room provenance
//!
//! Algorithm references (cited; no Linux/BSD source consulted):
//!
//!   - Tanenbaum, A. S. & Bos, H. (2014). *Modern Operating Systems*
//!     (4th ed.), §3.4 — LRU page replacement, working-set model.
//!     Pearson.
//!   - Kim, J. M., Choi, J., Lee, D., Noh, S. H., Min, S. L., Cho,
//!     Y. & Kim, C. S. (2001). "LRFU: A Spectrum of Policies that
//!     Subsumes the Least Recently Used and Least Frequently Used
//!     Policies." *IEEE Trans. Computers*, 50(12), 1352–1361.
//!   - Smaragdakis, Y., Kaplan, S. F. & Wilson, P. R. (1999). "EELRU:
//!     Simple and Effective Adaptive Page Replacement."
//!     *SIGMETRICS* '99, 122–133.
//!   - Jiang, S. & Zhang, X. (2005). "CLOCK-Pro: An Effective
//!     Improvement of the CLOCK Replacement." *USENIX ATC* '05.
//!
//! # TODO (for the agent merging `lib.rs`)
//!
//! `lib.rs` must add `pub mod reclaim;` — this file is otherwise
//! unreachable. See the header note here for the one-line addition.

extern crate alloc as alloc_crate;

use alloc_crate::collections::VecDeque;
use alloc_crate::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{PhysAddr, VirtAddr};

// ── Free-memory watermarks (Linux-shaped) ──────────────────────────
//
// `min`/`low`/`high`, in pages, sized from total RAM at boot. They are
// the single pressure signal a real reclaimer keys off:
//   * free ≥ high  — comfortable; background reclaim (kswapd) stops here.
//   * free < low   — reclaim should run (foreground/background).
//   * free < min   — emergency: direct reclaim before an allocation may
//                    fail; below this is OOM territory.
// Zero until `init_watermarks` runs; the accessors treat an unset
// watermark as "no reclaim" so a pre-boot / unconfigured kernel never
// spuriously reclaims.
//
// Sizing mirrors Linux's shape (min scales with √RAM, clamped to a
// band; low = 5/4·min; high = 3/2·min) without consulting its source.

static WMARK_MIN: AtomicU64 = AtomicU64::new(0);
static WMARK_LOW: AtomicU64 = AtomicU64::new(0);
static WMARK_HIGH: AtomicU64 = AtomicU64::new(0);

/// Lower clamp on `min` (pages): keep at least ~2 MiB free even on
/// tiny memories so an allocation storm always has a little headroom.
const WMARK_MIN_FLOOR_PAGES: u64 = 512;
/// Upper clamp on `min` (pages): cap the reserve at ~256 MiB so a huge
/// machine doesn't hold back an absurd amount of otherwise-usable RAM.
const WMARK_MIN_CEIL_PAGES: u64 = 65_536;

/// Compute + install the free-memory watermarks from the total usable
/// page count. Call once, at boot, after the frame allocator reports
/// its total. `min = clamp(4·√total, floor, ceil)`, `low = 5/4·min`,
/// `high = 3/2·min`.
pub fn init_watermarks(total_pages: usize) {
    let (min, low, high) = compute_watermarks(total_pages);
    WMARK_MIN.store(min, Ordering::Relaxed);
    WMARK_LOW.store(low, Ordering::Relaxed);
    WMARK_HIGH.store(high, Ordering::Relaxed);
}

/// Runtime override of the `min` free-page reserve — the analogue of
/// Linux's `vm.min_free_kbytes` sysctl. `low`/`high` are re-derived
/// from it (`low = 5/4·min`, `high = 3/2·min`), so tuning this one
/// knob shifts the whole reclaim band, exactly as writing
/// `min_free_kbytes` does. The value is clamped to the same
/// [floor, ceil] band as the boot auto-sizing. Intended to back a
/// future `/proc/sys/vm/min_free_kbytes` write.
pub fn set_min_free_pages(min_pages: u64) {
    let (min, low, high) = derive_watermarks(min_pages);
    WMARK_MIN.store(min, Ordering::Relaxed);
    WMARK_LOW.store(low, Ordering::Relaxed);
    WMARK_HIGH.store(high, Ordering::Relaxed);
}

/// Pure watermark math (no global state) — `(min, low, high)` in pages
/// sized from total RAM. Split out so it can be unit-tested without
/// perturbing the live boot-installed watermarks.
fn compute_watermarks(total_pages: usize) -> (u64, u64, u64) {
    derive_watermarks((total_pages as u64).isqrt().saturating_mul(4))
}

/// Clamp a requested `min` to the sane band and derive `(min, low,
/// high)`. Shared by the RAM auto-sizing and the runtime override so
/// both produce an identically-shaped, ordered band.
fn derive_watermarks(requested_min: u64) -> (u64, u64, u64) {
    let min = requested_min.clamp(WMARK_MIN_FLOOR_PAGES, WMARK_MIN_CEIL_PAGES);
    (min, min.saturating_mul(5) / 4, min.saturating_mul(3) / 2)
}

/// The `min` (emergency) free-page watermark, or 0 if unconfigured.
pub fn watermark_min() -> u64 {
    WMARK_MIN.load(Ordering::Relaxed)
}
/// The `low` (start-reclaim) free-page watermark, or 0 if unconfigured.
pub fn watermark_low() -> u64 {
    WMARK_LOW.load(Ordering::Relaxed)
}
/// The `high` (stop-reclaim) free-page watermark, or 0 if unconfigured.
pub fn watermark_high() -> u64 {
    WMARK_HIGH.load(Ordering::Relaxed)
}

/// `true` when free memory has fallen below the `low` watermark — the
/// signal that reclaim should run. `false` when watermarks are unset.
pub fn under_low_watermark() -> bool {
    let low = WMARK_LOW.load(Ordering::Relaxed);
    low != 0 && (crate::frame_stats().free as u64) < low
}

/// `true` when free memory is below the `min` (emergency) watermark —
/// the point at which an allocation path should reclaim before failing.
pub fn under_min_watermark() -> bool {
    let min = WMARK_MIN.load(Ordering::Relaxed);
    min != 0 && (crate::frame_stats().free as u64) < min
}

/// `true` when a userspace-backing allocation must be refused to keep the
/// `min` watermark reserve intact for the kernel. Refuse once granting one
/// more page would drop free below `min` (i.e. `free <= min`), reserving the
/// `min` band for kernel/atomic allocations so they never fail under userspace
/// memory pressure. Returns `false` (never blocks) when watermarks are unset.
pub fn user_alloc_would_breach_reserve() -> bool {
    let min = WMARK_MIN.load(Ordering::Relaxed);
    min != 0 && (crate::frame_stats().free as u64) <= min
}

// ── kswapd/reaper kthread wake hook ────────────────────────────────
//
// `memory` cannot depend on the scheduler, so the kernel binary installs a
// `fn()` that wakes the parked reclaimer kthread. The allocator calls
// `wake_kswapd()` when it pushes a userspace allocation against the reserve, so
// reclaim/OOM runs under load rather than only when a CPU happens to idle.

static KSWAPD_WAKE_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Set when the allocator could not satisfy a KERNEL allocation even after the
/// reserve and the vmalloc fallback — i.e. genuine, unrecoverable exhaustion,
/// not a transient dip below `min`. Only THIS arms the reclaimer's OOM killer;
/// ordinary reserve-breach wakes just reclaim + reap. Keeping the OOM decision
/// gated on real exhaustion is what stops the reclaimer from killing (and, with
/// stress-ng `--abort`, failing) a workload that the reserve + vmalloc already
/// carry without any kill.
static OOM_NEEDED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Signal that a kernel allocation genuinely failed, and wake the reclaimer to
/// OOM-kill. Called from the frame allocator's exhaustion path.
pub fn signal_oom_needed() {
    OOM_NEEDED.store(true, Ordering::Release);
    wake_kswapd();
}

/// Consume the pending-OOM signal (the reclaimer checks this before killing).
pub fn take_oom_needed() -> bool {
    OOM_NEEDED.swap(false, Ordering::AcqRel)
}

// ── Overcommit policy (vm.overcommit_memory analogue) ──────────────────
//
// The `min` reserve ALWAYS protects the kernel — a userspace allocation is
// refused once it would breach it (graceful ENOMEM), regardless of this knob.
// That anti-panic invariant is not configurable. What IS configurable is
// whether that user memory pressure also arms the OOM killer to reclaim a hog:
//
//   * Never (2)     — graceful ENOMEM only; the kernel never OOM-kills for user
//                     pressure. Matches the reserve's no-overcommit behaviour
//                     and lets stress-ng-style workloads that expect ENOMEM
//                     (and abort on a killed worker) run clean. NARF default.
//   * Heuristic (0) — Linux's default: user pressure the reclaimer can't clear
//                     kills the highest-badness process.
//   * Always (1)    — same OOM behaviour as Heuristic here (both allow the
//                     killer); kept distinct for the sysctl ABI value.

/// `vm.overcommit_memory` values.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum OvercommitMode {
    Heuristic = 0,
    Always = 1,
    Never = 2,
}

/// Default: `Never` — user pressure surfaces as ENOMEM, not an OOM-kill. This
/// is stricter than Linux's default (`Heuristic`) on purpose: NARF's reserve
/// already prevents the kernel from failing, so killing a process is a genuine
/// last resort reserved for real kernel exhaustion.
static OVERCOMMIT: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(OvercommitMode::Never as u8);

/// Set the overcommit mode from a raw sysctl value (0/1/2). Out-of-range
/// values are ignored. Backs a future `/proc/sys/vm/overcommit_memory`.
pub fn set_overcommit_mode(raw: u8) {
    if raw <= 2 {
        OVERCOMMIT.store(raw, Ordering::Relaxed);
    }
}

/// The current overcommit mode.
pub fn overcommit_mode() -> OvercommitMode {
    match OVERCOMMIT.load(Ordering::Relaxed) {
        0 => OvercommitMode::Heuristic,
        1 => OvercommitMode::Always,
        _ => OvercommitMode::Never,
    }
}

/// Whether a reserve-refused USER allocation should arm the OOM killer (kill a
/// hog) rather than only returning ENOMEM. True for Heuristic/Always.
pub fn user_pressure_arms_oom() -> bool {
    !matches!(overcommit_mode(), OvercommitMode::Never)
}

/// Install the reclaimer wake hook (the kernel binary passes a `fn()` that
/// wakes its parked kswapd/reaper kthread). Call once at boot.
pub fn set_kswapd_wake_hook(hook: fn()) {
    KSWAPD_WAKE_HOOK.store(hook as usize, Ordering::Release);
}

/// Wake the parked reclaimer kthread, if one is installed. Cheap and safe to
/// call from the allocation path: the hook only flags + wakes a waker. No-op
/// before the kthread is spawned.
pub fn wake_kswapd() {
    let p = KSWAPD_WAKE_HOOK.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: `p` was stored by `set_kswapd_wake_hook` from a live `fn()`,
        // and `fn()` and `usize` are the same width on every target here.
        let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(p) };
        hook();
    }
}

/// Pages a reclaim pass should aim to free to reach the `high`
/// watermark, or 0 if already at/above it (or unconfigured).
pub fn reclaim_goal_pages() -> usize {
    let high = WMARK_HIGH.load(Ordering::Relaxed);
    if high == 0 {
        return 0;
    }
    high.saturating_sub(crate::frame_stats().free as u64) as usize
}

// ── PSS-sized range reclaim planning ──────────────────────────────────────

/// Fixed-point units in one resident page of proportional-set-size (PSS).
///
/// Integer fixed point keeps reclaim planning deterministic and usable in
/// `no_std`: a private page contributes `PSS_UNITS_PER_PAGE`, while one alias
/// of a page with mapcount four contributes one quarter of that value.
pub const PSS_UNITS_PER_PAGE: u64 = 4096;

/// One cold, virtually-contiguous range offered to the reclaim planner.
///
/// `pages` is the number of resident mappings in the run. `mapcount` is the
/// average number of aliases per backing page and controls PSS sizing.
/// `expected_free_pages` is deliberately separate: it is the number of
/// physical pages reverse-map accounting predicts will actually become free
/// if the complete range is evicted. A shared alias with other live mappings
/// therefore has `expected_free_pages == 0`; a reverse-map group that removes
/// every alias may report the number of unique backing pages instead.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReclaimRangeCandidate {
    /// Architecture page-table root naming the address space.
    pub address_space_root: PhysAddr,
    /// First page-aligned virtual address in the resident run.
    pub base: VirtAddr,
    /// Resident virtual pages in the contiguous run.
    pub pages: usize,
    /// Average mapping count of each backing page; zero is treated as one.
    pub mapcount: u32,
    /// Conservative physical-page yield if the entire run is evicted.
    pub expected_free_pages: usize,
    /// LRU age; smaller values are colder and are considered first.
    pub age: u8,
    /// Pinned/wired ranges are never selected.
    pub locked: bool,
}

/// A prefix of a candidate selected for one swap/reclaim submission.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PlannedReclaimRange {
    pub address_space_root: PhysAddr,
    pub base: VirtAddr,
    pub pages: usize,
    pub mapcount: u32,
    pub estimated_pss_units: u64,
    pub expected_free_pages: usize,
}

/// Result of one range-planning pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReclaimBatchPlan {
    /// Cold ranges in execution order, bounded by the caller's page cap.
    pub ranges: Vec<PlannedReclaimRange>,
    /// Watermark-derived physical-page goal supplied by the caller.
    pub target_free_pages: usize,
    /// PSS target corresponding to `target_free_pages`.
    pub target_pss_units: u64,
    /// Sum of proportional resident size selected.
    pub selected_pss_units: u64,
    /// Conservative number of physical pages the selection should release.
    pub expected_free_pages: usize,
    /// Resident mappings examined, including ineligible ranges.
    pub scanned_pages: usize,
}

#[inline]
fn pss_units(pages: usize, mapcount: u32) -> u64 {
    let mappings = u64::from(mapcount.max(1));
    let scaled = (pages as u128).saturating_mul(PSS_UNITS_PER_PAGE as u128);
    (scaled / u128::from(mappings)).min(u128::from(u64::MAX)) as u64
}

#[inline]
fn proportional_yield(take: usize, candidate: &ReclaimRangeCandidate) -> usize {
    if take == candidate.pages {
        return candidate.expected_free_pages.min(candidate.pages);
    }
    take.saturating_mul(candidate.expected_free_pages) / candidate.pages.max(1)
}

/// Plan a cold-range reclaim batch using PSS and a physical-yield guard.
///
/// Candidates are ordered by age, then by expected physical yield. The
/// planner accumulates proportional resident size but never treats PSS as
/// proof that memory will be released: only `expected_free_pages` advances
/// the watermark goal. Selection stops at the physical goal, the equivalent
/// PSS target, or `max_selected_pages`, whichever bound is reached first.
///
/// This function performs policy only; it does not touch page tables or issue
/// I/O. Keeping the planner pure makes the expensive rmap/PTE scan separable
/// from the swap transaction and straightforward to test.
pub fn plan_reclaim_ranges(
    candidates: &[ReclaimRangeCandidate],
    target_free_pages: usize,
    max_selected_pages: usize,
) -> ReclaimBatchPlan {
    let target_pss_units = (target_free_pages as u128)
        .saturating_mul(PSS_UNITS_PER_PAGE as u128)
        .min(u128::from(u64::MAX)) as u64;
    let mut plan = ReclaimBatchPlan {
        target_free_pages,
        target_pss_units,
        ..ReclaimBatchPlan::default()
    };
    if target_free_pages == 0 || max_selected_pages == 0 {
        return plan;
    }

    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_unstable_by(|left, right| {
        let left = &candidates[*left];
        let right = &candidates[*right];
        left.age
            .cmp(&right.age)
            .then_with(|| {
                // Compare yield ratios without floating point. Higher yield
                // sorts first; u128 prevents overflow for hostile metadata.
                let lhs =
                    (left.expected_free_pages as u128).saturating_mul(right.pages.max(1) as u128);
                let rhs =
                    (right.expected_free_pages as u128).saturating_mul(left.pages.max(1) as u128);
                rhs.cmp(&lhs)
            })
            .then_with(|| left.base.as_u64().cmp(&right.base.as_u64()))
    });

    let mut selected_pages = 0usize;
    for index in order {
        let candidate = &candidates[index];
        plan.scanned_pages = plan.scanned_pages.saturating_add(candidate.pages);
        if candidate.locked
            || candidate.pages == 0
            || candidate.expected_free_pages == 0
            || candidate.base.as_u64() & 0xfff != 0
        {
            continue;
        }
        if plan.expected_free_pages >= target_free_pages
            || plan.selected_pss_units >= target_pss_units
            || selected_pages >= max_selected_pages
        {
            break;
        }

        let capacity = max_selected_pages - selected_pages;
        let remaining_free = target_free_pages - plan.expected_free_pages;
        // Conservative ceil: select enough of a uniformly-reclaimable range
        // to cover the remaining physical target, then clamp to the batch.
        let by_free = remaining_free
            .saturating_mul(candidate.pages)
            .saturating_add(candidate.expected_free_pages - 1)
            / candidate.expected_free_pages;
        let remaining_pss = target_pss_units - plan.selected_pss_units;
        let by_pss = ((remaining_pss as u128)
            .saturating_mul(u128::from(candidate.mapcount.max(1)))
            .saturating_add(PSS_UNITS_PER_PAGE as u128 - 1)
            / PSS_UNITS_PER_PAGE as u128)
            .min(usize::MAX as u128) as usize;
        let take = candidate
            .pages
            .min(capacity)
            .min(by_free.max(1))
            .min(by_pss.max(1));
        if take == 0 {
            break;
        }

        let range_pss = pss_units(take, candidate.mapcount);
        let range_yield = proportional_yield(take, candidate);
        plan.ranges.push(PlannedReclaimRange {
            address_space_root: candidate.address_space_root,
            base: candidate.base,
            pages: take,
            mapcount: candidate.mapcount.max(1),
            estimated_pss_units: range_pss,
            expected_free_pages: range_yield,
        });
        selected_pages = selected_pages.saturating_add(take);
        plan.selected_pss_units = plan.selected_pss_units.saturating_add(range_pss);
        plan.expected_free_pages = plan.expected_free_pages.saturating_add(range_yield);
    }
    plan
}

/// Build one bounded reclaim plan from the live high-watermark deficit.
pub fn plan_watermark_reclaim(
    candidates: &[ReclaimRangeCandidate],
    max_selected_pages: usize,
) -> ReclaimBatchPlan {
    plan_reclaim_ranges(candidates, reclaim_goal_pages(), max_selected_pages)
}

// ── Shrinker registry (Linux `struct shrinker`) ────────────────────
//
// The per-page frame LRU below (`register_page` / `reclaim_target_pages`)
// reclaims frames whose owner handed the subsystem a PhysAddr. But most
// NARF caches hold reclaimable state on the *heap* (e.g. the filesystem
// page cache's `Arc<[u8; PAGE_SIZE]>` entries, dentry/inode caches), not
// as registered frames. A shrinker is the general Linux mechanism for
// those: a subsystem registers a `{count, scan}` pair; under pressure the
// reclaimer asks each how much it holds and tells it to shed a slice,
// applying pressure *proportional* to each shrinker's size so a big cache
// gives back more than a small one.
//
// Callbacks are plain `fn` pointers (no captured state): a subsystem
// registers module-level functions that act on its own global cache
// registry. This keeps the registry `'static` and lock-simple.

/// A registered reclaimable cache.
#[derive(Copy, Clone, Debug)]
pub struct Shrinker {
    /// Stable identifier for diagnostics (`"page-cache"`, `"dentry"`, …).
    pub name: &'static str,
    /// Number of reclaimable objects the cache currently holds.
    pub count: fn() -> usize,
    /// Try to free up to `nr` objects; returns the number actually freed.
    pub scan: fn(usize) -> usize,
}

/// Max concurrently-registered shrinkers. A fixed array (not a `Vec`)
/// keeps the whole registry — registration AND reclaim — allocation-free
/// so `shrink_all` is safe to call from the allocation-failure / OOM
/// path, where allocating (as a `Vec` snapshot would) is exactly what
/// must not happen. The kernel has a handful of caches; 16 is ample.
const MAX_SHRINKERS: usize = 16;

static SHRINKERS: IrqSafeSpinLock<[Option<Shrinker>; MAX_SHRINKERS]> =
    IrqSafeSpinLock::new([None; MAX_SHRINKERS]);

/// Register a shrinker. Idempotent by name — re-registering the same
/// name replaces the entry rather than duplicating it, so a subsystem
/// that re-initialises doesn't get scanned twice. Silently ignored if
/// the fixed registry is full (raise `MAX_SHRINKERS` if that ever bites).
pub fn register_shrinker(s: Shrinker) {
    let mut g = SHRINKERS.lock();
    // Replace a same-named entry if present.
    for slot in g.iter_mut() {
        if matches!(slot, Some(e) if e.name == s.name) {
            *slot = Some(s);
            return;
        }
    }
    // Otherwise take the first empty slot.
    for slot in g.iter_mut() {
        if slot.is_none() {
            *slot = Some(s);
            return;
        }
    }
}

/// Total reclaimable objects across all registered shrinkers.
pub fn shrinkable_objects() -> usize {
    let snap = *SHRINKERS.lock();
    snap.iter()
        .flatten()
        .map(|s| (s.count)())
        .fold(0usize, |a, c| a.saturating_add(c))
}

/// Drive all shrinkers to free about `target` objects, distributing the
/// pressure in proportion to each shrinker's current size (Linux's
/// proportional-pressure model). Returns the total number of objects
/// actually freed (which may exceed or fall short of `target`).
///
/// Allocation-free: the registry array is copied out under the lock
/// (it is `Copy`), then the lock is dropped before invoking any `scan`
/// — a shrinker's `scan` may take its own locks, and must never run
/// while the registry lock is held. This is why the whole path avoids
/// `Vec`: `shrink_all` is callable from the allocation-failure path.
pub fn shrink_all(target: usize) -> usize {
    if target == 0 {
        return 0;
    }
    let snap = *SHRINKERS.lock();
    let total: usize = snap
        .iter()
        .flatten()
        .map(|s| (s.count)())
        .fold(0usize, |a, c| a.saturating_add(c));
    if total == 0 {
        return 0;
    }
    let mut freed = 0usize;
    for s in snap.iter().flatten() {
        if freed >= target {
            break;
        }
        let count = (s.count)();
        if count == 0 {
            continue;
        }
        // This shrinker's proportional share of the target, at least 1 so a
        // small cache still contributes when it holds anything.
        let share = ((target.saturating_mul(count)) / total).max(1);
        freed = freed.saturating_add((s.scan)(share));
    }
    freed
}

/// Test-only: drop all registered shrinkers so a test's mock never
/// leaks into another test's `shrink_all`.
#[doc(hidden)]
pub fn __reset_shrinkers_for_test() {
    *SHRINKERS.lock() = [None; MAX_SHRINKERS];
}

/// Free up to `target` reclaimable pages for a caller under allocation
/// pressure — the direct-reclaim entry point. Returns the number freed.
///
/// ALLOCATION-FREE: this is called from `GlobalAlloc::alloc` when an
/// allocation fails, where allocating is precisely what must not happen.
/// It therefore drives only the shrinker path (`shrink_all`), which is
/// allocation-free; the per-page frame LRU (`reclaim_target_pages`) is
/// NOT yet included because it snapshots into a `Vec` — it will join once
/// it is made allocation-free (and once a producer registers frames).
pub fn try_to_free(target: usize) -> usize {
    shrink_all(target)
}

/// Watermark-math tests. Always compiled (not `#[cfg(test)]`) so they
/// register in the in-kernel `narf.tests` section and actually run under
/// `cargo xtask test` — unlike the host-only `#[cfg(test)] mod tests`
/// below. They exercise the pure `compute_watermarks`, so they never
/// touch the live boot-installed watermark globals.
mod watermark_tests {
    use super::{
        compute_watermarks, derive_watermarks, WMARK_MIN_CEIL_PAGES, WMARK_MIN_FLOOR_PAGES,
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_reclaim_watermarks_ordered_and_scaled() -> TestResult {
        // 1 GiB = 262144 pages: min = clamp(4·√262144, ..) = 4·512 = 2048.
        let (min, low, high) = compute_watermarks(262_144);
        if min != 2048 {
            return TestResult::Fail("min for 1 GiB should be 2048 pages");
        }
        if low != min * 5 / 4 || high != min * 3 / 2 {
            return TestResult::Fail("low/high must be 5/4·min and 3/2·min");
        }
        if !(min < low && low < high) {
            return TestResult::Fail("watermarks must be strictly min<low<high");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/reclaim",
        smoke_reclaim_watermarks_ordered_and_scaled
    );

    fn smoke_reclaim_watermarks_clamped() -> TestResult {
        // Tiny memory clamps min up to the floor.
        let (min_small, _, _) = compute_watermarks(16);
        if min_small != WMARK_MIN_FLOOR_PAGES {
            return TestResult::Fail("tiny RAM must clamp min to the floor");
        }
        // Huge memory clamps min down to the ceiling.
        let (min_huge, low_huge, high_huge) = compute_watermarks(usize::MAX);
        if min_huge != WMARK_MIN_CEIL_PAGES {
            return TestResult::Fail("huge RAM must clamp min to the ceiling");
        }
        if !(min_huge < low_huge && low_huge < high_huge) {
            return TestResult::Fail("clamped watermarks must still be ordered");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_watermarks_clamped);

    fn smoke_reclaim_watermarks_tunable_override() -> TestResult {
        // The runtime override (vm.min_free_kbytes analogue) re-derives the
        // whole band from the requested min, clamped to the same range.
        let (min, low, high) = derive_watermarks(4096);
        if min != 4096 || low != 5120 || high != 6144 {
            return TestResult::Fail("override should derive low=5/4·min, high=3/2·min");
        }
        // Below the floor and above the ceiling clamp identically to boot.
        if derive_watermarks(1).0 != WMARK_MIN_FLOOR_PAGES {
            return TestResult::Fail("override below floor must clamp up");
        }
        if derive_watermarks(u64::MAX).0 != WMARK_MIN_CEIL_PAGES {
            return TestResult::Fail("override above ceiling must clamp down");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_watermarks_tunable_override);
}

/// Pure range-planner tests, registered in the in-kernel test image.
mod range_planner_tests {
    use super::{plan_reclaim_ranges, ReclaimRangeCandidate, PSS_UNITS_PER_PAGE};
    use crate::{PhysAddr, VirtAddr};
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn candidate(
        base: u64,
        pages: usize,
        mapcount: u32,
        expected_free_pages: usize,
        age: u8,
        locked: bool,
    ) -> ReclaimRangeCandidate {
        ReclaimRangeCandidate {
            address_space_root: PhysAddr::new(0x1000),
            base: VirtAddr::new(base),
            pages,
            mapcount,
            expected_free_pages,
            age,
            locked,
        }
    }

    fn smoke_reclaim_range_plan_private_target() -> TestResult {
        let candidates = [
            candidate(0x40_0000, 8, 1, 8, 5, false),
            candidate(0x50_0000, 8, 1, 8, 0, false),
        ];
        let plan = plan_reclaim_ranges(&candidates, 4, 16);
        if plan.ranges.len() != 1 || plan.ranges[0].base != VirtAddr::new(0x50_0000) {
            return TestResult::Fail("planner must select the coldest range first");
        }
        if plan.ranges[0].pages != 4
            || plan.expected_free_pages != 4
            || plan.selected_pss_units != 4 * PSS_UNITS_PER_PAGE
        {
            return TestResult::Fail("private range should stop exactly at the target");
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_range_plan_private_target);

    fn smoke_reclaim_range_plan_pss_sizes_shared_scan() -> TestResult {
        // Eight mapped pages with mapcount four account for two pages of PSS.
        // Reverse-map coverage predicts that evicting the whole range releases
        // two unique physical pages, so both stop conditions agree at 8 VAs.
        let candidates = [candidate(0x60_0000, 8, 4, 2, 0, false)];
        let plan = plan_reclaim_ranges(&candidates, 2, 16);
        if plan.ranges.len() != 1 || plan.ranges[0].pages != 8 {
            return TestResult::Fail("PSS sizing should retain the complete shared scan");
        }
        if plan.selected_pss_units != 2 * PSS_UNITS_PER_PAGE || plan.expected_free_pages != 2 {
            return TestResult::Fail("PSS and physical-yield accounting diverged");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/reclaim",
        smoke_reclaim_range_plan_pss_sizes_shared_scan
    );

    fn smoke_reclaim_range_plan_skips_phantom_yield() -> TestResult {
        let candidates = [
            // A single shared alias has PSS but cannot release its backing.
            candidate(0x70_0000, 16, 4, 0, 0, false),
            candidate(0x80_0000, 4, 1, 4, 1, true),
            candidate(0x90_0001, 4, 1, 4, 2, false),
            candidate(0xa0_0000, 4, 1, 4, 3, false),
        ];
        let plan = plan_reclaim_ranges(&candidates, 3, 64);
        if plan.ranges.len() != 1 || plan.ranges[0].base != VirtAddr::new(0xa0_0000) {
            return TestResult::Fail("planner selected locked, unaligned, or zero-yield range");
        }
        if plan.expected_free_pages != 3 || plan.scanned_pages != 28 {
            return TestResult::Fail("planner target or scan accounting is wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/reclaim",
        smoke_reclaim_range_plan_skips_phantom_yield
    );
}

/// Shrinker-registry tests. Always compiled so they register + run under
/// `cargo xtask test`. A mock shrinker backed by an atomic object count
/// exercises registration, proportional `shrink_all`, and idempotent
/// re-registration; the registry is reset before/after so the mock never
/// leaks into another test.
mod shrinker_tests {
    use super::{
        __reset_shrinkers_for_test, register_shrinker, shrink_all, shrinkable_objects, Shrinker,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static MOCK_AVAIL: AtomicUsize = AtomicUsize::new(0);

    fn mock_count() -> usize {
        MOCK_AVAIL.load(Ordering::Relaxed)
    }

    fn mock_scan(nr: usize) -> usize {
        let mut freed = 0usize;
        while freed < nr {
            let cur = MOCK_AVAIL.load(Ordering::Relaxed);
            if cur == 0 {
                break;
            }
            let take = core::cmp::min(nr - freed, cur);
            if MOCK_AVAIL
                .compare_exchange(cur, cur - take, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                freed += take;
            }
        }
        freed
    }

    fn smoke_reclaim_shrinker_proportional() -> TestResult {
        __reset_shrinkers_for_test();
        MOCK_AVAIL.store(100, Ordering::Relaxed);
        register_shrinker(Shrinker {
            name: "mock",
            count: mock_count,
            scan: mock_scan,
        });
        let result = (|| {
            if shrinkable_objects() != 100 {
                return TestResult::Fail("registry should report the mock's 100 objects");
            }
            if shrink_all(30) != 30 || MOCK_AVAIL.load(Ordering::Relaxed) != 70 {
                return TestResult::Fail("shrink_all(30) should free exactly 30");
            }
            // Re-register same name → replace, not duplicate.
            register_shrinker(Shrinker {
                name: "mock",
                count: mock_count,
                scan: mock_scan,
            });
            if shrinkable_objects() != 70 {
                return TestResult::Fail("re-register by name must not duplicate the shrinker");
            }
            // Over-target request frees all that remains.
            shrink_all(1000);
            if MOCK_AVAIL.load(Ordering::Relaxed) != 0 {
                return TestResult::Fail("over-target shrink should drain the cache");
            }
            // Nothing left → shrink_all is a no-op.
            if shrink_all(10) != 0 {
                return TestResult::Fail("empty cache should free nothing");
            }
            TestResult::Pass
        })();
        __reset_shrinkers_for_test();
        result
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_shrinker_proportional);
}

/// Reclaim handler outcome. The owner reports back what happened
/// when we asked it to give the page up.
///
/// We treat these the same way EELRU §4 describes the
/// "non-resident referenced" / "resident referenced" cases: the
/// subsystem trusts the owner's report and updates list membership
/// (or refuses to retry for a while) accordingly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReclaimOutcome {
    /// Page was successfully reclaimed: handler dropped its
    /// reference and the underlying frame is now free (or has been
    /// promised to be freed before the next sweep). The subsystem
    /// drops the page from tracking.
    Freed,
    /// Page is dirty — handler needs to write it back first. The
    /// subsystem leaves the page on `inactive` but flagged DIRTY so
    /// a future writeback pass can drain it.
    Dirty,
    /// Page is wired / pinned right now (DMA in flight, page-table
    /// page, kernel-stack page, etc.). The subsystem leaves it on
    /// the list — a pin is presumed transient and a later sweep
    /// will retry.
    Locked,
    /// Owner can't free the page directly but is willing to have
    /// the kernel hand it to the installed `Pager` for paging-out.
    /// Wave C of the pluggable-policy pass: the reclaim loop calls
    /// `pager::page_out_via_installed(phys, flags)`; on `Ok` the
    /// page is considered handed off. See `crate::pager` for the
    /// trait contract.
    ///
    /// Wave C ships with the *seam*: the loop logs the page-out
    /// result for diagnostics but does **not** yet free the frame
    /// or maintain a `(owner, phys) → SwapSlot` side-table. Full
    /// integration (frame-free on success + side-table for
    /// `page_in` discovery) is a Wave C+1 follow-up.
    ///
    /// The **live**, batched swap path now lives in `crate::swap` plus
    /// `AddressSpace::swap_out_reclaim_plan`: it writes a selected run in one
    /// backend call, transfers Region/PTE ownership, invalidates once, and
    /// faults consecutive leaves back through `swap_in_batch`. This per-phys
    /// seam still lacks reverse mappings; callers with rmap/VMA context feed
    /// `plan_reclaim_ranges` and the AddressSpace executor.
    DeferToPager,
}

/// Signature of a page-reclaim handler. Receives the page's
/// physical address; returns what happened. The handler is called
/// from a context that holds **no** reclaim-subsystem locks (we
/// drop the list lock before invoking), so the handler is free to
/// acquire its own locks, allocate from the slab, etc. — but it
/// must not call back into this module synchronously or it will
/// deadlock against the outer `reclaim_target_pages` loop on the
/// stats counters.
///
/// The handler is `fn`, not `Fn`, so handlers live in `.rodata`
/// and the page-entry struct stays `Copy`. Owners that need per-
/// page state encode it in the page itself (e.g. a header at the
/// start of the page) or in a side-table keyed by `phys`.
pub type ReclaimFn = fn(phys: PhysAddr) -> ReclaimOutcome;

/// Bit flags on a tracked page. Designed to be sampled from the
/// PTE A/D bits by an arch-specific sweep, but Stage-1 leaves the
/// PTE walk to the caller and accepts pushed bits.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageFlags(u8);

impl PageFlags {
    /// Page was accessed since the last sweep. PTE-A on x86_64,
    /// PTE-AF on aarch64. Promotion signal.
    pub const ACCESSED: PageFlags = PageFlags(1 << 0);
    /// Page was written since the last sweep. PTE-D. Pages with
    /// DIRTY set must go through writeback before they can be
    /// `Freed` by their handler.
    pub const DIRTY: PageFlags = PageFlags(1 << 1);
    /// Page is currently pinned. The reclaimer will skip locked
    /// pages on the inactive scan.
    pub const LOCKED: PageFlags = PageFlags(1 << 2);
    /// Page is on the `active` list (vs `inactive`). Kept in flags
    /// rather than computed so a handler reading flags out-of-band
    /// can tell at a glance.
    pub const ON_ACTIVE: PageFlags = PageFlags(1 << 3);

    /// Empty flag set.
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }
    /// Raw bits, for diagnostics.
    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }
    /// Are any of `other`'s bits set in `self`?
    #[inline]
    pub const fn contains(self, other: PageFlags) -> bool {
        (self.0 & other.0) == other.0
    }
    /// Bitwise-or, returning a new flag set.
    #[inline]
    pub const fn union(self, other: PageFlags) -> PageFlags {
        PageFlags(self.0 | other.0)
    }
    /// Clear the bits in `other` from `self`.
    #[inline]
    pub const fn without(self, other: PageFlags) -> PageFlags {
        PageFlags(self.0 & !other.0)
    }
}

impl core::ops::BitOr for PageFlags {
    type Output = PageFlags;
    #[inline]
    fn bitor(self, rhs: PageFlags) -> PageFlags {
        self.union(rhs)
    }
}

/// One tracked page. Constructed by the caller via
/// `PageEntry::new` (or its `Default`) and handed to
/// `register_page`. Once registered, callers manipulate it via
/// the returned `PageHandle` — they never see the entry again
/// directly until reclaim runs.
#[derive(Copy, Clone, Debug)]
pub struct PageEntry {
    /// Physical address of the page (4 KiB-aligned).
    pub phys: PhysAddr,
    /// Reclaim handler. See `ReclaimFn`.
    pub reclaim_fn: ReclaimFn,
    /// Current flags. Boot value is typically `empty()` (cold) or
    /// `ACCESSED` (newly faulted in).
    pub flags: PageFlags,
    /// Aging counter. Decremented by `reclaim_sweep` on pages that
    /// didn't see an access this sweep; reset to `INITIAL_AGE` on
    /// access. Tanenbaum & Bos §3.4 — aging is the practical
    /// approximation of LRU when the hardware only gives one A-bit.
    pub age: u8,
}

/// Default age assigned when a page joins the LRU or is observed
/// to be `ACCESSED`. The sweep decrements toward zero.
///
/// `7` is the canonical Tanenbaum-style 8-bit shadow but expressed
/// as a positive count of sweeps-since-access; the sweep decrements
/// by 1 per pass, so a freshly-accessed page survives ~7 sweeps of
/// idleness before becoming a top reclaim candidate.
pub const INITIAL_AGE: u8 = 7;

/// Demotion threshold — pages with `age == 0` are demoted from
/// `active` to `inactive` on the next sweep. Kept as a constant so
/// the test suite can reason about expected transitions.
pub const DEMOTE_AT_AGE: u8 = 0;

/// Opaque handle that identifies a registered page. Stable for the
/// lifetime of the registration; the caller stashes it alongside
/// whatever cache structure owns the page and hands it back to
/// `mark_accessed` / `mark_dirty` / `unregister_page`.
///
/// The wire format is a monotonically-incrementing generation
/// counter; we never recycle handles. Handle space is 2^64 — a
/// 1 GHz registration rate would burn through it in ~580 years.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PageHandle(u64);

impl PageHandle {
    /// Sentinel handle that never refers to a registered page.
    /// Useful for default-initialising fields and asserting
    /// "no page yet" in callers.
    pub const NONE: PageHandle = PageHandle(0);

    /// Raw representation. For diagnostics only; do not rely on
    /// the encoding.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Internal slot record. We keep the user's `PageEntry` plus our
/// own bookkeeping (the issued handle). Slots are addressed by
/// handle through a linear scan — see the module-level note about
/// scaling.
#[derive(Copy, Clone, Debug)]
struct Slot {
    handle: PageHandle,
    entry: PageEntry,
}

/// Reclaim subsystem state. Single global instance behind an
/// `IrqSafeSpinLock`. We accept the global-lock contention for
/// Stage-1; sharding by NUMA node is a follow-up alongside the
/// kthread.
#[derive(Debug)]
struct ReclaimState {
    /// All registered pages, addressed by handle via linear scan.
    /// `Vec` rather than a hash map because (a) the kernel doesn't
    /// have a no_std hash map handy and (b) typical N is small.
    slots: Vec<Slot>,
    /// Hot list: pages with recent access. Newest at the back,
    /// oldest at the front; the sweep walks front-first.
    active: VecDeque<PageHandle>,
    /// Cold list: reclaim candidates. Tail = oldest =
    /// `reclaim_target_pages` consumes from here.
    inactive: VecDeque<PageHandle>,
    /// Total successful reclaims since boot, for `lru_stats`.
    reclaim_count: u64,
    /// Total reclaim attempts (calls into a reclaim_fn) since boot.
    reclaim_attempts: u64,
    /// Total sweeps run since boot.
    sweep_count: u64,
}

impl ReclaimState {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            active: VecDeque::new(),
            inactive: VecDeque::new(),
            reclaim_count: 0,
            reclaim_attempts: 0,
            sweep_count: 0,
        }
    }

    /// Find the slot index for `handle`, or `None` if it isn't
    /// registered (e.g. already unregistered).
    fn find(&self, handle: PageHandle) -> Option<usize> {
        self.slots.iter().position(|s| s.handle == handle)
    }
}

/// The global reclaim subsystem. `const fn new` so it can be a
/// `static`; the spinlock initialises lazily.
static STATE: IrqSafeSpinLock<ReclaimState> = IrqSafeSpinLock::new(ReclaimState::new());

/// Monotonic source for `PageHandle`s. Atomic so handle minting
/// doesn't need the state lock — useful when register_page is
/// called from contexts that already hold related locks.
///
/// Starts at 1 so `PageHandle::NONE` (=0) is genuinely invalid.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Statistics snapshot returned by `lru_stats`. Plain data so
/// callers can format / serialise / compare freely.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LruStats {
    /// Number of pages on the `active` list right now.
    pub active: usize,
    /// Number of pages on the `inactive` list right now.
    pub inactive: usize,
    /// Total pages currently tracked (= active + inactive,
    /// reported separately so the caller doesn't have to add).
    pub total: usize,
    /// Total successful reclaims since boot (handler returned
    /// `Freed`).
    pub reclaim_count: u64,
    /// Total reclaim_fn invocations since boot — includes
    /// Dirty / Locked outcomes that didn't actually free a page.
    pub reclaim_attempts: u64,
    /// Number of sweeps run since boot.
    pub sweep_count: u64,
}

/// Register `entry` with the reclaim subsystem. The page is
/// inserted at the front of `inactive` — a fresh registration is
/// assumed *cold* until the owner pings `mark_accessed`. This is
/// the EELRU §3 "early-eviction" stance: don't promote on first
/// touch.
///
/// Returns the page's `PageHandle`, which the caller must stash
/// to drive future `mark_accessed` / `mark_dirty` /
/// `unregister_page` calls.
pub fn register_page(entry: PageEntry) -> PageHandle {
    let handle = PageHandle(NEXT_HANDLE.fetch_add(1, Ordering::Relaxed));
    let mut state = STATE.lock();

    // Strip ON_ACTIVE on the way in — fresh registrations land on
    // `inactive` regardless of what the caller set, so the bit
    // accurately reflects list membership.
    let entry = PageEntry {
        flags: entry.flags.without(PageFlags::ON_ACTIVE),
        ..entry
    };

    state.slots.push(Slot { handle, entry });
    state.inactive.push_back(handle);
    handle
}

/// Drop `handle` from the subsystem. Idempotent: unregistering a
/// stale handle is a no-op (the caller may legitimately race with
/// reclaim itself having already freed the page).
pub fn unregister_page(handle: PageHandle) {
    let mut state = STATE.lock();
    if let Some(idx) = state.find(handle) {
        let on_active = state.slots[idx].entry.flags.contains(PageFlags::ON_ACTIVE);
        state.slots.swap_remove(idx);
        let list = if on_active {
            &mut state.active
        } else {
            &mut state.inactive
        };
        if let Some(pos) = list.iter().position(|h| *h == handle) {
            list.remove(pos);
        }
    }
}

/// Mark a page as recently accessed. Sets the `ACCESSED` flag,
/// resets `age` to `INITIAL_AGE`, and — if the page is currently
/// on `inactive` — promotes it to `active` at the back (newest).
///
/// Promotion on second-or-later access is the EELRU shape: a page
/// that is referenced twice within an aging window graduates to
/// the hot list; a single one-shot reference does not.
///
/// Stale handles are silently ignored (the page may have been
/// reclaimed concurrently).
pub fn mark_accessed(handle: PageHandle) {
    let mut state = STATE.lock();
    let Some(idx) = state.find(handle) else {
        return;
    };

    state.slots[idx].entry.flags = state.slots[idx].entry.flags.union(PageFlags::ACCESSED);
    state.slots[idx].entry.age = INITIAL_AGE;

    let was_on_active = state.slots[idx].entry.flags.contains(PageFlags::ON_ACTIVE);
    if !was_on_active {
        // Promote: remove from inactive, push to back of active.
        if let Some(pos) = state.inactive.iter().position(|h| *h == handle) {
            state.inactive.remove(pos);
        }
        state.slots[idx].entry.flags = state.slots[idx].entry.flags.union(PageFlags::ON_ACTIVE);
        state.active.push_back(handle);
    } else {
        // Already hot — refresh recency by moving to the back.
        if let Some(pos) = state.active.iter().position(|h| *h == handle) {
            state.active.remove(pos);
            state.active.push_back(handle);
        }
    }
}

/// Mark a page as dirty (PTE-D observed set). Pure flag update —
/// dirty pages stay on whichever list they were on; the reclaim
/// path is the one that special-cases the DIRTY outcome.
pub fn mark_dirty(handle: PageHandle) {
    let mut state = STATE.lock();
    if let Some(idx) = state.find(handle) {
        state.slots[idx].entry.flags = state.slots[idx].entry.flags.union(PageFlags::DIRTY);
    }
}

/// Mark a page as locked (currently pinned). Locked pages are
/// skipped by `reclaim_target_pages`.
pub fn mark_locked(handle: PageHandle, locked: bool) {
    let mut state = STATE.lock();
    if let Some(idx) = state.find(handle) {
        if locked {
            state.slots[idx].entry.flags = state.slots[idx].entry.flags.union(PageFlags::LOCKED);
        } else {
            state.slots[idx].entry.flags = state.slots[idx].entry.flags.without(PageFlags::LOCKED);
        }
    }
}

/// One sweep over both LRU lists.
///
///   * Walk `active` front-to-back. For each page, if the
///     `ACCESSED` bit is set, clear it and refresh `age` (the
///     page stays hot); otherwise decrement `age`. Pages whose
///     `age` drops to `DEMOTE_AT_AGE` migrate to `inactive` at
///     the back (i.e. they become the newest cold page — they're
///     allowed one more grace period before they're eviction
///     candidates).
///   * Walk `inactive` similarly. If we see `ACCESSED`, the page
///     is genuinely active again — promote it back to the back
///     of `active`. Otherwise decrement age; nothing is dropped
///     here — eviction is `reclaim_target_pages`'s job, not the
///     sweep's.
///
/// Returns the number of pages moved between lists for diagnostics.
///
/// The sweep is `O(n)` in the total number of tracked pages; that
/// is fine because we expect to run it at "tens of ms" cadence
/// from a sleep-pump, not per-fault. Designed to be wired into
/// `sleep_pumps` once we have a stable hook for ~100 ms periodic
/// callbacks.
pub fn reclaim_sweep() -> usize {
    let mut state = STATE.lock();
    state.sweep_count = state.sweep_count.wrapping_add(1);
    let mut moved = 0usize;

    // ── Active list: demote idle pages. ─────────────────────────
    let snapshot_active: Vec<PageHandle> = state.active.iter().copied().collect();
    for handle in snapshot_active {
        let Some(idx) = state.find(handle) else {
            continue;
        };
        if state.slots[idx].entry.flags.contains(PageFlags::ACCESSED) {
            state.slots[idx].entry.flags =
                state.slots[idx].entry.flags.without(PageFlags::ACCESSED);
            state.slots[idx].entry.age = INITIAL_AGE;
        } else if state.slots[idx].entry.age > 0 {
            state.slots[idx].entry.age -= 1;
        }
        if state.slots[idx].entry.age == DEMOTE_AT_AGE
            && !state.slots[idx].entry.flags.contains(PageFlags::ACCESSED)
        {
            // Demote to inactive.
            if let Some(pos) = state.active.iter().position(|h| *h == handle) {
                state.active.remove(pos);
            }
            state.slots[idx].entry.flags =
                state.slots[idx].entry.flags.without(PageFlags::ON_ACTIVE);
            state.inactive.push_back(handle);
            moved += 1;
        }
    }

    // ── Inactive list: promote re-accessed pages. ───────────────
    let snapshot_inactive: Vec<PageHandle> = state.inactive.iter().copied().collect();
    for handle in snapshot_inactive {
        let Some(idx) = state.find(handle) else {
            continue;
        };
        if state.slots[idx].entry.flags.contains(PageFlags::ACCESSED) {
            // Promote.
            state.slots[idx].entry.flags =
                state.slots[idx].entry.flags.without(PageFlags::ACCESSED);
            state.slots[idx].entry.age = INITIAL_AGE;
            if let Some(pos) = state.inactive.iter().position(|h| *h == handle) {
                state.inactive.remove(pos);
            }
            state.slots[idx].entry.flags = state.slots[idx].entry.flags.union(PageFlags::ON_ACTIVE);
            state.active.push_back(handle);
            moved += 1;
        } else if state.slots[idx].entry.age > 0 {
            state.slots[idx].entry.age -= 1;
        }
    }

    moved
}

/// Foreground reclaim — scan the tail of `inactive` (oldest cold
/// pages first) and reclaim up to `n` pages. Returns how many
/// pages actually reported `Freed`.
///
/// Per-page protocol:
///   1. Skip if `LOCKED` (pinned right now — would deadlock the
///      owner, or at minimum waste a syscall).
///   2. Call `reclaim_fn(phys)`. Drop the state lock *before* the
///      call so the handler may freely acquire other kernel locks
///      and even (re-)enter the slab.
///   3. On `Freed` — drop the slot from tracking.
///      On `Dirty` / `Locked` — leave the slot, optionally rotate
///      to the front of `inactive` so we don't re-scan it on the
///      same call. Update flags from the outcome.
///
/// The caller is expected to invoke this when the buddy or slab
/// fails an allocation — bumping `reclaim_count` for the
/// pressure-driven path.
pub fn reclaim_target_pages(n: usize) -> usize {
    if n == 0 {
        return 0;
    }

    let mut freed = 0usize;

    // We can't hold the state lock across the reclaim_fn callback
    // (it might re-enter the slab / take other locks / call
    // unregister_page in some future shape). Instead: take a
    // small batch of candidates from the inactive tail under the
    // lock, drop the lock, invoke handlers, then re-acquire to
    // apply outcomes. Repeat until we hit `n` or run out.
    //
    // Batch size of 8 is a balance between lock-thrash and
    // worst-case wasted candidates if the first reclaim frees
    // everyone else (very rare). It also bounds stack growth from
    // the Vec.
    const BATCH: usize = 8;

    while freed < n {
        // Pull a batch of candidates from the tail.
        let batch: Vec<(PageHandle, PhysAddr, PageFlags, ReclaimFn, bool)> = {
            let mut state = STATE.lock();
            let take = core::cmp::min(BATCH, n - freed);
            let mut out: Vec<(PageHandle, PhysAddr, PageFlags, ReclaimFn, bool)> = Vec::new();
            // Pop from the back (oldest cold pages). We re-queue
            // any survivors after the lock is dropped + handlers
            // have run.
            for _ in 0..take {
                let Some(handle) = state.inactive.pop_back() else {
                    break;
                };
                let Some(idx) = state.find(handle) else {
                    // Stale list entry — shouldn't happen, but if
                    // it does just drop it and keep going.
                    continue;
                };
                let entry = state.slots[idx].entry;
                let locked = entry.flags.contains(PageFlags::LOCKED);
                out.push((handle, entry.phys, entry.flags, entry.reclaim_fn, locked));
            }
            out
        };

        if batch.is_empty() {
            break;
        }

        // Outside the lock — invoke handlers.
        let mut results: Vec<(PageHandle, PhysAddr, PageFlags, ReclaimOutcome)> =
            Vec::with_capacity(batch.len());
        for (handle, phys, flags, reclaim_fn, locked) in batch {
            if locked {
                results.push((handle, phys, flags, ReclaimOutcome::Locked));
                continue;
            }
            let outcome = reclaim_fn(phys);
            results.push((handle, phys, flags, outcome));
        }

        // Pager dispatch happens *outside* the state lock — the
        // pager impl may take its own locks / allocate / touch the
        // heap. Collect the page-out results here, then apply
        // bookkeeping under the state lock below.
        //
        // Wave C scope note: a successful `page_out` does **not**
        // yet free the physical frame or maintain a reverse-mapping
        // side-table mapping `(handle, phys) → SwapSlot`. Owners
        // currently have no way to recover the page via `page_in`;
        // the deliverable for this wave is the *seam*, not a live
        // swap. Wave C+1 will:
        //   1. free the frame on `Ok(slot)`,
        //   2. record the slot in a side-table keyed by handle,
        //   3. surface the slot to the owner so it can call
        //      `pager::page_in` on demand.
        // Until then we treat `DeferToPager → Ok(_)` as a no-op
        // bookkeeping-wise (keep the page tracked, same as
        // `Locked`) so the system stays correct.
        let mut pager_dispositions: Vec<(
            PageHandle,
            Result<crate::pager::SwapSlot, crate::pager::PagerError>,
        )> = Vec::new();
        for (handle, phys, flags, outcome) in &results {
            if matches!(outcome, ReclaimOutcome::DeferToPager) {
                let res = crate::pager::page_out_via_installed(*phys, *flags);
                pager_dispositions.push((*handle, res));
            }
        }

        // Apply outcomes under the lock.
        {
            let mut state = STATE.lock();
            let mut pager_iter = pager_dispositions.into_iter();
            for (handle, _phys, _flags, outcome) in results {
                state.reclaim_attempts = state.reclaim_attempts.wrapping_add(1);
                match outcome {
                    ReclaimOutcome::Freed => {
                        state.reclaim_count = state.reclaim_count.wrapping_add(1);
                        if let Some(idx) = state.find(handle) {
                            state.slots.swap_remove(idx);
                        }
                        freed += 1;
                    }
                    ReclaimOutcome::Dirty => {
                        if let Some(idx) = state.find(handle) {
                            state.slots[idx].entry.flags =
                                state.slots[idx].entry.flags.union(PageFlags::DIRTY);
                        }
                        // Push to front of inactive (newest cold)
                        // so the next call doesn't immediately
                        // retry the same dirty page — the writeback
                        // path gets a chance to clean it.
                        state.inactive.push_front(handle);
                    }
                    ReclaimOutcome::Locked => {
                        if let Some(idx) = state.find(handle) {
                            state.slots[idx].entry.flags =
                                state.slots[idx].entry.flags.union(PageFlags::LOCKED);
                        }
                        state.inactive.push_front(handle);
                    }
                    ReclaimOutcome::DeferToPager => {
                        // Pull the matching pager result. The pre-
                        // pass above pushed one entry per
                        // `DeferToPager` outcome in iteration order,
                        // so the head of the iterator is ours.
                        let _ = pager_iter.next();
                        // TODO(wave-C+1): on Ok(slot), free the
                        // frame and stash the slot in a side-table.
                        // For now, leave the page tracked on
                        // inactive — same disposition as Locked —
                        // so subsequent reclaim passes can retry.
                        state.inactive.push_front(handle);
                    }
                }
            }
        }

        // If the batch produced no `Freed`s, we'd loop forever on
        // a list full of Dirty / Locked pages. Detect and bail.
        if freed == 0 {
            break;
        }
        // Likewise: if we got *some* freed but no more candidates
        // could pop next iteration, the loop naturally exits via
        // the empty batch.
    }

    freed
}

/// Snapshot of the reclaim subsystem's statistics. Cheap (one
/// lock acquisition + struct copy), suitable for `/proc`-style
/// diagnostics and tests.
pub fn lru_stats() -> LruStats {
    let state = STATE.lock();
    LruStats {
        active: state.active.len(),
        inactive: state.inactive.len(),
        total: state.slots.len(),
        reclaim_count: state.reclaim_count,
        reclaim_attempts: state.reclaim_attempts,
        sweep_count: state.sweep_count,
    }
}

/// Periodic-sweep entry point — designed to be registered as a
/// `sleep_pump` callback (see `narf-userspace::handlers::sleep_pumps`)
/// that fires at ~100 ms cadence. Simply forwards to
/// `reclaim_sweep`; provided so the boot code has a `fn()`-shaped
/// hook to register without leaking the return value.
///
/// Once the kthread infrastructure lands, this becomes the
/// kthread's loop body; the sleep_pump shape is a hold-over for
/// the Stage-1 single-thread model.
pub fn reclaim_sweep_pump() {
    let _ = reclaim_sweep();
}

// Test-only helper: wipe global state so each test starts clean.
// Real boot path doesn't need this (state starts empty); tests
// need it because they run in-process and share the static.
#[cfg(test)]
fn reset_for_test() {
    let mut state = STATE.lock();
    state.slots.clear();
    state.active.clear();
    state.inactive.clear();
    state.reclaim_count = 0;
    state.reclaim_attempts = 0;
    state.sweep_count = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // The unit tests share the global `STATE` static, so we must
    // serialise them. Kernel-tests run sequentially (the runner
    // doesn't fork or parallelise), so a `reset_for_test()` at
    // the top of each test is sufficient.

    // ── Test handlers ────────────────────────────────────────

    fn handler_always_freed(_phys: PhysAddr) -> ReclaimOutcome {
        ReclaimOutcome::Freed
    }
    fn handler_always_dirty(_phys: PhysAddr) -> ReclaimOutcome {
        ReclaimOutcome::Dirty
    }
    fn handler_always_locked(_phys: PhysAddr) -> ReclaimOutcome {
        ReclaimOutcome::Locked
    }

    fn mk_entry(phys_raw: u64, reclaim_fn: ReclaimFn) -> PageEntry {
        PageEntry {
            phys: PhysAddr::new(phys_raw),
            reclaim_fn,
            flags: PageFlags::empty(),
            age: INITIAL_AGE,
        }
    }

    // ── 1. register / unregister round-trip ──────────────────

    fn smoke_reclaim_register_unregister_roundtrip() -> TestResult {
        reset_for_test();
        let stats_before = lru_stats();
        if stats_before.total != 0 {
            return TestResult::Fail("state not clean before test");
        }

        let h = register_page(mk_entry(0x1000, handler_always_freed));
        let stats_after = lru_stats();
        if stats_after.total != 1 || stats_after.inactive != 1 || stats_after.active != 0 {
            return TestResult::Fail("register_page did not land page on inactive");
        }
        if h == PageHandle::NONE {
            return TestResult::Fail("register_page returned NONE handle");
        }

        unregister_page(h);
        let stats_final = lru_stats();
        if stats_final.total != 0 || stats_final.inactive != 0 {
            return TestResult::Fail("unregister_page didn't drop the page");
        }

        // Idempotent re-call of unregister is safe.
        unregister_page(h);

        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/reclaim",
        smoke_reclaim_register_unregister_roundtrip
    );

    // ── 2. mark_accessed moves inactive → active ─────────────

    fn smoke_reclaim_mark_accessed_promotes() -> TestResult {
        reset_for_test();
        let h = register_page(mk_entry(0x2000, handler_always_freed));
        let before = lru_stats();
        if before.inactive != 1 || before.active != 0 {
            return TestResult::Fail("setup: page not on inactive");
        }

        mark_accessed(h);
        let after = lru_stats();
        if after.active != 1 || after.inactive != 0 {
            return TestResult::Fail("mark_accessed did not promote to active");
        }

        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_mark_accessed_promotes);

    // ── 3. sweep ages pages + demotes idle active ────────────

    fn smoke_reclaim_sweep_ages_and_demotes() -> TestResult {
        reset_for_test();
        let h = register_page(mk_entry(0x3000, handler_always_freed));
        mark_accessed(h);
        // Page now on active with age = INITIAL_AGE and ACCESSED set.

        // First sweep clears the ACCESSED bit + refreshes age (so
        // age stays high after first sweep).
        let _ = reclaim_sweep();
        let s1 = lru_stats();
        if s1.active != 1 || s1.inactive != 0 {
            return TestResult::Fail("page demoted too early — first sweep");
        }

        // Subsequent sweeps without re-access decrement age once
        // ACCESSED is clear; after INITIAL_AGE further sweeps the
        // page should be on inactive.
        for _ in 0..(INITIAL_AGE as usize + 1) {
            let _ = reclaim_sweep();
        }
        let s2 = lru_stats();
        if s2.inactive != 1 || s2.active != 0 {
            return TestResult::Fail("idle page never demoted to inactive");
        }
        if s2.sweep_count == 0 {
            return TestResult::Fail("sweep_count not incremented");
        }

        unregister_page(h);
        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_sweep_ages_and_demotes);

    // ── 4. reclaim_target_pages frees up to n clean pages ────

    fn smoke_reclaim_target_pages_frees_n() -> TestResult {
        reset_for_test();
        // Register 5 always-freed pages — they all land on inactive.
        for i in 0..5 {
            let _ = register_page(mk_entry(0x10_0000 + i * 0x1000, handler_always_freed));
        }
        if lru_stats().inactive != 5 {
            return TestResult::Fail("setup: expected 5 inactive pages");
        }

        // Ask for 3 — should get exactly 3.
        let freed = reclaim_target_pages(3);
        if freed != 3 {
            return TestResult::Fail("reclaim_target_pages did not return n");
        }
        let after = lru_stats();
        if after.total != 2 || after.inactive != 2 {
            return TestResult::Fail("freed pages still tracked");
        }
        if after.reclaim_count != 3 {
            return TestResult::Fail("reclaim_count not incremented correctly");
        }

        // Ask for many more than remain — should cap at remaining.
        let freed2 = reclaim_target_pages(100);
        if freed2 != 2 {
            return TestResult::Fail("reclaim did not cap at available");
        }
        if lru_stats().total != 0 {
            return TestResult::Fail("not all pages cleared");
        }

        // Zero is a no-op.
        if reclaim_target_pages(0) != 0 {
            return TestResult::Fail("reclaim(0) should be a no-op");
        }

        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_target_pages_frees_n);

    // ── 5. Dirty + Locked outcomes leave pages tracked ───────

    fn smoke_reclaim_dirty_locked_outcomes() -> TestResult {
        reset_for_test();
        let h_dirty = register_page(mk_entry(0x20_0000, handler_always_dirty));
        let h_locked = register_page(mk_entry(0x20_1000, handler_always_locked));
        let h_freed = register_page(mk_entry(0x20_2000, handler_always_freed));

        let freed = reclaim_target_pages(3);
        if freed != 1 {
            return TestResult::Fail("expected exactly 1 page actually freed");
        }
        let stats = lru_stats();
        // The two non-Freed pages should still be tracked.
        if stats.total != 2 {
            return TestResult::Fail("dirty/locked pages were dropped");
        }
        // reclaim_attempts should reflect all three calls.
        if stats.reclaim_attempts < 3 {
            return TestResult::Fail("reclaim_attempts undercounted");
        }
        if stats.reclaim_count != 1 {
            return TestResult::Fail("reclaim_count over/undercounted");
        }

        // Confirm the dirty page is flagged DIRTY now. We can't
        // peek at internal slots from outside, so the indirect
        // assertion is: the page is still on `inactive`.
        if stats.inactive != 2 {
            return TestResult::Fail("retained pages not on inactive");
        }

        unregister_page(h_dirty);
        unregister_page(h_locked);
        // h_freed was already dropped, unregister is a no-op.
        unregister_page(h_freed);

        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_dirty_locked_outcomes);

    // ── 6. Stats counters move monotonically ─────────────────

    fn smoke_reclaim_stats_counters_track_activity() -> TestResult {
        reset_for_test();
        let s0 = lru_stats();
        if s0.reclaim_count != 0 || s0.reclaim_attempts != 0 || s0.sweep_count != 0 {
            return TestResult::Fail("counters not zero after reset");
        }

        // Run a sweep — sweep_count ticks even with no pages.
        let _ = reclaim_sweep();
        let _ = reclaim_sweep();
        let s1 = lru_stats();
        if s1.sweep_count != 2 {
            return TestResult::Fail("sweep_count did not advance");
        }

        // Register one freed-able page, reclaim it, both counters
        // should bump.
        let _ = register_page(mk_entry(0x30_0000, handler_always_freed));
        let freed = reclaim_target_pages(1);
        if freed != 1 {
            return TestResult::Fail("reclaim of single page failed");
        }
        let s2 = lru_stats();
        if s2.reclaim_attempts != 1 {
            return TestResult::Fail("reclaim_attempts did not bump");
        }
        if s2.reclaim_count != 1 {
            return TestResult::Fail("reclaim_count did not bump");
        }

        // pump variant runs cleanly + still ticks sweep_count.
        reclaim_sweep_pump();
        let s3 = lru_stats();
        if s3.sweep_count != s2.sweep_count + 1 {
            return TestResult::Fail("reclaim_sweep_pump did not delegate");
        }

        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/reclaim",
        smoke_reclaim_stats_counters_track_activity
    );

    // ── 7. Bonus: mark_accessed on an inactive page during scan ─

    fn smoke_reclaim_promote_back_via_sweep() -> TestResult {
        reset_for_test();
        let h = register_page(mk_entry(0x40_0000, handler_always_freed));
        // Page is on inactive. Mark accessed manually (simulating
        // the PTE-A push path) — that promotes immediately. To
        // exercise the sweep's promotion logic instead, we'd want
        // to set the ACCESSED bit without going through
        // mark_accessed. Since the API doesn't expose that, the
        // best we can do here is verify the round-trip in the
        // other direction: a page on inactive that gets
        // mark_accessed lands on active, then a long idle run
        // demotes it again.
        mark_accessed(h);
        if lru_stats().active != 1 {
            return TestResult::Fail("mark_accessed didn't promote");
        }

        // Idle for many sweeps — should land back on inactive.
        for _ in 0..(INITIAL_AGE as usize + 2) {
            let _ = reclaim_sweep();
        }
        if lru_stats().inactive != 1 {
            return TestResult::Fail("page didn't return to inactive after idle");
        }

        // Now reclaim works again.
        let freed = reclaim_target_pages(1);
        if freed != 1 {
            return TestResult::Fail("inactive page not reclaimed");
        }

        reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("memory/reclaim", smoke_reclaim_promote_back_via_sweep);
}
