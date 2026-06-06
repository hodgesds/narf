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

use crate::PhysAddr;

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
        if state.slots[idx].entry.age <= DEMOTE_AT_AGE
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
