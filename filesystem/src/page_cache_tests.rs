//! Smoke tests for the reclaiming [`crate::page_cache::PageCache`].
//!
//! The cache must stay bounded (a distro boot streams hundreds of MiB
//! of shared libraries through it) via a CLOCK approximate-LRU and a
//! free-memory watermark, while never dropping a page that still owes
//! a writeback.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::page_cache::{
    default_capacity_pages, set_default_capacity_pages, set_free_pages_hook,
    set_low_watermark_pages, CacheFolio, PageCache, PageKey,
};

fn key(page_off: u64) -> PageKey {
    PageKey {
        fs_id: 0,
        inode: 0,
        page_off,
    }
}

fn clean_folio(fill: u8) -> CacheFolio {
    let mut folio = CacheFolio::alloc_zeroed().expect("cache folio frame for test");
    folio[..].fill(fill);
    folio
}

fn clean_order_folio(order: u8, fill: u8) -> CacheFolio {
    let mut folio =
        CacheFolio::alloc_order_zeroed(order).expect("ordered cache folio frame for test");
    folio[..].fill(fill);
    folio
}

/// Restore the process-global watermark + free-page hook so a test
/// never leaks memory-pressure state into its neighbours or the boot.
fn reset_globals() {
    set_low_watermark_pages(0);
    set_free_pages_hook(None);
}

/// Inserting past the hard ceiling evicts a cold clean page, keeping
/// the resident set bounded.
fn smoke_page_cache_hard_cap_evicts_clean() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(4);
    for i in 0..4 {
        cache.__insert_folio_for_test(key(i), clean_folio(i as u8));
    }
    if cache.len() != 4 {
        return TestResult::Fail("fill to capacity should hold 4 pages");
    }
    cache.__insert_folio_for_test(key(4), clean_folio(4));
    if cache.len() != 4 {
        return TestResult::Fail("cache exceeded its capacity ceiling");
    }
    if cache.lookup_folio(key(4)).is_none() {
        return TestResult::Fail("newest page must be resident");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_hard_cap_evicts_clean
);

/// CLOCK second chance: a page referenced (looked up) since the last
/// sweep survives an eviction that instead claims a colder page.
fn smoke_page_cache_clock_second_chance() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(3);
    cache.__insert_folio_for_test(key(0), clean_folio(0));
    cache.__insert_folio_for_test(key(1), clean_folio(1));
    cache.__insert_folio_for_test(key(2), clean_folio(2));
    // Reference the oldest page — it must NOT be the one evicted next.
    if cache.lookup_folio(key(0)).is_none() {
        return TestResult::Fail("key 0 should be resident before the sweep");
    }
    cache.__insert_folio_for_test(key(3), clean_folio(3)); // overflow → one eviction
    if cache.len() != 3 {
        return TestResult::Fail("capacity ceiling not held");
    }
    if cache.lookup_folio(key(0)).is_none() {
        return TestResult::Fail("referenced page must survive (CLOCK second chance)");
    }
    if cache.lookup_folio(key(1)).is_some() {
        return TestResult::Fail("the cold page (key 1) should have been evicted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_clock_second_chance
);

/// Dirty pages still owe a writeback and must never be evicted, even
/// under sustained clean-page pressure.
fn smoke_page_cache_never_evicts_dirty() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(2);
    cache.__insert_folio_for_test(key(0), clean_folio(0));
    cache.__insert_folio_for_test(key(1), clean_folio(1));
    if !cache.mark_dirty(key(0)) {
        return TestResult::Fail("mark_dirty on a resident page must succeed");
    }
    for i in 2..20 {
        cache.__insert_folio_for_test(key(i), clean_folio(i as u8));
    }
    if cache.lookup_folio(key(0)).is_none() {
        return TestResult::Fail("a dirty page must never be evicted");
    }
    let drained = cache.take_dirty(0, 0, 0, u64::MAX);
    if drained.len() != 1 || drained[0].0 != key(0) {
        return TestResult::Fail("dirty page's writeback obligation was lost");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/page_cache", smoke_page_cache_never_evicts_dirty);

/// Free-memory watermark: with no hard cap, a cache under the free
/// watermark sheds clean pages toward the reclaim floor; the same
/// workload with plenty of free memory keeps every page.
fn smoke_page_cache_watermark_reclaim() -> TestResult {
    // No hard ceiling — isolate watermark behaviour.
    // Plenty of free memory (hook well above the watermark): no reclaim.
    reset_globals();
    set_low_watermark_pages(1000);
    fn plenty() -> usize {
        1_000_000
    }
    set_free_pages_hook(Some(plenty));
    let relaxed = PageCache::with_capacity(0);
    for i in 0..600 {
        relaxed.__insert_folio_for_test(key(i), clean_folio(0));
    }
    if relaxed.len() != 600 {
        reset_globals();
        return TestResult::Fail("no reclaim expected when free memory is plentiful");
    }

    // Now simulate pressure: free below the watermark on every insert.
    fn starved() -> usize {
        1
    }
    set_free_pages_hook(Some(starved));
    let pressed = PageCache::with_capacity(0);
    for i in 0..600 {
        pressed.__insert_folio_for_test(key(i), clean_folio(0));
    }
    let n = pressed.len();
    reset_globals();
    if n >= 600 {
        return TestResult::Fail("watermark reclaim did not shed clean pages under pressure");
    }
    if n == 0 {
        return TestResult::Fail("watermark reclaim emptied the cache below its floor");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/page_cache", smoke_page_cache_watermark_reclaim);

/// `PageCache::new()` follows the process-global default ceiling so
/// the cache scales with the RAM-sized value boot installs, rather
/// than a compile-time constant.
fn smoke_page_cache_new_follows_global_default() -> TestResult {
    reset_globals();
    let saved = default_capacity_pages();
    set_default_capacity_pages(4);
    let cache = PageCache::new();
    for i in 0..10 {
        cache.__insert_folio_for_test(key(i), clean_folio(0));
    }
    let n = cache.len();
    set_default_capacity_pages(saved); // restore boot's RAM-sized value
    if n != 4 {
        return TestResult::Fail("new() did not honour the global default ceiling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_new_follows_global_default
);

/// The shrinker path (`reclaimable` / `shrink`) sheds clean pages under
/// memory pressure but never a dirty page (which still owes a writeback).
fn smoke_page_cache_shrink_evicts_clean_keeps_dirty() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(0); // unbounded: isolate shrink()
    for i in 0..10 {
        cache.__insert_folio_for_test(key(i), clean_folio(0));
    }
    cache.mark_dirty(key(3));
    cache.mark_dirty(key(7));
    if cache.reclaimable() != 8 {
        return TestResult::Fail("reclaimable must count only the 8 clean pages");
    }
    if cache.shrink(5) != 5 || cache.len() != 5 {
        return TestResult::Fail("shrink(5) should evict exactly 5 clean pages");
    }
    if cache.lookup_folio(key(3)).is_none() || cache.lookup_folio(key(7)).is_none() {
        return TestResult::Fail("dirty pages must survive shrink");
    }
    // Over-ask: evicts the 3 remaining clean pages, keeps both dirty.
    if cache.shrink(100) != 3 {
        return TestResult::Fail("shrink should evict the remaining clean pages");
    }
    if cache.len() != 2 || cache.reclaimable() != 0 {
        return TestResult::Fail("only the 2 dirty pages should remain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_shrink_evicts_clean_keeps_dirty
);

/// A hard capacity of 0 with no watermark set is unbounded — the
/// escape hatch for callers that manage lifetime themselves.
fn smoke_page_cache_zero_capacity_unbounded() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(0);
    for i in 0..1000 {
        cache.__insert_folio_for_test(key(i), clean_folio(0));
    }
    if cache.len() != 1000 {
        return TestResult::Fail("capacity 0 + no watermark should disable eviction");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_zero_capacity_unbounded
);

/// Folios are cache-native rather than a page wrapper: a tail-page lookup
/// resolves to its aligned head, dirtying the tail dirties the whole folio,
/// accounting uses constituent pages, and reclaim never splits it.
fn smoke_page_cache_ordered_folio_lookup_accounting_and_reclaim() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(0);
    let mut allocation =
        CacheFolio::alloc_order_zeroed(1).expect("order-1 cache folio frame for test");
    allocation[..4096].fill(0x11);
    allocation[4096..].fill(0x22);
    if !cache.__insert_folio_for_test(key(8), allocation) {
        return TestResult::Fail("aligned order-1 folio insertion failed");
    }
    if cache.len() != 2 || cache.folio_count() != 1 {
        return TestResult::Fail("folio accounting did not count two constituent pages");
    }
    let tail = match cache.lookup_folio(key(9)) {
        Some(found) => found,
        None => return TestResult::Fail("tail-page lookup missed its containing folio"),
    };
    if tail.base_key() != key(8)
        || tail.page_index() != 1
        || tail.order() != 1
        || tail.page_bytes()[0] != 0x22
    {
        return TestResult::Fail("tail-page lookup returned the wrong folio view");
    }
    if !cache.mark_dirty(key(9)) || cache.reclaimable() != 0 || cache.shrink(2) != 0 {
        return TestResult::Fail("tail dirtying did not protect the complete folio");
    }
    let dirty = cache.take_dirty(0, 0, 0, u64::MAX);
    if dirty.len() != 1 || dirty[0].0 != key(8) || dirty[0].1.order() != 1 {
        return TestResult::Fail("writeback did not receive the complete folio at its head");
    }
    // A folio someone still references (the lookup and the writeback batch)
    // is in use as the cache's copy and is not reclaimable.
    if cache.reclaimable() != 0 || cache.shrink(2) != 0 {
        return TestResult::Fail("reclaim evicted a folio that was still referenced");
    }
    drop(tail);
    drop(dirty);
    if cache.shrink(1) != 0 || cache.len() != 2 {
        return TestResult::Fail("reclaim split a folio to satisfy a one-page request");
    }
    if cache.shrink(2) != 2 || !cache.is_empty() {
        return TestResult::Fail("reclaim did not free the complete order-1 folio");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_ordered_folio_lookup_accounting_and_reclaim
);

/// The folio-head index has one owner for every covered base page.
fn smoke_page_cache_rejects_misaligned_and_overlapping_folios() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(0);
    if cache.__insert_folio_for_test(key(3), clean_order_folio(1, 0x33)) {
        return TestResult::Fail("misaligned order-1 folio was published");
    }
    if !cache.__insert_folio_for_test(key(8), clean_order_folio(1, 0x44)) {
        return TestResult::Fail("aligned order-1 folio insertion failed");
    }
    if cache.__insert_folio_for_test(key(9), clean_folio(0x55)) {
        return TestResult::Fail("tail-page insertion overlapped a resident folio");
    }
    if cache.len() != 2 || cache.folio_count() != 1 {
        return TestResult::Fail("rejected overlap mutated folio accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_rejects_misaligned_and_overlapping_folios
);

/// `invalidate_range` drops exactly the folios of one `(fs_id, inode)` that
/// overlap the page range — a multi-page folio straddling an end goes whole —
/// and leaves neighbours and other inodes cached.
fn smoke_page_cache_invalidate_range_is_exact() -> TestResult {
    let cache = PageCache::with_capacity(0);
    let other = |page_off| PageKey {
        fs_id: 0,
        inode: 7,
        page_off,
    };
    for p in [0u64, 1, 2, 3, 6] {
        cache.__insert_folio_for_test(key(p), clean_folio(p as u8));
        cache.__insert_folio_for_test(other(p), clean_folio(0xee));
    }
    // An order-1 folio over pages 4-5 straddles the range's start (5).
    if !cache.__insert_folio_for_test(key(4), clean_order_folio(1, 4)) {
        return TestResult::Fail("order-1 folio at page 4 was not inserted");
    }
    // Drop [1, 3) and [5, 6).
    let dropped = cache.invalidate_range(0, 0, 1, 3) + cache.invalidate_range(0, 0, 5, 6);
    if dropped != 4 {
        return TestResult::Fail("expected pages 1, 2 and the 4-5 folio (4 pages) dropped");
    }
    for (p, kept) in [
        (0, true),
        (1, false),
        (2, false),
        (3, true),
        (4, false),
        (5, false),
        (6, true),
    ] {
        if cache.lookup_folio(key(p)).is_some() != kept {
            return TestResult::Fail("invalidate_range kept or dropped the wrong page");
        }
    }
    for p in [0u64, 1, 2, 3, 6] {
        if cache.lookup_folio(other(p)).is_none() {
            return TestResult::Fail("invalidate_range touched another inode's pages");
        }
    }
    if cache.invalidate_range(0, 0, 3, 3) != 0 || cache.lookup_folio(key(3)).is_none() {
        return TestResult::Fail("an empty range must drop nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_invalidate_range_is_exact
);

// ── The fill protocol (`get_or_fill`) ──────────────────────────────

mod fill_protocol {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    use crate::page_cache::Filled;
    use crate::FsError;

    fn noop_waker() -> Waker {
        fn raw() -> RawWaker {
            unsafe fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            unsafe fn noop(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: every vtable entry is a no-op or rebuilds the same waker;
        // the null data pointer is never dereferenced.
        unsafe { Waker::from_raw(raw()) }
    }

    type FillFuture<'a> = Pin<Box<dyn Future<Output = Result<Filled, FsError>> + 'a>>;

    /// A fill that parks until `gate` opens, counts its runs in `runs`, and
    /// writes `byte` over the whole folio (or fails when `fail` is set).
    fn gated_fill<'a>(
        cache: &'a PageCache,
        page: u64,
        gate: &'a AtomicBool,
        runs: &'a AtomicUsize,
        byte: u8,
        fail: bool,
    ) -> FillFuture<'a> {
        Box::pin(
            cache.get_or_fill(key(page), 0, move |mut folio| async move {
                runs.fetch_add(1, Ordering::Relaxed);
                core::future::poll_fn(|_| {
                    if gate.load(Ordering::Acquire) {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
                if fail {
                    return Err(FsError::Io(narf_block::BlockError::IOError));
                }
                folio[..].fill(byte);
                Ok(folio)
            }),
        )
    }

    fn poll(fut: &mut FillFuture<'_>) -> Poll<Result<Filled, FsError>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        fut.as_mut().poll(&mut cx)
    }

    /// Concurrent misses on one page issue ONE fill; the second caller parks
    /// on the ticket and then takes the published folio (Linux: the second
    /// reader sleeps on the locked folio instead of reading it again).
    fn smoke_page_cache_get_or_fill_coalesces_concurrent_misses() -> TestResult {
        let cache = PageCache::with_capacity(0);
        let gate = AtomicBool::new(false);
        let runs = AtomicUsize::new(0);
        let mut first = gated_fill(&cache, 3, &gate, &runs, 0xa1, false);
        let mut second = gated_fill(&cache, 3, &gate, &runs, 0xb2, false);
        if poll(&mut first).is_ready() || poll(&mut second).is_ready() {
            return TestResult::Fail("a gated fill completed before its device");
        }
        if runs.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("two concurrent misses on one page both filled");
        }
        gate.store(true, Ordering::Release);
        let a = match poll(&mut first) {
            Poll::Ready(Ok(a)) => a,
            _ => return TestResult::Fail("the filler did not finish once released"),
        };
        let b = match poll(&mut second) {
            Poll::Ready(Ok(b)) => b,
            _ => return TestResult::Fail("the parked caller did not take the published folio"),
        };
        if !a.published() || !b.published() {
            return TestResult::Fail("an uncontested fill was not published");
        }
        if a.folio().page_bytes()[0] != 0xa1 || b.folio().page_bytes()[0] != 0xa1 {
            return TestResult::Fail("the waiter saw different bytes than the fill");
        }
        if runs.load(Ordering::Relaxed) != 1 || cache.len() != 1 {
            return TestResult::Fail("the waiter refilled or the folio was not cached once");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/page_cache",
        smoke_page_cache_get_or_fill_coalesces_concurrent_misses
    );

    /// Invalidation is per key. A write that invalidates the page being
    /// filled voids THAT fill (its bytes are returned to its caller but never
    /// cached, and a parked waiter refills); a write to another page voids
    /// nothing.
    fn smoke_page_cache_invalidation_voids_only_overlapping_fills() -> TestResult {
        let cache = PageCache::with_capacity(0);
        let gate = AtomicBool::new(false);
        let runs = AtomicUsize::new(0);
        let mut hit_fill = gated_fill(&cache, 5, &gate, &runs, 0x11, false);
        let mut spared_fill = gated_fill(&cache, 9, &gate, &runs, 0x22, false);
        let mut waiter = gated_fill(&cache, 5, &gate, &runs, 0x33, false);
        if poll(&mut hit_fill).is_ready()
            || poll(&mut spared_fill).is_ready()
            || poll(&mut waiter).is_ready()
        {
            return TestResult::Fail("a gated fill completed before its device");
        }
        if runs.load(Ordering::Relaxed) != 2 {
            return TestResult::Fail("expected one fill per page");
        }
        // The "write" lands on page 5 only.
        cache.invalidate_range(0, 0, 5, 6);
        // The waiter re-probes, finds no ticket, and starts its own fill.
        if poll(&mut waiter).is_ready() || runs.load(Ordering::Relaxed) != 3 {
            return TestResult::Fail("the waiter on an invalidated fill did not refill");
        }
        gate.store(true, Ordering::Release);
        let voided = match poll(&mut hit_fill) {
            Poll::Ready(Ok(v)) => v,
            _ => return TestResult::Fail("the invalidated fill did not complete"),
        };
        if voided.published() || voided.folio().page_bytes()[0] != 0x11 {
            return TestResult::Fail("an invalidated fill published its pre-write bytes");
        }
        let spared = match poll(&mut spared_fill) {
            Poll::Ready(Ok(v)) => v,
            _ => return TestResult::Fail("the unrelated fill did not complete"),
        };
        if !spared.published() {
            return TestResult::Fail("a write to page 5 voided the fill of page 9");
        }
        let refilled = match poll(&mut waiter) {
            Poll::Ready(Ok(v)) => v,
            _ => return TestResult::Fail("the refill did not complete"),
        };
        if !refilled.published() || refilled.folio().page_bytes()[0] != 0x33 {
            return TestResult::Fail("the post-write refill was not the cached copy");
        }
        match cache.lookup_folio(key(5)) {
            Some(found) if found.page_bytes()[0] == 0x33 => TestResult::Pass,
            _ => TestResult::Fail("page 5 does not hold the post-write fill"),
        }
    }
    kernel_test_in!(
        "filesystem/page_cache",
        smoke_page_cache_invalidation_voids_only_overlapping_fills
    );

    /// A failed fill and a dropped (cancelled) fill both release their
    /// ticket: nothing is cached and a parked waiter proceeds to fill itself
    /// instead of sleeping forever.
    fn smoke_page_cache_failed_or_dropped_fill_releases_its_waiters() -> TestResult {
        let cache = PageCache::with_capacity(0);
        let gate = AtomicBool::new(false);
        let runs = AtomicUsize::new(0);

        let mut failing = gated_fill(&cache, 1, &gate, &runs, 0, true);
        let mut waiter = gated_fill(&cache, 1, &gate, &runs, 0x44, false);
        if poll(&mut failing).is_ready() || poll(&mut waiter).is_ready() {
            return TestResult::Fail("a gated fill completed before its device");
        }
        gate.store(true, Ordering::Release);
        if !matches!(poll(&mut failing), Poll::Ready(Err(FsError::Io(_)))) {
            return TestResult::Fail("the failing fill did not report its error");
        }
        match poll(&mut waiter) {
            Poll::Ready(Ok(v)) if v.published() && v.folio().page_bytes()[0] == 0x44 => {}
            _ => return TestResult::Fail("the waiter of a failed fill did not fill itself"),
        }

        gate.store(false, Ordering::Release);
        let mut dropped = gated_fill(&cache, 2, &gate, &runs, 0x55, false);
        let mut waiter = gated_fill(&cache, 2, &gate, &runs, 0x66, false);
        if poll(&mut dropped).is_ready() || poll(&mut waiter).is_ready() {
            return TestResult::Fail("a gated fill completed before its device");
        }
        drop(dropped);
        gate.store(true, Ordering::Release);
        match poll(&mut waiter) {
            Poll::Ready(Ok(v)) if v.published() && v.folio().page_bytes()[0] == 0x66 => {}
            _ => return TestResult::Fail("the waiter of a dropped fill was stranded"),
        }
        if cache.len() != 2 {
            return TestResult::Fail("cache should hold exactly the two successful fills");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/page_cache",
        smoke_page_cache_failed_or_dropped_fill_releases_its_waiters
    );

    /// Reclaim never touches a fill ticket (it owns no frame yet) and the
    /// later publication accounts the folio exactly once.
    fn smoke_page_cache_reclaim_skips_fill_tickets() -> TestResult {
        let cache = Arc::new(PageCache::with_capacity(0));
        let gate = AtomicBool::new(false);
        let runs = AtomicUsize::new(0);
        let mut fill = gated_fill(&cache, 7, &gate, &runs, 0x77, false);
        if poll(&mut fill).is_ready() {
            return TestResult::Fail("a gated fill completed before its device");
        }
        if cache.reclaimable() != 0 || cache.shrink(16) != 0 || !cache.is_empty() {
            return TestResult::Fail("reclaim counted or evicted an in-flight fill");
        }
        gate.store(true, Ordering::Release);
        if !matches!(poll(&mut fill), Poll::Ready(Ok(ref v)) if v.published()) {
            return TestResult::Fail("the fill did not publish");
        }
        if cache.len() != 1 || cache.reclaimable() != 1 {
            return TestResult::Fail("the published folio was not accounted once");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/page_cache",
        smoke_page_cache_reclaim_skips_fill_tickets
    );
}
