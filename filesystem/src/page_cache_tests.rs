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
    set_low_watermark_pages, CacheFolio, Folio, PageCache, PageKey,
};

fn key(page_off: u64) -> PageKey {
    PageKey {
        fs_id: 0,
        inode: 0,
        page_off,
    }
}

fn clean_folio(fill: u8) -> Folio {
    let mut folio = CacheFolio::alloc_zeroed().expect("cache folio frame for test");
    folio[..].fill(fill);
    Folio::clean(folio)
}

fn clean_order_folio(order: u8, fill: u8) -> Folio {
    let mut folio =
        CacheFolio::alloc_order_zeroed(order).expect("ordered cache folio frame for test");
    folio[..].fill(fill);
    Folio::clean(folio)
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
        cache.insert_folio(key(i), clean_folio(i as u8));
    }
    if cache.len() != 4 {
        return TestResult::Fail("fill to capacity should hold 4 pages");
    }
    cache.insert_folio(key(4), clean_folio(4));
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
    cache.insert_folio(key(0), clean_folio(0));
    cache.insert_folio(key(1), clean_folio(1));
    cache.insert_folio(key(2), clean_folio(2));
    // Reference the oldest page — it must NOT be the one evicted next.
    if cache.lookup_folio(key(0)).is_none() {
        return TestResult::Fail("key 0 should be resident before the sweep");
    }
    cache.insert_folio(key(3), clean_folio(3)); // overflow → one eviction
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
    cache.insert_folio(key(0), clean_folio(0));
    cache.insert_folio(key(1), clean_folio(1));
    if !cache.mark_dirty(key(0)) {
        return TestResult::Fail("mark_dirty on a resident page must succeed");
    }
    for i in 2..20 {
        cache.insert_folio(key(i), clean_folio(i as u8));
    }
    if cache.lookup_folio(key(0)).is_none() {
        return TestResult::Fail("a dirty page must never be evicted");
    }
    let drained = cache.drain_dirty();
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
        relaxed.insert_folio(key(i), clean_folio(0));
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
        pressed.insert_folio(key(i), clean_folio(0));
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
        cache.insert_folio(key(i), clean_folio(0));
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
        cache.insert_folio(key(i), clean_folio(0));
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
        cache.insert_folio(key(i), clean_folio(0));
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
    if !cache.insert_folio(key(8), Folio::clean(allocation)) {
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
    let dirty = cache.drain_dirty();
    if dirty.len() != 1 || dirty[0].0 != key(8) || dirty[0].1.order() != 1 {
        return TestResult::Fail("writeback did not receive the complete folio at its head");
    }
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
    if cache.insert_folio(key(3), clean_order_folio(1, 0x33)) {
        return TestResult::Fail("misaligned order-1 folio was published");
    }
    if !cache.insert_folio(key(8), clean_order_folio(1, 0x44)) {
        return TestResult::Fail("aligned order-1 folio insertion failed");
    }
    if cache.insert_folio(key(9), clean_folio(0x55)) {
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
