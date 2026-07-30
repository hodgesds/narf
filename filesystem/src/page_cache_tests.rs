//! Smoke tests for the reclaiming [`crate::page_cache::PageCache`].
//!
//! The cache must stay bounded (a distro boot streams hundreds of MiB
//! of shared libraries through it) via a CLOCK approximate-LRU and a
//! free-memory watermark, while never dropping a page that still owes
//! a writeback.

extern crate alloc;

use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::page_cache::{
    default_capacity_pages, set_default_capacity_pages, set_free_pages_hook,
    set_low_watermark_pages, Page, PageCache, PageKey, PAGE_SIZE,
};

fn key(page_off: u64) -> PageKey {
    PageKey {
        fs_id: 0,
        inode: 0,
        page_off,
    }
}

fn clean_page(fill: u8) -> Page {
    Page {
        data: Arc::new([fill; PAGE_SIZE]),
        dirty: false,
        gen: 0,
    }
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
        cache.insert(key(i), clean_page(i as u8));
    }
    if cache.len() != 4 {
        return TestResult::Fail("fill to capacity should hold 4 pages");
    }
    cache.insert(key(4), clean_page(4));
    if cache.len() != 4 {
        return TestResult::Fail("cache exceeded its capacity ceiling");
    }
    if cache.lookup(key(4)).is_none() {
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
    cache.insert(key(0), clean_page(0));
    cache.insert(key(1), clean_page(1));
    cache.insert(key(2), clean_page(2));
    // Reference the oldest page — it must NOT be the one evicted next.
    if cache.lookup(key(0)).is_none() {
        return TestResult::Fail("key 0 should be resident before the sweep");
    }
    cache.insert(key(3), clean_page(3)); // overflow → one eviction
    if cache.len() != 3 {
        return TestResult::Fail("capacity ceiling not held");
    }
    if cache.lookup(key(0)).is_none() {
        return TestResult::Fail("referenced page must survive (CLOCK second chance)");
    }
    if cache.lookup(key(1)).is_some() {
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
    cache.insert(key(0), clean_page(0));
    cache.insert(key(1), clean_page(1));
    if !cache.mark_dirty(key(0)) {
        return TestResult::Fail("mark_dirty on a resident page must succeed");
    }
    for i in 2..20 {
        cache.insert(key(i), clean_page(i as u8));
    }
    if cache.lookup(key(0)).is_none() {
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
        relaxed.insert(key(i), clean_page(0));
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
        pressed.insert(key(i), clean_page(0));
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
        cache.insert(key(i), clean_page(0));
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

/// A hard capacity of 0 with no watermark set is unbounded — the
/// escape hatch for callers that manage lifetime themselves.
fn smoke_page_cache_zero_capacity_unbounded() -> TestResult {
    reset_globals();
    let cache = PageCache::with_capacity(0);
    for i in 0..1000 {
        cache.insert(key(i), clean_page(0));
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
