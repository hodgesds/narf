//! Smoke tests for the bounded [`crate::page_cache::PageCache`].
//!
//! The cache must stay bounded (a distro boot streams hundreds of MiB
//! of shared libraries through it) while never dropping a page that
//! still owes a writeback.

extern crate alloc;

use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::page_cache::{Page, PageCache, PageKey, PAGE_SIZE};

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

/// A clean page inserted past the capacity ceiling evicts the OLDEST
/// clean page (FIFO), keeping the resident set bounded.
fn smoke_page_cache_evicts_oldest_clean_first() -> TestResult {
    let cache = PageCache::with_capacity(4);
    for i in 0..4 {
        cache.insert(key(i), clean_page(i as u8));
    }
    if cache.len() != 4 {
        return TestResult::Fail("fill to capacity should hold 4 pages");
    }
    // One past capacity: the oldest (page_off 0) is evicted FIFO.
    cache.insert(key(4), clean_page(4));
    if cache.len() != 4 {
        return TestResult::Fail("cache exceeded its capacity ceiling");
    }
    if cache.lookup(key(0)).is_some() {
        return TestResult::Fail("oldest clean page was not evicted");
    }
    if cache.lookup(key(4)).is_none() {
        return TestResult::Fail("newest page must be resident");
    }
    if cache.lookup(key(2)).is_none() {
        return TestResult::Fail("mid-age page must be retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_evicts_oldest_clean_first
);

/// Dirty pages still owe a writeback and must never be evicted, even
/// under sustained clean-page pressure.
fn smoke_page_cache_never_evicts_dirty() -> TestResult {
    let cache = PageCache::with_capacity(2);
    cache.insert(key(0), clean_page(0));
    cache.insert(key(1), clean_page(1));
    if !cache.mark_dirty(key(0)) {
        return TestResult::Fail("mark_dirty on a resident page must succeed");
    }
    // Churn many clean pages through a 2-page cache: the dirty page survives.
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

/// A capacity of 0 disables eviction (unbounded) — the escape hatch
/// for callers that manage lifetime themselves.
fn smoke_page_cache_zero_capacity_unbounded() -> TestResult {
    let cache = PageCache::with_capacity(0);
    for i in 0..1000 {
        cache.insert(key(i), clean_page(0));
    }
    if cache.len() != 1000 {
        return TestResult::Fail("capacity 0 should disable eviction");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_zero_capacity_unbounded
);

/// Re-inserting an existing key updates its page in place without
/// double-counting it in the eviction queue (a duplicate entry would
/// let the cache evict below its live set).
fn smoke_page_cache_reinsert_no_double_count() -> TestResult {
    let cache = PageCache::with_capacity(3);
    cache.insert(key(0), clean_page(0));
    cache.insert(key(1), clean_page(1));
    cache.insert(key(2), clean_page(2));
    // Re-touch key(0) with new contents; must not enqueue a duplicate.
    cache.insert(key(0), clean_page(9));
    // One more insert evicts exactly one page (FIFO: key(1)).
    cache.insert(key(3), clean_page(3));
    if cache.len() != 3 {
        return TestResult::Fail("re-insert must not perturb the capacity bound");
    }
    match cache.lookup(key(0)) {
        Some(p) if p.data[0] == 9 => TestResult::Pass,
        Some(_) => TestResult::Fail("re-insert did not update the page contents"),
        None => TestResult::Fail("re-inserted key was wrongly evicted"),
    }
}
kernel_test_in!(
    "filesystem/page_cache",
    smoke_page_cache_reinsert_no_double_count
);
