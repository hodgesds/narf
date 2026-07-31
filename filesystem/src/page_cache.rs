//! Unified page cache — Stage-4 structural shape.
//!
//! Spec: `filesystem/specification/spec.md` (Stage-4: unified page
//! cache). A single tree of page-sized entries keyed by
//! `(fs_instance, inode, page_offset)`; every read goes through the
//! cache before hitting the backing store; writes mark pages dirty
//! and a writeback worker flushes them to disk.
//!
//! Reclaim (Linux-shaped): the cache is not a fixed vector. Two
//! pressures shrink it, both evicting only CLEAN pages via a CLOCK
//! (second-chance approximate-LRU) so a hot, recently-referenced page
//! outlives a cold one:
//!
//!  * a hard resident-page ceiling ([`PageCache::with_capacity`]) — a
//!    backstop so a single cache can never dominate RAM; and
//!  * a **free-memory watermark**: once the frame allocator's free
//!    count drops below [`set_low_watermark_pages`], each insert
//!    reclaims a batch of cold clean pages (down to a small floor),
//!    mirroring the kernel's watermark-driven page reclaim rather than
//!    a blunt capped array.
//!
//! Dirty pages still owe a writeback and are never evicted; only
//! re-readable clean pages are dropped, so reclaim is always
//! correctness-preserving.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Page size in bytes. 4 KiB is the architectural minimum on both
/// x86_64 and aarch64; huge-page support is a later refinement.
pub const PAGE_SIZE: usize = 4096;

/// Default resident-page ceiling: 32 Ki pages = 128 MiB of cached
/// file data per cache. A hard backstop — watermark reclaim (below)
/// keeps the working set well under this on a healthy system; this
/// only bounds pathological growth if the watermark source is unset.
pub const DEFAULT_MAX_RESIDENT_PAGES: usize = 32 * 1024;

/// Pages reclaimed per insert while under the free-memory watermark.
/// Bounded so a single insert never stalls scanning the whole cache;
/// sustained pressure drains it over successive inserts.
const RECLAIM_BATCH_PAGES: usize = 256;

/// Floor the watermark reclaim will not shrink below, so transient
/// pressure can't empty the cache and destroy the coalescing that
/// makes parallel dynamic-linker reads cheap.
const RECLAIM_FLOOR_PAGES: usize = 256;

/// Process-global default hard-ceiling backstop, in pages, used by
/// caches built with [`PageCache::new`]. Boot sizes this from total
/// RAM (a large fraction) so the cache can grow to use available
/// memory — the free-memory watermark, not this ceiling, is the
/// primary limiter (Linux-shaped). A fixed 128 MiB start keeps a
/// bound before boot wires the RAM-proportional value.
static DEFAULT_CAP_PAGES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_RESIDENT_PAGES);

/// Set the process-global default hard ceiling (pages) that
/// [`PageCache::new`]-built caches use as their backstop. Boot sizes
/// this from total RAM; a value of 0 makes those caches rely solely
/// on the watermark (no hard ceiling).
pub fn set_default_capacity_pages(pages: usize) {
    DEFAULT_CAP_PAGES.store(pages, Ordering::Relaxed);
}

/// The current process-global default hard ceiling, in pages.
pub fn default_capacity_pages() -> usize {
    DEFAULT_CAP_PAGES.load(Ordering::Relaxed)
}

/// Free-frame low watermark, in pages. When the frame allocator
/// reports fewer free pages than this, inserts reclaim clean pages.
/// 0 disables watermark reclaim (only the hard ceiling applies) — the
/// default until boot wires it via [`set_low_watermark_pages`].
static LOW_WATERMARK_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Set the free-memory low watermark (in pages) that triggers page
/// reclaim. Boot sizes this from total RAM (a small percentage);
/// 0 disables watermark reclaim.
pub fn set_low_watermark_pages(pages: usize) {
    LOW_WATERMARK_PAGES.store(pages, Ordering::Relaxed);
}

/// The current free-memory low watermark, in pages.
pub fn low_watermark_pages() -> usize {
    LOW_WATERMARK_PAGES.load(Ordering::Relaxed)
}

/// Test-injectable free-page source. Production leaves this null and
/// the cache reads the real frame allocator; tests install a closure
/// so they can simulate memory pressure deterministically.
static FREE_PAGES_HOOK: IrqSafeSpinLock<Option<fn() -> usize>> = IrqSafeSpinLock::new(None);

/// Override the free-page source (tests only). `None` restores the
/// real frame-allocator reading.
pub fn set_free_pages_hook(hook: Option<fn() -> usize>) {
    *FREE_PAGES_HOOK.lock() = hook;
}

/// Free frames available, per the injected hook or the real frame
/// allocator. `None` means "unknown" (no reclaim decision is made).
fn free_pages_available() -> Option<usize> {
    if let Some(f) = *FREE_PAGES_HOOK.lock() {
        return Some(f());
    }
    Some(narf_memory::frame_stats().free)
}

// ── Central-reclaim integration (one shrinker for all page caches) ──
//
// Every live page cache registers itself here (a `Weak` so a dropped
// filesystem's cache falls out). A single `page-cache` shrinker is
// registered with `narf_memory::reclaim` the first time any cache
// appears; its count/scan iterate this registry. The scan/count paths
// are allocation-free (iterate + upgrade under the registry lock, no
// `Vec`) so they are safe to drive from the memory-reclaim / OOM path.
// Lock order is always REGISTRY → cache-inner (register only takes the
// registry lock; lookup/insert/shrink only take the cache-inner lock),
// so holding the registry lock across `shrink` cannot deadlock.

static PAGE_CACHE_REGISTRY: IrqSafeSpinLock<Vec<Weak<PageCache>>> =
    IrqSafeSpinLock::new(Vec::new());
static SHRINKER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Register `cache` with the central memory reclaimer so its clean pages
/// can be shed under pressure. Call once per cache after it is wrapped in
/// its owning `Arc` (e.g. at filesystem mount). Registration allocates
/// (registry push) but happens off the reclaim path.
pub fn register_for_reclaim(cache: &Arc<PageCache>) {
    {
        let mut g = PAGE_CACHE_REGISTRY.lock();
        g.retain(|w| w.strong_count() > 0);
        g.push(Arc::downgrade(cache));
    }
    if !SHRINKER_REGISTERED.swap(true, Ordering::AcqRel) {
        narf_memory::reclaim::register_shrinker(narf_memory::reclaim::Shrinker {
            name: "page-cache",
            count: page_cache_shrinker_count,
            scan: page_cache_shrinker_scan,
        });
    }
}

/// Shrinker `count`: total clean, evictable pages across all live caches.
/// Allocation-free.
fn page_cache_shrinker_count() -> usize {
    let g = PAGE_CACHE_REGISTRY.lock();
    let mut n = 0usize;
    for w in g.iter() {
        if let Some(c) = w.upgrade() {
            n = n.saturating_add(c.reclaimable());
        }
    }
    n
}

/// Shrinker `scan`: shed up to `nr` clean pages across live caches.
/// Allocation-free (upgrades a `Weak` — no heap — and evicts in place).
fn page_cache_shrinker_scan(nr: usize) -> usize {
    let g = PAGE_CACHE_REGISTRY.lock();
    let mut freed = 0usize;
    for w in g.iter() {
        if freed >= nr {
            break;
        }
        if let Some(c) = w.upgrade() {
            freed = freed.saturating_add(c.shrink(nr - freed));
        }
    }
    freed
}

/// Cache key: filesystem + inode + page offset (in pages, not
/// bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageKey {
    pub fs_id: u32,
    pub inode: u64,
    pub page_off: u64,
}

/// A page-sized data frame the cache owns. The bytes live in a real
/// buddy frame (reached through the kernel direct map), NOT the slab
/// heap — so dropping a cached page returns memory DIRECTLY to the buddy
/// allocator. That is what lets memory reclaim relieve large (multi-page)
/// buddy allocations, and keeps hundreds of MiB of cached file data off
/// the slab. The frame is node-local (`alloc_frame` prefers the current
/// CPU's NUMA node) and freed to the buddy on drop.
pub struct CachePage {
    frame: narf_memory::PhysFrame,
}

impl CachePage {
    /// Allocate a zeroed page frame, or `None` under memory pressure
    /// (the caller then degrades — e.g. serves a read without caching).
    pub fn alloc_zeroed() -> Option<Self> {
        let frame = narf_memory::alloc_frame().ok()?;
        // SAFETY: a freshly-allocated frame is exclusively owned here and is
        // PAGE_SIZE bytes of RAM reachable via its kernel direct-map pointer.
        unsafe {
            core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, PAGE_SIZE);
        }
        Some(Self { frame })
    }
}

impl core::ops::Deref for CachePage {
    type Target = [u8; PAGE_SIZE];
    fn deref(&self) -> &Self::Target {
        // SAFETY: the frame is owned for this CachePage's lifetime and is
        // PAGE_SIZE bytes of RAM mapped in the kernel direct map.
        unsafe { &*self.frame.start_address().kernel_ptr::<[u8; PAGE_SIZE]>() }
    }
}

impl core::ops::DerefMut for CachePage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as `Deref`; `&mut self` proves exclusive access (only held
        // during construction, before the page is shared via `Arc`).
        unsafe {
            &mut *self
                .frame
                .start_address()
                .kernel_mut_ptr::<[u8; PAGE_SIZE]>()
        }
    }
}

impl Drop for CachePage {
    fn drop(&mut self) {
        narf_memory::free_frame(self.frame);
    }
}

impl core::fmt::Debug for CachePage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CachePage")
            .field("frame", &self.frame.number())
            .finish()
    }
}

/// Cached page entry. `data` is an `Arc<CachePage>` (a buddy frame) so
/// readers share one copy and the frame returns to the buddy on last
/// drop; dirty pages hold the reference until writeback commits.
#[derive(Clone, Debug)]
pub struct Page {
    pub data: Arc<CachePage>,
    pub dirty: bool,
    /// Monotonic generation — bumps on every write so stale readers
    /// can detect they've raced.
    pub gen: u64,
}

impl Page {
    /// A fresh zeroed cache page. Panics on frame-allocation failure —
    /// a test/building-block constructor; production read paths use the
    /// fallible [`CachePage::alloc_zeroed`] and degrade under pressure.
    pub fn zeroed() -> Self {
        Self {
            data: Arc::new(CachePage::alloc_zeroed().expect("cache page frame")),
            dirty: false,
            gen: 0,
        }
    }
}

#[derive(Debug)]
struct Slot {
    page: Page,
    /// CLOCK reference bit: set on every cache hit, cleared when the
    /// clock hand sweeps past. An entry survives an eviction pass iff
    /// it was referenced since the last sweep (second chance).
    referenced: bool,
}

#[derive(Debug)]
struct Inner {
    pages: BTreeMap<PageKey, Slot>,
    /// CLOCK ring of resident keys. Eviction sweeps from the front,
    /// giving referenced pages a second chance (bit cleared + requeued)
    /// and evicting the first cold, clean page it meets.
    clock: VecDeque<PageKey>,
    /// Inserts since the last free-memory watermark probe. The probe
    /// reads the frame allocator (a lock + sum), so it is rate-limited
    /// to once per [`WATERMARK_CHECK_INTERVAL`] inserts rather than
    /// hit on every 4 KiB read — otherwise it contends with the read
    /// path's own frame allocations and measurably slows I/O.
    since_watermark_check: usize,
}

/// Inserts between free-memory watermark probes. 64 pages (256 KiB of
/// reads) keeps reclaim responsive while making the per-insert cost of
/// the probe negligible.
const WATERMARK_CHECK_INTERVAL: usize = 64;

/// Unified page cache. A `BTreeMap` of page-sized entries under a
/// single lock, reclaimed by CLOCK-LRU under a hard ceiling and a
/// free-memory watermark.
#[derive(Debug)]
pub struct PageCache {
    inner: IrqSafeSpinLock<Inner>,
    /// Hard resident-page ceiling backstop. Clean pages are evicted
    /// once `pages.len()` would exceed this.
    max_pages: usize,
}

impl PageCache {
    pub const fn new() -> Self {
        // `usize::MAX` = "follow the process-global default ceiling"
        // ([`set_default_capacity_pages`]), which boot sizes from RAM so
        // the cache scales with available memory instead of a fixed cap.
        Self::with_capacity(usize::MAX)
    }

    /// Construct a cache with an explicit resident-page ceiling.
    /// `0` is "unbounded" (no hard cap — only watermark reclaim, if a
    /// watermark is set, applies); `usize::MAX` follows the global
    /// default ceiling; any other value is an explicit fixed ceiling.
    pub const fn with_capacity(max_pages: usize) -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Inner {
                pages: BTreeMap::new(),
                clock: VecDeque::new(),
                since_watermark_check: 0,
            }),
            max_pages,
        }
    }

    /// Look up a page; returns `None` if not present. A hit sets the
    /// CLOCK reference bit so the entry survives the next eviction
    /// sweep (approximate-LRU recency).
    pub fn lookup(&self, key: PageKey) -> Option<Page> {
        let mut g = self.inner.lock();
        if let Some(slot) = g.pages.get_mut(&key) {
            slot.referenced = true;
            Some(slot.page.clone())
        } else {
            None
        }
    }

    /// Insert `page` under `key`, replacing any prior page, then
    /// reclaim: enforce the hard ceiling and, under memory pressure,
    /// shed a batch of cold clean pages.
    pub fn insert(&self, key: PageKey, page: Page) {
        let mut g = self.inner.lock();
        match g.pages.get_mut(&key) {
            Some(slot) => {
                // Existing key: update contents, refresh recency.
                slot.page = page;
                slot.referenced = true;
            }
            None => {
                g.pages.insert(
                    key,
                    Slot {
                        page,
                        referenced: false,
                    },
                );
                g.clock.push_back(key);
            }
        }

        // Hard-ceiling backstop. `usize::MAX` follows the RAM-sized global
        // default; `0` means unbounded (watermark reclaim only).
        let cap = if self.max_pages == usize::MAX {
            DEFAULT_CAP_PAGES.load(Ordering::Relaxed)
        } else {
            self.max_pages
        };
        if cap != 0 {
            while g.pages.len() > cap {
                if !Self::evict_one_cold_clean(&mut g) {
                    break; // nothing clean to shed
                }
            }
        }

        // Free-memory watermark reclaim (Linux-shaped). Only when a
        // watermark is configured and the allocator is under it. The
        // free-memory probe is rate-limited (it locks the allocator), so
        // it never rides every 4 KiB read.
        let low = LOW_WATERMARK_PAGES.load(Ordering::Relaxed);
        g.since_watermark_check += 1;
        if low > 0 && g.since_watermark_check >= WATERMARK_CHECK_INTERVAL {
            g.since_watermark_check = 0;
            if let Some(free) = free_pages_available() {
                if free < low {
                    let mut shed = 0;
                    while shed < RECLAIM_BATCH_PAGES
                        && g.pages.len() > RECLAIM_FLOOR_PAGES
                        && Self::evict_one_cold_clean(&mut g)
                    {
                        shed += 1;
                    }
                }
            }
        }
    }

    /// One CLOCK sweep step: evict a cold, clean page. Gives referenced
    /// pages a second chance (clear bit + requeue) and skips dirty pages
    /// (requeued — they still owe a writeback). Returns `true` if a page
    /// was evicted.
    ///
    /// The scan is bounded to a small constant window so eviction stays
    /// O(1) regardless of cache size — a full-length CLOCK lap over a
    /// mult-GiB cache on every insert-at-capacity would serialise I/O
    /// (the boot-slowdown that starved udevd's start timeout). Within
    /// the window a cold clean page is preferred; failing that, the
    /// first clean page seen is evicted (recency-approximate, still
    /// correctness-preserving) so progress is guaranteed and cheap.
    fn evict_one_cold_clean(inner: &mut Inner) -> bool {
        const MAX_SCAN: usize = 128;
        let scan = inner.clock.len().min(MAX_SCAN);
        let mut fallback_clean: Option<PageKey> = None;
        for _ in 0..scan {
            let Some(k) = inner.clock.pop_front() else {
                break;
            };
            match inner.pages.get_mut(&k) {
                None => { /* stale queue entry — drop it */ }
                Some(slot) if slot.page.dirty => {
                    inner.clock.push_back(k); // owes a writeback — keep
                }
                Some(slot) if slot.referenced => {
                    // Second chance: clear the bit, requeue, remember it
                    // as a clean fallback if the window yields no cold page.
                    slot.referenced = false;
                    fallback_clean.get_or_insert(k);
                    inner.clock.push_back(k);
                }
                Some(_) => {
                    inner.pages.remove(&k); // cold + clean → evict
                    return true;
                }
            }
        }
        // No cold clean page in the window: evict the first clean one seen
        // (it was requeued, so pull it back out).
        if let Some(k) = fallback_clean {
            if let Some(pos) = inner.clock.iter().position(|&q| q == k) {
                inner.clock.remove(pos);
            }
            inner.pages.remove(&k);
            return true;
        }
        false
    }

    /// Mark `key` dirty and bump the generation.
    pub fn mark_dirty(&self, key: PageKey) -> bool {
        if let Some(slot) = self.inner.lock().pages.get_mut(&key) {
            slot.page.dirty = true;
            slot.page.gen = slot.page.gen.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Drain dirty entries for writeback. Returns the (key, page)
    /// pairs the caller should flush; clears the `dirty` flag on
    /// each in-cache entry so concurrent writers can re-dirty without
    /// losing coverage. Stage-4 writeback worker awaits a block I/O
    /// per returned entry.
    pub fn drain_dirty(&self) -> Vec<(PageKey, Page)> {
        let mut out = Vec::new();
        let mut g = self.inner.lock();
        for (k, slot) in g.pages.iter_mut() {
            if slot.page.dirty {
                out.push((*k, slot.page.clone()));
                slot.page.dirty = false;
            }
        }
        out
    }

    /// Total resident pages.
    pub fn len(&self) -> usize {
        self.inner.lock().pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().pages.is_empty()
    }

    /// Invalidate every resident page. Filesystems with direct block writes
    /// use this when they cannot identify the exact affected cache key.
    pub fn clear(&self) {
        let mut g = self.inner.lock();
        g.pages.clear();
        g.clock.clear();
    }

    /// Number of clean (evictable) resident pages — what this cache can
    /// hand back to memory reclaim without a writeback. Dirty pages still
    /// owe a writeback and are excluded. This is the shrinker `count`.
    pub fn reclaimable(&self) -> usize {
        let g = self.inner.lock();
        g.pages.values().filter(|slot| !slot.page.dirty).count()
    }

    /// Evict up to `nr` cold, clean pages in CLOCK order and return the
    /// number actually evicted. Dirty pages are never touched. This is the
    /// shrinker `scan`: memory reclaim calls it under pressure. Allocation-
    /// free (eviction only removes entries), so it is safe on the reclaim
    /// path.
    pub fn shrink(&self, nr: usize) -> usize {
        let mut g = self.inner.lock();
        let mut freed = 0;
        while freed < nr {
            if !Self::evict_one_cold_clean(&mut g) {
                break;
            }
            freed += 1;
        }
        freed
    }
}

impl Default for PageCache {
    fn default() -> Self {
        Self::new()
    }
}
