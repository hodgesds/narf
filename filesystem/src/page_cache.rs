//! Unified folio cache — Stage-4 structural shape.
//!
//! Spec: `filesystem/specification/spec.md` (Stage-4: unified page
//! cache). A single tree of folio heads keyed by
//! `(fs_instance, inode, page_offset)`; every read goes through the
//! cache before hitting the backing store; writes mark folios dirty
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

/// A physically contiguous cache folio containing `2^order` pages.
///
/// The bytes live in buddy frames reached through the kernel direct map,
/// never in the slab heap. Dropping the last reference therefore returns the
/// complete run directly to the buddy allocator. Order zero is the normal
/// base-page case; larger orders provide the page-cache plumbing for
/// filesystem readahead and large sequential objects without changing the
/// cache key or reclaim APIs again.
pub struct CacheFolio {
    frame: narf_memory::PhysFrame,
    order: u8,
}

impl CacheFolio {
    /// Allocate one zeroed base-page folio, or `None` under memory pressure.
    /// Kept argument-free so existing order-zero cache fillers remain simple.
    pub fn alloc_zeroed() -> Option<Self> {
        Self::alloc_order_zeroed(0)
    }

    /// Allocate a zeroed folio containing `2^order` physically contiguous
    /// pages. Higher-order failure is recoverable: callers may retry with a
    /// smaller order or use an uncached bounded buffer.
    pub fn alloc_order_zeroed(order: u8) -> Option<Self> {
        let page_count = 1usize.checked_shl(u32::from(order))?;
        let len = PAGE_SIZE.checked_mul(page_count)?;
        let frame = if order == 0 {
            narf_memory::alloc_frame().ok()?
        } else {
            narf_memory::alloc_pages_on(narf_memory::current_cpu_node(), order).ok()?
        };
        // SAFETY: the freshly-allocated contiguous run is exclusively owned
        // here and all `len` bytes are reachable through the direct map.
        unsafe {
            core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, len);
        }
        Some(Self { frame, order })
    }

    pub const fn order(&self) -> u8 {
        self.order
    }

    pub fn page_count(&self) -> usize {
        1usize << self.order
    }

    pub fn len(&self) -> usize {
        PAGE_SIZE * self.page_count()
    }

    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl core::ops::Deref for CacheFolio {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        // SAFETY: the contiguous frame run is owned for this folio's lifetime
        // and is mapped contiguously in the kernel direct map.
        unsafe {
            core::slice::from_raw_parts(self.frame.start_address().kernel_ptr::<u8>(), self.len())
        }
    }
}

impl core::ops::DerefMut for CacheFolio {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as `Deref`; `&mut self` proves exclusive access before the
        // folio is shared through `Arc`.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.frame.start_address().kernel_mut_ptr::<u8>(),
                self.len(),
            )
        }
    }
}

impl Drop for CacheFolio {
    fn drop(&mut self) {
        if self.order == 0 {
            narf_memory::free_frame(self.frame);
        } else {
            narf_memory::free_pages(self.frame, self.order);
        }
    }
}

impl core::fmt::Debug for CacheFolio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CacheFolio")
            .field("frame", &self.frame.number())
            .field("order", &self.order)
            .finish()
    }
}

/// Cached folio entry. Readers share the same buddy-backed bytes and the
/// complete frame run returns to the buddy on last drop. Dirty folios hold the
/// cache reference until writeback commits.
#[derive(Clone, Debug)]
pub struct Folio {
    data: Arc<CacheFolio>,
    dirty: bool,
    /// Monotonic generation — bumps on every write so stale readers
    /// can detect they've raced.
    generation: u64,
}

impl Folio {
    /// Wrap an exclusively-filled cache allocation as a clean folio.
    pub fn clean(data: CacheFolio) -> Self {
        Self {
            data: Arc::new(data),
            dirty: false,
            generation: 0,
        }
    }

    /// A fresh zeroed order-zero folio. Panics on frame-allocation failure;
    /// production read paths use fallible [`CacheFolio`] allocation and
    /// degrade to a bounded uncached read under pressure.
    pub fn zeroed() -> Self {
        Self::clean(CacheFolio::alloc_zeroed().expect("cache folio frame"))
    }

    pub fn page_count(&self) -> usize {
        self.data.page_count()
    }

    pub fn order(&self) -> u8 {
        self.data.order()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Retain a bounded byte range from this folio without copying it.
    pub fn slice(&self, offset: usize, len: usize) -> Option<FolioSlice> {
        let end = offset.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(FolioSlice {
            data: self.data.clone(),
            generation: self.generation,
            offset,
            len,
        })
    }
}

/// A retained lookup result for the folio containing a requested page.
/// `page_index` is relative to the folio head and makes lookup of tail pages
/// unambiguous without splitting or copying the folio.
#[derive(Clone, Debug)]
pub struct FolioRef {
    base: PageKey,
    data: Arc<CacheFolio>,
    generation: u64,
    page_index: usize,
}

impl FolioRef {
    pub const fn base_key(&self) -> PageKey {
        self.base
    }

    pub const fn page_index(&self) -> usize {
        self.page_index
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn order(&self) -> u8 {
        self.data.order()
    }

    pub fn folio_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Bytes of the base page selected by the lookup key.
    pub fn page_bytes(&self) -> &[u8] {
        let start = self.page_index * PAGE_SIZE;
        &self.data[start..start + PAGE_SIZE]
    }

    /// Retain a bounded byte range within the selected base page.
    pub fn page_slice(&self, offset: usize, len: usize) -> Option<FolioSlice> {
        let end = offset.checked_add(len)?;
        if end > PAGE_SIZE {
            return None;
        }
        Some(FolioSlice {
            data: self.data.clone(),
            generation: self.generation,
            offset: self.page_index * PAGE_SIZE + offset,
            len,
        })
    }
}

/// An owned, zero-copy byte view into a retained cache folio.
#[derive(Clone, Debug)]
pub struct FolioSlice {
    data: Arc<CacheFolio>,
    generation: u64,
    offset: usize,
    len: usize,
}

impl FolioSlice {
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.offset..self.offset + self.len]
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::ops::Deref for FolioSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[derive(Debug)]
struct Slot {
    folio: Folio,
    /// CLOCK reference bit: set on every cache hit, cleared when the
    /// clock hand sweeps past. An entry survives an eviction pass iff
    /// it was referenced since the last sweep (second chance).
    referenced: bool,
}

#[derive(Debug)]
struct Inner {
    folios: BTreeMap<PageKey, Slot>,
    /// Resident base pages, not number of folio heads.
    resident_pages: usize,
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

/// Unified page cache. A `BTreeMap` of folio heads under a single lock,
/// reclaimed by CLOCK-LRU under a base-page ceiling and a free-memory
/// watermark.
#[derive(Debug)]
pub struct PageCache {
    inner: IrqSafeSpinLock<Inner>,
    /// Hard resident-page ceiling backstop. Clean folios are evicted once
    /// their total constituent page count would exceed this.
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
                folios: BTreeMap::new(),
                resident_pages: 0,
                clock: VecDeque::new(),
                since_watermark_check: 0,
            }),
            max_pages,
        }
    }

    fn containing_folio_key(inner: &Inner, key: PageKey) -> Option<PageKey> {
        let (&base, slot) = inner.folios.range(..=key).next_back()?;
        if base.fs_id != key.fs_id || base.inode != key.inode {
            return None;
        }
        let pages = u64::try_from(slot.folio.page_count()).ok()?;
        (key.page_off < base.page_off.saturating_add(pages)).then_some(base)
    }

    /// Look up the folio containing `key`; returns `None` if the requested
    /// page is not resident. A hit sets the CLOCK reference bit.
    pub fn lookup_folio(&self, key: PageKey) -> Option<FolioRef> {
        let mut g = self.inner.lock();
        // Order zero is the overwhelmingly common case. Keep it to one tree
        // lookup; only a possible higher-order tail pays the predecessor
        // search plus head lookup.
        if let Some(slot) = g.folios.get_mut(&key) {
            slot.referenced = true;
            return Some(FolioRef {
                base: key,
                data: slot.folio.data.clone(),
                generation: slot.folio.generation,
                page_index: 0,
            });
        }
        let base = Self::containing_folio_key(&g, key)?;
        let slot = g.folios.get_mut(&base)?;
        slot.referenced = true;
        Some(FolioRef {
            base,
            data: slot.folio.data.clone(),
            generation: slot.folio.generation,
            page_index: usize::try_from(key.page_off - base.page_off).ok()?,
        })
    }

    /// Insert a folio whose first page is `key`. The key must be naturally
    /// aligned to the folio's page count and must not overlap a different
    /// resident folio. Returns `false` without mutation when either invariant
    /// is violated; miss-fill callers may still use their private folio.
    pub fn insert_folio(&self, key: PageKey, folio: Folio) -> bool {
        let page_count = folio.page_count();
        let Ok(page_count_u64) = u64::try_from(page_count) else {
            return false;
        };
        if key.page_off % page_count_u64 != 0 {
            return false;
        }
        let Some(end) = key.page_off.checked_add(page_count_u64) else {
            return false;
        };

        let mut g = self.inner.lock();
        let exact_head = g.folios.contains_key(&key);
        if !exact_head && Self::containing_folio_key(&g, key).is_some() {
            return false;
        }
        if page_count > 1 {
            if let Some((&next, _)) = g
                .folios
                .range(key..)
                .find(|(candidate, _)| **candidate != key)
            {
                if next.fs_id == key.fs_id && next.inode == key.inode && next.page_off < end {
                    return false;
                }
            }
        }

        match g.folios.get_mut(&key) {
            Some(slot) => {
                let old_pages = slot.folio.page_count();
                slot.folio = folio;
                slot.referenced = true;
                g.resident_pages = g
                    .resident_pages
                    .saturating_sub(old_pages)
                    .saturating_add(page_count);
            }
            None => {
                g.folios.insert(
                    key,
                    Slot {
                        folio,
                        referenced: false,
                    },
                );
                g.clock.push_back(key);
                g.resident_pages = g.resident_pages.saturating_add(page_count);
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
            while g.resident_pages > cap {
                if Self::evict_one_cold_clean(&mut g, usize::MAX) == 0 {
                    break; // nothing clean to shed
                }
            }
        }

        // Free-memory watermark reclaim (Linux-shaped). Only when a
        // watermark is configured and the allocator is under it. The
        // free-memory probe is rate-limited (it locks the allocator), so
        // it never rides every 4 KiB read.
        let low = LOW_WATERMARK_PAGES.load(Ordering::Relaxed);
        g.since_watermark_check = g.since_watermark_check.saturating_add(page_count);
        if low > 0 && g.since_watermark_check >= WATERMARK_CHECK_INTERVAL {
            g.since_watermark_check = 0;
            if let Some(free) = free_pages_available() {
                if free < low {
                    let mut shed = 0;
                    while shed < RECLAIM_BATCH_PAGES && g.resident_pages > RECLAIM_FLOOR_PAGES {
                        let freed = Self::evict_one_cold_clean(&mut g, RECLAIM_BATCH_PAGES - shed);
                        if freed == 0 {
                            break;
                        }
                        shed += freed;
                    }
                }
            }
        }
        true
    }

    /// One CLOCK sweep step: evict a cold, clean folio. Gives referenced
    /// folios a second chance and skips dirty folios. Returns the number of
    /// constituent pages evicted. A folio larger than `max_pages` is skipped
    /// because reclaim must not split retained data.
    ///
    /// The scan is bounded to a small constant window so eviction stays
    /// O(1) regardless of cache size — a full-length CLOCK lap over a
    /// mult-GiB cache on every insert-at-capacity would serialise I/O
    /// (the boot-slowdown that starved udevd's start timeout). Within
    /// the window a cold clean page is preferred; failing that, the
    /// first clean page seen is evicted (recency-approximate, still
    /// correctness-preserving) so progress is guaranteed and cheap.
    fn evict_one_cold_clean(inner: &mut Inner, max_pages: usize) -> usize {
        const MAX_SCAN: usize = 128;
        let scan = inner.clock.len().min(MAX_SCAN);
        let mut fallback_clean: Option<PageKey> = None;
        for _ in 0..scan {
            let Some(k) = inner.clock.pop_front() else {
                break;
            };
            match inner.folios.get_mut(&k) {
                None => { /* stale queue entry — drop it */ }
                Some(slot) if slot.folio.dirty || slot.folio.page_count() > max_pages => {
                    inner.clock.push_back(k); // not currently evictable — keep
                }
                Some(slot) if slot.referenced => {
                    // Second chance: clear the bit, requeue, remember it
                    // as a clean fallback if the window yields no cold page.
                    slot.referenced = false;
                    fallback_clean.get_or_insert(k);
                    inner.clock.push_back(k);
                }
                Some(slot) => {
                    let pages = slot.folio.page_count();
                    inner.folios.remove(&k); // cold + clean → evict
                    inner.resident_pages = inner.resident_pages.saturating_sub(pages);
                    return pages;
                }
            }
        }
        // No cold clean page in the window: evict the first clean one seen
        // (it was requeued, so pull it back out).
        if let Some(k) = fallback_clean {
            if let Some(pos) = inner.clock.iter().position(|&q| q == k) {
                inner.clock.remove(pos);
            }
            if let Some(slot) = inner.folios.remove(&k) {
                let pages = slot.folio.page_count();
                inner.resident_pages = inner.resident_pages.saturating_sub(pages);
                return pages;
            }
        }
        0
    }

    /// Mark `key` dirty and bump the generation.
    pub fn mark_dirty(&self, key: PageKey) -> bool {
        let mut g = self.inner.lock();
        if let Some(slot) = g.folios.get_mut(&key) {
            slot.folio.dirty = true;
            slot.folio.generation = slot.folio.generation.saturating_add(1);
            return true;
        }
        let Some(base) = Self::containing_folio_key(&g, key) else {
            return false;
        };
        if let Some(slot) = g.folios.get_mut(&base) {
            slot.folio.dirty = true;
            slot.folio.generation = slot.folio.generation.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// Drain dirty entries for writeback. Returns the (key, folio)
    /// pairs the caller should flush; clears the `dirty` flag on
    /// each in-cache entry so concurrent writers can re-dirty without
    /// losing coverage. Stage-4 writeback worker awaits a block I/O
    /// per returned entry.
    pub fn drain_dirty(&self) -> Vec<(PageKey, Folio)> {
        let mut out = Vec::new();
        let mut g = self.inner.lock();
        for (k, slot) in g.folios.iter_mut() {
            if slot.folio.dirty {
                out.push((*k, slot.folio.clone()));
                slot.folio.dirty = false;
            }
        }
        out
    }

    /// Total resident pages.
    pub fn len(&self) -> usize {
        self.inner.lock().resident_pages
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().resident_pages == 0
    }

    /// Number of resident folio heads. Unlike [`Self::len`], this does not
    /// count constituent base pages.
    pub fn folio_count(&self) -> usize {
        self.inner.lock().folios.len()
    }

    /// Invalidate every folio of `(fs_id, inode)` that overlaps pages
    /// `[first_page, end_page)` — Linux `invalidate_mapping_pages` over the
    /// range a direct write just changed on the device. A multi-page folio
    /// that straddles either end goes as a whole. Pages outside the range
    /// stay cached. Returns the number of base pages dropped.
    pub fn invalidate_range(
        &self,
        fs_id: u32,
        inode: u64,
        first_page: u64,
        end_page: u64,
    ) -> usize {
        if first_page >= end_page {
            return 0;
        }
        let lo = PageKey {
            fs_id,
            inode,
            page_off: first_page,
        };
        let hi = PageKey {
            fs_id,
            inode,
            page_off: end_page,
        };
        let mut g = self.inner.lock();
        let mut victims: Vec<PageKey> = g.folios.range(lo..hi).map(|(k, _)| *k).collect();
        if let Some(head) = Self::containing_folio_key(&g, lo) {
            if head != lo {
                victims.push(head);
            }
        }
        let mut dropped = 0;
        for key in victims {
            if let Some(slot) = g.folios.remove(&key) {
                let pages = slot.folio.page_count();
                g.resident_pages = g.resident_pages.saturating_sub(pages);
                dropped += pages;
            }
        }
        // The CLOCK queue keeps the removed keys; eviction drops a key whose
        // folio is gone when it reaches it.
        dropped
    }

    /// Invalidate every resident page.
    pub fn clear(&self) {
        let mut g = self.inner.lock();
        g.folios.clear();
        g.clock.clear();
        g.resident_pages = 0;
    }

    /// Number of clean (evictable) resident pages — what this cache can
    /// hand back to memory reclaim without a writeback. Dirty pages still
    /// owe a writeback and are excluded. This is the shrinker `count`.
    pub fn reclaimable(&self) -> usize {
        let g = self.inner.lock();
        g.folios
            .values()
            .filter(|slot| !slot.folio.dirty)
            .map(|slot| slot.folio.page_count())
            .sum()
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
            let pages = Self::evict_one_cold_clean(&mut g, nr - freed);
            if pages == 0 {
                break;
            }
            freed += pages;
        }
        freed
    }
}

impl Default for PageCache {
    fn default() -> Self {
        Self::new()
    }
}
