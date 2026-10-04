//! Unified folio cache — the NARF analogue of Linux `mm/filemap.c`.
//!
//! Spec: `filesystem/specification/spec.md` §3 "Page cache". One tree of
//! folio heads keyed by `(fs_instance, inode, page_offset)`.
//!
//! # The fill protocol lives here, not in filesystems
//!
//! Linux never lets a filesystem publish a page-cache folio by itself:
//! `filemap_read_folio` / `filemap_create_folio` add a *locked, !uptodate*
//! folio to the mapping before the read is issued, concurrent readers find it
//! and sleep on the folio lock, and truncation/invalidation of that index
//! removes the folio so the filler's result never becomes visible. NARF
//! encodes the same protocol in [`PageCache::get_or_fill`]:
//!
//!  1. **lookup** — a resident folio is returned immediately (a hit never
//!     queues behind an unrelated miss);
//!  2. **miss coalescing** — the first miss installs a *fill ticket*
//!     ([`SlotState::Filling`]) for exactly the folio's page range under the
//!     cache lock; later misses on any page of that range park on the ticket
//!     instead of issuing their own device read;
//!  3. **fill** — the caller's async `fill` runs with no cache lock held;
//!  4. **publish** — the folio replaces the ticket only if the ticket is
//!     still the one it installed.
//!
//! Invalidation is **per key**: [`PageCache::invalidate_range`] removes the
//! fill tickets that overlap its range together with the resident folios, so
//! a fill refuses to publish exactly when *its own* pages were written while
//! it read them. A write to any other page leaves the fill alone. Because the
//! ticket is installed before the fill starts its device read, and an
//! invalidation runs after the device write completes, either the fill's read
//! starts after the write (and sees it) or the ticket is gone (and the stale
//! bytes are never cached) — the same argument as Linux's locked-folio /
//! `invalidate_inode_pages2` interplay, with no volume-global generation.
//!
//! # Lock order and reclaim (load-bearing)
//!
//! * `Inner` is an [`IrqSafeSpinLock`]. It is **never held across an
//!   `.await`** (the fill runs unlocked) and **never held while calling a
//!   waker** (waiters are collected under the lock and woken after it drops).
//! * Allocation while `Inner` is held (BTreeMap / VecDeque / waiter-Vec
//!   growth) is sound only because `GlobalAlloc` never enters reclaim:
//!   `narf_memory::reclaim::GLOBAL_ALLOC_RUNS_SHRINKERS` is `false`, pinned by
//!   memory's `smoke_global_alloc_failure_has_no_inline_reclaim_or_retry`,
//!   and asserted at compile time below. Should that ever change, the
//!   shrinker would re-enter this lock on the same CPU.
//! * As a second, structural guard the shrinker entry points
//!   ([`PageCache::shrink`], [`PageCache::reclaimable`]) only `try_lock` the
//!   cache: a contended (or, hypothetically, re-entered) cache is skipped
//!   rather than deadlocked — the same policy as Linux's `trylock_super` in
//!   `super_cache_scan`.
//! * Folio frames are allocated *outside* the lock (`CacheFolio::alloc_*`),
//!   by the filler, after it owns the ticket.
//! * Registry order is `PAGE_CACHE_REGISTRY` → `Inner`.
//!
//! # Reclaim
//!
//! Two pressures shrink the cache, both evicting only CLEAN, resident folios
//! via a CLOCK (second-chance approximate-LRU): a hard resident-page ceiling
//! ([`PageCache::with_capacity`]) and a free-memory watermark
//! ([`set_low_watermark_pages`]). Dirty folios still owe a writeback and fill
//! tickets own no frame; neither is ever evicted.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

use crate::FsError;

// Allocation under `Inner` (see the module docs) is only deadlock-free while
// the global allocator never runs a shrinker inline. This is a cross-crate
// invariant: the memory crate owns the behaviour and its test; this crate
// owns the lock that would deadlock.
const _: () = assert!(
    !narf_memory::reclaim::GLOBAL_ALLOC_RUNS_SHRINKERS,
    "page_cache allocates under its IrqSafeSpinLock; a GlobalAlloc that runs \
     shrinkers inline would re-enter PageCache::inner from the shrinker"
);

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
// `Vec`) so they are safe to drive from the memory-reclaim path.
// Lock order is always REGISTRY → cache-inner, and the cache-inner side
// is only ever `try_lock`ed from here.

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
/// bytes). Inode 0 is the filesystem's block-device mapping (Linux's
/// `bdev` inode): metadata keyed by device page.
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
/// base-page case.
///
/// Mutable access (`DerefMut`) exists only while the folio is exclusively
/// owned — i.e. inside a fill, before publication. A published folio is
/// shared through an `Arc` and is read-only through this type.
pub struct CacheFolio {
    frame: narf_memory::PhysFrame,
    order: u8,
}

impl CacheFolio {
    /// Allocate one zeroed base-page folio, or `None` under memory pressure.
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

    /// Turn an exclusively owned (never published) folio into a retained
    /// byte view. Used for private one-off reads that must not enter the
    /// cache, e.g. journal-replay overrides.
    pub fn into_private_slice(self, offset: usize, len: usize) -> Option<FolioSlice> {
        let end = offset.checked_add(len)?;
        if end > self.len() {
            return None;
        }
        Some(FolioSlice {
            data: Arc::new(self),
            offset,
            len,
        })
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

/// A retained lookup result for the folio containing a requested page.
/// `page_index` is relative to the folio head and makes lookup of tail pages
/// unambiguous without splitting or copying the folio.
#[derive(Clone, Debug)]
pub struct FolioRef {
    base: PageKey,
    data: Arc<CacheFolio>,
    page_index: usize,
}

impl FolioRef {
    pub const fn base_key(&self) -> PageKey {
        self.base
    }

    pub const fn page_index(&self) -> usize {
        self.page_index
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
            offset: self.page_index * PAGE_SIZE + offset,
            len,
        })
    }
}

/// An owned, zero-copy byte view into a retained cache folio.
#[derive(Clone, Debug)]
pub struct FolioSlice {
    data: Arc<CacheFolio>,
    offset: usize,
    len: usize,
}

impl FolioSlice {
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.offset..self.offset + self.len]
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

/// What occupies one folio-head key.
#[derive(Debug)]
enum SlotState {
    /// Uptodate folio. `dirty` folios still owe a writeback.
    Resident { folio: Arc<CacheFolio>, dirty: bool },
    /// A fill is reading this folio's `pages` pages. Linux's locked,
    /// !uptodate folio: concurrent misses on any covered page park in
    /// `waiters`; an invalidation of any covered page removes the ticket.
    Filling {
        ticket: u64,
        pages: usize,
        waiters: Vec<Waker>,
    },
}

#[derive(Debug)]
struct Slot {
    state: SlotState,
    /// CLOCK reference bit: set on every cache hit, cleared when the
    /// clock hand sweeps past. An entry survives an eviction pass iff
    /// it was referenced since the last sweep (second chance).
    referenced: bool,
}

impl Slot {
    fn pages(&self) -> usize {
        match &self.state {
            SlotState::Resident { folio, .. } => folio.page_count(),
            SlotState::Filling { pages, .. } => *pages,
        }
    }
}

#[derive(Debug)]
struct Inner {
    folios: BTreeMap<PageKey, Slot>,
    /// Resident base pages (fill tickets own no frame and are not counted).
    resident_pages: usize,
    /// CLOCK ring of resident keys. Eviction sweeps from the front,
    /// giving referenced pages a second chance (bit cleared + requeued)
    /// and evicting the first cold, clean page it meets.
    clock: VecDeque<PageKey>,
    /// Inserts since the last free-memory watermark probe. The probe
    /// reads the frame allocator (a lock + sum), so it is rate-limited
    /// to once per [`WATERMARK_CHECK_INTERVAL`] inserts.
    since_watermark_check: usize,
}

/// Inserts between free-memory watermark probes. 64 pages (256 KiB of
/// reads) keeps reclaim responsive while making the per-insert cost of
/// the probe negligible.
const WATERMARK_CHECK_INTERVAL: usize = 64;

/// Unified page cache. A `BTreeMap` of folio heads under a single lock,
/// reclaimed by CLOCK-LRU under a base-page ceiling and a free-memory
/// watermark. See the module docs for the fill protocol and lock order.
#[derive(Debug)]
pub struct PageCache {
    inner: IrqSafeSpinLock<Inner>,
    /// Hard resident-page ceiling backstop. Clean folios are evicted once
    /// their total constituent page count would exceed this.
    max_pages: usize,
    /// Source of unique fill tickets.
    next_ticket: AtomicU64,
}

/// Result of [`PageCache::get_or_fill`].
#[derive(Clone, Debug)]
pub struct Filled {
    folio: FolioRef,
    published: bool,
}

impl Filled {
    /// The folio containing the requested page.
    pub fn folio(&self) -> &FolioRef {
        &self.folio
    }

    pub fn into_folio(self) -> FolioRef {
        self.folio
    }

    /// `true` when the returned folio is the cache's resident copy (a hit,
    /// or a fill that published). `false` when this caller's own fill raced
    /// an invalidation of its range: the bytes are a valid read that
    /// linearises before the invalidating write, but they are private to
    /// this caller and were never cached — they must not be handed out as
    /// the shared copy (e.g. mapped into userspace).
    pub const fn published(&self) -> bool {
        self.published
    }
}

/// How a folio-head key relates to the current index (under `Inner`).
enum Probe {
    Hit(FolioRef),
    Wait {
        head: PageKey,
        ticket: u64,
    },
    Miss,
    /// The requested folio range overlaps a differently-shaped folio or
    /// ticket; the caller cannot cache this range at this order.
    Conflict,
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
            next_ticket: AtomicU64::new(1),
        }
    }

    /// The head of the slot (resident folio or fill ticket) covering `key`.
    fn containing_key(inner: &Inner, key: PageKey) -> Option<PageKey> {
        let (&base, slot) = inner.folios.range(..=key).next_back()?;
        if base.fs_id != key.fs_id || base.inode != key.inode {
            return None;
        }
        let pages = u64::try_from(slot.pages()).ok()?;
        (key.page_off < base.page_off.saturating_add(pages)).then_some(base)
    }

    /// Classify a request for the `2^order`-page folio headed at `head`
    /// (naturally aligned) on behalf of the page `want`.
    fn probe(inner: &mut Inner, head: PageKey, pages: u64, want: PageKey) -> Probe {
        if let Some(base) = Self::containing_key(inner, want) {
            let slot = inner
                .folios
                .get_mut(&base)
                .expect("containing key is indexed");
            return match &slot.state {
                SlotState::Resident { folio, .. } => {
                    slot.referenced = true;
                    Probe::Hit(FolioRef {
                        base,
                        data: folio.clone(),
                        page_index: (want.page_off - base.page_off) as usize,
                    })
                }
                SlotState::Filling { ticket, .. } => Probe::Wait {
                    head: base,
                    ticket: *ticket,
                },
            };
        }
        // Nothing covers `want`; the whole requested folio range must also be
        // free of other heads (a smaller folio inside it, or a larger one
        // starting before it, was handled by `containing_key` above for
        // `want` only).
        let end = head.page_off.saturating_add(pages);
        if Self::containing_key(inner, head).is_some() {
            return Probe::Conflict;
        }
        if inner.folios.range(head..).next().is_some_and(|(k, _)| {
            k.fs_id == head.fs_id && k.inode == head.inode && k.page_off < end
        }) {
            return Probe::Conflict;
        }
        Probe::Miss
    }

    /// Look up the folio containing `key`; returns `None` if the requested
    /// page is not resident (including while it is being filled). A hit sets
    /// the CLOCK reference bit.
    pub fn lookup_folio(&self, key: PageKey) -> Option<FolioRef> {
        let mut g = self.inner.lock();
        // Order zero is the overwhelmingly common case. Keep it to one tree
        // lookup; only a possible higher-order tail pays the predecessor
        // search plus head lookup.
        if let Some(slot) = g.folios.get_mut(&key) {
            if let SlotState::Resident { folio, .. } = &slot.state {
                slot.referenced = true;
                return Some(FolioRef {
                    base: key,
                    data: folio.clone(),
                    page_index: 0,
                });
            }
            return None;
        }
        let base = Self::containing_key(&g, key)?;
        let slot = g.folios.get_mut(&base)?;
        let SlotState::Resident { folio, .. } = &slot.state else {
            return None;
        };
        slot.referenced = true;
        Some(FolioRef {
            base,
            data: folio.clone(),
            page_index: usize::try_from(key.page_off - base.page_off).ok()?,
        })
    }

    /// Return the folio containing `key`, filling it on a miss — Linux
    /// `filemap_read_folio` / `filemap_get_pages`.
    ///
    /// `order` is the folio size the caller would fill; the folio head is
    /// `key` rounded down to `2^order` pages. `fill` receives a zeroed,
    /// exclusively owned folio, must populate it, and hands it back. It runs
    /// with no cache lock held and only after this caller owns the fill
    /// ticket, so at most one fill per folio range is in flight; concurrent
    /// callers wait for it and then take the hit (or, if it failed or was
    /// invalidated, retry the protocol themselves).
    ///
    /// Errors: the fill's own error; [`FsError::OutOfMemory`] when no folio
    /// frame can be allocated (callers degrade to a bounded uncached read);
    /// [`FsError::Busy`] when the requested range overlaps a differently
    /// shaped resident folio or ticket.
    pub async fn get_or_fill<F, Fut>(
        &self,
        key: PageKey,
        order: u8,
        fill: F,
    ) -> Result<Filled, FsError>
    where
        F: FnOnce(CacheFolio) -> Fut,
        Fut: Future<Output = Result<CacheFolio, FsError>>,
    {
        let pages = 1u64
            .checked_shl(u32::from(order))
            .ok_or(FsError::InvalidData)?;
        let head = PageKey {
            page_off: key.page_off - key.page_off % pages,
            ..key
        };
        let ticket = loop {
            let probe = {
                let mut g = self.inner.lock();
                match Self::probe(&mut g, head, pages, key) {
                    Probe::Miss => {
                        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
                        g.folios.insert(
                            head,
                            Slot {
                                state: SlotState::Filling {
                                    ticket,
                                    pages: pages as usize,
                                    waiters: Vec::new(),
                                },
                                referenced: false,
                            },
                        );
                        break ticket;
                    }
                    other => other,
                }
            };
            match probe {
                Probe::Hit(folio) => {
                    return Ok(Filled {
                        folio,
                        published: true,
                    })
                }
                Probe::Wait { head, ticket } => {
                    WaitForFill {
                        cache: self,
                        head,
                        ticket,
                    }
                    .await
                }
                Probe::Conflict => return Err(FsError::Busy),
                Probe::Miss => unreachable!("a miss installs its ticket and breaks"),
            }
        };

        // From here the ticket is ours. Every exit path either publishes or
        // aborts it (the guard's Drop), waking whoever parked on it.
        let guard = FillTicket {
            cache: self,
            head,
            ticket,
        };
        let folio = CacheFolio::alloc_order_zeroed(order).ok_or(FsError::OutOfMemory)?;
        let folio = Arc::new(fill(folio).await?);
        let published = guard.publish(folio.clone());
        Ok(Filled {
            folio: FolioRef {
                base: head,
                data: folio,
                page_index: (key.page_off - head.page_off) as usize,
            },
            published,
        })
    }

    /// Replace the ticket `ticket` at `head` with `folio`. Returns `false`
    /// (and leaves the index alone) when an invalidation removed the ticket.
    fn publish(&self, head: PageKey, ticket: u64, folio: Arc<CacheFolio>) -> bool {
        let page_count = folio.page_count();
        let waiters;
        {
            let mut g = self.inner.lock();
            let Some(slot) = g.folios.get_mut(&head) else {
                return false;
            };
            match &mut slot.state {
                SlotState::Filling { ticket: t, .. } if *t == ticket => {}
                _ => return false,
            }
            let old = core::mem::replace(
                &mut slot.state,
                SlotState::Resident {
                    folio,
                    dirty: false,
                },
            );
            waiters = match old {
                SlotState::Filling { waiters, .. } => waiters,
                SlotState::Resident { .. } => unreachable!("checked above"),
            };
            g.clock.push_back(head);
            g.resident_pages = g.resident_pages.saturating_add(page_count);
            self.enforce_limits(&mut g, page_count);
        }
        for w in waiters {
            w.wake();
        }
        true
    }

    /// Remove our ticket after a failed or cancelled fill.
    fn abort_fill(&self, head: PageKey, ticket: u64) {
        let waiters = {
            let mut g = self.inner.lock();
            match g.folios.get(&head).map(|slot| &slot.state) {
                Some(SlotState::Filling { ticket: t, .. }) if *t == ticket => {}
                _ => return,
            }
            match g.folios.remove(&head).map(|slot| slot.state) {
                Some(SlotState::Filling { waiters, .. }) => waiters,
                _ => unreachable!("checked above"),
            }
        };
        for w in waiters {
            w.wake();
        }
    }

    /// Insert an already-filled folio whose first page is `key`, bypassing
    /// the fill protocol. Test-only: production fills go through
    /// [`Self::get_or_fill`], which is the only race-free way to publish.
    /// The key must be naturally aligned to the folio's page count and must
    /// not overlap a different resident folio or ticket; returns `false`
    /// without mutation otherwise. An existing resident folio at exactly
    /// `key` is replaced.
    #[doc(hidden)]
    pub fn __insert_folio_for_test(&self, key: PageKey, folio: CacheFolio) -> bool {
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
        let exact = g.folios.get(&key).map(|slot| &slot.state);
        if matches!(exact, Some(SlotState::Filling { .. })) {
            return false;
        }
        let exact_head = exact.is_some();
        if !exact_head && Self::containing_key(&g, key).is_some() {
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

        let folio = Arc::new(folio);
        match g.folios.get_mut(&key) {
            Some(slot) => {
                let old_pages = slot.pages();
                slot.state = SlotState::Resident {
                    folio,
                    dirty: false,
                };
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
                        state: SlotState::Resident {
                            folio,
                            dirty: false,
                        },
                        referenced: false,
                    },
                );
                g.clock.push_back(key);
                g.resident_pages = g.resident_pages.saturating_add(page_count);
            }
        }
        self.enforce_limits(&mut g, page_count);
        true
    }

    /// Apply the hard ceiling and the free-memory watermark after `added`
    /// pages became resident. Runs under `Inner`; allocation-free.
    fn enforce_limits(&self, g: &mut Inner, added: usize) {
        // Hard-ceiling backstop. `usize::MAX` follows the RAM-sized global
        // default; `0` means unbounded (watermark reclaim only).
        let cap = if self.max_pages == usize::MAX {
            DEFAULT_CAP_PAGES.load(Ordering::Relaxed)
        } else {
            self.max_pages
        };
        if cap != 0 {
            while g.resident_pages > cap {
                if Self::evict_one_cold_clean(g, usize::MAX) == 0 {
                    break; // nothing clean to shed
                }
            }
        }

        // Free-memory watermark reclaim (Linux-shaped). Only when a
        // watermark is configured and the allocator is under it. The
        // free-memory probe is rate-limited (it locks the allocator), so
        // it never rides every 4 KiB read.
        let low = LOW_WATERMARK_PAGES.load(Ordering::Relaxed);
        g.since_watermark_check = g.since_watermark_check.saturating_add(added);
        if low > 0 && g.since_watermark_check >= WATERMARK_CHECK_INTERVAL {
            g.since_watermark_check = 0;
            if let Some(free) = free_pages_available() {
                if free < low {
                    let mut shed = 0;
                    while shed < RECLAIM_BATCH_PAGES && g.resident_pages > RECLAIM_FLOOR_PAGES {
                        let freed = Self::evict_one_cold_clean(g, RECLAIM_BATCH_PAGES - shed);
                        if freed == 0 {
                            break;
                        }
                        shed += freed;
                    }
                }
            }
        }
    }

    /// Whether a slot may be evicted by reclaim at all: a clean folio that
    /// nobody but the cache references. An extra reference means someone is
    /// using the folio *as the cache's copy* — a writer updating it in place,
    /// a reader copying out, a user mapping holding it — and evicting it then
    /// would let the next lookup refill a second, divergent copy of the same
    /// file page (Linux reclaim likewise skips folios whose refcount it
    /// cannot freeze). The count is stable here: every new reference to a
    /// resident folio is cloned out of the index under this same lock.
    fn evictable(slot: &Slot, max_pages: usize) -> bool {
        match &slot.state {
            SlotState::Resident { folio, dirty } => {
                !*dirty && folio.page_count() <= max_pages && Arc::strong_count(folio) == 1
            }
            SlotState::Filling { .. } => false,
        }
    }

    /// One CLOCK sweep step: evict a cold, clean folio. Gives referenced
    /// folios a second chance and skips dirty folios and fill tickets.
    /// Returns the number of constituent pages evicted. A folio larger than
    /// `max_pages` is skipped because reclaim must not split retained data.
    ///
    /// The scan is bounded to a small constant window so eviction stays
    /// O(1) regardless of cache size. Within the window a cold clean page is
    /// preferred; failing that, the first clean page seen is evicted
    /// (recency-approximate, still correctness-preserving).
    fn evict_one_cold_clean(inner: &mut Inner, max_pages: usize) -> usize {
        const MAX_SCAN: usize = 128;
        let scan = inner.clock.len().min(MAX_SCAN);
        let mut fallback_clean: Option<PageKey> = None;
        for _ in 0..scan {
            let Some(k) = inner.clock.pop_front() else {
                break;
            };
            match inner.folios.get_mut(&k) {
                // Stale queue entry (removed, or replaced by a ticket whose
                // eventual publish requeues the key) — drop it.
                None => {}
                Some(slot) if matches!(slot.state, SlotState::Filling { .. }) => {}
                Some(slot) if !Self::evictable(slot, max_pages) => {
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
                    let pages = slot.pages();
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
            if inner
                .folios
                .get(&k)
                .is_some_and(|slot| Self::evictable(slot, max_pages))
            {
                let slot = inner.folios.remove(&k).expect("checked above");
                let pages = slot.pages();
                inner.resident_pages = inner.resident_pages.saturating_sub(pages);
                return pages;
            }
        }
        0
    }

    /// Mark the resident folio containing `key` dirty. Returns `false` when
    /// no resident folio covers `key`.
    pub fn mark_dirty(&self, key: PageKey) -> bool {
        let mut g = self.inner.lock();
        let Some(base) = Self::containing_key(&g, key) else {
            return false;
        };
        match g.folios.get_mut(&base).map(|slot| &mut slot.state) {
            Some(SlotState::Resident { dirty, .. }) => {
                *dirty = true;
                true
            }
            _ => false,
        }
    }

    /// Collect the dirty folios of `(fs_id, inode)` whose heads lie in pages
    /// `[first_page, end_page)` for writeback, clearing their dirty bit
    /// (Linux `folio_clear_dirty_for_io`). A writeback that fails must
    /// re-mark the folio with [`Self::mark_dirty`].
    pub fn take_dirty(
        &self,
        fs_id: u32,
        inode: u64,
        first_page: u64,
        end_page: u64,
    ) -> Vec<(PageKey, FolioRef)> {
        let mut out = Vec::new();
        if first_page >= end_page {
            return out;
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
        for (k, slot) in g.folios.range_mut(lo..hi) {
            if let SlotState::Resident { folio, dirty } = &mut slot.state {
                if *dirty {
                    *dirty = false;
                    out.push((
                        *k,
                        FolioRef {
                            base: *k,
                            data: folio.clone(),
                            page_index: 0,
                        },
                    ));
                }
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
    /// count constituent base pages (nor in-flight fill tickets).
    pub fn folio_count(&self) -> usize {
        self.inner
            .lock()
            .folios
            .values()
            .filter(|slot| matches!(slot.state, SlotState::Resident { .. }))
            .count()
    }

    /// Invalidate every folio and in-flight fill of `(fs_id, inode)` that
    /// overlaps pages `[first_page, end_page)` — Linux
    /// `invalidate_mapping_pages` over the range a direct write just changed
    /// on the device, plus the locked-folio half of the fill protocol: a
    /// fill ticket in the range is removed, so that fill's (possibly
    /// pre-write) bytes are never published, and its waiters retry. A
    /// multi-page folio that straddles either end goes as a whole. Pages
    /// outside the range — and fills of them — are untouched. Dirty folios
    /// are kept (they owe a writeback; Linux skips them too). Returns the
    /// number of resident base pages dropped.
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
        let mut wake: Vec<Waker> = Vec::new();
        let mut dropped = 0;
        {
            let mut g = self.inner.lock();
            let mut victims: Vec<PageKey> = g.folios.range(lo..hi).map(|(k, _)| *k).collect();
            if let Some(head) = Self::containing_key(&g, lo) {
                if head != lo {
                    victims.push(head);
                }
            }
            for key in victims {
                let keep = matches!(
                    g.folios.get(&key).map(|slot| &slot.state),
                    Some(SlotState::Resident { dirty: true, .. })
                );
                if keep {
                    continue;
                }
                match g.folios.remove(&key).map(|slot| slot.state) {
                    Some(SlotState::Resident { folio, .. }) => {
                        let pages = folio.page_count();
                        g.resident_pages = g.resident_pages.saturating_sub(pages);
                        dropped += pages;
                    }
                    Some(SlotState::Filling { waiters, .. }) => wake.extend(waiters),
                    None => {}
                }
            }
        }
        // The CLOCK queue keeps the removed keys; eviction drops a key whose
        // folio is gone when it reaches it.
        for w in wake {
            w.wake();
        }
        dropped
    }

    /// Remove EVERY folio (dirty or not) and in-flight fill of
    /// `(fs_id, inode)` overlapping pages `[first_page, end_page)` — Linux
    /// `truncate_inode_pages_range`, for truncation and inode eviction where
    /// the bytes cease to exist. Unlike [`Self::invalidate_range`] nothing is
    /// kept. Callers that may have the pages mapped into userspace must
    /// unmap them first; a removed folio stays alive for whoever still holds
    /// a reference to it. Returns the number of resident base pages dropped.
    pub fn remove_range(&self, fs_id: u32, inode: u64, first_page: u64, end_page: u64) -> usize {
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
        let mut wake: Vec<Waker> = Vec::new();
        let mut dropped = 0;
        let mut removed: Vec<Arc<CacheFolio>> = Vec::new();
        {
            let mut g = self.inner.lock();
            let mut victims: Vec<PageKey> = g.folios.range(lo..hi).map(|(k, _)| *k).collect();
            if let Some(head) = Self::containing_key(&g, lo) {
                if head != lo {
                    victims.push(head);
                }
            }
            for key in victims {
                match g.folios.remove(&key).map(|slot| slot.state) {
                    Some(SlotState::Resident { folio, .. }) => {
                        let pages = folio.page_count();
                        g.resident_pages = g.resident_pages.saturating_sub(pages);
                        dropped += pages;
                        removed.push(folio);
                    }
                    Some(SlotState::Filling { waiters, .. }) => wake.extend(waiters),
                    None => {}
                }
            }
        }
        // Frames return to the buddy (when last referenced) outside the lock.
        drop(removed);
        for w in wake {
            w.wake();
        }
        dropped
    }

    /// Invalidate every resident page and in-flight fill.
    pub fn clear(&self) {
        let wake: Vec<Waker> = {
            let mut g = self.inner.lock();
            let mut wake = Vec::new();
            for (_, slot) in core::mem::take(&mut g.folios) {
                if let SlotState::Filling { waiters, .. } = slot.state {
                    wake.extend(waiters);
                }
            }
            g.clock.clear();
            g.resident_pages = 0;
            wake
        };
        for w in wake {
            w.wake();
        }
    }

    /// Number of clean (evictable) resident pages — what this cache can
    /// hand back to memory reclaim without a writeback. This is the
    /// shrinker `count`; a contended cache reports 0 (see module docs).
    pub fn reclaimable(&self) -> usize {
        let Some(g) = self.inner.try_lock() else {
            return 0;
        };
        g.folios
            .values()
            .filter(|slot| Self::evictable(slot, usize::MAX))
            .map(Slot::pages)
            .sum()
    }

    /// Evict up to `nr` cold, clean pages in CLOCK order and return the
    /// number actually evicted. Dirty pages are never touched. This is the
    /// shrinker `scan`: memory reclaim calls it under pressure. Allocation-
    /// free, and it only `try_lock`s the cache — a contended cache is
    /// skipped this round rather than spun on (see module docs).
    pub fn shrink(&self, nr: usize) -> usize {
        let Some(mut g) = self.inner.try_lock() else {
            return 0;
        };
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

/// Owner of one fill ticket. Dropping it without publishing (fill error,
/// allocation failure, or the filling future itself being dropped) removes
/// the ticket and wakes its waiters, so a cancelled fill can never strand
/// them.
struct FillTicket<'a> {
    cache: &'a PageCache,
    head: PageKey,
    ticket: u64,
}

impl FillTicket<'_> {
    fn publish(self, folio: Arc<CacheFolio>) -> bool {
        let this = core::mem::ManuallyDrop::new(self);
        this.cache.publish(this.head, this.ticket, folio)
    }
}

impl Drop for FillTicket<'_> {
    fn drop(&mut self) {
        self.cache.abort_fill(self.head, self.ticket);
    }
}

/// Parks until fill ticket `ticket` at `head` is published, aborted, or
/// invalidated. Readiness is re-derived from the index on every poll, so a
/// spurious wake is harmless and a missed one is impossible: the waker is
/// registered under the same lock that every ticket transition takes.
struct WaitForFill<'a> {
    cache: &'a PageCache,
    head: PageKey,
    ticket: u64,
}

impl Future for WaitForFill<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut g = self.cache.inner.lock();
        match g.folios.get_mut(&self.head).map(|slot| &mut slot.state) {
            Some(SlotState::Filling {
                ticket, waiters, ..
            }) if *ticket == self.ticket => {
                if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    waiters.push(cx.waker().clone());
                }
                Poll::Pending
            }
            _ => Poll::Ready(()),
        }
    }
}

/// One inode's page cache — Linux `struct address_space`: the single set of
/// folios through which `read(2)`, `write(2)` and every `MAP_SHARED` mapping
/// of the inode see its bytes. The filesystem keeps exactly one per
/// in-memory inode.
///
/// Folios here are updated in place (a `write(2)` copies into the cached
/// folio; a user mapping stores into it directly), so this facade never hands
/// out `&[u8]` views: bytes move only by copy through [`FileFolio`].
#[derive(Clone, Debug)]
pub struct FileMapping {
    cache: Arc<PageCache>,
    fs_id: u32,
    inode: u64,
}

impl FileMapping {
    /// A mapping over `cache` for `inode`, which must not be 0 (the block
    /// device mapping's key).
    pub fn new(cache: Arc<PageCache>, fs_id: u32, inode: u64) -> Self {
        assert!(inode != 0, "inode 0 is the block-device mapping");
        Self {
            cache,
            fs_id,
            inode,
        }
    }

    pub fn cache(&self) -> &Arc<PageCache> {
        &self.cache
    }

    fn key(&self, page: u64) -> PageKey {
        PageKey {
            fs_id: self.fs_id,
            inode: self.inode,
            page_off: page,
        }
    }

    fn wrap(folio: FolioRef, published: bool) -> FileFolio {
        FileFolio {
            page: folio.base.page_off + folio.page_index as u64,
            data: folio.data,
            offset: folio.page_index * PAGE_SIZE,
            published,
        }
    }

    /// File page `page`, read by `fill` on a miss (Linux `filemap_read_folio`
    /// with the filesystem's `->read_folio` as `fill`). See
    /// [`PageCache::get_or_fill`] for the protocol and errors.
    pub async fn get_or_fill<F, Fut>(&self, page: u64, fill: F) -> Result<FileFolio, FsError>
    where
        F: FnOnce(CacheFolio) -> Fut,
        Fut: Future<Output = Result<CacheFolio, FsError>>,
    {
        let filled = self.cache.get_or_fill(self.key(page), 0, fill).await?;
        let published = filled.published();
        Ok(Self::wrap(filled.into_folio(), published))
    }

    /// The resident page `page`, without filling.
    pub fn lookup(&self, page: u64) -> Option<FileFolio> {
        self.cache
            .lookup_folio(self.key(page))
            .map(|folio| Self::wrap(folio, true))
    }

    /// Mark the resident page `page` dirty (it owes a writeback and must
    /// not be reclaimed). `false` when the page is not resident.
    pub fn mark_dirty(&self, page: u64) -> bool {
        self.cache.mark_dirty(self.key(page))
    }

    /// Hand the dirty pages in `[first_page, end_page)` to writeback,
    /// clearing their dirty bits (re-mark on failure).
    pub fn take_dirty(&self, first_page: u64, end_page: u64) -> Vec<FileFolio> {
        self.cache
            .take_dirty(self.fs_id, self.inode, first_page, end_page)
            .into_iter()
            .map(|(_, folio)| Self::wrap(folio, true))
            .collect()
    }

    /// Drop every page from `first_page` on, dirty or not, and void fills of
    /// them — Linux `truncate_inode_pages`. Returns the pages dropped.
    pub fn remove_from(&self, first_page: u64) -> usize {
        self.cache
            .remove_range(self.fs_id, self.inode, first_page, u64::MAX)
    }
}

/// A retained page of a [`FileMapping`]. The bytes are shared with every
/// other reader, writer and mapping of the file and may change at any time,
/// so they are only ever copied: there is no `&[u8]` view of them.
#[derive(Clone, Debug)]
pub struct FileFolio {
    page: u64,
    data: Arc<CacheFolio>,
    /// Byte offset of this page within `data`.
    offset: usize,
    published: bool,
}

impl FileFolio {
    /// The file page index.
    pub const fn page(&self) -> u64 {
        self.page
    }

    /// See [`Filled::published`]: `false` means this caller's own fill was
    /// invalidated while it read, so these bytes are a private, uncached
    /// snapshot — fine to return from one `read(2)`, never to update in
    /// place or to map.
    pub const fn published(&self) -> bool {
        self.published
    }

    fn ptr(&self, offset: usize, len: usize) -> *mut u8 {
        let end = offset.checked_add(len).expect("file folio range overflow");
        assert!(end <= PAGE_SIZE, "file folio access past its page");
        // SAFETY: `data` keeps the frame run alive; `self.offset + end` is
        // within it (one page at a page-aligned offset of the folio).
        unsafe {
            self.data
                .frame
                .start_address()
                .kernel_mut_ptr::<u8>()
                .add(self.offset + offset)
        }
    }

    /// Copy `dst.len()` bytes at `offset` within the page out.
    pub fn read(&self, offset: usize, dst: &mut [u8]) {
        let src = self.ptr(offset, dst.len());
        // SAFETY: `ptr` bounds-checked the range inside the retained frame.
        // The bytes are shared memory (other writers, user mappings): no
        // Rust reference to them exists, and a racing store yields some mix
        // of old and new bytes exactly as on Linux.
        unsafe { core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), dst.len()) }
    }

    /// Copy `src` into the page at `offset` — the in-place update `write(2)`
    /// makes to the cache's copy. Only meaningful on a published folio.
    pub fn write(&self, offset: usize, src: &[u8]) {
        let dst = self.ptr(offset, src.len());
        // SAFETY: as `read`; the caller serialises writers of the file.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) }
    }

    /// Zero `len` bytes at `offset` (Linux `folio_zero_range`).
    pub fn zero(&self, offset: usize, len: usize) {
        let dst = self.ptr(offset, len);
        // SAFETY: as `write`.
        unsafe { core::ptr::write_bytes(dst, 0, len) }
    }
}

/// A filesystem's block-device mapping (Linux: the `bdev` inode's
/// `address_space`, inode 0 of [`PageKey`]): metadata blocks keyed by device
/// page. Folios published here are never modified in place — a device write
/// invalidates the pages it covers — so zero-copy `&[u8]` views
/// ([`FolioRef`], [`FolioSlice`]) of them are sound.
#[derive(Clone, Debug)]
pub struct BlockMapping {
    cache: Arc<PageCache>,
    fs_id: u32,
}

impl BlockMapping {
    pub fn new(cache: Arc<PageCache>, fs_id: u32) -> Self {
        Self { cache, fs_id }
    }

    pub fn cache(&self) -> &Arc<PageCache> {
        &self.cache
    }

    fn key(&self, page: u64) -> PageKey {
        PageKey {
            fs_id: self.fs_id,
            inode: 0,
            page_off: page,
        }
    }

    /// The device page `page`, read through `fill` on a miss. See
    /// [`PageCache::get_or_fill`].
    pub async fn get_or_fill<F, Fut>(&self, page: u64, fill: F) -> Result<Filled, FsError>
    where
        F: FnOnce(CacheFolio) -> Fut,
        Fut: Future<Output = Result<CacheFolio, FsError>>,
    {
        self.cache.get_or_fill(self.key(page), 0, fill).await
    }

    /// The resident device page `page`, without filling.
    pub fn lookup(&self, page: u64) -> Option<FolioRef> {
        self.cache.lookup_folio(self.key(page))
    }

    /// The device pages `[first_page, end_page)` changed on disk: drop them
    /// and void any fill of them (see [`PageCache::invalidate_range`]).
    pub fn invalidate(&self, first_page: u64, end_page: u64) -> usize {
        self.cache
            .invalidate_range(self.fs_id, 0, first_page, end_page)
    }
}
