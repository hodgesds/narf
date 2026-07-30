//! Unified page cache — Stage-4 structural shape.
//!
//! Spec: `filesystem/specification/spec.md` (Stage-4: unified page
//! cache). A single tree of page-sized entries keyed by
//! `(fs_instance, inode, page_offset)`; every read goes through the
//! cache before hitting the backing store; writes mark pages dirty
//! and a writeback worker flushes them to disk.
//!
//! The cache is bounded: clean pages are evicted in FIFO order once
//! the resident set exceeds [`DEFAULT_MAX_RESIDENT_PAGES`]. Without a
//! bound the map grows one 4 KiB `Arc` per device page ever read — a
//! full distro boot streams hundreds of MiB of shared libraries
//! (libLLVM alone is ~161 MiB) through it, exhausting RAM and
//! panicking the allocator. Dirty pages are never evicted (they still
//! owe a writeback); only clean, re-readable pages are dropped, so
//! eviction is always correctness-preserving.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// Page size in bytes. 4 KiB is the architectural minimum on both
/// x86_64 and aarch64; huge-page support is a later refinement.
pub const PAGE_SIZE: usize = 4096;

/// Default resident-page ceiling: 32 Ki pages = 128 MiB of cached
/// file data per cache. Large enough to coalesce the parallel
/// dynamic-linker reads of a distro boot (systemd's generators, then
/// Plasma) yet bounded so the cache can never grow without limit and
/// OOM the kernel. Clean pages past this are evicted FIFO on insert.
pub const DEFAULT_MAX_RESIDENT_PAGES: usize = 32 * 1024;

/// Cache key: filesystem + inode + page offset (in pages, not
/// bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageKey {
    pub fs_id: u32,
    pub inode: u64,
    pub page_off: u64,
}

/// Cached page entry. `data` is an `Arc<[u8; PAGE_SIZE]>` so readers
/// never block a writer's RCU swap; dirty pages hold the write-half
/// until writeback commits.
#[derive(Clone, Debug)]
pub struct Page {
    pub data: Arc<[u8; PAGE_SIZE]>,
    pub dirty: bool,
    /// Monotonic generation — bumps on every write so stale readers
    /// can detect they've raced.
    pub gen: u64,
}

impl Page {
    pub fn zeroed() -> Self {
        Self {
            data: Arc::new([0u8; PAGE_SIZE]),
            dirty: false,
            gen: 0,
        }
    }
}

#[derive(Debug)]
struct Inner {
    pages: BTreeMap<PageKey, Page>,
    /// Recency order of resident keys, oldest at the front. Drives
    /// eviction; a key appears at most once — re-inserting an existing
    /// key moves it to the back (refreshes recency).
    order: VecDeque<PageKey>,
}

/// Unified page cache. Stage-4 uses a `BTreeMap<PageKey, Page>`
/// under a single lock; Stage-4-refinement will shard the map
/// per-filesystem + switch readers to RCU.
#[derive(Debug)]
pub struct PageCache {
    inner: IrqSafeSpinLock<Inner>,
    /// Resident-page ceiling. Clean pages are evicted FIFO once
    /// `pages.len()` would exceed this.
    max_pages: usize,
}

impl PageCache {
    pub const fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_RESIDENT_PAGES)
    }

    /// Construct a cache with an explicit resident-page ceiling.
    /// A ceiling of 0 is treated as "unbounded" (no eviction).
    pub const fn with_capacity(max_pages: usize) -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Inner {
                pages: BTreeMap::new(),
                order: VecDeque::new(),
            }),
            max_pages,
        }
    }

    /// Look up a page; returns `None` if not present.
    pub fn lookup(&self, key: PageKey) -> Option<Page> {
        self.inner.lock().pages.get(&key).cloned()
    }

    /// Insert `page` under `key`, replacing any prior page. Evicts
    /// clean pages in FIFO order if the resident set would exceed the
    /// capacity ceiling; dirty pages are retained (they still owe a
    /// writeback).
    pub fn insert(&self, key: PageKey, page: Page) {
        let mut g = self.inner.lock();
        if g.pages.insert(key, page).is_some() {
            // Existing key: refresh its recency so an active re-fill isn't
            // the next thing evicted. Drop its stale queue position (a
            // linear scan — re-inserts are rare, callers insert on miss).
            if let Some(pos) = g.order.iter().position(|&k| k == key) {
                g.order.remove(pos);
            }
        }
        g.order.push_back(key);
        if self.max_pages == 0 {
            return;
        }
        // Evict oldest clean pages until back under the ceiling (or no
        // evictable page remains — an all-dirty cache stays resident).
        while g.pages.len() > self.max_pages {
            let scan = g.order.len();
            let mut evicted = false;
            for _ in 0..scan {
                let Some(k) = g.order.pop_front() else { break };
                match g.pages.get(&k) {
                    Some(p) if !p.dirty => {
                        g.pages.remove(&k);
                        evicted = true;
                        break;
                    }
                    // Dirty: give it another lap so writeback can claim it.
                    Some(_) => g.order.push_back(k),
                    // Stale queue entry (page already gone): just drop it.
                    None => {}
                }
            }
            if !evicted {
                break;
            }
        }
    }

    /// Mark `key` dirty and bump the generation.
    pub fn mark_dirty(&self, key: PageKey) -> bool {
        if let Some(p) = self.inner.lock().pages.get_mut(&key) {
            p.dirty = true;
            p.gen = p.gen.saturating_add(1);
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
        for (k, p) in g.pages.iter_mut() {
            if p.dirty {
                out.push((*k, p.clone()));
                p.dirty = false;
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
        g.order.clear();
    }
}

impl Default for PageCache {
    fn default() -> Self {
        Self::new()
    }
}
