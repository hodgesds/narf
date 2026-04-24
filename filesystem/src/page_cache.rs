//! Unified page cache — Stage-4 structural shape.
//!
//! Spec: `filesystem/specification/spec.md` (Stage-4: unified page
//! cache). A single tree of page-sized entries keyed by
//! `(fs_instance, inode, page_offset)`; every read goes through the
//! cache before hitting the backing store; writes mark pages dirty
//! and a writeback worker flushes them to disk.
//!
//! What lands here: the entry shape + `PageCache` surface (lookup /
//! insert / mark_dirty / writeback-drain). No actual LRU or
//! writeback thread yet — those come when `scheduler/`'s multi-queue
//! dispatch and `io/`'s real IOMMU programming land under a real
//! block device.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// Page size in bytes. 4 KiB is the architectural minimum on both
/// x86_64 and aarch64; huge-page support is a later refinement.
pub const PAGE_SIZE: usize = 4096;

/// Cache key: filesystem + inode + page offset (in pages, not
/// bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageKey {
    pub fs_id:    u32,
    pub inode:    u64,
    pub page_off: u64,
}

/// Cached page entry. `data` is an `Arc<[u8; PAGE_SIZE]>` so readers
/// never block a writer's RCU swap; dirty pages hold the write-half
/// until writeback commits.
#[derive(Clone, Debug)]
pub struct Page {
    pub data:    Arc<[u8; PAGE_SIZE]>,
    pub dirty:   bool,
    /// Monotonic generation — bumps on every write so stale readers
    /// can detect they've raced.
    pub gen:     u64,
}

impl Page {
    pub fn zeroed() -> Self {
        Self {
            data: Arc::new([0u8; PAGE_SIZE]),
            dirty: false,
            gen:   0,
        }
    }
}

/// Unified page cache. Stage-4 uses a `BTreeMap<PageKey, Page>`
/// under a single lock; Stage-4-refinement will shard the map
/// per-filesystem + switch readers to RCU.
#[derive(Debug)]
pub struct PageCache {
    pages: IrqSafeSpinLock<BTreeMap<PageKey, Page>>,
}

impl PageCache {
    pub const fn new() -> Self {
        Self { pages: IrqSafeSpinLock::new(BTreeMap::new()) }
    }

    /// Look up a page; returns `None` if not present.
    pub fn lookup(&self, key: PageKey) -> Option<Page> {
        self.pages.lock().get(&key).cloned()
    }

    /// Insert `page` under `key`, replacing any prior page.
    pub fn insert(&self, key: PageKey, page: Page) {
        self.pages.lock().insert(key, page);
    }

    /// Mark `key` dirty and bump the generation.
    pub fn mark_dirty(&self, key: PageKey) -> bool {
        if let Some(p) = self.pages.lock().get_mut(&key) {
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
        let mut g = self.pages.lock();
        for (k, p) in g.iter_mut() {
            if p.dirty {
                out.push((*k, p.clone()));
                p.dirty = false;
            }
        }
        out
    }

    /// Total resident pages.
    pub fn len(&self) -> usize { self.pages.lock().len() }

    pub fn is_empty(&self) -> bool { self.pages.lock().is_empty() }
}

impl Default for PageCache {
    fn default() -> Self { Self::new() }
}
