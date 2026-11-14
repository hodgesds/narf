//! Verified extent-data cache: decompressed extents and uncompressed windows.
//!
//! A compressed btrfs extent (CachyOS: `compress=zstd:1`, up to 128 KiB of
//! data per extent) can only be decoded whole. Without a cache, every read of
//! a file range decompresses each overlapping extent again. Demand paging an
//! executable or a shared library reads 4 KiB at a time, so a single 128 KiB
//! extent was decompressed up to 32 times per process. That made a stock
//! systemd boot from a zstd root miss its 90 s unit start timeouts.
//! Uncompressed reads also reuse checksum-checked requested windows, avoiding
//! repeated block I/O. Their compression tag is `COMPRESS_NONE`; no read is
//! widened to populate the cache. Verification-disabled views bypass this
//! uncompressed cache, so they cannot populate it with unchecked bytes.
//!
//! Correctness, since this sits on the read path of a writable root:
//!
//! - **Key.** An entry is keyed by the volume plus the extent's full
//!   identity: `disk_bytenr`, `disk_num_bytes`, the compression type and the
//!   file-extent item's `generation`. A freed extent whose bytenr is
//!   reallocated to new data carries a new generation, so it can never hit an
//!   entry for the old contents.
//! - **Writes.** Every device write goes through
//!   `BtrfsVolume::write_logical_unchecked`. It calls [`invalidate`] for the
//!   written range before and after the write, which drops every overlapping
//!   entry and moves the volume's epoch. A reader records the epoch before its
//!   device read and only inserts if the epoch has not moved, so bytes read
//!   while a write was in flight are never published.
//! - **Per shared core.** Entries are keyed by the filesystem's shared
//!   `VolCore` (see [`crate::registry`]), so every subvolume mount of one
//!   filesystem shares them and a write through any mount invalidates them.
//!   Entries hold a `Weak` to the core. That keeps its address from being
//!   reused while an entry exists. A dead core's entries are never served
//!   and are dropped on the next insert.
//! - **Only verified data.** Callers insert only after the compressed bytes
//!   passed the checksum check (when the volume verifies checksums) *and*
//!   decompressed successfully. Failures are never cached.
//! - **Bounded.** At most [`budget_bytes`] (a fraction of RAM,
//!   [`crate::cache_budget::DATA_CACHE`]) of heap, counting each entry's
//!   buffer and its bookkeeping. The least recently used entry is evicted
//!   first. One spinlock serializes the bookkeeping, and the data is shared
//!   out as `Arc<Vec<u8>>`, so the lock is never held across I/O or
//!   decompression. An entry-count limit also bounds the eviction scan.
//! - **Can be switched off.** `btrfs.data_cache=0` on the kernel command
//!   line makes every lookup miss and every fill a no-op ([`enabled`]), so a
//!   suspected stale read can be checked against a run without the cache.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Most entries, across all volumes: eviction scans them for the least
/// recently used one.
const MAX_ENTRIES: usize = 8192;

/// Bookkeeping an entry costs on top of its buffer: the key and entry in the
/// map's B-tree node, and the `Arc` header and `Vec` triple.
const ENTRY_OVERHEAD: usize = 128;

/// What caching `plain` costs the heap.
fn charge(plain: &Arc<Vec<u8>>) -> usize {
    plain.capacity() + ENTRY_OVERHEAD
}

/// The budget in bytes, computed from RAM on first use (0: not yet).
static BUDGET: AtomicUsize = AtomicUsize::new(0);

/// Upper bound on the heap the cache holds, across all volumes: a fraction
/// of RAM ([`crate::cache_budget::DATA_CACHE`]; 32 MiB at 4 GiB, 128 MiB
/// from 16 GiB up). It used to be a fixed 32 MiB of buffer bytes, not
/// counting the bookkeeping.
pub fn budget_bytes() -> usize {
    match BUDGET.load(Ordering::Relaxed) {
        0 => {
            let budget = crate::cache_budget::DATA_CACHE.of(crate::cache_budget::total_ram_bytes());
            BUDGET.store(budget, Ordering::Relaxed);
            budget
        }
        budget => budget,
    }
}

/// Identity of a volume: its allocation address. Stable while any entry holds
/// its `Weak`.
type VolKey = usize;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    vol: VolKey,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    compression: u8,
    generation: u64,
}

struct Entry {
    owner: Weak<dyn Any + Send + Sync>,
    plain: Arc<Vec<u8>>,
    last_use: u64,
}

struct Cache {
    entries: BTreeMap<Key, Entry>,
    bytes: usize,
    clock: u64,
    /// Per-volume write epoch.
    epochs: BTreeMap<VolKey, u64>,
}

static CACHE: IrqSafeSpinLock<Cache> = IrqSafeSpinLock::new(Cache {
    entries: BTreeMap::new(),
    bytes: 0,
    clock: 0,
    epochs: BTreeMap::new(),
});

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);

/// Maximum cached on-disk span (`BTRFS_MAX_COMPRESSED` for compressed data).
/// Uncompressed windows use the same bound so an overlapping write anywhere
/// in either kind of entry is found by the bounded invalidation scan.
pub(crate) const MAX_DISK_BYTES: u64 = 128 * 1024;

/// A cache handle for one volume.
#[derive(Clone)]
pub struct VolumeRef {
    key: VolKey,
    owner: Weak<dyn Any + Send + Sync>,
}

impl core::fmt::Debug for VolumeRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VolumeRef")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl VolumeRef {
    /// `owner` is a `Weak` to the volume's shared core.
    pub fn new(owner: Weak<dyn Any + Send + Sync>) -> Self {
        Self {
            key: owner.as_ptr() as *const () as usize,
            owner,
        }
    }

    /// Identify a volume by address only, for invalidation (no entry is
    /// created from it).
    pub fn key_of<T>(volume: *const T) -> VolKey {
        volume as *const () as usize
    }
}

/// Extent identity, as stored in its file-extent item.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExtentId {
    pub disk_bytenr: u64,
    pub disk_num_bytes: u64,
    pub compression: u8,
    pub generation: u64,
}

fn key(vol: VolKey, id: ExtentId) -> Key {
    Key {
        vol,
        disk_bytenr: id.disk_bytenr,
        disk_num_bytes: id.disk_num_bytes,
        compression: id.compression,
        generation: id.generation,
    }
}

/// Cache state from the command line: 0 not read yet, 1 on, 2 off.
static ENABLED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Whether the cache is in use: unless `btrfs.data_cache=0` is on the
/// kernel command line.
pub fn enabled() -> bool {
    match ENABLED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = narf_boot::args().value("btrfs.data_cache") != Some("0");
            ENABLED.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

/// Test-only: turn the cache on or off, as `btrfs.data_cache=` would.
#[cfg(feature = "kernel-test")]
pub fn set_enabled_for_test(on: bool) {
    ENABLED.store(if on { 1 } else { 2 }, Ordering::Relaxed);
}

/// Look up a decompressed extent or verified uncompressed window.
pub fn get(vol: &VolumeRef, id: ExtentId) -> Option<Arc<Vec<u8>>> {
    if !enabled() {
        MISSES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let mut cache = CACHE.lock();
    cache.clock += 1;
    let now = cache.clock;
    match cache.entries.get_mut(&key(vol.key, id)) {
        Some(entry) if entry.owner.strong_count() > 0 => {
            entry.last_use = now;
            HITS.fetch_add(1, Ordering::Relaxed);
            Some(Arc::clone(&entry.plain))
        }
        _ => {
            MISSES.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// The volume's write epoch. Sample it before the device read of an extent
/// that may be inserted.
pub fn epoch(vol: &VolumeRef) -> u64 {
    CACHE.lock().epochs.get(&vol.key).copied().unwrap_or(0)
}

/// Insert a verified extent window or successfully decompressed extent read
/// while the volume's epoch was `epoch`. A later write epoch rejects the fill.
pub fn insert(vol: &VolumeRef, id: ExtentId, epoch_at_read: u64, plain: Arc<Vec<u8>>) {
    let size = plain.len();
    let budget = budget_bytes();
    if !enabled()
        || size == 0
        || charge(&plain) > budget / 4
        || id.disk_num_bytes == 0
        || id.disk_num_bytes > MAX_DISK_BYTES
        || (id.compression == crate::format::COMPRESS_NONE && size as u64 != id.disk_num_bytes)
    {
        return;
    }
    register_shrinker();
    let mut cache = CACHE.lock();
    if cache.epochs.get(&vol.key).copied().unwrap_or(0) != epoch_at_read {
        return;
    }
    // Drop entries of volumes that are gone.
    if cache.entries.values().any(|e| e.owner.strong_count() == 0) {
        let mut freed = 0;
        cache.entries.retain(|_, e| {
            let live = e.owner.strong_count() > 0;
            if !live {
                freed += charge(&e.plain);
            }
            live
        });
        cache.bytes -= freed;
        let live: Vec<VolKey> = cache.entries.keys().map(|k| k.vol).collect();
        cache
            .epochs
            .retain(|vol_key, _| *vol_key == vol.key || live.contains(vol_key));
    }
    let size = charge(&plain);
    while cache.bytes + size > budget || cache.entries.len() >= MAX_ENTRIES {
        let Some(victim) = cache
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_use)
            .map(|(k, _)| *k)
        else {
            break;
        };
        if let Some(entry) = cache.entries.remove(&victim) {
            cache.bytes -= charge(&entry.plain);
        }
    }
    cache.clock += 1;
    let now = cache.clock;
    let entry = Entry {
        owner: vol.owner.clone(),
        plain,
        last_use: now,
    };
    if let Some(old) = cache.entries.insert(key(vol.key, id), entry) {
        cache.bytes -= charge(&old.plain);
    }
    cache.bytes += size;
}

/// Drop every entry of volume `vol` whose on-disk range overlaps
/// `[logical, logical + len)`, and move the volume's epoch.
pub fn invalidate(vol: VolKey, logical: u64, len: usize) {
    let end = logical.saturating_add(len as u64);
    let mut cache = CACHE.lock();
    *cache.epochs.entry(vol).or_insert(0) += 1;
    if cache.entries.is_empty() {
        return;
    }
    let lo = Key {
        vol,
        disk_bytenr: logical.saturating_sub(MAX_DISK_BYTES),
        disk_num_bytes: 0,
        compression: 0,
        generation: 0,
    };
    let hi = Key {
        vol,
        disk_bytenr: end,
        disk_num_bytes: 0,
        compression: 0,
        generation: 0,
    };
    let doomed: Vec<Key> = cache
        .entries
        .range(lo..hi)
        .filter(|(k, _)| k.disk_bytenr.saturating_add(k.disk_num_bytes) > logical)
        .map(|(k, _)| *k)
        .collect();
    for k in doomed {
        if let Some(entry) = cache.entries.remove(&k) {
            cache.bytes -= charge(&entry.plain);
        }
    }
}

static SHRINKER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Let reclaim shrink the cache under memory pressure. Linux keeps
/// decompressed and verified file data in the page cache, which page reclaim
/// shrinks; this cache stands in for it and gives memory back the same way.
fn register_shrinker() {
    if !SHRINKER_REGISTERED.swap(true, Ordering::AcqRel) {
        narf_memory::reclaim::register_shrinker(narf_memory::reclaim::Shrinker {
            name: "btrfs-extent-data",
            count: shrinker_count,
            scan: shrinker_scan,
        });
    }
}

/// Shrinker `count`: base pages the cache holds. Allocation-free.
fn shrinker_count() -> usize {
    CACHE.lock().bytes / crate::cache_budget::PAGE
}

/// Shrinker `scan`: evict least recently used entries worth at most `nr`
/// base pages, never reporting more. Allocation-free; the lock is taken
/// per eviction and each entry is freed outside it.
fn shrinker_scan(nr: usize) -> usize {
    (shrink_bytes(nr.saturating_mul(crate::cache_budget::PAGE))) / crate::cache_budget::PAGE
}

/// Evict least recently used entries worth at most `max_bytes`; returns the
/// bytes evicted.
fn shrink_bytes(max_bytes: usize) -> usize {
    let mut freed = 0usize;
    loop {
        let victim = {
            let mut cache = CACHE.lock();
            let Some((key, size)) = cache
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_use)
                .map(|(k, e)| (*k, charge(&e.plain)))
            else {
                break;
            };
            if freed + size > max_bytes {
                break;
            }
            cache.bytes -= size;
            freed += size;
            cache.entries.remove(&key)
        };
        drop(victim);
    }
    freed
}

/// `(hits, misses)` since boot.
pub fn stats() -> (u64, u64) {
    (HITS.load(Ordering::Relaxed), MISSES.load(Ordering::Relaxed))
}

/// Heap charged for every entry, and the entry count (tests).
#[cfg(feature = "kernel-test")]
pub fn cached_total() -> (usize, usize) {
    let cache = CACHE.lock();
    (cache.bytes, cache.entries.len())
}

/// Drive the shrinker as kswapd would: `(pages counted, pages freed)`
/// (tests).
#[cfg(feature = "kernel-test")]
pub fn __test_shrinker(nr: usize) -> (usize, usize) {
    (shrinker_count(), shrinker_scan(nr))
}

/// Cached bytes for `vol` (tests).
#[cfg(feature = "kernel-test")]
pub fn cached_bytes_for(vol: &VolumeRef) -> usize {
    CACHE
        .lock()
        .entries
        .iter()
        .filter(|(k, _)| k.vol == vol.key)
        .map(|(_, e)| e.plain.len())
        .sum()
}
