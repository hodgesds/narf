//! Decompressed-extent cache.
//!
//! A compressed btrfs extent (CachyOS: `compress=zstd:1`, up to 128 KiB of
//! data per extent) can only be decoded whole. Without a cache, every read of
//! a file range decompresses each overlapping extent again. Demand paging an
//! executable or a shared library reads 4 KiB at a time, so a single 128 KiB
//! extent was decompressed up to 32 times per process. That made a stock
//! systemd boot from a zstd root miss its 90 s unit start timeouts.
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
//! - **Volume lifetime.** Entries hold a `Weak` to their volume. That keeps
//!   the allocation's address from being reused while the entry exists, and a
//!   dead volume's entries are dropped on the next insert.
//! - **Only verified data.** Callers insert only after the compressed bytes
//!   passed the checksum check (when the volume verifies checksums) *and*
//!   decompressed successfully. Failures are never cached.
//! - **Bounded.** At most [`BUDGET_BYTES`] of decompressed data. The least
//!   recently used entry is evicted first. One spinlock serializes the
//!   bookkeeping, and the data is shared out as `Arc<Vec<u8>>`, so the lock is
//!   never held across I/O or decompression.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Upper bound on cached decompressed bytes, across all volumes.
pub const BUDGET_BYTES: usize = 32 << 20;

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

/// The largest compressed extent btrfs writes (`BTRFS_MAX_COMPRESSED`).
/// Invalidation scans this far below a write's start for overlapping entries.
const MAX_COMPRESSED: u64 = 128 * 1024;

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
    /// `owner` is the volume's own `self_weak`.
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

/// Look up a decompressed extent.
pub fn get(vol: &VolumeRef, id: ExtentId) -> Option<Arc<Vec<u8>>> {
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

/// Insert a verified, successfully decompressed extent read while the volume's
/// epoch was `epoch`. It is dropped if a write has moved the epoch since.
pub fn insert(vol: &VolumeRef, id: ExtentId, epoch_at_read: u64, plain: Arc<Vec<u8>>) {
    let size = plain.len();
    if size == 0 || size > BUDGET_BYTES / 4 {
        return;
    }
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
                freed += e.plain.len();
            }
            live
        });
        cache.bytes -= freed;
        let live: Vec<VolKey> = cache.entries.keys().map(|k| k.vol).collect();
        cache
            .epochs
            .retain(|vol_key, _| *vol_key == vol.key || live.contains(vol_key));
    }
    while cache.bytes + size > BUDGET_BYTES {
        let Some(victim) = cache
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_use)
            .map(|(k, _)| *k)
        else {
            break;
        };
        if let Some(entry) = cache.entries.remove(&victim) {
            cache.bytes -= entry.plain.len();
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
        cache.bytes -= old.plain.len();
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
        disk_bytenr: logical.saturating_sub(MAX_COMPRESSED),
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
            cache.bytes -= entry.plain.len();
        }
    }
}

/// `(hits, misses)` since boot.
pub fn stats() -> (u64, u64) {
    (HITS.load(Ordering::Relaxed), MISSES.load(Ordering::Relaxed))
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
