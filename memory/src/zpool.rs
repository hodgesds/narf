//! Compressed page pool.
//!
//! Stores compressed copies of 4 KiB pages indexed by an opaque
//! `ZpoolHandle`. Backed by the kernel heap — each slot owns a
//! `Vec<u8>` sized to the compressed length. A real production zpool
//! would pack many sub-allocations into 64 KiB super-blocks to fight
//! fragmentation; we leave that as follow-up work and rely on the
//! global allocator's buddy/slab to keep waste bounded. The
//! observable consequence: `compressed_bytes` is a tight lower bound
//! on RSS; actual heap occupancy is a small constant factor above.
//!
//! Eviction policy: none. The pool grows unbounded; bounded RAM
//! enforcement is the consumer's job (the `CompressedRamDisk` in
//! `compressed_block.rs` caps it by capacity).

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::{self, CompressError};

/// 4 KiB — the only page size the pool understands.
pub const ZPAGE_SIZE: usize = 4096;

/// Opaque handle returned by `Zpool::store`. Refers to a slot in the
/// pool's internal `Vec`; recycled when a slot is freed. `Copy` so
/// callers can pass it around as a cheap value type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ZpoolHandle(u32);

impl ZpoolHandle {
    /// Raw slot index; useful for trace lines / debug formatting.
    pub fn as_index(self) -> u32 {
        self.0
    }
}

/// Errors returned by `Zpool` methods.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ZpoolError {
    /// Handle doesn't refer to a live slot.
    InvalidHandle,
    /// Underlying allocator failed.
    OutOfMemory,
    /// Decompression failed mid-pipeline (slot data corrupted).
    DecompressFailed,
}

/// Aggregate counters over the pool. Snapshotted on `stats()`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ZpoolStats {
    /// Currently-live slots.
    pub stored_pages: u64,
    /// Sum of compressed-payload bytes across live slots.
    pub compressed_bytes: u64,
    /// Sum of raw-input bytes across live slots. Always
    /// `stored_pages * ZPAGE_SIZE` while pages are uniformly 4 KiB,
    /// but reported explicitly so callers can compute the ratio
    /// without re-deriving the page size.
    pub raw_bytes: u64,
    /// Number of times a slot was freed (manual eviction, not LRU).
    pub eviction_count: u64,
}

/// One slot. `None` means the slot was freed and is on the free-list.
#[derive(Debug)]
enum ZpoolSlot {
    Live { data: Vec<u8>, raw_len: u32 },
    Free(Option<u32>), // next-free index, or None for end of list
}

/// Compressed-page pool. `Send`/`Sync`-able trivially — internal
/// vectors are owned. Concurrency control is the caller's job; the
/// `CompressedRamDisk` consumer wraps this in an `IrqSafeSpinLock`.
#[derive(Debug)]
pub struct Zpool {
    slots: Vec<ZpoolSlot>,
    free_head: Option<u32>,
    stats: ZpoolStats,
}

impl Default for Zpool {
    fn default() -> Self {
        Self::new()
    }
}

impl Zpool {
    /// Empty pool. Doesn't pre-allocate any slots.
    pub const fn new() -> Self {
        Self {
            slots: Vec::new(),
            free_head: None,
            stats: ZpoolStats {
                stored_pages: 0,
                compressed_bytes: 0,
                raw_bytes: 0,
                eviction_count: 0,
            },
        }
    }

    /// Compress and store `raw`. Returns an opaque handle.
    pub fn store(&mut self, raw: &[u8; ZPAGE_SIZE]) -> Result<ZpoolHandle, ZpoolError> {
        // Bound by `lz4_max_compressed_len`; on a typical 4 KiB page
        // that's ~4112 bytes. Allocate inline and shrink afterward
        // to avoid wasting heap on slack.
        let bound = compress::lz4_max_compressed_len(raw.len());
        let mut buf = vec![0u8; bound];
        let n = match compress::lz4_encode(raw, &mut buf) {
            Ok(n) => n,
            Err(CompressError::OutputTooSmall) => return Err(ZpoolError::OutOfMemory),
            // `lz4_encode` can't return other errors with a
            // pre-sized output, but keep the catch-all so the
            // codec can grow new error kinds without breaking us.
            Err(_) => return Err(ZpoolError::OutOfMemory),
        };
        buf.truncate(n);
        buf.shrink_to_fit();

        let slot = ZpoolSlot::Live {
            data: buf,
            raw_len: raw.len() as u32,
        };

        let idx = if let Some(free) = self.free_head {
            // Pop the free list. The slot at `free` is `Free(next)`.
            let next = match &self.slots[free as usize] {
                ZpoolSlot::Free(next) => *next,
                ZpoolSlot::Live { .. } => unreachable!("free-list contained a live slot"),
            };
            self.slots[free as usize] = slot;
            self.free_head = next;
            free
        } else {
            // 2^32 - 1 slots ought to be enough — but be defensive
            // anyway since the API explicitly returns `OutOfMemory`.
            if self.slots.len() == u32::MAX as usize {
                return Err(ZpoolError::OutOfMemory);
            }
            self.slots.push(slot);
            (self.slots.len() - 1) as u32
        };

        self.stats.stored_pages += 1;
        self.stats.compressed_bytes += n as u64;
        self.stats.raw_bytes += raw.len() as u64;
        Ok(ZpoolHandle(idx))
    }

    /// Decompress the slot identified by `h` into `out`.
    pub fn load(&self, h: ZpoolHandle, out: &mut [u8; ZPAGE_SIZE]) -> Result<(), ZpoolError> {
        let slot = self
            .slots
            .get(h.0 as usize)
            .ok_or(ZpoolError::InvalidHandle)?;
        let (data, raw_len) = match slot {
            ZpoolSlot::Live { data, raw_len } => (data, *raw_len as usize),
            ZpoolSlot::Free(_) => return Err(ZpoolError::InvalidHandle),
        };
        if raw_len != ZPAGE_SIZE {
            return Err(ZpoolError::DecompressFailed);
        }
        let n = compress::lz4_decode(data, out).map_err(|_| ZpoolError::DecompressFailed)?;
        if n != ZPAGE_SIZE {
            return Err(ZpoolError::DecompressFailed);
        }
        Ok(())
    }

    /// Drop a slot. Idempotent on the invalid-handle case — silently
    /// returns. (The `BlockDeviceSync` consumer calls `free` from
    /// hot paths and treats double-frees as benign.)
    pub fn free(&mut self, h: ZpoolHandle) {
        let idx = h.0 as usize;
        if idx >= self.slots.len() {
            return;
        }
        if let ZpoolSlot::Live { data, raw_len } = &self.slots[idx] {
            self.stats.compressed_bytes -= data.len() as u64;
            self.stats.raw_bytes -= *raw_len as u64;
            self.stats.stored_pages -= 1;
            self.stats.eviction_count += 1;
            self.slots[idx] = ZpoolSlot::Free(self.free_head);
            self.free_head = Some(h.0);
        }
    }

    /// Snapshot of pool counters.
    pub fn stats(&self) -> ZpoolStats {
        self.stats
    }

    /// Number of live + freed slots in the backing `Vec`. Test-only.
    #[doc(hidden)]
    pub fn slot_capacity(&self) -> usize {
        self.slots.len()
    }
}
