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

use alloc::vec::Vec;
use core::mem::size_of;

use crate::compress::{self, CompressError};

/// 4 KiB — the only page size the pool understands.
pub const ZPAGE_SIZE: usize = 4096;
/// Scratch bytes required to encode one page in the worst case.
pub const ZPAGE_COMPRESSED_MAX: usize = compress::lz4_max_compressed_len(ZPAGE_SIZE);

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

/// Keep slot-directory growth to one base-page allocation at a time. Linux's
/// zsmalloc likewise grows from page-backed zspages and slab handles rather
/// than doubling one physically contiguous metadata array under pressure.
pub(crate) const ZPOOL_SLOTS_PER_CHUNK: usize = ZPAGE_SIZE / size_of::<ZpoolSlot>();
const _: () = assert!(ZPOOL_SLOTS_PER_CHUNK > 0);

/// Compressed-page pool. `Send`/`Sync`-able trivially — internal
/// vectors are owned. Concurrency control is the caller's job; the
/// `CompressedRamDisk` consumer wraps this in an `IrqSafeSpinLock`.
#[derive(Debug)]
pub struct Zpool {
    slot_chunks: Vec<Vec<ZpoolSlot>>,
    slot_count: usize,
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
            slot_chunks: Vec::new(),
            slot_count: 0,
            free_head: None,
            stats: ZpoolStats {
                stored_pages: 0,
                compressed_bytes: 0,
                raw_bytes: 0,
                eviction_count: 0,
            },
        }
    }

    #[inline]
    fn slot(&self, index: usize) -> Option<&ZpoolSlot> {
        if index >= self.slot_count {
            return None;
        }
        self.slot_chunks
            .get(index / ZPOOL_SLOTS_PER_CHUNK)?
            .get(index % ZPOOL_SLOTS_PER_CHUNK)
    }

    #[inline]
    fn slot_mut(&mut self, index: usize) -> Option<&mut ZpoolSlot> {
        if index >= self.slot_count {
            return None;
        }
        self.slot_chunks
            .get_mut(index / ZPOOL_SLOTS_PER_CHUNK)?
            .get_mut(index % ZPOOL_SLOTS_PER_CHUNK)
    }

    /// Append one slot without ever geometrically reallocating the complete
    /// directory. Both the page-sized inner chunk and the small outer index
    /// grow fallibly before an infallible push publishes the new slot.
    fn push_slot(&mut self, slot: ZpoolSlot) -> Result<u32, ZpoolError> {
        if self.slot_count >= u32::MAX as usize {
            return Err(ZpoolError::OutOfMemory);
        }
        let index = self.slot_count;
        let chunk_index = index / ZPOOL_SLOTS_PER_CHUNK;
        if chunk_index == self.slot_chunks.len() {
            self.slot_chunks
                .try_reserve(1)
                .map_err(|_| ZpoolError::OutOfMemory)?;
            let mut chunk = Vec::new();
            chunk
                .try_reserve_exact(ZPOOL_SLOTS_PER_CHUNK)
                .map_err(|_| ZpoolError::OutOfMemory)?;
            self.slot_chunks.push(chunk);
        }
        let chunk = &mut self.slot_chunks[chunk_index];
        debug_assert_eq!(chunk.len(), index % ZPOOL_SLOTS_PER_CHUNK);
        debug_assert!(chunk.len() < chunk.capacity());
        chunk.push(slot);
        self.slot_count += 1;
        Ok(index as u32)
    }

    /// Compress and store `raw`. Returns an opaque handle.
    pub fn store(&mut self, raw: &[u8; ZPAGE_SIZE]) -> Result<ZpoolHandle, ZpoolError> {
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(ZPAGE_COMPRESSED_MAX)
            .map_err(|_| ZpoolError::OutOfMemory)?;
        scratch.resize(ZPAGE_COMPRESSED_MAX, 0);
        self.store_with_scratch(raw, &mut scratch)
    }

    /// Compress and store one page using caller-owned reusable scratch.
    ///
    /// The zram batch path keeps this scratch beside its locked pool. This
    /// avoids allocating and returning an order-1 buddy block for every page
    /// merely to hold the encoder's 4,128-byte worst-case output. Only the
    /// exact compressed payload becomes persistent heap ownership.
    pub(crate) fn store_with_scratch(
        &mut self,
        raw: &[u8; ZPAGE_SIZE],
        scratch: &mut [u8],
    ) -> Result<ZpoolHandle, ZpoolError> {
        if scratch.len() < ZPAGE_COMPRESSED_MAX {
            return Err(ZpoolError::OutOfMemory);
        }
        let n = match compress::lz4_encode(raw, scratch) {
            Ok(n) => n,
            Err(CompressError::OutputTooSmall) => return Err(ZpoolError::OutOfMemory),
            // `lz4_encode` can't return other errors with a
            // pre-sized output, but keep the catch-all so the
            // codec can grow new error kinds without breaking us.
            Err(_) => return Err(ZpoolError::OutOfMemory),
        };
        let mut data = Vec::new();
        data.try_reserve_exact(n)
            .map_err(|_| ZpoolError::OutOfMemory)?;
        data.extend_from_slice(&scratch[..n]);

        let slot = ZpoolSlot::Live {
            data,
            raw_len: raw.len() as u32,
        };

        let idx = if let Some(free) = self.free_head {
            // Pop the free list. The slot at `free` is `Free(next)`.
            let next = match self.slot(free as usize) {
                Some(ZpoolSlot::Free(next)) => *next,
                Some(ZpoolSlot::Live { .. }) => {
                    unreachable!("free-list contained a live slot")
                }
                None => unreachable!("free-list index outside slot directory"),
            };
            *self
                .slot_mut(free as usize)
                .expect("validated free-list slot disappeared") = slot;
            self.free_head = next;
            free
        } else {
            self.push_slot(slot)?
        };

        self.stats.stored_pages += 1;
        self.stats.compressed_bytes += n as u64;
        self.stats.raw_bytes += raw.len() as u64;
        Ok(ZpoolHandle(idx))
    }

    /// Decompress the slot identified by `h` into `out`.
    pub fn load(&self, h: ZpoolHandle, out: &mut [u8; ZPAGE_SIZE]) -> Result<(), ZpoolError> {
        let slot = self.slot(h.0 as usize).ok_or(ZpoolError::InvalidHandle)?;
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
        let next_free = self.free_head;
        let Some(slot) = self.slot_mut(idx) else {
            return;
        };
        let (compressed_bytes, raw_bytes) = match slot {
            ZpoolSlot::Live { data, raw_len } => (data.len() as u64, *raw_len as u64),
            ZpoolSlot::Free(_) => return,
        };
        *slot = ZpoolSlot::Free(next_free);
        self.free_head = Some(h.0);
        self.stats.compressed_bytes -= compressed_bytes;
        self.stats.raw_bytes -= raw_bytes;
        self.stats.stored_pages -= 1;
        self.stats.eviction_count += 1;
    }

    /// Snapshot of pool counters.
    pub fn stats(&self) -> ZpoolStats {
        self.stats
    }

    /// Number of live + freed slots in the backing `Vec`. Test-only.
    #[doc(hidden)]
    pub fn slot_capacity(&self) -> usize {
        self.slot_count
    }
}
