//! `CompressedRamDisk` — fixed-LBA-count, page-indexed compressed
//! RAM-backed storage. Each 4 KiB LBA-block lives compressed in a
//! [`Zpool`] handle; an all-zero page is represented as the absence
//! of a handle (reads see zeros, writes of all-zero free the slot).
//!
//! Stage-1 lives in `narf-memory` as a *struct only* — no
//! `BlockDeviceSync` impl. Wiring it as a `narf-block` device
//! requires the consumer crate to depend on both `narf-block` and
//! `narf-memory`. The explicit `narf-block → narf-memory` dep edge
//! currently triggers a layout-shift latent UB elsewhere in the
//! kernel (see `docs/notes/2026-05-19-layout-shift-bug.md`); until
//! that's chased, callers who need the block-device shape build a
//! thin adapter in a new crate they own.
//!
//! Eviction is bounded by `capacity_lba` — the page index is sized
//! at construction. Heap usage scales with compressed payload total,
//! not nominal capacity.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::zpool::{Zpool, ZpoolHandle, ZpoolStats, ZPAGE_SIZE};

/// LBA-block size for the compressed RAM disk. Hard-coded to the
/// zpool's page size; mixing block sizes would force a temporary
/// 4 KiB buffer per I/O which defeats the point of an in-memory
/// device.
pub const LBA_BYTES: u32 = ZPAGE_SIZE as u32;

/// Per-LBA index entry. Wrapped under the device-wide lock so a
/// write that frees-then-stores doesn't race a concurrent read on
/// a third LBA.
struct Inner {
    pool: Zpool,
    index: Vec<Option<ZpoolHandle>>,
}

/// Compressed-RAM disk. Reads of unmapped LBAs return zeros;
/// writes of all-zero free the slot.
pub struct CompressedRamDisk {
    inner: IrqSafeSpinLock<Inner>,
    capacity_lba: u64,
}

impl core::fmt::Debug for CompressedRamDisk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompressedRamDisk")
            .field("capacity_lba", &self.capacity_lba)
            .finish_non_exhaustive()
    }
}

/// Errors from disk operations. Distinct from `narf-block`'s
/// `BlockIoError` so this crate has no upstream dep on
/// `narf-block`; an adapter that bridges the two trivially maps
/// between the variants.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RamDiskError {
    /// Caller addressed an LBA past `capacity_lba`.
    OutOfRange,
    /// Allocator failed to give the zpool a slot.
    OutOfMemory,
    /// Decompressor reported corruption.
    DecodeFailed,
    /// Caller buffer too small for the requested transfer.
    BufferTooSmall,
}

impl CompressedRamDisk {
    /// Create with `capacity_lba` 4 KiB blocks. The page index is
    /// pre-allocated; the zpool starts empty and grows as writes
    /// land.
    pub fn new(capacity_lba: u64) -> Arc<Self> {
        let mut index = Vec::new();
        index.resize(capacity_lba as usize, None);
        Arc::new(Self {
            inner: IrqSafeSpinLock::new(Inner {
                pool: Zpool::new(),
                index,
            }),
            capacity_lba,
        })
    }

    /// Total addressable LBAs.
    pub fn capacity(&self) -> u64 {
        self.capacity_lba
    }

    /// Snapshot the zpool counters. Useful for observability and
    /// tests.
    pub fn stats(&self) -> ZpoolStats {
        self.inner.lock().pool.stats()
    }

    /// Read one 4 KiB block at `lba` into a fixed-size buffer.
    pub fn read_page(&self, lba: u64, out: &mut [u8; ZPAGE_SIZE]) -> Result<(), RamDiskError> {
        if lba >= self.capacity_lba {
            return Err(RamDiskError::OutOfRange);
        }
        let inner = self.inner.lock();
        match inner.index[lba as usize] {
            None => {
                // Unmapped LBA → sparse-block semantics: zeros.
                for b in out.iter_mut() {
                    *b = 0;
                }
                Ok(())
            }
            Some(h) => inner
                .pool
                .load(h, out)
                .map_err(|_| RamDiskError::DecodeFailed),
        }
    }

    /// Write one 4 KiB block. An all-zero page frees the slot
    /// (reads of unmapped LBAs already return zeros, so the bytes
    /// remain observable to readers).
    pub fn write_page(&self, lba: u64, data: &[u8; ZPAGE_SIZE]) -> Result<(), RamDiskError> {
        if lba >= self.capacity_lba {
            return Err(RamDiskError::OutOfRange);
        }
        let mut inner = self.inner.lock();
        // All-zero shortcut. The 4 KiB scan is fast enough that
        // skipping the codec for pure-zero pages wins on common
        // sparse-file workloads (zeroing a fresh allocation,
        // tmpfs-style scratch). Codec dominates on the non-zero
        // path so vectorising the scan isn't worth the noise.
        if data.iter().all(|b| *b == 0) {
            if let Some(h) = inner.index[lba as usize].take() {
                inner.pool.free(h);
            }
            return Ok(());
        }
        // Drop the prior version before storing the new one.
        // Peak heap during overwrite is then bounded by old + new
        // compressed sizes — cheap for 4 KiB blobs.
        if let Some(h) = inner.index[lba as usize].take() {
            inner.pool.free(h);
        }
        let h = inner
            .pool
            .store(data)
            .map_err(|_| RamDiskError::OutOfMemory)?;
        inner.index[lba as usize] = Some(h);
        Ok(())
    }

    /// Read `n_blocks` contiguous LBAs starting at `lba` into
    /// `out`. Convenience over the page-at-a-time accessor.
    pub fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), RamDiskError> {
        let n = n_blocks as usize;
        if n == 0 {
            return Ok(());
        }
        let bytes_needed = n * ZPAGE_SIZE;
        if out.len() < bytes_needed {
            return Err(RamDiskError::BufferTooSmall);
        }
        let end = lba
            .checked_add(n as u64)
            .ok_or(RamDiskError::OutOfRange)?;
        if end > self.capacity_lba {
            return Err(RamDiskError::OutOfRange);
        }
        for i in 0..n {
            let slice = &mut out[i * ZPAGE_SIZE..(i + 1) * ZPAGE_SIZE];
            let arr: &mut [u8; ZPAGE_SIZE] = slice.try_into().unwrap();
            self.read_page(lba + i as u64, arr)?;
        }
        Ok(())
    }

    /// Write `n_blocks` contiguous LBAs starting at `lba`.
    pub fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), RamDiskError> {
        let n = n_blocks as usize;
        if n == 0 {
            return Ok(());
        }
        let bytes_needed = n * ZPAGE_SIZE;
        if data.len() < bytes_needed {
            return Err(RamDiskError::BufferTooSmall);
        }
        let end = lba
            .checked_add(n as u64)
            .ok_or(RamDiskError::OutOfRange)?;
        if end > self.capacity_lba {
            return Err(RamDiskError::OutOfRange);
        }
        for i in 0..n {
            let slice = &data[i * ZPAGE_SIZE..(i + 1) * ZPAGE_SIZE];
            let arr: &[u8; ZPAGE_SIZE] = slice.try_into().unwrap();
            self.write_page(lba + i as u64, arr)?;
        }
        Ok(())
    }
}
