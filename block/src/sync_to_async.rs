//! Sync→Async block-device adapter.
//!
//! Wraps `Arc<dyn BlockDeviceSync>` and implements [`BlockDevice`]
//! (the async, cap-gated trait). The point: file-system drivers
//! that target `BlockDevice` (Ext2Volume, FatVolume, etc.) can be
//! constructed from a sync block device via this adapter, which is
//! what `root_mount`'s factory layer needs to wire up FS auto-mount
//! from any [`BlockDeviceSync`] (NVMe partition, USB MSC partition,
//! ramdisk, encrypted overlay).
//!
//! ## Why the adapter exists
//!
//! Two traits exist for historical / layering reasons:
//!
//! - **`BlockDeviceSync`** (this crate) — sync, `&mut [u8]`-based,
//!   `Arc<dyn>`-friendly. Used by the registry (storage drivers
//!   register here) and the partition / root-mount walkers.
//! - **`BlockDevice`** — async, cap-gated, uses `impl Future` so
//!   it isn't `dyn`-compatible. File-system drivers consume this
//!   directly via generic `B: BlockDevice`.
//!
//! The sync trait's call shape (read N blocks into a slice, return
//! when done) already matches what fs drivers actually want at the
//! block layer — the async/cap surface adds queueing and isolation
//! that sync callers don't care about. This adapter does the
//! "lift" via raw DMA-buffer access (no copy) and returns ready
//! futures (the underlying read/write is already done by the time
//! the future is built).
//!
//! ## Submit shape
//!
//! `submit(req)`:
//!   - resolves `req.buffer` to its [`DmaBuffer`] (cap-checked)
//!   - reads `req.blocks * lba_size()` bytes through the buffer's
//!     identity-mapped pointer
//!   - dispatches by `req.op`:
//!     - `Read` → `inner.read(lba, blocks, &mut buf)`
//!     - `Write { .. }` → `inner.write(lba, blocks, &buf)`
//!     - `WriteZeroes` / `Trim` → unsupported (`BlockError::IOError`)
//!   - returns a `core::future::Ready<BlockCompletion>`.

extern crate alloc;

use alloc::sync::Arc;
use core::future::{ready, Ready};

use narf_capabilities::Read;
use narf_io::{resolve_cap, DmaBuffer};

use crate::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest,
    BlockDeviceSync, CancelResult, LbaRange,
};

/// Adapter that exposes any `BlockDeviceSync` as a `BlockDevice`.
/// Constructed from an `Arc<dyn BlockDeviceSync>` so the registry's
/// device handles plug in unchanged.
///
/// The struct is `Clone` because the inner Arc is — cloning is
/// cheap and lets the FS layer hand out the same underlying device
/// to multiple drivers / partition wrappers.
#[derive(Clone)]
pub struct SyncBlock {
    inner: Arc<dyn BlockDeviceSync>,
}

impl SyncBlock {
    /// Wrap a sync block device.
    pub fn new(inner: Arc<dyn BlockDeviceSync>) -> Self {
        Self { inner }
    }

    /// Borrow the underlying sync device. Useful for the partition
    /// scanner which still wants the sync read shape.
    pub fn inner(&self) -> &Arc<dyn BlockDeviceSync> {
        &self.inner
    }
}

impl core::fmt::Debug for SyncBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyncBlock")
            .field("lba_size", &self.inner.lba_size())
            .field("capacity", &self.inner.capacity())
            .finish()
    }
}

impl BlockDevice for SyncBlock {
    fn logical_block_size(&self) -> u32 {
        self.inner.lba_size()
    }

    fn physical_block_size(&self) -> u32 {
        // BlockDeviceSync doesn't surface physical block size
        // distinct from logical; the legitimate fallback is to
        // report the same as logical (which is what every storage
        // driver does anyway for the bring-up arc — NVMe + USB
        // MSC both have phys == logical block).
        self.inner.lba_size()
    }

    fn capacity_blocks(&self) -> u64 {
        self.inner.capacity()
    }

    fn supports(&self, _feat: BlockFeature) -> bool {
        // Sync trait offers no feature negotiation; the safe answer
        // is "no" for every optional feature. Write-zeroes / discard
        // path in `submit` returns IOError for those ops; flush() is
        // a no-op future because the sync read/write call is
        // already synchronous-with-completion.
        false
    }

    fn submit(&self, req: BlockRequest) -> impl core::future::Future<Output = BlockCompletion> + Send {
        let result = submit_blocking(&self.inner, &req);
        ready(BlockCompletion {
            tag: req.user_tag,
            user_tag: req.user_tag,
            result,
        })
    }

    fn flush(&self) -> impl core::future::Future<Output = ()> + Send {
        // Sync trait has no flush — the underlying driver's sync
        // calls are flush-on-completion. No-op future.
        ready(())
    }

    fn discard(&self, _range: LbaRange) -> impl core::future::Future<Output = ()> + Send {
        // Same shape — sync trait can't discard; surface as no-op.
        // Callers that need real discard go through the async
        // BlockDevice's native impl, not this adapter.
        ready(())
    }

    fn cancel(&self, _tag: u64) -> impl core::future::Future<Output = CancelResult> + Send {
        // Sync trait operations are synchronous + already-done by
        // the time submit() returns; cancellation is meaningless.
        // Surface as NotFound (the canonical "no in-flight op").
        ready(CancelResult::NotFound)
    }
}

/// Inner submit implementation — resolves cap → DmaBuffer, dispatches
/// the op. Pulled out as a free fn so submit's future-construction
/// stays a one-liner.
fn submit_blocking(
    inner: &Arc<dyn BlockDeviceSync>,
    req: &BlockRequest,
) -> Result<(), BlockError> {
    // Resolve the cap to its DmaBuffer.
    let buf: Arc<DmaBuffer> = resolve_cap::<Read>(&req.buffer).ok_or(BlockError::IOError)?;
    let total_bytes = (req.blocks as usize) * inner.lba_size() as usize;
    if buf.len() < total_bytes {
        return Err(BlockError::InvalidRange);
    }
    // SAFETY: DmaBuffer guarantees identity-mapped backing for its
    // declared length. We're the sole submitter for this request
    // (the cap is move-by-value into the request), so no parallel
    // accessor exists for the duration of the sync read/write.
    let phys = buf.phys_addr().raw();
    match req.op {
        BlockOp::Read => {
            // SAFETY: caller-asserted ownership for the duration of
            // the sync read; the buffer lives at least as long as
            // the Arc<DmaBuffer> we hold.
            let slice = unsafe {
                core::slice::from_raw_parts_mut(phys as *mut u8, total_bytes)
            };
            inner
                .read(req.lba, req.blocks as u16, slice)
                .map_err(translate_io_error)
        }
        BlockOp::Write { .. } => {
            // SAFETY: same.
            let slice = unsafe {
                core::slice::from_raw_parts(phys as *const u8, total_bytes)
            };
            inner
                .write(req.lba, req.blocks as u16, slice)
                .map_err(translate_io_error)
        }
        BlockOp::WriteZeroes | BlockOp::Trim => {
            // Sync trait doesn't expose these; the adapter can't
            // synthesise them (writing zeros via repeated writes
            // would block the I/O queue for the whole transfer,
            // and Trim has no fallback at all). Surface as IO
            // error so callers fall back to their alternate path.
            Err(BlockError::IOError)
        }
    }
}

fn translate_io_error(e: crate::BlockIoError) -> BlockError {
    match e {
        crate::BlockIoError::OutOfRange => BlockError::InvalidRange,
        crate::BlockIoError::BufferTooSmall => BlockError::InvalidRange,
        crate::BlockIoError::DeviceRemoved => BlockError::DeviceRemoved,
        crate::BlockIoError::DriverError => BlockError::IOError,
    }
}
