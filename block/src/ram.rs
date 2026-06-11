//! In-memory `BlockDevice` backed by a heap `Vec<u8>`.
//!
//! Purpose: drive higher-level filesystems (FAT, ext, iso9660) in
//! kernel-tests without dragging in virtio-blk / NVMe queue pairs,
//! interrupt routing, or QEMU device wiring. The submit path
//! resolves `BlockRequest::buffer` against `narf_io`'s registry to
//! get the real `DmaBuffer`, then `memcpy`s between the buffer's
//! identity-mapped bytes and the device's storage.
//!
//! Single-CPU cooperative async friendly: `submit()` returns
//! `Ready` synchronously after the copy.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;

use narf_lib::sync::IrqSafeSpinLock;

use crate::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest, CancelResult,
    LbaRange,
};

/// A heap-backed block device. Wraps a `Vec<u8>` of `capacity *
/// logical_block_size` bytes; concurrent accesses serialise on the
/// inner `IrqSafeSpinLock`.
#[derive(Debug)]
pub struct RamBlockDevice {
    storage: IrqSafeSpinLock<Vec<u8>>,
    logical_block_size: u32,
    capacity_blocks: u64,
}

impl RamBlockDevice {
    /// Create a new RAM-backed device with `capacity_blocks` blocks
    /// of `logical_block_size` bytes each, zero-initialised.
    pub fn new(logical_block_size: u32, capacity_blocks: u64) -> Arc<Self> {
        let total = (logical_block_size as usize)
            .checked_mul(capacity_blocks as usize)
            .expect("RamBlockDevice capacity overflow");
        Arc::new(Self {
            storage: IrqSafeSpinLock::new(alloc::vec![0u8; total]),
            logical_block_size,
            capacity_blocks,
        })
    }

    /// Create a device whose storage is initialised from `image`.
    /// The device's `logical_block_size` is `lbs`; the image must
    /// be a whole multiple of `lbs`.
    pub fn from_image(lbs: u32, image: Vec<u8>) -> Arc<Self> {
        assert!(
            image.len() % lbs as usize == 0,
            "RamBlockDevice image length must be a multiple of lbs"
        );
        let capacity_blocks = (image.len() / lbs as usize) as u64;
        Arc::new(Self {
            storage: IrqSafeSpinLock::new(image),
            logical_block_size: lbs,
            capacity_blocks,
        })
    }

    /// Snapshot the underlying storage. Useful for tests that want
    /// to validate post-write state without re-issuing reads.
    pub fn snapshot(&self) -> Vec<u8> {
        self.storage.lock().clone()
    }

    fn byte_range(&self, lba: u64, blocks: u32) -> Result<(usize, usize), BlockError> {
        let lbs = self.logical_block_size as u64;
        let end = lba
            .checked_add(blocks as u64)
            .ok_or(BlockError::InvalidRange)?;
        if end > self.capacity_blocks {
            return Err(BlockError::InvalidRange);
        }
        let start = (lba * lbs) as usize;
        let len = (blocks as u64 * lbs) as usize;
        Ok((start, start + len))
    }
}

impl BlockDevice for RamBlockDevice {
    fn logical_block_size(&self) -> u32 {
        self.logical_block_size
    }

    fn physical_block_size(&self) -> u32 {
        self.logical_block_size
    }

    fn capacity_blocks(&self) -> u64 {
        self.capacity_blocks
    }

    fn supports(&self, f: BlockFeature) -> bool {
        matches!(f, BlockFeature::Flush | BlockFeature::WriteZeroes)
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send {
        // Resolve the cap → DmaBuffer indirection. The cap's
        // `slot.index` is the registry index `narf_io` assigned at
        // `register_with_cap` time. A revoked or stale cap fails
        // the check_live() inside `resolve_cap`.
        let buffer = narf_io::resolve_cap(&req.buffer);
        let result = self.do_io(&req, buffer);
        async move {
            BlockCompletion {
                tag: 0,
                user_tag: req.user_tag,
                result,
            }
        }
    }

    async fn flush(&self) {}

    async fn discard(&self, _r: LbaRange) {}

    async fn cancel(&self, _tag: u64) -> CancelResult {
        CancelResult::NotFound
    }
}

impl RamBlockDevice {
    fn do_io(
        &self,
        req: &BlockRequest,
        buffer: Option<Arc<narf_io::DmaBuffer>>,
    ) -> Result<(), BlockError> {
        let buffer = buffer.ok_or(BlockError::PermissionDenied)?;
        let (start, end) = self.byte_range(req.lba, req.blocks)?;
        let span = end - start;
        if buffer.len() < span {
            return Err(BlockError::InvalidRange);
        }

        // The DmaBuffer's identity-mapped bytes — see
        // `DmaBuffer::as_slice` for the safety argument. We hold a
        // strong `Arc<DmaBuffer>` for the duration of the copy so
        // the frame can't be freed under us.
        match req.op {
            BlockOp::Read => {
                let src = &self.storage.lock()[start..end];
                // SAFETY: `buffer.as_mut_ptr()` returns a raw ptr
                // into the identity-mapped DMA buffer; the cap →
                // registry resolve guarantees the buffer is alive
                // for the duration of the Arc we hold. No other
                // task is accessing the buffer because FAT
                // serialises sector ops through one volume-owned
                // cap, and we run cooperatively on a single CPU.
                let dst = unsafe { core::slice::from_raw_parts_mut(buffer.as_mut_ptr(), span) };
                dst.copy_from_slice(src);
                Ok(())
            }
            BlockOp::Write { fua: _ } => {
                // SAFETY: same identity-map argument as above.
                let src = unsafe { core::slice::from_raw_parts(buffer.as_ptr(), span) };
                let mut storage = self.storage.lock();
                storage[start..end].copy_from_slice(src);
                Ok(())
            }
            BlockOp::WriteZeroes => {
                let mut storage = self.storage.lock();
                for b in &mut storage[start..end] {
                    *b = 0;
                }
                Ok(())
            }
            BlockOp::Trim => Ok(()),
        }
    }
}
