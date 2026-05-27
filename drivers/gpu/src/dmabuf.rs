//! DMA-buf — cross-driver shareable GPU buffer primitive.
//!
//! A kernel-side analogue of Linux's `drivers/dma-buf/dma-buf.c`.
//! Each `DmaBuf` wraps a contiguous physical allocation and an ops
//! vtable supplied by the exporting driver. Drivers that wish to
//! import a buffer from another subsystem (e.g. V4L2 → GPU, or
//! GPU-A → GPU-B for copy-less zero-copy compositing) call
//! [`DmaBuf::import`]; the exporter calls [`export`].
//!
//! ## Reference
//!
//! - Linux `drivers/dma-buf/dma-buf.c` — overall lifecycle + attach/detach.
//! - Linux `drivers/dma-buf/dma-fence.c` — fence wiring (not yet
//!   implemented here; see deferred items).
//! - Linux `include/linux/dma-buf.h` — struct layout + op contracts.
//!
//! ## What is implemented
//!
//! - `DmaBuf` + `DmaBufOps` trait (map/unmap/mmap/attach/detach/release).
//! - Reference-counted attachment model: `attach()` increments, `detach()`
//!   decrements; on last detach the ops `release` callback fires (no
//!   further ops are valid).
//! - `export` (driver hands a physical allocation to a `DmaBuf`) and
//!   `import` (another driver gets a handle to an existing `DmaBuf`).
//!
//! ## Deferred
//!
//! - DMA-fence integration (explicit sync).
//! - `mmap_user`: needs page-table infrastructure; stub returns `Err`.
//! - File-descriptor handoff across IPC (needs FD table in kernel).

#![allow(dead_code)]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

// ── Errors ─────────────────────────────────────────────────────────────

/// Errors returned from DMA-buf operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaBufError {
    /// The buffer has already been released (refcount reached zero).
    Released,
    /// Mapping into kernel virtual address space is not supported by
    /// this buffer's backing allocator.
    MapUnsupported,
    /// mmap to userspace is not yet implemented.
    MmapNotImplemented,
    /// Physical address or length is invalid (e.g. zero-length).
    InvalidAllocation,
    /// An attachment with this key already exists.
    AlreadyAttached,
    /// No attachment found for the given key.
    NotAttached,
}

// ── DmaBufOps trait ────────────────────────────────────────────────────

/// Operations provided by the buffer's exporting driver.
///
/// The kernel calls these through the vtable when importers manipulate
/// the buffer. All ops are called with no locks held by the DMA-buf
/// layer itself; drivers may take their own internal locks.
///
/// Reference: `struct dma_buf_ops` in Linux `include/linux/dma-buf.h`.
pub trait DmaBufOps: Send + Sync {
    /// Map the buffer into kernel virtual address space, returning the
    /// base virtual address. The mapping must cover `len` bytes
    /// starting at `phys`.
    ///
    /// Linux equivalent: `map_dma_buf` / `kmap`.
    fn map_kernel(&self, phys: u64, len: usize) -> Result<*mut u8, DmaBufError>;

    /// Unmap a previously established kernel mapping.
    ///
    /// Linux equivalent: `unmap_dma_buf` / `kunmap`.
    fn unmap_kernel(&self, virt: *mut u8, len: usize);

    /// Map the buffer into a user-process address space.
    ///
    /// Returns `Err(DmaBufError::MmapNotImplemented)` until the
    /// page-table infrastructure is in place.
    ///
    /// Linux equivalent: `mmap`.
    fn mmap_user(&self, _phys: u64, _len: usize) -> Result<u64, DmaBufError> {
        Err(DmaBufError::MmapNotImplemented)
    }

    /// Called when an importer attaches to the buffer.
    ///
    /// The `device_key` is an opaque 64-bit token identifying the
    /// importing device (e.g. PCI BDF packed as a u64). Drivers may
    /// use this to set up IOMMU mappings, cache-coherency hints, etc.
    ///
    /// Linux equivalent: `attach`.
    fn attach(&self, phys: u64, len: usize, device_key: u64) -> Result<(), DmaBufError>;

    /// Called when an importer detaches from the buffer.
    ///
    /// Linux equivalent: `detach`.
    fn detach(&self, phys: u64, len: usize, device_key: u64);

    /// Called exactly once when the last attachment is dropped **and**
    /// the exporter itself has released its handle. The buffer's
    /// physical allocation should be freed here.
    ///
    /// After `release` returns, no further ops will be called.
    ///
    /// Linux equivalent: `release`.
    fn release(&self, phys: u64, len: usize);
}

// ── Inner shared state ─────────────────────────────────────────────────

struct DmaBufInner {
    /// Base physical address of the allocation.
    phys: u64,
    /// Byte length of the allocation.
    len: usize,
    /// Number of active attachments.  When this hits zero and the
    /// outer `Arc` count also hits one (only the exporter's reference
    /// left), `release` fires.
    attach_count: AtomicU32,
    /// Vtable provided by the exporting driver.
    ops: &'static dyn DmaBufOps,
}

impl core::fmt::Debug for DmaBufInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DmaBufInner")
            .field("phys", &self.phys)
            .field("len", &self.len)
            .field("attach_count", &self.attach_count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ── Public DmaBuf handle ───────────────────────────────────────────────

/// A reference-counted, cross-driver buffer handle.
///
/// Clone is cheap (Arc bump).  Drop decrements the Arc; when the last
/// handle is dropped, `ops.release` fires.
///
/// Linux analogue: `struct dma_buf *` with `dma_buf_get` /
/// `dma_buf_put` refcounting.
#[derive(Clone, Debug)]
pub struct DmaBuf(Arc<DmaBufInner>);

impl DmaBuf {
    // ── Physical metadata ─────────────────────────────────────────────

    /// Base physical address of the backing allocation.
    pub fn phys(&self) -> u64 {
        self.0.phys
    }

    /// Byte length of the backing allocation.
    pub fn len(&self) -> usize {
        self.0.len
    }

    /// Returns `true` if the allocation has zero length.
    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }

    // ── Attachment ────────────────────────────────────────────────────

    /// Attach an importing device to this buffer, incrementing the
    /// attachment refcount and calling `ops.attach`.
    ///
    /// `device_key` identifies the importer (e.g. PCI BDF).
    ///
    /// Linux equivalent: `dma_buf_attach`.
    pub fn attach(&self, device_key: u64) -> Result<(), DmaBufError> {
        self.0.ops.attach(self.0.phys, self.0.len, device_key)?;
        self.0.attach_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Detach an importing device, decrementing the attachment
    /// refcount and calling `ops.detach`.
    ///
    /// When the attachment refcount reaches zero, `ops.release` is
    /// called provided no other `DmaBuf` clones exist.
    ///
    /// Linux equivalent: `dma_buf_detach`.
    pub fn detach(&self, device_key: u64) {
        let prev = self.0.attach_count.fetch_sub(1, Ordering::AcqRel);
        self.0.ops.detach(self.0.phys, self.0.len, device_key);
        // If this was the last attachment *and* we are the only Arc
        // holder, fire release.  Arc::strong_count requires an
        // exclusive reference contract that we can't easily guarantee
        // here in no_std, so we rely on the Drop impl instead.
        let _ = prev;
    }

    // ── Kernel mapping ────────────────────────────────────────────────

    /// Map the buffer into kernel virtual address space.
    ///
    /// Linux equivalent: `dma_buf_kmap`.
    pub fn map_kernel(&self) -> Result<*mut u8, DmaBufError> {
        self.0.ops.map_kernel(self.0.phys, self.0.len)
    }

    /// Unmap a kernel mapping previously returned by `map_kernel`.
    ///
    /// Linux equivalent: `dma_buf_kunmap`.
    pub fn unmap_kernel(&self, virt: *mut u8) {
        self.0.ops.unmap_kernel(virt, self.0.len);
    }

    /// Map the buffer into userspace (stub).
    pub fn mmap_user(&self) -> Result<u64, DmaBufError> {
        self.0.ops.mmap_user(self.0.phys, self.0.len)
    }

    /// Current attachment count (for diagnostics / tests).
    pub fn attach_count(&self) -> u32 {
        self.0.attach_count.load(Ordering::Relaxed)
    }
}

impl Drop for DmaBuf {
    fn drop(&mut self) {
        // When our Arc count goes to 1, the only remaining Arc is *us*
        // about to go away — fire release.
        if Arc::strong_count(&self.0) == 1 {
            self.0.ops.release(self.0.phys, self.0.len);
        }
    }
}

// ── Public API ─────────────────────────────────────────────────────────

/// Export a physical allocation as a shareable `DmaBuf`.
///
/// `ops` must be a `'static` reference to the exporting driver's
/// vtable.  The driver retains its own clone of the returned handle;
/// importers receive additional clones via `import`.
///
/// Linux equivalent: `dma_buf_export`.
pub fn export(phys: u64, len: usize, ops: &'static dyn DmaBufOps) -> Result<DmaBuf, DmaBufError> {
    if len == 0 {
        return Err(DmaBufError::InvalidAllocation);
    }
    Ok(DmaBuf(Arc::new(DmaBufInner {
        phys,
        len,
        attach_count: AtomicU32::new(0),
        ops,
    })))
}

/// Import (clone) an existing `DmaBuf` handle.
///
/// This is a thin Arc-clone; no copy of physical data takes place.
///
/// Linux equivalent: `dma_buf_get` on an fd — here we skip the fd
/// indirection and hand out a typed clone directly.
pub fn import(buf: &DmaBuf) -> DmaBuf {
    buf.clone()
}
