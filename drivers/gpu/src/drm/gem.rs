//! GEM — Graphics Execution Manager buffer-object lifecycle.
//!
//! GEM is the kernel-side buffer-object (BO) framework used by DRM.
//! Each GPU driver creates GEM objects for GPU-accessible allocations;
//! userspace identifies them by opaque 32-bit handles that are
//! per-open-file in Linux but per-card in our simplified model.
//!
//! ## Linux reference
//!
//! - `drivers/gpu/drm/drm_gem.c` — allocation + handle table.
//! - `include/drm/drm_gem.h` — `struct drm_gem_object`.
//! - `drivers/gpu/drm/drm_gem_shmem_helper.c` — shmem backing (we
//!   use a physical address instead as we have no paging layer yet).
//!
//! ## What is implemented
//!
//! - `GemObject` — kernel descriptor for one GPU buffer.
//! - `GemTable` — per-card handle → object table.
//! - Alloc / free / lookup by handle (O(n) for now; n is small).
//! - No mmap / prime / fence integration yet.

use alloc::vec::Vec;

// ── Handle ─────────────────────────────────────────────────────────────

/// Opaque 32-bit GEM handle given to userspace.
///
/// Linux: `uint32_t handle` in `struct drm_gem_open` etc.
pub type GemHandle = u32;

// ── GemObject ─────────────────────────────────────────────────────────

/// Errors from GEM operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GemError {
    /// Handle not found in this card's table.
    NotFound,
    /// Maximum number of live objects per card reached.
    TableFull,
    /// Requested size is zero.
    ZeroSize,
}

/// A single GEM buffer object.
///
/// In the Linux driver model this would embed `struct drm_gem_object`
/// and include a `struct dma_resv` for implicit-sync fences.  We
/// carry just the physical backing information for now; the dma-buf
/// integration is deferred until the page-table layer is ready.
///
/// Linux analogue: `struct drm_gem_object` + driver sub-struct.
#[derive(Clone, Debug)]
pub struct GemObject {
    /// Handle by which userspace references this object.
    pub handle: GemHandle,
    /// Physical base address of the backing allocation.
    pub phys: u64,
    /// Byte size of the allocation (always > 0).
    pub size: usize,
    /// True once the object has been exported as a dma-buf.
    pub exported: bool,
    /// Driver-private tag (e.g. GTT offset for Intel, VRAM page for AMD).
    pub driver_priv: u64,
}

// ── GemTable ──────────────────────────────────────────────────────────

/// Maximum simultaneous live GEM objects per card.
///
/// Sized conservatively — enough for a full compositor session without
/// a heap-growing resize strategy.
const GEM_TABLE_MAX: usize = 8192;

/// Per-card handle-to-object table.
///
/// Linux keeps this as a `struct idr` (radix tree); we use a flat Vec
/// because the cardinality is modest and linear scan cost is
/// acceptable at this stage.
#[derive(Debug, Default)]
pub struct GemTable {
    objects: Vec<GemObject>,
    /// Next handle to try.  Increments on each alloc; wraps at u32::MAX
    /// (skipping 0 which is reserved as "invalid").
    next_handle: u32,
}

impl GemTable {
    /// Create an empty handle table.
    pub fn new() -> Self {
        GemTable {
            objects: Vec::new(),
            next_handle: 1,
        }
    }

    /// Allocate a new GEM object backed by the given physical address.
    ///
    /// Returns the handle userspace will use to refer to this buffer.
    ///
    /// Linux equivalent: `drm_gem_object_alloc` + `drm_gem_handle_create`.
    pub fn alloc(&mut self, phys: u64, size: usize) -> Result<GemHandle, GemError> {
        if size == 0 {
            return Err(GemError::ZeroSize);
        }
        if self.objects.len() >= GEM_TABLE_MAX {
            return Err(GemError::TableFull);
        }
        // Find a handle not already in use.
        let handle = self.next_free_handle();
        self.next_handle = handle.wrapping_add(1).max(1);
        self.objects.push(GemObject {
            handle,
            phys,
            size,
            exported: false,
            driver_priv: 0,
        });
        Ok(handle)
    }

    /// Free a GEM object by handle.
    ///
    /// Linux equivalent: `drm_gem_handle_delete` + `drm_gem_object_put`.
    pub fn free(&mut self, handle: GemHandle) -> Result<(), GemError> {
        let pos = self
            .objects
            .iter()
            .position(|o| o.handle == handle)
            .ok_or(GemError::NotFound)?;
        self.objects.swap_remove(pos);
        Ok(())
    }

    /// Look up an object by handle (immutable).
    pub fn lookup(&self, handle: GemHandle) -> Option<&GemObject> {
        self.objects.iter().find(|o| o.handle == handle)
    }

    /// Look up an object by handle (mutable).
    pub fn lookup_mut(&mut self, handle: GemHandle) -> Option<&mut GemObject> {
        self.objects.iter_mut().find(|o| o.handle == handle)
    }

    /// Number of live objects in the table.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Returns `true` if there are no live objects.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    // ── Internal ─────────────────────────────────────────────────────

    fn next_free_handle(&self) -> GemHandle {
        let mut candidate = self.next_handle;
        loop {
            if candidate == 0 {
                candidate = 1;
            }
            if !self.objects.iter().any(|o| o.handle == candidate) {
                return candidate;
            }
            candidate = candidate.wrapping_add(1).max(1);
        }
    }
}
