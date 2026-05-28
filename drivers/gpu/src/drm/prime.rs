//! DRM PRIME — handle ↔ fd bridge to dma-buf.
//!
//! PRIME is the per-fd cache that maps DRM GEM handles to dma-buf
//! file descriptors and back.  Userspace uses
//! `DRM_IOCTL_PRIME_HANDLE_TO_FD` to turn a per-driver GEM handle into
//! a shareable dma-buf fd, then `DRM_IOCTL_PRIME_FD_TO_HANDLE` on the
//! receiving driver to import the same buffer as a new GEM handle.
//! Mesa uses this to hand framebuffers from amdgpu / i915 / nouveau to
//! vaapi, V4L2, or another GPU driver.
//!
//! Linux model:
//!
//! - Per-file `drm_prime_file_private` holds two maps:
//!   `handle_to_buf` (dma-buf ptr → handle) and `buf_to_handle`
//!   (handle → dma-buf ptr).
//! - On HANDLE_TO_FD: look up GEM, call driver's `export` (or
//!   `drm_gem_prime_export`), allocate an fd that wraps the dma-buf.
//! - On FD_TO_HANDLE: pull the dma-buf from the fd, look up the
//!   cached handle (if any), or call driver's `gem_prime_import` to
//!   create one.
//!
//! What is implemented:
//!
//! - [`PrimeTable`] — per-fd bidirectional handle↔fd map.
//! - [`PrimeTable::handle_to_fd`] — given a [`GemHandle`] + DmaBuf,
//!   allocate an fd and cache the binding.
//! - [`PrimeTable::fd_to_handle`] — given an fd, recover the cached
//!   handle (or report `NotFound` if the fd isn't an exported binding
//!   from this fd-table).
//! - Cross-driver hand-off — two tables exchanging an fd both reach
//!   the same DmaBuf.
//!
//! ## Deferred
//!
//! - Real kernel fd table — we synthesise fds in the per-table range
//!   `[4096..)` so unit tests can verify round-trips without a real
//!   userspace fd allocator.  Once the kernel fd-table lands these
//!   numbers become real fds.
//! - `DRM_CLOEXEC` flag handling — no fd flags to honour yet.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_prime.c::drm_gem_prime_handle_to_fd`
//! - `drivers/gpu/drm/drm_prime.c::drm_gem_prime_fd_to_handle`
//! - `drivers/gpu/drm/drm_prime.c::drm_prime_add_buf_handle`
//! - `drivers/gpu/drm/drm_prime.c::drm_prime_lookup_buf_handle`

use alloc::vec::Vec;
use crate::dmabuf::DmaBuf;
use super::gem::GemHandle;

// ── Errors ─────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrimeError {
    /// No binding found for the requested fd or handle.
    NotFound,
    /// Handle does not exist in the GEM table — Linux returns -ENOENT.
    BadHandle,
    /// Per-fd binding table at capacity.
    Full,
    /// FD passed to fd_to_handle is not in the importable range.
    BadFd,
}

// ── Binding ────────────────────────────────────────────────────────────

/// One (handle, fd, dma_buf) cached binding.
///
/// Linux: an `xa_entry` in `file_priv->prime.dmabufs` and
/// `file_priv->prime.handles`.
#[derive(Clone, Debug)]
pub struct PrimeBinding {
    /// GEM handle on this fd.
    pub handle: GemHandle,
    /// fd assigned for this binding (per-table).
    pub fd: i32,
    /// Shared dma-buf the GEM/handle pair wraps.
    pub buf: DmaBuf,
}

// ── PrimeTable ─────────────────────────────────────────────────────────

const PRIME_TABLE_MAX: usize = 1024;
/// Synthesised fd allocator start.  Real kernel fds live below 4096
/// in our convention; PRIME exported fds start above to avoid clashes.
const PRIME_FD_BASE: i32 = 4096;

/// Per-fd PRIME binding table.
///
/// Linux equivalent: `struct drm_prime_file_private`.
#[derive(Debug, Default)]
pub struct PrimeTable {
    bindings: Vec<PrimeBinding>,
    /// Next fd to allocate.  Wraps at i32::MAX (we expect the table
    /// cap to bite first).
    next_fd: i32,
}

impl PrimeTable {
    /// New empty table.
    pub fn new() -> Self {
        PrimeTable { bindings: Vec::new(), next_fd: PRIME_FD_BASE }
    }

    /// Number of live PRIME bindings.
    pub fn len(&self) -> usize { self.bindings.len() }
    pub fn is_empty(&self) -> bool { self.bindings.is_empty() }

    /// HANDLE_TO_FD — export a GEM handle as a dma-buf fd.
    ///
    /// `handle` is the GEM handle on this fd; `buf` is the
    /// `DmaBuf` the GEM object's `prime_export` callback returned.
    ///
    /// If the handle was already exported (cached binding present),
    /// returns the existing fd.  Otherwise allocates a fresh fd and
    /// caches the binding.
    ///
    /// Linux equivalent: `drm_gem_prime_handle_to_fd`.
    pub fn handle_to_fd(&mut self, handle: GemHandle, buf: DmaBuf) -> Result<i32, PrimeError> {
        if let Some(b) = self.bindings.iter().find(|b| b.handle == handle) {
            return Ok(b.fd);
        }
        if self.bindings.len() >= PRIME_TABLE_MAX {
            return Err(PrimeError::Full);
        }
        let fd = self.alloc_fd();
        self.bindings.push(PrimeBinding { handle, fd, buf });
        Ok(fd)
    }

    /// FD_TO_HANDLE — recover the cached GEM handle for `fd` on this
    /// table.
    ///
    /// Returns the handle if the fd belongs to a binding this table
    /// already created.  In Linux, an unknown fd causes the driver's
    /// `gem_prime_import` callback to allocate a *new* handle; that
    /// path is not yet wired here because it requires a kernel fd
    /// table to recover the `DmaBuf` from the fd.  Callers that need
    /// cross-table import use [`PrimeTable::import_binding`].
    ///
    /// Linux equivalent: `drm_prime_lookup_buf_handle` (the cache
    /// half of `drm_gem_prime_fd_to_handle`).
    pub fn fd_to_handle(&self, fd: i32) -> Result<GemHandle, PrimeError> {
        if fd < PRIME_FD_BASE {
            return Err(PrimeError::BadFd);
        }
        self.bindings.iter().find(|b| b.fd == fd).map(|b| b.handle)
            .ok_or(PrimeError::NotFound)
    }

    /// Recover the [`DmaBuf`] for a binding fd.  Mirrors the second
    /// half of `drm_gem_prime_fd_to_handle` (pulling the dma_buf
    /// from the fd).
    pub fn fd_to_buf(&self, fd: i32) -> Result<&DmaBuf, PrimeError> {
        if fd < PRIME_FD_BASE {
            return Err(PrimeError::BadFd);
        }
        self.bindings.iter().find(|b| b.fd == fd).map(|b| &b.buf)
            .ok_or(PrimeError::NotFound)
    }

    /// Cross-driver import — when fd X comes in from another driver's
    /// PrimeTable, the receiving driver looks up the dma_buf (via the
    /// global fd table, here synthesised) and allocates a new handle
    /// for it.  We replicate the registration step here.
    ///
    /// `local_handle` is the GEM handle the importing driver
    /// allocated for the imported dma_buf.
    ///
    /// Linux equivalent: `drm_prime_add_buf_handle` after the
    /// driver-supplied `gem_prime_import` returned a new GEM object.
    pub fn import_binding(
        &mut self,
        fd: i32,
        local_handle: GemHandle,
        buf: DmaBuf,
    ) -> Result<(), PrimeError> {
        if fd < PRIME_FD_BASE {
            return Err(PrimeError::BadFd);
        }
        if self.bindings.iter().any(|b| b.handle == local_handle) {
            return Err(PrimeError::BadHandle);
        }
        if self.bindings.len() >= PRIME_TABLE_MAX {
            return Err(PrimeError::Full);
        }
        self.bindings.push(PrimeBinding { handle: local_handle, fd, buf });
        Ok(())
    }

    /// Drop a binding when its GEM handle is closed.
    ///
    /// Linux: when `drm_gem_handle_delete` is called on a handle that
    /// was previously exported, `drm_prime_remove_buf_handle_locked`
    /// drops the dma_buf reference.
    pub fn drop_handle(&mut self, handle: GemHandle) -> Result<(), PrimeError> {
        let pos = self.bindings.iter().position(|b| b.handle == handle)
            .ok_or(PrimeError::NotFound)?;
        self.bindings.swap_remove(pos);
        Ok(())
    }

    fn alloc_fd(&mut self) -> i32 {
        let mut candidate = self.next_fd;
        loop {
            if candidate < PRIME_FD_BASE { candidate = PRIME_FD_BASE; }
            if !self.bindings.iter().any(|b| b.fd == candidate) {
                self.next_fd = candidate.wrapping_add(1).max(PRIME_FD_BASE);
                return candidate;
            }
            candidate = candidate.wrapping_add(1).max(PRIME_FD_BASE);
        }
    }
}

// ── Wire-format struct ────────────────────────────────────────────────

/// `struct drm_prime_handle` — both PRIME ioctl args use this.
///
/// Linux: `include/uapi/drm/drm.h`.
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmPrimeHandle {
    pub handle: u32,
    pub flags: u32,
    pub fd: i32,
}
