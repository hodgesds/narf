//! Userspace shmem SDK — handle-oriented wrapper around the
//! shmem syscalls.
//!
//! `Shmem::create(len)` allocates a kernel-managed region, maps it
//! into the caller's VA, and returns a typed handle that derefs to
//! a byte slice. Drop destroys the region (kernel reaps the
//! frames; the user-VA mapping stays installed for now — cleaner
//! teardown lands when shmem grows a `Drop` path that walks +
//! unmaps the user range).
//!
//! Two-step pattern (`create_unmapped` + `map`) is exposed for
//! callers that want to share a handle with a kernel consumer
//! (audio's `submit(&Shmem, offset, len)`, fb's TAG_BLIT) without
//! ever paying for a userspace mapping.

use crate::{
    syscall1, syscall2, SYS_SHMEM_CREATE, SYS_SHMEM_DESTROY, SYS_SHMEM_MAP,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShmemError {
    /// Kernel rejected `create` — bad length, OOM, or no shmem
    /// vtable installed.
    Create,
    /// Kernel rejected `map` — handle vanished out from under us
    /// or the caller doesn't own it.
    Map,
}

/// Open shmem region; Drop destroys it.
#[derive(Debug)]
pub struct Shmem {
    handle: u64,
    base:   *mut u8,
    len:    usize,
}

unsafe impl Send for Shmem {}
unsafe impl Sync for Shmem {}

impl Shmem {
    /// Allocate `len` bytes (rounded up to a page) and map them
    /// into the calling process's VA. Returns a handle that owns
    /// both the kernel-side region and the user-VA mapping.
    pub fn create(len: usize) -> Result<Self, ShmemError> {
        // SAFETY: pure syscalls.
        let handle = unsafe { syscall1(SYS_SHMEM_CREATE, len as u64) };
        if handle == 0 || handle == !0u64 {
            return Err(ShmemError::Create);
        }
        // SAFETY: handle is live (we just got it).
        let va = unsafe { syscall1(SYS_SHMEM_MAP, handle) };
        if va == 0 || va == !0u64 {
            // SAFETY: handle is live; clean up.
            let _ = unsafe { syscall1(SYS_SHMEM_DESTROY, handle) };
            return Err(ShmemError::Map);
        }
        // The kernel rounds len up to a page; the user-side wrapper
        // exposes the rounded length so `as_mut_slice()` covers
        // the full mapping.
        let pages = (len + 4095) / 4096;
        let mapped_len = pages * 4096;
        Ok(Self { handle, base: va as *mut u8, len: mapped_len })
    }

    /// Raw kernel handle. Only valid while `&self` is alive.
    pub fn handle(&self) -> u64 { self.handle }

    /// Length of the mapping in bytes (page-rounded).
    pub fn len(&self) -> usize { self.len }

    /// Empty mappings can't exist — `Shmem::create(0)` errors.
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Mutable byte slice over the mapping.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `base` was returned by SYS_SHMEM_MAP; the kernel
        // installed a contiguous RW user-VA region of `len` bytes
        // for the calling task's address space, valid until Drop.
        // Single-threaded userspace today; SMP userspace will need
        // an explicit lock or a different shape.
        unsafe { core::slice::from_raw_parts_mut(self.base, self.len) }
    }

    /// Read-only byte slice over the mapping.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: see as_mut_slice.
        unsafe { core::slice::from_raw_parts(self.base, self.len) }
    }
}

impl Drop for Shmem {
    fn drop(&mut self) {
        // SAFETY: handle is live (we own it). Kernel reaps the
        // backing frames; the user-VA mapping isn't torn down yet
        // — leaks a VA range, not memory.
        let _ = unsafe { syscall1(SYS_SHMEM_DESTROY, self.handle) };
    }
}

// Suppress unused-import warning when only one of the syscall
// helpers is called.
#[allow(dead_code)]
fn _suppress() {
    // SAFETY: never called.
    let _ = unsafe { syscall2(SYS_SHMEM_DESTROY, 0, 0) };
}
