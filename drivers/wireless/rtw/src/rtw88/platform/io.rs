//! `narf_io` for the module: frame buffers.
//!
//! On USB no host memory is ever a DMA target (the USB KABI copies every
//! transfer), so the driver's "coherent" frame buffers are plain heap
//! memory with the built-in `DmaBuffer`'s CPU accessors.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr::NonNull;

use super::narf_lib::id::DomainId;

/// Allocation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoMemory;

/// A zeroed host buffer. Like the built-in buffer, its accessors hand out
/// mutable pointers from `&self`, so it owns its block through a raw
/// pointer rather than a borrow-tracked `Vec`.
#[derive(Debug)]
pub struct DmaBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: the buffer is plain memory owned by this value; sharing it across
// CPUs is what the driver's ring protocol already arbitrates, as built in.
unsafe impl Send for DmaBuffer {}
// SAFETY: as above.
unsafe impl Sync for DmaBuffer {}

/// `narf_io::alloc_coherent`: `len` zeroed bytes (at least one).
pub fn alloc_coherent(len: usize, _domain: DomainId) -> Result<DmaBuffer, NoMemory> {
    let len = len.max(1);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(|_| NoMemory)?;
    bytes.resize(len, 0u8);
    let raw = Box::into_raw(bytes.into_boxed_slice());
    // SAFETY: `Box::into_raw` never returns null.
    let ptr = unsafe { NonNull::new_unchecked(raw.cast::<u8>()) };
    Ok(DmaBuffer { ptr, len })
}

/// A device-visible address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaAddr(u64);

impl DmaAddr {
    pub fn raw(self) -> u64 {
        self.0
    }
}

impl DmaBuffer {
    /// Host memory has no device address in the module: always 0, which
    /// every descriptor builder refuses (only the PCI packet port, not
    /// compiled here, would program one).
    pub fn dma_addr(&self) -> DmaAddr {
        DmaAddr(0)
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Cache maintenance for a device range: nothing to do for host memory.
    pub fn sync(&self, _offset: usize, _len: usize) {}
    pub fn cpu_ptr_at<T>(&self, offset: u64) -> *const T {
        self.ptr
            .as_ptr()
            .wrapping_add(offset as usize)
            .cast_const()
            .cast()
    }
    pub fn cpu_mut_ptr_at<T>(&self, offset: u64) -> *mut T {
        self.ptr.as_ptr().wrapping_add(offset as usize).cast()
    }
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` names `len` initialised bytes owned by this buffer.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above; `&mut self` makes the borrow unique.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        let slice = core::ptr::slice_from_raw_parts_mut(self.ptr.as_ptr(), self.len);
        // SAFETY: `ptr`/`len` came from `Box::into_raw` of a `[u8]` of this
        // length and are freed exactly once, here.
        drop(unsafe { Box::from_raw(slice) });
    }
}
