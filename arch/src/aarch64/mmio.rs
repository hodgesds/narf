//! MMIO byte accessors for aarch64 (no legacy I/O ports).

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

/// Read a byte from `addr` via a `ldrb` through a volatile pointer.
#[inline(always)]
pub unsafe fn read_u8(addr: *const u8) -> u8 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller has mapped `addr` to a device region and upholds
    // access-size alignment for the target device.
    let v = unsafe { ptr::read_volatile(addr) };
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write a byte to `addr`.
#[inline(always)]
pub unsafe fn write_u8(addr: *mut u8, value: u8) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: see read_u8.
    unsafe { ptr::write_volatile(addr, value) };
    compiler_fence(Ordering::SeqCst);
}

/// Read a 32-bit word (used for PL011 register block).
#[inline(always)]
pub unsafe fn read_u32(addr: *const u32) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller has mapped a 4-byte-aligned device register at `addr`.
    let v = unsafe { ptr::read_volatile(addr) };
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write a 32-bit word.
#[inline(always)]
pub unsafe fn write_u32(addr: *mut u32, value: u32) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller has mapped a 4-byte-aligned device register at `addr`.
    unsafe { ptr::write_volatile(addr, value) };
    compiler_fence(Ordering::SeqCst);
}
