//! The four KABI exports this crate is built on.
//!
//! In a module these are undefined symbols the loader resolves against
//! KSYMTAB (`modules/src/kabi.rs`). Under `cfg(test)` — host unit tests —
//! they are in-process stand-ins: the console appends to a per-thread
//! transcript, the heap is the host allocator and the clock is a per-thread
//! counter the test advances by hand.

#[cfg(not(test))]
unsafe extern "C" {
    /// Write `len` bytes of UTF-8 to the kernel console. `-EINVAL` on null,
    /// empty or non-UTF-8 input.
    pub fn narf_printk(ptr: *const u8, len: usize) -> i32;
    /// Kernel heap allocation; null on failure or an invalid layout.
    pub fn narf_kmalloc(size: usize, align: usize) -> *mut u8;
    /// Release a `narf_kmalloc` block with its exact size and alignment.
    pub fn narf_kfree(ptr: *mut u8, size: usize, align: usize);
    /// Nanoseconds on the kernel's monotonic clock.
    pub fn narf_monotonic_ns() -> u64;
}

#[cfg(test)]
pub use host::*;

#[cfg(test)]
mod host {
    extern crate std;

    use std::alloc::{alloc, dealloc, Layout};
    use std::cell::{Cell, RefCell};
    use std::string::String;
    use std::vec::Vec;

    std::thread_local! {
        static TRANSCRIPT: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        static CLOCK_NS: Cell<u64> = const { Cell::new(0) };
    }

    /// Host stand-in: record the bytes, enforcing the kernel's UTF-8 rule.
    pub unsafe fn narf_printk(ptr: *const u8, len: usize) -> i32 {
        if ptr.is_null() || len == 0 {
            return -22;
        }
        // SAFETY: callers pass a live `&str`'s pointer and length.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
        match core::str::from_utf8(bytes) {
            Ok(s) => {
                TRANSCRIPT.with(|t| t.borrow_mut().push(s.into()));
                0
            }
            Err(_) => -22,
        }
    }

    /// Host stand-in for the kernel heap.
    pub unsafe fn narf_kmalloc(size: usize, align: usize) -> *mut u8 {
        match Layout::from_size_align(size, align) {
            // SAFETY: non-zero-sized, valid layout.
            Ok(layout) if layout.size() != 0 => unsafe { alloc(layout) },
            _ => core::ptr::null_mut(),
        }
    }

    /// Host stand-in for the kernel heap.
    pub unsafe fn narf_kfree(ptr: *mut u8, size: usize, align: usize) {
        if let Ok(layout) = Layout::from_size_align(size, align) {
            if !ptr.is_null() && layout.size() != 0 {
                // SAFETY: matched with `narf_kmalloc` above by the caller.
                unsafe { dealloc(ptr, layout) }
            }
        }
    }

    /// Host stand-in: a per-thread clock the test moves.
    pub unsafe fn narf_monotonic_ns() -> u64 {
        CLOCK_NS.with(Cell::get)
    }

    /// Advance this thread's fake clock.
    pub fn advance_ns(ns: u64) {
        CLOCK_NS.with(|c| c.set(c.get() + ns));
    }

    /// Take and clear this thread's console transcript.
    pub fn take_transcript() -> Vec<String> {
        TRANSCRIPT.with(|t| core::mem::take(&mut *t.borrow_mut()))
    }
}
