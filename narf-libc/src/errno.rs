//! errno via TLS slot.
//!
//! POSIX `errno` is per-thread state. The relibc-shape we follow
//! places it at a fixed negative offset from the thread pointer
//! (the SysV-AMD64 `fs:[0]` self-pointer). The validate binary's
//! linker script reserves the last 8 bytes of the TLS template
//! for this slot.
//!
//! Why a fixed offset and not a dynamic TLS lookup: dynamic-TLS
//! requires DT_TLSDESC + a runtime resolver, which would pull in
//! relocation processing the Stage-4 loader doesn't do. Fixed
//! offset = compile-time constant = no resolver required.

use narf_user_runtime::thread_pointer;

/// errno's offset within the TLS template, measured backwards
/// from the TCB self-pointer. The validate binary's link script
/// matches this layout.
const ERRNO_TLS_OFFSET: isize = -8;

/// POSIX errno values the libc shim sets. We keep the Linux
/// numbering so a future relibc swap-in observes the same wire
/// numbers without translation. The list grows as more shims
/// land — only the values actually written show up here.
pub const EINVAL: i32 = 22;
pub const ERANGE: i32 = 34;

/// Read `errno`. Both the TLS path and the static fallback are
/// covered — the function delegates to [`__errno_location`] so a
/// caller using either entrypoint observes the same slot.
pub fn errno() -> i32 {
    // SAFETY: __errno_location returns a pointer that is valid for
    // the calling thread's lifetime — pure read.
    unsafe { *__errno_location() }
}

/// Write `errno`. Same delegation as [`errno`].
pub fn set_errno(v: i32) {
    // SAFETY: see [`errno`].
    unsafe { *__errno_location() = v; }
}

// ── relibc-shape errno accessor ────────────────────────────────────
//
// C consumers want `int *__errno_location(void)` rather than a Rust
// `fn() -> i32` / `fn(i32)` pair — `errno` in C is a macro that
// expands to `(*__errno_location())`. We expose a pointer into the
// same TLS slot the Rust accessors use.
//
// When TLS is not staged we fall back to a static i32. This keeps
// the function total even on early boot or in test harnesses where
// no PT_TLS segment ran. Writes to the fallback slot are visible
// across threads only because Stage-4 user mode is single-threaded;
// once a real thread model lands the fallback should grow a per-
// thread shadow.

static mut FALLBACK_ERRNO: i32 = 0;

/// Pointer into the calling thread's `errno` slot. Stable across
/// the lifetime of the thread. C callers dereference this to read
/// or write `errno`.
///
/// # Safety
/// Caller must not retain the returned pointer beyond the lifetime
/// of the calling thread. The Stage-4 user mode is single-threaded,
/// so the lifetime is effectively the program's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __errno_location() -> *mut i32 {
    let tp = thread_pointer();
    if !tp.is_null() {
        // SAFETY: the TLS template's last 8 bytes are the errno slot;
        // the link script reserves them.
        return unsafe { tp.offset(ERRNO_TLS_OFFSET) as *mut i32 };
    }
    // Stage-4 fallback: static slot. Single-threaded user mode means
    // there's no race here today.
    let p = &raw mut FALLBACK_ERRNO;
    p
}
