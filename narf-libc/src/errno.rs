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

/// Read `errno`. Returns 0 if no TLS is staged (thread pointer
/// equals null) — this is a Stage-4 fallback so a binary without
/// a PT_TLS segment doesn't fault on the first read.
pub fn errno() -> i32 {
    let tp = thread_pointer();
    if tp.is_null() {
        return 0;
    }
    // SAFETY: TLS template's last 8 bytes carry errno; the
    // validate binary's PT_TLS reserves them. The kernel programs
    // FS_BASE such that `[fs:0] == fs_base`, so `tp - 8` lands in
    // the TLS image's tail.
    unsafe { *(tp.offset(ERRNO_TLS_OFFSET) as *const i32) }
}

/// Write `errno`. Silent no-op if no TLS is staged.
pub fn set_errno(v: i32) {
    let tp = thread_pointer();
    if tp.is_null() {
        return;
    }
    // SAFETY: see [`errno`]. Writes are aligned i32 stores into
    // the TLS slot the link script reserves.
    unsafe {
        *(tp.offset(ERRNO_TLS_OFFSET) as *mut i32) = v;
    }
}
