//! NARF coreutil: echo
//!
//! Prints arguments separated by spaces, followed by a newline.
//! Matches BusyBox echo semantics: no flag parsing, no escape
//! interpretation — simply argv[1..] joined by ' ' + '\n'.
//!
//! Reference: BusyBox coreutils/echo.c (minimal path)

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

/// Write `bytes` to fd 1 (stdout), looping on short writes.
unsafe fn write_stdout(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: bytes is a valid slice; posix_write is a syscall shim.
        let n = unsafe {
            libc::posix_write(
                1,
                bytes.as_ptr().add(written) as *const _,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
}

/// Walk a NUL-terminated C string and return its byte length.
unsafe fn cstr_len(p: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller guarantees p is NUL-terminated.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

#[no_mangle]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // argv[0] is the program name; print argv[1..].
    let mut i = 1i32;
    while i < argc {
        if i > 1 {
            // SAFETY: writing a literal byte slice.
            unsafe { write_stdout(b" "); }
        }
        // SAFETY: i < argc, so argv[i] is a valid pointer to a
        // NUL-terminated C string passed by the kernel exec machinery.
        let arg_ptr = unsafe { *argv.offset(i as isize) };
        if !arg_ptr.is_null() {
            let len = unsafe { cstr_len(arg_ptr) };
            if len > 0 {
                // SAFETY: arg_ptr points at len valid bytes.
                let s = unsafe { core::slice::from_raw_parts(arg_ptr, len) };
                unsafe { write_stdout(s); }
            }
        }
        i += 1;
    }
    unsafe { write_stdout(b"\n"); }
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
