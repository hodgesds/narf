//! NARF coreutil: pwd
//!
//! Prints the current working directory followed by a newline.
//! Uses `getcwd(2)` which routes through narf-libc to the kernel's
//! per-task cwd state.
//!
//! Reference: BusyBox coreutils/pwd.c (logical path, no -P/-L flags)

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

/// Write `bytes` to fd 2 (stderr), looping on short writes.
unsafe fn write_stderr(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: bytes is a valid slice.
        let n = unsafe {
            libc::posix_write(
                2,
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

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // argv is kernel-provided; entry signature is fixed
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // 4 KiB is more than the POSIX PATH_MAX of 4096 and well above
    // any path depth the shell can produce.
    let mut buf = [0u8; 4096];
    // SAFETY: buf is writable for buf.len() bytes.
    let p = unsafe { libc::getcwd(buf.as_mut_ptr(), buf.len()) };
    if p.is_null() {
        unsafe { write_stderr(b"pwd: getcwd failed\n"); }
        return 1;
    }
    // Find the NUL terminator.
    let mut n = 0usize;
    while n < buf.len() && buf[n] != 0 {
        n += 1;
    }
    unsafe { write_stdout(&buf[..n]); }
    unsafe { write_stdout(b"\n"); }
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
