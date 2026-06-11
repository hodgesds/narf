//! NARF coreutil: cat
//!
//! Concatenates files to stdout. With no arguments, reads stdin (fd 0)
//! and copies it to stdout (fd 1). For each positional argument, opens
//! the file, copies its content to stdout, then closes it.
//!
//! Reference: BusyBox coreutils/cat.c (simple path, no -A/-e/-t flags)

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

/// 4 KiB transfer buffer — matches typical page size and is
/// well within the stack budget of a minimal user binary.
const BUF_SIZE: usize = 4096;

/// Write `bytes` to fd 1 (stdout), looping on short writes.
unsafe fn write_stdout(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        // SAFETY: bytes is a valid slice.
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

/// Walk a NUL-terminated C string and return its byte length.
unsafe fn cstr_len(p: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller guarantees p is NUL-terminated.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

/// Copy all bytes from `in_fd` to stdout. Returns 0 on success,
/// 1 if a read error occurred mid-stream.
unsafe fn cat_fd(in_fd: i32) -> i32 {
    let mut buf = [0u8; BUF_SIZE];
    loop {
        // SAFETY: buf is writable for buf.len() bytes.
        let n = unsafe {
            libc::posix_read(in_fd, buf.as_mut_ptr() as *mut _, buf.len())
        };
        if n == 0 {
            // EOF.
            break;
        }
        if n < 0 {
            return 1;
        }
        unsafe { write_stdout(&buf[..n as usize]); }
    }
    0
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // argv is kernel-provided; entry signature is fixed
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc <= 1 {
        // No arguments: read from stdin (fd 0).
        return unsafe { cat_fd(0) };
    }

    let mut exit_code = 0i32;
    let mut i = 1i32;
    while i < argc {
        // SAFETY: i < argc, so argv[i] is valid.
        let arg_ptr = unsafe { *argv.offset(i as isize) };
        if arg_ptr.is_null() {
            i += 1;
            continue;
        }
        // Check for "-" meaning stdin.
        let len = unsafe { cstr_len(arg_ptr) };
        let is_stdin = len == 1 && unsafe { *arg_ptr } == b'-';

        if is_stdin {
            let rc = unsafe { cat_fd(0) };
            if rc != 0 {
                exit_code = rc;
            }
        } else {
            // Build a NUL-terminated path buffer (the arg_ptr is
            // already NUL-terminated, so pass it directly).
            // SAFETY: arg_ptr is a NUL-terminated C string.
            let fd = unsafe {
                libc::posix_open(arg_ptr as *const i8, libc::O_RDONLY, 0)
            };
            if fd < 0 {
                unsafe {
                    write_stderr(b"cat: cannot open: ");
                    if len > 0 {
                        let s = core::slice::from_raw_parts(arg_ptr, len);
                        write_stderr(s);
                    }
                    write_stderr(b"\n");
                }
                exit_code = 1;
            } else {
                let rc = unsafe { cat_fd(fd) };
                if rc != 0 {
                    exit_code = rc;
                }
                // SAFETY: fd was returned by posix_open.
                unsafe { libc::posix_close(fd); }
            }
        }
        i += 1;
    }
    exit_code
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
