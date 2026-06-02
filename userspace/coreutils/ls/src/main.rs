//! NARF coreutil: ls
//!
//! Lists the contents of a directory (default: ".").
//! One entry per line. No sorting — order follows the kernel's
//! enumeration order (typically insertion order for memfs/cpio).
//!
//! Uses narf-libc's `opendir` / `readdir` / `closedir` surface which
//! backs onto `narf_user_runtime::listdir` (NARF-specific syscall).
//!
//! Reference: BusyBox coreutils/ls.c (minimal non-recursive path)
//! Linux reference: fs/readdir.c::getdents64 (kernel side)

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use narf_libc as libc;

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

/// List entries in the directory at `path` (NUL-terminated C string).
/// Prints one entry name per line to stdout.
/// Returns 0 on success, 1 on failure.
unsafe fn list_dir(path: *const i8) -> i32 {
    // SAFETY: path is a NUL-terminated C string.
    let dir = unsafe { libc::opendir(path) };
    if dir.is_null() {
        unsafe { write_stderr(b"ls: opendir failed\n"); }
        return 1;
    }
    loop {
        // SAFETY: dir was returned by opendir.
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            break;
        }
        // dirent.d_name is a C string at a known offset.
        // SAFETY: ent is valid, d_name is a [c_char; 256] field.
        let name_ptr = unsafe {
            core::ptr::addr_of!((*ent).d_name) as *const u8
        };
        let nlen = unsafe { cstr_len(name_ptr) };
        if nlen > 0 {
            // SAFETY: name_ptr points at nlen valid bytes.
            let name = unsafe { core::slice::from_raw_parts(name_ptr, nlen) };
            unsafe { write_stdout(name); }
            unsafe { write_stdout(b"\n"); }
        }
    }
    // SAFETY: dir was returned by opendir.
    unsafe { libc::closedir(dir); }
    0
}

#[no_mangle]
pub extern "C" fn main(argc: i32, argv: *const *const u8, _envp: *const *const u8) -> i32 {
    if argc <= 1 {
        // No arguments — list current directory ".".
        return unsafe { list_dir(b".\0".as_ptr() as *const i8) };
    }

    let mut exit_code = 0i32;
    let mut i = 1i32;
    while i < argc {
        // SAFETY: i < argc, so argv[i] is valid.
        let arg_ptr = unsafe { *argv.offset(i as isize) };
        if !arg_ptr.is_null() {
            let rc = unsafe { list_dir(arg_ptr as *const i8) };
            if rc != 0 {
                exit_code = rc;
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
