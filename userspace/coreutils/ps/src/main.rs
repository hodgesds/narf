//! NARF coreutil: ps
//!
//! Lists running tasks by enumerating /proc, reading /proc/<pid>/comm
//! for the command name, and /proc/<pid>/status for the state field.
//!
//! Output format (matches BusyBox `ps` minimal output):
//!
//!   PID  CMD
//!     1  init
//!     2  shell
//!
//! Reference: BusyBox procps/ps.c (minimal non-option path)
//! Linux reference: fs/proc/array.c::do_task_stat (comm + state)

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

/// Walk a NUL-terminated C string and return its byte length.
unsafe fn cstr_len(p: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller guarantees p is NUL-terminated.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

/// Convert a u32 to decimal ASCII, writing into `buf` (at most 10
/// digits + NUL). Returns the subslice of `buf` that was written.
fn u32_to_decimal<'a>(mut v: u32, buf: &'a mut [u8; 12]) -> &'a [u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut pos = 12usize;
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    &buf[pos..]
}

/// Return true if `bytes` consists entirely of ASCII decimal digits.
fn all_digits(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| b >= b'0' && b <= b'9')
}

/// Build a NUL-terminated path like `/proc/<pid>/comm` into `buf`.
/// Returns the length (excluding NUL) on success, or 0 if the buffer
/// is too small.
fn build_proc_path(pid_name: &[u8], suffix: &[u8], buf: &mut [u8; 64]) -> usize {
    let prefix = b"/proc/";
    let total = prefix.len() + pid_name.len() + suffix.len() + 1; // +1 for NUL
    if total > buf.len() {
        return 0;
    }
    let mut pos = 0usize;
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    buf[pos..pos + pid_name.len()].copy_from_slice(pid_name);
    pos += pid_name.len();
    buf[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();
    buf[pos] = 0;
    pos
}

/// Read `/proc/<pid>/comm` into `out`. Returns the byte length
/// (trailing newline stripped), or 0 on failure.
unsafe fn read_comm(pid_name: &[u8], out: &mut [u8; 64]) -> usize {
    let mut path_buf = [0u8; 64];
    let path_len = build_proc_path(pid_name, b"/comm", &mut path_buf);
    if path_len == 0 {
        return 0;
    }
    // SAFETY: Valid memory or trusted environment
    let fd = unsafe {
        libc::posix_open(path_buf.as_ptr() as *const i8, libc::O_RDONLY, 0)
    };
    if fd < 0 {
        return 0;
    }
    // SAFETY: out is writable for out.len() bytes.
    let n = unsafe {
        libc::posix_read(fd, out.as_mut_ptr() as *mut _, out.len())
    };
    // SAFETY: Valid memory or trusted environment
    unsafe { libc::posix_close(fd); }
    if n <= 0 {
        return 0;
    }
    let mut len = n as usize;
    // Strip trailing newline if present.
    while len > 0 && (out[len - 1] == b'\n' || out[len - 1] == b'\r') {
        len -= 1;
    }
    len
}

/// Print a right-justified PID in a 5-column field, then two spaces,
/// then the comm name, then a newline.
unsafe fn print_proc(pid_name: &[u8], comm: &[u8]) {
    // Right-justify PID in 5 chars.
    let pad = if pid_name.len() < 5 { 5 - pid_name.len() } else { 0 };
    for _ in 0..pad {
        // SAFETY: Valid memory or trusted environment
        unsafe { write_stdout(b" "); }
    }
    // SAFETY: Valid memory or trusted environment
    unsafe { write_stdout(pid_name); }
    // SAFETY: Valid memory or trusted environment
    unsafe { write_stdout(b"  "); }
    // SAFETY: Valid memory or trusted environment
    unsafe { write_stdout(comm); }
    // SAFETY: Valid memory or trusted environment
    unsafe { write_stdout(b"\n"); }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // argv is kernel-provided; entry signature is fixed
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    // Print header.
    // SAFETY: Valid memory or trusted environment
    unsafe { write_stdout(b"  PID  CMD\n"); }

    // Open /proc and enumerate numeric entries (live PIDs).
    // SAFETY: Valid memory or trusted environment
    let dir = unsafe { libc::opendir(b"/proc\0".as_ptr() as *const i8) };
    if dir.is_null() {
        // SAFETY: Valid memory or trusted environment
        unsafe { write_stdout(b"ps: cannot open /proc\n"); }
        return 1;
    }

    loop {
        // SAFETY: dir was returned by opendir.
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            break;
        }
        // SAFETY: ent is valid; d_name is a [c_char; 256] field.
        let name_ptr = unsafe {
            core::ptr::addr_of!((*ent).d_name) as *const u8
        };
        // SAFETY: Valid memory or trusted environment
        let nlen = unsafe { cstr_len(name_ptr) };
        if nlen == 0 {
            continue;
        }
        // SAFETY: name_ptr points at nlen valid bytes.
        let name = unsafe { core::slice::from_raw_parts(name_ptr, nlen) };
        // Only process numeric entries (PIDs).
        if !all_digits(name) {
            continue;
        }
        // Read /proc/<pid>/comm.
        let mut comm_buf = [0u8; 64];
        // SAFETY: Valid memory or trusted environment
        let comm_len = unsafe { read_comm(name, &mut comm_buf) };
        let comm = if comm_len > 0 { &comm_buf[..comm_len] } else { b"?" };
        // SAFETY: Valid memory or trusted environment
        unsafe { print_proc(name, comm); }
    }

    // SAFETY: Valid memory or trusted environment
    unsafe { libc::closedir(dir); }
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
