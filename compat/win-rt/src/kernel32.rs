//! `kernel32.dll` — minimum-viable Win32 surface.
//!
//! Each function here matches the Microsoft signature exactly so a
//! patched IAT slot calls into us with the right ABI. We delegate
//! all I/O to `narf-userspace-runtime` for the actual syscall —
//! same path relibc and any other user-mode runtime takes. This
//! crate adds **zero** new kernel syscalls.

use narf_user_runtime as rt;

use crate::{handle, stdhandle};

/// One row of the export table consumed by the kernel-side
/// loader at IAT-patch time. The address is the function's
/// link-time VA — when the rt is mapped into a WinProcess at
/// the fixed `compat-win-rt` base, the actual user-mode VA is
/// `base + (addr - rt_link_base)`.
#[derive(Copy, Clone, Debug)]
pub struct Export {
    pub module: &'static str,
    pub symbol: &'static str,
    /// Link-time VA of the thunk. We store it as `*const ()` so
    /// the table can hold thunks declared with the architectural
    /// PE ABI (`extern "win64"` on x86_64, `extern "C"` on
    /// aarch64) without an ABI-changing fn-pointer cast — the
    /// loader patches the IAT slot with this address verbatim.
    pub addr: *const (),
}

// SAFETY: `addr` is a static function pointer; sharing it across
// threads is sound. The struct is `Copy`, but Rust 2024 still
// expects an explicit `Sync` bound for raw pointers.
unsafe impl Sync for Export {}

/// `GetStdHandle(nStdHandle: i32) -> HANDLE`.
///
/// Microsoft signature: `HANDLE WINAPI GetStdHandle(DWORD)`. The
/// arg is signed in practice (see WinBase.h: `STD_INPUT_HANDLE =
/// (DWORD)-10`); we accept i32 for the natural sign extension and
/// return the right sentinel.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "win64" fn GetStdHandle(handle_id: i32) -> u64 {
    match handle_id {
        stdhandle::STD_INPUT_HANDLE => handle::STDIN,
        stdhandle::STD_OUTPUT_HANDLE => handle::STDOUT,
        stdhandle::STD_ERROR_HANDLE => handle::STDERR,
        _ => stdhandle::INVALID_HANDLE_VALUE,
    }
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub extern "C" fn GetStdHandle(handle_id: i32) -> u64 {
    match handle_id {
        stdhandle::STD_INPUT_HANDLE => handle::STDIN,
        stdhandle::STD_OUTPUT_HANDLE => handle::STDOUT,
        stdhandle::STD_ERROR_HANDLE => handle::STDERR,
        _ => stdhandle::INVALID_HANDLE_VALUE,
    }
}

/// `WriteConsoleA(hConsole, lpBuffer, nBytesToWrite, lpBytesWritten,
/// lpReserved) -> BOOL`.
///
/// Routes to `rt::write` with the FD inferred from the handle. Per
/// spec §10.5 we'd emit an `ascii_substitution` tracing event for
/// non-ASCII bytes if a Probe cap were available; not implemented
/// in this skeleton.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub unsafe extern "win64" fn WriteConsoleA(
    h_console: u64,
    lp_buffer: *const u8,
    n_bytes: u32,
    written_out: *mut u32,
    _reserved: u64,
) -> i32 {
    let fd = match handle_to_fd(h_console) {
        Some(f) => f,
        None => return 0, // FALSE
    };
    if lp_buffer.is_null() {
        return 0;
    }
    // SAFETY: caller (PE in user mode) asserts the buffer is valid
    // for `n_bytes`. The buffer lives in user space; the rt's write
    // syscall validates against the calling task's AS.
    let slice = unsafe { core::slice::from_raw_parts(lp_buffer, n_bytes as usize) };
    let n = rt::write(fd, slice);
    if !written_out.is_null() {
        // SAFETY: caller-supplied pointer; PE is responsible for
        // its validity under the Win32 contract.
        unsafe {
            *written_out = n as u32;
        }
    }
    1 // TRUE
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WriteConsoleA(
    h_console: u64,
    lp_buffer: *const u8,
    n_bytes: u32,
    written_out: *mut u32,
    _reserved: u64,
) -> i32 {
    let fd = match handle_to_fd(h_console) {
        Some(f) => f,
        None => return 0,
    };
    if lp_buffer.is_null() {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(lp_buffer, n_bytes as usize) };
    let n = rt::write(fd, slice);
    if !written_out.is_null() {
        unsafe {
            *written_out = n as u32;
        }
    }
    1
}

/// `ExitProcess(uExitCode: u32) -> !`.
///
/// Direct delegation to the native `exit_task` — no kernel-side
/// `redirect_to_kernel` plumbing needed. NARF's `Syscall::ExitTask`
/// is currently parameterless (the exit code path through the
/// native ABI lands in a separate spec'd op); when an exit-code
/// variant ships, this thunk forwards it. For now the code is
/// dropped on the floor — same shape as POSIX `exit(0)` — and
/// the caller's exit observable is "the task ended."
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "win64" fn ExitProcess(_code: u32) -> ! {
    rt::exit_task()
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub extern "C" fn ExitProcess(_code: u32) -> ! {
    rt::exit_task()
}

/// Translate a Win32 console handle to a NARF FD. Returns `None`
/// for an unknown handle.
fn handle_to_fd(h: u64) -> Option<u32> {
    match h {
        handle::STDIN => Some(0),
        handle::STDOUT => Some(1),
        handle::STDERR => Some(2),
        _ => None,
    }
}

/// Export table consumed by the kernel-side loader. Each row
/// resolves a `(module, symbol)` lookup at IAT-patch time.
///
/// `addr` is the link-time VA; the loader translates to the
/// runtime VA based on where the rt was mapped in the
/// WinProcess AS.
pub const EXPORTS: &[Export] = &[
    Export {
        module: "kernel32.dll",
        symbol: "GetStdHandle",
        addr: GetStdHandle as *const (),
    },
    Export {
        module: "kernel32.dll",
        symbol: "WriteConsoleA",
        addr: WriteConsoleA as *const (),
    },
    Export {
        module: "kernel32.dll",
        symbol: "ExitProcess",
        addr: ExitProcess as *const (),
    },
];
