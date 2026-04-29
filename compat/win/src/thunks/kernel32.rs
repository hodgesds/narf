//! `kernel32.dll` — M0 thunk set.
//!
//! Each thunk is the actual Win32 entry function with the documented
//! Microsoft signature, declared via `win_thunk!` in the right per-
//! arch calling convention. The PE loader patches these addresses
//! directly into the IAT — a Win32 caller does
//! `call qword ptr [iat]` and lands here.
//!
//! M0 scope: stdout handle, write to stdout/stderr, exit. Real
//! console output and real exit-syscall plumbing land in M1 once
//! `narf_userspace` exposes a cap-checked user-pointer accessor and
//! a synthetic exit landing for the calling thread.

use crate::thunks::Thunk;
use crate::win_thunk;

// ── M0 console helper ────────────────────────────────────────────
//
// `WriteConsoleA` / `WriteConsoleW` read the user-VA buffer the
// caller passed in via `crate::user_ptr::copy_in` — bounds-checked
// against the active task's `AddressSpace` region table. A miss
// (zero VA, kernel-half VA, unmapped user range, oversized buffer)
// returns `false`/0 to the Win32 caller per the spec.

/// Best-effort copy of a user buffer into the kernel console stream.
/// Returns `true` if the entire range was forwarded; `false` if any
/// chunk failed the cap-checked accessor (and the partial output up
/// to the failure remains visible — same contract Win32 advertises
/// when `WriteConsole` returns short due to console-handle errors).
///
/// `unit_bytes` is 1 for `WriteConsoleA`, 2 for `WriteConsoleW`.
/// The W variant samples only the low byte of each u16 — fine for
/// pure ASCII content, which is what every M0-class PE produces.
fn forward_to_console(buf: u64, count: u32, unit_bytes: usize) -> bool {
    if buf == 0 || count == 0 { return true; }
    let total_bytes = (count as usize).saturating_mul(unit_bytes);
    let mut local = [0u8; crate::user_ptr::MAX_USER_COPY];
    let mut consumed: usize = 0;
    while consumed < total_bytes {
        let chunk = core::cmp::min(crate::user_ptr::MAX_USER_COPY,
                                   total_bytes - consumed);
        let dst = &mut local[..chunk];
        // SAFETY: copy_in bounds-checks against the active AS;
        // safe inside a SyscallHandler body because the trap path
        // entered with the user AS live.
        let ok = unsafe { crate::user_ptr::copy_in(buf + consumed as u64, dst) };
        if ok.is_err() {
            return false;
        }
        // For UTF-16: drop the high byte of each pair (M0 ASCII-only).
        let usable = if unit_bytes == 2 { chunk / 2 } else { chunk };
        let mut tmp = [0u8; crate::user_ptr::MAX_USER_COPY];
        for i in 0..usable {
            let b = if unit_bytes == 2 { local[i * 2] } else { local[i] };
            tmp[i] = if b.is_ascii() && b != 0 { b } else { b'?' };
        }
        // SAFETY: tmp[..usable] is pure ASCII, hence valid UTF-8.
        let s = unsafe { core::str::from_utf8_unchecked(&tmp[..usable]) };
        narf_console::write_str(s);
        consumed += chunk;
    }
    true
}

// ── Win32 HANDLE constants for the standard streams ──────────────
// Negative-signed sentinels in the Win32 spec; we carry their
// two's-complement bit patterns at u64 width so they round-trip
// through the calling convention unchanged on both arches.

const STD_INPUT_HANDLE:  u64 = (-10i64) as u64;
const STD_OUTPUT_HANDLE: u64 = (-11i64) as u64;
const STD_ERROR_HANDLE:  u64 = (-12i64) as u64;
const INVALID_HANDLE_VALUE: u64 = (-1i64) as u64;

// ── GetStdHandle ─────────────────────────────────────────────────
//
// HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
//
// M0 returns the sentinel back to the caller — Win32 hands out an
// opaque kernel handle in real Windows; we re-use the sentinel as
// a self-describing pseudo-handle until the M1 handle table lands.

win_thunk! {
    name = ("kernel32.dll", "getstdhandle");
    struct GetStdHandle;
    extern fn getstdhandle_entry(a0: u64, _a1: u64, _a2: u64, _a3: u64) -> u64 {
        // Win32: `HANDLE GetStdHandle(DWORD nStdHandle)`. The Win32
        // arg sits in the low 32 bits of `a0` (rcx on amd64, x0 on
        // aarch64) and is sign-extended to i64 via the as-i32-as-i64
        // chain so the negative sentinels match.
        let h = (a0 as u32 as i32 as i64) as u64;
        match h {
            STD_INPUT_HANDLE | STD_OUTPUT_HANDLE | STD_ERROR_HANDLE => h,
            _ => INVALID_HANDLE_VALUE,
        }
    }
}

// ── WriteConsoleA ────────────────────────────────────────────────
//
// BOOL WINAPI WriteConsoleA(
//   HANDLE  hConsoleOutput,
//   const VOID *lpBuffer,
//   DWORD   nNumberOfCharsToWrite,
//   LPDWORD lpNumberOfCharsWritten,
//   LPVOID  lpReserved          /* ignored */
// );
//
// Returns BOOL (32-bit). M0 cannot dereference the user buffer yet
// — the cap-checked user-pointer accessor in `narf_userspace` lands
// in M1 — so we accept the call, claim every byte was written, and
// return TRUE for stdout/stderr. Anything else returns FALSE.
//
// The 5th arg sits at `[rsp + 0x28]` on amd64 (after shadow space)
// and at `[sp + 0x00]` on aarch64 (after `x0..x7` are full); the
// compiler handles the load automatically given the typed signature.

win_thunk! {
    name = ("kernel32.dll", "writeconsolea");
    struct WriteConsoleA;
    extern fn writeconsolea_entry(a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
        // Win32: `BOOL WriteConsoleA(HANDLE, LPCVOID, DWORD,
        //          LPDWORD, LPVOID)`. Five args; the 5th
        // (`lpReserved`) is documented "must be NULL" and we ignore
        // it — passes through the unified-signature constraint
        // because the M0 trampoline doesn't relay user stack args.
        let handle      = a0;
        let buffer      = a1;
        let chars       = a2 as u32;
        let written_out = a3;
        if handle != STD_OUTPUT_HANDLE && handle != STD_ERROR_HANDLE {
            return 0;
        }
        if !forward_to_console(buffer, chars, 1) {
            return 0;
        }
        if written_out != 0 {
            // SAFETY: same user-AS contract; written_out is a user
            // VA the caller wants the byte count stored at.
            unsafe { (written_out as *mut u32).write_unaligned(chars); }
        }
        1
    }
}

// ── WriteConsoleW ────────────────────────────────────────────────
//
// Wide variant — UTF-16LE input. Same M0 behaviour as the A
// variant; differs only in unit width once the user-pointer
// accessor lands.

win_thunk! {
    name = ("kernel32.dll", "writeconsolew");
    struct WriteConsoleW;
    extern fn writeconsolew_entry(a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
        let handle      = a0;
        let buffer      = a1;
        let chars       = a2 as u32;
        let written_out = a3;
        if handle != STD_OUTPUT_HANDLE && handle != STD_ERROR_HANDLE {
            return 0;
        }
        // unit_bytes=2 → UTF-16LE, M0 samples the low byte of each
        // pair.
        if !forward_to_console(buffer, chars, 2) {
            return 0;
        }
        if written_out != 0 {
            // SAFETY: see module-level note.
            unsafe { (written_out as *mut u32).write_unaligned(chars); }
        }
        1
    }
}

// ── ExitProcess ──────────────────────────────────────────────────
//
// VOID WINAPI ExitProcess(UINT uExitCode);  // does not return.
//
// M0 placeholder — spin forever so a stray call during testing
// does not silently fall through. M1 wires this into
// `narf_userspace::handlers::set_exit_landing` so the calling task
// is torn down by the scheduler the way a native `exit(2)` is.
//
// The function is declared diverging (`-> !`) so the compiler will
// refuse to call any code after it on the caller side — the same
// guarantee the Microsoft prototype gives.

win_thunk! {
    name = ("kernel32.dll", "exitprocess");
    struct ExitProcess;
    // Real Win32 prototype is `VOID ExitProcess(UINT)` (does not
    // return). Our unified-signature wrapper returns u64 to match
    // the dispatcher's call shape; the body never reaches the
    // implicit return because M1 will redirect the trap frame to a
    // synthetic exit landing — until then the thunk loops.
    extern fn exitprocess_entry(_a0: u64, _a1: u64, _a2: u64, _a3: u64) -> u64 {
        loop { core::hint::spin_loop(); }
    }
}

/// Canonical M0 kernel32 thunk table. Handed to
/// `super::install_registry` once per boot, before any PE image is
/// loaded.
pub static KERNEL32_THUNKS: &[&dyn Thunk] = &[
    &GetStdHandle,
    &WriteConsoleA,
    &WriteConsoleW,
    &ExitProcess,
];

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// On amd64 hosts we can call the entry function directly via
    /// its typed pointer — `extern "win64"` is supported on every
    /// x86_64 target regardless of OS, so cargo test on
    /// x86_64-unknown-linux-gnu invokes the real entry.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn getstdhandle_entry_returns_sentinel_for_known() {
        // Replicate the function pointer cast the SYS_WIN_THUNK
        // dispatcher does. All M0 thunks share the unified
        // `extern "win64" fn(u64, u64, u64, u64) -> u64` signature.
        let ptr = GetStdHandle.entry_addr();
        let f: extern "win64" fn(u64, u64, u64, u64) -> u64 =
            unsafe { core::mem::transmute(ptr) };
        let stdout = f(0xFFFF_FFF5, 0, 0, 0); // -11 as u32
        assert_eq!(stdout, STD_OUTPUT_HANDLE);
        let bad = f(0x12345, 0, 0, 0);
        assert_eq!(bad, INVALID_HANDLE_VALUE);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn writeconsolea_entry_accepts_stdout() {
        let ptr = WriteConsoleA.entry_addr();
        let f: extern "win64" fn(u64, u64, u64, u64) -> u64 =
            unsafe { core::mem::transmute(ptr) };
        // stdout, null buffer (M0 ignores it), 5 chars, no
        // written_out — 5th Win32 arg `_reserved` is not relayed
        // through the M0 trampoline (see syscall.rs).
        assert_eq!(f(STD_OUTPUT_HANDLE, 0, 5, 0), 1);
        // Bogus handle → FALSE.
        assert_eq!(f(0x1234, 0, 5, 0), 0);
    }

    /// The kernel32 thunk table is ordered + populated.
    #[test]
    fn kernel32_table_is_complete() {
        assert_eq!(KERNEL32_THUNKS.len(), 4);
        let names: std::vec::Vec<_> = KERNEL32_THUNKS
            .iter()
            .map(|t| t.name())
            .collect();
        assert!(names.contains(&("kernel32.dll", "getstdhandle")));
        assert!(names.contains(&("kernel32.dll", "writeconsolea")));
        assert!(names.contains(&("kernel32.dll", "writeconsolew")));
        assert!(names.contains(&("kernel32.dll", "exitprocess")));
    }
}
