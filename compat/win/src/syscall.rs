//! `SYS_WIN_THUNK` — kernel-side dispatch for Win32 thunk
//! invocations issued from the per-process trampoline page.
//!
//! ## Wire-level contract
//!
//! ### amd64 (the syscall instruction is `int 0x80` per
//! `frame/src/x86_64/trap.rs`)
//!
//! On entry to `int 0x80`, the user trampoline guarantees:
//!
//! | reg | meaning                      |
//! |-----|------------------------------|
//! | rax | [`SYS_WIN_THUNK`]             |
//! | rdi | thunk id (`u16`)             |
//! | rsi | Win32 arg0 (was `rcx`)       |
//! | rdx | Win32 arg1                   |
//! | r8  | Win32 arg2                   |
//! | r9  | Win32 arg3                   |
//!
//! The kernel reads them as `args.{arg0..arg5}` per the existing
//! `int 0x80` mapping (`rdi/rsi/rdx/r10/r8/r9`). Our handler therefore
//! sees `arg0=thunk_id, arg1=Win32 arg0, arg2=Win32 arg1, arg4=Win32
//! arg2, arg5=Win32 arg3`. (`arg3` is unused — Win32 doesn't use the
//! `r10` slot.)
//!
//! ### aarch64 (`svc #0`)
//!
//! | reg | meaning                      |
//! |-----|------------------------------|
//! | x8  | [`SYS_WIN_THUNK`]             |
//! | x4  | thunk id (`u16`)             |
//! | x0  | Win32 arg0 (preserved)       |
//! | x1  | Win32 arg1                   |
//! | x2  | Win32 arg2                   |
//! | x3  | Win32 arg3                   |
//!
//! NARF's aarch64 syscall convention exposes `x0..x5` as
//! `args.{arg0..arg5}`, so the handler reads `arg4=thunk_id` and
//! the Win32 args sit naturally at `arg0..arg3`.
//!
//! ## Why a dedicated syscall number?
//!
//! Spec §8 option (1) — the trampoline crosses Ring 3 → kernel as a
//! pure ABI translation point. The thunks themselves still go
//! through `Cap<>` for any I/O they perform; the syscall is not a
//! privilege-escalation vector, just a dispatch primitive. Three
//! alternatives were considered and rejected:
//!   1. Overloading an existing syscall with a "win-thunk" tag —
//!      operands have wildly different semantics from any native op.
//!   2. Packing the id into upper bits of the syscall number —
//!      collides with NARF's 8-bit ABI versioning scheme (bits 24..31).
//!   3. WINE-style — thunks themselves in user mode, no special
//!      syscall. Cleaner but requires a user-mode thunk crate that
//!      mirrors the kernel-side ones. M2+ work.

use narf_userspace::syscall::{
    Syscall, SyscallArgs, SyscallHandler, SyscallReturn, SyscallTable,
};

use crate::thunks;

/// Canonical syscall number reserved for the Win32 thunk dispatcher.
/// Mirrors `Syscall::WinThunk` (300 — first free slot above the
/// SchedGetPriorityMax / *at family at 220..234, with room for
/// follow-on Win32-specific numbers in the same neighbourhood).
/// Lifted as a `u32` so the trampoline byte-generator can embed it
/// as `mov eax, imm32` without going through enum coercions at
/// runtime.
pub const SYS_WIN_THUNK: u32 = Syscall::WinThunk as u32;

/// Kernel-side dispatcher. Reads the thunk id, looks it up via
/// `thunks::thunk_by_id`, casts the entry address to the unified
/// `extern "win64" fn(u64, u64, u64, u64) -> u64` (amd64) /
/// `extern "C" fn(u64, u64, u64, u64) -> u64` (aarch64) signature,
/// and calls it with the user-supplied args.
///
/// Returns `SyscallReturn::ok(thunk_return)` on success,
/// `SyscallReturn::invalid_op()` when the id doesn't resolve.
#[derive(Debug)]
pub struct WinThunkHandler;

impl SyscallHandler for WinThunkHandler {
    fn invoke(&self, args: &SyscallArgs) -> SyscallReturn {
        let id = args.arg0 as u16;
        let Some(thunk) = thunks::thunk_by_id(id) else {
            return SyscallReturn::invalid_op();
        };
        let addr = thunk.entry_addr();
        if addr == 0 {
            return SyscallReturn::invalid_op();
        }

        // Pull the Win32 args out of the arg slots the trampoline
        // populated. See module-level diagram for the per-arch
        // mapping.
        #[cfg(target_arch = "x86_64")]
        let (a0, a1, a2, a3) = (args.arg1, args.arg2, args.arg4, args.arg5);
        #[cfg(target_arch = "aarch64")]
        let (a0, a1, a2, a3) = (args.arg0, args.arg1, args.arg2, args.arg3);
        // Host-test path: we never run a real syscall on a non-amd64/
        // non-aarch64 build; reuse the amd64 mapping so the handler
        // remains exercisable from cargo test on x86_64-linux.
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let (a0, a1, a2, a3) = (args.arg1, args.arg2, args.arg4, args.arg5);

        // SAFETY: `addr` is the entry function pointer the registry
        // returned. Every M0 thunk is declared with the unified
        // `extern "win64" fn(u64, u64, u64, u64) -> u64` (amd64) /
        // `extern "C" fn(u64, u64, u64, u64) -> u64` (aarch64)
        // signature, so the cast matches the actual ABI.
        let ret: u64 = unsafe {
            #[cfg(target_arch = "aarch64")]
            {
                let f: extern "C" fn(u64, u64, u64, u64) -> u64 =
                    core::mem::transmute(addr);
                f(a0, a1, a2, a3)
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                let f: extern "win64" fn(u64, u64, u64, u64) -> u64 =
                    core::mem::transmute(addr);
                f(a0, a1, a2, a3)
            }
        };
        SyscallReturn::ok(ret)
    }
}

/// Register the WinThunk dispatcher in `table`. Idempotent — call
/// it once per boot from the kernel's compat-init path. The
/// trampoline pages built by `process::load_pe` reach this slot
/// via `int 0x80` (amd64) / `svc #0` (aarch64).
pub fn install(table: &mut SyscallTable) {
    table.install(Syscall::WinThunk, "win_thunk", WinThunkHandler);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::thunks;

    /// End-to-end host smoke: install the kernel32 registry, build
    /// a SyscallTable with WinThunk wired up, dispatch a synthetic
    /// SyscallArgs that names `kernel32!getstdhandle`, and verify
    /// the thunk's body ran (returns the STD_OUTPUT_HANDLE sentinel
    /// for the matching input).
    ///
    /// Exercises the full pipeline minus the actual `int 0x80` /
    /// `svc` instruction: trampoline → trap → SyscallTable lookup
    /// → WinThunkHandler::invoke → thunk_by_id → extern "win64"
    /// call → return.
    #[test]
    fn dispatch_invokes_getstdhandle() {
        // Install the kernel32 registry.
        static TABLE: &[&dyn thunks::Thunk] = thunks::kernel32::KERNEL32_THUNKS;
        static REF: &&[&dyn thunks::Thunk] = &TABLE;
        thunks::install_registry(REF);

        // GetStdHandle is at index 0 in the registry slice.
        let id = thunks::thunk_id("kernel32.dll", "getstdhandle").expect("id");
        assert_eq!(id, 0);

        // Synthesize SyscallArgs as the trampoline would populate
        // them on amd64 (host = x86_64-unknown-linux-gnu).
        // arg0 = thunk_id, arg1 = Win32 arg0 = STD_OUTPUT_HANDLE.
        let args = SyscallArgs {
            arg0: id as u64,
            arg1: (-11i64) as u64,    // STD_OUTPUT_HANDLE
            arg2: 0, arg3: 0, arg4: 0, arg5: 0,
        };
        let ret = WinThunkHandler.invoke(&args);
        assert_eq!(ret.status, SyscallReturn::OK);
        // GetStdHandle returns the sentinel back when the input
        // matches a recognised stream.
        assert_eq!(ret.value, (-11i64) as u64);
    }

    #[test]
    fn dispatch_unknown_id_is_invalid_op() {
        static TABLE: &[&dyn thunks::Thunk] = thunks::kernel32::KERNEL32_THUNKS;
        static REF: &&[&dyn thunks::Thunk] = &TABLE;
        thunks::install_registry(REF);

        let args = SyscallArgs {
            arg0: 9999, arg1: 0, arg2: 0, arg3: 0, arg4: 0, arg5: 0,
        };
        let ret = WinThunkHandler.invoke(&args);
        assert_eq!(ret.status, SyscallReturn::INVALID_OP);
    }
}
