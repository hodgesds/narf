//! narf-compat-win-rt — Win32 user-mode runtime.
//!
//! Spec: `compat/win/specification/spec.md` v1.0 §8. This crate
//! is the userspace half of the Win32 compatibility layer. The
//! kernel-side `narf-compat-win` parses PEs, materialises the
//! WinProcess address space, and patches each PE's IAT to
//! point at the matching exported function in this crate
//! (mapped at a fixed VA per spec §8.5).
//!
//! ## Calling convention
//!
//! Every exported thunk is `extern "win64"` (x86_64) /
//! `extern "C"` (aarch64 — AAPCS64 matches Win32 ARM64) so the
//! PE caller's `call qword ptr [iat]` lands directly on a
//! correctly-ABI'd function. No syscall, no trampoline, no
//! ring transition.
//!
//! ## I/O
//!
//! Each thunk delegates to `narf-userspace-runtime` for native
//! syscalls (write, exit_task, …). The runtime is the same
//! crate `relibc` and other userspace consumers use; we are
//! one-of-many on top of it, mirroring `userspace/spec` §8.1
//! (native-first ABI with relibc-shaped compat layers).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod kernel32;

/// Re-export the symbol table so the kernel-side loader can
/// query it at IAT-patch time. Each entry pairs a
/// `"module.dll!Symbol"` string with the function's user-mode
/// VA (resolved at link time when the rt is built).
///
/// The kernel reads this table by mapping the rt's read-only
/// metadata section (a sibling of `.rdata` containing the
/// table) and walking it to populate IAT slots.
pub use kernel32::EXPORTS as KERNEL32_EXPORTS;

/// Standard handles. Returned from `GetStdHandle`.
pub mod stdhandle {
    pub const INVALID_HANDLE_VALUE: u64 = u64::MAX;
    pub const STD_INPUT_HANDLE:    i32 = -10;
    pub const STD_OUTPUT_HANDLE:   i32 = -11;
    pub const STD_ERROR_HANDLE:    i32 = -12;
}

/// Sentinel handle values returned to PE callers — opaque
/// integers that route to the right runtime stream.
pub mod handle {
    pub const STDIN:  u64 = 0x0000_0000_0000_0001;
    pub const STDOUT: u64 = 0x0000_0000_0000_0002;
    pub const STDERR: u64 = 0x0000_0000_0000_0003;
}
