//! Syscall table — Stage-4 structural shape.
//!
//! Spec: `userspace/specification/spec.md` + `abi/specification/spec.md`
//! §3. relibc enters the kernel via a platform-specific instruction
//! (`syscall` on x86_64, `svc #0` on aarch64). The trap handler in
//! `frame/` dispatches based on the syscall number in the first
//! argument register, pulling args from the remaining register set.
//! From there it either consults the per-task cap table (for ops
//! backed by a real cap) or dispatches through the `abi/`
//! submission ring (for ops that are really async).
//!
//! What lands here: the canonical syscall-number table. Numbers are
//! pinned so relibc can compile against them without re-negotiating;
//! each number's `Handler` field is `None` until the kernel-side
//! body is written. Stage-4's `frame/` trap entry will look up the
//! slot and either call the handler or return `NarfStatus::InvalidOp`.

use alloc::vec::Vec;

/// Canonical syscall numbers. NARF starts these at 100 so there's
/// no chance of accidentally colliding with Linux conventions
/// during relibc's dual-target development.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Syscall {
    /// Submit a single `abi::Submission` from inline registers.
    /// Equivalent to pushing it to the SQ ring; the implementation
    /// uses the per-task SQ under the hood.
    Submit       = 100,

    /// Bootstrap: mint the per-task SQ+CQ and config-page caps.
    Bootstrap    = 101,

    /// Block until a new completion arrives on the per-task CQ.
    WaitCompl    = 102,

    /// Exit the current task. No completion is emitted; the
    /// scheduler drops the slot.
    ExitTask     = 103,

    /// Yield the CPU. Returns when rescheduled.
    Yield        = 104,

    /// Sleep for `arg0` nanoseconds.
    Sleep        = 105,

    /// Open a file by path (zero-terminated string pointer in
    /// arg0). Returns a file descriptor on the per-task CQ.
    OpenFile     = 110,

    /// Read `arg1` bytes from file `arg0` into buffer at `arg2`.
    Read         = 111,

    /// Write `arg1` bytes to file `arg0` from buffer at `arg2`.
    Write        = 112,

    /// Close file `arg0`.
    Close        = 113,

    /// Map memory: `arg0` addr hint, `arg1` length, `arg2` flags.
    Mmap         = 120,

    /// Unmap memory.
    Munmap       = 121,
}

impl Syscall {
    /// Raw wire number.
    #[inline]
    pub const fn raw(self) -> u32 { self as u32 }

    /// Parse from a raw number.
    pub const fn from_raw(n: u32) -> Option<Self> {
        Some(match n {
            100 => Syscall::Submit,
            101 => Syscall::Bootstrap,
            102 => Syscall::WaitCompl,
            103 => Syscall::ExitTask,
            104 => Syscall::Yield,
            105 => Syscall::Sleep,
            110 => Syscall::OpenFile,
            111 => Syscall::Read,
            112 => Syscall::Write,
            113 => Syscall::Close,
            120 => Syscall::Mmap,
            121 => Syscall::Munmap,
            _   => return None,
        })
    }
}

/// Syscall arguments in register-passing order. Six arguments
/// matches the x86_64 syscall convention (rdi/rsi/rdx/r10/r8/r9)
/// and is wide enough for aarch64 (x0..=x5).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallArgs {
    pub arg0: u64, pub arg1: u64, pub arg2: u64,
    pub arg3: u64, pub arg4: u64, pub arg5: u64,
}

/// Return value for a syscall. Mirrors `abi::NarfStatus` + one
/// `u64` payload register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SyscallReturn {
    pub status: u32, // NarfStatus as u32
    pub value:  u64,
}

/// Table for Stage-4 in-kernel registration. `name` is diagnostic
/// only (tracing / crash dumps).
#[derive(Debug)]
pub struct SyscallTable {
    entries: Vec<SyscallEntry>,
}

#[derive(Debug)]
pub struct SyscallEntry {
    pub number: Syscall,
    pub name:   &'static str,
}

impl SyscallTable {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    /// Register a syscall name under its number. Call once at boot
    /// per implemented syscall.
    pub fn register(&mut self, n: Syscall, name: &'static str) {
        self.entries.push(SyscallEntry { number: n, name });
    }

    /// Look up a syscall's diagnostic name by number.
    pub fn name_of(&self, n: Syscall) -> Option<&'static str> {
        self.entries.iter().find(|e| e.number == n).map(|e| e.name)
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for SyscallTable {
    fn default() -> Self { Self::new() }
}
