//! Syscall table + dispatch.
//!
//! Spec: `userspace/specification/spec.md` + `abi/specification/spec.md`
//! §3. relibc enters the kernel via a platform-specific instruction
//! (`syscall` on x86_64, `svc #0` on aarch64). The arch trap entry
//! (in `frame/`) saves registers, reads the syscall number + args
//! out of the saved frame, and calls `kernel_syscall_entry(num, args)`
//! below. The asm stub has not landed yet on either arch — it's the
//! one remaining deep piece between this surface and running a user
//! binary — but the Rust-side dispatch is complete and tested
//! independently.
//!
//! Lifecycle:
//! 1. Each subsystem calls `SyscallTable::install(n, handler)` for
//!    the syscalls it implements at boot.
//! 2. `install_global(table)` publishes the assembled table as the
//!    kernel-wide dispatcher.
//! 3. The arch trap stub (once it lands) calls
//!    `kernel_syscall_entry(num, args)`.
//! 4. `kernel_syscall_entry` consults the global table, routes to
//!    the registered handler, and returns a `SyscallReturn`.
//!
//! Unregistered numbers surface `NarfStatus::InvalidOp` (value =
//! 1 on the wire — `InvalidOp` discriminant in `abi::NarfStatus`).

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

// ── Numbers ─────────────────────────────────────────────────────────

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

// ── Args + Return ───────────────────────────────────────────────────

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
///
/// `status` values match `abi::NarfStatus` wire tags so downstream
/// tooling shares a vocabulary:
/// - `0` = Ok
/// - `1` = InvalidOp
/// - `2` = Cancelled
/// - `3` = CancelRequested
/// - `4` = CapRevoked
/// ... (see `abi::NarfStatus`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SyscallReturn {
    pub status: u32,
    pub value:  u64,
}

impl SyscallReturn {
    pub const OK:         u32 = 0;
    pub const INVALID_OP: u32 = 1;

    #[inline]
    pub const fn ok(value: u64) -> Self { Self { status: Self::OK, value } }

    #[inline]
    pub const fn invalid_op() -> Self { Self { status: Self::INVALID_OP, value: 0 } }
}

// ── Handler + table ─────────────────────────────────────────────────

/// Dispatch target for a single syscall. Kernel subsystems
/// implement this and register themselves with a `SyscallTable`
/// at boot.
pub trait SyscallHandler: Send + Sync + 'static {
    fn invoke(&self, args: &SyscallArgs) -> SyscallReturn;
}

/// Convenience wrapper so `impl Fn(&SyscallArgs) -> SyscallReturn`
/// works as a handler without a manual struct.
pub struct FnHandler<F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static>(pub F);

impl<F> core::fmt::Debug for FnHandler<F>
where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FnHandler").finish_non_exhaustive()
    }
}

impl<F> SyscallHandler for FnHandler<F>
where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
    fn invoke(&self, args: &SyscallArgs) -> SyscallReturn { (self.0)(args) }
}

/// One table slot: the diagnostic name + the optional handler.
pub struct SyscallEntry {
    pub number:  Syscall,
    pub name:    &'static str,
    pub handler: Option<Box<dyn SyscallHandler>>,
}

impl core::fmt::Debug for SyscallEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyscallEntry")
            .field("number",   &self.number)
            .field("name",     &self.name)
            .field("has_handler", &self.handler.is_some())
            .finish()
    }
}

/// In-kernel syscall table. Constructed at boot, handed to
/// `install_global` once every subsystem has registered.
#[derive(Debug)]
pub struct SyscallTable {
    entries: Vec<SyscallEntry>,
}

impl SyscallTable {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    /// Register a diagnostic name against a syscall number (no
    /// handler body). Useful when a subsystem wants the name to
    /// show up in tracing while implementation is pending.
    pub fn register(&mut self, n: Syscall, name: &'static str) {
        self.entries.push(SyscallEntry { number: n, name, handler: None });
    }

    /// Register a live handler for `n`. Replaces any prior handler
    /// for the same number so Stage-4 subsystems can take over
    /// stubs landed earlier.
    pub fn install<H: SyscallHandler + 'static>(
        &mut self, n: Syscall, name: &'static str, handler: H,
    ) {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.number == n) {
            slot.name    = name;
            slot.handler = Some(Box::new(handler));
        } else {
            self.entries.push(SyscallEntry {
                number: n, name, handler: Some(Box::new(handler)),
            });
        }
    }

    /// Shorthand: install a closure handler.
    pub fn install_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
        self.install(n, name, FnHandler(f));
    }

    /// Look up the diagnostic name for `n`.
    pub fn name_of(&self, n: Syscall) -> Option<&'static str> {
        self.entries.iter().find(|e| e.number == n).map(|e| e.name)
    }

    /// Dispatch `args` against the handler registered for `n`.
    /// Returns `None` if no handler is installed; callers fold that
    /// into `SyscallReturn::invalid_op()`.
    pub fn dispatch(&self, n: Syscall, args: &SyscallArgs) -> Option<SyscallReturn> {
        let slot = self.entries.iter().find(|e| e.number == n)?;
        let h = slot.handler.as_ref()?;
        Some(h.invoke(args))
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for SyscallTable {
    fn default() -> Self { Self::new() }
}

// ── Global install + dispatch ───────────────────────────────────────

static GLOBAL: IrqSafeSpinLock<Option<SyscallTable>> = IrqSafeSpinLock::new(None);

/// Publish `table` as the kernel-wide dispatch table. Replaces any
/// prior installation; dropped tables free their handlers.
pub fn install_global(table: SyscallTable) {
    *GLOBAL.lock() = Some(table);
}

/// Read-only access: is a global table installed?
pub fn global_installed() -> bool {
    GLOBAL.lock().is_some()
}

/// Clear the global table — test hook.
#[doc(hidden)]
pub fn __test_clear_global() { *GLOBAL.lock() = None; }

/// Entry point the arch trap stub calls after saving the user
/// register file.  `num` is the raw wire number (not pre-validated
/// against the `Syscall` enum); unknown numbers or missing handlers
/// surface `SyscallReturn::invalid_op()`.
///
/// A `None` global (no `install_global` yet) also returns
/// `invalid_op` — the arch stub shouldn't be running before boot
/// finishes, but a safe fallback beats an unwrap.
#[inline]
pub fn kernel_syscall_entry(num: u32, args: &SyscallArgs) -> SyscallReturn {
    let n = match Syscall::from_raw(num) {
        Some(v) => v,
        None    => return SyscallReturn::invalid_op(),
    };
    let g = GLOBAL.lock();
    let table = match g.as_ref() {
        Some(t) => t,
        None    => return SyscallReturn::invalid_op(),
    };
    table.dispatch(n, args).unwrap_or_else(SyscallReturn::invalid_op)
}
