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

// ── TrapContext trait ───────────────────────────────────────────────
//
// Arch-neutral view onto the arch-specific TrapFrame for syscalls.
// The arch trap handler constructs an impl of this trait around its
// TrapFrame + extracted args, then calls `kernel_syscall_entry(num,
// &mut ctx)`. Raw handlers receive `&mut dyn TrapContext` and can
// both read args and write the return — plus `redirect_to_kernel`
// for handlers that want to unwind into kernel state instead of
// iretq-ing back to user (e.g. cleanup-and-exit paths).

/// Per-call context handed to raw syscall handlers. Normal
/// `SyscallHandler`s only see `args()`; raw handlers see the full
/// interface.
pub trait TrapContext {
    /// Arguments the user supplied in registers.
    fn args(&self) -> &SyscallArgs;

    /// Set the return value + status that the caller will observe
    /// in the arch's return registers.
    fn set_return(&mut self, ret: SyscallReturn);

    /// Redirect the upcoming return so it lands at `rip` on `rsp`
    /// in kernel mode with kernel selectors, instead of iretq-ing
    /// back to user. Returns `true` when the arch supports this
    /// (x86_64 today); returns `false` on arches where the trap
    /// path can't yet rewrite the EL/CPL target. Callers should
    /// check the return and fall back to `set_return` if `false`.
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool;
}

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

    /// Kick the kernel-side dispatcher to drain the calling task's
    /// shared SubmissionRing and post Completions to the shared
    /// CompletionRing. Returns the number of submissions processed.
    /// Used by the slow-path "submit + kick + poll" pattern when
    /// the kernel doesn't yet have a UIPI / UMWAIT-driven async
    /// dispatcher running.
    RingKick     = 130,
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
            130 => Syscall::RingKick,
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

/// Raw variant of `SyscallHandler`. Receives the full
/// `TrapContext`, can read args + set return, and additionally can
/// call `redirect_to_kernel` to unwind into kernel state instead
/// of returning to the caller's user context.
///
/// Use for syscalls that need direct control over the return path
/// (exit, fork, exec, longjmp-style unwinds); use plain
/// `SyscallHandler` for everything else.
pub trait RawSyscallHandler: Send + Sync + 'static {
    fn invoke(&self, ctx: &mut dyn TrapContext);
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

/// One table slot: the diagnostic name + zero/one handler of each
/// kind. Raw handler wins when both are installed.
pub struct SyscallEntry {
    pub number:      Syscall,
    pub name:        &'static str,
    pub handler:     Option<Box<dyn SyscallHandler>>,
    pub raw_handler: Option<Box<dyn RawSyscallHandler>>,
}

impl core::fmt::Debug for SyscallEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyscallEntry")
            .field("number",      &self.number)
            .field("name",        &self.name)
            .field("has_handler", &self.handler.is_some())
            .field("has_raw",     &self.raw_handler.is_some())
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
        self.entries.push(SyscallEntry {
            number: n, name, handler: None, raw_handler: None,
        });
    }

    /// Register a live plain handler for `n`. Replaces any prior
    /// plain handler for the same number so Stage-4 subsystems can
    /// take over stubs landed earlier. A raw handler registered
    /// separately still wins on dispatch.
    pub fn install<H: SyscallHandler + 'static>(
        &mut self, n: Syscall, name: &'static str, handler: H,
    ) {
        self.install_slot(n, name, Some(Box::new(handler) as Box<dyn SyscallHandler>), None);
    }

    /// Register a raw handler for `n`. A raw handler receives the
    /// full `TrapContext` (args + return setter + redirect-to-
    /// kernel) and is chosen over a plain handler when both are
    /// installed.
    pub fn install_raw<H: RawSyscallHandler + 'static>(
        &mut self, n: Syscall, name: &'static str, handler: H,
    ) {
        self.install_slot(n, name, None, Some(Box::new(handler) as Box<dyn RawSyscallHandler>));
    }

    fn install_slot(
        &mut self,
        n: Syscall,
        name: &'static str,
        plain: Option<Box<dyn SyscallHandler>>,
        raw:   Option<Box<dyn RawSyscallHandler>>,
    ) {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.number == n) {
            slot.name = name;
            if plain.is_some() { slot.handler     = plain; }
            if raw.is_some()   { slot.raw_handler = raw; }
        } else {
            self.entries.push(SyscallEntry {
                number: n, name, handler: plain, raw_handler: raw,
            });
        }
    }

    /// Shorthand: install a closure as a plain handler.
    pub fn install_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
        self.install(n, name, FnHandler(f));
    }

    /// Shorthand: install a closure as a raw handler.
    pub fn install_raw_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
        self.install_raw(n, name, RawFnHandler(f));
    }

    /// Look up the diagnostic name for `n`.
    pub fn name_of(&self, n: Syscall) -> Option<&'static str> {
        self.entries.iter().find(|e| e.number == n).map(|e| e.name)
    }

    /// Legacy dispatch: fires only plain handlers, returns
    /// `None` if no plain handler is installed. Kept for the
    /// existing tests; the arch trap path uses `dispatch_ctx` so
    /// it can honour raw handlers.
    pub fn dispatch(&self, n: Syscall, args: &SyscallArgs) -> Option<SyscallReturn> {
        let slot = self.entries.iter().find(|e| e.number == n)?;
        let h = slot.handler.as_ref()?;
        Some(h.invoke(args))
    }

    /// Raw-aware dispatch. If a raw handler is installed, call it
    /// with `ctx` (it's responsible for `set_return` /
    /// `redirect_to_kernel`). Otherwise fall back to the plain
    /// handler. Absence of both means `SyscallReturn::invalid_op`.
    pub fn dispatch_ctx(&self, n: Syscall, ctx: &mut dyn TrapContext) {
        if let Some(slot) = self.entries.iter().find(|e| e.number == n) {
            if let Some(h) = slot.raw_handler.as_ref() {
                h.invoke(ctx);
                return;
            }
            if let Some(h) = slot.handler.as_ref() {
                let ret = h.invoke(ctx.args());
                ctx.set_return(ret);
                return;
            }
        }
        ctx.set_return(SyscallReturn::invalid_op());
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

/// Closure-backed raw handler shim.
pub struct RawFnHandler<F: Fn(&mut dyn TrapContext) + Send + Sync + 'static>(pub F);

impl<F> core::fmt::Debug for RawFnHandler<F>
where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawFnHandler").finish_non_exhaustive()
    }
}

impl<F> RawSyscallHandler for RawFnHandler<F>
where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
    fn invoke(&self, ctx: &mut dyn TrapContext) { (self.0)(ctx); }
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
///
/// Arch trap code has two choices:
/// - **Plain path**: call `kernel_syscall_entry_plain(num, &args)`
///   which only fires plain handlers and returns a `SyscallReturn`
///   the caller writes into registers manually.
/// - **Raw-aware path**: call `kernel_syscall_entry(num, &mut ctx)`
///   so raw handlers can call `redirect_to_kernel` directly.
/// The arch trap path in this tree uses the raw-aware form.
#[inline]
pub fn kernel_syscall_entry(num: u32, ctx: &mut dyn TrapContext) {
    let n = match Syscall::from_raw(num) {
        Some(v) => v,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    let g = GLOBAL.lock();
    let table = match g.as_ref() {
        Some(t) => t,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    table.dispatch_ctx(n, ctx);
}

/// Legacy plain entry retained for the existing
/// `smoke_userspace_syscall_dispatch_via_global` test and any
/// caller that has `SyscallArgs` in hand but not a `TrapContext`.
#[inline]
pub fn kernel_syscall_entry_plain(num: u32, args: &SyscallArgs) -> SyscallReturn {
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
