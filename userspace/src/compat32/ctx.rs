//! The context an i386 call is handed to a native handler through when its
//! arguments, or the layout the handler must use, differ from what the
//! gate supplied.
//!
//! `table::forward` serves a call whose zero-extended registers already
//! are the native arguments. Some are not: a signed C argument (`int dfd`,
//! `pid_t`) arrives as a 32-bit register the `__ia32_sys_*` wrappers
//! sign-extend; `mmap2` carries pages, not bytes; a 64-bit offset comes as
//! two registers. [`Ia32ArgsCtx`] presents the native handler with the
//! converted [`SyscallArgs`] and an [`Ia32Abi`], and forwards everything
//! else — return, RIP, user state, signal delivery, `in_ia32_syscall`,
//! `in_compat_mode` (`syscall::forward_trap_context`) — to the gate's
//! context, so parking, restart and delivery behave exactly as for a
//! forwarded call.

use crate::syscall::{Ia32Abi, SyscallArgs, SyscallReturn, TrapContext};

/// A native view of an i386 call; see the module documentation.
pub(crate) struct Ia32ArgsCtx<'a> {
    inner: &'a mut dyn TrapContext,
    args: SyscallArgs,
    abi: Ia32Abi,
    /// Hold the native handler's return for the caller instead of writing
    /// it to the gate's context, so the caller can still convert or refuse
    /// it (`mmap` above `TASK_SIZE_32`, `_llseek`'s result pointer).
    capture: bool,
    ret: Option<SyscallReturn>,
}

impl core::fmt::Debug for Ia32ArgsCtx<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ia32ArgsCtx")
            .field("args", &self.args)
            .field("abi", &self.abi)
            .field("capture", &self.capture)
            .finish_non_exhaustive()
    }
}

impl<'a> Ia32ArgsCtx<'a> {
    /// The handler's return goes straight to `inner`.
    pub(crate) fn forwarding(
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
        abi: Ia32Abi,
    ) -> Self {
        Self {
            inner,
            args,
            abi,
            capture: false,
            ret: None,
        }
    }

    /// The handler's return is kept for [`Self::take_return`]. `None` then
    /// means the handler set none: it parked to re-execute the call, and the
    /// gate must see no result either.
    pub(crate) fn capturing(
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
        abi: Ia32Abi,
    ) -> Self {
        Self {
            inner,
            args,
            abi,
            capture: true,
            ret: None,
        }
    }

    pub(crate) fn take_return(&mut self) -> Option<SyscallReturn> {
        self.ret.take()
    }
}

impl TrapContext for Ia32ArgsCtx<'_> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, ret: SyscallReturn) {
        if self.capture {
            self.ret = Some(ret);
        } else {
            self.inner.set_return(ret);
        }
    }
    fn pending_return(&self) -> Option<SyscallReturn> {
        if self.capture {
            self.ret
        } else {
            self.inner.pending_return()
        }
    }
    fn ia32_abi(&self) -> Ia32Abi {
        self.abi
    }
    crate::syscall::forward_trap_context!(inner, except_ia32_abi);
}
