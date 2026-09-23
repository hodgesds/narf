#[allow(unused_imports)]
use super::*;

/// `ptrace(request, pid, addr, data)` — forwards to the implementation in
/// `crate::ptrace`.
///
/// This is a dispatch shim, not an implementation. It exists because the
/// syscall table is assembled from one `handlers/sys_*.rs` module per
/// syscall, while ptrace's logic is large enough to live in its own
/// top-level module.
///
/// It previously carried a doc comment reading "Currently a stub returning
/// ENOSYS (-38) since the GDB stub (observability) is not fully wired to
/// the userspace process table yet." That has not been true since the body
/// started forwarding, and the wording is actively harmful: a reader
/// grepping for `sys_ptrace` finds TWO functions with this name — this one
/// and `crate::ptrace::sys_ptrace` — sees the syscall table import this
/// one, reads "stub returning ENOSYS", and concludes ptrace is unwired. It
/// is wired, and the real implementation handles TRACEME/ATTACH/SEIZE with
/// pid-namespace translation. `docs/LINUX_COMPAT.md` carried that wrong
/// conclusion as a "real gap" on the strength of this comment.
pub(crate) fn sys_ptrace(ctx: &mut dyn TrapContext) {
    crate::ptrace::sys_ptrace(ctx);
}
