#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_get_priority_max, int, policy)`
/// — the largest `sched_priority` accepted for `policy`.
///
/// Two ABI details the previous version got wrong:
///
///   * `policy` is declared `int`, so only the low 32 bits are the argument.
///     Matching against the full 64-bit register made a caller that left
///     garbage in the upper half (a legal thing for a libc stub to do —
///     the psABI only promises the low 32 bits of an `int` argument) fall
///     through to the error arm for a perfectly valid policy.
///   * an unrecognised policy is `-EINVAL`, not a bare `-1`. `-1` reaches
///     the caller as errno 1 (EPERM), and glibc's pthread attribute code
///     probes this range before validating a priority — an EPERM there
///     reads as "not permitted to ask", not "no such policy".
pub(crate) fn sys_sched_get_priority_max(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    let policy = ctx.args().arg0 as i32;
    match priority_max_for_policy(policy) {
        Some(p) => ctx.set_return(SyscallReturn::ok(p as u64)),
        None => ctx.set_return(SyscallReturn::ok((-EINVAL) as u64)),
    }
}
