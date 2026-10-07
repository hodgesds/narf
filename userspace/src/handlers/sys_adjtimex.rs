#[allow(unused_imports)]
use super::*;

/// `kernel/time/timekeeping.c::SYSCALL_DEFINE1(adjtimex, struct
/// __kernel_timex __user *, txc_p)`.
///
/// ```text
/// if (copy_from_user(&txc, txc_p, sizeof(struct __kernel_timex)))
///         return -EFAULT;
/// ret = do_adjtimex(&txc);
/// return copy_to_user(txc_p, &txc, sizeof(struct __kernel_timex)) ? -EFAULT : ret;
/// ```
///
/// The struct is copied back even when `do_adjtimex` refused the request —
/// see `adjtimex_core`'s `writeback_on_error`. A read-only query
/// (`modes == 0`) needs no privilege; anything that modifies state needs
/// CAP_SYS_TIME, which `narf_time::ntp::validate` enforces.
pub(crate) fn sys_adjtimex(ctx: &mut dyn TrapContext) {
    let r = adjtimex_core(ctx.args().arg0, true, Ok(()));
    ctx.set_return(SyscallReturn::ok(r as u64));
}
