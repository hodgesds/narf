#[allow(unused_imports)]
use super::*;

/// `times(struct tms*)` — Linux `SYSCALL_DEFINE1(times)`. A faulting `tbuf`
/// is -EFAULT; otherwise the elapsed-uptime tick count is returned via
/// `force_successful_syscall_return`, so the value path never reports an error.
pub(crate) fn sys_times(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0;
    // times() RETURNS elapsed wall-clock in ticks (uptime since an
    // arbitrary epoch). The `tms` fields are `do_sys_times`: the thread
    // group's utime/stime and its reaped children's cutime/cstime, in
    // USER_HZ ticks (`nsec_to_clock_t`).
    use narf_scheduler::cputime::ns_to_clock_t;
    let uptime_ticks = ns_to_clock_t(narf_scheduler::narf_time::monotonic_ns()) as i64;
    if out_ptr != 0 {
        let task = current_task_id();
        let own = process_cpu_times(task);
        let children = children_cpu_times(task);
        let fields = [
            own.utime_ns,
            own.stime_ns,
            children.utime_ns,
            children.stime_ns,
        ];
        // Build the tms struct (four i64s: utime, stime, cutime, cstime)
        // in kernel memory, then copy to user under the SMAP bracket.
        let mut kbuf = [0u8; 32];
        for (slot, ns) in kbuf.chunks_exact_mut(8).zip(fields) {
            slot.copy_from_slice(&(ns_to_clock_t(ns) as i64).to_ne_bytes());
        }
        // SAFETY: `out_ptr` is the user `struct tms` pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 32-byte write.
        if unsafe { copy_to_user(out_ptr, &kbuf) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    // Linux returns the tick count through force_successful_syscall_return, so
    // the value is never reinterpreted as an errno (even were it to wrap into
    // the errno range in the far future). Return it verbatim.
    ctx.set_return(SyscallReturn::ok(uptime_ticks as u64));
}
