#[allow(unused_imports)]
use super::*;

/// `times(struct tms*)` — Linux `SYSCALL_DEFINE1(times)`. A faulting `tbuf`
/// is -EFAULT; otherwise the elapsed-uptime tick count is returned via
/// `force_successful_syscall_return`, so the value path never reports an error.
pub(crate) fn sys_times(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0;
    // times() RETURNS elapsed wall-clock in ticks (uptime since an
    // arbitrary epoch) — that part was always right. The `tms` FIELDS,
    // however, must carry this task's real CPU time, not uptime.
    let ns_per_tick: u64 = 1_000_000_000 / CLK_TCK_HZ;
    let uptime_ticks: i64 = (narf_scheduler::narf_time::monotonic_ns() / ns_per_tick) as i64;
    let task = current_task_id();
    let utime_ticks: i64 = (cpu_time_ns_of(task)
        .saturating_add(narf_scheduler::stackful::current_slice_elapsed_ns())
        / ns_per_tick) as i64;
    let stime_ticks: i64 = (kern_time_ns_of(task) / ns_per_tick) as i64;
    let cutime_ticks: i64 = (child_cpu_time_ns_of(task) / ns_per_tick) as i64;
    if out_ptr != 0 {
        // Build the tms struct (four i64s: utime, stime, cutime, cstime)
        // in kernel memory, then copy to user under the SMAP bracket.
        // stime = in-syscall time (kernel_syscall_entry's bracket);
        // cstime stays 0 (the children fold is one aggregate number).
        let mut kbuf = [0u8; 32];
        kbuf[..8].copy_from_slice(&utime_ticks.to_ne_bytes()); // utime
        kbuf[8..16].copy_from_slice(&stime_ticks.to_ne_bytes()); // stime
        kbuf[16..24].copy_from_slice(&cutime_ticks.to_ne_bytes()); // cutime
                                                                   // SAFETY: `out_ptr` is the user `struct tms` pointer (non-zero, checked);
                                                                   // copy_to_user range-validates it and SMAP-brackets the 32-byte write.
                                                                   // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(out_ptr, &kbuf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    }
    // Linux returns the tick count through force_successful_syscall_return, so
    // the value is never reinterpreted as an errno (even were it to wrap into
    // the errno range in the far future). Return it verbatim.
    ctx.set_return(SyscallReturn::ok(uptime_ticks as u64));
}
