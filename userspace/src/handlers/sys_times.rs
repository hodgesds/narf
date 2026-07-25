#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_times(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0;
    let fail = SyscallReturn::ok((-1i64) as u64);
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
            ctx.set_return(fail);
            return;
        }
    }
    if uptime_ticks < 0 {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(uptime_ticks as u64));
}
