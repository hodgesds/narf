#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getrusage(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let who = args.arg0 as i64;
    let out = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 {
        ctx.set_return(fail);
        return;
    }
    // RUSAGE_SELF (0) → this task's own CPU time; RUSAGE_CHILDREN (-1) →
    // accumulated reaped-children CPU time. (Previously this returned
    // monotonic uptime for every `who`, so every process looked like it
    // had burned the whole machine's wall-clock as user time.)
    const RUSAGE_CHILDREN: i64 = -1;
    let task = current_task_id();
    let ns: u64 = if who == RUSAGE_CHILDREN {
        child_cpu_time_ns_of(task)
    } else {
        // Folded slices + the in-flight one (own-stack folds only at
        // yield-out, so a busy task's own reads would otherwise lag).
        cpu_time_ns_of(task).saturating_add(narf_scheduler::stackful::current_slice_elapsed_ns())
    };
    let utime_sec = (ns / 1_000_000_000) as i64;
    let utime_usec = ((ns % 1_000_000_000) / 1_000) as i64;
    // ru_maxrss: the caller's own VM footprint for RUSAGE_SELF; 0 for
    // RUSAGE_CHILDREN (no accumulated per-child peak — wait4 reports
    // each child's footprint at reap instead).
    let maxrss_kb: i64 = if who == RUSAGE_CHILDREN {
        0
    } else {
        (task_vm_bytes(task) / 1024) as i64
    };
    // Build the rusage struct (RUSAGE_TOTAL_I64S i64s) in kernel
    // memory, then copy to user under the SMAP bracket.
    let mut kbuf = [0u8; RUSAGE_TOTAL_I64S * 8];
    kbuf[..8].copy_from_slice(&utime_sec.to_ne_bytes()); // ru_utime.tv_sec
    kbuf[8..16].copy_from_slice(&utime_usec.to_ne_bytes()); // ru_utime.tv_usec
                                                            // ru_stime: in-syscall time (RUSAGE_SELF; the children aggregate is
                                                            // utime-only — TASK_CHILD_CPU_NS folds one number).
    let stime_ns: u64 = if who == RUSAGE_CHILDREN {
        0
    } else {
        kern_time_ns_of(task)
    };
    let stime_sec = (stime_ns / 1_000_000_000) as i64;
    let stime_usec = ((stime_ns % 1_000_000_000) / 1_000) as i64;
    kbuf[16..24].copy_from_slice(&stime_sec.to_ne_bytes()); // ru_stime.tv_sec
    kbuf[24..32].copy_from_slice(&stime_usec.to_ne_bytes()); // ru_stime.tv_usec
    kbuf[32..40].copy_from_slice(&maxrss_kb.to_ne_bytes()); // ru_maxrss (KB)
                                                            // SAFETY: `out` is the user `struct rusage` pointer (non-zero, checked above);
                                                            // copy_to_user range-validates it and SMAP-brackets the write of `kbuf`.
                                                            // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
