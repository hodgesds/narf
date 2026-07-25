#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_clock_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let buf = args.arg1;
    if buf == 0 || buf & 0x7 != 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let (sec, nsec) = match id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            let w = narf_scheduler::narf_time::now_wall();
            (w.secs, w.nanos as i64)
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            let ns: u64 = narf_scheduler::narf_time::monotonic_ns();
            ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
        }
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            // Stage-4 processes are single-threaded in the common path, so
            // both clocks use the calling task's existing user+kernel
            // accounting. Include the active slice, which has not yet been
            // folded into TASK_CPU_NS.
            let task = current_task_id();
            let ns = cpu_time_ns_of(task)
                .saturating_add(kern_time_ns_of(task))
                .saturating_add(narf_scheduler::stackful::current_slice_elapsed_ns());
            ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
        }
        _ => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Write the timespec (two i64s: tv_sec, tv_nsec) under the SMAP bracket.
    let mut kbuf = [0u8; 16];
    kbuf[..8].copy_from_slice(&sec.to_ne_bytes());
    kbuf[8..].copy_from_slice(&nsec.to_ne_bytes());
    // SAFETY: `buf` is the user timespec pointer (non-zero and 8-aligned, checked above);
    // copy_to_user range-validates it and SMAP-brackets the 16-byte write.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
