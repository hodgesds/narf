#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_clock_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let buf = args.arg1;
    // `clockid_t` is an `int`. A negative id that is not CLOCKFD is a POSIX
    // CPU clock (`clockid_to_kclock`): `posix_cpu_clock_get` resolves its
    // target with `pid_for_clock(clock, true)` and answers -EINVAL — never
    // -ESRCH — when there is none (kernel/time/posix-cpu-timers.c:365-369);
    // the timespec copy-out (-EFAULT) comes last.
    let cpu_clock = id as i32;
    if is_cpu_clock(cpu_clock) {
        let task = current_task_id();
        let Some(target) = cpu_clock_target(task, cpu_clock, true) else {
            ctx.set_return(errno_ret(EINVAL));
            return;
        };
        let ns = cpu_clock_sample_ns(task, target, cpu_clock & 3);
        let mut kbuf = [0u8; 16];
        kbuf[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
        kbuf[8..].copy_from_slice(&((ns % 1_000_000_000) as i64).to_ne_bytes());
        // SAFETY: copy_to_user range-validates and fault-brackets the
        // caller's timespec.
        if buf == 0 || unsafe { copy_to_user(buf, &kbuf) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
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
        // `SYSCALL_DEFINE2(clock_gettime)` looks the clock up first:
        //
        //   const struct k_clock *kc = clockid_to_kclock(which_clock);
        //   if (!kc) return -EINVAL;
        //
        // This arm was `invalid_op()`, whose `value` is 0 and so reads as
        // success on the Linux ABI — while the timespec below is never
        // written. `clock_gettime(CLOCK_TAI, &ts)` therefore returned "fine"
        // and left `ts` holding stack garbage, which the caller then used as
        // a wall-clock reading. An error the caller can see is the whole
        // point: on -EINVAL it falls back to a clock this kernel does have.
        _ => {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    };
    // The NULL/faulting-pointer check comes AFTER the clock lookup, which is
    // Linux's order: `clockid_to_kclock` runs first and `put_timespec64` —
    // the only source of -EFAULT — runs after. `clock_gettime(bad_clock,
    // NULL)` is therefore -EINVAL, not -EFAULT. Linux never checks timespec
    // alignment either (copy_to_user handles unaligned stores).
    if buf == 0 {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // Write the timespec (two i64s: tv_sec, tv_nsec) under the SMAP bracket.
    let mut kbuf = [0u8; 16];
    kbuf[..8].copy_from_slice(&sec.to_ne_bytes());
    kbuf[8..].copy_from_slice(&nsec.to_ne_bytes());
    // SAFETY: `buf` is the user timespec pointer (non-zero and 8-aligned, checked above);
    // copy_to_user range-validates it and SMAP-brackets the 16-byte write.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        // Faulting timespec buffer → EFAULT.
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
