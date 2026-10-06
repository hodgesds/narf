#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_kill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `pid` is a pid_t: only the low 32 bits of the register count.
    let spec = i64::from(args.arg0 as u32 as i32);
    let signum = args.arg1 as u32;
    // `kill_something_info` (kernel/signal.c:1572) finds the target(s) FIRST;
    // the signal number is validated per target inside `group_send_sig_info`
    // → `check_kill_permission` (:805). So a target that does not exist is
    // -ESRCH even for an invalid signal, and -EINVAL is reported only once
    // there is someone to send it to.
    // Linux _NSIG = 64; NARF's bit-N bitmap represents 1..=63 (see
    // SIGNAL_PENDING) — signal 64 (SIGRTMAX) is rejected like an
    // out-of-range signal.
    let valid = signum <= 64;
    let caller = current_task_id();

    // Linux kill(2) target forms:
    //   pid > 0   → that process
    //   pid == 0  → every process in the CALLER's process group
    //   pid == -1 → every process the caller may signal (except init)
    //   pid < -1  → every process in process group -pid
    let result: Result<(), i64> = match spec {
        1.. => {
            // `kill_proc_info` → `find_vpid(pid)` → `pid_task(pid,
            // PIDTYPE_PID)` (:1480, :1457): ANY thread in the caller's pid
            // namespace, a non-leader's tid included. The signal is then
            // process-directed (`group_send_sig_info(..., PIDTYPE_TGID)`), so
            // it lands in the shared pending set of that thread's process.
            match find_task_by_vpid(caller, spec as i32) {
                None => Err(ESRCH),
                Some(_) if !valid => Err(EINVAL),
                // A null signal is only an existence probe.
                Some(_) if signum == 0 => Ok(()),
                Some(task) => {
                    let tgid = task_to_pid_raw(task).unwrap_or(task);
                    if kill_process(tgid, signum) {
                        Ok(())
                    } else {
                        Err(ESRCH)
                    }
                }
            }
        }
        0 => {
            // `task_pgrp(current)`: the process group of the caller's thread
            // group, whichever of its threads calls. The caller is always a
            // member, so an invalid signal has a target and is -EINVAL.
            let pgrp = read_pgid(process_state_key(caller));
            if pgrp == 0 {
                Err(ESRCH)
            } else if !valid {
                Err(EINVAL)
            } else if signum == 0 || kill_pgrp_user(pgrp, signum) {
                Ok(())
            } else {
                Err(ESRCH)
            }
        }
        -1 => {
            // Broadcast: every process the caller may signal, except init and
            // the caller's own thread group (`!same_thread_group(p, current)`,
            // :1590 — a non-leader caller must not signal its own leader).
            // Linux walks for_each_process and uses task_pid_vnr, which is 0
            // for tasks INVISIBLE in the caller's pid namespace, so it signals
            // only processes visible there. Without the ns filter a
            // containerized kill(-1) broadcasts to the entire host.
            let targets: alloc::vec::Vec<(u64, u64)> = pid_task_snapshot()
                .into_iter()
                .filter(|&(process, task)| {
                    if same_thread_group(task, caller) {
                        return false;
                    }
                    #[cfg(feature = "container")]
                    {
                        // Visible in the caller's ns and not init.
                        crate::pid_ns::ns_visible_inner(caller, process)
                            .is_some_and(|inner| inner > 1)
                    }
                    #[cfg(not(feature = "container"))]
                    {
                        process != 1
                    }
                })
                .collect();
            if targets.is_empty() {
                // `ret = count ? retval : -ESRCH;`
                Err(ESRCH)
            } else if !valid {
                Err(EINVAL)
            } else {
                let mut any = false;
                for (p, _t) in targets {
                    any |= signum == 0 || kill_process(p, signum);
                }
                if any { Ok(()) } else { Err(ESRCH) }
            }
        }
        _ => {
            // pid < -1: signal every process in process group -pid. Linux
            // resolves the pgid via find_vpid(-pid) — a lookup in the CALLER's
            // pid namespace — so translate the in-namespace pgid to the
            // TaskId-space group id `deliver_signal_to_pgrp` compares against.
            // Passing the raw inner pgid signalled whatever ROOT-namespace
            // group owned the same number. An unmapped in-namespace pgid
            // resolves to 0 -> ESRCH, as does `pid == INT_MIN` (:1582).
            let pgrp = if spec == i64::from(i32::MIN) {
                0
            } else {
                pgid_from_user((-spec) as u64)
            };
            if pgrp == 0 {
                Err(ESRCH)
            } else if !valid {
                // `__kill_pgrp_info` reaches check_kill_permission only for a
                // member; an empty group stays -ESRCH.
                if pgrp_task_snapshot(pgrp).is_empty() {
                    Err(ESRCH)
                } else {
                    Err(EINVAL)
                }
            } else if signum == 0 || kill_pgrp_user(pgrp, signum) {
                Ok(())
            } else {
                Err(ESRCH)
            }
        }
    };

    ctx.set_return(match result {
        Ok(()) => SyscallReturn::ok(0),
        Err(errno) => errno_ret(errno),
    });
}
