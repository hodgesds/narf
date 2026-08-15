#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_kill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let spec = args.arg0 as i64;
    let signum = args.arg1 as u32;
    let einval = SyscallReturn::ok((-22i64) as u64);
    let esrch = SyscallReturn::ok((-3i64) as u64);
    // Linux _NSIG = 64; NARF's bit-N bitmap represents 1..=63 (see
    // SIGNAL_PENDING) — signal 64 (SIGRTMAX) is rejected like an
    // out-of-range signal.
    if signum > 64 {
        ctx.set_return(einval);
        return;
    }

    // Linux kill(2) target forms:
    //   pid > 0   → that process
    //   pid == 0  → every process in the CALLER's process group
    //   pid == -1 → every process the caller may signal (except init)
    //   pid < -1  → every process in process group -pid
    let delivered = match spec {
        1.. => {
            #[allow(unused_mut)]
            let mut target = spec as u64;
            // Wave-67 — translate the user-supplied pid (interpreted as
            // in-namespace per Linux semantics) to the outer pid the
            // delivery path is keyed on.
            #[cfg(feature = "container")]
            {
                let caller = current_task_id();
                match crate::pid_ns::resolve_inner_pid(caller, target) {
                    Some(outer) => target = outer,
                    None => {
                        ctx.set_return(esrch);
                        return;
                    }
                }
            }
            // Existence check FIRST so `kill(pid, 0)` (the POSIX
            // liveness probe) reports ESRCH for a vanished target and
            // queues NOTHING for a live one.
            let target_tid = pid_to_task_raw(target).unwrap_or(target);
            let exists = signal_target_exists(target_tid);
            if !exists {
                false
            } else if signum == 0 {
                true
            } else if pid_to_task_raw(target).is_some() {
                kill_process(target, signum)
            } else {
                // Raw-tid fallback (boot-init spawned tasks).
                signal_stopcont_interaction(target, signum);
                raise_signal_pending(target, signum);
                wake_signal(target);
                true
            }
        }
        0 => {
            let pgrp = read_pgid(current_task_id());
            if pgrp == 0 {
                false
            } else if signum == 0 {
                true
            } else {
                deliver_signal_to_pgrp(pgrp, signum)
            }
        }
        -1 => {
            // Broadcast: every process with a registered pid except
            // init (pid 1) and the caller itself, per Linux.
            let self_tid = current_task_id();
            let targets: alloc::vec::Vec<(u64, u64)> = {
                let g = PID_TO_TASK.lock();
                g.as_ref()
                    .map(|m| {
                        m.iter()
                            .filter(|&(&p, &t)| p != 1 && t != self_tid)
                            .map(|(&p, &t)| (p, t))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let mut any = false;
            for (p, _t) in targets {
                if signum == 0 {
                    any = true;
                } else {
                    any |= kill_process(p, signum);
                }
            }
            any
        }
        _ => {
            // pid < -1: signal every process in process group -pid. Linux
            // resolves the pgid via find_vpid(-pid) — a lookup in the CALLER's
            // pid namespace — so translate the in-namespace pgid to the
            // TaskId-space group id `deliver_signal_to_pgrp` compares against.
            // Passing the raw inner pgid signalled whatever ROOT-namespace
            // group owned the same number. An unmapped in-namespace pgid
            // resolves to 0 -> ESRCH.
            let pgrp = pgid_from_user((-spec) as u64);
            if pgrp == 0 {
                false
            } else if signum == 0 {
                true
            } else {
                deliver_signal_to_pgrp(pgrp, signum)
            }
        }
    };

    ctx.set_return(if delivered {
        SyscallReturn::ok(0)
    } else {
        esrch
    });
}
