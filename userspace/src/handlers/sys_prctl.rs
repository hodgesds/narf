#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_prctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let op = args.arg0;
    let arg_a = args.arg1;
    let arg_b = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();

    match op {
        PR_SET_NAME => {
            // arg_a is a pointer to a NUL-terminated or 16-byte
            // bounded user buffer. Copy at most TASK_COMM_LEN bytes
            // under the SMAP bracket, then find the NUL.
            if arg_a == 0 {
                ctx.set_return(fail);
                return;
            }
            let mut raw = [0u8; TASK_COMM_LEN];
            // copy_from_user validates range; copy up to TASK_COMM_LEN bytes.
            // SAFETY: `arg_a` is the user name pointer (non-zero, checked above);
            // copy_from_user range-validates it and SMAP-brackets the read into `raw`.
            // SAFETY: Valid memory or trusted environment
            let _ = unsafe { copy_from_user(&mut raw, arg_a) };
            // Trim at first NUL.
            let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(TASK_COMM_LEN);
            let mut name = [0u8; TASK_COMM_LEN];
            name[..nul_pos].copy_from_slice(&raw[..nul_pos]);
            if !modify_prctl(task, |s| s.name = name) {
                ctx.set_return(fail);
                return;
            }
            // Mirror into PROC_COMM so /proc/[pid]/comm reflects the new name.
            if let Ok(s) = core::str::from_utf8(&name[..nul_pos]) {
                set_proc_comm(task, s);
                #[cfg(feature = "linux-compat")]
                crate::perf_event::on_comm(task, s);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_NAME => {
            if arg_a == 0 {
                ctx.set_return(fail);
                return;
            }
            let s = read_prctl(task);
            // Copy the 16-byte name buffer to user space under the SMAP bracket.
            // SAFETY: `arg_a` is the user name buffer (non-zero, checked above);
            // copy_to_user range-validates it and SMAP-brackets the write of `s.name`.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_to_user(arg_a, &s.name) }.is_err() {
                ctx.set_return(fail);
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_SET_PDEATHSIG => {
            // arg is the signal number; 0 clears. Same 1..=64 range as
            // every send path (SIGRTMAX=64 included).
            if arg_a > 64 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            modify_prctl(task, |s| s.pdeathsig = arg_a as u32);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_PDEATHSIG => {
            // Writes an int through the arg2 pointer (Linux ABI).
            if arg_a == 0 {
                ctx.set_return(fail);
                return;
            }
            let sig = read_prctl(task).pdeathsig as i32;
            // SAFETY: `arg_a` is the user int pointer (non-zero, checked);
            // copy_to_user range-validates and SMAP-brackets the 4-byte write.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_to_user(arg_a, &sig.to_ne_bytes()) }.is_err() {
                ctx.set_return(fail);
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_SET_KEEPCAPS => {
            if arg_a > 1 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            modify_prctl(task, |s| s.keep_caps = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_KEEPCAPS => {
            ctx.set_return(SyscallReturn::ok(read_prctl(task).keep_caps as u64));
        }
        PR_SET_CHILD_SUBREAPER => {
            modify_prctl(task, |s| s.child_subreaper = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_CHILD_SUBREAPER => {
            if arg_a == 0 {
                ctx.set_return(fail);
                return;
            }
            let v = read_prctl(task).child_subreaper as i32;
            // SAFETY: `arg_a` is the user int pointer (non-zero, checked);
            // copy_to_user range-validates and SMAP-brackets the 4-byte write.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_to_user(arg_a, &v.to_ne_bytes()) }.is_err() {
                ctx.set_return(fail);
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_SET_DUMPABLE => {
            modify_prctl(task, |s| s.dumpable = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_DUMPABLE => {
            let s = read_prctl(task);
            ctx.set_return(SyscallReturn::ok(s.dumpable as u64));
        }
        PR_SET_NO_NEW_PRIVS => {
            modify_prctl(task, |s| s.no_new_privs = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_NO_NEW_PRIVS => {
            let s = read_prctl(task);
            ctx.set_return(SyscallReturn::ok(s.no_new_privs as u64));
        }
        PR_CAP_AMBIENT => {
            // arg_a selects the sub-operation; arg_b is the capability
            // number for RAISE / LOWER / IS_SET (unused by CLEAR_ALL,
            // which Linux requires to be called with cap==0).
            match arg_a {
                PR_CAP_AMBIENT_CLEAR_ALL => {
                    if arg_b != 0 {
                        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                        return;
                    }
                    modify_prctl(task, |s| s.ambient_caps = 0);
                    ctx.set_return(SyscallReturn::ok(0));
                }
                PR_CAP_AMBIENT_RAISE | PR_CAP_AMBIENT_LOWER | PR_CAP_AMBIENT_IS_SET => {
                    if arg_b > CAP_LAST_CAP {
                        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                        return;
                    }
                    let bit = 1u64 << arg_b;
                    match arg_a {
                        PR_CAP_AMBIENT_RAISE => {
                            modify_prctl(task, |s| s.ambient_caps |= bit);
                            ctx.set_return(SyscallReturn::ok(0));
                        }
                        PR_CAP_AMBIENT_LOWER => {
                            modify_prctl(task, |s| s.ambient_caps &= !bit);
                            ctx.set_return(SyscallReturn::ok(0));
                        }
                        // IS_SET: 1 if raised, 0 otherwise.
                        _ => {
                            let set = read_prctl(task).ambient_caps & bit != 0;
                            ctx.set_return(SyscallReturn::ok(set as u64));
                        }
                    }
                }
                _ => ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64)),
            }
        }
        PR_CAPBSET_READ => {
            if arg_a > CAP_LAST_CAP {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            } else {
                // Every valid cap is "in the bounding set" — NARF doesn't
                // model one.
                ctx.set_return(SyscallReturn::ok(1));
            }
        }
        PR_CAPBSET_DROP => {
            if arg_a > CAP_LAST_CAP {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            } else {
                // Accept-and-ignore: nothing to drop from.
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        PR_GET_SECUREBITS => {
            let s = read_prctl(task);
            ctx.set_return(SyscallReturn::ok(s.securebits));
        }
        PR_SET_SECUREBITS => {
            // Stored-not-enforced; Linux validates against known SECBIT
            // bits (mask 0xFF covers SECBIT_* incl. the _LOCKED bits).
            if arg_a & !0xFF != 0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            } else {
                modify_prctl(task, |s| s.securebits = arg_a);
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        21 /* PR_GET_SECCOMP */ => {
            let mode = read_prctl(task).seccomp_mode;
            ctx.set_return(SyscallReturn::ok(mode as u64));
        }
        22 /* PR_SET_SECCOMP */ => {
            let mode = if arg_a != 0 { 2 } else { 0 };
            modify_prctl(task, |s| s.seccomp_mode = mode);
            ctx.set_return(SyscallReturn::ok(0));
        }
        52 /* PR_GET_SPECULATION_CTRL */ | 53 /* PR_SET_SPECULATION_CTRL */ | 0x53564d41 /* PR_SET_VMA */ => {
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}
