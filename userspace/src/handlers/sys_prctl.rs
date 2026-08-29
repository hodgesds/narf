#[allow(unused_imports)]
use super::*;

/// prctl(2) — `kernel/sys.c::SYSCALL_DEFINE5(prctl, int, option,
/// unsigned long, arg2, unsigned long, arg3, unsigned long, arg4,
/// unsigned long, arg5)`.
///
/// Two things about that signature drive the code below.
///
/// **Width.** `option` is `int`, so Linux dispatches on the low 32 bits
/// of the register; only `arg2..arg5` are full-width. A caller that
/// leaves junk in the upper half of the option register (easy to do from
/// a language runtime that builds the syscall frame by hand, and exactly
/// what a 32-bit compat caller produces) still reaches PR_SET_NAME on
/// Linux. Matching on the raw 64-bit register instead sent it to the
/// unknown-option arm.
///
/// **Errno.** Every user-pointer arm here writes through a pointer the
/// CALLER supplied, and Linux answers a bad one with `put_user` /
/// `copy_to_user` / `strncpy_from_user` failure — i.e. **EFAULT**. The
/// bare `-1` this handler used to return is EPERM, which tells a caller
/// something entirely different: EFAULT means "fix your pointer", EPERM
/// means "you are not allowed to ask". glibc's `pthread_setname_np` and
/// systemd's `rename_process` both branch on that: EFAULT is a caller
/// bug they can assert on, EPERM makes them log a permission failure and
/// keep the old name.
pub(crate) fn sys_prctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `int option` — dispatch on the low 32 bits, as Linux does.
    let op = args.arg0 as u32 as u64;
    let arg_a = args.arg1;
    let arg_b = args.arg2;
    /// A user pointer the caller handed us is unreadable/unwritable:
    /// `put_user`/`copy_to_user` failure, which every pointer-taking
    /// prctl option reports as EFAULT.
    const EFAULT_CODE: i64 = -14;
    let fail = SyscallReturn::ok(EFAULT_CODE as u64);
    let task = current_task_id();

    match op {
        PR_SET_NAME => {
            // arg_a is a pointer to a NUL-terminated or 16-byte
            // bounded user buffer. Copy at most TASK_COMM_LEN bytes
            // under the SMAP bracket, then find the NUL.
            // `kernel/sys.c` PR_SET_NAME:
            //
            //     if (strncpy_from_user(comm, (char __user *)arg2,
            //                           sizeof(me->comm) - 1) < 0)
            //             return -EFAULT;
            //
            // A NULL (or otherwise unreadable) name pointer is EFAULT.
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
            // No Linux analogue: `set_task_comm` cannot fail. This only
            // trips when PRCTL_TABLE was never initialised, i.e. the
            // per-task prctl store does not exist on this boot — ENOSYS
            // (the subsystem is absent), not EFAULT (the caller's pointer
            // was fine) and certainly not EPERM.
            if !modify_prctl(task, |s| s.name = name) {
                ctx.set_return(SyscallReturn::ok((-38i64) as u64)); // ENOSYS
                return;
            }
            // Mirror into PROC_COMM so /proc/[pid]/comm reflects the new name.
            if let Ok(s) = core::str::from_utf8(&name[..nul_pos]) {
                set_proc_comm(task, s);
                crate::perf_event::on_comm(task, s);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_NAME => {
            // `kernel/sys.c` PR_GET_NAME:
            //
            //     if (copy_to_user((char __user *)arg2, comm, sizeof(comm)))
            //             return -EFAULT;
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
            // `kernel/sys.c`: `if (!valid_signal(arg2)) { error = -EINVAL;
            // break; }`, and `valid_signal(sig)` is `sig <= _NSIG` (64).
            if arg_a > 64 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            modify_prctl(task, |s| s.pdeathsig = arg_a as u32);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_PDEATHSIG => {
            // Writes an int through the arg2 pointer (Linux ABI).
            // `kernel/sys.c`: `error = put_user(me->pdeath_signal,
            // (int __user *)arg2);` — a bad pointer is EFAULT.
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
            // `kernel/sys.c`: `error = put_user(
            //     me->signal->is_child_subreaper, (int __user *)arg2);`
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
            // `kernel/sys.c` PR_SET_DUMPABLE:
            //
            //     if (arg2 != SUID_DUMP_DISABLE && arg2 != SUID_DUMP_USER) {
            //             error = -EINVAL;
            //             break;
            //     }
            //
            // SUID_DUMP_DISABLE = 0, SUID_DUMP_USER = 1. SUID_DUMP_ROOT
            // (2) is a kernel-internal state that prctl deliberately will
            // NOT let userspace set, so 2 — and anything above it — is
            // EINVAL. Silently folding every non-zero value to "dumpable"
            // meant a caller asking for the root-only dump mode was told
            // it got it.
            if arg_a > 1 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            modify_prctl(task, |s| s.dumpable = arg_a != 0);
            ctx.set_return(SyscallReturn::ok(0));
        }
        PR_GET_DUMPABLE => {
            let s = read_prctl(task);
            ctx.set_return(SyscallReturn::ok(s.dumpable as u64));
        }
        PR_SET_NO_NEW_PRIVS => {
            // `kernel/sys.c` PR_SET_NO_NEW_PRIVS:
            //
            //     if (arg2 != 1 || arg3 || arg4 || arg5)
            //             return -EINVAL;
            //     task_set_no_new_privs(current);
            //
            // no_new_privs is deliberately ONE-WAY in Linux: there is no
            // clear path, because being able to drop it would defeat the
            // point (a sandboxed child could re-enable setuid execs). This
            // arm accepted `arg2 == 0` and cleared the flag, so anything
            // that read the flag back to decide whether a seccomp filter
            // could be installed unprivileged saw it flip off. Rejecting
            // 0 with EINVAL is both what Linux does and the safe answer.
            if arg_a != 1 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            modify_prctl(task, |s| s.no_new_privs = true);
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
            // Stored-not-enforced. PR_SET_SECUREBITS is handled by the LSM
            // hook, not the prctl switch — `security/commoncap.c::
            // cap_task_prctl` runs first (via `security_task_prctl`) and
            // returns -ENOSYS only for options it does not claim:
            //
            //     case PR_SET_SECUREBITS:
            //             if ((((old->securebits & SECURE_ALL_LOCKS) >> 1)
            //                  & (old->securebits ^ arg2))          /*[1]*/
            //                 || ((old->securebits & SECURE_ALL_LOCKS & ~arg2)) /*[2]*/
            //                 || (arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS))) /*[3]*/
            //                     return -EPERM;
            //
            // Case [3] is the "unsupported bits" arm, and its errno is
            // **EPERM**, not EINVAL. SECURE_ALL_BITS is bits 0/2/4/6 and
            // SECURE_ALL_LOCKS is those shifted left one, so the union is
            // exactly the 0xFF mask below. libcap's `cap_set_secbits()`
            // reports EINVAL as "this kernel is too old to know that bit"
            // and EPERM as "you lack CAP_SETPCAP" — the second is what a
            // caller poking at a bit outside the mask must see, or it
            // concludes the securebit model itself is unavailable.
            if arg_a & !0xFF != 0 {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
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
            // `kernel/seccomp.c::prctl_set_seccomp`, reached from
            // `kernel/sys.c` PR_SET_SECCOMP:
            //
            //     switch (seccomp_mode) {
            //     case SECCOMP_MODE_STRICT: op = SECCOMP_SET_MODE_STRICT; break;
            //     case SECCOMP_MODE_FILTER: op = SECCOMP_SET_MODE_FILTER; break;
            //     default:
            //             return -EINVAL;
            //     }
            //
            // Only STRICT (1) and FILTER (2) exist; DISABLED (0) is a
            // state, not a request, and there is no way back out of
            // seccomp. Folding every non-zero value to FILTER also lied to
            // PR_GET_SECCOMP, which must report the mode actually in
            // force, so store what was asked for.
            //
            // LINUX-GAP: NARF records the mode but does not ENFORCE it —
            // SECCOMP_MODE_STRICT does not kill the task on its first
            // syscall outside {read, write, _exit, sigreturn}, and no
            // filter program is evaluated. See sys_seccomp.rs.
            if arg_a != 1 && arg_a != 2 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            let mode = arg_a as u32;
            modify_prctl(task, |s| s.seccomp_mode = mode);
            ctx.set_return(SyscallReturn::ok(0));
        }
        52 /* PR_GET_SPECULATION_CTRL */ | 53 /* PR_SET_SPECULATION_CTRL */ | 0x53564d41 /* PR_SET_VMA */ => {
            ctx.set_return(SyscallReturn::ok(0));
        }
        29 /* PR_SET_TIMERSLACK */ => {
            // Timer slack tunes nanosleep/poll wakeup coalescing; NARF doesn't
            // coalesce timers, so accept and ignore (arg_a==0 resets to default).
            ctx.set_return(SyscallReturn::ok(0));
        }
        30 /* PR_GET_TIMERSLACK */ => {
            // Return value IS the slack (ns); report the Linux default (50µs).
            ctx.set_return(SyscallReturn::ok(50_000));
        }
        25 /* PR_GET_TSC */ => {
            // rdtsc is always enabled for user mode on NARF; report ON (1)
            // through the arg2 int pointer, matching Linux.
            //
            // `arch/x86/kernel/process.c::get_tsc_mode`:
            //
            //     return put_user(val, (unsigned int __user *)adr);
            //
            // The whole option IS the put_user, so an unwritable (or NULL)
            // pointer is EFAULT — Linux has no "no pointer supplied"
            // shortcut. Returning 0 without writing left the caller
            // reading whatever its uninitialised variable held and calling
            // that the TSC mode.
            let one: i32 = 1;
            // SAFETY: `arg_a` is the user int pointer; copy_to_user
            // range-validates it and SMAP-brackets the 4-byte write.
            if arg_a == 0 || unsafe { copy_to_user(arg_a, &one.to_ne_bytes()) }.is_err() {
                ctx.set_return(fail); // EFAULT
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        26 /* PR_SET_TSC */ => {
            // `arch/x86/kernel/process.c::set_tsc_mode`:
            //
            //     if (val == PR_TSC_SIGSEGV)
            //             disable_TSC();
            //     else if (val == PR_TSC_ENABLE)
            //             enable_TSC();
            //     else
            //             return -EINVAL;
            //
            // PR_TSC_ENABLE = 1, PR_TSC_SIGSEGV = 2; anything else
            // (including 0) is EINVAL.
            //
            // LINUX-GAP: NARF never disables rdtsc, so PR_TSC_SIGSEGV is
            // accepted and ignored — a sandbox asking for rdtsc to fault
            // is told it will and then still gets a working rdtsc. That is
            // a silent divergence, but it matches what PR_GET_TSC above
            // already reports, and rejecting it would break callers that
            // only set it opportunistically.
            if arg_a != 1 && arg_a != 2 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        33 /* PR_MCE_KILL */ | 34 /* PR_MCE_KILL_GET */ => {
            // Machine-check kill policy: NARF has no MCE handling, so accept the
            // set and report the system-default policy (0) on get.
            ctx.set_return(SyscallReturn::ok(0));
        }
        41 /* PR_SET_THP_DISABLE */ | 42 /* PR_GET_THP_DISABLE */ => {
            // NARF has no transparent huge pages; the per-process toggle is a
            // no-op and GET reports 0 (not disabled / not applicable).
            ctx.set_return(SyscallReturn::ok(0));
        }
        65 /* PR_SET_MDWE */ => {
            // `kernel/sys.c::prctl_set_mdwe`:
            //
            //     if (arg3 || arg4 || arg5)                         return -EINVAL;
            //     if (bits & ~(PR_MDWE_REFUSE_EXEC_GAIN |
            //                  PR_MDWE_NO_INHERIT))                 return -EINVAL;
            //     /* NO_INHERIT only makes sense with REFUSE_EXEC_GAIN */
            //     if (bits & PR_MDWE_NO_INHERIT &&
            //         !(bits & PR_MDWE_REFUSE_EXEC_GAIN))           return -EINVAL;
            //     ...
            //     current_bits = get_current_mdwe();
            //     if (current_bits && current_bits != bits)
            //             return -EPERM; /* Cannot unset the flags */
            //
            // The trailing -EPERM is the whole point of the feature: MDWE is
            // one-way. A process that has taken the restriction cannot drop
            // it, so an attacker who gains control of it cannot simply turn
            // W^X back off before mapping the page it wants.
            if arg_b != 0 || args.arg3 != 0 || args.arg4 != 0 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            if arg_a & !(PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT) != 0 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            if arg_a & PR_MDWE_NO_INHERIT != 0 && arg_a & PR_MDWE_REFUSE_EXEC_GAIN == 0 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            let task = current_task_id();
            let current_bits = task_mdwe(task);
            if current_bits != 0 && current_bits != arg_a {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
                return;
            }
            set_task_mdwe(task, arg_a);
            ctx.set_return(SyscallReturn::ok(0));
        }
        66 /* PR_GET_MDWE */ => {
            // `prctl_get_mdwe`: `if (arg2 || arg3 || arg4 || arg5) return
            // -EINVAL; return get_current_mdwe();`
            if arg_a != 0 || arg_b != 0 || args.arg3 != 0 || args.arg4 != 0 {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            ctx.set_return(SyscallReturn::ok(task_mdwe(current_task_id())));
        }
        _ => {
            // `kernel/sys.c::SYSCALL_DEFINE5(prctl)` `default:` arm:
            //     trace_task_prctl_unknown(option, arg2, arg3, arg4, arg5);
            //     error = -EINVAL;
            // Linux returns EINVAL for an unrecognised prctl option, not EPERM.
            // A -1/EPERM sentinel here made systemd treat a feature probe (e.g.
            // PR_SET_MDWE on this pre-6.3-style kernel) as a hard error instead
            // of degrading gracefully.
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        }
    }
}
