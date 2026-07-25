#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sigprocmask(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let how = args.arg0 as u32;
    let set_ptr = args.arg1;
    let old_ptr = args.arg2;
    let sigsetsize = args.arg3 as usize;

    let fail = SyscallReturn::ok((-1i64) as u64);
    if sigsetsize != 8 {
        ctx.set_return(fail);
        return;
    }

    let task = current_task_id();

    if old_ptr != 0 {
        let mask = SIGNAL_MASK
            .lock()
            .as_ref()
            .and_then(|m| m.get(&task).copied())
            .unwrap_or(0);
        // NARF's internal mask layout is bit N-1 = signal N — identical to a
        // userspace `sigset_t` — so the mask copies out verbatim.
        let user_mask = mask;
        // SAFETY: `old_ptr` is the user old-sigmask pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 8-byte write.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(old_ptr, &user_mask.to_ne_bytes()) }.is_err() {
            ctx.set_return(fail);
            return;
        }
    }

    if set_ptr != 0 {
        let mut buf = [0u8; 8];
        // SAFETY: `set_ptr` is the user new-sigmask pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 8-byte read.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_from_user(&mut buf, set_ptr) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        // Userspace `sigset_t` bit N-1 == signal N == NARF's internal layout
        // (see SIGNAL_PENDING), so the new mask installs verbatim.
        let set = u64::from_ne_bytes(buf);
        let mut g = SIGNAL_MASK.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let slot = map.entry(task).or_insert(0);
        match how {
            SIG_BLOCK => *slot |= set,
            SIG_UNBLOCK => *slot &= !set,
            SIG_SETMASK => *slot = set,
            _ => {
                ctx.set_return(fail);
                return;
            }
        }
        // Linux strips SIGKILL/SIGSTOP from every installed mask —
        // a task must never be able to block its own fatal kill.
        *slot &= !UNBLOCKABLE_MASK;
        drop(g);
        // An explicit mask install means the user retook control of the
        // mask — drop any suspend-saved record a signal-less (aborted)
        // rt_sigsuspend left behind, so a much-later delivery can't
        // "restore" a stale pre-suspend mask over this one.
        let _ = take_suspend_saved_mask(task);
    }
    ctx.set_return(SyscallReturn::ok(0));
}
