//! Linux syscall ABI conformance — signal group.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// ── Kill ────────────────────────────────────────────────────────────
// sys_kill(pid, sig): sig>=32 → invalid_op(); else ORs the pending bit
// and returns ok(0). FAKE_TASK targeting itself is reachable.

fn smoke_abi_signal_kill_pos() -> TestResult {
    with_setup(|| {
        // SIGUSR1 (10) to ourselves: in-range signum → ok(0).
        let r = call(Syscall::Kill.raw(), a1(FAKE_TASK, 10));
        if r != Some(0) {
            return Err("smoke_abi_signal_kill_pos: unexpected syscall return");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_kill_pos);

// POSIX null signal: `kill(pid, 0)` does existence/permission checking only
// and queues NOTHING. Regression for the stress-ng bug where a parent probing
// a child's liveness with kill(child, 0) set pending bit 0, which the delivery
// loop took as "signal 0" → default-action Terminate, killing the freshly-
// exec'd child at its entry point before it ran an instruction. The fix must
// (a) return ok(0) and (b) leave the target's pending mask untouched.
fn smoke_abi_signal_kill_null_signal() -> TestResult {
    with_setup(|| {
        let before = crate::handlers::signal_pending_of(FAKE_TASK);
        if before != 0 {
            return Err("precondition: FAKE_TASK should start with no pending signals");
        }
        // kill(self, 0): existence probe → ok(0), nothing queued.
        let r = call(Syscall::Kill.raw(), a1(FAKE_TASK, 0));
        if r != Some(0) {
            return Err("kill(self, 0) (null signal) should return 0");
        }
        let after = crate::handlers::signal_pending_of(FAKE_TASK);
        if after != 0 {
            return Err("kill(self, 0) must NOT set any pending bit (esp. bit 0)");
        }
        // Same contract for tkill/tgkill, which share the send path.
        if call(Syscall::Tkill.raw(), a1(FAKE_TASK, 0)) != Some(0)
            || call(Syscall::Tgkill.raw(), a2(FAKE_TASK, FAKE_TASK, 0)) != Some(0)
        {
            return Err("tkill/tgkill with sig 0 should return 0");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) != 0 {
            return Err("tkill/tgkill(self, 0) must NOT set any pending bit");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_kill_null_signal);

fn smoke_abi_signal_kill_neg() -> TestResult {
    with_setup(|| {
        // signum >= 32 → -EINVAL (Linux parity; was a non-Ok InvalidOp
        // shape before the signal-parity pass).
        let r = call(Syscall::Kill.raw(), a1(FAKE_TASK, 64));
        if r != Some(-22) {
            return Err("kill(self, 64) should return -EINVAL");
        }
        // A nonexistent target → -ESRCH (was ok(0) before parity).
        let r = call(Syscall::Kill.raw(), a1(0xDEAD_BEEF, 10));
        if r != Some(-3) {
            return Err("kill(nonexistent, SIGUSR1) should return -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_kill_neg);

// ── Pause ───────────────────────────────────────────────────────────
// sys_pause: the harness now REACHES the blocking path. `setup()` registers
// FAKE_TASK in the refcounted task registry, so `current_user_task()` resolves
// (it looks the ctx up by id), and the booted kernel-test kernel has a global
// yield-hook installed — so `sys_pause` takes the block branch, which bakes in
// -EINTR before parking. In the harness there is no own-stack context to park
// into, so the park returns immediately, leaving the -EINTR the handler set.
// (Before the refcounted-task-registry change `current_user_task()` was None,
// so pause hit the immediate fallback and returned -1 — that assumption is now
// stale.) -EINTR is the correct Linux pause(2) result for an interrupted wait.

fn smoke_abi_signal_pause_neg() -> TestResult {
    with_setup(|| {
        // Blocking path taken → pause(2) surfaces -EINTR (Linux parity).
        let r = call(Syscall::Pause.raw(), a0(0));
        if r != Some(-4) {
            return Err("pause should return -EINTR (-4) via the blocking path");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_pause_neg);

// ── RtSigaction ─────────────────────────────────────────────────────
// sys_rt_sigaction(sig, act, oact, sigsetsize): sig>=NSIG(32) OR
// sigsetsize!=8 → ok(-1). Otherwise ok(0). act=0 just leaves the slot.

fn smoke_abi_signal_rt_sigaction_pos() -> TestResult {
    with_setup(|| {
        // act=0 (query-only), valid signum + sigsetsize=8 → ok(0).
        let r = call(Syscall::RtSigaction.raw(), a3(10, 0, 0, 8));
        if r != Some(0) {
            return Err("rt_sigaction(SIGUSR1, NULL, NULL, 8) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigaction_pos);

fn smoke_abi_signal_rt_sigaction_neg() -> TestResult {
    with_setup(|| {
        // sigsetsize != 8 → -EINVAL (Linux parity; was ok(-1) before).
        let r = call(Syscall::RtSigaction.raw(), a3(10, 0, 0, 16));
        if r != Some(-22) {
            return Err("rt_sigaction with sigsetsize!=8 should return -EINVAL");
        }
        // SIGKILL(9)/SIGSTOP(19) can't have their action changed with a
        // non-NULL act → -EINVAL (Linux; previously silently accepted).
        // Pass a bogus non-zero act ptr; the signum check fires first.
        let r = call(Syscall::RtSigaction.raw(), a3(9, 0x1000, 0, 8));
        if r != Some(-22) {
            return Err("rt_sigaction(SIGKILL, act, ...) should return -EINVAL");
        }
        let r = call(Syscall::RtSigaction.raw(), a3(19, 0x1000, 0, 8));
        if r != Some(-22) {
            return Err("rt_sigaction(SIGSTOP, act, ...) should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigaction_neg);

// ── Sigaction ───────────────────────────────────────────────────────
// sys_sigaction(sig, handler, oldout, flags): sig>=NSIG → invalid_op();
// else stores handler + returns ok(0). NARF-native flattened shape.

fn smoke_abi_signal_sigaction_pos() -> TestResult {
    with_setup(|| {
        // handler=0 (clear), oldout=0, valid signum → ok(0).
        let r = call(Syscall::Sigaction.raw(), a3(10, 0, 0, 0));
        if r != Some(0) {
            return Err("smoke_abi_signal_sigaction_pos: unexpected syscall return");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigaction_pos);

fn smoke_abi_signal_sigaction_neg() -> TestResult {
    with_setup(|| {
        // signum >= NSIG(32) → invalid_op() (None).
        // LINUX-GAP: Linux returns -EINVAL; NARF reports NARF InvalidOp.
        let r = call(Syscall::Sigaction.raw(), a3(40, 0, 0, 0));
        if r.is_some() {
            return Err("sigaction(40,..) should be a non-Ok (InvalidOp) status");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigaction_neg);

// ── RtSigpending ────────────────────────────────────────────────────
// sys_rt_sigpending(set_out, sigsetsize): sigsetsize!=8 OR set_out==0
// → ok(-1). Otherwise writes (pending & mask) and returns ok(0).
// The success path writes through `set_out` with an unchecked
// write_unaligned, so the positive case needs a real writable address.

fn smoke_abi_signal_rt_sigpending_pos() -> TestResult {
    with_setup(|| {
        // Provide a real, writable 8-byte buffer for the set_out write.
        let mut buf: u64 = 0;
        let p = &mut buf as *mut u64 as u64;
        let r = call(Syscall::RtSigpending.raw(), a1(p, 8));
        if r != Some(0) {
            return Err("rt_sigpending(&buf, 8) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigpending_pos);

fn smoke_abi_signal_rt_sigpending_neg() -> TestResult {
    with_setup(|| {
        // sigsetsize != 8 → ok(-1) (and set_out==0 is also rejected,
        // which short-circuits before the unchecked write).
        // LINUX-GAP: Linux returns -EINVAL.
        let r = call(Syscall::RtSigpending.raw(), a1(0, 8));
        if r != Some(-1) {
            return Err("rt_sigpending(NULL, 8) should return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigpending_neg);

// ── RtSigqueueinfo ──────────────────────────────────────────────────
// sys_rt_sigqueueinfo(pid, sig, info): sig>=32 → invalid_op(); else
// captures siginfo (skipped when info=0) + raises pending → ok(0).

fn smoke_abi_signal_rt_sigqueueinfo_pos() -> TestResult {
    with_setup(|| {
        // info=0 → siginfo capture skipped; valid sig → ok(0).
        let r = call(Syscall::RtSigqueueinfo.raw(), a2(FAKE_TASK, 10, 0));
        if r != Some(0) {
            return Err("rt_sigqueueinfo(self, SIGUSR1, NULL) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigqueueinfo_pos);

fn smoke_abi_signal_rt_sigqueueinfo_neg() -> TestResult {
    with_setup(|| {
        // sig >= 32 → invalid_op() (None).
        // LINUX-GAP: Linux returns -EINVAL; NARF reports NARF InvalidOp.
        let r = call(Syscall::RtSigqueueinfo.raw(), a2(FAKE_TASK, 64, 0));
        if r.is_some() {
            return Err("rt_sigqueueinfo(self, 64, ..) should be a non-Ok status");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigqueueinfo_neg);

// ── RtTgsigqueueinfo ────────────────────────────────────────────────
// sys_rt_tgsigqueueinfo(tgid, tid, sig, info): sig>=32 → invalid_op();
// else captures siginfo (skipped when info=0) + raises pending → ok(0).

fn smoke_abi_signal_rt_tgsigqueueinfo_pos() -> TestResult {
    with_setup(|| {
        // info=0; valid sig at arg2 → ok(0).
        let r = call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(FAKE_TASK, FAKE_TASK, 10, 0),
        );
        if r != Some(0) {
            return Err("rt_tgsigqueueinfo(self, self, SIGUSR1, NULL) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_tgsigqueueinfo_pos);

fn smoke_abi_signal_rt_tgsigqueueinfo_neg() -> TestResult {
    with_setup(|| {
        // sig (arg2) >= 32 → invalid_op() (None).
        // LINUX-GAP: Linux returns -EINVAL; NARF reports NARF InvalidOp.
        let r = call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(FAKE_TASK, FAKE_TASK, 99, 0),
        );
        if r.is_some() {
            return Err("rt_tgsigqueueinfo(.., 99, ..) should be a non-Ok status");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_tgsigqueueinfo_neg);

// ── RtSigsuspend ────────────────────────────────────────────────────
// sys_rt_sigsuspend(set, sigsetsize): sigsetsize!=8 OR set==0 → ok(-1).
// The success path installs the mask then calls sys_pause (which in the
// harness returns ok(-1) too). Only the immediate input-validation
// error path is deterministic / non-blocking, so only the neg test is
// written here.

fn smoke_abi_signal_rt_sigsuspend_neg() -> TestResult {
    with_setup(|| {
        // set==0 → ok(-1) before any pause.
        // LINUX-GAP: Linux returns -EFAULT for a NULL set; the suspend
        // success path is -EINTR-after-block which the harness can't reach.
        let r = call(Syscall::RtSigsuspend.raw(), a1(0, 8));
        if r != Some(-1) {
            return Err("rt_sigsuspend(NULL, 8) should return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigsuspend_neg);

// ── RtSigtimedwait ──────────────────────────────────────────────────
// sys_rt_sigtimedwait(set, info, timeout, sigsetsize): sigsetsize!=8 OR
// set==0 → ok(-1); nothing-pending-in-set → ok(-1); else clears the bit
// and returns the signum. The positive path needs a pending signal AND
// a readable `set` pointer; queue one first.

fn smoke_abi_signal_rt_sigtimedwait_pos() -> TestResult {
    with_setup(|| {
        // Queue SIGUSR1 (10) to ourselves so it is pending.
        if call(Syscall::Kill.raw(), a1(FAKE_TASK, 10)) != Some(0) {
            return Err("smoke_abi_signal_rt_sigtimedwait_pos: unexpected syscall return");
        }
        // Userspace sigset puts signal N at bit N-1, so SIGUSR1 (10) is
        // bit 9. Provide a real readable set word covering it.
        let set: u64 = 1u64 << 9;
        let p = &set as *const u64 as u64;
        // info=0, timeout=0, sigsetsize=8.
        let r = call(Syscall::RtSigtimedwait.raw(), a3(p, 0, 0, 8));
        if r != Some(10) {
            return Err("smoke_abi_signal_rt_sigtimedwait_pos: unexpected syscall return");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigtimedwait_pos);

fn smoke_abi_signal_rt_sigtimedwait_neg() -> TestResult {
    with_setup(|| {
        // sigsetsize != 8 → ok(-1) before any pointer deref.
        // LINUX-GAP: Linux returns -EINVAL.
        let r = call(Syscall::RtSigtimedwait.raw(), a3(0, 0, 0, 16));
        if r != Some(-1) {
            return Err("rt_sigtimedwait with sigsetsize!=8 should return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigtimedwait_neg);

// ── Sigaltstack ─────────────────────────────────────────────────────
// sys_sigaltstack(ss_in, ss_out): both NULL → ok(0) (no-op). A bad
// flags value in *ss_in → ok(-1). The positive (both NULL) path is
// reachable; the negative needs a readable ss_in with an invalid flag.

fn smoke_abi_signal_sigaltstack_pos() -> TestResult {
    with_setup(|| {
        // ss_in=0, ss_out=0 → no-op → ok(0).
        let r = call(Syscall::Sigaltstack.raw(), a1(0, 0));
        if r != Some(0) {
            return Err("sigaltstack(NULL, NULL) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigaltstack_pos);

fn smoke_abi_signal_sigaltstack_neg() -> TestResult {
    with_setup(|| {
        // Build a stack_t in local memory with an invalid flag bit set
        // (0x4, outside {SS_ONSTACK=1, SS_DISABLE=2}) → ok(-1).
        // LINUX-GAP: Linux returns -EINVAL.
        let mut ss = [0u8; 24];
        ss[0..8].copy_from_slice(&0u64.to_ne_bytes()); // sp
        ss[8..12].copy_from_slice(&0x4u32.to_ne_bytes()); // bad flags
        ss[16..24].copy_from_slice(&0u64.to_ne_bytes()); // size
        let p = ss.as_ptr() as u64;
        let r = call(Syscall::Sigaltstack.raw(), a1(p, 0));
        if r != Some(-1) {
            return Err("sigaltstack with invalid flags should return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigaltstack_neg);

// ── Signalfd ────────────────────────────────────────────────────────
// sys_signalfd(fd, mask, sizemask, flags): fd<0 → create a new
// SignalFdFile, install into the fd table, return the new fd. fd>=0
// referencing a non-signalfd fd → ok(-1).

fn smoke_abi_signal_signalfd_pos() -> TestResult {
    with_setup(|| {
        // fd_arg = -1 (create), mask_ptr = 0 → mask 0, flags 0.
        // Returns a freshly installed non-negative fd.
        let r = call(Syscall::Signalfd.raw(), a3((-1i64) as u64, 0, 8, 0));
        match r {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("signalfd(-1, NULL, 8, 0) should return a new fd >= 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_signalfd_pos);

fn smoke_abi_signal_signalfd_neg() -> TestResult {
    with_setup(|| {
        // fd_arg = 0 (>=0) but fd 0 is not a registered signalfd →
        // signalfd_arc_from_fd misses → ok(-1).
        // LINUX-GAP: Linux returns -EINVAL/-EBADF here.
        let r = call(Syscall::Signalfd.raw(), a3(0, 0, 8, 0));
        if r != Some(-1) {
            return Err("signalfd on a non-signalfd fd should return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_signalfd_neg);

// ── Sigprocmask ─────────────────────────────────────────────────────
// sys_sigprocmask(how, set, oldset, sigsetsize): sigsetsize!=8 → ok(-1);
// unknown how → ok(-1); else updates the per-task mask → ok(0).

fn smoke_abi_signal_sigprocmask_pos() -> TestResult {
    with_setup(|| {
        // SIG_SETMASK(2) with set=0, oldset=0, sigsetsize=8 → ok(0).
        let r = call(Syscall::Sigprocmask.raw(), a3(2, 0, 0, 8));
        if r != Some(0) {
            return Err("sigprocmask(SIG_SETMASK, NULL, NULL, 8) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigprocmask_pos);

fn smoke_abi_signal_sigprocmask_neg() -> TestResult {
    with_setup(|| {
        // sigsetsize != 8 → ok(-1).
        // LINUX-GAP: Linux returns -EINVAL.
        let r = call(Syscall::Sigprocmask.raw(), a3(2, 0, 0, 16));
        if r != Some(-1) {
            return Err("sigprocmask with sigsetsize!=8 should return -1");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigprocmask_neg);

// ── Sigreturn ───────────────────────────────────────────────────────
// sys_sigreturn(sc_vaddr): resolves a recorded sigframe and restores
// it; on a failed perform_sigreturn it returns invalid_op(). In the
// harness no frame was delivered, so it can only fail. The success
// path (restore live user regs) is unreachable without a real delivery,
// so only the negative/stub case is written.

fn smoke_abi_signal_sigreturn_neg() -> TestResult {
    with_setup(|| {
        // No delivered sigframe + bogus vaddr → perform_sigreturn fails
        // → invalid_op() (call() decodes that as None).
        // LINUX-GAP: a real sigreturn does not return to the caller at
        // all; it resumes the interrupted context. Unreachable here.
        let r = call(Syscall::Sigreturn.raw(), a0(0));
        if r.is_some() {
            return Err("sigreturn with no frame should be a non-Ok (InvalidOp) status");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigreturn_neg);

// ── Tgkill ──────────────────────────────────────────────────────────
// sys_tgkill(tgid, tid, sig): sig>=32 → invalid_op(); else ORs the
// pending bit for `tid` and returns ok(0).

fn smoke_abi_signal_tgkill_pos() -> TestResult {
    with_setup(|| {
        // Valid sig to (tgid=FAKE_TASK, tid=FAKE_TASK) → ok(0).
        let r = call(Syscall::Tgkill.raw(), a2(FAKE_TASK, FAKE_TASK, 10));
        if r != Some(0) {
            return Err("smoke_abi_signal_tgkill_pos: unexpected syscall return");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_tgkill_pos);

fn smoke_abi_signal_tgkill_neg() -> TestResult {
    with_setup(|| {
        // sig (arg2) >= 32 → -EINVAL (Linux parity; was InvalidOp before).
        let r = call(Syscall::Tgkill.raw(), a2(FAKE_TASK, FAKE_TASK, 64));
        if r != Some(-22) {
            return Err("tgkill(.., 64) should return -EINVAL");
        }
        // Dead tid → -ESRCH (was silently ok before parity).
        let r = call(Syscall::Tgkill.raw(), a2(FAKE_TASK, 0xDEAD, 10));
        if r != Some(-3) {
            return Err("tgkill(.., dead_tid, ..) should return -ESRCH");
        }
        // (tgid, tid) mismatch → -ESRCH (tid exists, tgid wrong).
        let r = call(Syscall::Tgkill.raw(), a2(0xBAD2, FAKE_TASK, 10));
        if r != Some(-3) {
            return Err("tgkill(wrong_tgid, self, ..) should return -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_tgkill_neg);

// ── Tkill ───────────────────────────────────────────────────────────
// sys_tkill(tid, sig): sig>=32 → invalid_op(); else ORs the pending
// bit for `tid` and returns ok(0).

fn smoke_abi_signal_tkill_pos() -> TestResult {
    with_setup(|| {
        // Valid sig to tid=FAKE_TASK → ok(0).
        let r = call(Syscall::Tkill.raw(), a1(FAKE_TASK, 10));
        if r != Some(0) {
            return Err("smoke_abi_signal_tkill_pos: unexpected syscall return");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_tkill_pos);

fn smoke_abi_signal_tkill_neg() -> TestResult {
    with_setup(|| {
        // sig >= 32 → -EINVAL (Linux parity; was InvalidOp before).
        let r = call(Syscall::Tkill.raw(), a1(FAKE_TASK, 64));
        if r != Some(-22) {
            return Err("tkill(self, 64) should return -EINVAL");
        }
        // Dead tid → -ESRCH.
        let r = call(Syscall::Tkill.raw(), a1(0xDEAD, 10));
        if r != Some(-3) {
            return Err("tkill(dead_tid, ..) should return -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_tkill_neg);

// ── SIGKILL/SIGSTOP cannot be blocked ────────────────────────────────
// sigprocmask must silently strip SIGKILL(9)/SIGSTOP(19) from any
// installed block set (Linux parity — a task must never be able to
// block its own fatal kill). Regression for the pre-parity gap where a
// blocked SIGKILL made a task uninterruptible.
fn smoke_abi_signal_sigkill_unblockable() -> TestResult {
    with_setup(|| {
        // Build a user sigset with SIGKILL + SIGSTOP set. Userspace
        // sigset_t puts signal N at bit N-1.
        let set: u64 = (1u64 << (9 - 1)) | (1u64 << (19 - 1));
        let buf = set.to_ne_bytes();
        let set_ptr = buf.as_ptr() as u64;
        // SIG_BLOCK = 0. Install, then read the mask back.
        if call(Syscall::Sigprocmask.raw(), a3(0, set_ptr, 0, 8)) != Some(0) {
            return Err("sigprocmask(SIG_BLOCK, {SIGKILL,SIGSTOP}) should return 0");
        }
        // The stored mask (NARF keys signal N at bit N) must have
        // neither SIGKILL nor SIGSTOP set.
        let stored = crate::handlers::signal_mask_of(FAKE_TASK);
        if stored & ((1 << 9) | (1 << 19)) != 0 {
            return Err("SIGKILL/SIGSTOP must be stripped from the installed block mask");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigkill_unblockable);
