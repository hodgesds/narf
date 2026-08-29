//! Linux syscall ABI conformance — signal group.
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

/// The per-task raise generation (SIGNAL_RAISE_GEN) advances on EVERY signal
/// raise — including a second signal arriving while a first is still pending
/// (NOT the empty->non-empty transition that SIGNAL_READABLE_GEN tracks). This
/// is the invariant the signalfd poll/epoll park guard relies on: it snapshots
/// this generation before its scan and re-checks it after registering the
/// signal waker, so a raise in the scan->register window forces a re-execution
/// instead of a park on the ~10 ms backstop. `is_signal_pending`'s block-filter
/// cannot cover that window for a BLOCKED signal (the canonical signalfd case),
/// so the block-agnostic raise generation is what closes it. A bump ONLY on
/// was_empty would strand a poller whose signalfd watches the SECOND signal.
fn smoke_abi_signal_raise_generation_bumps_every_raise() -> TestResult {
    with_setup(|| {
        // FAKE_TASK starts clean (see smoke_abi_signal_kill_null_signal), so the
        // reset also zeroed SIGNAL_RAISE_GEN.
        let g0 = crate::handlers::signal_raise_generation(FAKE_TASK);
        // First raise: SIGUSR1 (10). was_empty == true.
        if call(Syscall::Kill.raw(), a1(FAKE_TASK, 10)) != Some(0) {
            return Err("kill(self, SIGUSR1) failed");
        }
        let g1 = crate::handlers::signal_raise_generation(FAKE_TASK);
        if g1 == g0 {
            return Err("raise generation did not advance on the first raise");
        }
        // Second raise while SIGUSR1 is still pending: SIGUSR2 (12). was_empty ==
        // false — this is the case a was_empty-only counter would miss.
        if call(Syscall::Kill.raw(), a1(FAKE_TASK, 12)) != Some(0) {
            return Err("kill(self, SIGUSR2) failed");
        }
        let g2 = crate::handlers::signal_raise_generation(FAKE_TASK);
        if g2 == g1 {
            return Err(
                "raise generation did not advance on a second (non-was_empty) raise — a \
                 signalfd watching the second signal would strand on the backstop",
            );
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_signal_raise_generation_bumps_every_raise
);

fn smoke_abi_signal_kill_neg() -> TestResult {
    with_setup(|| {
        // signum >= 32 → -EINVAL (Linux parity; was a non-Ok InvalidOp
        // shape before the signal-parity pass).
        let r = call(Syscall::Kill.raw(), a1(FAKE_TASK, 65));
        if r != Some(-22) {
            return Err("kill(self, 65) should return -EINVAL");
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
        // Which return shape we see depends on PROCESS-GLOBAL state this
        // test does not control: the blocking branch needs a yield hook +
        // user-task ctx, and in the shared-boot suite the global yield
        // hook is only installed if an executor test happened to run
        // earlier in the (hash-ordered) sequence. Hook present → the
        // block branch bakes -EINTR (-4); hook absent → the documented
        // no-executor fallback returns -1. Both are the harness-correct
        // answers (asserting only -4 made this test flip on unrelated
        // test insertions — it is order luck, not behavior). Real Linux
        // pause(2) -EINTR semantics are covered by the signal_smoke
        // integration path.
        let r = call(Syscall::Pause.raw(), a0(0));
        if r != Some(-4) && r != Some(-1) {
            return Err("pause should return -EINTR (-4, blocking) or -1 (no-executor fallback)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_pause_neg);

// ── RtSigaction ─────────────────────────────────────────────────────
// sys_rt_sigaction(sig, act, oact, sigsetsize): sig>=NSIG(64) OR
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
        // signal 0 is invalid (Linux `do_sigaction` `sig < 1`) → -EINVAL.
        if call(Syscall::RtSigaction.raw(), a3(0, 0, 0, 8)) != Some(EINVAL) {
            return Err("rt_sigaction(0, ...) should return -EINVAL");
        }
        // A faulting `act` → -EFAULT (the new action is read before the old is
        // written, so this wins even with a valid oact).
        if call(Syscall::RtSigaction.raw(), a3(10, u64::MAX, 0, 8)) != Some(EFAULT) {
            return Err("rt_sigaction with a faulting act should return -EFAULT");
        }
        // A faulting `oact` (act absent) → -EFAULT (written last).
        if call(Syscall::RtSigaction.raw(), a3(10, 0, u64::MAX, 8)) != Some(EFAULT) {
            return Err("rt_sigaction with a faulting oact should return -EFAULT");
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
        // signum >= NSIG(64) → invalid_op() (None). Signal 40 became a
        // VALID rt signal when the mask/pending bitmaps widened to u64;
        // 70 is the out-of-range probe now.
        // LINUX-GAP: Linux returns -EINVAL; NARF reports NARF InvalidOp.
        let r = call(Syscall::Sigaction.raw(), a3(70, 0, 0, 0));
        if r.is_some() {
            return Err("sigaction(70,..) should be a non-Ok (InvalidOp) status");
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
        // sigsetsize > sizeof(sigset_t) → -EINVAL (SYSCALL_DEFINE2 checks the
        // size before it touches the user pointer, so this wins over the
        // faulting NULL below).
        if call(Syscall::RtSigpending.raw(), a1(0, 16)) != Some(EINVAL) {
            return Err("rt_sigpending(_, 16) should return -EINVAL");
        }
        // Valid size but a NULL (faulting) set_out → copy_to_user faults →
        // -EFAULT.
        if call(Syscall::RtSigpending.raw(), a1(0, 8)) != Some(EFAULT) {
            return Err("rt_sigpending(NULL, 8) should return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigpending_neg);

// ── RtSigqueueinfo ──────────────────────────────────────────────────
fn smoke_abi_signal_rt_sigqueueinfo_pos() -> TestResult {
    with_setup(|| {
        // Unlike pidfd_send_signal, Linux's rt wrapper overwrites imported
        // si_signo with the syscall argument rather than rejecting a mismatch.
        let si = sigqueue_siginfo(11, -1, FAKE_TASK as u32, 7);
        let r = call(
            Syscall::RtSigqueueinfo.raw(),
            a2(FAKE_TASK, 10, si.as_ptr() as u64),
        );
        if r != Some(0) {
            return Err("rt_sigqueueinfo(self, SIGUSR1, &info) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigqueueinfo_pos);

fn smoke_abi_signal_rt_sigqueueinfo_neg() -> TestResult {
    with_setup(|| {
        let si = sigqueue_siginfo(65, -1, FAKE_TASK as u32, 0);
        if call(
            Syscall::RtSigqueueinfo.raw(),
            a2(FAKE_TASK, 65, si.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("rt_sigqueueinfo(self, 65, &info) should return -EINVAL");
        }
        if call(Syscall::RtSigqueueinfo.raw(), a2(FAKE_TASK, 10, 0)) != Some(EFAULT) {
            return Err("rt_sigqueueinfo with NULL info should return -EFAULT");
        }
        // Linux imports uinfo first: EFAULT wins over both an invalid signal
        // and a nonexistent target, and the failed import delivers nothing.
        let before = crate::handlers::signal_pending_of(FAKE_TASK);
        if call(Syscall::RtSigqueueinfo.raw(), a2(0xDEAD_BEEF, 65, u64::MAX)) != Some(EFAULT) {
            return Err("rt_sigqueueinfo must return -EFAULT before EINVAL/ESRCH");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) != before {
            return Err("failed rt_sigqueueinfo copy delivered a signal");
        }
        if crate::handlers::take_sigqueue_info(FAKE_TASK, 10).is_some() {
            return Err("failed rt_sigqueueinfo copy left a queued payload");
        }
        let missing = sigqueue_siginfo(10, -1, FAKE_TASK as u32, 0);
        if call(
            Syscall::RtSigqueueinfo.raw(),
            a2(0xDEAD_BEEF, 10, missing.as_ptr() as u64),
        ) != Some(ESRCH)
        {
            return Err("rt_sigqueueinfo of a missing target should return -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigqueueinfo_neg);

// ── RtTgsigqueueinfo ────────────────────────────────────────────────
fn smoke_abi_signal_rt_tgsigqueueinfo_pos() -> TestResult {
    with_setup(|| {
        let si = sigqueue_siginfo(10, -1, FAKE_TASK as u32, 7);
        let r = call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(FAKE_TASK, FAKE_TASK, 10, si.as_ptr() as u64),
        );
        if r != Some(0) {
            return Err("rt_tgsigqueueinfo(self, self, SIGUSR1, &info) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_tgsigqueueinfo_pos);

fn smoke_abi_signal_rt_tgsigqueueinfo_neg() -> TestResult {
    with_setup(|| {
        // The mandatory copy precedes tgid/tid validation.
        if call(Syscall::RtTgsigqueueinfo.raw(), a3(0, 0, 99, u64::MAX)) != Some(EFAULT) {
            return Err("rt_tgsigqueueinfo must return -EFAULT before argument errors");
        }
        if call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(FAKE_TASK, FAKE_TASK, 10, 0),
        ) != Some(EFAULT)
        {
            return Err("rt_tgsigqueueinfo with NULL info should return -EFAULT");
        }
        let si = sigqueue_siginfo(99, -1, FAKE_TASK as u32, 0);
        if call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(0, FAKE_TASK, 99, si.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("rt_tgsigqueueinfo with tgid 0 should return -EINVAL");
        }
        if call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(FAKE_TASK, FAKE_TASK, 99, si.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("rt_tgsigqueueinfo with signal 99 should return -EINVAL");
        }
        let missing = sigqueue_siginfo(10, -1, FAKE_TASK as u32, 0);
        // Keep the absent PID within signed pid_t range; 0xDEAD_BEEF is
        // negative after Linux's u64-to-pid_t syscall argument conversion
        // and must therefore fail earlier with EINVAL.
        const MISSING_POSITIVE_PID: u64 = 0x3EAD_BEEF;
        if call(
            Syscall::RtTgsigqueueinfo.raw(),
            a3(
                MISSING_POSITIVE_PID,
                MISSING_POSITIVE_PID,
                10,
                missing.as_ptr() as u64,
            ),
        ) != Some(ESRCH)
        {
            return Err("rt_tgsigqueueinfo of a missing target should return -ESRCH");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) != 0 {
            return Err("failed rt_tgsigqueueinfo validation delivered a signal");
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
        // `if (copy_from_user(&newset, unewset, sizeof(newset)))
        //          return -EFAULT;` — a NULL set fails the copy. This used
        // to assert the -1 sentinel, which reaches libc as EPERM.
        //
        // The suspend SUCCESS path is -EINTR-after-block, which this
        // harness still cannot reach (no executor to park on).
        let r = call(Syscall::RtSigsuspend.raw(), a1(0, 8));
        if r != Some(-14) {
            return Err("rt_sigsuspend(NULL, 8) should return -EFAULT");
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
        // sigsetsize != 8 → -EINVAL before any pointer deref (the size check
        // precedes copy_from_user in SYSCALL_DEFINE4).
        if call(Syscall::RtSigtimedwait.raw(), a3(0, 0, 0, 16)) != Some(EINVAL) {
            return Err("rt_sigtimedwait with sigsetsize!=8 should return -EINVAL");
        }
        // Valid size but a NULL (faulting) set → copy_from_user faults →
        // -EFAULT.
        if call(Syscall::RtSigtimedwait.raw(), a3(0, 0, 0, 8)) != Some(EFAULT) {
            return Err("rt_sigtimedwait(NULL set, 8) should return -EFAULT");
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
        // (a) An invalid flag bit (0x4, outside {SS_ONSTACK=1, SS_DISABLE=2})
        // → -EINVAL (do_sigaltstack `ss_mode != ...`).
        let mut ss = [0u8; 24];
        ss[8..12].copy_from_slice(&0x4u32.to_ne_bytes()); // bad flags
        ss[16..24].copy_from_slice(&(MIN_SIGSTKSZ_TEST).to_ne_bytes()); // ample size
        if call(Syscall::Sigaltstack.raw(), a1(ss.as_ptr() as u64, 0)) != Some(EINVAL) {
            return Err("sigaltstack with invalid flags should return -EINVAL");
        }

        // (b) A non-SS_DISABLE stack with ss_size < MINSIGSTKSZ → -ENOMEM
        // (do_sigaltstack size check). flags = SS_ONSTACK, size = 0.
        let mut small = [0u8; 24];
        small[8..12].copy_from_slice(&1u32.to_ne_bytes()); // SS_ONSTACK
        small[16..24].copy_from_slice(&0u64.to_ne_bytes()); // size 0 < 2048
        if call(Syscall::Sigaltstack.raw(), a1(small.as_ptr() as u64, 0)) != Some(ENOMEM) {
            return Err("sigaltstack with undersized stack should return -ENOMEM");
        }

        // (c) A faulting (non-user) ss_in → -EFAULT (copy_from_user reads the
        // input first, before any out-param write). ss_in==0 means query-only,
        // so use u64::MAX — the file's established faulting-pointer sentinel.
        if call(Syscall::Sigaltstack.raw(), a1(u64::MAX, 0)) != Some(EFAULT) {
            return Err("sigaltstack with a faulting ss_in should return -EFAULT");
        }
        Ok(())
    })
}
// MINSIGSTKSZ on x86_64 (see MIN_SIGSTKSZ in the handler). Used as an "ample"
// altstack size so the flag-validation path is reached before the size check.
const MIN_SIGSTKSZ_TEST: u64 = 8192;
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

// A signal sent by kill(2) must carry the SENDER's pid in the receiver's
// namespace — Linux fills si_pid = task_tgid_nr_ns(current, receiver_ns) at
// kernel/signal.c:1097. NARF's plain kill/tkill/tgkill path set only the
// pending bit and queued no siginfo, so the receiver's signalfd read
// ssi_pid == 0 — indistinguishable from a kernel-originated signal. systemd
// PID 1 and udevd read $signalfd and key on ssi_pid; a sender of 0 is
// dropped or misattributed.
fn smoke_abi_signal_kill_signalfd_reports_sender_pid() -> TestResult {
    with_setup(|| {
        const SIGUSR1: u32 = 10;
        const SENDER_TASK: u64 = 0x7710;
        const SENDER_PID: u64 = 0x7700;

        // Receiver (FAKE_TASK) installs a signalfd watching SIGUSR1.
        let mask = (1u64 << (SIGUSR1 - 1)).to_le_bytes();
        let sfd = match call(
            Syscall::Signalfd.raw(),
            a3((-1i64) as u64, mask.as_ptr() as u64, 8, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("signalfd(-1, &mask, 8, 0) did not return a fd"),
        };

        // A distinct sender task kills the receiver.
        crate::handlers::register_task_to_pid(SENDER_TASK, SENDER_PID);
        crate::handlers::register_pid_task_mapping(SENDER_PID, SENDER_TASK);
        if crate::task::task_get(SENDER_TASK).is_none() {
            let _ = crate::task::Task::new_registered(SENDER_TASK, SENDER_PID);
        }
        set_task(SENDER_TASK);
        let sent = call(Syscall::Kill.raw(), a1(FAKE_TASK, SIGUSR1 as u64));
        set_task(FAKE_TASK);
        if sent != Some(0) {
            crate::task::release_task(SENDER_TASK);
            return Err("kill(receiver, SIGUSR1) did not succeed");
        }

        // The receiver's signalfd record must name the sender.
        let mut rec = [0u8; 128];
        let n = call(
            Syscall::Read.raw(),
            a2(sfd, rec.as_mut_ptr() as u64, rec.len() as u64),
        );
        crate::task::release_task(SENDER_TASK);
        if n != Some(128) {
            return Err("signalfd read did not return one record");
        }
        if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != SIGUSR1 {
            return Err("signalfd record named the wrong signal");
        }
        // ssi_pid @ offset 12.
        match u32::from_le_bytes(rec[12..16].try_into().unwrap()) as u64 {
            SENDER_PID => Ok(()),
            0 => Err("kill delivered ssi_pid == 0 — the sender pid was not recorded"),
            _ => Err("kill recorded the wrong sender pid"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_signal_kill_signalfd_reports_sender_pid
);

// SIGCHLD must name the exiting child in the PARENT's namespace. Linux
// do_notify_parent fills si_pid = task_pid_nr_ns(child, parent_ns) and
// si_code = CLD_EXITED/KILLED/DUMPED; NARF set only the pending bit, so the
// parent's signalfd read ssi_pid == 0 and could not tell which child died.
// systemd PID 1's manager_dispatch_signal_fd keys on ssi_pid.
fn smoke_abi_signal_sigchld_signalfd_names_child() -> TestResult {
    with_setup(|| {
        const SIGCHLD: u32 = 17;
        const CLD_EXITED: i32 = 1;
        const CHILD_PID: u64 = 0x7799;

        // Parent (FAKE_TASK) watches SIGCHLD.
        let mask = (1u64 << (SIGCHLD - 1)).to_le_bytes();
        let sfd = match call(
            Syscall::Signalfd.raw(),
            a3((-1i64) as u64, mask.as_ptr() as u64, 8, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("signalfd(SIGCHLD) did not return a fd"),
        };

        // A child of FAKE_TASK exits with code 3.
        crate::handlers::__test_inject_parent_of(CHILD_PID, FAKE_TASK);
        crate::handlers::stage_pending_termination(CHILD_PID, 3 << 8);
        crate::user_task::notify_task_exited(CHILD_PID, CHILD_PID);

        let mut rec = [0u8; 128];
        if call(
            Syscall::Read.raw(),
            a2(sfd, rec.as_mut_ptr() as u64, rec.len() as u64),
        ) != Some(128)
        {
            return Err("signalfd read did not return one SIGCHLD record");
        }
        if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != SIGCHLD {
            return Err("signalfd record was not SIGCHLD");
        }
        if i32::from_le_bytes(rec[8..12].try_into().unwrap()) != CLD_EXITED {
            return Err("SIGCHLD ssi_code was not CLD_EXITED");
        }
        match u32::from_le_bytes(rec[12..16].try_into().unwrap()) as u64 {
            CHILD_PID => Ok(()),
            0 => Err("SIGCHLD delivered ssi_pid == 0 — the child was not named"),
            _ => Err("SIGCHLD named the wrong child pid"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigchld_signalfd_names_child);

// A signalfd read of a sigqueue'd STANDARD signal (SIGUSR1, coalescing single
// slot) must surface its SI_QUEUE payload (ssi_code=-1, ssi_int=value), never
// degrade to a payload-less SI_USER, and must leave no stranded pending bit —
// the signalfd consumer pops the payload and clears/re-arms the bit together
// under the sigqueue bucket lock (sigqueue_take_and_clear), the same invariant
// the sigwait and handler-delivery consumers hold. Back to back, so a
// per-cycle strand would surface as a wrong ssi_code/ssi_int on the next read.
fn smoke_abi_signal_signalfd_sigqueue_payload() -> TestResult {
    with_setup(|| {
        const SIGUSR1: u32 = 10;
        let mask = (1u64 << (SIGUSR1 - 1)).to_le_bytes();
        let sfd = match call(
            Syscall::Signalfd.raw(),
            a3((-1i64) as u64, mask.as_ptr() as u64, 8, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("signalfd(-1, &mask, 8, 0) did not return a fd"),
        };
        for value in [0xBEEFu64, 0x0102u64] {
            let si = sigqueue_siginfo(SIGUSR1, -1, FAKE_TASK as u32, value);
            if call(
                Syscall::RtSigqueueinfo.raw(),
                a2(FAKE_TASK, SIGUSR1 as u64, si.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("rt_sigqueueinfo(self, SIGUSR1, payload) should return 0");
            }
            let mut rec = [0u8; 128];
            if call(
                Syscall::Read.raw(),
                a2(sfd, rec.as_mut_ptr() as u64, rec.len() as u64),
            ) != Some(128)
            {
                return Err("signalfd read did not return one record");
            }
            if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != SIGUSR1 {
                return Err("signalfd record named the wrong signal");
            }
            // ssi_code @8 must be SI_QUEUE(-1), not SI_USER(0).
            if i32::from_le_bytes(rec[8..12].try_into().unwrap()) != -1 {
                return Err("signalfd ssi_code was not SI_QUEUE(-1) — payload lost");
            }
            // ssi_int @44 carries sival_int.
            if u32::from_le_bytes(rec[44..48].try_into().unwrap()) as u64 != value {
                return Err("signalfd ssi_int did not carry the queued sival");
            }
            if crate::handlers::signal_pending_of(FAKE_TASK) & crate::handlers::sig_bit(SIGUSR1)
                != 0
            {
                return Err("signalfd read left the SIGUSR1 pending bit set");
            }
            if crate::handlers::take_sigqueue_info(FAKE_TASK, SIGUSR1).is_some() {
                return Err("signalfd read left a stranded queued payload");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_signalfd_sigqueue_payload);

fn smoke_abi_signal_signalfd_neg() -> TestResult {
    with_setup(|| {
        // fd 0 is open (stdio) but is not a signalfd, so `do_signalfd4`'s
        // `if (fd_file(f)->f_op != &signalfd_fops) return -EINVAL;` applies.
        // A CLOSED descriptor takes the -EBADF arm above it instead.
        let r = call(Syscall::Signalfd.raw(), a3(0, 0, 8, 0));
        if r != Some(EINVAL) {
            return Err("signalfd on a non-signalfd fd should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_signalfd_neg);

// ── pidfd_send_signal(2) siginfo payload ────────────────────────────
//
// With a non-NULL `info`, `pidfd_send_signal` is `rt_sigqueueinfo(2)`
// addressed by pidfd: the caller's `siginfo_t` travels with the signal and
// has to survive all the way to the target's `signalfd` read. systemd's
// `pidref_sigqueue()` is precisely this call (SI_QUEUE + `si_pid =
// getpid()`), and a udev worker's `on_sigusr1` drops any SIGUSR1 whose
// `ssi_pid` is not its manager — so discarding the payload strands every
// worker in `udev_watch_end()` and leaves `/run/udev/data` empty.

/// x86_64 `siginfo_t` prefix in the layout userspace fills for sigqueue:
/// si_signo@0, si_errno@4, si_code@8, si_pid@16, si_uid@20, si_value@24.
fn sigqueue_siginfo(signum: u32, si_code: i32, si_pid: u32, si_value: u64) -> [u8; 48] {
    let mut si = [0u8; 48];
    si[0..4].copy_from_slice(&signum.to_le_bytes());
    si[8..12].copy_from_slice(&si_code.to_le_bytes());
    si[16..20].copy_from_slice(&si_pid.to_le_bytes());
    si[20..24].copy_from_slice(&1000u32.to_le_bytes()); // si_uid
    si[24..32].copy_from_slice(&si_value.to_le_bytes());
    si
}

/// A signalfd watching exactly `signum` (sigset_t puts signal N at bit N-1).
fn signalfd_watching(signum: u32) -> Result<u64, &'static str> {
    let mask = (1u64 << (signum - 1)).to_le_bytes();
    match call(
        Syscall::Signalfd.raw(),
        a3((-1i64) as u64, mask.as_ptr() as u64, 8, 0),
    ) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("signalfd(-1, &mask, 8, 0) did not return a fd"),
    }
}

/// A pidfd for the harness task, whose `pidfd_send_signal` target is the
/// same task the signalfd above belongs to.
fn pidfd_for_self() -> Result<u64, &'static str> {
    match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("pidfd_open(self) setup failed"),
    }
}

fn smoke_abi_signal_pidfd_send_signal_delivers_siginfo() -> TestResult {
    with_setup(|| {
        const SIGUSR1: u32 = 10;
        const SI_QUEUE: i32 = -1;
        const SENDER_PID: u32 = 4242;
        const SIVAL: u64 = 7;

        let sfd = signalfd_watching(SIGUSR1)?;
        let pidfd = pidfd_for_self()?;
        let si = sigqueue_siginfo(SIGUSR1, SI_QUEUE, SENDER_PID, SIVAL);
        if call(
            Syscall::PidfdSendSignal.raw(),
            a3(pidfd, SIGUSR1 as u64, si.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("pidfd_send_signal(SIGUSR1, &info) did not return 0");
        }

        let mut rec = [0u8; 128];
        if call(
            Syscall::Read.raw(),
            a2(sfd, rec.as_mut_ptr() as u64, rec.len() as u64),
        ) != Some(128)
        {
            return Err("signalfd read did not return one signalfd_siginfo record");
        }
        if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != SIGUSR1 {
            return Err("signalfd record named the wrong signal");
        }
        // ssi_code@8 and ssi_pid@12 are the two fields systemd reads via
        // si_code_from_process() + its manager-pid comparison.
        if i32::from_le_bytes(rec[8..12].try_into().unwrap()) != SI_QUEUE {
            return Err("pidfd_send_signal dropped si_code (ssi_code != SI_QUEUE)");
        }
        if u32::from_le_bytes(rec[12..16].try_into().unwrap()) != SENDER_PID {
            return Err("pidfd_send_signal dropped si_pid (ssi_pid != sender)");
        }
        // ssi_int@44 / ssi_ptr@48 carry sigqueue's sival payload.
        if u64::from_le_bytes(rec[48..56].try_into().unwrap()) != SIVAL {
            return Err("pidfd_send_signal dropped si_value (ssi_ptr)");
        }
        if u32::from_le_bytes(rec[44..48].try_into().unwrap()) != SIVAL as u32 {
            return Err("pidfd_send_signal dropped si_value (ssi_int)");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_signal_pidfd_send_signal_delivers_siginfo
);

fn smoke_abi_signal_pidfd_send_signal_null_info_has_no_payload() -> TestResult {
    with_setup(|| {
        const SIGUSR1: u32 = 10;

        let sfd = signalfd_watching(SIGUSR1)?;
        let pidfd = pidfd_for_self()?;
        if call(
            Syscall::PidfdSendSignal.raw(),
            a3(pidfd, SIGUSR1 as u64, 0, 0),
        ) != Some(0)
        {
            return Err("pidfd_send_signal(SIGUSR1, NULL) did not return 0");
        }

        let mut rec = [0u8; 128];
        if call(
            Syscall::Read.raw(),
            a2(sfd, rec.as_mut_ptr() as u64, rec.len() as u64),
        ) != Some(128)
        {
            return Err("signalfd read did not return one signalfd_siginfo record");
        }
        if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != SIGUSR1 {
            return Err("signalfd record named the wrong signal");
        }
        // A payload-less send is `kill(2)` shape: Linux's prepare_kill_siginfo
        // synthesizes si_code = SI_USER (0) with si_pid naming the SENDER in
        // the receiver's namespace. This test targets self, so ssi_pid is the
        // caller's own pid. The whole class (kill/tkill/tgkill and this
        // NULL-info arm) reports the sender together now — it used to read 0.
        const SI_USER: i32 = 0;
        if i32::from_le_bytes(rec[8..12].try_into().unwrap()) != SI_USER {
            return Err("payload-less pidfd_send_signal should report ssi_code SI_USER");
        }
        let my_pid = call(Syscall::GetPid.raw(), a0(0)).ok_or("getpid")? as u32;
        if u32::from_le_bytes(rec[12..16].try_into().unwrap()) != my_pid {
            return Err("payload-less pidfd_send_signal did not report the sender pid");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_signal_pidfd_send_signal_null_info_has_no_payload
);

fn smoke_abi_signal_pidfd_send_signal_validation_order() -> TestResult {
    with_setup(|| {
        const SIGUSR1: u32 = 10;
        const SI_QUEUE: i32 = -1;
        let pidfd = pidfd_for_self()?;
        let before = crate::handlers::signal_pending_of(FAKE_TASK);

        // With a resolved pidfd, copy/mismatch checks precede signal delivery,
        // including for the null signal probe.
        if call(Syscall::PidfdSendSignal.raw(), a3(pidfd, 0, u64::MAX, 0)) != Some(EFAULT) {
            return Err("pidfd_send_signal(sig 0, bad info) should return -EFAULT");
        }
        let mismatch = sigqueue_siginfo(SIGUSR1 + 1, SI_QUEUE, FAKE_TASK as u32, 0);
        if call(
            Syscall::PidfdSendSignal.raw(),
            a3(pidfd, SIGUSR1 as u64, mismatch.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("pidfd_send_signal with mismatched si_signo should return -EINVAL");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) != before {
            return Err("failed pidfd_send_signal import/validation delivered a signal");
        }
        if crate::handlers::take_sigqueue_info(FAKE_TASK, SIGUSR1).is_some() {
            return Err("failed pidfd_send_signal import/validation left a queued payload");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_signal_pidfd_send_signal_validation_order
);

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
        // sigsetsize != 8 → -EINVAL (checked before any pointer deref).
        if call(Syscall::Sigprocmask.raw(), a3(2, 0, 0, 16)) != Some(EINVAL) {
            return Err("sigprocmask with sigsetsize!=8 should return -EINVAL");
        }
        // A faulting `nset` → -EFAULT (read before the mask op).
        if call(Syscall::Sigprocmask.raw(), a3(2, u64::MAX, 0, 8)) != Some(EFAULT) {
            return Err("sigprocmask with a faulting nset should return -EFAULT");
        }
        // An unknown `how` with a real `nset` → -EINVAL (Linux `sigprocmask`
        // default arm). Provide a readable set word.
        let set: u64 = 0;
        if call(
            Syscall::Sigprocmask.raw(),
            a3(99, &set as *const u64 as u64, 0, 8),
        ) != Some(EINVAL)
        {
            return Err("sigprocmask with unknown how should return -EINVAL");
        }
        // A faulting `oset` (valid/absent nset) → -EFAULT (written last).
        if call(Syscall::Sigprocmask.raw(), a3(2, 0, u64::MAX, 8)) != Some(EFAULT) {
            return Err("sigprocmask with a faulting oset should return -EFAULT");
        }
        // An unknown `how` is IGNORED when `nset` is NULL — a pure query
        // returns 0 (Linux only inspects `how` when nset != NULL). Give a
        // real writable oset so the copy-out succeeds.
        let mut oset: u64 = 0;
        if call(
            Syscall::Sigprocmask.raw(),
            a3(99, 0, &mut oset as *mut u64 as u64, 8),
        ) != Some(0)
        {
            return Err("sigprocmask(garbage_how, NULL, oset, 8) should return 0");
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
        let r = call(Syscall::Tgkill.raw(), a2(FAKE_TASK, FAKE_TASK, 65));
        if r != Some(-22) {
            return Err("tgkill(.., 65) should return -EINVAL");
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

// gettid(2) reports a thread-group leader's PID, but the signal-pending
// table is TaskId-keyed.  tkill/tgkill must translate that Linux-visible TID
// back to the leader task before checking liveness or queuing the signal.
// This is the exact self-signal shape used by musl's signal smoke.
fn smoke_abi_signal_tkill_accepts_leader_gettid() -> TestResult {
    with_setup(|| {
        const PID: u64 = 0xCAFE;
        const OTHER_PID: u64 = 0xBEEF;
        const OTHER_LEADER: u64 = 0xD00D;
        crate::handlers::register_task_to_pid(FAKE_TASK, PID);
        crate::handlers::register_pid_task_mapping(PID, FAKE_TASK);

        // Reproduce the KDE thread-churn collision: this leader's Linux PID
        // is also the raw TaskId of an unrelated group's non-leader thread.
        // Raw-task-first resolution used to send tkill to PID and make
        // tgkill(PID, PID, ..) fail its tgid consistency check with ESRCH.
        crate::handlers::register_pid_task_mapping(OTHER_PID, OTHER_LEADER);
        crate::handlers::register_task_to_pid(PID, OTHER_PID);

        let tid = call(Syscall::Gettid.raw(), a0(0));
        if tid != Some(PID as i64) {
            return Err("gettid did not return the leader's PID");
        }
        if call(Syscall::Tkill.raw(), a1(PID, 10)) != Some(0) {
            return Err("tkill(gettid(), SIGUSR1) should target the leader");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) & (1 << (10 - 1)) == 0 {
            return Err("tkill(gettid()) did not queue SIGUSR1 on the leader task");
        }
        if crate::handlers::signal_pending_of(PID) & (1 << (10 - 1)) != 0 {
            return Err("tkill(gettid()) was misrouted to a colliding raw TaskId");
        }
        crate::handlers::clear_signal_pending(FAKE_TASK, 10);

        if call(Syscall::Tgkill.raw(), a2(PID, PID, 10)) != Some(0) {
            return Err("tgkill(getpid(), gettid(), SIGUSR1) should target the leader");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) & (1 << (10 - 1)) == 0 {
            return Err("tgkill(getpid(), gettid()) did not queue SIGUSR1 on the leader task");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_tkill_accepts_leader_gettid);

fn smoke_abi_signal_tkill_neg() -> TestResult {
    with_setup(|| {
        // sig >= 32 → -EINVAL (Linux parity; was InvalidOp before).
        let r = call(Syscall::Tkill.raw(), a1(FAKE_TASK, 65));
        if r != Some(-22) {
            return Err("tkill(self, 65) should return -EINVAL");
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
        // The stored mask (NARF keys signal N at bit N-1) must have
        // neither SIGKILL nor SIGSTOP set.
        let stored = crate::handlers::signal_mask_of(FAKE_TASK);
        if stored & (crate::handlers::sig_bit(9) | crate::handlers::sig_bit(19)) != 0 {
            return Err("SIGKILL/SIGSTOP must be stripped from the installed block mask");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_sigkill_unblockable);

// ── Real-time signals (33..=63) ──────────────────────────────────────
// The mask/pending bitmaps were u32 (NSIG=32), so RT signals could
// neither be sent nor blocked — musl reserves SIGCANCEL(33) for
// pthread_cancel and SIGSYNCCALL(34) for multithreaded setuid, and
// hands applications SIGRTMIN=35.., so the cap broke real threading
// paths. Everything is u64 now (bit N-1 = signal N, full 1..=64);
// smokes pin the widened range end-to-end: send, block, sigpending
// round-trip, timedwait drain, and the 64/SIGRTMAX rejection edge.

// kill() with an RT signal must queue it like any classic signal.
fn smoke_abi_signal_rt_kill_pending() -> TestResult {
    with_setup(|| {
        // musl SIGRTMIN = 35.
        if call(Syscall::Kill.raw(), a1(FAKE_TASK, 35)) != Some(0) {
            return Err("kill(self, SIGRTMIN=35) should return 0");
        }
        // 64 = SIGRTMAX is the highest valid signal (bit 63, the top
        // u64 slot) — stress-ng --sigrt installs a handler for it.
        if call(Syscall::Kill.raw(), a1(FAKE_TASK, 64)) != Some(0) {
            return Err("kill(self, 64=SIGRTMAX) should return 0");
        }
        let pending = crate::handlers::signal_pending_of(FAKE_TASK);
        if pending & crate::handlers::sig_bit(35) == 0
            || pending & crate::handlers::sig_bit(64) == 0
        {
            return Err("RT signals 35/64 must land in SIGNAL_PENDING");
        }
        // 65 is past _NSIG → rejected like any out-of-range signal.
        if call(Syscall::Kill.raw(), a1(FAKE_TASK, 65)) != Some(-22) {
            return Err("kill(self, 65) should return -EINVAL (past _NSIG)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_kill_pending);

// A default-ignored SIGCHLD remains pending until the return-to-user delivery
// path consumes it, but it must not interrupt wait4 with EINTR. A real handler
// for the same signal does make it actionable, while SIG_IGN suppresses it.
fn smoke_abi_signal_default_ignored_does_not_interrupt_wait() -> TestResult {
    with_setup(|| {
        const SIGCHLD: u32 = 17;
        crate::handlers::raise_signal_pending(FAKE_TASK, SIGCHLD);
        if !crate::handlers::is_signal_pending(FAKE_TASK) {
            return Err("SIGCHLD should remain visible as pending");
        }
        if crate::handlers::has_interrupting_signal(FAKE_TASK) {
            return Err("default-ignored SIGCHLD must not interrupt wait4");
        }

        crate::handlers::__test_set_sigaction(FAKE_TASK, SIGCHLD as usize, 0x4000);
        if !crate::handlers::has_interrupting_signal(FAKE_TASK) {
            return Err("caught SIGCHLD must wake an interruptible wait");
        }

        crate::handlers::__test_set_sigaction(FAKE_TASK, SIGCHLD as usize, 1);
        if crate::handlers::has_interrupting_signal(FAKE_TASK) {
            return Err("SIG_IGN SIGCHLD must not interrupt wait4");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_signal_default_ignored_does_not_interrupt_wait
);

// sigprocmask must be able to block an RT signal: user sigset bit 32
// == signal 33 (musl SIGCANCEL). Pre-widening the `as u32` truncation
// dropped every bit above signal 31, so pthread_cancel's block of
// SIGCANCEL silently did nothing.
fn smoke_abi_signal_rt_sigprocmask_blocks() -> TestResult {
    with_setup(|| {
        let set: u64 = 1u64 << (33 - 1); // userspace convention: bit N-1
        let buf = set.to_ne_bytes();
        // SIG_SETMASK = 2.
        if call(Syscall::Sigprocmask.raw(), a3(2, buf.as_ptr() as u64, 0, 8)) != Some(0) {
            return Err("sigprocmask(SIG_SETMASK, {33}) should return 0");
        }
        if crate::handlers::signal_mask_of(FAKE_TASK) & crate::handlers::sig_bit(33) == 0 {
            return Err("signal 33 must be blockable (mask bit 32 set)");
        }
        // A pending-but-blocked 33 must not be deliverable...
        crate::handlers::raise_signal_pending(FAKE_TASK, 33);
        if crate::handlers::is_signal_pending(FAKE_TASK) {
            return Err("blocked RT signal 33 must not be deliverable");
        }
        // ...and rt_sigpending must report it back in the user convention.
        let mut out = 0u64;
        let r = call(
            Syscall::RtSigpending.raw(),
            a1(&mut out as *mut u64 as u64, 8),
        );
        if r != Some(0) || out & (1u64 << (33 - 1)) == 0 {
            return Err("rt_sigpending must surface blocked-pending signal 33 at user bit 32");
        }
        // Unblocking makes it deliverable again.
        let empty = 0u64.to_ne_bytes();
        if call(
            Syscall::Sigprocmask.raw(),
            a3(2, empty.as_ptr() as u64, 0, 8),
        ) != Some(0)
        {
            return Err("sigprocmask(SIG_SETMASK, {}) should return 0");
        }
        if !crate::handlers::is_signal_pending(FAKE_TASK) {
            return Err("unblocked RT signal 33 must become deliverable");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigprocmask_blocks);

// rt_sigaction on an RT signal: the per-task handler array is NSIG=64
// slots now — installing and querying signum 35 must round-trip
// instead of falling off the old 32-slot table.
fn smoke_abi_signal_rt_sigaction_installs() -> TestResult {
    with_setup(|| {
        // act=0 query on an RT signum → ok(0) (in range).
        if call(Syscall::RtSigaction.raw(), a3(35, 0, 0, 8)) != Some(0) {
            return Err("rt_sigaction(35, NULL, NULL, 8) should return 0");
        }
        // 64 = SIGRTMAX is VALID now (the stress-ng --sigrt case that
        // motivated the bit-N-1 convention); 65 is the out-of-range edge.
        if call(Syscall::RtSigaction.raw(), a3(64, 0, 0, 8)) != Some(0) {
            return Err("rt_sigaction(64=SIGRTMAX, NULL, NULL, 8) should return 0");
        }
        if call(Syscall::RtSigaction.raw(), a3(65, 0, 0, 8)) != Some(-22) {
            return Err("rt_sigaction(65, ...) should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigaction_installs);

// rt_sigtimedwait must see and drain an RT signal: set bit 39 (user
// convention) == signal 40.
fn smoke_abi_signal_rt_sigtimedwait_rt() -> TestResult {
    with_setup(|| {
        crate::handlers::raise_signal_pending(FAKE_TASK, 40);
        let set: u64 = 1u64 << (40 - 1);
        let buf = set.to_ne_bytes();
        let r = call(
            Syscall::RtSigtimedwait.raw(),
            a3(buf.as_ptr() as u64, 0, 0, 8),
        );
        if r != Some(40) {
            return Err("rt_sigtimedwait must return the pending RT signum 40");
        }
        if crate::handlers::signal_pending_of(FAKE_TASK) & crate::handlers::sig_bit(40) != 0 {
            return Err("rt_sigtimedwait must clear the drained RT pending bit");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigtimedwait_rt);

// A STANDARD signal (SIGUSR1, coalescing single-slot payload) queued via
// sigqueue must reach rt_sigtimedwait with its SI_QUEUE payload intact —
// never degrade to a spurious SI_USER sival=0. That degradation is what
// stress-ng --sigq's child reads as its termination sentinel; it arose
// from rt_sigtimedwait clearing the pending bit BEFORE dequeuing the
// payload, so a racing coalescing sender on another CPU could strand the
// bit over an emptied queue. Consume must dequeue the payload first, then
// clear the bit. This drives the stress-ng loop shape single-threaded:
// each sigqueue/consume cycle must carry its own sival, back to back.
fn smoke_abi_signal_rt_sigtimedwait_std_payload() -> TestResult {
    with_setup(|| {
        let set: u64 = 1u64 << (10 - 1); // SIGUSR1 at bit 9
        let sp = &set as *const u64 as u64;
        for value in [0xABCDu64, 0x1234u64] {
            // sigqueue(self, SIGUSR1, {sival = value}) with SI_QUEUE(-1).
            let si = sigqueue_siginfo(10, -1, FAKE_TASK as u32, value);
            if call(
                Syscall::RtSigqueueinfo.raw(),
                a2(FAKE_TASK, 10, si.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("rt_sigqueueinfo(self, SIGUSR1, payload) should return 0");
            }
            // Consume it, capturing the delivered siginfo_t.
            let mut info = [0u8; 128];
            let r = call(
                Syscall::RtSigtimedwait.raw(),
                a3(sp, info.as_mut_ptr() as u64, 0, 8),
            );
            if r != Some(10) {
                return Err("rt_sigtimedwait must return the pending SIGUSR1 (10)");
            }
            let si_code = i32::from_ne_bytes(info[8..12].try_into().unwrap());
            let sival = u64::from_ne_bytes(info[24..32].try_into().unwrap());
            if si_code != -1 {
                return Err("delivered si_code must stay SI_QUEUE(-1), not SI_USER(0)");
            }
            if sival != value {
                return Err("delivered si_value must carry the queued payload, not 0");
            }
            // The consume must clear the bit AND leave no stranded payload:
            // bit set ⟺ payload queued is the invariant the fix preserves.
            if crate::handlers::signal_pending_of(FAKE_TASK) & crate::handlers::sig_bit(10) != 0 {
                return Err("rt_sigtimedwait must clear the drained SIGUSR1 bit");
            }
            if crate::handlers::take_sigqueue_info(FAKE_TASK, 10).is_some() {
                return Err("rt_sigtimedwait left a stranded queued payload");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_signal_rt_sigtimedwait_std_payload);
