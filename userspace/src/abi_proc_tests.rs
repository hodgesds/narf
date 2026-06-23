//! Linux syscall ABI conformance — proc group.
//!
//! Process/thread-management syscalls. Shares the harness in
//! [`crate::abi_test_support`]. Every test drives `kernel_syscall_entry`
//! against a synthetic `AbiCtx` (no user mode, no scheduler, no live
//! address space), so the reachable surface for the fork/clone/exec
//! family is the immediate argument-validation + table-bookkeeping path;
//! the success path that spawns a real child task is unreachable here and
//! is exercised only with its error/stub return.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// ── getppid(2) — infallible, returns parent visible pid (0 if none) ──

fn smoke_abi_proc_getppid_pos() -> TestResult {
    with_setup(|| {
        // getppid is infallible: it always reports Ok with the parent's
        // visible pid, defaulting to 0 when no parent-of mapping exists
        // for the fake task. Assert the Ok status + a non-negative value.
        match call(Syscall::GetPpid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getppid returned negative"),
            None => Err("getppid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getppid_pos);

fn smoke_abi_proc_getppid_ignores_args() -> TestResult {
    with_setup(|| {
        // getppid takes no arguments; garbage in arg0 must not change the
        // result (regression pin against an args-shape drift).
        let clean = call(Syscall::GetPpid.raw(), a0(0));
        let garbage = call(Syscall::GetPpid.raw(), a0(0xdead_beef));
        if clean == garbage {
            Ok(())
        } else {
            Err("getppid result changed with garbage in arg0")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getppid_ignores_args);

// ── gettid(2) — infallible, returns the caller's TaskId ──

fn smoke_abi_proc_gettid_pos() -> TestResult {
    with_setup(|| {
        // The harness reports FAKE_TASK as the current task id; gettid
        // returns exactly that.
        match call(Syscall::Gettid.raw(), a0(0)) {
            Some(v) if v as u64 == FAKE_TASK => Ok(()),
            Some(_) => Err("gettid did not return the current task id"),
            None => Err("gettid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_gettid_pos);

fn smoke_abi_proc_gettid_tracks_set_task() -> TestResult {
    with_setup(|| {
        set_task(4242);
        let r = call(Syscall::Gettid.raw(), a0(0));
        set_task(FAKE_TASK);
        match r {
            Some(4242) => Ok(()),
            _ => Err("gettid did not follow the overridden task id"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_gettid_tracks_set_task);

// ── getpgid(2) / setpgid(2) — process-group bookkeeping ──

fn smoke_abi_proc_setpgid_pos() -> TestResult {
    with_setup(|| {
        // setpgid(0, 0): make the caller its own group leader. PGID_TABLE
        // is boot-initialised, so this records the entry and returns 0.
        match call(Syscall::Setpgid.raw(), a1(0, 0)) {
            Some(0) => Ok(()),
            Some(_) => Err("setpgid(0,0) should return 0"),
            None => Err("setpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_pos);

fn smoke_abi_proc_getpgid_pos() -> TestResult {
    with_setup(|| {
        // After setpgid(0,0) the caller's pgid is itself; getpgid(0) must
        // then report a non-negative group id (the exact value depends on
        // pid-space translation under the container feature, so we only
        // assert Ok + non-negative).
        let _ = call(Syscall::Setpgid.raw(), a1(0, 0));
        match call(Syscall::Getpgid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getpgid returned negative pgid"),
            None => Err("getpgid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getpgid_pos);

fn smoke_abi_proc_setpgid_neg() -> TestResult {
    with_setup(|| {
        // NARF's setpgid never validates the target's existence/session;
        // it inserts unconditionally and returns 0. The only failure path
        // is an uninitialised table, which can't happen post-boot — so the
        // negative case here is the absence of an error: a setpgid against
        // an arbitrary (unknown) target pid still returns 0, not an errno.
        // LINUX-GAP: Linux returns -ESRCH for a non-existent target pid and
        // -EPERM across session boundaries; NARF accepts any pid with ok(0).
        match call(Syscall::Setpgid.raw(), a1(123456, 0)) {
            Some(0) => Ok(()),
            other => {
                let _ = other;
                Err("setpgid on an unknown pid changed from ok(0)")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setpgid_neg);

// ── getpgrp(2) — caller's pgid, no args ──

fn smoke_abi_proc_getpgrp_pos() -> TestResult {
    with_setup(|| match call(Syscall::Getpgrp.raw(), a0(0)) {
        Some(v) if v >= 0 => Ok(()),
        Some(_) => Err("getpgrp returned negative"),
        None => Err("getpgrp returned non-Ok status"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getpgrp_pos);

// ── getsid(2) / setsid(2) — session bookkeeping ──

fn smoke_abi_proc_setsid_pos() -> TestResult {
    with_setup(|| {
        // setsid makes the caller a session leader: sid = pgid = pid. The
        // handler records both tables and returns the new sid. SID_TABLE is
        // boot-initialised so this succeeds.
        match call(Syscall::Setsid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("setsid returned negative sid"),
            None => Err("setsid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setsid_pos);

fn smoke_abi_proc_getsid_pos() -> TestResult {
    with_setup(|| {
        // getsid(0) reads the caller's session id, defaulting to its own
        // task id when no setsid mapping exists. Infallible → Ok + >= 0.
        match call(Syscall::Getsid.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            Some(_) => Err("getsid returned negative"),
            None => Err("getsid returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getsid_pos);

fn smoke_abi_proc_getsid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux returns -ESRCH for getsid of a non-existent pid;
        // NARF's getsid has no error path — an unknown pid resolves to the
        // pid itself (default sid == pid) and returns Ok.
        match call(Syscall::Getsid.raw(), a0(987654)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("getsid on an unknown pid changed from the ok-default path"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_getsid_neg);

// ── prctl(2) — PR_SET/GET_NO_NEW_PRIVS round-trip + bad op ──

fn smoke_abi_proc_prctl_pos() -> TestResult {
    with_setup(|| {
        // PR_SET_NO_NEW_PRIVS = 38, arg = 1. Then PR_GET_NO_NEW_PRIVS = 39
        // must read back 1. PRCTL_TABLE is boot-initialised; this round-trips
        // deterministically regardless of any prior boot-time state for the
        // fake task (we set then immediately get).
        const PR_SET_NO_NEW_PRIVS: u64 = 38;
        const PR_GET_NO_NEW_PRIVS: u64 = 39;
        match call(Syscall::Prctl.raw(), a1(PR_SET_NO_NEW_PRIVS, 1)) {
            Some(0) => {}
            _ => return Err("PR_SET_NO_NEW_PRIVS did not return 0"),
        }
        match call(Syscall::Prctl.raw(), a0(PR_GET_NO_NEW_PRIVS)) {
            Some(1) => Ok(()),
            _ => Err("PR_GET_NO_NEW_PRIVS did not read back 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_pos);

fn smoke_abi_proc_prctl_neg() -> TestResult {
    with_setup(|| {
        // An unrecognised prctl op falls to the `_ => fail` arm, which
        // returns the -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL for an unknown option; NARF
        // returns the bare -1 sentinel.
        match call(Syscall::Prctl.raw(), a0(0xFFFF)) {
            Some(-1) => Ok(()),
            other => {
                let _ = other;
                Err("prctl with an unknown op did not return -1")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_prctl_neg);

// ── arch_prctl(2) — x86_64 thread-pointer install ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_arch_prctl_pos() -> TestResult {
    with_setup(|| {
        // ARCH_GET_FS = 0x1003: read the live IA32_FS_BASE and copy it as a
        // u64 to a (kernel-stack) buffer the harness passes as the "user"
        // pointer. copy_to_user operates on real addresses here, so the
        // write succeeds and the handler returns 0.
        const ARCH_GET_FS: u64 = 0x1003;
        let mut out = [0u8; 8];
        match call(
            Syscall::ArchPrctl.raw(),
            a1(ARCH_GET_FS, out.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("arch_prctl ARCH_GET_FS did not return 0"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_arch_prctl_pos);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_arch_prctl_neg() -> TestResult {
    with_setup(|| {
        // ARCH_SET_GS = 0x1001 is not yet wired; the handler returns
        // -EINVAL. An unknown sub-code (0x9999) likewise returns -EINVAL.
        const ARCH_SET_GS: u64 = 0x1001;
        match call(Syscall::ArchPrctl.raw(), a1(ARCH_SET_GS, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("arch_prctl ARCH_SET_GS did not return -EINVAL"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_arch_prctl_neg);

// ── set_tid_address(2) — records clear_child_tid, returns caller TID ──

fn smoke_abi_proc_set_tid_address_pos() -> TestResult {
    with_setup(|| {
        // set_tid_address records the pointer regardless of value and
        // returns the caller's TID (FAKE_TASK). A NULL pointer is the
        // legal "disable clear_child_tid" case and still returns the TID.
        match call(Syscall::SetTidAddress.raw(), a0(0)) {
            Some(v) if v as u64 == FAKE_TASK => Ok(()),
            Some(_) => Err("set_tid_address did not return the caller TID"),
            None => Err("set_tid_address returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_set_tid_address_pos);

fn smoke_abi_proc_set_tid_address_nonzero() -> TestResult {
    with_setup(|| {
        // A non-zero (kernel-stack) pointer is recorded the same way; the
        // return is invariant to the pointer value (it's always the TID).
        let mut slot = [0u8; 8];
        match call(
            Syscall::SetTidAddress.raw(),
            a0(slot.as_mut_ptr() as u64),
        ) {
            Some(v) if v as u64 == FAKE_TASK => Ok(()),
            _ => Err("set_tid_address with a pointer did not return the TID"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_set_tid_address_nonzero);

// ── capget(2) / capset(2) — capability-set round-trip ──

fn smoke_abi_proc_capset_capget_pos() -> TestResult {
    with_setup(|| {
        // capset then capget with the v3 header round-trips a cap mask.
        // The harness passes kernel-stack buffers as the user hdr/data
        // pointers; copy_{from,to}_user operate on real addresses.
        const CAP_VERSION_3: u32 = 0x2008_0522;
        // header: { u32 version; i32 pid } — pid 0 = self.
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        // data: 2 * cap_user_data_t, each { u32 effective; u32 permitted;
        // u32 inheritable }. For ndata=2 the layout is field-major: 3 lo
        // words then 3 hi words. Plant a low-word effective bit.
        let mut data = [0u8; 24];
        data[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // effective lo
        match call(
            Syscall::Capset.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("capset with a v3 header did not return 0"),
        }
        // Read it back.
        let mut out = [0u8; 24];
        match call(
            Syscall::Capget.raw(),
            a1(hdr.as_mut_ptr() as u64, out.as_mut_ptr() as u64),
        ) {
            Some(0) => {}
            _ => return Err("capget with a v3 header did not return 0"),
        }
        if out[0..4] == 0x0000_0001u32.to_le_bytes() {
            Ok(())
        } else {
            Err("capget did not read back the effective bit set by capset")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_capset_capget_pos);

fn smoke_abi_proc_capget_neg() -> TestResult {
    with_setup(|| {
        // hdrp == NULL → EFAULT (Linux-shaped error in the value).
        match call(Syscall::Capget.raw(), a1(0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("capget(NULL,..) did not return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_capget_neg);

fn smoke_abi_proc_capset_neg() -> TestResult {
    with_setup(|| {
        // An unknown capability version makes capset rewrite the header to
        // the preferred version and return EINVAL (Linux retry protocol).
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut data = [0u8; 24];
        match call(
            Syscall::Capset.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("capset with a bad version did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_capset_neg);

// ── personality(2) — always-accept stub ──

fn smoke_abi_proc_personality_pos() -> TestResult {
    with_setup(|| {
        // NARF's personality is a stub that returns 0 (the prior
        // personality, conventionally PER_LINUX == 0) for any argument.
        match call(Syscall::Personality.raw(), a0(0xffff_ffff)) {
            Some(0) => Ok(()),
            _ => Err("personality stub did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_personality_pos);

// ── kcmp(2) — resource comparison ──

fn smoke_abi_proc_kcmp_pos() -> TestResult {
    with_setup(|| {
        // kcmp(self, self, KCMP_VM, 0, 0): a task shares every resource
        // with itself → 0. KCMP_VM == 1.
        const KCMP_VM: u64 = 1;
        match call(
            Syscall::Kcmp.raw(),
            a3(FAKE_TASK, FAKE_TASK, KCMP_VM, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("kcmp(self,self) did not return 0 (equal)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_kcmp_pos);

fn smoke_abi_proc_kcmp_neg() -> TestResult {
    with_setup(|| {
        // type >= KCMP_TYPES (8) → EINVAL.
        match call(Syscall::Kcmp.raw(), a3(FAKE_TASK, FAKE_TASK, 99, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("kcmp with an out-of-range type did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_kcmp_neg);

fn smoke_abi_proc_kcmp_esrch() -> TestResult {
    with_setup(|| {
        // An unknown pid (no PID→TaskId mapping, and != self) → ESRCH.
        const KCMP_VM: u64 = 1;
        match call(
            Syscall::Kcmp.raw(),
            a3(FAKE_TASK, 7_654_321, KCMP_VM, 0),
        ) {
            Some(v) if v == ESRCH => Ok(()),
            _ => Err("kcmp with an unknown pid did not return -ESRCH"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_kcmp_esrch);

// ── pidfd_open(2) — mint a pidfd ──

fn smoke_abi_proc_pidfd_open_pos() -> TestResult {
    with_setup(|| {
        // A non-zero pid with no live mapping is treated as a zombie and a
        // pidfd is minted + installed in the caller's fd table, returning a
        // small non-negative fd.
        match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("pidfd_open did not return a valid fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_pos);

fn smoke_abi_proc_pidfd_open_neg() -> TestResult {
    with_setup(|| {
        // pid == 0 is rejected with the -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL for pid 0; NARF returns -1.
        match call(Syscall::PidfdOpen.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("pidfd_open(0) did not return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_open_neg);

// ── pidfd_send_signal(2) — deliver via a pidfd ──

fn smoke_abi_proc_pidfd_send_signal_pos() -> TestResult {
    with_setup(|| {
        // Mint a pidfd for self, then pidfd_send_signal(pidfd, 0, ...): sig
        // 0 is the existence/permission probe — it resolves the target and
        // returns 0 without queuing anything.
        let pidfd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open setup failed"),
        };
        match call(Syscall::PidfdSendSignal.raw(), a3(pidfd, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("pidfd_send_signal(sig 0) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_pos);

fn smoke_abi_proc_pidfd_send_signal_neg() -> TestResult {
    with_setup(|| {
        // signum >= 32 → EINVAL (checked before any fd resolution).
        match call(Syscall::PidfdSendSignal.raw(), a3(3, 64, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_send_signal with sig 64 did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_neg);

fn smoke_abi_proc_pidfd_send_signal_badfd() -> TestResult {
    with_setup(|| {
        // A valid signum but an fd that isn't a pidfd → EBADF.
        match call(Syscall::PidfdSendSignal.raw(), a3(4242, 9, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("pidfd_send_signal on a non-pidfd did not return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_send_signal_badfd);

// ── pidfd_getfd(2) — clone an fd out of a pidfd's target ──

fn smoke_abi_proc_pidfd_getfd_neg() -> TestResult {
    with_setup(|| {
        // flags != 0 → EINVAL (validated first).
        match call(Syscall::PidfdGetfd.raw(), a3(0, 0, 1, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pidfd_getfd with non-zero flags did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_getfd_neg);

fn smoke_abi_proc_pidfd_getfd_badfd() -> TestResult {
    with_setup(|| {
        // flags == 0 but arg0 is not a pidfd → EBADF.
        match call(Syscall::PidfdGetfd.raw(), a3(4242, 0, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("pidfd_getfd on a non-pidfd did not return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_getfd_badfd);

fn smoke_abi_proc_pidfd_getfd_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        // Open a real fd in the (single) task's fd table, mint a pidfd for
        // self, then pidfd_getfd should duplicate that fd into a new slot.
        // target_pid == self short-circuits the pid→task resolution so the
        // source table is the caller's own.
        let path = b"/abi/f\0";
        let srcfd = match call(Syscall::OpenFile.raw(), a1(path.as_ptr() as u64, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open setup failed"),
        };
        let pidfd = match call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("pidfd_open setup failed"),
        };
        match call(Syscall::PidfdGetfd.raw(), a3(pidfd, srcfd, 0, 0)) {
            Some(newfd) if newfd >= 0 && newfd as u64 != srcfd => Ok(()),
            Some(_) => Err("pidfd_getfd returned an unexpected fd"),
            None => Err("pidfd_getfd returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_pidfd_getfd_pos);

// ── wait4(2) — non-blocking reap paths ──

fn smoke_abi_proc_wait4_wnohang_no_child() -> TestResult {
    with_setup(|| {
        // wait4(-1, NULL, WNOHANG, NULL) with no pending child → 0
        // (no child ready). WNOHANG == 1.
        const WNOHANG: u64 = 1;
        match call(
            Syscall::Wait4.raw(),
            a3((-1i64) as u64, 0, WNOHANG, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("wait4 WNOHANG with no child did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_wait4_wnohang_no_child);

// LINUX-GAP: wait4 with no children should return -ECHILD; the blocking
// (non-WNOHANG, no-child) path is only exercised via the polling future,
// so the immediate-return WNOHANG path above is the reachable surface and
// returns 0 rather than -ECHILD.

// ── waitid(2) — non-blocking + validation paths ──

fn smoke_abi_proc_waitid_wnohang_no_child() -> TestResult {
    with_setup(|| {
        // waitid(P_ALL, 0, infop, WNOHANG) with no child → 0 (POSIX:
        // success, caller-prezeroed siginfo). P_ALL == 0, WNOHANG == 1.
        const P_ALL: u64 = 0;
        const WNOHANG: u64 = 1;
        let mut si = [0u8; 128];
        match call(
            Syscall::Waitid.raw(),
            a3(P_ALL, 0, si.as_mut_ptr() as u64, WNOHANG),
        ) {
            Some(0) => Ok(()),
            _ => Err("waitid WNOHANG with no child did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_waitid_wnohang_no_child);

fn smoke_abi_proc_waitid_neg() -> TestResult {
    with_setup(|| {
        // An unrecognised idtype (3) → EINVAL.
        match call(Syscall::Waitid.raw(), a3(3, 0, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("waitid with a bad idtype did not return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_waitid_neg);

// ── fork(2) / vfork(2) — no live address space in the harness ──

fn smoke_abi_proc_fork_neg() -> TestResult {
    with_setup(|| {
        // No user address space is installed in the harness, so sys_fork's
        // `current_address_space()` lookup returns None and the handler
        // reports a non-Ok NARF status (InvalidOp). The success path (spawn
        // a child) is unreachable without a live AS + scheduler.
        let r = call_raw(Syscall::Fork.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("fork without an address space did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_fork_neg);

fn smoke_abi_proc_vfork_neg() -> TestResult {
    with_setup(|| {
        // Vfork maps to sys_fork; same no-AS InvalidOp path.
        let r = call_raw(Syscall::Vfork.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("vfork without an address space did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_vfork_neg);

// ── clone(2) — no live address space ──

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_clone_neg() -> TestResult {
    with_setup(|| {
        // clone routes through do_clone3, whose first step is the
        // `current_address_space()` lookup — None in the harness → InvalidOp.
        let r = call_raw(Syscall::Clone.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clone without an address space did not report InvalidOp")
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_clone_neg);

// ── clone3(2) — struct validation + no live address space ──

fn smoke_abi_proc_clone3_badarg() -> TestResult {
    with_setup(|| {
        // clone3(NULL, ...) and clone3(ptr, size<8) are rejected with
        // InvalidOp before any address-space work.
        let r = call_raw(Syscall::Clone3.raw(), a1(0, 64));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clone3(NULL,..) did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_badarg);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_proc_clone3_no_as() -> TestResult {
    with_setup(|| {
        // A well-formed clone_args (size >= 8, non-NULL) passes the prefix
        // validation, then hits the no-AS InvalidOp path in do_clone3.
        let mut ca = [0u8; 88]; // CLONE_ARGS_MIN-ish; flags=0, all zero.
        let r = call_raw(
            Syscall::Clone3.raw(),
            a1(ca.as_mut_ptr() as u64, ca.len() as u64),
        );
        let _ = &mut ca;
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clone3 without an address space did not report InvalidOp")
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_proc_clone3_no_as);

// ── execve(2) / execveat(2) — NULL path rejection ──

fn smoke_abi_proc_execve_neg() -> TestResult {
    with_setup(|| {
        // execve(NULL, ...) is rejected with InvalidOp (path_uptr == 0).
        let r = call_raw(Syscall::Execve.raw(), a2(0, 0, 0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("execve(NULL,..) did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execve_neg);

fn smoke_abi_proc_execve_missing_path() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        // A non-NULL path that doesn't resolve (or that can't be loaded
        // without a live AS) fails: the handler reports a non-Ok NARF
        // status rather than success. The full success path needs a real
        // user address space to load the image into, unreachable here.
        let path = b"/abi/nope\0";
        let r = call_raw(
            Syscall::Execve.raw(),
            a3(path.as_ptr() as u64, 0, 0, 0),
        );
        if r.status != SyscallReturn::OK || (r.value as i64) < 0 {
            Ok(())
        } else {
            Err("execve of a missing path reported success")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execve_missing_path);

fn smoke_abi_proc_execveat_neg() -> TestResult {
    with_setup(|| {
        // execveat reshapes (dirfd, path, argv, envp, flags) → execve(path,
        // argv, envp); a NULL path (arg1) forwards as execve(NULL) → InvalidOp.
        let r = call_raw(Syscall::Execveat.raw(), a3(0, 0, 0, 0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("execveat with a NULL path did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_execveat_neg);

// ── exit_task — landing path not installed in the harness ──

fn smoke_abi_proc_exit_task_neg() -> TestResult {
    with_setup(|| {
        // With no UserTaskCtx exit hook and no EXIT_LANDING_RIP installed,
        // sys_exit_task can neither longjmp nor redirect, so it reports a
        // non-Ok NARF status (InvalidOp). The real "process exits" path is
        // unreachable without the polling future / landing trampoline.
        let r = call_raw(Syscall::ExitTask.raw(), a0(0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("exit_task without a landing path did not report InvalidOp")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_exit_task_neg);

// ── unshare(2) — no-op flags succeed ──

fn smoke_abi_proc_unshare_pos() -> TestResult {
    with_setup(|| {
        // unshare(0): no namespace bits set → Linux returns 0, and so does
        // NARF (the no-op success path).
        match call(Syscall::Unshare.raw(), a0(0)) {
            Some(0) => Ok(()),
            _ => Err("unshare(0) did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_unshare_pos);

// ── setns(2) — no resolvable target ──

fn smoke_abi_proc_setns_neg() -> TestResult {
    with_setup(|| {
        // setns with an fd that isn't an NsFd and a target that resolves to
        // no namespace yields the -1 sentinel: under `container`, no
        // supported nstype bits / no namespace → ok(!0); without `container`
        // the whole syscall is a !0 stub. Either way the value is -1.
        // LINUX-GAP: Linux returns -EBADF / -EINVAL here; NARF returns the
        // bare -1 sentinel.
        match call(Syscall::Setns.raw(), a1(4242, 0)) {
            Some(-1) => Ok(()),
            other => {
                let _ = other;
                Err("setns with an unresolvable target did not return -1")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_proc_setns_neg);
