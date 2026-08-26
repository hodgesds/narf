//! Linux syscall ABI conformance — async group.
use crate::abi_test_support::*;

// ════════════════════════════════════════════════════════════════════
// poll(2) — sys_poll(pollfds_ptr, nfds, timeout_ms)
//
// Handler: crate::poll::sys_poll. nfds==0 is legal (sleep-for-timeout),
// returns 0 immediately when timeout<=0. A null pollfd ptr with nfds>0
// fails through parse_pollfds → the -1 sentinel.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_poll_pos() -> TestResult {
    with_setup(|| {
        // poll(NULL, 0, 0): empty set, non-blocking → 0 ready.
        match call(Syscall::Poll.raw(), a2(0, 0, 0)) {
            Some(0) => Ok(()),
            other => {
                let _ = other;
                Err("poll(NULL,0,0) should return 0")
            }
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_poll_pos);

fn smoke_abi_async_poll_neg() -> TestResult {
    with_setup(|| {
        // poll(NULL, 1, 0): nfds>0 with a null array pointer → parse fails.
        // LINUX-GAP: Linux returns -EFAULT here; NARF returns the -1 sentinel.
        match call(Syscall::Poll.raw(), a2(0, 1, 0)) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("poll(NULL,1,0) must fail"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_poll_neg);

/// `poll(2)` must refuse a kernel-half `pollfd*` — it was an unprivileged
/// arbitrary kernel write.
///
/// `poll_common` took `args.arg0` straight to `parse_pollfds` /
/// `write_pollfds` on a `// SAFETY: user pointer in the active AS` comment that
/// nothing enforced. Both open a SMAP bracket, so with `EFLAGS.AC` set a
/// `CPL=0` access to a kernel page succeeds *silently* — SMAP only guards
/// `PTE.U=1`. That made the parse an arbitrary kernel read and `revents` —
/// two bytes at `ptr + i*8 + 6`, once per entry — an arbitrary kernel write.
///
/// Worse than the `bpf(2)` gadget of the same class, which needs euid 0:
/// `poll(2)` and `ppoll(2)` take no credential at all.
///
/// `with_setup_strict`, not `with_setup`: the ordinary harness holds the
/// kernel-buffers guard so its tests can hand kernel pointers to syscalls, and
/// under it this test would pass no matter what the code did.
fn smoke_abi_async_poll_kernel_ptr_neg() -> TestResult {
    with_setup_strict(|| {
        // A canonical kernel-half address. Never dereferenced: the point is
        // that validation rejects it before anything touches it.
        const KERNEL_PTR: u64 = 0xFFFF_8000_0000_0000;
        if call(Syscall::Poll.raw(), a2(KERNEL_PTR, 1, 0)) != Some(EFAULT) {
            return Err("poll() with a kernel-half pollfd array was not EFAULT");
        }
        // The last byte matters as much as the first: a base one entry below
        // the boundary whose array crosses it must go too.
        const NEAR_TOP: u64 = (1u64 << 47) - 8;
        if call(Syscall::Poll.raw(), a2(NEAR_TOP, 4, 0)) != Some(EFAULT) {
            return Err("poll() with an array crossing out of the user half was not EFAULT");
        }
        // ppoll(2) shares `poll_common`, so it inherits the check. Four args
        // is all the harness carries and all this needs: sigsetsize (arg4) is
        // only consulted when sigmask (arg3) is non-null.
        if call(Syscall::Ppoll.raw(), a3(KERNEL_PTR, 1, 0, 0)) != Some(EFAULT) {
            return Err("ppoll() with a kernel-half pollfd array was not EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_poll_kernel_ptr_neg);

// ════════════════════════════════════════════════════════════════════
// ppoll(2) — sys_ppoll(fds, nfds, timespec*, sigmask, sigsetsize)
//
// timespec NULL (arg2==0) → block-forever timeout, but nfds==0 returns 0
// at once (poll_common's empty-set fast path).
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_ppoll_pos() -> TestResult {
    with_setup(|| {
        // ppoll(NULL, 0, NULL, NULL, 0): empty set → 0.
        match call(Syscall::Ppoll.raw(), a3(0, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("ppoll(NULL,0,NULL,..) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_ppoll_pos);

fn smoke_abi_async_ppoll_neg() -> TestResult {
    with_setup(|| {
        // ppoll(NULL, 1, NULL, ..): null fds array with nfds>0 → fail.
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        match call(Syscall::Ppoll.raw(), a3(0, 1, 0, 0)) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("ppoll(NULL,1,NULL,..) must fail"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_ppoll_neg);

// ════════════════════════════════════════════════════════════════════
// select(2) — sys_select(nfds, rfds, wfds, efds, timeval*)
//
// An empty set with a zero timeout returns immediately. A null timeout is an
// interruptible infinite wait and is covered by the stackful userspace tests.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_select_pos() -> TestResult {
    with_setup(|| {
        let tv = [0i64, 0];
        let mut args = a3(0, 0, 0, 0);
        args.arg4 = tv.as_ptr() as u64;
        match call(Syscall::Select.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("select(0,NULL...,{0,0}) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_select_pos);

fn smoke_abi_async_select_neg() -> TestResult {
    with_setup(|| {
        // select(-1, ..): negative nfds → -EINVAL.
        match call(Syscall::Select.raw(), a3(u64::from(u32::MAX), 0, 0, 0)) {
            Some(EINVAL) => Ok(()),
            _ => Err("select(nfds<0) must return EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_select_neg);

// ════════════════════════════════════════════════════════════════════
// pselect6(2) — sys_pselect6(nfds, rfds, wfds, efds, timespec*, sigmask)
//
// Same shape as select with a timespec. Negative nfds is EINVAL.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_pselect6_pos() -> TestResult {
    with_setup(|| {
        let ts = [0i64, 0];
        let mut args = a3(0, 0, 0, 0);
        args.arg4 = ts.as_ptr() as u64;
        match call(Syscall::Pselect6.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("pselect6(0,NULL...,{0,0},NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_pselect6_pos);

fn smoke_abi_async_pselect6_neg() -> TestResult {
    with_setup(|| {
        // pselect6(-1, ..): negative nfds → -EINVAL.
        match call(Syscall::Pselect6.raw(), a3(u64::from(u32::MAX), 0, 0, 0)) {
            Some(EINVAL) => Ok(()),
            _ => Err("pselect6(nfds<0) must return EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_pselect6_neg);

// ════════════════════════════════════════════════════════════════════
// epoll_create1(2) — sys_epoll_create1(flags)
//
// Allocates an EpollInstance + installs a fresh fd. No reachable error
// path in the harness (EMFILE would need an exhausted fd table), so this
// is positive-only.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_epoll_create_pos() -> TestResult {
    with_setup(|| {
        // epoll_create1(0) → a non-negative fd.
        match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("epoll_create1(0) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_create_pos);

fn smoke_abi_async_epoll_create_cloexec() -> TestResult {
    with_setup(|| {
        // epoll_create1(O_CLOEXEC) also yields a valid fd (flag accepted).
        match call(Syscall::EpollCreate.raw(), a0(crate::fd::O_CLOEXEC as u64)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("epoll_create1(O_CLOEXEC) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_create_cloexec);

// ════════════════════════════════════════════════════════════════════
// epoll_ctl(2) — sys_epoll_ctl(epfd, op, fd, epoll_event*)
//
// EPOLL_CTL_ADD resolves and retains the target open-file description.
// A bad epfd or target fd fails.
// ════════════════════════════════════════════════════════════════════

const EPOLL_CTL_ADD: u64 = 1;

fn smoke_abi_async_epoll_ctl_pos() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        let target_fd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("target epoll_create1 failed"),
        };
        // struct epoll_event { u32 events; u64 data; } — read as 12 bytes.
        let mut ev = [0u8; 12];
        ev[0..4].copy_from_slice(&(0x1u32).to_ne_bytes()); // EPOLLIN
        let args = a3(epfd, EPOLL_CTL_ADD, target_fd, ev.as_ptr() as u64);
        match call(Syscall::EpollCtl.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("epoll_ctl(ADD) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_ctl_pos);

fn smoke_abi_async_epoll_ctl_close_reuse() -> TestResult {
    with_setup(|| {
        let epfd = call(Syscall::EpollCreate.raw(), a0(0))
            .filter(|fd| *fd >= 0)
            .ok_or("epoll_create1 failed")? as u64;
        let old_fd = call(
            Syscall::Signalfd.raw(),
            a3((-1i64) as u64, 0, 8, crate::fd::O_CLOEXEC as u64),
        )
        .filter(|fd| *fd >= 0)
        .ok_or("first signalfd failed")? as u64;
        let mut ev = [0u8; 12];
        ev[0..4].copy_from_slice(&0x1u32.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd, EPOLL_CTL_ADD, old_fd, ev.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("initial epoll_ctl(ADD signalfd) failed");
        }
        if call(Syscall::Close.raw(), a0(old_fd)) != Some(0) {
            return Err("close of watched signalfd failed");
        }
        let new_fd = call(
            Syscall::Signalfd.raw(),
            a3((-1i64) as u64, 0, 8, crate::fd::O_CLOEXEC as u64),
        )
        .filter(|fd| *fd >= 0)
        .ok_or("replacement signalfd failed")? as u64;
        if new_fd != old_fd {
            return Err("closed descriptor number was not reused");
        }
        match call(
            Syscall::EpollCtl.raw(),
            a3(epfd, EPOLL_CTL_ADD, new_fd, ev.as_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("stale epoll interest rejected a reused descriptor"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_ctl_close_reuse);

fn smoke_abi_async_epoll_ctl_neg() -> TestResult {
    with_setup(|| {
        let mut ev = [0u8; 12];
        ev[0..4].copy_from_slice(&(0x1u32).to_ne_bytes());
        // epoll_ctl on an epfd that was never created → fail.
        // LINUX-GAP: Linux returns -EBADF; NARF returns the -1 sentinel.
        let args = a3(999, EPOLL_CTL_ADD, 5, ev.as_ptr() as u64);
        match call(Syscall::EpollCtl.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("epoll_ctl on bad epfd must fail"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_ctl_neg);

// ════════════════════════════════════════════════════════════════════
// epoll_wait(2) — sys_epoll_wait(epfd, events, maxevents, timeout)
//
// With no live user task (the harness has none), epoll_wait can't park —
// it does one non-blocking readiness pass. An empty instance → 0.
// Null events ptr OR maxevents==0 → the -1 sentinel.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_epoll_wait_pos() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        // events buffer (one struct epoll_event), maxevents=1, timeout=0.
        let mut evbuf = [0u8; 12];
        let args = a3(epfd, evbuf.as_mut_ptr() as u64, 1, 0);
        match call(Syscall::EpollWait.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("epoll_wait on empty set should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_wait_pos);

fn smoke_abi_async_epoll_wait_neg() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        // Null events pointer → fail.
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        let args = a3(epfd, 0, 1, 0);
        match call(Syscall::EpollWait.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("epoll_wait(NULL events) must fail"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_wait_neg);

// ════════════════════════════════════════════════════════════════════
// epoll_pwait(2) — wired to sys_epoll_pwait so the temporary signal mask is
// validated, installed for the wait, and restored before return.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_epoll_pwait_pos() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        let mut evbuf = [0u8; 12];
        // epoll_pwait(epfd, events, 1, 0, NULL, 0).
        let args = SyscallArgs {
            arg0: epfd,
            arg1: evbuf.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        };
        match call(Syscall::EpollPwait.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("epoll_pwait on empty set should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_pwait_pos);

fn smoke_abi_async_epoll_pwait_neg() -> TestResult {
    with_setup(|| {
        // Bad epfd (never created) with a valid events buffer → fail.
        // LINUX-GAP: Linux returns -EBADF; NARF returns the -1 sentinel.
        let mut evbuf = [0u8; 12];
        let args = a3(999, evbuf.as_mut_ptr() as u64, 1, 0);
        match call(Syscall::EpollPwait.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("epoll_pwait on bad epfd must fail"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_pwait_neg);

/// The syscall table must route epoll_pwait through the pwait-aware wrapper,
/// not plain epoll_wait. A bad non-null sigmask pointer is a deterministic
/// discriminator: epoll_pwait must inspect it and fail, while epoll_wait would
/// ignore arg4/arg5 and incorrectly report the empty instance as ready with
/// zero events.
fn smoke_abi_async_epoll_pwait_validates_sigmask() -> TestResult {
    with_setup(|| {
        const BAD_PTR: u64 = 0x0001_0000_0000_0000;
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        let mut evbuf = [0u8; 12];
        let args = SyscallArgs {
            arg0: epfd,
            arg1: evbuf.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            arg4: BAD_PTR,
            arg5: 8,
        };
        match call(Syscall::EpollPwait.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("epoll_pwait ignored its non-null signal-mask argument"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_epoll_pwait_validates_sigmask
);

// ════════════════════════════════════════════════════════════════════
// epoll_pwait2(2) — sys_epoll_pwait2. Like epoll_pwait but arg3 is a
// `const struct timespec *timeout` instead of an int ms. A NULL timeout
// means block-forever; in the in-kernel harness (no user task to park)
// the wait falls back to a single non-blocking readiness poll, so an
// empty set returns 0 regardless of the timeout.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_epoll_pwait2_null_timeout() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        let mut evbuf = [0u8; 12];
        // epoll_pwait2(epfd, events, 1, NULL timeout, NULL sigmask, 0):
        // NULL timeout → block forever, but the empty set is immediately
        // "ready with nothing" → 0 events.
        let args = SyscallArgs {
            arg0: epfd,
            arg1: evbuf.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0, // NULL timespec*
            arg4: 0,
            arg5: 0,
        };
        match call(Syscall::EpollPwait2.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("epoll_pwait2(NULL timeout) on empty set should return 0"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_epoll_pwait2_null_timeout
);

fn smoke_abi_async_epoll_pwait2_timespec() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        let mut evbuf = [0u8; 12];
        // A {0 sec, 1 ns} timeout: the ns remainder must round UP to a
        // 1 ms wait, not truncate to a 0-ms poll. On an empty set the
        // harness still returns 0 immediately.
        let ts: [i64; 2] = [0, 1];
        let args = SyscallArgs {
            arg0: epfd,
            arg1: evbuf.as_mut_ptr() as u64,
            arg2: 1,
            arg3: ts.as_ptr() as u64,
            arg4: 0,
            arg5: 0,
        };
        match call(Syscall::EpollPwait2.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("epoll_pwait2(1ns timeout) on empty set should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_pwait2_timespec);

fn smoke_abi_async_epoll_pwait2_neg() -> TestResult {
    with_setup(|| {
        // Bad epfd (never created) with a valid events buffer → fail.
        // LINUX-GAP: Linux returns -EBADF; NARF returns the -1 sentinel.
        let mut evbuf = [0u8; 12];
        let args = SyscallArgs {
            arg0: 999,
            arg1: evbuf.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0, // NULL timeout
            arg4: 0,
            arg5: 0,
        };
        match call(Syscall::EpollPwait2.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("epoll_pwait2 on bad epfd must fail"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_epoll_pwait2_neg);

// ════════════════════════════════════════════════════════════════════
// futex(2) — sys_futex(uaddr, op, val, timeout, uaddr2, val3)
//
// kernel/futex/syscalls.c::do_futex. The errno is the whole interface
// here: EAGAIN says "the word moved, re-read it", ETIMEDOUT says "the
// deadline won", EINVAL says "this request is malformed", ENOSYS says
// "fall back to the older op". The bare -1 sentinel arrived at libc as
// EPERM, which no mutex/condvar fast path has a rule for.
//
// Order matters as much as the value: Linux decodes the timespec in the
// syscall wrapper (EFAULT/EINVAL), then rejects FUTEX_CLOCK_REALTIME on
// a non-absolute op (ENOSYS), then an empty bitset (EINVAL), and only
// then keys the address (EINVAL misaligned / EFAULT unreadable) and
// compares the word (EAGAIN).
// ════════════════════════════════════════════════════════════════════

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE: u64 = 0x80;
const FUTEX_CLOCK_REALTIME: u64 = 0x100;
const FUTEX_BITSET_MATCH_ANY: u64 = 0xffff_ffff;
// futex2 `flags`: FUTEX2_SIZE_U32 is the only access width Linux
// implements (`futex_flags_valid`), FUTEX2_PRIVATE aliases
// FUTEX_PRIVATE_FLAG, and 0x10 is outside FUTEX2_VALID_MASK (0x8f).
const FUTEX2_SIZE_U32: u64 = 0x02;
const FUTEX2_SIZE_U64: u64 = 0x03;
const FUTEX2_BAD_BIT: u64 = 0x10;
// Not in the shared errno table.
const ETIMEDOUT: i64 = -110;
// A canonical-hole pointer: 8-byte aligned (so it clears the futex
// alignment gate) but unmapped, which is what makes it an EFAULT probe.
const FUTEX_BAD_PTR: u64 = 0x0001_0000_0000_0000;

fn futex6(uaddr: u64, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> Option<i64> {
    call(
        Syscall::Futex.raw(),
        SyscallArgs {
            arg0: uaddr,
            arg1: op,
            arg2: val,
            arg3: timeout,
            arg4: uaddr2,
            arg5: val3,
        },
    )
}

fn smoke_abi_async_futex_pos() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        // futex(&word, FUTEX_WAKE, 1, 0): no waiters parked → 0 woken.
        let args = a3(&word as *const u32 as u64, FUTEX_WAKE, 1, 0);
        match call(Syscall::Futex.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("futex(FUTEX_WAKE) with no waiters should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_pos);

fn smoke_abi_async_classic_futex_wait_stale_eagain() -> TestResult {
    with_setup(|| {
        let word: u32 = 7;
        let args = a3(&word as *const u32 as u64, 0, 1, 0);
        match call(Syscall::Futex.raw(), args) {
            Some(-11) => Ok(()),
            _ => Err("classic FUTEX_WAIT on a stale value must return -EAGAIN"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_async_classic_futex_wait_stale_eagain
);

fn smoke_abi_async_futex_timespec_timeout() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let expired = [0i64, 0i64];
        let args = a3(
            &word as *const u32 as u64,
            FUTEX_WAIT | FUTEX_PRIVATE,
            0,
            expired.as_ptr() as u64,
        );
        if call(Syscall::Futex.raw(), args) != Some(ETIMEDOUT) {
            return Err("FUTEX_WAIT did not parse an expired relative timespec");
        }

        let invalid = [0i64, 1_000_000_000i64];
        if futex6(
            &word as *const u32 as u64,
            FUTEX_WAIT_BITSET | FUTEX_PRIVATE,
            0,
            invalid.as_ptr() as u64,
            0,
            FUTEX_BITSET_MATCH_ANY,
        ) != Some(EINVAL)
        {
            return Err("FUTEX_WAIT_BITSET accepted an invalid timespec");
        }
        // The timespec is decoded in SYSCALL_DEFINE6(futex), BEFORE
        // do_futex sees the op: an invalid timespec beats the -ENOSYS
        // that FUTEX_CLOCK_REALTIME|FUTEX_WAIT would otherwise get.
        if futex6(
            &word as *const u32 as u64,
            FUTEX_WAIT | FUTEX_CLOCK_REALTIME,
            0,
            invalid.as_ptr() as u64,
            0,
            0,
        ) != Some(EINVAL)
        {
            return Err("a bad timespec must outrank the CLOCK_REALTIME -ENOSYS");
        }
        // A faulting timespec pointer is -EFAULT, not -EINVAL.
        if futex6(
            &word as *const u32 as u64,
            FUTEX_WAIT | FUTEX_PRIVATE,
            0,
            FUTEX_BAD_PTR,
            0,
            0,
        ) != Some(EFAULT)
        {
            return Err("FUTEX_WAIT with a faulting timespec must return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_timespec_timeout);

fn smoke_abi_async_futex_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        // `do_futex` falls off the end of its switch with -ENOSYS. That is
        // the word a libc probe looks for before falling back to an older
        // op; as EPERM it read as "you are not allowed to lock".
        let args = a3(&word as *const u32 as u64, 99, 0, 0);
        match call(Syscall::Futex.raw(), args) {
            Some(v) if v == ENOSYS => Ok(()),
            _ => Err("futex(unknown op) must return -ENOSYS"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_neg);

fn smoke_abi_async_futex_clockrt_enosys() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let p = &word as *const u32 as u64;
        // do_futex: `if (flags & FLAGS_CLOCKRT) { if (cmd != FUTEX_WAIT_BITSET
        // && cmd != FUTEX_WAIT_REQUEUE_PI && cmd != FUTEX_LOCK_PI2)
        // return -ENOSYS; }` — the bit is only defined for the ops that take
        // an ABSOLUTE deadline.
        if futex6(p, FUTEX_WAKE | FUTEX_CLOCK_REALTIME, 1, 0, 0, 0) != Some(ENOSYS) {
            return Err("FUTEX_WAKE|FUTEX_CLOCK_REALTIME must return -ENOSYS");
        }
        if futex6(p, FUTEX_WAIT | FUTEX_CLOCK_REALTIME, 0, 0, 0, 0) != Some(ENOSYS) {
            return Err("FUTEX_WAIT|FUTEX_CLOCK_REALTIME must return -ENOSYS");
        }
        // FUTEX_WAIT_BITSET is on the allowed list, so the bit must NOT
        // turn a legitimate call into ENOSYS: it falls through to the
        // stale-value EAGAIN instead.
        let stale: u32 = 7;
        if futex6(
            &stale as *const u32 as u64,
            FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME,
            1,
            0,
            0,
            FUTEX_BITSET_MATCH_ANY,
        ) != Some(EAGAIN)
        {
            return Err("FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME must still be honoured");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_clockrt_enosys);

fn smoke_abi_async_futex_bitset_zero_einval() -> TestResult {
    with_setup(|| {
        // `futex_wake()` and `__futex_wait()` both open with
        // `if (!bitset) return -EINVAL;` — BEFORE get_futex_key, so the
        // empty bitset outranks even a stale word value.
        let stale: u32 = 7;
        let p = &stale as *const u32 as u64;
        if futex6(p, FUTEX_WAIT_BITSET, 1, 0, 0, 0) != Some(EINVAL) {
            return Err("FUTEX_WAIT_BITSET with an empty bitset must return -EINVAL");
        }
        if futex6(p, FUTEX_WAKE_BITSET, 1, 0, 0, 0) != Some(EINVAL) {
            return Err("FUTEX_WAKE_BITSET with an empty bitset must return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_futex_bitset_zero_einval
);

fn smoke_abi_async_futex_bitset_match_any_pos() -> TestResult {
    with_setup(|| {
        // The positive side of the bitset gate: FUTEX_BITSET_MATCH_ANY (what
        // glibc and musl actually pass) must sail through to the normal
        // wake/compare paths.
        let stale: u32 = 7;
        let p = &stale as *const u32 as u64;
        if futex6(p, FUTEX_WAKE_BITSET, 1, 0, 0, FUTEX_BITSET_MATCH_ANY) != Some(0) {
            return Err("FUTEX_WAKE_BITSET with MATCH_ANY should wake 0 and succeed");
        }
        if futex6(p, FUTEX_WAIT_BITSET, 1, 0, 0, FUTEX_BITSET_MATCH_ANY) != Some(EAGAIN) {
            return Err("FUTEX_WAIT_BITSET with MATCH_ANY should reach the stale-value EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_futex_bitset_match_any_pos
);

fn smoke_abi_async_futex_misaligned_einval() -> TestResult {
    with_setup(|| {
        // get_futex_key(): "The futex address must be naturally aligned" —
        // `if (unlikely((address % size) != 0)) return -EINVAL;`, checked
        // BEFORE access_ok's -EFAULT. A caller whose lock struct is laid
        // out wrong must be able to tell that apart from a vanished page.
        let word: u32 = 0;
        let skewed = (&word as *const u32 as u64) + 1;
        if futex6(skewed, FUTEX_WAKE, 1, 0, 0, 0) != Some(EINVAL) {
            return Err("FUTEX_WAKE on a misaligned word must return -EINVAL");
        }
        if futex6(skewed, FUTEX_WAIT, 0, 0, 0, 0) != Some(EINVAL) {
            return Err("FUTEX_WAIT on a misaligned word must return -EINVAL");
        }
        let dst: u32 = 0;
        if futex6(
            skewed,
            FUTEX_CMP_REQUEUE,
            0,
            0,
            &dst as *const u32 as u64,
            0,
        ) != Some(EINVAL)
        {
            return Err("FUTEX_CMP_REQUEUE on a misaligned source must return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_misaligned_einval);

fn smoke_abi_async_futex_wait_fault_efault() -> TestResult {
    with_setup(|| {
        // futex_wait_setup() re-reads the word with get_user() and returns
        // its -EFAULT. A caller whose lock page was reclaimed can fault it
        // back in and retry; EPERM told it to give up instead.
        if futex6(FUTEX_BAD_PTR, FUTEX_WAIT, 0, 0, 0, 0) != Some(EFAULT) {
            return Err("FUTEX_WAIT on an unreadable word must return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wait_fault_efault);

fn smoke_abi_async_futex_requeue_negative_einval() -> TestResult {
    with_setup(|| {
        // futex_requeue(): `if (nr_wake < 0 || nr_requeue < 0) return -EINVAL;`
        // — both counts are `int`, and it is the first thing checked.
        let src: u32 = 0;
        let dst: u32 = 0;
        let sp = &src as *const u32 as u64;
        let dp = &dst as *const u32 as u64;
        let neg = (-1i32) as u32 as u64;
        if futex6(sp, FUTEX_CMP_REQUEUE, neg, 0, dp, 0) != Some(EINVAL) {
            return Err("FUTEX_CMP_REQUEUE with nr_wake<0 must return -EINVAL");
        }
        if futex6(sp, FUTEX_CMP_REQUEUE, 0, neg, dp, 0) != Some(EINVAL) {
            return Err("FUTEX_CMP_REQUEUE with nr_requeue<0 must return -EINVAL");
        }
        // Positive control: legal counts still reach the *uaddr == val3
        // compare and succeed.
        if futex6(sp, FUTEX_CMP_REQUEUE, 1, 1, dp, 0) != Some(0) {
            return Err("FUTEX_CMP_REQUEUE with legal counts should succeed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_futex_requeue_negative_einval
);

fn smoke_abi_async_futex_op_upper_bits_pos() -> TestResult {
    with_setup(|| {
        // Linux declares the op as `int`, so only the low 32 bits reach
        // do_futex. A caller that left junk in the upper half of the
        // register (a sign-extended int in a hand-written stub) must still
        // get FUTEX_WAKE, not the unknown-op -ENOSYS.
        let word: u32 = 0;
        let op = 0xFFFF_FFFF_0000_0000u64 | FUTEX_WAKE;
        match futex6(&word as *const u32 as u64, op, 1, 0, 0, 0) {
            Some(0) => Ok(()),
            _ => Err("futex op must be decoded from its low 32 bits only"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_op_upper_bits_pos);

// ════════════════════════════════════════════════════════════════════
// futex_wake(2) [futex2] — sys_futex_wake(uaddr, mask, nr, flags)
//
// kernel/futex/syscalls.c::SYSCALL_DEFINE4(futex_wake): flags outside
// FUTEX2_VALID_MASK → EINVAL, an access width other than FUTEX2_SIZE_U32
// → EINVAL, an empty mask → EINVAL, a misaligned uaddr → EINVAL, and
// `nr == 0` → 0 (FLAGS_STRICT makes it a legal no-op).
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_futex_wake_pos() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        // futex_wake(&word, mask=MATCH_ANY, nr=1, FUTEX2_SIZE_U32) → 1.
        let args = a3(
            &word as *const u32 as u64,
            FUTEX_BITSET_MATCH_ANY,
            1,
            FUTEX2_SIZE_U32,
        );
        match call(Syscall::FutexWake.raw(), args) {
            Some(1) => Ok(()),
            _ => Err("futex_wake(nr=1) should return 1"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wake_pos);

fn smoke_abi_async_futex_wake_null() -> TestResult {
    with_setup(|| {
        // futex_wake(NULL, ..): a valid-but-empty key wakes nobody → 0.
        let args = a3(0, FUTEX_BITSET_MATCH_ANY, 5, FUTEX2_SIZE_U32);
        match call(Syscall::FutexWake.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("futex_wake(NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wake_null);

fn smoke_abi_async_futex_wake_zero_nr_pos() -> TestResult {
    with_setup(|| {
        // `if ((flags & FLAGS_STRICT) && !nr_wake) return 0;` — futex2 sets
        // FLAGS_STRICT, so a zero count is a success, not an error.
        let word: u32 = 0;
        let args = a3(
            &word as *const u32 as u64,
            FUTEX_BITSET_MATCH_ANY,
            0,
            FUTEX2_SIZE_U32,
        );
        match call(Syscall::FutexWake.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("futex_wake(nr=0) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wake_zero_nr_pos);

fn smoke_abi_async_futex_wake_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let p = &word as *const u32 as u64;
        // A flag bit outside FUTEX2_VALID_MASK (0x8f).
        if call(
            Syscall::FutexWake.raw(),
            a3(p, FUTEX_BITSET_MATCH_ANY, 1, FUTEX2_BAD_BIT),
        ) != Some(EINVAL)
        {
            return Err("futex_wake with an unknown flag bit must return -EINVAL");
        }
        // futex_flags_valid(): "Only 32bit futexes are implemented". A
        // silently-accepted 64-bit width would compare half a word.
        if call(
            Syscall::FutexWake.raw(),
            a3(p, FUTEX_BITSET_MATCH_ANY, 1, FUTEX2_SIZE_U64),
        ) != Some(EINVAL)
        {
            return Err("futex_wake with FUTEX2_SIZE_U64 must return -EINVAL");
        }
        // futex_wake(): `if (!bitset) return -EINVAL;`
        if call(Syscall::FutexWake.raw(), a3(p, 0, 1, FUTEX2_SIZE_U32)) != Some(EINVAL) {
            return Err("futex_wake with an empty mask must return -EINVAL");
        }
        // get_futex_key(): misaligned is EINVAL, not EFAULT.
        if call(
            Syscall::FutexWake.raw(),
            a3(p + 1, FUTEX_BITSET_MATCH_ANY, 1, FUTEX2_SIZE_U32),
        ) != Some(EINVAL)
        {
            return Err("futex_wake on a misaligned word must return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wake_neg);

// ════════════════════════════════════════════════════════════════════
// futex_wait(2) [futex2] — sys_futex_wait(uaddr, val, mask, flags,
// timeout, clockid)
//
// kernel/futex/syscalls.c::SYSCALL_DEFINE6(futex_wait), in order: flags
// → futex_validate_input(val) → futex2_setup_timeout (bad clockid
// EINVAL, then the timespec) → empty mask EINVAL → alignment EINVAL →
// fault EFAULT → stale value EAGAIN.
// ════════════════════════════════════════════════════════════════════

fn futex2_wait(uaddr: u64, val: u64, mask: u64, flags: u64, to: u64, clk: u64) -> Option<i64> {
    call(
        Syscall::FutexWait.raw(),
        SyscallArgs {
            arg0: uaddr,
            arg1: val,
            arg2: mask,
            arg3: flags,
            arg4: to,
            arg5: clk,
        },
    )
}

fn smoke_abi_async_futex_wait_pos() -> TestResult {
    with_setup(|| {
        // futex_wait(NULL, 0): null uaddr → immediate spurious wake (0).
        if futex2_wait(0, 0, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0, 0) != Some(0) {
            return Err("futex_wait(NULL) should return 0");
        }
        // A matching value parks; the harness has no task to park, so the
        // match branch falls through to a synchronous 0. This is the
        // positive control for every EINVAL gate above it.
        let word: u32 = 0xAAAA;
        if futex2_wait(
            &word as *const u32 as u64,
            0xAAAA,
            FUTEX_BITSET_MATCH_ANY,
            FUTEX2_SIZE_U32,
            0,
            0,
        ) != Some(0)
        {
            return Err("futex_wait on a matching value should park (0)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wait_pos);

fn smoke_abi_async_futex_wait_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 7;
        let p = &word as *const u32 as u64;
        // futex_wait(&word, val=1) where *word(7) != 1 → -EAGAIN. This is
        // the retry signal a pthread mutex fast path branches on.
        if futex2_wait(p, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0, 0) != Some(EAGAIN) {
            return Err("futex_wait on a stale value must return -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wait_neg);

fn smoke_abi_async_futex_wait_flags_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 7;
        let p = &word as *const u32 as u64;
        if futex2_wait(p, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_BAD_BIT, 0, 0) != Some(EINVAL) {
            return Err("futex_wait with an unknown flag bit must return -EINVAL");
        }
        if futex2_wait(p, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U64, 0, 0) != Some(EINVAL) {
            return Err("futex_wait with FUTEX2_SIZE_U64 must return -EINVAL");
        }
        // futex_validate_input(): an expected value wider than the futex
        // word can never compare equal — parking on it would strand the
        // caller forever, so Linux refuses it.
        if futex2_wait(p, 1u64 << 32, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0, 0) != Some(EINVAL)
        {
            return Err("futex_wait with a >32-bit val must return -EINVAL");
        }
        // futex2_setup_timeout() checks the clock id BEFORE reading the
        // timespec, so a bogus clockid is EINVAL even with a good pointer.
        let ts = [1i64, 0i64];
        if futex2_wait(
            p,
            1,
            FUTEX_BITSET_MATCH_ANY,
            FUTEX2_SIZE_U32,
            ts.as_ptr() as u64,
            99,
        ) != Some(EINVAL)
        {
            return Err("futex_wait with a bad clockid must return -EINVAL");
        }
        // …and a faulting timespec with a good clockid is EFAULT.
        if futex2_wait(
            p,
            1,
            FUTEX_BITSET_MATCH_ANY,
            FUTEX2_SIZE_U32,
            FUTEX_BAD_PTR,
            0,
        ) != Some(EFAULT)
        {
            return Err("futex_wait with a faulting timespec must return -EFAULT");
        }
        // __futex_wait(): `if (!bitset) return -EINVAL;` outranks the
        // stale-value EAGAIN this call would otherwise get.
        if futex2_wait(p, 1, 0, FUTEX2_SIZE_U32, 0, 0) != Some(EINVAL) {
            return Err("futex_wait with an empty mask must return -EINVAL");
        }
        // …and the alignment gate outranks it too.
        if futex2_wait(p + 1, 1, FUTEX_BITSET_MATCH_ANY, FUTEX2_SIZE_U32, 0, 0) != Some(EINVAL) {
            return Err("futex_wait on a misaligned word must return -EINVAL");
        }
        // An already-expired absolute deadline is -ETIMEDOUT, not a park.
        if futex2_wait(
            p,
            7,
            FUTEX_BITSET_MATCH_ANY,
            FUTEX2_SIZE_U32,
            [0i64, 0i64].as_ptr() as u64,
            1,
        ) != Some(ETIMEDOUT)
        {
            return Err("futex_wait with an expired deadline must return -ETIMEDOUT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_wait_flags_neg);

// ════════════════════════════════════════════════════════════════════
// futex_requeue(2) [futex2] — sys_futex_requeue(waiters, flags, nr_wake,
// nr_requeue)
//
// `waiters` points at two `struct futex_waitv` (24B each): [0] source,
// [1] destination. kernel/futex/syscalls.c::SYSCALL_DEFINE4(futex_requeue)
// rejects a non-zero syscall-level `flags`, a null array, a malformed
// entry, mismatched entry flags, and a negative count — each -EINVAL —
// before it wakes anything.
// ════════════════════════════════════════════════════════════════════

/// Build a two-entry `futex_waitv` array: `{ u64 val; u64 uaddr; u32
/// flags; u32 __reserved; }`.
fn waitv_pair(src: u64, dst: u64, src_flags: u64, dst_flags: u64) -> [u8; 48] {
    let mut w = [0u8; 48];
    w[8..16].copy_from_slice(&src.to_ne_bytes());
    w[16..20].copy_from_slice(&(src_flags as u32).to_ne_bytes());
    w[32..40].copy_from_slice(&dst.to_ne_bytes());
    w[40..44].copy_from_slice(&(dst_flags as u32).to_ne_bytes());
    w
}

fn smoke_abi_async_futex_requeue_pos() -> TestResult {
    with_setup(|| {
        let src: u32 = 0;
        let dst: u32 = 0;
        let waitv = waitv_pair(
            &src as *const u32 as u64,
            &dst as *const u32 as u64,
            FUTEX2_SIZE_U32,
            FUTEX2_SIZE_U32,
        );
        // futex_requeue(waiters, flags=0, nr_wake=1, nr_requeue=0) → 1.
        let args = a3(waitv.as_ptr() as u64, 0, 1, 0);
        match call(Syscall::FutexRequeue.raw(), args) {
            Some(1) => Ok(()),
            _ => Err("futex_requeue(nr_wake=1) should return 1"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_requeue_pos);

fn smoke_abi_async_futex_requeue_null() -> TestResult {
    with_setup(|| {
        // `if (!waiters) return -EINVAL;` — a null array is malformed, not
        // a no-op that still claims nr_wake waiters were released. musl's
        // pthread_cond_broadcast reads a non-error as "handoff done" and
        // leaves the next waiter parked forever.
        let args = a3(0, 0, 2, 0);
        match call(Syscall::FutexRequeue.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("futex_requeue(NULL) must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_requeue_null);

fn smoke_abi_async_futex_requeue_neg() -> TestResult {
    with_setup(|| {
        let src: u32 = 0;
        let dst: u32 = 0;
        let sp = &src as *const u32 as u64;
        let dp = &dst as *const u32 as u64;
        let ok = waitv_pair(sp, dp, FUTEX2_SIZE_U32, FUTEX2_SIZE_U32);
        // "This syscall supports no flags for now": `if (flags) return -EINVAL;`
        if call(Syscall::FutexRequeue.raw(), a3(ok.as_ptr() as u64, 1, 1, 0)) != Some(EINVAL) {
            return Err("futex_requeue with a non-zero flags word must return -EINVAL");
        }
        // futex_parse_waitv(): a faulting array is -EFAULT.
        if call(Syscall::FutexRequeue.raw(), a3(FUTEX_BAD_PTR, 0, 1, 0)) != Some(EFAULT) {
            return Err("futex_requeue with a faulting array must return -EFAULT");
        }
        // futex_parse_waitv(): per-entry flags are validated too.
        let bad_entry = waitv_pair(sp, dp, FUTEX2_BAD_BIT, FUTEX2_BAD_BIT);
        if call(
            Syscall::FutexRequeue.raw(),
            a3(bad_entry.as_ptr() as u64, 0, 1, 0),
        ) != Some(EINVAL)
        {
            return Err("futex_requeue with a bad entry flag must return -EINVAL");
        }
        // "For now mandate both flags are identical".
        let mismatch = waitv_pair(sp, dp, FUTEX2_SIZE_U32, FUTEX2_SIZE_U32 | 0x80);
        if call(
            Syscall::FutexRequeue.raw(),
            a3(mismatch.as_ptr() as u64, 0, 1, 0),
        ) != Some(EINVAL)
        {
            return Err("futex_requeue with mismatched entry flags must return -EINVAL");
        }
        // `__reserved` must be zero — it is how futex2 grows.
        let mut reserved = ok;
        reserved[20..24].copy_from_slice(&1u32.to_ne_bytes());
        if call(
            Syscall::FutexRequeue.raw(),
            a3(reserved.as_ptr() as u64, 0, 1, 0),
        ) != Some(EINVAL)
        {
            return Err("futex_requeue with a non-zero __reserved must return -EINVAL");
        }
        // futex_requeue(): `if (nr_wake < 0 || nr_requeue < 0) return -EINVAL;`
        let neg = (-1i32) as u32 as u64;
        if call(
            Syscall::FutexRequeue.raw(),
            a3(ok.as_ptr() as u64, 0, neg, 0),
        ) != Some(EINVAL)
        {
            return Err("futex_requeue with nr_wake<0 must return -EINVAL");
        }
        if call(
            Syscall::FutexRequeue.raw(),
            a3(ok.as_ptr() as u64, 0, 1, neg),
        ) != Some(EINVAL)
        {
            return Err("futex_requeue with nr_requeue<0 must return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_requeue_neg);

// ════════════════════════════════════════════════════════════════════
// futex_waitv(2) [futex2] — sys_futex_waitv(waiters, nr, flags, timeout,
// clockid)
//
// kernel/futex/syscalls.c::SYSCALL_DEFINE5(futex_waitv): non-zero flags,
// nr==0, nr>FUTEX_WAITV_MAX, or a null array → EINVAL; then the timeout;
// then futex_parse_waitv validates EVERY entry (-EFAULT on a faulting
// array, -EINVAL on a malformed one) BEFORE any word is read.
// ════════════════════════════════════════════════════════════════════

/// One `struct futex_waitv` entry.
fn waitv_one(val: u64, uaddr: u64, flags: u64) -> [u8; 24] {
    let mut w = [0u8; 24];
    w[0..8].copy_from_slice(&val.to_ne_bytes());
    w[8..16].copy_from_slice(&uaddr.to_ne_bytes());
    w[16..20].copy_from_slice(&(flags as u32).to_ne_bytes());
    w
}

fn smoke_abi_async_futex_waitv_pos() -> TestResult {
    with_setup(|| {
        // One futex_waitv entry whose expected val(1) != live *uaddr(0):
        // futex_waitv reports index 0 (this word is "already woken").
        let word: u32 = 0;
        let p = &word as *const u32 as u64;
        let waitv = waitv_one(1, p, FUTEX2_SIZE_U32);
        if call(Syscall::FutexWaitv.raw(), a2(waitv.as_ptr() as u64, 1, 0)) != Some(0) {
            return Err("futex_waitv with a moved word should return index 0");
        }
        // Every word matching parks (0 in the harness) — the positive
        // control for the validation gates below.
        let matching = waitv_one(0, p, FUTEX2_SIZE_U32);
        if call(
            Syscall::FutexWaitv.raw(),
            a2(matching.as_ptr() as u64, 1, 0),
        ) != Some(0)
        {
            return Err("futex_waitv on a matching word should park (0)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_waitv_pos);

fn smoke_abi_async_futex_waitv_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        let p = &word as *const u32 as u64;
        let ok = waitv_one(1, p, FUTEX2_SIZE_U32);
        // futex_waitv(NULL, 0, ..): nr==0 (and null waiters) → -EINVAL.
        if call(Syscall::FutexWaitv.raw(), a2(0, 0, 0)) != Some(EINVAL) {
            return Err("futex_waitv(nr=0) must return -EINVAL");
        }
        // `if (nr_futexes > FUTEX_WAITV_MAX)` → -EINVAL.
        if call(Syscall::FutexWaitv.raw(), a2(ok.as_ptr() as u64, 129, 0)) != Some(EINVAL) {
            return Err("futex_waitv(nr>128) must return -EINVAL");
        }
        // "This syscall supports no flags for now" — a flags word that is
        // accepted and then ignored is the silent-divergence case.
        if call(Syscall::FutexWaitv.raw(), a2(ok.as_ptr() as u64, 1, 1)) != Some(EINVAL) {
            return Err("futex_waitv with a non-zero flags word must return -EINVAL");
        }
        // futex_parse_waitv(): a faulting array is -EFAULT, NOT -EINVAL —
        // the caller has to know whether to fix its pointer or its layout.
        if call(Syscall::FutexWaitv.raw(), a2(FUTEX_BAD_PTR, 1, 0)) != Some(EFAULT) {
            return Err("futex_waitv with a faulting array must return -EFAULT");
        }
        // Per-entry flags and __reserved.
        let bad_flags = waitv_one(1, p, FUTEX2_SIZE_U64);
        if call(
            Syscall::FutexWaitv.raw(),
            a2(bad_flags.as_ptr() as u64, 1, 0),
        ) != Some(EINVAL)
        {
            return Err("futex_waitv with FUTEX2_SIZE_U64 must return -EINVAL");
        }
        let mut reserved = ok;
        reserved[20..24].copy_from_slice(&1u32.to_ne_bytes());
        if call(
            Syscall::FutexWaitv.raw(),
            a2(reserved.as_ptr() as u64, 1, 0),
        ) != Some(EINVAL)
        {
            return Err("futex_waitv with a non-zero __reserved must return -EINVAL");
        }
        // Every entry is validated before ANY word is compared: entry 0
        // has already moved, but the malformed entry 1 still wins.
        let mut two = [0u8; 48];
        two[..24].copy_from_slice(&ok);
        two[24..].copy_from_slice(&waitv_one(0, p, FUTEX2_BAD_BIT));
        if call(Syscall::FutexWaitv.raw(), a2(two.as_ptr() as u64, 2, 0)) != Some(EINVAL) {
            return Err("futex_waitv must validate every entry before reading any word");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_futex_waitv_neg);

// ════════════════════════════════════════════════════════════════════
// set_robust_list(2) / get_robust_list(2) — kernel/futex/syscalls.c
//
// The round-trip is covered in abi_sched_tests.rs; these cover the two
// errno arms. set_robust_list's length is the ABI-version handshake:
// `if (unlikely(len != sizeof(*head))) return -EINVAL;`. get_robust_list
// writes the LENGTH first and treats that write's failure as fatal:
// `if (put_user(sizeof(*head), len_ptr)) return -EFAULT;`.
// ════════════════════════════════════════════════════════════════════

const ROBUST_LIST_HEAD_SIZE: u64 = 24;

fn smoke_abi_async_set_robust_list_len_neg() -> TestResult {
    with_setup(|| {
        // A length other than sizeof(struct robust_list_head) means the
        // caller's layout disagrees with the kernel's. Accepting it makes
        // the exit-time walk read futex_offset from the wrong offset and
        // mark the wrong words FUTEX_OWNER_DIED — silent corruption.
        for len in [0u64, 16, 23, 25, 32] {
            if call(Syscall::SetRobustList.raw(), a1(0xCAFE_1000, len)) != Some(EINVAL) {
                return Err("set_robust_list with a mismatched len must return -EINVAL");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_set_robust_list_len_neg);

fn smoke_abi_async_get_robust_list_len_pos() -> TestResult {
    with_setup(|| {
        if call(
            Syscall::SetRobustList.raw(),
            a1(0xCAFE_1000, ROBUST_LIST_HEAD_SIZE),
        ) != Some(0)
        {
            return Err("set_robust_list(len=24) should return 0");
        }
        let mut head = [0u8; 8];
        let mut len = [0u8; 8];
        let args = a3(0, head.as_mut_ptr() as u64, len.as_mut_ptr() as u64, 0);
        if call(Syscall::GetRobustList.raw(), args) != Some(0) {
            return Err("get_robust_list should return 0");
        }
        if u64::from_ne_bytes(head) != 0xCAFE_1000 {
            return Err("get_robust_list did not read back the registered head");
        }
        // Linux always reports sizeof(*head), never a stored length.
        if u64::from_ne_bytes(len) != ROBUST_LIST_HEAD_SIZE {
            return Err("get_robust_list must report sizeof(struct robust_list_head)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_get_robust_list_len_pos);

fn smoke_abi_async_get_robust_list_len_neg() -> TestResult {
    with_setup(|| {
        // The len write comes FIRST and its failure is fatal. Swallowing it
        // reported success with `len` never written, and the caller then
        // walked the robust list with an uninitialised stride.
        let mut head = [0u8; 8];
        let args = a3(0, head.as_mut_ptr() as u64, FUTEX_BAD_PTR, 0);
        match call(Syscall::GetRobustList.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("get_robust_list with a faulting len pointer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_get_robust_list_len_neg);

// ════════════════════════════════════════════════════════════════════
// inotify_init1(2) — sys_inotify_init1(flags)
//
// Always creates a group + installs an fd. No reachable error path in the
// harness (EBADF only if the fd table is exhausted), so positive-only.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_inotify_init1_pos() -> TestResult {
    with_setup(|| {
        // inotify_init1(0) → a non-negative fd.
        match call(Syscall::InotifyInit1.raw(), a0(0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("inotify_init1(0) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_init1_pos);

fn smoke_abi_async_inotify_init1_nonblock() -> TestResult {
    with_setup(|| {
        // inotify_init1(IN_NONBLOCK=0o4000) also yields a valid fd.
        match call(Syscall::InotifyInit1.raw(), a0(0o4000)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("inotify_init1(IN_NONBLOCK) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_init1_nonblock);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_async_inotify_init_legacy_alias() -> TestResult {
    with_setup(|| {
        // Linux fs/notify/inotify/inotify_user.c::inotify_init dispatches
        // exactly as inotify_init1(0). The legacy entry is x86_64-only.
        match call(Syscall::InotifyInit.raw(), SyscallArgs::default()) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("legacy inotify_init() should return an fd"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_inotify_init_legacy_alias
);

// ════════════════════════════════════════════════════════════════════
// inotify_add_watch(2) — sys_inotify_add_watch(fd, path, mask)
//
// Resolves the inotify instance from the fd, copies the NUL-terminated
// path, allocates a watch descriptor (wd >= 1). A non-inotify / bad fd →
// -EBADF.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_inotify_add_watch_pos() -> TestResult {
    with_setup(|| {
        let fd = match call(Syscall::InotifyInit1.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("inotify_init1 failed"),
        };
        // inotify_add_watch(fd, "/abi/f", IN_MODIFY=0x2) → wd >= 1.
        let path = b"/abi/f\0";
        let args = a2(fd, path.as_ptr() as u64, 0x2);
        match call(Syscall::InotifyAddWatch.raw(), args) {
            Some(wd) if wd >= 1 => Ok(()),
            _ => Err("inotify_add_watch should return wd>=1"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_add_watch_pos);

fn smoke_abi_async_inotify_add_watch_neg() -> TestResult {
    with_setup(|| {
        // fd 999 is not an inotify instance → -EBADF.
        let path = b"/abi/f\0";
        let args = a2(999, path.as_ptr() as u64, 0x2);
        match call(Syscall::InotifyAddWatch.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("inotify_add_watch on a bad fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_add_watch_neg);

// ════════════════════════════════════════════════════════════════════
// inotify_rm_watch(2) — sys_inotify_rm_watch(fd, wd)
//
// Removes a watch by descriptor (→ 0). Unknown wd → -EINVAL; bad fd →
// -EBADF.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_inotify_rm_watch_pos() -> TestResult {
    with_setup(|| {
        let fd = match call(Syscall::InotifyInit1.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("inotify_init1 failed"),
        };
        let path = b"/abi/f\0";
        let wd = match call(
            Syscall::InotifyAddWatch.raw(),
            a2(fd, path.as_ptr() as u64, 0x2),
        ) {
            Some(wd) if wd >= 1 => wd as u64,
            _ => return Err("inotify_add_watch failed"),
        };
        // inotify_rm_watch(fd, wd) → 0.
        match call(Syscall::InotifyRmWatch.raw(), a1(fd, wd)) {
            Some(0) => Ok(()),
            _ => Err("inotify_rm_watch should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_rm_watch_pos);

fn smoke_abi_async_inotify_rm_watch_neg() -> TestResult {
    with_setup(|| {
        // fd 999 is not an inotify instance → -EBADF.
        match call(Syscall::InotifyRmWatch.raw(), a1(999, 1)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("inotify_rm_watch on a bad fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_rm_watch_neg);

// ════════════════════════════════════════════════════════════════════
// inotify event delivery — a filesystem mutation on a watched directory
// (or file) queues a `struct inotify_event` that read(2) returns and
// poll(2) reports readable. These drive the real syscall handlers, so
// the notify hooks in the mutation paths fire exactly as they do for a
// userspace program (systemd/udev watching /run, /etc, cgroup dirs).
// ════════════════════════════════════════════════════════════════════

// inotify mask + open flag constants used by the delivery tests.
const IN_MODIFY: u64 = 0x0000_0002;
const IN_MOVED_FROM: u64 = 0x0000_0040;
const IN_MOVED_TO: u64 = 0x0000_0080;
const IN_CREATE: u64 = 0x0000_0100;
const IN_DELETE: u64 = 0x0000_0200;
const O_CREAT: u64 = 0o100;
const O_WRONLY: u64 = 0o1;

/// One decoded `struct inotify_event` header (16 bytes) plus its name.
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: alloc::string::String,
}

/// Decode the queued records in `buf[..n]` into events. Mirrors the
/// serialization in `mqueue::serialize_event`: 16-byte header
/// (wd,mask,cookie,len) followed by `len` NUL-padded name bytes.
fn decode_events(buf: &[u8], n: usize) -> alloc::vec::Vec<Event> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i + 16 <= n {
        let wd = i32::from_ne_bytes(buf[i..i + 4].try_into().unwrap());
        let mask = u32::from_ne_bytes(buf[i + 4..i + 8].try_into().unwrap());
        let cookie = u32::from_ne_bytes(buf[i + 8..i + 12].try_into().unwrap());
        let len = u32::from_ne_bytes(buf[i + 12..i + 16].try_into().unwrap()) as usize;
        i += 16;
        if i + len > n {
            break;
        }
        let name_bytes = &buf[i..i + len];
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(len);
        let name = alloc::string::String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        out.push(Event {
            wd,
            mask,
            cookie,
            name,
        });
        i += len;
    }
    out
}

/// Init an inotify instance and add a watch on `path` for `mask`; returns
/// (inotify_fd, wd).
fn watch(path: &[u8], mask: u64) -> Result<(u64, i32), &'static str> {
    let ifd = match call(Syscall::InotifyInit1.raw(), a0(0)) {
        Some(fd) if fd >= 0 => fd as u64,
        _ => return Err("inotify_init1 failed"),
    };
    match call(
        Syscall::InotifyAddWatch.raw(),
        a2(ifd, path.as_ptr() as u64, mask),
    ) {
        Some(wd) if wd >= 1 => Ok((ifd, wd as i32)),
        _ => Err("inotify_add_watch failed"),
    }
}

/// Drain the inotify fd once into a fresh buffer and decode the records.
fn read_events(ifd: u64) -> alloc::vec::Vec<Event> {
    let mut buf = [0u8; 512];
    let n = match call(
        Syscall::Read.raw(),
        a2(ifd, buf.as_mut_ptr() as u64, buf.len() as u64),
    ) {
        Some(n) if n > 0 => n as usize,
        _ => 0,
    };
    decode_events(&buf, n)
}

// (a) create a file in a watched dir → IN_CREATE with the child's name.
fn smoke_abi_async_inotify_fire_create() -> TestResult {
    with_memfs("/ino", "ino", &[], || {
        let (ifd, wd) = watch(b"/ino\0", IN_CREATE)?;
        // open(O_CREAT) a new child → the notify_create hook fires.
        let path = b"/ino/newf\0";
        if call_open(path.as_ptr() as u64, O_CREAT | O_WRONLY).is_none() {
            return Err("create open failed");
        }
        let evs = read_events(ifd);
        match evs.first() {
            Some(e) if e.wd == wd && e.mask & IN_CREATE as u32 != 0 && e.name == "newf" => Ok(()),
            _ => Err("expected IN_CREATE with name=newf"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_fire_create);

// (b) modify a watched file → IN_MODIFY on the watched file (no name).
fn smoke_abi_async_inotify_fire_modify() -> TestResult {
    with_memfs("/ino", "ino", &[("f", b"....")], || {
        let (ifd, wd) = watch(b"/ino/f\0", IN_MODIFY)?;
        // Open the file for writing and write → notify_modify_fd fires.
        let path = b"/ino/f\0";
        let fd = match call_open(path.as_ptr() as u64, O_WRONLY) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open for write failed"),
        };
        let data = *b"XY";
        if call(Syscall::Write.raw(), a2(fd, data.as_ptr() as u64, 2)) != Some(2) {
            return Err("write failed");
        }
        let evs = read_events(ifd);
        match evs.iter().find(|e| e.mask & IN_MODIFY as u32 != 0) {
            Some(e) if e.wd == wd && e.name.is_empty() => Ok(()),
            _ => Err("expected IN_MODIFY on the watched file"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_fire_modify);

/// A kernel-side `cgroup.events` transition must traverse the same inotify
/// queue that systemd reads.  Unlike an ordinary file write, moving a task
/// into or out of a cgroup has no syscall write path on which to emit
/// `IN_MODIFY`; cgroupfs therefore calls the filesystem modify notifier.
///
/// Exercise both edges because the populated-to-empty edge is the one a
/// `Type=forking` start job waits for after its parent process exits.
#[cfg(feature = "cgroup")]
fn smoke_abi_async_inotify_cgroup_events_modify() -> TestResult {
    with_setup(|| {
        const PID: u64 = 909_102;
        let dir = b"/sys/fs/cgroup/t_ino_events\0";
        let events = b"/sys/fs/cgroup/t_ino_events/cgroup.events\0";

        // A filesystem-only test may have installed its observation callback
        // earlier in the shared kernel-test image. Restore the production
        // userspace bridge so this test covers actual inotify delivery.
        narf_filesystem::set_modify_notifier(crate::mqueue::notify_modify_path);

        narf_filesystem::cgroupfs::task_exited(PID);
        let _ = call_rmdir(dir.as_ptr() as u64);
        if call_mkdir(dir.as_ptr() as u64, 0o755) != Some(0) {
            return Err("mkdir of inotify test cgroup failed");
        }

        let outcome = (|| {
            let (ifd, wd) = watch(events, IN_MODIFY)?;

            narf_filesystem::cgroupfs::attach_by_path("/t_ino_events", PID)
                .map_err(|_| "attaching pid to inotify test cgroup failed")?;
            let populated = read_events(ifd);
            if !populated
                .iter()
                .any(|e| e.wd == wd && e.mask & IN_MODIFY as u32 != 0 && e.name.is_empty())
            {
                return Err("cgroup populated transition did not queue IN_MODIFY");
            }

            narf_filesystem::cgroupfs::task_exited(PID);
            let empty = read_events(ifd);
            if !empty
                .iter()
                .any(|e| e.wd == wd && e.mask & IN_MODIFY as u32 != 0 && e.name.is_empty())
            {
                return Err("cgroup empty transition did not queue IN_MODIFY");
            }
            Ok(())
        })();

        // Keep the global cgroup hierarchy clean even if an assertion above
        // fails after attaching the synthetic process.
        narf_filesystem::cgroupfs::task_exited(PID);
        let _ = call_rmdir(dir.as_ptr() as u64);
        outcome
    })
}
#[cfg(feature = "cgroup")]
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_inotify_cgroup_events_modify
);

// (c) delete a file in a watched dir → IN_DELETE with the child's name.
fn smoke_abi_async_inotify_fire_delete() -> TestResult {
    with_memfs("/ino", "ino", &[("gone", b"x")], || {
        let (ifd, wd) = watch(b"/ino\0", IN_DELETE)?;
        let path = b"/ino/gone\0";
        if call_unlink(path.as_ptr() as u64).unwrap_or(-1) < 0 {
            return Err("unlink failed");
        }
        let evs = read_events(ifd);
        match evs.iter().find(|e| e.mask & IN_DELETE as u32 != 0) {
            Some(e) if e.wd == wd && e.name == "gone" => Ok(()),
            _ => Err("expected IN_DELETE with name=gone"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_fire_delete);

// (d) rename within a watched dir → paired IN_MOVED_FROM / IN_MOVED_TO
// carrying the SAME cookie and the old/new leaf names.
fn smoke_abi_async_inotify_fire_rename() -> TestResult {
    with_memfs("/ino", "ino", &[("old", b"x")], || {
        let (ifd, wd) = watch(b"/ino\0", IN_MOVED_FROM | IN_MOVED_TO)?;
        let old = b"/ino/old\0";
        let new = b"/ino/new\0";
        if call_rename(old.as_ptr() as u64, new.as_ptr() as u64).unwrap_or(-1) < 0 {
            return Err("rename failed");
        }
        let evs = read_events(ifd);
        let from = evs.iter().find(|e| e.mask & IN_MOVED_FROM as u32 != 0);
        let to = evs.iter().find(|e| e.mask & IN_MOVED_TO as u32 != 0);
        match (from, to) {
            (Some(f), Some(t))
                if f.wd == wd
                    && t.wd == wd
                    && f.name == "old"
                    && t.name == "new"
                    && f.cookie != 0
                    && f.cookie == t.cookie =>
            {
                Ok(())
            }
            _ => Err("expected paired IN_MOVED_FROM/IN_MOVED_TO with a shared cookie"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_fire_rename);

// (e) poll(2) on the inotify fd is NOT readable while the queue is empty
// and BECOMES readable after a watched mutation queues an event.
fn smoke_abi_async_inotify_poll_readiness() -> TestResult {
    with_memfs("/ino", "ino", &[], || {
        let (ifd, _wd) = watch(b"/ino\0", IN_CREATE)?;
        // pollfd { fd: ifd, events: POLLIN(0x1), revents: 0 } — 8 bytes.
        let mut pfd = [0u8; 8];
        pfd[0..4].copy_from_slice(&(ifd as i32).to_ne_bytes());
        pfd[4..6].copy_from_slice(&0x1u16.to_ne_bytes());
        // Empty queue → poll(timeout=0) reports 0 ready.
        if call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) != Some(0) {
            return Err("empty inotify fd should not be readable");
        }
        // Queue an event, then poll must report 1 ready with POLLIN set.
        let path = b"/ino/x\0";
        if call_open(path.as_ptr() as u64, O_CREAT | O_WRONLY).is_none() {
            return Err("create open failed");
        }
        pfd[6..8].copy_from_slice(&0u16.to_ne_bytes()); // clear revents
        match call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) {
            Some(1) if u16::from_ne_bytes(pfd[6..8].try_into().unwrap()) & 0x1 != 0 => Ok(()),
            _ => Err("queued inotify fd should be POLLIN-readable"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_poll_readiness);

fn smoke_abi_async_inotify_epollet_hidden_refill() -> TestResult {
    with_memfs("/ino", "ino", &[], || {
        let (ifd, _wd) = watch(b"/ino\0", IN_CREATE)?;
        let epfd = call(Syscall::EpollCreate.raw(), a0(0))
            .filter(|fd| *fd >= 0)
            .ok_or("epoll_create1 failed")? as u64;
        let mut event = [0u8; 12];
        event[0..4].copy_from_slice(&(0x1u32 | (1u32 << 31)).to_ne_bytes());
        event[4..12].copy_from_slice(&ifd.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            a3(epfd, 1, ifd, event.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("epoll_ctl(ADD inotify EPOLLET) failed");
        }
        let mut out = [0u8; 12];

        if call_open(c"/ino/first".as_ptr() as u64, O_CREAT | O_WRONLY).is_none()
            || call(
                Syscall::EpollWait.raw(),
                a3(epfd, out.as_mut_ptr() as u64, 1, 0),
            ) != Some(1)
        {
            return Err("initial inotify edge was not delivered");
        }
        if read_events(ifd).is_empty() {
            return Err("failed to drain first inotify event");
        }
        // Refill before epoll gets a chance to observe the empty queue.
        if call_open(c"/ino/second".as_ptr() as u64, O_CREAT | O_WRONLY).is_none()
            || call(
                Syscall::EpollWait.raw(),
                a3(epfd, out.as_mut_ptr() as u64, 1, 0),
            ) != Some(1)
        {
            return Err("EPOLLET lost hidden inotify refill edge");
        }
        if call(
            Syscall::EpollWait.raw(),
            a3(epfd, out.as_mut_ptr() as u64, 1, 0),
        ) != Some(0)
        {
            return Err("inotify refill edge was delivered more than once");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_inotify_epollet_hidden_refill
);

// (f) IN_ATTRIB — a chmod on a watched file queues an attribute event.
fn smoke_abi_async_inotify_fire_attrib() -> TestResult {
    with_memfs("/ino", "ino", &[("f", b"x")], || {
        const IN_ATTRIB: u64 = 0x0000_0004;
        const AT_FDCWD: u64 = 0xffff_ffff_ffff_ff9c;
        let (ifd, wd) = watch(b"/ino/f\0", IN_ATTRIB)?;
        let path = b"/ino/f\0";
        // fchmodat(AT_FDCWD, path, 0o600, 0) routes to sys_fchmodat, whose
        // success branch fires notify_attrib on the file.
        if call(
            Syscall::Fchmodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o600, 0),
        )
        .unwrap_or(-1)
            < 0
        {
            return Err("fchmodat failed");
        }
        let evs = read_events(ifd);
        match evs.iter().find(|e| e.mask & IN_ATTRIB as u32 != 0) {
            Some(e) if e.wd == wd => Ok(()),
            _ => Err("expected IN_ATTRIB on the watched file"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_inotify_fire_attrib);

// ════════════════════════════════════════════════════════════════════
// fanotify_init(2) — sys_fanotify_init(flags, event_f_flags)
//
// Creates a group + installs an fd. No reachable error path in the
// harness, so positive-only.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_fanotify_init_pos() -> TestResult {
    with_setup(|| {
        // fanotify_init(0, 0) → a non-negative group fd.
        match call(Syscall::FanotifyInit.raw(), a1(0, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("fanotify_init(0,0) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_fanotify_init_pos);

fn smoke_abi_async_fanotify_init_cloexec() -> TestResult {
    with_setup(|| {
        // fanotify_init(FAN_CLOEXEC=0x1, 0) also yields a valid fd.
        match call(Syscall::FanotifyInit.raw(), a1(0x1, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("fanotify_init(FAN_CLOEXEC,0) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_fanotify_init_cloexec);

// ════════════════════════════════════════════════════════════════════
// fanotify_mark(2) — sys_fanotify_mark(fd, flags, mask, dirfd, path)
//
// FAN_MARK_ADD (0x1) stores an inode mark on the NUL-terminated absolute
// path (→ 0). A non-fanotify / bad fd → -EBADF.
// ════════════════════════════════════════════════════════════════════

const FAN_MARK_ADD: u64 = 0x1;

fn smoke_abi_async_fanotify_mark_pos() -> TestResult {
    with_setup(|| {
        let fd = match call(Syscall::FanotifyInit.raw(), a1(0, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("fanotify_init failed"),
        };
        // fanotify_mark(fd, FAN_MARK_ADD, FAN_MODIFY=0x2, AT_FDCWD, "/abi/f") → 0.
        let path = b"/abi/f\0";
        let args = SyscallArgs {
            arg0: fd,
            arg1: FAN_MARK_ADD,
            arg2: 0x2,
            arg3: 0,
            arg4: path.as_ptr() as u64,
            arg5: 0,
        };
        match call(Syscall::FanotifyMark.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("fanotify_mark(ADD) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_fanotify_mark_pos);

fn smoke_abi_async_fanotify_mark_neg() -> TestResult {
    with_setup(|| {
        // fd 999 is not a fanotify group → -EBADF.
        let path = b"/abi/f\0";
        let args = SyscallArgs {
            arg0: 999,
            arg1: FAN_MARK_ADD,
            arg2: 0x2,
            arg3: 0,
            arg4: path.as_ptr() as u64,
            arg5: 0,
        };
        match call(Syscall::FanotifyMark.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fanotify_mark on a bad fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi/async", smoke_abi_async_fanotify_mark_neg);

fn smoke_abi_async_fanotify_read_efault_does_not_publish_fd() -> TestResult {
    with_memfs("/fan", "fan", &[("f", b"x")], || {
        let fanfd = match call(Syscall::FanotifyInit.raw(), a1(0, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("fanotify_init failed"),
        };
        let path = b"/fan/f\0";
        let mark = SyscallArgs {
            arg0: fanfd,
            arg1: FAN_MARK_ADD,
            arg2: 0x2, // FAN_MODIFY
            arg3: 0,
            arg4: path.as_ptr() as u64,
            arg5: 0,
        };
        if call(Syscall::FanotifyMark.raw(), mark) != Some(0) {
            return Err("fanotify_mark failed");
        }
        let filefd = match call_open(path.as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("fanotify target open failed"),
        };
        let byte = [b'y'];
        if call(Syscall::Write.raw(), a2(filefd, byte.as_ptr() as u64, 1)) != Some(1) {
            return Err("fanotify target write failed");
        }

        let task = crate::handlers::current_task_id();
        let before = crate::fd::with_table(task, |table| table.open_fd_numbers().len())
            .ok_or("missing fd table")?;
        // 0x1000 passes the range-shape check but is unmapped, so the guarded
        // copy faults only after fanotify has selected the queued event.
        match call_raw(Syscall::Read.raw(), a2(fanfd, 0x1000, 24)) {
            r if r.status == SyscallReturn::OK && r.value as i64 == -14 => {}
            _ => return Err("fanotify read to unmapped user buffer was not EFAULT"),
        }
        let after = crate::fd::with_table(task, |table| table.open_fd_numbers().len())
            .ok_or("missing fd table after fanotify read")?;
        if after != before {
            return Err("fanotify EFAULT published/leaked an object fd");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/async",
    smoke_abi_async_fanotify_read_efault_does_not_publish_fd
);
