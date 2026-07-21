//! Linux syscall ABI conformance — async group.
#![cfg(feature = "linux-compat")]
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
kernel_test_in!("syscall_abi", smoke_abi_async_poll_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_poll_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_async_ppoll_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_ppoll_neg);

// ════════════════════════════════════════════════════════════════════
// select(2) — sys_select(nfds, rfds, wfds, efds, timeval*)
//
// All-null fd sets + a null timeval (block-forever) with an empty
// computed item list returns 0 immediately. nfds > FD_SETSIZE (1024)
// is rejected up front.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_select_pos() -> TestResult {
    with_setup(|| {
        // select(0, NULL, NULL, NULL, NULL): no fds, block-forever, but the
        // empty set returns 0 without ever sleeping.
        match call(Syscall::Select.raw(), a3(0, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("select(0,NULL,NULL,NULL,NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_select_pos);

fn smoke_abi_async_select_neg() -> TestResult {
    with_setup(|| {
        // select(2000, ..): nfds > FD_SETSIZE → rejected.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(Syscall::Select.raw(), a3(2000, 0, 0, 0)) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("select(nfds>FD_SETSIZE) must fail"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_select_neg);

// ════════════════════════════════════════════════════════════════════
// pselect6(2) — sys_pselect6(nfds, rfds, wfds, efds, timespec*, sigmask)
//
// Same shape as select with a timespec; null sets + null timespec → 0.
// nfds > FD_SETSIZE rejected.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_pselect6_pos() -> TestResult {
    with_setup(|| {
        // pselect6(0, NULL, NULL, NULL, NULL, NULL) → 0.
        match call(Syscall::Pselect6.raw(), a3(0, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("pselect6(0,NULL..) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_pselect6_pos);

fn smoke_abi_async_pselect6_neg() -> TestResult {
    with_setup(|| {
        // pselect6(2000, ..): nfds > FD_SETSIZE → rejected.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(Syscall::Pselect6.raw(), a3(2000, 0, 0, 0)) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("pselect6(nfds>FD_SETSIZE) must fail"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_pselect6_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_create_pos);

fn smoke_abi_async_epoll_create_cloexec() -> TestResult {
    with_setup(|| {
        // epoll_create1(O_CLOEXEC) also yields a valid fd (flag accepted).
        match call(Syscall::EpollCreate.raw(), a0(crate::fd::O_CLOEXEC as u64)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("epoll_create1(O_CLOEXEC) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_create_cloexec);

// ════════════════════════════════════════════════════════════════════
// epoll_ctl(2) — sys_epoll_ctl(epfd, op, fd, epoll_event*)
//
// EPOLL_CTL_ADD inserts into the instance's interest map (the target fd
// is NOT validated against the fd table). A bad epfd → the -1 sentinel.
// ════════════════════════════════════════════════════════════════════

const EPOLL_CTL_ADD: u64 = 1;

fn smoke_abi_async_epoll_ctl_pos() -> TestResult {
    with_setup(|| {
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        // struct epoll_event { u32 events; u64 data; } — read as 12 bytes.
        let mut ev = [0u8; 12];
        ev[0..4].copy_from_slice(&(0x1u32).to_ne_bytes()); // EPOLLIN
                                                           // EPOLL_CTL_ADD with a (here-arbitrary) target fd → 0.
        let args = a3(epfd, EPOLL_CTL_ADD, 5, ev.as_ptr() as u64);
        match call(Syscall::EpollCtl.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("epoll_ctl(ADD) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_ctl_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_ctl_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_wait_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_wait_neg);

// ════════════════════════════════════════════════════════════════════
// epoll_pwait(2) — also wired to sys_epoll_wait (is_pwait set, but the
// sigmask args are ignored when null). Same observable behavior.
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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_pwait_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_pwait_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_pwait2_null_timeout);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_pwait2_timespec);

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
kernel_test_in!("syscall_abi", smoke_abi_async_epoll_pwait2_neg);

// ════════════════════════════════════════════════════════════════════
// futex(2) — sys_futex(uaddr, op, val, timeout)
//
// FUTEX_WAKE (op=1) bumps the per-uaddr counter and wakes up to `val`
// parked waiters, returning the count woken (0 here). An unknown op
// returns the -1 sentinel.
// ════════════════════════════════════════════════════════════════════

const FUTEX_WAKE: u64 = 1;

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
kernel_test_in!("syscall_abi", smoke_abi_async_futex_pos);

fn smoke_abi_async_futex_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        // An unrecognized futex op (99) falls to the catch-all error.
        // LINUX-GAP: Linux returns -ENOSYS/-EINVAL; NARF returns -1.
        let args = a3(&word as *const u32 as u64, 99, 0, 0);
        match call(Syscall::Futex.raw(), args) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("futex(unknown op) must fail"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_neg);

// ════════════════════════════════════════════════════════════════════
// futex_wake(2) [futex2] — sys_futex_wake(uaddr, mask, nr, flags)
//
// Bumps the counter, fires up to `nr` waiters, returns `nr`. uaddr==0 is
// a no-op returning 0 (no error path — the "negative" is this no-op).
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_futex_wake_pos() -> TestResult {
    with_setup(|| {
        let word: u32 = 0;
        // futex_wake(&word, mask=~0, nr=1) → reports nr (1) released.
        let args = a3(&word as *const u32 as u64, u64::MAX, 1, 0);
        match call(Syscall::FutexWake.raw(), args) {
            Some(1) => Ok(()),
            _ => Err("futex_wake(nr=1) should return 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_wake_pos);

fn smoke_abi_async_futex_wake_null() -> TestResult {
    with_setup(|| {
        // futex_wake(NULL, ..): null uaddr is a no-op → 0 (no error path).
        let args = a3(0, u64::MAX, 5, 0);
        match call(Syscall::FutexWake.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("futex_wake(NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_wake_null);

// ════════════════════════════════════════════════════════════════════
// futex_wait(2) [futex2] — sys_futex_wait(uaddr, val, mask, flags, ...)
//
// Value-checked: *uaddr != val → -EAGAIN immediately. uaddr==0 is a
// permitted immediate spurious wake → 0. With a live mismatch we get the
// EAGAIN error; the harness has no task to park, so the match-and-park
// branch falls through to a synchronous 0.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_futex_wait_pos() -> TestResult {
    with_setup(|| {
        // futex_wait(NULL, 0): null uaddr → immediate spurious wake (0).
        let args = a1(0, 0);
        match call(Syscall::FutexWait.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("futex_wait(NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_wait_pos);

fn smoke_abi_async_futex_wait_neg() -> TestResult {
    with_setup(|| {
        let word: u32 = 7;
        // futex_wait(&word, val=1) where *word(7) != 1 → -EAGAIN.
        let args = a1(&word as *const u32 as u64, 1);
        match call(Syscall::FutexWait.raw(), args) {
            Some(v) if v == EAGAIN => Ok(()),
            _ => Err("futex_wait on a stale value must return -EAGAIN"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_wait_neg);

// ════════════════════════════════════════════════════════════════════
// futex_requeue(2) [futex2] — sys_futex_requeue(waiters, flags, nr_wake,
// nr_requeue)
//
// `waiters` points at two `struct futex_waitv` (24B each); entry[0] is the
// source to wake. Always reports `nr_wake` (no error path — even a null
// `waiters` returns nr_wake), so both tests assert the count back.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_futex_requeue_pos() -> TestResult {
    with_setup(|| {
        // Two futex_waitv entries (48 bytes). entry[0]: { val, uaddr, flags, _r }.
        let src: u32 = 0;
        let dst: u32 = 0;
        let mut waitv = [0u8; 48];
        // entry[0].uaddr at offset 8.
        waitv[8..16].copy_from_slice(&(&src as *const u32 as u64).to_ne_bytes());
        // entry[1].uaddr at offset 24+8 = 32.
        waitv[32..40].copy_from_slice(&(&dst as *const u32 as u64).to_ne_bytes());
        // futex_requeue(waiters, flags=0, nr_wake=1, nr_requeue=0) → 1.
        let args = a3(waitv.as_ptr() as u64, 0, 1, 0);
        match call(Syscall::FutexRequeue.raw(), args) {
            Some(1) => Ok(()),
            _ => Err("futex_requeue(nr_wake=1) should return 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_requeue_pos);

fn smoke_abi_async_futex_requeue_null() -> TestResult {
    with_setup(|| {
        // futex_requeue(NULL, 0, 2, 0): null waiters is tolerated and still
        // reports nr_wake (no error path in the counter model).
        let args = a3(0, 0, 2, 0);
        match call(Syscall::FutexRequeue.raw(), args) {
            Some(2) => Ok(()),
            _ => Err("futex_requeue(NULL) should return nr_wake"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_requeue_null);

// ════════════════════════════════════════════════════════════════════
// futex_waitv(2) [futex2] — sys_futex_waitv(waiters, nr, flags, timeout,
// clockid)
//
// nr==0 / waiters==0 / nr>128 → -EINVAL. A word whose live value already
// differs from its expected `val` returns that entry's index immediately.
// ════════════════════════════════════════════════════════════════════

fn smoke_abi_async_futex_waitv_pos() -> TestResult {
    with_setup(|| {
        // One futex_waitv entry whose expected val(1) != live *uaddr(0):
        // futex_waitv reports index 0 (this word is "already woken").
        let word: u32 = 0;
        let mut waitv = [0u8; 24];
        waitv[0..8].copy_from_slice(&(1u64).to_ne_bytes()); // val
        waitv[8..16].copy_from_slice(&(&word as *const u32 as u64).to_ne_bytes()); // uaddr
        let args = a2(waitv.as_ptr() as u64, 1, 0);
        match call(Syscall::FutexWaitv.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("futex_waitv with a moved word should return index 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_waitv_pos);

fn smoke_abi_async_futex_waitv_neg() -> TestResult {
    with_setup(|| {
        // futex_waitv(NULL, 0, ..): nr==0 (and null waiters) → -EINVAL.
        let args = a2(0, 0, 0);
        match call(Syscall::FutexWaitv.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("futex_waitv(nr=0) must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_futex_waitv_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_init1_pos);

fn smoke_abi_async_inotify_init1_nonblock() -> TestResult {
    with_setup(|| {
        // inotify_init1(IN_NONBLOCK=0o4000) also yields a valid fd.
        match call(Syscall::InotifyInit1.raw(), a0(0o4000)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("inotify_init1(IN_NONBLOCK) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_init1_nonblock);

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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_add_watch_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_add_watch_neg);

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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_rm_watch_pos);

fn smoke_abi_async_inotify_rm_watch_neg() -> TestResult {
    with_setup(|| {
        // fd 999 is not an inotify instance → -EBADF.
        match call(Syscall::InotifyRmWatch.raw(), a1(999, 1)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("inotify_rm_watch on a bad fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_rm_watch_neg);

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
        if call(
            Syscall::OpenFile.raw(),
            a1(path.as_ptr() as u64, O_CREAT | O_WRONLY),
        )
        .is_none()
        {
            return Err("create open failed");
        }
        let evs = read_events(ifd);
        match evs.first() {
            Some(e) if e.wd == wd && e.mask & IN_CREATE as u32 != 0 && e.name == "newf" => Ok(()),
            _ => Err("expected IN_CREATE with name=newf"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_fire_create);

// (b) modify a watched file → IN_MODIFY on the watched file (no name).
fn smoke_abi_async_inotify_fire_modify() -> TestResult {
    with_memfs("/ino", "ino", &[("f", b"....")], || {
        let (ifd, wd) = watch(b"/ino/f\0", IN_MODIFY)?;
        // Open the file for writing and write → notify_modify_fd fires.
        let path = b"/ino/f\0";
        let fd = match call(Syscall::OpenFile.raw(), a1(path.as_ptr() as u64, O_WRONLY)) {
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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_fire_modify);

// (c) delete a file in a watched dir → IN_DELETE with the child's name.
fn smoke_abi_async_inotify_fire_delete() -> TestResult {
    with_memfs("/ino", "ino", &[("gone", b"x")], || {
        let (ifd, wd) = watch(b"/ino\0", IN_DELETE)?;
        let path = b"/ino/gone\0";
        if call(Syscall::Unlink.raw(), a0(path.as_ptr() as u64)).unwrap_or(-1) < 0 {
            return Err("unlink failed");
        }
        let evs = read_events(ifd);
        match evs.iter().find(|e| e.mask & IN_DELETE as u32 != 0) {
            Some(e) if e.wd == wd && e.name == "gone" => Ok(()),
            _ => Err("expected IN_DELETE with name=gone"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_fire_delete);

// (d) rename within a watched dir → paired IN_MOVED_FROM / IN_MOVED_TO
// carrying the SAME cookie and the old/new leaf names.
fn smoke_abi_async_inotify_fire_rename() -> TestResult {
    with_memfs("/ino", "ino", &[("old", b"x")], || {
        let (ifd, wd) = watch(b"/ino\0", IN_MOVED_FROM | IN_MOVED_TO)?;
        let old = b"/ino/old\0";
        let new = b"/ino/new\0";
        if call(
            Syscall::Rename.raw(),
            a1(old.as_ptr() as u64, new.as_ptr() as u64),
        )
        .unwrap_or(-1)
            < 0
        {
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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_fire_rename);

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
        if call(
            Syscall::OpenFile.raw(),
            a1(path.as_ptr() as u64, O_CREAT | O_WRONLY),
        )
        .is_none()
        {
            return Err("create open failed");
        }
        pfd[6..8].copy_from_slice(&0u16.to_ne_bytes()); // clear revents
        match call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) {
            Some(1) if u16::from_ne_bytes(pfd[6..8].try_into().unwrap()) & 0x1 != 0 => Ok(()),
            _ => Err("queued inotify fd should be POLLIN-readable"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_poll_readiness);

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
kernel_test_in!("syscall_abi", smoke_abi_async_inotify_fire_attrib);

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
kernel_test_in!("syscall_abi", smoke_abi_async_fanotify_init_pos);

fn smoke_abi_async_fanotify_init_cloexec() -> TestResult {
    with_setup(|| {
        // fanotify_init(FAN_CLOEXEC=0x1, 0) also yields a valid fd.
        match call(Syscall::FanotifyInit.raw(), a1(0x1, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("fanotify_init(FAN_CLOEXEC,0) should return an fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_async_fanotify_init_cloexec);

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
kernel_test_in!("syscall_abi", smoke_abi_async_fanotify_mark_pos);

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
kernel_test_in!("syscall_abi", smoke_abi_async_fanotify_mark_neg);
