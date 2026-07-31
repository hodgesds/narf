//! `epoll_poll` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

// ── Poll tests (≥ 6) ─────────────────────────────────────────────────

/// poll: 1 fd, 0 timeout, data ready → returns 1
fn smoke_poll_one_fd_ready_returns_one() -> TestResult {
    let task = setup_poll_test();
    let fd = install_ready_file(task, narf_filesystem::POLL_IN);

    // pollfd: { fd=fd, events=POLLIN, revents=0 }
    let mut pfd: [u8; 8] = [0; 8];
    pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0, // timeout_ms = 0 = nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK status");
    }
    if r.value != 1 {
        return TestResult::Fail("poll should return 1 for one ready fd");
    }
    // Check revents was written.
    let revents = u16::from_ne_bytes([pfd[6], pfd[7]]);
    if revents == 0 {
        return TestResult::Fail("poll did not write revents");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_one_fd_ready_returns_one);

/// poll: 1 fd, 0 timeout, no data → returns 0 immediately
fn smoke_poll_one_fd_not_ready_returns_zero() -> TestResult {
    let task = setup_poll_test();
    let fd = install_ready_file(task, 0); // not ready

    let mut pfd: [u8; 8] = [0; 8];
    pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0, // nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK");
    }
    if r.value != 0 {
        return TestResult::Fail("poll should return 0 when fd is not ready (nonblocking)");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_one_fd_not_ready_returns_zero);

/// poll: invalid fd gives POLLNVAL in revents, returns 1
fn smoke_poll_invalid_fd_returns_pollnval() -> TestResult {
    let _task = setup_poll_test();

    let mut pfd: [u8; 8] = [0; 8];
    let bad_fd: i32 = 9999;
    pfd[..4].copy_from_slice(&bad_fd.to_ne_bytes());
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK");
    }
    if r.value != 1 {
        return TestResult::Fail("invalid fd: poll should count as one event (POLLNVAL)");
    }
    let revents = u16::from_ne_bytes([pfd[6], pfd[7]]);
    if (revents as u32 & narf_filesystem::POLL_NVAL) == 0 {
        return TestResult::Fail("POLLNVAL must be set for closed fd");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_invalid_fd_returns_pollnval);

/// poll: POLLHUP signalled when closed-pipe end is ready
fn smoke_poll_pollhup_on_closed_read_end() -> TestResult {
    let task = setup_poll_test();
    // Simulate a half-closed pipe: the read end has POLL_HUP set.
    let fd = install_ready_file(task, narf_filesystem::POLL_HUP);

    let mut pfd: [u8; 8] = [0; 8];
    pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    // We ask for POLL_IN but should get POLL_HUP even without asking.
    pfd[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfd.as_ptr() as u64,
            arg1: 1,
            arg2: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value == 0 {
        return TestResult::Fail("poll should notice POLL_HUP");
    }
    let revents = u16::from_ne_bytes([pfd[6], pfd[7]]);
    if (revents as u32 & narf_filesystem::POLL_HUP) == 0 {
        return TestResult::Fail("POLL_HUP must appear in revents");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_pollhup_on_closed_read_end);

/// poll: nfds=0, timeout=0 → returns 0 immediately (no fds, no spin)
fn smoke_poll_zero_fds_returns_zero() -> TestResult {
    let _task = setup_poll_test();
    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: 1, // non-null but irrelevant
            arg1: 0, // nfds=0
            arg2: 0, // timeout=0
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("poll with nfds=0 should return Ok(0)");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_zero_fds_returns_zero);

/// poll: multiple fds, only some ready → correct count
fn smoke_poll_multiple_fds_partial_ready() -> TestResult {
    let task = setup_poll_test();
    let fd_ready = install_ready_file(task, narf_filesystem::POLL_IN);
    let fd_notready = install_ready_file(task, 0);

    let mut pfds: [u8; 16] = [0; 16];
    pfds[..4].copy_from_slice(&(fd_ready as i32).to_ne_bytes());
    pfds[4..6].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());
    pfds[8..12].copy_from_slice(&(fd_notready as i32).to_ne_bytes());
    pfds[12..14].copy_from_slice(&(narf_filesystem::POLL_IN as u16).to_ne_bytes());

    let r = call(
        Syscall::Poll,
        SyscallArgs {
            arg0: pfds.as_ptr() as u64,
            arg1: 2,
            arg2: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("poll returned non-OK");
    }
    if r.value != 1 {
        return TestResult::Fail("poll: only 1 of 2 fds is ready, should return 1");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_poll_multiple_fds_partial_ready);

// ── select tests (≥ 3) ───────────────────────────────────────────────

/// select: 3 fds in readfds, only 1 is ready → only that bit set in output
fn smoke_select_readfds_partial_ready() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let fd_ready = install_ready_file(task, narf_filesystem::POLL_IN);
    let fd_a = install_ready_file(task, 0);
    let fd_b = install_ready_file(task, 0);

    let nfds = (fd_ready.max(fd_a).max(fd_b) + 1) as usize;
    let mut rfds = [0u8; 128];
    // Set all three bits in readfds.
    rfds[fd_ready as usize / 8] |= 1 << (fd_ready % 8);
    rfds[fd_a as usize / 8] |= 1 << (fd_a % 8);
    rfds[fd_b as usize / 8] |= 1 << (fd_b % 8);
    // timeval = 0 → nonblock
    let tv: [i64; 2] = [0, 0];

    let r = call(
        Syscall::Select,
        SyscallArgs {
            arg0: nfds as u64,
            arg1: rfds.as_mut_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: tv.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("select returned non-OK");
    }
    if r.value != 1 {
        return TestResult::Fail("select: only 1 of 3 fds is ready");
    }
    // Check the ready bit is set.
    let bit_ready = (rfds[fd_ready as usize / 8] >> (fd_ready % 8)) & 1;
    let bit_a = (rfds[fd_a as usize / 8] >> (fd_a % 8)) & 1;
    let bit_b = (rfds[fd_b as usize / 8] >> (fd_b % 8)) & 1;
    if bit_ready == 0 {
        return TestResult::Fail("select: ready fd bit not set in output readfds");
    }
    if bit_a != 0 || bit_b != 0 {
        return TestResult::Fail("select: non-ready fd bits should be clear");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_select_readfds_partial_ready);

/// pselect6: sigmask pointer accepted (silently ignored)
fn smoke_pselect6_sigmask_accepted() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let fd_ready = install_ready_file(task, narf_filesystem::POLL_IN);
    let nfds = (fd_ready + 1) as usize;
    let mut rfds = [0u8; 128];
    rfds[fd_ready as usize / 8] |= 1 << (fd_ready % 8);
    // ts = {0, 0} → nonblock
    let ts: [i64; 2] = [0, 0];
    // Fake sigmask pair: { ptr=1, size=8 } — non-null but content ignored.
    let sigmask_pair: [u64; 2] = [1, 8];

    let r = call(
        Syscall::Pselect6,
        SyscallArgs {
            arg0: nfds as u64,
            arg1: rfds.as_mut_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: ts.as_ptr() as u64,
            arg5: sigmask_pair.as_ptr() as u64,
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("pselect6 returned non-OK");
    }
    if r.value == (!0u64) {
        return TestResult::Fail("pselect6 returned -1");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_pselect6_sigmask_accepted);

/// select: no fds ready, timeout=0 → returns 0
fn smoke_select_no_ready_returns_zero() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let fd = install_ready_file(task, 0); // not ready
    let nfds = (fd + 1) as usize;
    let mut rfds = [0u8; 128];
    rfds[fd as usize / 8] |= 1 << (fd % 8);
    let tv: [i64; 2] = [0, 0]; // nonblock

    let r = call(
        Syscall::Select,
        SyscallArgs {
            arg0: nfds as u64,
            arg1: rfds.as_mut_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: tv.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("select with no ready fds + timeout=0 should return 0");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_select_no_ready_returns_zero);

// ── epoll tests (≥ 7) ───────────────────────────────────────────────

/// epoll_create1 returns a valid fd; close succeeds
fn smoke_epoll_create1_returns_valid_fd() -> TestResult {
    let task = setup_poll_test();

    let r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0, // no flags
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 returned non-OK");
    }
    let epfd = r.value as u32;
    if epfd == (!0u32) {
        return TestResult::Fail("epoll_create1 returned -1");
    }
    // Verify the fd exists in the table by trying to close it.
    let closed = crate::fd::with_table(task, |t| t.close(epfd)).unwrap_or(false);
    if !closed {
        return TestResult::Fail("epoll_create1 fd not in fd table");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_create1_returns_valid_fd);

/// epoll_ctl ADD then DEL — item removed from interest set
fn smoke_epoll_ctl_add_then_del() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    // Create epoll fd.
    let r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 failed");
    }
    let epfd = r.value as u32;

    // Install a watched fd.
    let watched = install_ready_file(task, narf_filesystem::POLL_IN);

    // epoll_event = { events: EPOLLIN, data: 0xABCD }
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN).to_ne_bytes());
    ev[4..12].copy_from_slice(&0xABCD_u64.to_ne_bytes());

    // ADD
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("epoll_ctl ADD failed");
    }

    // DEL
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_DEL as u64,
            arg2: watched as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("epoll_ctl DEL failed");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_ctl_add_then_del);

/// An epoll registration is tied to the watched open file, not whatever
/// object later reuses the same descriptor number.
fn smoke_epoll_fd_reuse_does_not_alias_stale_interest() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let watched = install_ready_file(task, 0);
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&0xA11A5_u64.to_ne_bytes());
    let added = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if added.value != 0 {
        return TestResult::Fail("initial epoll_ctl ADD failed");
    }
    crate::fd::with_table(task, |t| t.close(watched));
    let reused = install_ready_file(task, narf_filesystem::POLL_IN);
    if reused != watched {
        return TestResult::Fail("test did not reuse the closed fd slot");
    }

    let mut out = [0u8; 12];
    let stale = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if stale.value != 0 {
        return TestResult::Fail("stale epoll item aliased a reused fd");
    }

    let readded = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: reused as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if readded.value != 0 {
        return TestResult::Fail("dead epoll item prevented ADD of reused fd");
    }
    let ready = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if ready.value != 1 {
        return TestResult::Fail("re-added reused fd was not reported ready");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_fd_reuse_does_not_alias_stale_interest
);

/// Closing the descriptor used for ADD does not kill the watch while a dup
/// still retains the same open file description.
fn smoke_epoll_watch_survives_original_close_with_dup() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let dup = crate::fd::with_table(task, |t| {
        let entry = t.get(watched).cloned();
        entry.map(|entry| t.open(entry))
    })
    .flatten();
    if dup.is_none() {
        return TestResult::Fail("failed to duplicate watched fd");
    }
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&0xD09_u64.to_ne_bytes());
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("epoll_ctl ADD failed");
    }
    crate::fd::with_table(task, |t| t.close(watched));
    let mut out = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.value != 1 {
        return TestResult::Fail("dup did not retain watched open file");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_watch_survives_original_close_with_dup
);

/// EPOLLERR and EPOLLHUP are returned regardless of the requested mask.
fn smoke_epoll_hup_is_reported_without_explicit_interest() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let watched = install_ready_file(task, narf_filesystem::POLL_HUP);
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    let mut out = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    let events = u32::from_ne_bytes(out[..4].try_into().unwrap_or([0; 4]));
    if r.value != 1 || events & crate::epoll::EPOLLHUP == 0 {
        return TestResult::Fail("implicit EPOLLHUP was not delivered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_hup_is_reported_without_explicit_interest
);

/// A peer shutdown must wake epoll and report readable EOF plus implicit HUP,
/// even when the registration requested only EPOLLIN.
fn smoke_epoll_socket_shutdown_reports_in_and_hup() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    if call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_STREAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("socketpair failed");
    }
    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[1] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("epoll add failed");
    }

    let mut out = [0u8; 12];
    if call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("open empty peer unexpectedly readable");
    }
    if call(
        Syscall::SocketShutdown,
        SyscallArgs {
            arg0: sv[0] as u64,
            arg1: crate::socket::SHUT_RDWR as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("peer shutdown failed");
    }
    if call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
    {
        return TestResult::Fail("peer shutdown was not epoll-ready");
    }
    let events = u32::from_ne_bytes(out[..4].try_into().unwrap_or([0; 4]));
    if events & (crate::epoll::EPOLLIN | crate::epoll::EPOLLHUP)
        != crate::epoll::EPOLLIN | crate::epoll::EPOLLHUP
    {
        return TestResult::Fail("peer shutdown omitted EPOLLIN or implicit EPOLLHUP");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_socket_shutdown_reports_in_and_hup);

/// epoll_wait: 0 timeout, no ready items → returns 0
fn smoke_epoll_wait_no_ready_returns_zero() -> TestResult {
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    let watched = install_ready_file(task, 0); // NOT ready
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&42u64.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12 * 16];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 16,
            arg3: 0, // timeout=0 → nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("epoll_wait should return 0 when no fd is ready");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_wait_no_ready_returns_zero);

/// epoll_wait: 0 timeout, 1 ready → returns 1 with correct .data
fn smoke_epoll_wait_one_ready_returns_one() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    const USERDATA: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&USERDATA.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0, // nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 1 {
        return TestResult::Fail("epoll_wait: ready fd should return 1 event");
    }
    let data = u64::from_ne_bytes(out_ev[4..12].try_into().unwrap_or([0; 8]));
    if data != USERDATA {
        return TestResult::Fail("epoll_wait: returned wrong .data value");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_wait_one_ready_returns_one);

/// EPOLLET edge-triggered: first wake delivered; same-state call returns 0
fn smoke_epoll_epollet_edge_triggered() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    // Start as ready (POLL_IN) but add with EPOLLET + fresh last_mask=0.
    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    let flags = crate::epoll::EPOLLIN | crate::epoll::EPOLLET;
    ev[..4].copy_from_slice(&flags.to_ne_bytes());
    ev[4..12].copy_from_slice(&1u64.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12];
    // First wait: last_mask was 0, current is POLL_IN → transition → deliver.
    let r1 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );

    // Second wait: last_mask now == POLL_IN → no transition → should return 0.
    let r2 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    if r1.status != SyscallReturn::OK || r1.value != 1 {
        return TestResult::Fail("EPOLLET: first wake should be delivered");
    }
    if r2.status != SyscallReturn::OK || r2.value != 0 {
        return TestResult::Fail("EPOLLET: second same-state poll should return 0");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_epollet_edge_triggered);

/// EPOLLET must retain an enqueue edge that occurs after a drain but before
/// the next epoll_wait samples the socket.
fn smoke_epoll_epollet_dgram_drain_refill_before_wait() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    let pair = call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_DGRAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if pair.value != 0 {
        return TestResult::Fail("EPOLLET dgram socketpair failed");
    }

    let epfd = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    )
    .value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
    ev[4..12].copy_from_slice(&0xD6A6u64.to_ne_bytes());
    let add = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[1] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if add.value != 0 {
        return TestResult::Fail("EPOLLET dgram add failed");
    }

    let mut out_ev = [0u8; 12];
    for byte in [b'a', b'b'] {
        let sent = call(
            Syscall::SocketSend,
            SyscallArgs {
                arg0: sv[0] as u64,
                arg1: (&byte as *const u8) as u64,
                arg2: 1,
                ..SyscallArgs::default()
            },
        );
        if sent.value != 1 {
            return TestResult::Fail("EPOLLET dgram send failed");
        }
        let ready = call(
            Syscall::EpollWait,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: out_ev.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                ..SyscallArgs::default()
            },
        );
        if ready.value != 1 {
            return TestResult::Fail("EPOLLET lost drain/refill edge");
        }
        let mut received = 0u8;
        let recv = call(
            Syscall::SocketRecv,
            SyscallArgs {
                arg0: sv[1] as u64,
                arg1: (&mut received as *mut u8) as u64,
                arg2: 1,
                ..SyscallArgs::default()
            },
        );
        if recv.value != 1 || received != byte {
            return TestResult::Fail("EPOLLET dgram drain failed");
        }
        // The second send happens immediately on the next loop iteration,
        // before any empty-state epoll scan can clear last_mask.
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_epollet_dgram_drain_refill_before_wait
);

/// EPOLLET on an AF_UNIX datagram socket must report a rising edge when a second
/// datagram arrives, even if the inbox was already non-empty (not drained to empty).
fn smoke_epoll_epollet_dgram_consecutive_refill_without_empty_drain() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    let pair = call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_DGRAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if pair.value != 0 {
        return TestResult::Fail("EPOLLET dgram socketpair failed");
    }

    let epfd = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    )
    .value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
    ev[4..12].copy_from_slice(&0xD6A7u64.to_ne_bytes());
    let add = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[1] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if add.value != 0 {
        return TestResult::Fail("EPOLLET dgram add failed");
    }

    // Send packet 1.
    let byte1 = b'x';
    if call(
        Syscall::SocketSend,
        SyscallArgs {
            arg0: sv[0] as u64,
            arg1: (&byte1 as *const u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
    {
        return TestResult::Fail("EPOLLET dgram send 1 failed");
    }

    // First epoll_wait: observes packet 1.
    let mut out_ev = [0u8; 12];
    let ready = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if ready.value != 1 {
        return TestResult::Fail("EPOLLET initial dgram edge missing");
    }

    // Send packet 2 BEFORE reading packet 1 (inbox is non-empty throughout).
    let byte2 = b'y';
    if call(
        Syscall::SocketSend,
        SyscallArgs {
            arg0: sv[0] as u64,
            arg1: (&byte2 as *const u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
    {
        return TestResult::Fail("EPOLLET dgram send 2 failed");
    }

    // Second epoll_wait: MUST report the second datagram edge via generation token change.
    let ready2 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if ready2.value != 1 {
        return TestResult::Fail(
            "EPOLLET failed to observe consecutive refill on non-empty dgram inbox",
        );
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_epollet_dgram_consecutive_refill_without_empty_drain
);

/// EPOLLET on an AF_NETLINK socket (NETLINK_KOBJECT_UEVENT) must report rising
/// edges when new uevents arrive, even if the queue was already non-empty.
fn smoke_epoll_epollet_netlink_uevent_token_advances_on_new_uevents() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let sock_fd = call(
        Syscall::SocketOpen,
        SyscallArgs {
            arg0: crate::socket::AF_NETLINK as u64,
            arg1: crate::socket::SOCK_DGRAM as u64,
            arg2: crate::socket::NETLINK_KOBJECT_UEVENT as u64,
            ..SyscallArgs::default()
        },
    )
    .value as i32;
    if sock_fd < 0 {
        return TestResult::Fail("NETLINK_KOBJECT_UEVENT socket open failed");
    }

    let epfd = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    )
    .value as u32;

    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
    ev[4..12].copy_from_slice(&0x4E4C5545u64.to_ne_bytes());
    let add = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sock_fd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if add.value != 0 {
        return TestResult::Fail("EPOLLET netlink uevent add failed");
    }

    // Emit first uevent.
    narf_filesystem::emit_uevent(
        narf_filesystem::UeventAction::Add,
        alloc::string::ToString::to_string("/devices/virtual/test_dev0"),
        alloc::string::ToString::to_string("test"),
    );

    let mut out_ev = [0u8; 12];
    let ready1 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if ready1.value != 1 {
        return TestResult::Fail("EPOLLET netlink uevent first edge missing");
    }

    // Emit second uevent without reading first uevent (reader queue is non-empty).
    narf_filesystem::emit_uevent(
        narf_filesystem::UeventAction::Add,
        alloc::string::ToString::to_string("/devices/virtual/test_dev1"),
        alloc::string::ToString::to_string("test"),
    );

    let ready2 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if ready2.value != 1 {
        return TestResult::Fail("EPOLLET netlink uevent second edge missing on non-empty queue");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_epollet_netlink_uevent_token_advances_on_new_uevents
);

/// Consuming readable data must not manufacture a new EPOLLOUT edge when
/// the stream was writable before and after the read.
fn smoke_epoll_epollet_read_does_not_retrigger_writable() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    if call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_STREAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream socketpair failed");
    }

    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(
        &(crate::epoll::EPOLLIN | crate::epoll::EPOLLOUT | crate::epoll::EPOLLET).to_ne_bytes(),
    );
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[1] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream add failed");
    }

    let mut out_ev = [0u8; 12];
    let wait = |out: &mut [u8; 12]| {
        call(
            Syscall::EpollWait,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                ..SyscallArgs::default()
            },
        )
    };
    if wait(&mut out_ev).value != 1 {
        return TestResult::Fail("EPOLLET initial writable edge missing");
    }

    let byte = b'x';
    if call(
        Syscall::SocketSend,
        SyscallArgs {
            arg0: sv[0] as u64,
            arg1: (&byte as *const u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
        || wait(&mut out_ev).value != 1
    {
        return TestResult::Fail("EPOLLET readable edge missing");
    }

    let mut received = 0u8;
    if call(
        Syscall::SocketRecv,
        SyscallArgs {
            arg0: sv[1] as u64,
            arg1: (&mut received as *mut u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
        || received != byte
    {
        return TestResult::Fail("EPOLLET stream drain failed");
    }
    if wait(&mut out_ev).value != 0 {
        return TestResult::Fail("EPOLLET read retriggered unchanged writability");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_epollet_read_does_not_retrigger_writable
);

/// Data that arrives and is fully drained between epoll scans changes only
/// the readable-edge token. It must not be misreported as a new EPOLLOUT edge
/// just because the socket remains writable.
fn smoke_epoll_epollet_hidden_read_edge_does_not_retrigger_out() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    if call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_STREAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream socketpair failed");
    }
    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(
        &(crate::epoll::EPOLLIN | crate::epoll::EPOLLOUT | crate::epoll::EPOLLET).to_ne_bytes(),
    );
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[1] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream add failed");
    }

    let mut out = [0u8; 12];
    let wait = |out: &mut [u8; 12]| {
        call(
            Syscall::EpollWait,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                ..SyscallArgs::default()
            },
        )
    };
    if wait(&mut out).value != 1 {
        return TestResult::Fail("initial writable edge missing");
    }

    let byte = b'x';
    if call(
        Syscall::SocketSend,
        SyscallArgs {
            arg0: sv[0] as u64,
            arg1: (&byte as *const u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
    {
        return TestResult::Fail("send failed");
    }
    let mut received = 0u8;
    if call(
        Syscall::SocketRecv,
        SyscallArgs {
            arg0: sv[1] as u64,
            arg1: (&mut received as *mut u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
    {
        return TestResult::Fail("drain failed");
    }
    if wait(&mut out).value != 0 {
        return TestResult::Fail("hidden readable edge manufactured EPOLLOUT");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_epollet_hidden_read_edge_does_not_retrigger_out
);

/// Adding more bytes to an already-readable stream must not manufacture a
/// second EPOLLIN edge. The consumer has already been told to drain to
/// EAGAIN.
fn smoke_epoll_epollet_write_does_not_retrigger_readable() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    if call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_STREAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream socketpair failed");
    }

    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[1] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream add failed");
    }

    let mut out_ev = [0u8; 12];
    let wait = |out: &mut [u8; 12]| {
        call(
            Syscall::EpollWait,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                ..SyscallArgs::default()
            },
        )
    };
    for (index, byte) in [b'a', b'b'].into_iter().enumerate() {
        if call(
            Syscall::SocketSend,
            SyscallArgs {
                arg0: sv[0] as u64,
                arg1: (&byte as *const u8) as u64,
                arg2: 1,
                ..SyscallArgs::default()
            },
        )
        .value
            != 1
        {
            return TestResult::Fail("EPOLLET stream send failed");
        }
        let ready = wait(&mut out_ev).value;
        if (index == 0 && ready != 1) || (index == 1 && ready != 0) {
            return TestResult::Fail("EPOLLET retriggered unchanged readability");
        }
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_epollet_write_does_not_retrigger_readable
);

/// A full stream is not writable; consuming one byte must publish exactly one
/// EPOLLOUT edge for the full-to-space transition.
fn smoke_epoll_epollet_full_to_space_writable_edge() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();

    let mut sv = [0i32; 2];
    if call(
        Syscall::SocketPair,
        SyscallArgs {
            arg0: crate::socket::AF_UNIX as u64,
            arg1: crate::socket::SOCK_STREAM as u64,
            arg3: sv.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream socketpair failed");
    }

    let payload = alloc::vec![0x5au8; 64 * 1024];
    if call(
        Syscall::SocketSend,
        SyscallArgs {
            arg0: sv[0] as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != payload.len() as u64
    {
        return TestResult::Fail("failed to fill stream ring");
    }

    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLOUT | crate::epoll::EPOLLET).to_ne_bytes());
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: sv[0] as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET stream add failed");
    }

    let mut out_ev = [0u8; 12];
    let wait = |out: &mut [u8; 12]| {
        call(
            Syscall::EpollWait,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                ..SyscallArgs::default()
            },
        )
    };
    if wait(&mut out_ev).value != 0 {
        return TestResult::Fail("full stream was reported writable");
    }

    let mut byte = 0u8;
    if call(
        Syscall::SocketRecv,
        SyscallArgs {
            arg0: sv[1] as u64,
            arg1: (&mut byte as *mut u8) as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
    )
    .value
        != 1
    {
        return TestResult::Fail("failed to make stream writable");
    }
    if wait(&mut out_ev).value != 1 || wait(&mut out_ev).value != 0 {
        return TestResult::Fail("full-to-space transition did not publish one edge");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_epollet_full_to_space_writable_edge);

/// EPOLLONESHOT: fires once; re-arm via MOD; fires again
fn smoke_epoll_oneshot_fires_once_rearm_fires_again() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    let flags = crate::epoll::EPOLLIN | crate::epoll::EPOLLONESHOT;
    ev[..4].copy_from_slice(&flags.to_ne_bytes());
    ev[4..12].copy_from_slice(&77u64.to_ne_bytes());

    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let mut out_ev = [0u8; 12];
    // First wait: oneshot fires.
    let r1 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    // Second wait: should return 0 (disarmed).
    let r2 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );

    // Re-arm via MOD.
    let flags2 = crate::epoll::EPOLLIN | crate::epoll::EPOLLONESHOT;
    let mut ev2 = [0u8; 12];
    ev2[..4].copy_from_slice(&flags2.to_ne_bytes());
    ev2[4..12].copy_from_slice(&77u64.to_ne_bytes());
    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_MOD as u64,
            arg2: watched as u64,
            arg3: ev2.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    // Third wait: fires again after re-arm.
    let r3 = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    if r1.status != SyscallReturn::OK || r1.value != 1 {
        return TestResult::Fail("EPOLLONESHOT: first fire failed");
    }
    if r2.value != 0 {
        return TestResult::Fail("EPOLLONESHOT: should be disarmed after first fire");
    }
    if r3.value != 1 {
        return TestResult::Fail("EPOLLONESHOT: should fire again after MOD re-arm");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_oneshot_fires_once_rearm_fires_again
);

/// 1000 fds in one epoll set, 1 becomes ready → wait returns exactly 1
fn smoke_epoll_1000_fds_one_ready() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let epfd_r = call(
        Syscall::EpollCreate,
        SyscallArgs {
            arg0: 0,
            ..SyscallArgs::default()
        },
    );
    if epfd_r.status != SyscallReturn::OK {
        return TestResult::Fail("create failed");
    }
    let epfd = epfd_r.value as u32;

    // Install 999 not-ready fds + 1 ready one.
    let mut ev = [0u8; 12];
    let mut ready_fd = 0i32;
    const TOTAL: usize = 1000;
    const READY_IDX: usize = 500;
    for i in 0..TOTAL {
        let mask = if i == READY_IDX {
            narf_filesystem::POLL_IN
        } else {
            0
        };
        let fd = install_ready_file(task, mask);
        if i == READY_IDX {
            ready_fd = fd as i32;
        }
        ev.fill(0);
        ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
        ev[4..12].copy_from_slice(&(fd as u64).to_ne_bytes());
        call(
            Syscall::EpollCtl,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: crate::epoll::EPOLL_CTL_ADD as u64,
                arg2: fd as u64,
                arg3: ev.as_ptr() as u64,
                ..SyscallArgs::default()
            },
        );
    }

    let mut out_ev = [0u8; 12 * 16]; // room for 16 results
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 16,
            arg3: 0, // nonblock
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_wait failed");
    }
    if r.value != 1 {
        return TestResult::Fail("1000 fds: only 1 should be returned as ready");
    }
    // Verify the returned data matches the ready fd.
    let data = u64::from_ne_bytes(out_ev[4..12].try_into().unwrap_or([0; 8]));
    if data != ready_fd as u64 {
        return TestResult::Fail("1000 fds: returned wrong fd data");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_1000_fds_one_ready);

// ── Epoll instance identity + nested-epoll agreement smokes ──────────
//
// Regression tests for the PSTEP-WAYLAND livelock: the epoll instance
// used to live in a registry keyed by (creating task id, epfd), so a
// CLONE_FILES sibling thread's epoll_wait missed it and failed -1 while
// poll() on the same fd (resolved via the SHARED fd table) reported it
// readable — kwin_wayland span ppoll↔epoll_pwait at 100% CPU forever.
// Instances now resolve through the fd table (`as_any` downcast).

/// Same-process sibling (CLONE_FILES fd-table share): epoll created
/// under one task id must be waitable/ctl-able under the sibling's.
fn smoke_epoll_shared_fd_table_cross_thread_wait() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Own the current-task switch: setup_poll_test pins a fixed id.
    crate::syscall::__test_clear_global();
    crate::fd::__test_reset();
    crate::handlers::init_per_task_state();
    crate::epoll::__test_reset();

    const CREATOR: u64 = 0xEF01;
    const SIBLING: u64 = 0xEF02;
    static CUR_TASK: AtomicU64 = AtomicU64::new(CREATOR);
    fn task_lu() -> u64 {
        CUR_TASK.load(AtomicOrd::Relaxed)
    }
    crate::install_task_id_lookup(task_lu);
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // CREATOR builds the epoll + adds a ready fd.
    let r = call(Syscall::EpollCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK || r.value == (-1i64) as u64 {
        return TestResult::Fail("epoll_create1 failed");
    }
    let epfd = r.value as u32;
    let watched = install_ready_file(CREATOR, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&0xD00D_u64.to_ne_bytes());
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if r.value != 0 {
        return TestResult::Fail("creator's epoll_ctl ADD failed");
    }

    // SIBLING shares the fd table (CLONE_FILES) and waits on the epfd.
    crate::fd::share(CREATOR, SIBLING);
    CUR_TASK.store(SIBLING, AtomicOrd::Relaxed);
    let mut out_ev = [0u8; 12 * 4];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    // Park the lookup back on the creator id — a later test that installs
    // no lookup of its own shouldn't inherit the sibling id.
    CUR_TASK.store(CREATOR, AtomicOrd::Relaxed);
    if r.status != SyscallReturn::OK || r.value != 1 {
        return TestResult::Fail(
            "sibling thread's epoll_wait must see the shared instance (was: registry miss → -1)",
        );
    }
    let data = u64::from_ne_bytes(out_ev[4..12].try_into().unwrap_or([0; 8]));
    if data != 0xD00D {
        return TestResult::Fail("sibling's epoll_wait returned wrong .data");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_shared_fd_table_cross_thread_wait);

/// dup'd epfd aliases the same instance: ctl through the dup, wait
/// through the original.
fn smoke_epoll_dup_fd_aliases_same_instance() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let r = call(Syscall::EpollCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 failed");
    }
    let epfd = r.value as u32;
    // dup the epfd by cloning its fd entry (same Arc, new slot).
    let dup = crate::fd::with_table(task, |t| {
        let entry = t.get(epfd).cloned();
        entry.map(|e| t.open(e))
    })
    .flatten();
    let Some(dupfd) = dup else {
        return TestResult::Fail("dup of epfd failed");
    };

    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    ev[4..12].copy_from_slice(&7u64.to_ne_bytes());
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: dupfd as u64, // ctl via the DUP
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if r.value != 0 {
        return TestResult::Fail("epoll_ctl via dup'd epfd failed");
    }
    let mut out_ev = [0u8; 12 * 4];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64, // wait via the ORIGINAL
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 1 {
        return TestResult::Fail("epoll_wait via original epfd missed the dup-added item");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_epoll_dup_fd_aliases_same_instance);

/// poll(2) readability of an epoll fd must AGREE with epoll_wait: an
/// EPOLLET edge already consumed by epoll_wait is NOT readable (Linux
/// ep_eventpoll_poll reflects the ready list). Divergence here makes a
/// poll-over-epoll event loop spin: poll says ready, wait delivers 0.
fn smoke_epoll_fd_poll_readiness_matches_epoll_wait_et() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let r = call(Syscall::EpollCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 failed");
    }
    let epfd = r.value as u32;
    let watched = install_ready_file(task, narf_filesystem::POLL_IN);
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
    ev[4..12].copy_from_slice(&1u64.to_ne_bytes());
    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: watched as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );

    let epoll_ops = crate::fd::with_table(task, |t| t.get(epfd).map(|e| e.ops.clone())).flatten();
    let Some(epoll_ops) = epoll_ops else {
        return TestResult::Fail("epfd not in fd table");
    };

    // Fresh edge: both epoll_wait and the epoll fd's own readiness agree.
    if epoll_ops.poll_readiness() & narf_filesystem::POLL_IN == 0 {
        return TestResult::Fail("fresh ET edge: epoll fd must poll readable");
    }
    let mut out_ev = [0u8; 12 * 4];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.value != 1 {
        return TestResult::Fail("fresh ET edge: epoll_wait must deliver it");
    }

    // Edge consumed, level still high: epoll_wait delivers nothing more,
    // so the epoll fd must NOT poll readable either.
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out_ev.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.value != 0 {
        return TestResult::Fail("consumed ET edge: epoll_wait must return 0");
    }
    if epoll_ops.poll_readiness() & narf_filesystem::POLL_IN != 0 {
        return TestResult::Fail(
            "consumed ET edge: epoll fd must NOT poll readable (poll↔epoll_wait spin)",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_fd_poll_readiness_matches_epoll_wait_et
);

/// epoll_ctl must refuse self-add and 2-cycles (Linux: ELOOP) while
/// still allowing legitimate finite nesting (libwayland nests 2-3).
fn smoke_epoll_ctl_rejects_cycles_allows_finite_nesting() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    let _ = task;

    let mk = || {
        let r = call(Syscall::EpollCreate, SyscallArgs::default());
        r.value as u32
    };
    let (ep_a, ep_b, ep_c) = (mk(), mk(), mk());
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    let add = |epfd: u32, tfd: u32, ev_ptr: u64| {
        call(
            Syscall::EpollCtl,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: crate::epoll::EPOLL_CTL_ADD as u64,
                arg2: tfd as u64,
                arg3: ev_ptr,
                ..SyscallArgs::default()
            },
        )
        .value
    };

    // Self-add refused.
    if add(ep_a, ep_a, ev.as_ptr() as u64) == 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_ctl must refuse adding an epoll to itself");
    }
    // Finite chain A ⊇ B ⊇ C allowed.
    if add(ep_a, ep_b, ev.as_ptr() as u64) != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("legitimate 2-level epoll nesting must work");
    }
    if add(ep_b, ep_c, ev.as_ptr() as u64) != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("legitimate 3-level epoll nesting must work");
    }
    // Closing the loop C ⊇ A refused.
    let r = add(ep_c, ep_a, ev.as_ptr() as u64);
    crate::syscall::__test_clear_global();
    if r == 0 {
        return TestResult::Fail("epoll_ctl must refuse an A→B→C→A cycle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_epoll_ctl_rejects_cycles_allows_finite_nesting
);

/// An epoll fd forwards its nearest child timerfd deadline through
/// `poll_deadline`, so a `poll(2)` park over the epoll fd clamps its
/// wake-up to the timer instead of sleeping forever (a timerfd expiry
/// fires no readiness notify).
fn smoke_epoll_fd_forwards_nested_timerfd_poll_deadline() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();

    let r = call(Syscall::EpollCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK {
        return TestResult::Fail("epoll_create1 failed");
    }
    let epfd = r.value as u32;

    // Install an armed timerfd (absolute deadline well in the future).
    let tfd_ops = crate::io_mux::TimerFd::new();
    let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(500_000_000);
    tfd_ops.arm(deadline, 0);
    let tfd = crate::fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: tfd_ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .unwrap();

    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
    call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: tfd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();

    let epoll_ops = crate::fd::with_table(task, |t| t.get(epfd).map(|e| e.ops.clone())).flatten();
    let Some(epoll_ops) = epoll_ops else {
        return TestResult::Fail("epfd not in fd table");
    };
    match epoll_ops.poll_deadline() {
        Some(d) if d == deadline => TestResult::Pass,
        Some(_) => TestResult::Fail("epoll fd forwarded a WRONG nested timerfd deadline"),
        None => TestResult::Fail(
            "epoll fd must forward a nested timerfd deadline (poll(-1) parks forever without it)",
        ),
    }
}
kernel_test_in!(
    "userspace",
    smoke_epoll_fd_forwards_nested_timerfd_poll_deadline
);

// ── Wave-64 eventfd / timerfd / event-loop integration smokes ────────
//
// These exercise the syscall surface for `eventfd2(2)`, `timerfd_create
// /settime/gettime(2)`, and an end-to-end epoll-watching-eventfd loop.
// The handlers themselves were wired earlier — these prove that
// userspace can build a Linux-shaped event loop on top.

/// Wave-64: eventfd2(0, 0) → fd. Write 8 bytes counter delta, read
/// 8 bytes back; counter resets to 0 after a non-semaphore read.
#[cfg(feature = "linux-compat")]
fn smoke_wave64_eventfd_write_read_roundtrip() -> TestResult {
    let task = setup_poll_test();
    let r = call(
        Syscall::Eventfd,
        SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("eventfd2 syscall returned -1");
    }
    let efd = r.value as u32;
    // Write 0x42 to the fd: get the EventFd Arc out of the fd table.
    let ops = crate::fd::with_table(task, |t| t.get(efd).map(|e| e.ops.clone()))
        .flatten()
        .expect("eventfd fd not in table");
    let write_buf = 0x42u64.to_le_bytes();
    let read_buf_res = {
        // Use the FileOps directly — we already proved sys_write
        // routes through it via the OpenFile/Read tests upstream.
        // Driving the future to completion under no_std requires
        // the test poll_once helper which is present in this crate.
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        const NOOP: RawWaker = RawWaker::new(core::ptr::null(), &VT);
        unsafe fn no_op(_: *const ()) {}
        unsafe fn clone(_: *const ()) -> RawWaker {
            NOOP
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        let raw = NOOP;
        // SAFETY: `raw` pairs a null data pointer with the static `VT` vtable whose
        // clone returns the same null waker and wake/drop are no-ops that never
        // dereference the data pointer, so it upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw) };
        let mut cx = Context::from_waker(&waker);

        let mut wfut = ops.write(0, &write_buf);
        let _ = match wfut.as_mut().poll(&mut cx) {
            Poll::Ready(r) => r,
            Poll::Pending => {
                crate::syscall::__test_clear_global();
                return TestResult::Fail("eventfd write pending");
            }
        };
        drop(wfut);

        let mut rbuf = [0u8; 8];
        {
            let mut rfut = ops.read(0, &mut rbuf);
            let _ = match rfut.as_mut().poll(&mut cx) {
                Poll::Ready(r) => r,
                Poll::Pending => {
                    crate::syscall::__test_clear_global();
                    return TestResult::Fail("eventfd read pending");
                }
            };
        }
        rbuf
    };
    crate::syscall::__test_clear_global();
    let got = u64::from_le_bytes(read_buf_res);
    if got != 0x42 {
        return TestResult::Fail("eventfd round-trip value mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_eventfd_write_read_roundtrip);

/// Wave-64: timerfd_create → settime (1 ms relative) → after the
/// deadline passes, poll_readiness reports POLL_IN.
#[cfg(feature = "linux-compat")]
fn smoke_wave64_timerfd_create_settime_fires() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let _task = setup_poll_test();
    let r = call(
        Syscall::TimerfdCreate,
        SyscallArgs {
            arg0: 1, // CLOCK_MONOTONIC (ignored)
            arg1: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("timerfd_create returned -1");
    }
    let tfd = r.value as u32;
    // itimerspec: interval=0 (one-shot); value=1us (so we don't
    // have to wait long in a kernel-test fixture).
    let mut buf = [0u8; 32];
    // interval = 0 — bytes 0..16 stay zero.
    let value_sec: i64 = 0;
    let value_nsec: i64 = 1_000; // 1 μs
    buf[16..24].copy_from_slice(&value_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&value_nsec.to_le_bytes());
    let r = call(
        Syscall::TimerfdSettime,
        SyscallArgs {
            arg0: tfd as u64,
            arg1: 0,
            arg2: buf.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("timerfd_settime returned !=0");
    }
    // Spin until monotonic_ns has moved past the deadline.
    let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
    while narf_scheduler::narf_time::monotonic_ns() < deadline {
        core::hint::spin_loop();
    }
    // poll_readiness should now report POLL_IN — fetch the
    // TimerFd via the kernel-side arc map and call directly.
    let ready = crate::fd::with_table(_task, |t| t.get(tfd).map(|e| e.ops.poll_readiness()))
        .flatten()
        .unwrap_or(0);
    crate::syscall::__test_clear_global();
    if (ready & narf_filesystem::POLL_IN) == 0 {
        return TestResult::Fail("timerfd fd never became readable");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_timerfd_create_settime_fires);

/// Wave-64: timerfd_gettime returns the configured interval and a
/// value-remaining that drops toward zero. We arm with a 1 s
/// one-shot, then gettime and check the remaining is ≤ 1 s.
#[cfg(feature = "linux-compat")]
fn smoke_wave64_timerfd_gettime_reports_remaining() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let _task = setup_poll_test();
    let r = call(Syscall::TimerfdCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("timerfd_create -1");
    }
    let tfd = r.value as u32;
    let mut new_value = [0u8; 32];
    // interval = 500ms periodic
    let interval_sec: i64 = 0;
    let interval_nsec: i64 = 500_000_000;
    let value_sec: i64 = 1;
    let value_nsec: i64 = 0;
    new_value[0..8].copy_from_slice(&interval_sec.to_le_bytes());
    new_value[8..16].copy_from_slice(&interval_nsec.to_le_bytes());
    new_value[16..24].copy_from_slice(&value_sec.to_le_bytes());
    new_value[24..32].copy_from_slice(&value_nsec.to_le_bytes());
    let r = call(
        Syscall::TimerfdSettime,
        SyscallArgs {
            arg0: tfd as u64,
            arg1: 0,
            arg2: new_value.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("settime !=0");
    }
    let mut got = [0u8; 32];
    let r = call(
        Syscall::TimerfdGettime,
        SyscallArgs {
            arg0: tfd as u64,
            arg1: got.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 0 {
        return TestResult::Fail("gettime returned non-zero");
    }
    let interval_sec_r = i64::from_le_bytes(got[0..8].try_into().unwrap());
    let interval_nsec_r = i64::from_le_bytes(got[8..16].try_into().unwrap());
    let value_sec_r = i64::from_le_bytes(got[16..24].try_into().unwrap());
    let value_nsec_r = i64::from_le_bytes(got[24..32].try_into().unwrap());
    if interval_sec_r != 0 || interval_nsec_r != 500_000_000 {
        return TestResult::Fail("gettime reported wrong interval");
    }
    // Remaining should be > 0 and ≤ 1 s.
    let total_ns = (value_sec_r as u64).saturating_mul(1_000_000_000) + value_nsec_r as u64;
    if total_ns == 0 || total_ns > 1_000_000_000 {
        return TestResult::Fail("gettime remaining out of range");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_timerfd_gettime_reports_remaining);

/// Wave-64: end-to-end — register an eventfd in an epoll instance,
/// write to it, and confirm epoll_wait returns the event with the
/// userdata round-tripped intact. Level-triggered (the io_mux
/// epoll variant).
#[cfg(feature = "linux-compat")]
fn smoke_wave64_epoll_watches_eventfd() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let task = setup_poll_test();
    // 1. epoll_create1
    let r = call(Syscall::EpollCreate, SyscallArgs::default());
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_create -1");
    }
    let epfd = r.value as u32;
    // 2. eventfd2 with initval = 0 — starts not-ready.
    let r = call(
        Syscall::Eventfd,
        SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value == (-1i64 as u64) {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("eventfd -1");
    }
    let efd = r.value as u32;
    // 3. epoll_ctl ADD efd with EPOLLIN + custom userdata.
    const USERDATA: u64 = 0x1234_5678_ABCD_EF01;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_le_bytes());
    ev[4..12].copy_from_slice(&USERDATA.to_le_bytes());
    let r = call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: efd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_ctl ADD");
    }
    // 4. epoll_wait(timeout=0) — should return 0 (eventfd counter = 0).
    let mut out = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    if r.status != SyscallReturn::OK || r.value != 0 {
        crate::syscall::__test_clear_global();
        return TestResult::Fail("epoll_wait expected 0 events");
    }
    // 5. Poke the eventfd directly via its FileOps to bump the counter.
    {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        unsafe fn no_op(_: *const ()) {}
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        // SAFETY: the `RawWaker` pairs a null data pointer with the static `VT`
        // vtable whose clone returns the same null waker and wake/drop are no-ops
        // that never dereference the data pointer, so it upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        let ops = crate::fd::with_table(task, |t| t.get(efd).map(|e| e.ops.clone()))
            .flatten()
            .expect("efd in table");
        let buf = 7u64.to_le_bytes();
        let mut fut = ops.write(0, &buf);
        let _ = fut.as_mut().poll(&mut cx);
    }
    // 6. epoll_wait — now the eventfd reports POLLIN and userdata
    //    round-trips.
    let mut out = [0u8; 12];
    let r = call(
        Syscall::EpollWait,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            ..SyscallArgs::default()
        },
    );
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || r.value != 1 {
        return TestResult::Fail("epoll_wait expected 1 event after eventfd bump");
    }
    let got_events = u32::from_le_bytes(out[..4].try_into().unwrap());
    let got_data = u64::from_le_bytes(out[4..12].try_into().unwrap());
    if got_events & crate::epoll::EPOLLIN == 0 {
        return TestResult::Fail("epoll_wait revents missing EPOLLIN");
    }
    if got_data != USERDATA {
        return TestResult::Fail("epoll_wait userdata mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_wave64_epoll_watches_eventfd);

/// EPOLLET must observe an eventfd drain/refill transition even when no epoll
/// scan occurs while the counter is zero. Both scans then see POLLIN, so the
/// provider's readable transition token is the only evidence of the new edge.
#[cfg(feature = "linux-compat")]
fn smoke_epoll_epollet_eventfd_hidden_refill_edge() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    setup_poll_test();
    let epfd = call(Syscall::EpollCreate, SyscallArgs::default()).value as u32;
    let efd = call(
        Syscall::Eventfd,
        SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
    )
    .value as u32;
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
    if call(
        Syscall::EpollCtl,
        SyscallArgs {
            arg0: epfd as u64,
            arg1: crate::epoll::EPOLL_CTL_ADD as u64,
            arg2: efd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
    )
    .value
        != 0
    {
        return TestResult::Fail("EPOLLET eventfd add failed");
    }

    let wait = |out: &mut [u8; 12]| {
        call(
            Syscall::EpollWait,
            SyscallArgs {
                arg0: epfd as u64,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                ..SyscallArgs::default()
            },
        )
    };
    let one = 1u64.to_ne_bytes();
    let mut out = [0u8; 12];
    if call(
        Syscall::Write,
        SyscallArgs {
            arg0: efd as u64,
            arg1: one.as_ptr() as u64,
            arg2: 8,
            ..SyscallArgs::default()
        },
    )
    .value
        != 8
        || wait(&mut out).value != 1
    {
        return TestResult::Fail("initial eventfd edge was not delivered");
    }

    let mut drained = [0u8; 8];
    if call(
        Syscall::Read,
        SyscallArgs {
            arg0: efd as u64,
            arg1: drained.as_mut_ptr() as u64,
            arg2: 8,
            ..SyscallArgs::default()
        },
    )
    .value
        != 8
    {
        return TestResult::Fail("eventfd drain failed");
    }
    // Refill before another epoll scan observes the zero-counter state.
    if call(
        Syscall::Write,
        SyscallArgs {
            arg0: efd as u64,
            arg1: one.as_ptr() as u64,
            arg2: 8,
            ..SyscallArgs::default()
        },
    )
    .value
        != 8
        || wait(&mut out).value != 1
    {
        return TestResult::Fail("EPOLLET lost hidden eventfd refill edge");
    }
    if wait(&mut out).value != 0 {
        return TestResult::Fail("eventfd refill edge was delivered more than once");
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_epoll_epollet_eventfd_hidden_refill_edge);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_signalfd_epoll_wakes_on_signal() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::handlers::__test_signal_reset;
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    crate::fd::__test_reset();
    __test_signal_reset();
    crate::handlers::signal_init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // current_task_id() must be 0 here so signalfd's owner_task matches
    // the kill(pid=0) target; drop any lookup an earlier test leaked.
    crate::handlers::__test_reset_task_id_lookup();

    // Create signalfd watching SIGUSR2 (signum 12). NARF's internal
    // pending layout now matches the userspace sigset_t (signal N at bit
    // N-1), so SIGUSR2 is bit 11 both in the user mask and internally.
    let mask: u64 = 1u64 << 11;
    let mask_bytes = mask.to_le_bytes();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: (-1i64) as u64,
            arg1: mask_bytes.as_ptr() as u64,
            arg2: 8,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Signalfd.raw(), &mut ctx);
    let sfd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => {
            __test_signal_reset();
            __test_clear_global();
            return TestResult::Fail("signalfd did not return a fd");
        }
    };

    crate::handlers::register_pid_task_mapping(0, 0);

    // Create epoll instance.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollCreate.raw(), &mut ctx);
    let epfd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => {
            __test_signal_reset();
            __test_clear_global();
            return TestResult::Fail("epoll_create failed");
        }
    };

    // ADD signalfd with EPOLLIN|EPOLLET.
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&(1u32 | (1u32 << 31)).to_le_bytes());
    ev[4..].copy_from_slice(&0xC0FFEEu64.to_le_bytes());
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: epfd as u64,
            arg1: 1, // EPOLL_CTL_ADD
            arg2: sfd as u64,
            arg3: ev.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollCtl.raw(), &mut ctx);

    // Raise SIGUSR2 for the signalfd's owner (task 0). This test
    // exercises signalfd + epoll wakeup, not kill(2) routing — and
    // kill(0) now means "the caller's process group" (Linux parity),
    // which for the artificial task-0 owner has no pgrp. Set the
    // pending bit directly, which is exactly what the old kill(pid=0)
    // literal-target path did.
    crate::handlers::raise_signal_pending(0, 12);

    // epoll_wait timeout=0 → should immediately see 1 ready event.
    let mut events = [0u8; 12 * 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: epfd as u64,
            arg1: events.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollWait.raw(), &mut ctx);
    let nready = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => 0,
    };

    let user_data = u64::from_le_bytes(events[4..12].try_into().unwrap());

    // Drain the signal and raise the same signal again before another epoll
    // scan observes the empty pending set. The per-task signal generation
    // must preserve this hidden refill edge.
    let mut siginfo = [0u8; 128];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: sfd as u64,
            arg1: siginfo.as_mut_ptr() as u64,
            arg2: siginfo.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 128) {
        return TestResult::Fail("failed to drain signalfd before hidden refill");
    }
    crate::handlers::raise_signal_pending(0, 12);
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: epfd as u64,
            arg1: events.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::EpollWait.raw(), &mut ctx);
    let refill_ready = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == 1
    );

    __test_signal_reset();
    crate::fd::__test_reset();
    __test_clear_global();

    if nready != 1 {
        return TestResult::Fail("epoll_wait did not return 1 ready");
    }
    if user_data != 0xC0FFEE {
        return TestResult::Fail("epoll_wait user_data not echoed");
    }
    if !refill_ready {
        return TestResult::Fail("EPOLLET lost hidden signalfd refill edge");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_signalfd_epoll_wakes_on_signal);
