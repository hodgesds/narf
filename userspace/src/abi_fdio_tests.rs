//! Linux syscall ABI conformance — fdio group.
use crate::abi_test_support::*;

// ── Local helpers ──────────────────────────────────────────────────
//
// Every fd-based test needs a real open fd against a MemFs file. The
// open(2) handler is registered as `sys_open_linux` under linux-compat
// and takes a NUL-terminated absolute path in arg0 (flags in arg1). It
// returns the new fd as the syscall value on success, or the `-1`
// sentinel on failure (status stays Ok either way), so `call` yields
// `Some(fd)` / `Some(-1)`. The first user-opened fd in a fresh table is
// 3 (0/1/2 are the pre-seeded stdio slots).

/// Open `path` (a `&[u8]` ending in NUL) read/write; return the fd or
/// an `Err` message. Linux access modes are now enforced, so request O_RDWR.
fn open_fd(path: &[u8]) -> Result<u32, &'static str> {
    let ptr = path.as_ptr() as u64;
    match call_open(ptr, crate::fd::O_RDWR as u64) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open failed"),
    }
}

fn open_fd_flags(path: &[u8], flags: u64) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, flags) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open with flags failed"),
    }
}

/// Create a pipe via `sys_pipe`; return `(read_fd, write_fd)`.
fn make_pipe() -> Result<(u32, u32), &'static str> {
    let mut buf = [0u8; 8];
    let r = call_raw(Syscall::Pipe.raw(), a0(buf.as_mut_ptr() as u64));
    if r.status != SyscallReturn::OK || r.value as i64 != 0 {
        return Err("pipe failed");
    }
    let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u32;
    let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u32;
    Ok((rd, wr))
}

// ── read / write ───────────────────────────────────────────────────

fn smoke_abi_fdio_read_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        let mut buf = [0u8; 8];
        // read(fd, buf, 8) → 2 bytes "hi" at the head of the MemFs file.
        match call(
            Syscall::Read.raw(),
            a2(fd as u64, buf.as_mut_ptr() as u64, 8),
        ) {
            Some(2) if &buf[..2] == b"hi" => Ok(()),
            _ => Err("read did not return the seeded bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_read_pos);

fn smoke_abi_fdio_read_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 4];
        // read(2) on a fd that isn't open → -EBADF (the early fd check keeps
        // this distinct from read I/O errors, which stay InvalidOp).
        match call(Syscall::Read.raw(), a2(4242, buf.as_mut_ptr() as u64, 4)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("read on a bad fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_read_neg);

// A FIFO read/write must re-enqueue an own-stack-parked peer by bumping the
// io-waiter generation (the fix for named-pipe reads sleeping to the ~1 ms
// lost-wake backstop instead of waking on the write — stress-ng --fifo 499 ->
// 43405 bogo-ops). A non-FIFO fd must not, so the gate is free for other fds.
fn smoke_fifo_read_write_bump_io_waiter_generation() -> TestResult {
    use narf_filesystem::fifo::{FifoHandle, FifoNode};
    use narf_filesystem::FileOps;

    let node = FifoNode::new(0x9f10, 0o666);
    let shared = match node.fifo_shared() {
        Some(s) => s,
        None => return TestResult::Fail("fifo node exposes no shared state"),
    };
    let writer = FifoHandle::open(shared.clone(), 0x9f10, 0o666, 0, 0, false, true);
    let reader = FifoHandle::open(shared, 0x9f10, 0o666, 0, 0, true, false);

    let g0 = narf_net::readiness::generation();
    crate::handlers::wake_fifo_io_waiters(&writer);
    let g1 = narf_net::readiness::generation();
    if g1 == g0 {
        return TestResult::Fail("fifo write did not bump the io-waiter generation");
    }
    crate::handlers::wake_fifo_io_waiters(&reader);
    if narf_net::readiness::generation() == g1 {
        return TestResult::Fail("fifo read did not bump the io-waiter generation");
    }

    // The downcast gate: a non-FIFO fd leaves the generation untouched.
    let g2 = narf_net::readiness::generation();
    let dev = narf_filesystem::devfs_misc::DevFull;
    crate::handlers::wake_fifo_io_waiters(&dev);
    if narf_net::readiness::generation() != g2 {
        return TestResult::Fail("a non-fifo fd wrongly bumped the io-waiter generation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "syscall_abi",
    smoke_fifo_read_write_bump_io_waiter_generation
);

fn smoke_abi_fdio_write_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_fd(b"/abi/f\0")?;
        let data = *b"abcd";
        // write(fd, data, 4) → 4 bytes written to the MemFs file.
        match call(Syscall::Write.raw(), a2(fd as u64, data.as_ptr() as u64, 4)) {
            Some(4) => Ok(()),
            _ => Err("write did not return 4"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_write_pos);

fn smoke_abi_fdio_write_neg() -> TestResult {
    with_setup(|| {
        let data = *b"x";
        // write(2) on a fd that isn't open → -EBADF (the early fd check keeps
        // this distinct from write rejections like a sealed memfd).
        match call(Syscall::Write.raw(), a2(9191, data.as_ptr() as u64, 1)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("write on a bad fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_write_neg);

// ── readv / writev ─────────────────────────────────────────────────
//
// iovec is { void *base; size_t len } (16 bytes). A zero-length write
// over zero iovecs returns 0; we build a single iovec into a kernel
// buffer.

fn smoke_abi_fdio_writev_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_fd(b"/abi/f\0")?;
        let payload = *b"hello";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        // writev(fd, iov, 1) → total bytes across the one iovec.
        match call(Syscall::Writev.raw(), a2(fd as u64, iov.as_ptr() as u64, 1)) {
            Some(5) => Ok(()),
            _ => Err("writev did not return 5"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_writev_pos);

fn smoke_abi_fdio_append_independent_ofds_share_inode_lock() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let flags = (crate::fd::O_WRONLY | crate::fd::O_APPEND) as u64;
        let left = open_fd_flags(b"/abi/f\0", flags)?;
        let right = open_fd_flags(b"/abi/f\0", flags)?;
        let task = crate::handlers::current_task_id();
        let shared = crate::fd::with_table(task, |table| {
            let left = table.description(left)?;
            let right = table.description(right)?;
            Some(core::ptr::eq(left.append_lock(), right.append_lock()))
        })
        .flatten()
        .unwrap_or(false);
        if !shared {
            return Err("independent append OFDs did not share the inode append lock");
        }
        for (fd, byte) in [(left, [b'A']), (right, [b'B'])] {
            if call(Syscall::Write.raw(), a2(fd as u64, byte.as_ptr() as u64, 1)) != Some(1) {
                return Err("independent O_APPEND write failed");
            }
        }
        let reader = open_fd_flags(b"/abi/f\0", crate::fd::O_RDONLY as u64)?;
        let mut bytes = [0u8; 2];
        match call(
            Syscall::Read.raw(),
            a2(reader as u64, bytes.as_mut_ptr() as u64, bytes.len() as u64),
        ) {
            Some(2) if &bytes == b"AB" => Ok(()),
            _ => Err("independent O_APPEND writes overwrote one another"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_append_independent_ofds_share_inode_lock
);

fn smoke_abi_fdio_writev_neg() -> TestResult {
    with_setup(|| {
        // iovcnt > IOV_MAX (1024) → -EINVAL (Ok status, value -22).
        match call(Syscall::Writev.raw(), a2(1, 0x1000, 2000)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("writev over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_writev_neg);

fn smoke_abi_fdio_readv_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"world")], || {
        let fd = open_fd(b"/abi/f\0")?;
        let mut dst = [0u8; 8];
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(8u64).to_le_bytes());
        // readv(fd, iov, 1) → 5 bytes "world".
        match call(Syscall::Readv.raw(), a2(fd as u64, iov.as_ptr() as u64, 1)) {
            Some(5) if &dst[..5] == b"world" => Ok(()),
            _ => Err("readv did not return the seeded bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_readv_pos);

fn smoke_abi_fdio_readv_neg() -> TestResult {
    with_setup(|| {
        // iovcnt > IOV_MAX → -EINVAL.
        match call(Syscall::Readv.raw(), a2(0, 0x1000, 2000)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("readv over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_readv_neg);

// ── preadv / pwritev ───────────────────────────────────────────────

fn smoke_abi_fdio_pwritev_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_fd(b"/abi/f\0")?;
        let payload = *b"PQRS";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        // pwritev(fd, iov, 1, offset=0) → 4 bytes.
        match call(
            Syscall::Pwritev.raw(),
            a3(fd as u64, iov.as_ptr() as u64, 1, 0),
        ) {
            Some(4) => Ok(()),
            _ => Err("pwritev did not return 4"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pwritev_pos);

fn smoke_abi_fdio_pwritev_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        // iovcnt > IOV_MAX → -EINVAL. The fd must be OPEN for that to be the
        // failure under test: `do_pwritev` resolves the descriptor first, so
        // a closed one reports -EBADF before import_iovec ever runs.
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::Pwritev.raw(), a3(fd as u64, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pwritev over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pwritev_neg);

fn smoke_abi_fdio_preadv_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd(b"/abi/f\0")?;
        let mut dst = [0u8; 8];
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(8u64).to_le_bytes());
        // preadv(fd, iov, 1, offset=2) → reads "cdef" (4 bytes).
        match call(
            Syscall::Preadv.raw(),
            a3(fd as u64, iov.as_ptr() as u64, 1, 2),
        ) {
            Some(4) if &dst[..4] == b"cdef" => Ok(()),
            _ => Err("preadv at offset 2 did not return cdef"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_preadv_pos);

fn smoke_abi_fdio_preadv_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        // As in the pwritev case: an open fd, so -EINVAL from IOV_MAX is what
        // is being asserted rather than -EBADF from the fd lookup.
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::Preadv.raw(), a3(fd as u64, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("preadv over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_preadv_neg);

// ── close ──────────────────────────────────────────────────────────

fn smoke_abi_fdio_close_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::Close.raw(), a0(fd as u64)) {
            Some(0) => Ok(()),
            _ => Err("close of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_close_pos);

// POSIX open(2): the returned fd is the LOWEST-numbered descriptor not
// currently open. So after closing a low fd, the next open must reuse it
// — not bump to a fresh high slot. busybox ash depends on this exact
// guarantee: to redirect an async job's stdin it does
// `close(0); if (open("/dev/null") != 0) perror`, asserting the reopened
// fd is exactly 0. NARF's fd table used to skip 0..=2 unconditionally, so
// every `cmd &` in the distro died with "can't open '/dev/null'".
fn smoke_abi_fdio_open_reuses_lowest_closed_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let a = open_fd(b"/abi/f\0")?; // first user fd: 3
        let b = open_fd(b"/abi/f\0")?; // next: 4
        if a != 3 || b != 4 {
            return Err("unexpected initial fd allocation (expected 3,4)");
        }
        // Close the lower of the two; the next open MUST reclaim it.
        match call(Syscall::Close.raw(), a0(a as u64)) {
            Some(0) => {}
            _ => return Err("close failed"),
        }
        let c = open_fd(b"/abi/f\0")?;
        if c != a {
            return Err("open did not reuse the lowest closed fd (POSIX violation)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_open_reuses_lowest_closed_fd);

fn smoke_abi_fdio_close_neg() -> TestResult {
    with_setup(|| {
        // close(2) on a fd that isn't open → -EBADF (now Linux-conformant).
        match call(Syscall::Close.raw(), a0(7777)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("close on a bad fd should return -EBADF (-9)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_close_neg);

// ── close_range ────────────────────────────────────────────────────

fn smoke_abi_fdio_close_range_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // close_range(fd, fd, 0) → 0; range covers exactly the open fd.
        match call(Syscall::CloseRange.raw(), a2(fd as u64, fd as u64, 0)) {
            Some(0) => Ok(()),
            _ => Err("close_range did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_close_range_pos);

fn smoke_abi_fdio_close_range_neg() -> TestResult {
    with_setup(|| {
        // first > last → -EINVAL.
        match call(Syscall::CloseRange.raw(), a2(10, 5, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("close_range first>last was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_close_range_neg);

// ── dup / dup2 / dup3 ──────────────────────────────────────────────

fn smoke_abi_fdio_dup_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // dup(fd) → a new fd (> the original, lowest free slot).
        match call(Syscall::Dup.raw(), a0(fd as u64)) {
            Some(n) if n >= 0 && n as u32 != fd => Ok(()),
            _ => Err("dup did not return a fresh fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup_pos);

fn smoke_abi_fdio_dup_neg() -> TestResult {
    with_setup(|| {
        // LINUX ABI: dup(2) on a fd that is not open returns -EBADF (previously
        // folded to a non-Ok InvalidOp status). Shells actively probe EBADF.
        match call(Syscall::Dup.raw(), a0(6543)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("dup on bad fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup_neg);

fn smoke_abi_fdio_dup2_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // dup2(fd, 50) → returns the requested newfd (50).
        match call_dup2(fd as u64, 50) {
            Some(50) => Ok(()),
            _ => Err("dup2 did not return the requested newfd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup2_pos);

fn smoke_abi_fdio_dup2_neg() -> TestResult {
    with_setup(|| {
        // dup2 from a bad oldfd → InvalidOp.
        // LINUX-GAP: Linux returns -EBADF.
        match call_dup2(8888, 50) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup2_neg);

fn smoke_abi_fdio_dup3_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // dup3(fd, 51, 0) → returns newfd (51).
        match call(Syscall::Dup3.raw(), a2(fd as u64, 51, 0)) {
            Some(51) => Ok(()),
            _ => Err("dup3 did not return the requested newfd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup3_pos);

fn smoke_abi_fdio_dup3_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // dup3 requires oldfd != newfd (unlike dup2) → -EINVAL when equal.
        match call_raw(Syscall::Dup3.raw(), a2(fd as u64, fd as u64, 0)) {
            r if r.status == SyscallReturn::OK && r.value as i64 == -22 => {}
            _ => return Err("dup3(fd, fd, 0) was not -EINVAL"),
        }
        // Only O_CLOEXEC is accepted. The numerically-small FD_CLOEXEC slot
        // bit and every unknown flag are rejected before oldfd lookup.
        for flags in [1u64, 0x4000_0000] {
            match call_raw(Syscall::Dup3.raw(), a2(8888, 52, flags)) {
                r if r.status == SyscallReturn::OK && r.value as i64 == -22 => {}
                _ => return Err("dup3 unknown flags did not precede bad-oldfd EBADF"),
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup3_neg);

// ── fcntl ──────────────────────────────────────────────────────────
//
// F_GETFD = 1, F_SETFD = 2.

fn smoke_abi_fdio_fcntl_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        const F_SETFD: u64 = 2;
        const F_GETFD: u64 = 1;
        const FD_CLOEXEC: i64 = 1;
        // F_SETFD sets FD_CLOEXEC → 0; F_GETFD reads it back.
        if call(Syscall::Fcntl.raw(), a2(fd as u64, F_SETFD, 1)) != Some(0) {
            return Err("F_SETFD did not return 0");
        }
        match call(Syscall::Fcntl.raw(), a2(fd as u64, F_GETFD, 0)) {
            Some(v) if v == FD_CLOEXEC => Ok(()),
            _ => Err("F_GETFD did not read back FD_CLOEXEC"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fcntl_pos);

fn smoke_abi_fdio_fcntl_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // An unknown fcntl cmd falls through to InvalidOp.
        // LINUX-GAP: Linux returns -EINVAL for an unknown command.
        match call_raw(Syscall::Fcntl.raw(), a2(fd as u64, 9999, 0)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("fcntl unknown cmd was not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fcntl_neg);

// ── ioctl ──────────────────────────────────────────────────────────

fn smoke_abi_fdio_ioctl_neg_badfd() -> TestResult {
    with_setup(|| {
        // ioctl on a closed fd → -EBADF (Ok status, value -9).
        match call(Syscall::Ioctl.raw(), a2(3131, 0x5401, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("ioctl on bad fd was not -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_ioctl_neg_badfd);

fn smoke_abi_fdio_ioctl_pos_enotty() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // A valid fd with an unrecognised cmd → -ENOTTY (the MemFs
        // FileOps has no matching ioctl). This is the reachable "valid
        // fd" path; ENOTTY is the correct Linux answer for a regular
        // file given a tty ioctl.
        match call(Syscall::Ioctl.raw(), a2(fd as u64, 0x5401, 0)) {
            Some(v) if v == ENOTTY => Ok(()),
            _ => Err("ioctl on a regular file was not -ENOTTY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_ioctl_pos_enotty);

// ── lseek ──────────────────────────────────────────────────────────
//
// SEEK_SET = 0, SEEK_END = 2.

fn smoke_abi_fdio_lseek_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // lseek(fd, 3, SEEK_SET) → new offset 3.
        match call(Syscall::Lseek.raw(), a2(fd as u64, 3, 0)) {
            Some(3) => Ok(()),
            _ => Err("lseek SEEK_SET did not return 3"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_lseek_pos);

fn smoke_abi_fdio_lseek_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // An unknown whence → InvalidOp.
        // LINUX-GAP: Linux lseek(2) with a bad whence returns -EINVAL.
        match call(Syscall::Lseek.raw(), a2(fd as u64, 0, 99)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("expected -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_lseek_neg);

// ── fstat ──────────────────────────────────────────────────────────

fn smoke_abi_fdio_fstat_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // fstat(fd, statbuf) → 0 on success (linux Stat struct is large;
        // a 256-byte kernel buffer is ample).
        let mut stat = [0u8; 256];
        match call(
            Syscall::Fstat.raw(),
            a1(fd as u64, stat.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("fstat of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fstat_pos);

fn smoke_abi_fdio_fstat_neg() -> TestResult {
    with_setup(|| {
        let mut stat = [0u8; 256];
        // `fs/stat.c::vfs_fstat` opens with `fd_empty(f) -> -EBADF`, and it
        // runs before `cp_new_stat` ever looks at the destination.
        match call(Syscall::Fstat.raw(), a1(5252, stat.as_mut_ptr() as u64)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fstat on a bad fd must return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fstat_neg);

// ── fstatfs ────────────────────────────────────────────────────────
//
// The handler ignores the fd and fills synthetic "/" statfs into the
// user buffer. The positive path needs a real user buffer the kernel
// copy_to_user can write — in this harness there is no live user AS, so
// only the buf_ptr==0 failure path is asserted.

fn smoke_abi_fdio_fstatfs_neg() -> TestResult {
    with_setup(|| {
        // buf_ptr == 0 → fail sentinel (!0 == -1 as i64).
        match call(Syscall::Fstatfs.raw(), a1(3, 0)) {
            Some(-1) => Ok(()),
            _ => Err("fstatfs with null buf was not the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fstatfs_neg);

// ── ftruncate ──────────────────────────────────────────────────────

fn smoke_abi_fdio_ftruncate_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // ftruncate(fd, 3) → 0 (MemFs supports truncate).
        match call(Syscall::Ftruncate.raw(), a1(fd as u64, 3)) {
            Some(0) => Ok(()),
            _ => Err("ftruncate of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_ftruncate_pos);

fn smoke_abi_fdio_ftruncate_neg() -> TestResult {
    with_setup(|| {
        // `fs/open.c::do_sys_ftruncate`: `if (fd_empty(f)) return -EBADF;`.
        match call(Syscall::Ftruncate.raw(), a1(4949, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("ftruncate on bad fd was not -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_ftruncate_neg);

// ── fallocate ──────────────────────────────────────────────────────

fn smoke_abi_fdio_fallocate_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // fallocate(fd, mode=0, offset=0, len=16) → 0 (grows via truncate).
        match call(Syscall::Fallocate.raw(), a3(fd as u64, 0, 0, 16)) {
            Some(0) => Ok(()),
            _ => Err("fallocate of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fallocate_pos);

fn smoke_abi_fdio_fallocate_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // An unsupported mode returns Linux -EOPNOTSUPP.
        match call(Syscall::Fallocate.raw(), a3(fd as u64, 0x40, 0, 16)) {
            Some(-95) => Ok(()),
            _ => Err("fallocate bad mode was not -EOPNOTSUPP"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fallocate_neg);

// ── fsync / fdatasync ──────────────────────────────────────────────
//
// Fdatasync is wired to the same `sys_fsync` handler.

fn smoke_abi_fdio_fsync_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::Fsync.raw(), a0(fd as u64)) {
            Some(0) => Ok(()),
            _ => Err("fsync of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fsync_pos);

fn smoke_abi_fdio_fsync_neg() -> TestResult {
    with_setup(|| {
        // bad fd → -1 sentinel.
        // LINUX-GAP: Linux fsync(2) returns -EBADF.
        match call(Syscall::Fsync.raw(), a0(4040)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fsync_neg);

fn smoke_abi_fdio_fdatasync_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::Fdatasync.raw(), a0(fd as u64)) {
            Some(0) => Ok(()),
            _ => Err("fdatasync of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fdatasync_pos);

fn smoke_abi_fdio_fdatasync_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux fdatasync(2) returns -EBADF.
        match call(Syscall::Fdatasync.raw(), a0(4041)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fdatasync_neg);

// ── fadvise64 / readahead / sync_file_range ────────────────────────
//
// All three are accept-for-valid-fd / EBADF-otherwise stubs.

fn smoke_abi_fdio_fadvise64_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // fadvise64(fd, offset, len, advice) → 0 for a valid fd.
        match call(Syscall::Fadvise64.raw(), a3(fd as u64, 0, 16, 0)) {
            Some(0) => Ok(()),
            _ => Err("fadvise64 of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fadvise64_pos);

fn smoke_abi_fdio_fadvise64_neg() -> TestResult {
    with_setup(|| {
        // bad fd → -EBADF (Ok status, value -9).
        match call(Syscall::Fadvise64.raw(), a3(3535, 0, 16, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("fadvise64 on bad fd was not -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_fadvise64_neg);

fn smoke_abi_fdio_readahead_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::Readahead.raw(), a2(fd as u64, 0, 16)) {
            Some(0) => Ok(()),
            _ => Err("readahead of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_readahead_pos);

fn smoke_abi_fdio_readahead_neg() -> TestResult {
    with_setup(|| match call(Syscall::Readahead.raw(), a2(3636, 0, 16)) {
        Some(v) if v == EBADF => Ok(()),
        _ => Err("readahead on bad fd was not -EBADF"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_readahead_neg);

fn smoke_abi_fdio_sync_file_range_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        match call(Syscall::SyncFileRange.raw(), a3(fd as u64, 0, 16, 0)) {
            Some(0) => Ok(()),
            _ => Err("sync_file_range of a valid fd did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_sync_file_range_pos);

fn smoke_abi_fdio_sync_file_range_neg() -> TestResult {
    with_setup(
        || match call(Syscall::SyncFileRange.raw(), a3(3737, 0, 16, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("sync_file_range on bad fd was not -EBADF"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_sync_file_range_neg);

// ── sync / syncfs ──────────────────────────────────────────────────
//
// `sync` has no error path; `syncfs` validates and flushes its fd's
// backing filesystem.

fn smoke_abi_fdio_sync_pos() -> TestResult {
    with_setup(|| match call(Syscall::Sync.raw(), a0(0)) {
        Some(0) => Ok(()),
        _ => Err("sync did not return 0"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_sync_pos);

fn smoke_abi_fdio_syncfs_pos() -> TestResult {
    with_setup(|| {
        match (
            call(Syscall::Syncfs.raw(), a0(0)),
            call(Syscall::Syncfs.raw(), a0(9999)),
        ) {
            (Some(0), Some(-9)) => Ok(()),
            _ => Err("syncfs did not flush a valid fd or reject a bad fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_syncfs_pos);

// ── pipe / pipe2 ───────────────────────────────────────────────────

fn smoke_abi_fdio_pipe_pos() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        if wr <= rd {
            return Err("pipe write fd not above read fd");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_pos);

fn smoke_abi_fdio_pipe_fionread() -> TestResult {
    with_setup(|| {
        const FIONREAD: u64 = 0x541B;
        let (rd, wr) = make_pipe()?;
        let payload = b"plasma";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("pipe write failed");
        }
        let mut available = 0i32;
        if call(
            Syscall::Ioctl.raw(),
            a2(rd as u64, FIONREAD, (&mut available as *mut i32) as u64),
        ) != Some(0)
        {
            return Err("FIONREAD on pipe failed");
        }
        if available != payload.len() as i32 {
            return Err("FIONREAD reported the wrong pipe byte count");
        }
        // pipe_ioctl returns put_user() directly: an inaccessible output
        // pointer is EFAULT, while an unknown pipe ioctl is ENOTTY after
        // vfs_ioctl translates the driver's internal ENOIOCTLCMD.
        if call(Syscall::Ioctl.raw(), a2(rd as u64, FIONREAD, 0x1000)) != Some(EFAULT) {
            return Err("pipe FIONREAD bad result pointer was not -EFAULT");
        }
        if call(Syscall::Ioctl.raw(), a2(rd as u64, 0xDEAD_BEEF, 0)) != Some(-25) {
            return Err("unsupported pipe ioctl was not -ENOTTY");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_fionread);

fn smoke_abi_fdio_pipe_write_closed_reader_is_epipe() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        if call(Syscall::Close.raw(), a0(rd as u64)) != Some(0) {
            return Err("closing pipe reader failed");
        }
        let payload = b"x";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(EPIPE)
        {
            return Err("write with no pipe readers was not -EPIPE");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe_write_closed_reader_is_epipe
);

fn smoke_abi_fdio_pipe_neg() -> TestResult {
    with_setup(|| {
        // LINUX ABI: pipe(2) with a NULL fd-array pointer → -EFAULT (previously
        // folded to a non-Ok InvalidOp status).
        match call(Syscall::Pipe.raw(), a0(0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("pipe with null buffer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_neg);

fn smoke_abi_fdio_pipe2_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 8];
        // pipe2(buf, O_CLOEXEC) → 0.
        const O_CLOEXEC: u64 = 0x80000;
        match call(Syscall::Pipe2.raw(), a1(buf.as_mut_ptr() as u64, O_CLOEXEC)) {
            Some(0) => Ok(()),
            _ => Err("pipe2 did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe2_pos);

fn smoke_abi_fdio_pipe2_neg() -> TestResult {
    with_setup(|| {
        // LINUX ABI: pipe2(2) with a NULL fd-array pointer → -EFAULT (previously
        // folded to a non-Ok InvalidOp status).
        match call(Syscall::Pipe2.raw(), a1(0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("pipe2 with null buffer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe2_neg);

/// pipe2(2) flag validation — `fs/pipe.c::__do_pipe_flags`: any flag outside
/// O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE is -EINVAL.
fn smoke_abi_fdio_pipe2_bad_flags_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 8];
        // O_APPEND is not a pipe2 flag → -EINVAL.
        const O_APPEND: u64 = 0o2000;
        if call(Syscall::Pipe2.raw(), a1(buf.as_mut_ptr() as u64, O_APPEND)) != Some(EINVAL) {
            return Err("pipe2(O_APPEND) was not -EINVAL");
        }
        // Linux validates flags before touching fildes.
        if call(Syscall::Pipe2.raw(), a1(0, crate::fd::O_APPEND as u64)) != Some(EINVAL) {
            return Err("pipe2(NULL, O_APPEND) did not prioritize -EINVAL");
        }
        // The kernel ABI receives flags as an `int`, so unused high register
        // bits are truncated instead of participating in validation.
        let mut high_bits = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(high_bits.as_mut_ptr() as u64, 1u64 << 32),
        ) != Some(0)
        {
            return Err("pipe2 did not truncate flags to Linux int width");
        }
        let high_rd = i32::from_ne_bytes(high_bits[..4].try_into().unwrap()) as u32;
        let high_wr = i32::from_ne_bytes(high_bits[4..].try_into().unwrap()) as u32;
        let task = crate::handlers::current_task_id();
        let _ = crate::fd::with_table(task, |table| {
            table.close(high_rd);
            table.close(high_wr);
        });
        // O_NOTIFICATION_PIPE aliases O_EXCL (0200). With CONFIG_WATCH_QUEUE
        // absent Linux recognizes the flag and reports ENOPKG.
        const O_NOTIFICATION_PIPE: u64 = 0o200;
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NOTIFICATION_PIPE),
        ) != Some(-65)
        {
            return Err("pipe2(O_NOTIFICATION_PIPE) was not -ENOPKG");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe2_bad_flags_neg);

fn smoke_abi_fdio_pipe_efault_does_not_publish_fds() -> TestResult {
    with_setup(|| {
        let task = crate::handlers::current_task_id();
        let before = crate::fd::with_table(task, |table| table.open_fd_numbers().len())
            .ok_or("missing fd table")?;
        // Canonical user address, but deliberately unmapped: allocation has
        // happened before the guarded copy discovers EFAULT.
        if call(Syscall::Pipe2.raw(), a1(0x1000, 0)) != Some(EFAULT) {
            return Err("pipe2 to unmapped fildes was not -EFAULT");
        }
        let after = crate::fd::with_table(task, |table| table.open_fd_numbers().len())
            .ok_or("missing fd table after pipe2 EFAULT")?;
        if after != before {
            return Err("pipe2 EFAULT published or leaked descriptors");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe_efault_does_not_publish_fds
);

fn smoke_abi_fdio_pipe_emfile_precedes_bad_fildes() -> TestResult {
    with_setup(|| {
        // do_pipe2 calls __do_pipe_flags (including both fd reservations)
        // before copy_to_user. With no descriptor number available, EMFILE
        // therefore wins over the otherwise-faulting fildes pointer.
        let limit = [0u64, 4096];
        if call(
            Syscall::Setrlimit.raw(),
            a1(7, limit.as_ptr() as u64), // RLIMIT_NOFILE
        ) != Some(0)
        {
            return Err("could not lower RLIMIT_NOFILE for pipe EMFILE test");
        }
        if call(Syscall::Pipe.raw(), a0(0)) != Some(-24) {
            return Err("pipe(NULL) at RLIMIT_NOFILE did not prioritize -EMFILE");
        }
        if call(Syscall::Pipe2.raw(), a1(0, 0)) != Some(-24) {
            return Err("pipe2(NULL, 0) at RLIMIT_NOFILE did not prioritize -EMFILE");
        }
        // Flag validation is earlier still and remains EINVAL.
        if call(Syscall::Pipe2.raw(), a1(0, crate::fd::O_APPEND as u64)) != Some(EINVAL) {
            return Err("pipe2 bad flags did not prioritize -EINVAL over -EMFILE");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe_emfile_precedes_bad_fildes
);

fn smoke_abi_fdio_pipe_size_errno_and_rounding() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        const F_SETPIPE_SZ: u64 = 1031;
        const F_GETPIPE_SZ: u64 = 1032;
        let regular = open_fd(b"/abi/f\0")?;
        if call(Syscall::Fcntl.raw(), a2(regular as u64, F_GETPIPE_SZ, 0)) != Some(EBADF)
            || call(Syscall::Fcntl.raw(), a2(regular as u64, F_SETPIPE_SZ, 4096)) != Some(EBADF)
        {
            return Err("pipe-size fcntl on a non-pipe was not -EBADF");
        }

        let (rd, wr) = make_pipe()?;
        // Linux rounds sub-page sizes up to one page.
        if call(Syscall::Fcntl.raw(), a2(wr as u64, F_SETPIPE_SZ, 1)) != Some(4096)
            || call(Syscall::Fcntl.raw(), a2(rd as u64, F_GETPIPE_SZ, 0)) != Some(4096)
        {
            return Err("F_SETPIPE_SZ did not round to one page");
        }
        // Restore two pages, fill both, then reject a one-page shrink with
        // EBUSY because two live pipe buffers cannot fit.
        if call(Syscall::Fcntl.raw(), a2(wr as u64, F_SETPIPE_SZ, 8192)) != Some(8192) {
            return Err("F_SETPIPE_SZ could not grow to two pages");
        }
        let payload = [0x5au8; 8192];
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(8192)
        {
            return Err("two-page pipe fill failed");
        }
        if call(Syscall::Fcntl.raw(), a2(wr as u64, F_SETPIPE_SZ, 4096)) != Some(-16) {
            return Err("occupied pipe shrink was not -EBUSY");
        }
        // round_pipe_size rejects values above 2 GiB before allocation.
        if call(
            Syscall::Fcntl.raw(),
            a2(wr as u64, F_SETPIPE_SZ, u32::MAX as u64),
        ) != Some(EINVAL)
        {
            return Err("oversized F_SETPIPE_SZ was not -EINVAL");
        }
        // NARF has no privileged root bypass; growth above Linux's default
        // pipe-max-size therefore follows the unprivileged EPERM path.
        if call(Syscall::Fcntl.raw(), a2(wr as u64, F_SETPIPE_SZ, 1_048_577)) != Some(EPERM) {
            return Err("F_SETPIPE_SZ above pipe-max-size was not -EPERM");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_size_errno_and_rounding);

const O_DIRECT_FLAG: u64 = 0o40000;

/// Open a packet-mode pipe, returning `(read fd, write fd)`.
fn make_packet_pipe(extra: u64) -> Result<(u64, u64), &'static str> {
    let mut buf = [0u8; 8];
    if call(
        Syscall::Pipe2.raw(),
        a1(buf.as_mut_ptr() as u64, O_DIRECT_FLAG | extra),
    ) != Some(0)
    {
        return Err("pipe2(O_DIRECT) failed");
    }
    let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
    let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
    Ok((rd, wr))
}

/// `pipe2(O_DIRECT)` is packet mode: `pipe_write` gives each write its own
/// buffer tagged `PIPE_BUF_FLAG_PACKET` (`fs/pipe.c::is_packetized`), and
/// `pipe_read` stops at the end of one such buffer:
///
///     /* Was it a packet buffer? Clean up and exit */
///     if (buf->flags & PIPE_BUF_FLAG_PACKET) {
///             total_len = chars;
///             buf->len = 0;
///     }
///
/// So a read large enough for both records still returns only the first. The
/// byte-stream control arm is the point of the test: without it, a read that
/// returned 3 could simply mean the second write had not landed yet.
fn smoke_abi_fdio_pipe2_direct_preserves_record_boundaries() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let (rd, wr) = make_packet_pipe(O_NONBLOCK)?;
        for payload in [b"abc".as_slice(), b"defgh".as_slice()] {
            if call(
                Syscall::Write.raw(),
                a2(wr, payload.as_ptr() as u64, payload.len() as u64),
            ) != Some(payload.len() as i64)
            {
                return Err("packet-pipe write failed");
            }
        }
        // One read, buffer far larger than both records: exactly the first.
        let mut dst = [0u8; 64];
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 64)) != Some(3) {
            return Err("packet read crossed a record boundary");
        }
        if &dst[..3] != b"abc" {
            return Err("packet read returned the wrong first record");
        }
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 64)) != Some(5) {
            return Err("second packet read did not return the second record");
        }
        if &dst[..5] != b"defgh" {
            return Err("packet read returned the wrong second record");
        }
        // Control: the same two writes on a byte-stream pipe coalesce, so a
        // 64-byte read takes all 8 bytes at once. This is what proves the
        // boundary above came from O_DIRECT and not from write scheduling.
        let (rd2, wr2) = make_pipe()?;
        for payload in [b"abc".as_slice(), b"defgh".as_slice()] {
            if call(
                Syscall::Write.raw(),
                a2(wr2 as u64, payload.as_ptr() as u64, payload.len() as u64),
            ) != Some(payload.len() as i64)
            {
                return Err("stream-pipe write failed");
            }
        }
        if call(
            Syscall::Read.raw(),
            a2(rd2 as u64, dst.as_mut_ptr() as u64, 64),
        ) != Some(8)
        {
            return Err("stream pipe did not coalesce two writes into one read");
        }
        if &dst[..8] != b"abcdefgh" {
            return Err("stream pipe returned the wrong bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe2_direct_preserves_record_boundaries
);

/// `buf->len = 0` in the packet arm of `pipe_read` retires the whole buffer
/// however few bytes were copied, so a read too small for the packet returns
/// the truncated prefix and the REMAINDER IS LOST — pipe(7): "the excess bytes
/// in the packet are discarded".
///
/// This is the arm most easily got wrong by returning the leftover on the next
/// read, which silently turns one record into two and desynchronises every
/// subsequent one. The O_NONBLOCK EAGAIN is what makes "nothing left" testable
/// without blocking.
fn smoke_abi_fdio_pipe2_direct_short_read_discards_remainder() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let (rd, wr) = make_packet_pipe(O_NONBLOCK)?;
        let payload = b"0123456789";
        if call(
            Syscall::Write.raw(),
            a2(wr, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("packet write failed");
        }
        let mut dst = [0u8; 16];
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 4)) != Some(4) {
            return Err("short packet read did not return the requested prefix");
        }
        if &dst[..4] != b"0123" {
            return Err("short packet read returned the wrong prefix");
        }
        // The other six bytes are gone, not queued.
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 16)) != Some(EAGAIN) {
            return Err("packet remainder survived a short read");
        }
        // Control: a byte-stream pipe keeps the remainder, so the same
        // sequence yields the other six bytes. Without this, a broken read
        // that returned EAGAIN for every follow-up would still pass above.
        let (rd2, wr2) = make_pipe()?;
        if call(
            Syscall::Write.raw(),
            a2(wr2 as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("stream write failed");
        }
        if call(
            Syscall::Read.raw(),
            a2(rd2 as u64, dst.as_mut_ptr() as u64, 4),
        ) != Some(4)
        {
            return Err("stream short read did not return 4 bytes");
        }
        if call(
            Syscall::Read.raw(),
            a2(rd2 as u64, dst.as_mut_ptr() as u64, 16),
        ) != Some(6)
        {
            return Err("stream pipe lost the remainder of a partially-read write");
        }
        if &dst[..6] != b"456789" {
            return Err("stream pipe returned the wrong remainder");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe2_direct_short_read_discards_remainder
);

/// `pipe_full()` compares the BUFFER count against `pipe->max_usage`
/// (`PIPE_DEF_BUFFERS` = 16), not a byte count. Each packet write claims a
/// buffer of its own, so sixteen one-byte packets fill a 64 KiB pipe and the
/// seventeenth write must block — -EAGAIN under O_NONBLOCK.
///
/// A byte-capacity-only model passes every other packet test and fails only
/// here, by accepting writes into a pipe Linux considers full; the writer then
/// never gets the EAGAIN it uses to switch to polling.
fn smoke_abi_fdio_pipe2_direct_buffer_count_is_the_limit() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let (rd, wr) = make_packet_pipe(O_NONBLOCK)?;
        let byte = b"x";
        for i in 0..16 {
            if call(Syscall::Write.raw(), a2(wr, byte.as_ptr() as u64, 1)) != Some(1) {
                return Err("packet pipe rejected a write below the buffer limit");
            }
            let _ = i;
        }
        // 16 buffers queued, 16 bytes of a 65536-byte pipe used.
        if call(Syscall::Write.raw(), a2(wr, byte.as_ptr() as u64, 1)) != Some(EAGAIN) {
            return Err("packet pipe accepted a 17th buffer");
        }
        // Draining one record frees exactly one buffer.
        let mut dst = [0u8; 8];
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 8)) != Some(1) {
            return Err("packet read did not return one 1-byte record");
        }
        if call(Syscall::Write.raw(), a2(wr, byte.as_ptr() as u64, 1)) != Some(1) {
            return Err("freeing a buffer did not make the packet pipe writable");
        }
        // Control: on a byte-stream pipe those writes merge into one buffer,
        // so seventeen of them are nowhere near full.
        let (_rd2, wr2) = make_pipe()?;
        for _ in 0..17 {
            if call(
                Syscall::Write.raw(),
                a2(wr2 as u64, byte.as_ptr() as u64, 1),
            ) != Some(1)
            {
                return Err("stream pipe hit a buffer limit it should not have");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe2_direct_buffer_count_is_the_limit
);

/// `create_pipe_files` puts O_DIRECT on the WRITE file only:
///
///     f = alloc_file_pseudo(inode, pipe_mnt, "",
///                     O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT)), ...);
///     res[0] = alloc_file_clone(f, O_RDONLY | (flags & O_NONBLOCK), ...);
///
/// so F_GETFL on the read end must not report it. Packet framing is a property
/// of how records are written, and a reader that saw O_DIRECT on its own fd
/// could reasonably conclude the pipe was in packet mode when the writer had
/// never asked for it.
fn smoke_abi_fdio_pipe2_direct_is_on_the_write_end_only() -> TestResult {
    with_setup(|| {
        const F_GETFL: u64 = 3;
        const O_WRONLY: u64 = 1;
        let (rd, wr) = make_packet_pipe(0)?;
        match call(Syscall::Fcntl.raw(), a2(rd, F_GETFL, 0)) {
            Some(v) if v as u64 & O_DIRECT_FLAG == 0 => {}
            Some(_) => return Err("F_GETFL on the pipe read end reported O_DIRECT"),
            None => return Err("F_GETFL on the pipe read end failed"),
        }
        match call(Syscall::Fcntl.raw(), a2(wr, F_GETFL, 0)) {
            Some(v) if v as u64 & (O_DIRECT_FLAG | O_WRONLY) == O_DIRECT_FLAG | O_WRONLY => Ok(()),
            Some(_) => Err("F_GETFL on the pipe write end lacks O_DIRECT|O_WRONLY"),
            None => Err("F_GETFL on the pipe write end failed"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe2_direct_is_on_the_write_end_only
);

/// `is_packetized(filp)` reads `filp->f_flags` on every `pipe_write`, so
/// `fcntl(F_SETFL, O_DIRECT)` reframes subsequent writes on a pipe that was
/// created as a byte stream — and clearing it reverts them.
///
/// Recording the flag only in the fd's status word would make F_GETFL claim
/// packet mode while the writer kept emitting a byte stream; the reader would
/// then look for record boundaries the writer never made.
fn smoke_abi_fdio_fcntl_setfl_direct_reframes_pipe_writes() -> TestResult {
    with_setup(|| {
        const F_SETFL: u64 = 4;
        const O_NONBLOCK: u64 = 0o4000;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        let mut dst = [0u8; 64];

        // Created as a byte stream: two writes read back as one.
        for payload in [b"aa".as_slice(), b"bb".as_slice()] {
            if call(
                Syscall::Write.raw(),
                a2(wr, payload.as_ptr() as u64, payload.len() as u64),
            ) != Some(2)
            {
                return Err("stream-mode write failed");
            }
        }
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 64)) != Some(4) {
            return Err("stream-mode writes did not coalesce");
        }

        // Switch to packet mode: the same pair now reads back separately.
        if call(
            Syscall::Fcntl.raw(),
            a2(wr, F_SETFL, O_NONBLOCK | O_DIRECT_FLAG),
        ) != Some(0)
        {
            return Err("F_SETFL(O_DIRECT) failed");
        }
        for payload in [b"cc".as_slice(), b"dd".as_slice()] {
            if call(
                Syscall::Write.raw(),
                a2(wr, payload.as_ptr() as u64, payload.len() as u64),
            ) != Some(2)
            {
                return Err("packet-mode write failed");
            }
        }
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 64)) != Some(2) {
            return Err("F_SETFL(O_DIRECT) did not reframe subsequent writes");
        }
        if &dst[..2] != b"cc" {
            return Err("packet-mode read returned the wrong record");
        }
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 64)) != Some(2) {
            return Err("second packet-mode record missing");
        }

        // Clear it again: writes coalesce once more.
        if call(Syscall::Fcntl.raw(), a2(wr, F_SETFL, O_NONBLOCK)) != Some(0) {
            return Err("F_SETFL clearing O_DIRECT failed");
        }
        for payload in [b"ee".as_slice(), b"ff".as_slice()] {
            if call(
                Syscall::Write.raw(),
                a2(wr, payload.as_ptr() as u64, payload.len() as u64),
            ) != Some(2)
            {
                return Err("post-clear write failed");
            }
        }
        if call(Syscall::Read.raw(), a2(rd, dst.as_mut_ptr() as u64, 64)) != Some(4) {
            return Err("clearing O_DIRECT did not restore byte-stream framing");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_fcntl_setfl_direct_reframes_pipe_writes
);

/// `fs/splice.c::link_pipe` copies whole `struct pipe_buffer`s into the
/// destination and clears only GIFT and CAN_MERGE — `PIPE_BUF_FLAG_PACKET`
/// survives. So teeing a packet pipe into an ORDINARY pipe hands the reader
/// the source's records, not the destination's framing.
///
/// Routing tee through a byte peek plus the destination's own `write` gave the
/// payload the destination's framing instead, running every record together.
/// The source must also still hold its data afterwards: tee copies, it does
/// not consume.
fn smoke_abi_fdio_tee_carries_packet_framing_to_a_stream_pipe() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let (src_rd, src_wr) = make_packet_pipe(O_NONBLOCK)?;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2 for the tee destination failed");
        }
        let dst_rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let dst_wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;

        for payload in [b"abc".as_slice(), b"defgh".as_slice()] {
            if call(
                Syscall::Write.raw(),
                a2(src_wr, payload.as_ptr() as u64, payload.len() as u64),
            ) != Some(payload.len() as i64)
            {
                return Err("priming the packet source failed");
            }
        }
        // Both records, 8 bytes, in one tee.
        if call(Syscall::Tee.raw(), a3(src_rd, dst_wr, 64, 0)) != Some(8) {
            return Err("tee did not duplicate both records");
        }
        // The destination is an ORDINARY pipe, yet reads back records: the
        // flag travelled with the payload. Without it this first read takes
        // all 8 bytes.
        let mut dst = [0u8; 64];
        if call(Syscall::Read.raw(), a2(dst_rd, dst.as_mut_ptr() as u64, 64)) != Some(3) {
            return Err("teed packet lost its boundary in the destination");
        }
        if &dst[..3] != b"abc" {
            return Err("teed first record has the wrong bytes");
        }
        if call(Syscall::Read.raw(), a2(dst_rd, dst.as_mut_ptr() as u64, 64)) != Some(5) {
            return Err("teed second record missing or merged");
        }
        // tee does not consume: the source still holds both records.
        if call(Syscall::Read.raw(), a2(src_rd, dst.as_mut_ptr() as u64, 64)) != Some(3) {
            return Err("tee consumed the source pipe");
        }
        if call(Syscall::Read.raw(), a2(src_rd, dst.as_mut_ptr() as u64, 64)) != Some(5) {
            return Err("tee disturbed the source's second record");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_tee_carries_packet_framing_to_a_stream_pipe
);

/// The converse: teeing a BYTE-STREAM pipe into a packet pipe must not invent
/// records. `link_pipe` copies the source buffer's flags, so a non-packet
/// buffer stays non-packet however the destination was opened — the
/// destination's O_DIRECT governs its own `write` calls, not data teed into
/// it.
///
/// Two 4-byte tees are what separate the two implementations: framed by the
/// destination they arrive as two 4-byte packets and the first read returns 4;
/// carried from the source they are ordinary bytes that coalesce, and the read
/// returns all 8.
fn smoke_abi_fdio_tee_does_not_invent_records_in_a_packet_pipe() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2 for the stream source failed");
        }
        let src_rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let src_wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        let (dst_rd, dst_wr) = make_packet_pipe(O_NONBLOCK)?;

        let payload = b"abcdefgh";
        if call(
            Syscall::Write.raw(),
            a2(src_wr, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(8)
        {
            return Err("priming the stream source failed");
        }
        // tee does not consume, so both calls copy the same leading 4 bytes.
        for _ in 0..2 {
            if call(Syscall::Tee.raw(), a3(src_rd, dst_wr, 4, 0)) != Some(4) {
                return Err("4-byte tee did not copy 4 bytes");
            }
        }
        let mut dst = [0u8; 64];
        if call(Syscall::Read.raw(), a2(dst_rd, dst.as_mut_ptr() as u64, 64)) != Some(8) {
            return Err("tee framed stream bytes as packets in the destination");
        }
        if &dst[..8] != b"abcdabcd" {
            return Err("teed stream bytes came back wrong");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_tee_does_not_invent_records_in_a_packet_pipe
);

/// `link_pipe` truncates its LAST buffer to the caller's remaining length and
/// keeps the flag:
///
///     if (obuf->len > len)
///             obuf->len = len;
///
/// so a short tee of a packet yields a SHORTER PACKET, not a stream fragment.
/// Two 4-byte tees of one 10-byte record must therefore arrive as two separate
/// 4-byte records; if the flag were dropped on truncation they would coalesce
/// and the first read would return 8.
fn smoke_abi_fdio_tee_truncated_packet_keeps_its_flag() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let (src_rd, src_wr) = make_packet_pipe(O_NONBLOCK)?;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2 for the tee destination failed");
        }
        let dst_rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let dst_wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;

        let payload = b"0123456789";
        if call(
            Syscall::Write.raw(),
            a2(src_wr, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(10)
        {
            return Err("priming the packet source failed");
        }
        for _ in 0..2 {
            if call(Syscall::Tee.raw(), a3(src_rd, dst_wr, 4, 0)) != Some(4) {
                return Err("short tee of a packet did not copy 4 bytes");
            }
        }
        let mut dst = [0u8; 64];
        if call(Syscall::Read.raw(), a2(dst_rd, dst.as_mut_ptr() as u64, 64)) != Some(4) {
            return Err("truncated packet lost its flag on tee");
        }
        if &dst[..4] != b"0123" {
            return Err("truncated packet has the wrong bytes");
        }
        if call(Syscall::Read.raw(), a2(dst_rd, dst.as_mut_ptr() as u64, 64)) != Some(4) {
            return Err("second truncated packet missing");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_tee_truncated_packet_keeps_its_flag
);

/// `link_pipe`'s loop stops on `pipe_full(o_head, o_tail, opipe->max_usage)` —
/// a BUFFER-count test on the destination. A destination holding 16 packets
/// takes nothing more, so a non-blocking tee is -EAGAIN rather than a partial
/// copy or a 0 the caller would read as end-of-stream.
///
/// The EOF arm is the contrast that gives the EAGAIN its meaning: 0 is
/// reserved for a source whose last writer is gone (`ipipe_prep`).
fn smoke_abi_fdio_tee_full_destination_is_eagain() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        const SPLICE_F_NONBLOCK: u64 = 0x2;
        let (src_rd, src_wr) = make_packet_pipe(O_NONBLOCK)?;
        let (_dst_rd, dst_wr) = make_packet_pipe(O_NONBLOCK)?;
        let byte = b"x";
        if call(Syscall::Write.raw(), a2(src_wr, byte.as_ptr() as u64, 1)) != Some(1) {
            return Err("priming the tee source failed");
        }
        // Fill the destination's 16 buffers with 16 bytes.
        for _ in 0..16 {
            if call(Syscall::Write.raw(), a2(dst_wr, byte.as_ptr() as u64, 1)) != Some(1) {
                return Err("filling the tee destination failed");
            }
        }
        if call(
            Syscall::Tee.raw(),
            a3(src_rd, dst_wr, 64, SPLICE_F_NONBLOCK),
        ) != Some(EAGAIN)
        {
            return Err("tee into a buffer-full destination was not -EAGAIN");
        }
        // Contrast: an empty source whose writer is gone is a real EOF (0).
        let (eof_rd, eof_wr) = make_packet_pipe(O_NONBLOCK)?;
        if call(Syscall::Close.raw(), a0(eof_wr)) != Some(0) {
            return Err("closing the tee source writer failed");
        }
        let (_spare_rd, spare_wr) = make_packet_pipe(O_NONBLOCK)?;
        if call(
            Syscall::Tee.raw(),
            a3(eof_rd, spare_wr, 64, SPLICE_F_NONBLOCK),
        ) != Some(0)
        {
            return Err("tee from a writerless empty source was not EOF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_tee_full_destination_is_eagain);

/// `pipe_write` copies at most one page into each buffer
/// (`copy_page_from_iter(page, 0, PAGE_SIZE, from)`) and loops, so a packet
/// write LARGER than a page becomes several packets rather than one oversized
/// record. A reader sized for the whole write gets only the first page.
fn smoke_abi_fdio_pipe2_direct_splits_oversized_writes() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        const PAGE: usize = 4096;
        let (rd, wr) = make_packet_pipe(O_NONBLOCK)?;
        let payload = alloc::vec![b'z'; PAGE + 100];
        if call(
            Syscall::Write.raw(),
            a2(wr, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("oversized packet write failed");
        }
        let mut dst = alloc::vec![0u8; PAGE * 2];
        // A buffer twice the size of the write still stops at one page.
        if call(
            Syscall::Read.raw(),
            a2(rd, dst.as_mut_ptr() as u64, dst.len() as u64),
        ) != Some(PAGE as i64)
        {
            return Err("oversized packet write was not split at a page");
        }
        if call(
            Syscall::Read.raw(),
            a2(rd, dst.as_mut_ptr() as u64, dst.len() as u64),
        ) != Some(100)
        {
            return Err("second packet of an oversized write was wrong");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe2_direct_splits_oversized_writes
);

/// pipe2(O_NONBLOCK) must land O_NONBLOCK on both descriptors: a read on
/// the empty pipe is -EAGAIN (not a blocking park, and NOT a spurious 0 =
/// EOF), and F_GETFL reports the flag plus the access mode
/// (`fs/pipe.c::create_pipe_files`: read end O_RDONLY, write end O_WRONLY).
fn smoke_abi_fdio_pipe2_nonblock_pos() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: i64 = 0o4000;
        const O_WRONLY: i64 = 0o1;
        const F_GETFL: u64 = 3;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK as u64),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        // Empty pipe + open writer + O_NONBLOCK → -EAGAIN (fs/pipe.c::
        // pipe_read: "if (filp->f_flags & O_NONBLOCK) { ret = -EAGAIN; }").
        let mut b = [0u8; 4];
        if call(Syscall::Read.raw(), a2(rd, b.as_mut_ptr() as u64, 4)) != Some(EAGAIN) {
            return Err("nonblocking read of empty pipe was not -EAGAIN");
        }
        match call(Syscall::Fcntl.raw(), a2(wr, F_GETFL, 0)) {
            Some(fl) if fl & O_NONBLOCK != 0 && fl & 0o3 == O_WRONLY => Ok(()),
            _ => Err("F_GETFL on pipe write end lacks O_NONBLOCK|O_WRONLY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe2_nonblock_pos);

/// Both ends of an anonymous pipe fstat as a FIFO with zero size —
/// `fs/pipe.c::create_pipe_files` (`S_IFIFO | S_IRUSR | S_IWUSR`), and
/// pipefs never updates i_size. S_IFREG here sent GNU coreutils ≥ 9 `cat`
/// down its copy_file_range path on a pipe stdin (the Fedora xkbcomp
/// zero-byte keymap).
fn smoke_abi_fdio_pipe_fstat_is_fifo_pos() -> TestResult {
    with_setup(|| {
        const S_IFMT: u32 = 0o170000;
        const S_IFIFO: u32 = 0o010000;
        let (rd, wr) = make_pipe()?;
        // Queue bytes so a size-from-queue-length regression is visible.
        let payload = b"sz";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("pipe write failed");
        }
        for fd in [rd, wr] {
            let mut stat = [0u8; 256];
            if call(
                Syscall::Fstat.raw(),
                a1(fd as u64, stat.as_mut_ptr() as u64),
            ) != Some(0)
            {
                return Err("fstat on pipe fd failed");
            }
            // x86_64 struct stat: st_mode is the u32 at offset 24,
            // st_size the i64 at offset 48.
            let mode = u32::from_ne_bytes([stat[24], stat[25], stat[26], stat[27]]);
            if mode & S_IFMT != S_IFIFO {
                return Err("pipe fd does not fstat as S_IFIFO");
            }
            let size = i64::from_ne_bytes(stat[48..56].try_into().unwrap());
            if size != 0 {
                return Err("pipe fstat st_size was not 0");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_fstat_is_fifo_pos);

/// lseek(2) on either pipe end is -ESPIPE — `fs/pipe.c`'s `pipefifo_fops`
/// has no .llseek, so `fs/read_write.c::vfs_llseek` refuses (no
/// FMODE_LSEEK). A "successful" pipe lseek let seek-probing callers
/// believe a pipe had a movable file position.
fn smoke_abi_fdio_pipe_lseek_espipe_neg() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        // SEEK_CUR on the read end, SEEK_SET/SEEK_END on the write end.
        if call(Syscall::Lseek.raw(), a2(rd as u64, 0, 1)) != Some(ESPIPE) {
            return Err("lseek(pipe read end, SEEK_CUR) was not -ESPIPE");
        }
        if call(Syscall::Lseek.raw(), a2(wr as u64, 0, 0)) != Some(ESPIPE) {
            return Err("lseek(pipe write end, SEEK_SET) was not -ESPIPE");
        }
        if call(Syscall::Lseek.raw(), a2(wr as u64, 0, 2)) != Some(ESPIPE) {
            return Err("lseek(pipe write end, SEEK_END) was not -ESPIPE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_lseek_espipe_neg);

/// Positioned I/O on a pipe is -ESPIPE — `fs/read_write.c::ksys_pread64`
/// / `ksys_pwrite64` start from `ret = -ESPIPE` and only proceed with
/// FMODE_PREAD/FMODE_PWRITE, which streams never get. The old handlers
/// consumed pipe bytes "at an offset". Queued data must be untouched by
/// the refusal.
fn smoke_abi_fdio_pipe_pread_pwrite_espipe_neg() -> TestResult {
    with_setup(|| {
        const FIONREAD: u64 = 0x541B;
        let (rd, wr) = make_pipe()?;
        let payload = b"stays";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("pipe write failed");
        }
        let mut b = [0u8; 8];
        if call(
            Syscall::Pread64.raw(),
            a3(rd as u64, b.as_mut_ptr() as u64, 4, 0),
        ) != Some(ESPIPE)
        {
            return Err("pread64 on a pipe was not -ESPIPE");
        }
        if call(
            Syscall::Pwrite64.raw(),
            a3(wr as u64, b.as_ptr() as u64, 4, 0),
        ) != Some(ESPIPE)
        {
            return Err("pwrite64 on a pipe was not -ESPIPE");
        }
        // preadv/pwritev share the check.
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(b.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(4u64).to_le_bytes());
        if call(
            Syscall::Preadv.raw(),
            a3(rd as u64, iov.as_ptr() as u64, 1, 0),
        ) != Some(ESPIPE)
        {
            return Err("preadv on a pipe was not -ESPIPE");
        }
        if call(
            Syscall::Pwritev.raw(),
            a3(wr as u64, iov.as_ptr() as u64, 1, 0),
        ) != Some(ESPIPE)
        {
            return Err("pwritev on a pipe was not -ESPIPE");
        }
        // The refusals consumed nothing: all 5 bytes still queued.
        let mut avail = 0i32;
        if call(
            Syscall::Ioctl.raw(),
            a2(rd as u64, FIONREAD, (&mut avail as *mut i32) as u64),
        ) != Some(0)
            || avail != payload.len() as i32
        {
            return Err("ESPIPE refusal consumed pipe bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_pread_pwrite_espipe_neg);

/// copy_file_range(2) is defined only between REGULAR files
/// (`fs/read_write.c::generic_file_rw_checks`: "Don't copy dirs, pipes,
/// sockets..." → -EINVAL). Accepting a pipe fd made the fallback loop
/// read a transiently-empty pipe as instant EOF — how coreutils `cat`
/// truncated the Xwayland→xkbcomp keymap to zero bytes.
fn smoke_abi_fdio_copy_file_range_pipe_einval_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"payload"), ("dst", b"")], || {
        let (rd, wr) = make_pipe()?;
        let file = open_fd(b"/abi/dst\0")?;
        let src = open_fd(b"/abi/src\0")?;
        // Pipe read end as in-fd → -EINVAL (even with bytes queued).
        let payload = b"queued";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("pipe write failed");
        }
        if call_raw(
            Syscall::CopyFileRange.raw(),
            SyscallArgs {
                arg0: rd as u64,
                arg1: 0,
                arg2: file as u64,
                arg3: 0,
                arg4: 64,
                ..Default::default()
            },
        )
        .value as i64
            != EINVAL
        {
            return Err("copy_file_range(pipe → file) was not -EINVAL");
        }
        // Pipe write end as out-fd → -EINVAL.
        if call_raw(
            Syscall::CopyFileRange.raw(),
            SyscallArgs {
                arg0: src as u64,
                arg1: 0,
                arg2: wr as u64,
                arg3: 0,
                arg4: 64,
                ..Default::default()
            },
        )
        .value as i64
            != EINVAL
        {
            return Err("copy_file_range(file → pipe) was not -EINVAL");
        }
        // Positive control: regular file → regular file still copies.
        match call_raw(
            Syscall::CopyFileRange.raw(),
            SyscallArgs {
                arg0: src as u64,
                arg1: 0,
                arg2: file as u64,
                arg3: 0,
                arg4: 64,
                ..Default::default()
            },
        )
        .value as i64
        {
            7 => Ok(()),
            _ => Err("copy_file_range(file → file) did not copy 7 bytes"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_copy_file_range_pipe_einval_neg
);

/// splice(2) argument shape — `fs/splice.c::__do_splice`: at least one fd
/// must be a pipe (else -EINVAL) and an offset pointer for a pipe-side fd
/// is -ESPIPE. An empty-but-open pipe source under SPLICE_F_NONBLOCK is
/// -EAGAIN, never a transient-0 "EOF" (the lost-data shape).
fn smoke_abi_fdio_splice_shape() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"payload"), ("dst", b"")], || {
        const SPLICE_F_NONBLOCK: u64 = 0x2;
        let src = open_fd(b"/abi/src\0")?;
        let dst = open_fd_flags(b"/abi/dst\0", 1)?; // O_WRONLY
        let (rd, wr) = make_pipe()?;
        let mk = |a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64| SyscallArgs {
            arg0: a0,
            arg1: a1,
            arg2: a2,
            arg3: a3,
            arg4: a4,
            arg5: a5,
        };
        // Neither side a pipe → -EINVAL.
        if call(
            Syscall::Splice.raw(),
            mk(src as u64, 0, dst as u64, 0, 16, 0),
        ) != Some(EINVAL)
        {
            return Err("splice(file → file) was not -EINVAL");
        }
        // Offset pointer on the pipe side → -ESPIPE.
        let off: u64 = 0;
        if call(
            Syscall::Splice.raw(),
            mk(rd as u64, (&off as *const u64) as u64, dst as u64, 0, 16, 0),
        ) != Some(ESPIPE)
        {
            return Err("splice(pipe with off_in) was not -ESPIPE");
        }
        // Empty pipe source, writer open, SPLICE_F_NONBLOCK → -EAGAIN.
        if call(
            Syscall::Splice.raw(),
            mk(rd as u64, 0, dst as u64, 0, 16, SPLICE_F_NONBLOCK),
        ) != Some(EAGAIN)
        {
            return Err("splice(empty pipe, NONBLOCK) was not -EAGAIN");
        }
        // Positive control: file → pipe still moves the bytes.
        if call(
            Syscall::Splice.raw(),
            mk(src as u64, 0, wr as u64, 0, 64, 0),
        ) != Some(7)
        {
            return Err("splice(file → pipe) did not move 7 bytes");
        }
        let mut b = [0u8; 16];
        if call(
            Syscall::Read.raw(),
            a2(rd as u64, b.as_mut_ptr() as u64, 16),
        ) != Some(7)
            || &b[..7] != b"payload"
        {
            return Err("spliced bytes did not arrive in the pipe");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_splice_shape);

/// Wrong-direction pipe access is -EBADF, not a silent no-op:
/// `fs/read_write.c::vfs_read`/`vfs_write` fail the FMODE_READ /
/// FMODE_WRITE check before the pipe op runs. The old Ok(0)s here turned
/// "read the write end" into a fake EOF and "write the read end" into an
/// infinite retry loop.
fn smoke_abi_fdio_pipe_wrong_direction_ebadf_neg() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        let mut b = [0u8; 4];
        if call(Syscall::Read.raw(), a2(wr as u64, b.as_mut_ptr() as u64, 4)) != Some(EBADF) {
            return Err("read on the pipe WRITE end was not -EBADF");
        }
        if call(Syscall::Write.raw(), a2(rd as u64, b.as_ptr() as u64, 4)) != Some(EBADF) {
            return Err("write on the pipe READ end was not -EBADF");
        }
        // readv/writev share the vfs mode checks.
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(b.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(4u64).to_le_bytes());
        if call(Syscall::Readv.raw(), a2(wr as u64, iov.as_ptr() as u64, 1)) != Some(EBADF) {
            return Err("readv on the pipe WRITE end was not -EBADF");
        }
        if call(Syscall::Writev.raw(), a2(rd as u64, iov.as_ptr() as u64, 1)) != Some(EBADF) {
            return Err("writev on the pipe READ end was not -EBADF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_wrong_direction_ebadf_neg);

/// POSIX PIPE_BUF atomicity — `fs/pipe.c::pipe_write`: a write of ≤ 4096
/// bytes is all-or-nothing. Against a pipe with insufficient room it
/// writes NOTHING and (under O_NONBLOCK) returns -EAGAIN; only writes
/// larger than PIPE_BUF may land a partial prefix.
fn smoke_abi_fdio_pipe_buf_atomicity() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        const FIONREAD: u64 = 0x541B;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        // Fill the pipe to capacity (64 KiB) with 4 KiB atomic chunks.
        let chunk = [0x5Au8; 4096];
        for _ in 0..16 {
            if call(
                Syscall::Write.raw(),
                a2(wr, chunk.as_ptr() as u64, chunk.len() as u64),
            ) != Some(chunk.len() as i64)
            {
                return Err("filling the pipe did not take a full 4 KiB chunk");
            }
        }
        // Full: a further nonblocking write of any size is -EAGAIN.
        if call(Syscall::Write.raw(), a2(wr, chunk.as_ptr() as u64, 100)) != Some(EAGAIN) {
            return Err("write to a full pipe was not -EAGAIN");
        }
        // Drain 50 bytes → 50 bytes of room.
        let mut small = [0u8; 50];
        if call(Syscall::Read.raw(), a2(rd, small.as_mut_ptr() as u64, 50)) != Some(50) {
            return Err("draining 50 bytes failed");
        }
        // 100 ≤ PIPE_BUF with only 50 bytes of room: ATOMIC → -EAGAIN,
        // not a 50-byte partial. (This is the arm the old truncating
        // write failed.)
        if call(Syscall::Write.raw(), a2(wr, chunk.as_ptr() as u64, 100)) != Some(EAGAIN) {
            return Err("short-room write of ≤ PIPE_BUF was split, not atomic");
        }
        // FIONREAD confirms the atomic refusal wrote nothing.
        let mut avail = 0i32;
        if call(
            Syscall::Ioctl.raw(),
            a2(rd, FIONREAD, (&mut avail as *mut i32) as u64),
        ) != Some(0)
            || avail != 65536 - 50
        {
            return Err("atomic refusal still queued bytes");
        }
        // A > PIPE_BUF write MAY be partial: 8192 into 50 bytes of room
        // lands exactly the 50-byte prefix (fs/pipe.c: only "atomic" for
        // small writes).
        let big = [0xA5u8; 8192];
        if call(
            Syscall::Write.raw(),
            a2(wr, big.as_ptr() as u64, big.len() as u64),
        ) != Some(50)
        {
            return Err("> PIPE_BUF write did not land the partial prefix");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_buf_atomicity);

/// readv(2) on an open-but-empty O_NONBLOCK pipe is -EAGAIN — Linux
/// `do_readv` ends in the same `pipe_read` as read(2), whose ONLY 0
/// return is "no writers left". The old handler returned the transient 0
/// as EOF, which ended every musl stdio stream (`__stdio_read` uses
/// readv) at the first empty moment of a pipe.
fn smoke_abi_fdio_pipe_readv_empty_eagain() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
        let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        let mut dst = [0u8; 8];
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(dst.len() as u64).to_le_bytes());
        // Empty + writer open + O_NONBLOCK → -EAGAIN, not 0.
        if call(Syscall::Readv.raw(), a2(rd, iov.as_ptr() as u64, 1)) != Some(EAGAIN) {
            return Err("readv of empty nonblocking pipe was not -EAGAIN");
        }
        // With data queued the same readv returns it.
        let payload = b"iovec";
        if call(
            Syscall::Write.raw(),
            a2(wr, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
        {
            return Err("pipe write failed");
        }
        if call(Syscall::Readv.raw(), a2(rd, iov.as_ptr() as u64, 1)) != Some(payload.len() as i64)
        {
            return Err("readv did not return the queued bytes");
        }
        if &dst[..payload.len()] != payload {
            return Err("readv copied back the wrong bytes");
        }
        // Writer closed + empty → genuine EOF (0).
        if call(Syscall::Close.raw(), a0(wr)) != Some(0) {
            return Err("closing writer failed");
        }
        if call(Syscall::Readv.raw(), a2(rd, iov.as_ptr() as u64, 1)) != Some(0) {
            return Err("readv after last-writer close was not EOF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_readv_empty_eagain);

/// writev(2) into a pipe with no readers is SIGPIPE + -EPIPE
/// (`fs/pipe.c::pipe_write`), exactly like write(2) — the old handler
/// answered a bare -EPERM and skipped the signal. A full O_NONBLOCK pipe
/// is -EAGAIN, not a 0 count that stdio flush loops spin on.
fn smoke_abi_fdio_pipe_writev_epipe_eagain() -> TestResult {
    with_setup(|| {
        const O_NONBLOCK: u64 = 0o4000;
        // Arm 1: closed reader → -EPIPE.
        let (rd, wr) = make_pipe()?;
        if call(Syscall::Close.raw(), a0(rd as u64)) != Some(0) {
            return Err("closing reader failed");
        }
        let payload = b"gone";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        if call(Syscall::Writev.raw(), a2(wr as u64, iov.as_ptr() as u64, 1)) != Some(EPIPE) {
            return Err("writev with no pipe readers was not -EPIPE");
        }
        // Arm 2: full nonblocking pipe → -EAGAIN.
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let wr2 = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        let chunk = [0u8; 4096];
        for _ in 0..16 {
            if call(
                Syscall::Write.raw(),
                a2(wr2, chunk.as_ptr() as u64, chunk.len() as u64),
            ) != Some(chunk.len() as i64)
            {
                return Err("filling the pipe failed");
            }
        }
        if call(Syscall::Writev.raw(), a2(wr2, iov.as_ptr() as u64, 1)) != Some(EAGAIN) {
            return Err("writev into a full nonblocking pipe was not -EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_writev_epipe_eagain);

/// poll(2) readiness masks match `fs/pipe.c::pipe_poll`: the read end
/// reports EPOLLIN only while data is queued and EPOLLHUP once the
/// writers are gone; the write end reports EPOLLOUT while there is room
/// and EPOLLERR once the readers are gone.
fn smoke_abi_fdio_pipe_poll_hup_err() -> TestResult {
    with_setup(|| {
        const POLLIN: i16 = 0x001;
        const POLLOUT: i16 = 0x004;
        const POLLERR: i16 = 0x008;
        const POLLHUP: i16 = 0x010;
        // pollfd { fd: i32, events: i16, revents: i16 }
        fn poll1(fd: u32, events: i16) -> Result<i16, &'static str> {
            let mut pfd = [0u8; 8];
            pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
            pfd[4..6].copy_from_slice(&events.to_ne_bytes());
            let r = call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0));
            match r {
                Some(n) if n >= 0 => Ok(i16::from_ne_bytes([pfd[6], pfd[7]])),
                _ => Err("poll failed"),
            }
        }
        let (rd, wr) = make_pipe()?;
        // Empty pipe, writer open: no POLLIN, no POLLHUP.
        if poll1(rd, POLLIN)? != 0 {
            return Err("empty pipe with open writer reported readiness");
        }
        // Data queued: POLLIN.
        let payload = b"p";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, payload.as_ptr() as u64, 1),
        ) != Some(1)
        {
            return Err("pipe write failed");
        }
        if poll1(rd, POLLIN)? & POLLIN == 0 {
            return Err("pipe with data did not report POLLIN");
        }
        // Writer closed, data still queued: POLLIN | POLLHUP.
        if call(Syscall::Close.raw(), a0(wr as u64)) != Some(0) {
            return Err("closing writer failed");
        }
        let rev = poll1(rd, POLLIN)?;
        if rev & POLLIN == 0 || rev & POLLHUP == 0 {
            return Err("EOF'd pipe with residual data was not POLLIN|POLLHUP");
        }
        // Drained: POLLHUP only (POLLIN must drop — HUP is reported even
        // though the caller only asked for POLLIN).
        let mut b = [0u8; 4];
        if call(Syscall::Read.raw(), a2(rd as u64, b.as_mut_ptr() as u64, 4)) != Some(1) {
            return Err("draining the last byte failed");
        }
        let rev = poll1(rd, POLLIN)?;
        if rev & POLLHUP == 0 || rev & POLLIN != 0 {
            return Err("drained EOF'd pipe was not bare POLLHUP");
        }
        // Fresh pair: write end with the reader closed → POLLOUT | POLLERR.
        let (rd2, wr2) = make_pipe()?;
        if poll1(wr2, POLLOUT)? != POLLOUT {
            return Err("writable pipe was not bare POLLOUT");
        }
        if call(Syscall::Close.raw(), a0(rd2 as u64)) != Some(0) {
            return Err("closing reader failed");
        }
        let rev = poll1(wr2, POLLOUT)?;
        if rev & POLLERR == 0 {
            return Err("reader-less pipe write end did not report POLLERR");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe_poll_hup_err);

/// A pipe half whose PEER closes must PUBLISH a readiness wake, not only flip
/// its poll mask. Without the wake a reader/writer parked in poll(-1)/
/// epoll_wait(-1) never re-scans and hangs until the ~10 ms lost-wake backstop
/// (before that backstop existed, forever). The close travels
/// `PipeWrite`/`PipeRead::drop`, which latches POLL_HUP/POLL_ERR into the shared
/// durable readiness cell (waking a waiter armed on it) AND bumps the legacy
/// generation via `readiness::notify`.
///
/// Same two-halves shape as `smoke_abi_socket_connected_pair_peer_close_reports_hup`
/// and the neighbouring `..._pipe_poll_hup_err` (which covers only the timeout-0
/// mask, blind to a missing wake): assert the generation bump directly, then the
/// re-scan's mask. Covers BOTH directions — writer close → reader POLLHUP,
/// reader close → writer POLLERR.
fn smoke_abi_fdio_pipe_peer_close_wakes_parked_poller() -> TestResult {
    with_setup(|| {
        const POLLIN: i16 = 0x001;
        const POLLOUT: i16 = 0x004;
        const POLLERR: i16 = 0x008;
        const POLLHUP: i16 = 0x010;
        fn poll1(fd: u32, events: i16) -> Result<i16, &'static str> {
            let mut pfd = [0u8; 8];
            pfd[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
            pfd[4..6].copy_from_slice(&events.to_ne_bytes());
            match call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)) {
                Some(n) if n >= 0 => Ok(i16::from_ne_bytes([pfd[6], pfd[7]])),
                _ => Err("poll failed"),
            }
        }

        // Reader parked on an empty pipe: the writer's close must wake it and
        // then report POLLHUP so it runs read()→0=EOF.
        let (rd, wr) = make_pipe()?;
        if poll1(rd, POLLIN)? != 0 {
            return Err("empty pipe with open writer reported readiness");
        }
        let before = narf_net::readiness::generation();
        if call(Syscall::Close.raw(), a0(wr as u64)) != Some(0) {
            return Err("closing writer failed");
        }
        if narf_net::readiness::generation() <= before {
            return Err("writer close published no readiness wake for a parked reader");
        }
        if poll1(rd, POLLIN)? & POLLHUP == 0 {
            return Err("writer-closed pipe did not report POLLHUP to the woken reader");
        }
        let _ = call(Syscall::Close.raw(), a0(rd as u64));

        // Writer parked on a pipe: the reader's close must wake it and then
        // report POLLERR (a following write would get EPIPE).
        let (rd2, wr2) = make_pipe()?;
        let before = narf_net::readiness::generation();
        if call(Syscall::Close.raw(), a0(rd2 as u64)) != Some(0) {
            return Err("closing reader failed");
        }
        if narf_net::readiness::generation() <= before {
            return Err("reader close published no readiness wake for a parked writer");
        }
        if poll1(wr2, POLLOUT)? & POLLERR == 0 {
            return Err("reader-closed pipe write end did not report POLLERR to the woken writer");
        }
        let _ = call(Syscall::Close.raw(), a0(wr2 as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_pipe_peer_close_wakes_parked_poller
);

/// dup2(2) shares the open file description — the duplicate carries the
/// description's status flags (O_NONBLOCK) and file offset
/// (`fs/file.c::do_dup2`: both fds point at the same `struct file`).
fn smoke_abi_fdio_dup2_carries_description_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        const O_NONBLOCK: i64 = 0o4000;
        const F_GETFL: u64 = 3;
        // Status flags: an O_NONBLOCK pipe end dup2'd keeps O_NONBLOCK.
        let mut buf = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(buf.as_mut_ptr() as u64, O_NONBLOCK as u64),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        if call_dup2(wr, 20) != Some(20) {
            return Err("dup2 failed");
        }
        match call(Syscall::Fcntl.raw(), a2(20, F_GETFL, 0)) {
            Some(fl) if fl & O_NONBLOCK != 0 => {}
            _ => return Err("dup2 dropped O_NONBLOCK from the duplicate"),
        }
        const F_SETFL: u64 = 4;
        if call(Syscall::Fcntl.raw(), a2(20, F_SETFL, 0)) != Some(0) {
            return Err("F_SETFL through duplicate failed");
        }
        match call(Syscall::Fcntl.raw(), a2(wr, F_GETFL, 0)) {
            Some(fl) if fl & O_NONBLOCK == 0 => {}
            _ => return Err("status flags were not shared with original fd"),
        }
        // File offset: read 2 bytes, dup, and the duplicate continues at
        // offset 2 rather than rewinding to 0.
        let fd = open_fd(b"/abi/f\0")?;
        let mut b2 = [0u8; 2];
        if call(
            Syscall::Read.raw(),
            a2(fd as u64, b2.as_mut_ptr() as u64, 2),
        ) != Some(2)
        {
            return Err("priming read failed");
        }
        if call_dup2(fd as u64, 21) != Some(21) {
            return Err("dup2 of file fd failed");
        }
        if call(Syscall::Read.raw(), a2(21, b2.as_mut_ptr() as u64, 2)) != Some(2) {
            return Err("read via duplicate failed");
        }
        if &b2 != b"cd" {
            return Err("duplicate rewound to offset 0 instead of sharing it");
        }
        if call(
            Syscall::Read.raw(),
            a2(fd as u64, b2.as_mut_ptr() as u64, 2),
        ) != Some(2)
            || &b2 != b"ef"
        {
            return Err("duplicate advancement was not visible to original fd");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_dup2_carries_description_pos);

// ── eventfd ────────────────────────────────────────────────────────
//
// Always succeeds (installs a fresh fd). No reachable error path from
// this harness, so only a positive test.

fn smoke_abi_fdio_eventfd_pos() -> TestResult {
    with_setup(|| {
        // eventfd(initval=0, flags=0) → a fresh fd (>= 0).
        match call(Syscall::Eventfd.raw(), a1(0, 0)) {
            Some(n) if n >= 0 => Ok(()),
            _ => Err("eventfd did not return a fresh fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_eventfd_pos);

// ── flock ──────────────────────────────────────────────────────────
//
// LOCK_EX = 2, LOCK_NB = 4.

fn smoke_abi_fdio_flock_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // flock(fd, LOCK_EX|LOCK_NB) → 0 (uncontended exclusive lock).
        match call(Syscall::Flock.raw(), a1(fd as u64, 2 | 4)) {
            Some(0) => Ok(()),
            _ => Err("flock LOCK_EX|LOCK_NB did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_flock_pos);

fn smoke_abi_fdio_flock_neg() -> TestResult {
    with_setup(|| {
        // `fs/locks.c::SYSCALL_DEFINE2(flock)`: the operation translates
        // (LOCK_EX is valid), then `if (fd_empty(f)) return -EBADF;`.
        match call(Syscall::Flock.raw(), a1(4444, 2 | 4)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("flock on bad fd was not -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_flock_neg);

// ── sendfile ───────────────────────────────────────────────────────
//
// sendfile(out_fd, in_fd, off*, count). in_fd must not be a stream
// (pipe/socket) — a regular MemFs file is fine.

fn smoke_abi_fdio_sendfile_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"hi"), ("dst", b"")], || {
        let in_fd = open_fd(b"/abi/src\0")?;
        let out_fd = open_fd_flags(b"/abi/dst\0", 1)?; // O_WRONLY
                                                       // sendfile(out, in, NULL, 2) → 2 bytes copied.
        match call(
            Syscall::Sendfile.raw(),
            a3(out_fd as u64, in_fd as u64, 0, 2),
        ) {
            Some(2) => Ok(()),
            _ => Err("sendfile did not copy 2 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_sendfile_pos);

fn smoke_abi_fdio_sendfile_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("dst", b"")], || {
        let out_fd = open_fd_flags(b"/abi/dst\0", 1)?; // O_WRONLY
                                                       // bad in_fd → -EBADF.
        match call(Syscall::Sendfile.raw(), a3(out_fd as u64, 7070, 0, 4)) {
            Some(EBADF) => Ok(()),
            _ => Err("sendfile with bad in_fd was not -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_sendfile_neg);

/// Pin `fs/read_write.c::{sendfile,do_sendfile}` validation ordering and
/// exact errno values, including count==0 (which still validates both fds).
fn smoke_abi_fdio_sendfile_exact_validation() -> TestResult {
    const BAD_PTR: u64 = 0x0001_0000_0000_0000;
    const O_WRONLY: u64 = 1;
    const O_APPEND: u64 = 0o2000;
    with_memfs("/abi", "abi", &[("src", b"abcd"), ("dst", b"")], || {
        if call(Syscall::Sendfile.raw(), a3(7001, 7002, BAD_PTR, 1)) != Some(EFAULT) {
            return Err("sendfile did not import offset before fds");
        }
        let mut offset = 0u64;
        let src = open_fd(b"/abi/src\0")?;
        let dst = open_fd_flags(b"/abi/dst\0", O_WRONLY)?;
        if call(
            Syscall::Sendfile.raw(),
            a3(dst as u64, 7002, (&mut offset as *mut u64) as u64, 1),
        ) != Some(EBADF)
        {
            return Err("sendfile bad input fd was not EBADF");
        }

        let write_only_input = open_fd_flags(b"/abi/src\0", O_WRONLY)?;
        if call(
            Syscall::Sendfile.raw(),
            a3(7001, write_only_input as u64, 0, 1),
        ) != Some(EBADF)
        {
            return Err("sendfile did not validate input mode before output fd");
        }
        let (pipe_rd, _pipe_wr) = make_pipe()?;
        if call(
            Syscall::Sendfile.raw(),
            a3(7001, pipe_rd as u64, (&mut offset as *mut u64) as u64, 1),
        ) != Some(ESPIPE)
        {
            return Err("sendfile explicit pipe offset was not ESPIPE");
        }

        if call(Syscall::Sendfile.raw(), a3(7001, src as u64, 0, 1)) != Some(EBADF) {
            return Err("sendfile bad output fd was not EBADF");
        }
        let read_only_output = open_fd_flags(b"/abi/dst\0", 0)?;
        if call(
            Syscall::Sendfile.raw(),
            a3(read_only_output as u64, src as u64, 0, 1),
        ) != Some(EBADF)
        {
            return Err("sendfile read-only output was not EBADF");
        }
        let append_output = open_fd_flags(b"/abi/dst\0", O_WRONLY | O_APPEND)?;
        if call(
            Syscall::Sendfile.raw(),
            a3(append_output as u64, src as u64, 0, 1),
        ) != Some(EINVAL)
        {
            return Err("sendfile O_APPEND output was not EINVAL");
        }

        let mut negative_offset = u64::MAX;
        if call(
            Syscall::Sendfile.raw(),
            a3(
                dst as u64,
                src as u64,
                (&mut negative_offset as *mut u64) as u64,
                1,
            ),
        ) != Some(EINVAL)
            || negative_offset != u64::MAX
        {
            return Err("sendfile negative offset was not stable EINVAL");
        }
        if call(Syscall::Sendfile.raw(), a3(7001, src as u64, 0, 0)) != Some(EBADF) {
            return Err("zero-count sendfile skipped fd validation");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sendfile",
    smoke_abi_fdio_sendfile_exact_validation
);

/// A short pipe sink returns the accepted prefix and advances the input
/// position by exactly that prefix, never by the staged read length.
fn smoke_abi_fdio_sendfile_partial_pipe_preserves_tail() -> TestResult {
    let payload = alloc::vec![0x6Du8; 8192];
    with_memfs("/abi", "abi", &[("src", &payload)], || {
        let src = open_fd(b"/abi/src\0")?;
        let (rd, wr) = make_pipe()?;
        let filler = alloc::vec![0xA6u8; 65536 - 32];
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, filler.as_ptr() as u64, filler.len() as u64),
        ) != Some(filler.len() as i64)
        {
            return Err("failed to prepare partial sendfile sink");
        }
        if call(
            Syscall::Sendfile.raw(),
            a3(wr as u64, src as u64, 0, payload.len() as u64),
        ) != Some(32)
        {
            return Err("sendfile did not return the accepted pipe prefix");
        }
        let mut first = alloc::vec![0u8; 65536];
        if call(
            Syscall::Read.raw(),
            a2(rd as u64, first.as_mut_ptr() as u64, first.len() as u64),
        ) != Some(first.len() as i64)
            || first[filler.len()..] != payload[..32]
        {
            return Err("sendfile partial prefix was corrupted");
        }
        if call(
            Syscall::Sendfile.raw(),
            a3(wr as u64, src as u64, 0, payload.len() as u64),
        ) != Some((payload.len() - 32) as i64)
        {
            return Err("sendfile skipped or lost the staged source tail");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sendfile",
    smoke_abi_fdio_sendfile_partial_pipe_preserves_tail
);

fn smoke_abi_fdio_sendfile_pipe_errors() -> TestResult {
    const O_NONBLOCK: u64 = 0o4000;
    with_memfs("/abi", "abi", &[("src", b"x")], || {
        let src = open_fd(b"/abi/src\0")?;
        let mut fds = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(fds.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes(fds[..4].try_into().unwrap()) as u32;
        let wr = i32::from_ne_bytes(fds[4..].try_into().unwrap()) as u32;
        let chunk = [0x37u8; 4096];
        for _ in 0..16 {
            if call(
                Syscall::Write.raw(),
                a2(wr as u64, chunk.as_ptr() as u64, chunk.len() as u64),
            ) != Some(chunk.len() as i64)
            {
                return Err("failed to fill sendfile pipe");
            }
        }
        if call(Syscall::Sendfile.raw(), a3(wr as u64, src as u64, 0, 1)) != Some(EAGAIN) {
            return Err("sendfile to full O_NONBLOCK pipe was not EAGAIN");
        }
        if call(Syscall::Close.raw(), a0(rd as u64)) != Some(0)
            || call(Syscall::Sendfile.raw(), a3(wr as u64, src as u64, 0, 1)) != Some(EPIPE)
        {
            return Err("sendfile to broken pipe was not EPIPE");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/sendfile", smoke_abi_fdio_sendfile_pipe_errors);

// ── splice ─────────────────────────────────────────────────────────
//
// splice(fd_in, off_in*, fd_out, off_out*, len, flags). At least one
// side must be a pipe (`fs/splice.c::__do_splice` → -EINVAL otherwise);
// this positive arm splices file → pipe. The pipe-shape negatives
// (file→file EINVAL, pipe-side offset ESPIPE, empty-pipe EAGAIN) live
// in smoke_abi_fdio_splice_shape.
//
// HISTORY: this test used to assert a file→file splice SUCCEEDS —
// NARF's old splice had no pipe requirement. That encoded the
// divergence rather than pinning it; corrected to the Linux shape.

fn smoke_abi_fdio_splice_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"xyz")], || {
        let in_fd = open_fd(b"/abi/src\0")?;
        let (rd, wr) = make_pipe()?;
        // splice(file, NULL, pipe_wr, NULL, 3, 0) → 3 bytes.
        match call_raw(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: in_fd as u64,
                arg1: 0,
                arg2: wr as u64,
                arg3: 0,
                arg4: 3,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 3 => {}
            _ => return Err("splice did not copy 3 bytes"),
        }
        let mut b = [0u8; 4];
        match call(Syscall::Read.raw(), a2(rd as u64, b.as_mut_ptr() as u64, 4)) {
            Some(3) if &b[..3] == b"xyz" => Ok(()),
            _ => Err("spliced bytes did not arrive in the pipe"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_splice_pos);

fn smoke_abi_fdio_splice_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("dst", b"")], || {
        let out_fd = open_fd(b"/abi/dst\0")?;
        // bad fd_in → -EBADF (`fs/splice.c` fdget failure). Was the bare
        // -1 sentinel before splice resolved both fds up front.
        match call_raw(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: 6060,
                arg1: 0,
                arg2: out_fd as u64,
                arg3: 0,
                arg4: 4,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == EBADF => Ok(()),
            _ => Err("splice with bad fd_in was not -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_splice_neg);

/// Pin `fs/splice.c::{splice,__do_splice,do_splice}` ordering: zero length,
/// flags, fd lookup, pipe-offset rejection, user offset import, then f_mode.
fn smoke_abi_fdio_splice_exact_validation() -> TestResult {
    const BAD_PTR: u64 = 0x0001_0000_0000_0000;
    const UNKNOWN_FLAG: u64 = 0x10;
    const O_WRONLY: u64 = 1;
    const O_APPEND: u64 = 0o2000;
    let mk =
        |fd_in: u64, off_in: u64, fd_out: u64, off_out: u64, len: u64, flags: u64| SyscallArgs {
            arg0: fd_in,
            arg1: off_in,
            arg2: fd_out,
            arg3: off_out,
            arg4: len,
            arg5: flags,
        };
    with_memfs("/abi", "abi", &[("src", b"abcd"), ("dst", b"")], || {
        // len==0 wins over unknown flags, bad fds, and invalid pointers.
        if call(
            Syscall::Splice.raw(),
            mk(7001, BAD_PTR, 7002, BAD_PTR, 0, UNKNOWN_FLAG),
        ) != Some(0)
        {
            return Err("zero-length splice validated later arguments");
        }
        if call(Syscall::Splice.raw(), mk(7001, 0, 7002, 0, 1, UNKNOWN_FLAG)) != Some(EINVAL) {
            return Err("splice did not reject unknown flags before fds");
        }

        let src = open_fd(b"/abi/src\0")?;
        let dst = open_fd_flags(b"/abi/dst\0", O_WRONLY)?;
        let (rd, wr) = make_pipe()?;
        if call(Syscall::Splice.raw(), mk(7001, 0, wr as u64, 0, 1, 0)) != Some(EBADF)
            || call(Syscall::Splice.raw(), mk(src as u64, 0, 7002, 0, 1, 0)) != Some(EBADF)
        {
            return Err("splice fd lookup did not report EBADF");
        }

        // A pipe-side offset is ESPIPE without dereferencing the pointer.
        if call(
            Syscall::Splice.raw(),
            mk(rd as u64, BAD_PTR, dst as u64, 0, 1, 0),
        ) != Some(ESPIPE)
        {
            return Err("splice pipe offset did not precede uaccess");
        }

        // A non-pipe explicit offset is imported before f_mode validation.
        let write_only_src = open_fd_flags(b"/abi/src\0", O_WRONLY)?;
        if call(
            Syscall::Splice.raw(),
            mk(write_only_src as u64, BAD_PTR, wr as u64, 0, 1, 0),
        ) != Some(EFAULT)
        {
            return Err("splice f_mode check masked offset EFAULT");
        }
        let mut offset = 0u64;
        if call(
            Syscall::Splice.raw(),
            mk(
                write_only_src as u64,
                (&mut offset as *mut u64) as u64,
                wr as u64,
                0,
                1,
                0,
            ),
        ) != Some(EBADF)
        {
            return Err("splice write-only input was not EBADF");
        }
        let read_only_dst = open_fd_flags(b"/abi/dst\0", 0)?;
        if call(
            Syscall::Splice.raw(),
            mk(rd as u64, 0, read_only_dst as u64, 0, 1, 0),
        ) != Some(EBADF)
        {
            return Err("splice read-only output was not EBADF");
        }
        let append_dst = open_fd_flags(b"/abi/dst\0", O_WRONLY | O_APPEND)?;
        if call(
            Syscall::Splice.raw(),
            mk(rd as u64, 0, append_dst as u64, 0, 1, 0),
        ) != Some(EINVAL)
        {
            return Err("splice O_APPEND output was not EINVAL");
        }

        // The two ends of one pipe name one pipe_inode_info: EINVAL.
        if call(Syscall::Splice.raw(), mk(rd as u64, 0, wr as u64, 0, 1, 0)) != Some(EINVAL) {
            return Err("splice to the same pipe was not EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/splice", smoke_abi_fdio_splice_exact_validation);

/// O_NONBLOCK on either pipe endpoint implies SPLICE_F_NONBLOCK, and a pipe
/// whose last reader closed reports EPIPE (plus SIGPIPE) rather than EINVAL.
fn smoke_abi_fdio_splice_fd_nonblock_and_broken_pipe() -> TestResult {
    const O_NONBLOCK: u64 = 0o4000;
    with_memfs("/abi", "abi", &[("src", b"x")], || {
        let src = open_fd(b"/abi/src\0")?;
        let mut fds = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(fds.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes(fds[..4].try_into().unwrap()) as u32;
        let wr = i32::from_ne_bytes(fds[4..].try_into().unwrap()) as u32;
        let chunk = [0x55u8; 4096];
        for _ in 0..16 {
            if call(
                Syscall::Write.raw(),
                a2(wr as u64, chunk.as_ptr() as u64, chunk.len() as u64),
            ) != Some(chunk.len() as i64)
            {
                return Err("failed to fill nonblocking splice pipe");
            }
        }
        if call(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: src as u64,
                arg2: wr as u64,
                arg4: 1,
                ..Default::default()
            },
        ) != Some(EAGAIN)
        {
            return Err("pipe O_NONBLOCK did not imply splice EAGAIN");
        }

        if call(Syscall::Close.raw(), a0(rd as u64)) != Some(0) {
            return Err("closing splice pipe reader failed");
        }
        if call(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: src as u64,
                arg2: wr as u64,
                arg4: 1,
                ..Default::default()
            },
        ) != Some(EPIPE)
        {
            return Err("splice to a broken pipe was not EPIPE");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/splice",
    smoke_abi_fdio_splice_fd_nonblock_and_broken_pipe
);

/// splice(pipe → pipe) moves the queued bytes exactly once, reports the
/// moved count, and leaves the source drained.
fn smoke_abi_fdio_splice_pipe_to_pipe() -> TestResult {
    with_setup(|| {
        let (src_rd, src_wr) = make_pipe()?;
        let (dst_rd, dst_wr) = make_pipe()?;
        // Seed the source pipe with 5 bytes.
        let payload = *b"hello";
        if call(
            Syscall::Write.raw(),
            a2(src_wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(5)
        {
            return Err("seeding the source pipe failed");
        }
        // splice(src_rd, NULL, dst_wr, NULL, 5, 0) → 5 bytes moved.
        match call_raw(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: src_rd as u64,
                arg1: 0,
                arg2: dst_wr as u64,
                arg3: 0,
                arg4: 5,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 5 => {}
            _ => return Err("splice pipe→pipe did not move 5 bytes"),
        }
        // The bytes land in the destination pipe exactly once...
        let mut b = [0u8; 8];
        match call(
            Syscall::Read.raw(),
            a2(dst_rd as u64, b.as_mut_ptr() as u64, 8),
        ) {
            Some(5) if &b[..5] == b"hello" => {}
            _ => return Err("spliced bytes did not arrive in the destination pipe"),
        }
        // ...and the source is drained: a nonblocking read now EAGAINs (empty,
        // writer still open) rather than re-delivering the moved bytes.
        let _ = (src_rd, dst_wr);
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_splice_pipe_to_pipe);

/// A partially writable destination pipe must consume only the accepted
/// source prefix. The old generic copy core drained/read 64 KiB first and then
/// discarded `kbuf[written..]` after a short pipe write.
fn smoke_abi_fdio_splice_file_to_partial_pipe_preserves_tail() -> TestResult {
    let payload = alloc::vec![0x5Au8; 8192];
    with_memfs("/abi", "abi", &[("src", &payload)], || {
        let src = open_fd(b"/abi/src\0")?;
        let (dst_rd, dst_wr) = make_pipe()?;
        let filler = alloc::vec![0xA5u8; 65536 - 32];
        if call(
            Syscall::Write.raw(),
            a2(dst_wr as u64, filler.as_ptr() as u64, filler.len() as u64),
        ) != Some(filler.len() as i64)
        {
            return Err("failed to leave a 32-byte destination-pipe tail");
        }
        let splice = |len: usize| {
            call(
                Syscall::Splice.raw(),
                SyscallArgs {
                    arg0: src as u64,
                    arg1: 0,
                    arg2: dst_wr as u64,
                    arg3: 0,
                    arg4: len as u64,
                    arg5: 0,
                },
            )
        };
        if splice(payload.len()) != Some(32) {
            return Err("file splice did not report the accepted pipe prefix");
        }
        let mut first = alloc::vec![0u8; 65536];
        if call(
            Syscall::Read.raw(),
            a2(dst_rd as u64, first.as_mut_ptr() as u64, first.len() as u64),
        ) != Some(first.len() as i64)
            || first[..filler.len()] != filler
            || first[filler.len()..] != payload[..32]
        {
            return Err("first file splice corrupted the destination prefix");
        }
        if splice(payload.len()) != Some((payload.len() - 32) as i64) {
            return Err("file splice skipped the tail after a short write");
        }
        let mut tail = alloc::vec![0u8; payload.len() - 32];
        if call(
            Syscall::Read.raw(),
            a2(dst_rd as u64, tail.as_mut_ptr() as u64, tail.len() as u64),
        ) != Some(tail.len() as i64)
            || tail != payload[32..]
        {
            return Err("file splice lost or reordered its unwritten tail");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_splice_file_to_partial_pipe_preserves_tail
);

/// Pipe-to-pipe splice needs an atomic source-consume/destination-append
/// transaction: a 32-byte destination vacancy must leave the rest queued in
/// the source for the next call.
fn smoke_abi_fdio_splice_partial_pipe_to_pipe_preserves_tail() -> TestResult {
    with_setup(|| {
        let (src_rd, src_wr) = make_pipe()?;
        let (dst_rd, dst_wr) = make_pipe()?;
        let payload = alloc::vec![0x3Cu8; 8192];
        let filler = alloc::vec![0xC3u8; 65536 - 32];
        if call(
            Syscall::Write.raw(),
            a2(src_wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(payload.len() as i64)
            || call(
                Syscall::Write.raw(),
                a2(dst_wr as u64, filler.as_ptr() as u64, filler.len() as u64),
            ) != Some(filler.len() as i64)
        {
            return Err("failed to seed partial pipe-to-pipe splice");
        }
        let splice = |len: usize| {
            call(
                Syscall::Splice.raw(),
                SyscallArgs {
                    arg0: src_rd as u64,
                    arg1: 0,
                    arg2: dst_wr as u64,
                    arg3: 0,
                    arg4: len as u64,
                    arg5: 0,
                },
            )
        };
        if splice(payload.len()) != Some(32) {
            return Err("pipe splice did not stop at destination capacity");
        }
        let mut first = alloc::vec![0u8; 65536];
        if call(
            Syscall::Read.raw(),
            a2(dst_rd as u64, first.as_mut_ptr() as u64, first.len() as u64),
        ) != Some(first.len() as i64)
            || first[..filler.len()] != filler
            || first[filler.len()..] != payload[..32]
        {
            return Err("partial pipe splice corrupted the destination");
        }
        if splice(payload.len()) != Some((payload.len() - 32) as i64) {
            return Err("partial pipe splice did not retain the source tail");
        }
        let mut tail = alloc::vec![0u8; payload.len() - 32];
        if call(
            Syscall::Read.raw(),
            a2(dst_rd as u64, tail.as_mut_ptr() as u64, tail.len() as u64),
        ) != Some(tail.len() as i64)
            || tail != payload[32..]
        {
            return Err("partial pipe splice lost or reordered the source tail");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_splice_partial_pipe_to_pipe_preserves_tail
);

/// A non-pipe splice destination may use an explicit `off_out`. It advances
/// that pointer without changing the destination fd's own cursor.
fn smoke_abi_fdio_splice_honors_explicit_output_offset() -> TestResult {
    with_memfs("/abi", "abi", &[("dst", b"abcdef")], || {
        let dst = open_fd_flags(b"/abi/dst\0", 2)?; // O_RDWR
        let (src_rd, src_wr) = make_pipe()?;
        let payload = *b"XY";
        if call(
            Syscall::Write.raw(),
            a2(src_wr as u64, payload.as_ptr() as u64, payload.len() as u64),
        ) != Some(2)
        {
            return Err("failed to seed explicit-offset splice source");
        }
        let mut out_off = 2u64;
        if call(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: src_rd as u64,
                arg1: 0,
                arg2: dst as u64,
                arg3: (&mut out_off as *mut u64) as u64,
                arg4: 2,
                arg5: 0,
            },
        ) != Some(2)
            || out_off != 4
        {
            return Err("splice ignored or misadvanced explicit off_out");
        }
        let mut bytes = [0u8; 6];
        if call(
            Syscall::Read.raw(),
            a2(dst as u64, bytes.as_mut_ptr() as u64, bytes.len() as u64),
        ) != Some(6)
            || &bytes != b"abXYef"
        {
            return Err("explicit off_out changed the fd cursor or wrong bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_splice_honors_explicit_output_offset
);

/// vmsplice on a pipe READ end copies queued bytes OUT to user memory
/// (`fs/splice.c` SPLICE_TO_USER). This direction used to hit
/// `PipeRead::write`'s EBADF and abort stress-ng's vm-splice loop on the
/// first iteration; it now drains the ring into the iov buffer.
fn smoke_abi_fdio_vmsplice_from_pipe() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        // Queue 4 bytes into the pipe.
        let src = *b"data";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, src.as_ptr() as u64, src.len() as u64),
        ) != Some(4)
        {
            return Err("seeding the pipe failed");
        }
        // vmsplice(rd, iov→dst, 1, 0) drains up to 8 bytes into dst; the pipe
        // only holds 4, so it returns 4 and fills dst[..4].
        let mut dst = [0u8; 8];
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(dst.len() as u64).to_le_bytes());
        match call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, iov.as_ptr() as u64, 1, 0),
        ) {
            Some(4) if &dst[..4] == b"data" => Ok(()),
            _ => Err("vmsplice from a pipe read end did not drain 4 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_vmsplice_from_pipe);

/// A failed pipe→user vmsplice must not consume the source bytes.  Linux's
/// pipe-to-user actor advances the pipe only for bytes successfully copied;
/// this pins the stronger all-or-nothing behavior of NARF's guarded copy.
fn smoke_abi_fdio_vmsplice_efault_preserves_pipe() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        let src = *b"keep";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, src.as_ptr() as u64, src.len() as u64),
        ) != Some(src.len() as i64)
        {
            return Err("seeding the pipe failed");
        }

        let mut bad_iov = [0u8; 16];
        // Non-canonical on both supported architectures, so range validation
        // fails before any user byte or pipe byte can be touched.
        bad_iov[..8].copy_from_slice(&0x0001_0000_0000_0000u64.to_le_bytes());
        bad_iov[8..].copy_from_slice(&(src.len() as u64).to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, bad_iov.as_ptr() as u64, 1, 0),
        ) != Some(-14)
        {
            return Err("vmsplice to an invalid destination did not return EFAULT");
        }

        let mut out = [0u8; 4];
        match call(
            Syscall::Read.raw(),
            a2(rd as u64, out.as_mut_ptr() as u64, out.len() as u64),
        ) {
            Some(4) if out == src => Ok(()),
            _ => Err("vmsplice EFAULT consumed or reordered pipe data"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_vmsplice_efault_preserves_pipe);

/// The stress-ng vm-splice loop shape: vmsplice user memory INTO the pipe,
/// splice it OUT to a sink, then vmsplice the pipe read end back to memory —
/// all three make forward progress and the round-trip preserves the bytes.
/// Before the fix the final read-end vmsplice returned EBADF, which broke
/// the loop (0 bogo-ops).
fn smoke_abi_fdio_vmsplice_roundtrip_progress() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        let (sink_rd, sink_wr) = make_pipe()?;
        let payload = *b"vmsplice-roundtrip";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        // 1) gather user memory into the pipe write end.
        if call(
            Syscall::Vmsplice.raw(),
            a3(wr as u64, iov.as_ptr() as u64, 1, 0),
        ) != Some(payload.len() as i64)
        {
            return Err("vmsplice into the pipe did not gather the payload");
        }
        // 2) splice it out of the pipe read end into a sink pipe.
        match call_raw(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: rd as u64,
                arg1: 0,
                arg2: sink_wr as u64,
                arg3: 0,
                arg4: payload.len() as u64,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == payload.len() as i64 => {}
            _ => return Err("splice draining the pipe made no progress"),
        }
        // The source pipe is now empty, so a second vmsplice INTO it proceeds
        // (would have EAGAIN'd against a stuck-full pipe).
        if call(
            Syscall::Vmsplice.raw(),
            a3(wr as u64, iov.as_ptr() as u64, 1, 0),
        ) != Some(payload.len() as i64)
        {
            return Err("second vmsplice into the drained pipe did not proceed");
        }
        // 3) vmsplice the read end back to memory and verify the bytes.
        let mut back = [0u8; 32];
        let mut iov_back = [0u8; 16];
        iov_back[..8].copy_from_slice(&(back.as_mut_ptr() as u64).to_le_bytes());
        iov_back[8..].copy_from_slice(&(back.len() as u64).to_le_bytes());
        match call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, iov_back.as_ptr() as u64, 1, 0),
        ) {
            Some(n) if n == payload.len() as i64 && back[..payload.len()] == payload => {}
            _ => return Err("read-end vmsplice did not recover the payload"),
        }
        let _ = (sink_rd,);
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_vmsplice_roundtrip_progress);

// ── copy_file_range ────────────────────────────────────────────────

fn smoke_abi_fdio_copy_file_range_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"abcdef"), ("dst", b"")], || {
        let in_fd = open_fd(b"/abi/src\0")?;
        let out_fd = open_fd(b"/abi/dst\0")?;
        // copy_file_range(in, &off_in=1, out, &off_out=0, len=4, flags=0)
        // → 4 bytes copied from src[1..5], and the explicit offsets are
        // written back advanced (fd cursors untouched).
        let mut off_in: u64 = 1;
        let mut off_out: u64 = 0;
        match call_raw(
            Syscall::CopyFileRange.raw(),
            SyscallArgs {
                arg0: in_fd as u64,
                arg1: &mut off_in as *mut u64 as u64,
                arg2: out_fd as u64,
                arg3: &mut off_out as *mut u64 as u64,
                arg4: 4,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 4 => {
                if off_in != 5 || off_out != 4 {
                    return Err("copy_file_range did not write back advanced offsets");
                }
                Ok(())
            }
            _ => Err("copy_file_range did not copy 4 bytes"),
        }
    })
}

/// NULL offset pointers mean "use and advance each fd's own file
/// offset" — the shape glibc's `cat`/`cp` actually issue. A second
/// call must therefore resume where the first stopped and report EOF
/// rather than re-copying the same bytes forever.
fn smoke_abi_fdio_copy_file_range_null_offsets() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"abcdef"), ("dst", b"")], || {
        let in_fd = open_fd(b"/abi/src\0")?;
        let out_fd = open_fd(b"/abi/dst\0")?;
        let call = |len: u64| {
            call_raw(
                Syscall::CopyFileRange.raw(),
                SyscallArgs {
                    arg0: in_fd as u64,
                    arg1: 0, // NULL — use + advance the fd cursor
                    arg2: out_fd as u64,
                    arg3: 0, // NULL
                    arg4: len,
                    arg5: 0,
                },
            )
        };
        let first = call(6);
        if first.status != SyscallReturn::OK || first.value as i64 != 6 {
            return Err("copy_file_range(NULL offsets) did not copy 6 bytes");
        }
        // Cursor advanced to EOF ⇒ the follow-up copies nothing.
        let second = call(6);
        if second.status != SyscallReturn::OK || second.value as i64 != 0 {
            return Err("copy_file_range(NULL offsets) did not advance the fd cursor");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_copy_file_range_null_offsets);
kernel_test_in!("syscall_abi", smoke_abi_fdio_copy_file_range_pos);

fn smoke_abi_fdio_copy_file_range_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"abc"), ("dst", b"")], || {
        let in_fd = open_fd(b"/abi/src\0")?;
        let out_fd = open_fd(b"/abi/dst\0")?;
        // A non-zero flags word → -EINVAL, as Linux does (no flag is
        // defined for copy_file_range(2)).
        match call_raw(
            Syscall::CopyFileRange.raw(),
            SyscallArgs {
                arg0: in_fd as u64,
                arg1: 0,
                arg2: out_fd as u64,
                arg3: 0,
                arg4: 4,
                arg5: 1,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == -22 => {}
            _ => return Err("copy_file_range with non-zero flags was not -EINVAL"),
        }
        let in_fd = open_fd(b"/abi/src\0")?;
        let out_fd = open_fd(b"/abi/dst\0")?;
        let mut valid_offset = 0u64;
        // Keep this below USER_VA_LIMIT so it passes access_ok and faults in
        // the guarded copy itself. The former 0x1000 fixture is not reliably
        // unmapped on x86 NARF because low physical memory may be mapped.
        const UNMAPPED_USER: u64 = 0x0000_0080_0000_0000;
        for (off_in, off_out) in [
            (UNMAPPED_USER, &mut valid_offset as *mut u64 as u64),
            (&mut valid_offset as *mut u64 as u64, UNMAPPED_USER),
        ] {
            match call_raw(
                Syscall::CopyFileRange.raw(),
                SyscallArgs {
                    arg0: in_fd as u64,
                    arg1: off_in,
                    arg2: out_fd as u64,
                    arg3: off_out,
                    arg4: 1,
                    arg5: 0,
                },
            ) {
                r if r.status == SyscallReturn::OK && r.value as i64 == -14 => {}
                _ => return Err("copy_file_range guarded offset fault was not EFAULT"),
            }
        }
        for args in [
            // fd_in, then fd_out precede offset/flags and even zero length.
            SyscallArgs {
                arg0: 9999,
                arg1: 0x1000,
                arg2: out_fd as u64,
                arg3: 0,
                arg4: 1,
                arg5: 1,
            },
            SyscallArgs {
                arg0: in_fd as u64,
                arg1: 0,
                arg2: 9999,
                arg3: 0x1000,
                arg4: 0,
                arg5: 1,
            },
        ] {
            match call_raw(Syscall::CopyFileRange.raw(), args) {
                r if r.status == SyscallReturn::OK && r.value as i64 == -9 => {}
                _ => return Err("copy_file_range fd validation did not precede offsets/flags/len"),
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_copy_file_range_neg);

// ── tee ────────────────────────────────────────────────────────────
//
// tee(fd_in, fd_out, len, flags). Both ends must be distinct pipes; a
// non-pipe is -EINVAL. `fs/splice.c::ipipe_prep` returns 0 only once the
// source pipe has no writers left — a transient empty pipe waits, or
// -EAGAINs under SPLICE_F_NONBLOCK.

fn smoke_abi_fdio_tee_pos() -> TestResult {
    with_setup(|| {
        let (rd1, _wr1) = make_pipe()?;
        let (_rd2, wr2) = make_pipe()?;
        // The source is empty but its write end is still open, so this is not
        // end-of-stream. SPLICE_F_NONBLOCK (0x2) turns the wait into -EAGAIN;
        // reporting 0 (the old behaviour) told the caller the stream ended.
        match call(Syscall::Tee.raw(), a3(rd1 as u64, wr2 as u64, 16, 0x2)) {
            Some(v) if v == EAGAIN => Ok(()),
            _ => Err("tee on a live-but-empty pipe was not -EAGAIN"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_tee_pos);

fn smoke_abi_fdio_tee_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // fd_in is a regular file, not a pipe read end → -EINVAL.
        // (`do_tee`: `if (!ipipe || !opipe || ipipe == opipe) -EINVAL`.)
        match call(Syscall::Tee.raw(), a3(fd as u64, fd as u64, 16, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("tee on a non-pipe fd was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_tee_neg);

// ── vmsplice ───────────────────────────────────────────────────────
//
// vmsplice(fd, iov, nr_segs, flags) — gather user memory into the pipe
// referenced by fd (the write-to-pipe direction).

fn smoke_abi_fdio_vmsplice_pos() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        let payload = *b"ab";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        // vmsplice(wr, iov, 1, 0) → 2 bytes gathered into the pipe.
        match call(
            Syscall::Vmsplice.raw(),
            a3(wr as u64, iov.as_ptr() as u64, 1, 0),
        ) {
            Some(2) => Ok(()),
            _ => Err("vmsplice did not gather 2 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_vmsplice_pos);

fn smoke_abi_fdio_vmsplice_neg() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        // nr_segs > IOV_MAX (1024) → -EINVAL.
        match call(Syscall::Vmsplice.raw(), a3(wr as u64, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("vmsplice over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_vmsplice_neg);

/// Pin Linux's syscall-entry precedence (`fs/splice.c::vmsplice`): unknown
/// flags are checked first; fd/f_mode precede import_iovec; pipe identity is
/// checked only after a non-empty iovec has imported successfully.
fn smoke_abi_fdio_vmsplice_errno_order() -> TestResult {
    const BAD_PTR: u64 = 0x0001_0000_0000_0000;
    const UNKNOWN_FLAG: u64 = 0x10;
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        // Unknown flags win even when both fd and iovec are invalid.
        if call(Syscall::Vmsplice.raw(), a3(4242, BAD_PTR, 1, UNKNOWN_FLAG)) != Some(EINVAL) {
            return Err("vmsplice did not validate flags first");
        }
        // A missing fd wins over import_iovec errors and over IOV_MAX.
        if call(Syscall::Vmsplice.raw(), a3(4242, BAD_PTR, 1, 0)) != Some(EBADF)
            || call(Syscall::Vmsplice.raw(), a3(4242, BAD_PTR, 2000, 0)) != Some(EBADF)
        {
            return Err("vmsplice did not validate fd before the iovec");
        }

        let file_fd = open_fd(b"/abi/f\0")?;
        // A readable regular file passes fd/f_mode, so import_iovec's EFAULT
        // wins. With a valid non-empty iovec, get_pipe_info then yields EBADF.
        if call(Syscall::Vmsplice.raw(), a3(file_fd as u64, BAD_PTR, 1, 0)) != Some(EFAULT) {
            return Err("vmsplice checked pipe identity before import_iovec");
        }
        let payload = *b"x";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(file_fd as u64, iov.as_ptr() as u64, 1, 0),
        ) != Some(EBADF)
        {
            return Err("vmsplice on a non-pipe fd was not EBADF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/vmsplice", smoke_abi_fdio_vmsplice_errno_order);

/// Linux accepts a zero-segment NULL iovec after validating fd/f_mode, and an
/// imported all-zero vector returns 0 before get_pipe_info checks pipe type.
fn smoke_abi_fdio_vmsplice_zero_iovec() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let (_rd, wr) = make_pipe()?;
        if call(Syscall::Vmsplice.raw(), a3(wr as u64, 0, 0, 0)) != Some(0) {
            return Err("vmsplice rejected a NULL zero-segment iovec");
        }

        let file_fd = open_fd(b"/abi/f\0")?;
        if call(Syscall::Vmsplice.raw(), a3(file_fd as u64, 0, 0, 0)) != Some(0) {
            return Err("zero-segment vmsplice checked non-pipe identity");
        }
        let zero_iov = [0u8; 16];
        if call(
            Syscall::Vmsplice.raw(),
            a3(file_fd as u64, zero_iov.as_ptr() as u64, 1, 0),
        ) != Some(0)
        {
            return Err("all-zero vmsplice iovec did not return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi/vmsplice", smoke_abi_fdio_vmsplice_zero_iovec);

/// vmsplice into a pipe with no readers follows wait_for_space: SIGPIPE and
/// EPIPE, never the generic EINVAL previously used for every FileOps error.
fn smoke_abi_fdio_vmsplice_broken_pipe_errno() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        if call(Syscall::Close.raw(), a0(rd as u64)) != Some(0) {
            return Err("closing vmsplice pipe reader failed");
        }
        let payload = *b"x";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        match call(
            Syscall::Vmsplice.raw(),
            a3(wr as u64, iov.as_ptr() as u64, 1, 0),
        ) {
            Some(v) if v == EPIPE => Ok(()),
            _ => Err("vmsplice with no pipe readers was not EPIPE"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/vmsplice",
    smoke_abi_fdio_vmsplice_broken_pipe_errno
);

/// A real O_PATH open has neither FMODE_READ nor FMODE_WRITE and therefore
/// fails before the iovec is imported. This also pins F_GETFL: open_impl must
/// retain O_PATH instead of letting its low access-mode bits masquerade as
/// O_RDONLY.
fn smoke_abi_fdio_vmsplice_bad_mode_precedes_iovec() -> TestResult {
    const BAD_PTR: u64 = 0x0001_0000_0000_0000;
    const O_PATH: u64 = 0o10000000;
    const F_GETFL: u64 = 3;
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let file_fd = open_fd_flags(b"/abi/f\0", O_PATH)?;
        match call(Syscall::Fcntl.raw(), a2(file_fd as u64, F_GETFL, 0)) {
            Some(flags) if flags >= 0 && flags as u64 & O_PATH != 0 => {}
            _ => return Err("F_GETFL did not retain O_PATH on the open description"),
        }
        match call(Syscall::Vmsplice.raw(), a3(file_fd as u64, BAD_PTR, 1, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("vmsplice did not reject O_PATH before importing the iovec"),
        }
    })
}
kernel_test_in!(
    "syscall_abi/vmsplice",
    smoke_abi_fdio_vmsplice_bad_mode_precedes_iovec
);

/// Named FIFOs use the same pipe-to-user observe/copy/commit rule as
/// anonymous pipes. A fault after one completed iovec returns that prefix and
/// leaves the faulting segment queued; a fault before any progress returns
/// EFAULT and leaves the complete FIFO contents queued.
fn smoke_abi_fdio_vmsplice_named_fifo_copy_transaction() -> TestResult {
    const AT_FDCWD: u64 = (-100i64) as u64;
    const S_IFIFO: u64 = 0o010000;
    const O_WRONLY: u64 = 1;
    const O_NONBLOCK: u64 = 0o4000;
    const UNMAPPED_USER: u64 = 0x0000_0080_0000_0000;

    with_memfs("/abi", "abi", &[], || {
        let path = b"/abi/vmsplice.fifo\0";
        if call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, S_IFIFO | 0o600, 0),
        ) != Some(0)
        {
            return Err("failed to create named-FIFO vmsplice fixture");
        }
        // A nonblocking reader may open before its writer. Once it is present,
        // the nonblocking writer also opens without ENXIO.
        let rd = open_fd_flags(path, O_NONBLOCK)?;
        let wr = open_fd_flags(path, O_WRONLY | O_NONBLOCK)?;

        let first = *b"abcdef";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, first.as_ptr() as u64, first.len() as u64),
        ) != Some(first.len() as i64)
        {
            return Err("failed to seed named FIFO");
        }

        let mut prefix = [0u8; 3];
        let mut split_iov = [0u8; 32];
        split_iov[..8].copy_from_slice(&(prefix.as_mut_ptr() as u64).to_le_bytes());
        split_iov[8..16].copy_from_slice(&3u64.to_le_bytes());
        split_iov[16..24].copy_from_slice(&UNMAPPED_USER.to_le_bytes());
        split_iov[24..32].copy_from_slice(&3u64.to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, split_iov.as_ptr() as u64, 2, 0),
        ) != Some(3)
            || prefix != *b"abc"
        {
            return Err("named-FIFO vmsplice did not return its copied prefix");
        }

        let mut tail = [0u8; 3];
        let mut tail_iov = [0u8; 16];
        tail_iov[..8].copy_from_slice(&(tail.as_mut_ptr() as u64).to_le_bytes());
        tail_iov[8..].copy_from_slice(&3u64.to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, tail_iov.as_ptr() as u64, 1, 0),
        ) != Some(3)
            || tail != *b"def"
        {
            return Err("faulting named-FIFO segment was consumed or reordered");
        }

        let second = *b"ghi";
        if call(
            Syscall::Write.raw(),
            a2(wr as u64, second.as_ptr() as u64, second.len() as u64),
        ) != Some(second.len() as i64)
        {
            return Err("failed to reseed named FIFO");
        }
        let mut bad_iov = [0u8; 16];
        bad_iov[..8].copy_from_slice(&UNMAPPED_USER.to_le_bytes());
        bad_iov[8..].copy_from_slice(&3u64.to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, bad_iov.as_ptr() as u64, 1, 0),
        ) != Some(EFAULT)
        {
            return Err("zero-progress named-FIFO copy fault was not EFAULT");
        }

        let mut retry = [0u8; 3];
        let mut retry_iov = [0u8; 16];
        retry_iov[..8].copy_from_slice(&(retry.as_mut_ptr() as u64).to_le_bytes());
        retry_iov[8..].copy_from_slice(&3u64.to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(rd as u64, retry_iov.as_ptr() as u64, 1, 0),
        ) != Some(3)
            || retry != second
        {
            return Err("zero-progress copy fault consumed named-FIFO bytes");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/vmsplice",
    smoke_abi_fdio_vmsplice_named_fifo_copy_transaction
);

/// A nonblocking `vmsplice(SPLICE_F_NONBLOCK)` into a full pipe returns
/// -EAGAIN before gathering anything (`fs/splice.c::vmsplice_to_pipe` →
/// wait_for_space, short-circuited by O_NONBLOCK). Without the full-pipe
/// pre-check the write returned a 0-byte success, which stalls forward
/// progress instead of signalling back-pressure.
fn smoke_abi_fdio_vmsplice_full_pipe_eagain() -> TestResult {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    const O_NONBLOCK: u64 = 0o4000;
    with_setup(|| {
        let mut pipe_fds = [0u8; 8];
        if call(
            Syscall::Pipe2.raw(),
            a1(pipe_fds.as_mut_ptr() as u64, O_NONBLOCK),
        ) != Some(0)
        {
            return Err("pipe2(O_NONBLOCK) failed");
        }
        let rd = i32::from_ne_bytes(pipe_fds[..4].try_into().unwrap()) as u32;
        let wr = i32::from_ne_bytes(pipe_fds[4..].try_into().unwrap()) as u32;
        // Fill the pipe to capacity (64 KiB) with 4 KiB chunks.
        let chunk = [0x5Au8; 4096];
        for _ in 0..16 {
            if call(
                Syscall::Write.raw(),
                a2(wr as u64, chunk.as_ptr() as u64, chunk.len() as u64),
            ) != Some(chunk.len() as i64)
            {
                return Err("filling the pipe did not take a full 4 KiB chunk");
            }
        }
        // A further nonblocking vmsplice must report back-pressure, not 0.
        let payload = *b"ab";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(wr as u64, iov.as_ptr() as u64, 1, SPLICE_F_NONBLOCK),
        ) != Some(EAGAIN)
        {
            return Err("vmsplice into a full pipe was not -EAGAIN");
        }
        // import_iovec validates each payload range before wait_for_space.
        // Therefore an invalid payload pointer beats full-pipe EAGAIN.
        let mut bad_iov = [0u8; 16];
        bad_iov[..8].copy_from_slice(&0x0001_0000_0000_0000u64.to_le_bytes());
        bad_iov[8..].copy_from_slice(&1u64.to_le_bytes());
        if call(
            Syscall::Vmsplice.raw(),
            a3(wr as u64, bad_iov.as_ptr() as u64, 1, SPLICE_F_NONBLOCK),
        ) != Some(EFAULT)
        {
            return Err("full-pipe EAGAIN masked vmsplice payload EFAULT");
        }
        // Drain the pipe so the fixture tears down cleanly, and confirm the
        // refused vmsplice queued nothing (still exactly 64 KiB).
        let mut sink = [0u8; 4096];
        let mut drained = 0usize;
        loop {
            match call(
                Syscall::Read.raw(),
                a2(rd as u64, sink.as_mut_ptr() as u64, 4096),
            ) {
                Some(n) if n > 0 => drained += n as usize,
                _ => break,
            }
            if drained >= 65536 {
                break;
            }
        }
        if drained != 65536 {
            return Err("refused vmsplice altered the pipe contents");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/vmsplice",
    smoke_abi_fdio_vmsplice_full_pipe_eagain
);

// ── F_SETLKW: EINTR + harness-degrade + exit-sweep release ──
//
// The blocking half of the record-lock TODO(wave-69): a conflicting
// F_SETLKW now parks-and-retries in real runs. In the harness (no
// executor) it degrades to the EAGAIN answer, which is also what this
// smoke pins — plus the two liveness edges around the block: a pending
// signal must break the wait (-EINTR), and a dead holder's locks must
// vanish (locks::release_owner in the exit sweep) so a retry succeeds.

fn smoke_abi_fdio_setlkw_conflict_paths() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        const F_SETLK: u64 = 6;
        const F_SETLKW: u64 = 7;
        // flock { l_type: i16, l_whence: i16, pad, l_start: i64, l_len: i64, l_pid: i32 }
        // F_WRLCK = 1, SEEK_SET = 0. Whole file (len 0).
        let fl_wr: [i64; 4] = [1, 0, 0, 0]; // type+whence packed in word 0 (LE)
        let path = b"/p/f\0";
        const AT_FDCWD: u64 = (-100i64) as u64;
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 2, 0), // O_RDWR
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(/p/f, O_RDWR) should succeed"),
        };
        // Own lock: SETLK succeeds.
        if call(Syscall::Fcntl.raw(), a2(fd, F_SETLK, fl_wr.as_ptr() as u64)) != Some(0) {
            return Err("F_SETLK(WRLCK) on an uncontended file should return 0");
        }
        // A FOREIGN owner's conflicting write lock: install directly in
        // the lock table (the harness has one task id, so the syscall
        // path can't create a second owner).
        let key = crate::fd::with_table(crate::handlers::current_task_id(), |t| {
            t.get(fd as u32)
                .map(|e| alloc::sync::Arc::as_ptr(&e.ops) as *const () as usize)
        })
        .flatten()
        .ok_or("fd should resolve to an ops key")?;
        crate::fd::locks::__test_reset();
        let foreign = crate::fd::locks::Lock {
            owner: 0xF0E1,
            ty: crate::fd::locks::F_WRLCK,
            start: 0,
            len: 0,
        };
        if crate::fd::locks::try_set(key, foreign).is_err() {
            return Err("installing the foreign holder should succeed");
        }
        // F_SETLKW against the foreign holder: no executor in the
        // harness → the degrade path answers -EAGAIN (-11).
        if call(
            Syscall::Fcntl.raw(),
            a2(fd, F_SETLKW, fl_wr.as_ptr() as u64),
        ) != Some(-11)
        {
            return Err("blocked F_SETLKW must degrade to -EAGAIN without an executor");
        }
        // Pending signal breaks the wait BEFORE parking: -EINTR.
        crate::handlers::raise_signal_pending(crate::handlers::current_task_id(), 10);
        let r = call(
            Syscall::Fcntl.raw(),
            a2(fd, F_SETLKW, fl_wr.as_ptr() as u64),
        );
        crate::handlers::clear_signal_pending(crate::handlers::current_task_id(), 10);
        if r != Some(-4) {
            return Err("blocked F_SETLKW with a pending signal must return -EINTR");
        }
        // Holder "exits": the exit sweep's release_owner clears its
        // locks, and the same F_SETLKW now succeeds.
        crate::fd::locks::release_owner(0xF0E1);
        if call(
            Syscall::Fcntl.raw(),
            a2(fd, F_SETLKW, fl_wr.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("F_SETLKW must succeed once the dead holder's locks are released");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_setlkw_conflict_paths);

// ── F_SETLKW unlock wake: waiters drain + deadline clears ──
//
// The waiter fast path: a parked SETLKW registers (key, tid, waker);
// the holder's F_UNLCK drains the queue and wake_one clears each
// waiter's sleep deadline so its re-poll retries immediately (the 1 ms
// wheel entry stays armed purely as the lost-wake backstop).
fn smoke_abi_fdio_setlkw_unlock_wakes_waiters() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        fn noop_waker() -> core::task::Waker {
            use core::task::{RawWaker, RawWakerVTable, Waker};
            fn rw() -> RawWaker {
                unsafe fn cl(_: *const ()) -> RawWaker {
                    rw()
                }
                unsafe fn nop(_: *const ()) {}
                const V: RawWakerVTable = RawWakerVTable::new(cl, nop, nop, nop);
                RawWaker::new(core::ptr::null(), &V)
            }
            // SAFETY: no-op vtable, single-threaded test scope.
            unsafe { Waker::from_raw(rw()) }
        }
        const AT_FDCWD: u64 = (-100i64) as u64;
        const F_SETLK: u64 = 6;
        let path = b"/p/f\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 2, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(/p/f, O_RDWR) should succeed"),
        };
        let key = crate::fd::with_table(crate::handlers::current_task_id(), |t| {
            t.get(fd as u32)
                .map(|e| alloc::sync::Arc::as_ptr(&e.ops) as *const () as usize)
        })
        .flatten()
        .ok_or("fd should resolve to an ops key")?;
        // Hold a write lock, park a fake waiter on the key with a live
        // finite deadline (what a real SETLKW park leaves behind).
        let wr: [i64; 4] = [1, 0, 0, 0];
        if call(Syscall::Fcntl.raw(), a2(fd, F_SETLK, wr.as_ptr() as u64)) != Some(0) {
            return Err("taking the write lock should succeed");
        }
        const WAITER: u64 = 0x7B01;
        crate::handlers::register_task_to_pid(WAITER, WAITER);
        crate::handlers::register_pid_task_mapping(WAITER, WAITER);
        if crate::task::task_get(WAITER).is_none() {
            let _ = crate::task::Task::new_registered(WAITER, WAITER);
        }
        if let Some(t) = crate::task::task_get(WAITER) {
            t.uctx
                .sleep_deadline_ns
                .store(55, core::sync::atomic::Ordering::Release);
        }
        crate::fd::locks::register_waiter(key, WAITER, noop_waker());
        // Unlock through the real syscall: the Ok arm must drain + wake.
        let un: [i64; 4] = [2, 0, 0, 0]; // F_UNLCK
        if call(Syscall::Fcntl.raw(), a2(fd, F_SETLK, un.as_ptr() as u64)) != Some(0) {
            return Err("F_UNLCK should succeed");
        }
        let deadline = crate::task::task_get(WAITER)
            .map(|t| {
                t.uctx
                    .sleep_deadline_ns
                    .load(core::sync::atomic::Ordering::Acquire)
            })
            .unwrap_or(u64::MAX);
        let leftover = crate::fd::locks::drain_waiters(key).len();
        crate::handlers::release_reaped_task(WAITER); // registry hygiene
        if deadline != 0 {
            return Err("unlock must clear the parked waiter's sleep deadline");
        }
        if leftover != 0 {
            return Err("unlock must drain the key's waiter queue");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_setlkw_unlock_wakes_waiters);

// F_GETLK must report the conflicting lock owner's pid in the CALLER's
// namespace (Linux locks_translate_pid), not the raw scheduler TaskId the
// lock table stores. lslocks/sqlite/dpkg read l_pid.
fn smoke_abi_fdio_getlk_reports_owner_visible_pid() -> TestResult {
    const F_GETLK: u64 = 5;
    const F_WRLCK: i16 = 1;
    const FOREIGN_TASK: u64 = 0xF0E1;
    const FOREIGN_PID: u64 = 0xBEEF; // distinct from the TaskId
    with_memfs("/lk", "lk", &[("f", b"hi")], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        let path = b"/lk/f\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 2, 0), // O_RDWR
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(/lk/f, O_RDWR) should succeed"),
        };
        let key = crate::fd::with_table(crate::handlers::current_task_id(), |t| {
            t.get(fd as u32)
                .map(|e| alloc::sync::Arc::as_ptr(&e.ops) as *const () as usize)
        })
        .flatten()
        .ok_or("fd should resolve to an ops key")?;

        // A foreign owner (a TaskId) holds a whole-file write lock; that
        // TaskId maps to a distinct visible pid.
        crate::fd::locks::__test_reset();
        crate::handlers::register_task_to_pid(FOREIGN_TASK, FOREIGN_PID);
        crate::handlers::register_pid_task_mapping(FOREIGN_PID, FOREIGN_TASK);
        let foreign = crate::fd::locks::Lock {
            owner: FOREIGN_TASK,
            ty: F_WRLCK,
            start: 0,
            len: 0,
        };
        if crate::fd::locks::try_set(key, foreign).is_err() {
            return Err("installing the foreign holder should succeed");
        }

        // F_GETLK with a conflicting request returns the blocker's l_pid.
        // struct flock: l_type@0(i16) l_whence@2(i16) l_start@8(i64)
        // l_len@16(i64) l_pid@24(i32).
        let mut fl = [0u8; 32];
        fl[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        let r = call(
            Syscall::Fcntl.raw(),
            a2(fd, F_GETLK, fl.as_mut_ptr() as u64),
        );
        crate::fd::locks::__test_reset();
        if r != Some(0) {
            return Err("F_GETLK should return 0");
        }
        let l_pid = i32::from_le_bytes(fl[24..28].try_into().unwrap()) as u64;
        match l_pid {
            FOREIGN_PID => Ok(()),
            FOREIGN_TASK => {
                Err("F_GETLK reported the raw scheduler TaskId as l_pid instead of the visible pid")
            }
            _ => Err("F_GETLK reported an unexpected l_pid"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fdio_getlk_reports_owner_visible_pid
);
