//! Linux syscall ABI conformance — fdio group.
#![cfg(feature = "linux-compat")]
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
/// an `Err` message. flags=0 — MemFs ignores the access mode.
fn open_fd(path: &[u8]) -> Result<u32, &'static str> {
    let ptr = path.as_ptr() as u64;
    match call_open(ptr, 0) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open failed"),
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

fn smoke_abi_fdio_writev_neg() -> TestResult {
    with_setup(|| {
        // iovcnt > IOV_MAX (1024) → -EINVAL (Ok status, value -22).
        match call(Syscall::Writev.raw(), a2(3, 0x1000, 2000)) {
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
        match call(Syscall::Readv.raw(), a2(3, 0x1000, 2000)) {
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
    with_setup(|| {
        // iovcnt > IOV_MAX → -EINVAL.
        match call(Syscall::Pwritev.raw(), a3(3, 0x1000, 2000, 0)) {
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
    with_setup(
        || match call(Syscall::Preadv.raw(), a3(3, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("preadv over IOV_MAX was not -EINVAL"),
        },
    )
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
        // LINUX-GAP: Linux dup(2) on a bad fd returns -EBADF; NARF
        // reports InvalidOp.
        match call_raw(Syscall::Dup.raw(), a0(6543)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("dup on bad fd was not InvalidOp"),
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
        // dup3 requires oldfd != newfd (unlike dup2) → InvalidOp when equal.
        // LINUX-GAP: Linux dup3(fd, fd, 0) returns -EINVAL.
        match call_raw(Syscall::Dup3.raw(), a2(fd as u64, fd as u64, 0)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("dup3(fd, fd, 0) was not InvalidOp"),
        }
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
        // fstat on a bad fd → -1 sentinel (Ok status, value -1).
        // LINUX-GAP: Linux fstat(2) returns -EBADF, not the bare -1.
        match call(Syscall::Fstat.raw(), a1(5252, stat.as_mut_ptr() as u64)) {
            Some(-1) => Ok(()),
            _ => Err("fstat on bad fd was not -1"),
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
        // bad fd → -1 sentinel.
        // LINUX-GAP: Linux ftruncate(2) returns -EBADF.
        match call(Syscall::Ftruncate.raw(), a1(4949, 0)) {
            Some(-1) => Ok(()),
            _ => Err("ftruncate on bad fd was not -1"),
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
        // null out-pointer → InvalidOp.
        // LINUX-GAP: Linux pipe(2) returns -EFAULT for a bad buffer.
        match call_raw(Syscall::Pipe.raw(), a0(0)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("pipe with null buffer was not InvalidOp"),
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
        // LINUX-GAP: Linux pipe2(2) returns -EFAULT for a bad buffer.
        match call_raw(Syscall::Pipe2.raw(), a1(0, 0)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("pipe2 with null buffer was not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_pipe2_neg);

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
        // bad fd → -1 sentinel.
        // LINUX-GAP: Linux flock(2) returns -EBADF.
        match call(Syscall::Flock.raw(), a1(4444, 2 | 4)) {
            Some(-1) => Ok(()),
            _ => Err("flock on bad fd was not -1"),
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
        let out_fd = open_fd(b"/abi/dst\0")?;
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
        let out_fd = open_fd(b"/abi/dst\0")?;
        // bad in_fd → copy_fd_to_fd fails → -1 sentinel.
        // LINUX-GAP: Linux sendfile(2) returns -EBADF.
        match call(Syscall::Sendfile.raw(), a3(out_fd as u64, 7070, 0, 4)) {
            Some(-1) => Ok(()),
            _ => Err("sendfile with bad in_fd was not -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_sendfile_neg);

// ── splice ─────────────────────────────────────────────────────────
//
// splice(fd_in, off_in*, fd_out, off_out*, len, flags). NARF reuses the
// sendfile copy core (no pipe requirement enforced), so a file→file
// copy is the reachable success.

fn smoke_abi_fdio_splice_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("src", b"xyz"), ("dst", b"")], || {
        let in_fd = open_fd(b"/abi/src\0")?;
        let out_fd = open_fd(b"/abi/dst\0")?;
        // splice(in, NULL, out, NULL, 3, 0) → 3 bytes.
        match call_raw(
            Syscall::Splice.raw(),
            SyscallArgs {
                arg0: in_fd as u64,
                arg1: 0,
                arg2: out_fd as u64,
                arg3: 0,
                arg4: 3,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 3 => Ok(()),
            _ => Err("splice did not copy 3 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_splice_pos);

fn smoke_abi_fdio_splice_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("dst", b"")], || {
        let out_fd = open_fd(b"/abi/dst\0")?;
        // bad fd_in → -1 sentinel.
        // LINUX-GAP: Linux splice(2) returns -EBADF.
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
            r if r.status == SyscallReturn::OK && r.value as i64 == -1 => Ok(()),
            _ => Err("splice with bad fd_in was not -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_splice_neg);

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
            r if r.status == SyscallReturn::OK && r.value as i64 == -22 => Ok(()),
            _ => Err("copy_file_range with non-zero flags was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_copy_file_range_neg);

// ── tee ────────────────────────────────────────────────────────────
//
// tee(fd_in, fd_out, len, flags). fd_in must be a pipe read end
// (peekable). An empty pipe peeks to an empty slice → tee returns 0
// without consuming — the reachable success. A non-pipe fd_in → EINVAL.

fn smoke_abi_fdio_tee_pos() -> TestResult {
    with_setup(|| {
        let (rd1, _wr1) = make_pipe()?;
        let (_rd2, wr2) = make_pipe()?;
        // Empty source pipe → peek yields no bytes → tee returns 0.
        match call(Syscall::Tee.raw(), a3(rd1 as u64, wr2 as u64, 16, 0)) {
            Some(0) => Ok(()),
            _ => Err("tee on an empty pipe did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_tee_pos);

fn smoke_abi_fdio_tee_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd(b"/abi/f\0")?;
        // fd_in is a regular file, not a pipe read end → -EINVAL.
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
        // nr_segs > IOV_MAX (1024) → -EINVAL.
        match call(Syscall::Vmsplice.raw(), a3(3, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("vmsplice over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio_vmsplice_neg);

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
