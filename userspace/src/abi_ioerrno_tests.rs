//! Linux syscall ABI conformance — I/O **errno** group.
//!
//! The other `abi_*_tests` groups mostly assert what a syscall *does*. This
//! one asserts the number it fails with, because that number is a functional
//! contract: userspace branches on it. Every case here pins one arm of one
//! I/O syscall against the corresponding `if` in the kernel it mirrors, cited
//! per test. They exist because a family of NARF handlers used to answer every
//! failure with the `-1` sentinel, which reaches userspace as EPERM —
//! "Operation not permitted" for a closed fd, a faulting buffer, an
//! already-registered epoll fd, or a contended flock.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

const ELOOP: i64 = -40;
const EOPNOTSUPP: i64 = -95;

/// Canonical-but-unmapped user address: in the user half, so `access_ok`
/// accepts it, but no page backs it, so the guarded copy faults.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

/// Open `path` (NUL-terminated) with `flags`; return the fd.
fn open_fd_flags(path: &[u8], flags: u64) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, flags) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open failed"),
    }
}

fn open_rw(path: &[u8]) -> Result<u32, &'static str> {
    open_fd_flags(path, crate::fd::O_RDWR as u64)
}

/// One `struct iovec { void *base; size_t len; }`, LP64 layout.
fn iovec(base: u64, len: u64) -> [u8; 16] {
    let mut iov = [0u8; 16];
    iov[..8].copy_from_slice(&base.to_ne_bytes());
    iov[8..].copy_from_slice(&len.to_ne_bytes());
    iov
}

/// `pipe(2)` → `(read_fd, write_fd)`.
fn make_pipe() -> Result<(u32, u32), &'static str> {
    let mut buf = [0u8; 8];
    let r = call_raw(Syscall::Pipe.raw(), a0(buf.as_mut_ptr() as u64));
    if r.status != SyscallReturn::OK || r.value as i64 != 0 {
        return Err("pipe failed");
    }
    Ok((
        i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u32,
        i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u32,
    ))
}

/// Assert `got == want`, naming the syscall so a regression says which.
fn expect(got: Option<i64>, want: i64, what: &'static str) -> Result<(), &'static str> {
    match got {
        Some(v) if v == want => Ok(()),
        _ => Err(what),
    }
}

// ── pread64 / pwrite64 ─────────────────────────────────────────────
//
// `fs/read_write.c::ksys_pread64`:
//     if (pos < 0) return -EINVAL;
//     CLASS(fd, f)(fd); if (fd_empty(f)) return -EBADF;
//     if (f->f_mode & FMODE_PREAD) return vfs_read(...);
//     return -ESPIPE;
// and `vfs_read` checks FMODE_READ (-EBADF) before access_ok (-EFAULT).

fn smoke_abi_ioerrno_pread64_negative_offset() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let mut buf = [0u8; 4];
        expect(
            call(
                Syscall::Pread64.raw(),
                a3(fd as u64, buf.as_mut_ptr() as u64, 4, u64::MAX),
            ),
            EINVAL,
            "pread64 with a negative offset must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pread64_negative_offset);

fn smoke_abi_ioerrno_pread64_zero_len_bad_fd() -> TestResult {
    with_setup(|| {
        // The fd is resolved before vfs_read, so a zero-length pread on a
        // closed descriptor is still -EBADF, not a 0-byte success.
        expect(
            call(Syscall::Pread64.raw(), a3(4242, 0, 0, 0)),
            EBADF,
            "zero-length pread64 on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pread64_zero_len_bad_fd);

fn smoke_abi_ioerrno_pread64_wronly_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd_flags(b"/abi/f\0", crate::fd::O_WRONLY as u64)?;
        let mut buf = [0u8; 4];
        // vfs_read: `if (!(file->f_mode & FMODE_READ)) return -EBADF;`
        expect(
            call(
                Syscall::Pread64.raw(),
                a3(fd as u64, buf.as_mut_ptr() as u64, 4, 0),
            ),
            EBADF,
            "pread64 on a write-only fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pread64_wronly_fd);

fn smoke_abi_ioerrno_pread64_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        let mut buf = [0u8; 4];
        // A pipe never carries FMODE_PREAD, so ksys_pread64 falls through to
        // its -ESPIPE tail rather than consuming bytes "at an offset".
        expect(
            call(
                Syscall::Pread64.raw(),
                a3(rd as u64, buf.as_mut_ptr() as u64, 4, 0),
            ),
            ESPIPE,
            "pread64 on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pread64_pipe_espipe);

fn smoke_abi_ioerrno_pread64_efault() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Pread64.raw(), a3(fd as u64, BAD_PTR, 4, 0)),
            EFAULT,
            "pread64 into an unmapped buffer must be -EFAULT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pread64_efault);

fn smoke_abi_ioerrno_pwrite64_negative_offset() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"......")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let data = *b"z";
        expect(
            call(
                Syscall::Pwrite64.raw(),
                a3(fd as u64, data.as_ptr() as u64, 1, u64::MAX),
            ),
            EINVAL,
            "pwrite64 with a negative offset must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pwrite64_negative_offset);

fn smoke_abi_ioerrno_pwrite64_rdonly_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"......")], || {
        let fd = open_fd_flags(b"/abi/f\0", crate::fd::O_RDONLY as u64)?;
        let data = *b"z";
        // vfs_write: `if (!(file->f_mode & FMODE_WRITE)) return -EBADF;`
        expect(
            call(
                Syscall::Pwrite64.raw(),
                a3(fd as u64, data.as_ptr() as u64, 1, 0),
            ),
            EBADF,
            "pwrite64 on a read-only fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pwrite64_rdonly_fd);

fn smoke_abi_ioerrno_pwrite64_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        let data = *b"z";
        expect(
            call(
                Syscall::Pwrite64.raw(),
                a3(wr as u64, data.as_ptr() as u64, 1, 0),
            ),
            ESPIPE,
            "pwrite64 on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pwrite64_pipe_espipe);

// ── preadv / pwritev / preadv2 / pwritev2 ──────────────────────────
//
// `fs/read_write.c::do_preadv` has the same shape as ksys_pread64, and
// `SYSCALL_DEFINE6(preadv2)` routes `pos == -1` to plain `do_readv`.

fn smoke_abi_ioerrno_preadv_bad_fd() -> TestResult {
    with_setup(|| {
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        expect(
            call(Syscall::Preadv.raw(), a3(4242, iov.as_ptr() as u64, 1, 0)),
            EBADF,
            "preadv on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv_bad_fd);

fn smoke_abi_ioerrno_preadv_negative_offset() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        // preadv has no `pos == -1` escape hatch — only preadv2 does — so a
        // negative offset is -EINVAL here even though it is legal there.
        expect(
            call(
                Syscall::Preadv.raw(),
                a3(fd as u64, iov.as_ptr() as u64, 1, u64::MAX),
            ),
            EINVAL,
            "preadv with a negative offset must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv_negative_offset);

fn smoke_abi_ioerrno_preadv_iov_max() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // import_iovec() caps at UIO_MAXIOV (1024) with -EINVAL. The fd must
        // be valid for this to be the failure under test: on a closed fd,
        // do_preadv reports -EBADF first.
        expect(
            call(Syscall::Preadv.raw(), a3(fd as u64, BAD_PTR, 2000, 0)),
            EINVAL,
            "preadv above IOV_MAX must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv_iov_max);

fn smoke_abi_ioerrno_preadv_efault() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let iov = iovec(BAD_PTR, 4);
        expect(
            call(
                Syscall::Preadv.raw(),
                a3(fd as u64, iov.as_ptr() as u64, 1, 0),
            ),
            EFAULT,
            "preadv into an unmapped iovec must be -EFAULT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv_efault);

fn smoke_abi_ioerrno_preadv_wronly_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd_flags(b"/abi/f\0", crate::fd::O_WRONLY as u64)?;
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        expect(
            call(
                Syscall::Preadv.raw(),
                a3(fd as u64, iov.as_ptr() as u64, 1, 0),
            ),
            EBADF,
            "preadv on a write-only fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv_wronly_fd);

fn smoke_abi_ioerrno_pwritev_rdonly_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"......")], || {
        let fd = open_fd_flags(b"/abi/f\0", crate::fd::O_RDONLY as u64)?;
        let payload = *b"XY";
        let iov = iovec(payload.as_ptr() as u64, 2);
        expect(
            call(
                Syscall::Pwritev.raw(),
                a3(fd as u64, iov.as_ptr() as u64, 1, 0),
            ),
            EBADF,
            "pwritev on a read-only fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pwritev_rdonly_fd);

fn smoke_abi_ioerrno_preadv_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        expect(
            call(
                Syscall::Preadv.raw(),
                a3(rd as u64, iov.as_ptr() as u64, 1, 0),
            ),
            ESPIPE,
            "preadv on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv_pipe_espipe);

fn smoke_abi_ioerrno_preadv2_current_position() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // Advance the shared file position by two bytes.
        let mut head = [0u8; 2];
        if call(
            Syscall::Read.raw(),
            a2(fd as u64, head.as_mut_ptr() as u64, 2),
        ) != Some(2)
        {
            return Err("seed read did not consume two bytes");
        }
        let mut dst = [0u8; 8];
        let iov = iovec(dst.as_mut_ptr() as u64, 8);
        // `pos == -1` makes preadv2 behave exactly like readv: read from the
        // current position, not from literal offset (loff_t)-1 — which the
        // old code did, reporting a spurious 0-byte EOF.
        let got = call_raw(
            Syscall::Preadv2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: u64::MAX,
                arg4: u64::MAX,
                arg5: 0,
            },
        );
        if got.status != SyscallReturn::OK || got.value as i64 != 4 || &dst[..4] != b"cdef" {
            return Err("preadv2 at pos == -1 must read from the current position");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv2_current_position);

// ── ftruncate / truncate ───────────────────────────────────────────
//
// `fs/open.c::do_sys_ftruncate`: length < 0 -> -EINVAL, closed fd -> -EBADF,
// then `do_ftruncate`: !S_ISREG || !FMODE_WRITE -> -EINVAL.
// `do_sys_truncate` + `vfs_truncate`: length < 0 -> -EINVAL, lookup failure
// -> -ENOENT, S_ISDIR -> -EISDIR, !S_ISREG -> -EINVAL.

fn smoke_abi_ioerrno_ftruncate_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Ftruncate.raw(), a1(4242, 0)),
            EBADF,
            "ftruncate on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_ftruncate_bad_fd);

fn smoke_abi_ioerrno_ftruncate_negative_length() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Ftruncate.raw(), a1(fd as u64, u64::MAX)),
            EINVAL,
            "ftruncate with a negative length must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_ftruncate_negative_length);

fn smoke_abi_ioerrno_ftruncate_rdonly_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd_flags(b"/abi/f\0", crate::fd::O_RDONLY as u64)?;
        // Note this is -EINVAL, NOT -EBADF: do_sys_ftruncate has already
        // accepted the descriptor by the time do_ftruncate tests FMODE_WRITE.
        expect(
            call(Syscall::Ftruncate.raw(), a1(fd as u64, 2)),
            EINVAL,
            "ftruncate on a read-only fd must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_ftruncate_rdonly_fd);

fn smoke_abi_ioerrno_ftruncate_pipe() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        expect(
            call(Syscall::Ftruncate.raw(), a1(wr as u64, 0)),
            EINVAL,
            "ftruncate on a pipe must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_ftruncate_pipe);

fn smoke_abi_ioerrno_truncate_missing_path() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        // ENOENT is what makes the create-if-missing fallback work; the old
        // `-1` sentinel reported this as EPERM instead.
        expect(
            call(Syscall::Truncate.raw(), a1(c"/abi/nope".as_ptr() as u64, 0)),
            ENOENT,
            "truncate on a missing path must be -ENOENT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_truncate_missing_path);

fn smoke_abi_ioerrno_truncate_negative_length() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        expect(
            call(
                Syscall::Truncate.raw(),
                a1(c"/abi/f".as_ptr() as u64, u64::MAX),
            ),
            EINVAL,
            "truncate with a negative length must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_truncate_negative_length);

// ── fallocate ──────────────────────────────────────────────────────
//
// `SYSCALL_DEFINE4(fallocate)` resolves the fd (-EBADF) before
// `fs/open.c::vfs_fallocate`, which then applies
//   offset < 0 || len <= 0            -> -EINVAL
//   unsupported mode bits             -> -EOPNOTSUPP
//   !FMODE_WRITE                      -> -EBADF
//   S_ISFIFO / S_ISDIR / other        -> -ESPIPE / -EISDIR / -ENODEV

fn smoke_abi_ioerrno_fallocate_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Fallocate.raw(), a3(4242, 0, 0, 4096)),
            EBADF,
            "fallocate on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fallocate_bad_fd);

fn smoke_abi_ioerrno_fallocate_zero_len() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // len <= 0 is -EINVAL, not -EOPNOTSUPP: posix_fallocate treats
        // EOPNOTSUPP as "emulate by writing zeroes", so the wrong errno sends
        // it down a slow path for what is a caller bug.
        expect(
            call(Syscall::Fallocate.raw(), a3(fd as u64, 0, 0, 0)),
            EINVAL,
            "fallocate with len == 0 must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fallocate_zero_len);

fn smoke_abi_ioerrno_fallocate_negative_offset() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Fallocate.raw(), a3(fd as u64, 0, u64::MAX, 4096)),
            EINVAL,
            "fallocate with a negative offset must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fallocate_negative_offset);

fn smoke_abi_ioerrno_fallocate_bad_mode() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Fallocate.raw(), a3(fd as u64, 0x4000, 0, 4096)),
            EOPNOTSUPP,
            "fallocate with an unknown mode bit must be -EOPNOTSUPP",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fallocate_bad_mode);

fn smoke_abi_ioerrno_fallocate_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        expect(
            call(Syscall::Fallocate.raw(), a3(wr as u64, 0, 0, 4096)),
            ESPIPE,
            "fallocate on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fallocate_pipe_espipe);

// ── flock ──────────────────────────────────────────────────────────
//
// `fs/locks.c::SYSCALL_DEFINE2(flock)`: LOCK_MAND -> 0,
// flock_translate_cmd(cmd & ~LOCK_NB) < 0 -> -EINVAL (BEFORE the fd lookup),
// closed fd -> -EBADF, and a LOCK_NB conflict -> -EWOULDBLOCK (== EAGAIN).

const LOCK_SH: u64 = 1;
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;

fn smoke_abi_ioerrno_flock_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Flock.raw(), a1(4242, LOCK_EX)),
            EBADF,
            "flock on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_flock_bad_fd);

fn smoke_abi_ioerrno_flock_bad_operation() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // LOCK_SH | LOCK_EX is not one of the three translatable commands.
        expect(
            call(Syscall::Flock.raw(), a1(fd as u64, LOCK_SH | LOCK_EX)),
            EINVAL,
            "flock with a malformed operation must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_flock_bad_operation);

fn smoke_abi_ioerrno_flock_bad_operation_outranks_bad_fd() -> TestResult {
    with_setup(|| {
        // flock_translate_cmd runs before fdget, so EINVAL wins over EBADF.
        expect(
            call(Syscall::Flock.raw(), a1(4242, 0)),
            EINVAL,
            "flock's operation check must precede its fd lookup",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_flock_bad_operation_outranks_bad_fd
);

fn smoke_abi_ioerrno_flock_conflict_is_eagain() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        const OTHER_TASK: u64 = 4242;
        let fd = open_rw(b"/abi/f\0")?;
        if call(Syscall::Flock.raw(), a1(fd as u64, LOCK_EX)) != Some(0) {
            return Err("the first LOCK_EX did not succeed");
        }
        // flock conflicts are per open-file, across tasks. Hand a second task
        // its own descriptor onto the SAME file object, the way a fork or an
        // independent open would.
        let ops = crate::fd::with_table(FAKE_TASK, |t| t.get(fd).map(|e| e.ops.clone()))
            .flatten()
            .ok_or("could not clone the locked file's ops")?;
        set_task(OTHER_TASK);
        let other_fd = crate::fd::with_table(OTHER_TASK, |t| {
            t.open(crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            })
        })
        .ok_or("could not install the second task's descriptor")?;
        // This is the single-instance idiom: `flock(lockfd, LOCK_EX|LOCK_NB)`
        // and treat EWOULDBLOCK as "another copy already holds it". The old
        // `-1` sentinel reported EPERM, which callers escalate as fatal.
        let outcome = call(Syscall::Flock.raw(), a1(other_fd as u64, LOCK_EX | LOCK_NB));
        set_task(FAKE_TASK);
        let _ = call(Syscall::Flock.raw(), a1(fd as u64, LOCK_UN));
        expect(
            outcome,
            EAGAIN,
            "a contended flock(LOCK_NB) must be -EWOULDBLOCK",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_flock_conflict_is_eagain);

// ── tee ────────────────────────────────────────────────────────────
//
// `SYSCALL_DEFINE4(tee)`: bad flags -> -EINVAL, len == 0 -> 0, either fd
// closed -> -EBADF. `do_tee`: !FMODE_READ/!FMODE_WRITE -> -EBADF, then a
// non-pipe or self-pipe -> -EINVAL. `ipipe_prep` returns 0 only once the
// source pipe has no writers left; otherwise it waits or -EAGAINs.

fn smoke_abi_ioerrno_tee_bad_fd() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        expect(
            call(Syscall::Tee.raw(), a3(rd as u64, 4242, 16, 0)),
            EBADF,
            "tee onto a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_tee_bad_fd);

fn smoke_abi_ioerrno_tee_non_pipe() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let (rd, _wr) = make_pipe()?;
        let file = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Tee.raw(), a3(rd as u64, file as u64, 16, 0)),
            EINVAL,
            "tee onto a regular file must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_tee_non_pipe);

fn smoke_abi_ioerrno_tee_bad_flags() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        expect(
            call(Syscall::Tee.raw(), a3(rd as u64, 4242, 16, 0x1000)),
            EINVAL,
            "tee with an unknown flag must be -EINVAL (before the fd lookup)",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_tee_bad_flags);

fn smoke_abi_ioerrno_tee_empty_pipe_is_not_eof() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        let (_rd2, wr2) = make_pipe()?;
        // The source is empty but its write end is still open, so this is NOT
        // end-of-stream. Returning 0 here told every caller the stream was
        // finished; Linux waits, or reports -EAGAIN under SPLICE_F_NONBLOCK.
        expect(
            call(Syscall::Tee.raw(), a3(rd as u64, wr2 as u64, 16, 0x2)),
            EAGAIN,
            "tee on a live-but-empty pipe must be -EAGAIN, never 0",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_tee_empty_pipe_is_not_eof);

// ── epoll_ctl ──────────────────────────────────────────────────────
//
// `fs/eventpoll.c`: SYSCALL_DEFINE4 imports the event first (-EFAULT), then
// do_epoll_ctl checks epfd (-EBADF), the target fd (-EBADF), self/not-epoll
// (-EINVAL), a nesting cycle (-ELOOP), and finally the per-op arms:
// ADD on a registered fd -> -EEXIST, MOD/DEL on an unknown fd -> -ENOENT,
// any other op -> -EINVAL.

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

/// `struct epoll_event { u32 events; u64 data; }` — packed, 12 bytes on x86_64.
fn epoll_event(events: u32, data: u64) -> [u8; 12] {
    let mut ev = [0u8; 12];
    ev[..4].copy_from_slice(&events.to_le_bytes());
    ev[4..].copy_from_slice(&data.to_le_bytes());
    ev
}

fn make_epoll() -> Result<u32, &'static str> {
    match call(Syscall::EpollCreate.raw(), a0(0)) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("epoll_create failed"),
    }
}

fn smoke_abi_ioerrno_epoll_ctl_bad_epfd() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        let ev = epoll_event(1, 0);
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(4242, EPOLL_CTL_ADD, rd as u64, ev.as_ptr() as u64),
            ),
            EBADF,
            "epoll_ctl on a closed epfd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_bad_epfd);

fn smoke_abi_ioerrno_epoll_ctl_bad_target_fd() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let ev = epoll_event(1, 0);
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(ep as u64, EPOLL_CTL_ADD, 4242, ev.as_ptr() as u64),
            ),
            EBADF,
            "epoll_ctl on a closed target fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_bad_target_fd);

fn smoke_abi_ioerrno_epoll_ctl_epfd_not_epoll() -> TestResult {
    with_setup(|| {
        let (rd, wr) = make_pipe()?;
        let ev = epoll_event(1, 0);
        // Both descriptors resolve, so this is -EINVAL, not -EBADF.
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(rd as u64, EPOLL_CTL_ADD, wr as u64, ev.as_ptr() as u64),
            ),
            EINVAL,
            "epoll_ctl with a non-epoll epfd must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_epfd_not_epoll);

fn smoke_abi_ioerrno_epoll_ctl_self() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let ev = epoll_event(1, 0);
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(ep as u64, EPOLL_CTL_ADD, ep as u64, ev.as_ptr() as u64),
            ),
            EINVAL,
            "epoll_ctl adding an epoll to itself must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_self);

fn smoke_abi_ioerrno_epoll_ctl_duplicate_add() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let (rd, _wr) = make_pipe()?;
        let ev = epoll_event(1, 0);
        if call(
            Syscall::EpollCtl.raw(),
            a3(ep as u64, EPOLL_CTL_ADD, rd as u64, ev.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("the first EPOLL_CTL_ADD did not succeed");
        }
        // Event loops (libevent, libuv) keep a shadow interest set and treat
        // EEXIST as "already registered, nothing to do".
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(ep as u64, EPOLL_CTL_ADD, rd as u64, ev.as_ptr() as u64),
            ),
            EEXIST,
            "a duplicate EPOLL_CTL_ADD must be -EEXIST",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_duplicate_add);

fn smoke_abi_ioerrno_epoll_ctl_del_unregistered() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let (rd, _wr) = make_pipe()?;
        // The old handler returned 0 here, so a double-remove looked like it
        // had removed something both times.
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(ep as u64, EPOLL_CTL_DEL, rd as u64, 0),
            ),
            ENOENT,
            "EPOLL_CTL_DEL of an unregistered fd must be -ENOENT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_del_unregistered);

fn smoke_abi_ioerrno_epoll_ctl_mod_unregistered() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let (rd, _wr) = make_pipe()?;
        let ev = epoll_event(1, 0);
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(ep as u64, EPOLL_CTL_MOD, rd as u64, ev.as_ptr() as u64),
            ),
            ENOENT,
            "EPOLL_CTL_MOD of an unregistered fd must be -ENOENT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_mod_unregistered);

fn smoke_abi_ioerrno_epoll_ctl_unknown_op() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let (rd, _wr) = make_pipe()?;
        expect(
            call(Syscall::EpollCtl.raw(), a3(ep as u64, 99, rd as u64, 0)),
            EINVAL,
            "epoll_ctl with an unknown op must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_unknown_op);

fn smoke_abi_ioerrno_epoll_ctl_efault() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        let (rd, _wr) = make_pipe()?;
        // The event import happens in the syscall wrapper, before either fd
        // is resolved, so EFAULT outranks even a closed epfd.
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(ep as u64, EPOLL_CTL_ADD, rd as u64, BAD_PTR),
            ),
            EFAULT,
            "epoll_ctl with a faulting event pointer must be -EFAULT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_ctl_efault);

fn smoke_abi_ioerrno_epoll_ctl_nested_cycle_is_eloop() -> TestResult {
    with_setup(|| {
        let outer = make_epoll()?;
        let inner = make_epoll()?;
        let ev = epoll_event(1, 0);
        if call(
            Syscall::EpollCtl.raw(),
            a3(
                outer as u64,
                EPOLL_CTL_ADD,
                inner as u64,
                ev.as_ptr() as u64,
            ),
        ) != Some(0)
        {
            return Err("nesting inner inside outer did not succeed");
        }
        // Closing the loop is -ELOOP (ep_loop_check), not the blanket EPERM
        // the sentinel produced.
        expect(
            call(
                Syscall::EpollCtl.raw(),
                a3(
                    inner as u64,
                    EPOLL_CTL_ADD,
                    outer as u64,
                    ev.as_ptr() as u64,
                ),
            ),
            ELOOP,
            "an epoll nesting cycle must be -ELOOP",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_epoll_ctl_nested_cycle_is_eloop
);

// ── poll / ppoll ───────────────────────────────────────────────────
//
// `fs/select.c::do_sys_poll`: nfds above RLIMIT_NOFILE -> -EINVAL, a
// faulting pollfd array -> -EFAULT. `poll_select_set_timeout` rejects a
// non-normalized timespec with -EINVAL.

fn smoke_abi_ioerrno_poll_nfds_too_large() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Poll.raw(), a2(BAD_PTR, 4_000_000, 0)),
            EINVAL,
            "poll with an over-large nfds must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_poll_nfds_too_large);

fn smoke_abi_ioerrno_poll_efault() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Poll.raw(), a2(BAD_PTR, 1, 0)),
            EFAULT,
            "poll over an unmapped pollfd array must be -EFAULT",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_poll_efault);

fn smoke_abi_ioerrno_ppoll_bad_timespec() -> TestResult {
    with_setup(|| {
        let mut ts = [0u8; 16];
        ts[..8].copy_from_slice(&0u64.to_ne_bytes());
        ts[8..].copy_from_slice(&1_000_000_000u64.to_ne_bytes()); // tv_nsec == 1e9
        expect(
            call(Syscall::Ppoll.raw(), a3(BAD_PTR, 1, ts.as_ptr() as u64, 0)),
            EINVAL,
            "ppoll with a non-normalized timespec must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_ppoll_bad_timespec);

// ── fsync / lseek ──────────────────────────────────────────────────

fn smoke_abi_ioerrno_fsync_pipe_einval() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        // `fs/sync.c::vfs_fsync_range` opens with
        // `if (!file->f_op->fsync) return -EINVAL;`. A pipe has no fsync
        // operation, so this is a caller error, not the -EIO that tells a
        // log writer its data was lost.
        expect(
            call(Syscall::Fsync.raw(), a0(wr as u64)),
            EINVAL,
            "fsync on a pipe must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fsync_pipe_einval);

fn smoke_abi_ioerrno_fsync_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Fsync.raw(), a0(4242)),
            EBADF,
            "fsync on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fsync_bad_fd);

const SEEK_DATA: u64 = 3;
const SEEK_HOLE: u64 = 4;
const ENXIO: i64 = -6;

fn smoke_abi_ioerrno_lseek_seek_data_past_eof() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `must_set_pos`: SEEK_DATA at or past EOF is -ENXIO. -EINVAL is how
        // a caller detects "no SEEK_DATA support here" and falls back to a
        // whole-file copy, so it must not be reused for a real end-of-data.
        expect(
            call(Syscall::Lseek.raw(), a2(fd as u64, 6, SEEK_DATA)),
            ENXIO,
            "lseek SEEK_DATA at EOF must be -ENXIO",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_lseek_seek_data_past_eof);

fn smoke_abi_ioerrno_lseek_seek_hole_returns_eof() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // The generic model has one virtual hole, at EOF.
        expect(
            call(Syscall::Lseek.raw(), a2(fd as u64, 0, SEEK_HOLE)),
            6,
            "lseek SEEK_HOLE inside a file must report EOF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_lseek_seek_hole_returns_eof);

fn smoke_abi_ioerrno_lseek_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        expect(
            call(Syscall::Lseek.raw(), a2(rd as u64, 0, 1)),
            ESPIPE,
            "lseek on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_lseek_pipe_espipe);

fn smoke_abi_ioerrno_lseek_bad_whence() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Lseek.raw(), a2(fd as u64, 0, 99)),
            EINVAL,
            "lseek with an unknown whence must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_lseek_bad_whence);
