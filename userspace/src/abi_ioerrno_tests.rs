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
        let other_fd = crate::fd::install(
            OTHER_TASK,
            crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags: crate::fd::O_RDWR,
            },
        )
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

// ── eventfd / eventfd2 ─────────────────────────────────────────────
//
// `fs/eventfd.c::do_eventfd`: `if (flags & ~EFD_FLAGS_SET) return -EINVAL;`
// where the set is EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK. The one-arg
// `SYSCALL_DEFINE1(eventfd)` calls `do_eventfd(count, 0)` — it has no flag
// word at all.

const EFD_SEMAPHORE: u64 = 1;

fn smoke_abi_ioerrno_eventfd2_bad_flags() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Eventfd.raw(), a1(0, 0x4000_0000)),
            EINVAL,
            "eventfd2 with an unknown flag must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_eventfd2_bad_flags);

fn smoke_abi_ioerrno_eventfd2_known_flags_accepted() -> TestResult {
    with_setup(|| {
        let flags = EFD_SEMAPHORE | crate::fd::O_CLOEXEC as u64 | crate::fd::O_NONBLOCK as u64;
        match call(Syscall::Eventfd.raw(), a1(0, flags)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("eventfd2 rejected the full EFD_* set"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_eventfd2_known_flags_accepted
);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_ioerrno_eventfd_legacy_ignores_arg1() -> TestResult {
    with_setup(|| {
        // x86_64 284 takes ONE argument. arg1 is whatever the caller left in
        // rsi, so a handler that reads it as flags would fail here with
        // EINVAL — or worse, silently hand back a CLOEXEC descriptor built
        // from register garbage.
        match call(Syscall::EventfdLegacy.raw(), a1(0, 0xdead_beef)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("legacy eventfd must ignore arg1, not read it as flags"),
        }
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_eventfd_legacy_ignores_arg1);

// ── epoll_create / epoll_create1 ───────────────────────────────────

fn smoke_abi_ioerrno_epoll_create1_bad_flags() -> TestResult {
    with_setup(|| {
        // `do_epoll_create`: `if (flags & ~EPOLL_CLOEXEC) return -EINVAL;`
        expect(
            call(Syscall::EpollCreate.raw(), a0(0x4000_0000)),
            EINVAL,
            "epoll_create1 with an unknown flag must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_create1_bad_flags);

fn smoke_abi_ioerrno_epoll_create1_cloexec_is_set() -> TestResult {
    with_setup(|| {
        let fd = match call(Syscall::EpollCreate.raw(), a0(crate::fd::O_CLOEXEC as u64)) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("epoll_create1(EPOLL_CLOEXEC) failed"),
        };
        // F_GETFD == 1. Without FD_CLOEXEC the epoll fd leaks through every
        // exec in the process tree.
        match call(Syscall::Fcntl.raw(), a2(fd as u64, 1, 0)) {
            Some(flags) if flags & crate::fd::FD_CLOEXEC as i64 != 0 => Ok(()),
            _ => Err("epoll_create1(EPOLL_CLOEXEC) did not set FD_CLOEXEC"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_epoll_create1_cloexec_is_set
);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_ioerrno_epoll_create_zero_size() -> TestResult {
    with_setup(|| {
        // x86_64 213 reads arg0 as a SIZE, and
        // `SYSCALL_DEFINE1(epoll_create)` still rejects `size <= 0`.
        expect(
            call(Syscall::EpollCreateLegacy.raw(), a0(0)),
            EINVAL,
            "epoll_create(0) must be -EINVAL",
        )
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_create_zero_size);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_ioerrno_epoll_create_positive_size() -> TestResult {
    with_setup(|| match call(Syscall::EpollCreateLegacy.raw(), a0(1)) {
        Some(fd) if fd >= 0 => Ok(()),
        _ => Err("epoll_create(1) should succeed"),
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_create_positive_size);

// ── preadv2 / pwritev2 RWF_* flags ─────────────────────────────────
//
// `include/linux/fs.h::kiocb_set_rw_flags`.

fn preadv2_with_flags(fd: u32, iov: &[u8; 16], flags: u64) -> Option<i64> {
    let r = call_raw(
        Syscall::Preadv2.raw(),
        SyscallArgs {
            arg0: fd as u64,
            arg1: iov.as_ptr() as u64,
            arg2: 1,
            arg3: 0,
            arg4: 0,
            arg5: flags,
        },
    );
    (r.status == SyscallReturn::OK).then_some(r.value as i64)
}

fn smoke_abi_ioerrno_preadv2_unknown_flag() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        // `if (flags & ~RWF_SUPPORTED) return -EOPNOTSUPP;`
        expect(
            preadv2_with_flags(fd, &iov, 0x1000),
            EOPNOTSUPP,
            "preadv2 with an unknown RWF_ bit must be -EOPNOTSUPP",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv2_unknown_flag);

fn smoke_abi_ioerrno_preadv2_nowait_unsupported() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        // RWF_NOWAIT without FMODE_NOWAIT is -EOPNOTSUPP. Silently ignoring
        // it blocks an event loop that asked specifically not to be blocked.
        expect(
            preadv2_with_flags(fd, &iov, 0x8),
            EOPNOTSUPP,
            "preadv2 RWF_NOWAIT must be -EOPNOTSUPP, not silently ignored",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv2_nowait_unsupported);

fn smoke_abi_ioerrno_pwritev2_append_and_noappend() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let payload = *b"XY";
        let iov = iovec(payload.as_ptr() as u64, 2);
        // `if ((flags & RWF_APPEND) && (flags & RWF_NOAPPEND)) return -EINVAL;`
        let r = call_raw(
            Syscall::Pwritev2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: 0,
                arg5: 0x10 | 0x20,
            },
        );
        expect(
            (r.status == SyscallReturn::OK).then_some(r.value as i64),
            EINVAL,
            "pwritev2 with RWF_APPEND|RWF_NOAPPEND must be -EINVAL",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_pwritev2_append_and_noappend
);

fn smoke_abi_ioerrno_preadv2_sync_flags_accepted() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        // RWF_HIPRI | RWF_DSYNC | RWF_SYNC are honourable on a coherent
        // in-memory filesystem and must not be rejected.
        match preadv2_with_flags(fd, &iov, 0x1 | 0x2 | 0x4) {
            Some(4) if &dst[..4] == b"abcd" => Ok(()),
            _ => Err("preadv2 rejected RWF_HIPRI|RWF_DSYNC|RWF_SYNC"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_preadv2_sync_flags_accepted);

fn smoke_abi_ioerrno_pwritev2_append_is_rejected() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let payload = *b"ZZ";
        let iov = iovec(payload.as_ptr() as u64, 2);
        // `generic_write_checks_count` does
        // `if (iocb->ki_flags & IOCB_APPEND) iocb->ki_pos = i_size_read(inode);`
        // — RWF_APPEND OVERRIDES the explicit offset and writes at EOF.
        // Accepting the flag and honouring `pos` would put these two bytes at
        // offset 0 instead of offset 6, which no error would ever reveal.
        let r = call_raw(
            Syscall::Pwritev2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: 0,
                arg5: 0x10, // RWF_APPEND
            },
        );
        expect(
            (r.status == SyscallReturn::OK).then_some(r.value as i64),
            EOPNOTSUPP,
            "pwritev2 RWF_APPEND must be -EOPNOTSUPP, never silently ignored",
        )?;
        // And nothing may have been written at the offset it was told to use.
        let mut buf = [0u8; 6];
        match call(
            Syscall::Pread64.raw(),
            a3(fd as u64, buf.as_mut_ptr() as u64, 6, 0),
        ) {
            Some(6) if &buf == b"abcdef" => Ok(()),
            _ => Err("a rejected RWF_APPEND write must not have moved any bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pwritev2_append_is_rejected);

fn smoke_abi_ioerrno_pwritev2_nosignal_is_rejected() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let payload = *b"Z";
        let iov = iovec(payload.as_ptr() as u64, 1);
        // RWF_NOSIGNAL sets IOCB_NOSIGNAL, which is what suppresses the
        // `send_sig(SIGPIPE, current, 0)` in pipe_write. Ignoring it delivers
        // a signal whose default action kills the caller.
        let r = call_raw(
            Syscall::Pwritev2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: 0,
                arg5: 0x100, // RWF_NOSIGNAL
            },
        );
        expect(
            (r.status == SyscallReturn::OK).then_some(r.value as i64),
            EOPNOTSUPP,
            "pwritev2 RWF_NOSIGNAL must be -EOPNOTSUPP, never silently ignored",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_pwritev2_nosignal_is_rejected
);

fn smoke_abi_ioerrno_pwritev2_noappend_is_rejected() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let payload = *b"Z";
        let iov = iovec(payload.as_ptr() as u64, 1);
        // RWF_NOAPPEND negates the description's O_APPEND for one I/O. The
        // `pos == -1` form delegates to writev, which honours O_APPEND and
        // cannot be told not to, so the flag cannot be expressed here.
        let r = call_raw(
            Syscall::Pwritev2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: 0,
                arg5: 0x20, // RWF_NOAPPEND
            },
        );
        expect(
            (r.status == SyscallReturn::OK).then_some(r.value as i64),
            EOPNOTSUPP,
            "pwritev2 RWF_NOAPPEND must be -EOPNOTSUPP, never silently ignored",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_pwritev2_noappend_is_rejected
);

// ── fadvise64 / readahead / sync_file_range ────────────────────────

fn smoke_abi_ioerrno_fadvise_bad_advice() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `generic_fadvise`'s switch ends in `default: return -EINVAL;`.
        // 6 is the s390 DONTNEED value — a real portability bug on x86_64.
        expect(
            call(Syscall::Fadvise64.raw(), a3(fd as u64, 0, 0, 6)),
            EINVAL,
            "fadvise64 with an out-of-range advice must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fadvise_bad_advice);

fn smoke_abi_ioerrno_fadvise_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        expect(
            call(Syscall::Fadvise64.raw(), a3(rd as u64, 0, 0, 0)),
            ESPIPE,
            "fadvise64 on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fadvise_pipe_espipe);

fn smoke_abi_ioerrno_fadvise_valid_advice_ok() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // POSIX_FADV_WILLNEED — a hint NARF ignores, but must accept.
        expect(
            call(Syscall::Fadvise64.raw(), a3(fd as u64, 0, 0, 3)),
            0,
            "fadvise64 with a valid advice must succeed",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fadvise_valid_advice_ok);

fn smoke_abi_ioerrno_readahead_pipe_einval() -> TestResult {
    with_setup(|| {
        let (rd, _wr) = make_pipe()?;
        // `ksys_readahead`: only S_ISREG and S_ISBLK are eligible.
        expect(
            call(Syscall::Readahead.raw(), a2(rd as u64, 0, 4096)),
            EINVAL,
            "readahead on a pipe must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_readahead_pipe_einval);

fn smoke_abi_ioerrno_readahead_wronly_fd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd_flags(b"/abi/f\0", crate::fd::O_WRONLY as u64)?;
        // `if (!(file->f_mode & FMODE_READ)) return -EBADF;`
        expect(
            call(Syscall::Readahead.raw(), a2(fd as u64, 0, 4096)),
            EBADF,
            "readahead on a write-only fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_readahead_wronly_fd);

fn smoke_abi_ioerrno_sync_file_range_bad_flags() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `if (flags & ~VALID_FLAGS) goto out;` with ret = -EINVAL.
        expect(
            call(Syscall::SyncFileRange.raw(), a3(fd as u64, 0, 0, 8)),
            EINVAL,
            "sync_file_range with an unknown flag must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_sync_file_range_bad_flags);

fn smoke_abi_ioerrno_sync_file_range_negative_offset() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::SyncFileRange.raw(), a3(fd as u64, u64::MAX, 0, 0)),
            EINVAL,
            "sync_file_range with a negative offset must be -EINVAL",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_sync_file_range_negative_offset
);

fn smoke_abi_ioerrno_sync_file_range_pipe_espipe() -> TestResult {
    with_setup(|| {
        let (_rd, wr) = make_pipe()?;
        expect(
            call(Syscall::SyncFileRange.raw(), a3(wr as u64, 0, 0, 0)),
            ESPIPE,
            "sync_file_range on a pipe must be -ESPIPE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_sync_file_range_pipe_espipe);

// ── fcntl: F_DUPFD floor and memfd seals ───────────────────────────

fn smoke_abi_ioerrno_fcntl_dupfd_floor_too_high() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `f_dupfd`: `if (from >= nofile) return -EINVAL;`. The harness's
        // RLIMIT_NOFILE soft limit is 1024.
        expect(
            call(Syscall::Fcntl.raw(), a2(fd as u64, 0 /* F_DUPFD */, 4096)),
            EINVAL,
            "F_DUPFD above RLIMIT_NOFILE must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fcntl_dupfd_floor_too_high);

fn smoke_abi_ioerrno_fcntl_get_seals_non_memfd() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `memfd_get_seals` returns -EINVAL when the file has no seal word.
        // EPERM (the old answer) sends the caller hunting for a privilege.
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd as u64, 1034 /* F_GET_SEALS */, 0),
            ),
            EINVAL,
            "F_GET_SEALS on a non-memfd must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fcntl_get_seals_non_memfd);

fn smoke_abi_ioerrno_fcntl_seals_bad_fd() -> TestResult {
    with_setup(|| {
        // The fdget in the fcntl entry precedes memfd_fcntl entirely.
        expect(
            call(Syscall::Fcntl.raw(), a2(4242, 1034 /* F_GET_SEALS */, 0)),
            EBADF,
            "F_GET_SEALS on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fcntl_seals_bad_fd);

// ── the positive paths these validations must not break ────────────
//
// Every check added above rejects something. These pin the other side: the
// arguments that must keep working, so a later tightening cannot quietly
// turn a supported call into an error.

fn smoke_abi_ioerrno_fadvise_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Fadvise64.raw(), a3(4242, 0, 0, 0)),
            EBADF,
            "fadvise64 on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fadvise_bad_fd);

fn smoke_abi_ioerrno_fadvise_negative_len() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `generic_fadvise`: `if (!mapping || len < 0) return -EINVAL;`
        expect(
            call(Syscall::Fadvise64.raw(), a3(fd as u64, 0, u64::MAX, 0)),
            EINVAL,
            "fadvise64 with a negative len must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fadvise_negative_len);

fn smoke_abi_ioerrno_readahead_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::Readahead.raw(), a2(4242, 0, 4096)),
            EBADF,
            "readahead on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_readahead_bad_fd);

fn smoke_abi_ioerrno_readahead_regular_file_ok() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(Syscall::Readahead.raw(), a2(fd as u64, 0, 4096)),
            0,
            "readahead on a readable regular file must succeed",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_readahead_regular_file_ok);

fn smoke_abi_ioerrno_sync_file_range_bad_fd() -> TestResult {
    with_setup(|| {
        expect(
            call(Syscall::SyncFileRange.raw(), a3(4242, 0, 0, 0)),
            EBADF,
            "sync_file_range on a closed fd must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_sync_file_range_bad_fd);

fn smoke_abi_ioerrno_sync_file_range_valid_ok() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // SYNC_FILE_RANGE_WRITE_AND_WAIT — the whole VALID_FLAGS set.
        expect(
            call(Syscall::SyncFileRange.raw(), a3(fd as u64, 0, 6, 7)),
            0,
            "sync_file_range over a valid range must succeed",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_sync_file_range_valid_ok);

fn smoke_abi_ioerrno_fcntl_dupfd_valid_floor() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // A floor inside RLIMIT_NOFILE still duplicates, at the lowest free
        // slot at or above it — the new EINVAL check must not swallow this.
        match call(Syscall::Fcntl.raw(), a2(fd as u64, 0 /* F_DUPFD */, 100)) {
            Some(new_fd) if new_fd >= 100 => Ok(()),
            _ => Err("F_DUPFD with an in-range floor must return a new fd >= it"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fcntl_dupfd_valid_floor);

// ── memfd seals: the three outcomes fcntl must tell apart ──────────
//
// `mm/memfd.c::memfd_add_seals`:
//   !(file->f_mode & FMODE_WRITE)     -> -EPERM
//   seals & ~F_ALL_SEALS              -> -EINVAL
//   *file_seals & F_SEAL_SEAL         -> -EPERM
// A caller that retries with a corrected seal set needs EINVAL and EPERM
// distinguished; both were the same `-1` sentinel before.

const F_ADD_SEALS: u64 = 1033;
const F_GET_SEALS: u64 = 1034;
const MFD_ALLOW_SEALING: u64 = 0x0002;
const F_SEAL_SEAL: i64 = 0x0001;
const F_SEAL_WRITE: u64 = 0x0008;

fn make_memfd(flags: u64) -> Result<u32, &'static str> {
    let name = b"seal-test\0";
    match call(Syscall::MemfdCreate.raw(), a1(name.as_ptr() as u64, flags)) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("memfd_create failed"),
    }
}

fn smoke_abi_ioerrno_memfd_add_seal_succeeds() -> TestResult {
    with_setup(|| {
        let fd = make_memfd(MFD_ALLOW_SEALING)?;
        if call(
            Syscall::Fcntl.raw(),
            a2(fd as u64, F_ADD_SEALS, F_SEAL_WRITE),
        ) != Some(0)
        {
            return Err("F_ADD_SEALS(F_SEAL_WRITE) on a sealable memfd should succeed");
        }
        match call(Syscall::Fcntl.raw(), a2(fd as u64, F_GET_SEALS, 0)) {
            Some(seals) if seals as u64 & F_SEAL_WRITE != 0 => Ok(()),
            _ => Err("F_GET_SEALS did not report the seal just added"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_memfd_add_seal_succeeds);

fn smoke_abi_ioerrno_memfd_add_seal_unknown_bit() -> TestResult {
    with_setup(|| {
        let fd = make_memfd(MFD_ALLOW_SEALING)?;
        // `if (seals & ~(unsigned int)F_ALL_SEALS) return -EINVAL;` — a bad
        // seal set is a caller error, not a refusal, and the caller can fix
        // it and retry. EPERM (the old answer) told it to give up instead.
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd as u64, F_ADD_SEALS, 0x4000_0000),
            ),
            EINVAL,
            "F_ADD_SEALS with an undefined seal bit must be -EINVAL",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_memfd_add_seal_unknown_bit);

fn smoke_abi_ioerrno_memfd_add_seal_already_sealed() -> TestResult {
    with_setup(|| {
        let fd = make_memfd(MFD_ALLOW_SEALING)?;
        if call(
            Syscall::Fcntl.raw(),
            a2(fd as u64, F_ADD_SEALS, F_SEAL_SEAL as u64),
        ) != Some(0)
        {
            return Err("F_ADD_SEALS(F_SEAL_SEAL) should succeed once");
        }
        // `if (*file_seals & F_SEAL_SEAL) { error = -EPERM; }` — a genuine
        // refusal, and the one case that stays EPERM.
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd as u64, F_ADD_SEALS, F_SEAL_WRITE),
            ),
            EPERM,
            "F_ADD_SEALS on an F_SEAL_SEAL'd memfd must be -EPERM",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_memfd_add_seal_already_sealed
);

fn smoke_abi_ioerrno_memfd_without_allow_sealing() -> TestResult {
    with_setup(|| {
        // Without MFD_ALLOW_SEALING the file starts F_SEAL_SEAL'd, so it is
        // still a memfd — F_GET_SEALS reports, F_ADD_SEALS refuses.
        let fd = make_memfd(0)?;
        match call(Syscall::Fcntl.raw(), a2(fd as u64, F_GET_SEALS, 0)) {
            Some(seals) if seals == F_SEAL_SEAL => {}
            _ => return Err("a non-sealable memfd must report F_SEAL_SEAL"),
        }
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd as u64, F_ADD_SEALS, F_SEAL_WRITE),
            ),
            EPERM,
            "F_ADD_SEALS without MFD_ALLOW_SEALING must be -EPERM",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_memfd_without_allow_sealing);

// ── precedence and argument width ──────────────────────────────────
//
// Getting an errno right is only half of it: the kernel also fixes WHERE in
// the sequence each check runs, and how wide each argument is. These pin the
// cases where a validation added above could otherwise pre-empt an earlier
// check, or reject a value the kernel would have truncated into range.

fn smoke_abi_ioerrno_preadv2_bad_fd_outranks_bad_flag() -> TestResult {
    with_setup(|| {
        let mut dst = [0u8; 4];
        let iov = iovec(dst.as_mut_ptr() as u64, 4);
        // `do_preadv` resolves the descriptor, and `vfs_readv` checks FMODE,
        // imports the iovec and short-circuits an empty vector — all before
        // the flag word reaches `kiocb_set_rw_flags`. So a closed fd is
        // -EBADF even when the flags are also garbage.
        expect(
            preadv2_with_flags(4242, &iov, 0x1000),
            EBADF,
            "preadv2 must report -EBADF before it looks at the flag word",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_preadv2_bad_fd_outranks_bad_flag
);

fn smoke_abi_ioerrno_preadv2_empty_vector_ignores_flags() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `if (!tot_len) goto out;` returns 0 without ever validating flags.
        let r = call_raw(
            Syscall::Preadv2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: 0,
                arg2: 0, // iovcnt == 0 → nothing to transfer
                arg3: 0,
                arg4: 0,
                arg5: 0x1000, // an unsupported RWF_ bit, never reached
            },
        );
        expect(
            (r.status == SyscallReturn::OK).then_some(r.value as i64),
            0,
            "preadv2 over an empty vector must return 0 without checking flags",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_preadv2_empty_vector_ignores_flags
);

fn smoke_abi_ioerrno_eventfd2_count_is_32_bit() -> TestResult {
    with_setup(|| {
        // `SYSCALL_DEFINE2(eventfd2, unsigned int, count, ...)` — the initial
        // counter is 32 bits. Seeding from the full register would start this
        // eventfd at (1 << 32) + 5 instead of 5, so the first read returns a
        // value that never existed.
        let fd = match call(Syscall::Eventfd.raw(), a1((1u64 << 32) | 5, 0)) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("eventfd2 failed"),
        };
        let mut buf = [0u8; 8];
        if call(
            Syscall::Read.raw(),
            a2(fd as u64, buf.as_mut_ptr() as u64, 8),
        ) != Some(8)
        {
            return Err("eventfd read did not return 8 bytes");
        }
        match u64::from_ne_bytes(buf) {
            5 => Ok(()),
            _ => Err("eventfd2 must truncate its initial count to 32 bits"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_eventfd2_count_is_32_bit);

fn smoke_abi_ioerrno_fcntl_dupfd_bad_fd_outranks_floor() -> TestResult {
    with_setup(|| {
        // `do_fcntl` is handed an already-resolved file, so the entry's
        // fdget_raw reports -EBADF before F_DUPFD ever inspects its floor.
        expect(
            call(Syscall::Fcntl.raw(), a2(4242, 0 /* F_DUPFD */, 4096)),
            EBADF,
            "F_DUPFD on a closed fd must be -EBADF, not -EINVAL for the floor",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_fcntl_dupfd_bad_fd_outranks_floor
);

fn smoke_abi_ioerrno_fcntl_dupfd_floor_is_32_bit() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // `int argi = (int)arg` — the floor is the low 32 bits, so this is a
        // floor of 0 and duplicates normally. Comparing the untruncated
        // register against RLIMIT_NOFILE rejected it with -EINVAL instead.
        match call(
            Syscall::Fcntl.raw(),
            a2(fd as u64, 0 /* F_DUPFD */, 1u64 << 32),
        ) {
            Some(new_fd) if new_fd >= 0 => Ok(()),
            _ => Err("F_DUPFD must truncate its floor to 32 bits"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fcntl_dupfd_floor_is_32_bit);

fn smoke_abi_ioerrno_memfd_bad_seal_bit_outranks_sealed() -> TestResult {
    with_setup(|| {
        // Created without MFD_ALLOW_SEALING, so it already carries
        // F_SEAL_SEAL. `memfd_add_seals` still validates the REQUESTED set
        // first, so an undefined bit is -EINVAL here, not the -EPERM the
        // already-sealed state would otherwise produce.
        let fd = make_memfd(0)?;
        expect(
            call(
                Syscall::Fcntl.raw(),
                a2(fd as u64, F_ADD_SEALS, 0x4000_0000),
            ),
            EINVAL,
            "an undefined seal bit must be -EINVAL even on a sealed memfd",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_memfd_bad_seal_bit_outranks_sealed
);

// ── large transfers must be staged, not attempted in one copy ──────
//
// `validate_rw_user_range` deliberately skips NARF's generic 16-MiB
// single-copy cap so a large request is not rejected outright. That only
// works if the handler then honours the cap by chunking, the way sys_read and
// sys_write do. A single allocation the size of the request both asks the
// kernel heap for far too much and fails the copy on the 16-MiB limit — where
// Linux caps at MAX_RW_COUNT and transfers.

/// 16 MiB + 1: one byte past NARF's single-copy limit, so any handler that
/// does the whole transfer in one buffer fails here.
const OVER_COPY_LIMIT: usize = 16 * 1024 * 1024 + 1;

fn smoke_abi_ioerrno_pread64_over_copy_limit_is_chunked() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        let mut dst = alloc::vec![0u8; 64];
        // A count past the copy limit against a 6-byte file: the transfer is
        // short, but the handler must get there by staging rather than by
        // allocating `count` bytes up front.
        match call(
            Syscall::Pread64.raw(),
            a3(
                fd as u64,
                dst.as_mut_ptr() as u64,
                OVER_COPY_LIMIT as u64,
                0,
            ),
        ) {
            Some(6) if &dst[..6] == b"abcdef" => Ok(()),
            _ => Err("a pread past the 16-MiB copy limit must still transfer"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_pread64_over_copy_limit_is_chunked
);

fn smoke_abi_ioerrno_pwrite64_over_copy_limit_is_chunked() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // The source really is one big buffer; the handler must copy it in
        // bounded pieces. 17 MiB crosses the limit with room to spare.
        let src = alloc::vec![b'q'; OVER_COPY_LIMIT];
        match call(
            Syscall::Pwrite64.raw(),
            a3(fd as u64, src.as_ptr() as u64, src.len() as u64, 0),
        ) {
            Some(n) if n == OVER_COPY_LIMIT as i64 => {}
            _ => return Err("a pwrite past the 16-MiB copy limit must still transfer"),
        }
        // Spot-check the far end so a short write that reported the full
        // count cannot pass.
        let mut tail = [0u8; 4];
        match call(
            Syscall::Pread64.raw(),
            a3(
                fd as u64,
                tail.as_mut_ptr() as u64,
                4,
                (OVER_COPY_LIMIT - 4) as u64,
            ),
        ) {
            Some(4) if &tail == b"qqqq" => Ok(()),
            _ => Err("the tail of a chunked pwrite was not written"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_pwrite64_over_copy_limit_is_chunked
);

fn smoke_abi_ioerrno_preadv_single_iovec_over_copy_limit() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_rw(b"/abi/f\0")?;
        // ONE iovec larger than the copy limit. import_rw_iovecs caps the
        // whole vector at MAX_RW_COUNT, which is far above 16 MiB, so the
        // per-iovec staging is what has to be bounded.
        let mut dst = alloc::vec![0u8; OVER_COPY_LIMIT];
        let iov = iovec(dst.as_mut_ptr() as u64, OVER_COPY_LIMIT as u64);
        match call(
            Syscall::Preadv.raw(),
            a3(fd as u64, iov.as_ptr() as u64, 1, 0),
        ) {
            Some(6) if &dst[..6] == b"abcdef" => Ok(()),
            _ => Err("a preadv iovec past the copy limit must still transfer"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_preadv_single_iovec_over_copy_limit
);

fn smoke_abi_ioerrno_epoll_fd_is_rdwr() -> TestResult {
    with_setup(|| {
        let ep = make_epoll()?;
        // `do_epoll_create` opens the anon inode `O_RDWR | (flags & O_CLOEXEC)`.
        // F_GETFL == 3.
        match call(Syscall::Fcntl.raw(), a2(ep as u64, 3, 0)) {
            Some(flags) if flags as u32 & crate::fd::O_ACCMODE == crate::fd::O_RDWR => Ok(()),
            _ => Err("an epoll fd must report O_RDWR from F_GETFL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_fd_is_rdwr);

// ── RLIMIT_NOFILE / EMFILE ─────────────────────────────────────────
//
// `fs/file.c::alloc_fd` bounds the descriptor NUMBER, not the count of open
// descriptors:
//
//   fd = find_next_fd(fdt, fd);
//   error = -EMFILE;
//   if (unlikely(fd >= end)) goto out;
//
// with `end` = `rlimit(RLIMIT_NOFILE)` for every ordinary fd-creating call.
// NARF's table used to search upward without a bound, so -EMFILE was
// unreachable from every one of them and a descriptor leak grew silently
// instead of failing where the program could still notice.

const RLIMIT_NOFILE: u64 = 7;

/// Lower this task's RLIMIT_NOFILE soft limit to `cur`.
fn set_nofile(cur: u64) -> Result<(), &'static str> {
    // struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; }
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&cur.to_ne_bytes());
    buf[8..].copy_from_slice(&4096u64.to_ne_bytes());
    match call(
        Syscall::Setrlimit.raw(),
        a1(RLIMIT_NOFILE, buf.as_ptr() as u64),
    ) {
        Some(0) => Ok(()),
        _ => Err("setrlimit(RLIMIT_NOFILE) failed"),
    }
}

fn smoke_abi_ioerrno_open_reports_emfile_at_the_limit() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        // stdio occupies 0..=2, so a limit of 4 leaves exactly one slot.
        set_nofile(4)?;
        let first = open_rw(b"/abi/f\0")?;
        if first != 3 {
            return Err("the first open should land at fd 3");
        }
        // The next lowest free number is 4, which is the limit itself.
        match call_open(c"/abi/f".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(v) if v == EMFILE => Ok(()),
            _ => Err("open past RLIMIT_NOFILE must be -EMFILE"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_open_reports_emfile_at_the_limit
);

fn smoke_abi_ioerrno_dup_reports_emfile() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        set_nofile(4)?;
        let fd = open_rw(b"/abi/f\0")?;
        // dup(2) asks for any free slot, so exhaustion is -EMFILE — the
        // signal a server sheds load on. -EBADF would say its own descriptor
        // bookkeeping was broken, which is a different kind of bug entirely.
        expect(
            call(Syscall::Dup.raw(), a0(fd as u64)),
            EMFILE,
            "dup past RLIMIT_NOFILE must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_dup_reports_emfile);

fn smoke_abi_ioerrno_dup_bad_fd_still_ebadf_at_the_limit() -> TestResult {
    with_setup(|| {
        set_nofile(3)?; // stdio fills the table exactly
                        // `fget_raw(fildes)` fails before `get_unused_fd_flags` is reached,
                        // so a closed source is -EBADF even with no slot to put it in.
        expect(
            call(Syscall::Dup.raw(), a0(4242)),
            EBADF,
            "dup of a closed fd must be -EBADF, not -EMFILE",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_dup_bad_fd_still_ebadf_at_the_limit
);

fn smoke_abi_ioerrno_dup2_out_of_range_is_ebadf() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        set_nofile(8)?;
        let fd = open_rw(b"/abi/f\0")?;
        // `ksys_dup3`: `if (newfd >= rlimit(RLIMIT_NOFILE)) return -EBADF;`.
        // dup2 names an exact descriptor, so out-of-range is a bad argument
        // rather than exhaustion — the one place the two errnos diverge.
        expect(
            call(Syscall::Dup2.raw(), a1(fd as u64, 8)),
            EBADF,
            "dup2 to a descriptor at RLIMIT_NOFILE must be -EBADF, not -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_dup2_out_of_range_is_ebadf);

fn smoke_abi_ioerrno_dup3_out_of_range_is_ebadf() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        set_nofile(8)?;
        let fd = open_rw(b"/abi/f\0")?;
        expect(
            call(
                Syscall::Dup3.raw(),
                a2(fd as u64, 9, crate::fd::O_CLOEXEC as u64),
            ),
            EBADF,
            "dup3 to a descriptor past RLIMIT_NOFILE must be -EBADF",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_dup3_out_of_range_is_ebadf);

fn smoke_abi_ioerrno_fcntl_dupfd_reports_emfile() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        set_nofile(5)?;
        let fd = open_rw(b"/abi/f\0")?; // fd 3
                                        // A floor of 4 is legal (below the limit), but the only slot at or
                                        // above it is 4 — and once that is taken the allocation itself
                                        // fails. `f_dupfd` reports the floor error as -EINVAL and this one
                                        // as -EMFILE; they are separate answers to separate questions.
        if call(Syscall::Fcntl.raw(), a2(fd as u64, 0 /* F_DUPFD */, 4)) != Some(4) {
            return Err("the first F_DUPFD at floor 4 should land at fd 4");
        }
        expect(
            call(Syscall::Fcntl.raw(), a2(fd as u64, 0 /* F_DUPFD */, 4)),
            EMFILE,
            "F_DUPFD with no free slot below the limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_fcntl_dupfd_reports_emfile);

fn smoke_abi_ioerrno_pipe_is_all_or_nothing_at_the_limit() -> TestResult {
    with_setup(|| {
        // stdio holds 0..=2; a limit of 4 leaves exactly ONE free slot, so
        // the read end fits and the write end does not.
        set_nofile(4)?;
        let mut buf = [0u8; 8];
        let r = call_raw(Syscall::Pipe.raw(), a0(buf.as_mut_ptr() as u64));
        if r.status != SyscallReturn::OK || r.value as i64 != EMFILE {
            return Err("pipe with one free slot must be -EMFILE");
        }
        // `__do_pipe_flags` does `put_unused_fd(fdr)` on the second failure.
        // If the read end were left installed, this open would find no slot
        // and the caller could never recover by freeing one descriptor.
        match call_open(c"/dev/null".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(3) => Ok(()),
            _ => Err("a failed pipe must not consume a descriptor"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_pipe_is_all_or_nothing_at_the_limit
);

fn smoke_abi_ioerrno_emfile_is_positional_not_a_count() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        set_nofile(6)?;
        // Open three (fds 3, 4, 5) then close the middle one. Two are open,
        // well under a limit of 6 — but the lowest free NUMBER is 4, so the
        // next open must succeed there. A count-based check would have let
        // this through too; the distinction shows up in the reverse case,
        // which the `open_reports_emfile_at_the_limit` case above pins.
        let a = open_rw(b"/abi/f\0")?;
        let b = open_rw(b"/abi/f\0")?;
        let c = open_rw(b"/abi/f\0")?;
        if (a, b, c) != (3, 4, 5) {
            return Err("opens did not land at the lowest free descriptors");
        }
        if call(Syscall::Close.raw(), a0(b as u64)) != Some(0) {
            return Err("close failed");
        }
        match call_open(c"/abi/f".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(4) => {}
            _ => return Err("open did not reuse the freed descriptor"),
        }
        // Now every number below the limit is taken.
        match call_open(c"/abi/f".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(v) if v == EMFILE => Ok(()),
            _ => Err("open must be -EMFILE once every number below the limit is used"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_emfile_is_positional_not_a_count
);

fn smoke_abi_ioerrno_raising_the_limit_takes_effect() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        set_nofile(4)?;
        let _fd = open_rw(b"/abi/f\0")?;
        match call_open(c"/abi/f".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(v) if v == EMFILE => {}
            _ => return Err("expected -EMFILE at the lowered limit"),
        }
        // The bound is read from the task's rlimits on every fd-creating
        // call, so a raise applies to the very next one — no table state to
        // invalidate, which is what makes `setrlimit` usable as a recovery.
        set_nofile(16)?;
        match call_open(c"/abi/f".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("raising RLIMIT_NOFILE must let the next open succeed"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_raising_the_limit_takes_effect
);

// ── every fd-creating syscall reports the SAME exhaustion errno ─────
//
// Enforcing RLIMIT_NOFILE made ~49 allocation-failure arms reachable for the
// first time. Each one had inherited whatever sentinel its handler happened
// to use, so the same condition — no free descriptor — surfaced as EPERM
// from one syscall, EBADF from another and EMFILE from a third. Linux reaches
// `get_unused_fd_flags` from all of them and answers -EMFILE.

/// Fill the descriptor table so no free number remains below `limit`.
///
/// Pipes take two slots at a time, so an odd number of free slots would leave
/// exactly one behind — and one free slot is enough for every single-fd
/// syscall under test to succeed, which is how the first version of this
/// helper quietly tested nothing. Fill the remainder with `dup`, which takes
/// exactly one, then assert saturation rather than assuming it.
fn saturate_descriptors(limit: u64) -> Result<(), &'static str> {
    set_nofile(limit)?;
    let mut next = 3u64; // stdio occupies 0..=2
    while limit - next >= 2 {
        make_pipe()?;
        next += 2;
    }
    while next < limit {
        match call(Syscall::Dup.raw(), a0(0)) {
            Some(fd) if fd >= 0 => next += 1,
            _ => return Err("could not fill the final descriptor slot"),
        }
    }
    // The whole point of the helper: prove there is nothing left to allocate.
    match call(Syscall::Dup.raw(), a0(0)) {
        Some(v) if v == EMFILE => Ok(()),
        _ => Err("the descriptor table was not actually saturated"),
    }
}

fn assert_emfile(num: u32, args: SyscallArgs, what: &'static str) -> Result<(), &'static str> {
    let r = call_raw(num, args);
    match (r.status == SyscallReturn::OK).then_some(r.value as i64) {
        Some(v) if v == EMFILE => Ok(()),
        _ => Err(what),
    }
}

fn smoke_abi_ioerrno_timerfd_create_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        // `fs/timerfd.c` publishes via anon_inode_getfd -> get_unused_fd_flags.
        assert_emfile(
            Syscall::TimerfdCreate.raw(),
            a1(1 /* CLOCK_MONOTONIC */, 0),
            "timerfd_create at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_timerfd_create_reports_emfile
);

fn smoke_abi_ioerrno_signalfd_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        let mask = [0u8; 8];
        assert_emfile(
            Syscall::Signalfd.raw(),
            a3(u64::MAX /* new fd */, mask.as_ptr() as u64, 8, 0),
            "signalfd at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_signalfd_reports_emfile);

fn smoke_abi_ioerrno_memfd_create_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        let name = b"m\0";
        assert_emfile(
            Syscall::MemfdCreate.raw(),
            a1(name.as_ptr() as u64, 0),
            "memfd_create at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_memfd_create_reports_emfile);

fn smoke_abi_ioerrno_pidfd_open_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        assert_emfile(
            Syscall::PidfdOpen.raw(),
            a1(FAKE_TASK, 0),
            "pidfd_open at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_pidfd_open_reports_emfile);

fn smoke_abi_ioerrno_socket_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        // AF_UNIX / SOCK_STREAM — `sock_map_fd` -> get_unused_fd_flags.
        assert_emfile(
            Syscall::SocketOpen.raw(),
            a2(1, 1, 0),
            "socket at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_socket_reports_emfile);

fn smoke_abi_ioerrno_epoll_create_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        assert_emfile(
            Syscall::EpollCreate.raw(),
            a0(0),
            "epoll_create1 at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_epoll_create_reports_emfile);

fn smoke_abi_ioerrno_eventfd_reports_emfile() -> TestResult {
    with_setup(|| {
        saturate_descriptors(8)?;
        assert_emfile(
            Syscall::Eventfd.raw(),
            a1(0, 0),
            "eventfd2 at the descriptor limit must be -EMFILE",
        )
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ioerrno_eventfd_reports_emfile);

fn smoke_abi_ioerrno_open_and_dup_agree_on_emfile() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"x")], || {
        // The point of the sweep: one condition, one errno, whichever door
        // the caller came through.
        saturate_descriptors(8)?;
        match call_open(c"/abi/f".as_ptr() as u64, crate::fd::O_RDWR as u64) {
            Some(v) if v == EMFILE => {}
            _ => return Err("open at the limit must be -EMFILE"),
        }
        expect(
            call(Syscall::Dup.raw(), a0(0)),
            EMFILE,
            "dup at the limit must report the same -EMFILE as open",
        )
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ioerrno_open_and_dup_agree_on_emfile
);
