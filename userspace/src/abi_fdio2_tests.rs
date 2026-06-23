//! Linux syscall ABI conformance — fdio group, second pass.
//!
//! Additional regression pins for fd-I/O handler branches the original
//! `abi_fdio_tests.rs` does not exercise: the positional pread64/pwrite64
//! and preadv2/pwritev2 handlers (uncovered entirely), the EFAULT-on-bad-
//! pointer branch of read / readv / writev / vmsplice, the SEEK_CUR /
//! SEEK_END / negative-offset arms of lseek, the F_GETFL / F_SETFL /
//! F_DUPFD / F_DUPFD_CLOEXEC fcntl commands, the dup2(fd, fd) no-op vs.
//! bad-oldfd arms, and the close_range bad-flags / CLOSE_RANGE_CLOEXEC
//! paths. Every test asserts the CURRENT NARF behavior (regression pin);
//! Linux-ideal divergences carry a `// LINUX-GAP:` note.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// ── Local helpers (mirrors abi_fdio_tests.rs; kept private to this file) ──

/// Open `path` (a `&[u8]` ending in NUL) and return the fd. flags=0.
fn open_fd2(path: &[u8]) -> Result<u32, &'static str> {
    let ptr = path.as_ptr() as u64;
    match call(Syscall::OpenFile.raw(), a1(ptr, 0)) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open failed"),
    }
}

/// Create a pipe via `sys_pipe`; return `(read_fd, write_fd)`.
fn make_pipe2() -> Result<(u32, u32), &'static str> {
    let mut buf = [0u8; 8];
    let r = call_raw(Syscall::Pipe.raw(), a0(buf.as_mut_ptr() as u64));
    if r.status != SyscallReturn::OK || r.value as i64 != 0 {
        return Err("pipe failed");
    }
    let rd = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u32;
    let wr = i32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]) as u32;
    Ok((rd, wr))
}

/// A non-canonical x86_64 user VA: bit 48 set, bits 49..=62 clear. The
/// kernel's `validate_user_range` rejects it with EFAULT before any
/// dereference, so it is a deterministic "bad pointer" in this harness.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

// ── pread64 / pwrite64 — positional I/O, per-fd cursor untouched ────

fn smoke_abi_fdio2_pread64_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        let mut buf = [0u8; 8];
        // pread64(fd, buf, 4, offset=2) → reads "cdef" without moving the
        // per-fd cursor (POSIX guarantee).
        if call(
            Syscall::Pread64.raw(),
            a3(fd as u64, buf.as_mut_ptr() as u64, 4, 2),
        ) != Some(4)
            || &buf[..4] != b"cdef"
        {
            return Err("pread64 at offset 2 did not return cdef");
        }
        // Cursor must be unchanged: a following read from offset 0 returns
        // the file head, proving pread did not advance it.
        let mut b2 = [0u8; 2];
        match call(Syscall::Read.raw(), a2(fd as u64, b2.as_mut_ptr() as u64, 2)) {
            Some(2) if &b2[..2] == b"ab" => Ok(()),
            _ => Err("pread64 advanced the per-fd cursor"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pread64_pos);

fn smoke_abi_fdio2_pread64_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 4];
        // bad fd → -1 sentinel (Ok status, value -1).
        // LINUX-GAP: Linux pread64(2) on a bad fd returns -EBADF.
        match call(
            Syscall::Pread64.raw(),
            a3(5151, buf.as_mut_ptr() as u64, 4, 0),
        ) {
            Some(-1) => Ok(()),
            _ => Err("pread64 on bad fd was not -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pread64_neg);

fn smoke_abi_fdio2_pread64_zero_len() -> TestResult {
    with_setup(|| {
        // len == 0 short-circuits to 0 BEFORE the fd is looked up, so even
        // a bogus fd returns 0 (the boundary the handler special-cases).
        match call(Syscall::Pread64.raw(), a3(4242, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("pread64 zero-len did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pread64_zero_len);

fn smoke_abi_fdio2_pwrite64_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"......")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        let data = *b"XY";
        // pwrite64(fd, data, 2, offset=2) → 2 bytes written at offset 2,
        // cursor untouched.
        if call(Syscall::Pwrite64.raw(), a3(fd as u64, data.as_ptr() as u64, 2, 2)) != Some(2) {
            return Err("pwrite64 did not return 2");
        }
        // Read back the whole file from offset 0 to confirm placement.
        let mut buf = [0u8; 8];
        match call(Syscall::Pread64.raw(), a3(fd as u64, buf.as_mut_ptr() as u64, 6, 0)) {
            Some(6) if &buf[..6] == b"..XY.." => Ok(()),
            _ => Err("pwrite64 did not place bytes at offset 2"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pwrite64_pos);

fn smoke_abi_fdio2_pwrite64_neg() -> TestResult {
    with_setup(|| {
        let data = *b"z";
        // bad fd → -1 sentinel.
        // LINUX-GAP: Linux pwrite64(2) on a bad fd returns -EBADF.
        match call(Syscall::Pwrite64.raw(), a3(5252, data.as_ptr() as u64, 1, 0)) {
            Some(-1) => Ok(()),
            _ => Err("pwrite64 on bad fd was not -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pwrite64_neg);

// ── preadv2 / pwritev2 — positional vectored I/O with a flags word ─

fn smoke_abi_fdio2_preadv2_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        let mut dst = [0u8; 8];
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(8u64).to_le_bytes());
        // preadv2(fd, iov, 1, offset=2, pos_h=0, flags=0) → "cdef".
        match call_raw(
            Syscall::Preadv2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: 2,
                arg4: 0,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 4 && &dst[..4] == b"cdef" => {
                Ok(())
            }
            _ => Err("preadv2 at offset 2 did not return cdef"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_preadv2_pos);

fn smoke_abi_fdio2_preadv2_neg() -> TestResult {
    with_setup(|| {
        // iovcnt > IOV_MAX (1024) → -EINVAL.
        match call(Syscall::Preadv2.raw(), a3(3, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("preadv2 over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_preadv2_neg);

fn smoke_abi_fdio2_pwritev2_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        let payload = *b"WXYZ";
        let mut iov = [0u8; 16];
        iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
        iov[8..].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        // pwritev2(fd, iov, 1, offset=0, pos_h=0, flags=0) → 4 bytes.
        match call_raw(
            Syscall::Pwritev2.raw(),
            SyscallArgs {
                arg0: fd as u64,
                arg1: iov.as_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 4 => Ok(()),
            _ => Err("pwritev2 did not return 4"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pwritev2_pos);

fn smoke_abi_fdio2_pwritev2_neg() -> TestResult {
    with_setup(|| {
        // iovcnt > IOV_MAX → -EINVAL.
        match call(Syscall::Pwritev2.raw(), a3(3, 0x1000, 2000, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pwritev2 over IOV_MAX was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_pwritev2_neg);

// ── read / write — zero-length boundary + EFAULT branches ──────────
//
// The original file covers read/write success + bad-fd InvalidOp, but
// not the `len == 0` early-return (returns 0 before any fd lookup) nor
// the `validate_user_range` EFAULT arm.

fn smoke_abi_fdio2_read_zero_len() -> TestResult {
    with_setup(|| {
        // len == 0 returns 0 before the fd is consulted — even a bad fd.
        match call(Syscall::Read.raw(), a2(9999, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("read zero-len did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_read_zero_len);

fn smoke_abi_fdio2_read_efault() -> TestResult {
    with_setup(|| {
        // Non-null but non-canonical dst pointer → validate_user_range
        // rejects it → -EFAULT (Ok status, value -14), before any fd use.
        match call(Syscall::Read.raw(), a2(3, BAD_PTR, 4)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("read with a bad dst pointer was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_read_efault);

fn smoke_abi_fdio2_write_zero_len() -> TestResult {
    with_setup(|| {
        // len == 0 returns 0 before the fd / buffer are touched.
        match call(Syscall::Write.raw(), a2(9999, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("write zero-len did not return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_write_zero_len);

fn smoke_abi_fdio2_write_efault() -> TestResult {
    with_setup(|| {
        // copy_from_user_vec on a non-canonical src → -EFAULT.
        match call(Syscall::Write.raw(), a2(3, BAD_PTR, 4)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("write with a bad src pointer was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_write_efault);

// ── readv / writev / vmsplice — EFAULT on a bad iovec array ─────────
//
// The original file covers the IOV_MAX EINVAL arm but not the
// copy_from_user_vec(iov_ptr) failure arm (iovcnt within bounds, but
// the iovec array pointer itself is unreadable).

fn smoke_abi_fdio2_readv_efault() -> TestResult {
    with_setup(|| {
        // iovcnt == 1 (≤ IOV_MAX) but the iovec array pointer is bad →
        // copy_from_user_vec → -EFAULT.
        match call(Syscall::Readv.raw(), a2(3, BAD_PTR, 1)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("readv with a bad iovec ptr was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_readv_efault);

fn smoke_abi_fdio2_writev_efault() -> TestResult {
    with_setup(|| {
        match call(Syscall::Writev.raw(), a2(3, BAD_PTR, 1)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("writev with a bad iovec ptr was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_writev_efault);

fn smoke_abi_fdio2_vmsplice_efault() -> TestResult {
    with_setup(|| {
        // nr_segs == 1 (≤ IOV_MAX), bad iovec array → -EFAULT.
        match call(Syscall::Vmsplice.raw(), a3(3, BAD_PTR, 1, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("vmsplice with a bad iovec ptr was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_vmsplice_efault);

// ── lseek — SEEK_CUR / SEEK_END / negative-offset arms ─────────────
//
// SEEK_SET (0) is covered upstream. SEEK_CUR=1, SEEK_END=2.

fn smoke_abi_fdio2_lseek_cur_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        // Seed the cursor to 2 with SEEK_SET, then SEEK_CUR +2 → 4.
        if call(Syscall::Lseek.raw(), a2(fd as u64, 2, 0)) != Some(2) {
            return Err("lseek SEEK_SET seed did not return 2");
        }
        match call(Syscall::Lseek.raw(), a2(fd as u64, 2, 1)) {
            Some(4) => Ok(()),
            _ => Err("lseek SEEK_CUR +2 from 2 did not return 4"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_lseek_cur_pos);

fn smoke_abi_fdio2_lseek_end_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        // SEEK_END with offset 0 → file size (6 bytes).
        match call(Syscall::Lseek.raw(), a2(fd as u64, 0, 2)) {
            Some(6) => Ok(()),
            _ => Err("lseek SEEK_END did not return the file size"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_lseek_end_pos);

fn smoke_abi_fdio2_lseek_negative_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"abcdef")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        // A resulting offset < 0 (SEEK_SET to -1) → InvalidOp.
        // LINUX-GAP: Linux lseek(2) to a negative offset returns -EINVAL.
        match call_raw(Syscall::Lseek.raw(), a2(fd as u64, (-1i64) as u64, 0)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("lseek to a negative offset was not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_lseek_negative_neg);

// ── fcntl — F_GETFL / F_SETFL / F_DUPFD / F_DUPFD_CLOEXEC ───────────
//
// The original file covers F_GETFD / F_SETFD only. F_GETFL=3, F_SETFL=4,
// F_DUPFD=0, F_DUPFD_CLOEXEC=1030. O_NONBLOCK=0o4000.

fn smoke_abi_fdio2_fcntl_getfl_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        const F_SETFL: u64 = 4;
        const F_GETFL: u64 = 3;
        const O_NONBLOCK: i64 = 0o4000;
        // F_SETFL O_NONBLOCK → 0; F_GETFL reads the status flags back with
        // the O_NONBLOCK bit set (only the settable subset is honoured).
        if call(Syscall::Fcntl.raw(), a2(fd as u64, F_SETFL, O_NONBLOCK as u64)) != Some(0) {
            return Err("F_SETFL O_NONBLOCK did not return 0");
        }
        match call(Syscall::Fcntl.raw(), a2(fd as u64, F_GETFL, 0)) {
            Some(v) if v & O_NONBLOCK == O_NONBLOCK => Ok(()),
            _ => Err("F_GETFL did not read back O_NONBLOCK"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_fcntl_getfl_pos);

fn smoke_abi_fdio2_fcntl_dupfd_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        const F_DUPFD: u64 = 0;
        // F_DUPFD with a high floor → a fresh fd >= 20, distinct from fd.
        match call(Syscall::Fcntl.raw(), a2(fd as u64, F_DUPFD, 20)) {
            Some(n) if n >= 20 && n as u32 != fd => Ok(()),
            _ => Err("F_DUPFD did not return a fresh fd at/above the floor"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_fcntl_dupfd_pos);

fn smoke_abi_fdio2_fcntl_dupfd_cloexec_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        const F_DUPFD_CLOEXEC: u64 = 1030;
        const F_GETFD: u64 = 1;
        const FD_CLOEXEC: i64 = 1;
        // F_DUPFD_CLOEXEC atomically stamps FD_CLOEXEC on the new fd.
        let new_fd = match call(Syscall::Fcntl.raw(), a2(fd as u64, F_DUPFD_CLOEXEC, 30)) {
            Some(n) if n >= 30 => n as u64,
            _ => return Err("F_DUPFD_CLOEXEC did not return a fresh fd"),
        };
        match call(Syscall::Fcntl.raw(), a2(new_fd, F_GETFD, 0)) {
            Some(v) if v == FD_CLOEXEC => Ok(()),
            _ => Err("F_DUPFD_CLOEXEC did not set FD_CLOEXEC on the new fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_fcntl_dupfd_cloexec_pos);

fn smoke_abi_fdio2_fcntl_dupfd_neg() -> TestResult {
    with_setup(|| {
        const F_DUPFD: u64 = 0;
        // F_DUPFD from a bad oldfd → InvalidOp.
        // LINUX-GAP: Linux F_DUPFD on a bad fd returns -EBADF.
        match call_raw(Syscall::Fcntl.raw(), a2(7654, F_DUPFD, 0)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("F_DUPFD on a bad fd was not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_fcntl_dupfd_neg);

// ── dup2 — oldfd == newfd no-op (valid) vs. bad-oldfd ──────────────
//
// The original dup2 tests cover dup-to-a-different-slot and bad-oldfd
// (different slot). The POSIX same-fd no-op short-circuit is its own arm.

fn smoke_abi_fdio2_dup2_same_fd_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        // dup2(fd, fd) on a valid fd is a no-op that returns fd.
        match call(Syscall::Dup2.raw(), a1(fd as u64, fd as u64)) {
            Some(v) if v == fd as i64 => Ok(()),
            _ => Err("dup2(fd, fd) on a valid fd did not return fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_dup2_same_fd_pos);

fn smoke_abi_fdio2_dup2_same_fd_neg() -> TestResult {
    with_setup(|| {
        // dup2(badfd, badfd): same-fd path verifies validity first → the
        // closed fd is invalid → InvalidOp.
        // LINUX-GAP: Linux dup2(badfd, badfd) returns -EBADF.
        match call_raw(Syscall::Dup2.raw(), a1(3030, 3030)) {
            r if r.status == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("dup2(badfd, badfd) was not InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_dup2_same_fd_neg);

// ── close_range — CLOSE_RANGE_CLOEXEC flag + bad-flags EINVAL ───────
//
// The original file covers the plain (flags=0) success and the
// first>last EINVAL. The bad-flags EINVAL and the CLOEXEC-flag success
// are distinct branches in the guard.

fn smoke_abi_fdio2_close_range_cloexec_pos() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_fd2(b"/abi/f\0")?;
        const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
        // CLOSE_RANGE_CLOEXEC marks the range cloexec instead of closing;
        // a recognised flag → 0. The fd stays open afterwards.
        if call(
            Syscall::CloseRange.raw(),
            a2(fd as u64, fd as u64, CLOSE_RANGE_CLOEXEC),
        ) != Some(0)
        {
            return Err("close_range CLOEXEC did not return 0");
        }
        // The fd is still usable (marked cloexec, not closed).
        let mut buf = [0u8; 2];
        match call(Syscall::Read.raw(), a2(fd as u64, buf.as_mut_ptr() as u64, 2)) {
            Some(2) => Ok(()),
            _ => Err("close_range CLOEXEC unexpectedly closed the fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_close_range_cloexec_pos);

fn smoke_abi_fdio2_close_range_badflag_neg() -> TestResult {
    with_setup(|| {
        // An unrecognised flag bit (0x1) → -EINVAL (distinct from the
        // first>last EINVAL arm covered upstream).
        match call(Syscall::CloseRange.raw(), a2(3, 5, 0x1)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("close_range with a bad flag was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_close_range_badflag_neg);

// ── eventfd — EFD_NONBLOCK flag still yields a fresh fd ─────────────
//
// The upstream eventfd test passes flags=0. The flag-carrying path takes
// the same EventFd::new branch; pin it returns a valid fd too.

fn smoke_abi_fdio2_eventfd_nonblock_pos() -> TestResult {
    with_setup(|| {
        const EFD_NONBLOCK: u64 = 0o4000;
        // eventfd(initval=7, EFD_NONBLOCK) → a fresh fd (>= 0).
        match call(Syscall::Eventfd.raw(), a1(7, EFD_NONBLOCK)) {
            Some(n) if n >= 0 => Ok(()),
            _ => Err("eventfd with EFD_NONBLOCK did not return a fresh fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_eventfd_nonblock_pos);

// ── tee — empty-source consume + write-side success on a real pipe ──
//
// The upstream tee_pos uses two distinct empty pipes. Here we tee from a
// fed source so the write-to-fd_out arm (the `Some(Ok(n))` set_return) is
// exercised, not just the `data.is_empty()` early 0.

fn smoke_abi_fdio2_tee_with_data_pos() -> TestResult {
    with_setup(|| {
        let (rd1, wr1) = make_pipe2()?;
        let (_rd2, wr2) = make_pipe2()?;
        // Feed the source pipe so the peek yields bytes.
        let payload = *b"qrst";
        if call(Syscall::Write.raw(), a2(wr1 as u64, payload.as_ptr() as u64, 4)) != Some(4) {
            return Err("priming write to source pipe did not return 4");
        }
        // tee duplicates up to 4 bytes into wr2 without consuming wr1.
        match call(Syscall::Tee.raw(), a3(rd1 as u64, wr2 as u64, 4, 0)) {
            Some(4) => Ok(()),
            // Some pipe impls cap the peek; accept any positive count as the
            // write-side success arm, but require it be non-zero/non-error.
            Some(n) if n > 0 && n <= 4 => Ok(()),
            _ => Err("tee from a fed pipe did not copy bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fdio2_tee_with_data_pos);
