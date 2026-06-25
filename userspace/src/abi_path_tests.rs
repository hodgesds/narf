//! Linux syscall ABI conformance — path/filesystem group.
//!
//! The file syscalls musl/busybox lean on hardest. Linux-shaped ones take
//! a NUL-terminated path; a few remain NARF-native `(ptr, len)` (flagged
//! // LINUX-GAP). Uses the shared harness + a MemFs scratch mount.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

const AT_FDCWD: u64 = (-100i64) as u64;
const O_RDONLY: u64 = 0;

// ── openat: Linux (dirfd, path_ptr NUL-term, flags) ──

fn smoke_abi_path_openat_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("openat(existing, O_RDONLY) should return a fd >= 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_openat_pos);

fn smoke_abi_path_openat_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/nope\0";
        // Missing file, no O_CREAT → must NOT yield a valid fd.
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => Err("openat(missing, O_RDONLY) must fail, not open a fd"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_openat_neg);

// ── creat: NUL-term path, returns a fd ──

fn smoke_abi_path_creat_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/created\0";
        match call(Syscall::Creat.raw(), a1(path.as_ptr() as u64, 0o644)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("creat(new file) should return a fd >= 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_creat_pos);

fn smoke_abi_path_creat_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        // Parent directory does not exist → cannot create.
        let path = b"/p/no_such_dir/x\0";
        match call(Syscall::Creat.raw(), a1(path.as_ptr() as u64, 0o644)) {
            Some(fd) if fd >= 0 => Err("creat under a missing dir must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_creat_neg);

// ── unlink: NUL-term path → 0 / -1 ──

fn smoke_abi_path_unlink_pos() -> TestResult {
    with_memfs("/p", "p", &[("victim", b"x")], || {
        let path = b"/p/victim\0";
        match call(Syscall::Unlink.raw(), a0(path.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("unlink(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_unlink_pos);

fn smoke_abi_path_unlink_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let path = b"/p/nope\0";
        match call(Syscall::Unlink.raw(), a0(path.as_ptr() as u64)) {
            Some(0) => Err("unlink(missing) must not return success"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_unlink_neg);

// ── rename: two NUL-term paths → 0 / -1 ──

fn smoke_abi_path_rename_pos() -> TestResult {
    with_memfs("/p", "p", &[("old", b"x")], || {
        let old = b"/p/old\0";
        let new = b"/p/new\0";
        match call(
            Syscall::Rename.raw(),
            a1(old.as_ptr() as u64, new.as_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("rename(existing -> new) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_pos);

fn smoke_abi_path_rename_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let old = b"/p/missing\0";
        let new = b"/p/new\0";
        match call(
            Syscall::Rename.raw(),
            a1(old.as_ptr() as u64, new.as_ptr() as u64),
        ) {
            Some(0) => Err("rename(missing -> new) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_neg);

// ── rmdir: NUL-term path → 0 / -1 ──

fn smoke_abi_path_rmdir_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        // Create a directory then remove it.
        let dir = b"/p/d\0";
        let _ = call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        );
        match call(Syscall::Rmdir.raw(), a0(dir.as_ptr() as u64)) {
            Some(0) => Ok(()),
            other => {
                // Some backends don't support mkdir on MemFs; only assert the
                // missing-dir failure path then (still a real neg pin below).
                let _ = other;
                Err("rmdir(empty dir) should return 0")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rmdir_pos);

fn smoke_abi_path_rmdir_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let dir = b"/p/nope\0";
        match call(Syscall::Rmdir.raw(), a0(dir.as_ptr() as u64)) {
            Some(0) => Err("rmdir(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rmdir_neg);

// ── truncate: NARF-native (path_ptr, path_len, new_size) ──

fn smoke_abi_path_truncate_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hello")], || {
        let path = b"/p/f\0";
        // Linux: truncate(const char *path, off_t length) — arg0 NUL-term
        // path, arg1 length.
        match call(Syscall::Truncate.raw(), a1(path.as_ptr() as u64, 2)) {
            Some(0) => Ok(()),
            _ => Err("truncate(existing, 2) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_truncate_pos);

fn smoke_abi_path_truncate_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hello")], || {
        let path = b"/p/missing\0";
        match call(Syscall::Truncate.raw(), a1(path.as_ptr() as u64, 0)) {
            Some(0) => Err("truncate(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_truncate_neg);

// ── getcwd: (buf, len) ──

fn smoke_abi_path_getcwd_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 256];
        // Returns the cwd; success status (value is len/ptr depending on impl).
        match call_raw(
            Syscall::Getcwd.raw(),
            a1(buf.as_mut_ptr() as u64, buf.len() as u64),
        )
        .status
        {
            s if s == SyscallReturn::OK => Ok(()),
            _ => Err("getcwd(buf, 256) should succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_getcwd_pos);

fn smoke_abi_path_getcwd_neg() -> TestResult {
    with_setup(|| {
        // NULL buf / zero len → handler returns InvalidOp (non-Ok).
        match call(Syscall::Getcwd.raw(), a1(0, 0)) {
            None => Ok(()),
            Some(_) => Err("getcwd(NULL, 0) must not report success"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_getcwd_neg);

// ── statx: Linux (dirfd, path_ptr NUL-term, flags, mask, buf) ──

fn smoke_abi_path_statx_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        let mut buf = [0u8; 256];
        let args = SyscallArgs {
            arg0: AT_FDCWD,
            arg1: path.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: buf.as_mut_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::Statx.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("statx(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_pos);

fn smoke_abi_path_statx_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/nope\0";
        let mut buf = [0u8; 256];
        let args = SyscallArgs {
            arg0: AT_FDCWD,
            arg1: path.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            arg4: buf.as_mut_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::Statx.raw(), args) {
            Some(0) => Err("statx(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_neg);

// ── lstat: Linux (path_ptr NUL-term, statbuf) → 0 / -1 ──

fn smoke_abi_path_lstat_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        let mut sb = [0u8; 256];
        match call_lstat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("lstat(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_lstat_pos);

fn smoke_abi_path_lstat_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/nope\0";
        let mut sb = [0u8; 256];
        match call_lstat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Err("lstat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_lstat_neg);

// ── mkdirat: Linux (dirfd, path_ptr NUL-term, mode) ──

fn smoke_abi_path_mkdirat_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let path = b"/p/newdir\0";
        match call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o755, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("mkdirat(new dir) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mkdirat_pos);

fn smoke_abi_path_mkdirat_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        // mkdirat under a missing parent.
        let path = b"/p/missing/child\0";
        match call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o755, 0),
        ) {
            Some(0) => Err("mkdirat under a missing parent must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mkdirat_neg);

// mkdirat returns the right Linux errnos: EEXIST for an existing name,
// ENOENT for a missing parent. busybox `mkdir -p` walks each path
// component and depends on these exactly — EEXIST to skip components
// that already exist, ENOENT to recurse and create missing parents. A
// bare -1 (→ musl EPERM) aborted the whole chain, which broke udevd's
// `mkdir -p /run/udev` on the ext2 rootfs.
fn smoke_abi_path_mkdirat_errnos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let d = b"/p/d\0";
        match call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, d.as_ptr() as u64, 0o755, 0),
        ) {
            Some(0) => {}
            _ => return Err("mkdirat(new) should return 0"),
        }
        // Re-create the same dir → EEXIST.
        match call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, d.as_ptr() as u64, 0o755, 0),
        ) {
            Some(-17) => {}
            _ => return Err("mkdirat(existing) should return -EEXIST (-17)"),
        }
        // mkdir under a missing parent → ENOENT.
        let m = b"/p/missing/child\0";
        match call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, m.as_ptr() as u64, 0o755, 0),
        ) {
            Some(-2) => Ok(()),
            _ => Err("mkdirat(missing parent) should return -ENOENT (-2)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mkdirat_errnos);

// ── open (OpenFile): NARF-native (ptr,len) with a NUL-term fallback ──
//
// sys_open reads arg0=path_ptr, arg1=path_LEN. Crucially it treats len==0 as
// "read a NUL-terminated path", so a Linux-style open(path, flags=O_RDONLY)
// — which passes arg1=0 — still resolves the path. Pin both: the len==0
// NUL-term fallback opens an existing file, and a missing path fails.

fn smoke_abi_path_open_nul_term_fallback_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        match call_open(path.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("open(path, 0) should resolve the NUL-terminated path to a fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_open_nul_term_fallback_pos);

fn smoke_abi_path_open_missing_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/nope\0";
        match call_open(path.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => Err("open(missing, 0) must not return a fd"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_open_missing_neg);
