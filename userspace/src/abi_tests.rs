//! Linux syscall ABI conformance — core fs/path + getpid group.
//!
//! Shares the harness in [`crate::abi_test_support`]; see that module for
//! the rationale. Other categories live in `abi_<cat>_tests.rs`.

use crate::abi_test_support::*;

// ── stat: Linux 2-arg shape (path_ptr, statbuf_ptr), NUL-terminated ──

fn smoke_abi_stat_is_linux_shaped() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/f\0";
        let mut sb = [0u8; 256];
        // Linux: stat(const char *path, struct stat *buf). arg0=path,
        // arg1=buf. Plant garbage in arg2/arg3 (the old NARF (ptr,len)
        // tail) to prove they're ignored.
        match call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Ok(()),
            Some(_) => Err("stat on existing file should return 0"),
            None => Err("stat returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_stat_is_linux_shaped);

fn smoke_abi_stat_missing_path_fails() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/nope\0";
        let mut sb = [0u8; 256];
        // A missing path must NOT report success (value 0). NARF returns
        // the -1 sentinel today; Linux would use -ENOENT. Accept any
        // failure shape (negative value or non-Ok status).
        match call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(v) if v < 0 => Ok(()),
            None => Ok(()),
            Some(_) => Err("stat on a missing path must fail"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_stat_missing_path_fails);

// ── chdir: Linux 1-arg shape (path_ptr), NUL-terminated ──
//
// The canonical regression: chdir used to read arg1 as a NARF-native
// length, so musl's `chdir(path)` (which leaves arg1 = whatever was in
// rsi) mis-parsed. Assert the result is invariant to garbage in arg1.

fn smoke_abi_chdir_ignores_old_length_arg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi\0";
        let clean = call(Syscall::Chdir.raw(), a0(path.as_ptr() as u64));
        let garbage = call(Syscall::Chdir.raw(), a1(path.as_ptr() as u64, 0xdead_beef));
        if clean != garbage {
            return Err("chdir result changed with garbage in arg1 (still reads a length?)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_chdir_ignores_old_length_arg);

// ── mkdir: Linux shape (path_ptr), NUL-terminated ──

fn smoke_abi_mkdir_is_linux_shaped() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/newdir\0";
        // arg0 = NUL-term path; arg1 = mode (Linux) — garbage here must
        // not be treated as a path length.
        match call_mkdir(path.as_ptr() as u64, 0o755) {
            Some(0) => Ok(()),
            Some(_) => Err("mkdir of a new directory should return 0"),
            None => Err("mkdir returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_mkdir_is_linux_shaped);

// ── readlink: Linux -errno convention ──

fn smoke_abi_readlink_nonsymlink_is_einval() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/f\0";
        let mut buf = [0u8; 64];
        // POSIX/Linux: readlink on an existing non-symlink is EINVAL.
        match call_readlink(
            path.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("readlink on a non-symlink must return -EINVAL (-22)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_readlink_nonsymlink_is_einval);

fn smoke_abi_readlink_missing_is_enoent() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hello")], || {
        let path = b"/abi/nope\0";
        let mut buf = [0u8; 64];
        // Linux: a path that names nothing is ENOENT (musl's realpath
        // relies on distinguishing this from EINVAL).
        match call_readlink(
            path.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        ) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("readlink on a missing path must return -ENOENT (-2)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_readlink_missing_is_enoent);

// ── getpid: returns the calling task's visible pid ──

fn smoke_abi_getpid_returns_task() -> TestResult {
    with_setup(
        || match call(Syscall::GetPid.raw(), SyscallArgs::default()) {
            Some(p) if p as u64 == FAKE_TASK => Ok(()),
            _ => Err("getpid should return the calling task's pid"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_getpid_returns_task);
