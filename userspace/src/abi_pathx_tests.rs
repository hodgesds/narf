//! Linux syscall ABI conformance — path/fs *at + utimes group.
//!
//! The path/fs syscalls the first pass skipped: the `*at` directory-fd
//! variants (faccessat/fchmodat/…/renameat2/openat2/readlinkat/unlinkat),
//! the fd-keyed fchmod/fchown, the legacy access/chmod/chown/lchown
//! entries, statfs, the symlink pair, getdents64/listdir, and the
//! utime/utimes/utimensat time-stamp no-ops. Uses the shared harness + a
//! MemFs scratch mount. Most `*at` calls take `(dirfd, path_ptr, …)` with
//! `dirfd = AT_FDCWD`; NARF ignores the dirfd and requires absolute paths.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

const AT_FDCWD: u64 = (-100i64) as u64;

// ── access (NUL-term path, mode) → 0 / -1 ──────────────────────────
//
// sys_access_chmod_chown: arg0 = NUL-term path; existence check over
// files AND dirs (mode/uid/gid are structural-only, not enforced).

fn smoke_abi_pathx_access_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        const R_OK: u64 = 4;
        match call_access(path.as_ptr() as u64, R_OK) {
            Some(0) => Ok(()),
            _ => Err("access(existing, R_OK) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_access_pos);

fn smoke_abi_pathx_access_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call_access(path.as_ptr() as u64, 4) {
            Some(0) => Err("access(missing) must not return 0"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_access_neg);

// ── chmod (NUL-term path, mode) → 0 / -1 ───────────────────────────

fn smoke_abi_pathx_chmod_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call_chmod(path.as_ptr() as u64, 0o644) {
            Some(0) => Ok(()),
            _ => Err("chmod(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_chmod_pos);

fn smoke_abi_pathx_chmod_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call_chmod(path.as_ptr() as u64, 0o644) {
            Some(0) => Err("chmod(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_chmod_neg);

// ── chown (NUL-term path, uid, gid) → 0 / -1 ───────────────────────

fn smoke_abi_pathx_chown_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call_chown(path.as_ptr() as u64, 0, 0) {
            Some(0) => Ok(()),
            _ => Err("chown(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_chown_pos);

fn smoke_abi_pathx_chown_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call_chown(path.as_ptr() as u64, 0, 0) {
            Some(0) => Err("chown(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_chown_neg);

// ── lchown (NUL-term path, uid, gid) → shares sys_access_chmod_chown ──

fn smoke_abi_pathx_lchown_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        // LINUX-GAP: NARF has no symlink-follow distinction; lchown aliases
        // the chmod/chown path handler (no l-variant semantics).
        match call_lchown(path.as_ptr() as u64, 0, 0) {
            Some(0) => Ok(()),
            _ => Err("lchown(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_lchown_pos);

fn smoke_abi_pathx_lchown_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call_lchown(path.as_ptr() as u64, 0, 0) {
            Some(0) => Err("lchown(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_lchown_neg);

// ── chroot (NUL-term path) → 0 / -1 ────────────────────────────────
//
// chroot succeeds iff the absolute path is covered by a mount; a missing
// path or a non-absolute path → -1.

fn smoke_abi_pathx_chroot_pos() -> TestResult {
    let r = with_memfs("/p2", "p2", &[("f", b"hi")], || {
        // The mount root "/p2" is covered → chroot succeeds.
        let path = b"/p2\0";
        match call(Syscall::Chroot.raw(), a0(path.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("chroot(/p2) should return 0"),
        }
    });
    // chroot persists in ROOT_DIR_TABLE for FAKE_TASK and is NOT cleared by
    // setup(); wipe it so later tests' absolute paths aren't rewritten
    // through a stale "/p2" prefix (the mount_e2e_tests pattern).
    crate::handlers::__test_root_dir_reset();
    r
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_chroot_pos);

fn smoke_abi_pathx_chroot_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        // A relative path is rejected outright (must start with '/').
        let path = b"relative\0";
        match call(Syscall::Chroot.raw(), a0(path.as_ptr() as u64)) {
            Some(0) => Err("chroot(relative) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_chroot_neg);

// ── faccessat (dirfd, NUL-term path, mode, flags) → 0 / -1 ─────────

fn smoke_abi_pathx_faccessat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Faccessat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 4, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("faccessat(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_faccessat_pos);

fn smoke_abi_pathx_faccessat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call(
            Syscall::Faccessat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 4, 0),
        ) {
            Some(0) => Err("faccessat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_faccessat_neg);

// ── faccessat2 (dirfd, NUL-term path, mode, flags) → 0 / -1 ────────
//
// sys_at2_reshape measures the NUL-term path, then forwards to the
// shared fchmodat/fchownat existence body.

fn smoke_abi_pathx_faccessat2_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Faccessat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 4, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("faccessat2(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_faccessat2_pos);

fn smoke_abi_pathx_faccessat2_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call(
            Syscall::Faccessat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 4, 0),
        ) {
            Some(0) => Err("faccessat2(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_faccessat2_neg);

// ── fchmod (fd, mode) → 0 / -1 ─────────────────────────────────────
//
// sys_fchmod_or_fchown: arg0 = fd; accept-and-ignore on a known fd,
// -1 on a closed/unknown fd.

fn smoke_abi_pathx_fchmod_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let fd = open_fd(b"/p2/f\0")?;
        match call(Syscall::Fchmod.raw(), a1(fd as u64, 0o644)) {
            Some(0) => Ok(()),
            _ => Err("fchmod(valid fd) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmod_pos);

fn smoke_abi_pathx_fchmod_neg() -> TestResult {
    with_setup(|| {
        // bad fd → -1 sentinel.
        // LINUX-GAP: Linux fchmod(2) on a bad fd returns -EBADF.
        match call(Syscall::Fchmod.raw(), a1(7373, 0o644)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmod_neg);

// ── fchown (fd, uid, gid) → 0 / -1 (shares sys_fchmod_or_fchown) ───

fn smoke_abi_pathx_fchown_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let fd = open_fd(b"/p2/f\0")?;
        match call(Syscall::Fchown.raw(), a2(fd as u64, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("fchown(valid fd) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchown_pos);

fn smoke_abi_pathx_fchown_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux fchown(2) on a bad fd returns -EBADF; NARF -1.
        match call(Syscall::Fchown.raw(), a2(7474, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchown_neg);

// ── fchmodat (dirfd, NUL-term path, mode) → 0 / -1 ─────────────────

fn smoke_abi_pathx_fchmodat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchmodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o644, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("fchmodat(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmodat_pos);

fn smoke_abi_pathx_fchmodat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call(
            Syscall::Fchmodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o644, 0),
        ) {
            Some(0) => Err("fchmodat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmodat_neg);

// ── fchmodat2 (dirfd, NUL-term path, mode, flags) → 0 / -1 ─────────

fn smoke_abi_pathx_fchmodat2_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchmodat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o644, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("fchmodat2(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmodat2_pos);

fn smoke_abi_pathx_fchmodat2_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call(
            Syscall::Fchmodat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o644, 0),
        ) {
            Some(0) => Err("fchmodat2(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmodat2_neg);

// ── fchownat (dirfd, NUL-term path, uid, gid, flags) → 0 / -1 ──────
//
// Shares sys_fchmodat_or_fchownat: only the (dirfd, path) prefix is
// read; uid/gid/flags are ignored, existence decides the result.

fn smoke_abi_pathx_fchownat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchownat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("fchownat(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchownat_pos);

fn smoke_abi_pathx_fchownat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call(
            Syscall::Fchownat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) {
            Some(0) => Err("fchownat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchownat_neg);

// ── newfstatat (dirfd, NUL-term path, statbuf, flags) → 0 / -1 ─────

fn smoke_abi_pathx_newfstatat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        let mut sb = [0u8; 256];
        match call(
            Syscall::Newfstatat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, sb.as_mut_ptr() as u64, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("newfstatat(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_newfstatat_pos);

fn smoke_abi_pathx_newfstatat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        let mut sb = [0u8; 256];
        match call(
            Syscall::Newfstatat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, sb.as_mut_ptr() as u64, 0),
        ) {
            Some(0) => Err("newfstatat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_newfstatat_neg);

// ── openat2 (dirfd, NUL-term path, open_how*, size) → fd / -EINVAL ──
//
// open_how is { u64 flags; u64 mode; u64 resolve } (24 bytes). how==NULL
// or size<24 → -EINVAL; otherwise forwards to sys_open with the flags.

fn smoke_abi_pathx_openat2_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        let how = [0u8; 24]; // flags=0 (O_RDONLY), mode=0, resolve=0.
        match call(
            Syscall::Openat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, how.as_ptr() as u64, 24),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("openat2(existing) should return a fd >= 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_openat2_pos);

fn smoke_abi_pathx_openat2_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        // how==NULL → -EINVAL (structural check before any path work).
        match call(
            Syscall::Openat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 24),
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("openat2(how=NULL) was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_openat2_neg);

// ── readlinkat (dirfd, NUL-term path, buf, buflen) → len / -1 ──────
//
// Resolves a symlink and copies its target into buf, returning the byte
// count. Build the symlink first via symlinkat, then read it back.

fn smoke_abi_pathx_readlinkat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        // Create /p2/lnk -> "target" (Linux symlinkat: target, dirfd, linkpath).
        let target = b"target\0";
        let link = b"/p2/lnk\0";
        let _ = call(
            Syscall::Symlinkat.raw(),
            a2(target.as_ptr() as u64, AT_FDCWD, link.as_ptr() as u64),
        );
        let path = b"/p2/lnk\0";
        let mut buf = [0u8; 64];
        match call(
            Syscall::Readlinkat.raw(),
            a3(
                AT_FDCWD,
                path.as_ptr() as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            ),
        ) {
            Some(6) if &buf[..6] == b"target" => Ok(()),
            _ => Err("readlinkat(symlink) did not return the 6-byte target"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_readlinkat_pos);

fn smoke_abi_pathx_readlinkat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        let mut buf = [0u8; 64];
        match call(
            Syscall::Readlinkat.raw(),
            a3(
                AT_FDCWD,
                path.as_ptr() as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            ),
        ) {
            Some(n) if n >= 0 => Err("readlinkat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_readlinkat_neg);

// ── renameat (olddirfd, old NUL-term, newdirfd, new NUL-term) → 0/-1 ──

fn smoke_abi_pathx_renameat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("old", b"x")], || {
        let old = b"/p2/old\0";
        let new = b"/p2/new\0";
        match call(
            Syscall::Renameat.raw(),
            a3(AT_FDCWD, old.as_ptr() as u64, AT_FDCWD, new.as_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("renameat(existing -> new) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_renameat_pos);

fn smoke_abi_pathx_renameat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"x")], || {
        let old = b"/p2/missing\0";
        let new = b"/p2/new\0";
        match call(
            Syscall::Renameat.raw(),
            a3(AT_FDCWD, old.as_ptr() as u64, AT_FDCWD, new.as_ptr() as u64),
        ) {
            Some(0) => Err("renameat(missing -> new) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_renameat_neg);

// ── renameat2 (olddirfd, old, newdirfd, new, flags) → 0 / -EINVAL ──
//
// RENAME_NOREPLACE (1) is honoured; any other flag bit → -EINVAL.

fn smoke_abi_pathx_renameat2_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("old", b"x")], || {
        let old = b"/p2/old\0";
        let new = b"/p2/new\0";
        // flags=0 → plain rename.
        match call_raw(
            Syscall::Renameat2.raw(),
            SyscallArgs {
                arg0: AT_FDCWD,
                arg1: old.as_ptr() as u64,
                arg2: AT_FDCWD,
                arg3: new.as_ptr() as u64,
                arg4: 0,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 0 => Ok(()),
            _ => Err("renameat2(existing -> new, flags=0) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_renameat2_pos);

fn smoke_abi_pathx_renameat2_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("old", b"x")], || {
        let old = b"/p2/old\0";
        let new = b"/p2/new\0";
        // RENAME_EXCHANGE (2) is unsupported → -EINVAL.
        match call_raw(
            Syscall::Renameat2.raw(),
            SyscallArgs {
                arg0: AT_FDCWD,
                arg1: old.as_ptr() as u64,
                arg2: AT_FDCWD,
                arg3: new.as_ptr() as u64,
                arg4: 2,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == EINVAL => Ok(()),
            _ => Err("renameat2(RENAME_EXCHANGE) was not -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_renameat2_neg);

// ── statfs (NARF-native path_ptr, path_len, buf) → 0 / -1 ──────────
//
// LINUX-GAP: NARF-native (ptr, len, buf); Linux is (path NUL-term, buf).

fn smoke_abi_pathx_statfs_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        // Linux: statfs(const char *path, struct statfs *buf).
        let path = b"/p2/f\0";
        let mut buf = [0u8; 128];
        match call(
            Syscall::Statfs.raw(),
            a1(path.as_ptr() as u64, buf.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("statfs(existing, buf) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_statfs_pos);

fn smoke_abi_pathx_statfs_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        // buf_ptr == 0 → fill_statfs_for_path returns false → -1 sentinel.
        match call(Syscall::Statfs.raw(), a1(path.as_ptr() as u64, 0)) {
            Some(-1) => Ok(()),
            _ => Err("statfs(null buf) was not the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_statfs_neg);

// statfs must fill `struct statfs` (f_type FIRST), not a statvfs. Regression
// for the layout bug where f_type read back as a block size, so every
// f_type==<MAGIC> check (e.g. elogind detecting cgroup2) failed.
fn smoke_abi_pathx_statfs_ftype() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        let mut buf = [0u8; 128];
        if call(
            Syscall::Statfs.raw(),
            a1(path.as_ptr() as u64, buf.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("statfs(existing, buf) should return 0");
        }
        // f_type at offset 0 — a memfs reports TMPFS_MAGIC (0x01021994).
        let f_type = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        if f_type != 0x0102_1994 {
            return Err("statfs f_type (offset 0) was not TMPFS_MAGIC — wrong struct layout");
        }
        // f_bsize at offset 8 must be the 4096 block size, not the magic.
        let f_bsize = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        if f_bsize != 4096 {
            return Err("statfs f_bsize (offset 8) was not 4096");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_statfs_ftype);

// ── symlink: Linux (const char *target, const char *linkpath), NUL-term ──
//
// The link location is resolved against cwd; the target stays verbatim.

fn smoke_abi_pathx_symlink_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let target = b"f\0";
        let link = b"/p2/sl\0";
        match call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("symlink(target, /p2/sl) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_symlink_pos);

fn smoke_abi_pathx_symlink_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        // Link parent directory missing → symlink fails with -ENOENT (Linux).
        let target = b"f\0";
        let link = b"/p2/no_such_dir/sl\0";
        match call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) {
            Some(-2) => Ok(()),
            _ => Err("symlink under a missing parent must return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_symlink_neg);

// ── symlinkat: Linux (const char *target, int newdirfd, const char *linkpath) ──

fn smoke_abi_pathx_symlinkat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let target = b"f\0";
        let link = b"/p2/sla\0";
        match call(
            Syscall::Symlinkat.raw(),
            a2(target.as_ptr() as u64, AT_FDCWD, link.as_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("symlinkat(target, /p2/sla) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_symlinkat_pos);

fn smoke_abi_pathx_symlinkat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let target = b"f\0";
        let link = b"/p2/no_such_dir/sla\0";
        match call(
            Syscall::Symlinkat.raw(),
            a2(target.as_ptr() as u64, AT_FDCWD, link.as_ptr() as u64),
        ) {
            Some(-2) => Ok(()),
            _ => Err("symlinkat under a missing parent must return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_symlinkat_neg);

// ── unlinkat (dirfd, NUL-term path, flags) → 0 / -1 ────────────────
//
// flags=0 → unlink; AT_REMOVEDIR (0x200) → rmdir.

fn smoke_abi_pathx_unlinkat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("victim", b"x")], || {
        let path = b"/p2/victim\0";
        match call(
            Syscall::Unlinkat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("unlinkat(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_unlinkat_pos);

fn smoke_abi_pathx_unlinkat_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"x")], || {
        let path = b"/p2/nope\0";
        match call(
            Syscall::Unlinkat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) {
            Some(0) => Err("unlinkat(missing) must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_unlinkat_neg);

// ── getdents64 (dirfd, buf, count) → bytes / -1 ────────────────────
//
// Needs a directory fd (open(path) on a dir → DirFdFile). Opening the
// mount root "/p2" yields a dir fd whose enumerate serves the seeds.

fn smoke_abi_pathx_getdents64_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("a", b"x"), ("b", b"y")], || {
        let dfd = open_fd(b"/p2\0")?;
        let mut buf = [0u8; 256];
        // At least one linux_dirent64 record is written for the 2 seeds.
        match call(
            Syscall::Getdents64.raw(),
            a2(dfd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        ) {
            Some(n) if n > 0 => Ok(()),
            _ => Err("getdents64(dir fd) should return > 0 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_getdents64_pos);

fn smoke_abi_pathx_getdents64_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 256];
        // bad fd (not a directory fd) → -1 sentinel.
        // LINUX-GAP: Linux getdents64(2) returns -EBADF / -ENOTDIR.
        match call(
            Syscall::Getdents64.raw(),
            a2(9292, buf.as_mut_ptr() as u64, buf.len() as u64),
        ) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_getdents64_neg);

// ── getdents (legacy 32-bit-offset dirfd, buf, count) → bytes / -1 ──
//
// Same directory-fd resolution as getdents64, but the LEGACY
// `struct linux_dirent { d_ino: u64; d_off: u64; d_reclen: u16;
// d_name[]; }` wire format: the d_type byte lives at the LAST byte of
// each record (buf[off + d_reclen - 1]), with a NUL after the name.

fn smoke_abi_pathx_getdents_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("a", b"x"), ("b", b"y")], || {
        let dfd = open_fd(b"/p2\0")?;
        let mut buf = [0u8; 256];
        let n = match call(
            Syscall::Getdents.raw(),
            a2(dfd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        ) {
            Some(n) if n > 0 => n as usize,
            _ => return Err("getdents(dir fd) should return > 0 bytes"),
        };
        // Parse the first legacy linux_dirent record.
        if n < 18 {
            return Err("getdents record too short");
        }
        let d_ino = u64::from_ne_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        if d_ino == 0 {
            return Err("getdents d_ino must be non-zero");
        }
        let reclen = u16::from_ne_bytes([buf[16], buf[17]]) as usize;
        if reclen == 0 || reclen > n || reclen % 8 != 0 {
            return Err("getdents d_reclen must be a non-zero 8-aligned length");
        }
        // Name starts at offset 18 and is NUL-terminated; the first seed
        // enumerated is "a" (single byte name).
        if buf[18] != b'a' || buf[19] != 0 {
            return Err("getdents first entry name should be \"a\\0\"");
        }
        // Legacy d_type is the LAST byte of the record — DT_REG (8) for a
        // regular file seed.
        if buf[reclen - 1] != 8 {
            return Err("getdents d_type (at reclen-1) should be DT_REG (8)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_getdents_pos);

fn smoke_abi_pathx_getdents_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 256];
        // bad fd (not open) → -EBADF, same as getdents64.
        match call(
            Syscall::Getdents.raw(),
            a2(9292, buf.as_mut_ptr() as u64, buf.len() as u64),
        ) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_getdents_neg);

// ── listdir (NARF-native path_ptr, path_len, cursor, out, out_len) ──
//
// Path-based readdir: serialises the cursor-th entry as
// [name_len:u32][file_type:u32][name…]. Returns bytes_written (>0),
// 0 at end-of-directory, -1 on bad input. LINUX-GAP: NARF-only call.

fn smoke_abi_pathx_listdir_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("a", b"x"), ("b", b"y")], || {
        let path = b"/p2";
        let mut buf = [0u8; 128];
        // cursor 0 → first entry; expect 8-byte header + at least 1 name byte.
        match call(
            Syscall::Listdir.raw(),
            SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.len() as u64,
                arg2: 0,
                arg3: buf.as_mut_ptr() as u64,
                arg4: buf.len() as u64,
                arg5: 0,
            },
        ) {
            Some(n) if n > 8 => Ok(()),
            _ => Err("listdir(dir, cursor 0) should return > 8 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_listdir_pos);

fn smoke_abi_pathx_listdir_neg() -> TestResult {
    with_memfs("/p2", "p2", &[("a", b"x")], || {
        let path = b"/p2";
        // out_ptr == NULL → -1 sentinel.
        match call(
            Syscall::Listdir.raw(),
            SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.len() as u64,
                arg2: 0,
                arg3: 0,
                arg4: 128,
                arg5: 0,
            },
        ) {
            Some(-1) => Ok(()),
            _ => Err("listdir(null out buf) was not the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_listdir_neg);

// ── utime (NUL-term path) → 0 / -EFAULT ────────────────────────────
//
// sys_utime_noop: validates the path cstr, then accepts (file times are
// not tracked). LINUX-GAP: never touches the FS, so it returns 0 even
// for a path that does not exist — only a NULL/faulting ptr → -EFAULT.

fn smoke_abi_pathx_utime_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call_utime(path.as_ptr() as u64, 0) {
            Some(0) => Ok(()),
            _ => Err("utime(path) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utime_pos);

fn smoke_abi_pathx_utime_neg() -> TestResult {
    with_setup(|| {
        // NULL path → copy_user_cstr fails → -EFAULT.
        match call_utime(0, 0) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("utime(NULL) was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utime_neg);

// ── utimes (NUL-term path) → 0 / -EFAULT (shares sys_utime_noop) ───

fn smoke_abi_pathx_utimes_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call_utimes(path.as_ptr() as u64, 0) {
            Some(0) => Ok(()),
            _ => Err("utimes(path) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utimes_pos);

fn smoke_abi_pathx_utimes_neg() -> TestResult {
    with_setup(|| match call_utimes(0, 0) {
        Some(v) if v == EFAULT => Ok(()),
        _ => Err("utimes(NULL) was not -EFAULT"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utimes_neg);

// ── utimensat (dirfd, path, times, flags) → 0 / -EFAULT ────────────
//
// path == NULL is the futimens-on-dirfd form (accepted → 0); a non-NULL
// path is validated as a cstr, accepted on success, -EFAULT on fault.

fn smoke_abi_pathx_utimensat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("utimensat(path) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utimensat_pos);

fn smoke_abi_pathx_utimensat_neg() -> TestResult {
    with_setup(|| {
        // A non-NULL, non-canonical path pointer (bit 48 set, bits 49..63
        // clear) is rejected by validate_user_range *before* any deref, so
        // copy_user_cstr returns None → -EFAULT — without faulting the
        // harness (which has no live user AS to map a wild address).
        let bad = 0x0001_0000_0000_0000u64;
        match call(Syscall::Utimensat.raw(), a3(AT_FDCWD, bad, 0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("utimensat(non-canonical path) was not -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utimensat_neg);

// ── local helper ───────────────────────────────────────────────────

/// Open `path` (NUL-terminated, absolute) and return its fd. flags=0;
/// a path that names a directory yields a DirFdFile fd (for getdents64).
fn open_fd(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, 0) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open failed"),
    }
}

// ── utime / utimensat: missing path → -ENOENT (no-op on times, but the
//    path is still validated like Linux). ──

fn smoke_abi_pathx_utime_missing_is_enoent() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        match call_utime(path.as_ptr() as u64, 0) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("utime(missing path) should return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utime_missing_is_enoent);

fn smoke_abi_pathx_utimensat_missing_is_enoent() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/nope\0";
        // utimensat(dirfd, path, times, flags): a path that names nothing is ENOENT.
        let args = SyscallArgs {
            arg0: AT_FDCWD,
            arg1: path.as_ptr() as u64,
            ..Default::default()
        };
        match call(Syscall::Utimensat.raw(), args) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("utimensat(missing path) should return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_utimensat_missing_is_enoent);
