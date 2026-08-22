//! Linux syscall ABI conformance — path/fs *at + utimes group.
//!
//! The path/fs syscalls the first pass skipped: the `*at` directory-fd
//! variants (faccessat/fchmodat/…/renameat2/openat2/readlinkat/unlinkat),
//! the fd-keyed fchmod/fchown, the legacy access/chmod/chown/lchown
//! entries, statfs, the symlink pair, getdents64/listdir, and the
//! utime/utimes/utimensat time-stamp no-ops. Uses the shared harness + a
//! MemFs scratch mount. The `*at` cases cover both `AT_FDCWD` and real
//! directory-fd anchoring.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

const AT_FDCWD: u64 = (-100i64) as u64;

fn file_owners(path: &str) -> Option<(u32, u32)> {
    narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel)
                .ok()
                .map(|file| file.owners())
        })
        .flatten()
}

fn file_perms(path: &str) -> Option<u16> {
    narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel)
                .ok()
                .map(|file| file.stat().mode.perms)
        })
        .flatten()
}

fn dir_owners(path: &str) -> Option<(u32, u32)> {
    narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            let mut dir = fs.root();
            for component in rel.split('/').filter(|part| !part.is_empty()) {
                dir = dir.lookup_dir(component)?;
            }
            Some(dir.dir_owners())
        })
        .flatten()
}

fn dir_perms(path: &str) -> Option<u16> {
    narf_filesystem::registry()
        .resolve_absolute(path, |fs, rel| {
            let mut dir = fs.root();
            for component in rel.split('/').filter(|part| !part.is_empty()) {
                dir = dir.lookup_dir(component)?;
            }
            Some(dir.dir_mode())
        })
        .flatten()
}

fn lstat_owners(path: &[u8]) -> Option<(u32, u32)> {
    let mut buf = [0u8; 144];
    if call(
        Syscall::Lstat.raw(),
        a1(path.as_ptr() as u64, buf.as_mut_ptr() as u64),
    ) != Some(0)
    {
        return None;
    }
    Some((
        u32::from_ne_bytes(buf[28..32].try_into().ok()?),
        u32::from_ne_bytes(buf[32..36].try_into().ok()?),
    ))
}

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
        match call_chmod(path.as_ptr() as u64, 0o4754) {
            Some(0) if file_perms("/p2/f") == Some(0o4754) => Ok(()),
            _ => Err("chmod(existing) did not preserve special mode bits"),
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
        match call_chown(path.as_ptr() as u64, 1000, 1001) {
            Some(0) if file_owners("/p2/f") == Some((1000, 1001)) => Ok(()),
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

// access(2) applies to directories as well as regular files. In particular,
// systemd checks W_OK on the cgroup2 mount root immediately after mount(2);
// returning ENOENT for a mount directory makes it tear the hierarchy down.
fn smoke_abi_pathx_faccessat_mount_root_writable() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2\0";
        match call(
            Syscall::Faccessat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 2, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("faccessat(W_OK) on a writable mount root should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_faccessat_mount_root_writable);

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

// ── faccessat2(fd, "", X_OK, AT_EMPTY_PATH) → 0 ────────────────────
//
// glibc's access_fd() tests an O_PATH fd for executability via
// faccessat2(fd, "", X_OK, AT_EMPTY_PATH); systemd's
// open_and_check_executable / find_executable_full relies on it to confirm a
// service binary before execve. An empty path must name the fd itself — NOT
// resolve fd_path + "/", which turned a regular-file fd into a dir-shaped
// path that missed (ENOENT) and killed every sandboxed service 203/EXIT_EXEC.
fn smoke_abi_pathx_faccessat2_empty_path_fd() -> TestResult {
    with_memfs("/p2e", "p2e", &[("bin", b"exe")], || {
        let path = b"/p2e/bin\0";
        let fd = match call_open(path.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open /p2e/bin failed"),
        };
        const X_OK: u64 = 1;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let empty = b"\0";
        match call(
            Syscall::Faccessat2.raw(),
            a3(fd, empty.as_ptr() as u64, X_OK, AT_EMPTY_PATH),
        ) {
            Some(0) => Ok(()),
            _ => Err("faccessat2(fd, \"\", X_OK, AT_EMPTY_PATH) must return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_faccessat2_empty_path_fd);

// ── fchmod (fd, mode) → 0 / errno ──────────────────────────────────

fn smoke_abi_pathx_fchmod_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let fd = open_fd(b"/p2/f\0")?;
        match call(Syscall::Fchmod.raw(), a1(fd as u64, 0o4754)) {
            Some(0) if file_perms("/p2/f") == Some(0o4754) => Ok(()),
            _ => Err("fchmod(valid fd) did not preserve special mode bits"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmod_pos);

fn smoke_abi_pathx_fchmod_neg() -> TestResult {
    with_setup(|| {
        // Linux fchmod(2) on a bad fd returns -EBADF.
        match call(Syscall::Fchmod.raw(), a1(7373, 0o644)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmod_neg);

// ── fchown (fd, uid, gid) → 0 / -EBADF ─────────────────────────────

fn smoke_abi_pathx_fchown_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let fd = open_fd(b"/p2/f\0")?;
        match call(Syscall::Fchown.raw(), a2(fd as u64, 1000, 1001)) {
            Some(0) if file_owners("/p2/f") == Some((1000, 1001)) => Ok(()),
            _ => Err("fchown(valid fd) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchown_pos);

fn smoke_abi_pathx_fchown_neg() -> TestResult {
    with_setup(|| match call(Syscall::Fchown.raw(), a2(7474, 0, 0)) {
        Some(v) if v == EBADF => Ok(()),
        _ => Err("expected -EBADF"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchown_neg);

// ── fchmodat (dirfd, NUL-term path, mode) → 0 / -1 ─────────────────

fn smoke_abi_pathx_fchmodat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchmodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o2754, 0),
        ) {
            Some(0) if file_perms("/p2/f") == Some(0o2754) => Ok(()),
            _ => Err("fchmodat(existing) did not preserve special mode bits"),
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

fn smoke_abi_pathx_fchmodat_relative_dirfd_and_legacy_flags() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let dir = b"/p2\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("opening fchmodat parent failed"),
        };
        let name = b"f\0";
        // arg3 is outside legacy fchmodat's ABI. A stale nonzero register must
        // not be interpreted as fchmodat2 flags.
        let args = a3(dfd, name.as_ptr() as u64, 0o4750, u64::MAX);
        if call(Syscall::Fchmodat.raw(), args) != Some(0) || file_perms("/p2/f") != Some(0o4750) {
            return Err("legacy fchmodat did not anchor at dirfd or ignored arg3 incorrectly");
        }
        if call(
            Syscall::Fchmodat2.raw(),
            a3(dfd, name.as_ptr() as u64, 0o2750, 0),
        ) != Some(0)
            || file_perms("/p2/f") != Some(0o2750)
        {
            return Err("fchmodat2 did not resolve a relative path through dirfd");
        }
        if call(
            Syscall::Fchmodat.raw(),
            a3((-101i64) as u64, name.as_ptr() as u64, 0o600, 0),
        ) != Some(EBADF)
        {
            return Err("fchmodat(relative, invalid negative dirfd) must return EBADF");
        }
        let file_fd = open_fd(b"/p2/f\0")?;
        if call(
            Syscall::Fchmodat.raw(),
            a3(file_fd as u64, name.as_ptr() as u64, 0o600, 0),
        ) != Some(ENOTDIR)
        {
            return Err("fchmodat(relative, non-directory fd) must return ENOTDIR");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_fchmodat_relative_dirfd_and_legacy_flags
);

// ── fchmodat2 (dirfd, NUL-term path, mode, flags) → 0 / -1 ─────────

fn smoke_abi_pathx_fchmodat2_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchmodat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o1754, 0),
        ) {
            Some(0) if file_perms("/p2/f") == Some(0o1754) => Ok(()),
            _ => Err("fchmodat2(existing) did not preserve special mode bits"),
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

fn smoke_abi_pathx_fchmodat2_rejects_unknown_flags() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchmodat2.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o600, 0x4000_0000),
        ) {
            Some(EINVAL) if file_perms("/p2/f") != Some(0o600) => Ok(()),
            _ => Err("fchmodat2 accepted unknown flags"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_fchmodat2_rejects_unknown_flags
);

// systemd-udevd opens a device O_PATH and applies its final rule metadata via
// fchmodat2(fd, "", mode, AT_EMPTY_PATH). The empty path names the fd itself;
// it must never fall through cwd resolution and chmod the caller's directory.
fn smoke_abi_pathx_fchmodat2_empty_path_fd() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        const O_PATH: u64 = 0o10000000;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let path = b"/p2/f\0";
        let fd = match call_open(path.as_ptr() as u64, O_PATH) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(O_PATH) for fchmodat2 failed"),
        };
        let before_dir = dir_perms("/p2");
        let empty = b"\0";
        match call(
            Syscall::Fchmodat2.raw(),
            a3(fd, empty.as_ptr() as u64, 0o640, AT_EMPTY_PATH),
        ) {
            Some(0) if file_perms("/p2/f") == Some(0o640) && dir_perms("/p2") == before_dir => {
                Ok(())
            }
            _ => Err("fchmodat2(AT_EMPTY_PATH) did not update only the fd node"),
        }?;
        let dir = b"/p2\0";
        if call(Syscall::Chdir.raw(), a0(dir.as_ptr() as u64)) != Some(0)
            || call(
                Syscall::Fchmodat2.raw(),
                a3(AT_FDCWD, empty.as_ptr() as u64, 0o1701, AT_EMPTY_PATH),
            ) != Some(0)
            || dir_perms("/p2") != Some(0o1701)
        {
            return Err("fchmodat2(AT_EMPTY_PATH|AT_FDCWD) did not name cwd");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchmodat2_empty_path_fd);

// ── fchownat (dirfd, NUL-term path, uid, gid, flags) → 0 / -1 ──────
//
fn smoke_abi_pathx_fchownat_pos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        match call(
            Syscall::Fchownat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 1000, 1001),
        ) {
            Some(0) if file_owners("/p2/f") == Some((1000, 1001)) => Ok(()),
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

fn smoke_abi_pathx_fchownat_empty_path_requires_flag() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        const O_PATH: u64 = 0o10000000;
        const AT_EMPTY_PATH: u64 = 0x1000;
        let path = b"/p2/f\0";
        let fd = match call_open(path.as_ptr() as u64, O_PATH) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(O_PATH) for fchownat failed"),
        };
        let empty = b"\0";
        let with_flag = SyscallArgs {
            arg0: fd,
            arg1: empty.as_ptr() as u64,
            arg2: 1234,
            arg3: 5678,
            arg4: AT_EMPTY_PATH,
            arg5: 0,
        };
        if call(Syscall::Fchownat.raw(), with_flag) != Some(0)
            || file_owners("/p2/f") != Some((1234, 5678))
        {
            return Err("fchownat(AT_EMPTY_PATH) did not update the fd node");
        }
        let without_flag = SyscallArgs {
            arg4: 0,
            arg2: 2222,
            arg3: 3333,
            ..with_flag
        };
        if call(Syscall::Fchownat.raw(), without_flag) != Some(ENOENT)
            || file_owners("/p2/f") != Some((1234, 5678))
        {
            return Err("fchownat empty path without AT_EMPTY_PATH mutated the fd node");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_fchownat_empty_path_requires_flag
);

fn smoke_abi_pathx_fchownat_directory_persists() -> TestResult {
    with_memfs("/p2", "p2", &[], || {
        let dir = b"/p2/runtime-dir\0";
        if call_mkdir(dir.as_ptr() as u64, 0o700) != Some(0) {
            return Err("mkdir(runtime-dir) failed");
        }
        match call(
            Syscall::Fchownat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 1000, 1000),
        ) {
            Some(0) if dir_owners("/p2/runtime-dir") == Some((1000, 1000)) => Ok(()),
            _ => Err("fchownat(directory) did not persist ownership"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_fchownat_directory_persists);

fn smoke_abi_pathx_fchownat_relative_and_minus_one_fields() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let dir = b"/p2\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("opening fchownat parent failed"),
        };
        let name = b"f\0";
        if call(
            Syscall::Fchownat.raw(),
            a3(dfd, name.as_ptr() as u64, 1234, 5678),
        ) != Some(0)
            || file_owners("/p2/f") != Some((1234, 5678))
        {
            return Err("fchownat relative dirfd did not update owners");
        }
        if call(
            Syscall::Fchownat.raw(),
            a3(dfd, name.as_ptr() as u64, u32::MAX as u64, 6789),
        ) != Some(0)
            || file_owners("/p2/f") != Some((1234, 6789))
        {
            return Err("fchownat uid=-1 did not preserve uid");
        }
        let unknown_flags = SyscallArgs {
            arg0: dfd,
            arg1: name.as_ptr() as u64,
            arg2: 1,
            arg3: 2,
            arg4: 0x4000_0000,
            arg5: 0,
        };
        if call(Syscall::Fchownat.raw(), unknown_flags) != Some(EINVAL) {
            return Err("fchownat accepted unknown flags");
        }
        if call(
            Syscall::Fchownat.raw(),
            a3((-101i64) as u64, name.as_ptr() as u64, 1, 2),
        ) != Some(EBADF)
        {
            return Err("fchownat(relative, invalid negative dirfd) must return EBADF");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_fchownat_relative_and_minus_one_fields
);

fn smoke_abi_pathx_chown_follow_and_lchown_nofollow() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let target = b"f\0";
        let link = b"/p2/sl-meta\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) != Some(0) {
            return Err("metadata symlink creation failed");
        }
        if call_chmod(link.as_ptr() as u64, 0o6755) != Some(0)
            || file_perms("/p2/f") != Some(0o6755)
            || call(
                Syscall::Fchmodat2.raw(),
                a3(AT_FDCWD, link.as_ptr() as u64, 0o600, 0x100),
            ) != Some(-95)
            || file_perms("/p2/f") != Some(0o6755)
            || call(Syscall::Chown.raw(), a2(link.as_ptr() as u64, 1000, 1001)) != Some(0)
            || file_owners("/p2/f") != Some((1000, 1001))
            || file_perms("/p2/f") != Some(0o755)
        {
            return Err("chown did not follow symlink and clear privilege bits");
        }
        if call(Syscall::Lchown.raw(), a2(link.as_ptr() as u64, 2000, 2001)) != Some(0)
            || lstat_owners(link) != Some((2000, 2001))
            || file_owners("/p2/f") != Some((1000, 1001))
        {
            return Err("lchown did not update only the symlink inode");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_chown_follow_and_lchown_nofollow
);

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

// systemd-journald creates its runtime journal, enumerates the containing
// directory, then describes each entry through `newfstatat(dirfd, name,
// AT_SYMLINK_NOFOLLOW)`. The lookup must be relative to the real directory
// fd, rather than to the task cwd.
fn smoke_abi_pathx_newfstatat_relative_dirfd() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let dir = b"/p2\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("opening the newfstatat parent directory failed"),
        };
        let name = b"f\0";
        let mut sb = [0u8; 256];
        match call(
            Syscall::Newfstatat.raw(),
            a3(dfd, name.as_ptr() as u64, sb.as_mut_ptr() as u64, 0x100),
        ) {
            Some(0) => Ok(()),
            _ => Err("newfstatat(dirfd, relative path) should find the directory entry"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_newfstatat_relative_dirfd);

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

fn smoke_abi_pathx_newfstatat_exact_errnos() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let path = b"/p2/f\0";
        let empty = b"\0";
        let mut sb = [0u8; 256];

        if call(
            Syscall::Newfstatat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) != Some(EFAULT)
        {
            return Err("newfstatat with a null stat buffer must return -EFAULT");
        }
        if call(
            Syscall::Newfstatat.raw(),
            a3(AT_FDCWD, empty.as_ptr() as u64, sb.as_mut_ptr() as u64, 0),
        ) != Some(ENOENT)
        {
            return Err("newfstatat with an empty path and no AT_EMPTY_PATH must return -ENOENT");
        }
        if call(
            Syscall::Newfstatat.raw(),
            a3(
                AT_FDCWD,
                path.as_ptr() as u64,
                sb.as_mut_ptr() as u64,
                1u64 << 31,
            ),
        ) != Some(EINVAL)
        {
            return Err("newfstatat with unknown flags must return -EINVAL");
        }

        let file_fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("newfstatat errno test could not open its regular-file dirfd"),
        };
        let relative = b"child\0";
        match call(
            Syscall::Newfstatat.raw(),
            a3(file_fd, relative.as_ptr() as u64, sb.as_mut_ptr() as u64, 0),
        ) {
            Some(ENOTDIR) => Ok(()),
            _ => Err("newfstatat relative to a non-directory fd must return -ENOTDIR"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_newfstatat_exact_errnos);

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

// systemd's mount units chase the parent with openat2(O_PATH|O_DIRECTORY)
// then create the final mount point with mkdirat(parent_fd, leaf, …).  The
// O_PATH fd must retain its backing pathname so the relative mkdirat does not
// degrade to EBADF.
fn smoke_abi_pathx_openat2_opath_dirfd_mkdirat() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        const O_PATH: u64 = 0o10000000;
        const O_DIRECTORY: u64 = 0o200000;
        let parent = b"/p2\0";
        let mut how = [0u8; 24];
        how[..8].copy_from_slice(&(O_PATH | O_DIRECTORY).to_ne_bytes());
        let dfd = match call(
            Syscall::Openat2.raw(),
            a3(AT_FDCWD, parent.as_ptr() as u64, how.as_ptr() as u64, 24),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("openat2(O_PATH directory) did not return an fd"),
        };
        let leaf = b"connections\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(dfd, leaf.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdirat(openat2 O_PATH fd, leaf) should create the mount point");
        }
        let created = b"/p2/connections\0";
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, created.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("mkdirat under the O_PATH fd created at the wrong path"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_openat2_opath_dirfd_mkdirat);

// `openat2` has the same dirfd-relative lookup contract as `openat`.  The
// systemd mount-unit path walker obtains a parent directory this way before
// calling mkdirat for the final mount-point component.
fn smoke_abi_pathx_openat2_relative_dirfd() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let parent = b"/p2\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, parent.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("openat(parent) did not return a directory fd"),
        };
        let child = b"f\0";
        let how = [0u8; 24]; // O_RDONLY, mode=0, resolve=0.
        match call(
            Syscall::Openat2.raw(),
            a3(dfd, child.as_ptr() as u64, how.as_ptr() as u64, 24),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("openat2(dirfd, relative path) should resolve below dirfd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_openat2_relative_dirfd);

// All descriptor duplication APIs preserve the identity of a directory fd.
// systemd passes such duplicated O_PATH fds to mkdirat() while preparing
// mount points; losing this identity turns a live descriptor into EBADF.
fn smoke_abi_pathx_duplicated_dirfd_preserves_path() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let parent = b"/p2\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, parent.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("openat(parent) did not return a directory fd"),
        };
        const F_DUPFD: u64 = 0;
        let duplicates = [
            call(Syscall::Dup.raw(), a2(fd, 0, 0)),
            call(Syscall::Dup2.raw(), a2(fd, 110, 0)),
            call(Syscall::Dup3.raw(), a3(fd, 111, 0, 0)),
            call(Syscall::Fcntl.raw(), a2(fd, F_DUPFD, 112)),
        ];
        for (index, duplicate) in duplicates.into_iter().enumerate() {
            let duplicate = match duplicate {
                Some(new_fd) if new_fd >= 0 => new_fd as u64,
                _ => return Err("descriptor duplication did not return a usable fd"),
            };
            let leaf = match index {
                0 => b"dup\0".as_slice(),
                1 => b"dup2\0".as_slice(),
                2 => b"dup3\0".as_slice(),
                _ => b"fcntl\0".as_slice(),
            };
            if call(
                Syscall::Mkdirat.raw(),
                a3(duplicate, leaf.as_ptr() as u64, 0o755, 0),
            ) != Some(0)
            {
                return Err("mkdirat through a duplicated directory fd should succeed");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_duplicated_dirfd_preserves_path
);

// Linux open_tree without OPEN_TREE_CLONE returns an O_PATH fd to the named
// tree, not a detached mount object. systemd uses that fd as the parent for
// mkdirat while it creates an automount-triggering mount point.
fn smoke_abi_pathx_open_tree_path_fd_mkdirat() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        const OPEN_TREE_CLOEXEC: u64 = 0o2000000;
        let parent = b"/p2\0";
        let dfd = match call(
            Syscall::OpenTree.raw(),
            a3(AT_FDCWD, parent.as_ptr() as u64, OPEN_TREE_CLOEXEC, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open_tree(path) did not return an O_PATH fd"),
        };
        let leaf = b"tree-child\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(dfd, leaf.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdirat(open_tree path fd, leaf) should create the child");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_open_tree_path_fd_mkdirat);

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

// ── sd-device chase() of a DRM /sys/dev/char/226:0 symlink ───────────
//
// systemd-logind resolves each seat-master DRM device by devnum:
// `sd_device_new_from_devnum("226:0")` → `device_set_syspath(verify=true)` →
// `chase("/sys/dev/char/226:0")`. `chase()` walks the path one component at a
// time using the SYSCALL sequence a real sd-device uses:
//   openat(parent_fd, "226:0", O_PATH|O_NOFOLLOW|O_CLOEXEC)  (open the link)
//   fstat / newfstatat(fd, "", AT_EMPTY_PATH)                (S_ISLNK?)
//   readlinkat(parent_fd, "226:0", buf)                      (target)
//
// A real boot logged `sd-device: Failed to get target of
// '/sys/dev/char/226:0': Invalid argument` (EINVAL out of the readlink step),
// so logind gave up on the GPU and seat0 never became graphical. This drives
// that exact chase sequence against a sysfs symlink registered the way
// `drivers/gpu/.../drm_sysfs_bridge.rs::char_dev_link` builds it: a `226:0`
// symlink → `../../devices/platform/narf-drm/card0`, plus the real target
// node so a FULL chase resolves.
//
// Whichever step returns the wrong thing (fd<0, non-S_IFLNK, EINVAL, wrong
// target) IS the bug and is named in that step's assertion.
fn smoke_abi_pathx_sysfs_drm_char_symlink_chase() -> TestResult {
    use narf_filesystem::sysfs::{get_or_create_child, get_root, kobject_add_attr};

    const O_PATH: u64 = 0o10000000;
    const O_NOFOLLOW: u64 = 0o400000;
    const O_CLOEXEC: u64 = 0o2000000;
    const O_DIRECTORY: u64 = 0o200000;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const S_IFMT: u32 = 0o170000;
    const S_IFLNK: u32 = 0o120000;

    const LINK_PATH: &[u8] = b"/sys/dev/char/226:0\0";
    const LINK_TARGET: &str = "../../devices/platform/narf-drm/card0";

    with_setup(|| {
        // Build the DRM char-dev symlink exactly as `char_dev_link` does, plus
        // the real `card0` target node carrying a `uevent` attr so a full chase
        // (symlink-followed) reaches a live node. get_root() is the GLOBAL
        // sysfs kobject singleton, so this is additive and idempotent.
        let root = get_root();
        let devices = get_or_create_child(&root, "devices");
        let platform = get_or_create_child(&devices, "platform");
        let narf_drm = get_or_create_child(&platform, "narf-drm");
        let card0 = get_or_create_child(&narf_drm, "card0");
        kobject_add_attr(&card0, "uevent", || {
            alloc::string::String::from(
                "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n",
            )
        });
        let dev = get_or_create_child(&root, "dev");
        let dev_char = get_or_create_child(&dev, "char");
        dev_char.add_symlink("226:0", LINK_TARGET);

        // 1) openat(O_PATH|O_NOFOLLOW|O_CLOEXEC) — open the symlink NODE itself.
        let fd = match call(
            Syscall::Openat.raw(),
            a3(
                AT_FDCWD,
                LINK_PATH.as_ptr() as u64,
                O_PATH | O_NOFOLLOW | O_CLOEXEC,
                0,
            ),
        ) {
            Some(v) if v >= 0 => v as u64,
            Some(-2) => {
                return Err(
                    "openat(O_PATH|O_NOFOLLOW /sys/dev/char/226:0) returned ENOENT — \
                            the sysfs DRM char symlink is unreachable through the syscall path",
                )
            }
            _ => {
                return Err("openat(O_PATH|O_NOFOLLOW /sys/dev/char/226:0) failed — \
                            chase() cannot even open the DRM char symlink")
            }
        };

        // 2) newfstatat(fd, "", AT_EMPTY_PATH) — chase() checks S_ISLNK.
        let mut st = [0u8; 144];
        let empty = b"\0";
        let r = call(
            Syscall::Newfstatat.raw(),
            a3(
                fd,
                empty.as_ptr() as u64,
                st.as_mut_ptr() as u64,
                AT_EMPTY_PATH,
            ),
        );
        let _ = call(Syscall::Close.raw(), a0(fd));
        if r != Some(0) {
            return Err("newfstatat(O_PATH fd, AT_EMPTY_PATH) failed — \
                        chase() cannot fstat the opened DRM char link");
        }
        // st_mode is a u32 at byte offset 24 of the 144-byte struct stat.
        let mode = u32::from_ne_bytes([st[24], st[25], st[26], st[27]]);
        if mode & S_IFMT != S_IFLNK {
            return Err("fstat of the O_PATH|O_NOFOLLOW fd is not S_IFLNK — \
                        chase() sees the DRM char node as a non-symlink");
        }

        // 3) readlink(path) — chase() reads the target. EINVAL here is the exact
        //    real-boot failure ("Failed to get target ...: Invalid argument").
        let mut buf = [0u8; 128];
        match call_readlink(
            LINK_PATH.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        ) {
            Some(len) if len >= 0 => {
                if &buf[..len as usize] != LINK_TARGET.as_bytes() {
                    return Err("readlink(/sys/dev/char/226:0) returned the wrong target bytes");
                }
            }
            Some(-22) => {
                return Err("readlink(/sys/dev/char/226:0) returned EINVAL — THE BUG: \
                            chase() treats the registered DRM char symlink as a non-symlink")
            }
            _ => {
                return Err("readlink(/sys/dev/char/226:0) failed (non-EINVAL) — \
                            chase() cannot read the DRM char symlink target")
            }
        }

        // 4) readlinkat(parent_dirfd, "226:0", buf) — chase() actually reads the
        //    leaf RELATIVE to the parent-directory fd it holds, not absolutely.
        let parent = b"/sys/dev/char\0";
        let pfd = match call(
            Syscall::Openat.raw(),
            a3(
                AT_FDCWD,
                parent.as_ptr() as u64,
                O_PATH | O_DIRECTORY | O_CLOEXEC,
                0,
            ),
        ) {
            Some(v) if v >= 0 => v as u64,
            _ => {
                return Err("openat(O_PATH|O_DIRECTORY /sys/dev/char) failed — \
                            chase() has no parent dirfd to readlinkat against")
            }
        };
        let leaf = b"226:0\0";
        let mut buf2 = [0u8; 128];
        let rn = call(
            Syscall::Readlinkat.raw(),
            a3(
                pfd,
                leaf.as_ptr() as u64,
                buf2.as_mut_ptr() as u64,
                buf2.len() as u64,
            ),
        );
        let _ = call(Syscall::Close.raw(), a0(pfd));
        match rn {
            Some(len) if len >= 0 && &buf2[..len as usize] == LINK_TARGET.as_bytes() => {}
            Some(-22) => {
                return Err("readlinkat(parent_fd, \"226:0\") returned EINVAL — \
                            chase() cannot resolve the leaf against its parent dirfd")
            }
            _ => return Err("readlinkat(parent_fd, \"226:0\") did not return the DRM card target"),
        }

        // 5) Full chase outcome: following the symlink reaches the real card0
        //    node and its `uevent` is statable — this is what lets logind bind
        //    the seat master and mark seat0 graphical.
        let mut st2 = [0u8; 144];
        let uevent = b"/sys/dev/char/226:0/uevent\0";
        if call_stat(uevent.as_ptr() as u64, st2.as_mut_ptr() as u64) != Some(0) {
            return Err(
                "stat(/sys/dev/char/226:0/uevent) failed — the DRM char symlink \
                        does not chase through to the real card node",
            );
        }

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_pathx_sysfs_drm_char_symlink_chase);

// ── sd-device chase() of /sys/dev/char/226:0 from a PRIVATE mount ns ──
//
// The isolated chase above resolves correctly, so if logind's real boot
// failure is environmental the remaining suspect is the mount namespace:
// logind runs `PrivateMounts=yes`, so `chase()` resolves through the task's
// `MountNamespace`, not the global registry. `open`/`openat` go through
// `current_resolve_absolute()` (namespace-aware, falls back to the global
// registry), but `readlink`/`readlinkat` resolve via
// `registry().resolve_absolute()` directly — an asymmetry that already bit
// the directory-mutation syscalls (see
// `smoke_abi_fsx2_rename_resolves_in_private_mount_namespace`).
//
// This drives the SAME chase (openat O_PATH|O_NOFOLLOW → fstat S_ISLNK →
// readlinkat against the parent dirfd → readlink) from inside a private
// mount namespace and asserts the readlink still returns the DRM card
// target. If it reports EINVAL here while the isolated variant passed, the
// namespace path is the bug.
fn smoke_abi_pathx_sysfs_drm_char_chase_private_mount_ns() -> TestResult {
    use narf_filesystem::sysfs::{get_or_create_child, get_root, kobject_add_attr};

    const O_PATH: u64 = 0o10000000;
    const O_NOFOLLOW: u64 = 0o400000;
    const O_CLOEXEC: u64 = 0o2000000;
    const O_DIRECTORY: u64 = 0o200000;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const S_IFMT: u32 = 0o170000;
    const S_IFLNK: u32 = 0o120000;
    const CLONE_NEWNS: u64 = 0x0002_0000;

    const LINK_PATH: &[u8] = b"/sys/dev/char/226:0\0";
    const LINK_TARGET: &str = "../../devices/platform/narf-drm/card0";

    with_setup(|| {
        // Register the DRM char symlink + its target BEFORE entering the
        // private namespace, mirroring boot order (the DRM sysfs projection is
        // built at Stage::Late, well before logind starts).
        let root = get_root();
        let devices = get_or_create_child(&root, "devices");
        let platform = get_or_create_child(&devices, "platform");
        let narf_drm = get_or_create_child(&platform, "narf-drm");
        let card0 = get_or_create_child(&narf_drm, "card0");
        kobject_add_attr(&card0, "uevent", || {
            alloc::string::String::from(
                "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n",
            )
        });
        let dev = get_or_create_child(&root, "dev");
        let dev_char = get_or_create_child(&dev, "char");
        dev_char.add_symlink("226:0", LINK_TARGET);

        let result = (|| {
            // logind's PrivateMounts=yes: its own private mount namespace.
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            if crate::handlers::current_mount_namespace().is_none() {
                return Err("unshare did not install a mount namespace");
            }

            // 1) openat(O_PATH|O_NOFOLLOW) in the private namespace.
            let fd = match call(
                Syscall::Openat.raw(),
                a3(
                    AT_FDCWD,
                    LINK_PATH.as_ptr() as u64,
                    O_PATH | O_NOFOLLOW | O_CLOEXEC,
                    0,
                ),
            ) {
                Some(v) if v >= 0 => v as u64,
                Some(-2) => {
                    return Err("openat(/sys/dev/char/226:0) ENOENT in a private mount \
                                namespace — the sysfs symlink is invisible through the ns")
                }
                _ => {
                    return Err(
                        "openat(O_PATH|O_NOFOLLOW /sys/dev/char/226:0) failed in a private ns",
                    )
                }
            };

            // 2) fstat → S_ISLNK.
            let mut st = [0u8; 144];
            let empty = b"\0";
            let r = call(
                Syscall::Newfstatat.raw(),
                a3(
                    fd,
                    empty.as_ptr() as u64,
                    st.as_mut_ptr() as u64,
                    AT_EMPTY_PATH,
                ),
            );
            let _ = call(Syscall::Close.raw(), a0(fd));
            if r != Some(0) {
                return Err("newfstatat(fd, AT_EMPTY_PATH) failed in a private ns");
            }
            let mode = u32::from_ne_bytes([st[24], st[25], st[26], st[27]]);
            if mode & S_IFMT != S_IFLNK {
                return Err("fstat of the O_PATH fd is not S_IFLNK in a private mount namespace");
            }

            // 3) readlinkat against the held parent dirfd — the shape chase()
            //    uses. EINVAL here while the isolated variant passed pins the
            //    bug on the mount-namespace resolution asymmetry.
            let parent = b"/sys/dev/char\0";
            let pfd = match call(
                Syscall::Openat.raw(),
                a3(
                    AT_FDCWD,
                    parent.as_ptr() as u64,
                    O_PATH | O_DIRECTORY | O_CLOEXEC,
                    0,
                ),
            ) {
                Some(v) if v >= 0 => v as u64,
                _ => return Err("openat(/sys/dev/char) failed in a private ns"),
            };
            let leaf = b"226:0\0";
            let mut buf = [0u8; 128];
            let rn = call(
                Syscall::Readlinkat.raw(),
                a3(
                    pfd,
                    leaf.as_ptr() as u64,
                    buf.as_mut_ptr() as u64,
                    buf.len() as u64,
                ),
            );
            let _ = call(Syscall::Close.raw(), a0(pfd));
            match rn {
                Some(len) if len >= 0 && &buf[..len as usize] == LINK_TARGET.as_bytes() => {}
                Some(-22) => {
                    return Err(
                        "readlinkat(parent_fd, \"226:0\") returned EINVAL in a private \
                                mount namespace — chase() cannot read the DRM char symlink target",
                    )
                }
                _ => return Err("readlinkat(parent_fd, \"226:0\") wrong result in a private ns"),
            }

            // 4) Absolute readlink through the namespace resolver too.
            let mut buf2 = [0u8; 128];
            match call_readlink(
                LINK_PATH.as_ptr() as u64,
                buf2.as_mut_ptr() as u64,
                buf2.len() as u64,
            ) {
                Some(len) if len >= 0 && &buf2[..len as usize] == LINK_TARGET.as_bytes() => {}
                Some(-22) => {
                    return Err("readlink(/sys/dev/char/226:0) returned EINVAL in a private ns")
                }
                _ => return Err("readlink(/sys/dev/char/226:0) wrong result in a private ns"),
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_sysfs_drm_char_chase_private_mount_ns
);

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

// The exact shape `sd-device` uses to publish a udev database entry:
// write `<dir>/.#<id><random>`, then RENAME_NOREPLACE it onto `<dir>/<id>`.
// The names carry `.`, `#`, `+` and `:`, none of which are special to
// rename(2) but all of which are unusual enough to be worth pinning.
//
// The errno matters as much as the success. systemd's `rename_noreplace()`
// falls back to a racy link/unlink dance ONLY on EINVAL, ENOSYS or ENOTTY;
// any other error is returned to the caller verbatim. So a renameat2 that
// reports ENOENT for a rename it simply did not perform makes udev give up
// with "Failed to rename temporary database file ... No such file or
// directory" and never write `/run/udev/data/<id>` at all — which is exactly
// the failure the udev seat gate reports.
fn smoke_abi_pathx_renameat2_udev_db_publish_shape() -> TestResult {
    const RENAME_NOREPLACE: u64 = 1;
    const TMP: &str = ".#+pci:0000:00:02.037385736e4f26399";
    const FINAL: &str = "+pci:0000:00:02.0";
    with_memfs(
        "/p3",
        "p3",
        &[(TMP, b"E:ID_PATH=pci-0000:00:02.0\n")],
        || {
            let old = b"/p3/.#+pci:0000:00:02.037385736e4f26399\0";
            let new = b"/p3/+pci:0000:00:02.0\0";
            let r = call_raw(
                Syscall::Renameat2.raw(),
                SyscallArgs {
                    arg0: AT_FDCWD,
                    arg1: old.as_ptr() as u64,
                    arg2: AT_FDCWD,
                    arg3: new.as_ptr() as u64,
                    arg4: RENAME_NOREPLACE,
                    arg5: 0,
                },
            );
            if r.status != SyscallReturn::OK {
                return Err("renameat2 of a udev db temp file returned a non-OK NARF status");
            }
            match r.value as i64 {
            0 => {}
            -2 => {
                return Err(
                    "renameat2(RENAME_NOREPLACE) reported ENOENT — systemd's rename_noreplace only falls back on EINVAL/ENOSYS/ENOTTY, so udev gives up here",
                )
            }
            _ => return Err("renameat2 of a udev db temp file did not succeed"),
        }
            // The published entry must be readable under its final name, and the
            // temporary must be gone — a rename that reports success without
            // moving anything leaves udev reading a stale database forever.
            let mut buf = [0u8; 64];
            let final_path = b"/p3/+pci:0000:00:02.0\0";
            let fd = call_open(final_path.as_ptr() as u64, 0).unwrap_or(-1);
            if fd < 0 {
                return Err("renamed udev db entry is not openable under its final name");
            }
            let n = call(
                Syscall::Read.raw(),
                a2(fd as u64, buf.as_mut_ptr() as u64, 64),
            );
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
            if n.unwrap_or(-1) <= 0 {
                return Err("renamed udev db entry has no contents");
            }
            let tmp_path = b"/p3/.#+pci:0000:00:02.037385736e4f26399\0";
            if call_open(tmp_path.as_ptr() as u64, 0).unwrap_or(-1) >= 0 {
                return Err("the temporary udev db file still exists after a successful rename");
            }
            let _ = (TMP, FINAL);
            Ok(())
        },
    )
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_renameat2_udev_db_publish_shape
);

/// The same publish, but in a NESTED directory created at runtime — which is
/// what `/run/udev/data/` actually is: systemd mounts /run, then udev
/// `mkdir_parents()` its way to `data/`. The mount-root case above resolves
/// its parent trivially; this one exercises a real multi-component walk to
/// the parent before the rename.
fn smoke_abi_pathx_renameat2_udev_db_publish_nested() -> TestResult {
    const RENAME_NOREPLACE: u64 = 1;
    with_memfs("/p4", "p4", &[], || {
        // /p4/udev/data, built a component at a time like mkdir_parents.
        for dir in [b"/p4/udev\0".as_ref(), b"/p4/udev/data\0".as_ref()] {
            let r = call(Syscall::Mkdir.raw(), a1(dir.as_ptr() as u64, 0o755)).unwrap_or(-1);
            if r != 0 && r != -17 {
                return Err("mkdir of a udev database parent directory failed");
            }
        }
        let tmp = b"/p4/udev/data/.#c226:0e270627d7a3faea1\0";
        let fin = b"/p4/udev/data/c226:0\0";
        // Create the temp entry the way sd-device does (O_CREAT|O_EXCL).
        let fd = call_open(tmp.as_ptr() as u64, 0o100 | 0o200 | 0o1).unwrap_or(-1);
        if fd < 0 {
            return Err("could not create the temporary udev db file in a nested directory");
        }
        let payload = b"E:ID_FOR_SEAT=drm-pci\n";
        let _ = call(
            Syscall::Write.raw(),
            a2(fd as u64, payload.as_ptr() as u64, payload.len() as u64),
        );
        let _ = call(Syscall::Close.raw(), a0(fd as u64));

        let r = call_raw(
            Syscall::Renameat2.raw(),
            SyscallArgs {
                arg0: AT_FDCWD,
                arg1: tmp.as_ptr() as u64,
                arg2: AT_FDCWD,
                arg3: fin.as_ptr() as u64,
                arg4: RENAME_NOREPLACE,
                arg5: 0,
            },
        );
        if r.status != SyscallReturn::OK {
            return Err("nested renameat2 returned a non-OK NARF status");
        }
        match r.value as i64 {
            0 => {}
            -2 => {
                return Err(
                    "nested renameat2(RENAME_NOREPLACE) reported ENOENT — this is the udev database publish failing",
                )
            }
            _ => return Err("nested renameat2 of a udev db temp file did not succeed"),
        }
        if call_open(fin.as_ptr() as u64, 0).unwrap_or(-1) < 0 {
            return Err("nested udev db entry is not openable under its final name");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_renameat2_udev_db_publish_nested
);

/// Renaming a file that EXISTS must never report ENOENT. `/proc` has no
/// rename support, so the honest answer is EPERM/EINVAL/EXDEV/EACCES — the
/// errno family that says "this filesystem will not do that", not the one
/// that says "the path you named is not there".
///
/// The distinction is load-bearing rather than pedantic. systemd's
/// `rename_noreplace()` falls back to a link/unlink dance only on EINVAL,
/// ENOSYS or ENOTTY, and callers throughout systemd treat ENOENT as "the
/// source vanished, nothing to do". A rename handler that funnels every
/// failure — including an unimplemented `DirOps::rename` — into ENOENT
/// therefore turns a recoverable "unsupported" into a silent, permanent
/// give-up. That is the shape of the udev database publish failure:
/// "Failed to rename temporary database file ... No such file or directory"
/// for a temporary file that was created successfully moments earlier.
fn smoke_abi_pathx_rename_unsupported_is_not_enoent() -> TestResult {
    with_setup(|| {
        // A path that definitely exists and definitely cannot be renamed.
        let old = b"/proc/self/stat\0";
        let new = b"/proc/self/stat-renamed\0";
        // Confirm the source exists, so an ENOENT below cannot be honest.
        let fd = call_open(old.as_ptr() as u64, 0).unwrap_or(-1);
        if fd < 0 {
            // No procfs in this configuration — nothing to assert against.
            return Ok(());
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));

        let r = call_raw(
            Syscall::Renameat2.raw(),
            SyscallArgs {
                arg0: AT_FDCWD,
                arg1: old.as_ptr() as u64,
                arg2: AT_FDCWD,
                arg3: new.as_ptr() as u64,
                arg4: 0,
                arg5: 0,
            },
        );
        if r.status != SyscallReturn::OK {
            return Err("renameat2 on an unrenameable file returned a non-OK NARF status");
        }
        match r.value as i64 {
            0 => Err("renameat2 claimed to rename a /proc entry"),
            -2 => Err(
                "renameat2 reported ENOENT for a file that exists — 'unsupported' must not be laundered into 'no such file' (systemd's rename_noreplace only falls back on EINVAL/ENOSYS/ENOTTY)",
            ),
            _ => Ok(()),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_rename_unsupported_is_not_enoent
);

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

// ── quotactl(cmd, special, id, addr) — Linux disk-quota control ─────
//
// cmd = (subcmd << 8) | type. `if_dqblk` limits are in 1 KiB quota blocks;
// tmpfs blocks are 4 KiB, so a 2-page limit round-trips as bhardlimit = 8.

const Q_GETQUOTA: u64 = 0x0080_0007;
const Q_SETQUOTA: u64 = 0x0080_0008;
const Q_GETINFO: u64 = 0x0080_0005;
const Q_SETINFO: u64 = 0x0080_0006;
const USRQUOTA: u64 = 0;

fn quota_cmd(subcmd: u64, type_: u64) -> u64 {
    (subcmd << 8) | type_
}

fn smoke_abi_quotactl_setquota_getquota_roundtrip() -> TestResult {
    with_tmpfs("/q", "usrquota,size=1M", || {
        let path = b"/q\0";
        let uid = 4242u64;
        const QIF_BLIMITS: u32 = 1;
        // if_dqblk: bhardlimit=8 (→ 2 pages), bsoftlimit=4 (→ 1 page).
        let mut dqblk = [0u8; 72];
        dqblk[0..8].copy_from_slice(&8u64.to_le_bytes());
        dqblk[8..16].copy_from_slice(&4u64.to_le_bytes());
        dqblk[64..68].copy_from_slice(&QIF_BLIMITS.to_le_bytes());
        if call(
            Syscall::Quotactl.raw(),
            a3(
                quota_cmd(Q_SETQUOTA, USRQUOTA),
                path.as_ptr() as u64,
                uid,
                dqblk.as_ptr() as u64,
            ),
        ) != Some(0)
        {
            return Err("Q_SETQUOTA should return 0");
        }
        // Read it back.
        let mut out = [0u8; 72];
        if call(
            Syscall::Quotactl.raw(),
            a3(
                quota_cmd(Q_GETQUOTA, USRQUOTA),
                path.as_ptr() as u64,
                uid,
                out.as_mut_ptr() as u64,
            ),
        ) != Some(0)
        {
            return Err("Q_GETQUOTA should return 0");
        }
        let bhard = u64::from_le_bytes(out[0..8].try_into().unwrap());
        let bsoft = u64::from_le_bytes(out[8..16].try_into().unwrap());
        if bhard != 8 || bsoft != 4 {
            return Err("Q_GETQUOTA did not round-trip the block limits");
        }
        // GETINFO / SETINFO round-trip the block grace period.
        let mut info = [0u8; 32];
        info[0..8].copy_from_slice(&86_400u64.to_le_bytes()); // bgrace = 1 day
        const IIF_BGRACE: u32 = 1;
        info[20..24].copy_from_slice(&IIF_BGRACE.to_le_bytes());
        if call(
            Syscall::Quotactl.raw(),
            a3(
                quota_cmd(Q_SETINFO, USRQUOTA),
                path.as_ptr() as u64,
                0,
                info.as_ptr() as u64,
            ),
        ) != Some(0)
        {
            return Err("Q_SETINFO should return 0");
        }
        let mut got = [0u8; 32];
        if call(
            Syscall::Quotactl.raw(),
            a3(
                quota_cmd(Q_GETINFO, USRQUOTA),
                path.as_ptr() as u64,
                0,
                got.as_mut_ptr() as u64,
            ),
        ) != Some(0)
        {
            return Err("Q_GETINFO should return 0");
        }
        if u64::from_le_bytes(got[0..8].try_into().unwrap()) != 86_400 {
            return Err("Q_GETINFO did not report the grace period set by Q_SETINFO");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_quotactl_setquota_getquota_roundtrip
);

fn smoke_abi_quotactl_rejects_bad_type_and_nonquota_fs() -> TestResult {
    // A bad quota type is EINVAL regardless of the mount.
    let bad_type = with_tmpfs("/q", "usrquota", || {
        let path = b"/q\0";
        let mut out = [0u8; 72];
        if call(
            Syscall::Quotactl.raw(),
            a3(
                quota_cmd(Q_GETQUOTA, 5), // type 5 is not USR/GRP
                path.as_ptr() as u64,
                0,
                out.as_mut_ptr() as u64,
            ),
        ) != Some(-22)
        {
            return Err("bad quota type should return -EINVAL");
        }
        Ok(())
    });
    if !matches!(bad_type, TestResult::Pass) {
        return bad_type;
    }
    // A non-tmpfs mount has no quota support: ESRCH.
    with_memfs("/m", "m", &[("f", b"x")], || {
        let path = b"/m\0";
        let mut out = [0u8; 72];
        if call(
            Syscall::Quotactl.raw(),
            a3(
                quota_cmd(Q_GETQUOTA, USRQUOTA),
                path.as_ptr() as u64,
                0,
                out.as_mut_ptr() as u64,
            ),
        ) != Some(-3)
        {
            return Err("quotactl on a non-quota fs should return -ESRCH");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_quotactl_rejects_bad_type_and_nonquota_fs
);

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

// chdir(2) follows its final symlink.  Fedora's XKB data uses exactly this
// layout (`/usr/share/X11/xkb -> ../xkeyboard-config-2`), so rejecting the
// link prevents Xwayland from loading any keyboard map during Plasma boot.
fn smoke_abi_pathx_chdir_follows_directory_symlink() -> TestResult {
    with_memfs("/p2", "p2", &[("f", b"hi")], || {
        let target_dir = b"/p2/xkeyboard-config-2\0";
        if call_mkdir(target_dir.as_ptr() as u64, 0o755) != Some(0) {
            return Err("mkdir for chdir symlink target failed");
        }

        let target = b"xkeyboard-config-2\0";
        let link = b"/p2/xkb\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) != Some(0) {
            return Err("directory symlink creation failed");
        }

        match call(Syscall::Chdir.raw(), a0(link.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("chdir must follow a symlink to a directory"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_pathx_chdir_follows_directory_symlink
);

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

#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_pathx_getdents_pos);

#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
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
