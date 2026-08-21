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

fn smoke_abi_path_openat_empty_is_enoent() -> TestResult {
    setup();
    // Kernel-test fixture: hands the syscall entry point kernel `.rodata` /
    // stack pointers as stand-in user buffers. See
    // `handlers::kernel_buffers_guard` and `with_setup`, which does the same
    // for the tests that use the closure form of this harness.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let path = b"\0";
    let result = match call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
    ) {
        Some(-2) => TestResult::Pass,
        _ => TestResult::Fail("openat with an empty pathname must return -ENOENT"),
    };
    teardown();
    result
}
kernel_test_in!("syscall_abi", smoke_abi_path_openat_empty_is_enoent);

// ── openat with a real directory fd (dirfd-relative resolution) ──
//
// sd-device's chase_symlinks walks a path one openat() per component against
// parent-directory fds; ignoring dirfd broke every udev/libudev device lookup.

fn smoke_abi_path_openat_dirfd_relative() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        // Open the mount directory as a directory fd.
        let dirp = b"/p\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dirp.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("opening /p as a directory fd failed"),
        };
        // openat(dfd, "f") must resolve relative to /p → /p/f (a real dirfd,
        // not ignored-as-AT_FDCWD which would look for "f" in the cwd).
        let rel = b"f\0";
        match call(
            Syscall::Openat.raw(),
            a3(dfd, rel.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("openat(dirfd, \"f\") did not resolve relative to the dir fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_openat_dirfd_relative);

// ── O_NOFOLLOW / O_PATH symlink + readlinkat(dirfd) ──
//
// chase_symlinks opens each component O_PATH|O_NOFOLLOW, fstat()s it, and
// readlinkat()s a symlink relative to its parent-dir fd to resolve it.

fn smoke_abi_path_openat_nofollow_symlink() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        const O_PATH: u64 = 0o10000000;
        const O_NOFOLLOW: u64 = 0o400000;
        const ELOOP: i64 = -40;
        // /p/lnk -> f
        let target = b"f\0";
        let link = b"/p/lnk\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64).unwrap_or(-1) != 0 {
            return Err("symlink(/p/lnk -> f) creation failed");
        }
        let p = b"/p/lnk\0";
        // O_NOFOLLOW (no O_PATH) on a symlink → -ELOOP (must not follow).
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, p.as_ptr() as u64, O_NOFOLLOW, 0),
        ) {
            Some(r) if r == ELOOP => {}
            _ => return Err("open(O_NOFOLLOW) on a symlink did not return -ELOOP"),
        }
        // O_NOFOLLOW|O_PATH opens the symlink node itself (fd >= 0).
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, p.as_ptr() as u64, O_NOFOLLOW | O_PATH, 0),
        ) {
            Some(fd) if fd >= 0 => {}
            _ => return Err("open(O_NOFOLLOW|O_PATH) did not open the symlink node"),
        }
        // readlinkat relative to a dir fd resolves the target verbatim.
        let dirp = b"/p\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dirp.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("opening /p dir fd failed"),
        };
        let rel = b"lnk\0";
        let mut rlbuf = [0u8; 64];
        let n = call(
            Syscall::Readlinkat.raw(),
            a3(
                dfd,
                rel.as_ptr() as u64,
                rlbuf.as_mut_ptr() as u64,
                rlbuf.len() as u64,
            ),
        )
        .ok_or("readlinkat status")?;
        if n <= 0 {
            return Err("readlinkat(dirfd, \"lnk\") failed");
        }
        if &rlbuf[..n as usize] != b"f" {
            return Err("readlinkat(dirfd, \"lnk\") returned the wrong target");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_openat_nofollow_symlink);

// An absolute symlink is rooted at the process mount namespace, not at the
// filesystem instance that contained the link. Fedora masks several units
// with `/etc/systemd/system/*.service -> /dev/null`; the source rootfs and
// `/dev` are separate mounts in a direct PID 1 boot.
fn smoke_abi_path_openat_absolute_symlink_crosses_mount() -> TestResult {
    with_memfs("/p", "p", &[], || {
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let target = MemFs::with_seeds("target", &[("f", b"cross-mount" as &[u8])]);
        let handle = match registry().mount(&auth, "/target", target) {
            Ok(handle) => handle,
            Err(_) => return Err("mounting symlink target filesystem failed"),
        };
        let outcome = (|| {
            let link_target = b"/target/f\0";
            let link = b"/p/to-target\0";
            if call_symlink(link_target.as_ptr() as u64, link.as_ptr() as u64) != Some(0) {
                return Err("creating absolute symlink failed");
            }
            let fd = match call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, link.as_ptr() as u64, O_RDONLY, 0),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("open must follow an absolute symlink through the mount table"),
            };
            let mut bytes = [0u8; 32];
            let n = match call(
                Syscall::Read.raw(),
                a2(fd, bytes.as_mut_ptr() as u64, bytes.len() as u64),
            ) {
                Some(n) if n > 0 => n as usize,
                _ => return Err("reading cross-mount symlink target failed"),
            };
            if &bytes[..n] == b"cross-mount" {
                Ok(())
            } else {
                Err("absolute symlink resolved to the wrong mount")
            }
        })();
        let _ = registry().unmount(&handle, "/target");
        outcome
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_openat_absolute_symlink_crosses_mount
);

// ── os-release-shaped symlink: chase (O_NOFOLLOW|O_PATH) vs follow ──
//
// systemd (PID 1) reads /etc/os-release — a symlink to ../usr/lib/os-release —
// via open_os_release_at → chaseat, which walks each component with
// openat(…, O_CLOEXEC|O_NOFOLLOW|O_PATH) and readlinkat()s a symlink to get
// its target. Two invariants that flow must satisfy, or systemd logs
// "Failed to read os-release file … Bad file descriptor" and
// "Failed to copy os-release … Is a directory":
//   (1) O_NOFOLLOW|O_PATH on the symlink hands back the LINK node (S_IFLNK),
//       not its followed target — otherwise chaseat can't readlinkat it.
//   (2) A following open of the symlink resolves to the target REGULAR file:
//       read() returns its bytes (never -EBADF) and fstat reports S_IFREG
//       (never a directory — copy_file_atomic's fd_verify_regular rejects a
//       directory source with EISDIR).
// On a disk-backed rootfs (ext2) the leaf lookup must run through the ASYNC
// resolver; the sync `lookup` used previously is stubbed there, so every
// O_NOFOLLOW|O_PATH open silently followed the link. MemFs exercises both
// resolution modes and pins the resulting fd shapes.
fn smoke_abi_path_os_release_symlink_chase_and_follow() -> TestResult {
    const OS_RELEASE: &[u8] = b"ID=narf\nPRETTY_NAME=\"NARF\"\n";
    with_memfs("/p", "p", &[("os-release", OS_RELEASE)], || {
        const O_PATH: u64 = 0o10000000;
        const O_NOFOLLOW: u64 = 0o400000;
        // /p/link -> os-release (relative target, like /etc/os-release).
        let target = b"os-release\0";
        let link = b"/p/link\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64).unwrap_or(-1) != 0 {
            return Err("symlink(/p/link -> os-release) creation failed");
        }

        // (1) O_NOFOLLOW|O_PATH must open the LINK node itself → fstat S_IFLNK.
        let lfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, link.as_ptr() as u64, O_NOFOLLOW | O_PATH, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(link, O_NOFOLLOW|O_PATH) did not open the symlink node"),
        };
        let mut sb = [0u8; 256];
        if call(Syscall::Fstat.raw(), a1(lfd, sb.as_mut_ptr() as u64)) != Some(0) {
            return Err("fstat of the O_NOFOLLOW|O_PATH fd failed");
        }
        // st_mode at offset 24; S_IFMT=0o170000, S_IFLNK=0o120000.
        let lmode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if lmode & 0o170000 != 0o120000 {
            return Err("O_NOFOLLOW|O_PATH fd must fstat as S_IFLNK (the link, not its target)");
        }

        // (2) A following open resolves to the target regular file.
        let ffd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, link.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(link, O_RDONLY) following the symlink did not yield a fd"),
        };
        // read() returns the target's bytes — never -EBADF.
        let mut rbuf = [0u8; 64];
        let n = match call(
            Syscall::Read.raw(),
            a2(ffd, rbuf.as_mut_ptr() as u64, rbuf.len() as u64),
        ) {
            Some(v) if v == EBADF => return Err("read of a symlink-followed file returned -EBADF"),
            Some(v) if v > 0 => v as usize,
            _ => return Err("read of a symlink-followed file returned no bytes"),
        };
        if &rbuf[..n] != OS_RELEASE {
            return Err("symlink-followed read did not return the target's content");
        }
        // fstat of the followed fd reports S_IFREG — a directory here would make
        // systemd's fd_verify_regular reject the copy source with EISDIR.
        let mut fsb = [0u8; 256];
        if call(Syscall::Fstat.raw(), a1(ffd, fsb.as_mut_ptr() as u64)) != Some(0) {
            return Err("fstat of the followed fd failed");
        }
        let fmode = u32::from_ne_bytes([fsb[24], fsb[25], fsb[26], fsb[27]]);
        if fmode & 0o170000 != 0o100000 {
            return Err("symlink-followed fd must fstat as S_IFREG, not a directory");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_os_release_symlink_chase_and_follow
);

// ── fstatfs reports the fd's own filesystem magic ──
//
// sd-device's fd_is_fs_type(fd, SYSFS_MAGIC) fstatfs()es an opened /sys node
// and rejects it unless f_type == SYSFS_MAGIC. A synthetic "/" answer broke
// every udev device lookup; fstatfs must reflect the fd's actual mount.

fn smoke_abi_path_fstatfs_reports_fd_fs() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        // MemFs is not sysfs/proc/cgroup/ext → fill_statfs maps it to TMPFS.
        const TMPFS_MAGIC: u64 = 0x0102_1994;
        let path = b"/p/f\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open /p/f failed"),
        };
        let mut buf = [0u8; 128];
        let r = call(Syscall::Fstatfs.raw(), a1(fd, buf.as_mut_ptr() as u64))
            .ok_or("fstatfs status")?;
        if r != 0 {
            return Err("fstatfs of a valid fd did not return 0");
        }
        // Linux `struct statfs`: f_type is the first 8-byte field.
        let f_type = u64::from_ne_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);
        if f_type != TMPFS_MAGIC {
            return Err("fstatfs did not report the fd's own filesystem magic");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_fstatfs_reports_fd_fs);

// fstatfs follows the caller's mount namespace, not the global registry. A
// service with a private /run tmpfs uses this to distinguish runtime state
// from the host's persistent filesystem before recursively cleaning it.
fn smoke_abi_path_fstatfs_uses_private_mount_namespace() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const TMPFS_MAGIC: u64 = 0x0102_1994;
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let global = registry()
            .mount_arc(
                &auth,
                "/abi-statfs-ns",
                alloc::sync::Arc::new(narf_filesystem::SysFs::new()),
            )
            .map_err(|_| "global sysfs mount setup failed")?;

        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = crate::handlers::current_mount_namespace()
                .ok_or("unshare did not install a mount namespace")?;
            ns.mount_arc(
                &auth,
                "/abi-statfs-ns",
                alloc::sync::Arc::new(MemFs::with_seeds("statfs-private", &[])),
            )
            .map_err(|_| "private tmpfs mount setup failed")?;

            let path = b"/abi-statfs-ns\0";
            let fd = match call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("open of private mount root failed"),
            };
            let mut buf = [0u8; 128];
            if call(Syscall::Fstatfs.raw(), a1(fd, buf.as_mut_ptr() as u64)) != Some(0) {
                return Err("fstatfs of private mount failed");
            }
            let f_type = u64::from_ne_bytes(buf[..8].try_into().unwrap());
            if f_type != TMPFS_MAGIC {
                return Err("fstatfs used the global mount instead of the private tmpfs");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        let _ = registry().unmount(&global, "/abi-statfs-ns");
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_fstatfs_uses_private_mount_namespace
);

// The path recorded for an open fd is deliberately chroot-relative so it can
// be returned through /proc/self/fd. fstatfs must re-root that visible path
// before finding its backing mount.
fn smoke_abi_path_fstatfs_reroots_chrooted_fd_path() -> TestResult {
    with_setup(|| {
        const TMPFS_MAGIC: u64 = 0x0102_1994;
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let visible = registry()
            .mount_arc(
                &auth,
                "/abi-statfs-visible",
                alloc::sync::Arc::new(narf_filesystem::SysFs::new()),
            )
            .map_err(|_| "visible sysfs mount setup failed")?;
        let rooted = registry()
            .mount(
                &auth,
                "/abi-statfs-root/abi-statfs-visible",
                MemFs::new("statfs-rooted"),
            )
            .map_err(|_| "rooted tmpfs mount setup failed")?;

        let result = (|| {
            if !crate::handlers::install_root_dir(FAKE_TASK, "/abi-statfs-root") {
                return Err("chroot setup failed");
            }
            let path = b"/abi-statfs-visible\0";
            let fd = match call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("open of chrooted private mount root failed"),
            };
            let mut buf = [0u8; 128];
            if call(Syscall::Fstatfs.raw(), a1(fd, buf.as_mut_ptr() as u64)) != Some(0) {
                return Err("fstatfs of chrooted fd failed");
            }
            let f_type = u64::from_ne_bytes(buf[..8].try_into().unwrap());
            if f_type != TMPFS_MAGIC {
                return Err("fstatfs did not re-root the fd path before mount lookup");
            }
            Ok(())
        })();
        crate::handlers::__test_root_dir_reset();
        let _ = registry().unmount(&rooted, "/abi-statfs-root/abi-statfs-visible");
        let _ = registry().unmount(&visible, "/abi-statfs-visible");
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_fstatfs_reroots_chrooted_fd_path
);

// ── creat: NUL-term path, returns a fd ──

fn smoke_abi_path_creat_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/created\0";
        match call_creat(path.as_ptr() as u64, 0o644) {
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
        match call_creat(path.as_ptr() as u64, 0o644) {
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
        match call_unlink(path.as_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("unlink(existing) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_unlink_pos);

fn smoke_abi_path_unlink_neg() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let path = b"/p/nope\0";
        match call_unlink(path.as_ptr() as u64) {
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
        match call_rename(old.as_ptr() as u64, new.as_ptr() as u64) {
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
        match call_rename(old.as_ptr() as u64, new.as_ptr() as u64) {
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
        match call_rmdir(dir.as_ptr() as u64) {
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
        match call_rmdir(dir.as_ptr() as u64) {
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
        // LINUX ABI: a NULL destination pointer faults → -EFAULT (previously
        // folded to a non-Ok InvalidOp status).
        match call(Syscall::Getcwd.raw(), a1(0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("getcwd(NULL, 0) must return -EFAULT"),
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

// statx(2) must populate STATX_MNT_ID (mount id of the file's mount). systemd's
// fds_inode_and_mount_same/path_is_root_at compare stx_mnt_id to tell a
// bind/pivoted root from the real root; when statx omits STATX_MNT_ID,
// statx_mount_same() returns -ENODATA and a service's mount-namespace setup
// (e.g. systemd-udevd with PrivateMounts=yes) fails 226/EXIT_NAMESPACE and
// restart-loops, wedging boot before dbus.
fn smoke_abi_path_statx_reports_mnt_id() -> TestResult {
    const STATX_MNT_ID: u32 = 0x1000;
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        let mut buf = [0u8; 256];
        let args = SyscallArgs {
            arg0: AT_FDCWD,
            arg1: path.as_ptr() as u64,
            arg2: 0,
            arg3: STATX_MNT_ID as u64, // request the mount id
            arg4: buf.as_mut_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Statx.raw(), args) != Some(0) {
            return Err("statx(existing) should return 0");
        }
        // stx_mask is the first u32 of struct statx.
        let mask = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if mask & STATX_MNT_ID == 0 {
            return Err("statx must advertise STATX_MNT_ID in stx_mask");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_reports_mnt_id);

// systemd's `path_is_mount_point()` requests only STATX_TYPE|STATX_INO but
// still relies on the returned mount ID. statx may return cheap additional
// fields, and NARF must advertise this one so systemd can distinguish the
// API-filesystem bind mounts it inherited from ordinary directories.
fn smoke_abi_path_statx_systemd_mount_probe_includes_mnt_id() -> TestResult {
    const STATX_TYPE_AND_INO: u32 = 0x0101;
    const STATX_MNT_ID: u32 = 0x1000;
    const STATX_ATTR_MOUNT_ROOT: u64 = 0x0000_2000;
    with_memfs("/p", "p", &[("f", b"hi")], || {
        // systemd asks this shape about the API filesystem's *mount root*.
        let path = b"/p\0";
        let mut buf = [0u8; 256];
        let args = SyscallArgs {
            arg0: AT_FDCWD,
            arg1: path.as_ptr() as u64,
            arg2: 0x4800, // AT_STATX_SYNC_AS_STAT | AT_NO_AUTOMOUNT
            arg3: STATX_TYPE_AND_INO as u64,
            arg4: buf.as_mut_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Statx.raw(), args) != Some(0) {
            return Err("systemd-shaped statx probe should succeed");
        }
        let mask = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if mask & STATX_MNT_ID == 0 {
            return Err("systemd-shaped statx probe omitted STATX_MNT_ID");
        }
        // struct statx: stx_attributes @ 8, stx_attributes_mask @ 56.
        let attributes = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        let attributes_mask = u64::from_ne_bytes(buf[56..64].try_into().unwrap());
        if attributes_mask & STATX_ATTR_MOUNT_ROOT == 0 || attributes & STATX_ATTR_MOUNT_ROOT == 0 {
            return Err("systemd-shaped statx probe omitted STATX_ATTR_MOUNT_ROOT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_statx_systemd_mount_probe_includes_mnt_id
);

// The MOUNT_ROOT support bit is available for every statx response, but its
// value must not leak to children inside the mounted filesystem. Otherwise a
// service manager would treat ordinary paths (for example /proc/sys) as mount
// points and skip the mount it needs.
fn smoke_abi_path_statx_mount_root_is_exact() -> TestResult {
    const STATX_ATTR_MOUNT_ROOT: u64 = 0x0000_2000;
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        let mut buf = [0u8; 256];
        if do_statx(AT_FDCWD, path.as_ptr() as u64, 0, 0x0101, &mut buf) != Some(0) {
            return Err("statx of mount child should succeed");
        }
        let attributes = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        let attributes_mask = u64::from_ne_bytes(buf[56..64].try_into().unwrap());
        if attributes_mask & STATX_ATTR_MOUNT_ROOT == 0 {
            return Err("statx of mount child omitted MOUNT_ROOT support bit");
        }
        if attributes & STATX_ATTR_MOUNT_ROOT != 0 {
            return Err("statx reported a mount child as a mount root");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_mount_root_is_exact);

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

fn smoke_abi_path_mkdirat_dirfd_relative() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let dir = b"/p\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("mkdirat setup could not open its directory fd"),
        };
        let relative = b"runtime\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(dfd, relative.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdirat(dirfd, relative) did not create below the directory fd");
        }
        let created = b"/p/runtime\0";
        match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, created.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("mkdirat(dirfd, relative) created at the wrong path"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mkdirat_dirfd_relative);

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

// mknodat: NARF has no FIFO/device node types, so a node is created as a
// regular file — but it must EXIST and be openable, which elogind's
// per-session `.ref` FIFO (and /run/systemd/inaccessible/* nodes) depend on.
// Without mknodat, elogind's CreateSession failed EINVAL → no logind session
// (which a Wayland compositor needs to TakeDevice the GPU).
fn smoke_abi_path_mknodat_fifo_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        const S_IFIFO: u64 = 0o010000;
        let path = b"/p/sess.ref\0";
        // mknodat(AT_FDCWD, path, S_IFIFO|0600, dev=0) creates the node.
        if call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, S_IFIFO | 0o600, 0),
        ) != Some(0)
        {
            return Err("mknodat(FIFO) at a fresh path should return 0");
        }
        // It now exists → a second mknodat is -EEXIST, proving the node landed.
        match call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, S_IFIFO | 0o600, 0),
        ) {
            Some(-17) => Ok(()), // -EEXIST
            _ => Err("mknodat over an existing node should be -EEXIST"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mknodat_fifo_pos);

// mknod(2)/mkfifo(3): the created node's permission bits must come from the
// `mode` argument, not a filesystem default. systemd's `fifo_address_create()`
// creates `/run/initctl` with `mkfifo(path, 0600)` then rejects it with EEXIST
// unless a follow-up stat reports BOTH S_IFIFO and `(st_mode & 0777) == 0600`.
// Before the mode was persisted the FIFO stat'd as 0666 and systemd's listen
// failed with "File exists".
fn smoke_abi_path_mknodat_fifo_honors_mode() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        const S_IFIFO: u64 = 0o010000;
        let path = b"/p/initctl\0";
        if call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, S_IFIFO | 0o600, 0),
        ) != Some(0)
        {
            return Err("mknodat(FIFO, 0600) at a fresh path should return 0");
        }
        let mut sb = [0u8; 256];
        if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("stat of the new FIFO should return 0");
        }
        // st_mode is at offset 24; S_IFMT=0o170000, S_IFIFO=0o010000.
        let mode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if mode & 0o170000 != 0o010000 {
            return Err("mknodat(S_IFIFO) node must stat as a FIFO");
        }
        if mode & 0o777 != 0o600 {
            return Err("mknodat must persist the requested mode (0600), not a default");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mknodat_fifo_honors_mode);

// open(2) O_PATH on a FIFO must NOT apply fifo(7) peer-rendezvous: an O_PATH
// open resolves the inode without invoking any file operation, so it returns a
// path-reference fd immediately even with no writer present and no O_NONBLOCK.
// systemd-tmpfiles walks /dev with openat(…, O_NOFOLLOW|O_CLOEXEC|O_PATH) to
// stat/chmod each node it creates; before O_PATH short-circuited the FIFO
// rendezvous, that open PARKED forever on a writer that never came and
// systemd-tmpfiles-setup-dev.service never finished (the whole boot wedged
// before dbus). A plain O_RDONLY open of the same writerless FIFO would still
// block — which is exactly why the O_PATH form must not.
fn smoke_abi_path_open_opath_fifo_no_block() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        const S_IFIFO: u64 = 0o010000;
        const O_NOFOLLOW: u64 = 0o400000;
        const O_PATH: u64 = 0o10000000;
        const O_CLOEXEC: u64 = 0o2000000;
        let path = b"/p/opath.fifo\0";
        if call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, S_IFIFO | 0o600, 0),
        ) != Some(0)
        {
            return Err("mknodat(FIFO) at a fresh path should return 0");
        }
        // No writer, no O_NONBLOCK: only O_PATH keeps this from parking.
        match call(
            Syscall::Openat.raw(),
            a3(
                AT_FDCWD,
                path.as_ptr() as u64,
                O_PATH | O_NOFOLLOW | O_CLOEXEC,
                0,
            ),
        ) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("openat(FIFO, O_PATH) must return a fd without blocking on a writer"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_open_opath_fifo_no_block);

fn smoke_abi_path_mknodat_eexist() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        // "f" already exists → mknod over it is -EEXIST, not a clobber.
        let path = b"/p/f\0";
        match call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o100600, 0),
        ) {
            Some(-17) => Ok(()),
            _ => Err("mknodat over an existing file should be -EEXIST"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mknodat_eexist);

fn smoke_abi_path_mknodat_enoent() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        // mknodat under a missing parent must fail (not return 0).
        let path = b"/p/missing/child\0";
        match call(
            Syscall::Mknodat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 0o100600, 0),
        ) {
            Some(0) => Err("mknodat under a missing parent must fail"),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mknodat_enoent);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_path_mknod_legacy_alias() -> TestResult {
    with_memfs("/p", "p", &[], || {
        let path = b"/p/legacy-fifo\0";
        const S_IFIFO: u64 = 0o010000;
        if call(
            Syscall::Mknod.raw(),
            a2(path.as_ptr() as u64, S_IFIFO | 0o620, 0),
        ) != Some(0)
        {
            return Err("legacy mknod(FIFO) should create the node");
        }
        let mut sb = [0u8; 144];
        if call_lstat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("legacy mknod result should be reachable by lstat");
        }
        let mode = u32::from_ne_bytes(sb[24..28].try_into().unwrap()) as u64;
        if mode & 0o170000 != S_IFIFO || mode & 0o777 != 0o620 {
            return Err("legacy mknod must preserve FIFO type and permission bits");
        }
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_path_mknod_legacy_alias);

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

// mkdir on an existing MOUNT ROOT must return -EEXIST, not a bare -1.
// A mount root's parent fs does not expose it as a child entry, so the
// parent-lookup existence check can't see it; the full-path mount-aware
// check does. systemd's cg_create mkdir()s the cgroup2 hierarchy root
// (/sys/fs/cgroup, whose parent /sys/fs is sysfs) and treats EEXIST as
// success — a bare -1 (→ EPERM) there aborted every service's cgroup
// setup ("Failed to create cgroup /: Operation not permitted").
fn smoke_abi_path_mkdir_over_mount_root_eexists() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let root = b"/p\0";
        match call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, root.as_ptr() as u64, 0o755, 0),
        ) {
            Some(-17) => Ok(()), // -EEXIST
            other => {
                let _ = other;
                Err("mkdir over an existing mount root should return -EEXIST (-17), not -1")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_mkdir_over_mount_root_eexists);

// stat on an ANCESTOR of a mount point must report a directory, not
// ENOENT. In NARF's flat mount model the intermediate component has no
// real node in the parent fs, but it is logically a directory. systemd's
// mkdir_parents_safe mkdir()s each component then newfstatat()s it to
// confirm S_IFDIR — if stat and mkdir disagree, cg_create fails and no
// service cgroup can be realized. Mount at /anc/sub/leaf and stat /anc/sub.
fn smoke_abi_path_stat_mount_ancestor_is_dir() -> TestResult {
    with_memfs("/anc/sub/leaf", "leaf", &[("f", b"x")], || {
        let path = b"/anc/sub\0";
        let mut sb = [0u8; 256];
        if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("stat on a mount-ancestor dir should return 0, not ENOENT");
        }
        // st_mode is at offset 24 in the x86_64/aarch64 struct stat;
        // S_IFMT=0o170000, S_IFDIR=0o40000.
        let mode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if mode & 0o170000 == 0o40000 {
            Ok(())
        } else {
            Err("mount-ancestor stat st_mode must be S_IFDIR")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_stat_mount_ancestor_is_dir);

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

// ── link / linkat: hard links (same-parent; cross-dir → -EXDEV) ──

fn smoke_abi_path_link_pos() -> TestResult {
    with_memfs("/p", "p", &[("old", b"hi")], || {
        let old = b"/p/old\0";
        let new = b"/p/new\0";
        if call_link(old.as_ptr() as u64, new.as_ptr() as u64) != Some(0) {
            return Err("link(old, new) should return 0");
        }
        // The new name must open and read the SAME bytes — the alias
        // shares the backing node (hard-link semantics, not a copy).
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, new.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(/p/new) after link should succeed"),
        };
        let mut buf = [0u8; 2];
        if call(Syscall::Read.raw(), a2(fd, buf.as_mut_ptr() as u64, 2)) != Some(2) || &buf != b"hi"
        {
            return Err("read through the link must see the original bytes");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_link_pos);

fn smoke_abi_path_link_neg() -> TestResult {
    with_memfs("/p", "p", &[("old", b"hi"), ("taken", b"x")], || {
        let missing = b"/p/ghost\0";
        let new = b"/p/n1\0";
        // Missing source → -ENOENT.
        if call_link(missing.as_ptr() as u64, new.as_ptr() as u64) != Some(-2) {
            return Err("link(missing, ..) should return -ENOENT");
        }
        // Existing destination → -EEXIST (link never replaces).
        let old = b"/p/old\0";
        let taken = b"/p/taken\0";
        if call_link(old.as_ptr() as u64, taken.as_ptr() as u64) != Some(-17) {
            return Err("link(.., existing) should return -EEXIST");
        }
        // Cross-directory → -EXDEV (same-parent restriction, like rename).
        let elsewhere = b"/q/new\0";
        if call_link(old.as_ptr() as u64, elsewhere.as_ptr() as u64) != Some(-18) {
            return Err("cross-directory link should return -EXDEV");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_link_neg);

fn smoke_abi_path_linkat_pos() -> TestResult {
    with_memfs("/p", "p", &[("old", b"hi")], || {
        let old = b"/p/old\0";
        let new = b"/p/n2\0";
        // AT_FDCWD + absolute paths, flags = 0 (a3 zeroes arg4).
        match call(
            Syscall::Linkat.raw(),
            a3(AT_FDCWD, old.as_ptr() as u64, AT_FDCWD, new.as_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("linkat(AT_FDCWD, old, AT_FDCWD, new, 0) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_linkat_pos);

// ── fchdir: directory fd → cwd ──

fn smoke_abi_path_fchdir_pos() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let dirp = b"/p\0";
        let dfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dirp.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("opening /p as a directory fd failed"),
        };
        if call(Syscall::Fchdir.raw(), a0(dfd)) != Some(0) {
            return Err("fchdir(dirfd) should return 0");
        }
        // getcwd must now report /p.
        let mut buf = [0u8; 16];
        let n = call(Syscall::Getcwd.raw(), a1(buf.as_mut_ptr() as u64, 16));
        if n.is_none() || !buf.starts_with(b"/p\0") {
            return Err("getcwd after fchdir should report /p");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_fchdir_pos);

fn smoke_abi_path_fchdir_neg() -> TestResult {
    with_setup(|| {
        // Dead fd → -EBADF.
        match call(Syscall::Fchdir.raw(), a0(9999)) {
            Some(-9) => Ok(()),
            _ => Err("fchdir(dead fd) should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_fchdir_neg);

// ── utime / utimes / utimensat: real mtime round-trip ──
//
// FileOps::set_times landed (MemFs stores wall-ns, stat reports it back
// through the cycles→ns ABI conversion), so these assert the actual
// round-trip that tar -x / cp -p / make depend on — not just the old
// validate-the-path behavior.

/// st_mtim offsets in the x86_64/aarch64 `struct stat` (144 bytes):
/// dev8+ino8+nlink8+mode4+uid4+gid4+pad4+rdev8+size8+blksize8+blocks8
/// = 72 (st_atim), 88 (st_mtim.tv_sec), 96 (st_mtim.tv_nsec).
fn stat_mtime(path: &[u8]) -> Result<(i64, i64), &'static str> {
    let mut sb = [0u8; 144];
    if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
        return Err("stat on the target should succeed");
    }
    Ok((
        i64::from_ne_bytes(sb[88..96].try_into().unwrap()),
        i64::from_ne_bytes(sb[96..104].try_into().unwrap()),
    ))
}

fn smoke_abi_path_utimes_sets_mtime() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        // timeval[2]: atime {111 s, 0 µs}, mtime {222 s, 333 µs}.
        let tv: [i64; 4] = [111, 0, 222, 333];
        if call(
            Syscall::Utimes.raw(),
            a1(path.as_ptr() as u64, tv.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("utimes should return 0");
        }
        let (sec, nsec) = stat_mtime(path)?;
        if sec != 222 || nsec != 333_000 {
            return Err("stat must read back the utimes mtime (222 s, 333 µs)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_utimes_sets_mtime);

fn smoke_abi_path_utime_sets_mtime_seconds() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        // utimbuf { actime = 5, modtime = 7 } — seconds.
        let ub: [i64; 2] = [5, 7];
        if call(
            Syscall::Utime.raw(),
            a1(path.as_ptr() as u64, ub.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("utime should return 0");
        }
        let (sec, nsec) = stat_mtime(path)?;
        if sec != 7 || nsec != 0 {
            return Err("stat must read back the utime modtime (7 s)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_utime_sets_mtime_seconds);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_path_futimesat_sets_mtime() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        const AT_FDCWD: u64 = (-100i64) as u64;
        let path = b"/p/f\0";
        // timeval[2]: atime {31 s, 0 us}, mtime {47 s, 125 us}.
        let tv: [i64; 4] = [31, 0, 47, 125];
        if call(
            Syscall::Futimesat.raw(),
            a2(AT_FDCWD, path.as_ptr() as u64, tv.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("futimesat should return 0 for an existing file");
        }
        let (sec, nsec) = stat_mtime(path)?;
        if sec != 47 || nsec != 125_000 {
            return Err("futimesat mtime must round-trip through stat");
        }
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_path_futimesat_sets_mtime);

fn smoke_abi_path_utimensat_omit_and_invalid() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        // Seed a known mtime via utimes.
        let tv: [i64; 4] = [0, 0, 42, 0];
        if call(
            Syscall::Utimes.raw(),
            a1(path.as_ptr() as u64, tv.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("seeding utimes should return 0");
        }
        // utimensat with atime = UTIME_NOW, mtime = UTIME_OMIT must
        // leave the seeded mtime alone.
        const UTIME_NOW: i64 = 0x3FFF_FFFF;
        const UTIME_OMIT: i64 = 0x3FFF_FFFE;
        let ts: [i64; 4] = [0, UTIME_NOW, 0, UTIME_OMIT];
        const AT_FDCWD_I: u64 = (-100i64) as u64;
        if call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD_I, path.as_ptr() as u64, ts.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("utimensat(NOW, OMIT) should return 0");
        }
        let (sec, _) = stat_mtime(path)?;
        if sec != 42 {
            return Err("UTIME_OMIT must leave the seeded mtime unchanged");
        }
        // Out-of-range tv_nsec (not NOW/OMIT) → -EINVAL.
        let bad: [i64; 4] = [0, 0, 0, 2_000_000_000];
        if call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD_I, path.as_ptr() as u64, bad.as_ptr() as u64, 0),
        ) != Some(-22)
        {
            return Err("utimensat with tv_nsec out of range should return -EINVAL");
        }
        // Missing path → -ENOENT (times NULL = now).
        let ghost = b"/p/ghost\0";
        if call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD_I, ghost.as_ptr() as u64, 0, 0),
        ) != Some(-2)
        {
            return Err("utimensat on a missing path should return -ENOENT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_utimensat_omit_and_invalid);

fn smoke_abi_path_write_stamps_mtime() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        let path = b"/p/f\0";
        // O_WRONLY = 1. Write through the fd, then stat: the MemFs write
        // path stamps wall-now, so mtime must be non-zero afterwards
        // (fresh MemFs nodes start at the 0 = never-stamped sentinel).
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, 1, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(/p/f, O_WRONLY) should succeed"),
        };
        if call(Syscall::Write.raw(), a2(fd, b"zz".as_ptr() as u64, 2)) != Some(2) {
            return Err("write should return 2");
        }
        let (sec, nsec) = stat_mtime(path)?;
        if sec == 0 && nsec == 0 {
            return Err("a write must stamp a non-zero mtime");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_write_stamps_mtime);

// ── tmpfs directory-mutation errno discipline (systemd mount teardown) ──
//
// systemd's mount teardown mkdir()s then rename/rmdir()s propagation dirs
// under /run/systemd/propagate/<unit> (a tmpfs). A bare -1 → EPERM there
// logged "Unable to remove propagation dir … Operation not permitted" and
// aborted run-lock.mount. These pin the precise Linux errno each op must
// return (never a bare -1 → EPERM).

// rmdir of a freshly-created empty dir in a MemFs returns 0 (not EPERM).
fn smoke_abi_path_rmdir_fresh_empty_dir_ok() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let dir = b"/run/fresh\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir(/run/fresh) should return 0");
        }
        match call_rmdir(dir.as_ptr() as u64) {
            Some(0) => Ok(()),
            Some(EPERM) => Err("rmdir(fresh empty dir) must NOT return EPERM (bare -1)"),
            _ => Err("rmdir(fresh empty dir) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rmdir_fresh_empty_dir_ok);

// rmdir of a missing dir returns ENOENT, not the bare -1 → EPERM sentinel.
fn smoke_abi_path_rmdir_missing_is_enoent() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let dir = b"/run/nope\0";
        match call_rmdir(dir.as_ptr() as u64) {
            Some(ENOENT) => Ok(()),
            Some(EPERM) => Err("rmdir(missing) must be ENOENT, not EPERM"),
            _ => Err("rmdir(missing) should return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rmdir_missing_is_enoent);

// rmdir of a NON-empty dir returns ENOTEMPTY, not the bare -1 → EPERM.
fn smoke_abi_path_rmdir_nonempty_is_enotempty() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let dir = b"/run/full\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir(/run/full) should return 0");
        }
        // Plant a child so the dir is non-empty.
        let child = b"/run/full/child\0";
        if call_creat(child.as_ptr() as u64, 0o644).unwrap_or(-1) < 0 {
            return Err("creat(/run/full/child) should return a fd");
        }
        match call_rmdir(dir.as_ptr() as u64) {
            Some(ENOTEMPTY) => Ok(()),
            Some(EPERM) => Err("rmdir(non-empty) must be ENOTEMPTY, not EPERM"),
            _ => Err("rmdir(non-empty dir) should return -ENOTEMPTY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rmdir_nonempty_is_enotempty);

// rename of a freshly-created dir within a MemFs returns 0.
fn smoke_abi_path_rename_dir_ok() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let old = b"/run/pdir\0";
        let new = b"/run/pdir2\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, old.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdir(/run/pdir) should return 0");
        }
        match call_rename(old.as_ptr() as u64, new.as_ptr() as u64) {
            Some(0) => Ok(()),
            Some(EPERM) => Err("rename(dir) must NOT return EPERM (bare -1)"),
            _ => Err("rename(dir within a MemFs) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_dir_ok);

// ── cross-directory rename ─────────────────────────────────────────
//
// `rename(2)` is only EXDEV when the two paths are on different MOUNTS.
// Moving a name between directories of ONE filesystem must work: Qt's
// QSaveFile — so every KDE/KConfig/KSycoca write — stages into a temp
// file and renames it onto the target, and a blanket EXDEV surfaced to
// the user as "Invalid cross-device link" with the config never written.

/// EXDEV isn't in the shared errno table yet (nothing else returns it).
const EXDEV: i64 = -18;
const O_WRONLY_CREAT: u64 = 1 | 0o100;

/// `openat(AT_FDCWD, path, O_WRONLY|O_CREAT, 0644)`, returning the fd.
fn create_file(path: &[u8]) -> Option<u64> {
    match call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, O_WRONLY_CREAT, 0o644),
    ) {
        Some(fd) if fd >= 0 => Some(fd as u64),
        _ => None,
    }
}

fn smoke_abi_path_rename_cross_dir_ok() -> TestResult {
    with_memfs("/run", "run", &[("seed", b"x")], || {
        for d in [b"/run/ra\0", b"/run/rb\0"] {
            if call(
                Syscall::Mkdirat.raw(),
                a3(AT_FDCWD, d.as_ptr() as u64, 0o755, 0),
            ) != Some(0)
            {
                return Err("mkdir of the rename test dirs should return 0");
            }
        }
        // Stage a file in ra, write to it, then move it into rb.
        let src = b"/run/ra/tmp.XXX\0";
        let dst = b"/run/rb/final\0";
        let payload = b"cross";
        let fd = match create_file(src) {
            Some(f) => f,
            None => return Err("creating the staging file should succeed"),
        };
        if call(
            Syscall::Write.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 0),
        ) != Some(payload.len() as i64)
        {
            return Err("writing the staging file should succeed");
        }
        let _ = call(Syscall::Close.raw(), a3(fd, 0, 0, 0));

        match call_rename(src.as_ptr() as u64, dst.as_ptr() as u64) {
            Some(0) => {}
            Some(EXDEV) => return Err("cross-DIRECTORY rename within one mount must not be EXDEV"),
            _ => return Err("cross-directory rename should return 0"),
        }
        // The old name is gone and the new one carries the bytes — the
        // node moved, it wasn't copied and left behind.
        if matches!(
            call(Syscall::Openat.raw(), a3(AT_FDCWD, src.as_ptr() as u64, O_RDONLY, 0)),
            Some(fd) if fd >= 0
        ) {
            return Err("the source name must be gone after a cross-directory rename");
        }
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dst.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("the destination name must exist after the rename"),
        };
        let mut buf = [0u8; 8];
        let n = call(
            Syscall::Read.raw(),
            a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, 0),
        );
        let _ = call(Syscall::Close.raw(), a3(fd, 0, 0, 0));
        if n != Some(payload.len() as i64) || &buf[..payload.len()] != payload {
            return Err("the moved file must still hold its contents");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_cross_dir_ok);

/// POSIX `rename` REPLACES an existing destination. `link_node` alone
/// refuses to clobber (linkat never does), so the handler has to clear
/// the target first — otherwise the second save of any config file
/// fails forever.
fn smoke_abi_path_rename_cross_dir_replaces() -> TestResult {
    with_memfs("/run", "run", &[("seed", b"x")], || {
        for d in [b"/run/xa\0", b"/run/xb\0"] {
            if call(
                Syscall::Mkdirat.raw(),
                a3(AT_FDCWD, d.as_ptr() as u64, 0o755, 0),
            ) != Some(0)
            {
                return Err("mkdir of the rename test dirs should return 0");
            }
        }
        let src = b"/run/xa/new\0";
        let dst = b"/run/xb/old\0";
        for p in [src.as_slice(), dst.as_slice()] {
            match create_file(p) {
                Some(fd) => {
                    let _ = call(Syscall::Close.raw(), a3(fd, 0, 0, 0));
                }
                None => return Err("creating the rename fixtures should succeed"),
            }
        }
        match call_rename(src.as_ptr() as u64, dst.as_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("cross-directory rename over an existing name should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_cross_dir_replaces);

/// A rename that really does span two MOUNTS is still EXDEV — the case
/// callers must fall back to copy+unlink on. The second filesystem is
/// mounted by hand because `with_memfs` owns setup/teardown and so can't
/// nest.
fn smoke_abi_path_rename_cross_mount_is_exdev() -> TestResult {
    with_memfs("/run", "run", &[("src", b"x")], || {
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let other = MemFs::with_seeds("other", &[("keep", b"y" as &[u8])]);
        let handle = match registry().mount(&auth, "/other", other) {
            Ok(h) => h,
            Err(_) => return Err("mounting the second memfs failed"),
        };
        let src = b"/run/src\0";
        let dst = b"/other/src\0";
        let outcome = match call_rename(src.as_ptr() as u64, dst.as_ptr() as u64) {
            Some(EXDEV) => Ok(()),
            Some(0) => Err("rename across two mounts must not silently succeed"),
            _ => Err("rename across two mounts should return -EXDEV"),
        };
        let _ = registry().unmount(&handle, "/other");
        outcome
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_cross_mount_is_exdev);

// rename of a missing source returns ENOENT, not the bare -1 → EPERM.
fn smoke_abi_path_rename_missing_is_enoent() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let old = b"/run/ghost\0";
        let new = b"/run/there\0";
        match call_rename(old.as_ptr() as u64, new.as_ptr() as u64) {
            Some(ENOENT) => Ok(()),
            Some(EPERM) => Err("rename(missing) must be ENOENT, not EPERM"),
            _ => Err("rename(missing source) should return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_rename_missing_is_enoent);

// ── systemd-tmpfiles file-node ops on a tmpfs path ──
//
// systemd-tmpfiles creates/adjusts files+dirs per /usr/lib/tmpfiles.d. Each
// op must succeed on a tmpfs path AND the created node must stat with the
// right type/mode. mkdir+chmod, symlink, and utimensat are covered here.

// chmod on a tmpfs FILE persists the mode: a later stat reflects the new
// low-9 bits. systemd-tmpfiles `z`/`Z` lines chmod a file and then stat it to
// confirm the mode took. The x86_64 legacy `chmod(2)` and the `fchmodat(2)`
// both route through sys_fchmodat, which persists via FileOps::set_perms.
fn smoke_abi_path_chmod_file_mode_roundtrips() -> TestResult {
    with_memfs("/run", "run", &[("cfg", b"data")], || {
        let path = b"/run/cfg\0";
        if call_chmod(path.as_ptr() as u64, 0o640) != Some(0) {
            return Err("chmod(/run/cfg, 0o640) should return 0");
        }
        let mut sb = [0u8; 256];
        if call_stat(path.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("stat(/run/cfg) should return 0");
        }
        // st_mode is at offset 24 in the x86_64/aarch64 struct stat.
        let mode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if mode & 0o777 == 0o640 {
            Ok(())
        } else {
            Err("chmod on a file must round-trip the low-9 mode bits through stat")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_chmod_file_mode_roundtrips);

// chmod on a tmpfs DIRECTORY persists the mode: a later stat reports S_IFDIR
// with the new perms. systemd-tmpfiles `d`/`D` lines chmod a directory, and
// dbus/systemd reject XDG_RUNTIME_DIR unless it is not group/other-writable —
// so `chmod 0700` on a tmpfs dir must show through stat.
fn smoke_abi_path_chmod_dir_mode_roundtrips() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let dir = b"/run/lock\0";
        if call_mkdir(dir.as_ptr() as u64, 0o755) != Some(0) {
            return Err("mkdir(/run/lock, 0o755) should return 0");
        }
        if call_chmod(dir.as_ptr() as u64, 0o700) != Some(0) {
            return Err("chmod(/run/lock, 0o700) should return 0");
        }
        let mut sb = [0u8; 256];
        if call_stat(dir.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("stat(/run/lock) should return 0");
        }
        // st_mode at offset 24: S_IFMT=0o170000, S_IFDIR=0o40000.
        let mode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if mode & 0o170000 != 0o40000 {
            return Err("chmod'd dir must still stat as S_IFDIR");
        }
        if mode & 0o777 == 0o700 {
            Ok(())
        } else {
            Err("chmod on a dir must round-trip the low-9 mode bits through stat")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_chmod_dir_mode_roundtrips);

// chmod on a missing tmpfs path returns ENOENT, not the bare -1 → EPERM.
fn smoke_abi_path_chmod_missing_is_enoent() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let path = b"/run/absent\0";
        match call_chmod(path.as_ptr() as u64, 0o644) {
            Some(ENOENT) => Ok(()),
            Some(EPERM) => Err("chmod(missing) must be ENOENT, not EPERM"),
            _ => Err("chmod(missing) should return -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_chmod_missing_is_enoent);

// symlink on a tmpfs path succeeds and the node lstat()s as S_IFLNK.
fn smoke_abi_path_symlink_stats_as_link() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let target = b"f\0";
        let link = b"/run/ln\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64).unwrap_or(-1) != 0 {
            return Err("symlink(/run/ln -> f) should return 0");
        }
        let mut sb = [0u8; 256];
        if call_lstat(link.as_ptr() as u64, sb.as_mut_ptr() as u64) != Some(0) {
            return Err("lstat(/run/ln) should return 0");
        }
        // S_IFLNK = 0o120000.
        let mode = u32::from_ne_bytes([sb[24], sb[25], sb[26], sb[27]]);
        if mode & 0o170000 == 0o120000 {
            Ok(())
        } else {
            Err("symlink node must lstat as S_IFLNK")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_symlink_stats_as_link);

// symlink onto an existing name returns EEXIST (idempotent tmpfiles), not
// the bare -1 → EPERM sentinel.
fn smoke_abi_path_symlink_exists_is_eexist() -> TestResult {
    with_memfs("/run", "run", &[("taken", b"x")], || {
        let target = b"whatever\0";
        let link = b"/run/taken\0";
        match call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) {
            Some(EEXIST) => Ok(()),
            Some(EPERM) => Err("symlink over an existing name must be EEXIST, not EPERM"),
            _ => Err("symlink over an existing name should return -EEXIST"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_symlink_exists_is_eexist);

// utimensat on a tmpfs file returns 0 and the mtime round-trips through stat.
fn smoke_abi_path_utimensat_roundtrip() -> TestResult {
    with_memfs("/run", "run", &[("stamp", b"x")], || {
        let path = b"/run/stamp\0";
        // timespec[2] = { {100, 0}, {200, 500} } (atime, mtime).
        let mut ts = [0u8; 32];
        ts[0..8].copy_from_slice(&100i64.to_ne_bytes()); // atime.tv_sec
        ts[16..24].copy_from_slice(&200i64.to_ne_bytes()); // mtime.tv_sec
        ts[24..32].copy_from_slice(&500i64.to_ne_bytes()); // mtime.tv_nsec
        let r = call(
            Syscall::Utimensat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, ts.as_ptr() as u64, 0),
        );
        if r != Some(0) {
            return Err("utimensat(/run/stamp) should return 0");
        }
        let (sec, nsec) = stat_mtime(path)?;
        if sec != 200 || nsec != 500 {
            return Err("utimensat mtime must round-trip through stat st_mtim");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_utimensat_roundtrip);

// A nested tmpfs mount at /run/lock (under the existing /run tmpfs) must
// succeed and be independently resolvable — systemd's run-lock.mount mounts
// a tmpfs at /run/lock. NARF's flat mount model registers it as its own
// longest-prefix mount.
fn smoke_abi_path_nested_tmpfs_mount() -> TestResult {
    with_memfs("/run", "run", &[("f", b"x")], || {
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let lock_fs = MemFs::with_seeds("run-lock", &[("marker", b"L")]);
        let lock_handle = match registry().mount(&auth, "/run/lock", lock_fs) {
            Ok(h) => h,
            Err(_) => return Err("nested tmpfs mount at /run/lock should succeed"),
        };
        // A file in the NESTED mount resolves via the longest-prefix match
        // (proving /run/lock shadows /run for paths beneath it).
        let marker = b"/run/lock/marker\0";
        let opened = matches!(
            call(Syscall::Openat.raw(), a3(AT_FDCWD, marker.as_ptr() as u64, O_RDONLY, 0)),
            Some(fd) if fd >= 0
        );
        // A file in the OUTER /run mount still resolves too.
        let outer = b"/run/f\0";
        let outer_ok = matches!(
            call(Syscall::Openat.raw(), a3(AT_FDCWD, outer.as_ptr() as u64, O_RDONLY, 0)),
            Some(fd) if fd >= 0
        );
        let _ = registry().unmount(&lock_handle, "/run/lock");
        if !opened {
            return Err("a file in the nested /run/lock mount must be openable");
        }
        if !outer_ok {
            return Err("a file in the outer /run mount must still be openable");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_nested_tmpfs_mount);

// ── O_TMPFILE + linkat("/proc/self/fd/N") — the QSaveFile shape ─────
//
// Qt's QSaveFile — so every KDE/KConfig/KSycoca database write — opens
// an O_TMPFILE inode, writes it, then materialises it with
// `linkat(AT_FDCWD, "/proc/self/fd/N", AT_FDCWD, target, AT_SYMLINK_FOLLOW)`.
// The handler's "is this fd pathless?" guard used to ask whether
// `fd_path_of` returned None — but that helper synthesises an
// `anon_inode:[…]` placeholder for every pathless fd and so never
// answers None, making the branch unreachable. The call then fell
// through to a path-based hard link, where `/proc/self/fd/N` and the
// target sit in different directories, and came back EXDEV: KSycoca
// reported "Invalid cross-device link" and never wrote its database.
fn smoke_abi_path_linkat_proc_fd_materialises_tmpfile() -> TestResult {
    const O_TMPFILE_BIT: u64 = 0o20_000_000;
    const O_RDWR: u64 = 2;
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    with_memfs("/p", "p", &[("seed", b"x")], || {
        // O_TMPFILE names the DIRECTORY the inode is created in.
        let dir = b"/p\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, O_TMPFILE_BIT | O_RDWR, 0o600),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("openat(O_TMPFILE) should return an anonymous fd"),
        };
        let payload = b"sycoca";
        if call(
            Syscall::Write.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 0),
        ) != Some(payload.len() as i64)
        {
            return Err("writing the O_TMPFILE inode should succeed");
        }
        // Give it a name, exactly as Qt does.
        let mut src = [0u8; 32];
        let pre = b"/proc/self/fd/";
        src[..pre.len()].copy_from_slice(pre);
        let mut w = pre.len();
        let mut v = fd;
        let mut digits = [0u8; 20];
        let mut n = 0;
        if v == 0 {
            digits[0] = b'0';
            n = 1;
        }
        while v > 0 {
            digits[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        for i in (0..n).rev() {
            src[w] = digits[i];
            w += 1;
        }
        src[w] = 0;
        let dst = b"/p/named\0";
        match call_raw(
            Syscall::Linkat.raw(),
            SyscallArgs {
                arg0: AT_FDCWD,
                arg1: src.as_ptr() as u64,
                arg2: AT_FDCWD,
                arg3: dst.as_ptr() as u64,
                arg4: AT_SYMLINK_FOLLOW,
                arg5: 0,
            },
        ) {
            r if r.status == SyscallReturn::OK && r.value as i64 == 0 => {}
            r if r.status == SyscallReturn::OK && r.value as i64 == EXDEV => {
                return Err("linkat(/proc/self/fd/N) must not report EXDEV")
            }
            _ => return Err("linkat(/proc/self/fd/N, target) should return 0"),
        }
        let _ = call(Syscall::Close.raw(), a3(fd, 0, 0, 0));
        // The name now resolves and carries what was written through the fd —
        // the inode was aliased, not copied.
        let rfd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, dst.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(f) if f >= 0 => f as u64,
            _ => return Err("the materialised name should be openable"),
        };
        let mut buf = [0u8; 16];
        let got = call(
            Syscall::Read.raw(),
            a3(rfd, buf.as_mut_ptr() as u64, buf.len() as u64, 0),
        );
        let _ = call(Syscall::Close.raw(), a3(rfd, 0, 0, 0));
        if got != Some(payload.len() as i64) || &buf[..payload.len()] != payload {
            return Err("the materialised file must hold the bytes written via the fd");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_linkat_proc_fd_materialises_tmpfile
);

// ── statx STATX_MNT_ID / inode / type discipline ────────────────────
//
// `struct statx` field byte offsets (verified against the `Statx`
// definition in handlers/mod.rs — repr(C), size 256):
//   stx_mask   u32 @ 0
//   stx_mode   u16 @ 28
//   stx_ino    u64 @ 32
//   stx_size   u64 @ 40
//   stx_mnt_id u64 @ 144
// (statx's stx_mode is at 28, NOT 24 — offset 24 is `struct stat`'s
// st_mode.)
const STATX_MASK_OFF: usize = 0;
const STATX_MODE_OFF: usize = 28;
const STATX_INO_OFF: usize = 32;
const STATX_SIZE_OFF: usize = 40;
const STATX_MNT_ID_OFF: usize = 144;
const STATX_MNT_ID_BIT: u32 = 0x1000;
const AT_EMPTY_PATH_FLAG: u64 = 0x1000;
const AT_SYMLINK_NOFOLLOW_FLAG: u64 = 0x100;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// statx(dirfd, path, flags, mask, buf) into a 256-byte statx buffer.
fn do_statx(dirfd: u64, path_ptr: u64, flags: u64, mask: u64, buf: &mut [u8; 256]) -> Option<i64> {
    call(
        Syscall::Statx.raw(),
        SyscallArgs {
            arg0: dirfd,
            arg1: path_ptr,
            arg2: flags,
            arg3: mask,
            arg4: buf.as_mut_ptr() as u64,
            ..Default::default()
        },
    )
}

fn statx_u32(buf: &[u8; 256], off: usize) -> u32 {
    u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())
}
fn statx_u16(buf: &[u8; 256], off: usize) -> u16 {
    u16::from_ne_bytes(buf[off..off + 2].try_into().unwrap())
}
fn statx_u64(buf: &[u8; 256], off: usize) -> u64 {
    u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap())
}

// Files on DIFFERENT mounts advertise DIFFERENT stx_mnt_id values.
// systemd's statx_mount_same / path_is_root_at compare stx_mnt_id to tell
// a bind/pivoted root from the real root; two independent mounts sharing a
// mount id (or omitting STATX_MNT_ID) would make those comparisons alias
// and mis-detect the root. Mount two separate MemFs and confirm the mount
// ids of a file on each differ, with STATX_MNT_ID set on both.
fn smoke_abi_path_statx_cross_mount_mnt_id_differs() -> TestResult {
    with_memfs("/p", "p", &[("f", b"hi")], || {
        // A second, independent MemFs mounted by hand (with_memfs owns its
        // own setup/teardown and so can't nest).
        let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
        let other = MemFs::with_seeds("q", &[("g", b"bye" as &[u8])]);
        let handle = match registry().mount(&auth, "/q", other) {
            Ok(h) => h,
            Err(_) => return Err("mounting the second memfs at /q failed"),
        };
        let run = || -> Result<(), &'static str> {
            let pa = b"/p/f\0";
            let pb = b"/q/g\0";
            let mut ba = [0u8; 256];
            let mut bb = [0u8; 256];
            if do_statx(
                AT_FDCWD,
                pa.as_ptr() as u64,
                0,
                STATX_MNT_ID_BIT as u64,
                &mut ba,
            ) != Some(0)
            {
                return Err("statx(/p/f) should return 0");
            }
            if do_statx(
                AT_FDCWD,
                pb.as_ptr() as u64,
                0,
                STATX_MNT_ID_BIT as u64,
                &mut bb,
            ) != Some(0)
            {
                return Err("statx(/q/g) should return 0");
            }
            let mask_a = statx_u32(&ba, STATX_MASK_OFF);
            let mask_b = statx_u32(&bb, STATX_MASK_OFF);
            if mask_a & STATX_MNT_ID_BIT == 0 || mask_b & STATX_MNT_ID_BIT == 0 {
                return Err("statx on both mounts must advertise STATX_MNT_ID in stx_mask");
            }
            let id_a = statx_u64(&ba, STATX_MNT_ID_OFF);
            let id_b = statx_u64(&bb, STATX_MNT_ID_OFF);
            if id_a == id_b {
                return Err("files on two different mounts must have different stx_mnt_id");
            }
            Ok(())
        };
        let outcome = run();
        let _ = registry().unmount(&handle, "/q");
        outcome
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_statx_cross_mount_mnt_id_differs
);

// A directory and a file beneath it must have DISTINCT inodes, and their
// S_IFMT bits must be S_IFDIR vs S_IFREG respectively. systemd's rm_rf
// root-guard (rm_rf_children_inner) aborts if a directory and one of its
// entries report the same st_ino — a symptom of a filesystem confusing a
// dir with its parent — so a dir/file ino collision would make rm_rf bail.
fn smoke_abi_path_statx_dir_vs_file_ino_and_type() -> TestResult {
    with_memfs("/p", "p", &[("f", b"payload")], || {
        // Create a directory under the mount, then statx both it and the
        // seeded regular file /p/f.
        let dir = b"/p/d\0";
        if call(
            Syscall::Mkdirat.raw(),
            a3(AT_FDCWD, dir.as_ptr() as u64, 0o755, 0),
        ) != Some(0)
        {
            return Err("mkdirat(/p/d) should return 0");
        }
        let file = b"/p/f\0";
        let mut bd = [0u8; 256];
        let mut bf = [0u8; 256];
        if do_statx(AT_FDCWD, dir.as_ptr() as u64, 0, 0, &mut bd) != Some(0) {
            return Err("statx(/p/d) should return 0");
        }
        if do_statx(AT_FDCWD, file.as_ptr() as u64, 0, 0, &mut bf) != Some(0) {
            return Err("statx(/p/f) should return 0");
        }
        let dir_mode = statx_u16(&bd, STATX_MODE_OFF) as u32;
        let file_mode = statx_u16(&bf, STATX_MODE_OFF) as u32;
        if dir_mode & S_IFMT != S_IFDIR {
            return Err("the directory's stx_mode S_IFMT bits must be S_IFDIR");
        }
        if file_mode & S_IFMT != S_IFREG {
            return Err("the file's stx_mode S_IFMT bits must be S_IFREG");
        }
        let dir_ino = statx_u64(&bd, STATX_INO_OFF);
        let file_ino = statx_u64(&bf, STATX_INO_OFF);
        if dir_ino == file_ino {
            return Err("a directory and a file under it must have distinct stx_ino");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_dir_vs_file_ino_and_type);

// statx(fd, "", AT_EMPTY_PATH, …) describes the OPEN FD's file: it must
// return 0, report S_IFREG with the right size, and still advertise
// STATX_MNT_ID (the mount the fd resides on — from mqueue::fd_mount_id).
// systemd's path_is_root_at fstats a dir fd with AT_EMPTY_PATH and compares
// its stx_mnt_id against the parent's, so the fd form must carry it too.
fn smoke_abi_path_statx_at_empty_path_fd() -> TestResult {
    const PAYLOAD: &[u8] = b"empty-path-target";
    with_memfs("/p", "p", &[("f", PAYLOAD)], || {
        let path = b"/p/f\0";
        let fd = match call(
            Syscall::Openat.raw(),
            a3(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open(/p/f) should return a fd"),
        };
        let empty = b"\0";
        let mut buf = [0u8; 256];
        let r = do_statx(
            fd,
            empty.as_ptr() as u64,
            AT_EMPTY_PATH_FLAG,
            STATX_MNT_ID_BIT as u64,
            &mut buf,
        );
        let _ = call(Syscall::Close.raw(), a3(fd, 0, 0, 0));
        if r != Some(0) {
            return Err("statx(fd, \"\", AT_EMPTY_PATH) should return 0");
        }
        let mode = statx_u16(&buf, STATX_MODE_OFF) as u32;
        if mode & S_IFMT != S_IFREG {
            return Err("statx AT_EMPTY_PATH on a file fd must report S_IFREG");
        }
        let size = statx_u64(&buf, STATX_SIZE_OFF);
        if size != PAYLOAD.len() as u64 {
            return Err("statx AT_EMPTY_PATH must report the file's real size");
        }
        let mask = statx_u32(&buf, STATX_MASK_OFF);
        if mask & STATX_MNT_ID_BIT == 0 {
            return Err("statx AT_EMPTY_PATH (fd form) must advertise STATX_MNT_ID");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_at_empty_path_fd);

// Two independent opens of the SAME directory must be indistinguishable:
// identical stx_ino AND identical stx_mnt_id. This is an identity invariant,
// not a formatting one, and the existing statx smokes only check that the
// fields are PRESENT.
//
// systemd's `path_is_root_at()` / `fds_inode_and_mount_same()` decide "have I
// reached the root yet" by opening a reference directory and comparing it,
// via statx(AT_EMPTY_PATH), against the fd it is walking. If two opens of one
// directory disagree, that test can never say "yes" and the walk does not
// terminate. `systemd-udevd` was caught doing exactly this on the Fedora
// gate — an unbounded `openat("/") → statx(held_fd) → statx(new_fd) → close`
// loop, which is what a never-satisfied root comparison looks like from the
// syscall side, and it stops the daemon dead after two uevents.
//
// NARF fabricates inode numbers, so "same path, same identity" is a real
// thing to get wrong here rather than something the filesystem hands over for
// free — st_ino fabrication has already broken musl's DSO dedup once.
fn smoke_abi_path_statx_same_dir_twice_has_stable_identity() -> TestResult {
    with_memfs("/p", "p", &[("f", b"x")], || {
        let dir = b"/p ";
        let mut fds = [0u64; 2];
        for slot in fds.iter_mut() {
            *slot = match call(
                Syscall::Openat.raw(),
                a3(AT_FDCWD, dir.as_ptr() as u64, O_RDONLY, 0),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("open(/p) should return a fd"),
            };
        }
        let empty = b"\0";
        let mut buf_a = [0u8; 256];
        let mut buf_b = [0u8; 256];
        let ra = do_statx(
            fds[0],
            empty.as_ptr() as u64,
            AT_EMPTY_PATH_FLAG,
            STATX_MNT_ID_BIT as u64,
            &mut buf_a,
        );
        let rb = do_statx(
            fds[1],
            empty.as_ptr() as u64,
            AT_EMPTY_PATH_FLAG,
            STATX_MNT_ID_BIT as u64,
            &mut buf_b,
        );
        for fd in fds {
            let _ = call(Syscall::Close.raw(), a3(fd, 0, 0, 0));
        }
        if ra != Some(0) || rb != Some(0) {
            return Err("statx(dirfd, \"\", AT_EMPTY_PATH) should return 0 for both opens");
        }
        if statx_u64(&buf_a, STATX_INO_OFF) != statx_u64(&buf_b, STATX_INO_OFF) {
            return Err("two opens of the same directory reported different stx_ino");
        }
        if statx_u64(&buf_a, STATX_MNT_ID_OFF) != statx_u64(&buf_b, STATX_MNT_ID_OFF) {
            return Err("two opens of the same directory reported different stx_mnt_id");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_path_statx_same_dir_twice_has_stable_identity
);

// AT_SYMLINK_NOFOLLOW gives lstat semantics: statx of a symlink WITH the
// flag describes the LINK node (S_IFLNK), while statx WITHOUT it follows to
// the target regular file (S_IFREG). systemd's chase() walks each component
// with statx(dir_fd, name, AT_SYMLINK_NOFOLLOW, STATX_TYPE) and must see the
// link itself to readlink it; a follow there would resolve past the link.
fn smoke_abi_path_statx_nofollow_reports_link() -> TestResult {
    with_memfs("/p", "p", &[("f", b"target-bytes")], || {
        // /p/lnk -> f (relative target within the mount).
        let target = b"f\0";
        let link = b"/p/lnk\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64).unwrap_or(-1) != 0 {
            return Err("symlink(/p/lnk -> f) creation failed");
        }
        let p = b"/p/lnk\0";
        // With AT_SYMLINK_NOFOLLOW → the link node itself (S_IFLNK).
        let mut bl = [0u8; 256];
        if do_statx(
            AT_FDCWD,
            p.as_ptr() as u64,
            AT_SYMLINK_NOFOLLOW_FLAG,
            0,
            &mut bl,
        ) != Some(0)
        {
            return Err("statx(link, AT_SYMLINK_NOFOLLOW) should return 0");
        }
        let lmode = statx_u16(&bl, STATX_MODE_OFF) as u32;
        if lmode & S_IFMT != S_IFLNK {
            return Err("statx(AT_SYMLINK_NOFOLLOW) on a symlink must report S_IFLNK");
        }
        // Without the flag → follow to the target regular file (S_IFREG).
        let mut bt = [0u8; 256];
        if do_statx(AT_FDCWD, p.as_ptr() as u64, 0, 0, &mut bt) != Some(0) {
            return Err("statx(link) following the symlink should return 0");
        }
        let tmode = statx_u16(&bt, STATX_MODE_OFF) as u32;
        if tmode & S_IFMT != S_IFREG {
            return Err("statx(link) without NOFOLLOW must follow to the S_IFREG target");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_statx_nofollow_reports_link);

// ── getcwd(2) — errno correctness (ERANGE / EFAULT) ───────────────────
//
// glibc's getcwd grows its buffer on -ERANGE and retries; folding a
// too-small buffer to -EINVAL broke that loop. A NULL destination faults
// → -EFAULT. Both were previously the blanket invalid_op/-EINVAL.
fn smoke_abi_path_getcwd_errno() -> TestResult {
    with_setup(|| {
        // A 1-byte buffer cannot hold even "/" + NUL (needed >= 2), so the
        // handler must report -ERANGE regardless of the exact cwd length.
        let mut small = [0u8; 1];
        let r = call(
            Syscall::Getcwd.raw(),
            a1(small.as_mut_ptr() as u64, small.len() as u64),
        );
        if r != Some(ERANGE) {
            return Err("getcwd with an undersized buffer must return -ERANGE");
        }
        // A NULL destination pointer faults → -EFAULT.
        let r = call(Syscall::Getcwd.raw(), a1(0, 256));
        if r != Some(EFAULT) {
            return Err("getcwd(NULL, len) must return -EFAULT");
        }
        // A generous buffer succeeds and returns the cwd string length (>= 1
        // for the root "/"), proving the ERANGE arm is not swallowing valid
        // calls.
        let mut big = [0u8; 256];
        match call(
            Syscall::Getcwd.raw(),
            a1(big.as_mut_ptr() as u64, big.len() as u64),
        ) {
            Some(n) if n >= 1 => Ok(()),
            _ => Err("getcwd with a large buffer should return the path length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_path_getcwd_errno);
