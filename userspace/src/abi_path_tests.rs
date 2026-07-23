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
        if call(
            Syscall::Link.raw(),
            a1(old.as_ptr() as u64, new.as_ptr() as u64),
        ) != Some(0)
        {
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
        if call(
            Syscall::Link.raw(),
            a1(missing.as_ptr() as u64, new.as_ptr() as u64),
        ) != Some(-2)
        {
            return Err("link(missing, ..) should return -ENOENT");
        }
        // Existing destination → -EEXIST (link never replaces).
        let old = b"/p/old\0";
        let taken = b"/p/taken\0";
        if call(
            Syscall::Link.raw(),
            a1(old.as_ptr() as u64, taken.as_ptr() as u64),
        ) != Some(-17)
        {
            return Err("link(.., existing) should return -EEXIST");
        }
        // Cross-directory → -EXDEV (same-parent restriction, like rename).
        let elsewhere = b"/q/new\0";
        if call(
            Syscall::Link.raw(),
            a1(old.as_ptr() as u64, elsewhere.as_ptr() as u64),
        ) != Some(-18)
        {
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
