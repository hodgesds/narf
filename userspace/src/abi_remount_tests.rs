//! Linux syscall ABI conformance — remounting an existing mount.
//!
//! `systemd-remount-fs` runs `mount -o remount /` on every boot, with the
//! fstab options. util-linux 2.39+ does it through the new mount API
//! (strace on Linux 7.2, libmount 2.42):
//!
//! ```text
//! open_tree(AT_FDCWD, "/", OPEN_TREE_CLOEXEC)                  = 3
//! fspick(3, "", FSPICK_NO_AUTOMOUNT|FSPICK_EMPTY_PATH)         = 4
//! fsconfig(4, FSCONFIG_SET_STRING, "commit", "60", 0)          = 0
//! fsconfig(4, FSCONFIG_SET_FLAG, "rw", NULL, 0)                = 0
//! fsconfig(4, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0)         = 0
//! mount_setattr(3, "", AT_EMPTY_PATH, {attr_set=NOATIME,
//!               attr_clr=MOUNT_ATTR__ATIME}, 32)               = 0
//! ```
//!
//! and older callers through `mount(2)` with `MS_REMOUNT`. On NARF the
//! reconfigure step handed `rw` to the filesystem as if it were one of its
//! own parameters, so it failed -EINVAL — util-linux's "mount point not
//! mounted or bad option" — and nothing below it ran. These tests pin the
//! whole sequence and the flag bookkeeping `path_mount` / `do_remount` /
//! `reconfigure_super` do, as `/proc/self/mountinfo` reports it.

use crate::abi_test_support::*;

const MS_RDONLY: u64 = 1 << 0;
const MS_NOSUID: u64 = 1 << 1;
const MS_NODEV: u64 = 1 << 2;
const MS_NOEXEC: u64 = 1 << 3;
const MS_REMOUNT: u64 = 1 << 5;
const MS_NOATIME: u64 = 1 << 10;
const MS_BIND: u64 = 1 << 12;
const MS_STRICTATIME: u64 = 1 << 24;

const FSCONFIG_SET_FLAG: u64 = 0;
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
const FSPICK_NO_AUTOMOUNT: u64 = 0x4;
const FSPICK_EMPTY_PATH: u64 = 0x8;
const OPEN_TREE_CLOEXEC: u64 = 0o2000000;
const AT_EMPTY_PATH: u64 = 0x1000;
const MOUNT_ATTR_NOATIME: u64 = 0x10;
const MOUNT_ATTR__ATIME: u64 = 0x70;

fn mount_call(target: &[u8], fstype: &[u8], flags: u64, data: Option<&[u8]>) -> Option<i64> {
    let source = b"none\0";
    call(
        Syscall::Mount.raw(),
        SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: flags,
            arg4: data.map_or(0, |d| d.as_ptr() as u64),
            ..Default::default()
        },
    )
}

fn umount(target: &[u8]) {
    let _ = call(Syscall::Umount2.raw(), a1(target.as_ptr() as u64, 0));
}

/// The `/proc/self/mountinfo` line whose mount point is `path`, read the
/// way userspace reads it (open + read).
fn mountinfo_line(path: &str) -> Option<alloc::string::String> {
    let _mountinfo_hook =
        narf_filesystem::procfs::MountinfoHookGuard::install(crate::handlers::proc_ns_mountinfo);
    let file = b"/proc/self/mountinfo\0";
    let fd = call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, file.as_ptr() as u64, 0, 0),
    )?;
    if fd < 0 {
        return None;
    }
    let mut body = alloc::vec::Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match call(
            Syscall::Read.raw(),
            a2(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        ) {
            Some(n) if n > 0 => body.extend_from_slice(&buf[..n as usize]),
            _ => break,
        }
    }
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
    let text = core::str::from_utf8(&body).ok()?;
    text.lines()
        .filter(|line| line.split(' ').nth(4) == Some(path))
        .next_back()
        .map(alloc::string::String::from)
}

/// `(mount options, super options)` — mountinfo fields 6 and the one after
/// the fstype and source past the ` - ` separator.
fn mountinfo_opts(path: &str) -> Option<(alloc::string::String, alloc::string::String)> {
    let line = mountinfo_line(path)?;
    let (head, tail) = line.split_once(" - ")?;
    let mnt = head.split(' ').nth(5)?;
    // Only the superblock's own `rw`/`ro`: the filesystem's show_options
    // text (tmpfs `size=`, `mode=`, ...) follows it.
    let sb = tail.split(' ').nth(2)?.split(',').next()?;
    Some((mnt.into(), sb.into()))
}

fn create_file(path: &[u8]) -> Option<i64> {
    let fd = call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, 0o100 | 0o1, 0o644),
    )?;
    if fd >= 0 {
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Some(0)
    } else {
        Some(fd)
    }
}

// ── mount(2) MS_REMOUNT: flags land, atime is preserved, sb goes ro ─────

/// `path_mount` + `do_remount` + `set_mount_attributes`, observed through
/// mountinfo. A fresh mount is `relatime` by default; a remount that names
/// the restriction bits replaces the attachment's set; a remount that names
/// no atime flag KEEPS the previous atime policy ("The default atime for
/// remount is preservation"); `MS_RDONLY` makes the superblock read-only
/// too, so the super-options column says `ro` and writes are -EROFS.
fn smoke_abi_remount_legacy_flags_and_mountinfo_pos() -> TestResult {
    with_setup(|| {
        let target = b"/abi-remount-flags\0";
        let path = "/abi-remount-flags";
        let fstype = b"tmpfs\0";
        if mount_call(target, fstype, 0, None) != Some(0) {
            return Err("mounting the tmpfs fixture failed");
        }
        let finish = |r: Result<(), &'static str>| {
            umount(target);
            r
        };
        match mountinfo_opts(path) {
            Some((mnt, _)) if mnt == "rw,relatime" => {}
            _ => return finish(Err("a default mount(2) must show `rw,relatime`")),
        }
        let flags = MS_REMOUNT | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME;
        if mount_call(target, fstype, flags, None) != Some(0) {
            return finish(Err("remount,nosuid,nodev,noexec,noatime failed"));
        }
        match mountinfo_opts(path) {
            Some((mnt, sb)) if mnt == "rw,nosuid,nodev,noexec,noatime" && sb == "rw" => {}
            _ => return finish(Err("remount flags did not reach mountinfo")),
        }
        // No atime flag: noatime survives, the restriction bits are replaced.
        if mount_call(target, fstype, MS_REMOUNT | MS_RDONLY, None) != Some(0) {
            return finish(Err("remount,ro failed"));
        }
        match mountinfo_opts(path) {
            Some((mnt, sb)) if mnt == "ro,noatime" && sb == "ro" => {}
            _ => {
                return finish(Err(
                    "remount,ro must keep noatime and make the superblock ro",
                ))
            }
        }
        if create_file(b"/abi-remount-flags/f\0") != Some(EROFS) {
            return finish(Err("a write through a read-only remount must be -EROFS"));
        }
        // MS_STRICTATIME clears the atime policy; rw lifts the sb flag.
        if mount_call(target, fstype, MS_REMOUNT | MS_STRICTATIME, None) != Some(0) {
            return finish(Err("remount,rw,strictatime failed"));
        }
        match mountinfo_opts(path) {
            Some((mnt, sb)) if mnt == "rw" && sb == "rw" => {}
            _ => return finish(Err("remount,rw,strictatime must show a bare `rw`")),
        }
        if create_file(b"/abi-remount-flags/f\0") != Some(0) {
            return finish(Err("remount,rw did not make the mount writable again"));
        }
        finish(Ok(()))
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_remount_legacy_flags_and_mountinfo_pos
);

/// `do_remount` / `do_reconfigure_mnt` both open with
/// `if (!path_mounted(path)) return -EINVAL;`, and `reconfigure_super`
/// refuses a flag outside `MS_RMT_MASK` (`dirsync` in the data string)
/// and the filesystem refuses a parameter it does not know. In every case
/// the mount's flags must be untouched: the old handler wrote them BEFORE
/// asking the filesystem, so a refused remount still changed the mount.
fn smoke_abi_remount_legacy_rejects_neg() -> TestResult {
    with_setup(|| {
        let target = b"/abi-remount-neg\0";
        let path = "/abi-remount-neg";
        let fstype = b"tmpfs\0";
        let below = b"/abi-remount-neg/sub\0";
        if mount_call(target, fstype, 0, None) != Some(0) {
            return Err("mounting the tmpfs fixture failed");
        }
        let finish = |r: Result<(), &'static str>| {
            let _ = call_rmdir(below.as_ptr() as u64);
            umount(target);
            r
        };
        if call_mkdir(below.as_ptr() as u64, 0o755) != Some(0) {
            return finish(Err("mkdir below the fixture failed"));
        }
        // An existing directory that is not a mount root.
        if mount_call(below, fstype, MS_REMOUNT, None) != Some(EINVAL) {
            return finish(Err("MS_REMOUNT of a non-mountpoint must be -EINVAL"));
        }
        if mount_call(below, fstype, MS_REMOUNT | MS_BIND, None) != Some(EINVAL) {
            return finish(Err(
                "MS_BIND|MS_REMOUNT of a non-mountpoint must be -EINVAL",
            ));
        }
        // An unknown filesystem parameter, with restriction flags that must
        // NOT land because the reconfigure failed.
        let flags = MS_REMOUNT | MS_RDONLY | MS_NOEXEC;
        if mount_call(target, fstype, flags, Some(b"bogus_option=1\0")) != Some(EINVAL) {
            return finish(Err("an unknown tmpfs parameter on remount must be -EINVAL"));
        }
        // `dirsync` is a superblock flag, but not one a remount may change.
        if mount_call(target, fstype, flags, Some(b"dirsync\0")) != Some(EINVAL) {
            return finish(Err(
                "dirsync on remount must be -EINVAL (outside MS_RMT_MASK)",
            ));
        }
        match mountinfo_opts(path) {
            Some((mnt, sb)) if mnt == "rw,relatime" && sb == "rw" => {}
            _ => return finish(Err("a refused remount must leave the mount unchanged")),
        }
        if create_file(b"/abi-remount-neg/f\0") != Some(0) {
            return finish(Err("a refused remount left the mount unwritable"));
        }
        let _ = call_unlink(c"/abi-remount-neg/f".as_ptr() as u64);
        finish(Ok(()))
    })
}
kernel_test_in!("syscall_abi", smoke_abi_remount_legacy_rejects_neg);

// ── new mount API: libmount's remount sequence ──────────────────────────

fn fsconfig(fd: i64, cmd: u64, key: Option<&[u8]>, value: Option<&[u8]>) -> Option<i64> {
    call(
        Syscall::Fsconfig.raw(),
        a4(
            fd as u64,
            cmd,
            key.map_or(0, |k| k.as_ptr() as u64),
            value.map_or(0, |v| v.as_ptr() as u64),
            0,
        ),
    )
}

/// The exact syscalls `mount -o remount,noatime <mnt>` issues on
/// util-linux 2.42 (see the module doc), then the read-only variant:
/// `ro` via `FSCONFIG_SET_FLAG` is a SUPERBLOCK flag, so after the
/// reconfigure the super-options column is `ro` while the attachment's own
/// column still says `rw`, and every write is -EROFS
/// (`__mnt_is_readonly` checks `sb_rdonly`).
fn smoke_abi_remount_new_api_libmount_sequence_pos() -> TestResult {
    with_setup(|| {
        let target = b"/abi-remount-api\0";
        let path = "/abi-remount-api";
        let fstype = b"tmpfs\0";
        if mount_call(target, fstype, 0, None) != Some(0) {
            return Err("mounting the tmpfs fixture failed");
        }
        let mut fds: alloc::vec::Vec<i64> = alloc::vec::Vec::new();
        let finish = |r: Result<(), &'static str>, fds: &[i64]| {
            for fd in fds {
                let _ = call(Syscall::Close.raw(), a0(*fd as u64));
            }
            umount(target);
            r
        };
        let tree = match call(
            Syscall::OpenTree.raw(),
            a2(AT_FDCWD, target.as_ptr() as u64, OPEN_TREE_CLOEXEC),
        ) {
            Some(fd) if fd >= 0 => fd,
            _ => return finish(Err("open_tree(path, OPEN_TREE_CLOEXEC) failed"), &fds),
        };
        fds.push(tree);
        let empty = b"\0";
        let pick = |tree: i64| {
            call(
                Syscall::Fspick.raw(),
                a2(
                    tree as u64,
                    empty.as_ptr() as u64,
                    FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH,
                ),
            )
        };
        let fs = match pick(tree) {
            Some(fd) if fd >= 0 => fd,
            _ => return finish(Err("fspick(tree, \"\", EMPTY_PATH) failed"), &fds),
        };
        fds.push(fs);
        if fsconfig(fs, FSCONFIG_SET_FLAG, Some(b"rw\0"), None) != Some(0) {
            return finish(Err("fsconfig(SET_FLAG, \"rw\") failed"), &fds);
        }
        if fsconfig(fs, FSCONFIG_CMD_RECONFIGURE, None, None) != Some(0) {
            return finish(
                Err("CMD_RECONFIGURE after SET_FLAG rw must succeed (libmount's remount)"),
                &fds,
            );
        }
        // mount_setattr(tree, "", AT_EMPTY_PATH, {NOATIME, clr __ATIME}).
        let mut attr = [0u64; 4];
        attr[0] = MOUNT_ATTR_NOATIME;
        attr[1] = MOUNT_ATTR__ATIME;
        let set = call(
            Syscall::MountSetattr.raw(),
            a4(
                tree as u64,
                empty.as_ptr() as u64,
                AT_EMPTY_PATH,
                attr.as_ptr() as u64,
                32,
            ),
        );
        if set != Some(0) {
            return finish(Err("mount_setattr(noatime) on the tree fd failed"), &fds);
        }
        match mountinfo_opts(path) {
            Some((mnt, sb)) if mnt == "rw,noatime" && sb == "rw" => {}
            _ => {
                return finish(
                    Err("mountinfo must show `rw,noatime` after the sequence"),
                    &fds,
                )
            }
        }
        // Now `mount -o remount,ro` through the same API.
        if fsconfig(fs, FSCONFIG_SET_FLAG, Some(b"ro\0"), None) != Some(0)
            || fsconfig(fs, FSCONFIG_CMD_RECONFIGURE, None, None) != Some(0)
        {
            return finish(Err("fsconfig ro + CMD_RECONFIGURE failed"), &fds);
        }
        match mountinfo_opts(path) {
            Some((mnt, sb)) if mnt == "rw,noatime" && sb == "ro" => {}
            _ => {
                return finish(
                    Err("a superblock ro must show in the super column only"),
                    &fds,
                )
            }
        }
        if create_file(b"/abi-remount-api/f\0") != Some(EROFS) {
            return finish(
                Err("a write to a read-only superblock must be -EROFS"),
                &fds,
            );
        }
        if fsconfig(fs, FSCONFIG_SET_FLAG, Some(b"rw\0"), None) != Some(0)
            || fsconfig(fs, FSCONFIG_CMD_RECONFIGURE, None, None) != Some(0)
        {
            return finish(Err("fsconfig rw + CMD_RECONFIGURE failed"), &fds);
        }
        if create_file(b"/abi-remount-api/f\0") != Some(0) {
            return finish(Err("reconfiguring back to rw must make it writable"), &fds);
        }
        let _ = call_unlink(c"/abi-remount-api/f".as_ptr() as u64);
        finish(Ok(()), &fds)
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_remount_new_api_libmount_sequence_pos
);

/// `reconfigure_super`'s `if (fc->sb_flags_mask & ~MS_RMT_MASK) return
/// -EINVAL;` — `dirsync` is a superblock key `vfs_parse_sb_flag` accepts at
/// SET time, but a reconfiguration may not change it — and a parameter the
/// filesystem does not know fails the reconfigure too. The superblock stays
/// read-write in both cases.
fn smoke_abi_remount_new_api_rejects_neg() -> TestResult {
    with_setup(|| {
        let target = b"/abi-remount-api-neg\0";
        let path = "/abi-remount-api-neg";
        let fstype = b"tmpfs\0";
        if mount_call(target, fstype, 0, None) != Some(0) {
            return Err("mounting the tmpfs fixture failed");
        }
        let mut fds: alloc::vec::Vec<i64> = alloc::vec::Vec::new();
        let finish = |r: Result<(), &'static str>, fds: &[i64]| {
            for fd in fds {
                let _ = call(Syscall::Close.raw(), a0(*fd as u64));
            }
            umount(target);
            r
        };
        let pick = || {
            call(
                Syscall::Fspick.raw(),
                a2(AT_FDCWD, target.as_ptr() as u64, 0),
            )
        };
        let first = match pick() {
            Some(fd) if fd >= 0 => fd,
            _ => return finish(Err("fspick(path) failed"), &fds),
        };
        fds.push(first);
        if fsconfig(first, FSCONFIG_SET_FLAG, Some(b"ro\0"), None) != Some(0)
            || fsconfig(first, FSCONFIG_SET_FLAG, Some(b"dirsync\0"), None) != Some(0)
        {
            return finish(Err("fsconfig SET_FLAG ro/dirsync must be accepted"), &fds);
        }
        if fsconfig(first, FSCONFIG_CMD_RECONFIGURE, None, None) != Some(EINVAL) {
            return finish(Err("reconfiguring dirsync must be -EINVAL"), &fds);
        }
        let second = match pick() {
            Some(fd) if fd >= 0 => fd,
            _ => return finish(Err("second fspick(path) failed"), &fds),
        };
        fds.push(second);
        if fsconfig(second, FSCONFIG_SET_FLAG, Some(b"ro\0"), None) != Some(0)
            || fsconfig(
                second,
                FSCONFIG_SET_STRING,
                Some(b"bogus_option\0"),
                Some(b"1\0"),
            ) != Some(0)
        {
            return finish(Err("fsconfig SET_FLAG/SET_STRING setup failed"), &fds);
        }
        if fsconfig(second, FSCONFIG_CMD_RECONFIGURE, None, None) != Some(EINVAL) {
            return finish(
                Err("an unknown tmpfs parameter must fail the reconfigure"),
                &fds,
            );
        }
        match mountinfo_opts(path) {
            Some((_, sb)) if sb == "rw" => {}
            _ => {
                return finish(
                    Err("a failed reconfigure must leave the superblock rw"),
                    &fds,
                )
            }
        }
        if create_file(b"/abi-remount-api-neg/f\0") != Some(0) {
            return finish(
                Err("a failed reconfigure left the filesystem unwritable"),
                &fds,
            );
        }
        let _ = call_unlink(c"/abi-remount-api-neg/f".as_ptr() as u64);
        finish(Ok(()), &fds)
    })
}
kernel_test_in!("syscall_abi", smoke_abi_remount_new_api_rejects_neg);
