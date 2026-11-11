//! Linux syscall ABI conformance — the pty surface `openpty(3)` +
//! `ttyname(3)` drive.
//!
//! OpenSSH's `pty_allocate` is `openpty()` then `ttyname(slave)`, and it
//! dies with "openpty returns device for which ttyname fails" when the
//! second fails. These cases issue the exact syscalls glibc makes:
//!
//! * `openpty`: `open("/dev/ptmx")`, `TIOCGPTN`, `TIOCSPTLCK(0)`, then
//!   `ioctl(master, TIOCGPTPEER, O_RDWR|O_NOCTTY)` — the slave is never
//!   opened by path.
//! * `ttyname` (sysdeps/unix/sysv/linux/ttyname.c): `TCGETS`, `fstat`,
//!   `readlink("/proc/self/fd/N")`, `stat` of the link target, which must be
//!   a character device with the fstat's `st_ino`/`st_dev`/`st_rdev`; failing
//!   that, a `getdents64` scan of `/dev/pts` for an entry whose `d_ino` is the
//!   fstat's `st_ino`.

use crate::abi_test_support::*;

const O_RDWR: u64 = 0o2;
const O_NOCTTY: u64 = 0o400;
const O_DIRECTORY: u64 = 0o200000;
const TCGETS: u64 = 0x5401;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGPTPEER: u64 = 0x5441;
const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;

/// `(st_dev, st_ino, st_rdev, st_mode)` out of a raw `struct stat`.
fn stat_ids(sb: &[u8]) -> (u64, u64, u64, u32) {
    (
        u64::from_ne_bytes(sb[0..8].try_into().unwrap()),
        u64::from_ne_bytes(sb[8..16].try_into().unwrap()),
        stat_rdev(sb),
        stat_mode(sb),
    )
}

fn close(fd: u64) {
    let _ = call(Syscall::Close.raw(), a0(fd));
}

/// glibc `posix_openpt` + `grantpt` (a no-op on devpts) + `unlockpt` +
/// `ptsname_r`: the master fd and the pts index.
fn open_master() -> Result<(u64, u32), &'static str> {
    let master = match call_open(c"/dev/ptmx".as_ptr() as u64, O_RDWR | O_NOCTTY) {
        Some(fd) if fd >= 0 => fd as u64,
        _ => return Err("open(/dev/ptmx) failed"),
    };
    let mut index: u32 = u32::MAX;
    if call(
        Syscall::Ioctl.raw(),
        a2(master, TIOCGPTN, &mut index as *mut u32 as u64),
    ) != Some(0)
    {
        close(master);
        return Err("TIOCGPTN failed on a fresh master");
    }
    let mut unlock: i32 = 0;
    if call(
        Syscall::Ioctl.raw(),
        a2(master, TIOCSPTLCK, &mut unlock as *mut i32 as u64),
    ) != Some(0)
    {
        close(master);
        return Err("TIOCSPTLCK(0) failed on a fresh master");
    }
    Ok((master, index))
}

/// glibc `ttyname(fd)`'s first, `/proc/self/fd` branch. `Ok(name)` is what
/// `ttyname` would return; an `Err` names the step that sent glibc to its
/// directory-scan fallback.
fn ttyname_via_proc(fd: u64) -> Result<alloc::string::String, &'static str> {
    let mut termios = [0u8; 64];
    if call(
        Syscall::Ioctl.raw(),
        a2(fd, TCGETS, termios.as_mut_ptr() as u64),
    ) != Some(0)
    {
        return Err("tcgetattr(TCGETS) failed on the pty slave");
    }
    let mut fsb = [0u8; 256];
    if call(Syscall::Fstat.raw(), a1(fd, fsb.as_mut_ptr() as u64)) != Some(0) {
        return Err("fstat failed on the pty slave");
    }
    let (fdev, fino, frdev, fmode) = stat_ids(&fsb);
    if fmode & S_IFMT != S_IFCHR {
        return Err("fstat of the pty slave is not S_IFCHR");
    }
    let link = alloc::format!("/proc/self/fd/{fd}\0");
    let mut target = [0u8; 128];
    let len = match call_readlink(link.as_ptr() as u64, target.as_mut_ptr() as u64, 127) {
        Some(n) if n > 0 => n as usize,
        _ => return Err("readlink(/proc/self/fd/N) failed for the pty slave"),
    };
    if target[0] != b'/' {
        return Err("readlink(/proc/self/fd/N) of the pty slave is not an absolute path");
    }
    // `target` is NUL-terminated: 127 of 128 bytes were offered.
    let mut tsb = [0u8; 256];
    if call_stat(target.as_ptr() as u64, tsb.as_mut_ptr() as u64) != Some(0) {
        return Err("stat of the /proc/self/fd/N target failed");
    }
    let (tdev, tino, trdev, tmode) = stat_ids(&tsb);
    if tmode & S_IFMT != S_IFCHR {
        return Err("the /proc/self/fd/N target is not a character device");
    }
    if tino != fino {
        return Err("st_ino of the link target differs from fstat of the slave");
    }
    if tdev != fdev {
        return Err("st_dev of the link target differs from fstat of the slave");
    }
    if trdev != frdev {
        return Err("st_rdev of the link target differs from fstat of the slave");
    }
    core::str::from_utf8(&target[..len])
        .map(alloc::string::String::from)
        .map_err(|_| "the /proc/self/fd/N target is not UTF-8")
}

/// `openpty` hands sshd a slave made by `TIOCGPTPEER`; `ttyname` of it is
/// `/dev/pts/<N>` through the `/proc/self/fd` link, exactly as
/// `ptm_open_peer`'s `dentry_open` of the devpts dentry yields on Linux.
fn smoke_abi_pty_ttyname_of_tiocgptpeer_slave() -> TestResult {
    with_setup(|| {
        let prev = narf_filesystem::procfs::__test_fd_path_hook_snapshot();
        narf_filesystem::procfs::__test_fd_path_hook_restore(crate::handlers::fd_path_of as usize);
        let outcome = (|| {
            let (master, index) = open_master()?;
            let slave = match call(
                Syscall::Ioctl.raw(),
                a2(master, TIOCGPTPEER, O_RDWR | O_NOCTTY),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => {
                    close(master);
                    return Err("TIOCGPTPEER did not return a slave fd");
                }
            };
            let name = ttyname_via_proc(slave);
            close(slave);
            close(master);
            if name? != alloc::format!("/dev/pts/{index}") {
                return Err("ttyname of the TIOCGPTPEER slave is not /dev/pts/<TIOCGPTN>");
            }
            Ok(())
        })();
        narf_filesystem::procfs::__test_fd_path_hook_restore(prev);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/pty",
    smoke_abi_pty_ttyname_of_tiocgptpeer_slave
);

/// The pre-`TIOCGPTPEER` `openpty`: `ptsname_r` then `open("/dev/pts/N")`.
fn smoke_abi_pty_ttyname_of_path_opened_slave() -> TestResult {
    with_setup(|| {
        let prev = narf_filesystem::procfs::__test_fd_path_hook_snapshot();
        narf_filesystem::procfs::__test_fd_path_hook_restore(crate::handlers::fd_path_of as usize);
        let outcome = (|| {
            let (master, index) = open_master()?;
            let path = alloc::format!("/dev/pts/{index}\0");
            let slave = match call_open(path.as_ptr() as u64, O_RDWR | O_NOCTTY) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => {
                    close(master);
                    return Err("open(/dev/pts/N) failed after unlockpt");
                }
            };
            let name = ttyname_via_proc(slave);
            close(slave);
            close(master);
            if name? != alloc::format!("/dev/pts/{index}") {
                return Err("ttyname of the path-opened slave is not /dev/pts/<TIOCGPTN>");
            }
            Ok(())
        })();
        narf_filesystem::procfs::__test_fd_path_hook_restore(prev);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/pty",
    smoke_abi_pty_ttyname_of_path_opened_slave
);

/// glibc `ttyname`'s fallback (`getttyname("/dev/pts", ...)`): the `/dev/pts`
/// entry named `<N>` carries the `d_ino` that `fstat` of the slave reports.
fn smoke_abi_pty_devpts_dirent_ino_matches_fstat() -> TestResult {
    with_setup(|| {
        let (master, index) = open_master()?;
        let slave = match call(
            Syscall::Ioctl.raw(),
            a2(master, TIOCGPTPEER, O_RDWR | O_NOCTTY),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => {
                close(master);
                return Err("TIOCGPTPEER did not return a slave fd");
            }
        };
        let mut fsb = [0u8; 256];
        let frc = call(Syscall::Fstat.raw(), a1(slave, fsb.as_mut_ptr() as u64));
        let (_, fino, _, _) = stat_ids(&fsb);
        let dir = call_open(c"/dev/pts".as_ptr() as u64, O_DIRECTORY);
        let want = alloc::format!("{index}");
        let mut found: Option<u64> = None;
        if let Some(dirfd) = dir.filter(|fd| *fd >= 0) {
            let mut buf = [0u8; 1024];
            loop {
                let n = match call(
                    Syscall::Getdents64.raw(),
                    a2(dirfd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
                ) {
                    Some(n) if n > 0 => n as usize,
                    _ => break,
                };
                let mut off = 0usize;
                while off + 19 <= n {
                    let ino = u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
                    let reclen =
                        u16::from_ne_bytes(buf[off + 16..off + 18].try_into().unwrap()) as usize;
                    if reclen == 0 || off + reclen > n {
                        break;
                    }
                    let name = &buf[off + 19..off + reclen];
                    let name = &name[..name.iter().position(|b| *b == 0).unwrap_or(name.len())];
                    if name == want.as_bytes() {
                        found = Some(ino);
                    }
                    off += reclen;
                }
            }
            close(dirfd as u64);
        }
        close(slave);
        close(master);
        if frc != Some(0) {
            return Err("fstat failed on the pty slave");
        }
        if !matches!(dir, Some(fd) if fd >= 0) {
            return Err("open(/dev/pts, O_DIRECTORY) failed");
        }
        match found {
            None => Err("getdents64(/dev/pts) has no entry for the live pty"),
            Some(ino) if ino != fino => {
                Err("d_ino of /dev/pts/<N> differs from fstat st_ino of the slave")
            }
            Some(_) => Ok(()),
        }
    })
}
kernel_test_in!(
    "syscall_abi/pty",
    smoke_abi_pty_devpts_dirent_ino_matches_fstat
);
