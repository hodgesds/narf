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

/// Send `fd` over a fresh AF_UNIX socketpair with SCM_RIGHTS and return the
/// descriptor `recvmsg` installed — how sshd's monitor hands the pty it
/// allocated to the session process (`mm_send_fd` / `mm_receive_fd`).
fn pass_fd(fd: u64) -> Result<u64, &'static str> {
    const AF_UNIX: u64 = 1;
    const SOCK_STREAM: u64 = 1;
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    let mut sv = [0u8; 8];
    if call(
        Syscall::SocketPair.raw(),
        a3(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as u64),
    ) != Some(0)
    {
        return Err("socketpair failed");
    }
    let tx = i32::from_ne_bytes([sv[0], sv[1], sv[2], sv[3]]) as u64;
    let rx = i32::from_ne_bytes([sv[4], sv[5], sv[6], sv[7]]) as u64;
    let outcome = (|| {
        let payload = [0u8; 1];
        let mut iov = [0u8; 16];
        iov[0..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
        iov[8..16].copy_from_slice(&1u64.to_ne_bytes());
        // cmsghdr (16) + one int, padded to 8.
        let mut ctrl = [0u8; 24];
        ctrl[0..8].copy_from_slice(&20u64.to_ne_bytes());
        ctrl[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
        ctrl[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
        ctrl[16..20].copy_from_slice(&(fd as i32).to_ne_bytes());
        let mut smsg = [0u8; 56];
        smsg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
        smsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        smsg[32..40].copy_from_slice(&(ctrl.as_ptr() as u64).to_ne_bytes());
        smsg[40..48].copy_from_slice(&24u64.to_ne_bytes());
        if call(
            Syscall::SocketSendMsg.raw(),
            a2(tx, smsg.as_ptr() as u64, 0),
        ) != Some(1)
        {
            return Err("sendmsg(SCM_RIGHTS) failed");
        }
        let mut byte = [0u8; 1];
        let mut riov = [0u8; 16];
        riov[0..8].copy_from_slice(&(byte.as_mut_ptr() as u64).to_ne_bytes());
        riov[8..16].copy_from_slice(&1u64.to_ne_bytes());
        let mut rctrl = [0u8; 64];
        let mut rmsg = [0u8; 56];
        rmsg[16..24].copy_from_slice(&(riov.as_ptr() as u64).to_ne_bytes());
        rmsg[24..32].copy_from_slice(&1u64.to_ne_bytes());
        rmsg[32..40].copy_from_slice(&(rctrl.as_mut_ptr() as u64).to_ne_bytes());
        rmsg[40..48].copy_from_slice(&64u64.to_ne_bytes());
        if call(
            Syscall::SocketRecvMsg.raw(),
            a2(rx, rmsg.as_mut_ptr() as u64, 0),
        ) != Some(1)
        {
            return Err("recvmsg of the SCM_RIGHTS message failed");
        }
        let ctrllen = u64::from_ne_bytes(rmsg[40..48].try_into().unwrap());
        let level = i32::from_ne_bytes(rctrl[8..12].try_into().unwrap());
        let ctype = i32::from_ne_bytes(rctrl[12..16].try_into().unwrap());
        let received = i32::from_ne_bytes(rctrl[16..20].try_into().unwrap());
        if ctrllen < 20 || level != SOL_SOCKET || ctype != SCM_RIGHTS || received < 0 {
            return Err("recvmsg did not install the passed descriptor");
        }
        Ok(received as u64)
    })();
    close(tx);
    close(rx);
    outcome
}

/// A descriptor received over SCM_RIGHTS is the sender's open file
/// (`scm_fp_dup` / `receive_fd`), so `/proc/self/fd/N` names the same path:
/// the pty sshd's monitor allocated is still `/dev/pts/<N>` to `ttyname` in
/// the session process that receives it and makes it stdin.
fn smoke_abi_pty_ttyname_of_scm_rights_slave() -> TestResult {
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
            let received = pass_fd(slave);
            let name = received.and_then(ttyname_via_proc);
            if let Ok(fd) = received {
                close(fd);
            }
            close(slave);
            close(master);
            if name? != alloc::format!("/dev/pts/{index}") {
                return Err("ttyname of the received slave is not /dev/pts/<TIOCGPTN>");
            }
            Ok(())
        })();
        narf_filesystem::procfs::__test_fd_path_hook_restore(prev);
        outcome
    })
}
kernel_test_in!("syscall_abi/pty", smoke_abi_pty_ttyname_of_scm_rights_slave);

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
