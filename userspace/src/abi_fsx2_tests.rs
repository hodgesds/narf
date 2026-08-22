//! Linux syscall ABI conformance — fsx group, audit round 2.
//!
//! Additional regression pins for handler branches the first-pass
//! `abi_fsx_tests.rs` leaves uncovered:
//!   - xattr cores: EFAULT on a bad path/value pointer, EINVAL on an empty
//!     name in the get/list/remove cores, ERANGE on an undersized *get*
//!     buffer (the first file only pins ERANGE on the *list* path), and the
//!     XATTR_CREATE/XATTR_REPLACE flag branches (EEXIST / ENODATA).
//!   - name_to_handle_at: EINVAL (empty path), EFAULT (bad handle buf),
//!     EOVERFLOW (caller capacity smaller than the path).
//!   - open_by_handle_at: EINVAL (right handle type, zero handle_bytes),
//!     EFAULT (unreadable handle pointer).
//!   - mount: bind-mount success path; -1 sentinel on an unreadable target.
//!   - new-mount-API: fsconfig ENODEV (un-buildable fsname) + tmpfs
//!     FSCONFIG_SET_STRING application; move_mount EINVAL (valid fd, relative target);
//!     open_tree ENOENT (absolute path, no mount); fspick EINVAL (relative);
//!     mount_setattr EINVAL on the size>64 upper bound.
//!
//! Shares the harness in [`crate::abi_test_support`]; every test drives
//! `kernel_syscall_entry` through a synthetic `AbiCtx`.
#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// Wire values not in the shared harness set.
const ENODATA: i64 = -61;
const EOVERFLOW: i64 = -75;

// Linux setxattr flags.
const XATTR_CREATE: u64 = 1;
const XATTR_REPLACE: u64 = 2;

// new-mount-API fsconfig commands.
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_CMD_CREATE: u64 = 6;

// Open a MemFs-backed file via the (linux-compat) open syscall.
fn open_memfs_fd(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, 0) {
        Some(v) if v >= 0 => Ok(v as u32),
        _ => Err("open of seeded MemFs file should yield an fd"),
    }
}

// ── /proc/self/mountinfo: open/read reaches the live renderer ─────────
// systemd synchronously rescans this file after each mount helper exits. It
// is not enough for the userspace hook to format the right rows: the procfs
// pathname, open fd, and read syscall must deliver non-empty content at
// offset zero, including a mount that was just attached.
fn smoke_abi_fsx2_proc_self_mountinfo_reads_content() -> TestResult {
    with_setup(|| {
        const TARGET: &[u8] = b"/abi-mountinfo-live\0";
        let path = b"/proc/self/mountinfo\0";
        let fstype = b"tmpfs\0";
        // The kernel-test build does not run the normal boot hook wiring.
        // `/proc/self` needs the live pid/task hooks before ProcFs can descend
        // through the caller's per-pid directory.
        narf_filesystem::procfs::install_proc_hooks(
            crate::handlers::proc_current_pid,
            crate::handlers::proc_list_pids,
            crate::handlers::proc_task_info,
        );
        narf_filesystem::procfs::install_mountinfo_hook(crate::handlers::proc_ns_mountinfo);
        narf_filesystem::procfs::install_mountinfo_generation_hook(
            crate::handlers::proc_ns_mountinfo_generation,
        );
        if !narf_filesystem::registry()
            .list()
            .iter()
            .any(|mount| mount == "/proc")
        {
            return Err("/proc mount vanished before mountinfo ABI test");
        }
        if mount_fstype(TARGET, fstype) != Some(0) {
            return Err("mountinfo setup mount failed");
        }
        let fd = match call(
            Syscall::Openat.raw(),
            a3((-100i64) as u64, path.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            Some(-2) => return Err("open /proc/self/mountinfo returned ENOENT"),
            Some(-1) => return Err("open /proc/self/mountinfo returned the failure sentinel"),
            Some(_) => return Err("open /proc/self/mountinfo returned an unexpected errno"),
            None => return Err("open /proc/self/mountinfo did not return a Linux ABI result"),
        };
        let mut buf = [0u8; 4096];
        let read = call(
            Syscall::Read.raw(),
            a2(fd, buf.as_mut_ptr() as u64, buf.len() as u64),
        );
        let _ = call(Syscall::Close.raw(), a0(fd));
        let n = match read {
            Some(n) if n > 0 => n as usize,
            _ => return Err("read /proc/self/mountinfo returned no content"),
        };
        if core::str::from_utf8(&buf[..n])
            .ok()
            .is_some_and(|body| body.contains("/abi-mountinfo-live"))
        {
            Ok(())
        } else {
            Err("mountinfo read omitted the newly attached mount")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_proc_self_mountinfo_reads_content
);

// Linux signals POLLPRI on an already-open mountinfo file whenever the
// caller's mount namespace changes. libmount (and therefore systemd) uses
// that edge to decide when it must rescan after a mount helper exits.
fn smoke_abi_fsx2_proc_mountinfo_pollpri_after_mount_change() -> TestResult {
    with_setup(|| {
        let path = b"/proc/self/mountinfo\0";
        let fstype = b"tmpfs\0";
        let target = b"/abi-mountinfo-poll-edge\0";
        narf_filesystem::procfs::install_proc_hooks(
            crate::handlers::proc_current_pid,
            crate::handlers::proc_list_pids,
            crate::handlers::proc_task_info,
        );
        narf_filesystem::procfs::install_mountinfo_hook(crate::handlers::proc_ns_mountinfo);
        narf_filesystem::procfs::install_mountinfo_generation_hook(
            crate::handlers::proc_ns_mountinfo_generation,
        );

        let fd = match call(
            Syscall::Openat.raw(),
            a3((-100i64) as u64, path.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("open /proc/self/mountinfo before its change failed"),
        };
        let file = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("mountinfo fd was not installed")?;
        if file.poll_readiness() & narf_filesystem::POLL_PRI != 0 {
            return Err("a fresh mountinfo fd must not report a stale POLLPRI edge");
        }
        if mount_fstype(target, fstype) != Some(0) {
            return Err("mount change setup failed");
        }
        let changed = file.poll_readiness();
        if changed & (narf_filesystem::POLL_PRI | narf_filesystem::POLL_ERR)
            != narf_filesystem::POLL_PRI | narf_filesystem::POLL_ERR
        {
            return Err("mountinfo must report POLLPRI|POLLERR after a mount-table change");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_proc_mountinfo_pollpri_after_mount_change
);

// libmount registers the already-open mountinfo file for EPOLLIN|EPOLLET,
// drains its initial readable event, then relies on Linux's unconditional
// POLLERR mount-change edge to re-wake the monitor after a mount helper exits.
// Exercise those exact flags through the syscall ABI rather than calling
// FileOps directly.
fn smoke_abi_fsx2_proc_mountinfo_libmount_epollet_after_mount_change() -> TestResult {
    with_setup(|| {
        let path = b"/proc/self/mountinfo\0";
        let fstype = b"tmpfs\0";
        let target = b"/abi-mountinfo-epoll-edge\0";
        narf_filesystem::procfs::install_proc_hooks(
            crate::handlers::proc_current_pid,
            crate::handlers::proc_list_pids,
            crate::handlers::proc_task_info,
        );
        narf_filesystem::procfs::install_mountinfo_hook(crate::handlers::proc_ns_mountinfo);
        narf_filesystem::procfs::install_mountinfo_generation_hook(
            crate::handlers::proc_ns_mountinfo_generation,
        );

        let mountinfo_fd = match call(
            Syscall::Openat.raw(),
            a3((-100i64) as u64, path.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open /proc/self/mountinfo for epoll failed"),
        };
        let epfd = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("epoll_create1 failed"),
        };
        let mut interest = [0u8; 12];
        interest[..4]
            .copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
        interest[4..].copy_from_slice(&0x4d4f554e545f5052_u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            SyscallArgs {
                arg0: epfd,
                arg1: crate::epoll::EPOLL_CTL_ADD as u64,
                arg2: mountinfo_fd,
                arg3: interest.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("epoll_ctl(ADD, EPOLLIN|EPOLLET mountinfo) failed");
        }
        let mut events = [0u8; 12];
        let initial = call(
            Syscall::EpollWait.raw(),
            SyscallArgs {
                arg0: epfd,
                arg1: events.as_mut_ptr() as u64,
                arg2: 1,
                ..Default::default()
            },
        );
        let initial_mask = u32::from_ne_bytes(events[..4].try_into().unwrap());
        if initial != Some(1) || initial_mask & crate::epoll::EPOLLIN == 0 {
            return Err("libmount must receive mountinfo's initial EPOLLIN edge");
        }
        if call(
            Syscall::EpollWait.raw(),
            SyscallArgs {
                arg0: epfd,
                arg1: events.as_mut_ptr() as u64,
                arg2: 1,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("drained mountinfo EPOLLET monitor must be quiet before a change");
        }
        if mount_fstype(target, fstype) != Some(0) {
            return Err("mount change setup failed");
        }
        let ready = call(
            Syscall::EpollWait.raw(),
            SyscallArgs {
                arg0: epfd,
                arg1: events.as_mut_ptr() as u64,
                arg2: 1,
                ..Default::default()
            },
        );
        let event_mask = u32::from_ne_bytes(events[..4].try_into().unwrap());
        let _ = call(Syscall::Close.raw(), a0(epfd));
        let _ = call(Syscall::Close.raw(), a0(mountinfo_fd));
        if ready == Some(1) && event_mask & crate::epoll::EPOLLERR != 0 {
            Ok(())
        } else {
            Err("mountinfo generation change must re-wake libmount via EPOLLERR")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_proc_mountinfo_libmount_epollet_after_mount_change
);

// systemd puts libmount's EPOLLIN|EPOLLET mountinfo monitor inside its
// manager epoll. A passive readiness query of that nested epoll must not
// consume the mountinfo change before libmount drains the inner epoll after
// SIGCHLD. This is the topology used by mount_sigchld_event().
fn smoke_abi_fsx2_proc_mountinfo_nested_epoll_preserves_change() -> TestResult {
    with_setup(|| {
        let path = b"/proc/self/mountinfo\0";
        let fstype = b"tmpfs\0";
        let target = b"/abi-mountinfo-nested-epoll-edge\0";
        narf_filesystem::procfs::install_proc_hooks(
            crate::handlers::proc_current_pid,
            crate::handlers::proc_list_pids,
            crate::handlers::proc_task_info,
        );
        narf_filesystem::procfs::install_mountinfo_hook(crate::handlers::proc_ns_mountinfo);
        narf_filesystem::procfs::install_mountinfo_generation_hook(
            crate::handlers::proc_ns_mountinfo_generation,
        );

        let mountinfo_fd = match call(
            Syscall::Openat.raw(),
            a3((-100i64) as u64, path.as_ptr() as u64, 0, 0),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open /proc/self/mountinfo for nested epoll failed"),
        };
        let inner = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("inner epoll_create failed"),
        };
        let outer = match call(Syscall::EpollCreate.raw(), a0(0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("outer epoll_create failed"),
        };
        let mut mount_interest = [0u8; 12];
        mount_interest[..4]
            .copy_from_slice(&(crate::epoll::EPOLLIN | crate::epoll::EPOLLET).to_ne_bytes());
        mount_interest[4..].copy_from_slice(&0x4d4f554e545f4e53_u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            SyscallArgs {
                arg0: inner,
                arg1: crate::epoll::EPOLL_CTL_ADD as u64,
                arg2: mountinfo_fd,
                arg3: mount_interest.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("inner epoll_ctl(ADD, mountinfo) failed");
        }
        let mut outer_interest = [0u8; 12];
        outer_interest[..4].copy_from_slice(&crate::epoll::EPOLLIN.to_ne_bytes());
        outer_interest[4..].copy_from_slice(&0x4d4f554e545f4f55_u64.to_ne_bytes());
        if call(
            Syscall::EpollCtl.raw(),
            SyscallArgs {
                arg0: outer,
                arg1: crate::epoll::EPOLL_CTL_ADD as u64,
                arg2: inner,
                arg3: outer_interest.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("outer epoll_ctl(ADD, libmount monitor) failed");
        }
        let mut events = [0u8; 12];
        // libmount drains the ordinary initial EPOLLIN edge before the
        // manager begins its event loop.
        if call(
            Syscall::EpollWait.raw(),
            SyscallArgs {
                arg0: inner,
                arg1: events.as_mut_ptr() as u64,
                arg2: 1,
                ..Default::default()
            },
        ) != Some(1)
        {
            return Err("inner mountinfo monitor must receive its initial edge");
        }
        if mount_fstype(target, fstype) != Some(0) {
            return Err("nested epoll mount change setup failed");
        }
        let outer_ready = call(
            Syscall::EpollWait.raw(),
            SyscallArgs {
                arg0: outer,
                arg1: events.as_mut_ptr() as u64,
                arg2: 1,
                ..Default::default()
            },
        );
        let outer_mask = u32::from_ne_bytes(events[..4].try_into().unwrap());
        let inner_ready = call(
            Syscall::EpollWait.raw(),
            SyscallArgs {
                arg0: inner,
                arg1: events.as_mut_ptr() as u64,
                arg2: 1,
                ..Default::default()
            },
        );
        let inner_mask = u32::from_ne_bytes(events[..4].try_into().unwrap());
        let _ = call(Syscall::Close.raw(), a0(outer));
        let _ = call(Syscall::Close.raw(), a0(inner));
        let _ = call(Syscall::Close.raw(), a0(mountinfo_fd));
        if outer_ready == Some(1)
            && outer_mask & crate::epoll::EPOLLIN != 0
            && inner_ready == Some(1)
            && inner_mask & crate::epoll::EPOLLERR != 0
        {
            Ok(())
        } else {
            Err("nested epoll probe must leave the mountinfo change for libmount to drain")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_proc_mountinfo_nested_epoll_preserves_change
);

// ── setxattr: EFAULT on a NULL path pointer ───────────────────────────
//
// sys_setxattr → xattr_user_path(arg0); a 0/zero pointer yields None →
// the handler's second branch: ok(-EFAULT). The first file only pins the
// EINVAL (empty-name) core branch and the 0 success branch.

fn smoke_abi_fsx2_setxattr_efault_neg() -> TestResult {
    with_setup(|| {
        let name = b"user.k\0";
        let val = b"v";
        let args = SyscallArgs {
            arg0: 0, // bad path pointer → xattr_user_path None
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("setxattr with a NULL path pointer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_efault_neg);

// ── setxattr: EFAULT on a bad value pointer (size > 0) ────────────────
//
// xattr_set_core: name is valid, size != 0, so copy_from_user_vec(arg2)
// runs; a bogus value pointer fails → ok(-EFAULT).

fn smoke_abi_fsx2_setxattr_value_efault_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/vf\0";
        let name = b"user.vf\0";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0x0001_0000_0000_0000, // unmapped value pointer
            arg3: 8,                     // size != 0 forces the copy
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("setxattr with a bad value pointer (size>0) must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_value_efault_neg);

// ── setxattr: XATTR_REPLACE on a missing attribute → ENODATA ──────────
//
// xattr_set_core flag branch: flags & XATTR_REPLACE && !exists → ok(-ENODATA).

fn smoke_abi_fsx2_setxattr_replace_missing_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/repl\0";
        let name = b"user.repl\0";
        let val = b"v";
        let args = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: XATTR_REPLACE,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), args) {
            Some(v) if v == ENODATA => Ok(()),
            _ => Err("setxattr XATTR_REPLACE of an unset attribute must return -ENODATA"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_replace_missing_neg);

// ── setxattr: XATTR_CREATE on an existing attribute → EEXIST ──────────
//
// Seed once, then re-set with XATTR_CREATE: flags & XATTR_CREATE && exists
// → ok(-EEXIST). This is the positive-feature path for the create flag.

fn smoke_abi_fsx2_setxattr_create_exists_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/cre\0";
        let name = b"user.cre\0";
        let val = b"v";
        let seed = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), seed) != Some(0) {
            return Err("seed setxattr failed");
        }
        let again = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: XATTR_CREATE,
            ..Default::default()
        };
        match call(Syscall::Setxattr.raw(), again) {
            Some(v) if v == EEXIST => Ok(()),
            _ => Err("setxattr XATTR_CREATE on an existing attribute must return -EEXIST"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_setxattr_create_exists_pos);

// ── getxattr: ERANGE on an undersized destination buffer ──────────────
//
// xattr_get_core: name valid, value present, size != 0 but size < value.len()
// → ok(-ERANGE). The first file only pins getxattr(size=0) and the missing
// (ENODATA) case; ERANGE on the *value* buffer is unhit there.

fn smoke_abi_fsx2_getxattr_erange_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/ge\0";
        let name = b"user.ge\0";
        let val = b"abcdefgh"; // 8 bytes
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        let mut buf = [0u8; 4];
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: 4, // < 8 → ERANGE
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("getxattr with an undersized value buffer must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_getxattr_erange_neg);

// ── getxattr: full copy-out success path ──────────────────────────────
//
// size >= value.len() drives the copy_to_user branch and returns the value
// length. The first file only exercises getxattr(size=0) (length probe).

fn smoke_abi_fsx2_getxattr_copyout_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/gc\0";
        let name = b"user.gc\0";
        let val = b"wxyz"; // 4 bytes
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        let mut buf = [0u8; 8];
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: 8, // >= 4 → copy out, return len
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == val.len() as i64 && &buf[..4] == val => Ok(()),
            _ => Err("getxattr(size>=len) should copy the value and return its length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_getxattr_copyout_pos);

// ── getxattr: EINVAL on an empty name ─────────────────────────────────
//
// xattr_get_core rejects an empty name before any lookup. Distinct from the
// first file's getxattr ENODATA (unset attribute) case.

fn smoke_abi_fsx2_getxattr_emptyname_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/gn\0";
        let name = b"\0"; // empty → EINVAL
        let gargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: 0,
            arg3: 0,
            ..Default::default()
        };
        match call(Syscall::Getxattr.raw(), gargs) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("getxattr with an empty name must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_getxattr_emptyname_neg);

// ── listxattr: full copy-out success path ─────────────────────────────
//
// size >= names.len() drives the copy_to_user branch in xattr_list_core and
// returns the list length with the buffer populated. The first file only
// pins listxattr(size=0) and the ERANGE case.

fn smoke_abi_fsx2_listxattr_copyout_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/lc\0";
        let name = b"user.lc\0"; // "user.lc\0" = 8 bytes
        let val = b"v";
        let sargs = SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Setxattr.raw(), sargs) != Some(0) {
            return Err("seed setxattr failed");
        }
        let mut buf = [0u8; 16];
        let largs = a2(path.as_ptr() as u64, buf.as_mut_ptr() as u64, 16);
        match call(Syscall::Listxattr.raw(), largs) {
            Some(8) if &buf[..8] == b"user.lc\0" => Ok(()),
            _ => Err("listxattr(size>=len) should copy the name list and return its length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_listxattr_copyout_pos);

// ── listxattr: empty list (no attrs) → 0 ──────────────────────────────
//
// A path with no stored attributes yields an empty name list; size=0 returns
// 0 (not an error). Pins the "names empty, size 0" exit.

fn smoke_abi_fsx2_listxattr_empty_pos() -> TestResult {
    with_setup(|| {
        let path = b"/abi/empty-list\0";
        let largs = a2(path.as_ptr() as u64, 0, 0);
        match call(Syscall::Listxattr.raw(), largs) {
            Some(0) => Ok(()),
            _ => Err("listxattr(size=0) of a path with no attrs should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_listxattr_empty_pos);

// ── removexattr: EINVAL on an empty name ──────────────────────────────
//
// xattr_remove_core rejects an empty name. The first file pins removexattr
// ENODATA (unset attribute) but not the empty-name branch.

fn smoke_abi_fsx2_removexattr_emptyname_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi/rn\0";
        let name = b"\0"; // empty → EINVAL
        let rargs = a1(path.as_ptr() as u64, name.as_ptr() as u64);
        match call(Syscall::Removexattr.raw(), rargs) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("removexattr with an empty name must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_removexattr_emptyname_neg);

// ── fgetxattr: ERANGE on an undersized fd-keyed buffer ────────────────
//
// fd-keyed get core hits the same ERANGE branch; the first file only pins
// fgetxattr(size=0) and the EBADF case.

fn smoke_abi_fsx2_fgetxattr_erange_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let fd = open_memfs_fd(b"/abi/f\0")?;
        let name = b"user.fe\0";
        let val = b"longvalue"; // 9 bytes
        let sargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: val.as_ptr() as u64,
            arg3: val.len() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Fsetxattr.raw(), sargs) != Some(0) {
            return Err("seed fsetxattr failed");
        }
        let mut buf = [0u8; 4];
        let gargs = SyscallArgs {
            arg0: fd as u64,
            arg1: name.as_ptr() as u64,
            arg2: buf.as_mut_ptr() as u64,
            arg3: 4, // < 9 → ERANGE
            ..Default::default()
        };
        match call(Syscall::Fgetxattr.raw(), gargs) {
            Some(v) if v == ERANGE => Ok(()),
            _ => Err("fgetxattr with an undersized buffer must return -ERANGE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fgetxattr_erange_neg);

// ── name_to_handle_at: EINVAL on an empty path ────────────────────────
//
// sys_name_to_handle_at rejects an empty path BEFORE the existence check.
// The first file pins ENOENT (missing path) and 0 (success), not EINVAL.

fn smoke_abi_fsx2_name_to_handle_at_einval_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"\0"; // empty → EINVAL
        let mut hbuf = [0u8; 64];
        hbuf[0..4].copy_from_slice(&32u32.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("name_to_handle_at with an empty path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_einval_neg);

// ── name_to_handle_at: EOVERFLOW when capacity < path length ──────────
//
// Existing path, but the caller's handle_bytes (first u32 of arg2) is
// smaller than the path length → the handler writes the needed size back
// and returns -EOVERFLOW. "/abi/f" is 6 bytes; advertise capacity 2.

fn smoke_abi_fsx2_name_to_handle_at_overflow_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        let cap: u32 = 2; // < 6 → EOVERFLOW
        hbuf[0..4].copy_from_slice(&cap.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == EOVERFLOW => {
                // Handler should have written the required size (6) back.
                let needed = u32::from_ne_bytes(hbuf[0..4].try_into().unwrap());
                if needed == 6 {
                    Ok(())
                } else {
                    Err("name_to_handle_at EOVERFLOW should report the required size")
                }
            }
            _ => Err("name_to_handle_at with too-small capacity must return -EOVERFLOW"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_overflow_neg);

// ── name_to_handle_at: 8-byte inode handle when capacity is exactly 8 ──
//
// A caller advertising an exactly-8-byte f_handle (e.g. systemd's
// cg_path_get_cgroupid) gets the object's inode in a single u64, as Linux
// returns, rather than the path-carrying handle form.

fn smoke_abi_fsx2_name_to_handle_at_inode_form() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        let cap: u32 = 8;
        hbuf[0..4].copy_from_slice(&cap.to_ne_bytes());
        let args = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(0) => {
                // handle_bytes must read back as exactly 8, and the 8-byte
                // f_handle (the inode) must be nonzero.
                let hb = u32::from_ne_bytes(hbuf[0..4].try_into().unwrap());
                let ino = u64::from_ne_bytes(hbuf[8..16].try_into().unwrap());
                if hb != 8 {
                    Err("cap==8 handle_bytes not 8")
                } else if ino == 0 {
                    Err("cap==8 inode handle is zero")
                } else {
                    Ok(())
                }
            }
            _ => Err("name_to_handle_at cap==8 did not succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_inode_form);

// ── open(O_WRONLY) then fcntl(F_GETFL) reports the access mode ─────────
//
// glibc's fdopen(fd, "w") reads the fd's access mode via F_GETFL and
// rejects the stream with EINVAL unless it matches the requested mode.
// systemd fdopens a cgroup.procs it opened O_WRONLY, so the fd must
// report O_WRONLY (not just the settable status-flag bits).
fn smoke_abi_fsx2_open_wronly_fgetfl_access_mode() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        const O_WRONLY: u64 = 1;
        const F_GETFL: u64 = 3;
        const O_ACCMODE: u64 = 3;
        let path = b"/abi/f\0";
        let fd = match call_open(path.as_ptr() as u64, O_WRONLY) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("open O_WRONLY of a seeded MemFs file failed"),
        };
        match call(Syscall::Fcntl.raw(), a2(fd, F_GETFL, 0)) {
            Some(fl) if (fl as u64 & O_ACCMODE) == O_WRONLY => Ok(()),
            _ => Err("F_GETFL did not report the O_WRONLY access mode"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_wronly_fgetfl_access_mode);

// ── memfd_create returns an O_RDWR fd (F_GETFL access mode) ────────────
//
// Linux memfd_create(2) always hands back a read+write fd. glibc/musl
// fdopen(fd, "w+") reads F_GETFL and rejects the stream with EINVAL
// unless the access mode is O_RDWR. systemd 257 serializes sd-executor
// state to a memfd it then fdopens "w+", so the fd must report O_RDWR.
fn smoke_abi_fsx2_memfd_create_fgetfl_rdwr() -> TestResult {
    with_setup(|| {
        const F_GETFL: u64 = 3;
        const O_ACCMODE: u64 = 3;
        const O_RDWR: u64 = 2;
        let name = b"abi-memfd\0";
        let fd = match call(Syscall::MemfdCreate.raw(), a1(name.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("memfd_create failed"),
        };
        match call(Syscall::Fcntl.raw(), a2(fd, F_GETFL, 0)) {
            Some(fl) if (fl as u64 & O_ACCMODE) == O_RDWR => Ok(()),
            _ => Err("memfd_create fd did not report the O_RDWR access mode"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_memfd_create_fgetfl_rdwr);

// ── name_to_handle_at: EFAULT on an unreadable handle buffer ──────────
//
// Existing path, but arg2 (the handle buffer whose first u32 is read) is
// unmapped → copy_from_user fails → -EFAULT.

fn smoke_abi_fsx2_name_to_handle_at_efault_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let args = a3(0, path.as_ptr() as u64, 0x0001_0000_0000_0000, 0);
        match call(Syscall::NameToHandleAt.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("name_to_handle_at with an unreadable handle buffer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_name_to_handle_at_efault_neg);

// ── open_by_handle_at: EINVAL on zero handle_bytes (right type) ───────
//
// htype matches NARF_HANDLE_TYPE, but handle_bytes == 0 → -EINVAL. The
// first file pins ESTALE (wrong type) and the success path, not this branch.
// The correct handle type is whatever name_to_handle_at stamps, so we mint a
// real header first then zero its handle_bytes field.

fn smoke_abi_fsx2_open_by_handle_at_einval_neg() -> TestResult {
    with_memfs("/abi", "abi", &[("f", b"hi")], || {
        let path = b"/abi/f\0";
        let mut hbuf = [0u8; 64];
        hbuf[0..4].copy_from_slice(&56u32.to_ne_bytes());
        let nargs = a3(0, path.as_ptr() as u64, hbuf.as_mut_ptr() as u64, 0);
        if call(Syscall::NameToHandleAt.raw(), nargs) != Some(0) {
            return Err("name_to_handle_at setup failed");
        }
        // Keep the (correct) handle_type at bytes 4..8, zero handle_bytes.
        hbuf[0..4].copy_from_slice(&0u32.to_ne_bytes());
        let oargs = a2(0, hbuf.as_ptr() as u64, 0);
        match call(Syscall::OpenByHandleAt.raw(), oargs) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("open_by_handle_at with zero handle_bytes must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_by_handle_at_einval_neg);

// ── open_by_handle_at: EFAULT on an unreadable handle pointer ─────────
//
// arg1 unmapped → the 8-byte header copy_from_user fails → -EFAULT.

fn smoke_abi_fsx2_open_by_handle_at_efault_neg() -> TestResult {
    with_setup(|| {
        let oargs = a2(0, 0x0001_0000_0000_0000, 0);
        match call(Syscall::OpenByHandleAt.raw(), oargs) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("open_by_handle_at with an unreadable handle pointer must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_by_handle_at_efault_neg);

// ── mount: bind-mount success path ────────────────────────────────────
//
// fstype=="bind" routes to registry().bind_mount(source, target). Bind a
// freshly-mounted tmpfs onto a second path. The first file only covers the
// tmpfs and block-device branches.

fn smoke_abi_fsx2_mount_bind_pos() -> TestResult {
    with_setup(|| {
        // Seed a real source mount so bind_mount has something to clone.
        // Linux mount(2) ABI: (source, target, fstype, flags, data), NUL-term.
        let src_source = b"none\0";
        let src_target = b"/abi-bind-src\0";
        let tmpfs = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: src_source.as_ptr() as u64,
            arg1: src_target.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("source tmpfs setup mount failed");
        }
        // Now bind /abi-bind-src → /abi-bind-dst.
        let target = b"/abi-bind-dst\0";
        let fstype = b"bind\0";
        let args = SyscallArgs {
            arg0: src_target.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("bind mount of an existing source onto a fresh target should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_pos);

fn smoke_abi_fsx2_mount_bind_subdir_pos() -> TestResult {
    with_setup(|| {
        let src_source = b"none\0";
        let src_target = b"/abi-bind-tree\0";
        let tmpfs = b"tmpfs\0";
        let margs = SyscallArgs {
            arg0: src_source.as_ptr() as u64,
            arg1: src_target.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), margs) != Some(0) {
            return Err("subdirectory bind source mount failed");
        }
        let subdir = b"/abi-bind-tree/subdir\0";
        let mkdir = a2(subdir.as_ptr() as u64, 0o755, 0);
        if call(Syscall::Mkdir.raw(), mkdir) != Some(0) {
            return Err("subdirectory bind source mkdir failed");
        }
        let target = b"/abi-bind-subdir-dst\0";
        const MS_BIND: u64 = 1 << 12;
        let bind = SyscallArgs {
            arg0: subdir.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), bind) {
            Some(0) => Ok(()),
            _ => Err("bind mount of an ordinary subdirectory must return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_subdir_pos);

// mount(2) resolves both source and target symlinks before attaching a bind
// mount. Fedora's /var/mail -> spool/mail exercises this during the
// accounts-daemon sandbox setup: binding the symlink inode would make it a
// file-rooted mount and later namespace operations fail with EINVAL.
fn smoke_abi_fsx2_mount_bind_symlink_directory_pos() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let root = b"/abi-bind-symlink\0";
        let tmpfs = b"tmpfs\0";
        let mount = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: root.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), mount) != Some(0) {
            return Err("symlink-bind source tmpfs setup mount failed");
        }

        let actual = b"/abi-bind-symlink/spool\0";
        if call(Syscall::Mkdir.raw(), a2(actual.as_ptr() as u64, 0o755, 0)) != Some(0) {
            return Err("symlink-bind destination directory creation failed");
        }
        let target = b"spool\0";
        let link = b"/abi-bind-symlink/mail\0";
        if call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) != Some(0) {
            return Err("symlink-bind source symlink creation failed");
        }

        const MS_BIND: u64 = 1 << 12;
        let bind = SyscallArgs {
            arg0: link.as_ptr() as u64,
            arg1: link.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), bind) != Some(0) {
            return Err("bind mount through a directory symlink must succeed");
        }

        let canonical_is_dir = narf_filesystem::registry()
            .with_mount("/abi-bind-symlink/spool", |fs| fs.root_file().is_none())
            .unwrap_or(false);
        let raw_symlink_was_not_mounted = !narf_filesystem::registry()
            .list()
            .iter()
            .any(|path| path == "/abi-bind-symlink/mail");
        // These mounts live in the global registry in this ABI smoke. Pop
        // them before returning so later tests start from the documented
        // empty mount view.
        let _ = call(Syscall::Umount2.raw(), a1(actual.as_ptr() as u64, 0));
        let _ = call(Syscall::Umount2.raw(), a1(link.as_ptr() as u64, 0));
        let _ = call(Syscall::Umount2.raw(), a1(root.as_ptr() as u64, 0));
        if canonical_is_dir && raw_symlink_was_not_mounted {
            Ok(())
        } else {
            Err("bind mount must attach at the directory resolved through source and target symlinks")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_mount_bind_symlink_directory_pos
);

fn smoke_abi_fsx2_mount_bind_file_to_self_pos() -> TestResult {
    with_memfs(
        "/abi-self-bind",
        "self-bind",
        &[("control", b"value")],
        || {
            let path = b"/abi-self-bind/control\0";
            const MS_BIND: u64 = 1 << 12;
            let bind = SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND,
                ..Default::default()
            };
            match call(Syscall::Mount.raw(), bind) {
                Some(0) => Ok(()),
                _ => Err("bind-mounting a live file onto itself should succeed"),
            }
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_file_to_self_pos);

fn smoke_abi_fsx2_mount_bind_proc_file_alias_pos() -> TestResult {
    with_setup(|| {
        // systemd constructs service namespaces under a staging procfs mount,
        // then protects individual controls by binding them onto the matching
        // file in the visible /proc mount.
        narf_filesystem::procfs::sys_kernel::register_all();
        let source = b"proc\0";
        let staging = b"/abi-proc-staging\0";
        let procfs = b"proc\0";
        let mount = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: staging.as_ptr() as u64,
            arg2: procfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), mount) != Some(0) {
            return Err("staging procfs mount failed");
        }

        let staged_file = b"/abi-proc-staging/sys/kernel/domainname\0";
        let visible_file = b"/proc/sys/kernel/domainname\0";
        const MS_BIND: u64 = 1 << 12;
        let bind = SyscallArgs {
            arg0: staged_file.as_ptr() as u64,
            arg1: visible_file.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), bind) {
            Some(0) => Ok(()),
            _ => Err("same procfs file through two mountpoints must bind successfully"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_bind_proc_file_alias_pos);

fn smoke_abi_fsx2_mount_bind_remount_private_file_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MS_RDONLY: u64 = 1;
        const MS_REMOUNT: u64 = 1 << 5;
        const MS_BIND: u64 = 1 << 12;

        let result = (|| {
            // Direct PID 1 runs with its root published at /mnt. Exercise
            // the same root-relative paths that systemd hands to mount(2),
            // while the mount namespace stores the resolved host paths.
            if !crate::handlers::install_root_dir(FAKE_TASK, "/abi-private-root") {
                return Err("test root installation failed");
            }
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            narf_filesystem::procfs::sys_kernel::register_all();
            let source = b"proc\0";
            let staging = b"/abi-private-proc\0";
            let procfs = b"proc\0";
            let mount = SyscallArgs {
                arg0: source.as_ptr() as u64,
                arg1: staging.as_ptr() as u64,
                arg2: procfs.as_ptr() as u64,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), mount) != Some(0) {
                return Err("private staging procfs mount failed");
            }

            let file = b"/abi-private-proc/sys/kernel/domainname\0";
            let open = a3((-100i64) as u64, file.as_ptr() as u64, 0, 0);
            let fd = match call(Syscall::Openat.raw(), open) {
                Some(fd) if (0..=u32::MAX as i64).contains(&fd) => fd as u32,
                _ => return Err("open must resolve files in the current mount namespace"),
            };
            let _ = call(Syscall::Close.raw(), a0(fd as u64));

            // ProtectHostname= takes this exact Linux path: first bind the
            // procfs control FILE onto itself, which must stack a distinct
            // mount in the private namespace; only then remount that top
            // layer read-only. A plain remount test is insufficient: it
            // misses the file-rooted stack that systemd observes through
            // mountinfo while constructing a service sandbox.
            let rooted_file = "/abi-private-root/abi-private-proc/sys/kernel/domainname";
            let before_bind = crate::handlers::current_mount_namespace()
                .and_then(|ns| ns.mount_id_at(rooted_file));
            let bind = SyscallArgs {
                arg0: file.as_ptr() as u64,
                arg1: file.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), bind) != Some(0) {
                return Err("self-bind of a procfs control file must succeed");
            }
            let after_bind = crate::handlers::current_mount_namespace()
                .and_then(|ns| ns.mount_id_at(rooted_file));
            if !matches!((before_bind, after_bind), (Some(before), Some(after)) if after != before)
            {
                return Err("self-bind must stack a distinct private file mount");
            }
            let mountinfo = crate::handlers::proc_ns_mountinfo(FAKE_TASK)
                .ok_or("private mount namespace must render mountinfo")?;
            if !mountinfo.lines().any(|line| {
                line.split('\t').nth(2) == Some("/abi-private-proc/sys/kernel/domainname")
            }) {
                return Err(
                    "mountinfo must expose the stacked file mount at its root-relative path",
                );
            }

            let remount = SyscallArgs {
                arg0: 0,
                arg1: file.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND | MS_REMOUNT | MS_RDONLY,
                ..Default::default()
            };
            match call(Syscall::Mount.raw(), remount) {
                Some(0) => Ok(()),
                _ => Err("bind remount must validate files in the current mount namespace"),
            }
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        crate::handlers::__test_root_dir_reset();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_mount_bind_remount_private_file_pos
);

fn smoke_abi_fsx2_mount_namespace_stack_pos() -> TestResult {
    with_setup(|| {
        let ns = narf_filesystem::MountNamespace::snapshot_global();
        let auth = narf_filesystem::bootstrap_mount_authority();
        let first: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("stack-first"));
        let second: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("stack-second"));
        if ns.mount_arc(&auth, "/abi-private-stack", first).is_err() {
            return Err("first private namespace mount failed");
        }
        let first_id = match ns.mount_id_at("/abi-private-stack") {
            Some(id) if id != 0 => id,
            _ => return Err("first private mount must expose a nonzero mount id"),
        };
        if ns.mount_arc(&auth, "/abi-private-stack", second).is_err() {
            return Err("private mount namespace must permit stacking at one target");
        }
        match ns.mount_id_at("/abi-private-stack") {
            Some(id) if id != first_id => {}
            _ => return Err("stacking a mount must change the visible mount id"),
        }
        match ns.list_mountinfo().last() {
            Some((_, parent, path, _)) if *parent == first_id && path == "/abi-private-stack" => {}
            _ => return Err("a stacked mount must name the covered mount as its parent"),
        }
        match ns.resolve_absolute("/abi-private-stack", |fs, _| fs.name() == "stack-second") {
            Some(true) => Ok(()),
            _ => Err("private namespace path resolution must select the topmost mount"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_namespace_stack_pos);

fn smoke_abi_fsx2_mount_namespace_move_pos() -> TestResult {
    with_setup(|| {
        let ns = narf_filesystem::MountNamespace::snapshot_global();
        let auth = narf_filesystem::bootstrap_mount_authority();
        let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("move-source"));
        if ns.mount_arc(&auth, "/abi-move-source", fs).is_err() {
            return Err("private namespace move setup failed");
        }
        if ns
            .move_mount("/abi-move-source", "/abi-move-target")
            .is_err()
        {
            return Err("moving a private namespace mount should succeed");
        }
        if ns.resolve_absolute("/abi-move-source", |fs, _| fs.name() == "move-source") == Some(true)
        {
            return Err("moved mount must no longer resolve at its source");
        }
        match ns.resolve_absolute("/abi-move-target", |fs, _| fs.name() == "move-source") {
            Some(true) => Ok(()),
            _ => Err("moved mount must resolve at its target"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_namespace_move_pos);

fn smoke_abi_fsx2_mount_bind_remount_null_source_pos() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let target = b"/abi-bind-remount\0";
        let tmpfs = b"tmpfs\0";
        let setup = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: tmpfs.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Mount.raw(), setup) != Some(0) {
            return Err("bind-remount target setup failed");
        }
        const MS_RDONLY: u64 = 1;
        const MS_REMOUNT: u64 = 1 << 5;
        const MS_BIND: u64 = 1 << 12;
        let remount = SyscallArgs {
            arg0: 0,
            arg1: target.as_ptr() as u64,
            arg2: 0,
            arg3: MS_BIND | MS_REMOUNT | MS_RDONLY,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), remount) {
            Some(0) => Ok(()),
            _ => Err("MS_BIND|MS_REMOUNT with NULL source must update the existing mount"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_mount_bind_remount_null_source_pos
);

// ── mount: -EFAULT on an unreadable target pointer ────────────────────
//
// copy_user_cstr(arg1=bad, ...) fails → the handler's copy-failure branch,
// which returns -EFAULT. The first file's negative pins an unknown-fstype
// path (-ENODEV), a different failure branch.

fn smoke_abi_fsx2_mount_badtarget_neg() -> TestResult {
    with_setup(|| {
        let source = b"none\0";
        let fstype = b"tmpfs\0";
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: 0x0001_0000_0000_0000, // unreadable target (Linux ABI arg1)
            arg2: fstype.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        // A bad target pointer fails copy-in → -EFAULT (matching Linux).
        match call(Syscall::Mount.raw(), args) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("mount with an unreadable target must return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_badtarget_neg);

// ── fsconfig: ENODEV on an un-buildable fsname ────────────────────────
//
// fsopen accepts any non-empty fsname; fsconfig(CMD_CREATE) then calls
// build_fs, which returns None for an unknown fs → ENODEV. The first file
// only pins the tmpfs CMD_CREATE success and the EBADF (unknown fd) case.

fn smoke_abi_fsx2_fsconfig_enodev_neg() -> TestResult {
    with_setup(|| {
        let fsname = b"nosuchfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen of an arbitrary fsname should still open a context"),
        };
        let args = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        match call(Syscall::Fsconfig.raw(), args) {
            Some(v) if v == ENODEV => Ok(()),
            _ => Err("fsconfig(CMD_CREATE) on an un-buildable fsname must return -ENODEV"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fsconfig_enodev_neg);

// ── fsconfig: FSCONFIG_SET_STRING reaches tmpfs creation ──────────────
//
// The SET_STRING arm retains the key/value for CMD_CREATE. A supported value
// builds successfully; an unsupported THP policy is rejected by TmpFs.

fn smoke_abi_fsx2_fsconfig_set_string_pos() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        let key = b"size\0";
        let val = b"64m\0";
        let args = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_SET_STRING,
            arg2: key.as_ptr() as u64,
            arg3: val.as_ptr() as u64,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), args) != Some(0) {
            return Err("fsconfig(SET_STRING) should retain a readable tmpfs option");
        }
        let create = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        match call(Syscall::Fsconfig.raw(), create) {
            Some(0) => Ok(()),
            _ => Err("fsconfig(CMD_CREATE) rejected a supported tmpfs size option"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fsconfig_set_string_pos);

fn smoke_abi_fsx2_fsconfig_tmpfs_option_rejected() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        let key = b"huge\0";
        let val = b"always\0";
        if call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: FSCONFIG_SET_STRING,
                arg2: key.as_ptr() as u64,
                arg3: val.as_ptr() as u64,
                ..Default::default()
            },
        ) != Some(0)
        {
            return Err("fsconfig(SET_STRING) setup failed");
        }
        match call(
            Syscall::Fsconfig.raw(),
            SyscallArgs {
                arg0: fd,
                arg1: FSCONFIG_CMD_CREATE,
                ..Default::default()
            },
        ) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("tmpfs must reject an unsupported huge policy at CMD_CREATE"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fsconfig_tmpfs_option_rejected);

// ── move_mount: EINVAL on a relative target (valid from_dfd) ──────────
//
// Build a real detached-mount fd, then pass a relative to_path. mount_of
// succeeds, but the to_path branch rejects a non-'/' target → EINVAL. The
// first file's negative pins EBADF (unknown from_dfd) — a different branch.

fn smoke_abi_fsx2_move_mount_relpath_neg() -> TestResult {
    with_setup(|| {
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen setup failed"),
        };
        let cargs = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), cargs) != Some(0) {
            return Err("fsconfig setup failed");
        }
        let mfd = match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsmount setup failed"),
        };
        let to = b"relative-target\0"; // not absolute → EINVAL
        let args = SyscallArgs {
            arg0: mfd,
            arg1: 0,
            arg2: 0,
            arg3: to.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::MoveMount.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("move_mount with a relative to_path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_move_mount_relpath_neg);

fn smoke_abi_fsx2_move_mount_private_namespace_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let fsname = b"tmpfs\0";
            let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
                Some(v) if v >= 0 => v as u64,
                _ => return Err("fsopen setup failed"),
            };
            let create = SyscallArgs {
                arg0: fd,
                arg1: FSCONFIG_CMD_CREATE,
                ..Default::default()
            };
            if call(Syscall::Fsconfig.raw(), create) != Some(0) {
                return Err("fsconfig setup failed");
            }
            let mfd = match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
                Some(v) if v >= 0 => v as u64,
                _ => return Err("fsmount setup failed"),
            };
            let target = b"/proc\0";
            let attach = SyscallArgs {
                arg0: mfd,
                arg1: 0,
                arg2: (-100i64) as u64,
                arg3: target.as_ptr() as u64,
                ..Default::default()
            };
            if call(Syscall::MoveMount.raw(), attach) != Some(0) {
                return Err("move_mount must attach into the private namespace");
            }
            let resolved_target = crate::handlers::apply_chroot_for_test("/proc");
            let attached = crate::handlers::current_mount_namespace()
                .and_then(|ns| {
                    ns.resolve_absolute(&resolved_target, |fs, rel| {
                        rel.is_empty() && fs.name() == "tmpfs"
                    })
                })
                .unwrap_or(false);
            if !attached {
                return Err("detached mount was not visible in the current namespace");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_move_mount_private_namespace_pos
);

/// Directory-MUTATION syscalls must resolve through the caller's mount
/// namespace, exactly as `open` already does.
///
/// `open`/`read` go through `current_resolve_absolute()`, which consults the
/// task's `MountNamespace` and falls back to the global registry. Every
/// directory-mutation syscall — rename, renameat2, unlink, rmdir, symlink —
/// instead calls `registry().resolve_parent_absolute()` directly, because no
/// namespace-aware `current_resolve_parent_absolute` exists. A task in a
/// private mount namespace can therefore CREATE a file it cannot afterwards
/// rename or unlink: the parent resolves for one call and not the other.
///
/// This is what breaks udev. `systemd-udevd` runs with `PrivateMounts=yes`,
/// and `sd-device` publishes a database entry by writing
/// `/run/udev/data/.#<id><random>` and renaming it onto `/run/udev/data/<id>`.
/// The write succeeds, the rename returns ENOENT because the parent is
/// invisible to the global registry, and udevd reports "Failed to rename
/// temporary database file ... No such file or directory" for every device.
/// The same gap takes out its `/dev/char/<major>:<minor>` symlinks and
/// `/run/udev/watch/`.
fn smoke_abi_fsx2_rename_resolves_in_private_mount_namespace() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const O_CREAT_WRONLY: u64 = 0o100 | 0o1;
        const AT_FDCWD: u64 = (-100i64) as u64;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            // Mounted ONLY in this namespace — the global registry never
            // learns about it, which is the whole point.
            let auth = narf_filesystem::bootstrap_mount_authority();
            let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::MemFs::with_seeds("nsdata", &[]));
            if ns.mount_arc(&auth, "/abi-nsdata", fs).is_err() {
                return Err("private-namespace mount setup failed");
            }

            // sd-device's publish shape: create the temporary, then rename.
            let tmp = b"/abi-nsdata/.#c226:0e270627d7a3faea1\0";
            let fin = b"/abi-nsdata/c226:0\0";
            let fd = call_open(tmp.as_ptr() as u64, O_CREAT_WRONLY).unwrap_or(-1);
            if fd < 0 {
                return Err("open(O_CREAT) could not create a file in the private namespace");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));

            let r = call(
                Syscall::Renameat.raw(),
                a3(AT_FDCWD, tmp.as_ptr() as u64, AT_FDCWD, fin.as_ptr() as u64),
            );
            match r {
                Some(0) => {}
                Some(-2) => {
                    return Err(
                        "rename reported ENOENT for a file open() had just created — directory-mutation syscalls bypass the task's mount namespace",
                    )
                }
                _ => return Err("rename in a private mount namespace did not succeed"),
            }
            // And the result must be visible under its new name.
            let check = call_open(fin.as_ptr() as u64, 0).unwrap_or(-1);
            if check < 0 {
                return Err("renamed file is not openable under its final name");
            }
            let _ = call(Syscall::Close.raw(), a0(check as u64));
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_rename_resolves_in_private_mount_namespace
);

/// The rest of the directory-mutation family must resolve in the caller's
/// mount namespace too — `renameat2`, `unlink`, `rmdir` and `symlink` were
/// all routed through `current_resolve_parent_absolute()` alongside `rename`,
/// and a fix proven on one syscall proves nothing about the other four.
///
/// Each arm here would report ENOENT against the global registry, because
/// the mount exists only in this task's namespace.
fn smoke_abi_fsx2_mutations_resolve_in_private_mount_namespace() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const O_CREAT_WRONLY: u64 = 0o100 | 0o1;
        const RENAME_NOREPLACE: u64 = 1;
        const AT_FDCWD: u64 = (-100i64) as u64;
        const AT_REMOVEDIR: u64 = 0x200;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::MemFs::with_seeds("nsmut", &[]));
            if ns.mount_arc(&auth, "/abi-nsmut", fs).is_err() {
                return Err("private-namespace mount setup failed");
            }

            let make = |path: &[u8]| -> bool {
                let fd = call_open(path.as_ptr() as u64, O_CREAT_WRONLY).unwrap_or(-1);
                if fd < 0 {
                    return false;
                }
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
                true
            };

            // renameat2(RENAME_NOREPLACE)
            let a = b"/abi-nsmut/r2-src\0";
            let b = b"/abi-nsmut/r2-dst\0";
            if !make(a) {
                return Err("could not create the renameat2 source");
            }
            let r = call_raw(
                Syscall::Renameat2.raw(),
                SyscallArgs {
                    arg0: AT_FDCWD,
                    arg1: a.as_ptr() as u64,
                    arg2: AT_FDCWD,
                    arg3: b.as_ptr() as u64,
                    arg4: RENAME_NOREPLACE,
                    arg5: 0,
                },
            );
            if r.value as i64 != 0 {
                return Err("renameat2 did not resolve in the private mount namespace");
            }

            // unlink
            let u = b"/abi-nsmut/to-unlink\0";
            if !make(u) {
                return Err("could not create the unlink target");
            }
            if call(Syscall::Unlinkat.raw(), a2(AT_FDCWD, u.as_ptr() as u64, 0)) != Some(0) {
                return Err("unlink did not resolve in the private mount namespace");
            }
            if call_open(u.as_ptr() as u64, 0).unwrap_or(-1) >= 0 {
                return Err("unlink reported success but the file is still there");
            }

            // symlink
            let link = b"/abi-nsmut/a-link\0";
            let target = b"r2-dst\0";
            if call(
                Syscall::Symlinkat.raw(),
                a2(target.as_ptr() as u64, AT_FDCWD, link.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("symlink did not resolve in the private mount namespace");
            }

            // rmdir
            let d = b"/abi-nsmut/a-dir\0";
            if call(
                Syscall::Mkdirat.raw(),
                a2(AT_FDCWD, d.as_ptr() as u64, 0o755),
            ) != Some(0)
            {
                return Err("mkdir did not resolve in the private mount namespace");
            }
            if call(
                Syscall::Unlinkat.raw(),
                a2(AT_FDCWD, d.as_ptr() as u64, AT_REMOVEDIR),
            ) != Some(0)
            {
                return Err("rmdir did not resolve in the private mount namespace");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_mutations_resolve_in_private_mount_namespace
);

/// Cross-DIRECTORY rename must resolve in the caller's mount namespace too.
///
/// `cross_dir_rename` takes a different path from the same-directory case —
/// `resolve_two_parents_absolute`, whose same-mount check IS the EXDEV test —
/// so it needed its own namespace-aware twin and its own test. Leaving it on
/// the global registry would have kept exactly the udev-class bug alive for
/// any rename that moves a name between two directories.
fn smoke_abi_fsx2_cross_dir_rename_in_private_mount_namespace() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const O_CREAT_WRONLY: u64 = 0o100 | 0o1;
        const AT_FDCWD: u64 = (-100i64) as u64;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::MemFs::with_seeds("nsxdir", &[]));
            if ns.mount_arc(&auth, "/abi-nsxdir", fs).is_err() {
                return Err("private-namespace mount setup failed");
            }
            for dir in [b"/abi-nsxdir/from\0".as_ref(), b"/abi-nsxdir/to\0".as_ref()] {
                if call(
                    Syscall::Mkdirat.raw(),
                    a2(AT_FDCWD, dir.as_ptr() as u64, 0o755),
                ) != Some(0)
                {
                    return Err("mkdir of a cross-directory rename endpoint failed");
                }
            }
            let src = b"/abi-nsxdir/from/entry\0";
            let dst = b"/abi-nsxdir/to/entry\0";
            let fd = call_open(src.as_ptr() as u64, O_CREAT_WRONLY).unwrap_or(-1);
            if fd < 0 {
                return Err("could not create the cross-directory rename source");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));

            match call(
                Syscall::Renameat.raw(),
                a3(
                    AT_FDCWD,
                    src.as_ptr() as u64,
                    AT_FDCWD,
                    dst.as_ptr() as u64,
                ),
            ) {
                Some(0) => {}
                Some(-2) => {
                    return Err(
                        "cross-directory rename reported ENOENT — cross_dir_rename bypasses the task's mount namespace",
                    )
                }
                _ => return Err("cross-directory rename in a private namespace did not succeed"),
            }
            if call_open(dst.as_ptr() as u64, 0).unwrap_or(-1) < 0 {
                return Err("cross-directory renamed file is not openable at its destination");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_cross_dir_rename_in_private_mount_namespace
);

fn smoke_abi_fsx2_open_tree_preserves_descendant_mounts_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const OPEN_TREE_CLONE: u64 = 1;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let root: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("tree-root"));
            let child: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("tree-child"));
            if ns.mount_arc(&auth, "/abi-tree-source", root).is_err()
                || ns
                    .mount_arc(&auth, "/abi-tree-source/run/incoming", child)
                    .is_err()
            {
                return Err("detached-tree mount setup failed");
            }

            let source = b"/abi-tree-source\0";
            let mfd = match call(
                Syscall::OpenTree.raw(),
                a2((-100i64) as u64, source.as_ptr() as u64, OPEN_TREE_CLONE),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("open_tree(CLONE) failed"),
            };
            let target = b"/abi-tree-target\0";
            let attach = SyscallArgs {
                arg0: mfd,
                arg1: 0,
                arg2: (-100i64) as u64,
                arg3: target.as_ptr() as u64,
                ..Default::default()
            };
            if call(Syscall::MoveMount.raw(), attach) != Some(0) {
                return Err("move_mount of cloned tree failed");
            }
            match ns.resolve_absolute("/abi-tree-target/run/incoming", |fs, rel| {
                rel.is_empty() && fs.name() == "tree-child"
            }) {
                Some(true) => Ok(()),
                _ => Err("move_mount must rebase descendant mounts with the detached root"),
            }
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_open_tree_preserves_descendant_mounts_pos
);

fn smoke_abi_fsx2_recursive_bind_preserves_descendant_mounts_pos() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const MS_BIND: u64 = 1 << 12;
        const MS_REC: u64 = 1 << 14;
        let result = (|| {
            if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
                return Err("private mount namespace setup failed");
            }
            let ns = match crate::handlers::current_mount_namespace() {
                Some(ns) => ns,
                None => return Err("unshare did not install a mount namespace"),
            };
            let auth = narf_filesystem::bootstrap_mount_authority();
            let root: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("rbind-root"));
            let child: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
                alloc::sync::Arc::new(narf_filesystem::VirtiofsMount::new("rbind-child"));
            if ns.mount_arc(&auth, "/abi-rbind-source", root).is_err()
                || ns
                    .mount_arc(&auth, "/abi-rbind-source/sys/fs/cgroup", child)
                    .is_err()
            {
                return Err("recursive-bind mount setup failed");
            }
            let source = b"/abi-rbind-source\0";
            let target = b"/abi-rbind-target\0";
            let bind = SyscallArgs {
                arg0: source.as_ptr() as u64,
                arg1: target.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND | MS_REC,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), bind) != Some(0) {
                return Err("recursive bind mount failed");
            }
            match ns.resolve_absolute("/abi-rbind-target/sys/fs/cgroup", |fs, rel| {
                rel.is_empty() && fs.name() == "rbind-child"
            }) {
                Some(true) => {}
                _ => return Err("recursive bind must rebase descendant mounts"),
            }
            let before_self_bind = ns.list().len();
            let self_source = b"/abi-rbind-target/\0";
            let self_bind = SyscallArgs {
                arg0: self_source.as_ptr() as u64,
                arg1: target.as_ptr() as u64,
                arg2: 0,
                arg3: MS_BIND | MS_REC,
                ..Default::default()
            };
            if call(Syscall::Mount.raw(), self_bind) != Some(0) {
                return Err("recursive self-bind failed");
            }
            if ns.list().len() != before_self_bind + 1 {
                return Err("recursive self-bind must not duplicate existing descendants");
            }
            Ok(())
        })();
        crate::handlers::clear_current_mount_namespace_for_test();
        result
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_recursive_bind_preserves_descendant_mounts_pos
);

// ── open_tree: ENOENT on an absolute path with no covering mount ──────
//
// path is absolute (passes the EINVAL guard). open_tree resolves it via
// `fs_arc_at`, which special-cases a "/" root mount as a fallback matching
// EVERY absolute path. Whether a root mount is present when this test runs
// depends on boot-initcall ordering (the initramfs / auto-root disk mount at
// "/" may or may not have landed yet) — the same flakiness documented on
// `smoke_filesystem_resolve_absolute`. So accept either outcome: ENOENT when
// nothing covers the path, or a valid fd when a root mount does cover it.

fn smoke_abi_fsx2_open_tree_enoent_neg() -> TestResult {
    with_setup(|| {
        let path = b"/abi-no-mount-here\0";
        match call(Syscall::OpenTree.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("open_tree: expected -ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_open_tree_enoent_neg);

// ── fspick: EINVAL on a relative path ─────────────────────────────────
//
// The first file's fspick negative is lenient (accepts anything); pin the
// concrete EINVAL relative-path guard branch here.

fn smoke_abi_fsx2_fspick_relpath_neg() -> TestResult {
    with_setup(|| {
        let path = b"relative\0";
        match call(Syscall::Fspick.raw(), a2(0, path.as_ptr() as u64, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("fspick with a relative path must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_fspick_relpath_neg);

// ── mount_setattr: EINVAL on the size>64 upper bound ──────────────────
//
// The first file pins size==0 (lower bound) → EINVAL and size==32 success.
// Pin the size>64 upper-bound EINVAL branch.

fn smoke_abi_fsx2_mount_setattr_oversize_neg() -> TestResult {
    with_setup(|| {
        let args = SyscallArgs {
            arg0: 0,
            arg4: 65, // > 64 → EINVAL
            ..Default::default()
        };
        match call(Syscall::MountSetattr.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("mount_setattr with size>64 must return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_setattr_oversize_neg);

// ── mount: fstype breadth for systemd's early-boot pseudo-filesystems ──
//
// systemd mounts many pseudo-filesystems (proc, sysfs, tmpfs, securityfs,
// debugfs, cgroup2, mqueue, …). The shared dispatch (mount_api::build_fs)
// backs the ones NARF can with a real FsInstance and the rest with an empty
// in-memory directory; either way the mount succeeds and the mountpoint is
// statable as a directory. Linux mount(2) ABI: (source, target, fstype,
// flags, data), all NUL-terminated.

fn mount_fstype(target: &[u8], fstype: &[u8]) -> Option<i64> {
    let source = b"none\0";
    let args = SyscallArgs {
        arg0: source.as_ptr() as u64,
        arg1: target.as_ptr() as u64,
        arg2: fstype.as_ptr() as u64,
        arg3: 0, // flags
        arg4: 0, // data
        ..Default::default()
    };
    call(Syscall::Mount.raw(), args)
}

fn smoke_abi_fsx2_mount_tmpfs_statable_pos() -> TestResult {
    with_setup(|| {
        let target = b"/abi-tmpfs-stat\0";
        let fstype = b"tmpfs\0";
        if mount_fstype(target, fstype) != Some(0) {
            return Err("mount of tmpfs at a fresh target should return 0");
        }
        // The mountpoint must now be statable as a directory.
        let mut sb = [0u8; 256];
        match call_stat(target.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("a mounted tmpfs root must be statable"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_tmpfs_statable_pos);

fn smoke_abi_fsx2_mount_securityfs_pseudo_pos() -> TestResult {
    with_setup(|| {
        // securityfs has no NARF semantics; it mounts an empty directory so
        // systemd's sys-kernel-security.mount unit succeeds.
        let target = b"/abi-securityfs\0";
        let fstype = b"securityfs\0";
        if mount_fstype(target, fstype) != Some(0) {
            return Err("mount of securityfs (empty-dir pseudo) should return 0");
        }
        let mut sb = [0u8; 256];
        match call_stat(target.as_ptr() as u64, sb.as_mut_ptr() as u64) {
            Some(0) => Ok(()),
            _ => Err("a mounted securityfs root must be statable"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_securityfs_pseudo_pos);

// ── mount: propagation-only change is an accepted no-op ────────────────
//
// systemd marks the mount tree private/slave with
// mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL). NARF's flat mount model
// has no propagation state, so this succeeds without touching the registry.

fn smoke_abi_fsx2_mount_propagation_noop_pos() -> TestResult {
    with_setup(|| {
        const MS_PRIVATE: u64 = 1 << 18;
        const MS_REC: u64 = 1 << 14;
        let source = b"none\0";
        let target = b"/\0";
        // NULL fstype (arg2=0) + propagation flags only.
        let args = SyscallArgs {
            arg0: source.as_ptr() as u64,
            arg1: target.as_ptr() as u64,
            arg2: 0, // NULL fstype
            arg3: MS_PRIVATE | MS_REC,
            arg4: 0,
            ..Default::default()
        };
        match call(Syscall::Mount.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("a propagation-only mount (MS_PRIVATE|MS_REC) must be a no-op success"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_propagation_noop_pos);

// ── mount: a genuinely-unknown fstype is -ENODEV, never the -1 sentinel ─

fn smoke_abi_fsx2_mount_garbage_fstype_neg() -> TestResult {
    with_setup(|| {
        let target = b"/abi-garbage\0";
        let fstype = b"notarealfs\0";
        match mount_fstype(target, fstype) {
            Some(v) if v == ENODEV => Ok(()),
            _ => Err("mount of a garbage fstype must return -ENODEV"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_fsx2_mount_garbage_fstype_neg);

// ── new-mount-API: full fsopen→fsconfig(CREATE)→fsmount→move_mount chain ─
//
// The decomposed mount path must register a mount equivalent to the classic
// path. Drive the whole chain and assert the destination appears in
// registry().list().

fn smoke_abi_fsx2_new_mount_api_chain_registers_pos() -> TestResult {
    with_setup(|| {
        let dest = "/abi-newapi-chain";
        // fsopen("tmpfs").
        let fsname = b"tmpfs\0";
        let fd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsopen(tmpfs) should return a context fd"),
        };
        // fsconfig(fd, CMD_CREATE) — materialize the backend.
        let cargs = SyscallArgs {
            arg0: fd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), cargs) != Some(0) {
            return Err("fsconfig(CMD_CREATE) should return 0");
        }
        // fsmount(fd, 0, 0) — detached mount fd.
        let mfd = match call(Syscall::Fsmount.raw(), a2(fd, 0, 0)) {
            Some(v) if v >= 0 => v as u64,
            _ => return Err("fsmount on a created context should return a mount fd"),
        };
        // move_mount(mfd, "", AT_FDCWD, dest, 0).
        let empty = b"\0";
        let mut dest_c = [0u8; 32];
        dest_c[..dest.len()].copy_from_slice(dest.as_bytes());
        let mvargs = SyscallArgs {
            arg0: mfd,
            arg1: empty.as_ptr() as u64,
            arg2: 0xffffffffffffff9c, // AT_FDCWD
            arg3: dest_c.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        if call(Syscall::MoveMount.raw(), mvargs) != Some(0) {
            return Err("move_mount of the detached mount should return 0");
        }
        // The destination must now appear in the mount registry.
        let mounted = narf_filesystem::registry()
            .list()
            .iter()
            .any(|p| p.as_str() == dest);
        if mounted {
            Ok(())
        } else {
            Err("the new-mount-API chain must register the mount in registry().list()")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_new_mount_api_chain_registers_pos
);

// `mount(8)` may address its destination through an O_PATH handle, using
// `/proc/self/fd/N` as move_mount(2)'s `to_path`.  This must name the opened
// directory, not a literal procfs path: systemd verifies the resulting mount
// in its own `/proc/self/mountinfo` immediately after the helper exits.
fn smoke_abi_fsx2_new_mount_api_procfd_target_pos() -> TestResult {
    with_setup(|| {
        let destination = b"/abi-newapi-procfd-target\0";
        if mount_fstype(destination, b"tmpfs\0") != Some(0) {
            return Err("could not create a directory to address through an fd");
        }
        let dirfd = match call_open(destination.as_ptr() as u64, 0) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("open of new-mount destination should return a directory fd"),
        };

        let fsname = b"debugfs\0";
        let fsfd = match call(Syscall::Fsopen.raw(), a1(fsname.as_ptr() as u64, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("fsopen(debugfs) should return a context fd"),
        };
        let create = SyscallArgs {
            arg0: fsfd,
            arg1: FSCONFIG_CMD_CREATE,
            ..Default::default()
        };
        if call(Syscall::Fsconfig.raw(), create) != Some(0) {
            return Err("fsconfig(CMD_CREATE) for debugfs should succeed");
        }
        let mountfd = match call(Syscall::Fsmount.raw(), a2(fsfd, 0, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("fsmount(debugfs) should return a detached mount fd"),
        };

        let procfd_target = alloc::format!("/proc/self/fd/{dirfd}");
        let mut procfd_target_c = procfd_target.into_bytes();
        procfd_target_c.push(0);
        let empty = b"\0";
        let move_args = SyscallArgs {
            arg0: mountfd,
            arg1: empty.as_ptr() as u64,
            arg2: (-100i64) as u64, // AT_FDCWD
            arg3: procfd_target_c.as_ptr() as u64,
            arg4: 0,
            ..Default::default()
        };
        let moved = call(Syscall::MoveMount.raw(), move_args) == Some(0);
        let _ = call(Syscall::Close.raw(), a0(dirfd));
        let visible_type = narf_filesystem::registry()
            .resolve_absolute("/abi-newapi-procfd-target", |fs, _| {
                alloc::string::String::from(fs.name())
            })
            .as_deref()
            == Some("debugfs");
        if moved && visible_type {
            Ok(())
        } else {
            Err("move_mount(/proc/self/fd/N) must attach at the opened directory")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_fsx2_new_mount_api_procfd_target_pos
);
