#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_memfd_create(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _name_ptr = args.arg0;
    // Linux memfd_create(2) ABI: (const char *name, unsigned int flags) —
    // flags in arg1. The kernel ignores the (NUL-terminated) name. Reading
    // flags from arg2 (an old NARF-native 3-arg shape) dropped MFD_ALLOW_SEALING
    // for every musl caller (foot/kwin put flags in rsi=arg1), so F_ADD_SEALS
    // then returned -EPERM and Wayland SHM-buffer sealing failed.
    let _flags = args.arg1 as u32;
    // `mm/memfd.c::SYSCALL_DEFINE2(memfd_create)` publishes the file with
    // `get_unused_fd_flags`, so a table at RLIMIT_NOFILE is -EMFILE. The
    // `-1` sentinel these arms inherited reached userspace as EPERM, which
    // is indistinguishable from the seal-permission failure this same
    // syscall's descriptors can produce later.
    let task = current_task_id();
    {
        let mfd = crate::linux_compat::MemFdFile::new(_flags);
        memfd_arc_register(&mfd);
        let cloexec = (_flags & crate::linux_compat::MFD_CLOEXEC) != 0;
        let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        let fd = fd::install(task, crate::fd::FdEntry {
                ops: mfd,
                offset: 0,
                flags: install_flags,
                // Linux memfd_create(2) always returns an O_RDWR fd. glibc/musl
                // fdopen(fd, "w+") reads F_GETFL and rejects the fd with EINVAL if
                // the access mode isn't read+write (systemd's serialization memfd).
                status_flags: crate::fd::O_RDWR,
            });
        match fd {
            Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
        }
    }
}
