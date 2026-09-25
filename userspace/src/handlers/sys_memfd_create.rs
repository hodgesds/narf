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
    // `mm/memfd.c::sanitize_flags`, then `alloc_name`, both ahead of
    // `get_unused_fd_flags` — so -EINVAL for the flags, then -EFAULT /
    // -EINVAL for the name, then -EMFILE. Nothing was validated before:
    // an unknown flag or an unreadable name pointer created a memfd.
    //
    //   if (!(flags & MFD_HUGETLB)) {
    //           if (flags & ~MFD_ALL_FLAGS) return -EINVAL;
    //   } else {
    //           if (flags & ~(MFD_ALL_FLAGS | (MFD_HUGE_MASK << MFD_HUGE_SHIFT)))
    //                   return -EINVAL;
    //   }
    //   if ((flags & MFD_EXEC) && (flags & MFD_NOEXEC_SEAL)) return -EINVAL;
    const MFD_HUGETLB: u32 = 0x0004;
    const MFD_NOEXEC_SEAL: u32 = 0x0008;
    const MFD_EXEC: u32 = 0x0010;
    const MFD_ALL_FLAGS: u32 = crate::linux_compat::MFD_CLOEXEC
        | crate::linux_compat::MFD_ALLOW_SEALING
        | MFD_HUGETLB
        | MFD_NOEXEC_SEAL
        | MFD_EXEC;
    const MFD_HUGE_BITS: u32 = 0x3f << 26; // MFD_HUGE_MASK << MFD_HUGE_SHIFT
    let allowed = if _flags & MFD_HUGETLB != 0 {
        MFD_ALL_FLAGS | MFD_HUGE_BITS
    } else {
        MFD_ALL_FLAGS
    };
    if _flags & !allowed != 0 || (_flags & MFD_EXEC != 0 && _flags & MFD_NOEXEC_SEAL != 0) {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `alloc_name`: `strnlen_user(uname, MFD_NAME_MAX_LEN + 1)` — 0 (a fault)
    // is -EFAULT, a name longer than MFD_NAME_MAX_LEN (NAME_MAX minus the
    // 6-byte "memfd:" prefix = 249) is -EINVAL.
    const MFD_NAME_MAX_LEN: usize = 255 - 6;
    match copy_user_cstr_checked(_name_ptr, MFD_NAME_MAX_LEN + 1) {
        Ok(_) => {}
        Err(errno) if errno == EFAULT => {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        Err(_) => {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    }
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
            None => ctx.set_return(errno_ret(EMFILE)),
        }
    }
}
