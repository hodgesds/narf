#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_signalfd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `fd` is an int: sign-extend from 32 bits so a -1 passed as 0xffffffff
    // (glibc's signalfd(-1, ...)) is recognised as "create new" rather than
    // a bogus positive fd 0xffffffff. (`args.arg0 as i64` would read +4G.)
    let fd_arg = args.arg0 as i32 as i64; // -1 = create new; else replace mask
    let mask_ptr = args.arg1;
    let _sizemask = args.arg2;
    let flags = args.arg3 as u32;
    let mut mask: u64 = 0;
    if mask_ptr != 0 {
        let mut bytes = [0u8; 8];
        // SAFETY: `mask_ptr` is the user sigset pointer (non-zero, checked above);
        // copy_from_user range-validates it and SMAP-brackets the 8-byte read.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_from_user(&mut bytes, mask_ptr) }.is_ok() {
            // A userspace sigset_t puts signal N at bit N-1 — identical to
            // NARF's SIGNAL_PENDING layout — so the signalfd mask lines up
            // with the pending bits it is intersected against verbatim.
            mask = u64::from_le_bytes(bytes);
        }
    }
    let task = current_task_id();

    // Wave-70: prefer the new linux-compat SignalFdFile; replace mask
    // path uses its `set_mask`. Fall back to legacy SignalFd on a non-
    // linux-compat build (skip the side-table register, mint legacy).
    #[cfg(feature = "linux-compat")]
    {
        if fd_arg >= 0 {
            // Replace mask on existing signalfd.
            let target = fd_arg as u32;
            if let Some(sf) = signalfd_arc_from_fd(task, target) {
                sf.set_mask(mask);
                ctx.set_return(SyscallReturn::ok(target as u64));
                return;
            }
            // `do_signalfd4`'s `ufd != -1` branch REPLACES the mask on an
            // existing signalfd, and it is not an allocation at all:
            //
            //     CLASS(fd, f)(ufd);
            //     if (fd_empty(f))                        return -EBADF;
            //     if (fd_file(f)->f_op != &signalfd_fops) return -EINVAL;
            //
            // A closed descriptor and a descriptor that is simply not a
            // signalfd are different mistakes and get different answers.
            let open = fd::with_table(task, |t| t.get(fd_arg as u32).is_some()).unwrap_or(false);
            let errno: i64 = if open { -22 } else { -9 }; // -EINVAL / -EBADF
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
        let sfd = crate::linux_compat::SignalFdFile::new(mask, task);
        signalfd_arc_register(&sfd);
        let cloexec = (flags & crate::linux_compat::SFD_CLOEXEC) != 0;
        let nonblock = (flags & crate::linux_compat::SFD_NONBLOCK) != 0;
        let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        let status_flags = if nonblock { crate::fd::O_NONBLOCK } else { 0 };
        let new_fd = match fd::install(task, crate::fd::FdEntry {
                ops: sfd,
                offset: 0,
                flags: install_flags,
                status_flags,
            }) {
            Some(n) => n,
            None => {
                // `do_signalfd4` publishes the new signalfd with
                // `get_unused_fd_flags`, so a table at RLIMIT_NOFILE is
                // -EMFILE.
                ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
                return;
            }
        };
        ctx.set_return(SyscallReturn::ok(new_fd as u64));
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        let _ = fd_arg;
        let sfd = crate::io_mux::SignalFd::new(mask, task);
        // `crate::linux_compat` only exists under that feature; use the raw
        // signalfd4 flag bits here (SFD_CLOEXEC == O_CLOEXEC == 0x80000,
        // SFD_NONBLOCK == O_NONBLOCK == 0o4000) so this branch builds without it.
        let cloexec = (flags & 0x80000) != 0;
        let nonblock = (flags & 0o4000) != 0;
        let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        let status_flags = if nonblock { crate::fd::O_NONBLOCK } else { 0 };
        let new_fd = match fd::install(task, crate::fd::FdEntry {
                ops: sfd,
                offset: 0,
                flags: install_flags,
                status_flags,
            }) {
            Some(n) => n,
            None => {
                // Same allocation contract as the linux-compat branch above:
                // `do_signalfd4` gets its descriptor from
                // `get_unused_fd_flags`, so a full table is -EMFILE.
                ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
                return;
            }
        };
        ctx.set_return(SyscallReturn::ok(new_fd as u64));
    }
}
