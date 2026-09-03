#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pipe2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let out_ptr = args.arg0;
    // The Linux syscall prototype takes `int flags`; syscall-register bits
    // above the low 32 are discarded before `do_pipe2` validates the mask.
    let flags = args.arg1 as u32 as u64;
    // `fs/pipe.c::do_pipe2`: any flag outside O_CLOEXEC | O_NONBLOCK |
    // O_DIRECT | O_NOTIFICATION_PIPE is -EINVAL. Flag validation happens
    // before Linux reaches copy_to_user, so bad flags win over a bad pointer.
    //
    // O_DIRECT is packet mode (`pipe_write`'s one-buffer-per-write regime);
    // the pipe honours it, so it is accepted here.
    //
    // O_NOTIFICATION_PIPE (the O_EXCL bit in this syscall) is recognized but
    // the watch-queue feature is not built. Linux returns ENOPKG in exactly
    // that configuration; silently creating an ordinary pipe would strand a
    // caller waiting for notifications that can never arrive.
    let nonblock_bit = crate::fd::O_NONBLOCK as u64;
    let direct_bit = crate::fd::O_DIRECT as u64;
    const O_NOTIFICATION_PIPE: u64 = 0o200;
    if flags & !(O_CLOEXEC_BIT | nonblock_bit | direct_bit | O_NOTIFICATION_PIPE) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    if flags & O_NOTIFICATION_PIPE != 0 {
        ctx.set_return(SyscallReturn::ok((-65i64) as u64)); // -ENOPKG
        return;
    }
    let want_cloexec = (flags & O_CLOEXEC_BIT) != 0;
    let install_flags = if want_cloexec {
        crate::fd::FD_CLOEXEC
    } else {
        0
    };
    // O_NONBLOCK lands in the per-fd status flags (Linux stores it on the
    // open file description; F_GETFL reports it). The access-mode bits
    // mirror `create_pipe_files`: read end O_RDONLY, write end O_WRONLY.
    let nb = if flags & nonblock_bit != 0 {
        crate::fd::O_NONBLOCK
    } else {
        0
    };

    // Packet mode is a property of the WRITE end alone: `create_pipe_files`
    // builds the writer with `O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT))`
    // and clones the reader with `O_RDONLY | (flags & O_NONBLOCK)`, so
    // O_DIRECT never appears in the read fd's status flags and F_GETFL on the
    // read end must not report it.
    let packetized = flags & direct_bit != 0;
    let (rd, wr) = crate::pipe::pipe_pair_flags(packetized);
    let direct = if packetized { crate::fd::O_DIRECT } else { 0 };
    let task = current_task_id();
    let fds = fd::install_pair(
        task,
        crate::fd::FdEntry {
            ops: rd as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: install_flags,
            status_flags: crate::fd::O_RDONLY | nb,
        },
        crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: install_flags,
            status_flags: crate::fd::O_WRONLY | nb | direct,
        },
    );
    let (r, w) = match fds {
        Some(pair) => pair,
        // Both ends are allocated or neither is; see `fd::install_pair`.
        None => {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    // Write two i32 fds to user buffer under the SMAP bracket.
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&(r as i32).to_ne_bytes());
    buf[4..].copy_from_slice(&(w as i32).to_ne_bytes());
    // SAFETY: `out_ptr` is the user fd-pair buffer; copy_to_user range-validates
    // it and SMAP-brackets the write of the 8-byte `buf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        // Match do_pipe2: a failed user copy releases both reserved numbers
        // and both files; no descriptor becomes visible on an EFAULT return.
        let _ = fd::with_table(task, |table| {
            table.close(r);
            table.close(w);
        });
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
