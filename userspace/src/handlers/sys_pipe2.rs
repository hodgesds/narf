#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pipe2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let out_ptr = args.arg0;
    let flags = args.arg1;
    if out_ptr == 0 {
        // NULL fd-array pointer → EFAULT.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    // `fs/pipe.c::do_pipe2`: any flag outside O_CLOEXEC | O_NONBLOCK |
    // O_DIRECT | O_NOTIFICATION_PIPE is -EINVAL. LINUX-GAP: O_DIRECT
    // (packet mode, `pipe_write`'s one-buffer-per-write regime) and
    // watch-queue pipes are unimplemented, so those two are ALSO
    // rejected with -EINVAL here rather than silently ignored — a
    // caller that got a byte-stream pipe after asking for packet
    // framing would corrupt its own record boundaries.
    let nonblock_bit = crate::fd::O_NONBLOCK as u64;
    if flags & !(O_CLOEXEC_BIT | nonblock_bit) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
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

    let (rd, wr) = crate::pipe::pipe_pair();
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
            status_flags: crate::fd::O_WRONLY | nb,
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
        // Faulting fd-array buffer → EFAULT.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
