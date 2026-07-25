#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_copy_file_range(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_in = args.arg0 as u32;
    let off_in_ptr = args.arg1;
    let fd_out = args.arg2 as u32;
    let off_out_ptr = args.arg3;
    let len = args.arg4 as usize;
    let flags = args.arg5;
    const EBADF: i64 = -9;
    const EINVAL: i64 = -22;

    if flags != 0 {
        ctx.set_return(SyscallReturn::ok(EINVAL as u64));
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Fault the offset words in before any copying happens, so a bad
    // pointer is EFAULT rather than a half-completed copy.
    for p in [off_in_ptr, off_out_ptr] {
        if p != 0 {
            if let Err(e) = validate_user_range(p, 8) {
                ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
                return;
            }
        }
    }

    // Resolve both ops + their starting offsets up-front so we
    // don't hold the fd table lock across the FsFuture polls.
    let task = current_task_id();
    let resolved = fd::with_table(task, |t| {
        let in_e = t.get(fd_in)?;
        let in_off = if off_in_ptr == 0 {
            in_e.offset
        } else {
            read_user_u64(off_in_ptr)
        };
        let out_e = t.get(fd_out)?;
        let out_off = if off_out_ptr == 0 {
            out_e.offset
        } else {
            read_user_u64(off_out_ptr)
        };
        Some((in_e.ops.clone(), in_off, out_e.ops.clone(), out_off))
    });
    let (in_ops, mut cur_in, out_ops, mut cur_out) = match resolved {
        Some(Some(t)) => t,
        _ => {
            ctx.set_return(SyscallReturn::ok(EBADF as u64));
            return;
        }
    };

    let mut chunk = [0u8; 4096];
    let mut copied = 0usize;
    while copied < len {
        let span = core::cmp::min(len - copied, chunk.len());
        let read_n = poll_blocking(in_ops.read(cur_in, &mut chunk[..span]))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if read_n == 0 {
            break;
        }
        let write_n = poll_blocking(out_ops.write(cur_out, &chunk[..read_n]))
            .and_then(|r| r.ok())
            .unwrap_or(0);
        if write_n == 0 {
            break;
        }
        copied += write_n;
        cur_in += write_n as u64;
        cur_out += write_n as u64;
        if write_n < read_n {
            break;
        }
    }

    // A NULL offset pointer means the copy consumed the fd's own file
    // offset, so advance it; a non-NULL pointer leaves the cursor alone
    // and gets the advanced value written back instead.
    let _ = fd::with_table(task, |t| {
        if off_in_ptr == 0 {
            if let Some(e) = t.get_mut(fd_in) {
                e.offset = cur_in;
            }
        }
        if off_out_ptr == 0 {
            if let Some(e) = t.get_mut(fd_out) {
                e.offset = cur_out;
            }
        }
        Some(())
    });
    if off_in_ptr != 0 {
        write_user_u64(off_in_ptr, cur_in);
    }
    if off_out_ptr != 0 {
        write_user_u64(off_out_ptr, cur_out);
    }

    ctx.set_return(SyscallReturn::ok(copied as u64));
}
