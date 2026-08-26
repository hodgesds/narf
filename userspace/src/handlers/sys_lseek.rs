#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_lseek(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let offset = args.arg1 as i64;
    let whence = args.arg2;
    let task = current_task_id();
    // Linux errno: bad fd → -EBADF; bad whence / negative or overflowing
    // result → -EINVAL (was a blanket InvalidOp).
    let ebadf = SyscallReturn::ok((-9i64) as u64);
    let einval = SyscallReturn::ok((-22i64) as u64);
    let resolved = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        Some((entry.ops.clone(), t.description(fd)?))
    });
    let (ops, description) = match resolved {
        Some(Some(v)) => v,
        _ => {
            ctx.set_return(ebadf);
            return;
        }
    };
    let _position_guard = match poll_blocking(description.position_lock.lock()) {
        Some(guard) => guard,
        None => {
            ctx.set_return(SyscallReturn::ok((-5i64) as u64));
            return;
        }
    };
    let current = description.offset();
    // Pipes, FIFOs and sockets are not seekable: `fs/pipe.c`'s
    // `pipefifo_fops` and net/socket.c's `socket_file_ops` define no
    // .llseek, so `fs/read_write.c::vfs_llseek` fails with -ESPIPE
    // (FMODE_LSEEK is never set on them). Succeeding here (the old
    // behaviour) let seek-probing callers — glibc stdio, coreutils —
    // believe a pipe had a movable file position.
    {
        use narf_filesystem::FileType;
        let ty = ops.stat().mode.file_type;
        if ty == FileType::Fifo || ty == FileType::Socket {
            ctx.set_return(SyscallReturn::ok((-29i64) as u64)); // -ESPIPE
            return;
        }
    }
    const SEEK_DATA: u64 = 3;
    const SEEK_HOLE: u64 = 4;
    if whence == SEEK_DATA || whence == SEEK_HOLE {
        // `fs/read_write.c::must_set_pos`:
        //
        //   case SEEK_DATA: if ((u64)offset >= eof) return -ENXIO; break;
        //   case SEEK_HOLE: if ((u64)offset >= eof) return -ENXIO;
        //                   offset = eof; break;
        //
        // Note the UNSIGNED compare, so a negative offset is -ENXIO as well.
        // Every extent-mapping filesystem reports the same past-EOF answer.
        // Folding these into the -EINVAL of the SEEK_SET/CUR/END match below
        // (which has no arm for them) destroyed the distinction userspace
        // relies on: -EINVAL means "this kernel has no SEEK_DATA at all, use
        // a whole-file copy", while -ENXIO means "supported, and there is no
        // more data" — the loop-termination condition of a sparse copy.
        let eof = ops.stat().size;
        if (offset as u64) >= eof {
            ctx.set_return(SyscallReturn::ok((-6i64) as u64)); // -ENXIO
            return;
        }
        match poll_blocking(ops.seek(offset as u64, whence as u32)) {
            Some(Ok(new_off)) => {
                description.set_offset(new_off);
                ctx.set_return(SyscallReturn::ok(new_off));
                return;
            }
            // No extent map: fall through to the generic answer below.
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            // A filesystem that DOES map extents and found no such
            // data/hole at or after `offset` is reporting end-of-data.
            Some(Err(_)) => {
                ctx.set_return(SyscallReturn::ok((-6i64) as u64)); // -ENXIO
                return;
            }
        }
        // Generic model: the whole file is data and the only hole is the
        // virtual one at EOF.
        let new_off = if whence == SEEK_HOLE { eof } else { offset as u64 };
        description.set_offset(new_off);
        ctx.set_return(SyscallReturn::ok(new_off));
        return;
    }
    let outcome = {
        let base = match whence {
            SEEK_SET => 0i64,
            SEEK_CUR => current as i64,
            SEEK_END => ops.stat().size as i64,
            _ => {
                ctx.set_return(einval);
                return;
            }
        };
        let new_off = match base.checked_add(offset) {
            Some(v) if v >= 0 => v,
            _ => {
                ctx.set_return(einval);
                return;
            }
        };
        description.set_offset(new_off as u64);
        SyscallReturn::ok(new_off as u64)
    };
    ctx.set_return(outcome);
}
