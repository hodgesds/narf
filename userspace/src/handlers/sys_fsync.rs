#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fsync(ctx: &mut dyn TrapContext) {
    sync_fd(ctx, false);
}

pub(crate) fn sys_fdatasync(ctx: &mut dyn TrapContext) {
    sync_fd(ctx, true);
}

fn sync_fd(ctx: &mut dyn TrapContext, data_only: bool) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ops = fd::with_table(task, |t| t.get(fd).map(|entry| entry.ops.clone())).flatten();
    let Some(ops) = ops else {
        // fd isn't open → -EBADF (was the -1 sentinel musl maps to EPERM).
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    // `fs/sync.c::vfs_fsync_range` opens with
    // `if (!file->f_op->fsync) return -EINVAL;`. Neither `pipefifo_fops`/
    // `pipeanon_fops` nor `socket_file_ops` defines one, so fsync on a pipe,
    // FIFO or socket is a caller error — NOT the -EIO that tells a log writer
    // its data was lost. NARF's `FileOps::fsync` defaults to `Ok(())`, so the
    // "no such operation" case has to be recognised by file type here.
    {
        use narf_filesystem::FileType;
        let ty = ops.stat().mode.file_type;
        if ty == FileType::Fifo || ty == FileType::Socket {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    }
    // A generic filesystem may not expose physical page-cache frames for a
    // MAP_SHARED mapping. NARF then maps private frames and records them for
    // writeback; commit those bytes before the filesystem's own fsync so
    // fsync retains its Linux data-before-metadata ordering.
    if crate::mapped_file::flush_current_file(&ops).is_err() {
        ctx.set_return(SyscallReturn::ok((-5i64) as u64)); // -EIO
        return;
    }
    match poll_blocking(ops.fsync(data_only)) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        // `fs/sync.c::vfs_fsync_range` opens with
        // `if (!file->f_op->fsync) return -EINVAL;`, so a descriptor whose
        // file type has no fsync operation at all — a pipe, a socket — is
        // -EINVAL, not an I/O error. Callers that fsync whatever they were
        // handed (a log writer whose output is a pipe) treat EINVAL as
        // "nothing to flush" and EIO as data loss.
        Some(Err(narf_filesystem::FsError::Unsupported)) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)) // -EINVAL
        }
        _ => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}
