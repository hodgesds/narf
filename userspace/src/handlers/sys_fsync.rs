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
    // fd isn't open → -EBADF (was the -1 sentinel musl maps to EPERM). An
    // O_PATH descriptor is "not open" to `fdget` as well.
    let Some(ops) = copy_fd_endpoint(task, fd).map(|e| e.ops) else {
        ctx.set_return(errno_ret(EBADF));
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
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    }
    // `file_write_and_wait_range` before `->fsync`: the file's dirty
    // `MAP_SHARED` pages are written first, whoever dirtied them, so the
    // filesystem's own fsync commits them with everything else. A write
    // failure — this call's, or a background one nobody has been told
    // about — is this fsync's result, with its own errno (ENOSPC is not
    // EIO to a database deciding whether to retry).
    if let Err(error) = crate::mapped_file::flush_current_file(&ops) {
        ctx.set_return(errno_ret(copy_fs_errno(error)));
        return;
    }
    // A fatal signal ends the wait for the commit; the commit itself
    // finishes without this task (`killable_wait::fsync`).
    let outcome = match crate::killable_wait::fsync(&ops, data_only) {
        Ok(outcome) => outcome,
        Err(crate::killable_wait::Killed) => {
            ctx.set_return(errno_ret(EINTR));
            return;
        }
    };
    match outcome {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        // `fs/sync.c::vfs_fsync_range` opens with
        // `if (!file->f_op->fsync) return -EINVAL;`, so a descriptor whose
        // file type has no fsync operation at all — a pipe, a socket — is
        // -EINVAL, not an I/O error. Callers that fsync whatever they were
        // handed (a log writer whose output is a pipe) treat EINVAL as
        // "nothing to flush" and EIO as data loss.
        Some(Err(narf_filesystem::FsError::Unsupported)) => {
            ctx.set_return(errno_ret(EINVAL))
        }
        _ => ctx.set_return(errno_ret(EIO)),
    }
}
