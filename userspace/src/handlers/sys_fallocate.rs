#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fallocate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let mode = args.arg1;
    let offset = args.arg2;
    let len = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    const KEEP_SIZE: u64 = 0x01;
    const PUNCH_HOLE: u64 = 0x02;
    const ZERO_RANGE: u64 = 0x10;
    if len == 0
        || mode & !(KEEP_SIZE | PUNCH_HOLE | ZERO_RANGE) != 0
        || mode & PUNCH_HOLE != 0 && mode != PUNCH_HOLE | KEEP_SIZE
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
        return;
    }
    let target_end = offset.saturating_add(len);
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        match poll_blocking(ops.fallocate(mode as u32, offset, len)) {
            Some(Ok(())) => return Some(Ok(())),
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            Some(Err(error)) => return Some(Err(error)),
        }
        if mode != 0 && mode != FALLOC_FL_ZERO_RANGE {
            return Some(Err(narf_filesystem::FsError::Unsupported));
        }
        let cur_size = ops.stat().size;
        // Always ensure size >= offset + len. truncate handles
        // grow + zero-fill.
        if target_end > cur_size
            && poll_blocking(ops.truncate(target_end))
                .and_then(|r| r.ok())
                .is_none()
        {
            return Some(Err(narf_filesystem::FsError::NoSpace));
        }
        if mode == FALLOC_FL_ZERO_RANGE && len > 0 && offset < cur_size {
            // Zero existing bytes in [offset, min(target_end, old size)].
            // We do this in 4-KiB chunks of zeros via a fresh write.
            let zero_end = core::cmp::min(target_end, cur_size);
            let mut cur = offset;
            let chunk = [0u8; 4096];
            while cur < zero_end {
                let span = core::cmp::min(zero_end - cur, chunk.len() as u64) as usize;
                let n = poll_blocking(ops.write(cur, &chunk[..span]))
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                cur += n as u64;
            }
        }
        Some(Ok(()))
    });
    match outcome {
        Some(Some(Ok(()))) => ctx.set_return(SyscallReturn::ok(0)),
        Some(Some(Err(narf_filesystem::FsError::NoSpace))) => {
            ctx.set_return(SyscallReturn::ok((-28i64) as u64))
        }
        Some(Some(Err(narf_filesystem::FsError::QuotaExceeded))) => {
            ctx.set_return(SyscallReturn::ok((-122i64) as u64))
        }
        Some(Some(Err(narf_filesystem::FsError::Unsupported))) => {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64))
        }
        _ => ctx.set_return(fail),
    }
}
