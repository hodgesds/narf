#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fallocate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let mode = args.arg1;
    let offset = args.arg2;
    let len = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if mode != 0 && mode != FALLOC_FL_ZERO_RANGE {
        ctx.set_return(fail);
        return;
    }
    let target_end = offset.saturating_add(len);
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        match poll_blocking(ops.fallocate(mode as u32, offset, len)) {
            Some(Ok(())) => return Some(true),
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            _ => return Some(false),
        }
        let cur_size = ops.stat().size;
        // Always ensure size >= offset + len. truncate handles
        // grow + zero-fill.
        if target_end > cur_size
            && poll_blocking(ops.truncate(target_end))
                .and_then(|r| r.ok())
                .is_none()
        {
            return Some(false);
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
        Some(true)
    });
    match outcome {
        Some(Some(true)) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}
