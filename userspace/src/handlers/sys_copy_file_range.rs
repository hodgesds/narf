#[allow(unused_imports)]
use super::*;

fn import_offset(ptr: u64) -> Result<Option<u64>, u64> {
    if ptr == 0 {
        return Ok(None);
    }
    // SAFETY: validates and guards the complete loff_t load. A protection
    // change racing an earlier access_ok must be EFAULT, never offset zero.
    let bytes = unsafe { copy_from_user_vec(ptr, 8) }?;
    Ok(Some(u64::from_ne_bytes(bytes.try_into().unwrap())))
}

fn write_offset(ptr: u64, offset: u64) -> Result<(), u64> {
    if ptr == 0 {
        return Ok(());
    }
    // SAFETY: guarded write-back catches a racing unmap/protection change.
    unsafe { copy_to_user(ptr, &offset.to_ne_bytes()) }
}

pub(crate) fn sys_copy_file_range(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_in = args.arg0 as u32;
    let off_in_ptr = args.arg1;
    let fd_out = args.arg2 as u32;
    let off_out_ptr = args.arg3;
    let len = core::cmp::min(args.arg4 as usize, LINUX_MAX_RW_COUNT);
    let flags = args.arg5;

    // Linux fdget()s both descriptors before touching offset words or flags.
    let task = current_task_id();
    let Some(input) = copy_fd_endpoint(task, fd_in) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    let Some(output) = copy_fd_endpoint(task, fd_out) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };

    let explicit_in = match import_offset(off_in_ptr) {
        Ok(offset) => offset,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            return;
        }
    };
    let explicit_out = match import_offset(off_out_ptr) {
        Ok(offset) => offset,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            return;
        }
    };
    if flags != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }

    // Only regular files participate. A live empty pipe is not EOF: EINVAL
    // makes userspace fall back to its blocking read/write path.
    use narf_filesystem::FileType;
    let in_ty = input.ops.stat().mode.file_type;
    let out_ty = output.ops.stat().mode.file_type;
    if in_ty == FileType::Dir || out_ty == FileType::Dir {
        ctx.set_return(SyscallReturn::ok((-21i64) as u64));
        return;
    }
    if in_ty != FileType::File || out_ty != FileType::File {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if !input.readable() || !output.writable() || output.append() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    }
    if explicit_in.is_some_and(|offset| (offset as i64) < 0)
        || explicit_out.is_some_and(|offset| (offset as i64) < 0)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let implicit_in = explicit_in.is_none();
    let implicit_out = explicit_out.is_none();
    let same_description = Arc::ptr_eq(&input.description, &output.description);
    let mut input_guard = None;
    let mut output_guard = None;
    if implicit_in && implicit_out && !same_description {
        let input_key = Arc::as_ptr(&input.description) as usize;
        let output_key = Arc::as_ptr(&output.description) as usize;
        if input_key < output_key {
            input_guard = poll_blocking(input.description.position_lock.lock());
            if input_guard.is_some() {
                output_guard = poll_blocking(output.description.position_lock.lock());
            }
        } else {
            output_guard = poll_blocking(output.description.position_lock.lock());
            if output_guard.is_some() {
                input_guard = poll_blocking(input.description.position_lock.lock());
            }
        }
    } else if (implicit_in || implicit_out) && same_description {
        input_guard = poll_blocking(input.description.position_lock.lock());
    } else {
        if implicit_in {
            input_guard = poll_blocking(input.description.position_lock.lock());
        }
        if implicit_out {
            output_guard = poll_blocking(output.description.position_lock.lock());
        }
    }
    if same_description && (implicit_in || implicit_out) && input_guard.is_none()
        || !same_description
            && (implicit_in && input_guard.is_none() || implicit_out && output_guard.is_none())
    {
        ctx.set_return(SyscallReturn::ok((-5i64) as u64));
        return;
    }

    let start_in = explicit_in.unwrap_or_else(|| input.description.offset());
    let start_out = explicit_out.unwrap_or_else(|| output.description.offset());
    let mut cur_in = start_in;
    let mut cur_out = start_out;
    let mut copied = 0usize;
    let mut optimized = false;

    match poll_blocking(input.ops.copy_file_range_to(
        cur_in,
        output.ops.as_ref(),
        cur_out,
        len as u64,
        flags,
    )) {
        Some(Ok(n)) if n <= len as u64 => {
            copied = n as usize;
            optimized = true;
        }
        Some(Ok(_)) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
        Some(Err(narf_filesystem::FsError::Unsupported)) | None => {
            let mut chunk = [0u8; 4096];
            while copied < len {
                let span = core::cmp::min(len - copied, chunk.len());
                let read_n = match poll_blocking(input.ops.read(cur_in, &mut chunk[..span])) {
                    Some(Ok(n)) if n <= span => n,
                    Some(Ok(_)) => {
                        if copied == 0 {
                            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                            return;
                        }
                        break;
                    }
                    Some(Err(error)) => {
                        if copied == 0 {
                            ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
                            return;
                        }
                        break;
                    }
                    None => break,
                };
                if read_n == 0 {
                    break;
                }
                let write_n = match poll_blocking(output.ops.write(cur_out, &chunk[..read_n])) {
                    Some(Ok(n)) if n <= read_n => n,
                    Some(Ok(_)) => {
                        if copied == 0 {
                            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                            return;
                        }
                        break;
                    }
                    Some(Err(error)) => {
                        if copied == 0 {
                            ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
                            return;
                        }
                        break;
                    }
                    None => break,
                };
                copied += write_n;
                cur_in = cur_in.saturating_add(write_n as u64);
                cur_out = cur_out.saturating_add(write_n as u64);
                if write_n < read_n {
                    break;
                }
            }
        }
        Some(Err(error)) => {
            ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
            return;
        }
    }
    if optimized {
        cur_in = start_in.saturating_add(copied as u64);
        cur_out = start_out.saturating_add(copied as u64);
    }

    if copied != 0 {
        if implicit_in {
            input.description.set_offset(cur_in);
        }
        if implicit_out {
            output.description.set_offset(cur_out);
        }
        // Linux writes explicit offsets back only after positive progress. A
        // guarded fault then wins even though data has already moved.
        if write_offset(off_in_ptr, cur_in).is_err() || write_offset(off_out_ptr, cur_out).is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(copied as u64));
}
