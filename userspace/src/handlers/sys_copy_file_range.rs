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
    // `unsigned int flags`: the syscall ABI drops the upper register half.
    let flags = args.arg5 as u32 as u64;

    // Linux fdget()s both descriptors before touching offset words or flags.
    let task = current_task_id();
    let Some(input) = copy_fd_endpoint(task, fd_in) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let Some(output) = copy_fd_endpoint(task, fd_out) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };

    let explicit_in = match import_offset(off_in_ptr) {
        Ok(offset) => offset,
        Err(errno) => {
            ctx.set_return(errno_ret(errno as i64));
            return;
        }
    };
    let explicit_out = match import_offset(off_out_ptr) {
        Ok(offset) => offset,
        Err(errno) => {
            ctx.set_return(errno_ret(errno as i64));
            return;
        }
    };
    if flags != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // Only regular files participate. A live empty pipe is not EOF: EINVAL
    // makes userspace fall back to its blocking read/write path.
    use narf_filesystem::FileType;
    let in_ty = input.ops.stat().mode.file_type;
    let out_ty = output.ops.stat().mode.file_type;
    if in_ty == FileType::Dir || out_ty == FileType::Dir {
        ctx.set_return(errno_ret(EISDIR));
        return;
    }
    if in_ty != FileType::File || out_ty != FileType::File {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if !input.readable() || !output.writable() || output.append() {
        ctx.set_return(errno_ret(EBADF));
        return;
    }

    // Linux generic_copy_file_checks (fs/read_write.c):
    // Immutable output file -> -EPERM.
    if output.ops.inode_flags() & narf_filesystem::FS_IMMUTABLE_FL != 0 {
        ctx.set_return(errno_ret(EPERM));
        return;
    }

    let start_in = explicit_in.unwrap_or_else(|| input.description.offset());
    let start_out = explicit_out.unwrap_or_else(|| output.description.offset());

    // generic_copy_file_checks, in order. Every test below uses Linux's
    // mixed loff_t/uint64_t arithmetic, i.e. u64 wrap-around, and runs on the
    // caller's RAW len — not the MAX_RW_COUNT-clamped one:
    //
    //   if (pos_in + count < pos_in || pos_out + count < pos_out)
    //           return -EOVERFLOW;
    //
    // So `*off_in = 1, len = SIZE_MAX` and `*off_in = -1, len = 10` are both
    // -EOVERFLOW; a negative offset that does not wrap falls through to
    // rw_verify_area's -EINVAL below.
    let raw_len = args.arg4;
    if start_in.checked_add(raw_len).is_none() || start_out.checked_add(raw_len).is_none() {
        ctx.set_return(errno_ret(EOVERFLOW));
        return;
    }
    // "Shorten the copy to EOF": pos_in >= i_size -> count = 0, else
    // count = min(count, size_in - (u64)pos_in).
    let size_in = input.ops.stat().size;
    let mut count = if (start_in as i64) >= (size_in as i64) {
        0
    } else {
        raw_len.min(size_in.wrapping_sub(start_in))
    };
    // generic_write_check_limits(file_out, pos_out, &count): RLIMIT_FSIZE
    // (SIGXFSZ + -EFBIG at or past the limit, else clamp), then
    // s_maxbytes — MAX_LFS_FILESIZE (LLONG_MAX) for NARF's filesystems, so
    // `*off_out = INT64_MAX` is -EFBIG. Both apply even when count == 0.
    // A negative pos_out is below both limits and is left to rw_verify_area.
    if (start_out as i64) >= 0 {
        match fsize_check_write(task, start_out, count as usize, || true) {
            Ok(limited) => count = count.min(limited as u64),
            Err(errno) => {
                ctx.set_return(errno_ret(errno));
                return;
            }
        }
        if start_out >= i64::MAX as u64 {
            ctx.set_return(errno_ret(EFBIG));
            return;
        }
        count = count.min(i64::MAX as u64 - start_out);
    }

    // Don't allow overlapped copying within the same file -> -EINVAL. This
    // uses the EOF-shortened count: copying [0, 1000) of a 15-byte file to
    // offset 200 does not overlap.
    let same_file = Arc::ptr_eq(&input.ops, &output.ops)
        || (input.ops.ino() != 0
            && input.ops.ino() == output.ops.ino()
            && input.ops.inode_attrs().dev == output.ops.inode_attrs().dev);
    if same_file
        && start_out.wrapping_add(count) > start_in
        && start_out < start_in.wrapping_add(count)
    {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // vfs_copy_file_range: rw_verify_area(READ, in, &pos_in, len) and
    // rw_verify_area(WRITE, out, &pos_out, len) — negative offsets land here.
    if rw_verify_area_pos(start_in, count as usize).is_err()
        || rw_verify_area_pos(start_out, count as usize).is_err()
    {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let len = core::cmp::min(count as usize, LINUX_MAX_RW_COUNT);

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
        ctx.set_return(errno_ret(EIO));
        return;
    }

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
            ctx.set_return(errno_ret(EINVAL));
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
                            ctx.set_return(errno_ret(EINVAL));
                            return;
                        }
                        break;
                    }
                    Some(Err(error)) => {
                        if copied == 0 {
                            ctx.set_return(errno_ret(copy_fs_errno(error)));
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
                            ctx.set_return(errno_ret(EINVAL));
                            return;
                        }
                        break;
                    }
                    Some(Err(error)) => {
                        if copied == 0 {
                            ctx.set_return(errno_ret(copy_fs_errno(error)));
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
            ctx.set_return(errno_ret(copy_fs_errno(error)));
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
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(copied as u64));
}
