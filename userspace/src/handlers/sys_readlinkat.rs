#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_readlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `ssize_t readlinkat(int dirfd, const char *path,
    // char *buf, size_t bufsiz)`.
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let buf_ptr = args.arg2 as *mut u8;
    // `SYSCALL_DEFINE4(readlinkat, ..., int, bufsiz)` — the size is a
    // 32-bit signed int, so the upper half of the register is not part of
    // it and a negative value must stay negative for the -EINVAL gate in
    // `do_readlinkat`.
    let buf_len = args.arg3 as u32 as i32 as i64;
    if buf_len <= 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `getname_flags` is the first thing every path syscall does, and it has
    // exactly two failures: a pointer it cannot read is -EFAULT, and a path
    // that reaches PATH_MAX with no terminator is -ENAMETOOLONG. This used to
    // answer -1, which reaches libc as EPERM — "operation not permitted" about
    // a caller whose only mistake was a bad pointer.
    let path_str = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let task = current_task_id();
    // `do_readlinkat` always looks up with LOOKUP_EMPTY, so "" names the
    // dirfd itself — no AT_EMPTY_PATH flag needed:
    //
    //     if (d_is_symlink(path.dentry) || inode->i_op->readlink) ...
    //     else error = (name->name[0] == '\0') ? -ENOENT : -EINVAL;
    //
    // A bad anchor is therefore -EBADF (path_init's fdget), an
    // `O_PATH|O_NOFOLLOW` descriptor on a symlink reads that link, and any
    // other descriptor (or the cwd) is -ENOENT. This used to answer -ENOENT
    // for all of them.
    if path_str.is_empty() {
        const AT_FDCWD: i64 = -100;
        let dirfd = dirfd as i32 as i64;
        if dirfd == AT_FDCWD {
            ctx.set_return(errno_ret(ENOENT));
            return;
        }
        let ops = if dirfd < 0 {
            None
        } else {
            fd::with_table(task, |t| t.get(dirfd as u32).map(|e| e.ops.clone())).flatten()
        };
        match ops {
            None => ctx.set_return(errno_ret(EBADF)),
            Some(file) if file.stat().mode.file_type == narf_filesystem::FileType::Symlink => {
                readlink_node(ctx, &file, buf_ptr, buf_len as usize);
            }
            Some(_) => ctx.set_return(errno_ret(ENOENT)),
        }
        return;
    }
    let effective = match resolve_at_path(task, dirfd, &path_str) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    readlink_impl(ctx, effective, buf_ptr, buf_len);
}
