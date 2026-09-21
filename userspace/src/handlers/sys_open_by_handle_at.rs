#[allow(unused_imports)]
use super::*;

/// `open_by_handle_at(mount_fd, handle, flags)`.
pub(crate) fn sys_open_by_handle_at(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    const ESTALE: i64 = 116;
    const EFAULT: i64 = 14;
    const EBADF: i64 = 9;
    const AT_FDCWD: i64 = -100;
    let a = *ctx.args();
    let mount_fd = a.arg0 as i64;
    if mount_fd != AT_FDCWD {
        if mount_fd < 0 {
            ctx.set_return(SyscallReturn::ok((-EBADF) as u64));
            return;
        }
        let valid =
            fd::with_table(current_task_id(), |t| t.get(mount_fd as u32).is_some()).unwrap_or(false);
        if !valid {
            ctx.set_return(SyscallReturn::ok((-EBADF) as u64));
            return;
        }
    }
    let mut hdr = [0u8; 8];
    // SAFETY: copy_from_user validates the 8-byte header read.
    if unsafe { copy_from_user(&mut hdr, a.arg1) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let hbytes = u32::from_ne_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let htype = i32::from_ne_bytes(hdr[4..8].try_into().unwrap());
    // An nsfs handle resolves through the namespace tree, not the VFS:
    // `nsfs_fh_to_dentry` looks the id up, cross-checks the type and inode
    // against what it found, and applies the same visibility rule
    // `/proc/<pid>/ns/` does — otherwise a handle would be a way around it.
    #[cfg(feature = "container")]
    if htype == super::handler_nsfs::FILEID_NSFS {
        const EMFILE: i64 = -24;
        let n = core::cmp::max(hbytes, super::handler_nsfs::NSFS_FILE_HANDLE_SIZE);
        // SAFETY: copy_from_user_vec validates the f_handle range.
        let fid = match unsafe { copy_from_user_vec(a.arg1 + 8, n) } {
            Ok(b) => b,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
                return;
            }
        };
        let task = current_task_id();
        match super::handler_nsfs::decode_handle(task, &fid) {
            Ok(held) => {
                let ops: Arc<dyn narf_filesystem::FileOps> = crate::namespaces::NsFd::new(held);
                let f = fd::install(
                    task,
                    fd::FdEntry {
                        ops,
                        offset: 0,
                        flags: crate::fd::FD_CLOEXEC,
                        status_flags: 0,
                    },
                );
                match f {
                    Some(f) => ctx.set_return(SyscallReturn::ok(u64::from(f))),
                    None => ctx.set_return(SyscallReturn::ok(EMFILE as u64)),
                }
            }
            Err(e) => ctx.set_return(SyscallReturn::ok(e as u64)),
        }
        return;
    }
    if htype != NARF_HANDLE_TYPE {
        ctx.set_return(SyscallReturn::ok((-ESTALE) as u64));
        return;
    }
    if hbytes == 0 || hbytes > 4096 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // SAFETY: copy_from_user_vec validates the f_handle range.
    let path_bytes = match unsafe { copy_from_user_vec(a.arg1 + 8, hbytes) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    };
    let path = match alloc::string::String::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-ESTALE) as u64));
            return;
        }
    };
    let fd = fanotify_open_object(current_task_id(), &path);
    if fd < 0 {
        ctx.set_return(SyscallReturn::ok((-ESTALE) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(fd as u64));
}
