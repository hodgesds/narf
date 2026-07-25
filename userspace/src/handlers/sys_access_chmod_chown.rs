#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_access(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let mode = args.arg1 as u32;
    if mode & !7 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    let raw = match copy_user_cstr(args.arg0, 4096) {
        Some(path) => path,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    let path = resolve_cwd_path(current_task_id(), &raw);
    access_path(ctx, &path, mode);
}

pub(crate) fn sys_faccessat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let mode = args.arg2 as u32;
    if mode & !7 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    let raw = match copy_user_cstr(args.arg1, 4096) {
        Some(path) => path,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    const AT_FDCWD: i64 = -100;
    let dirfd = args.arg0 as i64;
    let effective = if raw.starts_with('/') || dirfd == AT_FDCWD {
        raw
    } else if dirfd >= 0 {
        match fd_path_of(current_task_id(), dirfd as u32) {
            Some(base) => alloc::format!("{}/{}", base.trim_end_matches('/'), raw),
            None => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64));
                return;
            }
        }
    } else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    let path = resolve_cwd_path(current_task_id(), &effective);
    access_path(ctx, &path, mode);
}

fn access_path(ctx: &mut dyn TrapContext, path: &str, mode: u32) {
    let Some(file) = xattr_file(path) else {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64));
        return;
    };
    match poll_blocking(file.access(mode)) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        Some(Err(narf_filesystem::FsError::PermissionDenied)) => {
            ctx.set_return(SyscallReturn::ok((-13i64) as u64))
        }
        Some(Err(narf_filesystem::FsError::Unsupported)) | None => {
            let st = file.stat();
            let (uid, gid) = file.owners();
            let request = narf_filesystem::AccessRequest {
                read: mode & 4 != 0,
                write: mode & 2 != 0,
                exec: mode & 1 != 0,
            };
            let allowed = narf_filesystem::posix_access_ok(
                narf_filesystem::FileOwner {
                    uid,
                    gid,
                    perms: st.mode.perms,
                },
                current_accessor(current_task_id()),
                request,
            );
            ctx.set_return(SyscallReturn::ok(if allowed { 0 } else { (-13i64) as u64 }));
        }
        _ => ctx.set_return(SyscallReturn::ok((-5i64) as u64)),
    }
}

pub(crate) fn sys_access_chmod_chown(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI for the three legacy entries:
    //   access(path, mode)      — arg1 = mode
    //   chmod(path, mode)       — arg1 = mode
    //   chown(path, uid, gid)   — arg1 = uid, arg2 = gid
    // All take an absolute path as a NUL-terminated cstr; the body
    // forwards to `sys_fchmodat_or_fchownat` which only enforces
    // the structural "path must be absolute" contract — we drop
    // the mode/uid/gid in the proxy so the underlying path-len
    // shape lines up.
    let path_uptr = args.arg0;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            // Unreadable user path pointer → EFAULT, not a bare -1 → EPERM.
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, ret: SyscallReturn) {
            self.inner.set_return(ret);
        }
        fn user_rsp(&self) -> u64 {
            self.inner.user_rsp()
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: (-100i64) as u64, // dirfd = AT_FDCWD (legacy access/chmod/chown).
        arg1: path_uptr,
        arg2: path_str.len() as u64,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_fchmodat_or_fchownat(&mut proxy);
}
