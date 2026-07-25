#[allow(unused_imports)]
use super::*;

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
