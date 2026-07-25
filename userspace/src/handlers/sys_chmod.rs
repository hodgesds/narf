#[allow(unused_imports)]
use super::*;

/// Legacy `chmod(path, mode)`. Reshaped into the `fchmodat(AT_FDCWD,
/// path, mode, 0)` argument order and forwarded to [`sys_fchmodat`], so
/// a `chmod` PERSISTS the mode (file: `FileOps::set_perms`; directory:
/// `DirOps::set_dir_mode`) and a later `stat` reflects it. musl builds
/// its `chmod(3)` on top of `fchmodat`, but a program (or a NARF-native
/// caller) that issues the bare `chmod(2)` number must round-trip the
/// mode too — systemd-tmpfiles `z`/`Z` (file) and `d`/`D` (dir) lines
/// chmod a path and then stat it to confirm. The accept-and-ignore
/// `sys_access_chmod_chown` proxy (still used by `access`/`chown`) drops
/// the mode, so `chmod` gets its own entry point.
pub(crate) fn sys_chmod(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Legacy ABI: chmod(path, mode) — arg0 = path ptr, arg1 = mode.
    // sys_fchmodat reads arg1 = path ptr, arg2 = mode, arg0 = dirfd.
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
        arg0: (-100i64) as u64, // dirfd = AT_FDCWD (legacy chmod).
        arg1: args.arg0,        // path ptr.
        arg2: args.arg1,        // mode.
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_fchmodat(&mut proxy);
}
