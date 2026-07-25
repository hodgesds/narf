#[allow(unused_imports)]
use super::*;

/// Linux ABI variant of `open(2)`: `int open(const char *pathname,
/// int flags, mode_t mode)`. Forwards to [`sys_open`] after
/// measuring the path length via [`copy_user_cstr`] (musl's open
/// call passes flags in arg1, not the NARF-native path_len).
pub(crate) fn sys_open_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_uptr = args.arg0;
    let flags = args.arg1;
    let _mode = args.arg2;
    let fail = SyscallReturn::ok(!0u64);
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
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
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: 0,
        arg3: 0,
        arg4: flags,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_open(&mut proxy);
}
