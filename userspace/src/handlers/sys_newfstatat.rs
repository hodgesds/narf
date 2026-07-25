#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_newfstatat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int fstatat(int dirfd, const char *pathname,
    // struct stat *statbuf, int flags)`. arg2 is statbuf, not
    // path_len.
    let _dirfd = args.arg0;
    let path_uptr = args.arg1;
    let stat_out = args.arg2;
    let _flags = args.arg3;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
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
        arg2: stat_out,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_stat(&mut proxy);
}
