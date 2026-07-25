#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_symlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: symlinkat(const char *target, int newdirfd, const char *linkpath).
    // arg0 = target (NUL-term), arg1 = newdirfd, arg2 = linkpath (NUL-term).
    // (Was NARF-native (target_ptr, target_len, dirfd, link_ptr, link_len).)
    let target_ptr = args.arg0;
    let _dirfd = args.arg1;
    let link_ptr = args.arg2;
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
    // sys_symlink is now Linux-shaped: arg0 = target ptr, arg1 = linkpath ptr.
    let proxy_args = SyscallArgs {
        arg0: target_ptr,
        arg1: link_ptr,
        ..Default::default()
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_symlink(&mut proxy);
}
