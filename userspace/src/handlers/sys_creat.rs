#[allow(unused_imports)]
use super::*;

/// `creat(path, mode)` — equivalent to
/// `open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`. Reshapes into `sys_open`'s
/// `(path_ptr, path_len, mnt_ptr, mnt_len, flags)` ABI, mirroring sys_openat.
pub(crate) fn sys_creat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let path_uptr = a.arg0;
    let path_str = match copy_user_cstr_checked(path_uptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    const O_CREAT_WRONLY_TRUNC: u64 = 0o100 | 0o1 | 0o1000;
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
        arg4: O_CREAT_WRONLY_TRUNC,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_open(&mut proxy);
}
