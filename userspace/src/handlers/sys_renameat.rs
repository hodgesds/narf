#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_renameat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _old_dirfd = args.arg0;
    // Linux ABI: `int renameat(int olddirfd, const char *oldpath,
    // int newdirfd, const char *newpath)`. Two cstrs, no lengths.
    let old_uptr = args.arg1;
    let _new_dirfd = args.arg2;
    let new_uptr = args.arg3;
    let old_str = match copy_user_cstr(old_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    let new_str = match copy_user_cstr(new_uptr, 4096) {
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
    // sys_rename is Linux-shaped: arg0 = old path ptr, arg1 = new path ptr
    // (both NUL-terminated). It was previously NARF-native
    // (old_ptr, old_len, new_ptr, new_len) and this reshape still passed
    // the lengths — so sys_rename read `old_len` as the new-path pointer
    // and every renameat(2) failed. Pass the two NUL-terminated pointers.
    let _ = (old_str, new_str); // validated above; sys_rename re-reads via the ptrs
    let proxy_args = SyscallArgs {
        arg0: old_uptr,
        arg1: new_uptr,
        ..Default::default()
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_rename(&mut proxy);
}
