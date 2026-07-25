#[allow(unused_imports)]
use super::*;

/// `openat2(dirfd, path, open_how*, size)` — openat with the
/// extensible `open_how { u64 flags; u64 mode; u64 resolve; }` struct.
/// Reads `flags` from the struct and routes through the openat/open
/// path; `mode` and `resolve` are accepted but not enforced.
pub(crate) fn sys_openat2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_uptr = args.arg1;
    let how_ptr = args.arg2;
    let size = args.arg3 as usize;
    let fail = SyscallReturn::ok(!0u64);
    if how_ptr == 0 || size < 24 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // SAFETY: `how_ptr` is the user `struct open_how*`; copy_from_user_vec
    // range-validates the 24-byte read.
    let how = match unsafe { copy_from_user_vec(how_ptr, 24) } {
        Ok(b) => b,
        Err(_) => {
            ctx.set_return(fail);
            return;
        }
    };
    let flags = u64::from_ne_bytes(how[0..8].try_into().unwrap());
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let proxy_args = SyscallArgs {
        arg0: path_uptr,
        arg1: path_str.len() as u64,
        arg2: 0,
        arg3: 0,
        arg4: flags,
        arg5: 0,
    };
    let mut proxy = ReshapeArgs {
        inner: ctx,
        args: proxy_args,
    };
    sys_open(&mut proxy);
}
