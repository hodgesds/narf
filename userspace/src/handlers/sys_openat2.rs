#[allow(unused_imports)]
use super::*;

/// `openat2(dirfd, path, open_how*, size)` — openat with the
/// extensible `open_how { u64 flags; u64 mode; u64 resolve; }` struct.
/// Reads `flags` and `mode` from the struct and routes through the openat
/// path; `resolve` is accepted but not yet enforced.
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
    let mode = u64::from_ne_bytes(how[8..16].try_into().unwrap());
    // `openat2` is an extensible version of `openat`, not of NARF's legacy
    // length-delimited `open` ABI. In particular, retain `dirfd`: systemd's
    // mount-unit path walker opens each child relative to an O_PATH parent
    // and later uses that parent in mkdirat(). Routing through `sys_open`
    // discarded the directory fd, so the returned descriptor had no usable
    // backing path for the subsequent mkdirat.
    let proxy_args = SyscallArgs {
        arg0: args.arg0,
        arg1: path_uptr,
        arg2: flags,
        arg3: mode,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = ReshapeArgs {
        inner: ctx,
        args: proxy_args,
    };
    sys_openat(&mut proxy);
}
