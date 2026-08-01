#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0;
    let path_len = args.arg1 as usize;
    let mnt_ptr = args.arg2;
    let mnt_len = args.arg3 as usize;
    let flags = args.arg4;
    // Copy path from userspace into kernel buffer under SMAP bracket.
    // Use the *raw* copy (no chroot) — `open_impl`'s `resolve_cwd_path` is the
    // single point that re-roots under the task's chroot. Using the
    // chroot-applying `copy_user_path` here would compose the chroot
    // prefix twice (e.g. `/init` → `/jail/jail/init`).
    let path_owned_raw = match copy_user_path_raw(path_ptr, path_len) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
    };
    open_impl(ctx, path_owned_raw, flags, mnt_ptr, mnt_len, 0o666);
}
