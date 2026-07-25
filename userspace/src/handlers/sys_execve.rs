#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_execve(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int execve(const char *pathname, char *const argv[],
    // char *const envp[])`. Register mapping on x86_64:
    //   rdi = pathname (NUL-terminated C string)
    //   rsi = argv     (NULL-terminated array of `char *`)
    //   rdx = envp     (NULL-terminated array of `char *`)
    let path_uptr = args.arg0;
    let argv_uptr = args.arg1;
    let envp_uptr = args.arg2;

    if path_uptr == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }

    // Step 1: copy the pathname from user memory under SMAP.
    let path_owned = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    do_execve_resolved(ctx, path_owned, argv_uptr, envp_uptr, None);
}
