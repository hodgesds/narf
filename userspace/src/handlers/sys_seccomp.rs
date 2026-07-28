#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_seccomp(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let op = args.arg0;
    let flags = args.arg1;
    let task = current_task_id();

    const SECCOMP_SET_MODE_STRICT: u64 = 0;
    const SECCOMP_SET_MODE_FILTER: u64 = 1;
    const SECCOMP_GET_ACTION_AVAIL: u64 = 2;

    const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 8;

    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
    const SECCOMP_RET_TRAP: u32 = 0x00030000;
    const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

    if op == SECCOMP_SET_MODE_STRICT || op == SECCOMP_SET_MODE_FILTER {
        if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
            // EINVAL (-22) for unsupported NEW_LISTENER flag
            ctx.set_return(SyscallReturn::ok(!21u64));
            return;
        }
        modify_prctl(task, |s| s.seccomp_mode = 2);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    if op == SECCOMP_GET_ACTION_AVAIL {
        let action_ptr = args.arg2;
        let mut act_bytes = [0u8; 4];
        if unsafe { copy_from_user(&mut act_bytes, action_ptr) }.is_ok() {
            let action = u32::from_ne_bytes(act_bytes);
            if matches!(
                action,
                SECCOMP_RET_KILL_PROCESS
                    | SECCOMP_RET_KILL_THREAD
                    | SECCOMP_RET_TRAP
                    | SECCOMP_RET_ERRNO
                    | SECCOMP_RET_ALLOW
            ) {
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
        }
        // EOPNOTSUPP (-95)
        ctx.set_return(SyscallReturn::ok(!94u64));
        return;
    }

    ctx.set_return(SyscallReturn::ok(0));
}
