#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_tcsetattr(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _fd = args.arg0;
    let _action = args.arg1;
    let in_ptr = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if in_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let mut bytes = [0u8; core::mem::size_of::<KTermios>()];
    // SAFETY: `in_ptr` is the user termios pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the read into `bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut bytes, in_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    // SAFETY: `bytes` is `size_of::<KTermios>()` bytes; KTermios is repr(C) of POD
    // ints + byte arrays, so any bit pattern is a valid value — transmute is a 1:1 view.
    // SAFETY: Valid memory or trusted environment
    let t: KTermios = unsafe { core::mem::transmute(bytes) };
    set_termios_of_task(task, t);
    ctx.set_return(SyscallReturn::ok(0));
}
