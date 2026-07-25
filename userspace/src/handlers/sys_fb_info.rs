#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fb_info(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let handle = args.arg0;
    let user_p = args.arg1;
    let v = match fb_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let mut out = [0u32; 6];
    if !(v.info)(handle, &mut out) {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Write 6 u32s into the user pointer under the SMAP bracket.
    if user_p == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Serialise the 6 u32s into a 24-byte kernel buffer, then copy_to_user.
    let mut kbuf = [0u8; 24];
    for (i, &w) in out.iter().enumerate() {
        kbuf[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    // SAFETY: `user_p` is the user info buffer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of the 24-byte `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(user_p, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
