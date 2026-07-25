#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getrandom(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let len = args.arg1 as usize;
    let _flags = args.arg2; // accepted-and-ignored
    let fail = SyscallReturn::ok((-1i64) as u64);
    if ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if len > MAX_USER_COPY {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    // Generate random bytes into a kernel buffer, then copy to user
    // space under the SMAP bracket.
    let mut kbuf = alloc::vec![0u8; len];
    let mut i = 0usize;
    while i + 4 <= len {
        let v = next_random_u32();
        kbuf[i] = (v & 0xFF) as u8;
        kbuf[i + 1] = ((v >> 8) & 0xFF) as u8;
        kbuf[i + 2] = ((v >> 16) & 0xFF) as u8;
        kbuf[i + 3] = ((v >> 24) & 0xFF) as u8;
        i += 4;
    }
    if i < len {
        let v = next_random_u32();
        let mut shift = 0u32;
        while i < len {
            kbuf[i] = ((v >> shift) & 0xFF) as u8;
            i += 1;
            shift += 8;
        }
    }
    // SAFETY: `ptr` is the user buffer (non-zero, `len <= MAX_USER_COPY`, both
    // checked above); copy_to_user range-validates it and SMAP-brackets the write of `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(ptr, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(len as u64));
}
