#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_getaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _pid = args.arg0;
    let size = args.arg1 as usize;
    let out = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out == 0 || size == 0 {
        ctx.set_return(fail);
        return;
    }
    // Linux requires `size` be a multiple of sizeof(unsigned long)
    // (8 on x86_64). Round down for the actual write but reject
    // truly tiny requests so a caller's `cpu_set_t` matches.
    if size < 8 {
        ctx.set_return(fail);
        return;
    }
    let bytes = size & !7; // round to 8
                           // Validate the destination range before allocating — an oversized size
                           // would otherwise OOM the kernel heap before copy_to_user fires.
    if validate_user_range(out, bytes).is_err() {
        ctx.set_return(fail);
        return;
    }
    // Build the affinity bitmap in kernel memory (CPU 0 set, rest zero),
    // then copy to user space under the SMAP bracket.
    let mut kbuf = alloc::vec![0u8; bytes];
    kbuf[0] = 0x01; // CPU 0 set
                    // SAFETY: `out`+`bytes` were validated by validate_user_range above; copy_to_user
                    // re-validates and SMAP-brackets the write of the `bytes`-long `kbuf`.
                    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(bytes as u64));
}
