#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_gethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf == 0 || len == 0 {
        ctx.set_return(fail);
        return;
    }
    // Wave-72: per-task UTS namespace wins when present.
    #[cfg(feature = "container")]
    let host_owned: Option<alloc::string::String> = {
        let task = current_task_id();
        crate::namespaces::uts_ns_of(task).map(|ns| ns.hostname())
    };
    #[cfg(not(feature = "container"))]
    let host_owned: Option<alloc::string::String> = None;

    let g_fallback;
    let bytes: &[u8] = if let Some(ref s) = host_owned {
        s.as_bytes()
    } else {
        g_fallback = HOSTNAME.lock();
        g_fallback.as_bytes()
    };
    if bytes.len() + 1 > len {
        ctx.set_return(fail);
        return;
    }
    // Build NUL-terminated output in kernel memory, then copy_to_user.
    let mut kbuf = alloc::vec![0u8; bytes.len() + 1];
    kbuf[..bytes.len()].copy_from_slice(bytes);
    // kbuf[bytes.len()] is already 0 (NUL).
    let n = bytes.len();
    drop(host_owned);
    // SAFETY: `buf` is the user hostname buffer (non-zero, checked above; `kbuf`
    // fits in `len`); copy_to_user range-validates it and SMAP-brackets the write.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(n as u64));
}
