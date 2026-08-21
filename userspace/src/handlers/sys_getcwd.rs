#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getcwd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as *mut u8;
    let len = args.arg1 as usize;
    if buf.is_null() {
        // NULL destination pointer → EFAULT. (A zero len falls through to the
        // len < needed check below, which yields ERANGE like a too-small buf.)
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    let task = current_task_id();
    let cwd = task_map_get(&CWD_TABLE, task).unwrap_or_else(|| alloc::string::String::from("/"));
    // Need cwd.len() + 1 bytes (string + NUL terminator). POSIX
    // getcwd(3) returns ERANGE when the buffer is too small — glibc's
    // getcwd grows its buffer on exactly this errno.
    let needed = cwd.len() + 1;
    if len < needed {
        // Buffer too small for the path + NUL → ERANGE.
        ctx.set_return(SyscallReturn::ok((-34i64) as u64));
        return;
    }
    // Build NUL-terminated cwd in kernel memory, then copy_to_user.
    let mut kbuf = alloc::vec![0u8; cwd.len() + 1];
    kbuf[..cwd.len()].copy_from_slice(cwd.as_bytes());
    // kbuf[cwd.len()] is already 0 (NUL).
    // SAFETY: `buf` is the user cwd buffer (non-null, `len >= needed`, both checked);
    // copy_to_user range-validates it and SMAP-brackets the write of `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(buf as u64, &kbuf) }.is_err() {
        // Faulting destination buffer → EFAULT.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(cwd.len() as u64));
}
