#[allow(unused_imports)]
use super::*;

/// `fs/d_path.c::SYSCALL_DEFINE2(getcwd)` decides the result in this order:
///
/// ```text
///     prepend_char(&b, 0);              /* the NUL goes in FIRST */
///     prepend_path(&pwd, &root, &b);
///     len = PATH_MAX - b.len;
///     if (unlikely(len > PATH_MAX))            error = -ENAMETOOLONG;
///     else if (unlikely(len > size))           error = -ERANGE;
///     else if (copy_to_user(buf, b.buf, len))  error = -EFAULT;
///     else                                     error = len;
/// ```
///
/// Two contract details follow from that, and this handler used to get both
/// wrong:
///
///   * The success value is `len`, and `len` COUNTS THE NUL — the terminator
///     is prepended before the path is, so `getcwd` of `/foo` returns 5, not
///     4. glibc sizes the heap buffer it hands back from `getcwd(NULL, 0)`
///     off this number and musl bounds its `memcpy` with it; one byte short
///     drops the last character of every path a caller reads back.
///   * ERANGE is decided BEFORE the buffer is written, so a too-small buffer
///     wins over a faulting one and `getcwd(NULL, 0)` is ERANGE rather than
///     EFAULT. glibc's dynamic getcwd deliberately probes with a small
///     buffer and doubles it on exactly ERANGE; any other errno makes it
///     give up and report failure instead of growing.
pub(crate) fn sys_getcwd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0 as *mut u8;
    // Linux takes `unsigned long size`; a "negative" size is simply huge.
    let len = args.arg1 as usize;
    let task = current_task_id();
    let cwd = task_map_get(&CWD_TABLE, task).unwrap_or_else(|| alloc::string::String::from("/"));
    // The kernel's `len`: the path plus its NUL terminator. This is both the
    // ERANGE threshold and the value returned on success.
    let needed = cwd.len() + 1;
    if needed > len {
        // Buffer too small for the path + NUL → ERANGE, ahead of any check
        // on `buf` itself (Linux never touches the buffer on this path).
        ctx.set_return(SyscallReturn::ok((-34i64) as u64)); // -ERANGE
        return;
    }
    if buf.is_null() {
        // A NULL destination that WAS big enough is the copy_to_user arm.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // Build NUL-terminated cwd in kernel memory, then copy_to_user.
    let mut kbuf = alloc::vec![0u8; needed];
    kbuf[..cwd.len()].copy_from_slice(cwd.as_bytes());
    // kbuf[cwd.len()] is already 0 (NUL).
    // SAFETY: `buf` is the user cwd buffer (non-null, `len >= needed`, both checked);
    // copy_to_user range-validates it and SMAP-brackets the write of `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(buf as u64, &kbuf) }.is_err() {
        // Faulting destination buffer → EFAULT.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // LINUX-GAP: Linux answers -ENOENT when the cwd's dentry has been
    // unlinked (`d_unlinked(pwd.dentry)`), and -ENAMETOOLONG when the
    // reconstructed path exceeds PATH_MAX. NARF stores the cwd as a string
    // and never invalidates it, so neither state is representable here.
    ctx.set_return(SyscallReturn::ok(needed as u64));
}
