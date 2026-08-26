#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::SYSCALL_DEFINE2(gethostname, char __user *, name, int, len)`:
///
/// ```text
/// if (len < 0)
///         return -EINVAL;
/// down_read(&uts_sem);
/// u = utsname();
/// i = 1 + strlen(u->nodename);
/// if (i > len)
///         i = len;
/// memcpy(tmp, u->nodename, i);
/// up_read(&uts_sem);
/// if (copy_to_user(name, tmp, i))
///         return -EFAULT;
/// return 0;
/// ```
///
/// x86_64 has no `gethostname` syscall number (glibc and musl both read
/// `uname()->nodename`), so this entry point is NARF-local and keeps its
/// NARF-local success contract: it returns the hostname BYTE LENGTH, and
/// NUL-terminates, rather than Linux's truncate-and-return-0. What is not
/// NARF-local is the failure shape, and that is what changes here.
///
/// * `len` is a signed `int`. Read as a 64-bit register, `gethostname(buf,
///   -1)` became a colossal length that passed the fits-in-the-buffer test
///   and wrote past the caller's array; Linux answers -EINVAL up front.
/// * A buffer too small to hold `name + NUL` is -ENAMETOOLONG, the errno
///   POSIX specifies for exactly this and the one glibc's own
///   `uname()`-based `gethostname` raises. The bare -1 sentinel reached the
///   caller as EPERM, which reads as "you may not ask", so a caller doing
///   the standard grow-the-buffer-and-retry loop gave up instead of
///   retrying with a bigger buffer.
/// * An unwritable destination is -EFAULT, matching `copy_to_user`.
pub(crate) fn sys_gethostname(ctx: &mut dyn TrapContext) {
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    const ENAMETOOLONG: i64 = 36;
    let args = *ctx.args();
    let buf = args.arg0;
    // `int len` — 32-bit and signed.
    let len = args.arg1 as i32;
    if len < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let len = len as usize;
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
    // `len == 0` lands here too: no room for even the NUL.
    if bytes.len() + 1 > len {
        ctx.set_return(SyscallReturn::ok((-ENAMETOOLONG) as u64));
        return;
    }
    // Build NUL-terminated output in kernel memory, then copy_to_user.
    let mut kbuf = alloc::vec![0u8; bytes.len() + 1];
    kbuf[..bytes.len()].copy_from_slice(bytes);
    // kbuf[bytes.len()] is already 0 (NUL).
    let n = bytes.len();
    drop(host_owned);
    if buf == 0 {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    // SAFETY: `buf` is the user hostname buffer (non-zero, checked above; `kbuf`
    // fits in `len`); copy_to_user range-validates it and SMAP-brackets the write.
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(n as u64));
}
