#[allow(unused_imports)]
use super::*;

#[cfg(all(
    feature = "linux-compat",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn sys_clone3(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let uargs = args.arg0;
    let size = args.arg1 as usize;
    #[cfg(feature = "syscall-trace")]
    if crate::syscall::syscall_trace_target_task() {
        narf_console::write_str(&alloc::format!(
            "[CLONE3 uargs={:#x} size={}]\n",
            uargs,
            size
        ));
    }
    if size > 4096 {
        // Linux caps extensible syscall structs at one page.
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // -E2BIG
        return;
    }
    if size < 64 {
        // CLONE_ARGS_SIZE_VER0 is the oldest accepted wire shape.
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if uargs == 0 {
        // NULL clone_args pointer → EFAULT.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }

    // Copy in just what we honour. Larger user structs (Linux has
    // grown the struct several times) are read as a prefix; smaller
    // ones (unlikely — the minimum Linux ever shipped was 64 bytes)
    // would be rejected above on the 8-byte floor.
    let copy_len = core::cmp::min(size, CLONE_ARGS_MIN);
    let mut raw = [0u8; CLONE_ARGS_MIN];
    // SAFETY: `uargs` is the user clone_args pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the read of `copy_len`
    // (<= CLONE_ARGS_MIN) bytes into the `raw` prefix.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut raw[..copy_len], uargs) }.is_err() {
        // Faulting clone_args buffer → EFAULT.
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    // Forward-compatible larger structs are accepted only when every byte
    // beyond the newest shape known to this kernel is zero. Linux's
    // copy_struct_from_user reports E2BIG for a non-zero unknown tail.
    let mut tail_off = CLONE_ARGS_MIN;
    while tail_off < size {
        let mut tail = [0u8; 64];
        let n = core::cmp::min(tail.len(), size - tail_off);
        let Some(src) = uargs.checked_add(tail_off as u64) else {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        };
        // SAFETY: src is the checked user pointer at the current tail offset;
        // copy_from_user range-validates the n-byte read.
        if unsafe { copy_from_user(&mut tail[..n], src) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
        if tail[..n].iter().any(|&byte| byte != 0) {
            ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // -E2BIG
            return;
        }
        tail_off += n;
    }
    // SAFETY: `CloneArgs` is `#[repr(C)]` of u64s; any bit pattern
    // is a valid `CloneArgs`. `raw` has the same size + alignment
    // (u8 array can be transmuted to a struct-of-u64 because we
    // only read it).
    // SAFETY: Valid memory or trusted environment
    let ca: CloneArgs = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const CloneArgs) };
    if ca.set_tid_size > 32
        || (ca.set_tid == 0 && ca.set_tid_size != 0)
        || (ca.set_tid != 0 && ca.set_tid_size == 0)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if ca.exit_signal > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if ca.flags & CLONE_INTO_CGROUP != 0 && (size < CLONE_ARGS_MIN || ca.cgroup > i32::MAX as u64) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if ca.set_tid != 0 {
        // Linux copies the pid_t array before checking whether the caller may
        // request specific PIDs. Preserve EFAULT precedence over the EPERM
        // returned by NARF's capability policy.
        let Some(bytes) = (ca.set_tid_size as usize).checked_mul(core::mem::size_of::<i32>())
        else {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        };
        let mut set_tid = [0u8; 32 * core::mem::size_of::<i32>()];
        // SAFETY: copy_from_user validates the checked byte range; the shape
        // checks above bound it to the fixed buffer.
        if unsafe { copy_from_user(&mut set_tid[..bytes], ca.set_tid) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    }
    #[cfg(feature = "syscall-trace")]
    if crate::syscall::syscall_trace_target_task() {
        narf_console::write_str(&alloc::format!(
            "[CLONE3 flags={:#x} pidfd_ptr={:#x} cgroup_fd={} stack={:#x}+{:#x}]\n",
            ca.flags,
            ca.pidfd,
            ca.cgroup,
            ca.stack,
            ca.stack_size
        ));
    }
    do_clone3(ctx, ca, false);
}

#[cfg(all(
    feature = "linux-compat",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
pub(crate) fn sys_clone3(ctx: &mut dyn TrapContext) {
    // Not implemented on this arch → ENOSYS (glibc's clone3→clone fallback keys on it).
    ctx.set_return(SyscallReturn::ok((-38i64) as u64));
}
