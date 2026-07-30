#[allow(unused_imports)]
use super::*;

#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
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
    if uargs == 0 || size < 8 {
        ctx.set_return(SyscallReturn::invalid_op());
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
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: `CloneArgs` is `#[repr(C)]` of u64s; any bit pattern
    // is a valid `CloneArgs`. `raw` has the same size + alignment
    // (u8 array can be transmuted to a struct-of-u64 because we
    // only read it).
    // SAFETY: Valid memory or trusted environment
    let ca: CloneArgs = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const CloneArgs) };
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
    do_clone3(ctx, ca);
}

#[cfg(all(feature = "linux-compat", not(target_arch = "x86_64")))]
pub(crate) fn sys_clone3(ctx: &mut dyn TrapContext) {
    // aarch64 / other arches: depends on x86_64-only user_task
    // pipeline. Will land alongside the EL0 user-task bring-up.
    ctx.set_return(SyscallReturn::invalid_op());
}
