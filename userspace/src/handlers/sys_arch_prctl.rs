#[allow(unused_imports)]
use super::*;

#[cfg(target_arch = "x86_64")]
pub(crate) fn sys_arch_prctl(ctx: &mut dyn TrapContext) {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    // `TASK_SIZE_MAX` for 4-level paging: `(1 << 47) - PAGE_SIZE`
    // (arch/x86/include/asm/page_64_types.h).
    const TASK_SIZE_MAX: u64 = (1 << 47) - 4096;

    let args = *ctx.args();
    let code = args.arg0;
    let addr = args.arg1;

    match code {
        // arch/x86/kernel/process_64.c::do_arch_prctl_64: both SET arms
        // refuse a base at or above TASK_SIZE_MAX with -EPERM before touching
        // anything ("Not strictly needed for %fs, but do it for symmetry").
        ARCH_SET_FS | ARCH_SET_GS if addr >= TASK_SIZE_MAX => {
            ctx.set_return(errno_ret(EPERM));
        }
        ARCH_SET_GS => {
            // The user GS base sits in IA32_KERNEL_GS_BASE while the kernel's
            // GS is live; the exit `swapgs` makes it the user's GS.base.
            // SAFETY: CPL0 syscall context; `addr` is below TASK_SIZE_MAX.
            unsafe { narf_arch::x86_64::user_mode::set_user_gs_base(addr) };
            // Per-task slot, so a preempt/park resume restores it.
            narf_scheduler::stackful::set_current_user_gs_base(addr);
            ctx.set_return(SyscallReturn::ok(0));
        }
        ARCH_GET_GS => {
            // `put_user(x86_gsbase_read_task(task), arg2)` — -EFAULT on a bad
            // pointer.
            // SAFETY: CPL0 syscall context, kernel GS live.
            let gs_base = unsafe { narf_arch::x86_64::user_mode::user_gs_base() };
            // SAFETY: copy_to_user range-validates and SMAP-brackets the write.
            if unsafe { copy_to_user(addr, &gs_base.to_le_bytes()) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        ARCH_SET_FS => {
            // SAFETY: `addr` is treated as an opaque u64 the user
            // owns — the MSR write is unconditional at CPL=0 and
            // any canonical-vaddr invariant is the user task's
            // responsibility (Linux behaves the same way).
            // SAFETY: Valid memory or trusted environment
            unsafe {
                narf_scheduler::set_user_fs_base(addr);
            }
            // Publish to the own-stack kernel_switch resume slot too: a
            // park/preempt resumes WITHOUT re-running `UserTaskFuture::poll`, so
            // `poll_to_yield` reloads FS_BASE from the per-task slot — it must
            // reflect this arch_prctl, else the next resume reverts to the stale
            // published value and the task's TLS reads fault.
            #[cfg(target_arch = "x86_64")]
            narf_scheduler::stackful::set_current_user_fs_base(addr);
            // Publish to the polling-future override so a
            // subsequent timer-driven re-poll restores THIS
            // FS_BASE, not the load-time synthetic-TLS value
            // from `process.fs_base`.
            if let Some(uctx) = crate::user_task::current_user_task() {
                // SAFETY: pending_fs_base is an AtomicU64 owned by
                // the live UserTaskCtx pinned for the duration of
                // this syscall.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    (*uctx)
                        .pending_fs_base
                        .store(addr, core::sync::atomic::Ordering::Release);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        ARCH_GET_FS => {
            // Read the live FS_BASE, copy it as a u64 to `addr`.
            let fs_base: u64;
            // SAFETY: `rdmsr` reads MSR `ecx`=IA32_FS_BASE into edx:eax; the MSR is
            // architectural and readable at CPL0. Operands name the ABI registers and
            // the instruction has no memory side effects.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                use core::arch::asm;
                let lo: u32;
                let hi: u32;
                const IA32_FS_BASE: u32 = 0xC000_0100;
                asm!(
                    "rdmsr",
                    in("ecx") IA32_FS_BASE,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, preserves_flags),
                );
                fs_base = (lo as u64) | ((hi as u64) << 32);
            }
            let buf = fs_base.to_le_bytes();
            // SAFETY: `addr` is the user-supplied destination; copy_to_user
            // range-validates it and SMAP-brackets the 8-byte write of `buf`.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_to_user(addr, &buf) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        }
    }
}
