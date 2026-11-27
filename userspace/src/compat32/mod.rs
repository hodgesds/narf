//! IA-32 system calls on x86_64 (Linux `CONFIG_IA32_EMULATION`).
//!
//! `int 0x80` is the i386 system-call gate for every task, 32-bit or 64-bit
//! (Linux `entry_INT80_compat` / `do_int80_emulation`): eax is the number
//! from `arch/x86/entry/syscalls/syscall_32.tbl`, ebx, ecx, edx, esi, edi
//! and ebp are the six arguments, zero-extended, and the result comes back
//! in eax; every other register is preserved.
//!
//! `frame`'s gate builds a [`TrapContext`] whose `args()` are that i386
//! register view, whose `set_return` writes eax ([`user_rax`]) and whose
//! `in_ia32_syscall()` is true, then calls [`dispatch`] with the number.
//! [`dispatch`] owns the entry work (seccomp with `AUDIT_ARCH_I386`, the
//! TLS calls in [`tls`], signal delivery with restart semantics) and hands
//! every other number to [`table::dispatch`], the i386 table proper.
//!
//! Ownership: the hook, [`user_rax`] and [`tls`] belong to the frame /
//! TCB work; [`table`]'s contents belong to the IA-32 userspace work, as
//! does [`mm`], the per-address-space state the ELF32 loader leaves for
//! later syscalls (`fs/compat_binfmt_elf.c`: `start_brk`, the exec-time
//! `READ_IMPLIES_EXEC`).

pub(crate) mod conv;
pub(crate) mod ctx;
pub(crate) mod ipc;
pub mod mm;
pub mod table;
pub mod tls;

use core::sync::atomic::Ordering;

use crate::syscall::{Syscall, SyscallReturn, TrapContext};

/// i386 `set_thread_area` (`syscall_32.tbl` 243).
pub const NR_SET_THREAD_AREA: u32 = 243;
/// i386 `get_thread_area` (`syscall_32.tbl` 244).
pub const NR_GET_THREAD_AREA: u32 = 244;

/// Width of `int 0x80` (CD 80): the rewind a re-executed call takes.
const INT80_LEN: u64 = 2;

/// Serve i386 system call `nr` (eax) on `ctx`, the gate's i386 view of the
/// trap frame. Returns with the result in `ctx` and any pending signal
/// delivered; the gate then restores eax to `nr` if the call parked to be
/// re-executed (RIP rewound onto `int 0x80`).
///
/// Mirrors the `syscall`-instruction path
/// (`kernel_syscall_entry_plain_with_state`): `__secure_computing` for the
/// i386 number and arch, `/proc/<pid>/syscall` bookkeeping, the call, then
/// the exit-to-user signal work. A call that parked and rewound RIP is
/// RESTART-PENDING: a caught signal completes it as -EINTR unless
/// `SA_RESTART` applies to the native call that served it (Linux
/// `handle_signal` over `-ERESTARTSYS`).
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) {
    let entry_rip = ctx.rip();
    let uctx = crate::user_task::current_user_task();
    let served = match crate::seccomp::secure_computing(ctx, nr) {
        // The filter (or its tracer) consumed the call and set the return
        // or queued the signal; deliver it below.
        None => None,
        Some(nr) => {
            // The in-syscall number is recorded only once a reader has
            // armed the latch (see `task::IN_SYSCALL_TRACKING`); the
            // context is still resolved below for the park-restart flag.
            if crate::task::in_syscall_tracking_enabled() {
                if let Some(u) = uctx {
                    // SAFETY: the in-flight task's poller-pinned context; atomic
                    // store only.
                    unsafe { (*u).in_syscall.store(nr.wrapping_add(1), Ordering::Relaxed) };
                }
            }
            let served = match nr {
                NR_SET_THREAD_AREA => {
                    tls::sys_set_thread_area(ctx);
                    None
                }
                NR_GET_THREAD_AREA => {
                    tls::sys_get_thread_area(ctx);
                    None
                }
                _ => table::dispatch(nr, ctx),
            };
            if let Some(u) = uctx {
                // SAFETY: as above.
                unsafe {
                    (*u).parked_in_syscall.store(false, Ordering::Release);
                    // The in-syscall number is recorded only once a reader
                    // has armed the latch (see `task::IN_SYSCALL_TRACKING`).
                    if crate::task::in_syscall_tracking_enabled() {
                        (*u).in_syscall.store(0, Ordering::Relaxed);
                    }
                }
            }
            served
        }
    };
    if !ctx.returning_to_user() {
        return;
    }
    // CPU-clock itimers sampled at the kernel→user transition, as on the
    // `syscall` path.
    crate::handlers::timer_tick_raise_due_signals();
    let rewound = ctx.rip() == entry_rip.wrapping_sub(INT80_LEN);
    let marked = uctx.is_some_and(|u| {
        // SAFETY: the in-flight task's poller-pinned context; atomic load.
        unsafe { (*u).syscall_parked_restarting.load(Ordering::Acquire) }
    });
    if marked && rewound {
        let native = served.map_or(crate::handlers::SYSCALL_NUM_NONE, Syscall::raw);
        crate::handlers::default_signal_delivery_restart_pending(ctx, native);
    } else {
        crate::default_signal_delivery(ctx, crate::handlers::SYSCALL_NUM_NONE);
    }
    if ctx.rip() != entry_rip.wrapping_sub(INT80_LEN) {
        // Completed, signal-directed or exec frame: drop the park marker so
        // a later RIP change is never mistaken for a restart-pending park.
        if let Some(u) = uctx {
            // SAFETY: as above; atomic store only.
            unsafe {
                (*u).syscall_parked_restarting
                    .store(false, Ordering::Release)
            };
        }
    }
}

/// The eax/rax an i386 caller sees for `ret`: the value, sign-extended to
/// 64 bits as Linux stores `regs->ax`. A NARF non-Ok status without an
/// errno in its value (`invalid_op`) reads as -EINVAL, as on the `syscall`
/// path; one that carries an errno (`not_implemented`'s -ENOSYS) keeps it.
pub fn user_rax(ret: SyscallReturn) -> u64 {
    if ret.status == SyscallReturn::OK || ret.value >= (-4095i64) as u64 {
        ret.value
    } else {
        (-crate::errno::EINVAL) as u64
    }
}
