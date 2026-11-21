//! i386 thread-local storage: `set_thread_area` / `get_thread_area` and the
//! `clone(CLONE_SETTLS)` descriptor (Linux `arch/x86/kernel/tls.c`).
//!
//! An i386 task's TLS is a GDT descriptor in one of the three per-task
//! slots 12..=14, reached through a segment register: glibc loads %gs with
//! `entry_number * 8 + 3` (0x63) after `set_thread_area(-1)` hands it slot
//! 12. Descriptor validation and encoding (`tls_desc_okay`, `fill_ldt`) are
//! `narf_arch::x86_64::segments`; the per-task slots and their reload on
//! every switch are the scheduler's (`set_current_user_tls_desc`).

use narf_arch::x86_64::segments::UserDesc;

use crate::syscall::{SyscallReturn, TrapContext};
use crate::UserSegments;

/// `set_thread_area(struct user_desc *u_info)` (i386 243).
pub fn sys_set_thread_area(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::not_implemented());
}

/// `get_thread_area(struct user_desc *u_info)` (i386 244).
pub fn sys_get_thread_area(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::not_implemented());
}

/// The calling task's segment state, as fork and clone copy it into the
/// child's `UserProcess::segs` (Linux `copy_thread` after `save_fsgs`).
pub fn current_segments() -> UserSegments {
    UserSegments::default()
}

/// Apply a `CLONE_SETTLS` descriptor to a child that has not run yet (Linux
/// `do_set_thread_area(p, -1, u_info, 0)` with `p != current`): validate
/// it, store it in its slot of `segs.tls`, and if the child's FS or GS
/// selector names that slot set the child's base to the descriptor's.
/// `info.entry_number` must name the slot (no allocation). Returns 0 or a
/// negative errno.
pub fn set_child_tls(
    segs: &mut UserSegments,
    gs_base: &mut u64,
    fs_base: &mut Option<u64>,
    info: &UserDesc,
) -> i64 {
    let _ = (segs, gs_base, fs_base, info);
    -crate::errno::ENOSYS
}

/// [`set_child_tls`] for the `user_desc` at user address `u_info` (the i386
/// `clone` TLS argument). Returns 0 or a negative errno (-EFAULT for an
/// unreadable `u_info`).
pub fn clone_settls(
    segs: &mut UserSegments,
    gs_base: &mut u64,
    fs_base: &mut Option<u64>,
    u_info: u64,
) -> i64 {
    let _ = (segs, gs_base, fs_base, u_info);
    -crate::errno::ENOSYS
}
