//! i386 thread-local storage: `set_thread_area` / `get_thread_area` and the
//! `clone(CLONE_SETTLS)` descriptor (Linux `arch/x86/kernel/tls.c`).
//!
//! An i386 task's TLS is a GDT descriptor in one of the three per-task
//! slots 12..=14, reached through a segment register: glibc loads %gs with
//! `entry_number * 8 + 3` (0x63) after `set_thread_area(-1)` hands it slot
//! 12. Descriptor validation and encoding (`tls_desc_okay`, `fill_ldt`) are
//! `narf_arch::x86_64::segments`; the per-task slots and their reload on
//! every switch are the scheduler's (`set_current_user_tls_desc`).

use narf_arch::x86_64::segments::{self, UserDesc, GDT_ENTRY_TLS_MAX, GDT_ENTRY_TLS_MIN};

use crate::errno::{EFAULT, EINVAL, ESRCH};
use crate::syscall::{SyscallReturn, TrapContext};
use crate::UserSegments;

/// The descriptor a validated request installs: empty for either "no
/// segment" spelling, `fill_ldt` otherwise (Linux `set_tls_desc`).
fn desc_for(info: &UserDesc) -> u64 {
    if segments::ldt_empty(info) || segments::ldt_zero(info) {
        0
    } else {
        segments::fill_ldt(info)
    }
}

/// `entry_number` as Linux's `int idx`: a slot index, or -1 for "allocate".
fn requested_slot(info: &UserDesc) -> i64 {
    i64::from(info.entry_number as i32)
}

/// Is `idx` a TLS slot's GDT index (`GDT_ENTRY_TLS_MIN..=GDT_ENTRY_TLS_MAX`)?
fn is_tls_index(idx: i64) -> bool {
    (GDT_ENTRY_TLS_MIN as i64..=GDT_ENTRY_TLS_MAX as i64).contains(&idx)
}

/// Copy the `user_desc` at `u_info` in.
fn read_user_desc(u_info: u64) -> Option<UserDesc> {
    let mut raw = [0u8; segments::USER_DESC_BYTES];
    // SAFETY: syscall context on the caller's own address space.
    unsafe { crate::handlers::copy_from_user(&mut raw, u_info) }.ok()?;
    Some(UserDesc::from_bytes(raw))
}

/// Linux `do_set_thread_area(current, -1, u_info, 1)`: validate, pick the
/// slot (allocating the first empty one for entry -1 and writing it back),
/// install the descriptor in the task and this CPU, and refresh any data
/// segment register naming the slot. Returns 0 or a negative errno.
fn set_thread_area_current(u_info: u64) -> i64 {
    let Some(info) = read_user_desc(u_info) else {
        return -EFAULT;
    };
    if !segments::tls_desc_okay(&info) {
        return -EINVAL;
    }
    let mut idx = requested_slot(&info);
    if idx == -1 {
        let Some(free) = segments::get_free_idx(&narf_scheduler::stackful::current_user_tls())
        else {
            return -ESRCH;
        };
        // put_user(idx, &u_info->entry_number)
        // SAFETY: syscall context on the caller's own address space.
        if unsafe { crate::handlers::copy_to_user(u_info, &free.to_ne_bytes()) }.is_err() {
            return -EFAULT;
        }
        idx = i64::from(free);
    }
    if !is_tls_index(idx) {
        return -EINVAL;
    }
    narf_scheduler::stackful::set_current_user_tls_desc(
        idx as usize - GDT_ENTRY_TLS_MIN,
        desc_for(&info),
    );
    0
}

/// Linux `do_get_thread_area(current, -1, u_info)`: read the slot index
/// from `u_info->entry_number` and write the slot back as a `user_desc`.
fn get_thread_area_current(u_info: u64) -> i64 {
    let mut raw = [0u8; 4];
    // get_user(idx, &u_info->entry_number)
    // SAFETY: syscall context on the caller's own address space.
    if unsafe { crate::handlers::copy_from_user(&mut raw, u_info) }.is_err() {
        return -EFAULT;
    }
    let idx = i64::from(i32::from_ne_bytes(raw));
    if !is_tls_index(idx) {
        return -EINVAL;
    }
    let slot = idx as usize - GDT_ENTRY_TLS_MIN;
    let desc = narf_scheduler::stackful::current_user_tls()[slot];
    let info = segments::fill_user_desc(idx as u32, desc);
    // SAFETY: syscall context on the caller's own address space.
    if unsafe { crate::handlers::copy_to_user(u_info, &info.to_bytes()) }.is_err() {
        return -EFAULT;
    }
    0
}

/// `set_thread_area(struct user_desc *u_info)` (i386 243).
pub fn sys_set_thread_area(ctx: &mut dyn TrapContext) {
    let ret = set_thread_area_current(ctx.args().arg0);
    ctx.set_return(SyscallReturn::ok(ret as u64));
}

/// `get_thread_area(struct user_desc *u_info)` (i386 244).
pub fn sys_get_thread_area(ctx: &mut dyn TrapContext) {
    let ret = get_thread_area_current(ctx.args().arg0);
    ctx.set_return(SyscallReturn::ok(ret as u64));
}

/// The calling task's segment state, as fork and clone copy it into the
/// child's `UserProcess::segs` (Linux `copy_thread` after `save_fsgs`).
pub fn current_segments() -> UserSegments {
    let (tls, sel) = narf_scheduler::stackful::current_user_segments();
    UserSegments {
        tls,
        ds: sel.ds,
        es: sel.es,
        fs: sel.fs,
        gs: sel.gs,
    }
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
    if !segments::tls_desc_okay(info) {
        return -EINVAL;
    }
    // can_allocate = 0: entry -1 stays -1 and fails the range check.
    let idx = requested_slot(info);
    if !is_tls_index(idx) {
        return -EINVAL;
    }
    segs.tls[idx as usize - GDT_ENTRY_TLS_MIN] = desc_for(info);
    let modified = ((idx as u16) << 3) | 3;
    if segs.fs == modified {
        *fs_base = Some(u64::from(info.base_addr));
    }
    if segs.gs == modified {
        *gs_base = u64::from(info.base_addr);
    }
    0
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
    match read_user_desc(u_info) {
        Some(info) => set_child_tls(segs, gs_base, fs_base, &info),
        None => -EFAULT,
    }
}
