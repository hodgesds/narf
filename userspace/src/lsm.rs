//! Batch 25 — generic LSM self-attribute syscalls (Linux 6.8):
//! `lsm_list_modules` / `lsm_get_self_attr` / `lsm_set_self_attr`.
//!
//! NARF's active security modules are the always-on capability checker and
//! (since batch 24) Landlock, so `lsm_list_modules` reports those two ids.
//! Neither exposes a per-process security *context* string — NARF has no
//! MAC label — so `lsm_get_self_attr(LSM_ATTR_CURRENT)` returns zero
//! attributes and `lsm_set_self_attr` is unsupported. That is the truthful
//! answer for NARF's security model, not a stub.

use crate::handlers::{copy_from_user, copy_to_user};
use crate::syscall::{SyscallReturn, TrapContext};

// ── errno (negated-long convention) ─────────────────────────────────
const E2BIG: i64 = 7;
const EINVAL: i64 = 22;
const EFAULT: i64 = 14;
const EOPNOTSUPP: i64 = 95;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

// LSM module ids (uapi/linux/lsm.h).
const LSM_ID_CAPABILITY: u64 = 100;
const LSM_ID_LANDLOCK: u64 = 110;
/// The security modules NARF actually runs.
const ACTIVE_MODULES: [u64; 2] = [LSM_ID_CAPABILITY, LSM_ID_LANDLOCK];

/// `lsm_list_modules(ids, size, flags)` — list active LSM ids.
///
/// `size` is an in/out `size_t*`: in = buffer bytes available, out = bytes
/// required. Returns the module count, or `-E2BIG` (with `*size` set to the
/// required length) when the buffer is too small.
pub fn sys_lsm_list_modules(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let ids_ptr = a.arg0;
    let size_ptr = a.arg1;
    let flags = a.arg2;
    if flags != 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let needed = (ACTIVE_MODULES.len() * 8) as u64;
    let mut szb = [0u8; 8];
    // SAFETY: copy_from_user range-validates the 8-byte size_t.
    if unsafe { copy_from_user(&mut szb, size_ptr) }.is_err() {
        ctx.set_return(err(EFAULT));
        return;
    }
    let avail = u64::from_ne_bytes(szb);
    // Always report the required length back.
    // SAFETY: range-validated by copy_to_user.
    if unsafe { copy_to_user(size_ptr, &needed.to_ne_bytes()) }.is_err() {
        ctx.set_return(err(EFAULT));
        return;
    }
    if avail < needed {
        ctx.set_return(err(E2BIG));
        return;
    }
    let mut buf = [0u8; ACTIVE_MODULES.len() * 8];
    for (i, id) in ACTIVE_MODULES.iter().enumerate() {
        buf[i * 8..i * 8 + 8].copy_from_slice(&id.to_ne_bytes());
    }
    // SAFETY: range-validated by copy_to_user.
    if unsafe { copy_to_user(ids_ptr, &buf) }.is_err() {
        ctx.set_return(err(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(ACTIVE_MODULES.len() as u64));
}

/// `lsm_get_self_attr(attr, ctx, size, flags)` — read a security attribute
/// of the calling task. NARF exposes no context-bearing LSM, so every
/// attribute yields zero `lsm_ctx` entries; `*size` is set to 0.
pub fn sys_lsm_get_self_attr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let size_ptr = a.arg2;
    if size_ptr != 0 {
        // SAFETY: range-validated by copy_to_user.
        let _ = unsafe { copy_to_user(size_ptr, &0u64.to_ne_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `lsm_set_self_attr(attr, ctx, size, flags)` — set a security attribute.
/// NARF has no settable MAC context, so this is unsupported.
pub fn sys_lsm_set_self_attr(ctx: &mut dyn TrapContext) {
    ctx.set_return(err(EOPNOTSUPP));
}
