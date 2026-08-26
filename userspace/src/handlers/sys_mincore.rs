#[allow(unused_imports)]
use super::*;

/// `mincore(addr, len, vec)` — write one residency byte per page into
/// `vec` (bit 0 set when the page is backed by a frame). Returns
/// ENOMEM if any page in the range is unmapped.
///
/// `mm/mincore.c::SYSCALL_DEFINE3(mincore)` uses three different codes and
/// commits to their order:
///
/// ```text
///     if (unlikely(start & ~PAGE_MASK))       return -EINVAL;
///     if (!access_ok((void __user *)start, len)) return -ENOMEM;
///     pages = len >> PAGE_SHIFT;
///     pages += (offset_in_page(len)) != 0;
///     if (!access_ok(vec, pages))             return -EFAULT;
///     ... do_mincore() /* unmapped page in the range => -ENOMEM */
/// ```
///
/// The `vec` EFAULT check runs **before** the walk, so a request with both a
/// bad output buffer and an unmapped range reports EFAULT, not ENOMEM. That
/// order is what makes mincore usable as a probe: tools that page-in-check a
/// heap (jemalloc's dirty-page accounting, `vmtouch`, CRIU's pre-dump) treat
/// ENOMEM as the authoritative "this range is not mapped" answer and stop
/// probing. Letting a mistyped `vec` pointer produce ENOMEM makes them
/// conclude a live mapping had disappeared.
pub(crate) fn sys_mincore(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    let vec_ptr = a.arg2;
    if addr & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // `access_ok(start, len)`. Structural range rejection does not need the
    // scheduler's current-AS lock. This is especially hot under mmapfixed,
    // which intentionally asks about non-canonical powers of two before
    // attempting each mapping.
    if addr >= AddressSpace::USER_HALF_END
        || a.arg1
            .checked_add(0xFFF)
            .and_then(|len| addr.checked_add(len & !0xFFF))
            .is_none_or(|end| end > AddressSpace::USER_HALF_END)
    {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    // `access_ok(vec, pages)` — one output byte per (rounded-up) page, and
    // Linux answers a bad buffer here rather than after the walk.
    let pages = (a.arg1 >> 12) + u64::from(a.arg1 & 0xFFF != 0);
    if pages != 0 && validate_user_range(vec_ptr, pages as usize).is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let as_ref = match current_address_space() {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let out = match as_ref.residency_range(VirtAddr::new(addr), a.arg1) {
        Ok(out) => out,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
            return;
        }
    };
    // SAFETY: `vec_ptr` is the user residency-vector pointer; copy_to_user
    // range-validates the `pages`-byte write.
    if !out.is_empty() && unsafe { copy_to_user(vec_ptr, &out) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
