#[allow(unused_imports)]
use super::*;

/// `mincore(addr, len, vec)` — write one residency byte per page into
/// `vec` (bit 0 set when the page is backed by a frame). Returns
/// ENOMEM if any page in the range is unmapped.
pub(crate) fn sys_mincore(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    let vec_ptr = a.arg2;
    if addr & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Structural range rejection does not need the scheduler's current-AS
    // lock. This is especially hot under mmapfixed, which intentionally asks
    // about non-canonical powers of two before attempting each mapping.
    if addr >= AddressSpace::USER_HALF_END
        || a.arg1
            .checked_add(0xFFF)
            .and_then(|len| addr.checked_add(len & !0xFFF))
            .is_none_or(|end| end > AddressSpace::USER_HALF_END)
    {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
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
