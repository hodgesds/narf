#[allow(unused_imports)]
use super::*;

/// `mincore(addr, len, vec)` — write one residency byte per page into
/// `vec` (bit 0 set when the page is backed by a frame). Returns
/// ENOMEM if any page in the range is unmapped.
pub(crate) fn sys_mincore(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    let len = a.arg1 as usize;
    let vec_ptr = a.arg2;
    if addr & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let as_ref = match current_address_space() {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let pages = len.div_ceil(4096);
    let mut out = alloc::vec![0u8; pages];
    for (i, slot) in out.iter_mut().enumerate() {
        let va = VirtAddr::new(addr + (i as u64) * 4096);
        match as_ref.lookup(va) {
            Some(region) => {
                let idx = ((va.as_u64() - region.base.as_u64()) >> 12) as usize;
                let resident = region.phys.get(idx).map(|p| p.raw() != 0).unwrap_or(false);
                *slot = resident as u8;
            }
            None => {
                ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
                return;
            }
        }
    }
    // SAFETY: `vec_ptr` is the user residency-vector pointer; copy_to_user
    // range-validates the `pages`-byte write.
    if unsafe { copy_to_user(vec_ptr, &out) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
