#[allow(unused_imports)]
use super::*;

/// `mremap(old_addr, old_len, new_len, flags, new_addr)` — resize an
/// existing anonymous mapping. NARF implements the in-place grow path:
/// the region keeps its frames at `old_addr` and the grown tail is
/// lazily backed (demand-paged) like a fresh mmap, so contents are
/// preserved with no copy. Shrink / no-op returns `old_addr`
/// unchanged; a grow that would collide with another region returns
/// `-ENOMEM` (we don't relocate even with MREMAP_MAYMOVE today), and
/// `MREMAP_FIXED` — an explicit move to a caller-chosen address — is
/// refused with `-ENOMEM` up front rather than "succeeding" in place.
pub(crate) fn sys_mremap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let old_addr = args.arg0;
    let old_len = (args.arg1 + 0xFFF) & !0xFFFu64;
    let new_len = (args.arg2 + 0xFFF) & !0xFFFu64;
    let flags = args.arg3 as u32;
    const MREMAP_MAYMOVE: u32 = 1;
    const MREMAP_FIXED: u32 = 2;
    const MREMAP_DONTUNMAP: u32 = 4;
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    if old_addr & 0xFFF != 0
        || new_len == 0
        || flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // MREMAP_FIXED asks for relocation to arg4's exact address —
    // which we don't implement. Fail with -ENOMEM (the Linux "cannot
    // move" answer) instead of returning old_addr as a fake success:
    // a caller believing the move happened would touch the requested
    // new address and SEGV (stress-ng --mmapfixed hammers exactly
    // this shape with arbitrary 64-bit targets).
    if flags & MREMAP_FIXED != 0 {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    if new_len <= old_len {
        // Shrink / unchanged — keep the mapping where it is.
        ctx.set_return(SyscallReturn::ok(old_addr));
        return;
    }
    match as_ref.grow_region(VirtAddr::new(old_addr), new_len) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(old_addr)),
        Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)), // ENOMEM
    }
}
