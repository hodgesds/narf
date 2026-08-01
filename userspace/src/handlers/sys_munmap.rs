#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_munmap(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    match as_ref
        .unmap_region(base)
        .map(|_| ())
        .or_else(|_| as_ref.unmap_huge_region(base))
    {
        Ok(_) => {
            // Ordered after the unmap, and that order is load-bearing: this
            // call drops the mapping's `Arc<dyn FileOps>`, which for a
            // demand-paged file (a BPF arena) may be the last reference and
            // free the frames the region was still pointing at a moment ago.
            // Releasing it first would open exactly the window the arena's
            // deliberate leak used to paper over.
            crate::mapped_file::unmap_current(base.as_u64());
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
