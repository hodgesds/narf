#[allow(unused_imports)]
use super::*;

/// `madvise(addr, len, advice)` — Linux syscall 28. The kernel honours
/// MADV_DONTNEED (4) and MADV_FREE (8) as "release backing frames; next
/// access reads zero." Every other advice value returns Ok(0) — `madvise`
/// is a hint, not a contract, so silently accepting unknown advice values
/// matches Linux's behaviour for callers that probe by value.
///
/// `arg0` = base, `arg1` = len, `arg2` = advice.
///
/// Returns `Ok(0)` on success or no-op-advice; `InvalidOp` if no region
/// intersects the range (Linux returns ENOMEM in that case — libc maps
/// our InvalidOp to ENOMEM).
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_madvise(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    let len = args.arg1;
    let advice = args.arg2 as i32;

    // MADV_DONTNEED (4) and MADV_FREE (8) — Linux's two "release this
    // memory" hints. NARF collapses them to the same shape because we
    // don't have a swap / page-aging path to differentiate the
    // eager-release (DONTNEED) from lazy-reclaim (FREE) semantics; both
    // end up with "next access reads zero", which is what callers need.
    const MADV_DONTNEED: i32 = 4;
    const MADV_FREE: i32 = 8;

    match advice {
        MADV_DONTNEED | MADV_FREE => match as_ref.madvise_dontneed(base, len) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
        },
        // Other advice values (MADV_NORMAL, MADV_RANDOM, MADV_WILLNEED,
        // MADV_SEQUENTIAL, MADV_HUGEPAGE, MADV_NOHUGEPAGE, MADV_DONTFORK,
        // MADV_DOFORK, MADV_REMOVE, MADV_DONTDUMP, MADV_DODUMP, …) —
        // accept and ignore. `madvise` is a hint; the contract is that
        // the kernel does its best and the program runs correctly either
        // way. Returning success here matches Linux's behaviour for
        // architectures that don't implement a given advice.
        _ => ctx.set_return(SyscallReturn::ok(0)),
    }
}
