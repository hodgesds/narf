#[allow(unused_imports)]
use super::*;

/// `madvise(addr, len, advice)` — Linux syscall 28. The kernel honours
/// MADV_DONTNEED (4) and MADV_FREE (8) as "release backing frames; next
/// access reads zero." Implemented performance-only hints are accepted as
/// no-ops. Unknown values and semantic controls NARF cannot honor return
/// EINVAL instead of claiming a state transition that did not happen.
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
    const MADV_NORMAL: i32 = 0;
    const MADV_RANDOM: i32 = 1;
    const MADV_SEQUENTIAL: i32 = 2;
    const MADV_WILLNEED: i32 = 3;
    const MADV_MERGEABLE: i32 = 12;
    const MADV_UNMERGEABLE: i32 = 13;
    const MADV_HUGEPAGE: i32 = 14;
    const MADV_NOHUGEPAGE: i32 = 15;
    const MADV_COLD: i32 = 20;
    const MADV_PAGEOUT: i32 = 21;

    match advice {
        MADV_DONTNEED | MADV_FREE => match as_ref.madvise_dontneed(base, len) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            // Linux madvise(2): EINVAL for a misaligned/out-of-range request,
            // else ENOMEM when the range spans an unmapped gap.
            Err(narf_memory::AddressSpaceError::AlignmentMismatch)
            | Err(narf_memory::AddressSpaceError::OutOfRange) => {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64))
            }
            Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)),
        },
        // These values are performance hints only. NARF has no readahead,
        // KSM, THP promotion, or active LRU aging policy to tune yet, so a
        // successful no-op preserves their contract.
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_MERGEABLE
        | MADV_UNMERGEABLE | MADV_HUGEPAGE | MADV_NOHUGEPAGE | MADV_COLD | MADV_PAGEOUT => {
            ctx.set_return(SyscallReturn::ok(0));
        }
        // DONTFORK/DOFORK, WIPEONFORK/KEEPONFORK, DONTDUMP/DODUMP,
        // POPULATE_*, REMOVE, COLLAPSE, guard pages, and unknown values have
        // observable semantics beyond a hint. Fail explicitly until those
        // state machines exist.
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
    }
}
