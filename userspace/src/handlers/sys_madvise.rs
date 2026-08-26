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
/// `mm/madvise.c::madvise_should_skip` runs the range validation for **every**
/// advice value, before the per-behaviour work and before any VMA lookup:
///
/// ```text
///     is_valid_madvise():
///         if (!madvise_behavior_valid(behavior))  return false;  /* -EINVAL */
///         if (!PAGE_ALIGNED(start))               return false;  /* -EINVAL */
///         len = PAGE_ALIGN(len_in);
///         if (len_in && !len)                     return false;  /* -EINVAL */
///         if (start + len < start)                return false;  /* -EINVAL */
///     if (start + PAGE_ALIGN(len_in) == start) { *err = 0; return true; }
/// ```
///
/// The zero-length arm is the one that bites: `madvise(p, 0, MADV_DONTNEED)`
/// is a **success** on Linux, and jemalloc/tcmalloc emit it whenever a purge
/// run rounds down to nothing. Reporting ENOMEM there makes an allocator
/// conclude its arena was unmapped underneath it. Symmetrically, a misaligned
/// `addr` is EINVAL (the caller must fix its arguments) and never ENOMEM
/// ("this range is gone"), which would send it looking for a mapping that is
/// in fact still there.
///
/// `advice` is an `int`, so only the low 32 bits are the caller's request.
///
/// Returns `Ok(0)` on success or no-op-advice; `InvalidOp` if the task has no
/// address space (unreachable for a real user task).
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_madvise(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let base = VirtAddr::new(args.arg0);
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

    let accepted = matches!(
        advice,
        MADV_DONTNEED
            | MADV_FREE
            | MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_MERGEABLE
            | MADV_UNMERGEABLE
            | MADV_HUGEPAGE
            | MADV_NOHUGEPAGE
            | MADV_COLD
            | MADV_PAGEOUT
    );
    // DONTFORK/DOFORK, WIPEONFORK/KEEPONFORK, DONTDUMP/DODUMP, POPULATE_*,
    // REMOVE, COLLAPSE, guard pages, and unknown values have observable
    // semantics beyond a hint. Fail explicitly until those state machines
    // exist. LINUX-GAP: Linux accepts the named ones; only a genuinely
    // unknown `advice` is EINVAL there.
    if !accepted {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // `!PAGE_ALIGNED(start)`, `len_in && !PAGE_ALIGN(len_in)`, and the
    // `start + len < start` wrap — all EINVAL, all before the zero-length
    // success arm because Linux orders them that way.
    let len = args.arg1.wrapping_add(0xFFF) & !0xFFF;
    if args.arg0 & 0xFFF != 0
        || (args.arg1 != 0 && len == 0)
        || args.arg0.checked_add(len).is_none()
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // `start + PAGE_ALIGN(len_in) == start` — nothing to do, and Linux says
    // so with 0 rather than consulting the address space at all.
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    match advice {
        MADV_DONTNEED | MADV_FREE => match as_ref.madvise_dontneed(base, len) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            // The range was validated above, so what is left is a coverage
            // failure: Linux's madvise_walk_vmas returns ENOMEM when the
            // request spans an unmapped gap.
            Err(narf_memory::AddressSpaceError::AlignmentMismatch)
            | Err(narf_memory::AddressSpaceError::OutOfRange) => {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64))
            }
            Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)),
        },
        // These values are performance hints only. NARF has no readahead,
        // KSM, THP promotion, or active LRU aging policy to tune yet, so a
        // successful no-op preserves their contract.
        //
        // LINUX-GAP: madvise_walk_vmas applies to hints too, so Linux reports
        // ENOMEM when the range is not fully mapped. NARF has no gap-aware
        // VMA-coverage query cheap enough to run on this path, so a hint over
        // an unmapped range succeeds here.
        _ => ctx.set_return(SyscallReturn::ok(0)),
    }
}
