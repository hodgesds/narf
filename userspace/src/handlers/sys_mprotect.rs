#[allow(unused_imports)]
use super::*;

/// `mm/mprotect.c::do_mprotect_pkey` — argument validation, in Linux's order,
/// before any VMA is touched:
///
/// ```text
///     prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
///     if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) return -EINVAL;
///     if (start & ~PAGE_MASK)                     return -EINVAL;
///     if (!len)                                   return 0;
///     len = PAGE_ALIGN(len);
///     end = start + len;
///     if (end <= start)                           return -ENOMEM;
///     if (!arch_validate_prot(prot, start))       return -EINVAL;
/// ```
///
/// `arch_validate_prot` is the generic one on x86_64/aarch64
/// (`include/linux/mman.h`): `(prot & ~(PROT_READ|PROT_WRITE|PROT_EXEC|
/// PROT_SEM)) == 0`.
///
/// The split matters to every allocator that mprotects: glibc's malloc grows
/// an arena by mprotecting the next slice of its PROT_NONE reservation and
/// retries with a fresh mmap only on **ENOMEM** ("that range is gone"); a
/// **EACCES** is a hard W^X/policy denial it must propagate; **EINVAL** means
/// its own arguments are malformed. Folding all three into one code (or into
/// the bare `-1` = EPERM this handler must never produce) turns a recoverable
/// arena miss into an abort, or an abort into an unbounded retry loop.
///
/// Two of these arms were previously silent rather than wrong: `len == 0` is a
/// **success** on Linux, and unknown `prot` bits are an **error** — NARF used
/// to reject the first and accept-and-ignore the second, so a caller passing
/// PROT_GROWSDOWN got a plain protection change with no diagnostic.
///
/// `prot` is declared `unsigned long` here but `int` in the syscall ABI, so
/// only the low 32 bits are the caller's request.
pub(crate) fn sys_mprotect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // PROT_GROWSDOWN/PROT_GROWSUP extend the change to the ends of a growable
    // VMA. NARF has no growsdown VMA to extend, so they are stripped and the
    // request applies to the literal range — but "both at once" is still the
    // contradiction Linux rejects first.
    const PROT_SEM: u32 = 0x8;
    const PROT_GROWSDOWN: u32 = 0x0100_0000;
    const PROT_GROWSUP: u32 = 0x0200_0000;
    let prot = args.arg2 as u32;
    let grows = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    let prot = prot & !(PROT_GROWSDOWN | PROT_GROWSUP);
    if grows == PROT_GROWSDOWN | PROT_GROWSUP {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if args.arg0 & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // `if (!len) return 0;` — a zero-length mprotect succeeds without looking
    // at the address at all, so it must not reach mprotect_core's "no
    // intersecting region" ENOMEM.
    if args.arg1 == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // PAGE_ALIGN wraps to zero for a length in the last page of the address
    // space; Linux then catches it with `end <= start`. Both land on ENOMEM.
    let len = args.arg1.wrapping_add(0xFFF) & !0xFFF;
    let end = args.arg0.wrapping_add(len);
    if end <= args.arg0 {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    // arch_validate_prot: PROT_SEM is accepted and has no NARF effect; any
    // other bit is a request NARF would otherwise honour only partially.
    if prot & !(0b111 | PROT_SEM) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let base = VirtAddr::new(args.arg0);
    match mprotect_core(&as_ref, base, len, prot) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        // e is the positive errno (ENOMEM for an unmapped range, EACCES for a
        // W^X denial / missing JIT cap); negate for the Linux ABI.
        Err(e) => ctx.set_return(SyscallReturn::ok((-e) as u64)),
    }
}
