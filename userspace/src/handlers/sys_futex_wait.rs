#[allow(unused_imports)]
use super::*;

/// Bits Linux accepts in a futex2 `flags` word:
/// `FUTEX2_VALID_MASK (FUTEX2_SIZE_MASK | FUTEX2_NUMA | FUTEX2_MPOL |
/// FUTEX2_PRIVATE)` = 0x03 | 0x04 | 0x08 | 0x80 (`kernel/futex/futex.h`).
pub(crate) const FUTEX2_VALID_MASK: u64 = 0x8f;
/// `FUTEX2_SIZE_MASK` and the one access width Linux implements:
/// `futex_flags_valid()` — "Only 32bit futexes are implemented -- for now"
/// — rejects everything but `FUTEX2_SIZE_U32`.
pub(crate) const FUTEX2_SIZE_MASK: u64 = 0x03;
pub(crate) const FUTEX2_SIZE_U32: u64 = 0x02;
/// `futex2_setup_timeout()` accepts only these two clocks.
pub(crate) const FUTEX2_CLOCK_REALTIME: i32 = 0;
pub(crate) const FUTEX2_CLOCK_MONOTONIC: i32 = 1;

/// Validate a futex2 `flags` word the way
/// `kernel/futex/syscalls.c` does before every futex2 op:
/// `if (flags & ~FUTEX2_VALID_MASK) return -EINVAL;` then
/// `if (!futex_flags_valid(futex2_to_flags(flags))) return -EINVAL;`.
/// Returns `false` when Linux would answer -EINVAL.
///
/// This is not pedantry: the width bits are how futex2 will grow to 8/16/64
/// bit futexes. A kernel that ACCEPTS `FUTEX2_SIZE_U64` and then quietly
/// operates on 32 bits hands the caller a half-compared word — a lock that
/// looks free because the top half was never read. Rejecting the width we
/// do not implement is what makes the eventual widening safe.
/// `kernel/futex/futex.h::futex_validate_input`:
///
/// ```c
/// int bits = 8 * futex_size(flags);
/// if (bits < 64 && (val >> bits))
///         return false;
/// ```
///
/// A value or mask may not carry bits above the futex's access width.
/// `futex2_flags_valid` above already confines NARF to FUTEX2_SIZE_U32, so
/// the width here is always 32 — but deriving it from `flags` keeps this
/// honest for the day the 8/16/64-bit sizes are admitted.
pub(crate) fn futex2_input_valid(flags: u64, val: u64) -> bool {
    let bits = 8u32 << (flags & FUTEX2_SIZE_MASK) as u32;
    bits >= 64 || (val >> bits) == 0
}

pub(crate) fn futex2_flags_valid(flags: u64) -> bool {
    flags & !FUTEX2_VALID_MASK == 0 && flags & FUTEX2_SIZE_MASK == FUTEX2_SIZE_U32
}

/// Decode a futex2 absolute timeout the way `futex2_setup_timeout()` does:
/// the clock id is checked BEFORE the timespec is read, so a bogus clockid
/// with a faulting `timeout` pointer is -EINVAL, not -EFAULT. Returns
/// `Ok(None)` when no timeout was supplied.
pub(crate) fn futex2_deadline(timeout_ptr: u64, clockid: i32) -> Result<Option<u64>, i64> {
    const EINVAL: i64 = 22;
    if timeout_ptr == 0 {
        return Ok(None);
    }
    if clockid != FUTEX2_CLOCK_REALTIME && clockid != FUTEX2_CLOCK_MONOTONIC {
        return Err(EINVAL);
    }
    // "Since there's no opcode for futex_waitv, use FUTEX_WAIT_BITSET that
    // uses absolute timeout as well" — futex2 deadlines are always absolute.
    futex_timeout_deadline(timeout_ptr, true, clockid == FUTEX2_CLOCK_REALTIME)
}

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE6(futex_wait)` — futex2's split
/// of the classic `FUTEX_WAIT_BITSET` op (x86_64=455, aarch64=455).
///
/// Linux's rejection order, which this reproduces:
///   1. `if (flags & ~FUTEX2_VALID_MASK) return -EINVAL;`
///   2. `if (!futex_flags_valid(flags)) return -EINVAL;` — width must be
///      `FUTEX2_SIZE_U32`.
///   3. `futex2_setup_timeout()` — bad clockid -EINVAL, faulting timespec
///      -EFAULT, invalid timespec -EINVAL, in that order.
///   4. `__futex_wait()`: `if (!bitset) return -EINVAL;` — an all-zero mask
///      can never match a wake, so Linux refuses it rather than parking the
///      caller forever.
///   5. `futex_wait_setup()` → `get_futex_key()`: misaligned uaddr -EINVAL,
///      inaccessible uaddr -EFAULT, and finally `*uaddr != val` -EAGAIN.
///
/// The EAGAIN at the end is the one a lock implementation actually reads:
/// it means "the word moved while you were entering the kernel, re-read it
/// and retry the fast path". Reported as the bare -1 it arrived as EPERM,
/// which a pthread mutex has no retry rule for.
pub(crate) fn sys_futex_wait(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    const ETIMEDOUT: i64 = 110;
    let args = *ctx.args();
    // `unsigned int flags` / `clockid_t clockid` are 32-bit; `val` and
    // `mask` are `unsigned long`.
    let flags = args.arg3 as u32 as u64;
    if !futex2_flags_valid(flags) {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `futex_validate_input` applies to BOTH the expected value and the mask.
    // A 64-bit expected value against a 32-bit word can never match, so
    // accepting it would park the caller forever; and "every bit" for a
    // 32-bit futex is 0xffffffff, not ~0UL.
    if !futex2_input_valid(flags, args.arg1) || !futex2_input_valid(flags, args.arg2) {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let deadline = match futex2_deadline(args.arg4, args.arg5 as i32) {
        Ok(d) => d,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // `__futex_wait`: an empty bitset is rejected before the address is
    // even keyed, so it outranks both the alignment and the value checks.
    if args.arg2 as u32 == 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    if args.arg0 % 4 != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // A deadline already in the past is -ETIMEDOUT without parking, the
    // same shortcut the classic FUTEX_WAIT arm takes.
    let now = narf_scheduler::narf_time::monotonic_ns();
    let park_cap = match deadline {
        Some(d) if d <= now => {
            ctx.set_return(SyscallReturn::ok((-ETIMEDOUT) as u64));
            return;
        }
        // Never park past the caller's deadline: the bounded park resumes
        // with 0 (a permitted spurious wake) and the caller's recheck loop
        // re-issues, which then lands on the -ETIMEDOUT shortcut above.
        // LINUX-GAP: Linux reports -ETIMEDOUT from the park itself.
        Some(d) => (d - now).min(FUTEX2_PARK_CAP_NS),
        None => FUTEX2_PARK_CAP_NS,
    };
    futex_wait_core(
        ctx,
        futex_namespace((flags & FUTEX_PRIVATE) != 0),
        args.arg0,
        args.arg1 as u32,
        park_cap,
    );
}
