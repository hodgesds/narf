#[allow(unused_imports)]
use super::*;

/// `struct futex_waitv { __u64 val; __u64 uaddr; __u32 flags; __u32
/// __reserved; }` — 24 bytes (`include/uapi/linux/futex.h`).
pub(crate) const FUTEX_WAITV_SIZE: usize = 24;
/// `FUTEX_WAITV_MAX` — "Max numbers of elements in a futex_waitv array".
pub(crate) const FUTEX_WAITV_MAX: u64 = 128;

/// One decoded `struct futex_waitv` entry.
pub(crate) struct Futex2Waiter {
    pub(crate) val: u64,
    pub(crate) uaddr: u64,
    pub(crate) flags: u64,
}

/// `kernel/futex/syscalls.c::futex_parse_waitv()` — the per-entry
/// validation shared by `futex_waitv(2)` and `futex_requeue(2)`:
///
/// ```text
/// if (copy_from_user(&aux, &uwaitv[i], sizeof(aux)))          return -EFAULT;
/// if ((aux.flags & ~FUTEX2_VALID_MASK) || aux.__reserved)     return -EINVAL;
/// flags = futex2_to_flags(aux.flags);
/// if (!futex_flags_valid(flags))                              return -EINVAL;
/// if (!futex_validate_input(flags, aux.val))                  return -EINVAL;
/// ```
///
/// Note that `__reserved` is checked, not ignored. That field is how futex2
/// will grow: a caller that leaves garbage there today would silently bind
/// itself to whatever meaning the field acquires tomorrow, so Linux makes
/// the mistake loud now. Returns the negative errno Linux would report.
pub(crate) fn futex2_parse_waitv(
    waiters: u64,
    nr: usize,
) -> Result<alloc::vec::Vec<Futex2Waiter>, i64> {
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    let mut out = alloc::vec::Vec::with_capacity(nr);
    for i in 0..nr {
        let mut entry = [0u8; FUTEX_WAITV_SIZE];
        let at = waiters + (i * FUTEX_WAITV_SIZE) as u64;
        // SAFETY: each 24-byte entry range is validated by copy_from_user.
        if unsafe { copy_from_user(&mut entry, at) }.is_err() {
            return Err(EFAULT);
        }
        let val = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
        let uaddr = u64::from_ne_bytes(entry[8..16].try_into().unwrap());
        let flags = u32::from_ne_bytes(entry[16..20].try_into().unwrap()) as u64;
        let reserved = u32::from_ne_bytes(entry[20..24].try_into().unwrap());
        if reserved != 0 || !handler_sys_futex_wait::futex2_flags_valid(flags) {
            return Err(EINVAL);
        }
        // `futex_validate_input`: an expected value wider than the futex
        // word can never compare equal, so parking on it would strand the
        // caller forever. Linux refuses instead.
        if val >> 32 != 0 {
            return Err(EINVAL);
        }
        out.push(Futex2Waiter { val, uaddr, flags });
    }
    Ok(out)
}

/// `kernel/futex/syscalls.c::SYSCALL_DEFINE5(futex_waitv)` (x86_64=449,
/// aarch64=449). Wait on several futexes at once, returning the array index
/// of one of the woken futexes.
///
/// Linux's rejection order:
///   1. `if (flags) return -EINVAL;` — "This syscall supports no flags for
///      now". A flags word that is validated and then IGNORED is the worst
///      outcome: the caller believes it asked for something.
///   2. `if (!nr_futexes || nr_futexes > FUTEX_WAITV_MAX || !waiters)
///      return -EINVAL;`
///   3. `futex2_setup_timeout()` — bad clockid -EINVAL, then -EFAULT /
///      -EINVAL from the timespec.
///   4. `futex_parse_waitv()` — EVERY entry is validated before ANY word is
///      read, so a malformed entry 5 outranks a value that already moved on
///      entry 0.
///   5. `futex_wait_multiple()` — per-word -EINVAL/-EFAULT/-EAGAIN.
pub(crate) fn sys_futex_waitv(ctx: &mut dyn TrapContext) {
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    const ETIMEDOUT: i64 = 110;
    let args = *ctx.args();
    let waiters = args.arg0;
    // `unsigned int nr_futexes` / `unsigned int flags`: 32-bit arguments.
    // Reading the whole register let a caller with junk in the upper half
    // trip the `nr > 128` bound on a request Linux would have accepted.
    let nr = args.arg1 as u32 as u64;
    if args.arg2 as u32 != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    if waiters == 0 || nr == 0 || nr > FUTEX_WAITV_MAX {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let deadline = match handler_sys_futex_wait::futex2_deadline(args.arg3, args.arg4 as i32) {
        Ok(d) => d,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let entries = match futex2_parse_waitv(waiters, nr as usize) {
        Ok(e) => e,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // Only now look at the words themselves. `get_futex_key` rejects a
    // skewed address with -EINVAL before anything is read.
    for e in &entries {
        if e.uaddr % 4 != 0 {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
    }
    for (i, e) in entries.iter().enumerate() {
        let Some(current) = futex_read_user_word(e.uaddr) else {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        };
        if current as u64 != e.val {
            // This word already moved — report it as the woken futex.
            ctx.set_return(SyscallReturn::ok(i as u64));
            return;
        }
    }
    // Every word still matches: park on the first word (bounded, like
    // futex_wait), then resume as a spurious wake of index 0 (the caller
    // re-checks all of them).
    let first = &entries[0];
    let now = narf_scheduler::narf_time::monotonic_ns();
    let park_cap = match deadline {
        Some(d) if d <= now => {
            ctx.set_return(SyscallReturn::ok((-ETIMEDOUT) as u64));
            return;
        }
        // Never park past the caller's deadline; see `sys_futex_wait.rs`.
        Some(d) => (d - now).min(FUTEX2_PARK_CAP_NS),
        None => FUTEX2_PARK_CAP_NS,
    };
    futex_wait_core(
        ctx,
        futex_namespace((first.flags & FUTEX_PRIVATE) != 0),
        first.uaddr,
        first.val as u32,
        park_cap,
    );
}
