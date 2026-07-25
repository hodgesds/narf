#[allow(unused_imports)]
use super::*;

/// Linux futex2 `futex_waitv(waiters, nr_futexes, flags, timeout,
/// clockid)` (x86_64=449, aarch64=449). Wait on several futexes at once,
/// returning the index of the first one whose value already differs from
/// its expected `val` (Linux's "this futex is the one that was woken").
/// If every word still matches, bounded-park like `futex_wait` and report
/// index 0 on resume — the libc recheck loop re-arms across all words.
pub(crate) fn sys_futex_waitv(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    let args = *ctx.args();
    let waiters = args.arg0;
    let nr = args.arg1 as usize;
    // Linux caps futex_waitv at 128 entries; reject obviously bad shapes.
    if waiters == 0 || nr == 0 || nr > 128 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    let mut park_uaddr = 0u64;
    for i in 0..nr {
        let mut entry = [0u8; 24];
        let at = waiters + (i as u64) * 24;
        // SAFETY: each 24-byte entry range is validated by copy_from_user.
        if unsafe { copy_from_user(&mut entry, at) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
        let val = u64::from_ne_bytes(entry[0..8].try_into().unwrap());
        let uaddr = u64::from_ne_bytes(entry[8..16].try_into().unwrap());
        if uaddr == 0 {
            continue;
        }
        let current = read_user_u32(uaddr) as u64;
        if current != (val & 0xffff_ffff) {
            // This word already moved — report it as the woken futex.
            ctx.set_return(SyscallReturn::ok(i as u64));
            return;
        }
        if park_uaddr == 0 {
            park_uaddr = uaddr;
        }
    }
    // Every word still matches: park on the first real word (bounded, like
    // futex_wait), then resume as a spurious wake of index 0 (the caller
    // re-checks all of them).
    futex_wait_core(
        ctx,
        park_uaddr,
        read_user_u32(park_uaddr),
        FUTEX2_PARK_CAP_NS,
    );
}
