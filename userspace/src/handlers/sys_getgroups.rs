#[allow(unused_imports)]
use super::*;

/// `kernel/groups.c::SYSCALL_DEFINE2(getgroups)` — return the caller's
/// supplementary group list.
///
/// ```text
/// if (gidsetsize < 0)
///         return -EINVAL;
/// i = cred->group_info->ngroups;
/// if (gidsetsize) {
///         if (i > gidsetsize) { i = -EINVAL; goto out; }
///         if (groups_to_user(grouplist, cred->group_info)) { i = -EFAULT; goto out; }
/// }
/// out:
///         return i;
/// ```
///
/// Two things follow from `gidsetsize` being a signed `int`:
///
///   * A negative size is -EINVAL, and it is the FIRST check. Reading the
///     argument as a 64-bit register instead turned `getgroups(-1, buf)`
///     into an enormous "size" that sailed past the `i > gidsetsize`
///     bound and wrote the whole list into a buffer the caller never
///     sized — a silent overflow where Linux gives a clean EINVAL.
///   * `gidsetsize == 0` is the "how many groups are there?" query and
///     must not touch `grouplist` at all.
///
/// The -EINVAL for a too-small buffer is load-bearing too: the documented
/// idiom is `getgroups(0, NULL)` to size, allocate, then call again, and
/// EINVAL is how a caller that lost a race (the list grew in between)
/// learns to re-size rather than truncate.
pub(crate) fn sys_getgroups(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `int gidsetsize` — 32-bit and signed.
    let size = args.arg0 as i32;
    let list = args.arg1;
    if size < 0 {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    let size = size as usize;
    let groups = read_groups(current_task_id());
    if size == 0 {
        ctx.set_return(SyscallReturn::ok(groups.len() as u64));
        return;
    }
    if size < groups.len() {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    // `groups_to_user` copies exactly `ngroups` entries, so an empty list
    // never dereferences `grouplist` — `getgroups(n, NULL)` with no
    // supplementary groups is a successful 0, not EFAULT.
    if groups.is_empty() {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if list == 0 {
        ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
        return;
    }
    let mut bytes = alloc::vec::Vec::with_capacity(groups.len() * 4);
    for gid in groups {
        bytes.extend_from_slice(&gid.to_ne_bytes());
    }
    // SAFETY: list is a user pointer; copy_to_user validates and SMAP-brackets.
    if unsafe { copy_to_user(list, &bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
    } else {
        ctx.set_return(SyscallReturn::ok((bytes.len() / 4) as u64));
    }
}
