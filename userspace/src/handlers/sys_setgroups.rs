#[allow(unused_imports)]
use super::*;

/// `kernel/groups.c::SYSCALL_DEFINE2(setgroups)` — replace the caller's
/// supplementary group list.
///
/// ```text
/// if (!may_setgroups())               return -EPERM;
/// if ((unsigned)gidsetsize > NGROUPS_MAX)  return -EINVAL;
/// group_info = groups_alloc(gidsetsize);
/// if (!group_info)                    return -ENOMEM;
/// retval = groups_from_user(group_info, grouplist);   /* -EFAULT / -EINVAL */
/// ```
///
/// and, per entry, `kernel/groups.c::groups_from_user()`:
///
/// ```text
/// if (get_user(gid, grouplist+i))     return -EFAULT;
/// kgid = make_kgid(user_ns, gid);
/// if (!gid_valid(kgid))               return -EINVAL;
/// ```
///
/// `gidsetsize` is a signed `int` that Linux compares as `unsigned`, which
/// is what makes a negative size EINVAL. Reading the raw 64-bit register
/// got the negative case right only by accident and got the positive case
/// wrong: a caller whose upper register half held junk (a value like
/// `1 << 32`) had its perfectly legal `setgroups(0, NULL)` rejected.
///
/// The EINVAL for an unmapped gid is the one a container runtime reads: it
/// means "that gid has no mapping in your user namespace", i.e. fix the
/// gid_map, as distinct from the EPERM that means "you may not call this
/// at all".
pub(crate) fn sys_setgroups(ctx: &mut dyn TrapContext) {
    const ENOMEM: i64 = 12;
    const NGROUPS_MAX: u32 = 65_536;
    let args = *ctx.args();
    // `int gidsetsize`, compared as `unsigned` — a negative size becomes a
    // huge unsigned and trips the bound.
    let size = args.arg0 as i32 as u32;
    let list = args.arg1;
    if size > NGROUPS_MAX {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    let size = size as usize;
    if size == 0 {
        // `groups_from_user` copies nothing, so `grouplist` is never read.
        let ok = write_groups(current_task_id(), alloc::vec::Vec::new());
        ctx.set_return(if ok {
            SyscallReturn::ok(0)
        } else {
            // Linux's only remaining failure here is the credential
            // allocation, which is -ENOMEM.
            SyscallReturn::ok((-ENOMEM) as u64)
        });
        return;
    }
    if list == 0 {
        ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
        return;
    }
    let mut bytes = alloc::vec![0u8; size * 4];
    // SAFETY: list is a user pointer; copy_from_user validates and SMAP-brackets.
    if unsafe { copy_from_user(&mut bytes, list) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-(EFAULT as i64)) as u64));
        return;
    }
    let mut groups = alloc::vec::Vec::with_capacity(size);
    for chunk in bytes.chunks_exact(4) {
        let gid = u32::from_ne_bytes(chunk.try_into().unwrap());
        #[cfg(feature = "container")]
        {
            let ns = crate::namespaces::current_user_ns(current_task_id());
            if !ns.is_initial() && !ns.gid_is_mapped(gid) {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
        }
        groups.push(gid);
    }
    let ok = write_groups(current_task_id(), groups);
    ctx.set_return(if ok {
        SyscallReturn::ok(0)
    } else {
        SyscallReturn::ok((-ENOMEM) as u64)
    });
}
