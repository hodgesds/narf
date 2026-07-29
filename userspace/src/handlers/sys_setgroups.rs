#[allow(unused_imports)]
use super::*;

/// `setgroups(size, list)` — replace the caller's supplementary group list.
pub(crate) fn sys_setgroups(ctx: &mut dyn TrapContext) {
    const NGROUPS_MAX: usize = 65_536;
    let args = *ctx.args();
    let size = args.arg0 as usize;
    let list = args.arg1;
    if size > NGROUPS_MAX {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
    if size == 0 {
        let ok = write_groups(current_task_id(), alloc::vec::Vec::new());
        ctx.set_return(if ok {
            SyscallReturn::ok(0)
        } else {
            SyscallReturn::ok((-1i64) as u64)
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
        SyscallReturn::ok((-1i64) as u64)
    });
}
