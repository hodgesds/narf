#[allow(unused_imports)]
use super::*;

/// `shmget(key, size, shmflg)` — create or look up a shared segment with
/// real frame backing.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmget_compat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let key = a.arg0 as u32;
    let size = a.arg1;
    let flg = a.arg2;
    #[cfg(feature = "container")]
    let ipc_namespace = current_shm_ipc_ns();
    #[cfg(feature = "container")]
    let ipc_ns = ipc_namespace.id();
    #[cfg(not(feature = "container"))]
    let ipc_ns = current_shm_ipc_ns_id();
    let mut g = SHM_SEGMENTS.lock();
    let segs = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    if key != 0 {
        if let Some(((_, id), seg)) = segs
            .iter()
            .find(|((namespace, _), s)| *namespace == ipc_ns && s.key == key && !s.removed)
        {
            let id = *id;
            if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // EEXIST
                return;
            }
            if size > seg.len {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            if !shm_ipc_allowed(seg, (flg as u32) & 0o777) {
                ctx.set_return(SyscallReturn::ok((-13i64) as u64)); // EACCES
                return;
            }
            ctx.set_return(SyscallReturn::ok(id));
            return;
        }
        if flg & IPC_CREAT == 0 {
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // ENOENT
            return;
        }
    }
    if size == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    const SHMMNI: usize = 4096;
    let shmmax = (v.max_len)();
    if size > shmmax {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let requested_pages = size.div_ceil(4096);
    let (live_ids, used_pages) = segs
        .iter()
        .filter(|((namespace, _), _)| *namespace == ipc_ns)
        .fold((0usize, 0u64), |(ids, pages), (_, seg)| {
            (
                ids.saturating_add(usize::from(!seg.removed)),
                pages.saturating_add(seg.len.div_ceil(4096)),
            )
        });
    let shmall = SHMMNI as u64 * shmmax / 4096;
    if used_pages.saturating_add(requested_pages) > shmall || live_ids >= SHMMNI {
        ctx.set_return(SyscallReturn::ok((-28i64) as u64)); // ENOSPC
        return;
    }
    // SysV segments belong to the IPC namespace, not to the creating
    // process. Owner id 0 exempts this backing from the generic per-process
    // shmem exit reaper; IPC_RMID/final detach owns destruction instead.
    let handle = (v.create)(0, size);
    if handle == 0 {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    #[cfg(feature = "container")]
    let shmid = u64::from(ipc_namespace.alloc_shm_id());
    #[cfg(not(feature = "container"))]
    let shmid = SHM_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let creator = current_task_id();
    let cpid = task_to_pid_raw(creator).unwrap_or(creator);
    let cred = current_ucred();
    segs.insert(
        (ipc_ns, shmid),
        ShmSegment {
            handle,
            key,
            len: size,
            uid: cred.uid,
            gid: cred.gid,
            cuid: cred.uid,
            cgid: cred.gid,
            mode: (flg as u32) & 0o777,
            cpid,
            lpid: 0,
            atime: 0,
            dtime: 0,
            ctime: shm_now_seconds(),
            nattch: 0,
            locked: false,
            removed: false,
        },
    );
    ctx.set_return(SyscallReturn::ok(shmid));
}
