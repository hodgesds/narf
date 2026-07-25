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
    let mut g = SHM_SEGMENTS.lock();
    let segs = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    if key != 0 {
        if let Some((id, _)) = segs.iter().find(|(_, s)| s.key == key) {
            let id = *id;
            if flg & IPC_CREAT != 0 && flg & IPC_EXCL != 0 {
                ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // EEXIST
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
    let v = match shmem_vtable() {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let handle = (v.create)(current_task_id(), size);
    if handle == 0 {
        ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
        return;
    }
    let shmid = SHM_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    segs.insert(
        shmid,
        ShmSegment {
            handle,
            key,
            len: size,
        },
    );
    ctx.set_return(SyscallReturn::ok(shmid));
}
