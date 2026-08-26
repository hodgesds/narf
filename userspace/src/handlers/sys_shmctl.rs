#[allow(unused_imports)]
use super::*;

const SHMID64_SIZE: usize = 112;

fn shm_put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn shm_put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn shm_put_i64(out: &mut [u8], offset: usize, value: i64) {
    out[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn shm_ids_to_user(uid: u32, gid: u32) -> (u32, u32) {
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(current_task_id());
        (
            ns.translate_uid_from_host(uid)
                .unwrap_or(crate::namespaces::OVERFLOW_ID),
            ns.translate_gid_from_host(gid)
                .unwrap_or(crate::namespaces::OVERFLOW_ID),
        )
    }
    #[cfg(not(feature = "container"))]
    (uid, gid)
}

fn shm_ids_from_user(uid: u32, gid: u32) -> Result<(u32, u32), ()> {
    #[cfg(feature = "container")]
    {
        let ns = crate::namespaces::current_user_ns(current_task_id());
        if !ns.uid_is_mapped(uid) || !ns.gid_is_mapped(gid) {
            return Err(());
        }
        Ok((ns.translate_uid_to_host(uid), ns.translate_gid_to_host(gid)))
    }
    #[cfg(not(feature = "container"))]
    Ok((uid, gid))
}

/// `shmctl(shmid, cmd, buf)` for the native 64-bit Linux ABI.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmctl(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let signed_shmid = a.arg0 as u32 as i32;
    let signed_cmd = a.arg1 as u32 as i32;
    if signed_shmid < 0 || signed_cmd < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    let shmid = signed_shmid as u32 as u64;
    let cmd = signed_cmd as u32 as u64;
    #[cfg(feature = "container")]
    let ipc_namespace = current_shm_ipc_ns();
    #[cfg(feature = "container")]
    let ipc_ns = ipc_namespace.id();
    #[cfg(not(feature = "container"))]
    let ipc_ns = current_shm_ipc_ns_id();
    let object = (ipc_ns, shmid);

    match cmd {
        IPC_STAT => {
            // Linux resolves the id and checks read permission before the
            // final full-structure copy_to_user.
            let snapshot = {
                let segments = SHM_SEGMENTS.lock();
                let Some(seg) = segments
                    .as_ref()
                    .and_then(|map| map.get(&object))
                    .filter(|seg| !seg.removed)
                else {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                };
                if !shm_ipc_allowed(seg, 0o4) {
                    ctx.set_return(SyscallReturn::ok((-13i64) as u64));
                    return;
                }
                (
                    seg.key, seg.uid, seg.gid, seg.cuid, seg.cgid, seg.mode, seg.len, seg.atime,
                    seg.dtime, seg.ctime, seg.cpid, seg.lpid, seg.nattch,
                )
            };
            let (uid, gid) = shm_ids_to_user(snapshot.1, snapshot.2);
            let (cuid, cgid) = shm_ids_to_user(snapshot.3, snapshot.4);
            let reader = current_task_id();
            let visible_pid = |pid: u64| -> u32 {
                if pid == 0 {
                    0
                } else {
                    report_pid_to(reader, pid) as u32
                }
            };
            let mut out = [0u8; SHMID64_SIZE];
            shm_put_u32(&mut out, 0, snapshot.0);
            shm_put_u32(&mut out, 4, uid);
            shm_put_u32(&mut out, 8, gid);
            shm_put_u32(&mut out, 12, cuid);
            shm_put_u32(&mut out, 16, cgid);
            shm_put_u32(&mut out, 20, snapshot.5 & 0o777);
            shm_put_u64(&mut out, 48, snapshot.6);
            shm_put_i64(&mut out, 56, snapshot.7);
            shm_put_i64(&mut out, 64, snapshot.8);
            shm_put_i64(&mut out, 72, snapshot.9);
            shm_put_u32(&mut out, 80, visible_pid(snapshot.10));
            shm_put_u32(&mut out, 84, visible_pid(snapshot.11));
            shm_put_u64(&mut out, 88, snapshot.12);
            // SAFETY: `buf` is the native shmid64_ds output pointer; the
            // guarded helper validates and copies the complete structure.
            if unsafe { copy_to_user(a.arg2, &out) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(0));
            }
        }
        IPC_SET => {
            // Linux imports the complete shmid64_ds before looking up shmid.
            // SAFETY: the guarded helper validates the entire native input
            // structure before returning its kernel-owned copy.
            let input = match unsafe { copy_from_user_vec(a.arg2, SHMID64_SIZE) } {
                Ok(input) => input,
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64));
                    return;
                }
            };
            let uid = u32::from_ne_bytes(input[4..8].try_into().unwrap());
            let gid = u32::from_ne_bytes(input[8..12].try_into().unwrap());
            let mode = u32::from_ne_bytes(input[20..24].try_into().unwrap());
            let mut segments = SHM_SEGMENTS.lock();
            let Some(seg) = segments
                .as_mut()
                .and_then(|map| map.get_mut(&object))
                .filter(|seg| !seg.removed)
            else {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                return;
            };
            if !shm_ipc_owner(seg) {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                return;
            }
            let (uid, gid) = match shm_ids_from_user(uid, gid) {
                Ok(ids) => ids,
                Err(()) => {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
            };
            seg.uid = uid;
            seg.gid = gid;
            seg.mode = (seg.mode & !0o777) | (mode & 0o777);
            seg.ctime = shm_now_seconds();
            ctx.set_return(SyscallReturn::ok(0));
        }
        IPC_RMID => {
            let destroy = {
                let mut segments = SHM_SEGMENTS.lock();
                let map = segments.get_or_insert_with(alloc::collections::BTreeMap::new);
                let Some(seg) = map.get_mut(&object).filter(|seg| !seg.removed) else {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                };
                if !shm_ipc_owner(seg) {
                    ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                    return;
                }
                seg.removed = true;
                seg.key = 0;
                if seg.nattch == 0 {
                    map.remove(&object).map(|seg| seg.handle)
                } else {
                    None
                }
            };
            if let (Some(handle), Some(vtable)) = (destroy, shmem_vtable()) {
                if handle != 0 {
                    (vtable.destroy)(handle);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)),
    }
}
