#[allow(unused_imports)]
use super::*;

const SHMID64_SIZE: usize = 112;
const SHMINFO64_SIZE: usize = 72;
const SHM_INFO_SIZE: usize = 48;
const SHMMNI: u64 = 4096;
const SHM_LOCK: u64 = 11;
const SHM_UNLOCK: u64 = 12;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const SHM_STAT_ANY: u64 = 15;
const SHM_LOCKED: u32 = 0o2000;

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

type ShmStatSnapshot = (u32, u32, u32, u32, u32, u32, u64, i64, i64, i64, u64, u64, u64);

fn encode_shm_stat(snapshot: ShmStatSnapshot) -> [u8; SHMID64_SIZE] {
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
    shm_put_u32(&mut out, 20, snapshot.5);
    shm_put_u64(&mut out, 48, snapshot.6);
    shm_put_i64(&mut out, 56, snapshot.7);
    shm_put_i64(&mut out, 64, snapshot.8);
    shm_put_i64(&mut out, 72, snapshot.9);
    shm_put_u32(&mut out, 80, visible_pid(snapshot.10));
    shm_put_u32(&mut out, 84, visible_pid(snapshot.11));
    shm_put_u64(&mut out, 88, snapshot.12);
    out
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
        IPC_INFO => {
            let Some(vtable) = shmem_vtable() else {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            };
            let shmmax = (vtable.max_len)();
            let max_index = {
                let segments = SHM_SEGMENTS.lock();
                segments
                    .as_ref()
                    .into_iter()
                    .flat_map(|map| map.iter())
                    .filter(|((namespace, _), seg)| *namespace == ipc_ns && !seg.removed)
                    .map(|((_, id), _)| *id)
                    .max()
                    .unwrap_or(0)
            };
            let mut out = [0u8; SHMINFO64_SIZE];
            shm_put_u64(&mut out, 0, shmmax);
            shm_put_u64(&mut out, 8, 1);
            shm_put_u64(&mut out, 16, SHMMNI);
            shm_put_u64(&mut out, 24, SHMMNI);
            shm_put_u64(&mut out, 32, SHMMNI.saturating_mul(shmmax / 4096));
            // SAFETY: Linux snapshots limits/index before validating copyout.
            if unsafe { copy_to_user(a.arg2, &out) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(max_index));
            }
        }
        SHM_INFO => {
            let (used_ids, total_pages, resident_pages, max_index) = {
                let segments = SHM_SEGMENTS.lock();
                segments
                    .as_ref()
                    .into_iter()
                    .flat_map(|map| map.iter())
                    .filter(|((namespace, _), _)| *namespace == ipc_ns)
                    .fold(
                        (0u32, 0u64, 0u64, 0u64),
                        |(ids, pages, rss, max_id), ((_, id), seg)| {
                        (
                            ids.saturating_add(u32::from(!seg.removed)),
                            pages.saturating_add(seg.len.div_ceil(4096)),
                            rss.saturating_add(if seg.removed {
                                0
                            } else {
                                seg.len.div_ceil(4096)
                            }),
                            if seg.removed {
                                max_id
                            } else {
                                core::cmp::max(max_id, *id)
                            },
                        )
                        },
                    )
            };
            let mut out = [0u8; SHM_INFO_SIZE];
            shm_put_u32(&mut out, 0, used_ids);
            shm_put_u64(&mut out, 8, total_pages);
            shm_put_u64(&mut out, 16, resident_pages); // live backing is resident
            // shm_swp, swap_attempts, and swap_successes remain zero.
            // SAFETY: Linux snapshots namespace usage before copyout.
            if unsafe { copy_to_user(a.arg2, &out) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(max_index));
            }
        }
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
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
                if cmd != SHM_STAT_ANY && !shm_ipc_allowed(seg, 0o4) {
                    ctx.set_return(SyscallReturn::ok((-13i64) as u64));
                    return;
                }
                (
                    seg.key,
                    seg.uid,
                    seg.gid,
                    seg.cuid,
                    seg.cgid,
                    (seg.mode & 0o777) | if seg.locked { SHM_LOCKED } else { 0 },
                    seg.len,
                    seg.atime,
                    seg.dtime,
                    seg.ctime,
                    seg.cpid,
                    seg.lpid,
                    seg.nattch,
                )
            };
            let out = encode_shm_stat(snapshot);
            // SAFETY: `buf` is the native shmid64_ds output pointer; the
            // guarded helper validates and copies the complete structure.
            if unsafe { copy_to_user(a.arg2, &out) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(if cmd == IPC_STAT { 0 } else { shmid }));
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
        SHM_LOCK | SHM_UNLOCK => {
            let authority = current_mlock_authority();
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
            let privileged = current_ucred().uid == 0;
            if cmd == SHM_LOCK && !privileged && !can_do_mlock(authority) {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                return;
            }
            let Some(vtable) = shmem_vtable() else {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                return;
            };
            let locked = cmd == SHM_LOCK;
            if seg.locked != locked {
                if locked {
                    match (vtable.lock)(
                        seg.handle,
                        {
                            #[cfg(feature = "container")]
                            {
                                crate::namespaces::current_user_ns(current_task_id()).id()
                            }
                            #[cfg(not(feature = "container"))]
                            {
                                0
                            }
                        },
                        current_ucred().uid,
                        authority.limit_bytes,
                        privileged || authority.bypass_limit,
                    ) {
                        Ok(()) => {}
                        Err(ShmemLockError::Limit) => {
                            ctx.set_return(SyscallReturn::ok((-12i64) as u64));
                            return;
                        }
                        Err(ShmemLockError::NotFound) => {
                            ctx.set_return(SyscallReturn::ok((-43i64) as u64));
                            return;
                        }
                    }
                } else if !(vtable.unlock)(seg.handle) {
                    ctx.set_return(SyscallReturn::ok((-43i64) as u64));
                    return;
                }
                seg.locked = locked;
            }
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
