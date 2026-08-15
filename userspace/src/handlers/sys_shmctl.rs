#[allow(unused_imports)]
use super::*;

/// `shmctl(shmid, cmd, buf)`. IPC_RMID destroys the segment; IPC_STAT
/// reports the segment size; others are accepted.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmctl(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let shmid = a.arg0;
    let cmd = a.arg1 & !IPC_64;
    match cmd {
        IPC_RMID => {
            let removed = {
                let mut g = SHM_SEGMENTS.lock();
                g.as_mut().and_then(|m| m.remove(&shmid))
            };
            match removed {
                Some(seg) => {
                    if let Some(v) = shmem_vtable() {
                        (v.destroy)(seg.handle);
                    }
                    ctx.set_return(SyscallReturn::ok(0));
                }
                None => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
            }
        }
        2 => {
            // IPC_STAT: fill the x86_64 shmid64_ds. shm_segsz sits right after
            // struct ipc64_perm (offset 48); shm_cpid/shm_lpid are 4-byte pids
            // at offsets 80/84 (after the three 8-byte time fields). The rest
            // stays caller-zeroed. cpid/lpid are OUTER ProcessIds — render them
            // in the READER's namespace (Linux pid_vnr), 0 = unset. (#33)
            let seg = {
                let g = SHM_SEGMENTS.lock();
                g.as_ref()
                    .and_then(|m| m.get(&shmid))
                    .map(|s| (s.len, s.cpid, s.lpid))
            };
            match seg {
                Some((len, cpid, lpid)) if a.arg2 != 0 => {
                    let reader = current_task_id();
                    let vis = |p: u64| -> u32 {
                        if p == 0 {
                            0
                        } else {
                            report_pid_to(reader, p) as u32
                        }
                    };
                    // SAFETY: a.arg2 is the user struct shmid_ds*; copy_to_user
                    // validates each write within the caller's 112-byte struct.
                    unsafe {
                        let _ = copy_to_user(a.arg2.wrapping_add(48), &len.to_le_bytes());
                        let _ = copy_to_user(a.arg2.wrapping_add(80), &vis(cpid).to_le_bytes());
                        let _ = copy_to_user(a.arg2.wrapping_add(84), &vis(lpid).to_le_bytes());
                    }
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Some(_) => ctx.set_return(SyscallReturn::ok(0)),
                None => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
            }
        }
        _ => ctx.set_return(SyscallReturn::ok(0)),
    }
}
