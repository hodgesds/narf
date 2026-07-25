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
            // IPC_STAT: report shm_segsz. On x86_64 the kernel's
            // shmid64_ds places shm_segsz right after struct ipc64_perm
            // (48 bytes). We fill just the size; the rest stays
            // caller-zeroed.
            let len = {
                let g = SHM_SEGMENTS.lock();
                g.as_ref().and_then(|m| m.get(&shmid)).map(|s| s.len)
            };
            match len {
                Some(len) if a.arg2 != 0 => {
                    // SAFETY: a.arg2 is the user struct shmid_ds*; copy_to_user
                    // validates the 8-byte shm_segsz write at offset 48.
                    let _ = unsafe { copy_to_user(a.arg2.wrapping_add(48), &len.to_le_bytes()) };
                    ctx.set_return(SyscallReturn::ok(0));
                }
                Some(_) => ctx.set_return(SyscallReturn::ok(0)),
                None => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
            }
        }
        _ => ctx.set_return(SyscallReturn::ok(0)),
    }
}
