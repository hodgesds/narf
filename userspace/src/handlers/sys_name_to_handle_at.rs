#[allow(unused_imports)]
use super::*;

/// `name_to_handle_at(dirfd, pathname, handle, mount_id, flags)`.
pub(crate) fn sys_name_to_handle_at(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    const ENOENT: i64 = 2;
    const EFAULT: i64 = 14;
    const EOVERFLOW: i64 = 75;
    const AT_EMPTY_PATH: u64 = 0x1000;
    let a = *ctx.args();
    let raw = copy_user_cstr(a.arg1, 4096).unwrap_or_default();
    // AT_EMPTY_PATH form: name_to_handle_at(fd, "", &handle, &mnt_id,
    // AT_EMPTY_PATH) requests a handle for the fd itself. Callers such as
    // systemd's cg_fd_get_cgroupid read this to obtain a cgroup's id — an
    // 8-byte f_handle whose value is a stable per-object identifier. Return
    // an exactly-8-byte handle: the fd's inode if the backing FS exposes one,
    // else a stable hash of the fd's path.
    if raw.is_empty() {
        if a.arg4 & AT_EMPTY_PATH == 0 {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
        let task = current_task_id();
        let dirfd = a.arg0 as u32;
        let id: Option<u64> = fd::with_table(task, |t| t.get(dirfd).map(|e| e.ops.ino()))
            .flatten()
            .filter(|&i| i != 0)
            .or_else(|| {
                fd_path_for_task(task, dirfd).map(|p| {
                    // FNV-1a over the fd's backing path — stable per object.
                    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
                    for b in p.as_bytes() {
                        h ^= *b as u64;
                        h = h.wrapping_mul(0x0000_0100_0000_01b3);
                    }
                    h
                })
            });
        let id = match id {
            Some(i) => i,
            None => {
                ctx.set_return(SyscallReturn::ok((-ENOENT) as u64));
                return;
            }
        };
        // handle->handle_bytes capacity check (first u32 of the caller's buf).
        let mut cap = [0u8; 4];
        // SAFETY: copy_from_user validates the 4-byte read.
        if unsafe { copy_from_user(&mut cap, a.arg2) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
        if (u32::from_ne_bytes(cap) as usize) < 8 {
            // SAFETY: copy_to_user validates the 4-byte destination.
            let _ = unsafe { copy_to_user(a.arg2, &8u32.to_ne_bytes()) };
            ctx.set_return(SyscallReturn::ok((-EOVERFLOW) as u64));
            return;
        }
        let mut hdr = [0u8; 8];
        hdr[0..4].copy_from_slice(&8u32.to_ne_bytes());
        hdr[4..8].copy_from_slice(&NARF_HANDLE_TYPE.to_ne_bytes());
        // SAFETY: copy_to_user validates the 8-byte header destination.
        let h1 = unsafe { copy_to_user(a.arg2, &hdr) };
        // SAFETY: copy_to_user validates the 8-byte id destination.
        let h2 = unsafe { copy_to_user(a.arg2 + 8, &id.to_ne_bytes()) };
        if h1.is_err() || h2.is_err() {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
        if a.arg3 != 0 {
            let mount_id = crate::mqueue::fd_mount_id(task, dirfd).unwrap_or(0) as i32;
            // SAFETY: copy_to_user validates the 4-byte destination.
            let _ = unsafe { copy_to_user(a.arg3, &mount_id.to_ne_bytes()) };
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Honour a real directory fd (same shape as sys_readlinkat/sys_statx):
    // resolve a relative path against the directory backing `dirfd`.
    // systemd's chase() calls name_to_handle_at(parent_dir_fd, name, ...)
    // per component to compute mount ids; resolving against the cwd
    // instead ENOENT'd exec_setup_credentials' mount-ns child (journald
    // 243/EXIT_CREDENTIALS).
    let dirfd_i = a.arg0 as i32;
    const AT_FDCWD_I32: i32 = -100;
    let raw = if raw.starts_with('/') || dirfd_i == AT_FDCWD_I32 || dirfd_i < 0 {
        raw
    } else {
        match fd_path_for_task(current_task_id(), dirfd_i as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), raw)
            }
            _ => raw,
        }
    };
    let path = apply_chroot(&raw);
    let mount_id = current_mount_id_at(&path).unwrap_or(0) as i32;
    // Dir-aware resolution (files, directories, mount roots and mount
    // ancestors alike), carrying the object's stable inode. A dir-only
    // node — e.g. a cgroup directory, whose children exist purely as
    // `lookup_dir` targets — has no FileOps shape, so a file-shape
    // resolve alone reports ENOENT for exactly the paths systemd's
    // cg_path_get_cgroupid asks about (/sys/fs/cgroup/.../<svc>.service).
    let path_ino = match stat_ino_path_dir_aware(&path) {
        Some((_, ino, _, _, _)) => ino,
        None => {
            ctx.set_return(SyscallReturn::ok((-ENOENT) as u64));
            return;
        }
    };
    // handle->handle_bytes (the caller's f_handle capacity) is the first u32.
    let mut cap = [0u8; 4];
    // SAFETY: copy_from_user validates the 4-byte read.
    if unsafe { copy_from_user(&mut cap, a.arg2) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let cap = u32::from_ne_bytes(cap) as usize;
    // Inode-form handle: a caller advertising an exactly-8-byte f_handle
    // (e.g. systemd's cg_path_get_cgroupid, which reads a cgroup's id from a
    // single u64) expects the object's id, as Linux returns. Resolve the
    // path's inode and emit an 8-byte handle. Larger capacities keep the
    // path-carrying handle form that open_by_handle_at round-trips.
    if cap == 8 {
        let mut hdr = [0u8; 8];
        hdr[0..4].copy_from_slice(&8u32.to_ne_bytes());
        hdr[4..8].copy_from_slice(&NARF_HANDLE_TYPE.to_ne_bytes());
        // SAFETY: copy_to_user validates the 8-byte header destination.
        let h1 = unsafe { copy_to_user(a.arg2, &hdr) };
        // SAFETY: copy_to_user validates the 8-byte id destination.
        let h2 = unsafe { copy_to_user(a.arg2 + 8, &path_ino.to_ne_bytes()) };
        if h1.is_err() || h2.is_err() {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
        if a.arg3 != 0 {
            // SAFETY: copy_to_user validates the 4-byte destination.
            let _ = unsafe { copy_to_user(a.arg3, &mount_id.to_ne_bytes()) };
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let needed = path.len();
    if cap < needed {
        // Report the required size and fail — the caller retries bigger.
        // SAFETY: copy_to_user validates the 4-byte destination.
        let _ = unsafe { copy_to_user(a.arg2, &(needed as u32).to_ne_bytes()) };
        ctx.set_return(SyscallReturn::ok((-EOVERFLOW) as u64));
        return;
    }
    // Write the 8-byte header { handle_bytes, handle_type } then the path.
    let mut hdr = [0u8; 8];
    hdr[0..4].copy_from_slice(&(needed as u32).to_ne_bytes());
    hdr[4..8].copy_from_slice(&NARF_HANDLE_TYPE.to_ne_bytes());
    // SAFETY: copy_to_user validates the 8-byte header destination.
    let h1 = unsafe { copy_to_user(a.arg2, &hdr) };
    // SAFETY: copy_to_user validates the path destination range.
    let h2 = unsafe { copy_to_user(a.arg2 + 8, path.as_bytes()) };
    if h1.is_err() || h2.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    // Linux exposes the visible mount's ID here. systemd compares it with
    // the parent mount ID to verify that a bind target became a mount point.
    if a.arg3 != 0 {
        // SAFETY: copy_to_user validates the 4-byte destination.
        let _ = unsafe { copy_to_user(a.arg3, &mount_id.to_ne_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}
