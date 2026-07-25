#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fchmodat_or_fchownat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    // access(2) semantics: a missing path is ENOENT, not the -1 sentinel
    // (which musl maps to EPERM). sd-device (libudev/elogind) keys
    // `errno == ENOENT` when validating a /sys/devices/<...> node's
    // `uevent`, so the wrong errno makes it reject the whole device.
    let missing = SyscallReturn::ok((-2i64) as u64); // -ENOENT
                                                     // Linux ABI: faccessat/fchmodat/fchownat take a NUL-terminated path
                                                     // in arg1 — arg2 is mode/owner, NOT a length. (Reading arg2 as a
                                                     // length truncated the path to mode-many bytes: `access("/dev/shm/
                                                     // nums", R_OK)` opened "/dev/s" and failed, breaking busybox grep.)
    let raw = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    // Honour a real directory fd for relative paths (mirrors `sys_openat`).
    // `faccessat(dirfd, "uevent", F_OK)` is how sd-device probes whether a
    // `/sys/devices/<...>` node is a real device; ignoring `dirfd` resolved
    // "uevent" against the CWD (always missing) → EPERM → every input/evdev
    // `TakeDevice` failed even though the node exists. `fd_path_of` returns
    // the dir's chroot-relative path; `stat_path_dir_aware` re-applies the
    // chroot, so a chrooted process (elogind under /mnt) resolves in its
    // own namespace. See the twin fix in `sys_openat`.
    const AT_FDCWD: i64 = -100;
    let effective = if raw.starts_with('/') || dirfd == AT_FDCWD || dirfd < 0 {
        raw
    } else {
        match fd_path_of(current_task_id(), dirfd as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), raw)
            }
            // Unknown / non-directory fd → best-effort cwd-relative resolve.
            _ => raw,
        }
    };
    let path = resolve_cwd_path(current_task_id(), &effective);
    // Existence check over files AND directories. mode/uid/gid are
    // structural-only state NARF doesn't enforce, so report success iff
    // the path exists (covers access(2) F_OK and grants R/W/X).
    if stat_path_dir_aware(&path).is_some() {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(missing);
    }
}
