#[allow(unused_imports)]
use super::*;

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EBUSY: i64 = 16;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

/// Map an `FsError` out of the mount registry's `unmount` onto the errno
/// `fs/namespace.c::do_umount` would report. `NotFound` is handled by the
/// caller, which has the path in hand and can tell "no such file" (-ENOENT)
/// from "not a mount point" (-EINVAL) apart.
fn umount_errno(e: narf_filesystem::FsError) -> i64 {
    use narf_filesystem::FsError;
    match e {
        FsError::Busy => EBUSY,             // propagate_mount_busy() → -EBUSY
        FsError::PermissionDenied => EPERM, // a revoked mount handle
        FsError::OperationNotPermitted => EPERM,
        _ => EINVAL,
    }
}

/// `fs/namespace.c::ksys_umount` / `can_umount` / `do_umount`, in the order
/// the kernel applies them:
///
/// ```text
///   // basic validity checks done first
///   if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))
///           return -EINVAL;
///   ret = user_path_at(AT_FDCWD, name, lookup_flags, &path);   /* -EFAULT/-ENOENT */
///   ...
///   can_umount():  if (!may_mount())      return -EPERM;
///                  if (!path_mounted(path)) return -EINVAL;
///   do_umount():   if (flags & MNT_EXPIRE) {
///                          if (... || flags & (MNT_FORCE | MNT_DETACH))
///                                  return -EINVAL;
///                  ...
///                  retval = -EBUSY;
/// ```
///
/// The order is load-bearing, not decoration: the flag word is validated
/// BEFORE the path is even looked at, so `umount2("/gone", 0xdead)` is
/// EINVAL and not ENOENT; and the path lookup runs BEFORE the mount checks,
/// so a path that names nothing is ENOENT while a path that exists but
/// carries no mount is EINVAL.
///
/// Every one of these was the bare `-1` sentinel = EPERM, which is the worst
/// possible answer here because EPERM is *also* what an unprivileged umount
/// legitimately returns. A teardown loop (systemd's `umount_recursive`, which
/// walks /proc/self/mountinfo and retries) cannot distinguish "not mine to
/// unmount, skip it" from "already gone, drop it from the list" from "still
/// busy, come back later", so it either spins or aborts the unit.
pub(crate) fn sys_umount2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `int flags` — the upper 32 bits of the register are not part of the
    // argument, so they must not be mistaken for unknown flag bits.
    let flags = args.arg1 as u32 as u64;

    // "basic validity checks done first": an unknown flag bit is -EINVAL
    // before the target string is read, let alone resolved.
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        ctx.set_return(fail(EINVAL));
        return;
    }

    // Linux `umount2(2)`: (const char *target, int flags). `target` is a
    // NUL-terminated path; there is no length arg. (Was NARF-native
    // (ptr, len, flags), which mis-read a musl caller's flags as the length.)
    let target_raw = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            // `user_path_at` on an unreadable name → -EFAULT.
            ctx.set_return(fail(EFAULT));
            return;
        }
    };
    // Resolve against the caller's cwd (and re-root under any chroot), like
    // sys_pivot_root / sys_mount. systemd's switch-root does
    // `fchdir(new_root_fd); pivot_root(".", "."); umount2(".", MNT_DETACH)` —
    // the RELATIVE "." must resolve to the cwd (the new root), not a literal
    // "." that matches no mount. When umount2(".") failed here, systemd fell
    // back to `mount(".", "/", MS_MOVE)`, which also mis-resolved "." and
    // returned ENOENT → 226/EXIT_NAMESPACE (udevd et al.).
    // Trim any trailing slash so the exact-match against registry mount paths
    // (which have none, except root) succeeds: `apply_chroot("/")` yields
    // "<root>/" (intentional, see apply_chroot), so umount2(".") right after
    // pivot_root(".",".") — cwd "/" in the new root — resolves to "<newroot>/".
    let target = {
        let t = resolve_cwd_path(current_task_id(), target_raw.as_str());
        if t.len() > 1 {
            alloc::string::String::from(t.trim_end_matches('/'))
        } else {
            t
        }
    };
    // We accept MNT_FORCE / MNT_DETACH / UMOUNT_NOFOLLOW but the registry
    // doesn't yet track in-flight refs against a mount, so the pop-by-path
    // is unconditional. The flag word is recorded for diagnostic symmetry
    // only. (MNT_EXPIRE's conflict check is enforced below.)
    let _ = flags & (MNT_FORCE | MNT_DETACH | UMOUNT_NOFOLLOW);

    // Protect the core API pseudo-filesystems from destructive unmount ONLY in
    // the GLOBAL registry. NARF has no mount stacking: the global /proc, /sys,
    // /dev (and cgroup2) are single shared instances the chroot's Stage::Late
    // `mnt-dev-bind` provides and everything depends on, so a global umount is a
    // keep-mounted no-op.
    //
    // A task with a PRIVATE mount namespace (every systemd service sandbox, after
    // unshare(CLONE_NEWNS)) must NOT get that no-op: `ns.unmount` only pops that
    // namespace's OWN mount entry — the shared singleton's `FsInstance` Arc, still
    // held by the global registry, is untouched. Applying the no-op there made
    // umount2 of a service's PRIVATE /dev (systemd's mount_private_dev →
    // umount_recursive before the MS_MOVE) a silent success while the mount stayed
    // in /proc/self/mountinfo, so umount_recursive looped FOREVER — the service's
    // sd-executor hung before execve and the Type=notify unit timed out (userdbd,
    // and every service with PrivateDevices=/ProtectProc=/etc.).
    let private_ns = current_mount_namespace();
    let protected = private_ns.is_none()
        && current_mount_list_with_names()
            .into_iter()
            .any(|(path, name)| {
                path == target
                    && matches!(
                        name.as_str(),
                        "procfs" | "sysfs" | "devfs" | "devtmpfs" | "cgroup2" | "cgroupfs"
                    )
            });
    if protected {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // `can_umount`'s `path_mounted()` test, split out ahead of the pop so the
    // two halves of the registry's single `NotFound` can be told apart the way
    // Linux tells them apart: the path lookup fails first (-ENOENT), and only
    // a path that DOES resolve reaches the "not a mount point" -EINVAL.
    if !current_mount_list().iter().any(|m| m == &target) {
        let errno = if stat_path_dir_aware(target.as_str()).is_some() {
            EINVAL
        } else {
            ENOENT
        };
        ctx.set_return(fail(errno));
        return;
    }

    // `do_umount`: MNT_EXPIRE is mutually exclusive with MNT_FORCE and
    // MNT_DETACH. Checked here, after the mount is resolved, because Linux
    // checks it there — a nonexistent path with this flag pair is still
    // -ENOENT.
    if flags & MNT_EXPIRE != 0 && flags & (MNT_FORCE | MNT_DETACH) != 0 {
        ctx.set_return(fail(EINVAL));
        return;
    }

    let auth = narf_filesystem::bootstrap_mount_authority();
    // SAFETY: bootstrapping a Write cap is the same TCB-trusted op
    // the registry uses internally to mint the per-mount handle.
    let handle: narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write> =
        narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap(
        );
    let _ = auth;
    let result = if let Some(ns) = private_ns {
        ns.unmount(target.as_str())
    } else {
        narf_filesystem::registry().unmount(&handle, target.as_str())
    };
    // A real mount (including the old root systemd detaches after pivot_root)
    // unmounts and returns 0. A racing unmount that emptied the slot between
    // the check above and here lands on `NotFound` → -EINVAL, Linux's answer
    // for "the path is no longer a mount point".
    match result {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(narf_filesystem::FsError::NotFound) => ctx.set_return(fail(EINVAL)),
        Err(e) => ctx.set_return(fail(umount_errno(e))),
    }
}
