#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_umount2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    // Linux `umount2(2)`: (const char *target, int flags). `target` is a
    // NUL-terminated path; there is no length arg. (Was NARF-native
    // (ptr, len, flags), which mis-read a musl caller's flags as the length.)
    let target_raw = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
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
    let flags = args.arg1;
    // We accept MNT_FORCE / MNT_DETACH / MNT_EXPIRE / UMOUNT_NOFOLLOW
    // but the registry doesn't yet track in-flight refs against a
    // mount, so the pop-by-path is unconditional. The flag word is
    // recorded for diagnostic symmetry only.
    let _ = flags & (MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW);

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
    // Linux `umount2(2)` reports failure (EINVAL for "not a mount point",
    // ENOENT for a missing path) rather than silently succeeding — swallowing
    // the error hid real unmount failures and broke conformance. A real mount
    // (including the old root systemd detaches after pivot_root) unmounts and
    // returns 0; a non-mount path returns the -1 sentinel.
    match result {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(fail),
    }
}
