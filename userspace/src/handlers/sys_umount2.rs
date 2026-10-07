#[allow(unused_imports)]
use super::*;


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
    let target_raw = match copy_user_cstr_checked(args.arg0, 4096) {
            Ok(s) => s,
            Err(errno) => {
            // `user_path_at` on an unreadable name → -EFAULT.
            ctx.set_return(fail(errno));
            return;
            }
        };
    // `getname("")` without LOOKUP_EMPTY is -ENOENT; resolving the empty
    // string would name the cwd and unmount whatever covers it.
    if target_raw.is_empty() {
        ctx.set_return(fail(ENOENT));
        return;
    }
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
    //
    // `user_path_at(AT_FDCWD, name, lookup_flags, &path)` carries
    // LOOKUP_FOLLOW unless UMOUNT_NOFOLLOW, so `umount2("/link-to-mnt", 0)`
    // unmounts what the link POINTS AT, while UMOUNT_NOFOLLOW resolves the
    // link itself — which is never a mount point, so it falls into the
    // "not mounted" -EINVAL below. NARF matched the UN-followed string
    // against the mount list either way: the flag changed nothing, and
    // unmounting through a symlink (how /etc/mtab-era tooling and
    // `/dev/shm`-style aliases spell a mount) was -EINVAL.
    //
    // The hops run in the task's OWN view and are re-rooted once at the end,
    // because a symlink's stored target is a name in that view: following it
    // in host space would escape a chroot through its own links.
    let task = current_task_id();
    let mut visible = resolve_cwd_path_user(task, target_raw.as_str());
    if flags & UMOUNT_NOFOLLOW == 0 {
        for _ in 0..SYMLOOP_MAX {
            let probe = apply_chroot(visible.trim_end_matches('/'));
            let Some(link) = resolve_final_symlink_target(&probe) else {
                break;
            };
            visible = if link.starts_with('/') {
                resolve_cwd_path_user(task, &link)
            } else {
                // A relative target resolves against the link's directory.
                let dir = visible
                    .trim_end_matches('/')
                    .rsplit_once('/')
                    .map(|(dir, _)| dir)
                    .unwrap_or("");
                resolve_cwd_path_user(task, &alloc::format!("{}/{}", dir, link))
            };
        }
    }
    let target = {
        let t = apply_chroot(&visible);
        if t.len() > 1 {
            alloc::string::String::from(t.trim_end_matches('/'))
        } else {
            t
        }
    };

    // `user_path_at` runs first (-ENOENT), then `can_umount`'s `may_mount()`
    // (-EPERM), then its `path_mounted()` (-EINVAL, below). Probed on Linux
    // 6.18: an unprivileged umount2 of a missing path is ENOENT, of an
    // existing non-mountpoint EPERM. This handler had no privilege check at
    // all, so any task could unmount anything.
    let mount_list = current_mount_list();
    let mounted = mount_list.iter().any(|m| m == &target);
    if !mounted && stat_path_dir_aware(target.as_str()).is_none() {
        ctx.set_return(fail(ENOENT));
        return;
    }
    if !mount_admin(current_task_id()) {
        ctx.set_return(fail(EPERM));
        return;
    }

    // Protect the core API pseudo-filesystems from destructive unmount ONLY in
    // the GLOBAL registry: the global /proc, /sys, /dev (and cgroup2) are single
    // shared instances the chroot's Stage::Late `mnt-dev-bind` provides and
    // everything depends on, so a global umount of one is a keep-mounted no-op.
    // That covers the singleton alone — the sole mount at its path. Anything
    // stacked on top of it is an ordinary mount and umount pops it, as Linux's
    // do_umount pops the top mount of the path. The match is on the fstype each
    // filesystem reports (`FsInstance::name`, what /proc/mounts shows).
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
    let at_target: alloc::vec::Vec<_> = current_mount_list_with_names()
        .into_iter()
        .filter(|(path, _)| path == &target)
        .collect();
    let protected = private_ns.is_none()
        && at_target.len() == 1
        && matches!(
            at_target[0].1.as_str(),
            "proc" | "sysfs" | "devtmpfs" | "cgroup2"
        );
    if protected {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // `can_umount`'s `path_mounted()` test, split out ahead of the pop so the
    // two halves of the registry's single `NotFound` can be told apart the way
    // Linux tells them apart: the path lookup failed first (-ENOENT, above),
    // and only a path that DOES resolve reaches the "not a mount point"
    // -EINVAL.
    if !mounted {
        ctx.set_return(fail(EINVAL));
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

    // `do_umount`'s `retval = -EBUSY`. Linux decides it from
    // `mnt_get_count(mnt)` against the references it expects, and the
    // references that count are exactly three things NARF records:
    //
    //   * a mount BENEATH the target pins its mountpoint
    //     (`propagate_mount_busy`'s walk over `mnt_mounts`),
    //   * a task's cwd or root on it pins it (`fs_struct`'s `pwd` / `root`,
    //     each holding a `struct path`), and
    //   * an open file on it pins it (`file->f_path.mnt`).
    //
    // The registry has no refcount of its own, so the three tables stand in
    // for it. The answer matters: an unconditional pop tore a mount out from
    // under a process still reading it, and reported success — so a teardown
    // loop had no "come back later" state and a caller that depends on EBUSY
    // to detect "someone is still in there" (systemd's `umount_recursive`,
    // udisks, every container runtime's cleanup) never saw it.
    // The table is in attachment order. Only mounts attached AFTER the
    // topmost target mount can be its children. This distinction matters for
    // `pivot_root(".", ".")`: it stacks the old root over the already
    // recursively-bound new root, then lazily detaches the top mount. Entries
    // that predate that stack operation belong to the new root and must
    // survive, including its recursively cloned `/run` mount.
    let topmost = mount_list
        .iter()
        .rposition(|mount| mount == &target)
        .expect("mounted target must have a topmost attachment");
    let submounts: alloc::vec::Vec<alloc::string::String> = mount_list
        .into_iter()
        .skip(topmost + 1)
        .filter(|mount| path_at_or_under(mount, target.as_str()))
        .collect();
    // MNT_DETACH is Linux's lazy unmount: detach the subtree now and let the
    // last reference free it. NARF's mounts are Arc'd, so a task holding a
    // file under a detached mount keeps the FsInstance alive by itself — the
    // detach IS the pop, and the submounts go with it (deepest first, as
    // `umount_tree` collects them).
    //
    // LINUX-GAP: MNT_FORCE additionally asks the filesystem to abort its
    // in-flight requests (`sb->s_op->umount_begin`, which only the network
    // filesystems implement). NARF has no such hook, so MNT_FORCE only
    // bypasses the busy test, exactly like MNT_DETACH, and aborts nothing.
    let lazy = flags & (MNT_DETACH | MNT_FORCE) != 0;
    if !lazy
        && (!submounts.is_empty()
            || any_task_cwd_under(target.as_str())
            || any_task_root_under(target.as_str())
            || crate::mqueue::any_fd_path_under(target.as_str()))
    {
        ctx.set_return(fail(EBUSY));
        return;
    }

    let auth = narf_filesystem::bootstrap_mount_authority();
    // SAFETY: bootstrapping a Write cap is the same TCB-trusted op
    // the registry uses internally to mint the per-mount handle.
    let handle: narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Write> =
        narf_capabilities::Cap::<narf_filesystem::MountPoint, narf_capabilities::Write>::bootstrap(
        );
    let _ = auth;
    let unmount_one = |path: &str| {
        if let Some(ns) = private_ns.as_ref() {
            ns.unmount(path)
        } else {
            narf_filesystem::registry().unmount(&handle, path)
        }
    };
    if lazy {
        // Deepest first, so no entry is left parented on a popped mount.
        let mut nested = submounts;
        nested.sort_by_key(|path| core::cmp::Reverse(path.len()));
        for path in &nested {
            let _ = unmount_one(path.as_str());
        }
    }
    let result = unmount_one(target.as_str());
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
