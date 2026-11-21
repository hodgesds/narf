#[allow(unused_imports)]
use super::*;


/// `fs/namespace.c::SYSCALL_DEFINE2(pivot_root)` → `path_pivot_root`:
///
/// ```text
///   if (!may_mount())              return -EPERM;
///   error = user_path_at(AT_FDCWD, new_root,
///                        LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &new);
///   if (error) return error;                    /* -EFAULT/-ENOENT/-ENOTDIR */
///   error = user_path_at(AT_FDCWD, put_old, ..., &old);
///   if (error) return error;
///   ...
///   if (d_unlinked(new->dentry))   return -ENOENT;
///   if (new_mnt == root_mnt || old_mnt == root_mnt)
///           return -EBUSY;  /* loop, on the same file system  */
///   if (!path_mounted(&root))      return -EINVAL; /* not a mountpoint */
/// ```
///
/// Both path arguments are resolved before any of the mount-topology checks,
/// so a bad pointer or a missing directory beats every later error — but
/// the privilege check comes first of all.
///
/// These were all the bare `-1` sentinel = EPERM. For pivot_root that is
/// specifically destructive: EPERM is the answer a container runtime expects
/// when it is not running as a privileged user, so it treats it as "this
/// kernel/user cannot pivot" and falls back to `chroot()` — silently giving
/// up the mount isolation it asked for — when the actual fault was a typo in
/// the new root path (ENOENT) or a bind that had not landed yet.
/// `user_path_at(..., LOOKUP_FOLLOW | LOOKUP_DIRECTORY)` for one pivot_root
/// argument. `LOOKUP_DIRECTORY` splits a failure two ways: a name that
/// resolves to a non-directory is -ENOTDIR, a name that resolves to nothing
/// at all (including the empty string, which `getname` refuses) is -ENOENT.
/// A runtime that assembled its root under a staging path needs the
/// difference — ENOTDIR means "you bound a file here", ENOENT means "the
/// bind has not happened yet". Errors are positive errno values.
fn pivot_lookup_dir(raw: &str, resolved: &str) -> Result<(), i64> {
    if raw.is_empty() {
        return Err(ENOENT);
    }
    // `resolve_dir_absolute`, not `resolve_absolute(|_,_| true)`: the latter
    // matches the root `/` mount as a fallback for ANY absolute path, so a
    // non-existent new_root (e.g. `pivot_root("/nonexistent", ...)`) would
    // bogusly pass, succeed, and install a garbage task root — corrupting
    // every later path lookup for the task.
    if resolve_dir_absolute(resolved).is_some() {
        return Ok(());
    }
    Err(if stat_path_dir_aware(resolved).is_some() {
        ENOTDIR
    } else {
        ENOENT
    })
}

pub(crate) fn sys_pivot_root(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let task = current_task_id();
    // `SYSCALL_DEFINE2(pivot_root)` opens with `if (!may_mount()) return
    // -EPERM;` — BEFORE either path is looked at, so an unprivileged caller
    // gets EPERM even for a faulting pointer or a missing directory (probed
    // on Linux 6.18). There was no privilege check here at all.
    if !mount_admin(task) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // Linux ABI: pivot_root(const char *new_root, const char *put_old).
    // Both arguments are NUL-terminated strings; there are no explicit
    // lengths. The old NARF-native four-argument decoder retained the
    // terminator in the stored root and consumed the put_old pointer as a
    // length, so successful calls installed a path such as "/new_root\0".
    //
    // The two lookups run in order, each to completion: new_root's
    // -EFAULT/-ENOENT/-ENOTDIR outranks anything wrong with put_old.
    let new_root = match copy_user_cstr_checked(args.arg0, 4096) {
        Ok(s) => s,
        Err(errno) => {
            // `user_path_at` on an unreadable name → -EFAULT.
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // new_root / put_old are resolved against the caller's cwd like any path
    // argument. The canonical container idiom is
    // `fchdir(new_root_fd); pivot_root(".", ".")` — systemd's
    // mount_switch_root_pivot (and runc, etc.) do exactly this — so RELATIVE
    // paths, notably ".", must resolve against the cwd rather than be rejected.
    // Rejecting non-absolute paths made systemd-udevd's PrivateMounts=yes
    // sandbox fail with 226/EXIT_NAMESPACE and restart-loop, wedging boot.
    // resolve_cwd_path resolves against the cwd and re-roots under any active
    // chroot, so absolute paths keep their prior meaning.
    let new_root_resolved = resolve_cwd_path(task, &new_root);
    // new_root must resolve to an EXISTING DIRECTORY (see `pivot_lookup_dir`).
    if let Err(errno) = pivot_lookup_dir(&new_root, &new_root_resolved) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    // `put_old` gets the same `LOOKUP_FOLLOW | LOOKUP_DIRECTORY` lookup.
    // It was never resolved at all, so a missing or non-directory put_old
    // "succeeded" and the old root was bound at a path with nothing there.
    let put_old = match copy_user_cstr_checked(args.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let put_old_resolved = resolve_cwd_path(task, &put_old);
    if let Err(errno) = pivot_lookup_dir(&put_old, &put_old_resolved) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    // The caller's cwd as a host path, resolved in the CURRENT (pre-swap) root
    // frame. systemd does `fchdir(new_root_fd); pivot_root(".", ".")`, so this
    // equals new_root_resolved for that idiom. Captured before ROOT_DIR_TABLE is
    // updated so it uses the old chroot prefix.
    let cwd_host = resolve_cwd_path(task, ".");
    let prior_root = root_dir_of(task).unwrap_or_else(|| alloc::string::String::from("/"));
    // `new_mnt == root_mnt` → -EBUSY ("loop, on the same file system"): the
    // new root may not be the root the caller is already standing on, or the
    // swap would have nothing to move the old root onto. NARF compares the
    // task root path, which is the whole of its root identity.
    if new_root_resolved.trim_end_matches('/') == prior_root.trim_end_matches('/') {
        ctx.set_return(errno_ret(EBUSY));
        return;
    }
    // `path_pivot_root` attaches the old root mount at put_old with its
    // whole tree — `attach_mnt(root_mnt, old_mnt, old_mp)` moves root_mnt,
    // and every mount below it moves with it — after `umount_mnt(new_mnt)`
    // took the new root's subtree out of that tree. bubblewrap reads
    // `/oldroot/proc/self/fd/N` and binds `/oldroot/proc` right after its
    // first pivot; attaching the root filesystem alone left `/oldroot/proc`
    // an empty directory, so both failed ENOENT ("Can't bind mount /oldroot/
    // on /newroot/").
    //
    // Route through the namespace-aware helper: when the caller unshared
    // CLONE_NEWNS (every systemd service sandbox does, before pivot_root),
    // the attachment must land in that task's PRIVATE mount table, not the
    // global registry. Attaching into the global registry leaked each
    // executor's put_old into every other task's view, so the per-service
    // root assembly became order-dependent — a fresh executor's
    // find_executable() intermittently hit ENOENT (203/EXIT_EXEC) while a
    // later one, snapshotting the polluted global table, happened to succeed.
    let trim = |path: &str| -> alloc::string::String {
        if path.len() > 1 {
            alloc::string::String::from(path.trim_end_matches('/'))
        } else {
            alloc::string::String::from(path)
        }
    };
    let _ = current_attach_old_root(
        &trim(&prior_root),
        &trim(&new_root_resolved),
        &trim(&put_old_resolved),
    );
    // Install the new root.
    set_root_dir(task, new_root_resolved.clone());
    // The cwd directory is physically unchanged, but the root moved — recompute
    // the cwd in the NEW root's frame. Without this, a following relative
    // resolution (systemd's `umount2(".", MNT_DETACH)` / `mount(".", "/",
    // MS_MOVE)` right after `pivot_root(".", ".")`) re-applies the new chroot
    // prefix on top of the still-old cwd, yielding a doubly-prefixed path that
    // matches no mount → ENOENT → 226/EXIT_NAMESPACE. A cwd at or above the new
    // root clamps to "/".
    let new_cwd = if cwd_host == new_root_resolved {
        alloc::string::String::from("/")
    } else if let Some(rest) = cwd_host
        .strip_prefix(new_root_resolved.as_str())
        .filter(|r| r.starts_with('/'))
    {
        alloc::string::String::from(rest)
    } else {
        alloc::string::String::from("/")
    };
    set_cwd(task, &new_cwd);
    ctx.set_return(SyscallReturn::ok(0));
}
