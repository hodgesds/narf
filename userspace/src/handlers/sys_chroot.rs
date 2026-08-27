#[allow(unused_imports)]
use super::*;

/// `fs/open.c::SYSCALL_DEFINE1(chroot)`:
///
/// ```text
///     unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
///     error = filename_lookup(AT_FDCWD, name, lookup_flags, &path, NULL);
///     if (error) return error;
///     error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
///     if (error) goto dput_and_out;
///     error = -EPERM;
///     if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT)) goto dput_and_out;
/// ```
///
/// The lookup runs FIRST, so a bad path outranks the capability check: a
/// missing target is -ENOENT and a target that is a plain file is -ENOTDIR
/// even for an unprivileged caller. Returning the bare -1 for all of these
/// meant every failure read back as EPERM, which is precisely the one errno
/// a container runtime must not confuse — `chroot` failing with EPERM says
/// "you are not root, give up", while ENOENT says "the rootfs you were told
/// to enter has not been staged yet".
///
/// Note the lookup uses AT_FDCWD, so a RELATIVE target is legal and joins
/// the caller's cwd (`chroot("rootfs")` is a normal thing to write). This
/// handler used to reject any path not starting with '/' outright.
pub(crate) fn sys_chroot(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux `chroot(const char *path)` passes a single NUL-terminated
    // path in arg0 — there is no length argument. (The earlier
    // `copy_user_path_raw(arg0, arg1)` form misread arg1 as a length,
    // which is garbage for a real Linux binary, so every chroot from
    // unmodified userspace failed with -1.)
    let raw = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            // LINUX-GAP: as in sys_chdir, `getname()`'s -ENAMETOOLONG is
            // folded into -EFAULT because copy_user_cstr cannot tell the
            // two apart.
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    };
    // No LOOKUP_EMPTY here either — `getname()` rejects "" with -ENOENT.
    if raw.is_empty() {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }
    let task = current_task_id();
    // AT_FDCWD anchoring: join a relative target to the cwd. resolve_cwd_path
    // ALSO composes any existing chroot (a nested chroot resolves under the
    // current root before installation), so apply_chroot must not run again
    // on top of the result or the prefix is doubled.
    let resolved = resolve_cwd_path(task, &raw);
    // Verify resolved exists as a directory under the global
    // registry — match Linux semantics: chroot fails if target
    // doesn't exist. We treat a covering mount as sufficient.
    let covered = narf_filesystem::registry()
        .resolve_absolute(&resolved, |_fs, _rel| true)
        .unwrap_or(false);
    if !covered {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }
    // LOOKUP_DIRECTORY: a target that resolves to a file, device or fifo is
    // -ENOTDIR, not a successful root change. (A path that resolves to
    // nothing inside a covering mount stays -ENOENT — see the LINUX-GAP
    // below.)
    if let Some((s, ..)) = stat_ino_path_dir_aware_ext(&resolved, true) {
        if s.mode.file_type != narf_filesystem::FileType::Dir {
            ctx.set_return(SyscallReturn::ok((-20i64) as u64)); // -ENOTDIR
            return;
        }
    }
    // LINUX-GAP: the "covering mount" test above is weaker than
    // filename_lookup — a path under an existing mount that names no entry
    // still installs as a root instead of reporting -ENOENT. Tightening it
    // would change which chroots succeed, not just their errno.
    // `error = -EPERM; if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT))
    // goto dput_and_out;` — note the position: Linux runs the lookup and
    // `path_permission` FIRST, so an unprivileged caller naming a path that
    // does not exist still gets -ENOENT, not -EPERM. Hoisting this check to
    // the top of the handler would leak less information than Linux does,
    // but it would also diverge from it, and a program that distinguishes
    // "no such directory" from "not allowed" would misreport.
    //
    // LINUX-GAP: -EACCES from `path_permission(MAY_EXEC | MAY_CHDIR)` is
    // still not modelled — NARF enforces no directory execute bits.
    if !capable(CAP_SYS_CHROOT) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    task_map_set(&ROOT_DIR_TABLE, task, resolved);
    ctx.set_return(SyscallReturn::ok(0));
}
