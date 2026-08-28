#[allow(unused_imports)]
use super::*;

/// `fs/open.c::SYSCALL_DEFINE1(chdir)`:
///
/// ```text
///     unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
///     error = filename_lookup(AT_FDCWD, name, lookup_flags, &path, NULL);
///     if (!error) {
///             error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
///             if (!error) set_fs_pwd(current->fs, &path);
///     }
/// ```
///
/// Every errno comes out of the lookup, so a missing directory is -ENOENT
/// and a path whose final component is a regular file is -ENOTDIR. This used
/// to answer the bare -1 sentinel for all of them, which libc reads as errno
/// 1 = EPERM: `cd /no/such/dir` printed "Operation not permitted", and the
/// very common "probe, then create" idiom (`chdir(d) || (mkdir(d), chdir(d))`
/// in build scripts, `getconf`-style config probes, systemd's
/// `mkdir_parents`) cannot distinguish "not there yet, go make it" from
/// "there and refused", so it aborts instead of creating.
pub(crate) fn sys_chdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    // Linux ABI: `int chdir(const char *path)` — a single NUL-terminated
    // path, no length arg. (Previously this read arg1 as a NARF-native
    // length, so musl/busybox's chdir(path) hit us with garbage in arg1
    // and failed every cd. Same fix as openat — see
    // [[narf-mmap-no-file-backed]] / the *at ABI cutover.)
    // `getname()` reports -EFAULT for an unreadable pointer and
    // -ENAMETOOLONG for a path that reaches PATH_MAX with no terminator.
    // Folding both into -EFAULT told a caller its POINTER was bad when the
    // pointer was fine and the PATH was too long.
    let path = match copy_user_cstr_checked(ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // chdir passes no LOOKUP_EMPTY, so `getname()` rejects "" outright with
    // -ENOENT. Without this the empty string joins the cwd and `chdir("")`
    // silently succeeds as a no-op.
    if path.is_empty() {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }
    let task = current_task_id();
    // Validate against the chroot-resolved path, but STORE the user
    // view — chroot is applied exactly once, at resolution time (see
    // resolve_cwd_path_user).
    let user_abs = resolve_cwd_path_user(task, &path);
    let abs = resolve_cwd_path(task, &path);
    // Linux chdir(2) follows the final symlink.  The directory walker below
    // deliberately accepts directories only, so expand links first instead
    // of rejecting a valid link-to-directory (Fedora's
    // /usr/share/X11/xkb -> ../xkeyboard-config-2 is one such path).
    let Some(resolved) = resolve_vfs_symlink_path(&abs, true) else {
        // The expander gives up only after SYMLOOP_MAX (40) hops or on a
        // link whose target is empty/unreadable — Linux's -ELOOP from
        // `link_path_walk`.
        ctx.set_return(SyscallReturn::ok((-40i64) as u64)); // -ELOOP
        return;
    };
    // Reject cd into a path that isn't a directory. LOOKUP_DIRECTORY makes
    // Linux say -ENOTDIR when the name resolves to a non-directory and
    // -ENOENT when it resolves to nothing; keep the two apart by asking the
    // dir-aware stat resolver what (if anything) is actually there.
    if resolve_dir_absolute(&resolved).is_none() {
        let errno = match stat_ino_path_dir_aware_ext(&resolved, true) {
            // Exists, but is not a directory (regular file, device, fifo…).
            Some((s, ..)) if s.mode.file_type != narf_filesystem::FileType::Dir => -20i64,
            // The final component resolves to nothing. Re-classify the
            // walk: a NON-final component that is not a directory is also
            // -ENOTDIR in Linux (`link_path_walk`), which this used to
            // report as -ENOENT.
            // `path_lookup_errno` also reports -EACCES when an ANCESTOR is
            // not searchable, which is what Linux's walk would have failed
            // with before it ever reached the final component.
            _ => -path_lookup_errno(&resolved),
        };
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `error = path_permission(&path, MAY_EXEC | MAY_CHDIR);` — the check
    // runs AFTER the lookup, so a missing or non-directory target keeps its
    // own errno and only a real directory can be refused for permission.
    //
    // This is the -EACCES that used to be a documented LINUX-GAP here: a
    // directory a task cannot search is one it cannot make its cwd.
    if !dir_search_permitted(&resolved, task) {
        ctx.set_return(SyscallReturn::ok((-13i64) as u64)); // -EACCES
        return;
    }
    task_map_set(&CWD_TABLE, task, user_abs);
    ctx.set_return(SyscallReturn::ok(0));
}
