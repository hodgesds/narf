#[allow(unused_imports)]
use super::*;

/// `linkat(olddirfd, oldpath, newdirfd, newpath, flags)` — x86_64 265,
/// aarch64 37. Relative paths resolve against their directory fd's
/// recorded open path (same prepend as sys_readlinkat); AT_FDCWD /
/// absolute paths take the cwd route inside `link_impl`.
/// AT_SYMLINK_FOLLOW is accepted and ignored for the path form — NARF's
/// `DirOps::link` links the symlink entry itself, the no-flags default.
///
/// Two `O_TMPFILE` materialisation forms are handled specially (they name
/// an inode by its open fd, not by a source path):
///   - `AT_EMPTY_PATH` + empty oldpath: olddirfd IS the O_TMPFILE fd.
///   - `AT_SYMLINK_FOLLOW` + oldpath = `/proc/self/fd/N`: N names the fd.
///
/// Both file the fd's anonymous inode into newpath via `link_node`.
pub(crate) fn sys_linkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `SYSCALL_DEFINE5(linkat)` takes `CLASS(filename, old)(oldname)` then
    // `CLASS(filename, new)(newname)`, and `filename_linkat` propagates the
    // OLD name's error first. The tuple form here evaluated both and then
    // reported one shared sentinel, so which pathname was at fault was lost
    // along with the reason; -EFAULT and -ENAMETOOLONG are now distinct and
    // the old name is answered first, as Linux does.
    let old_raw = match copy_user_cstr_checked(args.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let new_raw = match copy_user_cstr_checked(args.arg3, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    const AT_FDCWD: i64 = -100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    let flags = args.arg4;
    let task = current_task_id();
    let with_dirfd = |dirfd: i64, path: alloc::string::String| -> alloc::string::String {
        if path.starts_with('/') || dirfd == AT_FDCWD || dirfd < 0 {
            return path;
        }
        match fd_path_for_task(task, dirfd as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), path)
            }
            _ => path,
        }
    };
    let new_eff = with_dirfd(args.arg2 as i64, new_raw);

    // O_TMPFILE materialisation, form 1: AT_EMPTY_PATH + empty oldpath →
    // olddirfd is the O_TMPFILE fd whose anonymous inode gets named.
    if flags & AT_EMPTY_PATH != 0 && old_raw.is_empty() {
        let src_fd = args.arg0 as i64;
        if src_fd < 0 {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
        let new_abs = resolve_cwd_path(task, &new_eff);
        let r = link_fd_node_impl(task, src_fd as u32, &new_abs);
        ctx.set_return(SyscallReturn::ok(r as u64));
        return;
    }

    // O_TMPFILE materialisation, form 2: oldpath = /proc/self/fd/N (or
    // /proc/<pid>/fd/N) — the anonymous inode is named by that magic
    // symlink. Only take this route when N names a live PATHLESS fd (an
    // O_TMPFILE / memfd node); a /proc/self/fd/N that points at a real
    // named file falls through to the ordinary path-based hard link.
    let old_eff = with_dirfd(args.arg0 as i64, old_raw);
    if let Some(src_fd) = parse_proc_self_fd(&old_eff) {
        // `linkat(…, "/proc/self/fd/N", …, AT_SYMLINK_FOLLOW)` means "give
        // the object this fd refers to another name", so linking the fd's
        // NODE is the direct answer — for an anonymous O_TMPFILE inode and
        // for an already-named file alike. Qt's QSaveFile (every
        // KDE/KConfig/KSycoca database write) materialises its O_TMPFILE
        // inode with exactly this call.
        //
        // The previous guard tried to detect an "anonymous" fd first and
        // only then take this route, which was wrong twice over: it asked
        // `fd_path_of(..).is_none()`, and that helper synthesises an
        // `anon_inode:[TypeName]` placeholder rather than ever answering
        // None — so the branch was dead and every such call fell through
        // to the path-based hard link, where `/proc/self/fd/N` and the
        // target sit in different directories and the answer was EXDEV
        // ("Invalid cross-device link", database never written). Worse,
        // `fd_path_of` can hand back a STALE path for a recycled fd
        // number, so any predicate built on it is unreliable.
        //
        // Instead: take the node route whenever the fd is live, and fall
        // back to the ordinary path-based link only if this filesystem
        // can't adopt a foreign node (-EOPNOTSUPP from `link_node`).
        if fd::with_table(task, |t| t.get(src_fd).is_some()).unwrap_or(false) {
            const EOPNOTSUPP: i64 = -95;
            let new_abs = resolve_cwd_path(task, &new_eff);
            let r = link_fd_node_impl(task, src_fd, &new_abs);
            if r != EOPNOTSUPP {
                ctx.set_return(SyscallReturn::ok(r as u64));
                return;
            }
        }
    }

    link_impl(ctx, &old_eff, &new_eff);
}
