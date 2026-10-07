#[allow(unused_imports)]
use super::*;

fn current_file_exists(path: &str) -> bool {
    current_resolve_absolute(path, |_fs, root, rel| {
        if rel.is_empty() {
            return false;
        }
        matches!(
            poll_blocking(narf_filesystem::resolve_async_dentry_nofollow(root, rel)),
            Some(Ok(_))
        )
    })
    .unwrap_or(false)
}

/// Does `target` name something `mount(2)` could graft onto?
///
/// `do_mount` resolves the target with `user_path_at` before calling
/// `path_mount`, so a target that does not resolve is -ENOENT and nothing
/// else runs. NARF's mount table is flat, so "resolves" means any of: a
/// directory, an existing file (binding a file onto a file is legal — see
/// `graft_tree`), or a path that is already a mount point.
fn mount_target_exists(target: &str) -> bool {
    current_mount_list().iter().any(|mount| mount == target)
        || resolve_dir_absolute(target).is_some()
        || current_file_exists(target)
}

/// `MS_REMOUNT`, the tail of `path_mount` (`fs/namespace.c`):
///
/// ```text
/// /* The default atime for remount is preservation */
/// if ((flags & MS_REMOUNT) &&
///     ((flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME |
///                MS_STRICTATIME)) == 0)) {
///         mnt_flags &= ~MNT_ATIME_MASK;
///         mnt_flags |= path->mnt->mnt_flags & MNT_ATIME_MASK;
/// }
/// sb_flags = flags & (SB_RDONLY | SB_SYNCHRONOUS | SB_MANDLOCK | SB_DIRSYNC |
///                     SB_SILENT | SB_POSIXACL | SB_LAZYTIME | SB_I_VERSION);
/// if ((flags & (MS_REMOUNT | MS_BIND)) == (MS_REMOUNT | MS_BIND))
///         return do_reconfigure_mnt(path, mnt_flags);
/// if (flags & MS_REMOUNT)
///         return do_remount(path, sb_flags, mnt_flags, data_page);
/// ```
///
/// Both halves open with `if (!path_mounted(path)) return -EINVAL;` — a
/// remount names a mount, and "mount point not mounted or bad option" is
/// util-linux's text for exactly that -EINVAL. `do_reconfigure_mnt` only
/// replaces the attachment's flags. `do_remount` reconfigures the SUPERBLOCK
/// first — `fs_context_for_reconfigure(dentry, sb_flags, MS_RMT_MASK)`, then
/// `parse_monolithic_mount_data(fc, data)` (the generic `ro`/`rw`/`sync`
/// keys, then the filesystem's own), then `reconfigure_super` — and sets the
/// mount's flags only once that succeeded.
///
/// This used to write the flags before looking at `data`, so a remount the
/// filesystem refused still changed the mount, and any `data` at all went
/// to the filesystem whole: ext4 had no reconfigure, so `mount -o remount /`
/// with fstab's options was -EINVAL and systemd-remount-fs failed on every
/// boot.
fn remount(target: &str, flags: u64, mnt_flags: u64, data: &str) -> Result<(), i64> {
    use narf_filesystem::{mnt_flags as mnt, sb_flags as sb};
    let target = if target.len() > 1 {
        target.trim_end_matches('/')
    } else {
        target
    };
    // `path_mounted`.
    let Some(current) = current_mount_flags_exact(target) else {
        return Err(EINVAL);
    };
    let mut mnt_flags = mnt_flags;
    if flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME) == 0 {
        mnt_flags = (mnt_flags & !mnt::ATIME_MASK) | (current & mnt::ATIME_MASK);
    }
    if flags & MS_BIND == 0 {
        let fs = current_fs_arc_at(target).ok_or(EINVAL)?;
        // `fs_context_for_reconfigure(..., sb_flags, MS_RMT_MASK)`: the
        // legacy call restates every reconfigurable superblock flag.
        let mut sb_flags = flags
            & (MS_RDONLY
                | MS_SYNCHRONOUS
                | MS_MANDLOCK
                | MS_DIRSYNC
                | MS_SILENT
                | MS_POSIXACL
                | MS_LAZYTIME
                | MS_I_VERSION);
        let mut sb_mask = sb::RMT_MASK;
        let (set, clear, fs_options) = crate::mount_api::split_monolithic_options(data);
        sb_flags = (sb_flags | set) & !clear;
        sb_mask |= set | clear;
        crate::mount_api::reconfigure_super(&fs, sb_flags, sb_mask, &fs_options)?;
    }
    // `set_mount_attributes`.
    if current_set_mount_flags(target, mnt_flags) {
        Ok(())
    } else {
        Err(EINVAL)
    }
}

/// `path` positively resolves to something that is not a directory.
fn target_is_non_dir(path: &str) -> bool {
    resolve_dir_absolute(path).is_none() && current_file_exists(path)
}

/// `graft_tree`'s `d_is_dir(mountpoint) != d_is_dir(mnt_root)` for a bind,
/// answered only when both ends resolve (an unresolvable end is `false`).
fn mount_type_mismatch(source: &str, target: &str) -> bool {
    let src_dir = resolve_dir_absolute(source).is_some();
    let tgt_dir = resolve_dir_absolute(target).is_some();
    (src_dir && target_is_non_dir(target)) || (tgt_dir && target_is_non_dir(source))
}

/// `strndup_user` (`mm/util.c`) reports a string longer than its cap as
/// -EINVAL, where `copy_user_cstr_checked` gives the pathname answer.
fn strndup_user_errno(errno: i64) -> i64 {
    if errno == ENAMETOOLONG {
        EINVAL
    } else {
        errno
    }
}

/// Map an `FsError` raised while ATTACHING a built filesystem (or a bind) at
/// the target onto the errno `fs/namespace.c::do_add_mount` / `graft_tree`
/// would report. Notably not EFAULT: an attach failure has nothing to do with
/// the caller's pointers, and reporting "Bad address" for it sends a mount
/// helper hunting for a buffer bug that does not exist (this is exactly how
/// xdg-document-portal's "fuse: mount failed: Bad address" arose).
fn mount_attach_errno(e: narf_filesystem::FsError) -> SyscallReturn {
    errno_ret(crate::mount_api::mount_error_errno(e))
}

// `include/uapi/linux/mount.h`. Neither bit is in the shared `MS_*` block
// because nothing else in NARF acts on them.
//
// MS_MGC_VAL is the pre-2.4 "mount magic": callers used to OR it into the
// flag word and the kernel strips it before ANY flag is interpreted. That
// strip is not cosmetic — MS_MGC_VAL (0xC0ED0000) contains bit 31, which is
// MS_NOUSER, so a legacy caller that still passes the magic would otherwise
// be rejected with EINVAL by the very next check.
const MS_MGC_MSK: u64 = 0xffff_0000;
const MS_MGC_VAL: u64 = 0xC0ED_0000;
const MS_NOUSER: u64 = 1 << 31;

/// `fs/namespace.c::path_mount`, reached from `do_mount` /
/// `SYSCALL_DEFINE5(mount)`, in the order the kernel applies it:
///
/// ```text
///   SYSCALL_DEFINE5(mount): copy_mount_string(type);      /* -EFAULT */
///                           copy_mount_string(dev_name);  /* -EFAULT */
///                           copy_mount_options(data);     /* -EFAULT */
///   do_mount():   user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
///                                        /* -EFAULT/-ENOENT/-ENOTDIR/-EACCES */
///   path_mount(): if ((flags & MS_MGC_MSK) == MS_MGC_VAL) flags &= ~MS_MGC_MSK;
///                 if (flags & MS_NOUSER)  return -EINVAL;
///                 if (!may_mount())       return -EPERM;
///                 ... dispatch: remount / bind / change_type / move / new
/// ```
///
/// Getting the errno right matters more for mount(2) than for almost any
/// other syscall, precisely BECAUSE EPERM is one of its legitimate answers:
/// a bare `-1` is indistinguishable from "you lack CAP_SYS_ADMIN". A
/// container runtime branches hard on that — EPERM means "re-exec in a user
/// namespace / give up on this mount", while ENODEV means "load the module
/// or pick another fstype", EBUSY means "retry after the previous tenant
/// leaves", ENOENT means "mkdir the target first" and EINVAL means "the
/// option string is wrong". Collapsing all five into EPERM makes every one
/// of them look like a privilege problem.
///
/// LINUX-GAPs still open in this handler, all noted where they occur:
///   * The target is never required to exist. `do_mount` resolves it with
///     `user_path_at` and returns -ENOENT BEFORE `path_mount` runs, so a
///     missing target outranks both the MS_NOUSER -EINVAL and the
///     `may_mount()` -EPERM. NARF's flat mount table instead registers a
///     mount at a path that has no node, so the call reports success and
///     nothing is there. `do_add_mount`'s -EBUSY for a target that already
///     carries this same mount is likewise absent.
///
///     Closing this needs more than a check here. Mounts are string-prefix
///     routing over a flat `Vec<Mount>`, not a tree, so "does this target
///     exist" can only be answered by a filesystem that covers the path —
///     and NARF mounts a root only when the cmdline carries `root=`. The
///     kernel-test fixtures mount none at all and mount at paths with no
///     node throughout; a root MemFs makes them answerable (measured: no
///     regressions), after which ~65 fixtures still need their bespoke
///     targets created before the check can be turned on.
///   * -ENOTDIR is NOT "the target is not a directory". Linux raises it from
///     `graft_tree`, and it is a MISMATCH test between the two ends:
///
///         if (d_is_dir(mp->mp->m_dentry) != d_is_dir(mnt->mnt.mnt_root))
///                 return -ENOTDIR;
///
///     so a file bound onto a file is legal — that is how a container gets
///     its own /etc/resolv.conf — while a filesystem onto a file, or a file
///     onto a directory, is -ENOTDIR. Reading this arm as "target must be a
///     directory" and enforcing that would break file bind mounts. The
///     mismatch test is applied for binds and new filesystems (see
///     `mount_type_mismatch` / `target_is_non_dir`); overlay, FUSE and
///     block-device mounts do not yet make it.
///   * -ENOTBLK (a block-device fstype whose `source` names a non-block file)
///     and -EACCES (an unsearchable target directory) have no NARF analogue:
///     the block layer here is a flat name→device registry with no file
///     identity, and there is no directory permission walk on the mount path.
///   * MS_REC / MS_RELATIME are accepted and then ignored: NARF has no
///     mount propagation (every mount is private) and no per-inode atime
///     policy to relax. MS_RDONLY / MS_NOSUID / MS_NODEV / MS_NOEXEC are
///     translated into the mount's `MNT_*` set and enforced.
pub(crate) fn sys_mount(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // errno replies (negated-long convention). Every failure carries a
    // specific errno (a bare -1 would map to EPERM), matching Linux mount(2).
    let einval = errno_ret(EINVAL); // EINVAL — bad argument
    let enodev = errno_ret(ENODEV); // ENODEV — unknown fstype
    let ebusy = errno_ret(EBUSY); // EBUSY — target in use
    let enoent = errno_ret(ENOENT); // ENOENT — missing source

    // Linux `mount(2)`: (const char *source, const char *target,
    // const char *filesystemtype, unsigned long mountflags, const void *data).
    // All strings are NUL-terminated; there are NO explicit length args.
    //   arg0 = source, arg1 = target, arg2 = fstype, arg3 = flags, arg4 = data.
    // This handler previously used a NARF-native (ptr, len, ...) shape with
    // fstype_len/flags packed into arg5 — so a musl-built caller's Linux-ABI
    // call was mis-parsed (arg1 read as a length, etc.) and returned EPERM.
    // That silently broke every real mount: elogind's per-user tmpfs at
    // /run/user/0 failed → CreateSession failed → no logind session for kwin.
    //
    // `SYSCALL_DEFINE5(mount)` stages the three copyable strings BEFORE it
    // looks at the target, and `copy_mount_string` is `strndup_user`: a NULL
    // pointer yields NULL (no error), a faulting one yields -EFAULT. Folding
    // a fault into an empty string — which is what `unwrap_or_default()` did
    // for `source` and `fstype` — turned "your fstype pointer is garbage"
    // into "unknown filesystem type" (ENODEV) and a faulting `source` into a
    // silent block-device-less mount attempt.
    //
    // The copy ORDER is Linux's: type, then dev_name, then data, then the
    // target path. All four faults are EFAULT, so the order is only visible
    // through which string a handler stops on — but keeping it means a later
    // length/name check added to one of them lands where Linux puts it.
    //
    // fstype may be NULL for MS_REMOUNT / MS_BIND / MS_MOVE. The cap is
    // `copy_mount_string`'s PAGE_SIZE.
    //
    // `strndup_user` answers an over-long string with -EINVAL, not the
    // -ENAMETOOLONG `getname` uses for the target path below: these two are
    // opaque strings, not pathnames (probed on Linux 6.18: a 4096-byte
    // fstype or source is EINVAL, a 4096-byte target is ENAMETOOLONG).
    let fstype = if args.arg2 == 0 {
        alloc::string::String::new()
    } else {
        match copy_user_cstr_checked(args.arg2, 4096) {
            Ok(s) => s,
            Err(errno) => {
                ctx.set_return(errno_ret(strndup_user_errno(errno)));
                return;
            }
        }
    };
    // A NULL source is legal (MS_REMOUNT / propagation changes pass one).
    let source = if args.arg0 == 0 {
        alloc::string::String::new()
    } else {
        match copy_user_cstr_checked(args.arg0, 4096) {
            Ok(s) => s,
            Err(errno) => {
                ctx.set_return(errno_ret(strndup_user_errno(errno)));
                return;
            }
        }
    };
    // arg4 = fs-specific `data` (e.g. tmpfs "mode=0700,size=64M").
    let data = if args.arg4 == 0 {
        alloc::string::String::new()
    } else {
        match copy_user_cstr_checked(args.arg4, 4096) {
            Ok(data) => data,
            Err(errno) => {
                ctx.set_return(errno_ret(errno));
                return;
            }
        }
    };
    let target_raw = match copy_user_cstr_checked(args.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // `getname("")` without LOOKUP_EMPTY is -ENOENT. Resolving the empty
    // string instead would name the cwd and mount over it.
    if target_raw.is_empty() {
        ctx.set_return(enoent);
        return;
    }
    // `do_mount` (fs/namespace.c:4163) resolves the target FIRST and returns
    // the lookup's error before `path_mount` ever runs:
    //
    //     ret = user_path_at(AT_FDCWD, dir_name, LOOKUP_FOLLOW, &path);
    //     if (ret) return ret;
    //     return path_mount(dev_name, &path, type_page, flags, data_page);
    //
    // The order is load-bearing: a missing target is -ENOENT even for an
    // unprivileged caller passing an in-kernel-only flag, because both the
    // MS_NOUSER -EINVAL and the `may_mount()` -EPERM live inside
    // `path_mount`, downstream of this. Resolving here rather than after
    // those checks is what keeps "mkdir the target first" distinguishable
    // from "you may not mount" — the collapse this handler's header comment
    // is about.
    let target_path = parse_proc_self_fd(target_raw.as_str())
        .and_then(|fd| fd_path_for_task(current_task_id(), fd))
        .filter(|path| path.starts_with('/'))
        .unwrap_or(target_raw);
    // Resolve target under the calling task's chroot.
    let target = apply_chroot(target_path.as_str());
    // `mount(2)` resolves symlinks in the target before attaching. Fedora's
    // `/var/mail -> spool/mail` is one ordinary example: binding the link
    // inode as a file mount makes later namespace remounts fail instead of
    // binding the directory it names. `/proc/self/fd/N` magic links were
    // expanded above from their descriptor's backing path; leave other
    // procfs magic links to the procfs-specific resolver.
    let target = if target.starts_with("/proc/") {
        target
    } else {
        resolve_vfs_symlink_path(target.as_str(), true).unwrap_or(target)
    };
    // The -ENOENT `user_path_at` would have produced. Without it NARF's flat
    // mount table registered a mount at a path with no node: the call
    // reported success and nothing was there, so a caller that mounts to a
    // path it has not created — the "probe, then mkdir" idiom systemd and
    // every container runtime use — never learned it had to create it.
    if !mount_target_exists(target.as_str()) {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    // `path_mount` then discards the legacy mount magic before any flag is
    // read, and rejects MS_NOUSER — the in-kernel-only bit that marks a
    // mount userspace may not request.
    let flags = args.arg3;
    let flags = if flags & MS_MGC_MSK == MS_MGC_VAL {
        flags & !MS_MGC_MSK
    } else {
        flags
    };
    if flags & MS_NOUSER != 0 {
        ctx.set_return(einval);
        return;
    }
    // `if (!may_mount()) return -EPERM;` — `may_mount()` is
    // `ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN)`.
    //
    // Its position inside `path_mount` is after the four string copies and
    // after the MS_NOUSER rejection, so a faulting pointer is still -EFAULT
    // and the in-kernel-only flag is still -EINVAL for an unprivileged
    // caller. It sits before any mount state is touched, which is what
    // matters: an unprivileged mount must not partially register.
    //
    // LINUX-GAP: this is `ns_capable` against the MOUNT namespace's owning
    // user namespace, so a task that created a user+mount namespace pair may
    // mount inside it without being globally privileged. NARF checks the
    // effective set only — the restrictive direction.
    // `may_mount`: `ns_capable(current->nsproxy->mnt_ns->user_ns,
    // CAP_SYS_ADMIN)` — the MOUNT namespace's owner, not the host. Asking the
    // host question refuses a container that unshared its own mount
    // namespace, which is the one place mounting is supposed to be allowed.
    if !mount_admin(current_task_id()) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }

    // Propagation-only change (MS_SLAVE/MS_SHARED/MS_PRIVATE/MS_UNBINDABLE,
    // optionally |MS_REC) is dispatched AFTER target resolution below (it needs
    // the resolved, chroot-applied target path). It is gated on "a propagation
    // bit is set and no fstype / bind / move / remount work is requested" so a
    // legitimate mount that also carries a propagation bit still falls through
    // to the real dispatch. These calls carry a NULL source and NULL fstype.

    // systemd performs namespace assembly through O_PATH directory handles and
    // passes `/proc/self/fd/N` to mount(2). Linux follows that procfs magic
    // symlink before attaching the mount; treating it as a literal path mounts
    // over the procfs entry instead of the directory and leaves the assembled
    // namespace root absent.
    // Resolve source under chroot too when it's a path (bind / tmpfs
    // source-as-label is harmless to pass through; block-device names
    // don't start with `/` so apply_chroot is a no-op).
    let source_path = parse_proc_self_fd(source.as_str())
        .and_then(|fd| fd_path_for_task(current_task_id(), fd))
        .filter(|path| path.starts_with('/'))
        .unwrap_or_else(|| source.clone());
    let source_resolved = if source_path.starts_with('/') {
        apply_chroot(source_path.as_str())
    } else {
        source_path.clone()
    };
    // `mount(2)` resolves symlinks in both source and target before doing a
    // bind. Fedora's `/var/mail -> spool/mail` is one ordinary example:
    // binding the link inode as a file mount makes later namespace remounts
    // fail instead of binding the directory it names. `/proc/self/fd/N` magic
    // links were expanded above from their descriptor's backing path; leave
    // other procfs magic links to the procfs-specific resolver.
    let source_resolved =
        if !source_resolved.starts_with('/') || source_resolved.starts_with("/proc/") {
            source_resolved
        } else {
            resolve_vfs_symlink_path(source_resolved.as_str(), true).unwrap_or(source_resolved)
        };
    // `path_mount` translates the restriction flags into the `MNT_*` set
    // the mount carries, which the VFS then enforces per mount. MS_REC is
    // honoured for bind mounts (the bind branch replicates the source's
    // submounts) and for change_type (below).
    let mnt_flags = mnt_flags_from_ms(flags);

    // `fs/namespace.c::do_change_type` — `mount --make-{shared,private,slave,
    // unbindable}[,rshared,...]`. Reached when a propagation bit is set and no
    // bind/move/remount work is requested (those carry a real source/fstype;
    // a change_type call has NULL source and NULL fstype and only re-types the
    // mount already at `target`). systemd runs `mount(NULL,"/",NULL,MS_REC|
    // MS_SHARED,NULL)` (make-rshared) at early boot, and per-service make-shared
    // during sandbox assembly — the peer groups this establishes are what let a
    // mount created under a shared /run propagate to every namespace sharing it.
    //
    // `path_mount` dispatches remount, then bind, then change_type, then
    // move, so a propagation bit alongside MS_MOVE is a change_type request.
    // `flags_to_propagation_type` takes `flags & ~(MS_REC | MS_SILENT)` —
    // EVERY other bit, not just the propagation subset — and requires it to
    // be exactly one propagation flag: MS_SHARED|MS_MOVE and
    // MS_SHARED|MS_NOSUID are both -EINVAL (probed on Linux 6.18).
    if (flags & MS_PROPAGATION) != 0 && (flags & (MS_BIND | MS_REMOUNT)) == 0 {
        const MS_SILENT: u64 = 1 << 15;
        let prop_bits = flags & !(MS_REC | MS_SILENT);
        let prop = if prop_bits == MS_SHARED {
            narf_filesystem::MntPropagation::Shared
        } else if prop_bits == MS_PRIVATE {
            narf_filesystem::MntPropagation::Private
        } else if prop_bits == MS_SLAVE {
            narf_filesystem::MntPropagation::Slave
        } else if prop_bits == MS_UNBINDABLE {
            narf_filesystem::MntPropagation::Unbindable
        } else {
            // Zero or more-than-one propagation bit set.
            ctx.set_return(einval);
            return;
        };
        let recursive = (flags & MS_REC) != 0;
        // `change_propagation_at` re-types the mount at `target` and returns
        // whether it found one. LINUX-GAP: `do_change_type` answers -EINVAL when
        // the path is not a mountpoint, but NARF's flat, string-prefix mount
        // table registers a mount only where one was explicitly attached (see
        // the target-existence LINUX-GAP in this handler's doc), so a make-shared
        // on a path with no registered mount has no propagation state to change.
        // Reporting EINVAL there would break systemd's `make-rshared /` and
        // per-service `make-*` on the many paths NARF does not track as mounts;
        // a path with nothing to re-type is a no-op success, which is also the
        // behaviour this branch had before propagation existed.
        let _ = current_change_propagation(target.as_str(), prop, recursive);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // A bind remount changes flags on an existing mount; `source` and
    // `filesystemtype` are conventionally NULL and must not be interpreted as
    // a request to create another bind. systemd uses this after constructing
    // each service's private mount namespace.
    if (flags & MS_REMOUNT) != 0 {
        ctx.set_return(match remount(&target, flags, mnt_flags, &data) {
            Ok(()) => SyscallReturn::ok(0),
            Err(errno) => errno_ret(errno),
        });
        return;
    }

    let auth = narf_filesystem::bootstrap_mount_authority();

    // MS_BIND outranks MS_MOVE in `path_mount`'s dispatch.
    if (flags & MS_MOVE) != 0 && (flags & MS_BIND) == 0 {
        // `do_move_mount_old`: `if (!old_name || !*old_name) return -EINVAL;`
        if source.is_empty() {
            ctx.set_return(einval);
            return;
        }
        // A relative source (systemd's switch-root fallback does
        // `mount(".", "/", MS_MOVE)` after fchdir into the new root) resolves
        // against the caller's cwd, not as a literal path that matches no mount.
        let move_source = if source_resolved.starts_with('/') {
            source_resolved.clone()
        } else {
            resolve_cwd_path(current_task_id(), source_resolved.as_str())
        };
        // Trim a trailing slash so the exact mount-path match succeeds — a
        // relative "." at cwd "/" resolves to "<root>/" (see sys_umount2).
        let move_source = if move_source.len() > 1 {
            alloc::string::String::from(move_source.trim_end_matches('/'))
        } else {
            move_source
        };
        let move_target = if target.len() > 1 {
            target.trim_end_matches('/')
        } else {
            target.as_str()
        };
        return match current_move_mount(&auth, move_source.as_str(), move_target) {
            Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
            // `kern_path(old_name)` failing is -ENOENT; a source that resolves
            // but is not the root of a mount is `do_move_mount`'s -EINVAL.
            Err(narf_filesystem::FsError::NotFound) if mount_target_exists(&move_source) => {
                ctx.set_return(einval)
            }
            Err(narf_filesystem::FsError::NotFound) => ctx.set_return(enoent),
            Err(narf_filesystem::FsError::Busy) => ctx.set_return(ebusy),
            Err(_) => ctx.set_return(einval),
        };
    }

    // Wave-71: MS_BIND or fstype=="bind" → bind mount. `source` is
    // an absolute path; `target` is the new path. No block device.
    if fstype == "bind" || (flags & MS_BIND) != 0 {
        // `do_loopback`'s first line: `if (!old_name || !*old_name) return
        // -EINVAL;`. A NULL source is legal for MS_REMOUNT and the
        // propagation changes handled above, but a bind has nothing to bind
        // FROM without one — and reaching the lookup with an empty string
        // would resolve it against the cwd and bind something arbitrary.
        if source.is_empty() {
            ctx.set_return(einval);
            return;
        }
        // `graft_tree`: `if (d_is_dir(mp) != d_is_dir(mnt_root)) return
        // -ENOTDIR;` — a mismatch test, so file-on-file stays legal. Only
        // decided when both ends positively resolve; a missing source falls
        // through to the bind below and its -ENOENT.
        if mount_type_mismatch(source_resolved.as_str(), target.as_str()) {
            ctx.set_return(errno_ret(ENOTDIR));
            return;
        }
        let source_base = if source_resolved == "/" {
            "/"
        } else {
            source_resolved.trim_end_matches('/')
        };
        // `__do_loopback`: a recursive bind is `copy_tree` of the source mount
        // and every mount below it, grafted at the target — a self-bind
        // (`mount --rbind /x /x`) included, which stacks a copy of `/x` and of
        // each submount, exactly as mountinfo shows on Linux.
        let descendants = if flags & MS_REC != 0 {
            current_clone_mount_subtree(source_base)
                .map(|(_, descendants)| descendants)
                .unwrap_or_default()
        } else {
            alloc::vec::Vec::new()
        };
        // systemd protects procfs control files (ProtectHostname=,
        // ProtectKernelTunables=) by bind-mounting a file over itself before a
        // read-only remount. That must create a REAL mount entry — even for a
        // self-bind — so the path shows up in /proc/self/mountinfo; otherwise
        // systemd's recursive remount loops 32× waiting for it and fails EBUSY
        // (226/EXIT_NAMESPACE). current_bind_mount handles a file source by
        // registering a FileMount, so a self-bind of a file is a real mount
        // whose lookups still resolve to the same file.
        // `fs/namespace.c::do_loopback` reports why a bind failed:
        //
        // ```text
        // if (!old_name || !*old_name)             return -EINVAL;
        // err = kern_path(old_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
        // if (err)                                 return err;   /* -ENOENT */
        // err = -EINVAL;
        // if (mnt_ns_loop(old_path.dentry))        goto out;
        // if (!check_mnt(...))                     goto out;
        // ```
        //
        // This arm used to report 0 for every failure. A swallowed failure is
        // the worst shape in this whole audit: a wrong errno at least says
        // something went wrong, but "success" for a mount that does not exist
        // sends the caller on to use a path that was never attached. systemd
        // then remounts, or execs into, a directory it believes it isolated.
        //
        // The previous note declined to change it because live paths were
        // thought to depend on the success reply. Re-reading the failure
        // modes, they do not: `bind_mount` fails only when no mount covers
        // the source or `build_bind_fs` cannot resolve the leaf, and the two
        // named cases are both fine — a procfs control file resolves and
        // binds as a FileMount, and overmounting is explicitly supported
        // (see `VfsRegistry::mount`'s doc), so a self-bind succeeds and never
        // reaches this arm at all.
        return match current_bind_mount(&auth, source_resolved.as_str(), target.as_str()) {
            Ok(_h) => {
                for (relative, fs) in descendants {
                    let child_target = if target == "/" {
                        alloc::format!("/{}", relative.trim_start_matches('/'))
                    } else {
                        alloc::format!("{}{}", target.trim_end_matches('/'), relative)
                    };
                    let _ = current_mount_arc_with_flags(&auth, child_target.as_str(), fs, mnt_flags);
                }
                ctx.set_return(SyscallReturn::ok(0));
            }
            Err(e) => ctx.set_return(SyscallReturn::ok(bind_errno(e))),
        };
    }

    // A NULL type differs from an unknown registered name.
    if args.arg2 == 0 {
        ctx.set_return(einval);
        return;
    }
    super::mount_types::register_mount_types();
    let Some(fs_type) = narf_filesystem::lookup_fstype(&fstype) else {
        ctx.set_return(enodev);
        return;
    };
    if target_is_non_dir(&target) {
        ctx.set_return(errno_ret(ENOTDIR));
        return;
    }
    let (uid, gid) = current_fs_ids();
    let request = narf_filesystem::MountRequest {
        fs_type: &fstype, source: &source_resolved, options: &data,
        uid, gid, umask: current_umask() as u16,
        initial_namespace: current_mount_namespace().is_none(),
    };
    ctx.set_return(match fs_type.init(&request) {
        Ok(fs) => match current_mount_arc_with_flags(&auth, &target, fs, mnt_flags) {
            Ok(_) => SyscallReturn::ok(0),
            Err(error) => mount_attach_errno(error),
        },
        Err(error) => mount_attach_errno(error),
    });
}
