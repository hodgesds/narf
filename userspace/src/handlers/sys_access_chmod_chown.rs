#[allow(unused_imports)]
use super::*;

const AT_EACCESS: u64 = 0x200;
const AT_SYMLINK_NOFOLLOW_ACCESS: u64 = 0x100;
const AT_EMPTY_PATH_ACCESS: u64 = 0x1000;

/// `SYSCALL_DEFINE2(access)` is `do_faccessat(AT_FDCWD, filename, mode, 0)`.
pub(crate) fn sys_access(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    faccessat_common(ctx, (-100i64) as u64, args.arg0, args.arg1 as u32, 0);
}

pub(crate) fn sys_faccessat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    faccessat_common(ctx, args.arg0, args.arg1, args.arg2 as u32, 0);
}

pub(crate) fn sys_faccessat2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    faccessat_common(ctx, args.arg0, args.arg1, args.arg2 as u32, args.arg3);
}

/// `fs/open.c::do_faccessat`:
///
/// ```text
///     if (mode & ~S_IRWXO) return -EINVAL;
///     if (flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return -EINVAL;
///     if (!(flags & AT_SYMLINK_NOFOLLOW)) lookup_flags |= LOOKUP_FOLLOW;
///     if (flags & AT_EMPTY_PATH)          lookup_flags |= LOOKUP_EMPTY;
///     if (access_need_override_creds(flags)) old_cred = access_override_creds();
///     res = user_path_at(dfd, filename, lookup_flags, &path);
///     res = inode_permission(..., mode | MAY_ACCESS);
/// ```
///
/// So the final symlink is FOLLOWED unless the caller says otherwise — this
/// used to resolve it NOFOLLOW always, which made `access()` of a dangling
/// link succeed and checked a link's 0777 bits instead of its target's —
/// and the answer is for the REAL uid/gid unless `AT_EACCESS` is set.
fn faccessat_common(ctx: &mut dyn TrapContext, dirfd: u64, path_ptr: u64, mode: u32, flags: u64) {
    if mode & !7 != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW_ACCESS | AT_EMPTY_PATH_ACCESS) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let raw = match copy_user_cstr_checked(path_ptr, 4096) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let dirfd = dirfd as i64;
    let task = current_task_id();
    let follow = flags & AT_SYMLINK_NOFOLLOW_ACCESS == 0;
    let eaccess = flags & AT_EACCESS != 0;
    // AT_EMPTY_PATH (faccessat2 flags = arg3): an empty path names the fd
    // ITSELF. glibc's access_fd() does faccessat2(fd, "", X_OK, AT_EMPTY_PATH)
    // to test an O_PATH fd for executability, which systemd's
    // open_and_check_executable / find_executable_full uses to confirm a
    // service binary before execve. Without this the relative-join arm below
    // appends "/" to the fd's path, turning a regular-file fd into a
    // directory-shaped path that misses (ENOENT) and kills every sandboxed
    // service 203/EXIT_EXEC.
    if raw.is_empty() {
        if flags & AT_EMPTY_PATH_ACCESS == 0 {
            ctx.set_return(errno_ret(ENOENT));
            return;
        }
        if dirfd >= 0 {
            // LOOKUP_EMPTY resolves to the descriptor's own inode, and
            // `inode_permission` then runs on it like on any other: this
            // used to answer 0 for any open fd, so `access_fd(fd, X_OK)` on
            // a non-executable file said "executable" (Linux: -EACCES even
            // for root, whose CAP_DAC_OVERRIDE needs some x bit to exist).
            let ops = fd::with_table(task, |t| t.get(dirfd as u32).map(|e| e.ops.clone()))
                .flatten();
            match ops {
                Some(file) => access_file(ctx, &file, mode, eaccess),
                None => ctx.set_return(errno_ret(EBADF)),
            }
            return;
        } else if dirfd == -100 {
            let path = resolve_cwd_path(task, ".");
            access_path(ctx, &path, mode, false, eaccess);
            return;
        } else {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
    }
    let effective = match resolve_at_path(task, dirfd, &raw) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    // `/proc/self/fd/N` is a magic link: following it lands on the open
    // file itself, which may have no path at all (pipe, socket, memfd), so
    // the textual link expansion below cannot reach it. Mirror the stat
    // family's handling and check the descriptor's inode directly.
    if follow {
        if let Some(n) = parse_proc_self_fd(&effective) {
            let ops = fd::with_table(task, |t| t.get(n).map(|e| e.ops.clone())).flatten();
            if let Some(file) = ops {
                access_file(ctx, &file, mode, eaccess);
                return;
            }
        }
    }
    // `file/`, `file/.` and `file/../x` are -ENOTDIR in the literal walk;
    // a trailing slash also forces the final link to be followed.
    let path = match literal_walk_check(task, &effective) {
        Ok(Some(dir)) => dir,
        Ok(None) => resolve_cwd_path(task, &effective),
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    access_path(ctx, &path, mode, follow, eaccess);
}

fn access_path(ctx: &mut dyn TrapContext, path: &str, mode: u32, follow: bool, eaccess: bool) {
    // LOOKUP_FOLLOW: expand the final link the way chdir does before the
    // node-level lookups below, which do not follow a final symlink. A
    // resolver that gives up is out of link budget: -ELOOP.
    let followed;
    let path = if follow {
        match resolve_vfs_symlink_path(path, true) {
            Some(p) => {
                followed = p;
                followed.as_str()
            }
            None => {
                ctx.set_return(errno_ret(ELOOP));
                return;
            }
        }
    } else {
        path
    };
    // Resolve through the caller's PRIVATE mount namespace, not the global
    // registry (which `xattr_file` uses). A systemd service sandbox pivot_roots
    // into `/run/systemd/mount-rootfs` with the API filesystems bound in; a
    // global `access("/sys/.../card0/uevent", F_OK)` from inside that namespace
    // hits the empty tmpfs staging skeleton and returns ENOENT. That is exactly
    // the existence probe `sd_device_new_from_syspath` runs, so logind decided
    // card0 did not exist (-ENODEV) and `TakeDevice` failed — kwin never got
    // the GPU. The final link, if any, was expanded above.
    if let Some(file) = resolve_file_absolute_ext(path, false) {
        access_file(ctx, &file, mode, eaccess);
        return;
    }

    // `FileOps` resolution deliberately excludes directories. access(2)
    // applies to both inode kinds, however, and systemd probes a freshly
    // mounted cgroup2 root with W_OK before accepting the hierarchy. Treating
    // every directory (especially a mount root) as ENOENT makes systemd undo
    // the successful mount and abort PID 1.
    if let Some(dir) = resolve_dir_absolute(path) {
        let (uid, gid) = dir.dir_owners();
        // `DirOps` has no xattr surface, so a directory's ACL is not
        // reachable from here — see the LINUX-GAP note on `acl_of_file`
        // consumers in `filesystem/src/posix_acl.rs`.
        set_access_result(ctx, mode, dir.dir_mode(), uid, gid, true, None, eaccess);
    } else {
        // `user_path_at` failing: -ENOTDIR for a non-directory ancestor,
        // -ELOOP, -EACCES for an unsearchable ancestor, -ENAMETOOLONG —
        // not only -ENOENT, which is all this used to report.
        ctx.set_return(errno_ret(path_lookup_errno(path)));
    }
}

/// `inode_permission(inode, mode | MAY_ACCESS)` on a resolved node.
fn access_file(
    ctx: &mut dyn TrapContext,
    file: &alloc::sync::Arc<dyn narf_filesystem::FileOps>,
    mode: u32,
    eaccess: bool,
) {
    match poll_blocking(file.access(mode)) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        Some(Err(narf_filesystem::FsError::PermissionDenied)) => {
            ctx.set_return(errno_ret(EACCES))
        }
        Some(Err(narf_filesystem::FsError::Unsupported)) | None => {
            let st = file.stat();
            let (uid, gid) = file.owners();
            // `fs/namei.c::acl_permission_check` consults the inode's
            // ACCESS ACL between the owner test and the group/other
            // mode bits. Fetch it here so `access(2)` answers the same
            // question the ACL'd inode would: without this the check
            // silently degrades to mode bits and reports EACCES for a
            // path a `setfacl -m u:$uid:rwx` grants.
            let acl = match poll_blocking(narf_filesystem::acl_of_file(
                file.as_ref(),
                narf_filesystem::AclType::Access,
            )) {
                Some(Ok(acl)) => acl,
                // A stored ACL that does not decode is NOT a fallback
                // to the mode bits: `check_acl` returns the decode
                // error and `generic_permission` passes anything that
                // is not -EACCES straight out to the caller.
                Some(Err(narf_filesystem::FsError::Unsupported)) => {
                    ctx.set_return(errno_ret(EOPNOTSUPP));
                    return;
                }
                Some(Err(_)) => {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                // `poll_blocking` gave up — the park failed or the
                // fallback poll budget ran out. Fall back to the mode
                // bits, which is what the sibling `file.access(mode)`
                // arm above already does for its own `None`.
                None => None,
            };
            set_access_result(
                ctx,
                mode,
                st.mode.perms,
                uid,
                gid,
                st.mode.file_type == narf_filesystem::FileType::Dir,
                acl.as_ref(),
                eaccess,
            );
        }
        _ => ctx.set_return(errno_ret(EIO)),
    }
}

/// `fs/open.c::access_override_creds` — unless `AT_EACCESS`, access(2)
/// answers for the REAL ids, not the effective/fs ones:
///
/// ```text
///     override_cred->fsuid = override_cred->uid;
///     override_cred->fsgid = override_cred->gid;
///     if (!issecure(SECURE_NO_SETUID_FIXUP)) {
///             if (!uid_eq(override_cred->uid, root_uid))
///                     cap_clear(override_cred->cap_effective);
///             else
///                     override_cred->cap_effective = override_cred->cap_permitted;
///     }
/// ```
///
/// That is the whole point of access(2) for a set-uid program: "could the
/// user who ran me open this?" Using the fs ids answered for the program's
/// owner instead.
fn access_accessor(task: u64, file_uid: u32, file_gid: u32, eaccess: bool) -> narf_filesystem::Accessor {
    let mut acc = accessor_for_inode(task, file_uid, file_gid);
    if eaccess {
        return acc;
    }
    let ids = read_uidgid(task);
    #[cfg(feature = "container")]
    let initial_ns = {
        let uns = crate::namespaces::current_user_ns(task);
        acc.uid = uns.translate_uid_to_host(ids.uid);
        acc.gid = uns.translate_gid_to_host(ids.gid);
        uns.is_initial()
    };
    #[cfg(not(feature = "container"))]
    let initial_ns = {
        acc.uid = ids.uid;
        acc.gid = ids.gid;
        true
    };
    if !issecure(task, SECURE_NO_SETUID_FIXUP) {
        if ids.uid != 0 {
            acc.dac_override = false;
            acc.dac_read_search = false;
        } else if initial_ns {
            // A non-initial user namespace never holds DAC authority over
            // host inodes (see `current_accessor`); that stays withheld.
            let permitted = read_caps(task).permitted;
            acc.dac_override = permitted & (1u64 << CAP_DAC_OVERRIDE) != 0;
            acc.dac_read_search = permitted & (1u64 << CAP_DAC_READ_SEARCH) != 0;
        }
    }
    acc
}

/// `is_dir` selects Linux's directory override rules: CAP_DAC_READ_SEARCH
/// grants search on a directory but never write, while on a regular file
/// CAP_DAC_OVERRIDE cannot grant execute unless some execute bit is set.
#[allow(clippy::too_many_arguments)]
fn set_access_result(
    ctx: &mut dyn TrapContext,
    mode: u32,
    perms: u16,
    uid: u32,
    gid: u32,
    is_dir: bool,
    acl: Option<&narf_filesystem::PosixAcl>,
    eaccess: bool,
) {
    let request = narf_filesystem::AccessRequest {
        read: mode & 4 != 0,
        write: mode & 2 != 0,
        exec: mode & 1 != 0,
    };
    let allowed = narf_filesystem::posix_access_ok_with_acl(
        narf_filesystem::FileOwner {
            uid,
            gid,
            perms,
            is_dir,
        },
        &access_accessor(current_task_id(), uid, gid, eaccess),
        request,
        acl,
    );
    ctx.set_return(if allowed { SyscallReturn::ok(0) } else { errno_ret(EACCES) });
}

pub(crate) fn sys_chown(ctx: &mut dyn TrapContext) {
    chown_legacy(ctx, 0);
}

pub(crate) fn sys_lchown(ctx: &mut dyn TrapContext) {
    chown_legacy(ctx, 0x100); // AT_SYMLINK_NOFOLLOW
}

fn chown_legacy(ctx: &mut dyn TrapContext, flags: u64) {
    let args = *ctx.args();
    // Linux ABI for the three legacy entries:
    //   access(path, mode)      — arg1 = mode
    //   chmod(path, mode)       — arg1 = mode
    //   chown(path, uid, gid)   — arg1 = uid, arg2 = gid
    // All take an absolute path as a NUL-terminated cstr; the body
    // Forward legacy chown(path, uid, gid) to the fchownat ABI.
    let path_uptr = args.arg0;
    let _path_str = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            // Unreadable user path pointer → EFAULT, not a bare -1 → EPERM.
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    struct Reshape<'a> {
        inner: &'a mut dyn TrapContext,
        args: SyscallArgs,
    }
    impl<'a> TrapContext for Reshape<'a> {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, ret: SyscallReturn) {
            self.inner.set_return(ret);
        }
        fn user_rsp(&self) -> u64 {
            self.inner.user_rsp()
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool {
            self.inner.redirect_to_kernel(rip, rsp)
        }
    }
    let proxy_args = SyscallArgs {
        arg0: (-100i64) as u64, // dirfd = AT_FDCWD.
        arg1: path_uptr,
        arg2: args.arg1,
        arg3: args.arg2,
        arg4: flags,
        arg5: 0,
    };
    let mut proxy = Reshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_fchmodat_or_fchownat(&mut proxy);
}
