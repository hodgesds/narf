#[allow(unused_imports)]
use super::*;

fn current_file_exists(path: &str) -> bool {
    current_resolve_absolute(path, |fs, rel| {
        if rel.is_empty() {
            return false;
        }
        matches!(
            poll_blocking(narf_filesystem::resolve_async_nofollow(fs.root(), rel)),
            Some(Ok(_))
        )
    })
    .unwrap_or(false)
}

pub(crate) fn sys_mount(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // errno replies (negated-long convention). Every failure carries a
    // specific errno (a bare -1 would map to EPERM), matching Linux mount(2).
    let einval = SyscallReturn::ok((-22i64) as u64); // EINVAL — bad argument
    let enodev = SyscallReturn::ok((-19i64) as u64); // ENODEV — unknown fstype
    let ebusy = SyscallReturn::ok((-16i64) as u64); // EBUSY — target in use
    let enoent = SyscallReturn::ok((-2i64) as u64); // ENOENT — missing source
    let efault = SyscallReturn::ok((-14i64) as u64); // EFAULT — bad user pointer
                                                     // A copy-in failure means an unreadable user pointer → EFAULT.
    let fail = efault;

    // Linux `mount(2)`: (const char *source, const char *target,
    // const char *filesystemtype, unsigned long mountflags, const void *data).
    // All strings are NUL-terminated; there are NO explicit length args.
    //   arg0 = source, arg1 = target, arg2 = fstype, arg3 = flags, arg4 = data.
    // This handler previously used a NARF-native (ptr, len, ...) shape with
    // fstype_len/flags packed into arg5 — so a musl-built caller's Linux-ABI
    // call was mis-parsed (arg1 read as a length, etc.) and returned EPERM.
    // That silently broke every real mount: elogind's per-user tmpfs at
    // /run/user/0 failed → CreateSession failed → no logind session for kwin.
    let source = copy_user_cstr(args.arg0, 4096).unwrap_or_default();
    let target_raw = match copy_user_cstr(args.arg1, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // fstype may be NULL for MS_REMOUNT / MS_BIND / MS_MOVE.
    let fstype = if args.arg2 == 0 {
        alloc::string::String::new()
    } else {
        copy_user_cstr(args.arg2, 256).unwrap_or_default()
    };
    let flags = args.arg3;
    // arg4 = fs-specific `data` (e.g. tmpfs "mode=0700,size=64M").
    let data = if args.arg4 == 0 {
        alloc::string::String::new()
    } else {
        match copy_user_cstr(args.arg4, 4096) {
            Some(data) => data,
            None => {
                ctx.set_return(efault);
                return;
            }
        }
    };

    // Propagation-only change (MS_SLAVE/MS_SHARED/MS_PRIVATE/MS_UNBINDABLE,
    // optionally |MS_REC): change the propagation type of the mount at
    // `target` and nothing else. NARF has no propagation model, so this is a
    // no-op success. Gated to "a propagation bit is set and no fstype / bind /
    // move / remount work is requested" so a legitimate mount that also passes
    // a propagation bit still falls through to the real dispatch below. Handled
    // BEFORE bind/tmpfs/API dispatch because these calls carry a NULL source
    // and NULL fstype (see the MS_PROPAGATION comment).
    if (flags & MS_PROPAGATION) != 0 && (flags & (MS_BIND | MS_MOVE | MS_REMOUNT)) == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // systemd performs namespace assembly through O_PATH directory handles and
    // passes `/proc/self/fd/N` to mount(2). Linux follows that procfs magic
    // symlink before attaching the mount; treating it as a literal path mounts
    // over the procfs entry instead of the directory and leaves the assembled
    // namespace root absent.
    let target_path = parse_proc_self_fd(target_raw.as_str())
        .and_then(|fd| fd_path_for_task(current_task_id(), fd))
        .filter(|path| path.starts_with('/'))
        .unwrap_or(target_raw);
    // Resolve target under the calling task's chroot.
    let target = apply_chroot(target_path.as_str());
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
    let target = if target.starts_with("/proc/") {
        target
    } else {
        resolve_vfs_symlink_path(target.as_str(), true).unwrap_or(target)
    };
    let source_resolved =
        if !source_resolved.starts_with('/') || source_resolved.starts_with("/proc/") {
            source_resolved
        } else {
            resolve_vfs_symlink_path(source_resolved.as_str(), true).unwrap_or(source_resolved)
        };
    // Silence-the-warning swallow for option bits we accept but
    // don't yet act on; they're documented above.
    let _ =
        flags & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_REMOUNT | MS_REC | MS_RELATIME);

    // A bind remount changes flags on an existing mount; `source` and
    // `filesystemtype` are conventionally NULL and must not be interpreted as
    // a request to create another bind. systemd uses this after constructing
    // each service's private mount namespace. NARF does not yet persist
    // per-mount VFS flags, so validate the target and accept the flag update.
    if (flags & MS_REMOUNT) != 0 {
        let exists = current_mount_list().iter().any(|mount| mount == &target)
            || resolve_dir_absolute(target.as_str()).is_some()
            || current_file_exists(target.as_str());
        if !exists {
            ctx.set_return(enoent);
            return;
        }
        if !data.is_empty() {
            let result = current_fs_arc_at(&target).map(|fs| fs.reconfigure(&data));
            ctx.set_return(match result {
                Some(Ok(())) => SyscallReturn::ok(0),
                Some(Err(narf_filesystem::FsError::NoSpace)) => {
                    SyscallReturn::ok((-28i64) as u64)
                }
                Some(Err(_)) => einval,
                None => enoent,
            });
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Idempotent pseudo-filesystem mount. An init system mounts the API
    // filesystems (/proc, /sys, /dev, /run, ...) unconditionally at startup,
    // and NARF's Stage::Late `mnt-dev-bind` already binds procfs/sysfs/devfs
    // + tmpfs /run,/tmp into the chroot before PID 1 runs. NARF has no mount
    // stacking, so a re-mount of an already-provided pseudo-fs target reports
    // success (matching Linux, which stacks and succeeds) rather than
    // erroring. Scoped to the fstypes `mount_api::build_fs` recognizes (the
    // in-memory / synthetic filesystems) so bind / block-device mounts keep
    // their real handling (a bind onto an existing path is a distinct op).
    // The fstype→backend dispatch lives in the linux-compat-only mount_api;
    // the mount(2) syscall itself is only wired under linux-compat, so the
    // non-linux-compat build just needs this to compile (no pseudo-fs there).
    #[cfg(feature = "linux-compat")]
    let is_pseudo_fs = {
        let (uid, gid) = current_fs_ids();
        match crate::mount_api::build_fs_with_options(fstype.as_str(), data.as_str(), uid, gid) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(narf_filesystem::FsError::NoSpace) => {
                ctx.set_return(SyscallReturn::ok((-28i64) as u64));
                return;
            }
            Err(_) => {
                ctx.set_return(einval);
                return;
            }
        }
    };
    #[cfg(not(feature = "linux-compat"))]
    let is_pseudo_fs = false;
    if is_pseudo_fs && current_mount_list().iter().any(|m| m == &target) {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let auth = narf_filesystem::bootstrap_mount_authority();
    let domain = narf_lib::id::DomainId::DRIVER_0;

    if (flags & MS_MOVE) != 0 {
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
            Err(narf_filesystem::FsError::NotFound) => ctx.set_return(enoent),
            Err(narf_filesystem::FsError::Busy) => ctx.set_return(ebusy),
            Err(_) => ctx.set_return(einval),
        };
    }

    // Wave-71: MS_BIND or fstype=="bind" → bind mount. `source` is
    // an absolute path; `target` is the new path. No block device.
    if fstype == "bind" || (flags & MS_BIND) != 0 {
        let source_base = if source_resolved == "/" {
            "/"
        } else {
            source_resolved.trim_end_matches('/')
        };
        let target_base = if target == "/" {
            "/"
        } else {
            target.trim_end_matches('/')
        };
        let descendants = if flags & MS_REC != 0 && source_base != target_base {
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
        return match current_bind_mount(&auth, source_resolved.as_str(), target.as_str()) {
            Ok(_h) => {
                for (relative, fs) in descendants {
                    let child_target = if target == "/" {
                        alloc::format!("/{}", relative.trim_start_matches('/'))
                    } else {
                        alloc::format!("{}{}", target.trim_end_matches('/'), relative)
                    };
                    let _ = current_mount_arc(&auth, child_target.as_str(), fs);
                }
                ctx.set_return(SyscallReturn::ok(0));
            }
            Err(_) => ctx.set_return(SyscallReturn::ok(0)),
        };
    }

    // Pseudo / in-memory filesystems: tmpfs, proc, sysfs, devtmpfs, cgroup2,
    // devpts, mqueue, securityfs, debugfs, … The shared dispatch
    // (mount_api::build_fs) returns a real backend where NARF has one
    // (proc/sysfs/cgroup2 are global singletons whose content attaches at the
    // caller's target, e.g. a chroot's /proc or /sys/fs/cgroup) and a minimal
    // empty directory for the rest; only a genuinely unknown fstype returns
    // None. This is the same dispatch the new mount API (fsopen → fsconfig)
    // uses, so both entry points recognize identical filesystems. Block-device
    // fstypes (fat/vfat/ext…) fall through below because build_fs can't
    // synthesize them without a device.
    #[cfg(feature = "linux-compat")]
    {
        let (mount_uid, mount_gid) = current_fs_ids();
        match crate::mount_api::build_fs_with_options(
            fstype.as_str(),
            data.as_str(),
            mount_uid,
            mount_gid,
        ) {
            Ok(Some(fs)) => {
                return match current_mount_arc(&auth, target.as_str(), fs) {
                    Ok(_) | Err(_) => ctx.set_return(SyscallReturn::ok(0)),
                };
            }
            Err(narf_filesystem::FsError::NoSpace) => {
                ctx.set_return(SyscallReturn::ok((-28i64) as u64));
                return;
            }
            Err(_) => {
                ctx.set_return(einval);
                return;
            }
            Ok(None) => {}
        }
    }

    // overlayfs (union mount). Linux passes the layer paths in the mount(2)
    // `data` string (lowerdir=/a:/b,upperdir=/u,workdir=/w). NARF's mount ABI
    // has no register left for a `data` pointer, so the options string is
    // accepted via `source` instead (the conventional overlay source is the
    // information-free literal "overlay"). `workdir` is parsed but ignored —
    // copy-up/whiteout ops act directly on the upper dir.
    if fstype == "overlay" || fstype == "overlayfs" {
        let opts = source.as_str();
        let mut lowerdirs: alloc::vec::Vec<&str> = alloc::vec::Vec::new();
        let mut upperdir: Option<&str> = None;
        for kv in opts.split(',') {
            let kv = kv.trim();
            if let Some(v) = kv.strip_prefix("lowerdir=") {
                // Colon-separated, highest-priority first (Linux order).
                lowerdirs = v.split(':').filter(|s| !s.is_empty()).collect();
            } else if let Some(v) = kv.strip_prefix("upperdir=") {
                upperdir = Some(v);
            } else if kv.starts_with("workdir=") {
                // Accepted-and-ignored (documented above).
            }
        }
        let upper_path = match upperdir {
            Some(p) => apply_chroot(p),
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let upper = match resolve_dir_absolute(upper_path.as_str()) {
            Some(d) => d,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let mut lowers: alloc::vec::Vec<alloc::sync::Arc<dyn narf_filesystem::DirOps>> =
            alloc::vec::Vec::new();
        for lp in &lowerdirs {
            let abs = apply_chroot(lp);
            match resolve_dir_absolute(abs.as_str()) {
                Some(d) => lowers.push(d),
                None => {
                    ctx.set_return(fail);
                    return;
                }
            }
        }
        let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> =
            alloc::sync::Arc::new(narf_filesystem::OverlayFs::new("overlay", upper, lowers));
        return match current_mount_arc(&auth, target.as_str(), fs) {
            Ok(_h) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(fail),
        };
    }

    // FUSE mounts: `fstype == "fuse"` or `"fuse.<subtype>"`. Options carry
    // `fd=N` naming the open `/dev/fuse` connection (passed via `source`
    // since NARF's mount ABI has no `data` register). Parse fd, recover the
    // connection, build a FuseFs, drive FUSE_INIT. Linux: fuse_fill_super.
    if fstype == "fuse" || fstype.starts_with("fuse.") {
        let fd_opt = source
            .split(',')
            .find_map(|kv| kv.strip_prefix("fd="))
            .and_then(|v| v.trim().parse::<u32>().ok());
        let fd = match fd_opt {
            Some(fd) => fd,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        let task = current_task_id();
        let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone()));
        let conn = match ops {
            Some(Some(o)) => match narf_filesystem::fuse_conn::DevFuse::connection_of(&o) {
                Some(c) => c,
                None => {
                    ctx.set_return(fail);
                    return;
                }
            },
            _ => {
                ctx.set_return(fail);
                return;
            }
        };
        let subtype = fstype.strip_prefix("fuse.").unwrap_or("fuse");
        let fs = alloc::sync::Arc::new(narf_filesystem::fuse_conn::FuseFs::new(subtype, conn));
        // A mount is not usable until FUSE_INIT has negotiated a compatible
        // protocol. Do not publish a half-initialized filesystem when the
        // daemon rejects INIT, sends a malformed reply, disconnects, or never
        // replies before the bounded synchronous bridge expires.
        if !matches!(poll_blocking(fs.init()), Some(Ok(_))) {
            ctx.set_return(fail);
            return;
        }
        let fs_dyn: alloc::sync::Arc<dyn narf_filesystem::FsInstance> = fs;
        return match current_mount_arc(&auth, target.as_str(), fs_dyn) {
            Ok(_h) => ctx.set_return(SyscallReturn::ok(0)),
            Err(_) => ctx.set_return(fail),
        };
    }

    // Extensibility fallback: an out-of-tree crate may have registered a
    // constructor for this fstype via `register_fstype`. Built-in arms above
    // keep priority; consulted only for otherwise-unknown types, before the
    // block-device fallthrough. Options are passed via source/data.
    if let Some(builder) = narf_filesystem::lookup_fstype(fstype.as_str()) {
        return match builder(source_resolved.as_str(), source_resolved.as_str()) {
            Ok(fs) => match current_mount_arc(&auth, target.as_str(), fs) {
                Ok(_h) => ctx.set_return(SyscallReturn::ok(0)),
                Err(_) => ctx.set_return(fail),
            },
            Err(_) => ctx.set_return(fail),
        };
    }

    // Block-device-backed mounts: resolve `source` as a registered
    // block-device name. Strip a leading "/dev/" so callers can
    // pass either form.
    let dev_name = source.strip_prefix("/dev/").unwrap_or(source.as_str());
    let entry = match narf_block::block_devices()
        .into_iter()
        .find(|e| e.name == dev_name)
    {
        Some(e) => e,
        None => {
            // No backend, no register_fstype builder, and no such device: a
            // known block fstype with a missing device is ENOENT; a genuinely
            // unknown fstype is ENODEV (matching Linux, never a bare -1).
            match fstype.as_str() {
                "fat" | "vfat" | "fat16" | "fat32" | "ext2" | "ext3" | "ext4" | "xfs" | "btrfs"
                | "iso9660" | "9p" | "virtiofs" => ctx.set_return(enoent),
                _ => ctx.set_return(enodev),
            }
            return;
        }
    };

    let result = match fstype.as_str() {
        "fat" | "vfat" | "fat16" | "fat32" => {
            let dev = narf_block::SyncBlock::new(entry.dev.clone());
            let fut = narf_drivers_fs_fat::mount_fat(&auth, target.as_str(), dev, domain);
            poll_blocking(fut)
        }
        _ => {
            // A registered device but an unrecognized fstype for it.
            ctx.set_return(enodev);
            return;
        }
    };

    match result {
        Some(Ok(_handle)) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(einval),
    }
}
