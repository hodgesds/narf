#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_ioctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let cmd = args.arg1 as u32;
    let arg = args.arg2 as usize;
    let task = current_task_id();
    // Clone the Arc out of the fd table so we drop the table lock
    // before invoking the FileOps::ioctl body (which may take
    // device-internal locks of its own).
    let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone()));
    let ops = match ops {
        Some(Some(o)) => o,
        _ => {
            ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64));
            return;
        }
    };
    // FUSE_DEV_IOC_CLONE attaches this freshly opened `/dev/fuse` fd to
    // the connection named by the u32 source fd at `arg`. Linux implements
    // this in fs/fuse/dev.c because it must inspect and replace fd-private
    // state; keep the same split here rather than exposing fd tables to VFS.
    if cmd == narf_filesystem::fuse_conn::DevFuse::DEV_IOC_CLONE {
        let mut oldfd_bytes = [0u8; core::mem::size_of::<u32>()];
        // SAFETY: copy_from_user validates the user range and performs the
        // architecture's required user-access bracketing.
        if unsafe { copy_from_user(&mut oldfd_bytes, arg as u64) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        let oldfd = u32::from_ne_bytes(oldfd_bytes);
        let source = fd::with_table(task, |t| t.get(oldfd).map(|e| e.ops.clone())).flatten();
        let Some(source) = source else {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            return;
        };
        let cloned = match narf_filesystem::fuse_conn::DevFuse::clone_endpoint(&ops, &source) {
            Ok(cloned) => cloned,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
        };
        let replaced = fd::with_table(task, |t| {
            let Some(entry) = t.get_mut(fd) else {
                return false;
            };
            entry.ops = cloned;
            entry.offset = 0;
            true
        })
        .unwrap_or(false);
        ctx.set_return(SyscallReturn::ok(if replaced {
            0
        } else {
            (-(EBADF as i64)) as u64
        }));
        return;
    }
    // Wave-76 special-case: TIOCGPTPEER allocates a fresh slave fd in
    // the caller's table. The fd-allocation side lives here (not in the
    // filesystem crate), so we hijack the dispatch before delegating.
    #[cfg(feature = "linux-compat")]
    if cmd == narf_filesystem::devfs_pty::TIOCGPTPEER {
        let idx = match ops.as_pty_master_index() {
            Some(i) => i,
            None => {
                // Not a master fd — ENOTTY (Linux semantics).
                ctx.set_return(SyscallReturn::ok((-(ENOTTY as i64)) as u64));
                return;
            }
        };
        let slave = match narf_filesystem::devfs_pty::pts_open_peer(idx) {
            Some(Ok(s)) => s,
            Some(Err(())) => {
                // EIO: slave still locked.
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
            None => {
                ctx.set_return(SyscallReturn::ok((-(ENOTTY as i64)) as u64));
                return;
            }
        };
        let ops_dyn: Arc<dyn narf_filesystem::FileOps> = slave;
        let new_fd = fd::with_table(task, |t| {
            t.open(fd::FdEntry {
                ops: ops_dyn,
                offset: 0,
                // `arg` carries open(2) flags from glibc (O_RDWR | O_NOCTTY |
                // O_CLOEXEC). We mirror the CLOEXEC bit; the rest are no-ops.
                flags: if (arg as u32) & 0o2000000 != 0 { 1 } else { 0 },
                status_flags: arg as u32,
            })
        });
        match new_fd {
            Some(f) => ctx.set_return(SyscallReturn::ok(f as u64)),
            None => ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64)),
        }
        return;
    }
    // DRM_IOCTL_PRIME_HANDLE_TO_FD (_IOWR('d'=0x64, 0x2d, drm_prime_handle)):
    // export a GEM handle on a DRM card as a fresh mmap-able dma-buf fd. Like
    // TIOCGPTPEER, the fd-allocation side must live HERE (the syscall layer
    // owns the fd table); the gpu driver only supplies the buffer FileOps via
    // the registered PRIME hook. Mesa GBM's gbm_bo_get_fd relies on this to
    // CPU-mmap the kwin QPainter swapchain buffer — without it kwin logged
    // "drmPrimeHandleToFD() failed: Not a tty" and could not render.
    if (cmd & 0xFF) == 0x2d && ((cmd >> 8) & 0xFF) == 0x64 {
        if let Some(card_idx) = ops.as_drm_card_index() {
            // struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }
            let handle = read_user_u32(arg as u64);
            let dmabuf = match narf_filesystem::drm_prime_export(card_idx, handle) {
                Some(o) => o,
                None => {
                    const ENOENT: i64 = 2;
                    ctx.set_return(SyscallReturn::ok((-ENOENT) as u64));
                    return;
                }
            };
            // DRM passes DRM_CLOEXEC (0x1) / DRM_RDWR (0x2) in `flags`.
            let prime_flags = read_user_u32(arg as u64 + 4);
            let new_fd = fd::with_table(task, |t| {
                t.open(fd::FdEntry {
                    ops: dmabuf,
                    offset: 0,
                    flags: if prime_flags & 0x1 != 0 { 1 } else { 0 }, // CLOEXEC
                    status_flags: 0,
                })
            });
            match new_fd {
                Some(f) => {
                    write_user_u32(arg as u64 + 8, f); // drm_prime_handle.fd
                    ctx.set_return(SyscallReturn::ok(0));
                }
                None => ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64)),
            }
            return;
        }
    }
    // DRM_IOCTL_PRIME_FD_TO_HANDLE (_IOWR('d'=0x64, 0x2e, drm_prime_handle)):
    // re-import a PRIME dma-buf fd back to a GEM handle on this card — the
    // partner of HANDLE_TO_FD. A compositor exports its render buffer, then
    // imports it to build a scannable KMS framebuffer. Without it kwin logged
    // "drmPrimeFDToHandle() failed" → "Failed to create dumb framebuffer" →
    // "Applying output config failed!".
    if (cmd & 0xFF) == 0x2e && ((cmd >> 8) & 0xFF) == 0x64 && ops.as_drm_card_index().is_some() {
        // struct drm_prime_handle { u32 handle; u32 flags; s32 fd; }
        let dmabuf_fd = read_user_u32(arg as u64 + 8);
        let buf_ops = fd::with_table(task, |t| t.get(dmabuf_fd).map(|e| e.ops.clone())).flatten();
        match buf_ops.and_then(|o| o.as_prime_gem_handle()) {
            Some(h) => {
                write_user_u32(arg as u64, h); // drm_prime_handle.handle
                ctx.set_return(SyscallReturn::ok(0));
            }
            None => {
                const EINVAL: i64 = 22;
                ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            }
        }
        return;
    }
    // PIDFD_GET_*_NAMESPACE (_IO(0xFF, 1..=10)): mint an fd on the pidfd
    // target's namespace of the requested flavour (Linux 6.13 pidfs
    // ioctls; `fs/pidfs.c::pidfd_ioctl`). systemd 258's
    // `pidref_namespace_open_by_type()` tries this FIRST; on ENOTTY it
    // falls back to opening `/proc/<pid>/ns/<flavour>`, and when THAT
    // ENOENTs with /proc mounted it maps the miss to -ENOPKG — an errno
    // its callers treat as a hard error. Concretely: the service
    // executor's `is_idmapping_supported()` probe (setup_exec_directory,
    // RuntimeDirectory=) calls `userns_acquire()` → this ioctl; without
    // it every service with RuntimeDirectory= exits 233/RUNTIME_DIRECTORY
    // ("journald/logind/udevd failed with result 'exit-code'"). The fd
    // returned here is a real `NsFd`, so a later `setns(2)` on it works
    // (sys_setns downcasts via as_any).
    #[cfg(feature = "container")]
    if (0xff01..=0xff0a).contains(&cmd) {
        if let Some(target) = ops.pidfd_target_pid() {
            use crate::namespaces::NsFlavour;
            let flavour = match cmd & 0xFF {
                1 => Some(NsFlavour::Cgroup),
                2 => Some(NsFlavour::Ipc),
                3 => Some(NsFlavour::Mnt),
                4 => Some(NsFlavour::Net),
                // 5 = PID ns, 6 = PID-for-children: NARF tracks one
                // per-task pid-ns, serve it for both.
                5 | 6 => Some(NsFlavour::Pid),
                9 => Some(NsFlavour::User),
                10 => Some(NsFlavour::Uts),
                // 7/8 = time namespaces — not modelled; fall through to
                // the generic ENOTTY arm below (Linux pre-6.13 shape).
                _ => None,
            };
            let target_task = pid_to_task_raw(target).unwrap_or(target);
            if let Some(nsfd) = flavour.and_then(|f| {
                // Mount-ns fds are minted at the handlers layer (the
                // mount-ns table lives here, not in `namespaces`).
                if matches!(f, NsFlavour::Mnt) {
                    None
                } else {
                    crate::namespaces::ns_fd_for(target_task, f)
                }
            }) {
                let ops_dyn: Arc<dyn narf_filesystem::FileOps> = nsfd;
                // Linux mints these O_CLOEXEC (pidfs open_namespace).
                let new_fd = fd::with_table(task, |t| {
                    t.open(fd::FdEntry {
                        ops: ops_dyn,
                        offset: 0,
                        flags: crate::fd::FD_CLOEXEC,
                        status_flags: 0,
                    })
                });
                match new_fd {
                    Some(f) => ctx.set_return(SyscallReturn::ok(f as u64)),
                    None => ctx.set_return(SyscallReturn::ok((-(EBADF as i64)) as u64)),
                }
                return;
            }
        }
        // Not a pidfd / unmodelled flavour: fall through → generic
        // ENOTTY, which systemd tolerates (pre-pidfs kernel shape).
    }
    // PIDFD_GET_INFO (_IOWR(0xFF, 11, struct pidfd_info)): resolve a pidfd
    // to its target's pid/creds. systemd 258's `pidfd_get_pid()` tries this
    // ioctl FIRST (kernel 6.13+ path) after `pidfd_spawn`, to turn the
    // clone3-minted pidfd into a PidRef; on failure it falls back to parsing
    // `/proc/self/fdinfo/<n>` (which NARF doesn't render a "Pid:" line for).
    // Matched on magic+nr+direction with ANY size so binaries built against
    // older/newer uapi headers (the size is baked into the cmd) all land here.
    // Linux ref: `fs/pidfs.c::pidfd_info` + `include/uapi/linux/pidfd.h`.
    if (cmd & 0xFF) == 11 && ((cmd >> 8) & 0xFF) == 0xFF && (cmd >> 30) == 0x3 {
        if let Some(target) = ops.pidfd_target_pid() {
            let user_size = ((cmd >> 16) & 0x3FFF) as usize;
            const PIDFD_INFO_SIZE_VER0: usize = 64;
            if user_size < PIDFD_INFO_SIZE_VER0 {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            const PIDFD_INFO_PID: u64 = 1 << 0;
            const PIDFD_INFO_CREDS: u64 = 1 << 1;
            // struct pidfd_info (uapi VER2, 80 bytes): mask@0 cgroupid@8
            // pid@16 tgid@20 ppid@24 ruid@28 rgid@32 euid@36 egid@40
            // suid@44 sgid@48 fsuid@52 fsgid@56 exit_code@60
            // coredump_mask@64 coredump_signal@68 supported_mask@72.
            let mut info = [0u8; 80];
            info[0..8].copy_from_slice(&(PIDFD_INFO_PID | PIDFD_INFO_CREDS).to_ne_bytes());
            // Report pid/tgid/ppid in the CALLER's PID namespace view (the
            // process issuing the ioctl) — `target` and the parent are outer
            // ProcessIds. Identity in the root namespace.
            let caller = current_task_id();
            let pid32 = report_pid_to(caller, target) as u32;
            info[16..20].copy_from_slice(&pid32.to_ne_bytes()); // pid
            info[20..24].copy_from_slice(&pid32.to_ne_bytes()); // tgid
            let ppid = parent_of_get(target)
                .map(|p| report_pid_to(caller, task_to_pid_raw(p).unwrap_or(p)) as u32)
                .unwrap_or(0);
            info[24..28].copy_from_slice(&ppid.to_ne_bytes());
            let cred_task = pid_to_task_raw(target).unwrap_or(target);
            let ug = read_uidgid(cred_task);
            info[28..32].copy_from_slice(&ug.uid.to_ne_bytes()); // ruid
            info[32..36].copy_from_slice(&ug.gid.to_ne_bytes()); // rgid
            info[36..40].copy_from_slice(&ug.euid.to_ne_bytes()); // euid
            info[40..44].copy_from_slice(&ug.egid.to_ne_bytes()); // egid
            info[44..48].copy_from_slice(&ug.euid.to_ne_bytes()); // suid (= euid)
            info[48..52].copy_from_slice(&ug.egid.to_ne_bytes()); // sgid (= egid)
            info[52..56].copy_from_slice(&ug.fsuid.to_ne_bytes());
            info[56..60].copy_from_slice(&ug.fsgid.to_ne_bytes());
            let n = core::cmp::min(user_size, info.len());
            // SAFETY: `arg` is the user struct pointer for an _IOWR ioctl;
            // copy_to_user range-validates and SMAP-brackets the write of
            // min(user-declared size, our struct) bytes.
            // SAFETY: Valid memory or trusted environment
            if unsafe { copy_to_user(arg as u64, &info[..n]) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        // Not a pidfd: fall through — Linux returns ENOTTY via the
        // default file_operations dispatch, which the generic arm below
        // reproduces (FsError::Unsupported → ENOTTY).
    }
    match ops.ioctl(cmd, arg) {
        Ok(rc) => ctx.set_return(SyscallReturn::ok(rc)),
        Err(narf_filesystem::FsError::Unsupported) => {
            // Linux restricted FUSE ioctls derive their transfer buffers
            // solely from the command's _IOC direction and size fields.
            const IOC_WRITE: u32 = 1;
            const IOC_READ: u32 = 2;
            let dir = cmd >> 30;
            let size = ((cmd >> 16) & 0x3fff) as usize;
            let mut input = alloc::vec::Vec::new();
            if dir & IOC_WRITE != 0 && size != 0 {
                input.resize(size, 0);
                // SAFETY: the encoded ioctl input size bounds the copy and
                // copy_from_user validates the entire user range.
                if unsafe { copy_from_user(&mut input, arg as u64) }.is_err() {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                    return;
                }
            }
            let out_size = if dir & IOC_READ != 0 { size } else { 0 };
            match poll_blocking(ops.ioctl_async(cmd, arg as u64, &input, out_size)) {
                Some(Ok(reply)) => {
                    if !reply.output.is_empty() {
                        // SAFETY: output length was bounded by _IOC_SIZE in
                        // the filesystem layer; copy_to_user validates arg.
                        if unsafe { copy_to_user(arg as u64, &reply.output) }.is_err() {
                            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                            return;
                        }
                    }
                    ctx.set_return(SyscallReturn::ok((reply.result as i64) as u64));
                }
                Some(Err(narf_filesystem::FsError::Unsupported)) => {
                    ctx.set_return(SyscallReturn::ok((-(ENOTTY as i64)) as u64));
                }
                Some(Err(narf_filesystem::FsError::PermissionDenied)) => {
                    ctx.set_return(SyscallReturn::ok((-13i64) as u64));
                }
                _ => ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64)),
            }
        }
        Err(narf_filesystem::FsError::PermissionDenied) => {
            // EACCES = 13
            ctx.set_return(SyscallReturn::ok((-13i64) as u64));
        }
        Err(narf_filesystem::FsError::InvalidData) | Err(narf_filesystem::FsError::InvalidPath) => {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        }
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        }
    }
}
