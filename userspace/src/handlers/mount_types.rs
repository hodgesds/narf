//! Filesystems that require the calling task's namespace or descriptor table.
use super::*;
use narf_filesystem::{FileSystemType, FsError, FsInstance, MountRequest};
use narf_lib::sync::Once;

/// Composition point for the Linux ABI's linked filesystem drivers. No
/// constructor runs here, so fsopen can query support without side effects.
pub(crate) fn register_mount_types() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        narf_drivers_fs_fat::register_fstypes();
        narf_drivers_fs_ext2::register_fstypes();
        narf_drivers_fs_btrfs::register_fstypes();
        narf_drivers_fs_squashfs::register_fstypes();
        narf_drivers_fs_exfat::register_fstypes();
        narf_drivers_fs_minix::register_fstypes();
        narf_drivers_fs_iso9660::register_fstypes();
        narf_drivers_fs_udf::register_fstypes();
        narf_filesystem::register_fs_type(FileSystemType::new("overlay", build_overlay));
        narf_filesystem::register_fs_type(FileSystemType::new("overlayfs", build_overlay));
        let mut fuse = FileSystemType::new("fuse", build_fuse);
        fuse.subtypes = true;
        narf_filesystem::register_fs_type(fuse);
        narf_filesystem::register_fs_type(FileSystemType::new("mqueue", |_| {
            Ok(crate::mqueue::mount_current_namespace())
        }));
    });
}

/// Split legacy overlayfs `lowerdir=` values. Linux treats an unescaped colon
/// as a layer separator and permits `\:` and `\\` in pathnames.
fn parse_overlay_lowerdirs(value: &str) -> Option<alloc::vec::Vec<alloc::string::String>> {
    let mut layers = alloc::vec::Vec::new();
    let mut layer = alloc::string::String::new();
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            layer.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ':' {
            if layer.is_empty() {
                return None;
            }
            layers.push(core::mem::take(&mut layer));
        } else {
            layer.push(ch);
        }
    }
    if escaped || layer.is_empty() {
        return None;
    }
    layers.push(layer);
    Some(layers)
}

fn build_overlay(r: &MountRequest<'_>) -> Result<Arc<dyn FsInstance>, FsError> {
    let opts = if r.options.is_empty() {
        r.source
    } else {
        r.options
    };
    let mut lowerdirs: Option<alloc::vec::Vec<alloc::string::String>> = None;
    let mut upperdir: Option<&str> = None;
    let mut workdir: Option<&str> = None;
    let mut valid_options = true;
    for kv in opts.split(',') {
        let kv = kv.trim();
        if let Some(v) = kv.strip_prefix("lowerdir=") {
            // Colon-separated, highest-priority first (Linux order).
            if lowerdirs.is_some() {
                valid_options = false;
                break;
            }
            lowerdirs = parse_overlay_lowerdirs(v);
            if lowerdirs.is_none() {
                valid_options = false;
                break;
            }
        } else if let Some(v) = kv.strip_prefix("upperdir=") {
            if upperdir.is_some() || v.is_empty() {
                valid_options = false;
                break;
            }
            upperdir = Some(v);
        } else if let Some(v) = kv.strip_prefix("workdir=") {
            if workdir.is_some() || v.is_empty() {
                valid_options = false;
                break;
            }
            workdir = Some(v);
        } else if !kv.is_empty() {
            // Do not silently claim support for overlay features whose
            // persistence/security semantics NARF does not implement.
            valid_options = false;
            break;
        }
    }
    let lowerdirs = match (valid_options, lowerdirs) {
        (true, Some(layers)) if !layers.is_empty() => layers,
        _ => {
            return Err(FsError::InvalidData);
        }
    };
    if upperdir.is_some() != workdir.is_some() {
        return Err(FsError::InvalidData);
    }

    let mut lowers: alloc::vec::Vec<alloc::sync::Arc<dyn narf_filesystem::DirOps>> =
        alloc::vec::Vec::new();
    let mut resolved_lower_paths = alloc::vec::Vec::new();
    for lp in &lowerdirs {
        let abs = apply_chroot(lp.as_str());
        match resolve_dir_absolute(abs.as_str()) {
            Some(d) => {
                resolved_lower_paths.push(abs);
                lowers.push(d);
            }
            None => {
                return Err(FsError::NotFound);
            }
        }
    }
    let fs: alloc::sync::Arc<dyn narf_filesystem::FsInstance> = match (upperdir, workdir) {
        (Some(upper_path), Some(work_path)) => {
            let upper_path = apply_chroot(upper_path);
            let work_path = apply_chroot(work_path);
            // Linux requires separate work/upper subtrees. NARF does not
            // yet expose a filesystem identity through DirOps, so the
            // stronger same-superblock check remains an audited gap.
            if upper_path == work_path
                || resolved_lower_paths
                    .iter()
                    .any(|lower| lower == &upper_path || lower == &work_path)
            {
                return Err(FsError::InvalidData);
            }
            let upper = match resolve_dir_absolute(upper_path.as_str()) {
                Some(dir) => dir,
                None => {
                    return Err(FsError::NotFound);
                }
            };
            let work = match resolve_dir_absolute(work_path.as_str()) {
                Some(dir) => dir,
                None => {
                    return Err(FsError::NotFound);
                }
            };
            if !work.enumerate(0, 1).is_empty() {
                return Err(FsError::InvalidData);
            }
            alloc::sync::Arc::new(narf_filesystem::OverlayFs::new("overlay", upper, lowers))
        }
        (None, None) => {
            alloc::sync::Arc::new(narf_filesystem::OverlayFs::new_read_only("overlay", lowers))
        }
        _ => unreachable!(),
    };
    Ok(fs)
}

fn build_fuse(r: &MountRequest<'_>) -> Result<Arc<dyn FsInstance>, FsError> {
    let fd_opt = r
        .options
        .split(',')
        .find_map(|kv| kv.trim().strip_prefix("fd="))
        .and_then(|v| v.trim().parse::<u32>().ok());
    let fd = match fd_opt {
        Some(fd) => fd,
        None => {
            return Err(FsError::InvalidData);
        }
    };
    let task = current_task_id();
    let ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone()));
    let conn = match ops {
        Some(Some(o)) => match narf_filesystem::fuse_conn::DevFuse::connection_of(&o) {
            Some(c) => c,
            None => {
                return Err(FsError::InvalidData);
            }
        },
        _ => {
            return Err(FsError::InvalidData);
        }
    };
    let subtype = r.fs_type.strip_prefix("fuse.").unwrap_or("fuse");
    let fs = alloc::sync::Arc::new(narf_filesystem::fuse_conn::FuseFs::new(subtype, conn));
    // FUSE_INIT is driven in the BACKGROUND, and the mount is published
    // without waiting for it — this is what Linux does.
    // `fuse_fill_super` calls `fuse_send_init()`, which submits INIT via
    // `fuse_simple_background()` and returns; `process_init_reply()`
    // later sets `fc->initialized` from the reply callback
    // (`fs/fuse/inode.c`).
    //
    // Awaiting INIT inline here deadlocked every real mount. The only
    // process that can answer FUSE_INIT is the daemon, and a daemon
    // that issues mount(2) from the same thread it services /dev/fuse
    // on — which libfuse's `fuse_mount` does — is sitting inside THIS
    // syscall. Nobody reads the request, the bounded synchronous bridge
    // expires, and the mount fails: xdg-document-portal's
    // "fuse init failed: Can't mount path /run/narf-plasma/doc" on
    // every Fedora Plasma boot, after which it span on the descriptors
    // it had staged for the mount and burned a core through session
    // startup.
    //
    // `init()`'s own doc says it must be awaited CONCURRENTLY with the
    // daemon; a spawned task is what makes that true. INIT is enqueued
    // ahead of any later request, so the daemon still negotiates before
    // it serves traffic, and a failed negotiation leaves the connection
    // uninitialized exactly as an aborted Linux connection would.
    let init_fs = alloc::sync::Arc::clone(&fs);
    narf_scheduler::spawn(async move {
        let _ = init_fs.init().await;
    });
    let fs_dyn: alloc::sync::Arc<dyn narf_filesystem::FsInstance> = fs;
    Ok(fs_dyn)
}
