#[allow(unused_imports)]
use super::*;


#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

#[inline]
fn dirent_type(ftype: narf_filesystem::FileType) -> u8 {
    match ftype {
        narf_filesystem::FileType::File => 8,
        narf_filesystem::FileType::Dir => 4,
        narf_filesystem::FileType::Symlink => 10,
        narf_filesystem::FileType::Special => 2,
        narf_filesystem::FileType::Block => 6,
        narf_filesystem::FileType::Socket => 12,
        narf_filesystem::FileType::Fifo => 1,
    }
}

fn enumerate_batch(
    dir: &alloc::sync::Arc<dyn narf_filesystem::DirOps>,
    cursor: usize,
    batch_max: usize,
) -> Result<alloc::vec::Vec<(alloc::string::String, narf_filesystem::FileType)>, i64> {
    // `iterate_dir` takes the directory with `down_read_killable`.
    let batch = match crate::killable_wait::enumerate(dir, cursor, batch_max) {
        Ok(batch) => batch,
        Err(crate::killable_wait::Killed) => return Err(EINTR),
    };
    match batch {
        Some(Ok(entries)) => Ok(entries),
        Some(Err(narf_filesystem::FsError::Unsupported)) => {
            let mut entries = alloc::vec::Vec::new();
            entries.try_reserve(batch_max).map_err(|_| ENOMEM)?;
            for entry in dir.iter().skip(cursor).take(batch_max) {
                let mut name = alloc::string::String::new();
                name.try_reserve_exact(entry.name.len())
                    .map_err(|_| ENOMEM)?;
                name.push_str(&entry.name);
                entries.push((name, entry.file_type));
            }
            Ok(entries)
        }
        Some(Err(error)) => Err(copy_fs_errno(error)),
        None => Err(EIO),
    }
}

/// Directory positions `dir_emit_dots` gives `.` and `..`; the filesystem's
/// own entries start after them.
const DOT_ENTRIES: usize = 2;

/// `d_ino` of `.` and `..` for the directory open as `ops`, opened on the
/// host path `path` (`None` for a directory reached without one).
///
/// `dir_emit_dots` reports `file_inode(file)->i_ino` for `.` and
/// `parent_ino(dentry)` — the inode of `d_parent` — for `..`. A filesystem
/// root's dentry is its own parent, so at a mount of a filesystem's root `..`
/// is the directory itself; at a bind of a subdirectory it is the directory
/// above that in the filesystem (`FsInstance::root_parent_ino`); anywhere
/// else it is the directory above it, which is in the same filesystem. Filesystems whose on-disk format holds the two
/// entries (ext2, a FAT subdirectory) report the same numbers. A directory
/// with no inode number of its own keeps the position placeholder the other
/// records use, so `d_ino` is never the 0 glibc's readdir skips.
fn dot_inos(
    ops: &alloc::sync::Arc<dyn narf_filesystem::FileOps>,
    path: Option<&str>,
) -> (u64, u64) {
    let own = match ops.ino() {
        0 => 1,
        ino => ino,
    };
    let parent = path.and_then(|path| {
        let mount_root = current_covering_mount_info(path).is_some_and(|(mount, _)| mount == path);
        if path == "/" || mount_root {
            // A mount root's parent is inside its filesystem: none for the
            // filesystem's own root, the bound directory's parent for a bind.
            let fs = current_fs_arc_at(path)?;
            return poll_blocking(fs.root_parent_ino()).and_then(Result::ok);
        }
        let parent = match path.trim_end_matches('/').rsplit_once('/') {
            Some(("", _)) => "/",
            Some((parent, _)) => parent,
            None => return None,
        };
        stat_ino_path_dir_aware(parent).ok().map(|stat| stat.1)
    });
    (own, parent.filter(|ino| *ino != 0).unwrap_or(own))
}

/// Shared native implementation for x86_64 getdents and both architectures'
/// getdents64. Linux resolves the fd before touching the output buffer, faults
/// only when an entry is actually emitted, returns EINVAL when the first
/// pending record cannot fit, and preserves partial progress after a later
/// copy fault.
///
/// Every directory starts with `.` and `..` at positions 0 and 1, as
/// `dir_emit_dots` emits them for dcache_readdir, btrfs, procfs, kernfs and
/// the FAT root, and as ext2 and FAT subdirectories hold them on disk. They
/// are produced here, once for every filesystem; the filesystem's entries
/// follow at position 2 onwards, and any `.` or `..` a filesystem lists
/// itself is passed over so it is never reported twice.
pub(super) fn sys_getdents_common(ctx: &mut dyn TrapContext, legacy: bool) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1;
    // Linux declares count as unsigned int even on 64-bit targets.
    let out_len = args.arg2 as u32 as usize;
    let task = current_task_id();

    // `CLASS(fd_pos, f)(fd)` is `fdget`, which masks out FMODE_PATH: an
    // O_PATH descriptor is "not open" here and is -EBADF, even on a
    // directory (6.18: getdents64 on `open(dir, O_PATH)` → EBADF). NARF
    // wraps an O_PATH directory in `DirFdFile` for *at anchoring, so the
    // status flag has to be consulted explicitly or it enumerated.
    let entry = fd::with_table(task, |table| {
        let entry = table.get(fd)?;
        if table
            .status_flags(fd)
            .is_some_and(|status| status & crate::fd::O_PATH != 0)
        {
            return None;
        }
        let name = table
            .description(fd)
            .and_then(|description| description.name())
            .filter(|name| !name.deleted);
        Some((entry.ops.clone(), table.offset(fd)?, name))
    })
    .flatten();
    let Some((ops, offset, name)) = entry else {
        ctx.set_return(fail(EBADF));
        return;
    };
    let Some(dir) = ops.as_dir() else {
        ctx.set_return(fail(ENOTDIR));
        return;
    };
    let mut cursor = offset as usize;

    // One look-ahead entry distinguishes EOF from a first record that cannot
    // fit. The cap bounds kernel allocation for arbitrarily large user buffers
    // while retaining O(N) traversal across normal directory scans.
    const SNAPSHOT_ENTRY_CAP: usize = 4096;
    const MINIMUM_RECORD: usize = 24;
    let batch_max = (out_len / MINIMUM_RECORD)
        .saturating_add(1)
        .clamp(1, SNAPSHOT_ENTRY_CAP);
    // Room for a `.` and `..` the filesystem lists itself, which are passed
    // over below, so they never stand in for an entry that would fit.
    let fs_batch = batch_max.saturating_add(DOT_ENTRIES);
    let snapshot = match enumerate_batch(&dir, cursor.saturating_sub(DOT_ENTRIES), fs_batch) {
        Ok(snapshot) => snapshot,
        Err(errno) => {
            ctx.set_return(fail(errno));
            return;
        }
    };
    let dots: &[&str] = match cursor {
        0 => &[".", ".."],
        1 => &[".."],
        _ => &[],
    };
    let (dot_ino, dotdot_ino) = if dots.is_empty() {
        (0, 0)
    } else {
        dot_inos(&ops, name.as_ref().map(|name| &*name.path))
    };
    let mut pending = alloc::vec::Vec::new();
    if pending.try_reserve_exact(dots.len() + snapshot.len()).is_err() {
        ctx.set_return(fail(ENOMEM));
        return;
    }
    for dot in dots {
        pending.push((
            alloc::string::String::from(*dot),
            narf_filesystem::FileType::Dir,
            true,
        ));
    }
    for (name, ftype) in snapshot {
        pending.push((name, ftype, false));
    }

    let mut written = 0usize;
    let mut terminal_error = None;
    let mut record = alloc::vec::Vec::new();
    for (name, ftype, is_dot) in pending {
        if !is_dot && (name == "." || name == "..") {
            // Emitted above, at positions 0 and 1.
            cursor = cursor.saturating_add(1);
            continue;
        }
        let name = name.as_bytes();
        // Linux verify_dirent_name(): an empty, slash-containing, or
        // PATH_MAX-sized component indicates a corrupt filesystem record.
        if name.is_empty() || name.len() >= 4096 || name.contains(&b'/') {
            terminal_error = Some(EIO);
            break;
        }
        let fixed = if legacy { 18usize } else { 19usize };
        let extra = if legacy { 2usize } else { 1usize };
        let Some(raw_len) = fixed
            .checked_add(name.len())
            .and_then(|n| n.checked_add(extra))
        else {
            terminal_error = Some(EINVAL);
            break;
        };
        let Some(reclen) = raw_len.checked_add(7).map(|n| n & !7) else {
            terminal_error = Some(EINVAL);
            break;
        };
        if reclen > u16::MAX as usize {
            terminal_error = Some(EINVAL);
            break;
        }
        if reclen > out_len.saturating_sub(written) {
            terminal_error = (written == 0).then_some(EINVAL);
            break;
        }

        let next_cursor = cursor.saturating_add(1);
        record.clear();
        if record.try_reserve_exact(reclen).is_err() {
            terminal_error = Some(ENOMEM);
            break;
        }
        record.resize(reclen, 0);
        // `filldir64`: `d_ino` is the entry's inode number. A directory that
        // cannot name it without a lookup keeps the cursor placeholder.
        let d_ino = match (is_dot, name) {
            (true, b".") => dot_ino,
            (true, _) => dotdot_ino,
            (false, _) => core::str::from_utf8(name)
                .ok()
                .and_then(|name| dir.entry_ino(name))
                .unwrap_or(next_cursor as u64),
        };
        record[..8].copy_from_slice(&d_ino.to_ne_bytes());
        record[8..16].copy_from_slice(&(next_cursor as u64).to_ne_bytes());
        record[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        if legacy {
            record[18..18 + name.len()].copy_from_slice(name);
            record[reclen - 1] = dirent_type(ftype);
        } else {
            record[18] = dirent_type(ftype);
            record[19..19 + name.len()].copy_from_slice(name);
        }

        let Some(dest) = out_ptr.checked_add(written as u64) else {
            terminal_error = Some(EFAULT);
            break;
        };
        // SAFETY: copy_to_user validates the complete destination record and
        // performs the architecture's guarded user copy.
        if unsafe { copy_to_user(dest, &record) }.is_err() {
            terminal_error = Some(EFAULT);
            break;
        }
        written += reclen;
        cursor = next_cursor;
    }

    if written != 0 {
        fd::with_table(task, |table| table.set_offset(fd, cursor as u64));
        ctx.set_return(SyscallReturn::ok(written as u64));
    } else if let Some(errno) = terminal_error {
        ctx.set_return(fail(errno));
    } else {
        ctx.set_return(SyscallReturn::ok(0));
    }
}

pub(crate) fn sys_getdents64(ctx: &mut dyn TrapContext) {
    sys_getdents_common(ctx, false);
}
