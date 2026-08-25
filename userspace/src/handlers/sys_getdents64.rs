#[allow(unused_imports)]
use super::*;

const EBADF: i64 = 9;
const EIO: i64 = 5;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const ENOTDIR: i64 = 20;
const EINVAL: i64 = 22;

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
    match poll_blocking(dir.enumerate_async(cursor, batch_max)) {
        Some(Ok(entries)) => Ok(entries),
        Some(Err(narf_filesystem::FsError::Unsupported)) => {
            let mut entries = alloc::vec::Vec::new();
            entries.try_reserve(batch_max).map_err(|_| ENOMEM)?;
            for entry in dir.iter().skip(cursor).take(batch_max) {
                let mut name = alloc::string::String::new();
                name.try_reserve_exact(entry.name.len())
                    .map_err(|_| ENOMEM)?;
                name.push_str(entry.name);
                entries.push((name, entry.file_type));
            }
            Ok(entries)
        }
        Some(Err(error)) => Err(copy_fs_errno(error)),
        None => Err(EIO),
    }
}

/// Shared native implementation for x86_64 getdents and both architectures'
/// getdents64. Linux resolves the fd before touching the output buffer, faults
/// only when an entry is actually emitted, returns EINVAL when the first
/// pending record cannot fit, and preserves partial progress after a later
/// copy fault.
pub(super) fn sys_getdents_common(ctx: &mut dyn TrapContext, legacy: bool) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1;
    // Linux declares count as unsigned int even on 64-bit targets.
    let out_len = args.arg2 as u32 as usize;
    let task = current_task_id();

    let entry = fd::with_table(task, |table| {
        let entry = table.get(fd)?;
        Some((entry.ops.clone(), table.offset(fd)?))
    })
    .flatten();
    let Some((ops, offset)) = entry else {
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
    let snapshot = match enumerate_batch(&dir, cursor, batch_max) {
        Ok(snapshot) => snapshot,
        Err(errno) => {
            ctx.set_return(fail(errno));
            return;
        }
    };

    let mut written = 0usize;
    let mut terminal_error = None;
    let mut record = alloc::vec::Vec::new();
    for (name, ftype) in snapshot {
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
        record[..8].copy_from_slice(&(next_cursor as u64).to_ne_bytes());
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
