#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getdents64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut u8;
    let out_len = args.arg2 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if out_ptr.is_null() || out_len < 32 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();

    // EBADF: the fd isn't open at all (distinct from "open but not a dir").
    if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    // Pull the DirOps + current cursor off the fd. `as_dir()` is `Some`
    // only for a DirFdFile (an opened directory); the fd exists (checked
    // above) so a `None` here means it's a non-directory → -ENOTDIR.
    // The fd-table lock is released before we touch the FS
    // (enumerate_async), per the no-reentrancy rule.
    let dir_and_cursor = fd::with_table(task, |t| {
        t.get(fd)
            .and_then(|e| e.ops.as_dir().map(|d| (d, e.offset as usize)))
    })
    .flatten();
    let (dir, mut cursor) = match dir_and_cursor {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::ok((-20i64) as u64)); // -ENOTDIR
            return;
        }
    };

    let mut written = 0usize;
    // iter()-only DirOps — the procfs trees (/proc root, /proc/<pid>,
    // fd/, task/, ns/) — keep the Unsupported default for
    // enumerate_async. Bridge them through the sync iterator, or ps/
    // top/ls see an EMPTY /proc (opens worked, listing didn't: the
    // alpine-probe "no process info in /proc" failure). Snapshot the
    // remainder ONCE per getdents call: iter() rebuilds (and, for
    // ProcRoot, Box::leaks names on) every invocation, so a per-entry
    // re-iter would cost O(entries²) and multiply that leak by the
    // directory size on every ps/top refresh.
    let mut iter_snapshot: Option<
        alloc::vec::Vec<(alloc::string::String, narf_filesystem::FileType)>,
    > = None;
    let mut snapshot_pos = 0usize;
    loop {
        let batch: Option<alloc::vec::Vec<(alloc::string::String, narf_filesystem::FileType)>> =
            if let Some(snap) = iter_snapshot.as_ref() {
                let e = snap.get(snapshot_pos).cloned();
                snapshot_pos += 1;
                Some(e.into_iter().collect())
            } else {
                match poll_blocking(dir.enumerate_async(cursor, 1)) {
                    Some(Ok(v)) => Some(v),
                    Some(Err(narf_filesystem::FsError::Unsupported)) => {
                        let snap: alloc::vec::Vec<_> = dir
                            .iter()
                            .skip(cursor)
                            .map(|e| (alloc::string::String::from(e.name), e.file_type))
                            .collect();
                        let first = snap.first().cloned();
                        iter_snapshot = Some(snap);
                        snapshot_pos = 1;
                        Some(first.into_iter().collect())
                    }
                    _ => None,
                }
            };
        let mut entries = match batch {
            Some(v) if !v.is_empty() => v,
            _ => break,
        };
        let (name, ftype) = entries.pop().unwrap();
        let name_bytes = name.as_bytes();
        // 19-byte fixed header + name + NUL, padded up to 8 bytes.
        let raw_len = 19 + name_bytes.len() + 1;
        let reclen = (raw_len + 7) & !7;
        if written + reclen > out_len {
            // Record won't fit — stop here without advancing the
            // cursor for this entry. Linux returns whatever fit.
            break;
        }
        let next_cursor = cursor + 1;
        let dt = match ftype {
            narf_filesystem::FileType::File => 8,     // DT_REG
            narf_filesystem::FileType::Dir => 4,      // DT_DIR
            narf_filesystem::FileType::Symlink => 10, // DT_LNK
            narf_filesystem::FileType::Special => 2,  // DT_CHR
            narf_filesystem::FileType::Block => 6,    // DT_BLK
            narf_filesystem::FileType::Socket => 12,  // DT_SOCK
            narf_filesystem::FileType::Fifo => 1,     // DT_FIFO
        };
        // Build the dirent record in kernel memory, then copy it into
        // user space under the SMAP bracket.
        let mut rec = alloc::vec![0u8; reclen];
        rec[..8].copy_from_slice(&(next_cursor as u64).to_ne_bytes()); // d_ino
        rec[8..16].copy_from_slice(&(next_cursor as u64).to_ne_bytes()); // d_off
        rec[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes()); // d_reclen
        rec[18] = dt; // d_type
        rec[19..19 + name_bytes.len()].copy_from_slice(name_bytes); // d_name
                                                                    // NUL terminator + zero-padding through end already zeroed by vec init.
                                                                    // SAFETY: `out_ptr` is the user buffer base; `written < out_len` so the
                                                                    // offset stays inside the user-supplied region. Forms a user vaddr only.
                                                                    // SAFETY: Valid memory or trusted environment
        let dest = unsafe { out_ptr.add(written) } as u64;
        // SAFETY: `dest` is in-bounds of the user buffer (checked above); copy_to_user
        // range-validates it and SMAP-brackets the write of the `reclen`-byte `rec`.
        // SAFETY: Valid memory or trusted environment
        if unsafe { copy_to_user(dest, &rec) }.is_err() {
            break;
        }
        written += reclen;
        cursor = next_cursor;
    }

    // Persist the advanced cursor so the next getdents64 on this fd
    // resumes where we stopped (mid-directory if the buffer filled).
    fd::with_table(task, |t| {
        if let Some(e) = t.get_mut(fd) {
            e.offset = cursor as u64;
        }
    });

    ctx.set_return(SyscallReturn::ok(written as u64));
}
