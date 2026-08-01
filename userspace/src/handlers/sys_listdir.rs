#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_listdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0;
    let path_len = args.arg1 as usize;
    let cursor = args.arg2 as usize;
    let out_ptr = args.arg3 as *mut u8;
    let out_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    if out_len < 8 {
        // Need room for at least the header.
        ctx.set_return(fail);
        return;
    }
    let path = match copy_user_path(path_ptr, path_len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    // Resolve to a DirOps. Empty path or root → use the FS root
    // directly; otherwise descend through `lookup_dir_async` so
    // disk-backed FSes (FAT, ext2) that only implement the async side
    // can serve subdirectory walks.
    let entries = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
                fs.root()
            } else {
                // Walk segment by segment via the async lookup so
                // disk-backed FSes (FAT, ext2) resolve correctly.
                let mut cur = fs.root();
                for seg in rel.split('/').filter(|s| !s.is_empty()) {
                    cur = poll_blocking(cur.lookup_dir_async(seg)).and_then(|r| r.ok())?;
                }
                cur
            };
            // Use enumerate_async so disk-backed FSes (FAT, ext2) that
            // return Vec::new() from the sync enumerate() still work.
            // poll_blocking drives the future to completion via the
            // same internally-polled NVMe/virtio-blk driver path that
            // sys_open and sys_read already rely on.
            poll_blocking(dir.enumerate_async(cursor, 1)).and_then(|r| r.ok())
        })
        .flatten();

    let entries = match entries {
        Some(v) => v,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if entries.is_empty() {
        // End of directory.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let (name, ftype) = &entries[0];
    let name_bytes = name.as_bytes();
    let total = 8 + name_bytes.len();
    if total > out_len {
        ctx.set_return(fail);
        return;
    }
    // Encode FileType to the wire ordinal: 0=File, 1=Dir, 2=Symlink,
    // 3=Special, 4=Socket, 5=Fifo, 6=Block. New values append so the
    // existing NARF-native wire ordinals remain stable.
    let ftype_wire: u32 = match ftype {
        narf_filesystem::FileType::File => 0,
        narf_filesystem::FileType::Dir => 1,
        narf_filesystem::FileType::Symlink => 2,
        narf_filesystem::FileType::Special => 3,
        narf_filesystem::FileType::Socket => 4,
        narf_filesystem::FileType::Fifo => 5,
        narf_filesystem::FileType::Block => 6,
    };
    // Build the 8-byte header in kernel memory, then copy the whole
    // record (header + name) into user space under the SMAP bracket.
    let mut record = alloc::vec![0u8; total];
    record[..4].copy_from_slice(&(name_bytes.len() as u32).to_ne_bytes());
    record[4..8].copy_from_slice(&ftype_wire.to_ne_bytes());
    record[8..].copy_from_slice(name_bytes);
    // SAFETY: `out_ptr` is the user dirent buffer (null-checked, `total <= out_len`);
    // copy_to_user range-validates it and SMAP-brackets the write of `record`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, &record) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
