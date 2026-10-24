#[allow(unused_imports)]
use super::*;

/// `readahead(fd, offset, count)` — page-cache populate hint.
///
/// `mm/readahead.c::ksys_readahead`:
///
/// ```text
///   if (fd_empty(f))                    return -EBADF;
///   if (!(file->f_mode & FMODE_READ))   return -EBADF;
///   if (!file->f_mapping->a_ops)        return -EINVAL;
///   if (!S_ISREG(..) && !S_ISBLK(..))   return -EINVAL;
/// ```
///
/// A valid call populates the shared page cache for the requested range
/// (#731, `mapped_file::populate_file_cache`) — clamped to the file size,
/// advisory, with population I/O errors unreported, exactly as
/// `force_page_cache_readahead` treats them. The population is a no-op
/// for files that cannot retain idle cache pages (no cache generation)
/// and for direct fault providers, so the validation above remains the
/// observable contract: the checks still matter, because readahead(2) is
/// documented to work only where readahead is possible, and -EINVAL on a
/// pipe or socket is how a caller learns its optimisation does not apply
/// there rather than believing it took effect.
pub(crate) fn sys_readahead(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let offset = ctx.args().arg1;
    let count = ctx.args().arg2;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    if !endpoint.readable() {
        ctx.set_return(errno_ret(EBADF));
        return;
    }
    match endpoint.ops.stat().mode.file_type {
        narf_filesystem::FileType::File | narf_filesystem::FileType::Block => {
            // Populate through the pinned file — the same object a
            // mapping of this fd faults through — so the pages land
            // under the identity later faults look up.
            let pinned = endpoint
                .ops
                .mmap_pinned_file(alloc::sync::Arc::clone(&endpoint.ops));
            crate::mapped_file::populate_file_cache(&pinned, offset, count);
            ctx.set_return(SyscallReturn::ok(0))
        }
        _ => ctx.set_return(errno_ret(EINVAL)),
    }
}
