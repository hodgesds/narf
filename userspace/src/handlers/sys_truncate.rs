#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_truncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: truncate(const char *path, off_t length). arg0 = NUL-terminated
    // path, arg1 = new length. (Was NARF-native (path_ptr, path_len, size).)
    let ptr = args.arg0;
    let new_size = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let ops = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    match ops {
        Some(o) => match poll_blocking(o.truncate(new_size)) {
            Some(Ok(())) => {
                // inotify: truncate changes file content → IN_MODIFY.
                #[cfg(feature = "linux-compat")]
                crate::mqueue::notify_modify_path(&path);
                ctx.set_return(SyscallReturn::ok(0))
            }
            _ => ctx.set_return(fail),
        },
        None => ctx.set_return(fail),
    }
}
