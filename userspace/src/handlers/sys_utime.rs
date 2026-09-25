#[allow(unused_imports)]
use super::*;

/// `utime(path, utimbuf*)` — x86_64 132. `utimbuf { actime, modtime }`
/// in SECONDS; NULL times = both now.
///
/// ```text
/// if (times) { if (get_user(tv[0].tv_sec, &times->actime) ||
///                  get_user(tv[1].tv_sec, &times->modtime)) return -EFAULT; ... }
/// return do_utimes(AT_FDCWD, filename, times ? tv : NULL, 0);
/// ```
///
/// The buffer is read BEFORE the path, so a bad `utimbuf` is EFAULT even
/// when the path is also bad.
pub(crate) fn sys_utime(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let times = if a.arg1 == 0 {
        None
    } else {
        let mut buf = [0u8; 16];
        // SAFETY: non-zero user utimbuf pointer; copy_from_user
        // range-validates and SMAP-brackets the 16-byte read.
        if unsafe { copy_from_user(&mut buf, a.arg1) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let actime = i64::from_ne_bytes(buf[..8].try_into().unwrap());
        let modtime = i64::from_ne_bytes(buf[8..].try_into().unwrap());
        Some([(actime, 0), (modtime, 0)])
    };
    do_utimes(ctx, -100, a.arg0, times, 0);
}
