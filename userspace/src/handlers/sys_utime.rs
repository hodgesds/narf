#[allow(unused_imports)]
use super::*;

/// `utime(path, utimbuf*)` — x86_64 132. `utimbuf { actime, modtime }`
/// in SECONDS; NULL times = both now.
pub(crate) fn sys_utime(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let raw = match copy_user_cstr(a.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    };
    let (at, mt) = if a.arg1 == 0 {
        let now = wall_now_ns();
        (now, now)
    } else {
        let mut buf = [0u8; 16];
        // SAFETY: non-zero user utimbuf pointer; copy_from_user
        // range-validates and SMAP-brackets the 16-byte read.
        if unsafe { copy_from_user(&mut buf, a.arg1) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
        let actime = i64::from_ne_bytes(buf[..8].try_into().unwrap());
        let modtime = i64::from_ne_bytes(buf[8..].try_into().unwrap());
        (
            (actime.max(0) as u64).saturating_mul(1_000_000_000),
            (modtime.max(0) as u64).saturating_mul(1_000_000_000),
        )
    };
    let path = resolve_cwd_path(current_task_id(), &raw);
    let r = set_path_times(&path, Some(at), Some(mt));
    ctx.set_return(SyscallReturn::ok(r as u64));
}
