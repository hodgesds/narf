#[allow(unused_imports)]
use super::*;

/// `gettimeofday(timeval*, timezone*)` — get wall-clock time as
/// `{ tv_sec: i64, tv_usec: i64 }` in seconds + microseconds (not ns).
/// Converts from monotonic + wall-offset. Returns 0 on success.
pub(crate) fn sys_gettimeofday(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tv_ptr = args.arg0;
    // arg1 (timezone*) is ignored per Linux spec.
    if tv_ptr != 0 {
        // Write { tv_sec: i64, tv_usec: i64 } = 16 bytes.
        let wall = narf_scheduler::narf_time::now_wall();
        let sec = wall.secs;
        let usec = (wall.nanos / 1_000) as i64; // ns → µs (not nanoseconds!)
        let mut kbuf = [0u8; 16];
        kbuf[..8].copy_from_slice(&sec.to_ne_bytes());
        kbuf[8..].copy_from_slice(&usec.to_ne_bytes());
        // SAFETY: `tv_ptr` is the user timeval pointer (non-zero, checked above);
        // copy_to_user range-validates it and SMAP-brackets the 16-byte write.
        if unsafe { copy_to_user(tv_ptr, &kbuf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
