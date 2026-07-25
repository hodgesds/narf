#[allow(unused_imports)]
use super::*;

/// `time(time_t*)` — get wall-clock seconds. Returns seconds since epoch;
/// if arg0 is non-null, also store it there. Returns the seconds.
pub(crate) fn sys_time(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let time_ptr = args.arg0;
    let wall = narf_scheduler::narf_time::now_wall();
    let sec = wall.secs;
    if time_ptr != 0 {
        // SAFETY: `time_ptr` is the user time_t* pointer (non-zero, checked above);
        // copy_to_user range-validates it and SMAP-brackets the 8-byte write.
        let _ = unsafe { copy_to_user(time_ptr, &sec.to_ne_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(sec as u64));
}
