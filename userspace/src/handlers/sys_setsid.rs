#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setsid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    // POSIX: setsid(2) makes the caller a new session leader,
    // pgid = sid = pid. Record both tables together.
    {
        let mut g = SID_TABLE.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, task);
        }
    }
    {
        let mut g = PGID_TABLE.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, task);
        }
    }
    // Wave-76: a new session leader has no controlling tty until it
    // opens a tty without O_NOCTTY (or calls TIOCSCTTY). Mark the slot
    // DETACHED (not absent) — absent means "the boot-console default", so
    // a leader that detached must be distinguishable from one that never
    // touched its ctty. The next TIOCSCTTY installs a real one.
    #[cfg(feature = "linux-compat")]
    {
        let mut g = CTTY_TABLE.lock();
        if let Some(m) = g.as_mut() {
            m.insert(task, CTTY_DETACHED);
        }
    }
    // setsid(2) returns the new session id = the caller's pid, in the
    // visible-pid space userspace sees.
    ctx.set_return(SyscallReturn::ok(pgid_to_user(task)));
}
