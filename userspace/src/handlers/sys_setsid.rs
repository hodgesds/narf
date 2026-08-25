#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setsid(ctx: &mut dyn TrapContext) {
    let task = process_state_key(current_task_id());
    // Linux rejects a process-group leader, including a caller whose proposed
    // session id already names any existing process group. Validate while
    // holding the group table so a concurrent setpgid cannot race the check.
    let mut pgids = PGID_TABLE.lock();
    let pgid_rows = pgids.get_or_insert_with(BTreeMap::new);
    let current_pgid = pgid_rows.get(&task).copied().unwrap_or(task);
    if current_pgid == task || pgid_rows.values().any(|&pgid| pgid == task) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }

    // Publish SID, PGID and detached controlling-tty state as one serialized
    // process transition. The fixed lock order is PGID -> SID -> CTTY.
    let mut sids = SID_TABLE.lock();
    let sid_rows = sids.get_or_insert_with(BTreeMap::new);
    #[cfg(feature = "linux-compat")]
    let mut cttys = CTTY_TABLE.lock();

    pgid_rows.insert(task, task);
    sid_rows.insert(task, task);
    // Wave-76: a new session leader has no controlling tty until it
    // opens a tty without O_NOCTTY (or calls TIOCSCTTY). Mark the slot
    // DETACHED (not absent) — absent means "the boot-console default", so
    // a leader that detached must be distinguishable from one that never
    // touched its ctty. The next TIOCSCTTY installs a real one.
    #[cfg(feature = "linux-compat")]
    {
        cttys
            .get_or_insert_with(BTreeMap::new)
            .insert(task, CTTY_DETACHED);
    }
    // setsid(2) returns the new session id = the caller's pid, in the
    // visible-pid space userspace sees.
    ctx.set_return(SyscallReturn::ok(pgid_to_user(task)));
}
