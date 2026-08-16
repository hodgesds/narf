#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_exit_group(ctx: &mut dyn TrapContext) {
    let tid = current_task_id();
    let pid = task_to_pid_raw(tid).unwrap_or(tid);
    // [PROBE] A `systemd --user` instance (comm "systemd", not PID1) or one of
    // its "(sd-*)" helper forks that voluntarily exit_group()s during session
    // bring-up dies SILENTLY on the console (its log goes to the user journal),
    // so `user@N.service` flapping has no visible reason. Capture the exit code
    // HERE — comm is still live and the code is arg0 — gated on the light
    // cgevt_trace flag so it never fires in a normal boot. exit code 0 = a
    // clean/requested stop; non-zero maps to a systemd EXIT_* failure class.
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() {
        let comm = proc_comm_of_task(tid).unwrap_or_default();
        if comm == "systemd" || comm.starts_with("(sd") {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "USEREXIT pid={} tid={} comm={} exit_group_code={}",
                pid,
                tid,
                comm,
                ctx.args().arg0 as i64
            );
        }
    }
    zap_thread_group(tid, pid);
    sys_exit_task(ctx);
}
