#[allow(unused_imports)]
use super::*;

/// `vhangup(2)`: simulate a controlling-terminal hangup. On Linux this
/// revokes every *other* process's open of the terminal (used by
/// `/bin/login` and getty to drop a prior session's grip before taking
/// over the tty). NARF drives a singleton console with no per-open revoke
/// path, so there is nothing to tear down — the caller keeps its own open
/// fds. Return 0 so login proceeds instead of aborting on a bare -1.
///
/// Linux `fs/open.c::sys_vhangup` gates on `capable(CAP_SYS_TTY_CONFIG)`
/// returning `-EPERM` when unprivileged.
pub(crate) fn sys_vhangup(ctx: &mut dyn TrapContext) {
    if !capable(CAP_SYS_TTY_CONFIG) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

