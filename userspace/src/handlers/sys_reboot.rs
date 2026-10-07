#[allow(unused_imports)]
use super::*;

const LINUX_REBOOT_MAGIC1: u64 = 0xfee1_dead;
const MAGIC2: u64 = 672_274_793; // 0x28121969
const MAGIC2A: u64 = 0x0512_1996;
const MAGIC2B: u64 = 0x1604_1998;
const MAGIC2C: u64 = 0x2011_2000;
const CMD_RESTART: u64 = 0x0123_4567;
const CMD_HALT: u64 = 0xcdef_0123;
const CMD_POWER_OFF: u64 = 0x4321_fedc;
const CMD_RESTART2: u64 = 0xa1b2_c3d4;
const CMD_CAD_ON: u64 = 0x89ab_cdef;
const CMD_CAD_OFF: u64 = 0;

/// `kernel/reboot.c::SYSCALL_DEFINE4(reboot, int, magic1, int, magic2,
/// unsigned int, cmd, void __user *, arg)`.
///
/// ```text
/// /* We only trust the superuser with rebooting the system. */
/// if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
///         return -EPERM;
/// /* For safety, we require "magic" arguments. */
/// if (magic1 != LINUX_REBOOT_MAGIC1 || (magic2 != ...))
///         return -EINVAL;
/// ret = reboot_pid_ns(pid_ns, cmd);
/// if (ret) return ret;
/// ```
///
/// The capability check comes FIRST — before the magic numbers, so an
/// unprivileged caller gets -EPERM even for a garbage request — and this
/// handler had no capability check at all. Its note said "everything runs
/// root today, matching the rest of the surface", which stopped being true
/// as the surface grew its own checks (`sys_settimeofday`'s CAP_SYS_TIME,
/// `sys_vhangup`'s CAP_SYS_TTY_CONFIG, `sys_syslog`'s CAP_SYSLOG, module
/// load/unload's CAP_SYS_MODULE). Any task could power the machine off.
///
/// The magic pair is still what it is in Linux: a guard against a stray
/// syscall with garbage arguments landing on the power-off path, which is
/// why it is checked and why it is checked second.
///
/// RESTART goes through narf-power's FADT/CF9 reset; POWER_OFF and HALT both
/// enter ACPI S5 (NARF has no "halted but powered" CPU parking state worth
/// distinguishing — Linux's own `poweroff_fallback_to_halt` folds the pair
/// the other way when it cannot power off). The Ctrl-Alt-Del toggles are
/// accepted no-ops.
///
/// LINUX-GAP: `LINUX_REBOOT_CMD_KEXEC` and `LINUX_REBOOT_CMD_SW_SUSPEND`
/// are -EINVAL, as they are on a Linux built without CONFIG_KEXEC_CORE /
/// CONFIG_HIBERNATION. NARF has suspend-to-idle in `narf_power` but no
/// hibernation image writer, and no kexec.
pub(crate) fn sys_reboot(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();

    // `ns_capable(task_active_pid_ns(current)->user_ns, CAP_SYS_BOOT)` —
    // authority over the pid namespace being rebooted, which for a task in
    // the initial namespace is authority over the host.
    #[cfg(feature = "container")]
    let authorised = {
        let task = current_task_id();
        let pid_ns = crate::pid_ns::current_pid_ns(task);
        task_ns_capable(task, &pid_ns.owner_user_ns(), CAP_SYS_BOOT)
    };
    #[cfg(not(feature = "container"))]
    let authorised = capable(CAP_SYS_BOOT);
    if !authorised {
        ctx.set_return(errno_ret(EPERM));
        return;
    }

    // Linux truncates the magics to 32 bits before comparing (glibc
    // sign-extends LINUX_REBOOT_MAGIC1 through the int prototype).
    let magic1 = a.arg0 as u32 as u64;
    let magic2 = a.arg1 as u32 as u64;
    if magic1 != LINUX_REBOOT_MAGIC1 || !matches!(magic2, MAGIC2 | MAGIC2A | MAGIC2B | MAGIC2C) {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let cmd = a.arg2 as u32 as u64;

    // `reboot_pid_ns`: a task in a CHILD pid namespace never reboots the
    // machine. It kills its namespace's init and exits instead — a
    // container asking to shut down shuts the container down.
    #[cfg(feature = "container")]
    if reboot_pid_ns(ctx, cmd) {
        return;
    }

    match cmd {
        CMD_CAD_ON | CMD_CAD_OFF => ctx.set_return(SyscallReturn::ok(0)),
        CMD_RESTART => {
            use core::fmt::Write;
            let _ = writeln!(narf_console::Writer, "reboot: Restarting system");
            narf_power::system::reboot();
        }
        // `strncpy_from_user(&buffer[0], arg, sizeof(buffer) - 1)` then
        // `kernel_restart(buffer)`: the string names the restart mode for
        // the arch/firmware hook. A faulting `arg` is -EFAULT — the one
        // errno this command adds over RESTART. NARF's reset path takes no
        // mode argument, so the name is reported and the reset is the same
        // one RESTART performs.
        CMD_RESTART2 => {
            let cmd_str = match copy_user_cstr_checked(a.arg3, 256) {
                Ok(s) => s,
                Err(_) => {
                    ctx.set_return(errno_ret(EFAULT));
                    return;
                }
            };
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "reboot: Restarting system with command '{}'",
                cmd_str
            );
            narf_power::system::reboot();
        }
        CMD_POWER_OFF | CMD_HALT => {
            use core::fmt::Write;
            let _ = writeln!(narf_console::Writer, "reboot: Power down");
            narf_power::system::power_off();
        }
        _ => ctx.set_return(errno_ret(EINVAL)),
    }
}

/// `kernel/pid_namespace.c::reboot_pid_ns()`.
///
/// ```text
/// if (pid_ns == &init_pid_ns)
///         return 0;
/// switch (cmd) {
/// case LINUX_REBOOT_CMD_RESTART2:
/// case LINUX_REBOOT_CMD_RESTART:    pid_ns->reboot = SIGHUP;  break;
/// case LINUX_REBOOT_CMD_POWER_OFF:
/// case LINUX_REBOOT_CMD_HALT:       pid_ns->reboot = SIGINT;  break;
/// default:                          return -EINVAL;
/// }
/// send_sig(SIGKILL, pid_ns->child_reaper, 1);
/// do_exit(0);
/// ```
///
/// Returns `true` when the call was answered here — the caller must not fall
/// through to the machine-wide path. `false` means the caller is in the
/// initial namespace and the reboot is the real one.
///
/// This is the other half of the privilege story: `ns_capable` grants
/// authority over the namespace, and a container owner can legitimately hold
/// CAP_SYS_BOOT in its own user namespace, so without this the namespace
/// check would be a way to power off the HOST.
///
/// LINUX-GAP: Linux stashes the signal in `pid_ns->reboot` so
/// `zap_pid_ns_processes()` can report it as the namespace init's exit code
/// to whoever waits on it (that is how an outer supervisor learns "the
/// container asked to restart" rather than "the container was killed"). NARF
/// has no `zap_pid_ns_processes`, so the distinction between a requested
/// restart and a requested power-off is lost: both arrive as the SIGKILL.
#[cfg(feature = "container")]
fn reboot_pid_ns(ctx: &mut dyn TrapContext, cmd: u64) -> bool {
    const SIGKILL: u32 = 9;

    let pid_ns = crate::pid_ns::current_pid_ns(current_task_id());
    if pid_ns.id() == crate::pid_ns::initial_pid_ns().id() {
        return false;
    }
    // Only the four shutdown commands mean anything to a namespace: the
    // Ctrl-Alt-Del toggles and the kexec/suspend commands are machine-wide,
    // so inside a namespace they are -EINVAL rather than silent successes.
    if !matches!(cmd, CMD_RESTART | CMD_RESTART2 | CMD_POWER_OFF | CMD_HALT) {
        ctx.set_return(errno_ret(EINVAL));
        return true;
    }
    // `pid_ns->child_reaper` — pid 1 as the namespace numbers it.
    if let Some(init_pid) = pid_ns.inner_to_outer(1) {
        kill_process(init_pid, SIGKILL);
    }
    // `do_exit(0)`: this thread, with exit code 0 — not the reboot magic
    // that sits in arg0.
    let mut exit_ctx = ReshapeArgs {
        inner: ctx,
        args: SyscallArgs {
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
    };
    sys_exit_task(&mut exit_ctx);
    true
}
