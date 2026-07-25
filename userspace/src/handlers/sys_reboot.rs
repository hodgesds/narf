#[allow(unused_imports)]
use super::*;

/// `reboot(magic1, magic2, cmd, arg)` — Linux reboot(2). The magic
/// pair guards against a stray syscall with garbage args landing on
/// the power-off path (Linux's rationale exactly). No capability
/// check — everything runs root today, matching the rest of the
/// surface. RESTART goes through narf-power's FADT/CF9 reset,
/// POWER_OFF and HALT both enter ACPI S5 (NARF has no "halted but
/// powered" CPU parking state worth distinguishing). The
/// Ctrl-Alt-Del toggles are accepted no-ops.
pub(crate) fn sys_reboot(ctx: &mut dyn TrapContext) {
    const LINUX_REBOOT_MAGIC1: u64 = 0xfee1_dead;
    const MAGIC2: u64 = 672_274_793; // 0x28121969
    const MAGIC2A: u64 = 0x0512_1996;
    const MAGIC2B: u64 = 0x1604_1998;
    const MAGIC2C: u64 = 0x2011_2000;
    const CMD_RESTART: u64 = 0x0123_4567;
    const CMD_HALT: u64 = 0xcdef_0123;
    const CMD_POWER_OFF: u64 = 0x4321_fedc;
    const CMD_CAD_ON: u64 = 0x89ab_cdef;
    const CMD_CAD_OFF: u64 = 0;

    let a = *ctx.args();
    // Linux truncates the magics to 32 bits before comparing (glibc
    // sign-extends LINUX_REBOOT_MAGIC1 through the int prototype).
    let magic1 = a.arg0 as u32 as u64;
    let magic2 = a.arg1 as u32 as u64;
    if magic1 != LINUX_REBOOT_MAGIC1 || !matches!(magic2, MAGIC2 | MAGIC2A | MAGIC2B | MAGIC2C) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    match a.arg2 as u32 as u64 {
        CMD_CAD_ON | CMD_CAD_OFF => ctx.set_return(SyscallReturn::ok(0)),
        CMD_RESTART => {
            use core::fmt::Write;
            let _ = writeln!(narf_console::Writer, "reboot: Restarting system");
            narf_power::system::reboot();
        }
        CMD_POWER_OFF | CMD_HALT => {
            use core::fmt::Write;
            let _ = writeln!(narf_console::Writer, "reboot: Power down");
            narf_power::system::power_off();
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)),
    }
}
