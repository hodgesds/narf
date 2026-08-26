#[allow(unused_imports)]
use super::*;

/// `sysinfo(struct sysinfo*)` — fill the uptime (from the monotonic
/// clock) and RAM totals (from the frame allocator). Swap, loads, and
/// the high-memory fields stay zero; mem_unit is 1 (bytes).
pub(crate) fn sys_sysinfo(ctx: &mut dyn TrapContext) {
    let buf = ctx.args().arg0;
    if buf == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let uptime_secs = (narf_scheduler::narf_time::monotonic_ns() / 1_000_000_000) as i64;
    let stats = narf_memory::frame_stats();
    let total_bytes = (stats.total as u64).saturating_mul(4096);
    let free_bytes = (stats.free as u64).saturating_mul(4096);
    // struct sysinfo (LP64): uptime@0, loads@8/16/24, totalram@32,
    // freeram@40, sharedram@48, bufferram@56, totalswap@64, freeswap@72,
    // procs@80(u16), totalhigh@88, freehigh@96, mem_unit@104(u32). 112
    // bytes covers through mem_unit; the remaining __reserved stays as
    // the caller left it.
    let mut si = [0u8; 112];
    si[0..8].copy_from_slice(&uptime_secs.to_ne_bytes());
    // loads[3]: same EWMA /proc/loadavg renders, in the SI_LOAD_SHIFT=16
    // fixed point — busybox uptime reads sysinfo(2), not the proc file,
    // and previously showed a flat 0.00. procfs (and its EWMA) only
    // exists under linux-compat; other builds keep zeroed loads.
    {
        let (l1, l5, l15) = narf_filesystem::procfs::loadavg_sysinfo_fixed16();
        si[8..16].copy_from_slice(&l1.to_ne_bytes());
        si[16..24].copy_from_slice(&l5.to_ne_bytes());
        si[24..32].copy_from_slice(&l15.to_ne_bytes());
    }
    si[32..40].copy_from_slice(&total_bytes.to_ne_bytes());
    si[40..48].copy_from_slice(&free_bytes.to_ne_bytes());
    let procs = narf_scheduler::all_task_ids().len().min(u16::MAX as usize) as u16;
    si[80..82].copy_from_slice(&procs.to_ne_bytes()); // procs
    si[104..108].copy_from_slice(&1u32.to_ne_bytes()); // mem_unit = 1 byte
                                                       // SAFETY: `buf` is the user `struct sysinfo*` (non-zero); copy_to_user
                                                       // range-validates the 112-byte write.
    if unsafe { copy_to_user(buf, &si) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
