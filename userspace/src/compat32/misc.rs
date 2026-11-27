//! i386 entry points whose compat structure, 32-bit time or split 64-bit
//! argument differs from the native call (`syscall_32.tbl`'s
//! `compat_sys_*` and `sys_ia32_*` columns), served by the native handler
//! on converted arguments.
//!
//! A 64-bit value an i386 caller cannot pass in one register arrives as a
//! low and a high word (`sys_ia32_truncate64` and friends) and is joined
//! here. A structure the native handler writes in its own layout is staged
//! on the caller's stack ([`super::stage`]), and the result is narrowed into
//! the compat structure the way Linux's `put_compat_*` helpers do.

use alloc::vec::Vec;

use super::conv;
use super::stage::{self, Stage};
use super::table::{call_native, forward_args, succeeded};
use crate::errno::{to_ret, EINVAL, EOVERFLOW};
use crate::syscall::{Ia32Abi, Syscall, SyscallArgs, SyscallReturn, TrapContext};

fn args(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
    }
}

/// Report `result` (a return to set, or an errno) for `variant`.
fn finish(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    result: Result<Option<SyscallReturn>, i64>,
) -> Option<Syscall> {
    match result {
        Ok(Some(ret)) => ctx.set_return(ret),
        // The native handler parked to re-execute the call: no result yet.
        Ok(None) => {}
        Err(e) => ctx.set_return(to_ret(e)),
    }
    Some(variant)
}

fn native(ctx: &mut dyn TrapContext, variant: Syscall, a: SyscallArgs) -> Option<SyscallReturn> {
    call_native(ctx, variant, a, Ia32Abi::default())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

/// A 64-bit value passed as `(low, high)` 32-bit registers.
fn join(low: u64, high: u64) -> u64 {
    (high << 32) | (low & 0xFFFF_FFFF)
}

// ── split 64-bit arguments ────────────────────────────────────────────

/// `sys_ia32_truncate64(path, lo, hi)` (193), `sys_ia32_ftruncate64(fd,
/// lo, hi)` (194), `sys_ia32_fallocate(fd, mode, off_lo, off_hi, len_lo,
/// len_hi)` (324), `sys_ia32_fadvise64(fd, off_lo, off_hi, len, advice)`
/// (250), `sys_ia32_fadvise64_64(fd, off_lo, off_hi, len_lo, len_hi,
/// advice)` (272), `sys_ia32_readahead(fd, off_lo, off_hi, count)` (225)
/// and `sys_ia32_sync_file_range(fd, off_lo, off_hi, n_lo, n_hi, flags)`
/// (314): the native call on the joined 64-bit values.
pub(crate) fn split_offsets(ctx: &mut dyn TrapContext, nr: u32) -> Option<Syscall> {
    use super::table::nr::*;
    let a = *ctx.args();
    let sx = conv::sext;
    let (variant, native_args) = match nr {
        TRUNCATE64 => (
            Syscall::Truncate,
            args(a.arg0, join(a.arg1, a.arg2), 0, 0, 0, 0),
        ),
        FTRUNCATE64 => (
            Syscall::Ftruncate,
            args(a.arg0, join(a.arg1, a.arg2), 0, 0, 0, 0),
        ),
        FALLOCATE => (
            Syscall::Fallocate,
            args(
                sx(a.arg0),
                sx(a.arg1),
                join(a.arg2, a.arg3),
                join(a.arg4, a.arg5),
                0,
                0,
            ),
        ),
        FADVISE64 => (
            Syscall::Fadvise64,
            args(sx(a.arg0), join(a.arg1, a.arg2), a.arg3, sx(a.arg4), 0, 0),
        ),
        FADVISE64_64 => (
            Syscall::Fadvise64,
            args(
                sx(a.arg0),
                join(a.arg1, a.arg2),
                join(a.arg3, a.arg4),
                sx(a.arg5),
                0,
                0,
            ),
        ),
        READAHEAD => (
            Syscall::Readahead,
            args(sx(a.arg0), join(a.arg1, a.arg2), a.arg3, 0, 0, 0),
        ),
        SYNC_FILE_RANGE => (
            Syscall::SyncFileRange,
            args(
                sx(a.arg0),
                join(a.arg1, a.arg2),
                join(a.arg3, a.arg4),
                a.arg5,
                0,
                0,
            ),
        ),
        // `compat_sys_truncate` / `compat_sys_ftruncate`: a `compat_off_t`.
        TRUNCATE => (Syscall::Truncate, args(a.arg0, sx(a.arg1), 0, 0, 0, 0)),
        FTRUNCATE => (Syscall::Ftruncate, args(a.arg0, sx(a.arg1), 0, 0, 0, 0)),
        _ => {
            ctx.set_return(SyscallReturn::not_implemented());
            return None;
        }
    };
    forward_args(ctx, variant, native_args, Ia32Abi::default())
}

// ── time ──────────────────────────────────────────────────────────────

/// `time(tloc)` (i386 13, `sys_time32`): the seconds as an `old_time32_t`,
/// stored through `tloc` too when it is set.
pub(crate) fn time32(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let tloc = ctx.args().arg0;
    let Some(ret) = native(ctx, Syscall::Time, args(0, 0, 0, 0, 0, 0)) else {
        return Some(Syscall::Time);
    };
    if !succeeded(&ret) {
        ctx.set_return(ret);
        return Some(Syscall::Time);
    }
    let secs = ret.value as i32;
    if tloc != 0 {
        if let Err(e) = conv::write_user(tloc, &secs.to_le_bytes()) {
            ctx.set_return(to_ret(e));
            return Some(Syscall::Time);
        }
    }
    ctx.set_return(SyscallReturn::ok(i64::from(secs) as u64));
    Some(Syscall::Time)
}

/// The `old_timeval32` / `old_timespec32` at `ptr` as its native two-`i64`
/// form.
fn time32_to_native(ptr: u64) -> Result<[u8; 16], i64> {
    let mut t = [0u8; 8];
    conv::read_user(ptr, &mut t)?;
    let mut native = [0u8; 16];
    native[0..8].copy_from_slice(&i64::from(conv::word(&t, 0) as i32).to_le_bytes());
    native[8..16].copy_from_slice(&i64::from(conv::word(&t, 1) as i32).to_le_bytes());
    Ok(native)
}

/// Narrow the native two-`i64` time at staged `at` into the caller's
/// `old_timeval32` / `old_timespec32` at `ptr`.
fn native_time_to_32(at: u64, ptr: u64) -> Result<(), i64> {
    let native = stage::read_back(at, 16)?;
    let mut t = [0u8; 8];
    t[0..4].copy_from_slice(&native[0..4]);
    t[4..8].copy_from_slice(&native[8..12]);
    conv::write_user(ptr, &t)
}

/// `gettimeofday(tv, tz)` (78) / `settimeofday(tv, tz)` (79),
/// `compat_sys_*timeofday`: an `old_timeval32`; `struct timezone` is two
/// ints on both ABIs.
pub(crate) fn timeofday(ctx: &mut dyn TrapContext, set: bool) -> Option<Syscall> {
    let variant = if set {
        Syscall::Settimeofday
    } else {
        Syscall::Gettimeofday
    };
    let result = timeofday_staged(ctx, variant, set);
    finish(ctx, variant, result)
}

fn timeofday_staged(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    set: bool,
) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let (tv, tz) = (a.arg0, a.arg1);
    if tv == 0 {
        return Ok(native(ctx, variant, args(0, tz, 0, 0, 0, 0)));
    }
    let mut stage = Stage::new(ctx, 32)?;
    let at = if set {
        stage.put(&time32_to_native(tv)?)?
    } else {
        stage.put(&[0u8; 16])?
    };
    let Some(ret) = native(ctx, variant, args(at, tz, 0, 0, 0, 0)) else {
        return Ok(None);
    };
    if !set && succeeded(&ret) {
        native_time_to_32(at, tv)?;
    }
    Ok(Some(ret))
}

/// `times(buf)` (43, `compat_sys_times`): `struct compat_tms`, four
/// 32-bit `compat_clock_t`s.
pub(crate) fn times(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = times_staged(ctx);
    finish(ctx, Syscall::Times, result)
}

fn times_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let buf = ctx.args().arg0;
    if buf == 0 {
        return Ok(native(ctx, Syscall::Times, args(0, 0, 0, 0, 0, 0)));
    }
    let mut stage = Stage::new(ctx, 32)?;
    let at = stage.put(&[0u8; 32])?;
    let Some(ret) = native(ctx, Syscall::Times, args(at, 0, 0, 0, 0, 0)) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        let tms = stage::read_back(at, 32)?;
        let mut out = [0u8; 16];
        for i in 0..4 {
            out[i * 4..i * 4 + 4].copy_from_slice(&tms[i * 8..i * 8 + 4]);
        }
        conv::write_user(buf, &out)?;
    }
    Ok(Some(ret))
}

// ── rlimits and rusage ────────────────────────────────────────────────

const RLIM_INFINITY: u64 = u64::MAX;
const COMPAT_RLIM_INFINITY: u64 = 0xFFFF_FFFF;
/// `compat_sys_old_getrlimit`'s ceiling (`0x7FFFFFFF`).
const COMPAT_RLIM_OLD_INFINITY: u64 = 0x7FFF_FFFF;

/// `getrlimit` (76, `compat_sys_old_getrlimit`) / `ugetrlimit` (191,
/// `compat_sys_getrlimit`): a `struct compat_rlimit`, each limit clamped to
/// 0x7FFFFFFF / `COMPAT_RLIM_INFINITY`.
pub(crate) fn getrlimit(ctx: &mut dyn TrapContext, old: bool) -> Option<Syscall> {
    let result = getrlimit_staged(ctx, old);
    finish(ctx, Syscall::Getrlimit, result)
}

fn getrlimit_staged(ctx: &mut dyn TrapContext, old: bool) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let mut stage = Stage::new(ctx, 16)?;
    let at = stage.put(&[0u8; 16])?;
    let Some(ret) = native(ctx, Syscall::Getrlimit, args(a.arg0, at, 0, 0, 0, 0)) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        let r = stage::read_back(at, 16)?;
        let ceiling = if old {
            COMPAT_RLIM_OLD_INFINITY
        } else {
            COMPAT_RLIM_INFINITY
        };
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&(le64(&r, 0).min(ceiling) as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(le64(&r, 8).min(ceiling) as u32).to_le_bytes());
        conv::write_user(a.arg1, &out)?;
    }
    Ok(Some(ret))
}

/// `setrlimit(resource, rlim)` (75, `compat_sys_setrlimit`):
/// `COMPAT_RLIM_INFINITY` widens to `RLIM_INFINITY`.
pub(crate) fn setrlimit(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = setrlimit_staged(ctx);
    finish(ctx, Syscall::Setrlimit, result)
}

fn setrlimit_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let mut raw = [0u8; 8];
    conv::read_user(a.arg1, &mut raw)?;
    let widen = |v: u32| {
        if u64::from(v) == COMPAT_RLIM_INFINITY {
            RLIM_INFINITY
        } else {
            u64::from(v)
        }
    };
    let mut native_rlim = [0u8; 16];
    native_rlim[0..8].copy_from_slice(&widen(conv::word(&raw, 0)).to_le_bytes());
    native_rlim[8..16].copy_from_slice(&widen(conv::word(&raw, 1)).to_le_bytes());
    let mut stage = Stage::new(ctx, 16)?;
    let at = stage.put(&native_rlim)?;
    Ok(native(
        ctx,
        Syscall::Setrlimit,
        args(a.arg0, at, 0, 0, 0, 0),
    ))
}

/// Bytes of the native `struct rusage` and of `struct compat_rusage`.
const RUSAGE: usize = 144;
const COMPAT_RUSAGE: usize = 72;

/// `put_compat_rusage`: the two `timeval`s and fourteen `long`s narrowed to
/// 32 bits.
fn rusage_to_compat(native: &[u8]) -> [u8; COMPAT_RUSAGE] {
    let mut out = [0u8; COMPAT_RUSAGE];
    for i in 0..COMPAT_RUSAGE / 4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&native[i * 8..i * 8 + 4]);
    }
    out
}

/// `getrusage(who, ru)` (77, `compat_sys_getrusage`).
pub(crate) fn getrusage(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = getrusage_staged(ctx);
    finish(ctx, Syscall::Getrusage, result)
}

fn getrusage_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let mut stage = Stage::new(ctx, RUSAGE)?;
    let at = stage.put(&[0u8; RUSAGE])?;
    let Some(ret) = native(
        ctx,
        Syscall::Getrusage,
        args(conv::sext(a.arg0), at, 0, 0, 0, 0),
    ) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        conv::write_user(a.arg1, &rusage_to_compat(&stage::read_back(at, RUSAGE)?))?;
    }
    Ok(Some(ret))
}

/// `wait4(pid, status, options, ru)` (114, `compat_sys_wait4`): the rusage
/// of a reaped child in compat form.
pub(crate) fn wait4(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = wait4_staged(ctx);
    finish(ctx, Syscall::Wait4, result)
}

fn wait4_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let (pid, status, options, ru) = (conv::sext(a.arg0), a.arg1, conv::sext(a.arg2), a.arg3);
    if ru == 0 {
        return Ok(native(
            ctx,
            Syscall::Wait4,
            args(pid, status, options, 0, 0, 0),
        ));
    }
    let mut stage = Stage::new(ctx, RUSAGE)?;
    let at = stage.put(&[0u8; RUSAGE])?;
    let Some(ret) = native(ctx, Syscall::Wait4, args(pid, status, options, at, 0, 0)) else {
        return Ok(None);
    };
    if succeeded(&ret) && ret.value != 0 {
        conv::write_user(ru, &rusage_to_compat(&stage::read_back(at, RUSAGE)?))?;
    }
    Ok(Some(ret))
}

/// `waitid(which, pid, infop, options, ru)` (284, `compat_sys_waitid`):
/// Linux writes `si_signo`, `si_errno`, `si_code`, `si_pid`, `si_uid` and
/// `si_status` into the `struct compat_siginfo` (its `_sigchld` union at
/// offset 12), and the rusage in compat form.
pub(crate) fn waitid(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = waitid_staged(ctx);
    finish(ctx, Syscall::Waitid, result)
}

fn waitid_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    const SIGINFO: usize = 128;
    let a = *ctx.args();
    let (which, pid, infop, options, ru) = (
        conv::sext(a.arg0),
        conv::sext(a.arg1),
        a.arg2,
        conv::sext(a.arg3),
        a.arg4,
    );
    let mut stage = Stage::new(ctx, SIGINFO + RUSAGE + 32)?;
    let info_at = if infop != 0 {
        stage.put(&[0u8; SIGINFO])?
    } else {
        0
    };
    let ru_at = if ru != 0 {
        stage.put(&[0u8; RUSAGE])?
    } else {
        0
    };
    let Some(ret) = native(
        ctx,
        Syscall::Waitid,
        args(which, pid, info_at, options, ru_at, 0),
    ) else {
        return Ok(None);
    };
    if !succeeded(&ret) {
        return Ok(Some(ret));
    }
    if ru != 0 {
        conv::write_user(ru, &rusage_to_compat(&stage::read_back(ru_at, RUSAGE)?))?;
    }
    if infop != 0 {
        let si = stage::read_back(info_at, SIGINFO)?;
        let mut out = [0u8; SIGINFO];
        out[0..12].copy_from_slice(&si[0..12]); // si_signo, si_errno, si_code
        out[12..24].copy_from_slice(&si[16..28]); // si_pid, si_uid, si_status
        conv::write_user(infop, &out[..24])?;
    }
    Ok(Some(ret))
}

// ── filesystems and system information ────────────────────────────────

/// Bytes of the native `struct statfs` and the compat ones.
const STATFS: usize = 120;
const COMPAT_STATFS: usize = 64;
const COMPAT_STATFS64: usize = 84;

/// `statfs(path, buf)` (99) / `fstatfs(fd, buf)` (100) with `struct
/// compat_statfs` (`put_compat_statfs`: EOVERFLOW for a count past 32
/// bits, -1 file counts kept), and `statfs64(path, sz, buf)` (268) /
/// `fstatfs64(fd, sz, buf)` (269) with the packed 84-byte `struct
/// compat_statfs64` (`put_compat_statfs64`: EOVERFLOW for a block size
/// past 32 bits; any other `sz` is EINVAL).
pub(crate) fn statfs(ctx: &mut dyn TrapContext, by_fd: bool, wide: bool) -> Option<Syscall> {
    let variant = if by_fd {
        Syscall::Fstatfs
    } else {
        Syscall::Statfs
    };
    let result = statfs_staged(ctx, variant, by_fd, wide);
    finish(ctx, variant, result)
}

fn statfs_staged(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    by_fd: bool,
    wide: bool,
) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let (target, buf) = if wide {
        if a.arg1 as u32 as usize != COMPAT_STATFS64 {
            return Err(EINVAL);
        }
        (a.arg0, a.arg2)
    } else {
        (a.arg0, a.arg1)
    };
    let target = if by_fd { conv::sext(target) } else { target };
    let mut stage = Stage::new(ctx, STATFS)?;
    let at = stage.put(&[0u8; STATFS])?;
    let Some(ret) = native(ctx, variant, args(target, at, 0, 0, 0, 0)) else {
        return Ok(None);
    };
    if !succeeded(&ret) {
        return Ok(Some(ret));
    }
    let n = stage::read_back(at, STATFS)?;
    let field = |i: usize| le64(&n, i * 8);
    // f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree,
    // f_fsid (8 bytes), f_namelen, f_frsize, f_flags.
    let (bsize, frsize) = (field(1), field(9));
    let fsid = &n[56..64];
    let out = if wide {
        if (bsize | frsize) >> 32 != 0 {
            return Err(EOVERFLOW);
        }
        let mut out = alloc::vec![0u8; COMPAT_STATFS64];
        out[0..4].copy_from_slice(&(field(0) as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(bsize as u32).to_le_bytes());
        for (i, f) in (2..7).enumerate() {
            out[8 + i * 8..16 + i * 8].copy_from_slice(&field(f).to_le_bytes());
        }
        out[48..56].copy_from_slice(fsid);
        out[56..60].copy_from_slice(&(field(8) as u32).to_le_bytes());
        out[60..64].copy_from_slice(&(frsize as u32).to_le_bytes());
        out[64..68].copy_from_slice(&(field(10) as u32).to_le_bytes());
        out
    } else {
        let big = |v: u64| v >> 32 != 0;
        let big_count = |v: u64| v != u64::MAX && big(v);
        if big(field(2)) || big(field(3)) || big(field(4)) || big(bsize) || big(frsize) {
            return Err(EOVERFLOW);
        }
        if big_count(field(5)) || big_count(field(6)) {
            return Err(EOVERFLOW);
        }
        let mut out = alloc::vec![0u8; COMPAT_STATFS];
        for (i, f) in (0..7).enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&(field(f) as u32).to_le_bytes());
        }
        out[28..36].copy_from_slice(fsid);
        out[36..40].copy_from_slice(&(field(8) as u32).to_le_bytes());
        out[40..44].copy_from_slice(&(frsize as u32).to_le_bytes());
        out[44..48].copy_from_slice(&(field(10) as u32).to_le_bytes());
        out
    };
    conv::write_user(buf, &out)?;
    Ok(Some(ret))
}

/// `sysinfo(info)` (116, `compat_sys_sysinfo`): `struct compat_sysinfo`,
/// the memory counts rescaled through `mem_unit` when one does not fit 32
/// bits.
pub(crate) fn sysinfo(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = sysinfo_staged(ctx);
    finish(ctx, Syscall::Sysinfo, result)
}

fn sysinfo_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    const SYSINFO: usize = 112;
    const PAGE_SIZE: u64 = 4096;
    let info = ctx.args().arg0;
    let mut stage = Stage::new(ctx, SYSINFO)?;
    let at = stage.put(&[0u8; SYSINFO])?;
    let Some(ret) = native(ctx, Syscall::Sysinfo, args(at, 0, 0, 0, 0, 0)) else {
        return Ok(None);
    };
    if !succeeded(&ret) {
        return Ok(Some(ret));
    }
    let n = stage::read_back(at, SYSINFO)?;
    // totalram, freeram, sharedram, bufferram, totalswap, freeswap at 32..80;
    // totalhigh, freehigh at 88 and 96.
    let mut mem = [
        le64(&n, 32),
        le64(&n, 40),
        le64(&n, 48),
        le64(&n, 56),
        le64(&n, 64),
        le64(&n, 72),
        le64(&n, 88),
        le64(&n, 96),
    ];
    let mut mem_unit = u64::from(u32::from_le_bytes([n[104], n[105], n[106], n[107]]));
    if (mem[0] >> 32) != 0 || (mem[4] >> 32) != 0 {
        let mut shift = 0;
        while mem_unit < PAGE_SIZE {
            mem_unit <<= 1;
            shift += 1;
        }
        for m in mem.iter_mut() {
            *m >>= shift;
        }
    }
    let mut out = [0u8; 64];
    out[0..4].copy_from_slice(&n[0..4]); // uptime
    for i in 0..3 {
        out[4 + i * 4..8 + i * 4].copy_from_slice(&n[8 + i * 8..12 + i * 8]); // loads
    }
    for (i, m) in mem[..6].iter().enumerate() {
        out[16 + i * 4..20 + i * 4].copy_from_slice(&(*m as u32).to_le_bytes());
    }
    out[40..42].copy_from_slice(&n[80..82]); // procs
    out[44..48].copy_from_slice(&(mem[6] as u32).to_le_bytes());
    out[48..52].copy_from_slice(&(mem[7] as u32).to_le_bytes());
    out[52..56].copy_from_slice(&(mem_unit as u32).to_le_bytes());
    conv::write_user(info, &out)?;
    Ok(Some(ret))
}

// ── signals ───────────────────────────────────────────────────────────

/// `sigaltstack(uss, uoss)` (186, `compat_sys_sigaltstack`): `compat_stack_t
/// { compat_uptr_t ss_sp; int ss_flags; compat_size_t ss_size; }` against
/// the native 24-byte `stack_t`.
pub(crate) fn sigaltstack(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = sigaltstack_staged(ctx);
    finish(ctx, Syscall::Sigaltstack, result)
}

fn sigaltstack_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let (uss, uoss) = (a.arg0, a.arg1);
    let mut stage = Stage::new(ctx, 64)?;
    let ss_at = if uss != 0 {
        let mut raw = [0u8; 12];
        conv::read_user(uss, &mut raw)?;
        let mut native_ss = [0u8; 24];
        native_ss[0..8].copy_from_slice(&u64::from(conv::word(&raw, 0)).to_le_bytes());
        native_ss[8..12].copy_from_slice(&raw[4..8]);
        native_ss[16..24].copy_from_slice(&u64::from(conv::word(&raw, 2)).to_le_bytes());
        stage.put(&native_ss)?
    } else {
        0
    };
    let oss_at = if uoss != 0 { stage.put(&[0u8; 24])? } else { 0 };
    let Some(ret) = native(ctx, Syscall::Sigaltstack, args(ss_at, oss_at, 0, 0, 0, 0)) else {
        return Ok(None);
    };
    if succeeded(&ret) && uoss != 0 {
        let o = stage::read_back(oss_at, 24)?;
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&o[0..4]);
        out[4..8].copy_from_slice(&o[8..12]);
        out[8..12].copy_from_slice(&o[16..20]);
        conv::write_user(uoss, &out)?;
    }
    Ok(Some(ret))
}

// ── select and poll ───────────────────────────────────────────────────

/// The most descriptors a staged `fd_set` covers: past it the sets are cut,
/// as Linux cuts them at the descriptor table's size.
const MAX_STAGED_FDS: u64 = 65536;

/// `select`-family conversions (`do_compat_select` / `do_compat_pselect`):
/// each `fd_set` is an array of 32-bit `compat_ulong_t` words; the native
/// handler's are 64-bit. On little-endian x86 the bits sit at the same
/// bytes, so each set is copied into a native-sized staged buffer and its
/// `ceil(n / 32)` words copied back on success.
struct StagedSets {
    n: u64,
    sets: [(u64, u64); 3],
}

impl StagedSets {
    fn new(stage: &mut Stage, n: u64, user: [u64; 3]) -> Result<Self, i64> {
        if (n as u32 as i32) < 0 {
            return Err(EINVAL);
        }
        let n = n.min(MAX_STAGED_FDS);
        let compat_len = (n.div_ceil(32) * 4) as usize;
        let native_len = (n.div_ceil(64) * 8) as usize;
        let mut sets = [(0u64, 0u64); 3];
        for (slot, &ptr) in sets.iter_mut().zip(user.iter()) {
            if ptr == 0 {
                continue;
            }
            let mut bytes = alloc::vec![0u8; native_len];
            conv::read_user(ptr, &mut bytes[..compat_len])?;
            *slot = (ptr, stage.put(&bytes)?);
        }
        Ok(Self { n, sets })
    }

    fn native_args(&self) -> [u64; 3] {
        [self.sets[0].1, self.sets[1].1, self.sets[2].1]
    }

    fn copy_back(&self) -> Result<(), i64> {
        let compat_len = (self.n.div_ceil(32) * 4) as usize;
        for &(user, staged) in &self.sets {
            if user != 0 {
                let bytes = stage::read_back(staged, compat_len)?;
                conv::write_user(user, &bytes)?;
            }
        }
        Ok(())
    }

    fn bytes(n: u64) -> usize {
        (n.min(MAX_STAGED_FDS).div_ceil(64) * 8) as usize * 3 + 64
    }
}

/// `pselect6(n, in, out, ex, tsp, sig)` (308 with an `old_timespec32`, 413
/// `pselect6_time64` with a `__kernel_timespec`), `_newselect(n, in, out,
/// ex, tvp)` (142, `old_timeval32`) and `select(arg)` (82,
/// `compat_sys_old_select`: the five arguments in a `struct
/// compat_sel_arg_struct`). pselect's `sig` is a `{ compat_uptr_t ss;
/// compat_size_t ss_len; }` pack; a 32-bit timeout gets the time left
/// written back, as `poll_select_finish` writes it.
pub(crate) fn select(ctx: &mut dyn TrapContext, nr: u32) -> Option<Syscall> {
    let variant = if matches!(
        nr,
        super::table::nr::PSELECT6 | super::table::nr::PSELECT6_TIME64
    ) {
        Syscall::Pselect6
    } else {
        Syscall::Select
    };
    let result = select_staged(ctx, nr, variant);
    finish(ctx, variant, result)
}

fn select_staged(
    ctx: &mut dyn TrapContext,
    nr: u32,
    variant: Syscall,
) -> Result<Option<SyscallReturn>, i64> {
    use super::table::nr::{PSELECT6, PSELECT6_TIME64, SELECT};
    let a = *ctx.args();
    let regs = if nr == SELECT {
        let mut raw = [0u8; 20];
        conv::read_user(a.arg0, &mut raw)?;
        [0, 1, 2, 3, 4].map(|i| u64::from(conv::word(&raw, i)))
    } else {
        [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4]
    };
    let (n, timeout) = (regs[0], regs[4]);
    let time32 = nr != PSELECT6_TIME64;
    let mut stage = Stage::new(ctx, StagedSets::bytes(n) + 64)?;
    let sets = StagedSets::new(&mut stage, n, [regs[1], regs[2], regs[3]])?;
    let timeout_at = if timeout != 0 && time32 {
        stage.put(&time32_to_native(timeout)?)?
    } else {
        timeout
    };
    let sig_at = if (nr == PSELECT6 || nr == PSELECT6_TIME64) && a.arg5 != 0 {
        let mut pack = [0u8; 8];
        conv::read_user(a.arg5, &mut pack)?;
        let mut native_pack = [0u8; 16];
        native_pack[0..8].copy_from_slice(&u64::from(conv::word(&pack, 0)).to_le_bytes());
        native_pack[8..16].copy_from_slice(&u64::from(conv::word(&pack, 1)).to_le_bytes());
        stage.put(&native_pack)?
    } else {
        0
    };
    let [inp, outp, exp] = sets.native_args();
    let native_args = args(sets.n, inp, outp, exp, timeout_at, sig_at);
    let Some(ret) = native(ctx, variant, native_args) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        sets.copy_back()?;
        if timeout != 0 && time32 {
            native_time_to_32(timeout_at, timeout)?;
        }
    }
    Ok(Some(ret))
}

/// `ppoll(fds, nfds, tsp, sigmask, sigsetsize)` (309, `old_timespec32`):
/// the time left is written back; `struct pollfd` and the sigset are the
/// same on both ABIs (`ppoll_time64` passes straight through).
pub(crate) fn ppoll_time32(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = ppoll_staged(ctx);
    finish(ctx, Syscall::Ppoll, result)
}

fn ppoll_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    if a.arg2 == 0 {
        return Ok(native(ctx, Syscall::Ppoll, a));
    }
    let mut stage = Stage::new(ctx, 16)?;
    let at = stage.put(&time32_to_native(a.arg2)?)?;
    let Some(ret) = native(
        ctx,
        Syscall::Ppoll,
        args(a.arg0, a.arg1, at, a.arg3, a.arg4, 0),
    ) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        native_time_to_32(at, a.arg2)?;
    }
    Ok(Some(ret))
}

// ── vectored and offset I/O ───────────────────────────────────────────

/// `n` `compat_iovec`s at `iov` as native `struct iovec`s: EINVAL for more
/// than UIO_MAXIOV or a negative `compat_ssize_t` length.
fn native_iovecs(iov: u64, n: u64) -> Result<Vec<u8>, i64> {
    const UIO_MAXIOV: u64 = 1024;
    if n > UIO_MAXIOV {
        return Err(EINVAL);
    }
    let n = n as usize;
    let mut raw = alloc::vec![0u8; n * 8];
    if n != 0 {
        conv::read_user(iov, &mut raw)?;
    }
    let mut out = Vec::with_capacity(n * 16);
    for i in 0..n {
        let len = conv::word(&raw, 2 * i + 1);
        if (len as i32) < 0 {
            return Err(EINVAL);
        }
        out.extend_from_slice(&u64::from(conv::word(&raw, 2 * i)).to_le_bytes());
        out.extend_from_slice(&u64::from(len).to_le_bytes());
    }
    Ok(out)
}

/// `preadv` / `pwritev (fd, vec, vlen, pos_low, pos_high)` (333/334) and
/// `preadv2` / `pwritev2 (..., flags)` (378/379): `compat_iovec`s and a
/// split offset (`compat_sys_preadv64`... `pos_high:pos_low`, -1 for the
/// current position in the v2 forms).
pub(crate) fn preadv(ctx: &mut dyn TrapContext, variant: Syscall, v2: bool) -> Option<Syscall> {
    let result = preadv_staged(ctx, variant, v2);
    finish(ctx, variant, result)
}

fn preadv_staged(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    v2: bool,
) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let iov = native_iovecs(a.arg1, a.arg2)?;
    let mut stage = Stage::new(ctx, iov.len() + 16)?;
    let at = stage.put(&iov)?;
    let pos = join(a.arg3, a.arg4);
    let flags = if v2 { a.arg5 } else { 0 };
    Ok(native(
        ctx,
        variant,
        args(a.arg0, at, a.arg2, pos, 0, flags),
    ))
}

/// `sendfile(out_fd, in_fd, offset, count)` (187, `compat_sys_sendfile`): a
/// `compat_off_t` offset, read and written back as 32 bits.
pub(crate) fn sendfile32(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = sendfile_staged(ctx);
    finish(ctx, Syscall::Sendfile, result)
}

fn sendfile_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let (out_fd, in_fd, offset, count) = (conv::sext(a.arg0), conv::sext(a.arg1), a.arg2, a.arg3);
    if offset == 0 {
        return Ok(native(
            ctx,
            Syscall::Sendfile,
            args(out_fd, in_fd, 0, count, 0, 0),
        ));
    }
    let mut raw = [0u8; 4];
    conv::read_user(offset, &mut raw)?;
    let pos = i64::from(i32::from_le_bytes(raw));
    let mut stage = Stage::new(ctx, 16)?;
    let at = stage.put(&pos.to_le_bytes())?;
    let Some(ret) = native(ctx, Syscall::Sendfile, args(out_fd, in_fd, at, count, 0, 0)) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        let now = stage::read_back(at, 8)?;
        conv::write_user(offset, &now[..4])?;
    }
    Ok(Some(ret))
}
