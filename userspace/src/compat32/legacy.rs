//! The i386 entries that predate 64-bit time and 32-bit ids: the
//! `*_time32` forms (`old_timespec32`, `old_timeval32`, `old_utimbuf32`)
//! and the 16-bit uid/gid calls (`kernel/uid16.c`). Each is the native call
//! on converted arguments: times widened to two `i64`s on the caller's
//! stack ([`super::stage`]) and narrowed back, ids widened with
//! `low2highuid` (0xFFFF is -1) and narrowed with `high2lowuid` (an id past
//! 16 bits is the overflow id).

use super::conv;
use super::stage::{self, Stage};
use super::table::{call_native, succeeded};
use crate::errno::{to_ret, EINVAL};
use crate::syscall::{Ia32Abi, Syscall, SyscallArgs, SyscallReturn, TrapContext};

/// `overflowuid` / `overflowgid` (65534).
const OVERFLOW_ID: u32 = 65534;
/// -EINTR as a native return value.
const EINTR_RET: u64 = (-(crate::errno::EINTR)) as u64;

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

fn regs(a: &SyscallArgs) -> [u64; 6] {
    [a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5]
}

fn args_of(r: [u64; 6]) -> SyscallArgs {
    SyscallArgs {
        arg0: r[0],
        arg1: r[1],
        arg2: r[2],
        arg3: r[3],
        arg4: r[4],
        arg5: r[5],
    }
}

/// `r` with the registers `signed` names sign-extended.
fn signed(mut r: [u64; 6], signed: u8) -> [u64; 6] {
    for (i, v) in r.iter_mut().enumerate() {
        if signed & (1 << i) != 0 {
            *v = conv::sext(*v);
        }
    }
    r
}

// ── 32-bit times ──────────────────────────────────────────────────────

/// When a 32-bit-time call's outputs are copied back.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum Out {
    /// On success (a `tp` / `old_value` result).
    Success,
    /// When the call was interrupted (-EINTR): a sleep's `rem`.
    Interrupted,
}

/// A 32-bit-time call: `variant` with the arguments `mask` names
/// sign-extended, the arguments `ins` names pointing at `count` 8-byte
/// times to widen, and the arguments `outs` names receiving `count` times
/// to narrow back (`when`).
pub(crate) struct Time32 {
    pub(crate) variant: Syscall,
    pub(crate) mask: u8,
    pub(crate) ins: &'static [(usize, usize)],
    pub(crate) outs: &'static [(usize, usize)],
    pub(crate) when: Out,
}

/// Serve `call` (see [`Time32`]).
pub(crate) fn time32(ctx: &mut dyn TrapContext, call: &Time32) -> Option<Syscall> {
    let result = time32_staged(ctx, call);
    finish(ctx, call.variant, result)
}

fn time32_staged(ctx: &mut dyn TrapContext, call: &Time32) -> Result<Option<SyscallReturn>, i64> {
    let user = signed(regs(ctx.args()), call.mask);
    let mut native = user;
    let mut stage = Stage::new(ctx, (call.ins.len() + call.outs.len()) * 64 + 16)?;
    for &(idx, count) in call.ins {
        if user[idx] == 0 {
            continue;
        }
        let mut raw = alloc::vec![0u8; count * 8];
        conv::read_user(user[idx], &mut raw)?;
        let mut wide = alloc::vec![0u8; count * 16];
        for i in 0..count * 2 {
            let v = i64::from(conv::word(&raw, i) as i32);
            wide[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        native[idx] = stage.put(&wide)?;
    }
    let mut staged_outs = [(0u64, 0u64, 0usize); 2];
    for (slot, &(idx, count)) in staged_outs.iter_mut().zip(call.outs) {
        if user[idx] != 0 {
            let at = stage.put(&alloc::vec![0u8; count * 16])?;
            native[idx] = at;
            *slot = (user[idx], at, count);
        }
    }
    let Some(ret) = call_native(ctx, call.variant, args_of(native), Ia32Abi::default()) else {
        return Ok(None);
    };
    let copy = match call.when {
        Out::Success => succeeded(&ret),
        Out::Interrupted => ret.value == EINTR_RET,
    };
    if copy {
        for &(to, from, count) in &staged_outs {
            if to == 0 {
                continue;
            }
            let wide = stage::read_back(from, count * 16)?;
            let mut narrow = alloc::vec![0u8; count * 8];
            for i in 0..count * 2 {
                narrow[i * 4..i * 4 + 4].copy_from_slice(&wide[i * 8..i * 8 + 4]);
            }
            conv::write_user(to, &narrow)?;
        }
    }
    Ok(Some(ret))
}

/// The i386 `*_time32` calls by number (`syscall_32.tbl`'s `sys_*_time32`
/// / `sys_*32` entries): which arguments are `old_timespec32` (or
/// `old_timeval32` / `old_utimbuf32`) inputs and outputs, and how many.
pub(crate) fn time32_nr(ctx: &mut dyn TrapContext, nr: u32) -> Option<Syscall> {
    use super::table::nr::*;
    const NONE: &[(usize, usize)] = &[];
    fn t(
        variant: Syscall,
        mask: u8,
        ins: &'static [(usize, usize)],
        outs: &'static [(usize, usize)],
        when: Out,
    ) -> Time32 {
        Time32 {
            variant,
            mask,
            ins,
            outs,
            when,
        }
    }
    let call = match nr {
        NANOSLEEP => t(
            Syscall::Nanosleep,
            0,
            &[(0, 1)],
            &[(1, 1)],
            Out::Interrupted,
        ),
        CLOCK_NANOSLEEP => {
            // TIMER_ABSTIME: Linux leaves `rem` alone.
            const TIMER_ABSTIME: u64 = 1;
            let outs: &'static [(usize, usize)] = if ctx.args().arg1 & TIMER_ABSTIME != 0 {
                NONE
            } else {
                &[(3, 1)]
            };
            t(
                Syscall::ClockNanosleep,
                0b11,
                &[(2, 1)],
                outs,
                Out::Interrupted,
            )
        }
        CLOCK_SETTIME => t(Syscall::ClockSetTime, 0b1, &[(1, 1)], NONE, Out::Success),
        CLOCK_GETRES => t(Syscall::ClockGetres, 0b1, NONE, &[(1, 1)], Out::Success),
        TIMER_SETTIME => t(
            Syscall::TimerSettime,
            0b11,
            &[(2, 2)],
            &[(3, 2)],
            Out::Success,
        ),
        TIMER_GETTIME => t(Syscall::TimerGettime, 0b1, NONE, &[(1, 2)], Out::Success),
        TIMERFD_SETTIME => t(
            Syscall::TimerfdSettime,
            0b11,
            &[(2, 2)],
            &[(3, 2)],
            Out::Success,
        ),
        TIMERFD_GETTIME => t(Syscall::TimerfdGettime, 0b1, NONE, &[(1, 2)], Out::Success),
        UTIMENSAT => t(Syscall::Utimensat, 0b1001, &[(2, 2)], NONE, Out::Success),
        FUTIMESAT => t(Syscall::Futimesat, 0b1, &[(2, 2)], NONE, Out::Success),
        UTIMES => t(Syscall::Utimes, 0, &[(1, 2)], NONE, Out::Success),
        UTIME => t(Syscall::Utime, 0, &[(1, 1)], NONE, Out::Success),
        SCHED_RR_GET_INTERVAL => t(
            Syscall::SchedRrGetInterval,
            0b1,
            NONE,
            &[(1, 1)],
            Out::Success,
        ),
        IO_GETEVENTS => t(Syscall::IoGetevents, 0b110, &[(4, 1)], NONE, Out::Success),
        MQ_TIMEDSEND => t(Syscall::MqTimedsend, 0b1, &[(4, 1)], NONE, Out::Success),
        MQ_TIMEDRECEIVE => t(Syscall::MqTimedreceive, 0b1, &[(4, 1)], NONE, Out::Success),
        _ => {
            ctx.set_return(SyscallReturn::not_implemented());
            return None;
        }
    };
    time32(ctx, &call)
}

// ── 16-bit ids ────────────────────────────────────────────────────────

/// `low2highuid`: a 16-bit id, with 0xFFFF (-1) kept as -1.
fn low2high(id: u64) -> u64 {
    let id = id & 0xFFFF;
    if id == 0xFFFF {
        0xFFFF_FFFF
    } else {
        id
    }
}

/// `high2lowuid`: the overflow id for an id past 16 bits.
fn high2low(id: u32) -> u16 {
    if id > 0xFFFF {
        OVERFLOW_ID as u16
    } else {
        id as u16
    }
}

/// A 16-bit-id setter (`chown16`, `setuid16`, `setresuid16`, ...): the
/// arguments `ids` names widened with `low2highuid`.
pub(crate) fn set_ids16(ctx: &mut dyn TrapContext, variant: Syscall, ids: u8) -> Option<Syscall> {
    let mut r = regs(ctx.args());
    for (i, v) in r.iter_mut().enumerate() {
        if ids & (1 << i) != 0 {
            *v = low2high(*v);
        }
    }
    super::table::forward_args(ctx, variant, args_of(r), Ia32Abi::default())
}

/// `getresuid16` / `getresgid16(r, e, s)`: the three ids narrowed to
/// `old_uid_t`.
pub(crate) fn getres_ids16(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    let result = getres_staged(ctx, variant);
    finish(ctx, variant, result)
}

fn getres_staged(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
) -> Result<Option<SyscallReturn>, i64> {
    let user = regs(ctx.args());
    let mut stage = Stage::new(ctx, 64)?;
    let at = [
        stage.put(&[0u8; 4])?,
        stage.put(&[0u8; 4])?,
        stage.put(&[0u8; 4])?,
    ];
    let a = SyscallArgs {
        arg0: at[0],
        arg1: at[1],
        arg2: at[2],
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let Some(ret) = call_native(ctx, variant, a, Ia32Abi::default()) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        for i in 0..3 {
            let id = stage::read_back(at[i], 4)?;
            let id = high2low(u32::from_le_bytes([id[0], id[1], id[2], id[3]]));
            conv::write_user(user[i], &id.to_le_bytes())?;
        }
    }
    Ok(Some(ret))
}

/// `NGROUPS_MAX`.
const NGROUPS_MAX: u64 = 65536;

/// `getgroups16(gidsetsize, grouplist)` (80): the groups narrowed to
/// `old_gid_t`; a negative size is EINVAL, a zero one only counts.
pub(crate) fn getgroups16(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = getgroups16_staged(ctx);
    finish(ctx, Syscall::Getgroups, result)
}

fn getgroups16_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let size = a.arg0 as u32 as i32;
    if size < 0 {
        return Err(EINVAL);
    }
    let size = (size as u64).min(NGROUPS_MAX) as usize;
    let mut stage = Stage::new(ctx, size * 4 + 16)?;
    let at = if size == 0 {
        0
    } else {
        stage.put(&alloc::vec![0u8; size * 4])?
    };
    let native = SyscallArgs {
        arg0: size as u64,
        arg1: at,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let Some(ret) = call_native(ctx, Syscall::Getgroups, native, Ia32Abi::default()) else {
        return Ok(None);
    };
    if succeeded(&ret) && size != 0 {
        let n = (ret.value as usize).min(size);
        let wide = stage::read_back(at, n * 4)?;
        let narrow: alloc::vec::Vec<u8> = wide
            .chunks_exact(4)
            .flat_map(|c| high2low(u32::from_le_bytes([c[0], c[1], c[2], c[3]])).to_le_bytes())
            .collect();
        conv::write_user(a.arg1, &narrow)?;
    }
    Ok(Some(ret))
}

/// `setgroups16(gidsetsize, grouplist)` (81): the 16-bit groups widened
/// with `low2highgid`; a size past NGROUPS_MAX is EINVAL.
pub(crate) fn setgroups16(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let result = setgroups16_staged(ctx);
    finish(ctx, Syscall::Setgroups, result)
}

fn setgroups16_staged(ctx: &mut dyn TrapContext) -> Result<Option<SyscallReturn>, i64> {
    let a = *ctx.args();
    let size = u64::from(a.arg0 as u32);
    if size > NGROUPS_MAX {
        return Err(EINVAL);
    }
    let size = size as usize;
    let mut raw = alloc::vec![0u8; size * 2];
    if size != 0 {
        conv::read_user(a.arg1, &mut raw)?;
    }
    let wide: alloc::vec::Vec<u8> = raw
        .chunks_exact(2)
        .flat_map(|c| (low2high(u64::from(u16::from_le_bytes([c[0], c[1]]))) as u32).to_le_bytes())
        .collect();
    let mut stage = Stage::new(ctx, size * 4 + 16)?;
    let at = if size == 0 { 0 } else { stage.put(&wide)? };
    let native = SyscallArgs {
        arg0: size as u64,
        arg1: at,
        arg2: 0,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    Ok(call_native(
        ctx,
        Syscall::Setgroups,
        native,
        Ia32Abi::default(),
    ))
}
