//! Wave-73 — POSIX per-process timers (`timer_create` / `timer_settime`
//! / `timer_gettime` / `timer_delete`) + `clock_nanosleep`.
//!
//! Signal-delivered sibling of `timerfd_*`. A timer is a (clockid,
//! sigevent) tuple stored per-task; arming records an
//! `itimerspec` (initial + interval). A `sleep_pumps` callback walks
//! the table on every scheduler tick and, on expiry, ORs the signum
//! bit into the per-task `SIGNAL_PENDING` bitmap via the same path
//! `kill(2)` uses, so the next return-to-user picks the signal up
//! through the existing Wave-51/55 delivery hook.
//!
//! Gated under `#[cfg(feature = "linux-compat")]`. The kernel core
//! pays nothing when the feature is off.
//!
//! The `linux-compat` gate lives on the `pub mod posix_timer;` line in
//! `lib.rs`; no inner `#![cfg]` here (it would duplicate that gate).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

use crate::handlers::{current_task_id, raise_signal_pending};
use crate::syscall::{SyscallReturn, TrapContext};

// ── clockids accepted by `timer_create` / `clock_nanosleep` ──────────
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_BOOTTIME: u64 = 7;

// ── `sigevent.sigev_notify` ──────────────────────────────────────────
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;

// ── `timer_settime` flags ────────────────────────────────────────────
const TIMER_ABSTIME: u64 = 1;

const SIGALRM: u32 = 14;

/// One armed POSIX timer.
#[derive(Debug, Clone, Copy)]
struct PosixTimer {
    /// Owning task.
    task: u64,
    /// One of CLOCK_REALTIME / CLOCK_MONOTONIC(_RAW) / CLOCK_BOOTTIME.
    /// Realtime currently shares the monotonic source — no NTP yet.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    clockid: u64,
    /// Signum to raise on expiry (SIGEV_SIGNAL); 0 = SIGEV_NONE.
    signum: u32,
    /// Absolute monotonic-ns deadline for the next fire; 0 = disarmed.
    next_fire_ns: u64,
    /// Re-arm interval in ns; 0 = one-shot.
    interval_ns: u64,
    /// Expiries that fired since the last `timer_getoverrun` /
    /// `timer_gettime` — visible to the test harness.
    overrun: u32,
}

#[derive(Debug, Default)]
struct TimerTable {
    /// Monotonic timerid allocator (per process — Linux scopes
    /// timerids per process too).
    next_id: u32,
    /// Active timers keyed by timerid.
    by_id: BTreeMap<u32, PosixTimer>,
}

static TIMERS: IrqSafeSpinLock<Option<BTreeMap<u64, TimerTable>>> = IrqSafeSpinLock::new(None);
static PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Boot-time init — call once before any user task issues a
/// `timer_create`. Idempotent.
pub fn posix_timer_init() {
    *TIMERS.lock() = Some(BTreeMap::new());
    *ITIMERS.lock() = Some(BTreeMap::new());
    if !PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
        // Register a sleep-pump so timer expiries fire even while a
        // user task is parked in `sys_sleep` / `sys_clock_nanosleep`.
        narf_scheduler::sleep_pumps::register(posix_timer_pump);
    }
}

/// Test hook — drop every timer.
#[doc(hidden)]
pub fn __test_reset() {
    *TIMERS.lock() = Some(BTreeMap::new());
    *ITIMERS.lock() = Some(BTreeMap::new());
}

fn with_table<R>(f: impl FnOnce(&mut BTreeMap<u64, TimerTable>) -> R) -> Option<R> {
    let mut g = TIMERS.lock();
    g.as_mut().map(f)
}

fn read_timespec(buf: &[u8; 16]) -> (i64, i64) {
    let s = i64::from_le_bytes(buf[..8].try_into().unwrap());
    let n = i64::from_le_bytes(buf[8..].try_into().unwrap());
    (s, n)
}

fn write_timespec(out: &mut [u8; 16], sec: i64, nsec: i64) {
    out[..8].copy_from_slice(&sec.to_le_bytes());
    out[8..].copy_from_slice(&nsec.to_le_bytes());
}

fn timespec_to_ns(sec: i64, nsec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    Some(
        (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec as u64),
    )
}

fn ns_to_timespec(ns: u64) -> (i64, i64) {
    ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
}

// ── sigevent (Linux layout, first 16 bytes carry what we honour) ────
//
// struct sigevent {
//     sigval_t sigev_value;     // 8 B
//     int      sigev_signo;     // 4 B
//     int      sigev_notify;    // 4 B
//     ...                       // padding/union we don't read
// };
//
// 16 bytes is enough to decide SIGEV_SIGNAL vs SIGEV_NONE/THREAD and
// pick the signum.
fn parse_sigevent(buf: &[u8; 16]) -> (i32, u32) {
    let signo = i32::from_le_bytes(buf[8..12].try_into().unwrap());
    let notify = i32::from_le_bytes(buf[12..16].try_into().unwrap());
    (notify, signo as u32)
}

/// timer_create(clockid, sigevent, timerid_out)
pub fn sys_timer_create(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let clockid = args.arg0;
    let evp = args.arg1;
    let out_ptr = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);

    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => {}
        _ => {
            ctx.set_return(fail);
            return;
        }
    }
    if out_ptr == 0 {
        ctx.set_return(fail);
        return;
    }

    // Default: SIGEV_SIGNAL + SIGALRM (Linux default when evp == NULL).
    let (notify, signum) = if evp == 0 {
        (SIGEV_SIGNAL, SIGALRM)
    } else {
        let mut kbuf = [0u8; 16];
        // SAFETY: handler runs in the calling task's address space;
        // `copy_from_user` validates the user pointer + SMAP brackets.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(&mut kbuf, evp) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        parse_sigevent(&kbuf)
    };
    let effective_signum = match notify {
        SIGEV_SIGNAL => {
            if signum == 0 || signum >= 32 {
                ctx.set_return(fail);
                return;
            }
            signum
        }
        SIGEV_NONE | SIGEV_THREAD => 0, // SIGEV_THREAD: no real thread support, treat as NONE.
        _ => {
            ctx.set_return(fail);
            return;
        }
    };

    let task = current_task_id();
    let id = with_table(|m| {
        let t = m.entry(task).or_default();
        t.next_id = t.next_id.wrapping_add(1);
        if t.next_id == 0 {
            t.next_id = 1;
        }
        let id = t.next_id;
        t.by_id.insert(
            id,
            PosixTimer {
                task,
                clockid,
                signum: effective_signum,
                next_fire_ns: 0,
                interval_ns: 0,
                overrun: 0,
            },
        );
        id
    });
    let id = match id {
        Some(i) => i,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Write the timerid (kernel_timer_t is a `void*`-sized opaque on
    // Linux; we emit a u32 zero-extended to 8 B to keep wire-size
    // sane on both 32/64-bit consumers).
    let id_bytes = (id as u64).to_le_bytes();
    // SAFETY: `out_ptr` is a user address; `copy_to_user` range-validates it
    // and brackets the 8-byte write in the SMAP window. We run in the calling
    // task's address space from the syscall path (not IRQ context).
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_to_user(out_ptr, &id_bytes) }.is_err() {
        // Best-effort cleanup.
        with_table(|m| {
            if let Some(t) = m.get_mut(&task) {
                t.by_id.remove(&id);
            }
        });
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// timer_settime(timerid, flags, new, old)
pub fn sys_timer_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0 as u32;
    let flags = args.arg1;
    let new_ptr = args.arg2;
    let old_ptr = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if new_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let mut buf = [0u8; 32];
    // SAFETY: `new_ptr` is checked non-zero above and is a user address;
    // `copy_from_user` range-validates it and brackets the 32-byte read in the
    // SMAP window. Runs in the calling task's address space, not IRQ context.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_from_user(&mut buf, new_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let (int_s, int_n) = read_timespec(buf[0..16].try_into().unwrap());
    let (val_s, val_n) = read_timespec(buf[16..32].try_into().unwrap());
    let (interval_ns, value_ns) = match (timespec_to_ns(int_s, int_n), timespec_to_ns(val_s, val_n))
    {
        (Some(i), Some(v)) => (i, v),
        _ => {
            ctx.set_return(fail);
            return;
        }
    };

    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if value_ns == 0 {
        0 // disarm
    } else if flags & TIMER_ABSTIME != 0 {
        value_ns
    } else {
        now.saturating_add(value_ns)
    };

    let prev = with_table(|m| {
        let t = m.get_mut(&task)?;
        let entry = t.by_id.get_mut(&id)?;
        let prev_next = entry.next_fire_ns;
        let prev_interval = entry.interval_ns;
        entry.next_fire_ns = next_fire;
        entry.interval_ns = interval_ns;
        entry.overrun = 0;
        Some((prev_next, prev_interval))
    })
    .flatten();
    let (prev_next, prev_interval) = match prev {
        Some(p) => p,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    if old_ptr != 0 {
        let remaining = prev_next.saturating_sub(now);
        let mut out = [0u8; 32];
        let (is, in_) = ns_to_timespec(prev_interval);
        let (vs, vn) = ns_to_timespec(remaining);
        write_timespec((&mut out[0..16]).try_into().unwrap(), is, in_);
        write_timespec((&mut out[16..32]).try_into().unwrap(), vs, vn);
        // SAFETY: `old_ptr` is checked non-zero above and is a user address;
        // `copy_to_user` range-validates it and brackets the 32-byte write in
        // the SMAP window. Runs in the calling task's address space, not IRQ
        // context. Best-effort: a failed copy is ignored per POSIX old-value.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(old_ptr, &out) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// timer_gettime(timerid, cur)
pub fn sys_timer_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0 as u32;
    let out_ptr = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let snap = with_table(|m| {
        let t = m.get(&task)?;
        let e = t.by_id.get(&id)?;
        Some((e.next_fire_ns, e.interval_ns))
    })
    .flatten();
    let (next, interval) = match snap {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let remaining = if next == 0 {
        0
    } else {
        next.saturating_sub(now)
    };
    let mut out = [0u8; 32];
    let (is, in_) = ns_to_timespec(interval);
    let (vs, vn) = ns_to_timespec(remaining);
    write_timespec((&mut out[0..16]).try_into().unwrap(), is, in_);
    write_timespec((&mut out[16..32]).try_into().unwrap(), vs, vn);
    // SAFETY: `out_ptr` is checked non-zero above and is a user address;
    // `copy_to_user` range-validates it and brackets the 32-byte write in the
    // SMAP window. Runs in the calling task's address space, not IRQ context.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_to_user(out_ptr, &out) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// timer_delete(timerid)
pub fn sys_timer_delete(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0 as u32;
    let task = current_task_id();
    let removed = with_table(|m| m.get_mut(&task).and_then(|t| t.by_id.remove(&id)).is_some())
        .unwrap_or(false);
    if removed {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
    }
}

/// clock_nanosleep(clockid, flags, request, remain)
pub fn sys_clock_nanosleep(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let clockid = args.arg0;
    let flags = args.arg1;
    let req_ptr = args.arg2;
    let _rem_ptr = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => {}
        _ => {
            ctx.set_return(fail);
            return;
        }
    }
    if req_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let mut buf = [0u8; 16];
    // SAFETY: `req_ptr` is checked non-zero above and is a user address;
    // `copy_from_user` range-validates it and brackets the 16-byte read in the
    // SMAP window. Runs in the calling task's address space, not IRQ context.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_from_user(&mut buf, req_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let (sec, nsec) = read_timespec(&buf);
    let target_ns = match timespec_to_ns(sec, nsec) {
        Some(v) => v,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let now = narf_scheduler::narf_time::monotonic_ns();
    let delta = if flags & TIMER_ABSTIME != 0 {
        target_ns.saturating_sub(now)
    } else {
        target_ns
    };
    if delta == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let deadline = now.saturating_add(delta);

    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        if let Some(h) = crate::signal_delivery_hook() {
            h(ctx, crate::Syscall::ClockNanosleep.raw());
        }

        ctx.set_return(SyscallReturn::ok(0));
        // SAFETY: `uctx` is the `*mut UserTaskCtx` returned by
        // `current_user_task()` for the running task; it points to the live
        // per-task context owned by the scheduler and outlives this syscall.
        // We hold the task here (no concurrent mutator), so the `&*uctx`
        // borrow, the interior-mutable atomic/Cell stores, `save_user_state`
        // into `uc.state`, and the matching `yield_hook` call are sound.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let uc = &*uctx;
            uc.sleep_deadline_ns
                .store(deadline, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            hook(uctx);
        }
        // unreachable
    }

    while narf_scheduler::narf_time::monotonic_ns() < deadline {
        narf_scheduler::sleep_pumps::run();
        core::hint::spin_loop();
    }
    ctx.set_return(SyscallReturn::ok(0));
}

// ── setitimer / getitimer / alarm (ITIMER_REAL → SIGALRM) ────────────
//
// BSD-derived interval timers. Linux has three `which` slots:
//   ITIMER_REAL    (0) — wall-clock; delivers SIGALRM.
//   ITIMER_VIRTUAL (1) — user CPU time; delivers SIGVTALRM.
//   ITIMER_PROF    (2) — user+sys CPU time; delivers SIGPROF.
// NARF fully wires ITIMER_REAL (driven by the same `sleep_pumps` pump
// as the POSIX timers above). VIRTUAL/PROF have no CPU-time accounting
// yet, so they round-trip through set/getitimer but never fire.

const ITIMER_REAL: u64 = 0;
const ITIMER_PROF: u64 = 2;

/// One `which` slot's armed state. `itimerval` carries microseconds,
/// not nanoseconds — converted to ns on the way in.
#[derive(Debug, Clone, Copy, Default)]
struct Itimer {
    /// Absolute monotonic-ns deadline for the next fire; 0 = disarmed.
    next_fire_ns: u64,
    /// Re-arm interval in ns; 0 = one-shot.
    interval_ns: u64,
}

/// Per-task `[ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF]`.
static ITIMERS: IrqSafeSpinLock<Option<BTreeMap<u64, [Itimer; 3]>>> = IrqSafeSpinLock::new(None);

fn with_itimers<R>(f: impl FnOnce(&mut BTreeMap<u64, [Itimer; 3]>) -> R) -> R {
    // Lazily initialise — `posix_timer_init` is only called from the
    // in-kernel test harness, not the boot path, so the real-boot
    // arming syscalls must stand up the table themselves.
    let mut g = ITIMERS.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    f(m)
}

/// Ensure the `sleep_pumps` callback that fires interval timers is
/// registered. Idempotent — the boot path never calls
/// `posix_timer_init`, so the first armed itimer wires the pump.
fn ensure_pump_registered() {
    if !PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
        narf_scheduler::sleep_pumps::register(posix_timer_pump);
    }
}

fn read_timeval(buf: &[u8; 16]) -> (i64, i64) {
    let s = i64::from_le_bytes(buf[..8].try_into().unwrap());
    let us = i64::from_le_bytes(buf[8..].try_into().unwrap());
    (s, us)
}

fn write_timeval(out: &mut [u8; 16], sec: i64, usec: i64) {
    out[..8].copy_from_slice(&sec.to_le_bytes());
    out[8..].copy_from_slice(&usec.to_le_bytes());
}

fn timeval_to_ns(sec: i64, usec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return None;
    }
    Some(
        (sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add((usec as u64).saturating_mul(1000)),
    )
}

fn ns_to_timeval(ns: u64) -> (i64, i64) {
    (
        (ns / 1_000_000_000) as i64,
        ((ns % 1_000_000_000) / 1000) as i64,
    )
}

/// Snapshot a slot's remaining-value + interval into a 32-byte
/// `struct itimerval` (it_interval then it_value).
fn write_itimerval(out: &mut [u8; 32], slot: Itimer, now: u64) {
    let remaining = if slot.next_fire_ns == 0 {
        0
    } else {
        slot.next_fire_ns.saturating_sub(now)
    };
    let (is, iu) = ns_to_timeval(slot.interval_ns);
    let (vs, vu) = ns_to_timeval(remaining);
    write_timeval((&mut out[0..16]).try_into().unwrap(), is, iu);
    write_timeval((&mut out[16..32]).try_into().unwrap(), vs, vu);
}

/// setitimer(which, new, old)
pub fn sys_setitimer(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0;
    let new_ptr = args.arg1;
    let old_ptr = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which > ITIMER_PROF || new_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let mut buf = [0u8; 32];
    // SAFETY: `new_ptr` is checked non-zero above and is a user address;
    // `copy_from_user` range-validates it and brackets the 32-byte read in the
    // SMAP window. Runs in the calling task's address space, not IRQ context.
    if unsafe { crate::handlers::copy_from_user(&mut buf, new_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let (int_s, int_us) = read_timeval(buf[0..16].try_into().unwrap());
    let (val_s, val_us) = read_timeval(buf[16..32].try_into().unwrap());
    let (interval_ns, value_ns) = match (timeval_to_ns(int_s, int_us), timeval_to_ns(val_s, val_us))
    {
        (Some(i), Some(v)) => (i, v),
        _ => {
            ctx.set_return(fail);
            return;
        }
    };

    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if value_ns == 0 {
        0
    } else {
        now.saturating_add(value_ns)
    };

    ensure_pump_registered();
    let prev = with_itimers(|m| {
        let slots = m.entry(task).or_default();
        let prev = slots[which as usize];
        slots[which as usize] = Itimer {
            next_fire_ns: next_fire,
            interval_ns,
        };
        prev
    });

    if old_ptr != 0 {
        let mut out = [0u8; 32];
        write_itimerval(&mut out, prev, now);
        // SAFETY: `old_ptr` is checked non-zero above and is a user address;
        // `copy_to_user` range-validates it and brackets the 32-byte write in
        // the SMAP window. Runs in the calling task's address space, not IRQ
        // context. Best-effort: a failed copy is ignored per the old-value API.
        let _ = unsafe { crate::handlers::copy_to_user(old_ptr, &out) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// getitimer(which, cur)
pub fn sys_getitimer(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0;
    let out_ptr = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which > ITIMER_PROF || out_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let slot = with_itimers(|m| m.get(&task).map(|s| s[which as usize]).unwrap_or_default());
    let mut out = [0u8; 32];
    write_itimerval(&mut out, slot, now);
    // SAFETY: `out_ptr` is checked non-zero above and is a user address;
    // `copy_to_user` range-validates it and brackets the 32-byte write in the
    // SMAP window. Runs in the calling task's address space, not IRQ context.
    if unsafe { crate::handlers::copy_to_user(out_ptr, &out) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// alarm(seconds) — convenience wrapper over ITIMER_REAL with no
/// interval. Returns the previous alarm's remaining whole seconds
/// (rounded up), or 0 if none was armed.
pub fn sys_alarm(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let secs = args.arg0;
    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if secs == 0 {
        0
    } else {
        now.saturating_add(secs.saturating_mul(1_000_000_000))
    };

    ensure_pump_registered();
    let prev = with_itimers(|m| {
        let slots = m.entry(task).or_default();
        let prev = slots[ITIMER_REAL as usize];
        slots[ITIMER_REAL as usize] = Itimer {
            next_fire_ns: next_fire,
            interval_ns: 0,
        };
        prev
    });

    let prev_remaining = if prev.next_fire_ns == 0 {
        0
    } else {
        // Round up to whole seconds, like Linux.
        prev.next_fire_ns
            .saturating_sub(now)
            .saturating_add(999_999_999)
            / 1_000_000_000
    };
    ctx.set_return(SyscallReturn::ok(prev_remaining));
}

/// Sleep-pump half for ITIMER_REAL — collect SIGALRM deliveries for
/// every task whose real-timer slot has expired, re-arming periodic
/// timers. Called from `posix_timer_pump` under no lock nesting.
fn itimer_pump_collect(now: u64, deliveries: &mut Vec<(u64, u32)>) {
    let mut g = ITIMERS.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => return,
    };
    for (task, slots) in map.iter_mut() {
        let slot = &mut slots[ITIMER_REAL as usize];
        if slot.next_fire_ns == 0 || now < slot.next_fire_ns {
            continue;
        }
        deliveries.push((*task, SIGALRM));
        if slot.interval_ns == 0 {
            slot.next_fire_ns = 0;
        } else {
            let fires = ((now - slot.next_fire_ns) / slot.interval_ns).saturating_add(1);
            slot.next_fire_ns = slot
                .next_fire_ns
                .saturating_add(slot.interval_ns.saturating_mul(fires));
        }
    }
}

/// Sleep-pump: walks every per-task timer table, fires expired
/// signals via the existing `raise_signal_pending` path. Re-arms
/// periodic timers. Counts missed expiries into `overrun`.
fn posix_timer_pump() {
    let now = narf_scheduler::narf_time::monotonic_ns();
    // Collect (task, signum) pairs under the lock; deliver after
    // releasing it so we don't nest SIGNAL_PENDING under TIMERS.
    let mut deliveries: Vec<(u64, u32)> = Vec::new();
    {
        // The POSIX-timer table may be uninitialised in a real boot
        // (`posix_timer_init` only runs in the test harness). Skip its
        // walk when absent rather than aborting the whole pump — the
        // itimer half below stands up its own table on first use.
        let mut g = TIMERS.lock();
        if let Some(map) = g.as_mut() {
            for (_task, table) in map.iter_mut() {
                for (_id, t) in table.by_id.iter_mut() {
                    if t.next_fire_ns == 0 || now < t.next_fire_ns {
                        continue;
                    }
                    let fires = if t.interval_ns == 0 {
                        1
                    } else {
                        ((now - t.next_fire_ns) / t.interval_ns).saturating_add(1)
                    };
                    t.overrun = t.overrun.saturating_add(fires.saturating_sub(1) as u32);
                    if t.signum != 0 {
                        // Queue one signal — POSIX collapses missed
                        // expiries into a single signal + overrun count.
                        deliveries.push((t.task, t.signum));
                    }
                    if t.interval_ns == 0 {
                        t.next_fire_ns = 0;
                    } else {
                        t.next_fire_ns = t
                            .next_fire_ns
                            .saturating_add(t.interval_ns.saturating_mul(fires));
                    }
                }
            }
        }
    }
    itimer_pump_collect(now, &mut deliveries);
    for (task, signum) in deliveries {
        raise_signal_pending(task, signum);
    }
}

/// Diagnostic for the smokes — peek the overrun counter.
#[doc(hidden)]
pub fn overrun_of(task: u64, id: u32) -> Option<u32> {
    with_table(|m| {
        m.get(&task)
            .and_then(|t| t.by_id.get(&id))
            .map(|t| t.overrun)
    })
    .flatten()
}

/// Diagnostic for the smokes — peek the next-fire deadline.
#[doc(hidden)]
pub fn next_fire_of(task: u64, id: u32) -> Option<u64> {
    with_table(|m| {
        m.get(&task)
            .and_then(|t| t.by_id.get(&id))
            .map(|t| t.next_fire_ns)
    })
    .flatten()
}

/// Force the pump to run — for tests that don't have a real
/// scheduler tick driving `sleep_pumps`.
#[doc(hidden)]
pub fn __test_run_pump() {
    posix_timer_pump();
}
