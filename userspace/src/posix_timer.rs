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

/// Exit-time disarm: drop the dying task's POSIX timers and interval
/// timers so an expiry after exit can't raise a phantom signal into a
/// dead tid (or, once pids recycle, the wrong process). Part of the
/// `release_task_tables` teardown sweep.
pub fn release_task_timers(task: u64) {
    if let Some(m) = TIMERS.lock().as_mut() {
        m.remove(&task);
    }
    if let Some(m) = ITIMERS.lock().as_mut() {
        m.remove(&task);
    }
}

/// Test hook — directly arm a task's ITIMER_REAL slot, bypassing the
/// `setitimer` syscall path (which needs a TrapContext + user-memory
/// copy). Lets the in-kernel test drive `itimer_real_check_due_irq`
/// deterministically.
#[doc(hidden)]
pub fn __test_arm_itimer_real(task: u64, next_fire_ns: u64, interval_ns: u64) {
    with_itimers(|m| {
        let slots = m.entry(task).or_default();
        slots[ITIMER_REAL as usize] = Itimer {
            next_fire_ns,
            interval_ns,
        };
    });
}

/// Test hook — read a task's ITIMER_REAL next-fire deadline (0 = disarmed).
#[doc(hidden)]
pub fn __test_itimer_real_next_fire(task: u64) -> u64 {
    with_itimers(|m| {
        m.get(&task)
            .map(|s| s[ITIMER_REAL as usize].next_fire_ns)
            .unwrap_or(0)
    })
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
    // clock_nanosleep(clockid, flags, req, rem): arg0=clockid, arg1=flags,
    // arg2=req, arg3=rem.
    let args = *ctx.args();
    nanosleep_common(ctx, args.arg0, args.arg1, args.arg2, args.arg3);
}

/// nanosleep(req, rem): the legacy 2-arg sleep (Linux syscall 35). POSIX
/// measures the relative interval against the monotonic clock. This is
/// NOT NARF's native `sys_sleep` (whose arg0 is a raw nanosecond count) —
/// musl passes a `struct timespec *` in arg0, so it MUST parse the
/// timespec like clock_nanosleep, or the req pointer gets misread as a
/// (years-long) nanosecond duration and the task hangs forever.
pub fn sys_nanosleep(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    nanosleep_common(ctx, CLOCK_MONOTONIC, 0, args.arg0, args.arg1);
}

fn nanosleep_common(
    ctx: &mut dyn TrapContext,
    clockid: u64,
    flags: u64,
    req_ptr: u64,
    _rem_ptr: u64,
) {
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
            if narf_scheduler::stackful::user_own_stack_enabled() {
                crate::handlers::own_stack_block(ctx);
                return;
            }
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
    // Pre-create the task's SIGNAL_PENDING entry now (in syscall context,
    // where allocation is fine) so the IRQ-context `itimer_real_check_due_irq`
    // → `raise_signal_pending_irq` fast path only ever sets a bit in an
    // existing entry — never allocates from the timer trap.
    crate::handlers::ensure_signal_pending_slot(task);
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
    // See sys_setitimer: pre-create the pending slot so the IRQ fast path
    // never allocates.
    crate::handlers::ensure_signal_pending_slot(task);
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

/// IRQ-context fast path for ITIMER_REAL — the half that makes a
/// CPU-bound task's `setitimer`/`alarm` actually fire. The sleep-pump
/// above only runs when *some* task parks (sleep/pause); a task spinning
/// in a tight loop with no syscalls never parks, so without this its
/// real timer would never expire. Mirrors Linux's `it_real_fn` (the
/// ITIMER_REAL hrtimer callback raises SIGALRM straight from hardirq).
///
/// Checks ONLY `task`'s ITIMER_REAL slot (the interrupted task — on a
/// single CPU that's the only one that can be CPU-bound), re-arms a
/// periodic timer / disarms a one-shot, and returns true when SIGALRM
/// is due. Fully alloc-free: takes only the `IrqSafeSpinLock` and never
/// inserts (a missing table / slot just returns false). The caller
/// raises the pending bit via the alloc-free `raise_signal_pending_irq`.
///
/// Re-arming under the lock keeps the slow pump from double-firing: once
/// this advances `next_fire_ns`, the pump sees a future deadline.
pub fn itimer_real_check_due_irq(task: u64, now: u64) -> bool {
    let mut g = ITIMERS.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => return false,
    };
    let slot = match map.get_mut(&task) {
        Some(slots) => &mut slots[ITIMER_REAL as usize],
        None => return false,
    };
    if slot.next_fire_ns == 0 || now < slot.next_fire_ns {
        return false;
    }
    if slot.interval_ns == 0 {
        slot.next_fire_ns = 0;
    } else {
        let fires = ((now - slot.next_fire_ns) / slot.interval_ns).saturating_add(1);
        slot.next_fire_ns = slot
            .next_fire_ns
            .saturating_add(slot.interval_ns.saturating_mul(fires));
    }
    true
}

/// IRQ-context scan of **every** task's ITIMER_REAL slot — the multi-task
/// generalization of [`itimer_real_check_due_irq`]. For each due slot it
/// advances (periodic) / disarms (one-shot) the deadline under the lock and
/// records the owning task id in `out`; returns the number written (bounded
/// by `out.len()` — any overflow stays due and is caught next tick).
///
/// Why this exists: the single-current-task check only ever inspects the
/// *interrupted* task's slot. But a task that arms `setitimer(ITIMER_REAL)`
/// and then PARKS (e.g. blocks in `waitpid`) is never the interrupted task
/// while sibling CPU-bound tasks run — and the sleep-pump that would catch
/// the parked owner starves under that load (each busy task holds its CPU's
/// executor, so no round runs). Linux's `it_real_fn` is a per-process
/// hrtimer that fires regardless of which task is on-CPU; this restores that
/// semantics. Fully alloc-free (advance-in-place under the existing
/// `IrqSafeSpinLock`); the caller raises + wakes each returned task.
///
/// **O(1) stack.** Returns the lowest task id strictly greater than `after`
/// (or the lowest of all, when `after` is `None`) whose `ITIMER_REAL` is due
/// at `now`, advancing that slot in place so a subsequent call skips it.
/// `None` means no more are due. The caller loops, feeding the previous result
/// back as `after`, raising + waking each returned task between calls (so
/// `wake_signal` never runs under the `ITIMERS` lock).
///
/// This replaces an earlier `collect_all(out: &mut [u64])` form: returning the
/// owners through a `[u64; 64]` (~512 B) buffer put that array on the timer
/// IRQ's stack — the *user task's own kernel stack* under the per-task-own-stack
/// model — and that large IRQ-path frame deterministically smashed the timer
/// handler's return chain (`rip=0x3` #UD) under stress-ng fork/exec churn. Same
/// hazard the timer-wheel drain documents (`timer_wheel::drain_due_to_deferred`):
/// no big on-stack buffer in IRQ context.
pub fn itimer_real_take_one_due_irq(now: u64, after: Option<u64>) -> Option<u64> {
    use core::ops::Bound;
    let lower = match after {
        Some(a) => Bound::Excluded(a),
        None => Bound::Unbounded,
    };
    let mut g = ITIMERS.lock();
    let map = g.as_mut()?;
    for (task, slots) in map.range_mut((lower, Bound::Unbounded)) {
        let slot = &mut slots[ITIMER_REAL as usize];
        if slot.next_fire_ns == 0 || now < slot.next_fire_ns {
            continue;
        }
        if slot.interval_ns == 0 {
            slot.next_fire_ns = 0;
        } else {
            let fires = ((now - slot.next_fire_ns) / slot.interval_ns).saturating_add(1);
            slot.next_fire_ns = slot
                .next_fire_ns
                .saturating_add(slot.interval_ns.saturating_mul(fires));
        }
        return Some(*task);
    }
    None
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

// ── ITIMER_REAL IRQ fast-path lifecycle smokes ──────────────────────
//
// `itimer_real_check_due_irq` is the alloc-free hardirq-context half that
// makes a CPU-bound task's `setitimer(ITIMER_REAL)` actually fire (the slow
// `sleep_pumps` half only runs when *some* task parks). It is the mechanism a
// stress-ng worker relies on to be told to stop. These pin its three load-
// bearing behaviours — fire-when-due, one-shot-disarm, periodic-re-arm — which
// were verified live during the SMP `chroot_run` investigation but had no unit
// guard (only the syscall-ABI `setitimer`/`getitimer` smokes existed).

/// A unique task id for the smokes — well outside any real PID so it can't
/// collide with a live task's ITIMER_REAL slot in the shared `ITIMERS` map.
#[cfg(target_arch = "x86_64")]
const ITIMER_SMOKE_TASK: u64 = 0xFEED_0000_0000_0001;

/// One-shot ITIMER_REAL: doesn't fire before its deadline, fires exactly at/
/// after it, then DISARMS (next_fire_ns -> 0) and never re-fires.
#[cfg(target_arch = "x86_64")]
fn smoke_itimer_real_oneshot_fires_then_disarms() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let task = ITIMER_SMOKE_TASK;
    // One-shot (interval 0) due at t=1000.
    __test_arm_itimer_real(task, 1000, 0);
    if itimer_real_check_due_irq(task, 999) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("one-shot fired before its deadline");
    }
    if !itimer_real_check_due_irq(task, 1000) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("one-shot did not fire at its deadline");
    }
    if __test_itimer_real_next_fire(task) != 0 {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("one-shot did not disarm after firing");
    }
    if itimer_real_check_due_irq(task, 5000) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("disarmed one-shot fired again");
    }
    // Leave the slot clean.
    __test_arm_itimer_real(task, 0, 0);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
narf_kernel_test::kernel_test_in!(
    "userspace/posix_timer",
    smoke_itimer_real_oneshot_fires_then_disarms
);

/// Periodic ITIMER_REAL: fires at each deadline and RE-ARMS by exactly one
/// interval; a single check that lands many intervals late catches up in one
/// step (advances `next_fire_ns` strictly past `now`), mirroring Linux's
/// `it_real_fn` overrun handling.
#[cfg(target_arch = "x86_64")]
fn smoke_itimer_real_periodic_rearms_and_catches_up() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let task = ITIMER_SMOKE_TASK;
    // Periodic: first fire at 1000, interval 500.
    __test_arm_itimer_real(task, 1000, 500);
    if !itimer_real_check_due_irq(task, 1000) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("periodic did not fire at first deadline");
    }
    if __test_itimer_real_next_fire(task) != 1500 {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("periodic did not re-arm to next interval (1500)");
    }
    if itimer_real_check_due_irq(task, 1400) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("periodic fired before its re-armed deadline");
    }
    if !itimer_real_check_due_irq(task, 1600) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("periodic did not fire at second deadline");
    }
    if __test_itimer_real_next_fire(task) != 2000 {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("periodic did not re-arm to 2000");
    }
    // Catch-up: a check far past several deadlines fires once and snaps the
    // next deadline strictly past `now` (no re-fire storm).
    if !itimer_real_check_due_irq(task, 10_000) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("periodic did not fire on a late catch-up check");
    }
    let next = __test_itimer_real_next_fire(task);
    if next <= 10_000 {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("catch-up left next_fire_ns at/behind now");
    }
    __test_arm_itimer_real(task, 0, 0);
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
narf_kernel_test::kernel_test_in!(
    "userspace/posix_timer",
    smoke_itimer_real_periodic_rearms_and_catches_up
);

/// A check for a task with NO armed ITIMER_REAL slot is a no-op (returns
/// false), never spuriously raising SIGALRM — the common case on every tick
/// for tasks that never call `setitimer`/`alarm`.
#[cfg(target_arch = "x86_64")]
fn smoke_itimer_real_unarmed_never_fires() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    // A different unique id, left unarmed.
    let task = 0xFEED_0000_0000_0002;
    if itimer_real_check_due_irq(task, u64::MAX) {
        return TestResult::Fail("unarmed ITIMER_REAL spuriously fired");
    }
    // Explicitly disarmed slot (next_fire_ns == 0) also never fires.
    __test_arm_itimer_real(task, 0, 0);
    if itimer_real_check_due_irq(task, u64::MAX) {
        __test_arm_itimer_real(task, 0, 0);
        return TestResult::Fail("explicitly-disarmed ITIMER_REAL fired");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
narf_kernel_test::kernel_test_in!(
    "userspace/posix_timer",
    smoke_itimer_real_unarmed_never_fires
);
