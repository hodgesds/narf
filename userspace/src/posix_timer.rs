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
/// A modifier bit, not a value: `SIGEV_SIGNAL | SIGEV_THREAD_ID` means
/// "queue the signal to the thread named in `sigev_notify_thread_id`".
/// glibc's `SIGEV_THREAD` implementation rewrites the user's sigevent to
/// exactly that before issuing `timer_create`, so rejecting it breaks
/// every `SIGEV_THREAD` timer in a glibc program.
const SIGEV_THREAD_ID: i32 = 4;

// ── `timer_settime` flags ────────────────────────────────────────────
const TIMER_ABSTIME: u64 = 1;

const SIGALRM: u32 = 14;
/// `good_sigevent()` bounds `sigev_signo` by `SIGRTMAX`, which is 64 on
/// every Linux ABI NARF targets.
const SIGRTMAX: i32 = 64;

// ── errnos, returned the way every other Linux-compat handler does ───
//
// These used to be a bare `-1`. A `-1` return is not a sentinel once it
// crosses into libc: the syscall stub sees a value in [-4095, -1] and
// reports `-ret` as `errno`, so `-1` arrives as errno 1 = EPERM. Every
// failure in this file — a stale timer id, a faulting `itimerspec`, an
// unknown clock, an out-of-range `which` — therefore looked to a caller
// like a permission denial, which is the one diagnosis none of them
// admit: none of these syscalls has a privileged variant, so there is
// nothing for the caller to acquire and no reason for `strace` output
// to say "Operation not permitted". The errnos below are what Linux
// actually returns, and they are separable answers: EINVAL means "fix
// the argument", EFAULT means "fix the pointer", EOPNOTSUPP means "this
// kernel does not implement it, use your fallback".
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EOPNOTSUPP: i64 = 95;

/// Linux hands errors back as a negated errno in the return register.
fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}

// ── `clockid_t` as the 32-bit `int` the ABI actually delivers ────────
//
// `kernel/time/posix-timers.c::posix_clocks[]`. Kept separate from the
// `u64` constants above (which `clock_nanosleep`'s accept-list still
// matches on) because `timer_create` has to classify the *whole* table:
// a clockid Linux knows but cannot arm a timer on is EOPNOTSUPP, while
// one it does not know at all is EINVAL, and the two are not
// interchangeable to a caller probing for clock support.
const CLOCKID_REALTIME: i32 = 0;
const CLOCKID_MONOTONIC: i32 = 1;
const CLOCKID_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCKID_THREAD_CPUTIME_ID: i32 = 3;
const CLOCKID_MONOTONIC_RAW: i32 = 4;
const CLOCKID_REALTIME_COARSE: i32 = 5;
const CLOCKID_MONOTONIC_COARSE: i32 = 6;
const CLOCKID_BOOTTIME: i32 = 7;
const CLOCKID_REALTIME_ALARM: i32 = 8;
const CLOCKID_BOOTTIME_ALARM: i32 = 9;
const CLOCKID_TAI: i32 = 11;

/// Largest timerid `lock_timer()` will look up — see [`timer_id_arg`].
const TIMER_ID_MAX: u32 = i32::MAX as u32;

/// `kernel/time/posix-timers.c::lock_timer`:
///
/// ```text
///     /*
///      * timer_t could be any type >= int and we want to make sure any
///      * @timer_id outside positive int range fails lookup.
///      */
///     if ((unsigned long long)timer_id > INT_MAX)
///             return NULL;
/// ```
///
/// `timer_t` is `int`, so only the low 32 bits of the register reach the
/// kernel and an id with bit 31 set is a *negative* int — it can never
/// name a live timer. Returning `None` here (→ EINVAL at every call
/// site) keeps NARF from ever resolving `0xFFFF_FFFF` to a real entry
/// once the id allocator has wrapped, which Linux structurally cannot do
/// because `posix_timer_add()` only ever hands out 0..INT_MAX.
fn timer_id_arg(raw: u64) -> Option<u32> {
    let id = raw as u32;
    (id <= TIMER_ID_MAX).then_some(id)
}

/// One armed POSIX timer.
#[derive(Debug, Clone, Copy)]
struct PosixTimer {
    /// Owning task.
    task: u64,
    /// One of CLOCK_REALTIME / CLOCK_MONOTONIC / CLOCK_BOOTTIME, as the
    /// 32-bit `clockid_t` the ABI delivers. Realtime currently shares the
    /// monotonic source — no NTP yet.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    clockid: i32,
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

fn with_table<R>(f: impl FnOnce(&mut BTreeMap<u64, TimerTable>) -> R) -> R {
    // Match the interval-timer path below: the normal boot path does not call
    // `posix_timer_init`, so the first timer_create(2) must stand the table up.
    let mut g = TIMERS.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    f(m)
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
fn parse_sigevent(buf: &[u8; 16]) -> (i32, i32) {
    let signo = i32::from_le_bytes(buf[8..12].try_into().unwrap());
    let notify = i32::from_le_bytes(buf[12..16].try_into().unwrap());
    (notify, signo)
}

/// Classify a `clockid_t` the way `clockid_to_kclock()` +
/// `do_timer_create()` do:
///
/// ```text
///     if (!kc)                return -EINVAL;
///     if (!kc->timer_create)  return -EOPNOTSUPP;
/// ```
///
/// `posix_clocks[]` has a hole at index 10 and ends at `CLOCK_TAI` (11),
/// so anything outside 0..=11 — and index 10 itself — is EINVAL.
/// `CLOCK_MONOTONIC_RAW` and the two `_COARSE` clocks *are* in the table
/// but carry no `.timer_create`, which is EOPNOTSUPP, not EINVAL, and
/// not success: NARF used to accept `CLOCK_MONOTONIC_RAW` and hand back
/// a timer Linux would have refused to create.
fn timer_create_clock_ok(clockid: i32) -> Result<(), i64> {
    match clockid {
        // Backed by the monotonic source; these actually arm.
        CLOCKID_REALTIME | CLOCKID_MONOTONIC | CLOCKID_BOOTTIME => Ok(()),
        // In `posix_clocks[]`, no `.timer_create` — exactly Linux's
        // EOPNOTSUPP arm.
        CLOCKID_MONOTONIC_RAW | CLOCKID_REALTIME_COARSE | CLOCKID_MONOTONIC_COARSE => {
            Err(EOPNOTSUPP)
        }
        // LINUX-GAP: Linux *can* create timers on these (CPU-time clocks
        // via posix-cpu-timers.c, the alarm clocks via alarmtimer.c, TAI
        // via clock_tai). NARF has no CPU-time accounting, no RTC wakeup
        // source and no TAI offset, so there is nothing to arm. They are
        // reported as EOPNOTSUPP — "this clock exists, this operation is
        // unavailable" — which is the answer a feature probe is written
        // to handle, rather than EINVAL (which claims the clockid itself
        // is malformed) or the old EPERM.
        CLOCKID_PROCESS_CPUTIME_ID
        | CLOCKID_THREAD_CPUTIME_ID
        | CLOCKID_REALTIME_ALARM
        | CLOCKID_BOOTTIME_ALARM
        | CLOCKID_TAI => Err(EOPNOTSUPP),
        // Not in `posix_clocks[]` at all (index 10 is a hole, >= 12 is
        // past the end). Negative ids are the pid-encoded CPU-clock and
        // `CLOCKFD` dynamic-clock forms, which NARF cannot resolve —
        // `posix_cpu_timer_create()` answers EINVAL for every one it
        // cannot map to a task, so EINVAL is the right shape here too.
        _ => Err(EINVAL),
    }
}

/// `timer_create(clockid, sigevent, timerid_out)`.
///
/// `kernel/time/posix-timers.c::sys_timer_create` +
/// `do_timer_create()`:
///
/// ```text
///     SYSCALL_DEFINE3(timer_create, const clockid_t, which_clock, ...)
///     {
///             if (timer_event_spec) {
///                     if (copy_from_user(&event, timer_event_spec, sizeof (event)))
///                             return -EFAULT;
///                     return do_timer_create(which_clock, &event, created_timer_id);
///             }
///             return do_timer_create(which_clock, NULL, created_timer_id);
///     }
///
///     static int do_timer_create(...)
///     {
///             const struct k_clock *kc = clockid_to_kclock(which_clock);
///             if (!kc)                        return -EINVAL;
///             if (!kc->timer_create)          return -EOPNOTSUPP;
///             ...
///             if (!new_timer->it_pid) { error = -EINVAL; goto out; }  /* good_sigevent() */
///             ...
///             if (copy_to_user(created_timer_id, &new_timer_id, sizeof(new_timer_id))) {
///                     error = -EFAULT;
///                     goto out;
///             }
///     }
/// ```
///
/// The ORDER is load-bearing and is not the obvious one: the sigevent
/// copy happens in the syscall wrapper, *before* `do_timer_create` has
/// looked at the clockid at all. So `timer_create(999, faulting_evp,
/// out)` is EFAULT on Linux, not EINVAL — this handler copies first for
/// the same reason. Conversely `created_timer_id` is not touched until
/// the very end, so a NULL/faulting output pointer loses to both the
/// clock check and the sigevent check.
///
/// Why the errnos matter to a caller: a program that wants a
/// CLOCK_BOOTTIME timer and is willing to settle for CLOCK_MONOTONIC has
/// to distinguish "this kernel does not do timers on that clock"
/// (EOPNOTSUPP — retry on another clock) from "you passed nonsense"
/// (EINVAL — the clockid is wrong, retrying with a different one is
/// pointless) from "your sigevent is unmapped" (EFAULT — a bug in the
/// caller). All three used to be EPERM, which says none of those things
/// and implies a privilege the caller could go acquire; `timer_create`
/// has no privileged form, so that answer is a dead end.
pub fn sys_timer_create(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `clockid_t` is `int`: only the low 32 bits of the register reach
    // the kernel, so 0x1_0000_0000 is CLOCK_REALTIME, not a bad clock.
    let clockid = args.arg0 as u32 as i32;
    let evp = args.arg1;
    let out_ptr = args.arg2;

    // Step 1 — the sigevent copy, ahead of every other check (above).
    //
    // LINUX-GAP: Linux copies `sizeof(sigevent_t)` = 64 bytes here and
    // faults on any of them; NARF reads the 16 that carry sigev_value /
    // sigev_signo / sigev_notify, so a pointer that is valid for 16
    // bytes and faulting for 64 is EFAULT there and accepted here.
    let parsed = if evp == 0 {
        None
    } else {
        let mut kbuf = [0u8; 16];
        // SAFETY: handler runs in the calling task's address space;
        // `copy_from_user` validates the user pointer + SMAP brackets.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(&mut kbuf, evp) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
        Some(parse_sigevent(&kbuf))
    };

    // Step 2 — the clockid: EINVAL (unknown) vs EOPNOTSUPP (known, no
    // timers on it).
    if let Err(e) = timer_create_clock_ok(clockid) {
        ctx.set_return(err(e));
        return;
    }

    // Step 3 — `good_sigevent()`. Default when evp == NULL is
    // SIGEV_SIGNAL + SIGALRM, which the kernel builds without validating.
    let effective_signum = match parsed {
        None => SIGALRM,
        Some((notify, signo)) => {
            // `good_sigevent()`'s switch, arm for arm. Note it switches
            // on the RAW `sigev_notify`: `SIGEV_SIGNAL | SIGEV_THREAD_ID`
            // (4) is a listed case that falls through into SIGEV_SIGNAL,
            // but `SIGEV_THREAD | SIGEV_THREAD_ID` (6) and
            // `SIGEV_NONE | SIGEV_THREAD_ID` (5) are NOT — they land in
            // `default:` and are EINVAL. Masking the bit off instead of
            // enumerating would silently accept those two.
            //
            // The signo bound is `signo <= 0 || signo > SIGRTMAX`. The RT
            // half of that range matters in practice: glibc implements
            // SIGEV_THREAD by rewriting the sigevent to
            // `SIGEV_SIGNAL | SIGEV_THREAD_ID` with signo = SIGRTMIN
            // (34), so the `signum >= 32` cap this handler used to apply
            // rejected every glibc SIGEV_THREAD timer. NARF's
            // `raise_signal_pending` already accepts 1..=64, so widening
            // to Linux's bound costs nothing and unblocks that path.
            //
            // LINUX-GAP: for the THREAD_ID forms Linux additionally
            // requires `sigev_notify_thread_id` to name a live thread in
            // the caller's thread group (EINVAL otherwise) and queues the
            // signal to that thread. The field sits at offset 16, past
            // the 16 bytes NARF reads, and NARF's pending mask is
            // per-task — so the tid is neither validated nor honoured and
            // the signal goes to the calling task.
            const SIGEV_SIGNAL_THREAD_ID: i32 = SIGEV_SIGNAL | SIGEV_THREAD_ID;
            match notify {
                SIGEV_SIGNAL | SIGEV_SIGNAL_THREAD_ID => {
                    if signo <= 0 || signo > SIGRTMAX {
                        ctx.set_return(err(EINVAL));
                        return;
                    }
                    signo as u32
                }
                // `case SIGEV_THREAD:` validates its signo the same way
                // (it falls through from the SIGEV_SIGNAL case), but NARF
                // has no notify thread to spawn, so an accepted
                // SIGEV_THREAD timer degrades to SIGEV_NONE: it arms and
                // counts overruns, it just delivers nothing.
                SIGEV_THREAD => {
                    if signo <= 0 || signo > SIGRTMAX {
                        ctx.set_return(err(EINVAL));
                        return;
                    }
                    0
                }
                SIGEV_NONE => 0,
                _ => {
                    ctx.set_return(err(EINVAL));
                    return;
                }
            }
        }
    };

    let task = current_task_id();
    let id = with_table(|m| {
        let t = m.entry(task).or_default();
        // Stay inside 0..INT_MAX: `lock_timer()` refuses to look up
        // anything above it, so an id with bit 31 set would be
        // unaddressable the moment it was handed out.
        t.next_id = t.next_id.wrapping_add(1);
        if t.next_id == 0 || t.next_id > TIMER_ID_MAX {
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
    // Step 4 — publish the id. Linux writes `sizeof(new_timer_id)` where
    // `new_timer_id` is an `int`: FOUR bytes, not eight. musl and glibc
    // both pass `&(int)` here (`kernel_timer_t` is `int`) and widen the
    // result themselves, so the 8-byte write this used to do scribbled
    // four bytes past the caller's object — a stack smash in libc, not
    // just an ABI nit.
    let id_bytes = (id as i32).to_le_bytes();
    // SAFETY: `out_ptr` is a user address; `copy_to_user` range-validates it
    // and brackets the 4-byte write in the SMAP window. We run in the calling
    // task's address space from the syscall path (not IRQ context).
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_to_user(out_ptr, &id_bytes) }.is_err() {
        // Linux takes the `goto out` cleanup path here too — the timer is
        // unhashed and freed, so the failed id is not left live.
        with_table(|m| {
            if let Some(t) = m.get_mut(&task) {
                t.by_id.remove(&id);
            }
        });
        ctx.set_return(err(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `timer_settime(timerid, flags, new, old)`.
///
/// `kernel/time/posix-timers.c::sys_timer_settime` +
/// `do_timer_settime`:
///
/// ```text
///     SYSCALL_DEFINE4(timer_settime, timer_t, timer_id, int, flags, ...)
///     {
///             if (!new_setting)
///                     return -EINVAL;
///             if (get_itimerspec64(&new_spec, new_setting))
///                     return -EFAULT;
///             error = do_timer_settime(timer_id, flags, &new_spec, rtn);
///             if (!error && old_setting) {
///                     if (put_itimerspec64(&old_spec, old_setting))
///                             error = -EFAULT;
///             }
///             return error;
///     }
///
///     static int do_timer_settime(...)
///     {
///             if (!timespec64_valid(&new_spec64->it_interval) ||
///                 !timespec64_valid(&new_spec64->it_value))
///                     return -EINVAL;
///             ...
///             scoped_timer_get_or_fail(timer_id)      /* -EINVAL on miss */
///     }
/// ```
///
/// Three orderings this pins down:
///
///  * A NULL `new_setting` is **EINVAL, not EFAULT** — Linux rejects the
///    argument before it ever tries to read it. That distinction is the
///    difference between "you forgot the argument" and "your buffer is
///    unmapped"; conflating them sends a caller looking at its memory map.
///  * The `new` copy runs before the timer lookup, so a faulting `new`
///    with a stale `timerid` is EFAULT, not EINVAL.
///  * A faulting `old` is reported as **EFAULT after the timer has
///    already been re-armed**. This handler used to swallow that error
///    (`let _ = copy_to_user`), which is the worst of both worlds: the
///    caller is told the call succeeded and then reads a stale
///    `itimerspec` out of its own buffer. Losing the old value while
///    still arming is exactly what Linux does; hiding it is not.
///
/// A missing timerid is EINVAL — the single errno Linux uses for "no
/// such timer". As EPERM it was indistinguishable from a sandbox denial,
/// so a caller that legitimately raced a `timer_delete` could not tell
/// a stale handle from a policy failure and had no reason to re-create
/// the timer.
pub fn sys_timer_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `timer_t` is `int` and `flags` is `int`: 32 bits each, whatever the
    // caller left in the upper half of the register.
    let id_arg = args.arg0;
    let flags = args.arg1 as u32 as i32;
    let new_ptr = args.arg2;
    let old_ptr = args.arg3;

    // `if (!new_setting) return -EINVAL;` — before any dereference.
    if new_ptr == 0 {
        ctx.set_return(err(EINVAL));
        return;
    }
    let mut buf = [0u8; 32];
    // SAFETY: `new_ptr` is checked non-zero above and is a user address;
    // `copy_from_user` range-validates it and brackets the 32-byte read in the
    // SMAP window. Runs in the calling task's address space, not IRQ context.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_from_user(&mut buf, new_ptr) }.is_err() {
        ctx.set_return(err(EFAULT));
        return;
    }
    let (int_s, int_n) = read_timespec(buf[0..16].try_into().unwrap());
    let (val_s, val_n) = read_timespec(buf[16..32].try_into().unwrap());
    // `timespec64_valid`: tv_sec >= 0 and tv_nsec in [0, NSEC_PER_SEC).
    let (interval_ns, value_ns) = match (timespec_to_ns(int_s, int_n), timespec_to_ns(val_s, val_n))
    {
        (Some(i), Some(v)) => (i, v),
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    // `scoped_timer_get_or_fail` → `lock_timer` → EINVAL on a miss.
    let id = match timer_id_arg(id_arg) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };

    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    // Linux does not validate `flags`: `common_timer_set` only ever tests
    // `flags & TIMER_ABSTIME`, every other bit is accepted and ignored.
    // Matching that (rather than rejecting unknown bits) is deliberate —
    // a caller passing a bit from a newer ABI must not start failing.
    let next_fire = if value_ns == 0 {
        0 // disarm
    } else if flags & (TIMER_ABSTIME as i32) != 0 {
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
    });
    let (prev_next, prev_interval) = match prev {
        Some(p) => p,
        None => {
            ctx.set_return(err(EINVAL));
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
        // context.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_to_user(old_ptr, &out) }.is_err() {
            // `put_itimerspec64` failing turns the whole call into EFAULT
            // even though the timer is now armed — the arm is NOT undone.
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `timer_gettime(timerid, cur)`.
///
/// `kernel/time/posix-timers.c::sys_timer_gettime`:
///
/// ```text
///     int ret = do_timer_gettime(timer_id, &cur_setting);
///     if (!ret) {
///             if (put_itimerspec64(&cur_setting, setting))
///                     ret = -EFAULT;
///     }
///     return ret;
/// ```
///
/// with `do_timer_gettime` = `scoped_timer_get_or_fail(timer_id)`, i.e.
/// `-EINVAL` when the lookup misses.
///
/// ORDER: the lookup runs FIRST and the copy-out only on success, so
/// `timer_gettime(stale_id, NULL)` is EINVAL, not EFAULT. This handler
/// used to check the output pointer first and would have answered the
/// other way round once both were errno-ified; a caller diagnosing a
/// stale handle would have been pointed at its buffer instead.
pub fn sys_timer_gettime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let out_ptr = args.arg1;
    // `timer_t` is `int`; ids above INT_MAX never resolve (see
    // `timer_id_arg`), which is the same EINVAL as an unknown id.
    let id = match timer_id_arg(args.arg0) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let snap = with_table(|m| {
        let t = m.get(&task)?;
        let e = t.by_id.get(&id)?;
        Some((e.next_fire_ns, e.interval_ns))
    });
    let (next, interval) = match snap {
        Some(s) => s,
        None => {
            ctx.set_return(err(EINVAL));
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
    // SAFETY: `out_ptr` is a user address; `copy_to_user` range-validates it
    // (NULL included → EFAULT) and brackets the 32-byte write in the SMAP
    // window. Runs in the calling task's address space, not IRQ context.
    // SAFETY: Valid memory or trusted environment
    if unsafe { crate::handlers::copy_to_user(out_ptr, &out) }.is_err() {
        // `put_itimerspec64(...)` → `-EFAULT`.
        ctx.set_return(err(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `timer_delete(timerid)`.
///
/// `kernel/time/posix-timers.c::sys_timer_delete`:
///
/// ```text
///     SYSCALL_DEFINE1(timer_delete, timer_t, timer_id)
///     {
///             scoped_timer_get_or_fail(timer_id) {    /* -EINVAL on miss */
///                     timer = scoped_timer;
///                     posix_timer_delete(timer);
///             }
///             posix_timer_unhash_and_free(timer);
///             return 0;
///     }
/// ```
///
/// The only failure is the lookup, and it is EINVAL. This is the arm
/// where EPERM hurt most: double-free-style bugs and races against a
/// sibling thread's `timer_delete` are the normal way to reach it, and
/// "Operation not permitted" gives a caller no way to tell "already
/// gone, fine" from "the sandbox took my timers away".
pub fn sys_timer_delete(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = match timer_id_arg(args.arg0) {
        Some(id) => id,
        None => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let task = current_task_id();
    let removed = with_table(|m| m.get_mut(&task).and_then(|t| t.by_id.remove(&id)).is_some());
    if removed {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(err(EINVAL));
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

/// `setitimer(which, new, old)`.
///
/// `kernel/time/itimer.c::sys_setitimer` + `get_itimerval` +
/// `do_setitimer`:
///
/// ```text
///     if (value) {
///             error = get_itimerval(&set_buffer, value);   /* -EFAULT then -EINVAL */
///             if (error)
///                     return error;
///     } else {
///             memset(&set_buffer, 0, sizeof(set_buffer));
///             printk_once(KERN_WARNING "%s calls setitimer() with new_value NULL pointer."
///                         " Misfeature support will be removed\n", current->comm);
///     }
///
///     error = do_setitimer(which, &set_buffer, ovalue ? &get_buffer : NULL);
///     if (error || !ovalue)
///             return error;
///     if (put_itimerval(ovalue, &get_buffer))
///             return -EFAULT;
/// ```
///
/// with `get_itimerval` = `copy_from_user` (EFAULT) then
/// `timeval_valid` (EINVAL), and `do_setitimer`'s `switch (which)`
/// ending in `default: return -EINVAL;`.
///
/// Three divergences this fixes beyond the errno numbers themselves:
///
///  * **A NULL `value` is accepted**, not rejected. Linux treats it as a
///    zeroed `itimerval`, i.e. "disarm", and only grumbles into dmesg.
///    NARF refused it, so `setitimer(ITIMER_REAL, NULL, &old)` — the
///    documented way to read-and-clear in one call — failed where Linux
///    succeeds. Rejecting a value Linux accepts is the silent kind of
///    divergence: the caller's timer stays armed.
///  * **`which` is validated last.** `setitimer(99, faulting, NULL)` is
///    EFAULT on Linux because the value is parsed first; this handler
///    tested `which` first and would have answered EINVAL.
///  * **A faulting `ovalue` is EFAULT**, reported after the new timer is
///    already installed. The old code dropped that error on the floor and
///    returned 0, leaving the caller reading uninitialised memory as its
///    previous itimerval.
///
/// The errno itself matters because `which` and the buffer are the only
/// two things a caller can get wrong here: EINVAL says "that itimer slot
/// does not exist" (retry with ITIMER_REAL), EFAULT says "your struct is
/// not mapped". EPERM said neither, and setitimer has no permission
/// dimension at all — there is no privileged variant to escalate to.
pub fn sys_setitimer(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `which` is `int`: 32 bits. A caller with garbage in the top half of
    // the register still names ITIMER_REAL, as it does on Linux.
    let which = args.arg0 as u32 as i32;
    let new_ptr = args.arg1;
    let old_ptr = args.arg2;

    // Step 1 — the new value, ahead of the `which` check (see above).
    // NULL is the accepted "disarm" misfeature, not an error.
    let (interval_ns, value_ns) = if new_ptr == 0 {
        (0, 0)
    } else {
        let mut buf = [0u8; 32];
        // SAFETY: `new_ptr` is checked non-zero above and is a user address;
        // `copy_from_user` range-validates it and brackets the 32-byte read in
        // the SMAP window. Runs in the calling task's address space, not IRQ
        // context.
        if unsafe { crate::handlers::copy_from_user(&mut buf, new_ptr) }.is_err() {
            ctx.set_return(err(EFAULT));
            return;
        }
        let (int_s, int_us) = read_timeval(buf[0..16].try_into().unwrap());
        let (val_s, val_us) = read_timeval(buf[16..32].try_into().unwrap());
        // `timeval_valid`: tv_sec >= 0 and tv_usec in [0, USEC_PER_SEC).
        match (timeval_to_ns(int_s, int_us), timeval_to_ns(val_s, val_us)) {
            (Some(i), Some(v)) => (i, v),
            _ => {
                ctx.set_return(err(EINVAL));
                return;
            }
        }
    };

    // Step 2 — `do_setitimer`'s `switch (which) { ... default: -EINVAL }`.
    if !(0..=ITIMER_PROF as i32).contains(&which) {
        ctx.set_return(err(EINVAL));
        return;
    }
    let which = which as usize;

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
        let prev = slots[which];
        slots[which] = Itimer {
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
        // context.
        if unsafe { crate::handlers::copy_to_user(old_ptr, &out) }.is_err() {
            // `if (put_itimerval(ovalue, &get_buffer)) return -EFAULT;` —
            // the new timer stays installed; only the report is lost.
            ctx.set_return(err(EFAULT));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `getitimer(which, cur)`.
///
/// `kernel/time/itimer.c::sys_getitimer`:
///
/// ```text
///     int error = do_getitimer(which, &get_buffer);
///     if (!error && put_itimerval(value, &get_buffer))
///             error = -EFAULT;
///     return error;
/// ```
///
/// `do_getitimer`'s `switch (which)` ends in `default: return(-EINVAL);`,
/// and it runs BEFORE the copy-out — so `getitimer(99, NULL)` is EINVAL,
/// not EFAULT. The two checks used to share one `if` here, which made the
/// winner an accident of how the condition was written; splitting them
/// fixes the order at the same time as the errnos.
///
/// For the caller: EINVAL means the slot number is wrong (ITIMER_VIRTUAL
/// and ITIMER_PROF exist, so it is worth distinguishing), EFAULT means
/// the `struct itimerval` is not writable. EPERM meant neither, and
/// getitimer is unprivileged — there is no permission to acquire.
pub fn sys_getitimer(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `which` is `int`; only the low 32 bits reach the kernel.
    let which = args.arg0 as u32 as i32;
    let out_ptr = args.arg1;
    if !(0..=ITIMER_PROF as i32).contains(&which) {
        ctx.set_return(err(EINVAL));
        return;
    }
    let which = which as usize;
    let task = current_task_id();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let slot = with_itimers(|m| m.get(&task).map(|s| s[which]).unwrap_or_default());
    let mut out = [0u8; 32];
    write_itimerval(&mut out, slot, now);
    // SAFETY: `out_ptr` is a user address; `copy_to_user` range-validates it
    // (NULL included → EFAULT) and brackets the 32-byte write in the SMAP
    // window. Runs in the calling task's address space, not IRQ context.
    if unsafe { crate::handlers::copy_to_user(out_ptr, &out) }.is_err() {
        ctx.set_return(err(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `alarm(seconds)` — convenience wrapper over ITIMER_REAL with no
/// interval. Returns the previous alarm's remaining seconds, 0 if none
/// was armed. There is no error path: `SYSCALL_DEFINE1(alarm, unsigned
/// int, seconds)` returns an `unsigned int` and `do_setitimer` cannot
/// fail for a hardcoded `ITIMER_REAL` + a valid timespec.
///
/// `kernel/time/itimer.c::alarm_setitimer`:
///
/// ```text
///     static unsigned int alarm_setitimer(unsigned int seconds)
///     {
///             it_new.it_value.tv_sec = seconds;
///             ...
///             do_setitimer(ITIMER_REAL, &it_new, &it_old);
///
///             /*
///              * We can't return 0 if we have an alarm pending ...  And we'd
///              * better return too much than too little anyway
///              */
///             if ((!it_old.it_value.tv_sec && it_old.it_value.tv_nsec) ||
///                   it_old.it_value.tv_nsec >= (NSEC_PER_SEC / 2))
///                     it_old.it_value.tv_sec++;
///
///             return it_old.it_value.tv_sec;
///     }
/// ```
///
/// Two fixes, neither of them an errno:
///
///  * `seconds` is `unsigned int` — **32 bits**. Reading the full
///    register meant `alarm(1 << 32)` armed a ~136-year timer where
///    Linux truncates to 0 and *cancels* the alarm. A watchdog that
///    passes a computed 64-bit value would silently never fire.
///  * The rounding is round-to-nearest with a floor of 1 for any nonzero
///    sub-second remainder, not the unconditional round-up this used to
///    do: for 1.2 s remaining Linux answers 1, NARF answered 2. Callers
///    that re-arm with the returned value (the standard
///    save/restore-the-alarm idiom) drifted a second later on every hop.
pub fn sys_alarm(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `unsigned int seconds` — truncate, do not read the whole register.
    let secs = args.arg0 as u32 as u64;
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
        // `alarm_setitimer`'s bump, verbatim: add a second only when the
        // whole remainder is sub-second-but-nonzero (so a pending alarm
        // never reports 0 and looks unarmed), or when the sub-second part
        // is at least half a second.
        let rem = prev.next_fire_ns.saturating_sub(now);
        let sec = rem / 1_000_000_000;
        let nsec = rem % 1_000_000_000;
        if (sec == 0 && nsec != 0) || nsec >= 500_000_000 {
            sec.saturating_add(1)
        } else {
            sec
        }
    };
    // The return type is `unsigned int`; Linux truncates the same way.
    ctx.set_return(SyscallReturn::ok(prev_remaining as u32 as u64));
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
}

/// Diagnostic for the smokes — peek the next-fire deadline.
#[doc(hidden)]
pub fn next_fire_of(task: u64, id: u32) -> Option<u64> {
    with_table(|m| {
        m.get(&task)
            .and_then(|t| t.by_id.get(&id))
            .map(|t| t.next_fire_ns)
    })
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
