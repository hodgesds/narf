//! The NTP-steered timekeeper — Linux's `tk->tkr_mono` next to `tkr_raw`.
//!
//! NARF's kernel runs on the counter: [`crate::now_cycles`], every
//! `Instant` and deadline, and [`crate::monotonic_ns`] (the counter scaled
//! by its calibrated rate, like Linux's `sched_clock` / `local_clock`, which
//! also stamps the kernel log). Those are never steered. The clocks a
//! program reads — CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_REALTIME,
//! CLOCK_TAI — are this one: the same counter, scaled by a multiplier the
//! NTP discipline adjusts, as `timekeeping_adjust` adjusts
//! `tk->tkr_mono.mult` to `ntp_tick_length()`. CLOCK_MONOTONIC_RAW keeps
//! the counter's own scale.
//!
//! ```text
//! steered_ns(cyc) = base_ns + ((cyc - cycle_last) * mult) >> shift
//! ```
//!
//! `shift` is the counter's (`wall::cyc_to_ns_mult_shift`). Whenever the
//! rate changes ([`set_rate`]: once per second from the NTP tick, and at
//! once from `adjtimex`, as `ntp_update_frequency` applies a change "without
//! waiting for the next second_overflow"), the timekeeper is re-anchored at
//! the current counter value — `base_ns` takes the time there under the old
//! multiplier — so the clock is continuous and only its slope changes.
//! Readers take a seqlock snapshot and read the counter inside it, which
//! keeps the clock monotonic across a re-anchor. Until a rate is first set
//! (`mult == 0`) the steered clock IS the counter clock, so the boot-time RTC
//! anchor taken against [`crate::monotonic_ns`] stays valid.
//!
//! The vDSO publishes the same four numbers (`update_vsyscall`); every
//! re-anchor runs the vsyscall notifier so it never computes with a stale
//! slope.

use core::sync::atomic::{fence, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// ns per second.
const NSEC_PER_SEC: i64 = 1_000_000_000;

/// Linux `clocksource_max_adjustment`: the multiplier is never moved more
/// than 11% from the counter's.
const MAX_ADJ_PERCENT: i64 = 11;

/// The largest rate [`set_rate`] applies, ns/s << 32.
const MAX_RATE: i64 = (MAX_ADJ_PERCENT * NSEC_PER_SEC / 100) << 32;

static SEQ: AtomicU32 = AtomicU32::new(0);
/// Monotonic counter cycles ([`crate::now_cycles`]) at the anchor.
static CYCLE_LAST: AtomicU64 = AtomicU64::new(0);
/// Steered ns at [`CYCLE_LAST`].
static BASE_NS: AtomicU64 = AtomicU64::new(0);
/// Steered multiplier, with the counter's shift. 0: never steered — the
/// steered clock reads the counter clock.
static MULT: AtomicU32 = AtomicU32::new(0);
/// The rate the multiplier was derived from, ns/s << 32.
static RATE: AtomicI64 = AtomicI64::new(0);
/// Serialises writers; readers never take it.
static WRITER: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());
/// `update_vsyscall`: run after every re-anchor.
static VSYSCALL_NOTIFIER: AtomicUsize = AtomicUsize::new(0);

/// One consistent timekeeper snapshot (the vDSO's `vdso_clock` fields).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub cycle_last: u64,
    pub base_ns: u64,
    pub mult: u32,
    pub shift: u32,
}

impl Params {
    /// Steered ns at counter value `cyc`. A `cyc` before the anchor reads
    /// as the anchor (Linux `clocksource_delta` treats a negative delta as
    /// 0), so a reader racing a re-anchor never goes backwards.
    #[inline]
    pub fn ns_at(&self, cyc: u64) -> u64 {
        let delta = cyc.saturating_sub(self.cycle_last);
        self.base_ns
            .wrapping_add(((delta as u128 * self.mult as u128) >> self.shift) as u64)
    }
}

/// The counter clock as `Params`: what the steered clock is before any rate.
fn unsteered() -> Params {
    let (mult, shift) = crate::wall::cyc_to_ns_mult_shift();
    Params {
        cycle_last: 0,
        base_ns: 0,
        mult,
        shift,
    }
}

/// Read the snapshot and, inside the same seqlock section, the counter
/// (Linux reads the clocksource inside `read_seqcount_begin/retry`).
#[inline]
pub(crate) fn snapshot_with_now() -> (Params, u64) {
    loop {
        let seq = SEQ.load(Ordering::Acquire);
        if seq & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let cycle_last = CYCLE_LAST.load(Ordering::Relaxed);
        let base_ns = BASE_NS.load(Ordering::Relaxed);
        let mult = MULT.load(Ordering::Relaxed);
        let now = crate::now_cycles();
        fence(Ordering::Acquire);
        if SEQ.load(Ordering::Relaxed) != seq {
            continue;
        }
        if mult == 0 {
            return (unsteered(), now);
        }
        let (_, shift) = crate::wall::cyc_to_ns_mult_shift();
        return (
            Params {
                cycle_last,
                base_ns,
                mult,
                shift,
            },
            now,
        );
    }
}

/// The current timekeeper snapshot, for the vDSO.
pub fn params() -> Params {
    snapshot_with_now().0
}

/// CLOCK_MONOTONIC as userspace reads it, ns.
#[inline]
pub fn monotonic_ns() -> u64 {
    let (p, now) = snapshot_with_now();
    p.ns_at(now)
}

/// Steered minus counter clock, now, ns: what the steered hrtimer bases add
/// to the kernel's counter time (the `base->offset` of CLOCK_MONOTONIC as
/// userspace sees it).
#[inline]
pub fn offset_ns() -> i64 {
    let (p, now) = snapshot_with_now();
    p.ns_at(now) as i64 - crate::wall::cycles_to_ns(now) as i64
}

/// The rate the steered clock runs at against the counter, ns/s << 32.
pub fn rate() -> i64 {
    RATE.load(Ordering::Relaxed)
}

/// Install the `update_vsyscall` hook (the vDSO republishes its clock data).
pub fn set_vsyscall_notifier(f: fn()) {
    VSYSCALL_NOTIFIER.store(f as usize, Ordering::Release);
}

fn notify_vsyscall() {
    let raw = VSYSCALL_NOTIFIER.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `fn()` values are stored by the setter.
        let f: fn() = unsafe { core::mem::transmute(raw) };
        f();
    }
}

/// The multiplier for `rate` (ns/s << 32) on top of the counter's `raw`:
/// `raw · (1 + rate / 1e9 / 2^32)`, without a 128-bit division.
fn mult_for(raw: u32, rate: i64) -> u32 {
    // The rate as a 2^-32 fraction of one: |rate| ≤ MAX_RATE ≈ 4.7e17, so
    // the quotient fits and the i128 product cannot overflow.
    let frac = rate / NSEC_PER_SEC;
    let adj = ((raw as i128 * frac as i128) >> 32) as i64;
    (raw as i64 + adj).clamp(1, u32::MAX as i64) as u32
}

/// Re-anchor the timekeeper at now and run it at `rate` (ns/s << 32) from
/// here on, clamped to ±11% (`clocksource_max_adjustment`). IRQ-safe.
pub fn set_rate(rate: i64) {
    let rate = rate.clamp(-MAX_RATE, MAX_RATE);
    {
        let _w = WRITER.lock();
        let seq = SEQ.load(Ordering::Relaxed);
        SEQ.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        // Read the counter only now: a reader that finished before the odd
        // store above read it earlier, so the new anchor is not before it.
        let now = crate::now_cycles();
        let old = match MULT.load(Ordering::Relaxed) {
            0 => unsteered(),
            mult => Params {
                cycle_last: CYCLE_LAST.load(Ordering::Relaxed),
                base_ns: BASE_NS.load(Ordering::Relaxed),
                mult,
                shift: crate::wall::cyc_to_ns_mult_shift().1,
            },
        };
        let base_ns = old.ns_at(now);
        let (raw, _) = crate::wall::cyc_to_ns_mult_shift();
        CYCLE_LAST.store(now, Ordering::Relaxed);
        BASE_NS.store(base_ns, Ordering::Relaxed);
        MULT.store(mult_for(raw, rate), Ordering::Relaxed);
        RATE.store(rate, Ordering::Relaxed);
        SEQ.store(seq.wrapping_add(2), Ordering::Release);
    }
    notify_vsyscall();
}

/// The counter's scale changed (`wall::set_clock_hz`): the steered clock
/// falls back to the counter clock until the next [`set_rate`]. Only boot
/// calibration and tests change the scale.
pub(crate) fn reset_to_counter() {
    {
        let _w = WRITER.lock();
        let seq = SEQ.load(Ordering::Relaxed);
        SEQ.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        CYCLE_LAST.store(0, Ordering::Relaxed);
        BASE_NS.store(0, Ordering::Relaxed);
        MULT.store(0, Ordering::Relaxed);
        RATE.store(0, Ordering::Relaxed);
        SEQ.store(seq.wrapping_add(2), Ordering::Release);
    }
    notify_vsyscall();
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn mult_for_scales_by_the_rate() {
        let raw = 915_000_000u32;
        assert_eq!(mult_for(raw, 0), raw);
        // +500 ppm: raw * 1.0005, within a unit.
        let m = mult_for(raw, 500_000i64 << 32);
        assert!((m as i64 - 915_457_500).abs() <= 1);
        let m = mult_for(raw, -(500_000i64 << 32));
        assert!((m as i64 - 914_542_500).abs() <= 1);
    }

    #[test]
    fn params_ns_at_is_continuous_at_the_anchor() {
        let p = Params {
            cycle_last: 1_000,
            base_ns: 5_000,
            mult: 1 << 31,
            shift: 32,
        };
        assert_eq!(p.ns_at(1_000), 5_000);
        assert_eq!(p.ns_at(999), 5_000);
        assert_eq!(p.ns_at(3_000), 6_000);
    }
}
