//! Kernel NTP discipline state — the `adjtimex(2)` / `clock_adjtime(2)`
//! variables (`kernel/time/ntp.c`, Linux 7.3).
//!
//! Linux keeps these in a per-timekeeper `struct ntp_data` and touches them
//! only under `tk_core.lock`. NARF keeps the same variables here, behind one
//! [`IrqSafeSpinLock`], so the syscall layer does nothing but copy
//! `struct __kernel_timex` in and out, check `CAP_SYS_TIME`, and apply the one
//! mode that reaches the timekeeper ([`ADJ_SETOFFSET`]).
//!
//! The defaults are Linux's (`tk_ntp_data[]`'s initialiser): `TIME_OK` state
//! with `STA_UNSYNC` status, a `USER_HZ`-derived 10000 µs tick, time constant
//! 2 and both error estimates at `NTP_PHASE_LIMIT`. `STA_UNSYNC` is why a
//! query on a freshly booted kernel answers `TIME_ERROR` (5), not `TIME_OK`:
//! nothing has disciplined the clock yet. A time daemon that takes over
//! clears the bit with `ADJ_STATUS` and the answer becomes `TIME_OK`, exactly
//! as on Linux.
//!
//! LINUX-GAP (closed by #1764): the discipline loop. Linux feeds
//! `time_offset` / `time_freq` into `second_overflow()` on every tick and into
//! the timekeeper's multiplier, so a PLL correction physically slews
//! CLOCK_REALTIME. NARF has no timekeeper multiplier — the wall clock is
//! `monotonic_ns + WALL_OFFSET_NS` — so the loop lives here instead:
//! [`tick_second`], called once per wall second from the clockevent tick
//! handler, drains `time_offset` exponentially (`ntp_offset_chunk()`:
//! `time_offset >> (SHIFT_PLL + time_constant)`, whole remainder when the
//! chunk rounds to zero, exactly as Linux's `second_overflow()`) and folds
//! the chunk into the wall offset via [`crate::wall::adjust_wall_offset_ns`].
//! The slew is therefore applied at 1 Hz granularity, not spread over the
//! second's ticks: each second's jump is at most `MAXPHASE >> (SHIFT_PLL +
//! time_constant)` (≤ 8 ms while converging from the 128 ms step threshold,
//! ≤ 0.5 ms at the µs-mode default constant). [`apply_sample`] is the SNTP
//! client's entry point: offsets over the RFC 5905 step threshold (128 ms)
//! step the wall clock at once, smaller ones go through `ADJ_OFFSET`'s
//! PLL/FLL frequency learning ([`update_offset`], the full Linux
//! `ntp_update_offset()`), and the tick drains the phase. `ADJ_SETOFFSET`
//! (a step, not a slew) still reaches the timekeeper directly, as before.
//!
//! LINUX-GAP: no leap-second machinery here. `STA_INS` / `STA_DEL` are stored
//! and reported, but `time_state` never advances to `TIME_INS` / `TIME_DEL` /
//! `TIME_OOP` / `TIME_WAIT` because nothing runs the leap half of
//! `second_overflow()`. NARF's leap handling is [`crate::wall::begin_leap_smear`]
//! — a different mechanism with no adjtimex surface.
//!
//! LINUX-GAP: the `ADJ_ADJTIME` single-shot offset (`time_adjust`) is not
//! drained by [`tick_second`]. Linux drains it at `MAX_TICKADJ` (500 µs/s)
//! through the same per-tick skew machinery that carries `time_offset`;
//! NARF has no per-tick multiplier to carry it, so a single-shot offset
//! stays pending until something steps the clock. The SNTP path never sets
//! it.
//!
//! LINUX-GAP: no PPS, as if `CONFIG_NTP_PPS` were off. `ppsfreq`, `jitter`,
//! `shift`, `stabil`, `jitcnt`, `calcnt`, `errcnt` and `stbcnt` read back as
//! zero, which is what Linux's `pps_fill_timex()` stub leaves them as, and
//! `STA_PPS*` therefore never appears in `status`.
//!
//! LINUX-GAP: the TAI offset is stored and reported (`ADJ_TAI` →
//! `timex.tai`), but NARF implements no `CLOCK_TAI`, so nothing reads it. See
//! `sys_clock_gettime`.

use narf_lib::errno::{EINVAL, EPERM};
use narf_lib::sync::IrqSafeSpinLock;

// ── `include/uapi/linux/timex.h`: mode selector (`timex.modes`) ──────

/// Set the phase offset (`timex.offset`).
pub const ADJ_OFFSET: u32 = 0x0001;
/// Set the frequency offset (`timex.freq`, scaled ppm).
pub const ADJ_FREQUENCY: u32 = 0x0002;
/// Set the maximum error (`timex.maxerror`).
pub const ADJ_MAXERROR: u32 = 0x0004;
/// Set the estimated error (`timex.esterror`).
pub const ADJ_ESTERROR: u32 = 0x0008;
/// Set the clock status bits (`timex.status`).
pub const ADJ_STATUS: u32 = 0x0010;
/// Set the PLL time constant (`timex.constant`).
pub const ADJ_TIMECONST: u32 = 0x0020;
/// Set the TAI offset — also read out of `timex.constant`.
pub const ADJ_TAI: u32 = 0x0080;
/// Step the clock by `timex.time`.
pub const ADJ_SETOFFSET: u32 = 0x0100;
/// Select microsecond resolution (clears `STA_NANO`).
pub const ADJ_MICRO: u32 = 0x1000;
/// Select nanosecond resolution (sets `STA_NANO`).
pub const ADJ_NANO: u32 = 0x2000;
/// Set the tick length (`timex.tick`, µs).
pub const ADJ_TICK: u32 = 0x4000;
/// Switch to `adjtime(3)` semantics — the old single-shot interface.
pub const ADJ_ADJTIME: u32 = 0x8000;
/// `ADJ_ADJTIME | ADJ_OFFSET` — the only legal `ADJ_ADJTIME` spelling.
pub const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
/// Within `ADJ_ADJTIME`, read the pending single-shot offset without
/// replacing it. Shares the `ADJ_NANO` bit, which is why it is only ever
/// interpreted under `ADJ_ADJTIME`.
pub const ADJ_OFFSET_READONLY: u32 = 0x2000;

// ── `include/uapi/linux/timex.h`: clock status (`timex.status`) ──────

/// Enable PLL updates. Without it `ADJ_OFFSET` is ignored.
pub const STA_PLL: i32 = 0x0001;
/// Enable PPS frequency discipline.
pub const STA_PPSFREQ: i32 = 0x0002;
/// Enable PPS time discipline.
pub const STA_PPSTIME: i32 = 0x0004;
/// Select frequency-lock mode (FLL rather than PLL).
/// `include/uapi/linux/timex.h`: writable, so not in [`STA_RONLY`].
pub const STA_FLL: i32 = 0x0008;
/// Insert a leap second.
pub const STA_INS: i32 = 0x0010;
/// Delete a leap second.
pub const STA_DEL: i32 = 0x0020;
/// The clock is not synchronised. Linux's boot default.
pub const STA_UNSYNC: i32 = 0x0040;
/// Hold the frequency — `ntp_update_offset()` measures no interval while
/// set (`include/uapi/linux/timex.h`: writable, so not in [`STA_RONLY`]).
pub const STA_FREQHOLD: i32 = 0x0080;
/// PPS signal present (read-only).
pub const STA_PPSSIGNAL: i32 = 0x0100;
/// PPS jitter exceeded (read-only).
pub const STA_PPSJITTER: i32 = 0x0200;
/// PPS wander exceeded (read-only).
pub const STA_PPSWANDER: i32 = 0x0400;
/// PPS calibration error (read-only).
pub const STA_PPSERROR: i32 = 0x0800;
/// Clock hardware fault (read-only).
pub const STA_CLOCKERR: i32 = 0x1000;
/// Resolution is nanoseconds rather than microseconds (read-only).
pub const STA_NANO: i32 = 0x2000;
/// FLL rather than PLL mode (read-only).
pub const STA_MODE: i32 = 0x4000;
/// Clock source B rather than A (read-only).
pub const STA_CLK: i32 = 0x8000;

/// The bits userspace may not set (`STA_RONLY`). `ADJ_STATUS` preserves
/// these and takes the rest from the request.
pub const STA_RONLY: i32 = STA_PPSSIGNAL
    | STA_PPSJITTER
    | STA_PPSWANDER
    | STA_PPSERROR
    | STA_CLOCKERR
    | STA_NANO
    | STA_MODE
    | STA_CLK;

// ── `include/uapi/linux/timex.h`: clock state (the return value) ─────

/// Clock synchronised, no leap second pending.
pub const TIME_OK: i64 = 0;
/// Clock not synchronised (`is_error_status()`).
pub const TIME_ERROR: i64 = 5;

// ── RFC 5905 §3: stratum values ─────────────────────────────────────

/// Stratum 0 — unspecified or invalid; a reply at this stratum is a
/// kiss-o'-death packet, not time.
pub const STRATUM_UNSPECIFIED: u8 = 0;
/// Stratum 16 — unsynchronised; the server's clock is not disciplined.
pub const STRATUM_UNSYNCED: u8 = 16;

// ── `include/linux/timex.h` / `kernel/time/ntp.c` scaling ───────────

/// `NTP_SCALE_SHIFT` — the fixed-point shift `time_freq` and `time_offset`
/// carry.
const NTP_SCALE_SHIFT: u32 = 32;
/// `SHIFT_USEC`, the `time_freq` scale.
const SHIFT_USEC: u32 = 16;
/// `PPM_SCALE` — ppm → `time_freq` units.
const PPM_SCALE: i64 = 1_000i64 << (NTP_SCALE_SHIFT - SHIFT_USEC);
/// `PPM_SCALE_INV_SHIFT`.
const PPM_SCALE_INV_SHIFT: u32 = 19;
/// `PPM_SCALE_INV` — the reciprocal used to report `time_freq` back as ppm.
const PPM_SCALE_INV: i64 = ((1i64 << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / PPM_SCALE) + 1;
/// `MAXPHASE` — maximum phase error, ns.
const MAXPHASE: i64 = 500_000_000;
/// `MAXFREQ` — maximum frequency error, ns/s.
const MAXFREQ: i64 = 500_000;
/// `MAXFREQ_SCALED`.
const MAXFREQ_SCALED: i64 = MAXFREQ << NTP_SCALE_SHIFT;
/// `NTP_PHASE_LIMIT` — beyond maximum dispersion, µs.
const NTP_PHASE_LIMIT: i64 = (MAXPHASE / 1_000) << 5;
/// `MAXTC` — maximum PLL time constant.
const MAXTC: i64 = 10;
/// `SHIFT_PLL` — PLL dampening factor (`include/linux/timex.h`): how much of
/// `time_offset` is corrected each second, and how much the frequency is
/// adjusted for a given offset. Linux lowered Mills' reference 4 to 2 after
/// experimentation (fast convergence, good stability).
const SHIFT_PLL: u32 = 2;
/// `SHIFT_FLL` — FLL dampening factor (`include/linux/timex.h`).
const SHIFT_FLL: u32 = 2;
/// `MINSEC` — minimum interval between frequency updates, seconds
/// (`include/linux/timex.h`). Shorter intervals carry no frequency
/// information, so the FLL half of `ntp_update_offset()` ignores them.
const MINSEC: i64 = 256;
/// `MAXSEC` — maximum interval between frequency updates, seconds
/// (`include/linux/timex.h`). Longer intervals always take the FLL path,
/// even without `STA_FLL`, because the PLL's assumptions no longer hold.
const MAXSEC: i64 = 2048;
/// `MAX_TAI_OFFSET` (`kernel/time/ntp.c`).
const MAX_TAI_OFFSET: i64 = 100_000;
/// `USER_HZ`, the `times(2)`/`timex.tick` clock rate NARF reports.
const USER_HZ: i64 = 100;
/// `USER_TICK_USEC` — `(1000000 + USER_HZ/2) / USER_HZ`.
const USER_TICK_USEC: i64 = (1_000_000 + USER_HZ / 2) / USER_HZ;
/// `NTP_INTERVAL_FREQ` is Linux's `HZ`: the rate `time_offset` is scaled
/// against. NARF's own tick is `USER_HZ`, and the value cancels between
/// `ADJ_OFFSET` and the read-back, so a caller sees its own request return.
const NTP_INTERVAL_FREQ: i64 = USER_HZ;
/// µs per second.
const USEC_PER_SEC: i64 = 1_000_000;
/// ns per second.
const NSEC_PER_SEC: i64 = 1_000_000_000;
/// ns per µs.
const NSEC_PER_USEC: i64 = 1_000;

/// `include/linux/timex.h`'s `shift_right()` — an arithmetic shift that
/// rounds toward zero for negative values, which `>>` does not.
fn shift_right(x: i64, s: u32) -> i64 {
    if x < 0 {
        -((-x) >> s)
    } else {
        x >> s
    }
}

/// The mutable half of `struct __kernel_timex`: what the syscall layer
/// copies in, what [`adjtimex`] fills in, and what gets copied back out.
///
/// The PPS block (`ppsfreq`, `jitter`, `shift`, `stabil`, `jitcnt`,
/// `calcnt`, `errcnt`, `stbcnt`) is absent on purpose — NARF has no PPS, so
/// the caller writes those fields back as zero. See the module docs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timex {
    /// `timex.modes` — which fields of this request to apply.
    pub modes: u32,
    /// `timex.offset` — phase offset, µs (ns with `STA_NANO`).
    pub offset: i64,
    /// `timex.freq` — frequency offset, scaled ppm.
    pub freq: i64,
    /// `timex.maxerror` — maximum error, µs.
    pub maxerror: i64,
    /// `timex.esterror` — estimated error, µs.
    pub esterror: i64,
    /// `timex.status` — `STA_*` bits.
    pub status: i32,
    /// `timex.constant` — PLL time constant, and the TAI offset under
    /// `ADJ_TAI`.
    pub constant: i64,
    /// `timex.precision` — clock precision, µs (read-only).
    pub precision: i64,
    /// `timex.tolerance` — frequency tolerance, ppm (read-only).
    pub tolerance: i64,
    /// `timex.time.tv_sec` — current time, or the `ADJ_SETOFFSET` step.
    pub time_sec: i64,
    /// `timex.time.tv_usec` — µs (ns with `ADJ_NANO`).
    pub time_usec: i64,
    /// `timex.tick` — µs between clock ticks.
    pub tick: i64,
    /// `timex.tai` — TAI offset, seconds (read-only).
    pub tai: i32,
}

/// Linux's `struct ntp_data`, minus the PLL/PPS working state NARF has no
/// loop to drive.
#[derive(Debug)]
struct NtpState {
    tick_usec: i64,
    time_state: i64,
    time_status: i32,
    time_constant: i64,
    time_maxerror: i64,
    time_esterror: i64,
    /// Frequency offset, scaled by `NTP_SCALE_SHIFT`.
    time_freq: i64,
    /// Phase offset, scaled by `NTP_SCALE_SHIFT` and divided by
    /// `NTP_INTERVAL_FREQ`.
    time_offset: i64,
    /// Wall-clock seconds at the last `ADJ_OFFSET` (or PLL turn-on).
    /// `ntp_update_offset()` measures the update interval against this to
    /// learn the frequency; Linux calls it `time_reftime` and reads it from
    /// `ktime_get_ntp_seconds()`.
    time_reftime: i64,
    /// `adjtime(3)`'s single-shot offset, µs.
    time_adjust: i64,
    tai_offset: i32,
}

/// `kernel/time/ntp.c`'s `tk_ntp_data[]` initialiser.
static NTP: IrqSafeSpinLock<NtpState> = IrqSafeSpinLock::new(NtpState {
    tick_usec: USER_TICK_USEC,
    time_state: TIME_OK,
    time_status: STA_UNSYNC,
    time_constant: 2,
    time_maxerror: NTP_PHASE_LIMIT,
    time_esterror: NTP_PHASE_LIMIT,
    time_freq: 0,
    time_offset: 0,
    time_reftime: 0,
    time_adjust: 0,
    tai_offset: 0,
});

/// `kernel/time/ntp.c::is_error_status()` in its `!CONFIG_NTP_PPS` form —
/// the only one that can apply here, since no PPS bit is ever set.
fn is_error_status(status: i32) -> bool {
    status & (STA_UNSYNC | STA_CLOCKERR) != 0
}

/// `kernel/time/timekeeping.c::timekeeping_validate_timex()`.
///
/// ```text
/// if (txc->modes & ADJ_ADJTIME) {
///         if (!(txc->modes & ADJ_OFFSET_SINGLESHOT))      return -EINVAL;
///         if (!(txc->modes & ADJ_OFFSET_READONLY) &&
///             !capable(CAP_SYS_TIME))                     return -EPERM;
/// } else {
///         if (txc->modes && !capable(CAP_SYS_TIME))       return -EPERM;
///         if (txc->modes & ADJ_TICK &&
///             (txc->tick < 900000/USER_HZ ||
///              txc->tick > 1100000/USER_HZ))              return -EINVAL;
/// }
/// if (txc->modes & ADJ_SETOFFSET) { ... }
/// if (txc->modes & ADJ_FREQUENCY) { ... }
/// ```
///
/// `cap_sys_time` is the caller's `capable(CAP_SYS_TIME)`. Note what the
/// shape implies and what the whole gap was: **any** non-zero `modes` needs
/// the capability, so an unprivileged `adjtimex` is a read-only query and
/// nothing else. The errno is positive; the syscall layer negates it.
///
/// Linux's `aux_clock` arm is absent: NARF has no `CLOCK_AUX` timekeepers,
/// and `clock_adjtime` refuses those ids before reaching here.
pub fn validate(txc: &Timex, cap_sys_time: bool) -> Result<(), i64> {
    if txc.modes & ADJ_ADJTIME != 0 {
        // "singleshot must not be used with any other mode bits": the
        // ADJ_OFFSET bit is part of the ADJ_OFFSET_SINGLESHOT spelling.
        if txc.modes & ADJ_OFFSET_SINGLESHOT != ADJ_OFFSET_SINGLESHOT {
            return Err(EINVAL);
        }
        if txc.modes & ADJ_OFFSET_READONLY == 0 && !cap_sys_time {
            return Err(EPERM);
        }
    } else {
        if txc.modes != 0 && !cap_sys_time {
            return Err(EPERM);
        }
        // "if the quartz is off by more than 10% then something is VERY
        // wrong!"
        if txc.modes & ADJ_TICK != 0
            && (txc.tick < 900_000 / USER_HZ || txc.tick > 1_100_000 / USER_HZ)
        {
            return Err(EINVAL);
        }
    }

    if txc.modes & ADJ_SETOFFSET != 0 {
        // Injecting time needs the capability even in ADJ_ADJTIME mode,
        // where the checks above may have let a read-only request through.
        if !cap_sys_time {
            return Err(EPERM);
        }
        // The sub-second field is a magnitude, not a signed remainder: the
        // sign of the step lives in tv_sec.
        if txc.time_usec < 0 {
            return Err(EINVAL);
        }
        let limit = if txc.modes & ADJ_NANO != 0 {
            NSEC_PER_SEC
        } else {
            USEC_PER_SEC
        };
        if txc.time_usec >= limit {
            return Err(EINVAL);
        }
    }

    // "Check for potential multiplication overflows that can only happen on
    // 64-bit systems" — `freq * PPM_SCALE` below.
    if txc.modes & ADJ_FREQUENCY != 0
        && (i64::MIN / PPM_SCALE > txc.freq || i64::MAX / PPM_SCALE < txc.freq)
    {
        return Err(EINVAL);
    }

    Ok(())
}

/// `kernel/time/ntp.c::process_adj_status()`. `now_sec` is the realtime
/// sample the caller took: turning the PLL on (re)starts the frequency
/// loop, so `time_reftime` is reset to now — Linux does the same, and
/// without it the first `ADJ_OFFSET` after a PLL turn-on would measure its
/// interval against the boot epoch and take the FLL path for a stale
/// interval.
fn process_adj_status(ntp: &mut NtpState, txc: &Timex, now_sec: i64) {
    // Turning the PLL off abandons the discipline: back to an undisciplined
    // clock, as at boot.
    if ntp.time_status & STA_PLL != 0 && txc.status & STA_PLL == 0 {
        ntp.time_state = TIME_OK;
        ntp.time_status = STA_UNSYNC;
    }
    if ntp.time_status & STA_PLL == 0 && txc.status & STA_PLL != 0 {
        ntp.time_reftime = now_sec;
    }
    ntp.time_status &= STA_RONLY;
    ntp.time_status |= txc.status & !STA_RONLY;
}

/// `kernel/time/ntp.c::process_adjtimex_modes()`. `now_sec` is the realtime
/// sample the caller took, threaded to the status handler (PLL turn-on
/// resets `time_reftime`) and to the offset handler (the frequency loop
/// measures its update interval against it).
fn process_modes(ntp: &mut NtpState, txc: &Timex, now_sec: i64) {
    if txc.modes & ADJ_STATUS != 0 {
        process_adj_status(ntp, txc, now_sec);
    }
    if txc.modes & ADJ_NANO != 0 {
        ntp.time_status |= STA_NANO;
    }
    if txc.modes & ADJ_MICRO != 0 {
        ntp.time_status &= !STA_NANO;
    }
    if txc.modes & ADJ_FREQUENCY != 0 {
        ntp.time_freq = (txc.freq * PPM_SCALE).clamp(-MAXFREQ_SCALED, MAXFREQ_SCALED);
    }
    if txc.modes & ADJ_MAXERROR != 0 {
        ntp.time_maxerror = txc.maxerror.clamp(0, NTP_PHASE_LIMIT);
    }
    if txc.modes & ADJ_ESTERROR != 0 {
        ntp.time_esterror = txc.esterror.clamp(0, NTP_PHASE_LIMIT);
    }
    if txc.modes & ADJ_TIMECONST != 0 {
        ntp.time_constant = txc.constant.clamp(0, MAXTC);
        if ntp.time_status & STA_NANO == 0 {
            ntp.time_constant += 4;
        }
        ntp.time_constant = ntp.time_constant.clamp(0, MAXTC);
    }
    // ADJ_TAI reads `constant`, not a field of its own, and silently ignores
    // an out-of-range offset rather than failing the call.
    if txc.modes & ADJ_TAI != 0 && (0..=MAX_TAI_OFFSET).contains(&txc.constant) {
        ntp.tai_offset = txc.constant as i32;
    }
    if txc.modes & ADJ_OFFSET != 0 {
        update_offset(ntp, txc.offset, now_sec);
    }
    if txc.modes & ADJ_TICK != 0 {
        ntp.tick_usec = txc.tick;
    }
    // Linux follows with ntp_update_frequency() — the tick-length recompute.
    // NARF has no timekeeper multiplier whose length to recompute: the
    // frequency lives in `time_freq`, reported back and consumed by the
    // discipline loop's error accounting, not by a tick-length register.
}

/// `kernel/time/ntp.c::ntp_update_offset_fll()`.
///
/// The FLL half of the frequency update: over a long interval the offset
/// itself measures the frequency error directly (`offset / secs`). Only
/// runs for intervals of at least `MINSEC`, and — unless the caller asked
/// for FLL mode with `STA_FLL` — only for intervals past `MAXSEC`, where
/// the PLL's assumptions no longer hold. Sets `STA_MODE` (the read-only
/// "FLL rather than PLL" bit) while it is active, and clears it otherwise.
fn update_offset_fll(ntp: &mut NtpState, offset64: i64, secs: i64) -> i64 {
    ntp.time_status &= !STA_MODE;
    if secs < MINSEC {
        return 0;
    }
    if ntp.time_status & STA_FLL == 0 && secs <= MAXSEC {
        return 0;
    }
    ntp.time_status |= STA_MODE;
    // `div64_long(offset64 << (NTP_SCALE_SHIFT - SHIFT_FLL), secs)`.
    // `offset64` is clamped to ±MAXPHASE (5e8), so the shift cannot
    // overflow: 5e8 << 30 ≈ 5.4e17 < i64::MAX.
    (offset64 << (NTP_SCALE_SHIFT - SHIFT_FLL)) / secs
}

/// `kernel/time/ntp.c::ntp_update_offset()` — the full function, phase and
/// frequency halves. The PLL gate, the clamps, and the scaling are the same
/// as the old phase-only version; the frequency half is what makes this a
/// discipline loop rather than a phase accumulator:
///
/// * the interval since the last update (`now_sec - time_reftime`, held at
///   0 under `STA_FREQHOLD`) feeds the FLL half above and the PLL term
///   `(offset * secs) << (NTP_SCALE_SHIFT - 2 * (SHIFT_PLL + 2 +
///   time_constant))`, with the interval clamped to
///   `1 << (SHIFT_PLL + 1 + time_constant)` so a low sampling rate (e.g. an
///   intermittent network connection) cannot destabilise the loop;
/// * the resulting frequency adjustment is added to `time_freq` and clamped
///   to ±`MAXFREQ_SCALED`, so the learned frequency error survives between
///   polls and the tick loop's phase drain converges instead of re-measuring
///   the same drift every poll.
fn update_offset(ntp: &mut NtpState, offset: i64, now_sec: i64) {
    if ntp.time_status & STA_PLL == 0 {
        return;
    }
    let mut offset_ns = offset;
    if ntp.time_status & STA_NANO == 0 {
        // "Make sure the multiplication below won't overflow"
        offset_ns = offset_ns.clamp(-USEC_PER_SEC, USEC_PER_SEC) * NSEC_PER_USEC;
    }
    offset_ns = offset_ns.clamp(-MAXPHASE, MAXPHASE);

    // Select how the frequency is to be controlled and in which mode
    // (PLL or FLL).
    let real_secs = now_sec;
    let mut secs = real_secs - ntp.time_reftime;
    if ntp.time_status & STA_FREQHOLD != 0 {
        secs = 0;
    }
    ntp.time_reftime = real_secs;

    let offset64 = offset_ns;
    let mut freq_adj = update_offset_fll(ntp, offset64, secs);

    // Clamp update interval to reduce PLL gain with low sampling rate
    // (e.g. intermittent network connection) to avoid instability.
    // Linux clamps only the upper side; NARF clamps the lower side too,
    // so a backwards wall step between updates (e.g. an RTC reset) cannot
    // overflow the shift below — the PLL term is symmetric in `secs`, so
    // this only bounds the gain, same as the upper clamp.
    let secs_clamp = 1i64 << (SHIFT_PLL + 1 + ntp.time_constant as u32);
    if secs > secs_clamp {
        secs = secs_clamp;
    } else if secs < -secs_clamp {
        secs = -secs_clamp;
    }
    // `(offset64 * secs) << (NTP_SCALE_SHIFT - 2 * (SHIFT_PLL + 2 +
    // time_constant))`. The shift stays ≥ 4 (`time_constant` ≤ `MAXTC` =
    // 10), and `offset64 * secs` ≤ 5e8 * 8192 ≈ 4.1e12, so no overflow.
    freq_adj +=
        (offset64 * secs) << (NTP_SCALE_SHIFT - 2 * (SHIFT_PLL + 2 + ntp.time_constant as u32));
    freq_adj = (freq_adj + ntp.time_freq).min(MAXFREQ_SCALED);
    ntp.time_freq = freq_adj.max(-MAXFREQ_SCALED);

    ntp.time_offset = (offset64 << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ;
}

/// `kernel/time/ntp.c::ntp_adjtimex()` — apply `txc`'s modes, then overwrite
/// every reported field from the resulting state. `now_sec`/`now_nsec` are
/// the realtime sample the caller took *before* any `ADJ_SETOFFSET` step, so
/// `timex.time` reads back as the time the request saw, as it does on Linux.
///
/// Returns the clock state: `time_state`, or [`TIME_ERROR`] when the status
/// says the clock is not usable. [`validate`] must have run first — this
/// function applies what it is given.
///
/// `ADJ_SETOFFSET` is deliberately not handled here: stepping the clock is
/// the timekeeper's job (`__timekeeping_inject_offset`), so the syscall layer
/// does it. Every other mode is pure NTP state and lives here.
pub fn adjtimex(txc: &mut Timex, now_sec: i64, now_nsec: i64) -> i64 {
    let mut ntp = NTP.lock();

    if txc.modes & ADJ_ADJTIME != 0 {
        // `adjtime(3)` is independent of `ntp_adjtime(3)`: the request
        // replaces the pending single-shot offset and reads back the one it
        // displaced (which is the whole point of the read-only spelling).
        let save_adjust = ntp.time_adjust;
        if txc.modes & ADJ_OFFSET_READONLY == 0 {
            ntp.time_adjust = txc.offset;
        }
        txc.offset = save_adjust;
    } else {
        if txc.modes != 0 {
            process_modes(&mut ntp, txc, now_sec);
        }
        txc.offset = shift_right(ntp.time_offset * NTP_INTERVAL_FREQ, NTP_SCALE_SHIFT);
        if ntp.time_status & STA_NANO == 0 {
            txc.offset /= NSEC_PER_USEC;
        }
    }

    let result = if is_error_status(ntp.time_status) {
        TIME_ERROR
    } else {
        ntp.time_state
    };

    txc.freq = shift_right(
        (ntp.time_freq >> PPM_SCALE_INV_SHIFT) * PPM_SCALE_INV,
        NTP_SCALE_SHIFT,
    );
    txc.maxerror = ntp.time_maxerror;
    txc.esterror = ntp.time_esterror;
    txc.status = ntp.time_status;
    txc.constant = ntp.time_constant;
    txc.precision = 1;
    txc.tolerance = MAXFREQ_SCALED / PPM_SCALE;
    txc.tick = ntp.tick_usec;
    txc.tai = ntp.tai_offset;

    txc.time_sec = now_sec;
    txc.time_usec = if ntp.time_status & STA_NANO != 0 {
        now_nsec
    } else {
        now_nsec / NSEC_PER_USEC
    };

    result
}

/// Current TAI offset (`ADJ_TAI`), seconds. No in-tree `CLOCK_TAI` reads it
/// yet — see the module LINUX-GAP — but `timex.tai` reports it.
pub fn tai_offset() -> i32 {
    NTP.lock().tai_offset
}

// ── SNTP discipline (issue #1764) ─────────────────────────────────────
//
// The in-kernel SNTP client (`narf_net::sntp`) measures the clock offset
// against a server and hands the sample here. This is the daemon side of
// RFC 5905's clock discipline (§11.3, Appendix A `local_clock()`), reduced
// to what the kernel PLL can consume: the step/slew decision plus the
// `ADJ_OFFSET` feed. The per-second drain is [`tick_second`], driven from
// the clockevent tick handler.

// RFC 5905 Appendix A `STEPT` — the step threshold: offsets larger than
// this are stepped, not slewed (a slew would take longer than the error is
// worth).
pub const SNTP_STEP_THRESHOLD_NS: i64 = 128_000_000;
// RFC 5905 Appendix A `PANICT` — the panic threshold: offsets larger than
// this are refused outright. A sample past it means the local clock was
// never set, the server is lying, or the reply was corrupted; stepping a
// whole day would do more harm than staying wrong.
pub const SNTP_PANIC_THRESHOLD_NS: i64 = 1_000_000_000_000;

/// What [`apply_sample`] did with an SNTP sample.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DisciplineOutcome {
    /// The clock was stepped by this many nanoseconds (the offset was over
    /// [`SNTP_STEP_THRESHOLD_NS`]).
    Stepped(i64),
    /// The offset was fed to the PLL (`ADJ_OFFSET` path); [`tick_second`]
    /// slews it off over the coming seconds.
    Slewed(i64),
    /// The sample was ignored; the reason is a static string so callers can
    /// log it without allocating.
    Ignored(&'static str),
}

/// Apply one SNTP sample to the discipline state — the `local_clock()`
/// step/slew decision (RFC 5905 Appendix A), with the frequency learning
/// delegated to [`update_offset`] and the phase drain to [`tick_second`].
///
/// `offset_ns` is the RFC 5905 §8 clock offset (server minus local, so a
/// positive value means the local clock is behind); `delay_ns` is the
/// round-trip delay and `root_dispersion_ns` the server's reported root
/// dispersion, both used for the error estimates Linux keeps as the NTP
/// sync distance (`time_maxerror` = dispersion + delay/2, `time_esterror` =
/// dispersion). `stratum` is the server's stratum. `now_sec` is the current
/// realtime in seconds.
///
/// The first accepted sample takes over discipline — it sets `STA_PLL` and
/// clears `STA_UNSYNC`, the step the module docs describe as "a time daemon
/// takes over" — and records `time_reftime` so the frequency loop measures
/// its first interval from the takeover, not from boot.
///
/// Panic-threshold and unsynchronised-server samples are refused, never
/// stepped: a step that large is evidence of a broken clock or a spoofed
/// reply, and Linux's daemon refuses it the same way.
pub fn apply_sample(
    offset_ns: i64,
    delay_ns: i64,
    root_dispersion_ns: i64,
    stratum: u8,
    now_sec: i64,
) -> DisciplineOutcome {
    if stratum == STRATUM_UNSPECIFIED || stratum >= STRATUM_UNSYNCED {
        return DisciplineOutcome::Ignored("server stratum unsynchronised");
    }
    if offset_ns.unsigned_abs() > SNTP_PANIC_THRESHOLD_NS as u64 {
        return DisciplineOutcome::Ignored("offset over panic threshold");
    }

    let mut ntp = NTP.lock();

    // Take over discipline on the first accepted sample.
    if ntp.time_status & STA_PLL == 0 {
        ntp.time_status |= STA_PLL;
        ntp.time_reftime = now_sec;
    }
    ntp.time_status &= !STA_UNSYNC;

    // The sample's error estimates: Linux's sync distance.
    ntp.time_esterror = (root_dispersion_ns / NSEC_PER_USEC).clamp(0, NTP_PHASE_LIMIT);
    ntp.time_maxerror =
        ((root_dispersion_ns + delay_ns / 2) / NSEC_PER_USEC).clamp(0, NTP_PHASE_LIMIT);

    if offset_ns.unsigned_abs() > SNTP_STEP_THRESHOLD_NS as u64 {
        // Step, as `local_clock()`'s `step_time(offset)` does: fold the
        // whole offset into the wall clock at once and drop any pending
        // phase — slewing 128 ms+ would take minutes at the PLL's rate.
        // The frequency estimate survives the step (Linux keeps it across
        // `rstclock()` too, re-learning from the next samples).
        ntp.time_offset = 0;
        ntp.time_reftime = now_sec;
        crate::wall::adjust_wall_offset_ns(offset_ns);
        return DisciplineOutcome::Stepped(offset_ns);
    }

    // Slew: feed the phase to the PLL in the units `ADJ_OFFSET` takes —
    // microseconds while `STA_NANO` is clear. `update_offset` learns the
    // frequency from the interval since the last update and stores the
    // phase in `time_offset`; `tick_second` drains it.
    update_offset(&mut ntp, offset_ns / NSEC_PER_USEC, now_sec);
    DisciplineOutcome::Slewed(offset_ns)
}

/// The per-second discipline step — `kernel/time/ntp.c::second_overflow()`'s
/// phase half, adapted to NARF's wall clock. Called once per wall second
/// from the clockevent tick handler ([`crate::clockevent::on_tick`]).
///
/// * Bumps `time_maxerror` by `MAXFREQ / NSEC_PER_USEC` (500 µs per
///   second), clamping at `NTP_PHASE_LIMIT`; on saturation the clock is
///   marked `STA_UNSYNC`, exactly as Linux does — a clock nobody has fed
///   for ~4.4 hours is no longer trusted. A fresh SNTP sample resets the
///   estimates (see [`apply_sample`]), so a polling client never trips it.
/// * Drains `time_offset` exponentially: the chunk is
///   `ntp_offset_chunk()` — `time_offset >> (SHIFT_PLL + time_constant)` —
///   and when the chunk rounds to zero the whole remainder is delivered so
///   the phase converges instead of stalling just above zero (both are
///   Linux's `second_overflow()` verbatim). The chunk, converted back to
///   nanoseconds, is folded into the wall offset — that is the slew, since
///   NARF has no timekeeper multiplier to steer.
///
/// IRQ-safe: one spinlock plus atomics, no blocking, no allocation. Safe
/// to call before any sample was ever applied (the boot state has
/// `time_offset == 0`, so it is a maxerror bump and nothing else).
///
/// The leap half of `second_overflow()` is deliberately not here: leap
/// handling stays with the smear (`crate::wall::begin_leap_smear`), per the
/// module LINUX-GAP. `time_adjust` (the `ADJ_ADJTIME` single-shot offset)
/// is not drained either — same gap, same reason.
pub fn tick_second() {
    let mut ntp = NTP.lock();

    // Bump the maxerror field.
    ntp.time_maxerror += MAXFREQ / NSEC_PER_USEC;
    if ntp.time_maxerror > NTP_PHASE_LIMIT {
        ntp.time_maxerror = NTP_PHASE_LIMIT;
        ntp.time_status |= STA_UNSYNC;
    }

    // Compute the phase adjustment for the next second.
    if ntp.time_offset != 0 {
        // `ntp_offset_chunk()` (no-PPS form): exponential drain.
        let mut chunk = shift_right(ntp.time_offset, SHIFT_PLL + ntp.time_constant as u32);
        // Once the exponential chunk rounds to zero, deliver the last
        // remaining offset this second so it converges to zero instead
        // of stalling just above it.
        if chunk == 0 {
            chunk = ntp.time_offset;
        }
        // `chunk` is in `time_offset` units ((ns << 32) / 100); convert
        // back to ns. `chunk * NTP_INTERVAL_FREQ` cannot overflow:
        // `|time_offset|` ≤ `MAXPHASE << 32 / 100` ≈ 2.1e16, times 100
        // is ≈ 2.1e18 < `i64::MAX`.
        let chunk_ns = shift_right(chunk * NTP_INTERVAL_FREQ, NTP_SCALE_SHIFT);
        ntp.time_offset -= chunk;
        crate::wall::adjust_wall_offset_ns(chunk_ns);
    }
}

/// Test helper: restore the NTP state to Linux's boot defaults (see the
/// `NTP` initialiser). Tests that feed samples or drain phase must call
/// this first and last — the state is process-global and the adjtimex
/// syscall tests assert the boot defaults.
#[doc(hidden)]
pub fn __test_reset() {
    *NTP.lock() = NtpState {
        tick_usec: USER_TICK_USEC,
        time_state: TIME_OK,
        time_status: STA_UNSYNC,
        time_constant: 2,
        time_maxerror: NTP_PHASE_LIMIT,
        time_esterror: NTP_PHASE_LIMIT,
        time_freq: 0,
        time_offset: 0,
        time_reftime: 0,
        time_adjust: 0,
        tai_offset: 0,
    };
}
