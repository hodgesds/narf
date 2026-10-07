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
//! LINUX-GAP: the variables are modelled; the *discipline* is not. Linux feeds
//! `time_offset` / `time_freq` into `second_overflow()` on every tick and into
//! the timekeeper's multiplier, so a PLL correction physically slews
//! CLOCK_REALTIME. NARF has no tick-driven NTP loop and a fixed clocksource
//! multiplier, so `ADJ_OFFSET` and `ADJ_FREQUENCY` are recorded, reported back
//! and never consumed — a daemon's phase correction stays pending instead of
//! being worked off. `ADJ_SETOFFSET` (a step, not a slew) is the one request
//! that moves the clock; `ADJ_TICK`, `ADJ_STATUS`, `ADJ_TIMECONST`,
//! `ADJ_MAXERROR`, `ADJ_ESTERROR` and `ADJ_TAI` are pure state either way.
//!
//! LINUX-GAP: no leap-second machinery here. `STA_INS` / `STA_DEL` are stored
//! and reported, but `time_state` never advances to `TIME_INS` / `TIME_DEL` /
//! `TIME_OOP` / `TIME_WAIT` because nothing runs `second_overflow()`. NARF's
//! leap handling is [`crate::wall::begin_leap_smear`] — a different mechanism
//! with no adjtimex surface.
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
/// Insert a leap second.
pub const STA_INS: i32 = 0x0010;
/// Delete a leap second.
pub const STA_DEL: i32 = 0x0020;
/// The clock is not synchronised. Linux's boot default.
pub const STA_UNSYNC: i32 = 0x0040;
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

/// `kernel/time/ntp.c::process_adj_status()`.
fn process_adj_status(ntp: &mut NtpState, txc: &Timex) {
    // Turning the PLL off abandons the discipline: back to an undisciplined
    // clock, as at boot.
    if ntp.time_status & STA_PLL != 0 && txc.status & STA_PLL == 0 {
        ntp.time_state = TIME_OK;
        ntp.time_status = STA_UNSYNC;
    }
    // (Linux also resets `time_reftime` when the PLL is turned ON, which only
    // matters to the frequency loop NARF does not run.)

    // Only the writable bits come from the request.
    ntp.time_status &= STA_RONLY;
    ntp.time_status |= txc.status & !STA_RONLY;
}

/// `kernel/time/ntp.c::process_adjtimex_modes()`.
fn process_modes(ntp: &mut NtpState, txc: &Timex) {
    if txc.modes & ADJ_STATUS != 0 {
        process_adj_status(ntp, txc);
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
        update_offset(ntp, txc.offset);
    }
    if txc.modes & ADJ_TICK != 0 {
        ntp.tick_usec = txc.tick;
    }
    // Linux follows with ntp_update_frequency() — the tick-length recompute
    // for a loop NARF does not run (see the module LINUX-GAPs).
}

/// `kernel/time/ntp.c::ntp_update_offset()`, reduced to the phase bookkeeping
/// NARF can honour: the PLL gate, the clamps, and the scaling the read-back
/// inverts. The frequency-adjustment half of the function belongs to the
/// discipline loop and is a documented gap.
fn update_offset(ntp: &mut NtpState, offset: i64) {
    if ntp.time_status & STA_PLL == 0 {
        return;
    }
    let mut offset_ns = offset;
    if ntp.time_status & STA_NANO == 0 {
        // "Make sure the multiplication below won't overflow"
        offset_ns = offset_ns.clamp(-USEC_PER_SEC, USEC_PER_SEC) * NSEC_PER_USEC;
    }
    offset_ns = offset_ns.clamp(-MAXPHASE, MAXPHASE);
    ntp.time_offset = (offset_ns << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ;
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
            process_modes(&mut ntp, txc);
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
