//! Delta conversion for a one-shot clockevent device that counts at a
//! measured ratio to the reference clock.
//!
//! Linux's `clockevents_config` (kernel/time/clockevents.c) turns a device
//! frequency into a `mult`/`shift` pair plus `min_delta_ns`/`max_delta_ns`,
//! and `clockevents_program_event` clamps every requested delta to that range
//! before converting it to device ticks. NARF expresses deadlines in reference
//! counter units (TSC cycles on x86_64) rather than nanoseconds, and the
//! device ratio comes from a calibration run (Linux `calibrate_APIC_clock`)
//! whose endpoints each carry a known read uncertainty. [`ClockEventScale`]
//! keeps that uncertainty instead of discarding it:
//!
//! - deltas are converted with the **upper** bound of the measured
//!   ticks-per-unit ratio, so the programmed device never fires before the
//!   requested delta has elapsed — an early interrupt finds nothing due and
//!   costs a second, minimum-delta interrupt;
//! - [`Programmed::latest`] uses the **lower** bound, so a caller that
//!   records `now + latest` as the armed deadline never treats a still
//!   counting device as having fired. Re-programming such a device would
//!   cancel the interrupt it was about to raise.
//!
//! Pure integer arithmetic (32.32 fixed point, 128-bit products); no hardware.

/// Fixed-point fraction bits of the stored ratios.
const FRAC: u32 = 32;

/// `ceil(x * m / 2^FRAC)`.
#[inline]
const fn mul_frac_ceil(x: u64, m: u64) -> u64 {
    let p = (x as u128) * (m as u128);
    let r = (p + ((1u128 << FRAC) - 1)) >> FRAC;
    if r > u64::MAX as u128 {
        u64::MAX
    } else {
        r as u64
    }
}

/// `floor(x * m / 2^FRAC)`.
#[inline]
const fn mul_frac_floor(x: u64, m: u64) -> u64 {
    let r = ((x as u128) * (m as u128)) >> FRAC;
    if r > u64::MAX as u128 {
        u64::MAX
    } else {
        r as u64
    }
}

/// `n * 2^FRAC / d` rounded up (`up`) or down, saturating; `None` for `d == 0`.
const fn ratio(n: u64, d: u64, up: bool) -> Option<u64> {
    if d == 0 {
        return None;
    }
    let num = (n as u128) << FRAC;
    let d = d as u128;
    let q = if up { num.div_ceil(d) } else { num / d };
    if q > u64::MAX as u128 {
        None
    } else {
        Some(q as u64)
    }
}

/// One programming decision of [`ClockEventScale::program`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Programmed {
    /// Device ticks to load (Linux `clc`, written to e.g. LAPIC `TMICT`).
    pub ticks: u64,
    /// The device fires no later than this many reference units from the
    /// moment it was loaded (modulo interrupt delivery latency).
    pub latest: u64,
}

/// Reference-unit ↔ device-tick conversion for a one-shot clockevent
/// (Linux `struct clock_event_device` `mult`/`shift`/`min_delta_*`/
/// `max_delta_*`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClockEventScale {
    /// Device ticks per reference unit, upper bound, 32.32 fixed point.
    ticks_per_unit_hi: u64,
    /// Reference units per device tick, lower bound (= 1 / `ticks_per_unit_hi`).
    units_per_tick_lo: u64,
    /// Reference units per device tick, upper bound.
    units_per_tick_hi: u64,
    /// Reference units per device tick, the measured value.
    units_per_tick: u64,
    min_ticks: u64,
    max_ticks: u64,
    /// Smallest delta accepted by [`Self::program`] (Linux `min_delta_ns`).
    min_delta: u64,
    /// Largest delta accepted by [`Self::program`] (Linux `max_delta_ns`).
    max_delta: u64,
}

impl ClockEventScale {
    /// Build the conversion from a calibration: the device counted `ticks`
    /// while the reference clock advanced `units`. Each of the two
    /// `(reference, device)` samples bounding the window was taken within
    /// a bracket of the reference clock; `units_err` is the sum of the two
    /// half-brackets, so the true window is `units ± units_err`. The device
    /// count is exact to one tick at each end.
    ///
    /// `min_ticks`/`max_ticks` are the device's programmable range (Linux
    /// `min_delta_ticks`/`max_delta_ticks`; LAPIC: `0xF`/`0x7FFF_FFFF`).
    ///
    /// Returns `None` for a measurement that cannot bound the ratio: no
    /// ticks, an error as large as the window, or an empty tick range.
    pub const fn from_measurement(
        units: u64,
        ticks: u64,
        units_err: u64,
        min_ticks: u64,
        max_ticks: u64,
    ) -> Option<Self> {
        if ticks < 2 || units <= units_err || min_ticks == 0 || min_ticks > max_ticks {
            return None;
        }
        // Widest ratio range consistent with the measurement: one tick of
        // count quantisation at each end, `units_err` on the window.
        let fast_ticks = ticks + 1;
        let slow_ticks = ticks - 1;
        let short_units = units - units_err;
        let long_units = units.saturating_add(units_err);
        let Some(ticks_per_unit_hi) = ratio(fast_ticks, short_units, true) else {
            return None;
        };
        let Some(units_per_tick_lo) = ratio(short_units, fast_ticks, false) else {
            return None;
        };
        let Some(units_per_tick_hi) = ratio(long_units, slow_ticks, true) else {
            return None;
        };
        let Some(units_per_tick) = ratio(units, ticks, false) else {
            return None;
        };
        if ticks_per_unit_hi == 0 || units_per_tick_lo == 0 {
            return None;
        }
        // Linux `clockevents_config`: min/max delta are the tick limits
        // converted back to the request unit. The minimum is taken on the
        // slow side so a clamped request always loads >= `min_ticks`.
        let min_delta = mul_frac_ceil(min_ticks, units_per_tick_hi);
        let max_delta = mul_frac_floor(max_ticks, units_per_tick_lo);
        if min_delta > max_delta {
            return None;
        }
        Some(Self {
            ticks_per_unit_hi,
            units_per_tick_lo,
            units_per_tick_hi,
            units_per_tick,
            min_ticks,
            max_ticks,
            min_delta,
            max_delta,
        })
    }

    /// Linux `clockevents_program_event`: clamp `delta` (reference units
    /// from now) to `[min_delta, max_delta]` and convert it to device ticks.
    /// The device then fires no earlier than the clamped delta and no later
    /// than [`Programmed::latest`].
    pub const fn program(&self, delta: u64) -> Programmed {
        let delta = if delta < self.min_delta {
            self.min_delta
        } else if delta > self.max_delta {
            self.max_delta
        } else {
            delta
        };
        let mut ticks = mul_frac_ceil(delta, self.ticks_per_unit_hi);
        if ticks < self.min_ticks {
            ticks = self.min_ticks;
        } else if ticks > self.max_ticks {
            ticks = self.max_ticks;
        }
        let latest = mul_frac_ceil(ticks, self.units_per_tick_hi);
        Programmed {
            ticks,
            latest: if latest < delta { delta } else { latest },
        }
    }

    /// Reference units `ticks` device ticks take, at the measured ratio
    /// (a periodic reload expressed in device ticks, the tick resolution).
    pub const fn ticks_to_units(&self, ticks: u64) -> u64 {
        mul_frac_floor(ticks, self.units_per_tick)
    }

    /// Smallest programmable delta, reference units (Linux `min_delta_ns`).
    pub const fn min_delta(&self) -> u64 {
        self.min_delta
    }

    /// Largest programmable delta, reference units (Linux `max_delta_ns`).
    pub const fn max_delta(&self) -> u64 {
        self.max_delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LAPIC_MIN: u64 = 0xF;
    const LAPIC_MAX: u64 = 0x7FFF_FFFF;

    /// 4.7 GHz TSC against a 100 MHz APIC clock divided by 16 (6.25 MHz),
    /// measured over 10 ms with a 200-cycle read bracket at each end.
    fn zen() -> ClockEventScale {
        ClockEventScale::from_measurement(47_000_000, 62_500, 200, LAPIC_MIN, LAPIC_MAX).unwrap()
    }

    /// QEMU/KVM: 3 GHz TSC against the 1 GHz emulated APIC bus / 16,
    /// measured over ~7 ms with a 2 µs (6000-cycle) VM-exit bracket.
    fn kvm() -> ClockEventScale {
        ClockEventScale::from_measurement(21_000_000, 437_500, 6_000, LAPIC_MIN, LAPIC_MAX).unwrap()
    }

    /// The device never fires before `delta` at any true ratio the
    /// measurement admits: `ticks / true_ticks_per_unit >= delta`, checked at
    /// the fastest admissible ratio `(ticks + 1) / (units - err)`.
    fn never_early(units: u64, ticks: u64, err: u64, delta: u64, s: &ClockEventScale) -> bool {
        let p = s.program(delta);
        let delta = delta.clamp(s.min_delta(), s.max_delta());
        // p.ticks * (units - err) >= delta * (ticks + 1)
        (p.ticks as u128) * ((units - err) as u128) >= (delta as u128) * ((ticks + 1) as u128)
    }

    /// `latest` is no earlier than the device can fire at the slowest
    /// admissible ratio `(ticks - 1) / (units + err)`.
    fn never_claims_fired_early(
        units: u64,
        ticks: u64,
        err: u64,
        delta: u64,
        s: &ClockEventScale,
    ) -> bool {
        let p = s.program(delta);
        // p.latest * (ticks - 1) >= p.ticks * (units + err)
        (p.latest as u128) * ((ticks - 1) as u128) >= (p.ticks as u128) * ((units + err) as u128)
    }

    #[test]
    fn converts_a_millisecond_on_zen() {
        let s = zen();
        // 1 ms at 4.7 GHz = 4.7 M cycles ≈ 6250 APIC ticks.
        let p = s.program(4_700_000);
        assert!((6_250..=6_252).contains(&p.ticks), "{p:?}");
        assert!(
            p.latest >= 4_700_000 && p.latest < 4_700_000 + 4_700,
            "{p:?}"
        );
    }

    #[test]
    fn converts_a_millisecond_under_kvm() {
        let s = kvm();
        // 1 ms at 3 GHz ≈ 62_500 ticks; the 2 µs brackets widen it slightly.
        let p = s.program(3_000_000);
        assert!((62_500..=62_550).contains(&p.ticks), "{p:?}");
        assert!(
            p.latest >= 3_000_000 && p.latest < 3_000_000 + 3_000,
            "{p:?}"
        );
    }

    #[test]
    fn programming_is_never_early_and_never_claims_an_early_fire() {
        for (units, ticks, err) in [
            (47_000_000u64, 62_500u64, 200u64),
            (21_000_000, 437_500, 6_000),
            (33_554_432, 65_536, 1),
            (1 << 30, 1_200_000, 40_000),
        ] {
            let s =
                ClockEventScale::from_measurement(units, ticks, err, LAPIC_MIN, LAPIC_MAX).unwrap();
            let mut delta = 1u64;
            while delta < (1 << 44) {
                assert!(
                    never_early(units, ticks, err, delta, &s),
                    "early: {units} {ticks} {delta}"
                );
                assert!(
                    never_claims_fired_early(units, ticks, err, delta, &s),
                    "latest too soon: {units} {ticks} {delta}"
                );
                delta = delta * 3 + 7;
            }
        }
    }

    #[test]
    fn clamps_to_the_programmable_range() {
        let s = zen();
        // Below min_delta: loads at least the LAPIC's 0xF ticks.
        let p = s.program(0);
        assert!(p.ticks >= LAPIC_MIN);
        assert!(p.latest >= s.min_delta());
        // Far beyond max_delta: loads no more than 0x7FFF_FFFF ticks and
        // reports the clamped deadline, not the requested one.
        let p = s.program(u64::MAX);
        assert!(p.ticks <= LAPIC_MAX);
        assert!(p.latest < u64::MAX / 2);
        assert!(p.latest >= s.max_delta());
        // max_delta is ~343 s of 6.25 MHz ticks at 4.7 GHz.
        let secs = s.max_delta() / 4_700_000_000;
        assert!((340..=344).contains(&secs), "{secs}");
    }

    #[test]
    fn ticks_to_units_uses_the_measured_ratio() {
        let s = zen();
        // 10_000 ticks at 6.25 MHz = 1.6 ms = 7.52 M cycles at 4.7 GHz.
        assert_eq!(s.ticks_to_units(10_000), 7_520_000);
        assert_eq!(s.ticks_to_units(0), 0);
        // One tick: 752 cycles (the one-shot resolution).
        assert_eq!(s.ticks_to_units(1), 752);
    }

    #[test]
    fn rejects_measurements_that_bound_nothing() {
        assert!(ClockEventScale::from_measurement(1_000, 0, 0, 1, 10).is_none());
        assert!(ClockEventScale::from_measurement(1_000, 1, 0, 1, 10).is_none());
        assert!(ClockEventScale::from_measurement(1_000, 500, 1_000, 1, 10).is_none());
        assert!(ClockEventScale::from_measurement(1_000, 500, 0, 0, 10).is_none());
        assert!(ClockEventScale::from_measurement(1_000, 500, 0, 11, 10).is_none());
        assert!(ClockEventScale::from_measurement(0, 500, 0, 1, 10).is_none());
    }

    #[test]
    fn wider_uncertainty_only_moves_toward_late() {
        let tight =
            ClockEventScale::from_measurement(47_000_000, 62_500, 0, LAPIC_MIN, LAPIC_MAX).unwrap();
        let loose =
            ClockEventScale::from_measurement(47_000_000, 62_500, 50_000, LAPIC_MIN, LAPIC_MAX)
                .unwrap();
        let d = 47_000_000;
        assert!(loose.program(d).ticks >= tight.program(d).ticks);
        assert!(loose.program(d).latest >= tight.program(d).latest);
    }
}
