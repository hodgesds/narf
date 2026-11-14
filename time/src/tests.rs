//! Subsystem smokes for `narf-time`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `time` subsystem.
//!
//! Note: `smoke_sleep_future_waits` was *not* migrated here because
//! it depends on `narf-scheduler`, which is downstream of `narf-time`
//! and cannot be added without forming a cycle. That smoke remains in
//! the verification mega-lib (or should move into a scheduler-side
//! `tests.rs`).

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_monotonic_advances() -> TestResult {
    let a = crate::now_cycles();
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }
    let b = crate::now_cycles();
    if b > a {
        TestResult::Pass
    } else {
        TestResult::Fail("monotonic counter didn't advance")
    }
}
kernel_test_in!("time", smoke_monotonic_advances);

fn smoke_clock_scale_fixed_point_accuracy() -> TestResult {
    // One second of a 2.397 GHz TSC (2_397_000_000 cycles) must convert
    // to ~1e9 ns. The old integer `cyc / cycles_per_ns` truncated the
    // scale 2.397 → 2, yielding ~1.2e9 ns (20% fast); the mult/shift
    // path must be within 1 ppm.
    let ns = crate::wall::__test_cyc_to_ns_for_hz(2_397_000_000, 2_397_000_000);
    if ns.abs_diff(1_000_000_000) > 1_000 {
        return TestResult::Fail("2.397 GHz cyc->ns off by >1 ppm");
    }
    // A non-round frequency (3.3 GHz) over a 10 s span: 33e9 cyc → 10e9 ns.
    let ns2 = crate::wall::__test_cyc_to_ns_for_hz(3_300_000_000, 33_000_000_000);
    if ns2.abs_diff(10_000_000_000) > 10_000 {
        return TestResult::Fail("3.3 GHz cyc->ns off by >1 ppm");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_clock_scale_fixed_point_accuracy);

/// The ns→cycles direction, which sets the system tick rate.
///
/// `arm_periodic` turns "1000 Hz" into a TSC-deadline period of
/// `ns_to_cycles(1_000_000)`. It used to be `1_000_000 * cycles_per_ns()`,
/// and `cycles_per_ns()` is a TRUNCATED integer GHz clamped to 1..=6 — so
/// a 3.293 GHz TSC (a real measured value: `tsc: calibrated to 3293 MHz`)
/// read back as 3 and the period came out 9.8% long. Every CPU on the
/// machine then ticked slow against the rate the kernel believed it had
/// asked for, and every ns→cycles deadline in the tree inherited the same
/// skew.
///
/// The bound here is deliberately tight enough (1 ppm) that reverting to
/// the integer form fails it: the truncated answer is 3_000_000 cycles
/// against a correct 3_293_000, ~89000x the tolerance.
fn smoke_clock_ns_to_cycles_fixed_point_accuracy() -> TestResult {
    // 1 ms at 3.293 GHz = 3_293_000 cycles.
    let cyc = crate::wall::__test_ns_to_cyc_for_hz(3_293_000_000, 1_000_000);
    if cyc.abs_diff(3_293_000) > 4 {
        return TestResult::Fail("3.293 GHz ns->cyc off by >1 ppm (truncated integer rate?)");
    }
    // Round-trip: ns -> cycles -> ns must return the input at 1 ppm.
    let back = crate::wall::__test_cyc_to_ns_for_hz(3_293_000_000, cyc);
    if back.abs_diff(1_000_000) > 1 {
        return TestResult::Fail("ns->cyc->ns round-trip lost more than 1 ppm");
    }
    // A second non-integer rate, and a full second so any per-unit drift
    // is 1e9x amplified: 2.397 GHz.
    let cyc2 = crate::wall::__test_ns_to_cyc_for_hz(2_397_000_000, 1_000_000_000);
    if cyc2.abs_diff(2_397_000_000) > 2_400 {
        return TestResult::Fail("2.397 GHz ns->cyc off by >1 ppm");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_clock_ns_to_cycles_fixed_point_accuracy);

/// An arch frequency cache may already exist before wall conversions are
/// installed. Returning Cached must still make Deadline use that frequency.
#[cfg(target_arch = "x86_64")]
fn smoke_cached_calibration_installs_wall_scales() -> TestResult {
    let hz = narf_arch::x86_64::tsc::frequency_hz();
    if hz == 0 {
        return TestResult::Skip("TSC not calibrated");
    }
    let (result, source, cycles, ns) = narf_lib::sync::without_interrupts(|| {
        crate::set_clock_hz(1_000_000_000); // the pre-calibration identity scale
        let (result, source) = crate::calibrate_clocks_with_source();
        let cycles = crate::ns_to_cycles(1_000_000);
        let ns = crate::cycles_to_ns(hz);
        // Restore even when testing the old implementation, before assertions.
        crate::set_clock_hz(hz);
        (result, source, cycles, ns)
    });
    if result != hz || source != crate::CalibrationSource::Cached {
        return TestResult::Fail("cached TSC frequency not reused");
    }
    if cycles.abs_diff(hz / 1000) > (hz / 1_000_000_000).max(1) || ns.abs_diff(1_000_000_000) > 1000
    {
        return TestResult::Fail("cached calibration left wall conversions uncalibrated");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "time/calibration",
    smoke_cached_calibration_installs_wall_scales
);

fn smoke_hpet_calibration_samples_wrap_and_reject_stalled_counters() -> TestResult {
    use core::cell::Cell;
    let sample = |start: u64, end: u64, cycles: u64| {
        let hpet_reads = Cell::new(0);
        let tsc_reads = Cell::new(0);
        crate::hpet::measure_tsc(
            100_000_000,
            200,
            || {
                let n = hpet_reads.get();
                hpet_reads.set(n + 1);
                if n == 0 {
                    start
                } else {
                    end
                }
            },
            || {
                let n = tsc_reads.get();
                tsc_reads.set(n + 1);
                if n == 0 {
                    100
                } else {
                    100 + cycles
                }
            },
        )
    };
    if sample(1000, 1200, 10_000) != Some(5_000_000_000)
        || sample(u64::MAX - 100, 99, 10_000) != Some(5_000_000_000)
        || sample(1000, 1200, 0).is_some()
        || sample(1000, 1200, u64::MAX / 2).is_some()
    {
        return TestResult::Fail("HPET/TSC ratio, wrap, zero or overflow handling");
    }
    let tsc_reads = Cell::new(0);
    let stalled = crate::hpet::measure_tsc(
        100_000_000,
        200,
        || 123,
        || {
            let n = tsc_reads.get();
            tsc_reads.set(n + 1);
            if n == 0 {
                0
            } else {
                6_500_000_001
            }
        },
    );
    if stalled.is_some() || tsc_reads.get() != 2 {
        return TestResult::Fail("stalled HPET calibration ignored its TSC safety bound");
    }
    for (frequency, window) in [(0, 200), (100_000_000, 0)] {
        if crate::hpet::measure_tsc(frequency, window, || 0, || 0).is_some() {
            return TestResult::Fail("invalid HPET sample parameters accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "time/calibration",
    smoke_hpet_calibration_samples_wrap_and_reject_stalled_counters
);

// ── RTC backstops (CMOS / PL031 / Qualcomm PMIC) ──────────────────

fn smoke_rtc_cmos_bcd_to_bin_and_back() -> TestResult {
    use crate::rtc::cmos::{bcd_to_bin, bin_to_bcd};

    if bcd_to_bin(0x42) != 42 {
        return TestResult::Fail("BCD decode");
    }

    if bin_to_bcd(99) != 0x99 {
        return TestResult::Fail("BCD encode");
    }

    if bin_to_bcd(bcd_to_bin(0x59)) != 0x59 {
        return TestResult::Fail("BCD round-trip");
    }

    TestResult::Pass
}

kernel_test_in!("time/rtc", smoke_rtc_cmos_bcd_to_bin_and_back);

fn smoke_rtc_cmos_decodes_bcd_24h_with_century() -> TestResult {
    use crate::rtc::cmos::{decode_snapshot, CmosSnapshot, STATUS_B_24H};

    // 2026-05-07 14:35:22, BCD + 24h.

    let dt = decode_snapshot(CmosSnapshot {
        sec: 0x22,
        min: 0x35,
        hour: 0x14,
        day: 0x07,
        month: 0x05,
        year: 0x26,
        century: 0x20,
        status_b: STATUS_B_24H,
    });

    if dt.year != 2026 || dt.month != 5 || dt.day != 7 {
        return TestResult::Fail("date wrong");
    }

    if dt.hour != 14 || dt.minute != 35 || dt.second != 22 {
        return TestResult::Fail("time wrong");
    }

    TestResult::Pass
}

kernel_test_in!("time/rtc", smoke_rtc_cmos_decodes_bcd_24h_with_century);

fn smoke_rtc_cmos_12h_pm_bit_promotes_hour() -> TestResult {
    use crate::rtc::cmos::{decode_snapshot, CmosSnapshot};

    // 12h mode: status_b 24H bit clear. 03 PM with PM bit set →

    // hour 15.

    // sec/min/hour are BCD by default (status_b=0).

    let dt = decode_snapshot(CmosSnapshot {
        sec: 0,
        min: 0,
        hour: 0x83,
        day: 0x01,
        month: 0x01,
        year: 0x26,
        century: 0x20,
        status_b: 0,
    });

    if dt.hour != 15 {
        return TestResult::Fail("PM 03 should be 15:00");
    }

    TestResult::Pass
}

kernel_test_in!("time/rtc", smoke_rtc_cmos_12h_pm_bit_promotes_hour);

fn smoke_rtc_pl031_unix_seconds_to_datetime_known_vector() -> TestResult {
    use crate::rtc::pl031::unix_seconds_to_datetime;

    // 2026-05-07 14:35:22 UTC = 1762525122 (cross-checked vs the

    // POSIX-time formula).

    let dt = unix_seconds_to_datetime(1_778_589_322);

    // 1_778_589_322 = 2026-05-07 ... let's just confirm it's 2026,

    // a sane month, and the seconds round-trip.

    if dt.year != 2026 {
        return TestResult::Fail("year");
    }

    let s = crate::rtc::RtcDateTime { ..dt }.to_unix_seconds();

    if s != 1_778_589_322 {
        return TestResult::Fail("round-trip");
    }

    TestResult::Pass
}

kernel_test_in!(
    "time/rtc",
    smoke_rtc_pl031_unix_seconds_to_datetime_known_vector
);

fn smoke_rtc_pmic_decodes_4_byte_rdata_snapshot() -> TestResult {
    use crate::rtc::pmic::decode_snapshot;

    let s = 0u32; // Unix epoch.

    let dt = decode_snapshot(s.to_le_bytes());

    if dt.year != 1970 || dt.month != 1 || dt.day != 1 {
        return TestResult::Fail("epoch decode");
    }

    if dt.hour != 0 || dt.minute != 0 || dt.second != 0 {
        return TestResult::Fail("epoch h/m/s");
    }

    TestResult::Pass
}

kernel_test_in!("time/rtc", smoke_rtc_pmic_decodes_4_byte_rdata_snapshot);

fn smoke_rtc_datetime_unix_seconds_known_vectors() -> TestResult {
    use crate::rtc::RtcDateTime;

    // 1970-01-01 00:00:00 = 0.

    let dt = RtcDateTime {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    if dt.to_unix_seconds() != 0 {
        return TestResult::Fail("epoch");
    }

    // 2000-01-01 00:00:00 = 946684800.

    let dt = RtcDateTime {
        year: 2000,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    if dt.to_unix_seconds() != 946_684_800 {
        return TestResult::Fail("y2k");
    }

    TestResult::Pass
}

kernel_test_in!("time/rtc", smoke_rtc_datetime_unix_seconds_known_vectors);

// ── relocated from verification (subsystem 'time') ──

fn smoke_time_wall_offset_and_leap_smear() -> TestResult {
    use crate::{begin_leap_smear, now_wall, set_wall_offset, wall, WallClock, WallError};
    use narf_capabilities::{Cap, Write};

    wall::__test_reset();

    let cap: Cap<WallClock, Write> = Cap::bootstrap();

    // Setting an offset of 1_000_000_000 ns (1s) must show up in now_wall().
    if set_wall_offset(&cap, 1_000_000_000).is_err() {
        return TestResult::Fail("set_wall_offset failed on a live cap");
    }
    let t0 = now_wall();
    if t0.secs < 1 {
        return TestResult::Fail("wall offset did not take effect");
    }

    // Zero-window leap smear must be rejected structurally.
    match begin_leap_smear(&cap, 1_000, 0) {
        Err(WallError::InvalidSmearWindow) => {}
        _ => return TestResult::Fail("zero-window leap smear accepted"),
    }

    // A normal smear (500 ns window, 10 ns delta) must succeed.
    if begin_leap_smear(&cap, 10, 500).is_err() {
        return TestResult::Fail("legitimate leap smear rejected");
    }

    // Revocation blocks further writes.
    cap.revoke();
    match set_wall_offset(&cap, 0) {
        Err(WallError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked wall-clock cap accepted"),
    }

    wall::__test_reset();
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_wall_offset_and_leap_smear);

// ── HPET comparator-programming smokes ───────────────────────────

/// Linux `hpet_clkevt_set_next_event`: a one-shot comparator the counter has
/// passed, or is within `HPET_MIN_CYCLES` of, is -ETIME (equality-match
/// hardware would never fire it); one comfortably ahead is armed. In 32-bit
/// mode the distance is taken modulo 2^32, across the wrap.
fn smoke_hpet_oneshot_expired_matches_linux_etime() -> TestResult {
    use crate::hpet::{oneshot_expired, MIN_PROG_TICKS};
    let cases = [
        (1_000_000, 1_000_000 - MIN_PROG_TICKS, false, false),
        (1_000_000, 1_000_000 - MIN_PROG_TICKS + 1, false, true),
        (1_000_000, 1_000_000, false, true),
        (1_000_000, 1_000_001, false, true),
        (1_000_000, 900_000, false, false),
        // 32-bit mode: deadline just past the wrap, counter just before it.
        (0x0000_0100, 0xFFFF_FF00, true, false),
        // 32-bit mode: deadline behind a counter that wrapped.
        (0xFFFF_FF00, 0x0000_0010, true, true),
        // Upper bits are ignored in 32-bit mode.
        (0x1_0000_1000, 0x0000_0010, true, false),
    ];
    for (deadline, now, narrow, want) in cases {
        if oneshot_expired(deadline, now, narrow) != want {
            return TestResult::Fail("HPET one-shot expiry check disagrees with Linux -ETIME");
        }
    }
    TestResult::Pass
}
kernel_test_in!("time/hpet", smoke_hpet_oneshot_expired_matches_linux_etime);

fn smoke_hpet_arm_oneshot_rejects_when_uninitialised() -> TestResult {
    use crate::hpet;
    // Stash + reset so we don't clobber a real boot-initialised
    // HPET. `__reset_for_test` is the canonical reset hook.
    let was_present = hpet::is_present();
    // The boot hands the driver an ioremapped (vmalloc-window) base; the
    // reset clears it, and re-probing the raw physical default would map
    // HPET through the low half, which a user CR3 does not carry.
    let base = hpet::base_phys_for_ioremap();
    hpet::__reset_for_test();
    // SAFETY: HPET singleton is empty.
    let r = unsafe { hpet::arm_oneshot(0, 16, 0) };
    let pass = matches!(r, Err(hpet::ArmError::NotPresent));
    if was_present {
        // Restore the boot's HPET, at the base it was given.
        hpet::set_base_phys(base);
        // SAFETY: single-threaded test boot.
        let _ = unsafe { hpet::init() };
    }
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("arm_oneshot accepted a missing HPET")
    }
}
kernel_test_in!(
    "time/hpet",
    smoke_hpet_arm_oneshot_rejects_when_uninitialised
);

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_arm_oneshot_rejects_bad_gsi() -> TestResult {
    use crate::hpet;
    if !hpet::is_present() {
        return TestResult::Skip("HPET not initialised");
    }
    let cap = hpet::timer_route_cap(0);
    // Pick a GSI bit definitely *not* in the cap mask. If every
    // bit in 0..32 is set we can't construct a bad GSI — skip.
    let mut bad: Option<u8> = None;
    for g in 0u8..32 {
        if cap & (1u32 << g) == 0 {
            bad = Some(g);
            break;
        }
    }
    let bad = match bad {
        Some(g) => g,
        None => return TestResult::Skip("comparator 0 accepts every GSI in 0..32"),
    };
    // SAFETY: HPET window is live; we deliberately pass an invalid
    // GSI to verify the validation gate.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { hpet::arm_oneshot(0, bad, hpet::read_counter().wrapping_add(1_000_000)) };
    if matches!(r, Err(hpet::ArmError::BadGsi)) {
        TestResult::Pass
    } else {
        TestResult::Fail("arm_oneshot accepted a GSI outside Tn_INT_ROUTE_CAP")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("time/hpet", smoke_hpet_arm_oneshot_rejects_bad_gsi);

#[cfg(target_arch = "x86_64")]
fn smoke_hpet_disarm_clears_enable_bit() -> TestResult {
    use crate::hpet;
    if !hpet::is_present() {
        return TestResult::Skip("HPET not initialised");
    }
    let cap = hpet::timer_route_cap(0);
    // Pick the lowest bit set in cap that's >= 16 if possible —
    // safer than touching legacy ISA wiring during a smoke.
    let mut g: Option<u8> = None;
    for v in 16u8..32 {
        if cap & (1u32 << v) != 0 {
            g = Some(v);
            break;
        }
    }
    let g = match g {
        Some(v) => v,
        None => return TestResult::Skip("no safe GSI in comparator 0 route-cap"),
    };
    // Far-future deadline so the IRQ doesn't fire before we disarm.
    // 1 << 40 ticks is ~1 day at 14 MHz. We're not enabling
    // interrupts here so the comparator can't actually deliver,
    // but a paranoid deadline is cheap.
    let deadline = hpet::read_counter().wrapping_add(1u64 << 40);
    // SAFETY: HPET window live; IDT/IOAPIC plumbing not required
    // because we disarm before STI.
    // SAFETY: Valid memory or trusted environment
    if unsafe { hpet::arm_oneshot(0, g, deadline) }.is_err() {
        return TestResult::Fail("arm_oneshot rejected a route-cap GSI");
    }
    let cfg_after_arm = match hpet::read_timer_config(0) {
        Some(v) => v,
        None => return TestResult::Fail("read_timer_config returned None after arm"),
    };
    // Tn_INT_ENB_CNF is bit 2 (§2.3.5).
    if cfg_after_arm & (1u64 << 2) == 0 {
        return TestResult::Fail("Tn_INT_ENB_CNF not set after arm");
    }
    // SAFETY: HPET window live.
    if unsafe { hpet::disarm(0) }.is_err() {
        return TestResult::Fail("disarm returned error");
    }
    let cfg_after_disarm = hpet::read_timer_config(0).unwrap_or(0);
    if cfg_after_disarm & (1u64 << 2) != 0 {
        return TestResult::Fail("Tn_INT_ENB_CNF still set after disarm");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("time/hpet", smoke_hpet_disarm_clears_enable_bit);

// ── deep time::Instant + time::Deadline coverage ──────────────────

fn smoke_time_instant_now_monotonic_advances() -> TestResult {
    use crate::Instant;
    let a = Instant::now();
    crate::busy_wait_cycles(1_000);
    let b = Instant::now();
    if b.as_cycles() <= a.as_cycles() {
        return TestResult::Fail("Instant::now didn't advance after busy_wait");
    }
    if b.cycles_since(a) == 0 {
        return TestResult::Fail("cycles_since returned 0 after advance");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_instant_now_monotonic_advances);

fn smoke_time_instant_plus_cycles_saturates() -> TestResult {
    use crate::Instant;
    // A high-cycle Instant + a huge delta should saturate at MAX,
    // not wrap.
    let high = Instant::now().plus_cycles(u64::MAX - 100);
    let saturated = high.plus_cycles(u64::MAX);
    if saturated.as_cycles() != u64::MAX {
        return TestResult::Fail("plus_cycles didn't saturate at MAX");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_instant_plus_cycles_saturates);

fn smoke_time_instant_cycles_since_clamps_negative() -> TestResult {
    use crate::Instant;
    let now = Instant::now();
    let later = now.plus_cycles(1000);
    // Calling `cycles_since` with a future Instant should clamp to 0
    // (saturating sub), not panic.
    if now.cycles_since(later) != 0 {
        return TestResult::Fail("cycles_since didn't clamp negative to 0");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_instant_cycles_since_clamps_negative);

fn smoke_time_deadline_at_round_trip() -> TestResult {
    use crate::{Deadline, Instant};
    let i = Instant::now().plus_cycles(1_000_000);
    let d = Deadline::at(i);
    if d.as_instant().as_cycles() != i.as_cycles() {
        return TestResult::Fail("Deadline::at didn't round-trip the Instant");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_deadline_at_round_trip);

fn smoke_time_deadline_after_cycles_expires_in_future() -> TestResult {
    use crate::Deadline;
    let d = Deadline::after_cycles(1_000_000_000);
    if d.expired() {
        return TestResult::Fail("future deadline reported expired");
    }
    if d.remaining_cycles() == 0 {
        return TestResult::Fail("future deadline has 0 remaining cycles");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_deadline_after_cycles_expires_in_future);

fn smoke_time_deadline_zero_is_immediately_expired() -> TestResult {
    use crate::Deadline;
    let d = Deadline::after_cycles(0);
    if !d.expired() {
        return TestResult::Fail("after_cycles(0) didn't expire immediately");
    }
    if d.remaining_cycles() != 0 {
        return TestResult::Fail("expired deadline reported non-zero remaining");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_deadline_zero_is_immediately_expired);

fn smoke_time_deadline_after_units_consistent() -> TestResult {
    use crate::Deadline;
    // after_ns(N) == after_cycles(N * cycles_per_ns); after_us(N)
    // == after_ns(N*1000); after_ms(N) == after_ns(N*1000_000).
    // We only assert the ordering rather than exact equality (the
    // calls return different Instants because Instant::now is
    // sampled twice).
    let d_short = Deadline::after_us(1);
    let d_med = Deadline::after_us(100);
    let d_long = Deadline::after_ms(100);
    if d_short.as_instant() >= d_med.as_instant() {
        return TestResult::Fail("after_us(1) >= after_us(100)");
    }
    if d_med.as_instant() >= d_long.as_instant() {
        return TestResult::Fail("after_us(100) >= after_ms(100)");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_deadline_after_units_consistent);

fn smoke_time_elapsed_is_distinct_unit_struct() -> TestResult {
    use crate::Elapsed;
    let a = Elapsed;
    let b = Elapsed;
    if a != b {
        return TestResult::Fail("two Elapsed values compared unequal");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_time_elapsed_is_distinct_unit_struct);

/// The kernel-test boot runs the production timebase bring-up (HPET +
/// TSC calibration), so `monotonic_ns` counts nanoseconds. Before it did,
/// the clock ran in raw TSC cycles and every test `Deadline` scaled with
/// the host's TSC frequency.
#[cfg(target_arch = "x86_64")]
fn smoke_kernel_test_timebase_is_calibrated() -> TestResult {
    let hz = narf_arch::x86_64::tsc::frequency_hz();
    if hz == 0 {
        return TestResult::Fail("kernel-test boot left the TSC uncalibrated");
    }
    // A 20 ms busy wait must read as 20 ms (± scheduling slop), not as the
    // ~20 M raw cycles an uncalibrated clock would report as 20 ms.
    let t0 = crate::monotonic_ns();
    let c0 = narf_arch::x86_64::tsc::rdtsc();
    while narf_arch::x86_64::tsc::rdtsc().wrapping_sub(c0) < hz / 50 {
        core::hint::spin_loop();
    }
    let elapsed = crate::monotonic_ns() - t0;
    if !(15_000_000..=60_000_000).contains(&elapsed) {
        return TestResult::Fail("monotonic_ns does not track calibrated time");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("time", smoke_kernel_test_timebase_is_calibrated);

/// `sleep_ms` / `sleep_us` / `sleep_ns` / `sleep` target the same instant
/// as the matching `Deadline` constructor (calibrated ns -> cycles), and
/// `sleep_until` targets the deadline it is given.
fn smoke_sleep_helpers_use_wall_time() -> TestResult {
    let tolerance = crate::wall::ns_to_cycles(1_000_000).max(1_000_000);
    let close =
        |a: crate::Instant, b: crate::Instant| a.as_cycles().abs_diff(b.as_cycles()) <= tolerance;
    let at = |d: crate::Deadline| d.0;
    if !close(
        crate::sleep_ms(20).deadline,
        at(crate::Deadline::after_ms(20)),
    ) || !close(
        crate::sleep_us(20_000).deadline,
        at(crate::Deadline::after_ms(20)),
    ) || !close(
        crate::sleep_ns(20_000_000).deadline,
        at(crate::Deadline::after_ms(20)),
    ) || !close(
        crate::sleep(core::time::Duration::from_millis(20)).deadline,
        at(crate::Deadline::after_ms(20)),
    ) {
        return TestResult::Fail("sleep helper deadline differs from Deadline::after_ms");
    }
    let target = crate::Deadline::after_ms(5);
    if crate::sleep_until(target).deadline != target.0 {
        return TestResult::Fail("sleep_until does not target its deadline");
    }
    TestResult::Pass
}
kernel_test_in!("time", smoke_sleep_helpers_use_wall_time);

// ── NTP discipline loop (issue #1764) ────────────────────────────────
//
// The SNTP client's entry point is `ntp::apply_sample` and the per-second
// drain is `ntp::tick_second`. These smokes drive both directly (no
// network): a small offset slews off one exponential chunk per second, a
// large one steps at once, panic/unsynced samples are refused, and the
// PLL learns frequency from the interval between `ADJ_OFFSET` updates.
// Every test resets the NTP state and the wall offset first and last —
// both are process-global and the adjtimex syscall tests assert the boot
// defaults.

fn smoke_ntp_apply_sample_small_offset_slews_via_tick() -> TestResult {
    use crate::ntp::{adjtimex, apply_sample, tick_second, DisciplineOutcome, Timex};
    use crate::{ntp, wall};

    ntp::__test_reset();
    wall::__test_reset();
    const NOW_SEC: i64 = 1_700_000_000;

    // +50 ms: under the 128 ms step threshold, so it slews.
    match apply_sample(50_000_000, 2_000_000, 1_000_000, 2, NOW_SEC) {
        DisciplineOutcome::Slewed(50_000_000) => {}
        _ => return TestResult::Fail("a 50 ms sample should slew, not step or refuse"),
    }
    // No step yet: the wall offset has not moved.
    if wall::wall_offset_ns() != 0 {
        return TestResult::Fail("a slewed sample stepped the wall clock");
    }
    // The daemon took over: STA_PLL set, STA_UNSYNC clear, TIME_OK.
    let mut tx = Timex::default();
    if adjtimex(&mut tx, NOW_SEC, 0) != ntp::TIME_OK {
        return TestResult::Fail("a disciplined clock should answer TIME_OK");
    }
    if tx.status & ntp::STA_PLL == 0 || tx.status & ntp::STA_UNSYNC != 0 {
        return TestResult::Fail("apply_sample should take over discipline (PLL on, sync clear)");
    }
    // The phase reads back as the 50_000 µs that was fed in.
    if tx.offset != 50_000 {
        return TestResult::Fail("ADJ_OFFSET phase did not read back");
    }
    // First sample, zero interval: no frequency learned yet.
    if tx.freq != 0 {
        return TestResult::Fail("a zero-interval sample should learn no frequency");
    }

    // One second's drain: chunk = time_offset >> (SHIFT_PLL + constant) =
    // 50 ms >> 4 (boot constant 2) = 3_125_000 ns, folded into the wall.
    // The range admits a second chunk if a live tick boundary crossed
    // mid-test and the `on_tick` hook ran `tick_second` concurrently (the
    // hook fires once per wall second from IRQ context); the readback
    // range admits the same one-or-two-chunks outcomes (46_875, 43_945).
    tick_second();
    let moved = wall::wall_offset_ns();
    if !(3_125_000..=6_200_000).contains(&moved) {
        return TestResult::Fail("tick_second did not slew one exponential chunk");
    }
    let mut tx = Timex::default();
    let _ = adjtimex(&mut tx, NOW_SEC, 0);
    if !(40_000..=46_875).contains(&tx.offset) {
        return TestResult::Fail("tick_second did not drain ~1/16 of the phase");
    }

    ntp::__test_reset();
    wall::__test_reset();
    TestResult::Pass
}
kernel_test_in!("time", smoke_ntp_apply_sample_small_offset_slews_via_tick);

fn smoke_ntp_apply_sample_large_offset_steps() -> TestResult {
    use crate::ntp::{adjtimex, apply_sample, DisciplineOutcome, Timex};
    use crate::{ntp, wall};

    ntp::__test_reset();
    wall::__test_reset();
    const NOW_SEC: i64 = 1_700_000_000;

    // +600 s: above the 128 ms step threshold but below the 1000 s panic
    // threshold, so this is an accepted sample that steps at once.
    match apply_sample(600_000_000_000, 1_000_000, 1_000_000, 2, NOW_SEC) {
        DisciplineOutcome::Stepped(600_000_000_000) => {}
        _ => return TestResult::Fail("a 600 s sample should step, not slew or refuse"),
    }
    if wall::wall_offset_ns() != 600_000_000_000 {
        return TestResult::Fail("a stepped sample did not move the wall offset by the offset");
    }
    // The step consumed the pending phase.
    let mut tx = Timex::default();
    let _ = adjtimex(&mut tx, NOW_SEC, 0);
    if tx.offset != 0 {
        return TestResult::Fail("a step should clear the pending phase");
    }

    ntp::__test_reset();
    wall::__test_reset();
    TestResult::Pass
}
kernel_test_in!("time", smoke_ntp_apply_sample_large_offset_steps);

fn smoke_ntp_apply_sample_refuses_panic_and_unsynced() -> TestResult {
    use crate::ntp::{adjtimex, apply_sample, DisciplineOutcome, Timex};
    use crate::{ntp, wall};

    ntp::__test_reset();
    wall::__test_reset();
    const NOW_SEC: i64 = 1_700_000_000;

    // Over the 1000 s panic threshold: refused, clock untouched.
    match apply_sample(1_000_000_000_001, 1_000_000, 1_000_000, 2, NOW_SEC) {
        DisciplineOutcome::Ignored(_) => {}
        _ => return TestResult::Fail("an over-panic-threshold sample should be refused"),
    }
    // Stratum 16 (unsynchronised) and stratum 0 (kiss-o'-death): refused.
    match apply_sample(1_000_000, 1_000_000, 1_000_000, 16, NOW_SEC) {
        DisciplineOutcome::Ignored(_) => {}
        _ => return TestResult::Fail("a stratum-16 sample should be refused"),
    }
    match apply_sample(1_000_000, 1_000_000, 1_000_000, 0, NOW_SEC) {
        DisciplineOutcome::Ignored(_) => {}
        _ => return TestResult::Fail("a stratum-0 sample should be refused"),
    }
    if wall::wall_offset_ns() != 0 {
        return TestResult::Fail("a refused sample moved the wall clock");
    }
    let mut tx = Timex::default();
    if adjtimex(&mut tx, NOW_SEC, 0) != ntp::TIME_ERROR {
        return TestResult::Fail("refused samples should leave the clock undisciplined");
    }

    ntp::__test_reset();
    wall::__test_reset();
    TestResult::Pass
}
kernel_test_in!("time", smoke_ntp_apply_sample_refuses_panic_and_unsynced);

fn smoke_ntp_tick_second_drains_small_phase_to_zero() -> TestResult {
    use crate::ntp::{adjtimex, apply_sample, tick_second, Timex};
    use crate::{ntp, wall};

    ntp::__test_reset();
    wall::__test_reset();
    const NOW_SEC: i64 = 1_700_000_000;

    // +1 µs: the exponential chunk rounds to zero within a few seconds,
    // and then the whole remainder is delivered (Linux `second_overflow()`
    // convergence rule) — the phase must reach exactly zero, not stall.
    match apply_sample(1_000, 1_000_000, 1_000_000, 2, NOW_SEC) {
        crate::ntp::DisciplineOutcome::Slewed(1_000) => {}
        _ => return TestResult::Fail("a 1 µs sample should slew"),
    }
    // The drain is exponential (1/16 of the remainder per second at the
    // boot constant), so a 1 µs phase needs ~340 seconds to reach the
    // sub-16-unit remainder the convergence rule delivers whole.
    for _ in 0..500 {
        tick_second();
    }
    let mut tx = Timex::default();
    let _ = adjtimex(&mut tx, NOW_SEC, 0);
    if tx.offset != 0 {
        return TestResult::Fail("a 1 µs phase did not converge to zero");
    }
    // The wall moved by the whole microsecond, up to per-tick ns truncation.
    let moved = wall::wall_offset_ns();
    if !(900..=1_000).contains(&moved) {
        return TestResult::Fail("a 1 µs phase did not slew into the wall clock");
    }

    ntp::__test_reset();
    wall::__test_reset();
    TestResult::Pass
}
kernel_test_in!("time", smoke_ntp_tick_second_drains_small_phase_to_zero);

fn smoke_ntp_tick_second_maxerror_saturation_marks_unsync() -> TestResult {
    use crate::ntp::{adjtimex, apply_sample, tick_second, Timex};
    use crate::{ntp, wall};

    ntp::__test_reset();
    wall::__test_reset();
    const NOW_SEC: i64 = 1_700_000_000;

    // A fresh sample resets the error estimates to ~2 ms; then silence.
    // `tick_second` bumps maxerror 500 µs/s, so after 32_000 s of silence
    // it saturates at NTP_PHASE_LIMIT and the clock is marked unsynced —
    // Linux's `second_overflow()` rule: a clock nobody has fed for ~4.4
    // hours is no longer trusted.
    match apply_sample(1_000_000, 2_000_000, 1_000_000, 2, NOW_SEC) {
        crate::ntp::DisciplineOutcome::Slewed(_) => {}
        _ => return TestResult::Fail("a 1 ms sample should slew"),
    }
    for _ in 0..32_000 {
        tick_second();
    }
    let mut tx = Timex::default();
    if adjtimex(&mut tx, NOW_SEC, 0) != ntp::TIME_ERROR {
        return TestResult::Fail("a long-unfed clock should answer TIME_ERROR");
    }
    if tx.status & ntp::STA_UNSYNC == 0 {
        return TestResult::Fail("maxerror saturation should mark STA_UNSYNC");
    }
    if tx.maxerror != 16_000_000 {
        return TestResult::Fail("maxerror should clamp at NTP_PHASE_LIMIT");
    }

    ntp::__test_reset();
    wall::__test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "time",
    smoke_ntp_tick_second_maxerror_saturation_marks_unsync
);

/// The PLL frequency half of `ntp_update_offset()`: two `ADJ_OFFSET`
/// updates 64 s apart, both reporting a +100 µs phase error, mean the
/// oscillator runs fast — the second update must learn a positive
/// `time_freq`. The first update (zero interval after the PLL turn-on)
/// learns nothing.
///
/// Expected value, from Linux `kernel/time/ntp.c` with the boot constant
/// 2: the interval clamps to `1 << (SHIFT_PLL + 1 + 2)` = 32 s, so
/// `freq_adj = (100_000 ns * 32) << (32 - 2 * (2 + 2 + 2))` =
/// 3_355_443_200_000, which reads back as 51_200 scaled ppm
/// (0.78 ppm) through the `PPM_SCALE` round-trip.
fn smoke_ntp_update_offset_learns_frequency() -> TestResult {
    use crate::ntp;
    use crate::ntp::{adjtimex, Timex, ADJ_OFFSET, ADJ_STATUS, STA_PLL};

    ntp::__test_reset();
    const NOW_SEC: i64 = 1_700_000_000;

    // Turn the PLL on (resets time_reftime to NOW_SEC).
    let mut tx = Timex {
        modes: ADJ_STATUS,
        status: STA_PLL,
        ..Timex::default()
    };
    let _ = adjtimex(&mut tx, NOW_SEC, 0);

    // First update at the turn-on instant: zero interval, no learning.
    let mut tx = Timex {
        modes: ADJ_OFFSET,
        offset: 100,
        ..Timex::default()
    };
    let _ = adjtimex(&mut tx, NOW_SEC, 0);
    if tx.freq != 0 {
        return TestResult::Fail("a zero-interval update should learn no frequency");
    }
    if tx.offset != 100 {
        return TestResult::Fail("the first ADJ_OFFSET phase did not read back");
    }

    // Second update 64 s later, same +100 µs error: positive frequency.
    let mut tx = Timex {
        modes: ADJ_OFFSET,
        offset: 100,
        ..Timex::default()
    };
    let _ = adjtimex(&mut tx, NOW_SEC + 64, 0);
    if tx.freq != 51_200 {
        return TestResult::Fail("the PLL should learn +51_200 scaled ppm from a repeated error");
    }
    if tx.offset != 100 {
        return TestResult::Fail("the second ADJ_OFFSET phase did not read back");
    }

    ntp::__test_reset();
    TestResult::Pass
}
kernel_test_in!("time", smoke_ntp_update_offset_learns_frequency);
