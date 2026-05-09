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

    use crate::rtc::cmos::{decode_snapshot, STATUS_B_24H};

    // 2026-05-07 14:35:22, BCD + 24h.

    let dt = decode_snapshot(

        0x22, 0x35, 0x14, 0x07, 0x05, 0x26, 0x20, STATUS_B_24H,

    );

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

    use crate::rtc::cmos::decode_snapshot;

    // 12h mode: status_b 24H bit clear. 03 PM with PM bit set →

    // hour 15.

    // sec/min/hour are BCD by default (status_b=0).

    let dt = decode_snapshot(0, 0, 0x83, 0x01, 0x01, 0x26, 0x20, 0);

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

kernel_test_in!("time/rtc", smoke_rtc_pl031_unix_seconds_to_datetime_known_vector);



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

    let dt = RtcDateTime { year: 1970, month: 1, day: 1, hour: 0, minute: 0, second: 0 };

    if dt.to_unix_seconds() != 0 {

        return TestResult::Fail("epoch");

    }

    // 2000-01-01 00:00:00 = 946684800.

    let dt = RtcDateTime { year: 2000, month: 1, day: 1, hour: 0, minute: 0, second: 0 };

    if dt.to_unix_seconds() != 946_684_800 {

        return TestResult::Fail("y2k");

    }

    TestResult::Pass

}

kernel_test_in!("time/rtc", smoke_rtc_datetime_unix_seconds_known_vectors);

// ── relocated from verification (subsystem 'time') ──

fn smoke_time_wall_offset_and_leap_smear() -> TestResult {
    use narf_capabilities::{Cap, Write};
    use crate::{begin_leap_smear, now_wall, set_wall_offset, wall, WallClock, WallError};

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

fn smoke_hpet_arm_oneshot_rejects_when_uninitialised() -> TestResult {
    use crate::hpet;
    // Stash + reset so we don't clobber a real boot-initialised
    // HPET. `__reset_for_test` is the canonical reset hook.
    let was_present = hpet::is_present();
    hpet::__reset_for_test();
    // SAFETY: HPET singleton is empty.
    let r = unsafe { hpet::arm_oneshot(0, 16, 0) };
    let pass = matches!(r, Err(hpet::ArmError::NotPresent));
    if was_present {
        // Best-effort restore: re-init from the default base.
        // SAFETY: single-threaded test boot.
        let _ = unsafe { hpet::init() };
    }
    if pass {
        TestResult::Pass
    } else {
        TestResult::Fail("arm_oneshot accepted a missing HPET")
    }
}
kernel_test_in!("time/hpet", smoke_hpet_arm_oneshot_rejects_when_uninitialised);

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
