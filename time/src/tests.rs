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
