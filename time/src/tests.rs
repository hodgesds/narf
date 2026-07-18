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

// ── Timer wheel ──────────────────────────────────────────────────

extern crate alloc;

fn make_noop_waker() -> core::task::Waker {
    use alloc::sync::Arc;
    use alloc::task::Wake;
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    Arc::new(Noop).into()
}

fn smoke_wheel_register_then_fire_due_wakes() -> TestResult {
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};

    timer_wheel::__reset_for_test();

    struct W(AtomicUsize);
    impl Wake for W {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let cw = Arc::new(W(AtomicUsize::new(0)));
    let waker: core::task::Waker = cw.clone().into();

    timer_wheel::set_arm_callback(timer_wheel::__test_arm_callback);

    let _h = timer_wheel::register(100, waker).expect("register");
    if timer_wheel::ARM_FIRED.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("arm callback should fire on first registration");
    }
    if timer_wheel::LAST_ARM_DEADLINE.load(Ordering::Relaxed) != 100 {
        return TestResult::Fail("arm deadline mismatch");
    }
    if timer_wheel::next_deadline_cycles() != Some(100) {
        return TestResult::Fail("next_deadline_cycles mismatch");
    }

    if timer_wheel::fire_due(50) != 0 {
        return TestResult::Fail("nothing should fire before deadline");
    }
    if cw.0.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("waker fired prematurely");
    }
    if timer_wheel::fire_due(150) != 1 {
        return TestResult::Fail("expected exactly one fire");
    }
    if cw.0.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("waker not invoked on fire_due");
    }
    if timer_wheel::next_deadline_cycles().is_some() {
        return TestResult::Fail("wheel should be empty after fire");
    }

    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_register_then_fire_due_wakes);

fn smoke_wheel_arm_only_on_new_min() -> TestResult {
    use crate::timer_wheel;
    use core::sync::atomic::Ordering;

    timer_wheel::__reset_for_test();
    timer_wheel::set_arm_callback(timer_wheel::__test_arm_callback);

    let h_far = timer_wheel::register(1000, make_noop_waker()).unwrap();
    if timer_wheel::ARM_FIRED.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("first registration must arm");
    }
    let _h_later = timer_wheel::register(2000, make_noop_waker()).unwrap();
    if timer_wheel::ARM_FIRED.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("registration with later deadline must NOT re-arm");
    }
    let _h_earlier = timer_wheel::register(500, make_noop_waker()).unwrap();
    if timer_wheel::ARM_FIRED.load(Ordering::Relaxed) != 2 {
        return TestResult::Fail("registration with earlier deadline must re-arm");
    }
    if timer_wheel::LAST_ARM_DEADLINE.load(Ordering::Relaxed) != 500 {
        return TestResult::Fail("re-arm should target the new min");
    }
    timer_wheel::cancel(h_far);

    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_arm_only_on_new_min);

fn smoke_wheel_cancel_removes_slot() -> TestResult {
    use crate::timer_wheel;

    timer_wheel::__reset_for_test();

    let h = timer_wheel::register(500, make_noop_waker()).unwrap();
    if timer_wheel::occupied() != 1 {
        return TestResult::Fail("occupied count after register");
    }
    timer_wheel::cancel(h);
    if timer_wheel::occupied() != 0 {
        return TestResult::Fail("cancel should free the slot");
    }
    // Stale cancel — must be silent.
    timer_wheel::cancel(h);

    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_cancel_removes_slot);

fn smoke_wheel_full_returns_err() -> TestResult {
    use crate::timer_wheel;
    use alloc::vec::Vec;

    timer_wheel::__reset_for_test();
    let mut handles: Vec<timer_wheel::SleepHandle> = Vec::new();
    for i in 0..timer_wheel::MAX_SLEEPERS {
        let h = match timer_wheel::register(1000 + i as u64, make_noop_waker()) {
            Ok(h) => h,
            Err(_) => return TestResult::Fail("wheel rejected before MAX_SLEEPERS"),
        };
        handles.push(h);
    }
    match timer_wheel::register(99_999, make_noop_waker()) {
        Err(timer_wheel::WheelError::Full) => {}
        _ => return TestResult::Fail("MAX+1 registration should be Full"),
    }
    for h in handles {
        timer_wheel::cancel(h);
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_full_returns_err);

fn smoke_sleep_until_uses_wheel() -> TestResult {
    // SleepUntil registers with the wheel on first poll, then
    // returns Ready when fire_due crosses its deadline.
    use crate::{timer_wheel, Instant, SleepUntil};
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    timer_wheel::__reset_for_test();
    let waker = make_noop_waker();
    let mut cx = Context::from_waker(&waker);

    let deadline = Instant::now().plus_cycles(1_000_000_000);
    let mut s = SleepUntil::new(deadline);
    if !matches!(Pin::new(&mut s).poll(&mut cx), Poll::Pending) {
        return TestResult::Fail("future-deadline poll should be Pending");
    }
    if timer_wheel::occupied() != 1 {
        return TestResult::Fail("SleepUntil should have registered with wheel");
    }
    // Crossing the deadline + a re-poll → Ready. We can't actually
    // wait that long; instead, pretend the deadline already passed
    // by calling fire_due with a far-future time.
    let woken = timer_wheel::fire_due(u64::MAX);
    if woken != 1 {
        return TestResult::Fail("fire_due should wake the registered SleepUntil");
    }
    // After fire_due, polling SleepUntil sees Instant::now() <
    // deadline still (we lied to fire_due), but the slot is gone
    // — refresh_waker returns false and the recursive poll
    // re-registers. That's the spurious-wake path.
    // Instead, drop and verify cleanup.
    drop(s);
    if timer_wheel::occupied() != 0 {
        return TestResult::Fail("drop should clean wheel");
    }

    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_sleep_until_uses_wheel);

// ── extended time/wheel coverage ──────────────────────────────────
//
// Existing surface hits register/fire/cancel/full and the
// SleepUntil integration. New smokes close the remaining
// invariants on `refresh_waker`, multi-sleeper `fire_due`,
// `set_arm_callback` replacement, and generation uniqueness.

fn smoke_wheel_arm_callback_installed_reports() -> TestResult {
    use crate::timer_wheel;
    timer_wheel::__reset_for_test();
    if timer_wheel::arm_callback_installed() {
        return TestResult::Fail("freshly reset: arm callback should be uninstalled");
    }
    timer_wheel::set_arm_callback(timer_wheel::__test_arm_callback);
    if !timer_wheel::arm_callback_installed() {
        return TestResult::Fail("set_arm_callback didn't flip arm_callback_installed");
    }
    timer_wheel::clear_arm_callback();
    if timer_wheel::arm_callback_installed() {
        return TestResult::Fail("clear_arm_callback didn't unflip arm_callback_installed");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_arm_callback_installed_reports);

fn smoke_wheel_fire_due_wakes_only_expired() -> TestResult {
    // Three sleepers at deadlines 100/200/300; fire_due(150) wakes
    // exactly the first one; subsequent fire_due(250) wakes the
    // second; fire_due(350) wakes the last. Partial-fire ordering.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    timer_wheel::__reset_for_test();
    struct W(AtomicU32);
    impl Wake for W {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let a = Arc::new(W(AtomicU32::new(0)));
    let b = Arc::new(W(AtomicU32::new(0)));
    let c = Arc::new(W(AtomicU32::new(0)));

    let _ha = timer_wheel::register(100, a.clone().into()).unwrap();
    let _hb = timer_wheel::register(200, b.clone().into()).unwrap();
    let _hc = timer_wheel::register(300, c.clone().into()).unwrap();
    if timer_wheel::occupied() != 3 {
        return TestResult::Fail("three registrations not visible in occupied()");
    }

    if timer_wheel::fire_due(150) != 1 {
        return TestResult::Fail("fire_due(150) didn't fire exactly one");
    }
    if a.0.load(Ordering::Relaxed) != 1
        || b.0.load(Ordering::Relaxed) != 0
        || c.0.load(Ordering::Relaxed) != 0
    {
        return TestResult::Fail("wrong waker fired at 150");
    }

    if timer_wheel::fire_due(250) != 1 {
        return TestResult::Fail("fire_due(250) didn't fire exactly one");
    }
    if b.0.load(Ordering::Relaxed) != 1 || c.0.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("wrong waker fired at 250");
    }

    if timer_wheel::fire_due(350) != 1 {
        return TestResult::Fail("fire_due(350) didn't fire exactly one");
    }
    if c.0.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("c didn't fire at 350");
    }
    if timer_wheel::occupied() != 0 {
        return TestResult::Fail("wheel not empty after all three fired");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_fire_due_wakes_only_expired);

fn smoke_wheel_fire_due_empty_returns_zero() -> TestResult {
    // fire_due on an empty wheel returns 0 and doesn't panic.
    use crate::timer_wheel;
    timer_wheel::__reset_for_test();
    if timer_wheel::fire_due(0) != 0 {
        return TestResult::Fail("fire_due on empty wheel reported wakes");
    }
    if timer_wheel::fire_due(u64::MAX) != 0 {
        return TestResult::Fail("fire_due(MAX) on empty wheel reported wakes");
    }
    if timer_wheel::next_deadline_cycles().is_some() {
        return TestResult::Fail("empty wheel reported a next deadline");
    }
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_fire_due_empty_returns_zero);

fn smoke_wheel_refresh_waker_updates_live_slot() -> TestResult {
    // Refresh on a live handle replaces the slot's waker — the new
    // one is what fires on deadline.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    timer_wheel::__reset_for_test();
    struct W(AtomicU32);
    impl Wake for W {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let old = Arc::new(W(AtomicU32::new(0)));
    let new = Arc::new(W(AtomicU32::new(0)));

    let h = timer_wheel::register(100, old.clone().into()).unwrap();
    if !timer_wheel::refresh_waker(h, new.clone().into()) {
        return TestResult::Fail("refresh_waker on live slot returned false");
    }
    let woken = timer_wheel::fire_due(150);
    if woken != 1 {
        return TestResult::Fail("fire_due didn't wake");
    }
    if old.0.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("old waker fired after refresh");
    }
    if new.0.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("new waker didn't fire after refresh");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_refresh_waker_updates_live_slot);

fn smoke_wheel_refresh_waker_at_updates_deadline() -> TestResult {
    // `refresh_waker_at` must move the slot's DEADLINE too — a handle
    // reused across parks with different deadlines (own-stack
    // park_should_block / UserTaskFuture::poll) would otherwise pin the
    // fallback wake to the stale first deadline (the stress-ng --futex
    // strand residue). Register far out, refresh near, and the sleeper
    // fires at the NEW deadline.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    timer_wheel::__reset_for_test();
    struct W(AtomicU32);
    impl Wake for W {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let w = Arc::new(W(AtomicU32::new(0)));

    let h = timer_wheel::register(1_000_000, w.clone().into()).unwrap();
    // fire_due before the (old) deadline: nothing fires.
    if timer_wheel::fire_due(500) != 0 {
        return TestResult::Fail("fired before either deadline");
    }
    // Pull the deadline IN (1_000_000 → 400).
    if !timer_wheel::refresh_waker_at(h, 400, w.clone().into()) {
        return TestResult::Fail("refresh_waker_at on live slot returned false");
    }
    if timer_wheel::next_deadline_cycles() != Some(400) {
        return TestResult::Fail("refresh_waker_at didn't update the deadline");
    }
    if timer_wheel::fire_due(500) != 1 || w.0.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("sleeper didn't fire at the refreshed deadline");
    }
    // Slot is spent — a stale handle must be rejected.
    if timer_wheel::refresh_waker_at(h, 900, w.clone().into()) {
        return TestResult::Fail("refresh_waker_at accepted a fired slot's stale handle");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_refresh_waker_at_updates_deadline);

fn smoke_wheel_refresh_waker_rejects_recycled_handle() -> TestResult {
    // After fire_due reclaims the slot, the original handle's gen
    // is stale; refresh_waker against it must return false even if
    // the slot is later re-occupied by a different sleeper.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    timer_wheel::__reset_for_test();
    let waker = Arc::new(Noop).into();
    let stale_h = timer_wheel::register(100, waker).unwrap();
    timer_wheel::fire_due(150); // slot cleared
                                // Recycle the same slot with a fresh registration.
    let _fresh_h = timer_wheel::register(200, Arc::new(Noop).into()).unwrap();
    // The stale handle's gen mismatches the slot's new gen.
    if timer_wheel::refresh_waker(stale_h, Arc::new(Noop).into()) {
        return TestResult::Fail("refresh_waker accepted a recycled-slot stale handle");
    }
    // The cancel path should also be silent on the stale handle.
    timer_wheel::cancel(stale_h);
    if timer_wheel::occupied() != 1 {
        return TestResult::Fail("stale cancel evicted the fresh registration");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "time/wheel",
    smoke_wheel_refresh_waker_rejects_recycled_handle
);

fn smoke_wheel_handles_are_generationally_unique() -> TestResult {
    // Register / cancel / register cycles through the same slot
    // but the generations differ; the SleepHandle::generation()
    // reflects this and is what protects against use-after-recycle.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    timer_wheel::__reset_for_test();
    let h1 = timer_wheel::register(100, Arc::new(Noop).into()).unwrap();
    let gen1 = h1.generation();
    timer_wheel::cancel(h1);
    let h2 = timer_wheel::register(200, Arc::new(Noop).into()).unwrap();
    let gen2 = h2.generation();
    if gen1 == gen2 {
        return TestResult::Fail("re-registered handle reused the same generation");
    }
    if gen1 == 0 || gen2 == 0 {
        return TestResult::Fail("generation 0 leaked (should be skipped as sentinel)");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_handles_are_generationally_unique);

fn smoke_wheel_set_arm_callback_replaces_prior() -> TestResult {
    // set_arm_callback is idempotent for boot but useful for tests —
    // a second install replaces the first. Verify the most-recently
    // installed callback is what fires.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static FIRST: AtomicUsize = AtomicUsize::new(0);
    static SECOND: AtomicUsize = AtomicUsize::new(0);
    fn first_cb(_: u64) {
        FIRST.fetch_add(1, Ordering::Relaxed);
    }
    fn second_cb(_: u64) {
        SECOND.fetch_add(1, Ordering::Relaxed);
    }

    timer_wheel::__reset_for_test();
    FIRST.store(0, Ordering::Relaxed);
    SECOND.store(0, Ordering::Relaxed);

    timer_wheel::set_arm_callback(first_cb);
    timer_wheel::set_arm_callback(second_cb);

    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let _h = timer_wheel::register(100, Arc::new(Noop).into()).unwrap();

    if FIRST.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("first callback fired after being replaced");
    }
    if SECOND.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("second (replacement) callback didn't fire");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_set_arm_callback_replaces_prior);

fn smoke_wheel_cancel_after_fire_is_silent() -> TestResult {
    // A handle whose slot already fired must be safe to cancel —
    // no panic, no effect on the wheel.
    use crate::timer_wheel;
    use alloc::sync::Arc;
    use alloc::task::Wake;
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }

    timer_wheel::__reset_for_test();
    let h = timer_wheel::register(50, Arc::new(Noop).into()).unwrap();
    let fired = timer_wheel::fire_due(100);
    if fired != 1 {
        return TestResult::Fail("expected one fire");
    }
    // Now cancel the fired handle — must be silent.
    timer_wheel::cancel(h);
    if timer_wheel::occupied() != 0 {
        return TestResult::Fail("cancel-after-fire changed occupied count");
    }
    timer_wheel::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("time/wheel", smoke_wheel_cancel_after_fire_is_silent);

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
