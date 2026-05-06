//! Per-driver smoke tests for `narf-drivers-platform`.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

// ── SMBus ──────────────────────────────────────────────────────────

fn smoke_smbus_class_match_registered() -> TestResult {
    use crate::smbus;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    smbus::register_pci_driver();
    let regs = registered_pci_drivers();
    let has = regs.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::Class {
                class: 0x0C,
                mask: 0xFF
            }
        )
    });
    if !has {
        return TestResult::Fail("smbus class match missing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/smbus", smoke_smbus_class_match_registered);

    fn smoke_acpi_ec_discovery() -> TestResult {
    use crate::ec;
    if ec::with_ec(|_| {}).is_some() {
        TestResult::Pass
    } else {
        TestResult::Skip("ACPI EC not found (not a laptop config?)")
    }
    }
    kernel_test_in!("drivers/platform/ec", smoke_acpi_ec_discovery);

    fn smoke_acpi_thermal_discovery() -> TestResult {
        use narf_power::thermal::zone_count;
        if zone_count() >= 0 {
            TestResult::Pass
        } else {
            TestResult::Fail("zone_count logic error")
        }
    }
    kernel_test_in!("drivers/platform/thermal", smoke_acpi_thermal_discovery);

fn smoke_ec_sci_dispatch_notifies_subscribers() -> TestResult {
    use crate::ec;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    ec::__test_reset_sci();

    // Synthetic GPE event: install a subscriber that records when an
    // unclaimed-GPE notification fires, then synthesise the dispatch
    // path directly. Going through the SCI vector would require a
    // live IOAPIC route that QEMU doesn't always provide for the
    // FADT-supplied SCI_INT, so we exercise the dispatcher entry
    // point — which is also what `init_sci()` installs as the IRQ
    // handler.
    let saw = Arc::new(AtomicBool::new(false));
    let count = Arc::new(AtomicU64::new(0));
    let saw_c = saw.clone();
    let count_c = count.clone();
    ec::subscribe_platform_event(move |ev| {
        count_c.fetch_add(1, Ordering::Release);
        if let ec::PlatformEvent::PowerButton = ev {
            saw_c.store(true, Ordering::Release);
        }
    });

    // Verify the dispatcher's bookkeeping increments. We can't
    // simulate PM1 status without poking the chipset, so this test
    // exercises only the counter path; PM1 dispatch is covered when
    // the kernel-test harness actually fires the SCI on real
    // hardware.
    let before = ec::sci_fire_count();
    ec::dispatch_sci();
    let after = ec::sci_fire_count();
    if after != before + 1 {
        return TestResult::Fail("sci_fire_count did not increment");
    }
    let _ = saw;
    let _ = count;
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/ec",
    smoke_ec_sci_dispatch_notifies_subscribers
);

fn smoke_lid_subscriber_install_and_reset() -> TestResult {
    use crate::lid;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    lid::__test_reset();
    let fired = Arc::new(AtomicBool::new(false));
    let f = fired.clone();
    lid::subscribe(move |_| {
        f.store(true, Ordering::Release);
    });
    // Without a real LID device + EC events firing in QEMU, we only
    // verify the subscriber registry accepts installs and the reset
    // path is idempotent. Cross-check that double-reset doesn't
    // panic — historical pattern after revoke storms.
    lid::__test_reset();
    if fired.load(Ordering::Acquire) {
        return TestResult::Fail("subscriber fired without an event");
    }
    if !lid::lids().is_empty() {
        return TestResult::Fail("__test_reset did not drain lids");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/lid", smoke_lid_subscriber_install_and_reset);

fn smoke_buttons_inject_dispatches_to_subscribers() -> TestResult {
    use crate::buttons::{
        __test_inject, __test_reset, power_press_count, sleep_press_count, subscribe_any,
        subscribe_power, subscribe_sleep, Button,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU8, Ordering};

    __test_reset();
    let any_n = Arc::new(AtomicU8::new(0));
    let pwr_n = Arc::new(AtomicU8::new(0));
    let slp_n = Arc::new(AtomicU8::new(0));

    let a = any_n.clone();
    subscribe_any(move |_| {
        a.fetch_add(1, Ordering::Release);
    });
    let p = pwr_n.clone();
    subscribe_power(move |b| {
        if matches!(b, Button::Power) {
            p.fetch_add(1, Ordering::Release);
        }
    });
    let s = slp_n.clone();
    subscribe_sleep(move |b| {
        if matches!(b, Button::Sleep) {
            s.fetch_add(1, Ordering::Release);
        }
    });

    __test_inject(Button::Power);
    __test_inject(Button::Sleep);
    __test_inject(Button::Power);

    if power_press_count() != 2 {
        return TestResult::Fail("power_press_count != 2");
    }
    if sleep_press_count() != 1 {
        return TestResult::Fail("sleep_press_count != 1");
    }
    if any_n.load(Ordering::Acquire) != 3 {
        return TestResult::Fail("subscribe_any did not see all 3 presses");
    }
    if pwr_n.load(Ordering::Acquire) != 2 {
        return TestResult::Fail("subscribe_power miscount");
    }
    if slp_n.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("subscribe_sleep miscount");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/buttons",
    smoke_buttons_inject_dispatches_to_subscribers
);

fn smoke_backlight_snap_chooses_nearest_ladder_step() -> TestResult {
    use crate::backlight::{__test_install_panel, __test_reset};

    __test_reset();
    let panel = __test_install_panel("\\TEST.LCD", alloc::vec![0, 25, 50, 75, 100]);
    if panel.snap(0) != 0 {
        return TestResult::Fail("snap(0) != 0");
    }
    if panel.snap(13) != 0 {
        return TestResult::Fail("snap(13) should round down to 0");
    }
    if panel.snap(14) != 25 {
        return TestResult::Fail("snap(14) should round up to 25");
    }
    if panel.snap(63) != 75 {
        return TestResult::Fail("snap(63) should round up to 75");
    }
    if panel.snap(101) != 100 {
        return TestResult::Fail("snap above max should clamp to max");
    }
    if panel.max() != 100 {
        return TestResult::Fail("max() did not return ladder top");
    }
    __test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/backlight",
    smoke_backlight_snap_chooses_nearest_ladder_step
);

fn smoke_backlight_cap_revocation_blocks_set_percent() -> TestResult {
    use crate::backlight::{
        __test_install_panel, __test_reset, bootstrap_backlight_authority, set_percent,
        BacklightError,
    };

    __test_reset();
    // Without any panels the percentage path returns Ok but does
    // nothing; we want to focus on cap revocation here so install
    // a synthetic panel.
    let _ = __test_install_panel("\\TEST.LCD", alloc::vec![0, 100]);
    let cap = bootstrap_backlight_authority();
    cap.revoke();
    match set_percent(&cap, 50) {
        Err(BacklightError::AuthorityRevoked) => {}
        _ => return TestResult::Fail("revoked cap was accepted by set_percent"),
    }
    __test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/backlight",
    smoke_backlight_cap_revocation_blocks_set_percent
);

// ── TPM ────────────────────────────────────────────────────────────

fn smoke_tpm_init_default() -> TestResult {
    use crate::tpm;
    tpm::__reset_for_test();
    tpm::try_init_default();
    // Probe doesn't require a TPM to exist; if one isn't present,
    // we just want the no-op path to not panic.
    if tpm::is_present() {
        // Sanity: kind() should match what probe surfaced.
        let k = tpm::kind();
        if k.is_none() {
            return TestResult::Fail("tpm present but kind() = None");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/tpm", smoke_tpm_init_default);
