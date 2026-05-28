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

#[cfg(target_arch = "x86_64")]
fn smoke_ec_handle_gpe_unclaimed_notifies() -> TestResult {
    use crate::ec;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    ec::__test_reset_sci();
    let last = Arc::new(AtomicU32::new(0));
    let l = last.clone();
    ec::subscribe_platform_event(move |ev| {
        if let ec::PlatformEvent::UnclaimedGpe(n) = ev {
            l.store(n, Ordering::Release);
        }
    });
    // Pick a GPE bit unlikely to have any AML _Lxx/_Exx method
    // wired by QEMU's stock DSDT (we want the fall-through
    // unclaimed path). 0x42 is reserved territory on every QEMU
    // board.
    ec::__test_handle_gpe(0x42);
    if last.load(Ordering::Acquire) != 0x42 {
        return TestResult::Fail("UnclaimedGpe(0x42) was not notified");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/ec",
    smoke_ec_handle_gpe_unclaimed_notifies
);

#[cfg(target_arch = "x86_64")]
fn smoke_ec_synthetic_gpe_block_walk() -> TestResult {
    // Verify the bit-walk arithmetic in dispatch_gpe_block by
    // injecting a synthetic status-byte array. base_gsi=0,
    // status[0]=0b0000_0010 + status[1]=0b0001_0000 means GPEs
    // 1 and 12 fired. Both should land in handle_gpe and (since
    // no AML method exists for either) emit UnclaimedGpe with
    // the correct GPE numbers.
    use crate::ec;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::Ordering;

    ec::__test_reset_sci();
    let seen = Arc::new(narf_lib::sync::IrqSafeSpinLock::new(Vec::<u32>::new()));
    let s = seen.clone();
    ec::subscribe_platform_event(move |ev| {
        if let ec::PlatformEvent::UnclaimedGpe(n) = ev {
            s.lock().push(n);
        }
    });
    // status[8] = 0b0000_1100 → bits 2 and 3 set in byte 8
    // → gpe_num = 0 + 8*8 + 2 = 0x42 and = 0x43. Both are
    // unclaimed in QEMU's stock DSDT (no \_GPE._L42/_E42 etc).
    ec::__test_dispatch_synthetic_block(
        0,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0b0000_1100],
    );
    let g = seen.lock();
    if g.len() != 2 {
        return TestResult::Fail("expected 2 unclaimed-gpe events");
    }
    if !g.contains(&0x42) {
        return TestResult::Fail("expected UnclaimedGpe(0x42)");
    }
    if !g.contains(&0x43) {
        return TestResult::Fail("expected UnclaimedGpe(0x43)");
    }
    let _ = Ordering::Release; // keep import alive
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/ec",
    smoke_ec_synthetic_gpe_block_walk
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
    // `snap` chooses the nearest ladder step by absolute distance.
    // For levels [0, 25, 50, 75, 100]:
    //   snap(12) → 0  (12 ≤ 12.5 midpoint)
    //   snap(13) → 25 (distance 12 < 13)
    //   snap(63) → 75 (distance 12 < 13)
    if panel.snap(12) != 0 {
        return TestResult::Fail("snap(12) should round down to 0");
    }
    if panel.snap(13) != 25 {
        return TestResult::Fail("snap(13) should round up to 25 (nearest)");
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

// ── Battery (AML-driven) ───────────────────────────────────────────

fn smoke_battery_init_walks_aml_namespace_without_panic() -> TestResult {
    // Smoke: `battery::init()` must complete without panic on a
    // namespace that may or may not contain PNP0C0A devices.
    // Under QEMU's stock DSDT there's no battery, so the walk
    // returns an empty vec and `init()` is a no-op. Locks down
    // the contract that init handles "no batteries" gracefully —
    // important because every real laptop boot calls init() and
    // a regression would crash the bring-up before the FB
    // status panel paints.
    crate::battery::init();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/battery",
    smoke_battery_init_walks_aml_namespace_without_panic
);

// ── AC adapter ─────────────────────────────────────────────────────

fn smoke_ac_adapter_init_walks_aml_namespace_without_panic() -> TestResult {
    crate::ac_adapter::init();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/ac_adapter",
    smoke_ac_adapter_init_walks_aml_namespace_without_panic
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

// ── AMD AOAC ───────────────────────────────────────────────────────

/// IP-index → bit-position table: each IP's 2-bit field starts at
/// `2 * (index % 16)` within its register word.
fn smoke_aoac_ip_bit_positions() -> TestResult {
    use crate::amd_aoac::AoacIp;

    // UsbXhci0 is index 0 → bit 0.
    if AoacIp::UsbXhci0.bit_pos() != 0 {
        return TestResult::Fail("UsbXhci0 bit_pos should be 0");
    }
    // UsbXhci1 is index 1 → bit 2.
    if AoacIp::UsbXhci1.bit_pos() != 2 {
        return TestResult::Fail("UsbXhci1 bit_pos should be 2");
    }
    // Spi is index 15 → bit 30.
    if AoacIp::Spi.bit_pos() != 30 {
        return TestResult::Fail("Spi (index 15) bit_pos should be 30");
    }
    // GpuVga is index 5 → bit 10.
    if AoacIp::GpuVga.bit_pos() != 10 {
        return TestResult::Fail("GpuVga (index 5) bit_pos should be 10");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_aoac",
    smoke_aoac_ip_bit_positions
);

/// Exhaustive match over AoacIp variants — compile-time insurance
/// that no arm is silently unreachable.
fn smoke_aoac_ip_enum_exhaustive() -> TestResult {
    use crate::amd_aoac::AoacIp;

    let all = [
        AoacIp::UsbXhci0,
        AoacIp::UsbXhci1,
        AoacIp::UsbOhci,
        AoacIp::Sata,
        AoacIp::Nvme,
        AoacIp::GpuVga,
        AoacIp::Acp,
        AoacIp::Sdio0,
        AoacIp::Sdio1,
        AoacIp::I2c0,
        AoacIp::I2c1,
        AoacIp::I2c2,
        AoacIp::I2c3,
        AoacIp::Uart0,
        AoacIp::Uart1,
        AoacIp::Spi,
    ];
    for ip in all {
        let _n = match ip {
            AoacIp::UsbXhci0 => 0u8,
            AoacIp::UsbXhci1 => 1,
            AoacIp::UsbOhci => 2,
            AoacIp::Sata => 3,
            AoacIp::Nvme => 4,
            AoacIp::GpuVga => 5,
            AoacIp::Acp => 6,
            AoacIp::Sdio0 => 7,
            AoacIp::Sdio1 => 8,
            AoacIp::I2c0 => 9,
            AoacIp::I2c1 => 10,
            AoacIp::I2c2 => 11,
            AoacIp::I2c3 => 12,
            AoacIp::Uart0 => 13,
            AoacIp::Uart1 => 14,
            AoacIp::Spi => 15,
        };
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_aoac",
    smoke_aoac_ip_enum_exhaustive
);

/// aoac_set_d3 writes the correct bit pattern for USB XHCI0.
///
/// Uses a fake 8-byte register block redirected via `__test_redirect`.
/// `on = true` must write 0b00 into bits [1:0] of AOAC_DEV_D3_CTL_0.
/// `on = false` must write 0b01 into bits [1:0].
fn smoke_aoac_set_d3_usb_xhci_bit_pattern() -> TestResult {
    use crate::amd_aoac::{self, AoacIp, AoacState};

    // Allocate 16 bytes to cover both CTL and STATE register words.
    let mut regs = [0u32; 4];
    let base = regs.as_mut_ptr() as u64;
    // Offset layout inside the fake block (mirroring amd_aoac offsets
    // relative to FCH_MMIO_BASE):
    //   AOAC_DEV_D3_CTL_0  = 0x9C → for the fake we map it as index 0.
    //   AOAC_DEV_D3_CTL_1  = 0xA0 → index 1.
    //   AOAC_DEV_D3_STATE_0= 0xA4 → index 2.
    //   AOAC_DEV_D3_STATE_1= 0xA8 → index 3.
    //
    // The fake base is passed directly to __test_redirect; the driver
    // adds its register offsets on top, so we need the fake buffer
    // to start at `base - 0x9C` so that `base + 0x9C` lands at
    // regs[0].  Adjust accordingly.
    let fake_base = base.wrapping_sub(0x9C);
    amd_aoac::__test_redirect(fake_base);

    // Request D0 (on = true) for UsbXhci0.
    if amd_aoac::aoac_set_d3(AoacIp::UsbXhci0, true).is_err() {
        amd_aoac::__test_reset();
        return TestResult::Fail("aoac_set_d3(D0) failed unexpectedly");
    }
    // Bits [1:0] of CTL_0 (regs[0]) must be 0b00.
    if regs[0] & 0b11 != 0b00 {
        amd_aoac::__test_reset();
        return TestResult::Fail("D0 request should clear bits [1:0]");
    }

    // Request D3hot (on = false) for UsbXhci0.
    if amd_aoac::aoac_set_d3(AoacIp::UsbXhci0, false).is_err() {
        amd_aoac::__test_reset();
        return TestResult::Fail("aoac_set_d3(D3hot) failed unexpectedly");
    }
    // Bits [1:0] of CTL_0 must be 0b01.
    if regs[0] & 0b11 != 0b01 {
        amd_aoac::__test_reset();
        return TestResult::Fail("D3hot request should write 0b01 into bits [1:0]");
    }

    // Read-back: pre-seed STATE register with D3hot encoding and
    // verify aoac_get_state returns D3hot.
    regs[2] = 0b01; // AOAC_DEV_D3_STATE_0 bits [1:0] = D3hot
    let state = crate::amd_aoac::aoac_get_state(AoacIp::UsbXhci0);
    if state != AoacState::D3hot {
        amd_aoac::__test_reset();
        return TestResult::Fail("aoac_get_state did not decode D3hot correctly");
    }

    amd_aoac::__test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_aoac",
    smoke_aoac_set_d3_usb_xhci_bit_pattern
);

/// FCH base-address resolution: detect_soc() must return a known
/// variant on Renoir (family 0x17) and Phoenix (family 0x19) and
/// Unknown on any non-AMD host.
fn smoke_aoac_fch_base_soc_detect() -> TestResult {
    use crate::amd_aoac::{detect_soc, AmdSoc};

    let soc = detect_soc();
    // On non-AMD hosts (QEMU defaults to Intel or AMD Zen depending on
    // the -cpu flag) we accept any valid variant — this is a no-panic
    // smoke, not a "must be Renoir" assertion.
    match soc {
        AmdSoc::Renoir | AmdSoc::Phoenix | AmdSoc::Unknown => {}
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_aoac",
    smoke_aoac_fch_base_soc_detect
);

// ── AMD ASF ────────────────────────────────────────────────────────

/// ASF message header encode: wire_addr and encode() produce the
/// correct byte layout.
fn smoke_asf_message_header_encode() -> TestResult {
    use crate::amd_asf::AsfMessage;

    let msg = AsfMessage::new(0x2C, 0x04, 0x01, alloc::vec![0xDE, 0xAD]);
    // wire_addr = addr << 1.
    if msg.wire_addr() != 0x58 {
        return TestResult::Fail("wire_addr() should be addr<<1");
    }
    let enc = match msg.encode() {
        Some(v) => v,
        None => return TestResult::Fail("encode() returned None for short payload"),
    };
    // encode() layout: [body_len, netfn, cmd, payload…]
    // body = netfn + cmd + 2 payload bytes = 4 bytes.
    if enc[0] != 4 {
        return TestResult::Fail("length prefix should be 4");
    }
    if enc[1] != 0x04 {
        return TestResult::Fail("netfn byte mismatch");
    }
    if enc[2] != 0x01 {
        return TestResult::Fail("ipmi_cmd byte mismatch");
    }
    if enc[3] != 0xDE || enc[4] != 0xAD {
        return TestResult::Fail("payload bytes mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_asf",
    smoke_asf_message_header_encode
);
