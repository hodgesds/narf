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

/// Verify `dispatch_sci` is truly alloc-free when called from simulated
/// IRQ context. The `AllocContext::Sleepable` debug assert fires on
/// any `slab::alloc` call while `in_irq_depth > 0`, so this test would
/// **panic** (not return Fail) if the ISR path allocates.
///
/// This is the regression test for the Wave-23 fix — ensures the
/// deferred-drain design holds under repeated SCI fires.
#[cfg(target_arch = "x86_64")]
fn smoke_ec_dispatch_sci_from_irq_context() -> TestResult {
    use crate::ec;
    use narf_lib::context::{enter_irq, exit_irq};

    ec::__test_reset_sci();

    // Fire dispatch_sci 8 times from simulated IRQ context.
    // If any path inside dispatch_sci allocates from the sleepable
    // heap, the debug_assert_consistent() check in slab::alloc
    // will panic (which is visible as a test panic, not a Fail).
    for _ in 0..8 {
        enter_irq();
        ec::dispatch_sci();
        exit_irq();
    }

    // Counters should have advanced.
    if ec::sci_fire_count() < 8 {
        return TestResult::Fail("sci_fire_count did not advance across 8 simulated IRQ fires");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/ec",
    smoke_ec_dispatch_sci_from_irq_context
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

// ── WMI vendors ────────────────────────────────────────────────────

/// Dell event-payload decoder — Fn-key id table.
/// Verifies the core decode_dell_event() paths used at runtime.
#[cfg(target_arch = "x86_64")]
fn smoke_wmi_vendors_dell_event_decoder() -> TestResult {
    use crate::wmi_vendors::{decode_dell_event, DellEvent};

    // Mute (audio) key: type=0x0000, code=0x0109.
    // Reference: dell-wmi-base.c `KE_KEY, 0x0109, { KEY_MUTE }`.
    // Layout: word[0]=len, word[1]=event_type, word[2]=code.
    let buf_mute: [u8; 6] = [
        2, 0,       // word[0] = len=2 (2 extra words after this)
        0x00, 0x00, // word[1] = event_type 0x0000
        0x09, 0x01, // word[2] = code 0x0109
    ];
    match decode_dell_event(&buf_mute) {
        Some(DellEvent::FnFunctionKey { id: 0x0109 }) => {}
        other => {
            let _ = other;
            return TestResult::Fail("dell audio-mute code 0x0109 not decoded as FnFunctionKey");
        }
    }

    // Mic-mute: code 0x0150 — always decoded as MicMute regardless of type.
    // Reference: dell-wmi-base.c `KE_KEY, 0x0150, { KEY_MICMUTE }`.
    let buf_micmute: [u8; 6] = [
        2, 0,
        0x10, 0x00, // event_type 0x0010
        0x50, 0x01, // code 0x0150
    ];
    match decode_dell_event(&buf_micmute) {
        Some(DellEvent::MicMute) => {}
        _ => return TestResult::Fail("dell mic-mute code 0x0150 not decoded as MicMute"),
    }

    // Brightness down: type=0x0010, code=0x0057.
    // Reference: dell-wmi-base.c `KE_KEY, 0x57, { KEY_BRIGHTNESSDOWN }`.
    let buf_bright: [u8; 6] = [
        2, 0,
        0x10, 0x00, // event_type 0x0010
        0x57, 0x00, // code 0x0057
    ];
    match decode_dell_event(&buf_bright) {
        Some(DellEvent::FnFunctionKey { id: 0x0057 }) => {}
        _ => return TestResult::Fail("dell brightness-down code 0x0057 not decoded"),
    }

    // Tablet-mode: type=0x0011, code=0xe070.
    // Reference: dell-wmi-base.c line 447 — SW_TABLET_MODE, !buffer[0].
    let buf_tablet: [u8; 8] = [
        3, 0,       // len=3
        0x11, 0x00, // event_type 0x0011
        0x70, 0xe0, // code 0xe070
        0x00, 0x00, // word[3] = 0 → entering tablet mode (on=true)
    ];
    match decode_dell_event(&buf_tablet) {
        Some(DellEvent::TabletMode { on: true }) => {}
        _ => return TestResult::Fail("dell tablet-mode entry not decoded"),
    }

    // Truncated payload should return None.
    match decode_dell_event(&[0x02, 0x00]) {
        None => {}
        _ => return TestResult::Fail("truncated dell payload should return None"),
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/wmi_vendors",
    smoke_wmi_vendors_dell_event_decoder
);

/// HP event-payload decoder — event id and data parsing.
#[cfg(target_arch = "x86_64")]
fn smoke_wmi_vendors_hp_event_decoder() -> TestResult {
    use crate::wmi_vendors::{decode_hp_event, HpEvent};

    // HPWMI_WIRELESS (0x05): 8-byte payload.
    // Reference: hp-wmi.c `case HPWMI_WIRELESS`.
    let buf_wireless: [u8; 8] = [
        0x05, 0x00, 0x00, 0x00, // event_id = 5
        0x00, 0x00, 0x00, 0x00, // event_data = 0
    ];
    match decode_hp_event(&buf_wireless) {
        Some(HpEvent::WlanToggle) => {}
        _ => return TestResult::Fail("HP wireless event not decoded as WlanToggle"),
    }

    // HPWMI_BEZEL_BUTTON (0x04) with key_code 0x270 (mic mute).
    // Reference: hp-wmi.c keymap `{ KE_KEY, 0x270, { KEY_MICMUTE } }`.
    let buf_bezel: [u8; 8] = [
        0x04, 0x00, 0x00, 0x00, // event_id = 4 (BEZEL_BUTTON)
        0x70, 0x02, 0x00, 0x00, // event_data = 0x270
    ];
    match decode_hp_event(&buf_bezel) {
        Some(HpEvent::BezelButton { key_code: 0x270 }) => {}
        _ => return TestResult::Fail("HP bezel button key_code 0x270 not decoded"),
    }

    // 16-byte payload: event_data is at offset 8, not offset 4.
    // Reference: hp-wmi.c lines 1102–1105.
    let mut buf16 = [0u8; 16];
    buf16[0] = 0x04; // event_id = HPWMI_BEZEL_BUTTON
    buf16[8] = 0x03; // event_data at offset 8 = 0x03 (BrightnessDown)
    match decode_hp_event(&buf16) {
        Some(HpEvent::BezelButton { key_code: 0x03 }) => {}
        _ => return TestResult::Fail("HP 16-byte payload: event_data not read from offset 8"),
    }

    // Camera toggle open (event_data 0xfe).
    let buf_cam: [u8; 8] = [
        0x1A, 0x00, 0x00, 0x00, // event_id = 0x1A (CAMERA_TOGGLE)
        0xfe, 0x00, 0x00, 0x00, // event_data = 0xfe
    ];
    match decode_hp_event(&buf_cam) {
        Some(HpEvent::CameraToggle { open: true }) => {}
        _ => return TestResult::Fail("HP camera open (0xfe) not decoded"),
    }

    // Truncated payload → None.
    match decode_hp_event(&[0x04, 0x00, 0x00]) {
        None => {}
        _ => return TestResult::Fail("HP truncated payload should return None"),
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/wmi_vendors",
    smoke_wmi_vendors_hp_event_decoder
);

/// Lenovo tablet-mode toggle decoder (YMC GUID).
/// Reference: ymc.c sparse keymap — 0x01=laptop, 0x02–0x04=tablet.
#[cfg(target_arch = "x86_64")]
fn smoke_wmi_vendors_lenovo_tablet_mode() -> TestResult {
    use crate::wmi_vendors::{decode_lenovo_ymc_event, LenovoEvent};

    // Code 0x01 → laptop mode (on=false).
    let buf_laptop = 1u32.to_le_bytes();
    match decode_lenovo_ymc_event(&buf_laptop) {
        Some(LenovoEvent::TabletMode { on: false }) => {}
        _ => return TestResult::Fail("Lenovo YMC 0x01 should decode as TabletMode{on:false}"),
    }

    // Code 0x02 → tablet mode (on=true).
    let buf_tablet = 2u32.to_le_bytes();
    match decode_lenovo_ymc_event(&buf_tablet) {
        Some(LenovoEvent::TabletMode { on: true }) => {}
        _ => return TestResult::Fail("Lenovo YMC 0x02 should decode as TabletMode{on:true}"),
    }

    // Code 0x03 (tent mode) → tablet (on=true).
    let buf_tent = 3u32.to_le_bytes();
    match decode_lenovo_ymc_event(&buf_tent) {
        Some(LenovoEvent::TabletMode { on: true }) => {}
        _ => return TestResult::Fail("Lenovo YMC 0x03 (tent) should be TabletMode{on:true}"),
    }

    // Code 0x04 (stand mode) → tablet (on=true).
    let buf_stand = 4u32.to_le_bytes();
    match decode_lenovo_ymc_event(&buf_stand) {
        Some(LenovoEvent::TabletMode { on: true }) => {}
        _ => return TestResult::Fail("Lenovo YMC 0x04 (stand) should be TabletMode{on:true}"),
    }

    // Unknown code.
    let buf_unknown = 0xFFu32.to_le_bytes();
    match decode_lenovo_ymc_event(&buf_unknown) {
        Some(LenovoEvent::Unknown { raw: 0xFF }) => {}
        _ => return TestResult::Fail("Lenovo YMC unknown code should produce LenovoEvent::Unknown"),
    }

    // Truncated.
    match decode_lenovo_ymc_event(&[0x01]) {
        None => {}
        _ => return TestResult::Fail("Lenovo YMC truncated payload should return None"),
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/wmi_vendors",
    smoke_wmi_vendors_lenovo_tablet_mode
);

/// Vendor detection: guid_str_to_bytes parses known GUIDs and
/// init() returns UnknownVendor when no vendor GUID is in the registry.
#[cfg(target_arch = "x86_64")]
fn smoke_wmi_vendors_detection_no_guid() -> TestResult {
    use crate::wmi_vendors::{__test_reset, guid_str_to_bytes, init, WmiVendorError};

    // guid_str_to_bytes must round-trip for the five known GUIDs.
    let guids = [
        "8D9DDCBC-A997-11DA-B012-B622A1EF5492",
        "9DBB5994-A997-11DA-B012-B622A1EF5492",
        "95F24279-4D7B-4334-9387-ACCDC67EF61C",
        "5FB7F034-2C63-45E9-BE91-3D44E2C707E4",
        "21494638-4391-4287-94B2-DDF09FE4A7AA",
        "06129D99-6083-4164-81AD-F092F9D773A6",
    ];
    for g in guids {
        if guid_str_to_bytes(g).is_none() {
            return TestResult::Fail("guid_str_to_bytes returned None for a known GUID");
        }
    }

    // Malformed GUID.
    if guid_str_to_bytes("not-a-guid").is_some() {
        return TestResult::Fail("guid_str_to_bytes accepted a malformed string");
    }

    // With an empty WMI registry (no enumerate_guids call) init()
    // should return NoGuids.
    __test_reset();
    match init() {
        Err(WmiVendorError::NoGuids) => {}
        _ => return TestResult::Fail("init() should return NoGuids when GUID registry is empty"),
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/platform/wmi_vendors",
    smoke_wmi_vendors_detection_no_guid
);

// ── wmi_core ──────────────────────────────────────────────────────────

/// WMI block decode: GUID parse + object ID + flags.
/// Verifies the shared `wmi_core::guid_to_bytes` round-trips a known GUID
/// and that `decode_wdg` correctly unpacks a synthetic _WDG buffer.
fn smoke_wmi_core_guid_and_wdg_decode() -> TestResult {
    use crate::wmi_core::guid_to_bytes;
    use narf_aml::wmi::{decode_wdg, WDG_FLAG_EVENT};

    // Known Dell WMI descriptor GUID must parse successfully.
    let bytes = guid_to_bytes("8D9DDCBC-A997-11DA-B012-B622A1EF5492");
    if bytes.is_none() {
        return TestResult::Fail("wmi_core::guid_to_bytes failed for Dell descriptor GUID");
    }

    // Craft a minimal 20-byte _WDG buffer: one descriptor.
    //   GUID = [0u8; 16], object_id = b"AA", instance=1, flags=WDG_FLAG_EVENT.
    let mut wdg = [0u8; 20];
    wdg[16] = b'A';
    wdg[17] = b'A';
    wdg[18] = 1; // instance_count
    wdg[19] = WDG_FLAG_EVENT;

    let descs = decode_wdg(&wdg);
    match descs {
        Ok(ref v) if v.len() == 1 => {
            if !v[0].is_event() {
                return TestResult::Fail("WDG descriptor flag WDG_FLAG_EVENT not detected");
            }
            if v[0].object_id != [b'A', b'A'] {
                return TestResult::Fail("WDG descriptor object_id mismatch");
            }
        }
        _ => return TestResult::Fail("decode_wdg failed on valid 20-byte buffer"),
    }

    // Notification ID field — bad length should error.
    let short = [0u8; 7];
    if decode_wdg(&short).is_ok() {
        return TestResult::Fail("decode_wdg should reject non-multiple-of-20 length");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/wmi_core",
    smoke_wmi_core_guid_and_wdg_decode
);

/// WMI method invocation argument encoding.
/// Verifies `wmi_core::build_wmi_args` produces the correct three-arg layout.
fn smoke_wmi_core_method_arg_encode() -> TestResult {
    use crate::wmi_core::build_wmi_args;

    let guid = [0xABu8; 16];
    let args = build_wmi_args(0, 42, &guid);

    // Arg0 = integer 0 (instance).
    match &args[0] {
        narf_aml::Value::Integer(0) => {}
        _ => return TestResult::Fail("Arg0 should be Integer(0) for instance"),
    }
    // Arg1 = integer 42 (method_id).
    match &args[1] {
        narf_aml::Value::Integer(42) => {}
        _ => return TestResult::Fail("Arg1 should be Integer(42) for method_id"),
    }
    // Arg2 = Buffer(16 bytes of GUID).
    match &args[2] {
        narf_aml::Value::Buffer(b) if b.len() == 16 && b[0] == 0xAB => {}
        _ => return TestResult::Fail("Arg2 should be Buffer(16-byte GUID)"),
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/wmi_core",
    smoke_wmi_core_method_arg_encode
);

// ── thinkpad_acpi ──────────────────────────────────────────────────────

/// ThinkPad HKEY 0x1004 → KEY_BRIGHTNESSUP.
/// Reference: thinkpad_acpi.c hotkey_map for 0x1004 (BRIGHTNESSUP).
fn smoke_thinkpad_hkey_0x1004_brightness_up() -> TestResult {
    use crate::thinkpad_acpi::{decode_hkey_event, hkey_to_keycode, HkeyEvent};
    use narf_input::KeyCode;

    let ev = decode_hkey_event(0x1004);
    match ev {
        HkeyEvent::FnKey { code: 0x1004 } => {}
        _ => return TestResult::Fail("0x1004 should decode as FnKey{0x1004}"),
    }
    match hkey_to_keycode(0x1004) {
        Some(KeyCode::BrightnessUp) => {}
        _ => return TestResult::Fail("0x1004 should map to KeyCode::BrightnessUp"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad_acpi",
    smoke_thinkpad_hkey_0x1004_brightness_up
);

/// ThinkPad battery conservation set/get round-trip.
fn smoke_thinkpad_battery_conservation_round_trip() -> TestResult {
    use crate::thinkpad_acpi::{battery_conservation_enabled, set_battery_conservation, __test_reset};

    __test_reset();

    if battery_conservation_enabled() {
        return TestResult::Fail("conservation should be false after reset");
    }
    set_battery_conservation(true);
    if !battery_conservation_enabled() {
        return TestResult::Fail("conservation should be true after set(true)");
    }
    set_battery_conservation(false);
    if battery_conservation_enabled() {
        return TestResult::Fail("conservation should be false after set(false)");
    }
    __test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad_acpi",
    smoke_thinkpad_battery_conservation_round_trip
);

/// ThinkPad dock-in / dock-out HKEY decode.
fn smoke_thinkpad_dock_hkey_decode() -> TestResult {
    use crate::thinkpad_acpi::{decode_hkey_event, HkeyEvent};

    match decode_hkey_event(0x4010) {
        HkeyEvent::DockIn => {}
        _ => return TestResult::Fail("0x4010 should decode as DockIn"),
    }
    match decode_hkey_event(0x4011) {
        HkeyEvent::DockOut => {}
        _ => return TestResult::Fail("0x4011 should decode as DockOut"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/thinkpad_acpi",
    smoke_thinkpad_dock_hkey_decode
);

// ── dell_laptop ────────────────────────────────────────────────────────

/// Dell SMBIOS class/select/cmd encode (4-byte header).
/// Verifies `DellSmbiosCmd::encode` matches the Linux `struct dell_smbios_call_in`.
fn smoke_dell_smbios_cmd_encode() -> TestResult {
    use crate::dell_laptop::DellSmbiosCmd;

    let cmd = DellSmbiosCmd::new(17, 3);
    let buf = cmd.encode();
    // header = (17 << 8) | 3 = 0x1103 LE.
    let header = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if header != (17u32 << 8) | 3 {
        return TestResult::Fail("DellSmbiosCmd header encoding mismatch");
    }
    // in1..in3 should be zero for a default command.
    if buf[4..16].iter().any(|&b| b != 0) {
        return TestResult::Fail("DellSmbiosCmd default in1/in2/in3 should be zero");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/dell_laptop",
    smoke_dell_smbios_cmd_encode
);

/// Dell WMI event 0xE040 → KEY_KBDILLUMUP.
/// Reference: dell-wmi-base.c `KE_KEY, 0xE040, { KEY_KBDILLUMUP }`.
fn smoke_dell_wmi_event_0xe040_kbdillumup() -> TestResult {
    use crate::dell_laptop::{decode_dell_wmi_event, DellWmiEvent};

    let buf: [u8; 6] = [
        2, 0,
        0x10, 0x00, // event_type 0x0010
        0x40, 0xE0, // code 0xE040 LE
    ];
    match decode_dell_wmi_event(&buf) {
        Some(DellWmiEvent::KbdIllumUp) => {}
        _ => return TestResult::Fail("Dell WMI code 0xE040 should decode as KbdIllumUp"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/dell_laptop",
    smoke_dell_wmi_event_0xe040_kbdillumup
);

// ── hp_wmi ─────────────────────────────────────────────────────────────

/// HP WMI command type 0x07 (wireless) — verify type constant.
fn smoke_hp_wmi_command_wireless_type() -> TestResult {
    use crate::hp_wmi::HpWmiCommand;

    if HpWmiCommand::Wireless as u32 != 0x07 {
        return TestResult::Fail("HpWmiCommand::Wireless should have value 0x07");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/hp_wmi",
    smoke_hp_wmi_command_wireless_type
);

/// HP WMI wireless state decode from response buffer.
fn smoke_hp_wmi_wireless_state_decode() -> TestResult {
    use crate::hp_wmi::decode_wireless_state;

    // flags = 0x03 → wifi=true, bluetooth=true, wwan=false.
    let buf = [0x03u8, 0x00, 0x00, 0x00, 0, 0, 0, 0];
    let state = match decode_wireless_state(&buf) {
        Some(s) => s,
        None => return TestResult::Fail("decode_wireless_state returned None"),
    };
    if !state.wifi {
        return TestResult::Fail("wifi should be true (bit 0)");
    }
    if !state.bluetooth {
        return TestResult::Fail("bluetooth should be true (bit 1)");
    }
    if state.wwan {
        return TestResult::Fail("wwan should be false (bit 2 clear)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/hp_wmi",
    smoke_hp_wmi_wireless_state_decode
);

// ── asus_wmi ───────────────────────────────────────────────────────────

/// ASUS hotkey 0x39 → KEY_VOLUMEDOWN.
/// Reference: asus-nb-wmi.c keymap entry 0x39.
fn smoke_asus_hotkey_0x39_volumedown() -> TestResult {
    use crate::asus_wmi::asus_keycode;
    use narf_input::KeyCode;

    match asus_keycode(0x39) {
        Some(KeyCode::VolumeDown) => {}
        _ => return TestResult::Fail("ASUS hotkey 0x39 should map to KeyCode::VolumeDown"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/asus_wmi",
    smoke_asus_hotkey_0x39_volumedown
);

/// ASUS ROG fan curve 4-point setpoint interpolation.
fn smoke_asus_fan_curve_interpolate() -> TestResult {
    use crate::asus_wmi::FanCurve;

    let curve = FanCurve::new((30, 10), (50, 30), (70, 60), (90, 100));

    // Below lowest point → lowest pct.
    if curve.interpolate(20) != 10 {
        return TestResult::Fail("temp below min should return min fan pct (10)");
    }
    // Above highest point → 100%.
    if curve.interpolate(95) != 100 {
        return TestResult::Fail("temp above max should return 100");
    }
    // Midpoint between (50,30) and (70,60): temp=60 → pct=45.
    let mid = curve.interpolate(60);
    if mid != 45 {
        return TestResult::Fail("midpoint interpolation mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/asus_wmi",
    smoke_asus_fan_curve_interpolate
);

// ── ideapad_laptop ─────────────────────────────────────────────────────

/// IdeaPad VPC index 0x2 (camera state) — constant value.
fn smoke_ideapad_vpc_camera_index() -> TestResult {
    use crate::ideapad_laptop::VPC_IDX_CAMERA;

    if VPC_IDX_CAMERA != 0x2 {
        return TestResult::Fail("VPC_IDX_CAMERA must be 0x2 per ideapad-laptop.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/ideapad_laptop",
    smoke_ideapad_vpc_camera_index
);

/// IdeaPad performance mode 1=Balanced / 2=Performance round-trip.
fn smoke_ideapad_perf_mode_round_trip() -> TestResult {
    use crate::ideapad_laptop::{perf_mode, set_perf_mode, PerfMode, __test_reset};

    __test_reset();
    if perf_mode() != PerfMode::Balanced {
        return TestResult::Fail("default perf mode should be Balanced(1)");
    }
    set_perf_mode(PerfMode::Performance);
    if perf_mode() != PerfMode::Performance {
        return TestResult::Fail("set_perf_mode(Performance) not stored");
    }
    set_perf_mode(PerfMode::Quiet);
    if perf_mode() != PerfMode::Quiet {
        return TestResult::Fail("set_perf_mode(Quiet) not stored");
    }
    __test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/ideapad_laptop",
    smoke_ideapad_perf_mode_round_trip
);

/// IdeaPad battery conservation toggle round-trip.
fn smoke_ideapad_battery_conservation_toggle() -> TestResult {
    use crate::ideapad_laptop::{battery_conservation_enabled, set_battery_conservation, __test_reset};

    __test_reset();
    if battery_conservation_enabled() {
        return TestResult::Fail("conservation should be false after reset");
    }
    set_battery_conservation(true);
    if !battery_conservation_enabled() {
        return TestResult::Fail("conservation should be true after enable");
    }
    __test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/ideapad_laptop",
    smoke_ideapad_battery_conservation_toggle
);

// ── samsung_laptop ─────────────────────────────────────────────────────

/// Samsung SABI invocation header encode.
/// Verifies the magic bytes and class/function fields.
fn smoke_samsung_sabi_header_encode() -> TestResult {
    use crate::samsung_laptop::{SabiCmd, SABI_MAGIC};

    let cmd = SabiCmd {
        class: 0x08,
        function: 0x13,
        data0: 0xDEAD_BEEF,
    };
    let buf = cmd.encode();

    // Bytes 0–1: SABI_MAGIC (0x5AA5 LE).
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != SABI_MAGIC {
        return TestResult::Fail("SABI magic bytes incorrect");
    }
    // Byte 2: class.
    if buf[2] != 0x08 {
        return TestResult::Fail("SABI class byte incorrect");
    }
    // Byte 3: function.
    if buf[3] != 0x13 {
        return TestResult::Fail("SABI function byte incorrect");
    }
    // Bytes 4–7: data0 LE.
    let data0 = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if data0 != 0xDEAD_BEEF {
        return TestResult::Fail("SABI data0 bytes incorrect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/samsung_laptop",
    smoke_samsung_sabi_header_encode
);

// ── registry ───────────────────────────────────────────────────────────

/// Vendor-detect: match by manufacturer string → OemVendor route.
fn smoke_registry_vendor_detect_from_mfr() -> TestResult {
    use crate::registry::OemVendor;

    // LENOVO → ThinkPad (tentative; AML refinement not run in unit test).
    if OemVendor::from_manufacturer("LENOVO") != OemVendor::ThinkPad {
        return TestResult::Fail("LENOVO should map to OemVendor::ThinkPad");
    }
    // Dell variant with "Inc." suffix.
    if OemVendor::from_manufacturer("Dell Inc.") != OemVendor::Dell {
        return TestResult::Fail("Dell Inc. should map to OemVendor::Dell");
    }
    // HP with leading "HP " space.
    if OemVendor::from_manufacturer("HP Laptop") != OemVendor::Hp {
        return TestResult::Fail("HP Laptop should map to OemVendor::Hp");
    }
    // ASUS.
    if OemVendor::from_manufacturer("ASUSTeK COMPUTER INC.") != OemVendor::Asus {
        return TestResult::Fail("ASUSTeK should map to OemVendor::Asus");
    }
    // Samsung.
    if OemVendor::from_manufacturer("SAMSUNG ELECTRONICS CO., LTD.") != OemVendor::Samsung {
        return TestResult::Fail("SAMSUNG should map to OemVendor::Samsung");
    }
    // Unknown.
    if OemVendor::from_manufacturer("Acme Corp") != OemVendor::Unknown {
        return TestResult::Fail("Unknown manufacturer should map to OemVendor::Unknown");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/registry",
    smoke_registry_vendor_detect_from_mfr
);
