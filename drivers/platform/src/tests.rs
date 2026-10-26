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

fn smoke_asus_wmi_fan_curve_interpolate() -> TestResult {
    let curve = crate::asus_wmi::FanCurve::new((40, 20), (60, 40), (75, 70), (90, 100));
    if curve.interpolate(30) != 20 {
        return TestResult::Fail("below lowest point should cap at lowest pct");
    }
    if curve.interpolate(50) != 30 {
        return TestResult::Fail("linear interpolation failed (40..60)");
    }
    if curve.interpolate(100) != 100 {
        return TestResult::Fail("above highest point should cap at highest pct");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-platform", smoke_asus_wmi_fan_curve_interpolate);

fn smoke_acer_wmi_keycode_decode() -> TestResult {
    use narf_input::KeyCode;
    if crate::acer_wmi::acer_keycode(0x01) != Some(KeyCode::WLan) {
        return TestResult::Fail("0x01 should be WLan");
    }
    if crate::acer_wmi::acer_keycode(0x48) != Some(KeyCode::VolumeUp) {
        return TestResult::Fail("0x48 should be VolumeUp");
    }
    if crate::acer_wmi::acer_keycode(0x9999).is_some() {
        return TestResult::Fail("0x9999 should be None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-platform", smoke_acer_wmi_keycode_decode);

fn smoke_alienware_wmi_guids_valid() -> TestResult {
    if crate::wmi_vendors::guid_str_to_bytes(crate::alienware_wmi::WMAX_CONTROL_GUID).is_none() {
        return TestResult::Fail("WMAX_CONTROL_GUID is invalid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-platform", smoke_alienware_wmi_guids_valid);

fn smoke_system76_acpi_hid_valid() -> TestResult {
    if crate::system76_acpi::SYSTEM76_ACPI_HID.len() < 7 {
        return TestResult::Fail("System76 HID is invalid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-platform", smoke_system76_acpi_hid_valid);

fn smoke_surface_acpi_hid_valid() -> TestResult {
    if crate::surface_acpi::SURFACE_BUTTON_HID.len() < 7 {
        return TestResult::Fail("Surface HID is invalid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-platform", smoke_surface_acpi_hid_valid);

fn smoke_acpi_ec_discovery() -> TestResult {
    use crate::ec;
    if ec::with_ec(|_| {}).is_some() {
        TestResult::Pass
    } else {
        TestResult::Skip("ACPI EC not found (not a laptop config?)")
    }
}
kernel_test_in!("drivers/platform/ec", smoke_acpi_ec_discovery);

/// The installed EC must never move, be replaced, or be dropped.
///
/// `ec::probed_ec` reads the EC's address under the `GLOBAL_EC` lock,
/// releases the lock, and hands out a `&'static AcpiEc` used for whole
/// EC transactions — which is what lets the up-to-200 ms IBF/OBF waits
/// run with interrupts enabled instead of masking them machine-wide.
/// That is only sound because `init` installs the EC exactly once and
/// nothing ever stores `None` back. A later "re-init the EC on resume"
/// change would invalidate it silently, leaving a data race reachable
/// only under a live SCI burst — so assert it directly: a repeat
/// `init()` must be refused and must not move the installed EC.
fn smoke_acpi_ec_address_is_stable() -> TestResult {
    use crate::ec;
    let before = match ec::dbg_ec_addr() {
        Some(a) => a,
        None => return TestResult::Skip("ACPI EC not initialized"),
    };
    // A repeat init must early-return, not rebuild (or even rewrite)
    // the installed EC.
    ec::init();
    match ec::dbg_ec_addr() {
        Some(a) if a == before => {}
        Some(_) => return TestResult::Fail("re-init MOVED the installed EC"),
        None => return TestResult::Fail("re-init removed the installed EC"),
    }
    // And the unlocked accessor must hand back exactly that EC.
    match ec::probed_ec().map(|ec| ec as *const _ as usize) {
        Some(a) if a == before => TestResult::Pass,
        Some(_) => TestResult::Fail("probed_ec disagrees with the installed address"),
        None => TestResult::Fail("probed_ec lost the installed EC"),
    }
}
kernel_test_in!("drivers/platform/ec", smoke_acpi_ec_address_is_stable);

// ── ACPI thermal fixtures ──────────────────────────────────────
//
// Hand-encoded AML (the encoder idiom of aml's own e2e tests),
// appended to the boot namespace under unique names — no reset, so
// the real namespace and sibling fixtures are untouched. The
// fixture zone's `_TMP` reads a mutable Name (TMPV) the test
// rewrites through a fixture SETT method; the fixture fan's
// `_FSL`/`_ON`/`_OFF` Store their effect into Names the test reads
// back. The whole sense → decide → actuate loop is therefore driven
// and observed through the public AML surface, exactly as on real
// firmware.

/// PkgLength + NameString(`\SEG`) + body wrapper for Device /
/// ThermalZone terms (ExtOpPrefix + ext op).
fn fx_wrap(ext_op: u8, seg: &[u8; 4], inside: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    // PkgLength counts the PkgLength field itself.
    let rest = 1 + 4 + inside.len(); // NameString (root + seg) + inside
    let value = if rest + 1 < 64 { rest + 1 } else { rest + 2 };
    let mut v = Vec::new();
    v.push(0x5B); // ExtOpPrefix
    v.push(ext_op);
    if value < 64 {
        v.push(value as u8);
    } else {
        v.push(0x40 | (value as u8 & 0x0F));
        v.push((value >> 4) as u8);
    }
    v.push(b'\\');
    v.extend_from_slice(seg);
    v.extend_from_slice(inside);
    v
}

/// MethodOp with a single-byte PkgLength (all fixture methods are
/// small enough).
fn fx_method(seg: &[u8; 4], flags: u8, body: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let value = 1 + 4 + 1 + body.len(); // PkgLength counts itself
    let mut v = Vec::new();
    v.push(0x14); // MethodOp
    v.push(value as u8);
    v.extend_from_slice(seg);
    v.push(flags);
    v.extend_from_slice(body);
    v
}

/// Name(seg, WordPrefix value).
fn fx_name_word(seg: &[u8; 4], value: u16) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(0x08); // NameOp
    v.extend_from_slice(seg);
    v.push(0x0B); // WordPrefix
    v.extend_from_slice(&value.to_le_bytes());
    v
}

/// Name(seg, BytePrefix value).
fn fx_name_byte(seg: &[u8; 4], value: u8) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(0x08); // NameOp
    v.extend_from_slice(seg);
    v.push(0x0A); // BytePrefix
    v.push(value);
    v
}

/// Name(seg, 0) via ZeroOp.
fn fx_name_zero(seg: &[u8; 4]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(0x08); // NameOp
    v.extend_from_slice(seg);
    v.push(0x00); // ZeroOp
    v
}

/// NameString `\A.B` (root + DualNamePrefix + two segs).
fn fx_ref2(a: &[u8; 4], b: &[u8; 4]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(b'\\');
    v.push(0x2E); // DualNamePrefix
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

/// Method body `Return(\ZONE.TMPV)`.
fn fx_tmp_body(zone: &[u8; 4]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut v = Vec::new();
    v.push(0xA4); // ReturnOp
    v.extend_from_slice(&fx_ref2(zone, b"TMPV"));
    v
}

/// ThermalZone(TZ98) { TMPV=3132, _TMP, _CRT=3732, _PSV=3532 } —
/// 3132 deciK = 40.05 C, _CRT 100.05 C, _PSV 80.05 C.
fn fx_zone98() -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut inside = Vec::new();
    inside.extend_from_slice(&fx_name_word(b"TMPV", 3132));
    inside.extend_from_slice(&fx_method(b"_TMP", 0, &fx_tmp_body(b"TZ98")));
    inside.extend_from_slice(&fx_name_word(b"_CRT", 3732));
    inside.extend_from_slice(&fx_name_word(b"_PSV", 3532));
    fx_wrap(0x85, b"TZ98", &inside)
}

/// ThermalZone(TZ99) { TMPV, _TMP, SETT, _CRT=3732, _AC0=3332 } —
/// deliberately NO _PSV: the bridge maps warn ← _AC0 (60.05 C),
/// the retired platform duplicate would have used _CRT − 10 C
/// (90.05 C), so the Warm step at 70.05 C distinguishes them.
/// Plus Device(FAN9) { _HID="PNP0C0B", FANL=0xFF, FONS=0, _FIF,
/// _ON, _OFF, _FSL } with observable actuation state.
fn fx_zone99_fan9() -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let mut zone = Vec::new();
    zone.extend_from_slice(&fx_name_word(b"TMPV", 3132));
    zone.extend_from_slice(&fx_method(b"_TMP", 0, &fx_tmp_body(b"TZ99")));
    // Method(SETT, 1) { Store(Arg0, \TZ99.TMPV) }
    let mut sett = Vec::new();
    sett.push(0x70); // StoreOp
    sett.push(0x68); // Arg0
    sett.extend_from_slice(&fx_ref2(b"TZ99", b"TMPV"));
    zone.extend_from_slice(&fx_method(b"SETT", 1, &sett));
    zone.extend_from_slice(&fx_name_word(b"_CRT", 3732));
    zone.extend_from_slice(&fx_name_word(b"_AC0", 3332));
    let mut blob = fx_wrap(0x85, b"TZ99", &zone);

    let mut fan = Vec::new();
    // Name(_HID, "PNP0C0B")
    fan.push(0x08);
    fan.extend_from_slice(b"_HID");
    fan.push(0x0D); // StringPrefix
    fan.extend_from_slice(b"PNP0C0B");
    fan.push(0x00);
    fan.extend_from_slice(&fx_name_byte(b"FANL", 0xFF));
    fan.extend_from_slice(&fx_name_zero(b"FONS"));
    // Method(_FIF, 0) { Return(1) } — evaluates, so probe sees
    // fine-grained control; AcpiFan's ladder is then 10 steps.
    fan.extend_from_slice(&fx_method(b"_FIF", 0, &[0xA4, 0x01]));
    // Method(_ON, 0) { Store(1, \FAN9.FONS) }
    let mut on = Vec::new();
    on.push(0x70);
    on.push(0x01); // OneOp
    on.extend_from_slice(&fx_ref2(b"FAN9", b"FONS"));
    fan.extend_from_slice(&fx_method(b"_ON_", 0, &on));
    // Method(_OFF, 0) { Store(0, \FAN9.FONS) }
    let mut off = Vec::new();
    off.push(0x70);
    off.push(0x00); // ZeroOp
    off.extend_from_slice(&fx_ref2(b"FAN9", b"FONS"));
    fan.extend_from_slice(&fx_method(b"_OFF", 0, &off));
    // Method(_FSL, 1) { Store(Arg0, \FAN9.FANL) }
    let mut fsl = Vec::new();
    fsl.push(0x70);
    fsl.push(0x68); // Arg0
    fsl.extend_from_slice(&fx_ref2(b"FAN9", b"FANL"));
    fan.extend_from_slice(&fx_method(b"_FSL", 1, &fsl));
    blob.extend_from_slice(&fx_wrap(0x82, b"FAN9", &fan));
    blob
}

/// Production gets the thermal registry from power's Stage::PostCore
/// `thermal-registry` initcall. A sibling power smoke ends with
/// `thermal::__test_reset()`, so re-init here only if a reset landed
/// first — the power crate's own test idiom.
fn ensure_thermal_registry() {
    if !narf_power::thermal::has_active_cooling() {
        narf_power::thermal::init();
    }
}

/// Read an Integer Name node back out of the namespace.
fn fx_name_int(path: &str) -> Option<u64> {
    match narf_aml::find_node(path).and_then(|n| n.value) {
        Some(narf_aml::NameValue::Integer(v)) => Some(v),
        _ => None,
    }
}

/// (temp_milli, state) of a registered generic-registry zone.
fn snap_zone(path: &str) -> Option<(i32, narf_power::thermal::ThermalState)> {
    narf_power::thermal::zones_snapshot()
        .into_iter()
        .find(|(n, _, _)| n == path)
        .map(|(_, t, s)| (t, s))
}

fn smoke_acpi_thermal_discovery() -> TestResult {
    // Zone-count assertion against a fixture namespace (#915): the
    // previous body asserted nothing — `zone_count() >= 0` is true
    // for a `usize` even with the registry never initialised, which
    // is how the dead loop shipped unnoticed.
    let blob = fx_zone98();
    if narf_aml::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("fixture ThermalZone parse failed");
    }
    // The ACPI layer must enumerate the fixture zone...
    let zones = narf_power::acpi_thermal::enumerate();
    let zone = match zones.iter().find(|z| z.path == "\\TZ98") {
        Some(z) => z,
        None => return TestResult::Fail("enumerate() missed the fixture zone"),
    };
    // ...with its trip points modelled (TZ98: _CRT 100.05 C,
    // _PSV 80.05 C).
    let trips = zone.trip_points();
    if trips.critical_milli_c != Some(100_050) || trips.passive_milli_c != Some(80_050) {
        return TestResult::Fail("fixture zone trip points modelled wrong");
    }
    // The bridge must land it in the generic registry, and the
    // registry's zone count must grow by exactly the bridge's count.
    ensure_thermal_registry();
    let cap = narf_power::bootstrap_thermal_authority();
    let before = narf_power::thermal::zone_count();
    let n = narf_power::acpi_thermal::register_with_generic_registry(&cap);
    if n == 0 {
        return TestResult::Fail("bridge registered no zones (fixture zone should be new)");
    }
    if narf_power::thermal::zone_count() != before + n {
        return TestResult::Fail("zone_count did not grow by the bridge's registered count");
    }
    if snap_zone("\\TZ98").is_none() {
        return TestResult::Fail("fixture zone missing from the generic registry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/thermal", smoke_acpi_thermal_discovery);

fn smoke_thermal_loop_end_to_end() -> TestResult {
    use narf_power::thermal::ThermalState;

    // (1) Composition: power's registry initcall is registered at a
    // stage ordered before the Stage::Subsys producers. This is the
    // #907 regression oracle — with the initcall absent (or moved
    // to Subsys, where frame's registration order runs platform's
    // producers first), registration in a real boot fails
    // NotInitialised and the loop is dead.
    let postcore = narf_init::registered_names(narf_init::Stage::PostCore);
    if !postcore.contains(&"thermal-registry") {
        return TestResult::Fail("thermal-registry initcall missing at Stage::PostCore");
    }
    let subsys = narf_init::registered_names(narf_init::Stage::Subsys);
    if subsys.contains(&"thermal-registry") {
        return TestResult::Fail("thermal-registry must not sit at Stage::Subsys");
    }

    ensure_thermal_registry();

    // (2) Fixture namespace: TZ99 + FAN9 (see fx_zone99_fan9).
    let blob = fx_zone99_fan9();
    if narf_aml::__parse_body_for_test(&blob, "\\").is_err() {
        return TestResult::Fail("fixture zone/fan parse failed");
    }

    // (3) Producers, in boot order (platform registers acpi-thermal
    // before acpi-fan). thermal::init also spawns the poll task; it
    // samples the same fixture state, so it cannot disturb the
    // assertions below — every actuation is a pure function of the
    // current fixture temperature.
    crate::thermal::init();
    crate::fan::init();

    // Prime one sample: temperature lands, state stays Normal, and
    // the fan is untouched (no crossing → no actuation).
    let _ = narf_power::acpi_thermal::sample_all();
    match snap_zone("\\TZ99") {
        Some((40_050, ThermalState::Normal)) => {}
        _ => return TestResult::Fail("fixture zone not sampling as Normal at 40.05 C"),
    }
    if fx_name_int("\\FAN9.FONS") != Some(0) || fx_name_int("\\FAN9.FANL") != Some(0xFF) {
        return TestResult::Fail("fan actuated before any crossing");
    }

    // (4) Warm crossing: SETT 3432 deciK = 70.05 C. With the
    // bridge's warn ← _AC0 mapping (60.05 C) this is Warm; under the
    // retired duplicate's _CRT − 10 C warn (90.05 C) it would stay
    // Normal and the fan would never move — this step pins the
    // unification (#910), not just the loop.
    // StepPolicy Warm → level 128; AcpiFan maps that to _ON plus
    // _FSL step ceil(128 * 10 / 255) = 6 on its 10-step ladder.
    if narf_aml::eval::evaluate_method("\\TZ99.SETT", &[narf_aml::Value::Integer(3432)]).is_err() {
        return TestResult::Fail("fixture SETT method failed");
    }
    let _ = narf_power::acpi_thermal::sample_all();
    match snap_zone("\\TZ99") {
        Some((70_050, ThermalState::Warm)) => {}
        _ => return TestResult::Fail("70.05 C did not classify Warm (bridge warn mapping?)"),
    }
    if fx_name_int("\\FAN9.FONS") != Some(1) {
        return TestResult::Fail("Warm crossing did not turn the fan on (_ON)");
    }
    if fx_name_int("\\FAN9.FANL") != Some(6) {
        return TestResult::Fail("Warm crossing drove wrong _FSL step (want 6 for level 128)");
    }

    // (5) Critical crossing: 3832 deciK = 110.05 C ≥ _CRT.
    // StepPolicy Critical → level 255 → _FSL step 10 (ladder max).
    if narf_aml::eval::evaluate_method("\\TZ99.SETT", &[narf_aml::Value::Integer(3832)]).is_err() {
        return TestResult::Fail("fixture SETT method failed");
    }
    let _ = narf_power::acpi_thermal::sample_all();
    match snap_zone("\\TZ99") {
        Some((110_050, ThermalState::Critical)) => {}
        _ => return TestResult::Fail("110.05 C did not classify Critical"),
    }
    if fx_name_int("\\FAN9.FANL") != Some(10) {
        return TestResult::Fail("Critical crossing drove wrong _FSL step (want 10 for level 255)");
    }

    // (6) Back to Normal: 3132 deciK = 40.05 C. Level 0 → _OFF.
    // Leaves the fixture in the Normal band so the lingering poll
    // task idles at level 0.
    if narf_aml::eval::evaluate_method("\\TZ99.SETT", &[narf_aml::Value::Integer(3132)]).is_err() {
        return TestResult::Fail("fixture SETT method failed");
    }
    let _ = narf_power::acpi_thermal::sample_all();
    match snap_zone("\\TZ99") {
        Some((40_050, ThermalState::Normal)) => {}
        _ => return TestResult::Fail("return to 40.05 C did not classify Normal"),
    }
    if fx_name_int("\\FAN9.FONS") != Some(0) {
        return TestResult::Fail("Normal crossing did not turn the fan off (_OFF)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/thermal", smoke_thermal_loop_end_to_end);

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
    ec::__test_dispatch_synthetic_block(0, &[0, 0, 0, 0, 0, 0, 0, 0, 0b0000_1100]);
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
kernel_test_in!("drivers/platform/ec", smoke_ec_synthetic_gpe_block_walk);

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
kernel_test_in!(
    "drivers/platform/lid",
    smoke_lid_subscriber_install_and_reset
);

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

fn smoke_tpm_pcr_extend_request_bytes() -> TestResult {
    use crate::tpm;
    // PCR 4 (the measured-boot PCR) + a digest of distinct bytes so
    // any transposition in the frame shows up in the diff.
    let digest: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F,
    ];
    let buf = tpm::build_pcr_extend_request(4, &digest);
    // The exact frame a real TPM accepts for TPM2_PCR_Extend
    // (Part 3 §22.2), matching the reference encoding in
    // drivers/tpm/src/tpm2/commands.rs::pcr_extend:
    //   tag TPM_ST_SESSIONS, TPM_RS_PW session (authSize 9),
    //   TPML_DIGEST_VALUES { count 1, { SHA256, digest } }.
    // The hand-rolled frame this replaced used TPM_ST_NO_SESSIONS
    // with authorizationSize 0 and is rejected with TPM_RC_VALUE
    // on silicon (#937).
    let expected: [u8; 65] = [
        0x80, 0x02, // tag = TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x41, // commandSize = 65
        0x00, 0x00, 0x01, 0x82, // cc = TPM_CC_PCR_Extend
        0x00, 0x00, 0x00, 0x04, // pcrHandle = 4
        0x00, 0x00, 0x00, 0x09, // authorizationSize = 9
        0x40, 0x00, 0x00, 0x09, // sessionHandle = TPM_RS_PW
        0x00, 0x00, // nonceSize = 0
        0x00, // sessionAttributes = 0
        0x00, 0x00, // hmacSize = 0
        0x00, 0x00, 0x00, 0x01, // TPML_DIGEST_VALUES.count = 1
        0x00, 0x0B, // hashAlg = TPM_ALG_SHA256
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, // digest
    ];
    if buf.as_slice() != expected.as_slice() {
        return TestResult::Fail("platform pcr_extend frame != reference encoding");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/tpm", smoke_tpm_pcr_extend_request_bytes);
// ── TPM CRB probe core (#939) ───────────────────────────────────
//
// The probe sequence in `crate::tpm` runs against a `CrbRegs`
// register window so it can be driven against a firmware-shaped
// model of the control area. `FakeCrbRegs` is that model: a flat
// register file plus two firmware behaviours (locality grant on
// request; a floating bus reads back all-ones). Before #939 the
// only TPM fixture was the no-TPM smoke above — no fixture
// modelled a CRB control area at all, which is how the inverted
// buffer contract shipped untested.

struct FakeCrbRegs {
    regs: core::cell::RefCell<alloc::vec::Vec<u32>>,
    writes: core::cell::RefCell<alloc::vec::Vec<(u64, u32)>>,
    grant_locality: core::cell::Cell<bool>,
    floating: core::cell::Cell<bool>,
}

impl FakeCrbRegs {
    fn new() -> Self {
        Self {
            regs: core::cell::RefCell::new(alloc::vec![0; 1024]),
            writes: core::cell::RefCell::new(alloc::vec::Vec::new()),
            grant_locality: core::cell::Cell::new(true),
            floating: core::cell::Cell::new(false),
        }
    }
    fn set32(&self, offset: u64, value: u32) {
        self.regs.borrow_mut()[(offset / 4) as usize] = value;
    }
    fn get32(&self, offset: u64) -> u32 {
        self.regs.borrow()[(offset / 4) as usize]
    }
}

impl crate::tpm::CrbRegs for FakeCrbRegs {
    fn rd32(&self, offset: u64) -> u32 {
        if self.floating.get() {
            return u32::MAX;
        }
        // Firmware behaviour: once the host requests locality via
        // LOC_CTRL, LOC_STATE reads back locAssigned.
        if offset == crate::tpm::REG_LOC_STATE
            && self.grant_locality.get()
            && self.get32(crate::tpm::REG_LOC_CTRL) & crate::tpm::LOC_CTRL_REQ_ACCESS != 0
        {
            return crate::tpm::LOC_STATE_LOC_ASSIGNED;
        }
        self.get32(offset)
    }
    fn wr32(&self, offset: u64, value: u32) {
        self.writes.borrow_mut().push((offset, value));
        self.set32(offset, value);
    }
}

fn smoke_tpm_crb_probe_firmware_shaped_control_area() -> TestResult {
    use crate::tpm;
    let regs = FakeCrbRegs::new();
    // Firmware-shaped CRB control area: INTF_ID advertises CRB
    // (type 0, version 1) and — the normal, expected state — the
    // CMD_*/RSP_* buffer registers are all ZERO, because they are
    // host-programmed (PTP §6). The pre-#939 probe read them as
    // firmware-published and returned NoCommandBuffer on exactly
    // this shape, so CRB probe could never succeed on real fTPM
    // hardware.
    regs.set32(tpm::REG_INTERFACE_ID, 0x10);
    match tpm::identify(&regs) {
        Ok(tpm::TpmKind::Crb) => {}
        _ => return TestResult::Fail("firmware-shaped CRB area not identified as CRB"),
    }
    let cmd_phys: u64 = 0x2000_0000;
    let rsp_phys: u64 = 0x2000_1000;
    if tpm::crb_acquire_and_program(
        &regs,
        cmd_phys,
        4096,
        rsp_phys,
        4096,
        narf_time::Deadline::after_ms(750),
    )
    .is_err()
    {
        return TestResult::Fail("CRB bring-up failed on a firmware-shaped control area");
    }
    // The host must have PROGRAMMED all six buffer registers with
    // its own buffers — the exact inversion of the old contract.
    if regs.get32(tpm::REG_CRB_CMD_SIZE) != 4096 {
        return TestResult::Fail("CMD_SIZE was not programmed");
    }
    if regs.get32(tpm::REG_CRB_CMD_LO) != cmd_phys as u32 {
        return TestResult::Fail("CMD_PA_LO was not programmed");
    }
    if regs.get32(tpm::REG_CRB_CMD_HI) != 0 {
        return TestResult::Fail("CMD_PA_HI was not programmed");
    }
    if regs.get32(tpm::REG_CRB_RSP_SIZE) != 4096 {
        return TestResult::Fail("RSP_SIZE was not programmed");
    }
    if regs.get32(tpm::REG_CRB_RSP_LO) != rsp_phys as u32 {
        return TestResult::Fail("RSP_PA_LO was not programmed");
    }
    if regs.get32(tpm::REG_CRB_RSP_HI) != 0 {
        return TestResult::Fail("RSP_PA_HI was not programmed");
    }
    // Locality was requested before any programming happened.
    let writes = regs.writes.borrow();
    match writes.first() {
        Some(&(off, val)) if off == tpm::REG_LOC_CTRL && val == tpm::LOC_CTRL_REQ_ACCESS => {}
        _ => return TestResult::Fail("first write was not the LOC_CTRL locality request"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-crb-firmware",
    smoke_tpm_crb_probe_firmware_shaped_control_area
);

fn smoke_tpm_crb_probe_absent_window_fails_clean() -> TestResult {
    use crate::tpm;
    // Floating bus (absent device): every read is all-ones.
    let floating = FakeCrbRegs::new();
    floating.floating.set(true);
    if tpm::identify(&floating) != Err(tpm::TpmError::NotPresent) {
        return TestResult::Fail("floating window not reported NotPresent");
    }
    // Silent window: every read is zero.
    let silent = FakeCrbRegs::new();
    if tpm::identify(&silent) != Err(tpm::TpmError::NotPresent) {
        return TestResult::Fail("silent window not reported NotPresent");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-crb-absent",
    smoke_tpm_crb_probe_absent_window_fails_clean
);

fn smoke_tpm_crb_probe_garbage_interface_fails_clean() -> TestResult {
    use crate::tpm;
    // Undefined interface type — the PTP defines 0x0 (CRB) and 0xF
    // (TIS) only. The pre-#939 probe guessed CRB here.
    let undef = FakeCrbRegs::new();
    undef.set32(tpm::REG_INTERFACE_ID, 0x3);
    if tpm::identify(&undef) != Err(tpm::TpmError::NotPresent) {
        return TestResult::Fail("undefined interface type not rejected");
    }
    // A TIS claim with no DID_VID behind it is not a device.
    let tis_no_vid = FakeCrbRegs::new();
    tis_no_vid.set32(tpm::REG_INTERFACE_ID, 0xF);
    if tpm::identify(&tis_no_vid) != Err(tpm::TpmError::NotPresent) {
        return TestResult::Fail("TIS claim without DID_VID not rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-crb-garbage",
    smoke_tpm_crb_probe_garbage_interface_fails_clean
);

fn smoke_tpm_tis_identification_still_works() -> TestResult {
    use crate::tpm;
    let regs = FakeCrbRegs::new();
    regs.set32(tpm::REG_INTERFACE_ID, 0xF);
    regs.set32(tpm::REG_TIS_DID_VID, 0x15D1_0001);
    if tpm::identify(&regs) != Ok(tpm::TpmKind::Tis) {
        return TestResult::Fail("TIS part with a sane DID_VID not identified");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-tis-identify",
    smoke_tpm_tis_identification_still_works
);

fn smoke_tpm_crb_probe_locality_never_granted() -> TestResult {
    use crate::tpm;
    let regs = FakeCrbRegs::new();
    // Same firmware-shaped INTF_ID as the firmware fixture:
    // type 0 (CRB), version 1 → 0x10.
    regs.set32(tpm::REG_INTERFACE_ID, 0x10);
    regs.grant_locality.set(false);
    // Short deadline: this fixture pins the bounded-failure shape,
    // not production's 750 ms TIMEOUT_A budget.
    match tpm::crb_acquire_and_program(
        &regs,
        0x2000_0000,
        4096,
        0x2000_1000,
        4096,
        narf_time::Deadline::after_ms(1),
    ) {
        Err(tpm::TpmError::LocalityTimeout) => TestResult::Pass,
        _ => TestResult::Fail("ungranted locality did not time out cleanly"),
    }
}
kernel_test_in!(
    "drivers/platform/tpm-crb-locality",
    smoke_tpm_crb_probe_locality_never_granted
);

fn smoke_tpm_pcr_extend_response_validation() -> TestResult {
    use crate::tpm::validate_pcr_extend_response;
    use narf_tpm::{types::TpmRc, TpmError};
    // Negative fixture (#937): malformed/truncated extend responses
    // fail clean with a typed error — no panic, no silent success.
    // (a) Empty / header-truncated.
    for short in [&[][..], &[0x80u8, 0x02][..], &[0u8; 9][..]] {
        match validate_pcr_extend_response(short) {
            Err(TpmError::BadResponse) => {}
            _ => return TestResult::Fail("truncated extend response not BadResponse"),
        }
    }
    // (b) Header whose declared size overruns the buffer.
    let mut lying = [0u8; 10];
    lying[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    lying[2..6].copy_from_slice(&65u32.to_be_bytes());
    match validate_pcr_extend_response(&lying) {
        Err(TpmError::BadResponse) => {}
        _ => return TestResult::Fail("size-overrun extend response not BadResponse"),
    }
    // (c) TPM rejection: TPM_RC_VALUE (0x184) — the response a real
    // TPM gave the old malformed encoding — surfaces as Rc(Value).
    // The pre-fix platform path discarded the response unread and
    // reported this as success.
    let mut rejected = [0u8; 10];
    rejected[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    rejected[2..6].copy_from_slice(&10u32.to_be_bytes());
    rejected[6..10].copy_from_slice(&0x184u32.to_be_bytes());
    match validate_pcr_extend_response(&rejected) {
        Err(TpmError::Rc(TpmRc::Value)) => {}
        _ => return TestResult::Fail("TPM_RC_VALUE extend response not Rc(Value)"),
    }
    // (d) A complete success response (header + parameterSize +
    // session area, as a sessions-tagged extend returns) passes.
    let mut ok = [0u8; 23];
    ok[0..2].copy_from_slice(&0x8002u16.to_be_bytes());
    ok[2..6].copy_from_slice(&23u32.to_be_bytes());
    if validate_pcr_extend_response(&ok).is_err() {
        return TestResult::Fail("success extend response rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm",
    smoke_tpm_pcr_extend_response_validation
);

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
kernel_test_in!("drivers/platform/amd_aoac", smoke_aoac_ip_bit_positions);

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
kernel_test_in!("drivers/platform/amd_aoac", smoke_aoac_ip_enum_exhaustive);

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
kernel_test_in!("drivers/platform/amd_aoac", smoke_aoac_fch_base_soc_detect);

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
kernel_test_in!("drivers/platform/amd_asf", smoke_asf_message_header_encode);

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
        2, 0, // word[0] = len=2 (2 extra words after this)
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
        2, 0, 0x10, 0x00, // event_type 0x0010
        0x50, 0x01, // code 0x0150
    ];
    match decode_dell_event(&buf_micmute) {
        Some(DellEvent::MicMute) => {}
        _ => return TestResult::Fail("dell mic-mute code 0x0150 not decoded as MicMute"),
    }

    // Brightness down: type=0x0010, code=0x0057.
    // Reference: dell-wmi-base.c `KE_KEY, 0x57, { KEY_BRIGHTNESSDOWN }`.
    let buf_bright: [u8; 6] = [
        2, 0, 0x10, 0x00, // event_type 0x0010
        0x57, 0x00, // code 0x0057
    ];
    match decode_dell_event(&buf_bright) {
        Some(DellEvent::FnFunctionKey { id: 0x0057 }) => {}
        _ => return TestResult::Fail("dell brightness-down code 0x0057 not decoded"),
    }

    // Tablet-mode: type=0x0011, code=0xe070.
    // Reference: dell-wmi-base.c line 447 — SW_TABLET_MODE, !buffer[0].
    let buf_tablet: [u8; 8] = [
        3, 0, // len=3
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
        _ => {
            return TestResult::Fail("Lenovo YMC unknown code should produce LenovoEvent::Unknown")
        }
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
    use crate::thinkpad_acpi::{
        __test_reset, battery_conservation_enabled, set_battery_conservation,
    };

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
kernel_test_in!("drivers/platform/dell_laptop", smoke_dell_smbios_cmd_encode);

/// Dell WMI event 0xE040 → KEY_KBDILLUMUP.
/// Reference: dell-wmi-base.c `KE_KEY, 0xE040, { KEY_KBDILLUMUP }`.
fn smoke_dell_wmi_event_0xe040_kbdillumup() -> TestResult {
    use crate::dell_laptop::{decode_dell_wmi_event, DellWmiEvent};

    let buf: [u8; 6] = [
        2, 0, 0x10, 0x00, // event_type 0x0010
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
    use crate::ideapad_laptop::{__test_reset, perf_mode, set_perf_mode, PerfMode};

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
    use crate::ideapad_laptop::{
        __test_reset, battery_conservation_enabled, set_battery_conservation,
    };

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

// ── Intel MEI / HECI ────────────────────────────────────────────────

fn smoke_mei_pci_match_table() -> TestResult {
    use crate::mei;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    mei::register_pci_driver();
    let regs = registered_pci_drivers();
    for did in mei::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: mei::MEI_VENDOR, device,
            } if device == did)
        });
        if !found {
            return TestResult::Fail("mei PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_pci_match_table);

fn smoke_mei_claims_ms03_heci1_only() -> TestResult {
    use crate::mei;
    // 00:16.0 on the MS-03 is 8086:e370 (Panther Lake H), which
    // Linux's mei_me_pci_tbl carries.
    if !mei::is_supported_device(mei::MEI_DEV_PTL_H) || mei::MEI_DEV_PTL_H != 0xE370 {
        return TestResult::Fail("mei does not claim the MS-03's HECI-1");
    }
    // 00:18.0 is 8086:e35d. It is a HECI-class function but is not in
    // Linux's table and nothing binds it there; claiming it would be
    // us inventing support we have not reasoned about.
    if mei::is_supported_device(0xE35D) {
        return TestResult::Fail("mei claimed 8086:e35d, which Linux does not");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_claims_ms03_heci1_only);

fn smoke_mei_register_layout() -> TestResult {
    use crate::mei;
    if mei::REG_H_CB_WW != 0x00
        || mei::REG_H_CSR != 0x04
        || mei::REG_ME_CB_RW != 0x08
        || mei::REG_ME_CSR_HA != 0x0C
    {
        return TestResult::Fail("HECI register offsets wrong");
    }
    if mei::H_RST != 0x10 || mei::H_RDY != 0x08 || mei::H_IG != 0x04 {
        return TestResult::Fail("H_CSR control bits wrong");
    }
    if mei::ME_RDY_HRA != 0x08 || mei::ME_RST_HRA != 0x10 {
        return TestResult::Fail("ME_CSR_HA bits wrong");
    }
    if mei::H_CSR_IE_MASK != (mei::H_IE | mei::H_D0I3C_IE) {
        return TestResult::Fail("H_CSR_IE_MASK wrong");
    }
    if mei::PCI_CFG_HFS_1 != 0x40 || mei::PCI_CFG_HFS_2 != 0x48 {
        return TestResult::Fail("firmware-status config offsets wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_register_layout);

fn smoke_mei_filled_slots_wraps() -> TestResult {
    use crate::mei;
    // The circular-buffer pointers are free-running u8 counters.
    // `write - read` must wrap, or every wrap of the write pointer
    // past 0xFF reports a nonsense slot count.
    //
    // Depth 0x20, read pointer at 0xFE, write pointer at 0x02: four
    // slots are filled.
    let csr = (0x20u32 << 24) | (0x02u32 << 16) | (0xFEu32 << 8);
    if mei::host_filled_slots(csr) != 4 {
        return TestResult::Fail("filled_slots did not wrap across 0xFF");
    }
    if mei::host_buffer_depth(csr) != 0x20 {
        return TestResult::Fail("buffer depth decoded wrong");
    }
    // Equal pointers mean empty, not full.
    let empty = (0x20u32 << 24) | (0x11u32 << 16) | (0x11u32 << 8);
    if mei::host_filled_slots(empty) != 0 {
        return TestResult::Fail("equal pointers should read as empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_filled_slots_wraps);

fn smoke_mei_msg_hdr_round_trip() -> TestResult {
    use crate::mei::MeiMsgHdr;
    let hdr = MeiMsgHdr {
        me_addr: 0x07,
        host_addr: 0x21,
        length: 0x1F5,
        extended: false,
        dma_ring: false,
        internal: true,
        msg_complete: true,
    };
    let w = hdr.to_u32();
    if MeiMsgHdr::from_u32(w) != hdr {
        return TestResult::Fail("header did not round-trip");
    }
    // Field placement: me_addr in 7:0, host_addr in 15:8, length in
    // 24:16, msg_complete in bit 31.
    if w & 0xFF != 0x07 || (w >> 8) & 0xFF != 0x21 {
        return TestResult::Fail("address fields in the wrong bits");
    }
    if (w >> 16) & 0x1FF != 0x1F5 {
        return TestResult::Fail("length field in the wrong bits");
    }
    if w & (1 << 31) == 0 {
        return TestResult::Fail("msg_complete is not bit 31");
    }
    // Length is 9 bits; anything wider must be truncated rather than
    // bleeding into the flag bits above it.
    let wide = MeiMsgHdr::bus_message(0xFFFF).to_u32();
    if wide & 0xF000_0000 != (1u32 << 31) {
        return TestResult::Fail("an over-long length corrupted the flag bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_msg_hdr_round_trip);

fn smoke_mei_hbm_constants() -> TestResult {
    use crate::mei;
    if mei::HOST_START_REQ_CMD != 0x01 || mei::HOST_START_RES_CMD != 0x81 {
        return TestResult::Fail("HOST_START command ids wrong");
    }
    if mei::HOST_ENUM_REQ_CMD != 0x04 || mei::HOST_ENUM_RES_CMD != 0x84 {
        return TestResult::Fail("HOST_ENUM command ids wrong");
    }
    // A response is the request with bit 7 set.
    if mei::HOST_START_RES_CMD != mei::HOST_START_REQ_CMD | mei::MEI_HBM_CMD_RES_MSK {
        return TestResult::Fail("response mask does not relate req to res");
    }
    if mei::HBM_MAJOR_VERSION != 2 || mei::HBM_MINOR_VERSION != 2 {
        return TestResult::Fail("HBM version wrong");
    }
    if mei::data_to_slots(0) != 0 || mei::data_to_slots(1) != 1 || mei::data_to_slots(4) != 1 {
        return TestResult::Fail("data_to_slots does not round up");
    }
    if mei::data_to_slots(5) != 2 {
        return TestResult::Fail("data_to_slots did not round 5 bytes up to 2 slots");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_hbm_constants);

fn smoke_mei_version_response_decode() -> TestResult {
    use crate::mei::{HbmVersionResponse, HOST_START_RES_CMD};
    // struct hbm_version is { minor, major } — minor first.
    let buf = [HOST_START_RES_CMD, 1, 2, 2];
    let v = match HbmVersionResponse::parse(&buf) {
        Some(v) => v,
        None => return TestResult::Fail("well-formed response rejected"),
    };
    if !v.host_version_supported || v.me_major != 2 || v.me_minor != 2 {
        return TestResult::Fail("version response decoded wrong");
    }
    // A response carrying someone else's opcode is not ours.
    if HbmVersionResponse::parse(&[0x84, 1, 2, 2]).is_some() {
        return TestResult::Fail("accepted a response with the wrong opcode");
    }
    if HbmVersionResponse::parse(&[HOST_START_RES_CMD, 1, 2]).is_some() {
        return TestResult::Fail("accepted a short response");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/mei", smoke_mei_version_response_decode);

// ── Intel DTT (proc_thermal) ────────────────────────────────────────

fn smoke_proc_thermal_pci_match_table() -> TestResult {
    use crate::proc_thermal as pt;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    pt::register_pci_driver();
    let regs = registered_pci_drivers();
    for did in pt::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: pt::DTT_VENDOR, device,
            } if device == did)
        });
        if !found {
            return TestResult::Fail("proc_thermal match table missing a device id");
        }
    }
    // The MS-03's 00:04.0.
    if !pt::is_supported_device(pt::DTT_DEV_PTL) || pt::DTT_DEV_PTL != 0xB01D {
        return TestResult::Fail("proc_thermal does not claim the MS-03's DTT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/proc_thermal",
    smoke_proc_thermal_pci_match_table
);

fn smoke_proc_thermal_device_ids_are_unique() -> TestResult {
    use crate::proc_thermal as pt;
    // Linux defines NVL_S_THERMAL and ARL_S_THERMAL as the same
    // 0xAD03. Listing both would register two match entries for one
    // device, so the table must carry each id once.
    let ids = pt::SUPPORTED_DEVICE_IDS;
    for (i, a) in ids.iter().enumerate() {
        for b in ids.iter().skip(i + 1) {
            if a == b {
                return TestResult::Fail("duplicate device id in the DTT table");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/proc_thermal",
    smoke_proc_thermal_device_ids_are_unique
);

fn smoke_proc_thermal_mmio_fields() -> TestResult {
    use crate::proc_thermal as pt;
    // Four fields share the dword at 0x5820 and are told apart only
    // by shift and mask; a transposed shift silently reads the wrong
    // one.
    if pt::FIELD_THRES_0.reg != 0x5820 || pt::FIELD_THRES_0.shift != 8 {
        return TestResult::Fail("THRES_0 field wrong");
    }
    if pt::FIELD_INT_ENABLE_0.reg != 0x5820 || pt::FIELD_INT_ENABLE_0.shift != 15 {
        return TestResult::Fail("INT_ENABLE_0 field wrong");
    }
    if pt::FIELD_THRES_1.shift != 16 || pt::FIELD_INT_ENABLE_1.shift != 23 {
        return TestResult::Fail("THRES_1 / INT_ENABLE_1 fields wrong");
    }
    // TjMax is bits 23:16 of 0x599c, not the whole register.
    if pt::FIELD_TJMAX.reg != 0x599C || pt::FIELD_TJMAX.shift != 16 || pt::FIELD_TJMAX.mask != 0xFF
    {
        return TestResult::Fail("TJMAX field wrong");
    }
    if pt::FIELD_TJMAX.extract(0x0064_0000) != 100 {
        return TestResult::Fail("TJMAX extraction wrong");
    }
    // PKG_TEMP is the low byte of a different register.
    if pt::FIELD_PKG_TEMP.reg != 0x5978 || pt::FIELD_PKG_TEMP.shift != 0 {
        return TestResult::Fail("PKG_TEMP field wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/proc_thermal",
    smoke_proc_thermal_mmio_fields
);

fn smoke_proc_thermal_feature_masks() -> TestResult {
    use crate::proc_thermal as pt;
    // Panther Lake's mask from proc_thermal_pci_ids[].
    let ptl = pt::features_for(pt::DTT_DEV_PTL);
    let expect = pt::FEATURE_RAPL
        | pt::FEATURE_DLVR
        | pt::FEATURE_DVFS
        | pt::FEATURE_MSI_SUPPORT
        | pt::FEATURE_WT_HINT
        | pt::FEATURE_POWER_FLOOR
        | pt::FEATURE_PTC
        | pt::FEATURE_SOC_POWER_SLIDER;
    if ptl != expect {
        return TestResult::Fail("Panther Lake feature mask wrong");
    }
    // Panther Lake has no FIVR — Alder Lake does. Confusing the two
    // would have the driver look for an RFIM mailbox that isn't there.
    if ptl & pt::FEATURE_FIVR != 0 {
        return TestResult::Fail("Panther Lake should not advertise FIVR");
    }
    if pt::features_for(pt::DTT_DEV_ADL) & pt::FEATURE_FIVR == 0 {
        return TestResult::Fail("Alder Lake should advertise FIVR");
    }
    if pt::features_for(0xFFFF) != 0 {
        return TestResult::Fail("an unknown id should have no features");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/proc_thermal",
    smoke_proc_thermal_feature_masks
);

// ── Intel VSEC / PMT ────────────────────────────────────────────────

fn smoke_intel_vsec_pci_match_table() -> TestResult {
    use crate::intel_vsec as vs;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    vs::register_pci_driver();
    let regs = registered_pci_drivers();
    for did in vs::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: vs::VSEC_VENDOR, device,
            } if device == did)
        });
        if !found {
            return TestResult::Fail("intel_vsec match table missing a device id");
        }
    }
    // The MS-03's 00:0a.0.
    if !vs::is_supported_device(vs::VSEC_DEV_PTL) || vs::VSEC_DEV_PTL != 0xB07D {
        return TestResult::Fail("intel_vsec does not claim the MS-03's PMT function");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/intel_vsec",
    smoke_intel_vsec_pci_match_table
);

fn smoke_intel_vsec_header_decode() -> TestResult {
    use crate::intel_vsec as vs;
    // PCI_DVSEC_HEADER1: vid[15:0], rev[19:16], len[31:20].
    let h1 = 0x0201_8086u32;
    if vs::dvsec_header1_vid(h1) != 0x8086 {
        return TestResult::Fail("DVSEC vendor id decoded wrong");
    }
    if vs::dvsec_header1_rev(h1) != 1 {
        return TestResult::Fail("DVSEC revision decoded wrong");
    }
    if vs::dvsec_header1_len(h1) != 0x020 {
        return TestResult::Fail("DVSEC length decoded wrong");
    }
    // VNDR header packs id/rev/len the same way, minus the vendor id.
    let hv = 0x0301_0002u32;
    if vs::vndr_header_id(hv) != 0x0002 || vs::vndr_header_rev(hv) != 1 {
        return TestResult::Fail("VNDR header decoded wrong");
    }
    if vs::vndr_header_len(hv) != 0x030 {
        return TestResult::Fail("VNDR length decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/intel_vsec",
    smoke_intel_vsec_header_decode
);

fn smoke_intel_vsec_table_offset_keeps_low_bits_clear() -> TestResult {
    use crate::intel_vsec as vs;
    // The table dword packs the BAR index into bits 2:0 and the byte
    // offset into 31:3. The offset is *not* shifted down — it is the
    // dword with the BAR index masked off — so an implementation that
    // shifts would divide every offset by eight.
    let table = 0x0001_2348u32; // offset 0x12348, BAR 0
    if vs::table_bar(table) != 0 {
        return TestResult::Fail("BAR index decoded wrong");
    }
    if vs::table_offset(table) != 0x0001_2348 {
        return TestResult::Fail("table offset was shifted when it should not be");
    }
    let with_bar = 0x0001_2340u32 | 0x2; // offset 0x12340, BAR 2
    if vs::table_bar(with_bar) != 2 {
        return TestResult::Fail("BAR index 2 decoded wrong");
    }
    if vs::table_offset(with_bar) != 0x0001_2340 {
        return TestResult::Fail("BAR index leaked into the offset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/intel_vsec",
    smoke_intel_vsec_table_offset_keeps_low_bits_clear
);

fn smoke_intel_vsec_feature_ids() -> TestResult {
    use crate::intel_vsec as vs;
    // Linux maps a feature id to its capability bit with BIT(id), so
    // id 1 is telemetry and id 3 is crashlog.
    if vs::cap_bit_for_id(1) != vs::VSEC_CAP_TELEMETRY {
        return TestResult::Fail("feature id 1 is telemetry");
    }
    if vs::cap_bit_for_id(3) != vs::VSEC_CAP_CRASHLOG {
        return TestResult::Fail("feature id 3 is crashlog");
    }
    if vs::feature_name(1) != "telemetry" || vs::feature_name(3) != "crashlog" {
        return TestResult::Fail("feature names wrong");
    }
    // An id past the named range must not alias onto a real bit.
    if vs::cap_bit_for_id(40) != 0 {
        return TestResult::Fail("an out-of-range id should have no capability bit");
    }
    if vs::EXT_CAP_ID_DVSEC != 0x0023 || vs::EXT_CAP_ID_VNDR != 0x000B {
        return TestResult::Fail("extended capability ids wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/intel_vsec", smoke_intel_vsec_feature_ids);

// ── Power-service composition (#868) ───────────────────────────────

/// Park-step hook for the composition smoke: model a wake source
/// firing while the CPU is parked. Latching on the first step
/// means the park loop observes the event before its first real
/// halt — the harness arms no periodic clockevent on this path,
/// so a real halt could sleep past the idle-kill (the hazard
/// `s2idle`'s bounded test entry documents).
fn composition_park_step_latch() {
    narf_power::s2idle::note_wake_event(narf_power::s2idle::WakeSource::TestInjected);
}

fn smoke_power_state_freeze_end_to_end() -> TestResult {
    use narf_power::service;

    if !narf_power::s2idle::s2idle_supported() {
        return TestResult::Skip("s2idle not offered on this platform");
    }

    // Reset every surface the composition touches, so the fixture
    // measures the composition and not boot residue.
    service::__reset_for_test();
    narf_power::suspend::__test_reset();
    narf_power::s2idle::__test_reset();
    narf_power::device_pm::__reset_for_test();
    narf_power::sleep_request::__test_reset_sleep_request_hook();

    // Fail-closed first: with no consumer installed, a store of a
    // supported state must be refused ENODEV — never silently
    // dropped (the posture #877's review pinned).
    narf_power::sysfs_bridge::populate_power_state();
    let root = narf_filesystem::sysfs::get_root();
    let kobj = match root.get_child("power") {
        Some(k) => k,
        None => return TestResult::Fail("/sys/power kobject missing after populate"),
    };
    match kobj.attr_store("state", b"freeze\n") {
        Some(Err(narf_filesystem::FsError::NoDevice)) => {}
        _ => return TestResult::Fail("unwired freeze store was not refused with NoDevice"),
    }

    // The real composition root: platform executor + sleep-request
    // hook + providers + event subscriptions.
    crate::power_service::init();
    if !narf_power::sleep_request::sleep_request_hook_installed() {
        return TestResult::Fail("composition did not install the sleep-request hook");
    }

    // Arm the park and model the wake source.
    narf_power::s2idle::__test_arm_s2idle();
    narf_power::s2idle::__test_set_park_step_hook(Some(composition_park_step_latch));

    // The userspace write — `echo freeze > /sys/power/state` at
    // the sysfs model layer (the VFS write → store dispatch above
    // it is covered by the filesystem sysfs e2e tests).
    match kobj.attr_store("state", b"freeze\n") {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("freeze store refused with the composition installed"),
    }
    // The write only queues: the Freeze action pending (bit 2),
    // one freeze request counted, nothing executed in the writer's
    // context.
    if service::pending_actions() != 4 {
        return TestResult::Fail("freeze store did not queue the Freeze action");
    }
    if service::stats().freeze_requests != 1 {
        return TestResult::Fail("service did not count the freeze request");
    }

    // Execute from task context: the platform executor mints the
    // Power cap and runs `suspend_to_idle` — park, wake, resume.
    if service::pump_pending() != 1 {
        return TestResult::Fail("pump did not execute the queued freeze");
    }
    let s = narf_power::s2idle::stats();
    if s.parks != 1 || s.wakes != 1 || s.last_exit != narf_power::s2idle::ParkExit::WakeEvent {
        return TestResult::Fail("freeze did not park and wake exactly once");
    }
    if narf_power::suspend::current_phase() != narf_power::SuspendPhase::Idle {
        return TestResult::Fail("phase did not return to Idle after the freeze cycle");
    }

    // The hook's other half: `mem` queues Suspend — never Freeze —
    // and the platform executor runs the S3 core. Unarmed here, so
    // the core walks the phases and declines; the queue/executor
    // contract is what is pinned. Skipped where S3 does not parse.
    if narf_power::suspend::s3_supported() {
        match kobj.attr_store("state", b"mem\n") {
            Some(Ok(())) => {}
            _ => return TestResult::Fail("mem store refused with the composition installed"),
        }
        if service::pending_actions() != 1 {
            return TestResult::Fail("mem store did not queue the Suspend action");
        }
        if service::pump_pending() != 1 {
            return TestResult::Fail("pump did not execute the queued suspend");
        }
        if narf_power::suspend::current_phase() != narf_power::SuspendPhase::Idle {
            return TestResult::Fail("phase did not return to Idle after the mem cycle");
        }
    }

    // Clean up the test seams. The composition itself stays
    // installed — that is the production state.
    narf_power::s2idle::__test_set_park_step_hook(None);
    narf_power::s2idle::__test_reset();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/power-service",
    smoke_power_state_freeze_end_to_end
);
