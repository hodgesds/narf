//! Subsystem smokes for `narf-drivers-gpio`.
//!
//! Synthetic MMIO backing for both drivers:
//! - AMD FCH — exercises per-pin register programming, handler-table
//!   bookkeeping, and the shared ISR dispatch loop.
//! - Intel PCH (Stage-0) — exercises HID-list coverage, REVID/PADBAR
//!   decode against a hand-rolled backing, the stub GpioController
//!   surface, and the shared-registry integration.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::PhysAddr;

use crate::amd_fch::{
    recognised_hid, AmdFchGpio, __dispatch_for_test, __reset_dispatch_for_test,
};
use crate::intel_pch::{
    recognised_hids as intel_recognised_hids, IntelPchGpio, __new_for_test as intel_new_for_test,
    __probe_community_for_test as intel_probe_community,
};
use crate::{registry, GpioController, GpioError, GpioIrqConfig, GpioPull};

/// Allocate a 1 KiB zeroed MMIO backing buffer (256 pin registers).
/// Leak it so the synthetic device outlives the smoke.
fn make_synthetic_mmio() -> (PhysAddr, u64) {
    let buf: Box<[u32; 256]> = Box::new([0u32; 256]);
    let raw = Box::leak(buf);
    (PhysAddr::new(raw.as_ptr() as u64), 1024)
}

fn smoke_gpio_recognises_amdi0030() -> TestResult {
    if recognised_hid() != "AMDI0030" {
        return TestResult::Fail("AMDI0030 should be the recognised HID");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_gpio_recognises_amdi0030);

fn smoke_gpio_registry_dedupes_by_name() -> TestResult {
    registry::__reset_for_test();
    let (p, l) = make_synthetic_mmio();
    let a: Arc<dyn GpioController> = Arc::new(AmdFchGpio::new("dup".to_string(), p, l, None));
    let b: Arc<dyn GpioController> = Arc::new(AmdFchGpio::new("dup".to_string(), p, l, None));
    let r1 = registry::register_unique(a);
    let r2 = registry::register_unique(b);
    if !Arc::ptr_eq(&r1, &r2) {
        return TestResult::Fail("dedupe should return the existing Arc");
    }
    if registry::count() != 1 {
        return TestResult::Fail("dedupe should leave count at 1");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_gpio_registry_dedupes_by_name);

fn smoke_gpio_pin_count_derived_from_mmio_len() -> TestResult {
    // 0x100 bytes = 64 pins.
    let buf: Box<[u32; 64]> = Box::new([0u32; 64]);
    let raw = Box::leak(buf);
    let drv = AmdFchGpio::new(
        "small".to_string(),
        PhysAddr::new(raw.as_ptr() as u64),
        256,
        None,
    );
    if drv.pin_count() != 64 {
        return TestResult::Fail("pin_count should be mmio_len/4");
    }
    if drv.read_pin(64).err() != Some(GpioError::InvalidPin) {
        return TestResult::Fail("pin 64 (out of range) should be InvalidPin");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_gpio_pin_count_derived_from_mmio_len);

fn smoke_gpio_set_pin_requires_output_enable() -> TestResult {
    let (p, l) = make_synthetic_mmio();
    let drv = AmdFchGpio::new("noout".to_string(), p, l, None);
    // Pin register starts as 0 → bit 23 (Output Enable) clear → set
    // must refuse with WrongDirection.
    match drv.set_pin(7, true) {
        Err(GpioError::WrongDirection) => {}
        _ => return TestResult::Fail("set_pin should refuse without OE"),
    }
    // Manually flip Output Enable in the synthetic backing so set_pin
    // can succeed.
    let base = p.raw() as *mut u32;
    unsafe {
        core::ptr::write_volatile(base.add(7), 1u32 << 23);
    }
    if drv.set_pin(7, true).is_err() {
        return TestResult::Fail("set_pin should succeed once OE bit is set");
    }
    let v = unsafe { core::ptr::read_volatile(base.add(7)) };
    if v & (1 << 22) == 0 {
        return TestResult::Fail("Output Value bit didn't get set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_gpio_set_pin_requires_output_enable);

fn smoke_gpio_read_pin_reports_status_bit() -> TestResult {
    let (p, l) = make_synthetic_mmio();
    let drv = AmdFchGpio::new("read".to_string(), p, l, None);
    let base = p.raw() as *mut u32;
    // Set PinSts (bit 16) on pin 3.
    unsafe {
        core::ptr::write_volatile(base.add(3), 1u32 << 16);
    }
    match drv.read_pin(3) {
        Ok(true) => {}
        _ => return TestResult::Fail("PinSts=1 should read true"),
    }
    unsafe {
        core::ptr::write_volatile(base.add(3), 0);
    }
    match drv.read_pin(3) {
        Ok(false) => TestResult::Pass,
        _ => TestResult::Fail("PinSts=0 should read false"),
    }
}
kernel_test_in!("drivers-gpio", smoke_gpio_read_pin_reports_status_bit);

fn smoke_gpio_register_irq_programs_pin_register() -> TestResult {
    __reset_dispatch_for_test();
    let (p, l) = make_synthetic_mmio();
    let drv = AmdFchGpio::new("regirq".to_string(), p, l, None);
    fn dummy(_pin: u16) {}
    let r = drv.register_irq(
        17,
        GpioPull::Up,
        GpioIrqConfig {
            level_triggered: false,
            polarity: 1, // active low
        },
        dummy,
    );
    if r.is_err() {
        return TestResult::Fail("register_irq returned error");
    }
    let base = p.raw() as *const u32;
    let v = unsafe { core::ptr::read_volatile(base.add(17)) };
    // Should have INTR_ENABLE (28) + INTR_DELIVERY (29) + PULL_UP (19) + INTR_STATUS clear-write (11)
    if v & (1 << 28) == 0 || v & (1 << 29) == 0 {
        return TestResult::Fail("interrupt enable/delivery bits not set");
    }
    if v & (1 << 19) == 0 {
        return TestResult::Fail("pull-up bit not set");
    }
    // edge + active-low: TRIGGER_LEVEL=0, ACTIVE_HIGH=0
    if v & (1 << 9) != 0 {
        return TestResult::Fail("expected edge trigger (bit 9 = 0)");
    }
    if v & (1 << 10) != 0 {
        return TestResult::Fail("expected active-low (bit 10 = 0)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_gpio_register_irq_programs_pin_register);

fn smoke_gpio_register_irq_rejects_conflicting_handler() -> TestResult {
    __reset_dispatch_for_test();
    let (p, l) = make_synthetic_mmio();
    let drv = AmdFchGpio::new("conflict".to_string(), p, l, None);
    fn h1(_p: u16) {}
    fn h2(_p: u16) {}
    let cfg = GpioIrqConfig {
        level_triggered: true,
        polarity: 0,
    };
    drv.register_irq(5, GpioPull::None, cfg, h1).unwrap();
    // Same handler again — idempotent.
    if drv.register_irq(5, GpioPull::None, cfg, h1).is_err() {
        return TestResult::Fail("re-register with same handler should succeed");
    }
    // Different handler — refuse.
    match drv.register_irq(5, GpioPull::None, cfg, h2) {
        Err(GpioError::AlreadyRegistered) => TestResult::Pass,
        _ => TestResult::Fail("conflicting handler should be rejected"),
    }
}
kernel_test_in!(
    "drivers-gpio",
    smoke_gpio_register_irq_rejects_conflicting_handler
);

fn smoke_gpio_unregister_irq_clears_bits() -> TestResult {
    __reset_dispatch_for_test();
    let (p, l) = make_synthetic_mmio();
    let drv = AmdFchGpio::new("unreg".to_string(), p, l, None);
    fn dummy(_pin: u16) {}
    drv.register_irq(
        9,
        GpioPull::Down,
        GpioIrqConfig {
            level_triggered: true,
            polarity: 0,
        },
        dummy,
    )
    .unwrap();
    drv.unregister_irq(9);
    let base = p.raw() as *const u32;
    let v = unsafe { core::ptr::read_volatile(base.add(9)) };
    if v & (1 << 28) != 0 || v & (1 << 29) != 0 {
        return TestResult::Fail("interrupt bits should be cleared after unregister");
    }
    // Re-registering a different handler should now succeed.
    fn other(_pin: u16) {}
    let r = drv.register_irq(
        9,
        GpioPull::Down,
        GpioIrqConfig {
            level_triggered: true,
            polarity: 0,
        },
        other,
    );
    if r.is_err() {
        return TestResult::Fail("re-register after unregister should succeed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_gpio_unregister_irq_clears_bits);

static FIRE_COUNT: AtomicU32 = AtomicU32::new(0);
static FIRE_PIN: AtomicU32 = AtomicU32::new(u32::MAX);
fn fire_handler(pin: u16) {
    FIRE_COUNT.fetch_add(1, Ordering::SeqCst);
    FIRE_PIN.store(pin as u32, Ordering::SeqCst);
}

fn smoke_gpio_isr_dispatch_fires_handler_and_clears_status() -> TestResult {
    __reset_dispatch_for_test();
    registry::__reset_for_test();
    FIRE_COUNT.store(0, Ordering::SeqCst);
    FIRE_PIN.store(u32::MAX, Ordering::SeqCst);

    let (p, l) = make_synthetic_mmio();
    let drv: Arc<dyn GpioController> = Arc::new(AmdFchGpio::new("isr".to_string(), p, l, None));
    let _ = registry::register_unique(drv.clone());

    drv.register_irq(
        42,
        GpioPull::None,
        GpioIrqConfig {
            level_triggered: false,
            polarity: 0,
        },
        fire_handler,
    )
    .unwrap();

    // Set the pin's INTR_STATUS bit (11) by hand, then drive the
    // shared ISR. Synthetic backing doesn't model RW1C, so we
    // manually clear the bit between dispatches to simulate what
    // real hardware does in response to the driver's write-back.
    let base = p.raw() as *mut u32;
    let prev = unsafe { core::ptr::read_volatile(base.add(42)) };
    unsafe {
        core::ptr::write_volatile(base.add(42), prev | (1 << 11));
    }

    __dispatch_for_test();

    if FIRE_COUNT.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("handler should have fired exactly once");
    }
    if FIRE_PIN.load(Ordering::SeqCst) != 42 {
        return TestResult::Fail("handler should have received pin 42");
    }

    // Simulate hardware RW1C: clear bit 11 in the backing buffer.
    let after = unsafe { core::ptr::read_volatile(base.add(42)) };
    unsafe {
        core::ptr::write_volatile(base.add(42), after & !(1 << 11));
    }
    // Now a re-dispatch with no pending status must not fire.
    __dispatch_for_test();
    if FIRE_COUNT.load(Ordering::SeqCst) != 1 {
        return TestResult::Fail("handler fired again with no pending status");
    }
    registry::__reset_for_test();
    __reset_dispatch_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "drivers-gpio",
    smoke_gpio_isr_dispatch_fires_handler_and_clears_status
);

// ── Intel PCH GPIO Stage-0 smokes ──────────────────────────────────

/// Build a backing buffer large enough for one Intel PCH GPIO
/// community. Seeds REVID + PADBAR + (optionally) the GPIO HW INFO
/// caplist entry. Returns (phys, len, padbar_offset, has_debounce,
/// expected_pad_count).
fn make_intel_synthetic_mmio(
    rev: u32,
    padbar_off: u32,
    window_dwords: usize,
) -> (PhysAddr, u64, u32, bool, u16) {
    assert!(window_dwords * 4 > padbar_off as usize);
    let buf = alloc::vec![0u32; window_dwords].into_boxed_slice();
    let raw: &'static mut [u32] = Box::leak(buf);
    // REVID lives at offset 0x000 — top 16 bits = revision, low 16 = 0.
    raw[0] = (rev & 0xFFFF) << 16;
    // CAPLIST at 0x004 → empty chain (next=0, id=0).
    raw[1] = 0;
    // PADBAR at 0x00C → byte offset of pad config registers.
    raw[3] = padbar_off;
    let phys = PhysAddr::new(raw.as_ptr() as u64);
    let len = (window_dwords * 4) as u64;
    let has_debounce = rev >= 0x94;
    let pad_stride = if has_debounce { 16 } else { 8 };
    let pad_region = len - padbar_off as u64;
    let pad_count = (pad_region / pad_stride).min(u16::MAX as u64) as u16;
    (phys, len, padbar_off, has_debounce, pad_count)
}

fn smoke_intel_pch_recognises_bringup_hids() -> TestResult {
    // The bring-up target group covers Tiger Lake → Meteor Lake.
    // Guard against the table getting trimmed for any of them.
    for required in [
        "INT34BB", // Tiger Lake
        "INT3450", // Comet Lake / Cannon Lake-LP
        "INT34C8", // Raptor Lake-S
        "INT34C9", // Raptor Lake-P / Alder Lake-P
        "INT37FF", // Meteor Lake
        "INT3454", // Cannon Lake LP
        "INT3452", // Apollo Lake
    ] {
        if !intel_recognised_hids().iter().any(|h| *h == required) {
            return TestResult::Fail("required Intel PCH GPIO HID missing from list");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_intel_pch_recognises_bringup_hids);

fn smoke_intel_pch_probe_decodes_revid_padbar_pads_with_debounce() -> TestResult {
    // Tiger Lake / Alder Lake / Raptor Lake all report revisions
    // ≥ 0x94 → 4-dword pad stride (PADCFG0/1/2 + reserved).
    // Build a synthetic window: 4 KiB total, PADBAR=0x80 → 0xF80
    // bytes of pad region → 248 pads.
    let (phys, len, padbar, has_debounce, expected_pads) =
        make_intel_synthetic_mmio(0x94, 0x80, 1024);
    if !has_debounce {
        return TestResult::Fail("debounce feature should be on for rev 0x94");
    }
    // SAFETY: synthetic backing owned for the lifetime of the test.
    let probed = unsafe { intel_probe_community(phys, len) };
    match probed {
        Some((revid, pb, deb, pads)) => {
            if revid != 0x94 {
                return TestResult::Fail("decoded REVID wrong");
            }
            if pb != padbar {
                return TestResult::Fail("decoded PADBAR wrong");
            }
            if !deb {
                return TestResult::Fail("decoded debounce flag wrong");
            }
            if pads != expected_pads {
                return TestResult::Fail("decoded pad count wrong");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("probe rejected a healthy synthetic backing"),
    }
}
kernel_test_in!(
    "drivers-gpio",
    smoke_intel_pch_probe_decodes_revid_padbar_pads_with_debounce
);

fn smoke_intel_pch_probe_decodes_pads_without_debounce() -> TestResult {
    // Older silicon (rev < 0x94) → 2-dword pad stride.
    let (phys, len, padbar, has_debounce, expected_pads) =
        make_intel_synthetic_mmio(0x12, 0x40, 512);
    if has_debounce {
        return TestResult::Fail("debounce should be off for rev 0x12");
    }
    // SAFETY: synthetic backing.
    let probed = unsafe { intel_probe_community(phys, len) };
    match probed {
        Some((_, _, deb, pads)) => {
            if deb {
                return TestResult::Fail("debounce flag should be false");
            }
            if pads != expected_pads {
                return TestResult::Fail("pad count wrong for non-debounce stride");
            }
            // Sanity: pad region = 0x800 - 0x40 = 0x7C0 = 1984
            // bytes; stride 8 → 248 pads.
            let _ = padbar;
            TestResult::Pass
        }
        None => TestResult::Fail("probe rejected a healthy synthetic backing"),
    }
}
kernel_test_in!(
    "drivers-gpio",
    smoke_intel_pch_probe_decodes_pads_without_debounce
);

fn smoke_intel_pch_probe_rejects_absent_device() -> TestResult {
    // REVID reads all-ones → device-absent sentinel. Probe must
    // bail with None rather than registering a zombie controller.
    let buf = alloc::vec![u32::MAX; 256].into_boxed_slice();
    let raw: &'static mut [u32] = Box::leak(buf);
    let phys = PhysAddr::new(raw.as_ptr() as u64);
    // SAFETY: synthetic backing.
    match unsafe { intel_probe_community(phys, 1024) } {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("probe accepted REVID=~0u"),
    }
}
kernel_test_in!("drivers-gpio", smoke_intel_pch_probe_rejects_absent_device);

fn smoke_intel_pch_probe_rejects_bogus_padbar() -> TestResult {
    // PADBAR points back into the common-register area (< 0x10)
    // → mapping is wrong. Probe must reject.
    let buf = alloc::vec![0u32; 256].into_boxed_slice();
    let raw: &'static mut [u32] = Box::leak(buf);
    raw[0] = 0x0094_0000; // REVID = 0x94 (looks healthy)
    raw[3] = 0x04; // PADBAR = 0x04 (overlaps CAPLIST → bogus)
    let phys = PhysAddr::new(raw.as_ptr() as u64);
    // SAFETY: synthetic backing.
    match unsafe { intel_probe_community(phys, 1024) } {
        None => TestResult::Pass,
        Some(_) => TestResult::Fail("probe accepted PADBAR pointing into common regs"),
    }
}
kernel_test_in!("drivers-gpio", smoke_intel_pch_probe_rejects_bogus_padbar);

fn smoke_intel_pch_stage0_gpio_ops_return_bad_hardware() -> TestResult {
    // Stage-0 contract: read_pin / set_pin / register_irq all return
    // BadHardware. unregister_irq is a silent no-op. This locks the
    // contract so we notice if the stub silently grows behaviour
    // before Stage-1 lands.
    let drv = intel_new_for_test(
        "\\_SB.PC00.GPI0".to_string(),
        0,
        PhysAddr::new(0xFFC0_0000),
        0x1000,
        Some(0x94),
        Some(0x80),
        128,
        true,
    );
    if drv.pin_count() != 128 {
        return TestResult::Fail("pin_count getter wrong");
    }
    if drv.has_debounce() != true {
        return TestResult::Fail("has_debounce getter wrong");
    }
    if drv.read_pin(0).err() != Some(GpioError::BadHardware) {
        return TestResult::Fail("read_pin should return BadHardware in Stage-0");
    }
    if drv.set_pin(0, true).err() != Some(GpioError::BadHardware) {
        return TestResult::Fail("set_pin should return BadHardware in Stage-0");
    }
    fn dummy(_p: u16) {}
    let cfg = GpioIrqConfig {
        level_triggered: false,
        polarity: 1,
    };
    if drv.register_irq(0, GpioPull::Up, cfg, dummy).err() != Some(GpioError::BadHardware) {
        return TestResult::Fail("register_irq should return BadHardware in Stage-0");
    }
    drv.unregister_irq(0); // no-op; just verify it doesn't panic
    TestResult::Pass
}
kernel_test_in!(
    "drivers-gpio",
    smoke_intel_pch_stage0_gpio_ops_return_bad_hardware
);

fn smoke_intel_pch_names_communities_uniquely() -> TestResult {
    // Two communities under the same ACPI path must get distinct
    // registry names so i2c-hid-bind can address them separately —
    // the per-community suffix (`.C<idx>`) keys the dedupe.
    registry::__reset_for_test();
    let phys = PhysAddr::new(0xFFC0_0000);
    let a: Arc<dyn GpioController> = Arc::new(intel_new_for_test(
        "\\_SB.PC00.GPI0".to_string(),
        0,
        phys,
        0x1000,
        Some(0x94),
        Some(0x80),
        128,
        true,
    ));
    let b: Arc<dyn GpioController> = Arc::new(intel_new_for_test(
        "\\_SB.PC00.GPI0".to_string(),
        1,
        PhysAddr::new(0xFFC0_1000),
        0x1000,
        Some(0x94),
        Some(0x80),
        128,
        true,
    ));
    registry::register_unique(a.clone());
    registry::register_unique(b.clone());
    if registry::count() != 2 {
        return TestResult::Fail("expected 2 distinct community entries");
    }
    if registry::find("\\_SB.PC00.GPI0.C0").is_none() {
        return TestResult::Fail("community C0 not in registry");
    }
    if registry::find("\\_SB.PC00.GPI0.C1").is_none() {
        return TestResult::Fail("community C1 not in registry");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_intel_pch_names_communities_uniquely);

fn smoke_intel_pch_registers_into_shared_registry() -> TestResult {
    // Whole point of Stage-0: an IntelPchGpio community, once
    // registered, is discoverable through the SAME registry the
    // FCH driver uses — i2c-hid-bind looks up
    // `GpioInt::resource_source` against `registry::find` without
    // knowing or caring which backend populated the entry.
    registry::__reset_for_test();
    let drv = intel_new_for_test(
        "\\_SB.PC00.GPI3".to_string(),
        2,
        PhysAddr::new(0xFFC0_3000),
        0x1000,
        Some(0xA1),
        Some(0xC0),
        80,
        true,
    );
    let bus: Arc<dyn GpioController> = Arc::new(drv);
    registry::register_unique(bus.clone());
    if registry::count() != 1 {
        return TestResult::Fail("Intel PCH community didn't land in registry");
    }
    let found = registry::find("\\_SB.PC00.GPI3.C2");
    if found.is_none() {
        return TestResult::Fail("Intel PCH community not findable by name");
    }
    // Type-erase + assert it implements GpioController as expected.
    if let Some(c) = found {
        if c.pin_count() != 80 {
            return TestResult::Fail("registry lookup returned wrong controller");
        }
    }
    registry::__reset_for_test();
    let _ = IntelPchGpio::new(
        "smoke".to_string(),
        0,
        PhysAddr::new(0),
        0,
        None,
        None,
        0,
        false,
    );
    TestResult::Pass
}
kernel_test_in!("drivers-gpio", smoke_intel_pch_registers_into_shared_registry);
