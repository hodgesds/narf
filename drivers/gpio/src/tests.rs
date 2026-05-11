//! Subsystem smokes for `narf-drivers-gpio`.
//!
//! Synthetic MMIO backing for the AMD FCH driver — exercises the
//! per-pin register programming, handler-table bookkeeping, and the
//! shared ISR dispatch loop without needing a real FCH GPIO block.

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
