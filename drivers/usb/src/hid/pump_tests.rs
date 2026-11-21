//! The HID input pumps run each binding with the per-controller
//! registry unlocked. Its lock is IRQ-safe: holding it across a
//! binding's pump kept interrupts off on CPU0 for the whole event-ring
//! drain (`poll_interrupt_in`), the input routing of every report and
//! the pump's console notes.
use super::pump_unlocked;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

static REGISTRY: IrqSafeSpinLock<Vec<u8>> = IrqSafeSpinLock::new(Vec::new());

/// Every binding is pumped once, in order, with the registry lock free
/// (interrupts stay enabled); a binding added mid-pass (the supervisor
/// binds between pumps) is kept, after the pumped ones.
fn smoke_hid_pump_runs_bindings_with_registry_unlocked() -> TestResult {
    REGISTRY.lock().extend([1u8, 2, 3]);
    let mut unlocked = 0;
    let mut irqs_on = 0;
    let mut visited = Vec::new();
    pump_unlocked(&REGISTRY, |binding| {
        if let Some(mut g) = REGISTRY.try_lock() {
            unlocked += 1;
            if *binding == 2 {
                g.push(9);
            }
        }
        if narf_arch::interrupts_enabled() {
            irqs_on += 1;
        }
        visited.push(*binding);
    });
    let after: Vec<u8> = core::mem::take(&mut *REGISTRY.lock());
    if visited != [1, 2, 3] {
        return TestResult::Fail("a binding was skipped or pumped twice");
    }
    if unlocked != 3 {
        return TestResult::Fail("the registry lock was held across a binding's pump");
    }
    if after != [1, 2, 3, 9] {
        return TestResult::Fail("bindings were lost or reordered by the pump pass");
    }
    // The kernel-test harness itself may run with interrupts masked;
    // what the pump must not do is mask them on its own.
    if narf_arch::interrupts_enabled() && irqs_on != 3 {
        return TestResult::Fail("a binding was pumped with interrupts masked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/hid/pump",
    smoke_hid_pump_runs_bindings_with_registry_unlocked
);
