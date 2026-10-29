use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

#[cfg(target_arch = "x86_64")]
fn route(gsi: u32) -> Option<(u8, u32)> {
    // SAFETY: kernel tests run after MADT/IOAPIC initialization.
    unsafe { narf_acpi::ioapic::gsi_route(gsi) }.map(|(vector, _, low)| (vector, low))
}

#[cfg(target_arch = "x86_64")]
fn smoke_oneshot_intx_masks_on_delivery_and_unmasks_after_service() -> TestResult {
    use narf_acpi::ioapic::{MASKED, POLARITY_LOW, TRIGGER_LEVEL};
    // An unused (still masked) PCI-range GSI on the test machine.
    let Some(gsi) = (16..24).find(|&g| route(g).is_some_and(|(_, low)| low & MASKED != 0)) else {
        return TestResult::Skip("no free IOAPIC GSI");
    };
    use core::sync::atomic::AtomicU32;
    static WAKES: AtomicU32 = AtomicU32::new(0);
    WAKES.store(0, Ordering::Release);
    let notify: Notify = Arc::new(|| {
        WAKES.fetch_add(1, Ordering::AcqRel);
    });
    // SAFETY: test owns the chosen unused GSI.
    let line = match unsafe { Line::bind_exclusive(gsi, "oneshot-test", notify) } {
        Ok(line) => line,
        Err(_) => return TestResult::Fail("free GSI did not bind"),
    };
    let level_low = POLARITY_LOW | TRIGGER_LEVEL;
    match route(gsi) {
        Some((vector, low))
            if vector == line.vector() && low & (level_low | MASKED) == level_low | MASKED => {}
        _ => return TestResult::Fail("bound route is not masked level/active-low on its vector"),
    }
    line.unmask();
    if line.masked() || route(gsi).is_none_or(|(_, low)| low & MASKED != 0) {
        return TestResult::Fail("unmask did not clear the IOAPIC mask");
    }
    // A second owner cannot take a live route.
    if !matches!(
        // SAFETY: as above; refused before any programming.
        unsafe { Line::bind_exclusive(gsi, "oneshot-test-2", Arc::new(|| {})) },
        Err(Error::Shared)
    ) {
        return TestResult::Fail("live route was bound twice");
    }
    // Hard half: mask at the controller, count, wake the owner.
    if line.deliver_for_test() != IrqStatus::Handled
        || !line.masked()
        || route(gsi).is_none_or(|(_, low)| low & MASKED == 0)
        || line.fires() != 1
        || WAKES.load(Ordering::Acquire) != 1
    {
        return TestResult::Fail("delivery did not mask, count and notify");
    }
    line.unmask();
    line.unmask(); // idempotent
    if line.masked() || route(gsi).is_none_or(|(_, low)| low & MASKED != 0) {
        return TestResult::Fail("service unmask did not re-enable the line");
    }
    let vector = line.vector();
    drop(line);
    if route(gsi).is_none_or(|(_, low)| low & MASKED == 0)
        || !dispatch::installed_handler_names(vector).is_empty()
    {
        return TestResult::Fail("drop left the route live or the handler installed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "interrupts",
    smoke_oneshot_intx_masks_on_delivery_and_unmasks_after_service
);

#[cfg(not(target_arch = "x86_64"))]
fn smoke_oneshot_intx_unsupported_without_ioapic() -> TestResult {
    // SAFETY: refused before any controller access.
    match unsafe { Line::bind_exclusive(16, "oneshot-test", Arc::new(|| {})) } {
        Err(Error::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("oneshot INTx bound without an IOAPIC"),
    }
}
#[cfg(not(target_arch = "x86_64"))]
kernel_test_in!("interrupts", smoke_oneshot_intx_unsupported_without_ioapic);
