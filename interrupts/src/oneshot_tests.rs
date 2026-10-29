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

#[cfg(target_arch = "aarch64")]
fn smoke_oneshot_spi_masks_on_delivery_and_unmasks_after_service() -> TestResult {
    use crate::aarch64::gic;
    use core::sync::atomic::AtomicU32;
    static WAKES: AtomicU32 = AtomicU32::new(0);
    WAKES.store(0, Ordering::Release);
    // A high SPI whose dispatch slot is free (as gic_spi_tests does).
    let mut bound = None;
    for intid in (200u32..240).filter(|i| *i < gic::spi_limit()) {
        let notify: Notify = Arc::new(|| {
            WAKES.fetch_add(1, Ordering::AcqRel);
        });
        // SAFETY: the GIC is initialised at boot; the test owns this SPI.
        if let Ok(line) = unsafe { Line::bind_spi(intid, "oneshot-spi-test", notify) } {
            bound = Some(line);
            break;
        }
    }
    let Some(line) = bound else {
        return TestResult::Skip("no free SPI dispatch slot");
    };
    let intid = line.source();
    if !matches!(
        // SAFETY: as above; the slot is already reserved by `line`.
        unsafe { Line::bind_spi(intid, "oneshot-spi-test-2", Arc::new(|| {})) },
        Err(Error::Shared)
    ) {
        return TestResult::Fail("reserved SPI slot was bound twice");
    }
    let wait = |target: u32| {
        let start = narf_time::Instant::now();
        while WAKES.load(Ordering::Acquire) < target
            && narf_time::Instant::now().cycles_since(start) < narf_time::ns_to_cycles(200_000_000)
        {
            core::hint::spin_loop();
        }
    };
    let was = narf_arch::interrupts_enabled();
    // SAFETY: the GIC is initialised and the SPI is ours.
    unsafe { narf_arch::enable_interrupts() };
    // Pending while masked: no delivery.
    let pended = gic::pend_spi(intid).is_ok();
    wait(1);
    let quiet = WAKES.load(Ordering::Acquire) == 0 && line.fires() == 0;
    // Unmask: the pending SPI is delivered once and re-masked by the hard half.
    line.unmask();
    wait(1);
    if !was {
        // SAFETY: restore the caller's mask.
        unsafe { narf_arch::disable_interrupts() };
    }
    if !pended || !quiet {
        return TestResult::Fail("masked SPI was delivered");
    }
    if line.fires() != 1 || WAKES.load(Ordering::Acquire) != 1 || !line.masked() {
        return TestResult::Fail("unmasked SPI did not deliver once and re-mask");
    }
    let vector = line.vector();
    drop(line);
    if !dispatch::installed_handler_names(vector).is_empty()
        || crate::vector::reserve(vector).is_err()
    {
        return TestResult::Fail("drop left the handler or the slot reserved");
    }
    let _ = crate::vector::free(vector);
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "interrupts",
    smoke_oneshot_spi_masks_on_delivery_and_unmasks_after_service
);

#[cfg(target_arch = "aarch64")]
fn smoke_oneshot_intx_gsi_unsupported_without_ioapic() -> TestResult {
    // SAFETY: refused before any controller access.
    match unsafe { Line::bind_exclusive(16, "oneshot-test", Arc::new(|| {})) } {
        Err(Error::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("IOAPIC oneshot bound without an IOAPIC"),
    }
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "interrupts",
    smoke_oneshot_intx_gsi_unsupported_without_ioapic
);
