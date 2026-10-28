//! aarch64 GICv3 SPI configuration smokes (QEMU virt).

use narf_kernel_test::{kernel_test_in, TestResult};

/// End-to-end: reserve the dispatch slot, configure an SPI no virt
/// device uses (edge, routed to this CPU), software-pend it at the
/// distributor and see the trap deliver it to the handler on
/// `intid & 0xFF`.
#[cfg(target_arch = "aarch64")]
fn smoke_gic_spi_configure_and_deliver() -> TestResult {
    use crate::aarch64::gic;
    use core::sync::atomic::{AtomicU64, Ordering};
    static HITS: AtomicU64 = AtomicU64::new(0);
    fn handler(cookie: u64) -> crate::IrqStatus {
        HITS.fetch_add(cookie, Ordering::AcqRel);
        crate::IrqStatus::Handled
    }
    if gic::configure_spi(16, gic::SpiTrigger::Edge).is_ok() {
        return TestResult::Fail("PPI INTID accepted as SPI");
    }
    if gic::configure_spi(gic::spi_limit(), gic::SpiTrigger::Edge).is_ok() {
        return TestResult::Fail("INTID past ITLinesNumber accepted");
    }
    // A high SPI whose dispatch slot is free (virt devices sit low; the
    // on_irq scratch vectors are 100..=130).
    let Some(intid) = (200u32..240)
        .filter(|i| *i < gic::spi_limit())
        .find(|i| crate::vector::reserve(gic::spi_vector(*i)).is_ok())
    else {
        return TestResult::Skip("no free SPI dispatch slot");
    };
    let v = gic::spi_vector(intid);
    if crate::vector::reserve(v).is_ok() {
        return TestResult::Fail("vector reserved twice");
    }
    crate::dispatch::install_handler_named(v, "gic-spi-test", 1, handler);
    let before = crate::dispatch::fire_count(v);
    HITS.store(0, Ordering::Release);
    let was = narf_arch::interrupts_enabled();
    let ok =
        gic::configure_spi(intid, gic::SpiTrigger::Edge).is_ok() && gic::pend_spi(intid).is_ok();
    // SAFETY: the GIC is initialised at boot and the SPI is ours.
    unsafe { narf_arch::enable_interrupts() };
    let start = narf_time::Instant::now();
    while HITS.load(Ordering::Acquire) == 0
        && narf_time::Instant::now().cycles_since(start) < narf_time::ns_to_cycles(500_000_000)
    {
        core::hint::spin_loop();
    }
    if !was {
        // SAFETY: restore the caller's mask.
        unsafe { narf_arch::disable_interrupts() };
    }
    let _ = gic::mask_spi(intid);
    crate::dispatch::remove_handler(v, "gic-spi-test", 1);
    let _ = crate::vector::free(v);
    if !ok {
        return TestResult::Fail("configure/pend refused a valid SPI");
    }
    if HITS.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("SPI not delivered exactly once");
    }
    if crate::dispatch::fire_count(v) != before + 1 {
        return TestResult::Fail("fire_count did not advance by one");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("interrupts", smoke_gic_spi_configure_and_deliver);

fn smoke_vector_reserve_specific() -> TestResult {
    use crate::vector::{free, is_allocated, reserve, VectorError};
    if reserve(250) != Err(VectorError::OutOfRange) {
        return TestResult::Fail("reserve(250) must be OutOfRange");
    }
    let Some(v) = (190u8..200).find(|v| reserve(*v).is_ok()) else {
        return TestResult::Skip("no free vector in 190..200");
    };
    let twice = reserve(v);
    let marked = is_allocated(v);
    let _ = free(v);
    if twice != Err(VectorError::Exhausted) {
        return TestResult::Fail("second reserve must be Exhausted");
    }
    if !marked {
        return TestResult::Fail("reserved vector not marked");
    }
    TestResult::Pass
}
kernel_test_in!("interrupts", smoke_vector_reserve_specific);
