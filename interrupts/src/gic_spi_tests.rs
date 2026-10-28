//! aarch64 GIC (v2 + v3) SPI and SGI smokes (QEMU virt).

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

/// Both SGI send paths reach the AP on whichever backend probe chose
/// (GICv3 `ICC_SGI1R_EL1`, GICv2 `GICD_SGIR` target list / all-but-self),
/// and the backend the trap acknowledges through is the probed one.
#[cfg(target_arch = "aarch64")]
fn smoke_gic_sgi_unicast_and_broadcast_reach_ap() -> TestResult {
    use crate::aarch64::{gic, sgi};
    match gic::version() {
        Some(gic::GicVersion::V2) if !gic::is_v2() => {
            return TestResult::Fail("probed v2 but trap backend is v3")
        }
        Some(gic::GicVersion::V3) if gic::is_v2() => {
            return TestResult::Fail("probed v3 but trap backend is v2")
        }
        None => return TestResult::Fail("GIC never probed"),
        _ => {}
    }
    if !narf_lib::smp::is_online(1) {
        return TestResult::Skip("AP CPU 1 offline");
    }
    if narf_lib::percpu::current_cpu() == 1 {
        return TestResult::Skip("running on the target AP");
    }
    fn wait_rx(intid: u8, before: u64) -> bool {
        let start = narf_time::Instant::now();
        while narf_time::Instant::now().cycles_since(start) < narf_time::ns_to_cycles(500_000_000) {
            if sgi::rx_count(1, intid) > before {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
    // INTIDs 9 and 10 have no handler (reserved range): only the
    // receive counter moves.
    let before = sgi::rx_count(1, 9);
    // SAFETY: GIC initialised at boot; affinity 1 = AP 1 on QEMU virt.
    unsafe { sgi::send_to_cpu_aff(9, 1) };
    if !wait_rx(9, before) {
        return TestResult::Fail("unicast SGI did not reach AP 1");
    }
    let self_before = sgi::rx_count(narf_lib::percpu::current_cpu() as u32, 10);
    let before = sgi::rx_count(1, 10);
    // SAFETY: as above.
    unsafe { sgi::broadcast_others(10) };
    if !wait_rx(10, before) {
        return TestResult::Fail("broadcast SGI did not reach AP 1");
    }
    if sgi::rx_count(narf_lib::percpu::current_cpu() as u32, 10) != self_before {
        return TestResult::Fail("all-but-self SGI was delivered to the sender");
    }
    TestResult::Pass
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("interrupts", smoke_gic_sgi_unicast_and_broadcast_reach_ap);

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
