//! aarch64 kernel-test smokes for DT-bound serial devices.
//!
//! Kept apart from `tests.rs`, which is gated
//! `#![cfg(target_arch = "x86_64")]` at module level.

use narf_kernel_test::{kernel_test_in, TestResult};

/// Step-4 binding proof (issue #1048): on QEMU `virt` the PL011
/// was enumerated from the device tree, matched by the DT table,
/// probed, and published — with no hardcoded-address path in the
/// chain. Asserts, against the booted kernel:
///  * the driver holds a bound port at the DT-described window
///    (0x0900_0000 — the value is the *fixture tree's*, checked
///    here, never fed to the driver);
///  * its IRQ is the GIC-resolved INTID 33 (SPI 1 + 32);
///  * the serial registry carries the port as an MMIO entry;
///  * the hardware loopback round-trip passes over the mapped
///    window (the mapped registers are the live device).
fn smoke_pl011_dt_bound_and_loopback() -> TestResult {
    let Some((base, irq)) = crate::pl011::bound_port() else {
        return TestResult::Fail("PL011 was not bound by the DT match table");
    };
    if base != 0x0900_0000 {
        return TestResult::Fail("bound PL011 base is not the DT-described window");
    }
    if irq != Some(33) {
        return TestResult::Fail("bound PL011 IRQ is not the DT-resolved INTID 33");
    }
    let published = crate::registry::uarts()
        .iter()
        .any(|p| p.mmio_base == 0x0900_0000 && p.name == "ttyAMA0" && p.irq == Some(33));
    if !published {
        return TestResult::Fail("PL011 not published in the serial registry");
    }
    match crate::pl011::selftest_loopback_diag() {
        Some(crate::pl011::LoopbackOutcome::Pass) => TestResult::Pass,
        Some(crate::pl011::LoopbackOutcome::LbeNotSet(_)) => {
            TestResult::Fail("PL011 loopback: CR.LBE did not stick when read back")
        }
        Some(crate::pl011::LoopbackOutcome::RxEmpty(_)) => {
            TestResult::Fail("PL011 loopback: RX FIFO empty during read-back")
        }
        Some(crate::pl011::LoopbackOutcome::WrongByte { .. }) => {
            TestResult::Fail("PL011 loopback: read-back byte differs from pattern")
        }
        None => TestResult::Fail("bound PL011 vanished before the loopback test"),
    }
}
kernel_test_in!("drivers/serial/pl011", smoke_pl011_dt_bound_and_loopback);
