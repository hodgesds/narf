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
///  * the register-level config proof passes over the mapped
///    window (programmed control/line state, LBE sticks, TX
///    drains — the mapped registers are the live device).
///    RX loopback is NOT asserted here: QEMU 8.2's `virt`
///    model does not deliver it (see the driver note).
fn smoke_pl011_dt_bound_and_config() -> TestResult {
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
    // Register-level UART health proof (NOT a loopback
    // round-trip: QEMU 8.2's `virt` PL011 model does not deliver
    // loopback bytes to RX — measured with a register trace
    // under every guest-side precondition tried — so gating
    // this smoke on loopback would fail a correct driver. RX
    // loopback stays hardware-only validation via
    // `loopback_selftest_diag`; see the driver note.
    match crate::pl011::selftest_config_diag() {
        Some(crate::pl011::ConfigOutcome::Pass) => TestResult::Pass,
        Some(crate::pl011::ConfigOutcome::LbeNotSet(_)) => {
            TestResult::Fail("PL011 config: CR.LBE did not stick when read back")
        }
        Some(crate::pl011::ConfigOutcome::NotEnabled(_)) => {
            TestResult::Fail("PL011 config: UART not fully enabled (UARTEN/TXE/RXE)")
        }
        Some(crate::pl011::ConfigOutcome::BadLineControl(_)) => {
            TestResult::Fail("PL011 config: line control is not FEN|WLEN_8")
        }
        Some(crate::pl011::ConfigOutcome::TxStuck) => {
            TestResult::Fail("PL011 config: TX FIFO did not drain")
        }
        None => TestResult::Fail("bound PL011 vanished before the config test"),
    }
}
kernel_test_in!("drivers/serial/pl011", smoke_pl011_dt_bound_and_config);
