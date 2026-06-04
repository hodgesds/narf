//! Smoke tests for `narf-drivers-serial`.
//!
//! All tests are structural (host-side, no live hardware). Real-silicon
//! tests (detect, init, read/write) emit `Skip` when no UART is probed.

#![cfg(target_arch = "x86_64")]

use crate::uart_8250::{self, UartBase, UART_CLOCK_HZ};
use narf_kernel_test::{kernel_test_in, TestResult};

// ── Register layout ───────────────────────────────────────────────────

/// Verify register offset constants match the 8250 specification.
fn smoke_8250_register_offsets() -> TestResult {
    // THR/RBR share offset 0.
    if uart_8250::REG_THR_RBR != 0 {
        return TestResult::Fail("REG_THR_RBR should be offset 0");
    }
    if uart_8250::REG_IER != 1 {
        return TestResult::Fail("REG_IER should be offset 1");
    }
    if uart_8250::REG_IIR != 2 {
        return TestResult::Fail("REG_IIR should be offset 2");
    }
    if uart_8250::REG_FCR != 2 {
        return TestResult::Fail("REG_FCR should be offset 2 (same as IIR)");
    }
    if uart_8250::REG_LCR != 3 {
        return TestResult::Fail("REG_LCR should be offset 3");
    }
    if uart_8250::REG_MCR != 4 {
        return TestResult::Fail("REG_MCR should be offset 4");
    }
    if uart_8250::REG_LSR != 5 {
        return TestResult::Fail("REG_LSR should be offset 5");
    }
    if uart_8250::REG_MSR != 6 {
        return TestResult::Fail("REG_MSR should be offset 6");
    }
    if uart_8250::REG_SCR != 7 {
        return TestResult::Fail("REG_SCR should be offset 7");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_register_offsets);

/// Verify DLL/DLM are at the same offsets as THR/IER with DLAB=1.
fn smoke_8250_dll_dlm_offsets() -> TestResult {
    // DLL is at the same I/O port as THR when DLAB=1.
    if uart_8250::REG_DLL != uart_8250::REG_THR_RBR {
        return TestResult::Fail("DLL should be at same offset as THR (DLAB=1)");
    }
    // DLM is at the same I/O port as IER when DLAB=1.
    if uart_8250::REG_DLM != uart_8250::REG_IER {
        return TestResult::Fail("DLM should be at same offset as IER (DLAB=1)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_dll_dlm_offsets);

/// Baud divisor calculation: 9600 baud @ 1.8432 MHz clock → divisor 12.
/// Linux 8250_port.c `serial8250_do_set_divisor` ~L2100.
fn smoke_8250_baud_divisor_9600() -> TestResult {
    use crate::uart_8250::baud_divisor;
    match baud_divisor(9600, UART_CLOCK_HZ) {
        Some(12) => {}
        Some(d) => {
            let _ = d;
            return TestResult::Fail("9600 baud divisor should be 12");
        }
        None => return TestResult::Fail("baud_divisor returned None for 9600"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_baud_divisor_9600);

/// 115200 baud → divisor 1.
fn smoke_8250_baud_divisor_115200() -> TestResult {
    use crate::uart_8250::baud_divisor;
    match baud_divisor(115_200, UART_CLOCK_HZ) {
        Some(1) => {}
        Some(d) => {
            let _ = d;
            return TestResult::Fail("115200 baud divisor should be 1");
        }
        None => return TestResult::Fail("baud_divisor returned None for 115200"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_baud_divisor_115200);

/// baud=0 → divisor None (invalid).
fn smoke_8250_baud_zero() -> TestResult {
    use crate::uart_8250::baud_divisor;
    if baud_divisor(0, UART_CLOCK_HZ).is_some() {
        return TestResult::Fail("baud_divisor(0) should return None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_baud_zero);

/// COM1/COM2 base addresses match the PC standard.
fn smoke_8250_com_port_addresses() -> TestResult {
    if uart_8250::COM1_BASE != 0x3F8 {
        return TestResult::Fail("COM1 should be at 0x3F8");
    }
    if uart_8250::COM2_BASE != 0x2F8 {
        return TestResult::Fail("COM2 should be at 0x2F8");
    }
    if uart_8250::COM3_BASE != 0x3E8 {
        return TestResult::Fail("COM3 should be at 0x3E8");
    }
    if uart_8250::COM4_BASE != 0x2E8 {
        return TestResult::Fail("COM4 should be at 0x2E8");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_com_port_addresses);

/// LCR.DLAB bit and 8N1 encoding constants.
fn smoke_8250_lcr_constants() -> TestResult {
    if uart_8250::LCR_DLAB != 0x80 {
        return TestResult::Fail("LCR.DLAB should be bit 7 = 0x80");
    }
    if uart_8250::LCR_8N1 != 0x03 {
        return TestResult::Fail("LCR 8N1 should be 0x03");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_lcr_constants);

/// LSR bit constants: DR=0x01, THRE=0x20.
fn smoke_8250_lsr_bits() -> TestResult {
    if uart_8250::LSR_DR != 0x01 {
        return TestResult::Fail("LSR.DR should be bit 0 = 0x01");
    }
    if uart_8250::LSR_THRE != 0x20 {
        return TestResult::Fail("LSR.THRE should be bit 5 = 0x20");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_lsr_bits);

/// IIR.FIFO_ENABLED = 0xC0 (bits 7:6 set).
fn smoke_8250_iir_fifo_bits() -> TestResult {
    if uart_8250::IIR_FIFO_ENABLED != 0xC0 {
        return TestResult::Fail("IIR.FIFO_ENABLED should be 0xC0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_iir_fifo_bits);

/// UART constructor: new() returns UartType::NotDetected before detect().
fn smoke_8250_new_state() -> TestResult {
    use crate::uart_8250::{Uart8250, UartType};
    let u = Uart8250::new(0x3F8, Some(4));
    if u.base != UartBase::Io(0x3F8) {
        return TestResult::Fail("base address wrong");
    }
    if u.irq != Some(4) {
        return TestResult::Fail("IRQ wrong");
    }
    if u.uart_type != UartType::NotDetected {
        return TestResult::Fail("initial uart_type should be NotDetected");
    }
    if u.baud != 0 {
        return TestResult::Fail("initial baud should be 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/8250", smoke_8250_new_state);

/// Registry: register a fake UART, verify count increases.
fn smoke_serial_registry() -> TestResult {
    let before = crate::registry::count();
    crate::registry::register(crate::registry::UartInfo {
        io_base: 0x3F8,
        irq: Some(4),
        name: "test-COM1",
        baud: 115_200,
    });
    let after = crate::registry::count();
    if after <= before {
        return TestResult::Fail("registry count did not increase");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/registry", smoke_serial_registry);

/// LPSS UART: new_mmio constructor.
fn smoke_lpss_uart_constructor() -> TestResult {
    use crate::uart_8250::Uart8250;
    use narf_memory::PhysAddr;
    let phys = PhysAddr::new(0xFE00_0000);
    let u = Uart8250::new_mmio(phys, Some(12), 2, 100_000_000);
    if u.base != UartBase::Mmio(phys) {
        return TestResult::Fail("MMIO base address wrong");
    }
    if u.reg_shift != 2 {
        return TestResult::Fail("reg_shift wrong");
    }
    if u.clock_hz != 100_000_000 {
        return TestResult::Fail("clock_hz wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/lpss", smoke_lpss_uart_constructor);
