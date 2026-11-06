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
        base: UartBase::Io(0x3F8),
        reg_shift: 0,
        clock_hz: crate::uart_8250::UART_CLOCK_HZ,
        irq: Some(4),
        name: "test-COM1",
        baud: 115_200,
        kind: crate::registry::UartFamily::Uart8250,
        virt: None,
    });
    let after = crate::registry::count();
    if after <= before {
        return TestResult::Fail("registry count did not increase");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/serial/registry", smoke_serial_registry);

/// Registry: an MMIO entry round-trips its real base, stride and
/// clock — the fields a tty backend rebuilds its handle from. The
/// old I/O-shim registry could not represent this entry at all.
fn smoke_serial_registry_mmio_entry_is_truthful() -> TestResult {
    use narf_memory::PhysAddr;
    let phys = PhysAddr::new(0xFE00_1000);
    crate::registry::register(crate::registry::UartInfo {
        base: UartBase::Mmio(phys),
        reg_shift: 2,
        clock_hz: 100_000_000,
        irq: Some(12),
        name: "test-LPSS",
        baud: 115_200,
        kind: crate::registry::UartFamily::Uart8250,
        virt: None,
    });
    let found = crate::registry::uarts()
        .into_iter()
        .find(|u| u.name == "test-LPSS");
    let Some(u) = found else {
        return TestResult::Fail("MMIO registry entry not found in snapshot");
    };
    if u.base != UartBase::Mmio(phys) {
        return TestResult::Fail("MMIO base did not round-trip");
    }
    if u.reg_shift != 2 {
        return TestResult::Fail("MMIO reg_shift did not round-trip");
    }
    if u.clock_hz != 100_000_000 {
        return TestResult::Fail("MMIO clock_hz did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/serial/registry",
    smoke_serial_registry_mmio_entry_is_truthful
);

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

// ── PCI serial ──────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_pci_serial_class_matches_registered() -> TestResult {
    use crate::pci_serial as ps;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    ps::register_pci_driver();
    let regs = registered_pci_drivers();
    for prog_if in ps::SUPPORTED_PROG_IFS.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::ClassFull {
                    class: ps::PCI_CLASS_COMMUNICATION,
                    subclass: ps::PCI_SUBCLASS_SERIAL,
                    prog_if: p,
                } if p == prog_if
            )
        });
        if !found {
            return TestResult::Fail("pci-serial class match missing a prog-IF");
        }
    }
    // The MS-03's KT port is prog-IF 0x02.
    if !ps::SUPPORTED_PROG_IFS.contains(&0x02) {
        return TestResult::Fail("16550 prog-IF not claimed");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/serial/pci",
    smoke_pci_serial_class_matches_registered
);

#[cfg(target_arch = "x86_64")]
fn smoke_pci_serial_does_not_claim_whole_class() -> TestResult {
    use crate::pci_serial as ps;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    ps::register_pci_driver();
    // A bare `Class { class: 0x07 }` entry would also claim the two
    // CSME HECI functions (07:80) on this board, which have their own
    // driver. Every entry must pin the full triple.
    let too_broad = registered_pci_drivers()
        .iter()
        .any(|m| matches!(m.kind, MatchKind::Class { class: 0x07, .. }));
    if too_broad {
        return TestResult::Fail("pci-serial registered a whole-base-class match");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/serial/pci",
    smoke_pci_serial_does_not_claim_whole_class
);

#[cfg(target_arch = "x86_64")]
fn smoke_pci_serial_class_triple_decode() -> TestResult {
    use crate::pci_serial as ps;
    // lspci renders the MS-03's KT port as class 0700, prog-if 02.
    let class = 0x0007_0002u32;
    if ps::base_class_of(class) != 0x07 {
        return TestResult::Fail("base class decoded wrong");
    }
    if ps::subclass_of(class) != 0x00 {
        return TestResult::Fail("subclass decoded wrong");
    }
    if ps::prog_if_of(class) != 0x02 {
        return TestResult::Fail("prog-IF decoded wrong");
    }
    if ps::prog_if_name(0x02) != "16550" || ps::prog_if_name(0x06) != "16950" {
        return TestResult::Fail("prog-IF names wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers/serial/pci", smoke_pci_serial_class_triple_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_pci_serial_kt_quirks() -> TestResult {
    use crate::pci_serial::UartQuirks;
    let kt = UartQuirks::KT_IER_READS_ZERO | UartQuirks::KT_BUG_THRE;
    if !kt.contains(UartQuirks::KT_IER_READS_ZERO) || !kt.contains(UartQuirks::KT_BUG_THRE) {
        return TestResult::Fail("KT quirk bits do not compose");
    }
    if UartQuirks::NONE.contains(UartQuirks::KT_IER_READS_ZERO) {
        return TestResult::Fail("NONE should contain no quirks");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers/serial/pci", smoke_pci_serial_kt_quirks);

// ── ACPI PNP0501 ────────────────────────────────────────────────────
//
// The fake-AML builders mirror `narf_aml::pnp`'s fixtures (2-byte
// PkgLength form, EISA-integer `_HID`); they live here because the
// serial crate cannot import aml's private test helpers.

/// 2-byte PkgLength form: `opcode | len | payload`.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn acpi_pkg(opcode: &[u8], payload: &[u8]) -> alloc::vec::Vec<u8> {
    let length = payload.len() + 2;
    assert!(length < 4096);
    let mut bytes = opcode.to_vec();
    bytes.push(0x40 | (length as u8 & 15));
    bytes.push((length >> 4) as u8);
    bytes.extend_from_slice(payload);
    bytes
}

/// `DeviceOp(name) { body }`.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn acpi_device(name: &[u8; 4], body: &[u8]) -> alloc::vec::Vec<u8> {
    let mut payload = name.to_vec();
    payload.extend_from_slice(body);
    acpi_pkg(&[0x5B, 0x82], &payload)
}

/// `Name(_HID, <EISA integer>)`. PNP0501 = 0x0105_D041.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn acpi_hid_name_eisa(eisa: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0x08, b'_', b'H', b'I', b'D', 0x0C];
    v.extend_from_slice(&eisa.to_le_bytes());
    v
}

/// `Name(_HID, "<string>")`.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn acpi_hid_name_string(s: &str) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0x08, b'_', b'H', b'I', b'D', 0x0D];
    v.extend_from_slice(s.as_bytes());
    v.push(0);
    v
}

/// `Name(_CRS, Buffer(<size>) { <res_bytes> })`.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn acpi_crs_name(res_bytes: &[u8]) -> alloc::vec::Vec<u8> {
    let pkg_len = res_bytes.len() + 3;
    assert!(pkg_len < 0x40);
    let mut v = alloc::vec![0x08, b'_', b'C', b'R', b'S', 0x11];
    v.push(pkg_len as u8);
    v.push(0x0A); // BytePrefix: size TermArg
    v.push(res_bytes.len() as u8);
    v.extend_from_slice(res_bytes);
    v
}

/// COM-port resource template: IO desc (base) + IRQ desc (mask) + EndTag.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn acpi_com_resources(base: u16, irq_mask: u16) -> alloc::vec::Vec<u8> {
    alloc::vec![
        0x47,
        0x01, // IO desc, Decode16
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        (base & 0xFF) as u8,
        (base >> 8) as u8,
        0x08,
        0x08, // alignment, length
        0x22, // IRQ desc
        (irq_mask & 0xFF) as u8,
        (irq_mask >> 8) as u8,
        0x79,
        0x00, // EndTag
    ]
}

/// Fake namespace → registered UARTs, end to end.
///
/// Two PNP0501 UARTs at non-legacy bases (the dedup rule skips the
/// legacy COM1–COM4 bases), one PNP0303 decoy, one `_CRS`-less
/// PNP0501 device. The empty-namespace call first proves the
/// graceful no-op. Runs inside a scoped namespace so the boot
/// namespace is restored on drop.
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
fn smoke_acpi_pnp0501_enumerates_fake_uarts() -> TestResult {
    // SAFETY: serialized namespace scope; restores the boot namespace
    // on drop. Same pattern as power/wireless namespace fixtures.
    let _namespace = unsafe { narf_aml::__test_namespace_scope() };
    let before = crate::registry::count();
    crate::probe::enumerate_acpi_uarts();
    if crate::registry::count() != before {
        return TestResult::Fail("enumerate on empty namespace registered UARTs");
    }
    let mut body = alloc::vec::Vec::new();
    let mut com1 = acpi_hid_name_eisa(0x0105_D041);
    com1.extend_from_slice(&acpi_crs_name(&acpi_com_resources(0x2E0, 0x0020)));
    body.extend_from_slice(&acpi_device(b"COM1", &com1));
    let mut com2 = acpi_hid_name_eisa(0x0105_D041);
    com2.extend_from_slice(&acpi_crs_name(&acpi_com_resources(0x3E0, 0x0200)));
    body.extend_from_slice(&acpi_device(b"COM2", &com2));
    let mut kbd = acpi_hid_name_string("PNP0303");
    kbd.extend_from_slice(&acpi_crs_name(&acpi_com_resources(0x0060, 0x0002)));
    body.extend_from_slice(&acpi_device(b"KBD0", &kbd));
    body.extend_from_slice(&acpi_device(b"COM3", &acpi_hid_name_eisa(0x0105_D041)));
    if narf_aml::__parse_body_for_test(&body, "\\").is_err() {
        return TestResult::Fail("fake ACPI namespace parse failed");
    }
    crate::probe::enumerate_acpi_uarts();
    if crate::registry::count() != before + 2 {
        return TestResult::Fail("expected 2 ACPI UARTs registered");
    }
    for (base, irq) in [(0x2E0u16, 5u8), (0x3E0u16, 9u8)] {
        let found = crate::registry::uarts().into_iter().any(|u| {
            u.base == crate::uart_8250::UartBase::Io(base)
                && u.irq == Some(irq)
                && u.name == "acpi-pnp0501"
        });
        if !found {
            return TestResult::Fail("ACPI UART missing from registry");
        }
    }
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "kernel-test"))]
kernel_test_in!(
    "drivers/serial/acpi",
    smoke_acpi_pnp0501_enumerates_fake_uarts
);

/// Real boot namespace (QEMU q35): the query finds the firmware COM
/// ports — COM1 at 0x3F8, IRQ 4. Fails (not Skips) when the namespace
/// is built but holds no PNP0501 device: on QEMU that means the query
/// itself is broken, and the fake-namespace smokes are the coverage
/// for genuinely PNP0501-less platforms.
#[cfg(target_arch = "x86_64")]
fn smoke_acpi_pnp0501_real_namespace() -> TestResult {
    let devs = narf_aml::pnp::pnp_devices(crate::probe::PNP_COM_ID);
    if devs.is_empty() {
        return TestResult::Fail("no PNP0501 devices in the boot namespace");
    }
    if !devs
        .iter()
        .any(|d| d.io_base == Some(0x3F8) && d.irq == Some(4))
    {
        return TestResult::Fail("QEMU COM1 (0x3F8 irq 4) not found via PNP0501");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers/serial/acpi", smoke_acpi_pnp0501_real_namespace);

/// Enumerating twice registers nothing the second time: the dedup
/// rule keeps one physical port to one registry entry.
#[cfg(target_arch = "x86_64")]
fn smoke_acpi_enumerate_idempotent() -> TestResult {
    crate::probe::enumerate_acpi_uarts();
    let mid = crate::registry::count();
    crate::probe::enumerate_acpi_uarts();
    if crate::registry::count() != mid {
        return TestResult::Fail("second enumerate registered duplicates");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("drivers/serial/acpi", smoke_acpi_enumerate_idempotent);
