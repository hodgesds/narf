//! ACPI PNP0501 UART enumeration.
//!
//! Reference: `linux/drivers/tty/serial/8250/8250_acpi.c`
//! (Heikki Krogerus, Andy Shevchenko — GPL-2.0-or-later).
//! ACPI PNPID "PNP0501" is the standard PC COM port device ID.
//!
//! ## Discovery
//!
//! `narf_aml::pnp::pnp_devices` walks the AML namespace for devices
//! whose `_HID` equals "PNP0501" and evaluates `_CRS` (Current
//! Resource Settings) to get the I/O base address and IRQ for each.
//! This module converts each result to a `Uart8250` entry in the
//! serial registry.
//!
//! Non-legacy ports (PCI serial cards) use a class-code match
//! (PCI class 0x07 / subclass 0x00 / prog-if 0x02) — that path
//! lands when the PCI driver framework supports class-code probing.

use crate::registry;
use crate::uart_8250::{Uart8250, UartBase, UART_CLOCK_HZ};

/// ACPI PNP ID for standard COM ports.
pub const PNP_COM_ID: &str = "PNP0501";

/// Registry name for ACPI-enumerated UARTs.
const ACPI_UART_NAME: &str = "acpi-pnp0501";

/// Walk the ACPI namespace for PNP0501 devices and register any found
/// UART ports.
///
/// Graceful fallback: when the AML namespace hasn't been built yet
/// (Stage::Subsys runs before Stage::Acpi on some init orderings)
/// `pnp_devices` returns an empty list and this is a no-op apart
/// from the banner. Devices whose I/O base is already registered
/// (the legacy probe claims COM1–COM4 first) are skipped so one
/// physical port never gets two registry entries.
pub fn enumerate_acpi_uarts() {
    use core::fmt::Write as _;
    let mut found = 0usize;
    for dev in narf_aml::pnp::pnp_devices(PNP_COM_ID) {
        let Some(base) = dev.io_base else {
            continue;
        };
        if registry::uarts()
            .iter()
            .any(|u| u.base == UartBase::Io(base))
        {
            continue;
        }
        let mut uart = Uart8250::new(base, dev.irq);
        if !uart.init(115_200) {
            continue;
        }
        let _ = writeln!(
            narf_console::Writer,
            "  serial-acpi: {} at 0x{:03X} irq={:?} {:?}",
            PNP_COM_ID,
            base,
            dev.irq,
            uart.uart_type
        );
        registry::register(registry::UartInfo {
            base: UartBase::Io(base),
            reg_shift: 0,
            clock_hz: UART_CLOCK_HZ,
            irq: dev.irq,
            name: ACPI_UART_NAME,
            baud: 115_200,
        });
        found += 1;
    }
    if found == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  serial-acpi: no {} UARTs enumerated",
            PNP_COM_ID
        );
    }
}
