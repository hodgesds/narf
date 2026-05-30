//! ACPI PNP0501 UART enumeration.
//!
//! Reference: `linux/drivers/tty/serial/8250/8250_acpi.c`
//! (Heikki Krogerus, Andy Shevchenko — GPL-2.0-or-later).
//! ACPI PNPID "PNP0501" is the standard PC COM port device ID.
//!
//! ## Discovery
//!
//! The ACPI namespace walker finds devices with `_HID` == "PNP0501".
//! For each such device it evaluates `_CRS` (Current Resource
//! Settings) to get the I/O base address and IRQ.
//!
//! NARF's `narf_acpi` crate exposes a simplified namespace walker;
//! this module calls it and converts the result to `Uart8250` entries.
//!
//! Non-legacy ports (PCI serial cards) use a class-code match
//! (PCI class 0x07 / subclass 0x00 / prog-if 0x02) — that path
//! lands when the PCI driver framework supports class-code probing.

use crate::registry;
use crate::uart_8250::Uart8250;

/// ACPI PNP ID for standard COM ports.
pub const PNP_COM_ID: &str = "PNP0501";

/// Walk the ACPI namespace for PNP0501 devices and register any found
/// UART ports. Falls back gracefully if the ACPI crate hasn't enumerated
/// the namespace yet (Stage::Subsys runs before Stage::Acpi on some
/// init orderings).
pub fn enumerate_acpi_uarts() {
    use core::fmt::Write as _;
    // narf_acpi::pnp_devices walks the AML namespace and returns a list
    // of (io_base, irq) pairs for devices with the given PNP HID.
    // This function is currently a no-op shim — when narf_acpi exposes
    // pnp_devices() this loop will populate real entries.
    //
    // For now, emit a banner so the boot log shows the path was walked.
    let _ = writeln!(
        narf_console::Writer,
        "  serial-acpi: {} enumeration (ACPI walker pending)",
        PNP_COM_ID
    );
    // TODO: replace with:
    //   for (base, irq) in narf_acpi::pnp_devices(PNP_COM_ID) {
    //       let mut uart = Uart8250::new(base, irq);
    //       if uart.init(115_200) {
    //           registry::register(...);
    //       }
    //   }
    let _ = Uart8250::new; // keep import alive
    let _ = registry::register; // keep import alive
}
