//! Global UART registry.
//!
//! Drivers call [`register`] at probe time; the console / TTY layer
//! calls [`uarts`] to iterate registered devices.
//!
//! An entry describes the port's register file truthfully: its base in
//! the address space it actually lives in ([`UartBase`]) plus the
//! register stride and input clock the probe used. Earlier revisions
//! described every port by a 16-bit I/O base, which forced two lies:
//! PCI MMIO ports were left out of the registry entirely (they have no
//! I/O base) and Intel LPSS ports were published under a truncated
//! low-16-bits shim of their MMIO address. A consumer that built a tty
//! backend from the shim would poke the wrong ports, so the registry
//! now carries the real base and the MMIO exclusion is gone.

extern crate alloc;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::uart_8250::UartBase;

/// Registered UART descriptor.
#[derive(Clone, Debug)]
pub struct UartInfo {
    /// Register-file base: I/O port for legacy/PCI I/O-space ports,
    /// physical MMIO address for PCI MMIO and Intel LPSS ports.
    pub base: UartBase,
    /// Register stride (log2). 0 = 1 byte, 2 = 4 bytes (LPSS).
    pub reg_shift: u8,
    /// Input clock frequency in Hz the probe programmed against.
    pub clock_hz: u32,
    /// IRQ line (ISA-style), if assigned.
    pub irq: Option<u8>,
    /// Human-readable name (e.g. "COM1").
    pub name: &'static str,
    /// Baud rate currently programmed.
    pub baud: u32,
}

static REGISTRY: IrqSafeSpinLock<Vec<UartInfo>> = IrqSafeSpinLock::new(Vec::new());

/// Register a UART device.
pub fn register(info: UartInfo) {
    REGISTRY.lock().push(info);
}

/// Return a snapshot of all registered UARTs.
pub fn uarts() -> Vec<UartInfo> {
    let g = REGISTRY.lock();
    g.clone()
}

/// Number of registered UARTs.
pub fn count() -> usize {
    REGISTRY.lock().len()
}
