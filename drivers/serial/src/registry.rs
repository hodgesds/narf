//! Global UART registry.
//!
//! Drivers call [`register`] at probe time; the console / TTY layer
//! calls [`uarts`] to iterate registered devices.

extern crate alloc;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

/// Registered UART descriptor.
#[derive(Clone, Debug)]
pub struct UartInfo {
    /// IO base port (e.g. 0x3F8 for COM1); 0 for MMIO-only ports.
    pub io_base: u16,
    /// Physical MMIO base for memory-mapped ports (e.g. a PL011
    /// described by the device tree); 0 for I/O-port UARTs. The
    /// registry described ports by `io_base` alone until the first
    /// DT-bound MMIO UART (DT programme step 4) needed its address
    /// recorded.
    pub mmio_base: u64,
    /// IRQ line, if assigned: an ISA IRQ on x86, the GIC INTID on
    /// aarch64 (hence wider than a byte — SPIs start at 32).
    pub irq: Option<u16>,
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
