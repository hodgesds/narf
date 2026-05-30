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
    /// IO base port (e.g. 0x3F8 for COM1).
    pub io_base: u16,
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
