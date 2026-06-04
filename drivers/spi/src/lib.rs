//! SPI bus trait + AMD FCH and Intel LPSS controller drivers.
//!
//! Three layers:
//! - `SpiBus` trait + `SpiMode` + `SpiError` — the subsystem contract
//!   that controller drivers implement and client drivers consume.
//! - `amd_fch` — AMD FCH SPI (PCI 1022:1682 / ACPI AMDI0061/62/63).
//!   Register map from Linux `drivers/spi/spi-amd.c` (GPL-2.0-or-later).
//! - `intel_lpss` — Intel LPSS SSP SPI controllers (Skylake 8086:9DA4,
//!   Tiger Lake 8086:A0A4, Alder Lake 8086:7AA4, etc.). Register map
//!   from Linux `drivers/spi/spi-pxa2xx.c` and `spi-intel-pci.c`.
//!
//! ## Clock polarity / phase (SpiMode)
//!
//! SPI mode is the (CPOL, CPHA) pair, conventionally numbered 0-3:
//!
//! ```text
//! Mode 0  CPOL=0 CPHA=0 — idle-low,  sample on rising  edge
//! Mode 1  CPOL=0 CPHA=1 — idle-low,  sample on falling edge
//! Mode 2  CPOL=1 CPHA=0 — idle-high, sample on falling edge
//! Mode 3  CPOL=1 CPHA=1 — idle-high, sample on rising  edge
//! ```
//!
//! The bit positions used here (CPOL at bit 1, CPHA at bit 0) match the
//! `SPI_MODE_*` constants in Linux's `<linux/spi/spi.h>` and the AMD FCH
//! `SPI_CNTRL0` MODE field encoding.
//!
//! ## Linux source citations
//!
//! AMD FCH register map:
//!   - `drivers/spi/spi-amd.c` — AMD_SPI_CTRL0_REG, AMD_SPI_ALT_CS_REG,
//!     AMD_SPI_FIFO_BASE, AMD_SPI_TX_COUNT_REG, AMD_SPI_RX_COUNT_REG,
//!     AMD_SPI_STATUS_REG, AMD_SPI_ENA_REG, AMD_SPI_SPEED_REG.
//!     Source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/spi/spi-amd.c
//!   - `drivers/spi/spi-amd-pci.c` — PCI LPC bridge device ID 1022:1682,
//!     BAR offset arithmetic for HID2 MMIO base.
//!
//! Intel LPSS SPI register map:
//!   - `drivers/spi/spi-intel-pci.c` — PCI device table (9DA4, A0A4, 7AA4,
//!     51A4, etc.), MMIO at BAR0.
//!     Source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/spi/spi-intel-pci.c
//!   - `drivers/spi/spi-pxa2xx.c` — SSP SSCR0/SSCR1/SSDR/SSSR register map,
//!     LPSS private register offsets (CS control, clock gate).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod amd_fch;
pub mod intel_lpss;

use alloc::sync::Arc;
use alloc::vec::Vec;

// ── SpiMode ────────────────────────────────────────────────────────
//
// The (CPOL, CPHA) encoding below places CPOL at bit 1 and CPHA at
// bit 0, matching the Linux SPI_MODE_* constants defined in
// <linux/spi/spi.h>:
//
//   SPI_CPHA  = BIT(0)
//   SPI_CPOL  = BIT(1)
//   SPI_MODE_0 = 0              CPOL=0, CPHA=0
//   SPI_MODE_1 = SPI_CPHA       CPOL=0, CPHA=1
//   SPI_MODE_2 = SPI_CPOL       CPOL=1, CPHA=0
//   SPI_MODE_3 = SPI_CPOL|SPI_CPHA  CPOL=1, CPHA=1
//
// The AMD FCH SPI_CNTRL0 MODE field uses the same two-bit encoding
// (bits [21:20] on V1 / V2), so `SpiMode as u8` can be written
// directly after shifting into position.

/// SPI clock polarity / phase mode (CPOL, CPHA).
///
/// Bit 1 = CPOL, bit 0 = CPHA — matches Linux's `SPI_MODE_*` constants
/// (`SPI_CPHA = BIT(0)`, `SPI_CPOL = BIT(1)`, `<linux/spi/spi.h>`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SpiMode {
    /// CPOL=0, CPHA=0 — idle-low SCK, sample on rising edge.
    Mode0 = 0b00,
    /// CPOL=0, CPHA=1 — idle-low SCK, sample on falling edge.
    Mode1 = 0b01,
    /// CPOL=1, CPHA=0 — idle-high SCK, sample on falling edge.
    Mode2 = 0b10,
    /// CPOL=1, CPHA=1 — idle-high SCK, sample on rising edge.
    Mode3 = 0b11,
}

impl SpiMode {
    /// Extract the clock polarity bit (CPOL). 0 = SCK idles low,
    /// 1 = SCK idles high.
    #[inline]
    pub fn cpol(self) -> bool {
        (self as u8) & 0b10 != 0
    }

    /// Extract the clock phase bit (CPHA). 0 = sample on first
    /// (leading) SCK edge, 1 = sample on second (trailing) edge.
    #[inline]
    pub fn cpha(self) -> bool {
        (self as u8) & 0b01 != 0
    }
}

// ── SpiError ───────────────────────────────────────────────────────

/// Error surface for SPI operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpiError {
    /// Transfer didn't complete within the poll budget (BUSY bit
    /// never cleared, or FIFO didn't drain).
    Timeout,
    /// Hardware register read returned an impossible value —
    /// MMIO mapping likely wrong.
    BadHardware,
    /// Requested frequency is outside the controller's supported
    /// range.
    FrequencyOutOfRange,
    /// Chip-select index is out of range for this controller.
    InvalidCs,
    /// Transfer buffer length exceeded the FIFO depth after chunking
    /// — caller must reduce transfer size or enable DMA mode.
    BufferTooLarge,
    /// Generic hardware-reported error. The inner `u32` carries a
    /// controller-specific status register value for diagnostics.
    HwError(u32),
}

// ── SpiBus trait ───────────────────────────────────────────────────

/// SPI bus controller interface.
///
/// Implementors own the controller's MMIO and serialise concurrent
/// callers via their own internal lock. The trait is object-safe so
/// it can be stored as `Arc<dyn SpiBus>` in the registry.
pub trait SpiBus: Send + Sync + core::fmt::Debug {
    /// Full-duplex or half-duplex transfer.
    ///
    /// Clocks out `tx` bytes (or zero-bytes if `tx` is shorter than
    /// `rx`) while simultaneously clocking in bytes into `rx`. The
    /// shorter of the two slices determines the transfer byte count;
    /// callers pass equal-length slices for full-duplex or a
    /// zero-length `rx` for TX-only (or zero-length `tx` for RX-only).
    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SpiError>;

    /// Mutating full-duplex transfer. `tx` is transmitted; the
    /// received bytes overwrite `tx`. Both slices must be the same
    /// length. Equivalent to Linux's `spi_write_then_read` with
    /// same-buffer in/out.
    fn transfer_full_duplex(&self, tx: &mut [u8], rx: &mut [u8]) -> Result<(), SpiError>;

    /// Set the SPI clock polarity / phase mode. Takes effect on the
    /// next transfer.
    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError>;

    /// Set the SCK frequency in Hz. The controller picks the closest
    /// frequency it can generate that is ≤ `hz`. Returns
    /// `FrequencyOutOfRange` if `hz` is below the controller's minimum
    /// or above its maximum.
    fn set_freq(&self, hz: u32) -> Result<(), SpiError>;

    /// Assert chip-select `cs`. The controller deasserts the current
    /// CS before asserting the new one. Returns `InvalidCs` if `cs`
    /// is out of range.
    fn set_cs(&self, cs: u8) -> Result<(), SpiError>;

    /// Identifier for the registry — typically the ACPI path or PCI
    /// BDF string of the controller. Unique within a single boot.
    fn name(&self) -> &str;
}

// ── Process-global registry ────────────────────────────────────────

/// Thread-safe registry of all registered SPI buses.
pub mod registry {
    use super::SpiBus;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;

    pub static REGISTERED_COUNT: AtomicU32 = AtomicU32::new(0);

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn SpiBus>>> = IrqSafeSpinLock::new(Vec::new());

    /// Register `bus` if no bus with the same `name()` is present.
    /// Returns the existing Arc when a duplicate is found, otherwise
    /// the newly-inserted one. Cheap Arc clone on the fast path.
    pub fn register_unique(bus: Arc<dyn SpiBus>) -> Arc<dyn SpiBus> {
        let mut guard = REGISTRY.lock();
        if let Some(existing) = guard.iter().find(|b| b.name() == bus.name()) {
            return existing.clone();
        }
        guard.push(bus.clone());
        REGISTERED_COUNT.fetch_add(1, Ordering::Release);
        bus
    }

    /// Find a bus by name. O(n) — the list is short (≤8 buses on any
    /// real platform) so linear scan is fine.
    pub fn find(name: &str) -> Option<Arc<dyn SpiBus>> {
        REGISTRY.lock().iter().find(|b| b.name() == name).cloned()
    }

    /// Snapshot of all registered buses.
    pub fn list() -> Vec<Arc<dyn SpiBus>> {
        REGISTRY.lock().clone()
    }

    /// Count of registered buses.
    pub fn count() -> u32 {
        REGISTERED_COUNT.load(Ordering::Acquire)
    }

    /// Test-only: drain the registry so smokes start from a clean
    /// slate without leaking state into the next test.
    #[doc(hidden)]
    pub fn __reset_for_test() {
        let mut guard = REGISTRY.lock();
        guard.clear();
        REGISTERED_COUNT.store(0, Ordering::Release);
    }
}

// ── Initcall registration ──────────────────────────────────────────

/// Discover, instantiate, and register every supported SPI controller.
/// Called once during `Stage::Device`. Both AMD FCH and Intel LPSS
/// probes run as separate initcalls so a failure in one doesn't gate
/// the other.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "amd-fch-spi", || {
        let n = amd_fch::probe_all();
        if n == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
    narf_init::register(Stage::Device, "intel-lpss-spi", || {
        let n = intel_lpss::probe_all();
        if n == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
}

/// Snapshot of every registered SPI bus.
pub fn registered_buses() -> Vec<Arc<dyn SpiBus>> {
    registry::list()
}

/// Lock-free count of registered buses.
pub fn registered_bus_count() -> u32 {
    registry::REGISTERED_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
