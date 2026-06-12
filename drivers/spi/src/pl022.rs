//! ARM PrimeCell PL022 SPI controller driver.
//!
//! Provides support for the ARM PL022 Synchronous Serial Port (SSP)
//! controller, ubiquitous across many ARM platforms.
//!
//! References: `linux/drivers/spi/spi-pl022.c`

extern crate alloc;

/// Probe for PL022 SPI controllers.
pub fn probe_all() -> usize {
    // Placeholder for PL022 SPI discovery
    0
}
