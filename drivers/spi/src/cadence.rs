//! Cadence SPI controller driver.
//!
//! Provides support for the Cadence SPI controller found in many ARM
//! and Xilinx Zynq SoCs.
//!
//! References: `linux/drivers/spi/spi-cadence.c`

extern crate alloc;

/// Probe for Cadence SPI controllers.
pub fn probe_all() -> usize {
    // Placeholder for Cadence SPI discovery
    0
}
