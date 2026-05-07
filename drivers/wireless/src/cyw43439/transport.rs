//! CYW43439 transport-abstraction trait.
//!
//! The chip exposes the same logical address space behind two
//! physically-different host interfaces: gSPI (datasheet §6.4) and
//! 4-bit SDIO (datasheet §3.1 + §6.5). Both expose the same
//! `(function, address) → bytes` model from the driver's
//! perspective. This trait is the seam between those host adapters
//! and the upper-half (firmware loader, IOCTL codec) of the driver.
//!
//! Adapters live outside this crate — for SDIO, the future
//! `narf-bus` SDIO host controller; for gSPI, the platform's SPI
//! controller wrapped by the boot path.
//!
//! **No GPL `brcmfmac` / `bcmdhd` source consulted.** Cross-checks:
//! `soypat/cyw43439` (MIT) and Embassy `cyw43` (Apache-2.0 / MIT).

use core::fmt;

/// Logical access function on the chip. The numeric encoding
/// matches both the SDIO function index (datasheet §3.1) and the
/// gSPI function field (datasheet §6.4 Table 6-2), so the same
/// enum drives both transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Function {
    /// F0 (SDIO CCCR) / gSPI bus-control window.
    Bus = 0,
    /// F1 backplane access window.
    Backplane = 1,
    /// F2 WLAN bulk-data path.
    Wlan = 2,
    /// F3 BT data path (combo parts).
    Bt = 3,
}

impl Function {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Errors a transport adapter may report up to the driver. Adapters
/// translate their hardware-specific errors into these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// Transport reported a CRC failure / bad framing on the wire.
    BadFraming,
    /// The chip reported an `OVERFLOW` / `UNDERFLOW` status bit.
    ChipFlowError,
    /// Caller asked for an access wider than the transport supports.
    LengthOverflow,
    /// Caller asked for an address outside the function's window.
    AddressOverflow,
    /// Adapter timed out waiting for the chip's response.
    Timeout,
    /// Transport is not currently usable (powered-off / not init'd).
    NotReady,
    /// Adapter-specific failure code, opaque to the driver.
    Other(u32),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::BadFraming => f.write_str("bad framing"),
            TransportError::ChipFlowError => f.write_str("chip flow error"),
            TransportError::LengthOverflow => f.write_str("length overflow"),
            TransportError::AddressOverflow => f.write_str("address overflow"),
            TransportError::Timeout => f.write_str("transport timeout"),
            TransportError::NotReady => f.write_str("transport not ready"),
            TransportError::Other(_) => f.write_str("transport error"),
        }
    }
}

/// Synchronous transport surface — the minimal access layer the
/// firmware loader needs. Adapters that are inherently async wrap
/// this in their own executor.
///
/// The trait carries no `&mut self` requirement on individual
/// accesses so an adapter can choose between exclusive ownership
/// (single-task driver) and a sharded interior-mutability strategy
/// (multi-CPU bring-up), at the implementor's discretion.
pub trait Transport {
    /// Read a single 32-bit register through `function:address`.
    /// Address auto-increments unless the adapter explicitly fixes
    /// it (FIFO mode); for register reads the auto-increment policy
    /// is irrelevant because `length == 4`.
    fn read32(&mut self, function: Function, address: u32) -> Result<u32, TransportError>;

    /// Write a single 32-bit register at `function:address`.
    fn write32(
        &mut self,
        function: Function,
        address: u32,
        value: u32,
    ) -> Result<(), TransportError>;

    /// Read `buf.len()` bytes from `function:address` (auto-
    /// increment). The split into transport-sized bursts (gSPI
    /// max 2047 bytes, SDIO max 511 blocks of 64 bytes) is the
    /// adapter's responsibility.
    fn read_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &mut [u8],
    ) -> Result<(), TransportError>;

    /// Write `buf` at `function:address` (auto-increment).
    fn write_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &[u8],
    ) -> Result<(), TransportError>;
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_function_round_trip() -> TestResult {
        for (f, n) in [
            (Function::Bus, 0u8),
            (Function::Backplane, 1),
            (Function::Wlan, 2),
            (Function::Bt, 3),
        ] {
            if f.as_u8() != n {
                return TestResult::Fail("function enum mis-encoded");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/transport",
        smoke_function_round_trip
    );
}
