// SPDX-License-Identifier: GPL-2.0-or-later
//! `SdioFunction` abstraction — per-function CMD52 / CMD53 surface.
//!
//! Reference: SDIO Simplified Specification v3.00 §5 (I/O commands).

#![allow(dead_code)]

use crate::sdhci::cmd::{cmd52_arg, cmd53_arg};

/// Errors from SDIO function operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdioError {
    /// R5 response contained an error flag.
    ResponseError(u8),
    /// Transfer exceeded maximum block or byte count.
    LengthOverflow,
    /// Function number out of range [0, 7].
    BadFunction,
    /// Host controller rejected the command (timeout / CRC).
    HostError,
    /// Function is not yet enabled (I/O Enable not set).
    NotEnabled,
}

impl core::fmt::Display for SdioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SdioError::ResponseError(fl) => write!(f, "R5 error flags 0x{:02X}", fl),
            SdioError::LengthOverflow    => f.write_str("length overflow"),
            SdioError::BadFunction       => f.write_str("bad function number"),
            SdioError::HostError         => f.write_str("host error"),
            SdioError::NotEnabled        => f.write_str("function not enabled"),
        }
    }
}

/// Maximum byte count for a single CMD53 byte-mode transfer (2^9 - 1; 0 ≡ 512).
pub const CMD53_MAX_BYTE_COUNT: u16 = 512;
/// Maximum block count for a single CMD53 block-mode transfer.
pub const CMD53_MAX_BLOCK_COUNT: u16 = 511;

/// The capability surface a SDIO function exposes to its upper-level driver.
///
/// Implementors are concrete host-controller adapters (or mock adapters in
/// tests). The trait carries `&mut self` so adapters may hold mutable
/// state such as interrupt pending flags without interior mutability.
pub trait SdioFunction {
    /// Issue CMD52 — read a single byte from (func, addr).
    fn cmd52_read(&mut self, func: u8, addr: u32) -> Result<u8, SdioError>;

    /// Issue CMD52 — write a single byte to (func, addr).
    fn cmd52_write(&mut self, func: u8, addr: u32, val: u8) -> Result<(), SdioError>;

    /// Issue CMD53 in byte mode — read up to `buf.len()` bytes (≤ 512).
    fn cmd53_read(&mut self, func: u8, addr: u32, buf: &mut [u8]) -> Result<(), SdioError>;

    /// Issue CMD53 in byte mode — write `buf` (≤ 512 bytes).
    fn cmd53_write(&mut self, func: u8, addr: u32, buf: &[u8]) -> Result<(), SdioError>;

    /// Issue CMD53 in block mode — read `block_count` blocks into `buf`.
    fn cmd53_block_read(
        &mut self,
        func: u8,
        addr: u32,
        block_size: u16,
        block_count: u16,
        buf: &mut [u8],
    ) -> Result<(), SdioError>;

    /// Issue CMD53 in block mode — write `buf` as `block_count` blocks.
    fn cmd53_block_write(
        &mut self,
        func: u8,
        addr: u32,
        block_size: u16,
        block_count: u16,
        buf: &[u8],
    ) -> Result<(), SdioError>;

    /// Enable function `func` by setting bit `func` in CCCR IO_ENABLE.
    fn enable_func(&mut self, func: u8) -> Result<(), SdioError>;
}

/// Encode a CMD52 argument for a read and validate fields.
///
/// Returns `Err(SdioError::BadFunction)` if func > 7, or the 32-bit argument.
pub fn encode_cmd52_read(func: u8, addr: u32) -> Result<u32, SdioError> {
    if func > 7 {
        return Err(SdioError::BadFunction);
    }
    Ok(cmd52_arg(false, func, false, addr, 0))
}

/// Encode a CMD52 argument for a write.
pub fn encode_cmd52_write(func: u8, addr: u32, val: u8) -> Result<u32, SdioError> {
    if func > 7 {
        return Err(SdioError::BadFunction);
    }
    Ok(cmd52_arg(true, func, false, addr, val))
}

/// Encode a CMD53 argument for a byte-mode read.
pub fn encode_cmd53_byte_read(func: u8, addr: u32, len: u16) -> Result<u32, SdioError> {
    if func > 7 {
        return Err(SdioError::BadFunction);
    }
    if len == 0 || len > CMD53_MAX_BYTE_COUNT {
        return Err(SdioError::LengthOverflow);
    }
    // len == 512 encodes as 0 in the 9-bit count field.
    let count = if len == 512 { 0 } else { len };
    Ok(cmd53_arg(false, func, false, true, addr, count))
}

/// Encode a CMD53 argument for a byte-mode write.
pub fn encode_cmd53_byte_write(func: u8, addr: u32, len: u16) -> Result<u32, SdioError> {
    if func > 7 {
        return Err(SdioError::BadFunction);
    }
    if len == 0 || len > CMD53_MAX_BYTE_COUNT {
        return Err(SdioError::LengthOverflow);
    }
    let count = if len == 512 { 0 } else { len };
    Ok(cmd53_arg(true, func, false, true, addr, count))
}

/// Encode a CMD53 argument for a block-mode read.
pub fn encode_cmd53_block_read(
    func: u8,
    addr: u32,
    block_count: u16,
) -> Result<u32, SdioError> {
    if func > 7 {
        return Err(SdioError::BadFunction);
    }
    if block_count == 0 || block_count > CMD53_MAX_BLOCK_COUNT {
        return Err(SdioError::LengthOverflow);
    }
    Ok(cmd53_arg(false, func, true, true, addr, block_count))
}

/// Encode a CMD53 argument for a block-mode write.
pub fn encode_cmd53_block_write(
    func: u8,
    addr: u32,
    block_count: u16,
) -> Result<u32, SdioError> {
    if func > 7 {
        return Err(SdioError::BadFunction);
    }
    if block_count == 0 || block_count > CMD53_MAX_BLOCK_COUNT {
        return Err(SdioError::LengthOverflow);
    }
    Ok(cmd53_arg(true, func, true, true, addr, block_count))
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_encode_cmd52_read_fn0() -> TestResult {
        let arg = match encode_cmd52_read(0, 0x00) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("unexpected error"),
        };
        if (arg >> 31) & 1 != 0 {
            return TestResult::Fail("read bit set on a read");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/function", smoke_encode_cmd52_read_fn0);

    fn smoke_encode_cmd52_write_fn1() -> TestResult {
        let arg = match encode_cmd52_write(1, 0x100, 0xBE) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("unexpected error"),
        };
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit not set");
        }
        if (arg >> 28) & 7 != 1 {
            return TestResult::Fail("function field wrong");
        }
        if arg & 0xFF != 0xBE {
            return TestResult::Fail("data byte wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/function", smoke_encode_cmd52_write_fn1);

    fn smoke_encode_cmd53_byte_read_bounds() -> TestResult {
        // len = 0 should fail.
        if encode_cmd53_byte_read(1, 0, 0).is_ok() {
            return TestResult::Fail("len=0 should fail");
        }
        // len > 512 should fail.
        if encode_cmd53_byte_read(1, 0, 513).is_ok() {
            return TestResult::Fail("len=513 should fail");
        }
        // len = 512 is valid (encodes as 0).
        let arg = match encode_cmd53_byte_read(1, 0, 512) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("len=512 should succeed"),
        };
        if arg & 0x1FF != 0 {
            return TestResult::Fail("len=512 should encode count=0");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/function", smoke_encode_cmd53_byte_read_bounds);

    fn smoke_encode_cmd53_block_write() -> TestResult {
        let arg = match encode_cmd53_block_write(2, 0x1000, 4) {
            Ok(a) => a,
            Err(_) => return TestResult::Fail("unexpected error"),
        };
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit not set");
        }
        if (arg >> 27) & 1 != 1 {
            return TestResult::Fail("block-mode bit not set");
        }
        if arg & 0x1FF != 4 {
            return TestResult::Fail("block count wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/function", smoke_encode_cmd53_block_write);

    fn smoke_encode_bad_function() -> TestResult {
        // Function > 7 should be rejected for all encoders.
        if encode_cmd52_read(8, 0).is_ok() {
            return TestResult::Fail("func=8 should fail for CMD52 read");
        }
        if encode_cmd52_write(9, 0, 0).is_ok() {
            return TestResult::Fail("func=9 should fail for CMD52 write");
        }
        if encode_cmd53_byte_read(255, 0, 64).is_ok() {
            return TestResult::Fail("func=255 should fail for CMD53 read");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/sdio/function", smoke_encode_bad_function);
}
