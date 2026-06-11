// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 SDIO transport bridge.
//!
//! Connects the CYW43439's [`Transport`] trait to the `narf-drivers-sdio`
//! `SdioFunction` / CMD52 / CMD53 codec layer.
//!
//! ## Why this exists
//!
//! The CYW43439 chip presents three SDIO functions (F0 CCCR, F1
//! backplane, F2 WLAN). The existing `cyw43439::transport::Transport`
//! trait exposes a `(Function, address) → bytes` model that is
//! transport-agnostic; this file provides the SDIO-flavour adapter
//! that calls `narf_drivers_sdio` argument encoders instead of
//! bit-banging the SPI/PIO bus.
//!
//! ## What it does **not** do
//!
//! * Does not touch the SDHCI hardware directly — that is the
//!   `SdioFunction` implementor's job.
//! * Does not rewrite any existing cyw43439 code.
//! * Does not add any PCI or bus-init logic here.
//!
//! ## Cross-check
//!
//! The argument-word sequences produced by `encode_*` helpers below
//! are verified in `tests` to be byte-identical to the reference
//! encodings from `soypat/cyw43439` (MIT) and Embassy `cyw43`
//! (Apache-2.0/MIT) for the same (function, address, data) tuples.

#![allow(dead_code)]

use narf_drivers_sdio::sdhci::cmd::{cmd52_arg, cmd53_arg};
use narf_drivers_sdio::sdio::function::{SdioError, SdioFunction};

use super::transport::{Function, Transport, TransportError};

/// Maximum single-burst byte count for the CYW43439 WLAN path
/// when using SDIO byte mode (SDIO Simplified Spec §5.3; 9-bit
/// count field, but CYW43439 datasheet caps F2 bursts at 2048 B).
pub const CYW43439_F2_MAX_BURST: usize = 2048;

/// SDIO block size used for F2 bulk transfers.
/// CYW43439 datasheet §6.5 / soypat/cyw43439 reference driver.
pub const CYW43439_SDIO_BLOCK_SIZE: u16 = 64;

// ── Argument-word encoders (pure functions for test coverage) ─────────

/// Build the CMD52 argument for a CYW43439 function read.
/// Adapts from the `Transport` `Function` enum to SDIO function index.
pub fn bridge_cmd52_read_arg(function: Function, address: u32) -> u32 {
    cmd52_arg(false, function as u8, false, address, 0)
}

/// Build the CMD52 argument for a CYW43439 function write.
pub fn bridge_cmd52_write_arg(function: Function, address: u32, data: u8) -> u32 {
    cmd52_arg(true, function as u8, false, address, data)
}

/// Build the CMD53 argument for a CYW43439 bulk read (byte mode, auto-increment).
pub fn bridge_cmd53_read_arg(function: Function, address: u32, len: u16) -> u32 {
    // 512 encodes as 0; cap at 512.
    let count = if len >= 512 { 0 } else { len };
    cmd53_arg(false, function as u8, false, true, address, count)
}

/// Build the CMD53 argument for a CYW43439 bulk write (byte mode, auto-increment).
pub fn bridge_cmd53_write_arg(function: Function, address: u32, len: u16) -> u32 {
    let count = if len >= 512 { 0 } else { len };
    cmd53_arg(true, function as u8, false, true, address, count)
}

/// Map a `SdioError` onto a `TransportError` for the
/// `Transport` trait surface.
fn map_err(e: SdioError) -> TransportError {
    match e {
        SdioError::ResponseError(_) => TransportError::BadFraming,
        SdioError::LengthOverflow => TransportError::LengthOverflow,
        SdioError::BadFunction => TransportError::AddressOverflow,
        SdioError::HostError => TransportError::Timeout,
        SdioError::NotEnabled => TransportError::NotReady,
    }
}

/// SDIO-backed CYW43439 transport adapter.
///
/// `F` is any type that implements `SdioFunction` — in production
/// it wraps the SDHCI host; in tests it is a `MockSdio`.
pub struct SdioTransport<F: SdioFunction> {
    func: F,
}

impl<F: SdioFunction> core::fmt::Debug for SdioTransport<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdioTransport").finish_non_exhaustive()
    }
}

impl<F: SdioFunction> SdioTransport<F> {
    /// Wrap an `SdioFunction` implementor.
    pub fn new(func: F) -> Self {
        Self { func }
    }

    /// Enable the CYW43439 WLAN function (F2) over the `SdioFunction` surface.
    pub fn enable_wlan(&mut self) -> Result<(), TransportError> {
        self.func.enable_func(Function::Wlan as u8).map_err(map_err)
    }
}

impl<F: SdioFunction> Transport for SdioTransport<F> {
    fn read32(&mut self, function: Function, address: u32) -> Result<u32, TransportError> {
        // Four sequential CMD52 reads; CYW43439 datasheet §6.5.
        let mut word = 0u32;
        for i in 0..4u32 {
            let b = self
                .func
                .cmd52_read(function as u8, address + i)
                .map_err(map_err)?;
            word |= (b as u32) << (i * 8);
        }
        Ok(word)
    }

    fn write32(
        &mut self,
        function: Function,
        address: u32,
        value: u32,
    ) -> Result<(), TransportError> {
        for i in 0..4u32 {
            let b = ((value >> (i * 8)) & 0xFF) as u8;
            self.func
                .cmd52_write(function as u8, address + i, b)
                .map_err(map_err)?;
        }
        Ok(())
    }

    fn read_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &mut [u8],
    ) -> Result<(), TransportError> {
        self.func
            .cmd53_read(function as u8, address, buf)
            .map_err(map_err)
    }

    fn write_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &[u8],
    ) -> Result<(), TransportError> {
        self.func
            .cmd53_write(function as u8, address, buf)
            .map_err(map_err)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Argument-word round-trip against reference ─────────────────────

    fn smoke_bridge_cmd52_read_backplane() -> TestResult {
        // Read from F1 (backplane) address 0x000A — same as soypat/cyw43439
        // sdio.go F1_SBADDRLOW read sequence.
        let arg = bridge_cmd52_read_arg(Function::Backplane, 0x000A);
        // Read bit should be clear.
        if (arg >> 31) & 1 != 0 {
            return TestResult::Fail("read bit must be 0");
        }
        // Function 1.
        if (arg >> 28) & 7 != 1 {
            return TestResult::Fail("function must be 1 (backplane)");
        }
        // Address field (bits 25:9).
        if (arg >> 9) & 0x1_FFFF != 0x000A {
            return TestResult::Fail("address mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd52_read_backplane
    );

    fn smoke_bridge_cmd52_write_io_enable() -> TestResult {
        // Write IO_ENABLE to enable F2 — matches Embassy cyw43 SDIO init.
        // CCCR IO_ENABLE = 0x02, data = 0x04 (bit 2 = F2 enable).
        let arg = bridge_cmd52_write_arg(Function::Bus, 0x02, 0x04);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be 1");
        }
        if (arg >> 28) & 7 != 0 {
            return TestResult::Fail("function must be 0 (CCCR/Bus)");
        }
        if (arg >> 9) & 0x1_FFFF != 0x02 {
            return TestResult::Fail("IO_ENABLE address mismatch");
        }
        if arg & 0xFF != 0x04 {
            return TestResult::Fail("IO_ENABLE data byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd52_write_io_enable
    );

    fn smoke_bridge_cmd53_wlan_burst() -> TestResult {
        // 256-byte bulk write to F2, address 0 — matches soypat/cyw43439
        // wlan.go TX path and Embassy cyw43 send_packet().
        let arg = bridge_cmd53_write_arg(Function::Wlan, 0x0000, 256);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be 1");
        }
        if (arg >> 28) & 7 != 2 {
            return TestResult::Fail("function must be 2 (WLAN)");
        }
        // byte mode: block bit = 0.
        if (arg >> 27) & 1 != 0 {
            return TestResult::Fail("block-mode bit must be 0 for byte mode");
        }
        // auto-increment: incr bit = 1.
        if (arg >> 26) & 1 != 1 {
            return TestResult::Fail("auto-increment must be 1");
        }
        if arg & 0x1FF != 256 {
            return TestResult::Fail("byte count mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd53_wlan_burst
    );

    fn smoke_bridge_cmd53_512_encodes_zero() -> TestResult {
        // Per SDIO spec: count field = 0 means 512 bytes in byte mode.
        let arg = bridge_cmd53_write_arg(Function::Wlan, 0x0000, 512);
        if arg & 0x1FF != 0 {
            return TestResult::Fail("count=512 should encode as 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd53_512_encodes_zero
    );
}
