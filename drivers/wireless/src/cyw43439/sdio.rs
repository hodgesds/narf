//! SDIO host-interface helpers for the CYW43439.
//!
//! Reference set:
//!
//! - **CYW43439 datasheet Rev. 03 §3.1** — describes the three-
//!   function SDIO model (F0 control, F1 backplane, F2 WLAN).
//! - **SD Specifications, Part E1: SDIO Simplified Specification
//!   v3.00** (public, SD Association). Defines CMD52 (single-byte
//!   I/O) and CMD53 (multi-byte / block I/O) plus the F0 Common
//!   Card Information (CCCR) register layout the chip honours.
//!   <https://www.sdcard.org/downloads/pls/>
//!
//! This module provides the codec-only pieces: argument-word
//! packing for CMD52 / CMD53 and the symbolic addresses of the F0
//! and F1 registers the driver actually programs. **No GPL
//! `brcmfmac` / `bcmdhd` source consulted.**

use core::fmt;

/// SDIO function indices (datasheet §3.1).
pub const FUNC_F0_CONTROL: u8 = 0;
pub const FUNC_F1_BACKPLANE: u8 = 1;
pub const FUNC_F2_WLAN: u8 = 2;
pub const FUNC_F3_BT: u8 = 3;

// ── F0 (CCCR) register addresses (SDIO Simplified Spec §6.9) ──────

/// CCCR / SDIO revision (read-only). `0x00`.
pub const CCCR_SDIO_REVISION: u32 = 0x00;
/// I/O Enable — bit N enables function N. `0x02`.
pub const CCCR_IO_ENABLE: u32 = 0x02;
/// I/O Ready — bit N reflects function-N READY status. `0x03`.
pub const CCCR_IO_READY: u32 = 0x03;
/// Interrupt Enable — bit 0 master enable, bit N enables fn N. `0x04`.
pub const CCCR_INT_ENABLE: u32 = 0x04;
/// Interrupt Pending. `0x05`.
pub const CCCR_INT_PENDING: u32 = 0x05;
/// I/O Abort. `0x06`.
pub const CCCR_IO_ABORT: u32 = 0x06;
/// Bus Interface Control — sets bus width (1-bit / 4-bit). `0x07`.
pub const CCCR_BUS_IFACE_CTRL: u32 = 0x07;

/// Bus-width selector for [`CCCR_BUS_IFACE_CTRL`] (SDIO Simplified
/// Spec §6.9 Table 6-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BusWidth {
    OneBit = 0b00,
    FourBit = 0b10,
}

// ── F1 backplane registers (datasheet §6.5 Table 6-7) ─────────────

/// F1: low byte of the backplane window base address.
pub const F1_SBADDRLOW: u32 = 0x1_000A;
/// F1: middle byte of the backplane window base address.
pub const F1_SBADDRMID: u32 = 0x1_000B;
/// F1: high byte of the backplane window base address.
pub const F1_SBADDRHIGH: u32 = 0x1_000C;
/// F1 chip-clock control register (datasheet §6.5 Table 6-7). Used
/// to gate the ALP / HT clocks during firmware load.
pub const F1_CHIPCLK_CTRL: u32 = 0x1_000E;
/// F1 sleep / wake control register (datasheet §6.5 Table 6-7).
pub const F1_SLEEP_CSR: u32 = 0x1_000F;

/// CMD52 (single-byte I/O) raw argument word (SDIO Simplified Spec
/// §5.1 Figure 5-1).
///
/// ```text
///   31 | 30-28 | 27 | 26 | 25-9          | 8 | 7-0
///   RW |  FN   | RAW| 0  | REGISTER ADDR | 0 | DATA
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cmd52Arg {
    pub direction: Direction,
    /// Read-after-write — for write-with-readback transactions.
    pub raw: bool,
    pub function: u8,
    pub address: u32,
    pub data: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd52Error {
    AddressOverflow,
    FunctionOverflow,
}

impl fmt::Display for Cmd52Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cmd52Error::AddressOverflow => f.write_str("CMD52 address > 17 bits"),
            Cmd52Error::FunctionOverflow => f.write_str("CMD52 function > 3 bits"),
        }
    }
}

impl Cmd52Arg {
    /// 17-bit address mask (SDIO Simplified Spec §5.1).
    pub const ADDR_MASK: u32 = 0x1_FFFF;
    /// 3-bit function field.
    pub const FUNC_MASK: u8 = 0b111;

    pub fn read(function: u8, address: u32) -> Result<Self, Cmd52Error> {
        Self::new(Direction::Read, false, function, address, 0)
    }

    pub fn write(function: u8, address: u32, data: u8) -> Result<Self, Cmd52Error> {
        Self::new(Direction::Write, false, function, address, data)
    }

    pub fn new(
        direction: Direction,
        raw: bool,
        function: u8,
        address: u32,
        data: u8,
    ) -> Result<Self, Cmd52Error> {
        if address & !Self::ADDR_MASK != 0 {
            return Err(Cmd52Error::AddressOverflow);
        }
        if function & !Self::FUNC_MASK != 0 {
            return Err(Cmd52Error::FunctionOverflow);
        }
        Ok(Self {
            direction,
            raw,
            function,
            address,
            data,
        })
    }

    /// Encode to the 32-bit CMD52 argument word.
    pub fn encode(self) -> u32 {
        let rw = match self.direction {
            Direction::Read => 0u32,
            Direction::Write => 1u32,
        };
        let raw = if self.raw { 1u32 } else { 0u32 };
        (rw << 31)
            | ((u32::from(self.function) & 0b111) << 28)
            | (raw << 27)
            | ((self.address & Self::ADDR_MASK) << 9)
            | u32::from(self.data)
    }
}

/// CMD53 (multi-byte / block I/O) raw argument word (SDIO Simplified
/// Spec §5.3 Figure 5-3).
///
/// ```text
///   31 | 30-28 | 27       | 26   | 25-9          | 8-0
///   RW |  FN   | BLOCKMODE| INCR | REGISTER ADDR | COUNT
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cmd53Arg {
    pub direction: Direction,
    pub function: u8,
    pub block_mode: bool,
    pub op_increment: bool,
    pub address: u32,
    /// In byte mode: number of bytes (1-512). In block mode: number
    /// of blocks (1-511, with 0 meaning "infinite block count").
    pub count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmd53Error {
    AddressOverflow,
    FunctionOverflow,
    CountOverflow,
}

impl Cmd53Arg {
    /// 9-bit count field.
    pub const COUNT_MASK: u16 = 0x1FF;

    pub fn new(
        direction: Direction,
        function: u8,
        block_mode: bool,
        op_increment: bool,
        address: u32,
        count: u16,
    ) -> Result<Self, Cmd53Error> {
        if address & !Cmd52Arg::ADDR_MASK != 0 {
            return Err(Cmd53Error::AddressOverflow);
        }
        if function & !Cmd52Arg::FUNC_MASK != 0 {
            return Err(Cmd53Error::FunctionOverflow);
        }
        if count & !Self::COUNT_MASK != 0 {
            return Err(Cmd53Error::CountOverflow);
        }
        Ok(Self {
            direction,
            function,
            block_mode,
            op_increment,
            address,
            count,
        })
    }

    pub fn encode(self) -> u32 {
        let rw = match self.direction {
            Direction::Read => 0u32,
            Direction::Write => 1u32,
        };
        let block = if self.block_mode { 1u32 } else { 0u32 };
        let incr = if self.op_increment { 1u32 } else { 0u32 };
        (rw << 31)
            | ((u32::from(self.function) & 0b111) << 28)
            | (block << 27)
            | (incr << 26)
            | ((self.address & Cmd52Arg::ADDR_MASK) << 9)
            | (u32::from(self.count) & u32::from(Self::COUNT_MASK))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_cmd52_io_enable_write() -> TestResult {
        // Drive F2 enable: write 0x04 to CCCR_IO_ENABLE on F0.
        let arg = Cmd52Arg::write(FUNC_F0_CONTROL, CCCR_IO_ENABLE, 0x04).expect("valid CMD52 args");
        let word = arg.encode();
        // Bit 31 should be set (write).
        if (word >> 31) & 1 != 1 {
            return TestResult::Fail("CMD52 write direction bit not set");
        }
        // Function field (bits 28-30) should be zero.
        if (word >> 28) & 0b111 != 0 {
            return TestResult::Fail("CMD52 function should be 0 (CCCR)");
        }
        // Address field (bits 9-25) should equal CCCR_IO_ENABLE.
        if (word >> 9) & Cmd52Arg::ADDR_MASK != CCCR_IO_ENABLE {
            return TestResult::Fail("CMD52 address field misaligned");
        }
        if word & 0xFF != 0x04 {
            return TestResult::Fail("CMD52 data field misaligned");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio",
        smoke_cmd52_io_enable_write
    );

    fn smoke_cmd53_block_burst() -> TestResult {
        // 8 blocks of incrementing-address writes to F2 (a typical
        // bulk-data submission to the WLAN function).
        let arg = Cmd53Arg::new(Direction::Write, FUNC_F2_WLAN, true, true, 0, 8)
            .expect("valid CMD53 args");
        let word = arg.encode();
        if (word >> 31) & 1 != 1 {
            return TestResult::Fail("CMD53 write direction bit not set");
        }
        if (word >> 28) & 0b111 != 2 {
            return TestResult::Fail("CMD53 function should be 2 (WLAN)");
        }
        if (word >> 27) & 1 != 1 {
            return TestResult::Fail("CMD53 block-mode bit not set");
        }
        if (word >> 26) & 1 != 1 {
            return TestResult::Fail("CMD53 op-increment bit not set");
        }
        if word & u32::from(Cmd53Arg::COUNT_MASK) != 8 {
            return TestResult::Fail("CMD53 count field misaligned");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/sdio", smoke_cmd53_block_burst);
}
