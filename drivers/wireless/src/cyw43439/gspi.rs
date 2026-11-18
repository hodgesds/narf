//! CYW43439 command codec, Infineon 002-30348 Rev. *D §4.2.
//! Normal raw commands and integer payloads are little endian. Bootstrap
//! swaps bytes within each 16-bit word; RAM/SDPCM bytes stay unchanged.
//! Cross-check: MIT cyw43-driver fa9627e6076c61b58632289a36fcab4811f32c3a.

use core::fmt;

/// gSPI access function (datasheet §4.2 Table 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Function {
    /// Bus-control register window (gSPI-specific status / config).
    Bus = 0,
    /// Backplane access through the SDIO-equivalent F1.
    Backplane = 1,
    /// WLAN bulk-data path (the SDIO-equivalent F2).
    Wlan = 2,
    /// Bluetooth data path (combo parts only).
    Bt = 3,
}

impl Function {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0b11 {
            0 => Some(Function::Bus),
            1 => Some(Function::Backplane),
            2 => Some(Function::Wlan),
            3 => Some(Function::Bt),
            _ => None,
        }
    }
}

impl From<super::transport::Function> for Function {
    fn from(f: super::transport::Function) -> Self {
        match f {
            super::transport::Function::Bus => Function::Bus,
            super::transport::Function::Backplane => Function::Backplane,
            super::transport::Function::Wlan => Function::Wlan,
            super::transport::Function::Bt => Function::Bt,
        }
    }
}

/// Direction bit of the command word (datasheet §4.2 Figure 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Read,
    Write,
}

/// Address-increment policy for the access (datasheet §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    /// Address is held constant for every byte of the burst (FIFO
    /// access, e.g. backplane data window).
    Fixed,
    /// Address auto-increments per byte (register-block access).
    Increment,
}

/// Maximum payload length encoded in a single gSPI command word.
/// The zero length field encodes 2048 bytes. F1 separately limits bursts to 64.
pub const MAX_LEN: u16 = 2048;
const LENGTH_MASK: u32 = 0x7ff;

/// Address mask: 17 bits per datasheet §4.2 Table 5.
pub const ADDR_MASK: u32 = 0x1FFFF;

/// 32-bit gSPI command word.
///
/// Layout (MSB → LSB), per datasheet §4.2 Figure 10:
///
/// ```text
///  31    30    29-28  27-11      10-0
/// ┌────┬────┬─────┬──────────┬──────────┐
/// │ RW │ AI │ FN  │  ADDR    │  LENGTH  │
/// └────┴────┴─────┴──────────┴──────────┘
/// ```
///
/// - `RW`     — 1 = write to chip, 0 = read from chip.
/// - `AI`     — 1 = auto-increment address, 0 = fixed.
/// - `FN`     — 2-bit access function (see [`Function`]).
/// - `ADDR`   — 17-bit address into the function's window.
/// - `LENGTH` — 11-bit byte count for the burst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandWord {
    pub direction: Direction,
    pub addr_mode: AddrMode,
    pub function: Function,
    pub address: u32,
    pub length: u16,
}

/// Errors that can arise when validating / decoding a [`CommandWord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandError {
    /// Address exceeds the 17-bit field.
    AddressOverflow,
    /// Length is zero or exceeds 2048 bytes.
    LengthOverflow,
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::AddressOverflow => f.write_str("gSPI address > 17 bits"),
            CommandError::LengthOverflow => f.write_str("gSPI length outside 1..=2048"),
        }
    }
}

impl CommandWord {
    /// Convenience constructor for the common register-style access:
    /// auto-increment + 32-bit width.
    pub fn reg(
        direction: Direction,
        function: Function,
        address: u32,
    ) -> Result<Self, CommandError> {
        Self::new(direction, AddrMode::Increment, function, address, 4)
    }

    /// Construct a command word, validating field widths.
    pub fn new(
        direction: Direction,
        addr_mode: AddrMode,
        function: Function,
        address: u32,
        length: u16,
    ) -> Result<Self, CommandError> {
        if address & !ADDR_MASK != 0 {
            return Err(CommandError::AddressOverflow);
        }
        if length == 0 || length > MAX_LEN {
            return Err(CommandError::LengthOverflow);
        }
        Ok(Self {
            direction,
            addr_mode,
            function,
            address,
            length,
        })
    }

    /// Serialize to the 32-bit on-the-wire word (host-order; the
    /// caller is responsible for byte-ordering on the SPI link).
    pub fn encode(self) -> u32 {
        let rw: u32 = match self.direction {
            Direction::Read => 0,
            Direction::Write => 1,
        };
        let ai: u32 = match self.addr_mode {
            AddrMode::Fixed => 0,
            AddrMode::Increment => 1,
        };
        let fn_bits: u32 = u32::from(self.function.as_u8()) & 0b11;
        let addr_bits: u32 = self.address & ADDR_MASK;
        let len_bits: u32 = u32::from(self.length) & LENGTH_MASK;
        (rw << 31) | (ai << 30) | (fn_bits << 28) | (addr_bits << 11) | len_bits
    }

    /// Parse a 32-bit on-the-wire word back into a [`CommandWord`].
    pub fn decode(word: u32) -> Self {
        let direction = if (word >> 31) & 1 == 1 {
            Direction::Write
        } else {
            Direction::Read
        };
        let addr_mode = if (word >> 30) & 1 == 1 {
            AddrMode::Increment
        } else {
            AddrMode::Fixed
        };
        // Function field is 2 bits; from_u8 always succeeds for that mask.
        let function = Function::from_u8(((word >> 28) & 0b11) as u8).unwrap_or(Function::Bus);
        let address = (word >> 11) & ADDR_MASK;
        let encoded_length = (word & LENGTH_MASK) as u16;
        let length = if encoded_length == 0 {
            MAX_LEN
        } else {
            encoded_length
        };
        Self {
            direction,
            addr_mode,
            function,
            address,
            length,
        }
    }
}

// ── Bus-control register addresses (datasheet §4.2 Table 6) ─────

/// gSPI bus setup / endianness control (datasheet §4.2 Table 6).
pub const REG_BUS_CTRL: u32 = 0x0000;
/// gSPI bus response delay (datasheet §4.2 Table 6).
pub const REG_RESPONSE_DELAY_F0: u32 = 0x001c;
/// Individual F1 read response delay.
pub const REG_RESPONSE_DELAY_F1: u32 = 0x001d;
/// gSPI status register (datasheet §4.2 Table 6). Read explicitly;
/// the source profile disables automatic status trailers.
pub const REG_STATUS: u32 = 0x0008;
/// gSPI test read register — pre-initialised by silicon to a fixed
/// value the host uses to confirm endianness selection (datasheet
/// §6.4 Table 6). The factory default value is `0xFEEDBEAD`.
pub const REG_TEST_RO: u32 = 0x0014;
/// Factory pattern returned in `REG_TEST_RO` when the host has the
/// gSPI byte-order configured correctly (datasheet §4.2 Table 6).
pub const TEST_RO_PATTERN: u32 = 0xFEED_BEAD;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_gspi_cmd_word_round_trip() -> TestResult {
        // A representative read-from-backplane register access.
        let cmd = CommandWord::new(
            Direction::Read,
            AddrMode::Increment,
            Function::Backplane,
            0x1_8000,
            4,
        )
        .expect("valid fields");
        let word = cmd.encode();
        let decoded = CommandWord::decode(word);
        if decoded != cmd {
            return TestResult::Fail("gSPI command word round-trip mismatch");
        }
        // Bit-level invariants: read direction, increment, function 1.
        if (word >> 31) & 1 != 0 {
            return TestResult::Fail("read direction should clear bit 31");
        }
        if (word >> 30) & 1 != 1 {
            return TestResult::Fail("increment mode should set bit 30");
        }
        if (word >> 28) & 0b11 != 1 {
            return TestResult::Fail("function field should be 1 (backplane)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/gspi",
        smoke_gspi_cmd_word_round_trip
    );

    fn smoke_gspi_cmd_word_validation() -> TestResult {
        match CommandWord::new(
            Direction::Write,
            AddrMode::Fixed,
            Function::Wlan,
            ADDR_MASK + 1,
            0,
        ) {
            Err(CommandError::AddressOverflow) => {}
            other => {
                let _ = other;
                return TestResult::Fail("address overflow not rejected");
            }
        }
        match CommandWord::new(
            Direction::Write,
            AddrMode::Fixed,
            Function::Wlan,
            0,
            MAX_LEN + 1,
        ) {
            Err(CommandError::LengthOverflow) => {}
            other => {
                let _ = other;
                return TestResult::Fail("length overflow not rejected");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/gspi",
        smoke_gspi_cmd_word_validation
    );

    fn smoke_gspi_zero_field_encodes_2048_not_empty() -> TestResult {
        let cmd = CommandWord::new(
            Direction::Write,
            AddrMode::Increment,
            Function::Wlan,
            0,
            2048,
        )
        .unwrap();
        if cmd.encode().to_le_bytes() != [0, 0, 0, 0xe0]
            || CommandWord::decode(0xe0000000).length != 2048
            || !matches!(
                CommandWord::new(Direction::Read, AddrMode::Increment, Function::Wlan, 0, 0),
                Err(CommandError::LengthOverflow)
            )
        {
            return TestResult::Fail("zero length field confused with an empty transaction");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/gspi",
        smoke_gspi_zero_field_encodes_2048_not_empty
    );
}
