//! SMBus protocol transactions over an [`I2cBus`].
//!
//! An SMBus host controller (PIIX4/FCH, i801) executes a fixed set of
//! protocol transactions in hardware; it cannot run arbitrary I2C
//! message sequences. Linux models this split with two adapter
//! callbacks: `master_xfer` (raw I2C) and `smbus_xfer` (SMBus), plus a
//! `functionality` mask saying which of them, and which SMBus sizes,
//! the adapter supports. Core code falls back to emulating an SMBus
//! transaction with raw I2C messages when the adapter has only
//! `master_xfer` (`i2c_smbus_xfer_emulated`, drivers/i2c/i2c-core-smbus.c).
//!
//! NARF mirrors that: [`I2cBus::smbus_xfer`] defaults to
//! [`emulate`], which builds the I2C message sequence for the
//! transaction and runs it through [`I2cBus::transfer`]; an SMBus-only
//! host overrides `smbus_xfer` and reports its native sizes through
//! [`I2cBus::functionality`].
//!
//! The helpers at the bottom (`read_byte_data`, `read_word_swapped`, …)
//! are the `i2c_smbus_*` client API (include/linux/i2c.h).

use crate::{I2cBus, I2cError, I2cOp};

/// Largest SMBus block transfer (`I2C_SMBUS_BLOCK_MAX`).
pub const SMBUS_BLOCK_MAX: usize = 32;

/// One SMBus protocol transaction (SMBus 3.2 §6.5). Read variants
/// carry the location the result is written to.
#[derive(Debug)]
pub enum SmbusOp<'a> {
    /// Quick command: the R/W bit is the only payload.
    Quick { read: bool },
    /// Receive byte: read one byte with no command code.
    ReceiveByte { out: &'a mut u8 },
    /// Send byte: write one byte with no command code.
    SendByte { value: u8 },
    /// Read byte data: command code, then read one byte.
    ReadByteData { cmd: u8, out: &'a mut u8 },
    /// Write byte data: command code and one data byte.
    WriteByteData { cmd: u8, value: u8 },
    /// Read word data: command code, then read a little-endian word.
    ReadWordData { cmd: u8, out: &'a mut u16 },
    /// Write word data: command code and a little-endian word.
    WriteWordData { cmd: u8, value: u16 },
    /// Block read: the device returns a count (1..=32) and that many
    /// bytes; `len` receives the count.
    ReadBlockData {
        cmd: u8,
        out: &'a mut [u8; SMBUS_BLOCK_MAX],
        len: &'a mut usize,
    },
    /// Block write: command code, count, then `data` (1..=32 bytes).
    WriteBlockData { cmd: u8, data: &'a [u8] },
}

/// Adapter functionality mask, bit-compatible with Linux's
/// `I2C_FUNC_*` (include/uapi/linux/i2c.h).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct I2cFunc(u32);

impl I2cFunc {
    /// Plain I2C message transfers (`I2C_FUNC_I2C`).
    pub const I2C: Self = Self(0x0000_0001);
    pub const SMBUS_QUICK: Self = Self(0x0001_0000);
    pub const SMBUS_READ_BYTE: Self = Self(0x0002_0000);
    pub const SMBUS_WRITE_BYTE: Self = Self(0x0004_0000);
    pub const SMBUS_READ_BYTE_DATA: Self = Self(0x0008_0000);
    pub const SMBUS_WRITE_BYTE_DATA: Self = Self(0x0010_0000);
    pub const SMBUS_READ_WORD_DATA: Self = Self(0x0020_0000);
    pub const SMBUS_WRITE_WORD_DATA: Self = Self(0x0040_0000);
    pub const SMBUS_READ_BLOCK_DATA: Self = Self(0x0100_0000);
    pub const SMBUS_WRITE_BLOCK_DATA: Self = Self(0x0200_0000);

    /// `I2C_FUNC_SMBUS_BYTE`.
    pub const SMBUS_BYTE: Self = Self(Self::SMBUS_READ_BYTE.0 | Self::SMBUS_WRITE_BYTE.0);
    /// `I2C_FUNC_SMBUS_BYTE_DATA`.
    pub const SMBUS_BYTE_DATA: Self =
        Self(Self::SMBUS_READ_BYTE_DATA.0 | Self::SMBUS_WRITE_BYTE_DATA.0);
    /// `I2C_FUNC_SMBUS_WORD_DATA`.
    pub const SMBUS_WORD_DATA: Self =
        Self(Self::SMBUS_READ_WORD_DATA.0 | Self::SMBUS_WRITE_WORD_DATA.0);
    /// `I2C_FUNC_SMBUS_BLOCK_DATA`.
    pub const SMBUS_BLOCK_DATA: Self =
        Self(Self::SMBUS_READ_BLOCK_DATA.0 | Self::SMBUS_WRITE_BLOCK_DATA.0);

    /// What [`emulate`] can build from plain I2C messages: everything
    /// but Quick (a zero-length message) and block read (which needs
    /// the receive-length message flag the [`I2cOp`] model lacks).
    pub const EMULATED: Self = Self(
        Self::I2C.0
            | Self::SMBUS_BYTE.0
            | Self::SMBUS_BYTE_DATA.0
            | Self::SMBUS_WORD_DATA.0
            | Self::SMBUS_WRITE_BLOCK_DATA.0,
    );

    /// The raw `I2C_FUNC_*` bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is set (`i2c_check_functionality`).
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Bitwise union.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for I2cFunc {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Run `op` as plain I2C messages through `bus.transfer`, as Linux's
/// `i2c_smbus_xfer_emulated` does for adapters without `smbus_xfer`.
/// Quick and block read have no [`I2cOp`] encoding and return
/// [`I2cError::Unsupported`].
pub async fn emulate<B: I2cBus + ?Sized>(
    bus: &B,
    addr: u8,
    op: SmbusOp<'_>,
) -> Result<(), I2cError> {
    match op {
        SmbusOp::Quick { .. } | SmbusOp::ReadBlockData { .. } => Err(I2cError::Unsupported),
        SmbusOp::ReceiveByte { out } => {
            let mut buf = [0u8; 1];
            bus.transfer(addr, &mut [I2cOp::Read(&mut buf)]).await?;
            *out = buf[0];
            Ok(())
        }
        SmbusOp::SendByte { value } => bus.transfer(addr, &mut [I2cOp::Write(&[value])]).await,
        SmbusOp::ReadByteData { cmd, out } => {
            let mut buf = [0u8; 1];
            bus.transfer(addr, &mut [I2cOp::Write(&[cmd]), I2cOp::Read(&mut buf)])
                .await?;
            *out = buf[0];
            Ok(())
        }
        SmbusOp::WriteByteData { cmd, value } => {
            bus.transfer(addr, &mut [I2cOp::Write(&[cmd, value])]).await
        }
        SmbusOp::ReadWordData { cmd, out } => {
            let mut buf = [0u8; 2];
            bus.transfer(addr, &mut [I2cOp::Write(&[cmd]), I2cOp::Read(&mut buf)])
                .await?;
            *out = u16::from_le_bytes(buf);
            Ok(())
        }
        SmbusOp::WriteWordData { cmd, value } => {
            let [lo, hi] = value.to_le_bytes();
            bus.transfer(addr, &mut [I2cOp::Write(&[cmd, lo, hi])])
                .await
        }
        SmbusOp::WriteBlockData { cmd, data } => {
            // i2c_smbus_xfer_emulated: an `I2C_SMBUS_BLOCK_DATA` write
            // longer than I2C_SMBUS_BLOCK_MAX is -EINVAL; a zero count
            // goes out as command + count. (Native hosts differ: piix4
            // also refuses zero.)
            if data.len() > SMBUS_BLOCK_MAX {
                return Err(I2cError::InvalidArgs);
            }
            let mut buf = [0u8; SMBUS_BLOCK_MAX + 2];
            buf[0] = cmd;
            buf[1] = data.len() as u8;
            buf[2..2 + data.len()].copy_from_slice(data);
            bus.transfer(addr, &mut [I2cOp::Write(&buf[..2 + data.len()])])
                .await
        }
    }
}

// ── Client helpers (`i2c_smbus_*`) ───────────────────────────────────

/// `i2c_smbus_read_byte`: receive byte.
pub async fn read_byte<B: I2cBus + ?Sized>(bus: &B, addr: u8) -> Result<u8, I2cError> {
    let mut out = 0u8;
    bus.smbus_xfer(addr, SmbusOp::ReceiveByte { out: &mut out })
        .await?;
    Ok(out)
}

/// `i2c_smbus_read_byte_data`.
pub async fn read_byte_data<B: I2cBus + ?Sized>(
    bus: &B,
    addr: u8,
    cmd: u8,
) -> Result<u8, I2cError> {
    let mut out = 0u8;
    bus.smbus_xfer(addr, SmbusOp::ReadByteData { cmd, out: &mut out })
        .await?;
    Ok(out)
}

/// `i2c_smbus_write_byte_data`.
pub async fn write_byte_data<B: I2cBus + ?Sized>(
    bus: &B,
    addr: u8,
    cmd: u8,
    value: u8,
) -> Result<(), I2cError> {
    bus.smbus_xfer(addr, SmbusOp::WriteByteData { cmd, value })
        .await
}

/// `i2c_smbus_read_word_data`: the SMBus word is little-endian.
pub async fn read_word_data<B: I2cBus + ?Sized>(
    bus: &B,
    addr: u8,
    cmd: u8,
) -> Result<u16, I2cError> {
    let mut out = 0u16;
    bus.smbus_xfer(addr, SmbusOp::ReadWordData { cmd, out: &mut out })
        .await?;
    Ok(out)
}

/// `i2c_smbus_read_word_swapped`: a word whose device-side byte order
/// is big-endian.
pub async fn read_word_swapped<B: I2cBus + ?Sized>(
    bus: &B,
    addr: u8,
    cmd: u8,
) -> Result<u16, I2cError> {
    read_word_data(bus, addr, cmd).await.map(u16::swap_bytes)
}

/// `i2c_smbus_write_word_data`.
pub async fn write_word_data<B: I2cBus + ?Sized>(
    bus: &B,
    addr: u8,
    cmd: u8,
    value: u16,
) -> Result<(), I2cError> {
    bus.smbus_xfer(addr, SmbusOp::WriteWordData { cmd, value })
        .await
}
