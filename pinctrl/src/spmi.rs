//! MIPI SPMI 2.0 master-to-slave command codec.
//!
//! ## Reference (public only)
//!
//! - **MIPI Alliance Specification for System Power Management
//!   Interface (SPMI)**, Version 2.0. Public summary at
//!   <https://www.mipi.org/specifications/spmi>.
//!
//! No GPL / Linux source consulted.
//!
//! ## Wire format (SPMI 2.0 §5.1)
//!
//! Every master-to-slave command starts with a 4-bit Slave Slave
//! Address (SID) + a Command byte; the Command byte's upper bits
//! identify the operation. We support the operations Qualcomm
//! PMICs and similar chips actually use:
//!
//! ```text
//!   Extended Register Read (long):  0b0011_xxxx | <addr_h:8> | <addr_l:8> | <byte_count - 1: 4>
//!   Extended Register Write (long): 0b0001_xxxx | <addr_h:8> | <addr_l:8> | <byte_count - 1: 4> | <data...>
//!   Register Read (short):          0b0010_0xxx | <addr_h:5> | <addr_l: implicit byte 0>
//!   Register Write (short):         0b0100_xxxx | <addr_l:5>          | <data:8>
//!   Register Zero Write:            0b0001_0xxx | <data:8>
//!   Reset:                          0b0001_1101
//!   Sleep:                          0b0001_1100
//!   Shutdown:                       0b0001_1011
//!   Wakeup:                         0b0001_1010
//! ```
//!
//! This module covers the read/write codecs (extended forms — the
//! 16-bit-address variants every PMIC actually uses).

extern crate alloc;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpmiError {
    Short,
    BadOpcode,
    /// More data bytes promised by the byte-count field than fit
    /// in the buffer.
    Truncated,
}

/// Build an Extended Register Write (long form): writes `data` to
/// the slave at 16-bit register `addr`. `data.len()` must be 1..=16.
pub fn build_ext_write(sid: u8, addr: u16, data: &[u8]) -> Vec<u8> {
    assert!(
        (1..=16).contains(&data.len()),
        "ext write byte count 1..=16"
    );
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.push((sid & 0xF) << 4);
    let opcode = 0x10 | ((data.len() as u8 - 1) & 0x0F);
    buf.push(opcode);
    buf.push((addr >> 8) as u8);
    buf.push((addr & 0xFF) as u8);
    buf.extend_from_slice(data);
    buf
}

/// Build an Extended Register Read (long form): asks the slave at
/// 16-bit register `addr` to return `byte_count` (1..=16) bytes.
pub fn build_ext_read(sid: u8, addr: u16, byte_count: usize) -> Vec<u8> {
    assert!((1..=16).contains(&byte_count), "ext read byte count 1..=16");
    let mut buf = Vec::with_capacity(4);
    buf.push((sid & 0xF) << 4);
    let opcode = 0x30 | ((byte_count as u8 - 1) & 0x0F);
    buf.push(opcode);
    buf.push((addr >> 8) as u8);
    buf.push((addr & 0xFF) as u8);
    buf
}

/// Decoded command header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CommandHeader {
    pub sid: u8,
    pub op: SpmiOp,
    /// Register address (16-bit for extended forms).
    pub addr: u16,
    /// Byte count (1..=16) for extended forms; 1 for short.
    pub byte_count: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SpmiOp {
    ExtWrite,
    ExtRead,
}

pub fn decode_header(buf: &[u8]) -> Result<CommandHeader, SpmiError> {
    if buf.len() < 4 {
        return Err(SpmiError::Short);
    }
    let sid = (buf[0] >> 4) & 0xF;
    let opc = buf[1];
    let op_high = opc & 0xF0;
    let op = match op_high {
        0x10 => SpmiOp::ExtWrite,
        0x30 => SpmiOp::ExtRead,
        _ => return Err(SpmiError::BadOpcode),
    };
    let bc = (opc & 0x0F) + 1;
    let addr = ((buf[2] as u16) << 8) | (buf[3] as u16);
    Ok(CommandHeader {
        sid,
        op,
        addr,
        byte_count: bc,
    })
}

/// Decode a write packet into (header, data slice). Validates that
/// the buffer holds at least `byte_count` data bytes after the
/// header.
pub fn decode_write(buf: &[u8]) -> Result<(CommandHeader, &[u8]), SpmiError> {
    let h = decode_header(buf)?;
    if h.op != SpmiOp::ExtWrite {
        return Err(SpmiError::BadOpcode);
    }
    if buf.len() < 4 + h.byte_count as usize {
        return Err(SpmiError::Truncated);
    }
    Ok((h, &buf[4..4 + h.byte_count as usize]))
}
