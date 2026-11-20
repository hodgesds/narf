// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact RTL8723AE interrupt and TX-poll literals, Linux hw.c:1230..1252,
//! 1312..1322; sw.c:103..122; trx.c:678..688. reg.h's HIMR macros are not
//! used by those actual hw.c functions; do not substitute the CE register map.
use crate::rtlwifi::{
    firmware_transport::{Error as AccessError, Io},
    prepare::Error,
};
pub const ISR: u16 = 0x3a0;
pub const MASK0: u16 = 0x3a8;
pub const MASK1: u16 = 0x3ac;
pub const IRQ0: u32 = 0xff | (1 << 10) | (1 << 11) | (1 << 24) | (1 << 25) | (1 << 29);
pub const IRQ1: u32 = 1 << 8;
/// Mask both actual source banks; readbacks are native restrictions.
pub fn disable(io: &impl Io) -> Result<(), Error> {
    io.write32(MASK0, 0)?;
    io.write32(MASK1, 0)?;
    if io.read32(MASK0)? != 0 || io.read32(MASK1)? != 0 {
        return Err(Error::Readback);
    }
    Ok(())
}
pub fn enable(io: &impl Io) -> Result<(), Error> {
    io.write32(MASK0, IRQ0)?;
    io.write32(MASK1, IRQ1)?;
    if io.read32(MASK0)? != IRQ0 || io.read32(MASK1)? != IRQ1 {
        return Err(Error::Readback);
    }
    Ok(())
}
/// Source recognizes/acks only0x3a0; no invented HISRE read or W1C.
pub fn recognize(io: &impl Io) -> Result<crate::rtlwifi::irq::IsrStatus, Error> {
    let raw = io.read32(ISR)?;
    if raw == u32::MAX {
        return Err(Error::Access(AccessError::Gone));
    }
    let hisr = raw & IRQ0;
    io.write32(ISR, hisr)?;
    Ok(crate::rtlwifi::irq::IsrStatus { hisr, hisre: 0 })
}
pub fn poll_tx(io: &impl Io, hw_queue: u8) -> Result<(), Error> {
    if hw_queue > 7 {
        return Err(Error::Packet);
    }
    io.write16(0x300, if hw_queue == 4 { 1 << 4 } else { 1 << hw_queue })?;
    Ok(())
}
