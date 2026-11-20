// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE TX packet-buffer boundary and LLT initialization.
//!
//! Exact `rtl8821ae/hw.c::_rtl8821ae_llt_table_init` / `_rtl8821ae_llt_write`:
//! boundary `0xf7`, max page 255, RQPN `0x80e60808`, PBP `0x31`, RX driver-
//! info size 4 and the RX FIFO boundary `MAX_RX_DMA_BUFFER_SIZE - 1`.

use crate::rtlwifi::firmware_transport::Error;

pub const REG_PBP: u16 = 0x0104;
pub const REG_TRXFF_BNDY: u16 = 0x0114;
pub const REG_LLT_INIT: u16 = 0x01e0;
pub const REG_RQPN: u16 = 0x0200;
pub const REG_TDECTRL: u16 = 0x0208;
pub const REG_RQPN_NPQ: u16 = 0x0214;
pub const REG_TXPKTBUF_BCNQ_BDNY: u16 = 0x0424;
pub const REG_TXPKTBUF_MGQ_BDNY: u16 = 0x0425;
pub const REG_RX_DRVINFO_SZ: u16 = 0x060f;

/// `txpktbuf_bndy`.
pub const TX_PAGE_BOUNDARY: u8 = 0xf7;
/// `maxpage`.
pub const MAX_PAGE: u8 = 255;
/// `rqpn`.
pub const RQPN: u32 = 0x80e6_0808;
/// `MAX_RX_DMA_BUFFER_SIZE` (`def.h`).
pub const MAX_RX_DMA_BUFFER_SIZE: u16 = 0x3e80;
/// `POLLING_LLT_THRESHOLD`.
const POLLING_LLT_THRESHOLD: u32 = 20;

/// Exact-width MAC register access used by MAC initialization.
pub trait Regs {
    fn read32(&self, reg: u16) -> Result<u32, Error>;
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error>;
    fn write16(&self, reg: u16, value: u16) -> Result<(), Error>;
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error>;
}

/// `_LLT_INIT_ADDR | _LLT_INIT_DATA | _LLT_OP(_LLT_WRITE_ACCESS)`.
pub const fn llt_word(address: u8, data: u8) -> u32 {
    (address as u32) << 8 | data as u32 | 1 << 30
}

/// `_rtl8821ae_llt_write`: Linux polls until `_LLT_OP_VALUE == NO_ACTIVE`,
/// failing once the counter exceeds the threshold.
pub fn llt_write<R: Regs + ?Sized>(regs: &R, address: u8, data: u8) -> Result<(), Error> {
    regs.write32(REG_LLT_INIT, llt_word(address, data))?;
    for _ in 0..=POLLING_LLT_THRESHOLD + 1 {
        let value = regs.read32(REG_LLT_INIT)?;
        if value == u32::MAX {
            return Err(Error::Gone);
        }
        if (value >> 30) & 3 == 0 {
            return Ok(());
        }
    }
    Err(Error::Deadline)
}

/// The (address, next) links written by `_rtl8821ae_llt_table_init`, in
/// order: a TX chain terminated by `0xff`, then the ring buffer closing back
/// at the boundary.
pub fn links() -> impl Iterator<Item = (u8, u8)> {
    let b = TX_PAGE_BOUNDARY;
    (0..b - 1)
        .map(|i| (i, i + 1))
        .chain(core::iter::once((b - 1, 0xff)))
        .chain((b..MAX_PAGE).map(|i| (i, i + 1)))
        .chain(core::iter::once((MAX_PAGE, b)))
}

/// `_rtl8821ae_llt_table_init`.
pub fn init<R: Regs + ?Sized>(regs: &R) -> Result<(), Error> {
    regs.write8(REG_TRXFF_BNDY, TX_PAGE_BOUNDARY)?;
    regs.write16(REG_TRXFF_BNDY + 2, MAX_RX_DMA_BUFFER_SIZE - 1)?;
    regs.write8(REG_TDECTRL + 1, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_BCNQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_MGQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_PBP, 0x31)?;
    regs.write8(REG_RX_DRVINFO_SZ, 0x4)?;
    for (address, next) in links() {
        llt_write(regs, address, next)?;
    }
    regs.write32(REG_RQPN, RQPN)?;
    regs.write8(REG_RQPN_NPQ, 0x00)
}
