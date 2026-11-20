// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2012 Realtek Corporation.
//! `_rtl8723e_llt_table_init` (`rtl8723ae/hw.c`, `LLT_CONFIG == 5`).
//!
//! CR writes (`0x8b`, then `0xff`) are deliberately deferred to the
//! retained packet owner: cold table setup cannot enable MAC or DMA.
//! The LLT poll is source-identical to the existing RTL8821AE helper.
use crate::rtlwifi::firmware_transport::{Error, Io};
pub use crate::rtlwifi::rtl8821ae::llt::{
    llt_write, Regs, REG_LLT_INIT, REG_PBP, REG_RQPN, REG_RQPN_NPQ, REG_RX_DRVINFO_SZ, REG_TDECTRL,
    REG_TRXFF_BNDY, REG_TXPKTBUF_BCNQ_BDNY, REG_TXPKTBUF_MGQ_BDNY,
};

pub const TX_PAGE_BOUNDARY: u8 = 246;
pub const MAX_PAGE: u8 = 255;
pub const RQPN: u32 = 0x80ac_1c29;
pub const REG_BCNQ1_BDNY: u16 = 0x045d;

pub fn links() -> impl Iterator<Item = (u8, u8)> {
    (0..TX_PAGE_BOUNDARY - 1)
        .map(|i| (i, i + 1))
        .chain(core::iter::once((TX_PAGE_BOUNDARY - 1, 0xff)))
        .chain((TX_PAGE_BOUNDARY..MAX_PAGE).map(|i| (i, i + 1)))
        .chain(core::iter::once((MAX_PAGE, TX_PAGE_BOUNDARY)))
}

struct Access<'a, I>(&'a I);
impl<I: Io> Regs for Access<'_, I> {
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        self.0.read32(reg)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        self.0.write8(reg, value)
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), Error> {
        self.0.write16(reg, value)
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        self.0.write32(reg, value)
    }
}

pub fn init(regs: &impl Io) -> Result<(), Error> {
    regs.write16(REG_RQPN_NPQ, 0)?;
    regs.write32(REG_RQPN, RQPN)?;
    regs.write8(REG_RQPN_NPQ, 3)?;
    regs.write32(REG_TRXFF_BNDY, 0x27ff_0000 | u32::from(TX_PAGE_BOUNDARY))?;
    regs.write8(REG_TDECTRL + 1, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_BCNQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_MGQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_BCNQ1_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_PBP, 0x11)?;
    regs.write8(REG_RX_DRVINFO_SZ, 4)?;
    for (address, next) in links() {
        llt_write(&Access(regs), address, next)?;
    }
    let value = regs.read8(REG_RQPN + 3)?;
    // The source byte RMW sets bit 7 of RQPN+3, already set by RQPN.
    regs.write8(REG_RQPN + 3, value | 0x80)
}
