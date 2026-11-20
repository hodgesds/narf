// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE TX packet-buffer boundary and LLT initialization.
//!
//! Exact `rtl8192ce/hw.c::_rtl92ce_llt_table_init` with the compiled
//! `LLT_CONFIG == 5`: `REG_RQPN_NPQ` word 0, `REG_RQPN = 0x80b01c29`,
//! boundary 246 / max page 255, `TRXFF_BNDY = 0x27ff0000 | 246`, PBP `0x11`,
//! RX driver-info size 4. `_rtl92ce_llt_write` has the same poll as the
//! RTL8821AE one (`POLLING_LLT_THRESHOLD` 20, failure once the counter
//! exceeds it), so [`crate::rtlwifi::rtl8821ae::llt::llt_write`] is reused.

use crate::rtlwifi::firmware_transport::Error;
pub use crate::rtlwifi::rtl8821ae::llt::{
    llt_write, Regs, REG_LLT_INIT, REG_PBP, REG_RQPN, REG_RQPN_NPQ, REG_RX_DRVINFO_SZ, REG_TDECTRL,
    REG_TRXFF_BNDY, REG_TXPKTBUF_BCNQ_BDNY, REG_TXPKTBUF_MGQ_BDNY,
};

/// `txpktbuf_bndy` (`LLT_CONFIG == 5`).
pub const TX_PAGE_BOUNDARY: u8 = 246;
/// `maxpage`.
pub const MAX_PAGE: u8 = 255;
/// `REG_RQPN` value.
pub const RQPN: u32 = 0x80b0_1c29;
/// `0x45D`: the boundary copy Linux writes beside BCNQ/MGQ.
pub const REG_BCNQ1_BDNY: u16 = 0x045d;

/// The (address, next) links in `_rtl92ce_llt_table_init` order.
pub fn links() -> impl Iterator<Item = (u8, u8)> {
    let b = TX_PAGE_BOUNDARY;
    (0..b - 1)
        .map(|i| (i, i + 1))
        .chain(core::iter::once((b - 1, 0xff)))
        .chain((b..MAX_PAGE).map(|i| (i, i + 1)))
        .chain(core::iter::once((MAX_PAGE, b)))
}

/// `_rtl92ce_llt_table_init`.
pub fn init<R: Regs + ?Sized>(regs: &R) -> Result<(), Error> {
    regs.write16(REG_RQPN_NPQ, 0x0000)?;
    regs.write32(REG_RQPN, RQPN)?;
    regs.write32(REG_TRXFF_BNDY, 0x27ff_0000 | u32::from(TX_PAGE_BOUNDARY))?;
    regs.write8(REG_TDECTRL + 1, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_BCNQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_MGQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_BCNQ1_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_PBP, 0x11)?;
    regs.write8(REG_RX_DRVINFO_SZ, 0x4)?;
    for (address, next) in links() {
        llt_write(regs, address, next)?;
    }
    Ok(())
}
