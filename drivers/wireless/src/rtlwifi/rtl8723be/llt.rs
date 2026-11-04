// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE TX packet-buffer boundary and LLT initialization.
//!
//! Exact `rtl8723be/hw.c::_rtl8723be_llt_table_init`: boundary 245 / max
//! page 255, `TRXFF_BNDY = 0x27ff0000 | 245`, the boundary copies in
//! `TDECTRL+1`, BCNQ, MGQ and `0x45d`, PBP `0x31`, RX driver-info size 4, the
//! 256 links (TX chain ending `0xff`, ring 245..255 closing at 245), then
//! `REG_RQPN = 0x80e40808` and `REG_RQPN_NPQ` byte 0 (written after the
//! links, unlike the 92C). `_rtl8723be_llt_write` has the RTL8821AE poll
//! (`POLLING_LLT_THRESHOLD` 20), so
//! [`crate::rtlwifi::rtl8821ae::llt::llt_write`] is reused.

use crate::rtlwifi::firmware_transport::Error;
pub use crate::rtlwifi::rtl8821ae::llt::{
    llt_write, Regs, REG_LLT_INIT, REG_PBP, REG_RQPN, REG_RQPN_NPQ, REG_RX_DRVINFO_SZ, REG_TDECTRL,
    REG_TRXFF_BNDY, REG_TXPKTBUF_BCNQ_BDNY, REG_TXPKTBUF_MGQ_BDNY,
};

/// `txpktbuf_bndy`.
pub const TX_PAGE_BOUNDARY: u8 = 245;
/// `maxpage`.
pub const MAX_PAGE: u8 = 255;
/// `REG_RQPN` value.
pub const RQPN: u32 = 0x80e4_0808;
/// `0x45D`: the boundary copy Linux writes beside BCNQ/MGQ.
pub const REG_BCNQ1_BDNY: u16 = 0x045d;

/// The (address, next) links in `_rtl8723be_llt_table_init` order.
pub fn links() -> impl Iterator<Item = (u8, u8)> {
    let b = TX_PAGE_BOUNDARY;
    (0..b - 1)
        .map(|i| (i, i + 1))
        .chain(core::iter::once((b - 1, 0xff)))
        .chain((b..MAX_PAGE).map(|i| (i, i + 1)))
        .chain(core::iter::once((MAX_PAGE, b)))
}

/// `_rtl8723be_llt_table_init`.
pub fn init<R: Regs + ?Sized>(regs: &R) -> Result<(), Error> {
    regs.write32(REG_TRXFF_BNDY, 0x27ff_0000 | u32::from(TX_PAGE_BOUNDARY))?;
    regs.write8(REG_TDECTRL + 1, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_BCNQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_TXPKTBUF_MGQ_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_BCNQ1_BDNY, TX_PAGE_BOUNDARY)?;
    regs.write8(REG_PBP, 0x31)?;
    regs.write8(REG_RX_DRVINFO_SZ, 0x4)?;
    for (address, next) in links() {
        llt_write(regs, address, next)?;
    }
    regs.write32(REG_RQPN, RQPN)?;
    regs.write8(REG_RQPN_NPQ, 0x00)
}
