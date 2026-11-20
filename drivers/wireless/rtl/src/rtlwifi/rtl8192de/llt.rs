// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE TX packet-buffer boundary and LLT initialization.
//!
//! Exact `rtl8192de/hw.c::_rtl92de_llt_table_init` +
//! `rtl8192d/hw_common.c::rtl92d_llt_write`: the boundary, max page and
//! RQPN word depend on the mode — single MAC writes boundary 246, max
//! page 255, `REG_RQPN = 0x80bf0d29`; any dual mode writes boundary
//! 123, max page 127, `REG_RQPN = 0x80750005`. The LLT itself is a TX
//! chain (`0 .. boundary-1` linked forward, `boundary-1 -> 0xff`) plus
//! a ring buffer (`boundary .. maxpage` linked forward, `maxpage ->
//! boundary`), each link written through `REG_LLT_INIT` and polled
//! until its op field reads back `NO_ACTIVE`.

use super::MacPhyMode;
use crate::rtlwifi::firmware_transport::{Error, Io};

/// `REG_LLT_INIT` (`rtl8192d/reg.h`).
pub const REG_LLT_INIT: u16 = 0x01e0;
/// `REG_RQPN`, `REG_RQPN_NPQ`, `REG_TRXFF_BNDY`, `REG_TDECTRL`
/// (`rtl8192d/reg.h`).
pub const REG_RQPN: u16 = 0x0200;
pub const REG_RQPN_NPQ: u16 = 0x0214;
pub const REG_TRXFF_BNDY: u16 = 0x0114;
pub const REG_TDECTRL: u16 = 0x0208;
/// `REG_TXPKTBUF_BCNQ_BDNY`, `REG_TXPKTBUF_MGQ_BDNY`, `REG_PBP`,
/// `REG_RX_DRVINFO_SZ` (`rtl8192d/reg.h`).
pub const REG_TXPKTBUF_BCNQ_BDNY: u16 = 0x0424;
pub const REG_TXPKTBUF_MGQ_BDNY: u16 = 0x0425;
pub const REG_PBP: u16 = 0x0104;
pub const REG_RX_DRVINFO_SZ: u16 = 0x060f;
/// `0x45D`: the boundary copy Linux writes beside BCNQ/MGQ
/// (`WMAC_LBK_BF_HD`).
pub const REG_LBK_BF_HD: u16 = 0x045d;
/// `POLLING_LLT_THRESHOLD` (`rtl8192d/reg.h`).
pub const POLLING_LLT_THRESHOLD: u32 = 20;

/// The mode-dependent LLT geometry: `(maxpage, txpktbuf_bndy, rqpn)`.
pub fn params(mode: MacPhyMode) -> (u8, u8, u32) {
    match mode {
        MacPhyMode::SingleMacSinglePhy => (255, 246, 0x80bf_0d29),
        _ => (127, 123, 0x8075_0005),
    }
}

/// `_LLT_INIT_ADDR | _LLT_INIT_DATA | _LLT_OP(_LLT_WRITE_ACCESS)`.
pub const fn llt_word(address: u8, data: u8) -> u32 {
    (address as u32) << 8 | data as u32 | 1 << 30
}

/// `rtl92d_llt_write`: Linux polls until `_LLT_OP_VALUE == NO_ACTIVE`,
/// failing once the counter exceeds [`POLLING_LLT_THRESHOLD`]. A
/// `0xffffffff` read is a gone device, as elsewhere.
pub fn llt_write<I: Io + ?Sized>(io: &I, address: u8, data: u8) -> Result<(), Error> {
    io.write32(REG_LLT_INIT, llt_word(address, data))?;
    for _ in 0..=POLLING_LLT_THRESHOLD + 1 {
        let value = io.read32(REG_LLT_INIT)?;
        if value == u32::MAX {
            return Err(Error::Gone);
        }
        if (value >> 30) & 3 == 0 {
            return Ok(());
        }
    }
    Err(Error::Deadline)
}

/// The (address, next) links written by `_rtl92de_llt_table_init`, in
/// order: a TX chain terminated by `0xff`, then the ring buffer closing
/// back at the boundary.
pub fn links(mode: MacPhyMode) -> impl Iterator<Item = (u8, u8)> {
    let (maxpage, bndy, _) = params(mode);
    (0..bndy - 1)
        .map(|i| (i, i + 1))
        .chain(core::iter::once((bndy - 1, 0xff)))
        .chain((bndy..maxpage).map(|i| (i, i + 1)))
        .chain(core::iter::once((maxpage, bndy)))
}

/// `_rtl92de_llt_table_init`: `REG_RQPN_NPQ = 0`, the mode RQPN word,
/// `REG_TRXFF_BNDY` rebuilt from the live high word plus the boundary,
/// the boundary copies (`REG_TDECTRL+1`, BCNQ/MGQ, `0x45d`), `REG_PBP
/// = 0x11` (TX 128 bytes), `REG_RX_DRVINFO_SZ = 4`, then the LLT
/// links.
pub fn init<I: Io + ?Sized>(io: &I, mode: MacPhyMode) -> Result<(), Error> {
    let (_, bndy, rqpn) = params(mode);
    io.write8(REG_RQPN_NPQ, 0)?;
    io.write32(REG_RQPN, rqpn)?;
    let hi = u16::from_le_bytes([io.read8(REG_TRXFF_BNDY + 2)?, io.read8(REG_TRXFF_BNDY + 3)?]);
    io.write32(REG_TRXFF_BNDY, (u32::from(hi) << 16) | u32::from(bndy))?;
    io.write8(REG_TDECTRL + 1, bndy)?;
    io.write8(REG_TXPKTBUF_BCNQ_BDNY, bndy)?;
    io.write8(REG_TXPKTBUF_MGQ_BDNY, bndy)?;
    io.write8(REG_LBK_BF_HD, bndy)?;
    io.write8(REG_PBP, 0x11)?;
    io.write8(REG_RX_DRVINFO_SZ, 0x4)?;
    for (address, next) in links(mode) {
        llt_write(io, address, next)?;
    }
    Ok(())
}
