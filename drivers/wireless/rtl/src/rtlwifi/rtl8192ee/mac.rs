// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE `_rtl92ee_init_mac` remainder and `_rtl92ee_llt_table_init`.
//!
//! Probe already ran the enable prefix and `RTL8192E_NIC_ENABLE_FLOW`
//! (`power::power_on_with`) and the firmware owner downloaded the image.
//! This is the part of `_rtl92ee_init_mac` that follows the power sequence,
//! in Linux order, over the retained register owner, with two deliberate
//! differences:
//!
//! - the two `REG_CR` writes (`0xff` byte, then the `0x2ff` word) open the
//!   HCI/MAC TX/RX DMA engines and belong to the packet owner, which issues
//!   `REG_CR = 0x2ff` when it opens bus mastering (as for RTL8821AE); every
//!   other step, including the 2 ms settles, is issued here;
//! - LLT always runs: the owner is fresh after probe (Linux's
//!   `mac_func_enable == false` case).
//!
//! `dma64` is false (`rtl92ee_mod_params.dma64`), so the high halves of the
//! ring bases are not written. Ring bases are the *buffer descriptor* rings
//! (`tx_ring[].buffer_desc_dma`, `rx_ring[].dma`).

use super::trx::{RX_DESC_NUM, SEG_NUM, TX_DESC_NUM};
use crate::rtlwifi::firmware_transport::{Error, Io};

pub const REG_SYS_CLKR: u16 = 0x0008;
pub const REG_GPIO_MUXCFG: u16 = 0x0040;
pub const REG_HISR: u16 = 0x00b4;
pub const REG_HISRE: u16 = 0x00bc;
pub const REG_CR: u16 = 0x0100;
pub const REG_PBP: u16 = 0x0104;
pub const REG_TRXDMA_CTRL: u16 = 0x010c;
pub const REG_TRXFF_BNDY: u16 = 0x0114;
pub const REG_MCUTST_1: u16 = 0x01c0;
pub const REG_RQPN: u16 = 0x0200;
pub const REG_DWBCN0_CTRL: u16 = 0x0208;
pub const REG_AUTO_LLT: u16 = 0x0224;
pub const REG_DWBCN1_CTRL: u16 = 0x0228;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
pub const REG_INT_MIG: u16 = 0x0304;
pub const REG_BCNQ_DESA: u16 = 0x0308;
pub const REG_MGQ_DESA: u16 = 0x0310;
pub const REG_VOQ_DESA: u16 = 0x0318;
pub const REG_VIQ_DESA: u16 = 0x0320;
pub const REG_BEQ_DESA: u16 = 0x0328;
pub const REG_BKQ_DESA: u16 = 0x0330;
pub const REG_RX_DESA: u16 = 0x0338;
pub const REG_HQ0_DESA: u16 = 0x0340;
pub const REG_MGQ_TXBD_NUM: u16 = 0x0380;
pub const REG_RX_RXBD_NUM: u16 = 0x0382;
pub const REG_VOQ_TXBD_NUM: u16 = 0x0384;
pub const REG_VIQ_TXBD_NUM: u16 = 0x0386;
pub const REG_BEQ_TXBD_NUM: u16 = 0x0388;
pub const REG_BKQ_TXBD_NUM: u16 = 0x038a;
pub const REG_HI0Q_TXBD_NUM: u16 = 0x038c;
pub const REG_TSFTIMER_HCI: u16 = 0x039c;
pub const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
pub const REG_HWSEQ_CTRL: u16 = 0x0423;
pub const REG_BCNQ_BDNY: u16 = 0x0424;
pub const REG_MGQ_BDNY: u16 = 0x0425;
pub const REG_BCNQ1_BDNY: u16 = 0x0457;
pub const REG_TCR: u16 = 0x0604;
pub const REG_RCR: u16 = 0x0608;
pub const REG_RX_DRVINFO_SZ: u16 = 0x060f;
pub const REG_RXFLTMAP2: u16 = 0x06a4;

/// `txpktbuf_bndy` (`_rtl92ee_llt_table_init`).
pub const TXPKTBUF_BNDY: u8 = 0xf7;
/// `REG_RQPN` value.
pub const RQPN: u32 = 0x80e6_0808;

/// `rtlpci->receive_config` (`sw.c`): APPFCS | APP_MIC | APP_ICV |
/// APP_PHYST_RXFF | HTC_LOC_CTRL | AMF | ACF | ACRC32 | AB | AM | APM.
pub const RECEIVE_CONFIG: u32 = (1 << 31)
    | (1 << 30)
    | (1 << 29)
    | (1 << 28)
    | (1 << 14)
    | (1 << 13)
    | (1 << 12)
    | (1 << 8)
    | (1 << 3)
    | (1 << 2)
    | (1 << 1);
/// `rtlpci->transmit_config` (`CFENDFORM | BIT(15)`).
pub const TRANSMIT_CONFIG: u32 = (1 << 9) | (1 << 15);

/// `TX_DESC_NUM_92E | ((RTL8192EE_SEG_NUM << 12) & 0x3000)`.
pub const TXBD_NUM: u16 = TX_DESC_NUM | ((SEG_NUM << 12) & 0x3000);
/// `RX_DESC_NUM_92E | ((RTL8192EE_SEG_NUM << 13) & 0x6000) | 0x8000`.
pub const RXBD_NUM: u16 = RX_DESC_NUM | ((SEG_NUM << 13) & 0x6000) | 0x8000;

/// DMA32 buffer-descriptor ring bases.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rings {
    pub beacon: u32,
    pub mgnt: u32,
    pub vo: u32,
    pub vi: u32,
    pub be: u32,
    pub bk: u32,
    pub high: u32,
    pub rx: u32,
}

/// `_rtl92ee_llt_table_init`. Linux tests the *pre-write* `REG_AUTO_LLT+2`
/// value in its wait loop (so it waits only when BIT0 was already set, at
/// most 11 × 10 us) and always reports success; both are kept.
pub async fn llt_table_init<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    io.write32(REG_RQPN, RQPN)?;
    io.write8(REG_TRXFF_BNDY, TXPKTBUF_BNDY)?;
    io.write16(REG_TRXFF_BNDY + 2, 0x3d00 - 1)?;
    io.write8(REG_DWBCN0_CTRL + 1, TXPKTBUF_BNDY)?;
    io.write8(REG_DWBCN1_CTRL + 1, TXPKTBUF_BNDY)?;
    io.write8(REG_BCNQ_BDNY, TXPKTBUF_BNDY)?;
    io.write8(REG_BCNQ1_BDNY, TXPKTBUF_BNDY)?;
    io.write8(REG_MGQ_BDNY, TXPKTBUF_BNDY)?;
    io.write8(0x45d, TXPKTBUF_BNDY)?;
    io.write8(REG_PBP, 0x31)?;
    io.write8(REG_RX_DRVINFO_SZ, 0x4)?;
    let mut value = io.read8(REG_AUTO_LLT + 2)?;
    io.write8(REG_AUTO_LLT + 2, value | 1)?;
    let mut count = 0;
    while value & 1 != 0 {
        value = io.read8(REG_AUTO_LLT + 2)?;
        io.delay_us(10).await;
        count += 1;
        if count > 10 {
            break;
        }
    }
    Ok(())
}

/// `_rtl92ee_init_mac` after the power sequence, minus the `REG_CR` writes
/// (see the module comment). `TRXDMA_CTRL` is read with a dword read (the
/// retained interface has no 16-bit read) and written with the exact word.
pub async fn init_mac<I: Io + ?Sized>(io: &I, rings: &Rings) -> Result<(), Error> {
    io.delay_us(2000).await;
    io.write8(REG_HWSEQ_CTRL, 0x7f)?;
    io.delay_us(2000).await;
    let value = io.read8(REG_SYS_CLKR)?;
    io.write8(REG_SYS_CLKR, value | (1 << 3))?;
    let value = io.read8(REG_GPIO_MUXCFG + 1)?;
    io.write8(REG_GPIO_MUXCFG + 1, value & !(1 << 4))?;
    llt_table_init(io).await?;
    io.write32(REG_HISR, 0xffff_ffff)?;
    io.write32(REG_HISRE, 0xffff_ffff)?;
    let word = (io.read32(REG_TRXDMA_CTRL)? & 0xffff) as u16;
    io.write16(REG_TRXDMA_CTRL, (word & 0xf) | 0xf5b1)?;
    io.write8(REG_FWHW_TXQ_CTRL + 1, 0x1f)?;
    io.write32(REG_RCR, RECEIVE_CONFIG)?;
    io.write16(REG_RXFLTMAP2, 0xffff)?;
    io.write32(REG_TCR, TRANSMIT_CONFIG)?;
    io.write32(REG_BCNQ_DESA, rings.beacon)?;
    io.write32(REG_MGQ_DESA, rings.mgnt)?;
    io.write32(REG_VOQ_DESA, rings.vo)?;
    io.write32(REG_VIQ_DESA, rings.vi)?;
    io.write32(REG_BEQ_DESA, rings.be)?;
    io.read32(REG_BEQ_DESA)?;
    io.write32(REG_BKQ_DESA, rings.bk)?;
    io.write32(REG_HQ0_DESA, rings.high)?;
    io.write32(REG_RX_DESA, rings.rx)?;
    io.write32(REG_TSFTIMER_HCI, 0x3fff_ffff)?;
    let value = io.read8(REG_PCIE_CTRL_REG + 3)?;
    io.write8(REG_PCIE_CTRL_REG + 3, value | 0xf7)?;
    io.write32(REG_INT_MIG, 0)?;
    io.write32(REG_MCUTST_1, 0)?;
    // Linux order, including the repeated VOQ write; HI1..HI7 at 0x38e..0x39a.
    for reg in [
        REG_MGQ_TXBD_NUM,
        REG_VOQ_TXBD_NUM,
        REG_VIQ_TXBD_NUM,
        REG_BEQ_TXBD_NUM,
        REG_VOQ_TXBD_NUM,
        REG_BKQ_TXBD_NUM,
    ] {
        io.write16(reg, TXBD_NUM)?;
    }
    for hi in 0..8 {
        io.write16(REG_HI0Q_TXBD_NUM + 2 * hi, TXBD_NUM)?;
    }
    io.write16(REG_RX_RXBD_NUM, RXBD_NUM)?;
    io.write32(REG_TSFTIMER_HCI, 0xffff_ffff)
}

/// The deferred `REG_CR` release (`rtl_write_word(REG_CR, 0x2ff)`), issued
/// by the packet owner once its rings are published.
pub fn release_cr<I: Io + ?Sized>(io: &I) -> Result<(), Error> {
    io.write16(REG_CR, 0x2ff)
}
