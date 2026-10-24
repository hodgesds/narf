// SPDX-License-Identifier: GPL-2.0-or-later
//! Inactive RTL8822CE MAC/FIFO continuation of the retained firmware owner.
//! Linux mac.c::rtw_mac_init and rtw8822c.c::rtw8822c_mac_init, with DMA,
//! MAC TX/RX and host queues deliberately held closed pending RF ownership.
use super::firmware_transport::{Error, Io};
#[path = "mac/values.rs"]
mod values;
use values::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub cut: u8,
    pub reserved_boundary: u16,
    pub h2c_page: u16,
    pub firmware_tx_page: u16,
}
impl Info {
    fn new(cut: u8) -> Self {
        // RTL8822C: 256KiB /128, minus CSI50, firmware4, H2CQ8,
        // H2C static8/extra24 and driver16. These are on-chip FIFO pages,
        // unrelated to the separately retained PCI host BD arrays.
        Self {
            cut,
            reserved_boundary: 1938,
            h2c_page: 1986,
            firmware_tx_page: 1994,
        }
    }
}
fn w8(io: &mut impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write8(reg, value as u8)
}
fn w16(io: &mut impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write16(reg, value as u16)
}
fn u8(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = u32::from(io.read8(reg)?);
    w8(io, reg, value & !clear | set)
}
fn u16(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = u32::from(io.read16(reg)?);
    w16(io, reg, value & !clear | set)
}
fn u32(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read32(reg)?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    io.write32(reg, value & !clear | set)
}
async fn fifo(io: &mut impl Io, info: Info) -> Result<(), Error> {
    // PCIe queue mapping from rqpn_table_8822c[1].
    w16(io, REG_TXDMA_PQ_MAP, 0xc5a0)?;
    w8(io, REG_CR, 0)?;
    // Linux MAC_TRX_ENABLE is0xff. Only protocol/scheduler may be enabled
    // here: the existing firmware host rings, MAC and RF remain inactive.
    w8(io, REG_CR, MAC_TRX_ENABLE & !0xcf)?;
    io.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL)?;
    for reg in [
        REG_FIFOPAGE_INFO_1,
        REG_FIFOPAGE_INFO_2,
        REG_FIFOPAGE_INFO_3,
        REG_FIFOPAGE_INFO_4,
    ] {
        w16(io, reg, 64)?;
    }
    w16(
        io,
        REG_FIFOPAGE_INFO_5,
        u32::from(info.reserved_boundary) - 4 * 64 - 1,
    )?;
    u32(io, REG_RQPN_CTRL_2, 0, BIT_LD_RQPN)?;
    w16(io, REG_FIFOPAGE_CTRL_2, u32::from(info.reserved_boundary))?;
    u8(io, REG_FWHW_TXQ_CTRL + 2, 0, BIT_EN_WR_FREE_TAIL >> 16)?;
    for reg in [REG_BCNQ_BDNY_V1, REG_FIFOPAGE_CTRL_2 + 2, REG_BCNQ1_BDNY_V1] {
        w16(io, reg, u32::from(info.reserved_boundary))?;
    }
    io.write32(REG_RXFF_BNDY, 24576 - C2H_PKT_BUF - 1)?;
    u8(io, REG_AUTO_LLT_V1, 0, BIT_AUTO_INIT_LLT_V1)?;
    let deadline = narf_time::Deadline::after_ms(10);
    let mut complete = false;
    for _ in 0..1000 {
        let value = io.read32(REG_AUTO_LLT_V1)?;
        if value == u32::MAX {
            return Err(Error::Gone);
        }
        if value & BIT_AUTO_INIT_LLT_V1 == 0 {
            complete = true;
            break;
        }
        if deadline.expired() {
            break;
        }
        io.delay_us(10).await;
    }
    if !complete {
        return Err(Error::Timeout);
    }
    w8(io, REG_CR + 3, 0)?;
    let address = u32::from(info.h2c_page) << 7;
    u32(io, REG_H2C_HEAD, 0x3ffff, address)?;
    u32(io, REG_H2C_READ_ADDR, 0x3ffff, address)?;
    u32(io, REG_H2C_TAIL, 0x3ffff, address + (8 << 7))?;
    u8(io, REG_H2C_INFO, 3, 1)?;
    u8(io, REG_H2C_INFO, 4, 4)?;
    u8(io, REG_TXDMA_OFFSET_CHK + 1, 0x80, 0x80)?;
    let write = io.read32(REG_H2C_PKT_WRITEADDR)? & 0x3ffff;
    let read = io.read32(REG_H2C_PKT_READADDR)? & 0x3ffff;
    // An unequal pointer cannot establish an empty queue, regardless of the
    // direction or wrapping. Require the configured start as well as equality.
    if write != read || write != address {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
fn chip(io: &mut impl Io) -> Result<(), Error> {
    u8(io, REG_FWHW_TXQ_CTRL, 0, 1 << 7)?;
    w8(io, REG_FWHW_TXQ_CTRL + 1, WLAN_TXQ_RPT_EN)?;
    w16(io, REG_SPEC_SIFS, WLAN_SIFS_DUR_TUNE)?;
    io.write32(REG_SIFS, WLAN_SIFS_CFG)?;
    w16(
        io,
        REG_RESP_SIFS_CCK,
        WLAN_SIFS_CCK_CTX | WLAN_SIFS_CCK_IRX << 8,
    )?;
    w16(
        io,
        REG_RESP_SIFS_OFDM,
        WLAN_SIFS_OFDM_CTX | WLAN_SIFS_OFDM_IRX << 8,
    )?;
    for (reg, value) in [
        (REG_DARFRC, WLAN_DATA_RATE_FB_CNT_1_4),
        (REG_DARFRCH, WLAN_DATA_RATE_FB_CNT_5_8),
        (REG_RARFRCH, WLAN_RTS_RATE_FB_CNT_5_8),
        (REG_ARFR0, WLAN_DATA_RATE_FB_RATE0),
        (REG_ARFRH0, WLAN_DATA_RATE_FB_RATE0_H),
        (REG_ARFR1_V1, WLAN_RTS_RATE_FB_RATE1),
        (REG_ARFRH1_V1, WLAN_RTS_RATE_FB_RATE1_H),
        (REG_ARFR4, WLAN_RTS_RATE_FB_RATE4),
        (REG_ARFRH4, WLAN_RTS_RATE_FB_RATE4_H),
        (REG_ARFR5, WLAN_RTS_RATE_FB_RATE5),
        (REG_ARFRH5, WLAN_RTS_RATE_FB_RATE5_H),
    ] {
        io.write32(reg, value)?;
    }
    w8(io, REG_AMPDU_MAX_TIME_V1, WLAN_AMPDU_MAX_TIME)?;
    u8(io, REG_TX_HANG_CTRL, 0, BIT_EN_EOF_V1)?;
    let pre = WLAN_PRE_TXCNT_TIME_TH | BIT_EN_PRECNT;
    w8(io, REG_PRECNT_CTRL, pre & 255)?;
    w8(io, REG_PRECNT_CTRL + 1, pre >> 8)?;
    io.write32(
        REG_PROT_MODE_CTRL,
        WLAN_RTS_LEN_TH
            | WLAN_RTS_TX_TIME_TH << 8
            | WLAN_MAX_AGG_PKT_LIMIT << 16
            | WLAN_RTS_MAX_AGG_PKT_LIMIT << 24,
    )?;
    w16(
        io,
        REG_BAR_MODE_CTRL + 2,
        WLAN_BAR_RETRY_LIMIT | WLAN_RA_TRY_RATE_AGG_LIMIT << 8,
    )?;
    for (reg, value) in [
        (REG_FAST_EDCA_VOVI_SETTING, FAST_EDCA_VO_TH),
        (REG_FAST_EDCA_VOVI_SETTING + 2, FAST_EDCA_VI_TH),
        (REG_FAST_EDCA_BEBK_SETTING, FAST_EDCA_BE_TH),
        (REG_FAST_EDCA_BEBK_SETTING + 2, FAST_EDCA_BK_TH),
    ] {
        w8(io, reg, value)?;
    }
    u8(io, REG_LIFETIME_EN, BIT_BA_PARSER_EN, 0)?;
    u32(io, REG_RRSR, BITS_RRSR_RSC, 0)?;
    for (reg, value) in [
        (REG_EDCA_VO_PARAM, WLAN_EDCA_VO_PARAM),
        (REG_EDCA_VI_PARAM, WLAN_EDCA_VI_PARAM),
        (REG_EDCA_BE_PARAM, WLAN_EDCA_BE_PARAM),
        (REG_EDCA_BK_PARAM, WLAN_EDCA_BK_PARAM),
    ] {
        io.write32(reg, value)?;
    }
    w8(io, REG_PIFS, WLAN_PIFS_TIME)?;
    u8(io, REG_TX_PTCL_CTRL + 1, BIT_SIFS_BK_EN >> 8, 0)?;
    u8(
        io,
        REG_RD_CTRL + 1,
        0,
        (BIT_DIS_TXOP_CFE | BIT_DIS_LSIG_CFE | BIT_DIS_STBC_CFE) >> 8,
    )?;
    u32(io, REG_AFE_CTRL1, BIT_MAC_CLK_SEL, 0)?;
    w8(io, REG_USTIME_TSF, MAC_CLK_SPEED)?;
    w8(io, REG_USTIME_EDCA, MAC_CLK_SPEED)?;
    u8(io, REG_MISC_CTRL, 0, BIT_EN_FREE_CNT | BIT_DIS_SECOND_CCA)?;
    u8(io, REG_TIMER0_SRC_SEL, BIT_TSFT_SEL_TIMER0, 0)?;
    // Explicit inactive difference from Linux's TXPAUSE=0.
    w16(io, REG_TXPAUSE, 255)?;
    w8(io, REG_SLOT, WLAN_SLOT_TIME)?;
    io.write32(REG_RD_NAV_NXT, WLAN_NAV_CFG)?;
    w16(io, REG_RXTSF_OFFSET_CCK, WLAN_RX_TSF_CFG)?;
    u8(io, REG_BCN_CTRL, 0, BIT_EN_BCN_FUNCTION)?;
    io.write32(REG_TBTT_PROHIBIT, WLAN_TBTT_TIME)?;
    w8(io, REG_DRVERLYINT, WLAN_DRV_EARLY_INT)?;
    w8(io, REG_BCN_CTRL_CLINT0, WLAN_BCN_CTRL_CLT0)?;
    w8(io, REG_BCNDMATIM, WLAN_BCN_DMA_TIME)?;
    w8(io, REG_BCN_MAX_ERR, WLAN_BCN_MAX_ERR)?;
    io.write32(REG_MAR, WLAN_MULTI_ADDR)?;
    io.write32(REG_MAR + 4, WLAN_MULTI_ADDR)?;
    w8(io, REG_BBPSF_CTRL + 2, WLAN_RESP_TXRATE)?;
    w8(io, REG_ACKTO, WLAN_ACK_TO)?;
    w8(io, REG_ACKTO_CCK, WLAN_ACK_TO_CCK)?;
    w16(io, REG_EIFS, WLAN_EIFS_DUR_TUNE)?;
    w8(io, REG_NAV_CTRL + 2, WLAN_NAV_MAX)?;
    w8(io, REG_WMAC_TRXPTCL_CTL_H + 2, WLAN_BAR_ACK_TYPE)?;
    w16(io, REG_RXFLTMAP0, WLAN_RX_FILTER0)?;
    w16(io, REG_RXFLTMAP1, WLAN_RX_FILTER1)?;
    w16(io, REG_RXFLTMAP2, WLAN_RX_FILTER2)?;
    io.write32(REG_RCR, WLAN_RCR_CFG)?;
    w8(io, REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512)?;
    w8(io, REG_TCR + 2, WLAN_TX_FUNC_CFG2)?;
    w8(io, REG_TCR + 1, WLAN_TX_FUNC_CFG1)?;
    u32(io, REG_GENERAL_OPTION, 0, BIT_DUMMY_FCS_READY_MASK_EN)?;
    io.write32(REG_WMAC_OPTION_FUNCTION + 8, WLAN_MAC_OPT_FUNC2)?;
    w8(io, REG_WMAC_OPTION_FUNCTION_1, WLAN_MAC_OPT_NORM_FUNC1)?;
    u16(
        io,
        REG_RXPSF_CTRL + 2,
        !0xf00f,
        ((1 << BIT_SHIFT_RXGCK_VHT_FIFOTHR)
            | (1 << BIT_SHIFT_RXGCK_HT_FIFOTHR)
            | (1 << BIT_SHIFT_RXGCK_OFDM_FIFOTHR)
            | (1 << BIT_SHIFT_RXGCK_CCK_FIFOTHR))
            >> 16,
    )?;
    w16(
        io,
        REG_RXPSF_CTRL,
        (1 << BIT_SHIFT_RXPSF_PKTLENTHR)
            | BIT_RXPSF_CTRLEN
            | BIT_RXPSF_VHTCHKEN
            | BIT_RXPSF_HTCHKEN
            | BIT_RXPSF_OFDMCHKEN
            | BIT_RXPSF_CCKCHKEN
            | BIT_RXPSF_OFDMRST,
    )?;
    io.write32(REG_RXPSF_TYPE_CTRL, u32::MAX)?;
    u16(
        io,
        REG_RXPSF_CTRL,
        BIT_RXPSF_MHCHKEN
            | BIT_RXPSF_CCKRST
            | BIT_RXPSF_CONT_ERRCHKEN
            | (BIT_MASK_RXPSF_ERRTHR << BIT_SHIFT_RXPSF_ERRTHR),
        7 << BIT_SHIFT_RXPSF_ERRTHR,
    )?;
    u8(io, REG_SND_PTCL_CTRL, 0, BIT_DIS_CHK_VHTSIGB_CRC)?;
    io.write32(REG_INT_MIG, WLAN_MAC_INT_MIG_CFG)?;
    Ok(())
}
pub(super) async fn prepare(io: &mut impl Io) -> Result<Info, Error> {
    let cfg = io.read32(0xf0)?;
    if cfg == u32::MAX {
        return Err(Error::Gone);
    }
    let cut = ((cfg >> 12) & 15) as u8;
    if cut > 6 {
        return Err(Error::Unsupported);
    }
    let info = Info::new(cut);
    fifo(io, info).await?;
    chip(io)?;
    w8(io, REG_RX_DRVINFO_SZ, PHY_STATUS_SIZE)?;
    u8(io, REG_TRXFF_BNDY + 1, 0x0f, 0x0f)?;
    u32(io, REG_RCR, 0, BIT_APP_PHYSTS)?;
    u32(io, REG_WMAC_OPTION_FUNCTION + 4, 1 << 8 | 1 << 9, 0)?;
    if cut >= 3 {
        u32(io, 0x3fc, 0, 1 << 26)?;
    }
    Ok(info)
}
