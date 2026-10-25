// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-matched rtw8821c_mac_init; host DMA/MAC gates remain closed.
use super::{u8, w16, w8, Error, Io};
#[path = "rtl8821c_values.rs"]
mod values;
use values::*;

pub(super) fn chip(io: &mut impl Io) -> Result<(), Error> {
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
    u8(io, REG_INIRTS_RATE_SEL, 0, 1 << 5)?;
    u8(io, REG_TIMER0_SRC_SEL, BIT_TSFT_SEL_TIMER0, 0)?;
    // Explicit inactive projection: source TXPAUSE=0 never opens RF here.
    w16(io, REG_TXPAUSE, 255)?;
    w8(io, REG_SLOT, WLAN_SLOT_TIME)?;
    w8(io, REG_PIFS, WLAN_PIFS_TIME)?;
    io.write32(REG_SIFS, WLAN_SIFS_CFG)?;
    w16(io, REG_EDCA_VO_PARAM + 2, WLAN_VO_TXOP_LIMIT)?;
    w16(io, REG_EDCA_VI_PARAM + 2, WLAN_VI_TXOP_LIMIT)?;
    io.write32(REG_RD_NAV_NXT, WLAN_NAV_CFG)?;
    w16(io, REG_RXTSF_OFFSET_CCK, WLAN_RX_TSF_CFG)?;
    u8(io, REG_BCN_CTRL, 0, BIT_EN_BCN_FUNCTION)?;
    io.write32(REG_TBTT_PROHIBIT, WLAN_TBTT_TIME)?;
    w8(io, REG_DRVERLYINT, WLAN_DRV_EARLY_INT)?;
    w8(io, REG_BCNDMATIM, WLAN_BCN_DMA_TIME)?;
    u8(io, REG_TX_PTCL_CTRL + 1, BIT_SIFS_BK_EN >> 8, 0)?;
    w16(io, REG_RXFLTMAP0, WLAN_RX_FILTER0)?;
    w16(io, REG_RXFLTMAP1, WLAN_RX_FILTER1)?;
    w16(io, REG_RXFLTMAP2, WLAN_RX_FILTER2)?;
    io.write32(REG_RCR, WLAN_RCR_CFG)?;
    w8(io, REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512)?;
    w8(io, REG_TCR + 2, WLAN_TX_FUNC_CFG2)?;
    w8(io, REG_TCR + 1, WLAN_TX_FUNC_CFG1)?;
    w8(io, REG_ACKTO_CCK, 0x40)?;
    u8(io, REG_WMAC_TRXPTCL_CTL_H, 0, 1 << 1)?;
    u8(io, REG_SND_PTCL_CTRL, 0, BIT_DIS_CHK_VHTSIGB_CRC)?;
    io.write32(REG_WMAC_OPTION_FUNCTION + 8, WLAN_MAC_OPT_FUNC2)?;
    w8(io, REG_WMAC_OPTION_FUNCTION + 4, WLAN_MAC_OPT_NORM_FUNC1)?;
    Ok(())
}
