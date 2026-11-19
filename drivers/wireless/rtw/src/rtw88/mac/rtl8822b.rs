// SPDX-License-Identifier: GPL-2.0-or-later
//! Source-matched `rtw8822b.c::rtw8822b_mac_init`; host DMA/MAC gates remain
//! closed. Every `WLAN_*`/`FAST_EDCA_*` value `rtw8822b.c` defines is
//! numerically identical to the RTL8821C set, so the same frozen value table
//! is reused; the sequence itself is the 8822B one (BIT_PRE_TX_CMD clear, no
//! PRECNT/INIRTS/ACKTO_CCK/TRXPTCL writes, SND_PTCL before WMAC options).
use super::rtl8821c::values::*;
use super::{u8, w16, w8, Error, Io};

/// `reg.h`: `REG_SW_AMPDU_BURST_MODE_CTRL` / `BIT_PRE_TX_CMD`.
const REG_SW_AMPDU_BURST_MODE_CTRL: u16 = 0x04bc;
const BIT_PRE_TX_CMD: u32 = 1 << 6;

pub(super) async fn chip(io: &mut impl Io) -> Result<(), Error> {
    // protocol configuration
    u8(io, REG_SW_AMPDU_BURST_MODE_CTRL, BIT_PRE_TX_CMD, 0).await?;
    w8(io, REG_AMPDU_MAX_TIME_V1, WLAN_AMPDU_MAX_TIME).await?;
    u8(io, REG_TX_HANG_CTRL, 0, BIT_EN_EOF_V1).await?;
    io.write32(
        REG_PROT_MODE_CTRL,
        WLAN_RTS_LEN_TH
            | WLAN_RTS_TX_TIME_TH << 8
            | WLAN_MAX_AGG_PKT_LIMIT << 16
            | WLAN_RTS_MAX_AGG_PKT_LIMIT << 24,
    )
    .await?;
    w16(
        io,
        REG_BAR_MODE_CTRL + 2,
        WLAN_BAR_RETRY_LIMIT | WLAN_RA_TRY_RATE_AGG_LIMIT << 8,
    )
    .await?;
    for (reg, value) in [
        (REG_FAST_EDCA_VOVI_SETTING, FAST_EDCA_VO_TH),
        (REG_FAST_EDCA_VOVI_SETTING + 2, FAST_EDCA_VI_TH),
        (REG_FAST_EDCA_BEBK_SETTING, FAST_EDCA_BE_TH),
        (REG_FAST_EDCA_BEBK_SETTING + 2, FAST_EDCA_BK_TH),
    ] {
        w8(io, reg, value).await?;
    }
    // EDCA configuration
    u8(io, REG_TIMER0_SRC_SEL, BIT_TSFT_SEL_TIMER0, 0).await?;
    // Explicit inactive projection: source TXPAUSE=0 never opens RF here.
    w16(io, REG_TXPAUSE, 255).await?;
    w8(io, REG_SLOT, WLAN_SLOT_TIME).await?;
    w8(io, REG_PIFS, WLAN_PIFS_TIME).await?;
    io.write32(REG_SIFS, WLAN_SIFS_CFG).await?;
    w16(io, REG_EDCA_VO_PARAM + 2, WLAN_VO_TXOP_LIMIT).await?;
    w16(io, REG_EDCA_VI_PARAM + 2, WLAN_VI_TXOP_LIMIT).await?;
    io.write32(REG_RD_NAV_NXT, WLAN_NAV_CFG).await?;
    w16(io, REG_RXTSF_OFFSET_CCK, WLAN_RX_TSF_CFG).await?;
    u8(io, REG_BCN_CTRL, 0, BIT_EN_BCN_FUNCTION).await?;
    io.write32(REG_TBTT_PROHIBIT, WLAN_TBTT_TIME).await?;
    w8(io, REG_DRVERLYINT, WLAN_DRV_EARLY_INT).await?;
    w8(io, REG_BCNDMATIM, WLAN_BCN_DMA_TIME).await?;
    u8(io, REG_TX_PTCL_CTRL + 1, BIT_SIFS_BK_EN >> 8, 0).await?;
    // WMAC configuration
    w16(io, REG_RXFLTMAP0, WLAN_RX_FILTER0).await?;
    w16(io, REG_RXFLTMAP1, WLAN_RX_FILTER1).await?;
    w16(io, REG_RXFLTMAP2, WLAN_RX_FILTER2).await?;
    io.write32(REG_RCR, WLAN_RCR_CFG).await?;
    w8(io, REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512).await?;
    w8(io, REG_TCR + 2, WLAN_TX_FUNC_CFG2).await?;
    w8(io, REG_TCR + 1, WLAN_TX_FUNC_CFG1).await?;
    io.write32(REG_WMAC_OPTION_FUNCTION + 8, WLAN_MAC_OPT_FUNC2)
        .await?;
    w8(io, REG_WMAC_OPTION_FUNCTION + 4, WLAN_MAC_OPT_NORM_FUNC1).await?;
    u8(io, REG_SND_PTCL_CTRL, 0, BIT_DIS_CHK_VHTSIGB_CRC).await?;
    Ok(())
}
