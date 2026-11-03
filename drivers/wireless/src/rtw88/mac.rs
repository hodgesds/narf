// SPDX-License-Identifier: GPL-2.0-or-later
//! Inactive RTL8821CE/RTL8822CE MAC/FIFO continuation of the retained firmware owner.
//! Linux mac.c::rtw_mac_init and rtw8822c.c::rtw8822c_mac_init, with DMA,
//! MAC TX/RX and host queues deliberately held closed pending RF ownership.
use super::firmware_transport::{Error, Io};
#[path = "mac/values.rs"]
mod values;
use values::*;
#[path = "mac/rtl8821c.rs"]
mod rtl8821c;
#[path = "mac/rtl8822b.rs"]
mod rtl8822b;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub cut: u8,
    pub reserved_boundary: u16,
    pub h2c_page: u16,
    pub firmware_tx_page: u16,
}
impl Info {
    fn new(cut: u8, did: u16) -> Self {
        // RTL8822C: 256KiB /128, minus CSI50, firmware4, H2CQ8,
        // H2C static8/extra24 and driver16. These are on-chip FIFO pages,
        // unrelated to the separately retained PCI host BD arrays.
        // RTL8822B (`rtw_set_trx_fifo_info`): 2048 pages, csi_buf_pg_num 0,
        // rsvd_drv_pg_num 8 -> boundary 1996, H2CQ 2036, FW TXBUF 2044.
        let (reserved_boundary, h2c_page, firmware_tx_page) = match did {
            0xc821 => (460, 500, 508),
            0xb822 => (1996, 2036, 2044),
            _ => (1938, 1986, 1994),
        };
        Self {
            cut,
            reserved_boundary,
            h2c_page,
            firmware_tx_page,
        }
    }
}
async fn w8(io: &mut impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write8(reg, value as u8).await
}
async fn w16(io: &mut impl Io, reg: u16, value: u32) -> Result<(), Error> {
    io.write16(reg, value as u16).await
}
async fn u8(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = u32::from(io.read8(reg).await?);
    w8(io, reg, value & !clear | set).await
}
async fn u16(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = u32::from(io.read16(reg).await?);
    w16(io, reg, value & !clear | set).await
}
async fn u32(io: &mut impl Io, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read32(reg).await?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    io.write32(reg, value & !clear | set).await
}
/// Host interface the MAC queue/FIFO programming follows (`rtw_hci_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hci {
    Pcie,
    /// RTL8821CU: `rtwdev->hci.bulkout_num` selects the `rqpn_table_8821c` /
    /// `page_table_8821c` rows; `speed` feeds `rtw_usb_interface_cfg`.
    Usb {
        bulkout: u8,
        speed: super::usb::Speed,
    },
}
async fn fifo(io: &mut impl Io, info: Info, did: u16, hci: Hci) -> Result<(), Error> {
    let usb = match hci {
        Hci::Pcie => None,
        Hci::Usb { bulkout, .. } => {
            Some(super::usb::usb_tables(usize::from(bulkout)).map_err(|_| Error::Unsupported)?)
        }
    };
    // mac.c::txdma_queue_mapping: PCIe uses rqpn_table[1]; USB the
    // bulk-out-count row of rqpn_table_8821c.
    let map = match usb {
        Some((rqpn, _)) => u32::from(super::usb::txdma_pq_map(rqpn)),
        None => 0xc5a0,
    };
    w16(io, REG_TXDMA_PQ_MAP, map).await?;
    w8(io, REG_CR, 0).await?;
    // Linux MAC_TRX_ENABLE is0xff. Only protocol/scheduler may be enabled
    // here: the existing firmware host rings, MAC and RF remain inactive.
    w8(io, REG_CR, MAC_TRX_ENABLE & !0xcf).await?;
    io.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL).await?;
    if usb.is_some() {
        // txdma_queue_mapping USB tail: BIT_RXDMA_ARBBW_EN.
        u8(io, REG_TXDMA_PQ_MAP, 0, 1).await?;
    }
    // FIFOPAGE_INFO_1..4 = hq, lq, nq, exq (`__priority_queue_cfg`).
    let pages = match usb {
        Some((_, p)) => [p.hq, p.lq, p.nq, p.exq].map(u32::from),
        None if did == 0xc821 => [16, 16, 16, 14],
        None => [64; 4],
    };
    for (reg, count) in [
        REG_FIFOPAGE_INFO_1,
        REG_FIFOPAGE_INFO_2,
        REG_FIFOPAGE_INFO_3,
        REG_FIFOPAGE_INFO_4,
    ]
    .into_iter()
    .zip(pages)
    {
        w16(io, reg, count).await?;
    }
    w16(
        io,
        REG_FIFOPAGE_INFO_5,
        u32::from(info.reserved_boundary) - pages.iter().sum::<u32>() - 1,
    )
    .await?;
    u32(io, REG_RQPN_CTRL_2, 0, BIT_LD_RQPN).await?;
    w16(io, REG_FIFOPAGE_CTRL_2, u32::from(info.reserved_boundary)).await?;
    u8(io, REG_FWHW_TXQ_CTRL + 2, 0, BIT_EN_WR_FREE_TAIL >> 16).await?;
    for reg in [REG_BCNQ_BDNY_V1, REG_FIFOPAGE_CTRL_2 + 2, REG_BCNQ1_BDNY_V1] {
        w16(io, reg, u32::from(info.reserved_boundary)).await?;
    }
    io.write32(
        REG_RXFF_BNDY,
        (if did == 0xc821 { 16384 } else { 24576 }) - C2H_PKT_BUF - 1,
    )
    .await?;
    if usb.is_some() {
        // __priority_queue_cfg USB: BLK_DESC_NUM and AUTO_LLT_V1+3 =
        // usb_tx_agg_desc_num, TXDMA_OFFSET_CHK+1 BIT(1).
        u8(
            io,
            REG_AUTO_LLT_V1,
            0xf0,
            u32::from(super::usb::TX_AGG_DESC_NUM) << 4,
        )
        .await?;
        w8(io, REG_AUTO_LLT_V1 + 3, super::usb::TX_AGG_DESC_NUM.into()).await?;
        u8(io, REG_TXDMA_OFFSET_CHK + 1, 0, 1 << 1).await?;
    }
    u8(io, REG_AUTO_LLT_V1, 0, BIT_AUTO_INIT_LLT_V1).await?;
    let deadline = narf_time::Deadline::after_ms(10);
    let mut complete = false;
    for _ in 0..1000 {
        let value = io.read32(REG_AUTO_LLT_V1).await?;
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
    w8(io, REG_CR + 3, 0).await?;
    let address = u32::from(info.h2c_page) << 7;
    u32(io, REG_H2C_HEAD, 0x3ffff, address).await?;
    u32(io, REG_H2C_READ_ADDR, 0x3ffff, address).await?;
    u32(io, REG_H2C_TAIL, 0x3ffff, address + (8 << 7)).await?;
    u8(io, REG_H2C_INFO, 3, 1).await?;
    u8(io, REG_H2C_INFO, 4, 4).await?;
    u8(io, REG_TXDMA_OFFSET_CHK + 1, 0x80, 0x80).await?;
    let write = io.read32(REG_H2C_PKT_WRITEADDR).await? & 0x3ffff;
    let read = io.read32(REG_H2C_PKT_READADDR).await? & 0x3ffff;
    // An unequal pointer cannot establish an empty queue, regardless of the
    // direction or wrapping. Require the configured start as well as equality.
    if write != read || write != address {
        return Err(Error::Prerequisite);
    }
    Ok(())
}
async fn chip(io: &mut impl Io) -> Result<(), Error> {
    u8(io, REG_FWHW_TXQ_CTRL, 0, 1 << 7).await?;
    w8(io, REG_FWHW_TXQ_CTRL + 1, WLAN_TXQ_RPT_EN).await?;
    w16(io, REG_SPEC_SIFS, WLAN_SIFS_DUR_TUNE).await?;
    io.write32(REG_SIFS, WLAN_SIFS_CFG).await?;
    w16(
        io,
        REG_RESP_SIFS_CCK,
        WLAN_SIFS_CCK_CTX | WLAN_SIFS_CCK_IRX << 8,
    )
    .await?;
    w16(
        io,
        REG_RESP_SIFS_OFDM,
        WLAN_SIFS_OFDM_CTX | WLAN_SIFS_OFDM_IRX << 8,
    )
    .await?;
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
        io.write32(reg, value).await?;
    }
    w8(io, REG_AMPDU_MAX_TIME_V1, WLAN_AMPDU_MAX_TIME).await?;
    u8(io, REG_TX_HANG_CTRL, 0, BIT_EN_EOF_V1).await?;
    let pre = WLAN_PRE_TXCNT_TIME_TH | BIT_EN_PRECNT;
    w8(io, REG_PRECNT_CTRL, pre & 255).await?;
    w8(io, REG_PRECNT_CTRL + 1, pre >> 8).await?;
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
    u8(io, REG_LIFETIME_EN, BIT_BA_PARSER_EN, 0).await?;
    u32(io, REG_RRSR, BITS_RRSR_RSC, 0).await?;
    for (reg, value) in [
        (REG_EDCA_VO_PARAM, WLAN_EDCA_VO_PARAM),
        (REG_EDCA_VI_PARAM, WLAN_EDCA_VI_PARAM),
        (REG_EDCA_BE_PARAM, WLAN_EDCA_BE_PARAM),
        (REG_EDCA_BK_PARAM, WLAN_EDCA_BK_PARAM),
    ] {
        io.write32(reg, value).await?;
    }
    w8(io, REG_PIFS, WLAN_PIFS_TIME).await?;
    u8(io, REG_TX_PTCL_CTRL + 1, BIT_SIFS_BK_EN >> 8, 0).await?;
    u8(
        io,
        REG_RD_CTRL + 1,
        0,
        (BIT_DIS_TXOP_CFE | BIT_DIS_LSIG_CFE | BIT_DIS_STBC_CFE) >> 8,
    )
    .await?;
    u32(io, REG_AFE_CTRL1, BIT_MAC_CLK_SEL, 0).await?;
    w8(io, REG_USTIME_TSF, MAC_CLK_SPEED).await?;
    w8(io, REG_USTIME_EDCA, MAC_CLK_SPEED).await?;
    u8(io, REG_MISC_CTRL, 0, BIT_EN_FREE_CNT | BIT_DIS_SECOND_CCA).await?;
    u8(io, REG_TIMER0_SRC_SEL, BIT_TSFT_SEL_TIMER0, 0).await?;
    // Explicit inactive difference from Linux's TXPAUSE=0.
    w16(io, REG_TXPAUSE, 255).await?;
    w8(io, REG_SLOT, WLAN_SLOT_TIME).await?;
    io.write32(REG_RD_NAV_NXT, WLAN_NAV_CFG).await?;
    w16(io, REG_RXTSF_OFFSET_CCK, WLAN_RX_TSF_CFG).await?;
    u8(io, REG_BCN_CTRL, 0, BIT_EN_BCN_FUNCTION).await?;
    io.write32(REG_TBTT_PROHIBIT, WLAN_TBTT_TIME).await?;
    w8(io, REG_DRVERLYINT, WLAN_DRV_EARLY_INT).await?;
    w8(io, REG_BCN_CTRL_CLINT0, WLAN_BCN_CTRL_CLT0).await?;
    w8(io, REG_BCNDMATIM, WLAN_BCN_DMA_TIME).await?;
    w8(io, REG_BCN_MAX_ERR, WLAN_BCN_MAX_ERR).await?;
    io.write32(REG_MAR, WLAN_MULTI_ADDR).await?;
    io.write32(REG_MAR + 4, WLAN_MULTI_ADDR).await?;
    w8(io, REG_BBPSF_CTRL + 2, WLAN_RESP_TXRATE).await?;
    w8(io, REG_ACKTO, WLAN_ACK_TO).await?;
    w8(io, REG_ACKTO_CCK, WLAN_ACK_TO_CCK).await?;
    w16(io, REG_EIFS, WLAN_EIFS_DUR_TUNE).await?;
    w8(io, REG_NAV_CTRL + 2, WLAN_NAV_MAX).await?;
    w8(io, REG_WMAC_TRXPTCL_CTL_H + 2, WLAN_BAR_ACK_TYPE).await?;
    w16(io, REG_RXFLTMAP0, WLAN_RX_FILTER0).await?;
    w16(io, REG_RXFLTMAP1, WLAN_RX_FILTER1).await?;
    w16(io, REG_RXFLTMAP2, WLAN_RX_FILTER2).await?;
    io.write32(REG_RCR, WLAN_RCR_CFG).await?;
    w8(io, REG_RX_PKT_LIMIT, WLAN_RXPKT_MAX_SZ_512).await?;
    w8(io, REG_TCR + 2, WLAN_TX_FUNC_CFG2).await?;
    w8(io, REG_TCR + 1, WLAN_TX_FUNC_CFG1).await?;
    u32(io, REG_GENERAL_OPTION, 0, BIT_DUMMY_FCS_READY_MASK_EN).await?;
    io.write32(REG_WMAC_OPTION_FUNCTION + 8, WLAN_MAC_OPT_FUNC2)
        .await?;
    w8(io, REG_WMAC_OPTION_FUNCTION_1, WLAN_MAC_OPT_NORM_FUNC1).await?;
    u16(
        io,
        REG_RXPSF_CTRL + 2,
        !0xf00f,
        ((1 << BIT_SHIFT_RXGCK_VHT_FIFOTHR)
            | (1 << BIT_SHIFT_RXGCK_HT_FIFOTHR)
            | (1 << BIT_SHIFT_RXGCK_OFDM_FIFOTHR)
            | (1 << BIT_SHIFT_RXGCK_CCK_FIFOTHR))
            >> 16,
    )
    .await?;
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
    )
    .await?;
    io.write32(REG_RXPSF_TYPE_CTRL, u32::MAX).await?;
    u16(
        io,
        REG_RXPSF_CTRL,
        BIT_RXPSF_MHCHKEN
            | BIT_RXPSF_CCKRST
            | BIT_RXPSF_CONT_ERRCHKEN
            | (BIT_MASK_RXPSF_ERRTHR << BIT_SHIFT_RXPSF_ERRTHR),
        7 << BIT_SHIFT_RXPSF_ERRTHR,
    )
    .await?;
    u8(io, REG_SND_PTCL_CTRL, 0, BIT_DIS_CHK_VHTSIGB_CRC).await?;
    io.write32(REG_INT_MIG, WLAN_MAC_INT_MIG_CFG).await?;
    Ok(())
}
pub(super) async fn prepare(io: &mut impl Io) -> Result<Info, Error> {
    prepare_for(io, 0xc822).await
}
pub(super) async fn prepare_for(io: &mut impl Io, did: u16) -> Result<Info, Error> {
    prepare_on(io, did, Hci::Pcie).await
}
/// `mac.c::rtw_mac_init` for `hci`. USB exists only for the C21 die
/// (RTL8821CU); the PCIe byte stream is unchanged.
pub(super) async fn prepare_on(io: &mut impl Io, did: u16, hci: Hci) -> Result<Info, Error> {
    if !matches!(did, 0xc821 | 0xc822 | 0xb822) || did != 0xc821 && hci != Hci::Pcie {
        return Err(Error::Unsupported);
    }
    let cfg = io.read32(0xf0).await?;
    if cfg == u32::MAX {
        return Err(Error::Gone);
    }
    let cut = ((cfg >> 12) & 15) as u8;
    if cut > 6 {
        return Err(Error::Unsupported);
    }
    let info = Info::new(cut, did);
    fifo(io, info, did, hci).await?;
    if did == 0xc821 {
        rtl8821c::chip(io).await?;
    } else if did == 0xb822 {
        rtl8822b::chip(io).await?;
    } else {
        chip(io).await?;
    }
    w8(io, REG_RX_DRVINFO_SZ, PHY_STATUS_SIZE).await?;
    u8(io, REG_TRXFF_BNDY + 1, 0x0f, 0x0f).await?;
    u32(io, REG_RCR, 0, BIT_APP_PHYSTS).await?;
    u32(io, REG_WMAC_OPTION_FUNCTION + 4, 1 << 8 | 1 << 9, 0).await?;
    if did == 0xc822 && cut >= 3 {
        u32(io, 0x3fc, 0, 1 << 26).await?;
    }
    if let Hci::Usb { speed, .. } = hci {
        // rtw_hci_interface_cfg -> usb.c::rtw_usb_init_burst_pkt_len.
        super::usb::interface_cfg(io, speed).await?;
    }
    Ok(info)
}
