// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport-agnostic rtw88 MAC/FIFO bring-up (`mac.c::rtw_mac_init` /
//! `rtw8822c.c::rtw8822c_mac_init`), generic over [`RegIo`]. DMA, MAC TX/RX and
//! the host queues are deliberately held closed pending RF ownership — the
//! inactive projection the builtin driver and the loadable `.ko` both program.
//!
//! The only host-interface coupling of `mac.c::txdma_queue_mapping` /
//! `__priority_queue_cfg` (the bulk-out-count queue/page rows and the USB burst
//! tails) is resolved by the caller into [`MacParams`]; this module touches
//! registers only. `RegIo` is bridged to each transport by the consuming crate.
use crate::{ChipError as Error, RegIo as Io};
mod rtl8821c;
mod rtl8822b;
mod values;
use values::*;

/// `usb.c`'s `REG_RXDMA_MODE` / `BIT_DROP_DATA_EN` for the burst `interface_cfg`
/// tail (defined alongside the USB setup, not in the frozen MAC value table).
const REG_RXDMA_MODE: u16 = 0x290;
const BIT_DROP_DATA_EN: u16 = 1 << 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub cut: u8,
    pub reserved_boundary: u16,
    pub h2c_page: u16,
    pub firmware_tx_page: u16,
}
impl Info {
    pub fn new(cut: u8, did: u16) -> Self {
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

/// Queue/page programming the caller derives from the host interface
/// (`mac.c::txdma_queue_mapping` + `__priority_queue_cfg`). PCIe supplies the
/// fixed `0xc5a0` map and die-specific page counts with [`usb`](Self::usb)
/// `None`; USB supplies the bulk-out-count row plus the burst/aggregation
/// tails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacParams {
    /// `REG_TXDMA_PQ_MAP` value (`txdma_queue_mapping`).
    pub txdma_pq_map: u32,
    /// `REG_FIFOPAGE_INFO_1..4` = hq, lq, nq, exq.
    pub pages: [u32; 4],
    /// USB-only tails, present iff this is a USB device.
    pub usb: Option<UsbMacParams>,
}
/// The USB-specific portions of the MAC bring-up (`rtw_usb_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsbMacParams {
    /// `usb_tx_agg_desc_num` (`__priority_queue_cfg` AUTO_LLT block count).
    pub tx_agg_desc_num: u8,
    /// `rtw_usb_init_burst_pkt_len` burst selector from the bus speed.
    pub burst: u8,
}

/// `rtw8821c.c::rqpn_table_8821c` (row-for-row equal to `rqpn_table_8822b`),
/// indexed by the bulk-out pipe count. Each row is (vo, vi, be, bk, mg, hi) of
/// `enum rtw_dma_mapping` values (Extra 0, Low 1, Normal 2, High 3).
const USB_RQPN: [[u8; 6]; 5] = [
    [2, 2, 1, 1, 0, 3],
    [2, 2, 1, 1, 0, 3],
    [2, 2, 2, 3, 3, 3],
    [2, 2, 1, 1, 3, 3],
    [2, 2, 1, 1, 0, 3],
];
/// `rtw8821c.c::page_table_8821c` / `rtw8822b.c::page_table_8822b`, indexed by
/// the bulk-out pipe count. Each row is (hq, nq, lq, exq); the dies differ only
/// in the per-queue page count (16 vs 64).
const USB_PAGES_8821C: [[u32; 4]; 5] = [
    [16, 16, 16, 14],
    [16, 16, 16, 14],
    [16, 16, 0, 0],
    [16, 16, 16, 0],
    [16, 16, 16, 14],
];
const USB_PAGES_8822B: [[u32; 4]; 5] = [
    [64, 64, 64, 64],
    [64, 64, 64, 64],
    [64, 64, 0, 0],
    [64, 64, 64, 0],
    [64, 64, 64, 64],
];
/// `rtw8821c.c`/`rtw8822b.c` `usb_tx_agg_desc_num`.
const USB_TX_AGG_DESC_NUM: u8 = 3;

/// [`MacParams`] for a USB device: the `txdma_queue_mapping` / page rows for a
/// `bulkout` pipe count (2..=4) and die `did` (RTL8821CU `0xc821` / RTL8822BU
/// `0xb822`), plus the burst/aggregation tails. `burst` is the
/// `rtw_usb_init_burst_pkt_len` selector (Super 0 / High 1 / Full 2). `None`
/// for an unsupported die or pipe count (`txdma_queue_mapping` /
/// `priority_queue_cfg` reject those).
///
/// `#[inline]` so a `module`-build `.ko` codegens it locally rather than
/// leaving an undefined cross-crate symbol (the `.ko` is a single relocatable
/// object; only the kernel-ABI exports may stay undefined).
#[inline]
pub fn usb_mac_params(did: u16, bulkout: usize, burst: u8) -> Option<MacParams> {
    if !(2..=4).contains(&bulkout) {
        return None;
    }
    let page_rows = match did {
        0xc821 => &USB_PAGES_8821C,
        0xb822 => &USB_PAGES_8822B,
        _ => return None,
    };
    // mac.c::txdma_queue_mapping REG_TXDMA_PQ_MAP:
    // (hi<<14)|(mg<<12)|(bk<<10)|(be<<8)|(vi<<6)|(vo<<4).
    let r = USB_RQPN[bulkout];
    let txdma_pq_map = (u32::from(r[5]) << 14)
        | (u32::from(r[4]) << 12)
        | (u32::from(r[3]) << 10)
        | (u32::from(r[2]) << 8)
        | (u32::from(r[1]) << 6)
        | (u32::from(r[0]) << 4);
    // FIFOPAGE_INFO_1..4 = hq, lq, nq, exq (the page row is hq, nq, lq, exq).
    let p = page_rows[bulkout];
    let pages = [p[0], p[2], p[1], p[3]];
    Some(MacParams {
        txdma_pq_map,
        pages,
        usb: Some(UsbMacParams {
            tx_agg_desc_num: USB_TX_AGG_DESC_NUM,
            burst,
        }),
    })
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

async fn fifo(io: &mut impl Io, info: Info, did: u16, params: MacParams) -> Result<(), Error> {
    // mac.c::txdma_queue_mapping: PCIe uses rqpn_table[1]; USB the
    // bulk-out-count row of rqpn_table_8821c / rqpn_table_8822b (equal). The
    // caller resolved the row into `params`.
    w16(io, REG_TXDMA_PQ_MAP, params.txdma_pq_map).await?;
    w8(io, REG_CR, 0).await?;
    // Linux MAC_TRX_ENABLE is0xff. Only protocol/scheduler may be enabled
    // here: the existing firmware host rings, MAC and RF remain inactive.
    w8(io, REG_CR, MAC_TRX_ENABLE & !0xcf).await?;
    io.write32(REG_H2CQ_CSR, BIT_H2CQ_FULL).await?;
    if params.usb.is_some() {
        // txdma_queue_mapping USB tail: BIT_RXDMA_ARBBW_EN.
        u8(io, REG_TXDMA_PQ_MAP, 0, 1).await?;
    }
    // FIFOPAGE_INFO_1..4 = hq, lq, nq, exq (`__priority_queue_cfg`).
    let pages = params.pages;
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
    if let Some(u) = params.usb {
        // __priority_queue_cfg USB: BLK_DESC_NUM and AUTO_LLT_V1+3 =
        // usb_tx_agg_desc_num, TXDMA_OFFSET_CHK+1 BIT(1).
        u8(io, REG_AUTO_LLT_V1, 0xf0, u32::from(u.tx_agg_desc_num) << 4).await?;
        w8(io, REG_AUTO_LLT_V1 + 3, u.tx_agg_desc_num.into()).await?;
        u8(io, REG_TXDMA_OFFSET_CHK + 1, 0, 1 << 1).await?;
    }
    u8(io, REG_AUTO_LLT_V1, 0, BIT_AUTO_INIT_LLT_V1).await?;
    // mac.c busy-waits AUTO_INIT_LLT_V1 to self-clear (~10 ms: 1000 reads
    // spaced 10 us). `u32::MAX` means the device vanished (`poll32` -> Gone);
    // exhaustion is a timeout.
    crate::poll32(io, REG_AUTO_LLT_V1, BIT_AUTO_INIT_LLT_V1, 0, 1000, 10).await?;
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

/// `usb.c::rtw_usb_init_burst_pkt_len` (`rtw_usb_interface_cfg`'s register
/// writes), the USB tail of [`prepare`].
async fn interface_cfg(io: &mut impl Io, burst: u8) -> Result<(), Error> {
    io.write8(REG_RXDMA_MODE, 0x0c | 0x02 | burst << 4).await?;
    let value = io.read16(REG_TXDMA_OFFSET_CHK).await?;
    io.write16(REG_TXDMA_OFFSET_CHK, value | BIT_DROP_DATA_EN)
        .await
}

/// `mac.c::rtw_mac_init` over [`RegIo`] for the die `did`. `params` carries the
/// host-interface queue/page rows (PCIe or USB) the caller resolved; USB also
/// runs the burst `interface_cfg` tail. Returns the FIFO [`Info`] the firmware
/// command/PHY/RF stages consume. `did` 0xc822 is PCIe-only (its USB sibling
/// does not exist); a USB `params` for it is rejected as [`Error::Unsupported`]
/// (`ChipError::Unsupported`).
pub async fn prepare(io: &mut impl Io, did: u16, params: MacParams) -> Result<Info, Error> {
    if !matches!(did, 0xc821 | 0xc822 | 0xb822) || did == 0xc822 && params.usb.is_some() {
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
    fifo(io, info, did, params).await?;
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
    if let Some(u) = params.usb {
        // rtw_hci_interface_cfg -> usb.c::rtw_usb_init_burst_pkt_len.
        interface_cfg(io, u.burst).await?;
    }
    Ok(info)
}
