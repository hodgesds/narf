//! RTL8723BU post-table MAC stage of `rtl8xxxu_init_device` and the stage
//! after LC/IQ calibration.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/core.c::{rtl8xxxu_init_device, rtl8xxxu_set_spec_sifs,
//!   rtl8xxxu_set_retry, rtl8xxxu_init_burst}`
//! - `rtl8xxxu/8723b.c::{rtl8723bu_fops, rtl8723bu_init_aggregation,
//!   rtl8723bu_init_statistics}`
//!
//! The 8723BU fops have `init_burst` (`rtl8xxxu_init_burst`),
//! `init_aggregation` and `init_statistics` but no `init_reg_rxfltmap` or
//! `init_reg_pkt_life_time`. Unlike the RTL8192E, the 8723B hands antenna
//! control to the 8051 (`REG_LEDCFG2` DPDT select) and writes neither
//! `REG_QUEUE_CTRL` nor `REG_ACLK_MON` nor `REG_USB_HRPWM`; its GPIO mux is
//! left alone at this stage.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::rtl8192e_radio::{retry_limit, spec_sifs, RCR_INIT};
use super::rtl8723b_init::Factory;

const REG_RSV_CTRL: u16 = 0x001c;
const RSV_CTRL_WLOCK_1C: u8 = 1 << 5;
const RSV_CTRL_DIS_PRST: u8 = 1 << 6;
const REG_LEDCFG2: u16 = 0x004e;
const LEDCFG2_DPDT_SELECT: u8 = 1 << 7;
const REG_TRXDMA_CTRL: u16 = 0x010c;
const TRXDMA_CTRL_RXDMA_AGG_EN: u8 = 1 << 2;
const REG_RXDMA_AGG_PG_TH: u16 = 0x0280;
const RXDMA_USB_AGG_ENABLE: u32 = 1 << 31;
const REG_RXDMA_PRO_8723B: u16 = 0x0290;
const RXDMA_PRO_DMA_MODE: u8 = 1 << 1;
const RXDMA_PRO_DMA_BURST_CNT: u8 = 0x0c;
const RXDMA_PRO_DMA_BURST_SIZE: u8 = 0x30;
const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
const FWHW_TXQ_CTRL_AMPDU_RETRY: u8 = 1 << 7;
const FWHW_TXQ_CTRL_XMIT_MGMT_ACK: u32 = 1 << 12;
const REG_HWSEQ_CTRL: u16 = 0x0423;
const REG_SPEC_SIFS: u16 = 0x0428;
const REG_RETRY_LIMIT: u16 = 0x042a;
const REG_DARFRC: u16 = 0x0430;
const REG_RARFRC: u16 = 0x0438;
const REG_RESPONSE_RATE_SET: u16 = 0x0440;
const RESPONSE_RATE_BITMAP_ALL: u32 = 0xfffff;
const RESPONSE_RATE_RRSR_CCK_ONLY_1M: u32 = 0xffff1;
const REG_AMPDU_MAX_TIME_8723B: u16 = 0x0456;
const REG_AGGLEN_LMT: u16 = 0x0458;
const REG_FAST_EDCA_CTRL: u16 = 0x0460;
const REG_HT_SINGLE_AMPDU_8723B: u16 = 0x04c7;
const HT_SINGLE_AMPDU_ENABLE: u8 = 1 << 7;
const REG_MAX_AGGR_NUM: u16 = 0x04ca;
const REG_BAR_MODE_CTRL: u16 = 0x04cc;
const REG_EDCA_VO_PARAM: u16 = 0x0500;
const REG_EDCA_VI_PARAM: u16 = 0x0504;
const REG_EDCA_BE_PARAM: u16 = 0x0508;
const REG_EDCA_BK_PARAM: u16 = 0x050c;
const REG_BEACON_TCFG: u16 = 0x0510;
const REG_PIFS: u16 = 0x0512;
const REG_SIFS_CCK: u16 = 0x0514;
const REG_SIFS_OFDM: u16 = 0x0516;
const REG_TBTT_PROHIBIT: u16 = 0x0540;
const REG_BEACON_CTRL: u16 = 0x0550;
const BEACON_DISABLE_TSF_UPDATE: u16 = 1 << 4;
const REG_DRIVER_EARLY_INT: u16 = 0x0558;
const DRIVER_EARLY_INT_TIME: u8 = 5;
const REG_BEACON_DMA_TIME: u16 = 0x0559;
const BEACON_DMA_ATIME_INT_TIME: u8 = 2;
const REG_USTIME_TSF_8723B: u16 = 0x055c;
const REG_RCR: u16 = 0x0608;
const REG_RX_PKT_LIMIT: u16 = 0x060c;
const REG_MAR: u16 = 0x0620;
const REG_USTIME_EDCA: u16 = 0x0638;
const REG_MAC_SPEC_SIFS: u16 = 0x063a;
const REG_ACKTO: u16 = 0x0640;
const REG_NAV_UPPER: u16 = 0x0652;
const NAV_UPPER_UNIT: u32 = 128;
const REG_CAM_CMD: u16 = 0x0670;
const CAM_CMD_POLLING: u32 = 1 << 31;
const REG_FPGA0_RF_MODE: u16 = 0x0800;
const FPGA_RF_MODE_CCK: u32 = 1 << 24;
const FPGA_RF_MODE_OFDM: u32 = 1 << 25;
const REG_NHM_TH9_TH10_8723B: u16 = 0x0890;
const REG_NHM_TIMER_8723B: u16 = 0x0894;
const REG_NHM_TH3_TO_TH0_8723B: u16 = 0x0898;
const REG_NHM_TH7_TO_TH4_8723B: u16 = 0x089c;
const REG_CCK_NEW_AGC: u16 = 0x0a9c;
const REG_OFDM0_FA_RSTC: u16 = 0x0c0c;
const REG_OFDM1_CFO_TRACKING: u16 = 0x0d2c;
const CFO_TRACKING_ATC_STATUS: u32 = 1 << 11;
const REG_FPGA0_IQK: u16 = 0x0e28;
const RF6052_REG_T_METER_8723B: u8 = 0x42;

/// `rtl8723bu_fops.max_aggr_num`.
pub const MAX_AGGR_NUM: u16 = 0x0c14;
/// `rtl8723bu_fops.ampdu_max_time`.
pub const AMPDU_MAX_TIME: u8 = 0x5e;
/// `rtl8723bu_fops.ustime_tsf_edca`.
pub const USTIME_TSF_EDCA: u8 = 0x50;

async fn rmw32<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = o.read32(reg).await?;
    o.write32(reg, (value & !clear) | set).await
}

async fn rmw8<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
    let value = o.read8(reg).await?;
    o.write8(reg, (value & !clear) | set).await
}

/// `rtl8xxxu_init_burst` for the RTL8723B (not one of the 8188F/8710B/8192F
/// chips that also rewrite `FWHW_TXQ_CTRL`/`FAST_EDCA_CTRL` here).
async fn init_burst<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    // 512 B USB bursts: BURST_SIZE = 1, BURST_CNT = 3, DMA mode.
    rmw8(
        o,
        REG_RXDMA_PRO_8723B,
        RXDMA_PRO_DMA_BURST_SIZE | RXDMA_PRO_DMA_BURST_CNT,
        (1 << 4) | (3 << 2) | RXDMA_PRO_DMA_MODE,
    )
    .await?;
    rmw8(o, REG_HT_SINGLE_AMPDU_8723B, 0, HT_SINGLE_AMPDU_ENABLE).await?;
    o.write16(REG_MAX_AGGR_NUM, MAX_AGGR_NUM).await?;
    o.write8(REG_AMPDU_MAX_TIME_8723B, AMPDU_MAX_TIME).await?;
    o.write32(REG_AGGLEN_LMT, u32::MAX).await?;
    o.write8(REG_RX_PKT_LIMIT, 0x18).await?;
    o.write8(REG_PIFS, 0x00).await?;
    o.write8(REG_USTIME_TSF_8723B, USTIME_TSF_EDCA).await?;
    o.write8(REG_USTIME_EDCA, USTIME_TSF_EDCA).await?;
    rmw8(o, REG_RSV_CTRL, 0, RSV_CTRL_WLOCK_1C | RSV_CTRL_DIS_PRST).await
}

/// `rtl8723bu_init_aggregation`: RX aggregation disabled (both reads come
/// before both writes, as in Linux).
async fn init_aggregation<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    let ctrl = o.read8(REG_TRXDMA_CTRL).await? & !TRXDMA_CTRL_RXDMA_AGG_EN;
    let rx = o.read32(REG_RXDMA_AGG_PG_TH).await? & !RXDMA_USB_AGG_ENABLE & !0xff0f;
    o.write8(REG_TRXDMA_CTRL, ctrl).await?;
    o.write32(REG_RXDMA_AGG_PG_TH, rx).await
}

/// `rtl8723bu_init_statistics`: NHM timer/thresholds, TH8, CCK in NHM and
/// max-power-over-antennas in `OFDM0_FA_RSTC`.
async fn init_statistics<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    o.write16(REG_NHM_TIMER_8723B + 2, 0x2710).await?;
    o.write16(REG_NHM_TH9_TH10_8723B + 2, 0xffff).await?;
    o.write32(REG_NHM_TH3_TO_TH0_8723B, 0xffff_ff52).await?;
    o.write32(REG_NHM_TH7_TO_TH4_8723B, u32::MAX).await?;
    rmw32(o, REG_FPGA0_IQK, 0, 0xff).await?;
    rmw32(
        o,
        REG_NHM_TH9_TH10_8723B,
        0,
        (1 << 8) | (1 << 9) | (1 << 10),
    )
    .await?;
    rmw32(o, REG_OFDM0_FA_RSTC, 0, 1 << 7).await
}

/// `rtl8xxxu_init_device` from the initial WMAC settings through
/// `init_statistics`, i.e. everything between the HIMR write and
/// `phy_lc_calibrate`. The CAM invalidate is polled to completion (Linux
/// does not poll); a CAM still busy is `CamTimeout`.
pub(super) async fn post_tables<I: ControlIo>(
    o: &Owner<I>,
    factory: &Factory,
) -> Result<(), Error> {
    o.write32(REG_RCR, RCR_INIT).await?;
    // No init_reg_rxfltmap: accept all multicast.
    o.write32(REG_MAR, u32::MAX).await?;
    o.write32(REG_MAR + 4, u32::MAX).await?;
    rmw32(
        o,
        REG_RESPONSE_RATE_SET,
        RESPONSE_RATE_BITMAP_ALL,
        RESPONSE_RATE_RRSR_CCK_ONLY_1M,
    )
    .await?;
    o.write16(REG_SPEC_SIFS, spec_sifs(0x10, 0x10)).await?;
    o.write16(REG_RETRY_LIMIT, retry_limit(0x30, 0x30)).await?;
    o.write16(REG_SPEC_SIFS, spec_sifs(0x0a, 0x10)).await?;
    for reg in [REG_MAC_SPEC_SIFS, REG_SIFS_CCK, REG_SIFS_OFDM] {
        o.write16(reg, 0x100a).await?;
    }
    for (reg, value) in [
        (REG_EDCA_BE_PARAM, 0x005e_a42b),
        (REG_EDCA_BK_PARAM, 0x0000_a44f),
        (REG_EDCA_VI_PARAM, 0x005e_a324),
        (REG_EDCA_VO_PARAM, 0x002f_a226),
        (REG_DARFRC, 0),
        (REG_DARFRC + 4, 0x1008_0404),
        (REG_RARFRC, 0x0403_0201),
        (REG_RARFRC + 4, 0x0807_0605),
    ] {
        o.write32(reg, value).await?;
    }
    rmw8(o, REG_FWHW_TXQ_CTRL, 0, FWHW_TXQ_CTRL_AMPDU_RETRY).await?;
    o.write8(REG_ACKTO, 0x40).await?;
    o.write16(
        REG_BEACON_CTRL,
        BEACON_DISABLE_TSF_UPDATE | BEACON_DISABLE_TSF_UPDATE << 8,
    )
    .await?;
    o.write16(REG_TBTT_PROHIBIT, 0x6404).await?;
    o.write8(REG_DRIVER_EARLY_INT, DRIVER_EARLY_INT_TIME)
        .await?;
    o.write8(REG_BEACON_DMA_TIME, BEACON_DMA_ATIME_INT_TIME)
        .await?;
    o.write16(REG_BEACON_TCFG, 0x660f).await?;
    init_burst(o).await?;
    init_aggregation(o).await?;
    rmw32(
        o,
        REG_FPGA0_RF_MODE,
        0,
        FPGA_RF_MODE_CCK | FPGA_RF_MODE_OFDM,
    )
    .await?;
    o.write32(REG_CAM_CMD, CAM_CMD_POLLING | 1 << 30).await?;
    let mut cleared = false;
    for _ in 0..1000 {
        if o.read32(REG_CAM_CMD).await? & CAM_CMD_POLLING == 0 {
            cleared = true;
            break;
        }
        o.delay_us(10).await;
    }
    if !cleared {
        return Err(Error::CamTimeout);
    }
    // "Start out with default power levels for channel 6, 20MHz" — Linux
    // passes channel 1.
    super::rtl8723b_phy::set_tx_power(o, factory, 1, false).await?;
    // Let the 8051 take control of antenna setting.
    rmw8(o, REG_LEDCFG2, 0, LEDCFG2_DPDT_SELECT).await?;
    o.write8(REG_HWSEQ_CTRL, 0xff).await?;
    o.write32(REG_BAR_MODE_CTRL, 0x0201_ffff).await?;
    o.write16(REG_FAST_EDCA_CTRL, 0).await?;
    init_statistics(o).await
}

/// State `rtl8xxxu_init_device` keeps after calibration on the RTL8723B
/// (`priv->cck_agc_report_type` is RTL8192E-only and stays 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostCalibration {
    /// `priv->cck_new_agc` (`0xa9c[17]`).
    pub cck_new_agc: bool,
    /// `priv->cfo_tracking.atc_status` (`0xd2c[11]`).
    pub cfo_atc_status: bool,
}

/// `rtl8xxxu_init_device` after `phy_iq_calibrate` for the RTL8723B: gen2
/// thermal meter (`RF_A 0x42 = 0x37cf8`), the NAV upper bound, the
/// management-frame ACK and the CCK-AGC/CFO state reads.
pub(super) async fn post_calibration<I: ControlIo>(o: &Owner<I>) -> Result<PostCalibration, Error> {
    super::rtl8723b_phy::write_rfreg(o, RF6052_REG_T_METER_8723B, 0x37cf8).await?;
    o.write8(REG_NAV_UPPER, 30000u32.div_ceil(NAV_UPPER_UNIT) as u8)
        .await?;
    rmw32(o, REG_FWHW_TXQ_CTRL, 0, FWHW_TXQ_CTRL_XMIT_MGMT_ACK).await?;
    let cck_new_agc = o.read32(REG_CCK_NEW_AGC).await? & (1 << 17) != 0;
    let cfo_atc_status = o.read32(REG_OFDM1_CFO_TRACKING).await? & CFO_TRACKING_ATC_STATUS != 0;
    Ok(PostCalibration {
        cck_new_agc,
        cfo_atc_status,
    })
}
