//! RTL8192EU post-table MAC stage of `rtl8xxxu_init_device`, the stage after
//! LC/IQ calibration, two-path RF reads and the gen2 20/40 MHz channel
//! configuration.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/core.c::{rtl8xxxu_init_device, rtl8xxxu_set_spec_sifs,
//!   rtl8xxxu_set_retry, rtl8xxxu_read_rfreg, rtl8xxxu_gen2_config_channel}`
//! - `rtl8xxxu/8192e.c::{rtl8192eu_fops, rtl8192e_set_tx_power}`
//!
//! The 8192EU fops have no `init_reg_rxfltmap`, `init_burst`,
//! `init_aggregation`, `init_reg_pkt_life_time` or `init_statistics`, so
//! those `rtl8xxxu_init_device` branches are not taken. Unlike the 8188E the
//! 8192E keeps `REG_LEDCFG2` (no DPDT handover to the 8051) and its GPIO
//! mux, and writes `REG_FAST_EDCA_CTRL`, `REG_QUEUE_CTRL` and `REG_ACLK_MON`.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::rtl8192e_init::Factory;

const REG_AFE_MISC: u16 = 0x0010;
const REG_LDOV12_CTRL: u16 = super::rtl8192e::REG_8192E_LDOV12_CTRL;
const REG_ACLK_MON: u16 = 0x003e;
const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
const FWHW_TXQ_CTRL_AMPDU_RETRY: u32 = 1 << 7;
const FWHW_TXQ_CTRL_XMIT_MGMT_ACK: u32 = 1 << 12;
const REG_HWSEQ_CTRL: u16 = 0x0423;
const REG_SPEC_SIFS: u16 = 0x0428;
const REG_RETRY_LIMIT: u16 = 0x042a;
const REG_DARFRC: u16 = 0x0430;
const REG_RARFRC: u16 = 0x0438;
const REG_RESPONSE_RATE_SET: u16 = 0x0440;
const RESPONSE_RATE_BITMAP_ALL: u32 = 0xfffff;
const RESPONSE_RATE_RRSR_CCK_ONLY_1M: u32 = 0xffff1;
const REG_FAST_EDCA_CTRL: u16 = 0x0460;
const REG_DATA_SUBCHANNEL: u16 = 0x0483;
const REG_QUEUE_CTRL: u16 = 0x04c6;
const REG_BAR_MODE_CTRL: u16 = 0x04cc;
const REG_EDCA_VO_PARAM: u16 = 0x0500;
const REG_EDCA_VI_PARAM: u16 = 0x0504;
const REG_EDCA_BE_PARAM: u16 = 0x0508;
const REG_EDCA_BK_PARAM: u16 = 0x050c;
const REG_BEACON_TCFG: u16 = 0x0510;
const REG_SIFS_CCK: u16 = 0x0514;
const REG_SIFS_OFDM: u16 = 0x0516;
const REG_TBTT_PROHIBIT: u16 = 0x0540;
const REG_BEACON_CTRL: u16 = 0x0550;
const BEACON_DISABLE_TSF_UPDATE: u16 = 1 << 4;
const REG_DRIVER_EARLY_INT: u16 = 0x0558;
const DRIVER_EARLY_INT_TIME: u8 = 5;
const REG_BEACON_DMA_TIME: u16 = 0x0559;
const BEACON_DMA_ATIME_INT_TIME: u8 = 2;
const REG_RCR: u16 = 0x0608;
const RCR_ACCEPT_PHYS_MATCH: u32 = 1 << 1;
const RCR_ACCEPT_MCAST: u32 = 1 << 2;
const RCR_ACCEPT_BCAST: u32 = 1 << 3;
const RCR_ACCEPT_MGMT_FRAME: u32 = 1 << 13;
const RCR_HTC_LOC_CTRL: u32 = 1 << 14;
const RCR_APPEND_PHYSTAT: u32 = 1 << 28;
const RCR_APPEND_ICV: u32 = 1 << 29;
const RCR_APPEND_MIC: u32 = 1 << 30;
const REG_MAR: u16 = 0x0620;
const REG_MAC_SPEC_SIFS: u16 = 0x063a;
const REG_R2T_SIFS: u16 = 0x063c;
const REG_T2T_SIFS: u16 = 0x063e;
const REG_ACKTO: u16 = 0x0640;
const REG_NAV_UPPER: u16 = 0x0652;
const NAV_UPPER_UNIT: u32 = 128;
const REG_WMAC_TRXPTCL_CTL: u16 = 0x0668;
const WMAC_TRXPTCL_CTL_BW_MASK: u16 = (1 << 7) | (1 << 8);
const WMAC_TRXPTCL_CTL_BW_40: u16 = 1 << 7;
const REG_CAM_CMD: u16 = 0x0670;
const CAM_CMD_POLLING: u32 = 1 << 31;
const REG_FPGA0_RF_MODE: u16 = 0x0800;
const FPGA_RF_MODE: u32 = 1 << 0;
const FPGA_RF_MODE_CCK: u32 = 1 << 24;
const FPGA_RF_MODE_OFDM: u32 = 1 << 25;
const REG_FPGA0_POWER_SAVE: u16 = 0x0818;
const FPGA0_PS_LOWER_CHANNEL: u32 = 1 << 26;
const FPGA0_PS_UPPER_CHANNEL: u32 = 1 << 27;
const REG_FPGA0_XA_HSSI_PARM1: u16 = 0x0820;
const REG_FPGA0_XA_HSSI_PARM2: u16 = 0x0824;
const REG_FPGA0_XB_HSSI_PARM1: u16 = 0x0828;
const REG_FPGA0_XB_HSSI_PARM2: u16 = 0x082c;
const FPGA0_HSSI_PARM1_PI: u32 = 1 << 8;
const FPGA0_HSSI_PARM2_ADDR_SHIFT: u32 = 23;
const FPGA0_HSSI_PARM2_ADDR_MASK: u32 = 0x7f80_0000;
const FPGA0_HSSI_PARM2_EDGE_READ: u32 = 1 << 31;
const FPGA0_HSSI_PARM2_CCK_HIGH_PWR: u32 = 1 << 9;
const REG_FPGA0_XA_LSSI_READBACK: u16 = 0x08a0;
const REG_FPGA0_XB_LSSI_READBACK: u16 = 0x08a4;
const REG_HSPI_XA_READBACK: u16 = 0x08b8;
const REG_HSPI_XB_READBACK: u16 = 0x08bc;
const REG_FPGA1_RF_MODE: u16 = 0x0900;
const REG_CCK0_SYSTEM: u16 = 0x0a00;
const CCK0_SIDEBAND: u32 = 1 << 4;
const REG_AGC_RPT: u16 = 0x0a80;
const AGC_RPT_CCK: u32 = 1 << 7;
const REG_CCK_NEW_AGC: u16 = 0x0a9c;
const REG_OFDM0_TX_PSDO_NOISE_WEIGHT: u16 = 0x0ce4;
const REG_OFDM1_LSTF: u16 = 0x0d00;
const OFDM_LSTF_PRIME_CH_LOW: u32 = 1 << 10;
const OFDM_LSTF_PRIME_CH_HIGH: u32 = 1 << 11;
const OFDM_LSTF_PRIME_CH_MASK: u32 = OFDM_LSTF_PRIME_CH_LOW | OFDM_LSTF_PRIME_CH_HIGH;
const REG_OFDM1_CFO_TRACKING: u16 = 0x0d2c;
const CFO_TRACKING_ATC_STATUS: u32 = 1 << 11;
const REG_USB_HRPWM: u16 = 0xfe58;
const RF6052_REG_MODE_AG: u8 = 0x18;
const RF6052_REG_T_METER_8723B: u8 = 0x42;
const MODE_AG_CHANNEL_MASK: u32 = 0x3ff;
const MODE_AG_BW_MASK: u32 = (1 << 10) | (1 << 11);
const MODE_AG_BW_20MHZ_8723B: u32 = (1 << 10) | (1 << 11);
const MODE_AG_BW_40MHZ_8723B: u32 = 1 << 10;

/// `rtl8xxxu_init_device` RCR (`priv->regrcr`).
pub const RCR_INIT: u32 = RCR_ACCEPT_PHYS_MATCH
    | RCR_ACCEPT_MCAST
    | RCR_ACCEPT_BCAST
    | RCR_ACCEPT_MGMT_FRAME
    | RCR_HTC_LOC_CTRL
    | RCR_APPEND_PHYSTAT
    | RCR_APPEND_ICV
    | RCR_APPEND_MIC;

/// `rtl8xxxu_set_spec_sifs`.
pub fn spec_sifs(cck: u16, ofdm: u16) -> u16 {
    (cck & 0x00ff) | ((ofdm << 8) & 0xff00)
}

/// `rtl8xxxu_set_retry`.
pub fn retry_limit(short: u16, long: u16) -> u16 {
    ((short << 8) & 0x3f00) | (long & 0x003f)
}

async fn rmw32<I: ControlIo>(
    owner: &Owner<I>,
    reg: u16,
    clear: u32,
    set: u32,
) -> Result<u32, Error> {
    let value = (owner.read32(reg).await? & !clear) | set;
    owner.write32(reg, value).await?;
    Ok(value)
}

async fn rmw8<I: ControlIo>(owner: &Owner<I>, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
    let value = owner.read8(reg).await?;
    owner.write8(reg, (value & !clear) | set).await
}

/// `rtl8xxxu_read_rfreg` for path A or B (`rtl8xxxu_rfregs[]`). The edge
/// strobe always runs on path A's HSSI parameter 2, as in Linux. An all-ones
/// bus read is treated as a dead device rather than an RF value.
pub(super) async fn read_rfreg<I: ControlIo>(
    owner: &Owner<I>,
    path_b: bool,
    reg: u8,
) -> Result<u32, Error> {
    let (parm1, parm2, hspi, lssi) = if path_b {
        (
            REG_FPGA0_XB_HSSI_PARM1,
            REG_FPGA0_XB_HSSI_PARM2,
            REG_HSPI_XB_READBACK,
            REG_FPGA0_XB_LSSI_READBACK,
        )
    } else {
        (
            REG_FPGA0_XA_HSSI_PARM1,
            REG_FPGA0_XA_HSSI_PARM2,
            REG_HSPI_XA_READBACK,
            REG_FPGA0_XA_LSSI_READBACK,
        )
    };
    let hssia = owner.read32(REG_FPGA0_XA_HSSI_PARM2).await?;
    let base = if path_b {
        owner.read32(parm2).await?
    } else {
        hssia
    };
    if hssia == u32::MAX || base == u32::MAX {
        return Err(Error::RadioRead);
    }
    let request = (base & !FPGA0_HSSI_PARM2_ADDR_MASK)
        | (reg as u32) << FPGA0_HSSI_PARM2_ADDR_SHIFT
        | FPGA0_HSSI_PARM2_EDGE_READ;
    owner
        .write32(REG_FPGA0_XA_HSSI_PARM2, hssia & !FPGA0_HSSI_PARM2_EDGE_READ)
        .await?;
    owner.delay_us(10).await;
    owner.write32(parm2, request).await?;
    owner.delay_us(100).await;
    owner
        .write32(REG_FPGA0_XA_HSSI_PARM2, hssia | FPGA0_HSSI_PARM2_EDGE_READ)
        .await?;
    owner.delay_us(10).await;
    let pi = owner.read32(parm1).await?;
    if pi == u32::MAX {
        return Err(Error::RadioRead);
    }
    let value = owner
        .read32(if pi & FPGA0_HSSI_PARM1_PI != 0 {
            hspi
        } else {
            lssi
        })
        .await?;
    if value == u32::MAX {
        return Err(Error::RadioRead);
    }
    Ok(value & 0xfffff)
}

/// `rtl8xxxu_init_device` from the initial WMAC settings through
/// `REG_ACLK_MON`, i.e. everything between the HIMR clear and
/// `phy_lc_calibrate`. The CAM invalidate is polled to completion (Linux
/// does not poll); a CAM still busy is `CamTimeout`.
pub(super) async fn post_tables<I: ControlIo>(
    owner: &Owner<I>,
    factory: &Factory,
) -> Result<(), Error> {
    owner.write32(REG_RCR, RCR_INIT).await?;
    // No init_reg_rxfltmap: accept all multicast.
    owner.write32(REG_MAR, u32::MAX).await?;
    owner.write32(REG_MAR + 4, u32::MAX).await?;
    rmw32(
        owner,
        REG_RESPONSE_RATE_SET,
        RESPONSE_RATE_BITMAP_ALL,
        RESPONSE_RATE_RRSR_CCK_ONLY_1M,
    )
    .await?;
    owner.write16(REG_SPEC_SIFS, spec_sifs(0x10, 0x10)).await?;
    owner
        .write16(REG_RETRY_LIMIT, retry_limit(0x30, 0x30))
        .await?;
    owner.write16(REG_SPEC_SIFS, spec_sifs(0x0a, 0x10)).await?;
    for reg in [REG_MAC_SPEC_SIFS, REG_SIFS_CCK, REG_SIFS_OFDM] {
        owner.write16(reg, 0x100a).await?;
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
        owner.write32(reg, value).await?;
    }
    rmw8(owner, REG_FWHW_TXQ_CTRL, 0, FWHW_TXQ_CTRL_AMPDU_RETRY as u8).await?;
    owner.write8(REG_ACKTO, 0x40).await?;
    owner
        .write16(
            REG_BEACON_CTRL,
            BEACON_DISABLE_TSF_UPDATE | BEACON_DISABLE_TSF_UPDATE << 8,
        )
        .await?;
    owner.write16(REG_TBTT_PROHIBIT, 0x6404).await?;
    owner
        .write8(REG_DRIVER_EARLY_INT, DRIVER_EARLY_INT_TIME)
        .await?;
    owner
        .write8(REG_BEACON_DMA_TIME, BEACON_DMA_ATIME_INT_TIME)
        .await?;
    owner.write16(REG_BEACON_TCFG, 0x660f).await?;
    rmw32(
        owner,
        REG_FPGA0_RF_MODE,
        0,
        FPGA_RF_MODE_CCK | FPGA_RF_MODE_OFDM,
    )
    .await?;
    owner
        .write32(REG_CAM_CMD, CAM_CMD_POLLING | 1 << 30)
        .await?;
    let mut cleared = false;
    for _ in 0..1000 {
        if owner.read32(REG_CAM_CMD).await? & CAM_CMD_POLLING == 0 {
            cleared = true;
            break;
        }
        owner.delay_us(10).await;
    }
    if !cleared {
        return Err(Error::CamTimeout);
    }
    // "Start out with default power levels for channel 6, 20MHz" — Linux
    // passes channel 1.
    super::rtl8192e_phy::set_tx_power(owner, factory, 1, false).await?;
    owner.write8(REG_HWSEQ_CTRL, 0xff).await?;
    owner.write32(REG_BAR_MODE_CTRL, 0x0201_ffff).await?;
    owner.write16(REG_FAST_EDCA_CTRL, 0).await?;
    // 0x4c6[3] = 0: RTS bandwidth follows CCA / secondary CCA.
    rmw8(owner, REG_QUEUE_CTRL, 1 << 3, 0).await?;
    owner.write8(REG_ACLK_MON, 0).await
}

/// State `rtl8xxxu_init_device` keeps after calibration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostCalibration {
    /// `priv->cck_agc_report_type` (`0x824[9]`).
    pub cck_agc_report_type: bool,
    /// `priv->cck_new_agc` (`0xa9c[17]`).
    pub cck_new_agc: bool,
    /// `priv->cfo_tracking.atc_status` (`0xd2c[11]`).
    pub cfo_atc_status: bool,
}

/// `rtl8xxxu_init_device` after `phy_iq_calibrate`: gen2 thermal meter, NAV
/// upper bound, `REG_USB_HRPWM`, management-frame ACK, the 8192E LDPC RX hang
/// fix (`REG_AFE_MISC` + LDO 0x75), the CCK AGC report-type alignment of
/// `0x824[9]`/`0x82c[9]`/`0xa80[7]`, and the CCK-AGC/CFO state reads.
pub(super) async fn post_calibration<I: ControlIo>(
    owner: &Owner<I>,
) -> Result<PostCalibration, Error> {
    super::rtl8192e_phy::write_rfreg(owner, false, RF6052_REG_T_METER_8723B, 0x37cf8).await?;
    owner
        .write8(REG_NAV_UPPER, 30000u32.div_ceil(NAV_UPPER_UNIT) as u8)
        .await?;
    owner.write8(REG_USB_HRPWM, 0).await?;
    rmw32(owner, REG_FWHW_TXQ_CTRL, 0, FWHW_TXQ_CTRL_XMIT_MGMT_ACK).await?;
    let misc = owner.read32(REG_AFE_MISC).await?;
    owner.write8(REG_LDOV12_CTRL, 0x75).await?;
    owner
        .write32(REG_AFE_MISC, (misc & 0xfff0_0fff) | 0x0007_e000)
        .await?;
    let report = owner.read32(REG_FPGA0_XA_HSSI_PARM2).await? & FPGA0_HSSI_PARM2_CCK_HIGH_PWR != 0;
    let b = owner.read32(REG_FPGA0_XB_HSSI_PARM2).await?;
    if (b & FPGA0_HSSI_PARM2_CCK_HIGH_PWR != 0) != report {
        let b = if report {
            b | FPGA0_HSSI_PARM2_CCK_HIGH_PWR
        } else {
            b & !FPGA0_HSSI_PARM2_CCK_HIGH_PWR
        };
        owner.write32(REG_FPGA0_XB_HSSI_PARM2, b).await?;
    }
    let agc = owner.read32(REG_AGC_RPT).await?;
    owner
        .write32(
            REG_AGC_RPT,
            if report {
                agc | AGC_RPT_CCK
            } else {
                agc & !AGC_RPT_CCK
            },
        )
        .await?;
    let cck_new_agc = owner.read32(REG_CCK_NEW_AGC).await? & (1 << 17) != 0;
    let cfo_atc_status = owner.read32(REG_OFDM1_CFO_TRACKING).await? & CFO_TRACKING_ATC_STATUS != 0;
    Ok(PostCalibration {
        cck_agc_report_type: report,
        cck_new_agc,
        cfo_atc_status,
    })
}

/// Channel width handed to `rtl8xxxu_gen2_config_channel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    /// `NL80211_CHAN_WIDTH_20_NOHT`.
    NoHt20,
    /// `NL80211_CHAN_WIDTH_20`.
    Ht20,
    /// `NL80211_CHAN_WIDTH_40`, secondary channel above the primary.
    Ht40Above,
    /// `NL80211_CHAN_WIDTH_40`, secondary channel below the primary.
    Ht40Below,
}

/// RF channel (`MODE_AG[9:0]`) and `REG_DATA_SUBCHANNEL` value for a
/// primary channel, or `None` when the 2.4 GHz geometry is not admissible
/// (channel 14 is non-HT only; a 40 MHz pair must stay within 1..=13).
pub fn channel_geometry(primary: u8, width: Width) -> Option<(u8, u8)> {
    match width {
        Width::NoHt20 if (1..=14).contains(&primary) => Some((primary, 0)),
        Width::Ht20 if (1..=13).contains(&primary) => Some((primary, 0)),
        // Linux: center_freq1 > chan->center_freq → channel += 2, subchannel 2.
        Width::Ht40Above if (1..=9).contains(&primary) => Some((primary + 2, 2)),
        Width::Ht40Below if (5..=13).contains(&primary) => Some((primary - 2, 1)),
        _ => None,
    }
}

/// `rtl8xxxu_gen2_config_channel` for both RF paths (`priv->rf_paths = 2`
/// on the 8192EU and the 1T2R 8191EU).
pub(super) async fn config_channel<I: ControlIo>(
    owner: &Owner<I>,
    primary: u8,
    width: Width,
) -> Result<(), Error> {
    let (channel, subchannel) = channel_geometry(primary, width).ok_or(Error::RuntimeState)?;
    let forty = matches!(width, Width::Ht40Above | Width::Ht40Below);
    let above = width == Width::Ht40Above;
    let mut bw = owner.read16(REG_WMAC_TRXPTCL_CTL).await? & !WMAC_TRXPTCL_CTL_BW_MASK;
    if forty {
        bw |= WMAC_TRXPTCL_CTL_BW_40;
        rmw32(owner, REG_FPGA0_RF_MODE, 0, FPGA_RF_MODE).await?;
        rmw32(owner, REG_FPGA1_RF_MODE, 0, FPGA_RF_MODE).await?;
        rmw32(
            owner,
            REG_CCK0_SYSTEM,
            CCK0_SIDEBAND,
            if above { 0 } else { CCK0_SIDEBAND },
        )
        .await?;
        rmw32(
            owner,
            REG_OFDM1_LSTF,
            OFDM_LSTF_PRIME_CH_MASK,
            if above {
                OFDM_LSTF_PRIME_CH_LOW
            } else {
                OFDM_LSTF_PRIME_CH_HIGH
            },
        )
        .await?;
        rmw32(
            owner,
            REG_FPGA0_POWER_SAVE,
            FPGA0_PS_LOWER_CHANNEL | FPGA0_PS_UPPER_CHANNEL,
            if above {
                FPGA0_PS_UPPER_CHANNEL
            } else {
                FPGA0_PS_LOWER_CHANNEL
            },
        )
        .await?;
    } else {
        rmw32(owner, REG_FPGA0_RF_MODE, FPGA_RF_MODE, 0).await?;
        rmw32(owner, REG_FPGA1_RF_MODE, FPGA_RF_MODE, 0).await?;
        rmw32(
            owner,
            REG_OFDM0_TX_PSDO_NOISE_WEIGHT,
            (1 << 30) | (1 << 31),
            0,
        )
        .await?;
    }
    for path_b in [false, true] {
        let mode = read_rfreg(owner, path_b, RF6052_REG_MODE_AG).await?;
        super::rtl8192e_phy::write_rfreg(
            owner,
            path_b,
            RF6052_REG_MODE_AG,
            (mode & !MODE_AG_CHANNEL_MASK) | channel as u32,
        )
        .await?;
    }
    owner.write16(REG_WMAC_TRXPTCL_CTL, bw).await?;
    owner.write8(REG_DATA_SUBCHANNEL, subchannel).await?;
    let sifs = if width == Width::NoHt20 { 0x0a } else { 0x0e };
    owner.write8(REG_SIFS_CCK + 1, sifs).await?;
    owner.write8(REG_SIFS_OFDM + 1, sifs).await?;
    owner.write16(REG_R2T_SIFS, 0x0808).await?;
    owner.write16(REG_T2T_SIFS, 0x0a0a).await?;
    let bw_bits = if forty {
        MODE_AG_BW_40MHZ_8723B
    } else {
        MODE_AG_BW_20MHZ_8723B
    };
    for path_b in [false, true] {
        let mode = read_rfreg(owner, path_b, RF6052_REG_MODE_AG).await?;
        super::rtl8192e_phy::write_rfreg(
            owner,
            path_b,
            RF6052_REG_MODE_AG,
            (mode & !MODE_AG_BW_MASK) | bw_bits,
        )
        .await?;
    }
    Ok(())
}
