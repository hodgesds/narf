// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EU post-table MAC configuration and LC/IQ calibration.
//! Source: Linux rtl8xxxu/core.c::rtl8xxxu_init_device and 8188e.c fops.
//! MAC TX/RX remain closed until a retained packet/station owner activates
//! a policy-admitted channel. Factory power indices are not a dBm policy.
use super::{
    calibration, calibration_regs as r,
    device_init::Factory,
    firmware_transport::{ControlIo, Error, Owner},
};

async fn update8<I: ControlIo>(
    o: &Owner<I>,
    register: u16,
    clear: u8,
    set: u8,
) -> Result<(), Error> {
    let v = o.read8(register).await?;
    o.write8(register, (v & !clear) | set).await
}
async fn update32<I: ControlIo>(
    o: &Owner<I>,
    register: u16,
    clear: u32,
    set: u32,
) -> Result<(), Error> {
    let v = o.read32(register).await?;
    o.write32(register, (v & !clear) | set).await
}

/// Source-matched initial channel-one gain indices, while MAC transmission
/// is closed. No regulatory dBm limit is inferred from these calibration bytes.
pub(super) async fn power<I: ControlIo>(
    o: &Owner<I>,
    f: Factory,
    channel: u8,
) -> Result<(), Error> {
    if !(1..=14).contains(&channel) {
        return Err(Error::BadEfuse);
    }
    let group = match channel {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        _ => 4,
    };
    let cck_group = if channel == 14 { 5 } else { group };
    let cck = f.cck_power[cck_group];
    let ht = f.ht40_power[group];
    if cck > 0x3f || ht > 0x3f {
        return Err(Error::BadEfuse);
    }
    update32(o, r::REG_TX_AGC_A_CCK1_MCS32, 0xff00, u32::from(cck) << 8).await?;
    update32(
        o,
        r::REG_TX_AGC_B_CCK11_A_CCK2_11,
        0xffffff00,
        u32::from(cck) * 0x01010100,
    )
    .await?;
    // Linux 8188E EFUSE parsing populates bases only; per-rate differences
    // remain zero in its zero-initialized private state for this chip.
    for reg in [
        r::REG_TX_AGC_A_RATE18_06,
        r::REG_TX_AGC_A_RATE54_24,
        r::REG_TX_AGC_A_MCS03_MCS00,
        r::REG_TX_AGC_A_MCS07_MCS04,
        r::REG_TX_AGC_A_MCS11_MCS08,
        r::REG_TX_AGC_A_MCS15_MCS12,
    ] {
        o.write32(reg, u32::from(ht) * 0x01010101).await?;
    }
    Ok(())
}

pub(super) async fn configure<I: ControlIo>(
    o: &Owner<I>,
    f: Factory,
) -> Result<calibration::IqResult, Error> {
    // Reject erased/out-of-range calibration before programming any gains.
    if f.cck_power
        .iter()
        .chain(f.ht40_power.iter())
        .any(|&v| v > 0x3f)
    {
        return Err(Error::BadEfuse);
    }
    if o.read16(r::REG_CR).await? & 0xc0 != 0 {
        return Err(Error::Calibration);
    }
    let switch = r::FPGA0_RF_TRSW
        | r::FPGA0_RF_TRSWB
        | r::FPGA0_RF_ANTSW
        | r::FPGA0_RF_ANTSWB
        | r::FPGA0_RF_PAPE;
    o.write32(
        r::REG_FPGA0_XAB_RF_SW_CTRL,
        switch
            | ((r::FPGA0_RF_ANTSW | r::FPGA0_RF_ANTSWB | r::FPGA0_RF_PAPE)
                << r::FPGA0_RF_BD_CTRL_SHIFT),
    )
    .await?;
    update32(o, r::REG_TXDMA_OFFSET_CHK, 0, r::TXDMA_OFFSET_DROP_DATA_EN).await?;
    o.write8(r::REG_EARLY_MODE_CONTROL_8188E + 3, 1).await?;
    update8(
        o,
        r::REG_TX_REPORT_CTRL,
        0,
        1 | r::TX_REPORT_CTRL_TIMER_ENABLE as u8,
    )
    .await?;
    o.write8(r::REG_TX_REPORT_CTRL + 1, 2).await?;
    o.write16(r::REG_TX_REPORT_TIME, 0xcdf0).await?;
    update8(o, 0xa3, 7, 0).await?;
    o.write8(r::REG_RX_DRVINFO_SZ, 4).await?;
    o.write32(r::REG_HISR0, u32::MAX).await?;
    o.write32(
        r::REG_HIMR0,
        r::IMR0_PSTIMEOUT | r::IMR0_TBDER | r::IMR0_CPWM | r::IMR0_CPWM2,
    )
    .await?;
    o.write32(
        r::REG_HIMR1,
        r::IMR1_TXERR | r::IMR1_RXERR | r::IMR1_TXFOVW | r::IMR1_RXFOVW,
    )
    .await?;
    update8(
        o,
        r::REG_USB_SPECIAL_OPTION,
        r::USB_SPEC_USB_AGG_ENABLE as u8,
        r::USB_SPEC_INT_BULK_SELECT as u8,
    )
    .await?;
    update8(o, r::REG_TRXDMA_CTRL, r::TRXDMA_CTRL_RXDMA_AGG_EN as u8, 0).await?;
    let filter = r::RCR_ACCEPT_PHYS_MATCH
        | r::RCR_ACCEPT_MCAST
        | r::RCR_ACCEPT_BCAST
        | r::RCR_ACCEPT_MGMT_FRAME
        | r::RCR_HTC_LOC_CTRL
        | r::RCR_APPEND_PHYSTAT
        | r::RCR_APPEND_ICV
        | r::RCR_APPEND_MIC;
    o.write32(r::REG_RCR, filter).await?;
    for reg in [r::REG_MAR, r::REG_MAR + 4] {
        o.write32(reg, u32::MAX).await?;
    }
    for (i, byte) in f.mac.iter().enumerate() {
        o.write8(r::REG_MACID + i as u16, *byte).await?;
    }
    update32(
        o,
        r::REG_RESPONSE_RATE_SET,
        r::RESPONSE_RATE_BITMAP_ALL,
        r::RESPONSE_RATE_RRSR_CCK_ONLY_1M,
    )
    .await?;
    o.write16(r::REG_SPEC_SIFS, 0x100a).await?;
    o.write16(r::REG_RETRY_LIMIT, 0x3030).await?;
    for reg in [r::REG_MAC_SPEC_SIFS, r::REG_SIFS_CCK, r::REG_SIFS_OFDM] {
        o.write16(reg, 0x100a).await?;
    }
    for (reg, value) in [
        (r::REG_EDCA_BE_PARAM, 0x005ea42b),
        (r::REG_EDCA_BK_PARAM, 0x0000a44f),
        (r::REG_EDCA_VI_PARAM, 0x005ea324),
        (r::REG_EDCA_VO_PARAM, 0x002fa226),
        (r::REG_DARFRC, 0),
        (r::REG_DARFRC + 4, 0x10080404),
        (r::REG_RARFRC, 0x04030201),
        (r::REG_RARFRC + 4, 0x08070605),
    ] {
        o.write32(reg, value).await?;
    }
    update8(
        o,
        r::REG_FWHW_TXQ_CTRL,
        0,
        r::FWHW_TXQ_CTRL_AMPDU_RETRY as u8,
    )
    .await?;
    o.write8(r::REG_ACKTO, 0x40).await?;
    o.write16(r::REG_BEACON_CTRL, 0x1010).await?;
    o.write16(r::REG_TBTT_PROHIBIT, 0x6404).await?;
    o.write8(r::REG_DRIVER_EARLY_INT, r::DRIVER_EARLY_INT_TIME as u8)
        .await?;
    o.write8(r::REG_BEACON_DMA_TIME, r::BEACON_DMA_ATIME_INT_TIME as u8)
        .await?;
    o.write16(r::REG_BEACON_TCFG, 0x660f).await?;
    for reg in [r::REG_PKT_VO_VI_LIFE_TIME, r::REG_PKT_BE_BK_LIFE_TIME] {
        o.write16(reg, 0x400).await?;
    }
    update32(
        o,
        r::REG_FPGA0_RF_MODE,
        0,
        r::FPGA_RF_MODE_CCK | r::FPGA_RF_MODE_OFDM,
    )
    .await?;
    // Clear old hardware keys and disable TX/RX decryption. The pending
    // software CCMP path must receive the original ciphertext + MIC.
    o.write32(r::REG_CAM_CMD, r::CAM_CMD_POLLING | 1 << 30)
        .await?;
    let mut cleared = false;
    for _ in 0..1000 {
        if o.read32(r::REG_CAM_CMD).await? & r::CAM_CMD_POLLING == 0 {
            cleared = true;
            break;
        }
        o.delay_us(10).await;
    }
    if !cleared {
        return Err(Error::CamTimeout);
    }
    o.write8(r::REG_SECURITY_CFG, 0).await?;
    power(o, f, 1).await?;
    // Establish the first 20MHz radio channel/crystal before LC/IQK while
    // MAC packet gates are closed. A later policy owner controls activation.
    super::channel_runtime::initial20(o, f, 1).await?;
    update8(o, r::REG_LEDCFG2, 0, r::LEDCFG2_DPDT_SELECT as u8).await?;
    o.write8(r::REG_HWSEQ_CTRL, 0xff).await?;
    o.write32(r::REG_BAR_MODE_CTRL, 0x0201ffff).await?;
    update8(o, r::REG_GPIO_MUXCFG, r::GPIO_MUXCFG_IO_SEL_ENBT as u8, 0).await?;
    calibration::lc(o).await?;
    let result = calibration::iq(o).await?;
    calibration::write_rf(o, r::RF6052_REG_T_METER_8723B, 0x37cf8).await?;
    o.write8(r::REG_NAV_UPPER, 30000u32.div_ceil(r::NAV_UPPER_UNIT) as u8)
        .await?;
    o.write8(r::REG_USB_HRPWM, 0).await?;
    update32(o, r::REG_FWHW_TXQ_CTRL, 0, r::FWHW_TXQ_CTRL_XMIT_MGMT_ACK).await?;
    if o.read16(r::REG_CR).await? & 0xc0 != 0 {
        return Err(Error::Calibration);
    }
    Ok(result)
}
