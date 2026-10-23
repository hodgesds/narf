// SPDX-License-Identifier: GPL-2.0-or-later
//! Checked RTL8188EU 1T1R RF/LC/IQ calibration. GPL-2.0-or-later.
//! Reference: Linux rtl8xxxu/{core,8188e}.c read_rfreg, phy_lc_calibrate,
//! rtl8188eu_{iqk_path_a,rx_iqk_path_a,phy_iqcalibrate,phy_iq_calibrate}.
//! Every USB failure exits immediately: cleanup never follows an ambiguous TD.
use super::calibration_regs as r;
use super::firmware_transport::{ControlIo, Error, Owner};

const ADDA: [u16; 16] = [
    r::REG_FPGA0_XCD_SWITCH_CTRL,
    r::REG_BLUETOOTH,
    r::REG_RX_WAIT_CCA,
    r::REG_TX_CCK_RFON,
    r::REG_TX_CCK_BBON,
    r::REG_TX_OFDM_RFON,
    r::REG_TX_OFDM_BBON,
    r::REG_TX_TO_RX,
    r::REG_TX_TO_TX,
    r::REG_RX_CCK,
    r::REG_RX_OFDM,
    r::REG_RX_WAIT_RIFS,
    r::REG_RX_TO_RX,
    r::REG_STANDBY,
    r::REG_SLEEP,
    r::REG_PMPD_ANAEN,
];
const BB: [u16; 9] = [
    r::REG_OFDM0_TRX_PATH_ENABLE,
    r::REG_OFDM0_TR_MUX_PAR,
    r::REG_FPGA0_XCD_RF_SW_CTRL,
    r::REG_CONFIG_ANT_A,
    r::REG_CONFIG_ANT_B,
    r::REG_FPGA0_XAB_RF_SW_CTRL,
    r::REG_FPGA0_XA_RF_INT_OE,
    r::REG_FPGA0_XB_RF_INT_OE,
    r::REG_CCK0_AFE_SETTING,
];
const MAC: [u16; 4] = [
    r::REG_TXPAUSE,
    r::REG_BEACON_CTRL,
    r::REG_BEACON_CTRL_1,
    r::REG_GPIO_MUXCFG,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IqResult {
    pub tx_x: u16,
    pub tx_y: u16,
    pub rx_x: u16,
    pub rx_y: u16,
}

pub(super) async fn read_rf<I: ControlIo>(o: &Owner<I>, address: u8) -> Result<u32, Error> {
    let high = o.read32(r::REG_FPGA0_XA_HSSI_PARM2).await?;
    if high == u32::MAX {
        return Err(Error::RadioRead);
    }
    let request = (high & !r::FPGA0_HSSI_PARM2_ADDR_MASK)
        | u32::from(address) << r::FPGA0_HSSI_PARM2_ADDR_SHIFT
        | r::FPGA0_HSSI_PARM2_EDGE_READ;
    o.write32(
        r::REG_FPGA0_XA_HSSI_PARM2,
        high & !r::FPGA0_HSSI_PARM2_EDGE_READ,
    )
    .await?;
    o.delay_us(10).await;
    o.write32(r::REG_FPGA0_XA_HSSI_PARM2, request).await?;
    o.delay_us(100).await;
    o.write32(
        r::REG_FPGA0_XA_HSSI_PARM2,
        high | r::FPGA0_HSSI_PARM2_EDGE_READ,
    )
    .await?;
    o.delay_us(10).await;
    let parameter = o.read32(r::REG_FPGA0_XA_HSSI_PARM1).await?;
    if parameter == u32::MAX {
        return Err(Error::RadioRead);
    }
    let register = if parameter & r::FPGA0_HSSI_PARM1_PI != 0 {
        r::REG_HSPI_XA_READBACK
    } else {
        r::REG_FPGA0_XA_LSSI_READBACK
    };
    let value = o.read32(register).await?;
    if value == u32::MAX {
        return Err(Error::RadioRead);
    }
    Ok(value & 0xfffff)
}
pub(super) async fn write_rf<I: ControlIo>(
    o: &Owner<I>,
    address: u8,
    value: u32,
) -> Result<(), Error> {
    o.write32(
        r::REG_FPGA0_XA_LSSI_PARM,
        u32::from(address) << 20 | value & 0xfffff,
    )
    .await?;
    o.delay_us(1).await;
    Ok(())
}

pub(super) async fn lc<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    let lstf = o.read32(r::REG_OFDM1_LSTF).await?;
    let continuous = lstf & r::OFDM_LSTF_MASK != 0;
    let mut mode = 0;
    // Save pause instead of assuming the caller had every queue unpaused.
    let pause = if !continuous {
        Some(o.read8(r::REG_TXPAUSE).await?)
    } else {
        None
    };
    if continuous {
        o.write32(r::REG_OFDM1_LSTF, lstf & !r::OFDM_LSTF_MASK)
            .await?;
        mode = read_rf(o, r::RF6052_REG_AC).await?;
        write_rf(o, r::RF6052_REG_AC, mode & 0x8ffff | 0x10000).await?;
    } else {
        o.write8(r::REG_TXPAUSE, 0xff).await?;
    }
    let channel = read_rf(o, r::RF6052_REG_MODE_AG).await?;
    write_rf(o, r::RF6052_REG_MODE_AG, channel | 0x8000).await?;
    o.delay_us(100_000).await;
    if continuous {
        o.write32(r::REG_OFDM1_LSTF, lstf).await?;
        write_rf(o, r::RF6052_REG_AC, mode).await?;
    } else {
        o.write8(r::REG_TXPAUSE, pause.unwrap()).await?;
    }
    Ok(())
}

async fn mode<I: ControlIo>(o: &Owner<I>, enabled: bool) -> Result<(), Error> {
    let previous = o.read32(r::REG_FPGA0_IQK).await?;
    o.write32(
        r::REG_FPGA0_IQK,
        previous & 0xff | if enabled { 0x80800000 } else { 0 },
    )
    .await
}
async fn writes<I: ControlIo>(o: &Owner<I>, sequence: &[(u16, u32)]) -> Result<(), Error> {
    for &(register, value) in sequence {
        o.write32(register, value).await?;
    }
    Ok(())
}
async fn trigger<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    o.write32(r::REG_IQK_AGC_PTS, 0xf9000000).await?;
    o.write32(r::REG_IQK_AGC_PTS, 0xf8000000).await?;
    o.delay_us(10_000).await;
    Ok(())
}
async fn tx_good<I: ControlIo>(o: &Owner<I>) -> Result<bool, Error> {
    let after = o.read32(r::REG_RX_POWER_AFTER_IQK_A_2).await?;
    let before = o.read32(r::REG_TX_POWER_BEFORE_IQK_A).await?;
    let tx_after = o.read32(r::REG_TX_POWER_AFTER_IQK_A).await?;
    Ok(after & (1 << 28) == 0
        && before & 0x03ff0000 != 0x01420000
        && tx_after & 0x03ff0000 != 0x00420000)
}
async fn tx_once<I: ControlIo>(o: &Owner<I>) -> Result<bool, Error> {
    writes(
        o,
        &[
            (r::REG_TX_IQK_TONE_A, 0x10008c1c),
            (r::REG_RX_IQK_TONE_A, 0x30008c1c),
            (r::REG_TX_IQK_PI_A, 0x8214032a),
            (r::REG_RX_IQK_PI_A, 0x28160000),
            (r::REG_IQK_AGC_RSP, 0x00462911),
        ],
    )
    .await?;
    trigger(o).await?;
    tx_good(o).await
}
async fn rx_pa<I: ControlIo>(o: &Owner<I>, gain: u32) -> Result<(), Error> {
    mode(o, false).await?;
    for (address, value) in [
        (r::RF6052_REG_WE_LUT, 0x800a0),
        (r::RF6052_REG_RCK_OS, 0x30000),
        (r::RF6052_REG_TXPA_G1, 0xf),
        (r::RF6052_REG_TXPA_G2, gain),
    ] {
        write_rf(o, address, value).await?;
    }
    mode(o, true).await
}
async fn rx_once<I: ControlIo>(o: &Owner<I>) -> Result<bool, Error> {
    rx_pa(o, 0xf117b).await?;
    writes(
        o,
        &[
            (r::REG_TX_IQK, 0x01007c00),
            (r::REG_RX_IQK, 0x81004800),
            (r::REG_TX_IQK_TONE_A, 0x10008c1c),
            (r::REG_RX_IQK_TONE_A, 0x30008c1c),
            (r::REG_TX_IQK_PI_A, 0x82160804),
            (r::REG_RX_IQK_PI_A, 0x28160000),
            (r::REG_IQK_AGC_RSP, 0x0046a911),
        ],
    )
    .await?;
    trigger(o).await?;
    if !tx_good(o).await? {
        return Ok(false);
    }
    let before = o.read32(r::REG_TX_POWER_BEFORE_IQK_A).await?;
    let after = o.read32(r::REG_TX_POWER_AFTER_IQK_A).await?;
    o.write32(
        r::REG_TX_IQK,
        0x80007c00 | before & 0x03ff0000 | after >> 16 & 0x3ff,
    )
    .await?;
    rx_pa(o, 0xf7ffa).await?;
    writes(
        o,
        &[
            (r::REG_RX_IQK, 0x01004800),
            (r::REG_TX_IQK_TONE_A, 0x30008c1c),
            (r::REG_RX_IQK_TONE_A, 0x10008c1c),
            (r::REG_TX_IQK_PI_A, 0x82160c05),
            (r::REG_RX_IQK_PI_A, 0x28160c05),
            (r::REG_IQK_AGC_RSP, 0x0046a911),
        ],
    )
    .await?;
    trigger(o).await?;
    let after = o.read32(r::REG_RX_POWER_AFTER_IQK_A_2).await?;
    let before = o.read32(r::REG_RX_POWER_BEFORE_IQK_A_2).await?;
    Ok(after & (1 << 27) == 0
        && before & 0x03ff0000 != 0x01320000
        && after & 0x03ff0000 != 0x00360000)
}

struct Backup {
    adda: [u32; 16],
    bb: [u32; 9],
    mac: [u32; 4],
    pi: bool,
}
impl Backup {
    async fn save<I: ControlIo>(o: &Owner<I>) -> Result<Self, Error> {
        let mut result = Self {
            adda: [0; 16],
            bb: [0; 9],
            mac: [0; 4],
            pi: false,
        };
        for (index, &register) in ADDA.iter().enumerate() {
            result.adda[index] = o.read32(register).await?;
        }
        for (index, &register) in BB.iter().enumerate() {
            result.bb[index] = o.read32(register).await?;
        }
        for (index, &register) in MAC[..3].iter().enumerate() {
            result.mac[index] = u32::from(o.read8(register).await?);
        }
        result.mac[3] = o.read32(MAC[3]).await?;
        result.pi = o.read32(r::REG_FPGA0_XA_HSSI_PARM1).await? & r::FPGA0_HSSI_PARM1_PI != 0;
        Ok(result)
    }
    async fn restore<I: ControlIo>(&self, o: &Owner<I>) -> Result<(), Error> {
        if !self.pi {
            o.write32(r::REG_FPGA0_XA_HSSI_PARM1, 0x01000000).await?;
            o.write32(r::REG_FPGA0_XB_HSSI_PARM1, 0x01000000).await?;
        }
        for (index, &register) in ADDA.iter().enumerate() {
            o.write32(register, self.adda[index]).await?;
        }
        for (index, &register) in MAC[..3].iter().enumerate() {
            o.write8(register, self.mac[index] as u8).await?;
        }
        o.write32(MAC[3], self.mac[3]).await?;
        for (index, &register) in BB.iter().enumerate() {
            o.write32(register, self.bb[index]).await?;
        }
        writes(
            o,
            &[
                (r::REG_FPGA0_XA_LSSI_PARM, 0x00032ed3),
                (r::REG_TX_IQK_TONE_A, 0x01008c00),
                (r::REG_RX_IQK_TONE_A, 0x01008c00),
            ],
        )
        .await
    }
}
async fn attempt<I: ControlIo>(o: &Owner<I>, backup: &Backup) -> Result<[u16; 4], Error> {
    for (index, &register) in ADDA.iter().enumerate() {
        o.write32(register, if index == 0 { 0x0b1b25a0 } else { 0x0bdb25a0 })
            .await?;
    }
    if !backup.pi {
        o.write32(r::REG_FPGA0_XA_HSSI_PARM1, 0x01000100).await?;
        o.write32(r::REG_FPGA0_XB_HSSI_PARM1, 0x01000100).await?;
    }
    o.write8(MAC[0], 0x3f).await?;
    for (index, &register) in MAC[1..3].iter().enumerate() {
        o.write8(register, backup.mac[index + 1] as u8 & !8).await?;
    }
    o.write8(MAC[3], backup.mac[3] as u8 & !32).await?;
    let value = o.read32(r::REG_CCK0_AFE_SETTING).await?;
    o.write32(r::REG_CCK0_AFE_SETTING, value | 0x0f000000)
        .await?;
    writes(
        o,
        &[
            (r::REG_OFDM0_TRX_PATH_ENABLE, 0x03a05600),
            (r::REG_OFDM0_TR_MUX_PAR, 0x000800e4),
            (r::REG_FPGA0_XCD_RF_SW_CTRL, 0x22204000),
        ],
    )
    .await?;
    let value = o.read32(r::REG_FPGA0_XAB_RF_SW_CTRL).await?;
    o.write32(
        r::REG_FPGA0_XAB_RF_SW_CTRL,
        value | r::FPGA0_RF_PAPE | r::FPGA0_RF_PAPE << r::FPGA0_RF_BD_CTRL_SHIFT,
    )
    .await?;
    for register in [r::REG_FPGA0_XA_RF_INT_OE, r::REG_FPGA0_XB_RF_INT_OE] {
        let value = o.read32(register).await?;
        o.write32(register, value & !(1 << 10)).await?;
    }
    o.write32(r::REG_CONFIG_ANT_A, 0x0f600000).await?;
    mode(o, true).await?;
    writes(
        o,
        &[(r::REG_TX_IQK, 0x01007c00), (r::REG_RX_IQK, 0x81004800)],
    )
    .await?;
    let mut result = [0; 4];
    for _ in 0..2 {
        if tx_once(o).await? {
            result[0] = (o.read32(r::REG_TX_POWER_BEFORE_IQK_A).await? >> 16 & 0x3ff) as u16;
            result[1] = (o.read32(r::REG_TX_POWER_AFTER_IQK_A).await? >> 16 & 0x3ff) as u16;
            break;
        }
    }
    for _ in 0..2 {
        if rx_once(o).await? {
            result[2] = (o.read32(r::REG_RX_POWER_BEFORE_IQK_A_2).await? >> 16 & 0x3ff) as u16;
            result[3] = (o.read32(r::REG_RX_POWER_AFTER_IQK_A_2).await? >> 16 & 0x3ff) as u16;
            break;
        }
    }
    mode(o, false).await?;
    Ok(result)
}

fn similar(first: [u16; 4], second: [u16; 4]) -> bool {
    first.iter().zip(second).all(|(&a, b)| a.abs_diff(b) <= 5)
}
fn signed(value: u16) -> i32 {
    if value & 0x200 != 0 {
        i32::from(value) - 1024
    } else {
        i32::from(value)
    }
}
async fn apply<I: ControlIo>(o: &Owner<I>, result: [u16; 4]) -> Result<(), Error> {
    let previous = o.read32(r::REG_OFDM0_XA_TX_IQ_IMBALANCE).await?;
    let old = previous >> 22;
    let x = signed(result[0]) as u32;
    let product = x.wrapping_mul(old);
    let value = o.read32(r::REG_OFDM0_XA_TX_IQ_IMBALANCE).await?;
    o.write32(
        r::REG_OFDM0_XA_TX_IQ_IMBALANCE,
        value & !0x3ff | product >> 8,
    )
    .await?;
    let value = o.read32(r::REG_OFDM0_ENERGY_CCA_THRES).await?;
    o.write32(
        r::REG_OFDM0_ENERGY_CCA_THRES,
        value & !(1 << 31) | (product >> 7 & 1) << 31,
    )
    .await?;
    let y = signed(result[1]);
    let product = y.wrapping_mul(old as i32);
    let c = product >> 8;
    let value = o.read32(r::REG_OFDM0_XC_TX_AFE).await?;
    o.write32(
        r::REG_OFDM0_XC_TX_AFE,
        value & !0xf0000000 | ((c as u32 & 0x3c0) >> 6) << 28,
    )
    .await?;
    let value = o.read32(r::REG_OFDM0_XA_TX_IQ_IMBALANCE).await?;
    o.write32(
        r::REG_OFDM0_XA_TX_IQ_IMBALANCE,
        value & !0x003f0000 | (c as u32 & 0x3f) << 16,
    )
    .await?;
    let value = o.read32(r::REG_OFDM0_ENERGY_CCA_THRES).await?;
    o.write32(
        r::REG_OFDM0_ENERGY_CCA_THRES,
        value & !(1 << 29) | (product as u32 >> 7 & 1) << 29,
    )
    .await?;
    let value = o.read32(r::REG_OFDM0_XA_RX_IQ_IMBALANCE).await?;
    o.write32(
        r::REG_OFDM0_XA_RX_IQ_IMBALANCE,
        value & !0xffff | u32::from(result[2]) | u32::from(result[3] & 0x3f) << 10,
    )
    .await?;
    let value = o.read32(r::REG_OFDM0_RX_IQ_EXT_ANTA).await?;
    o.write32(
        r::REG_OFDM0_RX_IQ_EXT_ANTA,
        value & !0xf0000000 | u32::from(result[3] >> 6 & 15) << 28,
    )
    .await
}

pub(super) async fn iq<I: ControlIo>(o: &Owner<I>) -> Result<IqResult, Error> {
    let backup = Backup::save(o).await?;
    let mut results = [[0; 4]; 3];
    let mut chosen = None;
    for index in 0..3 {
        results[index] = attempt(o, &backup).await?;
        // Completed status failure is safe to restore; USB error uses ? and
        // never follows an ambiguous TD with cleanup or another attempt.
        if index != 0 {
            backup.restore(o).await?;
        }
        if index == 1 && similar(results[0], results[1]) {
            chosen = Some(results[0]);
            break;
        }
        if index == 2 {
            for pair in [(0, 2), (1, 2)] {
                if similar(results[pair.0], results[pair.1]) {
                    chosen = Some(results[pair.0]);
                    break;
                }
            }
        }
    }
    let result = chosen
        .filter(|value| value[0] != 0 && value[2] != 0)
        .ok_or(Error::Calibration)?;
    apply(o, result).await?;
    Ok(IqResult {
        tx_x: result[0],
        tx_y: result[1],
        rx_x: result[2],
        rx_y: result[3],
    })
}
