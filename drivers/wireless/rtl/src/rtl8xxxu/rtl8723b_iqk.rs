//! RTL8723BU LC calibration and path-A IQ calibration as
//! `rtl8xxxu_init_device` runs them (`fops->phy_lc_calibrate`, then
//! `fops->phy_iq_calibrate`).
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/core.c::{rtl8723a_phy_lc_calibrate (has_s0s1 = 1),
//!   rtl8xxxu_gen2_prepare_calibrate, rtl8xxxu_save_regs,
//!   rtl8xxxu_restore_regs, rtl8xxxu_save_mac_regs,
//!   rtl8xxxu_restore_mac_regs, rtl8xxxu_path_adda_on,
//!   rtl8xxxu_mac_calibration, rtl8xxxu_gen2_simularity_compare,
//!   rtl8xxxu_fill_iqk_matrix_a}`
//! - `rtl8xxxu/8723b.c::{rtl8723bu_iqk_path_a, rtl8723bu_rx_iqk_path_a,
//!   rtl8723bu_phy_iqcalibrate, rtl8723bu_phy_iq_calibrate}`
//!
//! `RTL8723BU_BT` is not defined in Linux, so the `GNT_BT = 1` writes after
//! each one-shot are not issued. The 8723BU is 1T1R (`tx_paths = rf_paths =
//! 1`): S0S1 is switched to `0x280` around each one-shot and no path-B work
//! runs. Every register write, RF write, delay and retry follows Linux. One
//! deliberate difference: Linux keeps the power-on IQ matrix when no
//! candidate is found (`candidate = -1`) or the candidate has no path-A TX
//! result; this owner finishes Linux's post-IQK restore (BT control,
//! RF PA table, calibration-done H2C) and then reports `Error::Calibration`,
//! as the RTL8192EU and RTL8188EU owners do.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::rtl8192e_iqk::{fill_matrix, simularity_compare, MatrixRegs, Row, PHY_IQ_BB_REGS};
use super::rtl8192e_radio::read_rfreg;
use super::rtl8723b_phy::write_rfreg;

const REG_GPIO_MUXCFG: u16 = 0x0040;
const REG_TXPAUSE: u16 = 0x0522;
const REG_BEACON_CTRL: u16 = 0x0550;
const REG_BEACON_CTRL_1: u16 = 0x0551;
/// `REG_BT_CONTROL_8723BU`; bit 11 is the BT grant used during IQK.
pub const REG_BT_CONTROL: u16 = 0x0764;
const REG_FPGA0_RF_MODE: u16 = 0x0800;
const REG_FPGA0_XCD_SWITCH_CTRL: u16 = 0x085c;
const REG_FPGA0_XA_RF_INT_OE: u16 = 0x0860;
const REG_FPGA0_XB_RF_INT_OE: u16 = 0x0864;
const REG_FPGA0_XAB_RF_SW_CTRL: u16 = 0x0870;
const REG_FPGA0_XCD_RF_SW_CTRL: u16 = 0x0874;
const REG_S0S1_PATH_SWITCH: u16 = 0x0948;
const REG_CCK0_AFE_SETTING: u16 = 0x0a04;
const REG_CONFIG_ANT_A: u16 = 0x0b68;
const REG_CONFIG_ANT_B: u16 = 0x0b6c;
const REG_OFDM0_TRX_PATH_ENABLE: u16 = 0x0c04;
const REG_OFDM0_TR_MUX_PAR: u16 = 0x0c08;
const REG_OFDM0_XA_RX_IQ_IMBALANCE: u16 = 0x0c14;
const REG_OFDM0_XA_AGC_CORE1: u16 = 0x0c50;
const REG_OFDM0_XB_AGC_CORE1: u16 = 0x0c58;
const REG_OFDM0_XA_TX_IQ_IMBALANCE: u16 = 0x0c80;
const REG_OFDM0_XC_TX_AFE: u16 = 0x0c94;
const REG_OFDM1_LSTF: u16 = 0x0d00;
const OFDM_LSTF_MASK: u32 = 0x7000_0000;
const REG_FPGA0_IQK: u16 = 0x0e28;
const REG_TX_IQK_TONE_A: u16 = 0x0e30;
const REG_RX_IQK_TONE_A: u16 = 0x0e34;
const REG_TX_IQK_PI_A: u16 = 0x0e38;
const REG_RX_IQK_PI_A: u16 = 0x0e3c;
const REG_TX_IQK: u16 = 0x0e40;
const REG_RX_IQK: u16 = 0x0e44;
const REG_IQK_AGC_PTS: u16 = 0x0e48;
const REG_IQK_AGC_RSP: u16 = 0x0e4c;
const REG_TX_IQK_TONE_B: u16 = 0x0e50;
const REG_RX_IQK_TONE_B: u16 = 0x0e54;
const REG_TX_IQK_PI_B: u16 = 0x0e58;
const REG_RX_IQK_PI_B: u16 = 0x0e5c;
const REG_BLUETOOTH: u16 = 0x0e6c;
const REG_RX_WAIT_CCA: u16 = 0x0e70;
const REG_TX_CCK_RFON: u16 = 0x0e74;
const REG_TX_CCK_BBON: u16 = 0x0e78;
const REG_TX_OFDM_RFON: u16 = 0x0e7c;
const REG_TX_OFDM_BBON: u16 = 0x0e80;
const REG_TX_TO_RX: u16 = 0x0e84;
const REG_TX_TO_TX: u16 = 0x0e88;
const REG_RX_CCK: u16 = 0x0e8c;
const REG_TX_POWER_BEFORE_IQK_A: u16 = 0x0e94;
const REG_TX_POWER_AFTER_IQK_A: u16 = 0x0e9c;
const REG_RX_POWER_BEFORE_IQK_A_2: u16 = 0x0ea4;
const REG_RX_POWER_AFTER_IQK_A_2: u16 = 0x0eac;
const REG_RX_OFDM: u16 = 0x0ed0;
const REG_RX_WAIT_RIFS: u16 = 0x0ed4;
const REG_RX_TO_RX: u16 = 0x0ed8;
const REG_STANDBY: u16 = 0x0edc;
const REG_SLEEP: u16 = 0x0ee0;
const REG_PMPD_ANAEN: u16 = 0x0eec;

const RF_AC: u8 = 0x00;
const RF_MODE_AG: u8 = 0x18;
const RF_RCK_OS: u8 = 0x30;
const RF_TXPA_G1: u8 = 0x31;
const RF_TXPA_G2: u8 = 0x32;
const RF_UNKNOWN_43: u8 = 0x43;
const RF_UNKNOWN_55: u8 = 0x55;
const RF_S0S1: u8 = 0xb0;
const RF_GAIN_CCA: u8 = 0xdf;
const RF_UNKNOWN_ED: u8 = 0xed;
const RF_WE_LUT: u8 = 0xef;

/// `rtl8723bu_fops.adda_1t_init` / `adda_1t_path_on` (both `0x01c00014`).
pub const ADDA_1T: u32 = 0x01c0_0014;
/// `H2C_8723B_BT_WLAN_CALIBRATION`.
pub const H2C_BT_WLAN_CALIBRATION: u8 = 0x6d;
/// S0S1 path for the 1T USB module during a one-shot (`rf_paths == 1`).
pub const S0S1_IQK: u32 = 0x0000_0280;
/// BT grant during IQK (`REG_BT_CONTROL_8723BU = 0x800`).
pub const BT_CONTROL_IQK: u32 = 0x0000_0800;

const ADDA_REGS: [u16; 16] = [
    REG_FPGA0_XCD_SWITCH_CTRL,
    REG_BLUETOOTH,
    REG_RX_WAIT_CCA,
    REG_TX_CCK_RFON,
    REG_TX_CCK_BBON,
    REG_TX_OFDM_RFON,
    REG_TX_OFDM_BBON,
    REG_TX_TO_RX,
    REG_TX_TO_TX,
    REG_RX_CCK,
    REG_RX_OFDM,
    REG_RX_WAIT_RIFS,
    REG_RX_TO_RX,
    REG_STANDBY,
    REG_SLEEP,
    REG_PMPD_ANAEN,
];
const MAC_REGS: [u16; 4] = [
    REG_TXPAUSE,
    REG_BEACON_CTRL,
    REG_BEACON_CTRL_1,
    REG_GPIO_MUXCFG,
];
/// `rtl8723bu_phy_iqcalibrate::iqk_bb_regs` (ends in `REG_FPGA0_RF_MODE`,
/// unlike the RTL8192EU list).
const BB_REGS: [u16; 9] = [
    REG_OFDM0_TRX_PATH_ENABLE,
    REG_OFDM0_TR_MUX_PAR,
    REG_FPGA0_XCD_RF_SW_CTRL,
    REG_CONFIG_ANT_A,
    REG_CONFIG_ANT_B,
    REG_FPGA0_XAB_RF_SW_CTRL,
    REG_FPGA0_XA_RF_INT_OE,
    REG_FPGA0_XB_RF_INT_OE,
    REG_FPGA0_RF_MODE,
];

/// Outcome of `rtl8723bu_phy_iq_calibrate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Iqk {
    /// Linux `candidate` (0, 1 or 3).
    pub candidate: usize,
    /// The chosen row (`result[candidate]`); path-B entries stay 0.
    pub row: Row,
    /// `priv->bb_recovery_backup`.
    pub recovery: [u32; 9],
}

async fn rmw32<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = o.read32(reg).await?;
    o.write32(reg, (value & !clear) | set).await
}

async fn writes<I: ControlIo>(o: &Owner<I>, sequence: &[(u16, u32)]) -> Result<(), Error> {
    for &(reg, value) in sequence {
        o.write32(reg, value).await?;
    }
    Ok(())
}

/// `val32 = read32(REG_FPGA0_IQK) & 0xff; [val32 |= enter;] write32`.
async fn iqk_mode<I: ControlIo>(o: &Owner<I>, enter: bool) -> Result<(), Error> {
    let value = o.read32(REG_FPGA0_IQK).await? & 0xff;
    let value = if enter { value | 0x8080_0000 } else { value };
    o.write32(REG_FPGA0_IQK, value).await
}

/// `WE_LUT |= 0x80000` then `RCK_OS`, `TXPA_G1`, `TXPA_G2`.
async fn pa_table<I: ControlIo>(o: &Owner<I>, rck: u32, g1: u32, g2: u32) -> Result<(), Error> {
    let lut = read_rfreg(o, false, RF_WE_LUT).await? | 0x80000;
    write_rfreg(o, RF_WE_LUT, lut).await?;
    write_rfreg(o, RF_RCK_OS, rck).await?;
    write_rfreg(o, RF_TXPA_G1, g1).await?;
    write_rfreg(o, RF_TXPA_G2, g2).await
}

/// The four tones, four PI words and the LO calibration word.
async fn iqk_setting<I: ControlIo>(
    o: &Owner<I>,
    tones: [u32; 4],
    pi: [u32; 4],
    rsp: u32,
) -> Result<(), Error> {
    writes(
        o,
        &[
            (REG_TX_IQK_TONE_A, tones[0]),
            (REG_RX_IQK_TONE_A, tones[1]),
            (REG_TX_IQK_TONE_B, tones[2]),
            (REG_RX_IQK_TONE_B, tones[3]),
            (REG_TX_IQK_PI_A, pi[0]),
            (REG_RX_IQK_PI_A, pi[1]),
            (REG_TX_IQK_PI_B, pi[2]),
            (REG_RX_IQK_PI_B, pi[3]),
            (REG_IQK_AGC_RSP, rsp),
        ],
    )
    .await
}

/// Enter IQK mode, S0S1 `0x280`, BT grant `0x800`, one-shot path-A LOK/IQK,
/// `mdelay(1)`, restore the antenna path, leave IQK mode.
async fn one_shot<I: ControlIo>(o: &Owner<I>, path_sel: u32) -> Result<(), Error> {
    iqk_mode(o, true).await?;
    o.write32(REG_S0S1_PATH_SWITCH, S0S1_IQK).await?;
    o.write32(REG_BT_CONTROL, BT_CONTROL_IQK).await?;
    o.write32(REG_IQK_AGC_PTS, 0xf900_0000).await?;
    o.write32(REG_IQK_AGC_PTS, 0xf800_0000).await?;
    o.delay_us(1_000).await;
    o.write32(REG_S0S1_PATH_SWITCH, path_sel).await?;
    iqk_mode(o, false).await
}

/// `(reg >> 16) & 0x3ff`, folded to a magnitude when bit 9 is set.
fn magnitude(reg: u32) -> u32 {
    let value = (reg >> 16) & 0x3ff;
    if value & 0x200 != 0 {
        0x400 - value
    } else {
        value
    }
}

/// The `rtl8723bu_iqk_path_a` TX pass test.
pub fn tx_ok(eac: u32, e94: u32, e9c: u32) -> bool {
    let e94 = e94 & 0x03ff_0000;
    eac & (1 << 28) == 0
        && e94 != 0x0142_0000
        && e9c & 0x03ff_0000 != 0x0042_0000
        && e94 < 0x0110_0000
        && e94 > 0x00f0_0000
        && magnitude(e9c) < 0xf
}

/// The `rtl8723bu_rx_iqk_path_a` RX pass test.
pub fn rx_ok(eac: u32, ea4: u32) -> bool {
    let ea4 = ea4 & 0x03ff_0000;
    eac & (1 << 27) == 0
        && ea4 != 0x0132_0000
        && eac & 0x03ff_0000 != 0x0036_0000
        && ea4 < 0x0110_0000
        && ea4 > 0x00f0_0000
        && magnitude(eac) < 0xf
}

/// `rtl8723bu_iqk_path_a`: path-A TX IQK, `true` on Linux's `0x01`.
async fn iqk_path_a<I: ControlIo>(o: &Owner<I>) -> Result<bool, Error> {
    let path_sel = o.read32(REG_S0S1_PATH_SWITCH).await?;
    iqk_mode(o, false).await?;
    pa_table(o, 0x20000, 0x0003f, 0xc7f87).await?;
    writes(o, &[(REG_TX_IQK, 0x0100_7c00), (REG_RX_IQK, 0x0100_4800)]).await?;
    iqk_setting(
        o,
        [0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c],
        [0x8214_03ea, 0x2811_0000, 0x8211_0000, 0x2811_0000],
        0x0046_2911,
    )
    .await?;
    one_shot(o, path_sel).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let e94 = o.read32(REG_TX_POWER_BEFORE_IQK_A).await?;
    let e9c = o.read32(REG_TX_POWER_AFTER_IQK_A).await?;
    Ok(tx_ok(eac, e94, e9c))
}

/// `rtl8723bu_rx_iqk_path_a`: returns the Linux bitmask (bit 0 TX, bit 1
/// RX); RX is attempted only after a passing TX stage.
async fn rx_iqk_path_a<I: ControlIo>(o: &Owner<I>) -> Result<u8, Error> {
    let path_sel = o.read32(REG_S0S1_PATH_SWITCH).await?;
    iqk_mode(o, false).await?;
    pa_table(o, 0x30000, 0x0001f, 0xf7fb7).await?;
    writes(o, &[(REG_TX_IQK, 0x0100_7c00), (REG_RX_IQK, 0x0100_4800)]).await?;
    iqk_setting(
        o,
        [0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c],
        [0x8216_0ff0, 0x2811_0000, 0x8211_0000, 0x2811_0000],
        0x0046_a911,
    )
    .await?;
    one_shot(o, path_sel).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let e94 = o.read32(REG_TX_POWER_BEFORE_IQK_A).await?;
    let e9c = o.read32(REG_TX_POWER_AFTER_IQK_A).await?;
    if !tx_ok(eac, e94, e9c) {
        return Ok(0);
    }
    o.write32(
        REG_TX_IQK,
        0x8000_7c00 | (e94 & 0x03ff_0000) | ((e9c & 0x03ff_0000) >> 16),
    )
    .await?;
    iqk_mode(o, false).await?;
    pa_table(o, 0x30000, 0x0001f, 0xf7d77).await?;
    write_rfreg(o, RF_GAIN_CCA, 0xf80).await?;
    write_rfreg(o, RF_UNKNOWN_55, 0x4021f).await?;
    o.write32(REG_RX_IQK, 0x0100_4800).await?;
    iqk_setting(
        o,
        [0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c],
        [0x8211_0000, 0x2816_001f, 0x8211_0000, 0x2811_0000],
        0x0046_a8d1,
    )
    .await?;
    one_shot(o, path_sel).await?;
    let eac = o.read32(REG_RX_POWER_AFTER_IQK_A_2).await?;
    let ea4 = o.read32(REG_RX_POWER_BEFORE_IQK_A_2).await?;
    write_rfreg(o, RF_GAIN_CCA, 0x780).await?;
    Ok(if rx_ok(eac, ea4) { 0x03 } else { 0x01 })
}

/// Register state saved on the first run (`priv->{adda,mac,bb}_backup`).
struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    bb: [u32; 9],
}

impl Backup {
    async fn save<I: ControlIo>(o: &Owner<I>) -> Result<Self, Error> {
        let mut backup = Self {
            adda: [0; 16],
            mac: [0; 4],
            bb: [0; 9],
        };
        for (slot, &reg) in backup.adda.iter_mut().zip(ADDA_REGS.iter()) {
            *slot = o.read32(reg).await?;
        }
        for (slot, &reg) in backup.mac[..3].iter_mut().zip(MAC_REGS[..3].iter()) {
            *slot = o.read8(reg).await? as u32;
        }
        backup.mac[3] = o.read32(MAC_REGS[3]).await?;
        for (slot, &reg) in backup.bb.iter_mut().zip(BB_REGS.iter()) {
            *slot = o.read32(reg).await?;
        }
        Ok(backup)
    }

    async fn restore<I: ControlIo>(&self, o: &Owner<I>) -> Result<(), Error> {
        for (&value, &reg) in self.adda.iter().zip(ADDA_REGS.iter()) {
            o.write32(reg, value).await?;
        }
        for (&value, &reg) in self.mac[..3].iter().zip(MAC_REGS[..3].iter()) {
            o.write8(reg, value as u8).await?;
        }
        o.write32(MAC_REGS[3], self.mac[3]).await?;
        for (&value, &reg) in self.bb.iter().zip(BB_REGS.iter()) {
            o.write32(reg, value).await?;
        }
        Ok(())
    }
}

/// `rtl8723bu_phy_iqcalibrate` for run `t`.
async fn iqcalibrate<I: ControlIo>(
    o: &Owner<I>,
    result: &mut [Row; 4],
    t: usize,
    saved: &mut Option<Backup>,
) -> Result<(), Error> {
    let xa_agc = o.read32(REG_OFDM0_XA_AGC_CORE1).await? & 0xff;
    // Linux reads the path-B AGC too; it is only used for 2T boards.
    o.read32(REG_OFDM0_XB_AGC_CORE1).await?;
    if t == 0 {
        *saved = Some(Backup::save(o).await?);
    }
    let backup = saved.as_ref().ok_or(Error::Calibration)?;
    // rtl8xxxu_path_adda_on, tx_paths == 1: regs[0] = adda_1t_init, the
    // rest adda_1t_path_on (both 0x01c00014).
    for &reg in ADDA_REGS.iter() {
        o.write32(reg, ADDA_1T).await?;
    }
    // rtl8xxxu_mac_calibration
    o.write8(MAC_REGS[0], 0x3f).await?;
    for (&reg, &value) in MAC_REGS[1..3].iter().zip(backup.mac[1..3].iter()) {
        o.write8(reg, (value & !(1 << 3)) as u8).await?;
    }
    o.write8(MAC_REGS[3], (backup.mac[3] & !(1 << 5)) as u8)
        .await?;
    rmw32(o, REG_CCK0_AFE_SETTING, 0, 0x0f00_0000).await?;
    writes(
        o,
        &[
            (REG_OFDM0_TRX_PATH_ENABLE, 0x03a0_5600),
            (REG_OFDM0_TR_MUX_PAR, 0x0008_00e4),
            (REG_FPGA0_XCD_RF_SW_CTRL, 0x2220_4000),
        ],
    )
    .await?;
    // "RX IQ calibration setting for 8723B D cut large current issue when
    // leaving IPS".
    iqk_mode(o, false).await?;
    pa_table(o, 0x30000, 0x0001f, 0xf7fb7).await?;
    let ed = read_rfreg(o, false, RF_UNKNOWN_ED).await? | 0x20;
    write_rfreg(o, RF_UNKNOWN_ED, ed).await?;
    write_rfreg(o, RF_UNKNOWN_43, 0x60fbd).await?;
    for _ in 0..2 {
        if iqk_path_a(o).await? {
            iqk_mode(o, false).await?;
            result[t][0] = (o.read32(REG_TX_POWER_BEFORE_IQK_A).await? >> 16) & 0x3ff;
            result[t][1] = (o.read32(REG_TX_POWER_AFTER_IQK_A).await? >> 16) & 0x3ff;
            break;
        }
    }
    for _ in 0..2 {
        if rx_iqk_path_a(o).await? == 0x03 {
            result[t][2] = (o.read32(REG_RX_POWER_BEFORE_IQK_A_2).await? >> 16) & 0x3ff;
            result[t][3] = (o.read32(REG_RX_POWER_AFTER_IQK_A_2).await? >> 16) & 0x3ff;
            break;
        }
    }
    iqk_mode(o, false).await?;
    if t != 0 {
        backup.restore(o).await?;
        let value = o.read32(REG_OFDM0_XA_AGC_CORE1).await? & 0xffff_ff00;
        o.write32(REG_OFDM0_XA_AGC_CORE1, value | 0x50).await?;
        o.write32(REG_OFDM0_XA_AGC_CORE1, value | xa_agc).await?;
        writes(
            o,
            &[
                (REG_TX_IQK_TONE_A, 0x0100_8c00),
                (REG_RX_IQK_TONE_A, 0x0100_8c00),
            ],
        )
        .await?;
    }
    Ok(())
}

/// `rtl8723bu_phy_iq_calibrate` candidate selection after run `t`
/// (`Some(None)` is Linux's `candidate = -1`).
pub fn choose(result: &mut [Row; 4], t: usize) -> Option<Option<usize>> {
    match t {
        1 if simularity_compare(result, 0, 1, 1) => Some(Some(0)),
        2 => {
            if simularity_compare(result, 0, 2, 1) {
                Some(Some(0))
            } else if simularity_compare(result, 1, 2, 1) {
                Some(Some(1))
            } else if result[3].iter().any(|&v| v != 0) {
                Some(Some(3))
            } else {
                Some(None)
            }
        }
        _ => None,
    }
}

/// `rtl8723bu_phy_iq_calibrate`.
pub(super) async fn iq_calibrate<I: ControlIo>(o: &Owner<I>) -> Result<Iqk, Error> {
    super::rtl8192e_init::h2c(o, &[H2C_BT_WLAN_CALIBRATION, 1]).await?;
    let bt_control = o.read32(REG_BT_CONTROL).await?;
    let mut result = [[0u32; 8]; 4];
    let mut backup = None;
    let mut candidate = None;
    for t in 0..3 {
        iqcalibrate(o, &mut result, t, &mut backup).await?;
        if let Some(chosen) = choose(&mut result, t) {
            candidate = chosen;
            break;
        }
    }
    let chosen = candidate.filter(|&c| result[c][0] != 0);
    if let Some(c) = chosen {
        let row = result[c];
        fill_matrix(
            o,
            &MatrixRegs {
                tx_iq: REG_OFDM0_XA_TX_IQ_IMBALANCE,
                tx_afe: REG_OFDM0_XC_TX_AFE,
                rx_iq: REG_OFDM0_XA_RX_IQ_IMBALANCE,
                cca_x_bit: 31,
                cca_y_bit: 29,
            },
            [row[0], row[1], row[2], row[3]],
            row[2] == 0,
            false,
        )
        .await?;
    }
    let mut recovery = [0u32; 9];
    for (slot, &reg) in recovery.iter_mut().zip(PHY_IQ_BB_REGS.iter()) {
        *slot = o.read32(reg).await?;
    }
    o.write32(REG_BT_CONTROL, bt_control).await?;
    pa_table(o, 0x18000, 0x0001f, 0xe6177).await?;
    let ed = read_rfreg(o, false, RF_UNKNOWN_ED).await? | 0x20;
    write_rfreg(o, RF_UNKNOWN_ED, ed).await?;
    write_rfreg(o, RF_UNKNOWN_43, 0x300bd).await?;
    super::rtl8192e_init::h2c(o, &[H2C_BT_WLAN_CALIBRATION, 0]).await?;
    let candidate = chosen.ok_or(Error::Calibration)?;
    Ok(Iqk {
        candidate,
        row: result[candidate],
        recovery,
    })
}

/// `rtl8723a_phy_lc_calibrate` with `has_s0s1 = 1` and `tx_paths = 1`: the
/// RF `0xb0` S0S1 LCK bracket around `MODE_AG[15]` and 100 ms.
pub(super) async fn lc_calibrate<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    let lstf = o.read32(REG_OFDM1_LSTF).await?;
    let continuous = lstf & OFDM_LSTF_MASK != 0;
    let mut a_mode = 0;
    if continuous {
        o.write32(REG_OFDM1_LSTF, lstf & !OFDM_LSTF_MASK).await?;
        a_mode = read_rfreg(o, false, RF_AC).await?;
        write_rfreg(o, RF_AC, (a_mode & 0x8ffff) | 0x10000).await?;
    } else {
        o.write8(REG_TXPAUSE, 0xff).await?;
    }
    write_rfreg(o, RF_S0S1, 0xdfbe0).await?;
    let mode = read_rfreg(o, false, RF_MODE_AG).await?;
    write_rfreg(o, RF_MODE_AG, mode | 0x08000).await?;
    o.delay_us(100_000).await;
    write_rfreg(o, RF_S0S1, 0xdffe0).await?;
    if continuous {
        o.write32(REG_OFDM1_LSTF, lstf).await?;
        write_rfreg(o, RF_AC, a_mode).await
    } else {
        o.write8(REG_TXPAUSE, 0).await
    }
}
