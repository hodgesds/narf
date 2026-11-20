// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE IQ calibration (both paths) and LC calibration.
//!
//! Exact `rtl8192ee/phy.c`:
//!
//! - `rtl92ee_phy_iq_calibrate(hw, false)`: up to three
//!   `_rtl92ee_phy_iq_calibrate(t, is2t = true)` runs with
//!   `_rtl92ee_phy_simularity_compare` after the second and third (12 → 0;
//!   13 → 0; 23 → 1; else 3), `final_candidate` 0xff when fewer runs were
//!   compared, then `_rtl92ee_phy_path_{a,b}_fill_iqk_matrix` and the save of
//!   the nine result registers (`iqk_bb_backup`, reloaded by the
//!   `b_recovery` form [`recover`]).
//! - `_rtl92ee_phy_iq_calibrate(t)`: at `t == 0` the ADDA / MAC / BB
//!   backups; ADDA on (`0x0fc01616`), BB IQK mode, MAC `0x520[23:16] = 0xff`,
//!   two retries each of path A TX (`0x01`), path A RX (`0x03`), path A
//!   standby, ADDA on, two retries each of path B TX / RX; leave IQK mode;
//!   for `t != 0` the reloads, `0xc50`/`0xc58` initial-gain toggles (Linux
//!   writes `0x50` to `0xc50` twice; kept) and the tone resets. Linux does
//!   not restore after `t == 0`; neither does this.
//! - Matrix fills keep Linux's u32 wrapping products and unmasked
//!   `rtl_set_bbreg` values. Linux's path-B fill reads and writes
//!   `ROFDM0_XATXIQIMBALANCE` (path A's register) for `tx1_a`; kept.
//! - `_rtl92ee_phy_lc_calibrate(is2t = false)` as `rtl92ee_phy_lc_calibrate`
//!   runs it. Linux never calls it on 8192EE (no hw_init or DM caller), so
//!   the init flow here does not run it either.

use super::phy::{get_bb, get_rf, set_bb, set_rf, Path, MASKDWORD, RFREG_OFFSET_MASK};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const RFPGA0_RFMOD: u16 = 0x800;
pub const RFPGA0_XAB_RFINTERFACESW: u16 = 0x870;
pub const RFPGA0_XCD_RFINTERFACESW: u16 = 0x874;
pub const RFPGA0_XA_RFINTERFACEOE: u16 = 0x860;
pub const RFPGA0_XB_RFINTERFACEOE: u16 = 0x864;
pub const ROFDM0_TRXPATHENABLE: u16 = 0xc04;
pub const ROFDM0_TRMUXPAR: u16 = 0xc08;
pub const ROFDM0_XARXIQIMBALANCE: u16 = 0xc14;
pub const ROFDM0_XBRXIQIMBALANCE: u16 = 0xc1c;
pub const ROFDM0_ECCATHRESHOLD: u16 = 0xc4c;
pub const ROFDM0_AGCRSSITABLE: u16 = 0xc78;
pub const ROFDM0_XATXIQIMBALANCE: u16 = 0xc80;
pub const ROFDM0_XBTXIQIMBALANCE: u16 = 0xc88;
pub const ROFDM0_XCTXAFE: u16 = 0xc94;
pub const ROFDM0_XDTXAFE: u16 = 0xc9c;
pub const ROFDM0_RXIQEXTANTA: u16 = 0xca0;
pub const RFPGA0_IQK: u16 = 0xe28;
pub const RTX_IQK_TONE_A: u16 = 0xe30;
pub const RRX_IQK_TONE_A: u16 = 0xe34;
pub const RTX_IQK_PI_A: u16 = 0xe38;
pub const RRX_IQK_PI_A: u16 = 0xe3c;
pub const RTX_IQK: u16 = 0xe40;
pub const RRX_IQK: u16 = 0xe44;
pub const RIQK_AGC_PTS: u16 = 0xe48;
pub const RIQK_AGC_RSP: u16 = 0xe4c;
pub const RTX_IQK_TONE_B: u16 = 0xe50;
pub const RRX_IQK_TONE_B: u16 = 0xe54;
pub const RTX_IQK_PI_B: u16 = 0xe58;
pub const RRX_IQK_PI_B: u16 = 0xe5c;
pub const RTX_POWER_BEFORE_IQK_A: u16 = 0xe94;
pub const RTX_POWER_AFTER_IQK_A: u16 = 0xe9c;
pub const RRX_POWER_BEFORE_IQK_A_2: u16 = 0xea4;
pub const RRX_POWER_AFTER_IQK_A_2: u16 = 0xeac;
pub const RTX_POWER_BEFORE_IQK_B: u16 = 0xeb4;
pub const RTX_POWER_AFTER_IQK_B: u16 = 0xebc;
pub const RRX_POWER_BEFORE_IQK_B_2: u16 = 0xec4;
pub const RRX_POWER_AFTER_IQK_B_2: u16 = 0xecc;
pub const REG_TXPAUSE: u16 = 0x522;

pub const RF_WE_LUT: u32 = 0xef;
pub const RF_RCK_OS: u32 = 0x30;
pub const RF_TXPA_G1: u32 = 0x31;
pub const RF_TXPA_G2: u32 = 0x32;
pub const MASK12BITS: u32 = 0xfff;
/// `IQK_DELAY_TIME` (ms).
pub const IQK_DELAY_US: u64 = 10_000;
pub const MAX_TOLERANCE: u32 = 5;
const RETRY: usize = 2;

pub const ADDA_REGS: [u16; 16] = [
    0x85c, 0xe6c, 0xe70, 0xe74, 0xe78, 0xe7c, 0xe80, 0xe84, 0xe88, 0xe8c, 0xed0, 0xed4, 0xed8,
    0xedc, 0xee0, 0xeec,
];
/// `iqk_mac_reg`: three byte backups then a dword (`0x040`).
pub const MAC_REGS: [u16; 4] = [0x522, 0x550, 0x551, 0x040];
pub const BB_REGS: [u16; 9] = [
    ROFDM0_TRXPATHENABLE,
    ROFDM0_TRMUXPAR,
    RFPGA0_XCD_RFINTERFACESW,
    0xb68,
    0xb6c,
    0x870,
    0x860,
    0x864,
    0x800,
];
/// `rtl92ee_phy_iq_calibrate`'s result-register backup (`iqk_bb_reg`).
pub const RESULT_REGS: [u16; 9] = [
    ROFDM0_XARXIQIMBALANCE,
    ROFDM0_XBRXIQIMBALANCE,
    ROFDM0_ECCATHRESHOLD,
    ROFDM0_AGCRSSITABLE,
    ROFDM0_XATXIQIMBALANCE,
    ROFDM0_XBTXIQIMBALANCE,
    ROFDM0_XCTXAFE,
    ROFDM0_XDTXAFE,
    ROFDM0_RXIQEXTANTA,
];

/// Backups taken at `t == 0`.
#[derive(Clone, Copy, Debug, Default)]
struct Backup {
    adda: [u32; 16],
    mac: [u32; 4],
    bb: [u32; 9],
}

/// Outcome of one full calibration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub result: [[u32; 8]; 4],
    pub final_candidate: u8,
    /// `rtlphy->iqk_bb_backup` after the fill (input to [`recover`]).
    pub saved: [u32; 9],
}

fn field(v: u32) -> u32 {
    (v & 0x03ff_0000) >> 16
}

async fn shot(io: &impl Io, pts: u32) -> Result<(), Error> {
    set_bb(io, RIQK_AGC_PTS, MASKDWORD, pts)?;
    set_bb(io, RIQK_AGC_PTS, MASKDWORD, 0xf800_0000)?;
    io.delay_us(IQK_DELAY_US).await;
    Ok(())
}

async fn tones(io: &impl Io, v: [u32; 4]) -> Result<(), Error> {
    set_bb(io, RTX_IQK_TONE_A, MASKDWORD, v[0])?;
    set_bb(io, RRX_IQK_TONE_A, MASKDWORD, v[1])?;
    set_bb(io, RTX_IQK_TONE_B, MASKDWORD, v[2])?;
    set_bb(io, RRX_IQK_TONE_B, MASKDWORD, v[3])
}

async fn pad_0(io: &impl Io, path: Path) -> Result<(), Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    set_rf(io, path, 0xdf, RFREG_OFFSET_MASK, 0x180).await
}

/// `_rtl92ee_phy_path_a_iqk`.
pub async fn path_a_tx(io: &impl Io) -> Result<u8, Error> {
    pad_0(io, Path::A).await?;
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0x8080_0000)?;
    tones(io, [0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c]).await?;
    set_bb(io, RTX_IQK_PI_A, MASKDWORD, 0x8214_0303)?;
    set_bb(io, RRX_IQK_PI_A, MASKDWORD, 0x6816_0000)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_2911)?;
    shot(io, 0xf900_0000).await?;
    let eac = get_bb(io, 0xeac, MASKDWORD)?;
    let e94 = get_bb(io, 0xe94, MASKDWORD)?;
    let e9c = get_bb(io, 0xe9c, MASKDWORD)?;
    Ok(u8::from(
        eac & (1 << 28) == 0 && field(e94) != 0x142 && field(e9c) != 0x42,
    ))
}

/// `_rtl92ee_phy_path_b_iqk`.
pub async fn path_b_tx(io: &impl Io) -> Result<u8, Error> {
    pad_0(io, Path::B).await?;
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0x8080_0000)?;
    set_bb(io, 0xe28, MASKDWORD, 0)?;
    set_bb(io, 0xe28, MASKDWORD, 0x8080_0000)?;
    tones(io, [0x3800_8c1c, 0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c]).await?;
    set_bb(io, RTX_IQK_PI_B, MASKDWORD, 0x8214_03e2)?;
    set_bb(io, RRX_IQK_PI_B, MASKDWORD, 0x6816_0000)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_2911)?;
    shot(io, 0xfa00_0000).await?;
    let eac = get_bb(io, 0xeac, MASKDWORD)?;
    let eb4 = get_bb(io, 0xeb4, MASKDWORD)?;
    let ebc = get_bb(io, 0xebc, MASKDWORD)?;
    Ok(u8::from(
        eac & (1 << 31) == 0 && field(eb4) != 0x142 && field(ebc) != 0x42,
    ))
}

/// The RX IQK mode-table writes shared by both RX stages.
async fn rx_mode(io: &impl Io, path: Path, txpa_g2: u32) -> Result<(), Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    set_rf(io, path, RF_WE_LUT, RFREG_OFFSET_MASK, 0x800a0).await?;
    set_rf(io, path, RF_RCK_OS, RFREG_OFFSET_MASK, 0x30000).await?;
    set_rf(io, path, RF_TXPA_G1, RFREG_OFFSET_MASK, 0x0000f).await?;
    set_rf(io, path, RF_TXPA_G2, RFREG_OFFSET_MASK, txpa_g2).await?;
    set_rf(io, path, 0xdf, RFREG_OFFSET_MASK, 0x980).await?;
    set_rf(io, path, 0x56, RFREG_OFFSET_MASK, 0x51000).await?;
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0x8080_0000)
}

/// `_rtl92ee_phy_path_a_rx_iqk`.
pub async fn path_a_rx(io: &impl Io) -> Result<u8, Error> {
    rx_mode(io, Path::A, 0xf117b).await?;
    set_bb(io, RTX_IQK, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, [0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c]).await?;
    set_bb(io, RTX_IQK_PI_A, MASKDWORD, 0x8216_0c1f)?;
    set_bb(io, RRX_IQK_PI_A, MASKDWORD, 0x6816_0c1f)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_a911)?;
    shot(io, 0xfa00_0000).await?;
    let eac = get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?;
    let e94 = get_bb(io, RTX_POWER_BEFORE_IQK_A, MASKDWORD)?;
    let e9c = get_bb(io, RTX_POWER_AFTER_IQK_A, MASKDWORD)?;
    if !(eac & (1 << 28) == 0 && field(e94) != 0x142 && field(e9c) != 0x42) {
        pad_0(io, Path::A).await?;
        return Ok(0);
    }
    let temp = 0x8000_7c00 | (e94 & 0x03ff_0000) | ((e9c & 0x03ff_0000) >> 16);
    set_bb(io, RTX_IQK, MASKDWORD, temp)?;
    rx_mode(io, Path::A, 0xf7ffa).await?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, [0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c, 0x3800_8c1c]).await?;
    set_bb(io, RTX_IQK_PI_A, MASKDWORD, 0x8216_0c1f)?;
    set_bb(io, RRX_IQK_PI_A, MASKDWORD, 0x2816_0c1f)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_a891)?;
    shot(io, 0xfa00_0000).await?;
    let eac = get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?;
    let ea4 = get_bb(io, RRX_POWER_BEFORE_IQK_A_2, MASKDWORD)?;
    pad_0(io, Path::A).await?;
    let rx = eac & (1 << 27) == 0 && field(ea4) != 0x132 && field(eac) != 0x36;
    Ok(0x01 | if rx { 0x02 } else { 0 })
}

/// `_rtl92ee_phy_path_b_rx_iqk`.
pub async fn path_b_rx(io: &impl Io) -> Result<u8, Error> {
    rx_mode(io, Path::B, 0xf117b).await?;
    set_bb(io, RTX_IQK, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, [0x3800_8c1c, 0x3800_8c1c, 0x1800_8c1c, 0x3800_8c1c]).await?;
    set_bb(io, RTX_IQK_PI_B, MASKDWORD, 0x8216_0c1f)?;
    set_bb(io, RRX_IQK_PI_B, MASKDWORD, 0x6816_0c1f)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_a911)?;
    shot(io, 0xfa00_0000).await?;
    let eac = get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?;
    let eb4 = get_bb(io, RTX_POWER_BEFORE_IQK_B, MASKDWORD)?;
    let ebc = get_bb(io, RTX_POWER_AFTER_IQK_B, MASKDWORD)?;
    if !(eac & (1 << 31) == 0 && field(eb4) != 0x142 && field(ebc) != 0x42) {
        pad_0(io, Path::B).await?;
        return Ok(0);
    }
    let temp = 0x8000_7c00 | (eb4 & 0x03ff_0000) | ((ebc & 0x03ff_0000) >> 16);
    set_bb(io, RTX_IQK, MASKDWORD, temp)?;
    rx_mode(io, Path::B, 0xf7ffa).await?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)?;
    tones(io, [0x3800_8c1c, 0x3800_8c1c, 0x3800_8c1c, 0x1800_8c1c]).await?;
    set_bb(io, RTX_IQK_PI_B, MASKDWORD, 0x8216_0c1f)?;
    set_bb(io, RRX_IQK_PI_B, MASKDWORD, 0x2816_0c1f)?;
    set_bb(io, RIQK_AGC_RSP, MASKDWORD, 0x0046_a891)?;
    shot(io, 0xfa00_0000).await?;
    let eac = get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?;
    let ec4 = get_bb(io, RRX_POWER_BEFORE_IQK_B_2, MASKDWORD)?;
    let ecc = get_bb(io, RRX_POWER_AFTER_IQK_B_2, MASKDWORD)?;
    pad_0(io, Path::B).await?;
    let rx = eac & (1 << 30) == 0 && field(ec4) != 0x132 && field(ecc) != 0x36;
    Ok(0x01 | if rx { 0x02 } else { 0 })
}

async fn adda_on(io: &impl Io) -> Result<(), Error> {
    for r in ADDA_REGS {
        set_bb(io, r, MASKDWORD, 0x0fc0_1616)?;
    }
    Ok(())
}

async fn enter(io: &impl Io) -> Result<(), Error> {
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0x8080_0000)?;
    set_bb(io, RTX_IQK, MASKDWORD, 0x0100_7c00)?;
    set_bb(io, RRX_IQK, MASKDWORD, 0x0100_4800)
}

/// `_rtl92ee_phy_iq_calibrate(result, t, is2t = true)`.
async fn calibrate_once(
    io: &impl Io,
    result: &mut [[u32; 8]; 4],
    t: usize,
    backup: &mut Backup,
) -> Result<(), Error> {
    let c50 = get_bb(io, 0xc50, 0xff)?;
    let c58 = get_bb(io, 0xc58, 0xff)?;
    if t == 0 {
        for (b, r) in backup.adda.iter_mut().zip(ADDA_REGS) {
            *b = get_bb(io, r, MASKDWORD)?;
        }
        for (i, r) in MAC_REGS.iter().copied().enumerate() {
            backup.mac[i] = if i < MAC_REGS.len() - 1 {
                u32::from(io.read8(r)?)
            } else {
                io.read32(r)?
            };
        }
        for (b, r) in backup.bb.iter_mut().zip(BB_REGS) {
            *b = get_bb(io, r, MASKDWORD)?;
        }
    }
    adda_on(io).await?;
    set_bb(io, RFPGA0_RFMOD, 1 << 24, 0)?;
    set_bb(io, ROFDM0_TRXPATHENABLE, MASKDWORD, 0x03a0_5600)?;
    set_bb(io, ROFDM0_TRMUXPAR, MASKDWORD, 0x0008_00e4)?;
    set_bb(io, RFPGA0_XCD_RFINTERFACESW, MASKDWORD, 0x2220_8200)?;
    set_bb(io, RFPGA0_XAB_RFINTERFACESW, 1 << 10, 1)?;
    set_bb(io, RFPGA0_XAB_RFINTERFACESW, 1 << 26, 1)?;
    set_bb(io, RFPGA0_XA_RFINTERFACEOE, 1 << 10, 1)?;
    set_bb(io, RFPGA0_XB_RFINTERFACEOE, 1 << 10, 1)?;
    // _rtl92ee_phy_mac_setting_calibration.
    set_bb(io, 0x520, 0x00ff_0000, 0xff)?;
    enter(io).await?;
    for _ in 0..RETRY {
        if path_a_tx(io).await? == 0x01 {
            result[t][0] = field(get_bb(io, RTX_POWER_BEFORE_IQK_A, MASKDWORD)?);
            result[t][1] = field(get_bb(io, RTX_POWER_AFTER_IQK_A, MASKDWORD)?);
            break;
        }
    }
    for _ in 0..RETRY {
        if path_a_rx(io).await? == 0x03 {
            result[t][2] = field(get_bb(io, RRX_POWER_BEFORE_IQK_A_2, MASKDWORD)?);
            result[t][3] = field(get_bb(io, RRX_POWER_AFTER_IQK_A_2, MASKDWORD)?);
            break;
        }
    }
    // _rtl92ee_phy_path_a_standby.
    set_bb(io, 0xe28, MASKDWORD, 0)?;
    set_rf(io, Path::A, 0, RFREG_OFFSET_MASK, 0x10000).await?;
    set_bb(io, 0xe28, MASKDWORD, 0x8080_0000)?;
    adda_on(io).await?;
    enter(io).await?;
    for _ in 0..RETRY {
        if path_b_tx(io).await? == 0x01 {
            result[t][4] = field(get_bb(io, RTX_POWER_BEFORE_IQK_B, MASKDWORD)?);
            result[t][5] = field(get_bb(io, RTX_POWER_AFTER_IQK_B, MASKDWORD)?);
            break;
        }
    }
    for _ in 0..RETRY {
        if path_b_rx(io).await? == 0x03 {
            result[t][6] = field(get_bb(io, RRX_POWER_BEFORE_IQK_B_2, MASKDWORD)?);
            result[t][7] = field(get_bb(io, RRX_POWER_AFTER_IQK_B_2, MASKDWORD)?);
            break;
        }
    }
    set_bb(io, RFPGA0_IQK, MASKDWORD, 0)?;
    if t != 0 {
        for (b, r) in backup.adda.iter().zip(ADDA_REGS) {
            set_bb(io, r, MASKDWORD, *b)?;
        }
        for (i, r) in MAC_REGS.iter().copied().enumerate() {
            if i < MAC_REGS.len() - 1 {
                io.write8(r, backup.mac[i] as u8)?;
            } else {
                io.write32(r, backup.mac[i])?;
            }
        }
        for (b, r) in backup.bb.iter().zip(BB_REGS) {
            set_bb(io, r, MASKDWORD, *b)?;
        }
        set_bb(io, 0xc50, 0xff, 0x50)?;
        set_bb(io, 0xc50, 0xff, c50)?;
        // is2t: Linux writes 0x50 to 0xc50 (not 0xc58) here.
        set_bb(io, 0xc50, 0xff, 0x50)?;
        set_bb(io, 0xc58, 0xff, c58)?;
        set_bb(io, RTX_IQK_TONE_A, MASKDWORD, 0x0100_8c00)?;
        set_bb(io, RRX_IQK_TONE_A, MASKDWORD, 0x0100_8c00)?;
    }
    Ok(())
}

fn signed10(v: u32) -> i32 {
    if v & 0x200 != 0 {
        (v | 0xffff_fc00) as i32
    } else {
        v as i32
    }
}

/// `_rtl92ee_phy_simularity_compare`.
pub fn simularity_compare(result: &mut [[u32; 8]; 4], c1: usize, c2: usize) -> bool {
    let mut candidate = [0xffu8; 2];
    let mut bitmap = 0u32;
    for i in 0..8 {
        let (t1, t2) = if i % 2 == 1 {
            (signed10(result[c1][i]), signed10(result[c2][i]))
        } else {
            (result[c1][i] as i32, result[c2][i] as i32)
        };
        if t1.abs_diff(t2) > MAX_TOLERANCE {
            if (i == 2 || i == 6) && bitmap == 0 {
                if result[c1][i].wrapping_add(result[c1][i + 1]) == 0 {
                    candidate[i / 4] = c2 as u8;
                } else if result[c2][i].wrapping_add(result[c2][i + 1]) == 0 {
                    candidate[i / 4] = c1 as u8;
                } else {
                    bitmap |= 1 << i;
                }
            } else {
                bitmap |= 1 << i;
            }
        }
    }
    if bitmap == 0 {
        let mut same = true;
        for (i, c) in candidate.iter().copied().enumerate() {
            if c != 0xff {
                let range = i * 4..(i + 1) * 4 - 2;
                let src = result[usize::from(c)];
                result[3][range.clone()].copy_from_slice(&src[range]);
                same = false;
            }
        }
        return same;
    }
    for (mask, range) in [(0x03u32, 0..2), (0x0c, 2..4), (0x30, 4..6), (0xc0, 6..8)] {
        if bitmap & mask == 0 {
            let src = result[c1];
            result[3][range.clone()].copy_from_slice(&src[range]);
        }
    }
    false
}

/// `_rtl92ee_phy_path_a_fill_iqk_matrix` / `_b_` (u32 wrapping as Linux).
async fn fill(
    io: &impl Io,
    path: Path,
    ok: bool,
    result: &[[u32; 8]; 4],
    candidate: u8,
    tx_only: bool,
) -> Result<(), Error> {
    if candidate == 0xff || !ok {
        return Ok(());
    }
    let row = &result[usize::from(candidate)];
    let base = if path == Path::A { 0 } else { 4 };
    let (bit_a, bit_c, txafe, tx_iq, rx_iq, rx_ext) = match path {
        Path::A => (
            31,
            29,
            ROFDM0_XCTXAFE,
            ROFDM0_XATXIQIMBALANCE,
            ROFDM0_XARXIQIMBALANCE,
            ROFDM0_RXIQEXTANTA,
        ),
        Path::B => (
            27,
            25,
            ROFDM0_XDTXAFE,
            ROFDM0_XBTXIQIMBALANCE,
            ROFDM0_XBRXIQIMBALANCE,
            ROFDM0_AGCRSSITABLE,
        ),
    };
    // Both paths read (and write tx_a into) ROFDM0_XATXIQIMBALANCE.
    let old = (get_bb(io, ROFDM0_XATXIQIMBALANCE, MASKDWORD)? >> 22) & 0x3ff;
    let mut x = row[base];
    if x & 0x200 != 0 {
        x |= 0xffff_fc00;
    }
    let tx_a = x.wrapping_mul(old) >> 8;
    set_bb(io, ROFDM0_XATXIQIMBALANCE, 0x3ff, tx_a)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        1 << bit_a,
        (x.wrapping_mul(old) >> 7) & 1,
    )?;
    let mut y = row[base + 1];
    if y & 0x200 != 0 {
        y |= 0xffff_fc00;
    }
    let tx_c = y.wrapping_mul(old) >> 8;
    set_bb(io, txafe, 0xf000_0000, (tx_c & 0x3c0) >> 6)?;
    set_bb(io, tx_iq, 0x003f_0000, tx_c & 0x3f)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        1 << bit_c,
        (y.wrapping_mul(old) >> 7) & 1,
    )?;
    if tx_only {
        return Ok(());
    }
    set_bb(io, rx_iq, 0x3ff, row[base + 2])?;
    set_bb(io, rx_iq, 0xfc00, row[base + 3] & 0x3f)?;
    set_bb(io, rx_ext, 0xf000_0000, (row[base + 3] >> 6) & 0xf)
}

/// `rtl92ee_phy_iq_calibrate(hw, false)`.
pub async fn calibrate(io: &impl Io) -> Result<Report, Error> {
    let mut result = [[0u32; 8]; 4];
    for i in [0, 2, 4, 6] {
        result[3][i] = 0x100;
    }
    let mut backup = Backup::default();
    let mut candidate = 0xffu8;
    for t in 0..3 {
        calibrate_once(io, &mut result, t, &mut backup).await?;
        if t == 1 && simularity_compare(&mut result, 0, 1) {
            candidate = 0;
            break;
        }
        if t == 2 {
            if simularity_compare(&mut result, 0, 2) {
                candidate = 0;
                break;
            }
            candidate = if simularity_compare(&mut result, 1, 2) {
                1
            } else {
                3
            };
        }
    }
    let pick = if candidate != 0xff {
        usize::from(candidate)
    } else {
        3
    };
    let ok = candidate != 0xff;
    let (e94, ea4, ec4) = (result[pick][0], result[pick][2], result[pick][6]);
    if e94 != 0 {
        fill(io, Path::A, ok, &result, candidate, ea4 == 0).await?;
    }
    fill(io, Path::B, ok, &result, candidate, ec4 == 0).await?;
    let mut saved = [0u32; 9];
    for (s, r) in saved.iter_mut().zip(RESULT_REGS) {
        *s = get_bb(io, r, MASKDWORD)?;
    }
    Ok(Report {
        result,
        final_candidate: candidate,
        saved,
    })
}

/// `rtl92ee_phy_iq_calibrate(hw, true)`: reload the saved result registers.
pub fn recover(io: &impl Io, saved: &[u32; 9]) -> Result<(), Error> {
    for (s, r) in saved.iter().zip(RESULT_REGS) {
        set_bb(io, r, MASKDWORD, *s)?;
    }
    Ok(())
}

/// `_rtl92ee_phy_lc_calibrate(is2t = false)`.
pub async fn lc_calibrate(io: &impl Io) -> Result<(), Error> {
    let tmp = io.read8(0xd03)?;
    let active = tmp & 0x70 != 0;
    let mut rf_a_mode = 0;
    if active {
        io.write8(0xd03, tmp & 0x8f)?;
        rf_a_mode = get_rf(io, Path::A, 0x00, MASK12BITS).await?;
        set_rf(
            io,
            Path::A,
            0x00,
            MASK12BITS,
            (rf_a_mode & 0x8ffff) | 0x10000,
        )
        .await?;
    } else {
        io.write8(REG_TXPAUSE, 0xff)?;
    }
    let lc_cal = get_rf(io, Path::A, 0x18, MASK12BITS).await?;
    set_rf(io, Path::A, 0x18, MASK12BITS, lc_cal | 0x08000).await?;
    io.delay_us(100_000).await;
    if active {
        io.write8(0xd03, tmp)?;
        set_rf(io, Path::A, 0x00, MASK12BITS, rf_a_mode).await?;
    } else {
        io.write8(REG_TXPAUSE, 0x00)?;
    }
    Ok(())
}
