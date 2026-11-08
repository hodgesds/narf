// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE bands, channel switching and 20/40 MHz bandwidth.
//!
//! `core.c::rtl_op_config` order: the wide channel is stored (HT40+ =
//! primary + 2 with `PRIME_CHNL_OFFSET_LOWER`, HT40- = primary - 2
//! with `PRIME_CHNL_OFFSET_UPPER`), then `rtl92d_phy_sw_chnl`
//! (TX power at the new channel, the `RF_CHNLBW` step), then
//! `rtl92d_phy_set_bw_mode`.
//!
//! Exact Linux `rtl8192de/phy.c` + `rtl8192d/phy_common.c`:
//!
//! - `channel_all[59]` and `rtl92d_get_chnlgroup_fromarray` (12 groups),
//!   `rtl92d_phy_get_chnlgroup_bypg` (regulatory-1 groups),
//!   `_rtl92c_phy_get_rightchnlplace`,
//!   `rtl92d_get_rightchnlplace_for_iqk`.
//! - `rtl92d_phy_set_bw_mode`: `REG_BWOPMODE` / `REG_RRSR+2` prime-sc,
//!   `RFPGA0/1_RFMOD` `BRFMOD`, `RFPGA0_ANALOGPARAMETER2` BIT(10) |
//!   BIT(11) (3 at 20 MHz, 0 at 40 MHz), the 2.4 GHz-only 40 MHz CCK
//!   sideband, `ROFDM1_LSTF`, `0x818`, then
//!   `rtl92d_phy_rf6052_set_bandwidth` (all paths, unlike the 92CE
//!   port's path-A-only loop).
//! - `rtl92d_phy_switch_wirelessband`: stop TRX, the MAC1 AGC reload,
//!   `rtl92d_update_bbrf_configuration`, CCK/OFDM re-enable, the
//!   `REG_MAC0` / `REG_MAC1` band bit, `mdelay(1)`.
//! - `rtl92d_update_bbrf_configuration`: the `RFPGA0_XAB_RFPARAMETER`
//!   band-select bits, RSSI-table select, CFO tracking, `0xB30`, the
//!   TX IQ imbalance words (internal-PA 5G selects `0x2d4000b5`), the
//!   RF-interface-switch words from `eeprom_c9` / `eeprom_cc`, the
//!   IQK-related tail, the per-path `RF_CHNLBW` / `0x0B` RF writes,
//!   the TRX-path enable by RF type, and the `RF_CHNLBW` / `0x3C`
//!   read-backs.
//! - `rtl92d_phy_sw_chnl`: the single-MAC band-switch trigger, the
//!   band/channel consistency guards, the TX-power command, and the
//!   `RF_CHNLBW` command (`rfreg_chnlval` low byte = channel; 5 GHz
//!   sets BIT(16) | BIT(8) and BIT(18) above channel 99).
//!
//! Not this step (remainders, listed in the PR body): the IMR reload
//! (`_rtl92d_phy_reload_imr_setting`, RF IMR tables), the RF setting
//! switch (`_rtl92d_phy_switch_rf_setting`, curve-index tables),
//! the IQK reload (`rtl92d_phy_reload_iqk_setting`), and the LCK
//! in-progress wait — all calibration-table work owned by later lanes.

use super::phy::{self, PgStore};
use super::txpower::{self, Efuse};
use super::{Band, BandSet, MacPhyMode, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `channel_all[59]` (`rtl8192d/phy_common.c`).
pub const CHANNEL_ALL: [u8; 59] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58,
    60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130,
    132, 134, 136, 138, 140, 149, 151, 153, 155, 157, 159, 161, 163, 165,
];

/// `rtl92d_get_chnlgroup_fromarray`: the group of a channel place
/// (0-based index into [`CHANNEL_ALL`]).
pub const fn chnlgroup_fromarray(index: u8) -> usize {
    let ch = CHANNEL_ALL[index as usize];
    if ch <= 3 {
        0
    } else if ch <= 9 {
        1
    } else if ch <= 14 {
        2
    } else if ch <= 44 {
        3
    } else if ch <= 54 {
        4
    } else if ch <= 64 {
        5
    } else if ch <= 112 {
        6
    } else if ch <= 126 {
        7
    } else if ch <= 140 {
        8
    } else if ch <= 153 {
        9
    } else if ch <= 159 {
        10
    } else {
        11
    }
}

/// `rtl92d_phy_get_chnlgroup_bypg`: the regulatory-1 group of a channel
/// place (0-based index into [`CHANNEL_ALL`]).
pub const fn chnlgroup_bypg(index: u8) -> usize {
    let ch = CHANNEL_ALL[index as usize];
    if ch <= 3 {
        0
    } else if ch <= 9 {
        1
    } else if ch <= 14 {
        2
    } else if ch <= 64 {
        6
    } else if ch <= 140 {
        7
    } else {
        8
    }
}

/// `_rtl92c_phy_get_rightchnlplace`: the 1-based place of a channel
/// number (the channel itself at or below 14, else its index in
/// [`CHANNEL_ALL`] plus one; an unknown 5 GHz channel walks off the
/// end, as in Linux — callers validate membership first).
pub fn rightchnlplace(channel: u8) -> u8 {
    if channel <= 14 {
        return channel;
    }
    for (i, ch) in CHANNEL_ALL.iter().copied().enumerate() {
        if i >= 14 && ch == channel {
            return (i + 1) as u8;
        }
    }
    CHANNEL_ALL.len() as u8
}

/// `rtl92d_get_rightchnlplace_for_iqk`: 0 on 2.4 GHz, the 5 GHz place
/// minus 13 otherwise (0 when the channel is not in the table).
pub fn iqk_place(channel: u8) -> u8 {
    if channel <= 14 {
        return 0;
    }
    for (i, ch) in CHANNEL_ALL.iter().copied().enumerate() {
        if i >= 14 && ch == channel {
            return i as u8 - 13;
        }
    }
    0
}

/// `nl80211_channel_type` on either band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelType {
    Ht20,
    Ht40Plus,
    Ht40Minus,
}

/// The `rtl_op_config` channel state for one primary channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operating {
    pub primary: u8,
    pub wide: u8,
    pub bw40: bool,
    pub prime_sc: u8,
}

/// `HAL_PRIME_CHNL_OFFSET_*` (`mac->cur_40_prime_sc`).
pub const PRIME_CHNL_OFFSET_DONT_CARE: u8 = 0;
pub const PRIME_CHNL_OFFSET_LOWER: u8 = 1;
pub const PRIME_CHNL_OFFSET_UPPER: u8 = 2;

impl Operating {
    /// Any channel in [`CHANNEL_ALL`]; a 40 MHz pair must keep the wide
    /// channel a legal channel too. Linux clamps `wide_chan <= 0` to 1,
    /// which never forms a valid pair; such requests are refused.
    pub fn new(primary: u8, kind: ChannelType) -> Result<Self, Error> {
        if !CHANNEL_ALL.contains(&primary) {
            return Err(Error::State);
        }
        let (wide, bw40, prime_sc) = match kind {
            ChannelType::Ht20 => (primary, false, PRIME_CHNL_OFFSET_DONT_CARE),
            ChannelType::Ht40Plus => (
                primary.checked_add(2).ok_or(Error::State)?,
                true,
                PRIME_CHNL_OFFSET_LOWER,
            ),
            ChannelType::Ht40Minus => (
                primary.checked_sub(2).ok_or(Error::State)?,
                true,
                PRIME_CHNL_OFFSET_UPPER,
            ),
        };
        if bw40 && !CHANNEL_ALL.contains(&wide) {
            return Err(Error::State);
        }
        Ok(Self {
            primary,
            wide,
            bw40,
            prime_sc,
        })
    }
}

/// The `CMDID_RF_WRITEREG` `rfreg_chnlval` for `channel` on one path:
/// low byte = channel; 5 GHz sets BIT(16) | BIT(8) and BIT(18) above
/// channel 99; 2.4 GHz clears all three.
pub fn rfreg_chnlval(channel: u8, band_5g: bool, current: u32) -> u32 {
    let mut v = (current & 0xffff_ff00) | u32::from(channel);
    if band_5g {
        if channel > 99 {
            v |= 1 << 18;
        } else {
            v &= !(1 << 18);
        }
        v |= (1 << 16) | (1 << 8);
    } else {
        v &= !((1 << 8) | (1 << 16) | (1 << 18));
    }
    v
}

/// `rtl92d_phy_rf6052_set_bandwidth` (all paths).
pub async fn rf6052_set_bandwidth(
    io: &impl Io,
    rf_type: RfType,
    bw40: bool,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    for &path in rf_type.rf_paths() {
        let p = path as usize;
        chnlval[p] &= 0xffff_f3ff;
        if !bw40 {
            chnlval[p] |= 0x0400;
        }
        phy::set_rf(
            io,
            path,
            phy::RF_CHNLBW,
            (1 << 10) | (1 << 11),
            if bw40 { 0 } else { 1 },
        )
        .await?;
    }
    Ok(())
}

/// `rtl92d_phy_set_bw_mode` (`prime_sc` = `cur_40_prime_sc`). The
/// caller serializes against channel switches, as Linux's
/// `set_bwmode_inprogress` does.
pub async fn set_bw_mode(
    io: &impl Io,
    band: Band,
    bw40: bool,
    prime_sc: u8,
    rf_type: RfType,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    use super::mac::{BWOPMODE_20MHZ, REG_BWOPMODE, REG_RRSR};
    let opmode = io.read8(REG_BWOPMODE)?;
    let prsr = io.read8(REG_RRSR + 2)?;
    if bw40 {
        io.write8(REG_BWOPMODE, opmode & !BWOPMODE_20MHZ)?;
        io.write8(REG_RRSR + 2, (prsr & 0x90) | (prime_sc << 5))?;
        phy::set_bb(io, phy::RFPGA0_RFMOD, phy::BRFMOD, 0x1)?;
        phy::set_bb(io, phy::RFPGA1_RFMOD, phy::BRFMOD, 0x1)?;
        if band == Band::On2Ghz {
            phy::set_bb(
                io,
                phy::RCCK0_SYSTEM,
                phy::BCCKSIDEBAND,
                u32::from(prime_sc >> 1),
            )?;
        }
        phy::set_bb(io, phy::ROFDM1_LSTF, 0xc00, u32::from(prime_sc))?;
        phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER2, (1 << 10) | (1 << 11), 0)?;
        let sel = if prime_sc == PRIME_CHNL_OFFSET_LOWER {
            2
        } else {
            1
        };
        phy::set_bb(io, 0x818, (1 << 26) | (1 << 27), sel)?;
    } else {
        io.write8(REG_BWOPMODE, opmode | BWOPMODE_20MHZ)?;
        phy::set_bb(io, phy::RFPGA0_RFMOD, phy::BRFMOD, 0x0)?;
        phy::set_bb(io, phy::RFPGA1_RFMOD, phy::BRFMOD, 0x0)?;
        phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER2, (1 << 10) | (1 << 11), 3)?;
    }
    rf6052_set_bandwidth(io, rf_type, bw40, chnlval).await
}

/// Inputs to `rtl92d_update_bbrf_configuration` beyond the band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bbrf {
    pub mode: MacPhyMode,
    pub rf_type: RfType,
    pub interface_index: u8,
    pub eeprom_c9: u8,
    pub eeprom_cc: u8,
    pub internal_pa_5g: [bool; 2],
}

/// `rtl92d_update_bbrf_configuration`. Updates `chnlval` in place and
/// returns the per-path `reg_rf3c` read-backs.
pub async fn update_bbrf_configuration(
    io: &impl Io,
    band: Band,
    cfg: &Bbrf,
    chnlval: &mut [u32; 2],
) -> Result<[u32; 2], Error> {
    use phy::*;
    let dual = cfg.mode == MacPhyMode::DualMacDualPhy;
    if band == Band::On2Ghz {
        set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 0, 0x0)?;
        set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 15, 0x0)?;
        if !dual {
            set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 16, 0x0)?;
            set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 31, 0x0)?;
        }
        set_bb(io, ROFDM0_AGCRSSITABLE, (1 << 6) | (1 << 7), 0x0)?;
        set_bb(io, ROFDM1_CFOTRACKING, (1 << 14) | (1 << 13), 0x0)?;
        set_bb(io, 0xB30, 0x00f0_0000, 0xa)?;
        set_bb(io, ROFDM0_XATXIQIMBALANCE, MASKDWORD, 0x4000_0100)?;
        set_bb(io, ROFDM0_XBTXIQIMBALANCE, MASKDWORD, 0x4000_0100)?;
        if dual {
            set_bb(
                io,
                RFPGA0_XAB_RFINTERFACESW,
                (1 << 10) | (1 << 6) | (1 << 5),
                ((u32::from(cfg.eeprom_c9) & (1 << 3)) >> 3)
                    | (u32::from(cfg.eeprom_c9) & (1 << 1))
                    | ((u32::from(cfg.eeprom_cc) & (1 << 1)) << 4),
            )?;
            set_bb(
                io,
                RFPGA0_XA_RFINTERFACEOE,
                (1 << 10) | (1 << 6) | (1 << 5),
                ((u32::from(cfg.eeprom_c9) & (1 << 2)) >> 2)
                    | ((u32::from(cfg.eeprom_c9) & (1 << 0)) << 1)
                    | ((u32::from(cfg.eeprom_cc) & (1 << 0)) << 5),
            )?;
            set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 15, 0)?;
        } else {
            set_bb(
                io,
                RFPGA0_XAB_RFINTERFACESW,
                (1 << 26) | (1 << 22) | (1 << 21) | (1 << 10) | (1 << 6) | (1 << 5),
                ((u32::from(cfg.eeprom_c9) & (1 << 3)) >> 3)
                    | (u32::from(cfg.eeprom_c9) & (1 << 1))
                    | ((u32::from(cfg.eeprom_cc) & (1 << 1)) << 4)
                    | ((u32::from(cfg.eeprom_c9) & (1 << 7)) << 9)
                    | ((u32::from(cfg.eeprom_c9) & (1 << 5)) << 12)
                    | ((u32::from(cfg.eeprom_cc) & (1 << 3)) << 18),
            )?;
            set_bb(
                io,
                RFPGA0_XA_RFINTERFACEOE,
                (1 << 10) | (1 << 6) | (1 << 5),
                ((u32::from(cfg.eeprom_c9) & (1 << 2)) >> 2)
                    | ((u32::from(cfg.eeprom_c9) & (1 << 0)) << 1)
                    | ((u32::from(cfg.eeprom_cc) & (1 << 0)) << 5),
            )?;
            set_bb(
                io,
                RFPGA0_XB_RFINTERFACEOE,
                (1 << 10) | (1 << 6) | (1 << 5),
                ((u32::from(cfg.eeprom_c9) & (1 << 6)) >> 6)
                    | ((u32::from(cfg.eeprom_c9) & (1 << 4)) >> 3)
                    | ((u32::from(cfg.eeprom_cc) & (1 << 2)) << 3),
            )?;
            set_bb(io, RFPGA0_XAB_RFPARAMETER, (1 << 31) | (1 << 15), 0)?;
        }
    } else {
        set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 0, 0x1)?;
        set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 15, 0x1)?;
        if !dual {
            set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 16, 0x1)?;
            set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 31, 0x1)?;
        }
        set_bb(io, ROFDM0_AGCRSSITABLE, (1 << 6) | (1 << 7), 0x1)?;
        set_bb(io, ROFDM1_CFOTRACKING, (1 << 14) | (1 << 13), 0x1)?;
        set_bb(io, 0xB30, 0x00f0_0000, 0x0)?;
        let txiq = |pa: bool| if pa { 0x2d40_00b5 } else { 0x2000_0080 };
        set_bb(
            io,
            ROFDM0_XATXIQIMBALANCE,
            MASKDWORD,
            txiq(cfg.internal_pa_5g[0]),
        )?;
        set_bb(
            io,
            ROFDM0_XBTXIQIMBALANCE,
            MASKDWORD,
            txiq(cfg.internal_pa_5g[1]),
        )?;
        if dual {
            set_bb(
                io,
                RFPGA0_XAB_RFINTERFACESW,
                (1 << 10) | (1 << 6) | (1 << 5),
                u32::from(cfg.eeprom_cc) & (1 << 5),
            )?;
            set_bb(
                io,
                RFPGA0_XA_RFINTERFACEOE,
                1 << 10,
                (u32::from(cfg.eeprom_cc) & (1 << 4)) >> 4,
            )?;
            set_bb(
                io,
                RFPGA0_XAB_RFPARAMETER,
                1 << 15,
                (u32::from(cfg.eeprom_cc) & (1 << 4)) >> 4,
            )?;
        } else {
            set_bb(
                io,
                RFPGA0_XAB_RFINTERFACESW,
                (1 << 26) | (1 << 22) | (1 << 21) | (1 << 10) | (1 << 6) | (1 << 5),
                (u32::from(cfg.eeprom_cc) & (1 << 5))
                    | ((u32::from(cfg.eeprom_cc) & (1 << 7)) << 14),
            )?;
            set_bb(
                io,
                RFPGA0_XA_RFINTERFACEOE,
                1 << 10,
                (u32::from(cfg.eeprom_cc) & (1 << 4)) >> 4,
            )?;
            set_bb(
                io,
                RFPGA0_XB_RFINTERFACEOE,
                1 << 10,
                (u32::from(cfg.eeprom_cc) & (1 << 6)) >> 6,
            )?;
            set_bb(
                io,
                RFPGA0_XAB_RFPARAMETER,
                (1 << 31) | (1 << 15),
                ((u32::from(cfg.eeprom_cc) & (1 << 4)) >> 4)
                    | ((u32::from(cfg.eeprom_cc) & (1 << 6)) << 10),
            )?;
        }
    }
    set_bb(io, ROFDM0_XARXIQIMBALANCE, MASKDWORD, 0x4000_0100)?;
    set_bb(io, ROFDM0_XBRXIQIMBALANCE, MASKDWORD, 0x4000_0100)?;
    set_bb(io, ROFDM0_XCTXAFE, 0xf000_0000, 0x00)?;
    set_bb(
        io,
        ROFDM0_ECCATHRESHOLD,
        (1 << 30) | (1 << 28) | (1 << 26) | (1 << 24),
        0x00,
    )?;
    set_bb(io, ROFDM0_XDTXAFE, 0xf000_0000, 0x00)?;
    set_bb(io, 0xca0, 0xf000_0000, 0x00)?;
    set_bb(io, ROFDM0_AGCRSSITABLE, 0x0000_f000, 0x00)?;
    for &path in cfg.rf_type.rf_paths() {
        if band == Band::On2Ghz {
            set_rf(io, path, RF_CHNLBW, (1 << 8) | (1 << 16) | (1 << 18), 0).await?;
            set_rf(io, path, 0x0b, 0x1c000, 0x07).await?;
        } else {
            set_rf(
                io,
                path,
                RF_CHNLBW,
                (1 << 8) | (1 << 16) | (1 << 18),
                ((1 << 16) | (1 << 8)) >> 8,
            )
            .await?;
        }
    }
    if cfg.rf_type == RfType::OneT1R {
        set_bb(io, ROFDM0_TRXPATHENABLE, MASKBYTE0, 0x11)?;
        set_bb(io, ROFDM1_TRXPATHENABLE, BDWORD, 0x1)?;
        if cfg.interface_index == 0 {
            set_bb(io, RFPGA0_ADDALLOCKEN, (1 << 12) | (1 << 13), 0x3)?;
        } else {
            phy::enable_anotherphy(io, false).await?;
            let v = phy::read_dword_dbi(io, RFPGA0_ADDALLOCKEN, 1 << 3).await?;
            phy::write_dword_dbi(io, RFPGA0_ADDALLOCKEN, v | (1 << 12) | (1 << 13), 1 << 3)?;
            phy::powerdown_anotherphy(io, false).await?;
        }
    } else {
        set_bb(io, ROFDM0_TRXPATHENABLE, MASKBYTE0, 0x33)?;
        set_bb(io, ROFDM1_TRXPATHENABLE, BDWORD, 0x3)?;
        set_bb(io, RFPGA0_ADDALLOCKEN, (1 << 12) | (1 << 13), 0)?;
    }
    let mut rf3c = [0u32; 2];
    for &path in cfg.rf_type.rf_paths() {
        let p = path as usize;
        chnlval[p] = get_rf(io, path, RF_CHNLBW, RFREG_OFFSET_MASK).await?;
        rf3c[p] = get_rf(io, path, 0x3c, RFREG_OFFSET_MASK).await?;
    }
    Ok(rf3c)
}

/// The `rtl92d_phy_switch_wirelessband` report: the bandset Linux
/// records (single-PHY forces `BOTH`), the TX-power reload flag, and
/// the `reg_rf3c` read-backs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandSwitch {
    pub bandset: BandSet,
    pub reload_txpower: bool,
    pub rf3c: [u32; 2],
}

/// `rtl92d_phy_switch_wirelessband`. `single_phy` is
/// `IS_92D_SINGLEPHY(version)`. The caller owns `bandset` /
/// `current_bandtype` and records [`BandSwitch::bandset`], and must
/// re-run TX power after the switch (`reload_txpower`).
pub async fn switch_wirelessband(
    io: &impl Io,
    band: Band,
    cfg: &Bbrf,
    single_phy: bool,
    chnlval: &mut [u32; 2],
) -> Result<BandSwitch, Error> {
    use super::power::{REG_MAC0, REG_MAC1};
    use phy::*;
    let bandset = if single_phy {
        BandSet::OnBoth
    } else {
        match band {
            Band::On2Ghz => BandSet::On2Ghz,
            Band::On5Ghz => BandSet::On5Ghz,
        }
    };
    set_bb(io, RFPGA0_RFMOD, BCCKEN, 0)?;
    set_bb(io, RFPGA0_RFMOD, BOFDMEN, 0)?;
    set_bb(io, ROFDM0_TRXPATHENABLE, MASKBYTE0, 0x00)?;
    set_bb(io, ROFDM1_TRXPATHENABLE, BDWORD, 0x0)?;
    if cfg.interface_index == 1 {
        agc_table_walk(io, super::agc_table(cfg.interface_index, band)).await?;
    }
    let rf3c = update_bbrf_configuration(io, band, cfg, chnlval).await?;
    if band == Band::On2Ghz {
        set_bb(io, RFPGA0_RFMOD, BCCKEN, 0x1)?;
    }
    set_bb(io, RFPGA0_RFMOD, BOFDMEN, 0x1)?;
    let mac_reg = if cfg.interface_index == 0 {
        REG_MAC0
    } else {
        REG_MAC1
    };
    let value = io.read8(mac_reg)?;
    io.write8(
        mac_reg,
        match band {
            Band::On2Ghz => value | (1 << 1),
            Band::On5Ghz => value & !(1 << 1),
        },
    )?;
    io.delay_us(1000).await;
    Ok(BandSwitch {
        bandset,
        reload_txpower: true,
        rf3c,
    })
}

/// The `rtl92d_phy_sw_chnl` outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwitchOutcome {
    /// False when a band/channel guard refused the switch.
    pub switched: bool,
    /// The bandset after the switch (changed only on a band switch).
    pub bandset: BandSet,
    /// `reg_rf3c` read back by a band switch, if one ran.
    pub rf3c: Option<[u32; 2]>,
}

/// `rtl92d_phy_sw_chnl` at `channel` (the wide channel, already
/// stored by the caller). The caller serializes against concurrent
/// bandwidth changes and LCK calibration, as Linux's
/// `sw_chnl_inprogress` / `set_bwmode_inprogress` / `lck_inprogress`
/// guards do; the band/channel consistency guards are enforced here.
/// The IMR reload, RF setting switch and IQK reload are remainders.
#[allow(clippy::too_many_arguments)]
pub async fn switch_channel(
    io: &impl Io,
    efuse: &Efuse,
    pg: &PgStore,
    rf_type: RfType,
    mode: MacPhyMode,
    interface_index: u8,
    band: &mut Band,
    bandset: &mut BandSet,
    single_phy: bool,
    channel: u8,
    bw40: bool,
    chnlval: &mut [u32; 2],
) -> Result<SwitchOutcome, Error> {
    let mut rf3c = None;
    if mode == MacPhyMode::SingleMacSinglePhy && *bandset == BandSet::OnBoth {
        let rfparam = phy::get_bb(io, phy::RFPGA0_XAB_RFPARAMETER, phy::MASKDWORD)?;
        if channel > 14 && rfparam & (1 << 0) == 0 {
            let cfg = Bbrf {
                mode,
                rf_type,
                interface_index,
                eeprom_c9: efuse.eeprom_c9,
                eeprom_cc: efuse.eeprom_cc,
                internal_pa_5g: efuse.internal_pa_5g,
            };
            let sw = switch_wirelessband(io, Band::On5Ghz, &cfg, single_phy, chnlval).await?;
            *band = Band::On5Ghz;
            *bandset = sw.bandset;
            rf3c = Some(sw.rf3c);
        } else if channel <= 14 && rfparam & (1 << 0) != 0 {
            let cfg = Bbrf {
                mode,
                rf_type,
                interface_index,
                eeprom_c9: efuse.eeprom_c9,
                eeprom_cc: efuse.eeprom_cc,
                internal_pa_5g: efuse.internal_pa_5g,
            };
            let sw = switch_wirelessband(io, Band::On2Ghz, &cfg, single_phy, chnlval).await?;
            *band = Band::On2Ghz;
            *bandset = sw.bandset;
            rf3c = Some(sw.rf3c);
        }
    }
    match *band {
        Band::On5Ghz if channel <= 14 => {
            return Ok(SwitchOutcome {
                switched: false,
                bandset: *bandset,
                rf3c: None,
            });
        }
        Band::On2Ghz if channel > 14 => {
            return Ok(SwitchOutcome {
                switched: false,
                bandset: *bandset,
                rf3c: None,
            });
        }
        _ => {}
    }
    let channel = if channel == 0 { 1 } else { channel };
    txpower::set_level(io, efuse, rf_type, pg, channel, *band, bw40, false)?;
    for &path in rf_type.rf_paths() {
        let p = path as usize;
        chnlval[p] = rfreg_chnlval(channel, *band == Band::On5Ghz, chnlval[p]);
        phy::set_rf(io, path, phy::RF_CHNLBW, phy::RFREG_OFFSET_MASK, chnlval[p]).await?;
    }
    Ok(SwitchOutcome {
        switched: true,
        bandset: *bandset,
        rf3c,
    })
}

/// `switch_channel` at the wide channel then `set_bw_mode` (the
/// `rtl_op_config` station path: `act_scanning` false).
#[allow(clippy::too_many_arguments)]
pub async fn configure(
    io: &impl Io,
    efuse: &Efuse,
    pg: &PgStore,
    rf_type: RfType,
    mode: MacPhyMode,
    interface_index: u8,
    band: &mut Band,
    bandset: &mut BandSet,
    single_phy: bool,
    op: &Operating,
    chnlval: &mut [u32; 2],
) -> Result<SwitchOutcome, Error> {
    let outcome = switch_channel(
        io,
        efuse,
        pg,
        rf_type,
        mode,
        interface_index,
        band,
        bandset,
        single_phy,
        op.wide,
        op.bw40,
        chnlval,
    )
    .await?;
    if outcome.switched {
        set_bw_mode(io, *band, op.bw40, op.prime_sc, rf_type, chnlval).await?;
    }
    Ok(outcome)
}
