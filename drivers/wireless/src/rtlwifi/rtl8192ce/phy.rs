// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192CE / RTL8188CE BB/RF configuration over the `table.c` arrays,
//! channel / bandwidth programming and LC calibration.
//!
//! Exact Linux `rtl8192c/phy_common.c` + `rtl8192ce/{phy,rf}.c` register
//! effects:
//!
//! - `rtl92c_phy_set_bb_reg` / `rtl92c_phy_query_bb_reg` (the shifted value
//!   is not re-masked, as in Linux).
//! - `_rtl92c_phy_rf_serial_write` / `_rtl92c_phy_rf_serial_read`
//!   (`offset &= 0x3f`; read: `0x824` edge low, the path's HSSI2 with the
//!   address and edge, `0x824` edge high, each followed by `mdelay(1)`, then
//!   the PI/SI read-back chosen by the path's HSSI1 BIT(8)).
//! - `rtl92c_phy_mac_config` (every MAC_2T row as a byte write, then
//!   `0x14 = 0x71` on 92C or `0x4ca = 0x0a` on 88C).
//! - `rtl92c_phy_bb_config` (BB/RF enable writes, `_rtl92c_phy_bb8192c_
//!   config_parafile`: PHY_REG walk with `rtl_addr_delay` + dword write +
//!   `udelay(1)`, the PHY_REG_PG `_rtl92c_store_pwrindex_diffrate_offset`
//!   store, the AGC walk, `cck_high_power`). The `RF_1T2R`
//!   `_rtl92c_phy_bb_config_1t` branch never runs: that bonding is refused.
//! - `rtl92ce_phy_rf6052_config` (`num_total_rfpath` 1 for `RF_1T1R`, 2 for
//!   `RF_2T2R`) with `rtl_rfreg_delay` rows.
//! - `rtl92ce_phy_set_bw_mode_callback` + `rtl92ce_phy_rf6052_set_bandwidth`
//!   and `_rtl92c_phy_sw_chnl_step_by_step` (TX power, `RF_CHNLBW` per
//!   path, `_rtl92c_phy_sw_rf_seting`, 10 ms).
//! - `_rtl92ce_phy_lc_calibrate` and `_rtl92c_phy_set_rfpath_switch` (run
//!   with `is_hal_stop` true: `rtl92ce_hw_init` precedes `set_hal_start`).

use super::tables;
use super::version::{RfType, Version};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const REG_SYS_FUNC_EN: u16 = 0x0002;
pub const REG_RF_CTRL: u16 = 0x001f;
pub const REG_AFE_XTAL_CTRL: u16 = 0x0024;
pub const REG_AFE_PLL_CTRL: u16 = 0x0028;
pub const REG_LEDCFG0: u16 = 0x004c;
pub const REG_RRSR: u16 = 0x0440;
pub const REG_TXPAUSE: u16 = 0x0522;
pub const REG_BWOPMODE: u16 = 0x0603;
/// `BW_OPMODE_20MHZ`.
pub const BW_OPMODE_20MHZ: u8 = 1 << 2;
/// `FEN_PPLL | FEN_PCIEA | FEN_DIO_PCIE | FEN_BB_GLB_RSTN | FEN_BBRSTB`.
pub const SYS_FUNC_EN_BB: u8 = 0x80 | 0x40 | 0x20 | 0x02 | 0x01;
/// `RF_EN | RF_RSTB | RF_SDMRSTB`.
pub const RF_CTRL_ON: u8 = 0x07;

pub const RFPGA0_RFMOD: u16 = 0x0800;
pub const RFPGA0_XA_HSSIPARAMETER1: u16 = 0x0820;
pub const RFPGA0_XA_HSSIPARAMETER2: u16 = 0x0824;
pub const RFPGA0_XB_HSSIPARAMETER1: u16 = 0x0828;
pub const RFPGA0_XB_HSSIPARAMETER2: u16 = 0x082c;
pub const RFPGA0_XA_LSSIPARAMETER: u16 = 0x0840;
pub const RFPGA0_XB_LSSIPARAMETER: u16 = 0x0844;
pub const RFPGA0_XA_RFINTERFACEOE: u16 = 0x0860;
pub const RFPGA0_XB_RFINTERFACEOE: u16 = 0x0864;
pub const RFPGA0_XAB_RFINTERFACESW: u16 = 0x0870;
pub const RFPGA0_XAB_RFPARAMETER: u16 = 0x0878;
pub const RFPGA0_ANALOGPARAMETER2: u16 = 0x0884;
pub const RFPGA0_XA_LSSIREADBACK: u16 = 0x08a0;
pub const RFPGA0_XB_LSSIREADBACK: u16 = 0x08a4;
pub const TRANSCEIVEA_HSPI_READBACK: u16 = 0x08b8;
pub const TRANSCEIVEB_HSPI_READBACK: u16 = 0x08bc;
pub const RFPGA1_RFMOD: u16 = 0x0900;
pub const RCCK0_SYSTEM: u16 = 0x0a00;
pub const ROFDM1_LSTF: u16 = 0x0d00;

pub const MASKDWORD: u32 = u32::MAX;
pub const MASK12BITS: u32 = 0xfff;
pub const RFREG_OFFSET_MASK: u32 = 0x000f_ffff;
pub const BLSSIREADADDRESS: u32 = 0x7f80_0000;
pub const BLSSIREADEDGE: u32 = 0x8000_0000;
pub const BLSSIREADBACKDATA: u32 = 0x000f_ffff;
pub const BRFSI_RFENV: u32 = 0x10;
pub const B3WIREADDREAALENGTH: u32 = 0x400;
pub const B3WIREDATALENGTH: u32 = 0x800;
pub const BCCKEN: u32 = 0x0100_0000;
pub const BOFDMEN: u32 = 0x0200_0000;
pub const BRFMOD: u32 = 0x1;
pub const BCCK_SIDEBAND: u32 = 0x10;

/// RF registers (`rtl8192ce/reg.h`).
pub const RF_AC: u32 = 0x00;
pub const RF_IPA: u32 = 0x15;
pub const RF_CHNLBW: u32 = 0x18;
pub const RF_RX_G1: u32 = 0x1a;
pub const RF_RX_G2: u32 = 0x1b;
pub const RF_RCK1: u32 = 0x1e;
pub const RF_RCK2: u32 = 0x1f;
pub const RF_SYN_G2: u32 = 0x26;

/// `HAL_PRIME_CHNL_OFFSET_*` (`mac->cur_40_prime_sc`).
pub const PRIME_CHNL_OFFSET_DONT_CARE: u8 = 0;
pub const PRIME_CHNL_OFFSET_LOWER: u8 = 1;
pub const PRIME_CHNL_OFFSET_UPPER: u8 = 2;

/// `RF90_PATH_A` / `RF90_PATH_B`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    A = 0,
    B = 1,
}

pub static PATHS: [Path; 2] = [Path::A, Path::B];

impl RfType {
    /// `rtl92ce_phy_rf6052_config` `num_total_rfpath` paths, in order.
    pub fn rf_paths(self) -> &'static [Path] {
        &PATHS[..self.paths()]
    }
}

/// `_rtl92c_phy_init_bb_rf_register_definition` for one path.
#[derive(Clone, Copy, Debug)]
pub struct PathRegs {
    pub rfintfs: u16,
    pub rfintfo: u16,
    pub rfintfe: u16,
    pub rf3wire_offset: u16,
    pub rfhssi_para1: u16,
    pub rfhssi_para2: u16,
    pub rf_rb: u16,
    pub rf_rbpi: u16,
}

impl Path {
    pub const fn regs(self) -> PathRegs {
        match self {
            Path::A => PathRegs {
                rfintfs: RFPGA0_XAB_RFINTERFACESW,
                rfintfo: RFPGA0_XA_RFINTERFACEOE,
                rfintfe: RFPGA0_XA_RFINTERFACEOE,
                rf3wire_offset: RFPGA0_XA_LSSIPARAMETER,
                rfhssi_para1: RFPGA0_XA_HSSIPARAMETER1,
                rfhssi_para2: RFPGA0_XA_HSSIPARAMETER2,
                rf_rb: RFPGA0_XA_LSSIREADBACK,
                rf_rbpi: TRANSCEIVEA_HSPI_READBACK,
            },
            Path::B => PathRegs {
                rfintfs: RFPGA0_XAB_RFINTERFACESW,
                rfintfo: RFPGA0_XB_RFINTERFACEOE,
                rfintfe: RFPGA0_XB_RFINTERFACEOE,
                rf3wire_offset: RFPGA0_XB_LSSIPARAMETER,
                rfhssi_para1: RFPGA0_XB_HSSIPARAMETER1,
                rfhssi_para2: RFPGA0_XB_HSSIPARAMETER2,
                rf_rb: RFPGA0_XB_LSSIREADBACK,
                rf_rbpi: TRANSCEIVEB_HSPI_READBACK,
            },
        }
    }
}

fn shift(mask: u32) -> u32 {
    mask.trailing_zeros() & 31
}

fn reg(addr: u32) -> Result<u16, Error> {
    u16::try_from(addr)
        .ok()
        .filter(|r| r & 3 == 0)
        .ok_or(Error::Descriptor)
}

/// `rtl92c_phy_set_bb_reg`.
pub fn set_bb(io: &impl Io, at: u16, mask: u32, value: u32) -> Result<(), Error> {
    let data = if mask == MASKDWORD {
        value
    } else {
        (io.read32(at)? & !mask) | (value << shift(mask))
    };
    io.write32(at, data)?;
    Ok(())
}

/// `rtl92c_phy_query_bb_reg`.
pub fn get_bb(io: &impl Io, at: u16, mask: u32) -> Result<u32, Error> {
    Ok((io.read32(at)? & mask) >> shift(mask))
}

/// `_rtl92c_phy_rf_serial_write`.
pub fn rf_write(io: &impl Io, path: Path, offset: u32, data: u32) -> Result<(), Error> {
    let word = (((offset & 0x3f) << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    set_bb(io, path.regs().rf3wire_offset, MASKDWORD, word)
}

/// `_rtl92c_phy_rf_serial_read`.
pub async fn rf_read(io: &impl Io, path: Path, offset: u32) -> Result<u32, Error> {
    let regs = path.regs();
    let offset = offset & 0x3f;
    let tmplong = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, MASKDWORD)?;
    let tmplong2 = if path == Path::A {
        tmplong
    } else {
        get_bb(io, regs.rfhssi_para2, MASKDWORD)?
    };
    let tmplong2 = (tmplong2 & !BLSSIREADADDRESS) | (offset << 23) | BLSSIREADEDGE;
    set_bb(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong & !BLSSIREADEDGE,
    )?;
    io.delay_us(1000).await;
    set_bb(io, regs.rfhssi_para2, MASKDWORD, tmplong2)?;
    io.delay_us(1000).await;
    set_bb(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong | BLSSIREADEDGE,
    )?;
    io.delay_us(1000).await;
    let pi = get_bb(io, regs.rfhssi_para1, 1 << 8)? != 0;
    get_bb(
        io,
        if pi { regs.rf_rbpi } else { regs.rf_rb },
        BLSSIREADBACKDATA,
    )
}

/// `rtl92ce_phy_set_rf_reg` (`RF_OP_BY_SW_3WIRE`; the shifted value is not
/// re-masked). Any mask other than `RFREG_OFFSET_MASK` — including
/// `MASKDWORD` — reads the register first, as Linux.
pub async fn set_rf(
    io: &impl Io,
    path: Path,
    offset: u32,
    mask: u32,
    value: u32,
) -> Result<(), Error> {
    let data = if mask == RFREG_OFFSET_MASK {
        value
    } else {
        (rf_read(io, path, offset).await? & !mask) | (value << shift(mask))
    };
    rf_write(io, path, offset, data)
}

/// `rtl92c_phy_query_rf_reg`.
pub async fn get_rf(io: &impl Io, path: Path, offset: u32, mask: u32) -> Result<u32, Error> {
    Ok((rf_read(io, path, offset).await? & mask) >> shift(mask))
}

/// `rtl_addr_delay` (microseconds; the lower bound of each
/// `usleep_range`). Returns 0 for a non-delay address.
pub const fn addr_delay_us(addr: u32) -> u64 {
    match addr {
        0xfe => 50_000,
        0xfd => 5_000,
        0xfc => 1_000,
        0xfb => 50,
        0xfa => 5,
        0xf9 => 1,
        _ => 0,
    }
}

/// `_rtl92c_phy_config_mac_with_headerfile` + the `rtl92c_phy_mac_config`
/// serial byte.
pub fn mac_config(io: &impl Io, version: Version) -> Result<(), Error> {
    for pair in tables::MAC_2T.chunks_exact(2) {
        let at = u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?;
        io.write8(at, pair[1] as u8)?;
    }
    if version.is_92c_serial() {
        io.write8(0x14, 0x71)?;
    } else {
        io.write8(0x04ca, 0x0a)?;
    }
    Ok(())
}

// ── PHY_REG_PG (`_rtl92c_store_pwrindex_diffrate_offset`) ───────────────

/// `MAX_PG_GROUP`.
pub const MAX_PG_GROUP: usize = 13;

/// `RTXAGC_*` registers (`reg.h`).
pub const RTXAGC_A_RATE18_06: u16 = 0x0e00;
pub const RTXAGC_A_RATE54_24: u16 = 0x0e04;
pub const RTXAGC_A_CCK1_MCS32: u16 = 0x0e08;
pub const RTXAGC_B_CCK11_A_CCK2_11: u16 = 0x086c;
pub const RTXAGC_A_MCS03_MCS00: u16 = 0x0e10;
pub const RTXAGC_A_MCS07_MCS04: u16 = 0x0e14;
pub const RTXAGC_A_MCS11_MCS08: u16 = 0x0e18;
pub const RTXAGC_A_MCS15_MCS12: u16 = 0x0e1c;
pub const RTXAGC_B_RATE18_06: u16 = 0x0830;
pub const RTXAGC_B_RATE54_24: u16 = 0x0834;
pub const RTXAGC_B_CCK1_55_MCS32: u16 = 0x0838;
pub const RTXAGC_B_MCS03_MCS00: u16 = 0x083c;
pub const RTXAGC_B_MCS07_MCS04: u16 = 0x0848;
pub const RTXAGC_B_MCS11_MCS08: u16 = 0x084c;
pub const RTXAGC_B_MCS15_MCS12: u16 = 0x0868;

/// `rtlphy->mcs_txpwrlevel_origoffset` and `pwrgroup_cnt` after the
/// PHY_REG_PG walk. On this family nothing reads `origoffset`: the
/// RF6052 TX-power code reads `rtlphy->mcs_offset`, which no
/// `rtl8192c`/`rtl8192ce` path writes (see [`super::txpower::MCS_OFFSET`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PgStore {
    pub origoffset: [[u32; 16]; MAX_PG_GROUP],
    pub pwrgroup_cnt: u8,
}

impl PgStore {
    /// `_rtl92ce_phy_config_bb_with_pgheaderfile(BASEBAND_CONFIG_PHY_REG)`
    /// over `(regaddr, bitmask, data)` rows. A group index past
    /// `MAX_PG_GROUP` (Linux would overrun the array) is refused.
    pub fn from_pg(table: &[u32]) -> Result<Self, Error> {
        let mut out = Self {
            origoffset: [[0; 16]; MAX_PG_GROUP],
            pwrgroup_cnt: 0,
        };
        for row in table.chunks_exact(3) {
            let (regaddr, bitmask, data) = (row[0], row[1], row[2]);
            let slot = match (u16::try_from(regaddr).unwrap_or(0), bitmask) {
                (RTXAGC_A_RATE18_06, _) => Some(0),
                (RTXAGC_A_RATE54_24, _) => Some(1),
                (RTXAGC_A_CCK1_MCS32, _) => Some(6),
                (RTXAGC_B_CCK11_A_CCK2_11, 0xffff_ff00) => Some(7),
                (RTXAGC_A_MCS03_MCS00, _) => Some(2),
                (RTXAGC_A_MCS07_MCS04, _) => Some(3),
                (RTXAGC_A_MCS11_MCS08, _) => Some(4),
                (RTXAGC_A_MCS15_MCS12, _) => Some(5),
                (RTXAGC_B_RATE18_06, _) => Some(8),
                (RTXAGC_B_RATE54_24, _) => Some(9),
                (RTXAGC_B_CCK1_55_MCS32, _) => Some(14),
                (RTXAGC_B_CCK11_A_CCK2_11, 0x0000_00ff) => Some(15),
                (RTXAGC_B_MCS03_MCS00, _) => Some(10),
                (RTXAGC_B_MCS07_MCS04, _) => Some(11),
                (RTXAGC_B_MCS11_MCS08, _) => Some(12),
                (RTXAGC_B_MCS15_MCS12, _) => Some(13),
                _ => None,
            };
            if let Some(slot) = slot {
                let group = out
                    .origoffset
                    .get_mut(usize::from(out.pwrgroup_cnt))
                    .ok_or(Error::Descriptor)?;
                group[slot] = data;
                if slot == 13 {
                    out.pwrgroup_cnt += 1;
                }
            }
        }
        Ok(out)
    }
}

// ── BB / RF configuration ────────────────────────────────────────────────

/// Facts produced by `rtl92c_phy_bb_config` / `rtl92c_phy_rf_config`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// `rtlphy->cck_high_power` read back after the AGC table.
    pub cck_high_power: bool,
    pub pg: PgStore,
}

/// `rtl92c_phy_bb_config` register effects in Linux order (provisioned
/// boards only, so the PG walk always runs: `!autoload_failflag`).
pub async fn bb_config(io: &impl Io, version: Version) -> Result<Report, Error> {
    let lo = io.read8(REG_SYS_FUNC_EN)?;
    let hi = io.read8(REG_SYS_FUNC_EN + 1)?;
    let regval = u16::from_le_bytes([lo, hi]) | (1 << 13) | 1 | (1 << 1);
    io.write16(REG_SYS_FUNC_EN, regval)?;
    io.write8(REG_AFE_PLL_CTRL, 0x83)?;
    io.write8(REG_AFE_PLL_CTRL + 1, 0xdb)?;
    io.write8(REG_RF_CTRL, RF_CTRL_ON)?;
    io.write8(REG_SYS_FUNC_EN, SYS_FUNC_EN_BB)?;
    io.write8(REG_AFE_XTAL_CTRL + 1, 0x80)?;
    let led = io.read32(REG_LEDCFG0)?;
    io.write32(REG_LEDCFG0, led | (1 << 23))?;
    let (phy_reg, agc): (&[u32], &[u32]) = if version.is_92c_serial() {
        (&tables::PHY_REG_2T, &tables::AGCTAB_2T)
    } else {
        (&tables::PHY_REG_1T, &tables::AGCTAB_1T)
    };
    for pair in phy_reg.chunks_exact(2) {
        let us = addr_delay_us(pair[0]);
        if us != 0 {
            io.delay_us(us).await;
        }
        // Linux writes the dword even at a delay address; no shipped row is one.
        set_bb(io, reg(pair[0])?, MASKDWORD, pair[1])?;
        io.delay_us(1).await;
    }
    let pg = PgStore::from_pg(&tables::PHY_REG_PG)?;
    for pair in agc.chunks_exact(2) {
        set_bb(io, reg(pair[0])?, MASKDWORD, pair[1])?;
        io.delay_us(1).await;
    }
    let cck_high_power = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, 0x200)? != 0;
    Ok(Report { cck_high_power, pg })
}

/// `_rtl92ce_phy_rf6052_config_parafile` over the version's RF tables.
pub async fn rf_config(io: &impl Io, version: Version) -> Result<(), Error> {
    let two = version.is_92c_serial();
    for &path in version.rf_type().rf_paths() {
        let regs = path.regs();
        let env_mask = match path {
            Path::A => BRFSI_RFENV,
            Path::B => BRFSI_RFENV << 16,
        };
        let saved = get_bb(io, regs.rfintfs, env_mask)?;
        set_bb(io, regs.rfintfe, BRFSI_RFENV << 16, 0x1)?;
        io.delay_us(1).await;
        set_bb(io, regs.rfintfo, BRFSI_RFENV, 0x1)?;
        io.delay_us(1).await;
        set_bb(io, regs.rfhssi_para2, B3WIREADDREAALENGTH, 0x0)?;
        io.delay_us(1).await;
        set_bb(io, regs.rfhssi_para2, B3WIREDATALENGTH, 0x0)?;
        io.delay_us(1).await;
        let table: &[u32] = match (path, two) {
            (Path::A, true) => &tables::RADIOA_2T,
            (Path::B, true) => &tables::RADIOB_2T,
            (Path::A, false) => &tables::RADIOA_1T,
            (Path::B, false) => &tables::RADIOB_1T,
        };
        for pair in table.chunks_exact(2) {
            // rtl_rfreg_delay.
            if (0xf9..=0xfe).contains(&pair[0]) {
                io.delay_us(addr_delay_us(pair[0])).await;
            } else {
                set_rf(io, path, pair[0], RFREG_OFFSET_MASK, pair[1]).await?;
                io.delay_us(1).await;
            }
        }
        set_bb(io, regs.rfintfs, env_mask, saved)?;
    }
    Ok(())
}

/// `rtl92ce_hw_init` UMC-cut RF fixups after `rtl92c_phy_rf_config`
/// (`MASKDWORD` RF writes: each is a read then write, as Linux).
pub async fn umc_fixups(io: &impl Io, version: Version) -> Result<(), Error> {
    if version.is_umc_a_cut() && !version.is_92c_serial() {
        set_rf(io, Path::A, RF_RX_G1, MASKDWORD, 0x30255).await?;
        set_rf(io, Path::A, RF_RX_G2, MASKDWORD, 0x50a00).await?;
    } else if version.is_umc_b_cut() {
        for (addr, data) in [
            (0x0c, 0x894ae),
            (0x0a, 0x1af31),
            (RF_IPA, 0x8f425),
            (RF_SYN_G2, 0x4f200),
            (RF_RCK1, 0x44053),
            (RF_RCK2, 0x80201),
        ] {
            set_rf(io, Path::A, addr, MASKDWORD, data).await?;
        }
    }
    Ok(())
}

/// `rtl92ce_hw_init` from `rtl92c_phy_mac_config` through the CCK/OFDM
/// enable and `RFPGA0_ANALOGPARAMETER2[10]` writes. `receive_config` is the
/// trimmed RCR (`mac::trim_receive_config`). Returns the report and
/// `rtlphy->rfreg_chnlval` (read from both paths, also on an 88C part, as
/// Linux).
pub async fn configure(io: &impl Io, version: Version) -> Result<(Report, [u32; 2]), Error> {
    mac_config(io, version)?;
    super::mac::trim_receive_config(io)?;
    let report = bb_config(io, version).await?;
    rf_config(io, version).await?;
    umc_fixups(io, version).await?;
    let chnlval = [
        get_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK).await?,
        get_rf(io, Path::B, RF_CHNLBW, RFREG_OFFSET_MASK).await?,
    ];
    set_bb(io, RFPGA0_RFMOD, BCCKEN, 0x1)?;
    set_bb(io, RFPGA0_RFMOD, BOFDMEN, 0x1)?;
    set_bb(io, RFPGA0_ANALOGPARAMETER2, 1 << 10, 1)?;
    Ok((report, chnlval))
}

// ── Bandwidth / channel ──────────────────────────────────────────────────

/// `rtl92ce_phy_rf6052_set_bandwidth` (path A only, as Linux).
pub async fn rf6052_set_bandwidth(
    io: &impl Io,
    bw40: bool,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    chnlval[0] = (chnlval[0] & 0xffff_f3ff) | if bw40 { 0 } else { 0x0400 };
    set_rf(io, Path::A, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[0]).await
}

/// `rtl92ce_phy_set_bw_mode_callback` (`prime_sc` = `cur_40_prime_sc`).
pub async fn set_bw_mode(
    io: &impl Io,
    bw40: bool,
    prime_sc: u8,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    let opmode = io.read8(REG_BWOPMODE)?;
    let prsr = io.read8(REG_RRSR + 2)?;
    if bw40 {
        io.write8(REG_BWOPMODE, opmode & !BW_OPMODE_20MHZ)?;
        io.write8(REG_RRSR + 2, (prsr & 0x90) | (prime_sc << 5))?;
        set_bb(io, RFPGA0_RFMOD, BRFMOD, 0x1)?;
        set_bb(io, RFPGA1_RFMOD, BRFMOD, 0x1)?;
        set_bb(io, RCCK0_SYSTEM, BCCK_SIDEBAND, u32::from(prime_sc >> 1))?;
        set_bb(io, ROFDM1_LSTF, 0xc00, u32::from(prime_sc))?;
        set_bb(io, RFPGA0_ANALOGPARAMETER2, 1 << 10, 0)?;
        let sel = if prime_sc == PRIME_CHNL_OFFSET_LOWER {
            2
        } else {
            1
        };
        set_bb(io, 0x818, (1 << 26) | (1 << 27), sel)?;
    } else {
        io.write8(REG_BWOPMODE, opmode | BW_OPMODE_20MHZ)?;
        set_bb(io, RFPGA0_RFMOD, BRFMOD, 0x0)?;
        set_bb(io, RFPGA1_RFMOD, BRFMOD, 0x0)?;
        set_bb(io, RFPGA0_ANALOGPARAMETER2, 1 << 10, 1)?;
    }
    rf6052_set_bandwidth(io, bw40, chnlval).await
}

/// The `CMDID_RF_WRITEREG` step of `_rtl92c_phy_sw_chnl_step_by_step`:
/// `RF_CHNLBW[9:0] = channel` on each of the `num_total_rfpath` paths, then
/// `_rtl92c_phy_sw_rf_seting` (UMC B-cut: RF A `RF_RX_G1` = `0x00255` on
/// channel 6 at 20 MHz, else rewritten with its own value), then the 10 ms
/// command delay. The preceding TX-power command is the caller's.
pub async fn sw_chnl_rf(
    io: &impl Io,
    version: Version,
    channel: u8,
    bw40: bool,
    chnlval: &mut [u32; 2],
) -> Result<(), Error> {
    if !(1..=14).contains(&channel) {
        return Err(Error::State);
    }
    for &path in version.rf_type().rf_paths() {
        let p = path as usize;
        chnlval[p] = (chnlval[p] & 0xffff_fc00) | u32::from(channel);
        set_rf(io, path, RF_CHNLBW, RFREG_OFFSET_MASK, chnlval[p]).await?;
    }
    if version.is_umc_b_cut() {
        if channel == 6 && !bw40 {
            set_rf(io, Path::A, RF_RX_G1, MASKDWORD, 0x00255).await?;
        } else {
            let backup = get_rf(io, Path::A, RF_RX_G1, RFREG_OFFSET_MASK).await?;
            set_rf(io, Path::A, RF_RX_G1, MASKDWORD, backup).await?;
        }
    }
    io.delay_us(10_000).await;
    Ok(())
}

// ── Calibration helpers ──────────────────────────────────────────────────

/// `_rtl92c_phy_set_rfpath_switch(bmain = true)` with `is_hal_stop` true
/// (the `rtl92ce_hw_init` call).
pub fn rfpath_switch_main(io: &impl Io, version: Version) -> Result<(), Error> {
    set_bb(io, REG_LEDCFG0, 1 << 23, 0x01)?;
    set_bb(io, RFPGA0_XAB_RFPARAMETER, 1 << 13, 0x01)?;
    if version.is_92c_serial() {
        set_bb(io, RFPGA0_XB_RFINTERFACEOE, (1 << 5) | (1 << 6), 0x1)
    } else {
        set_bb(io, RFPGA0_XA_RFINTERFACEOE, 0x300, 0x2)
    }
}

/// `_rtl92ce_phy_lc_calibrate(is2t)` (`rtl92c_phy_lc_calibrate`). The
/// `MASK12BITS` RF writes keep Linux's unmasked values (bit 16 lands in
/// the register).
pub async fn lc_calibrate(io: &impl Io, version: Version) -> Result<(), Error> {
    let is2t = version.is_92c_serial();
    let tmpreg = io.read8(0x0d03)?;
    let cont_tx = tmpreg & 0x70 != 0;
    if cont_tx {
        io.write8(0x0d03, tmpreg & 0x8f)?;
    } else {
        io.write8(REG_TXPAUSE, 0xff)?;
    }
    let (mut rf_a_mode, mut rf_b_mode) = (0, 0);
    if cont_tx {
        rf_a_mode = get_rf(io, Path::A, RF_AC, MASK12BITS).await?;
        if is2t {
            rf_b_mode = get_rf(io, Path::B, RF_AC, MASK12BITS).await?;
        }
        set_rf(
            io,
            Path::A,
            RF_AC,
            MASK12BITS,
            (rf_a_mode & 0x8ffff) | 0x10000,
        )
        .await?;
        if is2t {
            set_rf(
                io,
                Path::B,
                RF_AC,
                MASK12BITS,
                (rf_b_mode & 0x8ffff) | 0x10000,
            )
            .await?;
        }
    }
    let lc_cal = get_rf(io, Path::A, RF_CHNLBW, MASK12BITS).await?;
    set_rf(io, Path::A, RF_CHNLBW, MASK12BITS, lc_cal | 0x08000).await?;
    io.delay_us(100_000).await;
    if cont_tx {
        io.write8(0x0d03, tmpreg)?;
        set_rf(io, Path::A, RF_AC, MASK12BITS, rf_a_mode).await?;
        if is2t {
            set_rf(io, Path::B, RF_AC, MASK12BITS, rf_b_mode).await?;
        }
    } else {
        io.write8(REG_TXPAUSE, 0x00)?;
    }
    Ok(())
}
