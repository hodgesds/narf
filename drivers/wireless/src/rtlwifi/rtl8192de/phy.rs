// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE BB/RF register access, the RF 3-wire serial path, the DBI
//! cross-function path, and the factory power-group table walk.
//!
//! Exact Linux `rtl8192d/phy_common.c` + `rtl8192de/{phy,rf}.c`:
//!
//! - `rtl92d_phy_set_bb_reg` / `rtl92d_phy_query_bb_reg`: the shifted
//!   value is not re-masked, as in Linux — the `0xffffff00` CCK write
//!   carries the third AGC byte (see [`super::txpower`]; the sibling
//!   92CE port masks it out, which Linux does not do).
//! - `_rtl92d_phy_rf_serial_write` / `_rtl92d_phy_rf_serial_read`
//!   (`0x824` edge low, the path's HSSI2 with the address and edge,
//!   `0x824` edge high, `udelay(10)` / `udelay(100)` / `udelay(10)`,
//!   then the PI/SI read-back chosen by the path's HSSI1 BIT(8)).
//! - `rtl92d_phy_rf6052_config` `num_total_rfpath`: 1 for `RF_1T1R`,
//!   2 otherwise.
//! - `rtl92de_read_dword_dbi` / `rtl92de_write_dword_dbi`
//!   (`rtl8192de/hw.c`): `REG_DBI_CTRL` is the offset masked with
//!   `0xFFC` (`| 0xF000` on write), `REG_DBI_FLAG` is `BIT(1) | direct`
//!   on read / `BIT(0) | direct` on write, with a 10 us settle on read.
//! - `rtl92d_phy_enable_anotherphy` / `rtl92d_phy_powerdown_anotherphy`
//!   (`rtl8192de/rf.c`): the other MAC's `REG_MAC0` / `REG_MAC1`
//!   ON bit decides; enabling sets `REG_SYS_ISO_CTRL` BIT(29) |
//!   BIT(16) | BIT(17) over DBI, powering down writes `0` to the
//!   path-A LSSI parameter over DBI.
//! - `rtl92d_store_pwrindex_diffrate_offset`
//!   (`rtl8192d/phy_common.c`): the PHY_REG_PG factory table walk
//!   (`_rtl92d_phy_config_bb_with_pgheaderfile`, `rtl8192de/phy.c`)
//!   stores each triple's data into `mcs_offset[pwrgroup_cnt][index]`
//!   and advances `pwrgroup_cnt` when index 13
//!   (`RTXAGC_B_MCS15_MCS12`) lands. A group index past
//!   `MAX_PG_GROUP` (Linux would overrun the array) is refused.
//! - `rtl92d_phy_mac_config` (`rtl8192d/phy.c`): the `MAC_2T`
//!   byte-walk, then `REG_MAX_AGGR_NUM` (`0x04ca`) `0x0b` on a
//!   single-MAC part / `0x07` on a dual-MAC part.
//! - `rtl92d_phy_bb_config` (`rtl8192d/phy.c`): `SYS_FUNC_EN`
//!   `BIT(13) | BIT(0) | BIT(1)`, `AFE_PLL_CTRL` `0x83` / `0xdb`,
//!   `RF_CTRL` `RF_EN | RF_RSTB | RF_SDMRSTB`, `SYS_FUNC_EN`
//!   `FEN_PPLL | FEN_PCIEA | FEN_DIO_PCIE | FEN_BB_GLB_RSTN |
//!   FEN_BBRSTB`, `AFE_XTAL_CTRL+1` `0x80`, `LEDCFG0` `BIT(23)`
//!   unless `IS_92D_SINGLEPHY` — which is the RF type, not the
//!   MAC/PHY mode: the macro is true exactly for `RF_2T2R`
//!   (`rtl8192de/def.h`), so the LED bit is set on 1T parts only —
//!   then the `PHY_REG` walk (`set_bbreg` `MASKDWORD` + `udelay(1)`),
//!   the PG walk unless autoload failed, and the AGC walk — `AGCTAB`
//!   on MAC0, or `AGCTAB_2G` / `AGCTAB_5G` on MAC1 by band —
//!   returning `cck_high_power`, the `RFPGA0_XA_HSSIPARAMETER2`
//!   `0x200` bit.
//! - `rtl92d_phy_rf6052_config` (`rtl8192de/rf.c`): 1 path on
//!   `RF_1T1R`, 2 otherwise; dual-dual branches load the other
//!   MAC's radio table over DBI first (early-returning when the
//!   other MAC already loaded it, or when the other PHY was just
//!   powered up); interface 1 (MAC1, otherwise) loads only
//!   `radio_b` on path A (`true_bpath`); otherwise A takes
//!   `radioa` and B takes `radiob`, each under the RF-env
//!   save/restore dance, with `rtl_rfreg_delay` per `(reg, val)`
//!   pair. `rtl92d_phy_config_rf_with_headerfile` picks the
//!   internal-PA table per path and swaps the DMDP radio tables
//!   (`radiob_txt` on path A loads the `radio_b` table).
//! - `rtl92d_phy_get_hw_reg_originalvalue` (`rtl8192d/phy.c`):
//!   `initialgain[0..3]` from `ROFDM0_X{A,B,C,D}AGCCORE1` byte 0,
//!   `framesync` from `ROFDM0_RXDETECTOR3` byte 0, `framesync_c34`
//!   from `ROFDM0_RXDETECTOR2` as a dword.
//!
//! Not ported: `rtl92d_phy_lc_calibrate` (RF LC calibration, a
//! follow-up lane) and the IQK reload (`rtl92d_phy_reset_iqk_result`
//! is software-only; the IQK reload itself is a follow-up lane).

use super::{Band, MacPhyMode, RfType};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const MASKDWORD: u32 = u32::MAX;
pub const MASKBYTE0: u32 = 0xff;
pub const BDWORD: u32 = 0x0f;
pub const RFREG_OFFSET_MASK: u32 = 0x000f_ffff;
pub const BLSSIREADADDRESS: u32 = 0x7f80_0000;
pub const BLSSIREADEDGE: u32 = 0x8000_0000;
pub const BLSSIREADBACKDATA: u32 = 0x000f_ffff;
pub const BRFSI_RFENV: u32 = 0x10;
pub const BCCKEN: u32 = 0x0100_0000;
pub const BOFDMEN: u32 = 0x0200_0000;
pub const BRFMOD: u32 = 0x1;
pub const BCCKSIDEBAND: u32 = 0x10;

pub const RFPGA0_RFMOD: u16 = 0x0800;
pub const RFPGA0_XA_HSSIPARAMETER1: u16 = 0x0820;
pub const RFPGA0_XA_HSSIPARAMETER2: u16 = 0x0824;
pub const RFPGA0_XB_HSSIPARAMETER1: u16 = 0x0828;
pub const RFPGA0_XB_HSSIPARAMETER2: u16 = 0x082c;
pub const RFPGA0_XA_LSSIPARAMETER: u16 = 0x0840;
pub const RFPGA0_XB_LSSIPARAMETER: u16 = 0x0844;
pub const RFPGA0_XA_LSSIREADBACK: u16 = 0x08a0;
pub const RFPGA0_XB_LSSIREADBACK: u16 = 0x08a4;
pub const RFPGA0_XA_RFINTERFACEOE: u16 = 0x0860;
pub const RFPGA0_XB_RFINTERFACEOE: u16 = 0x0864;
pub const RFPGA0_XAB_RFINTERFACESW: u16 = 0x0870;
pub const RFPGA0_XAB_RFPARAMETER: u16 = 0x0878;
pub const RFPGA0_ANALOGPARAMETER2: u16 = 0x0884;
pub const RFPGA0_ADDALLOCKEN: u16 = 0x0888;
pub const RFPGA0_ANALOGPARAMETER4: u16 = 0x088c;
pub const RFPGA0_XCD_RFPARAMETER: u16 = 0x087c;
pub const ROFDM0_RXDETECTOR2: u16 = 0x0c34;
pub const ROFDM0_RXDETECTOR3: u16 = 0x0c38;
pub const ROFDM0_XAAGCCORE1: u16 = 0x0c50;
pub const ROFDM0_XBAGCCORE1: u16 = 0x0c58;
pub const ROFDM0_XCAGCCORE1: u16 = 0x0c60;
pub const ROFDM0_XDAGCCORE1: u16 = 0x0c68;

/// `REG_AFE_PLL_CTRL` (`rtl8192d/reg.h`).
pub const REG_AFE_PLL_CTRL: u16 = 0x0028;
/// `REG_RF_CTRL` (`rtl8192d/reg.h`).
pub const REG_RF_CTRL: u16 = 0x001f;
/// `REG_LEDCFG0` (`rtl8192d/reg.h`).
pub const REG_LEDCFG0: u16 = 0x004c;
/// `REG_MAX_AGGR_NUM` (`rtl8192d/reg.h`).
pub const REG_MAX_AGGR_NUM: u16 = 0x04ca;

/// `RF_EN` / `RF_RSTB` / `RF_SDMRSTB` (`rtl8192d/reg.h`).
pub const RF_EN: u8 = 1 << 0;
pub const RF_RSTB: u8 = 1 << 1;
pub const RF_SDMRSTB: u8 = 1 << 2;

/// `FEN_*` bits of `REG_SYS_FUNC_EN` (`rtl8192d/reg.h`).
pub const FEN_BBRSTB: u8 = 1 << 0;
pub const FEN_BB_GLB_RSTN: u8 = 1 << 1;
pub const FEN_DIO_PCIE: u8 = 1 << 5;
pub const FEN_PCIEA: u8 = 1 << 6;
pub const FEN_PPLL: u8 = 1 << 7;

/// `B3WIREADDRESSLENGTH` / `B3WIREDATALENGTH` (`rtl8192d/reg.h`).
pub const B3WIREADDRESSLENGTH: u32 = 0x400;
pub const B3WIREDATALENGTH: u32 = 0x800;
pub const RFPGA1_RFMOD: u16 = 0x0900;
pub const RCCK0_SYSTEM: u16 = 0x0a00;
pub const ROFDM0_TRXPATHENABLE: u16 = 0x0c04;
pub const ROFDM0_XARXIQIMBALANCE: u16 = 0x0c14;
pub const ROFDM0_XBRXIQIMBALANCE: u16 = 0x0c1c;
pub const ROFDM0_ECCATHRESHOLD: u16 = 0x0c4c;
pub const ROFDM0_AGCRSSITABLE: u16 = 0x0c78;
pub const ROFDM0_XATXIQIMBALANCE: u16 = 0x0c80;
pub const ROFDM0_XBTXIQIMBALANCE: u16 = 0x0c88;
pub const ROFDM0_XCTXAFE: u16 = 0x0c94;
pub const ROFDM0_XDTXAFE: u16 = 0x0c9c;
pub const ROFDM1_LSTF: u16 = 0x0d00;
pub const ROFDM1_TRXPATHENABLE: u16 = 0x0d04;
pub const ROFDM1_CFOTRACKING: u16 = 0x0d2c;

/// RF registers (`rtl8192d/reg.h`, `rtl8192de/phy.c`).
pub const RF_CHNLBW: u32 = 0x18;

/// `REG_DBI_*` (`rtl8192d/reg.h`).
pub const REG_DBI_WDATA: u16 = 0x0348;
pub const REG_DBI_RDATA: u16 = 0x034c;
pub const REG_DBI_CTRL: u16 = 0x0350;
pub const REG_DBI_FLAG: u16 = 0x0352;

/// `MAX_PG_GROUP` (`wifi.h`).
pub const MAX_PG_GROUP: usize = 13;

/// `RTXAGC_*` registers (`rtl8192d/reg.h`).
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

/// `RF90_PATH_A` / `RF90_PATH_B`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    A = 0,
    B = 1,
}

pub static PATHS: [Path; 2] = [Path::A, Path::B];

impl RfType {
    /// `rtl92d_phy_rf6052_config` `num_total_rfpath` paths, in order.
    pub fn rf_paths(self) -> &'static [Path] {
        &PATHS[..self.paths()]
    }

    /// `rtl92d_phy_rf6052_config`: 1 path for `RF_1T1R`, 2 otherwise.
    pub fn paths(self) -> usize {
        match self {
            RfType::OneT1R => 1,
            RfType::TwoT2R => 2,
        }
    }
}

/// `_rtl92d_phy_init_bb_rf_register_definition` for one path
/// (`rtl8192d/phy_common.c`; the A/B rows match the 92C map exactly).
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

pub const TRANSCEIVEA_HSPI_READBACK: u16 = 0x08b8;
pub const TRANSCEIVEB_HSPI_READBACK: u16 = 0x08bc;

fn shift(mask: u32) -> u32 {
    mask.trailing_zeros() & 31
}

/// `rtl92d_phy_set_bb_reg` on the local function (no DBI redirect).
pub fn set_bb(io: &impl Io, at: u16, mask: u32, value: u32) -> Result<(), Error> {
    let data = if mask == MASKDWORD {
        value
    } else {
        (io.read32(at)? & !mask) | (value << shift(mask))
    };
    io.write32(at, data)?;
    Ok(())
}

/// `rtl92d_phy_query_bb_reg`.
pub fn get_bb(io: &impl Io, at: u16, mask: u32) -> Result<u32, Error> {
    Ok((io.read32(at)? & mask) >> shift(mask))
}

/// `_rtl92d_phy_rf_serial_write`.
pub fn rf_write(io: &impl Io, path: Path, offset: u32, data: u32) -> Result<(), Error> {
    let word = ((offset << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    set_bb(io, path.regs().rf3wire_offset, MASKDWORD, word)
}

/// `_rtl92d_phy_rf_serial_read`.
pub async fn rf_read(io: &impl Io, path: Path, offset: u32) -> Result<u32, Error> {
    let regs = path.regs();
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
    io.delay_us(10).await;
    set_bb(io, regs.rfhssi_para2, MASKDWORD, tmplong2)?;
    io.delay_us(100).await;
    set_bb(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong | BLSSIREADEDGE,
    )?;
    io.delay_us(10).await;
    let pi = get_bb(io, regs.rfhssi_para1, 1 << 8)? != 0;
    get_bb(
        io,
        if pi { regs.rf_rbpi } else { regs.rf_rb },
        BLSSIREADBACKDATA,
    )
}

/// `rtl92d_phy_set_rf_reg` (`RF_OP_BY_SW_3WIRE`; the shifted value is not
/// re-masked). Any mask other than `RFREG_OFFSET_MASK` reads the register
/// first, as Linux. A zero mask writes nothing.
pub async fn set_rf(
    io: &impl Io,
    path: Path,
    offset: u32,
    mask: u32,
    value: u32,
) -> Result<(), Error> {
    if mask == 0 {
        return Ok(());
    }
    let data = if mask == RFREG_OFFSET_MASK {
        value
    } else {
        (rf_read(io, path, offset).await? & !mask) | (value << shift(mask))
    };
    rf_write(io, path, offset, data)
}

/// `rtl92d_phy_query_rf_reg`.
pub async fn get_rf(io: &impl Io, path: Path, offset: u32, mask: u32) -> Result<u32, Error> {
    Ok((rf_read(io, path, offset).await? & mask) >> shift(mask))
}

/// `rtl92de_read_dword_dbi` (`rtl8192de/hw.c`).
pub async fn read_dword_dbi(io: &impl Io, offset: u16, direct: u8) -> Result<u32, Error> {
    io.write16(REG_DBI_CTRL, offset & 0x0ffc)?;
    io.write8(REG_DBI_FLAG, (1 << 1) | direct)?;
    io.delay_us(10).await;
    Ok(io.read32(REG_DBI_RDATA)?)
}

/// `rtl92de_write_dword_dbi` (`rtl8192de/hw.c`).
pub fn write_dword_dbi(io: &impl Io, offset: u16, value: u32, direct: u8) -> Result<(), Error> {
    io.write16(REG_DBI_CTRL, (offset & 0x0ffc) | 0xf000)?;
    io.write32(REG_DBI_WDATA, value)?;
    Ok(io.write8(REG_DBI_FLAG, (1 << 0) | direct)?)
}

/// `rtl92d_phy_enable_anotherphy` (`rtl8192de/rf.c`). Returns whether the
/// other PHY needed enabling (its MAC was off, so the ISO bits were set
/// over DBI). The `during_mac0init_radiob` / `during_mac1init_radioa`
/// flags Linux clears here are transient to the RF-config DMDP flow and
/// are not modelled.
pub async fn enable_anotherphy(io: &impl Io, bmac0: bool) -> Result<bool, Error> {
    use super::power::{MAC0_ON, MAC1_ON, REG_MAC0, REG_MAC1, REG_SYS_ISO_CTRL};
    let direct = if bmac0 { (1 << 3) | (1 << 2) } else { 1 << 3 };
    let (mac_reg, mac_on) = if bmac0 {
        (REG_MAC1, MAC1_ON)
    } else {
        (REG_MAC0, MAC0_ON)
    };
    if io.read8(mac_reg)? & mac_on == 0 {
        let iso = read_dword_dbi(io, REG_SYS_ISO_CTRL, direct).await?;
        write_dword_dbi(
            io,
            REG_SYS_ISO_CTRL,
            iso | (1 << 29) | (1 << 16) | (1 << 17),
            direct,
        )?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// `rtl92d_phy_powerdown_anotherphy` (`rtl8192de/rf.c`).
pub async fn powerdown_anotherphy(io: &impl Io, bmac0: bool) -> Result<(), Error> {
    use super::power::{MAC0_ON, MAC1_ON, REG_MAC0, REG_MAC1};
    let direct = if bmac0 { (1 << 3) | (1 << 2) } else { 1 << 3 };
    let (mac_reg, mac_on) = if bmac0 {
        (REG_MAC1, MAC1_ON)
    } else {
        (REG_MAC0, MAC0_ON)
    };
    if io.read8(mac_reg)? & mac_on == 0 {
        write_dword_dbi(io, RFPGA0_XA_LSSIPARAMETER, 0, direct)?;
    }
    Ok(())
}

// ── PHY_REG_PG factory table (`_rtl92d_phy_config_bb_with_pgheaderfile`) ──

/// `rtlphy->mcs_offset` and `pwrgroup_cnt` after the PHY_REG_PG walk.
/// Unlike the 92C family, the 92D TX-power code reads `mcs_offset`
/// (`rtl92d_phy_rf6052_set_cck_txpower` /
/// `_rtl92d_get_txpower_writeval_by_regulatory`), so this store is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PgStore {
    pub mcs_offset: [[u32; 16]; MAX_PG_GROUP],
    pub pwrgroup_cnt: u8,
}

impl PgStore {
    /// `_rtl92d_phy_config_bb_with_pgheaderfile(BASEBAND_CONFIG_PHY_REG)`
    /// over `(regaddr, bitmask, data)` rows of `tables::PHY_REG_PG`. A
    /// group index past `MAX_PG_GROUP` (Linux would overrun the array)
    /// is refused.
    pub fn from_pg(table: &[u32]) -> Result<Self, Error> {
        let mut out = Self {
            mcs_offset: [[0; 16]; MAX_PG_GROUP],
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
                    .mcs_offset
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

/// `_rtl92d_phy_config_bb_with_headerfile(BASEBAND_CONFIG_AGC_TAB)`: the
/// AGC table as `(regaddr, data)` pairs, `udelay(1)` between rows.
pub async fn agc_table_walk(io: &impl Io, table: &[u32]) -> Result<(), Error> {
    for pair in table.chunks_exact(2) {
        let at = u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?;
        set_bb(io, at, MASKDWORD, pair[1])?;
        io.delay_us(1).await;
    }
    Ok(())
}

// ── PHY/BB/RF config (`rtl92de_hw_init` tail) ──────────────────────────

/// `rtl_addr_delay`: the `0xf9..=0xfe` RF-register addresses are
/// delays, not writes (shared with the 92CE port).
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

/// Which function a BB register access targets. Linux's
/// `rtl92d_phy_set_bb_reg` / `rtl92d_phy_query_bb_reg` redirect
/// through DBI while `during_mac1init_radioa` /
/// `during_mac0init_radiob` is set — i.e. inside
/// `rtl92d_phy_rf6052_config`'s DMDP flow, when one function loads
/// the other PHY's radio table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbTarget {
    /// The local function (no redirect).
    Local,
    /// MAC1 initialising radio A on PHY0 (`during_mac1init_radioa`):
    /// DBI direct `BIT(3)`.
    DbiMac1RadioA,
    /// MAC0 initialising radio B on PHY1 (`during_mac0init_radiob`):
    /// DBI direct `BIT(3) | BIT(2)`.
    DbiMac0RadioB,
}

impl BbTarget {
    const fn dbi_direct(self) -> u8 {
        match self {
            BbTarget::Local => 0,
            BbTarget::DbiMac1RadioA => 1 << 3,
            BbTarget::DbiMac0RadioB => (1 << 3) | (1 << 2),
        }
    }
}

/// `rtl92d_phy_set_bb_reg` for an explicit target (local MMIO, or a
/// DBI write when the target is redirected).
pub async fn set_bb_target(
    io: &impl Io,
    at: u16,
    mask: u32,
    value: u32,
    target: BbTarget,
) -> Result<(), Error> {
    if target == BbTarget::Local {
        return set_bb(io, at, mask, value);
    }
    let data = if mask == MASKDWORD {
        value
    } else {
        let original = read_dword_dbi(io, at, target.dbi_direct()).await?;
        (original & !mask) | (value << shift(mask))
    };
    write_dword_dbi(io, at, data, target.dbi_direct())
}

/// `rtl92d_phy_query_bb_reg` for an explicit target.
pub async fn get_bb_target(
    io: &impl Io,
    at: u16,
    mask: u32,
    target: BbTarget,
) -> Result<u32, Error> {
    let original = if target == BbTarget::Local {
        io.read32(at)?
    } else {
        read_dword_dbi(io, at, target.dbi_direct()).await?
    };
    Ok((original & mask) >> shift(mask))
}

/// `_rtl92d_phy_rf_serial_write` for an explicit target (a
/// `MASKDWORD` BB write, so the target's local/DBI choice is the
/// whole behaviour).
pub fn rf_write_target(
    io: &impl Io,
    path: Path,
    offset: u32,
    data: u32,
    target: BbTarget,
) -> Result<(), Error> {
    let word = ((offset << 20) | (data & 0x000f_ffff)) & 0x0fff_ffff;
    // Synchronous: the DBI write has no settle delay.
    match target {
        BbTarget::Local => set_bb(io, path.regs().rf3wire_offset, MASKDWORD, word),
        _ => write_dword_dbi(io, path.regs().rf3wire_offset, word, target.dbi_direct()),
    }
}

/// `_rtl92d_phy_rf_serial_read` for an explicit target.
pub async fn rf_read_target(
    io: &impl Io,
    path: Path,
    offset: u32,
    target: BbTarget,
) -> Result<u32, Error> {
    let regs = path.regs();
    let tmplong = get_bb_target(io, RFPGA0_XA_HSSIPARAMETER2, MASKDWORD, target).await?;
    let tmplong2 = if path == Path::A {
        tmplong
    } else {
        get_bb_target(io, regs.rfhssi_para2, MASKDWORD, target).await?
    };
    let tmplong2 = (tmplong2 & !BLSSIREADADDRESS) | (offset << 23) | BLSSIREADEDGE;
    set_bb_target(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong & !BLSSIREADEDGE,
        target,
    )
    .await?;
    io.delay_us(10).await;
    set_bb_target(io, regs.rfhssi_para2, MASKDWORD, tmplong2, target).await?;
    io.delay_us(100).await;
    set_bb_target(
        io,
        RFPGA0_XA_HSSIPARAMETER2,
        MASKDWORD,
        tmplong | BLSSIREADEDGE,
        target,
    )
    .await?;
    io.delay_us(10).await;
    let pi = get_bb_target(io, regs.rfhssi_para1, 1 << 8, target).await? != 0;
    get_bb_target(
        io,
        if pi { regs.rf_rbpi } else { regs.rf_rb },
        BLSSIREADBACKDATA,
        target,
    )
    .await
}

/// `rtl92d_phy_set_rf_reg` for an explicit target.
pub async fn set_rf_target(
    io: &impl Io,
    path: Path,
    offset: u32,
    mask: u32,
    value: u32,
    target: BbTarget,
) -> Result<(), Error> {
    if mask == 0 {
        return Ok(());
    }
    let data = if mask == RFREG_OFFSET_MASK {
        value
    } else {
        (rf_read_target(io, path, offset, target).await? & !mask) | (value << shift(mask))
    };
    rf_write_target(io, path, offset, data, target)
}

/// `rtl92d_phy_mac_config` (`rtl8192d/phy.c`): the `MAC_2T` table
/// as byte writes, then `REG_MAX_AGGR_NUM` — `0x0b` on a
/// single-MAC part, `0x07` otherwise (dual-MAC, including the
/// never-selected dual-MAC-single-PHY mode).
pub fn mac_config(io: &impl Io, mode: MacPhyMode) -> Result<(), Error> {
    for pair in super::tables::MAC_2T.chunks_exact(2) {
        let at = u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?;
        io.write8(at, pair[1] as u8)?;
    }
    let aggr = if mode == MacPhyMode::SingleMacSinglePhy {
        0x0b
    } else {
        0x07
    };
    io.write8(REG_MAX_AGGR_NUM, aggr)?;
    Ok(())
}

/// The `rtl92d_phy_bb_config` report: whether the CCK path runs at
/// high power (`RFPGA0_XA_HSSIPARAMETER2` bit `0x200`), and the
/// factory power-group store (absent when autoload failed, so the
/// PG walk was skipped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbReport {
    pub cck_high_power: bool,
    pub pg: Option<PgStore>,
}

/// `rtl92d_phy_bb_config` (`rtl8192d/phy.c`).
pub async fn bb_config(
    io: &impl Io,
    rf_type: RfType,
    interface_index: u8,
    band_5g: bool,
    autoload_fail: bool,
) -> Result<BbReport, Error> {
    let lo = io.read8(super::fw::REG_SYS_FUNC_EN)?;
    let hi = io.read8(super::fw::REG_SYS_FUNC_EN + 1)?;
    let regval = u16::from_le_bytes([lo, hi]) | (1 << 13) | 1 | (1 << 1);
    io.write16(super::fw::REG_SYS_FUNC_EN, regval)?;
    io.write8(REG_AFE_PLL_CTRL, 0x83)?;
    io.write8(REG_AFE_PLL_CTRL + 1, 0xdb)?;
    let rf = io.read8(REG_RF_CTRL)?;
    io.write8(REG_RF_CTRL, rf | RF_EN | RF_RSTB | RF_SDMRSTB)?;
    io.write8(
        super::fw::REG_SYS_FUNC_EN,
        FEN_PPLL | FEN_PCIEA | FEN_DIO_PCIE | FEN_BB_GLB_RSTN | FEN_BBRSTB,
    )?;
    io.write8(super::power::REG_AFE_XTAL_CTRL + 1, 0x80)?;
    // `IS_92D_SINGLEPHY` is the RF type (true exactly for 2T2R),
    // not the MAC/PHY mode: the LED bit is set on 1T parts only.
    if rf_type != RfType::TwoT2R {
        let led = io.read32(REG_LEDCFG0)?;
        io.write32(REG_LEDCFG0, led | (1 << 23))?;
    }
    for pair in super::tables::PHY_REG_2T.chunks_exact(2) {
        let us = addr_delay_us(pair[0]);
        if us != 0 {
            io.delay_us(us).await;
        }
        let at = u16::try_from(pair[0]).map_err(|_| Error::Descriptor)?;
        set_bb(io, at, MASKDWORD, pair[1])?;
        io.delay_us(1).await;
    }
    let pg = if autoload_fail {
        None
    } else {
        Some(PgStore::from_pg(&super::tables::PHY_REG_PG)?)
    };
    let band = if band_5g { Band::On5Ghz } else { Band::On2Ghz };
    agc_table_walk(io, super::agc_table(interface_index, band)).await?;
    let cck_high_power = get_bb(io, RFPGA0_XA_HSSIPARAMETER2, 0x200)? != 0;
    Ok(BbReport { cck_high_power, pg })
}

/// One radio-table load inside `rtl92d_phy_rf6052_config`: the
/// path, the table, and the BB target (local, or DBI-redirected
/// when this function loads the other PHY's radio).
#[derive(Clone, Copy, Debug)]
struct RfLoad {
    path: Path,
    table: &'static [u32],
    target: BbTarget,
}

/// The RF-env save/restore dance plus `rtl_rfreg_delay` walk for
/// one [`RfLoad`] (the per-iteration body of
/// `rtl92d_phy_rf6052_config`).
async fn rf_load(io: &impl Io, load: RfLoad) -> Result<(), Error> {
    let regs = load.path.regs();
    let env_mask = match load.path {
        Path::A => BRFSI_RFENV,
        Path::B => BRFSI_RFENV << 16,
    };
    let saved = get_bb_target(io, regs.rfintfs, env_mask, load.target).await?;
    set_bb_target(io, regs.rfintfe, BRFSI_RFENV << 16, 0x1, load.target).await?;
    io.delay_us(1).await;
    set_bb_target(io, regs.rfintfo, BRFSI_RFENV, 0x1, load.target).await?;
    io.delay_us(1).await;
    set_bb_target(io, regs.rfhssi_para2, B3WIREADDRESSLENGTH, 0x0, load.target).await?;
    io.delay_us(1).await;
    set_bb_target(io, regs.rfhssi_para2, B3WIREDATALENGTH, 0x0, load.target).await?;
    io.delay_us(1).await;
    for pair in load.table.chunks_exact(2) {
        if (0xf9..=0xfe).contains(&pair[0]) {
            io.delay_us(addr_delay_us(pair[0])).await;
        } else {
            set_rf_target(
                io,
                load.path,
                pair[0],
                RFREG_OFFSET_MASK,
                pair[1],
                load.target,
            )
            .await?;
            io.delay_us(1).await;
        }
    }
    set_bb_target(io, regs.rfintfs, env_mask, saved, load.target).await?;
    Ok(())
}

/// `rtl92d_phy_rf6052_config` (`rtl8192de/rf.c`), with the DMDP
/// branches: on a dual-MAC-dual-PHY part, MAC0 starting on 2.4 GHz
/// (interface 0) loads radio A locally, then radio B over DBI onto
/// PHY1 — unless the other MAC is already on, in which case both
/// tables are already loaded and this is a no-op; MAC1 starting on
/// 5 GHz (interface 1) mirrors it, loading radio A over DBI onto
/// PHY0 first, then radio B locally. Interface 1 on 2.4 GHz loads
/// only radio B on both paths (`true_bpath`). The other PHY is
/// powered down again afterwards when it was just enabled for the
/// load. `internal_pa_5g` is the EFUSE per-path internal-PA flag
/// (`rtl92d_phy_config_rf_with_headerfile` table selection).
pub async fn rf_config(
    io: &impl Io,
    mode: MacPhyMode,
    interface_index: u8,
    band_5g: bool,
    rf_type: RfType,
    internal_pa_5g: [bool; 2],
) -> Result<(), Error> {
    let (radioa, radiob) = super::radio_tables(internal_pa_5g);
    let mut loads = [RfLoad {
        path: Path::A,
        table: radioa,
        target: BbTarget::Local,
    }; 2];
    let count: usize;
    let mut powerdown: Option<bool> = None;
    if mode == MacPhyMode::DualMacDualPhy && !band_5g && interface_index == 0 {
        if enable_anotherphy(io, true).await? {
            loads[0] = RfLoad {
                path: Path::A,
                table: radioa,
                target: BbTarget::Local,
            };
            loads[1] = RfLoad {
                path: Path::A,
                table: radiob,
                target: BbTarget::DbiMac0RadioB,
            };
            count = 2;
            powerdown = Some(true);
        } else {
            return Ok(());
        }
    } else if mode == MacPhyMode::DualMacDualPhy && band_5g && interface_index == 1 {
        if enable_anotherphy(io, false).await? {
            loads[0] = RfLoad {
                path: Path::A,
                table: radioa,
                target: BbTarget::DbiMac1RadioA,
            };
            loads[1] = RfLoad {
                path: Path::A,
                table: radiob,
                target: BbTarget::Local,
            };
            count = 2;
            powerdown = Some(false);
        } else {
            return Ok(());
        }
    } else if mode == MacPhyMode::DualMacDualPhy && interface_index == 1 {
        for (i, &path) in rf_type.rf_paths().iter().enumerate() {
            loads[i] = RfLoad {
                path,
                table: radiob,
                target: BbTarget::Local,
            };
        }
        count = rf_type.rf_paths().len();
    } else {
        for (i, &path) in rf_type.rf_paths().iter().enumerate() {
            loads[i] = RfLoad {
                path,
                table: if path == Path::A { radioa } else { radiob },
                target: BbTarget::Local,
            };
        }
        count = rf_type.rf_paths().len();
    }
    for load in loads[..count].iter() {
        rf_load(io, *load).await?;
    }
    if let Some(bmac0) = powerdown {
        powerdown_anotherphy(io, bmac0).await?;
    }
    Ok(())
}

/// `rtl92d_phy_get_hw_reg_originalvalue` (`rtl8192d/phy.c`): the
/// default initial gains, the frame-sync byte, and the
/// frame-sync C34 dword.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginalValues {
    pub initialgain: [u8; 4],
    pub framesync: u8,
    pub framesync_c34: u32,
}

pub fn original_values(io: &impl Io) -> Result<OriginalValues, Error> {
    Ok(OriginalValues {
        initialgain: [
            get_bb(io, ROFDM0_XAAGCCORE1, MASKBYTE0)? as u8,
            get_bb(io, ROFDM0_XBAGCCORE1, MASKBYTE0)? as u8,
            get_bb(io, ROFDM0_XCAGCCORE1, MASKBYTE0)? as u8,
            get_bb(io, ROFDM0_XDAGCCORE1, MASKBYTE0)? as u8,
        ],
        framesync: get_bb(io, ROFDM0_RXDETECTOR3, MASKBYTE0)? as u8,
        framesync_c34: get_bb(io, ROFDM0_RXDETECTOR2, MASKDWORD)?,
    })
}
