//! RTL8192EU MAC/BB/RF table application, 2T2R RF configuration, the
//! cold FIFO/LLT tail of `rtl8xxxu_init_device` and EFUSE TX power.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/core.c::{rtl8xxxu_init_mac, rtl8xxxu_init_phy_regs,
//!   rtl8xxxu_init_phy_bb, rtl8xxxu_init_rf_regs, rtl8xxxu_init_phy_rf,
//!   rtl8xxxu_write_rfreg, rtl8xxxu_auto_llt_table,
//!   rtl8xxxu_gen2_usb_quirks, rtl8xxxu_gen2_channel_to_group,
//!   rtl8xxxu_init_device}`
//! - `rtl8xxxu/8192e.c::{rtl8192eu_init_phy_bb, rtl8192eu_init_phy_rf,
//!   rtl8192e_set_tx_power}`
//! - `rtl8xxxu/8723a.c::rtl8723a_set_crystal_cap` (the 8192EU fops hook)
//!
//! `priv->hi_pa` is never set for RTL8192EU in Linux, so the standard AGC
//! table is the only one applied.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::rtl8192e_init::Factory;
use super::rtl8192e_tables::{
    AGC_STD_TABLE, MAC_INIT_TABLE, PHY_INIT_TABLE, RADIO_A_INIT_TABLE, RADIO_B_INIT_TABLE,
};

const REG_SYS_FUNC: u16 = 0x0002;
const SYS_FUNC_BBRSTB: u16 = 1 << 0;
const SYS_FUNC_BB_GLB_RSTN: u16 = 1 << 1;
const SYS_FUNC_USBA: u16 = 1 << 2;
const SYS_FUNC_USBD: u16 = 1 << 4;
const SYS_FUNC_DIO_RF: u16 = 1 << 13;
const REG_RF_CTRL: u16 = 0x001f;
/// `RF_ENABLE | RF_RSTB | RF_SDMRSTB`.
const RF_CTRL_ON: u8 = 0x07;
const REG_AFE_XTAL_CTRL: u16 = 0x0024;
const REG_MAC_PHY_CTRL: u16 = 0x002c;
/// `8723a.c` XTAL1 = GENMASK(23, 18), XTAL0 = GENMASK(17, 12).
const XTAL_MASK: u32 = 0x00ff_f000;
const REG_RX_DRVINFO_SZ: u16 = 0x060f;
const REG_HIMR0: u16 = 0x00b0;
const REG_HIMR1: u16 = 0x00b8;
const REG_TDECTRL: u16 = 0x0208;
const REG_TXDMA_OFFSET_CHK: u16 = 0x020c;
const TXDMA_OFFSET_DROP_DATA_EN: u32 = 1 << 9;
const REG_AUTO_LLT: u16 = 0x0224;
const AUTO_LLT_INIT_LLT: u32 = 1 << 16;
const REG_TXPKTBUF_BCNQ_BDNY: u16 = 0x0424;
const REG_TXPKTBUF_MGQ_BDNY: u16 = 0x0425;
const REG_TXPKTBUF_WMAC_LBK_BF_HD: u16 = 0x045d;
const REG_TRXFF_BNDY: u16 = 0x0114;
const REG_FPGA0_TX_INFO: u16 = 0x0804;
const REG_FPGA0_POWER_SAVE: u16 = 0x0818;
const REG_FPGA0_XA_HSSI_PARM2: u16 = 0x0824;
const REG_FPGA0_XB_HSSI_PARM2: u16 = 0x082c;
const FPGA0_HSSI_3WIRE_DATA_LEN: u32 = 0x800;
const FPGA0_HSSI_3WIRE_ADDR_LEN: u32 = 0x400;
const REG_FPGA0_XA_LSSI_PARM: u16 = 0x0840;
const REG_FPGA0_XB_LSSI_PARM: u16 = 0x0844;
const REG_FPGA0_XA_RF_INT_OE: u16 = 0x0860;
const REG_FPGA0_XB_RF_INT_OE: u16 = 0x0864;
const REG_FPGA0_XA_RF_SW_CTRL: u16 = 0x0870;
const REG_FPGA0_XB_RF_SW_CTRL: u16 = 0x0872;
const FPGA0_RF_RFENV: u16 = 1 << 4;
const REG_FPGA1_TX_INFO: u16 = 0x090c;
const REG_CCK0_AFE_SETTING: u16 = 0x0a04;
const REG_OFDM0_TRX_PATH_ENABLE: u16 = 0x0c04;
const REG_OFDM0_AGC_PARM1: u16 = 0x0c70;
const REG_TX_CCK_RFON: u16 = 0x0e74;
const REG_TX_CCK_BBON: u16 = 0x0e78;
const REG_TX_OFDM_RFON: u16 = 0x0e7c;
const REG_TX_OFDM_BBON: u16 = 0x0e80;
const REG_TX_TO_TX: u16 = 0x0e88;

/// `REG_FPGA0_XAB_RF_SW_CTRL` value from `rtl8xxxu_init_device`:
/// TRSW/TRSWB/ANTSW/ANTSWB, BD control of ANTSW/ANTSWB, and PAPE (the
/// 8192EU never sets `no_pape`).
pub const XAB_RF_SW_CTRL: u32 = (1 << 5)
    | (1 << 6)
    | (1 << 8)
    | (1 << 9)
    | (((1 << 8) | (1 << 9)) << 16)
    | (1 << 10)
    | ((1 << 10) << 16);

/// `rtl8xxxu_gen2_channel_to_group`.
pub fn channel_group(channel: u8) -> usize {
    match channel {
        0..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        _ => 4,
    }
}

fn splat(value: u8) -> u32 {
    u32::from_le_bytes([value; 4])
}

/// Per-path TX power words from `rtl8192e_set_tx_power`: `(cck, ofdm, mcs)`.
/// Path A uses diff index 0 and path B index 1, exactly as Linux's shared
/// `tx_idx` post-increment selects them. Arithmetic wraps as `u8 += s8`.
pub fn tx_power(factory: &Factory, channel: u8, ht40: bool) -> [(u8, u32, u32); 2] {
    let group = channel_group(channel);
    let mut out = [(0, 0, 0); 2];
    for (idx, slot) in out.iter_mut().enumerate() {
        let power = &factory.power[idx];
        let cck = power.cck[group];
        let ofdm = power.ht40[group].wrapping_add_signed(power.ofdm_diff[idx]);
        let diff = if ht40 {
            power.ht40_diff[idx]
        } else {
            power.ht20_diff[idx]
        };
        let mcs = power.ht40[group].wrapping_add_signed(diff);
        *slot = (cck, splat(ofdm), splat(mcs));
    }
    out
}

/// Apply `rtl8192e_set_tx_power` for a 2.4 GHz channel. Path B is written only
/// for the two-TX-path bonding.
pub(super) async fn set_tx_power<I: ControlIo>(
    owner: &Owner<I>,
    factory: &Factory,
    channel: u8,
    ht40: bool,
) -> Result<(), Error> {
    let [(cck_a, ofdm_a, mcs_a), (cck_b, ofdm_b, mcs_b)] = tx_power(factory, channel, ht40);
    let cck_a = cck_a as u32;
    let value = owner.read32(0x0e08).await?;
    owner
        .write32(0x0e08, (value & 0xffff_00ff) | cck_a << 8)
        .await?;
    let value = owner.read32(0x086c).await?;
    owner
        .write32(
            0x086c,
            (value & 0xff) | cck_a << 8 | cck_a << 16 | cck_a << 24,
        )
        .await?;
    owner.write32(0x0e00, ofdm_a).await?;
    owner.write32(0x0e04, ofdm_a).await?;
    for reg in [0x0e10, 0x0e14, 0x0e18, 0x0e1c] {
        owner.write32(reg, mcs_a).await?;
    }
    if factory.identity.tx_paths > 1 {
        let cck_b = cck_b as u32;
        let value = owner.read32(0x0838).await?;
        owner
            .write32(
                0x0838,
                (value & 0xff) | cck_b << 8 | cck_b << 16 | cck_b << 24,
            )
            .await?;
        let value = owner.read32(0x086c).await?;
        owner.write32(0x086c, (value & 0xffff_ff00) | cck_b).await?;
        owner.write32(0x0830, ofdm_b).await?;
        owner.write32(0x0834, ofdm_b).await?;
        for reg in [0x083c, 0x0848, 0x084c, 0x0868] {
            owner.write32(reg, mcs_b).await?;
        }
    }
    Ok(())
}

/// `rtl8xxxu_write_rfreg` with the RTL8192E power-save bracket.
pub(super) async fn write_rfreg<I: ControlIo>(
    owner: &Owner<I>,
    path_b: bool,
    reg: u8,
    data: u32,
) -> Result<(), Error> {
    let lssi = if path_b {
        REG_FPGA0_XB_LSSI_PARM
    } else {
        REG_FPGA0_XA_LSSI_PARM
    };
    let value = owner.read32(REG_FPGA0_POWER_SAVE).await?;
    owner
        .write32(REG_FPGA0_POWER_SAVE, value & !0x20000)
        .await?;
    owner
        .write32(lssi, (reg as u32) << 20 | (data & 0x000f_ffff))
        .await?;
    owner.delay_us(1).await;
    let value = owner.read32(REG_FPGA0_POWER_SAVE).await?;
    owner.write32(REG_FPGA0_POWER_SAVE, value | 0x20000).await
}

async fn rmw32<I: ControlIo>(
    owner: &Owner<I>,
    reg: u16,
    clear: u32,
    set: u32,
) -> Result<(), Error> {
    let value = owner.read32(reg).await?;
    owner.write32(reg, (value & !clear) | set).await
}

/// `rtl8xxxu_init_phy_regs`.
async fn phy_regs<I: ControlIo>(
    owner: &Owner<I>,
    table: &[super::phy::Reg32Val],
) -> Result<(), Error> {
    for row in table {
        if row.reg == 0xffff && row.val == u32::MAX {
            break;
        }
        owner.write32(row.reg, row.val).await?;
        owner.delay_us(1).await;
    }
    Ok(())
}

/// `rtl8xxxu_init_phy_bb` with the `rtl8192eu_init_phy_bb` hook.
async fn init_phy_bb<I: ControlIo>(owner: &Owner<I>, factory: &Factory) -> Result<(), Error> {
    let value = owner.read16(REG_SYS_FUNC).await?;
    owner
        .write16(
            REG_SYS_FUNC,
            value | SYS_FUNC_BB_GLB_RSTN | SYS_FUNC_BBRSTB | SYS_FUNC_DIO_RF,
        )
        .await?;
    owner.write8(REG_RF_CTRL, RF_CTRL_ON).await?;
    let value = owner.read16(REG_SYS_FUNC).await?;
    owner
        .write16(
            REG_SYS_FUNC,
            value
                | SYS_FUNC_USBA
                | SYS_FUNC_USBD
                | SYS_FUNC_DIO_RF
                | SYS_FUNC_BB_GLB_RSTN
                | SYS_FUNC_BBRSTB,
        )
        .await?;
    owner.write8(REG_RF_CTRL, RF_CTRL_ON).await?;
    phy_regs(owner, PHY_INIT_TABLE).await?;
    phy_regs(owner, AGC_STD_TABLE).await?;
    if factory.identity.tx_paths == 1 {
        // 1T2R boards (RTL8191EU) transmit on path B.
        rmw32(owner, REG_FPGA0_TX_INFO, 3, 2).await?;
        rmw32(owner, REG_FPGA1_TX_INFO, 0x30_0033, 0x20_0022).await?;
        let value = owner.read32(REG_CCK0_AFE_SETTING).await?;
        let value = (value & !0x0f00_0000 & 0x00ff_ffff) | 0x4000_0000 | (1 << 26);
        owner.write32(REG_CCK0_AFE_SETTING, value).await?;
        // OFDM_RF_PATH_RX_A | RX_B | TX_B
        rmw32(owner, REG_OFDM0_TRX_PATH_ENABLE, 0xff, 0x23).await?;
        rmw32(owner, REG_OFDM0_AGC_PARM1, 0x30, 0x10).await?;
        for reg in [
            REG_TX_CCK_RFON,
            REG_TX_CCK_BBON,
            REG_TX_OFDM_RFON,
            REG_TX_OFDM_BBON,
            REG_TX_TO_TX,
        ] {
            rmw32(owner, reg, (1 << 27) | (1 << 26), 1 << 27).await?;
        }
    }
    // rtl8723a_set_crystal_cap: skipped when equal to the zeroed CFO state.
    let cap = factory.crystal_cap as u32;
    if cap != 0 {
        rmw32(owner, REG_MAC_PHY_CTRL, XTAL_MASK, cap << 18 | cap << 12).await?;
    }
    owner.write32(REG_AFE_XTAL_CTRL, 0x000f_81fb).await
}

/// `rtl8xxxu_init_phy_rf` + `rtl8xxxu_init_rf_regs` for one path.
async fn init_phy_rf<I: ControlIo>(
    owner: &Owner<I>,
    table: &[super::phy_tables::RfRow],
    path_b: bool,
) -> Result<(), Error> {
    let (sw_ctrl, int_oe, hssi) = if path_b {
        (
            REG_FPGA0_XB_RF_SW_CTRL,
            REG_FPGA0_XB_RF_INT_OE,
            REG_FPGA0_XB_HSSI_PARM2,
        )
    } else {
        (
            REG_FPGA0_XA_RF_SW_CTRL,
            REG_FPGA0_XA_RF_INT_OE,
            REG_FPGA0_XA_HSSI_PARM2,
        )
    };
    let env = owner.read16(sw_ctrl).await? & FPGA0_RF_RFENV;
    rmw32(owner, int_oe, 0, 1 << 20).await?;
    owner.delay_us(1).await;
    rmw32(owner, int_oe, 0, 1 << 4).await?;
    owner.delay_us(1).await;
    rmw32(owner, hssi, FPGA0_HSSI_3WIRE_ADDR_LEN, 0).await?;
    owner.delay_us(1).await;
    rmw32(owner, hssi, FPGA0_HSSI_3WIRE_DATA_LEN, 0).await?;
    owner.delay_us(1).await;
    for row in table {
        if row.reg == 0xff && row.val == u32::MAX {
            break;
        }
        let delay = match row.reg {
            0xfe => 50_000,
            0xfd => 5_000,
            0xfc => 1_000,
            0xfb => 50,
            0xfa => 5,
            0xf9 => 1,
            _ => 0,
        };
        if delay != 0 {
            owner.delay_us(delay).await;
            continue;
        }
        write_rfreg(owner, path_b, row.reg, row.val).await?;
        owner.delay_us(1).await;
    }
    let value = owner.read16(sw_ctrl).await?;
    owner
        .write16(sw_ctrl, (value & !FPGA0_RF_RFENV) | env)
        .await
}

/// `rtl8xxxu_init_device` from `init_mac` through the HIMR clear: MAC table
/// (no `REG_MAX_AGGR_NUM` write for 8192E), BB/AGC, both RF paths, RF switch
/// control, the cold TX buffer boundary, auto LLT, gen2 USB quirks and
/// `REG_RX_DRVINFO_SZ`. The 8192E skips `REG_PBP`, `REG_FPGA0_TX_INFO = 3` and
/// `REG_FPGA0_XA_RF_INT_OE = 0x66f60210`, and has no TX report setup.
pub(super) async fn mac_bb_rf<I: ControlIo>(
    owner: &Owner<I>,
    factory: &Factory,
) -> Result<(), Error> {
    for row in MAC_INIT_TABLE {
        if row.reg == 0xffff && row.val == 0xff {
            break;
        }
        owner.write8(row.reg, row.val).await?;
    }
    init_phy_bb(owner, factory).await?;
    init_phy_rf(owner, RADIO_A_INIT_TABLE, false).await?;
    init_phy_rf(owner, RADIO_B_INIT_TABLE, true).await?;
    owner
        .write32(REG_FPGA0_XA_RF_SW_CTRL, XAB_RF_SW_CTRL)
        .await?;
    let boundary = super::rtl8192e::TX_TOTAL_PAGES + 1;
    for reg in [
        REG_TXPKTBUF_BCNQ_BDNY,
        REG_TXPKTBUF_MGQ_BDNY,
        REG_TXPKTBUF_WMAC_LBK_BF_HD,
        REG_TRXFF_BNDY,
        REG_TDECTRL + 1,
    ] {
        owner.write8(reg, boundary).await?;
    }
    // rtl8xxxu_auto_llt_table
    rmw32(owner, REG_AUTO_LLT, 0, AUTO_LLT_INIT_LLT).await?;
    let mut done = false;
    for _ in 0..500 {
        if owner.read32(REG_AUTO_LLT).await? & AUTO_LLT_INIT_LLT == 0 {
            done = true;
            break;
        }
        owner.delay_us(2).await;
    }
    if !done {
        return Err(Error::LltTimeout);
    }
    rmw32(owner, REG_TXDMA_OFFSET_CHK, 0, TXDMA_OFFSET_DROP_DATA_EN).await?;
    owner.write8(REG_RX_DRVINFO_SZ, 4).await?;
    owner.write32(REG_HIMR0, 0).await?;
    owner.write32(REG_HIMR1, 0).await
}
