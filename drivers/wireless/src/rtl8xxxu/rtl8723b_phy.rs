//! RTL8723BU antenna selection, MAC/BB/AGC/RF table application with the
//! post-RF PHY LCK, RF switch control, cold TX buffer boundary, PBP, auto
//! LLT, gen2 USB quirks, TX report timer, HISR/HIMR and gen2 TX power.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/8723b.c::{rtl8723bu_phy_init_antenna_selection,
//!   rtl8723bu_init_phy_bb, rtl8723bu_init_phy_rf, rtl8723b_set_tx_power}`
//! - `rtl8xxxu/core.c::{rtl8xxxu_init_device (antenna selection → HIMR),
//!   rtl8xxxu_init_mac, rtl8xxxu_init_phy_regs, rtl8xxxu_init_phy_rf,
//!   rtl8xxxu_init_rf_regs, rtl8xxxu_write_rfreg, rtl8xxxu_auto_llt_table,
//!   rtl8xxxu_gen2_usb_quirks, rtl8xxxu_gen2_channel_to_group}`
//! - `rtl8xxxu/8723a.c::rtl8723a_set_crystal_cap`
//!
//! The RF writer is the plain `rtl8xxxu_write_rfreg` (the FPGA0_POWER_SAVE
//! bracket is RTL8192E-only), so `rtl8192e_phy`'s writer is not reused.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::phy::Reg32Val;
use super::phy_tables::RfRow;
use super::rtl8192e_phy::{channel_group, XAB_RF_SW_CTRL};
use super::rtl8723b_init::{Factory, PWR_DATA_EEPRPAD_RFE_CTRL_EN, TX_TOTAL_PAGES};
use super::rtl8723b_tables::{AGC_TABLE, MAC_INIT_TABLE, PHY_INIT_TABLE, RADIO_A_INIT_TABLE};

const REG_SYS_FUNC: u16 = 0x0002;
const SYS_FUNC_BBRSTB: u16 = 1 << 0;
const SYS_FUNC_BB_GLB_RSTN: u16 = 1 << 1;
const SYS_FUNC_DIO_RF: u16 = 1 << 13;
const REG_RF_CTRL: u16 = 0x001f;
/// `RF_ENABLE | RF_RSTB | RF_SDMRSTB`.
const RF_CTRL_ON: u8 = 0x07;
const REG_AFE_XTAL_CTRL: u16 = 0x0024;
const REG_MAC_PHY_CTRL: u16 = 0x002c;
const XTAL_MASK: u32 = 0x00ff_f000;
const REG_PWR_DATA: u16 = 0x0038;
const REG_GPIO_MUXCFG: u16 = 0x0040;
const REG_LEDCFG0: u16 = 0x004c;
const REG_PAD_CTRL1: u16 = 0x0064;
const REG_PBP: u16 = 0x0104;
/// `PBP_PAGE_SIZE_256` for RX (`<< 0`) and TX (`<< 4`).
const PBP_256: u8 = 0x02 | 0x02 << 4;
const REG_TRXFF_BNDY: u16 = 0x0114;
const REG_HIMR: u16 = 0x0120;
const REG_HISR: u16 = 0x0124;
const REG_TDECTRL: u16 = 0x0208;
const REG_TXDMA_OFFSET_CHK: u16 = 0x020c;
const TXDMA_OFFSET_DROP_DATA_EN: u32 = 1 << 9;
const REG_AUTO_LLT: u16 = 0x0224;
const AUTO_LLT_INIT_LLT: u32 = 1 << 16;
const REG_TXPKTBUF_BCNQ_BDNY: u16 = 0x0424;
const REG_TXPKTBUF_MGQ_BDNY: u16 = 0x0425;
const REG_TXPKTBUF_WMAC_LBK_BF_HD: u16 = 0x045d;
const REG_TX_REPORT_CTRL: u16 = 0x04ec;
const TX_REPORT_CTRL_TIMER_ENABLE: u8 = 1 << 1;
const REG_TX_REPORT_TIME: u16 = 0x04f0;
/// Undocumented "tmp ps" byte `rtl8xxxu_init_device` masks with `0xf8`.
const REG_TMP_PS: u16 = 0x00a3;
const REG_RX_DRVINFO_SZ: u16 = 0x060f;
const REG_FPGA0_XA_HSSI_PARM2: u16 = 0x0824;
const FPGA0_HSSI_3WIRE_DATA_LEN: u32 = 0x800;
const FPGA0_HSSI_3WIRE_ADDR_LEN: u32 = 0x400;
const REG_FPGA0_XA_LSSI_PARM: u16 = 0x0840;
const REG_FPGA0_XA_RF_INT_OE: u16 = 0x0860;
const REG_FPGA0_XAB_RF_SW_CTRL: u16 = 0x0870;
const FPGA0_RF_RFENV: u16 = 1 << 4;
const REG_RFE_CTRL_ANTA_SRC: u16 = 0x0930;
const REG_RFE_BUFFER: u16 = 0x0944;
const REG_S0S1_PATH_SWITCH: u16 = 0x0948;
/// `rtl8xxxu_init_device`: `REG_FPGA0_XA_RF_INT_OE = 0x66f60210` (not
/// skipped for RTL8723B).
pub const XA_RF_INT_OE: u32 = 0x66f6_0210;
/// `rtl8723bu_init_phy_rf` PHY LCK writes to RF_A `0xb0`.
pub const LCK_RF_REG: u8 = 0xb0;
pub const LCK_START: u32 = 0xdfbe0;
pub const LCK_MODE_AG: u32 = 0x8c01;
pub const LCK_END: u32 = 0xdffe0;
const RF_MODE_AG: u8 = 0x18;

async fn rmw32<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = o.read32(reg).await?;
    o.write32(reg, (value & !clear) | set).await
}

/// `rtl8xxxu_write_rfreg` on RF_A (8723B is 1T1R).
pub(super) async fn write_rfreg<I: ControlIo>(
    o: &Owner<I>,
    reg: u8,
    data: u32,
) -> Result<(), Error> {
    o.write32(
        REG_FPGA0_XA_LSSI_PARM,
        (reg as u32) << 20 | (data & 0x000f_ffff),
    )
    .await?;
    o.delay_us(1).await;
    Ok(())
}

/// `rtl8723bu_phy_init_antenna_selection`.
pub(super) async fn init_antenna_selection<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    rmw32(o, REG_PAD_CTRL1, (1 << 20) | (1 << 24), 0).await?;
    rmw32(o, REG_GPIO_MUXCFG, 1 << 4, 0).await?;
    rmw32(o, REG_GPIO_MUXCFG, 0, 1 << 3).await?;
    rmw32(o, REG_LEDCFG0, 0, 1 << 24).await?;
    rmw32(o, REG_LEDCFG0, 1 << 23, 0).await?;
    rmw32(o, REG_RFE_BUFFER, 0, (1 << 0) | (1 << 1)).await?;
    rmw32(o, REG_RFE_CTRL_ANTA_SRC, 0xff, 0x77).await?;
    rmw32(o, REG_PWR_DATA, 0, PWR_DATA_EEPRPAD_RFE_CTRL_EN).await
}

/// `rtl8xxxu_init_phy_regs`.
async fn phy_regs<I: ControlIo>(o: &Owner<I>, table: &[Reg32Val]) -> Result<(), Error> {
    for row in table {
        if row.reg == 0xffff && row.val == u32::MAX {
            break;
        }
        o.write32(row.reg, row.val).await?;
        o.delay_us(1).await;
    }
    Ok(())
}

/// `rtl8xxxu_init_phy_bb` with the `rtl8723bu_init_phy_bb` hook (1T1R: no
/// 1T2R patch), then `rtl8723a_set_crystal_cap`. The CFO state starts
/// zeroed, so a zero cap is not written (as Linux). No `AFE_XTAL_CTRL`
/// 32-bit write (RTL8192E only).
async fn init_phy_bb<I: ControlIo>(o: &Owner<I>, factory: &Factory) -> Result<(), Error> {
    let value = o.read16(REG_SYS_FUNC).await?;
    o.write16(
        REG_SYS_FUNC,
        value | SYS_FUNC_BB_GLB_RSTN | SYS_FUNC_BBRSTB | SYS_FUNC_DIO_RF,
    )
    .await?;
    o.write32(REG_S0S1_PATH_SWITCH, 0).await?;
    o.write8(REG_RF_CTRL, RF_CTRL_ON).await?;
    o.write8(REG_SYS_FUNC, 0xe3).await?;
    o.write8(REG_AFE_XTAL_CTRL + 1, 0x80).await?;
    phy_regs(o, PHY_INIT_TABLE).await?;
    phy_regs(o, AGC_TABLE).await?;
    let cap = factory.crystal_cap as u32;
    if cap != 0 {
        rmw32(o, REG_MAC_PHY_CTRL, XTAL_MASK, cap << 18 | cap << 12).await?;
    }
    Ok(())
}

/// `rtl8xxxu_init_phy_rf` + `rtl8xxxu_init_rf_regs` for RF_A, then the
/// `rtl8723bu_init_phy_rf` PHY LCK (`0xb0`, `MODE_AG = 0x8c01`, 200 ms,
/// `0xb0`).
async fn init_phy_rf<I: ControlIo>(o: &Owner<I>, table: &[RfRow]) -> Result<(), Error> {
    let env = o.read16(REG_FPGA0_XAB_RF_SW_CTRL).await? & FPGA0_RF_RFENV;
    rmw32(o, REG_FPGA0_XA_RF_INT_OE, 0, 1 << 20).await?;
    o.delay_us(1).await;
    rmw32(o, REG_FPGA0_XA_RF_INT_OE, 0, 1 << 4).await?;
    o.delay_us(1).await;
    rmw32(o, REG_FPGA0_XA_HSSI_PARM2, FPGA0_HSSI_3WIRE_ADDR_LEN, 0).await?;
    o.delay_us(1).await;
    rmw32(o, REG_FPGA0_XA_HSSI_PARM2, FPGA0_HSSI_3WIRE_DATA_LEN, 0).await?;
    o.delay_us(1).await;
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
            o.delay_us(delay).await;
            continue;
        }
        write_rfreg(o, row.reg, row.val).await?;
        o.delay_us(1).await;
    }
    let value = o.read16(REG_FPGA0_XAB_RF_SW_CTRL).await?;
    o.write16(REG_FPGA0_XAB_RF_SW_CTRL, (value & !FPGA0_RF_RFENV) | env)
        .await?;
    write_rfreg(o, LCK_RF_REG, LCK_START).await?;
    write_rfreg(o, RF_MODE_AG, LCK_MODE_AG).await?;
    o.delay_us(200_000).await;
    write_rfreg(o, LCK_RF_REG, LCK_END).await
}

/// `rtl8xxxu_init_device` from `phy_init_antenna_selection` through the
/// HIMR write for RTL8723B: antenna selection, MAC table (no
/// `REG_MAX_AGGR_NUM`), BB/AGC + crystal cap, RF A + PHY LCK, RF switch
/// control with PAPE, `XA_RF_INT_OE = 0x66f60210`, the cold TX buffer
/// boundary `0xf8`, PBP 256/256, auto LLT (checked), gen2 USB quirk, the
/// `has_tx_report` timer setup, `RX_DRVINFO_SZ = 4` and HISR/HIMR all-ones.
/// `REG_FPGA0_TX_INFO = 3` is skipped for RTL8723B as in Linux.
pub(super) async fn mac_bb_rf<I: ControlIo>(o: &Owner<I>, factory: &Factory) -> Result<(), Error> {
    init_antenna_selection(o).await?;
    for row in MAC_INIT_TABLE {
        if row.reg == 0xffff && row.val == 0xff {
            break;
        }
        o.write8(row.reg, row.val).await?;
    }
    init_phy_bb(o, factory).await?;
    init_phy_rf(o, RADIO_A_INIT_TABLE).await?;
    o.write32(REG_FPGA0_XAB_RF_SW_CTRL, XAB_RF_SW_CTRL).await?;
    o.write32(REG_FPGA0_XA_RF_INT_OE, XA_RF_INT_OE).await?;
    let boundary = TX_TOTAL_PAGES + 1;
    for reg in [
        REG_TXPKTBUF_BCNQ_BDNY,
        REG_TXPKTBUF_MGQ_BDNY,
        REG_TXPKTBUF_WMAC_LBK_BF_HD,
        REG_TRXFF_BNDY,
        REG_TDECTRL + 1,
    ] {
        o.write8(reg, boundary).await?;
    }
    o.write8(REG_PBP, PBP_256).await?;
    // rtl8xxxu_auto_llt_table
    rmw32(o, REG_AUTO_LLT, 0, AUTO_LLT_INIT_LLT).await?;
    let mut done = false;
    for _ in 0..500 {
        if o.read32(REG_AUTO_LLT).await? & AUTO_LLT_INIT_LLT == 0 {
            done = true;
            break;
        }
        o.delay_us(2).await;
    }
    if !done {
        return Err(Error::LltTimeout);
    }
    rmw32(o, REG_TXDMA_OFFSET_CHK, 0, TXDMA_OFFSET_DROP_DATA_EN).await?;
    // has_tx_report (RTL8723B: no bit 0, which is RTL8188E-only).
    let value = o.read8(REG_TX_REPORT_CTRL).await?;
    o.write8(REG_TX_REPORT_CTRL, value | TX_REPORT_CTRL_TIMER_ENABLE)
        .await?;
    o.write8(REG_TX_REPORT_CTRL + 1, 0x02).await?;
    o.write16(REG_TX_REPORT_TIME, 0xcdf0).await?;
    let value = o.read8(REG_TMP_PS).await?;
    o.write8(REG_TMP_PS, value & 0xf8).await?;
    o.write8(REG_RX_DRVINFO_SZ, 4).await?;
    o.write32(REG_HISR, u32::MAX).await?;
    o.write32(REG_HIMR, u32::MAX).await
}

fn splat(value: u8) -> u32 {
    u32::from_le_bytes([value; 4])
}

/// TX power words from `rtl8723b_set_tx_power`: `(cck, ofdm, mcs)` from the
/// path-B EFUSE indices (`cck_tx_power_index_B`, `ht40_1s_tx_power_index_B`)
/// and diff index 0's `.b` member. Arithmetic wraps as `u8 += s8`.
pub fn tx_power(factory: &Factory, channel: u8, ht40: bool) -> (u8, u32, u32) {
    let group = channel_group(channel);
    let b = &factory.power[1];
    let ofdm = b.ht40[group].wrapping_add_signed(b.ofdm_diff[0]);
    let diff = if ht40 { b.ht40_diff[0] } else { b.ht20_diff[0] };
    let mcs = b.ht40[group].wrapping_add_signed(diff);
    (b.cck[group], splat(ofdm), splat(mcs))
}

/// Apply `rtl8723b_set_tx_power` for a 2.4 GHz channel (path A registers).
pub(super) async fn set_tx_power<I: ControlIo>(
    o: &Owner<I>,
    factory: &Factory,
    channel: u8,
    ht40: bool,
) -> Result<(), Error> {
    let (cck, ofdm, mcs) = tx_power(factory, channel, ht40);
    let cck = cck as u32;
    let value = o.read32(0x0e08).await?;
    o.write32(0x0e08, (value & 0xffff_00ff) | cck << 8).await?;
    let value = o.read32(0x086c).await?;
    o.write32(0x086c, (value & 0xff) | cck << 8 | cck << 16 | cck << 24)
        .await?;
    o.write32(0x0e00, ofdm).await?;
    o.write32(0x0e04, ofdm).await?;
    o.write32(0x0e10, mcs).await?;
    o.write32(0x0e14, mcs).await
}
