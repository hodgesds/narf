//! RTL8723BU RF enable (with its BT-coexistence handover) and card power-off.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/8723b.c::{rtl8723b_enable_rf, rtl8723bu_write_btreg,
//!   rtl8723bu_power_off}`
//! - `rtl8xxxu/core.c::{rtl8723bu_set_ps_tdma, rtl8xxxu_active_to_lps,
//!   rtl8xxxu_flush_fifo, rtl8xxxu_firmware_self_reset,
//!   rtl8xxxu_gen2_disable_rf}`
//!
//! Deviation: Linux's `rtl8xxxu_active_to_lps` and `rtl8xxxu_flush_fifo`
//! only warn when their polls run out and `rtl8723bu_power_off` continues;
//! here an exhausted poll is a terminal `PowerTimeout` and nothing past it
//! touches the device. Every H2C reports `MailboxBusy` instead of being
//! dropped.

use super::firmware_transport::{ControlIo, Error, Owner};
use super::regs::*;
use super::rtl8192e_init::h2c;

const REG_PWR_DATA: u16 = 0x0038;
const PWR_DATA_EEPRPAD_RFE_CTRL_EN: u32 = 1 << 11;
const REG_GPIO_MUXCFG: u16 = 0x0040;
const REG_GPIO_INTM: u16 = 0x0048;
const REG_LEDCFG0: u16 = 0x004c;
const REG_PAD_CTRL1: u16 = 0x0064;
/// `REG_PAD_CTRL1 + 3` ("BT select S0/S1 controlled by WiFi", bit 5).
const REG_BT_SEL: u16 = 0x0067;
const REG_TX_REPORT_CTRL: u16 = 0x04ec;
const TX_REPORT_CTRL_TIMER_ENABLE: u8 = 1 << 1;
const REG_TXPAUSE: u16 = 0x0522;
const REG_DUAL_TSF_RST: u16 = 0x0553;
const DUAL_TSF_TX_OK: u8 = 1 << 5;
const REG_SCH_TX_CMD: u16 = 0x05f8;
const REG_BT_COEX_TABLE1: u16 = 0x06c0;
const REG_BT_COEX_TABLE2: u16 = 0x06c4;
const REG_BT_COEX_TABLE3: u16 = 0x06c8;
const REG_BT_COEX_TABLE4: u16 = 0x06cc;
const REG_WLAN_ACT_CONTROL_8723B: u16 = 0x076e;
/// Undocumented; `halbtc8723b1ant_InitHwConfig` antenna count (`0x01`).
const REG_ANT_COUNT: u16 = 0x0778;
/// Undocumented; Linux writes `0x05`.
const REG_UNKNOWN_790: u16 = 0x0790;
const REG_RFE_CTRL_ANTA_SRC: u16 = 0x0930;
const REG_RFE_BUFFER: u16 = 0x0944;
const REG_S0S1_PATH_SWITCH: u16 = 0x0948;
/// Undocumented "bits 6/7 in/out" byte (`0xff`).
const REG_UNKNOWN_974: u16 = 0x0974;
const REG_RX_WAIT_CCA: u16 = 0x0e70;
const RF6052_REG_IQADJ_G1: u8 = 0x01;
const SYS_FUNC_BBRSTB: u8 = 1 << 0;
const SYS_FUNC_BB_GLB_RSTN: u8 = 1 << 1;
const CR_HCI_TXDMA_ENABLE: u8 = 1 << 0;
const CR_HCI_RXDMA_ENABLE: u8 = 1 << 1;
/// `RTL8XXXU_MAX_REG_POLL`.
const MAX_REG_POLL: usize = 500;

/// `H2C_8723B_*` BT-class commands.
pub const H2C_B_TYPE_TDMA: u8 = 0x60;
pub const H2C_BT_INFO: u8 = 0x61;
pub const H2C_BT_IGNORE_WLANACT: u8 = 0x63;
pub const H2C_ANT_SEL_RSV: u8 = 0x65;
pub const H2C_BT_MP_OPER: u8 = 0x67;
pub const H2C_BT_GRANT: u8 = 0x6e;
/// `BT_MP_OP_WRITE_REG_VALUE`.
pub const BT_MP_OP_WRITE_REG_VALUE: u8 = 0x0d;

/// The two `bt_mp_oper` commands of `rtl8723bu_write_btreg` (request 0
/// carries the data, request 1 the address).
pub fn btreg_commands(reg: u8, data: u8) -> [[u8; 5]; 2] {
    [
        [H2C_BT_MP_OPER, 0, BT_MP_OP_WRITE_REG_VALUE, data, 0],
        [H2C_BT_MP_OPER, 1 << 4, BT_MP_OP_WRITE_REG_VALUE, 0, reg],
    ]
}

/// `rtl8723bu_write_btreg`.
pub(super) async fn write_btreg<I: ControlIo>(
    o: &Owner<I>,
    reg: u8,
    data: u8,
) -> Result<(), Error> {
    for command in btreg_commands(reg, data) {
        h2c(o, &command).await?;
    }
    Ok(())
}

/// `rtl8723bu_set_ps_tdma`.
pub(super) async fn set_ps_tdma<I: ControlIo>(o: &Owner<I>, args: [u8; 5]) -> Result<(), Error> {
    let mut command = [H2C_B_TYPE_TDMA, 0, 0, 0, 0, 0];
    command[1..].copy_from_slice(&args);
    h2c(o, &command).await
}

async fn rmw32<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u32, set: u32) -> Result<(), Error> {
    let value = o.read32(reg).await?;
    o.write32(reg, (value & !clear) | set).await
}

async fn rmw8<I: ControlIo>(o: &Owner<I>, reg: u16, clear: u8, set: u8) -> Result<(), Error> {
    let value = o.read8(reg).await?;
    o.write8(reg, (value & !clear) | set).await
}

/// `rtl8723b_enable_rf` (`rtl8xxxu_start`): RX CCA wait, the undocumented
/// `0x790`/`0x778` antenna bytes, GPIO mux, `RF_A IQADJ_G1 = 0x780`, BT TRx
/// mask on (`write_btreg(0x3c, 0x15)`), BT grant low, WLAN action by PTA,
/// BT S0/S1 under WiFi control, RFE control/buffer/antenna source, LED pins,
/// external switch Main→S1 / Aux→S0, antenna-inverse H2C, S0S1 `0x80`,
/// software TDMA with the antenna at WiFi, the coex tables, BT info and
/// "do not ignore WLAN activity".
pub(super) async fn enable_rf<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    rmw32(o, REG_RX_WAIT_CCA, 0, (1 << 22) | (1 << 23)).await?;
    o.write8(REG_UNKNOWN_790, 0x05).await?;
    o.write8(REG_ANT_COUNT, 0x01).await?;
    rmw8(o, REG_GPIO_MUXCFG, 0, 1 << 5).await?;
    super::rtl8723b_phy::write_rfreg(o, RF6052_REG_IQADJ_G1, 0x780).await?;
    write_btreg(o, 0x3c, 0x15).await?;
    h2c(o, &[H2C_BT_GRANT, 0]).await?;
    o.write8(REG_WLAN_ACT_CONTROL_8723B, 0x0c).await?;
    rmw8(o, REG_BT_SEL, 0, 1 << 5).await?;
    rmw32(o, REG_PWR_DATA, 0, PWR_DATA_EEPRPAD_RFE_CTRL_EN).await?;
    o.write8(REG_UNKNOWN_974, 0xff).await?;
    rmw32(o, REG_RFE_BUFFER, 0, (1 << 0) | (1 << 1)).await?;
    o.write8(REG_RFE_CTRL_ANTA_SRC, 0x77).await?;
    rmw32(o, REG_LEDCFG0, 1 << 24, 1 << 23).await?;
    rmw8(o, REG_PAD_CTRL1, 1 << 0, 0).await?;
    // ant_sel_rsv: ant_inverse = 1, int_switch_type = 0.
    h2c(o, &[H2C_ANT_SEL_RSV, 1, 0]).await?;
    // Normal/inverse antenna position table: 0x80 = PTA (inverse).
    o.write32(REG_S0S1_PATH_SWITCH, 0x80).await?;
    set_ps_tdma(o, [0x08, 0x00, 0x00, 0x00, 0x00]).await?;
    o.write32(REG_BT_COEX_TABLE1, 0x5555_5555).await?;
    o.write32(REG_BT_COEX_TABLE2, 0x5555_5555).await?;
    o.write32(REG_BT_COEX_TABLE3, 0x00ff_ffff).await?;
    o.write8(REG_BT_COEX_TABLE4, 0x03).await?;
    h2c(o, &[H2C_BT_INFO, 1 << 0]).await?;
    h2c(o, &[H2C_BT_IGNORE_WLANACT, 0]).await
}

/// `rtl8xxxu_gen2_disable_rf` (`rtl8xxxu_stop`).
pub(super) async fn disable_rf<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    super::rtl8192e_power::disable_rf(o).await
}

/// `rtl8xxxu_active_to_lps` (generic, unlike the RTL8192EU variant): the
/// `0x5f8` poll tests only its low byte (Linux stores the read in a `u8`),
/// and `REG_CR`/`REG_CR + 1` are byte writes.
async fn active_to_lps<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    o.write8(REG_TXPAUSE, 0xff).await?;
    let mut empty = false;
    for _ in 0..MAX_REG_POLL {
        if o.read32(REG_SCH_TX_CMD).await? as u8 == 0 {
            empty = true;
            break;
        }
        o.delay_us(10).await;
    }
    if !empty {
        return Err(Error::PowerTimeout);
    }
    rmw8(o, REG_SYS_FUNC, SYS_FUNC_BBRSTB, 0).await?;
    o.delay_us(2).await;
    rmw8(o, REG_SYS_FUNC, SYS_FUNC_BB_GLB_RSTN, 0).await?;
    // Linux reads REG_CR and then overwrites the value.
    o.read8(REG_CR).await?;
    o.write8(REG_CR, CR_HCI_TXDMA_ENABLE | CR_HCI_RXDMA_ENABLE)
        .await?;
    rmw8(o, REG_CR + 1, 1 << 1, 0).await?;
    rmw8(o, REG_DUAL_TSF_RST, 0, DUAL_TSF_TX_OK).await
}

/// `rtl8723bu_power_off`: FIFO flush, TX report timer off, `REG_CR = 0`,
/// active→LPS, firmware self reset when running from RAM, MCU reset, MCU
/// ready cleared, `rtl8723bu_active_to_emu`, HW suspend and GPIO9 as the
/// external wakeup. The caller owns the transfer-retirement precondition.
pub(super) async fn power_off<I: ControlIo>(o: &Owner<I>) -> Result<(), Error> {
    super::rtl8192e_power::flush_fifo(o).await?;
    rmw8(o, REG_TX_REPORT_CTRL, TX_REPORT_CTRL_TIMER_ENABLE, 0).await?;
    o.write8(REG_CR, 0x00).await?;
    active_to_lps(o).await?;
    if o.read8(REG_MCU_FW_DL).await? & MCU_FW_RAM_SEL != 0 {
        super::rtl8192e_power::firmware_self_reset(o).await?;
    }
    let func = o.read16(REG_SYS_FUNC).await? & !SYS_FUNC_CPU_ENABLE;
    o.write16(REG_SYS_FUNC, func).await?;
    o.write8(REG_MCU_FW_DL, 0x00).await?;
    super::rtl8723b_init::active_to_emu(o).await?;
    rmw8(o, REG_APS_FSMCO + 1, 0, 1 << 3).await?;
    rmw8(o, REG_GPIO_INTM + 2, 0, 1 << 0).await
}
