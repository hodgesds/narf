// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EU RF enable/disable and card power-off, from Linux
//! `rtl8xxxu/8192e.c` (`rtl8192e_enable_rf`, `rtl8192eu_power_off`,
//! `rtl8192eu_active_to_lps`) and `core.c` (`rtl8xxxu_gen2_disable_rf`,
//! `rtl8xxxu_flush_fifo`, `rtl8xxxu_firmware_self_reset`).
//!
//! Deviation: every Linux poll that only warns on exhaustion (RXDMA idle,
//! `REG_SCH_TX_CMD` empty) is a terminal `PowerTimeout` here; nothing past a
//! failed poll touches the device.
use super::firmware_transport::{ControlIo, Error, Owner};
use super::regs::*;

const REG_PWR_DATA: u16 = 0x0038;
const PWR_DATA_EEPRPAD_RFE_CTRL_EN: u32 = 1 << 11;
const REG_GPIO_MUXCFG: u16 = 0x0040;
const REG_LEDCFG0: u16 = 0x004c;
const REG_PAD_CTRL1: u16 = 0x0064;
const REG_RQPN: u16 = 0x0200;
const REG_RQPN_NPQ: u16 = 0x0214;
const REG_RXPKT_NUM: u16 = 0x0284;
const RXPKT_NUM_RXDMA_IDLE: u32 = 1 << 17;
const RXPKT_NUM_RW_RELEASE_EN: u32 = 1 << 18;
const REG_TX_REPORT_CTRL_8192E: u16 = 0x04ec;
const TX_REPORT_CTRL_TIMER_ENABLE: u8 = 1 << 1;
const REG_TXPAUSE: u16 = 0x0522;
const REG_DUAL_TSF_RST: u16 = 0x0553;
const DUAL_TSF_TX_OK: u8 = 1 << 5;
const REG_SCH_TX_CMD: u16 = 0x05f8;
const REG_WLAN_ACT_CONTROL_8723B: u16 = 0x076e;
const REG_RFE_CTRL_ANTA_SRC: u16 = 0x0930;
const REG_RFE_BUFFER: u16 = 0x0944;
const REG_RX_WAIT_CCA: u16 = 0x0e70;
const SYS_FUNC_BBRSTB: u8 = 1 << 0;
const SYS_FUNC_BB_GLB_RSTN: u8 = 1 << 1;
const CR_HCI_TXDMA_ENABLE: u16 = 1 << 0;
const CR_HCI_RXDMA_ENABLE: u16 = 1 << 1;
const CR_SECURITY_ENABLE: u16 = 1 << 9;
/// `rtl8xxxu_flush_fifo` / `rtl8192eu_active_to_lps` retry budget
/// (`retry = 100; do { } while (retry--)`: 101 reads).
const POLLS: usize = 101;

/// `rtl8192e_enable_rf` (`rtl8xxxu_start`): RX CCA wait, GPIO mux, PTA,
/// RFE control/buffer, antenna source, LED pin, external switch Main→S1 /
/// Aux→S0, and the TXPAUSE clear that "fixes transmission failure".
pub(super) async fn enable_rf<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let cca = owner.read32(REG_RX_WAIT_CCA).await? | (1 << 22) | (1 << 23);
    owner.write32(REG_RX_WAIT_CCA, cca).await?;
    let mux = owner.read8(REG_GPIO_MUXCFG).await? | (1 << 5);
    owner.write8(REG_GPIO_MUXCFG, mux).await?;
    owner.write8(REG_WLAN_ACT_CONTROL_8723B, 0x04).await?;
    let pwr = owner.read32(REG_PWR_DATA).await? | PWR_DATA_EEPRPAD_RFE_CTRL_EN;
    owner.write32(REG_PWR_DATA, pwr).await?;
    let rfe = owner.read32(REG_RFE_BUFFER).await? | 3;
    owner.write32(REG_RFE_BUFFER, rfe).await?;
    owner.write8(REG_RFE_CTRL_ANTA_SRC, 0x77).await?;
    let led = (owner.read32(REG_LEDCFG0).await? & !(1 << 24)) | (1 << 23);
    owner.write32(REG_LEDCFG0, led).await?;
    let pad = owner.read8(REG_PAD_CTRL1).await? & !1;
    owner.write8(REG_PAD_CTRL1, pad).await?;
    owner.write8(REG_TXPAUSE, 0x00).await
}

/// `rtl8xxxu_gen2_disable_rf` (`rtl8xxxu_stop`).
pub(super) async fn disable_rf<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let cca = owner.read32(REG_RX_WAIT_CCA).await? & !((1 << 22) | (1 << 23));
    owner.write32(REG_RX_WAIT_CCA, cca).await
}

/// `rtl8xxxu_flush_fifo`.
pub(super) async fn flush_fifo<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    owner.write8(REG_TXPAUSE, 0xff).await?;
    let rx = owner.read32(REG_RXPKT_NUM).await? | RXPKT_NUM_RW_RELEASE_EN;
    owner.write32(REG_RXPKT_NUM, rx).await?;
    let mut idle = false;
    for _ in 0..POLLS {
        if owner.read32(REG_RXPKT_NUM).await? & RXPKT_NUM_RXDMA_IDLE != 0 {
            idle = true;
            break;
        }
    }
    if !idle {
        return Err(Error::PowerTimeout);
    }
    owner.write16(REG_RQPN_NPQ, 0).await?;
    owner.write32(REG_RQPN, 0x8000_0000).await?;
    owner.delay_us(2_000).await;
    Ok(())
}

/// `rtl8192eu_active_to_lps`.
async fn active_to_lps<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    owner.write8(REG_TXPAUSE, 0xff).await?;
    let mut empty = false;
    for _ in 0..POLLS {
        if owner.read32(REG_SCH_TX_CMD).await? == 0 {
            empty = true;
            break;
        }
    }
    if !empty {
        return Err(Error::PowerTimeout);
    }
    let func = owner.read8(REG_SYS_FUNC).await? & !SYS_FUNC_BBRSTB;
    owner.write8(REG_SYS_FUNC, func).await?;
    owner.delay_us(2).await;
    let func = owner.read8(REG_SYS_FUNC).await? & !SYS_FUNC_BB_GLB_RSTN;
    owner.write8(REG_SYS_FUNC, func).await?;
    let cr = (owner.read16(REG_CR).await? & 0xff00) | CR_HCI_TXDMA_ENABLE | CR_HCI_RXDMA_ENABLE;
    owner.write16(REG_CR, cr).await?;
    let cr = owner.read16(REG_CR).await? & !CR_SECURITY_ENABLE;
    owner.write16(REG_CR, cr).await?;
    let tsf = owner.read8(REG_DUAL_TSF_RST).await? | DUAL_TSF_TX_OK;
    owner.write8(REG_DUAL_TSF_RST, tsf).await
}

/// `rtl8xxxu_firmware_self_reset`: ask the 8051 to reset, poll CPU-enable
/// clear (100 × 50 µs), else force it clear like Linux.
pub(super) async fn firmware_self_reset<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    owner.write8(REG_HMTFR + 3, 0x20).await?;
    for _ in 0..100 {
        if owner.read16(REG_SYS_FUNC).await? & SYS_FUNC_CPU_ENABLE == 0 {
            return Ok(());
        }
        owner.delay_us(50).await;
    }
    let func = owner.read16(REG_SYS_FUNC).await? & !SYS_FUNC_CPU_ENABLE;
    owner.write16(REG_SYS_FUNC, func).await
}

/// `rtl8192eu_power_off`: FIFO flush, TX report timer off, RF off,
/// active→LPS, firmware/MCU reset, `rtl8xxxu_reset_8051`, active→EMU and
/// EMU→disabled. The caller owns the transfer-retirement precondition (no
/// bulk TD may still reference the device).
pub(super) async fn power_off<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    flush_fifo(owner).await?;
    let report = owner.read8(REG_TX_REPORT_CTRL_8192E).await? & !TX_REPORT_CTRL_TIMER_ENABLE;
    owner.write8(REG_TX_REPORT_CTRL_8192E, report).await?;
    owner.write8(REG_RF_CTRL, 0x00).await?;
    active_to_lps(owner).await?;
    if owner.read8(REG_MCU_FW_DL).await? & MCU_FW_RAM_SEL != 0 {
        firmware_self_reset(owner).await?;
    }
    let func = owner.read16(REG_SYS_FUNC).await? & !SYS_FUNC_CPU_ENABLE;
    owner.write16(REG_SYS_FUNC, func).await?;
    owner.write8(REG_MCU_FW_DL, 0x00).await?;
    super::rtl8192e_init::reset_8051(owner).await?;
    super::rtl8192e_init::active_to_emu(owner).await?;
    super::rtl8192e_init::emu_to_disabled(owner).await
}
