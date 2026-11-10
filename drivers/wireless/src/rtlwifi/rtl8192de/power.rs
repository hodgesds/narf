// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE power-on (`rtl92d_phy_set_poweron` + the
//! `_rtl92de_init_mac` power prefix) and power-off
//! (`rtl92de_card_disable` + `_rtl92de_poweroff_adapter`).
//!
//! Linux has no separate `rtl92de_card_enable`: the card is enabled by
//! `rtl92de_hw_init` calling `_rtl92de_init_mac`, which starts with
//! `rtl92d_phy_set_poweron` (`rtl8192de/phy.c`) and then runs the power
//! document V11 resume sequence (`rtl8192de/hw.c`). [`power_on`] is
//! both, up to and including `REG_CR = 0x2ff` and the TX/RX DMA stop
//! clear — the point where the LLT ([`super::llt`]) and the rest of
//! [`super::mac`] take over.
//!
//! Fail-closed departures from Linux, as in [`super::fw`]: the
//! `APS_FSMCO+1` BIT(0) (`APFM_ONMAC`) poll failing after 1000 x 50 us
//! is a gate failure here (Linux keeps going over a MAC that never
//! reported power-on), and the dual-MAC power-off-in-process wait
//! expiring after 200 x 500 us is a deadline error (Linux only
//! `WARN_ONCE`s and continues).
//!
//! The power-off functions return [`prepare::Error`], not the
//! [`firmware_transport::Error`] [`power_on`] returns: they belong to
//! the prepare / radio-owner world (like [`super::mac`] /
//! [`super::phy`] / [`super::station`]), and the one
//! firmware-transport call inside them (`fw::selfreset`) is mapped to
//! [`prepare::Error::State`], the radio-owner idiom for foreign
//! errors.

use super::fw;
use super::mac;
use super::phy;
use super::station::{self, BcnCtrl, MediaKind};
use super::{Band, MacPhyMode};
use crate::rtlwifi::firmware_transport::{Error, Io};
use crate::rtlwifi::prepare::Error as PrepareError;

/// `REG_MAC0` / `REG_MAC1` (`rtl8192d/reg.h`).
pub const REG_MAC0: u16 = 0x0081;
pub const REG_MAC1: u16 = 0x0053;
/// `MAC0_ON` is BIT(7) of `REG_MAC0`; `MAC1_ON` is BIT(0) of
/// `REG_MAC1` (`rtl8192d/reg.h`).
pub const MAC0_ON: u8 = 1 << 7;
pub const MAC1_ON: u8 = 1 << 0;
/// `REG_POWER_OFF_IN_PROCESS` (`rtl8192d/reg.h`).
pub const REG_POWER_OFF_IN_PROCESS: u16 = 0x0017;
/// BIT(7): the other MAC's power-off is still in process.
pub const POWER_OFF_IN_PROCESS: u8 = 1 << 7;
/// `for (i = 0; i < 200; i++)` (`rtl92d_phy_set_poweron`).
pub const POWER_OFF_POLLS: u32 = 200;
/// `udelay(500)` between power-off-in-process reads.
pub const POWER_OFF_DELAY_US: u64 = 500;
/// `REG_GPIO_IO_SEL`, `REG_GPIO_PIN_CTRL` (`rtl8192d/reg.h`).
pub const REG_GPIO_IO_SEL: u16 = 0x0042;
pub const REG_GPIO_PIN_CTRL: u16 = 0x0044;
/// `REG_RSV_CTRL`, `REG_LDOA15_CTRL`, `REG_SPS0_CTRL`,
/// `REG_AFE_XTAL_CTRL` (`rtl8192d/reg.h`).
pub const REG_RSV_CTRL: u16 = 0x001c;
pub const REG_LDOA15_CTRL: u16 = 0x0020;
pub const REG_SPS0_CTRL: u16 = 0x0011;
pub const REG_AFE_XTAL_CTRL: u16 = 0x0024;
/// `REG_APS_FSMCO`, `REG_SYS_ISO_CTRL`, `REG_CR`,
/// `REG_PCIE_CTRL_REG` (`rtl8192d/reg.h`).
pub const REG_APS_FSMCO: u16 = 0x0004;
pub const REG_SYS_ISO_CTRL: u16 = 0x0000;
pub const REG_CR: u16 = 0x0100;
pub const REG_PCIE_CTRL_REG: u16 = 0x0300;
/// `_rtl92de_init_mac` `while ((bytetmp & BIT(0)) && retry < 1000)`.
pub const APFM_RETRIES: u32 = 1000;
/// `udelay(50)` between `APFM_ONMAC` reads.
pub const APFM_DELAY_US: u64 = 50;

/// `rtl92d_phy_set_poweron` (`rtl8192de/phy.c`): tell the firmware the
/// band on this function's MAC register (`0x81[1]` / `0x53[1]` = 0 for
/// 5 GHz, 1 for 2.4 GHz), set this function's MAC-ON bit, and — in a
/// dual mode — wait for the other function's power-off to finish
/// (`REG_POWER_OFF_IN_PROCESS` BIT(7) clear, up to
/// [`POWER_OFF_POLLS`] x 500 us). Single mode sets `REG_MAC0` only
/// and never waits.
pub async fn phy_set_poweron<I: Io + ?Sized>(
    io: &I,
    mode: MacPhyMode,
    interface_index: u8,
    band: Band,
) -> Result<(), Error> {
    let mac_reg = if interface_index == 0 {
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
    if mode == MacPhyMode::SingleMacSinglePhy {
        let value = io.read8(REG_MAC0)?;
        io.write8(REG_MAC0, value | MAC0_ON)?;
        return Ok(());
    }
    let (on_reg, on_bit) = if interface_index == 0 {
        (REG_MAC0, MAC0_ON)
    } else {
        (REG_MAC1, MAC1_ON)
    };
    let value = io.read8(on_reg)?;
    io.write8(on_reg, value | on_bit)?;
    for _ in 0..POWER_OFF_POLLS {
        if io.read8(REG_POWER_OFF_IN_PROCESS)? & POWER_OFF_IN_PROCESS == 0 {
            return Ok(());
        }
        io.delay_us(POWER_OFF_DELAY_US).await;
    }
    Err(Error::Deadline)
}

/// The `_rtl92de_init_mac` power prefix, after [`phy_set_poweron`]:
/// unlock ISO/CLK/power (`REG_RSV_CTRL = 0`), `REG_LDOA15_CTRL =
/// 0x05`, enable XTAL (`REG_AFE_XTAL_CTRL = 0x0f`) and SPS into PWM
/// mode (`REG_SPS0_CTRL = 0x2b`), auto-enable WLAN (`REG_APS_FSMCO+1`
/// BIT(0) set, then polled clear over at most [`APFM_RETRIES`] x
/// 50 us), `REG_APS_FSMCO = 0x1012`, release RF digital isolation
/// (`REG_SYS_ISO_CTRL+1 = 0x82`), disable `REG_CR` before enabling it
/// to assure reset (`REG_CR = 0`, then `0x2ff`), and clear the
/// stopping TX/RX DMA bit (`REG_PCIE_CTRL_REG+1 = 0`). The commented
/// out `REG_SYS_FUNC_EN = 0xE3` BB-reset write in Linux is not
/// issued, matching Linux.
pub async fn power_on<I: Io + ?Sized>(
    io: &I,
    mode: MacPhyMode,
    interface_index: u8,
    band: Band,
) -> Result<(), Error> {
    phy_set_poweron(io, mode, interface_index, band).await?;
    io.write8(REG_RSV_CTRL, 0x00)?;
    io.write8(REG_LDOA15_CTRL, 0x05)?;
    io.write8(REG_SPS0_CTRL, 0x2b)?;
    io.write8(REG_AFE_XTAL_CTRL, 0x0f)?;
    let value = io.read8(REG_APS_FSMCO + 1)? | 1;
    io.delay_us(2).await;
    io.write8(REG_APS_FSMCO + 1, value)?;
    io.delay_us(2).await;
    let mut value = io.read8(REG_APS_FSMCO + 1)?;
    io.delay_us(50).await;
    let mut retry = 0;
    while value & 1 != 0 && retry < APFM_RETRIES {
        retry += 1;
        value = io.read8(REG_APS_FSMCO + 1)?;
        io.delay_us(50).await;
    }
    if value & 1 != 0 {
        return Err(Error::Gate);
    }
    io.write16(REG_APS_FSMCO, 0x1012)?;
    io.write8(REG_SYS_ISO_CTRL + 1, 0x82)?;
    io.delay_us(2).await;
    io.write16(REG_CR, 0x0)?;
    io.write16(REG_CR, 0x2ff)?;
    io.write8(REG_PCIE_CTRL_REG + 1, 0x0)?;
    Ok(())
}

// ── Power-off (`rtl92de_card_disable`, `_rtl92de_poweroff_adapter`) ────

/// `rtl92d_phy_check_poweroff` (`rtl8192de/phy.c`): clear this
/// function's MAC-ON bit; on a single-MAC part the adapter can
/// always power off. On a dual part, power off only when the other
/// MAC's ON bit is already clear, and mark the power-off in process
/// (`REG_POWER_OFF_IN_PROCESS` BIT(7)) while doing so. Returns
/// whether the adapter may power off.
pub fn check_poweroff(
    io: &impl Io,
    mode: MacPhyMode,
    interface_index: u8,
) -> Result<bool, PrepareError> {
    if mode == MacPhyMode::SingleMacSinglePhy {
        let value = io.read8(REG_MAC0)?;
        io.write8(REG_MAC0, value & !MAC0_ON)?;
        return Ok(true);
    }
    let (on_reg, on_bit, other_reg, other_bit) = if interface_index == 0 {
        (REG_MAC0, MAC0_ON, REG_MAC1, MAC1_ON)
    } else {
        (REG_MAC1, MAC1_ON, REG_MAC0, MAC0_ON)
    };
    let value = io.read8(on_reg)?;
    io.write8(on_reg, value & !on_bit)?;
    if io.read8(other_reg)? & other_bit != 0 {
        return Ok(false);
    }
    let value = io.read8(REG_POWER_OFF_IN_PROCESS)?;
    io.write8(REG_POWER_OFF_IN_PROCESS, value | POWER_OFF_IN_PROCESS)?;
    Ok(true)
}

/// `_rtl92de_poweroff_adapter` (`rtl8192de/hw.c`): the full
/// power-off sequence once [`check_poweroff`] has cleared the way.
/// `enable_aspm` is skipped (ASPM stays disabled, as in the 92CE
/// port). Where Linux's comment and code disagree, the code wins:
/// `REG_GPIO_IO_SEL` `0x0790` (not `0x0780`), `REG_SPS0_CTRL`
/// `0x23` (not `0x22`), `REG_APS_FSMCO+1` `0x10` (not `0x58` /
/// `0x18` — the `0x10` write follows the SD1 test note in the
/// comment).
pub async fn poweroff_adapter(io: &impl Io, mode: MacPhyMode) -> Result<(), PrepareError> {
    io.write8(phy::REG_RF_CTRL, 0x00)?;
    phy::set_bb(io, phy::RFPGA0_XCD_RFPARAMETER, 1 << 3, 0)?;
    phy::set_bb(io, phy::RFPGA0_XCD_RFPARAMETER, 1 << 15, 0)?;
    io.write8(REG_LDOA15_CTRL, 0x04)?;
    fw::selfreset(io).await.map_err(|_| PrepareError::State)?;
    io.write8(fw::REG_SYS_FUNC_EN + 1, 0x51)?;
    io.write8(fw::REG_MCUFWDL, 0x00)?;
    io.write32(REG_GPIO_PIN_CTRL, 0x0000_0000)?;
    let value = io.read8(REG_GPIO_PIN_CTRL)?;
    io.write32(REG_GPIO_PIN_CTRL, 0x00ff_0000 | (u32::from(value) << 8))?;
    io.write16(REG_GPIO_IO_SEL, 0x0790)?;
    io.write16(phy::REG_LEDCFG0, 0x8080)?;
    io.write8(phy::REG_AFE_PLL_CTRL, 0x80)?;
    io.write8(REG_SPS0_CTRL, 0x23)?;
    io.write8(REG_AFE_XTAL_CTRL, 0x0e)?;
    io.write8(REG_RSV_CTRL, 0x0e)?;
    io.write8(REG_APS_FSMCO + 1, 0x10)?;
    if mode != MacPhyMode::SingleMacSinglePhy {
        let value = io.read8(REG_POWER_OFF_IN_PROCESS)?;
        io.write8(REG_POWER_OFF_IN_PROCESS, value & !POWER_OFF_IN_PROCESS)?;
    }
    Ok(())
}

/// `rtl92de_card_disable` (`rtl8192de/hw.c`): link state to NOLINK
/// (media status UNSPECIFIED), stop TX DMA
/// (`REG_PCIE_CTRL_REG+1 = 0xFE`, 50 µs), the RF-off sequence,
/// `REG_SYS_FUNC_EN` `0xE2` (`0xE0` on MAC1 — MAC0 cannot do the
/// global reset), stop TX/RX DMA (`REG_PCIE_CTRL_REG+1 = 0xFF`,
/// 50 µs), `REG_CR = 0`, then power the adapter off when
/// [`check_poweroff`] allows it. The LED power-off is skipped (no
/// LED owner in NARF). The `TXPAUSE` `0x522 = 0xFF` comment in
/// Linux has no write behind it — the TX queues must already be
/// stopped by the caller (the packet owner, which does not exist
/// yet for DE) before this runs. Returns whether the adapter
/// powered off.
pub async fn card_disable(
    io: &impl Io,
    mode: MacPhyMode,
    interface_index: u8,
    bcn: &mut BcnCtrl,
) -> Result<bool, PrepareError> {
    station::set_media_status(io, bcn, MediaKind::Unspecified)?;
    io.write8(REG_PCIE_CTRL_REG + 1, 0xfe)?;
    io.delay_us(50).await;
    phy::set_bb(io, phy::RFPGA0_ANALOGPARAMETER4, 0x00f0_0000, 0xf)?;
    phy::set_rf(io, phy::Path::A, 0x00, phy::RFREG_OFFSET_MASK, 0x00).await?;
    io.write8(mac::REG_APSD_CTRL, 0x40)?;
    phy::set_bb(io, phy::ROFDM0_TRXPATHENABLE, phy::MASKBYTE0, 0)?;
    phy::set_bb(io, phy::ROFDM1_TRXPATHENABLE, phy::BDWORD, 0)?;
    io.write8(fw::REG_SYS_FUNC_EN, 0xe2)?;
    if interface_index == 1 {
        io.write8(fw::REG_SYS_FUNC_EN, 0xe0)?;
    }
    io.delay_us(50).await;
    io.write8(REG_PCIE_CTRL_REG + 1, 0xff)?;
    io.delay_us(50).await;
    io.write8(REG_CR, 0x00)?;
    if check_poweroff(io, mode, interface_index)? {
        poweroff_adapter(io, mode).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
