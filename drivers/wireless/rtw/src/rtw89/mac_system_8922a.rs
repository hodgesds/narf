// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A post-firmware reset/clock and MAC0 system preparation.
//!
//! Source: Linux rtw8922a.c `rtw8922a_mac_enable_bb_rf` (3096..3103),
//! mac.c `rtw89_mac_init` (4360..4383), and mac_be.c `sys_init_be`
//! (772..936), using reg.h register definitions. The 8922A DMAC,
//! CMAC-share and chip hooks in `sys_init_be` are no-ops.
//!
//! Native prerequisite: all five MAC0 AFE power enables must be set, its
//! FEN set and isolation clear; MAC1 requires all five AFE enables clear,
//! its FEN clear and isolation set (the source full-power-off tuple).
//! Before any BB reset/clock or MAC power write, the first
//! effect closes and verifies inherited MAC0 CMAC TXEN/RXEN. The final function
//! write preserves those closed packet gates instead of Linux's full set.
//! This publishes only SystemConfigured: no normal SCC DLE/HFC, TRX,
//! interrupts, RF tables/calibration, operating channel or station readiness.
//! HAXI global DMA remains unchanged; WPDMA and all TX channels except CH12
//! must already be stopped, as left by the firmware-download owner.

use super::power;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

// Linux reg.h:3960..3971, 4137..4157, 4977, 6574..6624.
const AFE_CTRL1: u32 = 0x0024;
const WLCMAC0_ALL_EN: u32 = 0x1f00_0000;
const WLCMAC1_ALL_EN: u32 = 0x0000_001f;
const FEN_RST_ENABLE: u32 = 0x0084;
const ISO_CMAC02PP: u32 = 1 << 24;
const ISO_CMAC12PP: u32 = 1 << 25;
const CMAC0_FEN: u32 = 1 << 16;
const CMAC1_FEN: u32 = 1 << 17;
const BB_RESET: u8 = 0x03;
const DMAC_SYS_CR32B: u32 = 0x842c;
const DMAC_BB_SYS: u32 = 0x7ff9_7ff9;
const CMAC_FUNC_EN: u32 = 0x10000;
const CMAC_PACKET_GATES: u32 = 0x3000_0000;
const CMAC_FUNC_CLOSED: u32 = 0xc000_01ff;
const CK_EN: u32 = 0x10004;
const CK_EN_SET: u32 = 0x4000_01ff;

/// Fallible register operations; every native operation validates current
/// device authority independently, including the readback after a write.
pub(super) trait Regs {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error>;
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error>;
    fn read32(&mut self, address: u32) -> Result<u32, power::Error>;
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    NoOwner,
    FirmwareRequired,
    RingsRequired,
    ActiveOwner,
    Io(power::Error),
    DmaState,
    MacPowerRequired,
    UnsupportedMac1,
    PacketGates,
    Readback(u32),
    Terminal,
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Configuring,
    SystemConfigured,
    Failed(Error),
}

/// One startup attempt, retained alongside the firmware and DMA owners.
/// There are no waits or cancellation points within this synchronous stage.
/// A failed access/readback (or interrupted stack) never permits replay.
#[derive(Debug, Default)]
pub(super) struct System {
    state: State,
}
impl System {
    pub(super) fn state(&self) -> State {
        self.state
    }

    /// # Safety
    /// Caller exclusively owns the 8922A BAR after verified WCPU+BBMCU0
    /// firmware download, with programmed rings, MAC0 power already
    /// released, MAC1 powered off, no ordinary producers,
    /// no interrupt worker and no concurrent reset/removal. Retain every
    /// DMA allocation on failure until independent PCI quiescence.
    pub(super) unsafe fn configure(&mut self, regs: &mut impl Regs) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Configuring;
        let result = configure(regs);
        self.state = match result {
            Ok(()) => State::SystemConfigured,
            Err(error) => State::Failed(error),
        };
        result
    }
}

fn read8(regs: &mut impl Regs, address: u32) -> Result<u8, Error> {
    let value = regs.read8(address)?;
    if value == u8::MAX {
        return Err(power::Error::Gone.into());
    }
    Ok(value)
}
fn read32(regs: &mut impl Regs, address: u32) -> Result<u32, Error> {
    let value = regs.read32(address)?;
    if value == u32::MAX {
        return Err(power::Error::Gone.into());
    }
    Ok(value)
}
fn modify32(regs: &mut impl Regs, address: u32, clear: u32, set: u32) -> Result<(), Error> {
    check_dma(regs)?;
    check_power(regs)?;
    if address != CMAC_FUNC_EN {
        check_closed(regs)?;
    }
    let value = (read32(regs, address)? & !clear) | set;
    regs.write32(address, value)?;
    // Observe only the fields this stage owns; unrelated status/reserved
    // bits can change independently, and must never be written back again.
    if read32(regs, address)? & (clear | set) != set {
        return Err(Error::Readback(address));
    }
    check_closed(regs)?;
    check_dma(regs)?;
    Ok(())
}
fn check_dma(regs: &mut impl Regs) -> Result<(), Error> {
    use super::dma_be::{DMA_STOP1, STOP_CH12, STOP_CH13_14, STOP_WPDMA, TX_CH_MASK};
    let closed = STOP_WPDMA | TX_CH_MASK | STOP_CH13_14;
    if read32(regs, DMA_STOP1)? & (closed | STOP_CH12) != closed {
        return Err(Error::DmaState);
    }
    Ok(())
}
fn check_power(regs: &mut impl Regs) -> Result<(), Error> {
    let fen = read32(regs, FEN_RST_ENABLE)?;
    let afe = read32(regs, AFE_CTRL1)?;
    // mac_be.c::cmac_pwr_en_be(false) completes all three parts:
    // FEN clear, isolation set, then every AFE power enable clear.
    if fen & CMAC1_FEN != 0 || fen & ISO_CMAC12PP == 0 || afe & WLCMAC1_ALL_EN != 0 {
        return Err(Error::UnsupportedMac1);
    }
    // FEN alone cannot establish access to a powered CMAC register bank.
    if fen & CMAC0_FEN == 0 || fen & ISO_CMAC02PP != 0 || afe & WLCMAC0_ALL_EN != WLCMAC0_ALL_EN {
        return Err(Error::MacPowerRequired);
    }
    Ok(())
}
fn check_closed(regs: &mut impl Regs) -> Result<(), Error> {
    check_power(regs)?;
    if read32(regs, CMAC_FUNC_EN)? & CMAC_PACKET_GATES != 0 {
        return Err(Error::PacketGates);
    }
    Ok(())
}
fn configure(regs: &mut impl Regs) -> Result<(), Error> {
    check_dma(regs)?;
    check_power(regs)?;
    // Native closure is the first effect. The prior download may have
    // inherited active CMAC functions; BME parking cannot stop ACK/CTS.
    // No BB/global clock or power effect follows an unverified closure.
    modify32(regs, CMAC_FUNC_EN, CMAC_PACKET_GATES, 0)?;
    check_closed(regs)?;
    // rtw8922a_mac_enable_bb_rf, before sys_init_be (mac.c:4371).
    let resets = read8(regs, FEN_RST_ENABLE)?;
    check_closed(regs)?;
    regs.write8(FEN_RST_ENABLE, resets | BB_RESET)?;
    if read8(regs, FEN_RST_ENABLE)? & BB_RESET != BB_RESET {
        return Err(Error::Readback(FEN_RST_ENABLE));
    }
    check_closed(regs)?;
    check_dma(regs)?;
    regs.write32(DMAC_SYS_CR32B, DMAC_BB_SYS)?;
    if read32(regs, DMAC_SYS_CR32B)? != DMAC_BB_SYS {
        return Err(Error::Readback(DMAC_SYS_CR32B));
    }
    check_closed(regs)?;
    check_dma(regs)?;
    // cmac_pwr_en_be(MAC_0, true): idempotent source writes only; the
    // preflight already proved MAC0 released and MAC1 powered off.
    modify32(regs, AFE_CTRL1, 0, WLCMAC0_ALL_EN)?;
    modify32(regs, FEN_RST_ENABLE, ISO_CMAC02PP, 0)?;
    modify32(regs, FEN_RST_ENABLE, 0, CMAC0_FEN)?;
    // cmac_func_en_be(MAC_0, true), with packet gates kept closed.
    modify32(regs, CK_EN, 0, CK_EN_SET)?;
    modify32(regs, CMAC_FUNC_EN, CMAC_PACKET_GATES, CMAC_FUNC_CLOSED)?;
    check_dma(regs)?;
    check_closed(regs)
}

/// Borrowed, checked BAR port for this startup stage only. No DMA stop,
/// ring, interrupt-mask, PHY or RF register can be written through it.
pub(super) struct NativeRegs<'a> {
    region: &'a MmioRegion,
    authority: &'a Cap<BusDeviceCap, Write>,
    fault: Option<power::Error>,
    cancelled: Option<&'a core::sync::atomic::AtomicBool>,
}
impl<'a> NativeRegs<'a> {
    /// # Safety
    /// Caller exclusively owns this 8922A Device-mapped BAR and function
    /// for the whole port lifetime; no reset/removal or other BAR users.
    pub(super) unsafe fn new(
        region: &'a MmioRegion,
        authority: &'a Cap<BusDeviceCap, Write>,
    ) -> Self {
        Self {
            region,
            authority,
            fault: None,
            cancelled: None,
        }
    }
    pub(super) fn cancel_with(mut self, flag: &'a core::sync::atomic::AtomicBool) -> Self {
        self.cancelled = Some(flag);
        self
    }
    fn checked<T>(
        &mut self,
        address: u32,
        width: u32,
        write: bool,
        operation: impl FnOnce(&MmioRegion, u64) -> T,
    ) -> Result<T, power::Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if self
            .cancelled
            .is_some_and(|flag| flag.load(core::sync::atomic::Ordering::Acquire))
        {
            self.fault = Some(power::Error::Access);
            return Err(power::Error::Access);
        }
        let result = crate::rtw88::pci_park::invoke(self.authority, || {
            let permitted = match width {
                1 => address == FEN_RST_ENABLE,
                4 => {
                    matches!(
                        address,
                        AFE_CTRL1 | FEN_RST_ENABLE | DMAC_SYS_CR32B | CMAC_FUNC_EN | CK_EN
                    ) || (!write && address == super::dma_be::DMA_STOP1)
                }
                _ => false,
            };
            let offset = u64::from(address);
            if !permitted
                || address & (width - 1) != 0
                || offset
                    .checked_add(u64::from(width))
                    .is_none_or(|end| end > self.region.len)
            {
                return Err(power::Error::Access);
            }
            Ok(operation(self.region, offset))
        })
        .map_err(|_| power::Error::Access)
        .and_then(core::convert::identity);
        if let Err(error) = result {
            self.fault = Some(error)
        }
        result
    }
}
impl Regs for NativeRegs<'_> {
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        self.checked(address, 1, false, |region, offset| {
            // SAFETY: checked current authority, permitted address and extent;
            // the constructor requires exclusive ownership of the live BAR.
            unsafe { region.read8(offset) }
        })
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        self.checked(address, 1, true, |region, offset| {
            // SAFETY: checked current authority, permitted address and extent;
            // the constructor requires exclusive ownership of the live BAR.
            unsafe { region.write8(offset, value) }
        })
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        self.checked(address, 4, false, |region, offset| {
            // SAFETY: checked authority, permitted address, extent and alignment;
            // the constructor requires exclusive ownership of the live BAR.
            unsafe { region.read32(offset) }
        })
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        if address == CMAC_FUNC_EN && value & CMAC_PACKET_GATES != 0 {
            self.fault = Some(power::Error::Access);
            return Err(power::Error::Access);
        }
        self.checked(address, 4, true, |region, offset| {
            // SAFETY: checked authority, permitted address, extent and alignment;
            // the constructor requires exclusive ownership of the live BAR.
            unsafe { region.write32(offset, value) }
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mac_system_8922a_tests.rs"]
mod tests;
