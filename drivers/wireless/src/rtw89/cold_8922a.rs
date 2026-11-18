// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Native-only CLOSED RTL8922A cold power/BB/download owner.
//!
//! This is intentionally separate from the existing source-program helpers:
//! their ordinary CMAC enables, infallible ports and retry behavior stay intact.
//! The retained native supervisor composes checked power, factory, owned DMA,
//! firmware and closed SCC/TRX. Ordinary RX/RF/station gates remain closed.
//!
//! Primary source: local Linux rtw89 rtw8922a.c::rtw8922a_pwr_on_func,
//! ::rtw8922a_mac_disable_bb_rf, ::rtw8922a_bb_preinit;
//! mac_be.c::cmac_pwr_en_be, ::dbcc_bb_ctrl_be, ::rtw89_mac_disable_cpu_be;
//! mac.c::rtw89_mac_power_switch (reset before complete pwr_on_func).

use super::{fwdl_be as f, mac_pre_init_8922a as p, power};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapSlot, Write};

const BB0_RESET: u32 = 3;
const BB1_RESET: u32 = 3 << 8;
const BB_RESET: u32 = BB0_RESET | BB1_RESET;
const PACKET: u32 = 3 << 28;
const CLOSED_FUNCTIONS: u32 = f::B_BE_CMAC_FUNC_EN_SET & !PACKET;
const CPU_HELD: u32 = f::B_BE_HOLD_AFTER_RESET | f::B_BE_WCPU_EN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    Readback(u32),
    Identity,
    Terminal,
    PowerState(u32),
    MissingDmaBridge,
    Firmware(f::Error),
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
        Self::Register(error)
    }
}
impl From<f::Error> for Error {
    fn from(error: f::Error) -> Self {
        Self::Firmware(error)
    }
}

/// Tied to the exact original current-capability slot and mapped BAR extent.
/// There is no public constructor and no boolean readiness input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    slot: CapSlot,
    phys: u64,
    virt: u64,
    len: u64,
}

impl Binding {
    /// Immutable identity observation only; no current grant or stage receipt.
    pub(super) fn observe(region: &MmioRegion, authority: &Cap<BusDeviceCap, Write>) -> Self {
        Self {
            slot: authority.slot(),
            phys: region.phys.raw(),
            virt: region.virt,
            len: region.len,
        }
    }
}

pub(super) trait Regs {
    fn binding(&self) -> Binding;
    fn current(&mut self) -> Result<(), power::Error>;
    /// Each checked DMA snapshot/write/sync is a real fallible operation.
    /// Native overrides with original Bus and optional N22P invocation;
    /// the default supplies current-checked inert model behavior.
    fn dma_memory<T>(
        &mut self,
        operation: impl FnOnce() -> Result<T, super::checked_fwdl_8922a::Error>,
    ) -> Result<T, super::checked_fwdl_8922a::Error> {
        self.current()?;
        operation()
    }
    fn read8(&mut self, address: u32) -> Result<u8, power::Error>;
    fn read16(&mut self, address: u32) -> Result<u16, power::Error>;
    fn read32(&mut self, address: u32) -> Result<u32, power::Error>;
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error>;
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error>;
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error>;
    /// Native uses responsive_spin_until with a real bounded Deadline; model
    /// implements the hardware protocol with bounded explicit state changes.
    fn poll32(
        &mut self,
        address: u32,
        mask: u32,
        expected: u32,
        timeout_us: u64,
    ) -> Result<(), power::Error>;
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error>;
}

/// Retention contract of the checked original Prepared native DMA bridge.
///
/// # Safety
/// The same retained Prepared owner must prove programmed CH12 ring identities,
/// held ring configuration/source BDRAM request-clear and exact CH12-only
/// TX authority: WPDMA and TX
/// CH0..11/13/14 stopped, CH12 unstopped, with source global DMA state preserved.
/// Every allocation possibly referenced by a descriptor must remain retained
/// across error/cancellation until its actual TXBD/multitag terminal receipt or
/// independently verified reset/quiescence. Each register effect must be checked
/// and immediately fallible; no failed/reset-incomplete release_all is allowed.
/// submit must not recursively lock the currently borrowed Prepared owner.
///
/// The separate checked_fwdl_8922a::Port supplies this native contract; the
/// legacy infallible MmioRegs APIs cannot substitute for it.
pub(super) unsafe trait DownloadPort: Regs {
    fn dma_current(&mut self) -> Result<(), power::Error>;
    fn submit_retained(&mut self, bytes: &[u8], fwdl: bool) -> Result<(), f::Error>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Powering,
    ClosedPower,
    PreparingBbMcu0,
    BbMcu0Prepared,
    Downloading,
    FirmwareDownloaded,
    Failed(Error),
}

/// The receipt remains on its original owner; it is never Copy/Clone and does
/// not imply calibrated PHY, RX, station/AP, ordinary DMA or RF permission.
#[derive(Debug, Default)]
#[must_use]
pub(super) struct Cold {
    binding: Option<Binding>,
    state: State,
    raw_cut: Option<u8>,
}
impl Cold {
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// Denial-only propagation from the retained checked DMA composition.
    pub(super) fn poison(&mut self, error: Error) {
        self.state = State::Failed(error)
    }

    fn bind(&mut self, io: &mut impl Regs) -> Result<(), Error> {
        io.current()?;
        match self.binding {
            Some(binding) if binding != io.binding() => Err(Error::Identity),
            Some(_) => Ok(()),
            None => {
                self.binding = Some(io.binding());
                Ok(())
            }
        }
    }
    fn finish(&mut self, result: Result<(), Error>, success: State) -> Result<(), Error> {
        self.state = match result {
            Ok(()) => success,
            Err(error) => State::Failed(error),
        };
        result
    }
    /// # Safety
    /// Exclusive actual cold/reset-quiescent function and Device BAR ownership,
    /// verified BME clear, no previously published DMA, no concurrent firmware,
    /// reset/removal or interrupt worker. Parking alone does not prove temporal
    /// reset/quiescence. Common power controls must positively acknowledge entry
    /// closure; inaccessible/off-domain zeros do not construct a receipt.
    /// `cv` is the actual same-function chip-version observation, not a
    /// caller-selected board profile or guessed cut.
    pub(super) unsafe fn power_on(&mut self, io: &mut impl Regs, cv: u8) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        self.state = State::Powering;
        self.raw_cut = Some(cv);
        let result = (|| {
            self.bind(io)?;
            entry_close(io)?;
            let mut held = Guard {
                io,
                phase: Phase::BbHeld,
            };
            held.verify()?;
            reset_power(&mut held)?;
            power_head(&mut held)?;
            power_tail_prefix(&mut held, cv)?;
            // Linux cmac_pwr_en_be(MAC0,true), while both BBs remain held.
            set32(&mut held, f::R_BE_AFE_CTRL1, f::B_BE_R_SYM_WLCMAC0_ALL_EN)?;
            clear32(
                &mut held,
                f::R_BE_FEN_RST_ENABLE,
                f::B_BE_R_SYM_ISO_CMAC02PP,
            )?;
            set32(&mut held, f::R_BE_FEN_RST_ENABLE, f::B_BE_CMAC0_FEN)?;
            check_power(held.io)?; // Full AFE + FEN + isolation, before bank access.
            set32(&mut held, f::R_BE_CK_EN, f::B_BE_CK_EN_SET)?;
            // Close inherited TX/RX before constructing structural function state.
            modify32(&mut held, f::R_BE_CMAC_FUNC_EN, PACKET, CLOSED_FUNCTIONS)?;
            if read32(&mut held, f::R_BE_CK_EN)? & f::B_BE_CK_EN_SET != f::B_BE_CK_EN_SET
                || read32(&mut held, f::R_BE_CMAC_FUNC_EN)? & (PACKET | CLOSED_FUNCTIONS)
                    != CLOSED_FUNCTIONS
            {
                return Err(Error::Readback(f::R_BE_CMAC_FUNC_EN));
            }
            held.phase = Phase::ClosedHeld;
            held.verify()
        })();
        self.finish(result, State::ClosedPower)
    }
    /// Source BBMCU0 preinit only. This is not complete partial_init: no DLE,
    /// HFC, HAXI enable, BDRAM/ring programming or host DMA authority is added.
    pub(super) fn prepare_bbmcu0(&mut self, io: &mut impl Regs) -> Result<(), Error> {
        if self.state != State::ClosedPower {
            return Err(Error::Terminal);
        }
        self.state = State::PreparingBbMcu0;
        let result = (|| {
            self.bind(io)?;
            let mut held = Guard {
                io,
                phase: Phase::ClosedHeld,
            };
            held.verify()?;
            // mac.c::rtw89_mac_partial_init enables the internal HCI engines
            // before the first BB hook. PCI BME is still parked; HAXI and all
            // packet channels remain closed by the checked native owner.
            set32(
                &mut held,
                f::R_BE_HCI_FUNC_EN,
                f::B_BE_HCI_TXDMA_EN | f::B_BE_HCI_RXDMA_EN,
            )?;
            // Source first BB hook is reached only after packet gates were
            // observed closed in a fully powered MAC0; MAC1 remains fully off.
            held.phase = Phase::BbMcu0;
            bb_preinit(&mut held)?;
            held.verify()
        })();
        self.finish(result, State::BbMcu0Prepared)
    }
    /// Actual core.c chip identity, observed while the native power receipt
    /// still holds both BBs and WCPU. This is data, never an RF grant. Linux
    /// observes these fields before power-on; the closed native path delays
    /// XTAL access until its positively verified common power domain exists.
    pub(super) fn chip_version(&mut self, io: &mut impl Regs) -> Result<p::HalChipVer, Error> {
        if self.state != State::ClosedPower {
            return Err(Error::Terminal);
        }
        let result = (|| {
            let raw_cut = self.raw_cut.ok_or(Error::Identity)?;
            self.bind(io)?;
            let mut held = Guard {
                io,
                phase: Phase::ClosedHeld,
            };
            held.verify()?;
            // core.c::rtw89_read_chip_ver: ACV, CID, AID low, AID high.
            let acv = read_xtal(&mut held, p::XTAL_SI_CV)? & p::XTAL_SI_ACV_MASK;
            let cid =
                p::Cid::from_raw((held.read32(p::R_BE_SYS_CHIPINFO)? & p::B_BE_HW_ID_MASK) as u8);
            let low = read_xtal(&mut held, p::XTAL_SI_CHIP_ID_L)?;
            let high = read_xtal(&mut held, p::XTAL_SI_CHIP_ID_H)?;
            held.verify()?;
            Ok(p::HalChipVer {
                cv: raw_cut,
                acv,
                cid,
                aid: u16::from_le_bytes([low, high]),
            })
        })();
        if let Err(error) = result {
            self.poison(error);
        }
        result
    }
    /// Observe the same retained pre-FW owner for the separate checked DMA
    /// bridge. This neither advances Cold state nor grants ordinary readiness.
    pub(super) fn observe_dma_entry(&mut self, io: &mut impl Regs) -> Result<(), Error> {
        if self.state != State::BbMcu0Prepared {
            return Err(Error::Terminal);
        }
        let result = self.bind(io).and_then(|()| {
            Guard {
                io,
                phase: Phase::BbMcu0,
            }
            .verify()
        });
        if let Err(error) = result {
            self.state = State::Failed(error)
        }
        result
    }
    /// The real native owner refuses here until a checked Prepared DMA
    /// implementation exists. Keeping this explicit avoids adapting an
    /// infallible source port with sentinel reads or fabricated write success.
    pub(super) fn native_download_boundary(&mut self, io: &mut impl Regs) -> Result<(), Error> {
        if self.state != State::BbMcu0Prepared {
            return Err(Error::Terminal);
        }
        let checked = self.bind(io).and_then(|()| {
            let mut held = Guard {
                io,
                phase: Phase::BbMcu0,
            };
            held.verify()
        });
        let error = checked.err().unwrap_or(Error::MissingDmaBridge);
        self.state = State::Failed(error);
        Err(error)
    }
    /// Fallible FWDL over the actual retained checked native DMA port.
    /// Single attempt: source retries never replay uncertain native DMA here.
    pub(super) fn download(
        &mut self,
        io: &mut impl DownloadPort,
        normal: &f::Suit<'_>,
        bb: &f::Suit<'_>,
    ) -> Result<(), Error> {
        if self.state != State::BbMcu0Prepared {
            return Err(Error::Terminal);
        }
        self.state = State::Downloading;
        let result = (|| {
            self.bind(io)?;
            if normal.check != f::CheckType::Wcpu
                || bb.check != f::CheckType::Bb0
                || !normal.malloc_info
                || bb.malloc_info
            {
                return Err(Error::Identity);
            }
            io.dma_current()?;
            let mut closed = Guard {
                io,
                phase: Phase::Firmware,
            };
            closed.verify()?;
            // mac_fwdl_preconfig_be precedes the first download attempt.
            clear32(
                &mut closed,
                f::R_BE_FW_AUTO_CAL_DELAY,
                f::B_BE_WCPU_FW_DELAY_COUNT_VALID,
            )?;
            mask32(
                &mut closed,
                f::R_BE_FW_AUTO_CAL_DELAY,
                f::B_BE_WCPU_FW_DELAY_COUNT_MASK,
                0,
            )?;
            disable_cpu(&mut closed)?;
            enable_wcpu(&mut closed)?;
            download_suit(&mut closed, normal)?;
            download_suit(&mut closed, bb)?;
            closed.delay_us(5_000)?;
            check_ready(&mut closed, f::CheckType::FreeRtos)?;
            closed.verify()?;
            closed.io.dma_current()?;
            Ok(())
        })();
        self.finish(result, State::FirmwareDownloaded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    BbHeld,
    ClosedHeld,
    BbMcu0,
    Firmware,
}
struct Guard<'a, P> {
    io: &'a mut P,
    phase: Phase,
}
impl<P: Regs> Guard<'_, P> {
    fn verify(&mut self) -> Result<(), Error> {
        self.io.current()?;
        let fen = read32(self.io, f::R_BE_FEN_RST_ENABLE)?;
        if fen & BB1_RESET != 0 {
            return Err(Error::Readback(f::R_BE_FEN_RST_ENABLE));
        }
        check_mac1_off(self.io)?;
        match self.phase {
            Phase::BbHeld | Phase::ClosedHeld => {
                if fen & BB_RESET != 0
                    || read32(self.io, f::R_BE_PLATFORM_ENABLE)? & CPU_HELD != CPU_HELD
                {
                    return Err(Error::Readback(f::R_BE_FEN_RST_ENABLE));
                }
            }
            Phase::BbMcu0 => {
                if fen & 1 != 0 || read32(self.io, f::R_BE_PLATFORM_ENABLE)? & CPU_HELD != CPU_HELD
                {
                    return Err(Error::Readback(f::R_BE_FEN_RST_ENABLE));
                }
            }
            Phase::Firmware => {
                if fen & 1 != 0 {
                    return Err(Error::Readback(f::R_BE_FEN_RST_ENABLE));
                }
            }
        }
        if self.phase != Phase::BbHeld {
            check_closed(self.io)?;
        }
        Ok(())
    }
    fn before(&mut self) -> Result<(), power::Error> {
        self.verify().map_err(|error| match error {
            Error::Register(e) => e,
            _ => power::Error::Access,
        })
    }
}
impl<P: Regs> Regs for Guard<'_, P> {
    fn binding(&self) -> Binding {
        self.io.binding()
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.before()
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.io.read8(a)
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.io.read16(a)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.io.read32(a)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.before()?;
        self.io.write8(a, v)?;
        self.before()
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.before()?;
        self.io.write16(a, v)?;
        self.before()
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.before()?;
        self.io.write32(a, v)?;
        self.before()
    }
    fn poll32(&mut self, a: u32, m: u32, v: u32, us: u64) -> Result<(), power::Error> {
        self.before()?;
        self.io.poll32(a, m, v, us)?;
        self.before()
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.before()?;
        self.io.delay_us(us)?;
        self.before()
    }
}

fn read8(io: &mut impl Regs, a: u32) -> Result<u8, Error> {
    let value = io.read8(a)?;
    if value == u8::MAX {
        return Err(power::Error::Gone.into());
    }
    Ok(value)
}
fn read16(io: &mut impl Regs, a: u32) -> Result<u16, Error> {
    let value = io.read16(a)?;
    if value == u16::MAX {
        return Err(power::Error::Gone.into());
    }
    Ok(value)
}
fn read32(io: &mut impl Regs, a: u32) -> Result<u32, Error> {
    let value = io.read32(a)?;
    if value == u32::MAX {
        return Err(power::Error::Gone.into());
    }
    Ok(value)
}
fn modify32(io: &mut impl Regs, a: u32, clear: u32, set: u32) -> Result<(), Error> {
    let v = read32(io, a)?;
    io.write32(a, (v & !clear) | set)?;
    Ok(())
}
fn set32(io: &mut impl Regs, a: u32, bits: u32) -> Result<(), Error> {
    modify32(io, a, 0, bits)
}
fn clear32(io: &mut impl Regs, a: u32, bits: u32) -> Result<(), Error> {
    modify32(io, a, bits, 0)
}
fn mask32(io: &mut impl Regs, a: u32, mask: u32, value: u32) -> Result<(), Error> {
    modify32(io, a, mask, (value << mask.trailing_zeros()) & mask)
}
fn verify32(io: &mut impl Regs, a: u32, mask: u32, value: u32) -> Result<(), Error> {
    if read32(io, a)? & mask != value {
        return Err(Error::Readback(a));
    }
    Ok(())
}
fn set8(io: &mut impl Regs, a: u32, bits: u8) -> Result<(), Error> {
    let v = read8(io, a)?;
    io.write8(a, v | bits)?;
    Ok(())
}
fn check_mac1_off(io: &mut impl Regs) -> Result<(), Error> {
    let fen = read32(io, f::R_BE_FEN_RST_ENABLE)?;
    let afe = read32(io, f::R_BE_AFE_CTRL1)?;
    if fen & f::B_BE_CMAC1_FEN != 0
        || fen & f::B_BE_R_SYM_ISO_CMAC12PP == 0
        || afe & f::B_BE_R_SYM_WLCMAC1_ALL_EN != 0
    {
        return Err(Error::Readback(f::R_BE_AFE_CTRL1));
    }
    Ok(())
}
fn check_power(io: &mut impl Regs) -> Result<(), Error> {
    check_mac1_off(io)?;
    verify32(
        io,
        f::R_BE_AFE_CTRL1,
        f::B_BE_R_SYM_WLCMAC0_ALL_EN,
        f::B_BE_R_SYM_WLCMAC0_ALL_EN,
    )?;
    verify32(
        io,
        f::R_BE_FEN_RST_ENABLE,
        f::B_BE_CMAC0_FEN | f::B_BE_R_SYM_ISO_CMAC02PP,
        f::B_BE_CMAC0_FEN,
    )
}
fn check_closed(io: &mut impl Regs) -> Result<(), Error> {
    check_power(io)?;
    verify32(io, f::R_BE_CMAC_FUNC_EN, PACKET, 0)
}
fn held_cpu(io: &mut impl Regs) -> Result<(), Error> {
    clear32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN, 0)?;
    set32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_HOLD_AFTER_RESET)?;
    verify32(
        io,
        f::R_BE_PLATFORM_ENABLE,
        f::B_BE_HOLD_AFTER_RESET,
        f::B_BE_HOLD_AFTER_RESET,
    )?;
    set32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, CPU_HELD, CPU_HELD)
}
fn entry_close(io: &mut impl Regs) -> Result<(), Error> {
    // Source BB0 byte disable, then source DBCC BB1 dword disable. These
    // only assert reset; no new BB/PHY/global power is released at entry.
    let bb = read8(io, f::R_BE_FEN_RST_ENABLE)?;
    io.write8(f::R_BE_FEN_RST_ENABLE, bb & !3)?;
    verify32(io, f::R_BE_FEN_RST_ENABLE, BB0_RESET, 0)?;
    clear32(io, f::R_BE_FEN_RST_ENABLE, BB1_RESET)?;
    verify32(io, f::R_BE_FEN_RST_ENABLE, BB_RESET, 0)?;
    held_cpu(io)?;
    // Source cmac_pwr_en_be(false), MAC0 then MAC1. Only common-bank
    // controls; no off-domain CMAC read is used as a successful receipt.
    for (all, iso, fen) in [
        (
            f::B_BE_R_SYM_WLCMAC0_ALL_EN,
            f::B_BE_R_SYM_ISO_CMAC02PP,
            f::B_BE_CMAC0_FEN,
        ),
        (
            f::B_BE_R_SYM_WLCMAC1_ALL_EN,
            f::B_BE_R_SYM_ISO_CMAC12PP,
            f::B_BE_CMAC1_FEN,
        ),
    ] {
        clear32(io, f::R_BE_FEN_RST_ENABLE, fen)?;
        verify32(io, f::R_BE_FEN_RST_ENABLE, fen, 0)?;
        set32(io, f::R_BE_FEN_RST_ENABLE, iso)?;
        verify32(io, f::R_BE_FEN_RST_ENABLE, iso, iso)?;
        clear32(io, f::R_BE_AFE_CTRL1, all)?;
        verify32(io, f::R_BE_AFE_CTRL1, all, 0)?;
    }
    // Positive common isolation bits prevent all-zero off-domain reads
    // from minting closure. Both BBs and WCPU must also acknowledge hold.
    verify32(
        io,
        f::R_BE_FEN_RST_ENABLE,
        BB_RESET
            | f::B_BE_CMAC0_FEN
            | f::B_BE_CMAC1_FEN
            | f::B_BE_R_SYM_ISO_CMAC02PP
            | f::B_BE_R_SYM_ISO_CMAC12PP,
        f::B_BE_R_SYM_ISO_CMAC02PP | f::B_BE_R_SYM_ISO_CMAC12PP,
    )?;
    verify32(
        io,
        f::R_BE_AFE_CTRL1,
        f::B_BE_R_SYM_WLCMAC0_ALL_EN | f::B_BE_R_SYM_WLCMAC1_ALL_EN,
        0,
    )?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, CPU_HELD, CPU_HELD)
}

fn reset_power(io: &mut impl Regs) -> Result<(), Error> {
    let fsm = read32(io, p::R_BE_SYSON_FSM_MON)?;
    io.write32(
        p::R_BE_SYSON_FSM_MON,
        (fsm & p::WLAN_FSM_MASK) | p::WLAN_FSM_SET,
    )?;
    io.poll32(
        p::R_BE_SYSON_FSM_MON,
        p::WLAN_FSM_STATE_MASK,
        p::WLAN_FSM_IDLE,
        2_000_000,
    )?;

    let state = field(
        read32(io, p::R_BE_IC_PWR_STATE)?,
        p::B_BE_WLMAC_PWR_STE_MASK,
    );
    if !matches!(
        state,
        p::MAC_AX_MAC_OFF | p::MAC_AX_MAC_ON | p::MAC_AX_MAC_LPS
    ) {
        return Err(Error::PowerState(state));
    }
    if state == p::MAC_AX_MAC_OFF {
        clear32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HAXIDMA_IO_EN)?;
        io.poll32(
            p::R_BE_HCI_OPT_CTRL,
            p::B_BE_HAXIDMA_IO_ST | p::B_BE_HAXIDMA_BACKUP_RESTORE_ST,
            0,
            2_000_000,
        )?;
        clear32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_EN)?;
        io.poll32(p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_ST, 0, 2_000_000)?;
        clear32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_EN_WLON)?;
        clear32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_SWLPS)?;
    } else if state == p::MAC_AX_MAC_ON {
        clear32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HAXIDMA_IO_EN)?;
        io.poll32(
            p::R_BE_HCI_OPT_CTRL,
            p::B_BE_HAXIDMA_IO_ST | p::B_BE_HAXIDMA_BACKUP_RESTORE_ST,
            0,
            2_000_000,
        )?;
        clear32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_EN)?;
        io.poll32(p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_ST, 0, 2_000_000)?;
        set32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_EN_WLON)?;
        set32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_OFFMAC)?;
        io.poll32(p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_OFFMAC, 0, 2_000_000)?;
        clear32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_EN_WLON)?;
        clear32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_SWLPS)?;
    } else if state == p::MAC_AX_MAC_LPS {
        clear32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HAXIDMA_IO_EN)?;
        io.poll32(
            p::R_BE_HCI_OPT_CTRL,
            p::B_BE_HAXIDMA_IO_ST | p::B_BE_HAXIDMA_BACKUP_RESTORE_ST,
            0,
            2_000_000,
        )?;
        clear32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_EN)?;
        io.poll32(p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_ST, 0, 2_000_000)?;
        set32(io, p::R_BE_WLLPS_CTRL, p::B_BE_FORCE_LEAVE_LPS)?;
        io.poll32(
            p::R_BE_IC_PWR_STATE,
            p::B_BE_WLMAC_PWR_STE_MASK,
            p::MAC_AX_MAC_ON << 8,
            2_000_000,
        )?;
        set32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_EN_WLON)?;
        set32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_OFFMAC)?;
        io.poll32(p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_OFFMAC, 0, 2_000_000)?;
        clear32(io, p::R_BE_WLLPS_CTRL, p::B_BE_FORCE_LEAVE_LPS)?;
        clear32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_EN_WLON)?;
        clear32(io, p::R_BE_SYS_PW_CTRL, p::B_BE_APFM_SWLPS)?;
    }
    Ok(())
}

// Exact Linux pwr_on_func head, with each source RMW kept in order. No
// baseline_power_on_be combination, extra PSUS bit or pre-reset head call.
fn power_head(io: &mut impl Regs) -> Result<(), Error> {
    use super::mac as m;
    clear32(
        io,
        p::R_BE_SYS_PW_CTRL,
        m::B_BE_AFSM_WLSUS_EN | m::B_BE_AFSM_PCIE_SUS_EN,
    )?;
    set32(io, p::R_BE_SYS_PW_CTRL, m::B_BE_DIS_WLBT_PDNSUSEN_SOPC)?;
    set32(io, p::R_BE_WLLPS_CTRL, m::B_BE_DIS_WLBT_LPSEN_LOPC)?;
    clear32(io, p::R_BE_SYS_PW_CTRL, m::B_BE_APDM_HPDN)?;
    clear32(io, p::R_BE_SYS_PW_CTRL, m::B_BE_APFM_SWLPS)?;
    io.poll32(
        p::R_BE_SYS_PW_CTRL,
        m::B_BE_RDY_SYSPWR,
        m::B_BE_RDY_SYSPWR,
        3_000_000,
    )?;
    set32(io, p::R_BE_SYS_PW_CTRL, m::B_BE_EN_WLON)?;
    set32(
        io,
        m::R_BE_WLRESUME_CTRL as u32,
        m::B_BE_LPSROP_CMAC0 | m::B_BE_LPSROP_CMAC1,
    )?;
    set32(io, p::R_BE_SYS_PW_CTRL, m::B_BE_APFN_ONMAC)?;
    io.poll32(p::R_BE_SYS_PW_CTRL, m::B_BE_APFN_ONMAC, 0, 3_000_000)?;
    Ok(())
}

fn xtal(io: &mut impl Regs, offset: u8, value: u8, mask: u8) -> Result<(), Error> {
    let cmd = ((offset as u32) & p::B_BE_WL_XTAL_SI_ADDR_MASK)
        | (((value as u32) << 8) & p::B_BE_WL_XTAL_SI_DATA_MASK)
        | (((mask as u32) << 16) & p::B_BE_WL_XTAL_SI_BITMASK_MASK)
        | ((p::XTAL_SI_NORMAL_WRITE << 24) & p::B_BE_WL_XTAL_SI_MODE_MASK)
        | p::B_BE_WL_XTAL_SI_CMD_POLL;
    io.write32(p::R_BE_WLAN_XTAL_SI_CTRL, cmd)?;
    io.poll32(
        p::R_BE_WLAN_XTAL_SI_CTRL,
        p::B_BE_WL_XTAL_SI_CMD_POLL,
        0,
        50_000,
    )?;
    Ok(())
}
fn read_xtal(io: &mut impl Regs, offset: u8) -> Result<u8, Error> {
    let cmd = (u32::from(offset) & p::B_BE_WL_XTAL_SI_ADDR_MASK)
        | ((p::XTAL_SI_NORMAL_READ << 24) & p::B_BE_WL_XTAL_SI_MODE_MASK)
        | p::B_BE_WL_XTAL_SI_CMD_POLL;
    io.write32(p::R_BE_WLAN_XTAL_SI_CTRL, cmd)?;
    io.poll32(
        p::R_BE_WLAN_XTAL_SI_CTRL,
        p::B_BE_WL_XTAL_SI_CMD_POLL,
        0,
        50_000,
    )?;
    Ok(((io.read32(p::R_BE_WLAN_XTAL_SI_CTRL)? & p::B_BE_WL_XTAL_SI_DATA_MASK) >> 8) as u8)
}

fn power_tail_prefix(io: &mut impl Regs, cv: u8) -> Result<(), Error> {
    let is_pcie = true;
    // AFE clock-monitor off, ANAPAR LDO ports on, ADDA ISO clear.
    clear32(io, p::R_BE_AFE_ON_CTRL1, p::B_BE_REG_CK_MON_CK960M_EN)?;
    set8(
        io,
        p::R_BE_ANAPAR_POW_MAC,
        p::B_BE_POW_PC_LDO_PORT0 | p::B_BE_POW_PC_LDO_PORT1,
    )?;
    clear32(
        io,
        p::R_BE_FEN_RST_ENABLE,
        p::B_BE_R_SYM_ISO_ADDA_P02PP | p::B_BE_R_SYM_ISO_ADDA_P12PP,
    )?;
    set8(io, p::R_BE_PLATFORM_ENABLE, p::B_BE_PLATFORM_EN)?;

    if is_pcie {
        set32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HAXIDMA_IO_EN)?;
        io.poll32(
            p::R_BE_HCI_OPT_CTRL,
            p::B_BE_HAXIDMA_IO_ST,
            p::B_BE_HAXIDMA_IO_ST,
            3_000_000,
        )?;
        io.poll32(
            p::R_BE_HCI_OPT_CTRL,
            p::B_BE_HAXIDMA_BACKUP_RESTORE_ST,
            0,
            3_000_000,
        )?;
    }

    set32(io, p::R_BE_HCI_OPT_CTRL, p::B_BE_HCI_WLAN_IO_EN)?;
    io.poll32(
        p::R_BE_HCI_OPT_CTRL,
        p::B_BE_HCI_WLAN_IO_ST,
        p::B_BE_HCI_WLAN_IO_ST,
        3_000_000,
    )?;

    if is_pcie {
        clear32(io, p::R_BE_SYS_SDIO_CTRL, p::B_BE_PCIE_FORCE_IBX_EN)?;
    }

    // XTAL-SI program + ADIE pad power, in Linux order.
    xtal(io, p::XTAL_SI_PLL, 0x02, 0x02)?;
    xtal(io, p::XTAL_SI_PLL, 0x01, 0x01)?;
    set32(
        io,
        p::R_BE_SYS_ADIE_PAD_PWR_CTRL,
        p::B_BE_SYM_PADPDN_WL_RFC1_1P3,
    )?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x40, 0x40)?;
    set32(
        io,
        p::R_BE_SYS_ADIE_PAD_PWR_CTRL,
        p::B_BE_SYM_PADPDN_WL_RFC0_1P3,
    )?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x20, 0x20)?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x04, 0x04)?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x08, 0x08)?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x00, 0x10)?;
    xtal(io, p::XTAL_SI_WL_RFC_S0, 0xEB, 0xFF)?;
    xtal(io, p::XTAL_SI_WL_RFC_S1, 0xEB, 0xFF)?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x01, 0x01)?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x02, 0x02)?;
    xtal(io, p::XTAL_SI_ANAPAR_WL, 0x00, 0x80)?;
    xtal(io, p::XTAL_SI_XREF_RF1, 0x00, 0x40)?;
    xtal(io, p::XTAL_SI_XREF_RF2, 0x00, 0x40)?;
    xtal(io, p::XTAL_SI_PLL_1, 0x40, 0x60)?;
    xtal(io, p::XTAL_SI_SRAM_CTRL, 0x00, p::XTAL_SI_SRAM_DIS)?;

    // CV-conditional ISO sequence (`hal->cv != p::CHIP_CAV`).
    // The `mdelay(1)` between the EV2EF clears is kept.
    if cv != p::CHIP_CAV {
        set32(io, p::R_BE_PMC_DBG_CTRL2, p::B_BE_SYSON_DIS_PMCR_BE_WRMSK)?;
        set32(io, p::R_BE_SYS_ISO_CTRL, p::B_BE_ISO_EB2CORE)?;
        clear32(io, p::R_BE_SYS_ISO_CTRL, p::B_BE_PWC_EV2EF_B)?;
        io.delay_us(1_000)?;
        clear32(io, p::R_BE_SYS_ISO_CTRL, p::B_BE_PWC_EV2EF_S)?;
        clear32(io, p::R_BE_PMC_DBG_CTRL2, p::B_BE_SYSON_DIS_PMCR_BE_WRMSK)?;
    }

    // DMAC / CMAC function enables.
    let mut dmac = p::B_BE_MAC_FUNC_EN
        | p::B_BE_DMAC_FUNC_EN
        | p::B_BE_MPDU_PROC_EN
        | p::B_BE_WD_RLS_EN
        | p::B_BE_DLE_WDE_EN
        | p::B_BE_TXPKT_CTRL_EN
        | p::B_BE_STA_SCH_EN
        | p::B_BE_DLE_PLE_EN
        | p::B_BE_PKT_BUF_EN
        | p::B_BE_DMAC_TBL_EN
        | p::B_BE_PKT_IN_EN
        | p::B_BE_DLE_CPUIO_EN
        | p::B_BE_DISPATCHER_EN
        | p::B_BE_BBRPT_EN
        | p::B_BE_MAC_SEC_EN
        | p::B_BE_H_AXIDMA_EN
        | p::B_BE_DMAC_MLO_EN
        | p::B_BE_PLRLS_EN
        | p::B_BE_P_AXIDMA_EN
        | p::B_BE_DLE_DATACPUIO_EN;
    if is_pcie {
        dmac |= p::B_BE_LTR_CTL_EN;
    }
    set32(io, p::R_BE_DMAC_FUNC_EN, dmac)?;
    verify32(io, p::R_BE_DMAC_FUNC_EN, dmac, dmac)?;
    let share = p::B_BE_CMAC_SHARE_EN | p::B_BE_RESPBA_EN | p::B_BE_ADDRSRCH_EN | p::B_BE_BTCOEX_EN;
    set32(io, p::R_BE_CMAC_SHARE_FUNC_EN, share)?;
    verify32(io, p::R_BE_CMAC_SHARE_FUNC_EN, share, share)?;
    Ok(())
}

fn bb_preinit(io: &mut impl Regs) -> Result<(), Error> {
    mask32(
        io,
        f::R_BE_DMAC_SYS_CR32B,
        f::B_BE_DMAC_BB_PHY0_MASK,
        0x7FF9,
    )?;
    mask32(io, f::R_BE_FEN_RST_ENABLE, f::B_BE_FEN_BB_IP_RSTN, 0)?;
    mask32(io, f::R_BE_FEN_RST_ENABLE, f::B_BE_FEN_BBPLAT_RSTB, 0)?;
    mask32(io, f::R_BE_FEN_RST_ENABLE, f::B_BE_FEN_BB_IP_RSTN, 1)?;
    // PHY_0: `rdy = 0`.
    mask32(io, f::R_BE_FEN_RST_ENABLE, f::B_BE_BOOT_RDY0, 0)?;
    mask32(io, f::R_BE_MEM_PWR_CTRL, f::B_BE_MEM_BBMCU0_DS_V1, 0)?;
    // fsleep(1)
    io.delay_us(1)?;
    for (addr, data) in f::BB_MCU0_INIT_REG {
        // PHY_0: no 0x20000 band offset.
        io.write32(addr + f::BBMCU_ADDR_OFFSET, data)?;
    }
    Ok(())
}

fn disable_cpu(io: &mut impl Regs) -> Result<(), Error> {
    clear32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN, 0)?;
    set32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_HOLD_AFTER_RESET)?;
    verify32(
        io,
        f::R_BE_PLATFORM_ENABLE,
        f::B_BE_HOLD_AFTER_RESET,
        f::B_BE_HOLD_AFTER_RESET,
    )?;
    set32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, CPU_HELD, CPU_HELD)?;
    let v = read32(io, f::R_BE_WCPU_FW_CTRL)? & f::B_BE_RUN_ENV_MASK;
    io.write32(f::R_BE_WCPU_FW_CTRL, v)?;
    // WCPU remains positively held. Old path-ready/status/download bits
    // must actually clear before a fresh ROM/firmware handshake can count.
    verify32(io, f::R_BE_WCPU_FW_CTRL, !f::B_BE_RUN_ENV_MASK, 0)?;

    set32(io, f::R_BE_DCPU_PLATFORM_ENABLE, f::B_BE_DCPU_PLATFORM_EN)?;
    io.write32(f::R_BE_UDM0, 0)?;
    io.write32(f::R_BE_HALT_C2H, 0)?;
    io.write32(f::R_BE_UDM2, 0)?;
    Ok(())
}

fn enable_wcpu(io: &mut impl Regs) -> Result<f::BootResidue, Error> {
    let boot_reason = 0u8;
    let include_bb = true;
    let mut set = f::B_BE_WLANCPU_FWDL_EN;
    if include_bb {
        set |= f::B_BE_BBMCU0_FWDL_EN;
    }
    set32(io, f::R_BE_WCPU_FW_CTRL, set)?;
    verify32(
        io,
        f::R_BE_WCPU_FW_CTRL,
        f::B_BE_WLANCPU_FWDL_EN
            | f::B_BE_BBMCU0_FWDL_EN
            | f::B_BE_H2C_PATH_RDY
            | f::B_BE_DLFW_PATH_RDY
            | f::B_BE_WCPU_FWDL_STATUS_MASK,
        f::B_BE_WLANCPU_FWDL_EN | f::B_BE_BBMCU0_FWDL_EN,
    )?;

    let residue = f::BootResidue {
        halt_c2h: read32(io, f::R_BE_HALT_C2H)?,
        udm1: read32(io, f::R_BE_UDM1)?,
        udm2: read32(io, f::R_BE_UDM2)?,
    };
    io.write32(f::R_BE_UDM1, 0)?;
    io.write32(f::R_BE_UDM2, 0)?;
    io.write32(f::R_BE_BOOT_DBG, 0)?;
    io.write32(f::R_BE_HALT_H2C, 0)?;
    io.write32(f::R_BE_HALT_C2H, 0)?;
    io.write32(f::R_BE_HALT_H2C_CTRL, 0)?;
    io.write32(f::R_BE_HALT_C2H_CTRL, 0)?;
    let _ = read32(io, f::R_BE_HISR0)?;
    io.write32(f::R_BE_HISR0, f::B_BE_HALT_C2H_INT)?;

    set32(io, f::R_BE_SYS_CLK_CTRL, f::B_BE_CPU_CLK_EN)?;
    clear32(
        io,
        f::R_BE_SYS_CFG5,
        f::B_BE_WDT_WAKE_PCIE_EN | f::B_BE_WDT_WAKE_USB_EN,
    )?;
    clear32(
        io,
        f::R_BE_WCPU_FW_CTRL,
        f::B_BE_WDT_PLT_RST_EN | f::B_BE_WCPU_ROM_CUT_GET,
    )?;
    io.write32(f::R_BE_SECURE_BOOT_MALLOC_INFO, 0)?;
    clear32(io, f::R_BE_GPIO_MUXCFG, f::B_BE_BOOT_MODE)?;
    // 8922A does not set B_BE_HOST_EXIST.
    let reason = read16(io, f::R_BE_BOOT_REASON)?;
    io.write16(
        f::R_BE_BOOT_REASON,
        (reason & !f::B_BE_BOOT_REASON_MASK) | (u16::from(boot_reason) & f::B_BE_BOOT_REASON_MASK),
    )?;
    clear32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN, 0)?;
    clear32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_HOLD_AFTER_RESET)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, CPU_HELD, 0)?;
    set32(io, f::R_BE_PLATFORM_ENABLE, f::B_BE_WCPU_EN)?;
    verify32(io, f::R_BE_PLATFORM_ENABLE, CPU_HELD, f::B_BE_WCPU_EN)?;
    Ok(residue)
}

fn map_status(raw: u8) -> f::FwdlStatus {
    match raw {
        0 => f::FwdlStatus::Initial,
        1 => f::FwdlStatus::Ongoing,
        2 => f::FwdlStatus::WcpuFwdlReady,
        3 => f::FwdlStatus::WcpuFwInitReady,
        4 => f::FwdlStatus::ChecksumFail,
        5 | 6 => f::FwdlStatus::SecurityFail,
        7 => f::FwdlStatus::CvNotMatch,
        8 | 9 => f::FwdlStatus::Reserved,
        other => f::FwdlStatus::Raw(other),
    }
}

fn status(io: &mut impl Regs, check: f::CheckType) -> Result<f::FwdlStatus, Error> {
    let v = read32(io, f::R_BE_WCPU_FW_CTRL)?;
    let pass = match check {
        f::CheckType::Wcpu => v & f::B_BE_WLANCPU_FWDL_EN == 0,
        f::CheckType::Dcpu => v & f::B_BE_DATACPU_FWDL_EN == 0,
        f::CheckType::Bb0 => v & f::B_BE_BBMCU0_FWDL_EN == 0,
        f::CheckType::Bb1 => v & f::B_BE_BBMCU1_FWDL_EN == 0,
        f::CheckType::FreeRtos => false,
    };
    if pass {
        return Ok(f::FwdlStatus::WcpuFwInitReady);
    }
    Ok(map_status(
        ((v & f::B_BE_WCPU_FWDL_STATUS_MASK) >> 26) as u8,
    ))
}

fn field(value: u32, mask: u32) -> u32 {
    (value & mask) >> mask.trailing_zeros()
}
fn check_ready(io: &mut impl Regs, check: f::CheckType) -> Result<(), Error> {
    // FWDL_WAIT_CNT=400000 at1us (fw.h/fw.c). Port delay is responsive native
    // time, not a guessed successful read or an executor-dependent timer task.
    let mut last = f::FwdlStatus::Initial;
    for _ in 0..f::FW_READY_ATTEMPTS {
        last = status(io, check)?;
        if last == f::FwdlStatus::WcpuFwInitReady {
            return Ok(());
        }
        io.delay_us(1)?;
    }
    match last {
        f::FwdlStatus::ChecksumFail | f::FwdlStatus::SecurityFail | f::FwdlStatus::CvNotMatch => {
            Err(f::Error::Firmware(last).into())
        }
        _ => Err(power::Error::Timeout.into()),
    }
}
fn download_suit<P: DownloadPort>(io: &mut Guard<'_, P>, suit: &f::Suit<'_>) -> Result<(), Error> {
    if suit.malloc_info {
        io.write32(
            f::R_BE_SECURE_BOOT_MALLOC_INFO,
            f::SECURE_BOOT_MALLOC_INFO_8922A,
        )?;
    }
    io.poll32(
        f::R_BE_WCPU_FW_CTRL,
        f::B_BE_H2C_PATH_RDY,
        f::B_BE_H2C_PATH_RDY,
        u64::from(f::PATH_READY_ATTEMPTS),
    )?;
    let header = suit.plan.header_command(0).map_err(f::Error::Plan)?;
    io.before()?;
    io.io.dma_current()?;
    io.io.submit_retained(&header, false)?;
    io.verify()?;
    io.poll32(
        f::R_BE_WCPU_FW_CTRL,
        f::B_BE_DLFW_PATH_RDY,
        f::B_BE_DLFW_PATH_RDY,
        u64::from(f::PATH_READY_ATTEMPTS),
    )?;
    io.write32(f::R_BE_HALT_H2C_CTRL, 0)?;
    io.write32(f::R_BE_HALT_C2H_CTRL, 0)?;
    let part = suit.plan.part_size();
    for section in 0..suit.plan.section_count() {
        let len = suit
            .plan
            .section_len(section)
            .ok_or(f::Error::Plan(super::download_plan::Error::SectionGeometry))?;
        let mut offset = 0;
        while offset < len {
            let chunk = suit.plan.chunk(section, offset).map_err(f::Error::Plan)?;
            io.before()?;
            io.io.dma_current()?;
            io.io.submit_retained(&chunk, true)?;
            io.verify()?;
            offset += part;
        }
    }
    check_ready(io, suit.check)
}

/// Checked native port for the closed cold-power and BBMCU0 prefix only.
/// It grants no DMA/ring, RF table, interrupt, MAC1 bank or packet enable
/// surface. A register/access/time failure latches this port permanently.
pub(super) struct NativeRegs<'a> {
    region: &'a MmioRegion,
    authority: &'a Cap<BusDeviceCap, Write>,
    fault: Option<power::Error>,
    cancelled: Option<&'a core::sync::atomic::AtomicBool>,
}
impl<'a> NativeRegs<'a> {
    /// # Safety
    /// The exact capability and Device-mapped BAR belong to one exclusive
    /// actual RTL8922A PCI function. Caller independently verified BME clear
    /// and temporal cold/reset quiescence with no published DMA. The mapping
    /// outlives this port; no concurrent reset, removal, firmware or BAR user.
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
    fn cancellation(&mut self) -> Result<(), power::Error> {
        if self
            .cancelled
            .is_some_and(|flag| flag.load(core::sync::atomic::Ordering::Acquire))
        {
            return self.latch(Err(power::Error::Access));
        }
        Ok(())
    }
    fn latch<T>(&mut self, result: Result<T, power::Error>) -> Result<T, power::Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if let Err(error) = result {
            self.fault = Some(error);
        }
        result
    }
    fn checked<T>(
        &mut self,
        address: u32,
        width: u32,
        write: bool,
        operation: impl FnOnce(&MmioRegion, u64) -> T,
    ) -> Result<T, power::Error> {
        self.cancellation()?;
        if let Some(error) = self.fault {
            return Err(error);
        }
        let result = crate::rtw88::pci_park::invoke(self.authority, || {
            let permitted = match width {
                1 => [
                    p::R_BE_FEN_RST_ENABLE,
                    p::R_BE_ANAPAR_POW_MAC,
                    p::R_BE_PLATFORM_ENABLE,
                ]
                .contains(&address),
                2 => address == f::R_BE_BOOT_REASON,
                4 => {
                    let controls = [
                        p::R_BE_SYSON_FSM_MON,
                        p::R_BE_HCI_OPT_CTRL,
                        p::R_BE_SYS_PW_CTRL,
                        p::R_BE_WLLPS_CTRL,
                        super::mac::R_BE_WLRESUME_CTRL as u32,
                        p::R_BE_AFE_ON_CTRL1,
                        p::R_BE_FEN_RST_ENABLE,
                        p::R_BE_SYS_SDIO_CTRL,
                        p::R_BE_SYS_ADIE_PAD_PWR_CTRL,
                        p::R_BE_WLAN_XTAL_SI_CTRL,
                        p::R_BE_PMC_DBG_CTRL2,
                        p::R_BE_SYS_ISO_CTRL,
                        p::R_BE_DMAC_FUNC_EN,
                        p::R_BE_CMAC_SHARE_FUNC_EN,
                        f::R_BE_AFE_CTRL1,
                        f::R_BE_PLATFORM_ENABLE,
                        f::R_BE_CK_EN,
                        f::R_BE_CMAC_FUNC_EN,
                        f::R_BE_DMAC_SYS_CR32B,
                        f::R_BE_MEM_PWR_CTRL,
                        f::R_BE_WCPU_FW_CTRL,
                        f::R_BE_DCPU_PLATFORM_ENABLE,
                        f::R_BE_UDM0,
                        f::R_BE_UDM1,
                        f::R_BE_UDM2,
                        f::R_BE_HALT_C2H,
                        f::R_BE_HALT_H2C,
                        f::R_BE_BOOT_DBG,
                        f::R_BE_HALT_H2C_CTRL,
                        f::R_BE_HALT_C2H_CTRL,
                        f::R_BE_HISR0,
                        f::R_BE_SYS_CLK_CTRL,
                        f::R_BE_SYS_CFG5,
                        f::R_BE_SECURE_BOOT_MALLOC_INFO,
                        f::R_BE_GPIO_MUXCFG,
                        f::R_BE_FW_AUTO_CAL_DELAY,
                        f::R_BE_HCI_FUNC_EN,
                    ];
                    controls.contains(&address)
                        || super::pci_pre_init_8922a::checked::permits32(address, write)
                        || !write && [p::R_BE_IC_PWR_STATE, p::R_BE_SYS_CHIPINFO].contains(&address)
                        || write
                            && f::BB_MCU0_INIT_REG
                                .iter()
                                .any(|(offset, _)| address == offset + f::BBMCU_ADDR_OFFSET)
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
        self.latch(result)
    }
}
impl Regs for NativeRegs<'_> {
    fn binding(&self) -> Binding {
        Binding {
            slot: self.authority.slot(),
            phys: self.region.phys.raw(),
            virt: self.region.virt,
            len: self.region.len,
        }
    }
    fn current(&mut self) -> Result<(), power::Error> {
        self.cancellation()?;
        if let Some(error) = self.fault {
            return Err(error);
        }
        let result =
            crate::rtw88::pci_park::invoke(self.authority, || ()).map_err(|_| power::Error::Access);
        self.latch(result)
    }
    fn read8(&mut self, address: u32) -> Result<u8, power::Error> {
        let result = self
            .checked(address, 1, false, |region, offset| {
                // SAFETY: checked current grant, source register, width and BAR
                // extent; constructor requires one exclusive live Device mapping.
                unsafe { region.read8(offset) }
            })
            .and_then(|value| {
                (value != u8::MAX)
                    .then_some(value)
                    .ok_or(power::Error::Gone)
            });
        self.latch(result)
    }
    fn read16(&mut self, address: u32) -> Result<u16, power::Error> {
        let result = self
            .checked(address, 2, false, |region, offset| {
                // SAFETY: checked current grant, source register, width and BAR
                // extent; constructor requires one exclusive live Device mapping.
                unsafe { region.read16(offset) }
            })
            .and_then(|value| {
                (value != u16::MAX)
                    .then_some(value)
                    .ok_or(power::Error::Gone)
            });
        self.latch(result)
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        let result = self
            .checked(address, 4, false, |region, offset| {
                // SAFETY: checked current grant, source register, width and BAR
                // extent; constructor requires one exclusive live Device mapping.
                unsafe { region.read32(offset) }
            })
            .and_then(|value| {
                (value != u32::MAX)
                    .then_some(value)
                    .ok_or(power::Error::Gone)
            });
        self.latch(result)
    }
    fn write8(&mut self, address: u32, value: u8) -> Result<(), power::Error> {
        self.checked(address, 1, true, |region, offset| {
            // SAFETY: current grant, source register, alignment and extent
            // were checked; exclusive mapping is required by the constructor.
            unsafe { region.write8(offset, value) }
        })
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error> {
        self.checked(address, 2, true, |region, offset| {
            // SAFETY: current grant, source register, alignment and extent
            // were checked; exclusive mapping is required by the constructor.
            unsafe { region.write16(offset, value) }
        })
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        if address == f::R_BE_HAXI_DMA_STOP1 && value & 0x8000_7fff != 0x8000_7fff {
            return self.latch(Err(power::Error::Access));
        }
        if address == f::R_BE_HAXI_INIT_CFG1 && value & 0xb0 != 0x80 {
            return self.latch(Err(power::Error::Access));
        }
        if address == f::R_BE_CMAC_FUNC_EN && value & PACKET != 0 {
            return self.latch(Err(power::Error::Access));
        }
        if f::BB_MCU0_INIT_REG
            .iter()
            .any(|(offset, _)| address == offset + f::BBMCU_ADDR_OFFSET)
            && !f::BB_MCU0_INIT_REG.iter().any(|(offset, expected)| {
                address == offset + f::BBMCU_ADDR_OFFSET && value == *expected
            })
        {
            return self.latch(Err(power::Error::Access));
        }
        self.checked(address, 4, true, |region, offset| {
            // SAFETY: current grant, source register, alignment and extent
            // were checked; exclusive mapping is required by the constructor.
            unsafe { region.write32(offset, value) }
        })
    }
    fn poll32(&mut self, a: u32, mask: u32, expected: u32, us: u64) -> Result<(), power::Error> {
        self.current()?;
        if !(1..=3_000_000).contains(&us) || mask == 0 || expected & !mask != 0 {
            return self.latch(Err(power::Error::Access));
        }
        let mut fault = None;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read32(a) {
                Ok(value) => value & mask == expected,
                Err(error) => {
                    fault = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        let result = match fault {
            Some(error) => Err(error),
            None if done => self.current(),
            None => Err(power::Error::Timeout),
        };
        self.latch(result)
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        self.current()?;
        if us > 5_000 {
            return self.latch(Err(power::Error::Access));
        }
        let mut fault = None;
        let _ = narf_scheduler::responsive_spin_until(
            || match self.current() {
                Ok(()) => false,
                Err(error) => {
                    fault = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        let result = fault.map_or_else(|| self.current(), Err);
        self.latch(result)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "cold_8922a_tests.rs"]
mod tests;
