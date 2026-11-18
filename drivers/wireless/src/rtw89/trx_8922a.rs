// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked RTL8922A MAC0/PCIe/SCC TRX configuration while packet DMA is held.
//! Linux mac_be.c::trx_init_be (dmac_init_be then cmac_init_be, IMRs and host
//! release-report setup). Native HAXI remains positively stopped throughout;
//! CMAC TX/RX stay closed. Configuration alone grants no RF/RX/station use.
use super::{cold_8922a as cold, power};
use cold::Regs;
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};

#[derive(Clone, Copy)]
enum Op {
    U8(u32, u32, u32),
    U16(u32, u32, u32),
    U32(u32, u32, u32),
    W16(u32, u32),
    W32(u32, u32, u32),
    /// Source command/pulse, followed by its source completion check where
    /// one exists. Not a sampled assertion or a DMA-retirement receipt.
    C32(u32, u32, u32),
    P16(u32, u32, u32, u32),
    P32(u32, u32, u32, u32),
    Read32(u32),
    Delay(u32),
}
#[path = "trx_8922a_program.rs"]
mod program;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Io(power::Error),
    State,
    Identity,
    Readback(u32),
    Accounting,
}
impl From<power::Error> for Error {
    fn from(e: power::Error) -> Self {
        Self::Io(e)
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum State {
    #[default]
    New,
    Configuring,
    ConfiguredClosed,
    Failed(Error),
}
#[derive(Default)]
pub(super) struct Trx {
    state: State,
    binding: Option<cold::Binding>,
}
impl Trx {
    pub(super) fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Original successful NORMAL+BBMCU0 download and closed SystemConfigured
    /// owner, exact live original function/BAR, exclusive firmware/config/DMA
    /// ownership. Every pending CH12 descriptor has its actual RP consumption
    /// receipt; ALL original mappings remain owned. HAXI is stopped and idle,
    /// WCPU alive, MAC0 fully powered, MAC1 off, no IRQ/ordinary producer.
    pub(super) unsafe fn configure(&mut self, io: &mut impl Regs, cv: u8) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::State);
        }
        self.state = State::Configuring;
        self.binding = Some(io.binding());
        let r = (|| {
            closed(io)?;
            run(io, program::DLE_PRELOAD)?;
            run(io, program::HFC)?;
            // mac.c::hfc_pub_info_chk: exact actual used+available accounting,
            // not an expected-ready fixture value or firmware-ready proxy.
            let used = read(io, program::R_BE_PUB_PAGE_INFO1)?;
            let available = read(io, program::R_BE_PUB_PAGE_INFO2)?;
            let field = |v: u32, mask: u32| (v & mask) >> mask.trailing_zeros();
            if field(used, program::B_BE_G0_USE_PG_MASK)
                + field(used, program::B_BE_G1_USE_PG_MASK)
                + field(available, program::B_BE_PUB_AVAL_PG_MASK)
                != 3302
            {
                return Err(Error::Accounting);
            }
            run(io, program::DMAC)?;
            run(io, program::CMAC_A)?;
            if cv == 0 {
                run(io, program::CAV_RSC)?;
            }
            run(io, program::CMAC_B)?;
            run(io, program::FINISH)?;
            closed(io)
        })();
        self.state = match r {
            Ok(()) => State::ConfiguredClosed,
            Err(e) => State::Failed(e),
        };
        r
    }
    pub(super) fn current(&mut self, io: &mut impl Regs) -> Result<(), Error> {
        if self.state != State::ConfiguredClosed {
            return Err(Error::State);
        }
        let r = if self.binding != Some(io.binding()) {
            Err(Error::Identity)
        } else {
            closed(io)
        };
        if let Err(e) = r {
            self.state = State::Failed(e)
        }
        r
    }
}
fn read(io: &mut impl Regs, a: u32) -> Result<u32, Error> {
    io.current()?;
    let v = io.read32(a)?;
    if v == u32::MAX {
        return Err(power::Error::Gone.into());
    }
    Ok(v)
}
fn check(io: &mut impl Regs, a: u32, mask: u32, want: u32) -> Result<(), Error> {
    if read(io, a)? & mask != want {
        return Err(Error::Readback(a));
    }
    Ok(())
}
fn closed(io: &mut impl Regs) -> Result<(), Error> {
    check(io, 0x24, 0x1f00_001f, 0x1f00_0000)?;
    check(io, 0x84, 0x0303_0303, 0x0201_0003)?;
    check(io, 0x88, 0x802, 2)?;
    check(io, 0x8400, 0x7b7f_4f80, 0x7b7f_4f80)?;
    check(io, 0x10000, 0xf000_01ff, 0xc000_01ff)?;
    check(io, 0xb010, 0x8000_7fff, 0x8000_7fff)?;
    check(io, 0xb000, 0xb0, 0x80)?;
    check(io, 0xb01c, 0x8003_7fff, 0)
}
fn run(io: &mut impl Regs, ops: &[Op]) -> Result<(), Error> {
    for &op in ops {
        closed(io)?;
        match op {
            Op::U32(a, clear, set) | Op::C32(a, clear, set) => {
                let value = (read(io, a)? & !clear) | set;
                io.write32(a, value)?;
                if matches!(op, Op::U32(..)) {
                    check(io, a, clear | set, set)?;
                }
            }
            Op::U8(a, clear, set) => {
                let old = io.read8(a)?;
                if old == u8::MAX {
                    return Err(power::Error::Gone.into());
                }
                io.write8(a, (old & !(clear as u8)) | set as u8)?;
                let actual = io.read8(a)?;
                if actual == u8::MAX {
                    return Err(power::Error::Gone.into());
                }
                if u32::from(actual) & (clear | set) != set {
                    return Err(Error::Readback(a));
                }
            }
            Op::U16(a, clear, set) => {
                let old = io.read16(a)?;
                if old == u16::MAX {
                    return Err(power::Error::Gone.into());
                }
                io.write16(a, (old & !(clear as u16)) | set as u16)?;
                let actual = io.read16(a)?;
                if actual == u16::MAX {
                    return Err(power::Error::Gone.into());
                }
                if u32::from(actual) & (clear | set) != set {
                    return Err(Error::Readback(a));
                }
            }
            Op::W16(a, value) => {
                io.write16(a, value as u16)?;
                let actual = io.read16(a)?;
                if actual == u16::MAX {
                    return Err(power::Error::Gone.into());
                }
                if u32::from(actual) != value {
                    return Err(Error::Readback(a));
                }
            }
            Op::W32(a, value, mask) => {
                io.write32(a, value)?;
                let actual = io.read32(a)?;
                // Source CMAC_ERR_IMR writes all ones deliberately. That exact
                // configured data value is allowed only at its literal source
                // address, between positive common power/packet observations.
                if actual == u32::MAX && !(value == u32::MAX && program::ONES_READBACK.contains(&a))
                {
                    return Err(power::Error::Gone.into());
                }
                if actual & mask != value & mask {
                    return Err(Error::Readback(a));
                }
            }
            Op::P32(a, mask, want, us) => io.poll32(a, mask, want, u64::from(us))?,
            Op::P16(a, mask, want, us) => {
                let mut fault = None;
                let done = narf_scheduler::responsive_spin_until(
                    || match io.read16(a) {
                        Ok(u16::MAX) => {
                            fault = Some(power::Error::Gone);
                            true
                        }
                        Ok(v) => u32::from(v) & mask == want,
                        Err(e) => {
                            fault = Some(e);
                            true
                        }
                    },
                    narf_time::Deadline::after_us(u64::from(us)),
                );
                if let Some(e) = fault {
                    return Err(e.into());
                }
                if !done {
                    return Err(power::Error::Timeout.into());
                }
            }
            Op::Read32(a) => {
                read(io, a)?;
            }
            Op::Delay(us) => io.delay_us(u64::from(us))?,
        }
        closed(io)?;
    }
    Ok(())
}

pub(super) struct Native<'a> {
    region: &'a MmioRegion,
    authority: &'a Cap<BusDeviceCap, Write>,
    cancelled: &'a core::sync::atomic::AtomicBool,
    fault: Option<power::Error>,
}
impl<'a> Native<'a> {
    /// # Safety
    /// Exact original RTL8922A live Device BAR/current capability; retained
    /// closed FWDL/System/owned DMA receipt, no concurrent source or IRQ user.
    pub(super) unsafe fn new(
        region: &'a MmioRegion,
        authority: &'a Cap<BusDeviceCap, Write>,
        cancelled: &'a core::sync::atomic::AtomicBool,
    ) -> Self {
        Self {
            region,
            authority,
            cancelled,
            fault: None,
        }
    }
    fn latch<T>(&mut self, r: Result<T, power::Error>) -> Result<T, power::Error> {
        if let Some(e) = self.fault {
            return Err(e);
        }
        if let Err(e) = r {
            self.fault = Some(e)
        }
        r
    }
    fn access<T>(
        &mut self,
        a: u32,
        width: u32,
        write: bool,
        op: impl FnOnce(&MmioRegion, u64) -> T,
    ) -> Result<T, power::Error> {
        self.current()?;
        let result = crate::rtw88::pci_park::invoke(self.authority, || {
            let common = !write
                && width == 4
                && [0x24, 0x84, 0x88, 0x8400, 0x10000, 0xb010, 0xb000, 0xb01c].contains(&a);
            if !(common || program::permits(a, width, write))
                || a % width != 0
                || u64::from(a)
                    .checked_add(u64::from(width))
                    .is_none_or(|end| end > self.region.len)
            {
                return Err(power::Error::Access);
            }
            Ok(op(self.region, u64::from(a)))
        })
        .map_err(|_| power::Error::Access)
        .and_then(core::convert::identity);
        self.latch(result)
    }
}
impl Regs for Native<'_> {
    fn binding(&self) -> cold::Binding {
        cold::Binding::observe(self.region, self.authority)
    }
    fn current(&mut self) -> Result<(), power::Error> {
        if self.cancelled.load(core::sync::atomic::Ordering::Acquire) {
            return self.latch(Err(power::Error::Access));
        }
        if let Some(e) = self.fault {
            return Err(e);
        }
        let r =
            crate::rtw88::pci_park::invoke(self.authority, || ()).map_err(|_| power::Error::Access);
        self.latch(r)
    }
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access(a, 1, false, |r, o| {
            // SAFETY: exact current grant, source address/width/extent/alignment;
            // constructor requires one exclusive live Device mapping.
            unsafe { r.read8(o) }
        })
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access(a, 2, false, |r, o| {
            // SAFETY: exact current grant and checked aligned source word.
            unsafe { r.read16(o) }
        })
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access(a, 4, false, |r, o| {
            // SAFETY: exact current grant, source dword, alignment and extent.
            unsafe { r.read32(o) }
        })
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access(a, 1, true, |r, o| {
            // SAFETY: current grant and exact writable source byte/extent.
            unsafe { r.write8(o, v) }
        })
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access(a, 2, true, |r, o| {
            // SAFETY: current grant and exact writable aligned source word.
            unsafe { r.write16(o, v) }
        })
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        if a == 0x10000 && v & 0x3000_0000 != 0 {
            return self.latch(Err(power::Error::Access));
        }
        self.access(a, 4, true, |r, o| {
            // SAFETY: current grant and exact writable aligned source dword.
            unsafe { r.write32(o, v) }
        })
    }
    fn poll32(&mut self, a: u32, mask: u32, want: u32, us: u64) -> Result<(), power::Error> {
        if mask == 0 || want & !mask != 0 || !(1..=2000).contains(&us) {
            return self.latch(Err(power::Error::Access));
        }
        let mut fault = None;
        let done = narf_scheduler::responsive_spin_until(
            || match self.read32(a) {
                Ok(u32::MAX) => {
                    fault = Some(power::Error::Gone);
                    true
                }
                Ok(v) => v & mask == want,
                Err(e) => {
                    fault = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        self.latch(fault.map_or(
            if done {
                Ok(())
            } else {
                Err(power::Error::Timeout)
            },
            Err,
        ))
    }
    fn delay_us(&mut self, us: u64) -> Result<(), power::Error> {
        if us > 10 {
            return self.latch(Err(power::Error::Access));
        }
        self.current()?;
        let mut error = None;
        let _ = narf_scheduler::responsive_spin_until(
            || match self.current() {
                Ok(()) => false,
                Err(e) => {
                    error = Some(e);
                    true
                }
            },
            narf_time::Deadline::after_us(us),
        );
        error.map_or(Ok(()), Err)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "trx_8922a_tests.rs"]
mod tests;
