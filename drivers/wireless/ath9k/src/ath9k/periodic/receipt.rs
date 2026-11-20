// SPDX-License-Identifier: GPL-2.0-or-later
//! Separate live calibration state; the initial H receipt is immutable.
//! The sole Packet/Native owner supplies its current source/PCI adapter
//! and actual software+hardware quiet boundary.
use super::{AniSettings, Correction, Error, Io, Mode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Receipt {
    pub correction: Correction,
    pub pa: Option<u8>,
    pub noise: [i16; 2],
    pub ani: AniSettings,
    agc: u32,
    cca: [u32; 2],
}
impl Receipt {
    pub fn initial(
        io: &impl Io,
        report: super::super::calibration::Report,
        wide: Option<super::super::calibration::wide::WideReport>,
    ) -> Result<Self, Error> {
        let correction = Correction {
            iq: 0x800 | (u32::from(report.iq_i) << 5) | (report.iq_q as u32 & 31),
            adc: wide.map(|actual| actual.adc),
        };
        if wide.is_some_and(|actual| actual.report != report) {
            return Err(Error::State);
        }
        if Correction::read(io, wide.is_some())? != correction {
            return Err(Error::Descriptor);
        }
        let agc = io.read(0x9860)? & 0x28002;
        if agc & 2 != 0 {
            return Err(Error::State);
        }
        let control = io.read(0x9864)? & 511;
        let extension = if wide.is_some() {
            io.read(0x99bc)? & 511
        } else {
            control
        };
        let receipt = Self {
            correction,
            pa: report.pa_offset,
            noise: [
                report.noise_dbm,
                wide.map_or(report.noise_dbm, |actual| actual.ext_noise_dbm),
            ],
            ani: AniSettings::read(io)?,
            agc,
            cca: [control, extension],
        };
        receipt.readback(io, false)?;
        Ok(receipt)
    }
    fn readback(self, io: &impl Io, measuring: bool) -> Result<(), Error> {
        if measuring {
            if io.read(0x9920)? & 0xfff != self.correction.iq
                || self
                    .correction
                    .adc
                    .is_some_and(|value| io.read(0x99b4) != Ok(value))
            {
                return Err(Error::Descriptor);
            }
        } else {
            self.correction.readback(io)?;
        }
        if let Some(offset) = self.pa {
            if io.read(0x7834)? >> 20 & 63 != u32::from(offset >> 1)
                || io.read(0x7828)? >> 25 & 1 != u32::from(offset & 1)
            {
                return Err(Error::Descriptor);
            }
        }
        if io.read(0x9808)? & (1 << 27) != 0 {
            return Err(Error::Descriptor);
        }
        self.ani.readback(io)?;
        if io.read(0x9864)? & 511 != self.cca[0]
            || self.correction.adc.is_some() && io.read(0x99bc)? & 511 != self.cca[1]
        {
            return Err(Error::Descriptor);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Stable,
    Measuring(Mode, u64),
    Noise(u64),
    Mutating,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Live {
    receipt: Receipt,
    phase: Phase,
    serial: u64,
}
/// Consumed only by a completion of this exact mutation serial. A callback
/// cannot reuse an old mutation to authorize publication or mint a receipt.
pub(in crate::ath9k) struct Mutation {
    serial: u64,
}
impl Live {
    pub fn new(receipt: Receipt) -> Self {
        Self {
            receipt,
            phase: Phase::Stable,
            serial: 0,
        }
    }
    /// Validate a same-native-source snapshot transition before installation.
    /// No cached stable receipt can reopen a newer mutation, and no receipt
    /// can reopen a failed slot. Raw reads here must themselves retain the
    /// actual current P/base/PCI invocation without holding the slot lock.
    pub fn install_after(self, previous: Option<Self>, io: &impl Io) -> Result<(), Error> {
        let Some(previous) = previous else {
            if self.serial != 0 || self.phase != Phase::Stable {
                return Err(Error::State);
            }
            return self.readback(io);
        };
        if previous.phase == Phase::Failed || self.phase == Phase::Failed {
            return Err(Error::State);
        }
        if self == previous {
            return if self.phase == Phase::Mutating {
                quiet(io)
            } else {
                self.readback(io)
            };
        }
        if self.phase == Phase::Mutating
            && previous.serial.checked_add(1) == Some(self.serial)
            && self.receipt == previous.receipt
        {
            if let Phase::Measuring(mode, began) = previous.phase {
                // The exact expired sample has a dedicated clearing/retry
                // continuation; age expiry never grants ordinary access.
                if io.now_us() < began
                    || io.read(0x99f0)? != mode.register()
                    || io.read(0x9920)? & 0xf000 != 10 << 12
                    || io.read(0x9860)? & 0x28002 != previous.receipt.agc
                {
                    return Err(Error::Descriptor);
                }
                previous.receipt.readback(io, true)?;
            } else {
                previous.readback(io)?;
            }
            return quiet(io);
        }
        if previous.phase != Phase::Mutating || self.serial != previous.serial {
            return Err(Error::State);
        }
        if matches!(self.phase, Phase::Measuring(..) | Phase::Noise(..))
            && self.receipt != previous.receipt
        {
            return Err(Error::State);
        }
        quiet(io)?;
        self.readback(io)
    }
    /// Called inside actual current P/base/PCI invocation for every native
    /// MMIO, DMA descriptor/payload publication and copied-frame admission.
    /// Host mutations always reject ordinary access. Hardware measurement
    /// permits traffic only under exact unchanged prior coefficients/mode.
    pub fn readback(self, io: &impl Io) -> Result<(), Error> {
        match self.phase {
            Phase::Stable => {
                self.receipt.readback(io, false)?;
                if io.read(0x9860)? & 0x28002 != self.receipt.agc {
                    return Err(Error::Descriptor);
                }
            }
            Phase::Measuring(mode, began) => {
                self.receipt.readback(io, true)?;
                let now = io.now_us();
                let iq = io.read(0x9920)?;
                if now < began
                    || now - began >= 30_000_000
                    || iq & 0xf000 != 10 << 12
                    || io.read(0x99f0)? != mode.register()
                    || io.read(0x9860)? & 0x28002 != self.receipt.agc
                {
                    return Err(Error::Descriptor);
                }
            }
            Phase::Noise(began) => {
                self.receipt.readback(io, false)?;
                let now = io.now_us();
                if now < began || now - began >= 222_000 || io.read(0x9860)? & 0x28000 != 0x28000 {
                    return Err(Error::Descriptor);
                }
            }
            Phase::Mutating | Phase::Failed => return Err(Error::State),
        }
        Ok(())
    }
    /// Caller first drains actual native TX/control tickets, retains every
    /// RX mapping and admits the current quiet boundary. Register requests
    /// alone cannot establish that packet/BA/key/copy ownership prerequisite.
    pub fn begin(&mut self, io: &impl Io) -> Result<Mutation, Error> {
        self.readback(io)?;
        quiet(io)?;
        self.serial = self.serial.checked_add(1).ok_or(Error::State)?;
        self.phase = Phase::Mutating;
        Ok(Mutation {
            serial: self.serial,
        })
    }
    /// A30-second source timeout already rejects ordinary DMA/copy access.
    /// The retained worker may still clear the exact old DO_CAL operation
    /// under current P/PCI and actual quiet ownership. It cannot use this
    /// continuation to access DATA or claim a fresh measured coefficient.
    pub fn begin_retry(&mut self, io: &impl Io) -> Result<Mutation, Error> {
        let Phase::Measuring(mode, began) = self.phase else {
            return Err(Error::State);
        };
        let now = io.now_us();
        if now < began
            || now - began < 30_000_000
            || io.read(0x99f0)? != mode.register()
            || io.read(0x9920)? & 0xf000 != 10 << 12
            || io.read(0x9860)? & 0x28002 != self.receipt.agc
        {
            return Err(Error::State);
        }
        self.receipt.readback(io, true)?;
        quiet(io)?;
        self.serial = self.serial.checked_add(1).ok_or(Error::State)?;
        self.phase = Phase::Mutating;
        Ok(Mutation {
            serial: self.serial,
        })
    }
    fn token(&self, mutation: &Mutation) -> Result<(), Error> {
        if self.phase != Phase::Mutating || mutation.serial != self.serial {
            return Err(Error::State);
        }
        Ok(())
    }
    pub fn sampling(&mut self, io: &impl Io, mutation: Mutation, mode: Mode) -> Result<(), Error> {
        self.token(&mutation)?;
        quiet(io)?;
        if io.read(0x9920)? & 0x1f000 != 0x1a000
            || io.read(0x99f0)? != mode.register()
            || io.read(0x9860)? & 2 != 0
        {
            return Err(Error::Descriptor);
        }
        self.receipt.readback(io, true)?;
        self.phase = Phase::Measuring(mode, io.now_us());
        let result = self.readback(io);
        if result.is_err() {
            self.fail();
        }
        result
    }
    pub fn noise(&mut self, io: &impl Io, mutation: Mutation) -> Result<(), Error> {
        self.token(&mutation)?;
        quiet(io)?;
        if io.read(0x9860)? & 0x28002 != 0x28002 {
            return Err(Error::Descriptor);
        }
        self.receipt.readback(io, false)?;
        self.phase = Phase::Noise(io.now_us());
        let result = self.readback(io);
        if result.is_err() {
            self.fail();
        }
        result
    }
    /// Only actual algorithm completion supplies updates. The controller
    /// retains the exact Sampler/Noise/Pa/ANI owner, never scheduler intent.
    pub fn complete(
        &mut self,
        io: &impl Io,
        mutation: Mutation,
        correction: Option<Correction>,
        pa: Option<u8>,
        noise: Option<super::noise::Receipt>,
        ani: Option<AniSettings>,
    ) -> Result<Receipt, Error> {
        self.token(&mutation)?;
        quiet(io)?;
        let mut next = self.receipt;
        if let Some(correction) = correction {
            if correction.adc.is_some() != next.correction.adc.is_some() {
                return Err(Error::State);
            }
            next.correction = correction;
        }
        if let Some(pa) = pa {
            if next.pa.is_none() || pa > 127 {
                return Err(Error::State);
            }
            next.pa = Some(pa);
        }
        if let Some(noise) = noise {
            if noise.wide != next.correction.adc.is_some()
                || noise
                    .loaded
                    .iter()
                    .any(|value| !(-127..=-108).contains(value))
            {
                return Err(Error::State);
            }
            next.noise = noise.loaded;
            next.cca = [((-50i32 as u32) << 1) & 511; 2];
            next.agc = 0; // actual completed median load cleared ENA/NUP.
        }
        if let Some(ani) = ani {
            next.ani = ani;
        }
        if io.read(0x9860)? & 0x28002 != next.agc {
            return Err(Error::Descriptor);
        }
        next.readback(io, false)?;
        self.receipt = next;
        self.phase = Phase::Stable;
        Ok(next)
    }
    /// Cancellation/lost source/ambiguous readback closes normal authority;
    /// only the independent existing PCI terminal owner may retire DMA.
    pub fn fail(&mut self) {
        self.phase = Phase::Failed;
    }
}
pub(super) fn quiet(io: &impl Io) -> Result<(), Error> {
    if io.read(0x7044)? & 15 != 2
        || io.read(0x840)? & 0x3ff != 0
        || io.read(0x8048)? & 0x02000020 != 0x02000020
        || io.read(0x806c)? & 0x01f00000 != 0
    {
        return Err(Error::Busy);
    }
    for queue in 0..10 {
        if io.read(0xa00 + queue * 4)? & 3 != 0 {
            return Err(Error::Busy);
        }
    }
    Ok(())
}
