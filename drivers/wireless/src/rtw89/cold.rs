// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One backend through actual cold power, factory discovery and runtime power.
//! No system-memory DMA, firmware or radio publication occurs in this phase.
use super::{
    factory::{self, Factory, Identity, Source},
    pci_basic::{self, Basic},
    pcie::Interface,
    power::{self, Calibration, Phase as PowerPhase, Power},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Register(power::Error),
    Factory(factory::Error),
    Terminal,
    Profile,
}
impl From<power::Error> for Error {
    fn from(value: power::Error) -> Self {
        Self::Register(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    New,
    DiscoveryPower,
    Factory,
    PowerOff,
    Basic,
    RuntimePower,
    Ready,
    Terminal,
}
#[derive(Debug)]
pub struct Cold<I> {
    power: Power<I>,
    factory: Factory,
    basic: Basic,
    phase: Phase,
}
/// Constructible only by a completed cold operation. The same backend and
/// factory data move into the native command owner without recreating power,
/// PHY/DDV controller state or a ready receipt from caller-supplied booleans.
#[derive(Debug)]
pub struct Prepared<I> {
    io: I,
    basic: Basic,
    factory: Factory,
}
impl<I> Prepared<I> {
    pub(super) fn into_parts(self) -> (I, Basic, Factory) {
        (self.io, self.basic, self.factory)
    }
}
impl<I: Interface + Source> Cold<I> {
    pub fn new(io: I) -> Self {
        Self {
            power: Power::new(io),
            factory: Factory::default(),
            basic: Basic::default(),
            phase: Phase::New,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn identity(&self) -> Option<Identity> {
        if self.phase == Phase::Ready {
            self.factory.identity()
        } else {
            None
        }
    }
    /// # Safety
    /// This exact function is exclusively owned with verified BME off and old
    /// DMA independently stopped/fenced. No concurrent power/reset, producers,
    /// IRQ, config, EFUSE or PHY access. The native claim parks and checks BME;
    /// parking/MAC-OFF here never supplies a DMA-reclamation proof.
    pub async unsafe fn prepare(&mut self) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Terminal);
        }
        self.phase = Phase::DiscoveryPower;
        let result = self.prepare_inner().await;
        if result.is_err() {
            self.phase = Phase::Terminal;
        }
        result
    }
    async fn prepare_inner(&mut self) -> Result<(), Error> {
        let (chip, cut) = self.power.io().profile();
        // Linux's first discovery power-on has no decoded EFUSE calibration.
        // It is followed by actual factory reads, off, and a qualified second
        // power-on; it does not substitute default values for factory reads.
        // SAFETY: delegated exclusive, independently fenced BME-off contract.
        unsafe {
            self.power
                .normalize_inherited(chip, cut, Calibration::default())
                .await?;
        }
        self.phase = Phase::Factory;
        self.factory
            .read(self.power.io())
            .await
            .map_err(Error::Factory)?;
        let identity = self.factory.identity().ok_or(Error::Profile)?;
        self.phase = Phase::PowerOff;
        // SAFETY: no DMA has been published and the original fence/parking
        // contract remains held across the complete discovery lifecycle.
        unsafe {
            self.power.power_off().await?;
        }
        self.power.qualify_factory(identity)?;
        self.phase = Phase::Basic;
        // SAFETY: the same backend is retained after confirmed MAC-OFF; the
        // PCIe PHY/config window remains owned, parked and serialized.
        unsafe {
            self.basic.prepare(self.power.io(), chip).await?;
        }
        self.phase = Phase::RuntimePower;
        let cut = self
            .power
            .power_on(chip, identity.cut(), identity.calibration())
            .await?;
        if cut != identity.cut() || self.power.io().profile() != (chip, cut) {
            return Err(Error::Profile);
        }
        self.phase = Phase::Ready;
        Ok(())
    }
    pub fn into_prepared(self) -> Result<Prepared<I>, Error> {
        if self.phase != Phase::Ready
            || self.power.phase() != PowerPhase::Powered
            || self.basic.state() != pci_basic::State::Ready
            || self.factory.state() != factory::State::Ready
        {
            return Err(Error::Terminal);
        }
        let identity = self.factory.identity().ok_or(Error::Profile)?;
        let (io, chip, cut, calibration) = self.power.into_powered()?;
        if (chip, cut, calibration) != (identity.chip(), identity.cut(), identity.calibration())
            || io.profile() != (chip, cut)
        {
            return Err(Error::Profile);
        }
        Ok(Prepared {
            io,
            basic: self.basic,
            factory: self.factory,
        })
    }
}
