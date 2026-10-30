//! Explicit test-only platform model for native WoW lifecycle regressions.
//! A default model has no platform route; fixture
//! admission never becomes a production backend input or Power grant.
use super::*;
use narf_power::system_pm::SystemSleepState;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) enum Power {
    #[default]
    D0,
    EnteringD3,
    D3Hot,
    EnteringD0,
}

#[derive(Debug, Default)]
pub(super) struct Fixture {
    pub(super) route_available: bool,
    pub(super) armed: bool,
    pub(super) power: Power,
    pub(super) written_at: Option<u64>,
    pub(super) target: Option<SystemSleepState>,
    pub(super) arm_failure: bool,
    pub(super) disarm_failure: bool,
    pub(super) power_failure: bool,
    pub(super) hold_offload_ack: Arc<AtomicBool>,
}

impl Model {
    pub(super) fn wow_prepare_route(&mut self, target: SystemSleepState) -> Result<(), Error> {
        self.check()?;
        if !self.pm.wow.route_available {
            return Err(Error::UnsupportedFirmware);
        }
        if self.pm.wow.armed || self.pm.wow.power != Power::D0 {
            return Err(Error::Busy);
        }
        self.pm.trace.push("route-probe");
        self.pm.wow.target = Some(target);
        Ok(())
    }

    pub(super) fn wow_arm_route(&mut self, target: SystemSleepState) -> Result<(), Error> {
        self.check()?;
        if !self.pm.wow.route_available || self.pm.wow.armed || self.pm.wow.target != Some(target) {
            return Err(Error::Busy);
        }
        self.pm.trace.push("pme-arm");
        self.pm.wow.armed = true;
        if self.pm.wow.arm_failure {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }

    pub(super) fn wow_settled(&self) -> bool {
        self.pm
            .wow
            .written_at
            .is_none_or(|at| self.ticks.get().saturating_sub(at) >= 10_000_000)
    }

    pub(super) fn wow_enter_d3hot(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.pm.wow.armed
            || self.pm.dma_enabled
            || !self.pm.firmware_owned
            || self.pm.wow.power != Power::D0
        {
            return Err(Error::Busy);
        }
        self.pm.trace.push("d3hot");
        self.pm.wow.power = Power::EnteringD3;
        self.pm.wow.written_at = Some(self.now_ns());
        if self.pm.wow.power_failure {
            Err(Error::Register)
        } else {
            Ok(())
        }
    }

    pub(super) fn wow_verify_d3hot(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.wow_settled() || self.pm.wow.power != Power::EnteringD3 {
            return Err(Error::Busy);
        }
        self.pm.wow.power = Power::D3Hot;
        self.pm.wow.written_at = None;
        Ok(())
    }

    pub(super) fn wow_begin_d0(&mut self) -> Result<bool, Error> {
        self.check()?;
        if self.pm.wow.power == Power::D0 {
            return Ok(false);
        }
        if !self.wow_settled() {
            return Err(Error::Busy);
        }
        self.pm.trace.push("d0");
        self.pm.wow.power = Power::EnteringD0;
        self.pm.wow.written_at = Some(self.now_ns());
        Ok(true)
    }

    pub(super) fn wow_verify_d0(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.wow_settled() || self.pm.wow.power != Power::EnteringD0 {
            return Err(Error::Busy);
        }
        self.pm.wow.power = Power::D0;
        self.pm.wow.written_at = None;
        Ok(())
    }

    pub(super) fn wow_disarm_route(&mut self) -> Result<(), Error> {
        self.check()?;
        if self.pm.wow.power != Power::D0 || self.pm.wow.written_at.is_some() {
            return Err(Error::Busy);
        }
        if self.pm.wow.disarm_failure {
            return Err(Error::Register);
        }
        if self.pm.wow.armed {
            self.pm.trace.push("pme-disarm");
            self.pm.wow.armed = false;
        }
        Ok(())
    }
}
