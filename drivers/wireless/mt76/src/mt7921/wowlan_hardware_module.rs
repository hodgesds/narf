//! The module build's wake route: none.
//!
//! Built in, `wowlan_hardware.rs` arms the function's PME route and moves it
//! through PCI D3hot for WoWLAN system suspend. A `.ko` takes part in no
//! system PM transition and has no PMCSR/PME export, so the function stays
//! in D0, MMIO is always ready, and every wake-route step reports that the
//! firmware feature is unavailable. The station owner treats that exactly as
//! built in treats a platform without a usable wake route.

use super::{Error, Hardware};
use crate::platform::power::SystemSleepState;

/// No retained wake route or power transition (the built-in `Wake`'s place
/// in `Hardware`).
#[derive(Debug, Default)]
pub(super) struct Wake {
    _none: (),
}

impl Wake {
    pub(super) fn mmio_ready(&self) -> bool {
        true
    }

    pub(super) fn settled(&self, _now_ns: u64) -> bool {
        true
    }
}

impl Hardware {
    pub(super) fn wake_route_available(&self) -> Result<bool, Error> {
        Ok(false)
    }

    pub(super) fn prepare_wake_route(&mut self, _target: SystemSleepState) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }

    pub(super) fn arm_wake_route(&mut self, _target: SystemSleepState) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }

    pub(super) fn enter_wake_d3hot(&mut self) -> Result<(), Error> {
        Err(Error::UnsupportedFirmware)
    }

    pub(super) fn verify_wake_d3hot(&mut self) -> Result<(), Error> {
        Err(Error::Busy)
    }

    pub(super) fn begin_wake_d0(&mut self) -> Result<bool, Error> {
        Ok(false)
    }

    pub(super) fn verify_wake_d0(&mut self) -> Result<(), Error> {
        Err(Error::Busy)
    }

    pub(super) fn disarm_wake_route(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
