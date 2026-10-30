//! Retained native firmware-owned wake route and PCI PMCSR transitions.
//!
//! This is a child of firmware_transport_hw. Clock-only waits finish every
//! PCI D3hot transition before another configuration transaction. MMIO is
//! refused for the entire retained low-power interval, including a cancelled
//! entry. Endpoint authority never authorizes a Root Port or GPE write.

use super::{Backend, Error, Hardware};
use narf_bus::pci::{self, pme::WakeState, PciPowerState};
use narf_capabilities::Read;
use narf_power::{pci_wake::PciWake, system_pm::SystemSleepState};

#[derive(Debug, Default)]
pub(super) struct Wake {
    route: Option<PciWake>,
    /// Set before a PMCSR write; remains set on any missing receipt.
    d0_required: bool,
    /// Retained across future cancellation, so recovery cannot shorten the
    /// actual PCI D3hot entry/exit delay by starting a new future.
    last_power_write_ns: Option<u64>,
    evidence: narf_power::pci_wake::WakeEvidence,
    target: Option<SystemSleepState>,
}

impl Wake {
    pub(super) fn mmio_ready(&self) -> bool {
        !self.d0_required && self.last_power_write_ns.is_none()
    }

    pub(super) fn settled(&self, now_ns: u64) -> bool {
        self.last_power_write_ns
            .is_none_or(|at| now_ns.saturating_sub(at) >= pci::PM_D3HOT_DELAY_MS * 1_000_000)
    }
}

impl Drop for Wake {
    fn drop(&mut self) {
        if !self.mmio_ready() {
            // No synchronous Drop can await the outstanding PCI interval.
            // Preserve the actual GPE lease/caps rather than running its
            // hardware cleanup during an unknown power transition. Published
            // DMA already has the same no-proof/no-release retention rule.
            if let Some(route) = self.route.take() {
                route.quarantine();
            }
        }
    }
}

impl Hardware {
    pub(super) fn wake_route_available(&self) -> Result<bool, Error> {
        self.check()?;
        if !self.wake.mmio_ready() {
            return Ok(false);
        }
        let read = self
            .authority
            .derive::<Read>()
            .map_err(|_| Error::Authority)?;
        let endpoint = pci::pme::status(&read, &self.device).map_err(|_| Error::Authority)?;
        if endpoint.enabled || !endpoint.supports(WakeState::D3Hot) {
            return Ok(false);
        }
        if self.wake_power_state()? != PciPowerState::D0 {
            return Ok(false);
        }
        match PciWake::discover(&self.authority, self.device) {
            Ok(route) => Ok((narf_power::s2idle::s2idle_supported()
                && route
                    .admits(SystemSleepState::S0Idle, WakeState::D3Hot)
                    .is_ok())
                || (narf_power::suspend::s3_supported()
                    && route.admits(SystemSleepState::S3, WakeState::D3Hot).is_ok())),
            Err(narf_power::pci_wake::WakeError::Authority) => Err(Error::Authority),
            Err(_) => Ok(false),
        }
    }

    pub(super) fn prepare_wake_route(&mut self, target: SystemSleepState) -> Result<(), Error> {
        self.check()?;
        if !self.wake.mmio_ready() {
            return Err(Error::Busy);
        }
        if let Some(route) = self.wake.route.as_mut() {
            self.wake.evidence = route.disarm().map_err(|_| Error::Authority)?;
        }
        self.wake.route = None;
        let read = self
            .authority
            .derive::<Read>()
            .map_err(|_| Error::Authority)?;
        let endpoint = pci::pme::status(&read, &self.device).map_err(|_| Error::Authority)?;
        if endpoint.enabled || !endpoint.supports(WakeState::D3Hot) {
            return Err(Error::Busy);
        }
        if self.wake_power_state()? != PciPowerState::D0 {
            return Err(Error::Busy);
        }
        let route = PciWake::discover(&self.authority, self.device).map_err(wake_error)?;
        route.admits(target, WakeState::D3Hot).map_err(wake_error)?;
        self.wake.route = Some(route);
        self.wake.target = Some(target);
        Ok(())
    }

    pub(super) fn arm_wake_route(&mut self, target: SystemSleepState) -> Result<(), Error> {
        self.check()?;
        if !self.wake.mmio_ready() {
            return Err(Error::Busy);
        }
        self.wake
            .route
            .as_mut()
            .ok_or(Error::Busy)?
            .arm(target, WakeState::D3Hot)
            .map_err(wake_error)
    }

    pub(super) fn wake_power_state(&self) -> Result<PciPowerState, Error> {
        if !self.wake.settled(narf_time::wall::monotonic_ns()) {
            return Err(Error::Busy);
        }
        crate::mt7921::pci::invoke(&self.authority, || {
            pci::power_state(&self.authority, &self.device)
                .map_err(|_| Error::Authority)?
                .ok_or(Error::DeviceGone)
        })
        .map_err(|_| Error::Authority)?
    }

    pub(super) fn enter_wake_d3hot(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.wake.mmio_ready()
            || !self.wake.route.as_ref().is_some_and(PciWake::armed)
            || self.command(pci::cmd::BUS_MASTER, 0)? & pci::cmd::BUS_MASTER != 0
            || self.wake_power_state()? != PciPowerState::D0
        {
            return Err(Error::Busy);
        }
        // The private associated HIF transition has already consumed real
        // DMA-off/idle and final LPCTL firmware-own receipts. Do not touch
        // WFDMA MMIO again after giving LPCTL ownership back to firmware.
        self.wake
            .route
            .as_ref()
            .ok_or(Error::Busy)?
            .admits(self.wake.target.ok_or(Error::Busy)?, WakeState::D3Hot)
            .map_err(wake_error)?;
        self.wake.d0_required = true;
        let result = crate::mt7921::pci::invoke(&self.authority, || {
            pci::set_power_state(&self.authority, &self.device, PciPowerState::D3Hot)
                .map_err(|_| Error::Authority)
        })
        .map_err(|_| Error::Authority)
        .and_then(core::convert::identity);
        self.wake.last_power_write_ns = Some(narf_time::wall::monotonic_ns());
        result
    }

    pub(super) fn verify_wake_d3hot(&mut self) -> Result<(), Error> {
        if !self.wake.d0_required || self.wake_power_state()? != PciPowerState::D3Hot {
            return Err(Error::Busy);
        }
        self.wake.last_power_write_ns = None;
        Ok(())
    }

    pub(super) fn begin_wake_d0(&mut self) -> Result<bool, Error> {
        self.check()?;
        if !self.wake.d0_required {
            return Ok(false);
        }
        if !self.wake.settled(narf_time::wall::monotonic_ns()) {
            return Err(Error::Busy);
        }
        // Refuse an unavailable function before any PMCSR write.
        let _ = self.wake_power_state()?;
        // A cancelled D0 exit may already have written D0. Repeating that
        // write is safe after its retained delay, and requires a fresh delay
        // plus actual readback before any MMIO or PME teardown.
        let result = crate::mt7921::pci::invoke(&self.authority, || {
            pci::set_power_state(&self.authority, &self.device, PciPowerState::D0)
                .map_err(|_| Error::Authority)
        })
        .map_err(|_| Error::Authority)
        .and_then(core::convert::identity);
        self.wake.last_power_write_ns = Some(narf_time::wall::monotonic_ns());
        result?;
        Ok(true)
    }

    pub(super) fn verify_wake_d0(&mut self) -> Result<(), Error> {
        if !self.wake.d0_required || self.wake_power_state()? != PciPowerState::D0 {
            return Err(Error::Busy);
        }
        self.wake.last_power_write_ns = None;
        self.wake.d0_required = false;
        Ok(())
    }

    pub(super) fn disarm_wake_route(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.wake.mmio_ready() {
            return Err(Error::Busy);
        }
        if let Some(route) = self.wake.route.as_mut() {
            self.wake.evidence = route.disarm().map_err(|_| Error::Authority)?;
        }
        self.wake.route = None;
        self.wake.target = None;
        Ok(())
    }
}

fn wake_error(error: narf_power::pci_wake::WakeError) -> Error {
    use narf_power::pci_wake::WakeError;
    match error {
        WakeError::Authority => Error::Authority,
        WakeError::Unsupported | WakeError::Ambiguous => Error::UnsupportedFirmware,
        WakeError::Busy => Error::Busy,
        _ => Error::Register,
    }
}
