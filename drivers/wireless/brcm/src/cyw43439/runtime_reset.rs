// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport reset of one SDPCM/BCDC generation (Linux 7.3-rc4
//! `brcmfmac/sdio.c::brcmf_sdio_bus_reset`, reached from
//! `core.c::brcmf_core_bus_reset` after `brcmf_fw_crashed`): the card
//! interrupt is unregistered, the bus removed best-effort
//! (`brcmf_sdiod_remove`), the card power-cycled and re-enumerated
//! (`mmc_hw_reset`), and the function probed again, which downloads the
//! firmware afresh. The retained owner (`interface::generation`) then
//! replays `Station::initialize_live` and rejoins.
use super::*;

/// Reset/reboot authority of a reset-capable transport. It receives the
/// stopped generation's transport and returns a freshly booted one, or
/// consumes it (the device stays powered off) on failure.
pub(crate) trait Reboot<T>: Send {
    fn boot(&mut self, transport: T) -> Result<T, Error>;
}

impl<T: PacketTransport> Runtime<T> {
    /// Retain the reset authority of this generation.
    pub(crate) fn with_reboot(mut self, reboot: alloc::boxed::Box<dyn Reboot<T>>) -> Self {
        self.reboot = Some(reboot);
        self
    }
    /// Whether this generation can be reset in place.
    pub fn resettable(&self) -> bool {
        self.reboot.is_some()
    }
    /// The stop a reset-capable generation takes: the confirmed native stop
    /// when the firmware still answers, else Linux's `brcmf_sdio_bus_reset`
    /// prelude (card-interrupt unregistration, best-effort remove, host bus
    /// power off; [`PacketTransport::stop_dead`]). A generation without a
    /// reset authority keeps the strict confirmed stop only.
    pub(crate) fn stop_for_reset(&mut self) -> Result<(), Error> {
        let confirmed = self.stop_transport();
        if confirmed.is_ok() || self.reboot.is_none() {
            return confirmed;
        }
        self.transport.as_mut().ok_or(Error::Failed)?.stop_dead()?;
        self.stopped = true;
        self.pending = None;
        self.response = None;
        self.events.clear();
        self.data.clear();
        self.vif.clear();
        Ok(())
    }
    /// After a stop: reset the device and boot a fresh firmware generation
    /// in place under the retained authority. The fresh generation starts
    /// with Linux's probe-time protocol state (no TX credit, sequence 0, no
    /// queued event/data, no AP or secondary interface). A failed reboot
    /// consumed the old transport; this generation then stays stopped and
    /// empty.
    pub(crate) fn reset_transport(&mut self) -> Result<(), Error> {
        if self.reboot.is_none() {
            return Err(Error::Unsupported);
        }
        if !self.stopped {
            return Err(Error::Busy);
        }
        let transport = self.transport.take().ok_or(Error::Failed)?;
        let mut reboot = self.reboot.take().ok_or(Error::Unsupported)?;
        let booted = reboot.boot(transport);
        let fresh = match booted {
            Ok(fresh) => fresh,
            Err(error) => {
                self.reboot = Some(reboot);
                return Err(error);
            }
        };
        let vendor = self.vendor;
        // The old value holds neither a transport nor live AP state now.
        *self = Self::new(fresh).with_firmware_vendor(vendor);
        self.reboot = Some(reboot);
        Ok(())
    }
    /// Move this (freshly booted) generation into a new owner, leaving this
    /// one terminal and empty.
    pub(crate) fn take_generation(&mut self) -> Option<Self> {
        if self.failed || self.stopped || self.transport.is_none() {
            return None;
        }
        let mut retired = Self::with_transport(None);
        retired.failed = true;
        retired.stopped = true;
        Some(core::mem::replace(self, retired))
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn transport_mut(&mut self) -> Option<&mut T> {
        self.transport.as_mut()
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn without_reboot(mut self) -> Self {
        self.reboot = None;
        self
    }
}
