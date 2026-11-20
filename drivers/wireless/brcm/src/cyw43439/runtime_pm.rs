// SPDX-License-Identifier: GPL-2.0-or-later
//! System suspend/resume of the packet runtime's bus (Linux 7.3-rc4
//! brcmfmac `bcmsdh.c::brcmf_ops_sdio_suspend`/`brcmf_ops_sdio_resume`,
//! `brcmf_sdio_wowl_config`). The station has already brought the link
//! down or armed WoWL (`brcmf_cfg80211_suspend`) before this runs.

use super::{Error, PacketTransport, Runtime};

impl<T: PacketTransport> Runtime<T> {
    /// `brcmf_bus_wowl_config` -> `brcmf_sdio_wowl_config`: WoWL is armed
    /// for the next suspend (the bus must keep a wake path).
    pub fn wowl_config(&mut self, enabled: bool) {
        self.wowl_enabled = enabled;
    }

    /// Linux `bus_if->wowl_supported` for this bus.
    pub fn wowl_supported(&mut self) -> bool {
        !self.failed
            && !self.stopped
            && self
                .transport
                .as_mut()
                .is_some_and(|transport| transport.wowl_supported())
    }

    /// Whether the bus is system-suspended.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// `brcmf_ops_sdio_suspend` (keep-power branch): freeze the DPC, put
    /// the dongle to bus sleep and suspend the host keeping card power
    /// (+ card-interrupt wake when WoWL is armed). A refusal leaves the
    /// runtime usable so the coordinator unwinds; a transport fault while
    /// changing state is terminal.
    pub async fn suspend_transport(&mut self) -> Result<(), Error> {
        if self.failed || self.stopped {
            return Err(Error::Failed);
        }
        if self.suspended || self.pending.is_some() || self.ap.is_some() || !self.vif_ap.is_empty()
        {
            return Err(Error::Busy);
        }
        // brcmf_sdiod_freezer_on: the DPC drains its current pass first.
        self.poll()?;
        let wake = self.wowl_enabled;
        let transport = self.transport.as_mut().ok_or(Error::Failed)?;
        match transport.suspend(wake) {
            Ok(()) => {
                self.suspended = true;
                Ok(())
            }
            Err(super::TransportError::NotReady) => Err(Error::Unsupported),
            Err(super::TransportError::Busy) => Err(Error::Busy),
            Err(error) => {
                self.fail();
                Err(Error::Transport(error))
            }
        }
    }

    /// `brcmf_ops_sdio_resume` (keep-power branch): host resume, then
    /// `brcmf_sdiod_freezer_off` -> bus wake. Any error is terminal (the
    /// dongle lost power or state; recovery needs a transport reset).
    pub async fn resume_transport(&mut self) -> Result<(), Error> {
        if self.failed || self.stopped {
            return Err(Error::Failed);
        }
        if !self.suspended {
            return Err(Error::Busy);
        }
        let result = self
            .transport
            .as_mut()
            .ok_or(Error::Failed)
            .and_then(|transport| transport.resume().map_err(Error::Transport));
        self.suspended = false;
        if let Err(error) = result {
            self.fail();
            return Err(error);
        }
        Ok(())
    }
}
