// SPDX-License-Identifier: GPL-2.0-or-later
//! The control-only P2P_DEVICE vdev (`WMI_VDEV_TYPE_STA`, subtype P2P_DEV).
//!
//! Linux 7.3-rc4 `mac.c::ath10k_add_interface` for
//! `NL80211_IFTYPE_P2P_DEVICE` takes the lowest free id of
//! `ar->free_vdev_map`, sends `WMI_VDEV_CREATE` with the wdev address and
//! the vdev NSS parameter; `ath10k_remove_interface` sends
//! `WMI_VDEV_DELETE` and, with `WMI_SERVICE_SYNC_DELETE_CMDS`, waits up to
//! `ATH10K_VDEV_DELETE_TIMEOUT_HZ` (5 s) for `WMI_TLV_VDEV_DELETE_RESP`
//! (`ath10k_vdev_delete_sync`). The vdev is never started, has no BSS peer,
//! key or data port; it only names the vdev that discovery ROC scans run
//! on (`ath10k_remain_on_channel` uses `arvif->vdev_id`).
use super::*;

/// `WMI_TLV_VDEV_DELETE_RESP_EVENTID`.
const DELETE_RESPONSE: u32 = 0x5006;

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    /// P2P interface types exist only for TLV firmware without
    /// `ATH10K_FW_FEATURE_NO_P2P` (bit 3) — `core.c` clears P2P from
    /// `interface_modes` otherwise, and 10.x/10.4 combinations carry none.
    pub(in crate::ath10k) fn p2p_supported(&self) -> bool {
        self.wire.dialect == Dialect::Tlv && self.features & (1 << 3) == 0
    }
    pub(in crate::ath10k) fn p2p_device_vdev(&self) -> Option<u8> {
        self.p2p_device.map(p2p::Vdev::id)
    }
    /// Create the P2P_DEVICE vdev beside the managed role's vdev. Any
    /// ambiguous publication leaves the radio failed (no id is reused).
    pub(in crate::ath10k) async fn start_p2p_device(
        &mut self,
        address: [u8; 6],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<u8, Error> {
        if self.failed
            || self.ready.is_none()
            || !self.p2p_supported()
            || self.p2p_device.is_some()
            || self.scan_pending.is_some()
            || self.roc.is_some()
            || self.ap.is_some()
        {
            return Err(Error::Unsupported);
        }
        let chains = self.chains.ok_or(Error::Failed)?;
        let map = self.vdev_map.as_mut().ok_or(Error::Failed)?;
        let id = map.allocate()?;
        let vdev = p2p::Vdev::new(id, p2p::Role::P2pDevice);
        let commands = match (
            vdev.create(&self.wire, address),
            chains.vdev_nss_for(self.wire.dialect, id),
        ) {
            (Ok(create), Ok(nss)) => [create, nss],
            (Err(e), _) | (_, Err(e)) => {
                // Nothing was published; the id is still free.
                self.vdev_map.as_mut().ok_or(Error::Failed)?.release(id)?;
                return Err(e);
            }
        };
        self.failed = true;
        for command in &commands {
            self.send_scan_command(command, validate).await?;
        }
        validate()?;
        self.p2p_device = Some(vdev);
        self.p2p_device_mac = address;
        self.failed = false;
        Ok(id)
    }
    /// Delete the P2P_DEVICE vdev. A ROC still bound to it must have
    /// completed first; the id returns to the map only after the delete was
    /// published (and, with SYNC_DELETE, acknowledged).
    pub(in crate::ath10k) async fn stop_p2p_device(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let vdev = self.p2p_device.ok_or(Error::Unsupported)?;
        if self.failed
            || self.roc.as_ref().is_some_and(|w| w.vdev == vdev.id())
            || self.scan_pending.is_some()
        {
            return Err(Error::Unsupported);
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let sync = self.wire.sync_delete_required(caps);
        let command = vdev.delete(&self.wire)?;
        self.failed = true;
        self.send_scan_command(&command, validate).await?;
        if sync {
            let deadline = narf_time::Deadline::after_ms(5000);
            loop {
                validate()?;
                if deadline.expired() {
                    return Err(Error::Timeout);
                }
                match self.htt.poll_now()? {
                    htt::Event::Wmi(bytes)
                        if wire::word(&bytes, 0)? & 0xffffff == DELETE_RESPONSE =>
                    {
                        break;
                    }
                    htt::Event::Idle | htt::Event::Progress => narf_scheduler::yield_now().await,
                    event => self.queue(event)?,
                }
            }
        }
        self.p2p_device = None;
        self.p2p_device_mac = [0; 6];
        self.vdev_map
            .as_mut()
            .ok_or(Error::Failed)?
            .release(vdev.id())?;
        self.failed = false;
        Ok(())
    }
    /// The address frames on `vdev` carry as A2 (and A3 for Public Action)
    /// and the directed-RX address on it: the INIT address for the managed
    /// role's vdev, the wdev address for the P2P_DEVICE vdev
    /// (`ath10k_add_interface` creates each vdev with `vif->addr`).
    pub(super) fn vdev_address(&self, vdev: u8) -> Result<[u8; 6], Error> {
        if vdev == self.primary.id() {
            return Ok(self.ready.ok_or(Error::Failed)?.mac);
        }
        if self.p2p_device_vdev() == Some(vdev) {
            return Ok(self.p2p_device_mac);
        }
        Err(Error::Failed)
    }
    /// `mac.c::ath10k_hw_scan` on the P2P_DEVICE vif (P2P search): the
    /// firmware scan runs on that vdev, so its Probe Requests carry the
    /// P2P Device Address and its events carry that vdev id. `plan` is an
    /// unassociated active plan (`prepare_active_scan`); `None` is a passive
    /// scan of `channels`. Refused (`Unsupported`, nothing published) with
    /// no P2P_DEVICE vdev, a ROC in flight (`ar->scan.state` is shared with
    /// ROC), a station peer or an AP on the managed vdev. The managed
    /// role's scan cache is not replaced.
    pub(in crate::ath10k) async fn p2p_device_scan(
        &mut self,
        plan: Option<active_scan::Plan>,
        channels: &[u16],
        current: impl Fn() -> Result<narf_wireless::reg::RegulatoryDomain, Error>,
    ) -> Result<ScanReport, Error> {
        let vdev = self.p2p_device_vdev().ok_or(Error::Unsupported)?;
        if self.roc.is_some() || self.peer.is_some() || self.ap.is_some() {
            return Err(Error::Unsupported);
        }
        if let Some(mut plan) = plan {
            if plan.station.is_some() {
                return Err(Error::Unsupported);
            }
            plan.p2p_device = Some(vdev);
            return self.active_scan(plan, current).await;
        }
        let validate = || {
            let domain = current()?;
            associated_scan::receive_permission(&domain, channels)?;
            Ok(())
        };
        validate()?;
        self.scan_run_on(Some(vdev), channels, (&[], &[]), &[], None, validate)
            .await
    }
    /// The current ROC runs on the P2P_DEVICE vdev (its owner is the wdev).
    pub(in crate::ath10k) fn roc_on_p2p_device(&self) -> bool {
        self.roc
            .as_ref()
            .is_some_and(|w| Some(w.vdev) == self.p2p_device_vdev())
    }
    /// A ROC may run on the managed role's vdev or the P2P_DEVICE vdev.
    pub(super) fn roc_vdev_owned(&self, vdev: u8) -> bool {
        vdev == self.primary.id() || self.p2p_device_vdev() == Some(vdev)
    }
}
