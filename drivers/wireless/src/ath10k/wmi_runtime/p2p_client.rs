// SPDX-License-Identifier: GPL-2.0-or-later
//! The P2P client station vdev (`WMI_VDEV_TYPE_STA`, subtype P2P_CLI).
//!
//! Linux 7.3-rc4 `mac.c::ath10k_add_interface` for
//! `NL80211_IFTYPE_P2P_CLIENT` takes the lowest free id of
//! `ar->free_vdev_map` and sends `WMI_VDEV_CREATE` (STA type, P2P_CLI
//! subtype, `vif->addr`) and the vdev NSS parameter, exactly as for the
//! managed station vdev here; `ath10k_remove_interface` sends
//! `WMI_VDEV_DELETE` (with SYNC_DELETE, `ath10k_vdev_delete_sync`). The
//! vdev gets its own `StationSlot`: the ordinary station prepare,
//! association, key and data paths run on it inside a `ClientScope`, and
//! HTT RX / TX completions are demultiplexed to it by vdev and peer id.
//!
//! Channel rule: `Radio::start` sends `WMI_TLV_RESMGR_ADAPTIVE_OCS_CMDID`
//! (Linux `ath10k_wmi_adaptive_qcs(ar, true)` in `ath10k_start`) when the
//! firmware has `WMI_SERVICE_ADAPTIVE_OCS`; then the two-channel
//! `ath10k_tlv_qcs_if_limit` entry applies. Without it only the one-channel
//! `ath10k_tlv_if_limit` combination applies: the client's BSS must share
//! the home station's primary channel while both have a peer.
use super::*;

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    /// The P2P client slot's vdev and address, outside a `ClientScope`.
    pub(super) fn p2p_client_identity(&self) -> Option<(u8, [u8; 6])> {
        let slot = if self.in_client_scope {
            &self.station
        } else {
            self.p2p_client.as_deref()?
        };
        Some((slot.vdev?, slot.own?))
    }
    pub(in crate::ath10k) fn p2p_client_vdev(&self) -> Option<u8> {
        self.p2p_client_identity().map(|(vdev, _)| vdev)
    }
    /// Create the P2P client vdev and its station slot beside the managed
    /// vdev. Refused (nothing published, `Unsupported`) without P2P
    /// firmware, with a client already present, inside a client scope, or
    /// while a scan, ROC or AP owns the radio. Any ambiguous publication
    /// leaves the radio failed (no id is reused).
    pub(in crate::ath10k) async fn start_p2p_client(
        &mut self,
        address: [u8; 6],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<u8, Error> {
        if self.failed
            || self.ready.is_none()
            || !self.p2p_supported()
            || self.p2p_client.is_some()
            || self.in_client_scope
            || self.scan_pending.is_some()
            || self.roc.is_some()
            || self.ap.is_some() && !self.ap_is_go()
            || self.ap_staging.is_some()
            || Some(address) == self.go_identity().map(|(_, own)| own)
            || address == [0; 6]
            || address[0] & 1 != 0
            || Some(address) == self.ready.map(|r| r.mac)
        {
            return Err(Error::Unsupported);
        }
        let chains = self.chains.ok_or(Error::Failed)?;
        let map = self.vdev_map.as_mut().ok_or(Error::Failed)?;
        let id = map.allocate()?;
        let vdev = p2p::Vdev::new(id, p2p::Role::P2pClient);
        let commands = match (
            vdev.create(&self.wire, address),
            chains.vdev_nss_for(self.wire.dialect, id),
        ) {
            (Ok(create), Ok(nss)) => [create, nss],
            (Err(e), _) | (_, Err(e)) => {
                self.vdev_map.as_mut().ok_or(Error::Failed)?.release(id)?;
                return Err(e);
            }
        };
        self.failed = true;
        for command in &commands {
            self.send_scan_command(command, validate).await?;
        }
        validate()?;
        self.p2p_client = Some(alloc::boxed::Box::new(StationSlot::client(id, address)));
        self.failed = false;
        Ok(id)
    }
    /// Delete the P2P client vdev. Its BSS peer and data owner must already
    /// be retired (the netdev disconnects first); parked events are dropped
    /// with the slot. The id returns to the map only after the delete was
    /// published (and, with SYNC_DELETE, acknowledged).
    pub(in crate::ath10k) async fn stop_p2p_client(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if self.in_client_scope {
            return Err(Error::Unsupported);
        }
        let slot = self.p2p_client.as_deref().ok_or(Error::Unsupported)?;
        let id = slot.vdev.ok_or(Error::Failed)?;
        if self.failed
            || slot.peer.is_some()
            || slot.data.is_some()
            || self.roc.as_ref().is_some_and(|w| w.vdev == id)
            || self.scan_pending.is_some()
        {
            return Err(Error::Unsupported);
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let sync = self.wire.sync_delete_required(caps);
        let command = p2p::Vdev::new(id, p2p::Role::P2pClient).delete(&self.wire)?;
        self.failed = true;
        self.send_scan_command(&command, validate).await?;
        if sync {
            self.wait_vdev_delete(validate).await?;
        }
        self.p2p_client = None;
        self.vdev_map.as_mut().ok_or(Error::Failed)?.release(id)?;
        self.failed = false;
        Ok(())
    }
    /// Test fixture: make the associated home slot the P2P client slot
    /// (vdev 0 keeps the vdev0 goldens) and enter its client scope.
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn associated_slot_as_client_for_test(&mut self) -> ClientScope<'_, T> {
        let mut slot = core::mem::replace(&mut self.station, StationSlot::new());
        slot.vdev = Some(self.primary.id());
        slot.own = self.ready.map(|r| r.mac);
        self.p2p_client = Some(alloc::boxed::Box::new(slot));
        self.client_scope().expect("client slot")
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn failed_for_test(&self) -> bool {
        self.failed
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::ath10k) fn station_data_for_test(&self) -> bool {
        self.station.data.is_some()
    }
    /// One-channel rule (`ath10k_tlv_if_limit`, `num_different_channels`
    /// 1): a station slot may bind a BSS only on the sibling slot's primary
    /// channel while the sibling has a peer. Once adaptive QCS was enabled
    /// at start, `ath10k_tlv_qcs_if_limit` admits STA + P2P_CLIENT on two
    /// channels and firmware schedules them.
    pub(super) fn sibling_channel_admits(&self, frequency: u16) -> bool {
        self.adaptive_qcs
            || (self
                .p2p_client
                .as_deref()
                .and_then(|s| s.peer.as_ref())
                .is_none_or(|peer| peer.permission.frequency == frequency)
                && self.go_channel_admits(frequency))
    }
    /// A running GO's operating channel is the other vif of the
    /// one-channel combination.
    fn go_channel_admits(&self, frequency: u16) -> bool {
        self.ap
            .as_ref()
            .filter(|ap| ap.plan.role == p2p::Role::P2pGo)
            .is_none_or(|ap| ap.plan.config.frequency_mhz == u32::from(frequency))
    }
    /// Every station slot with a peer (home and P2P client) is on
    /// `frequency`: the one-channel rule for a GO start.
    pub(super) fn slots_on_channel(&self, frequency: u16) -> bool {
        [Some(&self.station), self.p2p_client.as_deref()]
            .into_iter()
            .flatten()
            .filter_map(|slot| slot.peer.as_ref())
            .all(|peer| peer.permission.frequency == frequency)
    }
}
