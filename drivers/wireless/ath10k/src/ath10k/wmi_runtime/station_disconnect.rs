// SPDX-License-Identifier: GPL-2.0-or-later
//! One-shot native peer/vdev retirement, without a DMA or reset/rejoin proof.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disconnected {
    pub bssid: [u8; 6],
    pub frequency: u16,
    /// The advertised TLV SYNC_DELETE_CMDS service required its separate ACK.
    pub synchronous_delete: bool,
}

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    /// Close this retained owner permanently, then retire its peer and stop
    /// its vdev. No command receipt is a firmware ACK. Success requires every
    /// owned HTT peer ID to unmap, the advertised TLV delete ACK, and the
    /// matching VDEV_STOPPED event. DMA remains retained through full reset.
    /// Unversioned firmware events do not fence another join on this owner.
    pub async fn disconnect_station(&mut self) -> Result<Disconnected, Error> {
        self.disconnect_station_inner(false).await
    }
    /// Only the retained failed-scan worker calls this after the matching
    /// scan terminal. Do not emit deauthentication after an RF-policy loss.
    pub(in crate::ath10k::wmi_runtime) async fn disconnect_after_failed_scan(
        &mut self,
    ) -> Result<Disconnected, Error> {
        self.disconnect_station_inner(true).await
    }
    async fn disconnect_station_inner(&mut self, failed_scan: bool) -> Result<Disconnected, Error> {
        let prepared = if failed_scan {
            self.prepared_peer_snapshot()
        } else {
            self.prepared_peer()
        }
        .ok_or(Error::Failed)?;
        let synchronous_delete = self
            .wire
            .sync_delete_required(self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?);
        // `mac.c::ath10k_bss_disassoc`/`ath10k_vdev_stop` on the peer's vdev.
        let vdev = self.station.peer.as_ref().ok_or(Error::Failed)?.vdev;
        let down = self.wire.down_station(vdev)?;
        let delete = self.wire.delete_peer(vdev, prepared.bssid)?;
        let stop = self.wire.stop_station(vdev)?;
        // Protected with the still-installed PTK before the owner fails.
        let deauthentication = if failed_scan {
            None
        } else {
            self.pmf_deauthentication()?
        };
        // This happens before any await, including receive quiescence. A
        // cancelled waiter can never restore association or replay DELETE.
        // A P2P client slot (`client_scope`) restores the radio only after
        // the whole retirement below succeeded.
        let client_slot = self.in_client_scope && !failed_scan && !self.failed;
        self.failed = true;
        if let Some(data) = &mut self.station.data {
            data.fail();
        }
        self.station.peer.as_mut().ok_or(Error::Failed)?.associated = None;
        if let Some(frame) = deauthentication {
            // Best effort, as mac80211 proceeds with teardown regardless; the
            // frame is already encrypted, so no key outlives `fail()`.
            management::validate(&frame, self.station_own()?, prepared.bssid)?;
            let _ = self.send_management_frame(&frame).await;
        }

        // Drain events received before DELETE. In particular, a stale STOPPED
        // or TLV delete response must never satisfy this new transaction.
        self.drain_before_delete().await?;
        for command in [&down, &delete] {
            self.htt
                .wmi
                .htc
                .send_wmi(command)
                .await
                .map_err(htt::Error::from)?;
        }
        self.wait_peer_deleted(vdev, prepared.bssid, synchronous_delete)
            .await?;
        self.htt
            .wmi
            .htc
            .send_wmi(&stop)
            .await
            .map_err(htt::Error::from)?;
        self.wait_vdev_stopped(vdev, prepared.bssid).await?;
        self.station.peer = None;
        if client_slot {
            // `mac.c::ath10k_remove_interface` tears only this vif down and
            // the other vifs keep running. Every peer id of this slot was
            // unmapped, its delete acknowledged and its vdev STOPPED; the HTT
            // TX table (`htt_runtime::tx`) still owns the DMA of any MSDU id
            // the dropped data owner published until firmware completes it
            // (a completion no slot owns is foreign and only frees that DMA),
            // so the slot's data owner is dropped and the radio resumes.
            self.drop_client_data()?;
            self.station.peer_pmf_offload = false;
            self.failed = false;
        }
        // Otherwise keep failed/closed set even after success: for the home
        // station neither peer retirement nor vdev STOP is the whole-device
        // reset/DMA reclamation proof.
        Ok(Disconnected {
            bssid: prepared.bssid,
            frequency: prepared.frequency,
            synchronous_delete,
        })
    }

    /// Drop the P2P client slot's data owner after its vif was retired. Each
    /// MSDU id it still has in flight is disowned at the HTT layer unless a
    /// sibling already handed its receipt to this slot (then its DMA is
    /// already free).
    fn drop_client_data(&mut self) -> Result<(), Error> {
        let Some(data) = self.station.data.take() else {
            return Ok(());
        };
        for id in data.pending_ids() {
            if !self.station.receipts.iter().any(|r| r.id == id) {
                self.htt.orphan_tx(id)?;
            }
        }
        self.station.receipts.clear();
        Ok(())
    }

    async fn drain_before_delete(&mut self) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..4096 {
            narf_scheduler::yield_now().await;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.station_progress().await?;
            if self.station.peer.as_ref().and_then(Peer::mapped).is_none() {
                return Err(Error::Failed);
            }
            match event {
                htt::Event::Idle => return Ok(()),
                htt::Event::Progress => {}
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if id != self.wire.stopped_event_id() && Some(id) != self.wire.delete_event_id()
                    {
                        self.queue(htt::Event::Wmi(bytes))?;
                    }
                }
                other => self.queue(other)?,
            }
        }
        Err(Error::Timeout)
    }

    async fn wait_peer_deleted(
        &mut self,
        vdev: u8,
        bssid: [u8; 6],
        sync: bool,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(5000);
        let mut acknowledged = !sync;
        for _ in 0..65536 {
            narf_scheduler::yield_now().await;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.station_progress().await?;
            match event {
                htt::Event::Idle
                    if acknowledged
                        && self.station.peer.as_ref().and_then(Peer::mapped).is_none() =>
                {
                    return Ok(())
                }
                htt::Event::Idle | htt::Event::Progress => {}
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if Some(id) == self.wire.delete_event_id() {
                        acknowledged |= self.wire.delete_response(vdev, &bytes[4..], bssid)?;
                    } else if id == self.wire.stopped_event_id() {
                        // STOP has not been sent; discard unsolicited/stale
                        // STOPPED instead of caching an apparent completion.
                    } else {
                        self.queue(htt::Event::Wmi(bytes))?;
                    }
                }
                other => self.queue(other)?,
            }
        }
        Err(Error::Timeout)
    }

    async fn wait_vdev_stopped(&mut self, vdev: u8, bssid: [u8; 6]) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(5000);
        let mut stopped = false;
        for _ in 0..65536 {
            narf_scheduler::yield_now().await;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.station_progress().await?;
            // A late matching MAP after DELETE completion invalidates the
            // retirement proof, even when STOPPED is in the same receive batch.
            if self.station.peer.as_ref().and_then(Peer::mapped).is_some() {
                return Err(Error::Malformed);
            }
            match event {
                htt::Event::Idle if stopped => return Ok(()),
                htt::Event::Idle | htt::Event::Progress => {}
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if id == self.wire.stopped_event_id() {
                        stopped |= self.wire.stopped_response(vdev, &bytes[4..])?;
                    } else if Some(id) == self.wire.delete_event_id() {
                        // Validate repeated delete envelopes; they confer no
                        // additional ownership or ability to restart this vdev.
                        let _ = self.wire.delete_response(vdev, &bytes[4..], bssid)?;
                    } else {
                        self.queue(htt::Event::Wmi(bytes))?;
                    }
                }
                other => self.queue(other)?,
            }
        }
        Err(Error::Timeout)
    }
}
