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
    /// vdev0. No command receipt is a firmware ACK. Success requires every
    /// owned HTT peer ID to unmap, the advertised TLV delete ACK, and the
    /// matching VDEV_STOPPED event. DMA remains retained through full reset.
    /// Unversioned firmware events do not fence another join on this owner.
    pub async fn disconnect_station(&mut self) -> Result<Disconnected, Error> {
        let prepared = self.prepared_peer().ok_or(Error::Failed)?;
        let synchronous_delete = self
            .wire
            .sync_delete_required(self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?);
        let down = self.wire.down_station()?;
        let delete = self.wire.delete_peer(prepared.bssid)?;
        let stop = self.wire.stop_station()?;
        // This happens before any await, including receive quiescence. A
        // cancelled waiter can never restore association or replay DELETE.
        self.failed = true;
        self.peer.as_mut().ok_or(Error::Failed)?.associated = None;

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
        self.wait_peer_deleted(prepared.bssid, synchronous_delete)
            .await?;
        self.htt
            .wmi
            .htc
            .send_wmi(&stop)
            .await
            .map_err(htt::Error::from)?;
        self.wait_vdev_stopped(prepared.bssid).await?;
        self.peer = None;
        // Keep failed/closed set even after success: neither peer retirement
        // nor vdev STOP is the whole-device reset/DMA reclamation proof.
        Ok(Disconnected {
            bssid: prepared.bssid,
            frequency: prepared.frequency,
            synchronous_delete,
        })
    }

    async fn drain_before_delete(&mut self) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..4096 {
            narf_scheduler::yield_now().await;
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = self.station_progress().await?;
            if self.peer.as_ref().and_then(Peer::mapped).is_none() {
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

    async fn wait_peer_deleted(&mut self, bssid: [u8; 6], sync: bool) -> Result<(), Error> {
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
                    if acknowledged && self.peer.as_ref().and_then(Peer::mapped).is_none() =>
                {
                    return Ok(())
                }
                htt::Event::Idle | htt::Event::Progress => {}
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if Some(id) == self.wire.delete_event_id() {
                        acknowledged |= self.wire.delete_response(&bytes[4..], bssid)?;
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

    async fn wait_vdev_stopped(&mut self, bssid: [u8; 6]) -> Result<(), Error> {
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
            if self.peer.as_ref().and_then(Peer::mapped).is_some() {
                return Err(Error::Malformed);
            }
            match event {
                htt::Event::Idle if stopped => return Ok(()),
                htt::Event::Idle | htt::Event::Progress => {}
                htt::Event::Wmi(bytes) => {
                    let id = wire::word(&bytes, 0)? & 0xffffff;
                    if id == self.wire.stopped_event_id() {
                        stopped |= self.wire.stopped_response(&bytes[4..])?;
                    } else if Some(id) == self.wire.delete_event_id() {
                        // Validate repeated delete envelopes; they confer no
                        // additional ownership or ability to restart this vdev.
                        let _ = self.wire.delete_response(&bytes[4..], bssid)?;
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
