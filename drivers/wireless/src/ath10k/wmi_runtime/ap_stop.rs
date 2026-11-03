// SPDX-License-Identifier: GPL-2.0-or-later
//! Original-device cleanup after AP cancellation/stop/source retirement.
//! UI emission loss never grants RF work; still-current native authority may
//! silence the old context. Missing native receipts keep DMA pinned for reset.
use super::{
    ap::{Publication, Session, Vdev},
    ap_wire, Error, Hif, HostMemory, HttMemory, Radio,
};

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(super) async fn ap_delete_client(
        &mut self,
        mac: [u8; 6],
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let ap = self.ap.as_mut().ok_or(Error::Failed)?;
        let peer = ap
            .peers
            .iter_mut()
            .find(|peer| peer.record.mac == mac)
            .ok_or(Error::Failed)?;
        peer.authorized = false;
        peer.record.delete_ack = false;
        peer.record.deleting = false;
        Session::invalidate(&ap.data_epoch)?;
        Session::invalidate(&ap.key_epoch)?;
        self.ap_prefix(validate).await?;
        self.ap_remove_peer(mac, validate).await?;
        self.ap_wait(
            |ap| {
                ap.peers
                    .iter()
                    .find(|peer| peer.record.mac == mac)
                    .is_some_and(|peer| !peer.record.mapped() && peer.record.delete_ack)
            },
            validate,
        )
        .await?;
        self.ap_prefix(validate).await?;
        let ap = self.ap.as_mut().ok_or(Error::Failed)?;
        let at = ap
            .peers
            .iter()
            .position(|peer| peer.record.mac == mac)
            .ok_or(Error::Failed)?;
        ap.peers.remove(at);
        Ok(())
    }
    /// A dropped control future sets the host endpoint closed, while this
    /// same retained native owner remains available to its physical worker.
    pub(in crate::ath10k) async fn ap_cleanup(
        &mut self,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let Some(ap) = &mut self.ap else {
            return Ok(());
        };
        let original = ap.vdev;
        ap.retire();
        ap.busy = true;
        self.htt.wmi.htc.transport.runtime_idle(false);
        validate()?;
        // No command was even staged in Original. There cannot be a native
        // AP buffer; prove the shared pool is quiet before removing metadata.
        if original == Vdev::Original {
            self.ap_quiet(validate).await?;
            self.ap = None;
            return Ok(());
        }
        if original == Vdev::StartSent {
            // START may have reached firmware although its waiter vanished.
            // Resolve its real response before assuming STOP is meaningful.
            self.ap_wait(|ap| ap.vdev == Vdev::Started, validate)
                .await?;
        }
        let phase = self.ap.as_ref().ok_or(Error::Failed)?.vdev;
        if matches!(phase, Vdev::Up | Vdev::Started | Vdev::StopSent) {
            // Autonomous beaconing is silenced before waiting on old DATA.
            // DOWN transport receipt alone is not a STOPPED/DMA-idle proof.
            self.ap_command(&self.wire.down_station(self.ap_vdev()?)?, validate)
                .await?;
            self.ap_barrier(validate).await?;
        }
        self.ap_quiet(validate).await?;
        if !matches!(phase, Vdev::DeleteSent | Vdev::Absent) {
            let macs: alloc::vec::Vec<_> = self
                .ap
                .as_ref()
                .ok_or(Error::Failed)?
                .peers
                .iter()
                .map(|peer| peer.record.mac)
                .collect();
            for mac in macs {
                self.ap_delete_client(mac, validate).await?;
            }
            if self.ap.as_ref().ok_or(Error::Failed)?.own.expected {
                let ap = self.ap.as_mut().unwrap();
                ap.own.delete_ack = false;
                ap.own.deleting = false;
                let own = ap.own.mac;
                self.ap_prefix(validate).await?;
                self.ap_remove_peer(own, validate).await?;
                self.ap_wait(|ap| !ap.own.mapped() && ap.own.delete_ack, validate)
                    .await?;
                self.ap.as_mut().unwrap().own.expected = false;
            }
            if matches!(phase, Vdev::Up | Vdev::Started | Vdev::StopSent) {
                self.ap_publish(
                    &self.wire.stop_station(self.ap_vdev()?)?,
                    Publication::Vdev(Vdev::StopSent),
                    validate,
                )
                .await?;
                self.ap_wait(|ap| ap.native_stopped, validate).await?;
                self.ap.as_mut().unwrap().vdev = Vdev::Stopped;
            }
            // CREATE may have been only partially published. A genuine delete
            // response is mandatory here; silence/timeout is never success.
            self.ap_publish(
                &ap_wire::delete(self.primary)?,
                Publication::Vdev(Vdev::DeleteSent),
                validate,
            )
            .await?;
        }
        if self.ap.as_ref().unwrap().vdev != Vdev::Absent {
            self.ap_wait(|ap| ap.vdev_deleted, validate).await?;
            self.ap.as_mut().unwrap().vdev = Vdev::Absent;
        }
        self.ap_prefix(validate).await?;
        // Reconstruct the original inactive station discovery vdev only after
        // actual AP destruction. No AP/STA role alias or new DATA port exists.
        let own = self.ap.as_ref().unwrap().own.mac;
        self.primary = super::p2p::Vdev::new(self.primary.id(), super::p2p::Role::Station);
        self.ap_command(&self.primary.create(&self.wire, own)?, validate)
            .await?;
        let nss = self
            .chains
            .ok_or(Error::Failed)?
            .vdev_nss_for(self.wire.dialect, self.primary.id())?;
        self.ap_command(&nss, validate).await?;
        let plan = &self.ap.as_ref().unwrap().plan;
        let defaults = super::wmm::legacy_defaults(plan.config.frequency_mhz as u16, plan.rates);
        self.ap_command(&super::wmm::command(self.wire.dialect, defaults)?, validate)
            .await?;
        self.ap_barrier(validate).await?;
        self.ap_command(&self.wire.channels(&self.channels)?, validate)
            .await?;
        self.ap_barrier(validate).await?;
        self.ap_prefix(validate).await?;
        if self.htt.wmi.htc.transport.pending_htt_tx()? != 0 {
            return Err(Error::Failed);
        }
        self.ap.as_mut().unwrap().vdev = Vdev::Retired;
        self.ap = None;
        self.failed = false;
        Ok(())
    }
}
