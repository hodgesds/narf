//! Native userspace-SME management TX. A matching terminal TXS, not token
//! release or a queued cookie, supplies the peer-ACK observation.
use super::*;

impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) async fn ap_send_management(
        &mut self,
        authority: Arc<ApControlAuthority>,
        frame: &[u8],
    ) -> Result<bool, Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        if !owner.activated
            || frame.len() < 24
            || frame[0] & 15 != 0
            || frame[1] & 0x47 != 0
            || frame[4..10] == [0; 6]
            || frame[10..16] != owner.plan.own
            || frame[16..22] != owner.plan.own
        {
            return Err(Error::Bounds);
        }
        let destination: [u8; 6] = frame[4..10].try_into().unwrap();
        // mt792x_tx uses the vif BMC WCID when no actual peer is supplied.
        let wcid = owner
            .peers
            .get(destination)
            .filter(|p| p.associated)
            .map_or(19, |p| p.wcid);
        let rate = owner.plan.rate;
        self.ap_transmit_control_frame(authority, frame, wcid, rate, true)
            .await
    }
    pub(super) async fn ap_transmit_control_frame(
        &mut self,
        authority: Arc<ApControlAuthority>,
        frame: &[u8],
        wcid: u8,
        rate: crate::mt7921::association::LegacyRate,
        request_ack: bool,
    ) -> Result<bool, Error> {
        self.check_ap_request(&authority)?;
        let destination: [u8; 6] = frame.get(4..10).ok_or(Error::Bounds)?.try_into().unwrap();
        super::super::ap_packet::descriptor(frame, 0, 1, wcid, rate)?;
        // No key, peer or port changes here: retain the current copy epoch,
        // including management received while this TX is waiting for ACK.
        self.ap_owner.as_mut().unwrap().pending = Some(authority.clone());
        self.stage(Stage::ApPeer);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.ap_drain_packets().await?;
            self.check_ap_request(&authority)?;
            let report = destination[0] & 1 == 0 && request_ack;
            if report {
                self.backend.arm_ap_management(wcid)?;
            }
            self.backend.submit_ap_management(frame, wcid, rate)?;
            self.data_pending.push_back(self.backend.now_ns());
            let terminal = self
                .wait(super::super::TIMEOUT_MS, |b| b.management_complete())
                .await?;
            self.data_pending.pop_front();
            // A no-ACK multicast frame cannot produce a positive peer ACK.
            // Its actual packet completion still bounds native ownership.
            let ack = if report {
                self.wait(super::super::TIMEOUT_MS, |b| b.poll_ap_management_ack())
                    .await?
            } else {
                if terminal.status != 0 {
                    return Err(Error::Rejected(terminal.status));
                }
                false
            };
            self.finish_ap_peer_request(&authority)?;
            Ok(ack)
        }
        .await;
        match result {
            Ok(ack) => Ok(ack),
            Err(e) => Err(self.ap_peer_failure(e).await),
        }
    }
}
