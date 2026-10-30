//! Explicit AP control-port TX never borrows an ordinary peer data grant.
use super::super::ap_crypto::Target;
use super::*;
use zeroize::Zeroizing;
impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) async fn ap_send_control(
        &mut self,
        authority: Arc<ApControlAuthority>,
        request: narf_wireless::ControlPortTxRequest,
    ) -> Result<bool, Error> {
        if !matches!(self.state, State::AccessPoint { .. }) || !authority.has_reservation() {
            return Err(Error::Busy);
        }
        self.check_ap_request(&authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        let settings = owner
            .start_settings
            .as_ref()
            .ok_or(Error::UnsupportedFirmware)?
            .control_port;
        if !owner.activated
            || !settings.enabled
            || !settings.over_nl80211
            || request.dest == [0; 6]
            || request.dest[0] & 1 != 0
            || request.pdu().is_empty()
            || request.pdu().len() > 2304
            || !(request.ethertype == settings.ethertype
                || request.ethertype == 0x88c7 && !settings.no_preauth)
        {
            return Err(Error::Bounds);
        }
        let peer = owner
            .peers
            .get(request.dest)
            .filter(|p| p.associated)
            .ok_or(Error::Bounds)?;
        let own = owner.plan.own;
        let rate = owner.plan.rate;
        let wcid = peer.wcid;
        let protected =
            !request.no_encrypt && !settings.no_encrypt && self.ap_keys.has_pair(request.dest);
        let mut header = vec![0; 24];
        header[0] = 8;
        header[1] = 2 | if protected { 0x40 } else { 0 };
        header[4..10].copy_from_slice(&request.dest);
        header[10..16].copy_from_slice(&own);
        header[16..22].copy_from_slice(&own);
        let mut body = Zeroizing::new(vec![0xaa, 0xaa, 3, 0, 0, 0]);
        body.extend_from_slice(&request.ethertype.to_be_bytes());
        body.extend_from_slice(request.pdu());
        let mut wire = Zeroizing::new(header.clone());
        if protected {
            wire.extend_from_slice(
                &self
                    .ap_keys
                    .protect(own, Target::Pairwise(request.dest), &header, &body)
                    .map_err(|_| Error::Bounds)?,
            );
        } else {
            wire.extend_from_slice(&body);
        }
        self.ap_transmit_control_frame(authority, &wire, wcid, rate, request.wait_for_ack)
            .await
    }
}
