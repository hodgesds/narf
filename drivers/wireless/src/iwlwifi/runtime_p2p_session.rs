//! API89 SESSION2 and API77 SESSION1 keep explicit PHY/link/broadcast
//! ownership and disjoint selectors. Neither inherits Sc/Bz's AUX ROC6.
//! Linux mvm/{phy-ctxt,link,mld-sta,mld-mac80211,time-event}.c.
use super::*;
pub(super) const PHY: u32 = 1;

fn link(action: u32, own: [u8; 6], channel: Channel, active: bool) -> [u8; 208] {
    let mut body =
        super::super::super::station_api::link_channel(action, own, active, channel, 0, 1);
    boot_context::put32(&mut body, 4, LINK);
    boot_context::put32(&mut body, 8, MAC);
    boot_context::put32(&mut body, 12, if active { PHY } else { u32::MAX });
    boot_context::put32(&mut body, 24, 1 | 2); // ACTIVE and actual rates only.
    boot_context::put32(&mut body, 36, 0); // P2P never advertises CCK basics.
    body
}
impl Hardware {
    async fn p2p_session_phy(
        &mut self,
        action: u32,
        channel: Channel,
        rx_chains: u32,
    ) -> Result<(), &'static str> {
        let abi = self
            .p2p
            .session
            .as_ref()
            .ok_or("P2P actual SESSION owner absent")?
            .abi;
        if abi == Abi::Session1 {
            let adapter = self
                .p2p
                .gen2
                .as_ref()
                .ok_or("P2P actual API77 PHY adapter absent")?;
            let (body, rlc) = adapter.phy(action, channel)?;
            super::super::super::ap_session::command(self, 1, 8, &body).await?;
            if let Some(rlc) = rlc {
                if !self
                    .command_with_header_version(5, 8, &rlc, 2)
                    .await?
                    .payload
                    .is_empty()
                {
                    return Err("P2P SESSION1 RLC2 PHY1 receipt extent");
                }
            }
        } else if abi == Abi::Session2 && self.is_mvm89() {
            let mut phy = super::super::super::station_api::phy_channel(action, channel);
            boot_context::put32(&mut phy, 0, PHY);
            self.ap_phy(&phy).await?;
            if action == 1 {
                // RLC2 is per actual PHY1. NSS or a PHY0 receipt loses the
                // original raw NVM receiver identity.
                let count = rx_chains.count_ones();
                let mut receive = [0; 32];
                boot_context::put32(&mut receive, 0, PHY);
                boot_context::put32(
                    &mut receive,
                    4,
                    (rx_chains << 1) | (count << 10) | (count << 12),
                );
                if !self
                    .command_with_header_version(5, 8, &receive, 2)
                    .await?
                    .payload
                    .is_empty()
                {
                    return Err("P2P SESSION2 RLC2 PHY1 receipt extent");
                }
            }
        } else {
            return Err("P2P SESSION cannot replace an AUX ROC PHY owner");
        }
        Ok(())
    }
    pub(super) async fn p2p_prepare_session(
        &mut self,
        channel: Channel,
        rx_chains: u32,
    ) -> Result<(), &'static str> {
        if !matches!(rx_chains, 1..=3) {
            return Err("P2P original SESSION/NVM receiver absent");
        }
        let session = self
            .p2p
            .session
            .as_mut()
            .ok_or("P2P SESSION2 original MAC absent")?;
        let abi = session.abi;
        let own = session.own;
        let station = session.aux_station;
        let mfp = session.broadcast_mfp;
        session
            .grant
            .as_mut()
            .ok_or("P2P SESSION2 original lease absent")?
            .phy_published = true;
        self.p2p_session_phy(1, channel, rx_chains).await?;
        // First bind the real PHY while inactive, then activate/rates.
        // Linux explicitly requires this before BCAST station/TVQM ADD.
        let mut binding = link(2, own, channel, false);
        boot_context::put32(&mut binding, 12, PHY);
        boot_context::put32(&mut binding, 24, 0);
        // A copied ACK can fail its final source check after the firmware
        // has already bound PHY1. Retire that possible reference even when
        // the caller never receives binding or activation success.
        self.p2p
            .session
            .as_mut()
            .unwrap()
            .grant
            .as_mut()
            .unwrap()
            .link_bound = true;
        super::super::super::ap_session::command(self, 3, 9, &binding).await?;
        super::super::super::ap_session::command(self, 3, 9, &link(2, own, channel, true)).await?;
        let mut broadcast = [0; 104];
        boot_context::put32(&mut broadcast, 0, u32::from(station));
        boot_context::put32(&mut broadcast, 4, LINK);
        broadcast[8..14].fill(255);
        broadcast[16..22].fill(255);
        boot_context::put32(&mut broadcast, 24, 1); // STATION_TYPE_BCAST_MGMT
        boot_context::put32(&mut broadcast, 36, u32::from(mfp));
        self.p2p
            .session
            .as_mut()
            .unwrap()
            .grant
            .as_mut()
            .unwrap()
            .aux_published = true;
        if abi == Abi::Session1 {
            let body = self
                .p2p
                .gen2
                .as_ref()
                .ok_or("P2P original API77 broadcast adapter absent")?
                .broadcast();
            let reply = self.command(1, 0x18, &body).await?;
            self.p2p.gen2.as_ref().unwrap().added(&reply.payload)
        } else {
            self.ap_peer(&broadcast).await
        }
    }
    pub(super) async fn p2p_unlink_session(
        &mut self,
        own: [u8; 6],
        channel: Channel,
    ) -> Result<(), &'static str> {
        let lease = self.p2p.session.as_ref().unwrap().grant.as_ref().unwrap();
        if lease.link_bound {
            super::super::super::ap_session::command(self, 3, 9, &link(2, own, channel, false))
                .await?;
            self.p2p
                .session
                .as_mut()
                .unwrap()
                .grant
                .as_mut()
                .unwrap()
                .link_bound = false;
        }
        if self
            .p2p
            .session
            .as_ref()
            .unwrap()
            .grant
            .as_ref()
            .unwrap()
            .phy_published
        {
            self.p2p_session_phy(3, channel, 0).await?;
            self.p2p
                .session
                .as_mut()
                .unwrap()
                .grant
                .as_mut()
                .unwrap()
                .phy_published = false;
        }
        Ok(())
    }
}
