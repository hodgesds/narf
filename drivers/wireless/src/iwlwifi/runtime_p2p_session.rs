//! API89 SESSION2 uses actual PHY/link/broadcast STA ownership. It cannot
//! inherit Sc/Bz's inactive-link AUX ROC6 or API77's MAC-selector binding.
//! Linux mvm/{phy-ctxt,link,mld-sta,mld-mac80211,time-event}.c.
use super::*;
const PHY: u32 = 1;

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
    pub(super) async fn p2p_prepare_session2(
        &mut self,
        channel: Channel,
        rx_chains: u32,
    ) -> Result<(), &'static str> {
        if !self.is_mvm89() || !matches!(rx_chains, 1..=3) {
            return Err("P2P SESSION2 original API89/NVM receiver absent");
        }
        let session = self
            .p2p
            .session
            .as_mut()
            .ok_or("P2P SESSION2 original MAC absent")?;
        if session.abi != Abi::Session2 {
            return Err("P2P SESSION2 cannot replace AUX ROC");
        }
        let own = session.own;
        let station = session.aux_station;
        let mfp = session.broadcast_mfp;
        session
            .grant
            .as_mut()
            .ok_or("P2P SESSION2 original lease absent")?
            .phy_published = true;
        let mut phy = super::super::super::station_api::phy_channel(1, channel);
        boot_context::put32(&mut phy, 0, PHY);
        self.ap_phy(&phy).await?;
        // API89's RLC2 is per-PHY, not the root's already-completed PHY0
        // receipt. Retain the raw NVM chain mask; NSS alone loses identity.
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
        self.ap_peer(&broadcast).await
    }
    pub(super) async fn p2p_unlink_session2(
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
            let mut phy = super::super::super::station_api::phy_channel(3, channel);
            boot_context::put32(&mut phy, 0, PHY);
            self.ap_phy(&phy).await?;
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
