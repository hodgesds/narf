// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Legacy20 association after retained native authentication. Linux mvm/
//! {mld-mac,link,sta}.c and mac80211 assoc_success; no carrier/data grant.
use super::super::{
    boot_context::{put16, put32},
    scan_api,
};
use super::{AuthenticationStatus, Owner, Phase};
use alloc::vec::Vec;
use narf_wireless::{
    association::{Bss, JoinPlan, SecurityMode},
    reg::RegulatoryDomain,
};

/// IEEE 802.11 management subtype 12 (Deauthentication), FC byte0.
pub(super) const DEAUTHENTICATION: u8 = 0xc0;
/// IEEE 802.11-2020 Table 9-49 reason 3, Linux `WLAN_REASON_DEAUTH_LEAVING`,
/// the reason cfg80211/wpa_supplicant use for a local disconnect.
pub(super) const DEAUTH_LEAVING: u16 = 3;

pub(super) struct Authenticated {
    pub status: AuthenticationStatus,
    pub response: Vec<u8>,
}
#[derive(Default)]
pub(super) struct Context {
    pub authenticated: Option<Authenticated>,
    pub(super) plan: Option<JoinPlan>,
    pub(super) prepared: Option<AssociationStatus>,
    pub(super) data: Option<super::data::Prepared>,
    /// Retained SAE plan/request/PMK between authentication and association.
    pub(super) sae: Option<alloc::boxed::Box<super::pmf::SaeAuthenticated>>,
    /// SAE PMK retained by a completed PMF association for its 4-way owner.
    pub(super) sae_pmk: Option<zeroize::Zeroizing<[u8; 32]>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssociationStatus {
    pub bssid: [u8; 6],
    pub channel: u8,
    pub aid: u16,
    pub supported_rates: u16,
    pub basic_rates: u16,
    pub protected: bool,
    pub short_preamble: bool,
    pub short_slot: bool,
    pub erp_protection: bool,
    /// Management-frame protection negotiated (WPA3-SAE, MFPR).
    pub pmf: bool,
}

fn peer(aid: u16) -> [u8; 48] {
    let mut body = super::auth::disable_tx(true);
    // Legacy MVM does not set CLASS_AUTH/CLASS_ASSOC in ADD_STA; Linux
    // supplies assoc_id after ieee80211_sta_state(ASSOC) and keeps SISO.
    put16(&mut body, 36, aid);
    body
}
fn mac(local: [u8; 6], aid: Option<u16>) -> [u8; 52] {
    let mut body = [0; 52];
    put32(&mut body, 4, 2);
    put32(&mut body, 8, 5);
    body[12..18].copy_from_slice(&local);
    put32(&mut body, 20, if aid.is_some() { 4 } else { 12 });
    if let Some(aid) = aid {
        body[36] = 1;
        put16(&mut body, 40, aid);
    }
    body
}
fn link(local: [u8; 6], status: AssociationStatus, interval: u16, dtim: u8) -> [u8; 208] {
    let mut body = [0; 208];
    put32(&mut body, 0, 2);
    body[16..22].copy_from_slice(&local);
    // Existing active PHY is unchanged: rates/protection/beacon timing only.
    put32(&mut body, 24, 2 | 4 | 16);
    let (cck, ofdm) = super::link::completed_response_rates(status.basic_rates);
    put32(&mut body, 36, u32::from(cck));
    put32(&mut body, 40, u32::from(ofdm));
    put32(&mut body, 44, u32::from(status.short_preamble));
    put32(&mut body, 48, u32::from(status.short_slot));
    put32(&mut body, 52, u32::from(status.erp_protection));
    // No HT, WMM, UAPSD, BA or HE flags can enter this legacy profile.
    put32(&mut body, 136, u32::from(interval));
    put32(&mut body, 140, u32::from(interval) * u32::from(dtim));
    body
}
fn beacon_timing(beacon: &super::super::connection::Beacon) -> Result<(u16, u8), &'static str> {
    if beacon.interval == 0 {
        return Err("association beacon interval missing");
    }
    Ok((beacon.interval, beacon.dtim.max(1)))
}
impl Owner {
    pub fn associated_station(&self) -> Option<AssociationStatus> {
        if !matches!(self.phase, Phase::Associated | Phase::DataPrepared)
            || self.hardware.is_failed()
        {
            return None;
        }
        let power = self.power.prepared.as_ref()?;
        self.prepared_transmit_power()?;
        power.mlme.prepared
    }
    /// No keys/controlled-port state is granted by successful association.
    pub async fn associate_legacy(
        &mut self,
        ssid: &[u8],
        security: SecurityMode,
    ) -> Result<AssociationStatus, &'static str> {
        self.associate_legacy_using(ssid, security, || {
            narf_wireless::reg::db::get_domain().ok_or("MVM association policy unavailable")
        })
        .await
    }
    pub(super) async fn associate_legacy_using(
        &mut self,
        ssid: &[u8],
        security: SecurityMode,
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AssociationStatus, &'static str> {
        self.associate_elements_using(ssid, security, &[], policy)
            .await
    }
    pub(super) async fn associate_elements_using(
        &mut self,
        ssid: &[u8],
        security: SecurityMode,
        elements: &[u8],
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AssociationStatus, &'static str> {
        let active = self
            .prepared_active_link()
            .ok_or("association requires active link")?;
        let queue = self
            .prepared_management_queue()
            .ok_or("association queue missing")?;
        let local = self.mac.ok_or("association MAC missing")?;
        if !self.hardware.idle_tx_binding(queue, 0, 15)
            || self.hardware.version(1, 0x18) != Some((12, 2))
            || self.hardware.version(3, 8) != Some((1, 0))
        {
            return Err("unsupported association peer/MAC API");
        }
        let beacon = self
            .beacons
            .iter()
            .find(|b| b.bssid == active.bssid && b.channel == active.channel)
            .ok_or("association BSS missing")?;
        let bss = Bss {
            bssid: beacon.bssid,
            ssid: beacon.ssid.clone(),
            channel: beacon.channel,
            signal_dbm: None,
            capability: beacon.capabilities,
            beacon_interval: beacon.interval,
            information_elements: beacon.information_elements.clone(),
        };
        if security.is_sae() {
            let timing = beacon_timing(beacon)?;
            return self
                .associate_sae_using(local, queue, timing, &mut policy)
                .await;
        }
        let mut plan = self.station_plan(
            &bss,
            ssid,
            security,
            elements,
            self.power.phy.offered.is_some(),
        )?;
        let authenticated = self
            .power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.authenticated.as_ref())
            .ok_or("missing actual retained authentication")?;
        if authenticated.status.bssid != active.bssid
            || authenticated.status.channel != active.channel
            || authenticated.status.status != 0
        {
            return Err("authentication differs from association context");
        }
        // This plan consumes the actual completed previous request/response,
        // whose TX completion and re-disable are retained by the same owner.
        plan.start_authentication()
            .map_err(|_| "association plan state")?;
        let mut frame = plan
            .authentication_response(&authenticated.response)
            .map_err(|_| "retained authentication invalid")?
            .ok_or("retained authentication foreign")?
            .to_vec();
        if self.power.phy.offered.is_some() {
            if frame.len() + narf_wireless::wmm::INFORMATION.len() > 4096 {
                return Err("MVM WMM request extent exceeded");
            }
            frame.extend_from_slice(&narf_wireless::wmm::INFORMATION);
        }
        frame[22..24].copy_from_slice(&16u16.to_le_bytes()); // next management sequence1
        let rate = self.authentication_rate(&bss.information_elements, bss.channel)?;
        self.check_link_power(&policy()?)?;
        let (interval, dtim) = beacon_timing(beacon)?;
        let mlme = &mut self.power.prepared.as_mut().unwrap().mlme;
        mlme.authenticated = None;
        mlme.plan = Some(plan);
        mlme.prepared = None;
        self.phase = Phase::Associating;
        self.finish_association(local, queue, &frame, rate, interval, dtim, &mut policy)
            .await
    }
    /// Shared tail of every association: reserve, exchange, publish.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn finish_association(
        &mut self,
        local: [u8; 6],
        queue: u16,
        frame: &[u8],
        rate: u32,
        interval: u16,
        dtim: u8,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AssociationStatus, &'static str> {
        let result = self
            .associate_inner(local, queue, frame, rate, interval, dtim, policy)
            .await;
        match result {
            Ok(status) => {
                self.phase = Phase::Associated;
                Ok(status)
            }
            Err(e) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(e)
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    async fn associate_inner(
        &mut self,
        local: [u8; 6],
        queue: u16,
        frame: &[u8],
        rate: u32,
        interval: u16,
        dtim: u8,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AssociationStatus, &'static str> {
        if let Some((version, query)) = self.mcc_request()? {
            let reply = self.qualified_link_command(1, 0xc8, &query, policy).await?;
            self.accept_mcc(version, &reply)?;
        }
        self.check_link_power(&policy()?)?;
        self.hardware.discard_key_transition_rx()?;
        let reply = self
            .qualified_link_command(1, 0x18, &super::auth::disable_tx(false), policy)
            .await?;
        if reply.len() != 4 || u32::from_le_bytes(reply[..4].try_into().unwrap()) & 255 != 1 {
            return Err("association peer enable failed");
        }
        self.qualified_management_transmit(queue, frame, rate, policy)
            .await?;
        let status = self.association_response(local, policy).await?;
        // Re-disable before any associated MAC/link update. A late/failed
        // response can never promote this private packet producer to data TX.
        let reply = self
            .hardware
            .command_with_header_version(1, 0x18, &super::auth::disable_tx(true), 0)
            .await?;
        if reply.payload.len() != 4
            || u32::from_le_bytes(reply.payload[..4].try_into().unwrap()) & 255 != 1
        {
            return Err("association peer disable failed");
        }
        self.check_link_power(&policy()?)?;
        let peer = self
            .power
            .phy
            .negotiated
            .map_or_else(|| peer(status.aid), |p| p.peer(status.aid));
        let reply = self.qualified_link_command(1, 0x18, &peer, policy).await?;
        if reply.len() != 4 || u32::from_le_bytes(reply[..4].try_into().unwrap()) & 255 != 1 {
            return Err("associated peer/AID update failed");
        }
        self.check_link_power(&policy()?)?;
        let mut link = link(local, status, interval, dtim);
        if let Some(p) = self.power.phy.negotiated {
            put32(
                &mut link,
                52,
                u32::from(status.erp_protection) | p.protection,
            );
        }
        for (group, id, body) in [
            (3, 9, link.to_vec()),
            (3, 8, mac(local, Some(status.aid)).to_vec()),
        ] {
            if !self
                .qualified_link_command(group, id, &body, policy)
                .await?
                .is_empty()
            {
                return Err("associated link/MAC receipt invalid");
            }
        }
        self.check_link_power(&policy()?)?;
        if !self.hardware.idle_tx_binding(queue, 0, 15) {
            return Err("association queue not terminal");
        }
        Ok(status)
    }
    async fn association_response(
        &mut self,
        local: [u8; 6],
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AssociationStatus, &'static str> {
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            self.check_link_power(&policy()?)?;
            let activity = self.hardware.activity();
            self.hardware.poll()?;
            while let Some(index) = self
                .hardware
                .notifications
                .iter()
                .position(|p| p.header.group_id == 0 && p.header.cmd == 0xc1)
            {
                let packet = self.hardware.notifications.remove(index).unwrap();
                let Some(mpdu) = scan_api::mpdu_gen2(&packet.payload) else {
                    continue;
                };
                let power = self.power.prepared.as_mut().unwrap();
                let active = power.active_link.unwrap();
                let f = mpdu.frame;
                if mpdu.channel != active.channel
                    || mpdu.amsdu
                    || f.len() < 30
                    || f[0] != 0x10
                    || f[1] & 0xc7 != 0
                    || f[4..10] != local
                    || f[10..16] != active.bssid
                    || f[16..22] != active.bssid
                    || f[22] & 15 != 0
                {
                    continue;
                }
                // Remove only firmware-described MAC padding/trailer before
                // the shared plan validates complete IEs, AID and rate offer.
                let Some(body) = mpdu.body(24, 0).filter(|body| body.len() >= 6) else {
                    continue;
                };
                let mut response = f[..24].to_vec();
                response.extend_from_slice(body);
                let plan = power.mlme.plan.as_mut().unwrap();
                if let Some(aid) = plan
                    .association_response(&response)
                    .map_err(|_| "AP association rejection/invalid response")?
                {
                    let (supported_rates, basic_rates) = plan.legacy_rates();
                    self.power.phy.confirm(plan, &body[6..])?;
                    let capability = u16::from_le_bytes([body[0], body[1]]);
                    let beacon = self
                        .beacons
                        .iter()
                        .find(|b| b.bssid == active.bssid && b.channel == active.channel)
                        .ok_or("associated BSS disappeared")?;
                    let negotiated = beacon.capabilities & capability;
                    let mut ies = beacon.information_elements.as_slice();
                    let mut erp = None;
                    while !ies.is_empty() {
                        if ies.len() < 2 || usize::from(ies[1]) > ies.len() - 2 {
                            return Err("invalid retained association IEs");
                        }
                        let len = usize::from(ies[1]);
                        if ies[0] == 42 && (len != 1 || erp.replace(ies[2]).is_some()) {
                            return Err("invalid association ERP profile");
                        }
                        ies = &ies[2 + len..];
                    }
                    let status = AssociationStatus {
                        bssid: active.bssid,
                        channel: active.channel,
                        aid,
                        supported_rates,
                        basic_rates,
                        protected: plan.security().is_rsn(),
                        pmf: plan.security().is_sae(),
                        short_preamble: active.channel <= 14 && negotiated & 32 != 0,
                        short_slot: active.channel > 14 || negotiated & 1024 != 0,
                        erp_protection: active.channel <= 14 && erp.is_some_and(|erp| erp & 2 != 0),
                    };
                    power.mlme.prepared = Some(status);
                    return Ok(status);
                }
            }
            if deadline.expired() {
                return Err("AP association response timed out");
            }
            activity.await;
        }
    }
    /// Linux net/mac80211/mlme.c::ieee80211_set_disassoc(tx=true), reached
    /// from a local cfg80211 disconnect: pending host frames are dropped
    /// first (the close owner drains the TX ring), then one Deauthentication
    /// goes to the current AP while the association, peer, management queue
    /// and keys are still installed, and its terminal TX receipt is awaited
    /// before any station teardown. Without MFP the frame is unprotected
    /// (IEEE 802.11-2020 11.13). A PMF association with an installed PTK
    /// sets Protected: Gen2's new TX API leaves no IV space and firmware
    /// CCMP-encrypts with the station key (`iwl_mvm_set_tx_params` clears
    /// `IWL_TX_FLAGS_ENCRYPT_DIS` for a hardware key, mac80211.c omits
    /// `PUT_IV_SPACE` on the new TX API).
    ///
    /// Without current platform/host emission authority the close stays
    /// local (Linux `tx=false`). A terminal TX_CMD without ACK is a complete
    /// receipt; only a revoked or uncertain in-flight frame fails the owner.
    /// Returns whether the AP acknowledged the frame.
    pub(super) async fn deauthenticate_using(
        &mut self,
        reason: u16,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<bool, &'static str> {
        if self.phase != Phase::DataPrepared || self.hardware.is_failed() {
            return Err("no associated MVM owner to deauthenticate");
        }
        let queue = self
            .management_queue
            .as_ref()
            .and_then(|q| q.id)
            .ok_or("MVM deauthentication management queue absent")?;
        let local = self.mac.ok_or("missing deauthentication MAC")?;
        if policy()
            .and_then(|domain| self.check_link_power(&domain))
            .is_err()
        {
            return Ok(false);
        }
        let chains = self
            .nvm
            .as_ref()
            .ok_or("missing deauthentication NVM")?
            .tx_chains;
        let keyed = self.security.has_pairwise();
        let data = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
            .ok_or("MVM deauthentication data owner absent")?;
        data.port_open = false;
        let mut frame = super::super::frame_api::management(
            DEAUTHENTICATION,
            local,
            data.status.bssid,
            data.sequence,
            &reason.to_le_bytes(),
        );
        if data.status.pmf && keyed {
            frame[1] |= 0x40;
        }
        data.sequence = data.sequence.wrapping_add(1) & 4095;
        let rate = super::super::rates::Rates {
            supported: data.status.supported_rates,
            basic: data.status.basic_rates,
        }
        .management_rate(chains & chains.wrapping_neg());
        // Reserved before publication; a cancelled close cannot reissue it.
        self.phase = Phase::TransmittingData;
        match self
            .qualified_closing_transmit(queue, &frame, rate, policy)
            .await
        {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                Ok(true)
            }
            Err(error) if error == super::super::runtime::TX_FAILED => {
                self.phase = Phase::DataPrepared;
                Ok(false)
            }
            Err(error) => self.data_failed(error),
        }
    }

    /// Local association close, without claiming an over-air deauthentication.
    /// Exact firmware receipts precede returning the still-active disabled peer.
    pub async fn clear_association(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::Associated || self.hardware.is_failed() {
            return Err("no completed association to close");
        }
        let local = self.mac.ok_or("missing associated MAC")?;
        self.phase = Phase::ClearingAssociation;
        let result = async {
            let reply = self
                .hardware
                .command_with_header_version(3, 8, &mac(local, None), 0)
                .await?;
            if !reply.payload.is_empty() {
                return Err("MAC association close receipt invalid");
            }
            let reply = self
                .hardware
                .command_with_header_version(1, 0x18, &peer(0), 0)
                .await?;
            if reply.payload.len() != 4
                || u32::from_le_bytes(reply.payload[..4].try_into().unwrap()) & 255 != 1
            {
                return Err("peer association close receipt invalid");
            }
            let active = self.power.prepared.as_ref().unwrap().active_link.unwrap();
            let mut idle = [0; 208];
            put32(&mut idle, 0, 2);
            idle[16..22].copy_from_slice(&local);
            put32(&mut idle, 24, 2 | 4 | 16);
            put32(&mut idle, 36, u32::from(active.cck_response_rates));
            put32(&mut idle, 40, u32::from(active.ofdm_response_rates));
            let reply = self
                .hardware
                .command_with_header_version(3, 9, &idle, 0)
                .await?;
            if !reply.payload.is_empty() {
                return Err("link association close receipt invalid");
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.power.prepared.as_mut().unwrap().mlme = Context::default();
                self.phase = Phase::LinkActive;
                Ok(())
            }
            Err(e) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(e)
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_assoc_tests.rs"]
mod tests;
