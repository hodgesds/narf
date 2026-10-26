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

pub(super) struct Authenticated {
    pub status: AuthenticationStatus,
    pub response: Vec<u8>,
}
#[derive(Default)]
pub(super) struct Context {
    pub authenticated: Option<Authenticated>,
    plan: Option<JoinPlan>,
    pub(super) prepared: Option<AssociationStatus>,
    pub(super) data: Option<super::data::Prepared>,
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
        let mut plan = JoinPlan::prepare(&bss, local, ssid, security)
            .map_err(|_| "unsupported legacy association offer")?;
        plan.append_sme_ies(elements)
            .map_err(|_| "unsupported MVM SME elements")?;
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
        frame[22..24].copy_from_slice(&16u16.to_le_bytes()); // next management sequence1
        let rate = self.authentication_rate(&bss.information_elements, bss.channel)?;
        self.check_link_power(&policy()?)?;
        let (interval, dtim) = (beacon.interval, beacon.dtim.max(1));
        if interval == 0 {
            return Err("association beacon interval missing");
        }
        let mlme = &mut self.power.prepared.as_mut().unwrap().mlme;
        mlme.authenticated = None;
        mlme.plan = Some(plan);
        mlme.prepared = None;
        self.phase = Phase::Associating;
        let result = self
            .associate_inner(local, queue, &frame, rate, interval, dtim, &mut policy)
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
        let reply = self
            .qualified_link_command(1, 0x18, &peer(status.aid), policy)
            .await?;
        if reply.len() != 4 || u32::from_le_bytes(reply[..4].try_into().unwrap()) & 255 != 1 {
            return Err("associated peer/AID update failed");
        }
        self.check_link_power(&policy()?)?;
        for (group, id, body) in [
            (3, 9, link(local, status, interval, dtim).to_vec()),
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
                        protected: plan.security().is_wpa2(),
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
