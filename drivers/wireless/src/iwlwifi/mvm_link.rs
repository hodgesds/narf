// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! API77 link activation over an already-bound PHY and TX-disabled AP peer.
//! Linux mvm/{link,mld-mac80211,mac-ctxt,power}.c and fw/api/mac-cfg.h.
//! This stage never clears STA_FLG_DISABLE_TX or exposes a packet producer.
use super::super::{boot_context::put32, rates::Rates};
use super::{Owner, Phase};
use alloc::vec::Vec;
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use narf_wireless::reg::RegulatoryDomain;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveLinkStatus {
    pub bssid: [u8; 6],
    pub channel: u8,
    pub cck_response_rates: u8,
    pub ofdm_response_rates: u8,
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_link_tests.rs"]
pub(super) mod tests;

/// Complete control-response rates exactly as iwl_mvm_ack_rates does: map
/// supported/basic legacy rates first, then include the lower mandatory PHY
/// responses. The latter are local mandatory rates, not invented AP IEs.
fn response_rates(ies: &[u8], channel: u8) -> Result<(u8, u8), &'static str> {
    let rates = Rates::parse(ies, channel)?;
    let mut cursor = ies;
    let (mut supported, mut extended, mut basic) = (false, false, false);
    while !cursor.is_empty() {
        // Rates::parse already validated every IE extent; retain explicit
        // bounds here so a later parser refactor cannot change this owner.
        if cursor.len() < 2 || usize::from(cursor[1]) > cursor.len() - 2 {
            return Err("invalid MVM link rate IE extent");
        }
        let len = usize::from(cursor[1]);
        if matches!(cursor[0], 1 | 50) {
            let duplicate = if cursor[0] == 1 {
                let duplicate = supported;
                supported = true;
                duplicate || len > 8
            } else {
                let duplicate = extended;
                extended = true;
                duplicate
            };
            if duplicate || len == 0 {
                return Err("duplicate/empty MVM link rate set");
            }
            basic |= cursor[2..2 + len].iter().any(|rate| rate & 0x80 != 0);
        }
        cursor = &cursor[2 + len..];
    }
    if !supported || !basic || rates.basic & !rates.supported != 0 {
        return Err("MVM active link requires an observed supported/basic rate intersection");
    }
    Ok(completed_response_rates(rates.basic))
}

pub(super) fn completed_response_rates(basic: u16) -> (u8, u8) {
    let mut cck = (basic & 15) as u8;
    let mut ofdm = (basic >> 4) as u8;
    let lowest_cck = if cck == 0 { 100 } else { cck.trailing_zeros() };
    let lowest_ofdm = if ofdm == 0 {
        100
    } else {
        ofdm.trailing_zeros()
    };
    for index in [3, 2, 1, 0] {
        if index < lowest_cck {
            cck |= 1 << index;
        }
    }
    for index in [4, 2, 0] {
        if index < lowest_ofdm {
            ofdm |= 1 << index;
        }
    }
    (cck, ofdm)
}

fn command(local: [u8; 6], active: Option<ActiveLinkStatus>) -> [u8; 208] {
    let mut body = [0; 208];
    put32(&mut body, 0, 2); // MODIFY existing link0/MAC0/PHY0
    body[16..22].copy_from_slice(&local);
    put32(&mut body, 24, if active.is_some() { 3 } else { 1 });
    // Linux binds PHY/local address while inactive first. They are ignored
    // when activating/deactivating; this operation does not rebind the PHY.
    if let Some(active) = active {
        put32(&mut body, 28, 1);
        put32(&mut body, 36, u32::from(active.cck_response_rates));
        put32(&mut body, 40, u32::from(active.ofdm_response_rates));
    }
    body
}

impl Owner {
    /// Firmware receipt metadata only, never carrier, association or TX rights.
    pub fn prepared_active_link(&self) -> Option<ActiveLinkStatus> {
        if self.phase != Phase::LinkActive || self.prepared_transmit_power().is_none() {
            return None;
        }
        self.power.prepared.as_ref()?.active_link
    }

    fn validate_link_api(&self) -> Result<(), &'static str> {
        // fw/img.c defaults an absent/UNKNOWN layout to1; recorded CC/Qu
        // tables may omit LINK_CONFIG. Version0 uses the same pre-v2 fields.
        if self
            .hardware
            .version(3, 9)
            .is_some_and(|(command, response)| {
                !matches!(command, 0 | 1 | 99) || !matches!(response, 0 | 99)
            })
            || self.hardware.version(1, 0xa9) != Some((1, 0))
        {
            return Err("unsupported MVM active link/MAC-power API");
        }
        Ok(())
    }

    pub(super) fn check_link_power(&self, policy: &RegulatoryDomain) -> Result<(), &'static str> {
        let power = self
            .power
            .prepared
            .as_ref()
            .ok_or("missing retained MVM link qualification")?;
        power.check_applied(policy)?;
        // This additionally checks the current NVM/MCC channel and width
        // flags. A completed power command is never permanent channel right.
        self.current_power(policy)?;
        Ok(())
    }

    /// Activate the existing legacy20 link after actual platform/host power
    /// preparation. The AP station and its management queue remain TX-disabled.
    pub async fn activate_link(&mut self) -> Result<(), &'static str> {
        self.activate_link_using(|| {
            narf_wireless::reg::db::get_domain().ok_or("MVM current active-link policy unavailable")
        })
        .await
    }

    async fn activate_link_using(
        &mut self,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::TransmitPowerPrepared || self.hardware.is_failed() {
            return Err("MVM link activation requires completed inactive power preparation");
        }
        self.validate_link_api()?;
        let queue = self
            .prepared_management_queue()
            .ok_or("missing MVM management queue")?;
        if !self.hardware.idle_tx_binding(queue, 0, 15) {
            return Err("MVM management queue is no longer its unused station0/TID15 prerequisite");
        }
        let (bssid, channel) = self
            .prepared_ap_peer()
            .ok_or("missing disabled MVM AP peer")?;
        let power = self
            .prepared_transmit_power()
            .ok_or("MVM link power is not current")?;
        if power.channel != channel
            || self.channel.current != Some(channel)
            || self
                .power
                .prepared
                .as_ref()
                .is_none_or(|power| power.active_link.is_some())
        {
            return Err("MVM active link does not match its retained peer/PHY/power");
        }
        let local = self.mac.ok_or("missing MVM link MAC")?;
        let beacon = self
            .beacons
            .iter()
            .find(|beacon| beacon.bssid == bssid && beacon.channel == channel)
            .ok_or("missing original MVM link BSS")?;
        let (cck_response_rates, ofdm_response_rates) =
            response_rates(&beacon.information_elements, channel)?;
        let active = ActiveLinkStatus {
            bssid,
            channel,
            cck_response_rates,
            ofdm_response_rates,
        };
        self.check_link_power(&policy()?)?;
        // Reserve the exact identity/rates before the first MCC/control wait.
        // Cancellation cannot turn a possibly active firmware link into an
        // inactive power/queue owner that another attempt may reuse.
        self.power.prepared.as_mut().unwrap().active_link = Some(active);
        self.phase = Phase::ActivatingLink;
        match self.activate_link_inner(local, active, &mut policy).await {
            Ok(()) => {
                self.phase = Phase::LinkActive;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    async fn activate_link_inner(
        &mut self,
        local: [u8; 6],
        active: ActiveLinkStatus,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if let Some((version, query)) = self.mcc_request()? {
            let response = self.qualified_link_command(1, 0xc8, &query, policy).await?;
            self.accept_mcc(version, &response)?;
        }
        self.check_link_power(&policy()?)?;
        let response = self
            .qualified_link_command(3, 9, &command(local, Some(active)), policy)
            .await?;
        if !response.is_empty() {
            return Err("invalid MVM active link receipt");
        }
        self.check_link_power(&policy()?)?;
        // mld_assign_vif_chanctx updates ordinary MAC power after activation.
        // This unassociated profile remains awake, keep-alive25s, no PS/quotas.
        let response = self
            .qualified_link_command(1, 0xa9, &super::scan::awake_mac_power(), policy)
            .await?;
        if !response.is_empty() {
            return Err("invalid MVM active MAC-power receipt");
        }
        self.check_link_power(&policy()?)?;
        Ok(())
    }

    pub(super) async fn qualified_link_command(
        &mut self,
        group: u8,
        id: u8,
        body: &[u8],
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Vec<u8>, &'static str> {
        let power = self
            .power
            .prepared
            .as_ref()
            .ok_or("missing retained MVM link qualification")?;
        let mut future = pin!(self
            .hardware
            .command_with_header_version(group, id, body, 0));
        poll_fn(|cx| {
            let result = policy().and_then(|domain| power.check_applied(&domain));
            if let Err(error) = result {
                return Poll::Ready(Err(error));
            }
            future.as_mut().poll(cx)
        })
        .await
        .map(|packet| packet.payload)
    }

    /// Closing an acknowledged active link requires no continuing TX grant.
    /// It still requires the exact native receipt; source loss or cancellation
    /// never releases any queue/peer/PHY or uncertain command DMA by itself.
    pub async fn deactivate_link(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::LinkActive
            || self.hardware.is_failed()
            || self
                .power
                .prepared
                .as_ref()
                .is_none_or(|power| power.active_link.is_none())
        {
            return Err("MVM owner has no completed active link to deactivate");
        }
        self.validate_link_api()?;
        let local = self.mac.ok_or("missing MVM active link MAC")?;
        self.phase = Phase::DeactivatingLink;
        let result = self
            .hardware
            .command_with_header_version(3, 9, &command(local, None), 0)
            .await;
        match result {
            Ok(reply) if reply.payload.is_empty() => {
                self.power.prepared.as_mut().unwrap().active_link = None;
                self.power.prepared.as_mut().unwrap().mlme = super::assoc::Context::default();
                self.phase = Phase::TransmitPowerPrepared;
                Ok(())
            }
            _ => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err("MVM link deactivation did not receive its exact native ACK")
            }
        }
    }
}
