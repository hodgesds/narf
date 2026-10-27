// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! One retained, unassociated open-system authentication exchange. Linux
//! mvm/sta.c::iwl_mvm_sta_modify_disable_tx, mvm/tx.c and fw/api/{sta,tx,rs}.h.
//! Only this private producer may use the temporary station0/TID15 TX window.
use super::super::{boot_context::put32, frame_api, rates::Rates, scan_api};
use super::{Owner, Phase};
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use narf_wireless::reg::RegulatoryDomain;

/// An observed protocol receipt, not association, key or controlled-port state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationStatus {
    pub bssid: [u8; 6],
    pub channel: u8,
    pub status: u16,
}

pub(super) fn disable_tx(disable: bool) -> [u8; 48] {
    let mut body = [0; 48];
    body[0] = 1; // STA_MODE_MODIFY; station0, MAC0/LMAC0
    put32(&mut body, 20, if disable { 1 << 4 } else { 0 });
    put32(&mut body, 24, 1 << 4); // modify ONLY STA_FLG_DISABLE_TX
    body
}

impl Owner {
    pub(super) fn authentication_rate(&self, ies: &[u8], channel: u8) -> Result<u32, &'static str> {
        // Linux ops.c requires all four rates-v2 indicators to agree. The
        // retained producer implements the pre-AX210 v9 TX parameters and
        // unaggregated response v6/7/8; no guessed absent-version fallback.
        if self.hardware.version(0, 0x1c).map(|v| v.0) != Some(9)
            || !matches!(self.hardware.version(1, 0x1c).map(|v| v.1), Some(6..=8))
            || self.hardware.version(0, 0xc1).map(|v| v.1) != Some(4)
            || self.hardware.version(5, 0xf7).map(|v| v.1) != Some(3)
        {
            return Err("unsupported/inconsistent MVM authentication TX/rate/RX APIs");
        }
        let chains = self
            .nvm
            .as_ref()
            .ok_or("missing authentication NVM")?
            .tx_chains;
        if !matches!(chains, 1..=3) {
            return Err("invalid authentication TX antenna");
        }
        // For legacy SISO, rates-v2 and v3 share modulation/index/antenna
        // bits. Select the lowest actual AP basic bitrate, one NVM antenna.
        Ok(
            Rates::parse_for_phy(ies, channel, u8::from(self.power.phy.offered.is_some()))?
                .management_rate(chains & chains.wrapping_neg()),
        )
    }

    /// Exchange algorithm0/transaction1 with the observed AP. The peer is
    /// disabled again before any result is published, even an AP rejection.
    /// This is not the shared station/SME interface and cannot submit data.
    pub async fn authenticate_open(&mut self) -> Result<AuthenticationStatus, &'static str> {
        self.authenticate_open_using(|| {
            narf_wireless::reg::db::get_domain()
                .ok_or("MVM current authentication policy unavailable")
        })
        .await
    }

    pub(super) async fn authenticate_open_using(
        &mut self,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<AuthenticationStatus, &'static str> {
        let link = self
            .prepared_active_link()
            .ok_or("MVM authentication requires active link")?;
        let queue = self
            .prepared_management_queue()
            .ok_or("missing authentication queue")?;
        let local = self.mac.ok_or("missing authentication MAC")?;
        if !self.hardware.idle_tx_binding(queue, 0, 15)
            || self.hardware.version(1, 0x18) != Some((12, 2))
        {
            return Err("MVM authentication peer/queue no longer matches");
        }
        let beacon = self
            .beacons
            .iter()
            .find(|b| b.bssid == link.bssid && b.channel == link.channel)
            .ok_or("missing original authentication BSS")?;
        let rate = self.authentication_rate(&beacon.information_elements, link.channel)?;
        self.check_link_power(&policy()?)?;
        // Reserve before any await, including fresh MCC. Cancel never restores
        // LinkActive while firmware may have enabled TX or consumed a packet.
        self.phase = Phase::Authenticating;
        let result = self
            .authenticate_open_inner(local, link.bssid, link.channel, queue, rate, &mut policy)
            .await;
        match result {
            Ok((status, response)) => {
                self.power.prepared.as_mut().unwrap().mlme.authenticated = (status.status == 0)
                    .then_some(super::assoc::Authenticated { status, response });
                self.phase = Phase::LinkActive;
                Ok(status)
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    async fn authenticate_open_inner(
        &mut self,
        local: [u8; 6],
        bssid: [u8; 6],
        channel: u8,
        queue: u16,
        rate: u32,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(AuthenticationStatus, alloc::vec::Vec<u8>), &'static str> {
        if let Some((version, request)) = self.mcc_request()? {
            let reply = self
                .qualified_link_command(1, 0xc8, &request, policy)
                .await?;
            self.accept_mcc(version, &reply)?;
        }
        self.check_link_power(&policy()?)?;
        // Exclude already queued management frames from this new attempt.
        self.hardware.discard_key_transition_rx()?;
        let reply = self
            .qualified_link_command(1, 0x18, &disable_tx(false), policy)
            .await?;
        if reply.len() != 4 || u32::from_le_bytes(reply[..4].try_into().unwrap()) & 0xff != 1 {
            return Err("MVM authentication peer-enable status failed");
        }
        self.check_link_power(&policy()?)?;
        let frame = frame_api::management(0xb0, local, bssid, 0, &[0, 0, 1, 0, 0, 0]);
        self.qualified_management_transmit(queue, &frame, rate, policy)
            .await?;
        self.check_link_power(&policy()?)?;
        let (status, response) = self
            .authentication_response(local, bssid, channel, policy)
            .await?;
        // Closing needs no continuing transmit authority. A terminal receipt
        // must nevertheless precede returning to the ordinary active owner.
        let reply = self
            .hardware
            .command_with_header_version(1, 0x18, &disable_tx(true), 0)
            .await?;
        if reply.payload.len() != 4
            || u32::from_le_bytes(reply.payload[..4].try_into().unwrap()) & 0xff != 1
            || !self.hardware.idle_tx_binding(queue, 0, 15)
        {
            return Err("MVM authentication peer-disable/queue receipt failed");
        }
        // Source/policy can be revoked during the closing command. Do not
        // publish protocol success under authority which is no longer current.
        self.check_link_power(&policy()?)?;
        Ok((
            AuthenticationStatus {
                bssid,
                channel,
                status,
            },
            response,
        ))
    }

    pub(super) async fn qualified_management_transmit(
        &mut self,
        queue: u16,
        frame: &[u8],
        rate: u32,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let power = self
            .power
            .prepared
            .as_ref()
            .ok_or("missing management qualification")?;
        let mut tx = pin!(self.hardware.transmit(queue, frame, 24, Some(rate)));
        poll_fn(|cx| {
            if let Err(error) = policy().and_then(|domain| power.check_applied(&domain)) {
                return Poll::Ready(Err(error));
            }
            tx.as_mut().poll(cx)
        })
        .await
    }

    /// As [`Self::qualified_management_transmit`], for the close owner's own
    /// final frame after host stop. Emission authority is still continuous.
    pub(super) async fn qualified_closing_transmit(
        &mut self,
        queue: u16,
        frame: &[u8],
        rate: u32,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let power = self
            .power
            .prepared
            .as_ref()
            .ok_or("missing management qualification")?;
        let mut tx = pin!(self.hardware.transmit_closing(queue, frame, 24, Some(rate)));
        poll_fn(|cx| {
            if let Err(error) = policy().and_then(|domain| power.check_applied(&domain)) {
                return Poll::Ready(Err(error));
            }
            tx.as_mut().poll(cx)
        })
        .await
    }

    async fn authentication_response(
        &mut self,
        local: [u8; 6],
        bssid: [u8; 6],
        channel: u8,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(u16, alloc::vec::Vec<u8>), &'static str> {
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
                let f = mpdu.frame;
                if mpdu.channel != channel
                    || f.len() < 30
                    || f[0] != 0xb0
                    || f[1] & 0xc7 != 0
                    || f[4..10] != local
                    || f[10..16] != bssid
                    || f[16..22] != bssid
                    || f[22] & 15 != 0
                    || mpdu.amsdu
                    || mpdu
                        .body(24, 0)
                        .is_none_or(|body| body.len() < 6 || body[..4] != [0, 0, 2, 0])
                {
                    continue;
                }
                let body = mpdu.body(24, 0).unwrap();
                // Retain the actual checked authentication response for the
                // association plan; never synthesize an authentication ACK.
                let mut response = f[..24].to_vec();
                response.extend_from_slice(body);
                return Ok((u16::from_le_bytes([body[4], body[5]]), response));
            }
            if deadline.expired() {
                return Err("MVM AP authentication response timed out");
            }
            activity.await;
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_auth_tests.rs"]
pub(super) mod tests;
