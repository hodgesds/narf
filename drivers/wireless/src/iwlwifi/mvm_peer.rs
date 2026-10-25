// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! An API77 AP-table entry retained behind an inactive PHY and disabled TX.
//! Linux mvm/sta.c and fw/api/sta.h: ADD_STA v12 keeps the 48-byte v10
//! structure, using mac_id_n_color as the LMAC ID, and REMOVE_STA v2 is four
//! bytes. This is neither an associated peer nor a packet-queue owner.
use super::super::boot_context::{put16, put32};
use super::{Owner, Phase};
use narf_wireless::reg::RegulatoryDomain;

const ADD_STA: u8 = 0x18;
const REMOVE_STA: u8 = 0x19;
const DISABLE_TX: u32 = 1 << 4;
const LEGACY_SISO_MASK: u32 = DISABLE_TX | (1 << 17) | (3 << 26) | (3 << 28);

#[derive(Clone, Copy)]
pub(super) struct ApPeer {
    bssid: [u8; 6],
    channel: u8,
}

fn add_command(bssid: [u8; 6]) -> [u8; 48] {
    let mut body = [0; 48];
    // Linux starts a station with all aggregation TIDs disabled. No TVQM
    // queue is allocated by this owner, and the actual TX-disable flag is
    // separately masked in. ADD, peer0, MAC0/LMAC0, LINK station type, no AID,
    // class-auth/assoc, HT/VHT, UAPSD, BA or queue mask remain zero.
    put16(&mut body, 2, u16::MAX);
    body[8..14].copy_from_slice(&bssid);
    put32(&mut body, 20, DISABLE_TX);
    put32(&mut body, 24, LEGACY_SISO_MASK);
    body
}

impl Owner {
    /// Metadata is exposed only after firmware accepted the disabled AP entry.
    /// It grants no link, transmit, key, queue or controlled-port authority.
    pub fn prepared_ap_peer(&self) -> Option<([u8; 6], u8)> {
        if !matches!(
            self.phase,
            Phase::PeerPrepared
                | Phase::ManagementQueuePrepared
                | Phase::TransmitPowerPrepared
                | Phase::LinkActive
        ) || self.hardware.is_failed()
        {
            return None;
        }
        self.peer.map(|peer| (peer.bssid, peer.channel))
    }

    /// Reserve the sole AP table entry after real inactive-channel preparation.
    /// Only a BSSID observed on that channel is eligible. The current signed
    /// receive policy and firmware MCC apply; no platform TX/SAR policy is
    /// inferred and the inactive link/disabled station never authorizes TX.
    pub async fn prepare_ap_peer(&mut self, bssid: [u8; 6]) -> Result<(), &'static str> {
        let domain = narf_wireless::reg::db::get_domain()
            .ok_or("missing authenticated MVM peer receive policy")?;
        self.prepare_peer_in_domain(bssid, &domain).await
    }

    pub(super) async fn prepare_peer_in_domain(
        &mut self,
        bssid: [u8; 6],
        domain: &RegulatoryDomain,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::ChannelPrepared
            || self.hardware.is_failed()
            || self.peer.is_some()
            || !self.scan.ready
        {
            return Err("MVM owner has no free prepared AP peer");
        }
        // Require the actually advertised legacy commands, not a guessed
        // MLD STA_CONFIG command absent from the captured API77 tables.
        if self.hardware.version(1, ADD_STA) != Some((12, 2))
            || self.hardware.version(1, REMOVE_STA) != Some((2, 0))
        {
            return Err("unsupported MVM AP peer command API");
        }
        let local = self.mac.ok_or("missing MVM peer identity")?;
        let channel = self.channel.current.ok_or("missing MVM peer PHY")?;
        let nvm = self.nvm.as_ref().ok_or("missing MVM peer NVM")?;
        if bssid == [0; 6]
            || bssid[0] & 1 != 0
            || bssid == local
            || local == [0; 6]
            || local[0] & 1 != 0
            || !nvm.channels.contains(&channel)
            || !matches!(nvm.tx_chains, 1..=3)
            || !matches!(nvm.rx_chains, 1..=3)
            || !super::scan::passive_permitted(domain, channel)
            || !self.beacons.iter().any(|beacon| {
                beacon.bssid == bssid && beacon.channel == channel && beacon.capabilities & 3 == 1
            })
        {
            return Err("MVM AP peer does not match prepared receive context");
        }
        self.validate_scan_profile()?;
        // Reserve before any MCC/ADD publication. Dropping this future leaves
        // PreparingPeer with its exact identity retained; no conflicting scan,
        // PHY release, peer retry or station activation can reuse the owner.
        self.peer = Some(ApPeer { bssid, channel });
        self.phase = Phase::PreparingPeer;
        let result = self.prepare_peer_inner(bssid, channel).await;
        match result {
            Ok(()) => {
                self.phase = Phase::PeerPrepared;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    async fn prepare_peer_inner(
        &mut self,
        bssid: [u8; 6],
        channel: u8,
    ) -> Result<(), &'static str> {
        // Refresh without recreating the already-bound idle MAC/link. Older
        // channel/scan MCC receipts confer no permanent receive permission.
        self.refresh_mcc().await?;
        if let Some(permissions) = &self.scan.permissions {
            let index = super::super::station_api::channel_index(channel)
                .ok_or("invalid MVM peer band/channel")?;
            if permissions.get(index).is_none_or(|flags| flags & 1 == 0) {
                return Err("MVM peer absent from current firmware MCC");
            }
        }
        let reply = self
            .hardware
            .command(1, ADD_STA, &add_command(bssid))
            .await?;
        // Linux iwl_mvm_send_cmd_status requires precisely one LE status
        // dword; ADD_STA_SUCCESS is low8=1, never generic empty command ACK.
        if reply.payload.len() != 4
            || u32::from_le_bytes(reply.payload[..4].try_into().unwrap()) & 0xff != 1
        {
            return Err("MVM AP peer add status failed");
        }
        Ok(())
    }

    /// Remove only the retained disabled peer. There are no packet queues or
    /// BA/key sessions to drain here; future active peers need their own ordered
    /// teardown. The PHY stays prepared until a separate acknowledged release.
    pub async fn release_ap_peer(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::PeerPrepared
            || self.hardware.is_failed()
            || self.peer.is_none()
            || self.management_queue.is_some()
        {
            return Err("MVM owner has no prepared AP peer");
        }
        if self.hardware.version(1, REMOVE_STA) != Some((2, 0)) {
            return Err("unsupported MVM AP peer removal API");
        }
        self.phase = Phase::RemovingPeer;
        let result = self.hardware.command(1, REMOVE_STA, &[0; 4]).await;
        match result {
            Ok(reply) if reply.payload.is_empty() => {
                self.peer = None;
                self.phase = Phase::ChannelPrepared;
                Ok(())
            }
            _ => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err("MVM AP peer removal failed")
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_peer_tests.rs"]
mod tests;
