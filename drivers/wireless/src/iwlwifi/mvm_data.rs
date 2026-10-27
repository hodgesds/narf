// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained API77 non-QoS legacy20 data service. Linux mvm/{sta,tx,rs-fw,
//! mac-ctxt}.c: normal data TID0, LINK EDCA and native TLC v2/v3/v4.
//! Association never grants a secured port or permission to bypass SAR.
use super::super::{
    boot_context::{put16, put32},
    frame_api,
    rates::Rates,
    scan_api,
};
use super::{AssociationStatus, Owner, Phase};
use alloc::{vec, vec::Vec};
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};
use narf_wireless::reg::RegulatoryDomain;

const STATION: u8 = 0;
const TID: u8 = 0; // fw/api/tx.h::IWL_TID_NON_QOS

/// Completed native prerequisite metadata, not a permanent transmit grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyDataStatus {
    pub bssid: [u8; 6],
    pub channel: u8,
    pub queue: u16,
    pub supported_rates: u16,
    pub protected: bool,
}

#[derive(Debug, Eq, PartialEq)]
pub enum LegacyReceive {
    Ethernet(Vec<u8>),
    /// An Ethernet packet whose L3/L4 checksums the firmware verified
    /// (`csum::rx_meta_l3l4`); only non-empty verdicts use this variant.
    Checked(Vec<u8>, narf_net::RxMeta),
    /// A bounded, original plaintext EAPOL packet observed before the native
    /// RSNA owner starts. It is never delivered to the ordinary Ethernet port.
    Eapol(Vec<u8>),
}

pub(super) struct Prepared {
    pub(super) status: AssociationStatus,
    pub(super) queue: Option<u16>,
    pub(super) port_open: bool,
    pub(super) sequence: u16,
    pub(super) replay: frame_api::Replay,
    pub(super) last_peer: u64,
    pub(super) aggregate: super::amsdu::Receiver,
}

fn edca(local: [u8; 6], use_11b: bool) -> [u8; 208] {
    let mut bytes = [0; 208];
    put32(&mut bytes, 0, 2); // MODIFY
    bytes[16..22].copy_from_slice(&local);
    // LINK_CONTEXT_MODIFY_QOS_PARAMS only.
    put32(&mut bytes, 24, 8);
    // This station did not negotiate WMM. mac80211::set_wmm_default(false)
    // uses DCF CWmin31 for11b, otherwise15, CWmax1023, AIFS2, TXOP0.
    // Firmware AC order BK/BE/VI/VO; Gen2 EDCA FIFO numbers1/2/3/4.
    // qos_flags=0: neither UPDATE_EDCA/WMM nor HT/TGN is negotiated.
    for index in 0..4 {
        let at = 60 + index * 8;
        put16(&mut bytes, at, if use_11b { 31 } else { 15 });
        put16(&mut bytes, at + 2, 1023);
        bytes[at + 4] = 2;
        bytes[at + 5] = 1 << (index + 1);
    }
    bytes
}

fn tlc(version: u8, rates: u16, chains: u8) -> Result<Vec<u8>, &'static str> {
    // rs-fw.c converts v4 to v3 and omits the final max_tx_op dword
    // belowv3. Legacy20 has no HT/SGI/A-MSDU, so all remaining fields0.
    let length = match version {
        2 => 24,
        3 | 4 => 28,
        _ => return Err("unsupported MVM legacy TLC payload"),
    };
    let mut bytes = vec![0; length];
    bytes[6] = chains;
    put16(&mut bytes, 10, rates);
    Ok(bytes)
}

fn legacy_rx_rate(payload: &[u8], status: LegacyDataStatus) -> bool {
    // API4 RX descriptor rate_n_flags is at28, before energy/channel at32.
    // This owner admitted rates-v2: modulation8..10 and width11..13.
    let Some(bytes) = payload.get(28..32) else {
        return false;
    };
    let rate = u32::from_le_bytes(bytes.try_into().unwrap());
    let index = rate & 15;
    let bit = match ((rate >> 8) & 7, index) {
        (0, 0..=3) if status.channel <= 14 => index,
        (1, 0..=7) => index + 4,
        _ => return false,
    };
    rate & (0xf0 | (7 << 11)) == 0 && status.supported_rates & (1 << bit) != 0
}

pub(super) fn ap_disconnected(
    mpdu: &scan_api::Mpdu<'_>,
    local: [u8; 6],
    status: LegacyDataStatus,
) -> bool {
    let f = mpdu.frame;
    mpdu.channel == status.channel
        && f.len() >= 24
        && matches!(f[0], 0xa0 | 0xc0)
        && f[1] & 0xc7 == 0
        && f[4..10] == local
        && f[10..16] == status.bssid
        && f[16..22] == status.bssid
        && f[22] & 15 == 0
        && !mpdu.amsdu
        && mpdu.body(24, 0).is_some_and(|b| b.len() == 2)
}

impl Owner {
    pub fn prepared_legacy_data(&self) -> Option<LegacyDataStatus> {
        if self.phase != Phase::DataPrepared || self.prepared_transmit_power().is_none() {
            return None;
        }
        let data = self.power.prepared.as_ref()?.mlme.data.as_ref()?;
        Some(LegacyDataStatus {
            bssid: data.status.bssid,
            channel: data.status.channel,
            queue: data.queue?,
            supported_rates: data.status.supported_rates,
            protected: data.status.protected,
        })
    }

    /// Current host policy and the retained signed platform source are
    /// checked again; historical queue/association metadata cannot open it.
    pub fn legacy_data_port_open(&mut self) -> bool {
        self.data_port_using(|| {
            narf_wireless::reg::db::get_domain().ok_or("MVM data policy unavailable")
        })
    }

    pub(super) fn data_port_using(
        &mut self,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> bool {
        if self.phase != Phase::DataPrepared {
            return false;
        }
        match policy().and_then(|p| self.data_ready(&p)) {
            Ok(status) => !status.protected || self.security.ready(),
            Err(error) => {
                let _ = self.data_failed::<()>(error);
                false
            }
        }
    }

    fn data_ready(&self, policy: &RegulatoryDomain) -> Result<LegacyDataStatus, &'static str> {
        let status = self
            .prepared_legacy_data()
            .ok_or("MVM data owner is not terminal/ready")?;
        self.check_link_power(policy)?;
        let prepared = self.power.prepared.as_ref().unwrap();
        if self.power.phy.negotiated.is_some() && prepared.emission != self.power.phy.emission() {
            return Err("MVM active PHY differs from qualified emitting program");
        }
        let data = prepared.mlme.data.as_ref().unwrap();
        if prepared.mlme.prepared != Some(data.status)
            || !self.hardware.idle_tx_binding(status.queue, STATION, TID)
            || (!status.protected && !data.port_open)
        {
            return Err("MVM data association/queue/controlled-port identity changed");
        }
        Ok(status)
    }

    pub async fn prepare_legacy_data(&mut self) -> Result<LegacyDataStatus, &'static str> {
        self.prepare_data_using(|| {
            narf_wireless::reg::db::get_domain().ok_or("MVM data policy unavailable")
        })
        .await
    }

    pub(super) async fn prepare_data_using(
        &mut self,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<LegacyDataStatus, &'static str> {
        if self.phase != Phase::Associated {
            return Err("MVM data requires completed association");
        }
        let association = self
            .associated_station()
            .ok_or("MVM associated peer missing")?;
        let queue = self
            .prepared_management_queue()
            .ok_or("MVM management queue missing")?;
        if self.power.prepared.as_ref().unwrap().mlme.data.is_some()
            || !self.hardware.idle_tx_binding(queue, STATION, 15)
            || self.hardware.version(5, 0x17) != Some((3, 2))
            || self.hardware.version(1, 0x18) != Some((12, 2))
        {
            return Err("unsupported MVM data peer/queue contract");
        }
        let local = self.mac.ok_or("MVM data MAC missing")?;
        let beacon = self
            .beacons
            .iter()
            .find(|b| b.bssid == association.bssid && b.channel == association.channel)
            .ok_or("MVM data BSS missing")?;
        // This also validates the exact Gen2 TX-v9/RX-v4/rates-v2 contract.
        self.authentication_rate(&beacon.information_elements, association.channel)?;
        let phy = self.power.phy.negotiated;
        if phy.is_some()
            && self.power.prepared.as_ref().unwrap().emission != self.power.phy.emission()
        {
            return Err("MVM new emitting profile lacks its distinct signed qualification");
        }
        let beacon_rates = Rates::parse_for_phy(
            &beacon.information_elements,
            association.channel,
            u8::from(phy.is_some_and(|p| p.ht)),
        )?;
        let allowed = if association.channel == 14 {
            15
        } else if association.channel <= 13 {
            0xfff
        } else {
            0xff0
        };
        if association.supported_rates == 0
            || association.supported_rates & !allowed != 0
            || association.basic_rates == 0
            || association.basic_rates & !association.supported_rates != 0
        {
            return Err("MVM data association rates invalid");
        }
        let chains = self.nvm.as_ref().unwrap().tx_chains;
        let chains = (chains & chains.wrapping_neg()) as u8;
        let payload = if let Some(p) = phy {
            p.tlc(
                self.hardware.version(5, 15).ok_or("MVM TLC API absent")?.0,
                association.supported_rates,
                chains,
            )?
        } else {
            tlc(
                self.hardware.version(5, 15).ok_or("MVM TLC API absent")?.0,
                association.supported_rates,
                chains,
            )?
        };
        let edca = phy.map_or_else(
            || edca(local, beacon_rates.supported & 0xff0 == 0),
            |p| p.edca(local),
        );
        self.check_link_power(&policy()?)?;
        // Reserve before any MCC/control/queue publication. A dropped future
        // retains this phase and every uncertain DMA allocation in Hardware.
        self.power.prepared.as_mut().unwrap().mlme.data = Some(Prepared {
            status: association,
            queue: None,
            port_open: false,
            sequence: 0,
            replay: frame_api::Replay::default(),
            last_peer: narf_time::now_cycles(),
            aggregate: super::amsdu::Receiver::default(),
        });
        self.phase = Phase::PreparingData;
        let result = self.prepare_data_inner(&edca, &payload, &mut policy).await;
        match result {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                self.prepared_legacy_data()
                    .ok_or("MVM data completion lost")
            }
            Err(error) => self.data_failed(error),
        }
    }

    pub(super) async fn fresh_data_policy(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if let Some((version, query)) = self.mcc_request()? {
            let reply = self.qualified_link_command(1, 0xc8, &query, policy).await?;
            self.accept_mcc(version, &reply)?;
        }
        self.check_link_power(&policy()?)
    }

    async fn prepare_data_inner(
        &mut self,
        edca: &[u8],
        tlc: &[u8],
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        self.fresh_data_policy(policy).await?;
        for (group, command, payload) in [(3, 9, edca), (5, 15, tlc)] {
            if !self
                .qualified_link_command(group, command, payload, policy)
                .await?
                .is_empty()
            {
                return Err("invalid MVM EDCA/TLC receipt");
            }
            self.check_link_power(&policy()?)?;
        }
        let id = {
            let power = self.power.prepared.as_ref().unwrap();
            let mut allocation = pin!(self.hardware.allocate_tx(STATION, TID));
            poll_fn(|cx| {
                if let Err(e) = policy().and_then(|p| power.check_applied(&p)) {
                    return Poll::Ready(Err(e));
                }
                allocation.as_mut().poll(cx)
            })
            .await?
        };
        self.power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap()
            .queue = Some(id);
        self.check_link_power(&policy()?)?;
        self.hardware.discard_key_transition_rx()?;
        if !self
            .power
            .prepared
            .as_ref()
            .unwrap()
            .mlme
            .data
            .as_ref()
            .unwrap()
            .status
            .protected
        {
            let reply = self
                .qualified_link_command(1, 0x18, &super::auth::disable_tx(false), policy)
                .await?;
            if reply.len() != 4 || u32::from_le_bytes(reply[..4].try_into().unwrap()) & 255 != 1 {
                return Err("MVM Open data peer enable failed");
            }
        }
        self.check_link_power(&policy()?)?;
        if !self.hardware.idle_tx_binding(id, STATION, TID) {
            return Err("MVM data queue not idle/bound after preparation");
        }
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        // Only an actual Open association opens the port here. WPA2 retains
        // TX-disable and has no caller flag/key/RSNA-completion shortcut.
        data.port_open = !data.status.protected;
        Ok(())
    }

    pub(super) fn data_failed<T>(&mut self, error: &'static str) -> Result<T, &'static str> {
        self.power.phy.ba.clear_packets();
        self.clear_data_aggregate();
        self.power.phy.actions.clear();
        if let Some(data) = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
        {
            data.port_open = false;
        }
        self.hardware.fail();
        self.phase = Phase::Failed;
        Err(error)
    }

    pub async fn transmit_legacy_ethernet(&mut self, ethernet: &[u8]) -> Result<(), &'static str> {
        self.transmit_data_using(ethernet, || {
            narf_wireless::reg::db::get_domain().ok_or("MVM data policy unavailable")
        })
        .await
    }

    pub(super) async fn transmit_data_using(
        &mut self,
        ethernet: &[u8],
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        self.transmit_data_assisted(ethernet, 0, policy).await
    }

    /// `assist` is the checksum `offload_assist` returned by
    /// `csum::prepare_tx` for this already-prepared Ethernet frame.
    pub(super) async fn transmit_data_assisted(
        &mut self,
        ethernet: &[u8],
        assist: u32,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let status = match policy().and_then(|p| self.data_ready(&p)) {
            Ok(status) => status,
            Err(error) if self.phase == Phase::DataPrepared => return self.data_failed(error),
            Err(error) => return Err(error),
        };
        if status.protected && !self.security.ready() {
            return Err("MVM secured controlled port requires real RSNA and keys");
        }
        // EAPOL belongs to an authenticated security owner, never an ordinary
        // Ethernet caller. Reject before sequence reservation or native I/O.
        if ethernet.get(12..14) == Some(&[0x88, 0x8e]) {
            return Err("MVM ordinary data producer cannot submit EAPOL");
        }
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        let qos = self.power.phy.negotiated.is_some();
        let frame = if qos {
            frame_api::transmit_qos(
                self.mac.unwrap(),
                status.bssid,
                data.sequence,
                ethernet,
                status.protected,
                0,
            )
        } else {
            frame_api::transmit(
                self.mac.unwrap(),
                status.bssid,
                data.sequence,
                ethernet,
                status.protected,
            )
        }
        .ok_or("invalid MVM legacy Ethernet frame")?;
        data.sequence = data.sequence.wrapping_add(1) & 0xfff;
        self.phase = Phase::TransmittingData;
        let result = async {
            self.fresh_data_policy(&mut policy).await?;
            {
                let power = self.power.prepared.as_ref().unwrap();
                let mut tx = pin!(self.hardware.transmit_assisted(
                    status.queue,
                    &frame,
                    if qos { 26 } else { 24 },
                    None,
                    assist,
                ));
                poll_fn(|cx| {
                    if let Err(error) = policy().and_then(|p| power.check_applied(&p)) {
                        return Poll::Ready(Err(error));
                    }
                    tx.as_mut().poll(cx)
                })
                .await?;
            }
            self.check_link_power(&policy()?)?;
            if !self.hardware.idle_tx_binding(status.queue, STATION, TID) {
                return Err("MVM data completion left outstanding DMA");
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                Ok(())
            }
            Err(error) => self.data_failed(error),
        }
    }

    /// The worker batches only ordinary BE/TID0 packets. RSNA/EAPOL retains
    /// the separate management owner and cannot enter this producer.
    pub(in crate::iwlwifi) async fn transmit_data_batch_using(
        &mut self,
        packets: &[(Vec<u8>, u32)],
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if !self.ba_qualified() {
            for (frame, assist) in packets {
                self.transmit_data_assisted(frame, *assist, &mut policy)
                    .await?;
            }
            return Ok(());
        }
        if packets.is_empty() || packets.len() > super::ba::PIPELINE {
            return Err("MVM batch packet bound");
        }
        let status = self.data_ready(&policy()?)?;
        if status.protected && !self.security.ready() {
            return Err("MVM BA port not authorized");
        }
        let local = self.mac.unwrap();
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        let mut frames = Vec::with_capacity(packets.len());
        for (packet, assist) in packets {
            if packet.get(12..14) == Some(&[0x88, 0x8e]) {
                return Err("MVM batch cannot carry EAPOL");
            }
            let frame = frame_api::transmit_qos(
                local,
                status.bssid,
                data.sequence,
                packet,
                status.protected,
                0,
            )
            .ok_or("MVM invalid BE batch Ethernet")?;
            data.sequence = data.sequence.wrapping_add(1) & 4095;
            frames.push((frame, *assist));
        }
        self.phase = Phase::TransmittingData;
        let result = async {
            self.fresh_data_policy(&mut policy).await?;
            self.enable_ba_tx(&mut policy).await?;
            {
                let power = self.power.prepared.as_ref().unwrap();
                let mut transmit = pin!(self.hardware.transmit_gen2_batch(status.queue, &frames));
                poll_fn(|cx| {
                    if let Err(e) = policy().and_then(|p| power.check_applied(&p)) {
                        return Poll::Ready(Err(e));
                    }
                    transmit.as_mut().poll(cx)
                })
                .await?;
            }
            self.check_link_power(&policy()?)
        }
        .await;
        match result {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                Ok(())
            }
            Err(e) => self.data_failed(e),
        }
    }

    /// One bounded synchronous native receive drain. No IP packet escapes a
    /// protected port; an active RSNA owner captures EAPOL privately.
    pub fn poll_legacy_receive(&mut self) -> Result<Option<LegacyReceive>, &'static str> {
        self.receive_data_using(|| {
            narf_wireless::reg::db::get_domain().ok_or("MVM data policy unavailable")
        })
    }

    pub(super) fn receive_data_using(
        &mut self,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Option<LegacyReceive>, &'static str> {
        if self.phase != Phase::DataPrepared {
            return Err("MVM receive owner is not ready");
        }
        match self.receive_data_inner(&mut policy) {
            Ok(packet) => Ok(packet),
            Err(error) => self.data_failed(error),
        }
    }

    pub(super) fn receive_data_inner(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Option<LegacyReceive>, &'static str> {
        let domain = policy()?;
        let status = if self.phase == Phase::SecuringData {
            self.check_link_power(&domain)?;
            self.security_status()?
        } else {
            self.data_ready(&domain)?
        };
        let local = self.mac.unwrap();
        let phy = self.power.phy.negotiated;
        if !status.protected || self.security.ready() && self.phase == Phase::DataPrepared {
            let data = self
                .power
                .prepared
                .as_mut()
                .unwrap()
                .mlme
                .data
                .as_mut()
                .unwrap();
            if let Some(frame) = data.aggregate.pop(narf_time::now_cycles()) {
                data.last_peer = narf_time::now_cycles();
                return Ok(Some(LegacyReceive::Ethernet(frame)));
            }
        }
        self.hardware.poll()?;
        self.power.phy.ba.tick()?;
        for _ in 0..256 {
            self.check_link_power(&policy()?)?;
            let (payload, released) =
                if let Some(bytes) = self.power.phy.ba.pop() {
                    (bytes, true)
                } else {
                    let Some(index) = self.hardware.notifications.iter().position(|p| {
                        p.header.group_id == 0 && matches!(p.header.cmd, 0xc1..=0xc3)
                    }) else {
                        break;
                    };
                    let packet = self.hardware.notifications.remove(index).unwrap();
                    if packet.header.cmd != 0xc1 {
                        if self.ba_qualified() {
                            self.power
                                .phy
                                .ba
                                .release(packet.header.cmd, &packet.payload)?;
                        }
                        continue;
                    }
                    (packet.payload, false)
                };
            let Some(mpdu) = scan_api::mpdu_gen2(&payload) else {
                self.cancel_data_partial();
                continue;
            };
            let f = mpdu.frame;
            if self.receive_ba_bar(&mpdu, local, status.bssid, status.channel) {
                continue;
            }
            if mpdu.channel != status.channel || f.len() < 24 || f[10..16] != status.bssid {
                self.clear_data_aggregate();
                continue;
            }
            if self.receive_phy_action(&mpdu, local, status.bssid) {
                self.clear_data_aggregate();
                continue;
            }
            if ap_disconnected(&mpdu, local, status) {
                return Err("MVM current AP disconnected legacy station");
            }
            if f[0] == 0x80
                && f[1] & 0xc7 == 0
                && f[4..10] == [255; 6]
                && f[16..22] == status.bssid
                && f[22] & 15 == 0
                && !mpdu.amsdu
                && mpdu
                    .body(24, 0)
                    .and_then(|body| super::super::mlme::parse_beacon_to_bss(status.bssid, body))
                    .is_some_and(|beacon| {
                        self.beacons
                            .iter()
                            .any(|b| b.bssid == status.bssid && b.ssid == beacon.ssid)
                            && (beacon.capability_info & 16 != 0) == status.protected
                    })
            {
                if phy.is_some_and(|p| {
                    mpdu.body(24, 0)
                        .and_then(|b| b.get(12..))
                        .is_none_or(|ies| !p.matches_beacon(ies))
                }) {
                    return Err("MVM current AP changed retained WMM/HT profile");
                }
                self.power
                    .prepared
                    .as_mut()
                    .unwrap()
                    .mlme
                    .data
                    .as_mut()
                    .unwrap()
                    .last_peer = narf_time::now_cycles();
                continue;
            }
            // Original FromDS frames only; QoS and native deaggregation need
            // the retained response-bound profile. Reject unsupported header,
            // PHY, reorder and crypto shapes before any replay publication.
            let qos = f[0] == 0x88;
            let header = if qos { 26 } else { 24 };
            if !matches!(f[0], 8 | 0x88)
                || qos && phy.is_none()
                || f[1] & 0x87 != 2
                || f[22] & 15 != 0
                || mpdu.status & (1 << 22) != 0
                || qos
                    && f.get(24..26).is_none_or(|q| {
                        !self.power.phy.ba.qos_policy(q[0], mpdu.reorder)
                            || q[1] != 0
                            || (q[0] & 0x80 != 0) != mpdu.amsdu
                    })
                || mpdu.amsdu && !phy.is_some_and(|p| p.ht)
                || phy.is_some() && mpdu.reorder & 0x7f000000 != 0x7f000000 && !self.ba_qualified()
                || !mpdu.amsdu && mpdu.amsdu_index != 0
                || !(legacy_rx_rate(&payload, status) || phy.is_some_and(|p| p.rx_rate(&payload)))
                || mpdu
                    .body(header, if f[1] & 0x40 != 0 { 8 } else { 0 })
                    .is_none_or(|b| !(8..=1508).contains(&b.len()))
            {
                self.clear_data_aggregate();
                continue;
            }
            let encrypted = f[1] & 0x40 != 0;
            if encrypted {
                // Native API4 must name station0 and report source/key-found,
                // CCM, MIC-OK and DECRYPTED. The IV remains in the MPDU;
                // firmware MIC stripping is described by its envelope.
                if !status.protected
                    || !self.security.has_pairwise()
                    || mpdu.status & (0x1f000000 | 0xf4c) != 0xa4c
                {
                    self.clear_data_aggregate();
                    continue;
                }
            } else if mpdu.status & 0xf40 != 0 {
                self.clear_data_aggregate();
                continue;
            }
            if mpdu.reorder & 0x7f000000 != 0x7f000000 && !released {
                // Retain the original native packet BEFORE any host replay
                // update or deaggregation. Released bytes traverse these same
                // current identity/PHY/crypto checks again, then PN in order.
                self.power.phy.ba.observe(&payload, local)?;
                continue;
            }
            let data = self
                .power
                .prepared
                .as_mut()
                .unwrap()
                .mlme
                .data
                .as_mut()
                .unwrap();
            // Only a single (non-A-MSDU) MPDU's descriptor describes the
            // delivered packet; Linux likewise sets ip_summed on that skb.
            let l3l4 = if mpdu.amsdu {
                0
            } else {
                u16::from_le_bytes([payload[10], payload[11]])
            };
            let Some(ethernet) = data.aggregate.observe(
                &mpdu,
                local,
                status.bssid,
                status.protected,
                &mut data.replay,
                narf_time::now_cycles(),
            ) else {
                continue;
            };
            if ethernet[6] & 1 != 0
                || ethernet[6..12] == [0; 6]
                || u16::from_be_bytes([ethernet[12], ethernet[13]]) < 0x600
            {
                continue;
            }
            self.check_link_power(&policy()?)?;
            if ethernet[12..14] == [0x88, 0x8e] {
                // IEEE802.1X header and body must have an exact bounded extent.
                let body = &ethernet[14..];
                if body.len() < 4
                    || !matches!(body[0], 1..=3)
                    || usize::from(u16::from_be_bytes([body[2], body[3]])) != body.len() - 4
                    || !status.protected
                    || ethernet[..6] != local
                    || ethernet[6..12] != status.bssid
                {
                    continue;
                }
                if self.security.started() {
                    self.power
                        .prepared
                        .as_mut()
                        .unwrap()
                        .mlme
                        .data
                        .as_mut()
                        .unwrap()
                        .last_peer = narf_time::now_cycles();
                    self.security.receive(ethernet, encrypted)?;
                    return Ok(None);
                }
                return Ok(Some(LegacyReceive::Eapol(ethernet)));
            }
            if !status.protected || self.security.ready() && self.phase == Phase::DataPrepared {
                self.power
                    .prepared
                    .as_mut()
                    .unwrap()
                    .mlme
                    .data
                    .as_mut()
                    .unwrap()
                    .last_peer = narf_time::now_cycles();
                let meta = super::super::csum::rx_meta_l3l4(l3l4, &ethernet);
                return Ok(Some(if meta == narf_net::RxMeta::default() {
                    LegacyReceive::Ethernet(ethernet)
                } else {
                    LegacyReceive::Checked(ethernet, meta)
                }));
            }
        }
        self.check_link_power(&policy()?)?;
        Ok(None)
    }

    /// Close host admission before the first wait. DISABLE_TX precedes exact
    /// idle queue REMOVE. Closing remains allowed after host/source revocation;
    /// a cancelled close retains the phase and all unreconciled allocations.
    pub async fn release_legacy_data(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::DataPrepared || self.hardware.is_failed() {
            return Err("no terminal MVM data owner to close");
        }
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        let queue = data.queue.ok_or("MVM data close queue missing")?;
        data.port_open = false;
        data.aggregate.clear();
        self.power.phy.actions.clear();
        self.phase = Phase::ClosingData;
        let result = async {
            self.retire_ba(None::<&mut fn() -> Result<RegulatoryDomain, &'static str>>)
                .await?;
            let reply = self
                .hardware
                .command_with_header_version(1, 0x18, &super::auth::disable_tx(true), 0)
                .await?;
            if reply.payload.len() != 4
                || u32::from_le_bytes(reply.payload[..4].try_into().unwrap()) & 255 != 1
            {
                return Err("MVM data close peer disable failed");
            }
            self.remove_security_keys().await?;
            self.hardware.discard_key_transition_rx()?;
            self.hardware.remove_idle_tx(queue, STATION, TID).await
        }
        .await;
        match result {
            Ok(()) => {
                self.power.prepared.as_mut().unwrap().mlme.data = None;
                self.phase = Phase::Associated;
                Ok(())
            }
            Err(error) => self.data_failed(error),
        }
    }
    pub(super) fn clear_data_aggregate(&mut self) {
        self.power.phy.ba.cancel_incomplete();
        if let Some(data) = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
        {
            data.aggregate.clear();
        }
    }
    pub(super) fn cancel_data_partial(&mut self) {
        self.power.phy.ba.cancel_incomplete();
        if let Some(data) = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
        {
            data.aggregate.cancel_pending();
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_data_tests.rs"]
pub(super) mod tests;
