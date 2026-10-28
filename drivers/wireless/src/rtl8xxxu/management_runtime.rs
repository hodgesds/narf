// SPDX-License-Identifier: GPL-2.0-or-later
//! First-channel RTL8188EU native management admission. The reused JoinPlan
//! prepares IEEE frames only; no CONNAC firmware record or radio state is used.
//! Association remains below regulatory TX authority and the controlled port.
use super::packet_codec::Mpdu;
use alloc::vec::Vec;
use narf_wireless::association::{self, Bss, JoinPlan};

pub use association::{Phase, SecurityMode};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Frame,
    Profile,
    Protocol(association::Error),
    PeerLeft(u16),
}

fn unicast(address: &[u8]) -> bool {
    address.len() == 6 && address != [0; 6] && address[0] & 1 == 0
}
fn elements(
    mut bytes: &[u8],
    mut visit: impl FnMut(u8, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    if bytes.len() > 2048 {
        return Err(Error::Frame);
    }
    while !bytes.is_empty() {
        let head = bytes.get(..2).ok_or(Error::Frame)?;
        let body = bytes.get(2..2 + usize::from(head[1])).ok_or(Error::Frame)?;
        visit(head[0], body)?;
        bytes = &bytes[2 + body.len()..];
    }
    Ok(())
}
fn native(frame: &Mpdu) -> bool {
    let b = &frame.bytes;
    b.len() >= 24
        && b.len() <= 4096
        && !frame.decrypted
        && !frame.bandwidth40
        && !frame.ht
        && frame.rate <= 11
        && b[0] & 0x0f == 0
        && b[1] & 0xc7 == 0
        && b[22] & 15 == 0
}

/// A validated beacon/probe response whose channel comes from the immutable
/// receive owner, never from an arbitrary RX label or an untrusted DS IE.
#[derive(Debug, Clone)]
pub struct Candidate {
    bss: Bss,
    ap_rsne: Option<Vec<u8>>,
    ap_rsnxe: Option<Vec<u8>>,
}
impl Candidate {
    pub fn from_receive(frame: &Mpdu, channel: u8, local: [u8; 6]) -> Result<Self, Error> {
        Self::from_receive_with_phy(frame, channel, local, None)
    }
    pub(super) fn from_receive_with_phy(
        frame: &Mpdu,
        channel: u8,
        local: [u8; 6],
        phy: Option<&association::phy::LocalPhy>,
    ) -> Result<Self, Error> {
        if channel != 1 || !unicast(&local) || !native(frame) {
            return Err(Error::Profile);
        }
        let bytes = &frame.bytes;
        if bytes.len() < 36
            || !matches!(bytes[0], 0x50 | 0x80)
            || !unicast(&bytes[10..16])
            || bytes[10..16] != bytes[16..22]
            || bytes[10..16] == local
            || (bytes[0] == 0x80 && bytes[4..10] != [255; 6])
            || (bytes[0] == 0x50 && bytes[4..10] != local)
        {
            return Err(Error::Frame);
        }
        let capability = u16::from_le_bytes([bytes[34], bytes[35]]);
        let beacon_interval = u16::from_le_bytes([bytes[32], bytes[33]]);
        if capability & 3 != 1 || beacon_interval == 0 {
            return Err(Error::Profile);
        }
        let mut ssid = None;
        let mut ds = false;
        let mut rsne = None;
        let mut rsnxe = None;
        let mut supported = false;
        let mut basic_one = false;
        elements(&bytes[36..], |id, body| {
            match id {
                0 => {
                    if ssid.is_some() || body.len() > 32 {
                        return Err(Error::Frame);
                    }
                    ssid = Some(body.to_vec());
                }
                1 | 50 => {
                    if body.is_empty() || id == 1 && (supported || body.len() > 8) {
                        return Err(Error::Frame);
                    }
                    supported |= id == 1;
                    basic_one |= body.contains(&0x82);
                }
                3 => {
                    if ds || body != [channel] {
                        return Err(Error::Profile);
                    }
                    ds = true;
                }
                48 => {
                    if rsne.is_some() {
                        return Err(Error::Frame);
                    }
                    rsne = Some(body.to_vec());
                }
                244 => {
                    if rsnxe.is_some() || body.is_empty() {
                        return Err(Error::Frame);
                    }
                    rsnxe = Some(body.to_vec());
                }
                _ => (),
            }
            Ok(())
        })?;
        // Current Realtek descriptor policy deliberately programs rate index0
        // (1Mbps). Require it as a basic rate rather than borrowing MT76's
        // unrelated OFDM hardware-index mapping or silently selecting HT.
        if !supported || !basic_one {
            return Err(Error::Profile);
        }
        let observed = if let Some(phy) = phy {
            association::observe_with_phy(frame, channel, local, None, phy)
        } else {
            association::observe(frame, channel, local, None)
        }
        .map_err(Error::Protocol)?;
        Ok(Self {
            bss: Bss {
                bssid: bytes[10..16].try_into().unwrap(),
                ssid: ssid.ok_or(Error::Frame)?,
                channel,
                band: None,
                signal_dbm: None,
                capability,
                beacon_interval,
                information_elements: observed.bss.information_elements,
            },
            ap_rsne: rsne,
            ap_rsnxe: rsnxe,
        })
    }
    pub fn bssid(&self) -> [u8; 6] {
        self.bss.bssid
    }
    pub(super) fn capability(&self) -> u16 {
        self.bss.capability
    }
    pub fn ssid(&self) -> &[u8] {
        &self.bss.ssid
    }
    pub fn channel(&self) -> u8 {
        self.bss.channel
    }
    pub fn information_elements(&self) -> &[u8] {
        &self.bss.information_elements
    }
    /// Original AP bodies, retained independently from the station's canonical
    /// negotiated RSNE for Supplicant::with_rsna and M3 KDE binding.
    pub fn ap_rsne(&self) -> Option<&[u8]> {
        self.ap_rsne.as_deref()
    }
    pub fn ap_rsnxe(&self) -> Option<&[u8]> {
        self.ap_rsnxe.as_deref()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Transmit(Vec<u8>),
    Associated { aid: u16 },
}
#[derive(Debug)]
pub struct Join {
    plan: JoinPlan,
    candidate: Candidate,
    local: [u8; 6],
    next_sequence: u16,
    wmm: Option<narf_wireless::wmm::Parameters>,
}
impl Join {
    pub fn prepare(
        candidate: Candidate,
        local: [u8; 6],
        ssid: &[u8],
        security: SecurityMode,
    ) -> Result<Self, Error> {
        Self::prepare_with_phy(candidate, local, ssid, security, None)
    }
    pub(super) fn prepare_with_phy(
        candidate: Candidate,
        local: [u8; 6],
        ssid: &[u8],
        security: SecurityMode,
        phy: Option<association::phy::LocalPhy>,
    ) -> Result<Self, Error> {
        let plan = if let Some(phy) = phy {
            JoinPlan::prepare_with_phy(&candidate.bss, local, ssid, security, phy)
        } else {
            JoinPlan::prepare(&candidate.bss, local, ssid, security)
        }
        .map_err(Error::Protocol)?;
        let wmm = narf_wireless::wmm::Parameters::parse(candidate.information_elements())
            .map_err(|_| Error::Profile)?;
        if let Some(p) = wmm {
            super::wmm_runtime::words(p, candidate.capability() & 0x400 != 0)
                .map_err(|_| Error::Profile)?;
        }
        if plan.offered_phy().is_some() && wmm.is_none() {
            return Err(Error::Profile);
        }
        Ok(Self {
            plan,
            candidate,
            local,
            next_sequence: 0,
            wmm,
        })
    }
    pub fn phase(&self) -> Phase {
        self.plan.phase()
    }
    pub(super) fn wmm(&self) -> Option<narf_wireless::wmm::Parameters> {
        self.wmm
    }
    pub(super) fn data_rate(&self) -> Result<u8, Error> {
        if !matches!(self.phase(), Phase::Associated { .. }) {
            return Err(Error::Profile);
        }
        if let Some(phy) = self.plan.negotiated_phy() {
            let ht = phy.ht();
            if phy.width() != association::phy::Width::Twenty
                || phy.center_channel() != 1
                || ht.operation().protection() != 0
            {
                return Err(Error::Profile);
            }
            return (0..8)
                .rev()
                .find(|i| ht.tx_mcs()[0] & (1 << i) != 0)
                .map(|i| 12 + i)
                .ok_or(Error::Profile);
        }
        let rates = self.plan.legacy_rates().0;
        [11, 10, 9, 8, 7, 6, 3, 5, 4, 2, 1, 0]
            .into_iter()
            .find(|rate| rates & (1 << rate) != 0)
            .ok_or(Error::Profile)
    }
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
    }
    /// Negotiated AP HT A-MPDU parameters: (maximum length exponent, density).
    pub(super) fn peer_ampdu(&self) -> Option<(u8, u8)> {
        self.plan
            .negotiated_phy()
            .map(|phy| (phy.ht().peer_ampdu_factor(), phy.ht().peer_mpdu_density()))
    }
    /// `rtl8xxxu_refresh_rate_mask` inputs: `supp_rates[0]` (negotiated
    /// legacy bitmap in DESC rate order), `ht_cap.mcs.rx_mask[0]` (MCS the
    /// peer receives and this 1T1R profile may send) and `ht_supported`.
    pub(super) fn rate_mask_inputs(&self) -> (u16, u8, bool) {
        let mcs = self
            .plan
            .negotiated_phy()
            .map_or(0, |phy| phy.ht().tx_mcs()[0]);
        (self.plan.legacy_rates().0, mcs, self.ht_selected())
    }
    pub(super) fn ht_selected(&self) -> bool {
        self.plan.negotiated_phy().is_some()
    }
    pub(super) fn ht_offered(&self) -> bool {
        self.plan.offered_phy().is_some()
    }
    pub fn rsn_body(&self) -> Option<Vec<u8>> {
        self.plan.rsn_body()
    }
    fn sequence(&mut self, mut frame: Vec<u8>) -> Vec<u8> {
        frame[22..24].copy_from_slice(&(self.next_sequence << 4).to_le_bytes());
        self.next_sequence = (self.next_sequence + 1) & 0x0fff;
        frame
    }
    pub fn begin(&mut self) -> Result<Action, Error> {
        let frame = self
            .plan
            .start_authentication()
            .map_err(Error::Protocol)?
            .to_vec();
        Ok(Action::Transmit(self.sequence(frame)))
    }
    pub fn append_sme_ies(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.plan.append_sme_ies(bytes).map_err(Error::Protocol)
    }
    pub fn cancel(&mut self) {
        self.wmm = None;
        self.plan.cancel();
    }
    /// Unrelated native traffic is ignored. A malformed matching management
    /// response terminates this attempt before an association/port transition.
    pub fn receive(&mut self, frame: &Mpdu) -> Result<Option<Action>, Error> {
        let bytes = &frame.bytes;
        if bytes.len() < 24
            || bytes[10..16] != self.candidate.bssid()
            || bytes[16..22] != self.candidate.bssid()
            || bytes[4..10] != self.local
                && !(matches!(bytes[0], 0xa0 | 0xc0) && bytes[4..10] == [255; 6])
        {
            return Ok(None);
        }
        if !matches!(bytes[0], 0x10 | 0xa0 | 0xb0 | 0xc0) {
            return Ok(None);
        }
        if !native(frame) {
            self.plan.cancel();
            return Err(Error::Frame);
        }
        if matches!(bytes[0], 0xa0 | 0xc0) {
            self.plan.cancel();
            let reason = bytes.get(24..26).ok_or(Error::Frame)?;
            let reason = u16::from_le_bytes([reason[0], reason[1]]);
            return Err(if reason == 0 {
                Error::Frame
            } else {
                Error::PeerLeft(reason)
            });
        }
        match (self.plan.phase(), bytes[0]) {
            (Phase::AwaitAuthentication, 0xb0) => {
                match self
                    .plan
                    .authentication_response(bytes)
                    .map_err(Error::Protocol)?
                {
                    Some(frame) => {
                        let mut frame = frame.to_vec();
                        if self.wmm.is_some() {
                            frame.extend_from_slice(&narf_wireless::wmm::INFORMATION);
                        }
                        Ok(Some(Action::Transmit(self.sequence(frame))))
                    }
                    None => Ok(None),
                }
            }
            (Phase::AwaitAssociation, 0x10) => {
                let aid = self
                    .plan
                    .association_response(bytes)
                    .map_err(Error::Protocol)?;
                if aid.is_some()
                    && self.plan.negotiated_phy().is_some()
                    && self.data_rate().is_err()
                {
                    self.cancel();
                    return Err(Error::Profile);
                }
                if aid.is_some() && self.wmm.is_some() {
                    let profile = (|| {
                        let p = narf_wireless::wmm::Parameters::parse(
                            bytes.get(30..).ok_or(Error::Frame)?,
                        )
                        .map_err(|_| Error::Profile)?
                        .ok_or(Error::Profile)?;
                        let capability = u16::from_le_bytes([bytes[24], bytes[25]])
                            & self.candidate.capability();
                        super::wmm_runtime::words(p, capability & 0x400 != 0)
                            .map_err(|_| Error::Profile)?;
                        Ok(p)
                    })();
                    match profile {
                        Ok(p) => self.wmm = Some(p),
                        Err(error) => {
                            // The common response receipt precedes native
                            // WMM admission. Revoke that intermediate state
                            // before returning an error to any Join caller.
                            self.cancel();
                            return Err(error);
                        }
                    }
                }
                Ok(aid.map(|aid| Action::Associated { aid }))
            }
            _ => Ok(None),
        }
    }
}
