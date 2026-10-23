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
        Ok(Self {
            bss: Bss {
                bssid: bytes[10..16].try_into().unwrap(),
                ssid: ssid.ok_or(Error::Frame)?,
                channel,
                signal_dbm: None,
                capability,
                beacon_interval,
                information_elements: bytes[36..].to_vec(),
            },
            ap_rsne: rsne,
            ap_rsnxe: rsnxe,
        })
    }
    pub fn bssid(&self) -> [u8; 6] {
        self.bss.bssid
    }
    pub fn ssid(&self) -> &[u8] {
        &self.bss.ssid
    }
    pub fn channel(&self) -> u8 {
        self.bss.channel
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
}
impl Join {
    pub fn prepare(
        candidate: Candidate,
        local: [u8; 6],
        ssid: &[u8],
        security: SecurityMode,
    ) -> Result<Self, Error> {
        let plan =
            JoinPlan::prepare(&candidate.bss, local, ssid, security).map_err(Error::Protocol)?;
        Ok(Self {
            plan,
            candidate,
            local,
            next_sequence: 0,
        })
    }
    pub fn phase(&self) -> Phase {
        self.plan.phase()
    }
    pub fn candidate(&self) -> &Candidate {
        &self.candidate
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
    pub fn cancel(&mut self) {
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
            return Err(Error::PeerLeft(u16::from_le_bytes([reason[0], reason[1]])));
        }
        match (self.plan.phase(), bytes[0]) {
            (Phase::AwaitAuthentication, 0xb0) => {
                match self
                    .plan
                    .authentication_response(bytes)
                    .map_err(Error::Protocol)?
                {
                    Some(frame) => {
                        let frame = frame.to_vec();
                        Ok(Some(Action::Transmit(self.sequence(frame))))
                    }
                    None => Ok(None),
                }
            }
            (Phase::AwaitAssociation, 0x10) => self
                .plan
                .association_response(bytes)
                .map(|aid| aid.map(|aid| Action::Associated { aid }))
                .map_err(Error::Protocol),
            _ => Ok(None),
        }
    }
}
