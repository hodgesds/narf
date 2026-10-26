use alloc::{vec, vec::Vec};
use narf_wireless::eapol::{self, HmacPrimitive, KeyFrame, Ptk};
use zeroize::{Zeroize, Zeroizing};

use crate::NetworkPlan;

/// The peer progresses only after observing the station's matching request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApPhase {
    Authentication,
    Association,
    Message2,
    Message4,
    Authorized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApError {
    Configuration,
    Frame,
    Phase,
    Association,
    Key,
    Mic,
}

/// A deterministic legacy Open/WPA2-PSK/CCMP access point.
///
/// Fixed PMK/nonces belong only to fixtures. The AP checks M2 and M4 MICs and
/// replay counters; it does not invoke the station MLME or supplicant. Device
/// wrappers translate returned 802.11 frames into their native RX descriptors.
pub struct FakeAp {
    plan: NetworkPlan,
    ssid: Vec<u8>,
    channel: u8,
    aid: u16,
    pmk: Option<Zeroizing<[u8; 32]>>,
    anonce: [u8; 32],
    ptk: Option<Ptk>,
    phase: ApPhase,
    basic_1mbps: bool,
    rates: Option<Vec<u8>>,
}

impl core::fmt::Debug for FakeAp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FakeAp")
            .field("phase", &self.phase)
            .field("channel", &self.channel)
            .field("protected", &self.pmk.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for FakeAp {
    fn drop(&mut self) {
        if let Some(ptk) = &mut self.ptk {
            ptk.kck.zeroize();
            ptk.kek.zeroize();
            ptk.tk.zeroize();
        }
    }
}

impl FakeAp {
    pub fn open(plan: NetworkPlan, ssid: &[u8], channel: u8, aid: u16) -> Result<Self, ApError> {
        Self::new(plan, ssid, channel, aid, None, [0; 32])
    }

    pub fn wpa2(
        plan: NetworkPlan,
        ssid: &[u8],
        channel: u8,
        aid: u16,
        pmk: [u8; 32],
        anonce: [u8; 32],
    ) -> Result<Self, ApError> {
        if anonce == [0; 32] {
            return Err(ApError::Configuration);
        }
        Self::new(plan, ssid, channel, aid, Some(Zeroizing::new(pmk)), anonce)
    }

    fn new(
        plan: NetworkPlan,
        ssid: &[u8],
        channel: u8,
        aid: u16,
        pmk: Option<Zeroizing<[u8; 32]>>,
        anonce: [u8; 32],
    ) -> Result<Self, ApError> {
        if ssid.is_empty()
            || ssid.len() > 32
            || !(1..=11).contains(&channel)
                && !matches!(channel, 36 | 40 | 44 | 48 | 149 | 153 | 157 | 161 | 165)
            || !(1..=2007).contains(&aid)
            || plan.station == plan.bssid
            || [plan.station, plan.bssid]
                .iter()
                .any(|mac| *mac == [0; 6] || mac[0] & 1 != 0)
        {
            return Err(ApError::Configuration);
        }
        Ok(Self {
            plan,
            ssid: ssid.to_vec(),
            channel,
            aid,
            pmk,
            anonce,
            ptk: None,
            phase: ApPhase::Authentication,
            basic_1mbps: false,
            rates: None,
        })
    }

    /// Select the fixed channel-1-era legacy 1Mbps fixture profile before
    /// authentication. Default constructors retain their OFDM6/12/24 profile.
    /// This configures only the fake peer; it grants no driver/radio authority.
    pub fn with_basic_1mbps(mut self) -> Result<Self, ApError> {
        if self.phase != ApPhase::Authentication || self.ptk.is_some() || self.channel > 14 {
            return Err(ApError::Phase);
        }
        self.basic_1mbps = true;
        self.rates = None;
        Ok(self)
    }

    /// Configure literal IEEE Supported Rates (the high bit marks basic
    /// rates). Only actual legacy CCK/OFDM values, unique entries and a basic
    /// subset are admitted. Five-GHz fixtures cannot offer CCK. This configures
    /// the independent AP and grants no station/device/regulatory authority.
    pub fn with_legacy_rates(mut self, rates: &[u8]) -> Result<Self, ApError> {
        if self.phase != ApPhase::Authentication || self.ptk.is_some() {
            return Err(ApError::Phase);
        }
        let mut seen = 0u16;
        let ieee = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
        if rates.is_empty() || rates.len() > 12 || !rates.iter().any(|r| r & 128 != 0) {
            return Err(ApError::Configuration);
        }
        for rate in rates {
            let index = ieee
                .iter()
                .position(|r| *r == rate & 127)
                .ok_or(ApError::Configuration)?;
            if seen & (1 << index) != 0 || self.channel > 14 && index < 4 {
                return Err(ApError::Configuration);
            }
            seen |= 1 << index;
        }
        self.rates = Some(rates.to_vec());
        Ok(self)
    }

    fn basic_rates(&self) -> &[u8] {
        if let Some(rates) = &self.rates {
            rates
        } else if self.basic_1mbps {
            &[0x82]
        } else {
            &[0x8c, 0x98, 0xb0]
        }
    }

    fn append_rates(&self, out: &mut Vec<u8>) {
        let rates = self.basic_rates();
        let first = rates.len().min(8);
        out.extend_from_slice(&[1, first as u8]);
        out.extend_from_slice(&rates[..first]);
        if first != rates.len() {
            out.extend_from_slice(&[50, (rates.len() - first) as u8]);
            out.extend_from_slice(&rates[first..]);
        }
    }

    pub fn phase(&self) -> ApPhase {
        self.phase
    }

    pub fn protected(&self) -> bool {
        self.pmk.is_some()
    }

    /// A standard beacon, without a vendor RX descriptor or FCS.
    pub fn beacon(&self) -> Vec<u8> {
        let mut frame = self.header(0x80, [255; 6]);
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&100u16.to_le_bytes());
        frame.extend_from_slice(&self.capabilities().to_le_bytes());
        frame.extend_from_slice(&self.ies());
        frame
    }

    /// React to one native station authentication/association/EAPOL frame.
    /// Invalid input leaves the AP's phase and installed PTK unchanged.
    pub fn receive(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
        if frame.len() > 4096 {
            return Err(ApError::Frame);
        }
        let header = frame.get(..24).ok_or(ApError::Frame)?;
        let fc = u16::from_le_bytes([header[0], header[1]]);
        if fc & 0xc403 != 0
            || header[22] & 15 != 0
            || header[4..10] != self.plan.bssid
            || header[10..16] != self.plan.station
            || header[16..22] != self.plan.bssid
        {
            return Err(ApError::Frame);
        }
        match (self.phase, fc & 0x00fc) {
            (ApPhase::Authentication, 0xb0) if fc & 0x0300 == 0 => {
                if frame.get(24..30) != Some(&[0, 0, 1, 0, 0, 0]) {
                    return Err(ApError::Frame);
                }
                let mut response = self.header(0xb0, self.plan.station);
                response.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
                self.phase = ApPhase::Association;
                Ok(vec![response])
            }
            (ApPhase::Association, 0x00) if fc & 0x0300 == 0 => {
                self.check_association(frame)?;
                let mut response = self.header(0x10, self.plan.station);
                response.extend_from_slice(&self.capabilities().to_le_bytes());
                response.extend_from_slice(&0u16.to_le_bytes());
                response.extend_from_slice(&(self.aid | 0xc000).to_le_bytes());
                self.append_rates(&mut response);
                if self.protected() {
                    let mut m1 = KeyFrame::empty(16);
                    m1.key_information = eapol::KI_KEY_TYPE_PAIRWISE
                        | eapol::KI_KEY_ACK
                        | eapol::KI_VERSION_HMAC_SHA1_AES;
                    m1.key_length = 16;
                    m1.replay_counter = 1;
                    m1.key_nonce = self.anonce;
                    self.phase = ApPhase::Message2;
                    Ok(vec![response, self.eapol_frame(&m1.into_eapol())])
                } else {
                    self.phase = ApPhase::Authorized;
                    Ok(vec![response])
                }
            }
            (ApPhase::Message2 | ApPhase::Message4, 0x08 | 0x88) if fc & 0x0300 == 0x0100 => {
                let offset = if fc & 0x80 == 0 { 24 } else { 26 };
                if frame.get(offset..offset + 8) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
                    return Err(ApError::Frame);
                }
                self.receive_key(frame.get(offset + 8..).ok_or(ApError::Frame)?)
            }
            _ => Err(ApError::Phase),
        }
    }

    fn capabilities(&self) -> u16 {
        if self.protected() {
            0x11
        } else {
            1
        }
    }

    fn header(&self, subtype: u8, destination: [u8; 6]) -> Vec<u8> {
        let mut out = vec![subtype, 0, 0, 0];
        out.extend_from_slice(&destination);
        out.extend_from_slice(&self.plan.bssid);
        out.extend_from_slice(&self.plan.bssid);
        out.extend_from_slice(&[0, 0]);
        out
    }

    fn rsn_ie(&self) -> Vec<u8> {
        // WPA2-Personal, CCMP group/pairwise, one PSK AKM, no PMF.
        vec![
            48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
        ]
    }

    fn ies(&self) -> Vec<u8> {
        let mut out = vec![0, self.ssid.len() as u8];
        out.extend_from_slice(&self.ssid);
        self.append_rates(&mut out);
        out.extend_from_slice(&[3, 1, self.channel]);
        if self.protected() {
            out.extend_from_slice(&self.rsn_ie());
        }
        out
    }

    fn check_association(&self, frame: &[u8]) -> Result<(), ApError> {
        let fixed = frame.get(24..28).ok_or(ApError::Association)?;
        if u16::from_le_bytes([fixed[0], fixed[1]]) & 0x11 != self.capabilities() {
            return Err(ApError::Association);
        }
        let mut ies = frame.get(28..).ok_or(ApError::Association)?;
        let (mut ssid, mut rates, mut extended_rates, mut rsn) = (None, None, None, None);
        while !ies.is_empty() {
            let h = ies.get(..2).ok_or(ApError::Association)?;
            let ie = ies
                .get(..2 + usize::from(h[1]))
                .ok_or(ApError::Association)?;
            match h[0] {
                0 if ssid.is_none() => ssid = Some(&ie[2..]),
                1 if rates.is_none() && (1..=8).contains(&usize::from(h[1])) => {
                    rates = Some(&ie[2..])
                }
                50 if extended_rates.is_none() && h[1] != 0 => extended_rates = Some(&ie[2..]),
                48 if rsn.is_none() => rsn = Some(ie),
                0 | 1 | 48 | 50 => return Err(ApError::Association),
                _ => {}
            }
            ies = &ies[ie.len()..];
        }
        if ssid != Some(self.ssid.as_slice())
            || !rates.is_some_and(|r| {
                self.basic_rates().iter().all(|basic| {
                    r.iter()
                        .chain(extended_rates.unwrap_or_default())
                        .any(|x| x & 0x7f == basic & 0x7f)
                })
            })
            || if self.protected() {
                rsn != Some(self.rsn_ie().as_slice())
            } else {
                rsn.is_some()
            }
        {
            return Err(ApError::Association);
        }
        Ok(())
    }

    fn eapol_frame(&self, pdu: &[u8]) -> Vec<u8> {
        let mut out = self.header(0x08, self.plan.station);
        out[1] = 2; // FromDS
        out.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
        out.extend_from_slice(pdu);
        out
    }

    fn receive_key(&mut self, pdu: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
        if pdu.len() < 99
            || !(1..=3).contains(&pdu[0])
            || pdu[1] != 3
            || usize::from(u16::from_be_bytes([pdu[2], pdu[3]])) != pdu.len() - 4
        {
            return Err(ApError::Key);
        }
        let key = KeyFrame::decode(&pdu[4..], 16).ok_or(ApError::Key)?;
        if key.descriptor_type != eapol::KEY_DESCRIPTOR_RSN || key.encode().len() != pdu.len() - 4 {
            return Err(ApError::Key);
        }
        let pairwise_mic =
            eapol::KI_KEY_TYPE_PAIRWISE | eapol::KI_KEY_MIC | eapol::KI_VERSION_HMAC_SHA1_AES;
        match self.phase {
            ApPhase::Message2 => {
                if key.key_information != pairwise_mic
                    || key.replay_counter != 1
                    || key.key_nonce == [0; 32]
                    || key.key_data != self.rsn_ie()
                {
                    return Err(ApError::Key);
                }
                let pmk = self.pmk.as_ref().ok_or(ApError::Key)?;
                let ptk = eapol::derive_ptk(
                    &Sha1,
                    pmk.as_ref(),
                    &self.plan.bssid,
                    &self.plan.station,
                    &self.anonce,
                    &key.key_nonce,
                    16,
                );
                check_mic(&ptk.kck, pdu)?;
                let mut m3 = KeyFrame::empty(16);
                m3.key_information = pairwise_mic
                    | eapol::KI_KEY_ACK
                    | eapol::KI_INSTALL
                    | eapol::KI_SECURE
                    | eapol::KI_ENCRYPTED_KEY_DATA;
                m3.key_length = 16;
                m3.replay_counter = 2;
                m3.key_nonce = self.anonce;
                let mut clear = self.rsn_ie();
                clear.extend_from_slice(&[221, 22, 0, 0x0f, 0xac, 1, 1, 0]);
                clear.extend_from_slice(&[0x77; 16]);
                if clear.len() % 8 != 0 {
                    clear.push(221);
                }
                while clear.len() % 8 != 0 {
                    clear.push(0);
                }
                m3.key_data = narf_crypto::aes_kw::aes_wrap(
                    ptk.kek.as_slice().try_into().map_err(|_| ApError::Key)?,
                    &clear,
                )
                .ok_or(ApError::Key)?;
                let pdu = signed(m3, &ptk.kck);
                self.ptk = Some(ptk);
                self.phase = ApPhase::Message4;
                Ok(vec![self.eapol_frame(&pdu)])
            }
            ApPhase::Message4 => {
                if key.key_information != pairwise_mic | eapol::KI_SECURE
                    || key.replay_counter != 2
                    || key.key_nonce != [0; 32]
                    || !key.key_data.is_empty()
                {
                    return Err(ApError::Key);
                }
                check_mic(&self.ptk.as_ref().ok_or(ApError::Key)?.kck, pdu)?;
                self.phase = ApPhase::Authorized;
                Ok(Vec::new())
            }
            _ => Err(ApError::Phase),
        }
    }
}

struct Sha1;
impl HmacPrimitive for Sha1 {
    fn out_len(&self) -> usize {
        20
    }
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        narf_crypto::pbkdf2_sha1::hmac_sha1(key, data).to_vec()
    }
}

fn check_mic(kck: &[u8], pdu: &[u8]) -> Result<(), ApError> {
    let mut clear = pdu.to_vec();
    clear[81..97].fill(0);
    let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(kck, &clear);
    if pdu[81..97] != mic[..16] {
        return Err(ApError::Mic);
    }
    Ok(())
}

fn signed(key: KeyFrame, kck: &[u8]) -> Vec<u8> {
    let mut pdu = key.into_eapol();
    let mic = narf_crypto::pbkdf2_sha1::hmac_sha1(kck, &pdu);
    pdu[81..97].copy_from_slice(&mic[..16]);
    pdu
}
