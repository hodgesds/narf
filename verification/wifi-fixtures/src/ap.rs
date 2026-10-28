use alloc::{vec, vec::Vec};
use narf_crypto::bip_cmac::Igtk;
use narf_wireless::eapol::{self, HmacPrimitive, KeyFrame, Ptk};
use narf_wireless::sae::SaeSession;
use zeroize::{Zeroize, Zeroizing};

use crate::ap_rsn::{ApPmf, ApSaePwe, RsnProfile, SaeAp};
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

/// A deterministic Open/WPA2-PSK/WPA3-SAE CCMP access point.
///
/// Fixed PMK/nonces belong only to fixtures. The AP checks M2 and M4 MICs and
/// replay counters; it does not invoke the station MLME or supplicant. Device
/// wrappers translate returned 802.11 frames into their native RX descriptors.
///
/// `wpa3_sae` and `with_pmf` select an RSN profile: SAE authentication
/// (hunting-and-pecking or H2E, through the shared `SaeSession`), MFPC/MFPR,
/// AKM-aware 4-way handshake keys and MICs, the IGTK KDE in message 3 when
/// PMF is negotiated, and `bip_broadcast_deauth`. Without a profile the AP
/// keeps its legacy WPA2 (AKM 2, no PMF) byte-exact behaviour.
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
    rsn: Option<alloc::boxed::Box<RsnProfile>>,
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
            rsn: None,
        })
    }

    /// A WPA3-Personal AP: SAE (AKM 8) with `password`, MFPC|MFPR, and the
    /// RSNXE SAE-H2E bit for `ApSaePwe::HashToElement`. The SAE scalar/mask
    /// come from `anonce` so a run is deterministic.
    pub fn wpa3_sae(
        plan: NetworkPlan,
        ssid: &[u8],
        channel: u8,
        aid: u16,
        password: &[u8],
        pwe: ApSaePwe,
        anonce: [u8; 32],
    ) -> Result<Self, ApError> {
        if password.is_empty() || anonce == [0; 32] {
            return Err(ApError::Configuration);
        }
        let mut ap = Self::new(plan, ssid, channel, aid, None, anonce)?;
        let mut seed = [0; 64];
        seed[..32].copy_from_slice(&anonce);
        seed[32..].copy_from_slice(&anonce);
        seed[63] ^= 0x5a;
        let session = match pwe {
            ApSaePwe::HuntAndPeck => {
                SaeSession::new_hunt_and_peck(password, plan.bssid, plan.station)
            }
            ApSaePwe::HashToElement => {
                SaeSession::new_h2e_bytes(ssid, password, plan.bssid, plan.station)
            }
        }
        .with_test_seed(seed);
        ap.rsn = Some(alloc::boxed::Box::new(RsnProfile {
            akms: vec![narf_wireless::rsn::AKM_SAE],
            caps: narf_wireless::rsn::RSN_CAP_MFP_CAPABLE
                | narf_wireless::rsn::RSN_CAP_MFP_REQUIRED,
            rsnxe: (pwe == ApSaePwe::HashToElement).then_some(narf_wireless::rsn::RSNX_CAP_SAE_H2E),
            sae: Some(SaeAp {
                session,
                pwe,
                accepted: false,
                ssid: ssid.to_vec(),
                password: password.to_vec(),
                seed,
                addresses: (plan.bssid, plan.station),
            }),
            igtk: [0x6b; 16],
            igtk_id: 4,
            ipn: 1,
            km: None,
            pmf: false,
            assoc_ies: Vec::new(),
        }));
        Ok(ap)
    }

    /// Advertise MFPC (`ApPmf::Optional`) or MFPC|MFPR on a WPA2-PSK AP. The
    /// IGTK is delivered in message 3 when the station also sets MFPC.
    pub fn with_pmf(mut self, pmf: ApPmf) -> Result<Self, ApError> {
        if self.phase != ApPhase::Authentication || self.pmk.is_none() && self.rsn.is_none() {
            return Err(ApError::Phase);
        }
        let caps = match pmf {
            ApPmf::Optional => narf_wireless::rsn::RSN_CAP_MFP_CAPABLE,
            ApPmf::Required => {
                narf_wireless::rsn::RSN_CAP_MFP_CAPABLE | narf_wireless::rsn::RSN_CAP_MFP_REQUIRED
            }
        };
        match self.rsn.as_mut() {
            Some(profile) => {
                if profile.sae.is_some() && pmf == ApPmf::Optional {
                    // SAE requires PMF.
                    return Err(ApError::Configuration);
                }
                profile.caps = caps;
            }
            None => {
                self.rsn = Some(alloc::boxed::Box::new(RsnProfile {
                    akms: vec![narf_wireless::rsn::AKM_PSK],
                    caps,
                    rsnxe: None,
                    sae: None,
                    igtk: [0x6b; 16],
                    igtk_id: 4,
                    ipn: 1,
                    km: None,
                    pmf: false,
                    assoc_ies: Vec::new(),
                }));
            }
        }
        Ok(self)
    }

    /// Replace the offered AKM suite types (for example `[8, 24]` for an
    /// SAE AP that also offers SAE-EXT-KEY, or `[6]` for PSK-SHA256).
    pub fn with_akms(mut self, akms: &[u8]) -> Result<Self, ApError> {
        let profile = self.rsn.as_mut().ok_or(ApError::Configuration)?;
        let sae = profile.sae.is_some();
        if self.phase != ApPhase::Authentication
            || akms.is_empty()
            || akms.iter().any(|a| {
                narf_wireless::eapol::KeyMgmt::from_suite_type(*a).is_none_or(|km| km.sae() != sae)
            })
        {
            return Err(ApError::Configuration);
        }
        profile.akms = akms.to_vec();
        Ok(self)
    }

    /// Select the IGTK, its key ID (4 or 5) and the IPN message 3 reports.
    pub fn with_igtk(mut self, igtk: [u8; 16], key_id: u16, ipn: u64) -> Result<Self, ApError> {
        let profile = self.rsn.as_mut().ok_or(ApError::Configuration)?;
        if !matches!(key_id, 4 | 5) || ipn >= 1 << 48 {
            return Err(ApError::Configuration);
        }
        (profile.igtk, profile.igtk_id, profile.ipn) = (igtk, key_id, ipn);
        Ok(self)
    }

    /// True once association negotiated PMF (both RSNEs set MFPC).
    pub fn pmf(&self) -> bool {
        self.rsn.as_ref().is_some_and(|p| p.pmf)
    }

    /// The negotiated AKM, after association.
    pub fn akm(&self) -> Option<narf_wireless::eapol::KeyMgmt> {
        self.rsn.as_ref().and_then(|p| p.km)
    }

    /// The installed pairwise TK after message 2 (for driver tests that
    /// check the key a device installed).
    pub fn pairwise_tk(&self) -> Option<[u8; 16]> {
        self.ptk
            .as_ref()
            .and_then(|p| p.tk.as_slice().try_into().ok())
    }

    /// The IGTK and key ID delivered in message 3.
    pub fn igtk(&self) -> Option<([u8; 16], u16)> {
        self.rsn
            .as_ref()
            .filter(|p| p.pmf)
            .map(|p| (p.igtk, p.igtk_id))
    }

    /// A group-addressed Deauthentication protected with BIP-CMAC-128 under
    /// the delivered IGTK (next IPN), as hostapd sends on AP shutdown with
    /// PMF. Refused before PMF is negotiated.
    pub fn bip_broadcast_deauth(&mut self, reason: u16) -> Result<Vec<u8>, ApError> {
        let header = self.header(0xc0, [255; 6]);
        let profile = self.rsn.as_mut().filter(|p| p.pmf).ok_or(ApError::Phase)?;
        let mut igtk = Igtk::install(profile.igtk, profile.igtk_id).map_err(|_| ApError::Key)?;
        igtk.tx_pn = profile.ipn;
        let mut body = reason.to_le_bytes().to_vec();
        narf_wireless::mfp::protect_outbound(&mut igtk, &header, &mut body)
            .map_err(|_| ApError::Key)?;
        profile.ipn += 1;
        let mut frame = header;
        frame.extend_from_slice(&body);
        Ok(frame)
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
        self.pmk.is_some() || self.rsn.is_some()
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
            (ApPhase::Authentication, 0xb0)
                if fc & 0x0300 == 0 && self.rsn.as_ref().is_some_and(|p| p.sae.is_some()) =>
            {
                self.receive_sae(frame)
            }
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
                    m1.key_information =
                        eapol::KI_KEY_TYPE_PAIRWISE | eapol::KI_KEY_ACK | self.key_version();
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

    fn key_version(&self) -> u16 {
        self.rsn
            .as_ref()
            .map_or(eapol::KI_VERSION_HMAC_SHA1_AES, |p| p.key_version())
    }

    /// SAE Authentication (algorithm 3): the station's Commit is answered
    /// with the AP's Commit, its Confirm (once verified) with the AP's
    /// Confirm, which completes authentication.
    fn receive_sae(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
        let fixed = frame.get(24..30).ok_or(ApError::Frame)?;
        let alg = u16::from_le_bytes([fixed[0], fixed[1]]);
        let seq = u16::from_le_bytes([fixed[2], fixed[3]]);
        let status = u16::from_le_bytes([fixed[4], fixed[5]]);
        let sae = self
            .rsn
            .as_mut()
            .and_then(|p| p.sae.as_mut())
            .ok_or(ApError::Phase)?;
        if alg != 3 {
            return Err(ApError::Frame);
        }
        let (seq, status, body) = sae.step(seq, status, &frame[30..]).ok_or(ApError::Key)?;
        let accepted = sae.accepted;
        let mut response = self.header(0xb0, self.plan.station);
        response.extend_from_slice(&3u16.to_le_bytes());
        response.extend_from_slice(&seq.to_le_bytes());
        response.extend_from_slice(&status.to_le_bytes());
        response.extend_from_slice(&body);
        if accepted {
            self.phase = ApPhase::Association;
        }
        Ok(vec![response])
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
        if let Some(profile) = self.rsn.as_ref() {
            return profile.elements();
        }
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

    fn check_association(&mut self, frame: &[u8]) -> Result<(), ApError> {
        let fixed = frame.get(24..28).ok_or(ApError::Association)?;
        if u16::from_le_bytes([fixed[0], fixed[1]]) & 0x11 != self.capabilities() {
            return Err(ApError::Association);
        }
        let mut ies = frame.get(28..).ok_or(ApError::Association)?;
        let (mut ssid, mut rates, mut extended_rates, mut rsn) = (None, None, None, None);
        let mut rsnxe = None;
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
                244 if rsnxe.is_none() => rsnxe = Some(ie),
                0 | 1 | 48 | 50 | 244 => return Err(ApError::Association),
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
            || match (self.rsn.as_mut(), rsn) {
                (Some(profile), Some(rsn)) => !profile.admit(rsn, rsnxe),
                (Some(_), None) => true,
                (None, _) if self.pmk.is_some() => rsn != Some(self.rsn_ie().as_slice()),
                (None, _) => rsn.is_some(),
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
        if self.rsn.is_some() {
            return self.receive_key_profiled(pdu);
        }
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

impl FakeAp {
    /// hostapd `wpa_auth` message 2 / 4 handling for an RSN profile: the
    /// negotiated AKM selects the Key Descriptor Version, PTK KDF and MIC;
    /// message 2 must repeat the association RSNE (+ RSNXE); message 3
    /// carries the AP RSNE (+ RSNXE), the GTK and, under PMF, the IGTK.
    fn receive_key_profiled(&mut self, pdu: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
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
        let profile = self.rsn.as_ref().ok_or(ApError::Key)?;
        let km = profile.km.ok_or(ApError::Key)?;
        let version = profile.key_version();
        let pairwise_mic = eapol::KI_KEY_TYPE_PAIRWISE | eapol::KI_KEY_MIC | version;
        let check = |kck: &[u8]| -> Result<(), ApError> {
            let mut clear = pdu.to_vec();
            clear[81..97].fill(0);
            let mic = eapol::wpa_eapol_key_mic(km, version, kck, &clear).ok_or(ApError::Mic)?;
            if pdu[81..97] != mic[..16] {
                return Err(ApError::Mic);
            }
            Ok(())
        };
        match self.phase {
            ApPhase::Message2 => {
                if key.key_information != pairwise_mic
                    || key.replay_counter != 1
                    || key.key_nonce == [0; 32]
                    || key.key_data != profile.assoc_ies
                {
                    return Err(ApError::Key);
                }
                let pmk = match (profile.sae_pmk(), self.pmk.as_ref()) {
                    (Some(pmk), _) => Zeroizing::new(pmk),
                    (None, Some(pmk)) => pmk.clone(),
                    (None, None) => return Err(ApError::Key),
                };
                let ptk = eapol::wpa_pmk_to_ptk(
                    km,
                    pmk.as_ref(),
                    &self.plan.bssid,
                    &self.plan.station,
                    &self.anonce,
                    &key.key_nonce,
                    16,
                );
                check(&ptk.kck)?;
                let mut m3 = KeyFrame::empty(16);
                m3.key_information = pairwise_mic
                    | eapol::KI_KEY_ACK
                    | eapol::KI_INSTALL
                    | eapol::KI_SECURE
                    | eapol::KI_ENCRYPTED_KEY_DATA;
                m3.key_length = 16;
                m3.replay_counter = 2;
                m3.key_nonce = self.anonce;
                let mut clear = profile.elements();
                clear.extend_from_slice(&[221, 22, 0, 0x0f, 0xac, 1, 1, 0]);
                clear.extend_from_slice(&[0x77; 16]);
                if profile.pmf {
                    clear.extend_from_slice(&profile.igtk_kde());
                }
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
                let mut pdu = m3.into_eapol();
                let mic =
                    eapol::wpa_eapol_key_mic(km, version, &ptk.kck, &pdu).ok_or(ApError::Mic)?;
                pdu[81..97].copy_from_slice(&mic[..16]);
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
                check(&self.ptk.as_ref().ok_or(ApError::Key)?.kck)?;
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
