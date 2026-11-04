//! One-link MLD AP wire profile. The physical NetworkPlan is never replaced
//! by an MLD alias: management/SAE/PTK use logical identities while original
//! data MPDU admission/PN remains physical-link owned. Unicast DATA crypto
//! projects to MLD addresses; group DATA and management retain link addresses.
use super::*;
use narf_wireless::association::mlo::{Context, Local};

/// Explicit fixture-only group material for this one selected link. Counters
/// are the last transmitted PN/IPN, not the next value and not a global RSC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MldGroupKeys {
    pub gtk: [u8; 16],
    pub gtk_id: u8,
    pub gtk_pn: u64,
    pub igtk: [u8; 16],
    pub igtk_id: u16,
    pub igtk_ipn: u64,
}
impl MldGroupKeys {
    fn valid(self) -> bool {
        self.gtk_id <= 3
            && matches!(self.igtk_id, 4 | 5)
            && self.gtk_pn < 1 << 48
            && self.igtk_ipn < 1 << 48
    }
}
pub(super) struct State {
    context: Context,
    pub(super) keys: MldGroupKeys,
    old_ptk: Option<Ptk>,
    replay: u64,
    // Per-TID replay owners plus the independent non-QoS slot16.
    rx_pn: [u64; 17],
    tx_pn: u64,
    tx_sequence: u16,
    pending_group: Option<MldGroupKeys>,
    last_request: Vec<u8>,
    last_reply: Vec<Vec<u8>>,
    retry: Option<Vec<u8>>,
}
impl Drop for State {
    fn drop(&mut self) {
        self.keys.gtk.zeroize();
        self.keys.igtk.zeroize();
        if let Some(keys) = self.pending_group.as_mut() {
            keys.gtk.zeroize();
            keys.igtk.zeroize();
        }
        if let Some(ptk) = self.old_ptk.as_mut() {
            ptk.kck.zeroize();
            ptk.kek.zeroize();
            ptk.tk.zeroize();
        }
    }
}
impl State {
    pub(super) fn beacon_element(&self) -> Vec<u8> {
        let mut bytes = vec![255, 13, 107, 0x10, 1, 10];
        bytes.extend_from_slice(&self.context.peer_mld());
        bytes.extend_from_slice(&[self.context.link_id(), 0, 0]);
        bytes
    }
}
impl FakeAp {
    /// Select the bounded MLD peer before authentication. The native fixture
    /// still supplies its actual HE/EHT capability/operation IEs and firmware
    /// role/address-translation proofs; this option grants none of them.
    pub fn with_single_link_mld(mut self, context: Context) -> Result<Self, ApError> {
        let profile = self.rsn.as_mut().ok_or(ApError::Configuration)?;
        if self.phase != ApPhase::Authentication
            || self.mld.is_some()
            || self.ptk.is_some()
            || profile.km.is_some()
            || profile.sae.as_ref().is_some_and(|s| {
                s.session.state() != narf_wireless::sae::SaeState::Nothing || s.accepted
            })
            || profile.caps & narf_wireless::rsn::RSN_CAP_MFP_REQUIRED == 0
            || context.own_link() != self.plan.station
            || context.peer_link() != self.plan.bssid
        {
            return Err(ApError::Configuration);
        }
        if let Some(sae) = profile.sae.as_mut() {
            let (own, peer) = (context.peer_mld(), context.own_mld());
            sae.session = match sae.pwe {
                ApSaePwe::HuntAndPeck => SaeSession::new_hunt_and_peck(&sae.password, own, peer),
                ApSaePwe::HashToElement => {
                    SaeSession::new_h2e_bytes(&sae.ssid, &sae.password, own, peer)
                }
            };
            sae.addresses = (own, peer);
        }
        self.mld = Some(alloc::boxed::Box::new(State {
            context,
            keys: MldGroupKeys {
                gtk: [0x77; 16],
                gtk_id: 1,
                gtk_pn: 0,
                igtk: profile.igtk,
                igtk_id: profile.igtk_id,
                igtk_ipn: profile.ipn,
            },
            old_ptk: None,
            replay: 1,
            rx_pn: [0; 17],
            tx_pn: 0,
            tx_sequence: 0,
            pending_group: None,
            last_request: Vec::new(),
            last_reply: Vec::new(),
            retry: None,
        }));
        Ok(self)
    }
    pub fn single_link_mld(&self) -> Option<&Context> {
        self.mld.as_deref().map(|mld| &mld.context)
    }
    /// Produce actual CCMP radio data under the same retained PN owner as
    /// EAPOL. Native adapters must not allocate a second independent AP PN.
    pub fn transmit_mld_data(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, ApError> {
        let state = self.mld.as_ref().ok_or(ApError::Configuration)?;
        let context = state.context;
        if self.phase != ApPhase::Authorized
            || state.pending_group.is_some()
            || state.old_ptk.is_some()
        {
            return Err(ApError::Phase);
        }
        if !(14..=1514).contains(&ethernet.len()) {
            return Err(ApError::Frame);
        }
        let destination = &ethernet[..6];
        let source = &ethernet[6..12];
        let kind = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        let group = destination[0] & 1 != 0;
        if destination == [0; 6]
            || source == [0; 6]
            || source[0] & 1 != 0
            || source == context.own_mld()
            || source == context.own_link()
            || !group && destination != context.own_mld()
            || kind < 0x600
            || kind == 0x888e
        {
            return Err(ApError::Frame);
        }
        let receiver = if group {
            destination.try_into().unwrap()
        } else {
            context.own_link()
        };
        let mut header = self.header(8, receiver);
        header[1] = 0x42;
        header[16..22].copy_from_slice(source);
        let crypto_header = context
            .data_crypto_header(&header)
            .map_err(|_| ApError::Frame)?;
        let state = self.mld.as_mut().unwrap();
        let counter = if group {
            &mut state.keys.gtk_pn
        } else {
            &mut state.tx_pn
        };
        if *counter >= (1 << 48) - 1 {
            return Err(ApError::Key);
        }
        *counter += 1;
        let pn = *counter;
        header[22..24].copy_from_slice(&(state.tx_sequence << 4).to_le_bytes());
        state.tx_sequence = (state.tx_sequence + 1) & 4095;
        let mut crypto_header = crypto_header;
        crypto_header[22..24].copy_from_slice(&header[22..24]);
        let key = Zeroizing::new(if group {
            state.keys.gtk
        } else {
            self.ptk
                .as_ref()
                .ok_or(ApError::Key)?
                .tk
                .as_slice()
                .try_into()
                .map_err(|_| ApError::Key)?
        });
        let mut body = Zeroizing::new(vec![0xaa, 0xaa, 3, 0, 0, 0, ethernet[12], ethernet[13]]);
        body.extend_from_slice(&ethernet[14..]);
        let wire = narf_wireless::ccmp::protect(
            &Ccm,
            &crypto_header,
            &key,
            pn,
            if group { state.keys.gtk_id } else { 0 },
            0,
            false,
            &mut body,
        )
        .map_err(|_| ApError::Key)?;
        header.extend_from_slice(&wire);
        Ok(header)
    }
    /// Repeat the exact current M1/M3/group wire packet: no new PN, replay
    /// counter, key derivation or after-MIC edits occur on retransmission.
    pub fn retransmit_mld(&self) -> Result<Vec<u8>, ApError> {
        self.mld
            .as_deref()
            .and_then(|mld| mld.retry.clone())
            .ok_or(ApError::Phase)
    }
    pub fn start_mld_pairwise_rekey(&mut self, anonce: [u8; 32]) -> Result<Vec<u8>, ApError> {
        let state = self.mld.as_mut().ok_or(ApError::Configuration)?;
        if self.phase != ApPhase::Authorized
            || state.pending_group.is_some()
            || state.old_ptk.is_some()
            || anonce == [0; 32]
            || anonce == self.anonce
            || state.replay > u64::MAX - 3
            || state.tx_pn >= (1 << 48) - 1
        {
            return Err(ApError::Phase);
        }
        state.old_ptk = Some(self.ptk.take().ok_or(ApError::Phase)?);
        state.replay += 2;
        state.last_request.clear();
        state.last_reply.clear();
        self.anonce = anonce;
        self.phase = ApPhase::Message2;
        let frame = self.mld_message1()?;
        self.mld.as_mut().unwrap().retry = Some(frame.clone());
        Ok(frame)
    }
    pub fn start_mld_group_rekey(&mut self, keys: MldGroupKeys) -> Result<Vec<u8>, ApError> {
        let state = self.mld.as_ref().ok_or(ApError::Configuration)?;
        if self.phase != ApPhase::Authorized
            || state.pending_group.is_some()
            || state.old_ptk.is_some()
            || !keys.valid()
            || state.replay > u64::MAX - 2
        {
            return Err(ApError::Phase);
        }
        let rc = state.replay + 2;
        let mut m1 = KeyFrame::empty(16);
        m1.key_information = self.key_version()
            | eapol::KI_KEY_ACK
            | eapol::KI_KEY_MIC
            | eapol::KI_SECURE
            | eapol::KI_ENCRYPTED_KEY_DATA;
        m1.key_length = 16;
        m1.replay_counter = rc;
        let ptk = self.ptk.as_ref().ok_or(ApError::Phase)?;
        m1.key_data = self.mld_wrapped_keys(keys, false, ptk)?;
        let pdu = self.mld_sign(m1, ptk)?;
        let frame = self.mld_eapol_frame(&pdu)?;
        let state = self.mld.as_mut().unwrap();
        state.replay = rc;
        state.pending_group = Some(keys);
        state.last_request.clear();
        state.last_reply.clear();
        state.retry = Some(frame.clone());
        Ok(frame)
    }
    fn mld_management(&self, subtype: u8) -> Vec<u8> {
        let context = self.mld.as_ref().unwrap().context;
        let mut frame = vec![subtype, 0, 0, 0];
        frame.extend_from_slice(&context.own_mld());
        frame.extend_from_slice(&context.peer_mld());
        frame.extend_from_slice(&context.peer_mld());
        frame.extend_from_slice(&[0, 0]);
        frame
    }
    pub(super) fn receive_mld(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
        if !(24..=4096).contains(&frame.len()) {
            return Err(ApError::Frame);
        }
        let state = self.mld.as_ref().unwrap();
        if state.last_request.as_slice() == frame {
            return Ok(state.last_reply.clone());
        }
        let context = state.context;
        let fc = u16::from_le_bytes([frame[0], frame[1]]);
        if fc & 0x8403 != 0 || frame[22] & 15 != 0 {
            return Err(ApError::Frame);
        }
        let mut received_pn = None;
        let retiring_packet_epoch = self.phase == ApPhase::Message4;
        let result = if fc & 0x000c == 0 {
            if fc & 0x4300 != 0
                || frame[4..10] != context.peer_mld()
                || frame[10..16] != context.own_mld()
                || frame[16..22] != context.peer_mld()
            {
                return Err(ApError::Frame);
            }
            match (self.phase, fc & 0x00fc) {
                (ApPhase::Authentication, 0xb0) => self.mld_authentication(frame),
                (ApPhase::Association, 0) => {
                    // The exact one-link request is checked independently of
                    // all caller/native PHY additions before RSN mutation.
                    let local =
                        Local::single_link(context.own_mld()).map_err(|_| ApError::Association)?;
                    let expected = local.request_element();
                    let mut found = None;
                    let mut ies = frame.get(28..).ok_or(ApError::Association)?;
                    while !ies.is_empty() {
                        let h = ies.get(..2).ok_or(ApError::Association)?;
                        let ie = ies
                            .get(..2 + usize::from(h[1]))
                            .ok_or(ApError::Association)?;
                        if h[0] == 242 {
                            return Err(ApError::Association);
                        }
                        if h[0] == 255 && ie.get(2) == Some(&107) && found.replace(ie).is_some() {
                            return Err(ApError::Association);
                        }
                        ies = &ies[ie.len()..];
                    }
                    if found != Some(expected.as_slice()) {
                        return Err(ApError::Association);
                    }
                    self.check_association(frame)?;
                    if !self.pmf() {
                        return Err(ApError::Association);
                    }
                    let mut response = self.mld_management(0x10);
                    response.extend_from_slice(&self.capabilities().to_le_bytes());
                    response.extend_from_slice(&0u16.to_le_bytes());
                    response.extend_from_slice(&(self.aid | 0xc000).to_le_bytes());
                    self.append_rates(&mut response);
                    response.extend_from_slice(&self.rsn_ie());
                    response.extend_from_slice(
                        &Local::single_link(context.peer_mld())
                            .unwrap()
                            .request_element(),
                    );
                    let m1 = self.mld_message1()?;
                    self.phase = ApPhase::Message2;
                    self.mld.as_mut().unwrap().retry = Some(m1.clone());
                    Ok(vec![response, m1])
                }
                _ => Err(ApError::Phase),
            }
        } else {
            if !matches!(fc & 0x00fc, 0x08 | 0x88)
                || fc & 0x0300 != 0x0100
                || frame[4..10] != context.peer_link()
                || frame[10..16] != context.own_link()
                || frame[16..22] != context.peer_mld()
            {
                return Err(ApError::Frame);
            }
            let offset = if fc & 0x80 == 0 { 24 } else { 26 };
            let header = frame.get(..offset).ok_or(ApError::Frame)?;
            if offset == 26 && (header[24] & 0xf0 != 0 || header[25] != 0) {
                return Err(ApError::Frame);
            }
            let clear;
            let body = if fc & 0x4000 != 0 {
                let state = self.mld.as_ref().unwrap();
                if state.old_ptk.is_none() && self.phase != ApPhase::Authorized {
                    return Err(ApError::Frame);
                }
                let ptk = state
                    .old_ptk
                    .as_ref()
                    .or(self.ptk.as_ref())
                    .ok_or(ApError::Key)?;
                let slot = if offset == 26 {
                    usize::from(header[24] & 15)
                } else {
                    16
                };
                let mut replay = narf_wireless::ccmp::ReplayWindow {
                    last_seen_pn: state.rx_pn[slot],
                };
                let mut wire = frame[offset..].to_vec();
                let crypto_header = context
                    .data_crypto_header(header)
                    .map_err(|_| ApError::Frame)?;
                clear = narf_wireless::ccmp::unprotect(
                    &Ccm,
                    &crypto_header,
                    ptk.tk.as_slice().try_into().map_err(|_| ApError::Key)?,
                    if offset == 26 { header[24] & 15 } else { 0 },
                    false,
                    &mut replay,
                    &mut wire,
                )
                .map_err(|_| ApError::Key)?;
                received_pn = Some((slot, replay.last_seen_pn));
                clear.as_slice()
            } else {
                if self.mld.as_ref().unwrap().old_ptk.is_some() || self.phase == ApPhase::Authorized
                {
                    return Err(ApError::Frame);
                }
                &frame[offset..]
            };
            if body.get(..8) != Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]) {
                return Err(ApError::Frame);
            }
            self.mld_receive_key(&body[8..])
        };
        if let Ok(replies) = &result {
            let state = self.mld.as_mut().unwrap();
            if let Some((slot, pn)) = received_pn {
                // M4 replaced the packet key and reset its PN owner already.
                if !retiring_packet_epoch {
                    state.rx_pn[slot] = pn;
                }
            }
            state.last_request = frame.to_vec();
            state.last_reply = replies.clone();
        }
        result
    }
    fn mld_authentication(&mut self, frame: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
        let context = self.mld.as_ref().unwrap().context;
        let fixed = frame.get(24..30).ok_or(ApError::Frame)?;
        let expected = Local::single_link(context.own_mld())
            .unwrap()
            .authentication_element();
        let body = frame.get(30..).ok_or(ApError::Frame)?;
        let at = body
            .len()
            .checked_sub(expected.len())
            .ok_or(ApError::Frame)?;
        if body[at..] != expected {
            return Err(ApError::Frame);
        }
        let mut response = self.mld_management(0xb0);
        let sae = self.rsn.as_mut().unwrap().sae.as_mut();
        if let Some(sae) = sae {
            if fixed[..2] != [3, 0] {
                return Err(ApError::Frame);
            }
            let (seq, status, body) = sae
                .step(
                    u16::from_le_bytes([fixed[2], fixed[3]]),
                    u16::from_le_bytes([fixed[4], fixed[5]]),
                    &body[..at],
                )
                .ok_or(ApError::Key)?;
            let accepted = sae.accepted;
            response.extend_from_slice(&3u16.to_le_bytes());
            response.extend_from_slice(&seq.to_le_bytes());
            response.extend_from_slice(&status.to_le_bytes());
            response.extend_from_slice(&body);
            if accepted {
                self.phase = ApPhase::Association;
            }
        } else {
            if fixed != [0, 0, 1, 0, 0, 0] || at != 0 {
                return Err(ApError::Frame);
            }
            response.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
            self.phase = ApPhase::Association;
        }
        response.extend_from_slice(
            &Local::single_link(context.peer_mld())
                .unwrap()
                .authentication_element(),
        );
        Ok(vec![response])
    }
    fn mld_message1(&mut self) -> Result<Vec<u8>, ApError> {
        let state = self.mld.as_ref().unwrap();
        let mut m1 = KeyFrame::empty(16);
        m1.key_information = eapol::KI_KEY_TYPE_PAIRWISE | eapol::KI_KEY_ACK | self.key_version();
        m1.key_length = 16;
        m1.replay_counter = state.replay;
        m1.key_nonce = self.anonce;
        m1.key_data = kde(3, &state.context.peer_mld());
        self.mld_eapol_frame(&m1.into_eapol())
    }
    fn mld_eapol_frame(&mut self, pdu: &[u8]) -> Result<Vec<u8>, ApError> {
        let context = self.mld.as_ref().unwrap().context;
        let mut frame = self.header(8, context.own_link());
        frame[1] = 2;
        frame[16..22].copy_from_slice(&context.peer_mld());
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e];
        body.extend_from_slice(pdu);
        let state = self.mld.as_mut().unwrap();
        frame[22..24].copy_from_slice(&(state.tx_sequence << 4).to_le_bytes());
        state.tx_sequence = (state.tx_sequence + 1) & 4095;
        let key = match state.old_ptk.as_ref() {
            Some(key) => Some(key),
            None if self.phase == ApPhase::Authorized => self.ptk.as_ref(),
            None => None,
        };
        if let Some(key) = key {
            if state.tx_pn >= (1 << 48) - 1 {
                return Err(ApError::Key);
            }
            state.tx_pn += 1;
            frame[1] |= 0x40;
            let crypto_header = context
                .data_crypto_header(&frame)
                .map_err(|_| ApError::Frame)?;
            let wire = narf_wireless::ccmp::protect(
                &Ccm,
                &crypto_header,
                key.tk.as_slice().try_into().map_err(|_| ApError::Key)?,
                state.tx_pn,
                0,
                0,
                false,
                &mut body,
            )
            .map_err(|_| ApError::Key)?;
            frame.extend_from_slice(&wire);
        } else {
            frame.extend_from_slice(&body);
        }
        Ok(frame)
    }
    fn mld_wrapped_keys(
        &self,
        keys: MldGroupKeys,
        pairwise: bool,
        ptk: &Ptk,
    ) -> Result<Vec<u8>, ApError> {
        let profile = self.rsn.as_ref().ok_or(ApError::Key)?;
        let context = self.mld.as_ref().unwrap().context;
        let mut clear = Zeroizing::new(Vec::new());
        if pairwise {
            clear.extend_from_slice(&kde(3, &context.peer_mld()));
            let mut link =
                vec![context.link_id() | 0x10 | if profile.rsnxe.is_some() { 0x20 } else { 0 }];
            link.extend_from_slice(&context.peer_link());
            link.extend_from_slice(&profile.elements());
            clear.extend_from_slice(&kde(19, &link));
        }
        let mut gtk = vec![context.link_id() << 4 | keys.gtk_id];
        gtk.extend_from_slice(&keys.gtk_pn.to_le_bytes()[..6]);
        gtk.extend_from_slice(&keys.gtk);
        clear.extend_from_slice(&kde(16, &gtk));
        gtk.zeroize();
        let mut igtk = keys.igtk_id.to_le_bytes().to_vec();
        igtk.extend_from_slice(&keys.igtk_ipn.to_le_bytes()[..6]);
        igtk.push(context.link_id() << 4);
        igtk.extend_from_slice(&keys.igtk);
        clear.extend_from_slice(&kde(17, &igtk));
        igtk.zeroize();
        if clear.len() % 8 != 0 {
            clear.push(221);
        }
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
        narf_crypto::aes_kw::aes_wrap(
            ptk.kek.as_slice().try_into().map_err(|_| ApError::Key)?,
            &clear,
        )
        .ok_or(ApError::Key)
    }
    fn mld_sign(&self, frame: KeyFrame, ptk: &Ptk) -> Result<Vec<u8>, ApError> {
        let mut pdu = frame.into_eapol();
        let profile = self.rsn.as_ref().unwrap();
        let mic = eapol::wpa_eapol_key_mic(
            profile.km.ok_or(ApError::Key)?,
            profile.key_version(),
            &ptk.kck,
            &pdu,
        )
        .ok_or(ApError::Mic)?;
        pdu[81..97].copy_from_slice(&mic[..16]);
        Ok(pdu)
    }
    fn mld_receive_key(&mut self, pdu: &[u8]) -> Result<Vec<Vec<u8>>, ApError> {
        if pdu.len() < 99
            || pdu[1] != 3
            || !(1..=3).contains(&pdu[0])
            || usize::from(u16::from_be_bytes([pdu[2], pdu[3]])) + 4 != pdu.len()
        {
            return Err(ApError::Key);
        }
        let key = KeyFrame::decode(&pdu[4..], 16).ok_or(ApError::Key)?;
        if key.descriptor_type != eapol::KEY_DESCRIPTOR_RSN || key.encode().len() + 4 != pdu.len() {
            return Err(ApError::Key);
        }
        let state = self.mld.as_ref().unwrap();
        let context = state.context;
        let rc = state.replay;
        let profile = self.rsn.as_ref().unwrap();
        let km = profile.km.ok_or(ApError::Key)?;
        let version = profile.key_version();
        let pair = version | eapol::KI_KEY_TYPE_PAIRWISE | eapol::KI_KEY_MIC;
        let verify = |ptk: &Ptk| -> Result<(), ApError> {
            let mut clear = pdu.to_vec();
            clear[81..97].fill(0);
            let mic =
                eapol::wpa_eapol_key_mic(km, version, &ptk.kck, &clear).ok_or(ApError::Mic)?;
            if mic[..16] != pdu[81..97] {
                return Err(ApError::Mic);
            }
            Ok(())
        };
        match self.phase {
            ApPhase::Message2 => {
                let rekey = state.old_ptk.is_some();
                let mut expected = profile.assoc_ies.clone();
                expected.extend_from_slice(&kde(3, &context.own_mld()));
                if key.key_information != pair | if rekey { eapol::KI_SECURE } else { 0 }
                    || key.replay_counter != rc
                    || key.key_nonce == [0; 32]
                    || key.key_data != expected
                {
                    return Err(ApError::Key);
                }
                let pmk = profile
                    .sae_pmk()
                    .map(Zeroizing::new)
                    .or_else(|| self.pmk.clone())
                    .ok_or(ApError::Key)?;
                let ptk = eapol::wpa_pmk_to_ptk(
                    km,
                    pmk.as_ref(),
                    &context.peer_mld(),
                    &context.own_mld(),
                    &self.anonce,
                    &key.key_nonce,
                    16,
                );
                verify(&ptk)?;
                let mut m3 = KeyFrame::empty(16);
                m3.key_information = pair
                    | eapol::KI_KEY_ACK
                    | eapol::KI_INSTALL
                    | eapol::KI_SECURE
                    | eapol::KI_ENCRYPTED_KEY_DATA;
                m3.key_length = 16;
                m3.replay_counter = rc + 1;
                m3.key_nonce = self.anonce;
                m3.key_data = self.mld_wrapped_keys(self.mld.as_ref().unwrap().keys, true, &ptk)?;
                let pdu = self.mld_sign(m3, &ptk)?;
                let wire = self.mld_eapol_frame(&pdu)?;
                self.ptk = Some(ptk);
                self.phase = ApPhase::Message4;
                self.mld.as_mut().unwrap().retry = Some(wire.clone());
                Ok(vec![wire])
            }
            ApPhase::Message4 => {
                if key.key_information != pair | eapol::KI_SECURE
                    || key.replay_counter != rc + 1
                    || key.key_nonce != [0; 32]
                    || !key.key_data.is_empty()
                {
                    return Err(ApError::Key);
                }
                verify(self.ptk.as_ref().ok_or(ApError::Key)?)?;
                self.phase = ApPhase::Authorized;
                let state = self.mld.as_mut().unwrap();
                if let Some(mut old) = state.old_ptk.take() {
                    old.kck.zeroize();
                    old.kek.zeroize();
                    old.tk.zeroize();
                }
                state.rx_pn = [0; 17];
                state.tx_pn = 0;
                state.retry = None;
                Ok(Vec::new())
            }
            ApPhase::Authorized if state.pending_group.is_some() => {
                if key.key_information != version | eapol::KI_KEY_MIC | eapol::KI_SECURE
                    || key.replay_counter != rc
                    || key.key_nonce != [0; 32]
                    || !key.key_data.is_empty()
                {
                    return Err(ApError::Key);
                }
                verify(self.ptk.as_ref().ok_or(ApError::Key)?)?;
                let state = self.mld.as_mut().unwrap();
                state.keys = state.pending_group.take().unwrap();
                let profile = self.rsn.as_mut().unwrap();
                (profile.igtk, profile.igtk_id, profile.ipn) =
                    (state.keys.igtk, state.keys.igtk_id, state.keys.igtk_ipn);
                state.retry = None;
                Ok(Vec::new())
            }
            _ => Err(ApError::Phase),
        }
    }
}
fn kde(selector: u8, bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![221, (4 + bytes.len()) as u8, 0, 0x0f, 0xac, selector];
    out.extend_from_slice(bytes);
    out
}
struct Ccm;
impl narf_wireless::ccmp::AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::seal(key, nonce, aad, body)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), narf_wireless::ccmp::CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag)
            .map_err(|_| narf_wireless::ccmp::CcmpError::AuthFailed)
    }
}

#[path = "ap_mlo_tests.rs"]
mod tests;
