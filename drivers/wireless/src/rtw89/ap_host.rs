// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B AP host session: the mac80211 work rtw89 leaves to the host for
//! one AP vif. Peers are bound to the `ApController` MACIDs; frames are
//! converted between 802.3 and FromDS/ToDS 802.11 exactly as mac80211 does
//! for a software-crypto AP, with host CCMP (`ap_crypto`), the control-port
//! split, intra-BSS forwarding and host AP power save (`ap_ps`).
//!
//! Linux 7.3-rc4: tx.c `ieee80211_build_hdr` (AP branch: FromDS, A1 DA,
//! A2 BSSID, A3 SA; QoS only for a WME peer, never for group addresses),
//! `ieee80211_tx_h_unicast_ps_buf`, `ieee80211_tx_h_multicast_ps_buf`
//! (`SEND_AFTER_DTIM`); rx.c `ieee80211_rx_h_uapsd_and_pspoll` before
//! `ieee80211_rx_h_decrypt`, `ieee80211_drop_unencrypted`,
//! `ieee80211_data_to_8023`, `ieee80211_deliver_skb` (intra-BSS forward
//! unless `ap_isolate`) and `ieee80211_frame_allowed` (control port).
//! rtw89 core.c `rtw89_core_rx` fills `RX_FLAG_*` only for hardware
//! decryption, which this profile never enables.
use super::{
    ap_crypto::{self, Install, Keys, Target},
    ap_ps::{self, ApPs, PeerConfig, Response, Transmit},
    ap_wire, qos,
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use narf_wireless::{ap_control::ApEventAuthority, ApConfig, ApStartSettings, StationConfig};
use zeroize::Zeroizing;

pub(in crate::rtw89) const CCMP: u32 = 0x000f_ac04;
/// Bounded host transmit backlog (ordinary TX ring work plus PS releases).
const OUTBOUND: usize = 64;
/// Bounded management subscriptions per AP (as the other host AP owners).
const REGISTRATIONS: usize = 16;
const LLC: [u8; 6] = [0xaa, 0xaa, 0x03, 0, 0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Error {
    /// Malformed or contradictory input; nothing changed.
    Invalid,
    /// A valid request outside this profile (MFP, HT/VHT/HE, MBSSID ...).
    Unsupported,
    /// Not yet started, no such peer/key, or the backlog is full.
    Busy,
    Crypto(ap_crypto::Error),
    Ps(ap_ps::Error),
}
impl From<ap_crypto::Error> for Error {
    fn from(error: ap_crypto::Error) -> Self {
        Self::Crypto(error)
    }
}
impl From<ap_ps::Error> for Error {
    fn from(error: ap_ps::Error) -> Self {
        Self::Ps(error)
    }
}

/// The started BSS: one 20 MHz primary and the beacon template parts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Plan {
    pub(in crate::rtw89) primary: u8,
    pub(in crate::rtw89) frequency: u32,
    pub(in crate::rtw89) beacon_interval: u16,
    pub(in crate::rtw89) dtim_period: u8,
    pub(in crate::rtw89) privacy: bool,
    head: Vec<u8>,
    tail: Vec<u8>,
}
fn beacon_head_valid(own: [u8; 6], head: &[u8]) -> bool {
    // 24-byte header + timestamp/interval/capability, broadcast A1, own A2/A3.
    head.len() >= 36
        && head[..2] == [0x80, 0]
        && head[4..10] == [0xff; 6]
        && head[10..16] == own
        && head[16..22] == own
}
fn elements_valid(mut ies: &[u8]) -> bool {
    while !ies.is_empty() {
        if ies.len() < 2 || ies.len() < 2 + usize::from(ies[1]) || ies[0] == 5 {
            return false;
        }
        ies = &ies[2 + usize::from(ies[1])..];
    }
    true
}
impl Plan {
    /// START_AP facts this AP profile honours. Every richer request (wider
    /// channel, MBSSID/EMA, FILS/unsolicited probe, FTM, TWT, HE BSS/OBSS,
    /// P2P GO power save) is refused rather than silently dropped.
    pub(in crate::rtw89) fn new(
        own: [u8; 6],
        config: &ApConfig,
        settings: &ApStartSettings,
        primary: u8,
    ) -> Result<Self, Error> {
        if config.mbssid.is_some()
            || !config.mbssid_elems.is_empty()
            || !config.ema_rnr_elems.is_empty()
            || config.fils_discovery.is_some()
            || config.unsol_bcast_probe_resp.is_some()
            || config.ftm_responder.is_some()
            || config.twt_responder
            || config.he_obss_pd.is_some()
            || config.he_bss_color.is_some()
            || settings.p2p_go.is_some()
            // NL80211_CHAN_WIDTH_20_NOHT / _20 only.
            || config.channel_width > 1
            || config.center_freq2_mhz.is_some()
            || config
                .center_freq1_mhz
                .is_some_and(|center| center != config.frequency_mhz)
        {
            return Err(Error::Unsupported);
        }
        if config.privacy {
            // Host CCMP-128 only (cipher_suites); TKIP/GCMP/BIP never pass.
            if settings
                .pairwise_ciphers
                .as_ref()
                .is_some_and(|ciphers| ciphers.iter().any(|c| *c != CCMP))
                || settings.group_cipher.is_some_and(|c| c != CCMP)
            {
                return Err(Error::Unsupported);
            }
        }
        let beacon_interval = u16::try_from(config.beacon_interval).map_err(|_| Error::Invalid)?;
        let dtim_period = u8::try_from(config.dtim_period).map_err(|_| Error::Invalid)?;
        if beacon_interval == 0
            || dtim_period == 0
            || !beacon_head_valid(own, &config.beacon_head)
            || !elements_valid(&config.beacon_head[36..])
            || !elements_valid(&config.beacon_tail)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            primary,
            frequency: config.frequency_mhz,
            beacon_interval,
            dtim_period,
            privacy: config.privacy,
            head: config.beacon_head.clone(),
            tail: config.beacon_tail.clone(),
        })
    }
}

/// One station known to the AP (`struct sta_info` subset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Peer {
    pub(in crate::rtw89) addr: [u8; 6],
    /// `rtwsta_link->mac_id` from `ApController::add_peer`.
    pub(in crate::rtw89) macid: u8,
    /// Nonzero once associated (`rtw89_core_sta_link_assoc`).
    pub(in crate::rtw89) aid: u16,
    /// `WLAN_STA_AUTHORIZED`.
    pub(in crate::rtw89) authorized: bool,
    pub(in crate::rtw89) wme: bool,
    pub(in crate::rtw89) uapsd_queues: u8,
    pub(in crate::rtw89) max_sp: u8,
    pub(in crate::rtw89) listen_interval: u16,
    /// `supp_rates` as the RA legacy bitmap (CCK bits 0..3, OFDM 4..11).
    pub(in crate::rtw89) rates: u16,
}
/// `ieee80211_get_sband`-style legacy rate bitmap from the NEW_STATION
/// supported-rates list (500 kb/s units, basic bit ignored).
pub(in crate::rtw89) fn legacy_rates(rates: &[u8], ghz5: bool) -> u16 {
    const TABLE: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let mut mask = rates.iter().fold(0u16, |mask, rate| {
        TABLE
            .iter()
            .position(|r| *r == rate & 0x7f)
            .map_or(mask, |bit| mask | 1 << bit)
    });
    // phy.c rtw89_phy_ra_sta_update: 5 GHz peers are OFDM-only.
    if ghz5 {
        mask &= 0xff0;
    }
    mask
}

/// A finished MPDU for `packet_submit_ap`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Outbound {
    pub(in crate::rtw89) mpdu: Vec<u8>,
    /// `IEEE80211_TX_CTL_SEND_AFTER_DTIM`: CH9 high queue on the vif port.
    pub(in crate::rtw89) after_dtim: bool,
    /// AP PS release whose terminal TX report ends a service period.
    pub(in crate::rtw89) release: Option<(u16, Response)>,
}

/// One received frame after host processing.
#[derive(Debug)]
pub(in crate::rtw89) enum Inbound {
    /// Management frame for the userspace SME subscriptions.
    Management(Vec<u8>),
    /// 802.3 frame for the network stack.
    Ethernet(Vec<u8>),
    /// Control-port PDU (EAPOL / pre-authentication) for the authenticator.
    Control {
        peer: [u8; 6],
        ethertype: u16,
        pdu: Zeroizing<Vec<u8>>,
        unencrypted: bool,
    },
}

pub(in crate::rtw89) struct Registration {
    pub(in crate::rtw89) event: ApEventAuthority,
    pub(in crate::rtw89) frame_type: u16,
    pub(in crate::rtw89) prefix: Vec<u8>,
}

struct Session {
    plan: Plan,
    settings: ApStartSettings,
    peers: Vec<Peer>,
    default_group: Option<u8>,
    ps: ApPs,
    sequence: u16,
    /// TIM changed since the last published beacon (`update_beacon_work`).
    beacon_dirty: bool,
}

/// Terminal report slot: the RPQ outcome and the PS release it ends.
type Report = (Option<bool>, Option<(u16, Response)>);
/// Per-device AP host owner. Key history survives role stop so retired
/// temporal-key material can never return with a reset PN.
#[derive(Default)]
pub(in crate::rtw89) struct Host {
    own: [u8; 6],
    session: Option<Session>,
    keys: Keys,
    outbound: VecDeque<Outbound>,
    /// Submitted frame id -> terminal report (`None` until RPQ release).
    reports: alloc::collections::BTreeMap<u64, Report>,
    pub(in crate::rtw89) registrations: Vec<Arc<Registration>>,
    pub(in crate::rtw89) control: Option<ApEventAuthority>,
    /// The START_AP request's captured emission authority; the started BSS
    /// lives only while it (source, registration, admin) stays current.
    pub(in crate::rtw89) emission: Option<narf_wireless::ap_control::ApEmissionAuthority>,
}

impl Host {
    pub(in crate::rtw89) fn started(&self) -> bool {
        self.session.is_some()
    }
    pub(in crate::rtw89) fn plan(&self) -> Option<&Plan> {
        self.session.as_ref().map(|s| &s.plan)
    }
    pub(in crate::rtw89) fn start(&mut self, own: [u8; 6], plan: Plan, settings: ApStartSettings) {
        self.own = own;
        self.keys.clear_active();
        self.outbound.clear();
        self.reports.clear();
        let ps = ApPs::new(own, plan.beacon_interval);
        self.session = Some(Session {
            plan,
            settings,
            peers: Vec::new(),
            default_group: None,
            ps,
            sequence: 0,
            beacon_dirty: false,
        });
    }
    /// `rtw89_ops_stop_ap`: every peer, key, buffer and report is dropped.
    pub(in crate::rtw89) fn stop(&mut self) {
        self.session = None;
        self.keys.clear_active();
        self.outbound.clear();
        self.reports.clear();
        self.control = None;
        self.emission = None;
    }
    /// head || TIM || tail with the element offset for `GRP_IE_OFST`.
    pub(in crate::rtw89) fn beacon(&mut self) -> Result<(Vec<u8>, usize), Error> {
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        session.beacon_dirty = false;
        let tim = session.ps.tim_element(0, session.plan.dtim_period);
        Ok(ap_wire::compose_beacon(
            &session.plan.head,
            &tim,
            &session.plan.tail,
        ))
    }
    pub(in crate::rtw89) fn beacon_dirty(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.beacon_dirty)
    }
    /// SET_BEACON: replace head and/or tail (the probe-response template is
    /// not offloaded; hostapd answers probes through management TX).
    pub(in crate::rtw89) fn set_beacon(
        &mut self,
        head: Option<Vec<u8>>,
        tail: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let own = self.own;
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        if head
            .as_ref()
            .is_some_and(|h| !beacon_head_valid(own, h) || !elements_valid(&h[36..]))
            || tail.as_ref().is_some_and(|t| !elements_valid(t))
        {
            return Err(Error::Invalid);
        }
        if let Some(head) = head {
            session.plan.head = head;
        }
        if let Some(tail) = tail {
            session.plan.tail = tail;
        }
        Ok(())
    }
    pub(in crate::rtw89) fn peers(&self) -> Vec<Peer> {
        self.session
            .as_ref()
            .map(|s| s.peers.clone())
            .unwrap_or_default()
    }
    pub(in crate::rtw89) fn peer(&self, addr: [u8; 6]) -> Option<Peer> {
        self.session
            .as_ref()?
            .peers
            .iter()
            .find(|p| p.addr == addr)
            .copied()
    }
    /// NEW_STATION admission: unicast, not own, no MFP and not yet present.
    pub(in crate::rtw89) fn check_new(&self, config: &StationConfig) -> Result<(), Error> {
        let session = self.session.as_ref().ok_or(Error::Busy)?;
        if config.mac == [0; 6] || config.mac[0] & 1 != 0 || config.mac == self.own {
            return Err(Error::Invalid);
        }
        if config.mfp == Some(true) {
            return Err(Error::Unsupported);
        }
        if session.peers.iter().any(|p| p.addr == config.mac) {
            return Err(Error::Invalid);
        }
        Self::check_wme(config)
    }
    fn check_wme(config: &StationConfig) -> Result<(), Error> {
        if config.aid > ap_ps::MAX_AID
            || config.uapsd_queues.is_some_and(|q| q > 0xf)
            || config.uapsd_max_sp.is_some_and(|sp| sp > 3)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(in crate::rtw89) fn add_peer(
        &mut self,
        config: &StationConfig,
        macid: u8,
    ) -> Result<Peer, Error> {
        self.check_new(config)?;
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        let peer = Peer {
            addr: config.mac,
            macid,
            aid: 0,
            authorized: false,
            wme: config.wme.unwrap_or(false),
            uapsd_queues: config.uapsd_queues.unwrap_or(0),
            max_sp: config.uapsd_max_sp.unwrap_or(0),
            listen_interval: config.listen_interval,
            rates: legacy_rates(
                &config.supported_rates,
                super::station::ghz5(session.plan.primary),
            ),
        };
        session.peers.try_reserve(1).map_err(|_| Error::Busy)?;
        session.peers.push(peer);
        Ok(peer)
    }
    /// SET_STATION before association updates the WMM/rate facts; once
    /// associated only authorization changes (mac80211 `sta_apply_parameters`
    /// refuses U-APSD changes for an associated AP client).
    pub(in crate::rtw89) fn update_peer(&mut self, config: &StationConfig) -> Result<Peer, Error> {
        Self::check_wme(config)?;
        if config.mfp == Some(true) {
            return Err(Error::Unsupported);
        }
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        let ghz5 = super::station::ghz5(session.plan.primary);
        let peer = session
            .peers
            .iter_mut()
            .find(|p| p.addr == config.mac)
            .ok_or(Error::Busy)?;
        if peer.aid == 0 {
            if let Some(wme) = config.wme {
                peer.wme = wme;
            }
            if let Some(queues) = config.uapsd_queues {
                peer.uapsd_queues = queues;
            }
            if let Some(sp) = config.uapsd_max_sp {
                peer.max_sp = sp;
            }
            if !config.supported_rates.is_empty() {
                peer.rates = legacy_rates(&config.supported_rates, ghz5);
            }
            if config.listen_interval != 0 {
                peer.listen_interval = config.listen_interval;
            }
        }
        if let Some(authorized) = config.authorized {
            if authorized && peer.aid == 0 && config.aid == 0 {
                return Err(Error::Invalid);
            }
            peer.authorized = authorized;
        }
        Ok(*peer)
    }
    /// `rtw89_core_sta_link_assoc` completed: the peer joins AP PS.
    pub(in crate::rtw89) fn associate(&mut self, addr: [u8; 6], aid: u16) -> Result<(), Error> {
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        if aid == 0 || session.peers.iter().any(|p| p.aid == aid && p.addr != addr) {
            return Err(Error::Invalid);
        }
        let peer = session
            .peers
            .iter_mut()
            .find(|p| p.addr == addr)
            .ok_or(Error::Busy)?;
        if peer.aid != 0 {
            return Err(Error::Invalid);
        }
        session.ps.add_peer(PeerConfig {
            aid,
            addr,
            wme: peer.wme,
            uapsd_queues: if peer.wme { peer.uapsd_queues } else { 0 },
            max_sp: peer.max_sp,
            listen_interval: peer.listen_interval.max(1),
        })?;
        peer.aid = aid;
        Ok(())
    }
    /// DEL_STATION: drop the peer, its pairwise key, PS buffers and TIM bit.
    pub(in crate::rtw89) fn remove_peer(&mut self, addr: [u8; 6]) -> Option<Peer> {
        let session = self.session.as_mut()?;
        let index = session.peers.iter().position(|p| p.addr == addr)?;
        let peer = session.peers.remove(index);
        if peer.aid != 0 && session.ps.remove_peer(peer.aid).unwrap_or(false) {
            session.beacon_dirty = true;
        }
        let _ = self.keys.remove(Target::Pairwise(addr));
        self.outbound
            .retain(|out| out.mpdu.get(4..10) != Some(&addr[..]));
        Some(peer)
    }
    pub(in crate::rtw89) fn install_key(&mut self, install: &Install) -> Result<(), Error> {
        let session = self.session.as_ref().ok_or(Error::Busy)?;
        if let Target::Pairwise(peer) = install.target {
            if !session.peers.iter().any(|p| p.addr == peer) {
                return Err(Error::Busy);
            }
        }
        self.keys
            .install(install.target, &install.tk, install.rsc)?;
        Ok(())
    }
    pub(in crate::rtw89) fn remove_key(&mut self, target: Target) -> Result<(), Error> {
        self.keys.remove(target)?;
        if let (Target::Group(id), Some(session)) = (target, self.session.as_mut()) {
            if session.default_group == Some(id) {
                session.default_group = None;
            }
        }
        Ok(())
    }
    pub(in crate::rtw89) fn default_group(&mut self, index: u8) -> Result<(), Error> {
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        if !self.keys.has_group(index) {
            return Err(Error::Busy);
        }
        session.default_group = Some(index);
        Ok(())
    }
    pub(in crate::rtw89) fn key_sequence(&self, target: Target) -> Result<[u8; 6], Error> {
        let pn = self.keys.transmit_pn(target)?;
        let mut seq = [0; 6];
        seq.copy_from_slice(&pn.to_le_bytes()[..6]);
        Ok(seq)
    }

    fn header(
        session: &mut Session,
        own: [u8; 6],
        da: [u8; 6],
        sa: [u8; 6],
        tid: Option<u8>,
    ) -> Vec<u8> {
        let mut header = Vec::with_capacity(26);
        header.extend_from_slice(&[if tid.is_some() { 0x88 } else { 0x08 }, 0x02, 0, 0]);
        header.extend_from_slice(&da);
        header.extend_from_slice(&own);
        header.extend_from_slice(&sa);
        header.extend_from_slice(&(session.sequence << 4).to_le_bytes());
        session.sequence = (session.sequence + 1) & 0x0fff;
        if let Some(tid) = tid {
            header.extend_from_slice(&[tid & 7, 0]);
        }
        header
    }
    /// Build one FromDS MPDU (`ieee80211_build_hdr` + `ccmp_encrypt_skb`).
    /// `encrypt` selects the pairwise key for unicast, the default GTK for
    /// group addresses; without privacy nothing is protected.
    fn build(
        &mut self,
        da: [u8; 6],
        sa: [u8; 6],
        ethertype: u16,
        payload: &[u8],
        encrypt: bool,
        tid: u8,
    ) -> Result<(Vec<u8>, Option<u16>), Error> {
        let own = self.own;
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        let group = da[0] & 1 != 0;
        let peer = if group {
            None
        } else {
            Some(
                session
                    .peers
                    .iter()
                    .find(|p| p.addr == da && p.aid != 0)
                    .copied()
                    .ok_or(Error::Busy)?,
            )
        };
        let qos = peer.is_some_and(|p| p.wme);
        let mut header = Self::header(session, own, da, sa, qos.then_some(tid));
        let mut body = Zeroizing::new(Vec::with_capacity(8 + payload.len()));
        body.extend_from_slice(&LLC);
        body.extend_from_slice(&ethertype.to_be_bytes());
        body.extend_from_slice(payload);
        let target = match (encrypt && session.plan.privacy, group) {
            (false, _) => None,
            (true, false) => Some(Target::Pairwise(da)),
            (true, true) => Some(Target::Group(session.default_group.ok_or(Error::Busy)?)),
        };
        let mut mpdu = header.clone();
        match target {
            Some(target) => {
                header[1] |= 0x40;
                let protected = self.keys.protect(own, target, &header, &body)?;
                mpdu[1] |= 0x40;
                mpdu.extend_from_slice(&protected);
            }
            None => mpdu.extend_from_slice(&body),
        }
        Ok((mpdu, peer.map(|p| p.aid)))
    }
    /// Hand one MPDU to AP PS (unicast) or the DTIM decision (group).
    fn queue(
        &mut self,
        mpdu: Vec<u8>,
        aid: Option<u16>,
        tid: u8,
        now_ms: u64,
    ) -> Result<(), Error> {
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        let fc = u16::from_le_bytes([mpdu[0], mpdu[1]]);
        let out = match aid {
            Some(aid) => match session.ps.transmit(aid, mpdu, tid, now_ms)? {
                Transmit::Send(mpdu) => Outbound {
                    mpdu,
                    after_dtim: false,
                    release: None,
                },
                Transmit::Buffered { tim_changed } => {
                    session.beacon_dirty |= tim_changed;
                    return Ok(());
                }
            },
            None => Outbound {
                after_dtim: ap_ps::group_after_dtim(&session.ps, fc),
                mpdu,
                release: None,
            },
        };
        if self.outbound.len() >= OUTBOUND {
            return Err(Error::Busy);
        }
        self.outbound.push_back(out);
        Ok(())
    }
    /// Ordinary netdev TX (the stack's own 802.3 frames). Unicast needs an
    /// authorized associated peer; group frames need one authorized peer.
    /// Control-port ethertypes never use this path.
    pub(in crate::rtw89) fn transmit_ethernet(
        &mut self,
        eth: &[u8],
        now_ms: u64,
    ) -> Result<(), Error> {
        let session = self.session.as_ref().ok_or(Error::Busy)?;
        if !(14..=1514).contains(&eth.len()) || eth[..6] == [0; 6] {
            return Err(Error::Invalid);
        }
        let da: [u8; 6] = eth[..6].try_into().map_err(|_| Error::Invalid)?;
        let sa: [u8; 6] = eth[6..12].try_into().map_err(|_| Error::Invalid)?;
        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        let preauth_on_netdev = session.settings.control_port.no_preauth;
        if ethertype < 0x600
            || ethertype == narf_wireless::ETH_P_PAE
            || ethertype == narf_wireless::ETH_P_PREAUTH && !preauth_on_netdev
        {
            return Err(Error::Invalid);
        }
        if da[0] & 1 != 0 {
            if !session.peers.iter().any(|p| p.authorized && p.aid != 0) {
                return Err(Error::Busy);
            }
        } else if !session
            .peers
            .iter()
            .any(|p| p.addr == da && p.authorized && p.aid != 0)
        {
            return Err(Error::Busy);
        }
        let tid = qos::classify(eth);
        let (mpdu, aid) = self.build(da, sa, ethertype, &eth[14..], true, tid)?;
        self.queue(mpdu, aid, tid, now_ms)
    }
    /// CONTROL_PORT_FRAME TX to one known peer (`ieee80211_tx_control_port`:
    /// encrypted with the pairwise key once installed unless `no_encrypt`).
    /// The caller submits it directly for its own TX status.
    pub(in crate::rtw89) fn control_frame(
        &mut self,
        dest: [u8; 6],
        ethertype: u16,
        pdu: &[u8],
        no_encrypt: bool,
    ) -> Result<Vec<u8>, Error> {
        let session = self.session.as_ref().ok_or(Error::Busy)?;
        if !matches!(
            ethertype,
            narf_wireless::ETH_P_PAE | narf_wireless::ETH_P_PREAUTH
        ) || pdu.is_empty()
            || pdu.len() > 2304
            || dest[0] & 1 != 0
            || !session.peers.iter().any(|p| p.addr == dest && p.aid != 0)
        {
            return Err(Error::Invalid);
        }
        let encrypt = !no_encrypt && self.keys.has_pair(dest);
        self.build(dest, self.own, ethertype, pdu, encrypt, 7)
            .map(|(mpdu, _)| mpdu)
    }
    /// NL80211_CMD_FRAME from the AP SME: own TA and BSSID; MFP is not in
    /// this profile, so a protected frame is refused.
    pub(in crate::rtw89) fn management_frame(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        let session = self.session.as_mut().ok_or(Error::Busy)?;
        if !(24..=2352).contains(&frame.len())
            || frame[0] & 0x0c != 0
            || frame[1] & !0x08 != 0
            || frame[10..16] != self.own
            || frame[16..22] != self.own
            // Beacons are firmware-template only.
            || frame[0] == 0x80
        {
            return Err(Error::Invalid);
        }
        let mut frame = frame.to_vec();
        frame[22..24].copy_from_slice(&(session.sequence << 4).to_le_bytes());
        session.sequence = (session.sequence + 1) & 0x0fff;
        Ok(frame)
    }

    pub(in crate::rtw89) fn next_outbound(&mut self) -> Option<&Outbound> {
        self.outbound.front()
    }
    pub(in crate::rtw89) fn consume_outbound(&mut self, id: u64) {
        if let Some(out) = self.outbound.pop_front() {
            if let Some(release) = out.release {
                self.reports.insert(id, (None, Some(release)));
            }
        }
    }
    /// The head frame was refused by the native owner (its peer binding is
    /// gone): drop it; a period-ending release still ends the period.
    pub(in crate::rtw89) fn drop_outbound(&mut self) {
        if let Some(Outbound {
            release: Some((aid, response)),
            ..
        }) = self.outbound.pop_front()
        {
            if let Some(session) = self.session.as_mut() {
                session.ps.tx_status(aid, &response);
            }
        }
    }
    /// Track a directly submitted frame's terminal report.
    pub(in crate::rtw89) fn watch_report(&mut self, id: u64) {
        self.reports.insert(id, (None, None));
    }
    pub(in crate::rtw89) fn take_report(&mut self, id: u64) -> Option<bool> {
        match self.reports.get(&id) {
            Some((Some(ack), _)) => {
                let ack = *ack;
                self.reports.remove(&id);
                Some(ack)
            }
            _ => None,
        }
    }
    pub(in crate::rtw89) fn forget_report(&mut self, id: u64) {
        self.reports.remove(&id);
    }
    /// RPQ terminal release (`rtw89_pci_tx_status`): an AP no-ack still
    /// ends a U-APSD / PS-Poll service period (status.c EOSP handling).
    pub(in crate::rtw89) fn report(&mut self, id: u64, acknowledged: bool) {
        let Some(entry) = self.reports.get_mut(&id) else {
            return;
        };
        if let (Some((aid, response)), Some(session)) = (entry.1.take(), self.session.as_mut()) {
            session.ps.tx_status(aid, &response);
            // Released frames have no waiter.
            self.reports.remove(&id);
            return;
        }
        entry.0 = Some(acknowledged);
    }
    /// `sta_info_cleanup_expire_buffered` on the service tick.
    pub(in crate::rtw89) fn expire(&mut self, now_ms: u64) {
        if let Some(session) = self.session.as_mut() {
            if !session.ps.expire(now_ms).is_empty() {
                session.beacon_dirty = true;
            }
        }
    }

    /// PS releases go out ahead of ordinary backlog, in source order.
    fn release(&mut self, aid: u16, responses: Vec<Response>) {
        let room = OUTBOUND.saturating_sub(self.outbound.len());
        for response in responses.into_iter().take(room).rev() {
            let release = response.ends_period.then(|| (aid, response.clone()));
            self.outbound.push_front(Outbound {
                mpdu: response.mpdu,
                after_dtim: false,
                release,
            });
        }
    }
    /// One received MPDU with the long-RXD `AX_RXD_MAC_ID` the address CAM
    /// assigned. Peer frames are accepted only when that MACID is the
    /// peer's own (the hardware classification and A2 agree).
    pub(in crate::rtw89) fn receive(
        &mut self,
        mac_id: Option<u8>,
        bytes: &[u8],
        now_ms: u64,
    ) -> Vec<Inbound> {
        let mut out = Vec::new();
        let own = self.own;
        let Some(session) = self.session.as_mut() else {
            return out;
        };
        if bytes.len() < 16 {
            return out;
        }
        let fc0 = bytes[0];
        let a2: [u8; 6] = match bytes.get(10..16) {
            Some(a2) => a2.try_into().unwrap_or([0; 6]),
            None => return out,
        };
        let peer = session
            .peers
            .iter()
            .find(|p| p.addr == a2)
            .copied()
            .filter(|p| mac_id == Some(p.macid));
        let associated = peer.filter(|p| p.aid != 0);
        // rx.c ieee80211_rx_h_uapsd_and_pspoll / sta_process PM transitions.
        if let Some(peer) = associated {
            let group = bytes[4] & 1 != 0;
            if let Ok(received) = session.ps.receive(peer.aid, bytes, group) {
                session.beacon_dirty |= received.tim_changed;
                let consumed = received.consumed;
                self.release(peer.aid, received.responses);
                if consumed {
                    return out;
                }
            }
        }
        match fc0 & 0x0c {
            0x00 if bytes.len() >= 24 => {
                // Unprotected management to us or broadcast (probe requests).
                let a1 = &bytes[4..10];
                if bytes[1] & 0x40 == 0 && (a1 == own || a1 == [0xff; 6]) {
                    out.push(Inbound::Management(bytes.to_vec()));
                }
            }
            0x08 if bytes.len() >= 24 => {
                let Some(peer) = associated else {
                    return out;
                };
                // ToDS only, no A4, not fragmented, to our BSSID.
                if bytes[1] & 0x03 != 0x01 || bytes[1] & 0x04 != 0 || bytes[4..10] != own {
                    return out;
                }
                // Null / QoS-Null carry only PM/U-APSD signalling.
                if fc0 & 0x40 != 0 {
                    return out;
                }
                let qos = fc0 & 0x80 != 0;
                let hdr = if qos { 26 } else { 24 };
                if bytes.len() < hdr || qos && bytes[24] & 0x80 != 0 {
                    return out; // A-MSDU is outside this profile.
                }
                let header = &bytes[..hdr];
                let protected = bytes[1] & 0x40 != 0;
                let body = if protected {
                    match self.keys.unprotect(own, peer.addr, header, &bytes[hdr..]) {
                        Ok(plain) => Zeroizing::new(plain),
                        Err(_) => return out,
                    }
                } else {
                    Zeroizing::new(bytes[hdr..].to_vec())
                };
                let Some(session) = self.session.as_ref() else {
                    return out;
                };
                if body.len() < 8 || body[..6] != LLC {
                    return out;
                }
                let ethertype = u16::from_be_bytes([body[6], body[7]]);
                let da: [u8; 6] = bytes[16..22].try_into().unwrap_or([0; 6]);
                let control = matches!(
                    ethertype,
                    narf_wireless::ETH_P_PAE | narf_wireless::ETH_P_PREAUTH
                );
                // ieee80211_drop_unencrypted: with privacy, only the control
                // port may arrive in the clear.
                if session.plan.privacy && !protected && !control {
                    return out;
                }
                let preauth_on_netdev = session.settings.control_port.no_preauth
                    && ethertype == narf_wireless::ETH_P_PREAUTH;
                if control && !preauth_on_netdev {
                    if ethertype == narf_wireless::ETH_P_PAE && da != own {
                        return out;
                    }
                    out.push(Inbound::Control {
                        peer: peer.addr,
                        ethertype,
                        pdu: Zeroizing::new(body[8..].to_vec()),
                        unencrypted: !protected,
                    });
                    return out;
                }
                if !peer.authorized {
                    return out;
                }
                let mut eth = Vec::with_capacity(6 + body.len());
                eth.extend_from_slice(&da);
                eth.extend_from_slice(&peer.addr);
                eth.extend_from_slice(&body[6..]);
                // ieee80211_deliver_skb: group frames go up and are
                // re-sent to the BSS; frames for another authorized peer
                // are forwarded only.
                let forward_to = session
                    .peers
                    .iter()
                    .any(|p| p.addr == da && p.authorized && p.aid != 0);
                if da[0] & 1 != 0 || forward_to {
                    let _ = self.transmit_ethernet(&eth, now_ms);
                }
                if !forward_to {
                    out.push(Inbound::Ethernet(eth));
                }
            }
            _ => {}
        }
        out
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "ap_host_tests.rs"]
mod tests;
