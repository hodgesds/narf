//! MT76 live station join and disassociate dispatch.
//! Channel/power authorization, MLME open authentication/association
//! request/response loops, and peer record installation.
use super::{
    scan::rx_on_channel, station::Command, Backend, Error, ScanBss, Session, Stage, State,
    TIMEOUT_MS,
};
use crate::mt7921::{
    association::{disconnect_record_on, JoinPlan, Security},
    cmd, packet_tx,
};
use alloc::{collections::VecDeque, vec, vec::Vec};
use narf_wireless::eapol::{EapolRx, EapolRxError, Gtk, RsnaParams, Supplicant};
use zeroize::{Zeroize, Zeroizing};

#[path = "wowlan_security.rs"]
mod wowlan;

/// Association-owned RSNA state. Key bytes are never included in driver
/// diagnostics. Keeping the same supplicant across RX permits PTK/GTK rekeys
/// and preserves its key-reinstallation and EAPOL replay checks.
pub(super) struct StationSecurity {
    supplicant: Supplicant,
    pub(super) port_open: bool,
    pub(super) pairwise: [u64; 17],
    group: [Option<[u64; 17]>; 4],
    pending: VecDeque<(Vec<u8>, bool)>,
    /// PMF negotiated (`JoinPlan::pmf()`): robust management frames are
    /// protected once the PTK is installed (mac80211 `sta->mfp`).
    pub(super) pmf: bool,
    /// The PTK is installed in WCID 1 (`ieee80211_drop_unencrypted_mgmt`
    /// requires `rx->sta->ptk_idx` / a pairwise key before it drops).
    ptk_installed: bool,
    /// Received unicast robust-management CCMP PN (mac80211 security_idx
    /// `IEEE80211_NUM_TIDS` for management frames).
    management_pn: u64,
    /// The installed IGTK for software BIP verification (mt76 hands BIP
    /// group management frames to mac80211 `ieee80211_crypto_aes_cmac_decrypt`).
    igtk: narf_wireless::mfp::MfpKeyStore,
    /// The last installed CCMP group key index, repeated as `key[0]` of
    /// the IGTK record (`sta_key_conf`).
    gtk_id: u8,
}

impl core::fmt::Debug for StationSecurity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StationSecurity").finish_non_exhaustive()
    }
}

impl StationSecurity {
    fn port_open(&self) -> bool {
        self.port_open && self.pending.is_empty()
    }
    pub(super) fn has_pending(&self) -> bool {
        !self.port_open()
    }
    pub(super) fn new(
        bss: &ScanBss,
        plan: &JoinPlan,
        own: [u8; 6],
        pmk: &[u8; 32],
    ) -> Result<Self, Error> {
        let body = plan.rsn_body().ok_or(Error::Bounds)?;
        let mut assoc_ie = vec![48, body.len() as u8];
        assoc_ie.extend_from_slice(&body);
        // SAE repeats its RSNXE (SAE-H2E) in message 2/4 (wpa_supplicant
        // `wpa_sm_set_assoc_rsnxe`).
        if let Some(rsnxe) = plan.sae().and_then(|sae| sae.station_rsnxe()) {
            assoc_ie.extend_from_slice(&[244, rsnxe.len() as u8]);
            assoc_ie.extend_from_slice(&rsnxe);
        }
        let key_mgmt = plan.akm().ok_or(Error::Bounds)?;
        let pmf = plan.pmf();
        let mut ies = &bss.information_elements[..];
        let mut ap_rsn_ie = None;
        let mut ap_rsnxe = None;
        while !ies.is_empty() {
            let header = ies.get(..2).ok_or(Error::Bounds)?;
            let ie = ies.get(..2 + usize::from(header[1])).ok_or(Error::Bounds)?;
            if header[0] == 48 {
                ap_rsn_ie = Some(ie.to_vec());
            }
            if header[0] == 244 {
                if ap_rsnxe.is_some() || ie.len() < 3 || usize::from(ie[2] & 15) + 3 != ie.len() {
                    return Err(Error::Bounds);
                }
                ap_rsnxe = Some(ie.to_vec());
            }
            ies = &ies[ie.len()..];
        }
        Ok(Self {
            port_open: false,
            supplicant: Supplicant::new(bss.bssid, own, [0; 32]).with_rsna(RsnaParams {
                key_mgmt,
                pmk: pmk.to_vec(),
                assoc_ie,
                ap_rsn_ie: ap_rsn_ie.ok_or(Error::Bounds)?,
                ap_rsnxe,
                pairwise_key_len: 16,
                group_key_len: 16,
                mgmt_group_key_len: pmf.then_some(16),
                pmf,
            }),
            pairwise: [0; 17],
            group: [None; 4],
            pending: VecDeque::new(),
            pmf,
            ptk_installed: false,
            management_pn: 0,
            igtk: narf_wireless::mfp::MfpKeyStore::new(),
            gtk_id: 0,
        })
    }

    fn process(
        &mut self,
        pdu: &[u8],
        encrypted: bool,
        mut fill: impl FnMut(&mut [u8]) -> Result<(), Error>,
    ) -> Result<Option<EapolRx>, Error> {
        let mut failure = None;
        let result = self.supplicant.rx_eapol_with_nonce(pdu, encrypted, || {
            let mut fresh = Zeroizing::new([0; 32]);
            match fill(&mut fresh[..]) {
                Ok(()) => Some(*fresh),
                Err(error) => {
                    failure = Some(error);
                    None
                }
            }
        });
        match result {
            Ok(rx) => {
                // Every accepted handshake step owns the closed port until
                // its real reply/key receipts explicitly authorize it below.
                self.port_open = false;
                Ok(Some(rx))
            }
            Err(EapolRxError::Drop(_)) => Ok(None),
            Err(EapolRxError::NonceUnavailable) => {
                Err(failure.unwrap_or(Error::EntropyUnavailable))
            }
            Err(_) => Err(Error::MalformedEvent),
        }
    }

    pub(super) fn commit_group(&mut self, gtk: &Gtk) -> Result<(), Error> {
        if gtk.key_id > 3 || gtk.key.len() != 16 || gtk.rsc[6..] != [0, 0] {
            return Err(Error::MalformedEvent);
        }
        self.group[usize::from(gtk.key_id)] = Some([u64::from_le_bytes(gtk.rsc); 17]);
        self.gtk_id = gtk.key_id;
        self.supplicant.group_keys_installed(Some(&gtk.key), None);
        Ok(())
    }

    /// The firmware accepted the PTK record: WCID 1 now protects robust
    /// management frames under PMF. A new PTK restarts the management PN.
    pub(super) fn commit_pairwise(&mut self) {
        self.supplicant.pairwise_key_installed();
        self.pairwise.fill(0);
        self.management_pn = 0;
        self.ptk_installed = true;
    }

    /// The firmware accepted the IGTK record. The KDE IPN is the AP's last
    /// IPN; mac80211 seeds the BIP replay counter with it.
    pub(super) fn commit_igtk(&mut self, igtk: &narf_wireless::eapol::Igtk) -> Result<(), Error> {
        let key: [u8; 16] = igtk
            .key
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedEvent)?;
        self.igtk
            .install_active(key, igtk.key_id)
            .map_err(|_| Error::MalformedEvent)?;
        let mut ipn = [0; 8];
        ipn[..6].copy_from_slice(&igtk.ipn);
        if let Some(active) = self.igtk.active.as_mut() {
            active.rx_pn = u64::from_le_bytes(ipn);
        }
        self.supplicant.group_keys_installed(None, Some(&igtk.key));
        Ok(())
    }

    /// The installed GTK, for the IGTK record's BIP batch `key[0]`.
    pub(super) fn gtk(&self) -> Option<(u8, &[u8])> {
        self.supplicant
            .gtk
            .as_deref()
            .filter(|gtk| gtk.len() == 16)
            .map(|gtk| (self.gtk_id, gtk))
    }

    /// Robust management frames are CCMP/BIP protected (mac80211
    /// `ieee80211_use_mfp` + an installed pairwise key).
    pub(super) fn protects_management(&self) -> bool {
        self.pmf && self.ptk_installed
    }

    /// mac80211 `ieee80211_drop_unencrypted_mgmt` and the CCMP/BIP
    /// management receive paths, for one native management MPDU from the
    /// AP. `None` drops the frame; `Some` is the admitted MPDU with the
    /// Protected bit cleared and any MMIE removed. Non-robust frames and
    /// frames before the PTK pass unchanged (protected ones are dropped).
    pub(super) fn admit_management(
        &mut self,
        frame: &[u8],
        ccmp: Option<super::scan::CcmpRx>,
    ) -> Option<Vec<u8>> {
        let protected = frame.get(1).is_some_and(|fc| fc & 0x40 != 0);
        if !self.protects_management() || !robust_management(frame) {
            return (!protected && ccmp.is_none()).then(|| frame.to_vec());
        }
        if frame[4] & 1 != 0 {
            // Group-addressed robust frames are never CCMP protected; BIP
            // (MMIE) under the installed IGTK (ieee80211_crypto_aes_cmac_decrypt).
            if protected || ccmp.is_some() {
                return None;
            }
            let body =
                narf_wireless::mfp::verify_inbound(&mut self.igtk, &frame[..24], &frame[24..])
                    .ok()?;
            let mut out = frame[..24].to_vec();
            out.extend_from_slice(body);
            return Some(out);
        }
        // Unicast: hardware-decrypted under the pairwise key only, with a
        // strictly increasing management PN (ieee80211_crypto_ccmp_decrypt).
        let ccmp = ccmp?;
        if !protected || ccmp.key_id != 0 || ccmp.pn <= self.management_pn {
            return None;
        }
        self.management_pn = ccmp.pn;
        let mut out = frame.to_vec();
        out[1] &= !0x40;
        Some(out)
    }
}

impl Drop for StationSecurity {
    fn drop(&mut self) {
        // Supplicant owns the only PMK/PTK/GTK copies retained by this driver.
        if let Some(params) = &mut self.supplicant.rsna {
            params.pmk.zeroize();
        }
        for ptk in [&mut self.supplicant.ptk, &mut self.supplicant.tptk]
            .into_iter()
            .flatten()
        {
            ptk.kck.zeroize();
            ptk.kek.zeroize();
            ptk.tk.zeroize();
        }
        for key in [&mut self.supplicant.gtk, &mut self.supplicant.igtk]
            .into_iter()
            .flatten()
        {
            key.zeroize();
        }
        for igtk in [&mut self.igtk.active, &mut self.igtk.next]
            .into_iter()
            .flatten()
        {
            igtk.key.zeroize();
        }
    }
}

/// Linux v7.2 include/linux/ieee80211.h `_ieee80211_is_robust_mgmt_frame`:
/// Deauthentication, Disassociation and Action frames outside the
/// non-robust categories (Public 4, HT 7, Unprotected WNM 11,
/// Self-Protected 15, Unprotected DMG 20, VHT 21, Unprotected S1G 22,
/// Vendor-specific 127); a protected Action frame is always robust.
pub(crate) fn robust_management(frame: &[u8]) -> bool {
    if frame.len() < 24 || frame[0] & 0x0c != 0 {
        return false;
    }
    match frame[0] {
        0xa0 | 0xc0 => true,
        0xd0 => {
            frame[1] & 0x40 != 0
                || frame
                    .get(24)
                    .is_some_and(|c| !matches!(*c, 4 | 7 | 11 | 15 | 20 | 21 | 22 | 127))
        }
        _ => false,
    }
}

/// mac80211 rx.c `ieee80211_process_sa_query_req`: a station answers an
/// admitted SA Query Request (category 8, action 0) from its BSSID that is
/// addressed to it with an SA Query Response carrying the same transaction
/// identifier, DA = SA of the request and BSSID = the AP. `ieee80211_rx_h_action`
/// requires `IEEE80211_MIN_ACTION_SIZE + sizeof(sa_query)` (28) octets.
pub(crate) fn sa_query_response(frame: &[u8], own: [u8; 6], peer: [u8; 6]) -> Option<Vec<u8>> {
    if frame.len() < 28
        || frame[0] != 0xd0
        || frame[1] & 0x40 != 0
        || frame[4..10] != own
        || frame[10..16] != peer
        || frame[16..22] != peer
        || frame[24..26] != [8, 0]
    {
        return None;
    }
    let mut response = vec![0; 28];
    response[0] = 0xd0;
    response[4..10].copy_from_slice(&peer);
    response[10..16].copy_from_slice(&own);
    response[16..22].copy_from_slice(&peer);
    response[24..26].copy_from_slice(&[8, 1]);
    response[26..28].copy_from_slice(&frame[26..28]);
    Some(response)
}

pub(crate) fn extract_eapol(frame: &[u8]) -> Option<&[u8]> {
    extract_native_eapol(frame, false)
}
fn extract_native_eapol(frame: &[u8], decrypted: bool) -> Option<&[u8]> {
    let header = frame.get(..24)?;
    // Only validated native decrypt metadata can describe an IV/MIC-stripped
    // protected EAPOL body. This check leaves the original header untouched.
    let fc =
        u16::from_le_bytes([header[0], header[1]]) & if decrypted { !0x4000 } else { u16::MAX };
    if !matches!(fc & 0xff, 0x08 | 0x88)
        || !matches!(fc & 0xc700, 0x0100 | 0x0200)
        || header[22] & 15 != 0
    {
        return None;
    }
    let snap_offset = if fc & 0x80 != 0 {
        if frame.get(24)? & 0x80 != 0 {
            return None;
        }
        26
    } else {
        24
    };
    if frame.get(snap_offset..snap_offset + 8)? != [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e] {
        return None;
    }
    let pdu = frame.get(snap_offset + 8..)?;
    let eapol = pdu.get(..4)?;
    if !(1..=3).contains(&eapol[0]) || eapol[1] != 3 {
        return None;
    }
    pdu.get(..4 + usize::from(u16::from_be_bytes([eapol[2], eapol[3]])))
}

/// An authenticator EAPOL PDU must come from the negotiated AP to this
/// station, in a validated native FromDS MPDU. Ethernet/descriptor fallbacks
/// cannot establish peer identity for the controlled port.
pub(super) fn peer_eapol(packet: &[u8], own: [u8; 6], peer: [u8; 6], channel: u8) -> Option<&[u8]> {
    let frame = rx_on_channel(packet, channel)?;
    let header = frame.get(..24)?;
    if header[1] & 3 != 2
        || header[4..10] != own
        || header[10..16] != peer
        || header[16..22] != peer
    {
        return None;
    }
    extract_eapol(frame)
}

pub(crate) fn wrap_eapol_frame(own: [u8; 6], peer: [u8; 6], eapol: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24 + 8 + eapol.len());
    frame.extend_from_slice(&[0x08, 0x01]); // 802.11 Data to-DS
    frame.extend_from_slice(&[0x00, 0x00]); // duration
    frame.extend_from_slice(&peer); // Addr1: BSSID
    frame.extend_from_slice(&own); // Addr2: SA
    frame.extend_from_slice(&peer); // Addr3: DA
    frame.extend_from_slice(&[0x00, 0x00]); // seq ctrl
    frame.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]); // LLC/SNAP EAPOL
    frame.extend_from_slice(eapol);
    frame
}

/// RFC1042 LLC/SNAP header (`rfc1042_header`, IEEE 802.1H selective translation).
const RFC1042: [u8; 6] = [0xaa, 0xaa, 3, 0, 0, 0];
/// IEEE 802.1H bridge-tunnel LLC/SNAP header (`bridge_tunnel_header`).
const BRIDGE_TUNNEL: [u8; 6] = [0xaa, 0xaa, 3, 0, 0, 0xf8];
/// Largest 802.3 length-framed MSDU (`ETH_DATA_LEN`). Values 1501..1535 are
/// neither lengths nor EtherTypes, so a longer LLC body cannot be framed.
const MAX_LLC_BODY: usize = 1500;

/// Linux `ieee80211_get_8023_tunnel_proto`: RFC1042 (except AARP/IPX, which
/// 802.1H keeps LLC-encapsulated) or bridge-tunnel SNAP yields its EtherType.
fn tunnel_protocol(body: &[u8]) -> Option<[u8; 2]> {
    let snap = body.get(..8)?;
    let protocol = [snap[6], snap[7]];
    let rfc1042 = snap[..6] == RFC1042 && !matches!(u16::from_be_bytes(protocol), 0x80f3 | 0x8137);
    // A tunnelled value below 0x0600 would be an 802.3 length, not an
    // EtherType; keep such bodies LLC-encapsulated rather than misframing.
    (rfc1042 || snap[..6] == BRIDGE_TUNNEL)
        .then_some(protocol)
        .filter(|protocol| u16::from_be_bytes(*protocol) >= 0x0600)
}

/// Convert an unfragmented native station RX frame to an Ethernet/802.3 frame,
/// following Linux `ieee80211_data_to_8023_exthdr` for a non-A-MSDU, non-mesh
/// station: RFC1042/bridge-tunnel SNAP is replaced by its EtherType, while any
/// other LLC body (AARP/IPX SNAP, STP/NetBIOS LLC, other OUIs) is delivered as an
/// 802.3 length-framed MSDU with its LLC header intact.
/// The retained transport disables RX header translation. Rejected native
/// frames must never be reinterpreted as an already translated Ethernet frame.
pub fn to_ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    let header = frame.get(..24)?;
    let fc = u16::from_le_bytes([header[0], header[1]]);
    if !matches!(fc & 0xff, 0x08 | 0x88)
        || fc & 0xc700 != 0x0200 // FromDS only; no fragments, protection or HT control.
        || header[22] & 15 != 0
    {
        return None;
    }
    let body_offset = if fc & 0x80 != 0 {
        let qos = frame.get(24..26)?;
        if qos[0] & 0x80 != 0 {
            return None; // A-MSDU needs its own bounded deaggregation path.
        }
        26
    } else {
        24
    };
    let body = &frame[body_offset..];
    let (type_or_length, payload) = match tunnel_protocol(body) {
        Some(protocol) => (protocol, &body[8..]),
        // An 802.3 MSDU carries at least the 802.2 DSAP/SSAP/control header.
        None if body.len() >= 3 => (u16::try_from(body.len()).ok()?.to_be_bytes(), body),
        None => return None,
    };
    if payload.len() > MAX_LLC_BODY {
        return None;
    }
    let mut eth = Vec::with_capacity(14 + payload.len());
    eth.extend_from_slice(&header[4..10]);
    eth.extend_from_slice(&header[16..22]);
    eth.extend_from_slice(&type_or_length);
    eth.extend_from_slice(payload);
    Some(eth)
}

impl<B: Backend> Session<B> {
    pub(super) fn renew_receive_epoch(&mut self) -> Result<(), Error> {
        // A GO fence leaves the home station owner untouched.
        if self.go_role() {
            return self.renew_go_receive_epoch();
        }
        self.cancel_transmit_ba_restart();
        // No partial MSDU survives a key or association change.
        self.station.rx_fragments.clear();
        self.backend.close_receive_capture(0);
        self.receive_epoch = 0;
        self.receive_epoch = super::NEXT_RECEIVE_EPOCH
            .fetch_update(
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
                |epoch| epoch.checked_add(1),
            )
            .map_err(|_| Error::Bounds)?;
        self.station.epoch = self.receive_epoch;
        // A fence of this owner is not a fence of the other station owner:
        // the shared capture stays open while that owner is current, and
        // this owner moves its floor again before it next admits a copy.
        self.close_own_receive_capture();
        Ok(())
    }
    /// Close this owner's copy-time port. The shared capture stays open
    /// while the other station owner is current (its copies keep their
    /// copy-time port) and this owner is marked fenced instead
    /// (`sync_receive_capture`). Without a group owner: a plain close.
    pub(super) fn close_own_receive_capture(&mut self) {
        self.backend.close_receive_capture(self.receive_epoch);
        if self.other_receive_current().unwrap_or(false)
            && self
                .backend
                .open_receive_capture(self.receive_epoch)
                .is_ok()
        {
            self.station.fenced = true;
        }
    }
    /// Open the shared capture while either station owner is current.
    /// A copy's `port_open` is copy-time state of the shared capture, so an
    /// owner that was not current while the capture stayed open for the
    /// other owner is marked fenced, and on becoming current it renews the
    /// epoch (its floor) before admitting anything: no copy captured while
    /// its own port was closed can reach it. Single-owner sessions never
    /// open the capture for a non-current owner, so nothing changes there.
    pub(super) fn sync_receive_capture(&mut self) -> Result<bool, Error> {
        let mut own = self.receive_current(self.receive_epoch)?;
        if own && self.station.fenced {
            self.renew_receive_epoch()?;
            self.station.fenced = false;
            own = self.receive_current(self.receive_epoch)?;
        }
        let other = self.other_receive_current()?;
        if own || other {
            self.backend.open_receive_capture(self.receive_epoch)?;
            if !own {
                self.station.fenced = true;
            }
            if !other {
                if let Some(group) = self.group.as_mut() {
                    group.station.fenced = true;
                }
            }
            Ok(true)
        } else {
            self.backend.close_receive_capture(self.receive_epoch);
            Ok(false)
        }
    }
    pub(super) fn receive_current(&self, epoch: u64) -> Result<bool, Error> {
        self.owner_receive_current(&self.station, &self.state, epoch)
    }
    /// The swapped-out station owner (the group link, or the home link
    /// while a group operation runs) under the same shared capture epoch.
    pub(super) fn other_receive_current(&self) -> Result<bool, Error> {
        let group = match self.group.as_ref() {
            Some(other) => {
                self.owner_receive_current(&other.station, &other.state, self.receive_epoch)?
            }
            None => false,
        };
        // A live concurrent GO keeps the shared capture open too.
        Ok(group || self.go_receive_current(self.receive_epoch)?)
    }
    pub(super) fn owner_receive_current(
        &self,
        station: &super::StationLink,
        state: &State,
        epoch: u64,
    ) -> Result<bool, Error> {
        if !self.epoch_admits(station, epoch)
            || station.peer_lost
            || !matches!(state, State::Associated { .. })
            || station
                .security
                .as_ref()
                .is_some_and(|security| !security.port_open())
        {
            return Ok(false);
        }
        self.backend.check()?;
        let Some(permission) = station.permission else {
            return Ok(false);
        };
        self.backend.check_tx_permission(permission)?;
        Ok(true)
    }
    pub(super) fn publish_receive(
        &self,
        epoch: u64,
        publish: impl FnOnce(),
    ) -> Result<bool, Error> {
        if !self.receive_current(epoch)? {
            return Ok(false);
        }
        publish();
        Ok(true)
    }
    pub(super) fn prepare_ht20_receive(
        &mut self,
        bss: &ScanBss,
    ) -> Result<super::Ht20ReceiveInfo, Error> {
        let info = match self.state {
            State::RadioReady(info) | State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        self.backend.check()?;
        let receiver = super::amsdu::Receiver::prepare(info, bss)?;
        let info = receiver.info();
        self.station.ht20_rx = Some(receiver);
        self.station.received_msdu.clear();
        Ok(info)
    }

    pub(super) fn clear_aggregate_receive(&mut self) {
        if let Some(receiver) = &mut self.station.ht20_rx {
            receiver.clear();
        }
        self.station.received_msdu.clear();
        self.station.rx_fragments.clear();
    }

    /// Linux `ieee80211_rx_h_defragment` for the native station path. Each
    /// hardware-decrypted fragment must beat the current per-queue replay
    /// counter, and continuations must carry PN `last + 1`; only a complete
    /// MSDU advances the counter (to the last fragment's PN). Fragments
    /// bypass the BA reorder buffer, as in `ieee80211_rx_reorder_ampdu`.
    /// The controlled port never accepts a fragmented EAPOL PDU.
    fn receive_fragment(&mut self, native: &super::scan::NativeRx<'_>) -> Option<Vec<u8>> {
        let frame = native.frame;
        let header = frame.get(..24)?;
        let fragmented = header[1] & 0x04 != 0 || header[22] & 15 != 0;
        // Fragments are never A-MPDU subframes, and the RXD FRAG marker must
        // agree with the MAC header before any PN is trusted.
        if native.ampdu || native.amsdu != 0 || native.fragment != fragmented {
            return None;
        }
        let pn = match (native.ccmp, self.station.security.as_ref()) {
            (Some(ccmp), Some(_)) if ccmp.key_id == 0 => Some(ccmp.pn),
            (None, None) => None,
            _ => return None,
        };
        let (fragment, _) = super::fragment::Cache::parse(frame, pn)?;
        if let (Some(pn), Some(security)) = (pn, self.station.security.as_ref()) {
            if pn <= security.pairwise[fragment.queue] {
                return None;
            }
        }
        let complete = self
            .station
            .rx_fragments
            .insert(frame, pn, self.backend.now_ns())?;
        let ethernet = to_ethernet(&complete.frame)?;
        if ethernet[12..14] == [0x88, 0x8e] {
            return None;
        }
        if let (Some(security), Some((_, last))) = (self.station.security.as_mut(), complete.pn) {
            security.pairwise[complete.queue] = last;
        }
        Some(ethernet)
    }

    fn receive_aggregate(
        &mut self,
        native: &super::scan::NativeRx<'_>,
        own: [u8; 6],
        peer: [u8; 6],
        channel: u8,
    ) -> Option<Vec<u8>> {
        let receiver = self.station.ht20_rx.as_mut()?;
        if !receiver.matches(own, peer, channel) {
            receiver.clear();
            return None;
        }
        let Some(qos) = native.frame.get(24) else {
            receiver.clear();
            return None;
        };
        let tid = usize::from(*qos & 15);
        if native.ampdu && !self.station.rx_ba.amsdu(tid as u8) {
            receiver.clear();
            return None;
        }
        if self.station.rx_ba.owns(tid as u8)
            && (!self.station.rx_ba.active(tid as u8)
                || native.wcid != u16::from(self.station.link.peer())
                || usize::from(native.tid) != tid)
        {
            receiver.clear();
            return None;
        }
        let floor = self
            .station
            .security
            .as_ref()
            .map(|security| security.pairwise[tid]);
        let complete = receiver.observe_with_ba(
            native,
            floor,
            self.backend.now_ns(),
            self.station.rx_ba.active(tid as u8),
        )?;
        if self.station.rx_ba.active(tid as u8) {
            let sequence = u16::from_le_bytes([native.frame[22], native.frame[23]]) >> 4;
            self.station.rx_ba.insert(
                tid as u8,
                super::ba::Packet::new(
                    sequence,
                    complete.replay.map(|r| r.pn),
                    complete.frames,
                    None,
                ),
                self.backend.now_ns(),
            );
            return self.receive_ba_ready();
        }
        // Only a complete, checked MPDU can consume its PN, and only once
        // for all hardware-deaggregated MSDUs sharing that PN.
        if let Some(replay) = complete.replay {
            self.station.security.as_mut()?.pairwise[replay.tid] = replay.pn;
        }
        self.station.received_msdu = complete.frames;
        self.station.received_msdu.pop_front()
    }

    fn receive_ba_ready(&mut self) -> Option<Vec<u8>> {
        // Replay validation follows sequence reordering, as mt76_rx_complete
        // calls mt76_check_ccmp_pn only after mt76_rx_aggr_reorder.
        for _ in 0..32 {
            let Some((tid, mut packet)) = self.station.rx_ba.pop() else {
                break;
            };
            // A queued ordinary packet cannot consume a PN or leave the
            // controlled port after an earlier ordered EAPOL closes it.
            if packet.eapol.is_none()
                && self
                    .station
                    .security
                    .as_ref()
                    .is_some_and(|security| !security.port_open())
            {
                continue;
            }
            match (self.station.security.as_mut(), packet.pn) {
                (Some(security), Some(pn)) if pn > security.pairwise[usize::from(tid)] => {
                    security.pairwise[usize::from(tid)] = pn
                }
                (None, None) => {}
                (Some(_), None) if packet.eapol.is_some() => {}
                _ => continue,
            }
            if let Some(pdu) = packet.eapol.take() {
                if let Some(security) = &mut self.station.security {
                    if security.pending.len() < 16 {
                        security.pending.push_back((pdu, packet.pn.is_some()));
                        self.close_own_receive_capture();
                    }
                }
                continue;
            }
            self.station.received_msdu = packet.frames;
            if let Some(frame) = self.station.received_msdu.pop_front() {
                return Some(frame);
            }
        }
        None
    }

    pub(super) fn keys_pending(&self) -> bool {
        self.owner_keys_pending(&self.station, &self.state)
    }
    /// Key/WMM/BA control work of one station owner (the current one, or
    /// the swapped-out group owner for `group_keys_pending`).
    pub(super) fn owner_keys_pending(&self, station: &super::StationLink, state: &State) -> bool {
        !station.peer_lost
            && !self.p2p_rf_busy()
            && matches!(state, State::Associated { .. })
            && self.data_pending.is_empty()
            && (station.wmm_pending.is_some()
                || self.policy_changed(station)
                || station.ps_wanted != station.ps_applied
                || !station.control_pending.is_empty()
                || station.rx_ba.pending(self.backend.now_ns())
                || station.tx_ba.pending(self.backend.now_ns())
                || station
                    .tx_restart
                    .is_some_and(|request| request.waiting_receipt())
                || station
                    .security
                    .as_ref()
                    .is_some_and(|security| !security.pending.is_empty()))
    }
    async fn install_group_key(&mut self, gtk: &Gtk) -> Result<(), Error> {
        if gtk.rsc[6..] != [0, 0] {
            return Err(Error::MalformedEvent);
        }
        let record = crate::mt7921::association::key_record_on(
            self.station.link,
            self.station.link.bmc(),
            gtk.key_id,
            Some(&gtk.key),
        )
        .map_err(|_| Error::MalformedEvent)?;
        self.exchange_station(Command::Unified { id: 3 }, &record)
            .await
            .map(|_| ())
    }

    /// mt7921_set_key(WLAN_CIPHER_SUITE_AES_CMAC) after the GTK: the IGTK
    /// record repeats the installed GTK as its BIP batch `key[0]`.
    async fn install_igtk(
        &mut self,
        security: &StationSecurity,
        igtk: &narf_wireless::eapol::Igtk,
    ) -> Result<(), Error> {
        let (gtk_id, gtk) = security.gtk().ok_or(Error::MalformedEvent)?;
        let record =
            crate::mt7921::association::igtk_record_on(self.station.link, gtk_id, gtk, &igtk.key)
                .map_err(|_| Error::MalformedEvent)?;
        self.exchange_station(Command::Unified { id: 3 }, &record)
            .await
            .map(|_| ())
    }

    /// Service authenticated PTK/GTK rekeys captured by the bounded RX step.
    /// The supplicant only reports a key when it differs from the installed
    /// one, so retransmissions cannot reset packet-number replay windows.
    pub(super) async fn service_keys(&mut self) -> Result<(), Error> {
        if self.p2p_rf_busy() {
            return Ok(());
        }
        let associated = self.state;
        self.service_keys_in(associated, associated).await
    }
    /// A scanning caller retains Running across every nested control/key
    /// await. The associated context is local input, never public state.
    pub(super) async fn service_keys_during_scan(
        &mut self,
        associated: State,
    ) -> Result<(), Error> {
        self.service_keys_in(associated, State::Running(Stage::ScanWait))
            .await
    }
    pub(super) async fn service_keys_during_wow(&mut self, associated: State) -> Result<(), Error> {
        self.service_keys_in(associated, State::Running(Stage::WowSuspend))
            .await
    }
    async fn service_keys_in(&mut self, associated: State, restore: State) -> Result<(), Error> {
        self.service_transmit_ba_restart(associated, restore)
            .await?;
        self.service_control_in(associated, restore).await?;
        let State::Associated { info, peer, .. } = associated else {
            return Ok(());
        };
        if !self.data_pending.is_empty() {
            return Ok(());
        }
        if self
            .station
            .security
            .as_ref()
            .is_none_or(|security| security.pending.is_empty())
        {
            return Ok(());
        }
        // A cancelled key operation cannot leave an authorized session with
        // its RSNA owner missing. The pending/running state survives cancellation.
        self.renew_receive_epoch()?;
        self.stage(Stage::EapolHandshake);
        self.clear_aggregate_receive();
        let Some(mut security) = self.station.security.take() else {
            return Ok(());
        };
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.retire_transmit_ba(true).await?;
            self.retire_receive_ba(peer).await?;
            for _ in 0..4 {
                let Some((pdu, protected)) = security.pending.pop_front() else {
                    break;
                };
                let Some(result) =
                    security.process(&pdu, protected, |out| self.backend.random_bytes(out))?
                else {
                    continue;
                };
                let (reply, tk, gtk, igtk, authorize) = match result {
                    EapolRx::Pairwise1(m1) => (m1.reply, None, None, None, false),
                    EapolRx::Pairwise3(m3) => {
                        if !m3.secure {
                            return Err(Error::MalformedEvent);
                        }
                        (m3.reply, m3.tk, m3.gtk, m3.igtk, true)
                    }
                    // An invalid IGTK KDE is "Failed to configure IGTK" and
                    // not fatal in wpa_supplicant; the old IGTK stays.
                    EapolRx::Group1(group) => (
                        group.reply,
                        None,
                        group.gtk,
                        group.igtk.and_then(|igtk| igtk.ok().flatten()),
                        true,
                    ),
                };
                self.send_management(
                    &wrap_eapol_frame(info.capabilities.mac, peer, &reply),
                    u16::from(self.station.link.peer()),
                )
                .await?;
                if let Some(tk) = tk {
                    let record = crate::mt7921::association::key_record_on(
                        self.station.link,
                        self.station.link.peer(),
                        0,
                        Some(&tk),
                    )
                    .map_err(|_| Error::MalformedEvent)?;
                    self.exchange_station(Command::Unified { id: 3 }, &record)
                        .await?;
                    security.commit_pairwise();
                }
                if let Some(gtk) = gtk {
                    self.install_group_key(&gtk).await?;
                    security.commit_group(&gtk)?;
                }
                if let Some(igtk) = igtk.filter(|_| security.pmf) {
                    self.install_igtk(&security, &igtk).await?;
                    security.commit_igtk(&igtk)?;
                }
                security.port_open = authorize;
            }
            self.check_station_tx()?;
            Ok(())
        }
        .await;
        self.boot_started = None;
        if let Err(error) = result {
            self.station.wmm = None;
            self.station.wmm_pending = None;
            self.station.permission = None;
            self.station.ht20_rx = None;
            self.station.ht20_profile = None;
            self.station.vht_profile = None;
            self.station.he_profile = None;
            self.station.ap_phy = None;
            self.station.rx_ba.fence();
            self.station.tx_ba.fence();
            self.state = State::Failed {
                stage: Stage::EapolHandshake,
                error,
            };
            return Err(error);
        }
        self.station.security = Some(security);
        self.state = restore;
        if let Err(error) = self.sync_receive_capture() {
            return Err(self.fail_data(error));
        }
        Ok(())
    }

    /// Receive only validated native data from this station's associated AP.
    /// A rejected RX descriptor is discarded with its payload; it is never
    /// returned as a raw Ethernet frame. The budget also bounds malformed bursts.
    pub(super) fn receive_ethernet(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.station.peer_lost {
            self.station.rx_ba.fence();
            self.station.tx_ba.fence();
            self.clear_aggregate_receive();
            return Err(Error::DeviceGone);
        }
        let (own, peer, channel) = match self.state {
            State::Associated {
                info,
                peer,
                channel,
                ..
            } => (info.capabilities.mac, peer, channel),
            _ => return Err(Error::Busy),
        };
        self.backend.check()?;
        if !self.sync_receive_capture()? {
            self.clear_aggregate_receive();
        }
        if self.station.rx_ba.tick(self.backend.now_ns()) {
            self.clear_aggregate_receive();
        }
        if let Some(frame) = self.station.received_msdu.pop_front() {
            return Ok(Some(frame));
        }
        if let Some(frame) = self.receive_ba_ready() {
            return Ok(Some(frame));
        }
        for _ in 0..16 {
            self.backend.check()?;
            let packet = if let Some(packet) = self.station.demuxed.pop_front() {
                Some(packet)
            } else if let Some(packet) = self.scan_packets.pop_front() {
                Some(packet)
            } else if self.scanning {
                None
            } else {
                self.backend.receive_data_captured()?
            };
            let Some(packet) = packet else {
                return Ok(None);
            };
            // The other station owner's copy (peer WCID or BSS): hand the
            // original to that link before this owner's epoch/channel
            // gates (Linux `mt792x_rx_get_wcid` -> its `mt792x_sta`); that
            // owner applies its own gates when it drains the queue.
            if self.group.is_some() || self.go.is_some() {
                let (group, go) = super::scan::rx_native_with_amsdu(&packet.bytes)
                    .map_or((false, false), |native| {
                        (self.other_owns_rx(&native), self.go_owns_rx(&native))
                    });
                if group {
                    self.forward_to_other(packet);
                    continue;
                }
                // The concurrent GO's copy (a GO peer WCID, the GO address
                // or a broadcast probe request): queued for the GO step.
                if go {
                    self.forward_to_go(packet);
                    continue;
                }
            }
            if !self.epoch_admits(&self.station, packet.epoch) {
                self.clear_aggregate_receive();
                continue;
            }
            let Some(native) = super::scan::rx_native_with_amsdu(&packet.bytes) else {
                self.clear_aggregate_receive();
                continue;
            };
            if native.channel != channel {
                self.clear_aggregate_receive();
                continue;
            }
            // GET_STATION: every frame the AP sent on the operating channel
            // contributes its signal; data frames also their rate.
            if native.frame.get(10..16) == Some(&peer[..]) {
                let data = native.frame.first().is_some_and(|fc| fc & 0x0c == 0x08);
                let beacon = native.frame.first() == Some(&0x80);
                self.station
                    .link_stats
                    .observe(native.rcpi, native.phy, data, beacon);
            }
            // PMF management admission before any MLME/BA consumer: mac80211
            // `ieee80211_drop_unencrypted_mgmt` plus the CCMP (hardware) and
            // BIP (software, `ieee80211_crypto_aes_cmac_decrypt`) management
            // receive paths. Admitted frames continue as plain MPDUs.
            let admitted;
            let native = match self.station.security.as_mut() {
                Some(security)
                    if security.protects_management()
                        && native.frame.first().is_some_and(|fc| fc & 0x0c == 0)
                        && native.frame.get(10..16) == Some(&peer[..]) =>
                {
                    let Some(frame) = security.admit_management(native.frame, native.ccmp) else {
                        self.clear_aggregate_receive();
                        continue;
                    };
                    admitted = frame;
                    super::scan::NativeRx {
                        frame: &admitted,
                        ccmp: None,
                        ..native
                    }
                }
                _ => native,
            };
            if native.ccmp.is_none() {
                if let Some(response) = sa_query_response(native.frame, own, peer) {
                    if self.station.control_pending.len() < 4 {
                        self.station.control_pending.push_back(response);
                    }
                    continue;
                }
            }
            // Management and the retained supplicant still make progress
            // while ordinary RX is closed. Admission is decided from the
            // original copy and current port before any aggregate/replay work.
            let ordinary = native.frame.first().is_some_and(|fc| fc & 12 == 8)
                && (native.amsdu != 0
                    || extract_native_eapol(native.frame, native.ccmp.is_some()).is_none());
            if ordinary && (!packet.port_open || !self.receive_current(packet.epoch)?) {
                self.clear_aggregate_receive();
                continue;
            }
            // HE P-RXV modes (8..11) are admitted only by a negotiated HE
            // profile; every other mode keeps the HT/VHT checks below.
            let he_ppdu = native
                .phy
                .filter(|v| (8..=11).contains(&((v >> 24) & 15)))
                .map(|v| {
                    self.station.he_profile.is_some_and(|he| {
                        crate::mt7921::he::receive_allowed(he.width(), v, he.rx_limits())
                    })
                });
            if he_ppdu == Some(false) {
                self.clear_aggregate_receive();
                continue;
            }
            if let Some(profile) = self.station.vht_profile {
                if native.frame.len() > 3895
                    || he_ppdu.is_none() && !profile.receive_allowed(native.phy)
                {
                    self.clear_aggregate_receive();
                    continue;
                }
                let f = native.frame;
                if native.ccmp.is_none()
                    && f.len() >= 26
                    && f[1] & 0xc7 == 0
                    && f[22] & 15 == 0
                    && f[10..16] == peer
                    && f[16..22] == peer
                    && (f[4..10] == own || f[4..10] == [255; 6])
                    && (matches!(f[0], 0x50 | 0x80)
                        && f.get(36..).is_some_and(|ies| !profile.matches(ies))
                        || f[0] == 0xd0 && (f[24..26] == [21, 2] || f[24..26] == [7, 0]))
                {
                    self.station.peer_lost = true;
                    self.station.rx_ba.fence();
                    self.station.tx_ba.fence();
                    self.clear_aggregate_receive();
                    return Err(Error::DeviceGone);
                }
            }
            if let Some(ap) = self.station.ap_phy {
                if self.station.vht_profile.is_none()
                    && he_ppdu.is_none()
                    && !crate::mt7921::vht::receive_allowed(
                        u8::from(
                            self.station
                                .ht20_profile
                                .is_some_and(|p| p.negotiated_secondary().is_some()),
                        ),
                        native.phy,
                        false,
                        crate::mt7921::vht::RxLimits {
                            streams: self.station.ht20_profile.map_or(1, |p| p.receive_streams()),
                            ldpc: self.station.ht20_profile.is_some_and(|p| p.receive_ldpc()),
                            stbc: self.station.ht20_profile.is_some_and(|p| p.receive_stbc()),
                            greenfield: self
                                .station
                                .ht20_profile
                                .is_some_and(|p| p.receive_greenfield()),
                            cck: channel <= 14,
                        },
                    )
                {
                    self.clear_aggregate_receive();
                    continue;
                }
                let f = native.frame;
                if native.ccmp.is_none()
                    && f.len() >= 36
                    && matches!(f[0], 0x50 | 0x80)
                    && f[1] & 0xc7 == 0
                    && f[22] & 15 == 0
                    && f[10..16] == peer
                    && f[16..22] == peer
                    && (f[4..10] == own || f[4..10] == [255; 6])
                    && !narf_wireless::association::phy::ApElements::parse(&f[36..])
                        .is_ok_and(|current| crate::mt7921::ht20::same_ap_phy(&ap, &current))
                {
                    self.station.peer_lost = true;
                    self.station.rx_ba.fence();
                    self.station.tx_ba.fence();
                    self.clear_aggregate_receive();
                    return Err(Error::DeviceGone);
                }
            }
            if native.amsdu != 0 {
                if let Some(frame) = self.receive_aggregate(&native, own, peer, channel) {
                    return Ok(Some(frame));
                }
                continue;
            }
            if let Some(receiver) = &mut self.station.ht20_rx {
                receiver.clear();
            }
            let frame = native.frame;
            if self.receive_ba_control(&native, own, peer) {
                if let Some(frame) = self.receive_ba_ready() {
                    return Ok(Some(frame));
                }
                continue;
            }
            let Some(header) = frame.get(..24) else {
                continue;
            };
            if let Some(profile) = self
                .station
                .ht20_profile
                .filter(|_| self.station.ap_phy.is_none())
            {
                if matches!(header[0], 0x80 | 0x50)
                    && header[1] & 0xc7 == 0
                    && header[10..16] == peer
                    && header[16..22] == peer
                    && (header[4..10] == own || header[4..10] == [0xff; 6])
                    && frame.get(36..).is_some_and(|ies| {
                        !crate::mt7921::ht20::Profile::parse(ies, channel)
                            .and_then(|p| p.with_secondary(profile.negotiated_secondary()))
                            .is_ok_and(|current| current.same_static(profile))
                    })
                {
                    self.station.peer_lost = true;
                    self.station.rx_ba.fence();
                    self.station.tx_ba.fence();
                    self.clear_aggregate_receive();
                    return Err(Error::DeviceGone);
                }
            }
            // The AP announces it is leaving this channel (Channel Switch
            // Announcement, element 37, or Extended CSA, element 60) — on a
            // radar channel because it detected radar. This owner does not
            // follow a switch, so it leaves the channel now, before the AP
            // does: no further transmission here, and the link loss reaches
            // userspace as a disconnect (mac80211's outcome when a switch
            // cannot be followed, `ieee80211_sta_connection_lost`).
            if native.ccmp.is_none()
                && matches!(header[0], 0x80 | 0x50)
                && header[1] & 0xc7 == 0
                && header[22] & 15 == 0
                && (header[4..10] == own || header[4..10] == [0xff; 6])
                && header[10..16] == peer
                && header[16..22] == peer
                && frame
                    .get(36..)
                    .is_some_and(crate::mt7921::association::announces_channel_switch)
            {
                self.station.peer_lost = true;
                self.station.rx_ba.fence();
                self.station.tx_ba.fence();
                self.clear_aggregate_receive();
                return Err(Error::DeviceGone);
            }
            if let Some(parameters) = self.station.wmm_pending.or(self.station.wmm) {
                if native.ccmp.is_none()
                    && matches!(header[0], 0x80 | 0x50)
                    && header[1] & 0xc7 == 0
                    && header[22] & 15 == 0
                    && (header[4..10] == own || header[4..10] == [0xff; 6])
                    && header[10..16] == peer
                    && header[16..22] == peer
                {
                    match frame.get(36..).and_then(|ies| {
                        crate::mt7921::association::wmm::Parameters::parse(ies)
                            .ok()
                            .flatten()
                    }) {
                        Some(updated) if updated == parameters => {}
                        Some(updated) if !updated.same_set(parameters) => {
                            // Copy the complete checked set, not an IE view.
                            // This blocks new DATA immediately; existing native
                            // tokens retain their original ownership until drain.
                            self.station.wmm_pending = Some(updated);
                        }
                        _ => {
                            // Missing/malformed parameters or changed rows with
                            // an unchanged change counter cannot authorize TX.
                            self.station.peer_lost = true;
                            self.station.wmm_pending = None;
                            self.station.rx_ba.fence();
                            self.station.tx_ba.fence();
                            self.clear_aggregate_receive();
                            return Err(Error::DeviceGone);
                        }
                    }
                }
            }
            if native.ccmp.is_none()
                && matches!(header[0], 0xa0 | 0xc0)
                && header[1] & 0xc7 == 0
                && header[22] & 15 == 0
                && (header[4..10] == own || header[4..10] == [0xff; 6])
                && header[10..16] == peer
                && header[16..22] == peer
                && frame.get(24..26).is_some_and(|reason| reason != [0, 0])
            {
                self.station.peer_lost = true;
                self.station.rx_ba.fence();
                self.station.tx_ba.fence();
                self.clear_aggregate_receive();
                return Err(Error::DeviceGone);
            }
            if header[10..16] != peer
                || header[4..10] != own && header[4] & 1 == 0
                || header[16..22] == [0; 6]
                || header[16] & 1 != 0
                || header[4] & 1 != 0 && header[16..22] == own
            {
                continue;
            }
            if native.fragment || header[1] & 0x04 != 0 || header[22] & 15 != 0 {
                if let Some(ethernet) = self.receive_fragment(&native) {
                    return Ok(Some(ethernet));
                }
                continue;
            }
            let qos = (header[0] == 0x88).then(|| frame.get(24..26)).flatten();
            let tid = qos.map(|qos| qos[0] & 15);
            let reordered = tid.is_some_and(|tid| self.station.rx_ba.active(tid));
            if (native.ampdu || tid.is_some_and(|tid| self.station.rx_ba.owns(tid)))
                && (!reordered
                    || native.wcid != u16::from(self.station.link.peer())
                    || tid != Some(native.tid)
                    || header[4..10] != own
                    || header[22] & 15 != 0
                    || qos.is_none_or(|q| q[1] != 0 || !matches!(q[0] & 0xe0, 0 | 0x60)))
            {
                continue;
            }
            let protected = header[1] & 0x40 != 0;
            let mut normalized;
            let mut replay = None;
            let frame = if let Some(ccmp) = native.ccmp {
                let Some(security) = self.station.security.as_mut() else {
                    continue;
                };
                if !protected {
                    continue;
                }
                let tid = if header[0] & 0x80 != 0 {
                    let Some(qos) = frame.get(24) else {
                        continue;
                    };
                    usize::from(qos & 15)
                } else {
                    16
                };
                let counter = if header[4] & 1 != 0 {
                    let Some(counters) = security.group[usize::from(ccmp.key_id)].as_ref() else {
                        continue;
                    };
                    counters[tid]
                } else {
                    if ccmp.key_id != 0 {
                        continue;
                    }
                    security.pairwise[tid]
                };
                if ccmp.pn <= counter {
                    continue;
                }
                replay = Some((tid, ccmp.pn, ccmp.key_id, header[4] & 1 != 0));
                // Native hardware-decrypted CCMP has IV/MIC stripped. Only
                // validated RX metadata authorizes removing the Protected bit.
                normalized = frame.to_vec();
                normalized[1] &= !0x40;
                &normalized[..]
            } else {
                if protected {
                    continue;
                }
                frame
            };
            if let Some(ethernet) = to_ethernet(frame) {
                let eapol = ethernet[12..14] == [0x88, 0x8e];
                if self.station.security.is_some() && !protected && !eapol {
                    continue;
                }
                if reordered {
                    let pdu = if eapol {
                        if ethernet[..6] != own || ethernet[6..12] != peer {
                            continue;
                        }
                        let Some(pdu) = extract_eapol(frame) else {
                            continue;
                        };
                        Some(pdu.to_vec())
                    } else {
                        None
                    };
                    let frames = if eapol {
                        VecDeque::new()
                    } else {
                        VecDeque::from([ethernet])
                    };
                    let sequence = u16::from_le_bytes([header[22], header[23]]) >> 4;
                    self.station.rx_ba.insert(
                        tid.unwrap(),
                        super::ba::Packet::new(sequence, replay.map(|r| r.1), frames, pdu),
                        self.backend.now_ns(),
                    );
                    if let Some(frame) = self.receive_ba_ready() {
                        return Ok(Some(frame));
                    }
                    continue;
                }
                if let Some(security) = self.station.security.as_mut() {
                    if let Some((tid, pn, key, group)) = replay {
                        if group {
                            security.group[usize::from(key)].as_mut().unwrap()[tid] = pn;
                        } else {
                            security.pairwise[tid] = pn;
                        }
                    }
                    if eapol {
                        if ethernet[..6] == own && ethernet[6..12] == peer {
                            if let Some(pdu) = extract_eapol(frame) {
                                if security.pending.len() < 16 {
                                    security.pending.push_back((pdu.to_vec(), protected));
                                    self.close_own_receive_capture();
                                }
                            }
                        }
                        continue;
                    }
                }
                if eapol {
                    continue;
                } // The retained driver owns the controlled port.
                return Ok(Some(ethernet));
            }
        }
        Ok(None)
    }

    pub(super) async fn send_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
    ) -> Result<packet_tx::Completion, Error> {
        self.check_station_tx()?;
        self.transmit_management(frame, wcid).await
    }

    /// Only callers that just checked their station or one-shot closing
    /// permission may publish. The closing caller never restores a host grant.
    async fn transmit_management(
        &mut self,
        frame: &[u8],
        wcid: u16,
    ) -> Result<packet_tx::Completion, Error> {
        // mac80211 `ieee80211_tx_h_select_key`: under PMF every unicast
        // robust management frame (deauth/disassoc, BA/SA Query actions)
        // takes the pairwise key; mt76 then sets MT_TXD3_PROTECT_FRAME and
        // the hardware inserts the CCMP header and MIC.
        let protected;
        let frame = if frame.get(1).is_some_and(|fc| fc & 0x40 == 0)
            && frame.get(4).is_some_and(|a1| a1 & 1 == 0)
            && robust_management(frame)
            && self
                .station
                .security
                .as_ref()
                .is_some_and(StationSecurity::protects_management)
        {
            let mut copy = frame.to_vec();
            copy[1] |= 0x40;
            protected = copy;
            &protected[..]
        } else {
            frame
        };
        self.backend.submit_management(
            self.station.link.vif(),
            frame,
            wcid,
            self.station.management_rate,
        )?;
        let completion = self
            .wait(TIMEOUT_MS, |backend| backend.management_complete())
            .await?;
        if completion.status != 0 {
            return Err(Error::Rejected(completion.status));
        }
        Ok(completion)
    }

    pub(super) async fn send_ethernet(
        &mut self,
        frame: &[u8],
    ) -> Result<packet_tx::Completion, Error> {
        if !self.data_pending.is_empty() {
            return Err(Error::Busy);
        }
        self.start_ethernet(frame)?;
        loop {
            let result = self
                .wait(TIMEOUT_MS, |backend| backend.management_complete())
                .await;
            match result {
                Ok(completion) => {
                    let Some(completion) = self.retire_data(completion) else {
                        continue;
                    };
                    if completion.status != 0 {
                        return Err(self.fail_data(Error::Rejected(completion.status)));
                    }
                    if self.station.tx_fragments.is_empty() {
                        return Ok(completion);
                    }
                    self.check_station_tx()?;
                    self.advance_fragment()?;
                }
                Err(error) => return Err(self.fail_data(error)),
            }
        }
    }

    pub(super) fn fail_data(&mut self, error: Error) -> Error {
        self.cancel_transmit_ba_restart();
        self.scan_packets.clear();
        self.scanning = false;
        self.station.tx_fragments.clear();
        self.station.tx_credit.clear();
        self.close_own_receive_capture();
        self.station.security = None;
        self.station.permission = None;
        self.station.wmm = None;
        self.station.wmm_pending = None;
        self.station.ht20_rx = None;
        self.station.ht20_profile = None;
        self.station.vht_profile = None;
        self.station.he_profile = None;
        self.station.ap_phy = None;
        self.station.rx_ba.fence();
        self.station.tx_ba.fence();
        self.clear_aggregate_receive();
        self.state = State::Failed {
            stage: Stage::StaRecord,
            error,
        };
        error
    }

    fn data_capacity(&self) -> usize {
        if self.station.ht20_profile.is_some() && self.station.wmm.is_some() {
            self.station.tx_ba.capacity()
        } else {
            1
        }
    }
    pub(super) fn data_controls_pending(&self) -> bool {
        self.station.wmm_pending.is_some()
            || !self.station.control_pending.is_empty()
            || self.station.rx_ba.pending(self.backend.now_ns())
            || self.station.tx_ba.pending(self.backend.now_ns())
            || self
                .station
                .security
                .as_ref()
                .is_some_and(|s| !s.port_open())
    }

    /// Publish one frame into this profile's bounded native ownership queue;
    /// synchronous network waiters advance the same completion proofs.
    pub(super) fn start_ethernet(&mut self, frame: &[u8]) -> Result<(), Error> {
        if self.station.peer_lost {
            return Err(Error::DeviceGone);
        }
        let State::Associated { info, .. } = self.state else {
            return Err(Error::Busy);
        };
        if !(14..=1514).contains(&frame.len())
            || frame[6..12] != info.capabilities.mac
            || u16::from_be_bytes([frame[12], frame[13]]) < 0x600
            || frame[12..14] == [0x88, 0x8e]
        {
            return Err(Error::Bounds);
        }
        if self.data_pending.len() >= self.data_capacity()
            || self.data_controls_pending()
            || !self.station.tx_fragments.is_empty()
        {
            return Err(Error::Busy);
        }
        self.check_station_tx()?;
        // cfg80211_classify8021d + ieee80211_downgrade_queue: QoS stations
        // transmit on the frame's user priority/AC; non-QoS uses TID 0.
        let tid = self
            .station
            .wmm
            .map_or(0, |wmm| super::super::tx_priority::select(frame, wmm.acm()));
        if self.restart_blocks(tid) {
            return Err(Error::Busy);
        }
        // wcid->amsdu: set by the STA_REC_HW_AMSDU record of an HT peer and
        // cleared by a TX BA agreement without the A-MSDU bit.
        let amsdu = self.station.wmm.is_some()
            && self.station.ht20_profile.is_some()
            && (!self.station.tx_ba.active_tid(tid) || self.station.tx_ba.amsdu_tid(tid));
        self.backend.set_hw_amsdu(amsdu);
        if let Some(fragments) = self.fragments(frame, tid) {
            return self.start_fragments(fragments, tid);
        }
        let result = if self.station.tx_ba.active_tid(tid) {
            self.backend.submit_data_tid_aggregated(
                self.station.link,
                frame,
                self.station.security.is_some(),
                tid,
            )
        } else if tid != 0 {
            self.backend.submit_data_tid(
                self.station.link,
                frame,
                self.station.security.is_some(),
                tid,
                self.data_capacity() > 1,
            )
        } else if self.data_capacity() > 1 {
            self.backend.submit_data_pipelined(
                self.station.link,
                frame,
                self.station.security.is_some(),
                true,
            )
        } else {
            self.backend.submit_data(
                self.station.link,
                frame,
                self.station.security.is_some(),
                self.station.wmm.is_some(),
            )
        };
        match result {
            Ok(()) => {}
            Err(Error::Busy) => return Err(Error::Busy),
            Err(error) => return Err(self.fail_data(error)),
        }
        self.data_pending
            .push_owned(self.backend.now_ns(), self.station.link);
        self.note_sequence_publication(tid);
        if self.station.wmm.is_some() {
            self.station.used_tids |= 1 << tid;
        }
        self.station.tx_ba.touch_tid(tid, self.backend.now_ns());
        Ok(())
    }

    /// mac80211 `ieee80211_tx_h_fragment` / `ieee80211_fragment` for the
    /// native station: with a wiphy threshold set, Linux disables 802.3
    /// encapsulation offload (iface.c `ieee80211_set_sdata_offload_flags`:
    /// mt76 lacks `SUPPORTS_TX_FRAG`) and splits each unicast MSDU whose
    /// MPDU + FCS exceeds the threshold, unless it goes out as A-MPDU
    /// (`IEEE80211_TX_CTL_DONTFRAG`). Every fragment repeats the
    /// (QoS) DATA header with ToDS, Protected under a PTK, the fragment
    /// number and MoreFrags on all but the last; each carries
    /// `threshold - header - FCS` body octets (RFC1042 LLC/SNAP + payload).
    pub(super) fn fragments(&self, frame: &[u8], tid: u8) -> Option<Vec<Vec<u8>>> {
        let State::Associated { peer, .. } = self.state else {
            return None;
        };
        let qos = self.station.wmm.is_some();
        let header = if qos { 26 } else { 24 };
        let threshold = usize::try_from(self.frag_threshold).ok()?;
        let body = frame.len() - 14 + 8;
        if self.frag_threshold == u32::MAX
            || header + body + 4 <= threshold
            || self.station.tx_ba.active_tid(tid)
        {
            return None;
        }
        let per = threshold.checked_sub(header + 4).filter(|per| *per > 0)?;
        let mut msdu = Vec::with_capacity(body);
        msdu.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        msdu.extend_from_slice(&frame[12..]);
        let count = msdu.len().div_ceil(per);
        let mut out = Vec::with_capacity(count);
        for (number, chunk) in msdu.chunks(per).enumerate() {
            let mut mpdu = vec![0; header];
            mpdu[0] = if qos { 0x88 } else { 0x08 };
            mpdu[1] =
                0x01 | if self.station.security.is_some() {
                    0x40
                } else {
                    0
                } | if number + 1 < count { 0x04 } else { 0 };
            mpdu[4..10].copy_from_slice(&peer);
            mpdu[10..16].copy_from_slice(&frame[6..12]);
            mpdu[16..22].copy_from_slice(&frame[..6]);
            mpdu[22] = number as u8;
            if qos {
                mpdu[24] = tid;
            }
            mpdu.extend_from_slice(chunk);
            out.push(mpdu);
        }
        Some(out)
    }

    fn start_fragments(&mut self, fragments: Vec<Vec<u8>>, tid: u8) -> Result<(), Error> {
        let mut fragments = VecDeque::from(fragments);
        let Some(first) = fragments.pop_front() else {
            return Err(Error::Bounds);
        };
        match self.backend.submit_fragment(self.station.link, &first) {
            Ok(()) => {}
            Err(Error::Busy) => return Err(Error::Busy),
            Err(error) => return Err(self.fail_data(error)),
        }
        self.station.tx_fragments = fragments;
        self.data_pending
            .push_owned(self.backend.now_ns(), self.station.link);
        self.note_sequence_publication(tid);
        if self.station.wmm.is_some() {
            self.station.used_tids |= 1 << tid;
        }
        Ok(())
    }

    /// Submit this owner's next software fragment after its predecessor's
    /// terminal TX (the caller checked the station grant).
    fn advance_fragment(&mut self) -> Result<(), Error> {
        let Some(next) = self.station.tx_fragments.pop_front() else {
            return Ok(());
        };
        if let Err(error) = self.backend.submit_fragment(self.station.link, &next) {
            return Err(self.fail_data(error));
        }
        self.data_pending
            .push_owned(self.backend.now_ns(), self.station.link);
        let tid = if next.first() == Some(&0x88) {
            next[24] & 7
        } else {
            0
        };
        self.note_sequence_publication(tid);
        Ok(())
    }

    /// Apply terminal TX statuses the other station owner's waits retired
    /// for this owner (`retire_data`): a failure fails this owner's data
    /// path, a success releases its next fragment.
    fn settle_tx_credit(&mut self) -> Result<(), Error> {
        while let Some(status) = self.station.tx_credit.pop_front() {
            if status != 0 {
                return Err(self.fail_data(Error::Rejected(status)));
            }
            if !self.station.tx_fragments.is_empty() {
                if let Err(error) = self.check_station_tx() {
                    return Err(self.fail_data(error));
                }
                self.advance_fragment()?;
            }
        }
        Ok(())
    }

    pub(super) fn poll_data_tx(&mut self) -> Result<bool, Error> {
        self.settle_tx_credit()?;
        for _ in 0..packet_tx::PIPELINE {
            // Only this owner's oldest entry bounds its wait; the other
            // owner's entries ahead of it are credited to that owner.
            let Some(started) = self.data_pending.oldest_for(self.station.link) else {
                return Ok(!self.data_controls_pending());
            };
            if let Err(error) = self.backend.check() {
                return Err(self.fail_data(error));
            }
            let completion = match self.backend.management_complete() {
                Ok(value) => value,
                Err(error) => return Err(self.fail_data(error)),
            };
            if let Some(completion) = completion {
                let Some(completion) = self.retire_data(completion) else {
                    continue;
                };
                if completion.status != 0 {
                    return Err(self.fail_data(Error::Rejected(completion.status)));
                }
                // The next fragment follows its predecessor's terminal TX.
                if !self.station.tx_fragments.is_empty() {
                    if let Err(error) = self.check_station_tx() {
                        return Err(self.fail_data(error));
                    }
                    self.advance_fragment()?;
                }
                continue;
            }
            if self.backend.now_ns().saturating_sub(started) >= TIMEOUT_MS * 1_000_000 {
                return Err(self.fail_data(Error::Timeout));
            }
            break;
        }
        Ok(self.data_pending.len() < self.data_capacity()
            && !self.data_controls_pending()
            && self.station.tx_fragments.is_empty())
    }

    pub(super) fn step_network(&mut self, tx: Option<&[u8]>) -> Result<super::PacketStep, Error> {
        if self.station.peer_lost || !matches!(self.state, State::Associated { .. }) {
            return Err(Error::DeviceGone);
        }
        let epoch = self.receive_epoch;
        let ready = !self.p2p_rf_busy() && self.poll_data_tx()?;
        let transmitted = if let Some(frame) = tx.filter(|_| ready) {
            self.start_ethernet(frame)?;
            true
        } else {
            false
        };
        let mut received = Vec::new();
        for _ in 0..4 {
            let Some(frame) = self.receive_ethernet()? else {
                break;
            };
            received.push(frame);
        }
        // An EAPOL/key challenge later in this same native drain closes the
        // earlier collected batch, even if TX still has independent credits.
        if !self.receive_current(epoch)? {
            received.clear();
        }
        Ok(super::PacketStep {
            transmitted,
            received,
            link: Some(self.station.link_stats),
            receive_epoch: epoch,
        })
    }

    /// WPA3-SAE Authentication (Linux leaves it to wpa_supplicant
    /// `sme_sae_auth` over mac80211 `ieee80211_rx_mgmt_auth`, algorithm 3):
    /// a Commit from the device CSPRNG, bounded anti-clogging retries,
    /// Confirm, then the association request carrying the SAE PMKID. The
    /// session (password element, scalars, PMK) stays boxed and is dropped
    /// here; only the PMK leaves, zeroized on drop.
    async fn authenticate_sae(
        &mut self,
        plan: &mut JoinPlan,
        bss: &ScanBss,
        ssid: &[u8],
        own: [u8; 6],
        password: crate::mt7921::association::SaePassword,
        rx_channel: u8,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), Error> {
        use narf_wireless::sae::{SaeError, SaeSession};
        let join = plan.sae().ok_or(Error::MalformedEvent)?;
        let (h2e, selector) = (join.h2e(), join.akm_suite_selector());
        let mut session = if h2e {
            SaeSession::new_h2e_bytes(ssid, password.as_bytes(), own, bss.bssid)
        } else {
            SaeSession::new_hunt_and_peck(password.as_bytes(), own, bss.bssid)
        };
        if let Some(selector) = selector {
            session = session
                .with_akm_suite_selector(selector)
                .map_err(|_| Error::MalformedEvent)?;
        }
        let mut session = alloc::boxed::Box::new(session);
        let mut failure = None;
        session
            .try_build_commit_with_entropy(|out| {
                self.backend.random_bytes(out).map_err(|error| {
                    failure = Some(error);
                    SaeError::EntropyUnavailable
                })
            })
            .map_err(|_| failure.unwrap_or(Error::EntropyUnavailable))?;
        let mut frame = plan
            .start_sae_authentication(&session)
            .map_err(|_| Error::MalformedEvent)?
            .to_vec();
        // Commit, at most the shared plan's MAX_ANTI_CLOGGING (3) token
        // retries, then Confirm; the plan fails any further token request.
        for _ in 0..5 {
            self.send_management(&frame, u16::from(self.station.link.peer()))
                .await?;
            let step = self
                .wait_station_rx(3_000, |_, packet| {
                    if let Some(reply) = rx_on_channel(packet, rx_channel) {
                        if let Some(step) = plan
                            .sae_authentication_response(reply, &mut session)
                            .map_err(|_| Error::MalformedEvent)?
                        {
                            return Ok(Some(step));
                        }
                    }
                    Ok(None)
                })
                .await?;
            match step {
                crate::mt7921::association::SaeOutcome::Transmit(next) => frame = next,
                crate::mt7921::association::SaeOutcome::Associate(request) => {
                    let pmk = Zeroizing::new(*session.pmk().ok_or(Error::MalformedEvent)?);
                    return Ok((request, pmk));
                }
            }
        }
        Err(Error::MalformedEvent)
    }

    /// Wait for the AP's Open System Authentication response and return
    /// the association request it releases.
    async fn open_authentication_response(
        &mut self,
        plan: &mut JoinPlan,
        rx_channel: u8,
    ) -> Result<Vec<u8>, Error> {
        self.wait_station_rx(3_000, |_, packet| {
            if let Some(frame) = rx_on_channel(packet, rx_channel) {
                if let Some(assoc) = plan
                    .authentication_response(frame)
                    .map_err(|_| Error::MalformedEvent)?
                {
                    return Ok(Some(assoc.to_vec()));
                }
            }
            Ok(None)
        })
        .await
    }

    pub(super) async fn associate_station(
        &mut self,
        bss: &ScanBss,
        ssid: &[u8],
        security: Security,
        permission: crate::mt7921::association::TxPermission,
        extra_ies: &[u8],
    ) -> Result<u16, Error> {
        self.associate_station_as(
            bss,
            ssid,
            security,
            permission,
            extra_ies,
            crate::mt7921::p2p_wire::Network::Infrastructure,
        )
        .await
    }

    /// Linux `mt7921_mac_sta_add`/`mt7921_bss_info_changed` for a STATION
    /// vif, with `vif->p2p` selecting the P2P-client BSS connection type.
    pub(super) async fn associate_station_as(
        &mut self,
        bss: &ScanBss,
        ssid: &[u8],
        security: Security,
        permission: crate::mt7921::association::TxPermission,
        extra_ies: &[u8],
        network: crate::mt7921::p2p_wire::Network,
    ) -> Result<u16, Error> {
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        let (info, setup) = match self.state {
            // A group vif publishes its DEV_INFO/BSS at start_group_link;
            // the passive scan setup is the home vif's own.
            State::RadioReady(info) if !self.group_role() => (info, true),
            State::ScanReady(info) => (info, false),
            State::Associated { .. } => return Err(Error::Busy),
            _ => return Err(Error::Busy),
        };
        // No station BSS is live here, so the role cannot change under an
        // already published BSS record.
        self.station.network = network;
        let six = crate::mt7921::association::is_six_ghz(bss);
        let band = if six {
            // MT_NIC_CAP_6G gates the 6 GHz band (mt7921/mcu.c:595).
            if !crate::mt7921::six_ghz::qualified(info) {
                return Err(Error::InvalidIdentity);
            }
            crate::mt7921::channel::Band::Ghz6
        } else {
            crate::mt7921::channel::band(bss.channel).ok_or(Error::Bounds)?
        };
        if !permission.permits_bss(bss) || permission.band() != Some(band) {
            return Err(Error::Authority);
        }
        // One shared channel context (mac80211 chanctx reuse): the other
        // live station owner's exact channel/width/power grant.
        if !self.shares_channel_context(permission) {
            return Err(Error::Busy);
        }
        if !six && info.capabilities.phy.bands & band.capability() == 0 {
            return Err(Error::InvalidIdentity);
        }
        // RXD3 CH_FREQ of the operating channel (mt792x_get_status_freq_info).
        let rx_channel =
            crate::mt7921::channel::rx_channel(band, bss.channel).ok_or(Error::Bounds)?;
        let initial_limits = permission
            .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
            .ok_or(Error::Bounds)?;
        let own = info.capabilities.mac;
        let mut plan = JoinPlan::prepare_native(bss, own, ssid, security, info, permission)?;
        plan.append_sme_ies(extra_ies).map_err(|_| Error::Bounds)?;
        self.backend.check_tx_permission(permission)?;
        if !self.station.rx_ba.begin_connection() || !self.station.tx_ba.begin_connection() {
            return Err(Error::Busy);
        }
        self.renew_receive_epoch()?;
        self.station.used_tids = 0;

        self.station.management_rate = plan.management_rate();
        // Discard idle receive preparation. Any HT activation below must be
        // rebuilt from the bound AP response and completed native receipts.
        self.station.ht20_rx = None;
        self.station.ht20_profile = None;
        self.station.vht_profile = None;
        self.station.he_profile = None;
        self.station.ap_phy = None;
        self.station.control_pending.clear();
        self.station.tx_fragments.clear();
        self.station.received_msdu.clear();
        self.station.demuxed.clear();
        self.station.tx_credit.clear();
        self.boot_started = Some(self.backend.now_ns());
        self.station.security = None;
        self.station.wmm = None;
        self.station.wmm_pending = None;
        self.station.permission = Some(permission);
        let mut sae_pmk: Option<Zeroizing<[u8; 32]>> = None;
        // The SAE network's credentials, and its live cached PMKSA for this
        // BSS (wpa_supplicant `pmksa_cache_get`).
        let credentials = match security {
            Security::Wpa3Sae { password } => {
                Some(crate::mt7921::pmksa::binding(ssid, password.as_bytes()))
            }
            _ => None,
        };
        let mut cached = credentials.and_then(|binding| {
            let now = self.backend.now_ns();
            self.pmksa.lookup(bss.bssid, binding, now)
        });
        // The PMKSA a full SAE exchange produced, recorded on success.
        let mut new_pmksa: Option<([u8; 16], Zeroizing<[u8; 32]>)> = None;
        let result = async {
            if setup {
                self.stage(Stage::ScanSetup);
                self.scan_setup(info).await?;
            }
            self.stage(Stage::ChannelSwitch);
            self.check_station_tx()?;
            if let Some(grant) = permission.six {
                // mt7921_mac_sta_add -> mt7921_regd_set_6ghz_power_type: the
                // AP's power type reaches the CLC as env_6g before the peer.
                self.program_6ghz_power_type(info, crate::mt7921::six_ghz::env_6g(grant.power))
                    .await?;
                self.check_station_tx()?;
            }
            // 1. Authorize transmission on the target channel in channel domain (NO_IR = 0):
            let domain = station_channel_domain(permission, band);
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &domain,
            )
            .await?;

            // The host policy's power ceiling is programmed before any
            // authentication/EAPOL/data frame can reach a TX descriptor.
            self.check_station_tx()?;
            self.notify(
                Command::Ce {
                    id: 0x5d,
                    query: false,
                },
                &initial_limits,
            )
            .await?;
            self.confirm_command_progress().await?;
            self.check_station_tx()?;

            // 2. Switch channel:
            let mut switch = [0u8; cmd::CHANNEL_SWITCH_SIZE];
            cmd::encode_channel_switch(
                bss.channel,
                permission.center_channel(),
                permission.native_width(),
                1, // The retained legacy profile transmits on one chain.
                (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
                band.switch_tag(),
                &mut switch,
            )
            .ok_or(Error::Bounds)?;
            self.exchange_station(
                Command::Extended {
                    id: crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH,
                    query: false,
                },
                &switch,
            )
            .await?;

            // Publish BSSID and an unauthorized AP WCID before management
            // or EAPOL RX; a scan-only BSS has no peer address installed.
            let mut bss_record =
                crate::mt7921::association::bss_record_qos_on(self.station.link, bss, false, false)
                    .map_err(|_| Error::Bounds)?;
            crate::mt7921::p2p_wire::group_bss(&mut bss_record, network)?;
            self.exchange_station(Command::Unified { id: 2 }, &bss_record)
                .await?;
            let peer_record = plan
                .peer_record_on(self.station.link, 0, false)
                .map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 3 }, &peer_record)
                .await?;

            // 3. Send Authentication Request:
            self.stage(Stage::Authenticate);
            let aid = loop {
                let attempt = async {
                    let assoc_req = match (security, cached.as_ref()) {
                        // PMKSA caching: Open System authentication and the
                        // cached PMKID instead of a new SAE exchange.
                        (Security::Wpa3Sae { .. }, Some((pmkid, pmk))) => {
                            let auth_req = plan
                                .start_pmksa_authentication(*pmkid)
                                .map_err(|_| Error::Busy)?
                                .to_vec();
                            self.send_management(&auth_req, u16::from(self.station.link.peer()))
                                .await?;
                            let request = self
                                .open_authentication_response(&mut plan, rx_channel)
                                .await?;
                            sae_pmk = Some(Zeroizing::new(**pmk));
                            request
                        }
                        (Security::Wpa3Sae { password }, None) => {
                            let (request, pmk) = self
                                .authenticate_sae(&mut plan, bss, ssid, own, password, rx_channel)
                                .await?;
                            new_pmksa = plan
                                .sae()
                                .and_then(|join| join.pmkid())
                                .map(|pmkid| (pmkid, Zeroizing::new(*pmk)));
                            sae_pmk = Some(pmk);
                            request
                        }
                        _ => {
                            let auth_req = plan.start_authentication().map_err(|_| Error::Busy)?;
                            self.send_management(auth_req, u16::from(self.station.link.peer()))
                                .await?;
                            // 4. Wait for Authentication Response:
                            self.open_authentication_response(&mut plan, rx_channel)
                                .await?
                        }
                    };

                    // 5. Send Association Request:
                    self.stage(Stage::Associate);
                    self.send_management(&assoc_req, u16::from(self.station.link.peer()))
                        .await?;

                    // 6. Wait for Association Response:
                    self.wait_station_rx(3_000, |_, packet| {
                        if let Some(frame) = rx_on_channel(packet, rx_channel) {
                            if let Some(aid) =
                                plan.association_response(frame)
                                    .map_err(|error| match error {
                                        // The status itself only selects the
                                        // PMKSA fallback below.
                                        narf_wireless::association::Error::Rejected(status) => {
                                            Error::Rejected(u8::try_from(status).unwrap_or(u8::MAX))
                                        }
                                        _ => Error::MalformedEvent,
                                    })?
                            {
                                return Ok(Some(aid));
                            }
                        }
                        Ok(None)
                    })
                    .await
                }
                .await;
                match attempt {
                    Ok(aid) => break aid,
                    // wpa_supplicant: "PMKSA caching attempt rejected - drop
                    // PMKSA cache entry and fall back to SAE authentication"
                    // (WLAN_STATUS_INVALID_PMKID, or no answer to it).
                    Err(_) if cached.take().is_some() => {
                        self.pmksa.remove(bss.bssid);
                        sae_pmk = None;
                        plan =
                            JoinPlan::prepare_native(bss, own, ssid, security, info, permission)?;
                        plan.append_sme_ies(extra_ies).map_err(|_| Error::Bounds)?;
                        self.stage(Stage::Authenticate);
                    }
                    Err(error) => return Err(error),
                }
            };

            self.station.management_rate = plan.management_rate();
            if let Some((width, center)) = plan.phy_channel() {
                let narrower = permission.narrow(width, center).ok_or(Error::Bounds)?;
                if width != permission.native_width()
                    || center != permission.center_channel()
                    || plan.transmit_streams() > 1
                {
                    // The radio's channel is shared with the other live
                    // station owner; no single-channel narrowing moves it.
                    if self.other_station_permission().is_some() || self.go_plan().is_some() {
                        return Err(Error::Busy);
                    }
                    self.station.permission = Some(narrower);
                    self.reconfigure_station_channel(
                        info,
                        bss.channel,
                        narrower,
                        plan.transmit_streams(),
                    )
                    .await?;
                }
            }
            if let Some(profile) = plan.ht20() {
                let mut response_bss = bss.clone();
                response_bss.information_elements = profile.received_ies();
                self.station.ht20_rx = Some(super::amsdu::Receiver::prepare_with_streams(
                    info,
                    &response_bss,
                    profile.receive_streams(),
                )?);
            }
            if let Some(parameters) = plan.wmm() {
                self.check_station_tx()?;
                // Native SET_EDCA_PARMS has no firmware reply. The following
                // matching PSE read bounds command progress before QoS WCID
                // publication; it is not an invented EDCA acceptance event.
                self.notify(
                    Command::Ce {
                        id: 0x1d,
                        query: false,
                    },
                    &crate::mt7921::association::wmm::on_vif(
                        self.station.link.vif(),
                        parameters.edca_limited(self.station.permission.and_then(|p| p.wmm_rule())),
                    ),
                )
                .await?;
                self.confirm_command_progress().await?;
                self.check_station_tx()?;
                // mt7921_mcu_set_tx: SET_MU_EDCA_PARMS follows SET_EDCA_PARMS
                // whenever he_support is set (no firmware reply either).
                if let Some(he) = plan.he() {
                    self.notify(
                        Command::Ce {
                            id: crate::mt7921::he::SET_MU_EDCA_PARMS,
                            query: false,
                        },
                        &he.mu_edca_request(true),
                    )
                    .await?;
                    self.confirm_command_progress().await?;
                    self.check_station_tx()?;
                }
            }
            let mut bss_record = crate::mt7921::association::bss_record_ht20_on(
                self.station.link,
                bss,
                plan.wmm().is_some(),
                plan.ht20().is_some(),
            )
            .map_err(|_| Error::Bounds)?;
            if plan.vht().is_some() {
                bss_record[29] |= 1 << 5;
            } // PHY_MODE_AC.
            crate::mt7921::p2p_wire::group_bss(&mut bss_record, network)?;
            if let Some(he) = plan.he() {
                bss_record[29] |= he.phy_mode();
            }
            self.exchange_station(Command::Unified { id: 2 }, &bss_record)
                .await?;
            if let Some(he) = plan.he() {
                // mt7921_mac_sta_event(ASSOC) -> uni_add_bss(enable = true):
                // HE_BASIC + BSS_COLOR follow BASIC/QBSS once he_support is set.
                self.exchange_station(
                    Command::Unified { id: 2 },
                    &crate::mt7921::vif_slots::on_bss(self.station.link.vif(), he.bss(true)),
                )
                .await?;
            }
            if let Some(profile) = plan.vht() {
                self.exchange_station(
                    Command::Unified { id: 2 },
                    &crate::mt7921::vif_slots::on_bss(
                        self.station.link.vif(),
                        profile.rlm(
                            bss.channel,
                            (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
                        ),
                    ),
                )
                .await?;
            } else if let Some(profile) = plan.ht20() {
                self.exchange_station(
                    Command::Unified { id: 2 },
                    &crate::mt7921::vif_slots::on_bss(
                        self.station.link.vif(),
                        profile.rlm(
                            bss.channel,
                            (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
                        ),
                    ),
                )
                .await?;
            } else if six {
                // mt76_connac_mcu_uni_set_chctx with band = NL80211_BAND_6GHZ.
                self.exchange_station(
                    Command::Unified { id: 2 },
                    &crate::mt7921::vif_slots::on_bss(
                        self.station.link.vif(),
                        crate::mt7921::six_ghz::rlm(
                            bss.channel,
                            permission.center_channel(),
                            permission.native_width(),
                            plan.transmit_streams(),
                            (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
                        ),
                    ),
                )
                .await?;
            }
            let peer_record = plan
                .peer_record_on(self.station.link, aid, true)
                .map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 3 }, &peer_record)
                .await?;
            let group_record =
                crate::mt7921::association::group_record_on(self.station.link, bss.bssid, aid)
                    .map_err(|_| Error::Bounds)?;
            self.exchange_station(Command::Unified { id: 3 }, &group_record)
                .await?;

            // 7. Update STA_REC / perform WPA2 4-way handshake:
            match security {
                Security::Open => {
                    self.stage(Stage::StaRecord);
                    let sta_rec = plan
                        .peer_record_on(self.station.link, aid, true)
                        .map_err(|_| Error::MalformedEvent)?;
                    self.exchange_station(Command::Unified { id: 3 }, &sta_rec)
                        .await?;
                }
                Security::Wpa2Psk { .. }
                | Security::Wpa2PskPmf { .. }
                | Security::Wpa2PskSelected { .. }
                | Security::Wpa3Sae { .. } => {
                    self.stage(Stage::EapolHandshake);
                    let pmk = match security {
                        Security::Wpa2Psk { psk }
                        | Security::Wpa2PskPmf { psk, .. }
                        | Security::Wpa2PskSelected { psk, .. } => Zeroizing::new(psk),
                        _ => sae_pmk.take().ok_or(Error::MalformedEvent)?,
                    };
                    let mut security = StationSecurity::new(bss, &plan, own, &pmk)?;
                    let mut established = false;
                    // Retry replies remain bounded by the operation's 30 s budget.
                    for _ in 0..16 {
                        let result = self
                            .wait_station_rx(3_000, |backend, packet| {
                                if let Some(pdu) = peer_eapol(packet, own, bss.bssid, rx_channel) {
                                    if let Some(result) = security
                                        .process(pdu, false, |out| backend.random_bytes(out))?
                                    {
                                        return Ok(Some(result));
                                    }
                                }
                                Ok(None)
                            })
                            .await?;
                        match result {
                            EapolRx::Pairwise1(m1) => {
                                self.send_management(
                                    &wrap_eapol_frame(own, bss.bssid, &m1.reply),
                                    u16::from(self.station.link.peer()),
                                )
                                .await?;
                            }
                            EapolRx::Pairwise3(m3) => {
                                // PMF requires the IGTK KDE in message 3
                                // (wpa_supplicant `ieee80211w_set_keys`; the
                                // shared supplicant reports it when not in use).
                                if !m3.secure
                                    || m3.tk.is_none()
                                    || m3.gtk.is_none()
                                    || security.pmf && m3.igtk.is_none()
                                {
                                    return Err(Error::MalformedEvent);
                                }
                                self.send_management(
                                    &wrap_eapol_frame(own, bss.bssid, &m3.reply),
                                    u16::from(self.station.link.peer()),
                                )
                                .await?;
                                self.stage(Stage::StaRecord);
                                let record = plan
                                    .secure_peer_record_on(
                                        self.station.link,
                                        aid,
                                        m3.tk.as_deref().unwrap(),
                                    )
                                    .map_err(|_| Error::MalformedEvent)?;
                                self.exchange_station(Command::Unified { id: 3 }, &record)
                                    .await?;
                                security.commit_pairwise();
                                let gtk = m3.gtk.as_ref().unwrap();
                                self.install_group_key(gtk).await?;
                                security.commit_group(gtk)?;
                                if let Some(igtk) = m3.igtk.as_ref().filter(|_| security.pmf) {
                                    self.install_igtk(&security, igtk).await?;
                                    security.commit_igtk(igtk)?;
                                }
                                security.port_open = true;
                                established = true;
                                break;
                            }
                            EapolRx::Group1(_) => return Err(Error::MalformedEvent),
                        }
                    }
                    if !established {
                        return Err(Error::Timeout);
                    }
                    self.station.security = Some(security);
                }
            }

            self.check_station_tx()?;
            Ok(aid)
        }
        .await;

        match result {
            Ok(aid) => {
                self.boot_started = None;
                self.station.peer_lost = false;
                self.station.link_stats = Default::default();
                self.station.ps_applied = false;
                self.station.applied_policy = self.backend.regulatory_domain().ok();
                if let (Some(binding), Some((pmkid, pmk))) = (credentials, new_pmksa.take()) {
                    let now = self.backend.now_ns();
                    self.pmksa.insert(bss.bssid, binding, pmkid, &pmk, now);
                }
                self.station.bss = Some(bss.clone());
                self.station.wmm = plan.wmm();
                self.station.ht20_profile = plan.ht20();
                self.station.vht_profile = plan.vht();
                self.station.he_profile = plan.he();
                self.station.ap_phy = plan.ap_phy();
                if let Some(receiver) = &mut self.station.ht20_rx {
                    receiver.active = true;
                }
                self.state = State::Associated {
                    info,
                    peer: bss.bssid,
                    channel: rx_channel,
                    aid,
                };
                if let Err(error) = self.sync_receive_capture() {
                    return Err(self.fail_data(error));
                }
                Ok(aid)
            }
            Err(error) => {
                // A join that used a cached PMKSA and still failed (a 4-way
                // handshake the AP's PMK did not match) drops the entry, as
                // wpa_supplicant clears the current PMKSA on that failure.
                if cached.is_some() {
                    self.pmksa.remove(bss.bssid);
                }
                self.station.security = None;
                self.station.wmm = None;
                self.station.wmm_pending = None;
                self.station.permission = None;
                self.station.ht20_rx = None;
                self.station.ht20_profile = None;
                self.station.vht_profile = None;
                self.station.he_profile = None;
                self.station.ap_phy = None;
                plan.cancel();
                let stage = match self.state {
                    State::Running(stage) | State::Failed { stage, .. } => stage,
                    _ => Stage::Associate,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }

    pub(super) async fn disassociate_station(&mut self) -> Result<(), Error> {
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        let (info, peer) = match self.state {
            State::Associated { info, peer, .. } => (info, peer),
            State::RadioReady(_) | State::ScanReady(_) | State::Suspended(_) | State::Stopped => {
                return Ok(())
            }
            _ => return Err(Error::Busy),
        };
        self.cancel_transmit_ba_restart();
        self.close_own_receive_capture();
        self.boot_started = Some(self.backend.now_ns());
        // ieee80211_set_disassoc sends the deauthentication before the
        // station's keys are flushed: under PMF it is CCMP protected.
        let protect_deauth = self
            .station
            .security
            .as_ref()
            .is_some_and(StationSecurity::protects_management);
        let secure = self.station.security.take().is_some();
        let had_wmm = self.station.wmm.take().is_some();
        self.station.wmm_pending = None;
        // Retire the host grant before the first wait. This local copy can
        // authorize only the closing deauth; a dropped waiter cannot leave a
        // reusable station permission in the retained running owner.
        let closing_permission = self.station.permission.take();
        self.station.rx_ba.fence();
        self.station.tx_ba.fence();
        self.station.ht20_rx = None;
        self.station.ht20_profile = None;
        self.station.vht_profile = None;
        let had_he = self.station.he_profile.take();
        self.station.ap_phy = None;
        self.station.control_pending.clear();
        self.station.tx_fragments.clear();
        self.station.received_msdu.clear();
        self.station.demuxed.clear();
        self.station.tx_credit.clear();
        let peer_lost = self.station.peer_lost;
        self.stage(Stage::StaRecord);
        let result = async {
            // Drain the device FIFO; the other owner's entries are
            // credited to it, never consumed as this owner's.
            while !self.data_pending.is_empty() {
                let completion = self
                    .wait(TIMEOUT_MS, |backend| backend.management_complete())
                    .await?;
                let _ = self.retire_data(completion);
            }
            self.retire_transmit_ba(false).await?;
            self.retire_receive_ba(peer).await?;
            if !peer_lost {
                let mut deauth = vec![0u8; 26];
                deauth[0] = 0xc0;
                deauth[1] = if protect_deauth { 0x40 } else { 0 };
                deauth[4..10].copy_from_slice(&peer);
                deauth[10..16].copy_from_slice(&info.capabilities.mac);
                deauth[16..22].copy_from_slice(&peer);
                deauth[24..26].copy_from_slice(&3u16.to_le_bytes());
                self.backend
                    .check_tx_permission(closing_permission.ok_or(Error::Authority)?)?;
                match self
                    .transmit_management(&deauth, u16::from(self.station.link.peer()))
                    .await
                {
                    Ok(_) | Err(Error::Rejected(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            // Retire keys before removing the station WCIDs. No cleanup ACK
            // is optional: uncertainty cannot become a reusable ready radio.
            let link = self.station.link;
            if secure {
                for wcid in [link.peer(), link.bmc()] {
                    let record = crate::mt7921::association::key_record_on(link, wcid, 0, None)
                        .map_err(|_| Error::Bounds)?;
                    self.exchange(Command::Unified { id: 3 }, &record).await?;
                }
            }
            for record in [
                disconnect_record_on(link, peer),
                crate::mt7921::association::group_disconnect_record_on(link),
            ] {
                self.exchange(Command::Unified { id: 3 }, &record).await?;
            }
            if let Some(bss) = &self.station.bss {
                let mut record = crate::mt7921::association::bss_record_qos_on(
                    self.station.link,
                    bss,
                    false,
                    false,
                )
                .map_err(|_| Error::Bounds)?;
                crate::mt7921::p2p_wire::group_bss(&mut record, self.station.network)?;
                self.exchange(Command::Unified { id: 2 }, &record).await?;
                // mt76_connac_mcu_uni_add_bss(enable = false) still sends the
                // HE request while he_support is set, with BSS color disabled.
                if let Some(he) = had_he {
                    self.exchange(
                        Command::Unified { id: 2 },
                        &crate::mt7921::vif_slots::on_bss(self.station.link.vif(), he.bss(false)),
                    )
                    .await?;
                }
            }
            if had_wmm {
                self.notify(
                    Command::Ce {
                        id: 0x1d,
                        query: false,
                    },
                    &crate::mt7921::association::wmm::on_vif(
                        self.station.link.vif(),
                        crate::mt7921::association::wmm::legacy_edca(),
                    ),
                )
                .await?;
                self.confirm_command_progress().await?;
            }
            if closing_permission.is_some_and(|p| p.six.is_some()) {
                // mt7921_mac_sta_remove -> mt7921_regd_set_6ghz_power_type
                // (is_add = false): IEEE80211_REG_UNSET_AP -> MT_AP_UNSET.
                self.program_6ghz_power_type(info, crate::mt7921::six_ghz::MT_AP_UNSET)
                    .await?;
            }
            Ok(())
        }
        .await;
        self.boot_started = None;
        self.station.permission = None;
        if let Err(error) = result {
            self.state = State::Failed {
                stage: Stage::StaRecord,
                error,
            };
            return Err(error);
        }
        self.station.bss = None;
        self.station.network = crate::mt7921::p2p_wire::Network::Infrastructure;
        self.station.peer_lost = false;
        self.state = State::ScanReady(info);
        Ok(())
    }

    pub(super) fn check_station_tx(&mut self) -> Result<(), Error> {
        // A retained off-channel owner pauses home TX. It does not revoke
        // the association, keys, BA state or controlled-port grant.
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        let result = self
            .station
            .permission
            .ok_or(Error::Authority)
            .and_then(|permission| self.backend.check_tx_permission(permission));
        if let Err(error) = result {
            self.station.permission = None;
            self.station.wmm = None;
            self.station.wmm_pending = None;
            self.station.security = None;
            self.station.ht20_rx = None;
            self.station.ht20_profile = None;
            self.station.vht_profile = None;
            self.station.he_profile = None;
            self.station.ap_phy = None;
            self.station.rx_ba.fence();
            self.station.tx_ba.fence();
            self.station.control_pending.clear();
            self.station.tx_fragments.clear();
            self.clear_aggregate_receive();
            let stage = match self.state {
                State::Running(stage) | State::Failed { stage, .. } => stage,
                _ => Stage::StaRecord,
            };
            self.state = State::Failed { stage, error };
        }
        result
    }

    /// Complete response-bound occupied-channel shrink before native peer,
    /// keys or controlled-port publication. The old broader grant can only
    /// lose constituents; each command earns the current narrower grant.
    async fn reconfigure_station_channel(
        &mut self,
        info: super::RadioInfo,
        channel: u8,
        permission: crate::mt7921::association::TxPermission,
        tx_streams: u8,
    ) -> Result<(), Error> {
        if !(1..=info.capabilities.phy.spatial_streams).contains(&tx_streams) {
            return Err(Error::Bounds);
        }
        let limits = permission
            .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
            .ok_or(Error::Bounds)?;
        let band = permission.band().ok_or(Error::Bounds)?;
        let channels = permission.channels();
        let mut domain = vec![0; 12 + 8 * channels.len()];
        domain[..2].copy_from_slice(&permission.country);
        domain[4..7].fill(1);
        domain[3 + usize::from(band.scan_tag())] = permission.domain_width();
        domain[7 + usize::from(band.scan_tag())] = channels.len() as u8;
        for (index, ch) in channels.into_iter().enumerate() {
            domain[12 + index * 8..14 + index * 8].copy_from_slice(&u16::from(ch).to_le_bytes());
        }
        self.check_station_tx()?;
        self.notify(
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &domain,
        )
        .await?;
        self.check_station_tx()?;
        self.notify(
            Command::Ce {
                id: 0x5d,
                query: false,
            },
            &limits,
        )
        .await?;
        self.confirm_command_progress().await?;
        self.check_station_tx()?;
        let mut switch = [0; cmd::CHANNEL_SWITCH_SIZE];
        cmd::encode_channel_switch(
            channel,
            permission.center_channel(),
            permission.native_width(),
            tx_streams,
            (1 << info.capabilities.phy.spatial_streams.min(2)) - 1,
            band.switch_tag(),
            &mut switch,
        )
        .ok_or(Error::Bounds)?;
        self.exchange_station(
            Command::Extended {
                id: crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH,
                query: false,
            },
            &switch,
        )
        .await?;
        Ok(())
    }

    /// Advance recipient BA and declined requests under the retained control
    /// owner. Dropping this future cannot restore an associated producer.
    async fn service_control_in(&mut self, associated: State, restore: State) -> Result<(), Error> {
        if self.station.wmm_pending.is_none()
            && !self.policy_changed(&self.station)
            && self.station.ps_wanted == self.station.ps_applied
            && self.station.control_pending.is_empty()
            && !self.station.rx_ba.pending(self.backend.now_ns())
            && !self.station.tx_ba.pending(self.backend.now_ns())
            || !self.data_pending.is_empty()
        {
            return Ok(());
        }
        let State::Associated { info, peer, .. } = associated else {
            return Ok(());
        };
        if self.station.peer_lost
            || self
                .station
                .security
                .as_ref()
                .is_some_and(|security| security.has_pending())
        {
            return Ok(());
        }
        self.stage(Stage::StaRecord);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.service_regulatory(info).await?;
            self.service_wmm_update().await?;
            self.service_power_save().await?;
            self.service_transmit_ba().await?;
            self.service_receive_ba(info.capabilities.mac, peer).await?;
            for _ in 0..4 {
                let Some(frame) = self.station.control_pending.pop_front() else {
                    break;
                };
                self.send_management(&frame, u16::from(self.station.link.peer()))
                    .await?;
            }
            self.check_station_tx()
        }
        .await;
        self.boot_started = None;
        if let Err(error) = result {
            self.station.security = None;
            self.station.wmm = None;
            self.station.wmm_pending = None;
            self.station.permission = None;
            self.station.ht20_profile = None;
            self.station.vht_profile = None;
            self.station.he_profile = None;
            self.station.ap_phy = None;
            self.station.ht20_rx = None;
            self.station.rx_ba.fence();
            self.station.tx_ba.fence();
            self.station.control_pending.clear();
            self.station.tx_fragments.clear();
            self.station.received_msdu.clear();
            self.state = State::Failed {
                stage: Stage::StaRecord,
                error,
            };
            return Err(error);
        }
        self.state = restore;
        Ok(())
    }

    /// Native SET_EDCA_PARMS is a no-reply command. Order it with Linux's
    /// matching PSE read, preserving the current grant around both waits.
    /// The caller already drained all native DATA tokens and moved the owner
    /// out of Associated before its first await; cancellation leaves it closed.
    async fn service_wmm_update(&mut self) -> Result<(), Error> {
        let Some(parameters) = self.station.wmm_pending else {
            return Ok(());
        };
        self.check_station_tx()?;
        self.notify(
            Command::Ce {
                id: 0x1d,
                query: false,
            },
            &crate::mt7921::association::wmm::on_vif(
                self.station.link.vif(),
                parameters.edca_limited(self.station.permission.and_then(|p| p.wmm_rule())),
            ),
        )
        .await?;
        self.check_station_tx()?;
        self.confirm_command_progress().await?;
        self.check_station_tx()?;
        self.station.wmm = Some(parameters);
        self.station.wmm_pending = None;
        Ok(())
    }

    /// Every association/key/port publication earns fresh authority after
    /// the preceding wait. Cleanup deliberately uses plain exchange instead.
    /// The installed regulatory policy is no longer the one this station's
    /// grant and firmware limits were programmed from.
    pub(super) fn policy_changed(&self, station: &super::StationLink) -> bool {
        // Compared by value: reinstalling identical rules is no change.
        station.applied_policy.as_ref().is_some_and(|applied| {
            self.backend
                .regulatory_domain()
                .is_ok_and(|now| !alloc::sync::Arc::ptr_eq(applied, &now) && **applied != *now)
        })
    }

    /// cfg80211's `reg_notifier` -> `mt7921_regd_notifier` for an associated
    /// station: the same BSS is re-admitted under the new policy and its
    /// channel domain and power limits are programmed again
    /// (`mt76_connac_mcu_set_channel_domain`, `mt76_connac_mcu_set_rate_txpower`).
    /// A policy that no longer permits the operating channel at the same
    /// width ends the link (`reg_leave_invalid_chans`).
    async fn service_regulatory(&mut self, info: super::RadioInfo) -> Result<(), Error> {
        if !self.policy_changed(&self.station) {
            return Ok(());
        }
        let now = self.backend.regulatory_domain()?;
        let (Some(old), Some(bss)) = (self.station.permission, self.station.bss.clone()) else {
            return Err(Error::Authority);
        };
        let new = crate::mt7921::association::TxPermission::from_ap_heard(
            &now,
            info,
            &bss,
            old.follows_heard_ap(),
        )
        .filter(|new| new.same_operation(old));
        let Some(new) = new else {
            self.station.peer_lost = true;
            self.station.rx_ba.fence();
            self.station.tx_ba.fence();
            return Err(Error::Authority);
        };
        let band = new.band().ok_or(Error::Bounds)?;
        let limits = new
            .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
            .ok_or(Error::Bounds)?;
        // The new grant is current under the new policy; the old one may
        // not be (a lower power ceiling).
        self.station.permission = Some(new);
        self.check_station_tx()?;
        self.notify(
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &station_channel_domain(new, band),
        )
        .await?;
        self.notify(
            Command::Ce {
                id: 0x5d,
                query: false,
            },
            &limits,
        )
        .await?;
        self.confirm_command_progress().await?;
        self.station.applied_policy = Some(now);
        self.check_station_tx()
    }

    /// mt7921_mcu_uni_bss_ps (`BSS_CHANGED_PS`): UNI_CMD BSS_INFO_UPDATE
    /// with the `UNI_BSS_INFO_PS` (21) TLV, `ps_state` 2 (dynamic power
    /// save, firmware-timed) or 0 (awake), for this link's BSS.
    async fn service_power_save(&mut self) -> Result<(), Error> {
        if self.station.ps_wanted == self.station.ps_applied {
            return Ok(());
        }
        let body = bss_power_save(self.station.link.bss(), self.station.ps_wanted);
        self.exchange_station(Command::Unified { id: 2 }, &body)
            .await?;
        self.station.ps_applied = self.station.ps_wanted;
        Ok(())
    }

    pub(super) async fn exchange_station(
        &mut self,
        command: Command,
        body: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.check_station_tx()?;
        let reply = self.exchange(command, body).await?;
        self.check_station_tx()?;
        Ok(reply)
    }

    /// Linux drains the SKU command through MCU's PSE register read. Match
    /// the actual register identity and exact native receipt, not merely any
    /// command reply. The same bounded operation orders EDCA before QoS TX.
    pub(super) async fn confirm_command_progress(&mut self) -> Result<(), Error> {
        let mut request = [0; 8];
        request[..4].copy_from_slice(&0x820c8000u32.to_le_bytes());
        let reply = self
            .exchange(
                Command::Ce {
                    id: 0xc0,
                    query: true,
                },
                &request,
            )
            .await?;
        if reply.len() != 8 || reply[..4] != request[..4] {
            return Err(Error::MalformedEvent);
        }
        Ok(())
    }
}

/// The `mt7921_mcu_uni_bss_ps` request: `{ bss_idx, pad[3] }` then the
/// `UNI_BSS_INFO_PS` TLV `{ tag 21, len 8, ps_state, pad[3] }`.
pub(super) fn bss_power_save(bss: u8, enabled: bool) -> [u8; 12] {
    let mut body = [0; 12];
    body[0] = bss;
    body[4..6].copy_from_slice(&21u16.to_le_bytes());
    body[6..8].copy_from_slice(&8u16.to_le_bytes());
    body[8] = if enabled { 2 } else { 0 };
    body
}

/// The station's channel domain (`mt76_connac_mcu_set_channel_domain`):
/// the occupied channels of `permission` with NO_IR cleared, everything
/// else absent.
pub(super) fn station_channel_domain(
    permission: crate::mt7921::association::TxPermission,
    band: crate::mt7921::channel::Band,
) -> Vec<u8> {
    let channels = permission.channels();
    let mut domain = vec![0u8; 12 + 8 * channels.len()];
    domain[..2].copy_from_slice(&permission.country);
    domain[4..7].fill(1); // 20 MHz
    domain[3 + usize::from(band.scan_tag())] = permission.domain_width();
    domain[7 + usize::from(band.scan_tag())] = channels.len() as u8;
    for (index, channel) in channels.into_iter().enumerate() {
        domain[12 + index * 8..14 + index * 8].copy_from_slice(&u16::from(channel).to_le_bytes());
        // Flags zero only after complete occupied-channel admission.
    }
    domain
}
