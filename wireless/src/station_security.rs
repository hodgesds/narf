//! Retained WPA2-PSK or WPA3-SAE/CCMP owner. Shared Supplicant owns EAPOL
//! authentication; this unit binds native peers, packet keys and exact
//! reply-delivery commits. A SAE association (AKM 8/24) negotiates PMF:
//! the M3/group IGTK is retained for BIP and unicast robust management
//! frames are CCMP-protected (IEEE802.11-2020 11.13, 12.5.3, 12.5.4).
use crate::eapol::{EapolRx, EapolRxError, Gtk, KeyMgmt, RsnaParams, Supplicant};
use crate::packet_key::{self, Key, Role};
use alloc::{vec, vec::Vec};
use zeroize::{Zeroize, Zeroizing};

/// Native receive admission supplied by the hardware adapter. The adapter
/// must bind the descriptor to its current peer/channel/profile, reject
/// transport/CRC/fragment errors, and retain the original native 802.11 bytes.
/// Hardware-decrypted or firmware-decapsulated data is not admitted here.
/// This trait grants no radio, key, carrier or controlled-port authority.
pub trait RawFrame {
    fn bytes(&self) -> &[u8];
    /// True only for an original MPDU in this adapter's admitted PHY profile.
    fn unmodified(&self) -> bool;
}

const HISTORY: usize = 16;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    State,
    Profile,
    Protocol,
    Allocation,
    Entropy,
    KeyReuse,
    Crypto(packet_key::Error),
}
/// A received management frame after PMF admission.
#[derive(Debug, PartialEq, Eq)]
pub enum MgmtRx {
    /// Dropped: unprotected robust frame under PMF, failed CCMP/BIP, a
    /// replay, or another peer.
    Ignored,
    /// The admitted frame with Protected cleared and CCMP header/MIC or
    /// MMIE removed (non-robust frames are returned unchanged).
    Frame(Vec<u8>),
}
#[derive(Debug, PartialEq, Eq)]
pub enum Rx {
    Ignored,
    ReplyReady,
    Data(Vec<u8>),
}
struct Slot {
    material: Zeroizing<[u8; 16]>,
    key: Key,
}
struct Group {
    id: u8,
    material: Zeroizing<[u8; 16]>,
    rsc: u64,
}
struct IgtkChange {
    id: u16,
    material: Zeroizing<[u8; 16]>,
    ipn: u64,
}
struct Change {
    pair: Option<Zeroizing<[u8; 16]>>,
    group: Option<Group>,
    igtk: Option<IgtkChange>,
    opens: bool,
}
struct Pending {
    frame: Vec<u8>,
    change: Change,
}
/// Remember rejected retired material for the full owner lifetime. An old
/// TK cannot reappear in a fresh Key with reset PN/replay state. History is
/// bounded; exhausting it terminates the owner rather than evicting evidence.
pub struct Security {
    own: [u8; 6],
    peer: [u8; 6],
    supplicant: Supplicant,
    pair: Option<Slot>,
    group: [Option<Slot>; 4],
    history: Vec<Zeroizing<[u8; 16]>>,
    pending: Option<Pending>,
    established: bool,
    failed: bool,
    sequence: u16,
    qos_sequence: [u16; 16],
    spp_amsdu: bool,
    /// PMF negotiated (SAE): IGTK required, robust management protected.
    pmf: bool,
    igtk: crate::mfp::MfpKeyStore,
}
impl core::fmt::Debug for Security {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StationSecurity")
            .field("port_open", &self.port_open())
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
fn ie(id: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    if body.len() > 255 {
        return Err(Error::Profile);
    }
    let mut out = vec![id, body.len() as u8];
    out.extend_from_slice(body);
    Ok(out)
}
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
impl Security {
    /// Caller supplies the already-negotiated station/AP RSNE bodies from
    /// the immutable join candidate, plus the retained device/AP identities.
    pub fn new(
        own: [u8; 6],
        peer: [u8; 6],
        pmk: &[u8; 32],
        station_rsne: &[u8],
        ap_rsne: &[u8],
        ap_rsnxe: Option<&[u8]>,
        sequence: u16,
    ) -> Result<Self, Error> {
        let owner = Self::new_inner(
            own,
            peer,
            pmk,
            station_rsne,
            None,
            ap_rsne,
            ap_rsnxe,
            sequence,
        )?;
        if owner.pmf {
            // SAE needs its RSNXE and the PMF owner: use `new_sae`.
            return Err(Error::Profile);
        }
        Ok(owner)
    }
    /// A WPA3-SAE owner: `pmk` is the accepted `SaeSession` PMK, the
    /// station RSNE/RSNXE are `JoinPlan::rsn_body()` and the plan's
    /// `SaeJoin::station_rsnxe()` (both repeated in message 2/4).
    #[allow(clippy::too_many_arguments)]
    pub fn new_sae(
        own: [u8; 6],
        peer: [u8; 6],
        pmk: &[u8; 32],
        station_rsne: &[u8],
        station_rsnxe: Option<&[u8]>,
        ap_rsne: &[u8],
        ap_rsnxe: Option<&[u8]>,
        sequence: u16,
    ) -> Result<Self, Error> {
        let owner = Self::new_inner(
            own,
            peer,
            pmk,
            station_rsne,
            station_rsnxe,
            ap_rsne,
            ap_rsnxe,
            sequence,
        )?;
        if !owner.pmf {
            return Err(Error::Profile);
        }
        Ok(owner)
    }
    /// True for a PMF (SAE) association.
    pub fn pmf(&self) -> bool {
        self.pmf
    }
    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        own: [u8; 6],
        peer: [u8; 6],
        pmk: &[u8; 32],
        station_rsne: &[u8],
        station_rsnxe: Option<&[u8]>,
        ap_rsne: &[u8],
        ap_rsnxe: Option<&[u8]>,
        sequence: u16,
    ) -> Result<Self, Error> {
        if station_rsnxe.is_some_and(|b| b.is_empty() || usize::from(b[0] & 15) + 1 != b.len()) {
            return Err(Error::Profile);
        }
        if station_rsne.len() > 255
            || ap_rsne.len() > 255
            || ap_rsnxe.is_some_and(|b| b.len() > 255)
            || !unicast(own)
            || !unicast(peer)
            || own == peer
            || sequence > 4095
        {
            return Err(Error::Profile);
        }
        // The station RSNE is the canonical WPA2-PSK/CCMP body, optionally
        // advertising SPP A-MSDU Capable (RSN Capabilities bit10), or the
        // JoinPlan SAE body: CCMP-128, AKM 8 or 24, MFPC|MFPR, at most the
        // one SAE PMKID and the default BIP-CMAC-128.
        use crate::rsn::{self, Suite};
        let station = crate::rsn::RsnIe::decode_body(station_rsne).ok_or(Error::Profile)?;
        let ccmp = Suite::standard(rsn::CIPHER_CCMP_128);
        let mfp = rsn::RSN_CAP_MFP_REQUIRED | rsn::RSN_CAP_MFP_CAPABLE;
        let key_mgmt = match station.akms.as_slice() {
            [akm] if *akm == Suite::standard(rsn::AKM_SAE) => KeyMgmt::Sae,
            [akm] if *akm == Suite::standard(rsn::AKM_SAE_EXT_KEY) => KeyMgmt::SaeExtKey,
            _ => KeyMgmt::Psk,
        };
        let pmf = key_mgmt.sae();
        if pmf {
            if station.group_cipher != ccmp
                || station.pairwise_ciphers != [ccmp]
                || station.rsn_capabilities != mfp
                || station.pmkids.len() > 1
                || station
                    .group_management_cipher
                    .is_some_and(|c| c != Suite::standard(rsn::CIPHER_BIP_CMAC_128))
            {
                return Err(Error::Profile);
            }
        } else {
            let mut canonical = crate::rsn::RsnIe::wpa2_psk_ccmp();
            canonical.rsn_capabilities =
                station.rsn_capabilities & crate::rsn::RSN_CAP_SPP_AMSDU_CAPABLE;
            if station != canonical {
                return Err(Error::Profile);
            }
        }
        let ap = crate::rsn::RsnIe::decode_body(ap_rsne).ok_or(Error::Profile)?;
        let ap_mfp_ok = if pmf {
            ap.rsn_capabilities & rsn::RSN_CAP_MFP_CAPABLE != 0
                && ap
                    .group_management_cipher
                    .is_none_or(|c| c == Suite::standard(rsn::CIPHER_BIP_CMAC_128))
        } else {
            ap.rsn_capabilities & rsn::RSN_CAP_MFP_REQUIRED == 0
        };
        if ap.group_cipher != ccmp
            || !ap.pairwise_ciphers.contains(&ccmp)
            || !ap.akms.contains(&Suite::standard(key_mgmt.suite_type()))
            || ap.rsn_capabilities & rsn::RSN_CAP_NO_PAIRWISE != 0
            || !ap_mfp_ok
            || ap_rsnxe.is_some_and(|b| b.is_empty() || usize::from(b[0] & 15) + 1 != b.len())
        {
            return Err(Error::Profile);
        }
        Ok(Self {
            own,
            peer,
            supplicant: Supplicant::new(peer, own, [0; 32]).with_rsna(RsnaParams {
                key_mgmt,
                pmk: pmk.to_vec(),
                assoc_ie: {
                    let mut assoc = ie(48, station_rsne)?;
                    if let Some(rsnxe) = station_rsnxe {
                        assoc.extend_from_slice(&ie(244, rsnxe)?);
                    }
                    assoc
                },
                ap_rsn_ie: ie(48, ap_rsne)?,
                ap_rsnxe: ap_rsnxe.map(|b| ie(244, b)).transpose()?,
                pairwise_key_len: 16,
                group_key_len: 16,
                mgmt_group_key_len: pmf.then_some(16),
                pmf,
            }),
            pair: None,
            group: core::array::from_fn(|_| None),
            history: Vec::new(),
            pending: None,
            established: false,
            failed: false,
            sequence,
            qos_sequence: [sequence; 16],
            // IEEE802.11-2020 12.5.3.3.3: SPP A-MSDU applies only when both
            // STAs advertise SPP A-MSDU Capable.
            spp_amsdu: station.rsn_capabilities
                & ap.rsn_capabilities
                & rsn::RSN_CAP_SPP_AMSDU_CAPABLE
                != 0,
            pmf,
            igtk: crate::mfp::MfpKeyStore::new(),
        })
    }
    /// True when both the retained station and AP RSNEs advertised SPP
    /// A-MSDU Capable, so pairwise CCMP authenticates A-MSDU Present.
    pub fn spp_amsdu(&self) -> bool {
        self.spp_amsdu
    }
    pub fn port_open(&self) -> bool {
        !self.failed
            && self.established
            && self.pending.is_none()
            && self.pair.is_some()
            && self.group.iter().any(Option::is_some)
    }
    /// A reply still awaits terminal delivery, or M2 has been delivered and
    /// the retained supplicant still awaits M3. During an established rekey,
    /// the old-key controlled port may reopen before this exchange finishes.
    /// Drivers use this independently of carrier/port state for their timeout.
    pub fn handshake_active(&self) -> bool {
        !self.failed
            && (self.pending.is_some()
                || self.supplicant.state == crate::eapol::FourWayState::WaitM3)
    }
    pub fn fail(&mut self) {
        self.failed = true;
        self.established = false;
    }
    pub fn pending_frame(&self) -> Option<&[u8]> {
        if self.failed {
            None
        } else {
            self.pending.as_ref().map(|p| p.frame.as_slice())
        }
    }
    fn normalize(&mut self, mpdu: &impl RawFrame) -> Result<Option<Vec<u8>>, Error> {
        let b = mpdu.bytes();
        if !mpdu.unmodified()
            || b.len() < 24
            || b.len() > 4096
            || !matches!(b[0], 8 | 0x88)
            || b[1] & 0x87 != 2
            || b[22] & 15 != 0
            || b[10..16] != self.peer
            || !unicast(b[16..22].try_into().unwrap())
            || b[4..10] != self.own && b[4] & 1 == 0
        {
            return Ok(None);
        }
        let length = if b[0] == 0x88 { 26 } else { 24 };
        if b.len() < length || length == 26 && b[24] & 0x80 != 0 {
            return Ok(None);
        }
        if b[1] & 0x40 == 0 {
            return Ok(Some(b.to_vec()));
        }
        let wire = b.get(length..).ok_or(Error::Protocol)?;
        let key_id = wire.get(3).ok_or(Error::Protocol)? >> 6;
        let slot = if b[4] & 1 != 0 {
            self.group[usize::from(key_id)].as_mut()
        } else {
            if key_id != 0 {
                return Ok(None);
            }
            self.pair.as_mut()
        };
        let Some(slot) = slot else { return Ok(None) };
        let mut wire = wire.to_vec();
        let plaintext = match slot.key.unprotect(&b[..length], &mut wire) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        let mut normalized = b[..length].to_vec();
        normalized[1] &= !0x40;
        normalized.extend_from_slice(&plaintext);
        Ok(Some(normalized))
    }
    /// A caller obtains fresh_snonce from the CSPRNG, never frame contents.
    /// Pending replies are serialized through the same retained transport TX owner.
    pub fn receive(&mut self, mpdu: &impl RawFrame, fresh_snonce: [u8; 32]) -> Result<Rx, Error> {
        self.receive_with_nonce(mpdu, || Some(fresh_snonce))
    }
    /// Receive one original protected QoS A-MSDU after the driver proves its
    /// actual native HT/peer/channel/descriptor profile. The established
    /// controlled port and current installed PTK/GTK are required before
    /// any crypto or replay state can change. Malformed input is ignored;
    /// complete authenticated subframes are returned as Ethernet-II frames.
    /// A-MSDU cannot supply EAPOL or drive the retained supplicant/rekey.
    pub fn receive_amsdu(&mut self, mpdu: &impl RawFrame) -> Result<Option<Vec<Vec<u8>>>, Error> {
        Ok(self
            .receive_amsdu_with(mpdu, packet_key::AmsduAdmission::new())?
            .map(|r| r.frames))
    }
    /// Admit normal/BlockAck-policy original A-MSDUs only after the driver
    /// proves a live BA agreement and releases this MPDU in native SN order.
    /// Default receive_amsdu remains normal-ACK-only; no header is rewritten.
    pub fn receive_amsdu_block_ack(
        &mut self,
        mpdu: &impl RawFrame,
    ) -> Result<Option<Vec<Vec<u8>>>, Error> {
        Ok(self
            .receive_amsdu_with(mpdu, packet_key::AmsduAdmission::new().with_block_ack(true))?
            .map(|r| r.frames))
    }
    /// Receive an original protected A-MSDU under the explicit ack-policy,
    /// EOSP and size opt-ins the driver's native receive path has proved.
    /// The same port/peer/key/replay rules as `receive_amsdu` apply, and the
    /// result carries the original TID, Ack Policy and EOSP facts.
    pub fn receive_amsdu_with(
        &mut self,
        mpdu: &impl RawFrame,
        admission: packet_key::AmsduAdmission,
    ) -> Result<Option<packet_key::AmsduReceive>, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        let bytes = mpdu.bytes();
        if !mpdu.unmodified()
            || !(26 + 16 + 22..=26 + 16 + admission.limit().bytes()).contains(&bytes.len())
        {
            return Ok(None);
        }
        let header = &bytes[..26];
        if packet_key::aggregate_header_with(header, admission).is_err()
            || header[10..16] != self.peer
            || !unicast(header[16..22].try_into().unwrap())
            || header[4..10] != self.own && header[4] & 1 == 0
        {
            return Ok(None);
        }
        let wire = &bytes[26..];
        let id = usize::from(wire[3] >> 6);
        let slot = if header[4] & 1 != 0 {
            self.group[id].as_mut()
        } else if id == 0 {
            self.pair.as_mut()
        } else {
            None
        };
        let Some(slot) = slot else {
            return Ok(None);
        };
        Ok(slot.key.unprotect_amsdu_with(header, wire, admission).ok())
    }
    pub fn receive_with_nonce(
        &mut self,
        mpdu: &impl RawFrame,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        let result = self.receive_inner(mpdu, fresh_snonce);
        if result.as_ref().is_err_and(|e| *e != Error::State) {
            self.fail();
        }
        result
    }
    fn receive_inner(
        &mut self,
        mpdu: &impl RawFrame,
        fresh_snonce: impl FnMut() -> Option<[u8; 32]>,
    ) -> Result<Rx, Error> {
        if self.failed || self.pending.is_some() {
            return Err(Error::State);
        }
        let protected = mpdu.bytes().get(1).is_some_and(|b| b & 0x40 != 0);
        let Some(frame) = self.normalize(mpdu)? else {
            return Ok(Rx::Ignored);
        };
        let offset = if frame[0] == 0x88 { 26 } else { 24 };
        let Some(snap) = frame.get(offset..offset + 8) else {
            return Ok(Rx::Ignored);
        };
        if snap[..6] != [0xaa, 0xaa, 3, 0, 0, 0] {
            return Ok(Rx::Ignored);
        }
        if snap[6..] != [0x88, 0x8e] {
            return if self.port_open() && protected {
                Ok(Rx::Data(frame))
            } else {
                Ok(Rx::Ignored)
            };
        }
        // Only the negotiated authenticator's unicast native FromDS EAPOL
        // reaches the supplicant. A group/source alias never becomes EAPOL.
        if frame[4..10] != self.own || frame[16..22] != self.peer {
            return Ok(Rx::Ignored);
        }
        let pdu = &frame[offset + 8..];
        if pdu.len() < 4
            || !(1..=3).contains(&pdu[0])
            || pdu[1] != 3
            || usize::from(u16::from_be_bytes([pdu[2], pdu[3]])) + 4 != pdu.len()
        {
            return Ok(Rx::Ignored);
        }
        let processed = match self
            .supplicant
            .rx_eapol_with_nonce(pdu, protected, fresh_snonce)
        {
            Ok(rx) => rx,
            Err(EapolRxError::Drop(_)) => return Ok(Rx::Ignored),
            Err(EapolRxError::NonceUnavailable) => return Err(Error::Entropy),
            Err(_) => {
                self.fail();
                return Err(Error::Protocol);
            }
        };
        let pmf = self.pmf;
        let first = self.pair.is_none();
        let (reply, pair, gtk, igtk, opens) = match processed {
            EapolRx::Pairwise1(m1) => (m1.reply, None, None, None, false),
            EapolRx::Pairwise3(mut m3) => {
                // Without PMF an IGTK is a protocol error; with PMF the
                // first M3 must deliver it (IEEE802.11-2020 12.7.6.4).
                if !m3.secure || m3.igtk.is_some() && !pmf || pmf && first && m3.igtk.is_none() {
                    if let Some(t) = &mut m3.tk {
                        t.zeroize();
                    }
                    if let Some(g) = &mut m3.gtk {
                        g.key.zeroize();
                    }
                    if let Some(igtk) = &mut m3.igtk {
                        igtk.key.zeroize();
                    }
                    self.fail();
                    return Err(Error::Protocol);
                }
                (m3.reply, m3.tk, m3.gtk, m3.igtk, true)
            }
            EapolRx::Group1(mut g) => {
                if !self.established || g.igtk.is_some() && !pmf || matches!(g.igtk, Some(Err(())))
                {
                    if let Some(gtk) = &mut g.gtk {
                        gtk.key.zeroize();
                    }
                    if let Some(Ok(Some(igtk))) = &mut g.igtk {
                        igtk.key.zeroize();
                    }
                    self.fail();
                    return Err(Error::Protocol);
                }
                let igtk = match g.igtk {
                    Some(Ok(igtk)) => igtk,
                    _ => None,
                };
                (g.reply, None, g.gtk, igtk, false)
            }
        };
        let igtk = igtk
            .map(|mut k: crate::eapol::Igtk| {
                let result = if !(4..=5).contains(&k.key_id) || k.key.len() != 16 {
                    Err(Error::Protocol)
                } else {
                    let mut ipn = [0; 8];
                    ipn[..6].copy_from_slice(&k.ipn);
                    Ok(IgtkChange {
                        id: k.key_id,
                        material: Zeroizing::new(k.key.as_slice().try_into().unwrap()),
                        ipn: u64::from_le_bytes(ipn),
                    })
                };
                k.key.zeroize();
                result
            })
            .transpose()?;
        let pair = pair.map(Zeroizing::new);
        let gtk = gtk
            .map(|mut g: Gtk| {
                let result = if g.key_id > 3 || g.key.len() != 16 || g.rsc[6..] != [0, 0] {
                    Err(Error::Protocol)
                } else {
                    Ok(Group {
                        id: g.key_id,
                        material: Zeroizing::new(g.key.as_slice().try_into().unwrap()),
                        rsc: u64::from_le_bytes(g.rsc),
                    })
                };
                g.key.zeroize();
                result
            })
            .transpose()?;
        let pair = pair
            .map(|p| {
                p.as_slice()
                    .try_into()
                    .map(Zeroizing::new)
                    .map_err(|_| Error::Protocol)
            })
            .transpose()?;
        let change = Change {
            pair,
            group: gtk,
            igtk,
            opens,
        };
        if let Err(error) = self.validate_change(&change) {
            self.fail();
            return Err(error);
        }
        let mut header = vec![8, 1, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&(self.sequence << 4).to_le_bytes());
        self.sequence = (self.sequence + 1) & 4095;
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e];
        body.extend_from_slice(&reply);
        // During a PTK rekey, M2/M4 use the still-installed old packet key.
        // The shared supplicant's newly verified PTK is committed below only
        // after this exact old-key-protected reply reaches terminal delivery.
        let frame = if let Some(old) = &mut self.pair {
            header[1] |= 0x40;
            let wire = old.key.protect(&header, &body).map_err(Error::Crypto)?;
            header.extend_from_slice(&wire);
            header
        } else {
            header.extend_from_slice(&body);
            header
        };
        self.pending = Some(Pending { frame, change });
        Ok(Rx::ReplyReady)
    }
    /// Ring clients submit Ethernet data only. Native EAPOL is exclusively
    /// generated by the retained supplicant, before this controlled port.
    pub fn transmit_ethernet(&mut self, ethernet: &[u8]) -> Result<Vec<u8>, Error> {
        self.transmit_ethernet_inner(ethernet, None)
    }
    /// Form the QoS header before CCMP authenticates its TID and nonce. The
    /// caller must separately own negotiated WMM/EDCA and native QoS admission.
    /// This helper grants no PHY/aggregation/U-APSD or packet-queue capability.
    pub fn transmit_ethernet_qos(&mut self, ethernet: &[u8], tid: u8) -> Result<Vec<u8>, Error> {
        if tid > 15 {
            return Err(Error::Profile);
        }
        self.transmit_ethernet_inner(ethernet, Some(tid))
    }
    /// Aggregate station-originated Ethernet-II frames into one protected
    /// QoS A-MSDU MPDU for `tid` (IEEE802.11-2020 9.3.2.2.2). Every frame
    /// must carry this station's SA and an ordinary Ethernet-II protocol; the
    /// control port, tunnels and VLAN-encapsulated control ports are rejected,
    /// so EAPOL is never aggregated. The outer Address3 is the BSSID per Table
    /// 9-30, Normal Ack is used and one QoS SN plus one PN are consumed. The
    /// caller must hold a peer-advertised `limit` and its own negotiated
    /// PHY/aggregation/queue admission; this grants none of them.
    pub fn transmit_amsdu_qos(
        &mut self,
        frames: &[&[u8]],
        tid: u8,
        limit: crate::amsdu::Limit,
    ) -> Result<Vec<u8>, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        if tid > 15 {
            return Err(Error::Profile);
        }
        let body = crate::amsdu::encode(frames, self.own, limit).map_err(|_| Error::Profile)?;
        let mut header = vec![0x88, 0x41, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&self.peer);
        let sequence = self.qos_sequence[usize::from(tid)];
        header.extend_from_slice(&(sequence << 4).to_le_bytes());
        header.extend_from_slice(&[0x80 | tid, 0]);
        let result = self
            .pair
            .as_mut()
            .ok_or(Error::State)?
            .key
            .protect_amsdu(&header, &body, limit);
        let wire = match result {
            Ok(wire) => wire,
            Err(error) => {
                self.fail();
                return Err(Error::Crypto(error));
            }
        };
        self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
        header.extend_from_slice(&wire);
        Ok(header)
    }
    /// Sample the next exact QoS SN without consuming it or a key PN.
    /// Native BA callers must freeze their producer and drain all preceding
    /// packets before using it as an ADDBA SSN; this value grants no BA or
    /// native queue authority. Non-QoS/EAPOL traffic cannot advance it.
    pub fn next_qos_sequence(&self, tid: u8) -> Result<u16, Error> {
        let sequence = self
            .qos_sequence
            .get(usize::from(tid))
            .ok_or(Error::Profile)?;
        if !self.port_open() {
            return Err(Error::State);
        }
        Ok(*sequence)
    }
    fn transmit_ethernet_inner(
        &mut self,
        ethernet: &[u8],
        tid: Option<u8>,
    ) -> Result<Vec<u8>, Error> {
        if !self.port_open() {
            return Err(Error::State);
        }
        if !(14..=1514).contains(&ethernet.len())
            || ethernet[6..12] != self.own
            || ethernet[..6] == [0; 6]
        {
            return Err(Error::Profile);
        }
        let protocol = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        if protocol < 0x600 || matches!(protocol, 0x888e | 0x80f3 | 0x8137) {
            return Err(Error::Profile);
        }
        let mut header = vec![if tid.is_some() { 0x88 } else { 8 }, 0x41, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&ethernet[..6]);
        let sequence = tid.map_or(self.sequence, |tid| self.qos_sequence[usize::from(tid)]);
        header.extend_from_slice(&(sequence << 4).to_le_bytes());
        if let Some(tid) = tid {
            header.extend_from_slice(&[tid, 0]);
        }
        if let Some(tid) = tid {
            self.qos_sequence[usize::from(tid)] = (sequence + 1) & 4095;
        } else {
            self.sequence = (sequence + 1) & 4095;
        }
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0];
        body.extend_from_slice(&ethernet[12..]);
        let result = self
            .pair
            .as_mut()
            .ok_or(Error::State)?
            .key
            .protect(&header, &body);
        let wire = match result {
            Ok(wire) => wire,
            Err(error) => {
                self.fail();
                return Err(Error::Crypto(error));
            }
        };
        header.extend_from_slice(&wire);
        Ok(header)
    }
    fn validate_change(&mut self, c: &Change) -> Result<(), Error> {
        let mut fresh = 0;
        if let Some(material) = &c.pair {
            if self
                .pair
                .as_ref()
                .is_none_or(|old| *old.material != **material)
            {
                if self.history.iter().any(|old| **old == **material) {
                    return Err(Error::KeyReuse);
                }
                fresh += 1;
            }
        }
        if let Some(group) = &c.group {
            if self.group[usize::from(group.id)]
                .as_ref()
                .is_none_or(|old| *old.material != *group.material)
            {
                if self.history.iter().any(|old| **old == *group.material)
                    || c.pair.as_ref().is_some_and(|p| **p == *group.material)
                {
                    return Err(Error::KeyReuse);
                }
                fresh += 1;
            }
        }
        if let Some(igtk) = &c.igtk {
            if self
                .igtk
                .find_by_key_id(igtk.id)
                .is_none_or(|old| old.key != *igtk.material)
            {
                if self.history.iter().any(|old| **old == *igtk.material)
                    || c.pair.as_ref().is_some_and(|p| **p == *igtk.material)
                    || c.group
                        .as_ref()
                        .is_some_and(|g| *g.material == *igtk.material)
                {
                    return Err(Error::KeyReuse);
                }
                fresh += 1;
            }
        }
        if c.opens && c.pair.is_none() && self.pair.is_none()
            || c.opens && self.pmf && c.igtk.is_none() && self.igtk.active.is_none()
            || self.history.len() + fresh > HISTORY
        {
            return Err(Error::Protocol);
        }
        self.history
            .try_reserve(fresh)
            .map_err(|_| Error::Allocation)
    }
    /// The packet owner has proved exact terminal host delivery. This never
    /// treats submission, a quiet poll or an on-air guess as M4 completion.
    pub fn reply_delivered(&mut self, native_bytes: usize) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        let Some(pending) = self.pending.take() else {
            return Err(Error::State);
        };
        if pending.frame.len() != native_bytes {
            self.fail();
            return Err(Error::Protocol);
        }
        if let Some(material) = pending.change.pair {
            if let Some(old) = &mut self.pair {
                if *old.material == *material {
                    old.key.reinstall(&material, 0).map_err(Error::Crypto)?;
                } else {
                    let key = Key::new(&material, 0, Role::Pairwise, self.own, self.peer, 0)
                        .and_then(|key| key.with_spp_amsdu(self.spp_amsdu))
                        .map_err(Error::Crypto)?;
                    self.history.push(Zeroizing::new(*material));
                    self.pair = Some(Slot { material, key });
                }
            } else {
                let key = Key::new(&material, 0, Role::Pairwise, self.own, self.peer, 0)
                    .and_then(|key| key.with_spp_amsdu(self.spp_amsdu))
                    .map_err(Error::Crypto)?;
                self.history.push(Zeroizing::new(*material));
                self.pair = Some(Slot { material, key });
            }
            self.supplicant.pairwise_key_installed();
        }
        if let Some(group) = pending.change.group {
            let at = usize::from(group.id);
            if self.group[at]
                .as_ref()
                .is_none_or(|old| *old.material != *group.material)
            {
                let key = Key::new(
                    &group.material,
                    group.id,
                    Role::Group,
                    self.own,
                    self.peer,
                    group.rsc,
                )
                .map_err(Error::Crypto)?;
                self.history.push(Zeroizing::new(*group.material));
                self.group[at] = Some(Slot {
                    material: group.material,
                    key,
                });
            }
            let material = &self.group[at].as_ref().unwrap().material;
            self.supplicant
                .group_keys_installed(Some(material.as_slice()), None);
        }
        if let Some(igtk) = pending.change.igtk {
            if self
                .igtk
                .find_by_key_id(igtk.id)
                .is_none_or(|old| old.key != *igtk.material)
            {
                self.igtk
                    .install_active(*igtk.material, igtk.id)
                    .map_err(|_| Error::Protocol)?;
                if let Some(active) = self.igtk.active.as_mut() {
                    // The KDE IPN is the last IPN the AP used; mac80211
                    // seeds rx_pn with it and requires a strictly larger IPN.
                    active.rx_pn = igtk.ipn;
                }
                self.history.push(Zeroizing::new(*igtk.material));
            }
            self.supplicant
                .group_keys_installed(None, Some(igtk.material.as_slice()));
        }
        self.established |= pending.change.opens;
        Ok(())
    }
    /// Robust management frames per Linux `_ieee80211_is_robust_mgmt_frame`.
    fn robust(frame: &[u8]) -> bool {
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
    /// Admit one received management MPDU from the AP under the negotiated
    /// PMF policy (mac80211 `ieee80211_drop_unencrypted_mgmt`,
    /// `ieee80211_crypto_ccmp_decrypt`, `ieee80211_crypto_aes_cmac_decrypt`):
    /// once the PTK is installed, unicast robust frames must be
    /// CCMP-protected with it and group robust frames must carry a valid
    /// BIP MMIE under the installed IGTK. Before keys, or without PMF,
    /// unprotected frames pass unchanged; deauthentication and SA Query
    /// policy remains the MLME owner's.
    pub fn receive_management(&mut self, mpdu: &impl RawFrame) -> Result<MgmtRx, Error> {
        if self.failed {
            return Err(Error::State);
        }
        let b = mpdu.bytes();
        if !mpdu.unmodified()
            || !(24..=4096).contains(&b.len())
            || b[0] & 0x0c != 0
            || b[1] & 0x07 != 0
            || b[22] & 15 != 0
            || b[10..16] != self.peer
            || b[16..22] != self.peer
            || b[4..10] != self.own && b[4] & 1 == 0
        {
            return Ok(MgmtRx::Ignored);
        }
        let protected = b[1] & 0x40 != 0;
        if !self.pmf || self.pair.is_none() || !Self::robust(b) {
            return Ok(if protected {
                MgmtRx::Ignored
            } else {
                MgmtRx::Frame(b.to_vec())
            });
        }
        if b[4] & 1 != 0 {
            // Group-addressed robust frame: unprotected with a BIP MMIE.
            if protected {
                return Ok(MgmtRx::Ignored);
            }
            return Ok(
                match crate::mfp::verify_inbound(&mut self.igtk, &b[..24], &b[24..]) {
                    Ok(body) => {
                        let mut out = b[..24].to_vec();
                        out.extend_from_slice(body);
                        MgmtRx::Frame(out)
                    }
                    Err(_) => MgmtRx::Ignored,
                },
            );
        }
        if !protected {
            return Ok(MgmtRx::Ignored);
        }
        let Some(pair) = self.pair.as_mut() else {
            return Ok(MgmtRx::Ignored);
        };
        let mut wire = b[24..].to_vec();
        match pair.key.unprotect_management(&b[..24], &mut wire) {
            Ok(plain) => {
                let mut out = b[..24].to_vec();
                out[1] &= !0x40;
                out.extend_from_slice(&plain);
                Ok(MgmtRx::Frame(out))
            }
            Err(_) => Ok(MgmtRx::Ignored),
        }
    }
    /// CCMP-protect one unicast robust management frame (Deauthentication,
    /// Disassociation or a robust Action) to the AP after the controlled
    /// port opened under PMF. `frame` is the unprotected MPDU with the
    /// caller's sequence number; the PN is consumed even if the transport
    /// later drops the frame.
    pub fn protect_management(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        if !self.pmf || !self.port_open() {
            return Err(Error::State);
        }
        if !(25..=4096).contains(&frame.len())
            || frame[0] & 0x0c != 0
            || frame[1] & 0x47 != 0
            || frame[22] & 15 != 0
            || !Self::robust(frame)
            || frame[4..10] != self.peer
            || frame[10..16] != self.own
            || frame[16..22] != self.peer
        {
            return Err(Error::Profile);
        }
        let mut header = frame[..24].to_vec();
        header[1] |= 0x40;
        let wire = self
            .pair
            .as_mut()
            .ok_or(Error::State)?
            .key
            .protect_management(&header, &frame[24..])
            .map_err(Error::Crypto)?;
        header.extend_from_slice(&wire);
        Ok(header)
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        if let Some(r) = &mut self.supplicant.rsna {
            r.pmk.zeroize();
        }
        for p in [&mut self.supplicant.ptk, &mut self.supplicant.tptk]
            .into_iter()
            .flatten()
        {
            p.kck.zeroize();
            p.kek.zeroize();
            p.tk.zeroize();
        }
        for key in [&mut self.supplicant.gtk, &mut self.supplicant.igtk]
            .into_iter()
            .flatten()
        {
            key.zeroize();
        }
        self.supplicant.snonce.zeroize();
        for igtk in [&mut self.igtk.active, &mut self.igtk.next]
            .into_iter()
            .flatten()
        {
            igtk.key.zeroize();
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "station_security_tests.rs"]
mod tests;
