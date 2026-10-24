//! Retained WPA2-PSK/CCMP owner. Shared Supplicant owns EAPOL authentication;
//! this unit binds native peers, packet keys and exact reply-delivery commits.
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
struct Change {
    pair: Option<Zeroizing<[u8; 16]>>,
    group: Option<Group>,
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
        if station_rsne.len() > 255
            || ap_rsne.len() > 255
            || ap_rsnxe.is_some_and(|b| b.len() > 255)
            || !unicast(own)
            || !unicast(peer)
            || own == peer
            || sequence > 4095
            || crate::rsn::RsnIe::decode_body(station_rsne)
                != Some(crate::rsn::RsnIe::wpa2_psk_ccmp())
        {
            return Err(Error::Profile);
        }
        let ap = crate::rsn::RsnIe::decode_body(ap_rsne).ok_or(Error::Profile)?;
        use crate::rsn::{self, Suite};
        if ap.group_cipher != Suite::standard(rsn::CIPHER_CCMP_128)
            || !ap
                .pairwise_ciphers
                .contains(&Suite::standard(rsn::CIPHER_CCMP_128))
            || !ap.akms.contains(&Suite::standard(rsn::AKM_PSK))
            || ap.rsn_capabilities & (rsn::RSN_CAP_MFP_REQUIRED | rsn::RSN_CAP_NO_PAIRWISE) != 0
            || ap_rsnxe.is_some_and(|b| b.is_empty() || usize::from(b[0] & 15) + 1 != b.len())
        {
            return Err(Error::Profile);
        }
        Ok(Self {
            own,
            peer,
            supplicant: Supplicant::new(peer, own, [0; 32]).with_rsna(RsnaParams {
                key_mgmt: KeyMgmt::Psk,
                pmk: pmk.to_vec(),
                assoc_ie: ie(48, station_rsne)?,
                ap_rsn_ie: ie(48, ap_rsne)?,
                ap_rsnxe: ap_rsnxe.map(|b| ie(244, b)).transpose()?,
                pairwise_key_len: 16,
                group_key_len: 16,
                mgmt_group_key_len: None,
                pmf: false,
            }),
            pair: None,
            group: core::array::from_fn(|_| None),
            history: Vec::new(),
            pending: None,
            established: false,
            failed: false,
            sequence,
        })
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
        let (reply, pair, gtk, opens) = match processed {
            EapolRx::Pairwise1(m1) => (m1.reply, None, None, false),
            EapolRx::Pairwise3(mut m3) => {
                if !m3.secure || m3.igtk.is_some() {
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
                (m3.reply, m3.tk, m3.gtk, true)
            }
            EapolRx::Group1(mut g) => {
                if !self.established || g.igtk.is_some() {
                    if let Some(gtk) = &mut g.gtk {
                        gtk.key.zeroize();
                    }
                    if let Some(Ok(Some(igtk))) = &mut g.igtk {
                        igtk.key.zeroize();
                    }
                    self.fail();
                    return Err(Error::Protocol);
                }
                (g.reply, None, g.gtk, false)
            }
        };
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
        let mut header = vec![8, 0x41, 0, 0];
        header.extend_from_slice(&self.peer);
        header.extend_from_slice(&self.own);
        header.extend_from_slice(&ethernet[..6]);
        header.extend_from_slice(&(self.sequence << 4).to_le_bytes());
        self.sequence = (self.sequence + 1) & 4095;
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
        if c.opens && c.pair.is_none() && self.pair.is_none()
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
                        .map_err(Error::Crypto)?;
                    self.history.push(Zeroizing::new(*material));
                    self.pair = Some(Slot { material, key });
                }
            } else {
                let key = Key::new(&material, 0, Role::Pairwise, self.own, self.peer, 0)
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
        self.established |= pending.change.opens;
        Ok(())
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
    }
}

#[cfg(feature = "kernel-test")]
#[path = "station_security_tests.rs"]
mod tests;
