//! Checked software CCMP ownership for native station paths.
//! The protocol layer owns header/AAD/nonce formatting. This owner adds strict
//! header/CCMP bounds, peer binding, per-key/TID replay and non-wrapping TX PN.
//! It does not open a controlled port or install keys before RSNA completes.
use crate::ccmp::{self, AesCcm, CcmpError, ReplayWindow};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PN: u64 = (1u64 << 48) - 1;
const MAX_BODY: usize = 4096;
const NON_QOS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Header,
    Key,
    Length,
    Exhausted,
    Crypto(CcmpError),
    Aggregate(crate::amsdu::Error),
}
/// QoS Control Ack Policy of an original aggregate (IEEE802.11-2020
/// 9.2.4.5.4, Table 9-11): Normal Ack/implicit BAR (00), No Ack (01),
/// No Explicit Acknowledgment/PSMP Ack/HTP Ack (10) and Block Ack (11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckPolicy {
    Normal,
    NoAck,
    NoExplicitAck,
    BlockAck,
}
impl AckPolicy {
    const fn from_qos(qos: u8) -> Self {
        match (qos >> 5) & 3 {
            0 => Self::Normal,
            1 => Self::NoAck,
            2 => Self::NoExplicitAck,
            _ => Self::BlockAck,
        }
    }
}

/// Explicit receive opt-ins for `Key::unprotect_amsdu_with`. The default is
/// the original `unprotect_amsdu` profile: unicast/group Normal Ack, no EOSP,
/// the HT3839 limit. Each opt-in states a fact the driver's native receive
/// path has proved, never an authority the helper grants:
/// - `block_ack`: a live unicast BA agreement released this MPDU in SN order.
/// - `no_ack`: No Ack policy, as Linux mac80211 ieee80211_set_qos_hdr sets for
///   every group-addressed QoS DATA frame and for TIDs in a peer's noack map.
///   Admitted for unicast and group receivers.
/// - `no_explicit_ack`: PSMP/HTP Ack policy; unicast only, since the
///   policy names an addressed recipient (9.2.4.5.4).
/// - `eosp`: the AP's End Of Service Period bit (9.2.4.5.3). Its value is
///   returned in `AmsduReceive::eosp` for the driver's U-APSD owner.
/// - `limit`: the larger HT/VHT size the station actually advertised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AmsduAdmission {
    block_ack: bool,
    no_ack: bool,
    no_explicit_ack: bool,
    eosp: bool,
    limit: crate::amsdu::Limit,
}
impl AmsduAdmission {
    pub const fn new() -> Self {
        Self {
            block_ack: false,
            no_ack: false,
            no_explicit_ack: false,
            eosp: false,
            limit: crate::amsdu::Limit::Ht3839,
        }
    }
    pub const fn with_block_ack(mut self, enabled: bool) -> Self {
        self.block_ack = enabled;
        self
    }
    pub const fn with_no_ack(mut self, enabled: bool) -> Self {
        self.no_ack = enabled;
        self
    }
    pub const fn with_no_explicit_ack(mut self, enabled: bool) -> Self {
        self.no_explicit_ack = enabled;
        self
    }
    pub const fn with_eosp(mut self, enabled: bool) -> Self {
        self.eosp = enabled;
        self
    }
    pub const fn with_limit(mut self, limit: crate::amsdu::Limit) -> Self {
        self.limit = limit;
        self
    }
    pub const fn limit(self) -> crate::amsdu::Limit {
        self.limit
    }
}

/// One authenticated aggregate's Ethernet-II frames and its original QoS
/// facts. `eosp`/`ack_policy` are wire facts for the driver, not grants.
#[derive(Debug, PartialEq, Eq)]
pub struct AmsduReceive {
    pub frames: Vec<Vec<u8>>,
    pub tid: u8,
    pub ack_policy: AckPolicy,
    pub eosp: bool,
}

/// Pairwise and group keys have different station address/packet ownership.
/// GTK KeyID zero is legal and must never be confused with a transmit PTK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Pairwise,
    Group,
}
struct Ccm;
impl AesCcm for Ccm {
    fn encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; 8], CcmpError> {
        // The adapter is total: a seal refusal (the CCM two-octet
        // length bound, 65535 bytes) surfaces as a typed error,
        // never a panic in the TX path. Key::protect pre-bounds
        // bodies to MAX_BODY, so this is defense in depth that keeps
        // the adapter's contract independent of caller pre-bounds.
        narf_crypto::aes_ccm::seal(key, nonce, aad, body).map_err(|error| match error {
            narf_crypto::aes_ccm::Error::Length => CcmpError::TooLong,
            narf_crypto::aes_ccm::Error::Authentication => CcmpError::AuthFailed,
        })
    }
    fn decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CcmpError> {
        narf_crypto::aes_ccm::open(key, nonce, aad, body, tag).map_err(|_| CcmpError::AuthFailed)
    }
}

/// One immutable key-ID/peer binding, kept for the connection's lifetime.
/// Only construct for a fresh temporal key. An EAPOL retransmission must use
/// `reinstall`, which preserves counters for an identical key. The station
/// retains these slots across rekeys/failed joins; it must not rebuild an
/// identical key with a reset PN. GTK slots are receive-only in station mode.
/// Hardware encryption must remain disabled while software CCMP owns packets.
pub struct Key {
    tk: Zeroizing<[u8; 16]>,
    key_id: u8,
    role: Role,
    local: [u8; 6],
    peer: [u8; 6],
    tx_pn: u64,
    receive: [ReplayWindow; 17],
    spp_amsdu: bool,
}
impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key")
            .field("key_id", &self.key_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}
impl Key {
    pub fn new(
        tk: &[u8; 16],
        key_id: u8,
        role: Role,
        local: [u8; 6],
        peer: [u8; 6],
        rsc: u64,
    ) -> Result<Self, Error> {
        if key_id > 3
            || (role == Role::Pairwise && key_id != 0)
            || rsc > MAX_PN
            || !unicast(local)
            || !unicast(peer)
            || local == peer
        {
            return Err(Error::Key);
        }
        Ok(Self {
            tk: Zeroizing::new(*tk),
            key_id,
            role,
            local,
            peer,
            tx_pn: 0,
            receive: [ReplayWindow { last_seen_pn: rsc }; 17],
            spp_amsdu: false,
        })
    }
    /// Bind this pairwise key to a negotiated SPP A-MSDU association: both
    /// station and AP RSNEs set RSN Capabilities bit10 (IEEE802.11-2020
    /// 9.4.2.24.4, 12.5.3.3.3). Its CCMP AAD then authenticates the A-MSDU
    /// Present bit. Group keys keep the ordinary AAD: a group-addressed
    /// aggregate cannot depend on every receiver's SPP capability. Set it once at
    /// construction; reinstall preserves it.
    pub fn with_spp_amsdu(mut self, enabled: bool) -> Result<Self, Error> {
        if enabled && self.role != Role::Pairwise {
            return Err(Error::Key);
        }
        self.spp_amsdu = enabled;
        Ok(self)
    }
    pub fn spp_amsdu(&self) -> bool {
        self.spp_amsdu
    }
    /// Return true when material changed. An identical-key retry must not
    /// roll TX/RX state back, even if the peer repeats a smaller receive RSC.
    pub fn reinstall(&mut self, tk: &[u8; 16], rsc: u64) -> Result<bool, Error> {
        if rsc > MAX_PN {
            return Err(Error::Key);
        }
        if *self.tk == *tk {
            return Ok(false);
        }
        self.tk.zeroize();
        self.tk.copy_from_slice(tk);
        self.tx_pn = 0;
        self.receive = [ReplayWindow { last_seen_pn: rsc }; 17];
        Ok(true)
    }
    /// Protect a validated native data header/body. Increment before handing
    /// bytes to the transport; a dropped or failed TX consumes its PN permanently.
    pub fn protect(&mut self, header: &[u8], body: &[u8]) -> Result<Vec<u8>, Error> {
        let shape = shape(header)?;
        if self.role != Role::Pairwise
            || header[1] & 3 != 1
            || header[4..10] != self.peer
            || header[10..16] != self.local
            || header[16..22] == [0; 6]
        {
            return Err(Error::Key);
        }
        if body.len() > MAX_BODY {
            return Err(Error::Length);
        }
        if self.tx_pn == MAX_PN {
            return Err(Error::Exhausted);
        }
        self.tx_pn += 1;
        let mut ciphertext = Zeroizing::new(body.to_vec());
        ccmp::protect(
            &Ccm,
            header,
            &self.tk,
            self.tx_pn,
            self.key_id,
            shape.priority,
            false,
            &mut ciphertext,
        )
        .map_err(Error::Crypto)
    }
    /// Authenticate before committing this key/TID's replay tracker. All
    /// admission/MIC/replay failures leave the entire wire buffer unchanged.
    pub fn unprotect(&mut self, header: &[u8], wire: &mut [u8]) -> Result<Vec<u8>, Error> {
        let shape = shape(header)?;
        if header[1] & 3 != 2
            || header[10..16] != self.peer
            || !unicast(header[16..22].try_into().unwrap())
            || match self.role {
                Role::Pairwise => header[4..10] != self.local,
                Role::Group => header[4] & 1 == 0,
            }
        {
            return Err(Error::Key);
        }
        if !(16..=MAX_BODY + 16).contains(&wire.len()) {
            return Err(Error::Length);
        }
        if wire[2] != 0 || wire[3] & 0x3f != 0x20 || wire[3] >> 6 != self.key_id {
            return Err(Error::Key);
        }
        // Keep the driver transaction explicit even though shared unprotect
        // also commits only after MIC. This binds state to the selected TID.
        let mut candidate = self.receive[shape.index];
        let plaintext = ccmp::unprotect(
            &Ccm,
            header,
            &self.tk,
            shape.priority,
            false,
            &mut candidate,
            wire,
        )
        .map_err(Error::Crypto)?;
        self.receive[shape.index] = candidate;
        Ok(plaintext)
    }
    /// Opt-in RAW HT aggregate receive. Authenticate the original protected
    /// QoS MPDU, validate every bounded subframe and allocate the complete
    /// Ethernet result before committing this key/TID's one replay update.
    /// The caller's ciphertext is immutable even on successful admission.
    /// Existing `unprotect` keeps rejecting A-MSDU headers.
    pub fn unprotect_amsdu(&mut self, header: &[u8], wire: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.unprotect_amsdu_with(header, wire, AmsduAdmission::new())
            .map(|r| r.frames)
    }
    /// Additional BlockAck-policy admission for an original whole MPDU
    /// already released by the caller's live native BA/reorder owner. This
    /// grants no agreement or reorder authority and never rewrites the header.
    pub fn unprotect_amsdu_block_ack(
        &mut self,
        header: &[u8],
        wire: &[u8],
    ) -> Result<Vec<Vec<u8>>, Error> {
        self.unprotect_amsdu_with(header, wire, AmsduAdmission::new().with_block_ack(true))
            .map(|r| r.frames)
    }
    /// Receive an original protected QoS A-MSDU under explicit `admission`.
    /// Header, key, length, MIC, every subframe and the result allocation are
    /// validated before this key/TID's single replay update commits; failures
    /// keep the ciphertext and replay state unchanged. With SPP A-MSDU the
    /// A-MSDU Present bit is authenticated, otherwise masked as before.
    pub fn unprotect_amsdu_with(
        &mut self,
        header: &[u8],
        wire: &[u8],
        admission: AmsduAdmission,
    ) -> Result<AmsduReceive, Error> {
        let priority = aggregate_header_with(header, admission)?;
        if header[10..16] != self.peer
            || !unicast(header[16..22].try_into().unwrap())
            || match self.role {
                Role::Pairwise => header[4..10] != self.local,
                Role::Group => header[4] & 1 == 0,
            }
        {
            return Err(Error::Key);
        }
        if !(16 + 22..=16 + admission.limit.bytes()).contains(&wire.len()) {
            return Err(Error::Length);
        }
        if wire[2] != 0 || wire[3] & 0x3f != 0x20 || wire[3] >> 6 != self.key_id {
            return Err(Error::Key);
        }
        let mut scratch = Zeroizing::new(Vec::new());
        scratch
            .try_reserve_exact(wire.len())
            .map_err(|_| Error::Aggregate(crate::amsdu::Error::Allocation))?;
        scratch.extend_from_slice(wire);
        let mut candidate = self.receive[usize::from(priority)];
        let opened = if self.spp_amsdu {
            ccmp::unprotect_spp_amsdu(
                &Ccm,
                header,
                &self.tk,
                priority,
                &mut candidate,
                &mut scratch,
            )
        } else {
            ccmp::unprotect(
                &Ccm,
                header,
                &self.tk,
                priority,
                false,
                &mut candidate,
                &mut scratch,
            )
        };
        let plaintext = Zeroizing::new(opened.map_err(Error::Crypto)?);
        let frames = crate::amsdu::decode_with_limit(
            &plaintext,
            self.local,
            header[4..10].try_into().unwrap(),
            admission.limit,
        )
        .map_err(Error::Aggregate)?;
        self.receive[usize::from(priority)] = candidate;
        Ok(AmsduReceive {
            frames,
            tid: priority,
            ack_policy: AckPolicy::from_qos(header[24]),
            eosp: header[24] & 0x10 != 0,
        })
    }
    /// Protect one station-originated A-MSDU body, normally from
    /// `amsdu::encode`. The header is the original26-byte ToDS protected QoS
    /// DATA header with A-MSDU Present, Normal Ack, no EOSP/fragments/Order
    /// and Address3 equal to the BSSID (IEEE802.11-2020 Table 9-30, as Linux
    /// ieee80211_amsdu_prepare_head rewrites it). Like `protect`, a PN is
    /// consumed before the transport sees the bytes. `limit` is the peer's
    /// advertised receive size; the caller owns PHY/BA/queue admission.
    pub fn protect_amsdu(
        &mut self,
        header: &[u8],
        body: &[u8],
        limit: crate::amsdu::Limit,
    ) -> Result<Vec<u8>, Error> {
        if header.len() != 26
            || header[0] != 0x88
            || header[1] & 0xc7 != 0x41
            || header[22] & 15 != 0
            || header[24] & 0xf0 != 0x80
            || header[25] != 0
        {
            return Err(Error::Header);
        }
        if self.role != Role::Pairwise
            || header[4..10] != self.peer
            || header[10..16] != self.local
            || header[16..22] != self.peer
        {
            return Err(Error::Key);
        }
        if !(22..=limit.bytes()).contains(&body.len()) {
            return Err(Error::Length);
        }
        if self.tx_pn == MAX_PN {
            return Err(Error::Exhausted);
        }
        let mut ciphertext = Zeroizing::new(Vec::new());
        ciphertext
            .try_reserve_exact(body.len())
            .map_err(|_| Error::Aggregate(crate::amsdu::Error::Allocation))?;
        ciphertext.extend_from_slice(body);
        self.tx_pn += 1;
        let priority = header[24] & 15;
        if self.spp_amsdu {
            ccmp::protect_spp_amsdu(
                &Ccm,
                header,
                &self.tk,
                self.tx_pn,
                self.key_id,
                priority,
                &mut ciphertext,
            )
        } else {
            ccmp::protect(
                &Ccm,
                header,
                &self.tk,
                self.tx_pn,
                self.key_id,
                priority,
                false,
                &mut ciphertext,
            )
        }
        .map_err(Error::Crypto)
    }
}
pub(crate) fn aggregate_header_with(header: &[u8], admission: AmsduAdmission) -> Result<u8, Error> {
    // FromDS, protected QoS DATA, no fragments/Address4/HT control. Ack policy
    // and EOSP follow the explicit admission; the original26-byte station
    // header is never rewritten.
    if header.len() != 26
        || header[0] != 0x88
        || header[1] & 0xc7 != 0x42
        || header[22] & 15 != 0
        || header[24] & 0x80 == 0
        || header[25] != 0
    {
        return Err(Error::Header);
    }
    let group = header[4] & 1 != 0;
    let policy = match AckPolicy::from_qos(header[24]) {
        AckPolicy::Normal => true,
        AckPolicy::NoAck => admission.no_ack,
        AckPolicy::NoExplicitAck => admission.no_explicit_ack && !group,
        AckPolicy::BlockAck => admission.block_ack && !group,
    };
    if !policy || header[24] & 0x10 != 0 && !admission.eosp {
        return Err(Error::Header);
    }
    Ok(header[24] & 15)
}
fn unicast(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}
struct Shape {
    index: usize,
    priority: u8,
}
fn shape(header: &[u8]) -> Result<Shape, Error> {
    if header.len() < 24 || !matches!(header[0], 0x08 | 0x88) || header[1] & 0x40 == 0 {
        return Err(Error::Header);
    }
    // Fragment reassembly is not admitted in the initial station profile.
    if header[1] & 4 != 0 || header[22] & 15 != 0 {
        return Err(Error::Header);
    }
    let qos = header[0] & 0x80 != 0;
    let offset = if header[1] & 3 == 3 { 30 } else { 24 };
    let length =
        offset + if qos { 2 } else { 0 } + if qos && header[1] & 0x80 != 0 { 4 } else { 0 };
    if header.len() != length {
        return Err(Error::Header);
    }
    if qos {
        // A-MSDU needs separate subframe admission and is not enabled yet.
        if header[offset] & 0x80 != 0 {
            return Err(Error::Header);
        }
        let priority = header[offset] & 15;
        Ok(Shape {
            index: usize::from(priority),
            priority,
        })
    } else {
        Ok(Shape {
            index: NON_QOS,
            priority: 0,
        })
    }
}
#[cfg(feature = "kernel-test")]
#[path = "packet_key_amsdu_tests.rs"]
mod amsdu_tests;
#[cfg(feature = "kernel-test")]
#[path = "packet_key_tests.rs"]
mod tests;
