// SPDX-License-Identifier: GPL-2.0-or-later
//! Single-link non-AP MLD identity and Basic Multi-Link negotiation.
//! Layout: pinned Linux7.2 ieee80211-eht.h (MLE size/common/profile checks),
//! mlme.c::ieee80211_assoc_add_ml_elem. These facts confer no radio/key grant.
use super::{ies, unicast, Error};
use alloc::{vec, vec::Vec};

pub const EXT_MULTI_LINK: u8 = 107;
const LINK_ID: u16 = 0x0010;
const MLD_CAPA: u16 = 0x0100;
const BASIC_FIELDS: u16 = 0x07f0;
// Linux ieee80211-eht.h::IEEE80211_MLD_MAX_NUM_LINKS; Link ID15 is reserved.
const MAX_LINKS: u8 = 15;

/// Only one associated link is requested. Max Simultaneous Links=0 encodes
/// one; EML, TID-to-link mapping and additional link profiles are not offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Local {
    address: [u8; 6],
}
impl Local {
    pub fn single_link(address: [u8; 6]) -> Result<Self, Error> {
        if !unicast(address) {
            return Err(Error::InvalidBss);
        }
        Ok(Self { address })
    }
    pub fn address(self) -> [u8; 6] {
        self.address
    }
    pub fn request_element(self) -> Vec<u8> {
        let mut bytes = vec![255, 12, EXT_MULTI_LINK];
        bytes.extend_from_slice(&MLD_CAPA.to_le_bytes());
        bytes.push(9);
        bytes.extend_from_slice(&self.address);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }
    /// Linux util.c::ieee80211_send_auth uses Basic common-info length7
    /// without capability/presence fields for every MLD auth transaction.
    pub fn authentication_element(self) -> Vec<u8> {
        let mut bytes = vec![255, 10, EXT_MULTI_LINK, 0, 0, 7];
        bytes.extend_from_slice(&self.address);
        bytes
    }
    /// Bind one actual BSS/link to the AP's advertised common identity. A
    /// native owner must still prove the same physical receive/link owner.
    pub fn context(
        self,
        own_link: [u8; 6],
        peer_link: [u8; 6],
        ap: &BasicMultiLink,
    ) -> Result<Context, Error> {
        let link_id = ap.link_id.ok_or(Error::InvalidBss)?;
        if !unicast(own_link)
            || !unicast(peer_link)
            || own_link == peer_link
            || self.address == ap.address
            || self.address == peer_link
            || own_link == ap.address
        {
            return Err(Error::InvalidBss);
        }
        Ok(Context {
            own_mld: self.address,
            peer_mld: ap.address,
            own_link,
            peer_link,
            link_id,
        })
    }
}

/// Immutable selected identity. Logical management/PTK identity is kept
/// separate from actual physical MPDU/PN ownership and native key binding;
/// unicast DATA uses its own explicit logical cryptographic projection.
/// A scalar link id alone can never select a different owner or peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    own_mld: [u8; 6],
    peer_mld: [u8; 6],
    own_link: [u8; 6],
    peer_link: [u8; 6],
    link_id: u8,
}
impl Context {
    pub fn own_mld(self) -> [u8; 6] {
        self.own_mld
    }
    pub fn peer_mld(self) -> [u8; 6] {
        self.peer_mld
    }
    pub fn own_link(self) -> [u8; 6] {
        self.own_link
    }
    pub fn peer_link(self) -> [u8; 6] {
        self.peer_link
    }
    pub fn link_id(self) -> u8 {
        self.link_id
    }
    /// Project an already physically admitted original DATA header to its
    /// MLD cryptographic address form. The caller retains the original radio
    /// header; no source/firmware/epoch authority follows from this copy.
    /// Group DATA keeps the link addresses. Management is deliberately not
    /// accepted here: its crypto uses the original physical link addresses.
    pub fn data_crypto_header(self, physical: &[u8]) -> Result<Vec<u8>, Error> {
        let length = match physical.first() {
            Some(0x08) => 24,
            Some(0x88) => 26,
            _ => return Err(Error::Protocol),
        };
        if physical.len() != length {
            return Err(Error::Protocol);
        }
        let mut crypto = physical.to_vec();
        match physical[1] & 3 {
            1 if physical[4..10] == self.peer_link && physical[10..16] == self.own_link => {
                crypto[4..10].copy_from_slice(&self.peer_mld);
                crypto[10..16].copy_from_slice(&self.own_mld);
            }
            2 if physical[10..16] == self.peer_link => {
                if physical[4] & 1 != 0 {
                    return Ok(crypto);
                }
                if physical[4..10] != self.own_link {
                    return Err(Error::Protocol);
                }
                crypto[4..10].copy_from_slice(&self.own_mld);
                crypto[10..16].copy_from_slice(&self.peer_mld);
            }
            _ => return Err(Error::Protocol),
        }
        // Intel mld/tx.c translates the exact A-MSDU BSSID only after
        // encryption. Ordinary MSDU A3 may name a bridged SA/DA and is never
        // rewritten; group DATA returned above keeps physical crypto.
        if length == 26 && physical[24] & 0x80 != 0 {
            if physical[16..22] != self.peer_link {
                return Err(Error::Protocol);
            }
            crypto[16..22].copy_from_slice(&self.peer_mld);
        }
        Ok(crypto)
    }
    /// Validate association-response IEs against the immutable selected MLD.
    /// An absent Link-ID keeps the beacon-selected link; a present mismatch
    /// or any extra link profile is rejected. This grants no native authority.
    pub fn response(self, bytes: &[u8]) -> Result<(), Error> {
        let ap = BasicMultiLink::from_ies(bytes)?;
        if ap.address != self.peer_mld
            || ap.link_id.is_some_and(|id| id != self.link_id)
            || ap.profiles != 0
        {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    /// SAE crypto bytes exclude the driver's appended canonical auth MLE.
    /// The fixed trailer is parsed separately so opaque scalars/tokens cannot
    /// masquerade as an IE stream or choose a different logical peer.
    pub fn authentication_body(self, bytes: &[u8]) -> Result<&[u8], Error> {
        let at = bytes.len().checked_sub(12).ok_or(Error::Protocol)?;
        let expected = Local {
            address: self.peer_mld,
        }
        .authentication_element();
        if bytes[at..] != expected {
            return Err(Error::Protocol);
        }
        Ok(&bytes[..at])
    }
    pub(super) fn own_auth_element(self) -> Vec<u8> {
        Local {
            address: self.own_mld,
        }
        .authentication_element()
    }
}

/// Parsed, unfragmented Basic MLE. Optional common fields are size-checked in
/// presence order; affiliated profiles are bounded/validated, never inherited
/// as the selected link's RSN/PHY or used to manufacture extra link contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicMultiLink {
    address: [u8; 6],
    link_id: Option<u8>,
    profiles: u16,
}
impl BasicMultiLink {
    pub fn address(self) -> [u8; 6] {
        self.address
    }
    pub fn link_id(self) -> Option<u8> {
        self.link_id
    }
    /// `body` starts at ML Control, after extension ID107.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        if body.len() < 9 {
            return Err(Error::InvalidBss);
        }
        let control = u16::from_le_bytes([body[0], body[1]]);
        if control & !BASIC_FIELDS != 0 {
            return Err(Error::InvalidBss);
        }
        let mut common = 7usize;
        for (bit, len) in [
            (0x10, 1),
            (0x20, 1),
            (0x40, 2),
            (0x80, 2),
            (0x100, 2),
            (0x200, 1),
            (0x400, 2),
        ] {
            if control & bit != 0 {
                common += len;
            }
        }
        if usize::from(body[2]) != common || 2 + common > body.len() {
            return Err(Error::InvalidBss);
        }
        let address = body[3..9].try_into().map_err(|_| Error::InvalidBss)?;
        if !unicast(address) {
            return Err(Error::InvalidBss);
        }
        let link_id = if control & LINK_ID != 0 {
            let id = body[9];
            if id >= MAX_LINKS {
                return Err(Error::InvalidBss);
            }
            Some(id)
        } else {
            None
        };
        let mut at = 2 + common;
        let mut profiles = 0u16;
        while at < body.len() {
            let header = body.get(at..at + 2).ok_or(Error::InvalidBss)?;
            let end = at + 2 + usize::from(header[1]);
            let profile = body.get(at + 2..end).ok_or(Error::InvalidBss)?;
            // Fragmented MLE/profile reassembly and unknown subelements are
            // unsupported in this bounded one-link request/response profile.
            if header[0] != 0 || profile.len() < 3 {
                return Err(Error::InvalidBss);
            }
            let flags = u16::from_le_bytes([profile[0], profile[1]]);
            let id = flags & 15;
            if id >= u16::from(MAX_LINKS) || flags & !0x0fff != 0 || profiles & (1 << id) != 0 {
                return Err(Error::InvalidBss);
            }
            let mut needed = 1usize;
            for (bit, len) in [(0x20, 6), (0x40, 2), (0x80, 8), (0x100, 2), (0x800, 1)] {
                if flags & bit != 0 {
                    needed += len;
                }
            }
            if flags & 0x210 == 0x210 {
                needed += if flags & 0x400 != 0 { 2 } else { 1 };
            }
            if usize::from(profile[2]) < needed || 2 + usize::from(profile[2]) > profile.len() {
                return Err(Error::InvalidBss);
            }
            if flags & 0x20 != 0 {
                let mac = profile
                    .get(3..9)
                    .ok_or(Error::InvalidBss)?
                    .try_into()
                    .map_err(|_| Error::InvalidBss)?;
                if !unicast(mac) {
                    return Err(Error::InvalidBss);
                }
            }
            profiles |= 1 << id;
            at = end;
        }
        Ok(Self {
            address,
            link_id,
            profiles,
        })
    }
    pub fn from_ies(bytes: &[u8]) -> Result<Self, Error> {
        let mut result = None;
        ies(bytes, |id, body| {
            if id == 255 && body.first() == Some(&EXT_MULTI_LINK) {
                if result.is_some() {
                    return Err(Error::InvalidBss);
                }
                result = Some(Self::parse(&body[1..])?);
            }
            if id == 242 {
                return Err(Error::InvalidBss);
            }
            Ok(())
        })?;
        result.ok_or(Error::InvalidBss)
    }
}
