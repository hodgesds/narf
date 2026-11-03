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
    medium_sync: Option<u16>,
    eml: Option<EmlCapabilities>,
    mld_capabilities: Option<u16>,
    affiliated: [Option<AffiliatedLink>; MAX_LINKS as usize],
}
impl BasicMultiLink {
    pub fn address(self) -> [u8; 6] {
        self.address
    }
    pub fn link_id(self) -> Option<u8> {
        self.link_id
    }
    /// Common-info Medium Synchronization Delay, as retained by Linux
    /// mlme.c into `vif->cfg.eml_med_sync_delay`.
    pub fn medium_sync_delay(self) -> Option<u16> {
        self.medium_sync
    }
    /// Common-info EML Capabilities (Linux `vif->cfg.eml_cap`). Absence
    /// means the AP MLD advertises no EML mode at all.
    pub fn eml_capabilities(self) -> Option<EmlCapabilities> {
        self.eml
    }
    /// Common-info MLD Capabilities and Operations, raw.
    pub fn mld_capabilities(self) -> Option<u16> {
        self.mld_capabilities
    }
    /// Bitmap of affiliated per-STA profile link ids.
    pub fn profile_links(self) -> u16 {
        self.profiles
    }
    /// Retained per-STA profile header facts for one affiliated link. These
    /// are AP-advertised identities only; they grant no channel, RSN, PHY or
    /// native owner until a separately validated link setup admits them.
    pub fn affiliated(self, link_id: u8) -> Option<AffiliatedLink> {
        self.affiliated.get(usize::from(link_id)).copied().flatten()
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
        // Optional common fields in presence order (ieee80211-eht.h
        // ieee80211_mle_basic_*): link id, BSS change count, medium sync,
        // EML capabilities, MLD capabilities, AP MLD id, ext MLD capa.
        let mut field = 9usize;
        let mut take = |bit: u16, len: usize| -> Option<usize> {
            if control & bit == 0 {
                return None;
            }
            let start = field;
            field += len;
            Some(start)
        };
        let word = |at: usize| u16::from_le_bytes([body[at], body[at + 1]]);
        let link_id = match take(LINK_ID, 1) {
            Some(at) => {
                let id = body[at];
                if id >= MAX_LINKS {
                    return Err(Error::InvalidBss);
                }
                Some(id)
            }
            None => None,
        };
        take(0x20, 1);
        let medium_sync = take(0x40, 2).map(word);
        let eml = take(0x80, 2).map(|at| EmlCapabilities(word(at)));
        let mld_capabilities = take(MLD_CAPA, 2).map(word);
        let mut at = 2 + common;
        let mut profiles = 0u16;
        let mut affiliated = [None; MAX_LINKS as usize];
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
            let mut address = None;
            if flags & 0x20 != 0 {
                let mac = profile
                    .get(3..9)
                    .ok_or(Error::InvalidBss)?
                    .try_into()
                    .map_err(|_| Error::InvalidBss)?;
                if !unicast(mac) {
                    return Err(Error::InvalidBss);
                }
                address = Some(mac);
            }
            profiles |= 1 << id;
            affiliated[usize::from(id)] = Some(AffiliatedLink {
                link_id: id as u8,
                complete: flags & 0x10 != 0,
                address,
            });
            at = end;
        }
        Ok(Self {
            address,
            link_id,
            profiles,
            medium_sync,
            eml,
            mld_capabilities,
            affiliated,
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

/// One affiliated per-STA profile header (Linux ieee80211-eht.h
/// IEEE80211_MLE_STA_CONTROL_*). Only bounded header facts are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffiliatedLink {
    link_id: u8,
    complete: bool,
    address: Option<[u8; 6]>,
}
impl AffiliatedLink {
    pub fn link_id(self) -> u8 {
        self.link_id
    }
    /// COMPLETE_PROFILE: only a complete profile can describe a link that
    /// mac80211 mlme.c may request in an association.
    pub fn complete(self) -> bool {
        self.complete
    }
    pub fn address(self) -> Option<[u8; 6]> {
        self.address
    }
}

/// EML Capabilities subfield (Linux ieee80211-eht.h IEEE80211_EML_CAP_*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmlCapabilities(pub u16);
impl EmlCapabilities {
    pub const EMLSR_SUPPORT: u16 = 0x0001;
    pub const PADDING_DELAY: u16 = 0x000e;
    pub const TRANSITION_DELAY: u16 = 0x0070;
    pub const EMLMR_SUPPORT: u16 = 0x0080;
    pub const TRANSITION_TIMEOUT: u16 = 0x7800;
    /// Linux mld/mac80211.c IWL_MLD_EMLSR_CAPA: EMLSR, padding32us,
    /// transition64us. A non-AP MLD advertises it only once every
    /// multiple-active-link owner exists.
    pub const INTEL_MLD_LOCAL: Self = Self(Self::EMLSR_SUPPORT | (1 << 1) | (3 << 4));
    pub fn emlsr(self) -> bool {
        self.0 & Self::EMLSR_SUPPORT != 0
    }
    /// ieee80211_emlsr_pad_delay_in_us.
    pub fn padding_delay_us(self) -> u32 {
        let code = u32::from((self.0 & Self::PADDING_DELAY) >> 1);
        if !self.emlsr() || code == 0 || code > 4 {
            return 0;
        }
        32 << (code - 1)
    }
    /// ieee80211_emlsr_trans_delay_in_us.
    pub fn transition_delay_us(self) -> u32 {
        let code = u32::from((self.0 & Self::TRANSITION_DELAY) >> 4);
        if !self.emlsr() || code == 0 || code > 5 {
            return 0;
        }
        16 << (code - 1)
    }
    /// Raw Transition Timeout code, clamped as Linux mld/iface.c
    /// iwl_mld_mac_cmd_fill_sta does for MAC client esr_transition_timeout.
    pub fn transition_timeout_code(self) -> u8 {
        (((self.0 & Self::TRANSITION_TIMEOUT) >> 11) as u8).min(10)
    }
    /// ieee80211_eml_trans_timeout_in_us.
    pub fn transition_timeout_us(self) -> u32 {
        let code = u32::from((self.0 & Self::TRANSITION_TIMEOUT) >> 11);
        if code == 0 || code > 10 {
            return 0;
        }
        128 << (code - 1)
    }
}

/// IEEE80211_MLD_CAP_OP_MAX_SIMUL_LINKS: encoded value plus one links.
pub fn max_simultaneous_links(mld_capabilities: u16) -> u8 {
    (mld_capabilities & 0x000f) as u8 + 1
}
