// SPDX-License-Identifier: GPL-2.0-or-later
//! Non-AP MLD identity and Basic Multi-Link negotiation (one associated link,
//! optionally with affiliated per-STA profiles for further links).
//! Layout: pinned Linux7.2 ieee80211-eht.h (MLE size/common/profile checks),
//! mlme.c::ieee80211_assoc_add_ml_elem, parse.c::ieee80211_prep_mle_link_parse.
//! These facts confer no radio/key grant.
use super::{ies, unicast, Error};
use alloc::{vec, vec::Vec};

pub const EXT_MULTI_LINK: u8 = 107;
const LINK_ID: u16 = 0x0010;
const BSS_CHANGE: u16 = 0x0020;
const EML_CAPA: u16 = 0x0080;
const MLD_CAPA: u16 = 0x0100;
// IEEE80211_MLE_STA_CONTROL_{COMPLETE_PROFILE,STA_MAC_ADDR_PRESENT,
// BSS_PARAM_CHANGE_CNT_PRESENT}.
const STA_COMPLETE: u16 = 0x0010;
const STA_MAC: u16 = 0x0020;
const STA_BSS_CHANGE: u16 = 0x0800;
// IEEE80211_MLE_SUBELEM_{PER_STA_PROFILE,FRAGMENT}, WLAN_EID_FRAGMENT.
const SUBELEM_PROFILE: u8 = 0;
const SUBELEM_FRAGMENT: u8 = 254;
const ELEMENT_FRAGMENT: u8 = 242;
/// WLAN_EID_EXT_NON_INHERITANCE.
pub const EXT_NON_INHERITANCE: u8 = 56;
const BASIC_FIELDS: u16 = 0x07f0;
// Linux ieee80211-eht.h::IEEE80211_MLD_MAX_NUM_LINKS; Link ID15 is reserved.
const MAX_LINKS: u8 = 15;

/// The local non-AP MLD. `single_link` keeps the canonical one-link request
/// (Max Simultaneous Links0, no EML). `with_capabilities` supplies the
/// driver's `wiphy_iftype_ext_capab` MLD capabilities/operations and EML
/// capabilities, which Linux copies verbatim into every request; a driver
/// supplies them only once every multiple-active-link owner exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Local {
    address: [u8; 6],
    mld_capabilities: u16,
    eml: EmlCapabilities,
}
impl Local {
    pub fn single_link(address: [u8; 6]) -> Result<Self, Error> {
        if !unicast(address) {
            return Err(Error::InvalidBss);
        }
        Ok(Self {
            address,
            mld_capabilities: 0,
            eml: EmlCapabilities(0),
        })
    }
    pub fn with_capabilities(self, mld_capabilities: u16, eml: EmlCapabilities) -> Self {
        Self {
            mld_capabilities,
            eml,
            ..self
        }
    }
    fn bare(address: [u8; 6]) -> Self {
        Self {
            address,
            mld_capabilities: 0,
            eml: EmlCapabilities(0),
        }
    }
    pub fn address(self) -> [u8; 6] {
        self.address
    }
    pub fn mld_capabilities(self) -> u16 {
        self.mld_capabilities
    }
    pub fn eml_capabilities(self) -> EmlCapabilities {
        self.eml
    }
    pub fn request_element(self) -> Vec<u8> {
        self.request_element_with_profiles(&[])
    }
    /// mlme.c::ieee80211_assoc_add_ml_elem: Basic MLE with MLD MAC, EML
    /// Capabilities only when EMLSR/EMLMR is supported, MLD capabilities,
    /// then the already encoded per-STA profile subelements; an element
    /// over255 bytes is split as ieee80211_fragment_element does.
    pub(super) fn request_element_with_profiles(self, profiles: &[u8]) -> Vec<u8> {
        let mut control = MLD_CAPA;
        let mut common = 9u8;
        let eml =
            self.eml.0 & (EmlCapabilities::EMLSR_SUPPORT | EmlCapabilities::EMLMR_SUPPORT) != 0;
        if eml {
            control |= EML_CAPA;
            common += 2;
        }
        let mut body = vec![EXT_MULTI_LINK];
        body.extend_from_slice(&control.to_le_bytes());
        body.push(common);
        body.extend_from_slice(&self.address);
        if eml {
            body.extend_from_slice(&self.eml.0.to_le_bytes());
        }
        body.extend_from_slice(&self.mld_capabilities.to_le_bytes());
        body.extend_from_slice(profiles);
        let mut bytes = Vec::with_capacity(body.len() + 4);
        push_fragmented(&mut bytes, 255, &body, ELEMENT_FRAGMENT);
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
    /// Multiple-link association response (mlme.c::ieee80211_assoc_success
    /// and ieee80211_assoc_config_link). The common info must name the exact
    /// AP MLD, any present Link ID must be the selected one and the BSS
    /// Parameters Change Count must be present. Every link in `requested`
    /// (excluding this one) needs a COMPLETE per-STA profile with the
    /// capability/status fixed fields; a successful one also needs its own
    /// change count, and a nested Basic MLE is refused. A missing requested
    /// link fails the association as in Linux; profiles for links that were
    /// not requested are ignored. The result grants no native link owner.
    pub fn multi_link_response(
        self,
        bytes: &[u8],
        requested: u16,
    ) -> Result<Vec<LinkResponse>, Error> {
        let ap = BasicMultiLink::from_ies(bytes)?;
        if ap.address != self.peer_mld
            || ap.link_id.is_some_and(|id| id != self.link_id)
            || ap.bss_change.is_none()
        {
            return Err(Error::Protocol);
        }
        let body = basic_body(bytes).map_err(|_| Error::Protocol)?;
        let mut links = Vec::new();
        for link_id in 0..MAX_LINKS {
            if requested & (1 << link_id) == 0 || link_id == self.link_id {
                continue;
            }
            let (control, info, content) = sta_profile(&body, link_id).ok_or(Error::Protocol)?;
            if control & STA_COMPLETE == 0 || content.len() < 4 {
                return Err(Error::Protocol);
            }
            let capability = u16::from_le_bytes([content[0], content[1]]);
            let status = u16::from_le_bytes([content[2], content[3]]);
            let elements = content[4..].to_vec();
            let mut nested = false;
            ies(&elements, |id, element| {
                nested |= id == 255 && element.first() == Some(&EXT_MULTI_LINK);
                Ok(())
            })
            .map_err(|_| Error::Protocol)?;
            if nested || status == 0 && control & STA_BSS_CHANGE == 0 {
                return Err(Error::Protocol);
            }
            let address = if control & STA_MAC != 0 {
                info[1..7].try_into().ok()
            } else {
                None
            };
            links.push(LinkResponse {
                link_id,
                address,
                capability,
                status,
                elements,
            });
        }
        Ok(links)
    }
    /// SAE crypto bytes exclude the driver's appended canonical auth MLE.
    /// The fixed trailer is parsed separately so opaque scalars/tokens cannot
    /// masquerade as an IE stream or choose a different logical peer.
    pub fn authentication_body(self, bytes: &[u8]) -> Result<&[u8], Error> {
        let at = bytes.len().checked_sub(12).ok_or(Error::Protocol)?;
        let expected = Local::bare(self.peer_mld).authentication_element();
        if bytes[at..] != expected {
            return Err(Error::Protocol);
        }
        Ok(&bytes[..at])
    }
    pub(super) fn own_auth_element(self) -> Vec<u8> {
        Local::bare(self.own_mld).authentication_element()
    }
}

/// Parsed, unfragmented Basic MLE. Optional common fields are size-checked in
/// presence order; affiliated profiles are bounded/validated, never inherited
/// as the selected link's RSN/PHY or used to manufacture extra link contexts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BasicMultiLink {
    address: [u8; 6],
    link_id: Option<u8>,
    bss_change: Option<u8>,
    profiles: u16,
    medium_sync: Option<u16>,
    eml: Option<EmlCapabilities>,
    mld_capabilities: Option<u16>,
    mld_id: Option<u8>,
    affiliated: [Option<AffiliatedLink>; MAX_LINKS as usize],
}
impl BasicMultiLink {
    pub fn address(self) -> [u8; 6] {
        self.address
    }
    pub fn link_id(self) -> Option<u8> {
        self.link_id
    }
    /// Common-info BSS Parameters Change Count
    /// (ieee80211_mle_get_bss_param_ch_cnt).
    pub fn bss_parameters_change_count(self) -> Option<u8> {
        self.bss_change
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
    /// Common-info AP MLD ID, 0 when absent (ieee80211_mle_get_mld_id).
    pub fn mld_id(self) -> u8 {
        self.mld_id.unwrap_or(0)
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
        let bss_change = take(BSS_CHANGE, 1).map(|at| body[at]);
        let medium_sync = take(0x40, 2).map(word);
        let eml = take(0x80, 2).map(|at| EmlCapabilities(word(at)));
        let mld_capabilities = take(MLD_CAPA, 2).map(word);
        let mld_id = take(0x200, 1).map(|at| body[at]);
        let mut at = 2 + common;
        let mut profiles = 0u16;
        let mut affiliated = [None; MAX_LINKS as usize];
        while at < body.len() {
            let header = body.get(at..at + 2).ok_or(Error::InvalidBss)?;
            let mut end = at + 2 + usize::from(header[1]);
            let profile = body.get(at + 2..end).ok_or(Error::InvalidBss)?;
            // Unknown subelements are unsupported. A255-octet profile may
            // continue in Fragment subelements; as in Linux
            // ieee80211_mle_basic_sta_prof_size_ok only the first fragment
            // carries the checked STA control/info header.
            if header[0] != SUBELEM_PROFILE || profile.len() < 3 {
                return Err(Error::InvalidBss);
            }
            if profile.len() == 255 {
                while body.get(end) == Some(&SUBELEM_FRAGMENT) {
                    let length = usize::from(*body.get(end + 1).ok_or(Error::InvalidBss)?);
                    end += 2 + length;
                    if end > body.len() {
                        return Err(Error::InvalidBss);
                    }
                    if length < 255 {
                        break;
                    }
                }
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
            bss_change,
            profiles,
            medium_sync,
            eml,
            mld_capabilities,
            mld_id,
            affiliated,
        })
    }
    /// The single Basic MLE of an element stream, reassembled from its
    /// trailing Fragment elements (cfg80211_defragment_element). A Fragment
    /// element that does not continue the MLE is refused.
    pub fn from_ies(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse(&basic_body(bytes)?)
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

/// One requested affiliated link's per-STA profile in an association
/// response: the fixed capability/status fields and the profile elements
/// (which still need `link_elements` inheritance before validation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkResponse {
    link_id: u8,
    address: Option<[u8; 6]>,
    capability: u16,
    status: u16,
    elements: Vec<u8>,
}
impl LinkResponse {
    pub fn link_id(&self) -> u8 {
        self.link_id
    }
    /// The AP's affiliated link address from STA Info, when present.
    pub fn address(&self) -> Option<[u8; 6]> {
        self.address
    }
    pub fn capability(&self) -> u16 {
        self.capability
    }
    /// Per-link status; non-zero rejects only this link (mlme.c
    /// ieee80211_assoc_success removes it from the valid links).
    pub fn status(&self) -> u16 {
        self.status
    }
    /// The reassembled profile elements after capability/status.
    pub fn elements(&self) -> &[u8] {
        &self.elements
    }
}

/// The single Basic MLE body (after the extension id), reassembled from
/// any Fragment elements that immediately follow a255-octet MLE. Fragment
/// elements anywhere else, or a second Basic MLE, are refused.
fn basic_body(mut bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut found: Option<Vec<u8>> = None;
    let mut continuing = false;
    while !bytes.is_empty() {
        let (id, length) = match bytes {
            [id, length, ..] => (*id, usize::from(*length)),
            _ => return Err(Error::InvalidBss),
        };
        let body = bytes.get(2..2 + length).ok_or(Error::InvalidBss)?;
        bytes = &bytes[2 + length..];
        if id == ELEMENT_FRAGMENT {
            let Some(mle) = found.as_mut().filter(|_| continuing) else {
                return Err(Error::InvalidBss);
            };
            mle.extend_from_slice(body);
            continuing = length == 255;
            continue;
        }
        continuing = false;
        if id == 255 && body.first() == Some(&EXT_MULTI_LINK) {
            if found.is_some() {
                return Err(Error::InvalidBss);
            }
            found = Some(body[1..].to_vec());
            continuing = length == 255;
        }
    }
    found.ok_or(Error::InvalidBss)
}

/// parse.c::ieee80211_mle_get_sta_prof over a validated Basic MLE body:
/// (STA control, STA info including its length octet, profile content), the
/// profile reassembled from Fragment subelements as Linux does.
fn sta_profile(body: &[u8], link_id: u8) -> Option<(u16, [u8; 7], Vec<u8>)> {
    let mut at = 2 + usize::from(*body.get(2)?);
    while at < body.len() {
        let length = usize::from(*body.get(at + 1)?);
        let mut profile = body.get(at + 2..at + 2 + length)?.to_vec();
        at += 2 + length;
        let mut continuing = length == 255;
        while continuing && body.get(at) == Some(&SUBELEM_FRAGMENT) {
            let length = usize::from(*body.get(at + 1)?);
            profile.extend_from_slice(body.get(at + 2..at + 2 + length)?);
            at += 2 + length;
            continuing = length == 255;
        }
        let control = u16::from_le_bytes([profile[0], profile[1]]);
        if control & 15 != u16::from(link_id) {
            continue;
        }
        let info_len = usize::from(profile[2]);
        let mut info = [0; 7];
        let raw = profile.get(2..2 + info_len)?;
        let kept = raw.len().min(7);
        info[..kept].copy_from_slice(&raw[..kept]);
        let content = profile.get(2 + info_len..)?.to_vec();
        return Some((control, info, content));
    }
    None
}

/// Element identity used by Linux's PRESENT_ELEM lists and the
/// Non-Inheritance element: extension elements are offset by0x100.
fn element_key(id: u8, body: &[u8]) -> u16 {
    match (id, body.first()) {
        (255, Some(&ext)) => 0x100 | u16::from(ext),
        _ => u16::from(id),
    }
}

/// Elements whose absence in a per-STA profile must be signalled through
/// Non-Inheritance: the ADD_PRESENT_ELEM set of
/// mlme.c::ieee80211_add_link_elems (power capability and supported channels
/// are never emitted here because no spectrum-management capability is set).
fn tracked(key: u16) -> bool {
    matches!(
        key,
        33 | 36 | 45 | 191 | 0x123 /* HE */ | 0x16c /* EHT */ | 0x198 /* UHR */
    )
}

/// The ordered tracked element keys present in an element stream.
pub(super) fn present_elements(bytes: &[u8]) -> Result<Vec<u16>, Error> {
    let mut present = Vec::new();
    ies(bytes, |id, body| {
        let key = element_key(id, body);
        if tracked(key) {
            present.push(key);
        }
        Ok(())
    })?;
    Ok(present)
}

/// mlme.c::ieee80211_add_non_inheritance_elem: list every outer present
/// element missing from the profile, normal ids then extension ids; nothing
/// is emitted when the profile repeats every outer element.
fn push_non_inheritance(out: &mut Vec<u8>, outer: &[u16], inner: &[u16]) {
    let missing = |extension: bool| -> Vec<u8> {
        outer
            .iter()
            .filter(|key| (**key >= 0x100) == extension && !inner.contains(key))
            .map(|key| *key as u8)
            .collect()
    };
    let (normal, extension) = (missing(false), missing(true));
    if normal.is_empty() && extension.is_empty() {
        return;
    }
    out.extend_from_slice(&[
        255,
        (3 + normal.len() + extension.len()) as u8,
        EXT_NON_INHERITANCE,
        normal.len() as u8,
    ]);
    out.extend_from_slice(&normal);
    out.push(extension.len() as u8);
    out.extend_from_slice(&extension);
}

/// One per-STA profile subelement for an additional requested link, as the
/// ieee80211_assoc_add_ml_elem loop writes it: Link ID with COMPLETE and STA
/// MAC present, STA Info (length7, own link MAC), the capability field and
/// the link's own elements, then Non-Inheritance against `outer`.
pub(super) fn push_request_profile(
    out: &mut Vec<u8>,
    link_id: u8,
    own_link: [u8; 6],
    capability: u16,
    elements: &[u8],
    outer: &[u16],
) -> Result<(), Error> {
    if link_id >= MAX_LINKS || !unicast(own_link) {
        return Err(Error::InvalidBss);
    }
    let inner = present_elements(elements)?;
    let mut body = Vec::with_capacity(elements.len() + 24);
    body.extend_from_slice(&(u16::from(link_id) | STA_COMPLETE | STA_MAC).to_le_bytes());
    body.push(7);
    body.extend_from_slice(&own_link);
    body.extend_from_slice(&capability.to_le_bytes());
    body.extend_from_slice(elements);
    push_non_inheritance(&mut body, outer, &inner);
    push_fragmented(out, SUBELEM_PROFILE, &body, SUBELEM_FRAGMENT);
    Ok(())
}

/// ieee80211_fragment_element: a first (sub)element of at most255 octets
/// followed by `fragment` (sub)elements carrying the remainder.
fn push_fragmented(out: &mut Vec<u8>, id: u8, body: &[u8], fragment: u8) {
    let mut chunks = body.chunks(255);
    let first = chunks.next().unwrap_or(&[]);
    out.extend_from_slice(&[id, first.len() as u8]);
    out.extend_from_slice(first);
    for chunk in chunks {
        out.extend_from_slice(&[fragment, chunk.len() as u8]);
        out.extend_from_slice(chunk);
    }
}

/// Per-link element view for an affiliated link (parse.c
/// ieee802_11_parse_elems_full with a link id): outer elements are inherited
/// unless named by the profile's Non-Inheritance element or repeated in the
/// profile (whose instance overrides, including all vendor elements); the
/// outer Multi-Link and Non-Inheritance elements are never inherited.
pub fn link_elements(outer: &[u8], profile: &[u8]) -> Result<Vec<u8>, Error> {
    let mut overridden = Vec::new();
    let mut excluded = Vec::new();
    let mut non_inheritance = false;
    ies(profile, |id, body| {
        let key = element_key(id, body);
        if key == 0x100 | u16::from(EXT_NON_INHERITANCE) {
            if non_inheritance {
                return Err(Error::Protocol);
            }
            non_inheritance = true;
            let normal_len = usize::from(*body.get(1).ok_or(Error::Protocol)?);
            let normal = body.get(2..2 + normal_len).ok_or(Error::Protocol)?;
            let rest = &body[2 + normal_len..];
            let extension_len = usize::from(*rest.first().ok_or(Error::Protocol)?);
            let extension = rest.get(1..1 + extension_len).ok_or(Error::Protocol)?;
            if rest.len() != 1 + extension_len {
                return Err(Error::Protocol);
            }
            excluded.extend(normal.iter().map(|id| u16::from(*id)));
            excluded.extend(extension.iter().map(|id| 0x100 | u16::from(*id)));
        } else {
            overridden.push(key);
        }
        Ok(())
    })
    .map_err(|_| Error::Protocol)?;
    let mut view = Vec::with_capacity(outer.len() + profile.len());
    let mut mle_fragment = false;
    ies(outer, |id, body| {
        let key = element_key(id, body);
        // The outer MLE and its Fragment continuation are never inherited.
        let continues = mle_fragment && id == ELEMENT_FRAGMENT;
        mle_fragment = (key == 0x100 | u16::from(EXT_MULTI_LINK) || continues) && body.len() == 255;
        if !continues
            && key != 0x100 | u16::from(EXT_MULTI_LINK)
            && key != 0x100 | u16::from(EXT_NON_INHERITANCE)
            && !excluded.contains(&key)
            && !overridden.contains(&key)
        {
            view.extend_from_slice(&[id, body.len() as u8]);
            view.extend_from_slice(body);
        }
        Ok(())
    })
    .map_err(|_| Error::Protocol)?;
    ies(profile, |id, body| {
        if element_key(id, body) != 0x100 | u16::from(EXT_NON_INHERITANCE) {
            view.extend_from_slice(&[id, body.len() as u8]);
            view.extend_from_slice(body);
        }
        Ok(())
    })?;
    Ok(view)
}

/// mlme.c::ieee80211_add_link_elems places the assoc link's Basic MLE after
/// the HE/HE 6GHz/regulatory elements and immediately before EHT
/// Capabilities (802.11be element order). Without EHT Capabilities it is
/// appended. `ies_start` is the offset of the first element.
pub fn insert_request_element(frame: &mut Vec<u8>, ies_start: usize, element: &[u8]) {
    let mut at = ies_start;
    while let (Some(&id), Some(&length)) = (frame.get(at), frame.get(at + 1)) {
        if id == 255 && frame.get(at + 2) == Some(&crate::association::eht::EXT_EHT_CAPABILITIES) {
            frame.splice(at..at, element.iter().copied());
            return;
        }
        at += 2 + usize::from(length);
    }
    frame.extend_from_slice(element);
}
