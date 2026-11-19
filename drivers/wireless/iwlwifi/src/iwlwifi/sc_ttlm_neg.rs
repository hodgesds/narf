//! Negotiated TID-to-link mapping (TTLM) and ML link reconfiguration for
//! the native Sc/Bz station MLD: Linux `IWL_MLD_CAPA_OPS`.
//!
//! The advertised-TTLM machinery in `sc_emlsr` covers mappings the AP
//! announces in beacons and association responses. This module covers the
//! other direction: mappings the station negotiates after association
//! through Protected EHT Action frames (Linux `cfg80211::set_ttlm` and
//! `assoc_ml_reconf`), plus teardown of a negotiated mapping.
//!
//! Frame shapes are taken from Linux `include/linux/ieee80211.h`
//! `struct ieee80211_mgmt`'s Protected EHT Action members:
//! - TTLM Request: action code, dialog token, variable (TTLM element).
//! - TTLM Response: action code, dialog token, status code (`__le16`),
//!   variable (TTLM element).
//! - TTLM Teardown: action code only.
//! - ML Reconfiguration Request: action code, dialog token, variable.
//! - ML Reconfiguration Response: action code, dialog token, count,
//!   variable.
//!
//! The TTLM element itself reuses the advertised element framing
//! (`sc_emlsr`'s `TTLM_*` constants, from Linux `ieee80211-eht.h`):
//! control byte (direction, default-map, switch-time-present,
//! expected-duration-present, link-map-size), presence indicator, switch
//! time, expected duration, then one link map per present TID. The one
//! deliberate difference from the advertised parser: a negotiated element
//! may map different TIDs to different link sets (moving a TID between
//! links is the negotiation); the advertised parser requires every TID on
//! the same set.
//!
//! WIRE VALUES, VERIFIED (#1553). The Protected EHT Action values below
//! are confirmed against Linux `include/linux/ieee80211-eht.h`
//! `enum ieee80211_protected_eht_actioncode` (ref tree
//! `~/workspace/scratch/wifi-wcn6750-linux`): TTLM request 0, TTLM
//! response 1, TTLM teardown 2 (lines 446-448), ML reconfiguration
//! request 11 and response 12 (lines 457-458). The category 37 is Linux
//! `WLAN_CATEGORY_PROTECTED_EHT` (`include/linux/ieee80211.h:1867`),
//! and the frame shapes match `struct ieee80211_mgmt`'s Protected EHT
//! Action members (`ieee80211.h:1160-1178`) and the mac80211 send sites
//! (`net/mac80211/mlme.c`: TTLM request 8609, response 8678, teardown
//! 8919). The TTLM element framing (ext id 109, control byte, presence
//! indicator, switch time, expected duration, per-TID link maps) is
//! Linux `WLAN_EID_EXT_TID_TO_LINK_MAPPING` (`ieee80211.h:1827`) and
//! `ieee80211_tid_to_link_map_size_ok` (`ieee80211-eht.h:1201`).
//! Negotiated TTLM is NOT advertised: `device.rs` leaves
//! `mld_capa_and_ops` at 0 until the action-frame transport below exists
//! (`MLD_CAP_OP_TTLM_NEG_SAME` is the bit this engine's single
//! both-directions map would claim).
//!
//! ML RECONFIGURATION, VERIFIED (#1553). The request carries a
//! Multi-Link element of type RECONF with per-station profiles (Linux
//! `ieee80211_build_ml_reconf_req`, `net/mac80211/mlme.c:11218`):
//! control type 2 (`ieee80211-eht.h:467`), MLD MAC address always
//! present, EML capabilities when EMLSR/EMLMR is supported, MLD
//! capabilities and operations when links are added; each changing link
//! gets a per-STA profile subelement (id 0) whose control carries the
//! link id, the operation (ADD_LINK 2 / DEL_LINK 3,
//! `ieee80211-eht.h:1158-1159`), COMPLETE_PROFILE for adds, and
//! STA-MAC-ADDR-PRESENT. An add profile carries the STA MAC address,
//! the capability field, the link's operational elements
//! (caller-supplied, copied verbatim), and the WMM info IE
//! (`ieee80211_add_wmm_info_ie`, `net/mac80211/util.c:4493`). The
//! response carries a `count` of `struct ieee80211_ml_reconf_status`
//! duples (link id in the info low nibble + LE16 status,
//! `ieee80211.h:1225`) followed, when links were added, by a group key
//! data length byte and the group key bytes
//! (`ieee80211_process_ml_reconf_resp`, `mlme.c:10985`): every changed
//! link gets exactly one duple, a failed removal is a protocol error, a
//! failed add drops that link, and the group key data is opaque
//! (mac80211 hands it to userland). There is no add/remove mask and no
//! TTLM element on the wire, and no switch time: the new valid set takes
//! effect when the response is processed, and a negotiated mapping in
//! effect is clipped to it (a TID left with no link drops the mapping
//! to the default). Link reconfiguration is NOT advertised either:
//! `IEEE80211_MLD_CAP_OP_LINK_RECONF_SUPPORT` (0x2000,
//! `ieee80211-eht.h:544`) stays clear in `device.rs`.
//!
//! Standing limitation, and the reason neither bit is advertised: the
//! MLME action-frame receive/transmit transport (Linux
//! `ieee80211_process_neg_ttlm_req`/`_res`, `ieee80211_process_ml_reconf_resp`)
//! and a `set_ttlm`/`assoc_ml_reconf` request path in `narf_wireless` are
//! still missing; `begin_request`/`begin_reconf`/`handle_response`/
//! `handle_reconf_response` are driven only by their fixtures, and
//! `Connection::service_ttlm` services `due` for a map that production
//! cannot stage yet. An ML element over 255 bytes is refused by the request
//! builder (Linux fragments it, `ieee80211_fragment_element`);
//! fragmentation is a remainder.
//!
//! Invariants:
//! - A response is matched to its request by dialog token; a token
//!   mismatch leaves the pending exchange untouched (a stray frame must
//!   not cancel an exchange), while a status failure, malformed element,
//!   or map outside the valid link set terminates the exchange.
//! - An accepted mapping supersedes any planned advertised switch: the
//!   advertised timer is cancelled, so the two switch paths can never
//!   race. A negotiated mapping already in effect is never withdrawn by
//!   beacon element absence (only teardown or reconfiguration withdraws
//!   it); see `TtlmState::negotiated`.
//! - A mapping takes effect at its switch time through the same
//!   safety-buffered TSF rule as the advertised path (switch time is TSF
//!   bits 10..25; scheduled 100 ms early; a switch time already past on a
//!   one-shot response applies immediately, since unlike a repeating
//!   beacon it cannot be re-read).
//! - A reconfiguration response carries exactly one status duple per
//!   changed link: a failed removal is a protocol error, a failed add
//!   drops that link, and the resulting valid set must be non-empty.
//!   A negotiated mapping in effect is clipped to the new valid set; a
//!   TID left with no link drops the mapping to the default.

use super::sc_emlsr::{
    AdvTtlm, TtlmState, ADV_TTLM_SAFETY_BUFFER_US, ADV_TTLM_ST_UNDERFLOW, TTLM_DEF_LINK_MAP,
    TTLM_DIRECTION_BOTH, TTLM_EXPECTED_DUR_PRESENT, TTLM_EXT_ID, TTLM_LINK_MAP_SIZE,
    TTLM_SWITCH_TIME_PRESENT,
};
use alloc::vec::Vec;

/// Linux `WLAN_CATEGORY_PROTECTED_EHT` (`include/linux/ieee80211.h:1867`),
/// verified #1553.
pub(super) const PROT_EHT_CATEGORY: u8 = 37;

/// Protected EHT Action field values, verified #1553 against Linux
/// `include/linux/ieee80211-eht.h` `enum ieee80211_protected_eht_actioncode`:
/// TTLM request/response/teardown (lines 446-448) and ML reconfiguration
/// request/response (lines 457-458). The ML reconfiguration values were
/// corrected from 3/4, which Linux assigns to EPCS enable
/// request/response (lines 449-450); the ML reconfiguration variable
/// layout is verified too, see the module docs.
pub(super) const PROT_EHT_TTLM_REQUEST: u8 = 0;
pub(super) const PROT_EHT_TTLM_RESPONSE: u8 = 1;
pub(super) const PROT_EHT_TTLM_TEARDOWN: u8 = 2;
pub(super) const PROT_EHT_ML_RECONF_REQUEST: u8 = 11;
pub(super) const PROT_EHT_ML_RECONF_RESPONSE: u8 = 12;

/// MLD Capabilities and Operations bits advertised in the association
/// request (`device.rs`), verified #1553 against Linux
/// `include/linux/ieee80211-eht.h:537-544`. The TID-to-link-map
/// negotiation field (mask 0x0060) with value SUPP_SAME (1) is 1 << 5:
/// this engine carries one map for both directions, so SAME is the
/// honest claim (DIFF would promise per-direction maps). The link
/// reconfiguration support bit (`IEEE80211_MLD_CAP_OP_LINK_RECONF_SUPPORT`,
/// 0x2000) is set: the ML reconfiguration wire layout is verified, see
/// the module docs.
pub(super) const MLD_CAP_OP_TTLM_NEG_SAME: u16 = 0x0020;
pub(super) const MLD_CAP_OP_LINK_RECONF_SUPPORT: u16 = 0x2000;

/// Linux `WLAN_EID_EXT_EHT_MULTI_LINK` (`include/linux/ieee80211.h:1825`).
pub(super) const ML_EXT_ID: u8 = 107;

/// Multi-Link element control: type RECONF (2) in bits 0..2, and the
/// RECONF common-info presence bits (Linux
/// `include/linux/ieee80211-eht.h:464-467, 562-566`).
pub(super) const ML_CONTROL_TYPE_RECONF: u16 = 2;
pub(super) const MLC_RECONF_PRES_MLD_MAC_ADDR: u16 = 0x0010;
pub(super) const MLC_RECONF_PRES_EML_CAPA: u16 = 0x0020;
pub(super) const MLC_RECONF_PRES_MLD_CAPA_OP: u16 = 0x0040;

/// Per-STA profile subelement id (Linux
/// `include/linux/ieee80211-eht.h:1003`).
pub(super) const MLE_SUBELEM_PER_STA_PROFILE: u8 = 0;

/// RECONF per-STA profile control bits (Linux
/// `include/linux/ieee80211-eht.h:1151-1159`): link id in bits 0..3,
/// COMPLETE_PROFILE for adds, STA-MAC-ADDR-PRESENT, operation type in
/// bits 7..10 (ADD_LINK 2, DEL_LINK 3).
pub(super) const MLE_STA_RECONF_CONTROL_LINK_ID: u16 = 0x000f;
pub(super) const MLE_STA_RECONF_CONTROL_COMPLETE_PROFILE: u16 = 0x0010;
pub(super) const MLE_STA_RECONF_CONTROL_STA_MAC_ADDR_PRESENT: u16 = 0x0020;
pub(super) const MLE_STA_RECONF_CONTROL_OPERATION_TYPE: u16 = 0x0780;
pub(super) const MLE_STA_RECONF_CONTROL_OPERATION_TYPE_ADD_LINK: u16 = 2;
pub(super) const MLE_STA_RECONF_CONTROL_OPERATION_TYPE_DEL_LINK: u16 = 3;

/// EML capability bits gating the EML Capabilities field in RECONF
/// common info (Linux `ieee80211-eht.h:499,521`).
pub(super) const EML_CAP_EMLSR_SUPP: u16 = 0x0001;
pub(super) const EML_CAP_EMLMR_SUPPORT: u16 = 0x0080;

/// A reconfiguration status duple's link id lives in the info byte's
/// low nibble (Linux `struct ieee80211_ml_reconf_status`,
/// `include/linux/ieee80211.h:1225-1230`).
pub(super) const ML_RECONF_LINK_ID_MASK: u8 = 0x0f;

/// Linux `IEEE80211_MLD_MAX_NUM_LINKS` (`ieee80211-eht.h:462`); link
/// id 15 is reserved.
pub(super) const MLD_MAX_NUM_LINKS: u8 = 15;

/// A parsed negotiated TTLM element body (after the extension id).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NegInfo {
    pub switch_time: u16,
    pub duration: u32,
    /// Per-TID link sets. For a default-flag element every entry is
    /// `0xffff`; the handler normalises those to the valid link set.
    pub map: [u16; 8],
    pub default: bool,
}

/// The `sc_emlsr::ttlm_size_ok` framing over an element body after the
/// extension id, with the negotiated rule: every TID present, each with
/// its own (possibly different) non-empty link set.
pub(super) fn parse_neg_t2l(data: &[u8]) -> Result<NegInfo, ()> {
    if !super::sc_emlsr::ttlm_size_ok(data) {
        return Err(());
    }
    let control = data[0];
    if control & 3 != TTLM_DIRECTION_BOTH {
        return Err(());
    }
    let mut pos = 1;
    let mut info = NegInfo {
        switch_time: 0,
        duration: 0,
        map: [0xffff; 8],
        default: false,
    };
    let mut presence = 0u8;
    if control & TTLM_DEF_LINK_MAP == 0 {
        presence = data[pos];
        pos += 1;
    }
    if control & TTLM_SWITCH_TIME_PRESENT != 0 {
        info.switch_time = u16::from_le_bytes([data[pos], data[pos + 1]]).max(1);
        pos += 2;
    }
    if control & TTLM_EXPECTED_DUR_PRESENT != 0 {
        info.duration = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], 0]);
        pos += 3;
    }
    if control & TTLM_DEF_LINK_MAP != 0 {
        info.default = true;
        return Ok(info);
    }
    if presence != 0xff {
        return Err(());
    }
    let size = if control & TTLM_LINK_MAP_SIZE != 0 {
        1
    } else {
        2
    };
    for tid in 0..8 {
        let at = pos + tid * size;
        info.map[tid] = if size == 1 {
            u16::from(data[at])
        } else {
            u16::from_le_bytes([data[at], data[at + 1]])
        };
        if info.map[tid] == 0 {
            return Err(());
        }
    }
    Ok(info)
}

/// Build a full TID-to-link mapping element field
/// (`[255, len, 109, body...]`), the inverse of `parse_neg_t2l`.
/// `None` builds the default mapping (all TIDs to all valid links).
/// A zero switch time or duration omits that field, matching the
/// parser's "absent means in effect / unparsed" reading.
pub(super) fn build_neg_element(
    map: Option<&[u16; 8]>,
    switch_time: u16,
    duration: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut control = TTLM_DIRECTION_BOTH;
    if map.is_none() {
        control |= TTLM_DEF_LINK_MAP;
    }
    if switch_time != 0 {
        control |= TTLM_SWITCH_TIME_PRESENT;
    }
    if duration != 0 {
        control |= TTLM_EXPECTED_DUR_PRESENT;
    }
    body.push(control);
    if let Some(map) = map {
        body.push(0xff);
        if switch_time != 0 {
            body.extend_from_slice(&switch_time.to_le_bytes());
        }
        if duration != 0 {
            body.extend_from_slice(&duration.to_le_bytes()[..3]);
        }
        for m in map {
            body.extend_from_slice(&m.to_le_bytes());
        }
    } else {
        if switch_time != 0 {
            body.extend_from_slice(&switch_time.to_le_bytes());
        }
        if duration != 0 {
            body.extend_from_slice(&duration.to_le_bytes()[..3]);
        }
    }
    let mut element = alloc::vec![255, (body.len() + 1) as u8, TTLM_EXT_ID];
    element.extend_from_slice(&body);
    element
}

/// Build a TTLM Request action frame body (no 802.11 header).
pub(super) fn build_ttlm_request(
    token: u8,
    map: &[u16; 8],
    switch_time: u16,
    duration: u32,
) -> Vec<u8> {
    let mut frame = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_TTLM_REQUEST, token];
    frame.extend_from_slice(&build_neg_element(Some(map), switch_time, duration));
    frame
}

/// Build a TTLM Teardown action frame body (action code only).
pub(super) fn build_ttlm_teardown() -> Vec<u8> {
    alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_TTLM_TEARDOWN]
}

/// One link to add in an ML reconfiguration request: the STA MAC
/// address the AP assigned the link, the capability field, the link's
/// operational elements copied from its BSS (opaque to this engine,
/// carried verbatim, as Linux copies `add_links_data->link[].elems`),
/// and the QoS info byte for the WMM info IE (Linux: U-APSD queues /
/// max SP length, else 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AddLink<'a> {
    pub link_id: u8,
    pub sta_addr: [u8; 6],
    pub capab: u16,
    pub elems: &'a [u8],
    pub qos_info: u8,
}

/// One link to remove in an ML reconfiguration request: the STA MAC
/// address of the link being removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RemoveLink {
    pub link_id: u8,
    pub sta_addr: [u8; 6],
}

/// Linux `ieee80211_add_wmm_info_ie` (`net/mac80211/util.c:4493`):
/// vendor-specific element, WFA OUI 00:50:F2, WME type 2, info subtype
/// 0, version 1, QoS info byte.
fn build_wmm_info_ie(qos_info: u8) -> [u8; 9] {
    [221, 7, 0x00, 0x50, 0xf2, 2, 0, 1, qos_info]
}

/// Build an ML Reconfiguration Request action frame body (no 802.11
/// header), Linux `ieee80211_build_ml_reconf_req`
/// (`net/mac80211/mlme.c:11218`): category, action 11, dialog token,
/// then the Multi-Link element of type RECONF with per-station profiles
/// in ascending link-id order. `mld_capa_ops` is the advertised MLD
/// capabilities and operations (it is only carried when links are
/// added); `eml_capa` is carried, with its presence bit, only when
/// links are added and EMLSR/EMLMR is supported, exactly as Linux
/// gates it. Returns `None` if a link id is out of range, a link is
/// listed twice or on both sides, or the ML element would exceed 255
/// bytes (Linux fragments it with `ieee80211_fragment_element`; that
/// is a remainder, not a silent truncation).
pub(super) fn build_ml_reconf_request(
    token: u8,
    mld_mac_addr: [u8; 6],
    mld_capa_ops: u16,
    eml_capa: u16,
    add: &[AddLink],
    remove: &[RemoveLink],
) -> Option<Vec<u8>> {
    let adding = !add.is_empty();
    let eml = adding && eml_capa & (EML_CAP_EMLSR_SUPP | EML_CAP_EMLMR_SUPPORT) != 0;
    let mut control = ML_CONTROL_TYPE_RECONF | MLC_RECONF_PRES_MLD_MAC_ADDR;
    if eml {
        control |= MLC_RECONF_PRES_EML_CAPA;
    }
    if adding {
        control |= MLC_RECONF_PRES_MLD_CAPA_OP;
    }
    let common_len: usize = 1 + 6 + if eml { 2 } else { 0 } + if adding { 2 } else { 0 };
    // One profile per changing link; profiles are emitted in ascending
    // link-id order, as Linux's single link-id loop does.
    let mut profiles = Vec::new();
    let mut seen: u16 = 0;
    for link_id in 0..MLD_MAX_NUM_LINKS {
        let bit = 1u16 << link_id;
        if let Some(link) = add.iter().find(|l| l.link_id == link_id) {
            seen |= bit;
            let sta_info_len = 1 + 6 + 2 + link.elems.len() + 9;
            if sta_info_len > u8::MAX as usize - 2 {
                return None;
            }
            let ctrl = u16::from(link_id) & MLE_STA_RECONF_CONTROL_LINK_ID
                | MLE_STA_RECONF_CONTROL_COMPLETE_PROFILE
                | MLE_STA_RECONF_CONTROL_STA_MAC_ADDR_PRESENT
                | (MLE_STA_RECONF_CONTROL_OPERATION_TYPE_ADD_LINK << 7)
                    & MLE_STA_RECONF_CONTROL_OPERATION_TYPE;
            profiles.push(MLE_SUBELEM_PER_STA_PROFILE);
            profiles.push((2 + sta_info_len) as u8);
            profiles.extend_from_slice(&ctrl.to_le_bytes());
            profiles.push(sta_info_len as u8);
            profiles.extend_from_slice(&link.sta_addr);
            profiles.extend_from_slice(&link.capab.to_le_bytes());
            profiles.extend_from_slice(link.elems);
            profiles.extend_from_slice(&build_wmm_info_ie(link.qos_info));
        } else if let Some(link) = remove.iter().find(|l| l.link_id == link_id) {
            seen |= bit;
            let ctrl = u16::from(link_id) & MLE_STA_RECONF_CONTROL_LINK_ID
                | MLE_STA_RECONF_CONTROL_STA_MAC_ADDR_PRESENT
                | (MLE_STA_RECONF_CONTROL_OPERATION_TYPE_DEL_LINK << 7)
                    & MLE_STA_RECONF_CONTROL_OPERATION_TYPE;
            profiles.push(MLE_SUBELEM_PER_STA_PROFILE);
            profiles.push(9);
            profiles.extend_from_slice(&ctrl.to_le_bytes());
            profiles.push(7);
            profiles.extend_from_slice(&link.sta_addr);
        }
    }
    // Any add/remove entry whose link id is out of range, or a link
    // listed twice, is not covered by the loop above.
    if add.iter().any(|l| l.link_id >= MLD_MAX_NUM_LINKS)
        || remove.iter().any(|l| l.link_id >= MLD_MAX_NUM_LINKS)
        || add.len() + remove.len() != seen.count_ones() as usize
    {
        return None;
    }
    let elem_len = 1 + 2 + common_len + profiles.len();
    if elem_len > u8::MAX as usize {
        return None;
    }
    let mut frame = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_ML_RECONF_REQUEST, token];
    frame.push(255);
    frame.push(elem_len as u8);
    frame.push(ML_EXT_ID);
    frame.extend_from_slice(&control.to_le_bytes());
    frame.push(common_len as u8);
    frame.extend_from_slice(&mld_mac_addr);
    if eml {
        frame.extend_from_slice(&eml_capa.to_le_bytes());
    }
    if adding {
        frame.extend_from_slice(&mld_capa_ops.to_le_bytes());
    }
    frame.extend_from_slice(&profiles);
    Some(frame)
}

/// Why a negotiated exchange failed. `WrongToken` (and the frame-shape
/// errors) leave a pending exchange untouched; `Rejected` and
/// `Malformed` terminate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NegError {
    Truncated,
    WrongCategory,
    WrongAction,
    WrongToken,
    Rejected,
    Malformed,
}

/// How an accepted mapping takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NegOutcome {
    /// Switch time absent (or already past): in effect now.
    Immediate,
    /// Switch time in the future: staged until `due`.
    Staged,
}

/// A reconfiguration acceptance: the link set after applying the
/// accepted adds/removes, plus the opaque group key data for the
/// accepted added links (empty when no link was added). The response
/// carries no switch time, so the new set takes effect when the
/// response is processed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReconfOutcome {
    pub new_valid: u16,
    pub added: u16,
    pub removed: u16,
    pub group_key_data: Vec<u8>,
}

/// Link masks a reconfiguration request asked to add or remove.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Reconf {
    pub add: u16,
    pub remove: u16,
}

/// What the pending exchange is: a TTLM negotiation (carrying the
/// requested map) or an ML reconfiguration (carrying the requested
/// add/remove masks the response's status duples are checked against).
#[derive(Clone, Debug, PartialEq, Eq)]
enum PendingKind {
    Ttlm {
        map: [u16; 8],
        switch_time: u16,
        duration: u32,
    },
    Reconf(Reconf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    token: u8,
    kind: PendingKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Staged {
    map: [u16; 8],
    switch_at_ms: u64,
}

/// Negotiated TTLM state for one MLD association: the exchange awaiting
/// a response, a mapping staged for its switch time, and the mapping
/// currently in effect (`None` means the default mapping).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct NegotiatedTtlm {
    pending: Option<Pending>,
    staged: Option<Staged>,
    map: Option<[u16; 8]>,
}

/// Split one element field off the front of an element stream and return
/// its body after the extension id. Mirrors `sc_emlsr::ttlm_elements`'
/// walk for the single-element action-frame case.
fn element_body(ies: &[u8]) -> Result<&[u8], NegError> {
    if ies.len() < 2 {
        return Err(NegError::Truncated);
    }
    let len = usize::from(ies[1]);
    let Some(body) = ies.get(2..2 + len) else {
        return Err(NegError::Truncated);
    };
    if ies[0] != 255 || body.first() != Some(&TTLM_EXT_ID) {
        return Err(NegError::Malformed);
    }
    Ok(&body[1..])
}

/// Clip a per-TID mapping to a new valid link set. `None` when any
/// TID is left with no link: the mapping no longer covers every TID
/// and must be dropped to the default.
fn clip_map(map: [u16; 8], valid: u16) -> Option<[u16; 8]> {
    let mut clipped = [0u16; 8];
    for (tid, m) in map.iter().enumerate() {
        clipped[tid] = m & valid;
        if clipped[tid] == 0 {
            return None;
        }
    }
    Some(clipped)
}

impl NegotiatedTtlm {
    /// Start a TTLM negotiation exchange. A new exchange abandons any
    /// unanswered one; dialog tokens are caller-allocated.
    pub(super) fn begin_request(
        &mut self,
        token: u8,
        map: [u16; 8],
        switch_time: u16,
        duration: u32,
    ) {
        self.pending = Some(Pending {
            token,
            kind: PendingKind::Ttlm {
                map,
                switch_time,
                duration,
            },
        });
    }

    /// Start an ML reconfiguration exchange. `add`/`remove` are the
    /// link masks the request asked to change; the response's status
    /// duples are checked against them.
    pub(super) fn begin_reconf(&mut self, token: u8, add: u16, remove: u16) {
        self.pending = Some(Pending {
            token,
            kind: PendingKind::Reconf(Reconf { add, remove }),
        });
    }

    /// The mapping currently in effect, if a negotiated one is active.
    pub(super) fn map(&self) -> Option<[u16; 8]> {
        self.map
    }

    /// Handle a TTLM Response action frame body. `valid` is the current
    /// valid link mask; `now_tsf` is the local TSF at receipt (the
    /// switch time is TSF bits 10..25, as on the advertised path).
    pub(super) fn handle_response(
        &mut self,
        frame: &[u8],
        valid: u16,
        ttlm: &mut TtlmState,
        now_tsf: u64,
        now_ms: u64,
    ) -> Result<NegOutcome, NegError> {
        if frame.len() < 5 {
            return Err(NegError::Truncated);
        }
        if frame[0] != PROT_EHT_CATEGORY {
            return Err(NegError::WrongCategory);
        }
        if frame[1] != PROT_EHT_TTLM_RESPONSE {
            return Err(NegError::WrongAction);
        }
        let Some(pending) = &self.pending else {
            return Err(NegError::WrongToken);
        };
        let PendingKind::Ttlm { .. } = &pending.kind else {
            return Err(NegError::WrongToken);
        };
        if frame[2] != pending.token {
            return Err(NegError::WrongToken);
        }
        let status = u16::from_le_bytes([frame[3], frame[4]]);
        if status != 0 {
            self.pending = None;
            return Err(NegError::Rejected);
        }
        // From here the exchange is terminal: a malformed or
        // out-of-range acceptance must not leave a stale pending entry
        // for a retransmitted response to revive.
        self.pending = None;
        let body = element_body(&frame[5..])?;
        let info = parse_neg_t2l(body).map_err(|()| NegError::Malformed)?;
        self.accept(info, valid, ttlm, now_tsf, now_ms)
    }

    /// Handle an ML Reconfiguration Response action frame body, Linux
    /// `ieee80211_process_ml_reconf_resp` (`net/mac80211/mlme.c:10985`):
    /// category, action 12, dialog token, `count`, then `count` status
    /// duples (link id in the info low nibble + LE16 status), followed
    /// by a group key data length byte and the group key bytes when
    /// links were added. Every changed link gets exactly one duple; a
    /// failed removal is a protocol error, a failed add drops that
    /// link. The new valid set takes effect immediately; a negotiated
    /// mapping in effect is clipped to it (a TID left with no link
    /// drops the mapping to the default). Returns the accepted link
    /// changes so the caller can update its link state and install the
    /// group key data.
    pub(super) fn handle_reconf_response(
        &mut self,
        frame: &[u8],
        valid: u16,
        ttlm: &mut TtlmState,
    ) -> Result<ReconfOutcome, NegError> {
        if frame.len() < 4 {
            return Err(NegError::Truncated);
        }
        if frame[0] != PROT_EHT_CATEGORY {
            return Err(NegError::WrongCategory);
        }
        if frame[1] != PROT_EHT_ML_RECONF_RESPONSE {
            return Err(NegError::WrongAction);
        }
        let Some(pending) = &self.pending else {
            return Err(NegError::WrongToken);
        };
        let PendingKind::Reconf(requested) = &pending.kind else {
            return Err(NegError::WrongToken);
        };
        if frame[2] != pending.token {
            return Err(NegError::WrongToken);
        }
        // Copy the requested masks out of the pending entry before
        // clearing it: `requested` borrows `self.pending`, so the
        // borrow must end before the assignment below (E0506).
        let requested = *requested;
        // From here the exchange is terminal: a malformed acceptance
        // must not leave a stale pending entry for a retransmitted
        // response to revive.
        self.pending = None;
        let count = usize::from(frame[3]);
        if frame.len() < 4 + count * 3 {
            return Err(NegError::Malformed);
        }
        let mut remaining = requested.add | requested.remove;
        let mut accepted_add = requested.add;
        let accepted_remove = requested.remove;
        let mut pos = 4;
        for _ in 0..count {
            let link_id = frame[pos] & ML_RECONF_LINK_ID_MASK;
            let status = u16::from_le_bytes([frame[pos + 1], frame[pos + 2]]);
            if link_id >= MLD_MAX_NUM_LINKS {
                return Err(NegError::Malformed);
            }
            let bit = 1u16 << link_id;
            if bit & remaining == 0 {
                return Err(NegError::Malformed);
            }
            // Clear the link to detect a duplicate duple for it.
            remaining &= !bit;
            if status != 0 {
                if bit & requested.remove != 0 {
                    // The AP failed to remove a link the station
                    // already removed locally; Linux disconnects.
                    return Err(NegError::Malformed);
                }
                // The AP failed to add a link: drop it from the
                // accepted adds.
                accepted_add &= !bit;
            }
            pos += 3;
        }
        if remaining != 0 {
            return Err(NegError::Malformed);
        }
        let new_valid = (valid & !accepted_remove) | accepted_add;
        if new_valid == 0 {
            return Err(NegError::Malformed);
        }
        let mut group_key_data = Vec::new();
        if accepted_add != 0 {
            // The Group Key Data field must be present when links are
            // added. Its bytes are opaque here (mac80211 hands them to
            // userland); the caller installs them as the MLO GTK.
            if frame.len() < pos + 1 || frame.len() < pos + 1 + usize::from(frame[pos]) {
                return Err(NegError::Malformed);
            }
            let len = usize::from(frame[pos]);
            group_key_data.extend_from_slice(&frame[pos + 1..pos + 1 + len]);
        }
        // The negotiated mapping (active and staged) was computed
        // against the old valid set: clip it to the new set, and drop
        // a mapping that leaves any TID with no link.
        if let Some(map) = self.map.take() {
            match clip_map(map, new_valid) {
                Some(clipped) => {
                    let union = clipped.iter().fold(0u16, |acc, m| acc | m);
                    self.map = Some(clipped);
                    ttlm.info.map = union;
                    ttlm.dormant = new_valid & !union;
                }
                None => {
                    self.map = None;
                    ttlm.negotiated = false;
                    ttlm.active = false;
                    ttlm.dormant = 0;
                    ttlm.info = AdvTtlm::default();
                }
            }
        }
        if let Some(staged) = self.staged.take() {
            if let Some(clipped) = clip_map(staged.map, new_valid) {
                self.staged = Some(Staged {
                    map: clipped,
                    switch_at_ms: staged.switch_at_ms,
                });
            }
        }
        Ok(ReconfOutcome {
            new_valid,
            added: accepted_add,
            removed: accepted_remove,
            group_key_data,
        })
    }

    /// Handle a received TTLM Teardown action frame body: back to the
    /// default mapping, any pending or staged exchange dropped.
    pub(super) fn handle_teardown(
        &mut self,
        frame: &[u8],
        ttlm: &mut TtlmState,
    ) -> Result<(), NegError> {
        if frame.len() < 2 {
            return Err(NegError::Truncated);
        }
        if frame[0] != PROT_EHT_CATEGORY {
            return Err(NegError::WrongCategory);
        }
        if frame[1] != PROT_EHT_TTLM_TEARDOWN {
            return Err(NegError::WrongAction);
        }
        if frame.len() != 2 {
            return Err(NegError::Malformed);
        }
        self.clear(ttlm);
        Ok(())
    }

    /// Drop every negotiated state (local teardown): back to default.
    pub(super) fn clear(&mut self, ttlm: &mut TtlmState) {
        self.pending = None;
        self.staged = None;
        self.map = None;
        *ttlm = TtlmState::default();
    }

    /// When a staged mapping's switch time arrives, install it and
    /// return the per-TID map plus the active/dormant masks the caller
    /// publishes (same derivation as the advertised `due`).
    pub(super) fn due(&mut self, now_ms: u64, valid: u16) -> Option<([u16; 8], u16, u16)> {
        let staged = self.staged?;
        if now_ms < staged.switch_at_ms {
            return None;
        }
        self.staged = None;
        self.map = Some(staged.map);
        let union = staged.map.iter().fold(0u16, |acc, m| acc | m);
        Some((staged.map, union & valid, valid & !union))
    }

    fn apply_now(
        &mut self,
        map: [u16; 8],
        union: u16,
        valid: u16,
        duration: u32,
        ttlm: &mut TtlmState,
    ) {
        self.map = Some(map);
        self.staged = None;
        ttlm.info = AdvTtlm {
            switch_time: 0,
            duration,
            map: union,
        };
        ttlm.active = true;
        ttlm.negotiated = true;
        ttlm.dormant = valid & !union;
    }

    fn accept(
        &mut self,
        info: NegInfo,
        valid: u16,
        ttlm: &mut TtlmState,
        now_tsf: u64,
        now_ms: u64,
    ) -> Result<NegOutcome, NegError> {
        let mut map = info.map;
        if info.default {
            map = [valid; 8];
        }
        if map.iter().any(|m| *m == 0 || *m & !valid != 0) {
            return Err(NegError::Malformed);
        }
        let union = map.iter().fold(0u16, |acc, m| acc | m);
        if union == 0 {
            return Err(NegError::Malformed);
        }
        // A negotiated mapping supersedes any planned advertised switch.
        ttlm.switch_at_ms = None;
        if info.switch_time == 0 {
            self.apply_now(map, union, valid, info.duration, ttlm);
            return Ok(NegOutcome::Immediate);
        }
        // TSF bits 10..25, as on the advertised path.
        let beacon_tu = ((now_tsf >> 10) & 0xffff) as u16;
        let delay = info.switch_time.wrapping_sub(beacon_tu);
        if delay > ADV_TTLM_ST_UNDERFLOW {
            // Already past: a one-shot response cannot be re-read like
            // a repeating beacon, so the mapping is in effect now.
            self.apply_now(map, union, valid, info.duration, ttlm);
            return Ok(NegOutcome::Immediate);
        }
        let delay_us = (u64::from(delay) * 1024).saturating_sub(ADV_TTLM_SAFETY_BUFFER_US);
        self.staged = Some(Staged {
            map,
            switch_at_ms: now_ms + delay_us / 1000,
        });
        Ok(NegOutcome::Staged)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sc_ttlm_neg_tests.rs"]
mod tests;
