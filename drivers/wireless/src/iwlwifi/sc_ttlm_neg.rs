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
//! UNVERIFIED WIRE VALUES. The Protected EHT Action field values below
//! and the ML reconfiguration variable layout (accepted add/remove link
//! masks followed by the accepted TTLM element) are NOT yet confirmed
//! against IEEE 802.11be or Linux `net/mac80211/ieee80211_i.h`: the
//! values used here follow the order Linux's `ieee80211_mgmt` action
//! union lists the frames (ttlm_req, ttlm_res, ttlm_tear_down,
//! ml_reconf_req, ml_reconf_resp). Until they are confirmed, support is
//! NOT advertised: `device.rs` keeps `mld_capa_and_ops` at 0 and the
//! association request carries no negotiation bits. The state machine
//! itself is fully fixture-verified end to end through these builders,
//! so confirming the values is a one-spot change plus the advertisement
//! flip. The MLME action-frame receive/transmit transport that would
//! call this engine is also still missing (same standing as other
//! no-production-caller limitations): the engine is driven by
//! `Connection::service_ttlm` at switch time and by its fixtures.
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
//! - A reconfiguration response may only accept links the request asked
//!   to add or remove, and the resulting valid set must be non-empty;
//!   the carried mapping must fit inside that new valid set.

use super::sc_emlsr::{
    AdvTtlm, TtlmState, ADV_TTLM_SAFETY_BUFFER_US, ADV_TTLM_ST_UNDERFLOW, TTLM_DEF_LINK_MAP,
    TTLM_DIRECTION_BOTH, TTLM_EXPECTED_DUR_PRESENT, TTLM_EXT_ID, TTLM_LINK_MAP_SIZE,
    TTLM_SWITCH_TIME_PRESENT,
};
use alloc::vec::Vec;

/// Linux `WLAN_CATEGORY_PROTECTED_EHT` (`include/linux/ieee80211.h`).
pub(super) const PROT_EHT_CATEGORY: u8 = 37;

/// UNVERIFIED (see module docs): Protected EHT Action field values, in
/// the order Linux's `ieee80211_mgmt` action union lists the frames.
pub(super) const PROT_EHT_TTLM_REQUEST: u8 = 0;
pub(super) const PROT_EHT_TTLM_RESPONSE: u8 = 1;
pub(super) const PROT_EHT_TTLM_TEARDOWN: u8 = 2;
pub(super) const PROT_EHT_ML_RECONF_REQUEST: u8 = 3;
pub(super) const PROT_EHT_ML_RECONF_RESPONSE: u8 = 4;

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

/// Build an ML Reconfiguration Request action frame body. `add` and
/// `remove` are link masks; the carried element is the mapping the
/// reconfigured link set should use.
pub(super) fn build_ml_reconf_request(
    token: u8,
    add: u16,
    remove: u16,
    map: &[u16; 8],
    switch_time: u16,
    duration: u32,
) -> Vec<u8> {
    let mut frame = alloc::vec![PROT_EHT_CATEGORY, PROT_EHT_ML_RECONF_REQUEST, token,];
    frame.extend_from_slice(&add.to_le_bytes());
    frame.extend_from_slice(&remove.to_le_bytes());
    frame.extend_from_slice(&build_neg_element(Some(map), switch_time, duration));
    frame
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
/// accepted add/remove masks, plus how its mapping takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReconfOutcome {
    pub new_valid: u16,
    pub outcome: NegOutcome,
}

/// Link masks a reconfiguration request asked to add or remove.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Reconf {
    pub add: u16,
    pub remove: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Pending {
    token: u8,
    map: [u16; 8],
    switch_time: u16,
    duration: u32,
    reconf: Option<Reconf>,
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
            map,
            switch_time,
            duration,
            reconf: None,
        });
    }

    /// Start an ML reconfiguration exchange.
    pub(super) fn begin_reconf(
        &mut self,
        token: u8,
        add: u16,
        remove: u16,
        map: [u16; 8],
        switch_time: u16,
        duration: u32,
    ) {
        self.pending = Some(Pending {
            token,
            map,
            switch_time,
            duration,
            reconf: Some(Reconf { add, remove }),
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

    /// Handle an ML Reconfiguration Response action frame body. The
    /// response echoes the accepted add/remove masks, then the accepted
    /// TTLM element. Returns the link set after the reconfiguration so
    /// the caller can update its link state.
    pub(super) fn handle_reconf_response(
        &mut self,
        frame: &[u8],
        valid: u16,
        ttlm: &mut TtlmState,
        now_tsf: u64,
        now_ms: u64,
    ) -> Result<ReconfOutcome, NegError> {
        if frame.len() < 7 {
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
        let Some(requested) = pending.reconf else {
            return Err(NegError::WrongToken);
        };
        if frame[2] != pending.token {
            return Err(NegError::WrongToken);
        }
        let accepted_add = u16::from_le_bytes([frame[3], frame[4]]);
        let accepted_remove = u16::from_le_bytes([frame[5], frame[6]]);
        self.pending = None;
        if accepted_add & accepted_remove != 0
            || accepted_add & !requested.add != 0
            || accepted_remove & !requested.remove != 0
        {
            return Err(NegError::Malformed);
        }
        let new_valid = (valid & !accepted_remove) | accepted_add;
        if new_valid == 0 {
            return Err(NegError::Malformed);
        }
        let body = element_body(&frame[7..])?;
        let info = parse_neg_t2l(body).map_err(|()| NegError::Malformed)?;
        let outcome = self.accept(info, new_valid, ttlm, now_tsf, now_ms)?;
        Ok(ReconfOutcome { new_valid, outcome })
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
