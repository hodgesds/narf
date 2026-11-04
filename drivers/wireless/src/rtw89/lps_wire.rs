// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! B LPS/RPWM source codecs only. No original physical/request/RF authority.
//! Linux7.3-rc4 fw.c::fw_feat_tbl,fw_h2c_lps_parm; mac.c RPWM/CPWM.
use alloc::{vec, vec::Vec};

/// Actual association-derived physical own/AP/AID plus negotiated WMM.
/// These bytes are templates, not permission to install/activate them.
pub(super) fn templates(own: [u8; 6], peer: [u8; 6], aid: u16, wmm: bool) -> Option<[Vec<u8>; 3]> {
    let unicast = |a: [u8; 6]| a != [0; 6] && a[0] & 1 == 0;
    if !unicast(own) || !unicast(peer) || own == peer || !(1..=2007).contains(&aid) {
        return None;
    }
    let mut poll = vec![0xa4, 0];
    poll.extend_from_slice(&(aid | 0xc000).to_le_bytes());
    poll.extend_from_slice(&peer);
    poll.extend_from_slice(&own);
    let mut null = vec![0x48, 1, 0, 0];
    null.extend_from_slice(&peer);
    null.extend_from_slice(&own);
    null.extend_from_slice(&peer);
    null.extend_from_slice(&[0, 0]);
    let mut qos = null.clone();
    if wmm {
        qos[0] = 0xc8;
        qos.extend_from_slice(&[7, 0]);
    }
    Some([poll, null, qos])
}
/// MAC1/FW_OFFLOAD9/PACKET1, RECV+DONE and separate actual copied C2H
/// MAC1/OFLD1/function2 response are needed by the native retained owner.
pub(super) fn add_packet(id: u8, frame: &[u8]) -> Option<Vec<u8>> {
    if id == 255 || !matches!(frame.len(), 16 | 24 | 26) {
        return None;
    }
    let mut bytes = vec![id, 0, frame.len() as u8, 0];
    bytes.extend_from_slice(frame);
    Some(bytes)
}
pub(super) fn delete_packet(id: u8) -> Option<[u8; 4]> {
    (id != 255).then_some([id, 1, 0, 0])
}
/// MAC1/FW_INFO0/GENERAL_PKT1 DONE_ACK; unused probe/CTS ids remain0xff.
pub(super) fn general(ids: [u8; 3]) -> Option<[u8; 6]> {
    (ids.iter().all(|id| *id != 255) && ids[0] != ids[1] && ids[0] != ids[2] && ids[1] != ids[2])
        .then_some([0, 255, ids[0], ids[1], ids[2], 255])
}
/// Header/category/class/function/native-copy ownership is the caller's.
/// Linux treats pkt_len!=0 as success for ADD and DEL; it is not a promised
/// length echo. Original id/op/issued-command ownership remains mandatory.
pub(super) fn packet_response(body: &[u8], id: u8, op: u8) -> bool {
    let Some(word) = body
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return false;
    };
    body.len() == 12
        && id != 255
        && op <= 1
        && word & 0xff == u32::from(id)
        && (word >> 8) & 7 == u32::from(op)
        && word & 0xf800 == 0
        && word >> 16 != 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Deep {
    Clock,
}
impl Deep {
    pub(super) fn state(self) -> u8 {
        match self {
            Self::Clock => 5,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    /// Actual selected inner image W1 tuple, never a filename/layout version.
    pub version: [u8; 4],
    pub deep: Deep,
}
impl Profile {
    pub(super) fn from_assets(assets: &super::radio_assets::Assets) -> Option<Self> {
        Self::for_version(assets.firmware_version())
    }
    pub(super) fn for_version(version: [u8; 4]) -> Option<Self> {
        // The actual admitted full-radio path already requires this exact
        // WLAN-only coexistence ABI. Older normal images and newer ABI
        // adapters are diagnostic/prerequisite paths, not live LPS producers.
        super::coex_native::Protocol::for_version(version)?;
        Some(Self {
            version,
            deep: Deep::Clock,
        })
    }
    pub(super) fn leave_done_ack(self) -> bool {
        true
    }
}

/// MAC category1/class2/function0. Source MACID0, LEGACY vs ACTIVE,
/// RLBM1/SMARTPS1/AWAKEINTERVAL1, UAPSD0, LASTRPWM0 vs6.
pub(super) fn parameters(enter: bool) -> [u8; 8] {
    [
        0,
        u8::from(enter),
        0x11,
        1,
        0,
        if enter { 0 } else { 6 },
        0,
        0,
    ]
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub wire: u16,
    pub state: u8,
    request: u8,
    response: u8,
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Counters {
    request: u8,
    response: u8,
}
impl Counters {
    /// Metadata proposal only. Native must retain its original source and
    /// publish exactly this wire through current actual PCI/PS program scopes.
    pub(super) fn prepare(self, previous_rpwm: u16, state: u8) -> Option<Request> {
        if state > 7 {
            return None;
        }
        let request = (self.request + 1) & 3;
        let wire = (!previous_rpwm & 0x8000)
            | u16::from(state)
            | u16::from(request) << 12
            | if state < 5 { 0x4000 } else { 0 };
        Some(Request {
            wire,
            state,
            request,
            response: (self.response + 1) & 3,
        })
    }
    /// Called only after real publication, never mere source/DMA metadata.
    pub(super) fn published(&mut self, proposal: Request) -> bool {
        if proposal.request != (self.request + 1) & 3
            || proposal.response != (self.response + 1) & 3
        {
            return false;
        }
        self.request = proposal.request;
        true
    }
    /// Native must also prove actual awake→deep or deep→awake ownership,
    /// current source, queue/prefix and original expected transition. Deep
    /// has only the actual LDM32K observation; nondeep has the exact original
    /// request/next response/state in one copied CPWM16 capture. Failed polls
    /// do not consume the expected response counter.
    pub(super) fn completed(&mut self, proposal: Request, ldm: u32, cpwm: u16) -> bool {
        if self.request != proposal.request
            || proposal.response != (self.response + 1) & 3
            || (ldm & 0x80000000 != 0) != (proposal.state >= 5)
        {
            return false;
        }
        if proposal.state >= 5 {
            return true;
        }
        if (cpwm >> 8) & 3 != u16::from(proposal.request)
            || (cpwm >> 12) & 3 != u16::from(proposal.response)
            || cpwm & 7 != u16::from(proposal.state)
        {
            return false;
        }
        self.response = proposal.response;
        true
    }
}
