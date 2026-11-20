// SPDX-License-Identifier: GPL-2.0-or-later
//! Primary-bsscfg AP wire records, pinned to Linux 7.3-rc4 cfg80211.c,
//! fwil.h and fwil_types.h. Firmware owns authentication/association and
//! beacon/TIM generation; no synthetic management frames represent its events.
use crate::cyw43439::runtime::Error;
use alloc::vec::Vec;

pub(super) const UP: u32 = 2;
pub(super) const DOWN: u32 = 3;
pub(super) const INFRA: u32 = 20;
pub(super) const AUTH: u32 = 22;
pub(super) const SET_SSID: u32 = 26;
pub(super) const GET_BEACON: u32 = 75;
pub(super) const SET_BEACON: u32 = 76;
pub(super) const GET_DTIM: u32 = 77;
pub(super) const SET_DTIM: u32 = 78;
pub(super) const GET_RATES: u32 = 114;
pub(super) const GET_AP: u32 = 117;
pub(super) const SET_AP: u32 = 118;
pub(super) const AUTHORIZE: u32 = 121;
pub(super) const DEAUTHORIZE: u32 = 122;
pub(super) const GET_BSS: u32 = 136;
pub(super) const GET_ASSOCIATIONS: u32 = 159;
pub(super) const DEAUTH_REASON: u32 = 201;

/// One source for Session transitions and pending Program SET barriers.
/// The event must already be the actual native firmware event envelope.
/// `expected` is the (ifidx, bsscfgidx) pair of the vif this session
/// serves (Linux `fweh.c::brcmf_fweh_event_worker` dispatches each event
/// by `bsscfgidx` to its owning `ifp` before any handler runs, and the AP
/// handler `cfg80211.c::brcmf_notify_connect_status_ap` performs no
/// ifidx/bsscfgidx check of its own). The transport demux already routes
/// each event to its own vif's session, so the gate admits exactly this
/// session's pair and rejects another vif's event as malformed — it must
/// not hard-code (0, 0), which drops every secondary AP / P2P GO
/// indication (ASSOC_IND 8, REASSOC_IND 10) before the session sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transition {
    Benign,
    Failed,
    Associated,
    Lost,
    Roamed,
}
pub(crate) fn event_transition(
    header: &crate::cyw43439::events::EventHeader,
    own: [u8; 6],
    expected: (u8, u8),
) -> Result<Transition, Error> {
    if header.if_idx != expected.0 || header.bsscfg_idx != expected.1 {
        return Err(Error::Malformed);
    }
    Ok(match header.event_type {
        63 => Transition::Failed,
        16 if header.flags & 1 == 0 && header.source_mac == own => Transition::Failed,
        0 if header.status != 0 => Transition::Failed,
        8 | 10 if header.status == 0 && header.reason == 0 => Transition::Associated,
        5 | 6 | 11 | 12 => Transition::Lost,
        17 => Transition::Roamed,
        _ => Transition::Benign,
    })
}

pub(super) fn unicast(peer: [u8; 6]) -> bool {
    peer != [0; 6] && peer[0] & 1 == 0
}
/// `sizeof(struct brcmf_join_params)`: SSID36, BSSID6 + padding2,
/// channel-count4, first channel2 + trailing alignment2. AP leaves the
/// association selectors zero; its actual `chanspec` was installed separately.
pub(super) fn ssid(value: &[u8]) -> Result<[u8; 52], Error> {
    if value.len() > 32 {
        return Err(Error::Malformed);
    }
    let mut out = [0; 52];
    out[..4].copy_from_slice(&(value.len() as u32).to_le_bytes());
    out[4..4 + value.len()].copy_from_slice(value);
    Ok(out)
}
/// `sizeof(struct brcmf_ssid_le)`: the leading part of [`ssid`].
pub(super) const SSID_LE: usize = 36;
/// `brcmf_fil_bss_enable_le` (`bsscfgidx`, `enable`) for the `bss` iovar
/// (Linux 7.3-rc4 `cfg80211.c` P2P_GO `start_ap`/`stop_ap`).
pub(super) fn bss_enable(bsscfgidx: u8, enable: bool) -> [u8; 8] {
    let mut out = [0; 8];
    out[..4].copy_from_slice(&u32::from(bsscfgidx).to_le_bytes());
    out[4..].copy_from_slice(&u32::from(enable).to_le_bytes());
    out
}
/// `brcmf_scb_val_le`, including its real trailing alignment. Deleting
/// one SCB grants no native TX terminal credit and cannot release its DMA.
pub(super) fn deauth(peer: [u8; 6], reason: u16) -> Result<[u8; 12], Error> {
    if !unicast(peer) || reason == 0 {
        return Err(Error::Malformed);
    }
    let mut out = [0; 12];
    out[..4].copy_from_slice(&u32::from(reason).to_le_bytes());
    out[4..10].copy_from_slice(&peer);
    Ok(out)
}
/// Original native legacy rate/basic-bit set, not a host-invented RF rate.
pub(super) fn rates(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() != 20 {
        return Err(Error::Malformed);
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if !(1..=16).contains(&count) {
        return Err(Error::Malformed);
    }
    let rates = &bytes[4..4 + count];
    for (at, rate) in rates.iter().enumerate() {
        if !matches!(
            rate & 0x7f,
            2 | 4 | 11 | 22 | 12 | 18 | 24 | 36 | 48 | 72 | 96 | 108
        ) || rates[..at].iter().any(|old| old & 0x7f == rate & 0x7f)
        {
            return Err(Error::Malformed);
        }
    }
    if !rates.iter().any(|rate| rate & 0x80 != 0) {
        return Err(Error::Malformed);
    }
    Ok(rates.to_vec())
}
/// Native WLC_GET_ASSOCLIST returns a count followed by complete MACs.
/// A bounded host buffer never treats a truncated list as a quiet peer set.
pub(super) fn associations(bytes: &[u8], maximum: usize) -> Result<Vec<[u8; 6]>, Error> {
    let count =
        u32::from_le_bytes(bytes.get(..4).ok_or(Error::Malformed)?.try_into().unwrap()) as usize;
    if count > maximum {
        return Err(Error::Busy);
    }
    let end = count
        .checked_mul(6)
        .and_then(|n| n.checked_add(4))
        .ok_or(Error::Malformed)?;
    let raw = bytes.get(4..end).ok_or(Error::Malformed)?;
    let mut out = Vec::new();
    for raw in raw.chunks_exact(6) {
        let peer = raw.try_into().unwrap();
        if !unicast(peer) || out.contains(&peer) {
            return Err(Error::Malformed);
        }
        out.push(peer);
    }
    Ok(out)
}

/// Defined prefix of native WLC_GET_BSS_INFO version109. Some firmware omits
/// optional variable IEs; absence supplies no template-byte observation.
pub(super) struct Bss<'a> {
    pub(super) own: [u8; 6],
    pub(super) ssid: &'a [u8],
    pub(super) beacon_interval: u16,
    pub(super) dtim: u8,
    pub(super) capability: u16,
    pub(super) chanspec: u16,
    pub(super) rates: Vec<u8>,
    pub(super) ies: &'a [u8],
}
pub(super) fn bss(bytes: &[u8]) -> Result<Bss<'_>, Error> {
    let record = bytes.get(4..).ok_or(Error::Malformed)?;
    let header = record.get(..128).ok_or(Error::Malformed)?;
    let version = u32::from_le_bytes(header[..4].try_into().unwrap());
    let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    if version != 109
        || length < 128
        || length > record.len()
        || header[18] > 32
        || !unicast(header[8..14].try_into().unwrap())
        || header[81] != 0
    // Actual legacy profile, not a relabelled HT BSS.
    {
        return Err(Error::Malformed);
    }
    let record = &record[..length];
    let offset = usize::from(u16::from_le_bytes(header[116..118].try_into().unwrap()));
    let ie_length = u32::from_le_bytes(header[120..124].try_into().unwrap()) as usize;
    let ies = if ie_length == 0 {
        &[][..]
    } else {
        if offset < 128 || ie_length > 2048 {
            return Err(Error::Malformed);
        }
        record
            .get(offset..offset.checked_add(ie_length).ok_or(Error::Malformed)?)
            .ok_or(Error::Malformed)?
    };
    let mut rest = ies;
    while !rest.is_empty() {
        let n = usize::from(*rest.get(1).ok_or(Error::Malformed)?);
        rest = rest.get(2 + n..).ok_or(Error::Malformed)?;
    }
    Ok(Bss {
        own: header[8..14].try_into().unwrap(),
        ssid: &header[19..19 + usize::from(header[18])],
        beacon_interval: u16::from_le_bytes(header[14..16].try_into().unwrap()),
        dtim: header[76],
        capability: u16::from_le_bytes(header[16..18].try_into().unwrap()),
        chanspec: u16::from_le_bytes(header[72..74].try_into().unwrap()),
        rates: rates(&header[52..72])?,
        ies,
    })
}
/// Source-defined common prefix of `brcmf_sta_info_le` (version2 onward).
/// No optional RSSI/PN/key statistics are fabricated from absent fields.
pub(super) struct Peer {
    pub(super) mac: [u8; 6],
    pub(super) capability: u16,
    pub(super) flags: u32,
    pub(super) rates: Vec<u8>,
}
pub(super) fn peer(bytes: &[u8]) -> Result<Peer, Error> {
    let head = bytes.get(..52).ok_or(Error::Malformed)?;
    let version = u16::from_le_bytes(head[..2].try_into().unwrap());
    let length = usize::from(u16::from_le_bytes(head[2..4].try_into().unwrap()));
    let count = u32::from_le_bytes(head[24..28].try_into().unwrap()) as usize;
    let mac = head[16..22].try_into().unwrap();
    if !(2..=7).contains(&version)
        || !(52..=bytes.len()).contains(&length)
        || !(1..=16).contains(&count)
        || !unicast(mac)
    {
        return Err(Error::Malformed);
    }
    let rates = head[28..28 + count].to_vec();
    for (at, rate) in rates.iter().enumerate() {
        if !matches!(
            rate & 127,
            2 | 4 | 11 | 22 | 12 | 18 | 24 | 36 | 48 | 72 | 96 | 108
        ) || rates[..at].iter().any(|old| old & 127 == rate & 127)
        {
            return Err(Error::Malformed);
        }
    }
    Ok(Peer {
        mac,
        capability: u16::from_le_bytes(head[4..6].try_into().unwrap()),
        flags: u32::from_le_bytes(head[8..12].try_into().unwrap()),
        rates,
    })
}
