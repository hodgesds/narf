// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded CONNAC2 hardware-deaggregated HT A-MSDU receive ownership.
//! Source: mt7921/mac.c::mt7921_mac_fill_rx, mt76/mac80211.c::{
//! mt76_rx_release_burst, mt76_rx_release_amsdu, mt76_check_ccmp_pn} and
//! net/wireless/util.c::ieee80211_amsdu_to_8023s. A prepared receiver alone
//! never enables HT peer programming or packet/carrier admission.
use super::{scan::NativeRx, Error, RadioInfo, ScanBss};
use alloc::{collections::VecDeque, vec::Vec};

const MAX_BYTES: usize = 3839;
// The smallest admitted Ethernet-II subframe has its 14-byte header and
// eight-byte RFC1042 prefix. Bound both memory and work for the whole MPDU.
const MAX_SUBFRAMES: usize = MAX_BYTES / 22;
const MAX_AGE_NS: u64 = 100_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Geometry of an inactive receive preparation. This is not an associated
/// PHY, an advertised station capability, or permission to transmit.
pub struct Ht20ReceiveInfo {
    pub channel: u8,
    pub peer: [u8; 6],
    pub receive_mcs: u8,
    pub max_amsdu_bytes: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Replay {
    pub tid: usize,
    pub pn: u64,
}

#[derive(Debug)]
struct Pending {
    header: [u8; 26],
    replay: Option<Replay>,
    started: u64,
    wire: Vec<u8>,
    subframes: usize,
    ampdu: bool,
    wcid: u16,
    tid: u8,
}

#[derive(Debug)]
pub(super) struct Receiver {
    info: Ht20ReceiveInfo,
    own: [u8; 6],
    // Preparation remains inactive; only the complete bound HT/WMM/peer/
    // security receipt path activates it. Older tests may also exercise the
    // explicit model-only post-admission seam.
    pub(super) active: bool,
    pending: Option<Pending>,
}

pub(super) struct Complete {
    pub frames: VecDeque<Vec<u8>>,
    pub replay: Option<Replay>,
}

impl Receiver {
    pub(super) fn prepare(info: RadioInfo, bss: &ScanBss) -> Result<Self, Error> {
        Self::prepare_with_streams(info, bss, 1)
    }
    pub(super) fn prepare_with_streams(
        info: RadioInfo,
        bss: &ScanBss,
        rx_streams: u8,
    ) -> Result<Self, Error> {
        if !info.capabilities.phy.ht
            || info.capabilities.phy.spatial_streams == 0
            || !(1..=2).contains(&rx_streams)
            || rx_streams > info.capabilities.phy.spatial_streams
            || bss.bssid == [0; 6]
            || bss.bssid[0] & 1 != 0
            || bss.bssid == info.capabilities.mac
            || bss.capability & 3 != 1
            || bss.beacon_interval == 0
            || bss.information_elements.len() > 2048
            || crate::mt7921::channel::band(bss.channel)
                .is_none_or(|band| info.capabilities.phy.bands & band.capability() == 0)
        {
            return Err(Error::InvalidIdentity);
        }
        let mut ies = bss.information_elements.as_slice();
        let (mut ht, mut operation) = (None, None);
        while !ies.is_empty() {
            let header = ies.get(..2).ok_or(Error::Bounds)?;
            let body = ies
                .get(2..2 + usize::from(header[1]))
                .ok_or(Error::Bounds)?;
            match header[0] {
                45 => {
                    if ht.is_some() || body.len() != 26 {
                        return Err(Error::Bounds);
                    }
                    ht = Some(body);
                }
                61 => {
                    if operation.is_some() || body.len() != 22 || body[0] != bss.channel {
                        return Err(Error::Bounds);
                    }
                    operation = Some(body);
                }
                _ => {}
            }
            ies = &ies[2 + body.len()..];
        }
        let ht = ht.ok_or(Error::UnsupportedFirmware)?;
        let operation = operation.ok_or(Error::UnsupportedFirmware)?;
        // Rate/NSS do not change the native MSDU layout. The typed5GHz
        // HT/VHT companion can promise RX2 after actual NIC qualification.
        // Take that bound from the completed typed profile: received_ies()
        // is intentionally a sanitized HT pair, not the original VHT offer.
        // Older standalone preparation retains its first-stream bound.
        if ht[3] == 0
            || rx_streams == 1 && operation[7] != 0
            || operation[8..].iter().any(|&byte| byte != 0)
        {
            return Err(Error::UnsupportedFirmware);
        }
        Ok(Self {
            info: Ht20ReceiveInfo {
                peer: bss.bssid,
                channel: bss.channel,
                receive_mcs: 0xff,
                max_amsdu_bytes: MAX_BYTES as u16,
            },
            own: info.capabilities.mac,
            active: false,
            pending: None,
        })
    }

    pub(super) fn info(&self) -> Ht20ReceiveInfo {
        self.info
    }
    pub(super) fn clear(&mut self) {
        self.pending = None;
    }
    pub(super) fn matches(&self, own: [u8; 6], peer: [u8; 6], channel: u8) -> bool {
        self.active && self.own == own && self.info.peer == peer && self.info.channel == channel
    }

    pub(super) fn observe(
        &mut self,
        native: &NativeRx<'_>,
        floor: Option<u64>,
        now: u64,
    ) -> Option<Complete> {
        self.observe_with_ba(native, floor, now, false)
    }
    pub(super) fn observe_with_ba(
        &mut self,
        native: &NativeRx<'_>,
        floor: Option<u64>,
        now: u64,
        block_ack: bool,
    ) -> Option<Complete> {
        let result = self.observe_inner(native, floor, now, block_ack);
        if result.is_err() {
            self.clear();
        }
        result.ok().flatten()
    }

    fn observe_inner(
        &mut self,
        native: &NativeRx<'_>,
        floor: Option<u64>,
        now: u64,
        block_ack: bool,
    ) -> Result<Option<Complete>, ()> {
        if !self.active || native.channel != self.info.channel || !matches!(native.amsdu, 1..=3) {
            return Err(());
        }
        let frame = native.frame;
        let header: [u8; 26] = frame.get(..26).ok_or(())?.try_into().map_err(|_| ())?;
        let fc = u16::from_le_bytes([header[0], header[1]]);
        if header[0] != 0x88
            || fc & 0x8700 != 0x0200
            || header[22] & 15 != 0
            || header[4..10] != self.own
            || header[10..16] != self.info.peer
            || header[16..22] == [0; 6]
            || header[16] & 1 != 0
            || header[24] & 0x80 == 0
            || !(header[24] & 0x70 == 0 || block_ack && header[24] & 0x70 == 0x60)
            || header[25] != 0
        {
            return Err(());
        }
        let protected = fc & 0x4000 != 0;
        let replay = match (native.ccmp, floor) {
            (Some(ccmp), Some(floor)) if protected && ccmp.key_id == 0 && ccmp.pn > floor => {
                Some(Replay {
                    tid: usize::from(header[24] & 15),
                    pn: ccmp.pn,
                })
            }
            (None, None) if !protected => None,
            _ => return Err(()),
        };
        // Linux moves the native header over two hardware padding bytes
        // before stripping those bytes; borrow the equivalent payload span.
        let bytes = frame.get(28..).ok_or(())?;
        let subheader = bytes.get(..14).ok_or(())?;
        let length = usize::from(u16::from_be_bytes([subheader[12], subheader[13]]));
        let extent = 14usize.checked_add(length).ok_or(())?;
        let padding = (4 - extent % 4) % 4;
        if length < 8
            || bytes.len() < extent
            || bytes.len() > extent + padding
            || subheader[..6] == [0xaa, 0xaa, 3, 0, 0, 0]
            || subheader[0] & 1 == 0 && subheader[..6] != self.own
            || subheader[6..12] == [0; 6]
            || subheader[6] & 1 != 0
            || subheader[6..12] == self.own
        {
            return Err(());
        }
        let payload = &bytes[14..extent];
        if payload[..6] != [0xaa, 0xaa, 3, 0, 0, 0] || length > 1508 {
            return Err(());
        }
        if native.amsdu == 3 {
            self.pending = Some(Pending {
                header,
                replay,
                started: now,
                wire: Vec::new(),
                subframes: 0,
                ampdu: native.ampdu,
                wcid: native.wcid,
                tid: native.tid,
            });
        }
        let pending = self.pending.as_mut().ok_or(())?;
        if pending.header != header
            || pending.replay != replay
            || now.saturating_sub(pending.started) >= MAX_AGE_NS
            || pending.subframes >= MAX_SUBFRAMES
            || pending.ampdu != native.ampdu
            || pending.wcid != native.wcid
            || pending.tid != native.tid
        {
            return Err(());
        }
        let added = if native.amsdu == 1 {
            extent
        } else {
            extent + padding
        };
        let total = pending.wire.len().checked_add(added).ok_or(())?;
        if total > MAX_BYTES {
            return Err(());
        }
        pending.wire.try_reserve_exact(added).map_err(|_| ())?;
        pending.wire.extend_from_slice(&bytes[..extent]);
        // CONNAC2 may strip inter-subframe padding. Its uninterpreted
        // alignment bytes are reconstructed only in this logical plaintext
        // aggregate; native MAC/CCMP metadata and subframes stay unchanged.
        pending.wire.resize(total, 0);
        pending.subframes += 1;
        if native.amsdu != 1 {
            return Ok(None);
        }
        if pending.subframes < 2 {
            return Err(());
        }
        let complete = self.pending.take().ok_or(())?;
        let frames = narf_wireless::amsdu::decode(
            &complete.wire,
            self.own,
            header[4..10].try_into().unwrap(),
        )
        .map_err(|_| ())?;
        Ok(Some(Complete {
            frames: frames.into_iter().collect(),
            replay: complete.replay,
        }))
    }
}
