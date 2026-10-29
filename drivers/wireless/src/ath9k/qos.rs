// SPDX-License-Identifier: GPL-2.0-or-later
//! AR9285-only measured four-AC EDCA and eight-TID transmit scheduling.
//!
//! Linux references (7.2): `init.c::ath9k_init_queues` (one DATA QCU per
//! mac80211 AC), `main.c::ath9k_conf_tx` -> `xmit.c::ath_txq_update` ->
//! `mac.c::ath9k_hw_set_txq_props`/`ath9k_hw_resettxqueue` (AIFS/CW per DCU),
//! `xmit.c::{ath_tx_queue_tid,ath_txq_schedule}` (per-TID software queues
//! drained per hardware queue), `net/wireless/util.c::cfg80211_classify8021d`,
//! and `net/mac80211/wme.c::{ieee802_1d_to_ac,ieee80211_downgrade_queue}`.
//! No measurement or signed asset is supplied by this implementation.
use super::{ht, packet::Error};
#[cfg(feature = "kernel-test")]
use alloc::vec::Vec;
use alloc::{collections::VecDeque, format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::wmm::{Ac, Parameters};

/// User priority -> WMM ACI (BE=0, BK=1, VI=2, VO=3); `ieee802_1d_to_ac`
/// expressed in the WMM Parameter element's canonical ACI order.
pub(super) const UP_TO_ACI: [usize; 8] = [0, 1, 1, 0, 2, 2, 3, 3];
/// ACI -> AR9285 QCU/DCU. BE keeps the original queue0 owner; Linux's VI (1)
/// and BK (3) indices are retained and VO takes the free QCU2.
pub(super) const ACI_TO_QCU: [u64; 4] = [0, 3, 1, 2];
/// Host service order, highest EDCA priority first: VO, VI, BE, BK.
const PRIORITY: [usize; 4] = [3, 2, 0, 1];
/// The two user priorities of each ACI, lower first.
const ACI_TIDS: [[u8; 2]; 4] = [[0, 3], [1, 2], [4, 5], [6, 7]];
/// Bounded per-TID software backlog (frames); tail drop beyond it.
pub(super) const PER_TID: usize = 16;
/// A backlogged AC passed over this many consecutive times is served next.
pub(super) const STARVE: u8 = 8;
/// Number of TIDs in the measured train (UP0..7).
pub(super) const TIDS: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}
pub(super) fn request(base: &ht::Grant) -> Request {
    let (identity, digest, mac) = base.ba_identity();
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(b"NARF AR9285 N85Q measured four-AC EDCA eight-TID HT20 LGI v1");
    h.update(&identity);
    h.update(&digest);
    h.update(&mac);
    h.update(b"same rev2 EEPROM/calibration/power/chain1 profile; noSGI20 noLDPC noTXSTBC; cfg80211_classify8021d DSCP/MPLS/802.21 UP, ieee802_1d_to_ac, ACM downgrade VO>VI>BE>BK without TSPEC, BE ACM and UAPSD refused; QCU BE0 VI1 VO2 BK3 each DQCUMASK 1<<q, actual AP AIFSN2..15 CWmin<=CWmax<=1023 per DCU, retry FR10 STA32/32, QMISC early-term, DMISC CWbackoff fragwait thresh2, CHNTIME0 single MPDU per access under any TXOP limit; one native PPDU in flight across all QCUs; host service VO VI BE BK strict with starvation bound 8 and per-AC TID round robin, 16 frames per TID tail drop; QoS26 per-TID sequence and CCMP PN; BA pair only TID0 BE; IMR_S0/S1 TXDESC/TXEOL QCU0..3; later beacon WMM change terminal; no checked-in measurements");
    h.update(b"complete static temperature/supply/antenna/BT/posture envelope including every AC contention, retry, protection and automatic response peak");
    Request {
        identity: h.finalize(),
        mac,
        filename: format!(
            "ath9k/ar9285-qos-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    }
}

pub(super) struct Grant {
    base: Arc<ht::Grant>,
    cap: Cap<FirmwareBlob, Read>,
    peak: i16,
    ceiling: i16,
}
pub(super) enum Source {
    Registered,
    #[cfg(feature = "kernel-test")]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}
impl Source {
    pub(super) fn load(self, base: Arc<ht::Grant>) -> Result<Arc<Grant>, Error> {
        struct Decode(Arc<ht::Grant>);
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let v = narf_firmware::view_of(cap).map_err(|_| Error::Access)?;
                    Grant::decode(v.bytes, v.signer, *cap, self.0)
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let cap = narf_firmware::open(&request(&base).filename, &loader)
                    .map_err(|_| Error::Access)?;
                cap.invoke(Decode(base)).map_err(|_| Error::Access)??
            }
            #[cfg(feature = "kernel-test")]
            Self::Verified { bytes, signer, cap } => Grant::decode(&bytes, signer, cap, base)?,
        };
        grant.check()?;
        Ok(Arc::new(grant))
    }
}
impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        base: Arc<ht::Grant>,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let r = request(&base);
        if signer.is_none()
            || b.len() != 96
            || b[..8] != [b'N', b'8', b'5', b'Q', 1, 0, 96, 0]
            || b[8..12] != 96u32.to_le_bytes()
            || b[12..16] != [0x8c, 0x16, 0x2b, 0]
            || b[16..48] != r.identity
            || b[48..54] != r.mac
            || b[54..58] != [1, 20, 1, 4]
            || b[60] != TIDS
            || b[61] != STARVE
            || b[64..] != [0; 32]
        {
            return Err(Error::Packet);
        }
        let g = Self {
            base,
            cap,
            peak: i16::from_le_bytes([b[58], b[59]]),
            ceiling: i16::from_le_bytes([b[62], b[63]]),
        };
        if !(-512..=256).contains(&g.peak) || !(-512..=256).contains(&g.ceiling) {
            return Err(Error::Packet);
        }
        Ok(g)
    }
    /// Run `op` inside current asset authority, after the measured all-AC
    /// peak plus the base antenna bound fits the signed ceiling, the base
    /// ceiling and every current overlapping host rule.
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Live<'a, F>(&'a Grant, F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<'_, F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let (antenna, base) = self.0.base.ba_limit();
                    let mut limit = self.0.ceiling.min(base);
                    let d = narf_wireless::reg::db::snapshot().ok_or(Error::Access)?;
                    for r in &d.rules {
                        if r.freq_start_mhz < 2422 && r.freq_end_mhz > 2402 {
                            limit = limit.min(i16::from(r.max_power_dbm) * 2);
                        }
                    }
                    if i32::from(self.0.peak) + i32::from(antenna) > i32::from(limit) {
                        return Err(Error::Access);
                    }
                    (self.1)()
                })())
            }
        }
        self.base
            .invoke(|| self.cap.invoke(Live(self, op)).map_err(|_| Error::Access)?)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.invoke(|| Ok(()))
    }
    pub(super) fn base(&self) -> &Arc<ht::Grant> {
        &self.base
    }
}

/// The actual AP's complete four-AC WMM contention program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    ac: [Ac; 4],
    /// `wmm_acm`: per-UP admission-control bits from ACI ACM flags.
    acm: u8,
}
impl Profile {
    /// Validate the WMM Parameter element of an IE stream. BE keeps the
    /// original `ht::contention` rules (no ACM, no TXOP, no U-APSD).
    pub(super) fn parse(ies: &[u8]) -> Result<Self, Error> {
        let be = ht::contention(ies)?;
        let w = Parameters::parse(ies)
            .map_err(|_| Error::Packet)?
            .ok_or(Error::Packet)?;
        if w.ac[0] != be {
            return Err(Error::Packet);
        }
        let mut acm = 0;
        for (aci, ac) in w.ac.iter().enumerate() {
            if !(2..=15).contains(&ac.aifsn) || ac.ecw_min > ac.ecw_max || ac.cw_max() > 1023 {
                return Err(Error::Packet);
            }
            if ac.admission_control {
                for up in ACI_TIDS[aci] {
                    acm |= 1 << up;
                }
            }
        }
        Ok(Self { ac: w.ac, acm })
    }
    /// `AR_D_LCL_IFS` word per QCU index 0..3.
    pub(super) fn words(&self) -> [u32; 4] {
        let mut words = [0; 4];
        for (aci, ac) in self.ac.iter().enumerate() {
            words[ACI_TO_QCU[aci] as usize] = u32::from(ac.cw_min())
                | (u32::from(ac.cw_max()) << 10)
                | (u32::from(ac.aifsn) << 20);
        }
        words
    }
    /// Transmit TID for one 802.3 frame: classification then ACM downgrade.
    pub(super) fn tid(&self, ethernet: &[u8]) -> u8 {
        downgrade(classify8021d(ethernet), self.acm)
    }
}
/// QCU that carries a QoS DATA MPDU of `tid`.
pub(super) fn queue(tid: u8) -> u64 {
    ACI_TO_QCU[UP_TO_ACI[usize::from(tid & 7)]]
}

/// `cfg80211_classify8021d` for an 802.3 frame (RFC 8325 DSCP mapping,
/// MPLS TC, 802.21). No QoS Map or out-of-band VLAN tag exists natively.
pub(super) fn classify8021d(ethernet: &[u8]) -> u8 {
    let Some(ethertype) = ethernet.get(12..14) else {
        return 0;
    };
    let payload = &ethernet[14..];
    let dscp = match u16::from_be_bytes([ethertype[0], ethertype[1]]) {
        0x0800 => match payload.get(1) {
            Some(tos) => tos & 0xfc,
            None => return 0,
        },
        0x86dd => match payload.get(..2) {
            Some(head) => ((head[0] << 4) | (head[1] >> 4)) & 0xfc,
            None => return 0,
        },
        0x8847 | 0x8848 => match payload.get(..4) {
            Some(l) => {
                let entry = u32::from_be_bytes([l[0], l[1], l[2], l[3]]);
                return ((entry >> 9) & 7) as u8;
            }
            None => return 0,
        },
        0x8917 => return 7,
        _ => return 0,
    };
    match dscp >> 2 {
        10 | 12 | 14 | 16 => 0,
        18 | 20 | 22 => 3,
        24 | 26 | 28 | 30 => 4,
        44 | 46 => 6,
        48 => 7,
        _ => dscp >> 5,
    }
}
/// `ieee80211_downgrade_queue` without an admitted TSPEC.
pub(super) fn downgrade(mut up: u8, acm: u8) -> u8 {
    while acm & (1 << up) != 0 {
        up = match up {
            6 | 7 => 5,
            4 | 5 => 3,
            0 | 3 => 2,
            _ => break,
        };
    }
    up
}

/// Per-TID software queues in front of the single in-flight native owner
/// (`ath_tx_queue_tid` + `ath_txq_schedule`). Without a QoS grant every
/// frame is TID0 and this degenerates to the original FIFO.
pub(super) struct Scheduler<T> {
    tids: [VecDeque<T>; 8],
    cursor: [u8; 4],
    skipped: [u8; 4],
}
impl<T> Default for Scheduler<T> {
    fn default() -> Self {
        Self {
            tids: Default::default(),
            cursor: [0; 4],
            skipped: [0; 4],
        }
    }
}
impl<T> Scheduler<T> {
    /// Queue one frame; a full TID returns it (tail drop).
    pub(super) fn push(&mut self, tid: u8, item: T) -> Result<(), T> {
        let q = &mut self.tids[usize::from(tid & 7)];
        if q.len() >= PER_TID {
            return Err(item);
        }
        q.push_back(item);
        Ok(())
    }
    pub(super) fn len(&self) -> usize {
        self.tids.iter().map(VecDeque::len).sum()
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn backlogged(&self, aci: usize) -> bool {
        ACI_TIDS[aci]
            .iter()
            .any(|t| !self.tids[usize::from(*t)].is_empty())
    }
    /// Next frame: highest backlogged AC, unless a lower one reached the
    /// starvation bound; TIDs of one AC alternate.
    pub(super) fn pop(&mut self) -> Option<(u8, T)> {
        let starved = PRIORITY
            .iter()
            .rev()
            .copied()
            .find(|a| self.backlogged(*a) && self.skipped[*a] >= STARVE);
        let aci = starved.or_else(|| PRIORITY.iter().copied().find(|a| self.backlogged(*a)))?;
        for other in 0..4 {
            if other != aci && self.backlogged(other) {
                self.skipped[other] = self.skipped[other].saturating_add(1);
            }
        }
        self.skipped[aci] = 0;
        let start = usize::from(self.cursor[aci]);
        for step in 0..2 {
            let index = (start + step) % 2;
            let tid = ACI_TIDS[aci][index];
            if let Some(item) = self.tids[usize::from(tid)].pop_front() {
                self.cursor[aci] = ((index + 1) % 2) as u8;
                return Some((tid, item));
            }
        }
        None
    }
    /// Take the next frame of one TID (aggregation partner).
    pub(super) fn pop_tid(&mut self, tid: u8) -> Option<T> {
        self.tids[usize::from(tid & 7)].pop_front()
    }
    pub(super) fn clear(&mut self) {
        for q in &mut self.tids {
            q.clear();
        }
        self.cursor = [0; 4];
        self.skipped = [0; 4];
    }
}

#[cfg(feature = "kernel-test")]
#[path = "qos/tests.rs"]
pub(super) mod tests;
