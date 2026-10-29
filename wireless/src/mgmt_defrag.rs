//! Bounded reassembly of fragmented unprotected unicast management MMPDUs
//! (IEEE802.11-2020 10.6 Fragmentation, 10.7 Defragmentation). It follows
//! Linux mac80211 rx.c ieee80211_rx_h_defragment and
//! ieee80211_reassemble_{add,find}: four in-flight sequences replaced
//! round-robin, a two-second lifetime, consecutive fragment numbers from
//! zero within one TA/sequence number/frame type, and the first fragment's
//! header with More Fragments cleared as the result.
//!
//! A complete MMPDU is the same unmodified header plus the concatenated
//! fragment bodies, so `association::JoinPlan` admits it exactly as an
//! unfragmented response. Only the native receive owner may feed this: it
//! must bind every MPDU to the current channel/peer, drop FCS/CRC errors and
//! perform duplicate (Retry) detection first. Group-addressed frames are
//! never fragmented (10.6), and protected management fragments need MFP
//! per-fragment CCMP/PN rules, so both are refused. This owner grants no
//! association, key or transmit authority.
use alloc::vec::Vec;

/// Bound on one reassembled MMPDU, header included and FCS excluded. It
/// matches the4096-byte management bound `JoinPlan` already applies.
pub const MAX_BYTES: usize = 4096;
/// In-flight sequences (mac80211 IEEE80211_FRAGMENT_MAX).
pub const ENTRIES: usize = 4;
/// Partial sequences older than this are discarded (mac80211: 2 * HZ).
pub const LIFETIME_NS: u64 = 2_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not a 24-byte-header unprotected management MPDU without DS bits.
    Header,
    /// Receiver is not the local station or the transmitter is not unicast.
    Address,
    /// No partial sequence expects this fragment; it is dropped.
    Sequence,
    /// The reassembled MMPDU would exceed `MAX_BYTES`; the sequence is dropped.
    Length,
    Allocation,
}

struct Entry {
    ta: [u8; 6],
    sequence: u16,
    next: u8,
    started: u64,
    frame: Vec<u8>,
}

pub struct Reassembler {
    local: [u8; 6],
    entries: [Option<Entry>; ENTRIES],
    next_slot: usize,
}
impl core::fmt::Debug for Reassembler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembler")
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

fn unicast(mac: &[u8]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

impl Reassembler {
    pub fn new(local: [u8; 6]) -> Result<Self, Error> {
        if !unicast(&local) {
            return Err(Error::Address);
        }
        Ok(Self {
            local,
            entries: core::array::from_fn(|_| None),
            next_slot: 0,
        })
    }
    /// Admit one native management MPDU (no FCS) at monotonic `now_ns`.
    /// An unfragmented MMPDU is returned unchanged; a fragment returns
    /// `Ok(None)` until its last fragment completes the sequence. A fragment
    /// that no partial sequence expects (missing predecessor, duplicate,
    /// different frame type) is dropped with `Error::Sequence` and leaves
    /// buffered sequences untouched, as mac80211 does.
    pub fn push(&mut self, mpdu: &[u8], now_ns: u64) -> Result<Option<Vec<u8>>, Error> {
        if mpdu.len() < 24 || mpdu[0] & 0x0c != 0 || mpdu[1] & 0xc3 != 0 {
            return Err(Error::Header);
        }
        if mpdu[4..10] != self.local || !unicast(&mpdu[10..16]) {
            return Err(Error::Address);
        }
        if mpdu.len() > MAX_BYTES {
            return Err(Error::Length);
        }
        self.expire(now_ns);
        let more = mpdu[1] & 0x04 != 0;
        let fragment = mpdu[22] & 15;
        let sequence = u16::from_le_bytes([mpdu[22], mpdu[23]]) >> 4;
        let ta: [u8; 6] = mpdu[10..16].try_into().unwrap();
        if fragment == 0 && !more {
            let mut frame = Vec::new();
            frame
                .try_reserve_exact(mpdu.len())
                .map_err(|_| Error::Allocation)?;
            frame.extend_from_slice(mpdu);
            return Ok(Some(frame));
        }
        if fragment == 0 {
            let mut frame = Vec::new();
            frame
                .try_reserve_exact(mpdu.len())
                .map_err(|_| Error::Allocation)?;
            frame.extend_from_slice(mpdu);
            // A new first fragment from the same TA supersedes its partial
            // sequence; otherwise reuse the next slot round-robin.
            let slot = match self
                .entries
                .iter()
                .position(|e| e.as_ref().is_some_and(|e| e.ta == ta))
            {
                Some(slot) => slot,
                None => {
                    let slot = self.next_slot;
                    self.next_slot = (self.next_slot + 1) % ENTRIES;
                    slot
                }
            };
            self.entries[slot] = Some(Entry {
                ta,
                sequence,
                next: 1,
                started: now_ns,
                frame,
            });
            return Ok(None);
        }
        let Some(slot) = self.entries.iter().position(|e| {
            e.as_ref().is_some_and(|e| {
                e.ta == ta && e.sequence == sequence && e.next == fragment && e.frame[0] == mpdu[0]
            })
        }) else {
            return Err(Error::Sequence);
        };
        let entry = self.entries[slot].as_mut().unwrap();
        let body = &mpdu[24..];
        if entry.frame.len() + body.len() > MAX_BYTES {
            self.entries[slot] = None;
            return Err(Error::Length);
        }
        entry
            .frame
            .try_reserve(body.len())
            .map_err(|_| Error::Allocation)?;
        entry.frame.extend_from_slice(body);
        if more {
            if fragment == 15 {
                // Sixteen fragments are the most a sequence can carry.
                self.entries[slot] = None;
                return Err(Error::Sequence);
            }
            entry.next = fragment + 1;
            return Ok(None);
        }
        let mut entry = self.entries[slot].take().unwrap();
        entry.frame[1] &= !0x04;
        Ok(Some(entry.frame))
    }
    /// Drop partial sequences older than `LIFETIME_NS`.
    pub fn expire(&mut self, now_ns: u64) {
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .is_some_and(|e| now_ns.saturating_sub(e.started) > LIFETIME_NS)
            {
                *slot = None;
            }
        }
    }
    /// Discard every partial sequence, e.g. on (re)association or channel
    /// change (mac80211 flushes its fragment cache on key/station changes).
    pub fn clear(&mut self) {
        self.entries = core::array::from_fn(|_| None);
    }
    /// Diagnostic count of partial sequences; not a capability.
    pub fn pending(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "mgmt_defrag_tests.rs"]
mod tests;
