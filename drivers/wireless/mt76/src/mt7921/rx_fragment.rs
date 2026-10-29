//! Bounded native station RX defragmentation.
//!
//! Adapted from Linux mac80211 `ieee80211_rx_h_defragment`,
//! `ieee80211_reassemble_add` and `ieee80211_reassemble_find`
//! (net/mac80211/rx.c) for the CONNAC2 path, where mt7921_mac_fill_rx
//! delivers each hardware-decrypted CCMP fragment with its PN in RX group 1
//! (`MT_RXD2_NORMAL_FRAG`) and leaves sequential-PN validation to the host.
//!
//! Rules kept from Linux:
//! - four entries per station (`IEEE80211_FRAGMENT_MAX`), replaced round-robin;
//! - a continuation must match sequence, replay queue (TID or non-QoS), frame
//!   type and the previous fragment number plus one;
//! - entries older than two seconds are purged on lookup;
//! - multicast fragments are dropped (`RX_DROP_U_MCAST_FRAGMENT`);
//! - a protected entry requires every continuation to be protected under the
//!   same key with PN exactly `last_pn + 1`, and an unprotected entry cannot
//!   take protected continuations (mixed-key / fragment-cache attacks).
//!
//! Native additions: the cache is flushed on every receive-epoch renewal, so
//! no entry survives a PTK/GTK change (the "key colour" of Linux), and the
//! reassembled MSDU is bounded to the 2304-byte IEEE 802.11 MSDU maximum.
use alloc::vec::Vec;

/// `IEEE80211_FRAGMENT_MAX`.
pub(super) const ENTRIES: usize = 4;
/// Linux `entry->first_frag_time + 2 * HZ`.
pub(super) const MAX_AGE_NS: u64 = 2_000_000_000;
/// IEEE 802.11 maximum MSDU size (header and CCMP excluded).
pub(super) const MAX_MSDU: usize = 2304;

/// Validated metadata of one native data fragment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Fragment {
    pub sequence: u16,
    pub number: u8,
    pub more: bool,
    /// Replay queue: QoS TID 0..15, or 16 for non-QoS data.
    pub queue: usize,
    /// Hardware-decrypted CCMP PN, or `None` for an unprotected fragment.
    pub pn: Option<u64>,
}

#[derive(Debug)]
struct Entry {
    sequence: u16,
    queue: usize,
    last_number: u8,
    first_pn: Option<u64>,
    last_pn: Option<u64>,
    started: u64,
    /// Normalized MAC header of the first fragment, then all bodies.
    frame: Vec<u8>,
    header_len: usize,
}

/// A complete reassembled MSDU, ready for the normal unfragmented path.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Reassembled {
    /// Normalized unfragmented MPDU: More Fragments, Protected and the
    /// fragment number are cleared; the body is the concatenated MSDU.
    pub frame: Vec<u8>,
    pub queue: usize,
    /// PN range of the constituent fragments (first, last), when protected.
    pub pn: Option<(u64, u64)>,
}

#[derive(Debug, Default)]
pub(super) struct Cache {
    entries: [Option<Entry>; ENTRIES],
    next: usize,
}

impl Cache {
    pub(super) fn clear(&mut self) {
        self.entries = Default::default();
        self.next = 0;
    }

    pub(super) fn pending(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Parse native fragment metadata. Only unicast FromDS data/QoS data
    /// without HT control or A-MSDU may be fragmented on this station path.
    pub(super) fn parse(frame: &[u8], pn: Option<u64>) -> Option<(Fragment, usize)> {
        let header = frame.get(..24)?;
        let fc = u16::from_le_bytes([header[0], header[1]]);
        let protected = fc & 0x4000 != 0;
        if !matches!(fc & 0xff, 0x08 | 0x88)
            || fc & 0x8300 != 0x0200 // FromDS only, no HT control.
            || header[4] & 1 != 0
            || protected != pn.is_some()
        {
            return None;
        }
        let number = header[22] & 15;
        let more = fc & 0x0400 != 0;
        if number == 0 && !more {
            return None; // Not a fragment.
        }
        let (queue, header_len) = if fc & 0x80 != 0 {
            let qos = frame.get(24..26)?;
            if qos[0] & 0x80 != 0 {
                return None; // Fragmented A-MSDU is not accepted.
            }
            (usize::from(qos[0] & 15), 26)
        } else {
            (16, 24)
        };
        Some((
            Fragment {
                sequence: u16::from_le_bytes([header[22], header[23]]) >> 4,
                number,
                more,
                queue,
                pn,
            },
            header_len,
        ))
    }

    /// Feed one validated fragment. Returns the complete MSDU after the last
    /// fragment; malformed, out-of-order or replayed continuations are
    /// dropped and never release partial data.
    pub(super) fn insert(
        &mut self,
        frame: &[u8],
        pn: Option<u64>,
        now: u64,
    ) -> Option<Reassembled> {
        let (fragment, header_len) = Self::parse(frame, pn)?;
        let body = &frame[header_len..];
        if body.len() > MAX_MSDU {
            return None;
        }
        if fragment.number == 0 {
            let mut copy = Vec::new();
            copy.try_reserve_exact(header_len + body.len()).ok()?;
            copy.extend_from_slice(frame);
            copy[1] &= !(0x04 | 0x40);
            copy[22] &= 0xf0;
            let slot = self.next;
            self.next = (self.next + 1) % ENTRIES;
            self.entries[slot] = Some(Entry {
                sequence: fragment.sequence,
                queue: fragment.queue,
                last_number: 0,
                first_pn: fragment.pn,
                last_pn: fragment.pn,
                started: now,
                frame: copy,
                header_len,
            });
            return None;
        }
        // Newest first, like ieee80211_reassemble_find.
        let mut found = None;
        for step in 1..=ENTRIES {
            let slot = (self.next + ENTRIES - step) % ENTRIES;
            let Some(entry) = &self.entries[slot] else {
                continue;
            };
            if entry.sequence != fragment.sequence
                || entry.queue != fragment.queue
                || entry.last_number + 1 != fragment.number
                || entry.header_len != header_len
                || (entry.frame[0] ^ frame[0]) & 0x0c != 0
                || entry.frame[4..16] != frame[4..16]
            {
                continue;
            }
            if now.saturating_sub(entry.started) > MAX_AGE_NS {
                self.entries[slot] = None;
                continue;
            }
            found = Some(slot);
            break;
        }
        let slot = found?;
        let entry = self.entries[slot].as_mut()?;
        match (entry.last_pn, fragment.pn) {
            (Some(last), Some(pn)) if last.checked_add(1) == Some(pn) => entry.last_pn = Some(pn),
            (None, None) => {}
            // Non-sequential PN, protected/unprotected mixing: drop the
            // continuation; Linux keeps the entry and lets it age out.
            _ => return None,
        }
        if entry.frame.len() - entry.header_len + body.len() > MAX_MSDU {
            self.entries[slot] = None;
            return None;
        }
        if entry.frame.try_reserve(body.len()).is_err() {
            self.entries[slot] = None;
            return None;
        }
        entry.frame.extend_from_slice(body);
        entry.last_number = fragment.number;
        if fragment.more {
            return None;
        }
        let entry = self.entries[slot].take()?;
        Some(Reassembled {
            frame: entry.frame,
            queue: entry.queue,
            pn: entry.first_pn.zip(entry.last_pn),
        })
    }
}
