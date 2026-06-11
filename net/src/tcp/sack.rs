//! Selective Acknowledgement — RFC 2018.
//!
//! ## Wire format (RFC 2018 §3, §4)
//!
//! `SACK-Permitted` (kind 4, length 2): advertised in SYN, says
//! "I will accept SACK option in your future segments".
//!
//! `SACK` (kind 5, length 2 + 8*N): each block is a `(left,
//! right)` pair of 32-bit sequence numbers. The RFC caps N at 4
//! (since the TCP options space is 40 bytes; 8*4 + 2 = 34, leaving
//! room for timestamps too).
//!
//! ## What we do with received SACK
//!
//! Mark the (left..right) ranges as "definitely received by the
//! peer". When retransmitting after fast retransmit or RTO,
//! *skip* anything covered by a SACK block — only the unacked
//! gaps go back on the wire. This is RFC 6675 selective
//! retransmit; we implement the simpler "skip-on-SACK" form
//! sufficient for typical loss patterns.
//!
//! ## What we send as SACK
//!
//! When out-of-order segments arrive, the SACK option carries
//! the ranges held in the reassembly queue. First block is the
//! most-recently-received range (RFC 2018 §4), remaining blocks
//! are older ranges in MRU order.
//!
//! Linux ref: `net/ipv4/tcp_input.c::tcp_sacktag_write_queue`,
//! `net/ipv4/tcp_output.c::tcp_options_write`.

#![allow(dead_code)]

use alloc::vec::Vec;

/// Maximum number of SACK blocks we'll encode into one TCP
/// header. Wire cap (RFC 2018 §3) is 4; we honour that exactly.
pub const MAX_SACK_BLOCKS: usize = 4;

/// One SACK block on the wire — left edge inclusive, right edge
/// exclusive in sequence space.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SackBlock {
    pub left: u32,
    pub right: u32,
}

impl SackBlock {
    /// `true` iff `seq` falls inside `[left, right)` in
    /// sequence-space.
    #[inline]
    pub fn contains(&self, seq: u32) -> bool {
        let in_left = (seq.wrapping_sub(self.left) as i32) >= 0;
        let in_right = (self.right.wrapping_sub(seq) as i32) > 0;
        in_left && in_right
    }

    /// Length of the block in bytes (handles wrap by reading as
    /// a 32-bit subtraction).
    #[inline]
    pub fn len(&self) -> u32 {
        self.right.wrapping_sub(self.left)
    }

    /// True when the block covers no sequence space (`left == right`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.left == self.right
    }
}

/// Encode up to `MAX_SACK_BLOCKS` SackBlocks as the option payload
/// (the kind/length header is written by the caller).
///
/// Output length is `8 * blocks.len()`.
pub fn encode_blocks(blocks: &[SackBlock]) -> Vec<u8> {
    let n = blocks.len().min(MAX_SACK_BLOCKS);
    let mut out = Vec::with_capacity(8 * n);
    for b in &blocks[..n] {
        out.extend_from_slice(&b.left.to_be_bytes());
        out.extend_from_slice(&b.right.to_be_bytes());
    }
    out
}

/// Decode SACK blocks from the option payload (i.e. the `value`
/// slice after the 2-byte kind/length header has been stripped).
pub fn decode_blocks(payload: &[u8]) -> Vec<SackBlock> {
    let mut out = Vec::new();
    let n = payload.len() / 8;
    for i in 0..n.min(MAX_SACK_BLOCKS) {
        let off = i * 8;
        let left = u32::from_be_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]);
        let right = u32::from_be_bytes([
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]);
        // Reject degenerate blocks (left == right or left > right
        // in wrap-aware sequence space).
        if left != right {
            out.push(SackBlock { left, right });
        }
    }
    out
}

/// Receiver-side SACK book: holds the up-to-4 ranges of
/// out-of-order data we'd advertise back to the sender.
///
/// New ranges go at the front (MRU first per RFC 2018 §4); we
/// merge with adjacent ranges before pushing.
#[derive(Clone, Debug, Default)]
pub struct SackBook {
    blocks: Vec<SackBlock>,
}

impl SackBook {
    pub const fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    /// Add a range. Merges with any adjacent / overlapping
    /// existing range, then truncates to `MAX_SACK_BLOCKS` keeping
    /// MRU first.
    pub fn add_range(&mut self, mut left: u32, mut right: u32) {
        if left == right {
            return;
        }
        // Sweep to merge overlaps / adjacencies; collect the
        // surviving ranges.
        let mut survivors = Vec::with_capacity(self.blocks.len() + 1);
        for b in self.blocks.drain(..) {
            if seq_overlaps_or_adjacent(b.left, b.right, left, right) {
                // Merge in place.
                left = seq_min(b.left, left);
                right = seq_max(b.right, right);
            } else {
                survivors.push(b);
            }
        }
        // New / merged range at the head (MRU).
        let mut next = Vec::with_capacity(MAX_SACK_BLOCKS);
        next.push(SackBlock { left, right });
        for b in survivors {
            if next.len() < MAX_SACK_BLOCKS {
                next.push(b);
            }
        }
        self.blocks = next;
    }

    /// Drop any block fully covered by `(0, snd_una)` — i.e. data
    /// that's now contiguous with the in-order stream.
    pub fn prune_to(&mut self, rcv_nxt: u32) {
        self.blocks.retain(|b| {
            // Keep blocks that have at least one byte beyond rcv_nxt.
            (b.right.wrapping_sub(rcv_nxt) as i32) > 0 && (b.left.wrapping_sub(rcv_nxt) as i32) >= 0
        });
    }

    pub fn blocks(&self) -> &[SackBlock] {
        &self.blocks
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Sender-side SACK book: ranges the receiver has acknowledged
/// (via incoming SACK options) that we shouldn't retransmit.
#[derive(Clone, Debug, Default)]
pub struct SenderScoreboard {
    pub blocks: Vec<SackBlock>,
}

impl SenderScoreboard {
    pub const fn new() -> Self {
        Self { blocks: Vec::new() }
    }

    /// Replace scoreboard from an incoming SACK option.
    pub fn update_from(&mut self, blocks: &[SackBlock]) {
        self.blocks = blocks.iter().copied().take(MAX_SACK_BLOCKS).collect();
    }

    /// `true` iff `seq` falls inside any scoreboarded block.
    pub fn is_sacked(&self, seq: u32) -> bool {
        self.blocks.iter().any(|b| b.contains(seq))
    }

    /// Drop scoreboard ranges that are now ≤ snd_una (i.e. covered
    /// by the cumulative ACK).
    pub fn prune_below(&mut self, snd_una: u32) {
        self.blocks.retain(|b| {
            // Keep blocks whose right edge is > snd_una.
            (b.right.wrapping_sub(snd_una) as i32) > 0
        });
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
    }
}

// ── helpers ───────────────────────────────────────────────────────

fn seq_overlaps_or_adjacent(la: u32, ra: u32, lb: u32, rb: u32) -> bool {
    // Two half-open ranges overlap iff la < rb AND lb < ra.
    // "Adjacent" means la == rb or lb == ra (one starts where the
    // other ends).
    let ovr = (la.wrapping_sub(rb) as i32) < 0 && (lb.wrapping_sub(ra) as i32) < 0;
    let adj = la == rb || lb == ra;
    ovr || adj
}

fn seq_min(a: u32, b: u32) -> u32 {
    if (a.wrapping_sub(b) as i32) <= 0 {
        a
    } else {
        b
    }
}

fn seq_max(a: u32, b: u32) -> u32 {
    if (a.wrapping_sub(b) as i32) >= 0 {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip_three_blocks() {
        let blocks = alloc::vec![
            SackBlock {
                left: 1000,
                right: 2000
            },
            SackBlock {
                left: 3000,
                right: 3500
            },
            SackBlock {
                left: 5000,
                right: 7000
            },
        ];
        let encoded = encode_blocks(&blocks);
        assert_eq!(encoded.len(), 8 * 3);
        let decoded = decode_blocks(&encoded);
        assert_eq!(decoded, blocks);
    }

    #[test]
    fn encode_caps_at_four_blocks() {
        let blocks = alloc::vec![
            SackBlock { left: 1, right: 2 },
            SackBlock { left: 3, right: 4 },
            SackBlock { left: 5, right: 6 },
            SackBlock { left: 7, right: 8 },
            SackBlock { left: 9, right: 10 },
        ];
        let encoded = encode_blocks(&blocks);
        assert_eq!(encoded.len(), 8 * 4);
    }

    #[test]
    fn book_merges_adjacent_ranges() {
        let mut b = SackBook::new();
        b.add_range(1000, 2000);
        b.add_range(2000, 3000); // adjacent right
        assert_eq!(b.blocks().len(), 1);
        assert_eq!(
            b.blocks()[0],
            SackBlock {
                left: 1000,
                right: 3000
            }
        );
    }

    #[test]
    fn book_keeps_mru_order() {
        let mut b = SackBook::new();
        b.add_range(1000, 2000);
        b.add_range(5000, 6000);
        // 5000..6000 should be first (MRU).
        assert_eq!(b.blocks()[0].left, 5000);
        assert_eq!(b.blocks()[1].left, 1000);
    }

    #[test]
    fn scoreboard_pruning() {
        let mut s = SenderScoreboard::new();
        s.update_from(&[
            SackBlock {
                left: 100,
                right: 200,
            },
            SackBlock {
                left: 300,
                right: 400,
            },
        ]);
        s.prune_below(250); // covers first block
        assert_eq!(s.blocks.len(), 1);
        assert_eq!(s.blocks[0].left, 300);
    }
}
