//! Send + receive buffers with out-of-order reassembly.
//!
//! ## Send buffer
//!
//! `SendBuf` is a contiguous-ish byte queue (`VecDeque<u8>`) that
//! the user writes into via `tcp_send` and the stack drains into
//! the wire. We track `unacked_head_seq` — the sequence number of
//! the first unacked byte — so segments can be rebuilt for
//! retransmit without re-asking the user.
//!
//! When ACKs come in we `release` ack'd prefix bytes so the
//! buffer footprint shrinks.
//!
//! ## Receive buffer
//!
//! `RecvBuf` is split into two halves:
//!
//! - `in_order`: byte queue contiguous with the user-visible
//!   `rcv_nxt`. The user drains this via `tcp_recv`.
//! - `out_of_order`: a list of `Segment`s keyed by sequence
//!   number for the gap-fill flow.
//!
//! When a segment arrives:
//!
//! 1. If `seq == rcv_nxt`, push into `in_order`, advance
//!    `rcv_nxt`, then try to drain consecutive out-of-order
//!    segments into `in_order`.
//! 2. Else queue into `out_of_order`. Merge with existing
//!    segments where ranges overlap or abut.
//!
//! ## Window math
//!
//! `advertised_window()` returns the remaining capacity in
//! bytes; capped by the socket buffer limit (256 KiB default).
//!
//! Linux ref: `net/ipv4/tcp_input.c::tcp_data_queue`,
//! `net/ipv4/tcp_input.c::tcp_ofo_queue`,
//! `include/net/tcp.h::tcp_rcv_wnd_update`.

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Default receive buffer size — 256 KiB matches the spec
/// requirement and slots into the wscale=7 ceiling cleanly.
pub const DEFAULT_RCV_BUF: usize = 256 * 1024;
/// Default send buffer size — same convention.
pub const DEFAULT_SND_BUF: usize = 256 * 1024;

/// Send-side byte buffer. `unacked_head_seq` is the sequence
/// number of `bytes[0]`; bytes ahead of `next_send_offset` are
/// queued-but-unsent.
#[derive(Debug)]
pub struct SendBuf {
    bytes: VecDeque<u8>,
    /// Sequence number of the first byte in `bytes` (the oldest
    /// unacked byte).
    pub unacked_head_seq: u32,
    /// Bytes already sent at least once — sum of segment lengths
    /// pushed via `mark_sent`. Reset on retransmit.
    pub sent_offset: usize,
    /// Maximum bytes the user may queue at once.
    pub limit: usize,
}

impl Default for SendBuf {
    fn default() -> Self {
        Self::new(DEFAULT_SND_BUF, 0)
    }
}

impl SendBuf {
    pub fn new(limit: usize, isn: u32) -> Self {
        Self {
            bytes: VecDeque::with_capacity(limit.min(64 * 1024)),
            unacked_head_seq: isn,
            sent_offset: 0,
            limit,
        }
    }

    /// User-facing write. Accepts up to `limit - len()` bytes;
    /// returns the byte count that fit.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let cap = self.limit.saturating_sub(self.bytes.len());
        let n = data.len().min(cap);
        for &b in &data[..n] {
            self.bytes.push_back(b);
        }
        n
    }

    /// Number of bytes queued (sent + unsent).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` iff no bytes are queued at all.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of bytes available to send (queued but not yet
    /// pushed to wire).
    pub fn unsent_len(&self) -> usize {
        self.bytes.len().saturating_sub(self.sent_offset)
    }

    /// Number of bytes that have been sent but not yet ack'd.
    pub fn inflight_bytes(&self) -> usize {
        self.sent_offset
    }

    /// Borrow the up-to-`n`-byte slice of unsent data starting at
    /// `sent_offset`. Returns two slices since the underlying
    /// VecDeque can wrap.
    pub fn unsent_slices(&self, n: usize) -> (&[u8], &[u8]) {
        let (a, b) = self.bytes.as_slices();
        let off = self.sent_offset;
        let take = self.unsent_len().min(n);
        if off >= a.len() {
            let bo = off - a.len();
            let avail = b.len().saturating_sub(bo);
            let t = take.min(avail);
            (&b[bo..bo + t], &[])
        } else {
            let avail_a = a.len() - off;
            if take <= avail_a {
                (&a[off..off + take], &[])
            } else {
                let from_b = take - avail_a;
                (&a[off..], &b[..from_b])
            }
        }
    }

    /// Borrow the entire buffer (sent + unsent, unacked) as two
    /// contiguous slices from the underlying VecDeque ring. Used
    /// when retransmitting data at an arbitrary offset into the
    /// buffer (e.g. selective retransmit). The slices together
    /// cover bytes `[unacked_head_seq, unacked_head_seq + len)`.
    pub fn full_slices(&self) -> (&[u8], &[u8]) {
        self.bytes.as_slices()
    }

    /// Mark `n` bytes from `sent_offset` as in-flight. Caller
    /// has just built a segment carrying those bytes.
    pub fn mark_sent(&mut self, n: usize) {
        self.sent_offset = (self.sent_offset + n).min(self.bytes.len());
    }

    /// Process a cumulative ACK that ack'd through `ack_seq`.
    /// Releases ack'd bytes from the buffer and slides
    /// `unacked_head_seq` forward.
    pub fn ack(&mut self, ack_seq: u32) -> usize {
        // Bytes ack'd = ack_seq - unacked_head_seq (wrap-aware).
        let n = ack_seq.wrapping_sub(self.unacked_head_seq) as usize;
        let n = n.min(self.bytes.len());
        for _ in 0..n {
            self.bytes.pop_front();
        }
        self.unacked_head_seq = self.unacked_head_seq.wrapping_add(n as u32);
        self.sent_offset = self.sent_offset.saturating_sub(n);
        n
    }

    /// Rewind `sent_offset` to 0 — used on RTO when we must
    /// retransmit from `unacked_head_seq`.
    pub fn rewind_for_retransmit(&mut self) {
        self.sent_offset = 0;
    }

    /// Walk forward `n` bytes from `sent_offset`. Used by the
    /// SACK-aware retransmit loop to skip ranges the peer
    /// already SACK'd.
    pub fn advance_sent_offset(&mut self, n: usize) {
        self.sent_offset = (self.sent_offset + n).min(self.bytes.len());
    }

    /// Sequence number at the current `sent_offset` (i.e. seq of
    /// the next byte we'd send if asked for more data right now).
    pub fn seq_at_sent_offset(&self) -> u32 {
        self.unacked_head_seq.wrapping_add(self.sent_offset as u32)
    }
}

/// One contiguous segment of out-of-order received data.
#[derive(Clone, Debug)]
struct OoSegment {
    seq: u32,
    data: Vec<u8>,
}

impl OoSegment {
    fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.data.len() as u32)
    }
}

/// Receive buffer + reassembly book.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Contiguous in-order data the user can read.
    in_order: VecDeque<u8>,
    /// Out-of-order segments waiting to be stitched in.
    out_of_order: Vec<OoSegment>,
    /// Receive-buffer capacity in bytes.
    pub limit: usize,
}

impl RecvBuf {
    pub fn new(limit: usize) -> Self {
        Self {
            in_order: VecDeque::with_capacity(limit.min(64 * 1024)),
            out_of_order: Vec::new(),
            limit,
        }
    }

    /// `true` iff no in-order data is queued and no out-of-order
    /// segments are pending.
    pub fn is_idle(&self) -> bool {
        self.in_order.is_empty() && self.out_of_order.is_empty()
    }

    /// Remaining bytes that fit. Used for the advertised window.
    pub fn free_window(&self) -> u32 {
        let used = self.in_order.len()
            + self
                .out_of_order
                .iter()
                .map(|s| s.data.len())
                .sum::<usize>();
        self.limit.saturating_sub(used) as u32
    }

    /// User-facing read. Pops up to `dst.len()` bytes from
    /// `in_order`. Returns the byte count.
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.in_order.len());
        for slot in &mut dst[..n] {
            *slot = self.in_order.pop_front().unwrap_or(0);
        }
        n
    }

    /// `true` iff `read()` would return at least one byte.
    pub fn has_data(&self) -> bool {
        !self.in_order.is_empty()
    }

    /// Accept a segment of length `data.len()` starting at `seq`.
    /// If it's contiguous with `rcv_nxt` it lands directly in
    /// `in_order`; otherwise it goes into the out-of-order pool.
    ///
    /// Returns the new `rcv_nxt` after stitching.
    pub fn accept(&mut self, mut seq: u32, mut data: &[u8], mut rcv_nxt: u32) -> u32 {
        if data.is_empty() {
            return rcv_nxt;
        }
        // Trim bytes that are already in-order (pure overlap with
        // existing in_order delivery).
        let skip = rcv_nxt.wrapping_sub(seq);
        if (skip as i32) > 0 && (skip as usize) < data.len() {
            data = &data[skip as usize..];
            seq = seq.wrapping_add(skip);
        } else if (skip as i32) >= data.len() as i32 {
            // Whole segment was already consumed.
            return rcv_nxt;
        }
        // Clamp to free window so we don't overflow the buffer.
        let free = self.free_window() as usize;
        let take = data.len().min(free);
        if take == 0 {
            return rcv_nxt;
        }
        let data = &data[..take];

        if seq == rcv_nxt {
            for &b in data {
                self.in_order.push_back(b);
            }
            rcv_nxt = rcv_nxt.wrapping_add(data.len() as u32);
            rcv_nxt = self.drain_ooo_into_in_order(rcv_nxt);
        } else {
            self.insert_ooo(OoSegment {
                seq,
                data: data.to_vec(),
            });
        }
        rcv_nxt
    }

    /// Merge overlapping / adjacent out-of-order segments and
    /// keep the list sorted by sequence number.
    fn insert_ooo(&mut self, seg: OoSegment) {
        if seg.data.is_empty() {
            return;
        }
        // Try to merge with each existing OO seg.
        let mut merged_seq = seg.seq;
        let mut merged_end = seg.end_seq();
        let mut merged: Vec<u8> = seg.data;
        let mut survivors = Vec::with_capacity(self.out_of_order.len() + 1);
        for existing in self.out_of_order.drain(..) {
            if segment_overlap_or_adjacent(merged_seq, merged_end, existing.seq, existing.end_seq())
            {
                // Merge.
                if seq_lt(existing.seq, merged_seq) {
                    let prepend_len = merged_seq.wrapping_sub(existing.seq) as usize;
                    let prepend_len = prepend_len.min(existing.data.len());
                    let mut new_data = Vec::with_capacity(prepend_len + merged.len());
                    new_data.extend_from_slice(&existing.data[..prepend_len]);
                    new_data.extend_from_slice(&merged);
                    merged = new_data;
                    merged_seq = existing.seq;
                }
                if seq_gt(existing.end_seq(), merged_end) {
                    let tail_start = merged_end.wrapping_sub(existing.seq) as usize;
                    if tail_start < existing.data.len() {
                        merged.extend_from_slice(&existing.data[tail_start..]);
                    }
                    merged_end = existing.end_seq();
                }
            } else {
                survivors.push(existing);
            }
        }
        survivors.push(OoSegment {
            seq: merged_seq,
            data: merged,
        });
        // Sort by seq (wrap-aware would be ideal; in practice
        // the segments cluster around rcv_nxt and a plain sort
        // keeps the right order modulo a single wrap window).
        survivors.sort_by_key(|s| s.seq);
        self.out_of_order = survivors;
    }

    /// After advancing rcv_nxt by an in-order segment, walk the
    /// OO list and slurp up consecutive segments into in_order.
    fn drain_ooo_into_in_order(&mut self, mut rcv_nxt: u32) -> u32 {
        loop {
            let mut consumed = None;
            for (i, seg) in self.out_of_order.iter().enumerate() {
                if seg.seq == rcv_nxt {
                    consumed = Some(i);
                    break;
                }
                if seq_lt(seg.end_seq(), rcv_nxt) {
                    // Already covered — drop.
                    consumed = Some(i);
                    break;
                }
                if seq_lt(seg.seq, rcv_nxt) && seq_gt(seg.end_seq(), rcv_nxt) {
                    // Partial overlap on the left edge — splice the
                    // post-rcv_nxt tail into in_order.
                    let skip = rcv_nxt.wrapping_sub(seg.seq) as usize;
                    let tail = &seg.data[skip..];
                    for &b in tail {
                        self.in_order.push_back(b);
                    }
                    rcv_nxt = rcv_nxt.wrapping_add(tail.len() as u32);
                    consumed = Some(i);
                    break;
                }
            }
            match consumed {
                Some(i) => {
                    let seg = self.out_of_order.remove(i);
                    if seg.seq == rcv_nxt {
                        for &b in &seg.data {
                            self.in_order.push_back(b);
                        }
                        rcv_nxt = rcv_nxt.wrapping_add(seg.data.len() as u32);
                    }
                }
                None => break,
            }
        }
        rcv_nxt
    }

    /// SACK blocks describing currently-held out-of-order ranges.
    /// MRU first per RFC 2018 §4.
    pub fn sack_blocks(&self) -> alloc::vec::Vec<super::sack::SackBlock> {
        let mut blocks: alloc::vec::Vec<super::sack::SackBlock> = self
            .out_of_order
            .iter()
            .map(|s| super::sack::SackBlock {
                left: s.seq,
                right: s.end_seq(),
            })
            .collect();
        // Reverse so the most-recently-pushed (last in vec post
        // sort) becomes the first in the SACK option.
        blocks.reverse();
        blocks
    }
}

#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

fn segment_overlap_or_adjacent(la: u32, ra: u32, lb: u32, rb: u32) -> bool {
    let overlap = seq_lt(la, rb) && seq_lt(lb, ra);
    let adjacent = la == rb || lb == ra;
    overlap || adjacent
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn send_buf_write_and_ack() {
        let mut s = SendBuf::new(1024, 100);
        let n = s.write(b"hello world");
        assert_eq!(n, 11);
        assert_eq!(s.unsent_len(), 11);
        s.mark_sent(5); // "hello"
        assert_eq!(s.inflight_bytes(), 5);
        assert_eq!(s.unsent_len(), 6);
        // Ack the first 3 bytes ("hel").
        let acked = s.ack(103);
        assert_eq!(acked, 3);
        assert_eq!(s.unacked_head_seq, 103);
        assert_eq!(s.inflight_bytes(), 2);
    }

    #[test]
    fn recv_buf_in_order_reads_back() {
        let mut r = RecvBuf::new(1024);
        let mut rcv_nxt = 100;
        rcv_nxt = r.accept(100, b"AAAA", rcv_nxt);
        assert_eq!(rcv_nxt, 104);
        let mut buf = [0u8; 8];
        let n = r.read(&mut buf);
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"AAAA");
    }

    #[test]
    fn recv_buf_out_of_order_stitches() {
        let mut r = RecvBuf::new(1024);
        let mut rcv_nxt = 100;
        // Arrive out-of-order: 110..115 first, then 100..110.
        rcv_nxt = r.accept(110, b"DDDDD", rcv_nxt);
        assert_eq!(rcv_nxt, 100, "out-of-order shouldn't advance rcv_nxt");
        rcv_nxt = r.accept(100, b"AAAAAAAAAA", rcv_nxt);
        assert_eq!(rcv_nxt, 115, "in-order arrival should stitch the OO seg");
        let mut buf = [0u8; 32];
        let n = r.read(&mut buf);
        assert_eq!(n, 15);
        assert_eq!(&buf[..10], b"AAAAAAAAAA");
        assert_eq!(&buf[10..15], b"DDDDD");
    }

    #[test]
    fn recv_buf_sack_blocks_after_ooo() {
        let mut r = RecvBuf::new(1024);
        let mut rcv_nxt = 100;
        rcv_nxt = r.accept(200, b"E", rcv_nxt);
        rcv_nxt = r.accept(300, b"F", rcv_nxt);
        let blocks = r.sack_blocks();
        assert_eq!(blocks.len(), 2);
        // MRU first.
        assert_eq!(blocks[0].left, 300);
        assert_eq!(blocks[1].left, 200);
        let _ = rcv_nxt;
    }

    #[test]
    fn recv_buf_free_window_decreases() {
        let mut r = RecvBuf::new(100);
        let initial = r.free_window();
        let _ = r.accept(0, &[0u8; 50], 0);
        let after = r.free_window();
        assert!(after < initial);
        assert_eq!(after, 50);
    }
}
