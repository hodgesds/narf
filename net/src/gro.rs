//! Software generic receive offload (GRO): coalesce consecutive in-order
//! segments of one TCP flow into a single larger frame before the stack
//! processes them, the receive-side mirror of TSO/GSO. Fewer trips through
//! `handle_segment` per byte is the win at high RX rates.
//!
//! This is a bounded, stateful coalescer. A driver's RX path `offer`s each
//! received Ethernet/IPv4/TCP frame; the engine either holds it (merging into
//! an in-progress flow) or returns the frames the stack should process now,
//! and `flush` drains everything held at the end of a poll round (the
//! NAPI-complete equivalent). Only plain ACK data segments with no TCP options
//! are coalesced; anything else (SYN/FIN/RST/URG, options, non-IPv4, a
//! sequence gap, or a full/pushed flow) is passed through or flushes the flow,
//! so GRO never reorders a connection or hides a control flag.

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::{set_ipv4_checksum, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_TCP};
use crate::pkt_tcp::{ipv4_pseudo_checksum, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN};

/// Max flows held in progress at once; a new flow beyond this flushes the
/// oldest. Small — GRO batches within a single poll burst, not forever.
const MAX_FLOWS: usize = 8;
/// Max coalesced payload before a forced flush (one IPv4 datagram's worth).
const MAX_GRO_BYTES: usize = 65_000;
/// TCP flags that make a segment ineligible for coalescing (control or urgent).
const NON_COALESCE_FLAGS: u8 = FLAG_SYN | FLAG_FIN | FLAG_RST | (1 << 5); // URG = bit 5

#[derive(Debug, PartialEq, Eq)]
struct FlowKey {
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug)]
struct Held {
    key: FlowKey,
    frame: Vec<u8>,
    tcp_off: usize,
    next_seq: u32,
    segs: u16,
}

/// Per-RX-queue GRO coalescer. Create one per RX pump; `offer` each frame and
/// `flush` at poll-complete.
#[derive(Debug, Default)]
pub struct Gro {
    held: Vec<Held>,
}

/// A parsed view of an eligible IPv4/TCP data segment.
struct Parsed {
    key: FlowKey,
    tcp_off: usize,
    seq: u32,
    flags: u8,
    psh: bool,
    payload_len: usize,
}

fn parse_ipv4_tcp(frame: &[u8]) -> Option<Parsed> {
    let eth = ETH_HDR_LEN;
    if frame.len() < eth + IPV4_HDR_LEN || frame[eth] >> 4 != 4 {
        return None;
    }
    let ihl = (frame[eth] & 0x0f) as usize * 4;
    if ihl != IPV4_HDR_LEN || frame[eth + 9] != IP_PROTO_TCP {
        return None; // IPv4 options: not coalesced.
    }
    // Fragments are never coalesced.
    let frag = u16::from_be_bytes([frame[eth + 6], frame[eth + 7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    let ip_total = u16::from_be_bytes([frame[eth + 2], frame[eth + 3]]) as usize;
    let tcp_off = eth + ihl;
    if frame.len() < tcp_off + 20 || ip_total < ihl + 20 {
        return None;
    }
    let data_off = (frame[tcp_off + 12] >> 4) as usize * 4;
    if data_off != 20 {
        return None; // TCP options (timestamps, etc.): not coalesced.
    }
    let flags = frame[tcp_off + 13];
    let payload_len = (ip_total - ihl - data_off).min(frame.len() - tcp_off - data_off);
    Some(Parsed {
        key: FlowKey {
            src: frame[eth + 12..eth + 16].try_into().ok()?,
            dst: frame[eth + 16..eth + 20].try_into().ok()?,
            src_port: u16::from_be_bytes([frame[tcp_off], frame[tcp_off + 1]]),
            dst_port: u16::from_be_bytes([frame[tcp_off + 2], frame[tcp_off + 3]]),
        },
        tcp_off,
        seq: u32::from_be_bytes(frame[tcp_off + 4..tcp_off + 8].try_into().ok()?),
        flags,
        psh: flags & FLAG_PSH != 0,
        payload_len,
    })
}

/// Recompute the coalesced frame's IPv4 total-length / header checksum and the
/// TCP checksum, and return it for delivery to the stack.
fn finalize(mut h: Held) -> Vec<u8> {
    let eth = ETH_HDR_LEN;
    let ip_total = (h.frame.len() - eth) as u16;
    h.frame[eth + 2..eth + 4].copy_from_slice(&ip_total.to_be_bytes());
    h.frame[eth + 10] = 0;
    h.frame[eth + 11] = 0;
    set_ipv4_checksum(&mut h.frame[eth..eth + IPV4_HDR_LEN]);
    let src: [u8; 4] = h.frame[eth + 12..eth + 16].try_into().unwrap();
    let dst: [u8; 4] = h.frame[eth + 16..eth + 20].try_into().unwrap();
    h.frame[h.tcp_off + 16] = 0;
    h.frame[h.tcp_off + 17] = 0;
    let cs = ipv4_pseudo_checksum(src, dst, &h.frame[h.tcp_off..]);
    h.frame[h.tcp_off + 16..h.tcp_off + 18].copy_from_slice(&cs.to_be_bytes());
    h.frame
}

impl Gro {
    pub const fn new() -> Self {
        Self { held: Vec::new() }
    }

    /// Offer one received frame. Returns the frames the stack should process
    /// now (0 when the frame was merged/held, 1–2 when a held flow is
    /// flushed). The caller passes each returned frame to the normal RX path.
    pub fn offer(&mut self, frame: Vec<u8>) -> Vec<Vec<u8>> {
        let Some(p) = parse_ipv4_tcp(&frame) else {
            // Not an eligible segment: deliver as-is.
            return alloc::vec![frame];
        };
        // A control/urgent segment flushes any held flow for its key, then is
        // delivered itself (never coalesced).
        if p.flags & NON_COALESCE_FLAGS != 0 || p.payload_len == 0 || p.flags & FLAG_ACK == 0 {
            let mut out = Vec::new();
            if let Some(i) = self.held.iter().position(|h| h.key == p.key) {
                out.push(finalize(self.held.remove(i)));
            }
            out.push(frame);
            return out;
        }

        if let Some(i) = self.held.iter().position(|h| h.key == p.key) {
            let h = &self.held[i];
            let contiguous = p.seq == h.next_seq;
            let fits = h.frame.len() - h.tcp_off - 20 + p.payload_len <= MAX_GRO_BYTES;
            if contiguous && fits {
                // Merge: append this segment's payload to the held frame.
                let data_start = p.tcp_off + 20;
                let h = &mut self.held[i];
                h.frame
                    .extend_from_slice(&frame[data_start..data_start + p.payload_len]);
                h.next_seq = h.next_seq.wrapping_add(p.payload_len as u32);
                h.segs = h.segs.saturating_add(1);
                // Push flag or size ceiling flushes the flow now.
                if p.psh || h.frame.len() - h.tcp_off - 20 >= MAX_GRO_BYTES {
                    return alloc::vec![finalize(self.held.remove(i))];
                }
                return Vec::new();
            }
            // Out-of-order / overflow: flush the held flow, then handle this
            // frame as a fresh offer (hold it, unless it is pushed).
            let flushed = finalize(self.held.remove(i));
            let mut out = alloc::vec![flushed];
            out.extend(self.start(frame, p));
            return out;
        }

        self.start(frame, p)
    }

    /// Begin holding a new flow, or deliver immediately when pushed. Evicts the
    /// oldest held flow if the table is full.
    fn start(&mut self, frame: Vec<u8>, p: Parsed) -> Vec<Vec<u8>> {
        if p.psh {
            return alloc::vec![frame];
        }
        let mut out = Vec::new();
        if self.held.len() >= MAX_FLOWS {
            out.push(finalize(self.held.remove(0)));
        }
        let next_seq = p.seq.wrapping_add(p.payload_len as u32);
        self.held.push(Held {
            key: p.key,
            frame,
            tcp_off: p.tcp_off,
            next_seq,
            segs: 1,
        });
        out
    }

    /// Flush every held flow (call at NAPI-complete / end of a poll burst).
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        self.held.drain(..).map(finalize).collect()
    }

    /// Whether any flow is currently held (needs a later flush).
    pub fn pending(&self) -> bool {
        !self.held.is_empty()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod gro_tests {
    use super::*;
    use crate::pkt::ip_checksum;
    use crate::pkt_tcp::TCP_HDR_MIN;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn seg(src: [u8; 4], dst: [u8; 4], seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let total = tcp_off + TCP_HDR_MIN + payload.len();
        let mut f = alloc::vec![0u8; total];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[ETH_HDR_LEN] = 0x45;
        let ip_total = (IPV4_HDR_LEN + TCP_HDR_MIN + payload.len()) as u16;
        f[ETH_HDR_LEN + 2..ETH_HDR_LEN + 4].copy_from_slice(&ip_total.to_be_bytes());
        f[ETH_HDR_LEN + 9] = IP_PROTO_TCP;
        f[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&src);
        f[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20].copy_from_slice(&dst);
        set_ipv4_checksum(&mut f[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
        f[tcp_off..tcp_off + 2].copy_from_slice(&1111u16.to_be_bytes());
        f[tcp_off + 2..tcp_off + 4].copy_from_slice(&80u16.to_be_bytes());
        f[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
        f[tcp_off + 12] = (TCP_HDR_MIN as u8 / 4) << 4;
        f[tcp_off + 13] = flags;
        f[tcp_off + TCP_HDR_MIN..].copy_from_slice(payload);
        let cs = ipv4_pseudo_checksum(src, dst, &f[tcp_off..]);
        f[tcp_off + 16..tcp_off + 18].copy_from_slice(&cs.to_be_bytes());
        f
    }

    fn smoke_gro_ipv4_coalesce() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let mut gro = Gro::new();
        // Three contiguous ACK segments, no PSH: all held, nothing delivered.
        if !gro
            .offer(seg(src, dst, 1000, FLAG_ACK, &[1u8; 100]))
            .is_empty()
            || !gro
                .offer(seg(src, dst, 1100, FLAG_ACK, &[2u8; 100]))
                .is_empty()
            || !gro
                .offer(seg(src, dst, 1200, FLAG_ACK, &[3u8; 50]))
                .is_empty()
        {
            return TestResult::Fail("coalescable segments were not held");
        }
        if !gro.pending() {
            return TestResult::Fail("GRO reports nothing pending after holding");
        }
        let flushed = gro.flush();
        if flushed.len() != 1 {
            return TestResult::Fail("flush did not merge into one frame");
        }
        let f = &flushed[0];
        // Coalesced payload = 250 bytes, seq = first, valid checksums.
        let payload = &f[tcp_off + TCP_HDR_MIN..];
        if payload.len() != 250 {
            return TestResult::Fail("coalesced payload length wrong");
        }
        if payload[..100].iter().any(|&b| b != 1)
            || payload[100..200].iter().any(|&b| b != 2)
            || payload[200..].iter().any(|&b| b != 3)
        {
            return TestResult::Fail("coalesced payload content wrong");
        }
        if u32::from_be_bytes(f[tcp_off + 4..tcp_off + 8].try_into().unwrap()) != 1000 {
            return TestResult::Fail("coalesced seq != first segment seq");
        }
        if ip_checksum(&f[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]) != 0 {
            return TestResult::Fail("coalesced IPv4 checksum invalid");
        }
        if ipv4_pseudo_checksum(src, dst, &f[tcp_off..]) != 0 {
            return TestResult::Fail("coalesced TCP checksum invalid");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_ipv4_coalesce);

    fn smoke_gro_flush_conditions() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let mut gro = Gro::new();
        // PSH delivers immediately (not held).
        let out = gro.offer(seg(src, dst, 1, FLAG_ACK | FLAG_PSH, &[7u8; 20]));
        if out.len() != 1 || gro.pending() {
            return TestResult::Fail("pushed segment should pass straight through");
        }
        // A sequence gap flushes the held flow and starts a new one.
        let _ = gro.offer(seg(src, dst, 100, FLAG_ACK, &[1u8; 50])); // held
        let gap = gro.offer(seg(src, dst, 500, FLAG_ACK, &[2u8; 50])); // non-contiguous
        if gap.len() != 1 {
            return TestResult::Fail("sequence gap did not flush the held flow");
        }
        // SYN/FIN/RST are never coalesced and flush any held flow.
        let fin = gro.offer(seg(src, dst, 550, FLAG_ACK | FLAG_FIN, &[3u8; 10]));
        if fin.len() != 2 {
            return TestResult::Fail("FIN should flush held + deliver itself");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_flush_conditions);
}
