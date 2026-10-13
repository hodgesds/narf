//! Software generic receive offload (GRO): coalesce consecutive in-order
//! segments of one TCP flow into a single larger frame before the stack
//! processes them, the receive-side mirror of TSO/GSO. Fewer trips through
//! `handle_segment` per byte is the win at high RX rates.
//!
//! This is a bounded, stateful coalescer. A driver's RX path `offer`s each
//! received Ethernet/IPv4/TCP frame; the engine either holds it (merging into
//! an in-progress flow) or returns the frames the stack should process now,
//! and `flush` drains everything held at the end of a poll round (the
//! NAPI-complete equivalent).
//!
//! The merge rules are Linux's (`inet_gro_receive`, `tcp4_gro_receive`,
//! `tcp_gro_receive`): only a checksum-valid, unfragmented, unpadded IPv4
//! segment is eligible, and it joins a held flow only when it continues the
//! sequence and every other header field — ACK, window, TCP options, TTL,
//! TOS, DF, and the IP ID pattern — matches. Anything else is passed through
//! untouched or flushes the flow, so GRO never reorders a connection, hides a
//! control flag, or launders a corrupted segment with a fresh checksum.
//!
//! Tables are per CPU (see `tcp_stack::gro_rx`); a driver must offer and
//! flush a burst on the same CPU, as its pinned RX poller does.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::pkt::{ip_checksum, set_ipv4_checksum, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_TCP};
use crate::pkt_tcp::{
    ipv4_pseudo_checksum, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, FLAG_URG,
};

/// Max flows held in progress at once; a new flow beyond this flushes the
/// oldest. Small — GRO batches within a single poll burst, not forever.
const MAX_FLOWS: usize = 8;
/// Max coalesced payload before a forced flush (one IPv4 datagram's worth).
const MAX_GRO_BYTES: usize = 65_000;
/// TCP flags that end a batch (`tcp_gro_receive`'s `out_check_final`). FIN,
/// SYN, RST and URG segments are never held; PSH may join a flow, then flushes
/// it.
const NON_COALESCE_FLAGS: u8 = FLAG_SYN | FLAG_FIN | FLAG_RST | FLAG_URG;
/// IPv4 "don't fragment".
const IP_DF: u16 = 0x4000;

#[derive(Debug, PartialEq, Eq)]
struct FlowKey {
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug)]
struct Held {
    /// Ingress interface the held frames arrived on; a flushed frame is
    /// dispatched back to this iface (the per-CPU table may interleave ifaces
    /// via the busy-wait drain fan-out, so flows are tagged, not assumed).
    iface: String,
    key: FlowKey,
    frame: Vec<u8>,
    tcp_off: usize,
    tcp_header_len: usize,
    next_seq: u32,
    /// Segments merged so far (`NAPI_GRO_CB(p)->count`).
    segs: u16,
    /// Payload length of the first segment: the flow's MSS (`gso_size`).
    mss: usize,
    /// IP ID of the first segment.
    ip_id: u16,
    /// Whether the flow's IP ID stays fixed (`ip_fixedid`), decided by the
    /// second segment; `None` while only one segment is held.
    fixed_id: Option<bool>,
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
    tcp_header_len: usize,
    seq: u32,
    flags: u8,
    payload_len: usize,
    ip_id: u16,
}

fn parse_ipv4_tcp(frame: &[u8]) -> Option<Parsed> {
    let eth = ETH_HDR_LEN;
    if frame.len() < eth + IPV4_HDR_LEN {
        return None;
    }
    // `inet_gro_receive`: `*(u8 *)iph != 0x45` — IPv4 with no options.
    if frame[eth] != 0x45 || frame[eth + 9] != IP_PROTO_TCP {
        return None;
    }
    // `ip_is_fragment`: neither more-fragments nor an offset.
    let frag = u16::from_be_bytes([frame[eth + 6], frame[eth + 7]]);
    if frag & 0x3fff != 0 {
        return None;
    }
    // The IPv4 total length must cover the frame exactly: Ethernet padding
    // after the datagram (`tot_len != skb_gro_len`) is never coalesced.
    let ip_total = u16::from_be_bytes([frame[eth + 2], frame[eth + 3]]) as usize;
    if eth + ip_total != frame.len() {
        return None;
    }
    // `ip_fast_csum`: a corrupt header goes to the stack, which drops it.
    if ip_checksum(&frame[eth..eth + IPV4_HDR_LEN]) != 0 {
        return None;
    }
    let tcp_off = eth + IPV4_HDR_LEN;
    if frame.len() < tcp_off + 20 {
        return None;
    }
    let data_off = (frame[tcp_off + 12] >> 4) as usize * 4;
    if !(20..=60).contains(&data_off) || frame.len() < tcp_off + data_off {
        return None;
    }
    let src: [u8; 4] = frame[eth + 12..eth + 16].try_into().ok()?;
    let dst: [u8; 4] = frame[eth + 16..eth + 20].try_into().ok()?;
    // `skb_gro_checksum_validate`: only a segment whose TCP checksum verifies
    // may be merged. `finalize` writes a fresh checksum over the merged frame,
    // so merging an unverified segment would turn corruption into valid data.
    if ipv4_pseudo_checksum(src, dst, &frame[tcp_off..]) != 0 {
        return None;
    }
    Some(Parsed {
        key: FlowKey {
            src,
            dst,
            src_port: u16::from_be_bytes([frame[tcp_off], frame[tcp_off + 1]]),
            dst_port: u16::from_be_bytes([frame[tcp_off + 2], frame[tcp_off + 3]]),
        },
        tcp_off,
        tcp_header_len: data_off,
        seq: u32::from_be_bytes(frame[tcp_off + 4..tcp_off + 8].try_into().ok()?),
        flags: frame[tcp_off + 13],
        payload_len: frame.len() - tcp_off - data_off,
        ip_id: u16::from_be_bytes([frame[eth + 4], frame[eth + 5]]),
    })
}

/// The TCP/IPv4 flow an ineligible frame belongs to, if it has one at all.
fn flow_key_of(frame: &[u8]) -> Option<FlowKey> {
    let eth = ETH_HDR_LEN;
    if frame.len() < eth + IPV4_HDR_LEN || frame[eth] >> 4 != 4 || frame[eth + 9] != IP_PROTO_TCP {
        return None;
    }
    let tcp_off = eth + (frame[eth] & 0x0f) as usize * 4;
    if frame.len() < tcp_off + 4 {
        return None;
    }
    Some(FlowKey {
        src: frame[eth + 12..eth + 16].try_into().ok()?,
        dst: frame[eth + 16..eth + 20].try_into().ok()?,
        src_port: u16::from_be_bytes([frame[tcp_off], frame[tcp_off + 1]]),
        dst_port: u16::from_be_bytes([frame[tcp_off + 2], frame[tcp_off + 3]]),
    })
}

/// `tcp_gro_receive` + `inet_gro_flush`: may segment `p` (in `frame`) join
/// the held flow `h`? Everything but the sequence-advancing fields must match.
fn can_merge(h: &Held, frame: &[u8], p: &Parsed) -> bool {
    let eth = ETH_HDR_LEN;
    let held = &h.frame;
    let (ht, pt) = (h.tcp_off, p.tcp_off);
    // TCP: contiguous sequence; identical header length, flags (but PSH),
    // ACK, window, and option bytes (TSval/TSecr included).
    if p.seq != h.next_seq
        || p.tcp_header_len != h.tcp_header_len
        || (held[ht + 13] ^ p.flags) & !FLAG_PSH != 0
        || held[ht + 8..ht + 12] != frame[pt + 8..pt + 12]
        || held[ht + 14..ht + 16] != frame[pt + 14..pt + 16]
        || held[ht + 20..ht + h.tcp_header_len] != frame[pt + 20..pt + p.tcp_header_len]
    {
        return false;
    }
    // `(len - 1) >= mss`: a segment larger than the flow's MSS starts anew.
    if p.payload_len > h.mss {
        return false;
    }
    // IPv4: TTL, TOS and DF match; the ID is either fixed or increments by
    // one per merged segment.
    let df = |f: &[u8]| u16::from_be_bytes([f[eth + 6], f[eth + 7]]) & IP_DF;
    if held[eth + 8] != frame[eth + 8] || held[eth + 1] != frame[eth + 1] || df(held) != df(frame) {
        return false;
    }
    let fixed = h.fixed_id.unwrap_or(p.ip_id == h.ip_id);
    let expected = if fixed {
        h.ip_id
    } else {
        h.ip_id.wrapping_add(h.segs)
    };
    if p.ip_id != expected {
        return false;
    }
    held.len() - ht - h.tcp_header_len + p.payload_len <= MAX_GRO_BYTES
}

/// Recompute the coalesced frame's IPv4 total-length / header checksum and the
/// TCP checksum, and return `(ingress iface, frame)` for delivery to the stack.
fn finalize(mut h: Held) -> (String, Vec<u8>) {
    if h.segs == 1 {
        // Nothing was merged: deliver the segment exactly as received.
        return (h.iface, h.frame);
    }
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
    (h.iface, h.frame)
}

impl Gro {
    pub const fn new() -> Self {
        Self { held: Vec::new() }
    }

    /// Offer one received frame from ingress interface `iface`. Returns the
    /// `(iface, frame)` pairs the stack should process now (empty when the
    /// frame was merged/held, 1–2 when a held flow is flushed). The caller
    /// dispatches each returned frame to its tagged iface.
    pub fn offer(&mut self, iface: &str, frame: Vec<u8>) -> Vec<(String, Vec<u8>)> {
        let Some(p) = parse_ipv4_tcp(&frame) else {
            // Not an eligible segment: deliver as-is, after any segments held
            // for its flow so the stack still sees the flow in order.
            let mut out = Vec::new();
            if let Some(key) = flow_key_of(&frame) {
                if let Some(i) = self
                    .held
                    .iter()
                    .position(|h| h.key == key && h.iface == iface)
                {
                    out.push(finalize(self.held.remove(i)));
                }
            }
            out.push((String::from(iface), frame));
            return out;
        };
        let held_idx = self
            .held
            .iter()
            .position(|h| h.key == p.key && h.iface == iface);
        // A control/urgent segment, a pure ACK, or one without ACK is never
        // coalesced: it flushes any held flow for its key, then is delivered
        // itself, in order.
        if p.flags & NON_COALESCE_FLAGS != 0 || p.payload_len == 0 || p.flags & FLAG_ACK == 0 {
            let mut out = Vec::new();
            if let Some(i) = held_idx {
                out.push(finalize(self.held.remove(i)));
            }
            out.push((String::from(iface), frame));
            return out;
        }

        if let Some(i) = held_idx {
            if can_merge(&self.held[i], &frame, &p) {
                let data_start = p.tcp_off + p.tcp_header_len;
                let h = &mut self.held[i];
                // `tcp_flag_word(th2) |= flags & (FIN | PSH)`.
                h.frame[h.tcp_off + 13] |= p.flags & FLAG_PSH;
                h.frame.extend_from_slice(&frame[data_start..]);
                h.next_seq = h.next_seq.wrapping_add(p.payload_len as u32);
                if h.segs == 1 {
                    h.fixed_id = Some(p.ip_id == h.ip_id);
                }
                h.segs = h.segs.saturating_add(1);
                // `out_check_final`: a pushed or short segment ends the batch,
                // as does reaching the size ceiling.
                let full = h.frame.len() - h.tcp_off - h.tcp_header_len >= MAX_GRO_BYTES;
                if p.flags & FLAG_PSH != 0 || p.payload_len < h.mss || full {
                    return alloc::vec![finalize(self.held.remove(i))];
                }
                return Vec::new();
            }
            // Mismatch: flush the held flow, then handle this frame as a fresh
            // offer (hold it, unless it is pushed).
            let flushed = finalize(self.held.remove(i));
            let mut out = alloc::vec![flushed];
            out.extend(self.start(iface, frame, p));
            return out;
        }

        self.start(iface, frame, p)
    }

    /// Begin holding a new flow, or deliver immediately when pushed. Evicts the
    /// oldest held flow if the table is full.
    fn start(&mut self, iface: &str, frame: Vec<u8>, p: Parsed) -> Vec<(String, Vec<u8>)> {
        if p.flags & FLAG_PSH != 0 {
            return alloc::vec![(String::from(iface), frame)];
        }
        let mut out = Vec::new();
        if self.held.len() >= MAX_FLOWS {
            out.push(finalize(self.held.remove(0)));
        }
        let next_seq = p.seq.wrapping_add(p.payload_len as u32);
        self.held.push(Held {
            iface: String::from(iface),
            key: p.key,
            frame,
            tcp_off: p.tcp_off,
            tcp_header_len: p.tcp_header_len,
            next_seq,
            segs: 1,
            mss: p.payload_len,
            ip_id: p.ip_id,
            fixed_id: None,
        });
        out
    }

    /// Flush every held flow (call at NAPI-complete / end of a poll burst).
    /// Each returned frame is tagged with the iface it arrived on.
    pub fn flush(&mut self) -> Vec<(String, Vec<u8>)> {
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

    #[allow(clippy::too_many_arguments)]
    fn timestamped_seg(
        src: [u8; 4],
        dst: [u8; 4],
        seq: u32,
        ack: u32,
        window: u16,
        flags: u8,
        tsval: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        const TCP_TS_HEADER_LEN: usize = TCP_HDR_MIN + 12;
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let total = tcp_off + TCP_TS_HEADER_LEN + payload.len();
        let mut frame = alloc::vec![0u8; total];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[ETH_HDR_LEN] = 0x45;
        let ip_total = (IPV4_HDR_LEN + TCP_TS_HEADER_LEN + payload.len()) as u16;
        frame[ETH_HDR_LEN + 2..ETH_HDR_LEN + 4].copy_from_slice(&ip_total.to_be_bytes());
        frame[ETH_HDR_LEN + 9] = IP_PROTO_TCP;
        frame[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&src);
        frame[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20].copy_from_slice(&dst);
        set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
        frame[tcp_off..tcp_off + 2].copy_from_slice(&1111u16.to_be_bytes());
        frame[tcp_off + 2..tcp_off + 4].copy_from_slice(&80u16.to_be_bytes());
        frame[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
        frame[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
        frame[tcp_off + 12] = (TCP_TS_HEADER_LEN as u8 / 4) << 4;
        frame[tcp_off + 13] = flags;
        frame[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());
        frame[tcp_off + 20..tcp_off + 24].copy_from_slice(&[1, 1, 8, 10]);
        frame[tcp_off + 24..tcp_off + 28].copy_from_slice(&tsval.to_be_bytes());
        frame[tcp_off + 28..tcp_off + 32].copy_from_slice(&77u32.to_be_bytes());
        frame[tcp_off + TCP_TS_HEADER_LEN..].copy_from_slice(payload);
        let checksum = ipv4_pseudo_checksum(src, dst, &frame[tcp_off..]);
        frame[tcp_off + 16..tcp_off + 18].copy_from_slice(&checksum.to_be_bytes());
        frame
    }

    fn smoke_gro_ipv4_coalesce() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let mut gro = Gro::new();
        // Two full-size contiguous ACK segments, no PSH: held, nothing
        // delivered.
        if !gro
            .offer("eth0", seg(src, dst, 1000, FLAG_ACK, &[1u8; 100]))
            .is_empty()
            || !gro
                .offer("eth0", seg(src, dst, 1100, FLAG_ACK, &[2u8; 100]))
                .is_empty()
        {
            return TestResult::Fail("coalescable segments were not held");
        }
        if !gro.pending() {
            return TestResult::Fail("GRO reports nothing pending after holding");
        }
        // A short segment (below the flow's MSS) joins and ends the batch
        // (`tcp_gro_receive`: `flush = len < mss`).
        let flushed = gro.offer("eth0", seg(src, dst, 1200, FLAG_ACK, &[3u8; 50]));
        if flushed.len() != 1 || gro.pending() {
            return TestResult::Fail("short segment did not flush one merged frame");
        }
        if flushed[0].0 != "eth0" {
            return TestResult::Fail("flushed frame lost its ingress iface tag");
        }
        let f = &flushed[0].1;
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

    fn smoke_gro_timestamped_ipv4_coalesce() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let mut gro = Gro::new();
        if !gro
            .offer(
                "eth0",
                timestamped_seg(src, dst, 1000, 50, 4096, FLAG_ACK, 10, &[1u8; 100]),
            )
            .is_empty()
        {
            return TestResult::Fail("first timestamped segment was not held");
        }
        // Same ACK, window and timestamps: mergeable. PSH joins, then ends
        // the batch, and is carried on the coalesced header.
        let out = gro.offer(
            "eth0",
            timestamped_seg(
                src,
                dst,
                1100,
                50,
                4096,
                FLAG_ACK | FLAG_PSH,
                10,
                &[2u8; 50],
            ),
        );
        if out.len() != 1 || gro.pending() {
            return TestResult::Fail("timestamped PSH did not flush one coalesced frame");
        }
        let frame = &out[0].1;
        if frame[tcp_off + 12] >> 4 != 8
            || frame[tcp_off + 13] & FLAG_PSH == 0
            || u32::from_be_bytes(frame[tcp_off + 8..tcp_off + 12].try_into().unwrap()) != 50
            || u16::from_be_bytes(frame[tcp_off + 14..tcp_off + 16].try_into().unwrap()) != 4096
            || u32::from_be_bytes(frame[tcp_off + 24..tcp_off + 28].try_into().unwrap()) != 10
        {
            return TestResult::Fail("coalesced frame changed the shared TCP header");
        }
        if frame.len() - tcp_off - 32 != 150 {
            return TestResult::Fail("timestamped coalesced payload length wrong");
        }
        if ipv4_pseudo_checksum(src, dst, &frame[tcp_off..]) != 0 {
            return TestResult::Fail("timestamped coalesced TCP checksum invalid");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_timestamped_ipv4_coalesce);

    fn smoke_gro_malformed_tcp_data_offset_bypasses() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        for words in [1u8, 15] {
            let mut frame = seg(src, dst, 1, FLAG_ACK, &[7u8; 20]);
            frame[tcp_off + 12] = words << 4;
            let mut gro = Gro::new();
            if gro.offer("eth0", frame).len() != 1 || gro.pending() {
                return TestResult::Fail("malformed TCP data offset did not bypass GRO");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_malformed_tcp_data_offset_bypasses);

    fn smoke_gro_flush_conditions() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let mut gro = Gro::new();
        // PSH delivers immediately (not held).
        let out = gro.offer("eth0", seg(src, dst, 1, FLAG_ACK | FLAG_PSH, &[7u8; 20]));
        if out.len() != 1 || gro.pending() {
            return TestResult::Fail("pushed segment should pass straight through");
        }
        // A sequence gap flushes the held flow and starts a new one.
        let _ = gro.offer("eth0", seg(src, dst, 100, FLAG_ACK, &[1u8; 50])); // held
        let gap = gro.offer("eth0", seg(src, dst, 500, FLAG_ACK, &[2u8; 50])); // non-contiguous
        if gap.len() != 1 {
            return TestResult::Fail("sequence gap did not flush the held flow");
        }
        // SYN/FIN/RST are never coalesced and flush any held flow.
        let fin = gro.offer("eth0", seg(src, dst, 550, FLAG_ACK | FLAG_FIN, &[3u8; 10]));
        if fin.len() != 2 {
            return TestResult::Fail("FIN should flush held + deliver itself");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_flush_conditions);

    /// Set IPv4 TTL/ID on a built segment and refresh its header checksum.
    fn with_ip(mut f: Vec<u8>, ttl: u8, id: u16) -> Vec<u8> {
        f[ETH_HDR_LEN + 8] = ttl;
        f[ETH_HDR_LEN + 4..ETH_HDR_LEN + 6].copy_from_slice(&id.to_be_bytes());
        f[ETH_HDR_LEN + 10] = 0;
        f[ETH_HDR_LEN + 11] = 0;
        set_ipv4_checksum(&mut f[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
        f
    }

    /// `tcp_gro_receive` merges only segments whose ACK, window and TCP options
    /// (TSval included) are identical. Linux flushes on any difference instead
    /// of keeping the newest values, so each segment reaches the stack with
    /// the header it was sent with.
    fn smoke_gro_header_mismatch_does_not_merge() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let base = |ack, window, tsval, payload: &[u8], seq| {
            timestamped_seg(src, dst, seq, ack, window, FLAG_ACK, tsval, payload)
        };
        for (what, second) in [
            ("ACK", base(51, 4096, 10, &[2u8; 100], 1100)),
            ("window", base(50, 8192, 10, &[2u8; 100], 1100)),
            ("TSval", base(50, 4096, 11, &[2u8; 100], 1100)),
        ] {
            let mut gro = Gro::new();
            let _ = gro.offer("eth0", base(50, 4096, 10, &[1u8; 100], 1000));
            let out = gro.offer("eth0", second);
            if out.len() != 1 || !gro.pending() {
                return TestResult::Fail(match what {
                    "ACK" => "segments with different ACKs were merged",
                    "window" => "segments with different windows were merged",
                    _ => "segments with different TSvals were merged",
                });
            }
            let flushed = gro.flush();
            if flushed.len() != 1 {
                return TestResult::Fail("mismatched segment was not held as its own flow");
            }
        }
        // Identical header fields do merge.
        let mut gro = Gro::new();
        let _ = gro.offer("eth0", base(50, 4096, 10, &[1u8; 100], 1000));
        if !gro
            .offer("eth0", base(50, 4096, 10, &[2u8; 100], 1100))
            .is_empty()
        {
            return TestResult::Fail("identical timestamped segments were not merged");
        }
        let flushed = gro.flush();
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        if flushed.len() != 1 || flushed[0].1.len() - tcp_off - 32 != 200 {
            return TestResult::Fail("identical timestamped segments lost payload");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_header_mismatch_does_not_merge);

    /// `skb_gro_checksum_validate`: a segment whose TCP checksum fails is never
    /// merged. Merging it would let `finalize` stamp a valid checksum over
    /// corrupted bytes; passing it through lets the stack drop it so the peer
    /// retransmits.
    fn smoke_gro_bad_checksum_passes_through_unchanged() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let mut gro = Gro::new();
        let _ = gro.offer("eth0", seg(src, dst, 1000, FLAG_ACK, &[1u8; 100]));
        let mut corrupt = seg(src, dst, 1100, FLAG_ACK, &[2u8; 100]);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        let out = gro.offer("eth0", corrupt.clone());
        // The held segment goes first (flow order), then the corrupted one
        // exactly as received.
        if out.len() != 2
            || out[0].1.len() != ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_MIN + 100
            || out[1].1 != corrupt
            || gro.pending()
        {
            return TestResult::Fail("a corrupted segment was merged or reordered");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_bad_checksum_passes_through_unchanged);

    /// `inet_gro_receive` flushes when the IPv4 total length disagrees with the
    /// frame (`tot_len != skb_gro_len`): Ethernet padding after a short
    /// datagram must never be appended to the stream as payload.
    fn smoke_gro_padded_frame_is_not_coalesced() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let mut padded = seg(src, dst, 1000, FLAG_ACK, &[1u8; 4]);
        padded.extend_from_slice(&[0u8; 6]);
        let mut gro = Gro::new();
        let out = gro.offer("eth0", padded.clone());
        if out.len() != 1 || out[0].1 != padded || gro.pending() {
            return TestResult::Fail("a padded frame was held for coalescing");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_padded_frame_is_not_coalesced);

    /// The first segment sets the flow's MSS (`gso_size`): a larger segment
    /// starts a new batch, and a shorter one joins and then ends the batch.
    fn smoke_gro_mss_bounds_the_batch() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let mut gro = Gro::new();
        let _ = gro.offer("eth0", seg(src, dst, 1000, FLAG_ACK, &[1u8; 50]));
        let out = gro.offer("eth0", seg(src, dst, 1050, FLAG_ACK, &[2u8; 100]));
        if out.len() != 1 || !gro.pending() {
            return TestResult::Fail("a segment larger than the flow MSS was merged");
        }
        let _ = gro.flush();
        let _ = gro.offer("eth0", seg(src, dst, 2000, FLAG_ACK, &[1u8; 100]));
        let out = gro.offer("eth0", seg(src, dst, 2100, FLAG_ACK, &[2u8; 40]));
        if out.len() != 1 || gro.pending() {
            return TestResult::Fail("a short segment did not end the batch");
        }
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        if out[0].1.len() - tcp_off - TCP_HDR_MIN != 140 {
            return TestResult::Fail("the short segment was not merged before the flush");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_mss_bounds_the_batch);

    /// `inet_gro_flush`: TTL must match, and the IP ID must either stay fixed
    /// or increment by one per segment.
    fn smoke_gro_ipv4_header_rules() -> TestResult {
        let src = [10, 0, 0, 5];
        let dst = [10, 0, 0, 9];
        let s = |seq, ttl, id| with_ip(seg(src, dst, seq, FLAG_ACK, &[1u8; 100]), ttl, id);
        let mut gro = Gro::new();
        let _ = gro.offer("eth0", s(1000, 64, 7));
        if !gro.offer("eth0", s(1100, 64, 8)).is_empty()
            || !gro.offer("eth0", s(1200, 64, 9)).is_empty()
        {
            return TestResult::Fail("incrementing IP IDs did not merge");
        }
        if gro.offer("eth0", s(1300, 64, 42)).len() != 1 {
            return TestResult::Fail("an out-of-pattern IP ID was merged");
        }
        let _ = gro.flush();
        let _ = gro.offer("eth0", s(2000, 64, 7));
        if gro.offer("eth0", s(2100, 63, 8)).len() != 1 {
            return TestResult::Fail("segments with different TTLs were merged");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/gro", smoke_gro_ipv4_header_rules);
}
