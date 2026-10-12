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

use alloc::string::String;
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
    /// Ingress interface the held frames arrived on; a flushed frame is
    /// dispatched back to this iface (the per-CPU table may interleave ifaces
    /// via the busy-wait drain fan-out, so flows are tagged, not assumed).
    iface: String,
    key: FlowKey,
    frame: Vec<u8>,
    tcp_off: usize,
    tcp_header_len: usize,
    timestamp_offset: Option<usize>,
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
    tcp_header_len: usize,
    timestamp_offset: Option<usize>,
    seq: u32,
    flags: u8,
    psh: bool,
    payload_len: usize,
}

/// Return the TCP-relative TSval offset for the one options layout Linux uses
/// on established timestamped flows. Other option sets stay on the ordinary
/// per-segment path until their merge semantics are specified.
fn timestamp_offset(options: &[u8]) -> Option<Option<usize>> {
    if options.is_empty() {
        return Some(None);
    }
    if options.len() == 12 && options[..4] == [1, 1, 8, 10] {
        return Some(Some(24));
    }
    None
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
    if frame.len() < tcp_off + 20 || ip_total < ihl + 20 || eth + ip_total > frame.len() {
        return None;
    }
    let data_off = (frame[tcp_off + 12] >> 4) as usize * 4;
    if !(20..=60).contains(&data_off) || ip_total < ihl + data_off {
        return None;
    }
    let timestamp_offset = timestamp_offset(&frame[tcp_off + 20..tcp_off + data_off])?;
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
        tcp_header_len: data_off,
        timestamp_offset,
        seq: u32::from_be_bytes(frame[tcp_off + 4..tcp_off + 8].try_into().ok()?),
        flags,
        psh: flags & FLAG_PSH != 0,
        payload_len,
    })
}

/// Recompute the coalesced frame's IPv4 total-length / header checksum and the
/// TCP checksum, and return `(ingress iface, frame)` for delivery to the stack.
fn finalize(mut h: Held) -> (String, Vec<u8>) {
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
            // Not an eligible segment: deliver as-is.
            return alloc::vec![(String::from(iface), frame)];
        };
        // A control/urgent segment flushes any held flow for its key, then is
        // delivered itself (never coalesced).
        if p.flags & NON_COALESCE_FLAGS != 0 || p.payload_len == 0 || p.flags & FLAG_ACK == 0 {
            let mut out = Vec::new();
            if let Some(i) = self
                .held
                .iter()
                .position(|h| h.key == p.key && h.iface == iface)
            {
                out.push(finalize(self.held.remove(i)));
            }
            out.push((String::from(iface), frame));
            return out;
        }

        if let Some(i) = self
            .held
            .iter()
            .position(|h| h.key == p.key && h.iface == iface)
        {
            let h = &self.held[i];
            let contiguous = p.seq == h.next_seq;
            let compatible = p.tcp_header_len == h.tcp_header_len
                && p.timestamp_offset == h.timestamp_offset
                && p.flags & !FLAG_PSH == h.frame[h.tcp_off + 13] & !FLAG_PSH;
            let fits =
                h.frame.len() - h.tcp_off - h.tcp_header_len + p.payload_len <= MAX_GRO_BYTES;
            if contiguous && compatible && fits {
                // Merge: append this segment's payload to the held frame.
                let data_start = p.tcp_off + p.tcp_header_len;
                let h = &mut self.held[i];
                // The coalesced segment begins at the first sequence number,
                // but its ACK/window and timestamp state must reflect the
                // newest wire segment in the batch. Preserve PSH when the
                // newest segment uses it to terminate the burst.
                h.frame[h.tcp_off + 8..h.tcp_off + 12]
                    .copy_from_slice(&frame[p.tcp_off + 8..p.tcp_off + 12]);
                h.frame[h.tcp_off + 13] = p.flags;
                h.frame[h.tcp_off + 14..h.tcp_off + 16]
                    .copy_from_slice(&frame[p.tcp_off + 14..p.tcp_off + 16]);
                if h.timestamp_offset.is_some() {
                    h.frame[h.tcp_off + 20..h.tcp_off + h.tcp_header_len]
                        .copy_from_slice(&frame[p.tcp_off + 20..p.tcp_off + p.tcp_header_len]);
                }
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
            out.extend(self.start(iface, frame, p));
            return out;
        }

        self.start(iface, frame, p)
    }

    /// Begin holding a new flow, or deliver immediately when pushed. Evicts the
    /// oldest held flow if the table is full.
    fn start(&mut self, iface: &str, frame: Vec<u8>, p: Parsed) -> Vec<(String, Vec<u8>)> {
        if p.psh {
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
            timestamp_offset: p.timestamp_offset,
            next_seq,
            segs: 1,
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
        // Three contiguous ACK segments, no PSH: all held, nothing delivered.
        if !gro
            .offer("eth0", seg(src, dst, 1000, FLAG_ACK, &[1u8; 100]))
            .is_empty()
            || !gro
                .offer("eth0", seg(src, dst, 1100, FLAG_ACK, &[2u8; 100]))
                .is_empty()
            || !gro
                .offer("eth0", seg(src, dst, 1200, FLAG_ACK, &[3u8; 50]))
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
        let out = gro.offer(
            "eth0",
            timestamped_seg(
                src,
                dst,
                1100,
                60,
                8192,
                FLAG_ACK | FLAG_PSH,
                11,
                &[2u8; 50],
            ),
        );
        if out.len() != 1 || gro.pending() {
            return TestResult::Fail("timestamped PSH did not flush one coalesced frame");
        }
        let frame = &out[0].1;
        if frame[tcp_off + 12] >> 4 != 8
            || frame[tcp_off + 13] & FLAG_PSH == 0
            || u32::from_be_bytes(frame[tcp_off + 8..tcp_off + 12].try_into().unwrap()) != 60
            || u16::from_be_bytes(frame[tcp_off + 14..tcp_off + 16].try_into().unwrap()) != 8192
            || u32::from_be_bytes(frame[tcp_off + 24..tcp_off + 28].try_into().unwrap()) != 11
        {
            return TestResult::Fail("coalesced frame did not retain newest TCP metadata");
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
}
