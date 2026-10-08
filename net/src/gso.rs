//! Software TCP segmentation offload (GSO): split one large "super-frame"
//! (a single TCP segment carrying up to `max_tso_bytes` of payload, as the
//! stack hands to a TSO-capable NIC) into the sequence of MSS-sized wire
//! segments. This is the software fallback a driver without hardware TSO runs
//! on a super-frame, and the reference oracle the TSO path is validated
//! against: `gso(super_frame) == the individually-built wire segments`.
//!
//! Each output segment gets its own IPv4 total-length / identification (for v4)
//! or IPv6 payload-length, its TCP sequence number advanced by the bytes that
//! precede it, PSH/FIN cleared on every segment but the last, and freshly
//! computed L3 (v4) and L4 checksums. Input must be a complete
//! Ethernet+IPv4/IPv6+TCP frame.

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::{ETH_HDR_LEN, IP_PROTO_TCP};
use crate::pkt_tcp::{ipv4_pseudo_checksum, FLAG_FIN, FLAG_PSH};

/// Clear PSH/FIN on a non-final segment; the final segment keeps the original
/// flags (so a pushed/closing super-frame still pushes/closes at its end).
fn segment_flags(base: u8, is_last: bool) -> u8 {
    if is_last {
        base
    } else {
        base & !(FLAG_PSH | FLAG_FIN)
    }
}

/// Split an IPv4 TCP super-frame into MSS-sized wire segments. Returns `None`
/// if the frame is not a well-formed Ethernet/IPv4/TCP frame or `mss == 0`.
/// A frame whose payload already fits in one `mss` is returned unchanged as a
/// single segment.
pub fn segment_ipv4_tcp(frame: &[u8], mss: usize) -> Option<Vec<Vec<u8>>> {
    if mss == 0 || frame.len() < ETH_HDR_LEN + 20 {
        return None;
    }
    let eth = ETH_HDR_LEN;
    if frame[eth] >> 4 != 4 {
        return None;
    }
    let ihl = (frame[eth] & 0x0f) as usize * 4;
    if ihl < 20 || frame[eth + 9] != IP_PROTO_TCP {
        return None;
    }
    let tcp_off = eth + ihl;
    if frame.len() < tcp_off + 20 {
        return None;
    }
    let data_off = (frame[tcp_off + 12] >> 4) as usize * 4;
    let hdr_end = tcp_off + data_off;
    if data_off < 20 || frame.len() < hdr_end {
        return None;
    }
    let payload = &frame[hdr_end..];
    if payload.len() <= mss {
        return Some(alloc::vec![frame.to_vec()]);
    }

    let src_ip: [u8; 4] = frame[eth + 12..eth + 16].try_into().ok()?;
    let dst_ip: [u8; 4] = frame[eth + 16..eth + 20].try_into().ok()?;
    let base_seq = u32::from_be_bytes(frame[tcp_off + 4..tcp_off + 8].try_into().ok()?);
    let base_flags = frame[tcp_off + 13];
    let base_id = u16::from_be_bytes(frame[eth + 4..eth + 6].try_into().ok()?);
    let template = &frame[..hdr_end];

    let mut out = Vec::new();
    let mut off = 0usize;
    let mut idx = 0u16;
    while off < payload.len() {
        let end = (off + mss).min(payload.len());
        let is_last = end == payload.len();
        let chunk = &payload[off..end];
        let mut seg = Vec::with_capacity(hdr_end + chunk.len());
        seg.extend_from_slice(template);
        seg.extend_from_slice(chunk);
        // IPv4: total length, identification, header checksum.
        let ip_total = (ihl + data_off + chunk.len()) as u16;
        seg[eth + 2..eth + 4].copy_from_slice(&ip_total.to_be_bytes());
        seg[eth + 4..eth + 6].copy_from_slice(&base_id.wrapping_add(idx).to_be_bytes());
        seg[eth + 10] = 0;
        seg[eth + 11] = 0;
        crate::pkt::set_ipv4_checksum(&mut seg[eth..eth + ihl]);
        // TCP: sequence, flags, checksum (field zeroed before the sum).
        let seq = base_seq.wrapping_add(off as u32);
        seg[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
        seg[tcp_off + 13] = segment_flags(base_flags, is_last);
        seg[tcp_off + 16] = 0;
        seg[tcp_off + 17] = 0;
        let cs = ipv4_pseudo_checksum(src_ip, dst_ip, &seg[tcp_off..]);
        seg[tcp_off + 16..tcp_off + 18].copy_from_slice(&cs.to_be_bytes());
        out.push(seg);
        off = end;
        idx += 1;
    }
    Some(out)
}

/// Split an IPv6 TCP super-frame into MSS-sized wire segments. Only a frame
/// with no IPv6 extension headers (next-header == TCP) is segmented.
pub fn segment_ipv6_tcp(frame: &[u8], mss: usize) -> Option<Vec<Vec<u8>>> {
    if mss == 0 || frame.len() < ETH_HDR_LEN + 40 {
        return None;
    }
    let eth = ETH_HDR_LEN;
    if frame[eth] >> 4 != 6 || frame[eth + 6] != crate::pkt_ipv6::NEXT_HEADER_TCP {
        return None;
    }
    let tcp_off = eth + 40;
    if frame.len() < tcp_off + 20 {
        return None;
    }
    let data_off = (frame[tcp_off + 12] >> 4) as usize * 4;
    let hdr_end = tcp_off + data_off;
    if data_off < 20 || frame.len() < hdr_end {
        return None;
    }
    let payload = &frame[hdr_end..];
    if payload.len() <= mss {
        return Some(alloc::vec![frame.to_vec()]);
    }

    let src_ip: [u8; 16] = frame[eth + 8..eth + 24].try_into().ok()?;
    let dst_ip: [u8; 16] = frame[eth + 24..eth + 40].try_into().ok()?;
    let base_seq = u32::from_be_bytes(frame[tcp_off + 4..tcp_off + 8].try_into().ok()?);
    let base_flags = frame[tcp_off + 13];
    let template = &frame[..hdr_end];

    let mut out = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let end = (off + mss).min(payload.len());
        let is_last = end == payload.len();
        let chunk = &payload[off..end];
        let mut seg = Vec::with_capacity(hdr_end + chunk.len());
        seg.extend_from_slice(template);
        seg.extend_from_slice(chunk);
        // IPv6 payload length = TCP header + this chunk.
        let plen = (data_off + chunk.len()) as u16;
        seg[eth + 4..eth + 6].copy_from_slice(&plen.to_be_bytes());
        let seq = base_seq.wrapping_add(off as u32);
        seg[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
        seg[tcp_off + 13] = segment_flags(base_flags, is_last);
        seg[tcp_off + 16] = 0;
        seg[tcp_off + 17] = 0;
        let cs = crate::pkt_ipv6::pseudo_checksum(
            src_ip,
            dst_ip,
            crate::pkt_ipv6::NEXT_HEADER_TCP,
            &seg[tcp_off..],
        );
        seg[tcp_off + 16..tcp_off + 18].copy_from_slice(&cs.to_be_bytes());
        out.push(seg);
        off = end;
    }
    Some(out)
}

#[cfg(any(test, feature = "kernel-test"))]
mod gso_tests {
    use super::*;
    use crate::pkt::{ip_checksum, IPV4_HDR_LEN};
    use crate::pkt_tcp::{FLAG_ACK, TCP_HDR_MIN};
    use narf_kernel_test::{kernel_test_in, TestResult};

    // Build a minimal IPv4/TCP super-frame: eth + ipv4 + tcp + payload, with
    // valid L3/L4 checksums (as the stack would hand a TSO NIC).
    fn super_frame_v4(src: [u8; 4], dst: [u8; 4], seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let total = tcp_off + TCP_HDR_MIN + payload.len();
        let mut f = alloc::vec![0u8; total];
        // Ethernet: dst, src, ethertype IPv4.
        f[0..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        // IPv4.
        f[ETH_HDR_LEN] = 0x45;
        let ip_total = (IPV4_HDR_LEN + TCP_HDR_MIN + payload.len()) as u16;
        f[ETH_HDR_LEN + 2..ETH_HDR_LEN + 4].copy_from_slice(&ip_total.to_be_bytes());
        f[ETH_HDR_LEN + 8] = 64; // TTL
        f[ETH_HDR_LEN + 9] = IP_PROTO_TCP;
        f[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&src);
        f[ETH_HDR_LEN + 16..ETH_HDR_LEN + 20].copy_from_slice(&dst);
        crate::pkt::set_ipv4_checksum(&mut f[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
        // TCP.
        f[tcp_off..tcp_off + 2].copy_from_slice(&1234u16.to_be_bytes());
        f[tcp_off + 2..tcp_off + 4].copy_from_slice(&80u16.to_be_bytes());
        f[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
        f[tcp_off + 12] = (TCP_HDR_MIN as u8 / 4) << 4;
        f[tcp_off + 13] = flags;
        f[tcp_off + 14..tcp_off + 16].copy_from_slice(&65535u16.to_be_bytes());
        f[tcp_off + TCP_HDR_MIN..].copy_from_slice(payload);
        let cs = ipv4_pseudo_checksum(src, dst, &f[tcp_off..]);
        f[tcp_off + 16..tcp_off + 18].copy_from_slice(&cs.to_be_bytes());
        f
    }

    fn smoke_gso_ipv4_tcp_segments() -> TestResult {
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let mss = 100usize;
        let mut payload = alloc::vec![0u8; 250];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8;
        }
        let base_seq = 1_000u32;
        let sf = super_frame_v4(src, dst, base_seq, FLAG_ACK | FLAG_PSH, &payload);
        let segs = match segment_ipv4_tcp(&sf, mss) {
            Some(s) => s,
            None => return TestResult::Fail("GSO v4 returned None for a valid frame"),
        };
        // 250 / 100 -> 3 segments (100, 100, 50).
        if segs.len() != 3 {
            return TestResult::Fail("wrong segment count");
        }
        let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let mut reassembled = Vec::new();
        for (i, seg) in segs.iter().enumerate() {
            let is_last = i == segs.len() - 1;
            // L3 checksum valid (sum over header == 0).
            if ip_checksum(&seg[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]) != 0 {
                return TestResult::Fail("segment IPv4 header checksum invalid");
            }
            // L4 checksum valid (pseudo-sum over segment == 0).
            if ipv4_pseudo_checksum(src, dst, &seg[tcp_off..]) != 0 {
                return TestResult::Fail("segment TCP checksum invalid");
            }
            // Sequence contiguous.
            let seq = u32::from_be_bytes(seg[tcp_off + 4..tcp_off + 8].try_into().unwrap());
            if seq != base_seq.wrapping_add(reassembled.len() as u32) {
                return TestResult::Fail("segment sequence not contiguous");
            }
            // PSH only on the last segment; ACK on all.
            let flags = seg[tcp_off + 13];
            if flags & FLAG_ACK == 0 {
                return TestResult::Fail("segment missing ACK");
            }
            if (flags & FLAG_PSH != 0) != is_last {
                return TestResult::Fail("PSH must be set only on the final segment");
            }
            reassembled.extend_from_slice(&seg[tcp_off + TCP_HDR_MIN..]);
        }
        if reassembled != payload {
            return TestResult::Fail("reassembled payload != original");
        }
        // A sub-MSS payload is returned as a single unchanged segment.
        let small = super_frame_v4(src, dst, base_seq, FLAG_ACK, &payload[..50]);
        match segment_ipv4_tcp(&small, mss) {
            Some(s) if s.len() == 1 && s[0] == small => TestResult::Pass,
            _ => TestResult::Fail("sub-MSS frame not returned as a single segment"),
        }
    }
    kernel_test_in!("net/gso", smoke_gso_ipv4_tcp_segments);
}
