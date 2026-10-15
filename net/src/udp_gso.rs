//! UDP generic segmentation offload (`UDP_SEGMENT`, Linux 4.18+): one
//! `sendmsg` hands the stack a payload of several `gso_size`-byte datagrams
//! and the stack emits them as separate UDP datagrams, the last one possibly
//! shorter. QUIC stacks (ngtcp2, quiche, Chromium, Firefox's neqo) batch
//! their ~1200-byte packets this way.
//!
//! Linux builds a single GSO skb and splits it at device transmit
//! (`__udp_gso_segment`); NARF has no deferred-GSO device path, so the send
//! path calls [`segment_v4`] / [`segment_payload`] directly on the finished
//! datagram. The observable result is the same: every segment carries its own
//! IP header (consecutive IP IDs, the DF bit of the whole datagram), UDP
//! length and full checksum.
//!
//! Linux refs: `net/ipv4/udp.c` (`udp_send_skb`, `__udp_cmsg_send`),
//! `net/ipv6/udp.c` (`udp_v6_send_skb`), `net/ipv4/udp_offload.c`
//! (`__udp_gso_segment`), `net/ipv4/af_inet.c` (`inet_gso_segment`'s IP ID
//! numbering), `include/linux/udp.h` (`UDP_MAX_SEGMENTS`).

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::{ip_checksum, IP_PROTO_UDP};
use crate::pkt_udp::UDP_HDR_LEN;

/// `UDP_MAX_SEGMENTS` (`include/linux/udp.h`): at most 128 segments per send.
pub const UDP_MAX_SEGMENTS: usize = 1 << 7;

/// `SOL_UDP` option / cmsg type `UDP_SEGMENT` (`include/uapi/linux/udp.h`).
pub const UDP_SEGMENT: u32 = 103;
/// `SOL_UDP` option / cmsg type `UDP_GRO` (`include/uapi/linux/udp.h`).
pub const UDP_GRO: u32 = 104;

/// Why [`gso_check`] refused a GSO send.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GsoError {
    /// `hlen + min(datalen, gso_size) > cork->fragsize` → -EMSGSIZE (no
    /// `ip_local_error` record: it is `udp_send_skb`'s, not
    /// `__ip_append_data`'s).
    MsgSize,
    /// `datalen > gso_size * UDP_MAX_SEGMENTS`, or the socket transmits
    /// without a UDP checksum (`sk_no_check_tx` / `UDP_NO_CHECK6_TX`) →
    /// -EINVAL.
    Invalid,
}

/// `udp_send_skb` / `udp_v6_send_skb`'s checks for a send with a nonzero
/// `gso_size`, in Linux's order. `net_hlen` is the network header length
/// (`skb_network_header_len`: 20 for IPv4 without options, 40 for IPv6
/// without extension headers), `datalen` the UDP payload length and
/// `fragsize` the cork's `fragsize` (the path MTU the socket sizes by).
///
/// Returns whether the payload is split (`datalen > gso_size`); a payload
/// that fits one segment goes out as an ordinary datagram.
pub fn gso_check(
    net_hlen: usize,
    datalen: usize,
    gso_size: u16,
    fragsize: u32,
    no_check_tx: bool,
) -> Result<bool, GsoError> {
    let gso = gso_size as usize;
    let hlen = net_hlen + UDP_HDR_LEN;
    if hlen + datalen.min(gso) > fragsize as usize {
        return Err(GsoError::MsgSize);
    }
    if datalen > gso * UDP_MAX_SEGMENTS {
        return Err(GsoError::Invalid);
    }
    if no_check_tx {
        return Err(GsoError::Invalid);
    }
    Ok(datalen > gso)
}

/// `__udp_gso_segment` + `inet_gso_segment` in software on a finished
/// Ethernet/IPv4/UDP frame whose IPv4 header starts at `ll` and covers the
/// whole GSO payload. Each output frame repeats the link and IPv4 headers with
/// its own total length, the next IP ID (`id`, `id + 1`, … — Linux never sets
/// `SKB_GSO_TCP_FIXEDID` for UDP) and a fresh header checksum; its UDP header
/// carries the segment length and a full pseudo-header checksum (a computed
/// 0 is sent as 0xFFFF, `CSUM_MANGLED_0`).
pub fn segment_v4(frame: &[u8], ll: usize, gso_size: usize) -> Vec<Vec<u8>> {
    let ihl = usize::from(frame[ll] & 0x0f) * 4;
    let udp_off = ll + ihl;
    let tot_len = usize::from(u16::from_be_bytes([frame[ll + 2], frame[ll + 3]]));
    let end = (ll + tot_len).min(frame.len());
    let payload = &frame[udp_off + UDP_HDR_LEN..end];
    let base_id = u16::from_be_bytes([frame[ll + 4], frame[ll + 5]]);
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&frame[ll + 12..ll + 16]);
    dst.copy_from_slice(&frame[ll + 16..ll + 20]);
    let mut out = Vec::with_capacity(payload.len().div_ceil(gso_size.max(1)));
    for (i, chunk) in payload.chunks(gso_size.max(1)).enumerate() {
        let mut seg = Vec::with_capacity(udp_off + UDP_HDR_LEN + chunk.len());
        seg.extend_from_slice(&frame[..udp_off + UDP_HDR_LEN]);
        seg.extend_from_slice(chunk);
        let ip_len = (ihl + UDP_HDR_LEN + chunk.len()) as u16;
        seg[ll + 2..ll + 4].copy_from_slice(&ip_len.to_be_bytes());
        seg[ll + 4..ll + 6].copy_from_slice(&base_id.wrapping_add(i as u16).to_be_bytes());
        seg[ll + 10..ll + 12].copy_from_slice(&[0, 0]);
        let hcs = ip_checksum(&seg[ll..ll + ihl]);
        seg[ll + 10..ll + 12].copy_from_slice(&hcs.to_be_bytes());
        let udp_len = (UDP_HDR_LEN + chunk.len()) as u16;
        seg[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        seg[udp_off + 6..udp_off + 8].copy_from_slice(&[0, 0]);
        let cs =
            crate::pkt_tcp::ipv4_pseudo_checksum_proto(src, dst, IP_PROTO_UDP, &seg[udp_off..]);
        let cs = if cs == 0 { 0xFFFF } else { cs };
        seg[udp_off + 6..udp_off + 8].copy_from_slice(&cs.to_be_bytes());
        out.push(seg);
    }
    out
}

/// The `gso_size`-byte payload slices a GSO send becomes (the last one
/// shorter when the payload is not a multiple). The receive side of a
/// loopback GSO send to a socket without `UDP_GRO` (`udp_rcv_segment`) and
/// the IPv6 transmit path use this.
pub fn segment_payload(payload: &[u8], gso_size: usize) -> core::slice::Chunks<'_, u8> {
    payload.chunks(gso_size.max(1))
}
