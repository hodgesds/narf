//! Packet builders + parsers for the minimal ARP / IPv4 / ICMP
//! stack the kernel uses to be ping-able under QEMU's user-mode
//! network backend.
//!
//! Layouts are spec-direct (no_std structs with `repr(C)`, big-
//! endian wire fields explicitly converted via `to_be` / `from_be`
//! at the boundary). No allocations — everything works against a
//! caller-supplied byte buffer.

// ── Ethernet ────────────────────────────────────────────────────────

pub const ETH_HDR_LEN:    usize = 14;
pub const ETHERTYPE_ARP:  u16   = 0x0806;
pub const ETHERTYPE_IPV4: u16   = 0x0800;

/// Build an Ethernet header at `out[0..14]`. Returns the byte
/// slice extending past the header so callers can write the
/// payload immediately after.
pub fn write_eth_header(
    out: &mut [u8],
    dst:       [u8; 6],
    src:       [u8; 6],
    ethertype: u16,
) -> Option<&mut [u8]> {
    if out.len() < ETH_HDR_LEN { return None; }
    out[0..6].copy_from_slice(&dst);
    out[6..12].copy_from_slice(&src);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    Some(&mut out[ETH_HDR_LEN..])
}

/// Decoded Ethernet header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EthHeader {
    pub dst:       [u8; 6],
    pub src:       [u8; 6],
    pub ethertype: u16,
}

pub fn parse_eth_header(buf: &[u8]) -> Option<(EthHeader, &[u8])> {
    if buf.len() < ETH_HDR_LEN { return None; }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&buf[0..6]);
    src.copy_from_slice(&buf[6..12]);
    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    Some((EthHeader { dst, src, ethertype }, &buf[ETH_HDR_LEN..]))
}

// ── ARP ─────────────────────────────────────────────────────────────

pub const ARP_PAYLOAD_LEN: usize = 28;
pub const ARP_OP_REQUEST:  u16   = 1;
pub const ARP_OP_REPLY:    u16   = 2;

/// Decoded ARP packet (Ethernet + IPv4 only — htype=1, ptype=0x0800).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub op:  u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

pub fn parse_arp(buf: &[u8]) -> Option<ArpPacket> {
    if buf.len() < ARP_PAYLOAD_LEN { return None; }
    let htype = u16::from_be_bytes([buf[0], buf[1]]);
    let ptype = u16::from_be_bytes([buf[2], buf[3]]);
    let hlen = buf[4];
    let plen = buf[5];
    if htype != 1 || ptype != ETHERTYPE_IPV4 || hlen != 6 || plen != 4 {
        return None;
    }
    let op = u16::from_be_bytes([buf[6], buf[7]]);
    let mut sha = [0u8; 6]; sha.copy_from_slice(&buf[8..14]);
    let mut spa = [0u8; 4]; spa.copy_from_slice(&buf[14..18]);
    let mut tha = [0u8; 6]; tha.copy_from_slice(&buf[18..24]);
    let mut tpa = [0u8; 4]; tpa.copy_from_slice(&buf[24..28]);
    Some(ArpPacket { op, sha, spa, tha, tpa })
}

pub fn write_arp(buf: &mut [u8], pkt: &ArpPacket) -> Option<usize> {
    if buf.len() < ARP_PAYLOAD_LEN { return None; }
    buf[0..2].copy_from_slice(&1u16.to_be_bytes());          // htype = Ethernet
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes()); // ptype = IPv4
    buf[4] = 6; buf[5] = 4;                                   // hlen, plen
    buf[6..8].copy_from_slice(&pkt.op.to_be_bytes());
    buf[8..14].copy_from_slice(&pkt.sha);
    buf[14..18].copy_from_slice(&pkt.spa);
    buf[18..24].copy_from_slice(&pkt.tha);
    buf[24..28].copy_from_slice(&pkt.tpa);
    Some(ARP_PAYLOAD_LEN)
}

/// Build a complete ARP request frame (Ethernet header + ARP body)
/// in `out`. Returns the total byte count.
pub fn build_arp_request(
    out: &mut [u8],
    src_mac:    [u8; 6],
    src_ip:     [u8; 4],
    target_ip:  [u8; 4],
) -> Option<usize> {
    let body = write_eth_header(out, [0xFF; 6], src_mac, ETHERTYPE_ARP)?;
    let _ = write_arp(body, &ArpPacket {
        op:  ARP_OP_REQUEST,
        sha: src_mac, spa: src_ip,
        tha: [0; 6],  tpa: target_ip,
    })?;
    Some(ETH_HDR_LEN + ARP_PAYLOAD_LEN)
}

/// Build a complete ARP reply frame (Ethernet + ARP) targeted at
/// the request's sender. Returns the total byte count.
pub fn build_arp_reply(
    out: &mut [u8],
    our_mac: [u8; 6],
    our_ip:  [u8; 4],
    request: &ArpPacket,
) -> Option<usize> {
    let body = write_eth_header(out, request.sha, our_mac, ETHERTYPE_ARP)?;
    let _ = write_arp(body, &ArpPacket {
        op:  ARP_OP_REPLY,
        sha: our_mac,    spa: our_ip,
        tha: request.sha, tpa: request.spa,
    })?;
    Some(ETH_HDR_LEN + ARP_PAYLOAD_LEN)
}

// ── IPv4 ────────────────────────────────────────────────────────────

pub const IPV4_HDR_LEN: usize = 20;
pub const IP_PROTO_ICMP: u8  = 1;
pub const IP_PROTO_UDP:  u8  = 17;
pub const IP_PROTO_TCP:  u8  = 6;

/// Compute the ones-complement IP checksum (RFC 1071).
pub fn ip_checksum(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub total_len: u16,
    pub protocol:  u8,
    pub src_ip:    [u8; 4],
    pub dst_ip:    [u8; 4],
}

pub fn parse_ipv4(buf: &[u8]) -> Option<(Ipv4Header, &[u8])> {
    if buf.len() < IPV4_HDR_LEN { return None; }
    let ver_ihl = buf[0];
    if ver_ihl >> 4 != 4 { return None; }
    let ihl = (ver_ihl & 0xF) as usize * 4;
    if ihl < IPV4_HDR_LEN || buf.len() < ihl { return None; }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]);
    if total_len as usize > buf.len() { return None; }
    let protocol = buf[9];
    let mut src = [0u8; 4]; src.copy_from_slice(&buf[12..16]);
    let mut dst = [0u8; 4]; dst.copy_from_slice(&buf[16..20]);
    Some((
        Ipv4Header { total_len, protocol, src_ip: src, dst_ip: dst },
        &buf[ihl..total_len as usize],
    ))
}

/// Write a 20-byte IPv4 header. Caller fills in the payload after
/// the header window then calls `set_ipv4_checksum` to finalize.
pub fn write_ipv4_header(
    out: &mut [u8],
    total_len:  u16,
    protocol:   u8,
    src_ip:     [u8; 4],
    dst_ip:     [u8; 4],
) -> Option<&mut [u8]> {
    if out.len() < IPV4_HDR_LEN { return None; }
    out[0]  = (4 << 4) | 5;         // ver=4, IHL=5
    out[1]  = 0;                     // ToS = 0
    out[2..4].copy_from_slice(&total_len.to_be_bytes());
    out[4..6].copy_from_slice(&0u16.to_be_bytes());  // ID = 0
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag, frag = 0
    out[8] = 64;                     // TTL
    out[9] = protocol;
    out[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    out[12..16].copy_from_slice(&src_ip);
    out[16..20].copy_from_slice(&dst_ip);
    Some(&mut out[IPV4_HDR_LEN..])
}

/// Compute + install the IPv4 header checksum at `out[0..20]`.
/// Call after the header is fully populated and before sending.
pub fn set_ipv4_checksum(out: &mut [u8]) {
    out[10] = 0; out[11] = 0;
    let cs = ip_checksum(&out[..IPV4_HDR_LEN]);
    out[10..12].copy_from_slice(&cs.to_be_bytes());
}

// ── ICMP echo ───────────────────────────────────────────────────────

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY:   u8 = 0;

/// Decoded ICMP echo header (8 bytes; payload follows).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IcmpEcho {
    pub kind:     u8,   // 8 = request, 0 = reply
    pub code:     u8,
    pub identifier: u16,
    pub seq:      u16,
}

pub fn parse_icmp_echo(buf: &[u8]) -> Option<(IcmpEcho, &[u8])> {
    if buf.len() < 8 { return None; }
    let kind = buf[0];
    let code = buf[1];
    let identifier = u16::from_be_bytes([buf[4], buf[5]]);
    let seq = u16::from_be_bytes([buf[6], buf[7]]);
    Some((IcmpEcho { kind, code, identifier, seq }, &buf[8..]))
}

/// Build a complete ICMP echo-request frame (Ethernet + IPv4 +
/// ICMP, no payload). Returns total byte count.
pub fn build_icmp_echo_request(
    out: &mut [u8],
    src_mac:    [u8; 6],
    dst_mac:    [u8; 6],
    src_ip:     [u8; 4],
    dst_ip:     [u8; 4],
    identifier: u16,
    seq:        u16,
) -> Option<usize> {
    let total = ETH_HDR_LEN + IPV4_HDR_LEN + 8;
    if out.len() < total { return None; }
    let _ = write_eth_header(out, dst_mac, src_mac, ETHERTYPE_IPV4)?;
    {
        let ip_buf = &mut out[ETH_HDR_LEN..];
        let _ = write_ipv4_header(
            ip_buf, (IPV4_HDR_LEN + 8) as u16, IP_PROTO_ICMP,
            src_ip, dst_ip,
        )?;
    }
    {
        let icmp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        out[icmp_off    ] = ICMP_ECHO_REQUEST;
        out[icmp_off + 1] = 0;
        out[icmp_off + 2] = 0; out[icmp_off + 3] = 0;
        out[icmp_off + 4..icmp_off + 6].copy_from_slice(&identifier.to_be_bytes());
        out[icmp_off + 6..icmp_off + 8].copy_from_slice(&seq.to_be_bytes());
        let cs = ip_checksum(&out[icmp_off..icmp_off + 8]);
        out[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());
    }
    set_ipv4_checksum(&mut out[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    Some(total)
}
