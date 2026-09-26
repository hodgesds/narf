//! Protocol-coverage smokes for `narf-net`.
//!
//! A coverage pass over the crate found whole protocol surfaces with a
//! happy-path test and no malformed-input test, and a few (IPv4 forwarding
//! edge cases, NAT checksum repair, IPv6 fragment reassembly, several TCP
//! states) with neither. These smokes close those gaps. They are grouped
//! per protocol under `net/coverage/<protocol>`.
//!
//! Every parser case follows one shape: a well-formed input decodes (so a
//! parser that rejects everything cannot pass), then each malformed variant
//! — truncated header, bad length, bad checksum, bad version, reserved bits
//! — is rejected WITHOUT panicking. A panic here is a remote kernel panic in
//! the RX path, which is why the IPv4 `total_len < ihl` case exists.
//!
//! State isolation: every smoke that touches process-global state (the
//! interface registry, FIB, ARP cache, TCB table, netfilter, bypass claims,
//! the IPv6 reassembly table) resets it first and uses interface names,
//! subnets and ports no other smoke uses (`cov-*`, 10.0.7x.0/24, 3xxxx).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use ::core::sync::atomic::Ordering;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::pkt::{
    ip_checksum, set_ipv4_checksum, write_eth_header, ETHERTYPE_IPV4, ETH_HDR_LEN, IPV4_HDR_LEN,
    IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
};

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Outbound frames captured from the `cov-*` interfaces. Separate from the
/// capture cells other test modules use, so no cross-module interference.
static COV_TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn cov_send(frame: &[u8]) -> Result<(), ()> {
    COV_TX.lock().push(frame.to_vec());
    Ok(())
}

fn cov_drain() -> Vec<Vec<u8>> {
    core::mem::take(&mut *COV_TX.lock())
}

/// IPv4 packets (Ethernet stripped) from the captured frames.
fn cov_drain_ipv4() -> Vec<Vec<u8>> {
    cov_drain()
        .into_iter()
        .filter(|f| {
            f.len() >= ETH_HDR_LEN + IPV4_HDR_LEN
                && u16::from_be_bytes([f[12], f[13]]) == ETHERTYPE_IPV4
        })
        .map(|f| f[ETH_HDR_LEN..].to_vec())
        .collect()
}

const COV_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x7C, 0x01];
const COV_PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x7C, 0x02];

/// Clean-slate the network stack and bring up one capture interface.
fn cov_reset_iface(iface: &'static str, local_ip: [u8; 4], gateway: [u8; 4]) {
    crate::tcp::core::__reset_for_test();
    crate::route::__reset_for_test();
    crate::arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    crate::bypass::__reset_for_test();
    crate::netfilter::__reset_all_for_test();
    narf_lib::sysctl::ipv4::__reset_for_test();
    crate::ip_forward::__reset_redirect_log_for_test();
    COV_TX.lock().clear();

    crate::iface::register(iface, COV_MAC, cov_send);
    crate::iface::set_iface_ipv4_fields(iface, local_ip, gateway);
    crate::iface::add_addr(iface, local_ip, 24);
    crate::tcp_stack::__arp_insert_legacy(gateway, COV_PEER_MAC);
    crate::arp_cache::insert(iface, gateway, COV_PEER_MAC);
    crate::tcp_stack::__arp_insert_legacy(local_ip, COV_MAC);
    crate::arp_cache::insert(iface, local_ip, COV_MAC);
}

/// Build a bare IPv4 packet (no Ethernet) with a valid header checksum.
/// `options` must be a multiple of 4 bytes; IHL follows from its length.
fn ipv4_packet(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    ttl: u8,
    frag_word: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let ihl = IPV4_HDR_LEN + options.len();
    let total = ihl + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x40 | (ihl / 4) as u8;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    p[6..8].copy_from_slice(&frag_word.to_be_bytes());
    p[8] = ttl;
    p[9] = proto;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[IPV4_HDR_LEN..ihl].copy_from_slice(options);
    p[ihl..].copy_from_slice(payload);
    let cs = ip_checksum(&p[..ihl]);
    p[10..12].copy_from_slice(&cs.to_be_bytes());
    p
}

/// Wrap an IPv4 packet in an Ethernet header addressed to `COV_MAC`.
fn eth_wrap(packet: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; ETH_HDR_LEN + packet.len()];
    write_eth_header(&mut f, COV_MAC, COV_PEER_MAC, ETHERTYPE_IPV4);
    f[ETH_HDR_LEN..].copy_from_slice(packet);
    f
}

/// A UDP datagram (header + payload) with a correct IPv4 pseudo checksum.
fn udp_datagram(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 8 + payload.len()];
    let n = crate::pkt_udp::build_ipv4(&mut d, src, dst, sport, dport, payload).unwrap_or(0);
    d.truncate(n);
    d
}

/// A 20-byte TCP header (+ payload) with a correct IPv4 pseudo checksum.
#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut hdr = crate::pkt_tcp::TcpHeader {
        src_port: sport,
        dst_port: dport,
        sequence: seq,
        acknowledgement: ack,
        header_len: 20,
        flags,
        window: 65535,
        checksum: 0,
        urgent_ptr: 0,
        options: Vec::new(),
    };
    let mut seg = hdr.encode();
    seg.extend_from_slice(payload);
    hdr.checksum = crate::pkt_tcp::ipv4_pseudo_checksum(src, dst, &seg);
    seg[16..18].copy_from_slice(&hdr.checksum.to_be_bytes());
    seg
}

/// True iff the L4 checksum of a TCP/UDP segment verifies against its
/// IPv4 header (IHL-aware).
fn l4_checksum_ok(packet: &[u8]) -> bool {
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    let src = [packet[12], packet[13], packet[14], packet[15]];
    let dst = [packet[16], packet[17], packet[18], packet[19]];
    let l4 = &packet[ihl..];
    match packet[9] {
        IP_PROTO_TCP => crate::pkt_tcp::verify_ipv4(src, dst, l4).is_ok(),
        IP_PROTO_UDP => crate::pkt_udp::verify_ipv4(src, dst, l4).is_ok(),
        _ => true,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Ethernet / L2
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_eth_header_rejects_truncated() -> TestResult {
    use crate::pkt::parse_eth_header;
    let mut f = [0u8; 14];
    write_eth_header(&mut f, [0xFF; 6], COV_MAC, ETHERTYPE_IPV4);
    match parse_eth_header(&f) {
        Some((h, rest)) if h.ethertype == ETHERTYPE_IPV4 && rest.is_empty() => {}
        _ => return TestResult::Fail("well-formed 14-byte Ethernet header rejected"),
    }
    for n in 0..14 {
        if parse_eth_header(&f[..n]).is_some() {
            return TestResult::Fail("Ethernet header shorter than 14 bytes accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/l2", smoke_cov_eth_header_rejects_truncated);

fn smoke_cov_vlan_and_lldp_reject_truncated() -> TestResult {
    use crate::pkt_l2::{iter_tlvs, parse_ttl, VlanTag};
    if VlanTag::decode(&[0x81, 0x00, 0x20]).is_some() || VlanTag::decode(&[]).is_some() {
        return TestResult::Fail("truncated 802.1Q tag accepted");
    }
    // An LLDP TLV header announcing 10 bytes of value with only 2 present.
    // type=5 (System Name) → 7-bit type, 9-bit length: (5 << 9) | 10.
    let hdr = ((5u16 << 9) | 10).to_be_bytes();
    let tlv = [hdr[0], hdr[1], b'a', b'b'];
    match iter_tlvs(&tlv).next() {
        Some(Err(_)) => {}
        _ => return TestResult::Fail("LLDP TLV with length past the buffer accepted"),
    }
    if parse_ttl(&[0x00]).is_ok() {
        return TestResult::Fail("1-byte LLDP TTL body accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/l2", smoke_cov_vlan_and_lldp_reject_truncated);

// ═══════════════════════════════════════════════════════════════════════════
// ARP
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_arp_rejects_truncated_and_bad_lengths() -> TestResult {
    use crate::pkt::{parse_arp, write_arp, ArpPacket, ARP_OP_REQUEST, ARP_PAYLOAD_LEN};
    let mut buf = [0u8; ARP_PAYLOAD_LEN];
    let pkt = ArpPacket {
        op: ARP_OP_REQUEST,
        sha: COV_MAC,
        spa: [10, 0, 70, 1],
        tha: [0; 6],
        tpa: [10, 0, 70, 2],
    };
    let _ = write_arp(&mut buf, &pkt);
    if parse_arp(&buf) != Some(pkt) {
        return TestResult::Fail("well-formed ARP request did not round-trip");
    }
    if parse_arp(&buf[..ARP_PAYLOAD_LEN - 1]).is_some() {
        return TestResult::Fail("27-byte ARP payload accepted");
    }
    // hlen / plen must describe Ethernet + IPv4 (6 / 4).
    let mut bad_hlen = buf;
    bad_hlen[4] = 8;
    let mut bad_plen = buf;
    bad_plen[5] = 16;
    if parse_arp(&bad_hlen).is_some() || parse_arp(&bad_plen).is_some() {
        return TestResult::Fail("ARP with non-Ethernet/IPv4 address lengths accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/arp",
    smoke_cov_arp_rejects_truncated_and_bad_lengths
);

// A malformed ARP frame reaching the RX path must not poison the cache.
fn smoke_cov_arp_rx_ignores_malformed_frame() -> TestResult {
    const IFACE: &str = "cov-arp1";
    cov_reset_iface(IFACE, [10, 0, 70, 15], [10, 0, 70, 2]);
    let spoof_ip = [10, 0, 70, 66];
    let mut frame = vec![0u8; 60];
    let n = crate::pkt::build_arp_request(&mut frame, COV_PEER_MAC, spoof_ip, [10, 0, 70, 15])
        .unwrap_or(0);
    // Break the protocol-address length: the body is no longer IPv4 ARP.
    frame[ETH_HDR_LEN + 5] = 6;
    crate::tcp_stack::rx_handler(IFACE, &mut frame[..n.max(42)]);
    if crate::arp_cache::lookup(IFACE, spoof_ip).is_some() {
        return TestResult::Fail("malformed ARP frame populated the ARP cache");
    }
    if !cov_drain().is_empty() {
        return TestResult::Fail("malformed ARP request was answered");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/arp", smoke_cov_arp_rx_ignores_malformed_frame);

// ═══════════════════════════════════════════════════════════════════════════
// IPv4 parsing
// ═══════════════════════════════════════════════════════════════════════════

// Regression: `total_len < ihl` made `parse_ipv4` slice `buf[ihl..total_len]`
// with start > end — a kernel panic from one crafted frame, reachable from
// the RX path (`handle_ipv4`) and the bypass classifier.
fn smoke_cov_ipv4_total_len_below_ihl_rejected() -> TestResult {
    use crate::pkt::parse_ipv4;
    let good = ipv4_packet(
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        IP_PROTO_UDP,
        64,
        0,
        &[],
        &[0; 8],
    );
    if parse_ipv4(&good).is_none() {
        return TestResult::Fail("well-formed IPv4 packet rejected");
    }
    for total in [0u16, 1, 19] {
        let mut p = good.clone();
        p[2..4].copy_from_slice(&total.to_be_bytes());
        if parse_ipv4(&p).is_some() {
            return TestResult::Fail("IPv4 total length below the header length accepted");
        }
    }
    // Same for a header with options: total 22 < IHL 24.
    let mut opt = ipv4_packet(
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        IP_PROTO_UDP,
        64,
        0,
        &[1, 1, 1, 1],
        &[0; 8],
    );
    opt[2..4].copy_from_slice(&22u16.to_be_bytes());
    if parse_ipv4(&opt).is_some() {
        return TestResult::Fail("IPv4 total length inside the options accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv4",
    smoke_cov_ipv4_total_len_below_ihl_rejected
);

fn smoke_cov_ipv4_rejects_bad_ihl_and_overlong_total() -> TestResult {
    use crate::pkt::parse_ipv4;
    let good = ipv4_packet(
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        IP_PROTO_UDP,
        64,
        0,
        &[],
        &[0; 8],
    );
    for ihl_words in 0u8..5 {
        let mut p = good.clone();
        p[0] = 0x40 | ihl_words;
        if parse_ipv4(&p).is_some() {
            return TestResult::Fail("IPv4 IHL below 5 accepted");
        }
    }
    // IHL=15 (60 bytes) in a 28-byte buffer.
    let mut p = good.clone();
    p[0] = 0x4F;
    if parse_ipv4(&p).is_some() {
        return TestResult::Fail("IPv4 IHL past the end of the buffer accepted");
    }
    // Total length claiming more than was received.
    let mut p = good.clone();
    p[2..4].copy_from_slice(&((good.len() + 1) as u16).to_be_bytes());
    if parse_ipv4(&p).is_some() {
        return TestResult::Fail("IPv4 total length past the buffer accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv4",
    smoke_cov_ipv4_rejects_bad_ihl_and_overlong_total
);

// Link-layer padding past Total Length is not payload, and IP options are
// skipped — the payload starts at IHL*4.
fn smoke_cov_ipv4_options_and_padding_delimit_payload() -> TestResult {
    use crate::pkt::parse_ipv4;
    let mut p = ipv4_packet(
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        IP_PROTO_UDP,
        64,
        0,
        &[1, 1, 1, 0],
        b"payload!",
    );
    p.extend_from_slice(&[0xEE; 10]); // Ethernet minimum-frame padding
    let (hdr, payload) = match parse_ipv4(&p) {
        Some(t) => t,
        None => return TestResult::Fail("IPv4 packet with options + padding rejected"),
    };
    if hdr.total_len != 32 {
        return TestResult::Fail("IPv4 total length misread");
    }
    if payload != b"payload!" {
        return TestResult::Fail("IPv4 payload not delimited by IHL and Total Length");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv4",
    smoke_cov_ipv4_options_and_padding_delimit_payload
);

// ═══════════════════════════════════════════════════════════════════════════
// ICMPv4
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_icmp_error_quote_capped_and_checksummed() -> TestResult {
    use crate::pkt_icmp_extra::{build_time_exceeded, IcmpError, ICMP_ERROR_QUOTE_MAX};
    let big = vec![0x5Au8; 1400];
    let msg = build_time_exceeded(0, &big);
    if msg.len() != 8 + ICMP_ERROR_QUOTE_MAX {
        return TestResult::Fail("ICMP error quote not capped at the RFC 1812 limit");
    }
    let (hdr, quoted) = match IcmpError::decode(&msg) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("built ICMP error does not verify"),
    };
    if hdr.typ != 11 || quoted.len() != ICMP_ERROR_QUOTE_MAX {
        return TestResult::Fail("ICMP error header/quote misdecoded");
    }
    // Any single flipped bit must break the checksum.
    let mut bad = msg.clone();
    bad[20] ^= 0x01;
    if IcmpError::decode(&bad).is_ok() {
        return TestResult::Fail("ICMP error with a corrupted body verified");
    }
    for n in 0..8 {
        if IcmpError::decode(&msg[..n]).is_ok() {
            return TestResult::Fail("ICMP error shorter than 8 bytes accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/icmp",
    smoke_cov_icmp_error_quote_capped_and_checksummed
);

fn smoke_cov_igmp_rejects_truncated() -> TestResult {
    use crate::pkt_icmp_extra::{GroupRecord, IgmpV3Query};
    for n in 0..12 {
        if IgmpV3Query::decode(&vec![0x11u8; n]).is_ok() {
            return TestResult::Fail("IGMPv3 query shorter than 12 bytes accepted");
        }
    }
    for n in 0..8 {
        if GroupRecord::decode(&vec![1u8; n]).is_ok() {
            return TestResult::Fail("IGMPv3 group record shorter than 8 bytes accepted");
        }
    }
    // A record claiming 4 sources with none present.
    let rec = [1u8, 0, 0, 4, 239, 1, 2, 3];
    if GroupRecord::decode(&rec).is_ok() {
        return TestResult::Fail("IGMPv3 group record with missing sources accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/icmp", smoke_cov_igmp_rejects_truncated);

// ═══════════════════════════════════════════════════════════════════════════
// IPv4 forwarding (router path)
// ═══════════════════════════════════════════════════════════════════════════

const FWD_IFACE: &str = "cov-fwd1";
const FWD_LOCAL: [u8; 4] = [10, 0, 71, 15];
const FWD_GW: [u8; 4] = [10, 0, 71, 2];
const FWD_SRC: [u8; 4] = [10, 0, 71, 99];
const FWD_DST: [u8; 4] = [198, 51, 100, 71];

/// A router with forwarding on and ICMP redirects off, so what leaves the
/// interface is only the transit packet and any error the case provokes.
fn fwd_setup() {
    cov_reset_iface(FWD_IFACE, FWD_LOCAL, FWD_GW);
    crate::iface::set_gateway(FWD_IFACE, FWD_GW);
    crate::arp_cache::insert(FWD_IFACE, FWD_SRC, COV_PEER_MAC);
    crate::tcp_stack::__arp_insert_legacy(FWD_SRC, COV_PEER_MAC);
    narf_lib::sysctl::ipv4::set_all_forwarding(true);
    narf_lib::sysctl::ipv4::SEND_REDIRECTS_ALL.store(0, Ordering::Relaxed);
    narf_lib::sysctl::ipv4::set_device_send_redirects(FWD_IFACE, false);
}

fn fwd_teardown() {
    narf_lib::sysctl::ipv4::__reset_for_test();
}

fn fwd_inject(packet: &[u8]) -> Vec<Vec<u8>> {
    cov_drain();
    let mut f = eth_wrap(packet);
    crate::tcp_stack::rx_handler(FWD_IFACE, &mut f);
    cov_drain_ipv4()
}

fn icmp_type_of(pkt: &[u8]) -> Option<u8> {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    (pkt[9] == IP_PROTO_ICMP && pkt.len() > ihl).then(|| pkt[ihl])
}

// RFC 1812 §5.2.2: a router validates the header checksum. The forward path
// recomputes the checksum on the way out, so skipping the check would
// re-emit a corrupted header with a fresh, valid checksum.
fn smoke_cov_fwd_bad_header_checksum_dropped() -> TestResult {
    fwd_setup();
    let udp = udp_datagram(FWD_SRC, FWD_DST, 30001, 30002, b"corrupt");
    let mut p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_UDP, 64, 0, &[], &udp);
    let good_out = fwd_inject(&p);
    p[10] ^= 0x5A;
    let bad_out = fwd_inject(&p);
    fwd_teardown();
    if good_out.len() != 1 {
        return TestResult::Fail("control: valid packet was not forwarded");
    }
    if !bad_out.is_empty() {
        return TestResult::Fail("packet with a bad header checksum was forwarded or answered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_bad_header_checksum_dropped
);

// A short packet in a minimum-size Ethernet frame arrives padded; the pad
// is not part of the datagram and must not be forwarded.
fn smoke_cov_fwd_trims_link_layer_padding() -> TestResult {
    fwd_setup();
    let udp = udp_datagram(FWD_SRC, FWD_DST, 30003, 30004, b"pad");
    let mut p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_UDP, 64, 0, &[], &udp);
    let total = p.len();
    p.extend_from_slice(&[0xEE; 15]);
    let out = fwd_inject(&p);
    fwd_teardown();
    if out.len() != 1 {
        return TestResult::Fail("padded packet was not forwarded");
    }
    if out[0].len() != total {
        return TestResult::Fail("link-layer padding forwarded as part of the datagram");
    }
    if !l4_checksum_ok(&out[0]) {
        return TestResult::Fail("forwarded UDP checksum no longer verifies");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_trims_link_layer_padding
);

// A total length the frame cannot hold is malformed, not forwardable.
fn smoke_cov_fwd_bad_total_length_dropped() -> TestResult {
    fwd_setup();
    let udp = udp_datagram(FWD_SRC, FWD_DST, 30005, 30006, b"len");
    let mut p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_UDP, 64, 0, &[], &udp);
    let claimed = (p.len() + 40) as u16;
    p[2..4].copy_from_slice(&claimed.to_be_bytes());
    set_ipv4_checksum(&mut p);
    let out = fwd_inject(&p);
    fwd_teardown();
    if !out.is_empty() {
        return TestResult::Fail("packet with total length past the frame was forwarded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_bad_total_length_dropped
);

// IP options survive forwarding; TTL and checksum are handled over IHL*4.
fn smoke_cov_fwd_preserves_ip_options() -> TestResult {
    fwd_setup();
    let udp = udp_datagram(FWD_SRC, FWD_DST, 30007, 30008, b"opts");
    let opts = [0x01, 0x01, 0x01, 0x00]; // NOP NOP NOP EOL
    let p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_UDP, 9, 0, &opts, &udp);
    let out = fwd_inject(&p);
    fwd_teardown();
    if out.len() != 1 {
        return TestResult::Fail("packet with IP options was not forwarded");
    }
    let q = &out[0];
    if q[0] != 0x46 || q[20..24] != opts {
        return TestResult::Fail("IP options were not preserved");
    }
    if q[8] != 8 {
        return TestResult::Fail("TTL not decremented on an options packet");
    }
    if ip_checksum(&q[..24]) != 0 {
        return TestResult::Fail("header checksum not repaired over the full IHL");
    }
    if q[24..] != udp[..] {
        return TestResult::Fail("payload after IP options altered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_preserves_ip_options
);

// RFC 1122 §3.2.2: never an ICMP error about an ICMP error. Two routers
// would otherwise bounce errors about errors forever.
fn smoke_cov_fwd_no_icmp_error_about_icmp_error() -> TestResult {
    fwd_setup();
    // Control: an expiring Echo Request IS answered with Time Exceeded.
    let echo = {
        let mut b = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        let cs = ip_checksum(&b);
        b[2..4].copy_from_slice(&cs.to_be_bytes());
        b
    };
    let p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_ICMP, 1, 0, &[], &echo);
    let control = fwd_inject(&p);
    // An expiring Time Exceeded / Dest Unreachable is not.
    let inner = ipv4_packet(FWD_DST, FWD_SRC, IP_PROTO_UDP, 64, 0, &[], &[0; 8]);
    let te = crate::pkt_icmp_extra::build_time_exceeded(0, &inner);
    let p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_ICMP, 1, 0, &[], &te);
    let about_te = fwd_inject(&p);
    let du = crate::pkt_icmp_extra::build_error(3, 3, 0, &inner);
    let p = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_ICMP, 1, 0, &[], &du);
    let about_du = fwd_inject(&p);
    fwd_teardown();
    if !control.iter().any(|q| icmp_type_of(q) == Some(11)) {
        return TestResult::Fail("control: expiring Echo Request got no Time Exceeded");
    }
    if !about_te.is_empty() || !about_du.is_empty() {
        return TestResult::Fail("router sent an ICMP error about an ICMP error");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_no_icmp_error_about_icmp_error
);

// RFC 1812 §4.3.2.7: no ICMP error about a non-initial fragment (one error
// per datagram, not per fragment) or a non-unicast source.
fn smoke_cov_fwd_no_icmp_error_for_fragment_or_multicast_src() -> TestResult {
    fwd_setup();
    let later_frag = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_UDP, 1, 0x0010, &[], &[0; 16]);
    let frag_out = fwd_inject(&later_frag);
    let mcast_src = ipv4_packet([224, 0, 0, 9], FWD_DST, IP_PROTO_UDP, 1, 0, &[], &[0; 8]);
    let mcast_out = fwd_inject(&mcast_src);
    let zero_src = ipv4_packet([0, 0, 0, 0], FWD_DST, IP_PROTO_UDP, 1, 0, &[], &[0; 8]);
    let zero_out = fwd_inject(&zero_src);
    // Control: the first fragment of the same datagram IS reported.
    let first_frag = ipv4_packet(FWD_SRC, FWD_DST, IP_PROTO_UDP, 1, 0x2000, &[], &[0; 16]);
    let first_out = fwd_inject(&first_frag);
    fwd_teardown();
    if !first_out.iter().any(|q| icmp_type_of(q) == Some(11)) {
        return TestResult::Fail("control: expiring first fragment got no Time Exceeded");
    }
    if !frag_out.is_empty() {
        return TestResult::Fail("ICMP error sent about a non-initial fragment");
    }
    if !mcast_out.is_empty() || !zero_out.is_empty() {
        return TestResult::Fail("ICMP error sent to a multicast / unspecified source");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_no_icmp_error_for_fragment_or_multicast_src
);

// Re-fragmenting a packet that is itself a middle fragment: every piece
// keeps MF (the original datagram continues past it) and the offsets
// continue from the inbound offset.
fn smoke_cov_fwd_refragments_middle_fragment() -> TestResult {
    fwd_setup();
    let base_units = 100u16;
    let payload = vec![0xC3u8; 2000];
    let p = ipv4_packet(
        FWD_SRC,
        FWD_DST,
        IP_PROTO_UDP,
        64,
        0x2000 | base_units,
        &[],
        &payload,
    );
    let out = fwd_inject(&p);
    fwd_teardown();
    if out.len() < 2 {
        return TestResult::Fail("oversized middle fragment was not re-fragmented");
    }
    let mut expect_off = base_units as usize * 8;
    let mut total = 0usize;
    for q in &out {
        let word = u16::from_be_bytes([q[6], q[7]]);
        if word & 0x2000 == 0 {
            return TestResult::Fail("piece of a middle fragment lost More Fragments");
        }
        if (word & 0x1FFF) as usize * 8 != expect_off {
            return TestResult::Fail("re-fragment offsets do not continue the inbound offset");
        }
        if ip_checksum(&q[..IPV4_HDR_LEN]) != 0 || q.len() > 1500 {
            return TestResult::Fail("re-fragment header invalid or over MTU");
        }
        let data = q.len() - IPV4_HDR_LEN;
        expect_off += data;
        total += data;
    }
    if total != payload.len() {
        return TestResult::Fail("re-fragments do not cover the inbound payload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ip_forward",
    smoke_cov_fwd_refragments_middle_fragment
);

// ═══════════════════════════════════════════════════════════════════════════
// Netfilter: tuple parsing, filter, NAT
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_nf_tuple_honours_ihl_and_fragments() -> TestResult {
    use crate::netfilter::parse_tuple_ipv4;
    let seg = tcp_segment([10, 0, 72, 5], [192, 0, 2, 1], 4321, 22, 1, 0, 0x02, &[]);
    let p = ipv4_packet(
        [10, 0, 72, 5],
        [192, 0, 2, 1],
        IP_PROTO_TCP,
        64,
        0,
        &[1, 1, 1, 1],
        &seg,
    );
    let t = match parse_tuple_ipv4(&p) {
        Some(t) => t,
        None => return TestResult::Fail("tuple of an options packet not parsed"),
    };
    if t.src_port != 4321 || t.dst_port != 22 {
        return TestResult::Fail("ports read from IP options instead of the TCP header");
    }
    // A later fragment whose payload happens to look like ports 4321 → 22.
    let frag = ipv4_packet(
        [10, 0, 72, 5],
        [192, 0, 2, 1],
        IP_PROTO_TCP,
        64,
        0x0020,
        &[],
        &seg,
    );
    match parse_tuple_ipv4(&frag) {
        Some(t) if t.src_port == 0 && t.dst_port == 0 => {}
        _ => return TestResult::Fail("non-first fragment's payload parsed as ports"),
    }
    let mut bad_ihl = p.clone();
    bad_ihl[0] = 0x43;
    if parse_tuple_ipv4(&bad_ihl).is_some() {
        return TestResult::Fail("tuple parsed from a packet with IHL < 5");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/netfilter",
    smoke_cov_nf_tuple_honours_ihl_and_fragments
);

// A `dport 22 drop` rule must match a packet carrying IP options. Reading
// ports at a fixed offset 20 made the options a firewall bypass.
fn smoke_cov_nf_filter_matches_port_behind_ip_options() -> TestResult {
    use crate::netfilter::filter::{filter_input, nf_table_add};
    use crate::netfilter::rules::Match;
    use crate::netfilter::{HookPoint, PktCtx, Verdict, __reset_all_for_test};
    __reset_all_for_test();
    let m = Match {
        dst_port: Some(22),
        proto: Some(IP_PROTO_TCP),
        ..Match::any()
    };
    nf_table_add("filter", "input", m, Verdict::Drop);
    let seg = tcp_segment([10, 0, 72, 6], [10, 0, 72, 1], 5555, 22, 1, 0, 0x02, &[]);
    let mut plain = ipv4_packet(
        [10, 0, 72, 6],
        [10, 0, 72, 1],
        IP_PROTO_TCP,
        64,
        0,
        &[],
        &seg,
    );
    let mut with_opts = ipv4_packet(
        [10, 0, 72, 6],
        [10, 0, 72, 1],
        IP_PROTO_TCP,
        64,
        0,
        &[1, 1, 1, 1],
        &seg,
    );
    let v_plain = filter_input(&mut PktCtx::new_ipv4(
        HookPoint::LocalIn,
        "cov-nf1",
        "",
        &mut plain,
    ));
    let v_opts = filter_input(&mut PktCtx::new_ipv4(
        HookPoint::LocalIn,
        "cov-nf1",
        "",
        &mut with_opts,
    ));
    __reset_all_for_test();
    if v_plain != Verdict::Drop {
        return TestResult::Fail("control: dport-22 rule did not drop a plain SYN");
    }
    if v_opts != Verdict::Drop {
        return TestResult::Fail("IP options let a SYN to port 22 bypass the drop rule");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/netfilter",
    smoke_cov_nf_filter_matches_port_behind_ip_options
);

fn snat(packet: &mut [u8]) -> crate::netfilter::Verdict {
    use crate::netfilter::{nat::snat_postrouting, HookPoint, PktCtx};
    let mut ctx = PktCtx::new_ipv4(HookPoint::PostRouting, "", "cov-nat0", packet);
    snat_postrouting(&mut ctx)
}

fn dnat(packet: &mut [u8]) {
    use crate::netfilter::{nat::dnat_prerouting, HookPoint, PktCtx};
    let mut ctx = PktCtx::new_ipv4(HookPoint::PreRouting, "cov-nat0", "", packet);
    let _ = dnat_prerouting(&mut ctx);
}

const NAT_INSIDE: [u8; 4] = [10, 0, 73, 5];
const NAT_PUBLIC: [u8; 4] = [203, 0, 113, 73];
const NAT_REMOTE: [u8; 4] = [198, 51, 100, 73];

fn nat_setup() {
    crate::netfilter::__reset_all_for_test();
    crate::netfilter::nat::nat_masquerade_add("cov-nat0", [10, 0, 73, 0], 24, NAT_PUBLIC);
}

// RFC 1624 incremental update must leave every checksum valid — the IP
// header, and the TCP/UDP pseudo-header checksum that covers the rewritten
// address and port — in both directions.
fn smoke_cov_nat_checksums_valid_both_directions() -> TestResult {
    nat_setup();
    let seg = tcp_segment(NAT_INSIDE, NAT_REMOTE, 40001, 443, 7, 0, 0x02, b"hello");
    let mut out = ipv4_packet(NAT_INSIDE, NAT_REMOTE, IP_PROTO_TCP, 64, 0, &[], &seg);
    let _ = snat(&mut out);
    let udp = udp_datagram(NAT_INSIDE, NAT_REMOTE, 40002, 53, b"query");
    let mut out_udp = ipv4_packet(NAT_INSIDE, NAT_REMOTE, IP_PROTO_UDP, 64, 0, &[], &udp);
    let _ = snat(&mut out_udp);
    let nat_port = u16::from_be_bytes([out[20], out[21]]);
    let reply_seg = tcp_segment(NAT_REMOTE, NAT_PUBLIC, 443, nat_port, 9, 8, 0x12, b"world");
    let mut reply = ipv4_packet(NAT_REMOTE, NAT_PUBLIC, IP_PROTO_TCP, 64, 0, &[], &reply_seg);
    dnat(&mut reply);
    crate::netfilter::__reset_all_for_test();
    if out[12..16] != NAT_PUBLIC || out_udp[12..16] != NAT_PUBLIC {
        return TestResult::Fail("egress source not masqueraded");
    }
    if ip_checksum(&out[..20]) != 0 || ip_checksum(&out_udp[..20]) != 0 {
        return TestResult::Fail("IP header checksum invalid after SNAT");
    }
    if !l4_checksum_ok(&out) {
        return TestResult::Fail("TCP checksum invalid after SNAT");
    }
    if !l4_checksum_ok(&out_udp) {
        return TestResult::Fail("UDP checksum invalid after SNAT");
    }
    if reply[16..20] != NAT_INSIDE || u16::from_be_bytes([reply[22], reply[23]]) != 40001 {
        return TestResult::Fail("reply not reverse-translated");
    }
    if ip_checksum(&reply[..20]) != 0 || !l4_checksum_ok(&reply) {
        return TestResult::Fail("checksums invalid after reverse NAT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/nat",
    smoke_cov_nat_checksums_valid_both_directions
);

// RFC 768: UDP checksum 0 means "none", so a computed 0 is sent as 0xFFFF.
// Build a datagram whose checksum becomes exactly 0 after the rewrite and
// check the NAT stores 0xFFFF rather than switching checksumming off.
fn smoke_cov_nat_udp_zero_checksum_sent_as_ffff() -> TestResult {
    nat_setup();
    // The rewrite changes only the source address (port 40010 is free and
    // preserved). Find the payload word that makes the POST-rewrite checksum
    // zero: build the datagram as it will look after NAT, with the payload
    // word 0, and solve for the one's-complement sum reaching 0xFFFF.
    let sport = 40010u16;
    let mut probe = udp_datagram(NAT_PUBLIC, NAT_REMOTE, sport, 5353, &[0, 0]);
    probe[6] = 0;
    probe[7] = 0;
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&NAT_PUBLIC);
    pseudo.extend_from_slice(&NAT_REMOTE);
    pseudo.extend_from_slice(&[0, IP_PROTO_UDP]);
    pseudo.extend_from_slice(&(probe.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&probe);
    // ip_checksum returns !sum; sum + w must fold to 0xFFFF → w = !sum... in
    // one's complement, w = 0xFFFF - sum = ip_checksum(pseudo).
    let w = ip_checksum(&pseudo);
    let payload = w.to_be_bytes();
    let udp = udp_datagram(NAT_INSIDE, NAT_REMOTE, sport, 5353, &payload);
    let mut p = ipv4_packet(NAT_INSIDE, NAT_REMOTE, IP_PROTO_UDP, 64, 0, &[], &udp);
    let _ = snat(&mut p);
    crate::netfilter::__reset_all_for_test();
    if p[12..16] != NAT_PUBLIC || u16::from_be_bytes([p[20], p[21]]) != sport {
        return TestResult::Fail("setup: SNAT did not rewrite as expected");
    }
    let cs = u16::from_be_bytes([p[26], p[27]]);
    if cs == 0 {
        return TestResult::Fail("SNAT stored a zero UDP checksum, disabling it");
    }
    if cs != 0xFFFF || !l4_checksum_ok(&p) {
        return TestResult::Fail("UDP checksum after SNAT is not the 0xFFFF encoding of zero");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/nat",
    smoke_cov_nat_udp_zero_checksum_sent_as_ffff
);

// With IP options the TCP header starts at IHL*4. The rewrite must patch
// the real port and checksum, not bytes inside the options.
fn smoke_cov_nat_rewrites_behind_ip_options() -> TestResult {
    nat_setup();
    let seg = tcp_segment(NAT_INSIDE, NAT_REMOTE, 40020, 80, 1, 0, 0x02, &[]);
    let opts = [0x01, 0x01, 0x01, 0x00];
    let mut p = ipv4_packet(NAT_INSIDE, NAT_REMOTE, IP_PROTO_TCP, 64, 0, &opts, &seg);
    let _ = snat(&mut p);
    crate::netfilter::__reset_all_for_test();
    if p[20..24] != opts {
        return TestResult::Fail("NAT rewrite corrupted the IP options");
    }
    if p[12..16] != NAT_PUBLIC {
        return TestResult::Fail("source address not rewritten");
    }
    if ip_checksum(&p[..24]) != 0 || !l4_checksum_ok(&p) {
        return TestResult::Fail("checksums invalid after NAT of an options packet");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/nat", smoke_cov_nat_rewrites_behind_ip_options);

// A non-first fragment has no L4 header: NAT may rewrite its addresses but
// must not touch its payload bytes.
fn smoke_cov_nat_leaves_fragment_payload_intact() -> TestResult {
    nat_setup();
    let payload: Vec<u8> = (0u8..32).collect();
    let mut p = ipv4_packet(
        NAT_INSIDE,
        NAT_REMOTE,
        IP_PROTO_UDP,
        64,
        0x0040,
        &[],
        &payload,
    );
    let _ = snat(&mut p);
    crate::netfilter::__reset_all_for_test();
    if p[12..16] != NAT_PUBLIC {
        return TestResult::Fail("later fragment's source not masqueraded");
    }
    if ip_checksum(&p[..20]) != 0 {
        return TestResult::Fail("IP header checksum invalid after fragment SNAT");
    }
    if p[20..] != payload[..] {
        return TestResult::Fail("NAT rewrote payload bytes of a non-first fragment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/nat",
    smoke_cov_nat_leaves_fragment_payload_intact
);

// Only sources inside the masquerade CIDR are translated.
fn smoke_cov_nat_skips_source_outside_rule() -> TestResult {
    nat_setup();
    let outside = [10, 0, 74, 5];
    let seg = tcp_segment(outside, NAT_REMOTE, 40030, 80, 1, 0, 0x02, &[]);
    let mut p = ipv4_packet(outside, NAT_REMOTE, IP_PROTO_TCP, 64, 0, &[], &seg);
    let before = p.clone();
    let v = snat(&mut p);
    crate::netfilter::__reset_all_for_test();
    if v != crate::netfilter::Verdict::Accept {
        return TestResult::Fail("non-matching packet not accepted");
    }
    if p != before {
        return TestResult::Fail("packet outside the masquerade CIDR was rewritten");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/nat", smoke_cov_nat_skips_source_outside_rule);

// ═══════════════════════════════════════════════════════════════════════════
// Kernel-bypass classifier
// ═══════════════════════════════════════════════════════════════════════════

fn bypass_iface(name: &'static str) {
    narf_scheduler::__reset_queues_for_test();
    if crate::registry().with_interface(name, |_| ()).is_none() {
        let authority = crate::bootstrap_authority();
        let _ = crate::register_loopback_named(&authority, name);
    }
    crate::iface::register(name, [0x02, 0, 0, 0, 0x7C, 0xAA], |_b| Ok(()));
}

/// Claim every TCP flow to 10.0.75.1 (any port) with a fresh socket whose
/// FILL ring holds one frame. Returns the socket parts, or `None` when the
/// environment has no DMA memory for a UMEM.
fn bypass_claim_wildcard(
    dst_port: u16,
    fill: bool,
    frame_size: u32,
) -> Option<crate::bypass::XdpSocketParts> {
    let umem = crate::bypass::Umem::register(frame_size * 2, frame_size).ok()?;
    let mut parts = crate::bypass::XdpSocket::create(umem);
    if fill {
        let _ = parts.fill_prod.try_send(
            crate::bypass::UmemSlot {
                frame_idx: 0,
                len: 0,
            }
            .pack(),
        );
    }
    let key = crate::bypass::FlowKey {
        src_ip: [0; 4],
        src_port: 0,
        dst_ip: [10, 0, 75, 1],
        dst_port,
        proto: IP_PROTO_TCP,
    };
    crate::bypass::register_flow(key, parts.socket.clone()).ok()?;
    Some(parts)
}

fn bypass_frame(frag_word: u16, payload: &[u8]) -> Vec<u8> {
    eth_wrap(&ipv4_packet(
        [10, 0, 75, 9],
        [10, 0, 75, 1],
        IP_PROTO_TCP,
        64,
        frag_word,
        &[],
        payload,
    ))
}

// Malformed frames fall through to the kernel stack, never panic, never
// get staged into a UMEM.
fn smoke_cov_bypass_malformed_frames_pass_through() -> TestResult {
    use crate::bypass::{classify, Verdict};
    crate::bypass::__reset_for_test();
    bypass_iface("lo.cov-byp1");
    let _parts = match bypass_claim_wildcard(0, true, 2048) {
        Some(p) => p,
        None => return TestResult::Skip("Umem::register NoMemory (no DMA in test env)"),
    };
    let seg = tcp_segment([10, 0, 75, 9], [10, 0, 75, 1], 1111, 80, 1, 0, 0x02, &[]);
    // total_len < ihl — the frame that used to panic parse_ipv4.
    let mut f = bypass_frame(0, &seg);
    f[ETH_HDR_LEN + 2] = 0;
    f[ETH_HDR_LEN + 3] = 4;
    let v1 = classify("lo.cov-byp1", &mut f).0;
    // Runt: shorter than an Ethernet header.
    let mut runt = vec![0u8; 10];
    let v2 = classify("lo.cov-byp1", &mut runt).0;
    // Not IPv4 at all.
    let mut arp = vec![0u8; 42];
    let _ = crate::pkt::build_arp_request(&mut arp, COV_PEER_MAC, [10, 0, 75, 9], [10, 0, 75, 1]);
    let v3 = classify("lo.cov-byp1", &mut arp).0;
    crate::bypass::__reset_for_test();
    if !matches!(v1, Verdict::PassThrough) {
        return TestResult::Fail("IPv4 frame with total_len < ihl was claimed");
    }
    if !matches!(v2, Verdict::PassThrough) || !matches!(v3, Verdict::PassThrough) {
        return TestResult::Fail("runt / non-IPv4 frame was claimed by an IPv4 flow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/bypass",
    smoke_cov_bypass_malformed_frames_pass_through
);

// A non-first fragment has no ports; crafted payload bytes must not steer it
// into a port-specific claim.
fn smoke_cov_bypass_later_fragment_not_port_matched() -> TestResult {
    use crate::bypass::{classify, Verdict};
    crate::bypass::__reset_for_test();
    bypass_iface("lo.cov-byp2");
    let _parts = match bypass_claim_wildcard(8080, true, 2048) {
        Some(p) => p,
        None => return TestResult::Skip("Umem::register NoMemory (no DMA in test env)"),
    };
    // Payload whose first 4 bytes read as ports 1111 → 8080.
    let mut fake = vec![0u8; 16];
    fake[0..2].copy_from_slice(&1111u16.to_be_bytes());
    fake[2..4].copy_from_slice(&8080u16.to_be_bytes());
    let mut first = bypass_frame(0x2000, &fake);
    let v_first = classify("lo.cov-byp2", &mut first).0;
    let mut later = bypass_frame(0x0010, &fake);
    let v_later = classify("lo.cov-byp2", &mut later).0;
    crate::bypass::__reset_for_test();
    if !matches!(v_first, Verdict::Consumed) {
        return TestResult::Fail("control: first fragment with matching ports not claimed");
    }
    // PassThrough, not merely "not Consumed": the FILL ring is empty now, so
    // a wrongly-matched fragment would come back Dropped.
    if !matches!(v_later, Verdict::PassThrough) {
        return TestResult::Fail("non-first fragment claimed via payload bytes read as ports");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/bypass",
    smoke_cov_bypass_later_fragment_not_port_matched
);

// Resource exhaustion drops rather than overruns: an empty FILL ring, or a
// frame larger than one UMEM chunk.
fn smoke_cov_bypass_empty_fill_or_oversize_drops() -> TestResult {
    use crate::bypass::{classify, Verdict};
    crate::bypass::__reset_for_test();
    bypass_iface("lo.cov-byp3");
    let _parts = match bypass_claim_wildcard(0, false, 2048) {
        Some(p) => p,
        None => return TestResult::Skip("Umem::register NoMemory (no DMA in test env)"),
    };
    let seg = tcp_segment([10, 0, 75, 9], [10, 0, 75, 1], 1111, 80, 1, 0, 0x02, &[]);
    let mut f = bypass_frame(0, &seg);
    let v_empty = classify("lo.cov-byp3", &mut f).0;
    crate::bypass::__reset_for_test();

    let _parts = match bypass_claim_wildcard(0, true, 2048) {
        Some(p) => p,
        None => return TestResult::Skip("Umem::register NoMemory (no DMA in test env)"),
    };
    let big_seg = tcp_segment(
        [10, 0, 75, 9],
        [10, 0, 75, 1],
        1111,
        80,
        1,
        0,
        0x18,
        &[0u8; 2100],
    );
    let mut big = bypass_frame(0, &big_seg);
    let v_big = classify("lo.cov-byp3", &mut big).0;
    crate::bypass::__reset_for_test();
    if !matches!(v_empty, Verdict::Dropped) {
        return TestResult::Fail("claimed frame with an empty FILL ring was not dropped");
    }
    if !matches!(v_big, Verdict::Dropped) {
        return TestResult::Fail("frame larger than a UMEM chunk was not dropped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/bypass",
    smoke_cov_bypass_empty_fill_or_oversize_drops
);

fn smoke_cov_bypass_unregister_releases_flow() -> TestResult {
    use crate::bypass::{classify, Verdict};
    crate::bypass::__reset_for_test();
    bypass_iface("lo.cov-byp4");
    let umem = match crate::bypass::Umem::register(4096, 2048) {
        Ok(u) => u,
        Err(_) => return TestResult::Skip("Umem::register NoMemory (no DMA in test env)"),
    };
    let parts = crate::bypass::XdpSocket::create(umem);
    let key = crate::bypass::FlowKey {
        src_ip: [0; 4],
        src_port: 0,
        dst_ip: [10, 0, 75, 1],
        dst_port: 0,
        proto: IP_PROTO_TCP,
    };
    let seq = match crate::bypass::register_flow(key, parts.socket.clone()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("register_flow failed"),
    };
    crate::bypass::unregister_flow(seq);
    let seg = tcp_segment([10, 0, 75, 9], [10, 0, 75, 1], 1111, 80, 1, 0, 0x02, &[]);
    let mut f = bypass_frame(0, &seg);
    let v = classify("lo.cov-byp4", &mut f).0;
    let left = crate::bypass::classifier::flow_count();
    crate::bypass::__reset_for_test();
    if left != 0 {
        return TestResult::Fail("unregistered claim still in the flow table");
    }
    if !matches!(v, Verdict::PassThrough) {
        return TestResult::Fail("traffic still claimed after unregister_flow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/bypass",
    smoke_cov_bypass_unregister_releases_flow
);

// ═══════════════════════════════════════════════════════════════════════════
// IPv6 header + extension headers
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_ipv6_header_rejects_truncated_and_bad_version() -> TestResult {
    use crate::pkt_ipv6::{Ipv6Header, NEXT_HEADER_UDP};
    let h = Ipv6Header {
        version: 6,
        payload_length: 8,
        next_header: NEXT_HEADER_UDP,
        hop_limit: 64,
        ..Default::default()
    };
    let enc = h.encode();
    if Ipv6Header::decode(&enc).map(|d| d.payload_length) != Ok(8) {
        return TestResult::Fail("well-formed IPv6 header rejected");
    }
    for n in [0usize, 1, 20, 39] {
        if Ipv6Header::decode(&enc[..n]).is_ok() {
            return TestResult::Fail("IPv6 header shorter than 40 bytes accepted");
        }
    }
    for v in [0u8, 5, 7, 15] {
        let mut b = enc;
        b[0] = (v << 4) | (b[0] & 0x0F);
        if Ipv6Header::decode(&b).is_ok() {
            return TestResult::Fail("IPv6 header with version != 6 accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6",
    smoke_cov_ipv6_header_rejects_truncated_and_bad_version
);

fn smoke_cov_ipv6_ext_header_chain_rejects_malformed() -> TestResult {
    use crate::ipv6_stack::skip_extension_headers;
    use crate::pkt_ipv6::{
        NEXT_HEADER_DESTINATION_OPTIONS, NEXT_HEADER_FRAGMENT, NEXT_HEADER_HBH, NEXT_HEADER_UDP,
    };
    // HBH (8 bytes) → Dest Opts (16 bytes) → UDP.
    let mut chain = vec![0u8; 24 + 8];
    chain[0] = NEXT_HEADER_DESTINATION_OPTIONS;
    chain[1] = 0;
    chain[8] = NEXT_HEADER_UDP;
    chain[9] = 1;
    match skip_extension_headers(NEXT_HEADER_HBH, &chain) {
        Some(l4) if l4.proto == NEXT_HEADER_UDP && l4.offset == 24 => {}
        _ => return TestResult::Fail("well-formed HBH → DestOpts → UDP chain misparsed"),
    }
    // Hdr Ext Len pointing past the buffer.
    let mut over = chain.clone();
    over[9] = 200;
    if skip_extension_headers(NEXT_HEADER_HBH, &over).is_some() {
        return TestResult::Fail("extension header longer than the packet accepted");
    }
    // Truncated in the middle of an extension header's fixed part.
    if skip_extension_headers(NEXT_HEADER_HBH, &chain[..1]).is_some()
        || skip_extension_headers(NEXT_HEADER_FRAGMENT, &chain[..7]).is_some()
    {
        return TestResult::Fail("truncated extension header accepted");
    }
    // Unknown next header / No Next Header (59).
    if skip_extension_headers(59, &chain).is_some()
        || skip_extension_headers(0xFD, &chain).is_some()
    {
        return TestResult::Fail("unknown next-header value accepted as L4");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6",
    smoke_cov_ipv6_ext_header_chain_rejects_malformed
);

// ═══════════════════════════════════════════════════════════════════════════
// IPv6 fragment reassembly (RFC 8200 §4.5, RFC 5722)
// ═══════════════════════════════════════════════════════════════════════════

fn frag_hdr(offset_bytes: u16, more: bool, id: u32) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0] = crate::pkt_ipv6::NEXT_HEADER_UDP;
    let word = (offset_bytes & 0xFFF8) | more as u16;
    h[2..4].copy_from_slice(&word.to_be_bytes());
    h[4..8].copy_from_slice(&id.to_be_bytes());
    h
}

fn v6(last: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = 0x0D;
    a[3] = 0xB8;
    a[15] = last;
    a
}

fn smoke_cov_ipv6_frag_out_of_order_completes() -> TestResult {
    use crate::ipv6_stack::{__reset_for_test, process_fragment_at};
    __reset_for_test();
    let (s, d) = (v6(1), v6(2));
    let a = [0xAAu8; 16];
    let b = [0xBBu8; 8];
    let c = [0xCCu8; 5];
    let r1 = process_fragment_at(1, s, d, &frag_hdr(24, false, 71), &c);
    let r2 = process_fragment_at(2, s, d, &frag_hdr(0, true, 71), &a);
    let r3 = process_fragment_at(3, s, d, &frag_hdr(16, true, 71), &b);
    __reset_for_test();
    if r1.is_some() || r2.is_some() {
        return TestResult::Fail("reassembly completed with a hole");
    }
    let (_, body) = match r3 {
        Some(t) => t,
        None => return TestResult::Fail("out-of-order fragments did not reassemble"),
    };
    if body.len() != 29 || body[..16] != a || body[16..24] != b || body[24..] != c {
        return TestResult::Fail("out-of-order reassembly produced the wrong bytes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6_frag",
    smoke_cov_ipv6_frag_out_of_order_completes
);

// RFC 5722: an overlapping fragment abandons the whole datagram — the
// defence against overlapping-fragment filter evasion.
fn smoke_cov_ipv6_frag_overlap_abandons_datagram() -> TestResult {
    use crate::ipv6_stack::{__reset_for_test, process_fragment_at};
    __reset_for_test();
    let (s, d) = (v6(3), v6(4));
    let _ = process_fragment_at(1, s, d, &frag_hdr(0, true, 72), &[1u8; 16]);
    // Overlaps bytes 8..16 of the first piece with different content.
    let _ = process_fragment_at(2, s, d, &frag_hdr(8, true, 72), &[2u8; 16]);
    // Completing pieces for BOTH interpretations: neither may complete.
    let r1 = process_fragment_at(3, s, d, &frag_hdr(16, false, 72), &[3u8; 8]);
    let r2 = process_fragment_at(4, s, d, &frag_hdr(24, false, 72), &[3u8; 8]);
    __reset_for_test();
    if r1.is_some() || r2.is_some() {
        return TestResult::Fail("datagram with overlapping fragments was reassembled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6_frag",
    smoke_cov_ipv6_frag_overlap_abandons_datagram
);

// RFC 8200 §4.5 allows dropping an exact duplicate while keeping the rest.
fn smoke_cov_ipv6_frag_exact_duplicate_tolerated() -> TestResult {
    use crate::ipv6_stack::{__reset_for_test, process_fragment_at};
    __reset_for_test();
    let (s, d) = (v6(5), v6(6));
    let _ = process_fragment_at(1, s, d, &frag_hdr(0, true, 73), &[7u8; 8]);
    let dup = process_fragment_at(2, s, d, &frag_hdr(0, true, 73), &[7u8; 8]);
    let done = process_fragment_at(3, s, d, &frag_hdr(8, false, 73), &[8u8; 3]);
    __reset_for_test();
    if dup.is_some() {
        return TestResult::Fail("duplicate first fragment completed a datagram");
    }
    match done {
        Some((_, body)) if body.len() == 11 => TestResult::Pass,
        _ => TestResult::Fail("exact duplicate fragment broke reassembly"),
    }
}
kernel_test_in!(
    "net/coverage/ipv6_frag",
    smoke_cov_ipv6_frag_exact_duplicate_tolerated
);

fn smoke_cov_ipv6_frag_rejects_bad_lengths() -> TestResult {
    use crate::ipv6_stack::{__reset_for_test, process_fragment_at};
    __reset_for_test();
    let (s, d) = (v6(7), v6(8));
    // Non-final fragment whose length is not a multiple of 8.
    let _ = process_fragment_at(1, s, d, &frag_hdr(0, true, 74), &[1u8; 12]);
    let odd = process_fragment_at(2, s, d, &frag_hdr(12 & 0xFFF8, false, 74), &[1u8; 4]);
    // offset + length > 65535 (would also overflow the u16 arithmetic).
    let huge = process_fragment_at(3, s, d, &frag_hdr(65528, false, 75), &[0u8; 16]);
    // Truncated fragment header.
    let short = process_fragment_at(4, s, d, &[0u8; 7], &[0u8; 8]);
    __reset_for_test();
    if odd.is_some() {
        return TestResult::Fail("non-final fragment with a non-multiple-of-8 length accepted");
    }
    if huge.is_some() || short.is_some() {
        return TestResult::Fail("oversized or truncated fragment accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6_frag",
    smoke_cov_ipv6_frag_rejects_bad_lengths
);

// Two "last" fragments disagreeing about the datagram's end cannot both be
// right; the datagram is abandoned instead of stitched from either.
fn smoke_cov_ipv6_frag_inconsistent_end_abandons() -> TestResult {
    use crate::ipv6_stack::{__reset_for_test, process_fragment_at};
    __reset_for_test();
    let (s, d) = (v6(9), v6(10));
    let _ = process_fragment_at(1, s, d, &frag_hdr(16, false, 76), &[1u8; 8]);
    let _ = process_fragment_at(2, s, d, &frag_hdr(8, false, 76), &[2u8; 4]);
    let r = process_fragment_at(3, s, d, &frag_hdr(0, true, 76), &[3u8; 8]);
    let r2 = process_fragment_at(4, s, d, &frag_hdr(8, true, 76), &[3u8; 8]);
    __reset_for_test();
    if r.is_some() || r2.is_some() {
        return TestResult::Fail("datagram with two conflicting final fragments reassembled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6_frag",
    smoke_cov_ipv6_frag_inconsistent_end_abandons
);

// RFC 8200 §4.5: reassembly not done within 60 s of the first fragment is
// abandoned — otherwise a never-completed datagram pins memory forever.
fn smoke_cov_ipv6_frag_reassembly_times_out() -> TestResult {
    use crate::ipv6_stack::{__reset_for_test, process_fragment_at, FRAG_REASSEMBLY_TIMEOUT_NS};
    __reset_for_test();
    let (s, d) = (v6(11), v6(12));
    let t0 = 1_000_000_000u64;
    let _ = process_fragment_at(t0, s, d, &frag_hdr(0, true, 77), &[1u8; 8]);
    let late = t0 + FRAG_REASSEMBLY_TIMEOUT_NS + 1;
    let r = process_fragment_at(late, s, d, &frag_hdr(8, false, 77), &[2u8; 8]);
    // Control: the same two fragments inside the window DO reassemble.
    let _ = process_fragment_at(t0, s, d, &frag_hdr(0, true, 78), &[1u8; 8]);
    let ok = process_fragment_at(t0 + 1_000, s, d, &frag_hdr(8, false, 78), &[2u8; 8]);
    __reset_for_test();
    if r.is_some() {
        return TestResult::Fail("fragment completed a reassembly older than 60 s");
    }
    if ok.is_none() {
        return TestResult::Fail("control: in-window fragments did not reassemble");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/ipv6_frag",
    smoke_cov_ipv6_frag_reassembly_times_out
);

// ═══════════════════════════════════════════════════════════════════════════
// ICMPv6 / NDP
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_nd_options_reject_zero_and_overlong_length() -> TestResult {
    use crate::pkt_ipv6::iter_nd_options;
    // Valid SLLA option then a zero-length option: iteration stops at the
    // zero length (RFC 4861 §4.6: nodes MUST silently discard such packets;
    // at minimum the walker must not loop forever).
    let opts = [1u8, 1, 1, 2, 3, 4, 5, 6, 3, 0, 0, 0, 0, 0, 0, 0];
    let n = iter_nd_options(&opts).count();
    if n != 1 {
        return TestResult::Fail("ND option walker did not stop at a zero-length option");
    }
    // Length claiming 16 bytes with only 8 present.
    let short = [1u8, 2, 1, 2, 3, 4, 5, 6];
    if iter_nd_options(&short).next().is_some() {
        return TestResult::Fail("ND option longer than the buffer accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/icmpv6",
    smoke_cov_nd_options_reject_zero_and_overlong_length
);

// RFC 4861 §6.1.2 / §7.1: NDP messages with a non-zero ICMP code, a
// multicast target, or (RA) a non-link-local source are invalid.
fn smoke_cov_ndp_rejects_invalid_messages() -> TestResult {
    use crate::ipv6::ndp::{on_na, on_ns, on_ra, on_redirect, NdRxResult};
    use crate::pkt_ipv6::{neighbor_advertisement, router_advertisement, NA_FLAG_SOLICITED};
    const IFACE: &str = "cov-ndp1";
    crate::ipv6::ndp::__reset_for_test();
    crate::ipv6::route::__reset_for_test();
    let target = v6(0x31);
    let mac = [0x02, 0, 0, 0, 0x7C, 0x31];
    let mut tlla = vec![2u8, 1];
    tlla.extend_from_slice(&mac);

    let mut na = neighbor_advertisement(NA_FLAG_SOLICITED, target, &tlla);
    na[1] = 1; // code != 0
    let r_code = on_na(IFACE, &na);
    let mut mcast = [0u8; 16];
    mcast[0] = 0xFF;
    mcast[1] = 0x02;
    mcast[15] = 1;
    let na_mc = neighbor_advertisement(NA_FLAG_SOLICITED, mcast, &tlla);
    let r_mc = on_na(IFACE, &na_mc);
    let mut ns = crate::pkt_ipv6::neighbor_solicitation(target, &[]);
    ns[1] = 7;
    let r_ns = on_ns(IFACE, None, &ns);
    let ra = router_advertisement(64, 0, 1800, 0, 0, &[]);
    let r_ra_global = on_ra(IFACE, v6(0x32), &ra, 0);
    let mut ra_code = ra.clone();
    ra_code[1] = 1;
    let mut ll = [0u8; 16];
    ll[0] = 0xFE;
    ll[1] = 0x80;
    ll[15] = 0x32;
    let r_ra_code = on_ra(IFACE, ll, &ra_code, 0);
    let r_ra_short = on_ra(IFACE, ll, &ra[..15], 0);
    let mut redirect = vec![137u8, 1, 0, 0, 0, 0, 0, 0];
    redirect.extend_from_slice(&v6(0x33));
    redirect.extend_from_slice(&v6(0x34));
    let r_redir = on_redirect(IFACE, &redirect);
    // Control: the valid NA does update the cache.
    let good = neighbor_advertisement(NA_FLAG_SOLICITED, target, &tlla);
    let r_good = on_na(IFACE, &good);
    let cached = crate::ipv6::ndp::neigh_lookup(IFACE, &target);
    let routers = crate::ipv6::ndp::routers();
    crate::ipv6::ndp::__reset_for_test();
    crate::ipv6::route::__reset_for_test();
    if !matches!(r_code, NdRxResult::Ignored) || !matches!(r_mc, NdRxResult::Ignored) {
        return TestResult::Fail("NA with non-zero code or multicast target processed");
    }
    if !matches!(r_ns, NdRxResult::Ignored) {
        return TestResult::Fail("NS with non-zero code processed");
    }
    if r_ra_global.is_some() || r_ra_code.is_some() || r_ra_short.is_some() {
        return TestResult::Fail("RA from a global source / with code != 0 / truncated processed");
    }
    if routers.iter().any(|r| r.iface == IFACE) {
        return TestResult::Fail("invalid RA installed a default router");
    }
    if !matches!(r_redir, NdRxResult::Ignored) {
        return TestResult::Fail("Redirect with non-zero code processed");
    }
    if !matches!(r_good, NdRxResult::Updated) || cached != Some(mac) {
        return TestResult::Fail("control: valid NA did not update the neighbour cache");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/icmpv6",
    smoke_cov_ndp_rejects_invalid_messages
);

// RFC 4443 §2.4: an ICMPv6 message whose checksum does not verify is
// discarded before it can touch neighbour state.
fn smoke_cov_icmpv6_bad_checksum_discarded() -> TestResult {
    use crate::pkt_ipv6::{
        neighbor_advertisement, pseudo_checksum, Ipv6Header, NA_FLAG_SOLICITED, NEXT_HEADER_ICMPV6,
    };
    const IFACE: &str = "cov-ndp2";
    crate::ipv6::ndp::__reset_for_test();
    let mut src = [0u8; 16];
    src[0] = 0xFE;
    src[1] = 0x80;
    src[15] = 0x41;
    let target = v6(0x42);
    let mac = [0x02, 0, 0, 0, 0x7C, 0x42];
    let mut tlla = vec![2u8, 1];
    tlla.extend_from_slice(&mac);
    let build = |corrupt: bool| {
        let mut body = neighbor_advertisement(NA_FLAG_SOLICITED, target, &tlla);
        let cs = pseudo_checksum(src, target, NEXT_HEADER_ICMPV6, &body);
        body[2..4].copy_from_slice(&cs.to_be_bytes());
        if corrupt {
            body[3] ^= 0xFF;
        }
        let ip = Ipv6Header {
            version: 6,
            payload_length: body.len() as u16,
            next_header: NEXT_HEADER_ICMPV6,
            hop_limit: 255,
            src_ip: src,
            dst_ip: target,
            ..Default::default()
        };
        let mut pkt = ip.encode().to_vec();
        pkt.extend_from_slice(&body);
        pkt
    };
    let _ = crate::ipv6_stack::rx_frame(IFACE, &build(true));
    let after_bad = crate::ipv6::ndp::neigh_lookup(IFACE, &target);
    let _ = crate::ipv6_stack::rx_frame(IFACE, &build(false));
    let after_good = crate::ipv6::ndp::neigh_lookup(IFACE, &target);
    crate::ipv6::ndp::__reset_for_test();
    if after_bad.is_some() {
        return TestResult::Fail("NA with a bad ICMPv6 checksum updated the neighbour cache");
    }
    if after_good != Some(mac) {
        return TestResult::Fail("control: NA with a valid checksum was not processed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/icmpv6",
    smoke_cov_icmpv6_bad_checksum_discarded
);

// ═══════════════════════════════════════════════════════════════════════════
// UDP
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_udp_verify_odd_length_and_corruption() -> TestResult {
    use crate::pkt_udp::verify_ipv4;
    let (s, d) = ([10, 0, 76, 1], [10, 0, 76, 2]);
    // Odd-length payload exercises the pad byte in the pseudo checksum.
    let dg = udp_datagram(s, d, 30100, 30101, b"odd");
    if verify_ipv4(s, d, &dg).is_err() {
        return TestResult::Fail("odd-length UDP datagram checksum rejected");
    }
    // The pseudo-header covers the addresses: same bytes, other dst.
    if verify_ipv4(s, [10, 0, 76, 3], &dg).is_ok() {
        return TestResult::Fail("UDP checksum does not cover the destination address");
    }
    let mut flip = dg.clone();
    let last = flip.len() - 1;
    flip[last] ^= 0x80;
    if verify_ipv4(s, d, &flip).is_ok() {
        return TestResult::Fail("UDP datagram with a flipped payload bit verified");
    }
    for n in 0..8 {
        if verify_ipv4(s, d, &dg[..n]).is_ok() {
            return TestResult::Fail("UDP datagram shorter than its header verified");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/udp",
    smoke_cov_udp_verify_odd_length_and_corruption
);

// ═══════════════════════════════════════════════════════════════════════════
// TCP wire format
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_tcp_decode_rejects_truncated_and_offsets() -> TestResult {
    use crate::pkt_tcp::TcpHeader;
    let seg = tcp_segment([1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 3, 4, 0x10, &[]);
    if TcpHeader::decode(&seg).is_err() {
        return TestResult::Fail("well-formed TCP header rejected");
    }
    for n in 0..20 {
        if TcpHeader::decode(&seg[..n]).is_ok() {
            return TestResult::Fail("TCP header shorter than 20 bytes accepted");
        }
    }
    // Data offset 8 (32 bytes of header) in a 20-byte segment.
    let mut long = seg.clone();
    long[12] = 8 << 4;
    if TcpHeader::decode(&long).is_ok() {
        return TestResult::Fail("TCP data offset past the segment accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp",
    smoke_cov_tcp_decode_rejects_truncated_and_offsets
);

fn smoke_cov_tcp_options_malformed_lengths_terminate() -> TestResult {
    use crate::pkt_tcp::{iter_options, TcpOption};
    // kind=2 (MSS) with length 0, 1 and past the buffer: each must stop the
    // walk (a length < 2 would otherwise never advance).
    for bad in [[2u8, 0, 0, 0], [2, 1, 0, 0], [2, 9, 5, 0xB4]] {
        if iter_options(&bad).take(8).count() != 0 {
            return TestResult::Fail("TCP option with an invalid length was yielded");
        }
    }
    // MSS with the wrong length is not decoded as an MSS.
    let odd = [2u8, 3, 5];
    if let Some(TcpOption::Mss(_)) = iter_options(&odd).next() {
        return TestResult::Fail("3-byte option decoded as MSS");
    }
    // NOP, NOP, EOL, then garbage: EOL ends the list.
    let eol = [1u8, 1, 0, 2, 4, 5, 0xB4];
    if iter_options(&eol).count() != 2 {
        return TestResult::Fail("TCP option walk did not stop at End-of-List");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp",
    smoke_cov_tcp_options_malformed_lengths_terminate
);

fn smoke_cov_tcp_checksum_covers_pseudo_header() -> TestResult {
    use crate::pkt_tcp::verify_ipv4;
    let (s, d) = ([10, 0, 77, 1], [10, 0, 77, 2]);
    let seg = tcp_segment(s, d, 30200, 30201, 1, 0, 0x18, b"x");
    if verify_ipv4(s, d, &seg).is_err() {
        return TestResult::Fail("odd-length TCP segment checksum rejected");
    }
    if verify_ipv4([10, 0, 77, 9], d, &seg).is_ok() {
        return TestResult::Fail("TCP checksum does not cover the source address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp",
    smoke_cov_tcp_checksum_covers_pseudo_header
);

// ═══════════════════════════════════════════════════════════════════════════
// TCP state machine edge cases (RFC 9293)
// ═══════════════════════════════════════════════════════════════════════════

const TCP_IFACE: &str = "cov-tcp1";
const TCP_LOCAL: [u8; 4] = [10, 0, 78, 1];

fn tcp_setup() {
    cov_reset_iface(TCP_IFACE, TCP_LOCAL, TCP_LOCAL);
}

fn tcp_inject(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
    let seg = tcp_segment(TCP_LOCAL, TCP_LOCAL, sport, dport, seq, ack, flags, payload);
    crate::tcp::core::handle_segment(TCP_LOCAL, TCP_LOCAL, &seg);
}

/// Captured TCP segments (IPv4 payload) since the last drain.
fn tcp_drain() -> Vec<Vec<u8>> {
    cov_drain_ipv4()
        .into_iter()
        .filter(|p| p[9] == IP_PROTO_TCP)
        .map(|p| {
            let ihl = ((p[0] & 0x0F) as usize) * 4;
            p[ihl..].to_vec()
        })
        .collect()
}

fn seg_flags(seg: &[u8]) -> u8 {
    seg[13]
}

fn seg_seq(seg: &[u8]) -> u32 {
    u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]])
}

fn seg_ack(seg: &[u8]) -> u32 {
    u32::from_be_bytes([seg[8], seg[9], seg[10], seg[11]])
}

/// Drive a passive open to ESTABLISHED. Returns `(server_tcb, client_iss,
/// server_iss)`.
fn tcp_established(listen_port: u16, client_port: u16, client_iss: u32) -> Option<(u32, u32, u32)> {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_SYN};
    let listen_id = crate::tcp::core::listen(TCP_LOCAL, listen_port, 4).ok()?;
    tcp_inject(client_port, listen_port, client_iss, 0, FLAG_SYN, &[]);
    let synack = tcp_drain()
        .into_iter()
        .find(|s| seg_flags(s) & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK))?;
    let server_iss = seg_seq(&synack);
    tcp_inject(
        client_port,
        listen_port,
        client_iss.wrapping_add(1),
        server_iss.wrapping_add(1),
        FLAG_ACK,
        &[],
    );
    let _ = tcp_drain();
    let mut server = None;
    for _ in 0..50 {
        if let Ok(Some(id)) = crate::tcp::core::accept(listen_id) {
            server = Some(id);
            break;
        }
    }
    Some((server?, client_iss, server_iss))
}

fn tcp_state(id: u32) -> Option<crate::tcp::state_machine::TcpState> {
    crate::tcp::core::__with_tcb(id, |t| t.state)
}

// RFC 9293 §3.10.7.4: a RST whose sequence number is in the window resets
// the connection; one outside it is answered with an ACK and ignored
// (RFC 5961 §3 challenge ACK) — the blind-reset defence.
fn smoke_cov_tcp_rst_window_check() -> TestResult {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_RST};
    use crate::tcp::state_machine::TcpState;
    tcp_setup();
    let (sid, ciss, _siss) = match tcp_established(31001, 51001, 0x0100_0000) {
        Some(t) => t,
        None => return TestResult::Fail("setup: handshake did not complete"),
    };
    // Far outside the receive window.
    tcp_inject(
        51001,
        31001,
        ciss.wrapping_add(0x4000_0000),
        0,
        FLAG_RST,
        &[],
    );
    let challenge = tcp_drain();
    let after_blind = tcp_state(sid);
    // Exactly RCV.NXT.
    tcp_inject(51001, 31001, ciss.wrapping_add(1), 0, FLAG_RST, &[]);
    let after_exact = tcp_state(sid);
    if after_blind != Some(TcpState::Established) {
        return TestResult::Fail("out-of-window RST tore down the connection");
    }
    if !challenge.iter().any(|s| seg_flags(s) & FLAG_ACK != 0) {
        return TestResult::Fail("out-of-window RST got no challenge ACK");
    }
    if matches!(after_exact, Some(TcpState::Established)) {
        return TestResult::Fail("in-window RST did not reset the connection");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/tcp_state", smoke_cov_tcp_rst_window_check);

// Passive close: peer FIN → CLOSE_WAIT with the FIN acknowledged; our
// close → LAST_ACK with a FIN on the wire; the peer's ACK ends it.
fn smoke_cov_tcp_passive_close_close_wait_last_ack() -> TestResult {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_FIN};
    use crate::tcp::state_machine::{Shutdown, TcpState};
    tcp_setup();
    let (sid, ciss, siss) = match tcp_established(31002, 51002, 0x0200_0000) {
        Some(t) => t,
        None => return TestResult::Fail("setup: handshake did not complete"),
    };
    tcp_inject(
        51002,
        31002,
        ciss.wrapping_add(1),
        siss.wrapping_add(1),
        FLAG_FIN | FLAG_ACK,
        &[],
    );
    // Flush any delayed ACK.
    if let Some(arc) = crate::tcp::core::lookup_tcb(sid) {
        crate::tcp::core::pump_send(&arc);
    }
    for _ in 0..4 {
        crate::tcp::core::tick_all();
    }
    let acks = tcp_drain();
    if tcp_state(sid) != Some(TcpState::CloseWait) {
        return TestResult::Fail("peer FIN did not move ESTABLISHED to CLOSE_WAIT");
    }
    let rcv_nxt = crate::tcp::core::__with_tcb(sid, |t| t.rcv_nxt).unwrap_or(0);
    if rcv_nxt != ciss.wrapping_add(2) {
        return TestResult::Fail("peer FIN did not consume one sequence number");
    }
    let _ = acks;
    if crate::tcp::core::shutdown(sid, Shutdown::Write).is_err() {
        return TestResult::Fail("shutdown(Write) in CLOSE_WAIT failed");
    }
    let fin = tcp_drain()
        .into_iter()
        .find(|s| seg_flags(s) & FLAG_FIN != 0);
    if tcp_state(sid) != Some(TcpState::LastAck) {
        return TestResult::Fail("close in CLOSE_WAIT did not enter LAST_ACK");
    }
    let fin = match fin {
        Some(f) => f,
        None => return TestResult::Fail("no FIN emitted from LAST_ACK"),
    };
    if seg_ack(&fin) != ciss.wrapping_add(2) {
        return TestResult::Fail("our FIN does not acknowledge the peer's FIN");
    }
    tcp_inject(
        51002,
        31002,
        ciss.wrapping_add(2),
        seg_seq(&fin).wrapping_add(1),
        FLAG_ACK,
        &[],
    );
    match tcp_state(sid) {
        None | Some(TcpState::Closed) => TestResult::Pass,
        Some(_) => TestResult::Fail("ACK of our FIN did not close a LAST_ACK connection"),
    }
}
kernel_test_in!(
    "net/coverage/tcp_state",
    smoke_cov_tcp_passive_close_close_wait_last_ack
);

// Simultaneous close: FIN_WAIT_1 receiving the peer's FIN that does not yet
// ack ours → CLOSING; the later ACK → TIME_WAIT.
fn smoke_cov_tcp_simultaneous_close_closing() -> TestResult {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_FIN};
    use crate::tcp::state_machine::{Shutdown, TcpState};
    tcp_setup();
    let (sid, ciss, siss) = match tcp_established(31003, 51003, 0x0300_0000) {
        Some(t) => t,
        None => return TestResult::Fail("setup: handshake did not complete"),
    };
    let _ = crate::tcp::core::shutdown(sid, Shutdown::Write);
    let _ = tcp_drain();
    if tcp_state(sid) != Some(TcpState::FinWait1) {
        return TestResult::Fail("shutdown(Write) did not enter FIN_WAIT_1");
    }
    let fin_seq = crate::tcp::core::__with_tcb(sid, |t| t.fin_seq).unwrap_or(0);
    // Peer's FIN acks only our SYN, not our FIN.
    tcp_inject(
        51003,
        31003,
        ciss.wrapping_add(1),
        siss.wrapping_add(1),
        FLAG_FIN | FLAG_ACK,
        &[],
    );
    if tcp_state(sid) != Some(TcpState::Closing) {
        return TestResult::Fail("crossed FINs did not enter CLOSING");
    }
    tcp_inject(
        51003,
        31003,
        ciss.wrapping_add(2),
        fin_seq.wrapping_add(1),
        FLAG_ACK,
        &[],
    );
    if tcp_state(sid) != Some(TcpState::TimeWait) {
        return TestResult::Fail("ACK of our FIN in CLOSING did not enter TIME_WAIT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp_state",
    smoke_cov_tcp_simultaneous_close_closing
);

// FIN_WAIT_1 receiving a FIN that also acks our FIN goes straight to
// TIME_WAIT.
fn smoke_cov_tcp_fin_wait1_fin_ack_to_time_wait() -> TestResult {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_FIN};
    use crate::tcp::state_machine::{Shutdown, TcpState};
    tcp_setup();
    let (sid, ciss, _siss) = match tcp_established(31004, 51004, 0x0400_0000) {
        Some(t) => t,
        None => return TestResult::Fail("setup: handshake did not complete"),
    };
    let _ = crate::tcp::core::shutdown(sid, Shutdown::Write);
    let _ = tcp_drain();
    let fin_seq = crate::tcp::core::__with_tcb(sid, |t| t.fin_seq).unwrap_or(0);
    tcp_inject(
        51004,
        31004,
        ciss.wrapping_add(1),
        fin_seq.wrapping_add(1),
        FLAG_FIN | FLAG_ACK,
        &[],
    );
    if tcp_state(sid) != Some(TcpState::TimeWait) {
        return TestResult::Fail("FIN+ACK of our FIN in FIN_WAIT_1 did not enter TIME_WAIT");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp_state",
    smoke_cov_tcp_fin_wait1_fin_ack_to_time_wait
);

// Simultaneous open (RFC 9293 §3.5, figure 8): SYN_SENT receiving a bare
// SYN answers SYN+ACK and moves to SYN_RECEIVED; the ACK of our SYN then
// establishes the connection.
fn smoke_cov_tcp_simultaneous_open() -> TestResult {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_SYN};
    use crate::tcp::state_machine::TcpState;
    tcp_setup();
    let id =
        crate::tcp::core::__install_test_tcb(TCP_LOCAL, 31005, TCP_LOCAL, 51005, TcpState::SynSent);
    let iss = crate::tcp::core::__with_tcb(id, |t| t.iss).unwrap_or(0);
    let peer_iss = 0x0500_0000u32;
    tcp_inject(51005, 31005, peer_iss, 0, FLAG_SYN, &[]);
    let out = tcp_drain();
    if tcp_state(id) != Some(TcpState::SynReceived) {
        return TestResult::Fail("SYN in SYN_SENT did not enter SYN_RECEIVED");
    }
    let synack = out
        .iter()
        .find(|s| seg_flags(s) & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK));
    match synack {
        Some(s) if seg_ack(s) == peer_iss.wrapping_add(1) => {}
        Some(_) => return TestResult::Fail("simultaneous-open SYN+ACK acks the wrong sequence"),
        None => return TestResult::Fail("simultaneous open sent no SYN+ACK"),
    }
    tcp_inject(
        51005,
        31005,
        peer_iss.wrapping_add(1),
        iss.wrapping_add(1),
        FLAG_ACK,
        &[],
    );
    if tcp_state(id) != Some(TcpState::Established) {
        return TestResult::Fail("ACK of our SYN in SYN_RECEIVED did not establish");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/tcp_state", smoke_cov_tcp_simultaneous_open);

// A listener only opens on SYN; a stray ACK creates nothing, and in
// SYN_RECEIVED an ACK that does not cover our SYN does not establish.
fn smoke_cov_tcp_listener_ignores_non_syn_and_bad_ack() -> TestResult {
    use crate::pkt_tcp::{FLAG_ACK, FLAG_SYN};
    tcp_setup();
    let listen_id = match crate::tcp::core::listen(TCP_LOCAL, 31006, 4) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("listen failed"),
    };
    tcp_inject(51006, 31006, 0x0600_0000, 0x1234, FLAG_ACK, &[]);
    if crate::tcp::core::listen_has_pending(listen_id) {
        return TestResult::Fail("bare ACK to a listener queued a connection");
    }
    tcp_inject(51007, 31006, 0x0700_0000, 0, FLAG_SYN, &[]);
    let synack = tcp_drain()
        .into_iter()
        .find(|s| seg_flags(s) & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK));
    let siss = match synack {
        Some(s) => seg_seq(&s),
        None => return TestResult::Fail("no SYN+ACK for a valid SYN"),
    };
    // ACK acknowledging our ISS itself (not ISS+1): must not establish.
    tcp_inject(51007, 31006, 0x0700_0001, siss, FLAG_ACK, &[]);
    if crate::tcp::core::listen_has_pending(listen_id) {
        return TestResult::Fail("ACK not covering our SYN completed the handshake");
    }
    tcp_inject(
        51007,
        31006,
        0x0700_0001,
        siss.wrapping_add(1),
        FLAG_ACK,
        &[],
    );
    if !crate::tcp::core::listen_has_pending(listen_id) {
        return TestResult::Fail("control: correct ACK did not complete the handshake");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp_state",
    smoke_cov_tcp_listener_ignores_non_syn_and_bad_ack
);

// Out-of-order data is held and delivered in order once the hole fills,
// through the full segment path (not just the reassembly buffer).
fn smoke_cov_tcp_out_of_order_delivered_in_order() -> TestResult {
    use crate::pkt_tcp::FLAG_ACK;
    tcp_setup();
    let (sid, ciss, siss) = match tcp_established(31008, 51008, 0x0800_0000) {
        Some(t) => t,
        None => return TestResult::Fail("setup: handshake did not complete"),
    };
    let base = ciss.wrapping_add(1);
    let ack = siss.wrapping_add(1);
    tcp_inject(51008, 31008, base.wrapping_add(5), ack, FLAG_ACK, b"world");
    let mut buf = [0u8; 32];
    let early = crate::tcp::core::recv(sid, &mut buf).unwrap_or(0);
    tcp_inject(51008, 31008, base, ack, FLAG_ACK, b"hello");
    let mut got = Vec::new();
    for _ in 0..4 {
        match crate::tcp::core::recv(sid, &mut buf) {
            Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    if early != 0 {
        return TestResult::Fail("out-of-order bytes were readable before the hole filled");
    }
    if got != b"helloworld" {
        return TestResult::Fail("out-of-order segments not delivered in sequence order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tcp_state",
    smoke_cov_tcp_out_of_order_delivered_in_order
);

// ═══════════════════════════════════════════════════════════════════════════
// DHCPv4
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_dhcp_rejects_truncated_and_bad_options() -> TestResult {
    use crate::pkt_dhcp::{iter_options, DhcpError, DhcpHeader};
    let mut msg = vec![0u8; 240];
    msg[0] = 2;
    msg[1] = 1;
    msg[2] = 6;
    msg[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    if DhcpHeader::decode(&msg).is_err() {
        return TestResult::Fail("well-formed DHCP header rejected");
    }
    if DhcpHeader::decode(&msg[..239]) != Err(DhcpError::Short) {
        return TestResult::Fail("DHCP message shorter than 240 bytes accepted");
    }
    // Option 53 claiming 4 bytes with 1 present: the walk stops.
    let opts = [53u8, 4, 1];
    if iter_options(&opts).next().is_some() {
        return TestResult::Fail("DHCP option running past the buffer yielded");
    }
    // Pad bytes skipped, End terminates even with bytes after it.
    let opts = [0u8, 0, 53, 1, 2, 255, 53, 1, 5];
    let v: Vec<_> = iter_options(&opts).collect();
    if v.len() != 1 || v[0].tag != 53 || v[0].data != [2] {
        return TestResult::Fail("DHCP option walk mishandled Pad / End");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/dhcp",
    smoke_cov_dhcp_rejects_truncated_and_bad_options
);

// ═══════════════════════════════════════════════════════════════════════════
// DNS / mDNS
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_dns_name_rejects_malformed() -> TestResult {
    use crate::pkt_dns::{decode_name, DnsError};
    let good = b"\x03www\x07example\x03com\x00";
    match decode_name(good, 0) {
        Ok((n, used)) if n == "www.example.com" && used == good.len() => {}
        _ => return TestResult::Fail("well-formed DNS name misdecoded"),
    }
    // Label length running past the message.
    if decode_name(b"\x05ab", 0).is_ok() {
        return TestResult::Fail("DNS label past the message accepted");
    }
    // Missing root label.
    if decode_name(b"\x03www", 0).is_ok() {
        return TestResult::Fail("DNS name without a terminating root label accepted");
    }
    // Compression pointer past the message.
    if decode_name(b"\xC0\x40", 0).is_ok() {
        return TestResult::Fail("DNS compression pointer out of range accepted");
    }
    // Reserved label types 0x40 / 0x80.
    if decode_name(b"\x41a\x00", 0) != Err(DnsError::BadName)
        || decode_name(b"\x81a\x00", 0) != Err(DnsError::BadName)
    {
        return TestResult::Fail("DNS reserved label type accepted");
    }
    // Truncated pointer (one byte).
    if decode_name(b"\xC0", 0).is_ok() {
        return TestResult::Fail("truncated DNS compression pointer accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/dns", smoke_cov_dns_name_rejects_malformed);

// RFC 1035 §2.3.4: names are at most 255 octets. Pointers can splice labels
// into longer names; the decoder must refuse them.
fn smoke_cov_dns_name_length_limit() -> TestResult {
    use crate::pkt_dns::{decode_name, DnsError};
    let label = |out: &mut Vec<u8>, n: usize| {
        out.push(n as u8);
        out.extend(core::iter::repeat_n(b'a', n));
    };
    // 3 × 63 + 61: 3*64 + 62 + 1 = 255 octets — the maximum legal name.
    let mut max = Vec::new();
    for _ in 0..3 {
        label(&mut max, 63);
    }
    label(&mut max, 61);
    max.push(0);
    if decode_name(&max, 0).is_err() {
        return TestResult::Fail("255-octet DNS name rejected");
    }
    // One octet more.
    let mut over = Vec::new();
    for _ in 0..3 {
        label(&mut over, 63);
    }
    label(&mut over, 62);
    over.push(0);
    if decode_name(&over, 0) != Err(DnsError::BadName) {
        return TestResult::Fail("256-octet DNS name accepted");
    }
    // Pointer splicing: 2 × 63 at offset 0, then at offset 128 two more
    // labels followed by a pointer back to offset 0 → 4 × 63 labels total.
    let mut msg = Vec::new();
    label(&mut msg, 63);
    label(&mut msg, 63);
    msg.push(0);
    let start = msg.len();
    label(&mut msg, 63);
    label(&mut msg, 63);
    msg.extend_from_slice(&[0xC0, 0x00]);
    if decode_name(&msg, start) != Err(DnsError::BadName) {
        return TestResult::Fail("over-long DNS name built from a compression pointer accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/dns", smoke_cov_dns_name_length_limit);

fn smoke_cov_dns_rr_and_header_reject_truncated() -> TestResult {
    use crate::pkt_dns::{DnsError, DnsHeader, Question, ResourceRecord};
    if DnsHeader::decode(&[0u8; 11]).is_ok() {
        return TestResult::Fail("11-byte DNS header accepted");
    }
    // name "a" + type/class/ttl + rdlength 16 with 4 bytes of rdata.
    let mut rr = b"\x01a\x00".to_vec();
    rr.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 16, 1, 2, 3, 4]);
    if ResourceRecord::decode(&rr, 0) != Err(DnsError::Truncated) {
        return TestResult::Fail("DNS RR with rdlength past the message accepted");
    }
    // Question missing its type/class.
    if Question::decode(b"\x01a\x00\x00", 0).is_ok() {
        return TestResult::Fail("truncated DNS question accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/dns",
    smoke_cov_dns_rr_and_header_reject_truncated
);

fn smoke_cov_mdns_srv_rejects_short_rdata() -> TestResult {
    use crate::pkt_mdns::SrvRecord;
    // SRV rdata needs 6 fixed bytes + a target name.
    let rdata = [0u8, 1, 0, 2, 0x1F];
    if SrvRecord::decode(&rdata, 0, rdata.len()).is_ok() {
        return TestResult::Fail("SRV rdata shorter than its fixed part accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/mdns", smoke_cov_mdns_srv_rejects_short_rdata);

// ═══════════════════════════════════════════════════════════════════════════
// DHCPv6, NTP, TFTP, SCTP, GRE
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_dhcpv6_rejects_truncated() -> TestResult {
    use crate::pkt_dhcpv6::{iter_options, DhcpV6Header, RelayHeader};
    if DhcpV6Header::decode(&[1, 0, 0]).is_ok() {
        return TestResult::Fail("3-byte DHCPv6 header accepted");
    }
    if RelayHeader::decode(&[12u8; 33]).is_ok() {
        return TestResult::Fail("33-byte DHCPv6 relay header accepted");
    }
    // Option 1 (CLIENTID) claiming 10 bytes with 2 present.
    let opts = [0u8, 1, 0, 10, 0xAA, 0xBB];
    let reported = matches!(iter_options(&opts).next(), Some(Err(_)));
    if !reported {
        return TestResult::Fail("DHCPv6 option past the buffer not reported");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/dhcpv6", smoke_cov_dhcpv6_rejects_truncated);

fn smoke_cov_ntp_rejects_truncated() -> TestResult {
    use crate::pkt_ntp::{NtpError, NtpHeader};
    if NtpHeader::decode(&[0x23u8; 48]).is_err() {
        return TestResult::Fail("48-byte NTP header rejected");
    }
    if NtpHeader::decode(&[0x23u8; 47]) != Err(NtpError::Short) {
        return TestResult::Fail("47-byte NTP header accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/ntp", smoke_cov_ntp_rejects_truncated);

fn smoke_cov_tftp_rejects_unterminated_and_short() -> TestResult {
    use crate::pkt_tftp::{Packet, TftpError};
    // RRQ whose mode string has no NUL.
    if Packet::decode(b"\x00\x01file\x00octet") != Err(TftpError::Unterminated) {
        return TestResult::Fail("TFTP RRQ with unterminated mode accepted");
    }
    if Packet::decode(b"\x00\x03\x00") != Err(TftpError::Short)
        || Packet::decode(b"\x00\x04\x00") != Err(TftpError::Short)
    {
        return TestResult::Fail("truncated TFTP DATA / ACK accepted");
    }
    if Packet::decode(b"\x00\x05\x00\x01no-nul") != Err(TftpError::Unterminated) {
        return TestResult::Fail("TFTP ERROR with unterminated message accepted");
    }
    if Packet::decode(b"\x00").is_ok() {
        return TestResult::Fail("1-byte TFTP packet accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/tftp",
    smoke_cov_tftp_rejects_unterminated_and_short
);

fn smoke_cov_sctp_rejects_bad_chunk_lengths() -> TestResult {
    use crate::pkt_sctp::{iter_chunks, CommonHeader, SctpError};
    if CommonHeader::decode(&[0u8; 11]).is_ok() {
        return TestResult::Fail("11-byte SCTP common header accepted");
    }
    let tiny = [0u8, 0, 0, 3];
    if !matches!(
        iter_chunks(&tiny).next(),
        Some(Err(SctpError::BadChunkLength))
    ) {
        return TestResult::Fail("SCTP chunk length < 4 accepted");
    }
    let over = [0u8, 0, 0, 20, 1, 2, 3, 4];
    if !matches!(iter_chunks(&over).next(), Some(Err(SctpError::Truncated))) {
        return TestResult::Fail("SCTP chunk longer than the packet accepted");
    }
    // After an error the iterator stops rather than re-reporting forever.
    if iter_chunks(&over).take(4).count() != 1 {
        return TestResult::Fail("SCTP chunk iterator did not stop after an error");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/sctp",
    smoke_cov_sctp_rejects_bad_chunk_lengths
);

fn smoke_cov_gre_rejects_truncated_and_reserved_flags() -> TestResult {
    use crate::pkt_gre::{build, GreError, GreHeader, FLAG_ROUTING};
    let pkt = build(0x0800, Some(7), Some(9), b"payload", true);
    if GreHeader::decode(&pkt).is_err() {
        return TestResult::Fail("well-formed GRE header rejected");
    }
    // Checksum + key + sequence flags set, optional fields cut off.
    for n in [3usize, 6, 10, 14] {
        if GreHeader::decode(&pkt[..n]).is_ok() {
            return TestResult::Fail("GRE header missing its optional fields accepted");
        }
    }
    // RFC 2784 §2.3: Routing (RFC 1701) set → discard.
    let mut routed = pkt.clone();
    let fv = u16::from_be_bytes([routed[0], routed[1]]) | FLAG_ROUTING;
    routed[0..2].copy_from_slice(&fv.to_be_bytes());
    if GreHeader::decode(&routed) != Err(GreError::ReservedFlags) {
        return TestResult::Fail("GRE packet with the RFC 1701 Routing bit accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/gre",
    smoke_cov_gre_rejects_truncated_and_reserved_flags
);

// ═══════════════════════════════════════════════════════════════════════════
// Application protocols
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_coap_rejects_truncated_options() -> TestResult {
    use crate::pkt_coap::{parse_options_and_payload, CoapError, Header};
    if Header::decode(&[0x40, 1, 0]).is_ok() {
        return TestResult::Fail("3-byte CoAP header accepted");
    }
    // TKL=4 with 2 token bytes.
    if Header::decode(&[0x44, 1, 0, 1, 0xAA, 0xBB]) != Err(CoapError::Truncated) {
        return TestResult::Fail("CoAP token past the message accepted");
    }
    // Option delta nibble 15 is reserved (only valid as the 0xFF marker).
    if parse_options_and_payload(&[0xF1, 0]).is_ok() {
        return TestResult::Fail("CoAP option with reserved delta 15 accepted");
    }
    // Option length 5 with 1 value byte.
    if parse_options_and_payload(&[0xB5, b'a']).is_ok() {
        return TestResult::Fail("CoAP option value past the message accepted");
    }
    // Extended delta (13) with its extension byte missing.
    if parse_options_and_payload(&[0xD0]).is_ok() {
        return TestResult::Fail("CoAP option with missing extended delta accepted");
    }
    // RFC 7252 §3: payload marker followed by nothing is a format error.
    if parse_options_and_payload(&[0xB1, b'a', 0xFF]).is_ok() {
        return TestResult::Fail("CoAP payload marker with an empty payload accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/coap",
    smoke_cov_coap_rejects_truncated_options
);

fn smoke_cov_http_rejects_malformed() -> TestResult {
    use crate::http::{iter_chunks, parse_headers, RequestLine, StatusLine};
    if RequestLine::decode(b"GET / HTTP/1.1\r\n").is_err() {
        return TestResult::Fail("well-formed request line rejected");
    }
    for bad in [
        &b"GET / HTTP/1.1"[..], // no CRLF
        b"GET\r\n",             // missing target + version
        b"\r\n",
    ] {
        if RequestLine::decode(bad).is_ok() {
            return TestResult::Fail("malformed HTTP request line accepted");
        }
    }
    if StatusLine::decode(b"HTTP/1.1\r\n").is_ok() {
        return TestResult::Fail("status line without a code accepted");
    }
    if parse_headers(b"Host: a\r\n").is_ok() {
        return TestResult::Fail("header block without the blank line accepted");
    }
    let bad_chunk: Vec<_> = iter_chunks(b"zz\r\nabc\r\n0\r\n\r\n").take(2).collect();
    if !matches!(bad_chunk.first(), Some(Err(_))) {
        return TestResult::Fail("non-hex chunk size accepted");
    }
    let short_chunk: Vec<_> = iter_chunks(b"10\r\nabc").take(2).collect();
    if matches!(short_chunk.first(), Some(Ok(_))) {
        return TestResult::Fail("chunk shorter than its declared size accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/http", smoke_cov_http_rejects_malformed);

fn smoke_cov_http2_rejects_truncated() -> TestResult {
    use crate::http2::{parse_settings_payload, FrameHeader};
    if FrameHeader::decode(&[0u8; 8]).is_ok() {
        return TestResult::Fail("8-byte HTTP/2 frame header accepted");
    }
    if FrameHeader::decode(&[0u8; 9]).is_err() {
        return TestResult::Fail("9-byte HTTP/2 frame header rejected");
    }
    if parse_settings_payload(&[0u8; 7]).is_ok() {
        return TestResult::Fail("SETTINGS payload not a multiple of 6 accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/http2", smoke_cov_http2_rejects_truncated);

fn smoke_cov_ws_rejects_truncated_lengths() -> TestResult {
    use crate::ws::{Frame, WsError};
    if Frame::decode(&[0x81]).is_ok() {
        return TestResult::Fail("1-byte WebSocket frame accepted");
    }
    // 16-bit extended length with one length byte present.
    if Frame::decode(&[0x82, 126, 0x01]) != Err(WsError::Short) {
        return TestResult::Fail("WebSocket 16-bit length truncated accepted");
    }
    // 64-bit length with the reserved top bit set.
    let mut b = vec![0x82u8, 127, 0x80, 0, 0, 0, 0, 0, 0, 1];
    b.push(0);
    if Frame::decode(&b) != Err(WsError::BadLength) {
        return TestResult::Fail("WebSocket 64-bit length with top bit set accepted");
    }
    // Masked frame missing its masking key.
    if Frame::decode(&[0x81, 0x85, 1, 2]) != Err(WsError::Short) {
        return TestResult::Fail("masked WebSocket frame without a full key accepted");
    }
    // Payload shorter than declared.
    if Frame::decode(&[0x81, 5, b'h', b'i']) != Err(WsError::Short) {
        return TestResult::Fail("WebSocket payload shorter than its length accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/ws", smoke_cov_ws_rejects_truncated_lengths);

fn smoke_cov_tls_rejects_truncated() -> TestResult {
    use crate::tls::{Alert, HandshakeMessage, Record, TlsError};
    if Record::decode(&[22, 3, 3, 0]).is_ok() {
        return TestResult::Fail("4-byte TLS record header accepted");
    }
    if Record::decode(&[22, 3, 3, 0, 5, 1, 2]) != Err(TlsError::Short) {
        return TestResult::Fail("TLS record shorter than its length accepted");
    }
    if HandshakeMessage::decode(&[1, 0, 0, 9, 1, 2, 3]) != Err(TlsError::Truncated) {
        return TestResult::Fail("TLS handshake message shorter than its length accepted");
    }
    if Alert::decode(&[2]).is_ok() {
        return TestResult::Fail("1-byte TLS alert accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/tls", smoke_cov_tls_rejects_truncated);

fn smoke_cov_quic_rejects_malformed_headers() -> TestResult {
    use crate::quic::{decode_long_header, varint_decode, QuicError};
    // 8-byte varint prefix with 3 bytes present.
    if varint_decode(&[0xC0, 0, 0]) != Err(QuicError::Short) || varint_decode(&[]).is_ok() {
        return TestResult::Fail("truncated QUIC varint accepted");
    }
    // Short-header first byte is not a long header.
    if decode_long_header(&[0x40, 0, 0, 0, 1, 0, 0]).is_ok() {
        return TestResult::Fail("short-header packet decoded as a long header");
    }
    // DCID length 8 with 2 bytes present.
    if decode_long_header(&[0xC0, 0, 0, 0, 1, 8, 1, 2]).is_ok() {
        return TestResult::Fail("QUIC long header with truncated DCID accepted");
    }
    // RFC 9000 §17.2: v1 connection IDs longer than 20 bytes are dropped.
    let mut long_cid = vec![0xC0u8, 0, 0, 0, 1, 21];
    long_cid.extend_from_slice(&[0xAB; 21]);
    long_cid.push(0);
    if decode_long_header(&long_cid) != Err(QuicError::BadConnectionIdLength) {
        return TestResult::Fail("QUIC v1 long header with a 21-byte DCID accepted");
    }
    // Version Negotiation (version 0) may carry longer IDs (RFC 8999).
    long_cid[1..5].copy_from_slice(&[0, 0, 0, 0]);
    if decode_long_header(&long_cid).is_err() {
        return TestResult::Fail("version-0 long header with a long DCID rejected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/quic",
    smoke_cov_quic_rejects_malformed_headers
);

fn smoke_cov_mqtt_rejects_truncated() -> TestResult {
    use crate::mqtt::{decode_utf8_string, decode_var_int, FixedHeader, MqttError};
    if decode_var_int(&[0x80, 0x80]).is_ok() {
        return TestResult::Fail("MQTT var-int with continuation but no end accepted");
    }
    if FixedHeader::decode(&[0x30]).is_ok() {
        return TestResult::Fail("MQTT fixed header without remaining length accepted");
    }
    if decode_utf8_string(&[0, 5, b'a'], 0) != Err(MqttError::Truncated) {
        return TestResult::Fail("MQTT UTF-8 string shorter than its length accepted");
    }
    if decode_utf8_string(&[0], 0) != Err(MqttError::Short) {
        return TestResult::Fail("MQTT UTF-8 string without a length accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/mqtt", smoke_cov_mqtt_rejects_truncated);

fn smoke_cov_stun_rejects_truncated() -> TestResult {
    use crate::stun::{decode_error_code, iter_attributes, StunError, StunHeader};
    let mut hdr = vec![0u8, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42];
    hdr.extend_from_slice(&[0u8; 12]);
    if StunHeader::decode(&hdr).is_err() {
        return TestResult::Fail("well-formed STUN header rejected");
    }
    if StunHeader::decode(&hdr[..19]) != Err(StunError::Short) {
        return TestResult::Fail("19-byte STUN header accepted");
    }
    // Attribute claiming 8 bytes with 4 present.
    let attr = [0x80u8, 0x22, 0, 8, b'n', b'a', b'r', b'f'];
    if !matches!(
        iter_attributes(&attr).next(),
        Some(Err(StunError::Truncated))
    ) {
        return TestResult::Fail("STUN attribute past the message accepted");
    }
    if decode_error_code(&[0, 0, 4]).is_ok() {
        return TestResult::Fail("3-byte STUN ERROR-CODE accepted");
    }
    TestResult::Pass
}
kernel_test_in!("net/coverage/stun", smoke_cov_stun_rejects_truncated);

fn smoke_cov_wireguard_rejects_wrong_type_and_length() -> TestResult {
    use crate::wireguard::{
        decode_cookie_reply, decode_handshake_initiation, decode_handshake_response,
        decode_transport_header, WgError, COOKIE_REPLY_LEN, HANDSHAKE_INITIATION_LEN,
        HANDSHAKE_RESPONSE_LEN, TRANSPORT_DATA_MIN_LEN,
    };
    let mut init = vec![0u8; HANDSHAKE_INITIATION_LEN];
    init[0] = 1;
    if decode_handshake_initiation(&init).is_err() {
        return TestResult::Fail("well-formed WireGuard initiation rejected");
    }
    if !matches!(
        decode_handshake_initiation(&init[..HANDSHAKE_INITIATION_LEN - 1]),
        Err(WgError::Short)
    ) {
        return TestResult::Fail("short WireGuard initiation accepted");
    }
    let mut wrong = init.clone();
    wrong[0] = 2;
    if !matches!(decode_handshake_initiation(&wrong), Err(WgError::BadType)) {
        return TestResult::Fail("WireGuard initiation with the response type accepted");
    }
    if decode_handshake_response(&[2u8; HANDSHAKE_RESPONSE_LEN - 1]).is_ok()
        || decode_cookie_reply(&[3u8; COOKIE_REPLY_LEN - 1]).is_ok()
        || decode_transport_header(&[4u8; TRANSPORT_DATA_MIN_LEN - 1]).is_ok()
    {
        return TestResult::Fail("truncated WireGuard message accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/wireguard",
    smoke_cov_wireguard_rejects_wrong_type_and_length
);

// ═══════════════════════════════════════════════════════════════════════════
// Readiness notifier
// ═══════════════════════════════════════════════════════════════════════════

fn smoke_cov_readiness_generation_advances() -> TestResult {
    // The hook itself is process-global (installed by the epoll layer) and
    // is deliberately left alone; only the generation counter is checked.
    let g0 = crate::readiness::generation();
    crate::readiness::bump_generation();
    let g1 = crate::readiness::generation();
    crate::readiness::notify(u64::MAX - 0x7C);
    let g2 = crate::readiness::generation();
    if g1 <= g0 || g2 <= g1 {
        return TestResult::Fail("readiness generation did not advance on bump / notify");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/coverage/readiness",
    smoke_cov_readiness_generation_advances
);
