//! UDP GSO (`UDP_SEGMENT`) transmit smokes.
//!
//! Each case sends through the real IPv4 (`udp_send_from`) or IPv6
//! (`ipv6_stack::send_udp`) UDP transmit path with a nonzero `gso_size`,
//! captures what reaches the driver and checks it the way a receiver would:
//! one datagram per `gso_size` bytes plus a shorter remainder, each with its
//! own valid IP header, UDP length and UDP checksum, the payloads tiling the
//! original buffer in order. The refusal cases check `udp_send_skb`'s errors
//! and that nothing reaches the wire.
//!
//! Linux refs: `net/ipv4/udp.c` (`udp_send_skb`), `net/ipv6/udp.c`
//! (`udp_v6_send_skb`), `net/ipv4/udp_offload.c` (`__udp_gso_segment`),
//! `net/ipv4/af_inet.c` (`inet_gso_segment`), `net/ipv4/ip_output.c`
//! (`__ip_append_data`, `__ip_make_skb`), `include/linux/udp.h`
//! (`UDP_MAX_SEGMENTS`).
//!
//! State isolation: every smoke resets the interface registry, FIB, ARP,
//! netfilter, pending-UDP queues and fragmentation counters, and uses the
//! `udpgso0` interface, 10.0.93.0/24 and ports 3930x that no other smoke uses.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::AtomicU16;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::ip_output::{IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_WANT};
use crate::pkt::{ip_checksum, ETHERTYPE_IPV4, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_UDP};
use crate::udp_sock::{udp_send_from, SocketAddrV4, UdpError, UdpOptions};

const IFACE: &str = "udpgso0";
const LOCAL: [u8; 4] = [10, 0, 93, 15];
const GW: [u8; 4] = [10, 0, 93, 1];
const PEER: [u8; 4] = [10, 0, 93, 7];
/// On-link, never in the ARP cache: exercises the pending-neighbour queue.
const UNRESOLVED: [u8; 4] = [10, 0, 93, 8];
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x93, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x93, 0x07];
const LATE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x93, 0x08];
const SPORT: u16 = 39301;
const DPORT: u16 = 39302;

const DF: u16 = 0x4000;
const MF: u16 = 0x2000;

static TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn capture(frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
    TX.lock().push(frame.to_vec());
    Ok(())
}

fn drain_frames() -> Vec<Vec<u8>> {
    core::mem::take(&mut *TX.lock())
}

/// The IPv4 packets (Ethernet stripped) transmitted since the last drain.
fn drain_ipv4() -> Vec<Vec<u8>> {
    drain_frames()
        .into_iter()
        .filter(|f| {
            f.len() >= ETH_HDR_LEN + IPV4_HDR_LEN
                && u16::from_be_bytes([f[12], f[13]]) == ETHERTYPE_IPV4
        })
        .map(|f| f[ETH_HDR_LEN..].to_vec())
        .collect()
}

fn reset() {
    crate::tcp::core::__reset_for_test();
    crate::route::__reset_for_test();
    crate::arp_cache::__reset_for_test();
    crate::ifaddr::__reset_for_test();
    crate::bypass::__reset_for_test();
    crate::netfilter::__reset_all_for_test();
    narf_lib::sysctl::ipv4::__reset_for_test();
    crate::ip_fragment::__reset_for_test();
    crate::udp_sock::__reset_pending_udp4_for_test();
    crate::ip_output::__reset_frag_stats_for_test();
    crate::ipv6_stack::__reset_for_test();
    TX.lock().clear();

    crate::iface::register(IFACE, MAC, capture);
    crate::iface::set_mtu(IFACE, 1500);
    crate::iface::set_link_state(IFACE, true);
    crate::iface::set_iface_ipv4_fields(IFACE, LOCAL, GW);
    crate::iface::add_addr(IFACE, LOCAL, 24);
    crate::tcp_stack::__arp_insert_legacy(PEER, PEER_MAC);
    crate::arp_cache::insert(IFACE, PEER, PEER_MAC);
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

fn opts(pmtudisc: i32, gso_size: u16) -> UdpOptions {
    UdpOptions {
        ip_pmtudisc: pmtudisc,
        gso_size,
        ..UdpOptions::default()
    }
}

fn send(payload: &[u8], o: &UdpOptions, dst: [u8; 4]) -> Result<usize, UdpError> {
    udp_send_from(0, SPORT, SocketAddrV4::new(dst, DPORT), payload, o, 0, None)
}

fn run(r: Result<(), &'static str>) -> TestResult {
    match r {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

fn ip_id(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[4], p[5]])
}

fn frag_word(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[6], p[7]])
}

/// Per-datagram payload lengths, the concatenated payload, and the IP IDs.
type Datagrams = (Vec<usize>, Vec<u8>, Vec<u16>);

/// Check every captured packet is one whole UDP datagram from LOCAL:SPORT to
/// `dst`:DPORT — a 20-byte IPv4 header whose length and checksum verify, not
/// a fragment, a UDP length matching the packet and a UDP checksum that
/// verifies (nonzero) — and return their payload lengths, concatenated
/// payload, and IP IDs.
fn datagrams(pkts: &[Vec<u8>], dst: [u8; 4]) -> Result<Datagrams, &'static str> {
    let mut sizes = Vec::new();
    let mut data = Vec::new();
    let mut ids = Vec::new();
    for p in pkts {
        if p[0] != 0x45 || p[9] != IP_PROTO_UDP {
            return Err("a packet is not IPv4/UDP with a 20-byte header");
        }
        if usize::from(u16::from_be_bytes([p[2], p[3]])) != p.len() {
            return Err("an IPv4 total length does not match the packet");
        }
        if ip_checksum(&p[..IPV4_HDR_LEN]) != 0 {
            return Err("an IPv4 header checksum does not verify");
        }
        if frag_word(p) & (MF | 0x1FFF) != 0 {
            return Err("a GSO segment was sent as an IP fragment");
        }
        if p[12..16] != LOCAL || p[16..20] != dst {
            return Err("a segment's addresses are wrong");
        }
        let udp = &p[IPV4_HDR_LEN..];
        if u16::from_be_bytes([udp[0], udp[1]]) != SPORT
            || u16::from_be_bytes([udp[2], udp[3]]) != DPORT
        {
            return Err("a segment's ports are wrong");
        }
        if usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len() {
            return Err("a UDP length does not match its segment");
        }
        if udp[6..8] == [0, 0] {
            return Err("a GSO segment carries no UDP checksum");
        }
        let mut src = [0u8; 4];
        src.copy_from_slice(&p[12..16]);
        if crate::pkt_tcp::ipv4_pseudo_checksum_proto(src, dst, IP_PROTO_UDP, udp) != 0 {
            return Err("a UDP checksum does not verify");
        }
        sizes.push(udp.len() - 8);
        data.extend_from_slice(&udp[8..]);
        ids.push(ip_id(p));
    }
    Ok((sizes, data, ids))
}

/// Five 1200-byte QUIC packets plus a 700-byte tail in one GSO send become
/// six datagrams of 1200 ×5 + 700 payload bytes, each a whole datagram with a
/// verifying UDP checksum, in order; their payloads tile the buffer. The IP
/// IDs run consecutively (`inet_gso_segment`, no FIXEDID for UDP) and DO
/// sets DF on every one.
fn smoke_udp_gso_v4_splits_into_checksummed_datagrams() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(5 * 1200 + 700);
        if send(&payload, &opts(IP_PMTUDISC_DO, 1200), PEER) != Ok(payload.len()) {
            return Err("a 6700-byte GSO send with gso_size 1200 failed");
        }
        let pkts = drain_ipv4();
        let (sizes, data, ids) = datagrams(&pkts, PEER)?;
        if sizes != [1200, 1200, 1200, 1200, 1200, 700] {
            return Err("segments are not 5 x 1200 + 700 bytes");
        }
        if data != payload {
            return Err("the segments' payloads do not tile the sent buffer in order");
        }
        if ids.windows(2).any(|w| w[1] != w[0].wrapping_add(1)) {
            return Err("segment IP IDs are not consecutive");
        }
        if pkts.iter().any(|p| frag_word(p) & DF == 0) {
            return Err("an IP_PMTUDISC_DO segment lacks DF");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "net/udp_gso",
    smoke_udp_gso_v4_splits_into_checksummed_datagrams
);

/// An exact multiple has no short tail; a payload no larger than gso_size is
/// one ordinary datagram. Under IP_PMTUDISC_WANT the GSO skb is longer than
/// the MTU, so `__ip_make_skb` leaves DF clear on every segment, while a
/// single datagram that fits gets DF as usual.
fn smoke_udp_gso_v4_exact_multiple_and_single() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(3 * 1000);
        if send(&payload, &opts(IP_PMTUDISC_WANT, 1000), PEER) != Ok(3000) {
            return Err("a 3 x 1000 GSO send failed");
        }
        let pkts = drain_ipv4();
        let (sizes, data, _) = datagrams(&pkts, PEER)?;
        if sizes != [1000, 1000, 1000] || data != payload {
            return Err("an exact multiple did not become 3 x 1000 bytes");
        }
        if pkts.iter().any(|p| frag_word(p) & DF != 0) {
            return Err("WANT segments of a GSO skb longer than the MTU carry DF");
        }
        let small = pattern(900);
        if send(&small, &opts(IP_PMTUDISC_WANT, 1000), PEER) != Ok(900) {
            return Err("a GSO send no larger than gso_size failed");
        }
        let pkts = drain_ipv4();
        let (sizes, data, _) = datagrams(&pkts, PEER)?;
        if sizes != [900] || data != small {
            return Err("a payload <= gso_size was not one ordinary datagram");
        }
        if frag_word(&pkts[0]) & DF == 0 {
            return Err("a WANT datagram that fits the MTU lacks DF");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_v4_exact_multiple_and_single);

/// `udp_send_skb`: `hlen + min(datalen, gso_size) > fragsize` is EMSGSIZE,
/// whatever IP_MTU_DISCOVER says — on a 1500-byte link 1472 is the largest
/// segment, and a payload under gso_size is measured by its own length (so
/// even a DONT socket that would otherwise fragment is refused). Nothing
/// reaches the wire.
fn smoke_udp_gso_v4_segment_over_mtu_emsgsize() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(4 * 1473);
        if send(&payload, &opts(IP_PMTUDISC_DO, 1473), PEER) != Err(UdpError::MsgTooLong) {
            return Err("gso_size 1473 on a 1500-byte link is not EMSGSIZE");
        }
        if send(&payload[..1473], &opts(IP_PMTUDISC_DONT, 2000), PEER) != Err(UdpError::MsgTooLong)
        {
            return Err("a 1473-byte single-segment GSO send is not EMSGSIZE under DONT");
        }
        if !drain_ipv4().is_empty() {
            return Err("a refused GSO send reached the wire");
        }
        if send(&payload[..4 * 1472], &opts(IP_PMTUDISC_DO, 1472), PEER) != Ok(4 * 1472) {
            return Err("gso_size 1472 (a full 1500-byte packet) was refused");
        }
        let (sizes, _, _) = datagrams(&drain_ipv4(), PEER)?;
        if sizes != [1472; 4] {
            return Err("gso_size 1472 did not send four full-MTU datagrams");
        }
        // The device MTU follows: at 1280, 1252 is the largest segment.
        crate::iface::set_mtu(IFACE, 1280);
        if send(&payload[..2 * 1253], &opts(IP_PMTUDISC_DO, 1253), PEER)
            != Err(UdpError::MsgTooLong)
        {
            return Err("gso_size 1253 on a 1280-byte link is not EMSGSIZE");
        }
        if send(&payload[..2 * 1252], &opts(IP_PMTUDISC_DO, 1252), PEER) != Ok(2 * 1252) {
            return Err("gso_size 1252 on a 1280-byte link was refused");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_v4_segment_over_mtu_emsgsize);

/// `datalen > gso_size * UDP_MAX_SEGMENTS` is EINVAL: 128 one-byte segments
/// are the most one send may carry. A GSO send also refuses SO_NO_CHECK
/// (`sk_no_check_tx`) with EINVAL, even when it would not be split; without
/// GSO, SO_NO_CHECK sends a zero UDP checksum.
fn smoke_udp_gso_v4_einval_cases() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(256);
        if send(&payload[..129], &opts(IP_PMTUDISC_DO, 1), PEER) != Err(UdpError::GsoInvalid) {
            return Err("129 one-byte segments are not EINVAL");
        }
        if send(&payload[..256], &opts(IP_PMTUDISC_DO, 2), PEER) != Ok(256) {
            return Err("128 two-byte segments were refused");
        }
        let (sizes, _, _) = datagrams(&drain_ipv4(), PEER)?;
        if sizes.len() != 128 || sizes.iter().any(|s| *s != 2) {
            return Err("256 bytes at gso_size 2 did not become 128 datagrams");
        }
        if send(&payload[..128], &opts(IP_PMTUDISC_DO, 1), PEER) != Ok(128) {
            return Err("128 one-byte segments were refused");
        }
        if drain_ipv4().len() != 128 {
            return Err("128 one-byte segments did not reach the wire");
        }
        let no_check = UdpOptions {
            no_check_tx: true,
            ..opts(IP_PMTUDISC_DO, 1200)
        };
        if send(&payload[..100], &no_check, PEER) != Err(UdpError::GsoInvalid) {
            return Err("a GSO send with SO_NO_CHECK is not EINVAL");
        }
        if !drain_ipv4().is_empty() {
            return Err("a refused GSO send reached the wire");
        }
        let plain_no_check = UdpOptions {
            no_check_tx: true,
            ..opts(IP_PMTUDISC_DO, 0)
        };
        if send(&payload[..100], &plain_no_check, PEER) != Ok(100) {
            return Err("an SO_NO_CHECK send without GSO failed");
        }
        let pkts = drain_ipv4();
        if pkts.len() != 1 || pkts[0][IPV4_HDR_LEN + 6..IPV4_HDR_LEN + 8] != [0, 0] {
            return Err("SO_NO_CHECK did not send a zero UDP checksum");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_v4_einval_cases);

/// A GSO send is appended against IP_MAX_MTU: under DO a 6000-byte payload
/// (well over the 1500-byte MTU that limits an ordinary DO send) is accepted,
/// and the IPv4 ceiling — 65507 bytes of payload — still applies.
fn smoke_udp_gso_v4_appended_against_ip_max_mtu() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(65_508);
        if send(&payload[..6000], &opts(IP_PMTUDISC_DO, 0), PEER).is_ok() {
            return Err("an ordinary 6000-byte DO send on a 1500-byte link was accepted");
        }
        if send(&payload[..6000], &opts(IP_PMTUDISC_DO, 1200), PEER) != Ok(6000) {
            return Err("a 6000-byte DO GSO send was refused");
        }
        if drain_ipv4().len() != 5 {
            return Err("6000 bytes at gso_size 1200 did not become 5 datagrams");
        }
        if send(&payload, &opts(IP_PMTUDISC_DO, 1200), PEER).is_ok() {
            return Err("a 65508-byte GSO payload was accepted");
        }
        if send(&payload[..65_507], &opts(IP_PMTUDISC_DO, 1200), PEER) != Ok(65_507) {
            return Err("a 65507-byte GSO payload was refused");
        }
        let (sizes, data, _) = datagrams(&drain_ipv4(), PEER)?;
        if sizes.len() != 55 || sizes[54] != 65_507 - 54 * 1200 || data != payload[..65_507] {
            return Err("65507 bytes at gso_size 1200 did not become 54 x 1200 + 707");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_v4_appended_against_ip_max_mtu);

/// A connected socket's GSO send takes one `inet_id` value for the whole skb
/// and its segments count up from it.
fn smoke_udp_gso_v4_connected_ids() -> TestResult {
    run((|| {
        reset();
        let inet_id = AtomicU16::new(500);
        let payload = pattern(3 * 1200);
        let sent = udp_send_from(
            0,
            SPORT,
            SocketAddrV4::new(PEER, DPORT),
            &payload,
            &opts(IP_PMTUDISC_DO, 1200),
            0,
            Some(&inet_id),
        );
        if sent != Ok(3600) {
            return Err("a connected GSO send failed");
        }
        let (_, _, ids) = datagrams(&drain_ipv4(), PEER)?;
        if ids != [501, 502, 503] {
            return Err("segments of a connected GSO send are not inet_id+1, +2, +3");
        }
        if inet_id.load(core::sync::atomic::Ordering::Relaxed) != 501 {
            return Err("a GSO send advanced inet_id by more than one");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_v4_connected_ids);

/// GSO segments to an unresolved neighbour are all queued; once ARP answers
/// they leave in order with the learned MAC.
fn smoke_udp_gso_v4_arp_pending_queues_every_segment() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(4 * 1200);
        if send(&payload, &opts(IP_PMTUDISC_DO, 1200), UNRESOLVED) != Ok(4800) {
            return Err("a GSO send to an unresolved neighbour was not accepted");
        }
        if crate::udp_sock::__pending_udp4_test_count(0) != 4 {
            return Err("not every segment was queued on the unresolved neighbour");
        }
        if !drain_ipv4().is_empty() {
            return Err("a segment left before the neighbour resolved");
        }
        crate::udp_sock::neighbor_resolved(0, IFACE, UNRESOLVED, LATE_MAC);
        let frames = drain_frames();
        if frames.len() != 4 || frames.iter().any(|f| f[0..6] != LATE_MAC) {
            return Err("the four segments did not leave with the resolved MAC");
        }
        let pkts: Vec<Vec<u8>> = frames.iter().map(|f| f[ETH_HDR_LEN..].to_vec()).collect();
        let (sizes, data, _) = datagrams(&pkts, UNRESOLVED)?;
        if sizes != [1200; 4] || data != payload {
            return Err("queued segments were not flushed whole and in order");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "net/udp_gso",
    smoke_udp_gso_v4_arp_pending_queues_every_segment
);

/// The pure check, against `udp_send_skb`'s order: the MTU check before the
/// segment-count check before the no-checksum check.
fn smoke_udp_gso_check_order() -> TestResult {
    use crate::udp_gso::{gso_check, GsoError};
    run((|| {
        // Over the MTU and over the segment limit and no-check: EMSGSIZE.
        if gso_check(20, 1473 * 200, 1473, 1500, true) != Err(GsoError::MsgSize) {
            return Err("the MTU check does not come first");
        }
        // Within the MTU, over the segment limit and no-check: EINVAL.
        if gso_check(20, 100 * 129, 100, 1500, true) != Err(GsoError::Invalid) {
            return Err("the segment-count check does not come second");
        }
        if gso_check(20, 100, 1200, 1500, true) != Err(GsoError::Invalid) {
            return Err("no-check is not refused for an unsplit GSO send");
        }
        if gso_check(20, 1200, 1200, 1500, false) != Ok(false) {
            return Err("a payload equal to gso_size is split");
        }
        if gso_check(20, 1201, 1200, 1500, false) != Ok(true) {
            return Err("a payload one byte over gso_size is not split");
        }
        if gso_check(40, 1233, 1233, 1280, false) != Err(GsoError::MsgSize)
            || gso_check(40, 1232, 1232, 1280, false) != Ok(false)
        {
            return Err("the IPv6 header length is not counted");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_check_order);

// ── IPv6 ────────────────────────────────────────────────────────────────────

const V6_SRC: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x93, 0x01];
const V6_ALL_NODES: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const ETHERTYPE_IPV6: u16 = 0x86DD;

fn send6(
    payload: &[u8],
    tx: crate::ipv6_stack::Udp6TxOpts,
) -> Result<usize, crate::ipv6_stack::Udp6SendError> {
    let ifindex = crate::iface::ifindex_of(IFACE).unwrap_or(0);
    crate::ipv6_stack::send_udp(
        0,
        Some(V6_SRC),
        SPORT,
        V6_ALL_NODES,
        DPORT,
        payload,
        ifindex,
        1,
        0,
        None,
        2, // IPV6_PMTUDISC_DO
        false,
        tx,
    )
}

/// The UDP segments of the IPv6 frames transmitted since the last drain,
/// after checking each one's payload length, UDP length and checksum.
fn drain_udp6() -> Result<Vec<Vec<u8>>, &'static str> {
    let mut out = Vec::new();
    for f in drain_frames() {
        if u16::from_be_bytes([f[12], f[13]]) != ETHERTYPE_IPV6 {
            continue;
        }
        let ip = &f[ETH_HDR_LEN..];
        if ip[6] != 17 {
            return Err("an IPv6 GSO segment is not a whole UDP datagram");
        }
        let udp = &ip[40..];
        if usize::from(u16::from_be_bytes([ip[4], ip[5]])) != udp.len()
            || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
        {
            return Err("an IPv6 payload / UDP length does not match the segment");
        }
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&ip[8..24]);
        dst.copy_from_slice(&ip[24..40]);
        if udp[6..8] != [0, 0] && crate::pkt_ipv6::pseudo_checksum(src, dst, 17, udp) != 0 {
            return Err("an IPv6 UDP checksum does not verify");
        }
        out.push(udp.to_vec());
    }
    Ok(out)
}

/// IPv6 (`udp_v6_send_skb`): 3 x 1200 + 100 bytes become four datagrams with
/// checksums; a segment over the 1280-byte MTU (40 + 8 + 1233) is EMSGSIZE;
/// 129 segments are EINVAL; UDP_NO_CHECK6_TX refuses GSO with EINVAL and,
/// without GSO, sends a zero checksum.
fn smoke_udp_gso_v6_segments_and_errors() -> TestResult {
    use crate::ipv6_stack::{Udp6SendError, Udp6TxOpts};
    run((|| {
        reset();
        crate::iface::set_mtu(IFACE, 1280);
        let gso = |gso_size| Udp6TxOpts {
            gso_size,
            no_check6_tx: false,
        };
        let payload = pattern(3 * 1200 + 100);
        if send6(&payload, gso(1200)) != Ok(3700) {
            return Err("an IPv6 GSO send failed");
        }
        let segs = drain_udp6()?;
        let sizes: Vec<usize> = segs.iter().map(|u| u.len() - 8).collect();
        if sizes != [1200, 1200, 1200, 100] {
            return Err("IPv6 segments are not 3 x 1200 + 100 bytes");
        }
        if segs.iter().any(|u| u[6..8] == [0, 0]) {
            return Err("an IPv6 GSO segment carries no checksum");
        }
        let data: Vec<u8> = segs.iter().flat_map(|u| u[8..].iter().copied()).collect();
        if data != payload {
            return Err("IPv6 segments do not tile the payload");
        }
        if send6(&payload[..2 * 1233], gso(1233)) != Err(Udp6SendError::MessageTooLong) {
            return Err("an IPv6 segment over the MTU is not EMSGSIZE");
        }
        if send6(&payload[..2 * 1232], gso(1232)) != Ok(2 * 1232) {
            return Err("a full-MTU IPv6 segment was refused");
        }
        let _ = drain_frames();
        if send6(&payload[..129], gso(1)) != Err(Udp6SendError::GsoInvalid) {
            return Err("129 IPv6 segments are not EINVAL");
        }
        let no_check = |gso_size| Udp6TxOpts {
            gso_size,
            no_check6_tx: true,
        };
        if send6(&payload[..100], no_check(1200)) != Err(Udp6SendError::GsoInvalid) {
            return Err("UDP_NO_CHECK6_TX with GSO is not EINVAL");
        }
        if !drain_frames().is_empty() {
            return Err("a refused IPv6 GSO send reached the wire");
        }
        if send6(&payload[..100], no_check(0)) != Ok(100) {
            return Err("a UDP_NO_CHECK6_TX send without GSO failed");
        }
        let segs = drain_udp6()?;
        if segs.len() != 1 || segs[0][6..8] != [0, 0] {
            return Err("UDP_NO_CHECK6_TX did not send a zero checksum");
        }
        Ok(())
    })())
}
kernel_test_in!("net/udp_gso", smoke_udp_gso_v6_segments_and_errors);
