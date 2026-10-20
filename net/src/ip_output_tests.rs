//! IPv4 output fragmentation smokes.
//!
//! Each case sends through a real socket path (`udp_send`, `udp_send_from`,
//! `icmp_echo_send`, an ICMP echo request arriving through
//! `tcp_stack::rx_handler`) or the shared fragmenter, captures what reaches
//! the driver, and checks it the way a receiver would: per-fragment headers
//! and checksums, the fragment geometry `ip_do_fragment` produces, the IP ID,
//! and — by feeding the captured fragments back through the RX reassembly —
//! that they rebuild the original datagram.
//!
//! Linux ref: `net/ipv4/ip_output.c` (`__ip_append_data`, `__ip_make_skb`,
//! `ip_fragment`, `ip_do_fragment`, `ip_frag_next`), `include/net/ip.h`
//! (`ip_select_ident_segs`), `net/ipv4/route.c` (`__ip_select_ident`),
//! `net/ipv4/ip_options.c` (`ip_options_fragment`).
//!
//! State isolation: each smoke resets the interface registry, FIB, ARP,
//! netfilter, TCB table, pending-UDP queue, reassembly queues and the
//! fragmentation counters, and uses the `ipout0` interface, 10.0.92.0/24 and
//! ports 3920x that no other smoke uses.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::ip_output::{
    self, frag_stats_in, FragStats, OutputError, IP_PMTUDISC_DO, IP_PMTUDISC_DONT,
    IP_PMTUDISC_INTERFACE, IP_PMTUDISC_OMIT, IP_PMTUDISC_PROBE, IP_PMTUDISC_WANT,
};
use crate::pkt::{
    ip_checksum, write_eth_header, ETHERTYPE_IPV4, ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_ICMP,
    IP_PROTO_UDP,
};
use crate::udp_sock::{
    udp_bind, udp_close, udp_connect, udp_recv, udp_send, udp_send_from, udp_setsockopt,
    SocketAddrV4, UdpError, UdpOptions, UdpSockOpt,
};

const IFACE: &str = "ipout0";
const LOCAL: [u8; 4] = [10, 0, 92, 15];
const GW: [u8; 4] = [10, 0, 92, 1];
const PEER: [u8; 4] = [10, 0, 92, 7];
/// On-link, never in the ARP cache: exercises the pending-neighbour queue.
const UNRESOLVED: [u8; 4] = [10, 0, 92, 8];
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x92, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x92, 0x07];
const LATE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x92, 0x08];

const DF: u16 = 0x4000;
const MF: u16 = 0x2000;
const OFFSET: u16 = 0x1FFF;

static TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn capture(frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
    TX.lock().push(frame.to_vec());
    Ok(())
}

/// Every Ethernet frame carrying IPv4 transmitted since the last drain.
fn drain_frames() -> Vec<Vec<u8>> {
    core::mem::take(&mut *TX.lock())
        .into_iter()
        .filter(|f| {
            f.len() >= ETH_HDR_LEN + IPV4_HDR_LEN
                && u16::from_be_bytes([f[12], f[13]]) == ETHERTYPE_IPV4
        })
        .collect()
}

/// The IPv4 packets (Ethernet stripped) transmitted since the last drain.
fn drain_ipv4() -> Vec<Vec<u8>> {
    drain_frames()
        .into_iter()
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
    ip_output::__reset_frag_stats_for_test();
    TX.lock().clear();

    crate::iface::register(IFACE, MAC, capture);
    // `register` keeps a re-registered device's MTU; start every case at
    // the Ethernet default.
    crate::iface::set_mtu(IFACE, 1500);
    crate::iface::set_link_state(IFACE, true);
    crate::iface::set_iface_ipv4_fields(IFACE, LOCAL, GW);
    crate::iface::add_addr(IFACE, LOCAL, 24);
    crate::tcp_stack::__arp_insert_legacy(PEER, PEER_MAC);
    crate::arp_cache::insert(IFACE, PEER, PEER_MAC);
    crate::tcp_stack::__arp_insert_legacy(LOCAL, MAC);
    crate::arp_cache::insert(IFACE, LOCAL, MAC);
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 + 5) as u8).collect()
}

fn ip_id(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[4], p[5]])
}

fn frag_word(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[6], p[7]])
}

fn tot_len(p: &[u8]) -> usize {
    u16::from_be_bytes([p[2], p[3]]) as usize
}

/// `(data bytes, offset in 8-byte units, MF, DF)` of each fragment, after
/// checking every header is well-formed: IHL 5, total length equal to the
/// packet, and a header checksum that verifies.
fn geometry(frags: &[Vec<u8>]) -> Result<Vec<(usize, u16, bool, bool)>, &'static str> {
    let mut out = Vec::new();
    for p in frags {
        if p[0] != 0x45 {
            return Err("fragment is not IPv4 with a 20-byte header");
        }
        if tot_len(p) != p.len() {
            return Err("fragment total length does not match its size");
        }
        if ip_checksum(&p[..IPV4_HDR_LEN]) != 0 {
            return Err("fragment header checksum does not verify");
        }
        let w = frag_word(p);
        out.push((p.len() - IPV4_HDR_LEN, w & OFFSET, w & MF != 0, w & DF != 0));
    }
    Ok(out)
}

/// Concatenate the fragments' data in offset order (they must tile).
fn reassemble(frags: &[Vec<u8>]) -> Result<Vec<u8>, &'static str> {
    let mut sorted: Vec<&Vec<u8>> = frags.iter().collect();
    sorted.sort_by_key(|p| frag_word(p) & OFFSET);
    let mut data = Vec::new();
    for p in sorted {
        if ((frag_word(p) & OFFSET) as usize) * 8 != data.len() {
            return Err("fragments leave a gap or overlap");
        }
        data.extend_from_slice(&p[IPV4_HDR_LEN..]);
    }
    Ok(data)
}

/// Hand `packet` to the stack as a frame received on `ipout0`.
fn rx(packet: &[u8]) {
    let mut f = vec![0u8; ETH_HDR_LEN + packet.len()];
    write_eth_header(&mut f, MAC, PEER_MAC, ETHERTYPE_IPV4);
    f[ETH_HDR_LEN..].copy_from_slice(packet);
    crate::tcp_stack::rx_handler(IFACE, &mut f);
}

/// Turn a fragment LOCAL→PEER into the same fragment PEER→LOCAL. The UDP
/// checksum survives: the pseudo-header sum does not depend on which address
/// is the source.
fn reflect(p: &[u8]) -> Vec<u8> {
    let mut q = p.to_vec();
    q[12..16].copy_from_slice(&p[16..20]);
    q[16..20].copy_from_slice(&p[12..16]);
    q[10] = 0;
    q[11] = 0;
    let cs = ip_checksum(&q[..IPV4_HDR_LEN]);
    q[10..12].copy_from_slice(&cs.to_be_bytes());
    q
}

fn run(r: Result<(), &'static str>) -> TestResult {
    match r {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

fn udp_sock(
    port: u16,
    pmtudisc: i32,
) -> Result<alloc::sync::Arc<crate::udp_sock::UdpSocket>, &'static str> {
    udp_bind(
        SocketAddrV4::new(LOCAL, port),
        UdpOptions {
            ip_pmtudisc: pmtudisc,
            ..UdpOptions::default()
        },
    )
    .map_err(|_| "bind failed")
}

// ── UDP: fragmentation geometry and reassembly ──────────────────────────────

/// A 4000-byte WANT datagram on a 1500-byte link: three fragments carrying
/// 1480, 1480 and 1048 bytes of the 4008-byte UDP datagram at offsets 0, 185
/// and 370 units, MF on all but the last, no DF, one shared ID, the socket's
/// TTL and TOS on every fragment; fed back through RX reassembly they
/// deliver the original payload. FragOKs 1, FragCreates 3.
fn smoke_ipout_udp_want_fragments_and_reassembles() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(4000);
        let tx = udp_sock(39201, IP_PMTUDISC_WANT)?;
        udp_setsockopt(&tx, UdpSockOpt::IpTtl(33));
        udp_setsockopt(&tx, UdpSockOpt::IpTos(0x28));
        let sent = udp_send(&tx, &payload, Some(SocketAddrV4::new(PEER, 39202)));
        udp_close(&tx);
        if sent != Ok(4000) {
            return Err("udp_send of a 4000-byte datagram did not succeed");
        }
        let frames = drain_frames();
        if frames.iter().any(|f| f.len() > ETH_HDR_LEN + 1500) {
            return Err("a frame exceeds the 1500-byte MTU");
        }
        if frames.iter().any(|f| f[0..6] != PEER_MAC) {
            return Err("a fragment is not addressed to the peer's MAC");
        }
        let frags: Vec<Vec<u8>> = frames.iter().map(|f| f[ETH_HDR_LEN..].to_vec()).collect();
        let geo = geometry(&frags)?;
        let want = [
            (1480, 0, true, false),
            (1480, 185, true, false),
            (1048, 370, false, false),
        ];
        if geo.as_slice() != want {
            return Err("fragment sizes/offsets/MF/DF are not 1480@0+MF, 1480@185+MF, 1048@370");
        }
        let id = ip_id(&frags[0]);
        if frags.iter().any(|p| ip_id(p) != id) {
            return Err("fragments of one datagram carry different IDs");
        }
        if frags
            .iter()
            .any(|p| p[1] != 0x28 || p[8] != 33 || p[9] != IP_PROTO_UDP)
        {
            return Err("TOS / TTL / protocol not applied to every fragment");
        }
        if frags
            .iter()
            .any(|p| p[12..16] != LOCAL || p[16..20] != PEER)
        {
            return Err("fragment addresses are wrong");
        }
        let st = frag_stats_in(0);
        if st
            != (FragStats {
                oks: 1,
                fails: 0,
                creates: 3,
            })
        {
            return Err("FragOKs/FragFails/FragCreates are not 1/0/3");
        }
        // The concatenated data is the UDP datagram, checksum and all.
        let dg = reassemble(&frags)?;
        if dg.len() != 4008 || dg[8..] != payload[..] {
            return Err("fragments do not tile the original UDP datagram");
        }
        if crate::pkt_udp::verify_ipv4(LOCAL, PEER, &dg).is_err() {
            return Err("UDP checksum over the whole datagram does not verify");
        }
        // And a receiver's reassembly rebuilds it.
        let rx_sock = udp_bind(
            SocketAddrV4::new([0, 0, 0, 0], 39202),
            UdpOptions::default(),
        )
        .map_err(|_| "receiver bind failed")?;
        for p in frags.iter().rev() {
            rx(&reflect(p));
        }
        let mut buf = vec![0u8; 8192];
        let got = udp_recv(&rx_sock, &mut buf);
        udp_close(&rx_sock);
        match got {
            Ok((n, from)) if n == 4000 && buf[..n] == payload[..] && from.port == 39201 => Ok(()),
            Ok(_) => Err("reassembled datagram differs from what was sent"),
            Err(_) => Err("captured fragments did not reassemble into a datagram"),
        }
    })())
}
kernel_test_in!(
    "net/ip_output",
    smoke_ipout_udp_want_fragments_and_reassembles
);

/// The MTU boundary: 1472 payload bytes (a 1500-byte packet) go out whole
/// with DF (WANT, fits); 1473 split into 1480 + 1 bytes and lose DF
/// (`__ip_make_skb` sets DF only when `skb->len <= mtu`).
fn smoke_ipout_udp_mtu_boundary() -> TestResult {
    run((|| {
        reset();
        let tx = udp_sock(39203, IP_PMTUDISC_WANT)?;
        let fit = udp_send(&tx, &pattern(1472), Some(SocketAddrV4::new(PEER, 9)));
        let fit_frags = drain_ipv4();
        let over = udp_send(&tx, &pattern(1473), Some(SocketAddrV4::new(PEER, 9)));
        let over_frags = drain_ipv4();
        udp_close(&tx);
        if fit != Ok(1472) || over != Ok(1473) {
            return Err("a send at the MTU boundary failed");
        }
        if geometry(&fit_frags)?.as_slice() != [(1480, 0, false, true)] {
            return Err("a datagram that fits was not sent whole with DF");
        }
        if geometry(&over_frags)?.as_slice() != [(1480, 0, true, false), (1, 185, false, false)] {
            return Err("one byte over the MTU is not 1480@0+MF, 1@185 without DF");
        }
        if frag_stats_in(0).creates != 2 {
            return Err("FragCreates did not count the two fragments");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_udp_mtu_boundary);

/// DO, PROBE and INTERFACE are limited to the MTU: one byte over is EMSGSIZE
/// carrying the MTU for `ip_local_error`, and nothing reaches the wire. At
/// the MTU DO and PROBE set DF and INTERFACE does not (`__ip_make_skb`). The
/// limit follows the device MTU.
fn smoke_ipout_udp_do_probe_interface_emsgsize() -> TestResult {
    run((|| {
        reset();
        for (i, (mode, df)) in [
            (IP_PMTUDISC_DO, true),
            (IP_PMTUDISC_PROBE, true),
            (IP_PMTUDISC_INTERFACE, false),
        ]
        .into_iter()
        .enumerate()
        {
            let tx = udp_sock(39204 + i as u16, mode)?;
            let over = udp_send(&tx, &pattern(1473), Some(SocketAddrV4::new(PEER, 9)));
            let over_frames = drain_ipv4();
            let fit = udp_send(&tx, &pattern(1472), Some(SocketAddrV4::new(PEER, 9)));
            let fit_frames = drain_ipv4();
            udp_close(&tx);
            if over != Err(UdpError::LocalMsgSize { info: 1500 }) {
                return Err("over-MTU DO/PROBE/INTERFACE datagram is not EMSGSIZE(info=mtu)");
            }
            if !over_frames.is_empty() {
                return Err("a refused datagram reached the wire");
            }
            if fit != Ok(1472) || geometry(&fit_frames)?.as_slice() != [(1480, 0, false, df)] {
                return Err("DO/PROBE must set DF at the MTU and INTERFACE must not");
            }
        }
        crate::iface::set_mtu(IFACE, 1400);
        let tx = udp_sock(39207, IP_PMTUDISC_DO)?;
        let over = udp_send(&tx, &pattern(1373), Some(SocketAddrV4::new(PEER, 9)));
        let fit = udp_send(&tx, &pattern(1372), Some(SocketAddrV4::new(PEER, 9)));
        udp_close(&tx);
        if over != Err(UdpError::LocalMsgSize { info: 1400 }) || fit != Ok(1372) {
            return Err("the DO limit did not follow a 1400-byte device MTU");
        }
        if frag_stats_in(0) != FragStats::default() {
            return Err("refusing at send time must not count FragFails");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_udp_do_probe_interface_emsgsize);

/// DONT and OMIT may always fragment and never set DF; their limit is
/// IP_MAX_MTU, so the largest UDP datagram (65507 bytes) goes out as 45
/// fragments.
fn smoke_ipout_udp_dont_omit_fragment_to_ip_max() -> TestResult {
    run((|| {
        reset();
        for (i, mode) in [IP_PMTUDISC_DONT, IP_PMTUDISC_OMIT].into_iter().enumerate() {
            let tx = udp_sock(39208 + i as u16, mode)?;
            let small = udp_send(&tx, b"x", Some(SocketAddrV4::new(PEER, 9)));
            let small_frames = drain_ipv4();
            let max = udp_send(&tx, &pattern(65507), Some(SocketAddrV4::new(PEER, 9)));
            let frags = drain_ipv4();
            udp_close(&tx);
            if small != Ok(1) || geometry(&small_frames)?.as_slice() != [(9, 0, false, false)] {
                return Err("DONT/OMIT set DF on a datagram that fits");
            }
            if max != Ok(65507) {
                return Err("DONT/OMIT refused the largest UDP datagram");
            }
            let geo = geometry(&frags)?;
            if geo.len() != 45 || geo.iter().any(|g| g.3) {
                return Err("65507-byte DONT/OMIT datagram is not 45 fragments without DF");
            }
            let dg = reassemble(&frags)?;
            if dg.len() != 65515 || dg[8..] != pattern(65507)[..] {
                return Err("the 45 fragments do not tile the datagram");
            }
        }
        Ok(())
    })())
}
kernel_test_in!(
    "net/ip_output",
    smoke_ipout_udp_dont_omit_fragment_to_ip_max
);

// ── IP ID selection ─────────────────────────────────────────────────────────

/// Unconnected sockets: fragmented and WANT-fitting datagrams take IDs from
/// `__ip_select_ident`, so two datagrams of one flow never share an ID; a DO
/// datagram (DF, `!ignore_df`) carries ID 0.
fn smoke_ipout_unconnected_ids() -> TestResult {
    run((|| {
        reset();
        let tx = udp_sock(39210, IP_PMTUDISC_WANT)?;
        let dst = Some(SocketAddrV4::new(PEER, 9));
        let _ = udp_send(&tx, &pattern(3000), dst);
        let a = drain_ipv4();
        let _ = udp_send(&tx, &pattern(3000), dst);
        let b = drain_ipv4();
        let _ = udp_send(&tx, b"fits", dst);
        let c = drain_ipv4();
        udp_close(&tx);
        if a.len() != 3 || b.len() != 3 || c.len() != 1 {
            return Err("unexpected fragment counts");
        }
        let (ia, ib, ic) = (ip_id(&a[0]), ip_id(&b[0]), ip_id(&c[0]));
        if a.iter().any(|p| ip_id(p) != ia) || b.iter().any(|p| ip_id(p) != ib) {
            return Err("fragments of one datagram do not share an ID");
        }
        if ia == ib || ib == ic || ia == ic {
            return Err("two datagrams of one flow share an IP ID");
        }
        if ia == 0 && ib == 0 {
            return Err("fragmented datagrams carry ID 0");
        }
        let tx = udp_sock(39211, IP_PMTUDISC_DO)?;
        let _ = udp_send(&tx, b"df", dst);
        let d = drain_ipv4();
        udp_close(&tx);
        if d.len() != 1 || ip_id(&d[0]) != 0 || frag_word(&d[0]) & DF == 0 {
            return Err("an unconnected DO datagram must carry DF and ID 0");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_unconnected_ids);

/// A connected socket numbers its datagrams from its own `inet_id`, DF or
/// fragmented alike: consecutive datagrams take consecutive IDs.
fn smoke_ipout_connected_socket_uses_inet_id() -> TestResult {
    run((|| {
        reset();
        let tx = udp_sock(39212, IP_PMTUDISC_WANT)?;
        udp_connect(&tx, SocketAddrV4::new(PEER, 9));
        let _ = udp_send(&tx, b"one", None);
        let a = drain_ipv4();
        let _ = udp_send(&tx, &pattern(3000), None);
        let b = drain_ipv4();
        let _ = udp_send(&tx, b"three", None);
        let c = drain_ipv4();
        udp_close(&tx);
        if a.len() != 1 || b.len() != 3 || c.len() != 1 {
            return Err("unexpected fragment counts");
        }
        let (ia, ib, ic) = (ip_id(&a[0]), ip_id(&b[0]), ip_id(&c[0]));
        if b.iter().any(|p| ip_id(p) != ib) {
            return Err("fragments of one datagram do not share an ID");
        }
        if ib != ia.wrapping_add(1) || ic != ib.wrapping_add(1) {
            return Err("a connected socket's datagrams do not take consecutive inet_id values");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_connected_socket_uses_inet_id);

// ── Neighbour resolution ────────────────────────────────────────────────────

/// A fragmented datagram to an unresolved neighbour queues every fragment;
/// once ARP answers, all of them go out in order with the learned MAC.
fn smoke_ipout_arp_pending_flushes_all_fragments() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(4000);
        let sent = udp_send_from(
            0,
            39213,
            SocketAddrV4::new(UNRESOLVED, 39214),
            &payload,
            &UdpOptions::default(),
            None,
        );
        if sent != Ok(4000) {
            return Err("a send to an unresolved neighbour was not accepted");
        }
        if crate::udp_sock::__pending_udp4_test_count(0) != 3 {
            return Err("not every fragment was queued on the unresolved neighbour");
        }
        if !drain_ipv4().is_empty() {
            return Err("a fragment left before the neighbour resolved");
        }
        crate::udp_sock::neighbor_resolved(0, IFACE, UNRESOLVED, LATE_MAC);
        let frames = drain_frames();
        if crate::udp_sock::__pending_udp4_test_count(0) != 0 {
            return Err("fragments stayed queued after resolution");
        }
        if frames.len() != 3 || frames.iter().any(|f| f[0..6] != LATE_MAC) {
            return Err("the three fragments did not leave with the resolved MAC");
        }
        let frags: Vec<Vec<u8>> = frames.iter().map(|f| f[ETH_HDR_LEN..].to_vec()).collect();
        let offsets: Vec<u16> = geometry(&frags)?.iter().map(|g| g.1).collect();
        if offsets != [0, 185, 370] {
            return Err("queued fragments were not flushed in order");
        }
        let dg = reassemble(&frags)?;
        if dg[8..] != payload[..] {
            return Err("flushed fragments do not tile the datagram");
        }
        Ok(())
    })())
}
kernel_test_in!(
    "net/ip_output",
    smoke_ipout_arp_pending_flushes_all_fragments
);

// ── ICMP ────────────────────────────────────────────────────────────────────

/// `ping -s 4000`: the echo request leaves as three fragments whose data is
/// one ICMP message with a checksum over the whole of it; DO above the MTU
/// is EMSGSIZE with the MTU.
fn smoke_ipout_icmp_echo_request_fragments() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(4000);
        let sock = crate::icmp_sock::icmp_echo_open();
        let sent =
            crate::icmp_sock::icmp_echo_send(&sock, PEER, 7, &payload, IP_PMTUDISC_WANT, None);
        let frags = drain_ipv4();
        let refused =
            crate::icmp_sock::icmp_echo_send(&sock, PEER, 8, &payload, IP_PMTUDISC_DO, None);
        let refused_frames = drain_ipv4();
        crate::icmp_sock::icmp_echo_close(&sock);
        if sent != Ok(()) {
            return Err("a 4000-byte echo request was not sent");
        }
        let geo = geometry(&frags)?;
        if geo.as_slice()
            != [
                (1480, 0, true, false),
                (1480, 185, true, false),
                (1048, 370, false, false),
            ]
        {
            return Err("echo request fragments have the wrong geometry");
        }
        if frags
            .iter()
            .any(|p| p[9] != IP_PROTO_ICMP || ip_id(p) != ip_id(&frags[0]))
        {
            return Err("echo request fragments disagree on protocol or ID");
        }
        let msg = reassemble(&frags)?;
        if msg.len() != 4008 || msg[0] != 8 || ip_checksum(&msg) != 0 || msg[8..] != payload[..] {
            return Err("reassembled echo request is not the original ICMP message");
        }
        if refused != Err(crate::icmp_sock::IcmpError2::LocalMsgSize { info: 1500 })
            || !refused_frames.is_empty()
        {
            return Err("an over-MTU DO echo request was not refused with EMSGSIZE");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_icmp_echo_request_fragments);

/// A fragmented 4000-byte echo request is reassembled and answered with a
/// fragmented echo reply: the ICMP control socket is IP_PMTUDISC_DONT, so
/// no DF, one ID, and the reply carries the request's payload.
fn smoke_ipout_icmp_echo_reply_fragments() -> TestResult {
    run((|| {
        reset();
        let payload = pattern(4000);
        let mut msg = vec![0u8; 8 + payload.len()];
        msg[0] = 8; // echo request
        msg[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        msg[6..8].copy_from_slice(&9u16.to_be_bytes());
        msg[8..].copy_from_slice(&payload);
        let cs = ip_checksum(&msg);
        msg[2..4].copy_from_slice(&cs.to_be_bytes());
        // Fragment it as PEER would, through the shared fragmenter.
        let mut packet = vec![0u8; IPV4_HDR_LEN + msg.len()];
        packet[0] = 0x45;
        let plen = packet.len() as u16;
        packet[2..4].copy_from_slice(&plen.to_be_bytes());
        packet[4..6].copy_from_slice(&0x7777u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = IP_PROTO_ICMP;
        packet[12..16].copy_from_slice(&PEER);
        packet[16..20].copy_from_slice(&LOCAL);
        packet[IPV4_HDR_LEN..].copy_from_slice(&msg);
        let cs = ip_checksum(&packet[..IPV4_HDR_LEN]);
        packet[10..12].copy_from_slice(&cs.to_be_bytes());
        let mut request = Vec::new();
        ip_output::ip_finish_output(1, &packet, 0, 1500, false, |f| {
            request.push(f.to_vec());
            Ok(())
        })
        .map_err(|_| "could not fragment the request")?;
        for f in &request {
            rx(f);
        }
        let reply = drain_ipv4();
        let geo = geometry(&reply)?;
        if geo.len() != 3 || geo.iter().any(|g| g.3) {
            return Err("echo reply is not three fragments without DF");
        }
        if reply
            .iter()
            .any(|p| ip_id(p) != ip_id(&reply[0]) || p[12..16] != LOCAL || p[16..20] != PEER)
        {
            return Err("echo reply fragments disagree on ID or addresses");
        }
        let body = reassemble(&reply)?;
        if body.len() != msg.len() || body[0] != 0 || ip_checksum(&body) != 0 {
            return Err("reassembled echo reply is not a valid ICMP echo reply");
        }
        if body[4..] != msg[4..] {
            return Err("echo reply does not carry the request's id/seq/payload");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_icmp_echo_reply_fragments);

// ── The shared fragmenter ───────────────────────────────────────────────────

/// A datagram that fits is handed to the output function as the caller's own
/// buffer: no copy, no allocation, no counters.
fn smoke_ipout_fitting_datagram_is_not_copied() -> TestResult {
    run((|| {
        ip_output::__reset_frag_stats_for_test();
        let mut frame = vec![0u8; ETH_HDR_LEN + 100];
        frame[ETH_HDR_LEN] = 0x45;
        frame[ETH_HDR_LEN + 2..ETH_HDR_LEN + 4].copy_from_slice(&100u16.to_be_bytes());
        let mut seen = None;
        ip_output::ip_finish_output(0, &frame, ETH_HDR_LEN, 100, false, |f| {
            seen = Some((f.as_ptr(), f.len()));
            Ok(())
        })
        .map_err(|_| "output failed")?;
        if seen != Some((frame.as_ptr(), frame.len())) {
            return Err("a datagram that fits was copied before output");
        }
        if frag_stats_in(0) != FragStats::default() {
            return Err("a datagram that fits touched the fragmentation counters");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_fitting_datagram_is_not_copied);

/// `ip_options_fragment`: the first fragment carries every option; later
/// fragments keep copied options and have the others overwritten with NOOP,
/// at the same header length. Each piece of a non-final fragment (forwarded
/// fragment of a fragment) keeps MF and adds its offset to the incoming one.
fn smoke_ipout_options_and_refragmentation() -> TestResult {
    run((|| {
        ip_output::__reset_frag_stats_for_test();
        // IHL 7: LSRR-shaped copied option, RR-shaped non-copied option, NOOP, END.
        let opts = [0x83, 3, 4, 0x07, 3, 4, 0x01, 0x00];
        let data = pattern(200);
        let hlen = IPV4_HDR_LEN + opts.len();
        let mut p = vec![0u8; hlen + data.len()];
        p[0] = 0x47;
        let plen = p.len() as u16;
        p[2..4].copy_from_slice(&plen.to_be_bytes());
        p[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes());
        // A middle fragment of a larger datagram: MF, offset 100 units.
        p[6..8].copy_from_slice(&(MF | 100).to_be_bytes());
        p[8] = 9;
        p[9] = IP_PROTO_UDP;
        p[12..16].copy_from_slice(&PEER);
        p[16..20].copy_from_slice(&GW);
        p[IPV4_HDR_LEN..hlen].copy_from_slice(&opts);
        p[hlen..].copy_from_slice(&data);
        let mut out = Vec::new();
        ip_output::ip_finish_output(0, &p, 0, 100, false, |f| {
            out.push(f.to_vec());
            Ok(())
        })
        .map_err(|_| "fragmenting failed")?;
        // 100 - 28 = 72 data bytes per fragment: 72, 72, 56.
        if out.len() != 3 {
            return Err("200 data bytes at MTU 100 with a 28-byte header is not 3 fragments");
        }
        let mut offset = 100u16;
        for (i, f) in out.iter().enumerate() {
            let want_len = if i < 2 { 72 } else { 56 };
            if f[0] != 0x47 || tot_len(f) != f.len() || f.len() != hlen + want_len {
                return Err("fragment header length or total length is wrong");
            }
            if ip_checksum(&f[..hlen]) != 0 {
                return Err("fragment header checksum does not verify");
            }
            if frag_word(f) != MF | offset {
                return Err("refragmented pieces must keep MF and add the base offset");
            }
            if ip_id(f) != 0xBEEF || f[8] != 9 {
                return Err("ID or TTL not copied into a fragment");
            }
            // Offset 100 is not 0, so this was not a datagram's first
            // fragment and the options are left as they arrived.
            if f[IPV4_HDR_LEN..hlen] != opts {
                return Err("options of a non-first fragment were rewritten");
            }
            if f[hlen..] != data[(offset - 100) as usize * 8..][..want_len] {
                return Err("fragment data is wrong");
            }
            offset += (want_len / 8) as u16;
        }
        // Now the datagram's real first fragment: offset 0, no MF.
        p[6..8].copy_from_slice(&0u16.to_be_bytes());
        p[10] = 0;
        p[11] = 0;
        out.clear();
        ip_output::ip_finish_output(0, &p, 0, 100, false, |f| {
            out.push(f.to_vec());
            Ok(())
        })
        .map_err(|_| "fragmenting failed")?;
        let trimmed = [0x83, 3, 4, 0x01, 0x01, 0x01, 0x01, 0x00];
        if out.len() != 3 || out[0][IPV4_HDR_LEN..hlen] != opts {
            return Err("the first fragment must carry every option");
        }
        if out[1..].iter().any(|f| f[IPV4_HDR_LEN..hlen] != trimmed) {
            return Err("later fragments must keep only copied options");
        }
        if frag_word(&out[2]) != 18 || frag_word(&out[0]) != MF {
            return Err("first-fragment offsets/MF are wrong");
        }
        let st = frag_stats_in(0);
        if st.oks != 2 || st.creates != 6 || st.fails != 0 {
            return Err("FragOKs/FragCreates not 2/6");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_options_and_refragmentation);

/// `ip_fragment`: an oversized packet with DF that may not be fragmented
/// locally is refused with EMSGSIZE and counted in FragFails; with
/// `ignore_df` it is fragmented and its fragments carry no DF. An output
/// failure part-way counts FragFails and the fragments already created.
fn smoke_ipout_df_and_output_failure() -> TestResult {
    run((|| {
        ip_output::__reset_frag_stats_for_test();
        let mut p = vec![0u8; 300];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&300u16.to_be_bytes());
        p[6..8].copy_from_slice(&DF.to_be_bytes());
        let r = ip_output::ip_finish_output(0, &p, 0, 100, false, |_| Ok(()));
        if r != Err(OutputError::MsgSize) || frag_stats_in(0).fails != 1 {
            return Err("DF without ignore_df must be EMSGSIZE and count FragFails");
        }
        let mut out = Vec::new();
        ip_output::ip_finish_output(0, &p, 0, 100, true, |f| {
            out.push(f.to_vec());
            Ok(())
        })
        .map_err(|_| "ignore_df datagram was not fragmented")?;
        if out.len() != 4 || out.iter().any(|f| frag_word(f) & DF != 0) {
            return Err("ignore_df fragments must not carry DF");
        }
        let mut n = 0;
        let r = ip_output::ip_finish_output(0, &p, 0, 100, true, |_| {
            n += 1;
            if n == 2 {
                Err(())
            } else {
                Ok(())
            }
        });
        let st = frag_stats_in(0);
        if r != Err(OutputError::Output) || n != 2 {
            return Err("an output failure did not stop fragmentation");
        }
        if st.fails != 2 || st.oks != 1 || st.creates != 4 + 1 {
            return Err("FragFails/FragOKs/FragCreates after a failure are wrong");
        }
        Ok(())
    })())
}
kernel_test_in!("net/ip_output", smoke_ipout_df_and_output_failure);

/// `append_check` and `df_wanted` across every IP_MTU_DISCOVER mode, and
/// `inetdev_valid_mtu`: an MTU below 68 is ENETUNREACH.
fn smoke_ipout_append_check_table() -> TestResult {
    use ip_output::{append_check, df_wanted, AppendError};
    // (mode, limit on bytes after the IP header at MTU 1500)
    let cases = [
        (IP_PMTUDISC_DONT, 65515),
        (IP_PMTUDISC_WANT, 65515),
        (IP_PMTUDISC_DO, 1480),
        (IP_PMTUDISC_PROBE, 1480),
        (IP_PMTUDISC_INTERFACE, 1480),
        (IP_PMTUDISC_OMIT, 65515),
    ];
    for (mode, limit) in cases {
        if append_check(mode, 1500, limit).is_err() {
            return TestResult::Fail("a datagram at the limit was refused");
        }
        if append_check(mode, 1500, limit + 1) != Err(AppendError::MsgSize { info: 1500 }) {
            return TestResult::Fail("one byte over the limit is not EMSGSIZE(info=mtu)");
        }
    }
    if append_check(IP_PMTUDISC_WANT, 67, 1) != Err(AppendError::NetUnreach)
        || append_check(IP_PMTUDISC_WANT, 68, 1).is_err()
    {
        return TestResult::Fail("MTU 67 must be ENETUNREACH and 68 valid");
    }
    // DF: DO/PROBE always; WANT only when it fits; DONT/INTERFACE/OMIT never.
    let df = [
        (IP_PMTUDISC_DONT, false, false),
        (IP_PMTUDISC_WANT, true, false),
        (IP_PMTUDISC_DO, true, true),
        (IP_PMTUDISC_PROBE, true, true),
        (IP_PMTUDISC_INTERFACE, false, false),
        (IP_PMTUDISC_OMIT, false, false),
    ];
    for (mode, fits, over) in df {
        if df_wanted(mode, 1500, 1500) != fits || df_wanted(mode, 1501, 1500) != over {
            return TestResult::Fail("DF rule disagrees with __ip_make_skb");
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/ip_output", smoke_ipout_append_check_table);
