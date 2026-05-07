//! Subsystem smokes for `narf-net`.
//!
//! Migrated from `narf-verification`. Tests register under the
//! `net` subsystem.

extern crate alloc;

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_net_loopback_register() -> TestResult {
    use crate::{bootstrap_authority, register_loopback_named, registry, Loopback};

    // Scheduler must be live: register_loopback_named spawns a
    // forwarder task at registration time (per the Stage-3 spec).
    narf_scheduler::init();

    let authority = bootstrap_authority();
    let before = registry().len();
    let _handle = match register_loopback_named(&authority, "lo.smoke-register") {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("register_loopback_named failed on fresh authority"),
    };
    if registry().len() != before + 1 {
        return TestResult::Fail("registry length didn't grow after register");
    }

    let info = registry().with_interface("lo.smoke-register", |i| (i.mac(), i.mtu(), i.link_up()));
    match info {
        Some((mac, mtu, link)) => {
            if mac != Loopback::DEFAULT_MAC {
                return TestResult::Fail("MAC mismatch");
            }
            if mtu != Loopback::DEFAULT_MTU {
                return TestResult::Fail("MTU mismatch");
            }
            if !link {
                return TestResult::Fail("loopback link not up");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("registered interface not found by name"),
    }
}
kernel_test_in!("net", smoke_net_loopback_register);

fn smoke_net_loopback_roundtrip() -> TestResult {
    // End-to-end zero-copy: write a known payload into a DmaBuffer,
    // wrap as a Frame, send via loopback's tx_ring, recv via rx_ring,
    // verify byte-exact match.
    use crate::{bootstrap_authority, register_loopback_named, registry, Frame};
    use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
    use narf_io::alloc_coherent;
    use narf_lib::id::DomainId;

    const PAYLOAD: [u8; 24] = [
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    static OUTCOME: AtomicU8 = AtomicU8::new(0);
    static GOT_LEN: AtomicU32 = AtomicU32::new(0);

    OUTCOME.store(0, Ordering::Relaxed);
    GOT_LEN.store(0, Ordering::Relaxed);

    narf_scheduler::init();

    let authority = bootstrap_authority();
    if register_loopback_named(&authority, "lo.smoke-roundtrip").is_err() {
        return TestResult::Fail("register_loopback_named failed");
    }

    let tx = registry()
        .with_interface("lo.smoke-roundtrip", |i| i.tx_ring().lock().take())
        .flatten();
    let rx = registry()
        .with_interface("lo.smoke-roundtrip", |i| i.rx_ring().lock().take())
        .flatten();
    let (Some(mut tx), Some(mut rx)) = (tx, rx) else {
        return TestResult::Fail("loopback ring halves missing");
    };

    narf_scheduler::spawn(async move {
        let Ok(buf) = alloc_coherent(PAYLOAD.len(), DomainId::DRIVER_0) else {
            return;
        };
        // SAFETY: buf is exclusively owned here; identity-mapped low-RAM.
        unsafe {
            let dst = buf.phys_addr().as_mut_ptr::<u8>();
            for (i, b) in PAYLOAD.iter().enumerate() {
                core::ptr::write_volatile(dst.add(i), *b);
            }
        }
        let frame = Frame::new(buf, PAYLOAD.len() as u32);
        let _ = tx.send(frame).await;
    });

    narf_scheduler::spawn(async move {
        let Ok(frame) = rx.recv().await else {
            OUTCOME.store(3, Ordering::Relaxed);
            return;
        };
        let len = frame.len();
        GOT_LEN.store(len, Ordering::Relaxed);
        let (buf, used) = frame.into_parts();
        let mut ok = used as usize == PAYLOAD.len();
        // SAFETY: buf ownership transferred here; identity-mapped read.
        unsafe {
            let src = buf.phys_addr().as_ptr::<u8>();
            for (i, expected) in PAYLOAD.iter().enumerate() {
                if core::ptr::read_volatile(src.add(i)) != *expected {
                    ok = false;
                    break;
                }
            }
        }
        OUTCOME.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    });

    narf_scheduler::run_until_empty();

    if GOT_LEN.load(Ordering::Relaxed) == 0 {
        return TestResult::Fail("receiver never observed a frame");
    }
    if GOT_LEN.load(Ordering::Relaxed) as usize != PAYLOAD.len() {
        return TestResult::Fail("frame length didn't match payload length");
    }
    match OUTCOME.load(Ordering::Relaxed) {
        1 => TestResult::Pass,
        2 => TestResult::Fail("payload mismatch after loopback round-trip"),
        3 => TestResult::Fail("rx recv resolved Closed before delivering a frame"),
        _ => TestResult::Fail("receiver task never ran"),
    }
}
kernel_test_in!("net", smoke_net_loopback_roundtrip);

fn smoke_net_loopback_revoked_authority() -> TestResult {
    use crate::{bootstrap_authority, register_loopback_named, RegisterError};

    narf_scheduler::init();

    let authority = bootstrap_authority();
    authority.revoke();
    match register_loopback_named(&authority, "lo.smoke-revoked") {
        Err(RegisterError::AuthorityRevoked) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error variant from revoked-authority register"),
        Ok(_) => TestResult::Fail("register_loopback_named accepted a revoked authority"),
    }
}
kernel_test_in!("net", smoke_net_loopback_revoked_authority);

fn smoke_net_arp_request_builder() -> TestResult {
    use crate::pkt::*;
    let mut buf = [0u8; 64];
    let n = build_arp_request(
        &mut buf,
        [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        [10, 0, 2, 15],
        [10, 0, 2, 2],
    )
    .unwrap_or(0);
    if n != ETH_HDR_LEN + ARP_PAYLOAD_LEN {
        return TestResult::Fail("arp request len wrong");
    }
    let (eth, body) = match parse_eth_header(&buf[..n]) {
        Some(t) => t,
        None => return TestResult::Fail("eth parse"),
    };
    if eth.ethertype != ETHERTYPE_ARP {
        return TestResult::Fail("ethertype != ARP");
    }
    let arp = match parse_arp(body) {
        Some(a) => a,
        None => return TestResult::Fail("arp parse"),
    };
    if arp.op != ARP_OP_REQUEST {
        return TestResult::Fail("ARP op not request");
    }
    if arp.tpa != [10, 0, 2, 2] {
        return TestResult::Fail("ARP tpa mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("net", smoke_net_arp_request_builder);

fn smoke_net_stack_attach_not_implemented() -> TestResult {
    use crate::{AttachError, NetIface, StackAttach, StackDaemon};
    use narf_capabilities::{Cap, Invoke, Write};

    let iface: Cap<NetIface, Write> = Cap::bootstrap();
    let daemon: Cap<StackDaemon, Invoke> = Cap::bootstrap();
    let req = StackAttach { iface, daemon };

    let stub = crate::virtio_net::VirtioNet::new("vnet0", [0; 6], 1500);
    match crate::stack::attach(&req, &stub) {
        Err(AttachError::NotImplemented) => {}
        _ => return TestResult::Fail("attach should surface NotImplemented"),
    }
    iface.revoke();
    match crate::stack::attach(&req, &stub) {
        Err(AttachError::IfaceCapRevoked) => {}
        _ => return TestResult::Fail("revoked iface cap should be rejected first"),
    }
    TestResult::Pass
}
kernel_test_in!("net", smoke_net_stack_attach_not_implemented);

// ── UDP codec smokes ───────────────────────────────────────────────

fn smoke_udp_header_round_trip() -> TestResult {
    use crate::pkt_udp::{UdpHeader, UDP_HDR_LEN};
    let h = UdpHeader {
        src_port: 53,
        dst_port: 5353,
        length: 32,
        checksum: 0xCAFE,
    };
    let bytes = h.encode();
    if bytes.len() != UDP_HDR_LEN {
        return TestResult::Fail("UDP header = 8 bytes");
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != 53 {
        return TestResult::Fail("src port BE");
    }
    let back = UdpHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("UDP header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_header_round_trip);

fn smoke_udp_build_and_verify_ipv4() -> TestResult {
    use crate::pkt_udp::{build_ipv4, verify_ipv4};
    let mut out = [0u8; 64];
    let written = build_ipv4(
        &mut out,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        53,
        b"hello",
    )
    .expect("build");
    if written != 8 + 5 {
        return TestResult::Fail("UDP datagram = 8 hdr + 5 payload");
    }
    verify_ipv4([10, 0, 0, 1], [10, 0, 0, 2], &out[..written]).expect("verify");
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_build_and_verify_ipv4);

fn smoke_udp_disabled_checksum_accepted() -> TestResult {
    use crate::pkt_udp::verify_ipv4;
    // 8-byte header with checksum field = 0 (disabled).
    let buf = [0u8, 53, 0, 53, 0, 8, 0, 0];
    verify_ipv4([0; 4], [0; 4], &buf).expect("disabled checksum should pass");
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_disabled_checksum_accepted);

fn smoke_udp_bad_checksum_rejected() -> TestResult {
    use crate::pkt_udp::{build_ipv4, verify_ipv4, UdpError};
    let mut out = [0u8; 64];
    let written = build_ipv4(
        &mut out,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        53,
        b"hello",
    )
    .expect("build");
    out[12] ^= 0xFF; // tamper payload
    match verify_ipv4([10, 0, 0, 1], [10, 0, 0, 2], &out[..written]) {
        Err(UdpError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("tampered datagram should fail verify"),
    }
}
kernel_test_in!("net/udp", smoke_udp_bad_checksum_rejected);

fn smoke_udp_zero_checksum_transmitted_as_ffff() -> TestResult {
    use crate::pkt_udp::ipv4_pseudo_checksum;
    // Hand-craft a datagram whose 16-bit one's-complement sum lands
    // on `0xFFFF` exactly — `!0xFFFF == 0`, so the helper hits its
    // "substitute 0xFFFF" path. Pseudo-header contributes
    // proto(17) + length(8) = 25; payload's first u16 = 0xFFE6
    // makes the total 0xFFFF.
    let payload = [0xFFu8, 0xE6, 0, 0, 0, 0, 0, 0];
    let v = ipv4_pseudo_checksum([0; 4], [0; 4], &payload);
    if v != 0xFFFF {
        return TestResult::Fail("0 checksum should be transmitted as 0xFFFF");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_zero_checksum_transmitted_as_ffff);

// ── TCP codec smokes ───────────────────────────────────────────────

fn smoke_tcp_header_round_trip() -> TestResult {
    use crate::pkt_tcp::{TcpHeader, FLAG_ACK, FLAG_SYN, TCP_HDR_MIN};
    let h = TcpHeader {
        src_port: 12345,
        dst_port: 80,
        sequence: 0xDEAD_BEEF,
        acknowledgement: 0xCAFE_BABE,
        header_len: TCP_HDR_MIN as u8,
        flags: FLAG_SYN | FLAG_ACK,
        window: 65535,
        checksum: 0xABCD,
        urgent_ptr: 0,
        options: alloc::vec::Vec::new(),
    };
    let bytes = h.encode();
    let (back, n) = TcpHeader::decode(&bytes).expect("decode");
    if n != TCP_HDR_MIN {
        return TestResult::Fail("min header = 20 bytes");
    }
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    // Data Offset field: high nibble of byte 12 = header_len/4 = 5.
    if (bytes[12] >> 4) != 5 {
        return TestResult::Fail("data offset = 5 for 20-byte header");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp", smoke_tcp_header_round_trip);

fn smoke_tcp_flag_bit_positions() -> TestResult {
    use crate::pkt_tcp::{
        FLAG_ACK, FLAG_CWR, FLAG_ECE, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, FLAG_URG,
    };
    if FLAG_FIN != 0x01 {
        return TestResult::Fail("FIN at bit 0");
    }
    if FLAG_SYN != 0x02 {
        return TestResult::Fail("SYN at bit 1");
    }
    if FLAG_RST != 0x04 {
        return TestResult::Fail("RST at bit 2");
    }
    if FLAG_PSH != 0x08 {
        return TestResult::Fail("PSH at bit 3");
    }
    if FLAG_ACK != 0x10 {
        return TestResult::Fail("ACK at bit 4");
    }
    if FLAG_URG != 0x20 {
        return TestResult::Fail("URG at bit 5");
    }
    if FLAG_ECE != 0x40 {
        return TestResult::Fail("ECE at bit 6");
    }
    if FLAG_CWR != 0x80 {
        return TestResult::Fail("CWR at bit 7");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp", smoke_tcp_flag_bit_positions);

fn smoke_tcp_options_decoder_walks_syn_options() -> TestResult {
    use crate::pkt_tcp::{build_syn, iter_options, TcpHeader, TcpOption};
    let h = build_syn(12345, 443, 0x1000_0000, 65535, 1460, 7, 0xCAFE_BEEF);
    let bytes = h.encode();
    let (back, _) = TcpHeader::decode(&bytes).expect("decode");
    let mut saw_mss = false;
    let mut saw_wscale = false;
    let mut saw_sack = false;
    let mut saw_ts = false;
    for opt in iter_options(&back.options) {
        match opt {
            TcpOption::Mss(v) => {
                if v != 1460 {
                    return TestResult::Fail("MSS round-trip");
                }
                saw_mss = true;
            }
            TcpOption::WindowScale(s) => {
                if s != 7 {
                    return TestResult::Fail("Window Scale round-trip");
                }
                saw_wscale = true;
            }
            TcpOption::SackPermitted => saw_sack = true,
            TcpOption::Timestamps { tsval, .. } => {
                if tsval != 0xCAFE_BEEF {
                    return TestResult::Fail("Timestamps tsval round-trip");
                }
                saw_ts = true;
            }
            _ => {}
        }
    }
    if !(saw_mss && saw_wscale && saw_sack && saw_ts) {
        return TestResult::Fail("expected MSS / WS / SACK perm / Timestamps");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp", smoke_tcp_options_decoder_walks_syn_options);

fn smoke_tcp_pseudo_checksum_round_trip() -> TestResult {
    use crate::pkt_tcp::{build_rst, ipv4_pseudo_checksum, verify_ipv4, TcpHeader};
    let mut h = build_rst(80, 12345, 0);
    let mut bytes = h.encode();
    let cs = ipv4_pseudo_checksum([192, 168, 1, 1], [192, 168, 1, 2], &bytes);
    bytes[16..18].copy_from_slice(&cs.to_be_bytes());
    h.checksum = cs;
    verify_ipv4([192, 168, 1, 1], [192, 168, 1, 2], &bytes).expect("verify");
    let _ = TcpHeader::decode(&bytes).expect("decode after install");
    TestResult::Pass
}
kernel_test_in!("net/tcp", smoke_tcp_pseudo_checksum_round_trip);

fn smoke_tcp_decode_rejects_bad_data_offset() -> TestResult {
    use crate::pkt_tcp::{TcpError, TcpHeader};
    let mut buf = [0u8; 20];
    // Data Offset = 4 means header is 16 bytes — below the 20-byte minimum.
    buf[12] = 4 << 4;
    match TcpHeader::decode(&buf) {
        Err(TcpError::BadDataOffset) => TestResult::Pass,
        _ => TestResult::Fail("header < 20 bytes must be rejected"),
    }
}
kernel_test_in!("net/tcp", smoke_tcp_decode_rejects_bad_data_offset);

fn smoke_tcp_options_padding_to_4_byte_boundary() -> TestResult {
    use crate::pkt_tcp::build_syn;
    let h = build_syn(12345, 443, 0, 65535, 1460, 7, 0);
    if h.header_len % 4 != 0 {
        return TestResult::Fail("header length must be multiple of 4 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("net/tcp", smoke_tcp_options_padding_to_4_byte_boundary);

// ── IPv6 + ICMPv6 ND smokes ────────────────────────────────────────

fn smoke_ipv6_header_round_trip() -> TestResult {
    use crate::pkt_ipv6::{Ipv6Header, IPV6_HDR_LEN, NEXT_HEADER_TCP};
    let h = Ipv6Header {
        version: 6,
        traffic_class: 0xCC,
        flow_label: 0xABCDE,
        payload_length: 1280,
        next_header: NEXT_HEADER_TCP,
        hop_limit: 64,
        src_ip: [0x20, 0x01, 0xDB, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42],
        dst_ip: [0x20, 0x01, 0xDB, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x43],
    };
    let bytes = h.encode();
    if bytes.len() != IPV6_HDR_LEN {
        return TestResult::Fail("IPv6 header = 40 bytes");
    }
    if (bytes[0] >> 4) != 6 {
        return TestResult::Fail("version field at top nibble of byte 0");
    }
    let back = Ipv6Header::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("IPv6 header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_ipv6_header_round_trip);

fn smoke_ipv6_decode_rejects_v4_payload() -> TestResult {
    use crate::pkt_ipv6::{Ipv6Error, Ipv6Header};
    let mut buf = [0u8; 40];
    buf[0] = 4 << 4; // version 4
    match Ipv6Header::decode(&buf) {
        Err(Ipv6Error::BadVersion(4)) => TestResult::Pass,
        _ => TestResult::Fail("v4 packet must be rejected"),
    }
}
kernel_test_in!("net/ipv6", smoke_ipv6_decode_rejects_v4_payload);

fn smoke_icmpv6_pseudo_checksum_round_trip() -> TestResult {
    use crate::pkt_ipv6::{pseudo_checksum, NEXT_HEADER_ICMPV6};
    // Tiny synthetic body: ICMPv6 Echo Request with checksum zeroed.
    let body = [128u8, 0, 0, 0, 0, 1, 0, 1];
    let cs = pseudo_checksum([0; 16], [0; 16], NEXT_HEADER_ICMPV6, &body);
    let mut probe = body;
    probe[2] = (cs >> 8) as u8;
    probe[3] = (cs & 0xFF) as u8;
    let verify = pseudo_checksum([0; 16], [0; 16], NEXT_HEADER_ICMPV6, &probe);
    if verify != 0 {
        return TestResult::Fail("checksummed body should sum to 0");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_icmpv6_pseudo_checksum_round_trip);

fn smoke_icmpv6_router_solicitation_layout() -> TestResult {
    use crate::pkt_ipv6::{router_solicitation, ICMPV6_ROUTER_SOLICITATION};
    let body = router_solicitation(&[]);
    if body.len() != 8 {
        return TestResult::Fail("RS without options = 8 bytes");
    }
    if body[0] != ICMPV6_ROUTER_SOLICITATION {
        return TestResult::Fail("type byte = 133");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_icmpv6_router_solicitation_layout);

fn smoke_icmpv6_neighbor_solicitation_carries_target() -> TestResult {
    use crate::pkt_ipv6::{neighbor_solicitation, ICMPV6_NEIGHBOR_SOLICITATION};
    let target = [0x20u8, 0x01, 0xDB, 0x8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
    let body = neighbor_solicitation(target, &[]);
    if body.len() != 24 {
        return TestResult::Fail("NS without options = 24 bytes");
    }
    if body[0] != ICMPV6_NEIGHBOR_SOLICITATION {
        return TestResult::Fail("type byte = 135");
    }
    if &body[8..24] != &target {
        return TestResult::Fail("target IP at bytes 8..24");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_icmpv6_neighbor_solicitation_carries_target);

fn smoke_icmpv6_neighbor_advertisement_flags() -> TestResult {
    use crate::pkt_ipv6::{
        neighbor_advertisement, ICMPV6_NEIGHBOR_ADVERTISEMENT, NA_FLAG_OVERRIDE, NA_FLAG_SOLICITED,
    };
    let target = [0u8; 16];
    let body = neighbor_advertisement(NA_FLAG_SOLICITED | NA_FLAG_OVERRIDE, target, &[]);
    if body[0] != ICMPV6_NEIGHBOR_ADVERTISEMENT {
        return TestResult::Fail("type byte = 136");
    }
    let flags = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    if flags & NA_FLAG_SOLICITED == 0 || flags & NA_FLAG_OVERRIDE == 0 {
        return TestResult::Fail("S + O flags should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_icmpv6_neighbor_advertisement_flags);

fn smoke_icmpv6_router_advertisement_layout() -> TestResult {
    use crate::pkt_ipv6::{
        router_advertisement, ICMPV6_ROUTER_ADVERTISEMENT, RA_FLAG_MANAGED,
    };
    let body = router_advertisement(64, RA_FLAG_MANAGED, 1800, 30_000, 1_000, &[]);
    if body[0] != ICMPV6_ROUTER_ADVERTISEMENT {
        return TestResult::Fail("type byte = 134");
    }
    if body[4] != 64 {
        return TestResult::Fail("CurHopLimit at byte 4");
    }
    if body[5] & RA_FLAG_MANAGED == 0 {
        return TestResult::Fail("M flag at byte 5 bit 7");
    }
    if u16::from_be_bytes([body[6], body[7]]) != 1800 {
        return TestResult::Fail("Router Lifetime at bytes 6..8");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_icmpv6_router_advertisement_layout);

fn smoke_icmpv6_nd_option_round_trip() -> TestResult {
    use crate::pkt_ipv6::{append_nd_option, iter_nd_options, ND_OPT_SOURCE_LINK_LAYER_ADDR};
    let mut out = alloc::vec::Vec::new();
    // SLLAO carries a 6-byte MAC, so option length = 2 + 6 = 8 (= 1 unit of 8 bytes).
    let mac = [0x02u8, 0x42, 0xCA, 0xFE, 0xBE, 0xEF];
    append_nd_option(&mut out, ND_OPT_SOURCE_LINK_LAYER_ADDR, &mac).expect("append");
    let opts: alloc::vec::Vec<_> = iter_nd_options(&out).collect();
    if opts.len() != 1 {
        return TestResult::Fail("expected 1 ND option");
    }
    if opts[0].typ != ND_OPT_SOURCE_LINK_LAYER_ADDR || opts[0].data != mac {
        return TestResult::Fail("SLLAO round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ipv6", smoke_icmpv6_nd_option_round_trip);

// ── DNS codec smokes ───────────────────────────────────────────────

fn smoke_dns_header_round_trip() -> TestResult {
    use crate::pkt_dns::{DnsHeader, FLAG_QR, FLAG_RA, FLAG_RD, RCODE_NOERROR};
    let h = DnsHeader {
        id: 0xCAFE,
        flags: FLAG_QR | FLAG_RD | FLAG_RA | (RCODE_NOERROR as u16),
        qdcount: 1,
        ancount: 2,
        nscount: 0,
        arcount: 0,
    };
    let bytes = h.encode();
    let back = DnsHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    if !back.is_response() {
        return TestResult::Fail("QR bit lost");
    }
    if back.rcode() != RCODE_NOERROR {
        return TestResult::Fail("RCODE in low 4 bits of flags");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_header_round_trip);

fn smoke_dns_encode_name_three_labels() -> TestResult {
    use crate::pkt_dns::encode_name;
    let mut out = alloc::vec::Vec::new();
    encode_name(&mut out, "www.example.com").expect("encode");
    let expected: alloc::vec::Vec<u8> = alloc::vec![
        3, b'w', b'w', b'w',
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        3, b'c', b'o', b'm',
        0,
    ];
    if out != expected {
        return TestResult::Fail("name wire encoding");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_encode_name_three_labels);

fn smoke_dns_decode_name_uncompressed() -> TestResult {
    use crate::pkt_dns::decode_name;
    let mut msg: alloc::vec::Vec<u8> = alloc::vec![0u8; 0];
    msg.extend_from_slice(&[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    let (name, used) = decode_name(&msg, 0).expect("decode");
    if name != "www.example.com" {
        return TestResult::Fail("uncompressed name decode");
    }
    if used != 17 {
        return TestResult::Fail("consumed bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_decode_name_uncompressed);

fn smoke_dns_decode_name_with_compression_pointer() -> TestResult {
    use crate::pkt_dns::decode_name;
    // Lay out a synthetic message:
    //   offset 0..  some bogus header bytes (we don't validate them).
    //   offset 12..28: full name "www.example.com" (17 bytes).
    //   offset 29..31: compressed pointer to offset 12 → 0xC0 0x0C.
    let mut msg: alloc::vec::Vec<u8> = alloc::vec![0u8; 12];
    msg.extend_from_slice(&[3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    msg.extend_from_slice(&[0xC0, 0x0C]);
    let (name, used) = decode_name(&msg, 29).expect("decode");
    if name != "www.example.com" {
        return TestResult::Fail("compressed name decode");
    }
    if used != 2 {
        return TestResult::Fail("compression pointer = 2 bytes consumed at this position");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_decode_name_with_compression_pointer);

fn smoke_dns_a_query_layout() -> TestResult {
    use crate::pkt_dns::{build_a_query, DnsHeader, FLAG_RD, TYPE_A};
    let msg = build_a_query(0x1234, "example.com").expect("build");
    let h = DnsHeader::decode(&msg).expect("decode header");
    if h.id != 0x1234 {
        return TestResult::Fail("transaction ID");
    }
    if h.qdcount != 1 || h.ancount != 0 {
        return TestResult::Fail("question/answer counts");
    }
    if h.flags & FLAG_RD == 0 {
        return TestResult::Fail("RD flag should be set");
    }
    // Query last 4 bytes are QTYPE/QCLASS — QTYPE = 0x0001 (A), QCLASS = 0x0001 (IN).
    let len = msg.len();
    if u16::from_be_bytes([msg[len - 4], msg[len - 3]]) != TYPE_A {
        return TestResult::Fail("QTYPE = A");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_a_query_layout);

fn smoke_dns_question_decode_round_trip() -> TestResult {
    use crate::pkt_dns::{Question, TYPE_AAAA};
    let q = Question {
        name: alloc::string::String::from("ipv6.example"),
        qtype: TYPE_AAAA,
        qclass: 1,
    };
    let mut msg: alloc::vec::Vec<u8> = alloc::vec![0u8; 12]; // dummy header
    q.encode(&mut msg).expect("encode");
    let (back, _) = Question::decode(&msg, 12).expect("decode");
    if back != q {
        return TestResult::Fail("question round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_question_decode_round_trip);

fn smoke_dns_resource_record_decode() -> TestResult {
    use crate::pkt_dns::{ResourceRecord, TYPE_A};
    // RR for example.com IN A 93.184.216.34 with TTL 3600.
    let mut msg: alloc::vec::Vec<u8> = alloc::vec![0u8; 12];
    let name_off = msg.len();
    msg.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
    msg.extend_from_slice(&TYPE_A.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS_IN
    msg.extend_from_slice(&3600u32.to_be_bytes()); // TTL
    msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    msg.extend_from_slice(&[93, 184, 216, 34]);
    let (rr, _) = ResourceRecord::decode(&msg, name_off).expect("decode");
    if rr.name != "example.com" {
        return TestResult::Fail("RR name decode");
    }
    if rr.rtype != TYPE_A {
        return TestResult::Fail("RR type");
    }
    if rr.rdata != [93, 184, 216, 34] {
        return TestResult::Fail("RDATA bytes");
    }
    TestResult::Pass
}
kernel_test_in!("net/dns", smoke_dns_resource_record_decode);

fn smoke_dns_compression_loop_rejected() -> TestResult {
    use crate::pkt_dns::{decode_name, DnsError};
    // Pointer at offset 0 points to itself → infinite loop.
    let msg = [0xC0u8, 0x00];
    match decode_name(&msg, 0) {
        Err(DnsError::BadName) => TestResult::Pass,
        _ => TestResult::Fail("self-pointer must be detected"),
    }
}
kernel_test_in!("net/dns", smoke_dns_compression_loop_rejected);

// ── DHCPv4 codec smokes ────────────────────────────────────────────

fn smoke_dhcp_header_round_trip() -> TestResult {
    use crate::pkt_dhcp::{DhcpHeader, FLAG_BROADCAST, HTYPE_ETHERNET, OP_BOOT_REQUEST};
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&[0x02, 0x42, 0xCA, 0xFE, 0xBE, 0xEF]);
    let h = DhcpHeader {
        op: OP_BOOT_REQUEST,
        htype: HTYPE_ETHERNET,
        hlen: 6,
        hops: 0,
        xid: 0xCAFE_BEEF,
        secs: 0,
        flags: FLAG_BROADCAST,
        ciaddr: [0; 4],
        yiaddr: [0; 4],
        siaddr: [0; 4],
        giaddr: [0; 4],
        chaddr,
    };
    let mut buf = alloc::vec::Vec::new();
    h.encode_into(&mut buf);
    if buf.len() != 240 {
        return TestResult::Fail("DHCP header = 240 bytes incl. magic cookie");
    }
    let back = DhcpHeader::decode(&buf).expect("decode");
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcp", smoke_dhcp_header_round_trip);

fn smoke_dhcp_decode_rejects_bad_magic() -> TestResult {
    use crate::pkt_dhcp::{DhcpError, DhcpHeader};
    let mut buf = [0u8; 240];
    // No magic cookie at offset 236.
    match DhcpHeader::decode(&buf) {
        Err(DhcpError::BadMagic) => {}
        _ => return TestResult::Fail("missing magic cookie must error"),
    }
    // Wrong cookie.
    buf[236..240].copy_from_slice(&[0x99, 0x99, 0x99, 0x99]);
    match DhcpHeader::decode(&buf) {
        Err(DhcpError::BadMagic) => TestResult::Pass,
        _ => TestResult::Fail("wrong cookie must error"),
    }
}
kernel_test_in!("net/dhcp", smoke_dhcp_decode_rejects_bad_magic);

fn smoke_dhcp_options_iterator_skips_pad_and_stops_on_end() -> TestResult {
    use crate::pkt_dhcp::{iter_options, OPT_DHCP_MESSAGE_TYPE, OPT_END, OPT_PAD};
    let buf = [
        OPT_PAD,
        OPT_PAD,
        OPT_DHCP_MESSAGE_TYPE,
        1,
        3,
        OPT_END,
        0xFF,
        0xFF, // garbage past END
    ];
    let recs: alloc::vec::Vec<_> = iter_options(&buf).collect();
    if recs.len() != 1 {
        return TestResult::Fail("only one option before END");
    }
    if recs[0].tag != OPT_DHCP_MESSAGE_TYPE || recs[0].data != [3] {
        return TestResult::Fail("DHCP Message Type round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcp", smoke_dhcp_options_iterator_skips_pad_and_stops_on_end);

fn smoke_dhcp_build_discover_carries_required_options() -> TestResult {
    use crate::pkt_dhcp::{
        build_discover, iter_options, DhcpHeader, DHCPDISCOVER, DHCP_HDR_LEN,
        OPT_CLIENT_IDENTIFIER, OPT_DHCP_MESSAGE_TYPE, OPT_PARAMETER_REQUEST_LIST,
    };
    let mac = [0x02, 0x42, 0xCA, 0xFE, 0xBE, 0xEF];
    let pkt = build_discover(0x1234_5678, mac);
    let h = DhcpHeader::decode(&pkt).expect("header");
    if h.xid != 0x1234_5678 {
        return TestResult::Fail("xid round-trip");
    }
    if h.flags & 0x8000 == 0 {
        return TestResult::Fail("BROADCAST flag should be set");
    }
    let mut saw_msg = false;
    let mut saw_cid = false;
    let mut saw_prl = false;
    for opt in iter_options(&pkt[DHCP_HDR_LEN..]) {
        match opt.tag {
            OPT_DHCP_MESSAGE_TYPE => {
                if opt.data != [DHCPDISCOVER] {
                    return TestResult::Fail("Message Type must be DHCPDISCOVER");
                }
                saw_msg = true;
            }
            OPT_CLIENT_IDENTIFIER => {
                if opt.data.len() != 7 || opt.data[0] != 1 {
                    return TestResult::Fail("Client ID must be hardware-type prefixed");
                }
                if &opt.data[1..7] != &mac {
                    return TestResult::Fail("Client ID MAC mismatch");
                }
                saw_cid = true;
            }
            OPT_PARAMETER_REQUEST_LIST => saw_prl = true,
            _ => {}
        }
    }
    if !(saw_msg && saw_cid && saw_prl) {
        return TestResult::Fail("missing required option");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcp", smoke_dhcp_build_discover_carries_required_options);

fn smoke_dhcp_build_request_carries_server_id_and_requested_ip() -> TestResult {
    use crate::pkt_dhcp::{
        build_request, iter_options, DHCP_HDR_LEN, OPT_REQUESTED_IP, OPT_SERVER_IDENTIFIER,
    };
    let pkt = build_request(0x9A, [0; 6], [10, 0, 0, 42], [10, 0, 0, 1]);
    let mut requested = None;
    let mut server = None;
    for opt in iter_options(&pkt[DHCP_HDR_LEN..]) {
        match opt.tag {
            OPT_REQUESTED_IP => requested = Some(opt.data.to_vec()),
            OPT_SERVER_IDENTIFIER => server = Some(opt.data.to_vec()),
            _ => {}
        }
    }
    if requested.as_deref() != Some(&[10u8, 0, 0, 42][..]) {
        return TestResult::Fail("Requested IP option missing/incorrect");
    }
    if server.as_deref() != Some(&[10u8, 0, 0, 1][..]) {
        return TestResult::Fail("Server Identifier option missing/incorrect");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/dhcp",
    smoke_dhcp_build_request_carries_server_id_and_requested_ip
);

fn smoke_dhcp_message_type_constants() -> TestResult {
    use crate::pkt_dhcp::{DHCPACK, DHCPDISCOVER, DHCPNAK, DHCPOFFER, DHCPREQUEST};
    if DHCPDISCOVER != 1 || DHCPOFFER != 2 || DHCPREQUEST != 3 || DHCPACK != 5 || DHCPNAK != 6 {
        return TestResult::Fail("RFC 2132 §9.6 message-type values");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcp", smoke_dhcp_message_type_constants);

// ── TLS 1.3 framing smokes ─────────────────────────────────────────

fn smoke_tls_record_round_trip() -> TestResult {
    use crate::tls::{Record, CONTENT_TYPE_HANDSHAKE, RECORD_HDR_LEN, TLS_VERSION_TLS_1_2};
    let payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
    let rec = Record {
        content_type: CONTENT_TYPE_HANDSHAKE,
        legacy_version: TLS_VERSION_TLS_1_2,
        fragment: &payload,
    };
    let mut out = alloc::vec::Vec::new();
    rec.encode(&mut out);
    if out.len() != RECORD_HDR_LEN + payload.len() {
        return TestResult::Fail("encoded length");
    }
    let (back, n) = Record::decode(&out).expect("decode");
    if n != out.len() {
        return TestResult::Fail("decode should consume entire record");
    }
    if back != rec {
        return TestResult::Fail("record round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tls", smoke_tls_record_round_trip);

fn smoke_tls_record_rejects_oversize_length() -> TestResult {
    use crate::tls::{Record, TlsError, MAX_CIPHERTEXT_LEN};
    // Forge a header claiming a length one byte over the ceiling.
    let too_big = (MAX_CIPHERTEXT_LEN + 1) as u16;
    let mut buf = alloc::vec::Vec::with_capacity(5);
    buf.push(0x17);
    buf.extend_from_slice(&0x0303u16.to_be_bytes());
    buf.extend_from_slice(&too_big.to_be_bytes());
    match Record::decode(&buf) {
        Err(TlsError::RecordTooLong) => TestResult::Pass,
        _ => TestResult::Fail("oversize record must be rejected"),
    }
}
kernel_test_in!("net/tls", smoke_tls_record_rejects_oversize_length);

fn smoke_tls_handshake_message_round_trip() -> TestResult {
    use crate::tls::{HandshakeMessage, HANDSHAKE_HDR_LEN, HS_CLIENT_HELLO};
    let body = alloc::vec![0x42u8; 100];
    let m = HandshakeMessage {
        msg_type: HS_CLIENT_HELLO,
        body: &body,
    };
    let mut out = alloc::vec::Vec::new();
    m.encode(&mut out);
    if out.len() != HANDSHAKE_HDR_LEN + body.len() {
        return TestResult::Fail("handshake header is 4 bytes");
    }
    if out[1] != 0 || out[2] != 0 || out[3] != 100 {
        return TestResult::Fail("length is 24-bit big-endian");
    }
    let (back, _) = HandshakeMessage::decode(&out).expect("decode");
    if back != m {
        return TestResult::Fail("handshake round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tls", smoke_tls_handshake_message_round_trip);

fn smoke_tls_record_for_handshake_uses_legacy_version() -> TestResult {
    use crate::tls::{
        record_for_handshake, HandshakeMessage, Record, CONTENT_TYPE_HANDSHAKE, HS_SERVER_HELLO,
        TLS_VERSION_TLS_1_2,
    };
    let body = [0u8; 16];
    let m = HandshakeMessage {
        msg_type: HS_SERVER_HELLO,
        body: &body,
    };
    let bytes = record_for_handshake(&m);
    let (rec, _) = Record::decode(&bytes).expect("decode");
    if rec.content_type != CONTENT_TYPE_HANDSHAKE {
        return TestResult::Fail("ContentType = handshake");
    }
    if rec.legacy_version != TLS_VERSION_TLS_1_2 {
        return TestResult::Fail("RFC 8446: legacy_record_version = 0x0303");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/tls",
    smoke_tls_record_for_handshake_uses_legacy_version
);

fn smoke_tls_alert_round_trip() -> TestResult {
    use crate::tls::{Alert, ALERT_CLOSE_NOTIFY, ALERT_LEVEL_WARNING};
    let a = Alert {
        level: ALERT_LEVEL_WARNING,
        description: ALERT_CLOSE_NOTIFY,
    };
    let bytes = a.encode();
    let back = Alert::decode(&bytes).expect("decode");
    if back != a {
        return TestResult::Fail("alert round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tls", smoke_tls_alert_round_trip);

fn smoke_tls_record_for_alert_layout() -> TestResult {
    use crate::tls::{
        record_for_alert, Alert, Record, ALERT_HANDSHAKE_FAILURE, ALERT_LEVEL_FATAL,
        CONTENT_TYPE_ALERT,
    };
    let bytes = record_for_alert(Alert {
        level: ALERT_LEVEL_FATAL,
        description: ALERT_HANDSHAKE_FAILURE,
    });
    let (rec, _) = Record::decode(&bytes).expect("decode");
    if rec.content_type != CONTENT_TYPE_ALERT {
        return TestResult::Fail("ContentType = alert");
    }
    if rec.fragment != [ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE] {
        return TestResult::Fail("alert payload mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("net/tls", smoke_tls_record_for_alert_layout);

fn smoke_tls_extension_constants() -> TestResult {
    use crate::tls::{
        EXT_KEY_SHARE, EXT_PRE_SHARED_KEY, EXT_SERVER_NAME, EXT_SUPPORTED_VERSIONS,
    };
    if EXT_SERVER_NAME != 0 {
        return TestResult::Fail("server_name = 0");
    }
    if EXT_PRE_SHARED_KEY != 41 {
        return TestResult::Fail("pre_shared_key = 41");
    }
    if EXT_SUPPORTED_VERSIONS != 43 {
        return TestResult::Fail("supported_versions = 43");
    }
    if EXT_KEY_SHARE != 51 {
        return TestResult::Fail("key_share = 51");
    }
    TestResult::Pass
}
kernel_test_in!("net/tls", smoke_tls_extension_constants);

// ── HTTP/1.1 framing smokes ────────────────────────────────────────

fn smoke_http_request_line_round_trip() -> TestResult {
    use crate::http::RequestLine;
    let r = RequestLine {
        method: alloc::string::String::from("GET"),
        target: alloc::string::String::from("/index.html"),
        version: alloc::string::String::from("HTTP/1.1"),
    };
    let mut out = alloc::vec::Vec::new();
    r.encode(&mut out);
    if &out[..] != b"GET /index.html HTTP/1.1\r\n" {
        return TestResult::Fail("request-line wire form");
    }
    let (back, used) = RequestLine::decode(&out).expect("decode");
    if used != out.len() {
        return TestResult::Fail("decode should consume CRLF");
    }
    if back != r {
        return TestResult::Fail("request-line round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/http", smoke_http_request_line_round_trip);

fn smoke_http_status_line_round_trip() -> TestResult {
    use crate::http::StatusLine;
    let s = StatusLine {
        version: alloc::string::String::from("HTTP/1.1"),
        status_code: 404,
        reason: alloc::string::String::from("Not Found"),
    };
    let mut out = alloc::vec::Vec::new();
    s.encode(&mut out);
    if &out[..] != b"HTTP/1.1 404 Not Found\r\n" {
        return TestResult::Fail("status-line wire form");
    }
    let (back, _) = StatusLine::decode(&out).expect("decode");
    if back != s {
        return TestResult::Fail("status-line round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/http", smoke_http_status_line_round_trip);

fn smoke_http_headers_round_trip() -> TestResult {
    use crate::http::{append_end_of_headers, append_field, parse_headers};
    let mut out = alloc::vec::Vec::new();
    append_field(&mut out, "Host", "example.com");
    append_field(&mut out, "Content-Length", "5");
    append_field(&mut out, "Connection", "close");
    append_end_of_headers(&mut out);
    let (fields, used) = parse_headers(&out).expect("parse");
    if used != out.len() {
        return TestResult::Fail("parse should consume the empty terminator line");
    }
    if fields.len() != 3 {
        return TestResult::Fail("expected 3 fields");
    }
    if fields[0].name != "Host" || fields[0].value != "example.com" {
        return TestResult::Fail("Host field round-trip");
    }
    if fields[1].name != "Content-Length" || fields[1].value != "5" {
        return TestResult::Fail("Content-Length field round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/http", smoke_http_headers_round_trip);

fn smoke_http_headers_handle_obs_fold_whitespace() -> TestResult {
    use crate::http::parse_headers;
    let buf = b"X-Trim:    value-with-leading-and-trailing-ows   \r\n\r\n";
    let (fields, _) = parse_headers(buf).expect("parse");
    if fields[0].value != "value-with-leading-and-trailing-ows" {
        return TestResult::Fail("OWS around field-value should be trimmed");
    }
    TestResult::Pass
}
kernel_test_in!("net/http", smoke_http_headers_handle_obs_fold_whitespace);

fn smoke_http_headers_reject_missing_colon() -> TestResult {
    use crate::http::{parse_headers, HttpError};
    let buf = b"BogusLineWithoutColon\r\n\r\n";
    match parse_headers(buf) {
        Err(HttpError::BadFieldLine) => TestResult::Pass,
        _ => TestResult::Fail("missing-colon line must error"),
    }
}
kernel_test_in!("net/http", smoke_http_headers_reject_missing_colon);

fn smoke_http_chunked_round_trip() -> TestResult {
    use crate::http::{encode_chunk, iter_chunks};
    let mut out = alloc::vec::Vec::new();
    encode_chunk(&mut out, b"hello ");
    encode_chunk(&mut out, b"world");
    encode_chunk(&mut out, &[]); // terminator
    let chunks: alloc::vec::Vec<_> = iter_chunks(&out).collect::<Result<_, _>>().expect("decode");
    if chunks.len() != 3 {
        return TestResult::Fail("expected 3 chunks (incl. terminator)");
    }
    if chunks[0].data != b"hello " {
        return TestResult::Fail("first chunk data");
    }
    if chunks[1].data != b"world" {
        return TestResult::Fail("second chunk data");
    }
    if !chunks[2].data.is_empty() {
        return TestResult::Fail("terminator must be empty");
    }
    TestResult::Pass
}
kernel_test_in!("net/http", smoke_http_chunked_round_trip);

fn smoke_http_chunked_strips_chunk_ext() -> TestResult {
    use crate::http::iter_chunks;
    // 5 bytes of data, with a chunk-ext that should be ignored.
    let buf = b"5;ext=value\r\nhello\r\n0\r\n";
    let chunks: alloc::vec::Vec<_> =
        iter_chunks(buf).collect::<Result<_, _>>().expect("decode");
    if chunks[0].data != b"hello" {
        return TestResult::Fail("chunk-ext was not stripped");
    }
    TestResult::Pass
}
kernel_test_in!("net/http", smoke_http_chunked_strips_chunk_ext);

// ── mDNS / DNS-SD smokes ───────────────────────────────────────────

fn smoke_mdns_multicast_addresses() -> TestResult {
    use crate::pkt_mdns::{MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT};
    if MDNS_PORT != 5353 {
        return TestResult::Fail("mDNS UDP port = 5353");
    }
    if MDNS_IPV4_GROUP != [224, 0, 0, 251] {
        return TestResult::Fail("IPv4 group = 224.0.0.251");
    }
    if MDNS_IPV6_GROUP[0] != 0xFF || MDNS_IPV6_GROUP[15] != 0xFB {
        return TestResult::Fail("IPv6 group = FF02::FB");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_multicast_addresses);

fn smoke_mdns_class_helpers_split_and_recombine() -> TestResult {
    use crate::pkt_mdns::{
        class_with_cache_flush, class_without_cache_flush, qclass_with_unicast_response,
        qclass_without_unicast_bit,
    };
    let cls = class_with_cache_flush(1);
    if cls & 0x8000 == 0 {
        return TestResult::Fail("cache-flush bit at top of CLASS");
    }
    if class_without_cache_flush(cls) != 1 {
        return TestResult::Fail("strip cache-flush bit");
    }
    let qcls = qclass_with_unicast_response(1);
    if qcls & 0x8000 == 0 {
        return TestResult::Fail("unicast-response bit at top of QCLASS");
    }
    if qclass_without_unicast_bit(qcls) != 1 {
        return TestResult::Fail("strip unicast bit");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_class_helpers_split_and_recombine);

fn smoke_mdns_browse_name_format() -> TestResult {
    use crate::pkt_mdns::{service_browse_name, services_meta_name};
    if services_meta_name() != "_services._dns-sd._udp.local" {
        return TestResult::Fail("services meta-query name (RFC 6763 §9)");
    }
    let n = service_browse_name("_http", "_tcp");
    if n != "_http._tcp.local" {
        return TestResult::Fail("service browsing name");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_browse_name_format);

fn smoke_mdns_query_response_headers() -> TestResult {
    use crate::pkt_mdns::{query_header, response_header};
    use crate::pkt_dns::{FLAG_AA, FLAG_QR};
    let q = query_header(2);
    if q.id != 0 {
        return TestResult::Fail("mDNS query ID = 0");
    }
    if q.flags & FLAG_QR != 0 {
        return TestResult::Fail("query has QR=0");
    }
    if q.qdcount != 2 {
        return TestResult::Fail("qdcount round-trip");
    }
    let r = response_header(3, 1);
    if r.flags & FLAG_QR == 0 {
        return TestResult::Fail("response has QR=1");
    }
    if r.flags & FLAG_AA == 0 {
        return TestResult::Fail("response has AA=1 per RFC 6762");
    }
    if r.ancount != 3 || r.arcount != 1 {
        return TestResult::Fail("counts round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_query_response_headers);

fn smoke_mdns_txt_rdata_round_trip() -> TestResult {
    use crate::pkt_mdns::{build_txt_rdata, parse_txt_rdata};
    let rdata = build_txt_rdata(&["path=/api", "version=1.0", "secure"]);
    let parsed = parse_txt_rdata(&rdata);
    if parsed.len() != 3 {
        return TestResult::Fail("expected 3 TXT entries");
    }
    if parsed[0] != "path=/api" {
        return TestResult::Fail("TXT entry 0");
    }
    if parsed[2] != "secure" {
        return TestResult::Fail("flag-style entry without =");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_txt_rdata_round_trip);

fn smoke_mdns_txt_empty_emits_zero_length_string() -> TestResult {
    use crate::pkt_mdns::{build_txt_rdata, parse_txt_rdata};
    let rdata = build_txt_rdata(&[]);
    if rdata != [0u8] {
        return TestResult::Fail("empty TXT must be a single zero-length string");
    }
    let parsed = parse_txt_rdata(&rdata);
    if !parsed.is_empty() {
        return TestResult::Fail("zero-length string parses to empty list");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_txt_empty_emits_zero_length_string);

fn smoke_mdns_srv_round_trip() -> TestResult {
    use crate::pkt_mdns::SrvRecord;
    let s = SrvRecord {
        priority: 10,
        weight: 60,
        port: 8080,
        target: alloc::string::String::from("server.local"),
    };
    let rdata = s.encode();
    if rdata[0] != 0 || rdata[1] != 10 || rdata[2] != 0 || rdata[3] != 60 {
        return TestResult::Fail("SRV priority/weight big-endian");
    }
    if rdata[4] != 0x1F || rdata[5] != 0x90 {
        return TestResult::Fail("SRV port BE");
    }
    // Wrap in a synthetic message with a fake DNS header so decode can
    // resolve the (uncompressed) target.
    let mut msg: alloc::vec::Vec<u8> = alloc::vec![0u8; 12];
    msg.extend_from_slice(&rdata);
    let back = SrvRecord::decode(&msg, 12, rdata.len()).expect("decode");
    if back != s {
        return TestResult::Fail("SRV round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/mdns", smoke_mdns_srv_round_trip);

// ── NTPv4 codec smokes ─────────────────────────────────────────────

fn smoke_ntp_header_round_trip() -> TestResult {
    use crate::pkt_ntp::{
        NtpHeader, LI_NO_WARNING, MODE_CLIENT, NTP_HDR_LEN, NTP_VERSION_4, STRATUM_PRIMARY,
    };
    let h = NtpHeader {
        leap_indicator: LI_NO_WARNING,
        version: NTP_VERSION_4,
        mode: MODE_CLIENT,
        stratum: STRATUM_PRIMARY,
        poll: 6,
        precision: -20,
        root_delay: 0x0001_0000,
        root_dispersion: 0x0002_0000,
        reference_id: *b"GPS\0",
        reference_timestamp: 0xCAFE_BEEF_DEAD_BEEF,
        origin_timestamp: 0x1111,
        receive_timestamp: 0x2222,
        transmit_timestamp: 0x3333,
    };
    let bytes = h.encode();
    if bytes.len() != NTP_HDR_LEN {
        return TestResult::Fail("NTP header = 48 bytes");
    }
    let back = NtpHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("NTP header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ntp", smoke_ntp_header_round_trip);

fn smoke_ntp_li_vn_mode_byte_packing() -> TestResult {
    use crate::pkt_ntp::NtpHeader;
    let mut h = NtpHeader::default();
    h.leap_indicator = 3; // alarm
    h.version = 4;
    h.mode = 3; // client
    let bytes = h.encode();
    // Expected: (3 << 6) | (4 << 3) | 3 = 0xC0 | 0x20 | 3 = 0xE3
    if bytes[0] != 0xE3 {
        return TestResult::Fail("LI/VN/Mode byte 0 packing wrong");
    }
    TestResult::Pass
}
kernel_test_in!("net/ntp", smoke_ntp_li_vn_mode_byte_packing);

fn smoke_ntp_short_fixed_point_round_trip() -> TestResult {
    use crate::pkt_ntp::{short_from_secs_frac, short_to_secs_frac};
    let raw = short_from_secs_frac(2, 0x8000);
    let (secs, frac) = short_to_secs_frac(raw);
    if secs != 2 || frac != 0x8000 {
        return TestResult::Fail("short fixed-point round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ntp", smoke_ntp_short_fixed_point_round_trip);

fn smoke_ntp_unix_epoch_offset_round_trip() -> TestResult {
    use crate::pkt_ntp::{ntp_to_unix, unix_to_ntp, NTP_UNIX_EPOCH_OFFSET_SECS};
    if NTP_UNIX_EPOCH_OFFSET_SECS != 2_208_988_800 {
        return TestResult::Fail("NTP epoch offset = 2_208_988_800 seconds");
    }
    let ntp = unix_to_ntp(1_700_000_000, 0xCAFE_BABE);
    let (unix, frac) = ntp_to_unix(ntp).expect("after epoch");
    if unix != 1_700_000_000 || frac != 0xCAFE_BABE {
        return TestResult::Fail("unix↔NTP round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ntp", smoke_ntp_unix_epoch_offset_round_trip);

fn smoke_ntp_client_request_layout() -> TestResult {
    use crate::pkt_ntp::{client_request, MODE_CLIENT, NTP_VERSION_4};
    let h = client_request(0x1234_5678_9ABC_DEF0);
    if h.mode != MODE_CLIENT {
        return TestResult::Fail("client request mode = 3");
    }
    if h.version != NTP_VERSION_4 {
        return TestResult::Fail("VN = 4");
    }
    if h.transmit_timestamp != 0x1234_5678_9ABC_DEF0 {
        return TestResult::Fail("transmit timestamp should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ntp", smoke_ntp_client_request_layout);

// ── WebSocket framing smokes ───────────────────────────────────────

fn smoke_ws_short_text_frame_round_trip() -> TestResult {
    use crate::ws::{text_frame, Frame, OP_TEXT};
    let f = text_frame("hello", true);
    let bytes = f.encode().expect("encode");
    if bytes.len() != 2 + 5 {
        return TestResult::Fail("Short unmasked text frame: 2 hdr + 5 payload");
    }
    if bytes[0] != 0x80 | OP_TEXT {
        return TestResult::Fail("byte 0 should be FIN | OP_TEXT");
    }
    if bytes[1] != 5 {
        return TestResult::Fail("length field should be 5");
    }
    let (back, n) = Frame::decode(&bytes).expect("decode");
    if n != bytes.len() {
        return TestResult::Fail("decode should consume full frame");
    }
    if back.payload != b"hello" {
        return TestResult::Fail("payload round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ws", smoke_ws_short_text_frame_round_trip);

fn smoke_ws_extended_length_16bit() -> TestResult {
    use crate::ws::{binary_frame, Frame};
    let payload = alloc::vec![0xAAu8; 200];
    let f = binary_frame(payload.clone(), true);
    let bytes = f.encode().expect("encode");
    if bytes[1] != 126 {
        return TestResult::Fail("length-126 marker for 16-bit length");
    }
    if u16::from_be_bytes([bytes[2], bytes[3]]) != 200 {
        return TestResult::Fail("extended 16-bit length");
    }
    let (back, _) = Frame::decode(&bytes).expect("decode");
    if back.payload != payload {
        return TestResult::Fail("200-byte payload round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ws", smoke_ws_extended_length_16bit);

fn smoke_ws_extended_length_64bit() -> TestResult {
    use crate::ws::{binary_frame, Frame};
    let payload = alloc::vec![0xBBu8; 70_000];
    let f = binary_frame(payload.clone(), true);
    let bytes = f.encode().expect("encode");
    if bytes[1] != 127 {
        return TestResult::Fail("length-127 marker for 64-bit length");
    }
    let (back, _) = Frame::decode(&bytes).expect("decode");
    if back.payload.len() != 70_000 {
        return TestResult::Fail("70 000-byte payload round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ws", smoke_ws_extended_length_64bit);

fn smoke_ws_client_masking_unwinds_on_decode() -> TestResult {
    use crate::ws::{Frame, OP_TEXT};
    // Construct a masked client frame manually.
    let key = [0x12u8, 0x34, 0x56, 0x78];
    let mut f = Frame {
        fin: true,
        rsv1: false,
        rsv2: false,
        rsv3: false,
        opcode: OP_TEXT,
        mask: Some(key),
        payload: b"hello".to_vec(),
    };
    let bytes = f.encode().expect("encode");
    if bytes[1] & 0x80 == 0 {
        return TestResult::Fail("MASK bit should be set");
    }
    // Encoded payload should differ from cleartext "hello".
    let payload_off = 2 + 4;
    if &bytes[payload_off..payload_off + 5] == b"hello" {
        return TestResult::Fail("masked payload must not be in cleartext");
    }
    f.payload = b"hello".to_vec();
    let (back, _) = Frame::decode(&bytes).expect("decode");
    if back.payload != b"hello" {
        return TestResult::Fail("decode should unwind the mask");
    }
    if back.mask != Some(key) {
        return TestResult::Fail("masking key should round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/ws", smoke_ws_client_masking_unwinds_on_decode);

fn smoke_ws_close_frame_status_round_trip() -> TestResult {
    use crate::ws::{close_frame, Frame, STATUS_NORMAL_CLOSURE};
    let f = close_frame(STATUS_NORMAL_CLOSURE, "bye");
    let bytes = f.encode().expect("encode");
    let (back, _) = Frame::decode(&bytes).expect("decode");
    if back.opcode != crate::ws::OP_CLOSE {
        return TestResult::Fail("opcode should be CLOSE");
    }
    let code = u16::from_be_bytes([back.payload[0], back.payload[1]]);
    if code != STATUS_NORMAL_CLOSURE {
        return TestResult::Fail("close-frame status code");
    }
    if &back.payload[2..] != b"bye" {
        return TestResult::Fail("close-frame reason");
    }
    TestResult::Pass
}
kernel_test_in!("net/ws", smoke_ws_close_frame_status_round_trip);

fn smoke_ws_control_frame_too_long_rejected() -> TestResult {
    use crate::ws::{ping_frame, WsError};
    let payload = alloc::vec![0u8; 200];
    let f = ping_frame(payload);
    match f.encode() {
        Err(WsError::ControlFrameTooLong) => TestResult::Pass,
        _ => TestResult::Fail("control frame > 125 bytes must be rejected"),
    }
}
kernel_test_in!("net/ws", smoke_ws_control_frame_too_long_rejected);

fn smoke_ws_opcode_constants() -> TestResult {
    use crate::ws::{OP_BINARY, OP_CLOSE, OP_CONTINUATION, OP_PING, OP_PONG, OP_TEXT};
    if OP_CONTINUATION != 0 || OP_TEXT != 1 || OP_BINARY != 2 {
        return TestResult::Fail("data-frame opcode values");
    }
    if OP_CLOSE != 8 || OP_PING != 9 || OP_PONG != 10 {
        return TestResult::Fail("control-frame opcode values");
    }
    TestResult::Pass
}
kernel_test_in!("net/ws", smoke_ws_opcode_constants);

// ── DHCPv6 codec smokes ────────────────────────────────────────────

fn smoke_dhcpv6_header_round_trip() -> TestResult {
    use crate::pkt_dhcpv6::{DhcpV6Header, MT_SOLICIT};
    let h = DhcpV6Header {
        msg_type: MT_SOLICIT,
        transaction_id: 0x12_3456,
    };
    let bytes = h.encode();
    if bytes[0] != MT_SOLICIT {
        return TestResult::Fail("msg-type byte 0");
    }
    if bytes[1] != 0x12 || bytes[2] != 0x34 || bytes[3] != 0x56 {
        return TestResult::Fail("24-bit transaction-id BE");
    }
    let back = DhcpV6Header::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcpv6", smoke_dhcpv6_header_round_trip);

fn smoke_dhcpv6_relay_header_round_trip() -> TestResult {
    use crate::pkt_dhcpv6::{RelayHeader, MT_RELAY_FORW, RELAY_HDR_LEN};
    let h = RelayHeader {
        msg_type: MT_RELAY_FORW,
        hop_count: 1,
        link_address: [0x20, 0x01, 0xDB, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        peer_address: [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    };
    let bytes = h.encode();
    if bytes.len() != RELAY_HDR_LEN {
        return TestResult::Fail("Relay header = 34 bytes");
    }
    let back = RelayHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("Relay header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcpv6", smoke_dhcpv6_relay_header_round_trip);

fn smoke_dhcpv6_options_iter() -> TestResult {
    use crate::pkt_dhcpv6::{
        append_elapsed_time, append_option, append_rapid_commit, iter_options, OPT_DNS_SERVERS,
        OPT_ELAPSED_TIME, OPT_RAPID_COMMIT,
    };
    let mut out = alloc::vec::Vec::new();
    append_elapsed_time(&mut out, 250);
    append_option(&mut out, OPT_DNS_SERVERS, &[0x20, 0x01]);
    append_rapid_commit(&mut out);
    let recs: alloc::vec::Vec<_> = iter_options(&out).collect::<Result<_, _>>().expect("walk");
    if recs.len() != 3 {
        return TestResult::Fail("expected 3 options");
    }
    if recs[0].code != OPT_ELAPSED_TIME || recs[0].data != [0, 250] {
        return TestResult::Fail("Elapsed Time round-trip");
    }
    if recs[2].code != OPT_RAPID_COMMIT || !recs[2].data.is_empty() {
        return TestResult::Fail("Rapid Commit must be a 0-byte option");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcpv6", smoke_dhcpv6_options_iter);

fn smoke_dhcpv6_clientid_duid_ll() -> TestResult {
    use crate::pkt_dhcpv6::{
        append_clientid_duid_ll, iter_options, DUID_TYPE_LL, OPT_CLIENTID,
    };
    let mut out = alloc::vec::Vec::new();
    let mac = [0x02u8, 0x42, 0xCA, 0xFE, 0xBE, 0xEF];
    append_clientid_duid_ll(&mut out, 1, &mac);
    let opt = iter_options(&out).next().unwrap().expect("decode");
    if opt.code != OPT_CLIENTID {
        return TestResult::Fail("Client ID option code = 1");
    }
    let duid_type = u16::from_be_bytes([opt.data[0], opt.data[1]]);
    if duid_type != DUID_TYPE_LL {
        return TestResult::Fail("DUID type = 3 (LL)");
    }
    if &opt.data[4..10] != &mac {
        return TestResult::Fail("MAC at end of DUID-LL");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcpv6", smoke_dhcpv6_clientid_duid_ll);

fn smoke_dhcpv6_solicit_layout() -> TestResult {
    use crate::pkt_dhcpv6::{
        build_solicit, iter_options, DhcpV6Header, MT_SOLICIT, OPT_CLIENTID, OPT_ELAPSED_TIME,
        OPT_ORO,
    };
    let pkt = build_solicit(
        0x12_3456,
        [0x02, 0x42, 0xCA, 0xFE, 0xBE, 0xEF],
        &[crate::pkt_dhcpv6::OPT_DNS_SERVERS, crate::pkt_dhcpv6::OPT_DOMAIN_LIST],
    );
    let h = DhcpV6Header::decode(&pkt).expect("header");
    if h.msg_type != MT_SOLICIT {
        return TestResult::Fail("SOLICIT");
    }
    if h.transaction_id != 0x12_3456 {
        return TestResult::Fail("transaction id round-trip");
    }
    let mut saw_client = false;
    let mut saw_elapsed = false;
    let mut saw_oro = false;
    for opt in iter_options(&pkt[4..]) {
        let opt = opt.expect("parse");
        match opt.code {
            OPT_CLIENTID => saw_client = true,
            OPT_ELAPSED_TIME => saw_elapsed = true,
            OPT_ORO => saw_oro = true,
            _ => {}
        }
    }
    if !(saw_client && saw_elapsed && saw_oro) {
        return TestResult::Fail("missing required option");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcpv6", smoke_dhcpv6_solicit_layout);

fn smoke_dhcpv6_status_codes() -> TestResult {
    use crate::pkt_dhcpv6::{
        STATUS_NOT_ON_LINK, STATUS_NO_ADDRS_AVAIL, STATUS_SUCCESS, STATUS_USE_MULTICAST,
    };
    if STATUS_SUCCESS != 0 || STATUS_NO_ADDRS_AVAIL != 2 || STATUS_NOT_ON_LINK != 4 || STATUS_USE_MULTICAST != 5 {
        return TestResult::Fail("status code values per §21.13");
    }
    TestResult::Pass
}
kernel_test_in!("net/dhcpv6", smoke_dhcpv6_status_codes);

// ── ICMP error / IGMPv3 smokes ─────────────────────────────────────

fn smoke_icmp_fragmentation_needed_round_trip() -> TestResult {
    use crate::pkt_icmp_extra::{
        build_fragmentation_needed, IcmpError, DUR_FRAGMENTATION_NEEDED, ICMP_DEST_UNREACHABLE,
    };
    let original = [0u8; 28]; // synthetic IP header + 8 bytes
    let pkt = build_fragmentation_needed(1500, &original);
    let (h, body) = IcmpError::decode(&pkt).expect("decode (checksum should verify)");
    if h.typ != ICMP_DEST_UNREACHABLE || h.code != DUR_FRAGMENTATION_NEEDED {
        return TestResult::Fail("Type 3 Code 4");
    }
    // Bottom 16 bits of rest_of_header carry the next-hop MTU (RFC 1191).
    if (h.rest_of_header & 0xFFFF) as u16 != 1500 {
        return TestResult::Fail("next-hop MTU at bits 15..0 of rest-of-header");
    }
    if body.len() != original.len() {
        return TestResult::Fail("original-packet head should follow header");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/icmp-extra",
    smoke_icmp_fragmentation_needed_round_trip
);

fn smoke_icmp_time_exceeded_layout() -> TestResult {
    use crate::pkt_icmp_extra::{
        build_time_exceeded, IcmpError, ICMP_TIME_EXCEEDED, TE_TTL_EXCEEDED_IN_TRANSIT,
    };
    let pkt = build_time_exceeded(TE_TTL_EXCEEDED_IN_TRANSIT, &[0u8; 28]);
    let (h, _) = IcmpError::decode(&pkt).expect("decode");
    if h.typ != ICMP_TIME_EXCEEDED || h.code != TE_TTL_EXCEEDED_IN_TRANSIT {
        return TestResult::Fail("Type 11 Code 0");
    }
    TestResult::Pass
}
kernel_test_in!("net/icmp-extra", smoke_icmp_time_exceeded_layout);

fn smoke_icmp_redirect_carries_gateway() -> TestResult {
    use crate::pkt_icmp_extra::{build_redirect, IcmpError, ICMP_REDIRECT, REDIRECT_HOST};
    let pkt = build_redirect(REDIRECT_HOST, [10, 0, 0, 1], &[0u8; 28]);
    let (h, _) = IcmpError::decode(&pkt).expect("decode");
    if h.typ != ICMP_REDIRECT {
        return TestResult::Fail("Type 5");
    }
    if h.rest_of_header != 0x0A_00_00_01 {
        return TestResult::Fail("gateway packed into rest-of-header");
    }
    TestResult::Pass
}
kernel_test_in!("net/icmp-extra", smoke_icmp_redirect_carries_gateway);

fn smoke_icmp_decode_rejects_bad_checksum() -> TestResult {
    use crate::pkt_icmp_extra::{
        build_fragmentation_needed, IcmpError, IcmpExtraError,
    };
    let mut pkt = build_fragmentation_needed(1280, &[0u8; 28]);
    pkt[10] ^= 0xFF;
    match IcmpError::decode(&pkt) {
        Err(IcmpExtraError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("tampered ICMP must fail checksum verify"),
    }
}
kernel_test_in!("net/icmp-extra", smoke_icmp_decode_rejects_bad_checksum);

fn smoke_igmpv3_membership_query_decode() -> TestResult {
    use crate::pkt_icmp_extra::{IgmpV3Query, IGMP_MEMBERSHIP_QUERY};
    let mut buf = alloc::vec![IGMP_MEMBERSHIP_QUERY, 0x64, 0, 0]; // type, max_resp, checksum (untested)
    buf.extend_from_slice(&[224, 0, 0, 1]); // group address
    buf.push(0x02); // QRV=2, S=0
    buf.push(0x12); // QQIC
    buf.extend_from_slice(&3u16.to_be_bytes()); // number-of-sources = 3
    let q = IgmpV3Query::decode(&buf).expect("decode");
    if q.max_resp_code != 0x64 {
        return TestResult::Fail("max-resp-code byte 1");
    }
    if q.group_address != [224, 0, 0, 1] {
        return TestResult::Fail("group address bytes 4..8");
    }
    if q.flags & 0x07 != 2 {
        return TestResult::Fail("QRV at low 3 bits of byte 8");
    }
    if q.number_of_sources != 3 {
        return TestResult::Fail("source count BE u16");
    }
    TestResult::Pass
}
kernel_test_in!("net/icmp-extra", smoke_igmpv3_membership_query_decode);

fn smoke_igmpv3_group_record_round_trip() -> TestResult {
    use crate::pkt_icmp_extra::{GroupRecord, IGMP_RECORD_MODE_IS_INCLUDE};
    let r = GroupRecord {
        record_type: IGMP_RECORD_MODE_IS_INCLUDE,
        multicast_address: [239, 255, 255, 250], // SSDP
        source_addresses: alloc::vec![[10u8, 0, 0, 1], [10, 0, 0, 2]],
        auxiliary_data: alloc::vec::Vec::new(),
    };
    let mut buf = alloc::vec::Vec::new();
    r.encode(&mut buf);
    let (back, used) = GroupRecord::decode(&buf).expect("decode");
    if used != buf.len() {
        return TestResult::Fail("GroupRecord decode should consume full block");
    }
    if back != r {
        return TestResult::Fail("GroupRecord round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/icmp-extra", smoke_igmpv3_group_record_round_trip);

fn smoke_igmpv3_report_round_trip() -> TestResult {
    use crate::pkt_icmp_extra::{
        build_v3_report, GroupRecord, IGMP_RECORD_CHANGE_TO_EXCLUDE, IGMP_V3_MEMBERSHIP_REPORT,
    };
    let r = GroupRecord {
        record_type: IGMP_RECORD_CHANGE_TO_EXCLUDE,
        multicast_address: [224, 0, 0, 251],
        source_addresses: alloc::vec::Vec::new(),
        auxiliary_data: alloc::vec::Vec::new(),
    };
    let pkt = build_v3_report(&[r]);
    if pkt[0] != IGMP_V3_MEMBERSHIP_REPORT {
        return TestResult::Fail("Type byte 0x22");
    }
    let n_records = u16::from_be_bytes([pkt[6], pkt[7]]);
    if n_records != 1 {
        return TestResult::Fail("number-of-group-records BE u16 at bytes 6..8");
    }
    // Checksum should bring the buffer to zero ones-complement sum.
    if crate::pkt::ip_checksum(&pkt) != 0 {
        return TestResult::Fail("checksum should be installed");
    }
    TestResult::Pass
}
kernel_test_in!("net/icmp-extra", smoke_igmpv3_report_round_trip);

// ── HTTP/2 framing smokes ──────────────────────────────────────────

fn smoke_http2_client_preface_constant() -> TestResult {
    use crate::http2::CLIENT_PREFACE;
    if CLIENT_PREFACE != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return TestResult::Fail("client preface bytes per RFC 9113 §3.4");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_client_preface_constant);

fn smoke_http2_frame_header_round_trip() -> TestResult {
    use crate::http2::{FrameHeader, FLAG_END_HEADERS, FT_HEADERS, FRAME_HEADER_LEN};
    let h = FrameHeader {
        length: 0x12_3456,
        frame_type: FT_HEADERS,
        flags: FLAG_END_HEADERS,
        stream_id: 0x12_3456_78,
    };
    let bytes = h.encode();
    if bytes.len() != FRAME_HEADER_LEN {
        return TestResult::Fail("frame header = 9 bytes");
    }
    if bytes[3] != FT_HEADERS {
        return TestResult::Fail("frame-type byte 3");
    }
    let back = FrameHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("frame header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_frame_header_round_trip);

fn smoke_http2_stream_id_high_bit_masked() -> TestResult {
    use crate::http2::FrameHeader;
    let h = FrameHeader {
        length: 0,
        frame_type: 0,
        flags: 0,
        stream_id: 0xFFFF_FFFF,
    };
    let bytes = h.encode();
    // Top bit on the wire must be 0 (R reserved bit).
    if bytes[5] & 0x80 != 0 {
        return TestResult::Fail("R bit must be 0");
    }
    let back = FrameHeader::decode(&bytes).expect("decode");
    if back.stream_id != 0x7FFF_FFFF {
        return TestResult::Fail("stream id capped at 31 bits");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_stream_id_high_bit_masked);

fn smoke_http2_settings_payload_round_trip() -> TestResult {
    use crate::http2::{
        build_settings_payload, parse_settings_payload, SETTINGS_INITIAL_WINDOW_SIZE,
        SETTINGS_MAX_CONCURRENT_STREAMS,
    };
    let pairs: alloc::vec::Vec<(u16, u32)> = alloc::vec![
        (SETTINGS_MAX_CONCURRENT_STREAMS, 100),
        (SETTINGS_INITIAL_WINDOW_SIZE, 65535),
    ];
    let bytes = build_settings_payload(&pairs);
    if bytes.len() != 12 {
        return TestResult::Fail("each setting is 6 bytes");
    }
    let back = parse_settings_payload(&bytes).expect("parse");
    if back != pairs {
        return TestResult::Fail("settings payload round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_settings_payload_round_trip);

fn smoke_http2_settings_payload_rejects_misaligned_buffer() -> TestResult {
    use crate::http2::{parse_settings_payload, Http2Error};
    let bytes = [0u8; 7];
    match parse_settings_payload(&bytes) {
        Err(Http2Error::BadLength) => TestResult::Pass,
        _ => TestResult::Fail("non-multiple-of-6 must be rejected"),
    }
}
kernel_test_in!(
    "net/http2",
    smoke_http2_settings_payload_rejects_misaligned_buffer
);

fn smoke_http2_window_update_layout() -> TestResult {
    use crate::http2::{build_window_update, FT_WINDOW_UPDATE};
    let pkt = build_window_update(3, 65535);
    if pkt[3] != FT_WINDOW_UPDATE {
        return TestResult::Fail("frame type byte");
    }
    if u32::from_be_bytes([pkt[9], pkt[10], pkt[11], pkt[12]]) != 65535 {
        return TestResult::Fail("increment in payload");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_window_update_layout);

fn smoke_http2_goaway_carries_last_stream_and_error() -> TestResult {
    use crate::http2::{build_goaway, ERROR_PROTOCOL_ERROR, FT_GOAWAY};
    let pkt = build_goaway(7, ERROR_PROTOCOL_ERROR, b"why");
    if pkt[3] != FT_GOAWAY {
        return TestResult::Fail("opcode");
    }
    if u32::from_be_bytes([pkt[9], pkt[10], pkt[11], pkt[12]]) != 7 {
        return TestResult::Fail("last stream id at bytes 9..12");
    }
    if u32::from_be_bytes([pkt[13], pkt[14], pkt[15], pkt[16]]) != ERROR_PROTOCOL_ERROR {
        return TestResult::Fail("error code at bytes 13..16");
    }
    if &pkt[17..] != b"why" {
        return TestResult::Fail("debug data tail");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_goaway_carries_last_stream_and_error);

fn smoke_http2_ping_ack_flag() -> TestResult {
    use crate::http2::{build_ping, FLAG_ACK, FT_PING};
    let pkt = build_ping(true, [0; 8]);
    if pkt[3] != FT_PING {
        return TestResult::Fail("opcode");
    }
    if pkt[4] & FLAG_ACK == 0 {
        return TestResult::Fail("ACK flag should be set on PING reply");
    }
    let pkt2 = build_ping(false, [0; 8]);
    if pkt2[4] & FLAG_ACK != 0 {
        return TestResult::Fail("non-ACK PING should have flags=0");
    }
    TestResult::Pass
}
kernel_test_in!("net/http2", smoke_http2_ping_ack_flag);

// ── STUN smokes ────────────────────────────────────────────────────

fn smoke_stun_message_type_round_trip() -> TestResult {
    use crate::stun::{
        message_type, parse_message_type, CLASS_ERROR_RESPONSE, CLASS_REQUEST, METHOD_BINDING,
    };
    let mt = message_type(METHOD_BINDING, CLASS_REQUEST);
    let (m, c) = parse_message_type(mt);
    if m != METHOD_BINDING || c != CLASS_REQUEST {
        return TestResult::Fail("Binding Request packing");
    }
    let mt2 = message_type(METHOD_BINDING, CLASS_ERROR_RESPONSE);
    if mt2 == mt {
        return TestResult::Fail("class field should differ for error response");
    }
    let (m2, c2) = parse_message_type(mt2);
    if m2 != METHOD_BINDING || c2 != CLASS_ERROR_RESPONSE {
        return TestResult::Fail("Binding error-response decode");
    }
    TestResult::Pass
}
kernel_test_in!("net/stun", smoke_stun_message_type_round_trip);

fn smoke_stun_header_carries_magic_cookie() -> TestResult {
    use crate::stun::{StunHeader, CLASS_REQUEST, MAGIC_COOKIE, METHOD_BINDING, STUN_HDR_LEN};
    let h = StunHeader {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
        message_length: 0,
        transaction_id: [0u8; 12],
    };
    let bytes = h.encode();
    if bytes.len() != STUN_HDR_LEN {
        return TestResult::Fail("STUN header = 20 bytes");
    }
    let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if cookie != MAGIC_COOKIE {
        return TestResult::Fail("magic cookie at offset 4..8");
    }
    let back = StunHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("STUN header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/stun", smoke_stun_header_carries_magic_cookie);

fn smoke_stun_decode_rejects_bad_cookie() -> TestResult {
    use crate::stun::{StunError, StunHeader};
    let mut buf = [0u8; 20];
    buf[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    match StunHeader::decode(&buf) {
        Err(StunError::BadCookie) => TestResult::Pass,
        _ => TestResult::Fail("non-magic cookie must error"),
    }
}
kernel_test_in!("net/stun", smoke_stun_decode_rejects_bad_cookie);

fn smoke_stun_xor_mapped_ipv4_round_trip() -> TestResult {
    use crate::stun::{decode_xor_mapped_ipv4, encode_xor_mapped_ipv4};
    let tid = [0u8; 12];
    let body = encode_xor_mapped_ipv4(&tid, 41234, [192, 168, 1, 42]);
    let (port, ip) = decode_xor_mapped_ipv4(&tid, &body).expect("decode");
    if port != 41234 || ip != [192, 168, 1, 42] {
        return TestResult::Fail("XOR-MAPPED-ADDRESS round-trip");
    }
    // Encoded body should NOT contain the cleartext port/ip bytes.
    let cleartext_port = 41234u16.to_be_bytes();
    if body[2] == cleartext_port[0] && body[3] == cleartext_port[1] {
        return TestResult::Fail("port should be XORed with magic-cookie high half");
    }
    TestResult::Pass
}
kernel_test_in!("net/stun", smoke_stun_xor_mapped_ipv4_round_trip);

fn smoke_stun_attribute_iterator_handles_padding() -> TestResult {
    use crate::stun::{append_attribute, iter_attributes, ATTR_SOFTWARE};
    let mut out = alloc::vec::Vec::new();
    // 7-byte software string forces 1 byte of padding.
    append_attribute(&mut out, ATTR_SOFTWARE, b"narf/v1");
    if out.len() != 4 + 8 {
        return TestResult::Fail("attribute should pad to 4-byte boundary");
    }
    let recs: alloc::vec::Vec<_> = iter_attributes(&out).collect::<Result<_, _>>().expect("walk");
    if recs.len() != 1 {
        return TestResult::Fail("expected 1 attribute");
    }
    if recs[0].typ != ATTR_SOFTWARE || recs[0].data != b"narf/v1" {
        return TestResult::Fail("attribute round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/stun", smoke_stun_attribute_iterator_handles_padding);

fn smoke_stun_error_code_attribute_round_trip() -> TestResult {
    use crate::stun::{decode_error_code, encode_error_code};
    let body = encode_error_code(401, "Unauthorized");
    let (code, reason) = decode_error_code(&body).expect("decode");
    if code != 401 {
        return TestResult::Fail("error code round-trip");
    }
    if reason != "Unauthorized" {
        return TestResult::Fail("reason round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/stun", smoke_stun_error_code_attribute_round_trip);

fn smoke_stun_binding_request_with_software() -> TestResult {
    use crate::stun::{
        build_binding_request, iter_attributes, parse_message_type, ATTR_SOFTWARE, CLASS_REQUEST,
        METHOD_BINDING, STUN_HDR_LEN,
    };
    let pkt = build_binding_request([0xCC; 12], Some("narf-stun"));
    let mt = u16::from_be_bytes([pkt[0], pkt[1]]);
    let (method, class) = parse_message_type(mt);
    if method != METHOD_BINDING || class != CLASS_REQUEST {
        return TestResult::Fail("Binding Request method/class");
    }
    let body_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let body = &pkt[STUN_HDR_LEN..STUN_HDR_LEN + body_len];
    let recs: alloc::vec::Vec<_> = iter_attributes(body).collect::<Result<_, _>>().expect("walk");
    if !recs.iter().any(|r| r.typ == ATTR_SOFTWARE && r.data == b"narf-stun") {
        return TestResult::Fail("SOFTWARE attribute should be present");
    }
    TestResult::Pass
}
kernel_test_in!("net/stun", smoke_stun_binding_request_with_software);

// ── MQTT v5 framing smokes ─────────────────────────────────────────

fn smoke_mqtt_var_int_round_trip() -> TestResult {
    use crate::mqtt::{decode_var_int, encode_var_int};
    // Test boundary values: 0, 127 (single byte), 128 (two bytes),
    // 16383 (two-byte max), 16384 (three bytes), 2_097_151 (three-byte max),
    // 268_435_455 (four-byte max).
    for v in [0u32, 127, 128, 16_383, 16_384, 2_097_151, 268_435_455] {
        let mut out = alloc::vec::Vec::new();
        encode_var_int(&mut out, v);
        let (back, _) = decode_var_int(&out).expect("decode");
        if back != v {
            return TestResult::Fail("VarInt round-trip");
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/mqtt", smoke_mqtt_var_int_round_trip);

fn smoke_mqtt_var_int_rejects_5_byte_overflow() -> TestResult {
    use crate::mqtt::{decode_var_int, MqttError};
    let buf = [0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF];
    match decode_var_int(&buf) {
        Err(MqttError::BadVarInt) => TestResult::Pass,
        _ => TestResult::Fail("> 4-byte VarInt must be rejected"),
    }
}
kernel_test_in!("net/mqtt", smoke_mqtt_var_int_rejects_5_byte_overflow);

fn smoke_mqtt_fixed_header_round_trip() -> TestResult {
    use crate::mqtt::{FixedHeader, PT_PUBLISH};
    let h = FixedHeader {
        packet_type: PT_PUBLISH,
        flags: 0b0011, // QoS 1 + retain
        remaining_length: 200,
    };
    let mut out = alloc::vec::Vec::new();
    h.encode(&mut out);
    let (back, used) = FixedHeader::decode(&out).expect("decode");
    if back != h {
        return TestResult::Fail("fixed header round-trip");
    }
    if used != out.len() {
        return TestResult::Fail("decode should consume entire header");
    }
    TestResult::Pass
}
kernel_test_in!("net/mqtt", smoke_mqtt_fixed_header_round_trip);

fn smoke_mqtt_utf8_string_round_trip() -> TestResult {
    use crate::mqtt::{append_utf8_string, decode_utf8_string};
    let mut out = alloc::vec::Vec::new();
    append_utf8_string(&mut out, "narf-client");
    let (s, n) = decode_utf8_string(&out, 0).expect("decode");
    if s != "narf-client" {
        return TestResult::Fail("UTF-8 string round-trip");
    }
    if n != out.len() {
        return TestResult::Fail("decode should consume length + body");
    }
    TestResult::Pass
}
kernel_test_in!("net/mqtt", smoke_mqtt_utf8_string_round_trip);

fn smoke_mqtt_connect_v5_layout() -> TestResult {
    use crate::mqtt::{
        build_connect_v5, decode_utf8_string, FixedHeader, CONNECT_CLEAN_START, PT_CONNECT,
    };
    let pkt = build_connect_v5(CONNECT_CLEAN_START, 60, "narf-test");
    let (h, hdr_len) = FixedHeader::decode(&pkt).expect("decode header");
    if h.packet_type != PT_CONNECT {
        return TestResult::Fail("CONNECT packet type");
    }
    // First UTF-8 string in the variable header should be "MQTT".
    let (proto, _) = decode_utf8_string(&pkt, hdr_len).expect("proto name");
    if proto != "MQTT" {
        return TestResult::Fail("Protocol Name = MQTT");
    }
    // Protocol Level lives at hdr_len + 6 (2-byte length + 4-byte body).
    if pkt[hdr_len + 6] != 5 {
        return TestResult::Fail("Protocol Level = 5 for MQTT v5");
    }
    if pkt[hdr_len + 7] & CONNECT_CLEAN_START == 0 {
        return TestResult::Fail("CLEAN_START flag should be set");
    }
    TestResult::Pass
}
kernel_test_in!("net/mqtt", smoke_mqtt_connect_v5_layout);

fn smoke_mqtt_publish_qos_flags_in_fixed_header() -> TestResult {
    use crate::mqtt::{build_publish_v5, FixedHeader, PT_PUBLISH};
    let pkt = build_publish_v5(false, 2, true, "topic/a", Some(0xCAFE), b"hello");
    let (h, _) = FixedHeader::decode(&pkt).expect("decode");
    if h.packet_type != PT_PUBLISH {
        return TestResult::Fail("PUBLISH packet type");
    }
    if (h.flags >> 1) & 0x03 != 2 {
        return TestResult::Fail("QoS at flags bits 2..1");
    }
    if h.flags & 0x01 == 0 {
        return TestResult::Fail("retain flag at bit 0");
    }
    TestResult::Pass
}
kernel_test_in!("net/mqtt", smoke_mqtt_publish_qos_flags_in_fixed_header);

fn smoke_mqtt_pingreq_is_two_bytes() -> TestResult {
    use crate::mqtt::{build_pingreq, PT_PINGREQ};
    let pkt = build_pingreq();
    if pkt.len() != 2 {
        return TestResult::Fail("PINGREQ = 2 bytes");
    }
    if (pkt[0] >> 4) != PT_PINGREQ {
        return TestResult::Fail("packet type byte 0");
    }
    if pkt[1] != 0 {
        return TestResult::Fail("Remaining Length = 0");
    }
    TestResult::Pass
}
kernel_test_in!("net/mqtt", smoke_mqtt_pingreq_is_two_bytes);

// ── VLAN + LLDP smokes ─────────────────────────────────────────────

fn smoke_vlan_tag_round_trip() -> TestResult {
    use crate::pkt_l2::{VlanTag, TPID_C_VLAN, TPID_S_VLAN};
    let v = VlanTag {
        tpid: TPID_C_VLAN,
        pcp: 5,
        dei: true,
        vid: 100,
    };
    let bytes = v.encode();
    let back = VlanTag::decode(&bytes).expect("decode");
    if back != v {
        return TestResult::Fail("VLAN tag round-trip");
    }
    if TPID_C_VLAN != 0x8100 || TPID_S_VLAN != 0x88A8 {
        return TestResult::Fail("VLAN TPIDs");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/vlan", smoke_vlan_tag_round_trip);

fn smoke_vlan_tci_bit_layout() -> TestResult {
    use crate::pkt_l2::VlanTag;
    let v = VlanTag {
        tpid: 0x8100,
        pcp: 7,
        dei: false,
        vid: 4094,
    };
    let bytes = v.encode();
    let tci = u16::from_be_bytes([bytes[2], bytes[3]]);
    if (tci >> 13) != 7 {
        return TestResult::Fail("PCP at bits 15..13");
    }
    if (tci >> 12) & 1 != 0 {
        return TestResult::Fail("DEI bit should be 0");
    }
    if (tci & 0x0FFF) != 4094 {
        return TestResult::Fail("VID in low 12 bits");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/vlan", smoke_vlan_tci_bit_layout);

fn smoke_lldp_tlv_round_trip() -> TestResult {
    use crate::pkt_l2::{
        append_chassis_id, append_end_of_lldpdu, append_port_id, append_ttl, iter_tlvs,
        parse_ttl, CHASSIS_ID_MAC_ADDRESS, PORT_ID_INTERFACE_NAME, TLV_CHASSIS_ID, TLV_PORT_ID,
        TLV_TTL,
    };
    let mut out = alloc::vec::Vec::new();
    append_chassis_id(&mut out, CHASSIS_ID_MAC_ADDRESS, &[0x02, 0x42, 0xCA, 0xFE, 0xBE, 0xEF]);
    append_port_id(&mut out, PORT_ID_INTERFACE_NAME, b"eth0");
    append_ttl(&mut out, 120);
    append_end_of_lldpdu(&mut out);

    let recs: alloc::vec::Vec<_> = iter_tlvs(&out).collect::<Result<_, _>>().expect("walk");
    if recs.len() != 3 {
        return TestResult::Fail("expected 3 TLVs (terminator stops iter)");
    }
    if recs[0].typ != TLV_CHASSIS_ID || recs[0].data[0] != CHASSIS_ID_MAC_ADDRESS {
        return TestResult::Fail("Chassis ID round-trip");
    }
    if recs[1].typ != TLV_PORT_ID || &recs[1].data[1..] != b"eth0" {
        return TestResult::Fail("Port ID round-trip");
    }
    if recs[2].typ != TLV_TTL {
        return TestResult::Fail("TTL TLV type");
    }
    if parse_ttl(recs[2].data).expect("parse TTL") != 120 {
        return TestResult::Fail("TTL value");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/lldp", smoke_lldp_tlv_round_trip);

fn smoke_lldp_tlv_header_packing() -> TestResult {
    use crate::pkt_l2::{append_tlv, TLV_SYSTEM_NAME};
    let mut out = alloc::vec::Vec::new();
    append_tlv(&mut out, TLV_SYSTEM_NAME, b"narf");
    let header = u16::from_be_bytes([out[0], out[1]]);
    if (header >> 9) != TLV_SYSTEM_NAME as u16 {
        return TestResult::Fail("Type at bits 15..9");
    }
    if (header & 0x01FF) != 4 {
        return TestResult::Fail("Length at bits 8..0");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/lldp", smoke_lldp_tlv_header_packing);

fn smoke_lldp_system_capabilities_layout() -> TestResult {
    use crate::pkt_l2::{
        append_system_capabilities, iter_tlvs, CAP_MAC_BRIDGE, CAP_ROUTER, TLV_SYSTEM_CAPABILITIES,
    };
    let mut out = alloc::vec::Vec::new();
    append_system_capabilities(&mut out, CAP_MAC_BRIDGE | CAP_ROUTER, CAP_MAC_BRIDGE);
    let recs: alloc::vec::Vec<_> = iter_tlvs(&out).collect::<Result<_, _>>().expect("walk");
    if recs[0].typ != TLV_SYSTEM_CAPABILITIES {
        return TestResult::Fail("System Capabilities TLV type");
    }
    let caps = u16::from_be_bytes([recs[0].data[0], recs[0].data[1]]);
    let enabled = u16::from_be_bytes([recs[0].data[2], recs[0].data[3]]);
    if caps != (CAP_MAC_BRIDGE | CAP_ROUTER) {
        return TestResult::Fail("capabilities round-trip");
    }
    if enabled != CAP_MAC_BRIDGE {
        return TestResult::Fail("enabled subset round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/lldp", smoke_lldp_system_capabilities_layout);

fn smoke_lldp_truncated_tlv_rejected() -> TestResult {
    use crate::pkt_l2::{iter_tlvs, LldpError};
    // Header claims 5-byte body, but only 2 bytes follow.
    let buf = [(2u16 << 9 | 5).to_be_bytes()[0], (2u16 << 9 | 5).to_be_bytes()[1], 0, 0];
    let mut errs = 0;
    for r in iter_tlvs(&buf) {
        if matches!(r, Err(LldpError::Truncated)) {
            errs += 1;
        }
    }
    if errs != 1 {
        return TestResult::Fail("truncated TLV must surface as error");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/lldp", smoke_lldp_truncated_tlv_rejected);

fn smoke_lldp_dest_mac_constant() -> TestResult {
    use crate::pkt_l2::LLDP_DEST_MAC_NEAREST_BRIDGE;
    if LLDP_DEST_MAC_NEAREST_BRIDGE != [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E] {
        return TestResult::Fail("LLDP nearest-bridge multicast MAC");
    }
    TestResult::Pass
}
kernel_test_in!("net/l2/lldp", smoke_lldp_dest_mac_constant);

// ── CoAP smokes ────────────────────────────────────────────────────

fn smoke_coap_header_round_trip() -> TestResult {
    use crate::pkt_coap::{Header, METHOD_GET, TYPE_CONFIRMABLE};
    let h = Header {
        version: 1,
        typ: TYPE_CONFIRMABLE,
        code: METHOD_GET,
        message_id: 0xABCD,
        token: alloc::vec![0xCAu8, 0xFE, 0xBE],
    };
    let mut buf = alloc::vec::Vec::new();
    h.encode_into(&mut buf);
    let (back, used) = Header::decode(&buf).expect("decode");
    if used != buf.len() {
        return TestResult::Fail("decode should consume header + token");
    }
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/coap", smoke_coap_header_round_trip);

fn smoke_coap_decode_rejects_bad_version() -> TestResult {
    use crate::pkt_coap::{CoapError, Header};
    let buf = [0xC0u8, 0, 0, 0]; // version field = 3
    match Header::decode(&buf) {
        Err(CoapError::BadVersion(3)) => TestResult::Pass,
        _ => TestResult::Fail("non-1 version must be rejected"),
    }
}
kernel_test_in!("net/coap", smoke_coap_decode_rejects_bad_version);

fn smoke_coap_decode_rejects_long_token_length() -> TestResult {
    use crate::pkt_coap::{CoapError, Header};
    let buf = [0x49u8, 0, 0, 0]; // version 1, type 0, TKL = 9
    match Header::decode(&buf) {
        Err(CoapError::BadTokenLength(9)) => TestResult::Pass,
        _ => TestResult::Fail("TKL > 8 must be rejected"),
    }
}
kernel_test_in!("net/coap", smoke_coap_decode_rejects_long_token_length);

fn smoke_coap_option_delta_extension_13() -> TestResult {
    use crate::pkt_coap::{append_option, parse_options_and_payload, CoapOption};
    let mut out = alloc::vec::Vec::new();
    let mut last = 0u32;
    // Option number 17 — uses delta extension form (13 ≤ delta < 269).
    append_option(
        &mut out,
        &mut last,
        &CoapOption {
            number: 17,
            value: alloc::vec![0xAA],
        },
    );
    if (out[0] >> 4) != 13 {
        return TestResult::Fail("delta nibble = 13 for delta 13..268");
    }
    if out[1] != (17 - 13) as u8 {
        return TestResult::Fail("extended delta byte");
    }
    let (opts, _, _) = parse_options_and_payload(&out).expect("parse");
    if opts.len() != 1 || opts[0].number != 17 || opts[0].value != [0xAA] {
        return TestResult::Fail("extended-delta option round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/coap", smoke_coap_option_delta_extension_13);

fn smoke_coap_option_delta_extension_14() -> TestResult {
    use crate::pkt_coap::{append_option, parse_options_and_payload, CoapOption};
    let mut out = alloc::vec::Vec::new();
    let mut last = 0u32;
    // Option number 1000 — uses delta extension form 14 (BE u16).
    append_option(
        &mut out,
        &mut last,
        &CoapOption {
            number: 1000,
            value: alloc::vec::Vec::new(),
        },
    );
    if (out[0] >> 4) != 14 {
        return TestResult::Fail("delta nibble = 14 for delta ≥ 269");
    }
    let (opts, _, _) = parse_options_and_payload(&out).expect("parse");
    if opts[0].number != 1000 {
        return TestResult::Fail("16-bit-extended delta round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/coap", smoke_coap_option_delta_extension_14);

fn smoke_coap_payload_marker_terminates_options() -> TestResult {
    use crate::pkt_coap::{
        build_message, parse_options_and_payload, CoapOption, Header, METHOD_POST, OPT_URI_PATH,
        TYPE_NON_CONFIRMABLE,
    };
    let header = Header {
        version: 1,
        typ: TYPE_NON_CONFIRMABLE,
        code: METHOD_POST,
        message_id: 0,
        token: alloc::vec::Vec::new(),
    };
    let opts = alloc::vec![CoapOption {
        number: OPT_URI_PATH,
        value: b"sensor".to_vec(),
    }];
    let pkt = build_message(&header, &opts, Some(b"42"));
    // Decode: skip 4-byte header, parse options + payload from byte 4.
    let (parsed_opts, payload, _) = parse_options_and_payload(&pkt[4..]).expect("parse");
    if parsed_opts.len() != 1 || parsed_opts[0].number != OPT_URI_PATH {
        return TestResult::Fail("Uri-Path option");
    }
    if payload != b"42" {
        return TestResult::Fail("payload after 0xFF marker");
    }
    TestResult::Pass
}
kernel_test_in!("net/coap", smoke_coap_payload_marker_terminates_options);

fn smoke_coap_response_code_split() -> TestResult {
    use crate::pkt_coap::{split_code, CODE_CONTENT, CODE_NOT_FOUND};
    let (c, d) = split_code(CODE_CONTENT);
    if c != 2 || d != 5 {
        return TestResult::Fail("2.05 splits into class=2, detail=5");
    }
    let (c, d) = split_code(CODE_NOT_FOUND);
    if c != 4 || d != 4 {
        return TestResult::Fail("4.04 splits into class=4, detail=4");
    }
    TestResult::Pass
}
kernel_test_in!("net/coap", smoke_coap_response_code_split);

fn smoke_coap_get_well_known_core() -> TestResult {
    use crate::pkt_coap::{build_get_request, parse_options_and_payload, OPT_URI_PATH};
    let pkt = build_get_request(0x1234, &[0xAA], &[".well-known", "core"]);
    let (opts, _, _) = parse_options_and_payload(&pkt[4 + 1..]).expect("parse"); // skip hdr + 1-byte token
    if opts.len() != 2 {
        return TestResult::Fail("expected two Uri-Path options");
    }
    if opts[0].number != OPT_URI_PATH || opts[0].value != b".well-known" {
        return TestResult::Fail("first Uri-Path");
    }
    if opts[1].value != b"core" {
        return TestResult::Fail("second Uri-Path");
    }
    TestResult::Pass
}
kernel_test_in!("net/coap", smoke_coap_get_well_known_core);

// ── GRE smokes ─────────────────────────────────────────────────────

fn smoke_gre_minimal_header_round_trip() -> TestResult {
    use crate::pkt_gre::GreHeader;
    let h = GreHeader {
        flags_version: 0,
        protocol_type: 0x0800,
        checksum: None,
        key: None,
        sequence: None,
    };
    let mut buf = alloc::vec::Vec::new();
    h.encode(&mut buf);
    if buf.len() != 4 {
        return TestResult::Fail("Minimal GRE header = 4 bytes");
    }
    if u16::from_be_bytes([buf[2], buf[3]]) != 0x0800 {
        return TestResult::Fail("protocol type = IPv4");
    }
    let (back, used) = GreHeader::decode(&buf).expect("decode");
    if used != buf.len() {
        return TestResult::Fail("decode should consume header");
    }
    if back != h {
        return TestResult::Fail("header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/gre", smoke_gre_minimal_header_round_trip);

fn smoke_gre_with_key_and_sequence() -> TestResult {
    use crate::pkt_gre::{GreHeader, FLAG_KEY, FLAG_SEQUENCE};
    let h = GreHeader {
        flags_version: FLAG_KEY | FLAG_SEQUENCE,
        protocol_type: 0x86DD,
        checksum: None,
        key: Some(0x1234_5678),
        sequence: Some(7),
    };
    let mut buf = alloc::vec::Vec::new();
    h.encode(&mut buf);
    // 4 hdr + 4 key + 4 seq = 12 bytes.
    if buf.len() != 12 {
        return TestResult::Fail("4 hdr + 4 key + 4 seq = 12 bytes");
    }
    let (back, _) = GreHeader::decode(&buf).expect("decode");
    if back.key != Some(0x1234_5678) || back.sequence != Some(7) {
        return TestResult::Fail("key / sequence round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/gre", smoke_gre_with_key_and_sequence);

fn smoke_gre_decode_rejects_non_zero_version() -> TestResult {
    use crate::pkt_gre::{GreError, GreHeader};
    let buf = [0u8, 1, 0, 0]; // version field = 1
    match GreHeader::decode(&buf) {
        Err(GreError::BadVersion(1)) => TestResult::Pass,
        _ => TestResult::Fail("non-zero version must be rejected"),
    }
}
kernel_test_in!("net/gre", smoke_gre_decode_rejects_non_zero_version);

fn smoke_gre_build_with_checksum_round_trip() -> TestResult {
    use crate::pkt_gre::{build, verify};
    let pkt = build(0x0800, None, None, b"payload-bytes", true);
    verify(&pkt).expect("checksum should verify");
    TestResult::Pass
}
kernel_test_in!("net/gre", smoke_gre_build_with_checksum_round_trip);

fn smoke_gre_bad_checksum_rejected() -> TestResult {
    use crate::pkt_gre::{build, verify, GreError};
    let mut pkt = build(0x0800, None, None, b"payload-bytes", true);
    let last = pkt.len() - 1;
    pkt[last] ^= 0xFF;
    match verify(&pkt) {
        Err(GreError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("tampered packet must fail verify"),
    }
}
kernel_test_in!("net/gre", smoke_gre_bad_checksum_rejected);

// ── SCTP smokes ────────────────────────────────────────────────────

fn smoke_sctp_common_header_round_trip() -> TestResult {
    use crate::pkt_sctp::{CommonHeader, COMMON_HDR_LEN};
    let h = CommonHeader {
        src_port: 8443,
        dst_port: 80,
        verification_tag: 0xCAFE_BABE,
        checksum: 0xDEAD_BEEF,
    };
    let bytes = h.encode();
    if bytes.len() != COMMON_HDR_LEN {
        return TestResult::Fail("SCTP common header = 12 bytes");
    }
    let back = CommonHeader::decode(&bytes).expect("decode");
    if back != h {
        return TestResult::Fail("common header round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/sctp", smoke_sctp_common_header_round_trip);

fn smoke_sctp_crc32c_known_vector() -> TestResult {
    use crate::pkt_sctp::crc32c;
    // CRC-32/CASTAGNOLI of "123456789" is 0xE3069283.
    let r = crc32c(b"123456789");
    if r != 0xE306_9283 {
        return TestResult::Fail("CRC-32C test vector mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("net/sctp", smoke_sctp_crc32c_known_vector);

fn smoke_sctp_chunk_iterator_and_alignment() -> TestResult {
    use crate::pkt_sctp::{append_chunk, iter_chunks, CHUNK_HEARTBEAT};
    let mut chunks = alloc::vec::Vec::new();
    // Heartbeat with 3-byte body should pad to 4-byte boundary.
    append_chunk(&mut chunks, CHUNK_HEARTBEAT, 0, &[1, 2, 3]);
    if chunks.len() != 8 {
        return TestResult::Fail("chunk should pad to 4-byte boundary");
    }
    let recs: alloc::vec::Vec<_> = iter_chunks(&chunks)
        .collect::<Result<_, _>>()
        .expect("walk");
    if recs.len() != 1 {
        return TestResult::Fail("expected 1 chunk");
    }
    if recs[0].typ != CHUNK_HEARTBEAT {
        return TestResult::Fail("chunk type round-trip");
    }
    if recs[0].length != 7 {
        return TestResult::Fail("chunk length excludes padding");
    }
    if recs[0].value != [1, 2, 3] {
        return TestResult::Fail("chunk value");
    }
    TestResult::Pass
}
kernel_test_in!("net/sctp", smoke_sctp_chunk_iterator_and_alignment);

fn smoke_sctp_data_chunk_value_layout() -> TestResult {
    use crate::pkt_sctp::build_data_value;
    let v = build_data_value(0xCAFE_BABE, 5, 7, 0x0000_0026, b"hi");
    if v.len() != 12 + 2 {
        return TestResult::Fail("DATA value = 12 hdr + payload");
    }
    if u32::from_be_bytes([v[0], v[1], v[2], v[3]]) != 0xCAFE_BABE {
        return TestResult::Fail("TSN BE");
    }
    if u16::from_be_bytes([v[4], v[5]]) != 5 {
        return TestResult::Fail("Stream ID");
    }
    if u32::from_be_bytes([v[8], v[9], v[10], v[11]]) != 0x0000_0026 {
        return TestResult::Fail("Payload Protocol ID");
    }
    if &v[12..] != b"hi" {
        return TestResult::Fail("user data tail");
    }
    TestResult::Pass
}
kernel_test_in!("net/sctp", smoke_sctp_data_chunk_value_layout);

fn smoke_sctp_packet_checksum_round_trip() -> TestResult {
    use crate::pkt_sctp::{
        append_chunk, build_packet, verify_packet, CommonHeader, CHUNK_HEARTBEAT,
    };
    let mut chunks = alloc::vec::Vec::new();
    append_chunk(&mut chunks, CHUNK_HEARTBEAT, 0, &[1, 2, 3]);
    let pkt = build_packet(
        CommonHeader {
            src_port: 1,
            dst_port: 2,
            verification_tag: 0,
            checksum: 0,
        },
        &chunks,
    );
    verify_packet(&pkt).expect("CRC32C should verify");
    TestResult::Pass
}
kernel_test_in!("net/sctp", smoke_sctp_packet_checksum_round_trip);

fn smoke_sctp_tampered_packet_rejected() -> TestResult {
    use crate::pkt_sctp::{
        append_chunk, build_packet, verify_packet, CommonHeader, SctpError, CHUNK_DATA,
    };
    let mut chunks = alloc::vec::Vec::new();
    append_chunk(&mut chunks, CHUNK_DATA, 0, &[0u8; 16]);
    let mut pkt = build_packet(
        CommonHeader {
            src_port: 0,
            dst_port: 0,
            verification_tag: 0,
            checksum: 0,
        },
        &chunks,
    );
    pkt[20] ^= 0xFF;
    match verify_packet(&pkt) {
        Err(SctpError::BadChecksum) => TestResult::Pass,
        _ => TestResult::Fail("tampered packet should fail CRC32C verify"),
    }
}
kernel_test_in!("net/sctp", smoke_sctp_tampered_packet_rejected);

// ── TFTP smokes ────────────────────────────────────────────────────

fn smoke_tftp_rrq_round_trip() -> TestResult {
    use crate::pkt_tftp::{Packet, MODE_OCTET, OP_RRQ};
    let p = Packet::Request {
        opcode: OP_RRQ,
        filename: alloc::string::String::from("kernel.elf"),
        mode: alloc::string::String::from(MODE_OCTET),
        options: alloc::vec::Vec::new(),
    };
    let bytes = p.encode();
    if u16::from_be_bytes([bytes[0], bytes[1]]) != OP_RRQ {
        return TestResult::Fail("RRQ opcode = 1");
    }
    let back = Packet::decode(&bytes).expect("decode");
    if back != p {
        return TestResult::Fail("RRQ round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tftp", smoke_tftp_rrq_round_trip);

fn smoke_tftp_rrq_with_options() -> TestResult {
    use crate::pkt_tftp::{Packet, MODE_OCTET, OP_RRQ};
    let p = Packet::Request {
        opcode: OP_RRQ,
        filename: alloc::string::String::from("img"),
        mode: alloc::string::String::from(MODE_OCTET),
        options: alloc::vec![
            (alloc::string::String::from("blksize"), alloc::string::String::from("1428")),
            (alloc::string::String::from("tsize"), alloc::string::String::from("0")),
        ],
    };
    let bytes = p.encode();
    let back = Packet::decode(&bytes).expect("decode");
    if back != p {
        return TestResult::Fail("RRQ with options round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tftp", smoke_tftp_rrq_with_options);

fn smoke_tftp_data_packet_round_trip() -> TestResult {
    use crate::pkt_tftp::{Packet, OP_DATA};
    let p = Packet::Data {
        block: 7,
        data: alloc::vec![0xCAu8; 256],
    };
    let bytes = p.encode();
    if u16::from_be_bytes([bytes[0], bytes[1]]) != OP_DATA {
        return TestResult::Fail("DATA opcode = 3");
    }
    if u16::from_be_bytes([bytes[2], bytes[3]]) != 7 {
        return TestResult::Fail("block field BE u16");
    }
    let back = Packet::decode(&bytes).expect("decode");
    if back != p {
        return TestResult::Fail("DATA round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tftp", smoke_tftp_data_packet_round_trip);

fn smoke_tftp_ack_packet_round_trip() -> TestResult {
    use crate::pkt_tftp::Packet;
    let bytes = Packet::Ack { block: 0 }.encode();
    if bytes.len() != 4 {
        return TestResult::Fail("ACK = 4 bytes");
    }
    let back = Packet::decode(&bytes).expect("decode");
    if back != (Packet::Ack { block: 0 }) {
        return TestResult::Fail("ACK round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tftp", smoke_tftp_ack_packet_round_trip);

fn smoke_tftp_error_packet_round_trip() -> TestResult {
    use crate::pkt_tftp::{Packet, ERROR_FILE_NOT_FOUND};
    let p = Packet::Error {
        code: ERROR_FILE_NOT_FOUND,
        message: alloc::string::String::from("not here"),
    };
    let bytes = p.encode();
    let back = Packet::decode(&bytes).expect("decode");
    if back != p {
        return TestResult::Fail("ERROR round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tftp", smoke_tftp_error_packet_round_trip);

fn smoke_tftp_oack_options_round_trip() -> TestResult {
    use crate::pkt_tftp::Packet;
    let p = Packet::OAck {
        options: alloc::vec![(
            alloc::string::String::from("blksize"),
            alloc::string::String::from("1428"),
        )],
    };
    let bytes = p.encode();
    let back = Packet::decode(&bytes).expect("decode");
    if back != p {
        return TestResult::Fail("OACK round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("net/tftp", smoke_tftp_oack_options_round_trip);

fn smoke_tftp_decode_rejects_unknown_opcode() -> TestResult {
    use crate::pkt_tftp::{Packet, TftpError};
    let buf = [0u8, 99, 0, 0];
    match Packet::decode(&buf) {
        Err(TftpError::BadOpcode(99)) => TestResult::Pass,
        _ => TestResult::Fail("non-1..6 opcode must be rejected"),
    }
}
kernel_test_in!("net/tftp", smoke_tftp_decode_rejects_unknown_opcode);



// ── WireGuard codec ───────────────────────────────────────────────



fn smoke_wireguard_handshake_initiation_round_trip() -> TestResult {

    use crate::wireguard::{build_handshake_initiation, decode_handshake_initiation, HANDSHAKE_INITIATION_LEN};

    let eph = [0xAAu8; 32];

    let stat = [0xBBu8; 48];

    let ts = [0xCCu8; 28];

    let mac1 = [0xDDu8; 16];

    let mac2 = [0x00u8; 16];

    let buf = build_handshake_initiation(0xCAFEBABE, &eph, &stat, &ts, &mac1, &mac2);

    if buf.len() != HANDSHAKE_INITIATION_LEN {

        return TestResult::Fail("length");

    }

    let h = decode_handshake_initiation(&buf).expect("decode");

    if h.sender_index != 0xCAFEBABE { return TestResult::Fail("sender"); }

    if h.unencrypted_ephemeral != &eph { return TestResult::Fail("eph"); }

    if h.encrypted_static != &stat { return TestResult::Fail("static"); }

    if h.mac1 != &mac1 { return TestResult::Fail("mac1"); }

    TestResult::Pass

}

kernel_test_in!("net/wireguard", smoke_wireguard_handshake_initiation_round_trip);



fn smoke_wireguard_handshake_response_round_trip() -> TestResult {

    use crate::wireguard::{build_handshake_response, decode_handshake_response};

    let eph = [0xEEu8; 32];

    let aead = [0xFFu8; 16];

    let mac1 = [0x11u8; 16];

    let mac2 = [0x00u8; 16];

    let buf = build_handshake_response(0xAA, 0xBB, &eph, &aead, &mac1, &mac2);

    let h = decode_handshake_response(&buf).expect("decode");

    if h.sender_index != 0xAA || h.receiver_index != 0xBB {

        return TestResult::Fail("indices");

    }

    TestResult::Pass

}

kernel_test_in!("net/wireguard", smoke_wireguard_handshake_response_round_trip);



fn smoke_wireguard_transport_header_round_trip() -> TestResult {

    use crate::wireguard::{build_transport_header, decode_transport_header};

    let h = build_transport_header(0x12345678, 0xDEADBEEF_CAFEBABE);

    let dec = decode_transport_header(&h).expect("decode");

    if dec.receiver_index != 0x12345678 { return TestResult::Fail("receiver"); }

    if dec.counter != 0xDEADBEEF_CAFEBABE { return TestResult::Fail("counter"); }

    TestResult::Pass

}

kernel_test_in!("net/wireguard", smoke_wireguard_transport_header_round_trip);



fn smoke_wireguard_decode_rejects_nonzero_reserved() -> TestResult {

    use crate::wireguard::{decode_handshake_initiation, WgError, HANDSHAKE_INITIATION_LEN};

    let mut buf = alloc::vec![0u8; HANDSHAKE_INITIATION_LEN];

    buf[0] = 1;

    buf[2] = 0xAA; // reserved byte tampered

    match decode_handshake_initiation(&buf) {

        Err(WgError::NonZeroReserved) => TestResult::Pass,

        _ => TestResult::Fail("reserved must be zero"),

    }

}

kernel_test_in!("net/wireguard", smoke_wireguard_decode_rejects_nonzero_reserved);



fn smoke_wireguard_anti_replay_window() -> TestResult {

    use crate::wireguard::AntiReplay;

    let mut ar = AntiReplay::default();

    if !ar.check_and_update(1) { return TestResult::Fail("first packet"); }

    if ar.check_and_update(1) { return TestResult::Fail("replay"); }

    if !ar.check_and_update(5) { return TestResult::Fail("jump"); }

    if !ar.check_and_update(2) { return TestResult::Fail("out-of-order ok"); }

    if ar.check_and_update(2) { return TestResult::Fail("out-of-order replay"); }

    if ar.check_and_update(0) { return TestResult::Fail("counter 0 reserved"); }

    TestResult::Pass

}

kernel_test_in!("net/wireguard", smoke_wireguard_anti_replay_window);



// ── QUIC + HTTP/3 ─────────────────────────────────────────────────



fn smoke_quic_varint_round_trip() -> TestResult {

    use crate::quic::{varint_decode, varint_encode};

    let cases = [0u64, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, 4_611_686_018_427_387_903];

    for v in cases {

        let enc = varint_encode(v);

        let (d, n) = varint_decode(&enc).expect("decode");

        if d != v || n != enc.len() {

            return TestResult::Fail("varint round-trip");

        }

    }

    TestResult::Pass

}

kernel_test_in!("net/quic", smoke_quic_varint_round_trip);



fn smoke_quic_varint_uses_minimum_encoding() -> TestResult {

    use crate::quic::varint_encode;

    if varint_encode(0).len() != 1 || varint_encode(63).len() != 1 {

        return TestResult::Fail("<=63 must be 1 byte");

    }

    if varint_encode(64).len() != 2 || varint_encode(16383).len() != 2 {

        return TestResult::Fail("14-bit form must be 2 bytes");

    }

    if varint_encode(16384).len() != 4 {

        return TestResult::Fail("30-bit form must be 4 bytes");

    }

    TestResult::Pass

}

kernel_test_in!("net/quic", smoke_quic_varint_uses_minimum_encoding);



fn smoke_quic_long_header_decodes() -> TestResult {

    use crate::quic::{decode_long_header, first_byte_long, LongPacketType};

    let mut buf = alloc::vec::Vec::new();

    buf.push(first_byte_long(LongPacketType::Initial, 0b0011)); // PNL = 4

    buf.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // version

    buf.push(8); // dcid len

    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

    buf.push(0); // scid len

    let (h, _) = decode_long_header(&buf).expect("decode");

    if h.packet_type != LongPacketType::Initial { return TestResult::Fail("ptype"); }

    if h.version != 1 { return TestResult::Fail("version"); }

    if h.dest_cid.len() != 8 || h.dest_cid[0] != 1 { return TestResult::Fail("dcid"); }

    if !h.src_cid.is_empty() { return TestResult::Fail("scid"); }

    TestResult::Pass

}

kernel_test_in!("net/quic", smoke_quic_long_header_decodes);



fn smoke_quic_connection_close_frame() -> TestResult {

    use crate::quic::{build_connection_close, FrameType, varint_decode};

    let f = build_connection_close(0x100, 0, b"test");

    if f[0] != FrameType::ConnectionCloseQuic as u8 { return TestResult::Fail("type byte"); }

    let (code, n) = varint_decode(&f[1..]).expect("code");

    if code != 0x100 { return TestResult::Fail("error code"); }

    let (frame_type, n2) = varint_decode(&f[1 + n..]).expect("frame_type");

    if frame_type != 0 { return TestResult::Fail("frame_type"); }

    let (rlen, _) = varint_decode(&f[1 + n + n2..]).expect("reason");

    if rlen != 4 { return TestResult::Fail("reason length"); }

    TestResult::Pass

}

kernel_test_in!("net/quic", smoke_quic_connection_close_frame);



fn smoke_h3_frame_round_trip() -> TestResult {

    use crate::quic::{build_h3_frame, decode_h3_frame, H3FrameType};

    let payload = b"hello";

    let buf = build_h3_frame(H3FrameType::Data as u64, payload);

    let (ty, body) = decode_h3_frame(&buf).expect("decode");

    if ty != H3FrameType::Data as u64 { return TestResult::Fail("type"); }

    if body != payload { return TestResult::Fail("body"); }

    TestResult::Pass

}

kernel_test_in!("net/h3", smoke_h3_frame_round_trip);
