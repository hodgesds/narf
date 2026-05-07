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
    // Hand-craft a datagram whose ones-complement sum hits 0.
    // Actually we just verify the helper substitutes 0xFFFF when its
    // raw computation would produce 0.
    let payload = [0u8, 0, 0, 0, 0, 0, 0, 0]; // header zeroed
    let v = ipv4_pseudo_checksum([0; 4], [0; 4], &payload);
    if v != 0xFFFF {
        // It's possible our specific input produced a non-zero
        // checksum; that's fine for this driver's contract — but we
        // must never emit 0 if the helper was given input meant to.
        // The function only substitutes when ip_checksum returns 0,
        // so as long as we test with a synthetic zero input we get
        // the substitution path.
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
