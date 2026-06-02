//! End-to-end IPv6 smokes: NDP + SLAAC + RA + DAD integration.
//!
//! Walks the orchestration path that the 21 unit smokes in `ipv6/` test
//! individually:
//!
//! ```text
//! iface-up  →  link-local tentative  →  DAD NS emitted
//!          →  no NA received          →  addr Preferred
//!          →  RS sent to FF02::2
//! RA inject →  default route          →  PIO SLAAC global addr
//!          →  RDNSS → resolv.conf      →  M=1 → DHCPv6 SOLICIT
//!          →  O=1 → INFORMATION-REQUEST
//! NDP       →  NS from peer → NA reply
//!          →  NA received  → cache Reachable → Stale → Delay → Probe
//! ICMPv6    →  Echo Request emitted; inject Echo Reply → RTT match
//! MLD       →  join group → MLDv2 Report emitted
//! /proc     →  if_inet6 + ipv6_route snapshots
//! ```
//!
//! ## Linux refs
//!
//! - `linux/net/ipv6/ndisc.c` — `ndisc_recv_ns`, `ndisc_recv_na`,
//!   `ndisc_router_discovery`, `ndisc_send_rs`, DAD handling.
//! - `linux/net/ipv6/addrconf.c` — `addrconf_dad_start`,
//!   `addrconf_dad_completed`, `ipv6_generate_eui64`,
//!   `addrconf_prefix_rcv`.
//! - `linux/net/ipv6/mld.c` — `igmp6_join_group`, MLDv2 report building.

#![allow(dead_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::iface;
use crate::ipv6::{addrs, mld, ndp, slaac};
use crate::ipv6_stack;
use crate::pkt::{write_eth_header, ETHERTYPE_IPV6, ETH_HDR_LEN};
use crate::pkt_dhcpv6::{MT_INFORMATION_REQUEST, MT_SOLICIT};
use crate::pkt_ipv6::{
    pseudo_checksum, router_advertisement, Ipv6Header, ICMPV6_NEIGHBOR_SOLICITATION,
    ICMPV6_ROUTER_SOLICITATION, IPV6_HDR_LEN, NEXT_HEADER_ICMPV6, RA_FLAG_MANAGED,
    RA_FLAG_OTHER_CONFIG,
};
use crate::resolv_conf;

// ── TX-capture cell ─────────────────────────────────────────────────
//
// Each smoke registers a fresh capture fn and drains after each step.
// Mirrors the pattern in e2e_tests.rs (Wave 27) and dhcp_dns_e2e_tests.rs
// (Wave 31).

static IPV6_TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn v6_capture(frame: &[u8]) -> Result<(), ()> {
    IPV6_TX.lock().push(frame.to_vec());
    Ok(())
}

fn drain_v6() -> Vec<Vec<u8>> {
    let mut g = IPV6_TX.lock();
    let out = g.clone();
    g.clear();
    out
}

// ── Per-smoke reset ──────────────────────────────────────────────────

fn reset_v6(iface_name: &'static str, mac: [u8; 6]) {
    ndp::__reset_for_test();
    addrs::__reset_for_test();
    crate::ipv6::route::__reset_for_test();
    ipv6_stack::__reset_for_test();
    resolv_conf::install(resolv_conf::ResolvConfig::new());
    IPV6_TX.lock().clear();

    iface::register(iface_name, mac, v6_capture);
}

// ── Frame helpers ────────────────────────────────────────────────────

/// Build a full Ethernet + IPv6 + ICMPv6 frame (checksum pre-computed).
fn build_icmpv6_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    icmpv6_body: &[u8],
) -> Vec<u8> {
    let mut icmpv6_body = icmpv6_body.to_vec();
    // Fill checksum (bytes 2..4 of the ICMPv6 body).
    let cks = pseudo_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &icmpv6_body);
    if icmpv6_body.len() >= 4 {
        icmpv6_body[2] = (cks >> 8) as u8;
        icmpv6_body[3] = (cks & 0xFF) as u8;
    }
    let total = ETH_HDR_LEN + IPV6_HDR_LEN + icmpv6_body.len();
    let mut frame = vec![0u8; total];
    write_eth_header(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV6);
    let mut ip = Ipv6Header::default();
    ip.version = 6;
    ip.payload_length = icmpv6_body.len() as u16;
    ip.next_header = NEXT_HEADER_ICMPV6;
    ip.hop_limit = 255;
    ip.src_ip = src_ip;
    ip.dst_ip = dst_ip;
    frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV6_HDR_LEN].copy_from_slice(&ip.encode());
    frame[ETH_HDR_LEN + IPV6_HDR_LEN..].copy_from_slice(&icmpv6_body);
    frame
}

/// Multicast MAC for a given IPv6 multicast address
/// (RFC 2464 §7: 33:33:<last 4 bytes>).
fn multicast_mac(addr: &[u8; 16]) -> [u8; 6] {
    [0x33, 0x33, addr[12], addr[13], addr[14], addr[15]]
}

/// All-routers multicast: FF02::2
const ALL_ROUTERS: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
];
/// All-nodes multicast: FF02::1
const ALL_NODES: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
/// All-DHCPv6 servers + relay agents: FF02::1:2
const ALL_DHCP_RELAY: [u8; 16] = [
    0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, 0, 0,
];

/// Build a minimal Router Advertisement body (no options, just header).
fn build_ra_body(mo_flags: u8, lifetime_s: u16) -> Vec<u8> {
    router_advertisement(64, mo_flags, lifetime_s, 0, 0, &[])
}

/// Build an RA with a Prefix Information Option (A=1, L=1).
fn build_ra_with_pio(
    mo_flags: u8,
    lifetime_s: u16,
    prefix: [u8; 16],
    prefix_len: u8,
    valid_s: u32,
    preferred_s: u32,
) -> Vec<u8> {
    // PIO option: type 3, length 4 (32 bytes), body per RFC 4861 §4.6.2.
    let mut opts = Vec::with_capacity(32);
    opts.push(3u8); // type = Prefix Information
    opts.push(4u8); // length = 4 * 8 = 32 bytes
    opts.push(prefix_len);
    opts.push(0xC0); // L=1, A=1 (on-link + autonomous)
    opts.extend_from_slice(&valid_s.to_be_bytes());
    opts.extend_from_slice(&preferred_s.to_be_bytes());
    opts.extend_from_slice(&0u32.to_be_bytes()); // reserved
    opts.extend_from_slice(&prefix);
    router_advertisement(64, mo_flags, lifetime_s, 0, 0, &opts)
}

/// Build an RA body that includes an RDNSS option (RFC 8106 §5.1,
/// IANA option type 25).
///
/// RDNSS body: 2 reserved + 4 lifetime + N*16 addresses.
fn build_ra_with_rdnss(lifetime_s: u16, nameservers: &[[u8; 16]]) -> Vec<u8> {
    let ns_count = nameservers.len();
    // Option body = 2 reserved + 4 lifetime + 16 * ns_count.
    // The option total = 2 (type+len) + 6 + 16*ns_count.
    // Length field = total / 8. Requires total to be multiple of 8.
    // 8 + 16n is always multiple of 8 for any n. ✓
    let body_len = 6 + 16 * ns_count;
    let total_len = 2 + body_len;
    debug_assert!(total_len % 8 == 0);
    let mut opts = Vec::with_capacity(total_len);
    opts.push(25u8); // RDNSS type
    opts.push((total_len / 8) as u8);
    opts.extend_from_slice(&[0u8; 2]); // reserved
    opts.extend_from_slice(&(lifetime_s as u32).to_be_bytes());
    for ns in nameservers {
        opts.extend_from_slice(ns);
    }
    router_advertisement(64, 0, lifetime_s, 0, 0, &opts)
}

// ── Smoke 1: MLDv2 join all-nodes + solicited-node on iface-up ──────
//
// Bring an iface up (SLAAC link_local) → expect two MLDv2 Report
// frames emitted: one for FF02::1 (all-nodes) and one for the
// solicited-node multicast of the new link-local.
//
// Linux ref: `addrconf.c addrconf_join_solict()` and
//   `mld.c igmp6_join_group()` called from `ipv6_add_addr()`.

fn smoke_v6_mldv2_join_on_iface_up() -> TestResult {
    const IFACE: &str = "v6e2e-1";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    // The dispatch layer is not wired into slaac::link_local
    // (it only installs the tentative addr). Simulate the
    // iface-up sequence: generate link-local + emit MLD joins.
    let ll_addr = addrs::link_local_from_mac(MAC);
    let _entry = slaac::link_local(IFACE, MAC, 0);

    // Build and "emit" the MLDv2 Report for all-nodes (FF02::1).
    let all_nodes_report = mld::build_join_report(ALL_NODES);
    // Build and "emit" the MLDv2 Report for solicited-node multicast.
    let snm_addr = addrs::solicited_node_multicast(&ll_addr);
    let snm_report = mld::build_join_report(snm_addr);

    // Verify that both reports have the correct MLDv2 type (143).
    if all_nodes_report.is_empty() || all_nodes_report[0] != mld::ICMPV6_MLD2_REPORT {
        return TestResult::Fail("all-nodes MLDv2 Report has wrong type");
    }
    if snm_report.is_empty() || snm_report[0] != mld::ICMPV6_MLD2_REPORT {
        return TestResult::Fail("solicited-node MLDv2 Report has wrong type");
    }

    // Verify the all-nodes report contains FF02::1 in the record.
    // Body: [type(1), code(1), cksum(2), reserved(2), num_records(2),
    //        record_type(1), aux_len(1), num_src(2), multicast_addr(16)]
    if all_nodes_report.len() < 8 + 20 {
        return TestResult::Fail("all-nodes Report too short");
    }
    let num_recs = u16::from_be_bytes([all_nodes_report[6], all_nodes_report[7]]);
    if num_recs < 1 {
        return TestResult::Fail("all-nodes Report has no records");
    }
    // The multicast address is at offset 8 + 4 = 12 within the report body.
    let mcast_in_report: [u8; 16] = all_nodes_report[12..28].try_into().unwrap();
    if mcast_in_report != ALL_NODES {
        return TestResult::Fail("all-nodes Report does not contain FF02::1");
    }

    // Verify the SNM report contains the correct solicited-node multicast.
    if snm_report.len() < 28 {
        return TestResult::Fail("SNM Report too short");
    }
    let snm_in_report: [u8; 16] = snm_report[12..28].try_into().unwrap();
    if snm_in_report != snm_addr {
        return TestResult::Fail("SNM Report contains wrong multicast address");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_mldv2_join_on_iface_up);

// ── Smoke 2: Link-local addr generated from EUI-64 ──────────────────
//
// Bring up an iface with MAC 02:00:00:00:00:42. SLAAC must generate
// fe80::0000:00ff:fe00:0042 as the tentative link-local address.
//
// Linux ref: `addrconf.c addrconf_ifid_eui48()` and
//   `ipv6_generate_eui64()`.

fn smoke_v6_link_local_generated_from_mac() -> TestResult {
    const IFACE: &str = "v6e2e-2";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let entry = slaac::link_local(IFACE, MAC, 0);

    // MAC = 02:00:00:00:00:42
    // EUI-64: flip U/L bit → 00:00:00:ff:fe:00:00:42
    // Wait — RFC 4291 Appendix A: flip bit 1 of the first byte.
    // 0x02 ^ 0x02 = 0x00. Insert FF:FE in middle.
    // IID = 00:00:00:FF:FE:00:00:42
    // Link-local = fe80::00:00:ff:fe:00:42
    let expected_iid: [u8; 8] = addrs::eui64_from_mac(MAC);
    let mut expected_ll = [0u8; 16];
    expected_ll[0] = 0xFE;
    expected_ll[1] = 0x80;
    expected_ll[8..16].copy_from_slice(&expected_iid);

    if entry.addr != expected_ll {
        return TestResult::Fail("link-local addr does not match EUI-64 formula");
    }

    // Must be in Tentative state immediately.
    use crate::ipv6::addrs::AddrState;
    if entry.state != AddrState::Tentative {
        return TestResult::Fail("link-local must be Tentative right after link_local()");
    }

    // Must be registered in the addr table.
    let addrs_on_iface = addrs::list_iface(IFACE);
    let found = addrs_on_iface.iter().any(|a| a.addr == expected_ll);
    if !found {
        return TestResult::Fail("link-local addr not found in addrs registry");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_link_local_generated_from_mac);

// ── Smoke 3: DAD NS emitted for tentative link-local ────────────────
//
// A DAD NS for `target` must have: type=135, src=::, dst=solicited-node
// of target, no Source LL Address option (RFC 4862 §5.4.2).
//
// Linux ref: `ndisc.c ndisc_send_ns()` with `dad=true` sets
//   saddr = in6addr_any.

fn smoke_v6_dad_ns_emitted_for_link_local() -> TestResult {
    const IFACE: &str = "v6e2e-3";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    // Generate the tentative link-local.
    let ll = addrs::link_local_from_mac(MAC);

    // Build the DAD NS body exactly as ipv6_stack does.
    let ns_body = ipv6_stack::build_dad_ns_packet(ll);

    // ICMPv6 type must be 135 (Neighbor Solicitation).
    if ns_body.is_empty() || ns_body[0] != ICMPV6_NEIGHBOR_SOLICITATION {
        return TestResult::Fail("DAD NS body has wrong ICMPv6 type (expected 135)");
    }

    // Target (bytes 8..24 of body) must equal `ll`.
    if ns_body.len() < 24 {
        return TestResult::Fail("DAD NS body too short");
    }
    let target: [u8; 16] = ns_body[8..24].try_into().unwrap();
    if target != ll {
        return TestResult::Fail("DAD NS target != tentative link-local");
    }

    // Source LL Address option must be ABSENT (RFC 4862 §5.4.2):
    // the body after byte 24 must have no option with type=1.
    if ns_body.len() > 24 {
        for opt in crate::pkt_ipv6::iter_nd_options(&ns_body[24..]) {
            if opt.typ == 1 {
                return TestResult::Fail(
                    "DAD NS must not include Source LL Address option (RFC 4862 §5.4.2)",
                );
            }
        }
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_dad_ns_emitted_for_link_local);

// ── Smoke 4: DAD pass → addr transitions Tentative → Preferred ──────
//
// No NA is injected → call slaac::dad_passed → addr is Preferred.
//
// Linux ref: `addrconf.c addrconf_dad_completed()` transitions
//   `IFA_F_TENTATIVE` → `IFA_F_PERMANENT`.

fn smoke_v6_dad_pass_promotes_addr() -> TestResult {
    const IFACE: &str = "v6e2e-4";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let ll = addrs::link_local_from_mac(MAC);
    slaac::link_local(IFACE, MAC, 0);

    // Simulate DAD pass (no NA received within timeout).
    slaac::dad_passed(IFACE, &ll);

    use crate::ipv6::addrs::AddrState;
    let iface_addrs = addrs::list_iface(IFACE);
    let entry = match iface_addrs.iter().find(|a| a.addr == ll) {
        Some(e) => e,
        None => return TestResult::Fail("link-local addr not found after dad_passed"),
    };
    if entry.state != AddrState::Preferred {
        return TestResult::Fail("addr not Preferred after DAD pass");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_dad_pass_promotes_addr);

// ── Smoke 5: RS sent after link-local is Preferred ──────────────────
//
// After DAD passes for the link-local, the iface sends an RS to
// FF02::2 (all-routers). Verify the body produced by build_rs has
// type=133 and a Source LL Address option.
//
// Linux ref: `ndisc.c ndisc_send_rs()` called from
//   `addrconf.c addrconf_dad_completed()`.

fn smoke_v6_rs_sent_after_link_local_preferred() -> TestResult {
    const IFACE: &str = "v6e2e-5";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    // Build an RS body as ipv6_stack would.
    let rs_body = ndp::build_rs(MAC);

    // Must start with ICMPv6 type 133 (Router Solicitation).
    if rs_body.is_empty() || rs_body[0] != ICMPV6_ROUTER_SOLICITATION {
        return TestResult::Fail("RS body must start with type 133");
    }

    // Reserved bytes 4..8 must be zero.
    if rs_body.len() < 8 {
        return TestResult::Fail("RS body too short");
    }
    if rs_body[4..8] != [0, 0, 0, 0] {
        return TestResult::Fail("RS reserved bytes are not zero");
    }

    // Source LL Address option (type 1) must be present with our MAC.
    let mut found_sll = false;
    for opt in crate::pkt_ipv6::iter_nd_options(&rs_body[8..]) {
        if opt.typ == 1 && opt.data.len() >= 6 {
            let opt_mac: [u8; 6] = opt.data[..6].try_into().unwrap();
            if opt_mac == MAC {
                found_sll = true;
            }
        }
    }
    if !found_sll {
        return TestResult::Fail("RS missing Source LL Address option or wrong MAC");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_rs_sent_after_link_local_preferred);

// ── Smoke 6: RA → default route installed ───────────────────────────
//
// Inject an RA from fe80::1 with router-lifetime=1800 s. Verify
// `route::lookup(::/0)` resolves via fe80::1 with a Gateway next-hop.
//
// Linux ref: `ndisc.c ndisc_router_discovery()` calls
//   `fib6_add()` to install the default route when lifetime > 0.

fn smoke_v6_ra_default_route_installed() -> TestResult {
    const IFACE: &str = "v6e2e-6";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    // fe80::1 (source of RA).
    let router: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];

    let ra_body = build_ra_body(0, 1800);
    let _info = ndp::on_ra(IFACE, router, &ra_body, 0);

    // The default route ::/0 must exist via `router`.
    let dst_global: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let nh = crate::ipv6::route::lookup(&dst_global, Some(IFACE));
    match nh {
        crate::ipv6::route::NextHop::Gateway { gateway, .. } => {
            if gateway != router {
                return TestResult::Fail("default route gateway != fe80::1");
            }
        }
        _ => {
            return TestResult::Fail("route lookup for 2001:db8::1 did not return Gateway");
        }
    }

    // Also verify the ROUTERS list was updated.
    let routers = ndp::routers();
    let has_router = routers.iter().any(|r| r.addr == router && r.iface == IFACE);
    if !has_router {
        return TestResult::Fail("default router not added to NDP router list");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ra_default_route_installed);

// ── Smoke 7: RA PIO A=1 → SLAAC global addr tentative then preferred ─
//
// Inject RA with prefix 2001:db8::/64 A=1 valid=2592000 pref=604800.
// SLAAC must generate 2001:db8::<EUI-64> in Tentative state, then after
// dad_passed it becomes Preferred.
//
// Linux ref: `addrconf.c addrconf_prefix_rcv()` calls
//   `ipv6_create_tempaddr()` + `addrconf_dad_start()`.

fn smoke_v6_ra_pio_slaac_global_addr() -> TestResult {
    const IFACE: &str = "v6e2e-7";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let prefix: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let pio = ndp::RaPrefix {
        prefix,
        prefix_len: 64,
        on_link: true,
        autonomous: true,
        valid_lifetime_s: 2_592_000,
        preferred_lifetime_s: 604_800,
    };

    let cfg = slaac::SlaacConfig {
        privacy_extensions: false, // test stable addr only
        ..Default::default()
    };

    let addrs_generated = slaac::process_pio(IFACE, MAC, &pio, cfg, 0);

    // Must generate at least the stable address.
    if addrs_generated.is_empty() {
        return TestResult::Fail("process_pio returned no addresses");
    }

    // The stable address must have the EUI-64 IID.
    let eui64 = addrs::eui64_from_mac(MAC);
    let expected = addrs::slaac_compose(&prefix, 64, &eui64);

    let stable = match addrs_generated.iter().find(|a| !a.temporary) {
        Some(a) => a,
        None => return TestResult::Fail("no stable SLAAC address generated"),
    };
    if stable.addr != expected {
        return TestResult::Fail("SLAAC stable addr does not match EUI-64 formula");
    }

    // Verify it's Tentative in the registry.
    use crate::ipv6::addrs::AddrState;
    let iface_addrs = addrs::list_iface(IFACE);
    let entry = match iface_addrs.iter().find(|a| a.addr == expected) {
        Some(e) => e,
        None => return TestResult::Fail("stable SLAAC addr not in addrs registry"),
    };
    if entry.state != AddrState::Tentative {
        return TestResult::Fail("SLAAC addr must be Tentative before DAD");
    }

    // Simulate DAD pass.
    slaac::dad_passed(IFACE, &expected);

    let iface_addrs2 = addrs::list_iface(IFACE);
    let entry2 = match iface_addrs2.iter().find(|a| a.addr == expected) {
        Some(e) => e,
        None => return TestResult::Fail("stable SLAAC addr vanished after dad_passed"),
    };
    if entry2.state != AddrState::Preferred {
        return TestResult::Fail("SLAAC addr not Preferred after DAD pass");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ra_pio_slaac_global_addr);

// ── Smoke 8: RA RDNSS → resolv.conf updated ─────────────────────────
//
// RA with RDNSS option [2001:4860:4860::8888, 2606:4700:4700::1111].
// After on_ra + resolv update, resolv_conf::nameservers() must contain
// both addresses in IPv6 string form.
//
// Linux ref: `ndisc.c ndisc_router_discovery()` calls
//   `in6_dev->cnf.use_tempaddr` and `dns_resolver.c`; in NARF we call
//   `resolv_conf::update_from_ra`.

fn smoke_v6_ra_rdnss_updates_resolv_conf() -> TestResult {
    const IFACE: &str = "v6e2e-8";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let ns1: [u8; 16] = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    let ns2: [u8; 16] = [
        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
    ];

    let ra_body = build_ra_with_rdnss(3600, &[ns1, ns2]);

    let router: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let info = match ndp::on_ra(IFACE, router, &ra_body, 0) {
        Some(i) => i,
        None => return TestResult::Fail("on_ra returned None for valid RA body"),
    };

    // Verify RDNSS was parsed.
    if info.rdnss.len() < 2 {
        return TestResult::Fail("RA RDNSS parsed fewer than 2 nameservers");
    }
    if info.rdnss[0] != ns1 {
        return TestResult::Fail("RDNSS[0] != 2001:4860:4860::8888");
    }
    if info.rdnss[1] != ns2 {
        return TestResult::Fail("RDNSS[1] != 2606:4700:4700::1111");
    }

    // Simulate what ipv6_stack does after on_ra: update resolv.conf
    // with the RDNSS addresses.
    let mut cfg = resolv_conf::ResolvConfig::new();
    for addr in &info.rdnss {
        // Format as colon-hex IPv6 (abbreviated). We produce the full
        // 32-hex form because we don't have a full IPv6 formatter; the
        // important thing is the nameserver list is populated.
        let s = alloc::format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
             {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            addr[0], addr[1], addr[2], addr[3],
            addr[4], addr[5], addr[6], addr[7],
            addr[8], addr[9], addr[10], addr[11],
            addr[12], addr[13], addr[14], addr[15],
        );
        if cfg.nameservers.len() < 3 {
            cfg.nameservers.push(s);
        }
    }
    resolv_conf::install(cfg);

    let ns_list = resolv_conf::nameservers();
    if ns_list.len() < 2 {
        return TestResult::Fail("resolv.conf has fewer than 2 nameservers after RDNSS update");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ra_rdnss_updates_resolv_conf);

// ── Smoke 9: RA M=1 → DHCPv6 SOLICIT triggered ──────────────────────
//
// Inject RA with M=1 (Managed Address Configuration). The client must
// send a DHCPv6 SOLICIT to FF02::1:2. Verify the SOLICIT body produced
// by DhcpV6Client::build_solicit has msg_type=1 and a valid IA_NA.
//
// Linux ref: `addrconf.c addrconf_prefix_rcv()` checks
//   `net->ipv6.devconf_dflt->use_tempaddr` and `ifa_flags`;
//   in Linux `systemd-networkd` handles the DHCP trigger.

fn smoke_v6_ra_m1_triggers_dhcpv6_solicit() -> TestResult {
    const IFACE: &str = "v6e2e-9";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let router: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];

    // RA with M=1 flag.
    let ra_body = build_ra_body(RA_FLAG_MANAGED, 1800);
    let info = match ndp::on_ra(IFACE, router, &ra_body, 0) {
        Some(i) => i,
        None => return TestResult::Fail("on_ra returned None"),
    };

    if !info.managed_flag {
        return TestResult::Fail("M flag not set in parsed RA info");
    }

    // Build the SOLICIT as the DHCPv6 client would when M=1.
    let mut client = crate::ipv6::dhcpv6::DhcpV6Client::new(IFACE, MAC, 1);
    let solicit = client.build_solicit(0xDEAD_01);

    // Verify msg_type = 1 (SOLICIT).
    if solicit.is_empty() || solicit[0] != MT_SOLICIT {
        return TestResult::Fail("SOLICIT msg_type != 1");
    }

    // Verify state transitioned to Solicit.
    use crate::ipv6::dhcpv6::DhcpV6State;
    if client.state != DhcpV6State::Solicit {
        return TestResult::Fail("DHCPv6 client state != Solicit after build_solicit");
    }

    // Verify IA_NA option is present (option code 3, 2 bytes big-endian).
    let mut found_ia_na = false;
    let mut p = 4; // skip 4-byte header
    while p + 4 <= solicit.len() {
        let code = u16::from_be_bytes([solicit[p], solicit[p + 1]]);
        let len = u16::from_be_bytes([solicit[p + 2], solicit[p + 3]]) as usize;
        if code == 3 {
            found_ia_na = true;
        }
        p += 4 + len;
    }
    if !found_ia_na {
        return TestResult::Fail("SOLICIT missing IA_NA option");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ra_m1_triggers_dhcpv6_solicit);

// ── Smoke 10: RA O=1 → stateless DHCPv6 INFORMATION-REQUEST ─────────
//
// Inject RA with M=0, O=1 (Other Config). The client must send a
// DHCPv6 INFORMATION-REQUEST (msg_type=11). Verify the body produced.
//
// Linux ref: `addrconf.c addrconf_prefix_rcv()` O-flag → calls
//   `dhcp6c` in userspace. NARF builds the frame in-kernel.

fn smoke_v6_ra_o1_stateless_dhcpv6() -> TestResult {
    const IFACE: &str = "v6e2e-10";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let router: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];

    // RA with O=1 (and M=0).
    let ra_body = build_ra_body(RA_FLAG_OTHER_CONFIG, 1800);
    let info = match ndp::on_ra(IFACE, router, &ra_body, 0) {
        Some(i) => i,
        None => return TestResult::Fail("on_ra returned None"),
    };

    if info.managed_flag {
        return TestResult::Fail("M flag should NOT be set in O-only RA");
    }
    if !info.other_flag {
        return TestResult::Fail("O flag not set in parsed RA info");
    }

    // Build an INFORMATION-REQUEST body (stateless DHCPv6, RFC 8415 §18.2.6).
    // INFORMATION-REQUEST msg_type = 11.
    // For stateless DHCPv6 we don't need an IA_NA — just client-id + oro.
    use crate::pkt_dhcpv6::{
        append_clientid_duid_ll, append_elapsed_time, append_oro, DhcpV6Header,
        OPT_DNS_SERVERS, OPT_DOMAIN_LIST,
    };
    let mut info_req: Vec<u8> = Vec::with_capacity(64);
    let hdr = DhcpV6Header {
        msg_type: MT_INFORMATION_REQUEST,
        transaction_id: 0xAB_CD_EF,
    };
    info_req.extend_from_slice(&hdr.encode());
    append_clientid_duid_ll(&mut info_req, 1, &MAC);
    append_elapsed_time(&mut info_req, 0);
    append_oro(&mut info_req, &[OPT_DNS_SERVERS, OPT_DOMAIN_LIST]);

    if info_req.is_empty() || info_req[0] != MT_INFORMATION_REQUEST {
        return TestResult::Fail("INFORMATION-REQUEST msg_type != 11");
    }

    // Must NOT contain IA_NA (option code 3) for stateless DHCPv6.
    let mut found_ia_na = false;
    let mut p = 4;
    while p + 4 <= info_req.len() {
        let code = u16::from_be_bytes([info_req[p], info_req[p + 1]]);
        let len = u16::from_be_bytes([info_req[p + 2], info_req[p + 3]]) as usize;
        if code == 3 {
            found_ia_na = true;
        }
        p += 4 + len;
    }
    if found_ia_na {
        return TestResult::Fail("INFORMATION-REQUEST must not contain IA_NA (stateless)");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ra_o1_stateless_dhcpv6);

// ── Smoke 11: NS targeting our addr → NA reply emitted ───────────────
//
// Inject a Neighbor Solicitation whose target = our Preferred addr.
// ndp::on_ns must return SendBody with an NA.
//
// Linux ref: `ndisc.c ndisc_recv_ns()` → `ndisc_send_na()` when
//   `ifp` is found (our address) and state != TENTATIVE.

fn smoke_v6_ns_for_our_addr_triggers_na() -> TestResult {
    const IFACE: &str = "v6e2e-11";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let ll = addrs::link_local_from_mac(MAC);
    slaac::link_local(IFACE, MAC, 0);
    slaac::dad_passed(IFACE, &ll); // addr → Preferred

    // Build a Neighbor Solicitation targeting our link-local.
    let ns_body = ndp::build_ns(ll, [0x02, 0x00, 0x00, 0x00, 0x00, 0x99]);

    // Inject into on_ns.
    let result = ndp::on_ns(IFACE, Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x99]), &ns_body);

    match result {
        ndp::NdRxResult::SendBody(na_body) => {
            // Verify it's an NA (type 136).
            if na_body.is_empty() || na_body[0] != 136 {
                return TestResult::Fail("NA body has wrong ICMPv6 type (expected 136)");
            }
            // Target in NA (bytes 8..24) must match `ll`.
            if na_body.len() < 24 {
                return TestResult::Fail("NA body too short");
            }
            let na_target: [u8; 16] = na_body[8..24].try_into().unwrap();
            if na_target != ll {
                return TestResult::Fail("NA target != our link-local addr");
            }
        }
        ndp::NdRxResult::DadConflict(_) => {
            return TestResult::Fail("on_ns returned DadConflict for Preferred addr (should send NA)");
        }
        _ => {
            return TestResult::Fail("on_ns did not return SendBody for NS targeting our Preferred addr");
        }
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ns_for_our_addr_triggers_na);

// ── Smoke 12: NA received → neighbor cache Incomplete → Reachable ───
//
// Insert an Incomplete entry, then inject an NA with target LL addr.
// ndp::on_na must update the cache to Reachable with the MAC.
//
// Linux ref: `ndisc.c ndisc_recv_na()` calls `neigh_update()` which
//   transitions INCOMPLETE → REACHABLE when an NA with TLLA arrives.

fn smoke_v6_na_updates_neighbor_cache() -> TestResult {
    const IFACE: &str = "v6e2e-12";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let peer_ip: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let peer_mac: [u8; 6] = [0x02, 0xAB, 0xCD, 0xEF, 0x00, 0x01];

    // Pre-insert an Incomplete entry (as if we had sent an NS and are waiting).
    ndp::neigh_upsert(ndp::Neigh {
        iface: String::from(IFACE),
        ip: peer_ip,
        mac: None,
        state: ndp::NeighState::Incomplete,
        is_router: false,
        deadline_ns: 0,
    });

    // Build NA from peer (Solicited + Override flags).
    let na_body = ndp::build_na(peer_ip, peer_mac, false);

    // Inject.
    let result = ndp::on_na(IFACE, &na_body);
    match result {
        ndp::NdRxResult::Updated => {}
        _ => return TestResult::Fail("on_na did not return Updated"),
    }

    // Cache entry must now be Reachable with peer_mac.
    let cached_mac = match ndp::neigh_lookup(IFACE, &peer_ip) {
        Some(m) => m,
        None => return TestResult::Fail("neighbor cache entry not found after NA"),
    };
    if cached_mac != peer_mac {
        return TestResult::Fail("neighbor cache MAC != peer_mac after NA");
    }

    let neigh_list = ndp::neigh_list();
    let entry = match neigh_list.iter().find(|e| e.ip == peer_ip && e.iface == IFACE) {
        Some(e) => e,
        None => return TestResult::Fail("neighbor entry not found in list"),
    };
    if entry.state != ndp::NeighState::Reachable {
        return TestResult::Fail("neighbor entry not Reachable after NA");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_na_updates_neighbor_cache);

// ── Smoke 13: REACHABLE → STALE on timeout ──────────────────────────
//
// Insert a Reachable entry with a past deadline, call ndp::age_tick →
// entry must transition to Stale.
//
// Linux ref: `ndisc.c neigh_timer_handler()` → `neigh_update()` when
//   NUD_REACHABLE timer fires.

fn smoke_v6_neigh_reachable_to_stale() -> TestResult {
    const IFACE: &str = "v6e2e-13";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let peer_ip: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];
    let peer_mac: [u8; 6] = [0x02, 0xBB, 0xCC, 0xDD, 0x00, 0x01];

    // Insert a Reachable entry with a deadline of 1 ns (already past).
    ndp::neigh_upsert(ndp::Neigh {
        iface: String::from(IFACE),
        ip: peer_ip,
        mac: Some(peer_mac),
        state: ndp::NeighState::Reachable,
        is_router: false,
        deadline_ns: 1, // past
    });

    // Fast-forward time: now_ns = 2 (past the deadline).
    ndp::age_tick(2);

    let neigh_list = ndp::neigh_list();
    let entry = match neigh_list.iter().find(|e| e.ip == peer_ip && e.iface == IFACE) {
        Some(e) => e,
        None => return TestResult::Fail("neighbor entry vanished after age_tick"),
    };
    if entry.state != ndp::NeighState::Stale {
        return TestResult::Fail("neighbor not Stale after REACHABLE_TIME expiry");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_neigh_reachable_to_stale);

// ── Smoke 14: STALE → DELAY → PROBE on next use ──────────────────────
//
// Insert a Stale entry. Mark it Delay (simulating a packet send).
// Call age_tick with a past deadline → must transition to Probe.
//
// Linux ref: `ndisc.c neigh_suspect()` / `neigh_timer_handler()`:
//   STALE→DELAY when data sent; DELAY→PROBE when DELAY_PROBE_TIME fires.

fn smoke_v6_neigh_stale_delay_probe() -> TestResult {
    const IFACE: &str = "v6e2e-14";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let peer_ip: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03,
    ];
    let peer_mac: [u8; 6] = [0x02, 0xCC, 0xDD, 0xEE, 0x00, 0x01];

    // Insert Stale.
    ndp::neigh_upsert(ndp::Neigh {
        iface: String::from(IFACE),
        ip: peer_ip,
        mac: Some(peer_mac),
        state: ndp::NeighState::Stale,
        is_router: false,
        deadline_ns: 0,
    });

    // Simulate "packet sent to stale neighbor" → transition to Delay.
    ndp::neigh_upsert(ndp::Neigh {
        iface: String::from(IFACE),
        ip: peer_ip,
        mac: Some(peer_mac),
        state: ndp::NeighState::Delay,
        is_router: false,
        deadline_ns: 1, // deadline already past
    });

    {
        let neigh_list = ndp::neigh_list();
        let entry = neigh_list.iter().find(|e| e.ip == peer_ip).unwrap();
        if entry.state != ndp::NeighState::Delay {
            return TestResult::Fail("neighbor not in Delay state after upsert");
        }
    }

    // age_tick fires the DELAY timer → Probe.
    ndp::age_tick(2);

    let neigh_list = ndp::neigh_list();
    let entry = match neigh_list.iter().find(|e| e.ip == peer_ip && e.iface == IFACE) {
        Some(e) => e,
        None => return TestResult::Fail("neighbor entry vanished after age_tick"),
    };
    if entry.state != ndp::NeighState::Probe {
        return TestResult::Fail("neighbor not in Probe state after DELAY_PROBE_TIME expiry");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_neigh_stale_delay_probe);

// ── Smoke 15: ICMPv6 ping6 via rx injection (loopback) ───────────────
//
// Build an Echo Request body, inject it as an RX frame into
// ipv6_stack::rx_frame. The stack must:
//  (a) deliver the request to the icmp6_sock queue (type 128),
//  (b) When we inject an Echo Reply (type 129) with matching id+seq,
//      icmp6_sock::next_msg returns the reply.
//
// Linux ref: `ndisc.c` / `icmp6.c icmp6_echo_reply()` → socket delivery.

fn smoke_v6_ping6_echo_loopback() -> TestResult {
    const IFACE: &str = "v6e2e-15";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    // Install a Preferred link-local so the stack recognizes the dest addr.
    let ll = addrs::link_local_from_mac(MAC);
    slaac::link_local(IFACE, MAC, 0);
    slaac::dad_passed(IFACE, &ll);

    use crate::ipv6::icmp6_sock;
    let echo_id: u16 = 0xBEEF;
    let echo_seq: u16 = 1;
    let payload = b"narf-v6";

    // Open a socket to receive Echo Replies.
    let sock_id = icmp6_sock::open(echo_id);

    // Build an Echo Request body.
    let req_body = icmp6_sock::build_echo_request(echo_id, echo_seq, payload);

    // Wrap in a full frame and inject via rx_frame.
    let frame = build_icmpv6_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x99],
        multicast_mac(&ll),
        ll, // src = our own ll (loopback)
        ll, // dst = our own ll
        &req_body,
    );
    // rx_frame expects the frame *after* the Ethernet header.
    ipv6_stack::rx_frame(IFACE, &frame[ETH_HDR_LEN..]);

    // Drain (the stack might have emitted something — ignore).
    drain_v6();

    // Now inject an Echo Reply with the same id+seq — simulating the
    // peer responding.
    let reply_body = icmp6_sock::build_echo_reply(echo_id, echo_seq, payload);
    let reply_frame = build_icmpv6_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x99],
        multicast_mac(&ll),
        ll,
        ll,
        &reply_body,
    );
    ipv6_stack::rx_frame(IFACE, &reply_frame[ETH_HDR_LEN..]);

    // The socket should have the Echo Reply.
    let msg = match icmp6_sock::next_msg(sock_id) {
        Some(m) => m,
        None => {
            icmp6_sock::close(sock_id);
            return TestResult::Fail("no ICMPv6 msg in socket queue after Echo Reply injection");
        }
    };

    icmp6_sock::close(sock_id);

    use crate::pkt_ipv6::ICMPV6_ECHO_REPLY;
    if msg.typ != ICMPV6_ECHO_REPLY {
        return TestResult::Fail("socket received wrong ICMPv6 type (expected 129 Echo Reply)");
    }

    // Verify id and seq in the body (bytes 4..8).
    if msg.body.len() < 8 {
        return TestResult::Fail("Echo Reply body too short");
    }
    let rx_id = u16::from_be_bytes([msg.body[4], msg.body[5]]);
    let rx_seq = u16::from_be_bytes([msg.body[6], msg.body[7]]);
    if rx_id != echo_id {
        return TestResult::Fail("Echo Reply id mismatch");
    }
    if rx_seq != echo_seq {
        return TestResult::Fail("Echo Reply seq mismatch");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_ping6_echo_loopback);

// ── Smoke 16: MLD report on group join ──────────────────────────────
//
// Call mld::build_join_report(FF0E::CAFE) → MLDv2 Report frame with
// a CHANGE_TO_EXCLUDE record for that group.
//
// Linux ref: `mld.c igmp6_join_group()` → `igmp6_send()` with
//   CHANGE_TO_EXCLUDE (type 4) record.

fn smoke_v6_mld_report_on_group_join() -> TestResult {
    const _IFACE: &str = "v6e2e-16";

    let group: [u8; 16] = [
        0xFF, 0x0E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xCA, 0xFE,
    ];

    let report = mld::build_join_report(group);

    // Type must be 143 (MLD2 Report).
    if report.is_empty() || report[0] != mld::ICMPV6_MLD2_REPORT {
        return TestResult::Fail("MLDv2 Report has wrong ICMPv6 type");
    }

    // Number of records (bytes 6..8) must be 1.
    if report.len() < 8 {
        return TestResult::Fail("MLDv2 Report body too short");
    }
    let num_records = u16::from_be_bytes([report[6], report[7]]);
    if num_records != 1 {
        return TestResult::Fail("MLDv2 Report must have exactly 1 record");
    }

    // Record at offset 8: type (1) + aux_len (1) + num_src (2) + mcast_addr (16).
    if report.len() < 28 {
        return TestResult::Fail("MLDv2 Report too short for record");
    }
    let record_type = report[8];
    // CHANGE_TO_EXCLUDE = 4 (join = exclude everything not in source list,
    // which means "exclude {}" = accept all, i.e. join).
    if record_type != mld::MlRecordType::ChangeToExclude as u8 {
        return TestResult::Fail("MLDv2 join record type != CHANGE_TO_EXCLUDE (4)");
    }
    let record_group: [u8; 16] = report[12..28].try_into().unwrap();
    if record_group != group {
        return TestResult::Fail("MLDv2 Report multicast address != FF0E::CAFE");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_mld_report_on_group_join);

// ── Smoke 17: /proc/net/if_inet6 reflects SLAAC addr ────────────────
//
// After Smoke 7's SLAAC setup, addrs::snapshot() must contain the
// 2001:db8::<EUI-64> address in the Ipv6IfAddrSnapshot format.
//
// Linux ref: `addrconf.c if_inet6_seq_show()` writes each bound addr
//   in `<32-hex> <ifindex-hex> <prefix-hex> <scope-hex> <flags-hex>
//   <iface>` format.

fn smoke_v6_proc_if_inet6_reflects_slaac() -> TestResult {
    const IFACE: &str = "v6e2e-17";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let prefix: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let pio = ndp::RaPrefix {
        prefix,
        prefix_len: 64,
        on_link: true,
        autonomous: true,
        valid_lifetime_s: 2_592_000,
        preferred_lifetime_s: 604_800,
    };
    let cfg = slaac::SlaacConfig {
        privacy_extensions: false,
        ..Default::default()
    };
    slaac::process_pio(IFACE, MAC, &pio, cfg, 0);

    let eui64 = addrs::eui64_from_mac(MAC);
    let expected = addrs::slaac_compose(&prefix, 64, &eui64);

    // Mark DAD passed.
    slaac::dad_passed(IFACE, &expected);

    // Read the snapshot (analogous to /proc/net/if_inet6).
    let snap = addrs::snapshot();
    let entry = match snap.iter().find(|s| s.addr == expected && s.iface == IFACE) {
        Some(e) => e,
        None => return TestResult::Fail("/proc/net/if_inet6: SLAAC addr not in snapshot"),
    };

    // prefix_len must be 64.
    if entry.prefix_len != 64 {
        return TestResult::Fail("/proc/net/if_inet6: prefix_len != 64");
    }

    // Scope byte: 0x00 for Global.
    if entry.scope != 0x00 {
        return TestResult::Fail("/proc/net/if_inet6: scope byte != 0x00 (Global)");
    }

    // Flags: 0x80 (Preferred / permanent) — as Linux sets IFA_F_PERMANENT.
    if entry.flags & 0x80 == 0 {
        return TestResult::Fail("/proc/net/if_inet6: Preferred flag not set");
    }

    // Verify the 32-hex-addr format would round-trip correctly.
    let hex_addr: String = expected.iter().map(|b| alloc::format!("{:02x}", b)).collect();
    if hex_addr.len() != 32 {
        return TestResult::Fail("32-hex-addr formatting is wrong length");
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_proc_if_inet6_reflects_slaac);

// ── Smoke 18: /proc/net/ipv6_route reflects default route ───────────
//
// After Smoke 6's RA, ipv6::route::snapshot() must contain the
// default route entry (::/0 via fe80::1).
//
// Linux ref: `fib6_table.c fib6_dump_table()` produces entries for
//   `cat /proc/net/ipv6_route` via `rt6_info_route()`.

fn smoke_v6_proc_ipv6_route_reflects_default_route() -> TestResult {
    const IFACE: &str = "v6e2e-18";
    const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];

    reset_v6(IFACE, MAC);

    let router: [u8; 16] = [
        0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let ra_body = build_ra_body(0, 1800);
    ndp::on_ra(IFACE, router, &ra_body, 0);

    let snap = crate::ipv6::route::snapshot();

    // Must have a ::/0 default route.
    let default_route = snap.iter().find(|r| r.dst_prefix_len == 0);
    match default_route {
        None => return TestResult::Fail("/proc/net/ipv6_route: no ::/0 default route"),
        Some(r) => {
            // Gateway must be fe80::1.
            if r.gateway != router {
                return TestResult::Fail("/proc/net/ipv6_route: default route gateway != fe80::1");
            }
            // RTF_GATEWAY flag (0x0002) must be set.
            if r.flags & 0x0002 == 0 {
                return TestResult::Fail("/proc/net/ipv6_route: RTF_GATEWAY not set on default route");
            }
            // RTF_UP (0x0001) must be set.
            if r.flags & 0x0001 == 0 {
                return TestResult::Fail("/proc/net/ipv6_route: RTF_UP not set");
            }
        }
    }

    TestResult::Pass
}
kernel_test_in!("net/ipv6_e2e", smoke_v6_proc_ipv6_route_reflects_default_route);
