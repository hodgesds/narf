//! Errno-conformance smokes for the in-kernel socket layer and netlink
//! responders, each checked against the Linux function that produces the
//! same error. Every smoke names the Linux source it mirrors.
//!
//! Scope: `udp_sock` / `icmp_sock` ICMP-error paths and the
//! `NETLINK_ROUTE` / `NETLINK_GENERIC` / `NETLINK_SOCK_DIAG` /
//! `NETLINK_NETFILTER` / `NETLINK_AUDIT` responders. Paths already asserted
//! elsewhere (duplicate IPv4 route `EEXIST`, conntrack miss `ENOENT`, the
//! UDP 65507 / SO_BROADCAST smokes in `udp_sock`, the kernel-TCP errno
//! suite in `tcp_e2e_tests`) are not repeated.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use narf_lib::errno as e;

// ── netlink framing helpers ─────────────────────────────────────────

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn push_attr(body: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    body.resize(align4(body.len()), 0);
    body.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    body.resize(align4(body.len()), 0);
}

fn nlmsg(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + body.len();
    let mut m = Vec::with_capacity(align4(len));
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&kind.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(body);
    m.resize(align4(len), 0);
    m
}

/// The (negated) `nlmsgerr.error` of a reply, if it is an `NLMSG_ERROR`.
fn nl_errno(reply: &[u8]) -> Option<i64> {
    if reply.len() < NLMSG_HDRLEN + 4 {
        return None;
    }
    if u16::from_ne_bytes([reply[4], reply[5]]) != NLMSG_ERROR {
        return None;
    }
    Some(-(i32::from_ne_bytes(reply[16..20].try_into().ok()?) as i64))
}

fn nl_type(reply: &[u8]) -> u16 {
    u16::from_ne_bytes([reply[4], reply[5]])
}

/// Errno of the first reply, `Some(0)` for an ACK, `None` for a non-error.
fn first_errno(replies: &[Vec<u8>]) -> Option<i64> {
    replies.first().and_then(|r| nl_errno(r))
}

// ── rtnetlink helpers ───────────────────────────────────────────────

fn discard(_: &[u8]) -> Result<(), ()> {
    Ok(())
}

/// Register a throwaway interface and an admin handle bound to it.
fn rtnl_admin(name: &'static str, mac_tail: u8) -> Option<(crate::AdminHandle, u32)> {
    crate::iface::register(name, [0x02, 0, 0, 0, 0x7e, mac_tail], discard);
    let ifindex = crate::netlink_route::ifindex_for_name(name)?;
    let cap = narf_capabilities::Cap::<crate::AdminCap, narf_capabilities::Invoke>::bootstrap();
    Some((crate::AdminHandle::new(cap, String::from(name)), ifindex))
}

fn rtnl(admin: Option<&crate::AdminHandle>, request: &[u8]) -> Option<i64> {
    let replies = crate::netlink_route::build_replies_authorized(request, admin).ok()?;
    first_errno(&replies)
}

fn ifaddrmsg(family: u8, prefix: u8, ifindex: u32, addr: &[u8]) -> Vec<u8> {
    let mut b = alloc::vec![family, prefix, 0, 0];
    b.extend_from_slice(&ifindex.to_ne_bytes());
    push_attr(&mut b, crate::netlink_route::IFA_LOCAL, addr);
    b
}

fn rtmsg(family: u8, dst_len: u8, dst: Option<&[u8]>, oif: u32) -> Vec<u8> {
    // family, dst_len, src_len, tos, table=MAIN, proto=BOOT(3),
    // scope=LINK(253), type=UNICAST(1), flags.
    let mut b = alloc::vec![family, dst_len, 0, 0, crate::route::TABLE_MAIN, 3, 253, 1];
    b.extend_from_slice(&0u32.to_ne_bytes());
    if let Some(dst) = dst {
        push_attr(&mut b, crate::netlink_route::RTA_DST, dst);
    }
    push_attr(&mut b, crate::netlink_route::RTA_OIF, &oif.to_ne_bytes());
    b
}

fn ndmsg(family: u8, ifindex: u32, dst: &[u8], lladdr: Option<[u8; 6]>) -> Vec<u8> {
    let mut b = alloc::vec![family, 0, 0, 0];
    b.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    b.extend_from_slice(&crate::netlink_route::NUD_REACHABLE.to_ne_bytes());
    b.extend_from_slice(&[0, 0]);
    push_attr(&mut b, 1 /* NDA_DST */, dst);
    if let Some(mac) = lladdr {
        push_attr(&mut b, 2 /* NDA_LLADDR */, &mac);
    }
    b
}

fn ifinfomsg(ifindex: i32, name: Option<&str>, mac: Option<[u8; 6]>) -> Vec<u8> {
    let mut b = alloc::vec![0u8, 0, 0, 0];
    b.extend_from_slice(&ifindex.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes()); // flags
    b.extend_from_slice(&0u32.to_ne_bytes()); // change
    if let Some(name) = name {
        let mut n = Vec::from(name.as_bytes());
        n.push(0);
        push_attr(&mut b, crate::netlink_route::IFLA_IFNAME, &n);
    }
    if let Some(mac) = mac {
        push_attr(&mut b, crate::netlink_route::IFLA_ADDRESS, &mac);
    }
    b
}

use crate::netlink_route::{
    RTM_DELADDR, RTM_DELNEIGH, RTM_DELROUTE, RTM_GETLINK, RTM_GETROUTE, RTM_NEWADDR, RTM_NEWLINK,
    RTM_NEWNEIGH, RTM_NEWROUTE, RTM_SETLINK,
};

// ── RTM_DELROUTE / RTM_DELADDR on missing state ────────────────────

/// Linux `fib_table_delete` (net/ipv4/fib_trie.c) returns -ESRCH when no
/// alias matches; `ip6_route_del` (net/ipv6/route.c) starts at
/// `err = -ESRCH`. iproute2 prints "RTNETLINK answers: No such process".
fn smoke_rtnl_delroute_missing_is_esrch() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt0", 1) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let v4 = nlmsg(
        RTM_DELROUTE,
        NLM_F_REQUEST | NLM_F_ACK,
        1,
        &rtmsg(AF_INET, 24, Some(&[203, 0, 113, 0]), ifindex),
    );
    if rtnl(Some(&admin), &v4) != Some(e::ESRCH) {
        return TestResult::Fail("IPv4 RTM_DELROUTE of a missing route must be -ESRCH");
    }
    let mut dst6 = [0u8; 16];
    dst6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    let v6 = nlmsg(
        RTM_DELROUTE,
        NLM_F_REQUEST | NLM_F_ACK,
        2,
        &rtmsg(AF_INET6, 64, Some(&dst6), ifindex),
    );
    if rtnl(Some(&admin), &v6) != Some(e::ESRCH) {
        return TestResult::Fail("IPv6 RTM_DELROUTE of a missing route must be -ESRCH");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_delroute_missing_is_esrch);

/// Linux `inet_rtm_deladdr` (net/ipv4/devinet.c): "ipv4: Address not
/// found" → -EADDRNOTAVAIL; `inet6_addr_del` (net/ipv6/addrconf.c):
/// "address not found" → -EADDRNOTAVAIL.
fn smoke_rtnl_deladdr_missing_is_eaddrnotavail() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt1", 2) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let v4 = nlmsg(
        RTM_DELADDR,
        NLM_F_REQUEST | NLM_F_ACK,
        3,
        &ifaddrmsg(AF_INET, 24, ifindex, &[198, 18, 7, 9]),
    );
    if rtnl(Some(&admin), &v4) != Some(e::EADDRNOTAVAIL) {
        return TestResult::Fail("IPv4 RTM_DELADDR of a missing address must be -EADDRNOTAVAIL");
    }
    let mut a6 = [0u8; 16];
    a6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    a6[15] = 0x77;
    let v6 = nlmsg(
        RTM_DELADDR,
        NLM_F_REQUEST | NLM_F_ACK,
        4,
        &ifaddrmsg(AF_INET6, 64, ifindex, &a6),
    );
    if rtnl(Some(&admin), &v6) != Some(e::EADDRNOTAVAIL) {
        return TestResult::Fail("IPv6 RTM_DELADDR of a missing address must be -EADDRNOTAVAIL");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_deladdr_missing_is_eaddrnotavail);

// ── NLM_F_CREATE / EXCL / REPLACE ladders ───────────────────────────

/// Linux `inet_rtm_newaddr` (net/ipv4/devinet.c) inserts a new address
/// without NLM_F_CREATE ("userspace already relies on not having to
/// provide this"); an existing one is -EEXIST without NLM_F_REPLACE.
fn smoke_rtnl_newaddr_without_create_succeeds() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt2", 3) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let body = ifaddrmsg(AF_INET, 24, ifindex, &[198, 18, 42, 1]);
    let add = nlmsg(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, 5, &body);
    if rtnl(Some(&admin), &add) != Some(0) {
        return TestResult::Fail("RTM_NEWADDR without NLM_F_CREATE must add the address");
    }
    if rtnl(Some(&admin), &add) != Some(e::EEXIST) {
        return TestResult::Fail("re-adding an address without NLM_F_REPLACE must be -EEXIST");
    }
    let del = nlmsg(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 6, &body);
    if rtnl(Some(&admin), &del) != Some(0) {
        return TestResult::Fail("RTM_DELADDR of the added address failed");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_newaddr_without_create_succeeds);

/// Linux `fib_table_insert` (net/ipv4/fib_trie.c): a new IPv4 route needs
/// NLM_F_CREATE (`err = -ENOENT; if (!(nlflags & NLM_F_CREATE)) goto out`).
/// `fib6_add_rt2node` (net/ipv6/ip6_fib.c) adds an IPv6 route anyway with a
/// "NLM_F_CREATE should be set" warning, unless NLM_F_REPLACE asked to
/// replace a route that is not there (-ENOENT).
fn smoke_rtnl_newroute_create_flag_per_family() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt3", 4) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let v4 = nlmsg(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK,
        7,
        &rtmsg(AF_INET, 24, Some(&[203, 0, 113, 0]), ifindex),
    );
    if rtnl(Some(&admin), &v4) != Some(e::ENOENT) {
        return TestResult::Fail("IPv4 RTM_NEWROUTE without NLM_F_CREATE must be -ENOENT");
    }
    let mut dst6 = [0u8; 16];
    dst6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    dst6[4] = 0x42;
    let body6 = rtmsg(AF_INET6, 64, Some(&dst6), ifindex);
    let replace = nlmsg(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE,
        8,
        &body6,
    );
    if rtnl(Some(&admin), &replace) != Some(e::ENOENT) {
        return TestResult::Fail("IPv6 NLM_F_REPLACE of a missing route must be -ENOENT");
    }
    let plain = nlmsg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, 9, &body6);
    if rtnl(Some(&admin), &plain) != Some(0) {
        return TestResult::Fail("IPv6 RTM_NEWROUTE without NLM_F_CREATE must still add");
    }
    let del = nlmsg(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, 10, &body6);
    if rtnl(Some(&admin), &del) != Some(0) {
        return TestResult::Fail("IPv6 RTM_DELROUTE of the added route failed");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_newroute_create_flag_per_family);

/// Linux `neigh_add` (net/core/neighbour.c): a missing entry without
/// NLM_F_CREATE is -ENOENT; an existing entry is -EEXIST only under
/// NLM_F_EXCL, and is otherwise updated (success) even without
/// NLM_F_REPLACE.
fn smoke_rtnl_newneigh_flag_ladder() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt4", 5) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let ip = [198, 18, 9, 9];
    let mac = Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let body = ndmsg(AF_INET, ifindex, &ip, mac);
    let no_create = nlmsg(RTM_NEWNEIGH, NLM_F_REQUEST | NLM_F_ACK, 11, &body);
    if rtnl(Some(&admin), &no_create) != Some(e::ENOENT) {
        return TestResult::Fail(
            "RTM_NEWNEIGH of a missing entry without NLM_F_CREATE must be -ENOENT",
        );
    }
    let create = nlmsg(
        RTM_NEWNEIGH,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        12,
        &body,
    );
    if rtnl(Some(&admin), &create) != Some(0) {
        return TestResult::Fail("RTM_NEWNEIGH with NLM_F_CREATE failed");
    }
    // Existing, no EXCL, no REPLACE: Linux updates and returns 0.
    if rtnl(Some(&admin), &create) != Some(0) {
        return TestResult::Fail(
            "RTM_NEWNEIGH on an existing entry without NLM_F_EXCL must succeed",
        );
    }
    let excl = nlmsg(
        RTM_NEWNEIGH,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        13,
        &body,
    );
    let excl_result = rtnl(Some(&admin), &excl);
    let del = nlmsg(RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK, 14, &body);
    let del_result = rtnl(Some(&admin), &del);
    if excl_result != Some(e::EEXIST) {
        return TestResult::Fail("RTM_NEWNEIGH NLM_F_EXCL on an existing entry must be -EEXIST");
    }
    if del_result != Some(0) {
        return TestResult::Fail("RTM_DELNEIGH of the created entry failed");
    }
    // `neigh_delete`: the entry is gone now → -ENOENT.
    if rtnl(Some(&admin), &del) != Some(e::ENOENT) {
        return TestResult::Fail("RTM_DELNEIGH of a missing entry must be -ENOENT");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_newneigh_flag_ladder);

// ── Family dispatch ─────────────────────────────────────────────────

/// Linux `neigh_add` / `neigh_delete`: `neigh_find_table(ndm_family)`
/// miss → -EAFNOSUPPORT. Address and route handlers are registered per
/// family, so `rtnetlink_rcv_msg` answers an unknown family -EOPNOTSUPP.
fn smoke_rtnl_unknown_family_errnos() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt5", 6) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    const AF_PACKET: u8 = 17;
    let neigh = nlmsg(
        RTM_NEWNEIGH,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        15,
        &ndmsg(AF_PACKET, ifindex, &[1, 2, 3, 4], None),
    );
    if rtnl(Some(&admin), &neigh) != Some(e::EAFNOSUPPORT) {
        return TestResult::Fail("RTM_NEWNEIGH with an unknown family must be -EAFNOSUPPORT");
    }
    let addr = nlmsg(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK,
        16,
        &ifaddrmsg(AF_PACKET, 24, ifindex, &[1, 2, 3, 4]),
    );
    if rtnl(Some(&admin), &addr) != Some(e::EOPNOTSUPP) {
        return TestResult::Fail("RTM_NEWADDR with an unknown family must be -EOPNOTSUPP");
    }
    let route = nlmsg(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        17,
        &rtmsg(AF_PACKET, 0, None, ifindex),
    );
    if rtnl(Some(&admin), &route) != Some(e::EOPNOTSUPP) {
        return TestResult::Fail("RTM_NEWROUTE with an unknown family must be -EOPNOTSUPP");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_unknown_family_errnos);

// ── Links ───────────────────────────────────────────────────────────

/// Linux `rtnl_setlink` / `__rtnl_newlink` / `rtnl_changelink`
/// (net/core/rtnetlink.c):
/// - SETLINK with neither ifindex nor IFLA_IFNAME → -EINVAL;
/// - SETLINK by IFLA_IFNAME with ifindex 0 resolves the device;
/// - SETLINK / NEWLINK (no CREATE) on an unknown ifindex → -ENODEV;
/// - NEWLINK with a negative ifindex → -EINVAL;
/// - NEWLINK on an existing device: NLM_F_EXCL → -EEXIST, NLM_F_REPLACE →
///   -EOPNOTSUPP;
/// - NEWLINK create with no link kind → -EOPNOTSUPP ("Unknown device type").
fn smoke_rtnl_link_resolution_errnos() -> TestResult {
    let name = "errno-rt6";
    let Some((admin, ifindex)) = rtnl_admin(name, 7) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let ack = NLM_F_REQUEST | NLM_F_ACK;
    let cases: [(u16, u16, Vec<u8>, i64, &str); 8] = [
        (
            RTM_SETLINK,
            ack,
            ifinfomsg(0, None, None),
            e::EINVAL,
            "rtnl: SETLINK without ifindex/IFLA_IFNAME must be -EINVAL",
        ),
        (
            RTM_SETLINK,
            ack,
            ifinfomsg(0, Some(name), None),
            0,
            "rtnl: SETLINK by IFLA_IFNAME with ifindex 0 must resolve",
        ),
        (
            RTM_SETLINK,
            ack,
            ifinfomsg(0x7fff_0000, None, None),
            e::ENODEV,
            "rtnl: SETLINK of an unknown ifindex must be -ENODEV",
        ),
        (
            RTM_NEWLINK,
            ack,
            ifinfomsg(-1, None, None),
            e::EINVAL,
            "rtnl: NEWLINK with a negative ifindex must be -EINVAL",
        ),
        (
            RTM_NEWLINK,
            ack | NLM_F_EXCL,
            ifinfomsg(ifindex as i32, None, None),
            e::EEXIST,
            "rtnl: NEWLINK NLM_F_EXCL on an existing link must be -EEXIST",
        ),
        (
            RTM_NEWLINK,
            ack | NLM_F_REPLACE,
            ifinfomsg(ifindex as i32, None, None),
            e::EOPNOTSUPP,
            "rtnl: NEWLINK NLM_F_REPLACE on an existing link must be -EOPNOTSUPP",
        ),
        (
            RTM_NEWLINK,
            ack,
            ifinfomsg(0, Some("errno-nosuch"), None),
            e::ENODEV,
            "rtnl: NEWLINK of a missing link without NLM_F_CREATE must be -ENODEV",
        ),
        (
            RTM_NEWLINK,
            ack | NLM_F_CREATE,
            ifinfomsg(0, Some("errno-nosuch"), None),
            e::EOPNOTSUPP,
            "rtnl: NEWLINK create without a link kind must be -EOPNOTSUPP",
        ),
    ];
    for (i, (kind, flags, body, want, what)) in cases.iter().enumerate() {
        let got = rtnl(Some(&admin), &nlmsg(*kind, *flags, 20 + i as u32, body));
        if got != Some(*want) {
            return TestResult::Fail(what);
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_link_resolution_errnos);

/// Linux `do_setlink` → `dev_set_mac_address` → `eth_prepare_mac_addr_change`
/// (net/ethernet/eth.c): `!is_valid_ether_addr()` → -EADDRNOTAVAIL.
fn smoke_rtnl_setlink_multicast_mac_is_eaddrnotavail() -> TestResult {
    let Some((admin, ifindex)) = rtnl_admin("errno-rt7", 8) else {
        return TestResult::Fail("test interface has no rtnetlink ifindex");
    };
    let req = nlmsg(
        RTM_SETLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        30,
        &ifinfomsg(ifindex as i32, None, Some([0x01, 0, 0x5e, 0, 0, 1])),
    );
    if rtnl(Some(&admin), &req) != Some(e::EADDRNOTAVAIL) {
        return TestResult::Fail("IFLA_ADDRESS with a multicast MAC must be -EADDRNOTAVAIL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/errno",
    smoke_rtnl_setlink_multicast_mac_is_eaddrnotavail
);

/// Linux `rtnl_getlink`: ifindex 0 and no IFLA_IFNAME → -EINVAL (only a
/// named-but-absent device is -ENODEV).
fn smoke_rtnl_getlink_without_selector_is_einval() -> TestResult {
    let req = nlmsg(RTM_GETLINK, NLM_F_REQUEST, 31, &ifinfomsg(0, None, None));
    let replies = crate::netlink_route::build_dump(&req);
    if first_errno(&replies) != Some(e::EINVAL) {
        return TestResult::Fail("RTM_GETLINK without ifindex or IFLA_IFNAME must be -EINVAL");
    }
    let req = nlmsg(
        RTM_GETLINK,
        NLM_F_REQUEST,
        32,
        &ifinfomsg(0, Some("errno-no-such-link"), None),
    );
    if first_errno(&crate::netlink_route::build_dump(&req)) != Some(e::ENODEV) {
        return TestResult::Fail("RTM_GETLINK of a missing name must be -ENODEV");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_getlink_without_selector_is_einval);

/// Linux `inet_rtm_getroute` (net/ipv4/route.c): an absent RTA_DST is
/// `nla_get_in_addr_default(.., 0)` — a lookup of 0.0.0.0, never -EINVAL.
/// A family with no RTM_GETROUTE doit is -EOPNOTSUPP (`rtnetlink_rcv_msg`).
fn smoke_rtnl_getroute_family_and_default_dst() -> TestResult {
    let mut body = alloc::vec![AF_INET, 0, 0, 0, 0, 0, 0, 0];
    body.extend_from_slice(&0u32.to_ne_bytes());
    let replies = crate::netlink_route::build_dump(&nlmsg(RTM_GETROUTE, NLM_F_REQUEST, 33, &body));
    match first_errno(&replies) {
        None | Some(e::ENETUNREACH) => {}
        Some(_) => return TestResult::Fail("RTM_GETROUTE without RTA_DST must look up 0.0.0.0"),
    }
    body[0] = 0; // AF_UNSPEC
    let replies = crate::netlink_route::build_dump(&nlmsg(RTM_GETROUTE, NLM_F_REQUEST, 34, &body));
    if first_errno(&replies) != Some(e::EOPNOTSUPP) {
        return TestResult::Fail("non-dump RTM_GETROUTE for AF_UNSPEC must be -EOPNOTSUPP");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_rtnl_getroute_family_and_default_dst);

// ── NETLINK_GENERIC ─────────────────────────────────────────────────

const GENL_ERRNO_FAMILY: u16 = 0x3e;
const GENL_ERRNO_CMD: u8 = 7;

fn genl_errno_handler(
    _: u8,
    _: &[u8],
    _: bool,
) -> Result<Vec<crate::netlink_generic::GenlReply>, i32> {
    // Reaching the handler for an op the table does not advertise would
    // be the bug under test; answer something distinctive.
    Err(e::EMLINK as i32)
}

static GENL_ERRNO_OPS: &[crate::netlink_generic::GenlOperation] =
    &[crate::netlink_generic::GenlOperation {
        command: GENL_ERRNO_CMD,
        flags: 1 << 1, // GENL_CMD_CAP_DO only
    }];

/// Linux `genl_rcv_msg` (net/netlink/genetlink.c): unknown family id →
/// -ENOENT. `genl_family_rcv_msg` → `genl_get_cmd()`: a command the
/// family's op table lacks, or a DUMP of a DO-only op → -EOPNOTSUPP,
/// before the family's handler runs.
fn smoke_genl_family_and_command_errnos() -> TestResult {
    let _ = crate::netlink_generic::register_family(crate::netlink_generic::GenlFamily {
        id: GENL_ERRNO_FAMILY,
        name: "narf-errno",
        version: 1,
        max_attr: 0,
        operations: GENL_ERRNO_OPS,
        groups: &[],
        handler: genl_errno_handler,
    });
    let run = |kind: u16, flags: u16, cmd: u8| {
        let req = nlmsg(kind, flags, 40, &[cmd, 1, 0, 0]);
        crate::netlink_generic::build_replies(&req)
            .ok()
            .and_then(|r| first_errno(&r))
    };
    if run(0x3fff, NLM_F_REQUEST, 1) != Some(e::ENOENT) {
        return TestResult::Fail("unknown generic-netlink family id must be -ENOENT");
    }
    if run(GENL_ERRNO_FAMILY, NLM_F_REQUEST, 99) != Some(e::EOPNOTSUPP) {
        return TestResult::Fail("command absent from the op table must be -EOPNOTSUPP");
    }
    if run(
        GENL_ERRNO_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        GENL_ERRNO_CMD,
    ) != Some(e::EOPNOTSUPP)
    {
        return TestResult::Fail("DUMP of a DO-only command must be -EOPNOTSUPP");
    }
    if run(GENL_ERRNO_FAMILY, NLM_F_REQUEST, GENL_ERRNO_CMD) != Some(e::EMLINK) {
        return TestResult::Fail("advertised DO command did not reach the family handler");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_genl_family_and_command_errnos);

/// Linux `ctrl_getfamily`: no CTRL_ATTR_FAMILY_ID / _NAME → -EINVAL;
/// unknown name → -ENOENT.
fn smoke_genl_getfamily_errnos() -> TestResult {
    let ctrl = crate::netlink_generic::GENL_ID_CTRL;
    let get = crate::netlink_generic::CTRL_CMD_GETFAMILY;
    let bare = nlmsg(ctrl, NLM_F_REQUEST, 41, &[get, 2, 0, 0]);
    let replies = crate::netlink_generic::build_replies(&bare).unwrap_or_default();
    if first_errno(&replies) != Some(e::EINVAL) {
        return TestResult::Fail("CTRL_CMD_GETFAMILY without a selector must be -EINVAL");
    }
    let mut body = alloc::vec![get, 2, 0, 0];
    push_attr(
        &mut body,
        2, /* CTRL_ATTR_FAMILY_NAME */
        b"no-such-family\0",
    );
    let replies = crate::netlink_generic::build_replies(&nlmsg(ctrl, NLM_F_REQUEST, 42, &body))
        .unwrap_or_default();
    if first_errno(&replies) != Some(e::ENOENT) {
        return TestResult::Fail("CTRL_CMD_GETFAMILY of an unknown name must be -ENOENT");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_genl_getfamily_errnos);

// ── NETLINK_SOCK_DIAG ───────────────────────────────────────────────

fn diag(kind: u16, family: u8, protocol: u8, len: usize) -> Option<i64> {
    let mut body = alloc::vec![0u8; len];
    if len >= 2 {
        body[0] = family;
        body[1] = protocol;
    }
    let req = nlmsg(kind, NLM_F_REQUEST | NLM_F_DUMP, 50, &body);
    first_errno(&crate::netlink_diag::build_replies(&req).ok()?)
}

/// Linux `sock_diag_rcv_msg` / `__sock_diag_cmd` (net/core/sock_diag.c)
/// and `inet_diag_handler_cmd` / `inet_diag_lock_handler`
/// (net/ipv4/inet_diag.c):
/// - unknown nlmsg_type → -EINVAL; TCPDIAG_GETSOCK without the compat hook
///   and SOCK_DESTROY without a destroy op → -EOPNOTSUPP;
/// - `sdiag_family >= AF_MAX` → -EINVAL; no handler for the family →
///   -ENOENT; no inet_diag handler for the protocol → -ENOENT.
fn smoke_sock_diag_errnos() -> TestResult {
    const AF_UNIX: u8 = 1;
    const IPPROTO_SCTP: u8 = 132;
    let cases: [(Option<i64>, i64, &str); 6] = [
        (
            diag(99, AF_INET, 6, 56),
            e::EINVAL,
            "sock_diag: unknown nlmsg_type must be -EINVAL",
        ),
        (
            diag(18, AF_INET, 6, 56),
            e::EOPNOTSUPP,
            "sock_diag: TCPDIAG_GETSOCK without compat must be -EOPNOTSUPP",
        ),
        (
            diag(21, AF_INET, 6, 56),
            e::EOPNOTSUPP,
            "sock_diag: SOCK_DESTROY without destroy op must be -EOPNOTSUPP",
        ),
        (
            diag(20, 46, 0, 56),
            e::EINVAL,
            "sock_diag: family >= AF_MAX must be -EINVAL",
        ),
        (
            diag(20, AF_UNIX, 0, 24),
            e::ENOENT,
            "sock_diag: family without a handler must be -ENOENT",
        ),
        (
            diag(20, AF_INET, IPPROTO_SCTP, 56),
            e::ENOENT,
            "sock_diag: protocol without an inet_diag handler must be -ENOENT",
        ),
    ];
    for (got, want, what) in cases {
        if got != Some(want) {
            return TestResult::Fail(what);
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_sock_diag_errnos);

// ── NETLINK_NETFILTER (nf_tables) ───────────────────────────────────

const NFT_SUBSYS: u16 = 10 << 8;

fn nft(
    ns: u64,
    admin: &crate::netfilter::NetfilterAdminHandle,
    msg: u16,
    flags: u16,
    family: u8,
    attrs: &[(u16, &[u8])],
) -> Option<i64> {
    let mut body = alloc::vec![family, 0, 0, 0];
    for (kind, payload) in attrs {
        push_attr(&mut body, *kind, payload);
    }
    let req = nlmsg(NFT_SUBSYS | msg, flags, 60, &body);
    let replies = crate::netlink_netfilter::build_replies_authorized(ns, &req, Some(admin)).ok()?;
    first_errno(&replies)
}

/// Linux `nf_tables_newtable` / `nf_tables_newchain`
/// (net/netfilter/nf_tables_api.c): an existing object is -EEXIST only under
/// NLM_F_EXCL, -EOPNOTSUPP under NLM_F_REPLACE, else an in-place update that
/// returns 0. `nft_supported_family` miss → -EOPNOTSUPP. `nft_table_lookup`
/// miss → -ENOENT.
fn smoke_nft_newtable_newchain_errnos() -> TestResult {
    use crate::netfilter::{NetfilterAdminHandle, NetfilterRights};
    const NEWTABLE: u16 = 0;
    const DELTABLE: u16 = 2;
    const NEWCHAIN: u16 = 3;
    const DELCHAIN: u16 = 5;
    const NFPROTO_IPV6: u8 = 10;
    let ns = 0x00e7_7a0e;
    let admin = NetfilterAdminHandle::mint(ns, NetfilterRights::ALL);
    let ack = NLM_F_REQUEST | NLM_F_ACK;
    let table: &[(u16, &[u8])] = &[(1, b"errno\0")];
    let chain: &[(u16, &[u8])] = &[(1, b"errno\0"), (3, b"in\0")];

    let checks: [(Option<i64>, i64, &str); 10] = [
        (
            nft(ns, &admin, NEWTABLE, ack | NLM_F_CREATE, AF_INET, table),
            0,
            "nft: NEWTABLE create failed",
        ),
        (
            nft(ns, &admin, NEWTABLE, ack | NLM_F_CREATE, AF_INET, table),
            0,
            "nft: NEWTABLE on an existing table without EXCL must succeed",
        ),
        (
            nft(
                ns,
                &admin,
                NEWTABLE,
                ack | NLM_F_CREATE | NLM_F_EXCL,
                AF_INET,
                table,
            ),
            e::EEXIST,
            "nft: NEWTABLE NLM_F_EXCL on an existing table must be -EEXIST",
        ),
        (
            nft(ns, &admin, NEWTABLE, ack | NLM_F_REPLACE, AF_INET, table),
            e::EOPNOTSUPP,
            "nft: NEWTABLE NLM_F_REPLACE must be -EOPNOTSUPP",
        ),
        (
            nft(ns, &admin, NEWCHAIN, ack | NLM_F_CREATE, AF_INET, chain),
            0,
            "nft: NEWCHAIN create failed",
        ),
        (
            nft(ns, &admin, NEWCHAIN, ack | NLM_F_CREATE, AF_INET, chain),
            0,
            "nft: NEWCHAIN on an existing chain without EXCL must succeed",
        ),
        (
            nft(
                ns,
                &admin,
                NEWCHAIN,
                ack | NLM_F_CREATE | NLM_F_EXCL,
                AF_INET,
                chain,
            ),
            e::EEXIST,
            "nft: NEWCHAIN NLM_F_EXCL on an existing chain must be -EEXIST",
        ),
        (
            nft(ns, &admin, DELCHAIN, ack, AF_INET, chain),
            0,
            "nft: DELCHAIN of an empty chain failed",
        ),
        (
            nft(ns, &admin, DELTABLE, ack, AF_INET, table),
            0,
            "nft: DELTABLE of an empty table failed",
        ),
        (
            nft(ns, &admin, DELTABLE, ack, AF_INET, table),
            e::ENOENT,
            "nft: DELTABLE of a missing table must be -ENOENT",
        ),
    ];
    for (got, want, what) in checks {
        if got != Some(want) {
            return TestResult::Fail(what);
        }
    }
    if nft(
        ns,
        &admin,
        NEWTABLE,
        ack | NLM_F_CREATE,
        NFPROTO_IPV6,
        table,
    ) != Some(e::EOPNOTSUPP)
    {
        return TestResult::Fail("nf_tables with an unsupported family must be -EOPNOTSUPP");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_nft_newtable_newchain_errnos);

// ── NETLINK_AUDIT ───────────────────────────────────────────────────

/// Linux `audit_netlink_ok` (kernel/audit.c): an unknown type is "bad msg"
/// -EINVAL; AUDIT_LIST/ADD/DEL are -EOPNOTSUPP; configuration writes need
/// CAP_AUDIT_CONTROL (-EPERM here, like AUDIT_SET). `audit_receive_msg`
/// answers AUDIT_LIST_RULES with a completed list even without NLM_F_DUMP.
fn smoke_audit_errnos() -> TestResult {
    let run = |kind: u16, flags: u16| {
        crate::netlink_audit::build_replies(&nlmsg(kind, flags, 70, &[])).unwrap_or_default()
    };
    if first_errno(&run(1999, NLM_F_REQUEST)) != Some(e::EINVAL) {
        return TestResult::Fail("unknown audit message type must be -EINVAL");
    }
    if first_errno(&run(1003, NLM_F_REQUEST)) != Some(e::EOPNOTSUPP) {
        return TestResult::Fail("obsolete AUDIT_ADD must be -EOPNOTSUPP");
    }
    if first_errno(&run(1011, NLM_F_REQUEST)) != Some(e::EPERM) {
        return TestResult::Fail("AUDIT_ADD_RULE without audit authority must be -EPERM");
    }
    let list = run(
        crate::netlink_audit::AUDIT_LIST_RULES,
        NLM_F_REQUEST | NLM_F_ACK,
    );
    if list.first().map(|m| nl_type(m)) != Some(NLMSG_DONE) {
        return TestResult::Fail("AUDIT_LIST_RULES without NLM_F_DUMP must return the rule list");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_audit_errnos);

// ── UDP ─────────────────────────────────────────────────────────────

/// Linux `icmp_err_convert[]` (net/ipv4/icmp.c) plus the overrides in
/// `udp_err` (net/ipv4/udp.c): FRAG_NEEDED → EMSGSIZE hard, PARAMETERPROB →
/// EPROTO hard, TIME_EXCEEDED / unknown → EHOSTUNREACH soft, codes > 15 →
/// EHOSTUNREACH soft, SOURCE_QUENCH / REDIRECT → not reported.
fn smoke_udp_icmp_err_convert_matches_linux() -> TestResult {
    use crate::udp_sock::icmp_err_convert;
    let table: [(i64, bool); 16] = [
        (e::ENETUNREACH, false),
        (e::EHOSTUNREACH, false),
        (e::ENOPROTOOPT, true),
        (e::ECONNREFUSED, true),
        (e::EMSGSIZE, true), // udp_err: PMTU, IP_PMTUDISC_WANT → hard
        (e::EOPNOTSUPP, false),
        (e::ENETUNREACH, true),
        (e::EHOSTDOWN, true),
        (e::ENONET, true),
        (e::ENETUNREACH, true),
        (e::EHOSTUNREACH, true),
        (e::ENETUNREACH, false),
        (e::EHOSTUNREACH, false),
        (e::EHOSTUNREACH, true),
        (e::EHOSTUNREACH, true),
        (e::EHOSTUNREACH, true),
    ];
    for (code, (errno, hard)) in table.iter().enumerate() {
        if icmp_err_convert(3, code as u8) != Some((*errno as i32, *hard)) {
            return TestResult::Fail(
                "Dest Unreachable code maps differently from icmp_err_convert",
            );
        }
    }
    let specials = [
        (3u8, 16u8, Some((e::EHOSTUNREACH as i32, false))),
        (11, 0, Some((e::EHOSTUNREACH as i32, false))),
        (12, 0, Some((e::EPROTO as i32, true))),
        (4, 0, None),
        (5, 1, None),
    ];
    for (t, c, want) in specials {
        if icmp_err_convert(t, c) != want {
            return TestResult::Fail("udp_err special-case ICMP mapping diverges");
        }
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_udp_icmp_err_convert_matches_linux);

/// Build an ICMP error body quoting a UDP datagram `src:sport → dst:9999`.
fn icmp_error_quoting_udp(icmp_type: u8, code: u8, src: [u8; 4], sport: u16) -> Vec<u8> {
    use crate::pkt::{ip_checksum, IPV4_HDR_LEN, IP_PROTO_UDP};
    let mut quoted = alloc::vec![0u8; IPV4_HDR_LEN + 8];
    quoted[0] = 0x45;
    quoted[2..4].copy_from_slice(&((IPV4_HDR_LEN + 8) as u16).to_be_bytes());
    quoted[8] = 64;
    quoted[9] = IP_PROTO_UDP;
    quoted[12..16].copy_from_slice(&src);
    quoted[16..20].copy_from_slice(&[198, 51, 100, 9]);
    let cs = ip_checksum(&quoted[..IPV4_HDR_LEN]);
    quoted[10..12].copy_from_slice(&cs.to_be_bytes());
    quoted[IPV4_HDR_LEN..IPV4_HDR_LEN + 2].copy_from_slice(&sport.to_be_bytes());
    quoted[IPV4_HDR_LEN + 2..IPV4_HDR_LEN + 4].copy_from_slice(&9999u16.to_be_bytes());
    let mut body = alloc::vec![0u8; 8];
    body[0] = icmp_type;
    body[1] = code;
    body.extend_from_slice(&quoted);
    let cs = ip_checksum(&body);
    body[2..4].copy_from_slice(&cs.to_be_bytes());
    body
}

/// Linux `__udp4_lib_lookup` (used by `udp_err`) matches an INADDR_ANY
/// bind, so a wildcard-bound socket receives the ICMP Port Unreachable that
/// becomes ECONNREFUSED.
fn smoke_udp_icmp_error_reaches_wildcard_bound_socket() -> TestResult {
    use crate::udp_sock::{udp_bind, udp_close, udp_err_recv, SocketAddrV4, UdpOptions};
    let port = 59_331u16;
    let Ok(sock) = udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) else {
        return TestResult::Fail("wildcard bind failed");
    };
    let body = icmp_error_quoting_udp(3, 3, [10, 0, 0, 1], port);
    crate::icmp_sock::deliver_error([198, 51, 100, 9], 3, 3, &body);
    let err = udp_err_recv(&sock);
    udp_close(&sock);
    match err.and_then(|e| e.linux_errno()) {
        Some((errno, true)) if errno as i64 == e::ECONNREFUSED => TestResult::Pass,
        Some(_) => TestResult::Fail("Port Unreachable must map to hard ECONNREFUSED"),
        None => TestResult::Fail("ICMP error not delivered to an INADDR_ANY-bound UDP socket"),
    }
}
kernel_test_in!(
    "net/errno",
    smoke_udp_icmp_error_reaches_wildcard_bound_socket
);

// ── ICMP ────────────────────────────────────────────────────────────

/// Linux `icmp_rcv` routes Parameter Problem through `icmp_unreach` to the
/// transport error handler; `udp_err` reports it as EPROTO (hard).
fn smoke_icmp_parameter_problem_reaches_udp_as_eproto() -> TestResult {
    use crate::udp_sock::{udp_bind, udp_close, udp_err_recv, SocketAddrV4, UdpOptions};
    let port = 59_332u16;
    let local = [10, 0, 0, 1];
    let Ok(sock) = udp_bind(SocketAddrV4::new(local, port), UdpOptions::default()) else {
        return TestResult::Fail("bind failed");
    };
    let body = icmp_error_quoting_udp(12, 0, local, port);
    crate::icmp_sock::on_icmp_rx([198, 51, 100, 9], local, &body);
    let err = udp_err_recv(&sock);
    udp_close(&sock);
    match err.and_then(|e| e.linux_errno()) {
        Some((errno, true)) if errno as i64 == e::EPROTO => TestResult::Pass,
        Some(_) => TestResult::Fail("Parameter Problem must map to hard EPROTO"),
        None => TestResult::Fail("ICMP Parameter Problem not delivered to the UDP socket"),
    }
}
kernel_test_in!(
    "net/errno",
    smoke_icmp_parameter_problem_reaches_udp_as_eproto
);

/// Linux `ping_v4_sendmsg` → `ip_append_data`: a datagram over 0xFFFF bytes
/// is -EMSGSIZE; NARF's echo payload limit is 0xFFFF - 20 - 8.
fn smoke_icmp_echo_oversize_is_msg_too_long() -> TestResult {
    use crate::icmp_sock::{
        icmp_echo_close, icmp_echo_open, icmp_echo_send, IcmpError2, ICMP_ECHO_MAX_PAYLOAD,
    };
    let sock = icmp_echo_open();
    let payload = alloc::vec![0u8; ICMP_ECHO_MAX_PAYLOAD + 1];
    let result = icmp_echo_send(&sock, [192, 0, 2, 1], 1, &payload);
    icmp_echo_close(&sock);
    if result != Err(IcmpError2::MsgTooLong) {
        return TestResult::Fail("oversize echo payload must fail MsgTooLong (-EMSGSIZE)");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_icmp_echo_oversize_is_msg_too_long);

// ── errno table ─────────────────────────────────────────────────────

/// `include/uapi/asm-generic/errno{-base,}.h` values the socket layer and
/// netlink responders use.
fn smoke_errno_values_match_asm_generic() -> TestResult {
    let table: [(i64, i64); 22] = [
        (e::EPERM, 1),
        (e::ENOENT, 2),
        (e::ESRCH, 3),
        (e::EACCES, 13),
        (e::EBUSY, 16),
        (e::EEXIST, 17),
        (e::ENODEV, 19),
        (e::EINVAL, 22),
        (e::EPIPE, 32),
        (e::ENONET, 64),
        (e::EPROTO, 71),
        (e::EMSGSIZE, 90),
        (e::ENOPROTOOPT, 92),
        (e::EOPNOTSUPP, 95),
        (e::EAFNOSUPPORT, 97),
        (e::EADDRNOTAVAIL, 99),
        (e::ENETUNREACH, 101),
        (e::ECONNRESET, 104),
        (e::ETIMEDOUT, 110),
        (e::ECONNREFUSED, 111),
        (e::EHOSTDOWN, 112),
        (e::EFTYPE, 134),
    ];
    for (got, want) in table {
        if got != want {
            return TestResult::Fail("errno constant differs from asm-generic/errno.h");
        }
    }
    if e::EHOSTUNREACH != 113 || e::EADDRINUSE != 98 {
        return TestResult::Fail("errno constant differs from asm-generic/errno.h");
    }
    TestResult::Pass
}
kernel_test_in!("net/errno", smoke_errno_values_match_asm_generic);
