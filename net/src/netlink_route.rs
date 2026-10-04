//! `NETLINK_ROUTE` (rtnetlink) dump responder.
//!
//! systemd-udevd and systemd-networkd (plus `ip link` / `ip addr`) open a
//! `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` and send `RTM_GETLINK` /
//! `RTM_GETADDR` / `RTM_GETROUTE` dump requests to enumerate the machine's
//! interfaces, addresses, and IPv4 routes. This module parses those request
//! headers and builds the reply message stream describing NARF's interfaces:
//! a synthetic loopback (`lo`, ifindex 1) plus every NIC in the `iface`
//! registry.
//!
//! Wire layout follows `include/uapi/linux/{netlink,rtnetlink,if_link,
//! if_addr}.h`. Every message is `NLMSG_ALIGN`-padded and carries the
//! request's `seq` echoed back and kernel sender port ID (`pid = 0`), so the
//! requester's libnl / sd-netlink sequence and sender validation match Linux.
//! A dump terminates with an `NLMSG_DONE`; an unsupported request type answers
//! `NLMSG_ERROR(-EOPNOTSUPP)`.
//!
//! This is a DUMP responder only — it does not implement rtnetlink writes or
//! neighbor tables. Those degrade to `NLMSG_ERROR` so a caller sees a clean
//! errno rather than a hang.

extern crate alloc;

use alloc::vec::Vec;

// ── netlink message header (struct nlmsghdr) ────────────────────────────

/// `struct nlmsghdr` is 16 bytes: len(u32) type(u16) flags(u16) seq(u32)
/// pid(u32), all native (little-endian on x86_64).
pub const NLMSG_HDRLEN: usize = 16;

/// `NLMSG_ALIGNTO` — netlink aligns every message + attribute to 4 bytes.
pub const NLMSG_ALIGNTO: usize = 4;

/// Round `len` up to the next `NLMSG_ALIGNTO` boundary.
#[inline]
pub fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

/// Round `len` up to the next `RTA_ALIGNTO` boundary (same 4-byte grid).
#[inline]
pub fn rta_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

// ── message types (nlmsg_type) ──────────────────────────────────────────

pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
/// Types below this are netlink control messages (`netlink_rcv_skb` skips them).
pub const NLMSG_MIN_TYPE: u16 = 0x10;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_GETRULE: u16 = 34;
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_GETTCLASS: u16 = 42;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_GETACTION: u16 = 50;
pub const RTM_GETADDRLABEL: u16 = 74;
pub const RTM_GETMDB: u16 = 86;
pub const RTM_GETNEXTHOP: u16 = 106;
/// `RTM_MAX` (include/uapi/linux/rtnetlink.h): `rtnetlink_rcv_msg` rejects
/// larger types with -EOPNOTSUPP.
pub const RTM_MAX: u16 = 123;

// ── netlink flags (nlmsg_flags) ─────────────────────────────────────────

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_ACK_TLVS: u16 = 0x200;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// ── IFLA_* link attribute types (if_link.h) ─────────────────────────────

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_BROADCAST: u16 = 2;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_QDISC: u16 = 6;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFLA_LINKMODE: u16 = 17;
pub const IFLA_STATS64: u16 = 23;
pub const IFLA_GROUP: u16 = 27;
pub const IFLA_CARRIER: u16 = 33;
pub const IF_OPER_UP: u8 = 6;
pub const IF_OPER_DOWN: u8 = 2;

// ── IFA_* address attribute types (if_addr.h) ───────────────────────────

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_CACHEINFO: u16 = 6;
pub const IFA_FLAGS: u16 = 8;

// ── IFA_F_* address flags (if_addr.h) ───────────────────────────────────

pub const IFA_F_TEMPORARY: u32 = 0x01;
pub const IFA_F_DEPRECATED: u32 = 0x20;
pub const IFA_F_TENTATIVE: u32 = 0x40;
pub const IFA_F_PERMANENT: u32 = 0x80;
/// `INFINITY_LIFE_TIME` (`include/net/addrconf.h`).
const INFINITY_LIFE_TIME: u32 = 0xFFFF_FFFF;

// ── RTA_* route attribute types (rtnetlink.h) ──────────────────────────

pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_TABLE: u16 = 15;

pub const NDA_DST: u16 = 1;
pub const NDA_LLADDR: u16 = 2;

pub const FRA_PRIORITY: u16 = 6;
pub const FRA_TABLE: u16 = 15;

pub const TCA_KIND: u16 = 1;
pub const TC_H_ROOT: u32 = 0xFFFF_FFFF;

// ── interface flags (net_device_flags, if.h) ────────────────────────────

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;
/// Driver signals L1 up (carrier). `dev_get_flags` reports it for a running
/// device with carrier; NetworkManager reads carrier from it.
pub const IFF_LOWER_UP: u32 = 0x1_0000;

// ── ARP hardware types (ARPHRD_*, if_arp.h) ─────────────────────────────

pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_LOOPBACK: u16 = 772;

// ── address family (AF_INET) ────────────────────────────────────────────

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

pub const RTPROT_KERNEL: u8 = 2;
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const NUD_INCOMPLETE: u16 = 0x01;
pub const NUD_REACHABLE: u16 = 0x02;
pub const NUD_STALE: u16 = 0x04;
pub const NUD_DELAY: u16 = 0x08;
pub const NUD_PROBE: u16 = 0x10;
pub const NTF_ROUTER: u8 = 0x80;
pub const FR_ACT_TO_TBL: u8 = 1;

/// `-EOPNOTSUPP` — the errno an unsupported dump request answers with,
/// carried in the `NLMSG_ERROR` payload (negated, per netlink convention).
pub const EOPNOTSUPP: i32 = 95;
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EEXIST: i32 = 17;
pub const ENODEV: i32 = 19;
pub const EINVAL: i32 = 22;
pub const ENETUNREACH: i32 = 101;
/// `fib_table_delete` / `ip6_route_del`: deleting a route that is not in
/// the FIB answers `-ESRCH` ("No such process"), not `-ENOENT`.
pub const ESRCH: i32 = 3;
/// `inet_rtm_deladdr` / `inet6_addr_del`: no such address on the device;
/// also `eth_prepare_mac_addr_change` for a multicast / all-zero MAC.
pub const EADDRNOTAVAIL: i32 = 99;
/// `neigh_add` / `neigh_delete`: `neigh_find_table()` has no table for the
/// requested `ndm_family`.
pub const EAFNOSUPPORT: i32 = 97;
pub const NLMSGERR_ATTR_MSG: u16 = 1;

// ── parsed request header ───────────────────────────────────────────────

/// The fields of an inbound `nlmsghdr` the dump responder cares about.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NlMsgHdr {
    pub len: u32,
    pub msg_type: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

/// Parse the leading `struct nlmsghdr` out of a request buffer. Returns
/// `None` if the buffer is shorter than a header.
pub fn parse_hdr(buf: &[u8]) -> Option<NlMsgHdr> {
    if buf.len() < NLMSG_HDRLEN {
        return None;
    }
    Some(NlMsgHdr {
        len: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        msg_type: u16::from_le_bytes([buf[4], buf[5]]),
        flags: u16::from_le_bytes([buf[6], buf[7]]),
        seq: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        pid: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

// ── message builders ────────────────────────────────────────────────────

/// Append one `rtattr` (type + payload) to `body`, aligned to `RTA_ALIGNTO`.
/// `struct rtattr` is `rta_len(u16) rta_type(u16)` then payload; `rta_len`
/// counts the 4-byte header + payload (NOT the alignment padding).
fn push_rtattr(body: &mut Vec<u8>, rta_type: u16, payload: &[u8]) {
    let rta_len = (4 + payload.len()) as u16;
    body.extend_from_slice(&rta_len.to_le_bytes());
    body.extend_from_slice(&rta_type.to_le_bytes());
    body.extend_from_slice(payload);
    // Pad the attribute out to the next 4-byte boundary.
    let pad = rta_align(payload.len()) - payload.len();
    body.extend(core::iter::repeat_n(0u8, pad));
}

/// Frame `payload` as a complete netlink message: a 16-byte `nlmsghdr`
/// (len = header + payload, before trailing alignment) followed by the
/// payload, then trailing pad so the whole message is `NLMSG_ALIGN`-sized.
fn frame_message(msg_type: u16, flags: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let len = (NLMSG_HDRLEN + payload.len()) as u32;
    let mut msg = Vec::with_capacity(nlmsg_align(len as usize));
    msg.extend_from_slice(&len.to_le_bytes());
    msg.extend_from_slice(&msg_type.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(&pid.to_le_bytes());
    msg.extend_from_slice(payload);
    let pad = nlmsg_align(len as usize) - len as usize;
    msg.extend(core::iter::repeat_n(0u8, pad));
    msg
}

/// Description of one interface for the RTM_NEWLINK builder.
struct LinkInfo {
    ifindex: u32,
    flags: u32,
    arphrd: u16,
    name: alloc::string::String,
    /// Hardware address bytes (6 for ethernet; empty for loopback, which
    /// carries no IFLA_ADDRESS).
    mac: Vec<u8>,
    mtu: u32,
}

/// Build one `RTM_NEWLINK` message. Payload is `struct ifinfomsg` +
/// IFLA_IFNAME / IFLA_ADDRESS / IFLA_MTU attributes.
fn build_newlink(link: &LinkInfo, seq: u32, pid: u32) -> Vec<u8> {
    // struct ifinfomsg: family(u8) pad(u8) type(u16) index(i32) flags(u32) change(u32)
    let mut body = Vec::new();
    body.push(0u8); // ifi_family = AF_UNSPEC
    body.push(0u8); // __ifi_pad
    body.extend_from_slice(&link.arphrd.to_le_bytes()); // ifi_type
    body.extend_from_slice(&(link.ifindex as i32).to_le_bytes()); // ifi_index

    // `dev_get_flags`: a running device with carrier also reports
    // IFF_LOWER_UP (NARF links that run have carrier).
    let flags = if link.flags & IFF_RUNNING != 0 {
        link.flags | IFF_LOWER_UP
    } else {
        link.flags
    };
    body.extend_from_slice(&flags.to_le_bytes()); // ifi_flags
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ifi_change = ~0

    // IFLA_IFNAME is a NUL-terminated string.
    let mut name_bytes = link.name.as_bytes().to_vec();
    name_bytes.push(0);
    push_rtattr(&mut body, IFLA_IFNAME, &name_bytes);
    if !link.mac.is_empty() {
        push_rtattr(&mut body, IFLA_ADDRESS, &link.mac);
        push_rtattr(&mut body, IFLA_BROADCAST, &[0xFF; 6]);
    }
    push_rtattr(&mut body, IFLA_MTU, &link.mtu.to_le_bytes());
    push_rtattr(&mut body, IFLA_QDISC, b"noqueue\0");
    push_rtattr(&mut body, IFLA_TXQLEN, &1000u32.to_ne_bytes());
    let running = link.flags & IFF_RUNNING != 0;
    push_rtattr(
        &mut body,
        IFLA_OPERSTATE,
        &[if running { IF_OPER_UP } else { IF_OPER_DOWN }],
    );
    push_rtattr(&mut body, IFLA_LINKMODE, &[0]);
    push_rtattr(&mut body, IFLA_GROUP, &0u32.to_ne_bytes());
    push_rtattr(&mut body, IFLA_CARRIER, &[u8::from(running)]);
    // struct rtnl_link_stats64. Centralized driver counters currently report
    // zero, but supplying the complete native-endian shape lets Linux parsers
    // consume `ip -s link` without treating the attribute as malformed.
    push_rtattr(&mut body, IFLA_STATS64, &[0u8; 25 * 8]);

    frame_message(RTM_NEWLINK, NLM_F_MULTI, seq, pid, &body)
}

fn clear_multipart(message: &mut [u8]) {
    if message.len() >= NLMSG_HDRLEN {
        let flags = u16::from_ne_bytes([message[6], message[7]]) & !NLM_F_MULTI;
        message[6..8].copy_from_slice(&flags.to_ne_bytes());
    }
}

/// Description of one address for the RTM_NEWADDR builder.
struct AddrInfo {
    ifindex: u32,
    prefix_len: u8,
    /// IPv4 address in [a, b, c, d] order.
    addr: [u8; 4],
    label: alloc::string::String,
}

/// Build one `RTM_NEWADDR` message. Payload is `struct ifaddrmsg` +
/// IFA_ADDRESS / IFA_LOCAL / IFA_LABEL attributes.
fn build_newaddr(a: &AddrInfo, seq: u32, pid: u32) -> Vec<u8> {
    // struct ifaddrmsg: family(u8) prefixlen(u8) flags(u8) scope(u8) index(u32)
    let mut body = Vec::new();
    body.push(AF_INET); // ifa_family
    body.push(a.prefix_len); // ifa_prefixlen
                             // ifa_flags: the low byte of the IFA_FLAGS word below (static → PERMANENT).
    body.push(IFA_F_PERMANENT as u8);
    // ifa_scope: 0 = RT_SCOPE_UNIVERSE for a routable addr, 254 =
    // RT_SCOPE_HOST for loopback (127.0.0.0/8).
    let scope = if a.addr[0] == 127 { 254u8 } else { 0u8 };
    body.push(scope);
    body.extend_from_slice(&a.ifindex.to_ne_bytes()); // ifa_index

    push_rtattr(&mut body, IFA_ADDRESS, &a.addr);
    push_rtattr(&mut body, IFA_LOCAL, &a.addr);
    let mut label_bytes = a.label.as_bytes().to_vec();
    label_bytes.push(0);
    push_rtattr(&mut body, IFA_LABEL, &label_bytes);
    // `inet_fill_ifaddr` always emits the full 32-bit flags word and the
    // lifetimes. NARF's IPv4 addresses are configured statically (no
    // lifetime), which Linux reports as IFA_F_PERMANENT with infinite
    // preferred/valid lifetimes (`set_ifa_lifetime`). systemd-resolved's
    // `link_address_update_rtnl` fails the whole manager with ENODATA when
    // IFA_FLAGS is missing.
    push_rtattr(&mut body, IFA_FLAGS, &IFA_F_PERMANENT.to_ne_bytes());
    push_rtattr(
        &mut body,
        IFA_CACHEINFO,
        &ifa_cacheinfo(INFINITY_LIFE_TIME, INFINITY_LIFE_TIME),
    );

    frame_message(RTM_NEWADDR, NLM_F_MULTI, seq, pid, &body)
}

/// `struct ifa_cacheinfo { ifa_prefered, ifa_valid, cstamp, tstamp }`
/// (`put_cacheinfo`). The two timestamps are hundredths of a second since
/// boot at creation / last update.
// LINUX-GAP: `put_cacheinfo` reports the address's creation and update
// times; NARF does not record them and reports 0 for both.
fn ifa_cacheinfo(preferred: u32, valid: u32) -> [u8; 16] {
    let mut ci = [0u8; 16];
    ci[0..4].copy_from_slice(&preferred.to_ne_bytes());
    ci[4..8].copy_from_slice(&valid.to_ne_bytes());
    ci
}

/// Remaining lifetime in whole seconds for a monotonic-ns deadline, the way
/// `inet6_fill_ifaddr` ages `prefered_lft` / `valid_lft`.
fn remaining_lifetime(deadline_ns: u64, now_ns: u64) -> u32 {
    if deadline_ns == u64::MAX {
        return INFINITY_LIFE_TIME;
    }
    let secs = deadline_ns.saturating_sub(now_ns) / 1_000_000_000;
    secs.min(u64::from(INFINITY_LIFE_TIME - 1)) as u32
}

/// The 32-bit `inet6_ifaddr.flags` for an address.
fn ipv6_ifa_flags(addr: &crate::ipv6::addrs::Ipv6IfAddr) -> u32 {
    use crate::ipv6::addrs::AddrState;
    let mut flags = match addr.state {
        AddrState::Tentative => IFA_F_TENTATIVE,
        AddrState::Deprecated => IFA_F_DEPRECATED,
        AddrState::Preferred | AddrState::Invalid => 0,
    };
    if addr.temporary {
        flags |= IFA_F_TEMPORARY;
    }
    // A statically configured address — one with no lifetime at all — is
    // IFA_F_PERMANENT (`inet6_addr_add` → `ifa_flags |= IFA_F_PERMANENT`
    // when `valid_lft == INFINITY_LIFE_TIME`); SLAAC addresses carry their
    // router-advertised lifetimes instead.
    if addr.valid_deadline_ns == u64::MAX && addr.preferred_deadline_ns == u64::MAX {
        flags |= IFA_F_PERMANENT;
    }
    flags
}

fn build_newaddr_v6(
    addr: &crate::ipv6::addrs::Ipv6IfAddr,
    ifindex: u32,
    seq: u32,
    pid: u32,
) -> Vec<u8> {
    use crate::ipv6::addrs::AddrScope;

    let mut body = Vec::new();
    body.push(AF_INET6);
    body.push(addr.prefix_len);
    let flags = ipv6_ifa_flags(addr);
    // `put_ifaddrmsg`: the legacy u8 field carries the low byte.
    body.push(flags as u8);
    body.push(match addr.scope {
        AddrScope::Host => 254, // RT_SCOPE_HOST
        AddrScope::Global | AddrScope::UniqueLocal => 0,
        AddrScope::LinkLocal => 0x20,
    });
    body.extend_from_slice(&ifindex.to_ne_bytes());
    push_rtattr(&mut body, IFA_ADDRESS, &addr.addr);
    // `inet6_fill_ifaddr` order: IFA_ADDRESS, IFA_CACHEINFO, IFA_FLAGS.
    let (preferred, valid) = if flags & IFA_F_PERMANENT != 0 {
        (INFINITY_LIFE_TIME, INFINITY_LIFE_TIME)
    } else {
        let now = narf_scheduler::narf_time::monotonic_ns();
        (
            remaining_lifetime(addr.preferred_deadline_ns, now),
            remaining_lifetime(addr.valid_deadline_ns, now),
        )
    };
    push_rtattr(&mut body, IFA_CACHEINFO, &ifa_cacheinfo(preferred, valid));
    push_rtattr(&mut body, IFA_FLAGS, &flags.to_ne_bytes());
    frame_message(RTM_NEWADDR, NLM_F_MULTI, seq, pid, &body)
}

/// Build one `RTM_NEWROUTE` message from the kernel FIB. Payload is
/// `struct rtmsg` followed by the Linux route attributes relevant to IPv4
/// consumers (`RTA_DST`, `RTA_OIF`, gateway, metric, and preferred source).
fn build_newroute(route: &crate::route::Route, ifindex: u32, seq: u32, pid: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(AF_INET); // rtm_family
    body.push(route.dst.prefix_len); // rtm_dst_len
    body.push(0); // rtm_src_len
    body.push(0); // rtm_tos
    body.push(route.table); // rtm_table (all current table IDs fit in u8)
    body.push(RTPROT_KERNEL); // rtm_protocol
    body.push(route.scope as u8); // rtm_scope
    body.push(if route.table == crate::route::TABLE_LOCAL {
        RTN_LOCAL
    } else {
        RTN_UNICAST
    }); // rtm_type
    body.extend_from_slice(&0u32.to_le_bytes()); // rtm_flags

    // Linux omits RTA_DST for the default route (/0).
    if route.dst.prefix_len != 0 {
        push_rtattr(&mut body, RTA_DST, &route.dst.addr.0);
    }
    push_rtattr(&mut body, RTA_OIF, &ifindex.to_le_bytes());
    if let Some(gateway) = route.gateway {
        push_rtattr(&mut body, RTA_GATEWAY, &gateway.0);
    }
    if route.metric != 0 {
        push_rtattr(&mut body, RTA_PRIORITY, &route.metric.to_le_bytes());
    }
    if let Some(src) = route.src_hint {
        push_rtattr(&mut body, RTA_PREFSRC, &src.0);
    }
    // Keep the full table ID available to parsers even though current IDs
    // also fit in rtmsg.rtm_table.
    push_rtattr(&mut body, RTA_TABLE, &(route.table as u32).to_le_bytes());

    frame_message(RTM_NEWROUTE, NLM_F_MULTI, seq, pid, &body)
}

fn build_newroute_v6(
    route: &crate::ipv6::route::Route,
    ifindex: u32,
    seq: u32,
    pid: u32,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(AF_INET6);
    body.push(route.prefix_len);
    body.extend_from_slice(&[0, 0]);
    body.push(crate::route::TABLE_MAIN);
    body.push(RTPROT_KERNEL);
    body.push(0);
    body.push(RTN_UNICAST);
    body.extend_from_slice(&0u32.to_ne_bytes());
    if route.prefix_len != 0 {
        push_rtattr(&mut body, RTA_DST, &route.prefix);
    }
    push_rtattr(&mut body, RTA_OIF, &ifindex.to_ne_bytes());
    if let Some(gateway) = route.gateway {
        push_rtattr(&mut body, RTA_GATEWAY, &gateway);
    }
    if route.metric != 0 {
        push_rtattr(&mut body, RTA_PRIORITY, &route.metric.to_ne_bytes());
    }
    push_rtattr(
        &mut body,
        RTA_TABLE,
        &(crate::route::TABLE_MAIN as u32).to_ne_bytes(),
    );
    frame_message(RTM_NEWROUTE, NLM_F_MULTI, seq, pid, &body)
}

struct NeighInfo<'a> {
    family: u8,
    dst: &'a [u8],
    mac: Option<[u8; 6]>,
    ifindex: u32,
    state: u16,
    flags: u8,
}

fn build_newneigh(neigh: &NeighInfo<'_>, seq: u32, pid: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(neigh.family);
    body.push(0);
    body.extend_from_slice(&0u16.to_ne_bytes());
    body.extend_from_slice(&(neigh.ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&neigh.state.to_ne_bytes());
    body.push(neigh.flags);
    body.push(0);
    push_rtattr(&mut body, NDA_DST, neigh.dst);
    if let Some(mac) = neigh.mac {
        push_rtattr(&mut body, NDA_LLADDR, &mac);
    }
    frame_message(RTM_NEWNEIGH, NLM_F_MULTI, seq, pid, &body)
}

fn build_newrule(family: u8, table: u8, priority: u32, seq: u32, pid: u32) -> Vec<u8> {
    // struct fib_rule_hdr: family, dst_len, src_len, tos, table,
    // res1, res2, action, flags.
    let mut body = Vec::new();
    body.push(family);
    body.extend_from_slice(&[0, 0, 0]);
    body.push(table);
    body.extend_from_slice(&[0, 0]);
    body.push(FR_ACT_TO_TBL);
    body.extend_from_slice(&0u32.to_ne_bytes());
    push_rtattr(&mut body, FRA_PRIORITY, &priority.to_ne_bytes());
    push_rtattr(&mut body, FRA_TABLE, &(table as u32).to_ne_bytes());
    frame_message(RTM_NEWRULE, NLM_F_MULTI, seq, pid, &body)
}

fn build_newqdisc(ifindex: u32, seq: u32, pid: u32) -> Vec<u8> {
    // struct tcmsg: family(u8), pad1(u8), pad2(u16), ifindex(i32),
    // handle(u32), parent(u32), info(u32).
    let mut body = Vec::new();
    body.push(0);
    body.push(0);
    body.extend_from_slice(&0u16.to_ne_bytes());
    body.extend_from_slice(&(ifindex as i32).to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    body.extend_from_slice(&TC_H_ROOT.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    push_rtattr(&mut body, TCA_KIND, b"noqueue\0");
    frame_message(RTM_NEWQDISC, NLM_F_MULTI, seq, pid, &body)
}

/// Build an `NLMSG_ERROR` message carrying `-errno` (negated per netlink
/// convention) followed by an echo of the offending request header.
fn build_error(errno: i32, seq: u32, pid: u32, req: &[u8]) -> Vec<u8> {
    // struct nlmsgerr: error(i32) followed by the offending request. Linux
    // echoes the full aligned request unless NETLINK_CAP_ACK caps it later.
    let mut body = Vec::with_capacity(4 + req.len().max(NLMSG_HDRLEN));
    body.extend_from_slice(&(-errno).to_le_bytes());
    body.extend_from_slice(req);
    if req.len() < NLMSG_HDRLEN {
        body.extend(core::iter::repeat_n(0u8, NLMSG_HDRLEN - req.len()));
    }
    frame_message(NLMSG_ERROR, 0, seq, pid, &body)
}

fn build_ack(seq: u32, req: &[u8]) -> Vec<u8> {
    build_error(0, seq, 0, req)
}

// ── dump entry point ────────────────────────────────────────────────────

/// Enumerate the interfaces the dump should describe. Loopback is synthetic
/// (ifindex 1); every other device reports the ifindex it was given when it
/// registered (`dev_new_index`). Returned as `(link, addrs)` so both dumps
/// share one enumeration.
fn enumerate() -> (Vec<LinkInfo>, Vec<AddrInfo>) {
    enumerate_in(0)
}

/// Interface `iface`'s IPv4 addresses in list order, `lo`'s built-in
/// 127.0.0.1/8 first — the `in_dev->ifa_list` the address handlers walk.
fn ipv4_addrs_of(iface: &str) -> Vec<([u8; 4], u8)> {
    let mut addrs: Vec<([u8; 4], u8)> = Vec::new();
    if iface == "lo" {
        addrs.push(([127, 0, 0, 1], 8));
    }
    for (addr, prefix_len) in crate::iface::get_addrs(iface) {
        if !addrs.contains(&(addr.0, prefix_len)) {
            addrs.push((addr.0, prefix_len));
        }
    }
    addrs
}

fn builtin_loopback_ipv6() -> crate::ipv6::addrs::Ipv6IfAddr {
    crate::ipv6::addrs::Ipv6IfAddr {
        iface: alloc::string::String::from("lo"),
        addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        prefix_len: 128,
        state: crate::ipv6::addrs::AddrState::Preferred,
        scope: crate::ipv6::addrs::AddrScope::Host,
        preferred_deadline_ns: u64::MAX,
        valid_deadline_ns: u64::MAX,
        temporary: false,
    }
}

fn enumerate_in(net_ns_id: u64) -> (Vec<LinkInfo>, Vec<AddrInfo>) {
    let mut links = Vec::new();
    let mut addrs = Vec::new();

    // Synthetic loopback: ifindex 1, IFF_UP|IFF_LOOPBACK|IFF_RUNNING,
    // ARPHRD_LOOPBACK, MTU 65536, address 127.0.0.1/8.
    links.push(LinkInfo {
        ifindex: 1,
        flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
        arphrd: ARPHRD_LOOPBACK,
        name: alloc::string::String::from("lo"),
        mac: Vec::new(),
        mtu: 65536,
    });
    addrs.push(AddrInfo {
        ifindex: 1,
        prefix_len: 8,
        addr: [127, 0, 0, 1],
        label: alloc::string::String::from("lo"),
    });

    // Legacy L3 interfaces first, each under the ifindex it registered with —
    // the same number the IPv4 stack, SIOCGIFINDEX and sysfs report.
    for nic in crate::iface::snapshot_all()
        .into_iter()
        // `lo` is the synthetic ifindex-1 entry above; its legacy L3
        // registration must not appear a second time as an Ethernet device.
        .filter(|nic| nic.net_ns_id == net_ns_id && nic.name != "lo")
    {
        let ifindex = nic.ifindex;
        links.push(LinkInfo {
            ifindex,
            flags: IFF_BROADCAST
                | IFF_MULTICAST
                | if nic.link_up { IFF_UP | IFF_RUNNING } else { 0 },
            arphrd: ARPHRD_ETHER,
            name: nic.name.clone(),
            mac: nic.mac.to_vec(),
            mtu: nic.mtu,
        });
        let configured = crate::iface::get_addrs(&nic.name);
        for (address, prefix_len) in &configured {
            if address.0 == [0, 0, 0, 0] {
                continue;
            }
            addrs.push(AddrInfo {
                ifindex,
                prefix_len: *prefix_len,
                addr: address.0,
                label: nic.name.clone(),
            });
        }
        // Preserve the boot-time primary address for legacy drivers that have
        // not yet mirrored it into the multi-address registry.
        if nic.ipv4 != [0, 0, 0, 0] && !configured.iter().any(|(address, _)| address.0 == nic.ipv4)
        {
            addrs.push(AddrInfo {
                ifindex,
                prefix_len: 24,
                addr: nic.ipv4,
                label: nic.name.clone(),
            });
        }
    }

    // Most hardware drivers register only in the capability-gated frame-ring
    // registry. Include names not represented by the legacy L3 registry so
    // every probed NIC is visible to the control plane exactly once. Physical
    // NICs live in the root namespace; a child netns must not see them in its
    // RTM_GETLINK dump (Linux: devices appear in exactly one netns). The
    // frame-ring loopback is the synthetic `lo` above, not a second device.
    let frame_ring_nics = if net_ns_id == 0 {
        crate::registry().snapshots()
    } else {
        Vec::new()
    };
    for nic in frame_ring_nics {
        if nic.is_loopback || links.iter().any(|link| link.name == nic.name) {
            continue;
        }
        let ifindex = crate::iface::stable_ifindex(&nic.name);
        links.push(LinkInfo {
            ifindex,
            flags: IFF_BROADCAST
                | IFF_MULTICAST
                | if nic.link_up { IFF_UP | IFF_RUNNING } else { 0 },
            arphrd: ARPHRD_ETHER,
            name: nic.name,
            mac: nic.mac.to_vec(),
            mtu: nic.mtu,
        });
    }

    (links, addrs)
}

/// Build the reply message stream for a dump request `req`. Returns one
/// `Vec<u8>` per netlink message (the socket layer delivers each as a
/// separate datagram, matching how the kernel dumps stream over
/// `NETLINK_ROUTE`). `RTM_GETLINK` → an `RTM_NEWLINK` per interface;
/// `RTM_GETADDR` → an `RTM_NEWADDR` per address; both end with `NLMSG_DONE`.
/// Any other request type → a single `NLMSG_ERROR(-EOPNOTSUPP)`.
pub fn build_dump(req: &[u8]) -> Vec<Vec<u8>> {
    build_dump_in(0, req)
}

pub fn build_dump_in(net_ns_id: u64, req: &[u8]) -> Vec<Vec<u8>> {
    build_get_in(net_ns_id, req, false, false)
}

/// Answer one `RTM_GET*` request: a `NLM_F_DUMP` request runs the Linux
/// dumpit (`dump::run`); otherwise the doit. `strict` is the socket's
/// `NETLINK_GET_STRICT_CHK`, `ext_ack` its `NETLINK_EXT_ACK`.
fn build_get_in(net_ns_id: u64, req: &[u8], strict: bool, ext_ack: bool) -> Vec<Vec<u8>> {
    let hdr = match parse_hdr(req) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let len = (hdr.len as usize).min(req.len());
    if len < NLMSG_HDRLEN {
        return Vec::new();
    }
    let req = &req[..len];
    // `rtnetlink_rcv_msg`: `nlmsg_flags & NLM_F_DUMP` (either bit) selects
    // the dumpit.
    if hdr.flags & NLM_F_DUMP != 0 && dump::is_dump_type(hdr.msg_type) {
        return dump::run(net_ns_id, req, strict, ext_ack);
    }
    let seq = hdr.seq;
    // Replies originate from the kernel netlink endpoint. Linux stamps
    // nlmsg_pid=0; the requester's port ID is not echoed in reply headers.
    let pid = 0;
    let mut out = Vec::new();
    match hdr.msg_type {
        RTM_GETLINK => {
            let (links, _addrs) = enumerate_in(net_ns_id);
            let tb = match valid_getlink_req(req, strict) {
                Ok(tb) => tb,
                Err(errno) => {
                    out.push(build_error(errno, seq, pid, req));
                    return out;
                }
            };
            // `rtnl_getlink`: IFLA_TARGET_NETNSID names a peer netns; NARF
            // assigns no netns ids, so `rtnl_get_net_ns_capable` fails.
            if tb[46].is_some() {
                out.push(build_error(EINVAL, seq, pid, req));
                return out;
            }
            let ifindex = i32::from_ne_bytes(req[20..24].try_into().unwrap_or([0; 4]));
            let requested_name = tb[IFLA_IFNAME as usize].and_then(|(off, len)| {
                let raw = &req[off..off + len];
                core::str::from_utf8(raw.strip_suffix(&[0]).unwrap_or(raw)).ok()
            });
            // `rtnl_getlink`: a positive ifindex selects by index only;
            // otherwise IFLA_IFNAME selects by name; with neither the
            // request is malformed (-EINVAL), not a missing device.
            // LINUX-GAP: IFLA_ALT_IFNAME selection is not implemented.
            if ifindex <= 0 && requested_name.is_none() {
                out.push(build_error(EINVAL, seq, pid, req));
                return out;
            }
            let selected = links.iter().find(|link| {
                if ifindex > 0 {
                    link.ifindex == ifindex as u32
                } else {
                    requested_name.is_some_and(|name| link.name == name)
                }
            });
            if let Some(link) = selected {
                let mut message = build_newlink(link, seq, pid);
                clear_multipart(&mut message);
                out.push(message);
            } else {
                out.push(build_error(ENODEV, seq, pid, req));
            }
        }
        RTM_GETROUTE => {
            let (links, _addrs) = enumerate_in(net_ns_id);
            // `rtnetlink_rcv_msg` dispatches a doit by family; a family
            // without an RTM_GETROUTE doit (AF_UNSPEC, or AF_INET6 which
            // NARF has not implemented) answers -EOPNOTSUPP.
            // LINUX-GAP: inet6_rtm_getroute / ipmr_rtm_getroute /
            // ip6mr_rtm_getroute are not implemented.
            if req.get(NLMSG_HDRLEN).copied() != Some(AF_INET) {
                out.push(build_error(EOPNOTSUPP, seq, pid, req));
                return out;
            }
            let tb = match valid_getroute_req(req, strict) {
                Ok(tb) => tb,
                Err(errno) => {
                    out.push(build_error(errno, seq, pid, req));
                    return out;
                }
            };
            // `inet_rtm_getroute`: `nla_get_in_addr_default(tb[RTA_DST], 0)`
            // — an absent RTA_DST looks up 0.0.0.0, it is not an error. The
            // policy guarantees a present RTA_DST carries four bytes.
            let dst = tb[RTA_DST as usize]
                .and_then(|(off, _)| req[off..off + 4].try_into().ok())
                .unwrap_or([0; 4]);
            let dst = crate::ipv4::Ipv4Addr(dst);
            if let Some(route) = crate::route::route_lookup_raw_in(net_ns_id, dst) {
                if let Some(link) = links.iter().find(|link| link.name == route.iface) {
                    let mut message = build_newroute(&route, link.ifindex, seq, pid);
                    clear_multipart(&mut message);
                    out.push(message);
                } else {
                    out.push(build_error(ENODEV, seq, pid, req));
                }
            } else {
                out.push(build_error(ENETUNREACH, seq, pid, req));
            }
        }
        // LINUX-GAP: the other RTM_GET* doits (inet6_rtm_getaddr, neigh_get,
        // tc_get_qdisc, rtm_get_nexthop, ...) are not implemented; a request
        // without NLM_F_DUMP is answered with the (non-strict) dump.
        msg_type if dump::is_dump_type(msg_type) => {
            return dump::run(net_ns_id, req, false, ext_ack);
        }
        _ => {
            out.push(build_error(EOPNOTSUPP, seq, pid, req));
        }
    }
    out
}

/// `rtnl_valid_getlink_req` (net/core/rtnetlink.c).
fn valid_getlink_req(req: &[u8], strict: bool) -> Result<dump::Tb, i32> {
    let mut extack = dump::ExtAck::default();
    if req.len() < NLMSG_HDRLEN + 16 {
        return Err(EINVAL);
    }
    if !strict {
        return dump::nlmsg_parse(
            req,
            16,
            &dump::IFLA_POLICY,
            dump::NL_VALIDATE_LIBERAL,
            &mut extack,
        );
    }
    // __ifi_pad, ifi_type, ifi_flags, ifi_change.
    if req[NLMSG_HDRLEN + 1] != 0
        || req[NLMSG_HDRLEN + 2..NLMSG_HDRLEN + 4] != [0, 0]
        || req[NLMSG_HDRLEN + 8..NLMSG_HDRLEN + 16] != [0; 8]
    {
        return Err(EINVAL);
    }
    let tb = dump::nlmsg_parse(
        req,
        16,
        &dump::IFLA_POLICY,
        dump::NL_VALIDATE_DEPRECATED_STRICT,
        &mut extack,
    )?;
    // IFLA_IFNAME, IFLA_EXT_MASK, IFLA_TARGET_NETNSID, IFLA_ALT_IFNAME.
    if tb
        .iter()
        .enumerate()
        .any(|(i, attr)| attr.is_some() && !matches!(i, 3 | 29 | 46 | 53))
    {
        return Err(EINVAL);
    }
    Ok(tb)
}

/// `inet_rtm_valid_getroute_req` (net/ipv4/route.c).
fn valid_getroute_req(req: &[u8], strict: bool) -> Result<dump::Tb, i32> {
    const RTM_F_NOTIFY: u32 = 0x100;
    const RTM_F_FIB_MATCH: u32 = 0x2000;
    const RTM_F_LOOKUP_TABLE: u32 = 0x1000;
    let mut extack = dump::ExtAck::default();
    if req.len() < NLMSG_HDRLEN + 12 {
        return Err(EINVAL);
    }
    if !strict {
        return dump::nlmsg_parse(
            req,
            12,
            &dump::RTM_IPV4_POLICY,
            dump::NL_VALIDATE_LIBERAL,
            &mut extack,
        );
    }
    let dst_len = req[NLMSG_HDRLEN + 1];
    let src_len = req[NLMSG_HDRLEN + 2];
    // rtm_table, rtm_protocol, rtm_scope, rtm_type.
    if (src_len != 0 && src_len != 32)
        || (dst_len != 0 && dst_len != 32)
        || req[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8] != [0; 4]
    {
        return Err(EINVAL);
    }
    let flags = u32::from_ne_bytes(
        req[NLMSG_HDRLEN + 8..NLMSG_HDRLEN + 12]
            .try_into()
            .unwrap_or([0; 4]),
    );
    if flags & !(RTM_F_NOTIFY | RTM_F_LOOKUP_TABLE | RTM_F_FIB_MATCH) != 0 {
        return Err(EINVAL);
    }
    let tb = dump::nlmsg_parse(
        req,
        12,
        &dump::RTM_IPV4_POLICY,
        dump::NL_VALIDATE_DEPRECATED_STRICT,
        &mut extack,
    )?;
    // RTA_SRC (2) / RTA_DST (1) require the matching /32 header length.
    if (tb[2].is_some() && src_len == 0) || (tb[1].is_some() && dst_len == 0) {
        return Err(EINVAL);
    }
    // RTA_IIF RTA_OIF RTA_SRC RTA_DST RTA_IP_PROTO RTA_SPORT RTA_DPORT
    // RTA_MARK RTA_UID.
    if tb
        .iter()
        .enumerate()
        .any(|(i, attr)| attr.is_some() && !matches!(i, 1 | 2 | 3 | 4 | 16 | 25 | 27 | 28 | 29))
    {
        return Err(EINVAL);
    }
    Ok(tb)
}

/// Linux builds an RTM_NEWADDR / RTM_DELADDR notification from the address
/// itself (`rtmsg_ifa` → `inet_fill_ifaddr`), so it always carries IFA_FLAGS
/// and IFA_CACHEINFO. NARF echoes the request, which need carry neither;
/// append them the way `rtm_to_ifaddr` + `set_ifa_lifetime` would have
/// derived them: flags from `ifa_flags` when IFA_FLAGS was absent, and a
/// request without IFA_CACHEINFO has infinite lifetimes, i.e. is
/// IFA_F_PERMANENT.
fn complete_addr_notification(message: &mut Vec<u8>) {
    const IFADDRMSG_LEN: usize = 8;
    if message.len() < NLMSG_HDRLEN + IFADDRMSG_LEN {
        return;
    }
    let has_cacheinfo = find_attr(message, IFADDRMSG_LEN, IFA_CACHEINFO).is_some();
    if find_attr(message, IFADDRMSG_LEN, IFA_FLAGS).is_none() {
        let mut flags = u32::from(message[NLMSG_HDRLEN + 2]);
        if !has_cacheinfo {
            flags |= IFA_F_PERMANENT;
        }
        push_rtattr(message, IFA_FLAGS, &flags.to_ne_bytes());
    }
    if !has_cacheinfo {
        push_rtattr(
            message,
            IFA_CACHEINFO,
            &ifa_cacheinfo(INFINITY_LIFE_TIME, INFINITY_LIFE_TIME),
        );
    }
    let len = message.len() as u32;
    message[0..4].copy_from_slice(&len.to_ne_bytes());
}

fn find_attr(request: &[u8], fixed_len: usize, kind: u16) -> Option<&[u8]> {
    let mut offset = NLMSG_HDRLEN + fixed_len;
    while offset + 4 <= request.len() {
        let len = u16::from_ne_bytes(request[offset..offset + 2].try_into().ok()?) as usize;
        let attr_kind = u16::from_ne_bytes(request[offset + 2..offset + 4].try_into().ok()?);
        if len < 4 || offset + len > request.len() {
            return None;
        }
        if attr_kind == kind {
            return Some(&request[offset + 4..offset + len]);
        }
        offset += rta_align(len);
    }
    None
}

fn iface_name_for_index(ifindex: u32) -> Option<alloc::string::String> {
    enumerate()
        .0
        .into_iter()
        .find(|iface| iface.ifindex == ifindex)
        .map(|iface| iface.name)
}

/// Resolve a name to the same ifindex exposed by RTM_GETLINK.
pub fn ifindex_for_name(name: &str) -> Option<u32> {
    enumerate()
        .0
        .into_iter()
        .find(|iface| iface.name == name)
        .map(|iface| iface.ifindex)
}

fn admin_errno(error: crate::AdminError) -> i32 {
    match error {
        crate::AdminError::AuthorityRevoked => EPERM,
        crate::AdminError::NoIface => ENODEV,
        crate::AdminError::InvalidMtu
        | crate::AdminError::InvalidMac
        | crate::AdminError::InvalidPrefix => EINVAL,
    }
}

/// `do_setlink` → `dev_set_mac_address` → `eth_prepare_mac_addr_change`
/// rejects a multicast / all-zero address with `-EADDRNOTAVAIL`; every other
/// admin failure keeps the shared mapping.
fn link_admin_errno(error: crate::AdminError) -> i32 {
    match error {
        crate::AdminError::InvalidMac => EADDRNOTAVAIL,
        other => admin_errno(other),
    }
}

/// IPv4 FIB insert (`fib_table_insert`, net/ipv4/fib_trie.c): an existing
/// alias is `-EEXIST` under `NLM_F_EXCL` or without `NLM_F_REPLACE`; a new
/// alias needs `NLM_F_CREATE` or the insert is `-ENOENT`.
fn validate_new_flags(exists: bool, flags: u16) -> Result<(), i32> {
    if exists {
        if flags & NLM_F_EXCL != 0 || flags & NLM_F_REPLACE == 0 {
            Err(EEXIST)
        } else {
            Ok(())
        }
    } else if flags & NLM_F_CREATE != 0 {
        Ok(())
    } else {
        Err(ENOENT)
    }
}

/// `inet_rtm_newaddr` (net/ipv4/devinet.c) and `inet6_rtm_newaddr`
/// (net/ipv6/addrconf.c): an existing address is `-EEXIST` under
/// `NLM_F_EXCL` or without `NLM_F_REPLACE`. A new address is inserted even
/// without `NLM_F_CREATE` ("userspace already relies on not having to
/// provide this").
fn validate_new_addr_flags(exists: bool, flags: u16) -> Result<(), i32> {
    if exists && (flags & NLM_F_EXCL != 0 || flags & NLM_F_REPLACE == 0) {
        Err(EEXIST)
    } else {
        Ok(())
    }
}

/// IPv6 FIB insert (`fib6_add_rt2node`, net/ipv6/ip6_fib.c): existing-route
/// rules match IPv4, but a missing route without `NLM_F_CREATE` is still
/// added (with a "NLM_F_CREATE should be set" warning) unless
/// `NLM_F_REPLACE` asked to replace something — then `-ENOENT`.
fn validate_new_route6_flags(exists: bool, flags: u16) -> Result<(), i32> {
    if exists {
        validate_new_flags(true, flags)
    } else if flags & NLM_F_REPLACE != 0 && flags & NLM_F_CREATE == 0 {
        Err(ENOENT)
    } else {
        Ok(())
    }
}

/// `neigh_add` (net/core/neighbour.c): a missing entry needs
/// `NLM_F_CREATE` (`-ENOENT`); an existing entry is `-EEXIST` only under
/// `NLM_F_EXCL` — without `NLM_F_REPLACE` Linux still updates it (minus
/// the override flags) and succeeds.
fn validate_new_neigh_flags(exists: bool, flags: u16) -> Result<(), i32> {
    if exists {
        if flags & NLM_F_EXCL != 0 {
            Err(EEXIST)
        } else {
            Ok(())
        }
    } else if flags & NLM_F_CREATE != 0 {
        Ok(())
    } else {
        Err(ENOENT)
    }
}

/// Resolve the device an `RTM_NEWLINK` / `RTM_SETLINK` names, with the
/// errno ladder of `__rtnl_newlink` / `rtnl_setlink` (net/core/rtnetlink.c).
fn resolve_link(request: &[u8], msg_type: u16, flags: u16) -> Result<alloc::string::String, i32> {
    let ifindex = i32::from_ne_bytes(request[20..24].try_into().map_err(|_| EINVAL)?);
    let requested_name = find_attr(request, 16, IFLA_IFNAME)
        .and_then(|raw| core::str::from_utf8(raw.strip_suffix(&[0]).unwrap_or(raw)).ok());
    if msg_type == RTM_NEWLINK && ifindex < 0 {
        // "ifindex can't be negative"
        return Err(EINVAL);
    }
    let named = ifindex > 0 || requested_name.is_some();
    if !named && msg_type == RTM_SETLINK {
        return Err(EINVAL);
    }
    let found = if ifindex > 0 {
        iface_name_for_index(ifindex as u32)
    } else {
        requested_name
            .and_then(|name| ifindex_for_name(name).map(|_| alloc::string::String::from(name)))
    };
    match found {
        Some(name) => {
            if msg_type == RTM_NEWLINK {
                // `rtnl_changelink`.
                if flags & NLM_F_EXCL != 0 {
                    return Err(EEXIST);
                }
                if flags & NLM_F_REPLACE != 0 {
                    return Err(EOPNOTSUPP);
                }
            }
            Ok(name)
        }
        // SETLINK, or NEWLINK without NLM_F_CREATE: the device does not exist.
        None if msg_type == RTM_SETLINK || flags & NLM_F_CREATE == 0 => Err(ENODEV),
        // NEWLINK create: NARF registers no `rtnl_link_ops` kinds, which is
        // `__rtnl_newlink`'s "Unknown device type" -EOPNOTSUPP.
        None => Err(EOPNOTSUPP),
    }
}

/// Who may change interface `iface` with this request. Linux
/// `rtnetlink_rcv_msg` refuses every non-GET request with -EPERM unless the
/// sender is `netlink_net_capable(skb, CAP_NET_ADMIN)` in the socket's network
/// namespace, and then lets it change any device of that namespace. NARF also
/// honours a delegated per-interface handle (a stack daemon's grant), which
/// covers exactly its one interface.
struct MutationAuthority<'a> {
    delegated: Option<&'a crate::AdminHandle>,
    net_admin: bool,
    net_ns_id: u64,
}

impl MutationAuthority<'_> {
    fn any(&self) -> bool {
        self.delegated.is_some() || self.net_admin
    }

    /// The handle that changes `iface`, or the errno refusing it.
    fn for_iface(&self, iface: &str) -> Result<crate::AdminHandle, i32> {
        if let Some(admin) = self.delegated {
            if admin.iface_name() == iface {
                return Ok(admin.clone());
            }
        }
        if self.net_admin {
            // A CAP_NET_ADMIN sender reaches only its own namespace's devices
            // (`__dev_get_by_index(sock_net(skb->sk), ...)` -> -ENODEV).
            if iface != "lo" && crate::iface::lookup_in(self.net_ns_id, iface).is_none() {
                return Err(ENODEV);
            }
            return crate::stack::kernel_admin(iface).ok_or(ENODEV);
        }
        Err(EPERM)
    }
}

/// Apply one rtnetlink change. On failure `msg` may hold the extended-ACK
/// text the Linux handler sets for that error (`NL_SET_ERR_MSG`); most Linux
/// failures set none, and neither does this.
fn apply_mutation(
    request: &[u8],
    authority: &MutationAuthority<'_>,
    msg: &mut Option<&'static str>,
) -> Result<(), i32> {
    let hdr = parse_hdr(request).ok_or(EINVAL)?;
    if !authority.any() {
        return Err(EPERM);
    }
    match hdr.msg_type {
        RTM_NEWLINK | RTM_SETLINK => {
            if request.len() < NLMSG_HDRLEN + 16 {
                return Err(EINVAL);
            }
            let iface_name = resolve_link(request, hdr.msg_type, hdr.flags)?;
            let admin = authority.for_iface(&iface_name)?;
            let flags = u32::from_ne_bytes(request[24..28].try_into().map_err(|_| EINVAL)?);
            let change = u32::from_ne_bytes(request[28..32].try_into().map_err(|_| EINVAL)?);
            if change & IFF_UP != 0 {
                admin.set_link(flags & IFF_UP != 0).map_err(admin_errno)?;
            }
            if let Some(mtu) = find_attr(request, 16, IFLA_MTU) {
                if mtu.len() != 4 {
                    return Err(EINVAL);
                }
                admin
                    .set_mtu(u32::from_ne_bytes(mtu.try_into().map_err(|_| EINVAL)?))
                    .map_err(admin_errno)?;
            }
            if let Some(mac) = find_attr(request, 16, IFLA_ADDRESS) {
                if mac.len() != 6 {
                    return Err(EINVAL);
                }
                admin
                    .set_mac(mac.try_into().map_err(|_| EINVAL)?)
                    .map_err(link_admin_errno)?;
            }
            Ok(())
        }
        RTM_NEWADDR | RTM_DELADDR => {
            if request.len() < NLMSG_HDRLEN + 8 {
                return Err(EINVAL);
            }
            let family = request[NLMSG_HDRLEN];
            let prefix_len = request[NLMSG_HDRLEN + 1];
            // Address handlers are registered for PF_INET / PF_INET6 only;
            // `rtnetlink_rcv_msg` answers any other family -EOPNOTSUPP
            // before a handler (and its device lookup) runs.
            if !matches!(family, AF_INET | AF_INET6) {
                return Err(EOPNOTSUPP);
            }
            let ifindex = u32::from_ne_bytes(request[20..24].try_into().map_err(|_| EINVAL)?);
            let local = find_attr(request, 8, IFA_LOCAL);
            let address = find_attr(request, 8, IFA_ADDRESS);
            if family == AF_INET {
                if hdr.msg_type == RTM_NEWADDR {
                    // `inet_rtm_newaddr` -> `inet_validate_rtm`: the prefix
                    // and IFA_LOCAL are checked before the device is looked up.
                    if prefix_len > 32 {
                        *msg = Some("ipv4: Invalid prefix length");
                        return Err(EINVAL);
                    }
                    let Some(local) = local else {
                        *msg = Some("ipv4: Local address is not supplied");
                        return Err(EINVAL);
                    };
                    let addr: [u8; 4] = local
                        .get(..4)
                        .ok_or(EINVAL)?
                        .try_into()
                        .map_err(|_| EINVAL)?;
                    // `if (!nla_get_in_addr(tb[IFA_LOCAL])) return 0;`
                    if addr == [0; 4] {
                        return Ok(());
                    }
                    // `inet_rtm_to_ifa`.
                    let Some(iface_name) = iface_name_for_index(ifindex) else {
                        *msg = Some("ipv4: Device not found");
                        return Err(ENODEV);
                    };
                    let admin = authority.for_iface(&iface_name)?;
                    let exists = ipv4_addrs_of(admin.iface_name())
                        .iter()
                        .any(|(existing, prefix)| *existing == addr && *prefix == prefix_len);
                    if let Err(errno) = validate_new_addr_flags(exists, hdr.flags) {
                        *msg = Some("ipv4: Address already assigned");
                        return Err(errno);
                    }
                    return admin.add_ipv4(addr, prefix_len).map_err(admin_errno);
                }
                // `inet_rtm_deladdr`: find the device, then delete the first
                // address every supplied selector matches.
                let Some(iface_name) = iface_name_for_index(ifindex) else {
                    *msg = Some("ipv4: Device not found");
                    return Err(ENODEV);
                };
                let admin = authority.for_iface(&iface_name)?;
                let local = match local {
                    Some(raw) => {
                        Some(<[u8; 4]>::try_from(raw.get(..4).ok_or(EINVAL)?).map_err(|_| EINVAL)?)
                    }
                    None => None,
                };
                let address = match address {
                    Some(raw) => {
                        Some(<[u8; 4]>::try_from(raw.get(..4).ok_or(EINVAL)?).map_err(|_| EINVAL)?)
                    }
                    None => None,
                };
                let label = find_attr(request, 8, IFA_LABEL).map(|raw| {
                    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
                    &raw[..end]
                });
                let victim =
                    ipv4_addrs_of(admin.iface_name())
                        .into_iter()
                        .find(|(addr, prefix)| {
                            local.is_none_or(|local| local == *addr)
                                && label.is_none_or(|label| label == admin.iface_name().as_bytes())
                                && address.is_none_or(|address| {
                                    // `inet_ifa_match`: same subnet under the address's mask.
                                    let mask = if *prefix == 0 {
                                        0
                                    } else {
                                        u32::MAX << (32 - u32::from(*prefix))
                                    };
                                    prefix_len == *prefix
                                        && (u32::from_be_bytes(address) ^ u32::from_be_bytes(*addr))
                                            & mask
                                            == 0
                                })
                        });
                let Some((addr, prefix)) = victim else {
                    *msg = Some("ipv4: Address not found");
                    return Err(EADDRNOTAVAIL);
                };
                return admin.del_ipv4(addr, prefix).map_err(admin_errno);
            }
            // IPv6 (`inet6_rtm_newaddr` / `inet6_rtm_deladdr`): `extract_addr`
            // prefers IFA_LOCAL; with neither attribute the request is a bare
            // -EINVAL before any device lookup.
            let addr: [u8; 16] = local
                .or(address)
                .ok_or(EINVAL)?
                .get(..16)
                .ok_or(EINVAL)?
                .try_into()
                .map_err(|_| EINVAL)?;
            if hdr.msg_type == RTM_DELADDR && prefix_len > 128 {
                // `inet6_addr_del`.
                *msg = Some("ipv6: Invalid prefix length");
                return Err(EINVAL);
            }
            let Some(iface_name) = iface_name_for_index(ifindex) else {
                *msg = Some("ipv6: Unable to find the interface");
                return Err(ENODEV);
            };
            let admin = authority.for_iface(&iface_name)?;
            let configured = |iface: &str| {
                let mut addrs: Vec<([u8; 16], u8)> = crate::ipv6::addrs::list_iface(iface)
                    .iter()
                    .map(|existing| (existing.addr, existing.prefix_len))
                    .collect();
                if iface == "lo" {
                    let builtin = builtin_loopback_ipv6();
                    addrs.push((builtin.addr, builtin.prefix_len));
                }
                addrs
            };
            if hdr.msg_type == RTM_NEWADDR {
                // `ipv6_get_ifaddr` matches the address alone.
                let exists = configured(admin.iface_name())
                    .iter()
                    .any(|(existing, _)| *existing == addr);
                if exists {
                    if let Err(errno) = validate_new_addr_flags(true, hdr.flags) {
                        *msg = Some("ipv6: address already assigned");
                        return Err(errno);
                    }
                } else if prefix_len > 128 {
                    // `inet6_addr_add`.
                    *msg = Some("ipv6: Invalid prefix length");
                    return Err(EINVAL);
                }
                return admin.add_ipv6(addr, prefix_len).map_err(admin_errno);
            }
            // `inet6_addr_del` matches prefix length and address.
            if !configured(admin.iface_name())
                .iter()
                .any(|(existing, prefix)| *existing == addr && *prefix == prefix_len)
            {
                *msg = Some("ipv6: address not found");
                return Err(EADDRNOTAVAIL);
            }
            admin.del_ipv6(addr, prefix_len).map_err(admin_errno)
        }
        RTM_NEWROUTE | RTM_DELROUTE => {
            if request.len() < NLMSG_HDRLEN + 12 {
                return Err(EINVAL);
            }
            let family = request[NLMSG_HDRLEN];
            let prefix_len = request[NLMSG_HDRLEN + 1];
            // Route handlers exist for PF_INET / PF_INET6 only (see the
            // address branch): any other family is -EOPNOTSUPP.
            if !matches!(family, AF_INET | AF_INET6) {
                return Err(EOPNOTSUPP);
            }
            if (family == AF_INET && prefix_len > 32) || (family == AF_INET6 && prefix_len > 128) {
                if family == AF_INET {
                    // `rtm_to_fib_config`.
                    *msg = Some("Invalid prefix length");
                }
                return Err(EINVAL);
            }
            let scope = match request[NLMSG_HDRLEN + 6] {
                0 => crate::route::Scope::Universe,
                253 => crate::route::Scope::Link,
                254 => crate::route::Scope::Host,
                _ => return Err(EINVAL),
            };
            let table = if let Some(raw) = find_attr(request, 12, RTA_TABLE) {
                if raw.len() != 4 {
                    return Err(EINVAL);
                }
                u32::from_ne_bytes(raw.try_into().map_err(|_| EINVAL)?)
                    .try_into()
                    .map_err(|_| EINVAL)?
            } else {
                request[NLMSG_HDRLEN + 4]
            };
            let oif = find_attr(request, 12, RTA_OIF).ok_or(EINVAL)?;
            if oif.len() != 4 {
                return Err(EINVAL);
            }
            let ifindex = u32::from_ne_bytes(oif.try_into().map_err(|_| EINVAL)?);
            let iface_name = iface_name_for_index(ifindex).ok_or(ENODEV)?;
            let admin = authority.for_iface(&iface_name)?;
            if family == AF_INET6 {
                if table != crate::route::TABLE_MAIN {
                    return Err(EOPNOTSUPP);
                }
                let dst = match find_attr(request, 12, RTA_DST) {
                    Some(raw) if raw.len() == 16 => raw.try_into().map_err(|_| EINVAL)?,
                    Some(_) => return Err(EINVAL),
                    None if prefix_len == 0 => [0; 16],
                    None => return Err(EINVAL),
                };
                let exists = crate::ipv6::route::list_all().iter().any(|route| {
                    route.iface == admin.iface_name()
                        && route.prefix == dst
                        && route.prefix_len == prefix_len
                });
                if hdr.msg_type == RTM_DELROUTE {
                    if !exists {
                        // `ip6_route_del`: `int err = -ESRCH;`.
                        return Err(ESRCH);
                    }
                    return admin.del_ipv6_route(dst, prefix_len).map_err(admin_errno);
                }
                validate_new_route6_flags(exists, hdr.flags)?;
                let gateway = match find_attr(request, 12, RTA_GATEWAY) {
                    Some(raw) if raw.len() == 16 => Some(raw.try_into().map_err(|_| EINVAL)?),
                    Some(_) => return Err(EINVAL),
                    None => None,
                };
                let metric = match find_attr(request, 12, RTA_PRIORITY) {
                    Some(raw) if raw.len() == 4 => {
                        u32::from_ne_bytes(raw.try_into().map_err(|_| EINVAL)?)
                    }
                    Some(_) => return Err(EINVAL),
                    None => 0,
                };
                return admin
                    .add_ipv6_route(crate::AdminIpv6Route {
                        dst,
                        prefix_len,
                        gateway,
                        metric,
                    })
                    .map_err(admin_errno);
            }
            let dst = match find_attr(request, 12, RTA_DST) {
                Some(raw) if raw.len() == 4 => raw.try_into().map_err(|_| EINVAL)?,
                Some(_) => return Err(EINVAL),
                None if prefix_len == 0 => [0; 4],
                None => return Err(EINVAL),
            };
            let exists = crate::route::route_list().iter().any(|route| {
                route.iface == admin.iface_name()
                    && route.dst.addr.0 == dst
                    && route.dst.prefix_len == prefix_len
                    && route.table == table
            });
            if hdr.msg_type == RTM_DELROUTE {
                if !exists {
                    // `fib_table_delete`: no matching alias → -ESRCH.
                    return Err(ESRCH);
                }
                return admin
                    .del_ipv4_route(dst, prefix_len, table)
                    .map_err(admin_errno);
            }
            validate_new_flags(exists, hdr.flags)?;
            let gateway = match find_attr(request, 12, RTA_GATEWAY) {
                Some(raw) if raw.len() == 4 => Some(raw.try_into().map_err(|_| EINVAL)?),
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let preferred_src = match find_attr(request, 12, RTA_PREFSRC) {
                Some(raw) if raw.len() == 4 => Some(raw.try_into().map_err(|_| EINVAL)?),
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let metric = match find_attr(request, 12, RTA_PRIORITY) {
                Some(raw) if raw.len() == 4 => {
                    u32::from_ne_bytes(raw.try_into().map_err(|_| EINVAL)?)
                }
                Some(_) => return Err(EINVAL),
                None => 0,
            };
            admin
                .add_ipv4_route(crate::AdminIpv4Route {
                    dst,
                    prefix_len,
                    gateway,
                    preferred_src,
                    metric,
                    scope,
                    table,
                })
                .map_err(admin_errno)
        }
        RTM_NEWNEIGH | RTM_DELNEIGH => {
            if request.len() < NLMSG_HDRLEN + 12 {
                return Err(EINVAL);
            }
            let family = request[NLMSG_HDRLEN];
            let ifindex = u32::from_ne_bytes(request[20..24].try_into().map_err(|_| EINVAL)?);
            let iface_name = iface_name_for_index(ifindex).ok_or(ENODEV)?;
            let admin = authority.for_iface(&iface_name)?;
            let state = u16::from_ne_bytes(request[24..26].try_into().map_err(|_| EINVAL)?);
            let flags = request[26];
            let Some(dst) = find_attr(request, 12, NDA_DST) else {
                // `neigh_add` / `neigh_delete`.
                *msg = Some("Network address not specified");
                return Err(EINVAL);
            };
            let mac = match find_attr(request, 12, NDA_LLADDR) {
                Some(raw) if raw.len() == 6 => Some(raw.try_into().map_err(|_| EINVAL)?),
                Some(_) => return Err(EINVAL),
                None => None,
            };
            let exists = match family {
                AF_INET if dst.len() == 4 => crate::arp::snapshot()
                    .iter()
                    .any(|(iface, entry)| iface == admin.iface_name() && entry.ip == dst),
                AF_INET6 if dst.len() == 16 => {
                    crate::ipv6::ndp::neigh_list_in(admin.net_ns_id().map_err(admin_errno)?)
                        .iter()
                        .any(|entry| entry.iface == admin.iface_name() && entry.ip == dst)
                }
                // Short NDA_DST for a known table: "Invalid network address".
                AF_INET | AF_INET6 => {
                    *msg = Some("Invalid network address");
                    return Err(EINVAL);
                }
                // `neigh_find_table()` found no table for this family.
                _ => return Err(EAFNOSUPPORT),
            };
            if hdr.msg_type == RTM_NEWNEIGH {
                validate_new_neigh_flags(exists, hdr.flags)?;
            } else if !exists {
                return Err(ENOENT);
            }
            match (hdr.msg_type, family) {
                (RTM_DELNEIGH, AF_INET) if dst.len() == 4 => admin
                    .del_ipv4_neighbor(dst.try_into().map_err(|_| EINVAL)?)
                    .map_err(admin_errno),
                (RTM_NEWNEIGH, AF_INET) if dst.len() == 4 => admin
                    .set_ipv4_neighbor(dst.try_into().map_err(|_| EINVAL)?, mac.ok_or(EINVAL)?)
                    .map_err(admin_errno),
                (RTM_DELNEIGH, AF_INET6) if dst.len() == 16 => admin
                    .del_ipv6_neighbor(dst.try_into().map_err(|_| EINVAL)?)
                    .map_err(admin_errno),
                (RTM_NEWNEIGH, AF_INET6) if dst.len() == 16 => {
                    let state = if state & NUD_REACHABLE != 0 {
                        crate::ipv6::ndp::NeighState::Reachable
                    } else if state & NUD_STALE != 0 {
                        crate::ipv6::ndp::NeighState::Stale
                    } else if state & NUD_DELAY != 0 {
                        crate::ipv6::ndp::NeighState::Delay
                    } else if state & NUD_PROBE != 0 {
                        crate::ipv6::ndp::NeighState::Probe
                    } else if state & NUD_INCOMPLETE != 0 {
                        crate::ipv6::ndp::NeighState::Incomplete
                    } else {
                        return Err(EINVAL);
                    };
                    admin
                        .set_ipv6_neighbor(
                            dst.try_into().map_err(|_| EINVAL)?,
                            mac,
                            state,
                            flags & NTF_ROUTER != 0,
                        )
                        .map_err(admin_errno)
                }
                _ => Err(EINVAL),
            }
        }
        RTM_DELLINK => Err(EOPNOTSUPP),
        _ => Err(EOPNOTSUPP),
    }
}

fn is_mutation(msg_type: u16) -> bool {
    matches!(
        msg_type,
        RTM_NEWLINK
            | RTM_DELLINK
            | RTM_SETLINK
            | RTM_NEWADDR
            | RTM_DELADDR
            | RTM_NEWROUTE
            | RTM_DELROUTE
            | RTM_NEWNEIGH
            | RTM_DELNEIGH
    )
}

/// Parse every aligned `nlmsghdr` in one netlink datagram and build a single
/// ordered reply queue. Linux permits callers to batch multiple requests in
/// one `sendmsg`; each request retains its own sequence number. Successful
/// requests carrying `NLM_F_ACK` receive an `NLMSG_ERROR` with error zero
/// after their dump. A malformed message length rejects the whole datagram.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_authorized(datagram, None)
}

pub fn build_replies_authorized(
    datagram: &[u8],
    admin: Option<&crate::AdminHandle>,
) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_with_options(datagram, admin, ReplyOptions::default())
}

#[derive(Copy, Clone, Debug, Default)]
pub struct ReplyOptions {
    pub ext_ack: bool,
    pub cap_ack: bool,
    pub strict_check: bool,
    /// The sender is `netlink_net_capable(CAP_NET_ADMIN)` in the socket's
    /// network namespace: it may change any of that namespace's devices.
    pub net_admin: bool,
}

pub fn build_replies_with_options(
    datagram: &[u8],
    admin: Option<&crate::AdminHandle>,
    options: ReplyOptions,
) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_with_options_in(0, datagram, admin, options)
}

pub fn build_replies_with_options_in(
    net_ns_id: u64,
    datagram: &[u8],
    admin: Option<&crate::AdminHandle>,
    options: ReplyOptions,
) -> Result<Vec<Vec<u8>>, ()> {
    let admin = admin.filter(|admin| admin.net_ns_id() == Ok(net_ns_id));
    let mut offset = 0usize;
    let mut replies = Vec::new();
    // Mutation failures whose Linux handler sets an extended-ACK message:
    // `(index into replies, text)`.
    let mut ext_ack_msgs: Vec<(usize, &'static str)> = Vec::new();

    // Linux `netlink_rcv_skb`: walk while a whole header remains, and stop
    // (silently — sendmsg still returns the full length) at a header whose
    // nlmsg_len is below NLMSG_HDRLEN or past the end. iproute2 sends its
    // RTM_GETADDR dump in a zero-padded 152-byte buffer, so the walk must end
    // at the trailing nlmsg_len == 0 header instead of failing the send.
    while datagram.len() - offset >= NLMSG_HDRLEN {
        let remaining = &datagram[offset..];
        let Some(hdr) = parse_hdr(remaining) else {
            break;
        };
        let msg_len = hdr.len as usize;
        if msg_len < NLMSG_HDRLEN || msg_len > remaining.len() {
            break;
        }
        let request = &remaining[..msg_len];
        // `msglen = NLMSG_ALIGN(nlmsg_len)`, clamped to what is left.
        let advance = nlmsg_align(msg_len).min(remaining.len());
        offset += advance;
        let wants_ack = hdr.flags & NLM_F_ACK != 0;

        // `netlink_rcv_skb`: only requests are handled by the kernel, and
        // control messages are skipped; either is ACKed (error 0) only on
        // NLM_F_ACK.
        if hdr.flags & NLM_F_REQUEST == 0 || hdr.msg_type < NLMSG_MIN_TYPE {
            if wants_ack {
                replies.push(build_ack(hdr.seq, request));
            }
            continue;
        }
        // `rtnetlink_rcv_msg`: an out-of-range type is -EOPNOTSUPP; a
        // message without even a one-byte `rtgenmsg` is ignored (returns 0).
        if hdr.msg_type > RTM_MAX {
            replies.push(build_error(EOPNOTSUPP, hdr.seq, 0, request));
            continue;
        }
        if msg_len - NLMSG_HDRLEN < 1 {
            if wants_ack {
                replies.push(build_ack(hdr.seq, request));
            }
            continue;
        }
        if is_mutation(hdr.msg_type) {
            let authority = MutationAuthority {
                delegated: admin,
                net_admin: options.net_admin,
                net_ns_id,
            };
            let mut msg = None;
            match apply_mutation(request, &authority, &mut msg) {
                Ok(()) => {
                    if wants_ack {
                        replies.push(build_ack(hdr.seq, request));
                    }
                }
                Err(errno) => {
                    if let Some(text) = msg {
                        ext_ack_msgs.push((replies.len(), text));
                    }
                    replies.push(build_error(errno, hdr.seq, 0, request));
                }
            }
            continue;
        }
        // A dump that starts is never ACKed: `__netlink_dump_start` returns
        // -EINTR and `netlink_rcv_skb` skips the ACK. Its errors travel in
        // the terminating NLMSG_DONE instead (`netlink_dump_done`).
        if hdr.flags & NLM_F_DUMP != 0 && dump::is_dump_type(hdr.msg_type) {
            replies.extend(dump::run(
                net_ns_id,
                request,
                options.strict_check,
                options.ext_ack,
            ));
            continue;
        }
        // A doit's error is its (only) ACK; a successful doit's reply is
        // followed by the ACK when NLM_F_ACK asked for one.
        let answer = build_get_in(net_ns_id, request, options.strict_check, options.ext_ack);
        let failed = answer
            .iter()
            .any(|message| parse_hdr(message).is_some_and(|reply| reply.msg_type == NLMSG_ERROR));
        replies.extend(answer);
        if wants_ack && !failed {
            replies.push(build_ack(hdr.seq, request));
        }
    }
    for (index, reply) in replies.iter_mut().enumerate() {
        if options.cap_ack {
            cap_acknowledgement(reply);
        }
        if options.ext_ack {
            if let Some((_, text)) = ext_ack_msgs.iter().find(|(at, _)| *at == index) {
                append_extended_ack(reply, text);
            }
        }
    }
    Ok(replies)
}

fn cap_acknowledgement(message: &mut Vec<u8>) {
    let Some(hdr) = parse_hdr(message) else {
        return;
    };
    if hdr.msg_type != NLMSG_ERROR || message.len() < NLMSG_HDRLEN + 4 + NLMSG_HDRLEN {
        return;
    }
    let capped_len = NLMSG_HDRLEN + 4 + NLMSG_HDRLEN;
    message.truncate(capped_len);
    message[0..4].copy_from_slice(&(capped_len as u32).to_ne_bytes());
    message[6..8].copy_from_slice(&(hdr.flags | NLM_F_CAPPED).to_ne_bytes());
}

/// `netlink_ack` with an extended-ACK message: attach the handler's
/// `NL_SET_ERR_MSG` text as NLMSGERR_ATTR_MSG and flag NLM_F_ACK_TLVS. Linux
/// sends a message only where the handler set one.
fn append_extended_ack(message: &mut Vec<u8>, text: &str) {
    let Some(hdr) = parse_hdr(message) else {
        return;
    };
    if hdr.msg_type != NLMSG_ERROR || message.len() < NLMSG_HDRLEN + 4 {
        return;
    }
    let declared_len = hdr.len as usize;
    if declared_len > message.len() {
        return;
    }
    message.truncate(declared_len);
    let mut text = text.as_bytes().to_vec();
    text.push(0);
    push_rtattr(message, NLMSGERR_ATTR_MSG, &text);
    let new_len = message.len() as u32;
    message[0..4].copy_from_slice(&new_len.to_ne_bytes());
    let flags = hdr.flags | NLM_F_ACK_TLVS;
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
}

/// Build kernel-originated multicast notifications for mutations that
/// succeeded in `build_replies_authorized`. The group mask uses the legacy
/// sockaddr_nl bit numbering consumed by `NETLINK_ADD_MEMBERSHIP`.
pub fn successful_mutation_notifications(
    datagram: &[u8],
    replies: &[Vec<u8>],
) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + NLMSG_HDRLEN <= datagram.len() {
        let Some(hdr) = parse_hdr(&datagram[offset..]) else {
            break;
        };
        let len = hdr.len as usize;
        if len < NLMSG_HDRLEN || offset + len > datagram.len() {
            break;
        }
        // Mirror the walk in `build_replies_with_options_in`: a message
        // without NLM_F_REQUEST, or with no payload, is never applied.
        if !is_mutation(hdr.msg_type) || hdr.flags & NLM_F_REQUEST == 0 || len == NLMSG_HDRLEN {
            offset += nlmsg_align(len);
            continue;
        }
        let failed = replies.iter().any(|reply| {
            let Some(reply_hdr) = parse_hdr(reply) else {
                return false;
            };
            reply_hdr.msg_type == NLMSG_ERROR
                && reply_hdr.seq == hdr.seq
                && reply.len() >= NLMSG_HDRLEN + 4
                && i32::from_ne_bytes(
                    reply[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) < 0
        });
        if !failed {
            let family = datagram.get(offset + NLMSG_HDRLEN).copied().unwrap_or(0);
            let (msg_type, group) = match hdr.msg_type {
                RTM_NEWLINK | RTM_SETLINK => (RTM_NEWLINK, 1),
                RTM_DELLINK => (RTM_DELLINK, 1),
                RTM_NEWNEIGH | RTM_DELNEIGH => (hdr.msg_type, 1u32 << (3 - 1)),
                RTM_NEWADDR | RTM_DELADDR => {
                    let group = if family == AF_INET6 { 9 } else { 5 };
                    (hdr.msg_type, 1u32 << (group - 1))
                }
                RTM_NEWROUTE | RTM_DELROUTE => {
                    let group = if family == AF_INET6 { 11 } else { 7 };
                    (hdr.msg_type, 1u32 << (group - 1))
                }
                _ => {
                    offset += nlmsg_align(len);
                    continue;
                }
            };
            let mut message = datagram[offset..offset + len].to_vec();
            message[4..6].copy_from_slice(&msg_type.to_ne_bytes());
            message[6..8].copy_from_slice(&0u16.to_ne_bytes());
            message[8..12].copy_from_slice(&0u32.to_ne_bytes());
            message[12..16].copy_from_slice(&0u32.to_ne_bytes());
            message.resize(nlmsg_align(len), 0);
            if matches!(msg_type, RTM_NEWADDR | RTM_DELADDR) {
                complete_addr_notification(&mut message);
            }
            out.push((group, message));
        }
        offset += nlmsg_align(len);
    }
    out
}

#[path = "netlink_route/dump.rs"]
mod dump;

#[cfg(test)]
#[path = "netlink_route/tests.rs"]
mod tests;
