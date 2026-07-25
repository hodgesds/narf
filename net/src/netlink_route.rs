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

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_GETRULE: u16 = 34;

// ── netlink flags (nlmsg_flags) ─────────────────────────────────────────

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// ── IFLA_* link attribute types (if_link.h) ─────────────────────────────

pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;

// ── IFA_* address attribute types (if_addr.h) ───────────────────────────

pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;

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

// ── interface flags (net_device_flags, if.h) ────────────────────────────

pub const IFF_UP: u32 = 0x1;
pub const IFF_BROADCAST: u32 = 0x2;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_MULTICAST: u32 = 0x1000;

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
    body.extend_from_slice(&link.flags.to_le_bytes()); // ifi_flags
    body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ifi_change = ~0

    // IFLA_IFNAME is a NUL-terminated string.
    let mut name_bytes = link.name.as_bytes().to_vec();
    name_bytes.push(0);
    push_rtattr(&mut body, IFLA_IFNAME, &name_bytes);
    if !link.mac.is_empty() {
        push_rtattr(&mut body, IFLA_ADDRESS, &link.mac);
    }
    push_rtattr(&mut body, IFLA_MTU, &link.mtu.to_le_bytes());

    frame_message(RTM_NEWLINK, NLM_F_MULTI, seq, pid, &body)
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
    body.push(0u8); // ifa_flags
                    // ifa_scope: 0 = RT_SCOPE_UNIVERSE for a routable addr, 254 =
                    // RT_SCOPE_HOST for loopback (127.0.0.0/8).
    let scope = if a.addr[0] == 127 { 254u8 } else { 0u8 };
    body.push(scope);
    body.extend_from_slice(&a.ifindex.to_le_bytes()); // ifa_index

    push_rtattr(&mut body, IFA_ADDRESS, &a.addr);
    push_rtattr(&mut body, IFA_LOCAL, &a.addr);
    let mut label_bytes = a.label.as_bytes().to_vec();
    label_bytes.push(0);
    push_rtattr(&mut body, IFA_LABEL, &label_bytes);

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

/// Build an `NLMSG_DONE` message (payload is a single i32 = 0). Terminates
/// every dump so the caller stops reading.
fn build_done(seq: u32, pid: u32) -> Vec<u8> {
    frame_message(NLMSG_DONE, NLM_F_MULTI, seq, pid, &0i32.to_le_bytes())
}

/// Build an `NLMSG_ERROR` message carrying `-errno` (negated per netlink
/// convention) followed by an echo of the offending request header.
fn build_error(errno: i32, seq: u32, pid: u32, req: &[u8]) -> Vec<u8> {
    // struct nlmsgerr: error(i32) msg(struct nlmsghdr). Echo back up to a
    // full header of the request (zero-padded if the request was shorter).
    let mut body = Vec::with_capacity(4 + NLMSG_HDRLEN);
    body.extend_from_slice(&(-errno).to_le_bytes());
    let echo = core::cmp::min(req.len(), NLMSG_HDRLEN);
    body.extend_from_slice(&req[..echo]);
    body.extend(core::iter::repeat_n(0u8, NLMSG_HDRLEN - echo));
    frame_message(NLMSG_ERROR, 0, seq, pid, &body)
}

fn build_ack(seq: u32, req: &[u8]) -> Vec<u8> {
    build_error(0, seq, 0, req)
}

// ── dump entry point ────────────────────────────────────────────────────

/// Enumerate the interfaces the dump should describe. Loopback is synthetic
/// (ifindex 1); registered NICs follow at ifindex 2, 3, … in registration
/// order. Returned as `(link, addrs)` so both dumps share one enumeration.
fn enumerate() -> (Vec<LinkInfo>, Vec<AddrInfo>) {
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

    // Each registered NIC: ARPHRD_ETHER, MTU 1500, its MAC + IPv4.
    for (i, nic) in crate::iface::snapshot_all().into_iter().enumerate() {
        let ifindex = (i as u32) + 2;
        links.push(LinkInfo {
            ifindex,
            flags: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST,
            arphrd: ARPHRD_ETHER,
            name: nic.name.clone(),
            mac: nic.mac.to_vec(),
            mtu: 1500,
        });
        // Report the iface's configured IPv4 (skip the 0.0.0.0 placeholder
        // an unconfigured iface carries — an addr dump shouldn't list it).
        if nic.ipv4 != [0, 0, 0, 0] {
            addrs.push(AddrInfo {
                ifindex,
                prefix_len: 24,
                addr: nic.ipv4,
                label: nic.name.clone(),
            });
        }
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
    let hdr = match parse_hdr(req) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let seq = hdr.seq;
    // Replies originate from the kernel netlink endpoint. Linux stamps
    // nlmsg_pid=0; the requester's port ID is not echoed in reply headers.
    let pid = 0;
    let mut out = Vec::new();
    match hdr.msg_type {
        RTM_GETLINK => {
            let (links, _addrs) = enumerate();
            for l in &links {
                out.push(build_newlink(l, seq, pid));
            }
            out.push(build_done(seq, pid));
        }
        RTM_GETADDR => {
            let (_links, addrs) = enumerate();
            for a in &addrs {
                out.push(build_newaddr(a, seq, pid));
            }
            out.push(build_done(seq, pid));
        }
        RTM_GETROUTE => {
            let (links, _addrs) = enumerate();
            let mut routes = crate::route::route_list();
            // Link/address dumps always expose loopback. Mirror that invariant
            // in route dumps even during early boot before net init installs
            // the canonical loopback FIB entry.
            if !routes
                .iter()
                .any(|r| r.iface == "lo" && r.dst.addr.0 == [127, 0, 0, 0] && r.dst.prefix_len == 8)
            {
                routes.push(crate::route::Route {
                    dst: crate::route::Ipv4Net {
                        addr: crate::ipv4::Ipv4Addr([127, 0, 0, 0]),
                        prefix_len: 8,
                    },
                    gateway: None,
                    iface: alloc::string::String::from("lo"),
                    src_hint: Some(crate::ipv4::Ipv4Addr([127, 0, 0, 1])),
                    metric: 0,
                    scope: crate::route::Scope::Host,
                    table: crate::route::TABLE_LOCAL,
                });
            }
            for route in &routes {
                if let Some(link) = links.iter().find(|link| link.name == route.iface) {
                    out.push(build_newroute(route, link.ifindex, seq, pid));
                }
            }
            out.push(build_done(seq, pid));
        }
        RTM_GETNEIGH => {
            let (links, _addrs) = enumerate();
            let requested_family = req.get(NLMSG_HDRLEN).copied().unwrap_or(0);
            if requested_family == 0 || requested_family == AF_INET {
                for (iface, entry) in crate::arp::snapshot() {
                    if let Some(link) = links.iter().find(|link| link.name == iface) {
                        out.push(build_newneigh(
                            &NeighInfo {
                                family: AF_INET,
                                dst: &entry.ip,
                                mac: Some(entry.mac),
                                ifindex: link.ifindex,
                                state: NUD_REACHABLE,
                                flags: 0,
                            },
                            seq,
                            pid,
                        ));
                    }
                }
            }
            if requested_family == 0 || requested_family == AF_INET6 {
                for entry in crate::ipv6::ndp::neigh_list() {
                    if let Some(link) = links.iter().find(|link| link.name == entry.iface) {
                        let state = match entry.state {
                            crate::ipv6::ndp::NeighState::Incomplete => NUD_INCOMPLETE,
                            crate::ipv6::ndp::NeighState::Reachable => NUD_REACHABLE,
                            crate::ipv6::ndp::NeighState::Stale => NUD_STALE,
                            crate::ipv6::ndp::NeighState::Delay => NUD_DELAY,
                            crate::ipv6::ndp::NeighState::Probe => NUD_PROBE,
                        };
                        out.push(build_newneigh(
                            &NeighInfo {
                                family: AF_INET6,
                                dst: &entry.ip,
                                mac: entry.mac,
                                ifindex: link.ifindex,
                                state,
                                flags: if entry.is_router { NTF_ROUTER } else { 0 },
                            },
                            seq,
                            pid,
                        ));
                    }
                }
            }
            out.push(build_done(seq, pid));
        }
        RTM_GETRULE => {
            let requested_family = req.get(NLMSG_HDRLEN).copied().unwrap_or(0);
            if requested_family == 0 || requested_family == AF_INET {
                // Linux installs these policy-routing rules by default:
                // priority 0 → local, 32766 → main, 32767 → default.
                out.push(build_newrule(
                    AF_INET,
                    crate::route::TABLE_LOCAL,
                    0,
                    seq,
                    pid,
                ));
                out.push(build_newrule(
                    AF_INET,
                    crate::route::TABLE_MAIN,
                    32_766,
                    seq,
                    pid,
                ));
                out.push(build_newrule(
                    AF_INET,
                    crate::route::TABLE_DEFAULT,
                    32_767,
                    seq,
                    pid,
                ));
            }
            out.push(build_done(seq, pid));
        }
        _ => {
            out.push(build_error(EOPNOTSUPP, seq, pid, req));
        }
    }
    out
}

/// Parse every aligned `nlmsghdr` in one netlink datagram and build a single
/// ordered reply queue. Linux permits callers to batch multiple requests in
/// one `sendmsg`; each request retains its own sequence number. Successful
/// requests carrying `NLM_F_ACK` receive an `NLMSG_ERROR` with error zero
/// after their dump. A malformed message length rejects the whole datagram.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    let mut offset = 0usize;
    let mut replies = Vec::new();

    while offset < datagram.len() {
        let remaining = &datagram[offset..];
        let hdr = parse_hdr(remaining).ok_or(())?;
        let msg_len = hdr.len as usize;
        if msg_len < NLMSG_HDRLEN || msg_len > remaining.len() {
            return Err(());
        }
        let request = &remaining[..msg_len];
        let supported = matches!(
            hdr.msg_type,
            RTM_GETLINK | RTM_GETADDR | RTM_GETROUTE | RTM_GETNEIGH | RTM_GETRULE
        );
        if supported && hdr.flags & NLM_F_ACK != 0 {
            replies.push(build_ack(hdr.seq, request));
        }
        replies.extend(build_dump(request));

        let step = nlmsg_align(msg_len);
        if step > remaining.len() {
            // An unpadded final message is valid only when its declared bytes
            // exactly consume the datagram.
            if msg_len == remaining.len() {
                offset = datagram.len();
            } else {
                return Err(());
            }
        } else {
            offset += step;
        }
    }
    Ok(replies)
}

#[cfg(test)]
#[path = "netlink_route/tests.rs"]
mod tests;
