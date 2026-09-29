//! rtnetlink dump dispatch, request validation, and `netlink_dump` error
//! delivery, following Linux exactly.
//!
//! Linux splits a `NLM_F_DUMP` request's life in two:
//!
//! * `rtnetlink_rcv_msg` (net/core/rtnetlink.c) looks up the dumpit for
//!   `(family, type)`, falling back to `PF_UNSPEC`. Only a missing dumpit
//!   fails here, and it fails with `NLMSG_ERROR(-EOPNOTSUPP)` via
//!   `netlink_ack`. A dump that starts is never ACKed (`__netlink_dump_start`
//!   returns `-EINTR`, which `netlink_rcv_skb` skips).
//! * The dumpit itself validates the request (strictly when the socket set
//!   `NETLINK_GET_STRICT_CHK`). Its negative return becomes the payload of the
//!   terminating `NLMSG_DONE` (`netlink_dump` / `netlink_dump_done`,
//!   net/netlink/af_netlink.c), with `NLM_F_MULTI | cb->answer_flags` and,
//!   under `NETLINK_EXT_ACK`, the extack message / offending-attribute offset.
//!
//! Every validator below names the Linux function it mirrors; the check order
//! and errno of each branch are taken from that function.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::{
    build_error, build_newaddr, build_newaddr_v6, build_newlink, build_newneigh, build_newqdisc,
    build_newroute, build_newroute_v6, build_newrule, builtin_loopback_ipv6, enumerate_in,
    frame_message, ifindex_for_name, nlmsg_align, parse_hdr, push_rtattr, rta_align, LinkInfo,
    NeighInfo, AF_INET, AF_INET6, EAFNOSUPPORT, EINVAL, ENODEV, ENOENT, EOPNOTSUPP,
    NLMSGERR_ATTR_MSG, NLMSG_DONE, NLMSG_HDRLEN, NLM_F_ACK_TLVS, NLM_F_MULTI, NTF_ROUTER,
    NUD_DELAY, NUD_INCOMPLETE, NUD_PROBE, NUD_REACHABLE, NUD_STALE, RTM_GETACTION, RTM_GETADDR,
    RTM_GETADDRLABEL, RTM_GETLINK, RTM_GETMDB, RTM_GETNEIGH, RTM_GETNEXTHOP, RTM_GETQDISC,
    RTM_GETROUTE, RTM_GETRULE, RTM_GETTCLASS, RTM_GETTFILTER, RTN_LOCAL, RTN_UNICAST,
    RTPROT_KERNEL,
};

pub const ERANGE: i32 = 34;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;
pub const NLMSGERR_ATTR_OFFS: u16 = 2;
pub const AF_BRIDGE: u8 = 7;
pub const RTNL_FAMILY_IPMR: u8 = 128;
pub const RTNL_FAMILY_IP6MR: u8 = 129;
pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;

const NLA_HDRLEN: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

// `enum netlink_validation` (include/net/netlink.h).
pub const NL_VALIDATE_LIBERAL: u32 = 0;
const NL_VALIDATE_TRAILING: u32 = 1 << 0;
const NL_VALIDATE_MAXTYPE: u32 = 1 << 1;
const NL_VALIDATE_UNSPEC: u32 = 1 << 2;
const NL_VALIDATE_STRICT_ATTRS: u32 = 1 << 3;
const NL_VALIDATE_NESTED: u32 = 1 << 4;
pub const NL_VALIDATE_DEPRECATED_STRICT: u32 = NL_VALIDATE_TRAILING | NL_VALIDATE_MAXTYPE;
const NL_VALIDATE_STRICT: u32 = NL_VALIDATE_TRAILING
    | NL_VALIDATE_MAXTYPE
    | NL_VALIDATE_UNSPEC
    | NL_VALIDATE_STRICT_ATTRS
    | NL_VALIDATE_NESTED;

// rtmsg flags (include/uapi/linux/rtnetlink.h).
const RTM_F_CLONED: u32 = 0x200;
const RTM_F_PREFIX: u32 = 0x800;
// ndmsg flags (include/uapi/linux/neighbour.h).
const NTF_PROXY: u8 = 0x08;

// ── extended ACK ────────────────────────────────────────────────────────

/// The parts of Linux `struct netlink_ext_ack` a dump reports: `_msg` and
/// `bad_attr` (as its byte offset from the request's `nlmsghdr`).
#[derive(Default)]
pub struct ExtAck {
    pub msg: Option<&'static str>,
    pub bad_attr: Option<usize>,
}

impl ExtAck {
    /// `NL_SET_ERR_MSG`.
    pub fn set(&mut self, msg: &'static str) {
        self.msg = Some(msg);
    }

    /// `NL_SET_ERR_MSG_ATTR` / `NL_SET_ERR_MSG_ATTR_POL`.
    // LINUX-GAP: NL_SET_ERR_MSG_ATTR_POL also records the policy, which Linux
    // reports as a nested NLMSGERR_ATTR_POLICY (netlink_policy_dump_write_attr);
    // NARF reports the message and NLMSGERR_ATTR_OFFS only.
    fn set_attr(&mut self, msg: &'static str, attr_off: usize) {
        self.msg = Some(msg);
        self.bad_attr = Some(attr_off);
    }
}

// ── attribute policy validation (lib/nlattr.c) ──────────────────────────

/// One `struct nla_policy` entry, reduced to what `validate_nla` inspects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pol {
    /// `NLA_UNSPEC` with `.len` as the minimum payload length.
    Unspec(usize),
    U8,
    U16,
    U32,
    S32,
    /// `NLA_POLICY_MIN(NLA_U32, min)`.
    MinU32(u32),
    /// `NLA_POLICY_MIN(NLA_S32, min)`.
    MinS32(i32),
    /// `NLA_POLICY_MASK(NLA_U32, mask)`.
    MaskU32(u32),
    Flag,
    /// `NLA_STRING` with `.len` (0 = unbounded).
    Str(usize),
    /// `NLA_NUL_STRING` with `.len` (0 = unbounded).
    NulStr(usize),
    /// `NLA_BINARY` with `.len` (0 = unbounded).
    Binary(usize),
    /// `NLA_NESTED` without a nested policy.
    Nested,
    /// `NLA_POLICY_BITFIELD32(valid)`.
    Bitfield32(u32),
    Reject,
}

impl Pol {
    /// `nla_attr_len[]`: the exact size of fixed-width integer types.
    fn exact_len(self) -> usize {
        match self {
            Pol::U8 => 1,
            Pol::U16 => 2,
            Pol::U32 | Pol::S32 | Pol::MinU32(_) | Pol::MinS32(_) | Pol::MaskU32(_) => 4,
            _ => 0,
        }
    }
}

/// A Linux attribute policy table: `maxtype`, `policy[0].strict_start_type`,
/// and the per-type entries (types absent from the table are
/// `Pol::Unspec(0)`, as a zero-initialised C entry is).
pub struct Policy {
    pub maxtype: u16,
    pub strict_start: u16,
    pub entry: fn(u16) -> Pol,
}

/// `tb[]`: for each attribute type, the (payload offset, payload length)
/// of the last attribute of that type, offsets relative to the request.
pub type Tb = Vec<Option<(usize, usize)>>;

fn read_u32(req: &[u8], off: usize) -> u32 {
    req.get(off..off + 4)
        .and_then(|raw| raw.try_into().ok())
        .map(u32::from_ne_bytes)
        .unwrap_or(0)
}

fn read_u16(req: &[u8], off: usize) -> u16 {
    req.get(off..off + 2)
        .and_then(|raw| raw.try_into().ok())
        .map(u16::from_ne_bytes)
        .unwrap_or(0)
}

fn byte(req: &[u8], off: usize) -> u8 {
    req.get(off).copied().unwrap_or(0)
}

/// `nla_get_u32` of a parsed attribute.
pub fn attr_u32(req: &[u8], attr: (usize, usize)) -> u32 {
    read_u32(req, attr.0)
}

/// `validate_nla`.
fn validate_nla(
    req: &[u8],
    attr_off: usize,
    policy: &Policy,
    mut validate: u32,
    extack: &mut ExtAck,
) -> Result<(), i32> {
    let nla_len = read_u16(req, attr_off) as usize;
    let raw_type = read_u16(req, attr_off + 2);
    let ty = raw_type & NLA_TYPE_MASK;
    let attrlen = nla_len - NLA_HDRLEN;
    let data = &req[attr_off + NLA_HDRLEN..attr_off + nla_len];

    if policy.strict_start != 0 && ty >= policy.strict_start {
        validate |= NL_VALIDATE_STRICT;
    }
    if ty == 0 || ty > policy.maxtype {
        return Ok(());
    }
    let pt = (policy.entry)(ty);

    let exact = pt.exact_len();
    if exact != 0 && attrlen != exact && validate & NL_VALIDATE_STRICT_ATTRS != 0 {
        extack.set_attr("invalid attribute length", attr_off);
        return Err(EINVAL);
    }
    if validate & NL_VALIDATE_NESTED != 0 {
        if pt == Pol::Nested && raw_type & NLA_F_NESTED == 0 {
            extack.set_attr("NLA_F_NESTED is missing", attr_off);
            return Err(EINVAL);
        }
        if pt != Pol::Nested && !matches!(pt, Pol::Unspec(_)) && raw_type & NLA_F_NESTED != 0 {
            extack.set_attr("NLA_F_NESTED not expected", attr_off);
            return Err(EINVAL);
        }
    }

    // `goto out_err`: the policy-validation failure with the given errno.
    let mut fail = |err: i32| {
        extack.set_attr("Attribute failed policy validation", attr_off);
        Err(err)
    };
    match pt {
        Pol::Reject => return fail(EINVAL),
        Pol::Flag => {
            if attrlen > 0 {
                return fail(ERANGE);
            }
        }
        Pol::Bitfield32(valid) => {
            if attrlen != 8 {
                return fail(ERANGE);
            }
            // `validate_nla_bitfield32`: struct nla_bitfield32 { value; selector; }.
            let value = read_u32(data, 0);
            let selector = read_u32(data, 4);
            if valid == 0 || selector & !valid != 0 || value & !valid != 0 || value & !selector != 0
            {
                return fail(EINVAL);
            }
        }
        Pol::NulStr(max) | Pol::Str(max) => {
            if let Pol::NulStr(_) = pt {
                let minlen = if max != 0 {
                    attrlen.min(max + 1)
                } else {
                    attrlen
                };
                if minlen == 0 || !data[..minlen].contains(&0) {
                    return fail(EINVAL);
                }
            }
            if attrlen < 1 {
                return fail(ERANGE);
            }
            if max != 0 {
                let mut len = attrlen;
                if data[len - 1] == 0 {
                    len -= 1;
                }
                if len > max {
                    return fail(ERANGE);
                }
            }
        }
        Pol::Binary(max) => {
            if max != 0 && attrlen > max {
                return fail(ERANGE);
            }
        }
        Pol::Nested => {
            // Empty is allowed; otherwise at least one attribute header.
            if attrlen != 0 && attrlen < NLA_HDRLEN {
                return fail(ERANGE);
            }
        }
        Pol::Unspec(min) => {
            if validate & NL_VALIDATE_UNSPEC != 0 {
                extack.set_attr("Unsupported attribute", attr_off);
                return Err(EINVAL);
            }
            if attrlen < min {
                return fail(ERANGE);
            }
        }
        Pol::U8 | Pol::U16 | Pol::U32 | Pol::S32 | Pol::MinU32(_) | Pol::MinS32(_) => {
            if attrlen < exact {
                return fail(ERANGE);
            }
        }
        Pol::MaskU32(_) => {
            if attrlen < exact {
                return fail(ERANGE);
            }
        }
    }

    // `pt->validation_type`.
    match pt {
        Pol::MinU32(min) if read_u32(data, 0) < min => {
            extack.set_attr("integer out of range", attr_off);
            Err(ERANGE)
        }
        Pol::MinS32(min) if (read_u32(data, 0) as i32) < min => {
            extack.set_attr("integer out of range", attr_off);
            Err(ERANGE)
        }
        Pol::MaskU32(mask) if read_u32(data, 0) & !mask != 0 => {
            extack.set_attr("reserved bit set", attr_off);
            Err(EINVAL)
        }
        _ => Ok(()),
    }
}

/// `__nla_validate_parse` over `len` bytes of attributes starting at `head`.
fn nla_parse(
    req: &[u8],
    head: usize,
    len: isize,
    policy: &Policy,
    validate: u32,
    extack: &mut ExtAck,
) -> Result<Tb, i32> {
    let mut tb: Tb = vec![None; policy.maxtype as usize + 1];
    let mut pos = head;
    let mut rem = len;
    // `nla_for_each_attr` / `nla_ok`.
    while rem >= NLA_HDRLEN as isize {
        let nla_len = read_u16(req, pos) as usize;
        if nla_len < NLA_HDRLEN || nla_len as isize > rem {
            break;
        }
        let ty = read_u16(req, pos + 2) & NLA_TYPE_MASK;
        if ty == 0 || ty > policy.maxtype {
            if validate & NL_VALIDATE_MAXTYPE != 0 {
                extack.set_attr("Unknown attribute type", pos);
                return Err(EINVAL);
            }
        } else {
            validate_nla(req, pos, policy, validate, extack)?;
            tb[ty as usize] = Some((pos + NLA_HDRLEN, nla_len - NLA_HDRLEN));
        }
        let total = rta_align(nla_len);
        pos += total;
        rem -= total as isize;
    }
    if rem > 0 {
        extack.set("bytes leftover after parsing attributes");
        if validate & NL_VALIDATE_TRAILING != 0 {
            return Err(EINVAL);
        }
    }
    Ok(tb)
}

/// `__nlmsg_parse`: attributes follow a `hdrlen`-byte family header.
pub fn nlmsg_parse(
    req: &[u8],
    hdrlen: usize,
    policy: &Policy,
    validate: u32,
    extack: &mut ExtAck,
) -> Result<Tb, i32> {
    if req.len() < NLMSG_HDRLEN + hdrlen {
        extack.set("Invalid header length");
        return Err(EINVAL);
    }
    let head = NLMSG_HDRLEN + nlmsg_align(hdrlen);
    nla_parse(
        req,
        head,
        req.len() as isize - head as isize,
        policy,
        validate,
        extack,
    )
}

/// `nlmsg_payload(nlh, len) != NULL`.
fn has_payload(req: &[u8], len: usize) -> bool {
    req.len() >= NLMSG_HDRLEN + len
}

/// `nlmsg_attrlen(nlh, hdrlen) != 0`.
fn has_attrs(req: &[u8], hdrlen: usize) -> bool {
    req.len() != NLMSG_HDRLEN + nlmsg_align(hdrlen)
}

// ── policies ────────────────────────────────────────────────────────────

/// `ifla_policy` (net/core/rtnetlink.c).
pub const IFLA_POLICY: Policy = Policy {
    maxtype: 69,      // IFLA_MAX
    strict_start: 65, // IFLA_DPLL_PIN
    entry: ifla_entry,
};

/// `MAX_TCP_HEADER + 1` for `IFLA_GSO{,_IPV4}_MAX_SIZE`: L1_CACHE_ALIGN(128 +
/// MAX_HEADER) with the x86_64 distro LL_MAX_HEADER (128) plus tunnels (+48).
const GSO_MAX_SIZE_MIN: u32 = 321;

fn ifla_entry(ty: u16) -> Pol {
    match ty {
        3 => Pol::Str(15),                                    // IFLA_IFNAME, IFNAMSIZ-1
        1 | 2 => Pol::Binary(32), // IFLA_ADDRESS/BROADCAST, MAX_ADDR_LEN
        14 => Pol::Unspec(32),    // IFLA_MAP, rtnl_link_ifmap
        4 | 5 | 10 | 13 | 15 | 19 | 28 | 29 => Pol::U32, // MTU LINK MASTER TXQLEN WEIGHT NET_NS_PID NET_NS_FD EXT_MASK
        33 | 16 | 17 | 39 => Pol::U8,                    // CARRIER OPERSTATE LINKMODE PROTO_DOWN
        18 | 22 | 24 | 25 | 26 | 43 | 52 | 55 => Pol::Nested, // LINKINFO VFINFO_LIST VF_PORTS PORT_SELF AF_SPEC XDP PROP_LIST PROTO_DOWN_REASON
        20 => Pol::Binary(255),                               // IFLA_IFALIAS, IFALIASZ-1
        30 | 31 | 32 | 40 | 35 | 44 | 27 | 47 | 48 | 50 | 51 | 58 | 64 => Pol::U32,
        41 | 63 => Pol::MinU32(GSO_MAX_SIZE_MIN), // GSO_MAX_SIZE, GSO_IPV4_MAX_SIZE
        34 | 36 => Pol::Binary(32),               // PHYS_PORT_ID, PHYS_SWITCH_ID
        37 | 46 => Pol::S32,                      // LINK_NETNSID, TARGET_NETNSID
        53 => Pol::Str(127),                      // IFLA_ALT_IFNAME, ALTIFNAMSIZ-1
        49 => Pol::MinS32(1),                     // IFLA_NEW_IFINDEX
        56 => Pol::NulStr(0),                     // IFLA_PARENT_DEV_NAME
        54 | 59 | 60 | 61 | 67 | 68 | 69 => Pol::Reject, // PERM_ADDRESS TSO_MAX_* ALLMULTI NETNS_IMMUTABLE HEADROOM TAILROOM
        _ => Pol::Unspec(0),
    }
}

/// `ifa_ipv4_policy` (net/ipv4/devinet.c).
const IFA_IPV4_POLICY: Policy = Policy {
    maxtype: 11, // IFA_MAX
    strict_start: 0,
    entry: |ty| match ty {
        1 | 2 | 4 | 8 | 9 => Pol::U32, // LOCAL ADDRESS BROADCAST FLAGS RT_PRIORITY
        3 => Pol::Str(15),             // IFA_LABEL
        6 => Pol::Unspec(16),          // IFA_CACHEINFO
        10 => Pol::S32,                // IFA_TARGET_NETNSID
        11 => Pol::U8,                 // IFA_PROTO
        _ => Pol::Unspec(0),
    },
};

/// `ifa_ipv6_policy` (net/ipv6/addrconf.c).
const IFA_IPV6_POLICY: Policy = Policy {
    maxtype: 11,
    strict_start: 0,
    entry: |ty| match ty {
        1 | 2 | 6 => Pol::Unspec(16), // ADDRESS LOCAL CACHEINFO
        8 | 9 => Pol::Unspec(4),      // FLAGS RT_PRIORITY
        10 => Pol::S32,
        11 => Pol::U8,
        _ => Pol::Unspec(0),
    },
};

/// `nda_policy` (net/core/neighbour.c).
const NDA_POLICY: Policy = Policy {
    maxtype: 17,      // NDA_MAX
    strict_start: 13, // NDA_NH_ID
    entry: |ty| match ty {
        1 | 2 => Pol::Binary(32),       // DST LLADDR
        3 => Pol::Unspec(16),           // CACHEINFO
        4 | 7 | 8 | 9 | 13 => Pol::U32, // PROBES VNI IFINDEX MASTER NH_ID
        5 | 6 => Pol::U16,              // VLAN PORT
        12 => Pol::U8,                  // PROTOCOL
        14 => Pol::Nested,              // FDB_EXT_ATTRS
        15 => Pol::MaskU32(0x5),        // FLAGS_EXT: NTF_EXT_MASK
        _ => Pol::Unspec(0),
    },
};

/// `rtm_ipv4_policy` (net/ipv4/fib_frontend.c).
pub const RTM_IPV4_POLICY: Policy = Policy {
    maxtype: 31,      // RTA_MAX
    strict_start: 30, // RTA_DPORT + 1
    entry: |ty| match ty {
        1..=7 | 11 | 15 | 16 | 25 | 30 => Pol::U32, // DST SRC IIF OIF GATEWAY PRIORITY PREFSRC FLOW TABLE MARK UID NH_ID
        8 | 22 => Pol::Nested,                      // METRICS ENCAP
        9 => Pol::Unspec(8),                        // MULTIPATH, rtnexthop
        21 | 28 | 29 => Pol::U16,                   // ENCAP_TYPE SPORT DPORT
        27 => Pol::U8,                              // IP_PROTO
        _ => Pol::Unspec(0),
    },
};

/// `rtm_nh_policy_dump` (net/ipv4/nexthop.c); maxtype is
/// `ARRAY_SIZE(rtm_nh_policy_dump) - 1` = NHA_OP_FLAGS.
const RTM_NH_POLICY_DUMP: Policy = Policy {
    maxtype: 14,
    strict_start: 0,
    entry: |ty| match ty {
        5 | 10 => Pol::U32,      // NHA_OIF NHA_MASTER
        9 | 11 => Pol::Flag,     // NHA_GROUPS NHA_FDB
        14 => Pol::MaskU32(0x3), // NHA_OP_FLAGS: NHA_OP_FLAGS_DUMP_ALL
        _ => Pol::Unspec(0),
    },
};

/// `rtm_tca_policy` (net/sched/sch_api.c).
const RTM_TCA_POLICY: Policy = Policy {
    maxtype: 16, // TCA_MAX
    strict_start: 0,
    entry: |ty| match ty {
        1 => Pol::Str(0),         // TCA_KIND
        5 => Pol::Binary(2),      // TCA_RATE, tc_estimator
        8 => Pol::Nested,         // TCA_STAB
        10 => Pol::Flag,          // TCA_DUMP_INVISIBLE
        11 | 13 | 14 => Pol::U32, // CHAIN INGRESS_BLOCK EGRESS_BLOCK
        _ => Pol::Unspec(0),
    },
};

/// `tcf_tfilter_dump_policy` (net/sched/cls_api.c).
const TCF_TFILTER_DUMP_POLICY: Policy = Policy {
    maxtype: 16,
    strict_start: 0,
    entry: |ty| match ty {
        11 => Pol::U32,           // TCA_CHAIN
        15 => Pol::Bitfield32(1), // TCA_DUMP_FLAGS: TCA_DUMP_FLAGS_TERSE
        _ => Pol::Unspec(0),
    },
};

/// `tcaa_policy` (net/sched/act_api.c).
const TCAA_POLICY: Policy = Policy {
    maxtype: 5, // TCA_ROOT_MAX
    strict_start: 0,
    entry: |ty| match ty {
        2 => Pol::Bitfield32(0x3), // TCA_ROOT_FLAGS: LARGE_DUMP_ON | TERSE_DUMP
        4 => Pol::U32,             // TCA_ROOT_TIME_DELTA
        _ => Pol::Unspec(0),
    },
};

// ── dumpit dispatch (rtnetlink_rcv_msg) ─────────────────────────────────

/// The dumpit functions Linux registers for the request types NARF answers.
#[derive(Clone, Copy)]
enum Dumpit {
    /// `rtnl_dump_ifinfo`.
    Link,
    /// `inet6_dump_ifinfo`.
    LinkInet6,
    /// `rtnl_bridge_getlink`.
    LinkBridge,
    /// `ipmr_rtm_dumplink`.
    LinkIpmr,
    /// `rtnl_dump_all` over PF_INET, PF_INET6.
    AddrAll,
    /// `inet_dump_ifaddr`.
    Addr4,
    /// `inet6_dump_ifaddr`.
    Addr6,
    /// `rtnl_dump_all` over PF_INET, PF_INET6, IPMR, IP6MR.
    RouteAll,
    /// `inet_dump_fib`.
    Route4,
    /// `inet6_dump_fib`.
    Route6,
    /// `ipmr_rtm_dumproute`.
    Ipmr,
    /// `ip6mr_rtm_dumproute`.
    Ip6mr,
    /// `neigh_dump_info`.
    Neigh,
    /// `rtnl_fdb_dump`.
    Fdb,
    /// `fib_nl_dumprule`.
    Rule,
    /// `tc_dump_qdisc`.
    Qdisc,
    /// `tc_dump_tclass`.
    Tclass,
    /// `tc_dump_tfilter`.
    Tfilter,
    /// `tc_dump_action`.
    Action,
    /// `ip6addrlbl_dump`.
    AddrLabel,
    /// `rtnl_mdb_dump`.
    Mdb,
    /// `rtm_dump_nexthop`.
    Nexthop,
}

/// The `rtnl_msg_handlers[family][type].dumpit` table for the families
/// registered by core, IPv4, IPv6, IPv4/IPv6 multicast routing, nexthop,
/// and the traffic-control core. Modules NARF does not model (MPLS, CAN gw,
/// Phonet, MCTP) are treated as not loaded.
fn registered(msg_type: u16, family: u8) -> Option<Dumpit> {
    Some(match (msg_type, family) {
        (RTM_GETLINK, 0) => Dumpit::Link,
        (RTM_GETLINK, AF_INET6) => Dumpit::LinkInet6,
        (RTM_GETLINK, AF_BRIDGE) => Dumpit::LinkBridge,
        (RTM_GETLINK, RTNL_FAMILY_IPMR) => Dumpit::LinkIpmr,
        (RTM_GETADDR, 0) => Dumpit::AddrAll,
        (RTM_GETADDR, AF_INET) => Dumpit::Addr4,
        (RTM_GETADDR, AF_INET6) => Dumpit::Addr6,
        (RTM_GETROUTE, 0) => Dumpit::RouteAll,
        (RTM_GETROUTE, AF_INET) => Dumpit::Route4,
        (RTM_GETROUTE, AF_INET6) => Dumpit::Route6,
        (RTM_GETROUTE, RTNL_FAMILY_IPMR) => Dumpit::Ipmr,
        (RTM_GETROUTE, RTNL_FAMILY_IP6MR) => Dumpit::Ip6mr,
        (RTM_GETNEIGH, 0) => Dumpit::Neigh,
        (RTM_GETNEIGH, AF_BRIDGE) => Dumpit::Fdb,
        (RTM_GETRULE, 0) => Dumpit::Rule,
        (RTM_GETQDISC, 0) => Dumpit::Qdisc,
        (RTM_GETTCLASS, 0) => Dumpit::Tclass,
        (RTM_GETTFILTER, 0) => Dumpit::Tfilter,
        (RTM_GETACTION, 0) => Dumpit::Action,
        (RTM_GETADDRLABEL, AF_INET6) => Dumpit::AddrLabel,
        (RTM_GETMDB, AF_BRIDGE) => Dumpit::Mdb,
        (RTM_GETNEXTHOP, 0 | AF_INET | AF_INET6) => Dumpit::Nexthop,
        _ => return None,
    })
}

/// `rtnetlink_rcv_msg`: `rtnl_get_link(family, type)`, and on a miss (or a
/// family beyond RTNL_FAMILY_MAX) `rtnl_get_link(PF_UNSPEC, type)`.
fn lookup(msg_type: u16, family: u8) -> Option<Dumpit> {
    registered(msg_type, family).or_else(|| registered(msg_type, 0))
}

/// True when rtnetlink registers any dumpit for this message type.
pub fn is_dump_type(msg_type: u16) -> bool {
    matches!(
        msg_type,
        RTM_GETLINK
            | RTM_GETADDR
            | RTM_GETROUTE
            | RTM_GETNEIGH
            | RTM_GETRULE
            | RTM_GETQDISC
            | RTM_GETTCLASS
            | RTM_GETTFILTER
            | RTM_GETACTION
            | RTM_GETADDRLABEL
            | RTM_GETMDB
            | RTM_GETNEXTHOP
    )
}

/// State shared by one dump: the request, `cb->strict_check`,
/// `cb->answer_flags`, `cb->extack`, and the messages written so far.
struct Dump<'a> {
    req: &'a [u8],
    family: u8,
    seq: u32,
    strict: bool,
    net_ns_id: u64,
    answer_flags: u16,
    extack: ExtAck,
    out: Vec<Vec<u8>>,
    links: Vec<LinkInfo>,
}

impl Dump<'_> {
    fn push(&mut self, mut message: Vec<u8>, extra_flags: u16) {
        if extra_flags != 0 && message.len() >= NLMSG_HDRLEN {
            let flags = u16::from_ne_bytes([message[6], message[7]]) | extra_flags;
            message[6..8].copy_from_slice(&flags.to_ne_bytes());
        }
        self.out.push(message);
    }

    /// `dev_get_by_index` in the request's namespace.
    fn dev_exists(&self, ifindex: u32) -> bool {
        self.links.iter().any(|link| link.ifindex == ifindex)
    }
}

/// Build the complete reply for a dump request: `NLMSG_ERROR(-EOPNOTSUPP)`
/// when no dumpit is registered, otherwise the dump's messages terminated by
/// `NLMSG_DONE` carrying the dumpit's return value.
pub fn run(net_ns_id: u64, req: &[u8], strict: bool, ext_ack: bool) -> Vec<Vec<u8>> {
    let Some(hdr) = parse_hdr(req) else {
        return Vec::new();
    };
    let family = byte(req, NLMSG_HDRLEN);
    let Some(dumpit) = lookup(hdr.msg_type, family) else {
        return vec![build_error(EOPNOTSUPP, hdr.seq, 0, req)];
    };
    let (links, _) = enumerate_in(net_ns_id);
    let mut dump = Dump {
        req,
        family,
        seq: hdr.seq,
        strict,
        net_ns_id,
        answer_flags: 0,
        extack: ExtAck::default(),
        out: Vec::new(),
        links,
    };
    let result = match dumpit {
        Dumpit::Link => dump_ifinfo(&mut dump),
        Dumpit::LinkInet6 => dump_inet6_ifinfo(&mut dump),
        Dumpit::LinkBridge => dump_bridge_getlink(&mut dump),
        Dumpit::LinkIpmr => dump_ipmr_link(&mut dump),
        Dumpit::AddrAll => dump_addr4(&mut dump).and_then(|()| dump_addr6(&mut dump)),
        Dumpit::Addr4 => dump_addr4(&mut dump),
        Dumpit::Addr6 => dump_addr6(&mut dump),
        Dumpit::RouteAll => dump_fib4(&mut dump)
            .and_then(|()| dump_fib6(&mut dump))
            .and_then(|()| dump_mr(&mut dump, RTNL_FAMILY_IPMR))
            .and_then(|()| dump_mr(&mut dump, RTNL_FAMILY_IP6MR)),
        Dumpit::Route4 => dump_fib4(&mut dump),
        Dumpit::Route6 => dump_fib6(&mut dump),
        Dumpit::Ipmr => dump_mr(&mut dump, RTNL_FAMILY_IPMR),
        Dumpit::Ip6mr => dump_mr(&mut dump, RTNL_FAMILY_IP6MR),
        Dumpit::Neigh => dump_neigh(&mut dump),
        // LINUX-GAP: rtnl_fdb_dump (valid_fdb_dump_strict / legacy) is not
        // implemented; NARF has no bridge FDB and does not synthesise the
        // per-device unicast/multicast entries ndo_dflt_fdb_dump reports.
        Dumpit::Fdb => Ok(()),
        Dumpit::Rule => dump_rule(&mut dump),
        Dumpit::Qdisc => dump_qdisc(&mut dump),
        Dumpit::Tclass => Ok(()), // tc_dump_tclass: no classful qdiscs exist
        Dumpit::Tfilter => dump_tfilter(&mut dump),
        Dumpit::Action => dump_action(&mut dump),
        Dumpit::AddrLabel => dump_addrlabel(&mut dump),
        Dumpit::Mdb => dump_mdb(&mut dump),
        Dumpit::Nexthop => dump_nexthop(&mut dump),
    };
    let errno = match result {
        Ok(()) => 0,
        Err(errno) => -errno,
    };
    let done = build_dump_done(
        dump.seq,
        errno,
        dump.answer_flags,
        ext_ack.then_some(&dump.extack),
    );
    dump.out.push(done);
    dump.out
}

/// `netlink_dump_done`: NLMSG_DONE whose payload is the dump's return value,
/// flagged `NLM_F_MULTI | cb->answer_flags`, plus `netlink_ack_tlv_fill`
/// TLVs when the socket enabled `NETLINK_EXT_ACK`.
fn build_dump_done(seq: u32, errno: i32, answer_flags: u16, extack: Option<&ExtAck>) -> Vec<u8> {
    let mut body = errno.to_ne_bytes().to_vec();
    let mut flags = NLM_F_MULTI | answer_flags;
    if let Some(extack) = extack {
        let mut tlvs = Vec::new();
        if let Some(msg) = extack.msg {
            let mut text = msg.as_bytes().to_vec();
            text.push(0);
            push_rtattr(&mut tlvs, NLMSGERR_ATTR_MSG, &text);
        }
        // Attribute-pointing TLVs are reported only for an error.
        if errno != 0 {
            if let Some(offset) = extack.bad_attr {
                push_rtattr(
                    &mut tlvs,
                    NLMSGERR_ATTR_OFFS,
                    &(offset as u32).to_ne_bytes(),
                );
            }
        }
        if !tlvs.is_empty() {
            flags |= NLM_F_ACK_TLVS;
            body.extend_from_slice(&tlvs);
        }
    }
    frame_message(NLMSG_DONE, flags, seq, 0, &body)
}

/// `rtnl_get_net_ns_capable`: NARF assigns no peer netns ids
/// (RTM_NEWNSID is not implemented), so `get_net_ns_by_id` never resolves one.
fn target_netns(_netnsid: i32) -> Result<(), i32> {
    Err(EINVAL)
}

// ── RTM_GETLINK ─────────────────────────────────────────────────────────

const IFINFOMSG_LEN: usize = 16;
const IFLA_MASTER: usize = 10;
const IFLA_LINKINFO: usize = 18;
const IFLA_EXT_MASK: usize = 29;
const IFLA_TARGET_NETNSID: usize = 46;

/// Nonzero `__ifi_pad`, `ifi_type`, `ifi_flags`, or `ifi_change`.
fn ifinfo_header_dirty(req: &[u8]) -> bool {
    byte(req, NLMSG_HDRLEN + 1) != 0
        || read_u16(req, NLMSG_HDRLEN + 2) != 0
        || read_u32(req, NLMSG_HDRLEN + 8) != 0
        || read_u32(req, NLMSG_HDRLEN + 12) != 0
}

fn ifinfo_index(req: &[u8]) -> u32 {
    read_u32(req, NLMSG_HDRLEN + 4)
}

/// `rtnl_valid_dump_ifinfo_req`.
fn valid_dump_ifinfo_req(d: &mut Dump<'_>) -> Result<Tb, i32> {
    if d.strict {
        if !has_payload(d.req, IFINFOMSG_LEN) {
            d.extack.set("Invalid header for link dump");
            return Err(EINVAL);
        }
        if ifinfo_header_dirty(d.req) {
            d.extack
                .set("Invalid values in header for link dump request");
            return Err(EINVAL);
        }
        if ifinfo_index(d.req) != 0 {
            d.extack
                .set("Filter by device index not supported for link dumps");
            return Err(EINVAL);
        }
        return nlmsg_parse(
            d.req,
            IFINFOMSG_LEN,
            &IFLA_POLICY,
            NL_VALIDATE_DEPRECATED_STRICT,
            &mut d.extack,
        );
    }
    // The pre-v3.9 iproute2 hack: a request shorter than ifinfomsg carries a
    // struct rtgenmsg header instead.
    let hdrlen = if d.req.len() - NLMSG_HDRLEN < IFINFOMSG_LEN {
        1
    } else {
        IFINFOMSG_LEN
    };
    nlmsg_parse(
        d.req,
        hdrlen,
        &IFLA_POLICY,
        NL_VALIDATE_LIBERAL,
        &mut d.extack,
    )
}

/// `rtnl_dump_ifinfo`.
fn dump_ifinfo(d: &mut Dump<'_>) -> Result<(), i32> {
    let mut flags = 0;
    let mut master_idx = 0i32;
    match valid_dump_ifinfo_req(d) {
        Err(err) if d.strict => return Err(err),
        Err(_) => {} // non-strict: `goto walk_entries`
        Ok(tb) => {
            for (i, attr) in tb.iter().enumerate() {
                let Some(attr) = *attr else { continue };
                match i {
                    IFLA_TARGET_NETNSID => {
                        if let Err(err) = target_netns(attr_u32(d.req, attr) as i32) {
                            d.extack.set("Invalid target network namespace id");
                            return Err(err);
                        }
                    }
                    IFLA_EXT_MASK => {}
                    IFLA_MASTER => master_idx = attr_u32(d.req, attr) as i32,
                    // `linkinfo_to_kind_ops`: NARF registers no rtnl_link_ops
                    // kinds, so the lookup never yields a kind filter.
                    IFLA_LINKINFO => {}
                    _ => {
                        if d.strict {
                            d.extack.set("Unsupported attribute in link dump request");
                            return Err(EINVAL);
                        }
                    }
                }
            }
            if master_idx != 0 {
                flags |= NLM_F_DUMP_FILTERED;
            }
        }
    }
    let links = core::mem::take(&mut d.links);
    for link in &links {
        // `link_master_filtered`: no NARF device has a master, so only the
        // "no master" selector (-1) matches.
        if master_idx != 0 && master_idx != -1 {
            continue;
        }
        d.push(build_newlink(link, d.seq, 0), flags);
    }
    d.links = links;
    Ok(())
}

/// `inet6_valid_dump_ifinfo`, the strict-only validator of
/// `inet6_dump_ifinfo`.
fn dump_inet6_ifinfo(d: &mut Dump<'_>) -> Result<(), i32> {
    if d.strict {
        if !has_payload(d.req, IFINFOMSG_LEN) {
            d.extack.set("ipv6: Invalid header for link dump request");
            return Err(EINVAL);
        }
        if has_attrs(d.req, IFINFOMSG_LEN) {
            d.extack.set("ipv6: Invalid data after header");
            return Err(EINVAL);
        }
        if ifinfo_header_dirty(d.req) || ifinfo_index(d.req) != 0 {
            d.extack
                .set("ipv6: Invalid values in header for dump request");
            return Err(EINVAL);
        }
    }
    // LINUX-GAP: inet6_fill_ifinfo emits AF_INET6 RTM_NEWLINK messages with
    // IFLA_PROTINFO (IFLA_INET6_*); NARF emits its AF_UNSPEC link shape.
    let links = core::mem::take(&mut d.links);
    for link in &links {
        d.push(build_newlink(link, d.seq, 0), 0);
    }
    d.links = links;
    Ok(())
}

/// `rtnl_bridge_getlink` / `valid_bridge_getlink_req`. No NARF device is a
/// bridge port or implements ndo_bridge_getlink, so a valid request is empty.
fn dump_bridge_getlink(d: &mut Dump<'_>) -> Result<(), i32> {
    let parsed = if d.strict {
        if !has_payload(d.req, IFINFOMSG_LEN) {
            d.extack.set("Invalid header for bridge link dump");
            return Err(EINVAL);
        }
        if ifinfo_header_dirty(d.req) || ifinfo_index(d.req) != 0 {
            d.extack
                .set("Invalid values in header for bridge link dump request");
            return Err(EINVAL);
        }
        nlmsg_parse(
            d.req,
            IFINFOMSG_LEN,
            &IFLA_POLICY,
            NL_VALIDATE_DEPRECATED_STRICT,
            &mut d.extack,
        )
    } else {
        nlmsg_parse(
            d.req,
            IFINFOMSG_LEN,
            &IFLA_POLICY,
            NL_VALIDATE_LIBERAL,
            &mut d.extack,
        )
    };
    match parsed {
        Err(err) if d.strict => return Err(err),
        Err(_) => {}
        Ok(tb) => {
            let unsupported = tb
                .iter()
                .enumerate()
                .any(|(i, attr)| attr.is_some() && i != IFLA_EXT_MASK);
            if unsupported && d.strict {
                d.extack
                    .set("Unsupported attribute in bridge link dump request");
                return Err(EINVAL);
            }
        }
    }
    Ok(())
}

/// `ipmr_rtm_dumplink` / `ipmr_valid_dumplink`.
fn dump_ipmr_link(d: &mut Dump<'_>) -> Result<(), i32> {
    if d.strict {
        if !has_payload(d.req, IFINFOMSG_LEN) {
            d.extack.set("ipv4: Invalid header for ipmr link dump");
            return Err(EINVAL);
        }
        if has_attrs(d.req, IFINFOMSG_LEN) {
            d.extack.set("Invalid data after header in ipmr link dump");
            return Err(EINVAL);
        }
        if ifinfo_header_dirty(d.req) || ifinfo_index(d.req) != 0 {
            d.extack
                .set("Invalid values in header for ipmr link dump request");
            return Err(EINVAL);
        }
    }
    // LINUX-GAP: Linux emits one RTNL_FAMILY_IPMR RTM_NEWLINK per multicast
    // routing table (IFLA_IPMR_* vif state); NARF has no multicast routing.
    Ok(())
}

// ── RTM_GETADDR ─────────────────────────────────────────────────────────

const IFADDRMSG_LEN: usize = 8;
const IFA_TARGET_NETNSID: usize = 10;

/// `inet_valid_dump_ifaddr_req` / `inet6_valid_dump_ifaddr_req`: returns the
/// `ifa_index` filter. `prefix` is the extack prefix the function uses.
fn valid_dump_ifaddr_req(d: &mut Dump<'_>, v6: bool) -> Result<u32, i32> {
    let (invalid_header, invalid_values, bad_netns, unsupported, policy) = if v6 {
        (
            "ipv6: Invalid header for address dump request",
            "ipv6: Invalid values in header for address dump request",
            "ipv6: Invalid target network namespace id",
            "ipv6: Unsupported attribute in dump request",
            &IFA_IPV6_POLICY,
        )
    } else {
        (
            "ipv4: Invalid header for address dump request",
            "ipv4: Invalid values in header for address dump request",
            "ipv4: Invalid target network namespace id",
            "ipv4: Unsupported attribute in dump request",
            &IFA_IPV4_POLICY,
        )
    };
    if !has_payload(d.req, IFADDRMSG_LEN) {
        d.extack.set(invalid_header);
        return Err(EINVAL);
    }
    // ifa_prefixlen, ifa_flags, ifa_scope.
    if byte(d.req, NLMSG_HDRLEN + 1) != 0
        || byte(d.req, NLMSG_HDRLEN + 2) != 0
        || byte(d.req, NLMSG_HDRLEN + 3) != 0
    {
        d.extack.set(invalid_values);
        return Err(EINVAL);
    }
    let ifindex = read_u32(d.req, NLMSG_HDRLEN + 4);
    if ifindex != 0 {
        d.answer_flags |= NLM_F_DUMP_FILTERED;
    }
    let tb = nlmsg_parse(
        d.req,
        IFADDRMSG_LEN,
        policy,
        NL_VALIDATE_DEPRECATED_STRICT,
        &mut d.extack,
    )?;
    for (i, attr) in tb.iter().enumerate() {
        let Some(attr) = *attr else { continue };
        if i == IFA_TARGET_NETNSID {
            if let Err(err) = target_netns(attr_u32(d.req, attr) as i32) {
                d.extack.set(bad_netns);
                return Err(err);
            }
        } else {
            d.extack.set(unsupported);
            return Err(EINVAL);
        }
    }
    Ok(ifindex)
}

/// `inet_dump_addr(RTM_NEWADDR)`. Only a strict request filters by
/// `ifa_index`; a legacy request's header is ignored.
fn dump_addr4(d: &mut Dump<'_>) -> Result<(), i32> {
    let mut ifindex = 0;
    let mut flags = 0;
    if d.strict {
        ifindex = valid_dump_ifaddr_req(d, false)?;
        if ifindex != 0 {
            flags = NLM_F_DUMP_FILTERED;
            if !d.dev_exists(ifindex) {
                return Err(ENODEV);
            }
        }
    }
    let (_links, addrs) = enumerate_in(d.net_ns_id);
    for addr in &addrs {
        if ifindex == 0 || addr.ifindex == ifindex {
            d.push(build_newaddr(addr, d.seq, 0), flags);
        }
    }
    Ok(())
}

/// `inet6_dump_addr(UNICAST_ADDR)`.
fn dump_addr6(d: &mut Dump<'_>) -> Result<(), i32> {
    let mut ifindex = 0;
    let mut flags = 0;
    if d.strict {
        ifindex = valid_dump_ifaddr_req(d, true)?;
        if ifindex != 0 {
            flags = NLM_F_DUMP_FILTERED;
            if !d.dev_exists(ifindex) {
                return Err(ENODEV);
            }
        }
    }
    if ifindex == 0 || ifindex == 1 {
        d.push(
            build_newaddr_v6(&builtin_loopback_ipv6(), 1, d.seq, 0),
            flags,
        );
    }
    for addr in crate::ipv6::addrs::list_all() {
        if addr.state == crate::ipv6::addrs::AddrState::Invalid {
            continue;
        }
        if let Some(addr_ifindex) = ifindex_for_name(&addr.iface) {
            if ifindex == 0 || ifindex == addr_ifindex {
                d.push(build_newaddr_v6(&addr, addr_ifindex, d.seq, 0), flags);
            }
        }
    }
    Ok(())
}

// ── RTM_GETROUTE ────────────────────────────────────────────────────────

const RTMSG_LEN: usize = 12;
const RTA_OIF: usize = 4;
const RTA_TABLE: usize = 15;

/// `struct fib_dump_filter`.
#[derive(Clone, Copy)]
struct FibDumpFilter {
    table_id: u32,
    dev: u32,
    protocol: u8,
    rt_type: u8,
    flags: u32,
    filter_set: bool,
    dump_routes: bool,
    dump_exceptions: bool,
}

impl FibDumpFilter {
    const fn new() -> Self {
        Self {
            table_id: 0,
            dev: 0,
            protocol: 0,
            rt_type: 0,
            flags: 0,
            filter_set: false,
            dump_routes: true,
            dump_exceptions: true,
        }
    }

    /// The entry flags `fn_trie_dump_leaf` / `rt6_dump_route` add.
    fn entry_flags(&self) -> u16 {
        if self.filter_set || !self.dump_exceptions || !self.dump_routes {
            NLM_F_DUMP_FILTERED
        } else {
            0
        }
    }

    fn matches(&self, protocol: u8, rt_type: u8, oif: u32) -> bool {
        !self.filter_set
            || !((self.rt_type != 0 && rt_type != self.rt_type)
                || (self.protocol != 0 && protocol != self.protocol)
                || (self.dev != 0 && oif != self.dev))
    }
}

/// `ip_valid_fib_dump_req` (net/ipv4/fib_frontend.c), shared by the IPv4,
/// IPv6, and multicast FIB dumps.
fn valid_fib_dump_req(d: &mut Dump<'_>, filter: &mut FibDumpFilter) -> Result<(), i32> {
    let req = d.req;
    if !has_payload(req, RTMSG_LEN) {
        d.extack.set("Invalid header for FIB dump request");
        return Err(EINVAL);
    }
    // rtm_dst_len, rtm_src_len, rtm_tos, rtm_scope.
    if byte(req, NLMSG_HDRLEN + 1) != 0
        || byte(req, NLMSG_HDRLEN + 2) != 0
        || byte(req, NLMSG_HDRLEN + 3) != 0
        || byte(req, NLMSG_HDRLEN + 6) != 0
    {
        d.extack
            .set("Invalid values in header for FIB dump request");
        return Err(EINVAL);
    }
    let rtm_flags = read_u32(req, NLMSG_HDRLEN + 8);
    if rtm_flags & !(RTM_F_CLONED | RTM_F_PREFIX) != 0 {
        d.extack.set("Invalid flags for FIB dump request");
        return Err(EINVAL);
    }
    if rtm_flags & RTM_F_CLONED != 0 {
        filter.dump_routes = false;
    } else {
        filter.dump_exceptions = false;
    }
    filter.flags = rtm_flags;
    filter.protocol = byte(req, NLMSG_HDRLEN + 5);
    filter.rt_type = byte(req, NLMSG_HDRLEN + 7);
    filter.table_id = byte(req, NLMSG_HDRLEN + 4) as u32;

    let tb = nlmsg_parse(
        req,
        RTMSG_LEN,
        &RTM_IPV4_POLICY,
        NL_VALIDATE_DEPRECATED_STRICT,
        &mut d.extack,
    )?;
    for (i, attr) in tb.iter().enumerate() {
        let Some(attr) = *attr else { continue };
        match i {
            RTA_TABLE => filter.table_id = attr_u32(req, attr),
            RTA_OIF => {
                let ifindex = attr_u32(req, attr);
                if !d.dev_exists(ifindex) {
                    return Err(ENODEV);
                }
                filter.dev = ifindex;
            }
            _ => {
                d.extack.set("Unsupported attribute in dump request");
                return Err(EINVAL);
            }
        }
    }
    if filter.flags != 0
        || filter.protocol != 0
        || filter.rt_type != 0
        || filter.table_id != 0
        || filter.dev != 0
    {
        filter.filter_set = true;
        d.answer_flags = NLM_F_DUMP_FILTERED;
    }
    Ok(())
}

/// The legacy (non-strict) `rtm_flags` a FIB dump still honours.
fn legacy_rtm_flags(req: &[u8]) -> u32 {
    if has_payload(req, RTMSG_LEN) {
        read_u32(req, NLMSG_HDRLEN + 8)
    } else {
        0
    }
}

/// The IPv4 routes NARF exposes, including the synthetic loopback route.
fn ipv4_routes(net_ns_id: u64) -> Vec<crate::route::Route> {
    let mut routes = crate::route::route_list_in(net_ns_id);
    // Link/address dumps always expose loopback. Mirror that invariant in
    // route dumps even during early boot before net init installs the
    // canonical loopback FIB entry.
    if !routes
        .iter()
        .any(|r| r.iface == "lo" && r.dst.addr.0 == [127, 0, 0, 0] && r.dst.prefix_len == 8)
    {
        routes.push(crate::route::Route {
            net_ns_id,
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
    routes
}

/// `inet_dump_fib` (net/ipv4/fib_frontend.c).
fn dump_fib4(d: &mut Dump<'_>) -> Result<(), i32> {
    let mut filter = FibDumpFilter::new();
    if d.strict {
        valid_fib_dump_req(d, &mut filter)?;
    } else {
        filter.flags = legacy_rtm_flags(d.req) & (RTM_F_PREFIX | RTM_F_CLONED);
    }
    // IPv4 does not use the prefix flag.
    if filter.flags & RTM_F_PREFIX != 0 {
        return Ok(());
    }
    let routes = ipv4_routes(d.net_ns_id);
    if filter.table_id != 0 {
        // `fib_get_table`: local and main always exist (the local table's
        // creation creates main); other tables exist once a route uses them.
        // LINUX-GAP: Linux keeps an emptied table until the netns exits.
        let exists = filter.table_id == RT_TABLE_LOCAL
            || filter.table_id == RT_TABLE_MAIN
            || routes.iter().any(|r| r.table as u32 == filter.table_id);
        if !exists {
            if d.family != AF_INET {
                return Ok(());
            }
            d.extack.set("ipv4: FIB table does not exist");
            return Err(ENOENT);
        }
    }
    if !filter.dump_routes {
        // Only cached exceptions (RTM_F_CLONED); NARF keeps no PMTU/redirect
        // exception routes.
        return Ok(());
    }
    let flags = filter.entry_flags();
    let links = core::mem::take(&mut d.links);
    for route in &routes {
        if filter.table_id != 0 && route.table as u32 != filter.table_id {
            continue;
        }
        let Some(link) = links.iter().find(|link| link.name == route.iface) else {
            continue;
        };
        let rt_type = if route.table == crate::route::TABLE_LOCAL {
            RTN_LOCAL
        } else {
            RTN_UNICAST
        };
        if !filter.matches(RTPROT_KERNEL, rt_type, link.ifindex) {
            continue;
        }
        d.push(build_newroute(route, link.ifindex, d.seq, 0), flags);
    }
    d.links = links;
    Ok(())
}

/// `inet6_dump_fib` (net/ipv6/ip6_fib.c).
fn dump_fib6(d: &mut Dump<'_>) -> Result<(), i32> {
    let mut filter = FibDumpFilter::new();
    if d.strict {
        valid_fib_dump_req(d, &mut filter)?;
    } else if legacy_rtm_flags(d.req) & RTM_F_PREFIX != 0 {
        filter.flags = RTM_F_PREFIX;
    }
    if filter.table_id != 0 {
        // `fib6_get_table`: main and local are created at netns init; NARF
        // installs every IPv6 route in main.
        if filter.table_id != RT_TABLE_MAIN && filter.table_id != RT_TABLE_LOCAL {
            if d.family != AF_INET6 {
                return Ok(());
            }
            d.extack.set("ipv6: FIB table does not exist");
            return Err(ENOENT);
        }
        if filter.table_id != RT_TABLE_MAIN {
            return Ok(());
        }
    }
    // `rt6_dump_route`: RTM_F_PREFIX keeps only RTF_PREFIX_RT routes and
    // RTM_F_CLONED only exceptions; NARF tracks neither.
    if filter.flags & RTM_F_PREFIX != 0 || !filter.dump_routes {
        return Ok(());
    }
    let flags = filter.entry_flags();
    let links = core::mem::take(&mut d.links);
    for route in crate::ipv6::route::list_all() {
        let Some(link) = links.iter().find(|link| link.name == route.iface) else {
            continue;
        };
        if !filter.matches(RTPROT_KERNEL, RTN_UNICAST, link.ifindex) {
            continue;
        }
        d.push(build_newroute_v6(&route, link.ifindex, d.seq, 0), flags);
    }
    d.links = links;
    Ok(())
}

/// `ipmr_rtm_dumproute` / `ip6mr_rtm_dumproute`: the default multicast
/// routing table (RT_TABLE_DEFAULT) exists and holds no MFC entries.
fn dump_mr(d: &mut Dump<'_>, family: u8) -> Result<(), i32> {
    let mut filter = FibDumpFilter::new();
    if d.strict {
        valid_fib_dump_req(d, &mut filter)?;
    }
    if filter.table_id != 0 && filter.table_id != RT_TABLE_DEFAULT {
        if d.family != family {
            return Ok(());
        }
        d.extack.set(if family == RTNL_FAMILY_IPMR {
            "ipv4: MR table does not exist"
        } else {
            "ipv6: MR table does not exist"
        });
        return Err(ENOENT);
    }
    Ok(())
}

// ── RTM_GETNEIGH ────────────────────────────────────────────────────────

const NDMSG_LEN: usize = 12;
const NDA_IFINDEX: usize = 8;
const NDA_MASTER: usize = 9;

/// `neigh_valid_dump_req`: returns (dev_idx, master_idx).
fn valid_neigh_dump_req(d: &mut Dump<'_>) -> Result<(i32, i32), i32> {
    let tb = if d.strict {
        if !has_payload(d.req, NDMSG_LEN) {
            d.extack.set("Invalid header for neighbor dump request");
            return Err(EINVAL);
        }
        // ndm_pad1, ndm_pad2, ndm_ifindex, ndm_state, ndm_type.
        if byte(d.req, NLMSG_HDRLEN + 1) != 0
            || read_u16(d.req, NLMSG_HDRLEN + 2) != 0
            || read_u32(d.req, NLMSG_HDRLEN + 4) != 0
            || read_u16(d.req, NLMSG_HDRLEN + 8) != 0
            || byte(d.req, NLMSG_HDRLEN + 11) != 0
        {
            d.extack
                .set("Invalid values in header for neighbor dump request");
            return Err(EINVAL);
        }
        if byte(d.req, NLMSG_HDRLEN + 10) & !NTF_PROXY != 0 {
            d.extack
                .set("Invalid flags in header for neighbor dump request");
            return Err(EINVAL);
        }
        nlmsg_parse(
            d.req,
            NDMSG_LEN,
            &NDA_POLICY,
            NL_VALIDATE_DEPRECATED_STRICT,
            &mut d.extack,
        )?
    } else {
        nlmsg_parse(
            d.req,
            NDMSG_LEN,
            &NDA_POLICY,
            NL_VALIDATE_LIBERAL,
            &mut d.extack,
        )?
    };
    let (mut dev_idx, mut master_idx) = (0, 0);
    for (i, attr) in tb.iter().enumerate() {
        let Some(attr) = *attr else { continue };
        match i {
            NDA_IFINDEX => dev_idx = attr_u32(d.req, attr) as i32,
            NDA_MASTER => master_idx = attr_u32(d.req, attr) as i32,
            _ => {
                if d.strict {
                    d.extack
                        .set("Unsupported attribute in neighbor dump request");
                    return Err(EINVAL);
                }
            }
        }
    }
    Ok((dev_idx, master_idx))
}

/// `neigh_dump_info` (net/core/neighbour.c).
fn dump_neigh(d: &mut Dump<'_>) -> Result<(), i32> {
    let proxy = has_payload(d.req, NDMSG_LEN) && byte(d.req, NLMSG_HDRLEN + 10) == NTF_PROXY;
    let (dev_idx, master_idx) = match valid_neigh_dump_req(d) {
        Ok(filter) => filter,
        Err(err) if d.strict => return Err(err),
        Err(_) => (0, 0),
    };
    // `pneigh_dump_table`: NARF keeps no proxy neighbour entries.
    if proxy {
        return Ok(());
    }
    let flags = if dev_idx != 0 || master_idx != 0 {
        NLM_F_DUMP_FILTERED
    } else {
        0
    };
    // `neigh_ifindex_filtered` + `neigh_master_filtered` (no NARF device has
    // a master, so only the "no master" selector -1 matches).
    let keep = |ifindex: u32| {
        (dev_idx == 0 || ifindex as i32 == dev_idx) && (master_idx == 0 || master_idx == -1)
    };
    let family = d.family;
    let links = core::mem::take(&mut d.links);
    if family == 0 || family == AF_INET {
        for (iface, entry) in crate::arp::snapshot() {
            let Some(link) = links.iter().find(|link| link.name == iface) else {
                continue;
            };
            if !keep(link.ifindex) {
                continue;
            }
            let message = build_newneigh(
                &NeighInfo {
                    family: AF_INET,
                    dst: &entry.ip,
                    mac: Some(entry.mac),
                    ifindex: link.ifindex,
                    state: NUD_REACHABLE,
                    flags: 0,
                },
                d.seq,
                0,
            );
            d.push(message, flags);
        }
    }
    if family == 0 || family == AF_INET6 {
        for entry in crate::ipv6::ndp::neigh_list_in(d.net_ns_id) {
            let Some(link) = links.iter().find(|link| link.name == entry.iface) else {
                continue;
            };
            if !keep(link.ifindex) {
                continue;
            }
            let state = match entry.state {
                crate::ipv6::ndp::NeighState::Incomplete => NUD_INCOMPLETE,
                crate::ipv6::ndp::NeighState::Reachable => NUD_REACHABLE,
                crate::ipv6::ndp::NeighState::Stale => NUD_STALE,
                crate::ipv6::ndp::NeighState::Delay => NUD_DELAY,
                crate::ipv6::ndp::NeighState::Probe => NUD_PROBE,
            };
            let message = build_newneigh(
                &NeighInfo {
                    family: AF_INET6,
                    dst: &entry.ip,
                    mac: entry.mac,
                    ifindex: link.ifindex,
                    state,
                    flags: if entry.is_router { NTF_ROUTER } else { 0 },
                },
                d.seq,
                0,
            );
            d.push(message, flags);
        }
    }
    d.links = links;
    Ok(())
}

// ── RTM_GETRULE ─────────────────────────────────────────────────────────

const FIB_RULE_HDR_LEN: usize = 12;

/// `fib_nl_dumprule` / `fib_valid_dumprule_req` (net/core/fib_rules.c).
fn dump_rule(d: &mut Dump<'_>) -> Result<(), i32> {
    if d.strict {
        if !has_payload(d.req, FIB_RULE_HDR_LEN) {
            d.extack.set("Invalid header for fib rule dump request");
            return Err(EINVAL);
        }
        // dst_len, src_len, tos, table, res1, res2, action, flags.
        if d.req[NLMSG_HDRLEN + 1..NLMSG_HDRLEN + 8]
            .iter()
            .any(|&b| b != 0)
            || read_u32(d.req, NLMSG_HDRLEN + 8) != 0
        {
            d.extack
                .set("Invalid values in header for fib rule dump request");
            return Err(EINVAL);
        }
        if has_attrs(d.req, FIB_RULE_HDR_LEN) {
            d.extack
                .set("Invalid data after header in fib rule dump request");
            return Err(EINVAL);
        }
    }
    match d.family {
        0 | AF_INET => {
            // Linux installs these IPv4 policy-routing rules by default:
            // priority 0 → local, 32766 → main, 32767 → default.
            for (table, priority) in [
                (crate::route::TABLE_LOCAL, 0),
                (crate::route::TABLE_MAIN, 32_766),
                (crate::route::TABLE_DEFAULT, 32_767),
            ] {
                d.push(build_newrule(AF_INET, table, priority, d.seq, 0), 0);
            }
            // LINUX-GAP: an AF_UNSPEC dump also walks the IPv6, IPMR, and
            // IP6MR rules_ops (their default rules); NARF has IPv4 rules only.
            Ok(())
        }
        // LINUX-GAP: `lookup_rules_ops` finds IPv6/IPMR/IP6MR rule tables
        // whose default rules NARF does not model; the dump is empty.
        AF_INET6 | RTNL_FAMILY_IPMR | RTNL_FAMILY_IP6MR => Ok(()),
        _ => Err(EAFNOSUPPORT),
    }
}

// ── traffic control ─────────────────────────────────────────────────────

const TCMSG_LEN: usize = 20;
const TCAMSG_LEN: usize = 4;

/// `tc_dump_qdisc` (net/sched/sch_api.c): no strict validator; the liberal
/// parse's failure is the dump's error, and every device is dumped (the
/// tcmsg ifindex is not a filter).
fn dump_qdisc(d: &mut Dump<'_>) -> Result<(), i32> {
    nlmsg_parse(
        d.req,
        TCMSG_LEN,
        &RTM_TCA_POLICY,
        NL_VALIDATE_LIBERAL,
        &mut d.extack,
    )?;
    let links = core::mem::take(&mut d.links);
    for link in &links {
        d.push(build_newqdisc(link.ifindex, d.seq, 0), 0);
    }
    d.links = links;
    Ok(())
}

/// `tc_dump_tfilter` (net/sched/cls_api.c): a short tcmsg is an empty dump;
/// otherwise the liberal parse runs. No NARF qdisc carries a filter block.
fn dump_tfilter(d: &mut Dump<'_>) -> Result<(), i32> {
    if !has_payload(d.req, TCMSG_LEN) {
        return Ok(());
    }
    nlmsg_parse(
        d.req,
        TCMSG_LEN,
        &TCF_TFILTER_DUMP_POLICY,
        NL_VALIDATE_LIBERAL,
        &mut d.extack,
    )?;
    Ok(())
}

/// `tc_dump_action` (net/sched/act_api.c). NARF registers no action kinds,
/// so `tc_lookup_action` never matches and a parsed request is empty.
fn dump_action(d: &mut Dump<'_>) -> Result<(), i32> {
    nlmsg_parse(
        d.req,
        TCAMSG_LEN,
        &TCAA_POLICY,
        NL_VALIDATE_LIBERAL,
        &mut d.extack,
    )?;
    Ok(())
}

// ── RTM_GETADDRLABEL / RTM_GETMDB / RTM_GETNEXTHOP ──────────────────────

const IFADDRLBLMSG_LEN: usize = 12;
const BR_PORT_MSG_LEN: usize = 8;
const NHMSG_LEN: usize = 8;
const NHA_OIF: usize = 5;
const NHA_MASTER: usize = 10;

/// `ip6addrlbl_dump` / `ip6addrlbl_valid_dump_req` (net/ipv6/addrlabel.c).
fn dump_addrlabel(d: &mut Dump<'_>) -> Result<(), i32> {
    if d.strict {
        if !has_payload(d.req, IFADDRLBLMSG_LEN) {
            d.extack
                .set("ipv6: Invalid header for address label dump request");
            return Err(EINVAL);
        }
        // __ifal_reserved, ifal_prefixlen, ifal_flags, ifal_index, ifal_seq.
        if d.req[NLMSG_HDRLEN + 1..NLMSG_HDRLEN + 4]
            .iter()
            .any(|&b| b != 0)
            || read_u32(d.req, NLMSG_HDRLEN + 4) != 0
            || read_u32(d.req, NLMSG_HDRLEN + 8) != 0
        {
            d.extack
                .set("ipv6: Invalid values in header for address label dump request");
            return Err(EINVAL);
        }
        if has_attrs(d.req, IFADDRLBLMSG_LEN) {
            d.extack
                .set("ipv6: Invalid data after header for address label dump request");
            return Err(EINVAL);
        }
    }
    // LINUX-GAP: Linux seeds the RFC 6724 default label table
    // (ip6addrlbl_init_table); NARF has no address-label policy table.
    Ok(())
}

/// `rtnl_mdb_dump` / `rtnl_mdb_valid_dump_req` (net/core/rtnetlink.c). No
/// NARF device implements ndo_mdb_dump.
fn dump_mdb(d: &mut Dump<'_>) -> Result<(), i32> {
    if d.strict {
        if !has_payload(d.req, BR_PORT_MSG_LEN) {
            d.extack.set("Invalid header for mdb dump request");
            return Err(EINVAL);
        }
        if read_u32(d.req, NLMSG_HDRLEN + 4) != 0 {
            d.extack
                .set("Filtering by device index is not supported for mdb dump request");
            return Err(EINVAL);
        }
        if has_attrs(d.req, BR_PORT_MSG_LEN) {
            d.extack
                .set("Invalid data after header in mdb dump request");
            return Err(EINVAL);
        }
    }
    Ok(())
}

/// `rtm_dump_nexthop` / `nh_valid_dump_req` (net/ipv4/nexthop.c). The
/// nexthop dump validates with `nlmsg_parse` (NL_VALIDATE_STRICT) whether or
/// not the socket asked for strict checking. NARF has no nexthop objects.
fn dump_nexthop(d: &mut Dump<'_>) -> Result<(), i32> {
    let tb = nlmsg_parse(
        d.req,
        NHMSG_LEN,
        &RTM_NH_POLICY_DUMP,
        NL_VALIDATE_STRICT,
        &mut d.extack,
    )?;
    // `__nh_valid_dump_req`.
    if let Some(attr) = tb[NHA_OIF] {
        if attr_u32(d.req, attr) > i32::MAX as u32 {
            d.extack.set("Invalid device index");
            return Err(EINVAL);
        }
    }
    if let Some(attr) = tb[NHA_MASTER] {
        if attr_u32(d.req, attr) > i32::MAX as u32 {
            d.extack.set("Invalid master device index");
            return Err(EINVAL);
        }
    }
    // nh_scope, nh_protocol, resvd, nh_flags.
    if byte(d.req, NLMSG_HDRLEN + 1) != 0
        || byte(d.req, NLMSG_HDRLEN + 2) != 0
        || byte(d.req, NLMSG_HDRLEN + 3) != 0
        || read_u32(d.req, NLMSG_HDRLEN + 4) != 0
    {
        d.extack
            .set("Invalid values in header for nexthop dump request");
        return Err(EINVAL);
    }
    Ok(())
}
