//! Linux-parity `setsockopt` / `getsockopt` for the SOL_SOCKET, SOL_IP and
//! SOL_IPV6 options the generic dispatcher in `socket.rs` does not own, plus
//! the multicast group state those options drive.
//!
//! Every value, errno and check order below is taken from the Linux source:
//!
//! - `net/core/sock.c` — `sk_setsockopt`, `sk_getsockopt`,
//!   `sock_copy_user_timeval`, `sock_set_timeout`, `sock_get_timeout`,
//!   `sock_bindtoindex_locked`, `__sock_set_rcvbuf`.
//! - `net/ipv4/ip_sockglue.c` — `do_ip_setsockopt`, `do_ip_getsockopt`,
//!   `ip_mcast_join_leave`, `ip_ra_control`.
//! - `net/ipv4/igmp.c` — `ip_mc_find_dev`, `__ip_mc_join_group`,
//!   `ip_mc_leave_group`, `ip_mc_sf_allow`.
//! - `net/ipv6/ipv6_sockglue.c` — `do_ipv6_setsockopt`,
//!   `do_ipv6_getsockopt`, `ipv6_mcast_join_leave`, `ip6_ra_control`.
//! - `net/ipv6/mcast.c` — `__ipv6_sock_mc_join`, `ipv6_sock_mc_drop`,
//!   `inet6_mc_check`.
//! - `include/net/ipv6.h` — `ip6_sock_set_addr_preferences`.
//!
//! Lock order: a socket's `options` → [`IP_MC_GROUPS`] / [`IP6_MC_GROUPS`].
//! Nothing takes a socket lock while holding a group table.

use super::*;

mod ip;
mod ipv6;
mod sol_socket;

// ── SOL_SOCKET (include/uapi/asm-generic/socket.h) ──────────────────────
pub const SO_DEBUG: u32 = 1;
pub const SO_DONTROUTE: u32 = 5;
pub const SO_OOBINLINE: u32 = 10;
pub const SO_NO_CHECK: u32 = 11;
pub const SO_PRIORITY: u32 = 12;
pub const SO_BSDCOMPAT: u32 = 14;
pub const SO_RCVLOWAT: u32 = 18;
pub const SO_SNDLOWAT: u32 = 19;
pub const SO_RCVTIMEO_OLD: u32 = 20;
pub const SO_SNDTIMEO_OLD: u32 = 21;
pub const SO_DETACH_FILTER: u32 = 27;
pub const SO_PEERNAME: u32 = 28;
pub const SO_PASSSEC: u32 = 34;
pub const SO_MARK: u32 = 36;
pub const SO_RXQ_OVFL: u32 = 40;
pub const SO_WIFI_STATUS: u32 = 41;
pub const SO_PEEK_OFF: u32 = 42;
pub const SO_NOFCS: u32 = 43;
pub const SO_LOCK_FILTER: u32 = 44;
pub const SO_SELECT_ERR_QUEUE: u32 = 45;
pub const SO_BUSY_POLL: u32 = 46;
pub const SO_MAX_PACING_RATE: u32 = 47;
pub const SO_BPF_EXTENSIONS: u32 = 48;
pub const SO_INCOMING_CPU: u32 = 49;
pub const SO_CNX_ADVICE: u32 = 53;
pub const SO_MEMINFO: u32 = 55;
pub const SO_INCOMING_NAPI_ID: u32 = 56;
pub const SO_COOKIE: u32 = 57;
pub const SO_ZEROCOPY: u32 = 60;
pub const SO_TXTIME: u32 = 61;
pub const SO_BINDTOIFINDEX: u32 = 62;
pub const SO_TIMESTAMPING_OLD: u32 = 37;
pub const SO_TIMESTAMPING_NEW: u32 = 65;
pub const SO_RCVTIMEO_NEW: u32 = 66;
pub const SO_SNDTIMEO_NEW: u32 = 67;
pub const SO_PREFER_BUSY_POLL: u32 = 69;
pub const SO_BUSY_POLL_BUDGET: u32 = 70;
pub const SO_NETNS_COOKIE: u32 = 71;
pub const SO_BUF_LOCK: u32 = 72;
pub const SO_RESERVE_MEM: u32 = 73;
pub const SO_TXREHASH: u32 = 74;
pub const SO_RCVMARK: u32 = 75;
pub const SO_PASSPIDFD: u32 = 76;
pub const SO_RCVPRIORITY: u32 = 82;
pub const SO_PASSRIGHTS: u32 = 83;
pub const SO_INQ: u32 = 84;

// ── SOL_IP (include/uapi/linux/in.h) ────────────────────────────────────
pub const IP_HDRINCL: u32 = 3;
pub const IP_OPTIONS: u32 = 4;
pub const IP_ROUTER_ALERT: u32 = 5;
pub const IP_RECVOPTS: u32 = 6;
pub const IP_RETOPTS: u32 = 7;
pub const IP_PKTOPTIONS: u32 = 9;
pub const IP_MTU_DISCOVER: u32 = 10;
pub const IP_RECVERR: u32 = 11;
pub const IP_RECVTOS: u32 = 13;
pub const IP_FREEBIND: u32 = 15;
pub const IP_IPSEC_POLICY: u32 = 16;
pub const IP_XFRM_POLICY: u32 = 17;
pub const IP_PASSSEC: u32 = 18;
pub const IP_TRANSPARENT: u32 = 19;
pub const IP_RECVORIGDSTADDR: u32 = 20;
pub const IP_MINTTL: u32 = 21;
pub const IP_NODEFRAG: u32 = 22;
pub const IP_CHECKSUM: u32 = 23;
pub const IP_BIND_ADDRESS_NO_PORT: u32 = 24;
pub const IP_RECVFRAGSIZE: u32 = 25;
pub const IP_RECVERR_RFC4884: u32 = 26;
pub const IP_MULTICAST_IF: u32 = 32;
pub const IP_MULTICAST_LOOP: u32 = 34;
pub const IP_ADD_MEMBERSHIP: u32 = 35;
pub const IP_DROP_MEMBERSHIP: u32 = 36;
pub const MCAST_JOIN_GROUP: u32 = 42;
pub const MCAST_LEAVE_GROUP: u32 = 45;
pub const IP_MULTICAST_ALL: u32 = 49;
pub const IP_UNICAST_IF: u32 = 50;
pub const IP_LOCAL_PORT_RANGE: u32 = 51;
pub const IP_PROTOCOL: u32 = 52;
/// `MRT_BASE ..= MRT_MAX` (`include/uapi/linux/mroute.h`).
const MRT_BASE: u32 = 200;
const MRT_MAX: u32 = 212;
const IP_PMTUDISC_WANT: i32 = 1;
const IP_PMTUDISC_OMIT: i32 = 5;
const IPPROTO_IGMP: u32 = 2;

// ── SOL_IPV6 (include/uapi/linux/in6.h) ─────────────────────────────────
pub const IPV6_ADDRFORM: u32 = 1;
pub const IPV6_2292PKTINFO: u32 = 2;
pub const IPV6_2292HOPOPTS: u32 = 3;
pub const IPV6_2292DSTOPTS: u32 = 4;
pub const IPV6_2292RTHDR: u32 = 5;
pub const IPV6_2292PKTOPTIONS: u32 = 6;
pub const IPV6_2292HOPLIMIT: u32 = 8;
pub const IPV6_FLOWINFO: u32 = 11;
pub const IPV6_MULTICAST_IF: u32 = 17;
pub const IPV6_MULTICAST_HOPS: u32 = 18;
pub const IPV6_MULTICAST_LOOP: u32 = 19;
pub const IPV6_ADD_MEMBERSHIP: u32 = 20;
pub const IPV6_DROP_MEMBERSHIP: u32 = 21;
pub const IPV6_ROUTER_ALERT: u32 = 22;
pub const IPV6_MULTICAST_ALL: u32 = 29;
pub const IPV6_ROUTER_ALERT_ISOLATE: u32 = 30;
pub const IPV6_RECVERR_RFC4884: u32 = 31;
pub const IPV6_FLOWINFO_SEND: u32 = 33;
pub const IPV6_IPSEC_POLICY: u32 = 34;
pub const IPV6_XFRM_POLICY: u32 = 35;
pub const IPV6_RECVHOPOPTS: u32 = 53;
pub const IPV6_RECVRTHDR: u32 = 56;
pub const IPV6_RECVDSTOPTS: u32 = 58;
pub const IPV6_RECVPATHMTU: u32 = 60;
pub const IPV6_PATHMTU: u32 = 61;
pub const IPV6_RECVTCLASS: u32 = 66;
pub const IPV6_TCLASS: u32 = 67;
pub const IPV6_AUTOFLOWLABEL: u32 = 70;
pub const IPV6_ADDR_PREFERENCES: u32 = 72;
pub const IPV6_MINHOPCOUNT: u32 = 73;
pub const IPV6_RECVORIGDSTADDR: u32 = 74;
pub const IPV6_TRANSPARENT: u32 = 75;
pub const IPV6_UNICAST_IF: u32 = 76;
pub const IPV6_RECVFRAGSIZE: u32 = 77;
pub const IPV6_FREEBIND: u32 = 78;
const IPV6_MIN_MTU: i32 = 1280;
/// `IPV6_DEFAULT_MCASTHOPS` (`include/net/ipv6.h`).
const IPV6_DEFAULT_MCASTHOPS: i32 = 1;
/// `ipv6.devconf_all->hop_limit` default (`IPV6_DEFAULT_HOPLIMIT`).
pub(super) const IPV6_DEFAULT_HOPLIMIT: i32 = 64;
const IPV6_PMTUDISC_OMIT: i32 = 5;

/// `IPV6_PREFER_SRC_*` (`include/uapi/linux/in6.h`).
const PREFER_SRC_TMP: u32 = 0x0001;
const PREFER_SRC_PUBLIC: u32 = 0x0002;
const PREFER_SRC_COA: u32 = 0x0004;
const PREFER_SRC_CGA: u32 = 0x0008;
const PREFER_SRC_PUBTMP_DEFAULT: u32 = 0x0100;
const PREFER_SRC_HOME: u32 = 0x0400;
const PREFER_SRC_NONCGA: u32 = 0x0800;
const PREFER_SRC_MASK: u32 = PREFER_SRC_TMP
    | PREFER_SRC_PUBLIC
    | PREFER_SRC_PUBTMP_DEFAULT
    | PREFER_SRC_COA
    | PREFER_SRC_HOME
    | PREFER_SRC_CGA
    | PREFER_SRC_NONCGA;

/// The CONFIG_HZ sockopt timeouts are rounded to. NARF models HZ=100, the
/// same value `sched_rr_get_interval` uses (see `sched_policy.inc.rs`).
const SOCK_HZ: i64 = 100;
const USEC_PER_SEC: i64 = 1_000_000;
/// `MAX_SCHEDULE_TIMEOUT / HZ - 1`: a larger tv_sec means "forever".
const TIMEO_MAX_SEC: i64 = i64::MAX / SOCK_HZ - 1;
/// `sysctl_wmem_max` / `sysctl_rmem_max` defaults.
const WMEM_MAX: u32 = 212_992;
const RMEM_MAX: u32 = 212_992;
/// `SOCK_MIN_SNDBUF` / `SOCK_MIN_RCVBUF` with the x86_64/arm64 skb size
/// (`2 * (2048 + SKB_DATA_ALIGN(sizeof(struct sk_buff)))`).
pub(super) const SOCK_MIN_SNDBUF: u32 = 4608;
pub(super) const SOCK_MIN_RCVBUF: u32 = 2304;
/// `sysctl_igmp_max_memberships` default.
const IGMP_MAX_MEMBERSHIPS: usize = 20;
/// `sizeof(struct group_req)` on LP64: u32 + pad + sockaddr_storage.
const GROUP_REQ_LEN: usize = 136;
/// `SOCK_BUF_LOCK_MASK` (`SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK`).
const SOCK_BUF_LOCK_MASK: i32 = 3;
/// `SKF_AD_MAX` (`include/uapi/linux/filter.h`) — `bpf_tell_extensions()`.
const SKF_AD_MAX: i32 = 64;
/// `SK_MEMINFO_VARS` (`include/uapi/linux/sock_diag.h`).
const SK_MEMINFO_VARS: usize = 9;
/// `SOCK_TXREHASH_DEFAULT` and the `net.core.txrehash` default
/// (`SOCK_TXREHASH_ENABLED`).
const SOCK_TXREHASH_DEFAULT: u8 = 255;
const SYSCTL_TXREHASH: u8 = 1;

/// One `struct ip_mc_socklist` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpMcMembership {
    pub group: u32,
    pub ifindex: u32,
    pub addr: u32,
}

/// One `struct ipv6_mc_socklist` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ip6McMembership {
    pub group: [u8; 16],
    pub ifindex: u32,
}

/// Option state beyond what `SockOptions` already models. Defaults are
/// Linux's (`sock_init_data_uid`, `inet_create`, `inet6_create`).
#[derive(Clone, Debug)]
pub struct SockOptExt {
    /// `sk_rcvtimeo` / `sk_sndtimeo` in jiffies; `None` is
    /// MAX_SCHEDULE_TIMEOUT (block forever).
    pub rcvtimeo: Option<u64>,
    pub sndtimeo: Option<u64>,
    pub debug: bool,
    pub dontroute: bool,
    pub oobinline: bool,
    pub no_check: bool,
    pub priority: u32,
    pub rcvlowat: i32,
    pub mark: u32,
    pub rcvmark: bool,
    pub rcvpriority: bool,
    pub rxq_ovfl: bool,
    pub wifi_status: bool,
    pub nofcs: bool,
    pub select_err_queue: bool,
    pub filter_locked: bool,
    pub busy_poll: u32,
    pub prefer_busy_poll: bool,
    pub busy_poll_budget: u32,
    pub max_pacing_rate: u64,
    pub incoming_cpu: i32,
    pub txrehash: u8,
    pub buf_lock: i32,
    pub reserve_mem: i32,
    pub passsec: bool,
    pub passpidfd: bool,
    pub passrights: bool,
    pub unix_inq: bool,
    pub cookie: u64,
    // SOL_IP
    pub ip_recvtos: bool,
    pub ip_recvopts: bool,
    pub ip_retopts: bool,
    pub ip_passsec: bool,
    pub ip_origdstaddr: bool,
    pub ip_recvfragsize: bool,
    pub ip_recverr: bool,
    pub ip_recverr_rfc4884: bool,
    pub ip_hdrincl: bool,
    pub ip_nodefrag: bool,
    pub ip_bind_address_no_port: bool,
    pub ip_transparent: bool,
    pub ip_router_alert: bool,
    pub ip_checksum: bool,
    pub ip_minttl: i32,
    pub ip_pmtudisc: i32,
    pub ip_local_port_range: u32,
    pub ip_mc_loop: bool,
    pub ip_mc_all: bool,
    pub ip_mc_index: u32,
    pub ip_mc_addr: u32,
    pub ip_uc_index: u32,
    pub ip_options: Vec<u8>,
    pub ip_mc_list: Vec<IpMcMembership>,
    // SOL_IPV6
    pub ipv6_mc_loop: bool,
    pub ipv6_mc_all: bool,
    pub ipv6_mcast_hops: i32,
    pub ipv6_mcast_oif: u32,
    pub ipv6_ucast_oif: u32,
    pub ipv6_tclass: i32,
    pub ipv6_2292pktinfo: bool,
    pub ipv6_2292hoplimit: bool,
    pub ipv6_recvrthdr: bool,
    pub ipv6_2292rthdr: bool,
    pub ipv6_recvhopopts: bool,
    pub ipv6_2292hopopts: bool,
    pub ipv6_recvdstopts: bool,
    pub ipv6_2292dstopts: bool,
    pub ipv6_recvtclass: bool,
    pub ipv6_flowinfo: bool,
    pub ipv6_recvpathmtu: bool,
    pub ipv6_recvorigdstaddr: bool,
    pub ipv6_recvfragsize: bool,
    pub ipv6_flowinfo_send: bool,
    /// `None` until IPV6_AUTOFLOWLABEL is set (`AUTOFLOWLABEL_SET`).
    pub ipv6_autoflowlabel: Option<bool>,
    pub ipv6_minhopcount: i32,
    pub ipv6_router_alert: bool,
    pub ipv6_router_alert_isolate: bool,
    pub ipv6_recverr_rfc4884: bool,
    pub ipv6_srcprefs: u32,
    pub ipv6_sticky_pktinfo: ([u8; 16], u32),
    pub ipv6_mc_list: Vec<Ip6McMembership>,
}

impl Default for SockOptExt {
    fn default() -> Self {
        Self {
            rcvtimeo: None,
            sndtimeo: None,
            debug: false,
            dontroute: false,
            oobinline: false,
            no_check: false,
            priority: 0,
            rcvlowat: 1,
            mark: 0,
            rcvmark: false,
            rcvpriority: false,
            rxq_ovfl: false,
            wifi_status: false,
            nofcs: false,
            select_err_queue: false,
            filter_locked: false,
            busy_poll: 0,
            prefer_busy_poll: false,
            busy_poll_budget: 0,
            max_pacing_rate: u64::MAX,
            incoming_cpu: -1,
            txrehash: SYSCTL_TXREHASH,
            buf_lock: 0,
            reserve_mem: 0,
            passsec: false,
            passpidfd: false,
            passrights: true,
            unix_inq: false,
            cookie: 0,
            ip_recvtos: false,
            ip_recvopts: false,
            ip_retopts: false,
            ip_passsec: false,
            ip_origdstaddr: false,
            ip_recvfragsize: false,
            ip_recverr: false,
            ip_recverr_rfc4884: false,
            ip_hdrincl: false,
            ip_nodefrag: false,
            ip_bind_address_no_port: false,
            ip_transparent: false,
            ip_router_alert: false,
            ip_checksum: false,
            ip_minttl: 0,
            ip_pmtudisc: IP_PMTUDISC_WANT,
            ip_local_port_range: 0,
            ip_mc_loop: true,
            ip_mc_all: true,
            ip_mc_index: 0,
            ip_mc_addr: 0,
            ip_uc_index: 0,
            ip_options: Vec::new(),
            ip_mc_list: Vec::new(),
            ipv6_mc_loop: true,
            ipv6_mc_all: true,
            ipv6_mcast_hops: IPV6_DEFAULT_MCASTHOPS,
            ipv6_mcast_oif: 0,
            ipv6_ucast_oif: 0,
            ipv6_tclass: 0,
            ipv6_2292pktinfo: false,
            ipv6_2292hoplimit: false,
            ipv6_recvrthdr: false,
            ipv6_2292rthdr: false,
            ipv6_recvhopopts: false,
            ipv6_2292hopopts: false,
            ipv6_recvdstopts: false,
            ipv6_2292dstopts: false,
            ipv6_recvtclass: false,
            ipv6_flowinfo: false,
            ipv6_recvpathmtu: false,
            ipv6_recvorigdstaddr: false,
            ipv6_recvfragsize: false,
            ipv6_flowinfo_send: false,
            ipv6_autoflowlabel: None,
            ipv6_minhopcount: 0,
            ipv6_router_alert: false,
            ipv6_router_alert_isolate: false,
            ipv6_recverr_rfc4884: false,
            ipv6_srcprefs: 0,
            ipv6_sticky_pktinfo: ([0; 16], 0),
            ipv6_mc_list: Vec::new(),
        }
    }
}

// ── Host multicast membership (`in_device->mc_list` / `inet6_dev->mc_list`) ──

/// Per-(netns, ifindex, group) join count: the device-level membership
/// `____ip_mc_inc_group` / `ip_mc_dec_group` maintain. A group is "joined on
/// the device" while any socket holds a membership there.
type McGroupTable<G> = IrqSafeSpinLock<BTreeMap<(u64, u32, G), u32>>;
static IP_MC_GROUPS: McGroupTable<u32> = IrqSafeSpinLock::new(BTreeMap::new());
static IP6_MC_GROUPS: McGroupTable<[u8; 16]> = IrqSafeSpinLock::new(BTreeMap::new());

/// Source of `sock_gen_cookie` values.
static NEXT_SOCK_COOKIE: AtomicU64 = AtomicU64::new(1);

/// Loopback's fixed ifindex.
pub(super) const LOOPBACK_IFINDEX: u32 = 1;
/// 224.0.0.1 (all-hosts): every IPv4 device joins it at bring-up
/// (`ip_mc_up` → `ip_mc_inc_group(IGMP_ALL_HOSTS)`).
const IGMP_ALL_HOSTS: u32 = 0xE000_0001;

pub(super) fn is_multicast_v4(addr: u32) -> bool {
    addr >> 28 == 0xE
}

pub(super) fn is_multicast_v6(addr: &[u8; 16]) -> bool {
    addr[0] == 0xff
}

/// Is `group` joined on device `ifindex` in `ns` (`ip_check_mc_rcv`'s
/// membership half)?
pub(super) fn host_joined_v4(ns: u64, ifindex: u32, group: u32) -> bool {
    group == IGMP_ALL_HOSTS || IP_MC_GROUPS.lock().contains_key(&(ns, ifindex, group))
}

/// `ipv6_chk_mcast_addr`: the all-nodes groups are joined on every device.
pub(super) fn host_joined_v6(ns: u64, ifindex: u32, group: &[u8; 16]) -> bool {
    let all_nodes = group[2..15] == [0; 13] && group[15] == 1 && matches!(group[1], 1 | 2);
    all_nodes || IP6_MC_GROUPS.lock().contains_key(&(ns, ifindex, *group))
}

fn mc_inc_v4(ns: u64, ifindex: u32, group: u32) {
    *IP_MC_GROUPS.lock().entry((ns, ifindex, group)).or_insert(0) += 1;
}

fn mc_dec_v4(ns: u64, ifindex: u32, group: u32) {
    let mut g = IP_MC_GROUPS.lock();
    if let Some(n) = g.get_mut(&(ns, ifindex, group)) {
        *n -= 1;
        if *n == 0 {
            g.remove(&(ns, ifindex, group));
        }
    }
}

fn mc_inc_v6(ns: u64, ifindex: u32, group: [u8; 16]) {
    *IP6_MC_GROUPS
        .lock()
        .entry((ns, ifindex, group))
        .or_insert(0) += 1;
}

fn mc_dec_v6(ns: u64, ifindex: u32, group: [u8; 16]) {
    let mut g = IP6_MC_GROUPS.lock();
    if let Some(n) = g.get_mut(&(ns, ifindex, group)) {
        *n -= 1;
        if *n == 0 {
            g.remove(&(ns, ifindex, group));
        }
    }
}

// ── Device lookups in NARF's ifindex space (1 = lo, 2.. = NICs) ──

/// `dev_get_by_index` in `ns`.
pub(super) fn ifindex_exists(ns: u64, ifindex: u32) -> bool {
    ifindex == LOOPBACK_IFINDEX
        || narf_net::iface::snapshot_all_in(ns)
            .iter()
            .any(|i| narf_net::iface::ifindex_of(&i.name) == Some(ifindex))
}

/// The device name for `ifindex` (`netdev_get_name`).
pub(super) fn ifindex_name(ns: u64, ifindex: u32) -> Option<String> {
    if ifindex == LOOPBACK_IFINDEX {
        return Some(String::from("lo"));
    }
    narf_net::iface::snapshot_all_in(ns)
        .into_iter()
        .find(|i| narf_net::iface::ifindex_of(&i.name) == Some(ifindex))
        .map(|i| i.name)
}

/// `__ip_dev_find(net, addr, devref)`: the device owning local address
/// `addr` (host order). With `fib`, any address the local table routes to
/// the host (all of 127/8) resolves; without it only an assigned address.
fn ip_dev_find(ns: u64, addr: u32, fib: bool) -> Option<u32> {
    if addr == 0x7F00_0001 || (fib && addr >> 24 == 127) {
        return Some(LOOPBACK_IFINDEX);
    }
    narf_net::iface::snapshot_all_in(ns)
        .into_iter()
        .find(|i| i.ipv4 == addr.to_be_bytes())
        .and_then(|i| narf_net::iface::ifindex_of(&i.name))
}

/// `ip_route_output` for a multicast group: its egress device, or `None`
/// when nothing routes it.
fn route_dev_v4(ns: u64, group: u32) -> Option<u32> {
    narf_net::iface::for_dst_in(ns, group.to_be_bytes())
        .and_then(|i| narf_net::iface::ifindex_of(&i.name))
}

/// `rt6_lookup` for a multicast group with no interface: the first device
/// carrying the `ff00::/8` local-table route, i.e. the first NIC (lo has
/// none).
fn route_dev_v6(ns: u64) -> Option<u32> {
    narf_net::iface::primary_in(ns).and_then(|i| narf_net::iface::ifindex_of(&i.name))
}

/// `ip_mc_find_dev`: fills `ifindex` in on success.
fn ip_mc_find_dev(ns: u64, group: u32, addr: u32, ifindex: &mut u32) -> bool {
    if *ifindex != 0 {
        return ifindex_exists(ns, *ifindex);
    }
    let dev = if addr != 0 {
        match ip_dev_find(ns, addr, false) {
            Some(d) => Some(d),
            None => return false,
        }
    } else {
        route_dev_v4(ns, group)
    };
    match dev {
        Some(d) => {
            *ifindex = d;
            true
        }
        None => false,
    }
}

// ── Value decoding ──

/// `do_ip_setsockopt`'s int read: a full int when `optlen >= 4`, a single
/// unsigned byte when `optlen >= 1`, and 0 for an empty optval.
fn ip_val(v: &[u8]) -> i32 {
    if v.len() >= 4 {
        i32::from_ne_bytes([v[0], v[1], v[2], v[3]])
    } else {
        v.first().map_or(0, |b| i32::from(*b))
    }
}

/// `do_ipv6_setsockopt`'s int read: a full int, else 0.
fn ip6_val(v: &[u8]) -> i32 {
    if v.len() >= 4 {
        i32::from_ne_bytes([v[0], v[1], v[2], v[3]])
    } else {
        0
    }
}

fn read_u32_at(v: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([v[off], v[off + 1], v[off + 2], v[off + 3]])
}

fn read_be_u32_at(v: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([v[off], v[off + 1], v[off + 2], v[off + 3]])
}

fn read_in6_at(v: &[u8], off: usize) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&v[off..off + 16]);
    a
}

const fn errno_err(e: i64) -> SocketOpResult {
    SocketOpResult::Err(SockError::Stack(e as i32))
}

const OK: SocketOpResult = SocketOpResult::Ok(0);
const EINVAL_R: SocketOpResult = SocketOpResult::Err(SockError::InvalidArg);
const ENOPROTOOPT_R: SocketOpResult = SocketOpResult::Err(SockError::NoProtoOpt);
const EOPNOTSUPP_R: SocketOpResult = SocketOpResult::Err(SockError::NotSupported);
const EPERM_R: SocketOpResult = SocketOpResult::Err(SockError::PermDenied);

fn capable(cap: u32) -> bool {
    crate::handlers::task_capable(crate::handlers::current_task_id(), cap)
}

fn net_raw_or_admin() -> bool {
    capable(crate::handlers::CAP_NET_RAW) || capable(crate::handlers::CAP_NET_ADMIN)
}

// ── Timeouts ──

/// `sock_copy_user_timeval` + `sock_set_timeout`. Both layouts are 16 bytes
/// on LP64 (`struct __kernel_old_timeval` and `__kernel_sock_timeval`).
fn sock_set_timeout(v: &[u8]) -> Result<Option<u64>, SockError> {
    if v.len() < 16 {
        return Err(SockError::InvalidArg);
    }
    let sec = i64::from_ne_bytes(v[0..8].try_into().unwrap_or([0; 8]));
    let usec = i64::from_ne_bytes(v[8..16].try_into().unwrap_or([0; 8]));
    if !(0..USEC_PER_SEC).contains(&usec) {
        return Err(SockError::Stack(errno::EDOM as i32));
    }
    if sec < 0 {
        return Ok(Some(0));
    }
    if (sec != 0 || usec != 0) && sec < TIMEO_MAX_SEC {
        let per_jiffy = USEC_PER_SEC / SOCK_HZ;
        let jiffies = sec * SOCK_HZ + (usec + per_jiffy - 1) / per_jiffy;
        return Ok(Some(jiffies as u64));
    }
    Ok(None)
}

/// `sock_get_timeout`: `{0, 0}` for MAX_SCHEDULE_TIMEOUT.
fn sock_get_timeout(t: Option<u64>) -> [u8; 16] {
    let (sec, usec) = match t {
        None => (0i64, 0i64),
        Some(j) => {
            let j = j as i64;
            (j / SOCK_HZ, (j % SOCK_HZ) * USEC_PER_SEC / SOCK_HZ)
        }
    };
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&sec.to_ne_bytes());
    b[8..].copy_from_slice(&usec.to_ne_bytes());
    b
}

/// A socket wait bound in nanoseconds: `None` = forever, `Some(0)` = do not
/// wait (`sock_rcvtimeo` / `sock_sndtimeo`).
pub fn timeo_ns(t: Option<u64>) -> Option<u64> {
    t.map(|j| j.saturating_mul(1_000_000_000 / SOCK_HZ as u64))
}

// ── getsockopt copy helpers ──

fn put_bytes(buf: &mut [u8], v: &[u8]) -> SocketOpResult {
    let n = core::cmp::min(buf.len(), v.len());
    buf[..n].copy_from_slice(&v[..n]);
    SocketOpResult::OptValue { n }
}

fn put_int(buf: &mut [u8], v: i32) -> SocketOpResult {
    put_bytes(buf, &v.to_ne_bytes())
}

/// `do_ip_getsockopt` copyval: a short buffer takes one byte when the value
/// fits in an unsigned char.
fn ip_copyval(buf: &mut [u8], v: i32) -> SocketOpResult {
    if !buf.is_empty() && buf.len() < 4 && (0..=255).contains(&v) {
        buf[0] = v as u8;
        return SocketOpResult::OptValue { n: 1 };
    }
    put_int(buf, v)
}

impl SocketFile {
    /// `sk_may_scm_recv`.
    fn may_scm_recv(&self) -> bool {
        matches!(self.domain, AF_UNIX | AF_NETLINK)
    }

    /// Does the socket's `proto_ops` have `set_peek_off` (unix, inet stream,
    /// inet dgram)?
    fn has_peek_off(&self) -> bool {
        self.domain == AF_UNIX
            || (matches!(self.domain, AF_INET | AF_INET6)
                && matches!(self.kind, SOCK_STREAM | SOCK_DGRAM))
    }

    fn is_tcp(&self) -> bool {
        matches!(self.domain, AF_INET | AF_INET6) && self.kind == SOCK_STREAM
    }

    /// The current `SO_RCVTIMEO` in jiffies (`None` = forever).
    pub fn rcvtimeo(&self) -> Option<u64> {
        self.options.lock().ext.rcvtimeo
    }

    /// The current `SO_SNDTIMEO` in jiffies (`None` = forever).
    pub fn sndtimeo(&self) -> Option<u64> {
        self.options.lock().ext.sndtimeo
    }

    /// `ip_mc_drop_socket` / `ipv6_sock_mc_close`: leave every group on
    /// close.
    pub(super) fn release_multicast(&self) {
        let ns = self.net_ns_id();
        let mut guard = self.options.lock();
        let opts = &mut *guard;
        for m in core::mem::take(&mut opts.ext.ip_mc_list) {
            mc_dec_v4(ns, m.ifindex, m.group);
        }
        for m in core::mem::take(&mut opts.ext.ipv6_mc_list) {
            mc_dec_v6(ns, m.ifindex, m.group);
        }
    }

    /// Options this module owns. `None` hands the option back to the
    /// generic dispatcher. SOL_SOCKET options arrive with `optlen >= 4`
    /// already enforced (`sk_setsockopt`).
    pub(super) fn sockopt_set_ext(
        &self,
        level: u32,
        name: u32,
        value: &[u8],
    ) -> Option<SocketOpResult> {
        match level {
            SOL_SOCKET => self.sol_socket_set(name, value),
            IPPROTO_IP if self.ip_level_applies() => self.ip_set(name, value),
            IPPROTO_IP if self.domain == AF_INET6 => Some(ENOPROTOOPT_R),
            IPPROTO_IPV6 if self.domain == AF_INET6 => self.ipv6_set(name, value),
            _ => None,
        }
    }

    /// `ipv6_setsockopt` / `ipv6_getsockopt` forward SOL_IP to the IPv4
    /// handler for every AF_INET6 socket but SOCK_RAW.
    fn ip_level_applies(&self) -> bool {
        self.domain == AF_INET || (self.domain == AF_INET6 && self.kind != SOCK_RAW)
    }

    pub(super) fn sockopt_get_ext(
        &self,
        level: u32,
        name: u32,
        buf: &mut [u8],
    ) -> Option<SocketOpResult> {
        match level {
            SOL_SOCKET => self.sol_socket_get(name, buf),
            IPPROTO_IP if self.ip_level_applies() => self.ip_get(name, buf),
            IPPROTO_IPV6 if self.domain == AF_INET6 => self.ipv6_get(name, buf),
            _ => None,
        }
    }

    /// `inet_sk(sk)->inet_num`: the protocol for a raw socket, else the
    /// bound local port.
    fn inet_num(&self) -> u32 {
        if self.kind == SOCK_RAW {
            return self.protocol;
        }
        self.local_addr()
            .filter(|a| a.body.len() >= 2)
            .map_or(0, |a| u32::from(u16::from_be_bytes([a.body[0], a.body[1]])))
    }

    fn is_established(&self) -> bool {
        matches!(
            &*self.state.lock(),
            SocketState::InetConnected { .. }
                | SocketState::Inet6Connected { .. }
                | SocketState::InetWired { .. }
                | SocketState::Inet6Wired { .. }
                | SocketState::InetDgram { peer: Some(_), .. }
                | SocketState::Inet6Dgram { peer: Some(_), .. }
        )
    }
}

/// `ip6_sock_set_addr_preferences`: `None` for a conflicting request.
fn addr_preferences(current: u32, val: u32) -> Option<u32> {
    let mut prefmask = !PREFER_SRC_MASK;
    let mut pref = 0u32;
    match val & (PREFER_SRC_PUBLIC | PREFER_SRC_TMP | PREFER_SRC_PUBTMP_DEFAULT) {
        PREFER_SRC_PUBLIC => {
            pref |= PREFER_SRC_PUBLIC;
            prefmask &= !(PREFER_SRC_PUBLIC | PREFER_SRC_TMP);
        }
        PREFER_SRC_TMP => {
            pref |= PREFER_SRC_TMP;
            prefmask &= !(PREFER_SRC_PUBLIC | PREFER_SRC_TMP);
        }
        PREFER_SRC_PUBTMP_DEFAULT => prefmask &= !(PREFER_SRC_PUBLIC | PREFER_SRC_TMP),
        0 => {}
        _ => return None,
    }
    match val & (PREFER_SRC_HOME | PREFER_SRC_COA) {
        PREFER_SRC_HOME => prefmask &= !PREFER_SRC_COA,
        PREFER_SRC_COA => pref |= PREFER_SRC_COA,
        0 => {}
        _ => return None,
    }
    match val & (PREFER_SRC_CGA | PREFER_SRC_NONCGA) {
        PREFER_SRC_CGA | PREFER_SRC_NONCGA | 0 => {}
        _ => return None,
    }
    Some((current & prefmask) | pref)
}

// ── Multicast delivery ──

/// `ip_mc_sf_allow` without source filters: a socket takes a datagram for
/// `group` arriving on `dif` when it joined that group on that device, or,
/// having not, while IP_MULTICAST_ALL is set.
pub(super) fn ip_mc_sf_allow(sock: &SocketFile, group: u32, dif: u32) -> bool {
    if !is_multicast_v4(group) {
        return true;
    }
    let o = sock.options.lock();
    o.ext
        .ip_mc_list
        .iter()
        .any(|m| m.group == group && m.ifindex == dif)
        || o.ext.ip_mc_all
}

/// `inet6_mc_check` without source filters (ifindex is not compared).
pub(super) fn inet6_mc_check(sock: &SocketFile, group: &[u8; 16]) -> bool {
    let o = sock.options.lock();
    o.ext.ipv6_mc_list.iter().any(|m| m.group == *group) || o.ext.ipv6_mc_all
}

/// Where a multicast datagram from an AF_INET socket leaves:
/// `IP_MULTICAST_IF`, else the bound device, else the route. `None` is
/// ENETUNREACH.
pub(super) fn mc_egress_v4(ns: u64, opts: &SockOptions, group: u32) -> Option<u32> {
    if opts.ext.ip_mc_index != 0 {
        return Some(opts.ext.ip_mc_index);
    }
    if opts.bindtodevice_index != 0 {
        return Some(opts.bindtodevice_index);
    }
    if opts.ext.ip_mc_addr != 0 {
        return ip_dev_find(ns, opts.ext.ip_mc_addr, true);
    }
    route_dev_v4(ns, group)
}

/// Where a multicast datagram from an AF_INET6 socket leaves: the
/// destination scope id, `IPV6_MULTICAST_IF`, the bound device, else the
/// first NIC.
pub(super) fn mc_egress_v6(ns: u64, opts: &SockOptions, scope_id: u32) -> Option<u32> {
    if scope_id != 0 {
        return Some(scope_id);
    }
    if opts.ext.ipv6_mcast_oif != 0 {
        return Some(opts.ext.ipv6_mcast_oif);
    }
    if opts.bindtodevice_index != 0 {
        return Some(opts.bindtodevice_index);
    }
    route_dev_v6(ns)
}

/// The IPv4 address a multicast from device `ifindex` carries
/// (`inet_select_addr`).
pub(super) fn mc_source_v4(ns: u64, ifindex: u32) -> u32 {
    if ifindex == LOOPBACK_IFINDEX {
        return 0x7F00_0001;
    }
    narf_net::iface::snapshot_all_in(ns)
        .into_iter()
        .find(|i| narf_net::iface::ifindex_of(&i.name) == Some(ifindex))
        .map_or(0, |i| u32::from_be_bytes(i.ipv4))
}
