//! `/proc/net/*` — network-subsystem visibility files.
//!
//! Each file in this module registers under `net/` and renders a
//! Linux-format text snapshot of one subsystem table. Unmodified
//! `netstat`, `ss`, `ip route`, `firewall-cmd`, container
//! runtimes, etc. all parse these formats — keeping the byte
//! layout exact is the goal.
//!
//! The net subsystem doesn't depend on `narf-filesystem` directly
//! (would create a cycle: net → fs → net). Instead, each
//! subsystem exposes a hook the FS calls into. The hooks are
//! function pointers stored as `AtomicUsize`, installed by the net
//! crate's `init_procfs_net` at boot. When a hook is absent, the
//! corresponding /proc/net/* file renders as empty (header only) —
//! matches what Linux does when the protocol module isn't loaded.
//!
//! Linux refs:
//! - `net/ipv4/proc.c`         /proc/net/{snmp,sockstat,...}
//! - `net/ipv4/tcp_ipv4.c`     `tcp4_seq_show` for /proc/net/tcp
//! - `net/ipv4/udp.c`          `udp4_seq_show` for /proc/net/udp
//! - `net/ipv4/route.c`        `rt_cpu_seq_show` for /proc/net/route
//! - `net/ipv4/arp.c`          `arp_seq_show` for /proc/net/arp
//! - `net/core/net-procfs.c`   `dev_seq_show` for /proc/net/dev
//! - `net/ipv6/proc.c`         /proc/net/{tcp6,udp6,...}
//! - `net/ipv6/addrconf.c`     `if6_seq_show` for /proc/net/if_inet6
//! - `net/ipv6/route.c`        for /proc/net/ipv6_route
//! - `net/netfilter/nf_conntrack_standalone.c`
//!   `ct_seq_show` for /proc/net/nf_conntrack

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::{register_proc, slice_read, ProcFile};
use narf_lib::sync::{IrqSafeSpinLock, OnceLock};

// ── Net-subsystem snapshot hooks ────────────────────────────────
//
// Function-pointer slots, set by `net::procfs::install_hooks` at
// boot. Each hook returns either a single `String` (for files
// already rendered upstream) or a typed `Vec<…>` the local
// renderer turns into a Linux-formatted line set.

/// Snapshot of one TCB for /proc/net/tcp. Fields chosen to match
/// the columns Linux emits in `tcp4_seq_show`.
#[derive(Clone, Debug)]
pub struct TcbSnapshot {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    /// TCP state code per Linux's tcp_state numbering
    /// (`include/net/tcp_states.h`): 01=ESTABLISHED, 02=SYN_SENT,
    /// 03=SYN_RECV, 04=FIN_WAIT1, 05=FIN_WAIT2, 06=TIME_WAIT,
    /// 07=CLOSE, 08=CLOSE_WAIT, 09=LAST_ACK, 0A=LISTEN, 0B=CLOSING.
    pub state_code: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub retrnsmt: u32,
    pub timer_active: u8,
    pub timer_expires: u32,
    pub probes_out: u32,
    pub rto: u32,
    pub ack_timeout: u32,
    pub snd_cwnd: u32,
    pub snd_ssthresh: i32,
    pub uid: u32,
    pub timeout: u32,
    pub inode: u64,
}

#[derive(Clone, Debug)]
pub struct UdpSocketSnapshot {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    /// Connected sockets have a peer set, so report state=07 (CLOSE
    /// per Linux's UDP convention — UDP has no real state, but ss
    /// expects this column to exist) for unconnected, 01 for
    /// connected — matches what `udp4_seq_show` would print.
    pub state_code: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub uid: u32,
    pub inode: u64,
}

#[derive(Clone, Debug)]
pub struct RawSocketSnapshot {
    pub local_addr: [u8; 4],
    pub remote_addr: [u8; 4],
    pub state_code: u8,
    pub uid: u32,
    pub inode: u64,
    pub protocol: u8,
}

#[derive(Clone, Debug)]
pub struct ArpSnapshot {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub iface: String,
    /// Linux flags from `net/ipv4/arp.c::arp_seq_show`:
    /// 0x0=Incomplete, 0x2=Complete, 0x4=Permanent, 0x6=Pub.
    pub flags: u8,
}

#[derive(Clone, Debug)]
pub struct RouteSnapshot {
    pub iface: String,
    /// Destination network address in network byte order.
    pub dst: [u8; 4],
    /// Gateway address in network byte order (0.0.0.0 = none).
    pub gateway: [u8; 4],
    /// Linux flag bits (RTF_UP=1, RTF_GATEWAY=2, RTF_HOST=4, ...).
    pub flags: u16,
    pub refcnt: u32,
    pub use_count: u32,
    pub metric: u32,
    /// Subnet mask in network byte order.
    pub mask: [u8; 4],
    pub mtu: u32,
    pub window: u32,
    pub irtt: u32,
}

#[derive(Clone, Debug)]
pub struct IfaceCounterSnapshot {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub rx_fifo: u64,
    pub rx_frame: u64,
    pub rx_compressed: u64,
    pub rx_multicast: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
    pub tx_fifo: u64,
    pub tx_colls: u64,
    pub tx_carrier: u64,
    pub tx_compressed: u64,
}

#[derive(Clone, Debug)]
pub struct Ipv6IfAddrSnapshot {
    pub iface: String,
    pub addr: [u8; 16],
    /// Linux `if_inet6` device index — 1-based; we use the
    /// caller-supplied value.
    pub ifindex: u32,
    pub prefix_len: u8,
    /// Address scope per RFC 4291 §2.7 — encoded as Linux's
    /// `inet6_ifaddr.scope` (0=Global, 0x10=LinkLocal, 0x20=SiteLocal).
    pub scope: u8,
    /// Address flags bitmap (Linux IFA_F_* — Tentative=0x40,
    /// Permanent=0x80, Deprecated=0x20).
    pub flags: u8,
}

#[derive(Clone, Debug)]
pub struct Ipv6RouteSnapshot {
    pub dst: [u8; 16],
    pub dst_prefix_len: u8,
    pub src: [u8; 16],
    pub src_prefix_len: u8,
    pub gateway: [u8; 16],
    pub metric: u32,
    pub refcnt: u32,
    pub use_count: u32,
    pub flags: u32,
    pub iface: String,
}

#[derive(Clone, Debug)]
pub struct ConntrackSnapshot {
    /// "ipv4" or "ipv6".
    pub l3proto: &'static str,
    /// 2 for IPv4, 10 for IPv6 (Linux AF_INET / AF_INET6).
    pub l3proto_num: u8,
    /// "tcp", "udp", "icmp", ...
    pub l4proto: &'static str,
    /// IPPROTO number (6=tcp, 17=udp, 1=icmp).
    pub l4proto_num: u8,
    pub timeout: u32,
    pub state: &'static str,
    pub orig_src: [u8; 4],
    pub orig_dst: [u8; 4],
    pub orig_sport: u16,
    pub orig_dport: u16,
    pub reply_src: [u8; 4],
    pub reply_dst: [u8; 4],
    pub reply_sport: u16,
    pub reply_dport: u16,
    pub assured: bool,
    pub use_count: u32,
}

/// SNMP MIB counters per RFC 1213 — populated by the net stack.
#[derive(Clone, Debug, Default)]
pub struct SnmpMib {
    // IP
    pub ip_forwarding: u64,
    pub ip_default_ttl: u64,
    pub ip_in_receives: u64,
    pub ip_in_hdr_errors: u64,
    pub ip_in_addr_errors: u64,
    pub ip_forwd_datagrams: u64,
    pub ip_in_unknown_protos: u64,
    pub ip_in_discards: u64,
    pub ip_in_delivers: u64,
    pub ip_out_requests: u64,
    pub ip_out_discards: u64,
    pub ip_out_no_routes: u64,
    pub ip_reasm_timeout: u64,
    pub ip_reasm_reqds: u64,
    pub ip_reasm_oks: u64,
    pub ip_reasm_fails: u64,
    pub ip_frag_oks: u64,
    pub ip_frag_fails: u64,
    pub ip_frag_creates: u64,

    // ICMP
    pub icmp_in_msgs: u64,
    pub icmp_in_errors: u64,
    pub icmp_in_dest_unreachs: u64,
    pub icmp_in_time_excds: u64,
    pub icmp_in_parm_probs: u64,
    pub icmp_in_src_quenchs: u64,
    pub icmp_in_redirects: u64,
    pub icmp_in_echos: u64,
    pub icmp_in_echo_reps: u64,
    pub icmp_in_timestamps: u64,
    pub icmp_in_timestamp_reps: u64,
    pub icmp_in_addr_masks: u64,
    pub icmp_in_addr_mask_reps: u64,
    pub icmp_out_msgs: u64,
    pub icmp_out_errors: u64,
    pub icmp_out_dest_unreachs: u64,
    pub icmp_out_time_excds: u64,
    pub icmp_out_parm_probs: u64,
    pub icmp_out_src_quenchs: u64,
    pub icmp_out_redirects: u64,
    pub icmp_out_echos: u64,
    pub icmp_out_echo_reps: u64,
    pub icmp_out_timestamps: u64,
    pub icmp_out_timestamp_reps: u64,
    pub icmp_out_addr_masks: u64,
    pub icmp_out_addr_mask_reps: u64,

    // TCP (15 standard MIB counters)
    pub tcp_rto_algorithm: u64,
    pub tcp_rto_min: u64,
    pub tcp_rto_max: u64,
    pub tcp_max_conn: u64,
    pub tcp_active_opens: u64,
    pub tcp_passive_opens: u64,
    pub tcp_attempt_fails: u64,
    pub tcp_estab_resets: u64,
    pub tcp_curr_estab: u64,
    pub tcp_in_segs: u64,
    pub tcp_out_segs: u64,
    pub tcp_retrans_segs: u64,
    pub tcp_in_errs: u64,
    pub tcp_out_rsts: u64,
    pub tcp_in_csum_errors: u64,

    // UDP
    pub udp_in_datagrams: u64,
    pub udp_no_ports: u64,
    pub udp_in_errors: u64,
    pub udp_out_datagrams: u64,
    pub udp_rcvbuf_errors: u64,
    pub udp_sndbuf_errors: u64,
    pub udp_in_csum_errors: u64,
    pub udp_ignored_multi: u64,
}

#[derive(Clone, Debug)]
pub struct IgmpSnapshot {
    pub ifindex: u32,
    pub iface: String,
    pub group: [u8; 4],
    pub users: u32,
    pub timer: u32,
    pub reporter: u8,
}

#[derive(Clone, Debug)]
pub struct Igmp6Snapshot {
    pub iface: String,
    pub ifindex: u32,
    pub group: [u8; 16],
    pub users: u32,
    pub flags: u32,
    pub timer: u32,
}

// ── Hook slots ──────────────────────────────────────────────────

type TcpSnapshotFn = fn(u64) -> Vec<TcbSnapshot>;
type UdpSnapshotFn = fn(u64) -> Vec<UdpSocketSnapshot>;
type RawSnapshotFn = fn(u64) -> Vec<RawSocketSnapshot>;
type ArpSnapshotFn = fn(u64) -> Vec<ArpSnapshot>;
type RouteSnapshotFn = fn(u64) -> Vec<RouteSnapshot>;
type IfaceCountersFn = fn(u64) -> Vec<IfaceCounterSnapshot>;
type Ipv6IfAddrFn = fn(u64) -> Vec<Ipv6IfAddrSnapshot>;
type Ipv6RouteFn = fn(u64) -> Vec<Ipv6RouteSnapshot>;
type ConntrackFn = fn(u64) -> Vec<ConntrackSnapshot>;
type SnmpFn = fn(u64) -> SnmpMib;
type IgmpFn = fn(u64) -> Vec<IgmpSnapshot>;
type Igmp6Fn = fn(u64) -> Vec<Igmp6Snapshot>;
type Tcp6SnapshotFn = fn(u64) -> Vec<Tcb6Snapshot>;
type Udp6SnapshotFn = fn(u64) -> Vec<Udp6SocketSnapshot>;
type Raw6SnapshotFn = fn(u64) -> Vec<Raw6SocketSnapshot>;

#[derive(Clone, Debug)]
pub struct Tcb6Snapshot {
    pub local_addr: [u8; 16],
    pub local_port: u16,
    pub remote_addr: [u8; 16],
    pub remote_port: u16,
    pub state_code: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub retrnsmt: u32,
    pub uid: u32,
    pub timeout: u32,
    pub inode: u64,
}

#[derive(Clone, Debug)]
pub struct Udp6SocketSnapshot {
    pub local_addr: [u8; 16],
    pub local_port: u16,
    pub remote_addr: [u8; 16],
    pub remote_port: u16,
    pub state_code: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
    pub uid: u32,
    pub inode: u64,
}

#[derive(Clone, Debug)]
pub struct Raw6SocketSnapshot {
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
    pub state_code: u8,
    pub uid: u32,
    pub inode: u64,
    pub protocol: u8,
}

static TCP_HOOK: AtomicUsize = AtomicUsize::new(0);
static UDP_HOOK: AtomicUsize = AtomicUsize::new(0);
static RAW_HOOK: AtomicUsize = AtomicUsize::new(0);
static ARP_HOOK: AtomicUsize = AtomicUsize::new(0);
static ROUTE_HOOK: AtomicUsize = AtomicUsize::new(0);
static IFACE_COUNTERS_HOOK: AtomicUsize = AtomicUsize::new(0);
static IPV6_IFADDR_HOOK: AtomicUsize = AtomicUsize::new(0);
static IPV6_ROUTE_HOOK: AtomicUsize = AtomicUsize::new(0);
static CONNTRACK_HOOK: AtomicUsize = AtomicUsize::new(0);
static SNMP_HOOK: AtomicUsize = AtomicUsize::new(0);
static IGMP_HOOK: AtomicUsize = AtomicUsize::new(0);
static IGMP6_HOOK: AtomicUsize = AtomicUsize::new(0);
static TCP6_HOOK: AtomicUsize = AtomicUsize::new(0);
static UDP6_HOOK: AtomicUsize = AtomicUsize::new(0);
static RAW6_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the per-subsystem snapshot hooks. Called by the net
/// crate's init path before `register_all()` exposes the files.
#[allow(clippy::too_many_arguments)] // one arg per protocol hook; bundling would obscure the layout
pub fn install_hooks(
    tcp: TcpSnapshotFn,
    udp: UdpSnapshotFn,
    raw: RawSnapshotFn,
    arp: ArpSnapshotFn,
    route: RouteSnapshotFn,
    iface_counters: IfaceCountersFn,
    ipv6_ifaddr: Ipv6IfAddrFn,
    ipv6_route: Ipv6RouteFn,
    conntrack: ConntrackFn,
    snmp: SnmpFn,
    igmp: IgmpFn,
    igmp6: Igmp6Fn,
    tcp6: Tcp6SnapshotFn,
    udp6: Udp6SnapshotFn,
    raw6: Raw6SnapshotFn,
) {
    TCP_HOOK.store(tcp as usize, Ordering::Release);
    UDP_HOOK.store(udp as usize, Ordering::Release);
    RAW_HOOK.store(raw as usize, Ordering::Release);
    ARP_HOOK.store(arp as usize, Ordering::Release);
    ROUTE_HOOK.store(route as usize, Ordering::Release);
    IFACE_COUNTERS_HOOK.store(iface_counters as usize, Ordering::Release);
    IPV6_IFADDR_HOOK.store(ipv6_ifaddr as usize, Ordering::Release);
    IPV6_ROUTE_HOOK.store(ipv6_route as usize, Ordering::Release);
    CONNTRACK_HOOK.store(conntrack as usize, Ordering::Release);
    SNMP_HOOK.store(snmp as usize, Ordering::Release);
    IGMP_HOOK.store(igmp as usize, Ordering::Release);
    IGMP6_HOOK.store(igmp6 as usize, Ordering::Release);
    TCP6_HOOK.store(tcp6 as usize, Ordering::Release);
    UDP6_HOOK.store(udp6 as usize, Ordering::Release);
    RAW6_HOOK.store(raw6 as usize, Ordering::Release);
}

fn tcp_snapshot(namespace: u64) -> Vec<TcbSnapshot> {
    let v = TCP_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a TcpSnapshotFn fn-pointer; non-zero confirms it.
    let f: TcpSnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn udp_snapshot(namespace: u64) -> Vec<UdpSocketSnapshot> {
    let v = UDP_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a UdpSnapshotFn fn-pointer; non-zero confirms it.
    let f: UdpSnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn raw_snapshot(namespace: u64) -> Vec<RawSocketSnapshot> {
    let v = RAW_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a RawSnapshotFn fn-pointer; non-zero confirms it.
    let f: RawSnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn arp_snapshot(namespace: u64) -> Vec<ArpSnapshot> {
    let v = ARP_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as an ArpSnapshotFn fn-pointer; non-zero confirms it.
    let f: ArpSnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn route_snapshot(namespace: u64) -> Vec<RouteSnapshot> {
    let v = ROUTE_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a RouteSnapshotFn fn-pointer; non-zero confirms it.
    let f: RouteSnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn iface_counters(namespace: u64) -> Vec<IfaceCounterSnapshot> {
    let v = IFACE_COUNTERS_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as an IfaceCountersFn fn-pointer; non-zero confirms it.
    let f: IfaceCountersFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn ipv6_ifaddr_snapshot(namespace: u64) -> Vec<Ipv6IfAddrSnapshot> {
    let v = IPV6_IFADDR_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as an Ipv6IfAddrFn fn-pointer; non-zero confirms it.
    let f: Ipv6IfAddrFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn ipv6_route_snapshot(namespace: u64) -> Vec<Ipv6RouteSnapshot> {
    let v = IPV6_ROUTE_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as an Ipv6RouteFn fn-pointer; non-zero confirms it.
    let f: Ipv6RouteFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn conntrack_snapshot(namespace: u64) -> Vec<ConntrackSnapshot> {
    let v = CONNTRACK_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a ConntrackFn fn-pointer; non-zero confirms it.
    let f: ConntrackFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn snmp_snapshot(namespace: u64) -> SnmpMib {
    let v = SNMP_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return SnmpMib::default();
    }
    // SAFETY: v was stored by install_hooks as a SnmpFn fn-pointer; non-zero confirms it.
    let f: SnmpFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn igmp_snapshot(namespace: u64) -> Vec<IgmpSnapshot> {
    let v = IGMP_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as an IgmpFn fn-pointer; non-zero confirms it.
    let f: IgmpFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn igmp6_snapshot(namespace: u64) -> Vec<Igmp6Snapshot> {
    let v = IGMP6_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as an Igmp6Fn fn-pointer; non-zero confirms it.
    let f: Igmp6Fn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn tcp6_snapshot(namespace: u64) -> Vec<Tcb6Snapshot> {
    let v = TCP6_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a Tcp6SnapshotFn fn-pointer; non-zero confirms it.
    let f: Tcp6SnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn udp6_snapshot(namespace: u64) -> Vec<Udp6SocketSnapshot> {
    let v = UDP6_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a Udp6SnapshotFn fn-pointer; non-zero confirms it.
    let f: Udp6SnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

fn raw6_snapshot(namespace: u64) -> Vec<Raw6SocketSnapshot> {
    let v = RAW6_HOOK.load(Ordering::Acquire);
    if v == 0 {
        return Vec::new();
    }
    // SAFETY: v was stored by install_hooks as a Raw6SnapshotFn fn-pointer; non-zero confirms it.
    let f: Raw6SnapshotFn = unsafe { core::mem::transmute(v) };
    f(namespace)
}

// ── Formatting helpers ──────────────────────────────────────────

/// Format an IPv4 address + port as Linux's `AABBCCDD:PPPP` style.
/// The address bytes go big-endian-first into the hex string, but
/// each *u32 word* is little-endian: Linux prints
/// `127.0.0.1` as `0100007F` because each 4-byte network-order word
/// is reversed to host order on x86. We mirror that here so
/// netstat's parser sees the same string.
///
/// Linux ref: `net/ipv4/tcp_ipv4.c:get_tcp4_sock`.
pub(crate) fn fmt_ipv4_port(addr: [u8; 4], port: u16) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(13);
    // Little-endian per-word: print bytes in reverse host order.
    let _ = write!(
        s,
        "{:02X}{:02X}{:02X}{:02X}:{:04X}",
        addr[3], addr[2], addr[1], addr[0], port
    );
    s
}

/// Format an IPv6 address + port as Linux's 32-hex-digit style. The
/// IPv6 address is split into four 32-bit words and each word is
/// printed in host-endian (little-endian on x86) — same pattern as
/// IPv4 above. Linux ref: `net/ipv6/tcp_ipv6.c:get_tcp6_sock`.
pub(crate) fn fmt_ipv6_port(addr: [u8; 16], port: u16) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(38);
    for word in 0..4 {
        let base = word * 4;
        // Little-endian word print.
        let _ = write!(
            s,
            "{:02X}{:02X}{:02X}{:02X}",
            addr[base + 3],
            addr[base + 2],
            addr[base + 1],
            addr[base]
        );
    }
    let _ = write!(s, ":{:04X}", port);
    s
}

/// Format an IPv6 address as 32 hex digits with no port/colon.
/// Used by /proc/net/if_inet6 + ipv6_route which encode addresses
/// purely as packed hex bytes (no per-word endian swap; the file
/// is documented in addrconf.c as "raw bytes hexlified").
pub(crate) fn fmt_ipv6_raw(addr: [u8; 16]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(32);
    for b in addr.iter() {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// One-line shared header used by /proc/net/{tcp,udp,raw,tcp6,udp6,raw6}.
/// Trailing newline included so the per-line emitter just writes
/// the next line directly.
const SOCK_HDR_LINE: &str =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

// ── ProcFile impls ──────────────────────────────────────────────

fn render_tcp(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(SOCK_HDR_LINE);
    for (i, tcb) in tcp_snapshot(namespace).into_iter().enumerate() {
        let local = fmt_ipv4_port(tcb.local_addr, tcb.local_port);
        let remote = fmt_ipv4_port(tcb.remote_addr, tcb.remote_port);
        let _ = writeln!(
            s,
            "{:>4}: {} {} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:>5} {:>8} {} 2 0000000000000000 {:>8} {:>8} 0 {:>5} {:>5}",
            i,
            local,
            remote,
            tcb.state_code,
            tcb.tx_queue,
            tcb.rx_queue,
            tcb.timer_active,
            tcb.timer_expires,
            tcb.retrnsmt,
            tcb.uid,
            tcb.probes_out,
            tcb.inode,
            tcb.rto,
            tcb.ack_timeout,
            tcb.snd_cwnd,
            tcb.snd_ssthresh,
        );
    }
    s.into_bytes()
}

fn render_udp(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(SOCK_HDR_LINE);
    for (i, u) in udp_snapshot(namespace).into_iter().enumerate() {
        let local = fmt_ipv4_port(u.local_addr, u.local_port);
        let remote = fmt_ipv4_port(u.remote_addr, u.remote_port);
        let _ = writeln!(
            s,
            "{:>4}: {} {} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:>5}        0 {} 2 0 0 0 0 ",
            i, local, remote, u.state_code, u.tx_queue, u.rx_queue, 0u8, 0u32, 0u32, u.uid, u.inode,
        );
    }
    s.into_bytes()
}

fn render_raw(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(SOCK_HDR_LINE);
    for (i, r) in raw_snapshot(namespace).into_iter().enumerate() {
        let local = fmt_ipv4_port(r.local_addr, u16::from(r.protocol));
        let remote = fmt_ipv4_port(r.remote_addr, 0);
        let _ = writeln!(
            s,
            "{:>4}: {} {} {:02X} 00000000:00000000 00:00000000 00000000 {:>5}        0 {} 2 0 ",
            i, local, remote, r.state_code, r.uid, r.inode,
        );
    }
    s.into_bytes()
}

fn render_tcp6(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(SOCK_HDR_LINE);
    for (i, tcb) in tcp6_snapshot(namespace).into_iter().enumerate() {
        let local = fmt_ipv6_port(tcb.local_addr, tcb.local_port);
        let remote = fmt_ipv6_port(tcb.remote_addr, tcb.remote_port);
        let _ = writeln!(
            s,
            "{:>4}: {} {} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:>5}        0 {} ",
            i,
            local,
            remote,
            tcb.state_code,
            tcb.tx_queue,
            tcb.rx_queue,
            0u8,
            0u32,
            tcb.retrnsmt,
            tcb.uid,
            tcb.inode,
        );
    }
    s.into_bytes()
}

fn render_udp6(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(SOCK_HDR_LINE);
    for (i, u) in udp6_snapshot(namespace).into_iter().enumerate() {
        let local = fmt_ipv6_port(u.local_addr, u.local_port);
        let remote = fmt_ipv6_port(u.remote_addr, u.remote_port);
        let _ = writeln!(
            s,
            "{:>4}: {} {} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:>5}        0 {} 2 0 0 0 0 ",
            i, local, remote, u.state_code, u.tx_queue, u.rx_queue, 0u8, 0u32, 0u32, u.uid, u.inode,
        );
    }
    s.into_bytes()
}

fn render_raw6(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(SOCK_HDR_LINE);
    for (i, r) in raw6_snapshot(namespace).into_iter().enumerate() {
        let local = fmt_ipv6_port(r.local_addr, u16::from(r.protocol));
        let remote = fmt_ipv6_port(r.remote_addr, 0);
        let _ = writeln!(
            s,
            "{:>4}: {} {} {:02X} 00000000:00000000 00:00000000 00000000 {:>5}        0 {} 2 0 ",
            i, local, remote, r.state_code, r.uid, r.inode,
        );
    }
    s.into_bytes()
}

fn render_sockstat(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let tcp = tcp_snapshot(namespace);
    let udp = udp_snapshot(namespace);
    let raw = raw_snapshot(namespace);
    let tcp_inuse = tcp.iter().filter(|t| t.state_code != 0x06).count();
    let tcp_tw = tcp.len().saturating_sub(tcp_inuse);
    let used = tcp
        .len()
        .saturating_add(udp.len())
        .saturating_add(raw.len());
    let mut s = String::new();
    let _ = writeln!(s, "sockets: used {used}");
    let _ = writeln!(
        s,
        "TCP: inuse {tcp_inuse} orphan 0 tw {tcp_tw} alloc {} mem 0",
        tcp.len()
    );
    let _ = writeln!(s, "UDP: inuse {} mem 0", udp.len());
    let _ = writeln!(s, "UDPLITE: inuse 0");
    let _ = writeln!(s, "RAW: inuse {}", raw.len());
    let _ = writeln!(s, "FRAG: inuse 0 memory 0");
    s.into_bytes()
}

fn render_sockstat6(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "TCP6: inuse {}", tcp6_snapshot(namespace).len());
    let _ = writeln!(s, "UDP6: inuse {}", udp6_snapshot(namespace).len());
    let _ = writeln!(s, "UDPLITE6: inuse 0");
    let _ = writeln!(s, "RAW6: inuse {}", raw6_snapshot(namespace).len());
    let _ = writeln!(s, "FRAG6: inuse 0 memory 0");
    s.into_bytes()
}

fn render_netstat(namespace: u64) -> Vec<u8> {
    let m = snmp_snapshot(namespace);
    // Linux emits each MIB family as a header row followed by a value row.
    // Keep the two lists positionally identical: iproute2 and procps parse
    // them by zipping fields rather than by accepting ad-hoc key/value text.
    alloc::format!(
        "TcpExt: SyncookiesSent SyncookiesRecv SyncookiesFailed EmbryonicRsts PruneCalled RcvPruned OfoPruned OutOfWindowIcmps LockDroppedIcmps TW TWRecycled TWKilled PAWSActive PAWSEstab DelayedACKs DelayedACKLocked DelayedACKLost ListenOverflows ListenDrops TCPTimeouts TCPRetransFail\n\
TcpExt: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {} 0\n\
IpExt: InNoRoutes InTruncatedPkts InMcastPkts OutMcastPkts InBcastPkts OutBcastPkts InOctets OutOctets InNoECTPkts InECT1Pkts InECT0Pkts InCEPkts\n\
IpExt: {} 0 0 0 0 0 0 0 0 0 0 0\n\
MPTcpExt: MPCapableSYNRX MPCapableSYNTX MPCapableSYNACKRX MPCapableACKRX\n\
MPTcpExt: 0 0 0 0\n",
        m.tcp_attempt_fails,
        m.ip_out_no_routes,
    )
    .into_bytes()
}

fn render_snmp6(namespace: u64) -> Vec<u8> {
    let m = snmp_snapshot(namespace);
    alloc::format!(
        "Ip6InReceives                  {}\n\
Ip6InHdrErrors                 {}\n\
Ip6InAddrErrors                {}\n\
Ip6InUnknownProtos             {}\n\
Ip6InDiscards                  {}\n\
Ip6InDelivers                  {}\n\
Ip6OutForwDatagrams            {}\n\
Ip6OutRequests                 {}\n\
Ip6OutDiscards                 {}\n\
Ip6OutNoRoutes                 {}\n\
Icmp6InMsgs                    {}\n\
Icmp6InErrors                  {}\n\
Icmp6OutMsgs                   {}\n\
Icmp6OutErrors                 {}\n\
Udp6InDatagrams                {}\n\
Udp6NoPorts                    {}\n\
Udp6InErrors                   {}\n\
Udp6OutDatagrams               {}\n",
        m.ip_in_receives,
        m.ip_in_hdr_errors,
        m.ip_in_addr_errors,
        m.ip_in_unknown_protos,
        m.ip_in_discards,
        m.ip_in_delivers,
        m.ip_forwd_datagrams,
        m.ip_out_requests,
        m.ip_out_discards,
        m.ip_out_no_routes,
        m.icmp_in_msgs,
        m.icmp_in_errors,
        m.icmp_out_msgs,
        m.icmp_out_errors,
        m.udp_in_datagrams,
        m.udp_no_ports,
        m.udp_in_errors,
        m.udp_out_datagrams,
    )
    .into_bytes()
}

fn render_arp(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "IP address       HW type     Flags       HW address            Mask     Device\n",
    );
    for e in arp_snapshot(namespace) {
        let _ = writeln!(
            s,
            "{:<16} 0x1         0x{:X}         {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}     *        {}",
            alloc::format!("{}.{}.{}.{}", e.ip[0], e.ip[1], e.ip[2], e.ip[3]),
            e.flags,
            e.mac[0], e.mac[1], e.mac[2], e.mac[3], e.mac[4], e.mac[5],
            e.iface,
        );
    }
    s.into_bytes()
}

fn render_route(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
    );
    for r in route_snapshot(namespace) {
        // Linux uses host-endian hex per u32. Same trick as the
        // tcp file: bytes printed in reverse to match the host
        // byte order on x86.
        let dst_hex = u32::from_le_bytes(r.dst);
        let gw_hex = u32::from_le_bytes(r.gateway);
        let mask_hex = u32::from_le_bytes(r.mask);
        let _ = writeln!(
            s,
            "{}\t{:08X}\t{:08X}\t{:04X}\t{}\t{}\t{}\t{:08X}\t{}\t{}\t{}",
            r.iface,
            dst_hex,
            gw_hex,
            r.flags,
            r.refcnt,
            r.use_count,
            r.metric,
            mask_hex,
            r.mtu,
            r.window,
            r.irtt,
        );
    }
    s.into_bytes()
}

fn render_dev(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for c in iface_counters(namespace) {
        let _ = writeln!(
            s,
            "{:>6}: {:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>10} {:>9} {:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>7} {:>10}",
            c.name,
            c.rx_bytes, c.rx_packets, c.rx_errs, c.rx_drop,
            c.rx_fifo, c.rx_frame, c.rx_compressed, c.rx_multicast,
            c.tx_bytes, c.tx_packets, c.tx_errs, c.tx_drop,
            c.tx_fifo, c.tx_colls, c.tx_carrier, c.tx_compressed,
        );
    }
    s.into_bytes()
}

fn render_if_inet6(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    for a in ipv6_ifaddr_snapshot(namespace) {
        // Linux format (one line per address):
        //   <32-hex-addr> <ifindex-hex> <prefix_len-hex>
        //   <scope-hex> <flags-hex> <devname>
        let _ = writeln!(
            s,
            "{} {:02x} {:02x} {:02x} {:02x} {:>8}",
            fmt_ipv6_raw(a.addr),
            a.ifindex,
            a.prefix_len,
            a.scope,
            a.flags,
            a.iface,
        );
    }
    s.into_bytes()
}

fn render_ipv6_route(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    for r in ipv6_route_snapshot(namespace) {
        // Linux net/ipv6/route.c::rt6_info_format:
        //   <dst> <plen> <src> <splen> <next-hop> <metric>
        //   <ref> <use> <flags> <device>
        let _ = writeln!(
            s,
            "{} {:02x} {} {:02x} {} {:08x} {:08x} {:08x} {:08x} {:>8}",
            fmt_ipv6_raw(r.dst),
            r.dst_prefix_len,
            fmt_ipv6_raw(r.src),
            r.src_prefix_len,
            fmt_ipv6_raw(r.gateway),
            r.metric,
            r.refcnt,
            r.use_count,
            r.flags,
            r.iface,
        );
    }
    s.into_bytes()
}

fn render_igmp(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    // Linux /proc/net/igmp header: 1 line per interface, then
    // 1 line per joined group indented by tab. Even with no
    // groups the file always exists with at least the version
    // marker so libnetfilter-mcast probes succeed.
    let mut s = String::from("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    let groups = igmp_snapshot(namespace);
    for iface in groups.chunk_by(|a, b| a.ifindex == b.ifindex) {
        let first = &iface[0];
        let _ = writeln!(
            s,
            "{}\t{:<10}: {:5} {:>7}",
            first.ifindex,
            first.iface,
            iface.len(),
            "V3"
        );
        for group in iface {
            let _ = writeln!(
                s,
                "\t\t\t\t{:08X} {:5} {}:{:08X}\t\t{}",
                u32::from_ne_bytes(group.group),
                group.users,
                u8::from(group.timer != 0),
                group.timer,
                group.reporter
            );
        }
    }
    s.into_bytes()
}

fn render_igmp6(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    for g in igmp6_snapshot(namespace) {
        let _ = writeln!(
            s,
            "{:<4} {:<15} {} {:5} {:08X} {}",
            g.ifindex,
            g.iface,
            fmt_ipv6_raw(g.group),
            g.users,
            g.flags,
            g.timer,
        );
    }
    s.into_bytes()
}

fn render_snmp(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let m = snmp_snapshot(namespace);
    let mut s = String::new();
    // IP MIB
    let _ = writeln!(
        s,
        "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates",
    );
    let _ = writeln!(
        s,
        "Ip: {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        m.ip_forwarding,
        m.ip_default_ttl,
        m.ip_in_receives,
        m.ip_in_hdr_errors,
        m.ip_in_addr_errors,
        m.ip_forwd_datagrams,
        m.ip_in_unknown_protos,
        m.ip_in_discards,
        m.ip_in_delivers,
        m.ip_out_requests,
        m.ip_out_discards,
        m.ip_out_no_routes,
        m.ip_reasm_timeout,
        m.ip_reasm_reqds,
        m.ip_reasm_oks,
        m.ip_reasm_fails,
        m.ip_frag_oks,
        m.ip_frag_fails,
        m.ip_frag_creates,
    );
    // ICMP MIB
    let _ = writeln!(
        s,
        "Icmp: InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps",
    );
    let _ = writeln!(
        s,
        "Icmp: {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        m.icmp_in_msgs,
        m.icmp_in_errors,
        m.icmp_in_dest_unreachs,
        m.icmp_in_time_excds,
        m.icmp_in_parm_probs,
        m.icmp_in_src_quenchs,
        m.icmp_in_redirects,
        m.icmp_in_echos,
        m.icmp_in_echo_reps,
        m.icmp_in_timestamps,
        m.icmp_in_timestamp_reps,
        m.icmp_in_addr_masks,
        m.icmp_in_addr_mask_reps,
        m.icmp_out_msgs,
        m.icmp_out_errors,
        m.icmp_out_dest_unreachs,
        m.icmp_out_time_excds,
        m.icmp_out_parm_probs,
        m.icmp_out_src_quenchs,
        m.icmp_out_redirects,
        m.icmp_out_echos,
        m.icmp_out_echo_reps,
        m.icmp_out_timestamps,
        m.icmp_out_timestamp_reps,
        m.icmp_out_addr_masks,
        m.icmp_out_addr_mask_reps,
    );
    // TCP MIB — 15 standard counters per RFC 1213.
    let _ = writeln!(
        s,
        "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors",
    );
    let _ = writeln!(
        s,
        "Tcp: {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        m.tcp_rto_algorithm,
        m.tcp_rto_min,
        m.tcp_rto_max,
        // `snmp_seq_show_tcp_udp` prints MaxConn signed: RFC 2012's
        // "dynamic" is -1, not 18446744073709551615.
        m.tcp_max_conn as i64,
        m.tcp_active_opens,
        m.tcp_passive_opens,
        m.tcp_attempt_fails,
        m.tcp_estab_resets,
        m.tcp_curr_estab,
        m.tcp_in_segs,
        m.tcp_out_segs,
        m.tcp_retrans_segs,
        m.tcp_in_errs,
        m.tcp_out_rsts,
        m.tcp_in_csum_errors,
    );
    // UDP MIB
    let _ = writeln!(
        s,
        "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti",
    );
    let _ = writeln!(
        s,
        "Udp: {} {} {} {} {} {} {} {}",
        m.udp_in_datagrams,
        m.udp_no_ports,
        m.udp_in_errors,
        m.udp_out_datagrams,
        m.udp_rcvbuf_errors,
        m.udp_sndbuf_errors,
        m.udp_in_csum_errors,
        m.udp_ignored_multi,
    );
    s.into_bytes()
}

fn render_nf_conntrack(namespace: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut s = String::new();
    for ct in conntrack_snapshot(namespace) {
        // Linux ref: net/netfilter/nf_conntrack_standalone.c::ct_seq_show
        // <l3proto> <l3proto_num> <l4proto> <l4proto_num>
        //   <timeout> <state>
        //   src=... dst=... sport=... dport=...
        //   src=... dst=... sport=... dport=...
        //   [ASSURED] mark=0 use=N
        let _ = write!(
            s,
            "{:<8} {} {:<7} {} {:>6} {:<10} src={}.{}.{}.{} dst={}.{}.{}.{} sport={} dport={} src={}.{}.{}.{} dst={}.{}.{}.{} sport={} dport={}",
            ct.l3proto, ct.l3proto_num,
            ct.l4proto, ct.l4proto_num,
            ct.timeout, ct.state,
            ct.orig_src[0], ct.orig_src[1], ct.orig_src[2], ct.orig_src[3],
            ct.orig_dst[0], ct.orig_dst[1], ct.orig_dst[2], ct.orig_dst[3],
            ct.orig_sport, ct.orig_dport,
            ct.reply_src[0], ct.reply_src[1], ct.reply_src[2], ct.reply_src[3],
            ct.reply_dst[0], ct.reply_dst[1], ct.reply_dst[2], ct.reply_dst[3],
            ct.reply_sport, ct.reply_dport,
        );
        if ct.assured {
            let _ = write!(s, " [ASSURED]");
        }
        let _ = writeln!(s, " mark=0 use={}", ct.use_count);
    }
    s.into_bytes()
}

// ── Public registration ─────────────────────────────────────────

/// Selection retained until the last reference to the open table is dropped.
#[derive(Debug)]
pub enum TableNamespace {
    Initial,
    Private(Arc<dyn crate::NsObject>),
}

impl TableNamespace {
    fn id(&self) -> u64 {
        match self {
            Self::Initial => 0,
            Self::Private(namespace) => namespace.ns_id(),
        }
    }
}

type NamespaceResolver = fn(Option<u64>) -> Option<TableNamespace>;
static NAMESPACE_RESOLVER: OnceLock<NamespaceResolver> = OnceLock::new();

/// Select the calling thread (None) or an outer PID/TID. A missing target has no view.
pub fn install_namespace_resolver(resolve: NamespaceResolver) {
    let _ = NAMESPACE_RESOLVER.set(resolve);
}

fn resolve_namespace(target: Option<u64>) -> Option<TableNamespace> {
    match NAMESPACE_RESOLVER.get() {
        Some(resolve) => resolve(target),
        None => target.is_none().then_some(TableNamespace::Initial),
    }
}

#[derive(Debug)]
struct NetworkTable(fn(u64) -> Vec<u8>);

impl ProcFile for NetworkTable {
    fn net_view(&self, target: Option<u64>) -> Option<Arc<dyn ProcFile>> {
        Some(Arc::new(OpenNetworkTable {
            namespace: resolve_namespace(target)?,
            render: self.0,
            contents: IrqSafeSpinLock::new(None),
        }))
    }

    fn read(&self) -> Vec<u8> {
        resolve_namespace(None).map_or_else(Vec::new, |namespace| (self.0)(namespace.id()))
    }
}

#[derive(Debug)]
struct OpenNetworkTable {
    namespace: TableNamespace,
    render: fn(u64) -> Vec<u8>,
    contents: IrqSafeSpinLock<Option<Vec<u8>>>,
}

impl ProcFile for OpenNetworkTable {
    fn read(&self) -> Vec<u8> {
        (self.render)(self.namespace.id())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, crate::FsError> {
        if offset != 0 {
            if let Some(bytes) = self.contents.lock().as_ref() {
                return slice_read(bytes, offset, buf);
            }
        }
        // Render outside the cache lock because providers may acquire network or socket locks.
        let fresh = self.read();
        let mut cache = self.contents.lock();
        let bytes = if offset == 0 {
            cache.insert(fresh)
        } else {
            cache.get_or_insert(fresh)
        };
        slice_read(bytes, offset, buf)
    }
}

/// Register a network table at its procfs registry path (e.g. `net/unix`).
pub fn register_table(path: &str, render: fn(u64) -> Vec<u8>) {
    register_proc(path, Arc::new(NetworkTable(render)));
}

/// Register every /proc/net/* file. Called from a single boot-time
/// initcall so the files appear together. Idempotent — repeated
/// calls just replace the old `Arc<dyn ProcFile>` handles.
pub fn register_all() {
    register_table("net/tcp", render_tcp);
    register_table("net/udp", render_udp);
    register_table("net/raw", render_raw);
    register_table("net/tcp6", render_tcp6);
    register_table("net/udp6", render_udp6);
    register_table("net/raw6", render_raw6);
    register_table("net/arp", render_arp);
    register_table("net/route", render_route);
    register_table("net/dev", render_dev);
    register_table("net/if_inet6", render_if_inet6);
    register_table("net/ipv6_route", render_ipv6_route);
    register_table("net/igmp", render_igmp);
    register_table("net/igmp6", render_igmp6);
    register_table("net/snmp", render_snmp);
    register_table("net/netstat", render_netstat);
    register_table("net/snmp6", render_snmp6);
    register_table("net/sockstat", render_sockstat);
    register_table("net/sockstat6", render_sockstat6);
    register_table("net/nf_conntrack", render_nf_conntrack);
}

// ── Tests ───────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// Helper: install a TCP-snapshot hook, render /proc/net/tcp, then
/// uninstall. Restoring the hook to 0 between tests keeps the
/// global state clean.
fn install_tcp_then<F: FnOnce() -> bool>(snap: Vec<TcbSnapshot>, f: F) -> bool {
    // We can't capture the Vec in a fn pointer, so we stash a
    // static slot the hook reads from.
    static FAKE_TCP: IrqSafeSpinLock<Vec<TcbSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_TCP.lock() = snap;
    fn fake_tcp_fn(_: u64) -> Vec<TcbSnapshot> {
        FAKE_TCP.lock().clone()
    }
    let prev = TCP_HOOK.swap(fake_tcp_fn as usize, Ordering::AcqRel);
    let ok = f();
    TCP_HOOK.store(prev, Ordering::Release);
    ok
}

fn smoke_tcp_one_socket_emits_one_line() -> TestResult {
    register_all();
    let snap = alloc::vec![TcbSnapshot {
        local_addr: [127, 0, 0, 1],
        local_port: 80,
        remote_addr: [0, 0, 0, 0],
        remote_port: 0,
        state_code: 0x0A, // LISTEN
        tx_queue: 0,
        rx_queue: 0,
        retrnsmt: 0,
        timer_active: 0,
        timer_expires: 0,
        probes_out: 0,
        rto: 100,
        ack_timeout: 0,
        snd_cwnd: 10,
        snd_ssthresh: -1,
        uid: 0,
        timeout: 0,
        inode: 0,
    }];
    let ok = install_tcp_then(snap, || {
        let body = render_tcp(0);
        let text = core::str::from_utf8(&body).unwrap_or("");
        text.lines().count() == 2 && text.lines().next().unwrap().contains("sl")
    });
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("tcp file format wrong with 1 socket")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_tcp_one_socket_emits_one_line);

fn smoke_tcp_linux_timer_and_tail_columns() -> TestResult {
    let snap = alloc::vec![TcbSnapshot {
        local_addr: [10, 0, 0, 1],
        local_port: 0x1234,
        remote_addr: [10, 0, 0, 2],
        remote_port: 0x5678,
        state_code: 0x01,
        tx_queue: 0x11,
        rx_queue: 0x22,
        retrnsmt: 3,
        timer_active: 1,
        timer_expires: 0x44,
        probes_out: 5,
        rto: 100,
        ack_timeout: 4,
        snd_cwnd: 10,
        snd_ssthresh: 7,
        uid: 42,
        timeout: 5,
        inode: 99,
    }];
    let ok = install_tcp_then(snap, || {
        let body = render_tcp(0);
        let row = core::str::from_utf8(&body)
            .unwrap_or("")
            .lines()
            .nth(1)
            .unwrap_or("");
        row.contains("0100000A:1234 0200000A:5678 01 00000011:00000022 01:00000044 00000003")
            && row.contains("   42        5 99 2 0000000000000000")
            && row.ends_with("     100        4 0    10     7")
    });
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("tcp Linux timer/tail columns mismatch")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_tcp_linux_timer_and_tail_columns
);

fn smoke_tcp_address_hex_little_endian() -> TestResult {
    // 127.0.0.1:80 should render as 0100007F:0050.
    let s = fmt_ipv4_port([127, 0, 0, 1], 80);
    if s == "0100007F:0050" {
        TestResult::Pass
    } else {
        TestResult::Fail("ipv4 hex encoding mismatch")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_tcp_address_hex_little_endian);

fn smoke_sockstat_linux_shape_and_counts() -> TestResult {
    let snap = alloc::vec![TcbSnapshot {
        local_addr: [0; 4],
        local_port: 80,
        remote_addr: [0; 4],
        remote_port: 0,
        state_code: 0x0A,
        tx_queue: 0,
        rx_queue: 0,
        retrnsmt: 0,
        timer_active: 0,
        timer_expires: 0,
        probes_out: 0,
        rto: 100,
        ack_timeout: 0,
        snd_cwnd: 10,
        snd_ssthresh: -1,
        uid: 0,
        timeout: 0,
        inode: 0,
    }];
    let ok = install_tcp_then(snap, || {
        let body = render_sockstat(0);
        let text = core::str::from_utf8(&body).unwrap_or("");
        text.starts_with("sockets: used ")
            && text.contains("TCP: inuse 1 orphan 0 tw 0 alloc 1 mem 0\n")
            && text.contains("UDPLITE: inuse 0\n")
            && text.ends_with("FRAG: inuse 0 memory 0\n")
    });
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("sockstat Linux shape/count mismatch")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_sockstat_linux_shape_and_counts
);

fn smoke_netstat_has_paired_linux_mib_rows() -> TestResult {
    let body = render_netstat(0);
    let text = core::str::from_utf8(&body).unwrap_or("");
    let lines: Vec<&str> = text.lines().collect();
    let paired = lines.chunks_exact(2).all(|pair| {
        pair[0].split_whitespace().count() == pair[1].split_whitespace().count()
            && pair[0].split(':').next() == pair[1].split(':').next()
    });
    if lines.len() == 6 && paired {
        TestResult::Pass
    } else {
        TestResult::Fail("netstat MIB header/value rows are not positional pairs")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_netstat_has_paired_linux_mib_rows
);

fn smoke_snmp6_uses_one_counter_per_line() -> TestResult {
    let body = render_snmp6(0);
    let text = core::str::from_utf8(&body).unwrap_or("");
    if text
        .lines()
        .all(|line| line.split_whitespace().count() == 2)
        && text.contains("Ip6InReceives")
        && text.contains("Udp6OutDatagrams")
    {
        TestResult::Pass
    } else {
        TestResult::Fail("snmp6 counter layout mismatch")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_snmp6_uses_one_counter_per_line
);

fn smoke_tcp6_address_is_32_hex_digits() -> TestResult {
    let mut addr = [0u8; 16];
    addr[15] = 1; // ::1
    let s = fmt_ipv6_port(addr, 8080);
    // 32 hex digits + ":" + 4 hex digits = 37 chars.
    if s.len() == 37 && s.contains(':') {
        TestResult::Pass
    } else {
        TestResult::Fail("ipv6 hex encoding wrong length")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_tcp6_address_is_32_hex_digits);

fn smoke_udp_two_sockets_two_lines() -> TestResult {
    register_all();
    static FAKE_UDP: IrqSafeSpinLock<Vec<UdpSocketSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_UDP.lock() = alloc::vec![
        UdpSocketSnapshot {
            local_addr: [0, 0, 0, 0],
            local_port: 53,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            state_code: 7,
            tx_queue: 0,
            rx_queue: 0,
            uid: 0,
            inode: 0,
        },
        UdpSocketSnapshot {
            local_addr: [0, 0, 0, 0],
            local_port: 67,
            remote_addr: [0, 0, 0, 0],
            remote_port: 0,
            state_code: 7,
            tx_queue: 0,
            rx_queue: 0,
            uid: 0,
            inode: 0,
        },
    ];
    fn fake_udp_fn(_: u64) -> Vec<UdpSocketSnapshot> {
        FAKE_UDP.lock().clone()
    }
    let prev = UDP_HOOK.swap(fake_udp_fn as usize, Ordering::AcqRel);
    let body = render_udp(0);
    UDP_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    if text.lines().count() == 3 {
        TestResult::Pass
    } else {
        TestResult::Fail("udp file did not emit 2 data lines + header")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_udp_two_sockets_two_lines);

fn smoke_arp_one_entry_parses_through_regex() -> TestResult {
    static FAKE_ARP: IrqSafeSpinLock<Vec<ArpSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_ARP.lock() = alloc::vec![ArpSnapshot {
        ip: [192, 168, 1, 1],
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        iface: String::from("eth0"),
        flags: 2,
    }];
    fn fake_arp_fn(_: u64) -> Vec<ArpSnapshot> {
        FAKE_ARP.lock().clone()
    }
    let prev = ARP_HOOK.swap(fake_arp_fn as usize, Ordering::AcqRel);
    let body = render_arp(0);
    ARP_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    let ok = text.contains("192.168.1.1")
        && text.contains("00:11:22:33:44:55")
        && text.contains("eth0")
        && text.contains("0x2");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("arp line missing expected fields")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_arp_one_entry_parses_through_regex
);

fn smoke_route_hex_destination_gateway() -> TestResult {
    static FAKE_ROUTE: IrqSafeSpinLock<Vec<RouteSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_ROUTE.lock() = alloc::vec![RouteSnapshot {
        iface: String::from("eth0"),
        dst: [0, 0, 0, 0],
        gateway: [192, 168, 1, 1],
        flags: 0x0003, // UP | GATEWAY
        refcnt: 0,
        use_count: 0,
        metric: 0,
        mask: [0, 0, 0, 0],
        mtu: 1500,
        window: 0,
        irtt: 0,
    }];
    fn fake_route_fn(_: u64) -> Vec<RouteSnapshot> {
        FAKE_ROUTE.lock().clone()
    }
    let prev = ROUTE_HOOK.swap(fake_route_fn as usize, Ordering::AcqRel);
    let body = render_route(0);
    ROUTE_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    // Destination is 0.0.0.0 → 00000000.
    // Gateway is 192.168.1.1 → 0101A8C0 in little-endian u32 hex.
    let ok = text.contains("eth0") && text.contains("00000000") && text.contains("0101A8C0");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("route hex fields mismatch")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_route_hex_destination_gateway);

fn smoke_dev_per_iface_counter_line() -> TestResult {
    static FAKE_DEV: IrqSafeSpinLock<Vec<IfaceCounterSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_DEV.lock() = alloc::vec![IfaceCounterSnapshot {
        name: String::from("eth0"),
        rx_bytes: 123456,
        rx_packets: 1234,
        rx_errs: 0,
        rx_drop: 0,
        rx_fifo: 0,
        rx_frame: 0,
        rx_compressed: 0,
        rx_multicast: 0,
        tx_bytes: 789012,
        tx_packets: 789,
        tx_errs: 0,
        tx_drop: 0,
        tx_fifo: 0,
        tx_colls: 0,
        tx_carrier: 0,
        tx_compressed: 0,
    }];
    fn fake_fn(_: u64) -> Vec<IfaceCounterSnapshot> {
        FAKE_DEV.lock().clone()
    }
    let prev = IFACE_COUNTERS_HOOK.swap(fake_fn as usize, Ordering::AcqRel);
    let body = render_dev(0);
    IFACE_COUNTERS_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    if text.contains("eth0") && text.contains("123456") && text.contains("789012") {
        TestResult::Pass
    } else {
        TestResult::Fail("dev counters missing")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_dev_per_iface_counter_line);

fn smoke_if_inet6_link_local_and_global() -> TestResult {
    static FAKE_IFADDR: IrqSafeSpinLock<Vec<Ipv6IfAddrSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    let mut ll = [0u8; 16];
    ll[0] = 0xfe;
    ll[1] = 0x80;
    ll[15] = 0x01;
    let mut gl = [0u8; 16];
    gl[0] = 0x20;
    gl[1] = 0x01;
    gl[15] = 0x02;
    *FAKE_IFADDR.lock() = alloc::vec![
        Ipv6IfAddrSnapshot {
            iface: String::from("eth0"),
            addr: ll,
            ifindex: 2,
            prefix_len: 0x40,
            scope: 0x20,
            flags: 0x80,
        },
        Ipv6IfAddrSnapshot {
            iface: String::from("eth0"),
            addr: gl,
            ifindex: 2,
            prefix_len: 0x40,
            scope: 0x00,
            flags: 0x80,
        },
    ];
    fn fake_fn(_: u64) -> Vec<Ipv6IfAddrSnapshot> {
        FAKE_IFADDR.lock().clone()
    }
    let prev = IPV6_IFADDR_HOOK.swap(fake_fn as usize, Ordering::AcqRel);
    let body = render_if_inet6(0);
    IPV6_IFADDR_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    let two_lines = text.lines().count() == 2;
    let has_ll = text.contains("fe80");
    let has_global = text.contains("20010000");
    if two_lines && has_ll && has_global {
        TestResult::Pass
    } else {
        TestResult::Fail("if_inet6 missing link-local + global lines")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_if_inet6_link_local_and_global
);

fn smoke_snmp_tcp_has_15_standard_counters() -> TestResult {
    let body = render_snmp(0);
    let text = core::str::from_utf8(&body).unwrap_or("");
    // The Tcp: header line names 15 counters.
    let tcp_header = text.lines().find(|l| l.starts_with("Tcp: RtoAlgorithm"));
    match tcp_header {
        Some(line) => {
            let names = line.split_whitespace().skip(1).count();
            if names == 15 {
                TestResult::Pass
            } else {
                TestResult::Fail("tcp MIB does not have 15 counters")
            }
        }
        None => TestResult::Fail("snmp file missing Tcp: header"),
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_snmp_tcp_has_15_standard_counters
);

fn smoke_nf_conntrack_one_entry_one_line() -> TestResult {
    static FAKE_CT: IrqSafeSpinLock<Vec<ConntrackSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_CT.lock() = alloc::vec![ConntrackSnapshot {
        l3proto: "ipv4",
        l3proto_num: 2,
        l4proto: "tcp",
        l4proto_num: 6,
        timeout: 431999,
        state: "ESTABLISHED",
        orig_src: [10, 0, 0, 5],
        orig_dst: [8, 8, 8, 8],
        orig_sport: 42000,
        orig_dport: 80,
        reply_src: [8, 8, 8, 8],
        reply_dst: [203, 0, 113, 7],
        reply_sport: 80,
        reply_dport: 32768,
        assured: true,
        use_count: 2,
    }];
    fn fake_fn(_: u64) -> Vec<ConntrackSnapshot> {
        FAKE_CT.lock().clone()
    }
    let prev = CONNTRACK_HOOK.swap(fake_fn as usize, Ordering::AcqRel);
    let body = render_nf_conntrack(0);
    CONNTRACK_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    let ok = text.lines().count() == 1
        && text.contains("ESTABLISHED")
        && text.contains("[ASSURED]")
        && text.contains("src=10.0.0.5")
        && text.contains("dport=32768");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("nf_conntrack format mismatch")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_nf_conntrack_one_entry_one_line
);

fn smoke_ipv6_route_default_line() -> TestResult {
    static FAKE_R: IrqSafeSpinLock<Vec<Ipv6RouteSnapshot>> = IrqSafeSpinLock::new(Vec::new());
    *FAKE_R.lock() = alloc::vec![Ipv6RouteSnapshot {
        dst: [0; 16],
        dst_prefix_len: 0,
        src: [0; 16],
        src_prefix_len: 0,
        gateway: {
            let mut g = [0u8; 16];
            g[0] = 0xfe;
            g[1] = 0x80;
            g[15] = 0x01;
            g
        },
        metric: 1024,
        refcnt: 0,
        use_count: 0,
        flags: 0x00000001,
        iface: String::from("eth0"),
    }];
    fn fake_fn(_: u64) -> Vec<Ipv6RouteSnapshot> {
        FAKE_R.lock().clone()
    }
    let prev = IPV6_ROUTE_HOOK.swap(fake_fn as usize, Ordering::AcqRel);
    let body = render_ipv6_route(0);
    IPV6_ROUTE_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    let ok = text.contains("eth0") && text.contains("fe80");
    if ok {
        TestResult::Pass
    } else {
        TestResult::Fail("ipv6_route default route missing")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_ipv6_route_default_line);

fn smoke_igmp_at_least_header_when_empty() -> TestResult {
    // No hook installed → empty body but header still present.
    let prev = IGMP_HOOK.swap(0, Ordering::AcqRel);
    let body = render_igmp(0);
    IGMP_HOOK.store(prev, Ordering::Release);
    let text = core::str::from_utf8(&body).unwrap_or("");
    if text.starts_with("Idx") && text.contains("Device") {
        TestResult::Pass
    } else {
        TestResult::Fail("igmp header missing")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_igmp_at_least_header_when_empty
);

fn smoke_proc_net_tcp_resolves_through_vfs() -> TestResult {
    use crate::procfs::ProcFs;
    use crate::{bootstrap_mount_authority, registry, resolve_async};

    register_all();
    let auth = bootstrap_mount_authority();
    // Mount under a unique test path to avoid clashing with the
    // boot-time mount.
    let path = "/smoke-procnet-tcp";
    let handle = match registry().mount(&auth, path, ProcFs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("procfs mount failed"),
    };
    // Resolve /proc/net/tcp through the FsRegistry → resolve_async.
    let result = registry()
        .resolve_absolute(&alloc::format!("{}/net/tcp", path), |fs, rel| {
            let root = fs.root();
            let fut = resolve_async(root, rel);
            super::poll_once(fut)
        })
        .flatten();
    let _ = registry().unmount(&handle, path);
    match result {
        Some(Ok(_)) => TestResult::Pass,
        _ => TestResult::Fail("/proc/net/tcp did not resolve through VFS"),
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_proc_net_tcp_resolves_through_vfs
);

fn smoke_proc_net_dir_lists_all_registered_files() -> TestResult {
    use crate::DirOps;
    register_all();
    let dir = super::ProcDynamicDir {
        path_components: alloc::vec![String::from("net")],
    };
    let names: Vec<String> = dir.iter().map(|e| String::from(e.name)).collect();
    let needed = [
        "tcp",
        "udp",
        "raw",
        "tcp6",
        "udp6",
        "raw6",
        "arp",
        "route",
        "dev",
        "if_inet6",
        "ipv6_route",
        "igmp",
        "igmp6",
        "snmp",
        "netstat",
        "snmp6",
        "sockstat",
        "sockstat6",
        "nf_conntrack",
    ];
    let all_present = needed.iter().all(|n| names.iter().any(|m| m == n));
    if all_present {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/net iter missing one of the registered files")
    }
}
kernel_test_in!(
    "filesystem/procfs/net",
    smoke_proc_net_dir_lists_all_registered_files
);

fn smoke_subsystem_can_unregister_file() -> TestResult {
    use super::{lookup_registry, register_proc, unregister_proc, ProcNodeSnapshot};
    #[derive(Debug)]
    struct EmptyFile;
    impl ProcFile for EmptyFile {
        fn read(&self) -> Vec<u8> {
            Vec::new()
        }
    }
    register_proc("net/hotplug_smoke", Arc::new(EmptyFile));
    let before = matches!(
        lookup_registry(&["net", "hotplug_smoke"]),
        Some(ProcNodeSnapshot::File(_))
    );
    let removed = unregister_proc("net/hotplug_smoke");
    let after = matches!(
        lookup_registry(&["net", "hotplug_smoke"]),
        Some(ProcNodeSnapshot::File(_))
    );
    if before && removed && !after {
        TestResult::Pass
    } else {
        TestResult::Fail("hotplug unregister did not clear entry")
    }
}
kernel_test_in!("filesystem/procfs/net", smoke_subsystem_can_unregister_file);
