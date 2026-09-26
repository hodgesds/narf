//! UDP socket layer — bind / connect / send / recv / options.
//!
//! References (clean-room):
//! - RFC 768 — User Datagram Protocol.
//!   <https://datatracker.ietf.org/doc/html/rfc768>
//! - RFC 6056 §3.2 — Ephemeral port algorithm.
//!   <https://www.rfc-editor.org/rfc/rfc6056>
//! - Linux net/ipv4/udp.c — `__udp4_lib_rcv` dispatch, socket table
//!   lookup, SO_RCVBUF / SO_SNDBUF handling, SO_BROADCAST guard,
//!   IP_PKTINFO / IP_RECVTTL options, SO_REUSEPORT load-balance.
//!   Lines cited inline where logic was verified against the spec.
//!
//! Architecture mirrors `tcp_stack`: a global locked port table maps
//! `dst_port → Vec<Arc<UdpSocket>>` (SO_REUSEPORT allows multiple
//! sockets per port; unconnected sockets accept all sources, connected
//! sockets filter to their peer).
//!
//! The RX path is synchronous: `deliver()` is called from
//! `tcp_stack::handle_udp` with the IP-layer stripped, enqueues the
//! datagram, and returns. There is no async waker — the in-kernel
//! test shim calls `udp_recv` synchronously after injecting a frame.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::iface;
use crate::pkt::{
    ip_checksum, set_ipv4_checksum, write_eth_header, write_ipv4_header, ETHERTYPE_IPV4,
    ETH_HDR_LEN, IPV4_HDR_LEN, IP_PROTO_UDP,
};
use crate::pkt_udp::{UdpHeader, UDP_HDR_LEN};

// ── Linux ephemeral range (32768-60999, net/ipv4/inet_connection_sock.c) ──
// The userspace `ephemeral_port.rs` uses RFC 6056's 49152-65535 range.
// Here we use the Linux default which better matches test expectations.
pub const UDP_EPHEMERAL_MIN: u16 = 32768;
pub const UDP_EPHEMERAL_MAX: u16 = 60999;

/// Largest UDP payload an IPv4 datagram can carry: 65535 - 20 (IPv4 header)
/// - 8 (UDP header). See the EMSGSIZE check in `udp_send_inner`.
pub const UDP_MAX_PAYLOAD: usize = 65507;

// ── Socket options ─────────────────────────────────────────────────

/// Subset of socket options relevant to UDP. Modelled on Linux
/// `udp_setsockopt` (net/ipv4/udp.c:2534+) and `sock_setsockopt`.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct UdpOptions {
    /// SO_BROADCAST: allow sends to 255.255.255.255 / subnet bcast.
    pub broadcast: bool,
    /// SO_RCVBUF: max number of datagrams in the RX queue. When the
    /// queue is full the *arriving* datagram is dropped and the queued ones
    /// are kept, as `__udp_enqueue_schedule_skb` (`net/ipv4/udp.c:1527`)
    /// does: `if (rmem > rcvbuf) goto drop;`.
    pub rcvbuf: usize,
    /// SO_SNDBUF: max single datagram payload in bytes.
    pub sndbuf: usize,
    /// IP_PKTINFO: attach source address and interface index to each
    /// received datagram (stored in `UdpDatagram::pktinfo`).
    pub ip_pktinfo: bool,
    /// IP_RECVTTL: attach the IP TTL to each received datagram.
    pub ip_recvttl: bool,
    /// SO_BINDTODEVICE ifindex (0 = unbound to device).
    pub bind_to_device: u32,
    /// SO_REUSEPORT: allow multiple sockets to bind the same port;
    /// incoming datagrams are distributed across them.
    pub reuseport: bool,
    /// IP_TTL: unicast TTL override (0 = use default 64).
    /// Linux `ip_setsockopt` / `do_ip_setsockopt` (net/ipv4/ip_sockglue.c).
    pub ip_ttl: u8,
    /// IP_TOS: DSCP/ECN byte override for outgoing datagrams (0 = default).
    /// Linux `ip_setsockopt` / `do_ip_setsockopt` (net/ipv4/ip_sockglue.c).
    pub ip_tos: u8,
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self {
            broadcast: false,
            rcvbuf: 128,
            sndbuf: 65507,
            ip_pktinfo: false,
            ip_recvttl: false,
            bind_to_device: 0,
            reuseport: false,
            ip_ttl: 0, // 0 = use system default (64)
            ip_tos: 0,
        }
    }
}

// ── Received datagram descriptor ───────────────────────────────────

#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub src: SocketAddrV4,
    /// Source IP as seen by the IP layer (≡ `src.ip` but kept
    /// separately for IP_PKTINFO).
    pub dst_ip: [u8; 4],
    pub payload: alloc::vec::Vec<u8>,
    pub ttl: u8,
}

/// Minimal IPv4 socket address.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SocketAddrV4 {
    pub ip: [u8; 4],
    pub port: u16,
}

impl SocketAddrV4 {
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }
    pub const UNSPECIFIED: Self = Self {
        ip: [0, 0, 0, 0],
        port: 0,
    };
}

// ── Error delivery from ICMP ────────────────────────────────────────

/// An ICMP error delivered back to a socket's error queue.
#[derive(Clone, Debug)]
pub struct SockError {
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// Source IP in the ICMP outer header.
    pub from_ip: [u8; 4],
}

impl SockError {
    /// The Linux errno and hard/soft class `udp_err` (net/ipv4/udp.c)
    /// derives from this ICMP error. See [`icmp_err_convert`].
    pub fn linux_errno(&self) -> Option<(i32, bool)> {
        icmp_err_convert(self.icmp_type, self.icmp_code)
    }
}

/// `udp_err`'s mapping of an ICMPv4 error `(type, code)` to `(errno, hard)`:
///
/// - Destination Unreachable code 0..=15 → `icmp_err_convert[code]`
///   (the table in `tcp::core`); higher codes → `EHOSTUNREACH`, soft.
/// - Fragmentation Needed → `EMSGSIZE`, hard (default `IP_PMTUDISC_WANT`).
/// - Parameter Problem → `EPROTO`, hard.
/// - Time Exceeded and any other type → `EHOSTUNREACH`, soft.
/// - Source Quench / Redirect → `None` (never reported to the socket).
///
/// Linux sets `sk_err` only for hard errors on a connected socket unless
/// `IP_RECVERR` is on; callers apply that rule, this only maps.
pub fn icmp_err_convert(icmp_type: u8, icmp_code: u8) -> Option<(i32, bool)> {
    use crate::tcp::core::{ICMP_UNREACH_ERRNO, ICMP_UNREACH_FATAL};
    use narf_lib::errno as e;
    const DEST_UNREACH: u8 = 3;
    const SOURCE_QUENCH: u8 = 4;
    const REDIRECT: u8 = 5;
    const PARAMETERPROB: u8 = 12;
    const FRAG_NEEDED: u8 = 4;
    let (errno, hard) = match icmp_type {
        SOURCE_QUENCH | REDIRECT => return None,
        PARAMETERPROB => (e::EPROTO, true),
        DEST_UNREACH if icmp_code == FRAG_NEEDED => (e::EMSGSIZE, true),
        DEST_UNREACH => match ICMP_UNREACH_ERRNO.get(icmp_code as usize) {
            Some(errno) => (*errno, ICMP_UNREACH_FATAL[icmp_code as usize]),
            None => (e::EHOSTUNREACH, false),
        },
        _ => (e::EHOSTUNREACH, false),
    };
    Some((errno as i32, hard))
}

// ── UDP socket ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct UdpSocket {
    pub net_ns_id: u64,
    pub local: SocketAddrV4,
    /// `Some` = connected mode; RX filters to this peer.
    pub peer: IrqSafeSpinLock<Option<SocketAddrV4>>,
    pub rx_queue: IrqSafeSpinLock<VecDeque<UdpDatagram>>,
    /// ICMP error queue (SO_ERROR).
    pub err_queue: IrqSafeSpinLock<VecDeque<SockError>>,
    pub options: IrqSafeSpinLock<UdpOptions>,
}

impl UdpSocket {
    fn new(net_ns_id: u64, local: SocketAddrV4, options: UdpOptions) -> Self {
        Self {
            net_ns_id,
            local,
            peer: IrqSafeSpinLock::new(None),
            rx_queue: IrqSafeSpinLock::new(VecDeque::new()),
            err_queue: IrqSafeSpinLock::new(VecDeque::new()),
            options: IrqSafeSpinLock::new(options),
        }
    }
}

// ── Global port table ──────────────────────────────────────────────
//
// Maps dst_port → list of Arc<UdpSocket>.  SO_REUSEPORT populates
// multiple entries for the same port (Linux udp.c:__udp4_lib_mcast_rcv
// and udp_lib_get_port do the same).  The round-robin counter below
// distributes datagrams across them.

// The port table is consulted on EVERY received UDP datagram (`deliver_in`
// filters by `dst_port`), so a single global lock + O(n) scan serialized all
// UDP RX across CPUs. Shard the `(port, socket)` entries 64-way by port: a
// datagram only touches its port's shard, so unrelated ports don't contend and
// each scan shrinks to that shard. The ephemeral-port cursor is a small
// separate lock (the alloc path is cold). `rr_counter` was already the separate
// `RR_COUNTER` atomic.
const PORT_SHARDS: usize = 64;

#[repr(align(64))]
struct PortShard {
    entries: IrqSafeSpinLock<Vec<(u16, Arc<UdpSocket>)>>,
}

impl PortShard {
    const fn new() -> Self {
        Self {
            entries: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}

static PORTS: [PortShard; PORT_SHARDS] = [const { PortShard::new() }; PORT_SHARDS];
static EPHEMERAL_CURSOR: IrqSafeSpinLock<u16> = IrqSafeSpinLock::new(UDP_EPHEMERAL_MIN);

#[inline]
fn port_shard(port: u16) -> usize {
    (port as usize) & (PORT_SHARDS - 1)
}

/// True if `(port, net_ns_id)` is already bound.
fn port_taken(port: u16, net_ns_id: u64) -> bool {
    PORTS[port_shard(port)]
        .entries
        .lock()
        .iter()
        .any(|(p, socket)| *p == port && socket.net_ns_id == net_ns_id)
}

/// Allocate a free ephemeral port for `net_ns_id`, advancing the shared cursor.
fn alloc_ephemeral(net_ns_id: u64) -> Option<u16> {
    let mut cursor = EPHEMERAL_CURSOR.lock();
    let start = *cursor;
    loop {
        let port = *cursor;
        *cursor = if *cursor >= UDP_EPHEMERAL_MAX {
            UDP_EPHEMERAL_MIN
        } else {
            *cursor + 1
        };
        if !port_taken(port, net_ns_id) {
            return Some(port);
        }
        if *cursor == start {
            return None; // exhausted
        }
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Error type returned from UDP socket operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UdpError {
    /// Tried to bind a port already in use (and SO_REUSEPORT not set).
    AddrInUse,
    /// No ephemeral port was available.
    NoEphemeral,
    /// No interface registered.
    NoInterface,
    /// Broadcast attempted without SO_BROADCAST.
    NoBroadcastPermission,
    /// Socket handle invalid.
    InvalidSocket,
    /// Send buffer too small for this payload.
    MsgTooLong,
    /// No data in the receive queue.
    WouldBlock,
    /// ICMP error was signalled (see `udp_err_peek`).
    IcmpError,
    /// ARP resolution for the destination failed.
    NetworkUnreachable,
}

/// Bind a new UDP socket to `local`. If `local.port == 0`, an
/// ephemeral port in 32768-60999 is allocated. Returns `Arc<UdpSocket>`.
/// Mirrors Linux `udp_lib_get_port` (net/ipv4/udp.c:253+).
pub fn udp_bind(local: SocketAddrV4, options: UdpOptions) -> Result<Arc<UdpSocket>, UdpError> {
    udp_bind_in(0, local, options)
}

pub fn udp_bind_in(
    net_ns_id: u64,
    local: SocketAddrV4,
    options: UdpOptions,
) -> Result<Arc<UdpSocket>, UdpError> {
    let port = if local.port == 0 {
        alloc_ephemeral(net_ns_id).ok_or(UdpError::NoEphemeral)?
    } else {
        // Check for collision unless SO_REUSEPORT is set.
        if !options.reuseport && port_taken(local.port, net_ns_id) {
            return Err(UdpError::AddrInUse);
        }
        local.port
    };
    let bound = SocketAddrV4::new(local.ip, port);
    let sock = Arc::new(UdpSocket::new(net_ns_id, bound, options));
    PORTS[port_shard(port)]
        .entries
        .lock()
        .push((port, sock.clone()));
    Ok(sock)
}

/// Connect a UDP socket to a peer. After this, `udp_send` uses
/// `peer` as the implicit destination and `udp_recv` only accepts
/// datagrams from `peer`. Mirrors Linux `udp_connect` (udp.c:1807+).
pub fn udp_connect(sock: &Arc<UdpSocket>, peer: SocketAddrV4) {
    *sock.peer.lock() = Some(peer);
}

/// Disconnect a connected UDP socket (set peer back to None).
pub fn udp_disconnect(sock: &Arc<UdpSocket>) {
    *sock.peer.lock() = None;
}

/// Set a socket option.
pub fn udp_setsockopt(sock: &Arc<UdpSocket>, opt: UdpSockOpt) {
    let mut opts = sock.options.lock();
    match opt {
        UdpSockOpt::Broadcast(v) => opts.broadcast = v,
        UdpSockOpt::RcvBuf(n) => opts.rcvbuf = n,
        UdpSockOpt::SndBuf(n) => opts.sndbuf = n,
        UdpSockOpt::IpPktInfo(v) => opts.ip_pktinfo = v,
        UdpSockOpt::IpRecvTtl(v) => opts.ip_recvttl = v,
        UdpSockOpt::BindToDevice(idx) => opts.bind_to_device = idx,
        UdpSockOpt::ReusePort(v) => opts.reuseport = v,
        UdpSockOpt::IpTtl(v) => opts.ip_ttl = v,
        UdpSockOpt::IpTos(v) => opts.ip_tos = v,
    }
}

/// Socket option discriminant.
#[derive(Copy, Clone, Debug)]
pub enum UdpSockOpt {
    Broadcast(bool),
    RcvBuf(usize),
    SndBuf(usize),
    IpPktInfo(bool),
    IpRecvTtl(bool),
    BindToDevice(u32),
    ReusePort(bool),
    /// IP_TTL: unicast TTL (0 = kernel default 64).
    IpTtl(u8),
    /// IP_TOS: DSCP/ECN byte.
    IpTos(u8),
}

/// Build and send a UDP datagram.
///
/// If `peer` is `None` and the socket is connected, the stored peer
/// is used.  Broadcast to 255.255.255.255 requires `SO_BROADCAST`.
/// Mirrors Linux `udp_sendmsg` (net/ipv4/udp.c:1087+).
pub fn udp_send(
    sock: &Arc<UdpSocket>,
    payload: &[u8],
    peer: Option<SocketAddrV4>,
) -> Result<usize, UdpError> {
    let dst = match peer {
        Some(p) => p,
        None => sock.peer.lock().ok_or(UdpError::InvalidSocket)?,
    };
    let opts = sock.options.lock().clone();
    // In-kernel senders (DHCP, DNS) keep the historical blocking resolve.
    udp_send_from(sock.net_ns_id, sock.local.port, dst, payload, &opts, 1000)
}

/// Emit one UDP datagram without needing a bound [`UdpSocket`].
///
/// `udp_send` reads only the namespace, the source port and the options off
/// its socket, so the body is factored out here for callers that HAVE a
/// source port but no socket in this table — notably the userspace socket
/// layer, which keeps its own bookkeeping and must not take a second
/// binding for the same port (that would be EADDRINUSE against itself).
pub fn udp_send_from(
    net_ns_id: u64,
    src_port: u16,
    dst: SocketAddrV4,
    payload: &[u8],
    options: &UdpOptions,
    arp_timeout_ms: u64,
) -> Result<usize, UdpError> {
    udp_send_inner(net_ns_id, src_port, dst, payload, options, arp_timeout_ms)
}

fn udp_send_inner(
    net_ns_id: u64,
    src_port: u16,
    dst: SocketAddrV4,
    payload: &[u8],
    options: &UdpOptions,
    arp_timeout_ms: u64,
) -> Result<usize, UdpError> {
    // The largest datagram IPv4 can carry: `__ip_append_data`
    // (`net/ipv4/ip_output.c:992`) refuses `length > IP_MAX_MTU(0xFFFF) -
    // sizeof(iphdr)` with EMSGSIZE, and `length` includes the 8-byte UDP
    // header, so the payload limit is 65535 - 20 - 8 = 65507. Checked before
    // SO_SNDBUF so a raised send buffer can never overflow the 16-bit UDP /
    // IP length fields below.
    if payload.len() > UDP_MAX_PAYLOAD {
        return Err(UdpError::MsgTooLong);
    }

    // SO_BROADCAST guard. `udp_sendmsg` (`net/ipv4/udp.c:1247`) fails with
    // EACCES when the route is `RTCF_BROADCAST` and the socket lacks
    // SOCK_BROADCAST. That flag covers the limited broadcast and a local
    // subnet's directed broadcast — not every address ending in .255.
    let is_broadcast = iface::is_broadcast_in(net_ns_id, dst.ip);
    if is_broadcast && !options.broadcast {
        return Err(UdpError::NoBroadcastPermission);
    }

    let (opts_sndbuf, ip_ttl, ip_tos) = (options.sndbuf, options.ip_ttl, options.ip_tos);
    if payload.len() > opts_sndbuf {
        return Err(UdpError::MsgTooLong);
    }

    // Wave-47: route by destination so flows on a non-primary iface
    // egress on the correct NIC (capture-iface smokes, multi-NIC hosts).
    // SO_BINDTODEVICE pins egress to one interface. Linux passes
    // `sk->sk_bound_dev_if` into the route lookup (`ip_route_output_flow`
    // via `flowi4.flowi4_oif`), so a bound socket cannot leak onto another
    // NIC just because the route table prefers it. This field was stored
    // and never read until now.
    let iface = if options.bind_to_device != 0 {
        let name = iface::snapshot_all_in(net_ns_id)
            .into_iter()
            .map(|i| i.name)
            .find(|n| iface::ifindex_of(n) == Some(options.bind_to_device))
            .ok_or(UdpError::NoInterface)?;
        iface::lookup_in(net_ns_id, &name).ok_or(UdpError::NoInterface)?
    } else {
        iface::for_dst_in(net_ns_id, dst.ip).ok_or(UdpError::NoInterface)?
    };
    let src_ip = iface.ipv4;
    let dst_ip = dst.ip;
    let dst_port = dst.port;

    // Resolve the destination MAC.  For broadcast, use ff:ff:ff:ff:ff:ff.
    let dst_mac = if is_broadcast {
        [0xFF; 6]
    } else {
        // `arp_timeout_ms == 0` means "do not wait": `ip_finish_output2`
        // hands an unresolved destination to `neigh_output`, which queues
        // the skb, fires an ARP request and returns — `sendmsg` never
        // blocks on resolution. Blocking a caller for a second inside
        // sendto is the one behaviour Linux definitely does not have.
        //
        // NARF has no neighbour queue, so an unresolved first datagram is
        // dropped rather than held. That IS a divergence, and a smaller one
        // than stalling the caller: the ARP request still goes out, so the
        // next datagram resolves.
        // Resolve the route's NEXT HOP, not the destination. Linux's
        // `ip_neigh_for_gw()` (include/net/route.h) uses the route's gateway
        // when it has one and the destination only when it does not, which is
        // `rt_nexthop()`. ARPing an off-link destination asks the local link
        // about a host that is not on it, so it can never resolve and every
        // off-link datagram failed `NetworkUnreachable`. Correct for an
        // on-link peer, where the next hop IS the destination, which is why
        // every existing smoke passed.
        let nexthop = crate::route::route_lookup_in(net_ns_id, crate::ipv4::Ipv4Addr(dst_ip))
            .map(|r| r.nexthop.0)
            .unwrap_or(dst_ip);
        crate::tcp_stack::arp_resolve_in(net_ns_id, nexthop, arp_timeout_ms)
            .map_err(|_| UdpError::NetworkUnreachable)?
    };

    let udp_len = UDP_HDR_LEN + payload.len();
    let ip_total = IPV4_HDR_LEN + udp_len;
    let frame_len = ETH_HDR_LEN + ip_total;
    let mut frame = alloc::vec![0u8; frame_len];

    // Ethernet header.
    write_eth_header(&mut frame, dst_mac, iface.mac, ETHERTYPE_IPV4);
    // IPv4 header.
    write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total as u16,
        IP_PROTO_UDP,
        src_ip,
        dst_ip,
    );
    // Apply IP_TOS (byte 1) and IP_TTL (byte 8) overrides if set.
    // Linux ref: `ip_build_and_send_pkt` / `ip_fragment` in net/ipv4/ip_output.c
    // apply inet->tos and inet->ttl from the socket.
    if ip_tos != 0 {
        frame[ETH_HDR_LEN + 1] = ip_tos;
    }
    if ip_ttl != 0 {
        frame[ETH_HDR_LEN + 8] = ip_ttl;
    }
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);

    // UDP header + payload.
    let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let udp_hdr = UdpHeader {
        src_port,
        dst_port,
        length: udp_len as u16,
        checksum: 0,
    };
    frame[udp_off..udp_off + UDP_HDR_LEN].copy_from_slice(&udp_hdr.encode());
    frame[udp_off + UDP_HDR_LEN..udp_off + UDP_HDR_LEN + payload.len()].copy_from_slice(payload);

    // Compute UDP checksum over pseudo-header + datagram.
    let udp_segment = &frame[udp_off..udp_off + udp_len];
    let mut pseudo = alloc::vec::Vec::with_capacity(12 + udp_len + 1);
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(IP_PROTO_UDP);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_segment);
    let cs = {
        let s = ip_checksum(&pseudo);
        if s == 0 {
            0xFFFF
        } else {
            s
        }
    };
    frame[udp_off + 6..udp_off + 8].copy_from_slice(&cs.to_be_bytes());

    if crate::tcp_stack::nf_tx_filter_in(net_ns_id, &iface.name, &mut frame[ETH_HDR_LEN..])
        != crate::netfilter::Verdict::Accept
    {
        return Ok(payload.len());
    }
    (iface.send)(&frame).map_err(|_| UdpError::NoInterface)?;
    Ok(payload.len())
}

/// Pop the next received datagram from the socket. Returns
/// `Err(WouldBlock)` if the queue is empty. Mirrors Linux
/// `udp_recvmsg` (net/ipv4/udp.c:1638+).
pub fn udp_recv(sock: &Arc<UdpSocket>, buf: &mut [u8]) -> Result<(usize, SocketAddrV4), UdpError> {
    let dg = {
        let mut q = sock.rx_queue.lock();
        q.pop_front().ok_or(UdpError::WouldBlock)?
    };
    let n = buf.len().min(dg.payload.len());
    buf[..n].copy_from_slice(&dg.payload[..n]);
    Ok((n, dg.src))
}

/// Peek at the next ICMP error without consuming it.
pub fn udp_err_peek(sock: &Arc<UdpSocket>) -> Option<SockError> {
    sock.err_queue.lock().front().cloned()
}

/// Drain the next ICMP error from the error queue.
pub fn udp_err_recv(sock: &Arc<UdpSocket>) -> Option<SockError> {
    sock.err_queue.lock().pop_front()
}

/// Unregister the socket from the port table and free its port.
pub fn udp_close(sock: &Arc<UdpSocket>) {
    let port = sock.local.port;
    PORTS[port_shard(port)]
        .entries
        .lock()
        .retain(|(p, s)| !(*p == port && Arc::ptr_eq(s, sock)));
}

pub(crate) fn remove_namespace(net_ns_id: u64) {
    for shard in &PORTS {
        shard
            .entries
            .lock()
            .retain(|(_, socket)| socket.net_ns_id != net_ns_id);
    }
}

// ── RX dispatch ────────────────────────────────────────────────────
//
// Called from `tcp_stack::handle_udp` with the IPv4 header already
// stripped.  Looks up matching sockets by dst_port; for SO_REUSEPORT
// buckets, round-robins across candidates (Linux udp.c:1844).

static RR_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Deliver a received UDP datagram to matching socket(s).
/// `datagram` is the raw UDP segment (header + payload, 8+ bytes).
pub fn deliver(src_ip: [u8; 4], dst_ip: [u8; 4], datagram: &[u8], ttl: u8) {
    deliver_in(0, src_ip, dst_ip, datagram, ttl, 0);
}

/// `fn(net_ns_id, src_ip, src_port, dst_ip, dst_port, payload, in_ifindex)
/// -> bool` — hand a datagram to the userspace socket layer, which keeps
/// its own port table. Returns whether a socket there consumed it.
///
/// `in_ifindex` is the arrival interface, so that layer can apply the same
/// SO_BINDTODEVICE rule; without it the check would hold for in-kernel
/// sockets and silently not for userspace ones.
type UserDeliverHook = fn(u64, [u8; 4], u16, [u8; 4], u16, &[u8], u32) -> bool;

static USER_DELIVER_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the userspace-socket delivery hook.
///
/// AF_INET datagram sockets live in the userspace crate with their own
/// bookkeeping, so the RX demux has to ask it rather than the other way
/// round — this crate cannot depend on that one.
pub fn install_user_deliver_hook(hook: UserDeliverHook) {
    USER_DELIVER_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
}

#[allow(clippy::too_many_arguments)]
fn user_deliver(
    net_ns_id: u64,
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
    in_ifindex: u32,
) -> bool {
    let raw = USER_DELIVER_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if raw == 0 {
        return false;
    }
    // SAFETY: `raw` was stored by `install_user_deliver_hook` from a
    // `UserDeliverHook`, the only writer of this slot, and function
    // pointers are never unmapped.
    let hook: UserDeliverHook = unsafe { core::mem::transmute(raw) };
    hook(
        net_ns_id, src_ip, src_port, dst_ip, dst_port, payload, in_ifindex,
    )
}

/// Demultiplex a received UDP datagram to the sockets bound for it.
///
/// `in_ifindex` is the interface it ARRIVED on — Linux's `dif` — and 0
/// means "unknown", which matches any socket. Without it SO_BINDTODEVICE
/// cannot be honoured on receive: a socket pinned to one NIC would still be
/// handed datagrams that came in on another.
pub fn deliver_in(
    net_ns_id: u64,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    datagram: &[u8],
    ttl: u8,
    in_ifindex: u32,
) {
    if datagram.len() < UDP_HDR_LEN {
        return;
    }
    let src_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let dst_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let udp_len = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    // `__udp4_lib_rcv` (`net/ipv4/udp.c:2412-2418`): a length field larger
    // than what arrived, or smaller than the header, is a short packet and is
    // dropped; bytes past the length field (link-layer padding) are trimmed.
    if udp_len > datagram.len() || udp_len < UDP_HDR_LEN {
        return;
    }
    let payload = &datagram[UDP_HDR_LEN..udp_len];

    let src_addr = SocketAddrV4::new(src_ip, src_port);

    // Collect candidate sockets for this dst_port.
    // `compute_score` (`net/ipv4/udp.c:398`):
    //
    //     dev_match = udp_sk_bound_dev_eq(net, sk->sk_bound_dev_if, dif, sdif);
    //     if (!dev_match)
    //             return -1;
    //     if (sk->sk_bound_dev_if)
    //             score += 4;
    //
    // Two rules, and both matter. A socket bound to a DIFFERENT interface
    // is not a candidate at all; and among sockets that do match, one bound
    // to this interface OUTRANKS an unbound one — so a wildcard listener
    // does not steal traffic from a socket that asked for this NIC
    // specifically.
    let mut candidates: Vec<Arc<UdpSocket>> = {
        PORTS[port_shard(dst_port)]
            .entries
            .lock()
            .iter()
            .filter(|(p, socket)| {
                if *p != dst_port || socket.net_ns_id != net_ns_id {
                    return false;
                }
                let bound = socket.options.lock().bind_to_device;
                // `inet_bound_dev_eq`: an unbound socket matches anything;
                // a bound one only its own interface. An unknown arrival
                // interface (0) cannot contradict a binding, so it matches.
                bound == 0 || in_ifindex == 0 || bound == in_ifindex
            })
            .map(|(_, s)| s.clone())
            .collect()
    };
    if candidates.len() > 1 {
        // Device-bound sockets first — the `score += 4` above.
        candidates.sort_by_key(|s| u8::from(s.options.lock().bind_to_device == 0));
        let best_is_bound = candidates[0].options.lock().bind_to_device != 0;
        if best_is_bound {
            candidates.retain(|s| s.options.lock().bind_to_device != 0);
        }
    }

    if candidates.is_empty() {
        // No in-kernel socket owns this port. AF_INET datagram sockets live
        // in the userspace crate with their own port table, so ask it
        // before the datagram is dropped — that table is the only place a
        // userspace `bind()` is recorded.
        user_deliver(
            net_ns_id, src_ip, src_port, dst_ip, dst_port, payload, in_ifindex,
        );
        return;
    }

    // SO_REUSEPORT: pick one by round-robin (Linux udp.c:1844).
    // For single-socket case this is just candidates[0].
    let idx = (RR_COUNTER.fetch_add(1, Ordering::Relaxed) as usize) % candidates.len();
    let sock = &candidates[idx];

    // Connected-mode filter: drop if peer doesn't match.
    let peer_opt = *sock.peer.lock();
    if let Some(peer) = peer_opt {
        if peer.ip != src_ip || peer.port != src_port {
            return;
        }
    }

    let opts = sock.options.lock().clone();
    let dg = UdpDatagram {
        src: src_addr,
        dst_ip,
        payload: payload.to_vec(),
        ttl,
    };

    // A full queue drops the ARRIVING datagram and keeps what is already
    // queued: `__udp_enqueue_schedule_skb` (`net/ipv4/udp.c:1527`) checks
    // `if (rmem > rcvbuf) goto drop;` before charging the new skb.
    let mut q = sock.rx_queue.lock();
    if q.len() >= opts.rcvbuf {
        return;
    }
    q.push_back(dg);
}

/// Snapshot of one UDP socket's fields-of-interest, used to
/// render `/proc/net/udp`. Mirrors what Linux's `udp4_seq_show`
/// extracts per row.
#[derive(Clone, Debug)]
pub struct UdpSocketSnapshot {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    /// Linux convention: 7=CLOSE (unconnected UDP), 1=ESTABLISHED
    /// (connected UDP, peer set).
    pub state_code: u8,
    pub tx_queue: u32,
    pub rx_queue: u32,
}

/// Snapshot every bound UDP socket. Cheap: a few fields per entry.
pub fn snapshot() -> alloc::vec::Vec<UdpSocketSnapshot> {
    snapshot_in(0)
}

pub fn snapshot_in(net_ns_id: u64) -> alloc::vec::Vec<UdpSocketSnapshot> {
    // Clone the matching sockets out of every shard first, then read their
    // per-socket fields with no shard lock held.
    let socks: alloc::vec::Vec<Arc<UdpSocket>> = PORTS
        .iter()
        .flat_map(|shard| {
            shard
                .entries
                .lock()
                .iter()
                .filter(|(_, socket)| socket.net_ns_id == net_ns_id)
                .map(|(_, s)| s.clone())
                .collect::<alloc::vec::Vec<_>>()
        })
        .collect();
    let mut out = alloc::vec::Vec::with_capacity(socks.len());
    for s in &socks {
        let peer = *s.peer.lock();
        let (remote_addr, remote_port, state_code) = match peer {
            Some(p) => (p.ip, p.port, 0x01),
            None => ([0u8; 4], 0u16, 0x07),
        };
        let rx_queue = s.rx_queue.lock().len() as u32;
        out.push(UdpSocketSnapshot {
            local_addr: s.local.ip,
            local_port: s.local.port,
            remote_addr,
            remote_port,
            state_code,
            tx_queue: 0, // UDP has no kernel send queue (sync send)
            rx_queue,
        });
    }
    out
}

/// Deliver an ICMP error to the socket whose local addr / port
/// matches the embedded original-datagram header.
/// Called from `icmp_sock::deliver_error`.
pub fn deliver_icmp_error(orig_src_ip: [u8; 4], orig_src_port: u16, err: SockError) {
    deliver_icmp_error_in(0, orig_src_ip, orig_src_port, err);
}

pub fn deliver_icmp_error_in(
    net_ns_id: u64,
    orig_src_ip: [u8; 4],
    orig_src_port: u16,
    err: SockError,
) {
    let candidates: Vec<Arc<UdpSocket>> = {
        PORTS[port_shard(orig_src_port)]
            .entries
            .lock()
            .iter()
            // `__udp4_lib_lookup` matches a wildcard (INADDR_ANY) bind as
            // well as an exact one; requiring an exact local address meant a
            // socket bound to 0.0.0.0 never saw its ICMP errors (so never
            // learned ECONNREFUSED).
            .filter(|(p, s)| {
                *p == orig_src_port
                    && s.net_ns_id == net_ns_id
                    && (s.local.ip == orig_src_ip || s.local.ip == [0, 0, 0, 0])
            })
            .map(|(_, s)| s.clone())
            .collect()
    };
    for sock in candidates {
        sock.err_queue.lock().push_back(err.clone());
    }
}

// ── Tests ──────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_udp_bind_ephemeral_port_range() -> TestResult {
    let sock = match udp_bind(SocketAddrV4::UNSPECIFIED, UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind ephemeral failed"),
    };
    let p = sock.local.port;
    udp_close(&sock);
    if !(UDP_EPHEMERAL_MIN..=UDP_EPHEMERAL_MAX).contains(&p) {
        return TestResult::Fail("ephemeral port outside Linux 32768-60999 range");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_bind_ephemeral_port_range);

fn smoke_udp_bind_collision_returns_addr_in_use() -> TestResult {
    let port = 59001u16;
    let addr = SocketAddrV4::new([127, 0, 0, 1], port);
    let s1 = match udp_bind(addr, UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("first bind failed"),
    };
    let result = udp_bind(addr, UdpOptions::default());
    udp_close(&s1);
    match result {
        Err(UdpError::AddrInUse) => TestResult::Pass,
        _ => TestResult::Fail("expected AddrInUse on duplicate bind"),
    }
}
kernel_test_in!("net/udp", smoke_udp_bind_collision_returns_addr_in_use);

fn smoke_udp_reuseport_two_sockets_same_port() -> TestResult {
    let port = 59002u16;
    let addr = SocketAddrV4::new([127, 0, 0, 1], port);
    let opts = UdpOptions {
        reuseport: true,
        ..Default::default()
    };
    let s1 = match udp_bind(addr, opts.clone()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("s1 bind failed"),
    };
    let s2 = match udp_bind(addr, opts) {
        Ok(s) => s,
        Err(_) => {
            udp_close(&s1);
            return TestResult::Fail("s2 bind failed — SO_REUSEPORT should allow it");
        }
    };
    udp_close(&s1);
    udp_close(&s2);
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_reuseport_two_sockets_same_port);

fn smoke_udp_recv_loopback_inject() -> TestResult {
    let port = 59010u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let payload = b"hello-udp";
    // Simulate the RX path: build a raw UDP segment and call deliver.
    let mut seg = [0u8; 8 + 9]; // UDP header + "hello-udp"
    seg[0..2].copy_from_slice(&9001u16.to_be_bytes()); // src port
    seg[2..4].copy_from_slice(&port.to_be_bytes()); // dst port
    seg[4..6].copy_from_slice(&(17u16).to_be_bytes()); // length=17
    seg[6..8].copy_from_slice(&[0, 0]); // checksum disabled
    seg[8..17].copy_from_slice(payload);

    deliver([10, 0, 0, 1], [0, 0, 0, 0], &seg, 64);

    let mut buf = [0u8; 64];
    let result = udp_recv(&sock, &mut buf);
    udp_close(&sock);
    match result {
        Ok((n, src)) => {
            if &buf[..n] != payload {
                return TestResult::Fail("payload mismatch");
            }
            if src.port != 9001 {
                return TestResult::Fail("src port mismatch");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("recv returned error after deliver"),
    }
}
kernel_test_in!("net/udp", smoke_udp_recv_loopback_inject);

fn smoke_udp_connected_mode_filters_peer() -> TestResult {
    let port = 59011u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    // Connect to 10.0.0.2:9002 — traffic from 10.0.0.99:9003 must be dropped.
    udp_connect(&sock, SocketAddrV4::new([10, 0, 0, 2], 9002));

    let mut seg = [0u8; 8 + 4];
    seg[0..2].copy_from_slice(&9003u16.to_be_bytes()); // wrong src port
    seg[2..4].copy_from_slice(&port.to_be_bytes());
    seg[4..6].copy_from_slice(&(12u16).to_be_bytes());
    seg[8..12].copy_from_slice(b"drop");
    deliver([10, 0, 0, 99], [0, 0, 0, 0], &seg, 64);

    let mut buf = [0u8; 64];
    let result = udp_recv(&sock, &mut buf);
    udp_close(&sock);
    match result {
        Err(UdpError::WouldBlock) => TestResult::Pass,
        _ => TestResult::Fail("connected-mode filter failed: wrong-peer packet accepted"),
    }
}
kernel_test_in!("net/udp", smoke_udp_connected_mode_filters_peer);

fn smoke_udp_broadcast_guard() -> TestResult {
    // Without SO_BROADCAST, sending to 255.255.255.255 must fail.
    let port = 59012u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let peer = SocketAddrV4::new([255, 255, 255, 255], 9999);
    let result = udp_send(&sock, b"broadcast", Some(peer));
    udp_close(&sock);
    match result {
        Err(UdpError::NoBroadcastPermission) => TestResult::Pass,
        _ => TestResult::Fail("expected NoBroadcastPermission without SO_BROADCAST"),
    }
}
kernel_test_in!("net/udp", smoke_udp_broadcast_guard);

/// A full queue drops the ARRIVING datagram and keeps the queued ones:
/// `__udp_enqueue_schedule_skb` (`net/ipv4/udp.c:1527`) is
/// `if (rmem > rcvbuf) goto drop;` before charging the new skb.
fn smoke_udp_rcvbuf_full_drops_newest() -> TestResult {
    let port = 59013u16;
    let opts = UdpOptions {
        rcvbuf: 2, // keep only 2 datagrams
        ..Default::default()
    };
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), opts) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    // Inject 3 datagrams: A, B, C. C arrives at a full queue and is dropped.
    for b in [b'A', b'B', b'C'] {
        deliver([10, 0, 0, 1], [0, 0, 0, 0], &seg(9001, port, &[b]), 64);
    }
    let mut got = alloc::vec::Vec::new();
    let mut buf = [0u8; 8];
    while let Ok((1, _)) = udp_recv(&sock, &mut buf) {
        got.push(buf[0]);
    }
    udp_close(&sock);
    if got != [b'A', b'B'] {
        return TestResult::Fail("full queue must keep A,B and drop the arriving C");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_rcvbuf_full_drops_newest);

fn smoke_udp_large_datagram_under_mtu() -> TestResult {
    // 1400-byte payload: within typical 1500-byte MTU. Deliver and recv.
    let port = 59014u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let big_payload = alloc::vec![0xABu8; 1400];
    let mut seg = alloc::vec![0u8; UDP_HDR_LEN + 1400];
    seg[0..2].copy_from_slice(&9001u16.to_be_bytes());
    seg[2..4].copy_from_slice(&port.to_be_bytes());
    seg[4..6].copy_from_slice(&((UDP_HDR_LEN + 1400) as u16).to_be_bytes());
    seg[UDP_HDR_LEN..].copy_from_slice(&big_payload);

    deliver([10, 0, 0, 1], [0, 0, 0, 0], &seg, 64);

    let mut buf = alloc::vec![0u8; 1500];
    let result = udp_recv(&sock, &mut buf);
    udp_close(&sock);
    match result {
        Ok((1400, _)) => TestResult::Pass,
        Ok((_n, _)) => TestResult::Fail("large datagram length mismatch"),
        Err(_) => TestResult::Fail("large datagram recv failed"),
    }
}
kernel_test_in!("net/udp", smoke_udp_large_datagram_under_mtu);

fn smoke_udp_reuseport_load_balance() -> TestResult {
    let port = 59015u16;
    let addr = SocketAddrV4::new([0, 0, 0, 0], port);
    let opts = UdpOptions {
        reuseport: true,
        ..Default::default()
    };
    let s1 = match udp_bind(addr, opts.clone()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("s1 bind failed"),
    };
    let s2 = match udp_bind(addr, opts) {
        Ok(s) => s,
        Err(_) => {
            udp_close(&s1);
            return TestResult::Fail("s2 bind failed");
        }
    };

    // Deliver 4 datagrams; round-robin should give 2 to each socket.
    for i in 0..4u8 {
        let mut seg = [0u8; 9];
        seg[0..2].copy_from_slice(&9001u16.to_be_bytes());
        seg[2..4].copy_from_slice(&port.to_be_bytes());
        seg[4..6].copy_from_slice(&(9u16).to_be_bytes());
        seg[8] = i;
        deliver([10, 0, 0, 1], [0, 0, 0, 0], &seg, 64);
    }

    let q1 = s1.rx_queue.lock().len();
    let q2 = s2.rx_queue.lock().len();
    udp_close(&s1);
    udp_close(&s2);

    if q1 + q2 != 4 {
        return TestResult::Fail("total datagram count wrong after load-balance");
    }
    if q1 == 0 || q2 == 0 {
        return TestResult::Fail("load-balance delivered all frames to one socket");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_reuseport_load_balance);

/// Fragmentation reassembly: simulate the IP layer reassembling two
/// fragments and handing the complete datagram to `deliver`.  In the
/// NARF stack the IP layer calls `deliver` with the fully reassembled
/// UDP segment (header + payload); this test verifies that path
/// accepts a large payload produced by stitching two 500-byte chunks.
///
/// Linux ref: `ip_defrag` → `ip_frag_queue` reassembles fragments
/// then calls `ip_local_deliver_finish` → UDP `udp_rcv` with the
/// complete segment (net/ipv4/reassembly.c, net/ipv4/udp.c:2069).
fn smoke_udp_fragment_reassembly_via_deliver() -> TestResult {
    let port = 59016u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };

    // Build a 1000-byte payload split across two 500-byte IP fragments
    // that the IP layer would reassemble into one UDP segment.
    let payload: alloc::vec::Vec<u8> = (0u8..200).cycle().take(1000).collect();

    // After IP-level reassembly, deliver() receives the full UDP segment.
    let total_udp = UDP_HDR_LEN + payload.len();
    let mut seg = alloc::vec![0u8; total_udp];
    seg[0..2].copy_from_slice(&9001u16.to_be_bytes()); // src port
    seg[2..4].copy_from_slice(&port.to_be_bytes()); // dst port
    seg[4..6].copy_from_slice(&(total_udp as u16).to_be_bytes()); // length
    seg[6..8].copy_from_slice(&[0, 0]); // checksum (optional)
    seg[UDP_HDR_LEN..].copy_from_slice(&payload);

    deliver([10, 0, 0, 5], [0, 0, 0, 0], &seg, 64);

    let mut buf = alloc::vec![0u8; 1100];
    let result = udp_recv(&sock, &mut buf);
    udp_close(&sock);
    match result {
        Ok((n, _src)) => {
            if n != payload.len() {
                return TestResult::Fail("reassembled datagram length mismatch");
            }
            if buf[..n] != payload[..] {
                return TestResult::Fail("reassembled datagram payload mismatch");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("recv failed after reassembled deliver"),
    }
}
kernel_test_in!("net/udp", smoke_udp_fragment_reassembly_via_deliver);

/// IP_TTL setsockopt: verify the option field is stored correctly.
/// (Wire verification requires a real iface; this tests the option state.)
fn smoke_udp_ip_ttl_tos_setsockopt() -> TestResult {
    let port = 59017u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    udp_setsockopt(&sock, UdpSockOpt::IpTtl(128));
    udp_setsockopt(&sock, UdpSockOpt::IpTos(0x10)); // DSCP AF11
    let opts = sock.options.lock();
    let ttl_ok = opts.ip_ttl == 128;
    let tos_ok = opts.ip_tos == 0x10;
    drop(opts);
    udp_close(&sock);
    if !ttl_ok {
        return TestResult::Fail("IP_TTL not stored correctly");
    }
    if !tos_ok {
        return TestResult::Fail("IP_TOS not stored correctly");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_ip_ttl_tos_setsockopt);

/// A UDP segment `sport → dport` carrying `payload`, checksum disabled.
fn seg(sport: u16, dport: u16, payload: &[u8]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; UDP_HDR_LEN + payload.len()];
    v[0..2].copy_from_slice(&sport.to_be_bytes());
    v[2..4].copy_from_slice(&dport.to_be_bytes());
    v[4..6].copy_from_slice(&((UDP_HDR_LEN + payload.len()) as u16).to_be_bytes());
    v[UDP_HDR_LEN..].copy_from_slice(payload);
    v
}

/// Malformed length fields are dropped, trailing padding is trimmed
/// (`__udp4_lib_rcv`, `net/ipv4/udp.c:2412-2418`).
fn smoke_udp_deliver_validates_length_field() -> TestResult {
    let port = 59020u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let mut buf = [0u8; 64];
    // Shorter than a header: ignored.
    deliver([10, 0, 0, 1], [0, 0, 0, 0], &[0u8; 7], 64);
    // Length field bigger than the segment: short packet, dropped.
    let mut long = seg(9001, port, b"data");
    long[4..6].copy_from_slice(&100u16.to_be_bytes());
    deliver([10, 0, 0, 1], [0, 0, 0, 0], &long, 64);
    // Length field smaller than the header: dropped.
    let mut tiny = seg(9001, port, b"data");
    tiny[4..6].copy_from_slice(&4u16.to_be_bytes());
    deliver([10, 0, 0, 1], [0, 0, 0, 0], &tiny, 64);
    if udp_recv(&sock, &mut buf) != Err(UdpError::WouldBlock) {
        udp_close(&sock);
        return TestResult::Fail("a malformed datagram was queued");
    }
    // Link-layer padding after the datagram: trimmed to the length field.
    let mut padded = seg(9001, port, b"abc");
    padded.extend_from_slice(&[0xEE; 5]);
    deliver([10, 0, 0, 1], [0, 0, 0, 0], &padded, 64);
    let r = udp_recv(&sock, &mut buf);
    udp_close(&sock);
    match r {
        Ok((3, _)) if &buf[..3] == b"abc" => TestResult::Pass,
        _ => TestResult::Fail("padding was not trimmed to the UDP length field"),
    }
}
kernel_test_in!("net/udp", smoke_udp_deliver_validates_length_field);

/// A short receive buffer gets the head of the datagram; the rest is gone.
fn smoke_udp_recv_truncates_to_buffer() -> TestResult {
    let port = 59021u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    deliver(
        [10, 0, 0, 1],
        [0, 0, 0, 0],
        &seg(9001, port, b"0123456789"),
        64,
    );
    let mut small = [0u8; 4];
    let first = udp_recv(&sock, &mut small);
    let second = udp_recv(&sock, &mut [0u8; 16]);
    udp_close(&sock);
    if first != Ok((4, SocketAddrV4::new([10, 0, 0, 1], 9001))) || &small != b"0123" {
        return TestResult::Fail("truncated recv did not return the first 4 bytes and source");
    }
    if second != Err(UdpError::WouldBlock) {
        return TestResult::Fail("the truncated remainder was left queued");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_recv_truncates_to_buffer);

/// Disconnect lifts the connected-peer filter.
fn smoke_udp_disconnect_accepts_any_peer() -> TestResult {
    let port = 59022u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    udp_connect(&sock, SocketAddrV4::new([10, 0, 0, 2], 9002));
    deliver([10, 0, 0, 2], [0, 0, 0, 0], &seg(9002, port, b"p"), 64);
    deliver([10, 0, 0, 3], [0, 0, 0, 0], &seg(9003, port, b"x"), 64);
    let mut buf = [0u8; 4];
    let peer_ok = udp_recv(&sock, &mut buf) == Ok((1, SocketAddrV4::new([10, 0, 0, 2], 9002)));
    let filtered = udp_recv(&sock, &mut buf) == Err(UdpError::WouldBlock);
    udp_disconnect(&sock);
    deliver([10, 0, 0, 3], [0, 0, 0, 0], &seg(9003, port, b"y"), 64);
    let after = udp_recv(&sock, &mut buf);
    udp_close(&sock);
    if !peer_ok {
        return TestResult::Fail("connected socket did not receive from its peer");
    }
    if !filtered {
        return TestResult::Fail("connected socket received from a stranger");
    }
    if after != Ok((1, SocketAddrV4::new([10, 0, 0, 3], 9003))) {
        return TestResult::Fail("disconnected socket still filters");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_disconnect_accepts_any_peer);

/// `udp_send` with no destination on an unconnected socket is refused.
fn smoke_udp_send_unconnected_without_peer_fails() -> TestResult {
    let sock = match udp_bind(
        SocketAddrV4::new([0, 0, 0, 0], 59023),
        UdpOptions::default(),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let r = udp_send(&sock, b"x", None);
    udp_close(&sock);
    if r != Err(UdpError::InvalidSocket) {
        return TestResult::Fail("send without a destination did not fail");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_send_unconnected_without_peer_fails);

/// The 65507-byte ceiling holds even with a larger SO_SNDBUF
/// (`__ip_append_data`, `net/ipv4/ip_output.c:992-995`) — otherwise the
/// 16-bit UDP/IP length fields would wrap — and SO_SNDBUF itself is honoured.
fn smoke_udp_send_size_limits() -> TestResult {
    let sock = match udp_bind(
        SocketAddrV4::new([0, 0, 0, 0], 59024),
        UdpOptions::default(),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let dst = Some(SocketAddrV4::new([10, 0, 0, 2], 9));
    udp_setsockopt(&sock, UdpSockOpt::SndBuf(200_000));
    let big = alloc::vec![0u8; UDP_MAX_PAYLOAD + 1];
    let over_ip = udp_send(&sock, &big, dst);
    udp_setsockopt(&sock, UdpSockOpt::SndBuf(10));
    let over_sndbuf = udp_send(&sock, &big[..11], dst);
    udp_close(&sock);
    if over_ip != Err(UdpError::MsgTooLong) {
        return TestResult::Fail("a 65508-byte payload was not refused");
    }
    if over_sndbuf != Err(UdpError::MsgTooLong) {
        return TestResult::Fail("a payload over SO_SNDBUF was not refused");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_send_size_limits);

/// ICMP errors land on the socket whose local addr/port sent the datagram;
/// peek leaves them queued, recv drains them.
fn smoke_udp_icmp_error_queue() -> TestResult {
    let local = [10, 0, 0, 5];
    let sock = match udp_bind(SocketAddrV4::new(local, 59025), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let err = SockError {
        icmp_type: 3,
        icmp_code: 3,
        from_ip: [10, 0, 0, 9],
    };
    // Wrong local address: not ours.
    deliver_icmp_error([10, 0, 0, 6], 59025, err.clone());
    let none = udp_err_peek(&sock).is_none();
    deliver_icmp_error(local, 59025, err);
    let peeked = udp_err_peek(&sock).map(|e| (e.icmp_type, e.icmp_code));
    let got = udp_err_recv(&sock).map(|e| e.from_ip);
    let drained = udp_err_recv(&sock).is_none();
    udp_close(&sock);
    if !none {
        return TestResult::Fail("an error for another local address was queued");
    }
    if peeked != Some((3, 3)) {
        return TestResult::Fail("peek did not show the queued error");
    }
    if got != Some([10, 0, 0, 9]) || !drained {
        return TestResult::Fail("recv did not drain exactly the one error");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_icmp_error_queue);

/// `/proc/net/udp` rows: state 7 (CLOSE) unconnected, 1 (ESTABLISHED)
/// connected with the remote filled in, and the rx queue depth.
fn smoke_udp_snapshot_rows() -> TestResult {
    let port = 59026u16;
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let row = |p: u16| snapshot().into_iter().find(|r| r.local_port == p);
    let unconnected = row(port);
    udp_connect(&sock, SocketAddrV4::new([10, 0, 0, 2], 9002));
    deliver([10, 0, 0, 2], [0, 0, 0, 0], &seg(9002, port, b"q"), 64);
    let connected = row(port);
    udp_close(&sock);
    let gone = row(port).is_none();
    match unconnected {
        Some(r) if r.state_code == 0x07 && r.remote_port == 0 && r.rx_queue == 0 => {}
        _ => return TestResult::Fail("unconnected row is not CLOSE with an empty queue"),
    }
    match connected {
        Some(r)
            if r.state_code == 0x01
                && r.remote_addr == [10, 0, 0, 2]
                && r.remote_port == 9002
                && r.rx_queue == 1 => {}
        _ => {
            return TestResult::Fail("connected row is not ESTABLISHED with the peer and 1 queued")
        }
    }
    if !gone {
        return TestResult::Fail("closed socket still listed");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_snapshot_rows);

/// Network namespaces are separate port spaces: the same port binds in two
/// namespaces, a datagram reaches only its own namespace's socket, and
/// tearing a namespace down removes its sockets.
fn smoke_udp_namespace_isolation() -> TestResult {
    const NS: u64 = 0x5EED_0001;
    let port = 59027u16;
    let any = SocketAddrV4::new([0, 0, 0, 0], port);
    let host = match udp_bind(any, UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("host bind failed"),
    };
    let guest = match udp_bind_in(NS, any, UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => {
            udp_close(&host);
            return TestResult::Fail("same port in another namespace was refused");
        }
    };
    deliver_in(
        NS,
        [10, 0, 0, 1],
        [0, 0, 0, 0],
        &seg(9001, port, b"g"),
        64,
        0,
    );
    let mut buf = [0u8; 4];
    let host_empty = udp_recv(&host, &mut buf) == Err(UdpError::WouldBlock);
    let guest_got = udp_recv(&guest, &mut buf).is_ok();
    remove_namespace(NS);
    let torn_down = snapshot_in(NS).is_empty();
    udp_close(&host);
    if !host_empty {
        return TestResult::Fail("a datagram crossed into the host namespace");
    }
    if !guest_got {
        return TestResult::Fail("the namespace's own socket did not receive");
    }
    if !torn_down {
        return TestResult::Fail("remove_namespace left sockets behind");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_namespace_isolation);

/// SO_BINDTODEVICE on receive — `compute_score` (`net/ipv4/udp.c:401-406`):
/// a socket pinned to another device is not a candidate, and one pinned to
/// the arrival device outranks an unbound one.
fn smoke_udp_bindtodevice_rx_scoring() -> TestResult {
    let port = 59028u16;
    let any = SocketAddrV4::new([0, 0, 0, 0], port);
    let opts = UdpOptions {
        reuseport: true,
        ..Default::default()
    };
    let (Ok(unbound), Ok(pinned)) = (udp_bind(any, opts.clone()), udp_bind(any, opts)) else {
        return TestResult::Fail("reuseport binds failed");
    };
    udp_setsockopt(&pinned, UdpSockOpt::BindToDevice(5));
    let mut buf = [0u8; 4];
    let mut take = |s: &Arc<UdpSocket>| udp_recv(s, &mut buf).is_ok();
    // Arrived on device 5: the pinned socket wins every time.
    for _ in 0..4 {
        deliver_in(
            0,
            [10, 0, 0, 1],
            [0, 0, 0, 0],
            &seg(9001, port, b"5"),
            64,
            5,
        );
    }
    let pinned_all = (0..4).all(|_| take(&pinned)) && !take(&unbound);
    // Arrived on device 6: the pinned socket is not a candidate.
    deliver_in(
        0,
        [10, 0, 0, 1],
        [0, 0, 0, 0],
        &seg(9001, port, b"6"),
        64,
        6,
    );
    let unbound_got = take(&unbound) && !take(&pinned);
    udp_close(&unbound);
    udp_close(&pinned);
    if !pinned_all {
        return TestResult::Fail("a device-bound socket did not outrank the unbound one");
    }
    if !unbound_got {
        return TestResult::Fail("traffic from another device reached the device-bound socket");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_bindtodevice_rx_scoring);

/// close() frees the port for a new bind.
fn smoke_udp_close_frees_port() -> TestResult {
    let addr = SocketAddrV4::new([127, 0, 0, 1], 59029);
    let Ok(a) = udp_bind(addr, UdpOptions::default()) else {
        return TestResult::Fail("bind failed");
    };
    udp_close(&a);
    match udp_bind(addr, UdpOptions::default()) {
        Ok(b) => {
            udp_close(&b);
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("port still taken after close"),
    }
}
kernel_test_in!("net/udp", smoke_udp_close_frees_port);

/// Broadcast classification (`RTCF_BROADCAST`): the limited broadcast and a
/// local subnet's `prefix | ~mask` (`fib_add_ifaddr`,
/// `net/ipv4/fib_frontend.c:1147`) — not a host address that merely ends in
/// .255, and not a /31's "broadcast".
fn smoke_udp_broadcast_classification() -> TestResult {
    const IFACE: &str = "udpbc0";
    iface::register(IFACE, [0x02, 0, 0, 0, 0xBC, 0], |_| Ok(()));
    iface::add_addr(IFACE, [10, 91, 0, 2], 16);
    iface::add_addr(IFACE, [10, 92, 0, 0], 31);
    let checks = [
        ([255, 255, 255, 255], true),
        ([10, 91, 255, 255], true),
        ([10, 91, 1, 255], false),
        ([10, 92, 0, 1], false),
    ];
    let ok = checks
        .iter()
        .all(|(ip, want)| iface::is_broadcast_in(0, *ip) == *want);
    // And udp_send enforces it: the directed broadcast needs SO_BROADCAST.
    let sock = match udp_bind(
        SocketAddrV4::new([0, 0, 0, 0], 59030),
        UdpOptions::default(),
    ) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    let r = udp_send(&sock, b"x", Some(SocketAddrV4::new([10, 91, 255, 255], 9)));
    udp_close(&sock);
    iface::del_addr(IFACE, [10, 91, 0, 2], 16);
    iface::del_addr(IFACE, [10, 92, 0, 0], 31);
    if !ok {
        return TestResult::Fail("broadcast classification is wrong");
    }
    if r != Err(UdpError::NoBroadcastPermission) {
        return TestResult::Fail("directed broadcast without SO_BROADCAST was not refused");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_broadcast_classification);

static WIRE_CAPTURE: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn wire_capture_send(frame: &[u8]) -> Result<(), ()> {
    WIRE_CAPTURE.lock().push(frame.to_vec());
    Ok(())
}

/// The frame `udp_send` puts on the wire: valid IPv4 header and checksum,
/// IP_TTL / IP_TOS applied, UDP ports, length and a checksum that verifies
/// over the pseudo-header (RFC 768).
fn smoke_udp_send_wire_frame_is_well_formed() -> TestResult {
    const IFACE: &str = "udpwire0";
    const LOCAL: [u8; 4] = [10, 93, 0, 2];
    const PEER: [u8; 4] = [10, 93, 0, 9];
    const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x93, 9];
    iface::register(IFACE, [0x02, 0, 0, 0, 0x93, 2], wire_capture_send);
    iface::set_iface_ipv4(IFACE, LOCAL, LOCAL);
    iface::add_addr(IFACE, LOCAL, 24);
    crate::arp_cache::insert(IFACE, PEER, PEER_MAC);
    crate::tcp_stack::__arp_insert_legacy(PEER, PEER_MAC);
    WIRE_CAPTURE.lock().clear();

    let sock = match udp_bind(SocketAddrV4::new(LOCAL, 59031), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    udp_setsockopt(&sock, UdpSockOpt::IpTtl(33));
    udp_setsockopt(&sock, UdpSockOpt::IpTos(0x28));
    let sent = udp_send(&sock, b"wire!", Some(SocketAddrV4::new(PEER, 5353)));
    udp_close(&sock);
    if sent != Ok(5) {
        return TestResult::Fail("udp_send to an on-link peer failed");
    }
    let frames = core::mem::take(&mut *WIRE_CAPTURE.lock());
    let Some(f) = frames.first() else {
        return TestResult::Fail("no frame reached the interface");
    };
    if f.len() != ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + 5 {
        return TestResult::Fail("frame length is not eth + ip + udp + payload");
    }
    if f[0..6] != PEER_MAC || u16::from_be_bytes([f[12], f[13]]) != ETHERTYPE_IPV4 {
        return TestResult::Fail("ethernet header is wrong");
    }
    let ip = &f[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN];
    if ip[0] != 0x45 || ip[1] != 0x28 || ip[8] != 33 || ip[9] != IP_PROTO_UDP {
        return TestResult::Fail("IPv4 version/IHL, TOS, TTL or protocol is wrong");
    }
    if ip_checksum(ip) != 0 {
        return TestResult::Fail("IPv4 header checksum does not verify");
    }
    if ip[12..16] != LOCAL || ip[16..20] != PEER {
        return TestResult::Fail("IPv4 addresses are wrong");
    }
    let udp = &f[ETH_HDR_LEN + IPV4_HDR_LEN..];
    let h = UdpHeader::decode(udp).unwrap_or_default();
    if h.src_port != 59031 || h.dst_port != 5353 || h.length as usize != udp.len() {
        return TestResult::Fail("UDP ports or length are wrong");
    }
    // Zero means "no checksum" on the wire; the sender always computes one
    // (and sends 0xFFFF for a computed 0, RFC 768).
    if h.checksum == 0 || crate::pkt_udp::verify_ipv4(LOCAL, PEER, udp).is_err() {
        return TestResult::Fail("UDP checksum does not verify");
    }
    if &udp[UDP_HDR_LEN..] != b"wire!" {
        return TestResult::Fail("payload is wrong");
    }
    TestResult::Pass
}
kernel_test_in!("net/udp", smoke_udp_send_wire_frame_is_well_formed);
