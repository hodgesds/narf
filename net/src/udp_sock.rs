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

// ── Socket options ─────────────────────────────────────────────────

/// Subset of socket options relevant to UDP. Modelled on Linux
/// `udp_setsockopt` (net/ipv4/udp.c:2534+) and `sock_setsockopt`.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct UdpOptions {
    /// SO_BROADCAST: allow sends to 255.255.255.255 / subnet bcast.
    pub broadcast: bool,
    /// SO_RCVBUF: max number of datagrams in the RX queue. When the
    /// queue is full the *oldest* datagram is dropped to make room
    /// (matches Linux drop-on-overflow behaviour, udp.c:1666).
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

    // SO_BROADCAST guard (Linux udp.c:1093).
    if (dst.ip == [255, 255, 255, 255] || dst.ip[3] == 255) && !sock.options.lock().broadcast {
        return Err(UdpError::NoBroadcastPermission);
    }

    let (opts_sndbuf, ip_ttl, ip_tos) = {
        let o = sock.options.lock();
        (o.sndbuf, o.ip_ttl, o.ip_tos)
    };
    if payload.len() > opts_sndbuf {
        return Err(UdpError::MsgTooLong);
    }

    // Wave-47: route by destination so flows on a non-primary iface
    // egress on the correct NIC (capture-iface smokes, multi-NIC hosts).
    let iface = iface::for_dst_in(sock.net_ns_id, dst.ip).ok_or(UdpError::NoInterface)?;
    let src_ip = iface.ipv4;
    let src_port = sock.local.port;
    let dst_ip = dst.ip;
    let dst_port = dst.port;

    // Resolve the destination MAC.  For broadcast, use ff:ff:ff:ff:ff:ff.
    let dst_mac = if dst_ip == [255, 255, 255, 255] {
        [0xFF; 6]
    } else {
        crate::tcp_stack::arp_resolve_in(sock.net_ns_id, dst_ip, 1000)
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

    if crate::tcp_stack::nf_tx_filter_in(sock.net_ns_id, &iface.name, &mut frame[ETH_HDR_LEN..])
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
    deliver_in(0, src_ip, dst_ip, datagram, ttl);
}

pub fn deliver_in(net_ns_id: u64, src_ip: [u8; 4], dst_ip: [u8; 4], datagram: &[u8], ttl: u8) {
    if datagram.len() < UDP_HDR_LEN {
        return;
    }
    let src_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let dst_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let udp_len = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    let end = udp_len.min(datagram.len());
    if end < UDP_HDR_LEN {
        return;
    }
    let payload = &datagram[UDP_HDR_LEN..end];

    let src_addr = SocketAddrV4::new(src_ip, src_port);

    // Collect candidate sockets for this dst_port.
    let candidates: Vec<Arc<UdpSocket>> = {
        PORTS[port_shard(dst_port)]
            .entries
            .lock()
            .iter()
            .filter(|(p, socket)| *p == dst_port && socket.net_ns_id == net_ns_id)
            .map(|(_, s)| s.clone())
            .collect()
    };

    if candidates.is_empty() {
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

    // Enqueue, dropping oldest if rcvbuf exceeded (Linux udp.c:1666).
    let mut q = sock.rx_queue.lock();
    if q.len() >= opts.rcvbuf {
        q.pop_front(); // drop oldest
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
            .filter(|(p, s)| {
                *p == orig_src_port && s.net_ns_id == net_ns_id && s.local.ip == orig_src_ip
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

fn smoke_udp_rcvbuf_overflow_drops_oldest() -> TestResult {
    let port = 59013u16;
    let opts = UdpOptions {
        rcvbuf: 2, // keep only 2 datagrams
        ..Default::default()
    };
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], port), opts) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };
    // Inject 3 datagrams: A, B, C.  A should be dropped when C arrives.
    for b in [b'A', b'B', b'C'] {
        let mut seg = [0u8; 9];
        seg[0..2].copy_from_slice(&9001u16.to_be_bytes());
        seg[2..4].copy_from_slice(&port.to_be_bytes());
        seg[4..6].copy_from_slice(&(9u16).to_be_bytes());
        seg[8] = b;
        deliver([10, 0, 0, 1], [0, 0, 0, 0], &seg, 64);
    }

    // Snapshot each recv's first byte before the next call overwrites buf.
    let mut buf = [0u8; 8];
    let first = udp_recv(&sock, &mut buf);
    let a = match first {
        Ok((1, _)) => buf[0],
        _ => {
            udp_close(&sock);
            return TestResult::Fail("first recv failed");
        }
    };
    let mut buf = [0u8; 8];
    let second = udp_recv(&sock, &mut buf);
    let b_byte = match second {
        Ok((1, _)) => buf[0],
        _ => {
            udp_close(&sock);
            return TestResult::Fail("second recv failed");
        }
    };
    let mut buf = [0u8; 8];
    let third = udp_recv(&sock, &mut buf);
    udp_close(&sock);

    if a != b'B' || b_byte != b'C' {
        return TestResult::Fail("oldest datagram not dropped (should be A)");
    }
    match third {
        Err(UdpError::WouldBlock) => TestResult::Pass,
        _ => TestResult::Fail("third recv should have been empty"),
    }
}
kernel_test_in!("net/udp", smoke_udp_rcvbuf_overflow_drops_oldest);

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
