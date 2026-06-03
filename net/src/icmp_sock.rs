//! ICMP socket layer — echo (SOCK_DGRAM IPPROTO_ICMP) and raw
//! (SOCK_RAW IPPROTO_ICMP).
//!
//! References (clean-room):
//! - RFC 792 — ICMP. <https://datatracker.ietf.org/doc/html/rfc792>
//! - Linux net/ipv4/icmp.c — `icmp_rcv` dispatch (line ~1067),
//!   echo-request/reply handling (`icmp_echo`, `ping_rcv`), error
//!   routing back to originating sockets (`icmp_err` / `udp_err`),
//!   ping_group_range checks.
//! - Linux net/ipv4/raw.c — raw socket RX delivery (`raw_rcv`), filter.
//!
//! Two socket kinds:
//!
//! 1. **Echo socket** (`IcmpEchoSocket`): sends Echo Requests and
//!    waits for the matching Echo Reply.  Identified by `(identifier, seq)`.
//!    Mirrors the Linux `SOCK_DGRAM`/`IPPROTO_ICMP` ping socket
//!    introduced by net.ipv4.ping_group_range.
//!
//! 2. **Raw ICMP socket** (`IcmpRawSocket`): receives every ICMP
//!    packet whose source IP matches an optional filter.
//!
//! Error routing: when an ICMP Dest Unreach or Time Exceeded arrives,
//! `deliver_error` extracts the embedded original IP+UDP/TCP header,
//! looks up the originating UDP socket, and enqueues a `SockError`
//! on it.  TCP errors are also delivered to the TCB table (simple
//! state-machine reset on Dest Unreach).

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::iface;
use crate::pkt::{
    ip_checksum, parse_ipv4, set_ipv4_checksum, write_eth_header, write_ipv4_header,
    ETHERTYPE_IPV4, ETH_HDR_LEN, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST, IPV4_HDR_LEN, IP_PROTO_ICMP,
    IP_PROTO_TCP, IP_PROTO_UDP,
};
use crate::pkt_icmp_extra::{ICMP_DEST_UNREACHABLE, ICMP_TIME_EXCEEDED};
use crate::tcp_stack::arp_resolve;
use crate::udp_sock::{deliver_icmp_error, SockError};

// ── Global echo-ID counter ─────────────────────────────────────────
//
// Mirrors Linux ping.c where each new ping socket gets a unique
// identifier (the socket's hash in the ping table; here we use a
// monotonically incrementing counter).

static NEXT_ECHO_ID: AtomicU16 = AtomicU16::new(1);

// ── Received ICMP datagram ─────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct IcmpDatagram {
    /// Source IP.
    pub src: [u8; 4],
    /// ICMP type.
    pub icmp_type: u8,
    /// ICMP code.
    pub icmp_code: u8,
    /// Full ICMP payload (after the 4-byte type/code/checksum header).
    pub payload: Vec<u8>,
}

// ── Echo socket ────────────────────────────────────────────────────

/// Pending echo reply slot.
#[derive(Debug)]
pub(crate) struct PendingEcho {
    #[allow(dead_code)]
    pub(crate) identifier: u16,
    pub(crate) seq: u16,
    /// Echo Reply received (payload).
    pub(crate) reply: Option<Vec<u8>>,
    /// Transmit timestamp in nanoseconds (for RTT).
    pub(crate) sent_ns: u64,
    /// Receive timestamp in nanoseconds.
    pub(crate) recv_ns: u64,
}

/// An ICMP echo socket.  Represents a single `ping` session.
#[derive(Debug)]
pub struct IcmpEchoSocket {
    pub identifier: u16,
    pending: IrqSafeSpinLock<VecDeque<PendingEcho>>,
}

impl IcmpEchoSocket {
    fn new(id: u16) -> Self {
        Self {
            identifier: id,
            pending: IrqSafeSpinLock::new(VecDeque::new()),
        }
    }
}

// ── Raw ICMP socket ────────────────────────────────────────────────

/// Filter applied when delivering ICMP packets to a raw socket.
#[derive(Copy, Clone, Debug)]
pub enum IcmpFilter {
    /// Accept packets from any source.
    Any,
    /// Accept only from this source IP.
    SrcIp([u8; 4]),
}

/// An ICMP raw socket receives every ICMP packet that matches its filter.
#[derive(Debug)]
pub struct IcmpRawSocket {
    pub filter: IcmpFilter,
    pub rx_queue: IrqSafeSpinLock<VecDeque<IcmpDatagram>>,
}

impl IcmpRawSocket {
    fn new(filter: IcmpFilter) -> Self {
        Self {
            filter,
            rx_queue: IrqSafeSpinLock::new(VecDeque::new()),
        }
    }
}

// ── Global socket tables ───────────────────────────────────────────

static ECHO_SOCKETS: IrqSafeSpinLock<Vec<Arc<IcmpEchoSocket>>> =
    IrqSafeSpinLock::new(Vec::new());

static RAW_SOCKETS: IrqSafeSpinLock<Vec<Arc<IcmpRawSocket>>> =
    IrqSafeSpinLock::new(Vec::new());

// ── Public API ─────────────────────────────────────────────────────

/// Open a new ICMP echo socket. Returns the socket and its assigned
/// identifier (to correlate replies). Mirrors Linux `ping_init_sock`
/// (net/ipv4/ping.c:143).
pub fn icmp_echo_open() -> Arc<IcmpEchoSocket> {
    let id = NEXT_ECHO_ID.fetch_add(1, Ordering::Relaxed);
    let sock = Arc::new(IcmpEchoSocket::new(id));
    ECHO_SOCKETS.lock().push(sock.clone());
    sock
}

/// Close an echo socket.
pub fn icmp_echo_close(sock: &Arc<IcmpEchoSocket>) {
    ECHO_SOCKETS
        .lock()
        .retain(|s| !Arc::ptr_eq(s, sock));
}

/// Send an ICMP Echo Request to `target` and record it as pending.
/// Returns the assigned `seq` number. Call `icmp_echo_recv_reply` to
/// collect the matching Echo Reply.
///
/// Mirrors Linux `ping_sendmsg` (net/ipv4/ping.c:762).
pub fn icmp_echo_send(
    sock: &Arc<IcmpEchoSocket>,
    target: [u8; 4],
    seq: u16,
    payload: &[u8],
) -> Result<(), IcmpError2> {
    // Wave-47: route by destination, not boot-time primary.
    let iface = iface::for_dst(target).ok_or(IcmpError2::NoInterface)?;
    let dst_mac = if target == [255, 255, 255, 255] {
        [0xFF; 6]
    } else {
        arp_resolve(target, 1000).map_err(|_| IcmpError2::NetworkUnreachable)?
    };

    // Build: Eth + IPv4 + ICMP echo request.
    let icmp_len = 8 + payload.len(); // 8-byte ICMP echo header
    let ip_total = IPV4_HDR_LEN + icmp_len;
    let frame_len = ETH_HDR_LEN + ip_total;
    let mut frame = alloc::vec![0u8; frame_len];

    write_eth_header(&mut frame, dst_mac, iface.mac, ETHERTYPE_IPV4);
    write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total as u16,
        IP_PROTO_ICMP,
        iface.ipv4,
        target,
    );
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);

    let icmp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    frame[icmp_off] = ICMP_ECHO_REQUEST;
    frame[icmp_off + 1] = 0; // code
    frame[icmp_off + 2] = 0; // checksum placeholder
    frame[icmp_off + 3] = 0;
    frame[icmp_off + 4..icmp_off + 6].copy_from_slice(&sock.identifier.to_be_bytes());
    frame[icmp_off + 6..icmp_off + 8].copy_from_slice(&seq.to_be_bytes());
    if !payload.is_empty() {
        frame[icmp_off + 8..icmp_off + 8 + payload.len()].copy_from_slice(payload);
    }
    let cs = ip_checksum(&frame[icmp_off..icmp_off + icmp_len]);
    frame[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());

    let sent_ns = narf_scheduler::narf_time::monotonic_ns();

    (iface.send)(&frame).map_err(|_| IcmpError2::NoInterface)?;

    // Record the pending echo.
    sock.pending.lock().push_back(PendingEcho {
        identifier: sock.identifier,
        seq,
        reply: None,
        sent_ns,
        recv_ns: 0,
    });

    Ok(())
}

/// Poll for a completed Echo Reply for the given `seq`. Returns
/// `Some((payload, rtt_ns))` if the reply has arrived, `None` otherwise.
pub fn icmp_echo_poll_reply(
    sock: &Arc<IcmpEchoSocket>,
    seq: u16,
) -> Option<(Vec<u8>, u64)> {
    let mut q = sock.pending.lock();
    for entry in q.iter_mut() {
        if entry.seq == seq {
            if let Some(payload) = entry.reply.take() {
                let rtt = entry.recv_ns.saturating_sub(entry.sent_ns);
                return Some((payload, rtt));
            }
        }
    }
    None
}

/// Remove all completed and timed-out pending echoes.
pub fn icmp_echo_drain(sock: &Arc<IcmpEchoSocket>) {
    sock.pending.lock().retain(|e| e.reply.is_none());
}

/// Open a raw ICMP socket. Receives all ICMP frames matching `filter`.
/// Mirrors Linux `raw_init_sk` (net/ipv4/raw.c) approach.
pub fn icmp_raw_open(filter: IcmpFilter) -> Arc<IcmpRawSocket> {
    let sock = Arc::new(IcmpRawSocket::new(filter));
    RAW_SOCKETS.lock().push(sock.clone());
    sock
}

/// Close a raw ICMP socket.
pub fn icmp_raw_close(sock: &Arc<IcmpRawSocket>) {
    RAW_SOCKETS
        .lock()
        .retain(|s| !Arc::ptr_eq(s, sock));
}

/// Receive from a raw ICMP socket. Returns the next queued datagram.
pub fn icmp_raw_recv(sock: &Arc<IcmpRawSocket>) -> Option<IcmpDatagram> {
    sock.rx_queue.lock().pop_front()
}

/// ICMP socket error type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IcmpError2 {
    NoInterface,
    NetworkUnreachable,
    BufferTooSmall,
}

// ── RX dispatch ────────────────────────────────────────────────────
//
// Called from `tcp_stack::handle_ipv4` when protocol == IP_PROTO_ICMP.

/// Dispatch a received ICMP packet. `icmp_body` is the raw ICMP data
/// (type + code + checksum + rest-of-header + payload), with no IP hdr.
///
/// Mirrors Linux `icmp_rcv` (net/ipv4/icmp.c:1067).
pub fn on_icmp_rx(src_ip: [u8; 4], dst_ip: [u8; 4], icmp_body: &[u8]) {
    if icmp_body.len() < 4 {
        return;
    }
    let icmp_type = icmp_body[0];
    let icmp_code = icmp_body[1];

    // Verify checksum.
    if ip_checksum(icmp_body) != 0 {
        return;
    }

    match icmp_type {
        ICMP_ECHO_REQUEST => {
            // Answer ping requests addressed to us.
            handle_echo_request(src_ip, dst_ip, icmp_body);
        }
        ICMP_ECHO_REPLY => {
            // Deliver to waiting echo sockets.
            handle_echo_reply(src_ip, icmp_body);
        }
        ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED => {
            // Route the error back to the originating socket.
            deliver_error(src_ip, icmp_type, icmp_code, icmp_body);
        }
        _ => {}
    }

    // Feed all raw ICMP sockets.
    deliver_to_raw(src_ip, icmp_type, icmp_code, icmp_body);
}

fn handle_echo_request(src_ip: [u8; 4], _dst_ip: [u8; 4], icmp_body: &[u8]) {
    if icmp_body.len() < 8 {
        return;
    }
    let identifier = u16::from_be_bytes([icmp_body[4], icmp_body[5]]);
    let seq = u16::from_be_bytes([icmp_body[6], icmp_body[7]]);
    let payload = &icmp_body[8..];

    // Wave-47: reply via the iface that owns the route to the requester.
    let iface = match iface::for_dst(src_ip) {
        Some(i) => i,
        None => return,
    };
    let dst_mac = match arp_resolve(src_ip, 1000) {
        Ok(m) => m,
        Err(_) => return,
    };

    let icmp_len = 8 + payload.len();
    let ip_total = IPV4_HDR_LEN + icmp_len;
    let frame_len = ETH_HDR_LEN + ip_total;
    let mut frame = alloc::vec![0u8; frame_len];

    write_eth_header(&mut frame, dst_mac, iface.mac, ETHERTYPE_IPV4);
    write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total as u16,
        IP_PROTO_ICMP,
        iface.ipv4,
        src_ip,
    );
    set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);

    let icmp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    frame[icmp_off] = ICMP_ECHO_REPLY;
    frame[icmp_off + 1] = 0;
    frame[icmp_off + 2] = 0;
    frame[icmp_off + 3] = 0;
    frame[icmp_off + 4..icmp_off + 6].copy_from_slice(&identifier.to_be_bytes());
    frame[icmp_off + 6..icmp_off + 8].copy_from_slice(&seq.to_be_bytes());
    if !payload.is_empty() {
        frame[icmp_off + 8..icmp_off + 8 + payload.len()].copy_from_slice(payload);
    }
    let cs = ip_checksum(&frame[icmp_off..icmp_off + icmp_len]);
    frame[icmp_off + 2..icmp_off + 4].copy_from_slice(&cs.to_be_bytes());

    let _ = (iface.send)(&frame);
}

fn handle_echo_reply(_src_ip: [u8; 4], icmp_body: &[u8]) {
    if icmp_body.len() < 8 {
        return;
    }
    let identifier = u16::from_be_bytes([icmp_body[4], icmp_body[5]]);
    let seq = u16::from_be_bytes([icmp_body[6], icmp_body[7]]);
    let payload = icmp_body[8..].to_vec();
    let recv_ns = narf_scheduler::narf_time::monotonic_ns();

    let sockets = ECHO_SOCKETS.lock().clone();
    for sock in sockets {
        if sock.identifier == identifier {
            let mut q = sock.pending.lock();
            for entry in q.iter_mut() {
                if entry.seq == seq && entry.reply.is_none() {
                    entry.reply = Some(payload.clone());
                    entry.recv_ns = recv_ns;
                    break;
                }
            }
        }
    }
}

/// Route an ICMP error message back to the socket that originated the
/// triggering packet.  The error message embeds the original IP header
/// + 8 bytes of the triggering datagram, which is enough to recover
/// the original `(proto, src_port, dst_ip, dst_port)`.
///
/// Mirrors Linux `icmp_err` → `udp_err` (net/ipv4/udp.c:633) and
/// `tcp_v4_err` (net/ipv4/tcp_ipv4.c:483).
pub fn deliver_error(
    from_ip: [u8; 4],
    icmp_type: u8,
    icmp_code: u8,
    icmp_body: &[u8],
) {
    // ICMP error body: [type code csum(2) rest(4) origIP+8bytes…]
    // The original IP header starts at offset 8.
    if icmp_body.len() < 8 + IPV4_HDR_LEN + 8 {
        return;
    }
    let orig_ip_body = &icmp_body[8..];
    let (orig_ip, orig_l4) = match parse_ipv4(orig_ip_body) {
        Some(p) => p,
        None => return,
    };
    if orig_l4.len() < 8 {
        return;
    }
    let orig_src_port = u16::from_be_bytes([orig_l4[0], orig_l4[1]]);

    let err = SockError { icmp_type, icmp_code, from_ip };

    match orig_ip.protocol {
        IP_PROTO_UDP => {
            // Deliver to the UDP socket that sent the triggering datagram.
            deliver_icmp_error(orig_ip.src_ip, orig_src_port, err);
        }
        IP_PROTO_TCP => {
            // Signal the TCP connection.
            crate::tcp_stack::signal_icmp_error(
                orig_ip.src_ip,
                orig_src_port,
                orig_ip.dst_ip,
                u16::from_be_bytes([orig_l4[2], orig_l4[3]]),
            );
        }
        _ => {}
    }
}

fn deliver_to_raw(src_ip: [u8; 4], icmp_type: u8, icmp_code: u8, icmp_body: &[u8]) {
    let dg = IcmpDatagram {
        src: src_ip,
        icmp_type,
        icmp_code,
        payload: icmp_body[4..].to_vec(), // skip type/code/checksum/rest
    };
    let sockets = RAW_SOCKETS.lock().clone();
    for sock in sockets {
        let matches = match sock.filter {
            IcmpFilter::Any => true,
            IcmpFilter::SrcIp(ip) => ip == src_ip,
        };
        if matches {
            sock.rx_queue.lock().push_back(dg.clone());
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_icmp_echo_send_recv_reply() -> TestResult {
    // Open an echo socket, inject a synthetic Echo Reply, and check
    // that `icmp_echo_poll_reply` returns it.
    let sock = icmp_echo_open();
    let id = sock.identifier;
    let seq = 1u16;

    // Pre-load a pending echo (normally done by icmp_echo_send but
    // we skip ARP/iface here and inject the reply directly).
    sock.pending.lock().push_back(crate::icmp_sock::PendingEcho {
        identifier: id,
        seq,
        reply: None,
        sent_ns: 1_000_000,
        recv_ns: 0,
    });

    // Simulate receiving a reply: build a minimal ICMP Echo Reply body.
    let mut icmp_body = [0u8; 8 + 4];
    icmp_body[0] = ICMP_ECHO_REPLY;
    icmp_body[1] = 0;
    icmp_body[4..6].copy_from_slice(&id.to_be_bytes());
    icmp_body[6..8].copy_from_slice(&seq.to_be_bytes());
    icmp_body[8..12].copy_from_slice(b"pong");
    // Compute checksum.
    icmp_body[2] = 0;
    icmp_body[3] = 0;
    let cs = ip_checksum(&icmp_body);
    icmp_body[2] = (cs >> 8) as u8;
    icmp_body[3] = (cs & 0xFF) as u8;

    handle_echo_reply([10, 0, 0, 1], &icmp_body);

    let result = icmp_echo_poll_reply(&sock, seq);
    icmp_echo_close(&sock);

    match result {
        Some((payload, _rtt)) => {
            if &payload == b"pong" {
                TestResult::Pass
            } else {
                TestResult::Fail("echo reply payload mismatch")
            }
        }
        None => TestResult::Fail("echo reply not delivered to socket"),
    }
}
kernel_test_in!("net/icmp", smoke_icmp_echo_send_recv_reply);

fn smoke_icmp_raw_receives_any() -> TestResult {
    let sock = icmp_raw_open(IcmpFilter::Any);

    // Build a minimal ICMP body (e.g. Echo Request type=8).
    let mut icmp_body = [0u8; 8];
    icmp_body[0] = ICMP_ECHO_REQUEST;
    icmp_body[1] = 0;
    icmp_body[4..6].copy_from_slice(&42u16.to_be_bytes()); // identifier
    icmp_body[6..8].copy_from_slice(&1u16.to_be_bytes());  // seq
    let cs = ip_checksum(&icmp_body);
    icmp_body[2] = (cs >> 8) as u8;
    icmp_body[3] = (cs & 0xFF) as u8;

    deliver_to_raw([10, 0, 0, 5], ICMP_ECHO_REQUEST, 0, &icmp_body);

    let dg = icmp_raw_recv(&sock);
    icmp_raw_close(&sock);

    match dg {
        Some(d) => {
            if d.src != [10, 0, 0, 5] || d.icmp_type != ICMP_ECHO_REQUEST {
                return TestResult::Fail("raw ICMP datagram fields wrong");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("raw socket received nothing"),
    }
}
kernel_test_in!("net/icmp", smoke_icmp_raw_receives_any);

fn smoke_icmp_dest_unreach_delivered_to_udp_socket() -> TestResult {
    use crate::udp_sock::{udp_bind, udp_close, udp_err_recv, SocketAddrV4, UdpOptions};

    let port = 59020u16;
    let local_ip = [10, 0, 0, 1];
    let sock = match udp_bind(SocketAddrV4::new(local_ip, port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };

    // Build an ICMP Dest Unreach body: 8 bytes ICMP hdr + embedded IP+UDP.
    // The embedded IP says: src=local_ip:port → dst=10.0.0.2:9999.
    let orig_total_len = (IPV4_HDR_LEN + 8) as u16;
    let mut orig_ip = [0u8; IPV4_HDR_LEN + 8];
    orig_ip[0] = (4 << 4) | 5;       // ver+IHL
    orig_ip[2..4].copy_from_slice(&orig_total_len.to_be_bytes()); // total_len
    orig_ip[9] = IP_PROTO_UDP;
    orig_ip[12..16].copy_from_slice(&local_ip);
    orig_ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    orig_ip[IPV4_HDR_LEN..IPV4_HDR_LEN + 2].copy_from_slice(&port.to_be_bytes());   // src port
    orig_ip[IPV4_HDR_LEN + 2..IPV4_HDR_LEN + 4].copy_from_slice(&9999u16.to_be_bytes()); // dst port
    // Patch IP checksum.
    orig_ip[10] = 0;
    orig_ip[11] = 0;
    let ip_cs = ip_checksum(&orig_ip[..IPV4_HDR_LEN]);
    orig_ip[10] = (ip_cs >> 8) as u8;
    orig_ip[11] = (ip_cs & 0xFF) as u8;

    let mut icmp_body = alloc::vec![0u8; 8 + orig_ip.len()];
    icmp_body[0] = ICMP_DEST_UNREACHABLE;
    icmp_body[1] = 3; // port unreachable
    icmp_body[8..].copy_from_slice(&orig_ip);
    icmp_body[2] = 0;
    icmp_body[3] = 0;
    let cs = ip_checksum(&icmp_body);
    icmp_body[2] = (cs >> 8) as u8;
    icmp_body[3] = (cs & 0xFF) as u8;

    deliver_error([10, 0, 0, 2], ICMP_DEST_UNREACHABLE, 3, &icmp_body);

    let err = udp_err_recv(&sock);
    udp_close(&sock);

    match err {
        Some(e) => {
            if e.icmp_type != ICMP_DEST_UNREACHABLE {
                return TestResult::Fail("wrong icmp_type in error");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("ICMP Dest Unreach not delivered to UDP socket"),
    }
}
kernel_test_in!("net/icmp", smoke_icmp_dest_unreach_delivered_to_udp_socket);

fn smoke_icmp_time_exceeded_delivered_to_udp_socket() -> TestResult {
    use crate::udp_sock::{udp_bind, udp_close, udp_err_recv, SocketAddrV4, UdpOptions};

    let port = 59021u16;
    let local_ip = [10, 0, 0, 1];
    let sock = match udp_bind(SocketAddrV4::new(local_ip, port), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bind failed"),
    };

    let orig_total_len2 = (IPV4_HDR_LEN + 8) as u16;
    let mut orig_ip = [0u8; IPV4_HDR_LEN + 8];
    orig_ip[0] = (4 << 4) | 5;
    orig_ip[2..4].copy_from_slice(&orig_total_len2.to_be_bytes()); // total_len
    orig_ip[9] = IP_PROTO_UDP;
    orig_ip[12..16].copy_from_slice(&local_ip);
    orig_ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    orig_ip[IPV4_HDR_LEN..IPV4_HDR_LEN + 2].copy_from_slice(&port.to_be_bytes());
    let ip_cs = ip_checksum(&orig_ip[..IPV4_HDR_LEN]);
    orig_ip[10] = (ip_cs >> 8) as u8;
    orig_ip[11] = (ip_cs & 0xFF) as u8;

    let mut icmp_body = alloc::vec![0u8; 8 + orig_ip.len()];
    icmp_body[0] = ICMP_TIME_EXCEEDED;
    icmp_body[1] = 0; // TTL exceeded in transit
    icmp_body[8..].copy_from_slice(&orig_ip);
    let cs = ip_checksum(&icmp_body);
    icmp_body[2] = (cs >> 8) as u8;
    icmp_body[3] = (cs & 0xFF) as u8;

    deliver_error([10, 0, 0, 2], ICMP_TIME_EXCEEDED, 0, &icmp_body);

    let err = udp_err_recv(&sock);
    udp_close(&sock);

    match err {
        Some(e) => {
            if e.icmp_type != ICMP_TIME_EXCEEDED {
                return TestResult::Fail("wrong icmp_type in error");
            }
            TestResult::Pass
        }
        None => TestResult::Fail("ICMP Time Exceeded not delivered to UDP socket"),
    }
}
kernel_test_in!("net/icmp", smoke_icmp_time_exceeded_delivered_to_udp_socket);

/// ICMP raw filter by source IP: a socket filtered to one source IP
/// must reject datagrams from a different source.
///
/// Linux ref: `raw_v4_input` (net/ipv4/raw.c:225) applies the
/// `daddr`/`saddr` filter from the raw-socket `inet_sock` before
/// queuing a packet.
fn smoke_icmp_raw_filter_rejects_wrong_source() -> TestResult {
    let wanted_src = [10, 0, 0, 7];
    let other_src  = [10, 0, 0, 8];
    let sock = icmp_raw_open(IcmpFilter::SrcIp(wanted_src));

    // Build a valid Echo Request ICMP body.
    let build_icmp = |id: u16| {
        let mut icmp = [0u8; 8];
        icmp[0] = ICMP_ECHO_REQUEST;
        icmp[4..6].copy_from_slice(&id.to_be_bytes());
        let cs = ip_checksum(&icmp);
        icmp[2] = (cs >> 8) as u8;
        icmp[3] = (cs & 0xFF) as u8;
        icmp
    };

    // Deliver from the wrong source — must be dropped.
    let wrong = build_icmp(99);
    deliver_to_raw(other_src, ICMP_ECHO_REQUEST, 0, &wrong);

    // Deliver from the wanted source — must be accepted.
    let right = build_icmp(42);
    deliver_to_raw(wanted_src, ICMP_ECHO_REQUEST, 0, &right);

    let pkt1 = icmp_raw_recv(&sock);
    let pkt2 = icmp_raw_recv(&sock);
    icmp_raw_close(&sock);

    match pkt1 {
        Some(d) => {
            if d.src != wanted_src {
                return TestResult::Fail("raw filter let wrong-src packet through");
            }
        }
        None => return TestResult::Fail("wanted-src packet not delivered"),
    }
    if pkt2.is_some() {
        return TestResult::Fail("extra packet in queue — filter should have dropped it");
    }
    TestResult::Pass
}
kernel_test_in!("net/icmp", smoke_icmp_raw_filter_rejects_wrong_source);
