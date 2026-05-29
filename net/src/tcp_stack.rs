//! Minimal kernel-side TCP stack for AF_INET SOCK_STREAM
//! non-loopback connections. Stage-1 scope:
//!
//!   - ARP cache: IP → MAC + a single-shot resolver (sends an
//!     ARP request, blocks until a reply lands, with a 1s timeout)
//!   - Per-connection TCB: SYN_SENT / ESTABLISHED / CLOSED only.
//!     No FIN_WAIT_*, no SACK, no retransmit, fixed 16 KiB rx
//!     window, no congestion control. Adequate for echo-style
//!     smoke; real workloads under packet loss will hang.
//!   - RX dispatch: parse Ethernet → ARP / IPv4 → TCP / ICMP-echo.
//!   - Outbound: build Eth + IPv4 + TCP frames, push through
//!     `iface::send`.
//!
//! Activation: `tcp_stack::init` installs the RX handler with the
//! iface registry. A separate kernel-side task pumps the NIC RX
//! ring and calls `iface::on_rx_frame` for each frame.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time;

use crate::iface;
use crate::pkt::{
    self, parse_arp, parse_eth_header, parse_ipv4, write_eth_header, write_ipv4_header,
    ARP_OP_REPLY, ARP_OP_REQUEST, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETH_HDR_LEN,
    IPV4_HDR_LEN, IP_PROTO_TCP, IP_PROTO_UDP,
};
use crate::pkt_tcp::{TcpHeader, ipv4_pseudo_checksum};

const TCP_MIN_HDR: usize = 20;
const TCP_MTU: usize = 1500;

// ── ARP cache ───────────────────────────────────────────────────

static ARP_CACHE: IrqSafeSpinLock<Option<BTreeMap<[u8; 4], [u8; 6]>>> =
    IrqSafeSpinLock::new(None);

fn arp_lookup(ip: [u8; 4]) -> Option<[u8; 6]> {
    let g = ARP_CACHE.lock();
    g.as_ref().and_then(|m| m.get(&ip).copied())
}

fn arp_insert(ip: [u8; 4], mac: [u8; 6]) {
    let mut g = ARP_CACHE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(ip, mac);
}

/// Public shim so `arp::arp_insert_from_rx` can populate the legacy
/// BTreeMap cache alongside the new LRU cache without a circular dep.
#[doc(hidden)]
pub fn __arp_insert_legacy(ip: [u8; 4], mac: [u8; 6]) {
    arp_insert(ip, mac);
}

/// Send an ARP request for `target_ip`. Returns Err if no iface
/// is registered.
pub fn send_arp_request(target_ip: [u8; 4]) -> Result<(), ()> {
    let iface = iface::primary().ok_or(())?;
    let mut frame = [0u8; 60];
    let n = pkt::build_arp_request(&mut frame, iface.mac, iface.ipv4, target_ip)
        .ok_or(())?;
    iface::send(&frame[..n])
}

/// Resolve an IPv4 address to a MAC, sending an ARP request if
/// not cached. Waits via `responsive_spin_until`, which ticks the
/// registered sleep_pumps (including the e1000 RX-pump) so the
/// reply gets drained off the NIC and into the cache. Returns
/// the MAC on success, Err on `timeout_ms` deadline.
pub fn arp_resolve(ip: [u8; 4], timeout_ms: u64) -> Result<[u8; 6], ()> {
    if let Some(m) = arp_lookup(ip) {
        return Ok(m);
    }
    let _ = send_arp_request(ip);
    let deadline = narf_time::Deadline::after_ns(timeout_ms.saturating_mul(1_000_000));
    let _ = narf_scheduler::responsive_spin_until(
        || {
            // Drain any pending RX so an inbound ARP reply lands
            // in the cache, then re-check.
            while iface::drain_pump() {}
            arp_lookup(ip).is_some()
        },
        deadline,
    );
    arp_lookup(ip).ok_or(())
}

// ── TCB (per-connection state) ──────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    Established,
    Closing,
}

#[derive(Debug)]
pub struct Tcb {
    pub local_addr: [u8; 4],
    pub local_port: u16,
    pub remote_addr: [u8; 4],
    pub remote_port: u16,
    pub remote_mac: [u8; 6],
    pub state: TcpState,
    /// Next sequence number to send.
    pub snd_nxt: u32,
    /// Last unacknowledged seq we sent.
    pub snd_una: u32,
    /// Next sequence number we expect to receive.
    pub rcv_nxt: u32,
    /// Inbound bytes waiting for the user to read.
    pub rx: VecDeque<u8>,
}

static TCB_TABLE: IrqSafeSpinLock<Option<BTreeMap<u32, Arc<IrqSafeSpinLock<Tcb>>>>> =
    IrqSafeSpinLock::new(None);
static NEXT_TCB_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_LOCAL_PORT: AtomicU32 = AtomicU32::new(49152); // ephemeral range

/// Allocate a TCB and start a connect. Returns the TCB id.
pub fn connect(remote_addr: [u8; 4], remote_port: u16) -> Result<u32, ()> {
    let iface = iface::primary().ok_or(())?;
    let mac = arp_resolve(iface.gateway, 1000)?;
    // For destinations on the local subnet we'd use their own MAC;
    // Stage-1 hard-codes "everything goes through the gateway"
    // since QEMU's user-net puts every dest behind the same NAT.
    let _ = remote_addr; // (used for IP fields below)
    let local_port = NEXT_LOCAL_PORT.fetch_add(1, Ordering::Relaxed) as u16;
    let id = NEXT_TCB_ID.fetch_add(1, Ordering::Relaxed);
    let isn = (narf_scheduler::narf_time::monotonic_ns() as u32).wrapping_mul(7);
    let tcb = Tcb {
        local_addr: iface.ipv4,
        local_port,
        remote_addr,
        remote_port,
        remote_mac: mac,
        state: TcpState::SynSent,
        snd_nxt: isn.wrapping_add(1),
        snd_una: isn,
        rcv_nxt: 0,
        rx: VecDeque::new(),
    };
    let arc = Arc::new(IrqSafeSpinLock::new(tcb));
    {
        let mut g = TCB_TABLE.lock();
        let m = g.get_or_insert_with(BTreeMap::new);
        m.insert(id, arc.clone());
    }
    // Send the SYN, then spin waiting for the state machine to
    // advance. responsive_spin_until ticks sleep_pumps each
    // iteration; the e1000 RX-pump is registered as one, so a
    // SYN-ACK landing on the wire gets drained, dispatched
    // through handle_tcp, and flips state to Established.
    send_tcp_segment(&arc, isn, 0, TcpFlags::SYN, &[]);
    let deadline = narf_time::Deadline::after_ns(3_000_000_000);
    let _ = narf_scheduler::responsive_spin_until(
        || {
            // Drain RX so the SYN-ACK reaches handle_tcp.
            while iface::drain_pump() {}
            arc.lock().state != TcpState::SynSent
        },
        deadline,
    );
    let st = arc.lock().state;
    match st {
        TcpState::Established => Ok(id),
        _ => Err(()),
    }
}

/// Send `buf` as a single TCP segment on the connection. Returns
/// the byte count.
pub fn send(id: u32, buf: &[u8]) -> Result<usize, ()> {
    let arc = {
        let g = TCB_TABLE.lock();
        g.as_ref().and_then(|m| m.get(&id).cloned()).ok_or(())?
    };
    let st = arc.lock().state;
    if st != TcpState::Established {
        return Err(());
    }
    let len = core::cmp::min(buf.len(), TCP_MTU - IPV4_HDR_LEN - TCP_MIN_HDR);
    let (seq, ack) = {
        let t = arc.lock();
        (t.snd_nxt, t.rcv_nxt)
    };
    send_tcp_segment(&arc, seq, ack, TcpFlags::ACK | TcpFlags::PSH, &buf[..len]);
    arc.lock().snd_nxt = seq.wrapping_add(len as u32);
    Ok(len)
}

/// Recv up to buf.len() bytes from the connection. Returns the
/// byte count (may be 0 if nothing is queued).
pub fn recv(id: u32, buf: &mut [u8]) -> Result<usize, ()> {
    let arc = {
        let g = TCB_TABLE.lock();
        g.as_ref().and_then(|m| m.get(&id).cloned()).ok_or(())?
    };
    let mut t = arc.lock();
    let n = core::cmp::min(buf.len(), t.rx.len());
    for i in 0..n {
        buf[i] = t.rx.pop_front().unwrap();
    }
    Ok(n)
}

/// Close the connection (Stage-1: just transitions to Closed +
/// sends a FIN; no FIN_WAIT_* tracking).
pub fn close(id: u32) -> Result<(), ()> {
    let arc = {
        let mut g = TCB_TABLE.lock();
        let m = g.as_mut().ok_or(())?;
        m.remove(&id).ok_or(())?
    };
    let (seq, ack) = {
        let t = arc.lock();
        (t.snd_nxt, t.rcv_nxt)
    };
    send_tcp_segment(&arc, seq, ack, TcpFlags::FIN | TcpFlags::ACK, &[]);
    arc.lock().state = TcpState::Closed;
    Ok(())
}

// ── TCP flag bits ───────────────────────────────────────────────

#[allow(non_snake_case)]
mod TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

fn send_tcp_segment(
    arc: &Arc<IrqSafeSpinLock<Tcb>>,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) {
    let iface = match iface::primary() {
        Some(i) => i,
        None => return,
    };
    let (src_mac, src_ip, dst_ip, dst_mac, src_port, dst_port) = {
        let t = arc.lock();
        (
            iface.mac,
            t.local_addr,
            t.remote_addr,
            t.remote_mac,
            t.local_port,
            t.remote_port,
        )
    };
    let total_len = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_MIN_HDR + payload.len();
    let mut frame = vec![0u8; total_len];
    let ip_total_len = (IPV4_HDR_LEN + TCP_MIN_HDR + payload.len()) as u16;
    // Eth header.
    if write_eth_header(&mut frame, dst_mac, src_mac, ETHERTYPE_IPV4).is_none() {
        return;
    }
    // IPv4 header — slice into the frame at known offsets.
    if write_ipv4_header(
        &mut frame[ETH_HDR_LEN..],
        ip_total_len,
        IP_PROTO_TCP,
        src_ip,
        dst_ip,
    )
    .is_none()
    {
        return;
    }
    pkt::set_ipv4_checksum(&mut frame[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN]);
    // Build TCP header + checksum.
    let tcp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let mut tcp_hdr = TcpHeader {
        src_port,
        dst_port,
        sequence: seq,
        acknowledgement: ack,
        header_len: TCP_MIN_HDR as u8,
        flags,
        window: 0xFFFF,
        checksum: 0,
        urgent_ptr: 0,
        options: alloc::vec::Vec::new(),
    };
    let hdr_bytes = tcp_hdr.encode();
    frame[tcp_off..tcp_off + TCP_MIN_HDR].copy_from_slice(&hdr_bytes);
    frame[tcp_off + TCP_MIN_HDR..tcp_off + TCP_MIN_HDR + payload.len()]
        .copy_from_slice(payload);
    // Compute TCP checksum over IPv4 pseudo + segment.
    let segment = &frame[tcp_off..tcp_off + TCP_MIN_HDR + payload.len()];
    let csum = ipv4_pseudo_checksum(src_ip, dst_ip, segment);
    tcp_hdr.checksum = csum;
    let final_hdr = tcp_hdr.encode();
    frame[tcp_off..tcp_off + TCP_MIN_HDR].copy_from_slice(&final_hdr);
    let _ = iface::send(&frame);
}

// ── RX dispatch ─────────────────────────────────────────────────

pub fn rx_handler(frame: &[u8]) {
    if frame.len() < ETH_HDR_LEN {
        return;
    }
    let (eth, body) = match parse_eth_header(frame) {
        Some(t) => t,
        None => return,
    };
    match eth.ethertype {
        ETHERTYPE_ARP => handle_arp(body),
        ETHERTYPE_IPV4 => handle_ipv4(body),
        ETHERTYPE_IPV6 => {
            // Dispatch via the IPv6 stack. Iface name is taken from
            // primary() — Stage-1 has at most one NIC, multi-NIC
            // dispatch lands when the driver layer surfaces the
            // ingress port.
            let iface_name = iface::primary()
                .map(|s| s.name)
                .unwrap_or_else(|| alloc::string::String::from("eth0"));
            let _ = crate::ipv6_stack::rx_frame(&iface_name, body);
        }
        _ => {}
    }
}

fn handle_arp(body: &[u8]) {
    let arp = match parse_arp(body) {
        Some(a) => a,
        None => return,
    };
    // Cache the sender's IP→MAC regardless of op (request or reply).
    arp_insert(arp.spa, arp.sha);
    // If it's a request targeting us, send a reply.
    if arp.op == ARP_OP_REQUEST {
        let iface = match iface::primary() {
            Some(i) => i,
            None => return,
        };
        if arp.tpa == iface.ipv4 {
            let mut frame = [0u8; 60];
            if let Some(n) = pkt::build_arp_reply(&mut frame, iface.mac, iface.ipv4, &arp) {
                let _ = iface::send(&frame[..n]);
            }
        }
    }
    let _ = ARP_OP_REPLY; // silence unused-import warning
}

fn handle_ipv4(body: &[u8]) {
    let (ip, payload) = match parse_ipv4(body) {
        Some(t) => t,
        None => return,
    };
    if ip.protocol == IP_PROTO_TCP {
        handle_tcp(ip.src_ip, ip.dst_ip, payload);
    } else if ip.protocol == IP_PROTO_UDP {
        handle_udp(ip.src_ip, ip.dst_ip, payload);
    }
    // ICMP/echo etc. omitted in Stage-1.
}

/// Minimal UDP dispatch. Splits off the 8-byte UDP header, routes by
/// destination port: the DHCP client listens on 68. New consumers
/// (mDNS, DNS-over-UDP, NTP) plug additional ports in here.
fn handle_udp(src_ip: [u8; 4], dst_ip: [u8; 4], datagram: &[u8]) {
    if datagram.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let dst_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let length = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    // `length` includes the 8-byte header.
    let end = length.min(datagram.len());
    if end < 8 {
        return;
    }
    let payload = &datagram[8..end];
    // DHCP client port. The dhcp module caches the reply for the
    // synchronous `acquire` busy-wait to observe.
    if dst_port == 68 {
        crate::dhcp::on_udp_in(src_ip, dst_ip, src_port, dst_port, payload);
    }
}

fn handle_tcp(src: [u8; 4], dst: [u8; 4], segment: &[u8]) {
    let (hdr, _data_off) = match TcpHeader::decode(segment) {
        Ok(t) => t,
        Err(_) => return,
    };
    // Find a TCB matching (local=dst:dst_port, remote=src:src_port).
    let arc = {
        let g = TCB_TABLE.lock();
        let m = match g.as_ref() {
            Some(m) => m,
            None => return,
        };
        m.values()
            .find(|t| {
                let g = t.lock();
                g.local_addr == dst
                    && g.local_port == hdr.dst_port
                    && g.remote_addr == src
                    && g.remote_port == hdr.src_port
            })
            .cloned()
    };
    let arc = match arc {
        Some(a) => a,
        None => return,
    };
    let payload_off = hdr.header_len as usize;
    let payload = &segment[payload_off..];
    let mut t = arc.lock();
    match t.state {
        TcpState::SynSent => {
            // Expect SYN+ACK.
            if hdr.flags & (TcpFlags::SYN | TcpFlags::ACK)
                == (TcpFlags::SYN | TcpFlags::ACK)
            {
                // Their ack acknowledges our SYN (consumed 1 seq).
                t.snd_una = hdr.acknowledgement;
                t.rcv_nxt = hdr.sequence.wrapping_add(1);
                t.state = TcpState::Established;
                let snd_nxt = t.snd_nxt;
                let rcv_nxt = t.rcv_nxt;
                drop(t);
                // Send the final ACK of the handshake.
                send_tcp_segment(&arc, snd_nxt, rcv_nxt, TcpFlags::ACK, &[]);
            }
        }
        TcpState::Established => {
            if hdr.flags & TcpFlags::RST != 0 {
                t.state = TcpState::Closed;
                return;
            }
            if !payload.is_empty() {
                for &b in payload {
                    t.rx.push_back(b);
                }
                t.rcv_nxt = t.rcv_nxt.wrapping_add(payload.len() as u32);
                let snd_nxt = t.snd_nxt;
                let rcv_nxt = t.rcv_nxt;
                drop(t);
                // Bare ACK acknowledging the data.
                send_tcp_segment(&arc, snd_nxt, rcv_nxt, TcpFlags::ACK, &[]);
            }
        }
        _ => {}
    }
}

// ── Init ────────────────────────────────────────────────────────

/// Wire the RX dispatch handler into the iface registry. Called
/// once at boot.
pub fn init() {
    iface::install_rx_handler(rx_handler);
}
