//! Kernel-side TCP stack — production grade.
//!
//! This file is the public entrypoint. The substantive TCP work
//! lives in `tcp/` submodules:
//!
//! - `tcp::state_machine`  — RFC 9293 §3.3.2 11-state FSM.
//! - `tcp::retransmit`     — RFC 6298 RTO + RTT smoothing + Karn.
//! - `tcp::congestion`     — CUBIC (RFC 9438) + NewReno (RFC 5681).
//! - `tcp::sack`           — RFC 2018 selective ACK.
//! - `tcp::options`        — MSS, Window Scale (RFC 7323),
//!                           Timestamps (RFC 7323), SACK-Permitted.
//! - `tcp::socket_buf`     — send + reassembly buffers.
//! - `tcp::core`           — TCB, segment-arrival dispatch, public
//!                           API surface.
//!
//! ## What this file owns
//!
//! - The legacy ARP cache + `arp_resolve` helper (kept so the
//!   existing `arp_cache`, `dhcp`, `udp_sock`, `icmp_sock`, and
//!   `ipv6_stack` modules keep compiling without churn).
//! - The L2 → L3 RX dispatch that routes incoming frames to
//!   `tcp::core::handle_segment` (for TCP), `dhcp` (for UDP/68),
//!   and the IPv6 stack.
//! - The sleep-pump that drives the retransmit / persist /
//!   keepalive / delayed-ACK / TIME-WAIT timers between RX events.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time;

use crate::arp_cache;
use crate::iface;
use crate::pkt::{
    self, parse_arp, parse_eth_header, parse_ipv4, ARP_OP_REPLY, ARP_OP_REQUEST, ETHERTYPE_ARP,
    ETHERTYPE_IPV4, ETH_HDR_LEN, IP_PROTO_TCP, IP_PROTO_UDP,
};

pub use crate::tcp::core::{
    accept, close, connect, getsockopt_cong, getsockopt_int, listen, lookup_tcb, recv, remove_tcb,
    send, setsockopt_int, setsockopt_str, shutdown, tick_retransmit, Tcb, TCP_CONGESTION, TCP_CORK,
    TCP_KEEPALIVE, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_MAXSEG, TCP_NODELAY, TCP_QUICKACK,
    TCP_USER_TIMEOUT,
};
pub use crate::tcp::state_machine::{DropCause, Shutdown, TcpState};

// ── ARP legacy cache (kept for compat with non-TCP callers) ─────

static ARP_CACHE: IrqSafeSpinLock<Option<BTreeMap<[u8; 4], [u8; 6]>>> =
    IrqSafeSpinLock::new(None);

fn arp_lookup_local(ip: [u8; 4]) -> Option<[u8; 6]> {
    let g = ARP_CACHE.lock();
    g.as_ref().and_then(|m| m.get(&ip).copied())
}

fn arp_insert_local(ip: [u8; 4], mac: [u8; 6]) {
    let mut g = ARP_CACHE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(ip, mac);
}

/// Public shim so `arp::arp_insert_from_rx` can populate the
/// legacy BTreeMap cache without a circular dep.
#[doc(hidden)]
pub fn __arp_insert_legacy(ip: [u8; 4], mac: [u8; 6]) {
    arp_insert_local(ip, mac);
}

/// Send an ARP request for `target_ip` via the primary iface.
pub fn send_arp_request(target_ip: [u8; 4]) -> Result<(), ()> {
    let iface = iface::primary().ok_or(())?;
    let mut frame = [0u8; 60];
    let n = pkt::build_arp_request(&mut frame, iface.mac, iface.ipv4, target_ip)
        .ok_or(())?;
    iface::send(&frame[..n])
}

/// Resolve `ip` to a MAC: cache → ARP-request → busy-wait for reply.
/// Returns the MAC on success, `Err(())` on timeout.
pub fn arp_resolve(ip: [u8; 4], timeout_ms: u64) -> Result<[u8; 6], ()> {
    if let Some(m) = arp_lookup_local(ip) {
        return Ok(m);
    }
    let _ = send_arp_request(ip);
    let deadline = narf_time::Deadline::after_ns(timeout_ms.saturating_mul(1_000_000));
    let _ = narf_scheduler::responsive_spin_until(
        || {
            while iface::drain_pump() {}
            arp_lookup_local(ip).is_some()
        },
        deadline,
    );
    arp_lookup_local(ip).ok_or(())
}

// ── RX dispatch ─────────────────────────────────────────────────

/// Top-level RX path called by the iface registry. Parses the
/// L2 header and routes by ethertype.
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
        _ => {}
    }
}

fn handle_arp(body: &[u8]) {
    handle_arp_on(body, None);
}

/// ARP handler with optional ingress-iface context. When `iface_name`
/// is Some the sender MAC is also recorded in the per-iface arp_cache
/// state-machine — the multi-NIC-correct path so a reply arriving on
/// iface1 doesn't populate iface2's cache.
/// Ref: Linux `arp_rcv()` in `net/ipv4/arp.c`.
pub fn handle_arp_on(body: &[u8], iface_name: Option<&str>) {
    let arp = match parse_arp(body) {
        Some(a) => a,
        None => return,
    };
    arp_insert_local(arp.spa, arp.sha);
    // Per-iface cache: record on the ingress interface if known.
    if let Some(name) = iface_name {
        arp_cache::insert(name, arp.spa, arp.sha);
    }
    if arp.op == ARP_OP_REQUEST {
        let snap = iface_name
            .and_then(|n| iface::lookup(n))
            .or_else(iface::primary);
        let iface = match snap {
            Some(i) => i,
            None => return,
        };
        if arp.tpa == iface.ipv4 {
            let mut frame = [0u8; 60];
            if let Some(n) = pkt::build_arp_reply(&mut frame, iface.mac, iface.ipv4, &arp) {
                let _ = (iface.send)(&frame[..n]);
            }
        }
    }
    let _ = ARP_OP_REPLY;
}

fn handle_ipv4(body: &[u8]) {
    let (ip, payload) = match parse_ipv4(body) {
        Some(t) => t,
        None => return,
    };
    match ip.protocol {
        IP_PROTO_TCP => crate::tcp::core::handle_segment(ip.src_ip, ip.dst_ip, payload),
        IP_PROTO_UDP => handle_udp(ip.src_ip, ip.dst_ip, payload),
        _ => {}
    }
}

fn handle_udp(src_ip: [u8; 4], dst_ip: [u8; 4], datagram: &[u8]) {
    if datagram.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let dst_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let length = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    let end = length.min(datagram.len());
    if end < 8 {
        return;
    }
    let payload = &datagram[8..end];
    if dst_port == 68 {
        crate::dhcp::on_udp_in(src_ip, dst_ip, src_port, dst_port, payload);
    }
}

// ── ICMP error signalling (called by icmp_sock) ─────────────────

/// Notify the TCP connection identified by
/// `(local_addr, local_port, remote_addr, remote_port)` that an
/// ICMP error was received. Per RFC 1122 §4.2.3.9 this is a soft
/// signal — we route it as `DropCause::PeerReset` to mirror Linux's
/// `tcp_v4_err` (`net/ipv4/tcp_ipv4.c:tcp_v4_err`) behaviour on
/// hard errors.
pub fn signal_icmp_error(
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
) {
    crate::tcp::core::signal_icmp_error(remote_addr, remote_port, local_addr, local_port);
}

// ── Periodic timer tick ─────────────────────────────────────────
//
// Wired into a `sleep_pump` at boot so retransmit / delayed-ACK /
// persist / keepalive / TIME-WAIT timers all advance even when
// no traffic is arriving.

static TIMER_PUMP_INSTALLED: AtomicUsize = AtomicUsize::new(0);

fn timer_tick_pump() {
    crate::tcp::core::tick_all();
}

// ── Init ────────────────────────────────────────────────────────

/// Wire the RX handler + timer pump into the kernel scaffolding.
/// Called once at boot.
pub fn init() {
    iface::install_rx_handler(rx_handler);
    if TIMER_PUMP_INSTALLED
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        narf_scheduler::sleep_pumps::register(timer_tick_pump);
    }
}

/// MTU we plan on per outbound frame. Kept at the legacy surface;
/// the tcp::core path computes its own per-MSS budget.
pub const TCP_MTU: usize = 1500;
