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
//!   Timestamps (RFC 7323), SACK-Permitted.
//! - `tcp::socket_buf`     — send + reassembly buffers.
//! - `tcp::core`           — TCB, segment-arrival dispatch, public
//!   API surface.
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
    ETHERTYPE_IPV4, ETH_HDR_LEN, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
};

pub use crate::tcp::core::{
    accept, close, connect, connect_errno_in, connect_in, getsockopt_cong, getsockopt_int, listen,
    listen_has_pending, listen_in, lookup_tcb, readable, recv, recv_errno, release, remove_tcb,
    send, send_errno, setsockopt_int, setsockopt_str, shutdown, shutdown_errno, take_sock_error,
    tick_retransmit, Tcb, TCP_CONGESTION, TCP_CORK, TCP_KEEPALIVE, TCP_KEEPCNT, TCP_KEEPIDLE,
    TCP_KEEPINTVL, TCP_MAXSEG, TCP_NODELAY, TCP_QUICKACK, TCP_USER_TIMEOUT,
};
pub use crate::tcp::state_machine::{DropCause, Shutdown, TcpState};

// ── ARP legacy cache (kept for compat with non-TCP callers) ─────

type ArpCache = BTreeMap<(u64, [u8; 4]), [u8; 6]>;
static ARP_CACHE: IrqSafeSpinLock<Option<ArpCache>> = IrqSafeSpinLock::new(None);

fn arp_lookup_local(net_ns_id: u64, ip: [u8; 4]) -> Option<[u8; 6]> {
    let g = ARP_CACHE.lock();
    g.as_ref().and_then(|m| m.get(&(net_ns_id, ip)).copied())
}

fn arp_insert_local(net_ns_id: u64, ip: [u8; 4], mac: [u8; 6]) {
    let mut g = ARP_CACHE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert((net_ns_id, ip), mac);
}

pub(crate) fn remove_namespace(net_ns_id: u64) {
    if let Some(cache) = ARP_CACHE.lock().as_mut() {
        cache.retain(|(namespace, _), _| *namespace != net_ns_id);
    }
}

/// Public shim so `arp::arp_insert_from_rx` can populate the
/// legacy BTreeMap cache without a circular dep.
#[doc(hidden)]
pub fn __arp_insert_legacy(ip: [u8; 4], mac: [u8; 6]) {
    arp_insert_local(0, ip, mac);
}

/// Send an ARP request for `target_ip` via the iface that owns the
/// route to `target_ip`. Wave-47: prior code went out the boot-time
/// primary, which on multi-NIC / capture-iface setups missed the
/// subnet that actually contains the target.
pub fn send_arp_request(target_ip: [u8; 4]) -> Result<(), ()> {
    send_arp_request_in(0, target_ip)
}

pub fn send_arp_request_in(net_ns_id: u64, target_ip: [u8; 4]) -> Result<(), ()> {
    let iface = iface::for_dst_in(net_ns_id, target_ip).ok_or(())?;
    let mut frame = [0u8; 60];
    let n = pkt::build_arp_request(&mut frame, iface.mac, iface.ipv4, target_ip).ok_or(())?;
    (iface.send)(&frame[..n])
}

/// Resolve `ip` to a MAC: cache → ARP-request → busy-wait for reply.
/// Returns the MAC on success, `Err(())` on timeout.
/// Non-blocking neighbour lookup: the cached MAC for `ip`, or `None`.
/// For RX-path callers (e.g. a TCP reset) that must never spin on ARP.
pub(crate) fn arp_cached_in(net_ns_id: u64, ip: [u8; 4]) -> Option<[u8; 6]> {
    arp_lookup_local(net_ns_id, ip)
}

pub fn arp_resolve(ip: [u8; 4], timeout_ms: u64) -> Result<[u8; 6], ()> {
    arp_resolve_in(0, ip, timeout_ms)
}

pub fn arp_resolve_in(net_ns_id: u64, ip: [u8; 4], timeout_ms: u64) -> Result<[u8; 6], ()> {
    if let Some(m) = arp_lookup_local(net_ns_id, ip) {
        return Ok(m);
    }
    // The cache is keyed by interface, so resolution state is tracked
    // against the interface that actually owns the route.
    let iface_name = iface::for_dst_in(net_ns_id, ip).map(|i| i.name);

    // Negative cache. Linux drops packets to a NUD_FAILED neighbour without
    // re-probing; without this, every send to a host that is switched off
    // restarts a full probe cycle, turning one unreachable address into a
    // burst of broadcast per packet.
    if let Some(name) = iface_name.as_deref() {
        if crate::arp_cache::resolution_failed(name, ip) {
            return Err(());
        }
        crate::arp_cache::mark_incomplete(name, ip);
    }

    let _ = send_arp_request_in(net_ns_id, ip);
    let deadline = narf_time::Deadline::after_ns(timeout_ms.saturating_mul(1_000_000));
    let mut gave_up = false;
    let _ = narf_scheduler::responsive_spin_until(
        || {
            while iface::drain_pump() {}
            if arp_lookup_local(net_ns_id, ip).is_some() {
                return true;
            }
            // Retransmit on the 1 s timer rather than firing once and
            // hoping. A single request lost to a dropped frame used to sink
            // the whole resolution until the caller's timeout expired.
            if let Some(name) = iface_name.as_deref() {
                match crate::arp_cache::poll_resolution(name, ip) {
                    crate::arp_cache::ResolutionStep::Retransmit => {
                        let _ = send_arp_request_in(net_ns_id, ip);
                    }
                    crate::arp_cache::ResolutionStep::GaveUp => {
                        gave_up = true;
                        return true;
                    }
                    crate::arp_cache::ResolutionStep::Wait => {}
                }
            }
            false
        },
        deadline,
    );
    if gave_up {
        return Err(());
    }
    let resolved = arp_lookup_local(net_ns_id, ip);
    if resolved.is_none() {
        // The caller's deadline expired before the probe budget did. That
        // is NOT a failed resolution — the entry stays Incomplete so a
        // later attempt resumes the remaining probes instead of starting a
        // negative-cache entry the host never earned.
        return Err(());
    }
    resolved.ok_or(())
}

// ── RX dispatch ─────────────────────────────────────────────────

/// Top-level RX path called by the iface registry. Parses the
/// L2 header and routes by ethertype.
///
/// `frame` is `&mut` because the bypass classifier runs the attached XDP
/// program, which may rewrite bytes in place. Once `classify` returns the
/// frame is only re-borrowed immutably (parse, deliver, and — for `XDP_TX`/
/// `XDP_REDIRECT` — retransmit), so downstream code sees the *possibly-
/// modified* frame, which is exactly what those verdicts must reflect.
pub fn rx_handler(iface_name: &str, frame: &mut [u8]) {
    if frame.len() < ETH_HDR_LEN {
        return;
    }
    // Ingress iface for ARP replies (empty = unknown).
    let _iface_name = if iface_name.is_empty() {
        None
    } else {
        Some(iface_name)
    };
    // Kernel-bypass classifier. Runs before any L2 parse so a
    // whole-NIC daemon attach sees the raw frame; per-flow claims
    // get their 5-tuple from the frame's IPv4+L4 headers. On a
    // Consumed verdict the frame is already staged into the
    // claimant's UMEM → RX ring and we MUST NOT continue down the
    // kernel stack — that would double-deliver the frame.
    //
    // Linux ref: linux/net/core/dev.c::netif_receive_skb_core
    // installs the XDP/AF_XDP hook ahead of the protocol-stack
    // dispatch; same shape.
    let ingress = _iface_name.and_then(iface::lookup);
    let net_ns_id = ingress.as_ref().map_or(0, |entry| entry.net_ns_id);
    let bypass_iface = ingress
        .as_ref()
        .map(|entry| entry.name.clone())
        .unwrap_or_else(|| alloc::string::String::from("eth0"));
    // `classify` runs any attached XDP program, which may resize the frame
    // (`bpf_xdp_adjust_head`/`_tail`). The effective packet is `frame[..len]`;
    // everything below transmits or delivers that window rather than the
    // original slice.
    let (verdict, len) = crate::bypass::classifier::classify(&bypass_iface, frame);
    match verdict {
        crate::bypass::classifier::Verdict::Consumed => return,
        crate::bypass::classifier::Verdict::Dropped => return,
        // XDP_TX: reflect the (possibly-rewritten, possibly-resized) frame back
        // out the iface it arrived on. `classify` returns this *after* releasing
        // its `XDP_PROGS` lock, so transmitting here does not run with that lock
        // held or IRQs masked by it — and the `&mut` borrow the program held is
        // gone, so this immutable re-borrow sees the bytes it wrote. A send
        // failure (link down, driver full) drops the frame — the same fate
        // XDP_TX has in Linux when the ring cannot take it — and is counted so it
        // is visible rather than silent.
        crate::bypass::classifier::Verdict::Transmit => {
            if iface::send_on(&bypass_iface, &frame[..len]).is_err() {
                crate::bypass::classifier::count_xdp_tx_drop();
            }
            return;
        }
        // XDP_REDIRECT: send the (possibly-rewritten, possibly-resized) frame out
        // the program-chosen iface, resolved from the ifindex `bpf_redirect`
        // stashed. An unknown ifindex or a driver error drops the frame (a
        // redirect to a down/absent device is a drop in Linux too) and is
        // counted.
        crate::bypass::classifier::Verdict::Redirect { ifindex } => {
            if iface::send_on_ifindex(ifindex, &frame[..len]).is_err() {
                crate::bypass::classifier::count_xdp_tx_drop();
            }
            return;
        }
        // XDP_REDIRECT with BPF_F_BROADCAST: fan the (possibly-rewritten,
        // possibly-resized) frame out every devmap port the program staged.
        // Sent here, after `classify` released `XDP_PROGS`, like the single
        // `Redirect`. `BPF_F_EXCLUDE_INGRESS` skips the iface the frame arrived
        // on, resolved from its name since only this side knows the ingress.
        // Each failed port is counted a drop, matching the single-target path.
        crate::bypass::classifier::Verdict::Broadcast => {
            let mut ports = [0u32; crate::bypass::classifier::MAX_XDP_BROADCAST_PORTS];
            let (n, exclude_ingress) = crate::bypass::classifier::take_xdp_broadcast(&mut ports);
            let ingress = if exclude_ingress {
                iface::ifindex_of(&bypass_iface)
            } else {
                None
            };
            for &ifindex in &ports[..n] {
                if Some(ifindex) == ingress {
                    continue;
                }
                if iface::send_on_ifindex(ifindex, &frame[..len]).is_err() {
                    crate::bypass::classifier::count_xdp_tx_drop();
                }
            }
            return;
        }
        crate::bypass::classifier::Verdict::PassThrough => {}
    }
    // The kernel stack likewise sees only the effective packet window: a
    // resizing program's `[data, data_end)` is `frame[..len]`.
    let frame = &mut frame[..len];

    // AF_PACKET raw sockets see every frame before L3 dispatch.
    crate::raw_sock::raw_pkt_deliver_in(net_ns_id, frame, 1);
    let (eth, body) = match parse_eth_header(frame) {
        Some(t) => t,
        None => return,
    };
    match eth.ethertype {
        ETHERTYPE_ARP => handle_arp_on_in(body, net_ns_id, _iface_name),
        ETHERTYPE_IPV4 => {
            handle_ipv4(body, net_ns_id, _iface_name.unwrap_or(""));
        }
        _ => {}
    }
}

/// ARP handler with optional ingress-iface context. When `iface_name`
/// is Some the sender MAC is also recorded in the per-iface arp_cache
/// state-machine — the multi-NIC-correct path so a reply arriving on
/// iface1 doesn't populate iface2's cache.
/// Ref: Linux `arp_rcv()` in `net/ipv4/arp.c`.
pub fn handle_arp_on(body: &[u8], iface_name: Option<&str>) {
    handle_arp_on_in(body, 0, iface_name);
}

pub fn handle_arp_on_in(body: &[u8], net_ns_id: u64, iface_name: Option<&str>) {
    let arp = match parse_arp(body) {
        Some(a) => a,
        None => return,
    };
    arp_insert_local(net_ns_id, arp.spa, arp.sha);
    // Per-iface cache: record on the ingress interface if known.
    if let Some(name) = iface_name {
        arp_cache::insert(name, arp.spa, arp.sha);
    }
    if arp.op == ARP_OP_REQUEST {
        // Answer from whichever iface actually owns the requested
        // address. ARP targets a specific IP, so the responder MUST be
        // that IP's iface — falling back to `primary()` (first-
        // registered) wrongly answers (or fails to answer) when the
        // owning NIC isn't first, e.g. e1000 registers before virtio-net
        // but only virtio-net carries 10.0.2.15. Without this, QEMU's
        // user-mode (SLIRP) hostfwd can't ARP-resolve the guest and the
        // forwarded SYN is never delivered.
        // Prefer the INGRESS iface when it owns the requested address —
        // the reply must go back out the NIC the request came in on, so a
        // multi-NIC / overlapping-subnet setup (e.g. two QEMU user-mode
        // NICs) answers on the correct link. Fall back to any iface that
        // owns the address, then `primary`.
        let snap = iface_name
            .and_then(iface::lookup)
            .filter(|s| s.net_ns_id == net_ns_id && s.ipv4 == arp.tpa)
            .or_else(|| iface::for_local_addr_in(net_ns_id, arp.tpa))
            .or_else(|| iface_name.and_then(iface::lookup))
            .filter(|s| s.net_ns_id == net_ns_id)
            .or_else(|| iface::primary_in(net_ns_id));
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

/// True iff this is a UDP datagram to the DHCP client port.
///
/// A DHCPOFFER/DHCPACK is addressed to the address being *offered*, which by
/// definition is not configured yet, so the routing decision above would drop
/// it and the lease could never be taken up. Linux never hits this because
/// its DHCP clients receive on AF_PACKET, below the routing decision; NARF's
/// client is in-kernel on the UDP path (`dhcp::on_udp_in_in`, reached from
/// `handle_udp`), so the exception has to be made here instead.
fn is_dhcp_client_datagram(body: &[u8]) -> bool {
    const DHCP_CLIENT_PORT: u16 = 68;
    if body.len() < crate::netfilter::IPV4_MIN_HDR_LEN {
        return false;
    }
    if body[9] != IP_PROTO_UDP {
        return false;
    }
    // Fragments past the first carry no L4 header: offset is the low 13 bits
    // of the flags/fragment word.
    if u16::from_be_bytes([body[6], body[7]]) & 0x1FFF != 0 {
        return false;
    }
    let ihl = ((body[0] & 0x0F) as usize) * 4;
    if ihl < crate::netfilter::IPV4_MIN_HDR_LEN || body.len() < ihl + 4 {
        return false;
    }
    u16::from_be_bytes([body[ihl + 2], body[ihl + 3]]) == DHCP_CLIENT_PORT
}

fn handle_ipv4(body: &[u8], net_ns_id: u64, iface_in: &str) {
    // ── Netfilter PRE_ROUTING + LOCAL_IN dispatch ──
    //
    // The hooks only READ the packet (conntrack parses the tuple, filter
    // matches rules) unless a NAT/mangle rule actually rewrites it, so we
    // hand them a copy-on-write borrow (`new_ipv4_ref`) instead of
    // eagerly copying every frame into a scratch buffer. With no mutating
    // rule (the common server case) this is zero-copy on the per-frame
    // forwarder hot path; only a NAT rewrite triggers a single clone. One
    // `PktCtx` carries the packet across both hook points so a PRE_ROUTING
    // mutation is visible at LOCAL_IN. If either returns Drop, drop here.
    //
    // Matches Linux's NF_HOOK call from `ip_rcv_core()` →
    // `ip_rcv_finish()` in `net/ipv4/ip_input.c`.
    if body.len() < crate::netfilter::IPV4_MIN_HDR_LEN {
        return;
    }
    let mut ctx = crate::netfilter::PktCtx::new_ipv4_ref(
        crate::netfilter::HookPoint::PreRouting,
        iface_in,
        "",
        body,
    )
    .with_net_ns(net_ns_id);
    if crate::netfilter::nf_dispatch(&mut ctx) == crate::netfilter::Verdict::Drop {
        return;
    }
    // ── Input routing decision ──
    //
    // Linux runs `ip_route_input_noref()` here, between PRE_ROUTING and
    // LOCAL_IN, and only RTN_LOCAL / RTN_BROADCAST / RTN_MULTICAST reach
    // `ip_local_deliver`. Anything else is forwarded or dropped. The order
    // matters: PRE_ROUTING (and any DNAT in it) runs first, so the decision
    // must read the possibly-rewritten packet, not the frame as it arrived.
    //
    // A destination that is not ours goes to `ip_forward::try_forward`,
    // which routes it on when `net.ipv4.ip_forward` allows and otherwise
    // drops. Without this step every packet reaching the stack was
    // delivered as if addressed to us.
    {
        let decided = ctx.packet();
        if let Some((ip, _)) = parse_ipv4(decided) {
            if !crate::ip_local::deliver_locally_in(net_ns_id, ip.dst_ip)
                && !is_dhcp_client_datagram(decided)
            {
                crate::ip_forward::try_forward(net_ns_id, iface_in, decided);
                return;
            }
        }
    }

    ctx.hook = crate::netfilter::HookPoint::LocalIn;
    ctx.conntrack_id = None;
    if crate::netfilter::nf_dispatch(&mut ctx) == crate::netfilter::Verdict::Drop {
        return;
    }
    let body = ctx.packet();
    let (ip, payload) = match parse_ipv4(body) {
        Some(t) => t,
        None => return,
    };
    // TTL is at byte offset 8 in the raw IPv4 header.
    let ttl = if body.len() >= 9 { body[8] } else { 64 };
    match ip.protocol {
        IP_PROTO_TCP => {
            crate::tcp::core::handle_segment_in(net_ns_id, ip.src_ip, ip.dst_ip, payload)
        }
        IP_PROTO_UDP => handle_udp(
            net_ns_id,
            ip.src_ip,
            ip.dst_ip,
            payload,
            ttl,
            // The arrival interface, Linux's `dif`. `handle_ipv4` has
            // carried the NAME all along; only the index was missing, which
            // is why SO_BINDTODEVICE could not be checked on receive.
            iface::ifindex_of(iface_in).unwrap_or(0),
        ),
        IP_PROTO_ICMP => crate::icmp_sock::on_icmp_rx_in(net_ns_id, ip.src_ip, ip.dst_ip, payload),
        _ => {}
    }
}

fn handle_udp(
    net_ns_id: u64,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    datagram: &[u8],
    ttl: u8,
    in_ifindex: u32,
) {
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
    // Deliver to registered UDP sockets (udp_sock layer).
    // `in_ifindex` is Linux's `dif`: SO_BINDTODEVICE is enforced against
    // the interface the datagram ARRIVED on.
    crate::udp_sock::deliver_in(net_ns_id, src_ip, dst_ip, datagram, ttl, in_ifindex);
    // Legacy per-protocol consumers.
    if dst_port == 68 {
        crate::dhcp::on_udp_in_in(net_ns_id, src_ip, dst_ip, src_port, dst_port, payload);
    }
}

// ── ICMP error signalling (called by icmp_sock) ─────────────────

/// Notify the TCP connection identified by
/// `(local_addr, local_port, remote_addr, remote_port)` of an ICMP error
/// about the segment with sequence number `seq`. Linux `tcp_v4_err`
/// semantics — see `tcp::core::signal_icmp_error_in`: fatal (abort with the
/// ICMP-derived errno) only during the handshake, a soft error otherwise.
pub fn signal_icmp_error(
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    icmp_type: u8,
    icmp_code: u8,
    seq: u32,
) {
    crate::tcp::core::signal_icmp_error(
        remote_addr,
        remote_port,
        local_addr,
        local_port,
        icmp_type,
        icmp_code,
        seq,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn signal_icmp_error_in(
    net_ns_id: u64,
    local_addr: [u8; 4],
    local_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    icmp_type: u8,
    icmp_code: u8,
    seq: u32,
) {
    crate::tcp::core::signal_icmp_error_in(
        net_ns_id,
        remote_addr,
        remote_port,
        local_addr,
        local_port,
        icmp_type,
        icmp_code,
        seq,
    );
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
    // Register default netfilter hooks: conntrack at PRE_ROUTING &
    // LOCAL_OUT, filter at all five points, NAT at PRE_ROUTING /
    // POST_ROUTING. Idempotent — calling twice double-registers, so
    // `init()` is only run once at boot.
    crate::netfilter::filter::init_all_default_hooks();
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

/// Run the netfilter LOCAL_OUT + POST_ROUTING hooks against an
/// outbound L3 packet. Callers building outbound IPv4 frames (TCP
/// stack, UDP socket layer, raw socket layer) should run this just
/// before handing the frame off to `iface::send`. The packet is
/// mutated in place — NAT rewrites src/dst + recomputes checksums.
/// Returns `Verdict::Accept` to mean "send", any other verdict to
/// mean "don't".
///
/// Matches the Linux outbound flow `__ip_local_out()` →
/// `ip_output()` in `net/ipv4/ip_output.c`.
pub fn nf_tx_filter(iface_out: &str, ipv4_packet: &mut [u8]) -> crate::netfilter::Verdict {
    nf_tx_filter_in(0, iface_out, ipv4_packet)
}

pub fn nf_tx_filter_in(
    net_ns_id: u64,
    iface_out: &str,
    ipv4_packet: &mut [u8],
) -> crate::netfilter::Verdict {
    {
        let mut ctx = crate::netfilter::PktCtx::new_ipv4(
            crate::netfilter::HookPoint::LocalOut,
            "",
            iface_out,
            ipv4_packet,
        )
        .with_net_ns(net_ns_id);
        let v = crate::netfilter::nf_dispatch(&mut ctx);
        if v != crate::netfilter::Verdict::Accept {
            return v;
        }
    }
    let mut ctx = crate::netfilter::PktCtx::new_ipv4(
        crate::netfilter::HookPoint::PostRouting,
        "",
        iface_out,
        ipv4_packet,
    )
    .with_net_ns(net_ns_id);
    crate::netfilter::nf_dispatch(&mut ctx)
}
