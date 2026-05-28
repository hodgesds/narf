//! DHCPv4 client — state machine + lease management.
//!
//! ## Protocol reference
//!
//! RFC 2131 — Dynamic Host Configuration Protocol (R. Droms, Mar 1997).
//! §3.1: client/server exchange flow (DISCOVER → OFFER → REQUEST → ACK).
//! §4.1: client state machine — INIT, SELECTING, REQUESTING, BOUND.
//! <https://datatracker.ietf.org/doc/html/rfc2131>
//!
//! RFC 2132 — DHCP Options and BOOTP Vendor Extensions
//! (S. Alexander & R. Droms, Mar 1997). Option 6 (DNS servers),
//! option 51 (lease time), option 53 (message type), option 54
//! (server identifier).
//! <https://datatracker.ietf.org/doc/html/rfc2132>
//!
//! RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses
//! (S. Cheshire et al., May 2005). §2.1 (169.254.0.0/16 range).
//! Used for the static fallback when DHCP times out.
//! <https://datatracker.ietf.org/doc/html/rfc3927>
//!
//! ## DISCOVER → OFFER → REQUEST → ACK state machine
//!
//! `dhcp_acquire` runs up to `DHCP_MAX_ATTEMPTS` (4) full
//! DISCOVER→OFFER→REQUEST→ACK cycles, each with a `DHCP_PER_ATTEMPT_MS`
//! (4 s) budget split equally between OFFER and ACK waits.  On timeout
//! after all attempts it falls back to a deterministic link-local
//! address derived from the interface MAC (RFC 3927 §2.1).
//!
//! ## Low-level `acquire`
//!
//! The original `acquire` function (single-attempt, `[u8;4]`-based API)
//! is kept for the TCP-stack's existing callers. The new `dhcp_acquire`
//! wraps it with retry + fallback and returns the richer `Lease` type.
//!
//! ## RX dispatch
//!
//! `on_udp_in` is called by `tcp_stack::handle_ipv4` when a UDP
//! datagram lands on src=67 dst=68. The parsed reply is stashed in a
//! static slot for `acquire`'s busy-wait loop to observe.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time;

use crate::iface;
use crate::ipv4::{bind_address, Ipv4Addr};
use crate::pkt::{
    self, set_ipv4_checksum, write_eth_header, write_ipv4_header, ETH_HDR_LEN, ETHERTYPE_IPV4,
    IPV4_HDR_LEN, IP_PROTO_UDP,
};
use crate::pkt_dhcp::{
    build_discover, build_request, iter_options, DhcpHeader, DHCPACK, DHCPOFFER,
    OPT_DHCP_MESSAGE_TYPE, OPT_DNS_SERVER, OPT_LEASE_TIME, OPT_ROUTER, OPT_SERVER_IDENTIFIER,
    OPT_SUBNET_MASK,
};
use crate::pkt_udp::{build_ipv4 as build_udp_datagram, UDP_HDR_LEN};

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

// ── Retry + fallback constants ─────────────────────────────────────

/// Number of full DISCOVER→OFFER→REQUEST→ACK cycles before giving up.
const DHCP_MAX_ATTEMPTS: u32 = 4;
/// Per-attempt timeout (milliseconds). Split equally between OFFER wait
/// and ACK wait inside the inner `acquire` call.
const DHCP_PER_ATTEMPT_MS: u64 = 4_000;

// ── Legacy internal reply type ─────────────────────────────────────

/// Snapshot of a successful DHCP lease (legacy `acquire` return type).
/// Callers that don't need the DNS list or `Option<gateway>` semantics
/// use this; `dhcp_acquire` returns the richer `Lease` type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DhcpLease {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub server: [u8; 4],
    pub lease_secs: u32,
}

// ── Parsed reply cache ─────────────────────────────────────────────

/// Internal parsed reply stashed by `on_udp_in` for the busy-wait in
/// `acquire` to observe.
#[derive(Clone, Debug)]
struct ParsedReply {
    xid: u32,
    msg_type: u8,
    yiaddr: [u8; 4],
    server: [u8; 4],
    netmask: [u8; 4],
    gateway: [u8; 4],
    /// Up to 3 DNS servers from option 6 (RFC 2132 §3.8).
    dns: [[u8; 4]; 3],
    dns_count: u8,
    lease_secs: u32,
}

static LATEST_REPLY: IrqSafeSpinLock<Option<ParsedReply>> = IrqSafeSpinLock::new(None);

/// Monotonic xid source — distinguishes our discover/request from
/// any other clients sharing the segment.
static XID_COUNTER: AtomicU32 = AtomicU32::new(0xC0DE_0000);

fn next_xid() -> u32 {
    XID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── RX dispatch hook ──────────────────────────────────────────────

/// Called from `tcp_stack::handle_ipv4` when a UDP datagram with
/// `dst_port == 68` arrives. Parses the DHCP payload and caches it
/// for `acquire` to pick up.
pub fn on_udp_in(
    _src_ip: [u8; 4],
    _dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) {
    if src_port != DHCP_SERVER_PORT || dst_port != DHCP_CLIENT_PORT {
        return;
    }
    let hdr = match DhcpHeader::decode(payload) {
        Ok(h) => h,
        Err(_) => return,
    };
    let mut msg_type = 0u8;
    let mut server = [0u8; 4];
    let mut netmask = [0u8; 4];
    let mut gateway = [0u8; 4];
    let mut dns: [[u8; 4]; 3] = [[0u8; 4]; 3];
    let mut dns_count = 0u8;
    let mut lease_secs = 0u32;
    if payload.len() < 240 {
        return;
    }
    for opt in iter_options(&payload[240..]) {
        match opt.tag {
            OPT_DHCP_MESSAGE_TYPE if opt.data.len() == 1 => msg_type = opt.data[0],
            OPT_SERVER_IDENTIFIER if opt.data.len() == 4 => server.copy_from_slice(opt.data),
            OPT_SUBNET_MASK if opt.data.len() == 4 => netmask.copy_from_slice(opt.data),
            OPT_ROUTER if opt.data.len() >= 4 => gateway.copy_from_slice(&opt.data[..4]),
            OPT_LEASE_TIME if opt.data.len() == 4 => {
                lease_secs = u32::from_be_bytes([
                    opt.data[0],
                    opt.data[1],
                    opt.data[2],
                    opt.data[3],
                ]);
            }
            // RFC 2132 §3.8 option 6: DNS server(s). Each address is 4
            // bytes; parse up to 3 addresses.
            OPT_DNS_SERVER if opt.data.len() >= 4 => {
                let n = (opt.data.len() / 4).min(3) as u8;
                for i in 0..n as usize {
                    dns[i].copy_from_slice(&opt.data[i * 4..i * 4 + 4]);
                }
                dns_count = n;
            }
            _ => {}
        }
    }
    *LATEST_REPLY.lock() = Some(ParsedReply {
        xid: hdr.xid,
        msg_type,
        yiaddr: hdr.yiaddr,
        server,
        netmask,
        gateway,
        dns,
        dns_count,
        lease_secs,
    });
}

fn take_matching_reply(want_xid: u32, want_msg_type: u8) -> Option<ParsedReply> {
    let mut g = LATEST_REPLY.lock();
    let r = g.as_ref()?.clone();
    if r.xid == want_xid && r.msg_type == want_msg_type {
        *g = None;
        Some(r)
    } else {
        None
    }
}

// ── Broadcast frame builder ────────────────────────────────────────

/// Wrap a DHCP payload in UDP + IPv4 + Ethernet for the broadcast
/// 255.255.255.255 destination. Returns the full on-wire frame.
fn wrap_broadcast_frame(src_mac: [u8; 6], src_ip: [u8; 4], dhcp_payload: &[u8]) -> Vec<u8> {
    let bcast_mac: [u8; 6] = [0xFF; 6];
    let bcast_ip: [u8; 4] = [255, 255, 255, 255];
    let total = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + dhcp_payload.len();
    let mut frame = alloc::vec![0u8; total];
    // Ethernet header.
    write_eth_header(&mut frame, bcast_mac, src_mac, ETHERTYPE_IPV4);
    // IPv4 header. `total_len` is IP-header + UDP-datagram length.
    let ip_total = (IPV4_HDR_LEN + UDP_HDR_LEN + dhcp_payload.len()) as u16;
    {
        let ip_off = ETH_HDR_LEN;
        let _ = write_ipv4_header(
            &mut frame[ip_off..],
            ip_total,
            IP_PROTO_UDP,
            src_ip,
            bcast_ip,
        );
        set_ipv4_checksum(&mut frame[ip_off..]);
    }
    // UDP datagram + payload.
    let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
    let _ = build_udp_datagram(
        &mut frame[udp_off..],
        src_ip,
        bcast_ip,
        DHCP_CLIENT_PORT,
        DHCP_SERVER_PORT,
        dhcp_payload,
    );
    frame
}

// ── Low-level single-attempt acquire ──────────────────────────────

/// Acquire a DHCP lease on the named interface. Times out after
/// `timeout_ms` total (DISCOVER + REQUEST share the budget).
///
/// On success: updates the iface registry's `ipv4`/`gateway` to the
/// leased values and returns the full lease. On failure (timeout,
/// NAK, no iface, send error): returns `Err`.
///
/// **Prefer `dhcp_acquire` for new callers** — it retries 4 times
/// and falls back to link-local. This function is the single-attempt
/// inner loop used by both.
pub fn acquire(iface_name: &str, timeout_ms: u64) -> Result<DhcpLease, ()> {
    let snap = iface::lookup(iface_name).ok_or(())?;
    let xid = next_xid();

    // Clear any stale reply cached from a previous run.
    *LATEST_REPLY.lock() = None;

    // ── DISCOVER ─────────────────────────────────────────────────
    let discover_dhcp = build_discover(xid, snap.mac);
    let discover_frame = wrap_broadcast_frame(snap.mac, [0, 0, 0, 0], &discover_dhcp);
    (snap.send)(&discover_frame)?;

    // Half the budget for OFFER, half for ACK.
    let half = timeout_ms / 2;
    let deadline = narf_time::Deadline::after_ns(half.saturating_mul(1_000_000));
    let mut offer: Option<ParsedReply> = None;
    let _ = narf_scheduler::responsive_spin_until(
        || {
            while iface::drain_pump() {}
            if let Some(r) = take_matching_reply(xid, DHCPOFFER) {
                offer = Some(r);
                return true;
            }
            false
        },
        deadline,
    );
    let offer = offer.ok_or(())?;

    // ── REQUEST ─────────────────────────────────────────────────
    let request_dhcp = build_request(xid, snap.mac, offer.yiaddr, offer.server);
    let request_frame = wrap_broadcast_frame(snap.mac, [0, 0, 0, 0], &request_dhcp);
    (snap.send)(&request_frame)?;

    let deadline = narf_time::Deadline::after_ns(half.saturating_mul(1_000_000));
    let mut ack: Option<ParsedReply> = None;
    let _ = narf_scheduler::responsive_spin_until(
        || {
            while iface::drain_pump() {}
            if let Some(r) = take_matching_reply(xid, DHCPACK) {
                ack = Some(r);
                return true;
            }
            false
        },
        deadline,
    );
    let ack = ack.ok_or(())?;

    // Apply the lease to the iface registry.
    if let Some(primary) = iface::primary() {
        if primary.name == iface_name {
            iface::set_default_ipv4(ack.yiaddr, ack.gateway);
        }
    }

    // Populate the DNS side-channel so dhcp_acquire can read it.
    {
        let mut g = LATEST_DNS.lock();
        g.0 = ack.dns;
        g.1 = ack.dns_count;
    }

    Ok(DhcpLease {
        ip: ack.yiaddr,
        netmask: ack.netmask,
        gateway: ack.gateway,
        server: ack.server,
        lease_secs: ack.lease_secs,
    })
}

// ── DNS side-channel ──────────────────────────────────────────────
//
// `acquire` returns the legacy `DhcpLease` which doesn't carry DNS.
// We stash the DNS array here (populated from the ACK's option 6)
// so `dhcp_acquire` can read it after `acquire` returns.

static LATEST_DNS: IrqSafeSpinLock<([[u8; 4]; 3], u8)> =
    IrqSafeSpinLock::new(([[0u8; 4]; 3], 0));

// ── Public API ────────────────────────────────────────────────────

/// Full DHCP lease returned by `dhcp_acquire`.
///
/// RFC 2131 §3 (BOUND state fields). `dns` contains up to 3 addresses
/// from option 6 (RFC 2132 §3.8). An empty `dns` vec is valid — some
/// networks don't push DNS via DHCP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    /// Assigned IPv4 address (RFC 2131 §2: yiaddr).
    pub addr: Ipv4Addr,
    /// Network mask (RFC 2132 option 1).
    pub netmask: Ipv4Addr,
    /// Default gateway, `None` if the server did not push option 3.
    pub gateway: Option<Ipv4Addr>,
    /// DNS resolver addresses (RFC 2132 option 6). Up to 3 entries.
    pub dns: Vec<Ipv4Addr>,
    /// Lease duration in seconds (RFC 2132 option 51).
    pub lease_seconds: u32,
}

/// Errors returned by `dhcp_acquire`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DhcpError {
    /// Interface not found in the `iface` registry.
    NoIface,
    /// All DHCP attempts timed out; link-local fallback was assigned.
    LinkLocalFallback,
}

/// Acquire an IPv4 address on `iface_name`. Runs up to
/// `DHCP_MAX_ATTEMPTS` (4) DISCOVER→OFFER→REQUEST→ACK cycles, each
/// with a `DHCP_PER_ATTEMPT_MS` (4 s) budget.
///
/// On success: installs the lease via `ipv4::bind_address` and returns
/// `Ok(Lease)`.
///
/// On timeout after all attempts: assigns a deterministic link-local
/// address from 169.254.0.0/16 (RFC 3927 §2.1) derived from the low
/// two bytes of the interface MAC, installs it via `bind_address`, and
/// returns `Err(DhcpError::LinkLocalFallback)`.
///
/// `timeout_ms` is reserved for future per-attempt tuning; the actual
/// budget is `DHCP_MAX_ATTEMPTS × DHCP_PER_ATTEMPT_MS`.
pub fn dhcp_acquire(iface_name: &str, _timeout_ms: u32) -> Result<Lease, DhcpError> {
    let snap = iface::lookup(iface_name).ok_or(DhcpError::NoIface)?;

    for _attempt in 0..DHCP_MAX_ATTEMPTS {
        // Reset DNS side-channel before each attempt.
        {
            let mut g = LATEST_DNS.lock();
            g.0 = [[0u8; 4]; 3];
            g.1 = 0;
        }

        if let Ok(raw) = acquire(iface_name, DHCP_PER_ATTEMPT_MS) {
            // Read the DNS side-channel written by `acquire`.
            let (dns_raw, dns_count) = {
                let g = LATEST_DNS.lock();
                (g.0, g.1)
            };

            let mut dns_vec: Vec<Ipv4Addr> = Vec::new();
            for i in 0..dns_count as usize {
                if dns_raw[i] != [0u8; 4] {
                    dns_vec.push(Ipv4Addr(dns_raw[i]));
                }
            }

            let gateway = if raw.gateway == [0u8; 4] {
                None
            } else {
                Some(Ipv4Addr(raw.gateway))
            };

            let lease = Lease {
                addr: Ipv4Addr(raw.ip),
                netmask: Ipv4Addr(raw.netmask),
                gateway,
                dns: dns_vec.clone(),
                lease_seconds: raw.lease_secs,
            };

            // Install the binding so `ipv4_send` can route.
            bind_address(
                iface_name,
                Ipv4Addr(raw.ip),
                Ipv4Addr(raw.netmask),
                gateway,
                &dns_vec,
            );

            return Ok(lease);
        }
    }

    // All attempts exhausted. Fall back to link-local (RFC 3927 §2.1).
    // Deterministic: 169.254.<mac[4] | 1>.<mac[5] | 1> avoids .0 and .255.
    let a = if snap.mac[4] == 0 { 1u8 } else { snap.mac[4] };
    let b = if snap.mac[5] == 0 || snap.mac[5] == 255 {
        1u8
    } else {
        snap.mac[5]
    };
    let ll_addr = Ipv4Addr([169, 254, a, b]);
    let ll_mask = Ipv4Addr([255, 255, 0, 0]);

    bind_address(iface_name, ll_addr, ll_mask, None, &[]);

    Err(DhcpError::LinkLocalFallback)
}

// ── Test helpers ───────────────────────────────────────────────────

/// Test-only: clear the cached reply so a follow-on test isn't
/// confused by a stale broadcast from the previous one.
#[doc(hidden)]
pub fn __reset_for_test() {
    *LATEST_REPLY.lock() = None;
    let _ = pkt::ETH_HDR_LEN; // silence unused-import warning
}
