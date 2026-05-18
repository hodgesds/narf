//! Minimal DHCPv4 client (RFC 2131 / RFC 2132).
//!
//! Acquires a lease through the registered `iface`: send DHCPDISCOVER
//! to 255.255.255.255:67, wait for a DHCPOFFER, send a DHCPREQUEST
//! for the offered address, wait for a DHCPACK. The lease populates
//! the `iface` registry's `ipv4` + `gateway` fields so the existing
//! TCP stack can route through the new address without re-init.
//!
//! Scope (Stage-1):
//!   * IPv4 only; no DHCPv6.
//!   * Single-server flow — first OFFER wins. No relay agents, no
//!     option-tagged authentication.
//!   * Synchronous busy-wait: `acquire` calls
//!     `narf_scheduler::responsive_spin_until` while draining the
//!     iface RX path. Production DHCP renew/rebind cycles are a
//!     follow-up.
//!   * No DECLINE / NAK retry — a NAK or timeout returns Err.
//!
//! Inbound dispatch: `on_udp_in` is called by `tcp_stack::handle_ipv4`
//! when a UDP datagram lands on src=67 dst=68. We stash the parsed
//! reply in a static slot so `acquire`'s busy-wait can observe it
//! between drain steps.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::narf_time;

use crate::iface;
use crate::pkt::{self, set_ipv4_checksum, write_eth_header, write_ipv4_header, ETH_HDR_LEN, ETHERTYPE_IPV4, IPV4_HDR_LEN, IP_PROTO_UDP};
use crate::pkt_dhcp::{
    build_discover, build_request, iter_options, DhcpHeader, DHCPACK, DHCPOFFER,
    OPT_DHCP_MESSAGE_TYPE, OPT_LEASE_TIME, OPT_ROUTER, OPT_SERVER_IDENTIFIER, OPT_SUBNET_MASK,
};
use crate::pkt_udp::{build_ipv4 as build_udp_datagram, UDP_HDR_LEN};

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;

/// Snapshot of a successful DHCP lease. Populated by the OFFER+ACK
/// exchange. Callers receive this from `acquire`; the same values
/// also land in the iface registry as the new default route.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DhcpLease {
    pub ip: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub server: [u8; 4],
    pub lease_secs: u32,
}

/// Latest DHCP reply observed by `on_udp_in`. `acquire` polls this
/// between drain steps. Reset to `None` at the start of each
/// `acquire` call to avoid stale-reply confusion across runs.
#[derive(Copy, Clone, Debug)]
struct ParsedReply {
    xid: u32,
    msg_type: u8,
    yiaddr: [u8; 4],
    server: [u8; 4],
    netmask: [u8; 4],
    gateway: [u8; 4],
    lease_secs: u32,
}

static LATEST_REPLY: IrqSafeSpinLock<Option<ParsedReply>> = IrqSafeSpinLock::new(None);
/// Monotonic xid source — distinguishes our discover/request from
/// any other clients sharing the segment.
static XID_COUNTER: AtomicU32 = AtomicU32::new(0xC0DE_0000);

fn next_xid() -> u32 {
    XID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Called from `tcp_stack::handle_ipv4` when a UDP datagram with
/// `dst_port == 68` arrives. Parses the DHCP payload + caches it
/// for `acquire` to pick up.
pub fn on_udp_in(_src_ip: [u8; 4], _dst_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) {
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
        lease_secs,
    });
}

fn take_matching_reply(want_xid: u32, want_msg_type: u8) -> Option<ParsedReply> {
    let mut g = LATEST_REPLY.lock();
    let r = *g.as_ref()?;
    if r.xid == want_xid && r.msg_type == want_msg_type {
        *g = None;
        Some(r)
    } else {
        None
    }
}

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
    // UDP datagram + payload. `build_udp_datagram` from pkt_udp
    // builds a complete UDP datagram (header + payload) with the
    // checksum computed against the IPv4 pseudo-header.
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

/// Acquire a DHCP lease on the named interface. Times out after
/// `timeout_ms` total (DISCOVER + REQUEST share the budget).
///
/// On success: updates the iface registry's `ipv4`/`gateway` to the
/// leased values and returns the full lease. On failure (timeout,
/// NAK, no iface, send error): returns `Err`.
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
    let mut offer = None;
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
    let mut ack = None;
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

    // Apply the lease to the iface registry. iface::set_default_ipv4
    // updates the *primary* iface, which may not be the named one
    // — short-circuit when names mismatch so a multi-iface host
    // doesn't accidentally retarget the wrong NIC.
    if let Some(primary) = iface::primary() {
        if primary.name == iface_name {
            iface::set_default_ipv4(ack.yiaddr, ack.gateway);
        }
    }
    Ok(DhcpLease {
        ip: ack.yiaddr,
        netmask: ack.netmask,
        gateway: ack.gateway,
        server: ack.server,
        lease_secs: ack.lease_secs,
    })
}

/// Test-only: clear the cached reply so a follow-on test isn't
/// confused by a stale broadcast from the previous one.
#[doc(hidden)]
pub fn __reset_for_test() {
    *LATEST_REPLY.lock() = None;
    let _ = pkt::ETH_HDR_LEN; // silence unused-import warning
}
