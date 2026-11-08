//! ICMPv6 socket — Echo (Ping6) + raw type-filtered receive.
//!
//! References (public-only):
//! - RFC 4443 — Internet Control Message Protocol (ICMPv6) for the
//!   IPv6 Specification (A. Conta, S. Deering, M. Gupta, Mar 2006).
//!   §4.1 (Echo Request, type 128), §4.2 (Echo Reply, type 129).
//!   <https://datatracker.ietf.org/doc/html/rfc4443>
//!
//! Stage-1 scope: a single-handle table keyed by 32-bit id. Each
//! handle owns a small inbound queue + an optional type filter (the
//! `IPV6_RECVERR`/`ICMP6_FILTER` analog). Send paths build the ICMPv6
//! Echo Request body; the caller (`ipv6_stack::send`) wraps it in
//! IPv6 + L2 and hands it to the iface.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::readiness::Readiness;
use narf_lib::sync::IrqSafeSpinLock;

use crate::pkt_ipv6::{Icmpv6Header, ICMPV6_ECHO_REPLY, ICMPV6_ECHO_REQUEST};

/// One inbound ICMPv6 message captured by a raw socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6Msg {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub typ: u8,
    pub code: u8,
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct Sock {
    /// 256-bit type filter where bit `t` set means "block type t"
    /// (Linux `struct icmp6_filter` semantics: 0 = pass, 1 = block).
    /// Default `[0u32; 8]` passes all types.
    filter: [u32; 8],
    queue: VecDeque<Icmp6Msg>,
    /// Echo session id used to match Echo Replies to Echo Requests.
    echo_id: u16,
    readiness: Arc<Readiness>,
}

static SOCKS: IrqSafeSpinLock<BTreeMap<u32, Arc<IrqSafeSpinLock<Sock>>>> =
    IrqSafeSpinLock::new(BTreeMap::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Open a new ICMPv6 socket. Returns its id.
pub fn open(echo_id: u16) -> u32 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let s = Sock {
        filter: [0u32; 8],
        queue: VecDeque::new(),
        echo_id,
        readiness: Arc::new(Readiness::new(crate::raw_sock::POLL_OUT)),
    };
    SOCKS.lock().insert(id, Arc::new(IrqSafeSpinLock::new(s)));
    id
}

/// Close a socket; drop its queue.
pub fn close(id: u32) -> bool {
    SOCKS.lock().remove(&id).is_some()
}

/// Query the durable readiness handle for a raw ICMPv6 socket.
pub fn readiness(id: u32) -> Option<Arc<Readiness>> {
    let arc = SOCKS.lock().get(&id).cloned()?;
    let r = arc.lock().readiness.clone();
    Some(r)
}

/// Set the raw 256-bit filter (`struct icmp6_filter`, 0 = pass, 1 = block).
pub fn set_filter_raw(id: u32, filter: [u32; 8]) -> bool {
    let arc = match SOCKS.lock().get(&id).cloned() {
        Some(a) => a,
        None => return false,
    };
    arc.lock().filter = filter;
    true
}

/// Get the raw 256-bit filter (`struct icmp6_filter`, 0 = pass, 1 = block).
pub fn get_filter_raw(id: u32) -> Option<[u32; 8]> {
    let arc = SOCKS.lock().get(&id).cloned()?;
    let f = arc.lock().filter;
    Some(f)
}

/// Replace the type filter with an allow-list of types.
/// `types = &[]` means "allow nothing"; a type appears in `types` iff it
/// should be passed (clears the block bit).
pub fn set_filter(id: u32, types: &[u8]) -> bool {
    let arc = match SOCKS.lock().get(&id).cloned() {
        Some(a) => a,
        None => return false,
    };
    let mut mask = [!0u32; 8];
    for &t in types {
        mask[(t / 32) as usize] &= !(1u32 << (t % 32));
    }
    arc.lock().filter = mask;
    true
}

/// Deliver an inbound ICMPv6 message to whichever socket matches.
/// Called from `ipv6_stack::handle_icmp6`.
pub fn on_rx(src_ip: [u8; 16], dst_ip: [u8; 16], typ: u8, code: u8, body: &[u8]) {
    let socks: Vec<Arc<IrqSafeSpinLock<Sock>>> = SOCKS.lock().values().cloned().collect();
    let msg = Icmp6Msg {
        src_ip,
        dst_ip,
        typ,
        code,
        body: body.to_vec(),
    };
    for arc in &socks {
        let mut g = arc.lock();
        let w = (typ / 32) as usize;
        let b = 1u32 << (typ % 32);
        let blocked = (g.filter[w] & b) != 0;
        if blocked {
            continue;
        }
        // Echo Reply matching: if the socket has an echo_id, only
        // deliver Echo Replies whose icmp6.id matches.
        if g.echo_id != 0 && typ == ICMPV6_ECHO_REPLY && body.len() >= 8 {
            let id = u16::from_be_bytes([body[4], body[5]]);
            if id != g.echo_id {
                continue;
            }
        }
        // Cap the queue to 64 messages; oldest drops.
        if g.queue.len() >= 64 {
            g.queue.pop_front();
        }
        g.queue.push_back(msg.clone());
        g.readiness.set(crate::raw_sock::POLL_IN, 0);
        g.readiness.notify(crate::raw_sock::POLL_IN);
    }
}

/// Take the next inbound message. Returns `None` if the queue is empty.
pub fn next_msg(id: u32) -> Option<Icmp6Msg> {
    let arc = SOCKS.lock().get(&id).cloned()?;
    let mut g = arc.lock();
    let m = g.queue.pop_front()?;
    if g.queue.is_empty() {
        g.readiness.set(0, crate::raw_sock::POLL_IN);
    }
    Some(m)
}

/// Check whether the socket has any inbound message pending.
pub fn has_msg(id: u32) -> bool {
    let arc = match SOCKS.lock().get(&id).cloned() {
        Some(a) => a,
        None => return false,
    };
    let empty = arc.lock().queue.is_empty();
    !empty
}

/// Peek the length of the next inbound message body.
pub fn next_msg_len(id: u32) -> Option<usize> {
    let arc = SOCKS.lock().get(&id).cloned()?;
    let len = arc.lock().queue.front().map(|m| m.body.len());
    len
}

/// Build an ICMPv6 Echo Request body (header + id + sequence + payload).
/// The IPv6 pseudo-header checksum is filled by the caller via
/// `pkt_ipv6::pseudo_checksum`.
pub fn build_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    let hdr = Icmpv6Header {
        typ: ICMPV6_ECHO_REQUEST,
        code: 0,
        checksum: 0,
    };
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build an ICMPv6 Echo Reply body.
pub fn build_echo_reply(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    let hdr = Icmpv6Header {
        typ: ICMPV6_ECHO_REPLY,
        code: 0,
        checksum: 0,
    };
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[doc(hidden)]
pub fn __reset_for_test() {
    SOCKS.lock().clear();
}
