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
    /// `None` → accept every type. `Some(mask)` → 256-bit type filter
    /// where bit `t` set means "deliver type t" (RFC 3542 §3.2 sentinel).
    type_filter: Option<[u32; 8]>,
    queue: VecDeque<Icmp6Msg>,
    /// Echo session id used to match Echo Replies to Echo Requests.
    echo_id: u16,
}

static SOCKS: IrqSafeSpinLock<BTreeMap<u32, Arc<IrqSafeSpinLock<Sock>>>> =
    IrqSafeSpinLock::new(BTreeMap::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// Open a new ICMPv6 socket. Returns its id.
pub fn open(echo_id: u16) -> u32 {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let s = Sock {
        type_filter: None,
        queue: VecDeque::new(),
        echo_id,
    };
    SOCKS.lock().insert(id, Arc::new(IrqSafeSpinLock::new(s)));
    id
}

/// Close a socket; drop its queue.
pub fn close(id: u32) -> bool {
    SOCKS.lock().remove(&id).is_some()
}

/// Replace the type filter. `types = &[]` means "allow nothing"; a
/// type appears in `types` iff it should be delivered.
pub fn set_filter(id: u32, types: &[u8]) -> bool {
    let arc = match SOCKS.lock().get(&id).cloned() {
        Some(a) => a,
        None => return false,
    };
    let mut mask = [0u32; 8];
    for &t in types {
        mask[(t / 32) as usize] |= 1u32 << (t % 32);
    }
    arc.lock().type_filter = Some(mask);
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
        let pass = match g.type_filter {
            None => true,
            Some(mask) => {
                let w = (typ / 32) as usize;
                let b = 1u32 << (typ % 32);
                (mask[w] & b) != 0
            }
        };
        // Echo Reply matching: if the socket has an echo_id, only
        // deliver Echo Replies whose icmp6.id matches.
        if pass && typ == ICMPV6_ECHO_REPLY && body.len() >= 8 {
            let id = u16::from_be_bytes([body[4], body[5]]);
            if id != g.echo_id {
                continue;
            }
        }
        if pass {
            // Cap the queue to 16 messages; oldest drops.
            if g.queue.len() >= 16 {
                g.queue.pop_front();
            }
            g.queue.push_back(msg.clone());
        }
    }
}

/// Take the next inbound message. Returns `None` if the queue is empty.
pub fn next_msg(id: u32) -> Option<Icmp6Msg> {
    let arc = SOCKS.lock().get(&id).cloned()?;
    let m = arc.lock().queue.pop_front();
    m
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
