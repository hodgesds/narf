//! Source NAT (masquerading) — single-IP NAT against the iface's
//! current address. Egress (POST_ROUTING) rewrites
//! `(src_ip, src_port) → (nat_src_ip, nat_src_port)`; ingress
//! (PRE_ROUTING) restores the original when a reply matches.
//!
//! Linux ref: `net/netfilter/nf_nat_core.c:get_unique_tuple()` and
//! `net/netfilter/nf_nat_masquerade.c`.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::{
    conntrack, HookPoint, L4Proto, PktCtx, Tuple, Verdict,
    parse_tuple_ipv4, IPV4_MIN_HDR_LEN, IPV4_OFF_DST, IPV4_OFF_SRC,
    L4_OFF_DPORT, L4_OFF_SPORT,
};

/// First port in the NAT ephemeral range — matches Linux's default
/// `net.ipv4.ip_local_port_range` lower bound.
pub const NAT_PORT_RANGE_LO: u16 = 32768;
pub const NAT_PORT_RANGE_HI: u16 = 60999;

/// One masquerade rule. Stage-3: a single-source-CIDR rule per iface.
#[derive(Clone, Debug)]
pub struct MasqRule {
    pub iface: String,
    /// CIDR — first 4 bytes are the network address, last byte is the
    /// prefix length (0–32). Mask is derived.
    pub net: [u8; 4],
    pub prefix: u8,
    /// Iface IP — the address packets get rewritten to on egress.
    pub iface_ip: [u8; 4],
}

impl MasqRule {
    /// True if `addr` falls within `self.net / self.prefix`.
    pub fn matches(&self, addr: [u8; 4]) -> bool {
        let net_u32 = u32::from_be_bytes(self.net);
        let addr_u32 = u32::from_be_bytes(addr);
        let mask = if self.prefix == 0 {
            0u32
        } else {
            (!0u32) << (32 - self.prefix)
        };
        (net_u32 & mask) == (addr_u32 & mask)
    }
}

/// NAT mapping table. Keys are `(iface_ip, nat_port, proto)`; values
/// are `(orig_src_ip, orig_src_port)`. On ingress with dst matching a
/// key, restore the original.
#[derive(Debug)]
pub struct Nat {
    rules: IrqSafeSpinLock<Vec<MasqRule>>,
    /// `(nat_src_ip, nat_src_port, proto) → (orig_src_ip, orig_src_port)`.
    egress_map: IrqSafeSpinLock<BTreeMap<([u8; 4], u16, u8), ([u8; 4], u16)>>,
    /// Conntrack id → allocated `(nat_src_ip, nat_src_port)` so the
    /// same flow always rewrites consistently.
    by_ct: IrqSafeSpinLock<BTreeMap<u64, ([u8; 4], u16)>>,
    /// Next port to try when allocating.
    next_port: AtomicU16,
}

impl Nat {
    pub const fn new() -> Self {
        Self {
            rules: IrqSafeSpinLock::new(Vec::new()),
            egress_map: IrqSafeSpinLock::new(BTreeMap::new()),
            by_ct: IrqSafeSpinLock::new(BTreeMap::new()),
            next_port: AtomicU16::new(NAT_PORT_RANGE_LO),
        }
    }

    /// Install a masquerade rule.
    pub fn masquerade_add(&self, rule: MasqRule) {
        self.rules.lock().push(rule);
    }

    /// Remove a masquerade rule by iface name.
    pub fn masquerade_remove(&self, iface: &str) {
        self.rules.lock().retain(|r| r.iface != iface);
    }

    /// Find the rule for an outbound packet, if any.
    pub fn lookup_rule(&self, iface_out: &str, src_ip: [u8; 4]) -> Option<MasqRule> {
        let rules = self.rules.lock();
        rules.iter()
            .find(|r| r.iface == iface_out && r.matches(src_ip))
            .cloned()
    }

    /// Allocate a NAT port. Walks `(iface_ip, port, proto)` from the
    /// next-port cursor; the first slot that isn't currently mapped
    /// wins. Returns `None` if every port in the range is in use
    /// (catastrophic — port pressure).
    fn allocate_port(
        &self,
        iface_ip: [u8; 4],
        proto: u8,
        original_port: u16,
    ) -> Option<u16> {
        let map = self.egress_map.lock();
        // First, try `original_port` itself (preserve when possible).
        if !map.contains_key(&(iface_ip, original_port, proto)) {
            return Some(original_port);
        }
        drop(map);
        let span = (NAT_PORT_RANGE_HI - NAT_PORT_RANGE_LO + 1) as u32;
        let start = self.next_port.load(Ordering::Acquire);
        for i in 0..span {
            let p = NAT_PORT_RANGE_LO
                + ((start as u32 - NAT_PORT_RANGE_LO as u32 + i) % span) as u16;
            let map = self.egress_map.lock();
            if !map.contains_key(&(iface_ip, p, proto)) {
                drop(map);
                self.next_port.store(p.wrapping_add(1), Ordering::Release);
                return Some(p);
            }
        }
        None
    }

    /// Install an egress mapping.
    fn insert_mapping(
        &self,
        ct_id: u64,
        iface_ip: [u8; 4],
        nat_port: u16,
        orig_src: [u8; 4],
        orig_port: u16,
        proto: u8,
    ) {
        self.egress_map.lock().insert(
            (iface_ip, nat_port, proto),
            (orig_src, orig_port),
        );
        self.by_ct.lock().insert(ct_id, (iface_ip, nat_port));
    }

    /// Look up the NAT mapping for an outbound conntrack id.
    pub fn lookup_ct(&self, ct_id: u64) -> Option<([u8; 4], u16)> {
        self.by_ct.lock().get(&ct_id).copied()
    }

    /// Reverse lookup an ingress packet: `(dst_ip, dst_port, proto)`
    /// matching → original `(orig_src_ip, orig_src_port)`.
    pub fn lookup_ingress(
        &self,
        dst_ip: [u8; 4],
        dst_port: u16,
        proto: u8,
    ) -> Option<([u8; 4], u16)> {
        self.egress_map.lock().get(&(dst_ip, dst_port, proto)).copied()
    }

    /// Wipe NAT state. Test-only.
    #[doc(hidden)]
    pub fn __reset_for_test(&self) {
        self.rules.lock().clear();
        self.egress_map.lock().clear();
        self.by_ct.lock().clear();
        self.next_port.store(NAT_PORT_RANGE_LO, Ordering::Relaxed);
    }

    /// Snapshot all rules (smoke instrumentation).
    pub fn rules_snapshot(&self) -> Vec<MasqRule> {
        self.rules.lock().clone()
    }
}

/// Global NAT state.
static NAT: Nat = Nat::new();

/// Reference the global NAT.
#[inline]
pub fn nat() -> &'static Nat {
    &NAT
}

/// Public masquerade-add helper.
pub fn nat_masquerade_add(iface: &str, net: [u8; 4], prefix: u8, iface_ip: [u8; 4]) {
    NAT.masquerade_add(MasqRule {
        iface: iface.to_string(),
        net,
        prefix,
        iface_ip,
    });
}

/// Public masquerade-remove helper.
pub fn nat_masquerade_remove(iface: &str) {
    NAT.masquerade_remove(iface);
}

#[doc(hidden)]
pub fn __reset_for_test() {
    NAT.__reset_for_test();
}

// ── Checksum maths ─────────────────────────────────────────────────
//
// RFC 1624 incremental checksum: HC' = ~(~HC + ~m + m'), where HC is
// the original checksum, m the old 16-bit field, m' the new. Plain
// recompute is also fine for short payloads; we do incremental to keep
// the rewrite O(1).

fn csum_incremental(old_csum: u16, old_word: u16, new_word: u16) -> u16 {
    let hc = !old_csum as u32;
    let m  = !old_word as u32;
    let mp = new_word as u32;
    let sum = hc + m + mp;
    let mut folded = (sum & 0xFFFF) + (sum >> 16);
    folded = (folded & 0xFFFF) + (folded >> 16);
    !(folded as u16)
}

/// Update IP src/dst + L4 checksums after rewriting `src_ip`.
fn rewrite_src_ip(packet: &mut [u8], new_src: [u8; 4]) {
    let old = [packet[IPV4_OFF_SRC], packet[IPV4_OFF_SRC + 1],
               packet[IPV4_OFF_SRC + 2], packet[IPV4_OFF_SRC + 3]];
    packet[IPV4_OFF_SRC..IPV4_OFF_SRC + 4].copy_from_slice(&new_src);

    // IP header checksum (offset 10–11). Update in-place — two
    // 16-bit words swapped.
    let ip_csum = u16::from_be_bytes([packet[10], packet[11]]);
    let mut new_csum = csum_incremental(
        ip_csum,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new_src[0], new_src[1]]),
    );
    new_csum = csum_incremental(
        new_csum,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new_src[2], new_src[3]]),
    );
    packet[10..12].copy_from_slice(&new_csum.to_be_bytes());

    // L4 checksum incremental update — TCP at offset 16, UDP at offset 6
    // within the L4 header.
    let proto = packet[9];
    let l4 = &mut packet[IPV4_MIN_HDR_LEN..];
    let (csum_off, applies) = match L4Proto::from_u8(proto) {
        L4Proto::Tcp  => (16, l4.len() >= 18),
        L4Proto::Udp  => (6, l4.len() >= 8),
        _ => (0, false),
    };
    if applies {
        let cur = u16::from_be_bytes([l4[csum_off], l4[csum_off + 1]]);
        // UDP csum=0 means "no checksum" — leave it.
        if cur != 0 || proto == 6 {
            let mut new_l4 = csum_incremental(
                cur,
                u16::from_be_bytes([old[0], old[1]]),
                u16::from_be_bytes([new_src[0], new_src[1]]),
            );
            new_l4 = csum_incremental(
                new_l4,
                u16::from_be_bytes([old[2], old[3]]),
                u16::from_be_bytes([new_src[2], new_src[3]]),
            );
            l4[csum_off..csum_off + 2].copy_from_slice(&new_l4.to_be_bytes());
        }
    }
}

/// Update IP dst + L4 checksums after rewriting `dst_ip`.
fn rewrite_dst_ip(packet: &mut [u8], new_dst: [u8; 4]) {
    let old = [packet[IPV4_OFF_DST], packet[IPV4_OFF_DST + 1],
               packet[IPV4_OFF_DST + 2], packet[IPV4_OFF_DST + 3]];
    packet[IPV4_OFF_DST..IPV4_OFF_DST + 4].copy_from_slice(&new_dst);

    let ip_csum = u16::from_be_bytes([packet[10], packet[11]]);
    let mut new_csum = csum_incremental(
        ip_csum,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new_dst[0], new_dst[1]]),
    );
    new_csum = csum_incremental(
        new_csum,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new_dst[2], new_dst[3]]),
    );
    packet[10..12].copy_from_slice(&new_csum.to_be_bytes());

    let proto = packet[9];
    let l4 = &mut packet[IPV4_MIN_HDR_LEN..];
    let (csum_off, applies) = match L4Proto::from_u8(proto) {
        L4Proto::Tcp  => (16, l4.len() >= 18),
        L4Proto::Udp  => (6, l4.len() >= 8),
        _ => (0, false),
    };
    if applies {
        let cur = u16::from_be_bytes([l4[csum_off], l4[csum_off + 1]]);
        if cur != 0 || proto == 6 {
            let mut new_l4 = csum_incremental(
                cur,
                u16::from_be_bytes([old[0], old[1]]),
                u16::from_be_bytes([new_dst[0], new_dst[1]]),
            );
            new_l4 = csum_incremental(
                new_l4,
                u16::from_be_bytes([old[2], old[3]]),
                u16::from_be_bytes([new_dst[2], new_dst[3]]),
            );
            l4[csum_off..csum_off + 2].copy_from_slice(&new_l4.to_be_bytes());
        }
    }
}

/// Update L4 src port + L4 checksum after rewriting `src_port`.
fn rewrite_src_port(packet: &mut [u8], new_port: u16) {
    let proto = packet[9];
    let l4 = &mut packet[IPV4_MIN_HDR_LEN..];
    if l4.len() < 4 { return; }
    let old = u16::from_be_bytes([l4[L4_OFF_SPORT], l4[L4_OFF_SPORT + 1]]);
    l4[L4_OFF_SPORT..L4_OFF_SPORT + 2].copy_from_slice(&new_port.to_be_bytes());
    let (csum_off, applies) = match L4Proto::from_u8(proto) {
        L4Proto::Tcp  => (16, l4.len() >= 18),
        L4Proto::Udp  => (6, l4.len() >= 8),
        _ => (0, false),
    };
    if applies {
        let cur = u16::from_be_bytes([l4[csum_off], l4[csum_off + 1]]);
        if cur != 0 || proto == 6 {
            let new_l4 = csum_incremental(cur, old, new_port);
            l4[csum_off..csum_off + 2].copy_from_slice(&new_l4.to_be_bytes());
        }
    }
}

/// Update L4 dst port + L4 checksum after rewriting `dst_port`.
fn rewrite_dst_port(packet: &mut [u8], new_port: u16) {
    let proto = packet[9];
    let l4 = &mut packet[IPV4_MIN_HDR_LEN..];
    if l4.len() < 4 { return; }
    let old = u16::from_be_bytes([l4[L4_OFF_DPORT], l4[L4_OFF_DPORT + 1]]);
    l4[L4_OFF_DPORT..L4_OFF_DPORT + 2].copy_from_slice(&new_port.to_be_bytes());
    let (csum_off, applies) = match L4Proto::from_u8(proto) {
        L4Proto::Tcp  => (16, l4.len() >= 18),
        L4Proto::Udp  => (6, l4.len() >= 8),
        _ => (0, false),
    };
    if applies {
        let cur = u16::from_be_bytes([l4[csum_off], l4[csum_off + 1]]);
        if cur != 0 || proto == 6 {
            let new_l4 = csum_incremental(cur, old, new_port);
            l4[csum_off..csum_off + 2].copy_from_slice(&new_l4.to_be_bytes());
        }
    }
}

// ── Hooks ───────────────────────────────────────────────────────────

/// POST_ROUTING hook: source-NAT outgoing flows matching a masquerade
/// rule. Allocates a NAT port if this is the first packet of the flow,
/// rewrites `(src_ip, src_port)`, records the mapping, and updates the
/// conntrack reply tuple so PRE_ROUTING can find the flow on the way
/// back.
pub fn snat_postrouting(ctx: &mut PktCtx<'_>) -> Verdict {
    let tuple = match parse_tuple_ipv4(ctx.packet) {
        Some(t) => t,
        None => return Verdict::Accept,
    };
    let rule = match NAT.lookup_rule(ctx.iface_out, tuple.src_ip) {
        Some(r) => r,
        None => return Verdict::Accept,
    };
    // Find / create conntrack entry.
    let ct = conntrack::ct();
    let now = narf_scheduler::narf_time::monotonic_ns();
    let entry = ct.lookup(&tuple).unwrap_or_else(|| ct.insert_new(tuple, now));
    let id = entry.lock().id;
    ctx.conntrack_id = Some(id);

    // Already NAT'd? Reuse mapping.
    if let Some((nat_ip, nat_port)) = NAT.lookup_ct(id) {
        rewrite_src_ip(ctx.packet, nat_ip);
        rewrite_src_port(ctx.packet, nat_port);
        return Verdict::Accept;
    }

    // Allocate a NAT port for this flow.
    let nat_port = match NAT.allocate_port(rule.iface_ip, tuple.proto, tuple.src_port) {
        Some(p) => p,
        None => return Verdict::Drop, // port pressure
    };
    NAT.insert_mapping(id, rule.iface_ip, nat_port, tuple.src_ip, tuple.src_port, tuple.proto);

    // Update conntrack's reply tuple so the ingress lookup finds this flow.
    let new_reply = Tuple {
        src_ip: tuple.dst_ip,
        dst_ip: rule.iface_ip,
        src_port: tuple.dst_port,
        dst_port: nat_port,
        proto: tuple.proto,
    };
    {
        let old_reply = entry.lock().reply;
        entry.lock().set_nat_reply(new_reply);
        ct.update_reply_tuple(id, old_reply, new_reply);
    }

    // Rewrite the packet in place.
    rewrite_src_ip(ctx.packet, rule.iface_ip);
    rewrite_src_port(ctx.packet, nat_port);
    Verdict::Accept
}

/// PRE_ROUTING hook: reverse-NAT ingress traffic whose dst matches a
/// recorded egress mapping. Rewrites
/// `(dst_ip, dst_port) → (orig_src_ip, orig_src_port)`.
pub fn dnat_prerouting(ctx: &mut PktCtx<'_>) -> Verdict {
    let tuple = match parse_tuple_ipv4(ctx.packet) {
        Some(t) => t,
        None => return Verdict::Accept,
    };
    if let Some((orig_ip, orig_port)) = NAT.lookup_ingress(tuple.dst_ip, tuple.dst_port, tuple.proto) {
        rewrite_dst_ip(ctx.packet, orig_ip);
        rewrite_dst_port(ctx.packet, orig_port);
    }
    Verdict::Accept
}

/// Register NAT hooks: PRE_ROUTING (reverse) at priority +100,
/// POST_ROUTING (forward) at priority +100 — after conntrack
/// (`-200`) but before final delivery. Matches `NF_IP_PRI_NAT_DST` /
/// `NF_IP_PRI_NAT_SRC` in Linux
/// `include/uapi/linux/netfilter_ipv4.h:54-55`.
pub fn register_default_hooks() {
    super::nf_register_hook(HookPoint::PreRouting,  100, dnat_prerouting);
    super::nf_register_hook(HookPoint::PostRouting, 100, snat_postrouting);
}
