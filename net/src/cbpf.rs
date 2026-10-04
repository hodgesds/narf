//! Classic BPF (`struct sock_filter`) socket filters: the attach-time
//! checker and the run-time interpreter.
//!
//! Linux references (GPL-2.0, the authority for every rule below):
//! - `net/core/filter.c` — `bpf_check_classic`, `chk_code_allowed`,
//!   `check_load_and_stores` (attach checks) and `bpf_convert_filter` /
//!   `convert_bpf_ld_abs` / `convert_bpf_extensions` (run-time semantics: a
//!   classic program is translated to eBPF and run by `__bpf_prog_run`).
//! - `include/uapi/linux/filter.h` — opcode encoding, `SKF_*` offsets.
//! - `kernel/bpf/core.c` — 32-bit ALU semantics (`(u32) DST OP ((u32) SRC
//!   & 31)` for shifts).
//!
//! The interpreter runs on a [`SkbView`]: the linear frame bytes plus the
//! `sk_buff` fields the classic ancillary loads read. A filter's return value
//! is the number of bytes to keep (0 = drop), exactly as `run_filter` in
//! `net/packet/af_packet.c` consumes it.

extern crate alloc;

use alloc::vec::Vec;

/// `BPF_MAXINSNS`.
pub const BPF_MAXINSNS: usize = 4096;
/// `BPF_MEMWORDS`: scratch memory slots `M[0..16)`.
pub const BPF_MEMWORDS: usize = 16;

/// `SKF_AD_OFF`: base of the ancillary-data pseudo offsets.
pub const SKF_AD_OFF: u32 = 0xffff_f000; // -0x1000
/// `SKF_NET_OFF`: offsets relative to the network header.
pub const SKF_NET_OFF: i32 = -0x10_0000;
/// `SKF_LL_OFF`: offsets relative to the link-layer (MAC) header.
pub const SKF_LL_OFF: i32 = -0x20_0000;

pub const SKF_AD_PROTOCOL: u32 = 0;
pub const SKF_AD_PKTTYPE: u32 = 4;
pub const SKF_AD_IFINDEX: u32 = 8;
pub const SKF_AD_NLATTR: u32 = 12;
pub const SKF_AD_NLATTR_NEST: u32 = 16;
pub const SKF_AD_MARK: u32 = 20;
pub const SKF_AD_QUEUE: u32 = 24;
pub const SKF_AD_HATYPE: u32 = 28;
pub const SKF_AD_RXHASH: u32 = 32;
pub const SKF_AD_CPU: u32 = 36;
pub const SKF_AD_ALU_XOR_X: u32 = 40;
pub const SKF_AD_VLAN_TAG: u32 = 44;
pub const SKF_AD_VLAN_TAG_PRESENT: u32 = 48;
pub const SKF_AD_PAY_OFFSET: u32 = 52;
pub const SKF_AD_RANDOM: u32 = 56;
pub const SKF_AD_VLAN_TPID: u32 = 60;
/// `SKF_AD_MAX`.
pub const SKF_AD_MAX: u32 = 64;

/// One `struct sock_filter` instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// A checked classic program, ready to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    insns: Vec<SockFilter>,
}

impl Program {
    /// Decode and check a native `struct sock_filter[]` image (8 bytes per
    /// instruction, host byte order). `None` is Linux's `-EINVAL` from
    /// `bpf_check_basics` / `bpf_check_classic`.
    #[must_use]
    pub fn from_bytes(image: &[u8]) -> Option<Self> {
        if image.is_empty() || image.len() % 8 != 0 {
            return None;
        }
        let insns: Vec<SockFilter> = image
            .chunks_exact(8)
            .map(|c| SockFilter {
                code: u16::from_ne_bytes([c[0], c[1]]),
                jt: c[2],
                jf: c[3],
                k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect();
        if !check_classic(&insns) {
            return None;
        }
        Some(Self { insns })
    }

    /// The program's instructions.
    #[must_use]
    pub fn insns(&self) -> &[SockFilter] {
        &self.insns
    }
}

/// `chk_code_allowed`: the opcodes a classic program may contain. Unused
/// size/mode/source bits are not accepted merely because the class is.
fn code_allowed(code: u16) -> bool {
    matches!(
        code,
        // ALU K/X, plus NEG.
        0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0x44 | 0x4c | 0x54 | 0x5c
            | 0x64 | 0x6c | 0x74 | 0x7c | 0x84 | 0x94 | 0x9c | 0xa4 | 0xac
            // LD / LDX.
            | 0x20 | 0x28 | 0x30 | 0x80 | 0x40 | 0x48 | 0x50 | 0x00 | 0x60 | 0x81 | 0xb1
            | 0x01 | 0x61
            // ST / STX, RET, MISC.
            | 0x02 | 0x03 | 0x06 | 0x16 | 0x07 | 0x87
            // JMP K/X and JA.
            | 0x05 | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d
    )
}

/// `bpf_check_classic` + `check_load_and_stores` over decoded instructions.
#[must_use]
pub fn check_classic(insns: &[SockFilter]) -> bool {
    let count = insns.len();
    if count == 0 || count > BPF_MAXINSNS {
        return false;
    }
    // `check_load_and_stores`: each target accumulates the scratch slots
    // initialized on every path that can reach it.
    let mut masks = alloc::vec![u16::MAX; count];
    let mut mem_valid = 0u16;
    for (pc, insn) in insns.iter().enumerate() {
        mem_valid &= masks[pc];
        let code = insn.code;
        let k = insn.k;
        if !code_allowed(code) {
            return false;
        }
        match code {
            // Immediate division/modulo by zero and oversized immediate
            // shifts are rejected by `bpf_check_classic`.
            0x34 | 0x94 if k == 0 => return false,
            0x64 | 0x74 if k >= 32 => return false,
            // Scratch loads/stores stay within M[0..16); a load must be
            // initialized on every control-flow path that reaches it.
            0x60 | 0x61 if k >= BPF_MEMWORDS as u32 => return false,
            0x60 | 0x61 if mem_valid & (1u16 << k) == 0 => return false,
            0x02 | 0x03 if k >= BPF_MEMWORDS as u32 => return false,
            0x02 | 0x03 => mem_valid |= 1u16 << k,
            // BPF_JA: `k >= flen - 1 - pc` is out of range.
            0x05 => {
                let Some(target) = pc
                    .checked_add(1)
                    .and_then(|next| next.checked_add(k as usize))
                else {
                    return false;
                };
                if target >= count {
                    return false;
                }
                masks[target] &= mem_valid;
                mem_valid = u16::MAX;
            }
            // Conditional jumps.
            0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                let next = pc + 1;
                let true_target = next + usize::from(insn.jt);
                let false_target = next + usize::from(insn.jf);
                if true_target >= count || false_target >= count {
                    return false;
                }
                masks[true_target] &= mem_valid;
                masks[false_target] &= mem_valid;
                mem_valid = u16::MAX;
            }
            // Only the enumerated ancillary offsets are accepted for absolute
            // packet loads (`bpf_anc_helper`; unknown `k >= SKF_AD_OFF` is
            // `-EINVAL`).
            0x20 | 0x28 | 0x30 if k >= SKF_AD_OFF => {
                let ancillary = k.wrapping_sub(SKF_AD_OFF);
                if ancillary >= SKF_AD_MAX || ancillary % 4 != 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    matches!(insns[count - 1].code, 0x06 | 0x16)
}

/// The `sk_buff` a classic filter observes.
///
/// `frame` holds the whole linear packet from its link-layer header;
/// `data_off` is where `skb->data` points into it (the MAC header for
/// `SOCK_RAW`, the network header for `SOCK_DGRAM` receivers) and `len` is
/// `skb->len` measured from there.
#[derive(Clone, Copy, Debug)]
pub struct SkbView<'a> {
    pub frame: &'a [u8],
    pub data_off: usize,
    pub len: usize,
    /// Offset of the MAC header within `frame` (`skb_mac_header`).
    pub mac_off: usize,
    /// Offset of the network header within `frame` (`skb_network_header`).
    pub net_off: usize,
    /// `skb->protocol`, host byte order.
    pub protocol: u16,
    /// `skb->pkt_type`.
    pub pkt_type: u8,
    /// `skb->dev->ifindex`.
    pub ifindex: u32,
    /// `skb->dev->type` (`ARPHRD_*`).
    pub hatype: u16,
    /// `skb->vlan_tci` / `skb->vlan_proto` when a tag is present.
    pub vlan: Option<(u16, u16)>,
}

impl SkbView<'_> {
    /// `bpf_skb_load_helper_convert_offset` followed by the linear-buffer
    /// bounds test (`headlen - offset >= size`). `None` is the helper's
    /// `-EFAULT`, which ends the program with return value 0.
    fn load(&self, offset: i32, size: usize) -> Option<u32> {
        let mac_offset = self.mac_off as i64 - self.data_off as i64;
        let net_offset = self.net_off as i64 - self.data_off as i64;
        let off: i64 = if offset >= 0 {
            i64::from(offset)
        } else if offset >= SKF_NET_OFF {
            i64::from(offset) - i64::from(SKF_NET_OFF) + net_offset
        } else if offset >= SKF_LL_OFF {
            i64::from(offset) - i64::from(SKF_LL_OFF) + mac_offset
        } else {
            return None;
        };
        if self.len as i64 - off < size as i64 {
            return None;
        }
        let start = self.data_off as i64 + off;
        if start < 0 {
            return None;
        }
        let start = start as usize;
        let bytes = self.frame.get(start..start + size)?;
        Some(match size {
            1 => u32::from(bytes[0]),
            2 => u32::from(u16::from_be_bytes([bytes[0], bytes[1]])),
            _ => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        })
    }

    /// The linear `skb->data .. skb->data + skb->len` window.
    fn data(&self) -> &[u8] {
        let end = (self.data_off + self.len).min(self.frame.len());
        &self.frame[self.data_off.min(end)..end]
    }
}

/// `nla_ok`: a whole attribute header and body fit in `rem`.
fn nla_ok(buf: &[u8], at: usize, rem: usize) -> Option<usize> {
    if rem < 4 {
        return None;
    }
    let len = usize::from(u16::from_ne_bytes([*buf.get(at)?, *buf.get(at + 1)?]));
    if len < 4 || len > rem {
        return None;
    }
    Some(len)
}

/// `nla_find(head, len, attrtype)` over `buf[at..at + len]`; returns the
/// attribute's offset in `buf`. `nla_type` masks NLA_F_NESTED and
/// NLA_F_NET_BYTEORDER.
fn nla_find(buf: &[u8], mut at: usize, mut rem: usize, attrtype: u32) -> Option<usize> {
    const NLA_TYPE_MASK: u16 = !((1 << 15) | (1 << 14));
    while let Some(len) = nla_ok(buf, at, rem) {
        let ty = u16::from_ne_bytes([buf[at + 2], buf[at + 3]]) & NLA_TYPE_MASK;
        // `nla_find` takes `int attrtype`.
        if u32::from(ty) == attrtype {
            return Some(at);
        }
        let aligned = (len + 3) & !3;
        if aligned > rem {
            return None;
        }
        at += aligned;
        rem -= aligned;
    }
    None
}

/// `bpf_skb_get_nlattr`.
fn get_nlattr(skb: &SkbView<'_>, a: u32, x: u32) -> u32 {
    let data = skb.data();
    let len = data.len();
    if len < 4 || a as usize > len - 4 {
        return 0;
    }
    nla_find(data, a as usize, len - a as usize, x).map_or(0, |off| off as u32)
}

/// `bpf_skb_get_nlattr_nest`.
fn get_nlattr_nest(skb: &SkbView<'_>, a: u32, x: u32) -> u32 {
    let data = skb.data();
    let len = data.len();
    if len < 4 || a as usize > len - 4 {
        return 0;
    }
    let a = a as usize;
    let Some(nla_len) = nla_ok(data, a, len - a) else {
        return 0;
    };
    // `nla_find_nested`: search the nested payload.
    nla_find(data, a + 4, nla_len - 4, x).map_or(0, |off| off as u32)
}

/// `skb_get_poff`: the transport payload offset relative to `skb->data`,
/// via `skb_flow_dissect_flow_keys_basic` + `__skb_get_poff`.
///
/// LINUX-GAP: Linux's flow dissector understands every encapsulation it
/// registers (MPLS, GRE, PPPoE, TIPC, batman-adv, FCoE, ARP, …). This walk
/// covers Ethernet-framed IPv4 and IPv6 (with hop-by-hop / routing /
/// destination / fragment extension headers) and the L4 header sizes
/// `__skb_get_poff` adds; any other network protocol is reported as a
/// dissection failure (0), as Linux does for a protocol it cannot dissect.
fn pay_offset(skb: &SkbView<'_>) -> u32 {
    const IPPROTO_HOPOPTS: u8 = 0;
    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_IGMP: u8 = 2;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const IPPROTO_DCCP: u8 = 33;
    const IPPROTO_ROUTING: u8 = 43;
    const IPPROTO_FRAGMENT: u8 = 44;
    const IPPROTO_ICMPV6: u8 = 58;
    const IPPROTO_DSTOPTS: u8 = 60;
    const IPPROTO_SCTP: u8 = 132;
    const IPPROTO_UDPLITE: u8 = 136;
    let net = skb.net_off as i64 - skb.data_off as i64;
    let data = skb.data();
    let byte = |off: i64| -> Option<u8> {
        if off < 0 {
            return None;
        }
        data.get(off as usize).copied()
    };
    let (thoff, ip_proto, later_fragment) = match skb.protocol {
        0x0800 => {
            let Some(vihl) = byte(net) else { return 0 };
            let ihl = i64::from(vihl & 0x0f) * 4;
            if ihl < 20 || byte(net + ihl - 1).is_none() {
                return 0;
            }
            let (Some(f0), Some(f1), Some(proto)) = (byte(net + 6), byte(net + 7), byte(net + 9))
            else {
                return 0;
            };
            let frag = u16::from_be_bytes([f0, f1]);
            // IP_MF | IP_OFFSET: a fragment; offset != 0: not the first.
            let later = frag & 0x1fff != 0;
            (net + ihl, proto, later)
        }
        0x86dd => {
            let Some(mut next) = byte(net + 6) else {
                return 0;
            };
            if byte(net + 39).is_none() {
                return 0;
            }
            let mut off = net + 40;
            let mut later = false;
            loop {
                match next {
                    IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                        let (Some(nh), Some(len)) = (byte(off), byte(off + 1)) else {
                            return 0;
                        };
                        next = nh;
                        off += (i64::from(len) + 1) * 8;
                    }
                    IPPROTO_FRAGMENT => {
                        let (Some(nh), Some(f0), Some(f1)) =
                            (byte(off), byte(off + 2), byte(off + 3))
                        else {
                            return 0;
                        };
                        // The dissector stops at a fragment header.
                        next = nh;
                        later = u16::from_be_bytes([f0, f1]) & 0xfff8 != 0;
                        off += 8;
                        break;
                    }
                    _ => break,
                }
            }
            (off, next, later)
        }
        _ => return 0,
    };
    // `key_control->thoff = min(nhoff, skb->len)`.
    let thoff = thoff.min(skb.len as i64);
    let mut poff = thoff;
    if !later_fragment {
        poff += match ip_proto {
            IPPROTO_TCP => match byte(thoff + 12) {
                Some(doff) => core::cmp::max(20, i64::from((doff & 0xf0) >> 2)),
                None => 0,
            },
            // udphdr, icmphdr, icmp6hdr, igmphdr: 8 bytes each.
            IPPROTO_UDP | IPPROTO_UDPLITE | IPPROTO_ICMP | IPPROTO_ICMPV6 | IPPROTO_IGMP => 8,
            // dccp_hdr, sctphdr: 12 bytes each.
            IPPROTO_DCCP | IPPROTO_SCTP => 12,
            _ => 0,
        };
    }
    poff.max(0) as u32
}

/// `prandom_u32` state for `SKF_AD_RANDOM`.
static RANDOM_STATE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x9e37_79b9_7f4a_7c15);

fn random_u32() -> u32 {
    use core::sync::atomic::Ordering;
    let mut x = RANDOM_STATE.load(Ordering::Relaxed);
    if x == 0x9e37_79b9_7f4a_7c15 {
        x ^= narf_scheduler::narf_time::monotonic_ns();
    }
    // xorshift64*.
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    RANDOM_STATE.store(x, Ordering::Relaxed);
    (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
}

/// Run `prog` over `skb` (`bpf_prog_run` of the converted program). Returns
/// the filter's verdict: the number of bytes to accept, 0 to drop.
#[must_use]
pub fn run(prog: &Program, skb: &SkbView<'_>) -> u32 {
    let insns = prog.insns();
    let mut a: u32 = 0;
    let mut x: u32 = 0;
    let mut mem = [0u32; BPF_MEMWORDS];
    let mut pc = 0usize;
    // The checker guarantees every jump moves forward and the last
    // instruction returns, so the loop terminates.
    while let Some(insn) = insns.get(pc) {
        let k = insn.k;
        pc += 1;
        match insn.code {
            // ── LD ──
            0x00 => a = k,
            0x60 => a = mem[k as usize],
            0x80 => a = skb.len as u32,
            0x20 | 0x28 | 0x30 => {
                if k >= SKF_AD_OFF {
                    match k - SKF_AD_OFF {
                        SKF_AD_PROTOCOL => a = u32::from(skb.protocol),
                        SKF_AD_PKTTYPE => a = u32::from(skb.pkt_type & 7),
                        SKF_AD_IFINDEX => a = skb.ifindex,
                        SKF_AD_HATYPE => a = u32::from(skb.hatype),
                        // NARF sk_buffs carry no mark, queue mapping or
                        // flow hash: the fields read as Linux's zeroed
                        // defaults for an skb that never had them set.
                        SKF_AD_MARK | SKF_AD_QUEUE | SKF_AD_RXHASH => a = 0,
                        SKF_AD_VLAN_TAG => a = skb.vlan.map_or(0, |(tci, _)| u32::from(tci)),
                        SKF_AD_VLAN_TAG_PRESENT => a = u32::from(skb.vlan.is_some()),
                        SKF_AD_VLAN_TPID => a = skb.vlan.map_or(0, |(_, tpid)| u32::from(tpid)),
                        SKF_AD_NLATTR => a = get_nlattr(skb, a, x),
                        SKF_AD_NLATTR_NEST => a = get_nlattr_nest(skb, a, x),
                        SKF_AD_CPU => a = narf_lib::percpu::current_cpu() as u32,
                        SKF_AD_RANDOM => a = random_u32(),
                        SKF_AD_ALU_XOR_X => a ^= x,
                        SKF_AD_PAY_OFFSET => a = pay_offset(skb),
                        // Unreachable for a checked program.
                        _ => return 0,
                    }
                    continue;
                }
                let size = match insn.code {
                    0x20 => 4,
                    0x28 => 2,
                    _ => 1,
                };
                match skb.load(k as i32, size) {
                    Some(v) => a = v,
                    None => return 0,
                }
            }
            0x40 | 0x48 | 0x50 => {
                let size = match insn.code {
                    0x40 => 4,
                    0x48 => 2,
                    _ => 1,
                };
                // `BPF_MOV64_REG(ARG4, X); BPF_ALU64_IMM(ADD, ARG4, k)`
                // then the helper's `int offset` argument.
                let offset = (u64::from(x).wrapping_add(k as i32 as i64 as u64)) as i32;
                match skb.load(offset, size) {
                    Some(v) => a = v,
                    None => return 0,
                }
            }
            // ── LDX ──
            0x01 => x = k,
            0x61 => x = mem[k as usize],
            0x81 => x = skb.len as u32,
            0xb1 => match skb.load(k as i32, 1) {
                Some(v) => x = (v & 0xf) << 2,
                None => return 0,
            },
            // ── ST / STX ──
            0x02 => mem[k as usize] = a,
            0x03 => mem[k as usize] = x,
            // ── ALU ──
            0x04 => a = a.wrapping_add(k),
            0x0c => a = a.wrapping_add(x),
            0x14 => a = a.wrapping_sub(k),
            0x1c => a = a.wrapping_sub(x),
            0x24 => a = a.wrapping_mul(k),
            0x2c => a = a.wrapping_mul(x),
            0x34 => a /= k,
            0x3c => {
                // "For cBPF programs, this was always return 0."
                if x == 0 {
                    return 0;
                }
                a /= x;
            }
            0x44 => a |= k,
            0x4c => a |= x,
            0x54 => a &= k,
            0x5c => a &= x,
            0x64 => a <<= k & 31,
            0x6c => a <<= x & 31,
            0x74 => a >>= k & 31,
            0x7c => a >>= x & 31,
            0x84 => a = a.wrapping_neg(),
            0x94 => a %= k,
            0x9c => {
                if x == 0 {
                    return 0;
                }
                a %= x;
            }
            0xa4 => a ^= k,
            0xac => a ^= x,
            // ── JMP ──
            0x05 => pc += k as usize,
            0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d => {
                let operand = if insn.code & 0x08 != 0 { x } else { k };
                let taken = match insn.code & 0xf0 {
                    0x10 => a == operand,
                    0x20 => a > operand,
                    0x30 => a >= operand,
                    _ => a & operand != 0,
                };
                pc += usize::from(if taken { insn.jt } else { insn.jf });
            }
            // ── RET ──
            0x06 => return k,
            0x16 => return a,
            // ── MISC ──
            0x07 => x = a,
            0x87 => a = x,
            // Unreachable for a checked program.
            _ => return 0,
        }
    }
    0
}
