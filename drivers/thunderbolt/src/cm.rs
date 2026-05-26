//! Connection Manager (SW-CM) — control packet protocol over the NHI
//! ring 0 mailbox.
//!
//! The Thunderbolt control channel is a fixed-format byte stream the
//! Connection Manager sends through NHI ring 0. Each request is a
//! little-endian sequence of dwords:
//!
//! ```text
//! dword 0: route_hi[21:0] | seq+unknown[31:22]
//! dword 1: route_lo (low 32 bits of the 64-bit route)
//! dword 2: offset[12:0] | length[18:13] | port[24:19] | space[26:25] | seq[28:27] | zero[31:29]
//! dword 3+: payload (for WRITE) / unused (for READ)
//! ```
//!
//! For Stage-1 we only need the *encode* side: produce a well-formed
//! `cfg_read` / `cfg_write` packet that the NHI mailbox can hand to
//! the link. The Stage-2 work (actual mailbox plumbing + completion
//! demux) will read the response back and route it to the requester.
//!
//! Stage-1 scope:
//!   - Packet type enum (TB_CFG_PKG_*).
//!   - Config space enum (HOPS / PORT / SWITCH / COUNTERS).
//!   - `Header` + `Address` encode helpers.
//!   - `cfg_read_pkg` / `cfg_write_pkg` byte-stream constructors.
//!   - Route-string compose / decompose (and depth derivation).
//!
//! Source: Linux `drivers/thunderbolt/tb_msgs.h` (`struct tb_cfg_header`,
//! `struct tb_cfg_address`, `enum tb_cfg_pkg_type`) and
//! `include/linux/thunderbolt.h` (`enum tb_cfg_pkg_type`). GPL-2.0-or-
//! later citation per `feedback_no_gpl_links` (NARF relicensed
//! 2026-05-20). USB4 1.0 §"Routing" + §"Configuration Space" are the
//! public-spec backstop for the wire format.

use core::fmt;

/// Bits-per-hop in a route string. The route is a 64-bit big-endian
/// sequence of 8-bit port numbers, where bit 0..7 selects the port at
/// the host switch (depth 0), bits 8..15 select the port at the next
/// switch (depth 1), and so on. A zero byte terminates the route.
///
/// Linux: `tb_regs.h:#define TB_ROUTE_SHIFT 8`.
pub const TB_ROUTE_SHIFT: u32 = 8;

/// Maximum depth of a Thunderbolt domain tree. USB4 allows up to 6
/// hops past the host, so a route fits in 8 bytes (= 64 bits, the
/// full route field). The host itself is depth 0.
pub const TB_MAX_DEPTH: u32 = 7;

/// Width of the per-hop port field in a route string. Same as
/// `TB_ROUTE_SHIFT` — kept as a separate name for the mask side.
pub const TB_HOP_MASK: u64 = 0xFF;

/// Control-channel packet type. Maps `enum tb_cfg_pkg_type` from
/// Linux `include/linux/thunderbolt.h`. Each NHI ring-0 frame is
/// tagged with one of these so the CM can demux responses + events.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CfgPkgType {
    /// Read N dwords from a config space at (route, port, offset).
    Read = 1,
    /// Write N dwords to a config space at (route, port, offset).
    Write = 2,
    /// Error reply (set by switch on a bad read/write).
    Error = 3,
    /// Notify-ACK reply.
    NotifyAck = 4,
    /// Plug / unplug / link-state event from the link.
    Event = 5,
    /// XDomain request frame.
    XDomainReq = 6,
    /// XDomain response frame.
    XDomainResp = 7,
    /// Override (firmware bring-up — not used by SW-CM).
    Override = 8,
    /// Domain reset.
    Reset = 9,
    /// ICM event (firmware-CM only — we won't see these on SW-CM).
    IcmEvent = 10,
    /// ICM command (firmware-CM only).
    IcmCmd = 11,
    /// ICM response (firmware-CM only).
    IcmResp = 12,
}

impl CfgPkgType {
    /// Decode the raw type byte off a CM packet. Returns `None` for
    /// values not in the enum — caller decides whether to drop the
    /// frame or log an unknown-type error.
    pub fn from_raw(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::Error,
            4 => Self::NotifyAck,
            5 => Self::Event,
            6 => Self::XDomainReq,
            7 => Self::XDomainResp,
            8 => Self::Override,
            9 => Self::Reset,
            10 => Self::IcmEvent,
            11 => Self::IcmCmd,
            12 => Self::IcmResp,
            _ => return None,
        })
    }
}

/// Config-space selector — which register block on an adapter / switch
/// the read or write targets. Maps `enum tb_cfg_space` from Linux
/// `tb_msgs.h`. Two-bit field in the address dword.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CfgSpace {
    /// Per-hop credit / buffer config — only valid on PCIe / DP / USB3
    /// adapter ports.
    Hops = 0,
    /// Per-port config — every adapter on every switch has one.
    Port = 1,
    /// Per-switch config — header at port 0 of every switch.
    Switch = 2,
    /// Performance counters — optional.
    Counters = 3,
}

/// Control-packet header (two dwords on the wire). The first dword
/// carries the high 22 bits of the 64-bit route plus 10 bits of seq +
/// reply flag; the second dword carries the low 32 bits of the route.
///
/// Layout from `tb_msgs.h::struct tb_cfg_header`:
/// ```text
/// dword 0: bits  0..21 = route_hi, bits 22..31 = unknown (seq/reply)
/// dword 1: bits  0..31 = route_lo
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// 64-bit route. High 22 bits land in dword 0, low 32 bits in
    /// dword 1. Routes wider than 54 bits aren't representable here.
    pub route: u64,
    /// The 10-bit "unknown" field at dword 0 bits 22..31. Linux sets
    /// the top bit on replies; SW-CM keeps it zero on requests.
    pub unknown: u16,
}

impl Header {
    /// Maximum representable route value. `route` only has 54 bits on
    /// the wire (22 high + 32 low). A real domain tree never exceeds
    /// depth 7 × 8 bits = 56 bits, but the upper two bits land
    /// inside the `unknown` field — Linux assumes a route fits in 54
    /// bits and `tb_cfg_make_header` warns otherwise. We treat over-
    /// width routes as a hard error so the smokes catch a regression.
    pub const ROUTE_MAX: u64 = (1u64 << 54) - 1;

    /// Encode `self` into two LE dwords (eight bytes). Returns the
    /// packed dword pair `[d0, d1]`. Caller is responsible for
    /// concatenating this with the address dword(s) + payload.
    pub fn encode(&self) -> [u32; 2] {
        let route_hi: u32 = ((self.route >> 32) & 0x003F_FFFF) as u32;
        let route_lo: u32 = (self.route & 0xFFFF_FFFF) as u32;
        let unknown: u32 = (self.unknown as u32) & 0x3FF;
        let d0 = route_hi | (unknown << 22);
        let d1 = route_lo;
        [d0, d1]
    }

    /// Decode two LE dwords from the wire back into a `Header`.
    pub fn decode(words: [u32; 2]) -> Self {
        let d0 = words[0];
        let d1 = words[1];
        let route_hi = (d0 & 0x003F_FFFF) as u64;
        let unknown = ((d0 >> 22) & 0x3FF) as u16;
        let route_lo = d1 as u64;
        Self {
            route: (route_hi << 32) | route_lo,
            unknown,
        }
    }
}

/// Address dword for a config read/write packet.
///
/// Layout from `tb_msgs.h::struct tb_cfg_address`:
/// ```text
/// bits  0..12  = offset (in dwords)
/// bits 13..18  = length (in dwords, 6 bits = up to 63 dwords)
/// bits 19..24  = port  (which adapter on the target switch)
/// bits 25..26  = space (2-bit `CfgSpace`)
/// bits 27..28  = seq   (sequence number, 2 bits)
/// bits 29..31  = zero
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// Dword offset within the selected config space.
    pub offset: u16,
    /// Length in dwords. Must be ≤ 63 (`tb_msgs.h::cfg_write_pkg.data`
    /// holds `u32 data[64]` — the +1 is the address dword itself).
    pub length: u8,
    /// Port number on the target switch. 0 = switch header itself,
    /// 1..max_port = adapters.
    pub port: u8,
    /// Which config space the read/write targets.
    pub space: CfgSpace,
    /// 2-bit sequence number — SW-CM increments per outstanding
    /// request so the response demux can pair them.
    pub seq: u8,
}

impl Address {
    /// Largest representable per-packet length (6-bit field).
    pub const MAX_LENGTH: u8 = 0x3F;
    /// Largest representable per-packet offset (13-bit field).
    pub const MAX_OFFSET: u16 = 0x1FFF;
    /// Largest representable port index (6-bit field).
    pub const MAX_PORT: u8 = 0x3F;

    /// Encode `self` into one LE dword.
    pub fn encode(&self) -> u32 {
        let offset = (self.offset as u32) & 0x1FFF;
        let length = ((self.length as u32) & 0x3F) << 13;
        let port = ((self.port as u32) & 0x3F) << 19;
        let space = ((self.space as u32) & 0x3) << 25;
        let seq = ((self.seq as u32) & 0x3) << 27;
        offset | length | port | space | seq
    }

    /// Decode one LE dword from the wire back into an `Address`.
    pub fn decode(dword: u32) -> Option<Self> {
        let space_raw = ((dword >> 25) & 0x3) as u8;
        let space = match space_raw {
            0 => CfgSpace::Hops,
            1 => CfgSpace::Port,
            2 => CfgSpace::Switch,
            3 => CfgSpace::Counters,
            _ => return None,
        };
        Some(Self {
            offset: (dword & 0x1FFF) as u16,
            length: ((dword >> 13) & 0x3F) as u8,
            port: ((dword >> 19) & 0x3F) as u8,
            space,
            seq: ((dword >> 27) & 0x3) as u8,
        })
    }
}

/// Errors emitted while constructing a control packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmError {
    /// `route` exceeds 54 bits (the on-wire header can't represent it).
    RouteTooWide,
    /// `length` exceeds `Address::MAX_LENGTH`.
    LengthTooLarge,
    /// `offset` exceeds `Address::MAX_OFFSET`.
    OffsetTooLarge,
    /// `port` exceeds `Address::MAX_PORT`.
    PortTooLarge,
    /// A `Write` had a payload shorter than `length` dwords (or longer).
    PayloadLengthMismatch,
}

impl fmt::Display for CmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RouteTooWide => f.write_str("route too wide"),
            Self::LengthTooLarge => f.write_str("length too large"),
            Self::OffsetTooLarge => f.write_str("offset too large"),
            Self::PortTooLarge => f.write_str("port too large"),
            Self::PayloadLengthMismatch => f.write_str("payload length mismatch"),
        }
    }
}

/// Build the on-wire byte stream for a `TB_CFG_PKG_READ` packet:
/// 3 dwords = 12 bytes, written into `dst`. Returns the number of
/// bytes written.
///
/// Stage-1: pure encode. The actual NHI ring-0 hand-off is Stage-2.
pub fn encode_cfg_read(
    header: Header,
    addr: Address,
    dst: &mut [u32; 3],
) -> Result<usize, CmError> {
    if header.route > Header::ROUTE_MAX {
        return Err(CmError::RouteTooWide);
    }
    if addr.length > Address::MAX_LENGTH {
        return Err(CmError::LengthTooLarge);
    }
    if addr.offset > Address::MAX_OFFSET {
        return Err(CmError::OffsetTooLarge);
    }
    if addr.port > Address::MAX_PORT {
        return Err(CmError::PortTooLarge);
    }
    let hdr = header.encode();
    dst[0] = hdr[0];
    dst[1] = hdr[1];
    dst[2] = addr.encode();
    Ok(3 * 4)
}

/// Build the on-wire byte stream for a `TB_CFG_PKG_WRITE` packet:
/// `3 + payload.len()` dwords. Returns the number of bytes written.
///
/// `payload.len()` must equal `addr.length` exactly — a short payload
/// would underflow the switch's write window; a long one would
/// overflow the NHI ring frame.
pub fn encode_cfg_write(
    header: Header,
    addr: Address,
    payload: &[u32],
    dst: &mut [u32],
) -> Result<usize, CmError> {
    if header.route > Header::ROUTE_MAX {
        return Err(CmError::RouteTooWide);
    }
    if addr.length > Address::MAX_LENGTH {
        return Err(CmError::LengthTooLarge);
    }
    if addr.offset > Address::MAX_OFFSET {
        return Err(CmError::OffsetTooLarge);
    }
    if addr.port > Address::MAX_PORT {
        return Err(CmError::PortTooLarge);
    }
    if payload.len() != addr.length as usize {
        return Err(CmError::PayloadLengthMismatch);
    }
    if dst.len() < 3 + payload.len() {
        return Err(CmError::PayloadLengthMismatch);
    }
    let hdr = header.encode();
    dst[0] = hdr[0];
    dst[1] = hdr[1];
    dst[2] = addr.encode();
    dst[3..3 + payload.len()].copy_from_slice(payload);
    Ok((3 + payload.len()) * 4)
}

/// Compose a downstream route from a parent route plus a hop value.
///
/// Linux: `tb_downstream_route()` in `tb.h`:
/// ```c
/// return tb_route(port->sw) | ((u64) port->port << (port->sw->config.depth * 8));
/// ```
///
/// `depth` is the depth of the *parent* (0 for the host) — the new
/// hop byte slots in at the parent's depth × 8 bit position.
///
/// Returns `None` if `depth` exceeds `TB_MAX_DEPTH` or the resulting
/// route would exceed `Header::ROUTE_MAX`.
pub fn compose_downstream(parent_route: u64, depth: u32, hop: u8) -> Option<u64> {
    if depth > TB_MAX_DEPTH {
        return None;
    }
    let shifted = (hop as u64) << (depth * TB_ROUTE_SHIFT);
    // The parent route already has all higher hops zeroed — composing
    // is a simple OR. We disallow overwriting an existing hop byte:
    // that would mean the caller mis-tracked depth.
    let parent_hop_at_depth = (parent_route >> (depth * TB_ROUTE_SHIFT)) & TB_HOP_MASK;
    if parent_hop_at_depth != 0 {
        return None;
    }
    let route = parent_route | shifted;
    if route > Header::ROUTE_MAX {
        return None;
    }
    Some(route)
}

/// Inverse of `compose_downstream`: count the depth implied by a
/// route. Host (route = 0) is depth 0; each non-zero leading hop
/// byte adds one to the depth.
///
/// Linux: `tb_route_length()` in `tb.h`.
pub fn route_depth(route: u64) -> u32 {
    if route == 0 {
        return 0;
    }
    let leading_zeros = route.leading_zeros();
    let bits_used = 64 - leading_zeros;
    bits_used.div_ceil(TB_ROUTE_SHIFT)
}

/// Pretty-print a route as an 8-byte hex string in the "least-
/// significant-hop-first" order used by Linux `tb_route`.
pub fn fmt_route(route: u64) -> impl fmt::Display {
    struct R(u64);
    impl fmt::Display for R {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{:016x}", self.0)
        }
    }
    R(route)
}

#[cfg(test)]
mod cm_unit_tests {
    use super::*;

    // Stage-1 has integration smokes in src/tests.rs; the host-side
    // unit tests live in src/tests.rs too so they share the same
    // build wiring as the rest of the kernel-test framework.
    #[allow(dead_code)]
    fn keep_module_alive() {
        let _ = encode_cfg_read;
        let _ = encode_cfg_write;
    }
}
