//! DisplayPort bandwidth allocation — the connection-manager side
//! of the USB4 DisplayPort bandwidth-allocation mode.
//!
//! Register layouts and the allocation handshake follow the USB4
//! specification's DisplayPort adapter configuration space and DP
//! tunnelling chapters, cross-checked against Linux
//! `drivers/thunderbolt/tb_regs.h` (the `ADP_DP_CS_*` /
//! `DP_COMMON_CAP_*` definitions) and the CM helpers in
//! `drivers/thunderbolt/usb4.c` (`usb4_dp_port_*_bandwidth`,
//! `usb4_dp_port_set_cm_ack`, granularity / NRD accessors) and
//! `drivers/thunderbolt/tb.c` (bandwidth groups, estimated-bandwidth
//! recalculation, the 10% link guard band in
//! `tb_maximum_bandwidth`).
//!
//! ## The shared link-training seam (Intel #1092)
//!
//! DP link training itself — DPCD reads, AUX negotiation, the CR/EQ
//! state machine — is owned by exactly one implementation: the GPU
//! crate's `dp_link_training` (`read_caps`, `negotiate`,
//! `train_negotiated`), built by Intel lane #1092 (PR #1114). This
//! module deliberately contains no training state machine. What the
//! CM consumes from that seam is its negotiation vocabulary:
//!
//! - the rate ladder [`DpRate`] (RBR / HBR / HBR2 / HBR3) — here in
//!   its `DP_COMMON_CAP` adapter encoding (0..=3), there in its DPCD
//!   `LINK_BW_SET` encoding (0x06 / 0x0A / 0x14 / 0x1E);
//! - lane counts from {1, 2, 4}, spent before rate, exactly as
//!   `negotiate` picks them;
//! - the payload arithmetic `rate * lanes * 8/10` (8b/10b coding
//!   carries 8 payload bits per 10-bit symbol; the DP adapters strip
//!   the encoding before the fabric, so the payload is what the
//!   fabric must reserve) — identical to the core's
//!   `LinkRate::payload_kbps`, in Mb/s instead of kb/s;
//! - the fallback policy of the core's `run_with_fallback`: step
//!   the rate down first, then halve the lanes and restart the
//!   ladder — [`fit_link`] applies it against the fabric budget.
//!
//! The core's `SourceCaps` documentation names the tunnelled source
//! as reporting "the tunnel's envelope instead": this module is
//! that envelope's producer. The CM programs the negotiated
//! envelope into the DP adapters' `DP_REMOTE_CAP` registers and
//! reserves exactly its payload in the allocation ledger; the GPU
//! side then negotiates and trains against the envelope through the
//! tunnelled AUX channel, and asks for fabric bandwidth through the
//! DPIA DPCD extension (the GPU-side half, e.g.
//! `amdgpu_dp_tunnel`), whose requests land in this module's
//! register model as `ADP_DP_CS_8` DR / REQUESTED_BW.
//!
//! The thunderbolt crate cannot link the GPU crate (the CM is
//! GPU-vendor-neutral; the GPU crate is a downstream consumer of
//! fabric state), so the seam is consumed at this interface level:
//! one training implementation, one negotiation vocabulary, two
//! encodings of it.
use super::{ring::Error, tunnel::Endpoint};

// ── DP adapter configuration space ──────────────────────────────
//
// Offsets are DWORD indices relative to the adapter capability
// offset (`Port::adapter_cap`) in port configuration space, per
// the USB4 DP adapter configuration layout (tb_regs.h:
// ADP_DP_CS_0..ADP_DP_CS_8, DP_LOCAL_CAP, DP_REMOTE_CAP,
// DP_STATUS / DP_STATUS_CTRL, DP_COMMON_CAP).

/// `ADP_DP_CS_2`: NRD fields, HPD, CM ack, granularity, group/CM
/// identity and the CM-owned estimated-bandwidth field. (CS_0,
/// the adapter enable DWORD — AE bit 30 / VE bit 31 — is accessed
/// at the bare capability offset by the tunnel code.)
pub(crate) const ADP_DP_CS_2: u16 = 2;
/// `ADP_DP_CS_2` HPD status bit (DP OUT): sink attached.
pub(crate) const CS2_HPD: u32 = 1 << 6;
/// `ADP_DP_CS_2` CM Acknowledge: the CM pulses this after writing
/// a new `ALLOCATED_BW` so the adapter latches the grant and
/// clears its request.
pub(crate) const CS2_CA: u32 = 1 << 10;
/// `ADP_DP_CS_2` GR — allocation granularity encoding [12:11]:
/// 0 = 0.25 Gb/s, 1 = 0.5 Gb/s, 2 = 1 Gb/s, 3 = reserved.
pub(crate) const CS2_GR_SHIFT: u32 = 11;
/// `ADP_DP_CS_2` GROUP_ID [15:13]: bandwidth group the adapter
/// belongs to; adapters in one group share one estimate pool.
pub(crate) const CS2_GROUP_ID_SHIFT: u32 = 13;
/// `ADP_DP_CS_2` CM_ID [19:16]: identity of the managing CM.
pub(crate) const CS2_CM_ID_SHIFT: u32 = 16;
/// `ADP_DP_CS_2` CMMS (bit 20): the CM supports bandwidth
/// allocation mode. Set by the CM on DP IN adapters it manages in
/// allocation mode.
pub(crate) const CS2_CMMS: u32 = 1 << 20;
/// `ADP_DP_CS_2` ESTIMATED_BW [31:24], in granularity units: the
/// CM's published estimate of bandwidth available to this
/// adapter's group (its own allocation included), consumed by the
/// source through the DPIA DPCD ESTIMATED_BW register.
pub(crate) const CS2_ESTIMATED_BW_SHIFT: u32 = 24;
/// `DP_LOCAL_CAP` (CS_4): the adapter's own capabilities, in the
/// `DP_COMMON_CAP` layout.
pub(crate) const DP_LOCAL_CAP: u16 = 4;
/// `DP_REMOTE_CAP` (CS_5): the paired adapter's capabilities as
/// programmed by the CM — this is where the negotiated tunnel
/// envelope (rate, lanes, allocation mode) is written.
pub(crate) const DP_REMOTE_CAP: u16 = 5;
/// `DP_STATUS` (CS_6, DP IN): ALLOCATED_BW [31:24], in
/// granularity units — the CM's grant to this adapter, consumed
/// by the source through the DPIA DPCD ALLOCATED_BW register.
pub(crate) const DP_STATUS: u16 = 6;
pub(crate) const STATUS_ALLOCATED_BW_SHIFT: u32 = 24;
/// `DP_COMMON_CAP` RATE [11:8]: 0 = RBR, 1 = HBR, 2 = HBR2,
/// 3 = HBR3; all other encodings are reserved. The layout is
/// shared by CS_4 / CS_5 / CS_7.
pub(crate) const CAP_RATE_SHIFT: u32 = 8;
pub(crate) const CAP_RATE_MASK: u32 = 0xf << CAP_RATE_SHIFT;
/// `DP_COMMON_CAP` LANES [14:12]: 0 = 1 lane, 1 = 2 lanes,
/// 2 = 4 lanes; all other encodings are reserved.
pub(crate) const CAP_LANES_SHIFT: u32 = 12;
pub(crate) const CAP_LANES_MASK: u32 = 0x7 << CAP_LANES_SHIFT;
/// `DP_COMMON_CAP` UHBR rate support bits [19:17]. The CM does
/// not program UHBR (128b/132b) envelopes; the bits are cleared
/// from programmed REMOTE_CAP words rather than propagated.
pub(crate) const CAP_UHBR_MASK: u32 = 0x7 << 17;
/// `DP_COMMON_CAP` BW_MODE (bit 28): the adapter supports (in
/// LOCAL_CAP) or is operating in (in REMOTE_CAP) DisplayPort
/// bandwidth-allocation mode.
pub(crate) const CAP_BW_MODE: u32 = 1 << 28;
/// `ADP_DP_CS_8` (DP IN, present only when the adapter supports
/// bandwidth-allocation mode): REQUESTED_BW [7:0] in granularity
/// units, DPME (bit 30, adapter-owned mode-enabled status), DR
/// (bit 31, an allocation request is pending). The request side
/// is written by the adapter on behalf of the source's DPIA DPCD
/// REQUESTED_BW write; the CM only reads CS_8 and answers through
/// DP_STATUS + the CA pulse. The CM never writes CS_8.
pub(crate) const ADP_DP_CS_8: u16 = 8;
pub(crate) const CS8_REQUESTED_BW_MASK: u32 = 0xff;
pub(crate) const CS8_DR: u32 = 1 << 31;

/// Lane-adapter current-speed field values (`LANE_ADP_CS_1`
/// CURRENT_SPEED [19:16], tb_regs.h): one-hot generation codes.
pub(crate) const LANE_CS_1: u16 = 1;
pub(crate) const LANE_CURRENT_SPEED_SHIFT: u32 = 16;
/// Raw per-lane Mb/s of a USB4 Gen 2 link — the slowest link
/// generation the USB4 specification defines, hence the floor for
/// a link-budget computation that cannot read the negotiated
/// speed: any live link carries at least this much.
pub(crate) const GEN2_MBPS_PER_LANE: u32 = 10_000;
/// Guard band withheld from every link budget, per Linux
/// `tb_maximum_bandwidth` ("Leave 10% guard band"): the fabric
/// also carries control traffic and non-DP tunnels' overhead.
pub(crate) const LINK_GUARD_NUM: u32 = 9;
pub(crate) const LINK_GUARD_DEN: u32 = 10;
/// GROUP_ID is a 3-bit field and group indices run 1..=7 (Linux
/// `MAX_GROUPS`).
pub(crate) const MAX_GROUP_ID: u8 = 7;

// ── The negotiated-link vocabulary (shared seam) ────────────────

/// A DisplayPort link rate on the shared ladder, in its
/// `DP_COMMON_CAP` encoding. The same ladder exists in the GPU
/// crate's link-training core as the DPCD `LINK_BW_SET` encoding
/// (RBR 0x06, HBR 0x0A, HBR2 0x14, HBR3 0x1E).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DpRate {
    /// 1.62 Gb/s per lane — Reduced Bit Rate.
    Rbr = 0,
    /// 2.7 Gb/s per lane.
    Hbr = 1,
    /// 5.4 Gb/s per lane.
    Hbr2 = 2,
    /// 8.1 Gb/s per lane.
    Hbr3 = 3,
}

impl DpRate {
    /// Decode a `DP_COMMON_CAP` RATE field value; reserved
    /// encodings (4..=15) are refused, never floored — an adapter
    /// advertising one is not describing a DP link.
    pub(crate) fn from_cap_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::Rbr),
            1 => Some(Self::Hbr),
            2 => Some(Self::Hbr2),
            3 => Some(Self::Hbr3),
            _ => None,
        }
    }

    pub(crate) fn cap_code(self) -> u32 {
        self as u32
    }

    /// Raw per-lane link rate in Mb/s (symbol rate; 8b/10b coding
    /// included). Identical figures to the training core's
    /// `LinkRate::rate_kbps` / 1000.
    pub(crate) fn mbps_per_lane(self) -> u32 {
        match self {
            Self::Rbr => 1_620,
            Self::Hbr => 2_700,
            Self::Hbr2 => 5_400,
            Self::Hbr3 => 8_100,
        }
    }

    /// Payload bandwidth of a link at this rate with `lanes`
    /// lanes, in Mb/s: raw rate × lanes × 8/10. The DP adapters
    /// strip the 8b/10b coding before the fabric, so this payload
    /// — not the raw symbol rate — is what a tunnel reserves.
    /// Identical arithmetic to the training core's
    /// `LinkRate::payload_kbps` / 1000.
    pub(crate) fn payload_mbps(self, lanes: u8) -> u32 {
        self.mbps_per_lane() * lanes as u32 * 8 / 10
    }

    /// One step down the ladder; `None` at RBR.
    pub(crate) fn next_lower(self) -> Option<Self> {
        match self {
            Self::Hbr3 => Some(Self::Hbr2),
            Self::Hbr2 => Some(Self::Hbr),
            Self::Hbr => Some(Self::Rbr),
            Self::Rbr => None,
        }
    }

    pub(crate) fn min(a: Self, b: Self) -> Self {
        if a <= b {
            a
        } else {
            b
        }
    }
}

/// Decode a `DP_COMMON_CAP` LANES field value (0 = 1, 1 = 2,
/// 2 = 4); reserved encodings are refused.
pub(crate) fn decode_lane_count(enc: u32) -> Option<u8> {
    match enc {
        0 => Some(1),
        1 => Some(2),
        2 => Some(4),
        _ => None,
    }
}

/// Encode a lane count for a `DP_COMMON_CAP` LANES field.
pub(crate) fn encode_lane_count(lanes: u8) -> Option<u32> {
    match lanes {
        1 => Some(0),
        2 => Some(1),
        4 => Some(2),
        _ => None,
    }
}

/// Fit a link under a bandwidth budget, applying the shared
/// fallback policy: start at the demanded (rate, lanes); step the
/// rate down the ladder first; at the bottom rate, halve the lane
/// count and restart the ladder from the demanded rate. Returns
/// the first configuration whose payload fits, or `None` when
/// even RBR × 1 exceeds the budget.
pub(crate) fn fit_link(
    demand_rate: DpRate,
    demand_lanes: u8,
    available_mbps: u32,
) -> Option<(DpRate, u8)> {
    let mut lanes = demand_lanes;
    loop {
        let mut rate = demand_rate;
        loop {
            if rate.payload_mbps(lanes) <= available_mbps {
                return Some((rate, lanes));
            }
            match rate.next_lower() {
                Some(lower) => rate = lower,
                None => break,
            }
        }
        if lanes <= 1 {
            return None;
        }
        lanes /= 2;
    }
}

/// The capabilities a DP adapter advertises in its `DP_LOCAL_CAP`
/// (the `DP_COMMON_CAP` layout), decoded strictly: reserved rate
/// or lane encodings fail the decode instead of being floored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DpAdapterCaps {
    /// Highest link rate the adapter supports.
    pub max_rate: DpRate,
    /// Highest lane count the adapter supports (1, 2 or 4).
    pub max_lanes: u8,
    /// The adapter supports DisplayPort bandwidth-allocation mode
    /// (meaningful on DP IN adapters; allocation is an IN-side
    /// function).
    pub bw_mode: bool,
}

impl DpAdapterCaps {
    pub(crate) fn decode(local_cap: u32) -> Result<Self, Error> {
        let max_rate = DpRate::from_cap_code((local_cap & CAP_RATE_MASK) >> CAP_RATE_SHIFT)
            .ok_or(Error::Invalid)?;
        let max_lanes = decode_lane_count((local_cap & CAP_LANES_MASK) >> CAP_LANES_SHIFT)
            .ok_or(Error::Invalid)?;
        Ok(Self {
            max_rate,
            max_lanes,
            bw_mode: local_cap & CAP_BW_MODE != 0,
        })
    }
}

/// Compose a `DP_REMOTE_CAP` word: the peer's LOCAL_CAP with the
/// fields the CM programs — RATE, LANES, the UHBR bits (never
/// propagated; this CM does not program UHBR envelopes) and
/// BW_MODE — replaced by the negotiated envelope. All other peer
/// bits are preserved exactly, as the legacy programming did.
pub(crate) fn remote_cap_word(peer_local: u32, rate: DpRate, lanes: u8, bw_mode: bool) -> u32 {
    let lanes_enc = encode_lane_count(lanes).unwrap_or(0);
    (peer_local & !(CAP_RATE_MASK | CAP_LANES_MASK | CAP_UHBR_MASK | CAP_BW_MODE))
        | (rate.cap_code() << CAP_RATE_SHIFT)
        | (lanes_enc << CAP_LANES_SHIFT)
        | if bw_mode { CAP_BW_MODE } else { 0 }
}

/// Allocation granularity of a DP IN adapter, from the
/// `ADP_DP_CS_2` GR field. All bandwidth values exchanged with
/// the adapter (ESTIMATED_BW, ALLOCATED_BW, REQUESTED_BW) are
/// counts of these units in 8-bit fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Granularity(u32);

impl Granularity {
    /// Decode the GR field; the reserved encoding (3) yields
    /// `None` — an adapter whose granularity cannot be decoded
    /// cannot be allocated against, so it is programmed in
    /// legacy mode instead.
    pub(crate) fn decode(cs2: u32) -> Option<Self> {
        match (cs2 >> CS2_GR_SHIFT) & 0x3 {
            0 => Some(Self(250)),
            1 => Some(Self(500)),
            2 => Some(Self(1_000)),
            _ => None,
        }
    }

    /// Whole units covering at most `mbps` (the grant direction:
    /// the adapter is never told it has more than the CM granted).
    /// Saturates at the 8-bit field maximum rather than wrapping.
    pub(crate) fn units_floor(self, mbps: u32) -> u32 {
        (mbps / self.0).min(0xff)
    }

    /// Mb/s value of a unit count read from an adapter field.
    pub(crate) fn to_mbps(self, units: u32) -> u32 {
        units * self.0
    }
}

// ── Fabric budget and groups ────────────────────────────────────

/// Decode a lane adapter's CURRENT_SPEED field (one-hot
/// generation code) into raw Mb/s per lane: Gen 2 = 10 Gb/s,
/// Gen 3 = 20 Gb/s, Gen 4 = 40 Gb/s. Unknown or multi-bit values
/// yield `None`.
pub(crate) fn lane_speed_mbps(field: u32) -> Option<u32> {
    match field {
        0x8 => Some(10_000),
        0x4 => Some(20_000),
        0x2 => Some(40_000),
        _ => None,
    }
}

/// A link's DP budget: raw link bandwidth (per-lane speed ×
/// bonded width) less the guard band.
pub(crate) fn link_budget_mbps(speed_mbps_per_lane: u32, width: u8) -> u32 {
    speed_mbps_per_lane * width as u32 * LINK_GUARD_NUM / LINK_GUARD_DEN
}

/// Identify the first fabric link a host-to-device tunnel
/// traverses — the link between the input endpoint's router and
/// the next router towards the output — as (child route of that
/// link, lane port number on the parent router). Tunnels sharing
/// a first link share a bandwidth group: their DP reservations
/// and the USB3 tunnels over the same link all draw on one
/// budget.
pub(crate) fn first_link_key(input: Endpoint, output: Endpoint) -> (u64, u8) {
    let depth = super::cm::route_depth(input.route);
    let child_route = if depth >= 7 {
        output.route
    } else {
        output.route & ((1u64 << ((depth + 1) * 8)) - 1)
    };
    let lane_port = (output.route >> (depth * 8)) as u8;
    (child_route, lane_port)
}

/// The published state of one live DP tunnel: the envelope the CM
/// programmed, what it currently holds in the allocation ledger,
/// and the group it draws on. Recorded in `TunnelInfo` at
/// activation, so suspend/resume replay (which rebuilds a tunnel
/// from its recorded identity) replays the tunnel at its recorded
/// rate and allocation rather than renegotiating from scratch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpTunnelInfo {
    /// Negotiated link rate programmed into both REMOTE_CAPs.
    pub rate: DpRate,
    /// Negotiated lane count programmed into both REMOTE_CAPs.
    pub lanes: u8,
    /// Bandwidth this tunnel currently holds, in Mb/s: the
    /// payload of (rate, lanes) in legacy mode; the live grant
    /// (register value × granularity) in allocation mode, updated
    /// as allocation requests are serviced.
    pub allocated_mbps: u32,
    /// The tunnel's DP IN adapter operates in bandwidth-allocation
    /// mode (its LOCAL_CAP advertised BW_MODE and its granularity
    /// decoded).
    pub bw_mode: bool,
    /// GROUP_ID written to the DP IN adapter (1..=7).
    pub group: u8,
    /// The first-link group budget this tunnel was accounted
    /// against, in Mb/s. Group members carry it so a later
    /// accounting pass uses the smallest budget any member saw —
    /// a link that renegotiated slower never leaves the group
    /// overcommitted on a stale, larger budget.
    pub budget_mbps: u32,
}

#[cfg(feature = "kernel-test")]
#[path = "dp_bw_tests.rs"]
pub(crate) mod tests;
