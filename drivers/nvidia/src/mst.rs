//! DisplayPort Multi-Stream Transport (MST) — topology + payload
//! bandwidth table.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   `nv50_mstm_*` — Nouveau's MST entry points (port enumeration,
//!   payload allocation, link training kick-off).
//! - **`/home/daniel/git/linux/drivers/gpu/drm/display/drm_dp_mst_topology.c`**
//!   — the canonical MST topology walker + sideband encoder.
//! - **VESA DisplayPort 1.4 §2.5** — MST topology + virtual channel
//!   payload table layout.
//!
//! ## Concepts
//!
//! - **Branch** — a DP MST hub that fan-outs an upstream link into
//!   multiple downstream ports.
//! - **Port** — one downstream output on a branch. The host
//!   addresses sinks by a relative-address path
//!   (e.g. `[1,2,4]` = port 4 of port 2 of port 1).
//! - **Time slot** — the upstream link is divided into 64 time
//!   slots (the "Virtual Channel Payload Table"). Each stream
//!   allocates a contiguous run of slots.
//! - **VCPI** — Virtual Channel Payload Identifier. The 7-bit
//!   stream id used in the payload table.

#![allow(dead_code)]

use alloc::vec::Vec;

// ── DPCD MST registers ───────────────────────────────────────────
//
// Cite `/home/daniel/git/linux/include/drm/display/drm_dp.h` for the
// canonical DPCD addresses we mirror.

/// DPCD register: MSTM_CAP — bit 0 set when sink supports MST.
pub const DPCD_MSTM_CAP: u32 = 0x0021;
/// DPCD register: MSTM_CTRL — bit 0 = MST_EN, bit 1 = UPSTREAM_ENABLED,
/// bit 2 = UP_REQ_EN.
pub const DPCD_MSTM_CTRL: u32 = 0x0111;
/// DPCD register: PAYLOAD_ALLOCATE_SET — stream id 1..63.
pub const DPCD_PAYLOAD_ALLOCATE_SET: u32 = 0x01C0;
/// DPCD register: PAYLOAD_ALLOCATE_START_TIME_SLOT.
pub const DPCD_PAYLOAD_ALLOCATE_START: u32 = 0x01C1;
/// DPCD register: PAYLOAD_ALLOCATE_TIME_SLOT_COUNT.
pub const DPCD_PAYLOAD_ALLOCATE_COUNT: u32 = 0x01C2;
/// DPCD register: PAYLOAD_TABLE_UPDATE_STATUS.
pub const DPCD_PAYLOAD_TABLE_STATUS: u32 = 0x02C0;
/// DPCD register: VC_PAYLOAD_ID_SLOT_1 — start of the 64-entry
/// payload table (one byte per slot).
pub const DPCD_VC_PAYLOAD_ID_SLOT_1: u32 = 0x02C1;

/// MSTM_CTRL bit: MST_EN.
pub const MSTM_CTRL_MST_EN: u8 = 1 << 0;
/// MSTM_CTRL bit: UP_REQ_EN — allow upstream requests through.
pub const MSTM_CTRL_UP_REQ_EN: u8 = 1 << 1;
/// MSTM_CAP bit: MST support.
pub const MSTM_CAP_MST: u8 = 1 << 0;

// ── Sideband message encoding ────────────────────────────────────
//
// Cite `drm_dp_mst_topology.c::drm_dp_encode_sideband_msg_*`. The
// sideband path is a small request/reply protocol layered on top of
// AUX. Each message has a 5-bit "request type", an LCT (link count
// total — depth in the topology tree), and a per-message body.

/// MST sideband request type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SidebandReq {
    /// LINK_ADDRESS — enumerate the branch's downstream ports.
    LinkAddress = 0x01,
    /// CONNECTION_STATUS_NOTIFY — upstream signals a status change.
    ConnectionStatusNotify = 0x02,
    /// ENUM_PATH_RESOURCES — query VCPI capacity along a path.
    EnumPathResources = 0x10,
    /// ALLOCATE_PAYLOAD — bind a VCPI to a port + slot range.
    AllocatePayload = 0x11,
    /// QUERY_PAYLOAD — read back a port's current VCPI allocation.
    QueryPayload = 0x12,
    /// RESOURCE_STATUS_NOTIFY — upstream signals VCPI availability.
    ResourceStatusNotify = 0x13,
    /// CLEAR_PAYLOAD_ID_TABLE — clear the entire MST payload table.
    ClearPayloadIdTable = 0x14,
    /// REMOTE_DPCD_READ — read DPCD on a remote sink via the branch.
    RemoteDpcdRead = 0x20,
    /// REMOTE_DPCD_WRITE — write DPCD on a remote sink.
    RemoteDpcdWrite = 0x21,
    /// REMOTE_I2C_READ — I²C-over-MST read.
    RemoteI2cRead = 0x22,
    /// REMOTE_I2C_WRITE — I²C-over-MST write.
    RemoteI2cWrite = 0x23,
}

impl SidebandReq {
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Sideband message header (4 bytes max — packs LCT + path + req).
/// Cite `drm_dp_mst_topology.c::drm_dp_encode_sideband_msg_hdr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SidebandHeader {
    /// Link count total — depth (0..15).
    pub lct: u8,
    /// Per-hop port number (lct entries). The first entry is the
    /// top branch's downstream port.
    pub lcr: [u8; 15],
    /// Request type.
    pub req: SidebandReq,
    /// Path-message indicator.
    pub broadcast: bool,
    /// Sequence number (rolling 1-bit field).
    pub seqno: bool,
}

impl SidebandHeader {
    pub const fn new(req: SidebandReq, lct: u8, lcr: [u8; 15]) -> Self {
        Self {
            lct: lct & 0xF,
            lcr,
            req,
            broadcast: false,
            seqno: false,
        }
    }
}

/// Encode the 1..2 byte sideband header. Per
/// `drm_dp_encode_sideband_msg_hdr`:
/// - byte 0: `(lct << 4) | (lcr[0..1] high nibbles)` — actually
///   `(lct << 4) | encode_lcr` per spec.
/// - byte 1 onward: per-hop port numbers (4 bits each, packed).
///
/// Returns the encoded bytes (variable length).
pub fn encode_sideband_header(h: &SidebandHeader) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(((h.lct & 0xF) << 4) | 0); // lcr count placeholder
    // Each hop is 4 bits; pack two per byte.
    let mut byte = 0u8;
    let mut half = false;
    for i in 0..(h.lct as usize) {
        let port = h.lcr[i] & 0xF;
        if !half {
            byte = port << 4;
            half = true;
        } else {
            byte |= port;
            out.push(byte);
            half = false;
        }
    }
    if half {
        out.push(byte);
    }
    // Last byte: broadcast/seqno flags + req code.
    let flags = ((h.broadcast as u8) << 7) | ((h.seqno as u8) << 4);
    out.push(flags | (h.req.code() & 0x1F));
    out
}

// ── VCPI / payload-bandwidth table ───────────────────────────────

/// Number of time slots in the MST payload table.
pub const VCPI_SLOT_COUNT: usize = 64;

/// One VCPI allocation — VCPI id + slot range.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VcpiAllocation {
    /// VCPI stream id (1..63; 0 means "unused slot").
    pub vcpi: u8,
    /// First slot in the run (1..64).
    pub start_slot: u8,
    /// Number of slots.
    pub slot_count: u8,
}

/// VCPI/payload table. Stage 1 model: a 64-byte byte array tracking
/// VCPI assignments per slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VcpiTable {
    slots: [u8; VCPI_SLOT_COUNT],
}

impl VcpiTable {
    pub const fn empty() -> Self {
        Self {
            slots: [0; VCPI_SLOT_COUNT],
        }
    }

    /// Find the first run of `count` empty slots starting at slot
    /// 1 (slot 0 is reserved). Returns the start slot or `None` if
    /// the table can't fit.
    pub fn find_run(&self, count: u8) -> Option<u8> {
        if count == 0 || count as usize > VCPI_SLOT_COUNT - 1 {
            return None;
        }
        let mut run = 0usize;
        let mut run_start = 1usize;
        for i in 1..VCPI_SLOT_COUNT {
            if self.slots[i] == 0 {
                if run == 0 {
                    run_start = i;
                }
                run += 1;
                if run == count as usize {
                    return Some(run_start as u8);
                }
            } else {
                run = 0;
            }
        }
        None
    }

    /// Allocate a contiguous run. Returns `Some(start)` on success.
    pub fn allocate(&mut self, vcpi: u8, count: u8) -> Option<u8> {
        if vcpi == 0 || vcpi > 63 {
            return None;
        }
        let start = self.find_run(count)?;
        for i in 0..count {
            self.slots[start as usize + i as usize] = vcpi;
        }
        Some(start)
    }

    /// Release every slot belonging to `vcpi`. Returns the number
    /// of slots freed.
    pub fn release(&mut self, vcpi: u8) -> u32 {
        let mut freed = 0;
        for i in 1..VCPI_SLOT_COUNT {
            if self.slots[i] == vcpi {
                self.slots[i] = 0;
                freed += 1;
            }
        }
        freed
    }

    /// Read the VCPI allocation for a given stream id.
    pub fn lookup(&self, vcpi: u8) -> Option<VcpiAllocation> {
        let mut start = None;
        let mut count = 0u8;
        for i in 1..VCPI_SLOT_COUNT {
            if self.slots[i] == vcpi {
                if start.is_none() {
                    start = Some(i as u8);
                }
                count += 1;
            }
        }
        start.map(|s| VcpiAllocation {
            vcpi,
            start_slot: s,
            slot_count: count,
        })
    }

    /// Current number of free slots (excluding slot 0).
    pub fn free_count(&self) -> u8 {
        self.slots[1..]
            .iter()
            .filter(|s| **s == 0)
            .count() as u8
    }

    /// Iterate over the raw 64-byte table — useful for live DPCD
    /// writes (DPCD 0x2C1..0x300).
    pub fn raw(&self) -> &[u8; VCPI_SLOT_COUNT] {
        &self.slots
    }
}

// ── Topology model ───────────────────────────────────────────────

/// One node in the MST topology — a branch (hub) with N
/// downstream ports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstBranch {
    /// LCR address from the upstream root (empty == root branch).
    pub lcr: Vec<u8>,
    /// Number of downstream ports the branch exposes.
    pub port_count: u8,
    /// Per-port classification — sink (true) or sub-branch (false).
    pub port_is_sink: [bool; 16],
    /// GUID of the branch (16 bytes per DP spec). Used to identify
    /// the branch across re-enumeration.
    pub guid: [u8; 16],
}

impl MstBranch {
    pub fn new(lcr: Vec<u8>, port_count: u8, guid: [u8; 16]) -> Self {
        Self {
            lcr,
            port_count,
            port_is_sink: [false; 16],
            guid,
        }
    }

    /// Mark port `p` as a sink (default is sub-branch).
    pub fn set_sink(&mut self, p: u8) {
        if (p as usize) < 16 {
            self.port_is_sink[p as usize] = true;
        }
    }
}

/// MST topology model — a list of branches indexed by LCR. Stage 1
/// keeps the model flat; Stage 2 builds a real tree as branches
/// LINK_ADDRESS-reply.
#[derive(Clone, Debug, Default)]
pub struct MstTopology {
    pub branches: Vec<MstBranch>,
}

impl MstTopology {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_branch(&mut self, b: MstBranch) {
        self.branches.push(b);
    }

    pub fn find_branch_mut(&mut self, lcr: &[u8]) -> Option<&mut MstBranch> {
        self.branches.iter_mut().find(|b| b.lcr.as_slice() == lcr)
    }

    pub fn sink_count(&self) -> u32 {
        self.branches
            .iter()
            .flat_map(|b| {
                b.port_is_sink[..b.port_count as usize]
                    .iter()
                    .copied()
            })
            .filter(|s| *s)
            .count() as u32
    }
}

/// Per-stream bandwidth request, in time slots. Cite
/// `drm_dp_mst_topology.c::drm_dp_atomic_find_time_slots`.
pub fn slots_for_pbn(pbn: u32) -> u8 {
    // Spec: 1 slot = 64 × link_rate / lane_count Mbps. PBN itself
    // is in 54 KHz units, so slots = ceil(pbn / 64). Stage 1 picks
    // the conservative ratio (matches drm_dp_mst).
    pbn.div_ceil(64).min(63) as u8
}
