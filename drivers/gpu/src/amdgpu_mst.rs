//! DisplayPort MST (Multi-Stream Transport) — topology +
//! payload table.
//!
//! MST lets a single DP link carry up to 63 logical streams
//! distributed across a tree of branch devices (MST hubs). The
//! source enumerates the topology via sideband messages
//! (DP_LINK_ADDRESS, DP_ENUM_PATH_RESOURCES) and reserves
//! payload bandwidth per stream (DP_ALLOCATE_PAYLOAD).
//!
//! USB-C DP-Alt-mode dongles + docking stations frequently
//! present as MST topologies (one upstream port → multiple
//! downstream sinks), so MST coverage matters even for laptops
//! that don't have native multi-monitor support.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/display/drm_dp_mst_topology.c`
//!   (`drm_dp_mst_topology_mgr_set_mst`,
//!   `drm_dp_send_link_address`,
//!   `drm_dp_payload_send_msg`)
//! - VESA DisplayPort Standard 1.4a, §2.11 "MST Sideband Messaging"
//! - Linux `include/drm/display/drm_dp.h` — sideband opcodes
//!
//! GPL-2.0-or-later (matches NARF). Adapted directly.
//!
//! ## Topology model
//!
//! ```text
//!   Source (host GPU)
//!     │
//!     ▼  DP_TX (single physical port)
//!   ┌─────────┐
//!   │  Branch  │  (MST hub)  ←── upstream port (port 0)
//!   │   GUID  │
//!   ├─────────┤
//!   │ port 1 ├─── Sink A (display)
//!   │ port 2 ├─── Sink B (display)
//!   │ port 3 ├─── Branch (downstream hub)
//!   │        │       ├─── Sink C
//!   │        │       └─── Sink D
//!   └─────────┘
//! ```
//!
//! Each branch is uniquely identified by a 128-bit GUID. Each
//! port has a port-num (1-based) and a PDT (Peer Device Type)
//! byte indicating Sink vs Branch vs MCCS-only.

extern crate alloc;

use alloc::vec::Vec;

// ── Sideband message opcodes ─────────────────────────────────────

/// `DP_LINK_ADDRESS` — enumerate downstream ports.
pub const SB_LINK_ADDRESS: u8 = 0x01;
/// `DP_CONNECTION_STATUS_NOTIFY` — async, sink reports change.
pub const SB_CONNECTION_STATUS_NOTIFY: u8 = 0x02;
/// `DP_ENUM_PATH_RESOURCES` — query available bandwidth.
pub const SB_ENUM_PATH_RESOURCES: u8 = 0x10;
/// `DP_ALLOCATE_PAYLOAD` — reserve VCPI bandwidth.
pub const SB_ALLOCATE_PAYLOAD: u8 = 0x11;
/// `DP_QUERY_PAYLOAD` — verify allocation.
pub const SB_QUERY_PAYLOAD: u8 = 0x12;
/// `DP_RESOURCE_STATUS_NOTIFY` — async, bandwidth changed.
pub const SB_RESOURCE_STATUS_NOTIFY: u8 = 0x13;
/// `DP_CLEAR_PAYLOAD_ID_TABLE` — full reset.
pub const SB_CLEAR_PAYLOAD_ID_TABLE: u8 = 0x14;
/// `DP_REMOTE_DPCD_READ` — proxy DPCD read through MST.
pub const SB_REMOTE_DPCD_READ: u8 = 0x20;
/// `DP_REMOTE_DPCD_WRITE` — proxy DPCD write.
pub const SB_REMOTE_DPCD_WRITE: u8 = 0x21;

// ── Peer Device Type ────────────────────────────────────────────

/// PDT (Peer Device Type) per VESA DP MST spec, table 2-50.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeerDeviceType {
    /// No device.
    None,
    /// Sink (display panel).
    Sink,
    /// Stream sink with internal branch (rare).
    SinkOrBranch,
    /// Pure branch device (MST hub).
    Branch,
    /// Sink that's also a DPCD legacy device.
    LegacyDevice,
    Reserved(u8),
}

impl PeerDeviceType {
    pub fn from_byte(b: u8) -> Self {
        match b & 0x07 {
            0 => PeerDeviceType::None,
            1 => PeerDeviceType::SinkOrBranch,
            2 => PeerDeviceType::Sink,
            3 => PeerDeviceType::Branch,
            4 => PeerDeviceType::LegacyDevice,
            n => PeerDeviceType::Reserved(n),
        }
    }

    pub fn is_sink(self) -> bool {
        matches!(
            self,
            PeerDeviceType::Sink | PeerDeviceType::SinkOrBranch | PeerDeviceType::LegacyDevice
        )
    }

    pub fn is_branch(self) -> bool {
        matches!(self, PeerDeviceType::Branch | PeerDeviceType::SinkOrBranch)
    }
}

// ── Branch + port ───────────────────────────────────────────────

/// 128-bit GUID identifying a branch. Allocated by the branch
/// at first power-up; persists across reseat.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const ZERO: Guid = Guid([0; 16]);
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 16]
    }
}

/// One downstream port on a branch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Port {
    /// 1-based port number on the branch (port 0 is upstream).
    pub port_num: u8,
    pub peer_device_type: PeerDeviceType,
    /// `true` if a device is connected (input-port flag).
    pub input_port: bool,
    /// `true` if a sink/branch has been detected here.
    pub mcs: bool, // Mcs == Message Capability Status
    /// `true` if this port supports DPCD access through MST.
    pub ddps: bool,
    /// Available payload bandwidth (10-bit VC slots; 64 = full
    /// link).
    pub available_pbn: u16,
}

/// One branch device in the topology.
#[derive(Clone, Debug)]
pub struct Branch {
    pub guid: Guid,
    pub ports: Vec<Port>,
    /// Relative Address (RAD) — path from source to this
    /// branch. Empty for the first branch.
    pub rad: Vec<u8>,
}

impl Branch {
    pub fn sink_ports(&self) -> impl Iterator<Item = &Port> + '_ {
        self.ports.iter().filter(|p| p.peer_device_type.is_sink())
    }
    pub fn branch_ports(&self) -> impl Iterator<Item = &Port> + '_ {
        self.ports.iter().filter(|p| p.peer_device_type.is_branch())
    }
}

// ── Payload table ───────────────────────────────────────────────

/// One payload allocation. `vcpi` is the Virtual Channel Payload
/// Identifier (1..=63); `pbn` is the payload bandwidth number
/// in 1/4 Mbit increments per VESA spec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PayloadAllocation {
    pub vcpi: u8,
    pub pbn: u16,
    /// Sink port number on the leaf branch.
    pub sink_port: u8,
    /// GUID of the leaf branch.
    pub branch_guid: Guid,
}

/// MST payload table — tracks reserved bandwidth per sink.
/// Maximum 63 active streams per link (VCPIs are 6-bit).
#[derive(Clone, Debug, Default)]
pub struct PayloadTable {
    pub allocations: Vec<PayloadAllocation>,
    /// Total link PBN (per link rate). 6.4 Gbps × 4 lanes = 64
    /// PBN slots after 8b10b overhead → 64 in the wire format.
    pub link_pbn: u16,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MstError {
    /// All 63 VCPIs in use.
    NoFreeVcpi,
    /// Reservation would exceed link PBN.
    NotEnoughBandwidth,
    /// VCPI not found.
    NoSuchVcpi,
    /// Topology has no branch at the requested RAD.
    NoSuchBranch,
}

impl PayloadTable {
    pub fn new(link_pbn: u16) -> Self {
        Self {
            allocations: Vec::new(),
            link_pbn,
        }
    }

    /// Allocate a fresh VCPI for `pbn` bandwidth at `(branch, port)`.
    pub fn allocate(&mut self, branch_guid: Guid, sink_port: u8, pbn: u16) -> Result<u8, MstError> {
        if self.allocations.len() >= 63 {
            return Err(MstError::NoFreeVcpi);
        }
        if self.used_pbn() + pbn > self.link_pbn {
            return Err(MstError::NotEnoughBandwidth);
        }
        // Find smallest free VCPI (1-based).
        let mut next = 1u8;
        while self.allocations.iter().any(|a| a.vcpi == next) {
            next = next.checked_add(1).ok_or(MstError::NoFreeVcpi)?;
            if next > 63 {
                return Err(MstError::NoFreeVcpi);
            }
        }
        self.allocations.push(PayloadAllocation {
            vcpi: next,
            pbn,
            sink_port,
            branch_guid,
        });
        Ok(next)
    }

    /// Free a VCPI. No-op if not allocated.
    pub fn release(&mut self, vcpi: u8) -> Result<(), MstError> {
        let pos = self
            .allocations
            .iter()
            .position(|a| a.vcpi == vcpi)
            .ok_or(MstError::NoSuchVcpi)?;
        self.allocations.swap_remove(pos);
        Ok(())
    }

    /// Total PBN used.
    pub fn used_pbn(&self) -> u16 {
        self.allocations.iter().map(|a| a.pbn).sum()
    }

    /// Bandwidth headroom.
    pub fn available_pbn(&self) -> u16 {
        self.link_pbn.saturating_sub(self.used_pbn())
    }
}

// ── Bandwidth conversion ────────────────────────────────────────

/// Convert a pixel clock + bpp to PBN per VESA DP spec. PBN is
/// expressed in 64×10⁻⁶ Mbit chunks; the formula is:
///
///   PBN = (pixel_clock_khz × bpp × 1.006) / (8 × 54000)
///
/// 1.006 is the MTPH (Margin To Pixel Header) overhead per spec.
pub fn pixel_clock_to_pbn(pixel_clock_khz: u32, bpp: u32) -> u32 {
    // Use 1006/1000 fixed-point to avoid floating-point.
    let num = (pixel_clock_khz as u64) * (bpp as u64) * 1006;
    let den: u64 = 8 * 54_000 * 1000;
    num.div_ceil(den) as u32
}

// ── Topology ────────────────────────────────────────────────────

/// MST topology — list of discovered branches.
#[derive(Clone, Debug, Default)]
pub struct Topology {
    pub branches: Vec<Branch>,
    /// Payload table for the upstream link.
    pub payload: PayloadTable,
}

impl Topology {
    pub fn new(link_pbn: u16) -> Self {
        Self {
            branches: Vec::new(),
            payload: PayloadTable::new(link_pbn),
        }
    }

    /// Add a branch to the topology. Caller's responsibility to
    /// supply a unique RAD.
    pub fn add_branch(&mut self, branch: Branch) {
        // Replace existing branch at the same RAD if any.
        if let Some(slot) = self.branches.iter_mut().find(|b| b.rad == branch.rad) {
            *slot = branch;
        } else {
            self.branches.push(branch);
        }
    }

    /// Lookup branch by GUID.
    pub fn branch_by_guid(&self, guid: Guid) -> Option<&Branch> {
        self.branches.iter().find(|b| b.guid == guid)
    }

    /// Count of total sinks in the topology.
    pub fn sink_count(&self) -> usize {
        self.branches.iter().flat_map(|b| b.sink_ports()).count()
    }
}

// ── DPCD payload-table commit (live stream activation) ────────────
//
// After PayloadTable::allocate reserves a VCPI, the host must:
//   1. Write the per-VCPI time-slot count into DPCD PAYLOAD_TABLE
//      registers 0x1C0-0x1FF (PAYLOAD_ALLOCATE_SET + START_TIME_SLOT
//      + TIME_SLOT_COUNT).
//   2. Poll DPCD 0x2C0 (PAYLOAD_TABLE_UPDATE_STATUS) for the
//      VCPI_PAYLOAD_TABLE_UPDATED bit.
//   3. Send the ALLOCATE_PAYLOAD MST sideband message over AUX to
//      the branch+sink pair so the branch updates its own table.
//   4. Send the ENABLE_STREAM SB message — flips the branch from
//      "VCPI reserved" → "VCPI carrying real pixels".
//
// References (post 2026-05-20 GPL relicense):
//   - drivers/gpu/drm/display/drm_dp_mst_topology.c (drm_dp_mst_*
//     primitives — the canonical commit flow)
//   - drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_mst.c
//   - include/drm/display/drm_dp.h:778-987 (DPCD addresses)

/// DPCD addresses for the per-VCPI commit registers.
pub const DPCD_PAYLOAD_ALLOCATE_SET: u16 = 0x01C0;
pub const DPCD_PAYLOAD_ALLOCATE_START_TIME_SLOT: u16 = 0x01C1;
pub const DPCD_PAYLOAD_ALLOCATE_TIME_SLOT_COUNT: u16 = 0x01C2;
pub const DPCD_PAYLOAD_TABLE_UPDATE_STATUS: u16 = 0x02C0;

/// Status bit in DPCD 0x2C0 — set by the branch when our commit
/// has reached it. Cleared by writing 1 back.
pub const PAYLOAD_TABLE_UPDATED_BIT: u8 = 1 << 0;

/// MST sideband message opcodes (subset).
/// Per VESA DP MST spec.
pub const MST_SB_ALLOCATE_PAYLOAD: u8 = 0x10;
pub const MST_SB_ENABLE_STREAM: u8 = 0x12;
pub const MST_SB_REMOTE_DPCD_READ: u8 = 0x20;
pub const MST_SB_REMOTE_DPCD_WRITE: u8 = 0x21;

/// Trait for the host driver's AUX channel. Same shape as the
/// existing dp_aux module's transport.
pub trait MstAux {
    /// Write `value` to DPCD `addr`. Returns the ack byte.
    fn dpcd_write_u8(&mut self, addr: u16, value: u8) -> u8;
    /// Read a DPCD byte.
    fn dpcd_read_u8(&mut self, addr: u16) -> u8;
    /// Issue an MST sideband message (already packetised + checksummed).
    /// Returns the response payload.
    fn sb_message(&mut self, opcode: u8, body: &[u8]) -> alloc::vec::Vec<u8>;
}

/// Poll cap for the PAYLOAD_TABLE_UPDATE_STATUS bit.
pub const PAYLOAD_TABLE_POLL_BUDGET: u32 = 100_000;

/// Commit a payload-table change to silicon + sink. Sequence
/// adapted from `drm_dp_mst_topology.c::drm_dp_mst_update_payload_part1`.
///
/// `start_time_slot` is the first VCPI time slot index in the
/// link's 64-slot MTPH frame. `time_slot_count` is the number of
/// consecutive slots the VCPI owns (proportional to pbn).
pub fn commit_payload_to_sink<A: MstAux>(
    aux: &mut A,
    vcpi: u8,
    start_time_slot: u8,
    time_slot_count: u8,
) -> Result<(), MstStreamError> {
    if vcpi == 0 || vcpi > 63 {
        return Err(MstStreamError::BadVcpi);
    }
    // Step 1: write the per-VCPI assignment to DPCD.
    aux.dpcd_write_u8(DPCD_PAYLOAD_ALLOCATE_SET, vcpi);
    aux.dpcd_write_u8(DPCD_PAYLOAD_ALLOCATE_START_TIME_SLOT, start_time_slot);
    aux.dpcd_write_u8(DPCD_PAYLOAD_ALLOCATE_TIME_SLOT_COUNT, time_slot_count);

    // Step 2: poll for the branch to ack the update.
    let mut i = 0u32;
    loop {
        let s = aux.dpcd_read_u8(DPCD_PAYLOAD_TABLE_UPDATE_STATUS);
        if s & PAYLOAD_TABLE_UPDATED_BIT != 0 {
            // Clear the status bit by writing 1 back (W1C semantics).
            aux.dpcd_write_u8(DPCD_PAYLOAD_TABLE_UPDATE_STATUS, PAYLOAD_TABLE_UPDATED_BIT);
            break;
        }
        i += 1;
        if i >= PAYLOAD_TABLE_POLL_BUDGET {
            return Err(MstStreamError::CommitTimeout);
        }
    }
    Ok(())
}

/// Send the ALLOCATE_PAYLOAD MST sideband message — tells the
/// branch+leaf chain about the new VCPI's bandwidth + lct/rad.
pub fn send_allocate_payload<A: MstAux>(
    aux: &mut A,
    vcpi: u8,
    pbn: u16,
    branch_lct: u8,
    branch_rad: &[u8],
) -> Result<(), MstStreamError> {
    if vcpi == 0 || vcpi > 63 {
        return Err(MstStreamError::BadVcpi);
    }
    // Body layout per DP MST spec §2.11.5.3:
    //   [LCT | RAD bytes... | VCPI | PBN]
    // PBN is encoded as a single payload byte (low byte; high byte is
    // always 0 for practical bandwidths and is omitted by the branch).
    let mut body = alloc::vec::Vec::with_capacity(3 + branch_rad.len());
    body.push(branch_lct);
    for r in branch_rad {
        body.push(*r);
    }
    body.push(vcpi);
    body.push((pbn & 0xFF) as u8);
    let _resp = aux.sb_message(MST_SB_ALLOCATE_PAYLOAD, &body);
    Ok(())
}

/// Send the ENABLE_STREAM MST sideband message — flips the
/// per-VCPI carrying state on the branch. Must follow a successful
/// ALLOCATE_PAYLOAD + commit_payload_to_sink.
pub fn send_enable_stream<A: MstAux>(
    aux: &mut A,
    vcpi: u8,
    branch_lct: u8,
    branch_rad: &[u8],
) -> Result<(), MstStreamError> {
    if vcpi == 0 || vcpi > 63 {
        return Err(MstStreamError::BadVcpi);
    }
    let mut body = alloc::vec::Vec::with_capacity(4 + branch_rad.len());
    body.push(branch_lct);
    for r in branch_rad {
        body.push(*r);
    }
    body.push(vcpi);
    let _resp = aux.sb_message(MST_SB_ENABLE_STREAM, &body);
    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MstStreamError {
    BadVcpi,
    CommitTimeout,
}

/// Full live activation: VCPI alloc (from PayloadTable) → DPCD
/// commit → sideband ALLOCATE_PAYLOAD → sideband ENABLE_STREAM.
#[allow(clippy::too_many_arguments)] // MST stream activation genuinely requires all DP topology fields
pub fn activate_stream<A: MstAux>(
    aux: &mut A,
    table: &mut PayloadTable,
    branch_guid: Guid,
    branch_lct: u8,
    branch_rad: &[u8],
    sink_port: u8,
    pbn: u16,
    start_time_slot: u8,
) -> Result<u8, MstStreamErrorOrAlloc> {
    let vcpi = table.allocate(branch_guid, sink_port, pbn)?;
    // Time slot count = pbn / link rate per slot. The PayloadTable's
    // link_pbn is split into 64 slots; one slot = link_pbn / 64.
    let slots_per_pbn = if table.link_pbn != 0 {
        (pbn as u32 * 64).div_ceil(table.link_pbn as u32)
    } else {
        0
    };
    commit_payload_to_sink(aux, vcpi, start_time_slot, slots_per_pbn as u8)?;
    send_allocate_payload(aux, vcpi, pbn, branch_lct, branch_rad)?;
    send_enable_stream(aux, vcpi, branch_lct, branch_rad)?;
    Ok(vcpi)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MstStreamErrorOrAlloc {
    Stream(MstStreamError),
    Alloc(MstError),
}
impl From<MstError> for MstStreamErrorOrAlloc {
    fn from(e: MstError) -> Self {
        MstStreamErrorOrAlloc::Alloc(e)
    }
}
impl From<MstStreamError> for MstStreamErrorOrAlloc {
    fn from(e: MstStreamError) -> Self {
        MstStreamErrorOrAlloc::Stream(e)
    }
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pdt_decode() -> TestResult {
        if PeerDeviceType::from_byte(0) != PeerDeviceType::None {
            return TestResult::Fail("0 should be None");
        }
        if PeerDeviceType::from_byte(2) != PeerDeviceType::Sink {
            return TestResult::Fail("2 should be Sink");
        }
        if PeerDeviceType::from_byte(3) != PeerDeviceType::Branch {
            return TestResult::Fail("3 should be Branch");
        }
        if !PeerDeviceType::Sink.is_sink() {
            return TestResult::Fail("Sink.is_sink false");
        }
        if PeerDeviceType::Sink.is_branch() {
            return TestResult::Fail("Sink.is_branch true");
        }
        if !PeerDeviceType::Branch.is_branch() {
            return TestResult::Fail("Branch.is_branch false");
        }
        // SinkOrBranch is both.
        if !PeerDeviceType::SinkOrBranch.is_sink() || !PeerDeviceType::SinkOrBranch.is_branch() {
            return TestResult::Fail("SinkOrBranch not both");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_pdt_decode);

    fn smoke_pbn_calculation_4k60() -> TestResult {
        // 4K60: 533.250 MHz × 24 bpp ≈ 32.2 PBN per spec table.
        // We allow ±2 PBN tolerance for the 1.006/1000 fixed-point.
        let pbn = pixel_clock_to_pbn(533_250, 24);
        if !(30..=35).contains(&pbn) {
            return TestResult::Fail("4K60 24bpp PBN out of expected band");
        }
        // 1080p60: 148.5 MHz × 24bpp ≈ 9 PBN.
        let pbn = pixel_clock_to_pbn(148_500, 24);
        if !(8..=11).contains(&pbn) {
            return TestResult::Fail("1080p60 24bpp PBN out of expected band");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_pbn_calculation_4k60);

    fn smoke_payload_allocate_release() -> TestResult {
        let mut p = PayloadTable::new(64);
        let v1 = p.allocate(Guid::ZERO, 1, 10).expect("a1");
        if v1 != 1 {
            return TestResult::Fail("first VCPI not 1");
        }
        let v2 = p.allocate(Guid::ZERO, 2, 20).expect("a2");
        if v2 != 2 {
            return TestResult::Fail("second VCPI not 2");
        }
        if p.used_pbn() != 30 {
            return TestResult::Fail("used_pbn wrong");
        }
        if p.available_pbn() != 34 {
            return TestResult::Fail("available_pbn wrong");
        }
        // Release + reuse — should get VCPI 1 back (lowest free).
        p.release(v1).expect("release v1");
        let v3 = p.allocate(Guid::ZERO, 3, 5).expect("a3");
        if v3 != 1 {
            return TestResult::Fail("VCPI not reused");
        }
        // Release missing.
        if p.release(99) != Err(MstError::NoSuchVcpi) {
            return TestResult::Fail("missing VCPI release not flagged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_payload_allocate_release);

    fn smoke_payload_bandwidth_exhausted() -> TestResult {
        let mut p = PayloadTable::new(32);
        p.allocate(Guid::ZERO, 1, 20).expect("a1");
        if p.allocate(Guid::ZERO, 2, 20) != Err(MstError::NotEnoughBandwidth) {
            return TestResult::Fail("overcommit not rejected");
        }
        // Smaller request fits.
        if p.allocate(Guid::ZERO, 2, 10).is_err() {
            return TestResult::Fail("fitting request rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_payload_bandwidth_exhausted);

    fn smoke_payload_vcpi_exhaustion() -> TestResult {
        let mut p = PayloadTable::new(u16::MAX);
        for _ in 0..63 {
            p.allocate(Guid::ZERO, 0, 1).expect("alloc");
        }
        if p.allocate(Guid::ZERO, 0, 1) != Err(MstError::NoFreeVcpi) {
            return TestResult::Fail("VCPI exhaustion not flagged");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_payload_vcpi_exhaustion);

    fn smoke_topology_branch_lookup() -> TestResult {
        let mut t = Topology::new(64);
        let g1 = Guid([1; 16]);
        let g2 = Guid([2; 16]);
        let b1 = Branch {
            guid: g1,
            ports: alloc::vec![
                Port {
                    port_num: 1,
                    peer_device_type: PeerDeviceType::Sink,
                    input_port: true,
                    mcs: true,
                    ddps: true,
                    available_pbn: 32,
                },
                Port {
                    port_num: 2,
                    peer_device_type: PeerDeviceType::Branch,
                    input_port: false,
                    mcs: true,
                    ddps: true,
                    available_pbn: 32,
                },
            ],
            rad: Vec::new(),
        };
        let b2 = Branch {
            guid: g2,
            ports: alloc::vec![Port {
                port_num: 1,
                peer_device_type: PeerDeviceType::Sink,
                input_port: true,
                mcs: true,
                ddps: true,
                available_pbn: 16,
            }],
            rad: alloc::vec![2],
        };
        t.add_branch(b1);
        t.add_branch(b2);
        if t.branches.len() != 2 {
            return TestResult::Fail("branch count wrong");
        }
        if t.branch_by_guid(g1).is_none() {
            return TestResult::Fail("guid lookup failed");
        }
        if t.branch_by_guid(Guid([9; 16])).is_some() {
            return TestResult::Fail("missing guid returned Some");
        }
        // Sink count: 1 in b1 + 1 in b2 = 2.
        if t.sink_count() != 2 {
            return TestResult::Fail("sink count wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_topology_branch_lookup);

    fn smoke_topology_replace_on_same_rad() -> TestResult {
        let mut t = Topology::new(64);
        let b1 = Branch {
            guid: Guid([1; 16]),
            ports: Vec::new(),
            rad: alloc::vec![1, 2, 3],
        };
        let b2 = Branch {
            guid: Guid([2; 16]),
            ports: Vec::new(),
            rad: alloc::vec![1, 2, 3],
        };
        t.add_branch(b1);
        t.add_branch(b2);
        if t.branches.len() != 1 {
            return TestResult::Fail("same RAD didn't replace");
        }
        if t.branches[0].guid != Guid([2; 16]) {
            return TestResult::Fail("replacement didn't take");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_topology_replace_on_same_rad);

    fn smoke_sideband_opcode_values() -> TestResult {
        // Anchor the spec constants so refactors don't silently shift.
        if SB_LINK_ADDRESS != 0x01 {
            return TestResult::Fail("LINK_ADDRESS opcode shifted");
        }
        if SB_ENUM_PATH_RESOURCES != 0x10 {
            return TestResult::Fail("ENUM_PATH_RESOURCES opcode shifted");
        }
        if SB_ALLOCATE_PAYLOAD != 0x11 {
            return TestResult::Fail("ALLOCATE_PAYLOAD opcode shifted");
        }
        if SB_REMOTE_DPCD_READ != 0x20 {
            return TestResult::Fail("REMOTE_DPCD_READ opcode shifted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_sideband_opcode_values);

    // ── Live stream activation ────────────────────────────────

    struct MockMstAux {
        dpcd_writes: Vec<(u16, u8)>,
        sb_messages: Vec<(u8, Vec<u8>)>,
        /// After N reads, return PAYLOAD_TABLE_UPDATED_BIT.
        poll_count: u32,
    }
    impl MstAux for MockMstAux {
        fn dpcd_write_u8(&mut self, addr: u16, value: u8) -> u8 {
            self.dpcd_writes.push((addr, value));
            0
        }
        fn dpcd_read_u8(&mut self, addr: u16) -> u8 {
            if addr == DPCD_PAYLOAD_TABLE_UPDATE_STATUS {
                self.poll_count += 1;
                if self.poll_count >= 2 {
                    return PAYLOAD_TABLE_UPDATED_BIT;
                }
            }
            0
        }
        fn sb_message(&mut self, opcode: u8, body: &[u8]) -> Vec<u8> {
            self.sb_messages.push((opcode, body.to_vec()));
            Vec::new()
        }
    }

    fn smoke_commit_payload_writes_three_dpcd_regs() -> TestResult {
        let mut aux = MockMstAux {
            dpcd_writes: Vec::new(),
            sb_messages: Vec::new(),
            poll_count: 0,
        };
        commit_payload_to_sink(&mut aux, 5, 10, 8).expect("commit");
        // 3 DPCD writes for SET / START / COUNT + 1 W1C clear.
        if aux.dpcd_writes.len() != 4 {
            return TestResult::Fail("expected 4 DPCD writes");
        }
        if aux.dpcd_writes[0] != (DPCD_PAYLOAD_ALLOCATE_SET, 5) {
            return TestResult::Fail("VCPI write wrong");
        }
        if aux.dpcd_writes[1] != (DPCD_PAYLOAD_ALLOCATE_START_TIME_SLOT, 10) {
            return TestResult::Fail("start slot wrong");
        }
        if aux.dpcd_writes[2] != (DPCD_PAYLOAD_ALLOCATE_TIME_SLOT_COUNT, 8) {
            return TestResult::Fail("slot count wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_commit_payload_writes_three_dpcd_regs);

    fn smoke_commit_payload_rejects_bad_vcpi() -> TestResult {
        let mut aux = MockMstAux {
            dpcd_writes: Vec::new(),
            sb_messages: Vec::new(),
            poll_count: 0,
        };
        if commit_payload_to_sink(&mut aux, 0, 0, 0) != Err(MstStreamError::BadVcpi) {
            return TestResult::Fail("VCPI 0 not rejected");
        }
        if commit_payload_to_sink(&mut aux, 64, 0, 0) != Err(MstStreamError::BadVcpi) {
            return TestResult::Fail("VCPI 64 not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_commit_payload_rejects_bad_vcpi);

    fn smoke_send_allocate_payload_carries_rad() -> TestResult {
        let mut aux = MockMstAux {
            dpcd_writes: Vec::new(),
            sb_messages: Vec::new(),
            poll_count: 0,
        };
        send_allocate_payload(&mut aux, 7, 0x40, 2, &[0x11, 0x22]).expect("send");
        if aux.sb_messages.len() != 1 {
            return TestResult::Fail("expected 1 SB message");
        }
        let (op, body) = &aux.sb_messages[0];
        if *op != MST_SB_ALLOCATE_PAYLOAD {
            return TestResult::Fail("wrong opcode");
        }
        // body: [lct=2, rad bytes, vcpi=7, pbn_hi=0, pbn_lo=0x40].
        if body.len() != 5 {
            return TestResult::Fail("body wrong length");
        }
        if body[0] != 2 || body[1] != 0x11 || body[2] != 0x22 || body[3] != 7 {
            return TestResult::Fail("body bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_send_allocate_payload_carries_rad);

    fn smoke_activate_stream_end_to_end() -> TestResult {
        let mut aux = MockMstAux {
            dpcd_writes: Vec::new(),
            sb_messages: Vec::new(),
            poll_count: 0,
        };
        let mut table = PayloadTable::new(64);
        let guid = Guid([0xAA; 16]);
        let vcpi =
            activate_stream(&mut aux, &mut table, guid, 2, &[0x11], 0, 32, 0).expect("activate");
        if vcpi == 0 {
            return TestResult::Fail("vcpi 0");
        }
        // 2 SB messages — ALLOCATE_PAYLOAD + ENABLE_STREAM.
        if aux.sb_messages.len() != 2 {
            return TestResult::Fail("expected 2 SB msgs");
        }
        if aux.sb_messages[0].0 != MST_SB_ALLOCATE_PAYLOAD {
            return TestResult::Fail("1st SB not ALLOC");
        }
        if aux.sb_messages[1].0 != MST_SB_ENABLE_STREAM {
            return TestResult::Fail("2nd SB not ENABLE");
        }
        // PayloadTable updated.
        if table.allocations.len() != 1 {
            return TestResult::Fail("table not updated");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_activate_stream_end_to_end);
}
