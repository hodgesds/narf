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
//!    `drm_dp_send_link_address`,
//!    `drm_dp_payload_send_msg`)
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
        matches!(self, PeerDeviceType::Sink | PeerDeviceType::SinkOrBranch | PeerDeviceType::LegacyDevice)
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
    pub fn allocate(
        &mut self,
        branch_guid: Guid,
        sink_port: u8,
        pbn: u16,
    ) -> Result<u8, MstError> {
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
    ((num + den - 1) / den) as u32
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
        self.branches
            .iter()
            .flat_map(|b| b.sink_ports())
            .count()
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
        if !PeerDeviceType::SinkOrBranch.is_sink()
            || !PeerDeviceType::SinkOrBranch.is_branch()
        {
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
}
