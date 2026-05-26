//! Thunderbolt switch (router) enumeration + topology.
//!
//! A Thunderbolt domain is a tree of switches. The host's NHI sits at
//! the root (route = 0, depth = 0); each child switch hangs off one
//! of its parent's lane (LANE) ports. Stage-1 walks this tree using
//! the Connection Manager control packets defined in `cm.rs` —
//! breadth-first, depth-bounded.
//!
//! Stage-1 scope:
//!   - `Switch` struct: route, depth, vendor / device IDs, adapter
//!     count, list of adapters with their types.
//!   - `Adapter` struct: per-port type + index.
//!   - `Topology` struct: container for the discovered domain.
//!   - Pure-logic `walk_topology(...)` driver that consumes a closure
//!     producing `tb_regs_port_header` / `tb_regs_switch_header`
//!     bytes — Stage-1 doesn't talk to real hardware, but the walker
//!     is shaped to drop straight into a Stage-2 NHI-backed
//!     implementation.
//!
//! Source: Linux `drivers/thunderbolt/{tb,switch}.c` (the SW-CM
//! `tb_scan_port` walk in particular). USB4 §"Topology" is the
//! public-spec backstop.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use crate::adapter::AdapterType;
use crate::cm::{compose_downstream, route_depth, Header, TB_MAX_DEPTH};

/// One adapter on one switch — Stage-1 carries just the type + the
/// port number. Stage-2 will add credit + lane state + DP / PCIe
/// resource state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Adapter {
    /// Port number on the switch (1..max_port). Port 0 is the
    /// switch's own header, not an adapter.
    pub port: u8,
    /// Decoded adapter type. `None` if the type word didn't match
    /// any known protocol — caller logs but doesn't fail the walk.
    pub kind: Option<AdapterType>,
}

/// One discovered switch — Stage-1 holds the minimum fields the
/// log-line and Stage-2 tunnel planner need: route, depth, vendor /
/// device IDs, the upstream port (the LANE adapter facing the
/// parent), the list of all adapters with their types.
#[derive(Clone, Debug)]
pub struct Switch {
    /// 64-bit route from the host (depth-0) down to this switch.
    /// Host itself has route = 0.
    pub route: u64,
    /// Depth in the tree. Host = 0, first downstream = 1, …
    pub depth: u32,
    /// Vendor ID from the switch's TB_CFG_SWITCH header.
    pub vendor: u16,
    /// Device ID from the switch's TB_CFG_SWITCH header.
    pub device: u16,
    /// Adapter port that connects this switch up to its parent.
    /// Zero for the host (no parent).
    pub upstream_port: u8,
    /// Highest valid port number on this switch (inclusive). On a
    /// USB4 router this is typically ~12 (ports 1..12).
    pub max_port: u8,
    /// List of adapters. Stage-1 fills one entry per port from 1
    /// through `max_port`.
    pub adapters: Vec<Adapter>,
}

impl Switch {
    /// True if this switch is the host (route = 0, depth = 0).
    pub fn is_host(&self) -> bool {
        self.route == 0 && self.depth == 0
    }

    /// Iterate over adapters that terminate a tunnel (PCIe-UP /
    /// PCIe-DOWN / DP-IN / DP-OUT / USB3-UP / USB3-DOWN).
    pub fn tunnel_endpoints(&self) -> impl Iterator<Item = &Adapter> {
        self.adapters
            .iter()
            .filter(|a| matches!(a.kind, Some(k) if k.is_tunnel_endpoint()))
    }

    /// Iterate over LANE adapters — these are how downstream switches
    /// attach. A LANE adapter that is reported as "connected" by the
    /// parent (Stage-2 will check `tb_cap_phy.state`) is followed.
    pub fn lane_adapters(&self) -> impl Iterator<Item = &Adapter> {
        self.adapters
            .iter()
            .filter(|a| matches!(a.kind, Some(AdapterType::Port)))
    }

    /// Render a one-line topology summary for the boot transcript:
    /// `switch[$route](depth=$d, $N adapters: PCIe-UP, DP-IN, ...)`
    pub fn fmt_summary(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            &mut s,
            "switch[{:016x}](depth={}, vid={:#06x}, did={:#06x}, {} adapters",
            self.route,
            self.depth,
            self.vendor,
            self.device,
            self.adapters.len(),
        );
        let endpoints: Vec<_> = self.tunnel_endpoints().collect();
        if !endpoints.is_empty() {
            let _ = write!(&mut s, ": ");
            for (i, a) in endpoints.iter().enumerate() {
                if i > 0 {
                    let _ = write!(&mut s, ", ");
                }
                if let Some(k) = a.kind {
                    let _ = write!(&mut s, "{}", k.short_name());
                }
            }
        }
        let _ = write!(&mut s, ")");
        s
    }
}

/// One Thunderbolt *domain* — the tree of switches rooted at one
/// host NHI. A system with two NHIs has two domains.
#[derive(Clone, Debug)]
pub struct Topology {
    /// Domain index — 0 for the first NHI, 1 for the second, …
    pub domain: u32,
    /// Switches in breadth-first order. `switches[0]` is always the
    /// host.
    pub switches: Vec<Switch>,
}

impl Topology {
    /// Empty topology for `domain`. Caller pushes the host switch
    /// before invoking `walk_topology`.
    pub fn new(domain: u32) -> Self {
        Self {
            domain,
            switches: Vec::new(),
        }
    }

    /// Total switch count (includes the host).
    pub fn switch_count(&self) -> usize {
        self.switches.len()
    }

    /// Render a multi-line topology summary. One line for the
    /// header, one line per switch.
    pub fn fmt_summary(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            &mut s,
            "thunderbolt: domain {}, {} switches",
            self.domain,
            self.switches.len(),
        );
        for sw in &self.switches {
            let _ = write!(&mut s, "\n  {}", sw.fmt_summary());
        }
        s
    }
}

/// Errors emitted by `walk_topology`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WalkError {
    /// Walk would exceed `TB_MAX_DEPTH` — caller hit a routing loop
    /// or hostile firmware reporting a child where its grandparent
    /// already sits.
    DepthExceeded,
    /// Probe closure couldn't read a switch / port header at the
    /// requested route. Stage-2 will surface the underlying NHI /
    /// timeout error here.
    ProbeFailed,
}

/// Result returned by the probe closure for one switch. Mirrors the
/// fields of `tb_regs_switch_header` we actually use.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SwitchHeader {
    pub vendor: u16,
    pub device: u16,
    pub upstream_port: u8,
    pub max_port: u8,
}

/// Result returned by the probe closure for one port. Mirrors the
/// 24-bit `type` field of `tb_regs_port_header`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortInfo {
    /// The 24-bit type word read from the port header.
    pub raw_type: u32,
}

/// Probe-side callbacks. Stage-1 callers can stub these out (closures
/// over an in-memory tree) so the walker can be unit-tested
/// independently of the NHI. Stage-2 wires them through the CM.
pub trait TopologyProbe {
    /// Read the switch header (TB_CFG_SWITCH dword 0..) for the
    /// switch at `route`.
    fn read_switch(&mut self, route: u64) -> Result<SwitchHeader, WalkError>;
    /// Read the port header (TB_CFG_PORT dword 2) for `(route, port)`.
    fn read_port(&mut self, route: u64, port: u8) -> Result<PortInfo, WalkError>;
    /// True if the lane adapter at `(route, port)` reports a peer on
    /// the link (Stage-2 will read `tb_cap_phy.state`). Stage-1
    /// callers can stub this to "yes" for every lane port they
    /// populated in the in-memory tree.
    fn port_has_peer(&mut self, route: u64, port: u8) -> Result<bool, WalkError>;
}

/// Walk the topology breadth-first starting at the host (route = 0).
/// Populates `topology.switches` in the order visited. The walker
/// stops at `TB_MAX_DEPTH`. Probe failures abort the walk with the
/// underlying error.
///
/// Shape mirrors Linux's `tb_scan_switch` recursion, but flattened
/// to an iterative BFS so we don't blow the kernel stack on deep
/// (depth-7) trees. The closure dispatch keeps the walker testable
/// without an NHI.
pub fn walk_topology<P: TopologyProbe>(
    topology: &mut Topology,
    probe: &mut P,
) -> Result<(), WalkError> {
    // BFS queue of (parent_route, parent_depth, parent_index_in_topology).
    // The host is always switch index 0.
    let host_hdr = probe.read_switch(0)?;
    let host = Switch {
        route: 0,
        depth: 0,
        vendor: host_hdr.vendor,
        device: host_hdr.device,
        upstream_port: 0,
        max_port: host_hdr.max_port,
        adapters: enumerate_adapters(probe, 0, host_hdr.max_port)?,
    };
    topology.switches.push(host);

    // Pending queue: indices into `topology.switches`.
    let mut pending: Vec<usize> = Vec::new();
    pending.push(0);

    while let Some(parent_idx) = pending.pop() {
        // Snapshot the parent's identity — we'll re-borrow `topology`
        // mutably below to push children, so we can't keep a parent
        // borrow live across the loop.
        let parent_route = topology.switches[parent_idx].route;
        let parent_depth = topology.switches[parent_idx].depth;
        let parent_upstream = topology.switches[parent_idx].upstream_port;
        if parent_depth >= TB_MAX_DEPTH {
            // Already at max depth — children would exceed it.
            continue;
        }
        // Collect candidate downstream ports without holding the
        // adapters borrow across the recursion. Skip the upstream
        // port (= the lane that came from the parent's parent —
        // following it loops back up the tree).
        let mut lane_ports: Vec<u8> = Vec::new();
        for a in topology.switches[parent_idx].lane_adapters() {
            if a.port == parent_upstream {
                continue;
            }
            lane_ports.push(a.port);
        }
        for port in lane_ports {
            if !probe.port_has_peer(parent_route, port)? {
                continue;
            }
            // Compose the child's route. The new hop sits at the
            // parent's depth × 8 bit position.
            let child_route = match compose_downstream(parent_route, parent_depth, port) {
                Some(r) => r,
                None => continue,
            };
            // Validate the route fits in the on-wire header.
            if child_route > Header::ROUTE_MAX {
                continue;
            }
            let child_depth = parent_depth + 1;
            if child_depth > TB_MAX_DEPTH {
                return Err(WalkError::DepthExceeded);
            }
            let child_hdr = probe.read_switch(child_route)?;
            let child = Switch {
                route: child_route,
                depth: child_depth,
                vendor: child_hdr.vendor,
                device: child_hdr.device,
                upstream_port: child_hdr.upstream_port,
                max_port: child_hdr.max_port,
                adapters: enumerate_adapters(probe, child_route, child_hdr.max_port)?,
            };
            topology.switches.push(child);
            let new_idx = topology.switches.len() - 1;
            pending.push(new_idx);
        }
    }
    Ok(())
}

fn enumerate_adapters<P: TopologyProbe>(
    probe: &mut P,
    route: u64,
    max_port: u8,
) -> Result<Vec<Adapter>, WalkError> {
    let mut adapters = Vec::new();
    // Ports 1..=max_port are adapters; port 0 is the switch header.
    for port in 1..=max_port {
        let info = probe.read_port(route, port)?;
        adapters.push(Adapter {
            port,
            kind: AdapterType::from_raw(info.raw_type),
        });
    }
    Ok(adapters)
}

/// Sanity-check derived from `route_depth`: depth-of-route must match
/// the depth we *believe* a switch should sit at. Useful for the
/// Stage-1 self-test smoke that builds a synthetic tree, walks it,
/// and confirms each visited switch's depth lines up with where its
/// route says it belongs.
pub fn depth_matches_route(sw: &Switch) -> bool {
    route_depth(sw.route) == sw.depth
}
